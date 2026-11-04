# Easy paths first: weighted attack paths with Cypher 25 on a Kubernetes attack graph

<!-- DRAFT, 4 Nov 2026. Numbers from blog/results/ (bench_gremlin_vs_cypher, bench_weighted, q1–q3). -->

An attacker who lands in one container doesn't care about *every* path to cluster admin. They care
about the **easy** ones: the exec they're already allowed to run, the token lying in a mounted
volume, the `nsenter` that works because someone set `privileged: true`. Defenders should care
about the same paths, for the same reason.

Attack path analysis tools find these paths by enumerating them. Datadog's
[KubeHound](https://github.com/DataDog/KubeHound) builds a graph of a Kubernetes cluster in which
every edge is an attack, stores it in JanusGraph, and asks Gremlin for every path from a foothold
to a critical asset. That works well on small clusters. On a bigger one, the number of paths
explodes after a handful of hops, long before KubeHound's default limit of 10.

This post moves KubeHound's graph, unchanged, into Neo4j. First it asks KubeHound's own questions
in Cypher 25 and compares the two engines; then it adds what KubeHound doesn't have: a **cost per
attack**. Pruning on that cost while the path grows, either per move or for the whole path, is
what turns "all paths" into "the easy paths", and what lets the search go to 15 hops and back in
half a second.

> **TL;DR**
> - Same graph, same questions, **same path counts** in Gremlin and Cypher 25 (`ACYCLIC` is
>   Gremlin's `simplePath()`). Neo4j is **15–1,100× faster** from 3 hops on.
> - Unweighted, both engines hit a wall: **1.8 million paths at 6 hops** from just 14 containers,
>   and nobody finishes 7.
> - A **total effort budget** (`allReduce` over the attack weights) makes the hop limit
>   irrelevant: the 707 paths of effort ≤ 4 come back in **0.57 s at 15 hops**, KubeHound's
>   maximum. Gremlin can do the same with `sack()`, in 9.7 s.
> - A **per-attack cap** ("easy moves only") reaches 10 hops but not 15: cheap moves form loops
>   of their own.
> - Write the budget on the QPP's relationship group. The same condition on `relationships(p)`,
>   or checked afterwards, gives the same answer and doesn't finish 7 hops.

All queries need **Cypher 25**: start them with `CYPHER 25` unless your database defaults to it.

## The data: a real cluster, attacked by KubeHound

| Layer | Source | What |
|---|---|---|
| Cluster | a [kind](https://kind.sigs.k8s.io/) cluster we run: Kubernetes v1.37, 1 control plane + 7 workers, 1,641 pods | KubeHound's own vulnerable test fixtures, copied into **90 tenant namespaces** (a seeded random 60% of the fixtures each), plus four popular Helm charts at their defaults: ingress-nginx, cert-manager, Argo CD, kube-prometheus-stack |
| Attack graph | **KubeHound v1.6.7**, used as released | 7,212 vertices (containers, pods, nodes, identities, permission sets, volumes, endpoints) and 175,843 attack edges of 24 kinds |
| Techniques | **MITRE ATT&CK** | KubeHound tags every attack with its ATT&CK technique and tactic |

KubeHound does the hard part. It dumps the cluster's resources from the Kubernetes API, and for
each of its attacks a builder decides where the attack applies: `CE_NSENTER` from a container
that runs `privileged` with `hostPID` to its node, `TOKEN_STEAL` from a container to the identity
whose token is mounted in it, `ROLE_BIND` from a permission set that may create role bindings to
every role it could bind. A risk engine marks the dangerous permission sets, cluster-wide roles
such as the ability to create pods anywhere, as `critical`: 109 of the 1,235. We export the built
graph over Gremlin and load it, vertex for vertex and edge for edge.

### One relationship type: `:ATTACKS`

In JanusGraph every attack is its own edge label (`ROLE_BIND`, `POD_EXEC`, …). In Neo4j they all
become one relationship type, so every traversal is a single quantified path pattern:

```
(:Container)-[:ATTACKS {kind: 'CE_NSENTER', techniqueId: 'T1611', tacticId: 'TA0004', w: 1}]->(:Node)
```

Two attacks between the same two nodes stay two relationships: they are different moves.

### Where the paths come from, and why there are so many

`ROLE_BIND` is **84% of all edges** (148,060). A namespace identity that may create role
bindings can bind *any* ClusterRole in its namespace, and every tenant brings its own
ClusterRoles, so these edges grow with the square of the number of tenants. That dense mesh of
permission sets is where path counts explode. `EXPLOIT_HOST_TRAVERSE` comes second (13,765): a
container with the host's filesystem mounted can read the token of every pod on its node.

### The weights: an example cost model

KubeHound has no notion of cost; every edge is just "possible". We add a weight `w`, the
attacker's effort to make the move, graded from the *Exploitation* section of each attack's page
in [KubeHound's attack reference](https://kubehound.io/reference/attacks/):

| w | Effort | Attacks | Edges |
|---|---|---|---|
| 0.5 | discovery: "No exploitation is necessary" | `PERMISSION_DISCOVER`, `VOLUME_DISCOVER`, `VOLUME_ACCESS` | 3,812 |
| 1 | direct use: one standard command with access already held | `POD_EXEC`, `CONTAINER_ATTACH`, `TOKEN_STEAL`, `TOKEN_LIST`, `IDENTITY_ASSUME`, `EXPLOIT_HOST_TRAVERSE`, `SHARE_PS_NAMESPACE`, `CE_NSENTER` | 19,717 |
| 2 | crafted but deterministic: a crafted manifest or API call, a few host-file steps | `ROLE_BIND`, `POD_CREATE`, `POD_PATCH`, `POD_ATTACH`, `CE_PRIV_MOUNT`, `CE_VAR_LOG_SYMLINK`, `EXPLOIT_HOST_WRITE` | 151,018 |
| 3 | hard: payload or compiled code, kernel tricks, offline work, or no guaranteed success | `CE_MODULE_LOAD`, `CE_SYS_PTRACE`, `CE_UMH_CORE_PATTERN`, `EXPLOIT_HOST_READ`, `TOKEN_BRUTEFORCE`, `ENDPOINT_EXPLOIT` | 1,296 |

A few examples from the docs: `CE_NSENTER` is one command (`nsenter --target 1 --mount --uts
--ipc --net --pid -- bash`); `TOKEN_LIST` is "Simply dump all secrets using kubectl"; for
`CE_UMH_CORE_PATTERN` you write and compile a crashing program and hijack the kernel's
`core_pattern`. `ENDPOINT_EXPLOIT` gets a 3 for a different reason: KubeHound's doc says the edge
"does not signal that the endpoint is exploitable", so crossing it needs a vulnerability the graph
doesn't know about.

**This is an example, not a standard.** Your threat model may weigh noise, detection coverage or
required privileges instead. The weights are plain properties, so changing them is one `SET` per
attack kind and no reload (`scripts/set_weights.py`).

## Part 1: KubeHound's questions, in Gremlin and in Cypher

KubeHound's main question is `criticalPaths()`: from a foothold, every loop-free path to the first
critical asset it meets. We start from the 14 containers of one tenant, `tenant-001`.

**Gremlin** (KubeHound's DSL, with its definition from `KubeHoundTraversalDsl.java` expanded):

```groovy
kh.V().has('class','Container').has('namespace','tenant-001').criticalPaths(5).count()

// criticalPaths(maxHops) is:
  .repeat(outE().inV().simplePath())
  .until(has('critical', true).or().loops().is(maxHops))
  .has('critical', true)
  .path()
```

**Cypher 25**:

```cypher
CYPHER 25
MATCH (s:Container {namespace: 'tenant-001'})
MATCH p = ACYCLIC (s) (()-[:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,4}
                  ()-[:ATTACKS]->(:PermissionSet {critical: true})
RETURN count(p) AS n
```

| Gremlin | Cypher 25 |
|---|---|
| `simplePath()` | `ACYCLIC`: no node twice |
| `loops().is(5)` | `{0,4}` plus the last hop: at most 5 attacks |
| `until(critical)` stops at the **first** critical asset | intermediate nodes `x` must not be critical |
| final `has('critical', true)` | the path ends on `(:PermissionSet {critical: true})` |

The second question is the "basic attack paths" example of KubeHound's docs, the **blast radius
to the nodes**: every path from the containers to the first `Node` they can take over, by any
sequence of attacks. Same structure, with `(:Node)` as the target.

Both engines ran on the same machine, in Docker with a 4 GB heap each: KubeHound's JanusGraph 1.1
(in-memory backend) and Neo4j 2026.10 Community. Times are the median of three runs after a
warm-up, with a 60 s timeout; counting happens on the server.

**Containers → first critical permission set**

| Max hops | Paths (both) | Gremlin | Neo4j | |
|---|---|---|---|---|
| 2 | 1 | 68 ms | 16 ms | 4× |
| 3 | 176 | 317 ms | 21 ms | 15× |
| 4 | 458 | 969 ms | 49 ms | 20× |
| 5 | 28,102 | 3.3 s | 94 ms | 35× |
| 6 | 1,802,392 | timeout | 0.9 s | |
| 7 | | | timeout | |

**Blast radius to the nodes: containers → first node**

| Max hops | Paths (both) | Gremlin | Neo4j | |
|---|---|---|---|---|
| 4 | 12 | 41 ms | 11 ms | 4× |
| 5 | 12 | 332 ms | 8 ms | 41× |
| 6 | 12 | 40.6 s | 35 ms | 1,160× |
| 7 | 222 | timeout | 1.8 s | |
| 8 | | | timeout | |

Wherever both finished, **the counts are identical**, so the migration is faithful. The speed-up
grows with depth: at 6 hops, Gremlin needs 40 s to find the same 12 paths to a node that Neo4j
finds in 35 ms.

But look at the first table again. From 5 to 6 hops the number of paths goes from 28 thousand to
**1.8 million**, and neither engine gets anywhere near KubeHound's default of 10 hops. That is the
`ROLE_BIND` mesh: once a path reaches a permission set that can bind roles, it can wander from role
to role. Most of those 1.8 million paths are variations nobody would ever walk. A faster engine
moves the wall, it doesn't remove it.

## Part 2: weights, or "show me the easy paths"

The fix is to stop asking for every path and ask for the **easy** ones. With `w` on every
attack there are two natural ways to say "easy", and Cypher 25 checks both *while the path grows*:

**A cap per attack:** every move is at most `w ≤ 1` ("only things I can do with one command"):

```cypher
MATCH p = ACYCLIC (s) (()-[r:ATTACKS WHERE r.w <= 1]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS WHERE l.w <= 1]->(:PermissionSet {critical: true})
```

**A budget for the whole path:** the efforts add up to at most 4. `allReduce` keeps the running
sum and drops a path the moment it goes over:

```cypher
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(:PermissionSet {critical: true})
WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= 4)        // pruned while the path grows
  AND reduce(c = 0.0, e IN r | c + e.w) + l.w <= 4        // and the last attack
```

Gremlin can express both with native steps. KubeHound's JanusGraph schema doesn't allow a new
property on its edges, so the cap becomes the list of edge labels with `w ≤ 1` (exactly what
KubeHound's own `criticalPathsFilter` does), and the budget a `sack()` that adds each edge's weight,
looked up by label:

```groovy
g.withSack(0.0d).V().has('class','Container').has('namespace','tenant-001')
  .repeat(outE().sack(sum).by(choose(label()).option('ROLE_BIND', constant(2.0d)).option(...))
               .filter(sack().is(lte(4.0d)))
               .inV().simplePath())
  .until(has('critical',true).or().loops().is(15))
  .has('critical',true).path().count()
```

Same 14 containers, same targets, now up to 15 hops:

| Max hops | Unweighted | Cap w ≤ 1 | Budget ≤ 3 | Budget ≤ 4 | Budget ≤ 5 |
|---|---|---|---|---|---|
| 5 | 28,102 · 0.1 s | 352 · 0.03 s | 46 · 0.05 s | 707 · 0.09 s | 10,751 · 0.14 s |
| 6 | 1,802,392 · 0.9 s | 385 · 0.12 s | 46 · 0.08 s | 707 · 0.34 s | 10,784 · 1.3 s |
| 8 | timeout | 697 · 0.74 s | 46 · 0.08 s | 707 · 0.54 s | 10,784 · 5.5 s |
| 10 | timeout | 1,842 · 1.5 s | 46 · 0.09 s | 707 · 0.53 s | 10,784 · 5.0 s |
| 15 | timeout | timeout | **46 · 0.11 s** | **707 · 0.57 s** | **10,784 · 5.3 s** |

*(Neo4j: paths · median time. Gremlin returned the same counts wherever it finished.)*

**The budget makes the hop limit irrelevant.** With a total effort of 4, every path is complete
by 5 hops: the cheapest move costs 0.5, so the budget, not the hop limit, decides how far a path
can go. Raising the limit to 15 costs nothing more and finds nothing new: 707 paths at 5 hops, 707
at 15. That is the question KubeHound can't finish unweighted, answered in half a second.

**The cap alone is not enough.** "Easy moves only" removes the `ROLE_BIND` mesh (`w = 2`), so it
gets to 10 hops. But easy moves form loops of their own: escape to a node with `nsenter`, steal the
token of every pod on it, exec into one of those pods, escape again… At 15 hops that still times
out. A cap says *which* moves are allowed; only a budget says *how many*.

**Budgets have to be tight to work.** At 5 the search still finishes 15 hops (10,784 paths, 5 s);
at 6 it takes 48 s; at 8 it times out at 7 hops, because a budget of 8 allows four role bindings in
a row and the mesh is back. Combining a cap of 2 (no hard exploits) with a budget of 6 changes
almost nothing (100,620 paths instead of 101,392): the hard exploits are rare, the cost comes from
the many medium moves.

**Gremlin vs Neo4j, weighted:**

| Question | Gremlin | Neo4j | |
|---|---|---|---|
| cap w ≤ 1, 10 hops (1,842 paths) | 9.4 s | 1.5 s | 6× |
| budget ≤ 3, 15 hops (46 paths) | 1.4 s | 0.11 s | 12× |
| budget ≤ 4, 15 hops (707 paths) | 9.7 s | 0.57 s | 17× |
| budget ≤ 5, 15 hops (10,784 paths) | timeout at 6 hops | 5.3 s | |

The cap narrows the gap (at 7 hops it's 0.9 s against 0.8 s): with a short list of edge labels,
Gremlin's expansion is cheap too. The budget widens it again.

## Part 3: what the easy paths look like

Counting is for benchmarks. Here are the answers (`queries/q1`–`q3`, all at 15 hops):

**The cheapest paths** (budget 4, `q1_easiest_paths.cypher`, 1.1 s):

| Container | Effort | Moves (ATT&CK) | Critical target |
|---|---|---|---|
| `pod-create-pod` | 1.5 | `IDENTITY_ASSUME` (T1078) → `PERMISSION_DISCOVER` (T1069) | `create-pods` |
| `pod-create-pod` | 2.0 | `VOLUME_DISCOVER` (T1613) → `TOKEN_STEAL` (T1552) → `PERMISSION_DISCOVER` | `create-pods` |
| `nsenter-pod` | 2.5 | `CE_NSENTER` (T1611) → `IDENTITY_ASSUME` → `PERMISSION_DISCOVER` | kubeadm node-autoapprove CSR role |
| `endpoints-pod` | 3.0 | `CE_NSENTER` → `VOLUME_ACCESS` → `TOKEN_STEAL` → `PERMISSION_DISCOVER` | `argocd-application-controller` |

The last row is the kind of path a defender wants to see: a tenant container escapes to its node,
picks up a token from a volume there, and that token belongs to **Argo CD's application
controller**, which comes from a Helm chart at its default settings, not from any fixture.

**Every container's cheapest way in** (budget 4, `q2_effort_per_container.cypher`, 0.6 s): 9 of
the 14 containers reach a critical asset within the budget.

| Container | Cheapest effort | Paths within budget |
|---|---|---|
| `pod-create-pod` | 1.5 | 2 |
| `endpoints-pod` | 2.5 | 154 |
| `nsenter-pod` | 2.5 | 192 |
| `host-read-exploit-pod` | 3.0 | 10 |
| `host-write-exploit-pod` | 3.0 | 15 |
| `priv-pod` | 3.5 | 6 |
| 3 × `rolebind-pod-…` | 3.5 | 108–110 each |

That is a priority list: fix `pod-create-pod`'s service account first, then the two containers
that run with `hostPID` and `privileged`.

**Easy moves only** (cap w ≤ 1, 10 hops, `q3_easy_moves_only.cypher`, 0.8 s): the most common
sequence is `CE_NSENTER → VOLUME_ACCESS → EXPLOIT_HOST_TRAVERSE → TOKEN_STEAL →
PERMISSION_DISCOVER` (306 paths). The longer ones repeat it: escape, steal, `POD_EXEC` into another
pod, escape again. Those are the loops that keep the cap from reaching 15 hops.

## Part 4: how you write it matters

The same question can be written in ways that give the same answer but run very differently. All
the queries below share this start, and differ only in the `MATCH p = …` and `WHERE` lines:

```cypher
CYPHER 25
MATCH (s:Container {namespace: 'tenant-001'})
```

### Where the budget is checked

Three ways to say "the attacks on the path add up to at most 4":

**A. `allReduce` over the QPP's relationship group** (the one used in Parts 2 and 3):

```cypher
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(:PermissionSet {critical: true})
WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= 4)
  AND reduce(c = 0.0, e IN r | c + e.w) + l.w <= 4
RETURN count(p) AS n
```

`r` is the *group variable* of the QPP: the list of relationships matched by the repeated part
so far. Because `allReduce` reads `r`, the planner can check it after every hop and drop a path
the moment it goes over 4.

**B. `allReduce` over `relationships(p)`**: the same sum, but over the whole path `p`:

```cypher
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(:PermissionSet {critical: true})
WHERE allReduce(c = 0.0, e IN relationships(p) | c + e.w, c <= 4)
RETURN count(p) AS n
```

Shorter, and it includes the last attack `l`, so no second line is needed. But `p` only exists
once the path is complete, so in our runs nothing was pruned while the path was growing.

**C. `reduce` in a plain `WHERE`**: the only way to write it before `allReduce`
(Neo4j 2025.08):

```cypher
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(:PermissionSet {critical: true})
WHERE reduce(c = 0.0, e IN r | c + e.w) + l.w <= 4
RETURN count(p) AS n
```

`reduce` returns one number for a finished path, so every path is built first and filtered
afterwards.

| Max hops | **A** `allReduce` over `r` | B `allReduce` over `relationships(p)` | C `reduce` afterwards |
|---|---|---|---|
| 5 | 0.09 s | 0.15 s | 0.11 s |
| 6 | 0.34 s | 5.1 s | 2.4 s |
| 7 | 0.51 s | timeout | timeout |
| 15 | **0.57 s** | | |

All three find the same 707 paths, but only A gets past 6 hops. **Prune on the group variable.**

### The shape of the pattern

Two ways to write the unweighted question from Part 1 (shown at 6 hops):

**D. The target gets its own hop** (every query above):

```cypher
MATCH p = ACYCLIC (s) (()-[:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,5}
                  ()-[:ATTACKS]->(:PermissionSet {critical: true})
RETURN count(p) AS n
```

The repeated part goes up to the last node *before* the target, which must not be critical. The
last attack is written separately and ends on a critical permission set.

**E. One QPP that ends at the target:**

```cypher
MATCH p = ACYCLIC (s) ((a WHERE a.critical IS NULL OR NOT a.critical)-[:ATTACKS]->()){1,6}
                  (:PermissionSet {critical: true})
RETURN count(p) AS n
```

Every hop, the last one included, is part of the repetition. The "stop at the first critical
asset" rule moves to the *start* node `a` of each hop: a path may not continue from a critical
node.

| Question, 6 hops | **D** own last hop | E one QPP |
|---|---|---|
| unweighted (1,802,392 paths) | **0.9 s** | 15.8 s |
| with budget ≤ 4, as in A (707 paths) | 0.34 s | 0.31 s |

The plans show why D wins when you enumerate. In D the planner sees a separate last hop into a
selective target, so it runs a second search *from the 109 critical permission sets*: one step
backwards (17,661 attacks into them), hash-joined with the forward search from the containers.
In E it expands every last hop of every path (281,595 at 5 hops) and only then checks whether it
landed on a target. With a budget pruning the search there is little left to save, and the two
shapes are even. **When you enumerate, give a selective target its own hop.**

## Takeaways

1. **Ask for the easy paths, not all paths.** On a real attack graph the number of loop-free
   paths explodes after a few hops, in any engine. A weight per attack, checked while the path
   grows, is what makes long horizons answerable.
2. **A budget bounds depth, a cap bounds breadth.** The total effort (`allReduce`) decides how far
   a path can go, so the hop limit stops mattering; a per-attack cap only decides which moves
   count. Use both, and keep the budget tight.
3. **Same answers as Gremlin, an order of magnitude faster.** Cypher 25's `ACYCLIC` is
   `simplePath()`, an inline `WHERE` on intermediate nodes is `until()`, and `allReduce` is a
   pruning `sack()`. The counts match exactly. Neo4j is up to 1,100× faster; the gap is
   smallest when a cap leaves Gremlin only a few edge labels to follow.
4. **Write the condition where the planner can use it.** Prune on the QPP's group variable, not on
   `relationships(p)`, and give a selective target its own hop.

## Caveats

- **The weights are ours.** KubeHound doesn't grade its attacks; the 0.5 / 1 / 2 / 3 tiers are an
  example graded from its docs. Different weights give different "easy" paths.
- **The cluster is vulnerable on purpose.** 90 tenants of KubeHound's attack fixtures are not a
  production cluster; the Helm charts are the realistic part.
- **Paths count moves, not routes.** Two attacks between the same nodes are two paths, in both
  engines.
- **Timings come from one machine** (32 GB, Docker with WSL 2), both engines with a 4 GB heap,
  median of three runs; JanusGraph runs KubeHound's in-memory configuration. The 60 s timeout
  marks "didn't finish", not a crash.
- One tenant as the starting point. Other tenants hold other fixture mixes.

## Try it yourself

Everything, from building the cluster to the benchmarks, is in the
[project repository](https://github.com/BennuFire/cypher25-kubehound-attack-paths)
(`cluster/`, `scripts/`, `queries/`, `blog/results/`).

## Data and credits

- **KubeHound** v1.6.7, © Datadog, Apache-2.0: <https://github.com/DataDog/KubeHound>. Attack
  reference: <https://kubehound.io/reference/attacks/>. Used unchanged; its fixtures are the
  tenants' workloads.
- Helm charts (Apache-2.0): ingress-nginx, cert-manager, Argo CD, kube-prometheus-stack.
- Neo4j docs: [ACYCLIC paths](https://neo4j.com/docs/cypher-manual/current/patterns/acyclic-paths/),
  [match modes and path modes](https://neo4j.com/docs/cypher-manual/25/patterns/reference/match-modes-and-path-modes/);
  `allReduce`: [Neo4j 2025.08 release notes](https://neo4j.com/release-notes/database/neo4j-2025-08/).

---
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

*© 2026 Harold Agudelo. This article is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); the code is under the [MIT License](https://opensource.org/license/mit).*

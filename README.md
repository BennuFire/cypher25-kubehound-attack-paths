# Attack Path Analysis graph — Neo4j Cypher 25 path modes & QPP

Material for a blog post and a NeoDash / Aura Dashboards demo that shows Neo4j's quantified path
patterns (QPP), the GQL path modes `WALK`, `TRAIL` and `ACYCLIC`, and `SHORTEST k` on a
cybersecurity **attack graph**. It follows up the Electric Grid post: same tooling, same
two-layers-plus-a-bridge idea.

| Layer | Source | Scope | Source label |
|---|---|---|---|
| Threat knowledge | MITRE ATT&CK Enterprise v20.0, CAPEC, CWE, NVD CVE/CPE, CISA KEV, FIRST EPSS | real, public | `:MITRE`, `:NVD` |
| Infrastructure | Kubernetes attack graph built by Datadog's **KubeHound** v1.6.7 from a real kind cluster we run: KubeHound's vulnerable fixtures in 90 tenant namespaces + 4 popular Helm charts | 7,212 vertices, 175,923 attack edges, 24 attack types | `:KubeHound` |

Every attacker move is one `:ATTACKS` relationship whose `techniqueId` is the ATT&CK technique it
stands for. KubeHound already tags each of its attacks with one, so a path reads as an attack
narrative (T1609 → T1611 → T1552 → …) and joins to `(:Technique {id: r.techniqueId})`.

**Bridge (planned).** Scan the cluster's container images with Trivy, so a container links to the
real CVEs in its image: `Container → Image → CVE → CWE → CAPEC → Technique`.

> Status: the KubeHound layer is built, loaded and benchmarked (`blog/post.md` is the draft).
> The threat-knowledge layer (prepare / load) and the Trivy bridge are still to write.

## Graph model (draft)

### Threat knowledge layer
```
(:Technique)-[:IN_TACTIC]->(:Tactic)
(:Technique)-[:SUBTECHNIQUE_OF]->(:Technique)
(:ThreatGroup)-[:USES]->(:Technique)          ATT&CK "groups" (ThreatGroup, so :Group stays free for AD groups)
(:Mitigation)-[:MITIGATES]->(:Technique)
(:AttackPattern)-[:MAPS_TO]->(:Technique)     CAPEC -> ATT&CK
(:AttackPattern)-[:TARGETS]->(:Weakness)      CAPEC -> CWE
(:CVE)-[:HAS_WEAKNESS]->(:Weakness)           NVD
(:CVE)-[:AFFECTS]->(:Product)                 NVD configurations (CPE 2.3)
```
`CVE` carries `cvss`, `epss`, `epssPercentile`, `kev` (true when it's in CISA KEV) and
`kevDateAdded`. We load only the CVEs found in the cluster's images, plus all KEV CVEs, so the graph
stays under the AuraDB Free limit (200k nodes / 400k relationships).

### Infrastructure layer (KubeHound)
**All path finding uses one relationship type, `:ATTACKS`.** Like `:CONNECTS` in the grid
post, this keeps every traversal a single QPP, `(()-[r:ATTACKS]->())+`, with no long type unions.
Each `:ATTACKS` edge is one move an attacker can make from the source node to the target node:

| Property | Meaning |
|---|---|
| `techniqueId` | ATT&CK technique ID, e.g. `T1021.002`; joins to `(:Technique {id})` |
| `w` | weight, the effort or noise of the move (higher = harder), for weighted shortest paths and `reduce` / `allReduce` path costs |
| `kind` | the KubeHound attack name, e.g. `CE_PRIV_MOUNT`, `POD_EXEC`, `TOKEN_STEAL` |
| `tacticId` | ATT&CK tactic, also from KubeHound, e.g. `TA0004` |

Vertices: `Container` 1,819, `Endpoint` 232, `Pod` 1,641, `PermissionSet` 1,235, `Volume` 1,287, `Node` 8, `Identity` 990. The KubeHound attacks and the techniques they carry (from the export):

| ATT&CK | KubeHound attacks (`kind`) | edges |
|---|---|---|
| T1611 Escape to Host | `CE_MODULE_LOAD`, `CE_NSENTER`, `CE_PRIV_MOUNT`, `CE_SYS_PTRACE`, `CE_UMH_CORE_PATTERN`, `EXPLOIT_HOST_READ`, `EXPLOIT_HOST_WRITE` | 855 |
| T1609 Container Administration Command | `CONTAINER_ATTACH`, `POD_ATTACH`, `POD_EXEC`, `POD_PATCH` | 5,321 |
| T1610 Deploy Container | `POD_CREATE` | 65 |
| T1552 Unsecured Credentials | `TOKEN_STEAL`, `EXPLOIT_HOST_TRAVERSE`, `CE_VAR_LOG_SYMLINK` | 14,763 |
| T1528 Steal Application Access Token | `TOKEN_BRUTEFORCE`, `TOKEN_LIST` | 1,411 |
| T1078 Valid Accounts | `IDENTITY_ASSUME`, `ROLE_BIND` | 149,008 |
| T1210 Exploitation of Remote Services | `ENDPOINT_EXPLOIT` | 224 |
| T1080 Taint Shared Content | `SHARE_PS_NAMESPACE` | 464 |
| T1069 Permission Groups Discovery | `PERMISSION_DISCOVER` | 1,238 |
| T1613 Container and Resource Discovery | `VOLUME_ACCESS`, `VOLUME_DISCOVER` | 2,574 |

`w` is not in KubeHound's data. It is an **example cost model**: the attacker's effort per attack
kind, graded from the *Exploitation* section of each page in KubeHound's attack reference
(`docs/reference/attacks/<KIND>.md`). The table with a reason per attack is `WEIGHTS` in
`scripts/prepare_kubehound.py`; edit it and run `set_weights.py` to apply it without a reload.

| w | Effort | Edges |
|---|---|---|
| 0.5 | discovery: "No exploitation is necessary" (`PERMISSION_DISCOVER`, `VOLUME_DISCOVER`, `VOLUME_ACCESS`) | 3,812 |
| 1 | one standard command with access already held (`POD_EXEC`, `TOKEN_STEAL`, `CE_NSENTER`, `EXPLOIT_HOST_TRAVERSE`, …) | 19,717 |
| 2 | crafted but deterministic (`ROLE_BIND`, `POD_CREATE`, `CE_PRIV_MOUNT`, `EXPLOIT_HOST_WRITE`, …) | 151,018 |
| 3 | payload / compiled code / kernel tricks / no guaranteed success (`CE_MODULE_LOAD`, `TOKEN_BRUTEFORCE`, `ENDPOINT_EXPLOIT`, …) | 1,296 |

#### The cluster (`cluster/`)
A real kind cluster (Kubernetes v1.37, 1 control plane + 7 workers, `maxPods: 250`) with 1,641
running pods:

- **KubeHound's own fixtures and test users** in `default` / `vault`, deployed by its script.
- **90 tenant namespaces** (`tenant-001` … `tenant-090`, plus a `-vault` namespace each). Each one
  holds a seeded random 60% of KubeHound's fixture files (`render_tenants.py`, seed 7; the pick per
  tenant is in `cluster/out/tenants.plan.txt`). Cluster-scoped roles get a `-tenant-NNN` suffix, and
  `hostPort` is dropped (it fits only once per node).
- **4 Helm charts** at chart defaults, for production-like RBAC: ingress-nginx 4.15.1, cert-manager
  v1.21.3, Argo CD 10.11.6, kube-prometheus-stack 92.17.0 (`charts.sh`).

Every edge is computed by KubeHound itself; we only decide what runs in the cluster. **Known skew:**
`ROLE_BIND` is 84% of the edges. A namespace identity that may create RoleBindings and `bind` roles
can bind *any* ClusterRole in its namespace, and each tenant adds its own ClusterRoles, so these
edges grow with the square of the tenant count. `EXPLOIT_HOST_TRAVERSE` (7.8%) likewise grows with
the number of pods per node. The charts' workloads are well configured, so they add vertices (mostly
targets) but few edges.

The size is the practical limit of the build machine (32 GB RAM, Docker ~30 GB): with the cluster
running, KubeHound's backend no longer fits, so the cluster is dumped first and stopped before the
ingest (`build_graph.sh`).

### Showcase questions (`queries/`)
Written: `q1_easiest_paths` (cheapest paths to a critical asset within an effort budget),
`q2_effort_per_container`, `q3_easy_moves_only` (every attack `w <= cap`). Planned:
1. **Shortest attack paths** from an exposed endpoint or a compromised container to a cluster node
   (blast radius to the nodes) or a cluster-admin identity: `SHORTEST k` by hop count, and the cheapest paths
   by summed `w`; the ATT&CK technique sequence of each path.
2. **Only realistic moves:** QPP with an inline predicate on `:ATTACKS`, e.g. skip discovery moves,
   or (once images are scanned) exploit only KEV CVEs; `allReduce` over `w` to drop paths whose cost
   passes a budget.
3. **`TRAIL` vs `ACYCLIC` vs `WALK`:** tokens and role bindings create cycles (identity → permission
   set → pod → token → identity); compare result counts and runtime, as in the grid post.
4. **Choke points:** which single edge (a role binding, a privileged mount, a token) shows up on the
   most paths → the fix that cuts the most attack paths.
5. **Threat-informed:** which paths use only techniques a given ATT&CK group (e.g. APT29) is known
   to use, and which mitigations break them.

## Layout

```
scripts/
  db.py                    Neo4j connection helper (reads .env)
  fetch_sources.py         downloads ATT&CK, CAPEC, CWE, KEV, EPSS, NVD -> data/raw (cached, logged)
  export_kubehound.py      KubeHound's built graph (Gremlin, port 8182) -> data/raw/kubehound/graph/*.jsonl
  cpe.py                   CPE 2.3 parsing and NVD version-range matching
  prepare_kubehound.py     export -> data/import/kubehound/{nodes,attacks}.jsonl; the WEIGHTS table
  load_kubehound.py        loads them into Neo4j (:KubeHound, :ATTACKS)
  set_weights.py           re-applies WEIGHTS to the loaded graph (no reload)
  run_queries.py           runs queries/*.cypher -> blog/results/<name>.csv
  bench_gremlin_vs_cypher.py  KubeHound's questions in Gremlin (JanusGraph) and Cypher 25 (Neo4j)
  bench_weighted.py        per-attack cap and total budget, both engines, up to 15 hops
  prepare_knowledge.py     (stub) raw sources -> data/import/knowledge/*.csv
  generate_enterprise.py   (stub, superseded by KubeHound) synthetic company
  reset_db.py              deletes ALL data, constraints and indexes in the database
  load_knowledge.py        (stub) loads data/import/knowledge into Neo4j
  load_enterprise.py       (stub) loads data/import/enterprise into Neo4j (run after knowledge)
cluster/
  kind.yaml                the kind cluster: 1 control plane + 7 workers, 250 pods per node
  create_cluster.sh        (re)creates it: KubeHound fixtures + users, charts.sh, tenants
  charts.sh                pinned Helm charts (ingress-nginx, cert-manager, Argo CD, kube-prometheus-stack)
  render_tenants.py        KubeHound fixtures -> N tenant namespaces -> cluster/out/tenants.yaml
  build_graph.sh           dump -> KubeHound ingest -> export (--dump-only / --ingest-only)
  out/                     rendered manifests and logs (git-ignored)
queries/                   showcase questions as .cypher files
data/raw/                  downloaded sources (git-ignored); fetch.log = date, URL, size, SHA-256
data/import/               cleaned CSVs, ready to load
blog/                      post.md (article draft) and results/ (benchmark CSVs and logs)
dashboard/                 NeoDash / Aura Dashboards exports
```

## Rebuild from scratch

```bash
py -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
cp .env.example .env       # fill in from the Aura credentials file

cd scripts
../.venv/Scripts/python fetch_sources.py          # ~ATT&CK, CAPEC, CWE, KEV, EPSS + NVD 2002-today
```

### KubeHound graph (needs Docker Desktop with WSL 2, kind, kubectl)

KubeHound is used unchanged from its v1.6.7 release, cloned next to this project (no fork). Tools:
`winget install Kubernetes.kind Helm.Helm` (kubectl comes with Docker Desktop). The scripts find
kind and Helm in winget's package folder, since Git Bash doesn't see winget's PATH.

```bash
cd ..   # D:\Users\Harold\Documents\Blog
git clone --depth 1 --branch v1.6.7 https://github.com/DataDog/KubeHound.git
mkdir -p KubeHound/bin && curl -L -o KubeHound/bin/kubehound.exe \
  https://github.com/DataDog/KubeHound/releases/download/v1.6.7/kubehound-windows-x86_64.exe
# check against kubehound-windows-x86_64.exe.sha256 from the same release
cd APA

bash cluster/create_cluster.sh 90 0.6     # kind cluster + KubeHound fixtures + charts + tenants (~20 min)
bash cluster/build_graph.sh --dump-only   # raw k8s resources -> data/raw/kubehound (kept for provenance)
docker stop $(docker ps -q --filter name=kubehound.test.local-)   # free CPU/RAM for the backend
bash cluster/build_graph.sh --ingest-only # KubeHound backend + ingest, then export_kubehound.py
```

Windows / Git Bash workarounds, all inside the scripts: KubeHound's setup script sets `KUBECONFIG`
before reading its `.config`, so `.config` is loaded first; `MSYS2_ARG_CONV_EXCL="/CN"` stops Git
Bash rewriting openssl's `/CN=...` subject as a path; `dump` needs `-y`; the Windows build unpacks a
`.tar.gz` into a hard-coded `/tmp`, so the dump is extracted and the folder is ingested.

### Neo4j

```bash
cd scripts
../.venv/Scripts/python prepare_knowledge.py      # TODO
../.venv/Scripts/python reset_db.py               # careful: wipes the target database
../.venv/Scripts/python load_knowledge.py         # TODO
../.venv/Scripts/python load_enterprise.py        # TODO
../.venv/Scripts/python prepare_kubehound.py
../.venv/Scripts/python load_kubehound.py          # Aura Free: ~10 min; local: ~35 s
```

### Benchmarks (local, same machine as KubeHound's backend)

```bash
docker run -d --name apa-neo4j -p 7474:7474 -p 7687:7687   -e NEO4J_AUTH=neo4j/apa-bench-local -e NEO4J_server_memory_heap_max__size=4G   neo4j:2026.10.1-community
cd scripts
export NEO4J_URI=neo4j://127.0.0.1:7687 NEO4J_USERNAME=neo4j NEO4J_PASSWORD=apa-bench-local NEO4J_DATABASE=neo4j
../.venv/Scripts/python load_kubehound.py
../.venv/Scripts/python bench_gremlin_vs_cypher.py    # needs KubeHound's backend up (port 8182)
../.venv/Scripts/python bench_weighted.py
../.venv/Scripts/python run_queries.py
```
KubeHound's JanusGraph runs in-memory with a 4 GB heap, so the local Neo4j gets the same heap.
JanusGraph's schema (fixed by KubeHound's init script) doesn't accept a new `w` edge property, so
the Gremlin side of `bench_weighted.py` looks weights up by edge label instead.

## License

Code: **MIT** (`LICENSE`). Blog text: **CC BY 4.0**. Data keeps its sources' terms, and MITRE
data requires an attribution notice: see [LICENSE.md](LICENSE.md). © 2026 Harold Agudelo.

## Sources

Checked 2 Nov 2026.

### Data
- **MITRE ATT&CK** Enterprise, STIX 2.1: <https://github.com/mitre-attack/attack-stix-data>
  (v20.0, 13 Oct 2026). Terms: <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>.
  Free for research and commercial use; copies must carry MITRE's copyright notice.
- **MITRE CAPEC**: <https://capec.mitre.org/data/xml/capec_latest.xml>. Same MITRE terms of use.
- **MITRE CWE**: <https://cwe.mitre.org/data/xml/cwec_latest.xml.zip>. Terms:
  <https://cwe.mitre.org/about/termsofuse.html>.
- **NVD CVE / CPE** (NIST): CVE API 2.0 JSON, taken from the daily mirror
  <https://github.com/fkie-cad/nvd-json-data-feeds> (one `CVE-<year>.json.xz` per year). NVD data
  is a U.S. government work. Official API: <https://nvd.nist.gov/developers/vulnerabilities>; on
  2 Nov 2026 `nvd.nist.gov` didn't resolve from the build machine, which is why we use the mirror.
- **CISA Known Exploited Vulnerabilities**:
  <https://www.cisa.gov/known-exploited-vulnerabilities-catalog> (JSON feed; catalog 2026.10.30,
  1,766 CVEs). U.S. government work.
- **FIRST EPSS**: <https://www.first.org/epss/data>, daily file
  <https://epss.empiricalsecurity.com/epss_scores-current.csv.gz>. Free, no registration.

- **KubeHound** v1.6.7 (Datadog, Apache-2.0): <https://github.com/DataDog/KubeHound>, docs
  <https://kubehound.io/>, attack reference <https://kubehound.io/reference/attacks/>. Release binary
  `kubehound-windows-x86_64.exe` (SHA-256 `a7d509ee…a0b`, checked). Fixtures from its test cluster
  (`test/setup/test-cluster/attacks/*.yaml`); graph built on 3 Nov 2026, export metadata (KubeHound
  run ID, counts) in `data/raw/kubehound/graph/export.json`.
- **Helm charts** (all Apache-2.0): ingress-nginx 4.15.1 (<https://kubernetes.github.io/ingress-nginx>),
  cert-manager v1.21.3 (<https://charts.jetstack.io>), Argo CD 10.11.6
  (<https://argoproj.github.io/argo-helm>), kube-prometheus-stack 92.17.0
  (<https://prometheus-community.github.io/helm-charts>).

### Considered, not used (yet)
- **LANL Comprehensive, Multi-Source Cyber-Security Events** (A. D. Kent, 2015,
  doi:10.17021/1179829): <https://csr.lanl.gov/data/cyber1/>. Real, anonymized data from 58 days:
  1.6 billion events, 12,425 users, 17,684 computers, with a red-team ground truth file. **CC0**, but
  you have to register (email + intended use) to download, and it is 12 GB compressed. It has no
  software inventory, so it can't use the CVE bridge. A candidate for a "real lateral movement"
  follow-up.
- **BRON** (MIT ALFA group, MIT license): <https://github.com/ALFA-group/BRON>. ATT&CK, CAPEC, CWE,
  CVE, D3FEND and more already linked, built for ArangoDB. We build the same links ourselves from
  the primary sources so every edge is traceable.
- **BloodHound** (SpecterOps, Apache-2.0) and **BloodHound-Tools / DBCreator** (LGPL-3.0, last
  updated June 2024): synthetic Active Directory data. Our enterprise layer borrows its edge
  semantics.
- **GOAD**, Game of Active Directory (Orange Cyberdefense, GPL-3.0): a vulnerable AD lab; needs
  VMs to produce data.
- **Cartography** (CNCF, Apache-2.0): loads real AWS / Azure / GCP accounts into Neo4j.

### Neo4j
- Match modes and path modes: <https://neo4j.com/docs/cypher-manual/25/patterns/reference/match-modes-and-path-modes/>
- ACYCLIC paths: <https://neo4j.com/docs/cypher-manual/current/patterns/acyclic-paths/>
- Shortest paths: <https://neo4j.com/docs/cypher-manual/current/patterns/shortest-paths/>

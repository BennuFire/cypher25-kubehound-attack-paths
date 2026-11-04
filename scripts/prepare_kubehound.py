"""KubeHound graph export (data/raw/kubehound/graph) -> data/import/kubehound/{nodes,attacks}.jsonl.

Every KubeHound edge is an attack and becomes one :ATTACKS relationship with
  kind         the KubeHound attack name (CE_PRIV_MOUNT, ROLE_BIND, ...)
  techniqueId  ATT&CK technique, as KubeHound tags it (attckTechniqueID)
  tacticId     ATT&CK tactic, as KubeHound tags it (attckTacticID)
  w            our weight for the attack type (WEIGHTS below; KubeHound has none)
Parallel attacks between the same two nodes stay separate edges (different moves).

Self-loops (a PermissionSet "attacking" itself: every POD_CREATE, and the PermissionSet ->
PermissionSet POD_PATCH / POD_EXEC) add nothing to a path, so they are dropped and kept as the node
property selfAttacks, e.g. ['POD_CREATE'].

JSONL instead of CSV so the property types (booleans, integers, lists) survive: KubeHound's vertex
properties differ per label.
"""
import json
import re
from collections import Counter, defaultdict

from db import ROOT

RAW = ROOT / "data" / "raw" / "kubehound" / "graph"
OUT = ROOT / "data" / "import" / "kubehound"

# w = attacker effort to make the move, given the source node. KubeHound has no weights: this is an
# EXAMPLE cost model, graded from the Exploitation section of each attack's page in KubeHound's docs
# (docs/reference/attacks/<KIND>.md). Change it freely; set_weights.py applies it without a reload.
#   0.5  discovery: the doc says "No exploitation is necessary"
#   1    direct use: one standard command with access already held (kubectl exec, cat a token)
#   2    crafted but deterministic: a crafted manifest / API call, or a few host-file steps
#   3    hard: payload or compiled code, kernel tricks, offline work, or success not guaranteed
WEIGHTS = {
    "PERMISSION_DISCOVER": 0.5, "VOLUME_DISCOVER": 0.5, "VOLUME_ACCESS": 0.5,
    "POD_EXEC": 1,               # kubectl exec --stdin --tty <POD NAME> -- /bin/bash
    "CONTAINER_ATTACH": 1,       # one kubectl debug command
    "TOKEN_STEAL": 1,            # read the mounted service account token
    "TOKEN_LIST": 1,             # "Simply dump all secrets using kubectl"
    "IDENTITY_ASSUME": 1,        # use the token / kubelet certificate found
    "EXPLOIT_HOST_TRAVERSE": 1,  # ls/find the token symlinks under the mounted host path
    "SHARE_PS_NAMESPACE": 1,     # read /proc/<pid>/root of the neighbour container
    "CE_NSENTER": 1,             # nsenter --target 1 ... -- bash
    "ROLE_BIND": 2,              # kubectl create rolebinding ... (crafted RBAC object)
    "POD_CREATE": 2,             # craft an overprivileged pod spec and apply it
    "POD_PATCH": 2,              # patch the pod to a backdoored image
    "POD_ATTACH": 2,             # "The only obstacle is the right tooling" (ctr on the node)
    "CE_PRIV_MOUNT": 2,          # mount the host disk, then a host write to get execution
    "CE_VAR_LOG_SYMLINK": 2,     # symlink in /var/log plus kubelet log API calls
    "EXPLOIT_HOST_WRITE": 2,     # write a cron.d reverse shell on the host mount
    "CE_MODULE_LOAD": 3,         # load a precompiled kernel module for the host's kernel
    "CE_SYS_PTRACE": 3,          # gdb into a host process and inject a shell
    "CE_UMH_CORE_PATTERN": 3,    # write and compile a crasher, hijack core_pattern
    "EXPLOIT_HOST_READ": 3,      # dump process memory, extract SSH keys offline
    "TOKEN_BRUTEFORCE": 3,       # "can be complex and time-consuming"
    "ENDPOINT_EXPLOIT": 3,       # the edge "does not signal that the endpoint is exploitable":
                                 # crossing it needs a vulnerability KubeHound doesn't know about
}
# KubeHound bookkeeping we don't load: 'class' repeats the label, the run ID and cluster are one
# value for the whole graph (kept in data/raw/kubehound/graph/export.json)
DROP = {"class", "label", "id", "storeID", "runID", "cluster"}
TENANT = re.compile(r"tenant-\d{3}")


def main():
    vertices = [json.loads(l) for l in open(RAW / "vertices.jsonl", encoding="utf-8")]
    edges = [json.loads(l) for l in open(RAW / "edges.jsonl", encoding="utf-8")]
    store_id = {v["id"]: v["storeID"] for v in vertices}

    unknown = {e["label"] for e in edges} - WEIGHTS.keys()
    if unknown:
        raise SystemExit(f"no weight for KubeHound attack(s): {sorted(unknown)}")

    self_attacks = defaultdict(set)
    attacks = []
    for e in edges:
        if e["from"] == e["to"]:
            self_attacks[e["from"]].add(e["label"])
            continue
        attacks.append({"from": store_id[e["from"]], "to": store_id[e["to"]], "kind": e["label"],
                        "techniqueId": e["attckTechniqueID"], "tacticId": e["attckTacticID"],
                        "w": WEIGHTS[e["label"]]})

    nodes = []
    for v in vertices:
        # KubeHound writes "" for unset values: leave those properties out
        props = {k: x for k, x in v.items() if k not in DROP and x != ""}
        # tenant from the namespace, or for cluster-scoped objects from the -tenant-NNN name suffix
        m = TENANT.search(v.get("namespace") or "") or TENANT.search(v.get("name") or "")
        props["tenant"] = m.group(0) if m else None
        if v["id"] in self_attacks:
            props["selfAttacks"] = sorted(self_attacks[v["id"]])
        nodes.append({"id": v["storeID"], "label": v["label"], "props": props})

    OUT.mkdir(parents=True, exist_ok=True)
    for name, rows in (("nodes", nodes), ("attacks", attacks)):
        with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
    print(f"nodes   {len(nodes):>7}  {dict(Counter(n['label'] for n in nodes))}")
    print(f"attacks {len(attacks):>7}  (dropped {len(edges) - len(attacks)} self-loops: "
          f"{dict(Counter(a for s in self_attacks.values() for a in s))})")


if __name__ == "__main__":
    main()

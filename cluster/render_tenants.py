"""Render KubeHound's vulnerable test fixtures into many tenant namespaces -> cluster/out/tenants.yaml.

KubeHound's own test cluster (test/setup/test-cluster/attacks/*.yaml, one file per attack) gives a
graph of ~1k edges. To get a bigger *real* cluster we deploy copies of those fixtures into N tenant
namespaces, each tenant taking a seeded random subset of the fixture files, so tenants differ.
KubeHound then computes every attack edge itself from the running cluster.

Renaming rules:
- namespaced objects (Pod, Role, RoleBinding, ServiceAccount, Service): namespace 'default' ->
  '<tenant>', 'vault' -> '<tenant>-vault'
- cluster-scoped objects (ClusterRole, ClusterRoleBinding): name + '-<tenant>', so copies don't
  collide; references to fixture ClusterRoles follow, built-in ones (e.g. cluster-admin) stay
- ServiceAccount subjects follow the namespace mapping; User / Group subjects stay (the users
  KubeHound's setup script creates are cluster-wide)
- container hostPort is dropped (it fits once per node)

    python render_tenants.py --tenants 40 --share 0.5 --seed 7
"""
import argparse
import random
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT.parent / "KubeHound" / "test" / "setup" / "test-cluster" / "attacks"
OUT = ROOT / "cluster" / "out"
CLUSTER_SCOPED = {"ClusterRole", "ClusterRoleBinding"}


def load_fixtures():
    fixtures = {}
    for f in sorted(FIXTURES.glob("*.yaml")):
        fixtures[f.stem] = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
    return fixtures


def render(doc, tenant, fixture_crs):
    doc = yaml.safe_load(yaml.safe_dump(doc))  # deep copy
    ns_map = {"default": tenant, "vault": f"{tenant}-vault"}
    meta = doc.setdefault("metadata", {})
    if doc["kind"] in CLUSTER_SCOPED:
        meta["name"] = f"{meta['name']}-{tenant}"
    else:
        meta["namespace"] = ns_map[meta.get("namespace", "default")]
    meta.setdefault("labels", {})["apa.tenant"] = tenant
    ref = doc.get("roleRef")
    if ref and ref["kind"] == "ClusterRole" and ref["name"] in fixture_crs:
        ref["name"] = f"{ref['name']}-{tenant}"
    for s in doc.get("subjects", []) or []:
        if s["kind"] == "ServiceAccount":
            s["namespace"] = ns_map[s.get("namespace", "default")]
    # a hostPort fits once per node, so copies would stay Pending; the container port stays
    for c in doc.get("spec", {}).get("containers", []) if doc["kind"] == "Pod" else []:
        for p in c.get("ports", []):
            p.pop("hostPort", None)
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--tenants", type=int, default=40)
    ap.add_argument("--share", type=float, default=0.5, help="share of fixture files per tenant")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    fixtures = load_fixtures()
    fixture_crs = {d["metadata"]["name"] for docs in fixtures.values() for d in docs
                   if d["kind"] == "ClusterRole"}
    rnd = random.Random(args.seed)
    out, plan = [], []
    for i in range(1, args.tenants + 1):
        tenant = f"tenant-{i:03d}"
        picked = sorted(rnd.sample(sorted(fixtures), max(1, round(args.share * len(fixtures)))))
        plan.append(f"{tenant}: {', '.join(picked)}")
        for ns in (tenant, f"{tenant}-vault"):
            out.append({"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": ns, "labels": {"apa.tenant": tenant}}})
        out += [render(d, tenant, fixture_crs) for name in picked for d in fixtures[name]]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "tenants.yaml").write_text(yaml.safe_dump_all(out, sort_keys=False), encoding="utf-8")
    (OUT / "tenants.plan.txt").write_text("\n".join(plan) + "\n", encoding="utf-8")
    pods = sum(d["kind"] == "Pod" for d in out)
    print(f"{args.tenants} tenants, {len(out)} objects, {pods} pods -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

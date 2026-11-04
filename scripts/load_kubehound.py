"""Load data/import/kubehound/{nodes,attacks}.jsonl into Neo4j.

Nodes get the :KubeHound source label plus their KubeHound label (:KubeHound:Container, ...).
Attacks become (a)-[:ATTACKS {kind, techniqueId, tacticId, w}]->(b); MERGE on kind keeps parallel
attacks between the same two nodes as separate relationships, and makes reloading safe.
"""
import json
from collections import defaultdict

from db import ROOT, Graph

DATA = ROOT / "data" / "import" / "kubehound"
LABELS = ["Container", "Pod", "Node", "Identity", "PermissionSet", "Volume", "Endpoint"]

SCHEMA = [
    # Neo4j orders labels(n) by when each label name first appeared, so the source label goes
    # first (only works on a brand-new database, see reset_db.py)
    "CREATE (n:KubeHound) DELETE n",
    "CREATE CONSTRAINT kubehound_id IF NOT EXISTS FOR (n:KubeHound) REQUIRE n.id IS UNIQUE",
    *(f"CREATE INDEX {l.lower()}_name IF NOT EXISTS FOR (n:{l}) ON (n.name)" for l in LABELS),
    "CREATE INDEX kubehound_tenant IF NOT EXISTS FOR (n:KubeHound) ON (n.tenant)",
    "CREATE INDEX kubehound_namespace IF NOT EXISTS FOR (n:KubeHound) ON (n.namespace)",
    "CREATE INDEX attacks_kind IF NOT EXISTS FOR ()-[r:ATTACKS]-() ON (r.kind)",
    "CREATE INDEX attacks_technique IF NOT EXISTS FOR ()-[r:ATTACKS]-() ON (r.techniqueId)",
]

NODES = """
    MERGE (n:KubeHound {{id: row.id}})
    SET n:{label}, n += row.props"""
ATTACKS = """
    MATCH (a:KubeHound {id: row.from}), (b:KubeHound {id: row.to})
    MERGE (a)-[r:ATTACKS {kind: row.kind}]->(b)
    SET r.techniqueId = row.techniqueId, r.tacticId = row.tacticId, r.w = row.w"""


def read(name):
    return [json.loads(l) for l in open(DATA / f"{name}.jsonl", encoding="utf-8")]


def main():
    with Graph() as g:
        for stmt in SCHEMA:
            g.run(stmt)
        by_label = defaultdict(list)
        for n in read("nodes"):
            by_label[n["label"]].append(n)
        for label in LABELS:
            g.load(NODES.format(label=label), by_label.pop(label, []))
            print(f"{label:14s} loaded")
        if by_label:
            raise RuntimeError(f"unexpected labels: {sorted(by_label)}")
        attacks = read("attacks")
        g.load(ATTACKS, attacks, batch=5000)
        print(f"attacks        {len(attacks):>7} rows")
        print("graph:", g.counts())


if __name__ == "__main__":
    main()

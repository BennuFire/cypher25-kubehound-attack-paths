"""Export the attack graph KubeHound built (its Gremlin backend) -> data/raw/kubehound/graph/.

KubeHound itself is used unchanged (pinned release, see README): its dump holds only raw Kubernetes
resources, and its Go ingest pipeline decides which attacks apply. We take the graph it built, so
KubeHound stays the authority on the attack logic.

Needs the KubeHound backend running (`kubehound backend up`) with the cluster ingested.

    python export_kubehound.py [--url ws://127.0.0.1:8182/gremlin]

Writes vertices.jsonl, edges.jsonl and export.json (counts, cluster, KubeHound run ID, date).
"""
import argparse
import datetime as dt
import json

from gremlin_python.driver import client, serializer

from db import ROOT

OUT = ROOT / "data" / "raw" / "kubehound" / "graph"
PAGE = 500


def flat(value_map):
    """Gremlin valueMap gives every property as a list; unwrap the single values."""
    return {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in value_map.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--url", default="ws://127.0.0.1:8182/gremlin")
    args = ap.parse_args()

    c = client.Client(args.url, "kh", message_serializer=serializer.GraphSONSerializersV3d0())
    q = lambda s, **b: c.submit(s, b).all().result()
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        n_v = q("g.V().count()")[0]
        with open(OUT / "vertices.jsonl", "w", encoding="utf-8") as f:
            for lo in range(0, n_v, PAGE):
                for r in q("g.V().order().by(id).range(lo, hi)"
                           ".project('id', 'label', 'props').by(id).by(label).by(valueMap())",
                           lo=lo, hi=lo + PAGE):
                    f.write(json.dumps({"id": r["id"], "label": r["label"], **flat(r["props"])}) + "\n")

        n_e = q("g.E().count()")[0]
        with open(OUT / "edges.jsonl", "w", encoding="utf-8") as f:
            # JanusGraph edge ids are objects, so edges are paged by their out-vertex instead
            out_ids = q("g.E().outV().id().dedup()")
            for i in range(0, len(out_ids), PAGE):
                for r in q("g.V(ids).outE().project('label', 'from', 'to', 'props')"
                           ".by(label).by(outV().id()).by(inV().id()).by(valueMap())",
                           ids=out_ids[i:i + PAGE]):
                    f.write(json.dumps({"label": r["label"], "from": r["from"], "to": r["to"],
                                        **r["props"]}) + "\n")

        meta = {
            "exportedAt": dt.datetime.now().isoformat(timespec="seconds"),
            "vertices": n_v, "edges": n_e,
            "vertexLabels": q("g.V().groupCount().by(label)")[0],
            "edgeLabels": q("g.E().groupCount().by(label)")[0],
            "clusters": q("g.V().values('cluster').dedup()"),
            "runIDs": q("g.V().values('runID').dedup()"),
        }
    finally:
        c.close()
    (OUT / "export.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"vertices {n_v}, edges {n_e} -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

"""Same attack-path questions on KubeHound's JanusGraph (Gremlin) and on Neo4j (Cypher 25).

Both databases hold the same graph: the JanusGraph backend still holds KubeHound's own build, and
Neo4j holds our load of its export (load_kubehound.py). Each question is written twice:
  gremlin  as KubeHound queries it (its `kh` DSL, or the plain Gremlin from its docs)
  cypher   the Cypher 25 equivalent, with ACYCLIC for Gremlin's simplePath()
The path counts must match; the script raises the hop limit until an engine times out.

Fair timing: JanusGraph runs in Docker on this machine (in-memory backend, 4 GB heap), so the
reference Neo4j is a local Docker container with the same heap (neo4j:2026.10.1-community).
--aura adds the AuraDB Free instance from .env, which is remote and much smaller.
Times are wall-clock from the client, median of the timed runs, results counted server-side.

    python bench_gremlin_vs_cypher.py [--aura] [--timeout 60] [--runs 3] [--max-hops 10]
"""
import argparse
import csv
import logging
import statistics
import time

from dotenv import dotenv_values
from gremlin_python.driver import client, serializer
from neo4j import GraphDatabase, Query

from db import ROOT

# the Gremlin driver logs every server timeout with a full Java stack trace
logging.getLogger("gremlinpython").setLevel(logging.CRITICAL)

OUT = ROOT / "blog" / "results"
TENANT = "tenant-001"

# Paths stop at the first target, like Gremlin's repeat().until(target), so intermediate nodes
# must not be targets. Gremlin's loops().is(h) caps the path at h edges.
CASES = [
    {
        "case": "critical_paths",
        "what": f"containers of {TENANT} -> first critical PermissionSet (KubeHound DSL criticalPaths)",
        "gremlin": "kh.V().has('class','Container').has('namespace', ns).criticalPaths({h}).count()",
        "start": "(s:Container {namespace: $ns})",
        "via": "x.critical IS NULL OR NOT x.critical",
        "end": "(:PermissionSet {critical: true})",
    },
    {
        "case": "container_to_node",
        "what": f"containers of {TENANT} -> first Node: blast radius to the nodes (KubeHound docs, 'basic attack paths')",
        "gremlin": "g.V().has('class','Container').has('namespace', ns)"
                   ".repeat(out().simplePath()).until(has('class','Node').or().loops().is({h}))"
                   ".has('class','Node').path().count()",
        "start": "(s:Container {namespace: $ns})",
        "via": "NOT x:Node",
        "end": "(:Node)",
    },
]


def cypher(case, h):
    """Paths of at most h edges whose intermediate nodes satisfy `via` and whose last node is `end`.
    One hop is a plain pattern: Cypher takes neither a {0,0} quantifier nor two node patterns side
    by side without one."""
    if h == 1:
        path = f"(s)-[:ATTACKS]->{case['end']}"
    else:
        path = (f"(s) (()-[:ATTACKS]->(x WHERE {case['via']})){{0,{h - 1}}} "
                f"()-[:ATTACKS]->{case['end']}")
    return f"CYPHER 25 MATCH {case['start']} MATCH p = ACYCLIC {path} RETURN count(p) AS n"


class Gremlin:
    name = "gremlin-janusgraph"

    def __init__(self, url):
        self.c = client.Client(url, "kh", message_serializer=serializer.GraphSONSerializersV3d0())

    def count(self, case, h, timeout):
        q = case["gremlin"].format(h=h)
        return self.c.submit(q, {"ns": TENANT},
                             request_options={"evaluationTimeout": timeout * 1000}).all().result()[0]

    def close(self):
        self.c.close()


class Cypher:
    def __init__(self, name, uri, user, password, database):
        self.name, self.database = name, database or None
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def count(self, case, h, timeout):
        q = cypher(case, h)
        with self.driver.session(database=self.database) as s:
            return s.run(Query(q, timeout=timeout), ns=TENANT).single()["n"]

    def close(self):
        self.driver.close()


def measure(engine, case, h, timeout, runs):
    """(paths, median ms, runs done, status). One warm-up run; slow queries get no repeats."""
    times = []
    try:
        for i in range(runs + 1):
            t = time.perf_counter()
            n = engine.count(case, h, timeout)
            ms = (time.perf_counter() - t) * 1000
            if i > 0 or ms > timeout * 1000 / 3:   # keep the warm-up if it was already slow
                times.append(ms)
            if ms > timeout * 1000 / 3:
                break
        return n, statistics.median(times), len(times), "ok"
    except Exception as ex:  # timeouts come back as server errors
        msg = str(ex).splitlines()[0]
        status = "timeout" if "imeout" in msg or "imed out" in msg else f"error: {msg[:80]}"
        return None, None, 0, status


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--aura", action="store_true", help="also run on the AuraDB instance in .env")
    ap.add_argument("--timeout", type=int, default=60, help="seconds per query")
    ap.add_argument("--runs", type=int, default=3, help="timed runs after one warm-up")
    ap.add_argument("--max-hops", type=int, default=10)
    ap.add_argument("--gremlin", default="ws://127.0.0.1:8182/gremlin")
    ap.add_argument("--neo4j", default="neo4j://127.0.0.1:7687")
    ap.add_argument("--neo4j-password", default="apa-bench-local")
    args = ap.parse_args()

    engines = [Gremlin(args.gremlin),
               Cypher("neo4j-local", args.neo4j, "neo4j", args.neo4j_password, "neo4j")]
    if args.aura:
        env = dotenv_values(ROOT / ".env")
        engines.append(Cypher("neo4j-aura", env["NEO4J_URI"], env["NEO4J_USERNAME"],
                              env["NEO4J_PASSWORD"], env.get("NEO4J_DATABASE")))

    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    with open(OUT / "bench_gremlin_vs_cypher.log", "w", encoding="utf-8") as log:
        def say(s):
            print(s, flush=True)
            log.write(s + "\n")

        for case in CASES:
            say(f"\n== {case['case']}: {case['what']}")
            alive = {e.name for e in engines}
            for h in range(1, args.max_hops + 1):
                counts = {}
                for e in engines:
                    if e.name not in alive:
                        continue
                    n, ms, done, status = measure(e, case, h, args.timeout, args.runs)
                    counts[e.name] = n
                    rows.append({"case": case["case"], "hops": h, "engine": e.name, "paths": n,
                                 "ms_median": None if ms is None else round(ms, 1),
                                 "runs": done, "status": status})
                    say(f"h={h:<2} {e.name:20s} paths={n!s:>12}  "
                        f"{'' if ms is None else f'{ms:10.1f} ms'}  {status}")
                    if status != "ok":
                        alive.discard(e.name)
                got = {v for v in counts.values() if v is not None}
                if len(got) > 1:
                    say(f"     !! path counts differ: {counts}")
                if not alive:
                    break

    with open(OUT / "bench_gremlin_vs_cypher.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for e in engines:
        e.close()


if __name__ == "__main__":
    main()

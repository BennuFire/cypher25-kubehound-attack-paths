"""Weighted attack paths: limit what each attack may cost, or what the whole path may cost.

Same question as bench_gremlin_vs_cypher.py (containers of tenant-001 -> first critical
PermissionSet), now with the attack weights w (prepare_kubehound.py, an example cost model):
  cap      every attack on the path has w <= cap               ("easy moves only")
  budget   the attacks on the path add up to at most budget     ("total effort")
Both are checked while the path grows, so they also bound the search: the hop limit can go up to
15, KubeHound's maximum, where the unweighted search times out at 7.

Cypher 25 checks the cap inline (-[r WHERE r.w <= $cap]->) and the budget with allReduce over the
QPP's relationship group. Slower ways of writing the same questions are measured too:
  budget_relsp       allReduce over relationships(p)
  budget_after       reduce() in a plain WHERE: the only option before allReduce (Neo4j 2025.08)
  single_qpp(_budget) one QPP that ends at the target, without a last hop of its own
Gremlin (KubeHound's JanusGraph) gets the same rules with native steps: KubeHound's schema has no
w on its edges, so the cap is the list of edge labels with w <= cap (as in KubeHound's
criticalPathsFilter) and the budget is a sack() that looks the weight up by label.

    python bench_weighted.py [--timeout 60] [--runs 3] [--no-gremlin]
"""
import argparse
import asyncio
import csv
import sys
import warnings

from neo4j import Query

from bench_gremlin_vs_cypher import OUT, TENANT, Cypher, Gremlin, measure
from prepare_kubehound import WEIGHTS

if sys.platform == "win32":  # quiet the Proactor "event loop self pipe" noise of the Gremlin driver
    warnings.simplefilter("ignore", DeprecationWarning)
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOPS = [5, 6, 7, 8, 10, 15]
VIA = "x.critical IS NULL OR NOT x.critical"   # stop at the first critical asset
CRITICAL = "(:PermissionSet {critical: true})"
COST = "reduce(c = 0.0, e IN r | c + e.w) + l.w"


def cypher(h, cap=None, where=""):
    """Containers -> first critical PermissionSet in at most h attacks. The last attack is a hop of
    its own, so the planner can start from the 109 critical targets and join in the middle."""
    rw = "" if cap is None else f" WHERE r.w <= {cap}"
    lw = "" if cap is None else f" WHERE l.w <= {cap}"
    return (f"CYPHER 25 MATCH (s:Container {{namespace: $ns}}) "
            f"MATCH p = ACYCLIC (s) (()-[r:ATTACKS{rw}]->(x WHERE {VIA})){{0,{h - 1}}} "
            f"()-[l:ATTACKS{lw}]->{CRITICAL} {where} RETURN count(p) AS n")


def single_qpp(h, where=""):
    """The same question as one QPP that ends at the target: no join, every last hop is expanded."""
    return (f"CYPHER 25 MATCH (s:Container {{namespace: $ns}}) "
            f"MATCH p = ACYCLIC (s) ((a WHERE a.critical IS NULL OR NOT a.critical)-[r:ATTACKS]->()){{1,{h}}} "
            f"{CRITICAL} {where} RETURN count(p) AS n")


def budget(b):
    return f"WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= {b}) AND {COST} <= {b}"


W_BY_LABEL = "choose(label())" + "".join(f".option('{k}', constant({float(w)}d))"
                                          for k, w in WEIGHTS.items())


def gremlin(h, step, sack=False):
    src = "g.withSack(0.0d)" if sack else "g"
    return (f"{src}.V().has('class','Container').has('namespace', ns)"
            f".repeat({step}.inV().simplePath())"
            f".until(has('critical',true).or().loops().is({h}))"
            f".has('critical',true).path().count()")


def cap_labels(cap):
    return ",".join(f"'{k}'" for k, w in sorted(WEIGHTS.items()) if w <= cap)


def variants():
    yield {"case": "unweighted", "limit": None,
           "cypher": lambda h: cypher(h), "gremlin": lambda h: gremlin(h, "outE()")}
    for cap in (1, 2):
        yield {"case": "cap", "limit": cap,
               "cypher": lambda h, c=cap: cypher(h, cap=c),
               "gremlin": lambda h, c=cap: gremlin(h, f"outE({cap_labels(c)})")}
    for b in (3, 4, 5, 6, 8):
        yield {"case": "budget", "limit": b,
               "cypher": lambda h, b=b: cypher(h, where=budget(b)),
               "gremlin": lambda h, b=b: gremlin(
                   h, f"outE().sack(sum).by({W_BY_LABEL}).filter(sack().is(lte({float(b)}d)))", sack=True)}
    yield {"case": "cap+budget", "limit": "2/6",
           "cypher": lambda h: cypher(h, cap=2, where=budget(6)),
           "gremlin": lambda h: gremlin(h, f"outE({cap_labels(2)}).sack(sum).by({W_BY_LABEL})"
                                           ".filter(sack().is(lte(6.0d)))", sack=True)}
    # the same budget, written in ways that don't prune while the path grows
    yield {"case": "budget_relsp", "limit": 4,
           "cypher": lambda h: cypher(h, where="WHERE allReduce(c = 0.0, e IN relationships(p) | c + e.w, c <= 4)")}
    yield {"case": "budget_after", "limit": 4,
           "cypher": lambda h: cypher(h, where=f"WHERE {COST} <= 4")}
    # the same questions as a single QPP (see single_qpp)
    yield {"case": "single_qpp", "limit": None, "cypher": lambda h: single_qpp(h)}
    yield {"case": "single_qpp_budget", "limit": 4,
           "cypher": lambda h: single_qpp(h, "WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= 4)")}


class Run:
    """Adapts a variant to measure(): engine.count(case, h, timeout)."""

    def __init__(self, engine, key):
        self.engine, self.key, self.name = engine, key, engine.name

    def count(self, v, h, timeout):
        q = v[self.key](h)
        if self.key == "gremlin":
            return self.engine.c.submit(q, {"ns": TENANT}, request_options={
                "evaluationTimeout": timeout * 1000}).all().result()[0]
        with self.engine.driver.session(database=self.engine.database) as s:
            return s.run(Query(q, timeout=timeout), ns=TENANT).single()["n"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--no-gremlin", action="store_true")
    ap.add_argument("--neo4j", default="neo4j://127.0.0.1:7687")
    ap.add_argument("--neo4j-password", default="apa-bench-local")
    args = ap.parse_args()

    neo = Cypher("neo4j-local", args.neo4j, "neo4j", args.neo4j_password, "neo4j")
    runs = [Run(neo, "cypher")]
    if not args.no_gremlin:
        runs.insert(0, Run(Gremlin("ws://127.0.0.1:8182/gremlin"), "gremlin"))

    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    with open(OUT / "bench_weighted.log", "w", encoding="utf-8") as log:
        def say(s):
            print(s, flush=True)
            log.write(s + "\n")

        for v in variants():
            say(f"\n== {v['case']} {'' if v['limit'] is None else v['limit']}")
            alive = {r.name for r in runs if r.key in v}
            for h in HOPS:
                counts = {}
                for r in runs:
                    if r.name not in alive:
                        continue
                    n, ms, done, status = measure(r, v, h, args.timeout, args.runs)
                    counts[r.name] = n
                    rows.append({"case": v["case"], "limit": v["limit"], "hops": h, "engine": r.name,
                                 "paths": n, "ms_median": None if ms is None else round(ms, 1),
                                 "runs": done, "status": status})
                    say(f"h={h:<2} {r.name:20s} paths={n!s:>10}  "
                        f"{'' if ms is None else f'{ms:10.1f} ms'}  {status}")
                    if status != "ok":
                        alive.discard(r.name)
                if len({c for c in counts.values() if c is not None}) > 1:
                    say(f"     !! path counts differ: {counts}")
                if not alive:
                    break

    with open(OUT / "bench_weighted.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for r in runs:
        r.engine.close()


if __name__ == "__main__":
    main()

"""Run the showcase queries in queries/*.cypher and save each result in blog/results/<name>.csv.

Parameters come from each file's `// :param name => value` lines (as for Neo4j Browser).
Connection from the NEO4J_* environment variables, else .env (see db.py).
    python run_queries.py [name ...]
"""
import ast
import csv
import re
import sys
import time

from db import ROOT, Graph

QUERIES = ROOT / "queries"
OUT = ROOT / "blog" / "results"
PARAM = re.compile(r"^// :param (\w+) => (.+)$")


def main():
    names = sys.argv[1:] or sorted(p.stem for p in QUERIES.glob("q*.cypher"))
    OUT.mkdir(parents=True, exist_ok=True)
    with Graph() as g:
        for name in names:
            text = (QUERIES / f"{name}.cypher").read_text(encoding="utf-8")
            params = {m[1]: ast.literal_eval(m[2]) for m in map(PARAM.match, text.splitlines()) if m}
            t = time.perf_counter()
            recs, _, keys = g.run(text.strip().rstrip(";"), **params)
            ms = (time.perf_counter() - t) * 1000
            with open(OUT / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(keys)
                w.writerows([r[k] for k in keys] for r in recs)
            print(f"{name:28s} {len(recs):>4} rows  {ms:8.0f} ms  {params}")


if __name__ == "__main__":
    main()

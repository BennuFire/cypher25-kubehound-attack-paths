"""Apply the WEIGHTS table of prepare_kubehound.py to the loaded graph, without a reload.

w is an example cost model (see prepare_kubehound.py): edit the table, then run this script.
    python set_weights.py
"""
from db import Graph
from prepare_kubehound import WEIGHTS

SET = """
    MATCH ()-[r:ATTACKS {kind: $kind}]->()
    CALL (r) { SET r.w = $w } IN TRANSACTIONS OF 20000 ROWS"""


def main():
    with Graph() as g:
        kinds = {r["k"] for r in g.run("MATCH ()-[r:ATTACKS]->() RETURN DISTINCT r.kind AS k")[0]}
        if kinds - WEIGHTS.keys():
            raise SystemExit(f"no weight for: {sorted(kinds - WEIGHTS.keys())}")
        with g.driver.session(database=g.database) as s:
            for kind in sorted(kinds):
                s.run(SET, kind=kind, w=WEIGHTS[kind]).consume()
        for r in g.run("MATCH ()-[r:ATTACKS]->() RETURN r.w AS w, count(*) AS n ORDER BY w")[0]:
            print(f"w={r['w']:<4} {r['n']:>7} attacks")


if __name__ == "__main__":
    main()

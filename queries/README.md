Showcase questions as `.cypher` files, runnable in Neo4j Browser with the `:param` lines at the
top of each file, or all at once with `scripts/run_queries.py` (results in `blog/results/`).

- `q1_easiest_paths`: cheapest paths from a tenant's containers to a critical permission set,
  total effort `sum(w) <= $budget`, up to 15 attacks.
- `q2_effort_per_container`: each container's cheapest effort to a critical asset.
- `q3_easy_moves_only`: paths where every attack has `w <= $cap`.

Planned: TRAIL vs ACYCLIC vs WALK, choke points, threat-group paths. See the main README.

// Q2: for each container of a tenant, the cheapest way to a critical permission set, and how
// many paths there are at that effort. Containers with no path within $budget don't appear.
// :param ns => 'tenant-001'
// :param budget => 4
CYPHER 25
MATCH (s:Container {namespace: $ns})
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(:PermissionSet {critical: true})
WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= $budget)
  AND reduce(c = 0.0, e IN r | c + e.w) + l.w <= $budget
WITH s, reduce(c = 0.0, e IN relationships(p) | c + e.w) AS effort
WITH s, effort, count(*) AS paths ORDER BY effort
WITH s, collect({effort: effort, paths: paths}) AS byEffort
RETURN s.name AS container, byEffort[0].effort AS cheapest,
       byEffort[0].paths AS cheapestPaths, reduce(n = 0, b IN byEffort | n + b.paths) AS pathsInBudget
ORDER BY cheapest, container;

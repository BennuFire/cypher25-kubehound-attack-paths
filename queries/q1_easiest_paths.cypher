// Q1: the easiest attack paths from a tenant's containers to a critical permission set.
// Total effort (sum of w) of at most $budget, at most 15 attacks (KubeHound's maximum hop limit).
// Paths stop at the first critical asset, like KubeHound's criticalPaths().
// :param ns => 'tenant-001'
// :param budget => 4
CYPHER 25
MATCH (s:Container {namespace: $ns})
MATCH p = ACYCLIC (s) (()-[r:ATTACKS]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,14}
                  ()-[l:ATTACKS]->(t:PermissionSet {critical: true})
WHERE allReduce(c = 0.0, e IN r | c + e.w, c <= $budget)
  AND reduce(c = 0.0, e IN r | c + e.w) + l.w <= $budget
WITH s, t, relationships(p) AS attacks
WITH s, t, attacks, reduce(c = 0.0, e IN attacks | c + e.w) AS effort
RETURN s.name AS container, t.name AS target, effort, size(attacks) AS hops,
       [e IN attacks | e.kind] AS moves,
       [e IN attacks | e.techniqueId] AS techniques
ORDER BY effort, hops
LIMIT 10;

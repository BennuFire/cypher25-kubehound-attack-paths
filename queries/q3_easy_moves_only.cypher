// Q3: paths that use only easy moves: every attack has w <= $cap (1 = direct use of access already
// held: exec, read a token, nsenter...), at most $hops attacks.
// :param ns => 'tenant-001'
// :param cap => 1
CYPHER 25
MATCH (s:Container {namespace: $ns})
MATCH p = ACYCLIC (s) (()-[r:ATTACKS WHERE r.w <= $cap]->(x WHERE x.critical IS NULL OR NOT x.critical)){0,9}
                  ()-[l:ATTACKS WHERE l.w <= $cap]->(t:PermissionSet {critical: true})
RETURN [e IN relationships(p) | e.kind] AS moves, count(*) AS paths
ORDER BY paths DESC
LIMIT 10;

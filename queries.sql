-- Discover all access paths through nested groups.
-- Finds every identity that reaches a sensitive resource through
-- any level of group nesting, without knowing who to look for.

GRAPH SecurityGraph
MATCH (identity:Identities)-[:IS_MEMBER]->(g:UserGroups)
      -[:NESTED_IN]->{1, 5}(parent:UserGroups)
      -[:HAS_PERMISSION]->(res:Resources {sensitivity: 'High'})
RETURN identity.email AS Identity,
       identity.type AS Type,
       g.name AS EntryGroup,
       parent.name AS InheritsFrom,
       res.name AS TargetResource;


-- Targeted investigation: trace a specific identity's access chain.

GRAPH SecurityGraph
MATCH (bot:Identities {email: 'suspect-sa@project.iam.gserviceaccount.com'})
      -[:IS_MEMBER]->(g:UserGroups)
      -[:NESTED_IN]->{1, 5}(parent:UserGroups)
      -[:HAS_PERMISSION]->(res:Resources {sensitivity: 'High'})
RETURN bot.email AS ThreatActor,
       g.email AS EntryGroup,
       parent.email AS UltimateParent,
       res.name AS TargetResource;


-- ZSP audit: find expired temporary access that should have been revoked.

@{scan_method=columnar} GRAPH SecurityGraph
MATCH (g:UserGroups {name: 'Temp-Contractors'})<-[:IS_MEMBER]-(u:Identities)
      -[access:HAS_JIT_ACCESS]->(res:Resources {sensitivity: 'High'})
WHERE access.expires_at < CURRENT_TIMESTAMP()
RETURN g.name AS Group_Name,
       res.name AS Target_Resource,
       COUNT(u.name) AS Total_Blocked_Sessions
GROUP BY g.name, res.name
ORDER BY Total_Blocked_Sessions DESC;

"""Raw threat-knowledge sources (data/raw) -> data/import/knowledge/*.csv.

Plan:
- ATT&CK STIX: attack-pattern -> Technique (id = external_id, e.g. T1021.002), x-mitre-tactic ->
  Tactic, intrusion-set -> ThreatGroup, course-of-action -> Mitigation; relationships 'uses',
  'mitigates', 'subtechnique-of'. Skip revoked / deprecated objects.
- CAPEC XML: AttackPattern, Related_Weaknesses -> TARGETS Weakness, Taxonomy_Mappings
  (ATTACK) -> MAPS_TO Technique.
- CWE XML: Weakness (id, name, abstraction).
- NVD JSON (per-year .xz): keep CVEs that affect a product in the enterprise catalog, plus every
  KEV CVE; HAS_WEAKNESS from 'weaknesses', AFFECTS from 'configurations' (CPE 2.3 match criteria
  with version ranges).
- KEV + EPSS: join onto CVE as kev / kevDateAdded / epss / epssPercentile.
"""


def main():
    raise NotImplementedError("scaffold: not written yet, see the docstring for the plan")


if __name__ == "__main__":
    main()

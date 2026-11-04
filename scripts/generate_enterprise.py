"""Generate the fictional company (fixed random seed) -> data/import/enterprise/*.csv.

Plan: zones (Internet, DMZ, Corp, Servers, Tier0), hosts with OS, services with real product CPEs
(and versions chosen so a few have real KEV CVEs), users, AD groups, sessions and admin rights.
Every attacker move becomes one :ATTACKS relationship with techniqueId (ATT&CK ID), w (weight)
and kind (see README, Enterprise layer).
"""


def main():
    raise NotImplementedError("scaffold: not written yet, see the docstring for the plan")


if __name__ == "__main__":
    main()

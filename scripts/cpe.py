"""CPE 2.3 parsing and NVD applicability matching (shared by generate_enterprise and prepare_knowledge).

A CPE 2.3 name: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:
target_sw:target_hw:other. NVD says a CVE applies to products through 'configurations', each
a tree of nodes with cpeMatch entries: a criteria CPE (version may be '*') plus optional
versionStart/End(In|Ex)cluding bounds.

Simplification: a product is affected when it matches any *vulnerable* cpeMatch entry. AND nodes
("app X, only when running on OS Y") are not evaluated, so the result can over-count for products
that are vulnerable only on a given platform.
"""
import re

FIELDS = ["part", "vendor", "product", "version", "update", "edition", "language",
          "sw_edition", "target_sw", "target_hw", "other"]


def parse(cpe):
    # colons inside a value are escaped as '\:'
    parts = re.split(r"(?<!\\):", cpe)[2:]
    return dict(zip(FIELDS, parts))


def _key(v):
    """Natural sort key: '2.4.49' < '2.4.50', '7.13.6' < '7.13.10', '22631.4317' by number."""
    return [(0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"[.\-_+:]", v.lower()) if t]


def vcmp(a, b):
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def _field_ok(want, have):
    # CPE name matching: '*' (ANY) matches every value, '-' (NA) and real values only themselves.
    # So an old Windows CVE listed as windows_server_2022:- (no build) does not hit a host whose
    # product has a build number: it was fixed by a later build.
    return want == "*" or want == have


def matches(match, product):
    """Does the NVD cpeMatch entry `match` cover `product` (dict from parse())?"""
    crit = parse(match["criteria"])
    for f in ("part", "vendor", "product"):
        if crit[f] != product[f]:
            return False
    for f in FIELDS[4:]:
        if not _field_ok(crit[f], product[f]):
            return False
    if crit["version"] != "*":
        return crit["version"] == product["version"]
    v = product["version"]
    bounds = {"versionStartIncluding": lambda c: c >= 0, "versionStartExcluding": lambda c: c > 0,
              "versionEndIncluding": lambda c: c <= 0, "versionEndExcluding": lambda c: c < 0}
    return all(ok(vcmp(v, match[k])) for k, ok in bounds.items() if k in match)


def vulnerable_matches(cve):
    """All vulnerable cpeMatch entries of an NVD CVE item, from every configuration node."""
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    yield m

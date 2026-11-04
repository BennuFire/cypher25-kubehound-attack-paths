"""Download the open threat-knowledge sources into data/raw/ (cached; rerun with --force to refresh).

Every download is appended to data/raw/fetch.log with date, URL, size and SHA-256, so the blog
can say exactly which version of each source it used.

    python fetch_sources.py                     # everything
    python fetch_sources.py attack kev          # only some sources
    python fetch_sources.py nvd --years 2020-2026

NVD comes from the fkie-cad/nvd-json-data-feeds mirror (NVD CVE API 2.0 JSON, one file per year,
rebuilt daily) rather than the NVD API: no API key, no rate limit, and it also works when
nvd.nist.gov is unreachable.
"""
import argparse
import datetime as dt
import hashlib
import urllib.request

from db import ROOT

RAW = ROOT / "data" / "raw"
NVD_MIRROR = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"

SOURCES = {
    "attack": [
        ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
         "mitre/enterprise-attack.json"),
    ],
    "capec": [("https://capec.mitre.org/data/xml/capec_latest.xml", "mitre/capec_latest.xml")],
    "cwe": [("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", "mitre/cwec_latest.xml.zip")],
    "kev": [("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
             "cisa/known_exploited_vulnerabilities.json")],
    "epss": [("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
              "first/epss_scores-current.csv.gz")],
    "nvd": [],  # filled from --years
}


def years(spec):
    lo, _, hi = spec.partition("-")
    return range(int(lo), int(hi or lo) + 1)


def fetch(url, target, force):
    if target.exists() and not force:
        print(f"  cached  {target.relative_to(ROOT)}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "apa-blog-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    tmp.replace(target)
    data = target.read_bytes()
    line = (f"{dt.datetime.now().isoformat(timespec='seconds')}\t{url}\t{len(data)}\t"
            f"{hashlib.sha256(data).hexdigest()}\t{target.relative_to(RAW).as_posix()}\n")
    with open(RAW / "fetch.log", "a", encoding="utf-8") as log:
        log.write(line)
    print(f"  fetched {target.relative_to(ROOT)} ({len(data) / 1e6:.1f} MB)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("sources", nargs="*", metavar="source",
                    help=f"any of {', '.join(SOURCES)} (default: all)")
    ap.add_argument("--years", default=f"2002-{dt.date.today().year}",
                    help="NVD years to fetch, e.g. 2018-2026 (CVE-1999 holds 1999-2001)")
    ap.add_argument("--force", action="store_true", help="download again even if cached")
    args = ap.parse_args()
    if unknown := set(args.sources) - set(SOURCES):
        ap.error(f"unknown source(s): {', '.join(sorted(unknown))}")

    SOURCES["nvd"] = [(f"{NVD_MIRROR}/CVE-{y}.json.xz", f"nvd/CVE-{y}.json.xz")
                      for y in years(args.years)]
    for name in args.sources or SOURCES:
        print(name)
        for url, rel in SOURCES[name]:
            fetch(url, RAW / rel, args.force)


if __name__ == "__main__":
    main()

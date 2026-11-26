"""Self-tests for the signature set.

The tests run over the **combined** rule set, that is the MIT licensed subset
(`signatures/rules.json`) plus the copyleft derived subset
(`signatures/agpl/rules-agpl.json`).  The tier-1 rules are the framework
fingerprints that are meant to be deployed on their own, so a tier-1 hit on
ordinary traffic is a false alarm.

Test 1 -- benign browser traffic
    A synthetic but realistic browser request (Chrome user agent, standard
    browser header set, ordinary page path, empty body) must match **zero**
    tier-1 rules of either licensed subset.

Test 2 -- a known tier-1 pattern fires
    A synthetic request that carries the literal of a selected tier-1 rule
    must match that rule, and the benign request must not.

Test 3 -- the shipped scanner traffic stays clean
    Every request of the published scanner captures (six independent tool
    containers) is matched against every tier-1 rule; the number of hits must
    be zero.  This re-runs, on the data that ships with the repository, the
    check that the study performed on the full WAF corpus.

Example
-------
```bash
python -m research.ci.selftest_rules
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from ..engine import ioc_match
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.engine import ioc_match

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = [REPO_ROOT / "signatures" / "rules.json",
                 REPO_ROOT / "signatures" / "agpl" / "rules-agpl.json"]
DEFAULT_SCANNER_DIR = REPO_ROOT / "data" / "negative"

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

BROWSER_HEADERS = (
    "Host: shop.example.org\r\n"
    "User-Agent: " + BROWSER_UA + "\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Sec-Fetch-Site: none\r\n"
    "Sec-Fetch-User: ?1\r\n"
    "Sec-Ch-Ua: \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"\r\n"
    "Sec-Ch-Ua-Mobile: ?0\r\n"
    "Sec-Ch-Ua-Platform: \"Windows\"\r\n"
    "Referer: https://example.org/\r\n"
    "Cookie: session=6f1a2b3c4d5e6f70\r\n"
    "Connection: keep-alive\r\n"
)


def benign_request() -> dict:
    """A synthetic, entirely legitimate browser request."""
    return {"ua": BROWSER_UA, "uri": "/index.html", "body": "", "hdr": BROWSER_HEADERS}


def load_rules(paths) -> list:
    try:
        from .check_signatures import load_rules as _load
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from research.ci.check_signatures import load_rules as _load

    rules = []
    for p in paths:
        rules.extend(_load(p))
    return rules


def tier1_rules(rules: list) -> list:
    return [r for r in rules if r.get("tier") == "T1"]


def pick_positive_rule(t1: list) -> dict:
    """Choose a tier-1 rule with a literal value that can be replayed."""
    candidates = [r for r in t1 if r.get("match") == "exact" and r.get("pattern")
                  and r.get("field") in ("user_agent", "uri", "body")]
    if not candidates:
        raise SystemExit("no tier-1 rule with a literal value was found")
    for field in ("user_agent", "uri", "body"):
        for r in candidates:
            if r.get("field") == field:
                return r
    return candidates[0]


def request_for_rule(rule: dict) -> dict:
    """Build a request that carries the literal of `rule`."""
    sample = benign_request()
    field = rule.get("field")
    literal = str(rule.get("pattern"))
    if field == "user_agent":
        sample["ua"] = literal
    elif field == "uri":
        sample["uri"] = "/" + literal
    elif field == "body":
        sample["body"] = literal
    return sample


def scan_sample(rules: list, path: Path) -> dict:
    """Match every tier-1 rule against every request of a JSONL capture."""
    hits = {}
    n = 0
    if not Path(path).exists():
        return {"records": 0, "hits": hits, "missing": True}
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            n += 1
            sample = {"ua": d.get("ua", ""), "uri": d.get("uri", ""),
                      "body": d.get("body", ""), "hdr": d.get("hdr", "")}
            for r in rules:
                if ioc_match.match_sample(r, sample):
                    hits[r["id"]] = hits.get(r["id"], 0) + 1
    return {"records": n, "hits": hits, "missing": False}


def scan_directory(rules: list, directory: Path) -> dict:
    """Scan every capture below a directory."""
    total_records = 0
    total_hits = {}
    files = sorted(Path(directory).rglob("access.jsonl")) if Path(directory).is_dir() else []
    for f in files:
        res = scan_sample(rules, f)
        total_records += res["records"]
        for rid, count in res["hits"].items():
            total_hits[rid] = total_hits.get(rid, 0) + count
    return {"records": total_records, "hits": total_hits, "files": len(files)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Self-tests for the combined signature set.")
    ap.add_argument("--rules", nargs="+", default=[str(p) for p in DEFAULT_RULES],
                    help="rule set files; all of them are validated together")
    ap.add_argument("--scanner-dir", default=str(DEFAULT_SCANNER_DIR),
                    help="directory with the published scanner captures")
    args = ap.parse_args(argv)

    rules = load_rules(args.rules)
    t1 = tier1_rules(rules)
    failures = []
    print("rule sets      : %s" % ", ".join(args.rules))
    print("rules          : %d  tier-1: %d" % (len(rules), len(t1)))

    # --- test 1: benign browser request -------------------------------------
    benign = benign_request()
    benign_hits = [r["id"] for r in t1 if ioc_match.match_sample(r, benign)]
    print("test 1  benign browser request vs %d tier-1 rules: %d hit(s)" % (len(t1), len(benign_hits)))
    if benign_hits:
        failures.append("benign browser request matched tier-1 rules: %s" % ", ".join(benign_hits))

    # --- test 2: a known tier-1 pattern fires --------------------------------
    rule = pick_positive_rule(t1)
    sample = request_for_rule(rule)
    fired = ioc_match.match_sample(rule, sample)
    print("test 2  rule %s (%s, %s) fires on a request carrying its literal: %s"
          % (rule.get("id"), rule.get("field"), rule.get("pattern"), fired))
    if not fired:
        failures.append("rule %s did not fire on a request carrying its literal" % rule.get("id"))
    if ioc_match.match_sample(rule, benign):
        failures.append("rule %s also fires on the benign request" % rule.get("id"))

    # --- test 3: the shipped scanner traffic ---------------------------------
    scan = scan_directory(t1, Path(args.scanner_dir))
    print("test 3  %d scanner requests in %d captures: %d tier-1 hit(s)"
          % (scan["records"], scan["files"], len(scan["hits"])))
    if scan["hits"]:
        failures.append("tier-1 rules fired on the scanner captures: %s" % json.dumps(scan["hits"]))

    report = {
        "rule_sets": list(args.rules),
        "rules": len(rules),
        "tier1_rules": len(t1),
        "benign_hits": benign_hits,
        "positive_rule": {"id": rule.get("id"), "field": rule.get("field"),
                          "pattern": rule.get("pattern"), "fired": bool(fired)},
        "scanner_captures": {"path": str(args.scanner_dir), "records": scan["records"],
                             "files": scan["files"], "hits": scan["hits"]},
        "failures": failures,
    }

    if failures:
        print("")
        print("FAILED:")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("")
    print("OK: benign traffic matches no tier-1 rule, the selected tier-1 rule fires, "
          "the shipped scanner traffic stays clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Lint the signature set and check platform-file consistency.

Checks performed
----------------
1. **Syntax** -- every rule in the signature set must compile as a Python
   regular expression, both in its stored `regex` form and in the deployed
   form produced by the shared matcher (`research/engine/ioc_match.py`).
2. **Platform compatibility** -- no deployed regular expression may contain
   `\\s`.  Lucene and KQL have no `\\s` operator, so a rule that uses it
   silently never fires on those platforms.
3. **Platform-file consistency** -- the number of rules in each platform file
   must equal the number of rules in the signature set that the platform can
   express:

   * Elasticsearch / OpenSearch (KQL), Splunk SPL and Suricata carry every
     non-retired rule that is observable in an HTTP access log, that is every
     rule whose field is `user_agent`, `uri`, `body` or `header`.
   * Sigma (webproxy) carries the User-Agent rules only, because the Sigma
     webproxy schema models the request as an image with a single
     `UserAgent` field.

   The invariant is recomputed from the signature set on every run, so adding
   a rule without regenerating the platform files fails the build.
4. **Empty-rule guard** -- a platform rule with an empty pattern is a
   regression of a previously fixed defect and fails the build.

Example
-------
```bash
python -m research.ci.check_signatures \
    --rules signatures/rules.json --platform-dir signatures
```
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    from ..engine import ioc_match
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.engine import ioc_match

WEB_LOG_FIELDS = ("user_agent", "uri", "body", "header")
RETIRED_TIER = "T3"

PLATFORM_EXTENSIONS = {
    "es": (".kql",),
    "sigma": (".yml", ".yaml"),
    "splunk": (".spl",),
    "suricata": (".rules",),
}

PLATFORM_SUFFIX = {
    "es": " (Elasticsearch / OpenSearch, KQL)",
    "sigma": " (Sigma webproxy)",
    "splunk": " (Splunk SPL)",
    "suricata": " (Suricata / Snort)",
}


# ------------------------------------------------------------------ loading ---
def load_rules(path) -> list:
    """Load rules from a JSON file or from every JSON file in a directory."""
    p = Path(path)
    rules = []
    if p.is_dir():
        files = sorted(p.glob("*.json"))
        if not files:
            raise SystemExit("no signature JSON files found in %s" % p)
        for f in files:
            rules.extend(_rules_from_json(f.read_text(encoding="utf-8")))
        return rules
    return _rules_from_json(p.read_text(encoding="utf-8"))


def _rules_from_json(text: str) -> list:
    data = json.loads(text)
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in ("rules", "signatures", "items"):
            if isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
    raise SystemExit("unrecognised signature file layout")


AGPL_SUBDIR = "agpl"


def find_platform_files(platform_dir, recursive: bool = False) -> dict:
    """Locate the platform rule files.

    The signature directory holds two independently licensed sets side by side:

        signatures/            MIT-licensed subset        -> rules.json
        signatures/agpl/       copyleft-derived subset     -> rules-agpl.json

    Both are complete, independently deployable rule files. The default scan is
    NOT recursive so that the MIT check does not pick up the AGPL files (and vice
    versa); pass recursive=True when you explicitly want the whole tree.
    """
    root = Path(platform_dir)
    found = {}
    for platform, exts in PLATFORM_EXTENSIONS.items():
        files = []
        walker = root.rglob("*") if recursive else root.glob("*")
        for f in sorted(walker):
            if not f.is_file():
                continue
            if f.suffix.lower() not in exts:
                continue
            if not recursive and AGPL_SUBDIR in f.relative_to(root).parts:
                continue
            if platform in f.stem.lower() or platform in f.parts:
                files.append(f)
        found[platform] = files
    return found


# ------------------------------------------------------------------ parsing ---
def parse_platform_rules(path: Path, platform: str) -> list:
    """Split a platform rule file into individual rules.

    A rule is a block of consecutive non-empty lines; comment lines inside a
    block document the rule and are ignored for matching purposes.
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"\n\s*\n", text)
    out = []
    for blk in blocks:
        lines = [ln for ln in blk.splitlines() if ln.strip()]
        if not lines:
            continue
        code = [ln for ln in lines if not ln.strip().startswith("#")]
        if not code:
            continue
        body = "\n".join(code)
        pattern, field = _extract_pattern(body, platform)
        out.append({"file": str(path), "pattern": pattern, "field": field, "text": body})
    return out


def _extract_pattern(body: str, platform: str):
    """Extract the regular expression (or literal) of one platform rule."""
    if platform == "sigma":
        m = re.search(r'Image\|contains\|[^:]+:\s*"((?:[^"\\]|\\.)*)"', body)
        if m:
            return m.group(1), "user_agent"
        m = re.search(r'"((?:[^"\\]|\\.)*)"', body)
        return (m.group(1) if m else ""), "user_agent"
    # KQL / SPL / Suricata: the expression is delimited by the first and the
    # last slash of the rule body.
    start = body.find("/")
    end = body.rfind("/")
    if start < 0 or end <= start:
        return "", ""
    return body[start + 1:end], ""


# ------------------------------------------------------------------- checks ---
def check_regexes(rules: list) -> list:
    """Every rule must compile and must stay Lucene/KQL compatible."""
    problems = []
    for r in rules:
        rid = r.get("id", "<no-id>")
        raw = r.get("regex")
        if raw:
            try:
                re.compile(raw)
            except re.error as exc:
                problems.append("rule %s: stored regex does not compile: %s" % (rid, exc))
        deployed = ioc_match.deploy_regex(r)
        if deployed:
            try:
                re.compile(deployed)
            except re.error as exc:
                problems.append("rule %s: deployed regex does not compile: %s" % (rid, exc))
            if "\\s" in deployed:
                problems.append("rule %s: deployed regex contains \\s, which Lucene/KQL do not support" % rid)
        elif r.get("pattern"):
            problems.append("rule %s: deployed regex is empty" % rid)
    return problems


def expected_platform_counts(rules: list) -> dict:
    """Number of rules each platform file must contain, derived from the set."""
    live = [r for r in rules if r.get("tier") != RETIRED_TIER]
    web = [r for r in live if r.get("field") in WEB_LOG_FIELDS]
    ua = [r for r in live if r.get("field") == "user_agent"]
    return {"es": len(web), "splunk": len(web), "suricata": len(web), "sigma": len(ua)}


def check_platforms(rules: list, platform_files: dict) -> list:
    problems = []
    expected = expected_platform_counts(rules)
    for platform, files in sorted(platform_files.items()):
        if not files:
            problems.append("no %s platform file found%s" % (platform, PLATFORM_SUFFIX[platform]))
            continue
        total = 0
        for f in files:
            rules_here = parse_platform_rules(f, platform)
            total += len(rules_here)
            for i, r in enumerate(rules_here, start=1):
                if not r["pattern"].strip():
                    problems.append("%s: empty rule in %s (rule %d) -- deployment regression" % (
                        platform, f.name, i))
        want = expected[platform]
        if total != want:
            problems.append("%s: %d rules, expected %d (non-retired rules expressible on this platform)" % (
                platform, total, want))
    return problems


def run_set(label: str, rules_path: str, platform_dir: str):
    """Run every check against one independently deployable rule set."""
    rules = load_rules(rules_path)
    platform_files = find_platform_files(platform_dir)

    problems = []
    problems += check_regexes(rules)
    problems += check_platforms(rules, platform_files)

    tiers = {}
    for r in rules:
        tiers[r.get("tier", "?")] = tiers.get(r.get("tier", "?"), 0) + 1

    print("[%s] signature set : %s" % (label, rules_path))
    print("[%s] rules         : %d  %s" % (label, len(rules), tiers))
    for platform in sorted(platform_files):
        files = platform_files[platform]
        count = sum(len(parse_platform_rules(f, platform)) for f in files)
        print("[%s]   %-10s %-40s files=%d rules=%d" % (
            label, platform, PLATFORM_SUFFIX[platform], len(files), count))
    print("[%s] expected      : %s" % (label, expected_platform_counts(rules)))
    print("")
    return rules, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Lint signatures and check platform consistency for one or two licensed rule sets.")
    ap.add_argument("--rules", required=True, help="signature set (JSON file or directory)")
    ap.add_argument("--platform-dir", required=True, help="directory holding the platform rule files")
    ap.add_argument("--agpl-rules", default="",
                    help="optional second rule set (the copyleft-derived subset) to validate")
    ap.add_argument("--agpl-dir", default="",
                    help="optional directory holding the platform rule files of the second set")
    ap.add_argument("--out", default="", help="optional JSON report")
    args = ap.parse_args(argv)

    problems = []
    _, p1 = run_set("primary", args.rules, args.platform_dir)
    problems += p1
    if bool(args.agpl_rules) != bool(args.agpl_dir):
        raise SystemExit("--agpl-rules and --agpl-dir must be given together")
    if args.agpl_rules:
        _, p2 = run_set("agpl", args.agpl_rules, args.agpl_dir)
        problems += p2

    if problems:
        print("FAILED (%d problem(s)):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        if args.out:
            Path(args.out).write_text(json.dumps({"problems": problems}, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
        return 1

    print("OK: every rule compiles, no \\s in any deployed expression, "
          "platform rule counts match the signature set")
    if args.out:
        Path(args.out).write_text(json.dumps({"problems": []}, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

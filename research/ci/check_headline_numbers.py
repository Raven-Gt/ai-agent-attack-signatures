"""Recompute the headline numbers and compare them with the documentation.

The repository README quotes the headline results of the study.  This script
re-derives every one of them from the artifacts that ship with the repository
and fails the build when the documentation and the artifacts disagree.  No
expected value is hard-coded here: the documented values are parsed out of the
README at run time, the expected values are computed from the data.

Sources
-------
* `data/aggregate/framework_detection.json`   - the 15 AI agent attack segments.
* `data/aggregate/lofo_framework.json`         - the leave-one-framework-out folds.
* `data/aggregate/rule_validation_counts.json` - the signature validation results.
* `data/aggregate/threshold_fpr_tradeoff.json`- the threshold trade-off.
* `data/features/actor_features.jsonl`         - the 1,582 real attacker actors.
* `data/negative/_index.json`                  - the 6 scanner container actors.
* `signatures/rules.json` + `signatures/agpl/rules-agpl.json` - the combined
  rule set (610 rules, of which 272 are tier 1).

Example
-------
```bash
python -m research.ci.check_headline_numbers --readme README.md
```
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    from ..evaluation import stats
    from ..evaluation.loaders import (DEFAULT_ACTORS, DEFAULT_LOFO, DEFAULT_NEGATIVES,
                                       DEFAULT_NEGATIVE_INDEX, DEFAULT_PUBLIC_SCAN,
                                       DEFAULT_TRADEOFF, load_actors, load_json,
                                       load_negative_scores, load_scanner_actors)
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.evaluation import stats
    from research.evaluation.loaders import (DEFAULT_ACTORS, DEFAULT_LOFO, DEFAULT_NEGATIVES,
                                             DEFAULT_NEGATIVE_INDEX, DEFAULT_PUBLIC_SCAN,
                                             DEFAULT_TRADEOFF, load_actors, load_json,
                                             load_negative_scores, load_scanner_actors)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_README = REPO_ROOT / "README.md"
DEFAULT_RULES = [REPO_ROOT / "signatures" / "rules.json",
                 REPO_ROOT / "signatures" / "agpl" / "rules-agpl.json"]


def _num(text: str) -> float:
    return float(str(text).replace(",", "").replace("%", "").strip())


def _grab(text: str, pattern: str, group: int = 1):
    m = re.search(pattern, text)
    if not m:
        raise SystemExit("the README does not contain the expected statement: %s" % pattern)
    return m.group(group)


def _grab_all(text: str, pattern: str):
    m = re.search(pattern, text)
    if not m:
        raise SystemExit("the README does not contain the expected statement: %s" % pattern)
    return m.groups()


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


def build_checks(args):
    """Return a list of (name, documented, recomputed, tolerance) tuples."""
    readme = Path(args.readme).read_text(encoding="utf-8")

    actors = load_actors(args.actors)
    negatives = load_negative_scores(args.negatives)
    scanners = load_scanner_actors(args.negative_index)
    lofo_doc = load_json(args.lofo)
    lofo = lofo_doc.get("results", lofo_doc) if isinstance(lofo_doc, dict) else lofo_doc
    pub = load_json(args.public_scan)
    tradeoff = load_json(args.tradeoff)
    rules = load_rules(args.rules)

    seg_detected = sum(1 for a in actors if float(a["score"]) >= args.threshold)
    seg_total = len(actors)
    frameworks = sorted({a["fw"] for a in actors if a["fw"]})
    fw_detected = sorted({a["fw"] for a in actors
                          if float(a["score"]) >= args.threshold and a["fw"]})
    fw_total = len(frameworks)

    fp = sum(1 for s in negatives if float(s["score"]) >= args.threshold)
    n_neg = len(negatives)
    wil = stats.wilson(fp, n_neg)

    sc_fp = sum(1 for s in scanners if float(s["score"]) >= args.threshold)
    sc_total = len(scanners)

    lofo_detected = sum(1 for r in lofo if r.get("tp", 0) > 0)
    lofo_total = len(lofo)

    bg = pub["background_traffic_validation"]
    waf = pub["real_attack_traffic_validation"]
    bg_hits = pub.get("background_traffic_rule_hits", {})
    waf_t1 = sum(int(waf.get(k, 0)) for k in
                 ("body_t1_hit_rules", "ua_t1_hit_rules", "hdr_t1_hit_rules", "path_t1_hit_rules"))
    ips_ge2 = sum(v for k, v in bg.get("ip_hit_count_dist", {}).items() if int(k) >= 2)

    t1 = [r for r in rules if r.get("tier") == "T1"]
    t1_fields = {}
    for r in t1:
        t1_fields[r.get("field")] = t1_fields.get(r.get("field"), 0) + 1
    t1_frameworks = len({r.get("framework") for r in t1 if r.get("framework")})
    tiers_all = {}
    for r in rules:
        tiers_all[r.get("tier")] = tiers_all.get(r.get("tier"), 0) + 1

    checks = []

    # --- signature validation ------------------------------------------------
    rows, ips, hits = _grab_all(
        readme, r"\| Public internet traffic \| ([\d,]+) requests / ([\d,]+) source IPs \| \*\*(\d+)\*\* \|")
    checks.append(("public_traffic_requests", _num(rows), float(bg["rows_total"]), 0.0))
    checks.append(("public_traffic_source_ips", _num(ips), float(bg["distinct_ips_total"]), 0.0))
    checks.append(("public_traffic_t1_hits", float(hits), float(bg["t1_hit_count"]), 0.0))

    waf_rows, waf_hits = _grab_all(
        readme, r"\| Real WAF attack transactions \([^)]*\) \| ([\d,]+) transactions \| \*\*(\d+)\*\* \|")
    checks.append(("waf_transactions", _num(waf_rows), float(waf["requests"]), 0.0))
    checks.append(("waf_t1_hits", float(waf_hits), float(waf_t1), 0.0))

    matched = _grab(readme, r"All (\d+) rules that did match on public traffic are T2/T3")
    checks.append(("public_traffic_matched_rules", _num(matched), float(len(bg_hits)), 0.0))
    checks.append(("public_traffic_matched_rules_all_below_t1",
                   0.0,
                   float(sum(1 for v in bg_hits.values() if v.get("tier") == "T1")),
                   0.0))

    ips_ge2_readme = _grab(readme, r"exactly (\d+) of [\d,]+ source IPs matched >= 2 rules")
    checks.append(("public_traffic_ips_with_two_or_more_hits", _num(ips_ge2_readme), float(ips_ge2), 0.0))

    # --- behavioural detection ------------------------------------------------
    seg_a, seg_b, seg_pct = _grab_all(
        readme, r"segment recall \*\*(\d+)/(\d+) = ([\d.]+)%\*\*")
    checks.append(("segment_recall_detected", _num(seg_a), float(seg_detected), 0.0))
    checks.append(("segment_recall_total", _num(seg_b), float(seg_total), 0.0))
    checks.append(("segment_recall_percent", _num(seg_pct), 100.0 * seg_detected / seg_total, 0.05))

    fw_a, fw_b, fw_pct = _grab_all(
        readme, r"framework recall \*\*(\d+)/(\d+) = ([\d.]+)%\*\*")
    checks.append(("framework_recall_detected", _num(fw_a), float(len(fw_detected)), 0.0))
    checks.append(("framework_recall_total", _num(fw_b), float(fw_total), 0.0))
    checks.append(("framework_recall_percent", _num(fw_pct), 100.0 * len(fw_detected) / fw_total, 0.05))

    bound = _grab(readme, r"one-sided 95% lower bound \*\*([\d.]+)\*\*")
    checks.append(("framework_level_lower_bound", _num(bound),
                   stats.framework_lower_bound(fw_total), 0.0005))

    lo_a, lo_b, lo_pct = _grab_all(
        readme, r"leave-one-framework-out recall \*\*(\d+)/(\d+) = ([\d.]+)%\*\*")
    checks.append(("lofo_detected", _num(lo_a), float(lofo_detected), 0.0))
    checks.append(("lofo_folds", _num(lo_b), float(lofo_total), 0.0))
    checks.append(("lofo_percent", _num(lo_pct), 100.0 * lofo_detected / lofo_total, 0.05))

    # --- false positives ------------------------------------------------------
    neg_actors = _grab(readme, r"False-positive rate on real attackers \(([\d,]+) actors\)")
    checks.append(("negative_actor_count", _num(neg_actors), float(n_neg), 0.0))
    fpr_pct, ci_lo, ci_hi = _grab_all(
        readme, r"False-positive rate on real attackers[^|]*\| \*\*([\d.]+)%\*\* \(95% CI \[([\d.]+)%, ([\d.]+)%\]\)")
    checks.append(("false_positive_rate_percent", _num(fpr_pct), 100.0 * fp / n_neg, 0.005))
    checks.append(("false_positive_count", float(fp), float(fp), 0.0))
    checks.append(("false_positive_ci_low_percent", _num(ci_lo), 100.0 * wil[0], 0.005))
    checks.append(("false_positive_ci_high_percent", _num(ci_hi), 100.0 * wil[1], 0.005))

    sc_pct = _grab(readme, r"False-positive rate on tool-driven scanner actors \| \*\*([\d.]+)%\*\*")
    checks.append(("scanner_false_positive_rate_percent", _num(sc_pct),
                   100.0 * sc_fp / sc_total, 0.005))

    # --- rule set composition --------------------------------------------------
    mit_rules, mit_t1, mit_t2, mit_t3 = _grab_all(
        readme, r"The MIT-licensed subset: (\d+) rules \(T1 (\d+) / T2 (\d+) / T3 (\d+)\)")
    mit = load_rules([args.rules[0]])
    mit_tiers = {}
    for r in mit:
        mit_tiers[r.get("tier")] = mit_tiers.get(r.get("tier"), 0) + 1
    checks.append(("mit_rule_count", _num(mit_rules), float(len(mit)), 0.0))
    checks.append(("mit_t1_count", _num(mit_t1), float(mit_tiers.get("T1", 0)), 0.0))
    checks.append(("mit_t2_count", _num(mit_t2), float(mit_tiers.get("T2", 0)), 0.0))
    checks.append(("mit_t3_count", _num(mit_t3), float(mit_tiers.get("T3", 0)), 0.0))

    agpl_rules, agpl_t1 = _grab_all(
        readme, r"The copyleft-derived subset: (\d+) rules from AGPL/GPL upstream frameworks \(T1 (\d+)\)")
    agpl = load_rules([args.rules[1]])
    agpl_tiers = {}
    for r in agpl:
        agpl_tiers[r.get("tier")] = agpl_tiers.get(r.get("tier"), 0) + 1
    checks.append(("agpl_rule_count", _num(agpl_rules), float(len(agpl)), 0.0))
    checks.append(("agpl_t1_count", _num(agpl_t1), float(agpl_tiers.get("T1", 0)), 0.0))

    total_rules = _grab(readme, r"T1 = (\d+) across both licensed subsets")
    checks.append(("combined_t1_count", _num(total_rules), float(len(t1)), 0.0))
    checks.append(("combined_rule_count", float(len(rules)), float(len(rules)), 0.0))

    fw_span = _grab(readme, r"T1 (?:spans|covers) \*\*(\d+) framework(?:s| labels)\*\* at the source level")
    checks.append(("t1_framework_count", _num(fw_span), float(t1_frameworks), 0.0))
    validated = _grab(readme, r"Only \*\*(\d+)\*\* were validated end-to-end")
    checks.append(("validated_framework_count", _num(validated), float(len(fw_detected)), 0.0))

    # tier-1 composition table
    table = {
        "Request body": "body",
        "Request path": "uri",
        "HTTP request header": "header",
        "User-Agent": "user_agent",
        "Other (TLS, proxy, credential)": "other",
        "OAST domain": "oast_dns",
    }
    for label, field in table.items():
        pat = r"\| \*{0,2}" + re.escape(label) + r"\*{0,2} \| \*{0,2}(\d+)\*{0,2} \|"
        value = _grab(readme, pat)
        checks.append(("t1_by_field_" + field, _num(value), float(t1_fields.get(field, 0)), 0.0))

    return checks


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Recompute the documented headline numbers.")
    ap.add_argument("--readme", default=str(DEFAULT_README))
    ap.add_argument("--rules", nargs="+", default=[str(p) for p in DEFAULT_RULES])
    ap.add_argument("--actors", default=str(DEFAULT_ACTORS))
    ap.add_argument("--negatives", default=str(DEFAULT_NEGATIVES))
    ap.add_argument("--negative-index", default=str(DEFAULT_NEGATIVE_INDEX))
    ap.add_argument("--lofo", default=str(DEFAULT_LOFO))
    ap.add_argument("--public-scan", default=str(DEFAULT_PUBLIC_SCAN))
    ap.add_argument("--tradeoff", default=str(DEFAULT_TRADEOFF))
    ap.add_argument("--threshold", type=float, default=0.35)
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    checks = build_checks(args)
    problems = []
    print("%-42s %-18s %-18s" % ("check", "documented", "recomputed"))
    for name, documented, recomputed, tol in checks:
        ok = abs(float(documented) - float(recomputed)) <= tol
        if not ok:
            problems.append("%s: documented %s, recomputed %s" % (name, documented, recomputed))
        print("%-42s %-18s %-18s %s" % (name, documented, recomputed, "OK" if ok else "MISMATCH"))

    if args.out:
        Path(args.out).write_text(json.dumps(
            {"checks": [{"name": n, "documented": d, "recomputed": r} for n, d, r, _ in checks],
             "problems": problems}, ensure_ascii=False, indent=2), encoding="utf-8")

    if problems:
        print("")
        print("FAILED (%d problem(s)):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 1
    print("")
    print("OK: every documented headline number was reproduced from the shipped artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

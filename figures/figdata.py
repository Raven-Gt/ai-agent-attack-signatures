# -*- coding: utf-8 -*-
"""Derived statistics for the figures, computed from the shipped artifacts.

Everything here is a *derivation* of a released file, never a new measurement:

* ai_actor_behaviour()  - request rate and endpoint breadth of the 15 AI agent
  actors, recomputed from data/positive/<capture>/access.jsonl with the
  repository's own ground-truth labelling (research/engine/ground_truth.py).
* scanner_behaviour()    - the same quantities for the 6 scanner hard negatives
  from data/negative/<capture>/access.jsonl.
* real_attacker_stats()  - request rate and endpoint breadth of the 1,582 WAF
  actors, read straight from data/features/actor_features.csv.

The result is cached in figures/_derived.json so the figure build is fast and
deterministic.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from figlib import (AGG, DATA, NEG, POS, REPO_ROOT, actor_stats, load_json)

sys.path.insert(0, str(REPO_ROOT))
from research.engine import ground_truth  # noqa: E402  (repository ground truth)

CACHE = REPO_ROOT / "figures" / "_derived.json"


def _access_records(path: Path):
    out = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def ai_actor_behaviour():
    """One entry per published AI agent capture."""
    actors = load_json(AGG / "framework_detection.json")["per_actor"]
    by_id = {a["actor_id"]: a for a in actors}
    out = []
    for cap_dir in sorted(p for p in POS.iterdir() if p.is_dir()):
        meta = load_json(cap_dir / "meta.json")
        rec = by_id.get(cap_dir.name, {})
        lab = rec.get("capture_label") or meta.get("capture_label")
        records = _access_records(cap_dir / "access.jsonl")
        agent = [r for r in records
                 if ground_truth.is_agent(ground_truth.label_for_request(lab, r.get("src", ""), r.get("ua", "")))]
        st = actor_stats(agent)
        out.append({
            "actor_id": cap_dir.name,
            "framework": rec.get("framework") or meta.get("framework", ""),
            "capture_label": lab,
            "ai_score": float(rec.get("ai_score", meta.get("ai_score", 0.0))),
            "detected": rec.get("detected", ""),
            "fired_rules": rec.get("fired_rules", ""),
            "published_records": len(records),
            "agent_records": st["n"],
            "scored_actor_requests": int(rec.get("actor_requests", st["n"])),
            "duration_s": st["duration_s"],
            "rpm": st["rpm"],
            "templates": st["templates"],
            "families": st["families"],
        })
    out.sort(key=lambda a: -a["ai_score"])
    return out


def scanner_behaviour():
    index = load_json(NEG / "_index.json")
    out = []
    for cap in index["captures"]:
        d = NEG / cap["actor_id"]
        records = _access_records(d / "access.jsonl")
        st = actor_stats(records)
        out.append({
            "actor_id": cap["actor_id"],
            "actor_class": cap["actor_class"],
            "tool_signature": cap.get("tool_signature", ""),
            "ai_score": float(cap["ai_score"]),
            "detected": bool(cap["detected"]),
            "fired_rules": cap.get("fired_rules", ""),
            "records": st["n"],
            "duration_s": float(cap.get("duration_s", st["duration_s"])),
            "rpm": st["rpm"],
            "templates": st["templates"],
            "families": st["families"],
        })
    return out


def real_attacker_stats():
    """Request rate / endpoint breadth distribution of the 1,582 WAF actors."""
    rpm, tmpl, scores, classes = [], [], [], []
    with (DATA / "features" / "actor_features.csv").open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                rpm.append(float(row["f5_rpm"]))
                tmpl.append(float(row["f5_distinct_templates"]))
            except (KeyError, ValueError):
                continue
            try:
                scores.append(float(row["ai_score"]))
            except (KeyError, ValueError):
                pass
            classes.append(row.get("actor_class", ""))
    return {"n": len(rpm), "rpm": rpm, "templates": tmpl,
            "scores": scores, "classes": classes}


def build(force: bool = False):
    if CACHE.exists() and not force:
        return load_json(CACHE)
    data = {
        "ai_actors": ai_actor_behaviour(),
        "scanners": scanner_behaviour(),
        "real_attackers": real_attacker_stats(),
    }
    CACHE.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return data


if __name__ == "__main__":
    d = build(force=True)
    print("AI actors")
    for a in d["ai_actors"]:
        print("  %-18s %-14s agent_req=%-6d published=%-6d dur=%-8.0f rpm=%-8.2f tmpl=%-5d fam=%d" % (
            a["actor_id"], a["framework"], a["agent_records"], a["published_records"],
            a["duration_s"], a["rpm"], a["templates"], a["families"]))
    print("Scanners")
    for s in d["scanners"]:
        print("  %-12s %-8s n=%-5d dur=%-8.0f rpm=%-9.2f tmpl=%-4d score=%.4f detected=%s" % (
            s["actor_id"], s["tool_signature"], s["records"], s["duration_s"],
            s["rpm"], s["templates"], s["ai_score"], s["detected"]))
    r = d["real_attackers"]
    print("real attackers n=%d" % r["n"])

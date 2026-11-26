"""Shared loading helpers for the evaluation scripts.

Every evaluation script reads the JSON and JSONL artifacts that ship with the
repository, so that every number reported by the study can be recomputed from
data that is part of the repository:

* `data/aggregate/framework_detection.json`  - the 15 behavioural actors of the
  15 AI-agent attack captures with their attribution score and the evidence
  rules that fired.
* `data/features/actor_features.jsonl`        - the 1,582 real attacker actors
  with their attribution score.
* `data/negative/_index.json`                 - the 6 scanner container actors.
* `data/aggregate/rule_validation_counts.json` - the recorded signature
  validation results on public traffic and on real WAF attack traffic.

All paths are resolved relative to the repository root, so the scripts work
from any working directory.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
AGGREGATE_DIR = DATA_DIR / "aggregate"
SIGNATURES_DIR = REPO_ROOT / "signatures"

DEFAULT_ACTORS = AGGREGATE_DIR / "framework_detection.json"
DEFAULT_NEGATIVES = DATA_DIR / "features" / "actor_features.jsonl"
DEFAULT_NEGATIVE_INDEX = DATA_DIR / "negative" / "_index.json"
DEFAULT_LOFO = AGGREGATE_DIR / "lofo_framework.json"
DEFAULT_TRADEOFF = AGGREGATE_DIR / "threshold_fpr_tradeoff.json"
DEFAULT_PUBLIC_SCAN = AGGREGATE_DIR / "rule_validation_counts.json"
DEFAULT_ABLATION = AGGREGATE_DIR / "feature_family_ablation.json"
DEFAULT_RULES = SIGNATURES_DIR / "rules.json"
DEFAULT_AGPL_RULES = SIGNATURES_DIR / "agpl" / "rules-agpl.json"


def load_json(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path) -> list:
    out = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _parse_weights(text) -> dict:
    """Parse the "F3=0.4800;F5=0.3400" weight string of the aggregate artifact."""
    out = {}
    if not text:
        return out
    for part in str(text).split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        try:
            out[key.strip()] = float(value)
        except ValueError:
            continue
    return out


def load_actors(path=None) -> list:
    """Load the positive actors (one entry per AI-agent attack segment).

    Three artifact layouts are understood and normalised to the same shape:

    * the aggregate artifact `data/aggregate/framework_detection.json`
      (a list under `per_actor`),
    * the study artifact (a list under `actors`),
    * a directory of per-capture score files as written by
      `research/pipeline/score_actor.py` (JSONL, one actor per line).

    A directory is walked recursively and the index and meta files are skipped.
    """
    p = Path(path or DEFAULT_ACTORS)
    if p.is_dir():
        out = []
        for f in sorted(p.rglob("*")):
            if not f.is_file() or f.suffix.lower() not in (".json", ".jsonl"):
                continue
            if f.name.startswith("_") or f.name == "meta.json":
                continue
            out.extend(load_actors(f))
        return out
    if p.suffix.lower() == ".jsonl":
        rows = load_jsonl(p)
        return [{
            "key": r.get("key", r.get("actor_id", "")),
            "fw": r.get("fw", r.get("framework", "")),
            "lab": r.get("lab", r.get("capture_label", "")),
            "n": r.get("n", r.get("n_requests", r.get("actor_requests", 0))),
            "score": float(r.get("score", r.get("ai_score", 0.0))),
            "fired": list(r.get("fired", r.get("fired_rules", []))),
            "weights": _parse_weights(r.get("weights")),
        } for r in rows]
    data = load_json(p)
    rows = data.get("per_actor") if isinstance(data, dict) else None
    if rows is None:
        rows = data.get("actors", []) if isinstance(data, dict) else data
    out = []
    for r in rows:
        if "ai_score" in r:
            out.append({
                "key": r.get("actor_id", ""),
                "fw": r.get("framework", ""),
                "lab": r.get("capture_label", ""),
                "n": r.get("actor_requests", 0),
                "score": float(r.get("ai_score", 0.0)),
                "fired": [x for x in str(r.get("fired_rules", "")).split(";") if x],
                "weights": _parse_weights(r.get("weights")),
                "detected": str(r.get("detected", "")).lower() in ("yes", "true", "1"),
            })
        else:
            out.append({
                "key": r.get("lab", ""),
                "fw": r.get("fw", ""),
                "lab": r.get("lab", ""),
                "n": r.get("n", 0),
                "score": float(r.get("score", 0.0)),
                "fired": list(r.get("fired", [])),
                "weights": {k: float(v) for k, v in (r.get("weights") or {}).items()},
            })
    return out


def load_negative_scores(path=None) -> list:
    """Load the negative actors (real internet attackers) with their scores."""
    p = Path(path or DEFAULT_NEGATIVES)
    if p.is_dir():
        p = p / "actor_features.jsonl"
    out = []
    for r in load_jsonl(p):
        out.append({
            "key": r.get("actor_id", ""),
            "cls": r.get("actor_class", ""),
            "score": float(r.get("ai_score", 0.0)),
            "fired": list(r.get("fired_rules", [])),
            "n": r.get("request_count", 0),
            "src": "N2",
        })
    return out


def load_scanner_actors(path=None) -> list:
    """Load the scanner container actors with their scores."""
    data = load_json(path or DEFAULT_NEGATIVE_INDEX)
    rows = data.get("captures", []) if isinstance(data, dict) else data
    return [{
        "key": r.get("actor_id", ""),
        "cls": r.get("actor_class", ""),
        "score": float(r.get("ai_score", 0.0)),
        "fired": [x for x in str(r.get("fired_rules", "")).split(";") if x],
        "n": r.get("records_published", 0),
        "src": "N3",
    } for r in rows]


def detected(actors: list, threshold: float) -> list:
    return [a for a in actors if float(a.get("score", 0.0)) >= threshold]


def frameworks_of(actors: list) -> list:
    return sorted({a.get("fw", "") for a in actors if a.get("fw")})


def frameworks_detected(actors: list, threshold: float) -> list:
    return sorted({a.get("fw", "") for a in detected(actors, threshold) if a.get("fw")})

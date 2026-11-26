"""Attribution scoring: compute the AI-attribution score for one actor.

The score is the noisy-OR combination of the evidence rules that fired:
`score = 1 - prod(1 - w_i)`.  Two reverse-evidence rules (E14 dictionary
brute-force discrimination, E15 dictionary-driven high frequency enumeration)
carry weight zero and cap the score at 0.25 when they fire, because a scripted
enumerator is not an AI attack agent.

The decision threshold used by the study is 0.35.

Two input modes
---------------
* `--input DIR`   : a directory of capture directories (each holding an
  `access.jsonl`).  Every capture is segmented into behavioural actors and
  scored; one JSONL file per capture is written into the output directory.
* `--actors FILE` : a file of pre-segmented actors, as written by
  `research/pipeline/actor_segmentation.py`.

Example
-------
```bash
python -m research.pipeline.score_actor --input data/positive --out out/actor
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from ..engine import evidence as engine_evidence
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.engine import evidence as engine_evidence

DECISION_THRESHOLD = 0.35


def score_features(features: dict, threshold: float = DECISION_THRESHOLD) -> dict:
    """Score one feature vector and report the rules that fired."""
    res = engine_evidence.score_window(features, threshold)
    return {
        "score": res["score"],
        "verdict": "ai_suspect" if res["score"] >= threshold else "not_ai_suspect",
        "threshold": threshold,
        "fired": [f["rule"] for f in res["fired"]],
        "fired_detail": [{"rule": f["rule"], "name": f["name"], "family": f["family"],
                          "weight": f["weight"], "why": f["why"]} for f in res["fired"]],
        "families": res["families"],
        "vetoed": res["vetoed"],
        "veto_reason": res["veto_reason"],
    }


def score_requests(requests: list, threshold: float = DECISION_THRESHOLD) -> dict:
    """Score one group of engine request objects."""
    try:
        from .feature_extraction import extract_features
    except ImportError:
        from research.pipeline.feature_extraction import extract_features

    return score_features(extract_features(requests), threshold)


def score_actor(actor: dict, threshold: float = DECISION_THRESHOLD) -> dict:
    """Score one actor record (as produced by `actor_segmentation.py`)."""
    try:
        from .feature_extraction import _requests_from_actor
    except ImportError:
        from research.pipeline.feature_extraction import _requests_from_actor

    reqs = _requests_from_actor(actor)
    out = score_requests(reqs, threshold)
    out.update({
        "key": actor.get("key", ""),
        "src": actor.get("src", ""),
        "lab": actor.get("lab", ""),
        "n_requests": actor.get("n_requests", len(reqs)),
        "duration_s": actor.get("duration_s", 0.0),
    })
    return out


def score_capture(capture: Path, threshold: float = DECISION_THRESHOLD, mode: str = "session") -> list:
    """Segment one capture file into actors and score every actor."""
    try:
        from .actor_segmentation import read_requests, segment_requests
        from .feature_extraction import _requests_from_actor, extract_features
    except ImportError:
        from research.pipeline.actor_segmentation import read_requests, segment_requests
        from research.pipeline.feature_extraction import _requests_from_actor, extract_features

    reqs = read_requests(capture, lab=capture.parent.name)
    actors = segment_requests(reqs, mode=mode)
    out = []
    for a in actors:
        rec = score_requests(a.requests, threshold)
        rec.update({
            "key": a.key,
            "src": a.src,
            "lab": capture.parent.name,
            "n_requests": a.n_requests,
            "duration_s": a.duration_s,
        })
        out.append(rec)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score the actors of a capture directory or of an actor file.")
    ap.add_argument("--input", default="", help="directory with capture directories (each holding access.jsonl)")
    ap.add_argument("--actors", default="", help="file of pre-segmented actors")
    ap.add_argument("--out", required=True, help="output directory (with --input) or file (with --actors)")
    ap.add_argument("--threshold", type=float, default=DECISION_THRESHOLD)
    ap.add_argument("--mode", choices=("session", "window"), default="session")
    args = ap.parse_args(argv)

    if bool(args.input) == bool(args.actors):
        raise SystemExit("give exactly one of --input or --actors")

    if args.actors:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with Path(args.actors).open("r", encoding="utf-8") as fh, outp.open("w", encoding="utf-8") as out:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                out.write(json.dumps(score_actor(json.loads(line), args.threshold),
                                     ensure_ascii=False, sort_keys=True) + "\n")
                n += 1
        print("actors=%d -> %s" % (n, outp))
        return 0

    root = Path(args.input)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    captures = sorted([f for f in root.rglob("access.jsonl") if f.is_file()])
    if not captures:
        captures = sorted([f for f in root.rglob("*.jsonl") if f.is_file()])
    if not captures:
        raise SystemExit("no capture files found under %s" % root)
    frameworks = _framework_map(root)
    total = 0
    for cap in captures:
        recs = score_capture(cap, args.threshold, args.mode)
        name = cap.parent.name if cap.parent != root else root.name
        framework = frameworks.get(name, "")
        for rec in recs:
            rec["fw"] = framework
            rec["capture"] = name
        outp = outdir / ("%s.jsonl" % name)
        with outp.open("w", encoding="utf-8") as out:
            for rec in recs:
                out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        total += len(recs)
        print("%-24s actors=%-4d max_score=%.4f -> %s" % (
            name, len(recs), max([r["score"] for r in recs]) if recs else 0.0, outp))
    print("captures=%d actors=%d -> %s" % (len(captures), total, outdir))
    return 0


def _framework_map(root: Path) -> dict:
    """Map a capture directory name to its framework, using the shipped index."""
    index = Path(root) / "_index.json"
    if not index.exists():
        index = Path(root).parent / "_index.json"
    if not index.exists():
        return {}
    try:
        data = json.loads(index.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for row in data.get("captures", []):
        actor_id = row.get("actor_id")
        if actor_id:
            out[actor_id] = row.get("framework", "")
    return out


if __name__ == "__main__":
    raise SystemExit(main())

"""Feature extraction: thin wrapper around the vendored engine extractor.

The engine (`research/engine/features.py`) owns every feature definition; this
module only provides a stable entry point, a JSON-serialisable output and a
command line interface.  Keeping the wrapper thin guarantees that the numbers
produced here are the same numbers the study measured.

Feature families
----------------
F1 semantic causality, F2 active probe, F3 feedback adaptivity, F4 rhythm,
F5 exploration structure, F6 repetition and verification, F7 identity lineage,
F8 egress intelligence, F9 tool fingerprint, F10 machine-like account naming,
F11 payload semantics.

Two families are not computable from a request-only capture and are therefore
reported as unavailable rather than as zero: F1 needs response headers/body and
F2 needs a response side channel.  `unavailable_families()` lists them.

Example
-------
```bash
python -m research.pipeline.feature_extraction \
    --actors actors.jsonl --out features.jsonl
```
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:  # package import
    from ..engine import config as engine_config
    from ..engine import features as engine_features
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.engine import config as engine_config
    from research.engine import features as engine_features

# Families that need a response-side capture.  The study capture layer records
# requests only, so these families are not measurable and are never faked.
RESPONSE_SIDE_FAMILIES = ("F1_semantic_causality", "F2_probe")


def default_config():
    """Engine configuration used by the study (all measurable families on)."""
    return engine_config.default_config()


def unavailable_families(cfg=None) -> list:
    """Families that cannot be computed with the current capture capability."""
    cfg = cfg or default_config()
    out = []
    if not (cfg.have_response_headers or cfg.have_response_body):
        out.append("F1_semantic_causality")
    out.append("F2_probe")
    return out


def extract_features(requests: list, cfg=None, egress=None) -> dict:
    """Extract the full feature vector for one request group.

    `requests` is a list of engine `Request` objects (or anything with the
    same attributes).  Returns a flat `{feature_name: float}` mapping.
    """
    cfg = cfg or default_config()
    if not requests:
        return {}
    return engine_features.extract(list(requests), cfg, egress=egress)


def feature_names(cfg=None) -> list:
    """Sorted list of the feature names produced for a configuration."""
    feats = extract_features  # placeholder to keep the linter quiet
    del feats
    cfg = cfg or default_config()
    prefixes = []
    for fam, pref in engine_features.FAMILY_OF.items():
        if cfg.feature_enabled(fam):
            prefixes.append(pref)
    return sorted(prefixes)


def _requests_from_actor(actor: dict):
    """Rebuild engine Request objects from a serialised actor record."""
    try:
        from ..engine.capture import Request, _parse_ts
    except ImportError:
        from research.engine.capture import Request, _parse_ts

    out = []
    for r in actor.get("requests", []):
        d = dict(r)
        ts = d.get("ts")
        if isinstance(ts, str):
            ts = _parse_ts(ts)
        out.append(Request(
            ts=ts, rid=str(d.get("rid", "")), src=str(d.get("src", "")),
            method=str(d.get("method", "")).upper(), uri=str(d.get("uri", "") or ""),
            args=str(d.get("args", "") or ""), status=int(d.get("status", 0) or 0),
            bytes=int(d.get("bytes", 0) or 0), rt=float(d.get("rt", 0) or 0),
            urt=str(d.get("urt", "") or ""), uaddr=str(d.get("uaddr", "") or ""),
            host=str(d.get("host", "") or ""), ua=str(d.get("ua", "") or ""),
            ref=str(d.get("ref", "") or ""), user=str(d.get("user", "-") or "-"),
            role=str(d.get("role", "-") or "-"), body=str(d.get("body", "") or ""),
            lab=str(d.get("lab", "") or "")))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Extract features for every actor in an actor file.")
    ap.add_argument("--actors", required=True, help="actor file produced by actor_segmentation.py")
    ap.add_argument("--out", required=True, help="output feature file (JSONL)")
    args = ap.parse_args(argv)

    cfg = default_config()
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with Path(args.actors).open("r", encoding="utf-8") as fh, outp.open("w", encoding="utf-8") as out:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            actor = json.loads(line)
            reqs = _requests_from_actor(actor)
            feats = extract_features(reqs, cfg)
            rec = {
                "key": actor.get("key", ""),
                "src": actor.get("src", ""),
                "lab": actor.get("lab", ""),
                "n_requests": actor.get("n_requests", len(reqs)),
                "features": feats,
                "unavailable_families": unavailable_families(cfg),
            }
            out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    print("actors=%d -> %s" % (n, outp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

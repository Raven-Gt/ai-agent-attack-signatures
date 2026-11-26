"""Actor segmentation: split a request stream into behavioural actors.

Definition used throughout the study
------------------------------------
The decision unit is a *behavioural actor*: a group of requests issued by one
source address within one time window.  The source address is only a grouping
key -- it never enters the feature set, so the detector cannot cheat by
memorising an address.

Two segmentation modes are provided because the study uses two different
definitions, and both are reproduced here:

* `session` (default) -- one actor per (source address, contiguous burst).
  A new actor starts when the silence since the previous request of that
  address exceeds `--gap-seconds` (default 600 s).  This is the mode used for
  the positive corpus (real AI attack-agent runs).
* `window` -- one actor per (source address, fixed time window).
  A new actor starts when a request falls outside the window that the first
  request of the current actor opened (default 10 min).  This is the mode used
  for the negative corpus (real internet attackers segmented by address and
  10 minute window), so that repeated bursts by one attacker do not collapse
  into a single actor.

Container health checks (`/health`, `/healthz`, `/ready`, `/live`) are
removed before segmentation, exactly as in the study, because a docker
healthcheck stream is not attacker behaviour.

Example
-------
```bash
python -m research.pipeline.actor_segmentation \
    --input capture.jsonl --out actors.jsonl --mode session
```
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:  # package import
    from ..engine import capture as engine_capture
    from ..engine import segment as engine_segment
except ImportError:  # executed as a script
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.engine import capture as engine_capture
    from research.engine import segment as engine_segment

HEALTH_URIS = ("/health", "/healthz", "/ready", "/live")


@dataclass
class Actor:
    """One behavioural actor."""

    key: str
    src: str
    mode: str
    lab: str = ""
    start: float = 0.0
    end: float = 0.0
    n_requests: int = 0
    requests: list = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end - self.start)

    def to_dict(self, include_requests: bool = True) -> dict:
        out = {
            "key": self.key,
            "src": self.src,
            "mode": self.mode,
            "lab": self.lab,
            "start": self.start,
            "end": self.end,
            "duration_s": self.duration_s,
            "n_requests": self.n_requests,
        }
        if include_requests:
            out["requests"] = [_request_to_dict(r) for r in self.requests]
        return out


def _request_to_dict(request) -> dict:
    """Serialise one request; the timestamp becomes an ISO 8601 string."""
    out = dict(request.__dict__)
    ts = out.get("ts")
    if hasattr(ts, "isoformat"):
        out["ts"] = ts.isoformat()
    return out


def read_requests(path: Path, lab: str = "") -> list:
    """Read an nginx-audit-style JSONL capture into `Request` objects."""
    return engine_capture.read_access_jsonl(Path(path), lab=lab)


def drop_health_checks(requests: list) -> list:
    """Remove container health-check traffic (not attacker behaviour)."""
    return [r for r in requests if r.uri not in HEALTH_URIS]


def segment_sessions(requests: list, gap_seconds: float = 600.0,
                     min_requests: int = 1, lab: str = "") -> list:
    """Split by source address and by silence (gap based)."""
    by_src = {}
    for r in requests:
        by_src.setdefault(r.src, []).append(r)
    actors = []
    for src in sorted(by_src):
        rs = sorted(by_src[src], key=lambda r: (r.t, r.rid))
        current = []
        prev_t = None
        for r in rs:
            if prev_t is not None and (r.t - prev_t) > gap_seconds and current:
                actors.append(_make_actor(src, current, "session", lab))
                current = []
            current.append(r)
            prev_t = r.t
        if current:
            actors.append(_make_actor(src, current, "session", lab))
    return [a for a in actors if a.n_requests >= min_requests]


def segment_windows(requests: list, window_minutes: float = 10.0,
                    min_requests: int = 1, lab: str = "") -> list:
    """Split by source address and by fixed time window."""
    width = window_minutes * 60.0
    by_src = {}
    for r in requests:
        by_src.setdefault(r.src, []).append(r)
    actors = []
    for src in sorted(by_src):
        rs = sorted(by_src[src], key=lambda r: (r.t, r.rid))
        current = []
        anchor = None
        for r in rs:
            if anchor is None:
                anchor = r.t
            if current and (r.t - anchor) > width:
                actors.append(_make_actor(src, current, "window", lab))
                current = []
                anchor = r.t
            current.append(r)
        if current:
            actors.append(_make_actor(src, current, "window", lab))
    return [a for a in actors if a.n_requests >= min_requests]


def _make_actor(src: str, reqs: list, mode: str, lab: str) -> Actor:
    a = Actor(key="%s#%d" % (src, len(reqs) and 0), src=src, mode=mode, lab=lab)
    a.requests = reqs
    a.n_requests = len(reqs)
    a.start = reqs[0].t
    a.end = reqs[-1].t
    return a


def segment_requests(requests: list, mode: str = "session", gap_seconds: float = 600.0,
                     window_minutes: float = 10.0, min_requests: int = 1,
                     keep_noise: bool = False, lab: str = "") -> list:
    """Segment a request stream into behavioural actors."""
    reqs = list(requests)
    if not keep_noise:
        reqs = drop_health_checks(reqs)
    if mode == "session":
        out = segment_sessions(reqs, gap_seconds=gap_seconds, min_requests=min_requests, lab=lab)
    elif mode == "window":
        out = segment_windows(reqs, window_minutes=window_minutes, min_requests=min_requests, lab=lab)
    else:
        raise ValueError("unknown mode %r (expected 'session' or 'window')" % mode)
    for i, a in enumerate(out):
        a.key = "%s#%d" % (a.src, i)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Segment a request stream into behavioural actors.")
    ap.add_argument("--input", required=True, help="capture file (nginx audit JSONL)")
    ap.add_argument("--out", required=True, help="output actor file (JSONL)")
    ap.add_argument("--mode", choices=("session", "window"), default="session")
    ap.add_argument("--gap-seconds", type=float, default=600.0)
    ap.add_argument("--window-minutes", type=float, default=10.0)
    ap.add_argument("--min-requests", type=int, default=1)
    ap.add_argument("--lab", default="")
    ap.add_argument("--keep-noise", action="store_true", help="keep container health checks")
    ap.add_argument("--no-requests", action="store_true", help="do not embed the requests in the output")
    args = ap.parse_args(argv)

    reqs = read_requests(Path(args.input), lab=args.lab)
    actors = segment_requests(reqs, mode=args.mode, gap_seconds=args.gap_seconds,
                              window_minutes=args.window_minutes, min_requests=args.min_requests,
                              keep_noise=args.keep_noise, lab=args.lab)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("w", encoding="utf-8") as fh:
        for a in actors:
            fh.write(json.dumps(a.to_dict(include_requests=not args.no_requests), ensure_ascii=False) + "\n")
    total = sum(a.n_requests for a in actors)
    print("segments=%d requests=%d -> %s" % (len(actors), total, outp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

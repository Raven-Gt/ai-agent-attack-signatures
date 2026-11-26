"""Segmentation layer: noise removal -> behavioural actor -> session -> online detection window.

Design constraints
------------------
* The segmentation does **not** use the source address as a feature.  It is
  only a grouping key, so that the detector cannot cheat by telling addresses
  apart.  Every feature is therefore computed inside a group, and the address
  is only used to cut the traffic into behavioural actors.
* Sessions are cut on **time silence** only (gap > session_gap_s), never on the
  user agent and never on the identity.  An identity change is a feature (F7
  identity lineage); using it to cut sessions would leak the answer.
* The window is the **online detection** unit: sliding windows cover the whole
  session and are used to compute early-stop detection latency.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .capture import Request
from .config import Config

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
LONGNUM_RE = re.compile(r"\d{3,}")
HASH_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Static asset and infrastructure paths: they show that a browser was loading
STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".map", ".webp", ".mp4", ".txt")


def normalize_path(uri: str) -> str:
    """Turn a path into a template: numbers, UUIDs, hashes and mail addresses -> {id}.

    This is the basis of the "same endpoint" decision: an agent hammers the
    same endpoint with different ids, and only after templating can that be
    counted as endpoint enumeration instead of a pile of distinct paths.
    """
    p = (uri or "").split("?")[0]
    p = UUID_RE.sub("{id}", p)
    p = HASH_RE.sub("{id}", p)
    p = EMAIL_RE.sub("{email}", p)
    p = LONGNUM_RE.sub("{id}", p)
    return p


def path_family(tmpl: str) -> str:
    """Endpoint family: the service prefix formed by the first path segment.

    Measured AI attacks span several service prefixes (identity, workshop,
    community, mailhog, chatbot), while a fixed script usually hits one or
    two.  That is the structured measure of breadth.
    """
    seg = [s for s in (tmpl or "").split("/") if s]
    if not seg:
        return "/"
    if seg[0] in ("identity", "workshop", "community", "chatbot", "mailhog"):
        return "/" + seg[0]
    return "/" + seg[0]


def status_class(code: int) -> str:
    if code < 200:
        return "1xx"
    if code < 300:
        return "2xx"
    if code < 400:
        return "3xx"
    if code < 500:
        return "4xx"
    return "5xx"


def is_static(uri: str) -> bool:
    return (uri or "").split("?")[0].lower().endswith(STATIC_EXT)


@dataclass
class Session:
    key: str
    lab: str
    reqs: list = field(default_factory=list)
    label: str = ""          # ground truth (evaluation only, never a feature)
    actor: str = ""

    @property
    def start(self) -> float:
        return self.reqs[0].t if self.reqs else 0.0

    @property
    def end(self) -> float:
        return self.reqs[-1].t if self.reqs else 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)


@dataclass
class Window:
    """Online detection unit: a run of consecutive requests and its metadata."""
    key: str
    lab: str
    reqs: list = field(default_factory=list)
    label: str = ""
    session_key: str = ""
    start_idx: int = 0
    is_prefix: bool = False   # prefix window of the session (used by early-stop detection)

    @property
    def duration(self) -> float:
        if not self.reqs:
            return 0.0
        return self.reqs[-1].t - self.reqs[0].t


def filter_noise(reqs: list, cfg: Config) -> list:
    """Remove container health checks and similar noise.

    Measured: 475+401 /health responses with status 200 on 127.0.0.1 are docker
    health checks, not attacker behaviour.  They must be removed, otherwise a
    high frequency health check is mistaken for a machine-like signal.
    """
    out = []
    for r in reqs:
        if getattr(cfg, "drop_uri_all_src", False) and r.uri in cfg.drop_uri_exact:
            continue
        if cfg.drop_src_loopback and r.src in ("127.0.0.1", "::1") and r.uri in cfg.drop_uri_exact:
            continue
        if r.uri in cfg.drop_uri_exact and r.src.startswith("127."):
            continue
        out.append(r)
    return out


def build_sessions(reqs: list, cfg: Config, labels: dict = None) -> list:
    """Cut sessions by (source address, time silence).

    labels: optional {src: label} mapping, used only to attach ground truth
    labels during evaluation.
    """
    labels = labels or {}
    by_src = {}
    for r in reqs:
        by_src.setdefault(r.src, []).append(r)
    sessions = []
    for src, rs in sorted(by_src.items()):
        rs.sort(key=lambda r: (r.t, r.rid))
        cur = []
        prev_t = None
        for r in rs:
            if prev_t is not None and (r.t - prev_t) > cfg.session_gap_s and cur:
                sessions.append(Session(key="%s#%d" % (src, len(sessions)),
                                        lab=cur[0].lab, reqs=cur,
                                        label=labels.get(src, ""), actor=src))
                cur = []
            cur.append(r)
            prev_t = r.t
        if cur:
            sessions.append(Session(key="%s#%d" % (src, len(sessions)),
                                    lab=cur[0].lab, reqs=cur,
                                    label=labels.get(src, ""), actor=src))
    return [s for s in sessions if len(s.reqs) >= cfg.min_session_len]


def make_windows(sessions: list, cfg: Config) -> list:
    """Cut a session into sliding windows and prefix windows (online detection)."""
    out = []
    for s in sessions:
        n = len(s.reqs)
        for start in range(0, max(1, n - cfg.window_size + 1), cfg.window_stride):
            chunk = s.reqs[start:start + cfg.window_size]
            if len(chunk) < min(cfg.min_session_len, cfg.window_size):
                continue
            out.append(Window(key="%s::w%d" % (s.key, start), lab=s.lab, reqs=chunk,
                              label=s.label, session_key=s.key, start_idx=start,
                              is_prefix=(start == 0)))
        # Prefix windows: the first k requests, used by early-stop detection
        for k in (5, 10, 20, 30, 50, 100):
            if 5 <= k <= n:
                out.append(Window(key="%s::p%d" % (s.key, k), lab=s.lab,
                              reqs=s.reqs[:k], label=s.label, session_key=s.key,
                              start_idx=0, is_prefix=True))
    return out

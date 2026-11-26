"""Capture layer: parse raw lab logs into a unified request event stream.

Sources:
1. nginx audit layer access.jsonl (primary source)
   ts, rid, src, xff, method, uri, ruri, args, status, bytes, rt, urt,
   uaddr, host, ua, ref, user, role, body
2. kernel interception log denied.log (blocked egress -> egress intelligence F8)

Measured facts:
* access.jsonl records no response body and no response headers, so F1
  (semantic causality) and F2 (active probe) cannot be computed from it.
  They are reported as not available, never as invented numbers.
* user and role are the sub and role claims that nginx decodes from the JWT.
  They are server side identities even when the token itself is not stored,
  and they are the raw material for identity lineage (F7) and for machine-like
  account naming (F10).
* requests with src=127.0.0.1 and uri=/health are container health check
  noise and must be removed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import Config


@dataclass
class Request:
    ts: datetime
    rid: str
    src: str
    method: str
    uri: str
    args: str
    status: int
    bytes: int
    rt: float
    urt: str
    uaddr: str
    host: str
    ua: str
    ref: str
    user: str
    role: str
    body: str
    lab: str = ""

    @property
    def t(self) -> float:
        return self.ts.timestamp()

    @property
    def full_path(self) -> str:
        return self.uri + (("?" + self.args) if self.args else "")


@dataclass
class Egress:
    ts: datetime
    src: str
    dst: str
    dpt: int
    proto: str
    kind: str
    lab: str = ""


def _parse_ts(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tail = "", ""
        for i, ch in enumerate(rest):
            if ch.isdigit():
                frac += ch
            else:
                tail = rest[i:]
                break
        s = head + "." + (frac + "000000")[:6] + tail
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def read_access_jsonl(path: Path, lab: str = "") -> list:
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                ts = _parse_ts(d["ts"])
            except Exception:
                continue
            out.append(Request(
                ts=ts, rid=str(d.get("rid", "")), src=str(d.get("src", "")),
                method=str(d.get("method", "")).upper(),
                uri=str(d.get("uri", "") or ""), args=str(d.get("args", "") or ""),
                status=int(d.get("status", 0) or 0), bytes=int(d.get("bytes", 0) or 0),
                rt=float(d.get("rt", 0) or 0), urt=str(d.get("urt", "") or ""),
                uaddr=str(d.get("uaddr", "") or ""), host=str(d.get("host", "") or ""),
                ua=str(d.get("ua", "") or ""), ref=str(d.get("ref", "") or ""),
                user=str(d.get("user", "-") or "-"), role=str(d.get("role", "-") or "-"),
                body=str(d.get("body", "") or ""), lab=lab))
    out.sort(key=lambda r: (r.t, r.rid))
    return out


_DENY_RE = re.compile(r"^\[(?P<ts>[\d.]+)\]\s+(?P<kind>[A-Z\-]+)\s+(?P<rest>.*)$")
_KV_RE = re.compile(r"(?P<k>\w+)=(?P<v>\S+)")


def read_denied_log(path: Path, lab: str = "") -> list:
    """Kernel interception log: outbound traffic blocked by the network guard -> F8."""
    out = []
    if not path or not Path(path).exists():
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = _DENY_RE.match(line)
            if not m:
                continue
            kv = {mm.group("k"): mm.group("v") for mm in _KV_RE.finditer(m.group("rest"))}
            try:
                ts = datetime.fromtimestamp(float(m.group("ts")), tz=timezone.utc)
            except Exception:
                continue
            out.append(Egress(ts=ts, src=kv.get("SRC", ""), dst=kv.get("DST", ""),
                               dpt=int(kv.get("DPT", "0") or 0), proto=kv.get("PROTO", ""),
                               kind=m.group("kind"), lab=lab))
    out.sort(key=lambda e: e.ts)
    return out


def load_lab(lab: str, cfg: Config):
    from .config import LABS

    if lab not in LABS:
        raise KeyError("unknown lab %s; known=%s" % (lab, list(LABS)))
    spec = LABS[lab]
    cp = Path(spec["capture"])
    dp = Path(spec["denied"]) if spec.get("denied") else None
    reqs = read_access_jsonl(cp, lab=lab) if cp.exists() else []
    egr = read_denied_log(dp, lab=lab) if dp else []
    return reqs, egr

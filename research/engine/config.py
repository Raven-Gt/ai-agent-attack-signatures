"""WP14 AI autonomous attack traffic detection engine: configuration and paths.

Design notes
------------
1. The capture layer only trusts the raw capture files (nginx access.jsonl and
   denied.log) and never a pre-computed feature file.  An existing report on
   one lab degenerated to two requests because its window start equalled its
   window end, so the features have to be recomputed from the raw layer.
2. The feature families are F1..F11 and each one can be switched off
   individually, which is what the ablation experiments need.
3. The probe family (passphrase inheritance, transformation challenge, hint
   following) needs response side capture.  The current capture layer has no
   response headers and no response body, so the probe family is marked as not
   available instead of being given invented numbers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------- path lookup ---
# Vendored copy note: the upstream project hard-coded absolute paths to an
# experimental lab (a WSL share) in this block.  This released repository must
# not reference paths outside the repository, so the lab registry is now read
# from an optional labs.json located next to this module (empty when absent).
# The research pipeline always receives capture files as command line arguments.
LABS_FILE = Path(__file__).resolve().parent / "labs.json"


def load_labs() -> dict:
    """Read the optional lab registry (labs.json, relative to this module)."""
    if not LABS_FILE.exists():
        return {}
    import json

    data = json.loads(LABS_FILE.read_text(encoding="utf-8"))
    out = {}
    for name, spec in (data or {}).items():
        spec = dict(spec)
        for k in ("capture", "denied", "identity_log", "runs"):
            if spec.get(k):
                spec[k] = str(Path(spec[k]))
        out[name] = spec
    return out


LABS = load_labs()

OUT_DIR = Path(__file__).resolve().parent.parent / "out"


# ------------------------------------------------------------------ configuration ---
@dataclass
class Config:
    # --- segmentation ---
    session_gap_s: float = 600.0        # a longer silence starts a new session
    window_size: int = 30               # online detection window, in requests
    window_stride: int = 10
    min_session_len: int = 5            # shorter sessions do not produce windows

    # --- noise removal ---
    drop_uri_exact = ("/health", "/healthz", "/ready", "/live")
    drop_src_loopback = True            # 127.0.0.1 /health container health checks
    drop_uri_all_src = True             # /health from 172.x is a health check too, not behaviour

    # --- normalisation ---
    id_param_re = r"(?<![A-Za-z0-9])((?:\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}))(?![A-Za-z0-9])"
    uuid_re = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    email_re = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    ts_suffix_re = r"\d{10,13}"        # timestamp suffix inside account names
    label_tokens = {
        "exp", "repro", "test", "probe", "dsh", "p1", "p2", "p3", "p4", "p5",
        "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",
        "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24",
        "rev", "role", "role2", "isadmin", "credit", "type", "veh", "qa",
        "admin", "user", "guest", "attacker", "lab", "scan",
    }

    # --- feature switches (used by the ablation) ---
    feature_families = {
        "F1_semantic_causality": True,
        "F2_probe": True,
        "F3_feedback_adaptivity": True,
        "F4_rhythm": True,
        "F5_exploration": True,
        "F6_repetition_verify": True,
        "F7_identity": True,
        "F8_egress_intel": True,
        "F9_tool_fingerprint": True,
        "F10_machine_identity": True,
        "F11_payload_semantics": True,
    }

    # --- decision threshold ---
    decision_threshold: float = 0.5
    early_detection_windows: tuple = (1, 3, 5, 10)

    # --- capture capability (decides whether F1 and F2 are usable) ---
    have_response_headers: bool = False   # the capture layer records no response headers
    have_response_body: bool = False       # the capture layer records no response body

    out_dir: Path = field(default=OUT_DIR)

    def feature_enabled(self, name: str) -> bool:
        return bool(self.feature_families.get(name, False))


def default_config() -> Config:
    return Config()

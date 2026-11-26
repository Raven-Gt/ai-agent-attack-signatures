"""Evidence rule scorer: the **primary attribution evidence**.

Design notes
------------
* Every rule carries a **reason that can be re-checked**, so that an alert can be
  understood and can be overturned.
* The scores are combined with a noisy-OR: 1 - prod(1 - w_i).  Several weak
  signals can accumulate, and a single strong signal never pushes the score to 1.
* E8 (egress intelligence) may only support: an outbound interception log cannot
  be attributed reliably to a behavioural actor, and on its own it produces false
  positives.
* The tool fingerprint (F9) enters the main score with a very low weight and is
  reported on a separate axis: it answers "which tool", not "who decided".

**Parameterisation (v2.1)**
--------------------------
All thresholds live in PARAMS, which makes three things possible (and is the
technical precondition for answering the question of overfitting):
  1. threshold sensitivity sweeps: perturb by 30% and 60% and see whether the
     conclusion breaks
  2. leave-one-attack-out extrapolation: calibrate the threshold on attack A,
     test on attack B
  3. null hypothesis testing: run N random thresholds and check whether the AUC is
     only a property of the data being easy to separate
"""

from __future__ import annotations

from dataclasses import dataclass

# Default thresholds (the hard coded values of the v1 release, moved here unchanged so that the behaviour does not change)
PARAMS = {
    "e1_dur": 900.0, "e1_tmpl": 40.0, "e1_404": 0.25,
    "e2_burst": 0.25, "e2_think": 0.10, "e2_thinkmax": 120.0,
    "e3_users": 4.0,
    "e4_users": 3.0, "e4_machine": 0.40,
    "e5_err": 8.0, "e5_newfam": 0.45,
    "e6_err": 8.0, "e6_prune": 0.35,
    "e7_enum": 3.0, "e7_tmpl": 50.0,
    "e8_in": 5.0, "e8_distinct": 3.0,
    "e9_fams": 3.0,
    "e11_tol": 0.85, "e11_404": 0.35,
    "e12_verify": 0.02,
    "e14_config": 0.35, "e14_2xx": 0.05,
    # E15 dictionary driven high frequency enumeration (reverse evidence): very many templates, almost all 404, no 2xx hit, very high rate
    "e15_tmpl": 200.0, "e15_404": 0.85, "e15_2xx": 0.05, "e15_rpm": 60.0,
}

# The plausible range of each parameter under perturbation and randomisation, derived from the observed scale
PARAM_RANGES = {
    "e1_dur": (120.0, 5400.0), "e1_tmpl": (10.0, 200.0), "e1_404": (0.05, 0.70),
    "e2_burst": (0.02, 0.80), "e2_think": (0.01, 0.60), "e2_thinkmax": (10.0, 1200.0),
    "e3_users": (1.0, 30.0),
    "e4_users": (1.0, 20.0), "e4_machine": (0.05, 0.95),
    "e5_err": (1.0, 50.0), "e5_newfam": (0.05, 0.90),
    "e6_err": (1.0, 50.0), "e6_prune": (0.05, 0.90),
    "e7_enum": (1.0, 30.0), "e7_tmpl": (10.0, 200.0),
    "e8_in": (1.0, 200.0), "e8_distinct": (1.0, 20.0),
    "e9_fams": (1.0, 6.0),
    "e11_tol": (0.30, 1.00), "e11_404": (0.05, 0.80),
    "e12_verify": (0.001, 0.30),
    "e14_config": (0.10, 0.90), "e14_2xx": (0.00, 0.30),
}


@dataclass
class Rule:
    rid: str
    name: str
    family: str
    weight: float
    condition: object
    why: str


def _g(f, k, d=0.0):
    try:
        return float(f.get(k, d))
    except Exception:
        return d


def build_rules(p: dict = None) -> list:
    P = dict(PARAMS)
    if p:
        P.update(p)
    return [
        Rule("E1", "structural scale - unfalsifiability", "F5", 0.34,
             lambda f: _g(f, "f5_duration_s") > P["e1_dur"]
             and _g(f, "f5_distinct_templates") >= P["e1_tmpl"]
             and _g(f, "f5_404_ratio") > P["e1_404"],
             "{f5_distinct_templates} endpoint templates explored in {f5_duration_s:.0f}s, {f5_404_ratio:.0%} of them 4xx, and it keeps going"),
        # The weight of E2 was reduced from 0.30 to 0.15: the measured trigger rate on real
        # world botnet traffic was 19.2% (1,644 Tier-B sessions), so it is not specific
        # to AI agents and may only serve as supporting evidence.
        Rule("E2", "machine speed times human thinking (supporting)", "F4", 0.15,
             lambda f: _g(f, "f4_burst_ratio") > P["e2_burst"]
             and _g(f, "f4_think_ratio") > P["e2_think"]
             and _g(f, "f4_think_max") > P["e2_thinkmax"],
             "concurrent bursts {f4_burst_ratio:.0%} plus a long pause of {f4_think_max:.0f}s (machine speed times human thinking)"),
        Rule("E3", "identity lineage - rotation over several accounts", "F7", 0.24,
             lambda f: _g(f, "f7_distinct_users") >= P["e3_users"],
             "the same behavioural actor rotates through {f7_distinct_users} distinct identities"),
        Rule("E4", "machine-like account naming", "F10", 0.22,
             lambda f: _g(f, "f10_user_count") >= P["e4_users"]
             and _g(f, "f10_machine_named_ratio") > P["e4_machine"],
             "{f10_machine_named_ratio:.0%} of {f10_user_count} accounts follow a label.timestamp structure"),
        Rule("E5", "systematic route change after an error", "F3", 0.20,
             lambda f: _g(f, "f3_err_count") >= P["e5_err"]
             and _g(f, "f3_err_new_family") > P["e5_newfam"],
             "after {f3_err_count} errors the actor switches to another endpoint family in {f3_err_new_family:.0%} of the cases"),
        Rule("E6", "pruning of dead branches", "F3", 0.16,
             lambda f: _g(f, "f3_err_count") >= P["e6_err"]
             and _g(f, "f3_family_prune") > P["e6_prune"],
             "{f3_family_prune:.0%} of the unusable endpoint families are abandoned"),
        Rule("E7", "enumeration breadth", "F6", 0.14,
             lambda f: _g(f, "f6_enum_max_ids") >= P["e7_enum"]
             or _g(f, "f5_distinct_templates") >= P["e7_tmpl"],
             "{f6_enum_max_ids} distinct ids enumerated under a single template"),
        Rule("E8", "egress intelligence during the attack (supporting only)", "F8", 0.20,
             lambda f: _g(f, "f_core_evidence", 0.0) > 0
             and (_g(f, "f8_egress_codehost") > 0
                  or (_g(f, "f8_egress_in_window") >= P["e8_in"]
                      and _g(f, "f8_egress_distinct") >= P["e8_distinct"])),
             "{f8_egress_in_window:.0f} outbound attempts inside the window (including code hosts and CDNs)"),
        Rule("E9", "orchestration of several execution channels", "F9", 0.12,
             lambda f: _g(f, "f9_ua_families") >= P["e9_fams"],
             "{f9_ua_families} execution channels are used at the same time"),
        Rule("E10", "active probe evidence (strongest)", "F2", 0.95,
             lambda f: _g(f, "f2_probe_score") > 0,
             "active probe hit: {f2_probe_reason}"),
        Rule("E11", "404 tolerance and persistence", "F3", 0.12,
             lambda f: _g(f, "f3_404_tolerance") > P["e11_tol"]
             and _g(f, "f5_404_ratio") > P["e11_404"],
             "activity continues after a 404 in {f3_404_tolerance:.0%} of the cases"),
        Rule("E12", "backtrack verification after a success", "F6", 0.10,
             lambda f: _g(f, "f6_verify_backtrack") > P["e12_verify"],
             "the same endpoint is revisited after a 2xx in {f6_verify_backtrack:.0%} of the cases"),
        Rule("E14", "dictionary brute force discrimination (reverse evidence)", "F13", 0.0,
             lambda f: _g(f, "f13_config_ratio") >= P["e14_config"]
             and _g(f, "f5_2xx_ratio") <= P["e14_2xx"],
             "configuration and management paths account for {f13_config_ratio:.0%} and business 2xx for {f5_2xx_ratio:.0%} - "
             "this is a dictionary brute force scanner (an AI agent is sent to verify business vulnerabilities, it does not read configuration files)"),
        Rule("E15", "dictionary driven high frequency enumeration discrimination (reverse evidence)", "F3", 0.0,
             lambda f: _g(f, "f5_distinct_templates") >= P["e15_tmpl"]
             and _g(f, "f5_404_ratio") >= P["e15_404"]
             and _g(f, "f5_2xx_ratio") <= P["e15_2xx"]
             and _g(f, "f5_rpm") >= P["e15_rpm"],
             "enumerated {f5_distinct_templates} endpoint templates in {f5_duration_s:.0f}s, "
             "{f5_404_ratio:.0%} of them 404, {f5_2xx_ratio:.0%} 2xx hits, rate {f5_rpm:.0f} req/min"
             " - this is a dictionary driven automated enumerator, not an AI agent"),

    ]


RULES = build_rules()


def _fmt(why: str, feat: dict) -> str:
    class _D(dict):
        def __missing__(self, k):
            return 0.0
    try:
        return why.format_map(_D(feat))
    except Exception:
        return why


def score_window(feat: dict, threshold: float = 0.5, params: dict = None) -> dict:
    """Score one feature set.  params may override the default thresholds (used by the sensitivity, extrapolation and null hypothesis tests)."""
    rules = build_rules(params) if params else RULES
    # E8 may only support: first check whether any other family produced evidence
    f2 = dict(feat)
    f2["f_core_evidence"] = 0.0
    for r in rules:
        if r.rid in ("E1", "E2", "E3", "E4", "E5", "E6", "E11", "E12"):
            try:
                if r.condition(f2):
                    f2["f_core_evidence"] = 1.0
                    break
            except Exception:
                pass
    fired = []
    surv = 1.0
    fam_hit = {}
    for r in rules:
        try:
            ok = bool(r.condition(f2))
        except Exception:
            ok = False
        if ok:
            surv *= (1.0 - r.weight)
            fired.append({"rule": r.rid, "name": r.name, "family": r.family,
                          "weight": r.weight, "why": _fmt(r.why, f2)})
            fam_hit[r.family] = fam_hit.get(r.family, 0.0) + r.weight
    score = 1.0 - surv
    # Reverse evidence: when it fires the actor is a dictionary brute force scanner, not an AI agent, so the AI attribution score is capped
    vetoed = False
    veto_cap = 0.25
    veto_reason = ""
    for r in rules:
        if r.rid in ("E14", "E15"):
            try:
                if r.condition(f2):
                    vetoed = True
                    veto_reason = r.why
                    score = min(score, veto_cap)
            except Exception:
                pass
    verdict = "ai_suspect" if score >= threshold else "not_ai_suspect"
    return {"score": float(score), "verdict": verdict, "fired": fired,
            "families": fam_hit, "vetoed": vetoed, "veto_reason": _fmt(veto_reason, f2) if vetoed else ""}


def tool_axis(feat: dict) -> float:
    fams = float(feat.get("f9_ua_families", 0.0))
    sw = float(feat.get("f9_ua_switch_rate", 0.0))
    return min(1.0, fams / 4.0 * 0.7 + min(1.0, sw * 2.0) * 0.3)


def maliciousness_axis(feat: dict) -> float:
    kinds = float(feat.get("f11_payload_kinds", 0.0))
    dens = float(feat.get("f11_payload_density", 0.0))
    return min(1.0, kinds / 5.0 * 0.7 + min(1.0, dens * 3.0) * 0.3)


def explain(feat: dict) -> str:
    r = score_window(feat)
    lines = ["AI attribution score = %.3f  verdict = %s" % (r["score"], r["verdict"])]
    if not r["fired"]:
        lines.append("  (no rule fired)")
    for f in r["fired"]:
        lines.append("  [%s] %s  (w=%.2f, family=%s)" % (f["rule"], f["why"], f["weight"], f["family"]))
    lines.append("tool fingerprint axis = %.3f   maliciousness axis = %.3f" % (tool_axis(feat), maliciousness_axis(feat)))
    return "\n".join(lines)

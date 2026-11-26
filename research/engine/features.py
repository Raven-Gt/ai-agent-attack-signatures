"""Feature family extraction: F1..F11.

Every family forms one group and can be switched off as a whole, which is what
the ablation needs to answer "how much did each family contribute".

Family list
-----------
F1  semantic causality  - is the next action decided by the content of the previous response (probe / identity switch); only partially available without response capture
F2  active probe        - passphrase inheritance, transformation challenge, hint following (needs response headers or body)
F3  feedback adaptivity - after a 4xx or 5xx, does the actor change route, prune or recover
F4  rhythm              - machine speed (concurrent bursts) times human thinking time (long pauses)
F5  exploration         - breadth, depth, entropy, 404 tolerance, discovery rate
F6  repetition          - enumeration strength, retry breadth, backtrack verification
F7  identity lineage    - number of identities, unauthenticated share, identity churn, roles
F8  egress intelligence - classification of the outbound destinations during the attack (code host, CDN, metadata, LLM API)
F9  tool fingerprint    - number of user agent families and switches (reference only, not part of the main score)
F10 machine naming      - how structured the local part of registered account names is (server side visible, hard to forge)
F11 payload semantics   - sqli, xss, ssrf and similar payload hits (the "maliciousness" axis, orthogonal to "AI-ness")
"""

from __future__ import annotations

import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from .capture import Request
from .config import Config
from .segment import EMAIL_RE, is_static, normalize_path, path_family, status_class


def shannon(counts) -> float:
    tot = sum(counts)
    if tot <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / tot
            h -= p * math.log2(p)
    return h


def cv(values) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    m = sum(values) / n
    if m <= 0:
        return 0.0
    var = sum((v - m) ** 2 for v in values) / (n - 1)
    return math.sqrt(var) / m


def bimodality(values) -> float:
    """Bimodality coefficient BC = (skew^2 + 1) / (excess kurtosis + 3); values above 0.555 count as bimodal."""
    n = len(values)
    if n < 4:
        return 0.0
    m = sum(values) / n
    var = sum((v - m) ** 2 for v in values) / n
    if var <= 0:
        return 0.0
    sd = math.sqrt(var)
    skew = sum((v - m) ** 3 for v in values) / n / (sd ** 3)
    kurt = sum((v - m) ** 4 for v in values) / n / (sd ** 4) - 3.0
    return (skew * skew + 1.0) / (kurt + 3.0)


def safe_div(a: float, b: float) -> float:
    return float(a) / float(b) if b else 0.0


SQLI_RE = re.compile(r"(union\s+select|or\s+1\s*=\s*1|information_schema|sqlite_master|sleep\(|benchmark\(|--\s|/\*|\b1\s*=\s*1)", re.I)
XSS_RE = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<img\s)", re.I)
SSRF_RE = re.compile(r"(169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|file://|gopher://|dict://|http://\d+\.\d+\.\d+\.\d+)", re.I)
TRAV_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e%252e)", re.I)
CMD_RE = re.compile(r"(\bcat\s+/etc|\bls\s+-la|;\s*whoami|\|\s*sh\b|\$\()", re.I)
JWT_RE = re.compile(r"(eyJ[A-Za-z0-9_-]{10,}|alg\s*[=:]|\bnone\b)", re.I)
MASS_RE = re.compile(r"(\brole\s*[=:]\s*|\badmin\s*[=:]\s*true|\bprice\s*[=:]\s*0)", re.I)
NOSQL_RE = re.compile(r"(\$ne\s*:|\$gt\s*:|\$regex\s*:)", re.I)

CONFIG_PROBE_RE = re.compile(
    r"(^|/)(\.env|\.git|\.ssh|\.svn|\.hg|wp-|wp_|config|configuration|"
    r"\.sql|\.bak|\.old|\.swp|\.yml|\.yaml|\.toml|\.ini|\.conf|"
    r"id_rsa|\.pem|\.key|\.tfstate|\.pkrvars|composer|package\.json|"
    r"\.aws|\.kube|\.dockercfg|Dockerfile|admin|manager)", re.I)
API_PATH_RE = re.compile(r"/api/", re.I)

PAYLOAD_PATS = {"sqli": SQLI_RE, "xss": XSS_RE, "ssrf": SSRF_RE,
                "path_traversal": TRAV_RE, "cmd_injection": CMD_RE,
                "jwt_tamper": JWT_RE, "mass_assignment": MASS_RE, "nosql": NOSQL_RE}


def classify_payload(text: str) -> list:
    hits = []
    for name, pat in PAYLOAD_PATS.items():
        if text and pat.search(text):
            hits.append(name)
    return hits


def _prep(reqs):
    """Expand the request list into parallel arrays for the analysis (avoid repeated traversal)."""
    tmpl = [normalize_path(r.uri) for r in reqs]
    fam = [path_family(t) for t in tmpl]
    stc = [status_class(r.status) for r in reqs]
    t = [r.t for r in reqs]
    return tmpl, fam, stc, t


def f3_feedback(reqs, tmpl, fam, stc, cfg) -> dict:
    """F3 feedback adaptivity: after an error, does the actor change route, prune or recover?

    Script: after a 404 it keeps walking down its word list (no family switch, no pruning).
    AI: after a 404 or 403 it **switches to another, semantically related route**
    and **abandons** the family that has been proven useless.
    """
    n = len(reqs)
    out = {}
    err_idx = [i for i in range(n) if stc[i] in ("4xx", "5xx")]
    out["f3_err_count"] = float(len(err_idx))
    if not err_idx:
        out.update({"f3_err_new_family": 0.0, "f3_err_new_template": 0.0,
                    "f3_err_same_template": 0.0, "f3_err_to_2xx_k3": 0.0,
                    "f3_family_prune": 0.0, "f3_404_tolerance": 0.0,
                    "f3_403_tolerance": 0.0, "f3_distinct_err_families": 0.0})
        return out
    nf = nt = ns = 0
    rec = 0
    for i in err_idx:
        if i + 1 >= n:
            continue
        if fam[i + 1] != fam[i]:
            nf += 1
        if tmpl[i + 1] != tmpl[i]:
            nt += 1
        else:
            ns += 1
        if any(stc[j] == "2xx" for j in range(i + 1, min(n, i + 4))):
            rec += 1
    m = max(1, len(err_idx))
    out["f3_err_new_family"] = safe_div(nf, m)
    out["f3_err_new_template"] = safe_div(nt, m)
    out["f3_err_same_template"] = safe_div(ns, m)
    out["f3_err_to_2xx_k3"] = safe_div(rec, m)
    out["f3_distinct_err_families"] = float(len(set(fam[i] for i in err_idx)))
    # Family pruning: after a family produced at least two 4xx responses, is it basically not visited any more?
    bad_fams = defaultdict(int)
    for i in err_idx:
        bad_fams[fam[i]] += 1
    pruned = tot = 0
    for f, c in bad_fams.items():
        if c < 2:
            continue
        last_err = max(i for i in err_idx if fam[i] == f)
        after = sum(1 for j in range(last_err + 1, n) if fam[j] == f)
        tot += 1
        if after <= 1:
            pruned += 1
    out["f3_family_prune"] = safe_div(pruned, tot)
    # 404 and 403 tolerance: does activity continue after an error (no pruning)?
    def tol(code):
        idx = [i for i in err_idx if reqs[i].status == code]
        if not idx:
            return 0.0
        cont = sum(1 for i in idx if i + 1 < n)
        return safe_div(cont, len(idx))
    out["f3_404_tolerance"] = tol(404)
    out["f3_403_tolerance"] = tol(403)
    return out


def _max_in_window(t, width):
    """Largest number of requests contained in any window of the given width.

    `t` must be sorted.  Equivalent to scanning every start index and counting
    the requests that follow within `width` seconds, but linear.
    """
    best = 0
    left = 0
    n = len(t)
    for right in range(n):
        while t[right] - t[left] > width:
            left += 1
        span = right - left + 1
        if span > best:
            best = span
    return best


def f4_rhythm(reqs, t, cfg) -> dict:
    """F4 rhythm: machine speed multiplied by human thinking time.

    Measured (lab1 PentAGI, 541 requests over 115 minutes):
      gap CV=7.86, median 0 s, p99=23 s, max 2462 s, at most 13 concurrent requests within 1 s.
    Measured (lab2 DSH, 1521 requests over 98 minutes):
      gap CV=19.92, 935 of 1520 gaps are 0, largest gap 2462 s.
    A fixed script has an almost constant interval (CV about 0) and no long pauses.

    The core composite is f4_machine_x_think:
      - a high "machine speed" (share of concurrent bursts) combined with a high
        "human thinking" (share of long pauses) is the core fingerprint of an AI
        attack: a script only has machine speed, a human only has human speed.
    """
    n = len(reqs)
    gaps = [t[i] - t[i - 1] for i in range(1, n)]
    out = {"f4_req_count": float(n)}
    if n < 2:
        out.update({"f4_gap_cv": 0.0, "f4_gap_median": 0.0, "f4_gap_p90": 0.0,
                    "f4_gap_max": 0.0, "f4_zero_gap_ratio": 0.0,
                    "f4_bimodality": 0.0, "f4_burst_max_1s": float(n),
                    "f4_burst_max_10s": float(n), "f4_burst_ratio": 1.0,
                    "f4_think_ratio": 0.0, "f4_think_cv": 0.0,
                    "f4_think_median": 0.0, "f4_think_max": 0.0,
                    "f4_machine_speed": 0.0, "f4_machine_x_think": 0.0,
                    "f4_gap_log_entropy": 0.0})
        return out
    gs = sorted(gaps)
    out["f4_gap_cv"] = cv(gaps)
    out["f4_gap_median"] = gs[len(gs) // 2]
    out["f4_gap_p90"] = gs[int(len(gs) * 0.9)]
    out["f4_gap_max"] = gs[-1]
    out["f4_zero_gap_ratio"] = safe_div(sum(1 for g in gaps if g <= 0.0), len(gaps))
    out["f4_bimodality"] = bimodality([math.log10(g + 0.01) for g in gaps])
    # Burst clusters: the largest number of requests inside a window of fixed
    # width.  The window is scanned with a sliding two-pointer, which is
    # equivalent to the original quadratic scan (both compute the maximum
    # number of requests contained in any window of that width) but linear in
    # the number of requests, which matters for captures with tens of
    # thousands of requests.
    out["f4_burst_max_1s"] = float(_max_in_window(t, 1.0))
    out["f4_burst_max_10s"] = float(_max_in_window(t, 10.0))
    burst_gaps = [g for g in gaps if g <= 1.0]
    think_gaps = [g for g in gaps if g > 1.0]
    out["f4_burst_ratio"] = safe_div(len(burst_gaps), len(gaps))
    out["f4_think_ratio"] = safe_div(len(think_gaps), len(gaps))
    out["f4_think_cv"] = cv(think_gaps)
    out["f4_think_median"] = sorted(think_gaps)[len(think_gaps) // 2] if think_gaps else 0.0
    out["f4_think_max"] = max(think_gaps) if think_gaps else 0.0
    out["f4_machine_speed"] = out["f4_burst_ratio"]
    out["f4_machine_x_think"] = out["f4_burst_ratio"] * out["f4_think_ratio"]
    out["f4_gap_log_entropy"] = shannon(Counter(round(math.log10(g + 0.01), 1) for g in gaps).values())
    return out


def f5_exploration(reqs, tmpl, fam, stc, t, cfg) -> dict:
    """F5 exploration structure: breadth, depth, entropy, 404 tolerance, discovery rate.

    Core insight (measured in lab1): 371 of 541 AI requests are 404 (69%), and
    the agent keeps widening its coverage over 115 minutes; a fixed script stops
    once it cannot make progress.
    """
    n = len(reqs)
    c_t = Counter(tmpl)
    c_f = Counter(fam)
    c_s = Counter(stc)
    n_cfg = sum(1 for r in reqs if CONFIG_PROBE_RE.search(r.uri))
    n_api = sum(1 for r in reqs if API_PATH_RE.search(r.uri))
    out = {
        "f13_config_ratio": safe_div(n_cfg, n),
        "f13_api_ratio": safe_div(n_api, n),
        "f5_distinct_templates": float(len(c_t)),
        "f5_template_entropy": shannon(c_t.values()),
        "f5_family_count": float(len(c_f)),
        "f5_family_entropy": shannon(c_f.values()),
        "f5_depth_max": float(max([p.count("/") for p in tmpl] or [0])),
        "f5_status_entropy": shannon(c_s.values()),
        "f5_404_ratio": safe_div(c_s.get("4xx", 0), n),
        "f5_5xx_ratio": safe_div(c_s.get("5xx", 0), n),
        "f5_2xx_ratio": safe_div(c_s.get("2xx", 0), n),
        "f5_401_ratio": safe_div(sum(1 for r in reqs if r.status == 401), n),
        "f5_403_ratio": safe_div(sum(1 for r in reqs if r.status == 403), n),
        "f5_500_as_signal": safe_div(sum(1 for r in reqs if r.status == 500), n),
        "f5_duration_s": (t[-1] - t[0]) if n > 1 else 0.0,
        "f5_rpm": safe_div(n, max(1e-9, (t[-1] - t[0]) / 60.0)),
        "f5_static_ratio": safe_div(sum(1 for r in reqs if is_static(r.uri)), n),
        "f5_discovery_rate": safe_div(len(c_t) * 100.0, n),
        "f5_method_count": float(len(set(r.method for r in reqs))),
        "f5_body_ratio": safe_div(sum(1 for r in reqs if r.body), n),
        "f5_arg_ratio": safe_div(sum(1 for r in reqs if r.args), n),
    }
    return out


def f6_repetition(reqs, tmpl, fam, stc, t, cfg) -> dict:
    """F6 repetition and verification: enumeration strength, retry breadth, backtrack verification."""
    n = len(reqs)
    c_t = Counter(tmpl)
    # Enumeration strength: how many distinct ids appear under one template
    ids_per_tmpl = defaultdict(set)
    for r, tm in zip(reqs, tmpl):
        m = re.search(r"\d{3,}", r.uri)
        if m:
            ids_per_tmpl[tm].add(m.group(0))
    enum_max = max([len(v) for v in ids_per_tmpl.values()] or [0])
    enum_tmpls = sum(1 for v in ids_per_tmpl.values() if len(v) > 1)
    retried = sum(1 for v in c_t.values() if v > 1)
    # Backtrack verification: after a 2xx, is the same template visited again (verification behaviour)?
    verify = 0
    for i in range(n):
        if stc[i] != "2xx":
            continue
        if any(tmpl[j] == tmpl[i] for j in range(i + 1, min(n, i + 8))):
            verify += 1
    # Same template with different parameters (parameter mutation)
    arg_variants = defaultdict(set)
    for r, tm in zip(reqs, tmpl):
        if r.args:
            arg_variants[tm].add(r.args)
    out = {
        "f6_retry_templates": float(retried),
        "f6_retry_ratio": safe_div(retried, len(c_t)),
        "f6_repeat_request_ratio": safe_div(sum(v - 1 for v in c_t.values() if v > 1), n),
        "f6_enum_max_ids": float(enum_max),
        "f6_enum_templates": float(enum_tmpls),
        "f6_verify_backtrack": safe_div(verify, max(1, sum(1 for s in stc if s == "2xx"))),
        "f6_arg_variant_max": float(max([len(v) for v in arg_variants.values()] or [0])),
        "f6_top_repeat": float(max(c_t.values()) if c_t else 0),
    }
    return out


def f7_identity(reqs, stc, t, cfg) -> dict:
    """F7 identity lineage: identity count, unauthenticated share, identity churn, roles.

    Measured (lab2 DSH): **62 different accounts** are rotated inside one
    behavioural actor (p2.tester / p4.ma.role / exp.bola / repro.ssrf / dsh.race...),
    one account per independent hypothesis under test.
    This is the direct fingerprint of an agent that verifies hypotheses one by
    one; a fixed script usually has a single credential.
    """
    n = len(reqs)
    users = [r.user for r in reqs if r.user not in ("-", "", None)]
    roles = [r.role for r in reqs if r.role not in ("-", "", None)]
    cu = Counter(users)
    dur = max(1e-9, (t[-1] - t[0]) if n > 1 else 0.0)
    first_auth = None
    for i, r in enumerate(reqs):
        if r.user not in ("-", "", None):
            first_auth = i
            break
    out = {
        "f7_distinct_users": float(len(cu)),
        "f7_distinct_roles": float(len(set(roles))),
        "f7_unauth_ratio": safe_div(sum(1 for r in reqs if r.user in ("-", "", None)), n),
        "f7_identity_churn": safe_div(len(cu), dur / 60.0),
        "f7_users_per_100req": safe_div(len(cu) * 100.0, n),
        "f7_first_auth_latency": float(first_auth if first_auth is not None else n),
        "f7_never_auth": 1.0 if not cu else 0.0,
        "f7_admin_role_ratio": safe_div(sum(1 for r in roles if "admin" in (r or "").lower()), max(1, len(roles))),
    }
    return out


def f9_tool(reqs, t, cfg) -> dict:
    """F9 tool fingerprint: user agent families and switches (reference only, not part of the main score).

    Measured lab1 PentAGI: curl 393 / python-urllib 82 / HeadlessChrome 62 -
    the same behavioural actor uses three tools at once, which shows that an
    **orchestrator** drives several execution channels.
    """
    n = len(reqs)
    def fam_of(ua):
        u = (ua or "").lower()
        if not u:
            return "empty"
        if "headlesschrome" in u or "chrome" in u:
            return "browser"
        if "curl" in u:
            return "curl"
        if "python-urllib" in u:
            return "urllib"
        if "python-requests" in u:
            return "requests"
        if "powershell" in u:
            return "powershell"
        if "mozilla" in u:
            return "browser"
        if "wget" in u:
            return "wget"
        if "go-http" in u or "golang" in u:
            return "go"
        if "java" in u:
            return "java"
        if "sqlmap" in u or "nmap" in u or "nikto" in u or "nuclei" in u:
            return "scanner"
        return "other"
    fams = [fam_of(r.ua) for r in reqs]
    cf = Counter(fams)
    switches = 0
    for i in range(1, n):
        if fams[i] != fams[i - 1]:
            switches += 1
        # Are the tool switches clustered (orchestration: each tool runs for a while, then the next one starts)?
    clusters = 0
    for i in range(1, n):
        if fams[i] != fams[i - 1]:
            clusters += 1
    out = {
        "f9_ua_families": float(len(cf)),
        "f9_ua_entropy": shannon(cf.values()),
        "f9_ua_switches": float(switches),
        "f9_ua_switch_rate": safe_div(switches, n),
        "f9_has_browser": 1.0 if cf.get("browser", 0) > 0 else 0.0,
        "f9_has_scanner": 1.0 if cf.get("scanner", 0) > 0 else 0.0,
        "f9_noncurl_ratio": safe_div(n - cf.get("curl", 0), n),
        "f9_ua_block_ratio": safe_div(max(1, len(cf) - 1), max(1, len(cf))),
    }
    return out


def f10_machine_identity(reqs, cfg) -> dict:
    """F10 machine-like account naming: how structured are registered account names?

    Measured (lab2 DSH) account names:
      p2.tester.1795439349@example.com
      p4.ma.role2.1795439402@example.com
      exp.bola.1795440219@example.com
      repro.ssrf.1795440264@example.com
      dsh.race2.1795440705@example.com
      p22.race.1795440797.0@example.com
    The pattern is <label>.<sublabel>[.<sequence>].<13 digit timestamp>@<domain>.
    That is the machine trace of an agent opening accounts in bulk for every
    separate hypothesis.  Humans do not name accounts like that (a human uses a
    real name or a common nickname).
    **The server sees the user name at registration time**, so this feature can
    be deployed on any web application.
    """
    users = sorted(set(r.user for r in reqs if r.user not in ("-", "", None)))
    n_users = len(users)
    out = {
        "f10_user_count": float(n_users),
        "f10_machine_named_ratio": 0.0,
        "f10_ts_suffix_ratio": 0.0,
        "f10_dot_label_ratio": 0.0,
        "f10_label_entropy": 0.0,
        "f10_seq_suffix_ratio": 0.0,
    }
    if n_users == 0:
        return out
    ts_re = re.compile(r"\d{10,13}$")
    seq_re = re.compile(r"\.\d{1,3}$")
    machine = 0
    ts_suffix = 0
    dot_lab = 0
    seq_suffix = 0
    labels = []
    for u in users:
        local = u.split("@")[0]
        parts = [p for p in local.split(".") if p]
        labels.extend(parts)
        has_ts = bool(ts_re.search(local))
        if has_ts:
            ts_suffix += 1
        if len(parts) >= 2:
            dot_lab += 1
        low = [p.lower() for p in parts]
        known = sum(1 for p in low if p in cfg.label_tokens)
        if has_ts and (known >= 1 or len(parts) >= 2):
            machine += 1
        if seq_re.search(local):
            seq_suffix += 1
    out["f10_machine_named_ratio"] = safe_div(machine, n_users)
    out["f10_ts_suffix_ratio"] = safe_div(ts_suffix, n_users)
    out["f10_dot_label_ratio"] = safe_div(dot_lab, n_users)
    out["f10_seq_suffix_ratio"] = safe_div(seq_suffix, n_users)
    out["f10_label_entropy"] = shannon(Counter(labels).values())
    return out


def f11_payload(reqs, cfg) -> dict:
    """F11 payload semantics: the **maliciousness** axis, orthogonal to "AI-ness".

    Measured counter-example: in one round of 537 requests the PentAGI run in
    lab1 carried **zero injection payloads** (payload_classes={}), while a
    10-line fixed script (selftest2) produced sqli, xss and ssrf payloads.
    => Payload features are useful for "is this an attack" and almost useless
    for "is this an AI".  They have to be decoupled from the AI features and
    reported on their own axis.
    """
    n = len(reqs)
    cnt = Counter()
    for r in reqs:
        for h in classify_payload(r.full_path + " " + r.body):
            cnt[h] += 1
    out = {
        "f11_payload_total": float(sum(cnt.values())),
        "f11_payload_kinds": float(len(cnt)),
        "f11_payload_density": safe_div(sum(cnt.values()), n),
    }
    for k in PAYLOAD_PATS:
        out["f11_pay_" + k] = float(cnt.get(k, 0))
    return out


def f1_semantic(reqs, cfg) -> dict:
    """F1 semantic causality: is the next action decided by the previous response?

    The current capture layer has **no response body and no response headers**,
    so the full "passphrase inheritance / token carry" analysis cannot be
    computed.  The part that can be computed is the **identity switch**: a change
    of the JWT sub claim that nginx decoded means the actor took the credential
    from the previous response and continued - that is itself "the response
    content decides the next step".

    When response capture is switched on (cfg.have_response_headers and
    cfg.have_response_body), the token carry analysis becomes active as well
    (the request objects then carry resp_headers and resp_body).
    """
    n = len(reqs)
    users = [r.user for r in reqs]
    switches = sum(1 for i in range(1, n) if users[i] != users[i - 1])
    real_switch = sum(1 for i in range(1, n) if users[i] not in ("-", "", None) and users[i] != users[i - 1])
    out = {
        "f1_identity_switches": float(switches),
        "f1_identity_switch_rate": safe_div(switches, n),
        "f1_real_switches": float(real_switch),
        "f1_response_capture": 1.0 if (cfg.have_response_headers or cfg.have_response_body) else 0.0,
        "f1_token_carry_hits": 0.0,
        "f1_token_carry_ratio": 0.0,
        "f1_hint_follow_hits": 0.0,
    }
    if cfg.have_response_headers or cfg.have_response_body:
        carry = 0
        hint = 0
        checked = 0
        prev_text = ""
        for i, r in enumerate(reqs):
            rh = getattr(r, "resp_headers", None) or {}
            rb = getattr(r, "resp_body", None) or ""
            issued = set()
            for k, v in rh.items():
                if "ref" in k.lower() or "token" in k.lower() or "nonce" in k.lower():
                    issued.add(str(v))
            if rb:
                issued |= set(re.findall(r"\b[A-Z0-9]{4,12}\b", rb))
            if i > 0 and issued:
                checked += 1
                nxt = reqs[i].full_path + " " + (reqs[i].body or "")
                if any(tok and tok in nxt for tok in issued):
                    carry += 1
                if prev_text:
                    for h in re.findall(r"/[A-Za-z0-9_./\-]{6,}", prev_text):
                        if h in nxt:
                            hint += 1
                            break
            prev_text = (prev_text + " " + (rb or ""))[-2000:]
        out["f1_token_carry_hits"] = float(carry)
        out["f1_token_carry_ratio"] = safe_div(carry, checked)
        out["f1_hint_follow_hits"] = float(hint)
    return out


CODEHOST_RE = re.compile(r"(github|gitlab|gitee|bitbucket|stackoverflow|readthedocs|npmjs|pypi)", re.I)
CDN_RE = re.compile(r"(cloudflare|fastly|akamai|cloudfront|jsdelivr|unpkg)", re.I)
LLM_RE = re.compile(r"(openai|anthropic|deepseek|gemini|googleapis|generativelanguage|dashscope|moonshot|groq|mistral|cohere)", re.I)


def f8_egress(egress, reqs, t, cfg) -> dict:
    """F8 egress intelligence: the outbound destinations during the attack.

    Measured (lab1 PentAGI): the network guard blocked 648 outbound attempts,
    with destinations including Cloudflare (172.66.147.243 / 104.20.23.154) and
    Fastly (151.101.x) - it fetched material from GitHub and documentation sites
    while attacking.  A fixed script does not do that.

    Clock: denied.log uses the kernel monotonic clock and cannot be aligned to
    UTC directly.  The approximation used here maps the denied.log time span
    linearly onto the capture time span, and then attributes events per window.
    """
    out = {
        "f8_egress_total": 0.0,
        "f8_egress_distinct": 0.0,
        "f8_egress_codehost": 0.0,
        "f8_egress_cdn": 0.0,
        "f8_egress_llm_api": 0.0,
        "f8_egress_metadata": 0.0,
        "f8_egress_per_min": 0.0,
        "f8_egress_in_window": 0.0,
    }
    if not egress:
        return out
    c = Counter(e.dst for e in egress)
    out["f8_egress_total"] = float(len(egress))
    out["f8_egress_distinct"] = float(len(c))
    out["f8_egress_codehost"] = float(sum(1 for e in egress if CODEHOST_RE.search(e.dst + e.src)))
    out["f8_egress_cdn"] = float(sum(1 for e in egress if CDN_RE.search(e.dst)))
    out["f8_egress_llm_api"] = float(sum(1 for e in egress if LLM_RE.search(e.dst)))
    out["f8_egress_metadata"] = float(sum(1 for e in egress if e.dst == "169.254.169.254"))
    if reqs:
        t0, t1 = t[0], t[-1]
        e0 = egress[0].ts.timestamp()
        e1 = egress[-1].ts.timestamp()
        span = max(1e-9, e1 - e0)
        def map_ts(ts):
            return t0 + (ts.timestamp() - e0) * (t1 - t0) / span
        # Proximity attribution: only count outbound attempts that fall within
        # 60 s of a request.
        # The whole session span is not used because the requests of a scripted
        # session can cover the entire capture window, which would add egress
        # that does not belong to it (measured: this made E8 fire on scripted
        # traffic).
        ts_sorted = sorted(t)
        inw = 0
        for mt in mapped:
            lo = bisect_left(ts_sorted, mt - 60.0)
            hi = bisect_right(ts_sorted, mt + 60.0)
            if hi > lo:
                inw += 1
        out["f8_egress_in_window"] = float(inw)
        dur = max(1e-9, (t1 - t0) / 60.0)
        out["f8_egress_per_min"] = safe_div(inw, dur)
    return out


FAMILY_OF = {
    "F1_semantic_causality": "f1_",
    "F3_feedback_adaptivity": "f3_",
    "F4_rhythm": "f4_",
    "F5_exploration": "f5_",
    "F6_repetition_verify": "f6_",
    "F7_identity": "f7_",
    "F8_egress_intel": "f8_",
    "F9_tool_fingerprint": "f9_",
    "F10_machine_identity": "f10_",
    "F11_payload_semantics": "f11_",
}


def extract(reqs, cfg, egress=None, probe_scores=None) -> dict:
    """Extract every feature from one group of requests (a session or a window).

    Returns a {feature_name: float} mapping.  A family that cannot be computed
    is reported as not available instead of being silently read as zero, so that
    "cannot be computed" is never confused with "not present".
    """
    reqs = list(reqs)
    out = {}
    if not reqs:
        return out
    tmpl, fam, stc, t = _prep(reqs)
    if cfg.feature_enabled("F1_semantic_causality"):
        out.update(f1_semantic(reqs, cfg))
    if cfg.feature_enabled("F3_feedback_adaptivity"):
        out.update(f3_feedback(reqs, tmpl, fam, stc, cfg))
    if cfg.feature_enabled("F4_rhythm"):
        out.update(f4_rhythm(reqs, t, cfg))
    if cfg.feature_enabled("F5_exploration"):
        out.update(f5_exploration(reqs, tmpl, fam, stc, t, cfg))
    if cfg.feature_enabled("F6_repetition_verify"):
        out.update(f6_repetition(reqs, tmpl, fam, stc, t, cfg))
    if cfg.feature_enabled("F7_identity"):
        out.update(f7_identity(reqs, stc, t, cfg))
    if cfg.feature_enabled("F8_egress_intel"):
        out.update(f8_egress(egress or [], reqs, t, cfg))
    if cfg.feature_enabled("F9_tool_fingerprint"):
        out.update(f9_tool(reqs, t, cfg))
    if cfg.feature_enabled("F10_machine_identity"):
        out.update(f10_machine_identity(reqs, cfg))
    if cfg.feature_enabled("F11_payload_semantics"):
        out.update(f11_payload(reqs, cfg))
    if probe_scores:
        out.update(probe_scores)
    return out


def feature_names(cfg) -> list:
    """The feature names produced under the current configuration (column alignment for modelling)."""
    probe_cols = ["f2_available", "f2_carry_hits", "f2_transform_hits",
                  "f2_hint_hits", "f2_probe_score"]
    cols = []
    for fam, pref in FAMILY_OF.items():
        if cfg.feature_enabled(fam):
            cols.append(pref)
    if cfg.feature_enabled("F2_probe"):
        cols.append("f2_")
    return cols, probe_cols

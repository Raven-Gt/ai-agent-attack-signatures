# -*- coding: utf-8 -*-
"""Figures 1-6 of the paper figure set."""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Patch

from figlib import (AGG, AMBER, BLUE, DATA, GREY, INK, MUTED, NEG, PALETTE, RED,
                    REPO_ROOT, TEAL, check_ascii, framework_lower_bound, load_json,
                    load_jsonl, save, wilson)

# --------------------------------------------------------------- figure 1 ---
# runtime status is an *ordinal* scale (captured > executed > dry run > blocked),
# so it is encoded with a single-hue sequential ramp; the nominal attribution
# class uses the categorical accents.
RUNTIME_RAMP = {
    "executed-captured": "#1B3A6B",
    "executed-ok-with-framework-fingerprint": "#2E5EAA",
    "executed-ok-no-framework-fingerprint": "#6E93CC",
    "executed-ok-dry-run-only": "#A8BFE0",
    "blocked-recorded": "#E3E8EF",
}
RUNTIME_LABEL = {
    "executed-captured": "captured (actor traffic)",
    "executed-ok-with-framework-fingerprint": "ran, own fingerprint seen",
    "executed-ok-no-framework-fingerprint": "ran, no own fingerprint",
    "executed-ok-dry-run-only": "ran, dry run only",
    "blocked-recorded": "blocked (not executed)",
}
RUNTIME_ORDER = list(RUNTIME_RAMP)
ATTR_COLOR = {
    "yes-framework-own-fingerprint": TEAL,
    "partial": AMBER,
    "no": GREY,
}
ATTR_LABEL = {
    "yes-framework-own-fingerprint": "own fingerprint",
    "partial": "generic tool traffic",
    "no": "no target traffic",
}
ATTR_ORDER = ["yes-framework-own-fingerprint", "partial", "no"]


def figure1():
    cov = load_json(AGG / "framework_coverage_matrix.json")
    rows = cov["rows"]
    for r in rows:
        check_ascii(r["repository"], "framework name")
    order = {a: i for i, a in enumerate(ATTR_ORDER)}
    rorder = {s: i for i, s in enumerate(RUNTIME_ORDER)}
    rows = sorted(rows, key=lambda r: (order[r["target_side_attributable"]],
                                       rorder[r["runtime_status"]],
                                       r["repository"].lower()))
    n = len(rows)

    fig = plt.figure(figsize=(16.5, 13.5))
    gs = fig.add_gridspec(2, 3, width_ratios=[3.05, 1.45, 1.35],
                          height_ratios=[1.0, 1.25],
                          left=0.115, right=0.975, top=0.875, bottom=0.065,
                          wspace=0.30, hspace=0.42)

    ax = fig.add_subplot(gs[:, 0])
    ys = [n - 1 - i for i in range(n)]
    cols = [("Source\naudit", "source_audit_present"),
            ("IOC\ninventory", "ioc_inventory_present"),
            ("Runtime\nstatus", "runtime_status"),
            ("Target-side\nattribution", "target_side_attributable")]
    for c, (head, key) in enumerate(cols):
        ax.text(c * 1.18, n + 1.0, head, ha="center", va="bottom", fontsize=10.5,
                fontweight="bold", color=INK)
    for i, r in enumerate(rows):
        y = ys[i]
        for c, (head, key) in enumerate(cols):
            val = r[key]
            if key == "runtime_status":
                face, edge = RUNTIME_RAMP[val], "#1F2933"
            elif key == "target_side_attributable":
                face, edge = ATTR_COLOR[val], "none"
            else:
                face, edge = (BLUE if val == "yes" else "#E3E8EF"), "none"
            ax.add_patch(Rectangle((c * 1.18 - 0.4, y - 0.42), 0.8, 0.84,
                                   facecolor=face, edgecolor=edge, linewidth=0.6))
        ax.text(-0.62, y, r["repository"], ha="right", va="center", fontsize=10)
    ax.set_xlim(-3.9, 4.55)
    ax.set_ylim(-0.8, n + 2.4)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_visible(False)
    ax.set_title("64 audited repositories, sorted by target-side attribution class",
                 fontsize=12.5, loc="left", pad=26)

    axb = fig.add_subplot(gs[:, 1], sharey=ax)
    vals = [float(r["ioc_class_a_target_side_count"]) for r in rows]
    cols_bar = [ATTR_COLOR[r["target_side_attributable"]] for r in rows]
    axb.barh(ys, vals, color=cols_bar, height=0.72)
    axb.set_ylim(ax.get_ylim())
    axb.set_yticks([])
    axb.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    axb.set_axisbelow(True)
    axb.set_title("Indicator inventory\n(class-A target-side indicators)", fontsize=12.5,
                  loc="left", pad=26)
    for i, v in enumerate(vals):
        if v >= 3:
            axb.text(v + 0.4, ys[i], "%d" % v, va="center", fontsize=9, color=INK)
    axb.set_xlim(0, max(vals) * 1.18)

    axf = fig.add_subplot(gs[0, 2])
    n_exec = sum(1 for r in rows if r["runtime_status"].startswith("executed"))
    n_own = sum(1 for r in rows if r["target_side_attributable"] == "yes-framework-own-fingerprint")
    funnel = [("Audited repositories", len(rows)),
              ("With an IOC inventory", sum(1 for r in rows if r["ioc_inventory_present"] == "yes")),
              ("Executed against the target", n_exec),
              ("Own fingerprint on target side", n_own)]
    counts = [f[1] for f in funnel]
    cols_f = ["#1B3A6B", "#2E5EAA", "#6E93CC", TEAL]
    ypos = np.arange(len(funnel))[::-1]
    axf.barh(ypos, counts, color=cols_f, height=0.62)
    for yy, c in zip(ypos, counts):
        axf.text(c + 1.2, yy, "%d  (%.0f%%)" % (c, 100.0 * c / len(rows)),
                 va="center", fontsize=10.5, color=INK)
    axf.set_yticks(ypos)
    axf.set_yticklabels([f[0] for f in funnel], fontsize=10)
    axf.set_xlim(0, len(rows) * 1.45)
    axf.set_xticks([])
    axf.spines["bottom"].set_visible(False)
    axf.spines["left"].set_visible(False)
    axf.set_title("Coverage funnel", fontsize=12.5, loc="left", pad=8)
    axf.grid(False)

    axc = fig.add_subplot(gs[1, 2])
    mat = np.zeros((len(RUNTIME_ORDER), len(ATTR_ORDER)))
    for r in rows:
        mat[RUNTIME_ORDER.index(r["runtime_status"]),
            ATTR_ORDER.index(r["target_side_attributable"])] += 1
    axc.imshow(mat, cmap=plt.get_cmap("Blues"), vmin=0, vmax=max(mat.max(), 1), aspect="auto")
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            v = int(mat[i, j])
            axc.text(j, i, str(v), ha="center", va="center", fontsize=11,
                     fontweight="bold" if v else "normal",
                     color="white" if v > mat.max() * 0.55 else INK)
    axc.set_xticks(range(len(ATTR_ORDER)))
    axc.set_xticklabels(["own\nfinger-\nprint", "generic\ntool\ntraffic", "no target\ntraffic"],
                         fontsize=9.5)
    axc.set_yticks(range(len(RUNTIME_ORDER)))
    axc.set_yticklabels([RUNTIME_LABEL[s].replace(", ", ",\n") for s in RUNTIME_ORDER], fontsize=9)
    axc.tick_params(length=0)
    for s in axc.spines.values():
        s.set_visible(False)
    axc.set_title("Runtime status x attribution (repositories)", fontsize=12.5, loc="left", pad=8)

    handles = [Patch(facecolor=ATTR_COLOR[a], label="attribution: " + ATTR_LABEL[a])
               for a in ATTR_ORDER]
    handles += [Patch(facecolor=RUNTIME_RAMP[s], edgecolor="#1F2933",
                      label="runtime: " + RUNTIME_LABEL[s]) for s in RUNTIME_ORDER]
    fig.legend(handles=handles, loc="lower center", ncol=4, fontsize=10,
               bbox_to_anchor=(0.5, 0.002), handlelength=1.3, columnspacing=1.4)

    fig.suptitle("Figure 1 - Framework attribution matrix: only 10 of 64 audited AI pentest "
                 "repositories leave an attributable fingerprint on the target side",
                 fontsize=15, fontweight="bold", x=0.115, ha="left", y=0.975)
    fig.text(0.115, 0.945,
             "Headline number: 10 of 64 repositories (16%) are attributable on the target side; "
             "the other 54 delegate to generic tooling or never reach the target.",
             fontsize=11, color="#42505E", ha="left")
    return save(fig, "fig01_framework_attribution_matrix", 16.5, 13.5)


# --------------------------------------------------------------- figure 2 ---
def figure2():
    def load(p):
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        return d["rules"] if isinstance(d, dict) else d
    rules = (load(REPO_ROOT / "signatures" / "rules.json")
             + load(REPO_ROOT / "signatures" / "agpl" / "rules-agpl.json"))
    t1 = [r for r in rules if r.get("tier") == "T1"]
    order = ["body", "uri", "header", "user_agent", "other", "oast_dns"]
    pretty = {"body": "Request body", "uri": "Request path (URI)",
              "header": "HTTP request header", "user_agent": "User-Agent",
              "other": "Other (TLS / proxy / credential)", "oast_dns": "OAST domain"}
    counts = {f: sum(1 for r in t1 if r.get("field") == f) for f in order}
    total = len(t1)

    fig = plt.figure(figsize=(13.5, 6.8))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.35, 1.0], left=0.185, right=0.975,
                          top=0.80, bottom=0.125, wspace=0.34)
    ax = fig.add_subplot(gs[0, 0])
    y = np.arange(len(order))[::-1]
    vals = [counts[f] for f in order]
    shades = ["#1B3A6B", "#2E5EAA", "#4C79B4", "#6E93CC", "#93AED4", "#B7C7E0"]
    ax.barh(y, vals, color=shades, height=0.68)
    for yy, f, v in zip(y, order, vals):
        ax.text(v + 3.5, yy, "%d   (%.1f%%)" % (v, 100.0 * v / total), va="center",
                fontsize=11.5, color=INK)
    ax.set_yticks(y)
    ax.set_yticklabels([pretty[f] for f in order], fontsize=11)
    ax.set_xlabel("number of tier-1 rules", fontsize=12)
    ax.set_xlim(0, max(vals) * 1.32)
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Tier-1 rules (alertable on their own) by the request field they match",
                 fontsize=12.5, loc="left", pad=10)

    gsr = gs[0, 1].subgridspec(2, 1, height_ratios=[0.38, 1.0], hspace=1.15)
    ax2t = fig.add_subplot(gsr[0])
    tiers = {}
    for r in rules:
        tiers[r.get("tier")] = tiers.get(r.get("tier"), 0) + 1
    left = 0
    for t, c in [("T1", TEAL), ("T2", AMBER), ("T3", GREY)]:
        v = tiers.get(t, 0)
        ax2t.barh([0], [v], left=left, color=c, height=0.55)
        ax2t.text(left + v / 2, 0, "%s\n%d" % (t, v), ha="center", va="center",
                  fontsize=10.5, fontweight="bold", color="white" if t != "T2" else INK)
        left += v
    ax2t.set_xlim(0, left)
    ax2t.set_ylim(-0.4, 0.4)
    ax2t.set_yticks([])
    ax2t.set_xticks([])
    ax2t.set_xlabel("rules in the combined rule set (610)", fontsize=11)
    ax2t.set_title("Rule set by tier", fontsize=12.5, loc="left", pad=8)
    ax2t.spines["left"].set_visible(False)
    ax2t.spines["bottom"].set_visible(False)

    ax2 = fig.add_subplot(gsr[1])
    kinds = {}
    for r in t1:
        kinds[r.get("kind")] = kinds.get(r.get("kind"), 0) + 1
    korder = sorted(kinds, key=lambda k: -kinds[k])
    yk = np.arange(len(korder))[::-1]
    ax2.barh(yk, [kinds[k] for k in korder], color=BLUE, height=0.62)
    for yy, k, v in zip(yk, korder, [kinds[k] for k in korder]):
        ax2.text(v + 3, yy, "%d" % v, va="center", fontsize=10, color=INK)
    ax2.set_ylim(-0.7, len(korder) - 0.3)
    ax2.set_xlim(0, max(kinds.values()) * 1.22)
    ax2.set_yticks(yk)
    ax2.set_yticklabels(korder, fontsize=10)
    ax2.set_xlabel("tier-1 rules by indicator kind", fontsize=11)
    ax2.spines["left"].set_visible(False)
    ax2.spines["bottom"].set_visible(False)

    fig.suptitle("Figure 2 - Composition of the tier-1 signature set by request field",
                 fontsize=15, fontweight="bold", x=0.185, ha="left", y=0.975)
    fig.text(0.185, 0.915,
             "Headline number: 150 of the 272 tier-1 rules (55.1%) match on the request body; "
             "only 35 (12.9%) are User-Agent rules.",
             fontsize=11, color="#42505E", ha="left")
    return save(fig, "fig02_t1_signature_composition", 13.5, 6.4)


# --------------------------------------------------------------- figure 3 ---
def figure3():
    fd = load_json(AGG / "framework_detection.json")
    actors = fd["per_actor"]
    tau = fd["decision_threshold"]
    actors = sorted(actors, key=lambda a: a["ai_score"])
    y = np.arange(len(actors))
    cols = [BLUE if a["detected"] == "yes" else RED for a in actors]

    fig = plt.figure(figsize=(13.5, 9.4))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.15, 1.0], left=0.235, right=0.975,
                          top=0.855, bottom=0.105, wspace=0.26)
    ax = fig.add_subplot(gs[0, 0])
    ax.barh(y, [a["ai_score"] for a in actors], color=cols, height=0.68)
    ax.axvline(tau, color=INK, linestyle="--", linewidth=1.6)
    ax.set_ylim(-0.7, len(actors) + 1.7)
    ax.text(tau + 0.012, len(actors) + 0.55, "decision threshold tau = 0.35", va="center",
            ha="left", fontsize=11, color=INK, fontweight="bold")
    for yy, a in zip(y, actors):
        ax.text(a["ai_score"] + 0.008, yy, "%.3f" % a["ai_score"], va="center",
                fontsize=10, color=INK)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  (%s)   n=%s" % (a["actor_id"], a["framework"],
                                             format(a["actor_requests"], ","))
                        for a in actors], fontsize=10)
    ax.set_xlabel("AI attribution score", fontsize=12)
    ax.set_xlim(0, 0.93)
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Per-actor attribution score of the 15 AI agent attack segments",
                 fontsize=12.5, loc="left", pad=10)

    lo = actors[0]
    ax.annotate("pentest-ai: E15 reverse evidence fires\n"
                "(dictionary-driven enumerator),\nwhich caps the score at 0.25",
                xy=(lo["ai_score"] + 0.012, 0), xytext=(0.46, 0.30),
                fontsize=10, color=INK, va="center",
                arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.4))
    hi = actors[1]
    ax.annotate("hackingBuddyGPT: only E5 + E12 fire\nover 62 requests - no structural-scale\n"
                "evidence (E1) is present",
                xy=(hi["ai_score"] + 0.012, 1), xytext=(0.46, 1.45),
                fontsize=10, color=INK, va="center",
                arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.4))

    ax2 = fig.add_subplot(gs[0, 1])
    det = sum(1 for a in actors if a["detected"] == "yes")
    fws = sorted({a["framework"] for a in actors})
    fdet = sorted({a["framework"] for a in actors if a["detected"] == "yes"})
    k = len(fws)
    lb = framework_lower_bound(k)
    bars = [("AI agent segments detected", det, BLUE, len(actors)),
            ("AI agent segments missed", len(actors) - det, RED, len(actors)),
            ("Frameworks detected", len(fdet), TEAL, k),
            ("Frameworks missed", k - len(fdet), RED, k)]
    yy = np.arange(len(bars))[::-1]
    ax2.barh(yy, [b[1] for b in bars], color=[b[2] for b in bars], height=0.6)
    for y2, b in zip(yy, bars):
        ax2.text(b[1] + 0.25, y2, "%d / %d" % (b[1], b[3]), va="center", fontsize=11, color=INK)
    ax2.set_yticks(yy)
    ax2.set_yticklabels([b[0] for b in bars], fontsize=10.5)
    ax2.set_xlim(0, 19)
    ax2.set_ylim(-2.0, 3.6)
    ax2.set_xlabel("count", fontsize=11)
    ax2.set_title("Detection outcome at tau = 0.35", fontsize=12.5, loc="left", pad=10)
    ax2.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.text(0.0, 0.015,
             ("Segment recall 13/15 = 86.7%\n"
              "Framework recall 10/12 = 83.3%\n\n"
              "One-sided 95% lower bound for\n"
              "'all 12 frameworks detected':\n"
              "0.05^(1/12) = {:.3f}").format(lb),
             transform=ax2.transAxes, fontsize=10.5, color=INK, va="bottom",
             bbox=dict(boxstyle="round,pad=0.5", facecolor="#F4F7FA", edgecolor="#D7DEE6"))

    fig.suptitle("Figure 3 - Per-framework attribution score and the two frameworks the "
                 "detector misses", fontsize=15, fontweight="bold", x=0.235, ha="left", y=0.978)
    fig.text(0.235, 0.925,
             "Headline number: 13 of 15 AI agent segments (86.7%) reach the decision threshold; "
             "hackingBuddyGPT (0.280) and pentest-ai (0.250) are missed.",
             fontsize=11, color="#42505E", ha="left")
    return save(fig, "fig03_per_framework_detection_score", 13.5, 9.2)


# --------------------------------------------------------------- figure 4 ---
def figure4():
    tr = load_json(AGG / "threshold_fpr_tradeoff.json")
    rec = {r["threshold"]: r for r in tr["recomputed_on_released_set"]["rows"]}
    ths = sorted(rec, key=float)
    x = [float(t) for t in ths]
    cap_rec = [rec[t]["capture_recall"] for t in ths]
    fw_rec = [rec[t]["framework_recall"] for t in ths]
    fpr = [tr["threshold"][t]["fpr"] for t in ths]
    lo = [tr["threshold"][t]["fpr_ci"][0] for t in ths]
    hi = [tr["threshold"][t]["fpr_ci"][1] for t in ths]
    fp = [tr["threshold"][t]["fp"] for t in ths]

    fig = plt.figure(figsize=(13.5, 6.6))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.25, 1.0], left=0.075, right=0.975,
                          top=0.835, bottom=0.145, wspace=0.24)
    ax = fig.add_subplot(gs[0, 0])
    ax.plot(x, cap_rec, "-o", color=BLUE, label="segment (capture) recall")
    ax.plot(x, fw_rec, "--s", color=TEAL, label="framework recall")
    ax.axvline(0.35, color=INK, linestyle=":", linewidth=1.5)
    ax.annotate("operating point tau = 0.35\n13/15 = 86.7%   10/12 = 83.3%",
                xy=(0.35, 0.8667), xytext=(0.385, 0.42), fontsize=10.5, color=INK,
                arrowprops=dict(arrowstyle="->", color=INK, linewidth=1.3))
    ax.set_xlabel("decision threshold tau", fontsize=12)
    ax.set_ylabel("recall", fontsize=12)
    ax.set_ylim(0.35, 1.08)
    ax.set_xlim(0.22, 0.63)
    ax.set_yticks([0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    ax.set_yticklabels(["40%", "50%", "60%", "70%", "80%", "90%", "100%"])
    ax.yaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.legend(loc="lower left", fontsize=10)
    ax.set_title("Detection recall", fontsize=12.5, loc="left", pad=8)

    ax2 = fig.add_subplot(gs[0, 1])
    ax2.fill_between(x, lo, hi, color=BLUE, alpha=0.16, linewidth=0)
    ax2.plot(x, fpr, "-o", color=BLUE, label="false-positive rate")
    ax2.axvline(0.35, color=INK, linestyle=":", linewidth=1.5)
    ax2.annotate("operating point tau = 0.35\n43 / 1,582 = 2.72%\n95% CI [2.02%, 3.64%]",
                 xy=(0.35, 0.02718), xytext=(0.395, 0.030), fontsize=10.5, color=INK,
                 arrowprops=dict(arrowstyle="->", color=INK, linewidth=1.3))
    for xi, f, h in zip(x, fpr, hi):
        if xi in (0.25, 0.30, 0.35, 0.50):
            ax2.text(xi, h * 1.4, "%d FP" % f, ha="center", fontsize=9, color="#42505E")
    ax2.set_xlabel("decision threshold tau", fontsize=12)
    ax2.set_ylabel("false-positive rate", fontsize=12)
    ax2.set_yscale("log")
    ax2.set_ylim(4e-4, 0.8)
    ax2.set_xlim(0.22, 0.63)
    ax2.set_yticks([0.001, 0.01, 0.1])
    ax2.set_yticklabels(["0.1%", "1%", "10%"])
    ax2.yaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("False positives on 1,582 real attackers (band = 95% Wilson CI)",
                  fontsize=12.5, loc="left", pad=8)

    fig.suptitle("Figure 4 - Threshold trade-off: detection recall against the false-positive rate",
                 fontsize=15, fontweight="bold", x=0.075, ha="left", y=0.955)
    fig.text(0.075, 0.895,
             "Headline number: at tau = 0.35 the detector keeps 86.7% of the AI agent segments and "
             "83.3% of the frameworks while false-positiving on 2.72% of 1,582 real attackers; "
             "raising the threshold to 0.50 cuts the false-positive rate to 0.19% but drops segment "
             "recall to 73.3%.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig04_threshold_tradeoff", 13.5, 6.6)


# --------------------------------------------------------------- figure 5 ---
def figure5():
    neg = load_json(AGG / "negative_set_summary.json")
    buckets = neg["buckets"]
    order = ["N2 WAF-hit, per-IP", "N2 WAF-hit, per-IP+window",
             "N1 honeypot, per-IP", "N1 honeypot, per-IP+window",
             "N3 scanner, per-IP", "N3 scanner, per-IP+window"]
    labels = {
        "N2 WAF-hit, per-IP": "Real internet attackers - WAF log, per IP",
        "N2 WAF-hit, per-IP+window": "Real internet attackers - WAF log, per IP + 10 min window",
        "N1 honeypot, per-IP": "Honeypot background traffic, per IP",
        "N1 honeypot, per-IP+window": "Honeypot background traffic, per IP + 10 min window",
        "N3 scanner, per-IP": "Scanner containers (ffuf / curl), per IP",
        "N3 scanner, per-IP+window": "Scanner containers (ffuf / curl), per IP + 10 min window",
    }
    color_of = {"N2 WAF-hit": BLUE, "N1 honeypot": GREY, "N3 scanner": RED}
    rate, lo, hi, ns = [], [], [], []
    for k in order:
        b = buckets[k]
        n, fp = b["att"], b["fp"]
        r = fp / n if n else 0.0
        l, h = wilson(fp, n)
        rate.append(r)
        lo.append(r - l)
        hi.append(h - r)
        ns.append("%d / %d" % (fp, n))

    fig = plt.figure(figsize=(14.0, 7.0))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.1, 1.0], left=0.285, right=0.975,
                          top=0.845, bottom=0.135, wspace=0.30)
    ax = fig.add_subplot(gs[0, 0])
    y = np.arange(len(order))[::-1]
    ax.barh(y, [100.0 * r for r in rate],
            color=[color_of[buckets[k]["source"]] for k in order], height=0.66)
    ax.errorbar([100.0 * r for r in rate], y,
                xerr=[[100.0 * l for l in lo], [100.0 * h for h in hi]],
                fmt="none", ecolor=INK, elinewidth=1.3, capsize=4)
    for i, (yy, k, r, nstr) in enumerate(zip(y, order, rate, ns)):
        ax.text(max(100.0 * r, 100.0 * (r + hi[i])) + 2.0, yy,
                "%s = %.2f%%" % (nstr, 100.0 * r), va="center", fontsize=10, color=INK)
    ax.set_yticks(y)
    ax.set_yticklabels([labels[k] for k in order], fontsize=10.5)
    ax.set_xlabel("false-positive rate (share of attacker-class actors flagged)", fontsize=12)
    ax.set_xlim(0, 132)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xticklabels(["0%", "20%", "40%", "60%", "80%", "100%"])
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("False-positive rate per negative population (error bars = 95% Wilson CI)",
                 fontsize=12.5, loc="left", pad=10)

    ax2 = fig.add_subplot(gs[0, 1])
    scores = [float(r.get("ai_score", 0.0))
              for r in load_jsonl(DATA / "features" / "actor_features.jsonl")]
    sc_idx = load_json(NEG / "_index.json")
    sc_scores = [float(c["ai_score"]) for c in sc_idx["captures"]]
    bins = np.linspace(0, 0.85, 35)
    ax2.hist(scores, bins=bins, color=BLUE, alpha=0.85, label="1,582 real attackers (WAF)")
    top = ax2.get_ylim()[1]
    ax2.scatter(sc_scores, [top * 0.9] * len(sc_scores), s=70, color=RED, zorder=5,
                label="6 scanner actors", edgecolor="white", linewidth=0.8)
    ax2.axvline(0.35, color=INK, linestyle="--", linewidth=1.5)
    ax2.text(0.365, top * 0.55, "tau = 0.35", fontsize=10.5, color=INK, fontweight="bold")
    ax2.set_xlabel("AI attribution score", fontsize=12)
    ax2.set_ylabel("actors (log scale)", fontsize=12)
    ax2.set_yscale("log")
    ax2.legend(fontsize=10, loc="upper right")
    ax2.set_title("Where the two populations sit", fontsize=12.5, loc="left", pad=10)
    ax2.text(0.02, 0.62, "43 of 1,582 real attackers reach tau\n"
                         "4 of 6 scanner actors reach tau\n"
                         "the scanner scores sit inside the\n"
                         "real-attacker score range",
             transform=ax2.transAxes, fontsize=10, color=INK, va="top",
             bbox=dict(boxstyle="round,pad=0.45", facecolor="#F4F7FA", edgecolor="#D7DEE6"))

    fig.suptitle("Figure 5 - False positives: 2.72% on real attackers versus 66.67% on "
                 "tool-driven scanners", fontsize=15, fontweight="bold", x=0.285, ha="left", y=0.958)
    fig.text(0.285, 0.908,
             "Headline number: the detector false-positives on 43 of 1,582 real attackers (2.72%, "
             "95% CI 2.02-3.64%) but on 4 of 6 scanner containers (66.67%) - a 24.5x difference "
             "between the two attacker populations.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig05_false_positive_breakdown", 14.0, 7.0)


# --------------------------------------------------------------- figure 6 ---
FAMILY_NAME = {
    "F3": "feedback adaptivity (route change / pruning after an error)",
    "F4": "rhythm (machine speed x human thinking)",
    "F5": "exploration structure (breadth, depth, 404 tolerance)",
    "F6": "repetition and verification (enumeration, backtrack)",
    "F7": "identity lineage (account rotation)",
    "F9": "tool fingerprint (user-agent families)",
    "F10": "machine-like account naming",
}


def figure6():
    ab = load_json(AGG / "feature_family_ablation.json")
    fam = ab["per_family_upper_recall"]
    base = ab["base_recall"]
    fd = load_json(AGG / "framework_detection.json")
    actors = fd["per_actor"]
    tau = fd["decision_threshold"]

    def score_without(mapping, drop):
        p = 1.0
        for f, w in mapping.items():
            if f == drop:
                continue
            p *= (1.0 - w)
        return 1.0 - p

    def parse_weights(text):
        out = {}
        for part in str(text).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = float(v)
        return out

    lost = {}
    for f in fam:
        n = 0
        for a in actors:
            w = parse_weights(a["weights"])
            if a["ai_score"] >= tau and score_without(w, f) < tau:
                n += 1
        lost[f] = n

    fams = sorted(fam, key=lambda f: (fam[f], f))
    fig = plt.figure(figsize=(13.5, 6.6))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.0, 1.0], left=0.175, right=0.975,
                          top=0.835, bottom=0.155, wspace=0.28)
    ax = fig.add_subplot(gs[0, 0])
    y = np.arange(len(fams))[::-1]
    vals = [fam[f] for f in fams]
    cols = [RED if f == "F3" else (AMBER if f == "F6" else BLUE) for f in fams]
    ax.barh(y, vals, color=cols, height=0.66)
    ax.axvline(base, color=INK, linestyle="--", linewidth=1.5)
    ax.text(base + 0.004, -0.95, "base recall 0.933 (14 of 15 segments)", fontsize=10.5,
            color=INK, fontweight="bold", va="center")
    for yy, f, v in zip(y, fams, vals):
        delta = (v - base) * 100.0
        label = "%.3f" % v if abs(delta) < 1e-9 else "%.3f  (%+.1f pp)" % (v, delta)
        ax.text(v + 0.004, yy, label, va="center", fontsize=10.5, color=INK)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  -  %s" % (f, FAMILY_NAME[f].split(" (")[0]) for f in fams],
                       fontsize=10.5)
    ax.set_xlabel("recall upper bound if the family is unavailable", fontsize=12)
    ax.set_xlim(0.60, 1.04)
    ax.set_xticks([0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 1.00])
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Feature-family ablation", fontsize=12.5, loc="left", pad=10)
    ax.annotate("F3 is load-bearing: without it\n3 of the 15 segments drop below tau",
                xy=(fam["F3"] + 0.008, len(fams) - 1 - fams.index("F3")),
                xytext=(0.78, 0.30), fontsize=10.5, color=INK,
                arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.4))

    ax2 = fig.add_subplot(gs[0, 1])
    y2 = np.arange(len(fams))[::-1]
    ax2.barh(y2, [lost[f] for f in fams],
             color=[RED if f == "F3" else (AMBER if f == "F6" else BLUE) for f in fams],
             height=0.66)
    for yy, f in zip(y2, fams):
        ax2.text(lost[f] + 0.08, yy, "%d" % lost[f], va="center", fontsize=10.5, color=INK)
    ax2.set_yticks(y2)
    ax2.set_yticklabels(fams, fontsize=10.5)
    ax2.set_xlabel("segments that fall below tau without the family", fontsize=11.5)
    ax2.set_xlim(0, 3.6)
    ax2.set_xticks([0, 1, 2, 3])
    ax2.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("Segments lost per family", fontsize=12.5, loc="left", pad=10)

    fig.suptitle("Figure 6 - Feature-family ablation: F3 (feedback adaptivity) carries the "
                 "detector", fontsize=15, fontweight="bold", x=0.175, ha="left", y=0.955)
    fig.text(0.175, 0.895,
             "Headline number: removing F3 lowers the recall upper bound from 0.933 to 0.733 "
             "(-20.0 points, 3 of 15 segments lost); removing F6 costs 1 segment (0.867); the "
             "other five families cost nothing.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig06_feature_family_ablation", 13.5, 6.6)

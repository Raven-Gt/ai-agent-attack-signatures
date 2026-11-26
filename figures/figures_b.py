# -*- coding: utf-8 -*-
"""Figures 7-12 of the paper figure set."""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

from figlib import (AGG, AMBER, BLUE, DATA, GREY, INK, MUTED, NEG, PALETTE, RED,
                    REPO_ROOT, TEAL, check_ascii, framework_lower_bound, load_json,
                    load_jsonl, save, wilson)
import figdata

sys.path.insert(0, str(REPO_ROOT))
from research.engine import evidence  # noqa: E402  (the shipped evidence rules)


def _rules():
    """The shipped evidence rules: id -> (family, weight, name)."""
    out = {}
    for r in evidence.build_rules():
        out[r.rid] = (r.family, r.weight, r.name)
    return out


FAMILY_COLOR = {
    "F5": BLUE, "F3": RED, "F7": TEAL, "F10": AMBER, "F6": GREY,
    "F4": "#7E9CCB", "F9": "#7FC6BC", "F8": "#A6ADB4", "F2": INK, "F13": MUTED,
}
FAMILY_SHORT = {
    "F2": "active probe", "F3": "feedback adaptivity", "F4": "rhythm",
    "F5": "exploration", "F6": "repetition", "F7": "identity lineage",
    "F8": "egress", "F9": "tool channel", "F10": "machine naming",
    "F13": "config surface",
}


# --------------------------------------------------------------- figure 7 ---
def figure7():
    lofo = load_json(AGG / "lofo_framework.json")
    res = lofo["results"]
    res = sorted(res, key=lambda r: (r["recall"], r["holdout"]))
    fig = plt.figure(figsize=(14.0, 7.0))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.05, 1.0], left=0.135, right=0.975,
                          top=0.835, bottom=0.135, wspace=0.26)
    ax = fig.add_subplot(gs[0, 0])
    y = np.arange(len(res))
    cols = [BLUE if r["tp"] > 0 else RED for r in res]
    ax.barh(y, [r["recall"] for r in res], color=cols, height=0.66)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  (n_test=%d)" % (r["holdout"], r["n_test"]) for r in res],
                       fontsize=10.5)
    for yy, r in zip(y, res):
        lab = ("recall 1.000" if r["tp"] else "recall 0.000")
        ax.text(1.02, yy, lab, va="center", fontsize=10, color=INK)
        ax.text(1.02, yy - 0.32, "tau = %.4f" % r["tau"], va="center", fontsize=9,
                color="#42505E")
    ax.set_xlabel("recall on the held-out framework", fontsize=12)
    ax.set_xlim(0, 1.35)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Leave-one-framework-out recall (10 folds)", fontsize=12.5, loc="left", pad=10)
    bad = [r for r in res if r["tp"] == 0][0]
    ax.set_ylim(-2.1, len(res) - 0.4)
    ax.annotate("hackingBuddyGPT fails: the threshold calibrated on the other nine\n"
                "frameworks (tau = 0.4146) is above its own score (0.280), so the\n"
                "held-out framework is never flagged",
                xy=(0.05, -0.45), xytext=(0.02, -1.25), fontsize=10.5, color=INK,
                va="center", ha="left",
                arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.4))

    ax2 = fig.add_subplot(gs[0, 1])
    ks = list(range(1, 21))
    lbs = [framework_lower_bound(k) for k in ks]
    ax2.plot(ks, lbs, "-o", color=BLUE, markersize=4.5)
    ax2.axhline(lbs[9], color=INK, linestyle=":", linewidth=1.3)
    ax2.plot([10], [lbs[9]], "o", color=TEAL, markersize=9, zorder=5)
    ax2.annotate("k = 10 folds\n0.05^(1/10) = 0.741", xy=(10, lbs[9]), xytext=(2.6, 0.86),
                 fontsize=10.5, color=INK, ha="left", va="center",
                 arrowprops=dict(arrowstyle="->", color=TEAL, linewidth=1.3))
    ax2.plot([12], [lbs[11]], "o", color=RED, markersize=9, zorder=5)
    ax2.annotate("k = 12 frameworks\n0.05^(1/12) = 0.779", xy=(12, lbs[11]), xytext=(12.3, 0.90),
                 fontsize=10.5, color=INK,
                 arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.3))
    ax2.set_xlabel("number of frameworks k", fontsize=12)
    ax2.set_ylabel("one-sided 95% lower bound", fontsize=12)
    ax2.set_xlim(1, 20)
    ax2.set_ylim(0, 1.0)
    ax2.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax2.set_yticklabels(["0", "0.2", "0.4", "0.6", "0.8", "1.0"])
    ax2.yaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("Strength of the generalisation claim", fontsize=12.5, loc="left", pad=10)

    fig.suptitle("Figure 7 - Leave-one-framework-out: the detector generalises to nine of the "
                 "ten unseen frameworks", fontsize=15, fontweight="bold", x=0.135, ha="left", y=0.955)
    fig.text(0.135, 0.905,
             "Headline number: 9 of 10 leave-one-framework-out folds reach recall 1.000 (90.0%) "
             "with 0 false positives in every fold (56 negative actors, 95% Wilson upper bound "
             "6.42%); the single failure is hackingBuddyGPT.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig07_leave_one_framework_out", 14.0, 7.0)


# --------------------------------------------------------------- figure 8 ---
def figure8():
    rv = load_json(AGG / "rule_validation_counts.json")
    hits = rv["background_traffic_rule_hits"]
    bg = rv["background_traffic_validation"]
    waf = rv["real_attack_traffic_validation"]
    items = sorted(hits.items(), key=lambda kv: kv[1]["requests"])
    tier_color = {"T2": AMBER, "T3": GREY}

    fig = plt.figure(figsize=(15.0, 8.4))
    gs = fig.add_gridspec(2, 2, width_ratios=[2.35, 1.0], height_ratios=[0.88, 1.12],
                          left=0.215, right=0.975, top=0.855, bottom=0.115,
                          wspace=0.26, hspace=0.40)
    ax = fig.add_subplot(gs[:, 0])
    y = np.arange(len(items))
    vals = [v["requests"] for _, v in items]
    ax.barh(y, vals, color=[tier_color[v["tier"]] for _, v in items], height=0.68)
    xmax = 3.0e7
    for yy, (rid, v) in zip(y, items):
        label = "%s req / %d IPs" % (format(v["requests"], ","),
                                     v["distinct_source_addresses"])
        if v["requests"] > xmax * 0.12:
            ax.text(v["requests"] * 0.93, yy, label, va="center", ha="right", fontsize=9.5,
                    color="white")
        else:
            ax.text(v["requests"] * 1.35, yy, label, va="center", ha="left", fontsize=9.5,
                    color=INK)
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  %s" % (rid, v["framework"]) for rid, v in items], fontsize=10)
    ax.set_xlabel("requests matched (log scale)", fontsize=12)
    ax.set_xscale("log")
    ax.set_xlim(1, xmax)
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("The 16 rules that matched on public traffic - all of them tier 2 or tier 3",
                 fontsize=12.5, loc="left", pad=10)
    ax.legend(handles=[Patch(facecolor=AMBER, label="tier 2 (attack-evidence rules)"),
                        Patch(facecolor=GREY, label="tier 3 (withdrawn / generic tooling)")],
              loc="lower right", fontsize=10)

    ax2 = fig.add_subplot(gs[0, 1])
    ax2.axis("off")
    ax2.text(0.0, 0.97, "T1 validation on real traffic", fontsize=12.5, fontweight="bold",
             color=INK, va="top")
    ax2.text(0.0, 0.84, "Public internet traffic\n%s requests  /  %s source IPs\n\n"
                         "Real WAF attack transactions\n%s transactions (30 days, ModSecurity)\n\n"
                         "T1 rules matched:  0   and   0"
             % (format(bg["rows_total"], ","), format(bg["distinct_ips_total"], ","),
                format(waf["requests"], ",")),
             fontsize=11, color=INK, va="top", linespacing=1.5,
             bbox=dict(boxstyle="round,pad=0.6", facecolor="#F4F7FA", edgecolor="#D7DEE6"))
    ax2.text(0.0, 0.02, "%d tier-1 body rules were evaluated against the WAF log: %d matched."
             % (waf["body_t1_total"], waf["body_t1_hit_rules"]),
             fontsize=10.5, color="#42505E", va="bottom")

    ax3 = fig.add_subplot(gs[1, 1])
    dist = bg["ip_hit_count_dist"]
    cats = ["1 rule", "2 rules", "3+ rules"]
    vals = [dist.get("1", 0), dist.get("2", 0), 0]
    ax3.bar(range(3), vals, color=[BLUE, RED, MUTED], width=0.55)
    for i, v in enumerate(vals):
        ax3.text(i, v + 1.6, str(v), ha="center", fontsize=11, color=INK)
    ax3.set_yscale("log")
    ax3.set_ylim(0.5, 200)
    ax3.set_xticks(range(3))
    ax3.set_xticklabels(cats, fontsize=10.5)
    ax3.set_xlabel("rules matched by one source IP", fontsize=11.5)
    ax3.set_ylabel("source IPs (log scale)", fontsize=11.5)
    ax3.yaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax3.set_axisbelow(True)
    ax3.set_title("Combinatorial criterion over %s source IPs" % format(bg["distinct_ips_total"], ","),
                  fontsize=12, loc="left", pad=8)
    ax3.text(0.5, -0.34, "exactly 1 of %s source IPs matched >= 2 rules"
             % format(bg["distinct_ips_total"], ","),
             transform=ax3.transAxes, fontsize=10.5, color=INK, ha="center",
             bbox=dict(boxstyle="round,pad=0.45", facecolor="#F4F7FA", edgecolor="#D7DEE6"))

    fig.suptitle("Figure 8 - Rule validation on real traffic: no tier-1 rule fires on "
                 "9.9M public requests or 142,705 attack transactions",
                 fontsize=15, fontweight="bold", x=0.215, ha="left", y=0.958)
    fig.text(0.215, 0.915,
             "Headline number: tier-1 rules matched 0 of 9,905,794 public internet requests and "
             "0 of 142,705 real WAF attack transactions; all 16 rules that did match on public "
             "traffic are tier 2 or tier 3 and are excluded from deployment.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig08_rule_validation_real_traffic", 15.0, 8.2)


# --------------------------------------------------------------- figure 9 ---
def figure9():
    rules = _rules()
    withdrawn = {"E13": ("withdrawn", 0.0, "rejected on real traffic (not implemented)")}
    items = []
    for rid in sorted(rules, key=lambda r: int(r[1:])):
        fam, w, name = rules[rid]
        items.append((rid, fam, w, name))
    for rid, (fam, w, name) in withdrawn.items():
        items.append((rid, fam, w, name))
    order = sorted(range(len(items)),
                   key=lambda i: (FAMILY_SHORT.get(items[i][1], "zz"), int(items[i][0][1:])))
    items = [items[i] for i in order]
    fam_conv = {}
    for rid, (fam, w, name) in rules.items():
        if rid == "E10" or w <= 0:
            continue
        fam_conv.setdefault(fam, []).append(w)
    fam_conv = {f: 1.0 - math.prod([1.0 - w for w in v]) for f, v in fam_conv.items()}
    tau = 0.35

    fig = plt.figure(figsize=(15.0, 8.8))
    gs = fig.add_gridspec(1, 2, width_ratios=[2.05, 1.0], left=0.165, right=0.975,
                          top=0.795, bottom=0.185, wspace=0.26)
    ax = fig.add_subplot(gs[0, 0])
    y = np.arange(len(items))
    for i, (rid, fam, w, name) in enumerate(items):
        c = FAMILY_COLOR.get(fam, MUTED)
        if rid == "E10":
            ax.barh(i, 0.395, color="#E3E8EF", edgecolor=INK, hatch="///", linewidth=0.8,
                    height=0.68)
        elif rid == "E13":
            ax.barh(i, 0.001, color="#E3E8EF", edgecolor=INK, linewidth=0.8, height=0.68)
        else:
            ax.barh(i, w, color=c, height=0.68)
        if rid == "E10":
            ax.text(0.42, i, "0.95 - response-side probe, not observable passively",
                    va="center", fontsize=9.5, color="#42505E", style="italic")
        elif rid == "E13":
            ax.text(0.012, i, "withdrawn - rejected on real traffic", va="center",
                    fontsize=9.5, color="#42505E", style="italic")
        elif w > 0:
            ax.text(w + 0.006, i, "%.2f" % w, va="center", fontsize=10, color=INK)
    ax.axvline(tau, color=INK, linestyle="--", linewidth=1.6)
    ax.set_ylim(-0.7, len(items) + 1.4)
    ax.text(tau + 0.008, len(items) + 0.55, "decision threshold 0.35", va="center", ha="left",
            fontsize=10.5, color=INK, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(["%s  %s" % (rid, FAMILY_SHORT.get(fam, fam)) for rid, fam, w, n in items],
                       fontsize=10)
    ax.set_xlabel("weight of the evidence rule", fontsize=12)
    ax.set_xlim(0, 0.62)
    ax.set_xticks([0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6])
    ax.set_xticklabels(["0", "0.10", "0.20", "0.30", "0.40", "0.50", "0.60"])
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("The 15 evidence-rule identifiers E1-E15, coloured by feature family\n"
                 "(the largest single-rule weight is 0.34, below the 0.35 decision line)",
                 fontsize=12.5, loc="left", pad=10)

    handles = [Patch(facecolor=FAMILY_COLOR[f], label="%s %s" % (f, FAMILY_SHORT[f]))
               for f in sorted(FAMILY_COLOR, key=lambda f: FAMILY_SHORT[f])
               if f in {it[1] for it in items}]
    fig.legend(handles=handles, loc="lower center", ncol=5, fontsize=9.5,
               bbox_to_anchor=(0.30, 0.005), handlelength=1.3, columnspacing=1.2)

    ax2 = fig.add_subplot(gs[0, 1])
    fams = sorted(fam_conv, key=lambda f: -fam_conv[f])
    y2 = np.arange(len(fams))[::-1]
    ax2.barh(y2, [fam_conv[f] for f in fams],
             color=[RED if fam_conv[f] >= tau else BLUE for f in fams], height=0.66)
    for yy, f in zip(y2, fams):
        ax2.text(fam_conv[f] + 0.008, yy, "%.4f" % fam_conv[f], va="center", fontsize=10.5,
                 color=INK)
    ax2.axvline(tau, color=INK, linestyle="--", linewidth=1.6)
    ax2.set_ylim(-0.7, len(fams) + 1.4)
    ax2.text(tau + 0.006, len(fams) + 0.55, "decision threshold 0.35", va="center", ha="left",
             fontsize=10.5, color=INK, fontweight="bold")
    ax2.set_yticks(y2)
    ax2.set_yticklabels(["%s  %s" % (f, FAMILY_SHORT[f]) for f in fams], fontsize=10.5)
    ax2.set_xlabel("conviction weight of a whole family", fontsize=12)
    ax2.set_xlim(0, 0.50)
    ax2.set_xticks([0, 0.1, 0.2, 0.3, 0.4, 0.5])
    ax2.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("Family conviction capacity\n"
                  "(F3 alone reaches 0.4086 > 0.35: one family can convict)",
                  fontsize=12.5, loc="left", pad=10)

    fig.suptitle("Figure 9 - Evidence-rule weights and the family that carries the decision",
                 fontsize=15, fontweight="bold", x=0.165, ha="left", y=0.975)
    fig.text(0.165, 0.925,
             "Headline number: the largest single-rule weight is 0.34 (E1), below the 0.35 "
             "decision line, but the three feedback-adaptivity rules of family F3 together reach "
             "0.4086 - above it.",
             fontsize=10.5, color="#42505E", ha="left")
    return save(fig, "fig09_evidence_rule_weights", 15.0, 8.0)


# -------------------------------------------------------------- figure 10 ---
def _ecdf(values):
    xs = np.sort(np.asarray(values, dtype=float))
    ys = np.arange(1, len(xs) + 1) / len(xs)
    return xs, ys


def figure10():
    d = figdata.build()
    ai = d["ai_actors"]
    sc = d["scanners"]
    real = d["real_attackers"]
    tau = 0.35

    fig = plt.figure(figsize=(16.0, 7.4))
    gs = fig.add_gridspec(1, 3, width_ratios=[1.35, 1.0, 1.0], left=0.055, right=0.985,
                          top=0.795, bottom=0.135, wspace=0.30)

    # (a) overlap map
    ax = fig.add_subplot(gs[0, 0])
    xlim = (0.3, 6.0e3)
    ylim = (0.5, 2.0e4)
    rx = np.clip(np.maximum(real["rpm"], 1e-3), xlim[0], xlim[1])
    ry = np.clip(np.maximum(real["templates"], 1), ylim[0], ylim[1])
    h = ax.hexbin(rx, ry, gridsize=26, cmap="Blues", mincnt=1, alpha=0.40, linewidths=0.3,
                  bins="log")
    ax.scatter([a["rpm"] for a in ai], [a["templates"] for a in ai], s=70, color=BLUE,
               edgecolor="white", linewidth=0.8, zorder=4, label="AI agent actors (15)")
    ax.scatter([s["rpm"] for s in sc], [s["templates"] for s in sc], s=90, marker="D",
               color=RED, edgecolor="white", linewidth=0.8, zorder=5,
               label="scanner actors (6)")
    flag = [s for s in sc if s["detected"]]
    ax.annotate("%d flagged scanner actors" % len(flag),
                xy=(float(np.median([s["rpm"] for s in flag])),
                    float(np.median([s["templates"] for s in flag]))),
                xytext=(0.60, 0.86), textcoords="axes fraction", fontsize=9.5, color=RED,
                arrowprops=dict(arrowstyle="->", color=RED, linewidth=1.2))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(xlim)
    ax.set_ylim(ylim)
    ax.set_xlabel("request rate (requests per minute)", fontsize=12)
    ax.set_ylabel("distinct endpoint templates", fontsize=12)
    ax.grid(True, color="#EDF1F5", linewidth=0.7)
    ax.set_axisbelow(True)
    handles, labels = ax.get_legend_handles_labels()
    handles.append(Patch(facecolor="#B7CFEB", alpha=0.75, label="real attackers (1,582)"))
    ax.legend(handles=handles, loc="upper left", fontsize=9.5)
    ax.set_title("Rate and breadth overlap", fontsize=12.5, loc="left", pad=10)

    # (b) ECDF of the request rate
    ax2 = fig.add_subplot(gs[0, 1])
    for vals, color, lab in [([a["rpm"] for a in ai], BLUE, "AI agent actors"),
                              ([s["rpm"] for s in sc], RED, "scanner actors")]:
        xs, ys = _ecdf(vals)
        ax2.step(xs, ys, where="post", color=color, linewidth=2.0, label=lab)
        ax2.scatter(vals, [float(np.searchsorted(np.sort(vals), v) + 1) / len(vals)
                           for v in vals], s=34, color=color, zorder=5)
    xs, ys = _ecdf([max(v, 1e-3) for v in real["rpm"]])
    ax2.step(xs, ys, where="post", color=GREY, linestyle="--", linewidth=1.8,
             label="real attackers (1,582)")
    ax2.set_xscale("log")
    ax2.set_xlim(0.3, 2.0e4)
    ax2.set_xlabel("request rate (requests per minute)", fontsize=12)
    ax2.set_ylabel("cumulative share of actors", fontsize=12)
    ax2.set_ylim(0, 1.02)
    ax2.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax2.set_yticklabels(["0", "25%", "50%", "75%", "100%"])
    ax2.grid(True, color="#EDF1F5", linewidth=0.7)
    ax2.set_axisbelow(True)
    ax2.legend(loc="lower right", fontsize=9.5)
    ax2.set_title("Request-rate distribution", fontsize=12.5, loc="left", pad=10)

    # (c) ECDF of endpoint breadth
    ax3 = fig.add_subplot(gs[0, 2])
    for vals, color, lab in [([a["templates"] for a in ai], BLUE, "AI agent actors"),
                              ([s["templates"] for s in sc], RED, "scanner actors")]:
        xs, ys = _ecdf(vals)
        ax3.step(xs, ys, where="post", color=color, linewidth=2.0, label=lab)
    xs, ys = _ecdf(real["templates"])
    ax3.step(xs, ys, where="post", color=GREY, linestyle="--", linewidth=1.8,
             label="real attackers (1,582)")
    ax3.set_xscale("log")
    ax3.set_xlim(0.5, 2.0e4)
    ax3.set_xlabel("distinct endpoint templates", fontsize=12)
    ax3.set_ylabel("cumulative share of actors", fontsize=12)
    ax3.set_ylim(0, 1.02)
    ax3.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax3.set_yticklabels(["0", "25%", "50%", "75%", "100%"])
    ax3.grid(True, color="#EDF1F5", linewidth=0.7)
    ax3.set_axisbelow(True)
    ax3.legend(loc="lower right", fontsize=9.5)
    ax3.set_title("Endpoint-breadth distribution", fontsize=12.5, loc="left", pad=10)

    fig.suptitle("Figure 10 - AI agent versus scanner behaviour: the two populations overlap",
                 fontsize=15, fontweight="bold", x=0.055, ha="left", y=0.975)
    fig.text(0.055, 0.925,
             "Headline number: the 4 flagged scanner actors sit inside the request-rate and "
             "endpoint-breadth range of the AI agent actors -\n"
             "the same traffic shape that makes an agent recognisable also makes a "
             "content-discovery scanner recognisable, which is the source of the\n"
             "66.67% scanner false-positive rate.",
             fontsize=10.5, color="#42505E", ha="left", va="top", linespacing=1.5)
    return save(fig, "fig10_ai_agent_vs_scanner_behaviour", 16.0, 7.0)


# -------------------------------------------------------------- figure 11 ---
def figure11():
    d = figdata.build()
    ai = d["ai_actors"]
    fd = load_json(AGG / "framework_detection.json")
    tau = fd["decision_threshold"]
    total = sum(a["scored_actor_requests"] for a in ai)

    fig = plt.figure(figsize=(15.0, 7.2))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.25, 1.0], left=0.06, right=0.975,
                          top=0.80, bottom=0.135, wspace=0.24)
    ax = fig.add_subplot(gs[0, 0])
    for a in ai:
        det = a["detected"] == "yes"
        ax.scatter(a["duration_s"], a["ai_score"],
                   s=40 + 260 * (a["scored_actor_requests"] / total) ** 0.35,
                   color=BLUE if det else RED, alpha=0.85, edgecolor="white",
                   linewidth=1.0, zorder=4)
    ax.axhline(tau, color=INK, linestyle="--", linewidth=1.5)
    ax.set_xscale("log")
    ax.set_xlim(45, 3.0e4)
    ax.set_ylim(0.15, 0.92)
    ax.text(48, tau + 0.022, "decision threshold 0.35", fontsize=10.5, color=INK,
            fontweight="bold", va="bottom", ha="left")

    # greedy label placement: no label may overlap another label or a bubble
    placed = []
    offsets = [(0, 13), (0, -20), (58, 6), (58, -18), (-58, 6), (-58, -18),
               (0, 30), (0, -36), (80, 24), (-80, 24), (80, -34), (-80, -34)]
    fs = 8.8
    for a in sorted(ai, key=lambda x: -x["ai_score"]):
        px, py = ax.transData.transform((a["duration_s"], a["ai_score"]))
        area = 40 + 260 * (a["scored_actor_requests"] / total) ** 0.35
        rad = math.sqrt(area / math.pi) + 2.0
        w = len(a["actor_id"]) * fs * 0.75
        h = fs * 1.6
        best = offsets[0]
        for dx, dy in offsets:
            x0 = px + dx - w / 2.0
            x1 = px + dx + w / 2.0
            y0 = py + dy - h / 2.0
            y1 = py + dy + h / 2.0
            if all(not (x0 < bx1 and x1 > bx0 and y0 < by1 and y1 > by0)
                   for bx0, bx1, by0, by1 in placed):
                best = (dx, dy)
                break
        placed.append((px + best[0] - w / 2.0, px + best[0] + w / 2.0,
                       py + best[1] - h / 2.0, py + best[1] + h / 2.0))
        placed.append((px - rad, px + rad, py - rad, py + rad))
        ax.annotate(a["actor_id"], (a["duration_s"], a["ai_score"]),
                    textcoords="offset points", xytext=best, fontsize=fs,
                    ha="center", va="center", color=INK, zorder=6,
                    path_effects=[pe.withStroke(linewidth=2.6, foreground="white")])
    ax.set_xlabel("attack duration of the actor (seconds, log scale)", fontsize=12)
    ax.set_ylabel("AI attribution score", fontsize=12)
    ax.set_yticks([0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    ax.yaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("The 15 AI agent actors: duration versus score (bubble = request volume)",
                 fontsize=12.5, loc="left", pad=10)

    ax2 = fig.add_subplot(gs[0, 1])
    ordered = sorted(ai, key=lambda a: -a["scored_actor_requests"])
    y = np.arange(len(ordered))[::-1]
    ax2.barh(y, [a["scored_actor_requests"] for a in ordered], color=BLUE, height=0.68)
    for yy, a in zip(y, ordered):
        ax2.text(a["scored_actor_requests"] * 1.25, yy,
                 "%s req  (%s s)" % (format(a["scored_actor_requests"], ","),
                                     format(int(a["duration_s"]), ",")),
                 va="center", fontsize=9.5, color=INK)
    ax2.set_yticks(y)
    ax2.set_yticklabels([a["actor_id"] for a in ordered], fontsize=10)
    ax2.set_xscale("log")
    ax2.set_xlim(25, 1.0e6)
    ax2.set_xlabel("scored requests per actor (log scale)", fontsize=12)
    ax2.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("Attack volume per actor", fontsize=12.5, loc="left", pad=10)
    top = ordered[0]
    ax2.text(0.0, -0.16, "strix alone contributes %s of the %s scored agent requests (%.0f%%)"
             % (format(top["scored_actor_requests"], ","), format(total, ","),
                100.0 * top["scored_actor_requests"] / total),
             transform=ax2.transAxes, fontsize=10.5, color=INK,
             bbox=dict(boxstyle="round,pad=0.45", facecolor="#F4F7FA", edgecolor="#D7DEE6"))

    fig.suptitle("Figure 11 - The 15 AI agent attack segments: duration, volume and score",
                 fontsize=15, fontweight="bold", x=0.06, ha="left", y=0.975)
    fig.text(0.06, 0.925,
             "Headline number: a single capture (strix, %s requests) carries %.0f%% of all scored "
             "agent traffic, and the two missed frameworks\n"
             "are the two thinnest actors in the set (hackingBuddyGPT with 62 requests, pentest-ai "
             "veto-capped at 0.250)."
             % (format(top["scored_actor_requests"], ","),
                100.0 * top["scored_actor_requests"] / total),
             fontsize=10.5, color="#42505E", ha="left", va="top", linespacing=1.5)
    return save(fig, "fig11_ai_actor_timeline", 15.0, 7.2)


# -------------------------------------------------------------- figure 12 ---
def figure12():
    rules = _rules()
    fam_of = {rid: v[0] for rid, v in rules.items()}
    w_of = {rid: v[1] for rid, v in rules.items()}

    def split(rs):
        if isinstance(rs, str):
            return [x for x in rs.split(";") if x]
        return [x for x in rs if x]

    pops = {}
    pops["AI agent actors (15)"] = [split(a["fired_rules"])
                                   for a in load_json(AGG / "framework_detection.json")["per_actor"]]
    pops["Scanner actors (6)"] = [split(c["fired_rules"])
                                  for c in load_json(NEG / "_index.json")["captures"]]
    pops["Real attackers (1,582)"] = [split(r.get("fired_rules", []))
                                     for r in load_jsonl(DATA / "features" / "actor_features.jsonl")]

    fams = sorted({f for f in fam_of.values() if f})
    mean_w = {}
    for name, actors in pops.items():
        acc = {f: 0.0 for f in fams}
        for rs in actors:
            tot = {f: 0.0 for f in fams}
            for r in rs:
                if r in fam_of and fam_of[r]:
                    tot[fam_of[r]] += w_of[r]
            for f in fams:
                acc[f] += tot[f]
        mean_w[name] = {f: acc[f] / len(actors) for f in fams}

    fire = {}
    for name, actors in pops.items():
        c = {r: 0 for r in rules}
        for rs in actors:
            for r in set(rs):
                if r in c:
                    c[r] += 1
        fire[name] = {r: c[r] / len(actors) for r in rules}

    colors = {"AI agent actors (15)": BLUE, "Scanner actors (6)": RED,
              "Real attackers (1,582)": GREY}
    fig = plt.figure(figsize=(15.0, 7.8))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.15, 1.0], left=0.10, right=0.975,
                          top=0.80, bottom=0.135, wspace=0.30)
    ax = fig.add_subplot(gs[0, 0])
    names = list(pops)
    fh = len(names)
    h = 0.24
    for j, name in enumerate(names):
        yy = np.arange(len(fams)) + (fh - 1) / 2.0 * h - j * h
        ax.barh(yy, [mean_w[name][f] for f in fams], height=h * 0.92,
                color=colors[name], label=name)
    ax.set_yticks(np.arange(len(fams)))
    ax.set_yticklabels(["%s  %s" % (f, FAMILY_SHORT[f]) for f in fams], fontsize=10.5)
    ax.set_xlabel("mean conviction weight contributed by the family", fontsize=12)
    ax.set_xlim(0, 0.42)
    ax.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10, loc="lower right")
    ax.set_title("Which feature families carry the score", fontsize=12.5, loc="left", pad=10)
    ax.text(0.20, 0.50,
            "the flagged scanner actors fire the shared\n"
            "rules E5, E6, E7, E11 and E12; those five rules\n"
            "alone sum to 0.542, above the 0.35 decision line",
            transform=ax.transAxes, fontsize=9.5, color=INK, va="center", ha="left",
            bbox=dict(boxstyle="round,pad=0.45", facecolor="#F4F7FA", edgecolor="#D7DEE6"))

    ax2 = fig.add_subplot(gs[0, 1])
    active = sorted([r for r in rules if any(fire[n][r] > 0 for n in names)],
                     key=lambda r: -fire[names[-1]][r])
    y2 = np.arange(len(active))[::-1]
    for j, name in enumerate(names):
        yy = y2 + (fh - 1) / 2.0 * h - j * h
        ax2.barh(yy, [fire[name][r] for r in active], height=h * 0.92, color=colors[name],
                 label=name if j == 0 else None)
    for j, name in enumerate(names):
        yy = y2 + (fh - 1) / 2.0 * h - j * h
        for r, v in zip(active, [fire[name][r] for r in active]):
            if v >= 0.05:
                ax2.text(v + 0.012, yy[list(active).index(r)], "%.0f%%" % (100 * v),
                         va="center", fontsize=8.5, color=INK)
    ax2.set_yticks(y2)
    ax2.set_yticklabels(active, fontsize=10)
    ax2.set_xlabel("share of actors in which the rule fired", fontsize=12)
    ax2.set_xlim(0, 1.0)
    ax2.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax2.set_xticklabels(["0", "25%", "50%", "75%", "100%"])
    ax2.xaxis.grid(True, color="#E6EAEF", linewidth=0.8)
    ax2.set_axisbelow(True)
    ax2.set_title("Rule firing rate per population (colours as in the left panel)",
                  fontsize=12.5, loc="left", pad=10)
    ax2.text(0.5, -0.20,
             "the flagged scanner actors fire the shared rules E5, E6, E7, E11 and E12\n"
             "(plus E9 for three of them); those five rules alone sum to 0.542 > 0.35",
             transform=ax2.transAxes, fontsize=10, color=INK, va="top", ha="center",
             linespacing=1.5)

    fig.suptitle("Figure 12 - The scanner false positives fire the same evidence rules as the "
                 "AI agents", fontsize=15, fontweight="bold", x=0.10, ha="left", y=0.975)
    fig.text(0.10, 0.925,
             "Headline number: the flagged scanner actors trigger E5, E6, E7, E11 and E12 - the\n"
             "feedback, repetition and enumeration rules that carry the AI signal - and those five\n"
             "rules alone sum to 0.542, above the 0.35 decision line: 66.67% of the scanners are flagged.",
             fontsize=10.5, color="#42505E", ha="left", va="top", linespacing=1.5)
    return save(fig, "fig12_feature_family_profile", 15.0, 7.6)

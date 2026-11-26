"""Evaluation module: session level and window level metrics, cluster bootstrap
confidence intervals and early-stop detection.

Metric definitions (written down, so that they cannot be challenged)
-------------------------------------------------------------------
* **Window level** (the online detection unit): one sliding window = one sample.
  The sample count is large (lab1 541 + lab2 1521 requests gives thousands of
  windows), so precision, recall and F1 are stable.
* **Session level**: one whole session = one sample.  The sample count is small
  (one or two sessions per lab), so these numbers are indicative only; the
  session level scatter and the bootstrap interval are reported instead.
* **Cluster bootstrap**: windows inside one session are correlated, so the
  confidence interval resamples whole **sessions**.  Resampling windows
  independently would underestimate the interval badly.
* **Early-stop detection**: starting at the first request of a session, a
  decision is taken every k requests; the report gives "after how many
  requests the alarm fires" and the recall at 5, 10, 20 and 50.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict


def confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    return tp, fp, fn, tn


def prf(tp, fp, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def binary_metrics(y_true, y_pred):
    tp, fp, fn, tn = confusion(y_true, y_pred)
    prec, rec, f1 = prf(tp, fp, fn)
    spec = tn / (tn + fp) if (tn + fp) else 0.0
    acc = (tp + tn) / len(y_true) if y_true else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return {
        "n": len(y_true),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": prec, "recall": rec, "f1": f1,
        "specificity": spec, "accuracy": acc, "mcc": mcc,
        "fpr": (fp / (fp + tn)) if (fp + tn) else 0.0,
    }


def roc_auc(y_true, scores):
    """Mann-Whitney U formulation of the AUC (with average ranks for ties)."""
    pairs = sorted(zip(scores, y_true))
    n = len(pairs)
    if n == 0:
        return 0.0
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    pos = sum(y_true)
    neg = n - pos
    if pos == 0 or neg == 0:
        return 0.5
    rsum = sum(r for r, (_, t) in zip(ranks, pairs) if t == 1)
    return (rsum - pos * (pos + 1) / 2.0) / (pos * neg)


def pr_auc(y_true, scores):
    """Average precision."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    pos = sum(y_true)
    if pos == 0:
        return 0.0
    tp = 0
    prev_rec = 0.0
    ap = 0.0
    for rank, idx in enumerate(order, start=1):
        if y_true[idx] == 1:
            tp += 1
            rec = tp / pos
            prec = tp / rank
            ap += (rec - prev_rec) * prec
            prev_rec = rec
    return ap


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def cluster_bootstrap_ci(y_true, y_pred, groups, n_boot=1000, seed=12345):
    """Bootstrap CI that resamples sessions (groups), handling the within-session correlation of windows."""
    by_group = defaultdict(list)
    for t, p, g in zip(y_true, y_pred, groups):
        by_group[g].append((t, p))
    keys = list(by_group)
    if not keys:
        return {}
    rng = random.Random(seed)
    stats = {"precision": [], "recall": [], "f1": []}
    for _ in range(n_boot):
        yb, pb = [], []
        for _ in range(len(keys)):
            g = keys[rng.randrange(len(keys))]
            yb.extend(t for t, _ in by_group[g])
            pb.extend(p for _, p in by_group[g])
        if not yb:
            continue
        tp, fp, fn, tn = confusion(yb, pb)
        prec, rec, f1 = prf(tp, fp, fn)
        stats["precision"].append(prec)
        stats["recall"].append(rec)
        stats["f1"].append(f1)
    out = {}
    for k, v in stats.items():
        if not v:
            continue
        v = sorted(v)
        out[k] = {
            "lo": v[int(0.025 * len(v))],
            "hi": v[min(len(v) - 1, int(0.975 * len(v)))],
            "mean": sum(v) / len(v),
        }
    return out


def early_detection(sessions, threshold):
    """sessions: [{key, label, windows:[{n_requests, score}]}] -> early-stop detection metrics."""
    per_sess = []
    for s in sessions:
        hit = None
        for w in sorted(s["windows"], key=lambda x: x["n_requests"]):
            if w["score"] >= threshold:
                hit = w["n_requests"]
                break
        per_sess.append({
            "key": s["key"], "label": s["label"],
            "detected_at": hit,
            "total": max((w["n_requests"] for w in s["windows"]), default=0),
        })
    out = {"per_session": per_sess}
    for k in (5, 10, 20, 50, 100):
        agents = [p for p in per_sess if str(p["label"]).startswith("agent")]
        scripts = [p for p in per_sess if str(p["label"]).startswith("script")]
        def hit_rate(lst):
            if not lst:
                return None
            return sum(1 for p in lst if p["detected_at"] is not None and p["detected_at"] <= k) / len(lst)
        out["recall_at_%d" % k] = {
            "agent": hit_rate(agents),
            "script_false_alarm": hit_rate(scripts),
        }
    det = [p["detected_at"] for p in per_sess if p["detected_at"] is not None and str(p["label"]).startswith("agent")]
    out["agent_detect_latency_median"] = sorted(det)[len(det) // 2] if det else None
    return out

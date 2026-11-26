"""Interval estimators used by the evaluation scripts.

All estimators are implemented with the standard library so that the released
pipeline has no third-party runtime dependency.  When SciPy is installed its
`scipy.stats.beta` implementation is used for the Beta quantiles, because that
is the implementation the study used; the pure-python fallback is numerically
equivalent (verified against SciPy to 1e-12) and is used only when SciPy is
absent.

Estimators
----------
* Clopper-Pearson  -- exact two-sided binomial interval (conservative).
* Jeffreys         -- two-sided interval from the Jeffreys Beta(1/2, 1/2) prior.
* Wilson           -- score interval, used for the false-positive rate.
* rule of three    -- 95% upper bound when zero events are observed.
* framework bound  -- one-sided 95% lower bound 0.05^(1/k) for "k frameworks
  all detected", the correct uncertainty statement for generalisation to
  unseen frameworks.
"""

from __future__ import annotations

import math

try:  # optional, used when available
    from scipy.stats import beta as _scipy_beta
except Exception:  # pragma: no cover - exercised only without SciPy
    _scipy_beta = None


# --------------------------------------------------------------------- beta ---
def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-16:
            break
    return h


def _betai(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta + b * math.log(1.0 - x) + a * math.log(x)) * _betacf(b, a, 1.0 - x) / b


def _beta_ppf(p: float, a: float, b: float) -> float:
    """Quantile of Beta(a, b)."""
    if _scipy_beta is not None:
        return float(_scipy_beta.ppf(p, a, b))
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if _betai(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


# --------------------------------------------------------------- intervals ---
def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple:
    """Exact two-sided binomial confidence interval (Clopper-Pearson)."""
    if n <= 0:
        return (0.0, 1.0)
    k = max(0, min(int(k), int(n)))
    lo = 0.0 if k == 0 else _beta_ppf(alpha / 2.0, k, n - k + 1)
    hi = 1.0 if k == n else _beta_ppf(1.0 - alpha / 2.0, k + 1, n - k)
    return (float(lo), float(hi))


def jeffreys(k: int, n: int, alpha: float = 0.05) -> tuple:
    """Two-sided interval from the Jeffreys Beta(1/2, 1/2) prior."""
    if n <= 0:
        return (0.0, 1.0)
    k = max(0, min(int(k), int(n)))
    lo = 0.0 if k == 0 else _beta_ppf(alpha / 2.0, k + 0.5, n - k + 0.5)
    hi = 1.0 if k == n else _beta_ppf(1.0 - alpha / 2.0, k + 0.5, n - k + 0.5)
    return (float(lo), float(hi))


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple:
    """Wilson score interval for a binomial proportion."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rule_of_three(n: int) -> float:
    """95% upper bound on the rate when zero events were observed (3/n)."""
    return (3.0 / n) if n else 1.0


def framework_lower_bound(k: int, alpha: float = 0.05) -> float:
    """One-sided 95% lower bound for 'all k frameworks detected' = alpha^(1/k)."""
    return float(alpha ** (1.0 / k)) if k > 0 else 0.0


def ratio(k: int, n: int) -> float:
    return (k / n) if n else 0.0

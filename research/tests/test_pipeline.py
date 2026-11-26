"""Unit tests for the research pipeline.

Run them with `python -m pytest research/tests -q` from the repository root.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from research.engine import ioc_match  # noqa: E402
from research.engine.capture import Request  # noqa: E402
from research.evaluation import stats  # noqa: E402
from research.evaluation.loaders import (load_actors, load_negative_scores,  # noqa: E402
                                         load_scanner_actors)
from research.pipeline.actor_segmentation import segment_requests  # noqa: E402
from research.pipeline.feature_extraction import extract_features  # noqa: E402
from research.pipeline.score_actor import score_requests  # noqa: E402


def _request(ts, src, uri, status=200, ua="curl/8.18.0", user="-", body=""):
    return Request(ts=ts, rid="r%d" % int(ts.timestamp()), src=src, method="GET", uri=uri,
                   args="", status=status, bytes=100, rt=0.0, urt="", uaddr="", host="example.org",
                   ua=ua, ref="", user=user, role="-", body=body)


def test_segmentation_splits_by_address():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    reqs = [_request(base + timedelta(seconds=i), "10.0.0.1", "/a/%d" % i) for i in range(3)]
    reqs += [_request(base + timedelta(seconds=i), "10.0.0.2", "/b/%d" % i) for i in range(3)]
    actors = segment_requests(reqs, mode="session", min_requests=1)
    assert len(actors) == 2
    assert sorted(a.src for a in actors) == ["10.0.0.1", "10.0.0.2"]


def test_segmentation_splits_on_silence():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    reqs = [_request(base, "10.0.0.1", "/a"),
            _request(base + timedelta(seconds=10), "10.0.0.1", "/b"),
            _request(base + timedelta(seconds=1200), "10.0.0.1", "/c")]
    actors = segment_requests(reqs, mode="session", gap_seconds=600.0, min_requests=1)
    assert len(actors) == 2
    assert actors[0].n_requests == 2
    assert actors[1].n_requests == 1


def test_segmentation_window_mode():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    reqs = [_request(base, "10.0.0.1", "/a"),
            _request(base + timedelta(seconds=60), "10.0.0.1", "/b"),
            _request(base + timedelta(seconds=1200), "10.0.0.1", "/c")]
    actors = segment_requests(reqs, mode="window", window_minutes=10.0, min_requests=1)
    assert len(actors) == 2


def test_health_checks_are_removed():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    reqs = [_request(base, "127.0.0.1", "/health", status=200)]
    assert segment_requests(reqs, min_requests=1) == []
    assert len(segment_requests(reqs, min_requests=1, keep_noise=True)) == 1


def test_score_of_a_flat_browser_stream_is_low():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    reqs = [_request(base + timedelta(seconds=i), "10.0.0.1", "/page/%d" % i,
                     status=200, ua=ua) for i in range(20)]
    feats = extract_features(reqs)
    assert set(feats) >= {"f5_distinct_templates", "f7_distinct_users", "f9_ua_families"}
    score = score_requests(reqs)["score"]
    assert 0.0 <= score < 0.35


def test_veto_caps_a_dictionary_enumerator():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    reqs = []
    for i in range(400):
        reqs.append(_request(base + timedelta(seconds=i * 2), "10.0.0.1",
                              "/admin/%d" % i, status=404, ua="ffuf/2.1"))
    res = score_requests(reqs)
    assert res["vetoed"] is True
    assert res["score"] <= 0.25


def test_interval_estimators():
    jeff = stats.jeffreys(0, 10)
    assert jeff[0] == 0.0 and 0.2 < jeff[1] < 0.4
    wil = stats.wilson(43, 1582)
    assert abs(wil[0] - 0.0202413) < 1e-5
    assert abs(wil[1] - 0.0364109) < 1e-5
    assert abs(stats.rule_of_three(1582) - 3.0 / 1582) < 1e-12
    assert abs(stats.framework_lower_bound(12) - 0.05 ** (1.0 / 12)) < 1e-12


def test_pure_python_beta_matches_scipy():
    try:
        from scipy.stats import beta as scipy_beta
    except Exception:
        return
    for a, b, p in ((13, 2, 0.025), (2, 14, 0.975), (13.5, 2.5, 0.025)):
        assert abs(stats._beta_ppf(p, a, b) - float(scipy_beta.ppf(p, a, b))) < 1e-9


def test_shipped_artifacts_reproduce_the_headline_numbers():
    actors = load_actors()
    detected = [a for a in actors if a["score"] >= 0.35]
    assert len(detected) == 13
    assert len(actors) == 15
    frameworks = {a["fw"] for a in actors}
    detected_frameworks = {a["fw"] for a in detected}
    assert len(detected_frameworks) == 10
    assert len(frameworks) == 12

    negatives = load_negative_scores()
    fp = sum(1 for s in negatives if s["score"] >= 0.35)
    assert (len(negatives), fp) == (1582, 43)

    scanners = load_scanner_actors()
    sc_fp = sum(1 for s in scanners if s["score"] >= 0.35)
    assert (len(scanners), sc_fp) == (6, 4)


def test_tier1_rules_do_not_fire_on_benign_browser_traffic():
    rules = json.loads((REPO_ROOT / "signatures" / "rules.json").read_text(encoding="utf-8"))["rules"]
    rules += json.loads((REPO_ROOT / "signatures" / "agpl" / "rules-agpl.json")
                        .read_text(encoding="utf-8"))["rules"]
    t1 = [r for r in rules if r["tier"] == "T1"]
    assert len(t1) == 272
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    sample = {"ua": ua, "uri": "/index.html", "body": "",
              "hdr": "Accept-Language: en-US,en;q=0.9"}
    assert [r["id"] for r in t1 if ioc_match.match_sample(r, sample)] == []


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))

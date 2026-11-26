"""Reproducible research pipeline for AI attack-agent traffic detection.

Layout
------
```
research/
  engine/       vendored detection engine (feature families, evidence rules, IOC matcher)
  pipeline/     request stream -> actors -> features -> attribution score
  evaluation/   recall / false-positive / ablation / leave-one-framework-out statistics
  ci/           helper scripts invoked by the GitHub Actions workflow
  fixtures/     vendored data snapshots used by the evaluation scripts and by CI
```

Every number reported by the study is recomputed from the JSON artifacts under
`research/fixtures/` (or from `data/` when that tree is populated).
"""

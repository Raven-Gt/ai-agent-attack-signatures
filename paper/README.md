# arXiv LaTeX package

This directory is the submission-ready LaTeX version of the paper
**"Attribution Limits of AI Pentest Agents: An Empirical Study of 65 Audited Codebases,
272 Validated Traffic Signatures, and the Boundary Where Attribution Stops Working"**.

The canonical, human-readable source of the paper remains
[`docs/PAPER.md`](../docs/PAPER.md). This directory is a faithful LaTeX rendering of it:
every number in `main.tex` is taken verbatim from `docs/PAPER.md` (or, for figure captions,
from [`figures/CAPTIONS.md`](../figures/CAPTIONS.md)) and is not re-derived, re-rounded or
otherwise altered.

**Artefact repository:** <https://github.com/Raven-Gt/ai-agent-attack-signatures>
(the signatures, the captured datasets and the evaluation code that back every number in the
paper).

## Contents

| Path | What it is |
|---|---|
| `main.tex` | The paper. Plain `article` class, 11pt. |
| `main.pdf` | The compiled paper (18 pages, letter, 1in margins). |
| `REFERENCES.bib` | Bibliography. |
| `figures/` | The 12 vector (PDF) figures actually referenced by the paper. |
| `Makefile` | Build rules for `make`. |
| `build.sh` | Shell fallback for environments without `make`. |

## Rebuilding

Requirements: a TeX distribution with `pdflatex` and `bibtex`. The paper uses only packages
that ship with TeX Live and are available on arXiv: `geometry`, `graphicx`, `booktabs`,
`amsmath`, `amssymb`, `array`, `tabularx`, `longtable`, `listings`, `xcolor`,
`microtype`, `caption`, `lmodern`, `hyperref`. No class or package outside that set is
required, and no non-standard option is used.

```bash
# with make
make

# without make
sh build.sh

# or by hand
pdflatex -interaction=nonstopmode main.tex
bibtex   main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

The result is `main.pdf`. The build must run **inside this directory**: `main.tex` refers to
the figures as `figures/<filename>.pdf` and to the bibliography as `REFERENCES.bib`, and the
package references nothing outside it.

### Verified build

The committed `main.pdf` was produced with:

```
TeX Live 2025 (pdfTeX 3.141592653-2.6-1.40.27) + BibTeX 0.99d
pdflatex -> bibtex -> pdflatex -> pdflatex
```

| Check | Result |
|---|---|
| Page count | 18 |
| `Overfull \hbox` / `Overfull \vbox` above 20pt | none (the build log contains no overfull or underfull box at all) |
| Undefined references or citations | none; no `??` anywhere in the output |
| Figures | all 12 vector figures included and referenced from the text |
| `latexmk`/`pdflatex` warnings | none |

`xelatex` and `tectonic` also work, but `pdflatex` is the reference build because the
package is written for it.

## Notes on the figures

The twelve PDFs in `figures/` are **byte-identical copies** of
`figures/vector/*.pdf` in the repository root; they are copied here so that the package is
self-contained for arXiv. The vector artwork carries its own in-image title band
("Figure N - ..." plus a "Headline number:" line), which would otherwise duplicate --- and
conflict with --- the LaTeX caption. `main.tex` therefore clips that band with
\`\\includegraphics[trim=0 0 0 <bp>,clip,width=...]\` at include time. The clipping happens in
the LaTeX source, **not** in the copied files: the figure PDFs themselves are unmodified.

Because the LaTeX figure numbers follow document order, they do not coincide with the
"Figure N" indices inside the original artwork. The mapping is:

| LaTeX figure | Source artwork | Subject |
|---:|---|---|
| 1 | `fig01_framework_attribution_matrix.pdf` | Framework attribution matrix |
| 2 | `fig09_evidence_rule_weights.pdf` | Evidence-rule weights and family conviction |
| 3 | `fig02_t1_signature_composition.pdf` | Tier-1 signature composition by request field |
| 4 | `fig08_rule_validation_real_traffic.pdf` | Rule validation on real traffic |
| 5 | `fig03_per_framework_detection_score.pdf` | Per-framework attribution score |
| 6 | `fig11_ai_actor_timeline.pdf` | The 15 AI agent attack segments |
| 7 | `fig04_threshold_tradeoff.pdf` | Threshold trade-off |
| 8 | `fig05_false_positive_breakdown.pdf` | False-positive breakdown |
| 9 | `fig07_leave_one_framework_out.pdf` | Leave-one-framework-out recall |
| 10 | `fig06_feature_family_ablation.pdf` | Feature-family ablation |
| 11 | `fig10_ai_agent_vs_scanner_behaviour.pdf` | AI agent versus scanner behaviour |
| 12 | `fig12_feature_family_profile.pdf` | Which feature families carry the decision |

Each figure block in `main.tex` also carries a `% source artwork: figures/...` comment.

## Submitting to arXiv

1. Create the upload archive from **inside this directory**:

   ```bash
   tar czf ai-agent-attack-signatures-paper.tar.gz \
       main.tex REFERENCES.bib main.pdf figures/
   ```

   `main.pdf` is included so that arXiv can compare its own compilation against it. The
   archive must **not** contain anything outside this directory: the paper references no file
   outside `paper/`.

2. Go to <https://arxiv.org/submit>, choose **Upload or switch your submission**, then
   **Submit a new paper**.

3. Under *Upload*, upload the tarball. arXiv detects `main.tex` as the root document.

4. Set the metadata:
   - *Primary subject class*: **cs.CR** (Cryptography and Security). Secondary option:
     **cs.AI**.
   - *Title*: "Attribution Limits of AI Pentest Agents: An Empirical Study of 65 Audited
     Codebases, 272 Validated Traffic Signatures, and the Boundary Where Attribution Stops
     Working".
   - *Abstract*: the contents of `../arxiv_abstract.txt` (it is the YAML front matter of that
     file, without the front-matter keys).
   - *Authors*: the contributors of the repository. Add the corresponding e-mail addresses;
     arXiv requires at least one.
   - *Comments*: "18 pages, 12 figures. Artefact: https://github.com/Raven-Gt/ai-agent-attack-signatures".

5. Check the arXiv-generated PDF against the committed `main.pdf`. They should match; if they
   do not, arXiv's TeX Live is older than the local one and the usual fix is to report the
   difference in the submission comments.

### Things arXiv may ask about

- **The figures are vector PDFs.** arXiv accepts PDF figures for submission; they are
  converted to their own storage format. Keep the PNG/SVG masters in `figures/vector/` in the
  repository if a raster version is ever needed.
- **The paper is self-contained.** It refers to no file outside `paper/` and states the
  artefact repository URL in the abstract page, in the introduction and in the conclusion.
- **The bibliography is generated with BibTeX** from `REFERENCES.bib` using the standard
  `plain` style. arXiv runs BibTeX itself; `main.bbl` is therefore not shipped.
- **Bibliography scope.** Only sources that this study actually used are cited: the public
  internet background-traffic corpus, the ModSecurity / OWASP Core Rule Set deployment that
  produced the WAF audit log, and the artefact repository itself. The 65 audited AI pentest
  frameworks are **not** given bibliographic entries, because no published paper was read for
  each of them; each is cited by upstream repository URL in `NOTICE` and carries per-signature
  provenance in `signatures/rules.json`. The paper states this explicitly in its References
  section.

## Regenerating the figures

The figures themselves are produced by the repository's own pipeline and are **not** part of
this package's build:

```bash
python figures/build_figures.py     # renders PNG + PDF + SVG into figures/ and figures/vector/
python figures/verify_figures.py     # size / blank / vector / ASCII checks
```

If the figures are regenerated, copy the new vector PDFs into `paper/figures/` and re-run the
build.

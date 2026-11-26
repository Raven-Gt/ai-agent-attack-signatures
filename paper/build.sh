#!/bin/sh
# Build the paper without make.
#
#   sh build.sh
#
# Override the engine with e.g.  LATEX=xelatex sh build.sh

set -e

cd "$(dirname "$0")"

LATEX="${LATEX:-pdflatex}"
BIBTEX="${BIBTEX:-bibtex}"

echo "==> $LATEX main.tex"
"$LATEX" -interaction=nonstopmode main.tex

echo "==> $BIBTEX main"
"$BIBTEX" main

echo "==> $LATEX main.tex (pass 2)"
"$LATEX" -interaction=nonstopmode main.tex

echo "==> $LATEX main.tex (pass 3)"
"$LATEX" -interaction=nonstopmode main.tex

echo "==> done: main.pdf"
ls -l main.pdf

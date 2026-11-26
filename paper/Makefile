# Makefile for the arXiv LaTeX package.
#
#   make            build main.pdf
#   make clean      remove the auxiliary files
#   make distclean  remove the auxiliary files and main.pdf
#
# Override the engine if needed, e.g.:  make LATEX=xelatex

LATEX ?= pdflatex
BIBTEX ?= bibtex

FIGURES := $(wildcard figures/*.pdf)
SOURCES := main.tex REFERENCES.bib

.PHONY: all clean distclean

all: main.pdf

main.pdf: $(SOURCES) $(FIGURES)
	$(LATEX) -interaction=nonstopmode main.tex
	$(BIBTEX) main
	$(LATEX) -interaction=nonstopmode main.tex
	$(LATEX) -interaction=nonstopmode main.tex

clean:
	rm -f main.aux main.bbl main.blg main.log main.out main.toc main.txt

distclean: clean
	rm -f main.pdf

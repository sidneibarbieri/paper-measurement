# Git-ready manifest

## Core manuscript
- `ACM CCS - Paper 2/main.tex`
- `ACM CCS - Paper 2/references_official_downloaded.bib`
- `ACM CCS - Paper 2/references.bib`
- `ACM CCS - Paper 2/figs/coverage_template.tex`
- `ACM CCS - Paper 2/figs/software_specificity_template.tex`
- `ACM CCS - Paper 2/figs/cve_location_template.tex`
- `ACM CCS - Paper 2/figs/jaccard_cdf_template.tex`

## Measurement software and data
- `measurement/sut/scripts/sut_measurement_pipeline.py`
- `measurement/sut/scripts/data/enterprise-attack.json`
- `measurement/sut/scripts/data/mobile-attack.json`
- `measurement/sut/scripts/data/ics-attack.json`
- `measurement/sut/scripts/results/todo_values.json`
- `measurement/sut/scripts/results/todo_values_latex.tex`
- `measurement/sut/scripts/results/figures_data.json`
- `measurement/sut/README.md`
- `measurement/sut/release_check.sh`

## Optional process docs
- `measurement/MEASUREMENT_DOD.md`
- `measurement/meta/*`

## Validation command
From repository root:

```bash
./measurement/sut/release_check.sh
```

Expected result: `PASS: pipeline + data + paper build are consistent`

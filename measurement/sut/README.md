# Measurement SUT Pipeline

This directory contains the measurement software and exported artifacts used by the SUT-focused study.

## Layout
- `scripts/sut_measurement_pipeline.py`: main pipeline
- `scripts/data/`: ATT&CK STIX bundles used by the run
- `scripts/results/todo_values.json`: canonical numeric outputs
- `scripts/results/figures_data.json`: figure payloads
- `scripts/results/audit/*.csv`: audit trails (campaign/software/CVE/compatibility/platform)

## Reproducibility
### Prerequisites
- Python 3.10+
- No external dependency required
- Optional: `numpy` (faster Jaccard computation)

### Run
```bash
cd "/Users/sidneibarbieri/paper measurement/measurement/sut/scripts"
python3 sut_measurement_pipeline.py
```

### Expected outputs
After a successful run, these files are regenerated:
- `results/todo_values.json`
- `results/todo_values_latex.tex`
- `results/figures_data.json`
- `results/audit/all_cves.csv`
- `results/audit/campaign_cves.csv`
- `results/audit/campaign_software.csv`
- `results/audit/campaign_platforms_software_only.csv`
- `results/audit/campaign_os_family_counts.csv`
- `results/audit/campaign_non_os_platform_counts.csv`
- `results/audit/campaign_platform_unknown.csv`
- `results/audit/is_cves.csv`
- `results/audit/is_software.csv`
- `results/audit/platform_distribution.csv`
- `results/audit/technique_compatibility.csv`

## Link to the manuscript
The LaTeX manuscript uses these outputs as the source of truth for reported values and figure data.
Reference note in manuscript:
- `ACM CCS - Paper 2/main.tex` lines around pipeline comments in Analysis section.

## Data integrity notes
- Deprecated/revoked ATT&CK objects are filtered in the pipeline.
- CVE extraction separates illustrative technique CVEs from actionable CVEs linked to campaign/software/intrusion-set evidence.
- Campaign-level exploited CVEs can be audited from `results/audit/campaign_cves.csv`.
- Campaign-level platform inference is software-only (`malware/tool` linked to campaign). Technique-level platforms are excluded from this step to avoid inflated campaign targeting claims.

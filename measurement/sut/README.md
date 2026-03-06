# Measurement SUT Pipeline

This directory contains the measurement software and exported artifacts used by the SUT-focused study.

## Layout
- `scripts/sut_measurement_pipeline.py`: main pipeline
- `scripts/data/`: STIX bundles used by the run
  - `enterprise-attack.json`
  - `mobile-attack.json`
  - `ics-attack.json`
  - `stix-capec.json`
  - `fight-enterprise-10.1.json`
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
python3 render_figures.py
python3 generate_traceability.py
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
- `results/audit/initial_access_campaigns.csv`
- `results/audit/initial_access_techniques.csv`
- `results/audit/profile_specificity_software_only.csv`
- `results/audit/profile_ablation_summary.csv`
- `results/audit/evidence_threshold_curve.csv`
- `results/audit/delta_sensitivity.csv`
- `results/audit/bootstrap_confusion_distribution.csv`
- `results/audit/platform_distribution.csv`
- `results/audit/technique_compatibility.csv`
- `ACM CCS - Paper 2/figs/coverage_template.tex`
- `ACM CCS - Paper 2/figs/software_specificity_template.tex`
- `ACM CCS - Paper 2/figs/cve_location_template.tex`
- `ACM CCS - Paper 2/figs/jaccard_cdf_template.tex`
- `measurement/sut/TRACEABILITY.md`

## Link to the manuscript
The LaTeX manuscript uses these outputs as the source of truth for reported values and figure data.
Reference note in manuscript:
- `ACM CCS - Paper 2/main.tex` lines around pipeline comments in Analysis section.

## Data integrity notes
- Deprecated/revoked ATT&CK objects are filtered in the pipeline.
- Cross-corpus coverage (Figure 1 metrics) is measured for Enterprise, Mobile, ICS, CAPEC, and FiGHT.
- CVE extraction separates illustrative technique CVEs from actionable CVEs linked to campaign/software/intrusion-set evidence.
- Campaign-level exploited CVEs can be audited from `results/audit/campaign_cves.csv`.
- Campaign-level platform inference is software-only (`malware/tool` linked to campaign). Technique-level platforms are excluded from this step to avoid inflated campaign targeting claims.

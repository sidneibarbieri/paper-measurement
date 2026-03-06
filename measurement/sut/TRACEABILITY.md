# Traceability Appendix

This file is auto-generated from measurement outputs.
Do not edit manually; run `python3 measurement/sut/scripts/generate_traceability.py`.

## Claim-to-Evidence Map

| Claim ID | Paper Anchor | Measured Value | Metric Key(s) | Evidence Artifact(s) |
|---|---|---|---|---|
| RQ1-P1 | Analysis: Platform Constraint Coverage | 691/691 (100.0%) | `enterprise_platform_count, enterprise_platform_pct` | `results/todo_values.json`, `results/audit/platform_distribution.csv` |
| RQ1-P2 | Analysis: Platform Constraint Coverage | 0 (0.0%) | `enterprise_system_requirements_count, enterprise_system_requirements_pct` | `results/todo_values.json` |
| RQ1-P3 | Figure 1 coverage by corpus | E=100.0 M=100.0 I=98.8 C=0.0 F=100.0 | `enterprise_platform_pct, mobile_platform_pct, ics_platform_percentage, capec_platform_percentage, fight_platform_percentage` | `results/figures_data.json`, `ACM CCS - Paper 2/figs/coverage_template.tex` |
| RQ1-S1 | Analysis: Software Reference Rate | campaigns 47/52 (90.4%), groups 158/172 (91.9%) | `enterprise_campaigns_with_software_count, enterprise_campaigns_with_software_percentage, enterprise_intrusion_sets_with_software_count, enterprise_intrusion_sets_with_software_percentage` | `results/todo_values.json`, `results/audit/campaign_software.csv`, `results/audit/is_software.csv` |
| RQ1-S2 | Analysis: Version/CPE specificity | version 2.4%, cpe 0.0% | `software_with_version_signal_percentage, software_with_cpe_percentage` | `results/todo_values.json`, `results/figures_data.json` |
| RQ1-C1 | Analysis: Vulnerability Reference Rate | unique=26 structured=21 free-text-only=5 (19.2%) | `cve_unique_count, cve_structured_count, cve_freetext_only_count, cve_from_freetext_pct` | `results/todo_values.json`, `results/audit/all_cves.csv`, `results/figures_data.json` |
| RQ1-C2 | Analysis: Campaign/IS CVE coverage | campaigns 5/52 (9.6%), groups 4/172 (2.3%) | `ent_campaigns_with_cve_count, ent_campaigns_with_cve_pct, ent_intrusion_sets_with_cve_count, ent_intrusion_sets_with_cve_pct` | `results/todo_values.json`, `results/audit/campaign_cves.csv`, `results/audit/is_cves.csv` |
| RQ1-C3 | Analysis: actionable vs illustrative CVEs | actionable=12 technique-only=14 campaign-linked=8 | `cve_actionable_count, cve_technique_only_count, campaign_linked_cve_count` | `results/todo_values.json`, `results/audit/campaign_cves.csv` |
| RQ2-K1 | Analysis: Compatibility table | CF=19 (2.7%), VMR=526 (76.1%), ID=146 (21.1%) | `compatibility_container_feasible_count, compatibility_vm_required_count, compatibility_infrastructure_dependent_count` | `results/todo_values.json`, `results/audit/technique_compatibility.csv` |
| RQ3-J1 | Analysis: Profile specificity | unique(sw)=90.7% unique(sw+cve)=90.7% confused=9.3% | `sut_profile_unique_software_percentage, sut_profile_unique_software_cve_percentage, sut_profile_confusion_software_cve_percentage` | `results/todo_values.json`, `results/figures_data.json`, `ACM CCS - Paper 2/figs/jaccard_cdf_template.tex` |
| AUX-OS1 | Analysis: Campaign OS-family table | Windows=42 Linux=23 macOS=21 | `campaign_os_windows_count, campaign_os_linux_count, campaign_os_macos_count` | `results/todo_values.json`, `results/audit/campaign_os_family_counts.csv` |
| AUX-OS2 | Analysis: Unknown-platform campaigns | 5 (9.6%) | `enterprise_campaigns_platform_unknown_count, enterprise_campaigns_platform_unknown_pct` | `results/todo_values.json`, `results/audit/campaign_platform_unknown.csv` |

## Reproduction Order

1. `python3 measurement/sut/scripts/sut_measurement_pipeline.py`
2. `python3 measurement/sut/scripts/render_figures.py`
3. `python3 measurement/sut/scripts/generate_traceability.py`
4. `./measurement/sut/release_check.sh`

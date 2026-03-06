#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/sidneibarbieri/paper measurement"
MEAS_SCRIPTS="$ROOT/measurement/sut/scripts"
PAPER_DIR="$ROOT/ACM CCS - Paper 2"

log() { printf '[release-check] %s\n' "$*"; }
fail() { printf '[release-check][FAIL] %s\n' "$*" >&2; exit 1; }

log "0) Verifying required input bundles"
required_inputs=(
  "data/enterprise-attack.json"
  "data/mobile-attack.json"
  "data/ics-attack.json"
  "data/stix-capec.json"
  "data/fight-enterprise-10.1.json"
)
for f in "${required_inputs[@]}"; do
  [[ -f "$MEAS_SCRIPTS/$f" ]] || fail "missing input bundle: $MEAS_SCRIPTS/$f"
done

log "1) Running measurement pipeline"
cd "$MEAS_SCRIPTS"
python3 sut_measurement_pipeline.py >/tmp/measurement_pipeline_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_pipeline_release.log >&2
  fail "pipeline execution failed"
}

log "1b) Rendering TikZ figures from measured outputs"
python3 render_figures.py >/tmp/measurement_render_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_render_release.log >&2
  fail "figure rendering failed"
}

log "1c) Generating traceability appendix"
python3 generate_traceability.py >/tmp/measurement_traceability_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_traceability_release.log >&2
  fail "traceability generation failed"
}

log "2) Checking required output artifacts"
required=(
  "results/todo_values.json"
  "results/todo_values_latex.tex"
  "results/figures_data.json"
  "results/audit/all_cves.csv"
  "results/audit/campaign_cves.csv"
  "results/audit/campaign_software.csv"
  "results/audit/campaign_platforms_software_only.csv"
  "results/audit/campaign_os_family_counts.csv"
  "results/audit/campaign_non_os_platform_counts.csv"
  "results/audit/campaign_platform_unknown.csv"
  "results/audit/is_cves.csv"
  "results/audit/is_software.csv"
  "results/audit/initial_access_campaigns.csv"
  "results/audit/initial_access_techniques.csv"
  "results/audit/profile_specificity_software_only.csv"
  "results/audit/profile_ablation_summary.csv"
  "results/audit/evidence_threshold_curve.csv"
  "results/audit/delta_sensitivity.csv"
  "results/audit/bootstrap_confusion_distribution.csv"
  "results/audit/platform_distribution.csv"
  "results/audit/technique_compatibility.csv"
)
for f in "${required[@]}"; do
  [[ -f "$f" ]] || fail "missing artifact: $MEAS_SCRIPTS/$f"
done

log "3) Validating key numeric invariants"
python3 - <<'PY'
import json, csv, sys
from pathlib import Path
base = Path('results')
with open(base/'todo_values.json') as f:
    d = json.load(f)

checks = []
checks.append((d['enterprise_platform_count'] == 691, 'enterprise_platform_count must be 691'))
checks.append((d['enterprise_campaigns_with_software_count'] == 47, 'campaigns_with_software_count must be 47'))
checks.append((d['enterprise_campaigns_with_platform_signal_count'] == 47, 'campaigns_with_platform_signal_count must be 47'))
checks.append((d['enterprise_campaigns_platform_unknown_count'] == 5, 'campaigns_platform_unknown_count must be 5'))
checks.append((d['ent_campaigns_with_cve_count'] == 5, 'campaigns_with_cve_count must be 5'))
checks.append((d['compatibility_container_feasible_count'] + d['compatibility_vm_required_count'] + d['compatibility_infrastructure_dependent_count'] == d['enterprise_platform_count'], 'CF+VMR+ID must equal enterprise_platform_count'))
checks.append((d['threshold_k_one_confusion_pct'] >= d['threshold_k_three_confusion_pct'], 'confusion should not increase from k>=1 to k>=3'))
checks.append((d['threshold_k_three_confusion_pct'] >= d['threshold_k_five_confusion_pct'], 'confusion should not increase from k>=3 to k>=5'))
checks.append((d['delta_zero_zero_five_confusion_pct'] <= d['delta_zero_ten_confusion_pct'], 'confusion should not decrease when delta goes 0.05 -> 0.10'))
checks.append((d['delta_zero_ten_confusion_pct'] <= d['delta_zero_fifteen_confusion_pct'], 'confusion should not decrease when delta goes 0.10 -> 0.15'))
checks.append((d['enterprise_campaigns_with_software_ci_low'] <= d['enterprise_campaigns_with_software_percentage'] <= d['enterprise_campaigns_with_software_ci_high'], 'campaign software CI must bound point estimate'))
checks.append((d['ent_campaigns_with_cve_ci_low'] <= d['ent_campaigns_with_cve_pct'] <= d['ent_campaigns_with_cve_ci_high'], 'campaign CVE CI must bound point estimate'))
checks.append((d['campaigns_with_initial_access_ci_low'] <= d['campaigns_with_initial_access_pct'] <= d['campaigns_with_initial_access_ci_high'], 'initial access CI must bound point estimate'))
checks.append((d['bootstrap_confusion_ci_low'] <= d['bootstrap_confusion_pct'] <= d['bootstrap_confusion_ci_high'], 'bootstrap confusion CI must bound point estimate'))
checks.append((d['bootstrap_unique_ci_low'] <= d['bootstrap_unique_pct'] <= d['bootstrap_unique_ci_high'], 'bootstrap unique CI must bound point estimate'))
checks.append((0.0 <= d['sut_profile_confusion_software_platform_percentage'] <= 100.0, 'software+platform confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_cve_platform_percentage'] <= 100.0, 'software+cve+platform confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_family_only_percentage'] <= 100.0, 'software+family confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_compat_percentage'] <= 100.0, 'software+compat confusion pct out of range'))
checks.append((d['capec_platform_percentage'] == 0.0, 'CAPEC platform percentage must be 0.0 for this bundle'))
checks.append((d['capec_software_link_pct'] == 0.0, 'CAPEC software-link percentage must be 0.0 for this bundle'))
checks.append((d['capec_cve_link_pct'] == 0.0, 'CAPEC CVE-link percentage must be 0.0 for this bundle'))

unknown_names = []
with open(base/'audit'/'campaign_platform_unknown.csv', newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    unknown_names = sorted(row['campaign_name'] for row in r if row.get('campaign_name'))
expected_unknown = sorted([
    'FrostyGoop Incident',
    'KV Botnet Activity',
    'Leviathan Australian Intrusions',
    'SPACEHOP Activity',
    'ShadowRay'
])
checks.append((unknown_names == expected_unknown, 'unknown campaign list mismatch'))

campaign_cve_map = {}
with open(base/'audit'/'campaign_cves.csv', newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    for row in r:
        try:
            if int(row.get('cve_count', '0')) > 0:
                cves = '; '.join(c.strip() for c in row.get('cves', '').split(';') if c.strip())
                campaign_cve_map[row['campaign_name']] = cves
        except ValueError:
            continue
expected_campaign_cve_map = {
    'APT28 Nearest Neighbor Campaign': 'CVE-2022-38028',
    'ShadowRay': 'CVE-2023-48022',
    'Operation MidnightEclipse': 'CVE-2024-3400',
    'Versa Director Zero Day Exploitation': 'CVE-2024-39717',
    'SharePoint ToolShell Exploitation': 'CVE-2025-49704; CVE-2025-49706; CVE-2025-53770; CVE-2025-53771',
}
checks.append((campaign_cve_map == expected_campaign_cve_map, 'campaign-linked CVE table source map mismatch'))

# Dataset table totals in main.tex are currently static and must stay aligned
# with local bundles used by the pipeline.
expected_bundle_totals = {
    'enterprise-attack.json': {'attack-pattern': 835, 'campaign': 52, 'intrusion-set': 187, 'malware': 696, 'tool': 91},
    'mobile-attack.json': {'attack-pattern': 190, 'campaign': 3, 'intrusion-set': 17, 'malware': 121, 'tool': 2},
    'ics-attack.json': {'attack-pattern': 95, 'campaign': 8, 'intrusion-set': 16, 'malware': 30, 'tool': 0},
    'stix-capec.json': {'attack-pattern': 615, 'campaign': 0, 'intrusion-set': 0, 'malware': 0, 'tool': 0},
    'fight-enterprise-10.1.json': {'attack-pattern': 707, 'campaign': 0, 'intrusion-set': 136, 'malware': 475, 'tool': 73},
}
for fname, exp in expected_bundle_totals.items():
    with open(Path('data')/fname, encoding='utf-8') as f:
        bundle = json.load(f).get('objects', [])
    counts = {'attack-pattern': 0, 'campaign': 0, 'intrusion-set': 0, 'malware': 0, 'tool': 0}
    for o in bundle:
        t = o.get('type')
        if t in counts:
            counts[t] += 1
    checks.append((counts == exp, f'bundle total count mismatch for {fname}: {counts} != {exp}'))

bad = [msg for ok, msg in checks if not ok]
if bad:
    for msg in bad:
        print('[release-check][FAIL]', msg)
    sys.exit(1)
print('[release-check] numeric invariants OK')
PY

log "3b) Validating static tables in manuscript against measured artifacts"
python3 - <<'PY'
import csv, re, sys
from pathlib import Path

main = Path('/Users/sidneibarbieri/paper measurement/ACM CCS - Paper 2/main.tex').read_text(encoding='utf-8')

required_dataset_rows = [
    r"Enterprise & 835 & 52  & 187 & 696 & 91 \\",
    r"Mobile     & 190 & 3   & 17  & 121 & 2  \\",
    r"ICS        & 95  & 8   & 16  & 30  & 0  \\",
    r"CAPEC      & 615 & 0   & 0   & 0   & 0 \\",
    r"FiGHT      & 707 & 0   & 136 & 475 & 73 \\",
]
for row in required_dataset_rows:
    if row not in main:
        print(f"[release-check][FAIL] dataset table row missing/mismatched: {row}")
        sys.exit(1)

expected = {}
with open('/Users/sidneibarbieri/paper measurement/measurement/sut/scripts/results/audit/campaign_cves.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if int(row.get('cve_count','0')) > 0:
            cves = '; '.join(x.strip() for x in row['cves'].split(';') if x.strip())
            expected[row['campaign_name']] = cves

for name, cves in expected.items():
    latex_row = f"{name} & {cves} \\\\"
    if latex_row not in main:
        print(f"[release-check][FAIL] campaign CVE row missing/mismatched in main.tex: {latex_row}")
        sys.exit(1)

print('[release-check] static table checks OK')
PY

log "4) Building manuscript PDF"
cd "$PAPER_DIR"
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex >/tmp/measurement_paper_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_paper_release.log >&2
  fail "latex build failed"
}

log "5) Ensuring no active TODO placeholders in manuscript body"
# Ignore macro definition line; fail if TODO/TBD markers appear elsewhere.
if rg -n 'TODO\{|\[TBD\]' main.tex | rg -v '^87:' >/tmp/measurement_todo_hits.log; then
  cat /tmp/measurement_todo_hits.log >&2
  fail "found unresolved TODO/TBD markers"
fi

log "6) Ensuring manuscript imports generated measurement macros"
rg -n '\\input\{../measurement/sut/scripts/results/todo_values_latex.tex\}' main.tex >/dev/null || \
  fail "main.tex is not importing generated todo_values_latex.tex"

log "6b) Ensuring rendered ablation figure template exists"
[[ -f "$ROOT/ACM CCS - Paper 2/figs/ablation_template.tex" ]] || fail "missing ablation_template.tex"

log "7) Ensuring traceability appendix exists"
[[ -f "$ROOT/measurement/sut/TRACEABILITY.md" ]] || fail "missing TRACEABILITY.md"

log "PASS: pipeline + data + paper build are consistent"

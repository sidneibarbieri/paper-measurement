#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/sidneibarbieri/paper measurement"
MEAS_SCRIPTS="$ROOT/measurement/sut/scripts"
PAPER_DIR="$ROOT/ACM CCS - Paper 2"

log() { printf '[release-check] %s\n' "$*"; }
fail() { printf '[release-check][FAIL] %s\n' "$*" >&2; exit 1; }

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
  "results/audit/evidence_threshold_curve.csv"
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

bad = [msg for ok, msg in checks if not ok]
if bad:
    for msg in bad:
        print('[release-check][FAIL]', msg)
    sys.exit(1)
print('[release-check] numeric invariants OK')
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

log "7) Ensuring traceability appendix exists"
[[ -f "$ROOT/measurement/sut/TRACEABILITY.md" ]] || fail "missing TRACEABILITY.md"

log "PASS: pipeline + data + paper build are consistent"

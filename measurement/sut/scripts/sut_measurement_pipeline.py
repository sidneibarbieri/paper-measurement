#!/usr/bin/env python3
"""
SUT Measurement Pipeline:
"Measuring System Under Test Requirements for APT Emulation Using MITRE ATT&CK"

Generates all TODO placeholder values for the Analysis section.
Reads STIX 2.x bundles (JSON) directly — no external STIX libraries needed.

Usage:
    python3 sut_measurement_pipeline.py

Output:
    - results/todo_values.json          — all 28+ TODO values
    - results/todo_values_latex.tex     — LaTeX \newcommand definitions
    - results/figures_data.json         — data for TikZ figures
    - results/audit/                    — per-technique, per-campaign CSVs for audit

Authors: Roth, Barbieri, Evangelista, Pereira Jr.
Date: 2026-03-05
Bundle version: ATT&CK v18.1 (Enterprise)
"""

import json
import os
import re
import csv
import sys
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

# Optional: numpy/scipy for Jaccard (fallback to pure Python)
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("[WARN] numpy not found; using pure-Python Jaccard. Install with: pip3 install numpy")

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
RESULTS_DIR = SCRIPT_DIR / "results"
AUDIT_DIR = RESULTS_DIR / "audit"

ENTERPRISE_FILE = DATA_DIR / "enterprise-attack.json"
MOBILE_FILE = DATA_DIR / "mobile-attack.json"
ICS_FILE = DATA_DIR / "ics-attack.json"
CAPEC_FILE = DATA_DIR / "stix-capec.json"
FIGHT_FILE = DATA_DIR / "fight-enterprise-10.1.json"

# Fixed denominators (from paper methodology)
ENTERPRISE_TECHNIQUES = 835
USABLE_CAMPAIGNS = 52          # ATT&CK v18.1 active campaigns with current filters
INTRUSION_SETS = 187
EXCLUDED_CAMPAIGN_ID = None    # Will be identified dynamically

# Jaccard threshold for SUT profile confusion
JACCARD_DELTA = 0.1

# CVE regex pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────

def load_bundle(filepath):
    """Load a STIX 2.x bundle from JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    return bundle['objects']


def is_deprecated_or_revoked(obj):
    """Check if a STIX object is deprecated or revoked."""
    return obj.get('x_mitre_deprecated', False) or obj.get('revoked', False)


def index_objects_by_type(objects):
    """Index all STIX objects by type, excluding deprecated/revoked."""
    by_type = defaultdict(list)
    by_id = {}
    for obj in objects:
        if is_deprecated_or_revoked(obj):
            continue
        obj_type = obj.get('type', '')
        by_type[obj_type].append(obj)
        by_id[obj.get('id', '')] = obj
    return by_type, by_id


def build_relationship_index(relationships):
    """Build indices for relationship traversal."""
    # Forward: source_ref → [(relationship_type, target_ref)]
    # Reverse: target_ref → [(relationship_type, source_ref)]
    fwd = defaultdict(list)
    rev = defaultdict(list)
    by_type = defaultdict(list)
    for rel in relationships:
        src = rel.get('source_ref', '')
        tgt = rel.get('target_ref', '')
        rtype = rel.get('relationship_type', '')
        fwd[src].append((rtype, tgt, rel))
        rev[tgt].append((rtype, src, rel))
        by_type[rtype].append(rel)
    return fwd, rev, by_type


def pct(count, total, decimals=1):
    """Compute percentage with rounding."""
    if total == 0:
        return 0.0
    val = (count / total) * 100
    if val < 1.0 and val > 0:
        return round(val, 2)  # More precision for < 1%
    return round(val, decimals)


def proportion_ci_wilson(count, total, z=1.96):
    """
    Wilson score interval (95% default) for binomial proportions, in percent.
    """
    if total <= 0:
        return (0.0, 0.0)
    p = count / total
    denom = 1 + (z * z) / total
    center = (p + (z * z) / (2 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1 - p) / total) + ((z * z) / (4 * total * total)))
    low = max(0.0, (center - margin) * 100)
    high = min(100.0, (center + margin) * 100)
    return (round(low, 1), round(high, 1))


def normalize_os_family(platform_label):
    """
    Map ATT&CK platform labels to coarse OS families.
    Returns one of: Windows, Linux, macOS, iOS, Android, BSD, ESXi, or None.
    """
    p = (platform_label or '').strip().lower()
    if not p:
        return None
    if 'windows' in p:
        return 'Windows'
    if 'linux' in p:
        return 'Linux'
    if 'macos' in p or 'mac os' in p:
        return 'macOS'
    if p == 'ios' or 'ios' in p:
        return 'iOS'
    if 'android' in p:
        return 'Android'
    if 'bsd' in p:
        return 'BSD'
    if 'esxi' in p:
        return 'ESXi'
    return None


# ─────────────────────────────────────────────────────────────────
# 1. Platform Coverage Analysis
# ─────────────────────────────────────────────────────────────────

def analyze_platform_coverage(techniques):
    """
    RQ1: Compute platform coverage metrics.
    Returns: (platform_count, platform_pct, sysreq_count, sysreq_pct)
    """
    total = len(techniques)
    with_platform = 0
    with_sys_req = 0
    platform_counts = Counter()

    for tech in techniques:
        platforms = tech.get('x_mitre_platforms', [])
        sys_reqs = tech.get('x_mitre_system_requirements', [])

        if platforms:
            with_platform += 1
            for p in platforms:
                platform_counts[p] += 1

        if sys_reqs:
            with_sys_req += 1

    return {
        'total_techniques': total,
        'with_platform': with_platform,
        'platform_pct': pct(with_platform, total),
        'with_system_requirements': with_sys_req,
        'system_requirements_pct': pct(with_sys_req, total),
        'platform_distribution': dict(platform_counts.most_common()),
    }


def analyze_domain_bundle(filepath, domain_name):
    """
    Analyze one bundle for Figure 1 metrics:
      - platform coverage over active attack-pattern objects
      - software-link coverage over active attack-pattern objects
      - CVE-link coverage over active attack-pattern objects
    """
    objects = load_bundle(filepath)
    by_type, by_id = index_objects_by_type(objects)
    relationships = by_type.get('relationship', [])
    rel_fwd, rel_rev, _ = build_relationship_index(relationships)

    techniques = by_type.get('attack-pattern', [])
    total = len(techniques)
    with_platform = sum(1 for t in techniques if t.get('x_mitre_platforms'))
    sw_link_pct = compute_software_link_rate(by_type, rel_fwd, rel_rev)
    cve_link_pct = compute_cve_link_rate_for_techniques(techniques)

    return {
        'domain': domain_name,
        'total_techniques': total,
        'with_platform': with_platform,
        'platform_pct': pct(with_platform, total),
        'software_link_pct': sw_link_pct,
        'cve_link_pct': cve_link_pct,
        'num_relationships': len(relationships),
        'num_software': len(by_type.get('malware', [])) + len(by_type.get('tool', [])),
        'num_intrusion_sets': len(by_type.get('intrusion-set', [])),
        'num_campaigns': len(by_type.get('campaign', [])),
    }


# ─────────────────────────────────────────────────────────────────
# 2. Software Reference Analysis
# ─────────────────────────────────────────────────────────────────

def analyze_software_references(campaigns, intrusion_sets, software_objects,
                                rel_fwd, rel_rev, by_id, excluded_campaign_ids):
    """
    RQ1/RQ2: Software reference rate for campaigns and intrusion sets.
    Also measures version signal and CPE presence in software objects.
    """
    # Software IDs (malware + tool)
    software_ids = set(s['id'] for s in software_objects)
    software_by_id = {s['id']: s for s in software_objects}

    # --- Campaigns with software ---
    campaigns_with_software = 0
    campaign_software_details = []
    campaigns_with_platform_signal = 0
    campaigns_unknown_platform = 0
    campaign_platform_details = []
    campaign_os_family_counts = Counter()
    campaign_non_os_platform_counts = Counter()
    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]

    for camp in usable_campaigns:
        camp_id = camp['id']
        linked_software = set()
        # Direct: campaign -uses-> software
        for rtype, tgt, _ in rel_fwd.get(camp_id, []):
            if rtype == 'uses' and tgt in software_ids:
                linked_software.add(tgt)
        # Also check reverse: software -uses-> campaign (less common but possible)
        for rtype, src, _ in rel_rev.get(camp_id, []):
            if rtype == 'uses' and src in software_ids:
                linked_software.add(src)

        has_software = len(linked_software) > 0
        if has_software:
            campaigns_with_software += 1

        # Campaign-level platform inference from linked software only.
        raw_platforms = set()
        for sw_id in linked_software:
            sw_obj = software_by_id.get(sw_id, {})
            for p in sw_obj.get('x_mitre_platforms', []) or []:
                raw_platforms.add(p)

        os_families = set()
        non_os_platforms = set()
        for p in raw_platforms:
            fam = normalize_os_family(p)
            if fam is None:
                non_os_platforms.add(p)
            else:
                os_families.add(fam)

        platform_signal = len(raw_platforms) > 0
        if platform_signal:
            campaigns_with_platform_signal += 1
            for fam in os_families:
                campaign_os_family_counts[fam] += 1
            for p in non_os_platforms:
                campaign_non_os_platform_counts[p] += 1
        else:
            campaigns_unknown_platform += 1

        unknown_reason = ''
        if not platform_signal:
            if has_software:
                unknown_reason = 'linked_software_without_platform'
            else:
                unknown_reason = 'no_linked_software'

        campaign_software_details.append({
            'campaign_name': camp.get('name', 'unknown'),
            'campaign_id': camp_id,
            'software_count': len(linked_software),
            'software_ids': list(linked_software),
        })
        campaign_platform_details.append({
            'campaign_name': camp.get('name', 'unknown'),
            'campaign_id': camp_id,
            'software_count': len(linked_software),
            'platform_signal': platform_signal,
            'os_families': sorted(os_families),
            'raw_platforms': sorted(raw_platforms),
            'non_os_platforms': sorted(non_os_platforms),
            'unknown_reason': unknown_reason,
        })

    # --- Intrusion sets with software ---
    is_with_software = 0
    is_software_details = []

    for iset in intrusion_sets:
        is_id = iset['id']
        linked_software = set()
        for rtype, tgt, _ in rel_fwd.get(is_id, []):
            if rtype == 'uses' and tgt in software_ids:
                linked_software.add(tgt)
        for rtype, src, _ in rel_rev.get(is_id, []):
            if rtype == 'uses' and src in software_ids:
                linked_software.add(src)

        has_software = len(linked_software) > 0
        if has_software:
            is_with_software += 1
        is_software_details.append({
            'is_name': iset.get('name', 'unknown'),
            'is_id': is_id,
            'software_count': len(linked_software),
        })

    # --- Version signal and CPE in software objects ---
    # Version signal: any version-like pattern in name, aliases, or external_references
    version_pattern = re.compile(
        r'(?:v?\d+\.\d+|\bversion\s+\d+|\b\d+\.\d+\.\d+)',
        re.IGNORECASE
    )

    software_with_version = 0
    software_with_cpe = 0
    total_software = len(software_objects)

    for sw in software_objects:
        # Check version signal
        name = sw.get('name', '')
        aliases = sw.get('aliases', []) or []
        ext_refs = sw.get('external_references', []) or []

        has_version = False
        has_cpe = False

        # Check name
        if version_pattern.search(name):
            has_version = True

        # Check aliases
        for alias in aliases:
            if version_pattern.search(alias):
                has_version = True
                break

        # Check external_references
        for ref in ext_refs:
            ref_str = json.dumps(ref)
            if version_pattern.search(ref_str):
                has_version = True
            if 'cpe:' in ref_str.lower() or ref.get('source_name', '').lower() == 'cpe':
                has_cpe = True

        if has_version:
            software_with_version += 1
        if has_cpe:
            software_with_cpe += 1

    n_usable = len(usable_campaigns)
    return {
        'campaigns_with_software': campaigns_with_software,
        'campaigns_with_software_pct': pct(campaigns_with_software, n_usable),
        'campaigns_with_platform_signal': campaigns_with_platform_signal,
        'campaigns_with_platform_signal_pct': pct(campaigns_with_platform_signal, n_usable),
        'campaigns_unknown_platform': campaigns_unknown_platform,
        'campaigns_unknown_platform_pct': pct(campaigns_unknown_platform, n_usable),
        'total_usable_campaigns': n_usable,
        'is_with_software': is_with_software,
        'is_with_software_pct': pct(is_with_software, len(intrusion_sets)),
        'total_intrusion_sets': len(intrusion_sets),
        'total_software': total_software,
        'software_with_version': software_with_version,
        'software_with_version_pct': pct(software_with_version, total_software),
        'software_with_cpe': software_with_cpe,
        'software_with_cpe_pct': pct(software_with_cpe, total_software),
        'campaign_details': campaign_software_details,
        'campaign_platform_details': campaign_platform_details,
        'campaign_unknown_platform_names': sorted(
            row['campaign_name'] for row in campaign_platform_details if not row['platform_signal']
        ),
        'campaign_os_family_counts': dict(campaign_os_family_counts.most_common()),
        'campaign_non_os_platform_counts': dict(campaign_non_os_platform_counts.most_common()),
        'is_details': is_software_details,
    }


# ─────────────────────────────────────────────────────────────────
# 3. CVE / Vulnerability Analysis
# ─────────────────────────────────────────────────────────────────

def extract_cves_from_object(obj):
    """Extract all CVE identifiers from an object's text fields and references."""
    cves_structured = set()
    cves_freetext = set()

    # Check external_references for structured CVEs
    for ref in obj.get('external_references', []) or []:
        source = ref.get('source_name', '').lower()
        ext_id = ref.get('external_id', '')
        url = ref.get('url', '')

        if source == 'cve' or CVE_PATTERN.match(ext_id):
            match = CVE_PATTERN.search(ext_id)
            if match:
                cves_structured.add(match.group().upper())
        # Also check URL for CVE references
        if url:
            for m in CVE_PATTERN.finditer(url):
                cves_structured.add(m.group().upper())

    # Check description for free-text CVEs
    desc = obj.get('description', '')
    if desc:
        for m in CVE_PATTERN.finditer(desc):
            cve_id = m.group().upper()
            if cve_id not in cves_structured:
                cves_freetext.add(cve_id)

    return cves_structured, cves_freetext


def analyze_vulnerability_references(campaigns, intrusion_sets, software_objects,
                                      techniques, vulnerability_objects,
                                      rel_fwd, rel_rev, by_id, excluded_campaign_ids):
    """
    RQ1/RQ2: Vulnerability reference rate.
    Extract CVEs from structured fields and free text.
    """
    # Collect all CVEs across entire bundle
    all_cves_structured = set()
    all_cves_freetext = set()

    # Track CVEs by source type for the paper's CVE location figure
    cves_from_techniques = set()   # Illustrative examples in technique descriptions
    cves_from_software = set()     # From malware/tool objects (actionable)
    cves_from_campaigns = set()    # Direct campaign associations
    cves_from_is = set()           # Direct IS associations

    # Scan techniques (these are illustrative examples, noted separately)
    for obj in techniques:
        s, f = extract_cves_from_object(obj)
        cves_from_techniques.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan software objects (actionable CVEs)
    for obj in software_objects:
        s, f = extract_cves_from_object(obj)
        cves_from_software.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan campaigns
    for obj in campaigns:
        s, f = extract_cves_from_object(obj)
        cves_from_campaigns.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan intrusion sets
    for obj in intrusion_sets:
        s, f = extract_cves_from_object(obj)
        cves_from_is.update(s | f)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan vulnerability objects
    for obj in vulnerability_objects:
        s, f = extract_cves_from_object(obj)
        all_cves_structured.update(s)
        all_cves_freetext.update(f)

    # Scan relationship descriptions for CVEs
    # (relationships are not indexed by type in by_type due to separate processing)

    all_cves = all_cves_structured | all_cves_freetext
    only_freetext = all_cves_freetext - all_cves_structured

    # Actionable CVEs: those NOT only from technique examples
    actionable_cves = (cves_from_software | cves_from_campaigns | cves_from_is)
    technique_only_cves = cves_from_techniques - actionable_cves

    # --- Campaigns with CVE ---
    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]
    campaigns_with_cve = 0
    campaign_cve_details = []

    for camp in usable_campaigns:
        camp_cves = set()
        # Direct CVEs in campaign object
        s, f = extract_cves_from_object(camp)
        camp_cves.update(s | f)

        # CVEs from linked software (malware/tool objects)
        # NOTE: We intentionally exclude CVEs from technique descriptions.
        # Technique descriptions mention CVEs as illustrative examples
        # (e.g., "Exploit Public-Facing Application" cites CVE-2016-6662
        # as a generic example), NOT as campaign-specific vulnerability usage.
        # Including them would inflate campaign CVE counts artificially.
        for rtype, tgt, _ in rel_fwd.get(camp['id'], []):
            if rtype == 'uses' and tgt in by_id:
                target_obj = by_id[tgt]
                if target_obj.get('type') in ('malware', 'tool'):
                    s2, f2 = extract_cves_from_object(target_obj)
                    camp_cves.update(s2 | f2)

        if camp_cves:
            campaigns_with_cve += 1
        campaign_cve_details.append({
            'campaign_name': camp.get('name', ''),
            'cve_count': len(camp_cves),
            'cves': sorted(camp_cves),
        })

    # --- Intrusion sets with CVE ---
    is_with_cve = 0
    is_cve_details = []

    for iset in intrusion_sets:
        is_cves = set()
        s, f = extract_cves_from_object(iset)
        is_cves.update(s | f)

        # CVEs from linked software (not techniques — see campaign note above)
        for rtype, tgt, _ in rel_fwd.get(iset['id'], []):
            if rtype == 'uses' and tgt in by_id:
                target_obj = by_id[tgt]
                if target_obj.get('type') in ('malware', 'tool'):
                    s2, f2 = extract_cves_from_object(target_obj)
                    is_cves.update(s2 | f2)

        if is_cves:
            is_with_cve += 1
        is_cve_details.append({
            'is_name': iset.get('name', ''),
            'cve_count': len(is_cves),
            'cves': sorted(is_cves),
        })

    n_usable = len(usable_campaigns)

    # For the paper: cve_unique_count reports ALL CVEs found in the bundle.
    # cve_from_freetext_pct reports the fraction found ONLY in descriptions.
    # We also provide actionable_cve_count (excluding technique-example CVEs)
    # for the narrative that distinguishes actionable vs illustrative CVE refs.
    return {
        'cve_unique_count': len(all_cves),
        'cve_structured_count': len(all_cves_structured),
        'cve_freetext_only_count': len(only_freetext),
        'cve_from_freetext_pct': pct(len(only_freetext), len(all_cves)) if all_cves else 0,
        'actionable_cve_count': len(actionable_cves),
        'technique_only_cve_count': len(technique_only_cves),
        'cves_from_techniques': sorted(cves_from_techniques),
        'cves_from_software': sorted(cves_from_software),
        'cves_from_campaigns': sorted(cves_from_campaigns),
        'cves_from_is': sorted(cves_from_is),
        'campaigns_with_cve': campaigns_with_cve,
        'campaigns_with_cve_pct': pct(campaigns_with_cve, n_usable),
        'is_with_cve': is_with_cve,
        'is_with_cve_pct': pct(is_with_cve, len(intrusion_sets)),
        'all_cves': sorted(all_cves),
        'structured_cves': sorted(all_cves_structured),
        'freetext_only_cves': sorted(only_freetext),
        'actionable_cves': sorted(actionable_cves),
        'campaign_cve_details': campaign_cve_details,
        'is_cve_details': is_cve_details,
    }


# ─────────────────────────────────────────────────────────────────
# 4. Initial Access Analysis
# ─────────────────────────────────────────────────────────────────

def get_attack_external_id(obj):
    """Return ATT&CK external technique ID (e.g., T1566.001) when available."""
    for ref in obj.get('external_references', []) or []:
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id', '')
    return ''


def analyze_initial_access(campaigns, techniques, rel_fwd, cve_results, excluded_campaign_ids):
    """
    Initial Access focused analysis:
      - campaigns using at least one Initial Access technique
      - social-interaction proxy via phishing/trusted-relationship techniques
      - overlap with campaign-level CVE evidence
    """
    # Initial Access technique set
    initial_access_ids = set()
    ext_id_by_tech = {}
    tech_name_by_id = {}
    for tech in techniques:
        tech_id = tech['id']
        ext_id_by_tech[tech_id] = get_attack_external_id(tech)
        tech_name_by_id[tech_id] = tech.get('name', '')
        for phase in tech.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack' and phase.get('phase_name') == 'initial-access':
                initial_access_ids.add(tech_id)
                break

    # Conservative social-interaction proxy:
    # - Phishing family (T1566.*)
    # - Trusted Relationship (T1199)
    social_proxy_ids = set()
    for tid in initial_access_ids:
        ext = ext_id_by_tech.get(tid, '')
        if ext.startswith('T1566') or ext == 'T1199':
            social_proxy_ids.add(tid)

    usable_campaigns = [c for c in campaigns if c['id'] not in excluded_campaign_ids]
    n_campaigns = len(usable_campaigns)

    # Map campaign name -> CVE count from existing vulnerability analysis.
    campaign_cve_count = {}
    for row in cve_results.get('campaign_cve_details', []):
        campaign_cve_count[row['campaign_name']] = int(row.get('cve_count', 0))

    campaigns_with_ia = 0
    campaigns_with_social_proxy = 0
    campaigns_with_ia_and_cve = 0
    campaign_rows = []
    ia_technique_counter = Counter()

    for camp in usable_campaigns:
        cid = camp['id']
        cname = camp.get('name', '')
        ia_tids = set()
        for rtype, tgt, _ in rel_fwd.get(cid, []):
            if rtype == 'uses' and tgt in initial_access_ids:
                ia_tids.add(tgt)

        has_ia = len(ia_tids) > 0
        has_social_proxy = len(ia_tids & social_proxy_ids) > 0
        cve_count = campaign_cve_count.get(cname, 0)
        has_cve = cve_count > 0

        if has_ia:
            campaigns_with_ia += 1
            for tid in ia_tids:
                ia_technique_counter[tech_name_by_id.get(tid, tid)] += 1
        if has_social_proxy:
            campaigns_with_social_proxy += 1
        if has_ia and has_cve:
            campaigns_with_ia_and_cve += 1

        campaign_rows.append({
            'campaign_name': cname,
            'campaign_id': cid,
            'has_initial_access': has_ia,
            'has_social_proxy': has_social_proxy,
            'campaign_cve_count': cve_count,
            'initial_access_technique_count': len(ia_tids),
            'initial_access_techniques': sorted(
                f"{ext_id_by_tech.get(tid, '')}:{tech_name_by_id.get(tid, tid)}"
                for tid in ia_tids
            ),
        })

    return {
        'initial_access_technique_count': len(initial_access_ids),
        'social_proxy_technique_count': len(social_proxy_ids),
        'campaigns_with_initial_access_count': campaigns_with_ia,
        'campaigns_with_initial_access_pct': pct(campaigns_with_ia, n_campaigns),
        'campaigns_with_social_initial_access_count': campaigns_with_social_proxy,
        'campaigns_with_social_initial_access_pct': pct(campaigns_with_social_proxy, n_campaigns),
        'campaigns_with_initial_access_and_cve_count': campaigns_with_ia_and_cve,
        'campaigns_with_initial_access_and_cve_pct': pct(campaigns_with_ia_and_cve, n_campaigns),
        'campaigns_with_initial_access_no_cve_count': campaigns_with_ia - campaigns_with_ia_and_cve,
        'campaigns_with_initial_access_no_cve_pct': pct(campaigns_with_ia - campaigns_with_ia_and_cve, n_campaigns),
        'top_initial_access_techniques': ia_technique_counter.most_common(),
        'campaign_rows': campaign_rows,
    }


# ─────────────────────────────────────────────────────────────────
# 5. SUT Compatibility Classification
# ─────────────────────────────────────────────────────────────────

# Tactic IDs that map to specific clusters
# These are based on MITRE ATT&CK Enterprise tactic x_mitre_shortname
LATERAL_MOVEMENT_TACTICS = {'lateral-movement'}
PRIVILEGE_ESCALATION_TACTICS = {'privilege-escalation'}
DEFENSE_EVASION_TACTICS = {'defense-evasion'}

# Keywords for infrastructure-dependent techniques
ID_PLATFORM_KEYWORDS = {
    'Windows Domain', 'Azure AD', 'Google Workspace',
    'Office 365', 'SaaS', 'IaaS', 'Identity Provider',
    'Entra ID',
}

# Keywords in technique name/description for kernel/boot interaction
KERNEL_BOOT_KEYWORDS = re.compile(
    r'boot|firmware|kernel|driver|rootkit|bios|uefi|mbr|vbr|bootkit',
    re.IGNORECASE
)

# Permissions indicating VMR
VMR_PERMISSIONS = {'Administrator', 'SYSTEM', 'root'}


def get_technique_tactics(technique, tactic_objects):
    """Get tactic shortnames for a technique via kill_chain_phases."""
    tactics = set()
    for phase in technique.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.add(phase.get('phase_name', ''))
    return tactics


def classify_technique_compatibility(technique, rel_fwd, by_id):
    """
    Classify a technique as CF, VMR, or ID.
    Rules (in order of precedence, matching paper methodology):
    1. If platforms include domain/identity/SaaS keywords → ID
    2. If kernel/boot keywords in name or is in priv-esc/defense-evasion boot cluster → VMR
    3. If permissions include Admin/SYSTEM/root → VMR
    4. If platforms are only Containers or Linux (user-space) → CF
    5. Default → VMR
    """
    platforms = set(technique.get('x_mitre_platforms', []))
    permissions = set(technique.get('x_mitre_permissions_required', []) or [])
    name = technique.get('name', '')
    description = technique.get('description', '')
    tactics = set()
    for phase in technique.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.add(phase.get('phase_name', ''))

    # Rule 3 (check first for ID): Infrastructure-dependent
    # Lateral Movement with AD/domain dependency
    if platforms & ID_PLATFORM_KEYWORDS:
        return 'ID'

    # Check if it's Lateral Movement with software dependency on AD
    if 'lateral-movement' in tactics:
        # Check linked software for AD-related tools
        tech_id = technique['id']
        for rtype, tgt, _ in rel_fwd.get(tech_id, []):
            if rtype == 'uses' and tgt in by_id:
                sw = by_id[tgt]
                sw_name = sw.get('name', '').lower()
                if any(kw in sw_name for kw in ['active directory', 'kerberos', 'ldap', 'domain']):
                    return 'ID'
        # Lateral Movement techniques generally need multi-host → ID
        # But some may be CF/VMR depending on platform
        # Conservative: if lateral movement, default to ID
        return 'ID'

    # Rule 2: VM-required
    # Kernel/boot keywords
    if KERNEL_BOOT_KEYWORDS.search(name) or KERNEL_BOOT_KEYWORDS.search(description[:200]):
        return 'VMR'

    # Privilege escalation with elevated permissions
    if permissions & VMR_PERMISSIONS:
        return 'VMR'

    # Process injection, hooking (common VMR patterns)
    vmr_name_patterns = re.compile(
        r'process\s+inject|hook|dll\s+side|hijack|token\s+manipul|'
        r'access\s+token|credential\s+dump|lsass|sam\s+database|'
        r'registry|service\s+execut|scheduled\s+task|'
        r'windows\s+management\s+instrument|wmi|'
        r'exploitation\s+for\s+privilege',
        re.IGNORECASE
    )
    if vmr_name_patterns.search(name):
        return 'VMR'

    # Rule 1: Container-feasible
    # Only if platforms are limited to container-compatible ones
    container_compatible = {'Containers', 'Linux'}
    if platforms and platforms.issubset(container_compatible):
        # But check for kernel interaction
        if 'privilege-escalation' in tactics or 'defense-evasion' in tactics:
            # Even on Linux, priv-esc often needs kernel → VMR
            if permissions & VMR_PERMISSIONS:
                return 'VMR'
        return 'CF'

    # Rule 4: Default → VMR
    return 'VMR'


def analyze_compatibility(techniques, rel_fwd, by_id):
    """
    RQ2: Classify all techniques into CF/VMR/ID.
    """
    classification = {'CF': [], 'VMR': [], 'ID': []}

    for tech in techniques:
        cls = classify_technique_compatibility(tech, rel_fwd, by_id)
        classification[cls].append({
            'id': tech['id'],
            'name': tech.get('name', ''),
            'platforms': tech.get('x_mitre_platforms', []),
            'permissions': tech.get('x_mitre_permissions_required', []),
            'class': cls,
        })

    total = len(techniques)
    return {
        'cf_count': len(classification['CF']),
        'cf_pct': pct(len(classification['CF']), total),
        'vmr_count': len(classification['VMR']),
        'vmr_pct': pct(len(classification['VMR']), total),
        'id_count': len(classification['ID']),
        'id_pct': pct(len(classification['ID']), total),
        'total': total,
        'details': classification,
    }


# ─────────────────────────────────────────────────────────────────
# 6. SUT Profile Specificity (Jaccard)
# ─────────────────────────────────────────────────────────────────

def build_sut_profiles(
    intrusion_sets, software_objects, rel_fwd, by_id,
    include_cve=False, platform_mode='none',
    include_compat_summary=False, compatibility_by_technique=None
):
    """
    Build binary SUT profile vectors for each intrusion set.
    Profile = set of software IDs (+ optionally CVE IDs, platform labels, compatibility summaries) linked to the IS.
    platform_mode: 'none' | 'raw' | 'family'
    """
    software_ids = set(s['id'] for s in software_objects)

    # Build universe of all possible features
    all_features = set()
    profiles = {}

    for iset in intrusion_sets:
        is_id = iset['id']
        profile = set()

        # Software linked to IS
        for rtype, tgt, _ in rel_fwd.get(is_id, []):
            if rtype == 'uses' and tgt in software_ids:
                profile.add(tgt)
                all_features.add(tgt)

        # Optionally add CVEs
        if include_cve:
            # Direct CVEs
            _, f = extract_cves_from_object(iset)
            s, _ = extract_cves_from_object(iset)
            cves = s | f

            # CVEs from linked software
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') in ('malware', 'tool'):
                        s2, f2 = extract_cves_from_object(obj)
                        cves.update(s2 | f2)

            for cve in cves:
                profile.add(f"CVE:{cve}")
                all_features.add(f"CVE:{cve}")

        # Optionally add platform labels from linked software objects
        if platform_mode in ('raw', 'family'):
            platforms = set()
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') in ('malware', 'tool'):
                        for p in obj.get('x_mitre_platforms', []) or []:
                            if platform_mode == 'raw':
                                platforms.add(p)
                            else:
                                fam = normalize_os_family(p)
                                if fam:
                                    platforms.add(fam)
            for p in platforms:
                feat = f"PLATFORM:{p}"
                profile.add(feat)
                all_features.add(feat)

        # Optionally add compatibility summary from IS-linked techniques.
        if include_compat_summary and compatibility_by_technique is not None:
            compat_counts = Counter()
            for rtype, tgt, _ in rel_fwd.get(is_id, []):
                if rtype == 'uses' and tgt in by_id:
                    obj = by_id[tgt]
                    if obj.get('type') == 'attack-pattern':
                        cls = compatibility_by_technique.get(tgt)
                        if cls:
                            compat_counts[cls] += 1
            if compat_counts:
                for cls in sorted(compat_counts.keys()):
                    feat = f"COMPAT_PRESENT:{cls}"
                    profile.add(feat)
                    all_features.add(feat)
                dominant_cls = max(
                    sorted(compat_counts.keys()),
                    key=lambda k: compat_counts[k],
                )
                dom_feat = f"COMPAT_DOMINANT:{dominant_cls}"
                profile.add(dom_feat)
                all_features.add(dom_feat)

        profiles[is_id] = profile

    return profiles, sorted(all_features)


def jaccard_distance(set_a, set_b):
    """Compute Jaccard distance between two sets."""
    if not set_a and not set_b:
        return 0.0  # Both empty → identical
    union = set_a | set_b
    intersection = set_a & set_b
    if not union:
        return 0.0
    return 1.0 - len(intersection) / len(union)


def analyze_profile_specificity(
    intrusion_sets, software_objects, rel_fwd, by_id, compatibility_by_technique=None
):
    """
    RQ3: SUT profile specificity analysis.
    Computes for software-only, software+CVE, software+platform, software+CVE+platform,
    software+OS-family, and software+compatibility-summary settings.
    """
    results = {}

    settings = [
        ('software_only', False, 'none', False),
        ('software_cve', True, 'none', False),
        ('software_platform', False, 'raw', False),
        ('software_cve_platform', True, 'raw', False),
        ('software_family_only', False, 'family', False),
        ('software_compat', False, 'none', True),
    ]
    for setting, include_cve, platform_mode, include_compat_summary in settings:
        profiles, features = build_sut_profiles(
            intrusion_sets, software_objects, rel_fwd, by_id,
            include_cve=include_cve,
            platform_mode=platform_mode,
            include_compat_summary=include_compat_summary,
            compatibility_by_technique=compatibility_by_technique,
        )

        is_ids = list(profiles.keys())
        n = len(is_ids)

        # Compute pairwise Jaccard distances
        # Find nearest neighbor for each IS
        nearest_distances = []
        confused_count = 0  # IS with at least one neighbor within delta
        per_is_rows = []

        for i in range(n):
            min_dist = float('inf')
            prof_i = profiles[is_ids[i]]
            nearest_neighbor = ""

            for j in range(n):
                if i == j:
                    continue
                prof_j = profiles[is_ids[j]]
                dist = jaccard_distance(prof_i, prof_j)
                if dist < min_dist:
                    min_dist = dist
                    nearest_neighbor = is_ids[j]

            # Handle empty profiles: distance to any non-empty is 1.0
            # distance to another empty is 0.0
            if min_dist == float('inf'):
                min_dist = 1.0

            nearest_distances.append(min_dist)
            if min_dist <= JACCARD_DELTA:
                confused_count += 1
            per_is_rows.append({
                'intrusion_set_id': is_ids[i],
                'feature_count': len(prof_i),
                'nearest_neighbor_id': nearest_neighbor,
                'nearest_distance': round(min_dist, 4),
                'confused': min_dist <= JACCARD_DELTA,
            })

        unique_count = n - confused_count
        unique_pct = pct(unique_count, n)
        confused_pct = pct(confused_count, n)

        results[setting] = {
            'unique_count': unique_count,
            'unique_pct': unique_pct,
            'confused_count': confused_count,
            'confused_pct': confused_pct,
            'total_is': n,
            'nearest_distances': nearest_distances,
            'num_features': len(features),
            'per_is_rows': per_is_rows,
        }

    return results


def analyze_min_evidence_threshold(per_is_rows, threshold_delta):
    """
    Compute confusion behavior for increasing minimum profile size.
    """
    if not per_is_rows:
        return {
            'curve': [],
            'k1_confusion_pct': 0.0,
            'k3_confusion_pct': 0.0,
            'k5_confusion_pct': 0.0,
            'k3_sample': 0,
            'k5_sample': 0,
        }

    max_k = max(row['feature_count'] for row in per_is_rows)
    curve = []
    for k in range(1, max_k + 1):
        subset = [row for row in per_is_rows if row['feature_count'] >= k]
        if not subset:
            continue
        confused = sum(1 for row in subset if row['nearest_distance'] <= threshold_delta)
        curve.append({
            'min_software_count': k,
            'sample_size': len(subset),
            'confused_count': confused,
            'confusion_pct': pct(confused, len(subset)),
        })

    by_k = {row['min_software_count']: row for row in curve}
    return {
        'curve': curve,
        'k1_confusion_pct': by_k.get(1, {}).get('confusion_pct', 0.0),
        'k3_confusion_pct': by_k.get(3, {}).get('confusion_pct', 0.0),
        'k5_confusion_pct': by_k.get(5, {}).get('confusion_pct', 0.0),
        'k3_sample': by_k.get(3, {}).get('sample_size', 0),
        'k5_sample': by_k.get(5, {}).get('sample_size', 0),
    }


def analyze_delta_sensitivity(per_is_rows, deltas):
    """
    Confusion sensitivity for multiple Jaccard thresholds using same IS set.
    """
    rows = []
    total = len(per_is_rows)
    for delta in deltas:
        confused = sum(1 for row in per_is_rows if row['nearest_distance'] <= delta)
        rows.append({
            'delta': delta,
            'sample_size': total,
            'confused_count': confused,
            'confusion_pct': pct(confused, total),
        })
    return rows


def bootstrap_confusion_ci(per_is_rows, delta, n_boot=5000, seed=42):
    """
    Bootstrap CI for confusion and unique rates at a fixed delta.
    Sampling unit: intrusion-set row (nearest-distance summary), with replacement.
    """
    total = len(per_is_rows)
    if total == 0:
        return {
            'confusion_pct': 0.0,
            'unique_pct': 0.0,
            'confusion_ci_low': 0.0,
            'confusion_ci_high': 0.0,
            'unique_ci_low': 0.0,
            'unique_ci_high': 0.0,
            'bootstrap_summary_rows': [],
        }

    rng = random.Random(seed)
    confusion_samples = []
    unique_samples = []

    for _ in range(n_boot):
        sample = [per_is_rows[rng.randrange(total)] for _ in range(total)]
        confused = sum(1 for row in sample if row['nearest_distance'] <= delta)
        confusion_rate = 100.0 * confused / total
        unique_rate = 100.0 - confusion_rate
        confusion_samples.append(confusion_rate)
        unique_samples.append(unique_rate)

    confusion_samples.sort()
    unique_samples.sort()
    lo_idx = int(0.025 * n_boot)
    hi_idx = int(0.975 * n_boot) - 1
    if hi_idx < 0:
        hi_idx = 0

    point_confused = sum(1 for row in per_is_rows if row['nearest_distance'] <= delta)
    point_conf_pct = pct(point_confused, total)
    point_unique_pct = pct(total - point_confused, total)

    return {
        'confusion_pct': point_conf_pct,
        'unique_pct': point_unique_pct,
        'confusion_ci_low': round(confusion_samples[lo_idx], 1),
        'confusion_ci_high': round(confusion_samples[hi_idx], 1),
        'unique_ci_low': round(unique_samples[lo_idx], 1),
        'unique_ci_high': round(unique_samples[hi_idx], 1),
        'bootstrap_summary_rows': [
            {'stat': 'n_boot', 'confusion_pct': float(n_boot), 'unique_pct': float(n_boot)},
            {'stat': 'p01', 'confusion_pct': round(confusion_samples[int(0.01 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.01 * n_boot)], 4)},
            {'stat': 'p05', 'confusion_pct': round(confusion_samples[int(0.05 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.05 * n_boot)], 4)},
            {'stat': 'p50', 'confusion_pct': round(confusion_samples[int(0.50 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.50 * n_boot)], 4)},
            {'stat': 'p95', 'confusion_pct': round(confusion_samples[int(0.95 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.95 * n_boot)], 4)},
            {'stat': 'p99', 'confusion_pct': round(confusion_samples[int(0.99 * n_boot)], 4), 'unique_pct': round(unique_samples[int(0.99 * n_boot)], 4)},
        ],
    }


# ─────────────────────────────────────────────────────────────────
# 7. Cross-domain coverage (for Figure 1)
# ─────────────────────────────────────────────────────────────────

def analyze_cross_domain_coverage(file_by_domain):
    """
    Compute measured coverage for all local bundles.
    """
    results = {}
    for key, meta in file_by_domain.items():
        path = meta['path']
        name = meta['name']
        if path.exists():
            results[key] = analyze_domain_bundle(path, name)
        else:
            print(f"[WARN] {name} bundle not found at {path}")
    return results


# ─────────────────────────────────────────────────────────────────
# 8. Software coverage for cross-domain figure
# ─────────────────────────────────────────────────────────────────

def compute_software_link_rate(objects_by_type, rel_fwd, rel_rev):
    """Fraction of attack-patterns linked to at least one malware/tool."""
    techniques = objects_by_type.get('attack-pattern', [])
    software_ids = set()
    for s in objects_by_type.get('malware', []):
        software_ids.add(s['id'])
    for s in objects_by_type.get('tool', []):
        software_ids.add(s['id'])

    linked = 0
    for tech in techniques:
        for rtype, tgt, _ in rel_fwd.get(tech['id'], []):
            if rtype == 'uses' and tgt in software_ids:
                linked += 1
                break
        else:
            # ATT&CK and FiGHT commonly encode software -> uses -> technique.
            for rtype, src, _ in rel_rev.get(tech['id'], []):
                if rtype == 'uses' and src in software_ids:
                    linked += 1
                    break
    return pct(linked, len(techniques)) if techniques else 0.0


def compute_cve_link_rate_for_techniques(techniques):
    """Fraction of techniques with at least one CVE mention."""
    with_cve = 0
    for tech in techniques:
        s, f = extract_cves_from_object(tech)
        if s or f:
            with_cve += 1
    return pct(with_cve, len(techniques)) if techniques else 0.0


# ─────────────────────────────────────────────────────────────────
# Main Pipeline
# ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("SUT Measurement Pipeline")
    print("=" * 70)

    # Create output directories
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load Enterprise bundle ──
    print("\n[1/7] Loading Enterprise STIX bundle...")
    all_objects = load_bundle(ENTERPRISE_FILE)
    by_type, by_id = index_objects_by_type(all_objects)
    relationships = by_type.get('relationship', [])
    rel_fwd, rel_rev, rel_by_type = build_relationship_index(relationships)

    techniques = by_type.get('attack-pattern', [])
    campaigns = by_type.get('campaign', [])
    intrusion_sets = by_type.get('intrusion-set', [])
    malware = by_type.get('malware', [])
    tools = by_type.get('tool', [])
    software_objects = malware + tools
    vulnerability_objects = by_type.get('vulnerability', [])

    print(f"  Techniques: {len(techniques)}")
    print(f"  Campaigns: {len(campaigns)}")
    print(f"  Intrusion sets: {len(intrusion_sets)}")
    print(f"  Malware: {len(malware)}")
    print(f"  Tools: {len(tools)}")
    print(f"  Vulnerability objects: {len(vulnerability_objects)}")
    print(f"  Relationships: {len(relationships)}")

    # Identify excluded campaigns (no 'uses' relationships)
    excluded_campaign_ids = set()
    for camp in campaigns:
        has_uses = False
        for rtype, _, _ in rel_fwd.get(camp['id'], []):
            if rtype == 'uses':
                has_uses = True
                break
        if not has_uses:
            excluded_campaign_ids.add(camp['id'])
            print(f"  [EXCLUDED] Campaign '{camp.get('name', '')}' ({camp['id']}) — no 'uses' relationships")

    # ── Platform Coverage ──
    print("\n[2/7] Analyzing platform coverage (RQ1)...")
    platform_results = analyze_platform_coverage(techniques)
    print(f"  Platform coverage: {platform_results['with_platform']}/{platform_results['total_techniques']} "
          f"({platform_results['platform_pct']}%)")
    print(f"  System requirements: {platform_results['with_system_requirements']}/{platform_results['total_techniques']} "
          f"({platform_results['system_requirements_pct']}%)")

    # ── Software References ──
    print("\n[3/7] Analyzing software references (RQ1/RQ2)...")
    software_results = analyze_software_references(
        campaigns, intrusion_sets, software_objects,
        rel_fwd, rel_rev, by_id, excluded_campaign_ids
    )
    print(f"  Campaigns with software: {software_results['campaigns_with_software']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_with_software_pct']}%)")
    print(f"  Campaigns with software-derived platform signal: {software_results['campaigns_with_platform_signal']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_with_platform_signal_pct']}%)")
    print(f"  Campaigns with unknown platform (software-only rule): {software_results['campaigns_unknown_platform']}/{software_results['total_usable_campaigns']} "
          f"({software_results['campaigns_unknown_platform_pct']}%)")
    print(f"  Unknown-platform campaigns: {software_results['campaign_unknown_platform_names']}")
    print(f"  IS with software: {software_results['is_with_software']}/{software_results['total_intrusion_sets']} "
          f"({software_results['is_with_software_pct']}%)")
    print(f"  Software with version signal: {software_results['software_with_version']}/{software_results['total_software']} "
          f"({software_results['software_with_version_pct']}%)")
    print(f"  Software with CPE: {software_results['software_with_cpe']}/{software_results['total_software']} "
          f"({software_results['software_with_cpe_pct']}%)")

    # ── Vulnerability References ──
    print("\n[4/7] Analyzing vulnerability references (RQ1/RQ2)...")
    cve_results = analyze_vulnerability_references(
        campaigns, intrusion_sets, software_objects,
        techniques, vulnerability_objects,
        rel_fwd, rel_rev, by_id, excluded_campaign_ids
    )
    print(f"  Unique CVEs (all sources): {cve_results['cve_unique_count']}")
    print(f"  Structured CVEs: {cve_results['cve_structured_count']}")
    print(f"  Free-text only CVEs: {cve_results['cve_freetext_only_count']}")
    print(f"  CVE from free text: {cve_results['cve_from_freetext_pct']}%")
    print(f"  Actionable CVEs (from software/campaign/IS): {cve_results['actionable_cve_count']}")
    print(f"  Technique-example-only CVEs: {cve_results['technique_only_cve_count']}")
    print(f"  CVEs from techniques (examples): {cve_results['cves_from_techniques']}")
    print(f"  CVEs from software: {cve_results['cves_from_software']}")
    print(f"  CVEs from campaigns: {cve_results['cves_from_campaigns']}")
    print(f"  CVEs from intrusion sets: {cve_results['cves_from_is']}")
    print(f"  Campaigns with CVE: {cve_results['campaigns_with_cve']}/{software_results['total_usable_campaigns']} "
          f"({cve_results['campaigns_with_cve_pct']}%)")
    print(f"  IS with CVE: {cve_results['is_with_cve']}/{software_results['total_intrusion_sets']} "
          f"({cve_results['is_with_cve_pct']}%)")

    # ── Initial Access analysis ──
    print("\n[5/7] Analyzing Initial Access signals...")
    initial_access_results = analyze_initial_access(
        campaigns, techniques, rel_fwd, cve_results, excluded_campaign_ids
    )
    print(f"  Initial Access techniques: {initial_access_results['initial_access_technique_count']}")
    print(f"  Campaigns with Initial Access: {initial_access_results['campaigns_with_initial_access_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_pct']}%)")
    print(f"  Campaigns with social-interaction IA proxy: {initial_access_results['campaigns_with_social_initial_access_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_social_initial_access_pct']}%)")
    print(f"  Campaigns with IA and CVE evidence: {initial_access_results['campaigns_with_initial_access_and_cve_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_and_cve_pct']}%)")
    print(f"  Campaigns with IA and no CVE evidence: {initial_access_results['campaigns_with_initial_access_no_cve_count']}/{software_results['total_usable_campaigns']} "
          f"({initial_access_results['campaigns_with_initial_access_no_cve_pct']}%)")

    # ── Compatibility Classification ──
    print("\n[6/7] Classifying technique compatibility (RQ2)...")
    compat_results = analyze_compatibility(techniques, rel_fwd, by_id)
    print(f"  CF: {compat_results['cf_count']} ({compat_results['cf_pct']}%)")
    print(f"  VMR: {compat_results['vmr_count']} ({compat_results['vmr_pct']}%)")
    print(f"  ID: {compat_results['id_count']} ({compat_results['id_pct']}%)")
    print(f"  Total: {compat_results['cf_count'] + compat_results['vmr_count'] + compat_results['id_count']}")
    compatibility_by_technique = {}
    for cls_name, cls_list in compat_results['details'].items():
        for tech in cls_list:
            compatibility_by_technique[tech['id']] = cls_name

    # ── Profile Specificity ──
    print("\n[7/7] Computing SUT profile specificity (RQ3)...")
    specificity_results = analyze_profile_specificity(
        intrusion_sets, software_objects, rel_fwd, by_id, compatibility_by_technique
    )
    sw_only = specificity_results['software_only']
    sw_cve = specificity_results['software_cve']
    sw_platform = specificity_results['software_platform']
    sw_cve_platform = specificity_results['software_cve_platform']
    sw_family_only = specificity_results['software_family_only']
    sw_compat = specificity_results['software_compat']
    print(f"  Software-only unique profiles: {sw_only['unique_count']}/{sw_only['total_is']} "
          f"({sw_only['unique_pct']}%)")
    print(f"  Software+CVE unique profiles: {sw_cve['unique_count']}/{sw_cve['total_is']} "
          f"({sw_cve['unique_pct']}%)")
    print(f"  Software+CVE confused: {sw_cve['confused_count']}/{sw_cve['total_is']} "
          f"({sw_cve['confused_pct']}%)")
    print(f"  Software+platform unique profiles: {sw_platform['unique_count']}/{sw_platform['total_is']} "
          f"({sw_platform['unique_pct']}%)")
    print(f"  Software+platform confused: {sw_platform['confused_count']}/{sw_platform['total_is']} "
          f"({sw_platform['confused_pct']}%)")
    print(f"  Software+CVE+platform unique profiles: {sw_cve_platform['unique_count']}/{sw_cve_platform['total_is']} "
          f"({sw_cve_platform['unique_pct']}%)")
    print(f"  Software+CVE+platform confused: {sw_cve_platform['confused_count']}/{sw_cve_platform['total_is']} "
          f"({sw_cve_platform['confused_pct']}%)")
    print(f"  Software+OS-family unique profiles: {sw_family_only['unique_count']}/{sw_family_only['total_is']} "
          f"({sw_family_only['unique_pct']}%)")
    print(f"  Software+OS-family confused: {sw_family_only['confused_count']}/{sw_family_only['total_is']} "
          f"({sw_family_only['confused_pct']}%)")
    print(f"  Software+compat unique profiles: {sw_compat['unique_count']}/{sw_compat['total_is']} "
          f"({sw_compat['unique_pct']}%)")
    print(f"  Software+compat confused: {sw_compat['confused_count']}/{sw_compat['total_is']} "
          f"({sw_compat['confused_pct']}%)")

    threshold_results = analyze_min_evidence_threshold(
        specificity_results['software_only']['per_is_rows'],
        JACCARD_DELTA,
    )
    delta_sensitivity = analyze_delta_sensitivity(
        specificity_results['software_only']['per_is_rows'],
        [0.05, 0.10, 0.15],
    )
    bootstrap_results = bootstrap_confusion_ci(
        specificity_results['software_only']['per_is_rows'],
        JACCARD_DELTA,
        n_boot=5000,
        seed=42,
    )
    print("  Confusion by minimum software count:")
    print(f"    k>=1: {threshold_results['k1_confusion_pct']}%")
    print(f"    k>=3: {threshold_results['k3_confusion_pct']}% (n={threshold_results['k3_sample']})")
    print(f"    k>=5: {threshold_results['k5_confusion_pct']}% (n={threshold_results['k5_sample']})")
    print("  Delta sensitivity (software-only):")
    for row in delta_sensitivity:
        print(f"    delta={row['delta']:.2f}: {row['confusion_pct']}% (n={row['sample_size']})")
    print(
        "  Bootstrap (delta=0.10): "
        f"confusion {bootstrap_results['confusion_pct']}% "
        f"[{bootstrap_results['confusion_ci_low']}, {bootstrap_results['confusion_ci_high']}]"
    )

    # ── Cross-domain coverage ──
    print("\n[8/8] Computing cross-domain coverage...")
    cross_domain = analyze_cross_domain_coverage({
        'enterprise': {'name': 'Enterprise', 'path': ENTERPRISE_FILE},
        'mobile': {'name': 'Mobile', 'path': MOBILE_FILE},
        'ics': {'name': 'ICS', 'path': ICS_FILE},
        'capec': {'name': 'CAPEC', 'path': CAPEC_FILE},
        'fight': {'name': 'FiGHT', 'path': FIGHT_FILE},
    })
    for domain, data in cross_domain.items():
        print(
            f"  {data.get('domain', domain)}: "
            f"platform={data.get('platform_pct', 'N/A')}%, "
            f"software-link={data.get('software_link_pct', 'N/A')}%, "
            f"CVE-link={data.get('cve_link_pct', 'N/A')}%"
        )

    # ══════════════════════════════════════════════════════════════
    # Assemble TODO values
    # ══════════════════════════════════════════════════════════════
    todo_values = {
        # RQ1 Platform
        'enterprise_platform_count': platform_results['with_platform'],
        'enterprise_platform_pct': platform_results['platform_pct'],
        'enterprise_system_requirements_count': platform_results['with_system_requirements'],
        'enterprise_system_requirements_pct': platform_results['system_requirements_pct'],
        'mobile_platform_pct': cross_domain.get('mobile', {}).get('platform_pct', 'N/A'),
        'ics_platform_percentage': cross_domain.get('ics', {}).get('platform_pct', 'N/A'),
        'capec_platform_percentage': cross_domain.get('capec', {}).get('platform_pct', 'N/A'),
        'fight_platform_percentage': cross_domain.get('fight', {}).get('platform_pct', 'N/A'),

        # Figure 1 (cross-corpus coverage)
        'enterprise_software_link_pct': cross_domain.get('enterprise', {}).get('software_link_pct', 'N/A'),
        'enterprise_cve_link_pct': cross_domain.get('enterprise', {}).get('cve_link_pct', 'N/A'),
        'mobile_software_link_pct': cross_domain.get('mobile', {}).get('software_link_pct', 'N/A'),
        'mobile_cve_link_pct': cross_domain.get('mobile', {}).get('cve_link_pct', 'N/A'),
        'ics_software_link_pct': cross_domain.get('ics', {}).get('software_link_pct', 'N/A'),
        'ics_cve_link_pct': cross_domain.get('ics', {}).get('cve_link_pct', 'N/A'),
        'capec_software_link_pct': cross_domain.get('capec', {}).get('software_link_pct', 'N/A'),
        'capec_cve_link_pct': cross_domain.get('capec', {}).get('cve_link_pct', 'N/A'),
        'fight_software_link_pct': cross_domain.get('fight', {}).get('software_link_pct', 'N/A'),
        'fight_cve_link_pct': cross_domain.get('fight', {}).get('cve_link_pct', 'N/A'),

        # RQ1/RQ2 Software
        'enterprise_campaigns_with_software_count': software_results['campaigns_with_software'],
        'enterprise_campaigns_with_software_percentage': software_results['campaigns_with_software_pct'],
        'enterprise_campaigns_with_software_ci_low': proportion_ci_wilson(
            software_results['campaigns_with_software'],
            software_results['total_usable_campaigns'],
        )[0],
        'enterprise_campaigns_with_software_ci_high': proportion_ci_wilson(
            software_results['campaigns_with_software'],
            software_results['total_usable_campaigns'],
        )[1],
        'enterprise_active_campaign_count': software_results['total_usable_campaigns'],
        'enterprise_campaigns_with_platform_signal_count': software_results['campaigns_with_platform_signal'],
        'enterprise_campaigns_with_platform_signal_pct': software_results['campaigns_with_platform_signal_pct'],
        'enterprise_campaigns_platform_unknown_count': software_results['campaigns_unknown_platform'],
        'enterprise_campaigns_platform_unknown_pct': software_results['campaigns_unknown_platform_pct'],
        'campaign_os_windows_count': software_results['campaign_os_family_counts'].get('Windows', 0),
        'campaign_os_linux_count': software_results['campaign_os_family_counts'].get('Linux', 0),
        'campaign_os_macos_count': software_results['campaign_os_family_counts'].get('macOS', 0),
        'enterprise_intrusion_sets_with_software_count': software_results['is_with_software'],
        'enterprise_intrusion_sets_with_software_percentage': software_results['is_with_software_pct'],
        'enterprise_active_intrusion_set_count': software_results['total_intrusion_sets'],
        'enterprise_active_software_count': software_results['total_software'],
        'enterprise_active_malware_count': len(malware),
        'enterprise_active_tool_count': len(tools),
        'software_with_version_signal_percentage': software_results['software_with_version_pct'],
        'software_with_version_signal_ci_low': proportion_ci_wilson(
            software_results['software_with_version'],
            software_results['total_software'],
        )[0],
        'software_with_version_signal_ci_high': proportion_ci_wilson(
            software_results['software_with_version'],
            software_results['total_software'],
        )[1],
        'software_with_cpe_percentage': software_results['software_with_cpe_pct'],

        # RQ1/RQ2 CVE
        'cve_unique_count': cve_results['cve_unique_count'],
        'cve_structured_count': cve_results['cve_structured_count'],
        'cve_freetext_only_count': cve_results['cve_freetext_only_count'],
        'cve_from_freetext_pct': cve_results['cve_from_freetext_pct'],
        'cve_actionable_count': cve_results['actionable_cve_count'],
        'cve_technique_only_count': cve_results['technique_only_cve_count'],
        'campaign_linked_cve_count': len(cve_results['cves_from_campaigns']),
        'ent_campaigns_with_cve_count': cve_results['campaigns_with_cve'],
        'ent_campaigns_with_cve_pct': cve_results['campaigns_with_cve_pct'],
        'ent_campaigns_with_cve_ci_low': proportion_ci_wilson(
            cve_results['campaigns_with_cve'],
            software_results['total_usable_campaigns'],
        )[0],
        'ent_campaigns_with_cve_ci_high': proportion_ci_wilson(
            cve_results['campaigns_with_cve'],
            software_results['total_usable_campaigns'],
        )[1],
        'ent_intrusion_sets_with_cve_count': cve_results['is_with_cve'],
        'ent_intrusion_sets_with_cve_pct': cve_results['is_with_cve_pct'],

        # Initial Access
        'initial_access_technique_count': initial_access_results['initial_access_technique_count'],
        'campaigns_with_initial_access_count': initial_access_results['campaigns_with_initial_access_count'],
        'campaigns_with_initial_access_pct': initial_access_results['campaigns_with_initial_access_pct'],
        'campaigns_with_initial_access_ci_low': proportion_ci_wilson(
            initial_access_results['campaigns_with_initial_access_count'],
            software_results['total_usable_campaigns'],
        )[0],
        'campaigns_with_initial_access_ci_high': proportion_ci_wilson(
            initial_access_results['campaigns_with_initial_access_count'],
            software_results['total_usable_campaigns'],
        )[1],
        'campaigns_with_social_initial_access_count': initial_access_results['campaigns_with_social_initial_access_count'],
        'campaigns_with_social_initial_access_pct': initial_access_results['campaigns_with_social_initial_access_pct'],
        'campaigns_with_initial_access_and_cve_count': initial_access_results['campaigns_with_initial_access_and_cve_count'],
        'campaigns_with_initial_access_and_cve_pct': initial_access_results['campaigns_with_initial_access_and_cve_pct'],
        'campaigns_with_initial_access_no_cve_count': initial_access_results['campaigns_with_initial_access_no_cve_count'],
        'campaigns_with_initial_access_no_cve_pct': initial_access_results['campaigns_with_initial_access_no_cve_pct'],

        # RQ2 Compatibility
        'compatibility_container_feasible_count': compat_results['cf_count'],
        'compatibility_container_feasible_percentage': compat_results['cf_pct'],
        'compatibility_vm_required_count': compat_results['vmr_count'],
        'compatibility_vm_required_percentage': compat_results['vmr_pct'],
        'compatibility_infrastructure_dependent_count': compat_results['id_count'],
        'compatibility_infrastructure_dependent_percentage': compat_results['id_pct'],

        # RQ3 Specificity
        'sut_profile_unique_software_percentage': sw_only['unique_pct'],
        'sut_profile_unique_software_cve_percentage': sw_cve['unique_pct'],
        'sut_profile_unique_software_platform_percentage': sw_platform['unique_pct'],
        'sut_profile_unique_software_cve_platform_percentage': sw_cve_platform['unique_pct'],
        'sut_profile_unique_software_family_only_percentage': sw_family_only['unique_pct'],
        'sut_profile_unique_software_compat_percentage': sw_compat['unique_pct'],
        'sut_profile_confusion_software_percentage': sw_only['confused_pct'],
        'sut_profile_confusion_software_cve_percentage': sw_cve['confused_pct'],
        'sut_profile_confusion_software_platform_percentage': sw_platform['confused_pct'],
        'sut_profile_confusion_software_cve_platform_percentage': sw_cve_platform['confused_pct'],
        'sut_profile_confusion_software_family_only_percentage': sw_family_only['confused_pct'],
        'sut_profile_confusion_software_compat_percentage': sw_compat['confused_pct'],
        'sut_profile_confusion_software_cve_ci_low': proportion_ci_wilson(
            sw_cve['confused_count'],
            sw_cve['total_is'],
        )[0],
        'sut_profile_confusion_software_cve_ci_high': proportion_ci_wilson(
            sw_cve['confused_count'],
            sw_cve['total_is'],
        )[1],
        'threshold_k_one_confusion_pct': threshold_results['k1_confusion_pct'],
        'threshold_k_three_confusion_pct': threshold_results['k3_confusion_pct'],
        'threshold_k_five_confusion_pct': threshold_results['k5_confusion_pct'],
        'threshold_k_three_sample': threshold_results['k3_sample'],
        'threshold_k_five_sample': threshold_results['k5_sample'],
        'delta_zero_zero_five_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.05) < 1e-9),
            0.0,
        ),
        'delta_zero_ten_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.10) < 1e-9),
            0.0,
        ),
        'delta_zero_fifteen_confusion_pct': next(
            (row['confusion_pct'] for row in delta_sensitivity if abs(row['delta'] - 0.15) < 1e-9),
            0.0,
        ),
        'bootstrap_confusion_pct': bootstrap_results['confusion_pct'],
        'bootstrap_confusion_ci_low': bootstrap_results['confusion_ci_low'],
        'bootstrap_confusion_ci_high': bootstrap_results['confusion_ci_high'],
        'bootstrap_unique_pct': bootstrap_results['unique_pct'],
        'bootstrap_unique_ci_low': bootstrap_results['unique_ci_low'],
        'bootstrap_unique_ci_high': bootstrap_results['unique_ci_high'],
    }

    # ── Save TODO values as JSON ──
    with open(RESULTS_DIR / 'todo_values.json', 'w') as f:
        json.dump(todo_values, f, indent=2)
    print(f"\n✓ TODO values saved to {RESULTS_DIR / 'todo_values.json'}")

    # ── Save as LaTeX newcommands ──
    with open(RESULTS_DIR / 'todo_values_latex.tex', 'w') as f:
        f.write("% Auto-generated extracted values\n")
        f.write(f"% Generated: 2026-03-05\n")
        f.write(f"% Bundle: ATT&CK Enterprise v18.1\n\n")
        for key, val in todo_values.items():
            latex_key = key.replace('_', '')
            f.write(f"\\newcommand{{\\{latex_key}}}{{{val}}}\n")
    print(f"✓ LaTeX commands saved to {RESULTS_DIR / 'todo_values_latex.tex'}")

    # ── Save figure data ──
    figure_data = {
        'coverage_chart': {
            'enterprise': {
                'platform': cross_domain.get('enterprise', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('enterprise', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('enterprise', {}).get('cve_link_pct', 0),
            },
            'mobile': {
                'platform': cross_domain.get('mobile', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('mobile', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('mobile', {}).get('cve_link_pct', 0),
            },
            'ics': {
                'platform': cross_domain.get('ics', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('ics', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('ics', {}).get('cve_link_pct', 0),
            },
            'capec': {
                'platform': cross_domain.get('capec', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('capec', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('capec', {}).get('cve_link_pct', 0),
            },
            'fight': {
                'platform': cross_domain.get('fight', {}).get('platform_pct', 0),
                'software_link': cross_domain.get('fight', {}).get('software_link_pct', 0),
                'cve_link': cross_domain.get('fight', {}).get('cve_link_pct', 0),
            },
        },
        'software_specificity': {
            'total_software': software_results['total_software'],
            'no_version_no_cpe': software_results['total_software'] - software_results['software_with_version'] - software_results['software_with_cpe'] + min(software_results['software_with_version'], software_results['software_with_cpe']),
            'version_no_cpe': software_results['software_with_version'] - min(software_results['software_with_version'], software_results['software_with_cpe']),
            'with_cpe': software_results['software_with_cpe'],
            'no_version_no_cpe_pct': 0,  # Will compute
            'version_no_cpe_pct': 0,
            'with_cpe_pct': 0,
        },
        'cve_location': {
            'structured_count': cve_results['cve_structured_count'],
            'freetext_only_count': cve_results['cve_freetext_only_count'],
            'total': cve_results['cve_unique_count'],
        },
        'jaccard_cdf': {
            'software_only_distances': specificity_results['software_only']['nearest_distances'],
            'software_cve_distances': specificity_results['software_cve']['nearest_distances'],
            'software_platform_distances': specificity_results['software_platform']['nearest_distances'],
            'software_cve_platform_distances': specificity_results['software_cve_platform']['nearest_distances'],
            'software_family_only_distances': specificity_results['software_family_only']['nearest_distances'],
            'software_compat_distances': specificity_results['software_compat']['nearest_distances'],
            'delta_threshold': JACCARD_DELTA,
        },
        'compatibility_table': {
            'cf': compat_results['cf_count'],
            'vmr': compat_results['vmr_count'],
            'id': compat_results['id_count'],
        },
    }

    # Fix software specificity percentages
    total_sw = figure_data['software_specificity']['total_software']
    # Compute segments properly: need to know overlap between version and CPE
    # For simplicity, treat as: with_cpe (strongest), version_only (has version but no CPE), neither
    sw_with_both = 0
    for sw in software_objects:
        has_v = False
        has_c = False
        name = sw.get('name', '')
        aliases = sw.get('aliases', []) or []
        ext_refs = sw.get('external_references', []) or []
        version_pattern = re.compile(r'(?:v?\d+\.\d+|\bversion\s+\d+|\b\d+\.\d+\.\d+)', re.IGNORECASE)
        if version_pattern.search(name):
            has_v = True
        for a in aliases:
            if version_pattern.search(a):
                has_v = True
        for ref in ext_refs:
            ref_str = json.dumps(ref)
            if version_pattern.search(ref_str):
                has_v = True
            if 'cpe:' in ref_str.lower():
                has_c = True
        if has_v and has_c:
            sw_with_both += 1

    version_only = software_results['software_with_version'] - sw_with_both
    cpe_any = software_results['software_with_cpe']
    neither = total_sw - version_only - cpe_any

    figure_data['software_specificity']['no_version_no_cpe'] = neither
    figure_data['software_specificity']['version_no_cpe'] = version_only
    figure_data['software_specificity']['with_cpe'] = cpe_any
    figure_data['software_specificity']['no_version_no_cpe_pct'] = pct(neither, total_sw)
    figure_data['software_specificity']['version_no_cpe_pct'] = pct(version_only, total_sw)
    figure_data['software_specificity']['with_cpe_pct'] = pct(cpe_any, total_sw)

    with open(RESULTS_DIR / 'figures_data.json', 'w') as f:
        # Convert numpy types to native Python for JSON serialization
        json.dump(figure_data, f, indent=2, default=float)
    print(f"✓ Figure data saved to {RESULTS_DIR / 'figures_data.json'}")

    # ── Save audit CSVs ──
    # Campaign software details
    with open(AUDIT_DIR / 'campaign_software.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['campaign_name', 'campaign_id', 'software_count'])
        writer.writeheader()
        for row in software_results['campaign_details']:
            writer.writerow({k: row[k] for k in ['campaign_name', 'campaign_id', 'software_count']})

    # Campaign platform inference details (software-only)
    with open(AUDIT_DIR / 'campaign_platforms_software_only.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                'campaign_name', 'campaign_id', 'software_count', 'platform_signal',
                'os_families', 'raw_platforms', 'non_os_platforms', 'unknown_reason'
            ]
        )
        writer.writeheader()
        for row in software_results['campaign_platform_details']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'campaign_id': row['campaign_id'],
                'software_count': row['software_count'],
                'platform_signal': row['platform_signal'],
                'os_families': ';'.join(row['os_families']),
                'raw_platforms': ';'.join(row['raw_platforms']),
                'non_os_platforms': ';'.join(row['non_os_platforms']),
                'unknown_reason': row['unknown_reason'],
            })

    # Campaign OS family aggregate counts (multi-label over campaigns)
    with open(AUDIT_DIR / 'campaign_os_family_counts.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['os_family', 'campaign_count'])
        writer.writeheader()
        for fam, count in software_results['campaign_os_family_counts'].items():
            writer.writerow({'os_family': fam, 'campaign_count': count})

    # Campaign non-OS platform aggregate counts
    with open(AUDIT_DIR / 'campaign_non_os_platform_counts.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['platform_label', 'campaign_count'])
        writer.writeheader()
        for label, count in software_results['campaign_non_os_platform_counts'].items():
            writer.writerow({'platform_label': label, 'campaign_count': count})

    # Campaigns with unknown platform signal under software-only inference
    with open(AUDIT_DIR / 'campaign_platform_unknown.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['campaign_name'])
        writer.writeheader()
        for name in software_results['campaign_unknown_platform_names']:
            writer.writerow({'campaign_name': name})

    # Campaign CVE details
    with open(AUDIT_DIR / 'campaign_cves.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['campaign_name', 'cve_count', 'cves'])
        writer.writeheader()
        for row in cve_results['campaign_cve_details']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'cve_count': row['cve_count'],
                'cves': ';'.join(row['cves']),
            })

    # IS CVE details
    with open(AUDIT_DIR / 'is_cves.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['is_name', 'cve_count', 'cves'])
        writer.writeheader()
        for row in cve_results['is_cve_details']:
            writer.writerow({
                'is_name': row['is_name'],
                'cve_count': row['cve_count'],
                'cves': ';'.join(row['cves']),
            })

    # Initial Access campaign details
    with open(AUDIT_DIR / 'initial_access_campaigns.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                'campaign_name', 'campaign_id', 'has_initial_access', 'has_social_proxy',
                'campaign_cve_count', 'initial_access_technique_count', 'initial_access_techniques'
            ]
        )
        writer.writeheader()
        for row in initial_access_results['campaign_rows']:
            writer.writerow({
                'campaign_name': row['campaign_name'],
                'campaign_id': row['campaign_id'],
                'has_initial_access': row['has_initial_access'],
                'has_social_proxy': row['has_social_proxy'],
                'campaign_cve_count': row['campaign_cve_count'],
                'initial_access_technique_count': row['initial_access_technique_count'],
                'initial_access_techniques': ';'.join(row['initial_access_techniques']),
            })

    # Initial Access technique frequency across campaigns
    with open(AUDIT_DIR / 'initial_access_techniques.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['technique_name', 'campaign_count'])
        writer.writeheader()
        for name, count in initial_access_results['top_initial_access_techniques']:
            writer.writerow({'technique_name': name, 'campaign_count': count})

    # Technique compatibility classification
    with open(AUDIT_DIR / 'technique_compatibility.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['name', 'id', 'class', 'platforms', 'permissions'])
        writer.writeheader()
        for cls_name, cls_list in compat_results['details'].items():
            for tech in cls_list:
                writer.writerow({
                    'name': tech['name'],
                    'id': tech['id'],
                    'class': tech['class'],
                    'platforms': ';'.join(tech['platforms'] or []),
                    'permissions': ';'.join(tech['permissions'] or []),
                })

    # IS software details
    with open(AUDIT_DIR / 'is_software.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['is_name', 'is_id', 'software_count'])
        writer.writeheader()
        for row in software_results['is_details']:
            writer.writerow(row)

    # Per-IS nearest-neighbor specificity rows (software-only)
    with open(AUDIT_DIR / 'profile_specificity_software_only.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['intrusion_set_id', 'feature_count', 'nearest_neighbor_id', 'nearest_distance', 'confused']
        )
        writer.writeheader()
        for row in specificity_results['software_only']['per_is_rows']:
            writer.writerow(row)

    # Profile specificity ablation summary at delta=0.10
    with open(AUDIT_DIR / 'profile_ablation_summary.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['setting', 'unique_count', 'unique_pct', 'confused_count', 'confused_pct', 'total_is', 'num_features']
        )
        writer.writeheader()
        for setting in [
            'software_only',
            'software_cve',
            'software_platform',
            'software_cve_platform',
            'software_family_only',
            'software_compat',
        ]:
            row = specificity_results[setting]
            writer.writerow({
                'setting': setting,
                'unique_count': row['unique_count'],
                'unique_pct': row['unique_pct'],
                'confused_count': row['confused_count'],
                'confused_pct': row['confused_pct'],
                'total_is': row['total_is'],
                'num_features': row['num_features'],
            })

    # Confusion curve by minimum software evidence threshold
    with open(AUDIT_DIR / 'evidence_threshold_curve.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['min_software_count', 'sample_size', 'confused_count', 'confusion_pct']
        )
        writer.writeheader()
        for row in threshold_results['curve']:
            writer.writerow(row)

    # Confusion sensitivity across multiple Jaccard deltas
    with open(AUDIT_DIR / 'delta_sensitivity.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['delta', 'sample_size', 'confused_count', 'confusion_pct']
        )
        writer.writeheader()
        for row in delta_sensitivity:
            writer.writerow(row)

    # Bootstrap distribution for confusion/unique rates at delta=0.10
    with open(AUDIT_DIR / 'bootstrap_confusion_distribution.csv', 'w', newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['stat', 'confusion_pct', 'unique_pct']
        )
        writer.writeheader()
        for row in bootstrap_results['bootstrap_summary_rows']:
            writer.writerow(row)

    # Platform distribution
    with open(AUDIT_DIR / 'platform_distribution.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['platform', 'technique_count'])
        writer.writeheader()
        for platform, count in sorted(platform_results['platform_distribution'].items(),
                                       key=lambda x: -x[1]):
            writer.writerow({'platform': platform, 'technique_count': count})

    # All CVEs found
    with open(AUDIT_DIR / 'all_cves.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['cve_id', 'source'])
        writer.writeheader()
        for cve in sorted(cve_results['structured_cves']):
            writer.writerow({'cve_id': cve, 'source': 'structured'})
        for cve in sorted(cve_results['freetext_only_cves']):
            writer.writerow({'cve_id': cve, 'source': 'freetext_only'})

    print(f"✓ Audit CSVs saved to {AUDIT_DIR}")

    # ── Print summary ──
    print("\n" + "=" * 70)
    print("SUMMARY: Extracted Values")
    print("=" * 70)
    for key, val in todo_values.items():
        print(f"  \\TODO{{{key}}} = {val}")

    print("\n" + "=" * 70)
    print("VALIDATION CHECKS")
    print("=" * 70)
    cf_vmr_id_sum = compat_results['cf_count'] + compat_results['vmr_count'] + compat_results['id_count']
    print(f"  CF + VMR + ID = {cf_vmr_id_sum} (should be {len(techniques)})")
    pct_sum = compat_results['cf_pct'] + compat_results['vmr_pct'] + compat_results['id_pct']
    print(f"  CF% + VMR% + ID% = {pct_sum}% (should be ~100%)")
    print(f"  Usable campaigns: {len(campaigns) - len(excluded_campaign_ids)} (should be {USABLE_CAMPAIGNS})")
    print(f"  Excluded campaigns: {excluded_campaign_ids}")

    return todo_values


if __name__ == '__main__':
    todo_values = main()

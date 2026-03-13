#!/usr/bin/env python3
"""
Campaign Clustering and LCS Analysis for STICKS Paper 1.

Computes:
  - Silhouette coefficient from k-means clustering (k=7) on
    campaign-technique binary vectors
  - LCS (Longest Common Subsequence) statistics across campaign pairs
    on tactic-ordered technique sequences

Usage (from the sticks/ project root):
    python3 analyze_campaigns.py --bundle data/stix/enterprise-attack.json

Outputs:
    Prints LaTeX-ready values for:
        \\silhouetteScore, \\lcsLengthMean, \\lcsLengthMedian, \\lcsLengthMax
"""

import json
import argparse
import sys
import statistics
from collections import defaultdict
from itertools import combinations

# ── Tactic phase order (ATT&CK kill-chain order) ──────────────────────────────
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
TACTIC_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}

# ── Deprecation filter ────────────────────────────────────────────────────────

def is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


# ── STIX bundle loading ───────────────────────────────────────────────────────

def load_bundle(path):
    with open(path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects}

    campaigns = [o for o in objects if o.get("type") == "campaign" and is_active(o)]
    techniques = [o for o in objects if o.get("type") == "attack-pattern" and is_active(o)]
    relationships = [o for o in objects if o.get("type") == "relationship"]

    return by_id, campaigns, techniques, relationships


def get_external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def get_tactic_rank(technique):
    """Return the minimum tactic rank for a technique (for ordering)."""
    phases = technique.get("kill_chain_phases", [])
    ranks = [
        TACTIC_RANK.get(p.get("phase_name", ""), 99)
        for p in phases
        if p.get("kill_chain_name") == "mitre-attack"
    ]
    return min(ranks) if ranks else 99


# ── Relationship indexing ─────────────────────────────────────────────────────

def build_fwd_index(relationships):
    """src → {rel_type → [target_id, ...]}"""
    idx = defaultdict(lambda: defaultdict(list))
    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        rtype = rel.get("relationship_type", "")
        if src and tgt and rtype:
            idx[src][rtype].append(tgt)
    return idx


# ── Campaign technique extraction ─────────────────────────────────────────────

def campaign_technique_sets(campaigns, by_id, fwd):
    """
    Returns:
        camp_ids    : list of campaign STIX IDs (length N)
        camp_techs  : list of sets of technique STIX IDs
        tech_ids    : sorted list of all observed technique STIX IDs
    """
    camp_ids = []
    camp_techs = []
    all_techs = set()

    for camp in campaigns:
        cid = camp["id"]
        uses = fwd.get(cid, {}).get("uses", [])
        techs = {t for t in uses if by_id.get(t, {}).get("type") == "attack-pattern"
                 and is_active(by_id.get(t, {}))}
        camp_ids.append(cid)
        camp_techs.append(techs)
        all_techs.update(techs)

    tech_ids = sorted(all_techs)
    return camp_ids, camp_techs, tech_ids


# ── Binary feature matrix ─────────────────────────────────────────────────────

def build_feature_matrix(camp_techs, tech_ids):
    """Returns list of lists (N x M) of 0/1."""
    tech_pos = {t: i for i, t in enumerate(tech_ids)}
    M = len(tech_ids)
    matrix = []
    for techs in camp_techs:
        row = [0] * M
        for t in techs:
            if t in tech_pos:
                row[tech_pos[t]] = 1
        matrix.append(row)
    return matrix


# ── K-means (pure Python, no numpy) ──────────────────────────────────────────

def euclidean_sq(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b))


def centroid(points):
    n = len(points)
    m = len(points[0])
    return [sum(p[i] for p in points) / n for i in range(m)]


def kmeans(matrix, k, max_iter=300, seed=42):
    """Simple k-means. Returns (labels, centroids)."""
    import random
    rng = random.Random(seed)
    n = len(matrix)
    # k-means++ style seeding
    centers = [list(matrix[rng.randrange(n)])]
    for _ in range(k - 1):
        dists = [min(euclidean_sq(p, c) for c in centers) for p in matrix]
        total = sum(dists)
        if total == 0:
            centers.append(list(matrix[rng.randrange(n)]))
            continue
        r = rng.random() * total
        cumul = 0.0
        for i, d in enumerate(dists):
            cumul += d
            if cumul >= r:
                centers.append(list(matrix[i]))
                break
        else:
            centers.append(list(matrix[-1]))

    labels = [0] * n
    for _ in range(max_iter):
        # Assignment
        new_labels = [
            min(range(k), key=lambda j: euclidean_sq(matrix[i], centers[j]))
            for i in range(n)
        ]
        if new_labels == labels:
            break
        labels = new_labels
        # Update centroids
        for j in range(k):
            cluster_pts = [matrix[i] for i in range(n) if labels[i] == j]
            if cluster_pts:
                centers[j] = centroid(cluster_pts)

    return labels, centers


# ── Silhouette coefficient ────────────────────────────────────────────────────

def silhouette_coefficient(matrix, labels):
    """
    Returns mean silhouette score (float).
    Uses Euclidean distance on binary vectors.
    """
    n = len(matrix)
    if n < 2:
        return 0.0

    # Group indices by cluster
    clusters = defaultdict(list)
    for i, lab in enumerate(labels):
        clusters[lab].append(i)

    scores = []
    for i in range(n):
        lab_i = labels[i]
        same = [j for j in clusters[lab_i] if j != i]

        # a(i) = mean distance to same-cluster points
        if not same:
            scores.append(0.0)
            continue
        a_i = sum(euclidean_sq(matrix[i], matrix[j]) ** 0.5 for j in same) / len(same)

        # b(i) = min mean distance to points in any other cluster
        b_i = float("inf")
        for lab_other, members in clusters.items():
            if lab_other == lab_i:
                continue
            if not members:
                continue
            mean_dist = sum(
                euclidean_sq(matrix[i], matrix[j]) ** 0.5 for j in members
            ) / len(members)
            if mean_dist < b_i:
                b_i = mean_dist

        if b_i == float("inf"):
            scores.append(0.0)
            continue

        denom = max(a_i, b_i)
        scores.append((b_i - a_i) / denom if denom > 0 else 0.0)

    return sum(scores) / len(scores)


# ── Tactic-ordered technique sequences ───────────────────────────────────────

def campaign_technique_sequences(camp_techs, by_id):
    """
    For each campaign, return the sorted sequence of technique external IDs
    ordered by (tactic_rank, external_id).
    """
    seqs = []
    for techs in camp_techs:
        ordered = sorted(
            techs,
            key=lambda tid: (
                get_tactic_rank(by_id.get(tid, {})),
                get_external_id(by_id.get(tid, {})),
            ),
        )
        seq = [get_external_id(by_id.get(t, {})) for t in ordered if get_external_id(by_id.get(t, {}))]
        seqs.append(seq)
    return seqs


# ── LCS (dynamic programming) ────────────────────────────────────────────────

def lcs_length(a, b):
    """Standard DP LCS between two lists."""
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


def compute_lcs_stats(seqs):
    """Compute pairwise LCS lengths and return (mean, median, max)."""
    lengths = []
    pairs = list(combinations(range(len(seqs)), 2))
    for i, j in pairs:
        if len(seqs[i]) == 0 or len(seqs[j]) == 0:
            continue
        l = lcs_length(seqs[i], seqs[j])
        lengths.append(l)

    if not lengths:
        return 0.0, 0.0, 0

    mean_l = statistics.mean(lengths)
    median_l = statistics.median(lengths)
    max_l = max(lengths)
    return mean_l, median_l, max_l


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Compute silhouette and LCS stats for STICKS Paper 1."
    )
    parser.add_argument(
        "--bundle",
        default="data/stix/enterprise-attack.json",
        help="Path to the Enterprise STIX bundle JSON.",
    )
    parser.add_argument(
        "--k", type=int, default=7, help="Number of k-means clusters (default: 7)."
    )
    parser.add_argument(
        "--output-latex",
        action="store_true",
        help="Print \\newcommand lines for direct pasting into values.tex.",
    )
    args = parser.parse_args()

    print(f"[analyze_campaigns] Loading bundle: {args.bundle}", file=sys.stderr)
    by_id, campaigns, techniques, relationships = load_bundle(args.bundle)
    print(
        f"[analyze_campaigns] Active campaigns: {len(campaigns)}, "
        f"techniques: {len(techniques)}",
        file=sys.stderr,
    )

    fwd = build_fwd_index(relationships)
    camp_ids, camp_techs, tech_ids = campaign_technique_sets(campaigns, by_id, fwd)

    # Drop campaigns with zero techniques (can't cluster)
    nonempty = [(ct, cid) for ct, cid in zip(camp_techs, camp_ids) if len(ct) > 0]
    camp_techs_ne = [x[0] for x in nonempty]
    camp_ids_ne = [x[1] for x in nonempty]
    print(
        f"[analyze_campaigns] Campaigns with ≥1 technique: {len(camp_techs_ne)}",
        file=sys.stderr,
    )

    # ── Clustering ──────────────────────────────────────────────────────────
    k = args.k
    matrix = build_feature_matrix(camp_techs_ne, tech_ids)
    print(f"[analyze_campaigns] Running k-means (k={k})…", file=sys.stderr)
    labels, _ = kmeans(matrix, k=k, seed=42)
    sil = silhouette_coefficient(matrix, labels)
    sil_rounded = round(sil, 2)

    cluster_counts = defaultdict(int)
    for lab in labels:
        cluster_counts[lab] += 1
    print(
        f"[analyze_campaigns] Cluster sizes: {dict(sorted(cluster_counts.items()))}",
        file=sys.stderr,
    )
    print(f"[analyze_campaigns] Silhouette coefficient: {sil:.4f}", file=sys.stderr)

    # ── LCS ─────────────────────────────────────────────────────────────────
    print("[analyze_campaigns] Computing pairwise LCS…", file=sys.stderr)
    seqs = campaign_technique_sequences(camp_techs_ne, by_id)
    lcs_mean, lcs_median, lcs_max = compute_lcs_stats(seqs)
    lcs_mean_r = round(lcs_mean, 1)
    lcs_median_r = round(float(lcs_median), 1)

    print(
        f"[analyze_campaigns] LCS: mean={lcs_mean_r}, median={lcs_median_r}, max={lcs_max}",
        file=sys.stderr,
    )

    # ── Output ──────────────────────────────────────────────────────────────
    if args.output_latex:
        print(f"\\newcommand{{\\silhouetteScore}}{{{sil_rounded}}}")
        print(f"\\newcommand{{\\lcsLengthMean}}{{{lcs_mean_r}}}")
        print(f"\\newcommand{{\\lcsLengthMedian}}{{{lcs_median_r}}}")
        print(f"\\newcommand{{\\lcsLengthMax}}{{{lcs_max}}}")
    else:
        print(f"\nResults (k={k}):")
        print(f"  silhouetteScore  = {sil_rounded}")
        print(f"  lcsLengthMean    = {lcs_mean_r}")
        print(f"  lcsLengthMedian  = {lcs_median_r}")
        print(f"  lcsLengthMax     = {lcs_max}")
        print(
            "\nTo paste into ACM CCS - Paper 1/results/values.tex, run with --output-latex"
        )


if __name__ == "__main__":
    main()

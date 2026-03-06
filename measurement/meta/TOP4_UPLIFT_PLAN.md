# Top-4 Uplift Plan (Measurement-Backed)

## Goal
Increase contribution strength using only claims that are directly reproducible from the measurement pipeline.

## Already Implemented
- Full STIX measurement pipeline with deterministic outputs.
- Traceability map from paper claims to result artifacts.
- Initial Access measurement (campaign coverage, social proxy, CVE overlap).
- CVE split between actionable evidence and illustrative technique examples.
- Minimum-evidence confusion curve for SUT profile specificity.

## Next High-Impact Implementations
1. Add confidence intervals for key rates (campaign CVE rate, software version rate, confusion rate).
2. Add sensitivity sweep for Jaccard threshold delta (e.g., 0.05, 0.10, 0.15).
3. Add bootstrap stability test for uniqueness/confusion estimates.
4. Add taxonomy ablation: software-only vs software+CVE vs software+platform for profile specificity.
5. Add reproducibility manifest hash (bundle SHA256 + output SHA256).
6. Add automated claim-check script that fails if manuscript numbers diverge from `todo_values_latex.tex`.
7. Add explicit threats-to-validity checks generated from measured limitations (missing software links, missing version/CPE, zero vulnerability SDOs).

## Non-goals
- No unmeasured attribution claim.
- No manual number insertion in manuscript.
- No external conjecture about vendor security posture.

## Acceptance Criteria
- Every quantitative statement in Analysis/Discussion maps to one metric key and one audit artifact.
- Release check passes in one command (`./measurement/sut/release_check.sh`).
- Manuscript compiles and uses generated macros only.

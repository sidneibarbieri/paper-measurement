# Rewrite-Ready Edits (Phase 2)

## 1) Evaluation-dependence claim
- Location: `Introduction`
- Before: "APT detection systems are only evaluated against techniques that can actually reach a target"
- After: "APT detection systems are meaningfully evaluated only for techniques that can actually reach a target"
- Why: removes absolute wording risk and improves scientific defensibility.

## 2) ATT&CK adoption claim
- Location: `Introduction`
- Before: "most widely adopted structured CTI standard"
- After: "widely adopted as a structured CTI standard"
- Why: avoids unverifiable superlative while preserving the argument.

## 3) Core novelty claim (exhaustive wording)
- Location: `Related Work` (The gap this paper fills)
- Before: "None measures whether ... not measured anywhere in the literature"
- After: "To the best of our knowledge, prior studies do not explicitly measure whether ... not systematically measured in this problem setting"
- Why: narrows scope, avoids brittle universal claims, keeps top-tier rigor.

## 4) Critical STIX citation TODO hardening
- Location: `Background` (STIX representation)
- Added: explicit TODO to replace `stixspec` by official OASIS STIX 2.1 reference in `references.bib` and verify metadata.
- Why: makes the blocker actionable for camera-ready.

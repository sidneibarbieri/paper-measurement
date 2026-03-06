# Claim Strength Audit (Phase 2)

Scope: `Introduction`, `Related Work`, `Discussion` in `main.tex`.
Scale: `Strong` (direct evidence), `Medium` (reasonable inference), `Weak` (overclaim risk).

## Introduction
- [main.tex:334] Counts for ATT&CK scope (`835/187/52`) -> **Medium**
  - Evidence: ATT&CK-adoption sources support context, but exact counts are version-sensitive.
  - Action: Keep as scoped to `v18.1` and verify in final dataset appendix.
- [main.tex:356] "Automated SUT generation ... not feasible" -> **Strong**
  - Evidence: This is the measured thesis and is tied to analysis sections.
- [main.tex:361] "Frameworks leave SUT instantiation to analyst" -> **Strong**
  - Evidence: Multiple emulation/tooling references and framework design assumptions.
- [main.tex:363] "Detection evaluated only on reachable techniques" -> **Medium**
  - Evidence: Strongly supported by provenance detection literature; wording remains broad.
  - Action: Acceptable with current citation bundle.
- [main.tex:365] Attribution ambiguity under overlap/incomplete reporting -> **Strong**
  - Evidence: Practitioner + longitudinal papers.
- [main.tex:389] "most widely adopted structured CTI standard" -> **Medium**
  - Evidence: widely accepted claim but not a formal benchmark.
  - Action: keep; avoid adding superlatives elsewhere.

## Related Work
- [main.tex:551] Coverage depends on representable telemetry/behaviors -> **Strong**
  - Evidence: multi-paper provenance detection set.
- [main.tex:557] CTI extraction pipelines improve behavioral structuring -> **Strong**
  - Evidence: SoK + extraction/graph-construction papers.
- [main.tex:560] Extraction lines prioritize "what" not "where" -> **Medium**
  - Evidence: Inference from scope of cited methods.
  - Action: kept as scoped observation, not absolute statement.
- [main.tex:565] Attribution practice prioritizes context over naming actors -> **Strong**
  - Evidence: interview-based practitioner study.
- [main.tex:569] Longitudinal reports are heterogeneous in granularity -> **Strong**
  - Evidence: decade-scale APT dossier analysis.
- [main.tex:580] "None derives environment specifications from CTI automatically" -> **Medium**
  - Evidence: supported by surveyed frameworks; still an exhaustive-style statement.
  - Action: acceptable within reviewed set; revisit if new contrary source appears.
- [main.tex:598] "None measures ... environmental information" -> **Medium**
  - Evidence: supported within scoped corpus; exhaustive wording retained but narrowed by next sentence.
- [main.tex:604] "to the best of our knowledge" qualifier -> **Strong (mitigation)**
  - Action applied to reduce overclaim risk.

## Discussion
- [main.tex:988] "structured CTI provides only partial information" -> **Strong**
  - Evidence: direct summary of measured results.
- [main.tex:992] "not feasible from CTI alone" -> **Strong**
  - Evidence: direct consequence of RQ1/RQ2 metrics.
- [main.tex:1003] "non-trivial fraction require VM/infrastructure" -> **Strong**
  - Evidence: direct from compatibility table.
- [main.tex:1016] "profiles not specific enough for unique actor" -> **Strong**
  - Evidence: direct from RQ3 confusion analysis.
- [main.tex:1058] "schema carries no SUT compatibility field" -> **Medium/Strong**
  - Evidence: schema-level observation; final camera-ready should include precise STIX citation.

## Conclusion
- [main.tex:1088] "to the best of our knowledge, first measurement" -> **Medium (mitigated)**
  - Action applied: added explicit qualifier.

## Applied Edits in This Phase
- Added overclaim-mitigation qualifiers:
  - [main.tex:604]
  - [main.tex:1088]
- Preserved citation consistency: no missing keys after edits.

## Remaining High-Priority Editorial TODO
- [main.tex:462] `stixspec` is flagged in-text as unresolved and must be replaced by the correct STIX standard reference before submission.

# Deep Read Claim-Evidence Map (Paper 2)

## Scope
Progressive deep read focused on the must-cite set for Paper 2 (CTI/ATT&CK/SUT axis), using abstract/introduction evidence from local PDFs.

## Claim -> Evidence

1. Claim: Public CTI sharing in STIX is increasing but structurally uneven in quality/coverage.
- Evidence: `jin2024sharing`
- Why: Empirical STIX-sharing measurement (volume, timeliness, quality, object distribution).

2. Claim: Automated CTI extraction pipelines improve behavioral structuring but do not solve environment derivation.
- Evidence: `marvin2025sokttp`, `xu2024intelex`, `savat2021extractor`, `cheng2025ctinexus`
- Why: Focus on TTP/knowledge extraction from reports, not SUT instantiation constraints.

3. Claim: ATT&CK coverage is widely used in endpoint evaluation but is not a complete security metric.
- Evidence: `apurva2024mitre`, `10.1145/3634737.3645012`, `dong2023arewe`
- Why: ATT&CK labeling/coverage inconsistencies and operational limitations in deployment/evaluation.

4. Claim: Provenance-based APT detection literature is strong but evaluates detectability under telemetry/graph assumptions.
- Evidence: `milajerdi2019holmes`, `han2020unicorn`, `feng2023distdet`, `fanyang2023prographer`, `li2024nodlink`, `zian2024magic`, `zhang2025tapas`, `aly2025ocrapt`
- Why: Detection efficacy is conditioned on representable system traces and graph modeling choices.

5. Claim: Lateral-movement and attack-investigation methods reinforce deployment complexity beyond simple containers.
- Evidence: `lv2024trec`, `10646673`, `10646725`, `king2023euler`, `khoury2024jbeil`
- Why: Multi-host provenance and temporal graph dependencies imply stronger environment requirements.

6. Claim: Attribution in practice remains ambiguity-prone and evidence-fragmented.
- Evidence: `saha2025expert`, `yuldoshkhujaev2025decade`
- Why: Practitioner and longitudinal perspectives both report heterogeneity/incompleteness of evidence.

7. Claim: Structured CTI currently has a procedural gap; this work addresses the orthogonal environmental gap.
- Evidence: `ferraz2026proceduralsemanticsgapstructured`
- Why: Companion paper establishes the "how-to-execute" deficiency; Paper 2 targets "where-to-execute".

8. Claim: Emulation frameworks generally assume a prepared environment rather than deriving it from CTI.
- Evidence: `applebaum2016caldera`, `redcanary2023art`, `orbinato2024laccolith`, `damodaran2025automated`, `wang2024sands`
- Why: Execution tooling is present, but environment synthesis from structured CTI remains manual/heuristic.

## Risks Found and Applied Fixes
- Fixed a high-risk attribution issue: removed unsupported numeric specificity claim (34%/73%/24%) previously linked to `saha2025expert`.
- Reframed that paragraph to defensible practitioner + longitudinal evidence (`saha2025expert`, `yuldoshkhujaev2025decade`).
- Kept STIX normative citation explicitly flagged as unresolved TODO in `main.tex`.

## Editorial Guardrails (for next passes)
- Use multi-citation bundles only for broad claims; avoid citation inflation in local, narrow claims.
- Prefer top-4 and arXiv references already in `references.bib`; keep posters excluded from citation claims.
- For any numeric statement, ensure one directly supporting source and avoid transitive inference.

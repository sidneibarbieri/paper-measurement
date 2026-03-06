# Deep Read Findings Snippets (Must-Cite)

## 2024 - NDSS - Sharing Cyber Threat Intelligence Does It Really Help - doi02424228.pdf
- We propose a framework named CTI-Lense to collect and analyze the volume, timeliness, coverage, and quality of Structured Threat Information eXpression (STIX) data, a de facto standard CTI format, from a list of publicly available CTI sources.
- Based on our findings, we recommend practical considerations for effective and scalable STIX data sharing among organizations.
- We evaluate the quality of the values contained in the STIX data from two aspects: correctness and completeness.
- We find that URL objects are typically disseminated promptly, with approximately 72% and 88% of URLs shared either before or on the same day as their appearance on VirusTotal and HybridAnalysis, respectively.
- We analyze the distribution of STIX objects and attributes in a large dataset of publicly available STIX data.
- We evaluate improper usage by investigating whether values are incorrectly assigned to improper objects or attributes when they exist (see Section VII).

## 2024 - arXiv - IntelEX LLM driven Attack level Threat Intelligence Extraction.pdf
- To bridge this gap, we propose IntelEX (Intelligence Extraction), an automated tool designed to extract structural, attack-level intelligence by identifying logical attack sequences—including tactics, techniques, and procedures (TTPs)—and contextual insights.
- We systematically evaluate IntelEX’s performance using 1,769 newly crawled reports in the real world and 16 manually labeled and calibrated reports.
- We propose IntelEX (Intelligence Extraction) framework, which extracts the attack-level intelligence details (i.e., TTPs) with contextual insights.
- The experimental results show that the generated rules can achieve up to 0.929 F1 score in catching the malicious events/logs, significantly outperforming that without TTPs.
- Experimental results show that our generated rules can signficant outperform existing open-sourced rule sets either from Sigma or Splunk in detecting malicious security events in the wild.
- Second, we evaluate whether our generated procedures can help red teams reproduce and simulate attacks.

## 2025 - USENIXSec - Sok Automated Ttp Extraction CTI Reports Are We There.pdf
- From this table, we find that approaches leverage different subsets of discussed techniques making it difficult to assess the influence of individual steps.
- We evaluate the performance of NER using the TRAM2 dataset as discussed in Section 3.2.
- However, this also results in a lower recall compared to the other approaches, where we find that components sacrifice precision for an increase in recall.
- Finally, we find that disabling the related word component can actually improve performance in terms of both precision and F1-score, meaning that synonyms may not always be relevant when detecting named entities.
- Following a similar approach, we evaluate only the data augmentation optimization, as commonly proposed in the literature [35, 45, 80, 100].
- In conclusion, our results show that a direct comparison of these works with their customized optimizations is not appropriate, and emphasize the need to focus on the underlying core NLP methods in order to be able to make generalizable statements.

## 2024 - USENIXSec - How Endpoint Detection Uses MITRE ATTACK Framework.pdf
- Combined, our findings highlight the limitations of overdepending on ATT&CK coverage when evaluating security posture; most notably, many techniques are unrealizable as detection rules, and coverage of an ATT&CK technique does not consistently imply coverage of the same real-world threats.
- We find that products do not attempt to cover all ATT&CK techniques, with coverage ranging from 48% to 55%.
- Finally, in addition to the total coverage of techniques between products being fairly consistent, we find that the products have similar preferences for which ATT&CK techniques to cover with statistical significance.
- Examining 37 malicious entities that are explicitly referenced in at least two rulesets, we find that vendors are applying ATT&CK technique labels in equally-valid but inconsistent ways.
- We conclude by discussing the implications of our findings for the enterprise security ecosystem at large.
- We find that ATT&CK, while useful for explanation purposes, is a poor measure of the detection capabilities of an endpoint detection product.

## 2025 - CCS - Decade long Landscape Advanced Persistent Threats Longitudinal Analysis - doi73765085.pdf
- We systematically analyze six reliable sources— three focused on technical reports and another three on threat actors— examining 1,509 APT dossiers (i.e., totaling 24,215 pages) spanning from 2014 to 2023 (a decade), and identifying 603 unique APT groups in the world.
- Furthermore, we present our findings through interactive visualization tools, such as an APT map or a flow diagram, to facilitate intuitive understanding of the global patterns and trends in APT activities.
- 2 Vulnerability-wise, while the exploited CVEs are highly severe (average score of 8.5), our findings indicate that many of the attacks do not need to rely on zero-day vulnerabilities to be successful, which peaked between 2014 and 2016 but has declined thereafter.
- Our findings reveal global trends and key insights, including that the campaigns have affected 80% of countries worldwide; a small number of actors are responsible for a disproportionate share of attacks; and the exploitation of both zero-day and one-day vulnerabilities is prevalent.
- Out of 2,563 TRs, we analyze 1, 509 unique TRs (after removing 1, 003 duplicates and 51 APT trend dossiers), along with 177 news articles.
- To this end, we evaluate three popular LLMs: Gemini-1.5-Flash [7], GPT-4o [44], and GPT-4-Turbo [81] with the same prompt and questions.

## 2023 - CCS - Are we there yet Industrial Viewpoint Provenance based.pdf
- These results show that EDR systems have the potential to replace the EDR systems and become the dominating security defense systems for advanced cyber attacks.
- These results show that future research efforts should focus on optimizing the operating cost of P-EDR systems on both the client-side and the server-side.
- 2.3 Example Provenance Analysis In Figure 2, we show an example of the provenance graph for a real APT attack.
- The results show that most of the reported values are much higher than the reference values we obtained (< 20MB/host), except for RAPID [46].
- Similarly, a small set of papers provide evaluations for part of the four factors, and their results show that these systems fail to satisfy the reference values obtained from our studies.
- Particularly, we find that Auditd introduces a significant overhead because it uses Netlink and has heavy processing logic.

## 2024 - NDSS - Nodlink Online System Fine Grained APT Attack Detection Investigation.pdf
- To utilize the frameworks of the STP approximation algorithm for APT attack detection, we propose a novel design of in-memory cache, an efficient attack screening method, and a new STP approximation algorithm that is more efficient than the conventional one in APT attack detection while maintaining the same complexity.
- We evaluate N OD L INK with an open-world setting in the production environments of customers of Sangfor, including hospitals, universities, and factories.
- In this paper, we propose the FIRST online detection system that achieves fine-grained detection while maintaining detection accuracy under the constraints of timeliness and limited resources.
- Thus, to address this fundamental limitation, we propose to model the provenance graph construction (step ② of provenance detection) as an STP (Steiner Tree Problem) [49], [51], which is effective in modeling multiple goals and has efficient online approximation solutions with theoretical bounded errors.
- Instead, we propose a novel SPT framework that is more efficient while maintaining the approximation error.
- To solve this problem, we propose a novel in-memory cache design with a scoring method to prioritize • We model the APT detection as the online STP, which provides a new vision in online APT detection.

## 2024 - USENIXSec - MAGIC Detecting Advanced Persistent Threats.pdf
- We evaluate MAGIC on three widely-used datasets, including both real-world and simulated attacks.
- Evaluation results show that MAGIC is able to perform entity-level APT detection with 97.26% precision and 99.91% recall as well as minimum overhead, less memory demanding and significantly faster than state-of-the-art approaches (e.g.
- In summary, this paper makes the following contributions: • We propose MAGIC, a universal APT detection approach based on masked graph representation learning and outlier detection methods, capable of performing multi-granularity detection on massive audit logs.
- • We evaluate MAGIC on three widely-used datasets, involving both real-world and simulated APT attacks.
- Evaluation results show that MAGIC detects APTs with promising results and minimum computation overhead.
- To illustrate, we show how our noise reduction combines multi-edges and how it affects the edge initial embeddings in Figure 3 (II an III).

## 2025 - CCS - OCR APT Reconstructing APT Stories from Audit Logs.pdf
- Our contributions can be summarized as follows: • We propose a GNN-based anomaly detection model combined with a one-class classification to accurately identify anomalous nodes and APT-related subgraphs in provenance graphs.
- Our Approach: To address the above challenges, we propose OCR-APT1 , a novel system that performs end-to-end reconstruction of APT stories from audit logs.
- We evaluate OCR-APT on three provenance graph datasets: DARPA TC3 [18], OpTC [19], and NODLINK [46].
- The judge LLM selects the most critical IOC per node type using 𝑝 judg (lines 17–18): 𝐼𝑂𝐶 = 𝑓 (𝑅comp, 𝑝 judg ) Datasets We evaluated our system on three datasets: DARPA Transparent Computing Engagement 3 (TC3) [18], DARPA Operationally Transparent Cyber (OpTC) [19], and NODLINK simulated dataset [46].
- Finally, we evaluate the quality of our LLM-based investigation by comparing generated reports to ground truth reports from simulated attacks.
- The results show that subgraph detection improves 7.4.3 Hyperparameter Tuning.

## 2025 - USENIXSec - Expert Insights into Advanced Persistent Threats Analysis Attribution Challenges - id52e4b9f9.pdf
- We find that practitioners typically prioritize understanding the adversary’s tactics, techniques, procedures (TTPs), and motivations over identifying the specific entity behind an attack.
- To address this limitation, we ensure careful interpretation of our qualitative results and do not attempt to generalize our findings.
- To enrich our findings, we include incident and organizational detail whenever participants provided them.
- Apart from this, we did not observe clear differences in themes across the reported roles, suggesting that our findings apply broadly across different aspects of the work.
- Instead, we analyzed the goals and technical aspects of attribution and how it informs incident response.
- Our findings highlight a disconnect between theories and practical realities, identifying that victim organization progresses through three distinct layers of increasing classification specificity depending on the incident and their situation.

## 2025 - USENIXSec - TAPAS Efficient Online APT Detection Task Guided Segmentation.pdf
- To address these challenges, we propose TAPAS, an efﬁcient online APT detection framework that reduces graph dimensionality in both spatial and temporal spaces.
- Our results show that TAPAS reduces storage requirements by up to 1806× and achieves 99.99% accuracy with an average detection time of 12.78 seconds per GB of audit data, validating its practicality for enterprise deployment with throughputs well above the enterprise requirement of 104 KB/s.
- Building upon our key insights of spatial and temporal dimensional reduction in the APT provenance graph, we propose an efﬁcient online APT detection framework TAPAS, which achieves a low computational cost of detection to improve usability in real-world environments while exhibiting high detection performance.
- • We evaluate TAPAS on widely-used public datasets and compare it with SOTA studies.
- The results show that TAPAS can signiﬁcantly reduce detection overhead while accurately detecting attacks.
- To validate these insights empirically, we analyzed realworld data from the DARPA datasets (detailed in Section 5.1).

## 2026 - ASIACCS - The Procedural Semantics Gap Structured CTI.pdf
- In this work, we systematically analyze threat group profiles built from two public CTI knowledge bases: MITRE ATT&CK and Malpedia.
- We find that only 34% of threat groups in ATT&CK have group-specific techniques, limiting the use of techniques as reliable behavioral signatures to identify the threat group behind an attack.
- Next, we evaluate how group profiles improve when data from both sources are combined.
- Our findings raise concerns about the specificity of existing behavioral profiles and highlight the need for caution, as well as further improvement, when using them for threat group attribution.
- We find two knowledge bases satisfying those properties: MITRE’s Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) [28] and Malpedia [15].
- We find only 522 report URLs shared between ATT&CK and Malpedia, resulting in a low Jaccard Index of 3.2%, indicating minimal overlap in referenced sources.

## 2026 - arXiv - Procedural Semantics Gap Structured CTI APT Emulation - 2512_12078v2.pdf
- Through systematic measurements of the ATT&CK Enterprise bundle, we show that campaign objects encode just fragmented slices of behavior.
- We demonstrate its viability by instantiating the resulting steps as operations in the MITRE Caldera framework.
- We evaluate the extent to which current STIXencoded ATT&CK data contains (or lacks) the procedural semantics required for automated emulation.
- formed into machine-actionable representations for multi-stage adversary we propose a three-stage methodology defined 6.3 Stageemulation, 3: Emulation Integration at an abstract level.
- These results show that descriptive CTI can support reproducible execution chains: single-host or multi-host, depending on the campaign, when supplemented with analystdriven reconstruction of missing procedural elements.
- Our findings should therefore be viewed as a boundary-mapping study: they quantify what current structured CTI can support and, equally notably, what it cannot.

## 2024 - AsiaCCS - Decoding MITRE Engenuity ATTACK Enterprise Evaluation Analysis EDR.pdf
- Besides, we analyze MITRE evaluation’s results over multiple years from various aspects, including detection coverage, detection confidence, detection modifier, data source, compatibility, etc.
- Through the above studies, we have compiled a thorough summary of our findings and gained valuable insights from the evaluation results.
- To address these problems, we propose analysis methodologies on the MITRE evaluation dataset to perform fine-grained wholegraph analysis and holistic assessments of EDR systems’ capabilities.
- We evaluate EDR systems’ attack reconstruction capability by conducting the connectivity analysis, examining whether the EDR system can reconstruct the complete attack kill chain.
- • We propose a new evaluation metric and identify and highlight flaws in EDR systems.
- Besides, instead of the detection-related information, the results show what kind of protection is triggered at each step.


# Deep Read Notes - Must-Cite Set

## 2024 - NDSS - Sharing Cyber Threat Intelligence Does It Really Help - doi02424228.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/01_CTI_STIX/2024 - NDSS - Sharing Cyber Threat Intelligence Does It Really Help - doi02424228.pdf`

Title guess: Sharing cyber threat intelligence:

Abstract/early-text snippet:

Abstract—The sharing of Cyber Threat Intelligence (CTI) across organizations is gaining traction, as it can automate threat analysis and improve security awareness. However, limited empirical studies exist on the prevalent types of cybersecurity threat data and their effectiveness in mitigating cyber attacks. We propose a framework named CTI-Lense to collect and analyze the volume, timeliness, coverage, and quality of Structured Threat Information eXpression (STIX) data, a de facto standard CTI format, from a list of publicly available CTI sources. We collected about 6 million STIX data objects from October 31, 2014 to April 10, 2023 from ten data sources and analyzed their characteristics. Our analysis reveals that STIX data sharing has steadily increased in recent years, but the volume of STIX data shared is still relatively low to cover all cyber threats. Additionally, only a few types of threat data objects have been shared, with malware signatures and URLs accounting for more than 90% of the collected data. While URLs are usually shared promptly, with about 72% of URLs shared earlier than or on the same day as VirusTotal, the sharing of malware signatures is significantly slower. Furthermore, we found that 19% of the Threat actor data contained incorrect information, and only 0.09% of the Indicator data provided security rules to detect cyber attacks. Based on our findings, we recommend practical considerations for effective and scalable STIX data sharing among organizations. I. I NTRODUCTION Cyber attacks have increased in number, and their risks are becoming more severe [1]. A recent report [20] reveals a 435% increase in the number of ransomware attacks from 2019 to 2020. It is also reported that 68% of industry practitioners felt that cybersecurity risks would 

Keyword hits: att&ck, mitre, stix, cti, advanced persistent, vulnerability, cve

---

## 2024 - arXiv - IntelEX LLM driven Attack level Threat Intelligence Extraction.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/01_CTI_STIX/2024 - arXiv - IntelEX LLM driven Attack level Threat Intelligence Extraction.pdf`

Title guess: IntelEX: A LLM-driven Attack-level Threat Intelligence Extraction Framework

Abstract/early-text snippet:

Abstract—To combat increasingly sophisticated cyberattacks, a common practice is to transform unstructured cyber threat intelligence (CTI) reports into structured intelligence, facilitating downstream security tasks such as summarizing detection rules or simulating attack scenarios for red team exercises. However, existing threat intelligence often remains at the technique-level details, lacking critical attack-level insights, such as the use of specific techniques across different attack stages, detailed implementation procedures and contextual reasons, which are crucial for rapid investigation and analysis. To bridge this gap, we propose IntelEX (Intelligence Extraction), an automated tool designed to extract structural, attack-level intelligence by identifying logical attack sequences—including tactics, techniques, and procedures (TTPs)—and contextual insights. Specifically, IntelEX leverages the in-context learning capabilities of large language models (LLMs), enhanced with an external intelligence vector database, to pinpoint fine-grained attack details. Additionally, IntelEX introduces a novel LLM-as-a-judgment module to mitigate hallucination issues, reducing false positives. We systematically evaluate IntelEX’s performance using 1,769 newly crawled reports in the real world and 16 manually labeled and calibrated reports. Experimental results highlight IntelEX’s effectiveness in identifying attack-level intelligence. Specifically, IntelEX identifies 3,591 techniques and achieves an average F1 score of 0.792 in identifying techniques, outperforming stateof-the-art approaches of AttackKG by 1.34x. Moreover, the extracted attack-level intelligence directly benefits downstream security tasks. We demonstrate its utility in two key application scenarios: (1) automated 

Keyword hits: att&ck, mitre, stix, cti, provenance, vulnerability, llm

---

## 2025 - USENIXSec - Sok Automated Ttp Extraction CTI Reports Are We There.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/01_CTI_STIX/2025 - USENIXSec - Sok Automated Ttp Extraction CTI Reports Are We There.pdf`

Title guess: SoK: Automated TTP Extraction from

Abstract/early-text snippet:

Abstract Cyber Threat Intelligence (CTI) plays a critical role in sharing knowledge about new and evolving threats. With the increased prevalence and sophistication of threat actors, intelligence has expanded from simple indicators of compromise to extensive CTI reports describing high-level attack steps known as Tactics, Techniques and Procedures (TTPs). Such TTPs, often classified into the ontology of the ATT&CK framework, make CTI significantly more valuable, but also harder to interpret and automatically process. Natural Language Processing (NLP) makes it possible to automate large parts of the knowledge extraction from CTI reports; over 40 papers discuss approaches, ranging from named entity recognition over embedder models to generative large language models. Unfortunately, existing solutions are largely incomparable as they consider decisively different and constrained settings, rely on custom TTP ontologies, and use a multitude of custom, inaccessible CTI datasets. We take stock, systematize the knowledge in the field, and empirically evaluate existing approaches in a unified setting for fair comparisons. We gain several fundamental insights, including (1) the finding of a kind of performance limit that existing approaches seemingly cannot overcome as of yet, (2) that traditional NLP approaches (possibly counterintuitively) outperform modern embedderbased and generative approaches in realistic settings, and (3) that further research on understanding inherent ambiguities in TTP ontologies and on the creation of qualitative datasets is key to take a leap in the field. 1 Introduction In today’s rapidly evolving cyber landscape, the sophistication and frequency of cyber threats are increasingly growing, challenging the ability of cybersecurity teams to anticipate, i

Keyword hits: att&ck, mitre, stix, cti, cve, llm

---

## 2024 - USENIXSec - How Endpoint Detection Uses MITRE ATTACK Framework.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/02_MITRE_ATTACK/2024 - USENIXSec - How Endpoint Detection Uses MITRE ATTACK Framework.pdf`

Title guess: How does Endpoint Detection use the

Abstract/early-text snippet:

Abstract MITRE ATT&CK is an open-source taxonomy of adversary tactics, techniques, and procedures based on real-world observations. Increasingly, organizations leverage ATT&CK technique “coverage” as the basis for evaluating their security posture, while Endpoint Detection and Response (EDR) and Security Indicator and Event Management (SIEM) products integrate ATT&CK into their design as well as marketing. However, the extent to which ATT&CK coverage is suitable to serve as a security metric remains unclear— Does ATT&CK coverage vary meaningfully across different products? Is it possible to achieve total coverage of ATT&CK? Do endpoint products that detect the same attack behaviors even claim to cover the same ATT&CK techniques? In this work, we attempt to answer these questions by conducting a comprehensive (and, to our knowledge, the first) analysis of endpoint detection products’ use of MITRE ATT&CK. We begin by evaluating 3 ATT&CK-annotated detection rulesets from major commercial providers (Carbon Black, Splunk, Elastic) and a crowdsourced ruleset (Sigma) to identify commonalities and underutilized regions of the ATT&CK matrix. We continue by performing a qualitative analysis of unimplemented ATT&CK techniques to determine their feasibility as detection rules. Finally, we perform a consistency analysis of ATT&CK labeling by examining 37 specific threat entities for which at least 2 products include specific detection rules. Combined, our findings highlight the limitations of overdepending on ATT&CK coverage when evaluating security posture; most notably, many techniques are unrealizable as detection rules, and coverage of an ATT&CK technique does not consistently imply coverage of the same real-world threats. 1 Introduction It is difficult to overstate the influenc

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, vulnerability, cve

---

## 2025 - CCS - Decade long Landscape Advanced Persistent Threats Longitudinal Analysis - doi73765085.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/02_MITRE_ATTACK/2025 - CCS - Decade long Landscape Advanced Persistent Threats Longitudinal Analysis - doi73765085.pdf`

Title guess: A Decade-long Landscape of Advanced Persistent Threats:

Abstract/early-text snippet:

Abstract CCS Concepts An advanced persistent threat (APT) refers to a covert and longterm cyberattack, typically conducted by state-sponsored actors, targeting critical sectors and often remaining undetected for long periods. In response, collective intelligence from around the globe collaborates to identify and trace surreptitious activities, generating substantial documentation on APT campaigns publicly available on the web. While a multitude of prior works predominantly focus on specific aspects of APT cases, such as detection, evaluation, cyber threat intelligence, and dataset creation, limited attention has been devoted to revisiting and investigating these scattered dossiers in a longitudinal manner. The objective of our study lies in filling the gap by offering a macro perspective, connecting key insights and global trends in the past APT attacks. We systematically analyze six reliable sources— three focused on technical reports and another three on threat actors— examining 1,509 APT dossiers (i.e., totaling 24,215 pages) spanning from 2014 to 2023 (a decade), and identifying 603 unique APT groups in the world. To efficiently unearth relevant information, we employ a hybrid methodology that combines rule-based information retrieval with large-language-model-based search techniques. Our longitudinal analysis reveals shifts in threat actor activities, global attack vectors, changes in targeted sectors, and the relationships between cyberattacks and significant events, such as elections or wars, which provides insights into historical patterns in APT evolution. Over the past decade, 154 countries have been affected, primarily using malicious documents and spear phishing as the dominant initial infiltration vectors, and a noticeable decline in zero-day exploitation s

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, vulnerability, cve, llm

---

## 2023 - CCS - Are we there yet Industrial Viewpoint Provenance based.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2023 - CCS - Are we there yet Industrial Viewpoint Provenance based.pdf`

Title guess: Published: 21 November 2023

Abstract/early-text snippet:

ABSTRACT alarm triage cost and interpretation cost; and (3) excessive serverside memory consumption. This paper’s findings provide objective data on the effectiveness of P-EDR systems and how much improvements are needed to adopt P-EDR systems in industry. Provenance-Based Endpoint Detection and Response (P-EDR) systems are deemed crucial for future Advanced Persistent Threats (APT) defenses. Despite the fact that numerous new techniques to improve P-EDR systems have been proposed in academia, it is still unclear whether the industry will adopt P-EDR systems and what improvements the industry desires for P-EDR systems. To this end, we conduct the first set of systematic studies on the effectiveness and the limitations of P-EDR systems. Our study consists of four components: a one-to-one interview, an online questionnaire study, a survey of the relevant literature, and a systematic measurement study. Our research indicates that all industry experts consider P-EDR systems to be more effective than conventional Endpoint Detection and Response (EDR) systems. However, industry experts are concerned about the operating cost of P-EDR systems. In addition, our research reveals three significant gaps between academia and industry: (1) overlooking client-side overhead; (2) imbalanced CCS CONCEPTS • Security and privacy → Intrusion detection systems. KEYWORDS Provenance-Based EDR, APT, systematic study, gaps ACM Reference Format: Feng Dong, Shaofei Li, Peng Jiang, Ding Li, Haoyu Wang, Liangyi Huang, Xusheng Xiao, Jiedong Chen, Xiapu Luo, Yao Guo, and Xiangqun Chen. 2023. Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools. In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS ’23), November 26–

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, vulnerability, cve

---

## 2024 - NDSS - Nodlink Online System Fine Grained APT Attack Detection Investigation.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2024 - NDSS - Nodlink Online System Fine Grained APT Attack Detection Investigation.pdf`

Title guess: N OD L INK: An Online System for Fine-Grained APT

Abstract/early-text snippet:

Abstract—Advanced Persistent Threats (APT) attacks have plagued modern enterprises, causing significant financial losses. To counter these attacks, researchers propose techniques that capture the complex and stealthy scenarios of APT attacks by using provenance graphs to model system entities and their dependencies. Particularly, to accelerate attack detection and reduce financial losses, online provenance-based detection systems that detect and investigate APT attacks under the constraints of timeliness and limited resources are in dire need. Unfortunately, existing online systems usually sacrifice detection granularity to reduce computational complexity and produce provenance graphs with more than 100,000 nodes, posing challenges for security admins to interpret the detection results. In this paper, we design and implement N OD L INK, the first online detection system that maintains high detection accuracy without sacrificing detection granularity. Our insight is that the APT attack detection process in online provenance-based detection systems can be modeled as a Steiner Tree Problem (STP), which has efficient online approximation algorithms that recover concise attack-related provenance graphs with a theoretically bounded error. To utilize the frameworks of the STP approximation algorithm for APT attack detection, we propose a novel design of in-memory cache, an efficient attack screening method, and a new STP approximation algorithm that is more efficient than the conventional one in APT attack detection while maintaining the same complexity. We evaluate N OD L INK in a production environment. The openworld experiment shows that N OD L INK outperforms two state-ofthe-art (SOTA) online provenance analysis systems by achieving magnitudes higher detection and investig

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, vulnerability, cve, llm

---

## 2024 - USENIXSec - MAGIC Detecting Advanced Persistent Threats.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2024 - USENIXSec - MAGIC Detecting Advanced Persistent Threats.pdf`

Title guess: MAGIC: Detecting Advanced Persistent Threats

Abstract/early-text snippet:

Abstract Advance Persistent Threats (APTs), adopted by most delicate attackers, are becoming increasing common and pose great threat to various enterprises and institutions. Data provenance analysis on provenance graphs has emerged as a common approach in APT detection. However, previous works have exhibited several shortcomings: (1) requiring attack-containing data and a priori knowledge of APTs, (2) failing in extracting the rich contextual information buried within provenance graphs and (3) becoming impracticable due to their prohibitive computation overhead and memory consumption. In this paper, we introduce MAGIC, a novel and flexible self-supervised APT detection approach capable of performing multi-granularity detection under different level of supervision. MAGIC leverages masked graph representation learning to model benign system entities and behaviors, performing efficient deep feature extraction and structure abstraction on provenance graphs. By ferreting out anomalous system behaviors via outlier detection methods, MAGIC is able to perform both system entity level and batched log level APT detection. MAGIC is specially designed to handle concept drift with a model adaption mechanism and successfully applies to universal conditions and detection scenarios. We evaluate MAGIC on three widely-used datasets, including both real-world and simulated attacks. Evaluation results indicate that MAGIC achieves promising detection results in all scenarios and shows enormous advantage over state-of-the-art APT detection approaches in performance overhead. 1 Introduction Advanced Persistent Threats (APTs) are intentional and sophisticated cyber-attacks conducted by skilled attackers and pose great threat to both enterprises and institutions [1]. Most APTs involve zero-day 

Keyword hits: cti, advanced persistent, provenance, vulnerability

---

## 2025 - CCS - OCR APT Reconstructing APT Stories from Audit Logs.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2025 - CCS - OCR APT Reconstructing APT Stories from Audit Logs.pdf`

Title guess: Total Downloads: 2494

Abstract/early-text snippet:

Abstract 1 Introduction Advanced Persistent Threats (APTs) are stealthy cyberattacks that often evade detection in system-level audit logs. Provenance graphs model these logs as connected entities and events, revealing relationships that are missed by linear log representations. Existing systems apply anomaly detection to these graphs but often suffer from high false positive rates and coarse-grained alerts. Their reliance on node attributes like file paths or IPs leads to spurious correlations, reducing detection robustness and reliability. To fully understand an attack’s progression and impact, security analysts need systems that can generate accurate, human-like narratives of the entire attack. To address these challenges, we introduce OCRAPT, a system for APT detection and reconstruction of human-like attack stories. OCR-APT uses Graph Neural Networks (GNNs) for subgraph anomaly detection, learning behavior patterns around nodes rather than fragile attributes such as file paths or IPs. This approach leads to a more robust anomaly detection. It then iterates over detected subgraphs using Large Language Models (LLMs) to reconstruct multi-stage attack stories. Each stage is validated before proceeding, reducing hallucinations and ensuring an interpretable final report. Our evaluations on the DARPA TC3, OpTC, and NODLINK datasets show that OCR-APT outperforms state-ofthe-art systems in both detection accuracy and alert interpretability. Moreover, OCR-APT reconstructs human-like reports that comprehensively capture the attack story. Advanced Persistent Threats (APTs) are among the most insidious forms of cyberattacks. Characterized by stealth, persistence, and adaptability, APTs often evade traditional security mechanisms by exploiting zero-day vulnerabilities and mainta

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, vulnerability, llm

---

## 2025 - USENIXSec - Expert Insights into Advanced Persistent Threats Analysis Attribution Challenges - id52e4b9f9.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2025 - USENIXSec - Expert Insights into Advanced Persistent Threats Analysis Attribution Challenges - id52e4b9f9.pdf`

Title guess: Expert Insights into Advanced Persistent Threats:

Abstract/early-text snippet:

Abstract Advanced Persistent Threats (APTs) are sophisticated and targeted threats that demand significant effort from analysts for detection and attribution. Researchers have developed various techniques to support these efforts. However, security practitioners’ perceptions and challenges in analyzing APTlevel threats are not yet well understood. To address this gap, we conducted semi-structured interviews with 15 security practitioners across diverse roles and expertise. From the interview responses, we identify a three-layer approach to APT attribution, each having its own goals and challenges. We find that practitioners typically prioritize understanding the adversary’s tactics, techniques, procedures (TTPs), and motivations over identifying the specific entity behind an attack. We also find challenges in existing tools and processes mostly stemming from their inability to handle diverse and complex data and issues with both internal and external collaboration. Based on these findings, we provide four recommendations for improving attribution approaches and discuss how these improvements can address the identified challenges. 1 Introduction Advanced Persistent Threats (APTs) have become a critical instrument of modern geopolitical warfare, allowing nationstates to conduct sophisticated cyber espionage and strategic intelligence. Cyber threat analysts regularly uncover APT campaigns targeting government agencies and private sector companies [15, 17, 65]. Attribution of these campaigns has exposed evolving and sophisticated adversaries that engage in espionage, theft of information, and disruption of services. In response, researchers and industry practitioners have advanced APT detection [20, 25, 26, 30, 36, 40] and attribution [56, 58, 59, 60, 69] emphasizing its cr

Keyword hits: att&ck, mitre, stix, cti, advanced persistent, provenance, vulnerability, cve, llm

---

## 2025 - USENIXSec - TAPAS Efficient Online APT Detection Task Guided Segmentation.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/04_APT_Detection_Attribution/2025 - USENIXSec - TAPAS Efficient Online APT Detection Task Guided Segmentation.pdf`

Title guess: TAPAS: An Efficient Online APT Detection with

Abstract/early-text snippet:

Abstract Advanced Persistent Threats (APTs) pose critical security challenges to institutions and enterprises through sophisticated, long-duration attack campaigns. While recent APT detection methods primarily leverage provenance graphs constructed from kernel-level audit logs to reveal attack patterns, they face severe scalability limitations in production environments. The provenance graphs grow rapidly (several GB per day) and require long-term maintenance to capture APT campaigns that span months, creating prohibitive storage and computational overhead for real-time detection. To address these challenges, we propose TAPAS, an efﬁcient online APT detection framework that reduces graph dimensionality in both spatial and temporal spaces. For spatial dimensionality, TAPAS focuses on the backbone of the provenance graph, which is often large-scale but sparse. Speciﬁcally, TAPAS constructs stacked LSTM-GRU models that iteratively update the representations of the backbone nodes based on relevant redundant nodes, replacing direct storage and computation of these redundancies. For temporal dimensionality, TAPAS designs a task-guided backbone graph segmentation algorithm that identiﬁes active subgraphs as objects to be detected in real-time, reducing structural redundancy in the temporal space. Evaluation in widely used benchmark datasets, DARPA TC and OpTC, demonstrates TAPAS’s effectiveness in providing fast, low-overhead online detection while maintaining similar detection accuracy to state-of-the-art methods. Our results show that TAPAS reduces storage requirements by up to 1806× and achieves 99.99% accuracy with an average detection time of 12.78 seconds per GB of audit data, validating its practicality for enterprise deployment with throughputs well above the enterpris

Keyword hits: cti, advanced persistent, provenance, vulnerability

---

## 2026 - ASIACCS - The Procedural Semantics Gap Structured CTI.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/99_Companion_Grupo/2026 - ASIACCS - The Procedural Semantics Gap Structured CTI.pdf`

Title guess: Kitten or Panda? Measuring the Specificity of Threat Group

Abstract/early-text snippet:

Abstract 1 In recent years, the cyber threat intelligence (CTI) community has invested significant effort in building knowledge bases that catalog threat groups. These knowledge bases associate each threat group with its observed behaviors, including their Tactics, Techniques, and Procedures (TTPs) as well as the malware and tools they employ during attacks. However, the distinctiveness and completeness of such behavioral profiles remain largely unexplored, despite being critical for tasks such as threat group attribution. In this work, we systematically analyze threat group profiles built from two public CTI knowledge bases: MITRE ATT&CK and Malpedia. We first investigate what fraction of threat groups have group-specific behaviors, i.e., behaviors used exclusively by a single group. We find that only 34% of threat groups in ATT&CK have group-specific techniques, limiting the use of techniques as reliable behavioral signatures to identify the threat group behind an attack. The software used by a threat group proves to be more distinctive, with 73% of ATT&CK groups using group-specific software. However, this percentage drops to 24% in the broader Malpedia dataset. Next, we evaluate how group profiles improve when data from both sources are combined. While coverage improves modestly, the proportion of groups with group-specific behaviors remains under 30%. We then enhance profiles by adding exploited vulnerabilities and additional techniques extracted from threat reports. Despite the additional information, 64% of groups still lack any group-specific behavior. Our findings raise concerns about the specificity of existing behavioral profiles and highlight the need for caution, as well as further improvement, when using them for threat group attribution. In recent years, 

Keyword hits: att&ck, mitre, stix, cti, advanced persistent, vulnerability, cve, llm

---

## 2026 - arXiv - Procedural Semantics Gap Structured CTI APT Emulation - 2512_12078v2.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/01_Essenciais_Paper2/99_Companion_Grupo/2026 - arXiv - Procedural Semantics Gap Structured CTI APT Emulation - 2512_12078v2.pdf`

Title guess: The Procedural Semantics Gap in Structured CTI: A

Abstract/early-text snippet:

Abstract Cyber threat intelligence (CTI) encoded in Structured Threat Information Expression (STIX) and structured according to the MITRE ATT&CK framework has become a global reference for describing adversary behavior. However, ATT&CK was designed as a descriptive knowledge base rather than a procedural model. We therefore ask whether its structured artifacts contain sufficient behavioral detail to support multi-stage adversary emulation. Through systematic measurements of the ATT&CK Enterprise bundle, we show that campaign objects encode just fragmented slices of behavior. Only 35.6% of techniques appear in at least one campaign, and neither clustering nor sequence analysis reveals any reusable behavioral structure under technique overlap or Longest Common Subsequence (LCS)-based analyses. Intrusion sets cover a broader portion of the technique space, yet omit the procedural semantics required to transform behavioral knowledge into executable chains, including ordering, preconditions, and environmental assumptions. These findings reveal a procedural semantic gap in current CTI standards: they describe what adversaries do, but not exactly how that behavior was operationalized. To assess how far this gap can be bridged in practice, we introduce a three-stage methodology that translates behavioral information from structured CTI into executable steps and makes the necessary environmental assumptions explicit. We demonstrate its viability by instantiating the resulting steps as operations in the MITRE Caldera framework. Case studies of ShadowRay and Soft Cell show that structured CTI can enable the emulation of multistage APT campaigns, but only when analyst-supplied parameters and assumptions are explicitly recorded. This, in turn, exposes ∗ These authors contributed equ

Keyword hits: att&ck, mitre, stix, cti, advanced persistent, provenance, emulation, vulnerability, llm

---

## 2024 - AsiaCCS - Decoding MITRE Engenuity ATTACK Enterprise Evaluation Analysis EDR.pdf
Path: `/Users/sidneibarbieri/paper measurement/papers repo/02_Suporte_Qualificado/Top4/2024 - AsiaCCS - Decoding MITRE Engenuity ATTACK Enterprise Evaluation Analysis EDR.pdf`

Title guess: Decoding the MITRE Engenuity ATT&CK Enterprise Evaluation:

Abstract/early-text snippet:

ABSTRACT KEYWORDS Endpoint detection and response (EDR) systems have emerged as a critical component of enterprise security solutions, effectively combating endpoint threats like APT attacks with extended lifecycles. In light of the growing significance of endpoint detection and response (EDR) systems, many cybersecurity providers have developed their own proprietary EDR solutions. It’s crucial for users to assess the capabilities of these detection engines to make informed decisions about which products to choose. This is especially urgent given the market’s size, which is expected to reach around 3.7 billion dollars by 2023 and is still expanding. MITRE is a leading organization in cyber threat analysis. In 2018, MITRE started to conduct annual APT emulations that cover major EDR vendors worldwide. Indicators include telemetry, detection and blocking capability, etc. Nevertheless, the evaluation results published by MITRE don’t contain any further interpretations or suggestions. In this paper, we thoroughly analyzed MITRE evaluation results to gain further insights into real-world EDR systems under test. Specifically, we designed a whole-graph analysis method, which utilizes additional control flow and data flow information to measure the performance of EDR systems. Besides, we analyze MITRE evaluation’s results over multiple years from various aspects, including detection coverage, detection confidence, detection modifier, data source, compatibility, etc. Through the above studies, we have compiled a thorough summary of our findings and gained valuable insights from the evaluation results. We believe these summaries and insights can assist researchers, practitioners, and vendors in better understanding the strengths and limitations of mainstream EDR products. EDR Sys

Keyword hits: att&ck, mitre, cti, advanced persistent, provenance, emulation

---


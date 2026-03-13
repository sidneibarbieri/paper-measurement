# STICKS — Structured CTI to Executable Emulation Pipeline

Companion artifact for two ACM CCS 2026 submissions:

- **Limits of Semantic CTI for Multi-Stage APT Emulation** — measures the procedural semantics gap between structured CTI and executable adversary behavior.
- **The Environment Semantics Gap in Structured CTI** — measures the environment semantics gap in SUT requirements for APT emulation.

## Prerequisites

- Python 3.9+
- [Caldera 5.3.0](https://caldera.mitre.org/) (for emulation execution)

```bash
pip install -r requirements.txt
```

## Configuration

All credentials and service endpoints are loaded from environment variables:

```bash
export CALDERA_URL="http://172.20.0.10:8888"
export CALDERA_USERNAME="red"
export CALDERA_PASSWORD="admin"
export CALDERA_API_KEY_RED="ADMIN123"
export GITHUB_TOKEN=""          # Optional: for higher GitHub API rate limits
```

Defaults are provided in `config/config.py` for the isolated testbed used in the papers.

## Usage

```bash
# Full pipeline: download STIX, extract APTs, generate Caldera abilities
python3 main.py init

# Remove generated data
python3 main.py clean

# Run a specific campaign emulation
python3 lib/run_campaign.py <campaign_name>
```

## Architecture

```
sticks/
  main.py                # Entry point: init, clean, help
  requirements.txt       # Python dependencies
  config/
    config.py            # Paths, URLs, credentials (env vars)
  lib/
    stix.py              # STIX bundle download, merge, and parsing
    campaign.py          # Campaign extraction and Caldera profile generation
    ability.py           # Caldera ability generation from ATT&CK techniques
    adversary.py         # Caldera adversary profile management
    operation.py         # Caldera operation creation and execution
    run_campaign.py      # End-to-end campaign emulation with DAG ordering
    command.py           # Caldera command execution and output retrieval
    agent.py             # Caldera agent management
    tools.py             # GitHub download utilities
  data/
    stix/                # Downloaded STIX bundles
    campaign/            # Extracted campaign ability files
    dag/                 # DAGs for campaign technique ordering
    caldera_abilities/   # Generated Caldera ability YAML files
    caldera_adversaries/ # Generated Caldera adversary profiles
    sut/                 # System Under Test specifications
```

## Three-Stage Methodology

The pipeline implements the three-stage methodology described in the papers:

1. **Stage 1 — Automated Structural Modeling**: Downloads STIX bundles, extracts campaigns and intrusion sets, constructs tactic-ordered technique lists.
2. **Stage 2 — Technique Translation Layer**: Human analyst translates technique descriptions into executable Caldera commands, documenting assumptions and environment bindings.
3. **Stage 3 — Emulation Integration**: Translated steps become Caldera abilities, assembled into adversary profiles and executed as operations.

## Validated Case Studies

| Campaign   | Techniques | Tactics Covered | Status    |
|------------|-----------|-----------------|-----------|
| ShadowRay  | 14        | 9               | Validated |
| Soft Cell  | 18        | 10              | Validated |
| APT41 DUST | 23        | 10              | Validated |

## Reproducibility

Experiments are conducted in a fully isolated virtual testbed:
- Debian GNU/Linux 13 VM hosting the Caldera server
- Kali Linux 2025.1c VM running the Caldera agent
- Private virtual network without outbound routing
- Clean snapshot restoration between operations

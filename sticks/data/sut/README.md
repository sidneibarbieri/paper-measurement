# MITRE ATT&CK System Under Test (SUT) Specifications

This directory contains SUT specifications for various MITRE ATT&CK campaigns.

## Directory Structure

```
sut/
├── <campaign_name>/
│   ├── sut.yaml          # Main SUT specification (YAML)
│   └── campaign_info.json # Campaign metadata
└── README.md
```

## Usage

Each `sut.yaml` describes the infrastructure required to run an adversary
emulation exercise for the corresponding MITRE ATT&CK campaign.

# config.py — STICKS configuration
#
# All credentials and service endpoints are loaded from environment
# variables. Hardcoded defaults are provided only for non-sensitive
# values used in the isolated emulation testbed.

import os
from pathlib import Path

# ── External service credentials (set via environment) ──────────────
AZURE_SECRET_KEY = os.environ.get("AZURE_SECRET_KEY", "")
AZURE_ENDPOINT = os.environ.get("AZURE_ENDPOINT", "")
AZURE_DEPLOYMENT = os.environ.get("AZURE_DEPLOYMENT", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# ── STIX source URL ─────────────────────────────────────────────────
STIX_URL = os.environ.get(
    "STIX_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json",
)

# ── Base data directory (relative to project root) ──────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# ── Derived paths ───────────────────────────────────────────────────
ATOMIC_RED_DIR = DATA_DIR / "atomic-red"
STIX_DIR = DATA_DIR / "stix"
APT_DIR = DATA_DIR / "stix_adversaries"
CALDERA_ABILITIES_DIR = DATA_DIR / "caldera_abilities"
CALDERA_ADVERSARIES_DIR = DATA_DIR / "caldera_adversaries"
STIX_FILE = STIX_DIR / "stix_full.json"
AGENT_PATH = DATA_DIR / "agents"

# ── Caldera server ──────────────────────────────────────────────────
CALDERA_URL = os.environ.get("CALDERA_URL", "http://172.20.0.10:8888")
CALDERA_USERNAME = os.environ.get("CALDERA_USERNAME", "red")
CALDERA_PASSWORD = os.environ.get("CALDERA_PASSWORD", "admin")
CALDERA_API_KEY_RED = os.environ.get("CALDERA_API_KEY_RED", "ADMIN123")

AGENT_PATHS = {
    "linux": "/tmp/master",
    "windows": r"C:\Temp\master.exe",
    "darwin": "/tmp/master_mac",
}

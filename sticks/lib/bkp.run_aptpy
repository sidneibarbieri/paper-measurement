import json
import requests
import sys
from pathlib import Path
import yaml
from stix2 import parse
from typing import List, Dict, Any
import re


project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    import config
except ImportError:
    print("❌ Could not import 'config' module. Make sure your PYTHONPATH includes the project root.")
    sys.exit(1)

CALDERA_URL = config.CALDERA_URL.rstrip("/")
API_KEY = getattr(config, "CALDERA_API_KEY_RED", None)
CALDERA_ADVERSARIES_DIR = getattr(config, "CALDERA_ADVERSARIES_DIR", None)
HEADERS = {
    "KEY": API_KEY,
    "Content-Type": "application/json"
}

def test_sources():
    url = f"{CALDERA_URL}/api/v2/sources"
    response = requests.get(url, headers=HEADERS, verify=False)
    if response.ok:
        print("Sources endpoint OK")
    else:
        print(f"Sources endpoint failed: {response.status_code} - {response.text}")

def fetch_agents():
    url = f"{CALDERA_URL}/api/v2/agents"
    response = requests.get(url, headers=HEADERS, verify=False)
    if response.ok:
        agents = response.json()
        print(f"Agents list:\n{json.dumps(agents, indent=2)}")
    else:
        print(f"Failed to fetch agents: {response.status_code} - {response.text}")

def main():
    print("Testing connection to Caldera API...")
    test_sources()
    fetch_agents()

if __name__ == "__main__":
    main()

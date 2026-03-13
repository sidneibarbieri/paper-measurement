import json
import requests
from pathlib import Path

CALDERA_URL = "http://127.0.0.1:8888"
API_KEY = "ADMIN123"   # change to your real key
ABILITIES_FILE = "data/backup/abilities.json"  # path to your exported abilities file

def restore_abilities():
    abilities_path = Path(ABILITIES_FILE)
    if not abilities_path.exists():
        print(f"❌ File not found: {ABILITIES_FILE}")
        return

    with open(abilities_path, "r", encoding="utf-8") as f:
        try:
            abilities = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse JSON: {e}")
            return

    if not isinstance(abilities, list):
        abilities = [abilities]  # wrap single ability in list

    headers = {
        "Content-Type": "application/json",
        "key": API_KEY
    }

    for ability in abilities:
        try:
            resp = requests.post(
                f"{CALDERA_URL}/api/v2/abilities",
                headers=headers,
                json=ability
            )
            if resp.status_code == 200:
                print(f"✅ Restored ability: {ability.get('name')} ({ability.get('ability_id')})")
            else:
                print(f"⚠️ Failed to restore {ability.get('name')}: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"❌ Error restoring {ability.get('name')}: {e}")

if __name__ == "__main__":
    restore_abilities()

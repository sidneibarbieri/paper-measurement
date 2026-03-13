# tools.py — GitHub download utilities for STICKS
import os
import sys
from pathlib import Path

import requests

try:
    import config
except ImportError as exc:
    print(f"Could not import 'config': {exc}")
    sys.exit(1)

HEADERS = {}
if getattr(config, "GITHUB_TOKEN", None):
    HEADERS["Authorization"] = f"token {config.GITHUB_TOKEN}"


def download_github_folder(
    owner: str,
    repo: str,
    folder_path: str,
    local_dir: str,
    branch: str = "main",
) -> None:
    """Recursively download a GitHub repository folder."""
    api_url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/contents/{folder_path}?ref={branch}"
    )
    resp = requests.get(api_url, headers=HEADERS, timeout=30)
    resp.raise_for_status()

    local_dir = Path(local_dir)
    local_dir.mkdir(parents=True, exist_ok=True)

    for item in resp.json():
        if item["type"] == "file":
            file_resp = requests.get(
                item["download_url"], headers=HEADERS, timeout=60,
            )
            file_resp.raise_for_status()
            (local_dir / item["name"]).write_bytes(file_resp.content)
            print(f"  downloaded {item['path']}")
        elif item["type"] == "dir":
            download_github_folder(
                owner,
                repo,
                f"{folder_path}/{item['name']}",
                local_dir / item["name"],
                branch,
            )

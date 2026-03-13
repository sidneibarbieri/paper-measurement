#!/usr/bin/env python3
"""STICKS — STIX-to-Caldera Emulation Pipeline.

Entry point for the STICKS pipeline that transforms MITRE ATT&CK STIX
bundles into executable Caldera operations for multi-stage APT emulation.
"""

import argparse
import shutil
import sys
from pathlib import Path

# Project root (where main.py lives)
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "lib"))
sys.path.insert(0, str(PROJECT_ROOT / "config"))

import config
import stix
import agent
import campaign
import intrusionSet
import ability


def ensure_dirs(*dirs: Path) -> None:
    """Create directories if they do not exist."""
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"  ensured directory: {directory}")


def clean_generated_data() -> None:
    """Remove generated Caldera adversaries and abilities."""
    for target in (config.CALDERA_ADVERSARIES_DIR, config.CALDERA_ABILITIES_DIR):
        if target.exists():
            shutil.rmtree(target)
            target.mkdir(parents=True, exist_ok=True)
            print(f"  cleaned {target}")


def run_init() -> None:
    """Execute the full STICKS pipeline."""
    ensure_dirs(
        config.STIX_DIR,
        config.APT_DIR,
        config.AGENT_PATH,
        config.CALDERA_ABILITIES_DIR,
    )

    print("\n[1/7] Downloading STIX data...")
    stix.download_all()

    print("\n[2/7] Downloading Atomic Red Team data...")
    ability.get_atomic()

    print("\n[3/7] Merging STIX files...")
    stix.merge_all_stix_files()

    print("\n[4/7] Extracting APT groups...")
    stix.extract_all_apts()

    print("\n[5/7] Generating abilities...")
    ability.generate_abilities_from_matrix()

    print("\n[6/7] Updating abilities with Atomic Red Team commands...")
    ability.translate_all_caldera_abilities()

    print("\n[7/7] Generating and uploading adversaries...")
    campaign.generate_campaigns()
    intrusionSet.generate_adversaries()
    campaign.upload_all_campaigns()
    intrusionSet.upload_all_adversaries()

    print("\nPipeline completed successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="STICKS: STIX-to-Caldera Emulation Pipeline",
    )
    parser.add_argument(
        "step",
        choices=["init", "clean", "help"],
        nargs="?",
        default="help",
        help="Pipeline step to execute (default: help)",
    )
    args = parser.parse_args()

    if args.step == "init":
        run_init()
    elif args.step == "clean":
        clean_generated_data()
    elif args.step == "help":
        print("Usage:")
        print("  python main.py init   — Run the full pipeline")
        print("  python main.py clean  — Remove generated data")
        print("  python main.py help   — Show this message")


if __name__ == "__main__":
    main()

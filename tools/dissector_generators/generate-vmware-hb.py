#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Moshe Kaplan
"""
Fetch VMware ESXi releases and update Wireshark dissector.

This script fetches the latest VMware ESXi release list from virten.net
and updates the vmware_hb_build_number value_string array in a Wireshark
source file.
"""

import argparse
import re
import requests


RELEASES_URL = "https://www.virten.net/repo/esxiReleases.json"

def fetch_releases(url: str) -> list[dict]:
    """Fetch and return ESXi releases sorted ascending by build number.

    Args:
        url: URL of the JSON endpoint that provides ESXi release data.

    Returns:
        A list of release dicts sorted by integer build number, each
        containing at least ``build`` and ``friendlyName`` keys.
        For example:
        { "build": "20842708", "friendlyName": "ESXi 7.0 Update 3i" }
    """
    response = requests.get(url, headers={ 'User-Agent': 'Wireshark vmware-hb.py'})
    response.raise_for_status()
    releases = response.json()["data"]["esxiReleases"]
    return sorted(releases, key=lambda r: int(r["build"]))


def update_dissector(c_file: str, releases: list[dict], dry_run: bool, quiet: bool) -> None:
    """Replace the vmware_hb_build_number array in a Wireshark dissector file.

    Reads ``c_file``, substitutes the ``vmware_hb_build_number`` value_string
    array with entries derived from ``releases``, and writes the result back.
    A ``{0, NULL}`` sentinel is automatically appended as required by the
    Wireshark value_string API.

    Args:
        c_file: Path to the C source file to update.
        releases: Sorted list of release dicts as returned by
            :func:`fetch_releases`.
    """
    entries = "\n".join(
        f'    {{ {r["build"]}, "{r["friendlyName"]}" }},'
        for r in releases
    )
    new_block = (
        "static const value_string vmware_hb_build_number[] = {\n"
        + entries + "\n"
        + "    {0, NULL}\n"
        + "};"
    )

    with open(c_file, "r", encoding="utf-8") as f:
        source = f.read()

    pattern = r"static const value_string vmware_hb_build_number\[\]\s*=\s*\{.*?\};"
    new_source, count = re.subn(pattern, new_block, source, flags=re.DOTALL)

    if count == 0:
        raise RuntimeError(
            f"Could not find 'vmware_hb_build_number' array in '{c_file}'."
        )

    if dry_run:
        if not quiet:
            print(f"[dry-run] Would update '{c_file}' with {len(releases)} entries.")
        return

    with open(c_file, "w", encoding="utf-8") as f:
        f.write(new_source)

    if not quiet:
        print(f"Updated '{c_file}' with {len(releases)} release entries.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch the latest VMware ESXi release list and update the "
            "vmware_hb_build_number value_string table in a Wireshark "
            "dissector source file."
        )
    )
    parser.add_argument(
        "c_file",
        metavar="FILE",
        help="Path to the C source file containing vmware_hb_build_number "
             "(e.g. epan/dissectors/packet-vmware-hb.c).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying the file.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress normal output.",
    )

    args = parser.parse_args()

    releases = fetch_releases(RELEASES_URL)
    update_dissector(args.c_file, releases, args.dry_run, args.quiet)


if __name__ == "__main__":
    main()
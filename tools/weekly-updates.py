#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Wrapper for our various scripts that update manuf, services, enterprise numbers, and other registry data."""

import argparse
import os
import os.path
import subprocess
import sys

# To do:
# - Add a "build command" argument so we can try a build after running each tool.

# A list of update tools to run
# - name: The name of the tool; it will be printed in the commit message if it fails.
# - path: Path to the tool relative to the repository root.
# - python_modules: List of required Python modules (optional).
# - updated_files: List of files that this tool updates.
#
# Each tool must
# - Run without arguments, i.e. the script should perform the desired update by default.
# - Exit with 0 on success and nonzero on failure.
# - Print a short, informative message suitable for inclusion in a git commit on failure.
# - Preferably be able to run from anywhere.

UPDATE_TOOLS = (
    {
        "name": "AUTHORS",
        "path": "tools/generate_authors.py",
        "python_modules": ["pyuca"],
        "updated_files": ["AUTHORS"],
    },
    {
        "name": "IANA constants",
        "path": "tools/make-iana-constants.py",
        "updated_files": ["epan/iana-info.c", "epan/iana-info.h"],
    },
    {
        'name': 'manuf',
        'path': 'tools/make-manuf.py',
        "python_modules": ["icu"],
        'updated_files': ['epan/manuf-data.c']
    },
    {
        "name": "USB",
        "path": "tools/make-usb.py",
        "updated_files": ["epan/dissectors/data-usb.c"],
    },
    {
        "name": "Bluetooth",
        "python_modules": ["PyYAML"],
        "path": "tools/make-bluetooth.py",
        "updated_files": ["epan/dissectors/data-bluetooth.c"],
    },
    {
        "name": "TLS CT Log IDs",
        "python_modules": ["requests"],
        "path": "tools/make-tls-ct-logids.py",
        "updated_files": ["epan/dissectors/packet-tls-utils.c"],
    },
    {
        "name": "PCI IDs",
        "path": "tools/make-usb.py",
        "updated_files": ["epan/dissectors/data-ncsi.c", "epan/dissectors/data-ncsi.h"],
    },
    {
        "name": "ISOBUS parameters",
        "path": "tools/make-isobus.py",
        "updated_files": [
            "epan/dissectors/data-isobus.c",
            "epan/dissectors/data-isobus.h",
        ],
    },
    {
        "name": "BACNET",
        "python_modules": ["beautifulsoup4"],
        "path": "tools/generate-bacnet-vendors.py",
        "updated_files": ["epan/dissectors/data-bacnet.c"],
    },
    {
        "name": "DMX",
        "path": "tools/make-dmx-manfid.py",
        "updated_files": [
            "epan/dissectors/data-dmx-manfid.c",
            "epan/dissectors/data-dmx-manfid.h",
        ],
    },
    # Asterix requires an argument and a compile, and should only be run from master.
    # {
    #     'name': 'Asterix',
    #     'path': 'tools/make-specs.py',
    #     'updated_files': []
    # },
    {
        "name": "Introspection enumerations",
        "python_modules": ["pyclibrary"],
        "path": "tools/make-enums.py",
        "updated_files": [
            "epan/introspection-enums.c",
            "wiretap/introspection-enums.c",
        ],
    },
    {
        "name": "Freedesktop.org metadata",
        "path": "tools/update-appdata.py",
        "updated_files": ["resources/freedesktop/org.wireshark.Wireshark.metainfo.xml"],
    },
)


def main():
    this_dir = os.path.dirname(__file__)
    top_level = os.path.join(this_dir, "..")
    # Some scripts need to be run from the top level?
    os.chdir(top_level)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--list-python-modules",
        action="store_true",
        help="Print required Python modules, suitable for passing to `pip install` and exit",
    )
    parser.add_argument(
        "--tool-output",
        default="tool_output.log",
        action="store_true",
        help="Status log file, suitable for including in a commit message",
    )
    parser.add_argument(
        "--updated-files",
        default="updated_files.log",
        help="File containing a list of updated repository files",
    )
    args = parser.parse_args()

    if args.list_python_modules:
        modules = []
        for tool in UPDATE_TOOLS:
            try:
                modules.extend(tool["python_modules"])
            except KeyError:
                pass
        print(f"{' '.join(modules)}")
        sys.exit(0)

    # Update everything by default
    updated_files = []
    with open(args.tool_output, "w") as tool_output_f:
        # XXX Should we build after each update as well?
        for tool in UPDATE_TOOLS:
            print(f"Running {tool['path']}.\n")
            res = subprocess.run([tool["path"]], capture_output=True, encoding="UTF-8")
            print(res.stdout, end="")
            print(res.stderr, end="")
            if res.returncode == 0:
                try:
                    updated_files.extend(tool["updated_files"])
                except KeyError:
                    pass
            else:
                tool_output_f.write(f"{tool['name']} failed:\n")
                tool_output_f.write(res.stdout)
                tool_output_f.write(res.stderr)
    with open(args.updated_files, "w") as updated_f:
        updated_f.write("\n".join(updated_files) + "\n")


if __name__ == "__main__":
    # args --list-python-modules
    main()

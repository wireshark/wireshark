# Wireshark tests for Zabbix protocol dissector
# Copyright 2025, Markku Leiniö <markku.leinio@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Zabbix dissector tests"""

import subprocess
from pathlib import Path
from typing import List

import pytest


def _tshark_outputs(tshark: str, capture_file: Path) -> List[str]:
    res = subprocess.run(
        (
            tshark,
            "-r", str(capture_file),
            "-Y", "zabbix",
            "-T", "fields", "-e", "_ws.col.info",
        ),
        capture_output=True,
        check=True,
        encoding="utf-8",
        text=True,
    )
    return [line.strip() for line in res.stdout.splitlines()]


def _get_zabbix_capture_files() -> List[Path]:
    # Unfortunately unable to use Wireshark-defined fixtures (like dirs) as they are not
    # available at the time of decorating the parametrized test. So let's resolve the
    # capture file location ourselves.
    # This needs to be modified if the test or capture files are reorganized.
    zabbix_capture_dir = Path(__file__).parent.parent / "captures" / "zabbix"
    return zabbix_capture_dir.glob("*.pcap*")


def _get_zabbix_capture_files_names_only() -> List[str]:
    # The returned file names are used for parametrized test ids
    return [p.name for p in _get_zabbix_capture_files()]


def _get_output_file_contents(capture_file: Path) -> List[str]:
    if len(capture_file.suffixes) == 1:
        # It is just .pcap or .pcapng or similar, replace it
        output_file = capture_file.with_suffix(".output")
    else:
        # Otherwise we have multipart file suffix, replace them all with .output
        basename = capture_file.name.split(".")[0]
        output_file = capture_file.parent / f"{basename}.output"
    return [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines()]


class TestZabbix:

    @pytest.mark.parametrize(
        "zabbix_capture_file",
        _get_zabbix_capture_files(),
        ids=_get_zabbix_capture_files_names_only(),
    )
    def test_zabbix_capture(self, cmd_tshark, zabbix_capture_file):
        """This test is run separately for each capture file found in captures/zabbix,
        to provide readable output when a test fails.

        For each capture file the corresponding .output file is read, and the contents of
        it are compared to the tshark output.
        """
        expected_outputs = _get_output_file_contents(zabbix_capture_file)
        tshark_outputs = _tshark_outputs(cmd_tshark, zabbix_capture_file)
        assert len(expected_outputs) == len(tshark_outputs), "Output length mismatch"
        # Let's do the checks line by line to provide readable output in case of error
        for i in range(len(expected_outputs)):
            assert expected_outputs[i] == tshark_outputs[i], "Output line mismatch"

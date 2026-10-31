# Wireshark tests for the IPFS/libp2p dissector.
# SPDX-License-Identifier: GPL-2.0-or-later

import subprocess
from pathlib import Path

import pytest


CAPTURE_DIR = Path(__file__).parent.parent / "captures" / "ipfs"
CASES = (
    ("ipfs-4kb.pcap", "cat", "QmZLws5v55MQJmyTo2deZfp3Z1KuKa9MwyCaymTxqXXmkh"),
    ("ipfs-16kb.pcap", "get", "Qmbn3EFs2q1bNMSpBYKoQjiKTzCcr8QR5R8VUbGqMbc4Fe"),
    ("ipfs-4-4kb.pcap", "repo/gc", None),
)


@pytest.mark.parametrize(("capture_name", "command", "argument"), CASES)
def test_ipfs_rpc_capture(cmd_tshark, test_env, capture_name, command, argument):
    """Check that real Kubo HTTP RPC captures expose command and argument fields."""
    capture = CAPTURE_DIR / capture_name
    result = subprocess.run(
        (
            cmd_tshark,
            "-r", str(capture),
            "-Y", "ipfs.rpc.command",
            "-T", "fields",
            "-e", "ipfs.rpc.command",
            "-e", "ipfs.rpc.argument",
            "-e", "ipfs.rpc.uri",
        ),
        capture_output=True,
        check=True,
        encoding="utf-8",
        text=True,
        env=test_env,
    )

    rows = [line.split("\t") for line in result.stdout.splitlines()]
    assert rows, f"No IPFS RPC fields found in {capture_name}"
    assert any(row[0] == command for row in rows), (
        f"Expected command {command!r} in {capture_name}; got {rows!r}"
    )
    if argument is not None:
        assert any(
            row[0] == command and len(row) > 1 and row[1] == argument
            for row in rows
        ), f"Expected decoded arg {argument!r} for {command!r} in {capture_name}"
    assert any(
        len(row) > 2 and row[2].startswith("/api/v0/")
        for row in rows
    ), f"No RPC URI field found in {capture_name}"

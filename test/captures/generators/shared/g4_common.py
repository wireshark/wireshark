# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared helpers for group g4 reproducers: Exported PDU pcap writer."""
import struct


def exp_pdu(proto, payload):
    name = proto.encode()
    pad = (-len(name)) % 4
    hdr = struct.pack('>HH', 12, len(name) + pad) + name + b'\0' * pad
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload


def write_pcap(path, frames, linktype=252):
    """frames: list of bytes (already wrapped for the link type)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def write_exp_pdu_pcap(path, proto, payloads):
    write_pcap(path, [exp_pdu(proto, p) for p in payloads])

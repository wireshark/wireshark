# Helper module for the smpte_2038 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal MPEG-2 transport stream builder (PAT, PMT, PES)."""
import struct


def crc32_mpeg(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc


def section(table_id, ext, body, ver=0):
    n = 5 + len(body) + 4
    s = struct.pack('!BHHBBB', table_id, 0xb000 | n, ext, 0xc1 | (ver << 1), 0, 0) + body
    return s + struct.pack('!I', crc32_mpeg(s))


def ts_packet(pid, payload, cc, pusi=False, stuff=True):
    """188 octet packet; payload shorter than 184 is preceded by adaptation
    field stuffing."""
    assert len(payload) <= 184
    hdr = 0x47
    if len(payload) < 184:
        pad = 184 - len(payload)
        if pad == 1:
            af = b'\0'
        else:
            af = bytes([pad - 1, 0x00]) + b'\xff' * (pad - 2)
        return struct.pack('!BHB', hdr, (0x4000 if pusi else 0) | pid,
                           0x30 | (cc & 15)) + af + payload
    return struct.pack('!BHB', hdr, (0x4000 if pusi else 0) | pid, 0x10 | (cc & 15)) + payload


def psi_packet(pid, sec, cc):
    return ts_packet(pid, b'\0' + sec, cc, pusi=True)


def pat(prog=1, pmt_pid=0x100):
    return section(0, 1, struct.pack('!HH', prog, 0xe000 | pmt_pid))


def pmt(streams, prog=1, pcr_pid=0x101):
    """streams: list of (stream_type, pid, descriptors bytes)."""
    body = struct.pack('!HH', 0xe000 | pcr_pid, 0xf000)
    for st, pid, desc in streams:
        body += struct.pack('!BHH', st, 0xe000 | pid, 0xf000 | len(desc)) + desc
    return section(2, prog, body)


def pes(stream_id, payload, pts=None, bounded=True):
    if pts is None:
        hdr = struct.pack('!BBB', 0x84, 0x00, 0)
    else:
        p = pts
        ptsb = bytes([0x21 | ((p >> 29) & 0x0e), (p >> 22) & 0xff, 0x01 | ((p >> 14) & 0xfe),
                      (p >> 7) & 0xff, 0x01 | ((p << 1) & 0xfe)])
        hdr = struct.pack('!BBB', 0x84, 0x80, 5) + ptsb
    ln = len(hdr) + len(payload) if bounded else 0
    return b'\0\0\x01' + bytes([stream_id]) + struct.pack('!H', ln) + hdr + payload


def pes_to_ts(pid, data, cc):
    """Split a PES packet into TS packets; returns (packets, next cc)."""
    out = []
    first = True
    while data or first:
        chunk, data = data[:184], data[184:]
        out.append(ts_packet(pid, chunk, cc, pusi=first))
        cc = (cc + 1) & 15
        first = False
    return out, cc


def null_packet():
    return ts_packet(0x1fff, b'\xff' * 184, 0)

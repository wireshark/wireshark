#!/usr/bin/env python3
# Generates test/captures/lwm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Lightweight Mesh (LwMesh) coverage captures for
epan/dissectors/packet-lwm.c.  LwMesh frames are carried in IEEE 802.15.4
data frames (link type 230, IEEE 802.15.4 without FCS), where the "lwm_wlan"
heuristic finds them.  Every packet is built with struct; nothing comes
from a real network.  The MIC of secured frames is a placeholder: no key is
ever used, so the decryption code is not exercised.

Usage: mklwm.py <outdir>
Writes lwm-coverage.pcapng (main; the last frame is an Exported PDU naming
"lwm", the reproducer of the NULL data argument fix, which needs the
lwm.lwmes_key preference to matter) and lwm-coverage-malformed.pcap (frames
that need Decode As of PAN 0x1234 to LwMesh, other malformed input).
"""
import os
import struct
import sys

PAN = 0x1234


def wpan(payload, seq=1, src=0x0001, dst=0x0002, pan=PAN):
    # frame control: data frame, PAN ID compression, short destination and source addresses
    fcf = 0x0001 | 0x0040 | (2 << 10) | (2 << 14)
    return struct.pack('<HBHHH', fcf, seq & 0xff, pan, dst, src) + payload


def lwm(fcf=0, seq=1, src=0x8001, dst=0x0005, srcep=1, dstep=2, payload=b'', multi=None):
    h = struct.pack('<BBHHB', fcf, seq, src, dst, (srcep << 4) | dstep)
    if multi is not None:
        h += struct.pack('<H', multi)
    return h + payload


ACK, REQ_ERR = 0x01, 0x02          # fcf bits: ack request, security
SEC, LINK, MULTI = 0x02, 0x04, 0x08


def main_frames():
    F = []

    def add(p, **kw):
        F.append(wpan(p, seq=len(F) + 1, **kw))

    # application data between endpoints 1 and 2, with the FCF flags one by one
    add(lwm(payload=b'hello lwmesh'))
    add(lwm(fcf=0x01, seq=2, payload=b'ack requested'))
    add(lwm(fcf=LINK, seq=3, payload=b'link local'))
    # source and destination address classes
    add(lwm(src=0x0010, dst=0x0020, seq=4, payload=b'routing to routing'))
    add(lwm(src=0x8010, dst=0x8020, seq=5, payload=b'non-routing to non-routing'))
    add(lwm(src=0x0010, dst=0xffff, seq=6, payload=b'broadcast'))
    add(lwm(src=0xffff, dst=0x0007, seq=7, payload=b'source is the broadcast address'))
    # multicast: group destination and the multicast header (radius fields)
    add(lwm(fcf=MULTI, dst=0x8003, seq=8, multi=0x4321, payload=b'multicast data'))
    add(lwm(fcf=MULTI | 0x01, dst=0x0009, seq=9, multi=0x0000, payload=b'multicast ack'))
    # secured frame without a key: payload and a placeholder MIC
    add(lwm(fcf=SEC, seq=10, payload=b'0123456789abcdef' + b'\0\0\0\0'))
    add(lwm(fcf=SEC | MULTI, dst=0x8003, seq=11, multi=0x1111, payload=b'secured multicast' + b'\0\0\0\0'))
    # empty payload
    add(lwm(seq=12))
    add(lwm(fcf=MULTI, seq=13, multi=0x2222, dst=0x8004))
    # stack commands (both endpoints 0)
    add(lwm(srcep=0, dstep=0, seq=14, payload=bytes([0x00, 0x0e, 0x00])))                       # ACK
    add(lwm(srcep=0, dstep=0, seq=15, payload=bytes([0x01]) + struct.pack('<HHB', 0x0001, 0x0002, 0)))   # route error
    add(lwm(srcep=0, dstep=0, seq=16, payload=bytes([0x01]) + struct.pack('<HHB', 0x8001, 0x8002, 1)))
    add(lwm(srcep=0, dstep=0, seq=17, payload=bytes([0x02]) + struct.pack('<HHBB', 0x0001, 0x0002, 0, 255)))   # route request
    add(lwm(srcep=0, dstep=0, seq=18, payload=bytes([0x02]) + struct.pack('<HHBB', 0x0003, 0x0004, 1, 17)))
    add(lwm(srcep=0, dstep=0, seq=19, payload=bytes([0x03]) + struct.pack('<HHBBB', 0x0001, 0x0002, 0, 100, 255)))  # reply
    add(lwm(srcep=0, dstep=0, seq=20, payload=bytes([0x03]) + struct.pack('<HHBBB', 0x0005, 0x0006, 1, 100, 50)))
    # source and destination endpoint 15
    add(lwm(srcep=15, dstep=15, seq=21, payload=b'endpoint 15'))
    return F


def malformed_frames():
    """Frames reached with Decode As (wpan.panid 0x1234 -> lwm) or malformed."""
    F = []

    def add(p, **kw):
        F.append(wpan(p, seq=len(F) + 1, **kw))

    # endpoint mismatch: one stack command endpoint (the heuristic refuses these, Decode As takes them)
    add(lwm(srcep=0, dstep=3, seq=1, payload=b'mismatch a'))
    add(lwm(srcep=4, dstep=0, seq=2, payload=b'mismatch b'))
    add(lwm(srcep=0, dstep=5, seq=3, fcf=MULTI, multi=0x1234, payload=b'mismatch multicast'))
    # command with trailing bytes, and an unknown command (error expert infos)
    add(lwm(srcep=0, dstep=0, seq=21, payload=bytes([0x00, 0x05, 0x00]) + b'extra'))
    add(lwm(srcep=0, dstep=0, seq=22, payload=bytes([0x7f, 1, 2, 3])))
    # reserved FCF bits set: not LwMesh for the heuristic
    add(lwm(fcf=0x10, seq=4, payload=b'reserved bit'))
    # too short for the header
    add(b'\x00\x01\x02\x03\x04\x05')
    # secured frame shorter than the MIC
    add(lwm(fcf=SEC, seq=5, payload=b'\x01\x02'))
    add(lwm(fcf=SEC, seq=6, payload=b'\x01'))
    # multicast header cut short
    add(lwm(fcf=MULTI, seq=7)[:8])
    # stack commands cut short
    for cmd, n in ((0x00, 1), (0x01, 4), (0x02, 5), (0x03, 6), (0x03, 7)):
        add(lwm(srcep=0, dstep=0, seq=8, payload=bytes([cmd]) + bytes(range(1, n))))
    return F


def exppdu_frames():
    def tag(t, v):
        pad = (-len(v)) % 4
        return struct.pack('!HH', t, len(v) + pad) + v + b'\0' * pad
    hdr = tag(12, b'lwm') + struct.pack('!HH', 0, 0)
    # secured LwMesh frame (FCF security bit), placeholder payload and MIC
    p = lwm(fcf=SEC, seq=1, src=0x0002, dst=0x0003, srcep=1, dstep=1, payload=b'PAYLOAD!' + b'\0\0\0\0')
    return [hdr + p]


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def write_pcapng(path, idbs, frames):
    """idbs: link types; frames: (interface index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)


def write_pcap(path, frames, linktype):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    # the main capture has two interfaces: IEEE 802.15.4 without FCS and, for the last frame,
    # Exported PDU naming "lwm" (the reproducer of the NULL data argument fix)
    frames = [(0, f) for f in main_frames()] + [(1, f) for f in exppdu_frames()]
    write_pcapng(os.path.join(out, 'lwm-coverage.pcapng'), (230, 252), frames)
    write_pcap(os.path.join(out, 'lwm-coverage-malformed.pcap'), malformed_frames(), 230)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/tdmop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-tdmop.c (TDMoP). Usage: mktdmop.py <outdir>
# TDMoP is not claimed by default: the captures use ethertype 0x0808
# (-o tdmop.ethertype:0x808) and UDP port 5555 (-d udp.port==5555,tdmop).
import os
import struct
import sys
from pcaplib import Pcap, eth, ip4, udp, hdlc_stream, reverse8

DLT_EN10MB = 1
ETHERTYPE = 0x0808
UDP_PORT = 5555

F_NO_DATA, F_REMOTE_NO_DATA, F_COMPRESSED, F_LOST = 0x08, 0x04, 0x10, 0x02

def hdr(seq, flags=0, dst=3, src=2, tid=0x0001, srcdst=0x23, lastrecv=0, delay=0, reserved=0):
    return struct.pack('<HBBBBHHHH', tid, dst, src, flags, srcdst, seq, lastrecv, delay, reserved)

def swap16(v):
    return ((v >> 16) & 0xffff) | ((v & 0xffff) << 16)

def comp_block(channels, data):
    """A compressed block: mask word (halves swapped) and 4 octets per channel."""
    m = 0
    for c in channels:
        m |= 1 << c
    return struct.pack('<I', swap16(m)) + b''.join(data[c] for c in channels)

def uncomp_block(data):
    return b''.join(data.get(c, bytes([0x80 + c] * 4)) for c in range(32))

def lapd(ctrl, payload=b'', sapi=0, tei=64, cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1]) + ctrl + payload

SETUP = bytes([0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa3, 0x70, 0x03, 0x80, 0x31, 0x32])
REL = bytes([0x08, 0x01, 0x81, 0x5a, 0x08, 0x02, 0x80, 0x90])
LAPD_FRAMES = [
    lapd(bytes([0x00, 0x00]), SETUP),
    lapd(bytes([0x01, 0x02])),
    lapd(bytes([0x02, 0x04]), REL, cr=1),
    lapd(b'\x7f'),
    lapd(b'\x73'),
]

def main(out):
    # D channel bit stream, bits reversed per octet on the wire
    stream = hdlc_stream(LAPD_FRAMES, lead=2, align=4, gap=1, fcs='>', tail=160)
    wire = bytes(reverse8(b) for b in stream)
    pieces = [wire[i:i + 4].ljust(4, b'\x00') for i in range(0, len(wire), 4)]
    # the last octets are padding with flag bits: repeat the flag octet
    # the last 40 pieces are flags that keep the D channel in sync
    spare = pieces[-40:]
    pieces = pieces[:-40]

    p = Pcap(DLT_EN10MB)
    seq = [0]
    def send(payload, flags_hdr=0, udp_port=False, src=2, dst=3):
        seq[0] += 1
        body = hdr(seq[0], flags_hdr, dst=dst, src=src) + payload
        if udp_port:
            f = eth(ip4(17, udp(body, 4000, UDP_PORT)), 0x0800)
        else:
            f = eth(body, ETHERTYPE)
        p.add(f)
    other = {c: bytes([0x10 * (c % 15) + 1] * 4) for c in range(32)}

    # 1-4: header only frames (no data) with the flag combinations
    send(b'', F_NO_DATA)
    send(b'', F_NO_DATA | F_REMOTE_NO_DATA)
    send(b'', F_LOST | F_NO_DATA)
    send(b'', F_LOST | F_REMOTE_NO_DATA | F_NO_DATA | F_COMPRESSED)
    # 5-6: compressed frames without the D channel (channels 0, 1, 31)
    send(comp_block([0, 1, 31], other), F_COMPRESSED)
    send(comp_block([5], other) + comp_block([6, 7], other), F_COMPRESSED | F_REMOTE_NO_DATA)
    # 7-: the D channel stream, one or more 4 octet pieces (channel 16) per frame,
    #     as compressed blocks with other channels around it
    i = 0
    n = 0
    while i < len(pieces):
        k = 1 + (n % 3)
        blocks = b''
        for j in range(k):
            if i >= len(pieces):
                break
            d = dict(other)
            d[16] = pieces[i]
            i += 1
            blocks += comp_block([4, 16] if j % 2 == 0 else [16], d)
        send(blocks, F_COMPRESSED | (F_LOST if n == 4 else 0))
        n += 1
    # an uncompressed frame (default mask: all 32 channels, one and two blocks)
    send(uncomp_block({16: spare.pop(0)}))
    send(uncomp_block({16: spare.pop(0)}) + uncomp_block({16: spare.pop(0)}))
    # a compressed frame that overflows the 128 octet D channel buffer
    send(b''.join(comp_block([16], {16: spare.pop(0)}) for _ in range(34 if len(spare) >= 34 else len(spare))), F_COMPRESSED)
    # UDP transport (Decode As): compressed and uncompressed
    send(comp_block([2, 3, 16], {**other, 16: bytes(reverse8(0x7e) for _ in range(4))}), F_COMPRESSED, udp_port=True)
    send(uncomp_block({16: bytes(reverse8(0x7e) for _ in range(4))}), 0, udp_port=True, src=3, dst=2)
    send(b'', F_NO_DATA, udp_port=True)
    p.write(os.path.join(out, 'tdmop-coverage.pcap'))

    m = Pcap(DLT_EN10MB)
    seq[0] = 100
    def msend(payload, flags=0):
        seq[0] += 1
        m.add(eth(hdr(seq[0], flags) + payload, ETHERTYPE))
    msend(comp_block([], {}), F_COMPRESSED)                  # empty mask (loop fix)
    msend(comp_block([3], other) + comp_block([], {}), F_COMPRESSED)
    msend(uncomp_block({})[:40])                             # channel data truncated
    msend(struct.pack('<I', swap16(0x30000)) + bytes(5), F_COMPRESSED)  # truncated block
    msend(b'\x01\x02\x03')                                   # payload shorter than a block
    m.add(eth(b'\x01\x00\x03', ETHERTYPE))                   # shorter than the flags octet
    m.add(eth(hdr(1, 0)[:10], ETHERTYPE))                    # header truncated
    m.write(os.path.join(out, 'tdmop-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')

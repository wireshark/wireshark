#!/usr/bin/env python3
# Generates test/captures/ifcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ifcp.c (iFCP, TCP port 3420; the heuristic
is on by default so any port works).  Usage: mkifcp.py <outdir>"""
import struct
import sys
import os
from pylib import Pcap, Tcp

PORT = 3420

def fc_frame(r_ctl, d_id, s_id, typ, f_ctl, seq_id, seq_cnt, ox_id, rx_id, param, payload=b''):
    h = struct.pack('>B3sB3sB3sBBHHHI', r_ctl, d_id, 0, s_id, typ, f_ctl, seq_id, 0, seq_cnt, ox_id, rx_id, param)
    assert len(h) == 24 and len(payload) % 4 == 0
    return h + payload + bytes(4)        # placeholder CRC

D, S_ = bytes([0x01, 0x02, 0x03]), bytes([0x04, 0x05, 0x06])
FCP_PAYLOAD = bytes(32)     # LUN 0, CDB 00 (TEST UNIT READY), data length 0

def abts(n=1):
    return fc_frame(0x81, D, S_, 0x00, bytes([0x28, 0, 0]), n & 0xff, 0, 0x1000 + n, 0xffff, 0)

def fcp_cmnd(n=1):
    return fc_frame(0x06, D, S_, 0x08, bytes([0x29, 0, 0]), n & 0xff, 0, 0x2000 + n, 0xffff, 0, FCP_PAYLOAD)

def els_acc(n=1):
    # ELS ECHO request (named els_acc for the callers)
    return fc_frame(0x22, S_, D, 0x01, bytes([0x29, 0, 0]), n & 0xff, 0, 0x3000 + n, 0xffff, 0, bytes([0x10, 0, 0, 0, 1, 2, 3, 4]))

def els_logo(n=1):
    return fc_frame(0x22, D, S_, 0x01, bytes([0x29, 0, 0]), n & 0xff, 0, 0x4000 + n, 0xffff, 0,
                    bytes([0x05, 0, 0, 0, 0, 0, 0, 0x00]) + bytes([1, 2, 3, 4, 5, 6, 7, 8]))

ABTS, FCP_CMND, ELS_LS_ACC, ELS_LOGO = abts(), fcp_cmnd(), els_acc(), els_logo()

def ifcp(fc, sof=0x2e, eof=0x41, flags=0, cflags=0, ls_acc=0, tsec=0x65000000, tusec=0x00001000, hdr4=0, crc=0):
    words = (28 + 4 + len(fc) + 4) // 4
    assert (28 + 4 + len(fc) + 4) % 4 == 0
    w = (cflags << 8) | words          # 6 bit flags in the top of the 16 bit field
    w = (cflags << 10) | words
    b = bytes([2, 1, 0xfd, 0xfe]) + struct.pack('>I', hdr4)
    b += bytes([ls_acc, flags, sof, eof])
    b += struct.pack('>HH', w, (~w) & 0xffff)
    b += struct.pack('>III', tsec, tusec, crc)
    b += bytes([sof, sof, (~sof) & 0xff, (~sof) & 0xff])
    b += fc
    b += bytes([eof, eof, (~eof) & 0xff, (~eof) & 0xff])
    return b

def main(out):
    p = Pcap(1)
    t = Tcp(p, sport=50000, dport=PORT)
    t.hs()
    # SOF/EOF combinations
    combos = [(0x2e, 0x41), (0x2e, 0x42), (0x28, 0x41), (0x29, 0x44), (0x2d, 0x46),
              (0x31, 0x49), (0x35, 0x41), (0x36, 0x42), (0x39, 0x4e), (0x2e, 0x4f),
              (0x35, 0x50), (0x20, 0x99), (0x00, 0x41)]
    frames = [fcp_cmnd, abts, els_logo, els_acc]
    for i, (sof, eof) in enumerate(combos):
        t.seg(ifcp(frames[i % 4](i + 10), sof, eof, hdr4=i), fwd=bool(i % 4 != 3))
    # Flags: session control, transparent, special processing, CRC valid
    t.seg(ifcp(abts(41), flags=0x04))
    t.seg(ifcp(abts(42), flags=0x02))
    t.seg(ifcp(abts(43), flags=0x01))
    t.seg(ifcp(abts(44), flags=0x07, cflags=0x01, ls_acc=2))
    t.seg(ifcp(abts(45), cflags=0x04), fwd=False)
    # Two frames in one segment, one split across two segments
    t.seg(ifcp(abts(60)) + ifcp(els_acc(61), 0x2e, 0x42))
    m = ifcp(fcp_cmnd(62))
    t.seg(m[:20]); t.seg(m[20:])
    # Largest frame (2112 octet FC payload would exceed the MSS here: 500 octets)
    t.seg(ifcp(fc_frame(0x01, D, S_, 0x08, bytes([0x29, 0, 0]), 5, 0, 0x5234, 0xffff, 0, bytes(range(256)) * 1 + bytes(0)[:0] + bytes(244))))
    t.seg(b'', True, 0x11); t.seg(b'', False, 0x11)
    # Short TCP payload on a stream the heuristic has not claimed
    t3 = Tcp(p, sport=50002, dport=3262)
    t3.hs()
    t3.seg(bytes(8))
    # A second stream on another port
    t2 = Tcp(p, sport=50001, dport=3260 + 1)
    t2.hs()
    t2.seg(ifcp(els_logo(70), 0x28, 0x42))
    t2.seg(ifcp(els_acc(70), 0x28, 0x42), fwd=False)
    p.write(os.path.join(out, 'ifcp-coverage.pcap'))

    m = Pcap(1)
    t = Tcp(m, sport=50002, dport=PORT)
    t.hs()
    # Good frame first (the heuristic sets the conversation)
    t.seg(ifcp(ABTS))
    # Frame length field inconsistent with its complement, too small, too large
    bad = bytearray(ifcp(ABTS)); bad[14] ^= 0x01
    t.seg(bytes(bad))
    bad = bytearray(ifcp(ABTS)); bad[12:14] = struct.pack('>H', 10); bad[14:16] = struct.pack('>H', (~10) & 0xffff)
    t.seg(bytes(bad))
    bad = bytearray(ifcp(ABTS)); bad[12:14] = struct.pack('>H', 600); bad[14:16] = struct.pack('>H', (~600) & 0xffff)
    t.seg(bytes(bad))
    # Wrong protocol/version bytes
    bad = bytearray(ifcp(ABTS)); bad[0] = 1
    t.seg(bytes(bad))
    # Frame length larger than the data in the segment (waits for the rest)
    full = ifcp(FCP_CMND)
    t.seg(full[:40])
    # Frame cut by the snap length
    n = t.seg(full, fwd=False)
    m.origs[n - 1] = len(m.frames[n - 1]); m.frames[n - 1] = m.frames[n - 1][:54 + 60]
    # Frame whose FC part is too short for the FC header
    t.seg(ifcp(bytes(4) , 0x2e, 0x41))
    # Garbage
    t.seg(bytes(range(40)))
    # Heuristic start of a conversation on another port: bad frame length
    t3 = Tcp(m, sport=50003, dport=PORT + 1)
    t3.hs()
    bad = bytearray(ifcp(ABTS)); bad[14] ^= 0x01
    t3.seg(bytes(bad))
    m.write(os.path.join(out, 'ifcp-coverage-malformed.pcap'))

main(sys.argv[1])

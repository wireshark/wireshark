#!/usr/bin/env python3
# Generates test/captures/gsm_osmux_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Osmux captures.  Usage: mkgsm_osmux.py <outdir>

The Osmux conversations are set up the way a real trace does it: an MGCP
message carrying X-Osmux and an SDP body (packet-mgcp.c -> packet-sdp.c ->
osmux_add_address()).  Everything is built with struct."""
import sys
import os
from pcaplib import pcap_ts, udp_frame

A, B = '10.0.0.1', '10.0.0.2'

def mgcp_resp(txid, addr, port):
    sdp = ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
           'm=audio %d RTP/AVP 112\r\na=rtpmap:112 AMR/8000\r\n' % (addr, addr, port))
    return ('200 %d OK\r\nI: 1\r\nX-Osmux: 1\r\n\r\n%s' % (txid, sdp)).encode()

AMR_BYTES = [12, 13, 15, 17, 19, 20, 26, 31, 5]

def osmux(cid, seq, amr_ft=7, ctr=0, m=0, ft=1, q=0, f=0, cmr=15, data=None, size=None):
    b = bytes([(m << 7) | (ft << 5) | (ctr << 2) | (q << 1) | f, seq, cid,
               (amr_ft << 4) | cmr])
    if size is None:
        size = AMR_BYTES[amr_ft] if amr_ft < 9 else 0
    n = size * (ctr + 1)
    if data is None:
        data = bytes((seq + i) & 0xff for i in range(n))
    return b + data

def build(outdir):
    main = []
    t = [0]
    def add(fr, dt=20000):
        t[0] += dt
        main.append((t[0], fr))
    def mg(txid, addr, port, sp=2727, dp=2427):
        add(udp_frame(A, B, sp, dp, mgcp_resp(txid, addr, port)), 1000)
    def up(pl, rev=False, dt=20000):
        if rev:
            add(udp_frame(B, A, 50002, 4002, pl), dt)
        else:
            add(udp_frame(A, B, 50000, 4000, pl), dt)

    # 1-2: MGCP responses with X-Osmux and SDP set up the two conversations
    mg(1001, B, 4000)
    mg(1002, A, 4002)
    # stream A, CID 1: AMR frames with every codec mode, in order
    for i, ft in enumerate(range(9)):
        up(osmux(1, i, amr_ft=ft, m=1 if i == 0 else 0))
    # several AMR frames per Osmux frame (ctr), q and f flags, odd cmr
    up(osmux(1, 9, ctr=3, q=1, f=1, cmr=3))
    up(osmux(1, 10, ctr=7, amr_ft=8, f=1))
    # repeated sequence number
    up(osmux(1, 10, ctr=7, amr_ft=8))
    # lost frames (jump from 10 to 14)
    up(osmux(1, 14))
    # out of order (14 -> 12)
    up(osmux(1, 12))
    # reserved AMR frame types 9..15 carry no payload
    up(osmux(1, 15, amr_ft=9, data=b''))
    up(osmux(1, 16, amr_ft=15, data=b''))
    # marker bit again with a long gap (jitter reset)
    up(osmux(1, 17, m=1), dt=200000)
    # in-order with a large relative delay (jitter)
    up(osmux(1, 18, ctr=1), dt=95000)
    # wrap around the sequence number with loss: jump to 250, then 3
    up(osmux(1, 250))
    up(osmux(1, 3))
    # signalling, dummy and reserved field types, and the new-style dummy
    up(osmux(1, 4, ft=0, amr_ft=15, data=b''))
    up(osmux(1, 5, ft=2, amr_ft=15, data=b''))
    up(osmux(1, 6, ft=3, amr_ft=15, data=b''))
    # old style dummy: control byte 0x23 and the CID in a 2 octet datagram
    up(bytes([0x23, 1]))
    up(bytes([0x23, 9]))
    # a 0x23 control byte in a longer frame is an ordinary frame (ft=1, ctr=0)
    up(bytes([0x23, 20, 2, 0x70]) + bytes(31))
    # several Osmux frames in one UDP datagram (different CIDs)
    up(osmux(1, 19) + osmux(2, 0, amr_ft=2) + osmux(3, 0, amr_ft=8, ctr=1, ft=1))
    # a trailing single octet is ignored
    up(osmux(1, 20) + b'\x55')
    # stream B, CID 7, other direction, short sequence including wrap in order
    for s in (254, 255, 0, 1):
        up(osmux(7, s, amr_ft=3, ctr=2), rev=True)
    # another CID on stream B, no AMR at all (signalling only)
    up(osmux(8, 0, ft=0, amr_ft=14, data=b''), rev=True)
    pcap_ts(os.path.join(outdir, 'gsm_osmux-coverage.pcap'), main)

    mal = []
    t[0] = 0
    def addm(fr, dt=20000):
        t[0] += dt
        mal.append((t[0], fr))
    addm(udp_frame(A, B, 2727, 2427, mgcp_resp(2001, B, 4000)), 1000)
    # payload shorter than ctr+1 AMR frames
    addm(udp_frame(A, B, 50000, 4000, osmux(1, 0, ctr=7)[:20]))
    # header cut after the sequence number, after the CID
    addm(udp_frame(A, B, 50000, 4000, bytes([0x20, 1, 2])))
    addm(udp_frame(A, B, 50000, 4000, bytes([0x24, 1, 2])))
    # second frame in the datagram is truncated
    addm(udp_frame(A, B, 50000, 4000, osmux(1, 1) + osmux(2, 2)[:10]))
    # control byte 0x23 plus CID only for a new-style dummy that is 3 bytes
    addm(udp_frame(A, B, 50000, 4000, bytes([0x23, 1, 2])))
    pcap_ts(os.path.join(outdir, 'gsm_osmux-coverage-malformed.pcap'), mal)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

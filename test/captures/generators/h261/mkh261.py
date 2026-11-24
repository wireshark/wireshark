#!/usr/bin/env python3
# Generates test/captures/h261_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.261 coverage captures. Usage: mkh261.py <outdir> [-v]
H.261 is reached the way a real call reaches it: a SIP INVITE whose SDP
puts the static RTP payload type 31 on UDP 5004, then RTP packets with
payload type 31; and IAX2 video frames with the H.261 codec.
Everything is built with struct; nothing comes from a real network."""
import struct
import sys
import os
from _lib import Pcap, A, B, sip, sdp, rtp

def h261(sbit=0, ebit=0, i=0, v=0, gobn=0, mbap=0, quant=0, hmvd=0, vmvd=0, data=b''):
    """4 octet H.261 payload header (RFC 4587 / H.225.0 Annex C)."""
    b0 = (sbit << 5) | (ebit << 2) | (i << 1) | v
    b1 = (gobn << 4) | (mbap >> 1)
    b2 = ((mbap & 1) << 7) | (quant << 2) | (hmvd >> 3)   # MBAP 1 bit, QUANT 5, HMVD 2 of 5
    b3 = ((hmvd & 7) << 5) | vmvd                         # HMVD 3 bits, VMVD 5 bits
    return bytes([b0, b1, b2, b3]) + data

def iax2_video(src, dst, ts, oseq, iseq, csub, payload):
    """IAX2 full frame, type 3 (video)."""
    return struct.pack('!HHIBBBB', 0x8000 | src, dst, ts, oseq, iseq, 3, csub) + payload

def main(out, verbose=False):
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def send(payload, mk=0, sport=5004, dport=5004):
        p.udp(A, B, sport, dport, rtp(payload, 31, mk))

    mark('SIP INVITE with SDP (static payload type 31 on UDP 5004)')
    p.udp(A, B, 5060, 5060, sip(sdp(5004, 31, 'H261/90000')))
    mark('H.261 header: every SBIT/EBIT/I/V combination')
    for sb, eb, i, v in [(0, 0, 0, 0), (7, 7, 1, 1), (3, 5, 1, 0), (1, 2, 0, 1)]:
        send(h261(sb, eb, i, v, data=b'\x00\x01\x00\x01\x81\x02'))
    mark('GOBN, MBAP, QUANT, HMVD, VMVD values')
    send(h261(gobn=15, mbap=31, quant=31, hmvd=31, vmvd=31, data=b'\xde\xad\xbe\xef'), mk=1)
    send(h261(gobn=1, mbap=0, quant=1, hmvd=1, vmvd=1, data=b'\x55'))
    send(h261(gobn=5, mbap=17, quant=12, hmvd=0, vmvd=16, data=b'\xaa' * 40))
    send(h261(gobn=2, mbap=1, quant=0, hmvd=16, vmvd=0, data=b'\x01'))
    mark('VMVD with the high bits of the octet clear / only the low 5 bits (mask 0x1F)')
    send(h261(hmvd=0, vmvd=0x1f, data=b'\x00'))   # all five VMVD bits set, HMVD 0
    send(h261(hmvd=7, vmvd=0x00, data=b'\x00'))   # HMVD low bits set, VMVD 0
    mark('large payload')
    send(h261(i=1, data=bytes(range(256)) * 4), mk=1)
    mark('IAX2 video frames with the H.261 codec (UDP 4569)')
    p.udp(A, B, 4569, 4569, iax2_video(0x1234, 0x0001, 100, 1, 0, 0x80 | 18, h261(1, 1, 1, 0, 4, 8, 9, 10, 11, b'\x12\x34')))
    p.udp(A, B, 4569, 4569, iax2_video(0x1234, 0x0001, 140, 2, 0, 0x80 | 18 | 0x40, h261(data=b'\x99' * 8)))

    p.write(os.path.join(out, 'h261-coverage.pcap'))
    nclean = len(p.frames)

    # ---- malformed ----
    m = Pcap()
    m.udp(A, B, 5060, 5060, sip(sdp(5004, 31, 'H261/90000')))
    m.udp(A, B, 5004, 5004, rtp(h261(gobn=3), 31))   # header only, no data: exception
    for n in (1, 2, 3):
        m.udp(A, B, 5004, 5004, rtp(b'\x20\x00\x00\x00'[:n], 31))
    m.udp(A, B, 4569, 4569, iax2_video(0x1234, 0x0001, 100, 1, 0, 18, b'\x01\x02'))
    m.write(os.path.join(out, 'h261-coverage-malformed.pcap'))
    if verbose:
        print('main capture: %d frames' % nclean)
        for n, d in marks: print('  %d: %s' % (n, d))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

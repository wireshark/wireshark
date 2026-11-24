#!/usr/bin/env python3
# Generates test/captures/h263p_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.263+ (RFC 4629) coverage captures. Usage: mkh263p.py <outdir> [-v]
H.263+ is reached the way a real call reaches it: a SIP INVITE whose SDP
maps RTP payload types to "H263-1998/90000" (UDP 5008, type 98) and
"H263-2000/90000" (UDP 5010, type 99); then RTP packets with those
payload types. Everything is built with struct; nothing comes from a real
network."""
import struct
import sys
import os
from _lib import Pcap, A, B, sip, sdp, rtp, Bits

def hdr(rr=0, p=0, v=0, plen=0, pebit=0, vrc=None):
    b = struct.pack('!H', (rr << 11) | (p << 10) | (v << 9) | (plen << 3) | pebit)
    if vrc is not None:
        b += bytes([vrc])
    return b

def pic(tr=3, ptype=(0, 2, 0), pquant=9, cpm=0, psbi=0, pei=0):
    """Picture header with the 6 bit PSC of RFC 4629 (no tail)."""
    b = Bits().u(6, 0x20).u(8, tr).u(1, 1).u(1, 0).u(3, 0).u(3, 2).u(5, 0).u(5, pquant).u(1, cpm)
    if cpm: b.u(2, psbi)
    b.u(1, pei)
    return b.pad().bytes()

def gob(gn=5):
    return Bits().u(1, 1).u(5, gn).u(2, 0).pad().bytes() + b'\x11\x22\x33\x44'

def main(out, verbose=False):
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def send(payload, port=5008, pt=98, mk=0):
        p.udp(A, B, port, port, rtp(payload, pt, mk))

    mark('SIP INVITE with two media sections: H263-1998 (UDP 5008, type 98) and H263-2000 (UDP 5010, type 99)')
    body = (sdp(5008, 98, 'H263-1998/90000') +
            b'm=video 5010 RTP/AVP 99\r\na=rtpmap:99 H263-2000/90000\r\n')
    p.udp(A, B, 5060, 5060, sip(body, call='c23h263p'))
    mark('P=0: payload without a start code; RR and PEBIT values')
    send(hdr() + b'\x01\x02\x03\x04')
    send(hdr(rr=0x1f, pebit=7) + b'\x05' * 10)
    mark('PEBIT 1..6 (3 bit field; mask 0x0007)')
    for pe in range(1, 7):
        send(hdr(pebit=pe, p=1) + gob(pe))
    mark('P=1: picture start code (PSC), picture header with PEI')
    send(hdr(p=1) + pic() + b'\xde\xad')
    send(hdr(p=1, pebit=5) + pic(cpm=1, psbi=1) + b'\xde\xad', port=5010, pt=99)
    mark('P=1: GOB start code (GBSC)')
    send(hdr(p=1) + gob(9))
    send(hdr(p=1) + gob(31), port=5010, pt=99)
    mark('P=1: EOS (0xfc, 0xfe), EOSBS (0xf8)')
    send(hdr(p=1) + b'\xfc\x00\x00')
    send(hdr(p=1) + b'\xfe\x00\x00')
    send(hdr(p=1) + b'\xf8\x00\x00')
    mark('P=1 with a first octet without the top bit (no start code)')
    send(hdr(p=1) + b'\x55\x00\x00')
    mark('V=1: VRC header (TID, Trun, S)')
    send(hdr(v=1, vrc=0x00) + b'\x01\x02')
    send(hdr(v=1, vrc=(5 << 5) | (9 << 1) | 1, p=1) + gob(2))
    send(hdr(v=1, vrc=(7 << 5) | (15 << 1)) + b'\x01')
    mark('PLEN: extra picture header (parsed as a picture header), alone and with V and P')
    eh = pic(tr=77, pquant=3)
    send(hdr(plen=len(eh)) + eh + b'\x01\x02\x03')
    send(hdr(plen=len(eh), v=1, vrc=0x42, pebit=3) + eh + b'\x01\x02')
    send(hdr(plen=len(eh), p=1) + eh + gob(4), port=5010, pt=99)
    send(hdr(plen=len(pic(cpm=1, psbi=2)), p=1, v=1, vrc=0x11) + pic(cpm=1, psbi=2) + pic() + b'\x99')
    mark('payloads of one octet after the header and a long payload')
    send(hdr() + b'\x7f')
    send(hdr(p=1) + b'\xa0' + bytes(range(256)) * 3, mk=1)
    p.write(os.path.join(out, 'h263p-coverage.pcap'))
    n = len(p.frames)

    m = Pcap()
    m.udp(A, B, 5060, 5060, sip(body, call='c23h263p'))
    def msend(payload): m.udp(A, B, 5008, 5008, rtp(payload, 98))
    msend(b'\x04')                                   # header cut to one octet
    msend(hdr(v=1))                                  # V=1 without the VRC octet
    msend(hdr(plen=20) + b'\x01\x02')                # PLEN longer than the packet
    msend(hdr(plen=3) + pic()[:3])                   # picture header cut in the PSC / TR
    msend(hdr(plen=2) + pic()[:2])
    msend(hdr(plen=5) + pic()[:5])
    msend(hdr(p=1))                                  # P=1 with no payload
    msend(hdr(p=1) + pic()[:3])                      # picture header cut
    msend(hdr(p=1) + pic()[:6])
    msend(hdr(p=1) + gob(3)[:1])                     # GOB header cut
    msend(hdr(p=1, v=1))                             # P=1 and V=1, nothing after
    m.write(os.path.join(out, 'h263p-coverage-malformed.pcap'))
    if verbose:
        print('main capture: %d frames' % n)
        for k, d in marks: print('  %d: %s' % (k, d))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

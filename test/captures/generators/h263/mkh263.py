#!/usr/bin/env python3
# Generates test/captures/h263_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.263 coverage captures. Usage: mkh263.py <outdir> [-v]
H.263 (packet-h263.c, the picture and GOB layer routines) is reached the
way a real call reaches it: a SIP INVITE whose SDP puts the static RTP
payload type 34 on UDP 5006, then RTP packets with payload type 34 that
the RFC 2190 dissector hands to H.263 after its mode A, B or C header;
and IAX2 video frames with the H.263 codec (also through RFC 2190).
Everything is built with struct; nothing comes from a real network."""
import struct
import sys
import os
from _lib import Pcap, A, B, sip, sdp, rtp, Bits

def mode_a(sbit=0, ebit=0, src=2, i=0, u=0, s=0, a=0, dbq=0, trb=0, tr=7):
    return bytes([(sbit << 3) | ebit, (src << 5) | (i << 4) | (u << 3) | (s << 2) | (a << 1),
                  (dbq << 3) | trb, tr])

def mode_b(sbit=0, ebit=0, src=2, quant=10, gobn=3, mba=100, i=0, u=0, s=0, a=0,
           hmv1=5, vmv1=6, hmv2=7, vmv2=8):
    return bytes([0x80 | (sbit << 3) | ebit, (src << 5) | quant,
                  (gobn << 3) | (mba >> 6), ((mba & 0x3f) << 2),
                  (i << 7) | (u << 6) | (s << 5) | (a << 4) | (hmv1 >> 3),
                  ((hmv1 & 7) << 5) | (vmv1 >> 2), ((vmv1 & 3) << 6) | (hmv2 >> 1),
                  ((hmv2 & 1) << 7) | vmv2])

def mode_c(dbq=1, trb=2, tr=9, **kw):
    return bytes([mode_b(**kw)[0] | 0x40]) + mode_b(**kw)[1:] + bytes([0, 0, (dbq << 3) | trb, tr])

def picture(tr=1, split=0, doc=0, freeze=0, src=2, ctype=0, umv=0, sac=0, ap=0, pb=0,
            pquant=8, cpm=0, psbi=0, trb=2, dbq=1, psupp=(), tail=b'\xaa\xbb\xcc'):
    """PSC and picture header of H.263 without PLUSPTYPE (src != 7)."""
    b = Bits().u(22, 0x20).u(8, tr).u(1, 1).u(1, 0).u(1, split).u(1, doc).u(1, freeze).u(3, src)
    b.u(1, ctype).u(1, umv).u(1, sac).u(1, ap).u(1, pb).u(5, pquant).u(1, cpm)
    if cpm: b.u(2, psbi)
    if pb: b.u(3, trb).u(2, dbq)
    for x in psupp: b.u(1, 1).u(8, x)
    b.u(1, 0)
    return b.pad().bytes() + tail

def picture_plus(tr=1, ufep=1, opp_src=2, custom_pcf=0, opp_rest=0x1000, ptc=1, mp_rest=0x08,
                 cpm=0, psbi=0, tail=b'\xaa\xbb\xcc\xdd', **kw):
    """PSC and picture header with PLUSPTYPE (source format 7)."""
    b = Bits().u(22, 0x20).u(8, tr).u(1, 1).u(1, 0).u(1, 0).u(1, 0).u(1, 0).u(3, 7)
    b.u(3, ufep)
    if ufep == 1:
        b.u(3, opp_src).u(1, custom_pcf).u(14, opp_rest)
    b.u(3, ptc).u(6, mp_rest).u(1, cpm)
    if cpm: b.u(2, psbi)
    return b.pad().bytes() + tail

def gob(gn=5):
    return Bits().u(17, 1).u(5, gn).u(2, 0).pad().bytes() + b'\x11\x22\x33\x44'

def picture4629(tr=3, tail=b'\xaa\xbb'):
    """Picture header as carried in RFC 4629 (first two zero octets of the PSC removed)."""
    b = Bits().u(6, 0x20).u(8, tr).u(1, 1).u(1, 0).u(3, 0).u(3, 2).u(5, 0).u(5, 9).u(1, 0).u(1, 0)
    return b.pad().bytes() + tail

def h263p_hdr(p=1, v=0, plen=0, pebit=0):
    return struct.pack('!H', (p << 10) | (v << 9) | (plen << 3) | pebit)

def iax2_video(src, dst, ts, oseq, iseq, csub, payload):
    return struct.pack('!HHIBBBB', 0x8000 | src, dst, ts, oseq, iseq, 3, csub) + payload

def main(out, verbose=False):
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def send(payload, mk=0):
        p.udp(A, B, 5006, 5006, rtp(payload, 34, mk))

    mark('SIP INVITE with SDP (static payload type 34 on UDP 5006)')
    p.udp(A, B, 5060, 5060, sip(sdp(5006, 34, 'H263/90000'), call='c23h263'))
    mark('mode A picture headers: source formats, picture coding type')
    for src in (1, 2, 3, 4, 5, 6):
        send(mode_a(src=src, i=src & 1) + picture(src=src, ctype=src & 1))
    mark('mode A: option bits, split screen, document camera, freeze release')
    send(mode_a(u=1, s=1, a=1) + picture(split=1, doc=1, freeze=1, umv=1, sac=1, ap=1, tr=200))
    mark('mode A: CPM with PSBI')
    send(mode_a() + picture(cpm=1, psbi=2))
    mark('mode A: PB-frames mode (TRB, DBQUANT)')
    send(mode_a(dbq=2, trb=5) + picture(pb=1, trb=5, dbq=2))
    mark('mode A: PEI with PSUPP octets (one, then three)')
    send(mode_a() + picture(psupp=(0x55,)))
    send(mode_a() + picture(psupp=(0x01, 0x02, 0x03)))
    mark('mode A: source format 7 (PLUSPTYPE), UFEP 1, custom PCF 0/1, picture type codes')
    send(mode_a(src=7) + picture_plus(ufep=1, custom_pcf=0, ptc=0))
    send(mode_a(src=7) + picture_plus(ufep=1, custom_pcf=1, ptc=2, opp_src=6))
    mark('mode A: PLUSPTYPE with UFEP 0, and with CPM / PSBI')
    send(mode_a(src=7) + picture_plus(ufep=0, ptc=3))
    send(mode_a(src=7) + picture_plus(ufep=1, cpm=1, psbi=3, ptc=1))
    mark('mode A: GOB start code (GBSC, group number)')
    send(mode_a() + gob(5))
    send(mode_a() + gob(31))
    mark('mode A: EOS (00 00 fc), EOSBS (00 00 f8), 00 00 fe')
    send(mode_a() + b'\x00\x00\xfc\x00\x01')
    send(mode_a() + b'\x00\x00\xf8\x00\x01')
    send(mode_a() + b'\x00\x00\xfe\x00\x01')
    mark('mode A: no start code; data shorter than 4 octets; no data')
    send(mode_a() + bytes(range(1, 20)))
    send(mode_a() + b'\x00\x01\x02')
    send(mode_a())
    mark('mode B headers with picture and GOB data')
    send(mode_b() + picture())
    send(mode_b(sbit=1, ebit=2, src=3, quant=31, gobn=31, mba=511, i=1, u=1, s=1, a=1,
                hmv1=127, vmv1=127, hmv2=127, vmv2=127) + gob(2))
    mark('mode C headers (PB-frames)')
    send(mode_c(dbq=3, trb=7, tr=250) + picture(pb=1))
    send(mode_c(src=5, quant=1) + gob(7))
    mark('IAX2 video frames with the H.263 codec (UDP 4569)')
    p.udp(A, B, 4569, 4569, iax2_video(0x1234, 1, 100, 1, 0, 0x80 | 19, mode_a() + picture()))
    p.udp(A, B, 4569, 4569, iax2_video(0x1234, 1, 140, 2, 0, 0x80 | 19 | 0x40, mode_a() + gob(3)))

    mark('SIP INVITE for H263-1998 (RFC 4629) on UDP 5008, payload type 98: picture and GOB layer routines with the RFC 4629 bit layout')
    p.udp(A, B, 5060, 5060, sip(sdp(5008, 98, 'H263-1998/90000'), call='c23h263b'))
    p.udp(A, B, 5008, 5008, rtp(h263p_hdr() + picture4629(), 98))
    p.udp(A, B, 5008, 5008, rtp(h263p_hdr() + Bits().u(1, 1).u(5, 9).u(2, 0).pad().bytes() + b'\x11', 98))

    p.write(os.path.join(out, 'h263-coverage.pcap'))
    n = len(p.frames)

    m = Pcap()
    m.udp(A, B, 5060, 5060, sip(sdp(5006, 34, 'H263/90000'), call='c23h263'))
    def msend(payload): m.udp(A, B, 5006, 5006, rtp(payload, 34))
    # picture headers cut off inside the bit fields (exception in the bit items)
    full = picture()
    for cut in (4, 6, 8, 9, 10):
        msend(mode_a() + full[:cut])
    msend(mode_a() + picture_plus()[:9])
    msend(mode_a() + picture(psupp=(0x55,))[:11])
    msend(mode_a() + gob(5)[:5])
    msend(mode_a() + gob(5)[:4])
    msend(mode_b()[:6])
    msend(mode_a()[:2])
    m.write(os.path.join(out, 'h263-coverage-malformed.pcap'))
    if verbose:
        print('main capture: %d frames' % n)
        for k, d in marks: print('  %d: %s' % (k, d))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

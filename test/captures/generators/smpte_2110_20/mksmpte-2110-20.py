#!/usr/bin/env python3
# Generates test/captures/smpte_2110_20_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMPTE ST 2110-20 dissector
(packet-smpte-2110-20.c, uncompressed active video over RTP).

Usage: mksmpte-2110-20.py <output directory>

The RTP stream is announced by a SIP INVITE whose SDP names the payload
type "ST2110-20" (rtpmap), which is how RTP reaches the dissector by
default. Every packet is built with struct; nothing is captured.

Writes:
  smpte-2110-20-coverage.pcapng            Ethernet (interface 0) and
                                           Exported PDU (interface 1)
  smpte-2110-20-coverage-malformed.pcapng  SRD headers or data cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, udp

SIP = ('INVITE sip:video@192.0.2.2 SIP/2.0\r\n'
       'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
       'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:video@192.0.2.2>\r\n'
       'Call-ID: st2110-20@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
       'Contact: <sip:a@192.0.2.1>\r\nContent-Type: application/sdp\r\n'
       'Content-Length: %d\r\n\r\n%s')
SDP = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=video\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n'
       'm=video 5004 RTP/AVP 96\r\n'
       'a=rtpmap:96 ST2110-20/90000\r\n'
       'a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10\r\n')


def rtp(seq, ts, payload, pt=96, marker=0, ssrc=0x1234):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts, ssrc) + payload


def srd(rows, ext=0):
    """rows: list of (length, field, rownum, offset); data follows."""
    p = struct.pack('!H', ext)
    for i, (ln, fld, row, off) in enumerate(rows):
        cont = 0x8000 if i < len(rows) - 1 else 0
        p += struct.pack('!HHH', ln, (fld << 15) | row, cont | off)
    for ln, *_ in rows:
        p += bytes((k * 7) & 0xff for k in range(ln))
    return p


def vid(seq, payload, ts=3000, port=5004):
    return udp(rtp(seq, ts, payload), 5004, port, ident=seq & 0xffff)


def main(out):
    sdp = SDP
    fr = [udp((SIP % (len(sdp), sdp)).encode(), 5060, 5060)]
    # one, two and three SRD headers, field bits, continuation, offsets
    fr.append(vid(100, srd([(16, 0, 0, 0)])))
    fr.append(vid(101, srd([(8, 1, 1, 0), (8, 1, 2, 4)])))
    fr.append(vid(102, srd([(4, 0, 1079, 100), (4, 0, 1079, 104), (4, 1, 3, 0x7fff)])))
    fr.append(vid(103, srd([(0, 0, 5, 0)]), ts=6000))
    fr.append(vid(104, srd([(1200, 0, 10, 0)], ext=1), ts=6000, ))
    # the extended sequence number: RTP seq wraps, ext field changes
    fr.append(vid(65535, srd([(12, 0, 20, 0)], ext=0x0102), ts=9000))
    fr.append(vid(0, srd([(12, 0, 21, 0)], ext=0x0103), ts=9000))
    # the reproducer of the field-width fix as a registered RTP stream:
    # the 32 bit sequence number 0x0102xxxx (16908288 = 0x0102 0000)
    fr.append(vid(0, srd([(4, 0, 0, 0)], ext=0x0102), ts=12000))
    # trailing bytes after the SRD data (left to the RTP dissector)
    fr.append(vid(1, srd([(4, 0, 0, 0)]) + b'\xaa\xbb', ts=12000))
    # second RTP stream, same ports, marker bit
    fr.append(udp(rtp(2, 12000, srd([(4, 0, 0, 0)]), marker=1), 5004, 5004, ident=2))
    # Exported PDU naming st2110_20: no RTP conversation data, so the RTP
    # sequence number and timestamp are 0; the fix: 32 bit st2110_20.seq
    ep = exported_pdu('st2110_20', struct.pack('!H', 0x0102) +
                      struct.pack('!HHH', 4, 0x0001, 0x0000) + b'\x11\x22\x33\x44')
    ep2 = exported_pdu('st2110_20', srd([(4, 0, 7, 0), (4, 1, 8, 0)], ext=0xffff))
    n = len(fr)
    frames = [(0, f) for f in fr] + [(1, ep), (1, ep2)]
    pcapng(os.path.join(out, 'smpte-2110-20-coverage.pcapng'), frames,
           (LT_ETH, LT_EXPORTED_PDU))
    print('frames 1-%d Ethernet (1 SIP, 2-%d RTP), %d-%d Exported PDU' % (n, n, n + 1, n + 2))
    # malformed
    m = [(0, udp((SIP % (len(sdp), sdp)).encode(), 5060, 5060))]
    m.append((0, vid(200, struct.pack('!H', 0))))                        # no SRD header
    m.append((0, vid(201, struct.pack('!HHH', 4, 0, 0)[:-1])))          # header cut
    m.append((0, vid(202, srd([(50, 0, 1, 0)])[:20])))                  # data cut
    m.append((0, vid(203, struct.pack('!H', 0) + struct.pack('!HHH', 4, 0, 0x8000) * 3)))  # 3 headers, data missing
    m.append((0, vid(204, b'\x01')))                                    # ext seqno cut
    m.append((1, exported_pdu('st2110_20', b'\x00')))
    pcapng(os.path.join(out, 'smpte-2110-20-coverage-malformed.pcapng'), m,
           (LT_ETH, LT_EXPORTED_PDU))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

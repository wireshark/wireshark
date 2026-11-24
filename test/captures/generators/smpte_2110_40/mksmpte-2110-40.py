#!/usr/bin/env python3
# Generates test/captures/smpte_2110_40_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMPTE ST 2110-40 dissector
(packet-smpte-2110-40.c, RFC 8331 ancillary data over RTP).

Usage: mksmpte-2110-40.py <output directory>

A SIP INVITE with an SDP rtpmap "smpte291" announces the RTP stream, which
is how RTP reaches the dissector by default; an Exported PDU frame names
st2110_40 directly. Every packet is built with struct; nothing is captured.

Writes:
  smpte-2110-40-coverage.pcapng            Ethernet (interface 0) and
                                           Exported PDU (interface 1)
  smpte-2110-40-coverage-malformed.pcapng  bad lengths, reserved bits,
                                           F=1, bad parity, checksum and
                                           word_align, truncated packets
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, udp
from vanc import afd, anc_words, bits, cdp, timecode, tobytes

SIP = ('INVITE sip:anc@192.0.2.2 SIP/2.0\r\n'
       'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
       'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:anc@192.0.2.2>\r\n'
       'Call-ID: st2110-40@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
       'Contact: <sip:a@192.0.2.1>\r\nContent-Type: application/sdp\r\n'
       'Content-Length: %d\r\n\r\n%s')
SDP = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=anc\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n'
       'm=video 5006 RTP/AVP 100\r\n'
       'a=rtpmap:100 smpte291/90000\r\n'
       'a=fmtp:100 DID_SDID={0x61,0x01}\r\n')


def anc(c, line, hoff, s, stream, did, sdid, udw, align_fill='0', **kw):
    """One RFC 8331 ANC packet padded to a 32 bit boundary."""
    b = str(c) + format(line, '011b') + format(hoff, '012b') + str(s) + format(stream, '07b')
    b += bits(anc_words(did, sdid, udw, **kw))
    b += align_fill * ((-len(b)) % 32)
    return tobytes(b)


def payload(ancs, esn=0, f=0, res=0, count=None, length=None):
    body = b''.join(ancs)
    n = len(ancs) if count is None else count
    ln = len(body) if length is None else length
    return struct.pack('!HHBBH', esn, ln, n, (f << 6) | ((res >> 16) & 0x3f), res & 0xffff) + body


def rtp(seq, ts, pl, pt=100, marker=1, ssrc=0x2345):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts, ssrc) + pl


def pkt(seq, pl, ts=9000, port=5006, ident=None):
    return udp(rtp(seq, ts, pl), 5006, port, ident=ident or seq)


def main(out):
    fr = [udp((SIP % (len(SDP), SDP)).encode(), 5060, 5060)]
    seq = [0]

    def add(pl, ts=9000):
        seq[0] += 1
        fr.append(pkt(seq[0], pl, ts))

    tc = timecode()
    add(payload([]))                                            # no ANC data
    add(payload([anc(0, 9, 0, 0, 0, 0x60, 0x60, tc)], f=0))     # time code, progressive
    add(payload([anc(1, 20, 100, 0, 0, 0x41, 0x05, afd())], f=2))   # AFD, field 1, C channel
    add(payload([anc(0, 21, 0xffe, 1, 5, 0x41, 0x0b, [1, 2, 3])], f=3))   # field 2, S bit, stream 5
    add(payload([anc(0, 0x7ff, 0xfff, 0, 0, 0xe0, 0x11, [])]))   # Type 1 with DBN, no UDW, no location
    add(payload([anc(0, 0x7fe, 0xffe, 0, 0, 0xec, 0x12, [9, 8, 7, 6])]))
    add(payload([anc(0, 0x7fd, 0xffd, 0, 0, 0xf4, 0x13, [0x7f])]))
    add(payload([anc(0, 100, 0xffc, 0, 0, 0xa0, 0x01, list(range(11)))]))    # offset too big
    # several packets in one RTP payload with data counts 0-9 (all alignments)
    add(payload([anc(k & 1, 30 + k, k * 7, 0, 0, 0x45, 1 + (k & 7), list(range(k))) for k in range(10)]),
        ts=12000)
    # a long packet (255 UDW)
    add(payload([anc(0, 40, 0, 0, 0, 0x44, 0x04, [(5 * k) & 0xff for k in range(255)])]))
    # extended sequence number
    add(payload([anc(0, 41, 0, 0, 0, 0x60, 0x60, timecode(1, 2, 3, 4, drop=True))], esn=0x1234))
    # other known DIDs for the shared ST 291 table
    for did, sdid, u in ((0x61, 0x01, cdp()), (0x61, 0x01, cdp(0x4321, 3, False)),
                         (0x50, 0x01, [0x12, 0x34]), (0x62, 0x01, [3]), (0x99, 0x77, [1])):
        add(payload([anc(0, 50, 0, 0, 0, did, sdid, u)]))
    # a second stream on the other side (port 5006 -> 5006): the same stream
    fr.append(udp(rtp(200, 15000, payload([anc(0, 9, 0, 0, 0, 0x60, 0x60, tc)])), 5006, 5006, ident=200))
    n = len(fr)
    ep = exported_pdu('st2110_40', payload([anc(0, 9, 0, 0, 0, 0x60, 0x60, tc),
                                             anc(0, 10, 0, 0, 0, 0x41, 0x05, afd())]))
    pcapng(os.path.join(out, 'smpte-2110-40-coverage.pcapng'),
           [(0, f) for f in fr] + [(1, ep)], (LT_ETH, LT_EXPORTED_PDU))
    print('frames 1-%d Ethernet (1 SIP, 2-%d RTP), %d Exported PDU' % (n, n, n + 1))

    # malformed (RTP stream announced by the same INVITE)
    m = [udp((SIP % (len(SDP), SDP)).encode(), 5060, 5060)]
    good = anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2, 3])

    def madd(pl):
        seq[0] += 1
        m.append(pkt(seq[0], pl))
    madd(payload([], length=4))                                  # count 0, length != 0
    madd(payload([good], length=0))                              # count != 0, length 0
    madd(payload([good], f=1))                                   # F = 1
    madd(payload([good], res=0x2a5a5))                           # reserved bits
    madd(payload([good], length=len(good) + 40))                 # claims more than present
    madd(payload([good, good], count=1))                         # length bigger than count accounts for
    madd(payload([good], count=3))                               # count bigger than data
    madd(payload([good], length=len(good) - 4))                  # packet past the Length boundary
    madd(payload([good])[:12])                                   # header of the ANC packet cut short
    madd(payload([good])[:8])                                    # nothing after the payload header
    madd(struct.pack('!HHB', 0, 0, 0))                           # payload header cut short (7 octets)
    # the ANC packet lacks its word_align bits: 82 bits of content in an 11 octet Length
    nopad = payload([anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1])])
    madd(struct.pack('!HHBBH', 0, 11, 1, 0, 0) + nopad[8:19])
    madd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2], bad_did=True, bad_sdid=True, bad_dc=True)]))
    madd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2], bad_cs=True)]))
    madd(payload([anc(0, 9, 0, 0, 0, 0xe0, 0x0b, [1, 2], bad_sdid=True, bad_cs=True)]))
    madd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x00, [1, 2])]))                 # SDID 0 in Type 2
    madd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2, 3], align_fill='1')]))   # word_align bits set
    madd(payload([anc(0, 9, 0, 0, 0, 0x60, 0x60, [1, 2, 3])]))              # short time code
    madd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x05, [1, 2, 3])]))              # short AFD
    # captured length shorter than the ANC data (snaplen cut)
    cut = pkt(900, payload([good, good]))
    pcapng(os.path.join(out, 'smpte-2110-40-coverage-malformed.pcapng'),
           [(0, f) for f in m] + [(0, cut[:-9], len(cut)), (1, exported_pdu('st2110_40', b'\0\0'))],
           (LT_ETH, LT_EXPORTED_PDU))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

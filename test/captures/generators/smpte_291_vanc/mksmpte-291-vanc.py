#!/usr/bin/env python3
# Generates test/captures/smpte_291_vanc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMPTE ST 291 / VANC payload
dissectors (packet-smpte-291-vanc.c: ST 12-2 time code, ST 2010 SCTE-104
fragments, ST 2016-3 AFD and bar data, ST 334-2 caption distribution
packets, ST 2031 and OP-47 teletext).

Usage: mksmpte-291-vanc.py <output directory>

The ancillary packets travel in RTP (RFC 8331, ST 2110-40): a SIP INVITE
with an SDP rtpmap "smpte291" announces the stream, which is how RTP
reaches the ST 2110-40 dissector by default, and that dissector hands each
ANC packet to the "st291.did_sdid" table. Exported PDU frames name the
payload dissectors (st12_2, st2010, st2016_3, st334_2, st2031, op47)
directly. Every packet is built with struct; nothing is captured.

Writes:
  smpte-291-vanc-coverage.pcapng            Ethernet (interface 0) and
                                            Exported PDU (interface 1)
  smpte-291-vanc-coverage-malformed.pcapng  bad lengths, reserved bits,
                                            truncated sections, orphan
                                            fragments, short ANC packets
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, udp
from vanc import anc_words, bits, tobytes

SIP = ('INVITE sip:anc@192.0.2.2 SIP/2.0\r\n'
       'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
       'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:anc@192.0.2.2>\r\n'
       'Call-ID: st291-vanc@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
       'Contact: <sip:a@192.0.2.1>\r\nContent-Type: application/sdp\r\n'
       'Content-Length: %d\r\n\r\n%s')
SDP = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=anc\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n'
       'm=video 5006 RTP/AVP 100\r\n'
       'a=rtpmap:100 smpte291/90000\r\n'
       'm=video 5008 RTP/AVP 100\r\n'
       'a=rtpmap:100 smpte291/90000\r\n')


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


# ---------------------------------------------------------------- ST 12-2
def atc(h=12, m=34, s=56, f=7, drop=False, color=False, flags=0, bg=None, dbb1=0, dbb2=0):
    """16 UDWs of ST 12-2: BCD digits in the high nibble of the odd
    numbered UDWs (1-based), binary groups in the even ones. bg: eight
    nibbles (binary groups 1-8); flags: bits to set in the flag positions
    (b4-b7 of UDW 7, 11, 15 as 27/43/58/59 style bits)."""
    bg = bg or [0] * 8
    u = [0] * 16
    u[0] = (f % 10) << 4
    u[2] = ((f // 10) << 4) | (0x40 if drop else 0) | (0x80 if color else 0)
    u[4] = (s % 10) << 4
    u[6] = ((s // 10) << 4) | (0x80 if flags & 1 else 0)
    u[8] = (m % 10) << 4
    u[10] = ((m // 10) << 4) | (0x80 if flags & 2 else 0)
    u[12] = (h % 10) << 4
    u[14] = ((h // 10) << 4) | (0x40 if flags & 4 else 0) | (0x80 if flags & 8 else 0)
    for i in range(8):
        u[2 * i + 1] = (bg[i] & 0xf) << 4
    # The dissector reads DBB1/DBB2 from bit 4 counted from the most
    # significant bit (mask 0x08) of UDW 1-8 and 9-16
    for i in range(8):
        u[i] |= ((dbb1 >> i) & 1) << 3
        u[8 + i] |= ((dbb2 >> i) & 1) << 3
    return u


# ---------------------------------------------------------------- ST 2016-3
def afd3(afd=8, ar=1, flags=0xc0, v1=0xc000 | 100, v2=0xc000 | 200, r1=0, r2=0, afd_res=0):
    return [(afd << 3) | (ar << 2) | afd_res, r1, r2, flags, v1 >> 8, v1 & 0xff, v2 >> 8, v2 & 0xff]


# ---------------------------------------------------------------- ST 334-2
def cdp_pkt(rate=7, seq=0x1234, tc=True, cc=True, svc=0, future=(), ccn=None,
            cctypes=None, ident=0x9669, footer=True, fseq=None, flags_extra=0x01,
            order=None, bad_sum=False, length=None, tc_bytes=None, svcs=None,
            svc_flags_start=0, ccvalid=0x04, svc_res=0x80, ccmark=0xf8):
    counts = {1: 25, 2: 25, 3: 24, 4: 20, 5: 20, 6: 12, 7: 10, 8: 10}
    n = counts.get(rate, 10) if ccn is None else ccn
    secs = {}
    if tc:
        secs['tc'] = tc_bytes or bytes([0x71, 0xc0 | 0x12, 0x80 | 0x34, 0x40 | 0x56, 0x80 | 0x07])
    if cc:
        body = bytes([0x72, 0xe0 | n])
        for i in range(n):
            t = (cctypes[i % len(cctypes)] if cctypes else (3 if i == 0 else 2))
            body += bytes([ccmark | ccvalid | t, 0x80 + i, 0x80 + i])
        secs['cc'] = body
    if svc:
        svcs = svcs if svcs is not None else [
            (0x80 | 1, b'eng', 0x80 | 0x40 | 1, 0x3f | 0x80, 0xff),
            (0x80 | 0x40 | 0x20 | 3, b'spa', 0x40 | 0x7e | 1, 0x3f | 0x40, 0xff)][:svc]
        sb = bytes([0x73, svc_res | (svc_flags_start << 4) | len(svcs)])
        for first, lang, b4, b5, b6 in svcs:
            sb += bytes([first]) + lang + bytes([b4, b5, b6])
        secs['svc'] = sb
    fut = b''.join(bytes([i, len(d)]) + d for i, d in future)
    order = order or ['tc', 'cc', 'svc', 'fut']
    body = b''
    for k in order:
        if k == 'fut':
            body += fut
        elif k in secs:
            body += secs[k]
    flags = (0x80 if tc else 0) | (0x40 if cc else 0) | (0x20 if svc else 0) | \
        (svc_flags_start << 2) | 0x02 | flags_extra
    hdr = struct.pack('>HBBBH', ident, 0, (rate << 4) | 0x0f, flags, seq)
    total = len(hdr) + len(body) + (4 if footer else 0)
    hdr = struct.pack('>HBBBH', ident, total if length is None else length,
                      (rate << 4) | 0x0f, flags, seq)
    s = hdr + body
    if footer:
        ft = bytes([0x74]) + struct.pack('>H', seq if fseq is None else fseq)
        s += ft
        ck = (-sum(s)) & 0xff
        if bad_sum:
            ck ^= 0x55
        s += bytes([ck])
    return list(s)


# ---------------------------------------------------------------- WST
def wst_bytes(mag, pnum, page=0x42, text=b'', ctrl=0xff, c8=0xff, c9=0xff, fill=0x00):
    """42 octet teletext packet: the magazine and packet number are in the
    odd bit positions 1,3,5 and 7,9,11,13,15; the page units/tens in the
    odd bits of octets 2 and 3."""
    b = bytearray([fill] * 42)

    def setbit(bitpos, v):
        if v:
            b[bitpos // 8] |= 0x80 >> (bitpos % 8)
        else:
            b[bitpos // 8] &= ~(0x80 >> (bitpos % 8)) & 0xff
    m = mag & 7
    for i, p in enumerate((1, 3, 5)):
        setbit(p, (m >> i) & 1)
    for i, p in enumerate((7, 9, 11, 13, 15)):
        setbit(p, (pnum >> i) & 1)
    if pnum == 0:
        for i, p in enumerate((17, 19, 21, 23)):
            setbit(p, ((page & 0xf) >> i) & 1)
        for i, p in enumerate((25, 27, 29, 31)):
            setbit(p, ((page >> 4) >> i) & 1)
        b[5], b[7], b[8], b[9] = ctrl, ctrl, c8, c9
        text = (text or b'HEADER 0123456789 TELETEXT PAGE').ljust(32)[:32]
        b[10:42] = bytes(((c & 0x7f) << 1) | (bin(c & 0x7f).count('1') & 1 ^ 1) for c in text)
    elif 1 <= pnum <= 25:
        text = (text or b'Packet text line of forty characters.').ljust(40)[:40]
        b[2:42] = bytes(((c & 0x7f) << 1) | (bin(c & 0x7f).count('1') & 1 ^ 1) for c in text)
    return bytes(b)


def st2031(unit=2, ident=0x10, wst=None, dlen=44, fieldline=0x20 | 7, framing=0xe4):
    wst = wst if wst is not None else wst_bytes(1, 1)
    return list(bytes([ident, unit, dlen, fieldline, framing]) + wst)


def op47(wsts, fmt=2, ident=0x5115, adesc=None, length=None, trunc=0):
    n = len(wsts)
    ad = adesc if adesc is not None else ([0x0a + i for i in range(n)] + [0] * (5 - n))[:5]
    body = bytes(ad)
    for w in wsts:
        rev = bytes(int(format(c, '08b')[::-1], 2) for c in w)
        body += bytes([0x55, 0x55, 0x27]) + rev
    s = struct.pack('>HBB', ident, 9 + 45 * n if length is None else length, fmt) + body
    s = s[:len(s) - trunc]
    return list(s)


def main(out):
    fr = [udp((SIP % (len(SDP), SDP)).encode(), 5060, 5060)]
    seq = [0]

    def add(pl, ts=9000, port=5006):
        seq[0] += 1
        fr.append(pkt(seq[0], pl, ts, port))

    def one(did, sdid, udw, line=9, ts=9000, port=5006, **kw):
        add(payload([anc(0, line, 0, 0, 0, did, sdid, udw, **kw)]), ts, port)

    # ---- ST 12-2 time code
    one(0x60, 0x60, atc())
    one(0x60, 0x60, atc(23, 59, 58, 29, drop=True, color=True, flags=0xf))
    one(0x60, 0x60, atc(0, 0, 0, 0))
    one(0x60, 0x60, atc(1, 2, 2, 1, flags=3, bg=[0, 2, 4, 6, 3, 5, 7, 9], dbb1=0x01, dbb2=0xa5))   # VITC 1
    one(0x60, 0x60, atc(1, 2, 2, 2, bg=[1, 0, 0, 0, 1, 1, 1, 1], dbb1=0x02, dbb2=0x5a))        # VITC 2
    for t in (0x00, 0x03, 0x06, 0x07, 0x7d, 0x7e, 0x7f, 0x55):
        one(0x60, 0x60, atc(2, 3, 4, 5, dbb1=t, dbb2=t ^ 0xff))
    one(0x60, 0x60, atc(10, 20, 30, 12, bg=[0xf] * 8))
    one(0x60, 0x60, atc(7, 8, 9, 3, bg=[2, 4, 6, 8, 3, 5, 7, 9]))
    one(0x60, 0x60, atc(11, 11, 11, 11, bg=[0, 8, 0, 8, 1, 9, 1, 9]))
    # ---- ST 2016-3 AFD and bar data
    for afd in range(16):
        for ar in (0, 1):
            one(0x41, 0x05, afd3(afd, ar, flags=0x00 if afd % 3 else 0xc0))
    one(0x41, 0x05, afd3(10, 0, flags=0x30, v1=0xc000 | 5, v2=0xc000 | 6))      # left and right bars
    one(0x41, 0x05, afd3(10, 1, flags=0xc0, v1=0xc000 | 0x3fff, v2=0xc000 | 0))
    # ---- ST 334-2 caption distribution packets
    for rate in range(1, 9):
        one(0x61, 0x01, cdp_pkt(rate=rate, seq=0x100 + rate))
    one(0x61, 0x01, cdp_pkt(tc=False, cc=True, seq=1))
    one(0x61, 0x01, cdp_pkt(tc=True, cc=False, seq=2))
    one(0x61, 0x01, cdp_pkt(tc=False, cc=False, seq=3))
    one(0x61, 0x01, cdp_pkt(cc=True, cctypes=[0, 1, 0, 1], ccn=4, rate=9, seq=4))   # 608 only, unknown rate
    one(0x61, 0x01, cdp_pkt(cc=True, cctypes=[2, 3, 3, 2], ccn=4, rate=0, seq=5))
    one(0x61, 0x01, cdp_pkt(cc=True, ccn=0, rate=0, seq=6))                         # no constructs
    one(0x61, 0x01, cdp_pkt(svc=1, seq=7, svc_flags_start=7))
    one(0x61, 0x01, cdp_pkt(svc=2, seq=8, svc_flags_start=2))
    one(0x61, 0x01, cdp_pkt(svc=2, seq=9, tc=False, cc=False))
    one(0x61, 0x01, cdp_pkt(svc=1, svcs=[], seq=10))                                # no services
    one(0x61, 0x01, cdp_pkt(future=[(0x75, b''), (0xa0, b'\x01\x02\x03'), (0xef, b'x' * 20)], seq=11))
    one(0x61, 0x01, cdp_pkt(svc=2, future=[(0x80, b'abc')], seq=12, order=['tc', 'cc', 'svc', 'fut']))
    # extra bytes after the footer (declared length shorter than the payload is a warning:
    # keep the length right and exercise the checksum with an unusual sum)
    one(0x61, 0x01, cdp_pkt(seq=13, cctypes=[2, 2, 2], rate=9, ccn=3))
    # CC-608 constructs with the valid bit clear (dtvcc not collected)
    one(0x61, 0x01, cdp_pkt(seq=14, rate=7, ccn=10, cctypes=[0, 1], ccvalid=0))
    one(0x61, 0x01, cdp_pkt(seq=15, rate=7, ccn=10, cctypes=[2, 0, 3, 1]))
    # ---- ST 2010 SCTE-104: single message, fragmented message (first, middle, last)
    one(0x41, 0x07, [0x08] + list(range(1, 33)), ts=20000)
    one(0x41, 0x07, [0x08, 0xff, 0xff, 0x00, 0x01])
    one(0x41, 0x07, [0x0c] + [0xa0 + i for i in range(20)], line=11, ts=21000)       # continued
    one(0x41, 0x07, [0x0e] + [0xb0 + i for i in range(20)], line=12, ts=21000)       # continued + following
    one(0x41, 0x07, [0x0e] + [0xb0 + i for i in range(5)], line=13, ts=21000)
    one(0x41, 0x07, [0x0a] + [0xc0 + i for i in range(10)], line=14, ts=21000)       # last
    # a message of two fragments on another stream, a duplicate flag
    one(0x41, 0x07, [0x0d] + [0x31] * 7, line=11, ts=22000, port=5008)               # continued, duplicate
    one(0x41, 0x07, [0x0b] + [0x32] * 7, line=12, ts=22000, port=5008)               # last, duplicate
    # a second complete message after the first on the first stream
    one(0x41, 0x07, [0x0c] + [0x41] * 4, line=11, ts=23000)
    one(0x41, 0x07, [0x0a] + [0x42] * 4, line=12, ts=23000)
    # ---- ST 2031 teletext
    one(0x41, 0x08, st2031(2, wst=wst_bytes(1, 0, 0x42)))                           # header packet, page 0x142
    one(0x41, 0x08, st2031(3, wst=wst_bytes(8, 0, 0x99, ctrl=0x00, c8=0x00, c9=0x00)))
    one(0x41, 0x08, st2031(2, wst=wst_bytes(1, 1)))
    one(0x41, 0x08, st2031(3, wst=wst_bytes(5, 25, text=b'last text row')))
    one(0x41, 0x08, st2031(2, wst=wst_bytes(2, 26)))                                # no text defined
    one(0x41, 0x08, st2031(2, wst=wst_bytes(3, 31)))
    one(0x41, 0x08, st2031(0xc3, wst=b''))                                          # VPS: not parsed
    one(0x41, 0x08, st2031(0xc5, wst=b'\x00' * 4))
    one(0x41, 0x08, st2031(2, wst=wst_bytes(1, 2)[:20]))                            # data block too short
    one(0x41, 0x08, [0x10])                                                         # one octet only
    # ---- OP-47
    one(0x43, 0x02, op47([wst_bytes(1, 0, 0x01)]))
    one(0x43, 0x02, op47([wst_bytes(1, 0, 0x01), wst_bytes(1, 1), wst_bytes(1, 2)]))
    one(0x43, 0x02, op47([wst_bytes(2, i) for i in range(5)]))
    one(0x43, 0x02, op47([wst_bytes(1, 3)], fmt=0x07))                              # other format code
    one(0x43, 0x02, op47([wst_bytes(1, 3)], adesc=[0, 0, 0, 0, 0]))                 # no descriptor
    one(0x43, 0x02, op47([wst_bytes(1, 3), wst_bytes(1, 4)], adesc=[0x0a, 0, 0, 0, 0]))   # stops at the second
    one(0x43, 0x02, op47([wst_bytes(1, 3), wst_bytes(1, 4)], trunc=20))             # second structure cut
    one(0x43, 0x02, [0x51, 0x15, 5, 0x02, 0x0a])                                    # shorter than nine octets
    one(0x43, 0x02, [0x51, 0x15, 5])                                                # shorter than four
    # ---- other ST 291 identities (generic lookup in the shared table)
    for did, sdid in ((0x08, 0x08), (0x40, 0x01), (0x41, 0x01), (0x41, 0x0b), (0x43, 0x01), (0x44, 0x04),
                      (0x45, 0x03), (0x50, 0x01), (0x60, 0x61), (0x62, 0x01), (0x99, 0x77)):
        one(did, sdid, [1, 2, 3, 4], line=20)
    for did in (0x00, 0x80, 0xa0, 0xe0, 0xec, 0xf0, 0xf4, 0xf8, 0xc3):
        one(did, 0x11, [9, 8, 7], line=21)
    # several ANC packets in one RTP payload, all dispatched
    add(payload([anc(0, 30, 0, 0, 0, 0x60, 0x60, atc(5, 4, 3, 2)),
                 anc(0, 31, 0, 0, 0, 0x41, 0x05, afd3(8, 1)),
                 anc(0, 32, 0, 0, 0, 0x61, 0x01, cdp_pkt(seq=77)),
                 anc(0, 33, 0, 0, 0, 0x41, 0x08, st2031(2, wst=wst_bytes(4, 7))),
                 anc(0, 34, 0, 0, 0, 0x43, 0x02, op47([wst_bytes(3, 9)]))]), ts=30000)
    n = len(fr)
    eps = [
        ('st12_2', bytes(atc(9, 8, 7, 6))),
        ('st2010', bytes([0x08, 1, 2, 3])),
        ('st2010', bytes([0x0c, 1, 2, 3])),
        ('st2010', bytes([0x0a, 4, 5, 6])),
        ('st2016_3', bytes(afd3(4, 0))),
        ('st334_2', bytes(cdp_pkt(seq=500))),
        ('st2031', bytes(st2031(2, wst=wst_bytes(6, 3)))),
        ('op47', bytes(op47([wst_bytes(7, 12)]))),
    ]
    pcapng(os.path.join(out, 'smpte-291-vanc-coverage.pcapng'),
           [(0, f) for f in fr] + [(1, exported_pdu(nm, p)) for nm, p in eps], (LT_ETH, LT_EXPORTED_PDU))
    print('frames 1-%d Ethernet (1 SIP, 2-%d RTP), %d-%d Exported PDU' % (n, n, n + 1, n + len(eps)))

    # ---------------------------------------------------------------- malformed
    m = [udp((SIP % (len(SDP), SDP)).encode(), 5060, 5060)]

    def madd(did, sdid, udw, port=5006, ts=9000, **kw):
        seq[0] += 1
        m.append(pkt(seq[0], payload([anc(0, 9, 0, 0, 0, did, sdid, udw, **kw)]), ts, port))

    madd(0x60, 0x60, atc()[:15])                                   # ST 12-2 short
    madd(0x41, 0x05, afd3()[:7])                                   # AFD length != 8
    madd(0x41, 0x05, afd3() + [0])
    madd(0x41, 0x05, afd3(3, 1, afd_res=0x81, r1=1, r2=2, flags=0xc5))   # reserved bits everywhere
    madd(0x41, 0x05, afd3(3, 1, flags=0x80))                       # top bar only
    madd(0x41, 0x05, afd3(3, 1, flags=0x40, v1=0x1000, v2=0x2000)) # bottom only, bad markers
    madd(0x41, 0x05, afd3(3, 1, flags=0x20))
    madd(0x41, 0x05, afd3(3, 1, flags=0x10, v1=5))
    madd(0x41, 0x05, afd3(3, 1, flags=0xf0, v1=0x1234, v2=0x4321)) # all four bars
    madd(0x41, 0x05, afd3(3, 1, flags=0xc0, v1=0xc005, v2=0x0007)) # value 2 marker bad
    madd(0x41, 0x05, afd3(3, 1, flags=0x30, v1=0x0005, v2=0x0007))
    # ST 2010
    madd(0x41, 0x07, [0x68, 1, 2, 3])                              # reserved bits
    madd(0x41, 0x07, [0x10, 1, 2, 3])                              # bad version
    madd(0x41, 0x07, [0x08])                                       # empty payload
    madd(0x41, 0x07, [0x0a, 1, 2])                                 # orphan following fragment
    madd(0x41, 0x07, [0x0c, 1, 2], ts=40000)                       # first fragment
    madd(0x41, 0x07, [0x0c, 3, 4], ts=40000)                       # new message while reassembling
    madd(0x41, 0x07, [0x0a, 5, 6], ts=40000)
    # ST 334-2
    madd(0x61, 0x01, [1, 2, 3, 4, 5, 6])                           # shorter than 7
    madd(0x61, 0x01, cdp_pkt(ident=0x1234))
    madd(0x61, 0x01, cdp_pkt(length=200))                          # length > payload
    madd(0x61, 0x01, cdp_pkt(length=3))                            # length < 7
    madd(0x61, 0x01, cdp_pkt(rate=7, ccn=7))                       # count != rate
    madd(0x61, 0x01, cdp_pkt(ccmark=0x00, seq=40))                 # marker bits clear
    madd(0x61, 0x01, cdp_pkt(fseq=9))                              # sequence mismatch
    madd(0x61, 0x01, cdp_pkt(bad_sum=True))
    madd(0x61, 0x01, cdp_pkt(order=['cc', 'tc', 'svc', 'fut']))    # order
    madd(0x61, 0x01, cdp_pkt(svc=1, order=['svc', 'tc', 'cc', 'fut']))
    madd(0x61, 0x01, cdp_pkt(footer=False))                        # no footer
    madd(0x61, 0x01, cdp_pkt(tc=False, cc=False, footer=False))
    madd(0x61, 0x01, cdp_pkt(flags_extra=0))                       # reserved bit clear
    madd(0x61, 0x01, cdp_pkt(svc=1, svc_flags_start=0)[:0] or cdp_pkt(svc=1, svc_flags_start=3, flags_extra=0))
    # header says no time code but a section is there, etc.
    b = cdp_pkt(seq=5)
    b[4] = 0x01 | 0x02                                             # flags: nothing present
    m.append(pkt(1000, payload([anc(0, 9, 0, 0, 0, 0x61, 0x01, b)])))
    b = cdp_pkt(svc=1, seq=6)
    b[3] = 0x70                                                    # reserved nibble of the rate byte
    m.append(pkt(1001, payload([anc(0, 9, 0, 0, 0, 0x61, 0x01, b)])))
    # service info start/change/complete flags differ from the CDP header
    b = cdp_pkt(svc=1, seq=9, svc_flags_start=3)
    b[4] ^= 0x04
    m.append(pkt(1002, payload([anc(0, 9, 0, 0, 0, 0x61, 0x01, b)])))
    # duplicate sections
    d = cdp_pkt(order=['tc', 'tc', 'cc', 'cc', 'svc', 'svc'], svc=1, seq=8)
    madd(0x61, 0x01, d)
    madd(0x61, 0x01, cdp_pkt(svc=2, svcs=[(0x80 | 0x40 | 0x1f, b'eng', 0x00, 0x00, 0x00),
                                          (0x80 | 2, b'fra', 0x7f, 0x00, 0x00)]))
    madd(0x61, 0x01, cdp_pkt(order=['tc', 'cc', 'svc', 'fut'], seq=2, svc=1,
                             svcs=[(0x81, b'eng', 0x80, 0x3f, 0xff)], svc_flags_start=7))
    madd(0x61, 0x01, cdp_pkt(cctypes=[0], rate=7, ccn=10, seq=3, cc=True)[:0] or
         [0x96, 0x69, 0x0d, 0x7f, 0x42, 0x00, 0x01] + [0x74, 0x00, 0x01, 0x00])  # short CDP, unknown flags
    # truncated sections: cut the payload and fix the declared length
    for trunc_at, sec in ((10, 'tc'), (8, 'cc'), (12, 'cc')):
        full = cdp_pkt(seq=20)
        cut = full[:trunc_at]
        cut[2] = len(cut)
        madd(0x61, 0x01, cut)
    sv = cdp_pkt(svc=2, seq=21, tc=False, cc=False)
    for cutlen in (8, 12, len(sv) - 9):
        c = sv[:cutlen]
        c[2] = len(c)
        madd(0x61, 0x01, c)
    fu = cdp_pkt(future=[(0x90, b'abcdef')], seq=22, tc=False, cc=False)
    for cutlen in (8, 11):
        c = fu[:cutlen]
        c[2] = len(c)
        madd(0x61, 0x01, c)
    c = cdp_pkt(seq=23, tc=False, cc=False, footer=False)
    c[2] = len(c) + 2
    madd(0x61, 0x01, c + [0x74, 0x00])                             # footer cut
    c2 = cdp_pkt(seq=24, tc=False, cc=False, footer=False)
    c2[2] = len(c2) + 1
    madd(0x61, 0x01, c2 + [0x72])                                  # CC section id without a count
    madd(0x61, 0x01, cdp_pkt(seq=25, tc=False, cc=False, footer=False, length=7 + 1) + [0x73])
    madd(0x61, 0x01, cdp_pkt(seq=26, tc=False, cc=False, footer=False, length=7 + 1) + [0x75])
    madd(0x61, 0x01, cdp_pkt(seq=27, tc=False, cc=False, footer=False, length=7 + 1) + [0x71])
    # unknown section id that cannot be skipped
    q = cdp_pkt(seq=28, tc=False, cc=False, footer=False)
    q = q + [0xf0, 0x00]
    q[2] = len(q)
    madd(0x61, 0x01, q)
    # a CC section whose declared constructs run past the end
    q = cdp_pkt(seq=29, tc=False, cc=False, footer=False) + [0x72, 0xe0 | 5, 0xff, 0x10]
    q[2] = len(q)
    madd(0x61, 0x01, q)
    # a CC data section with marker bits clear
    q = cdp_pkt(seq=30, tc=False, cc=False, footer=False) + [0x72, 0x03, 0x07, 1, 2, 0x00, 3, 4, 0x00, 5, 6]
    q[2] = len(q)
    madd(0x61, 0x01, q)
    # service information: reserved bits cleared
    q = cdp_pkt(seq=31, tc=False, cc=False, svc=1, footer=False, svc_res=0,
                svcs=[(0x00, b'eng', 0x00, 0x00, 0x00)])
    q[2] = len(q)
    madd(0x61, 0x01, q)
    q = cdp_pkt(seq=32, tc=False, cc=False, svc=1, footer=False, svc_flags_start=3,
                svcs=[(0x80 | 0x40 | 0x00, b'eng', 0x00, 0x00, 0x00)])
    madd(0x61, 0x01, q)
    # ST 2031: unit id 2 but fewer than 47 octets is not parsed (no tree below the header)
    # OP-47
    madd(0x43, 0x02, [0x51])                                       # shorter than four (not dissected)
    # a time code section with the footer after a future section (rank ordering)
    madd(0x61, 0x01, cdp_pkt(order=['fut', 'tc', 'cc'], future=[(0x80, b'zz')], seq=33))
    pcapng(os.path.join(out, 'smpte-291-vanc-coverage-malformed.pcapng'),
           [(0, f) for f in m] + [(1, exported_pdu('st12_2', b'\x01' * 4)),
                                  (1, exported_pdu('st2010', b'\x08')),
                                  (1, exported_pdu('st2010', b'')),
                                  (1, exported_pdu('st2016_3', b'\x01\x02')),
                                  (1, exported_pdu('st334_2', b'\x01\x02')),
                                  (1, exported_pdu('st2031', b'\x10')),
                                  (1, exported_pdu('op47', b'\x51'))],
           (LT_ETH, LT_EXPORTED_PDU))

    # ---------------------------------------------------------------- RTP/ANC header errors
    h = [udp((SIP % (len(SDP), SDP)).encode(), 5060, 5060)]
    good = anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2, 3])

    def hadd(pl):
        seq[0] += 1
        h.append(pkt(seq[0], pl))
    hadd(payload([good])[:12])                                     # ANC header cut short
    hadd(payload([good], length=len(good) - 4))                    # ANC packet past the Length boundary
    hadd(payload([anc(0, 9, 0, 0, 0, 0x41, 0x0b, [1, 2, 3, 4, 5])], length=8)[:16])
    pcapng(os.path.join(out, 'smpte-291-vanc-coverage-short.pcapng'),
           [(0, f) for f in h], (LT_ETH,))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

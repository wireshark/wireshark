#!/usr/bin/env python3
# Generates test/captures/h223_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.223 coverage captures. Usage: mkh223.py <outdir> [-v]

H.223 is reached the way a real call reaches it:
 * IAX2 (UDP 4569): a NEW frame with the DATAFORMAT information element
   "ITU-T H.223/H.245", an ACCEPT, then mini frames with bit-swapped
   MUX-PDUs (circuit mode);
 * RTP with payload type name CLEARMODE announced in SDP (conversation
   mode, bit-swapped);
 * TCP port 5555 needs Decode As h223 (not registered by default); these
   frames are the last ones of the main capture.
VC 0 carries SRP / CCSRL / H.245 (MultiplexEntrySend, OpenLogicalChannel,
OpenLogicalChannelAck); the H.245 PER encodings are built by hand
(_per.py). Everything is built with struct; nothing comes from a real
network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap
from _per import PW

# ---------------------------------------------------------------- H.223 --
def golay_encode(w):
    m = [0xc75, 0x49f, 0xd4b, 0x6e3, 0x9b3, 0xb66, 0xecc, 0x1ed, 0x3da, 0x7b4, 0xb1d, 0xe3a]
    out = 0
    for i in range(12):
        if w & (1 << i):
            out ^= m[i]
    return w | (out << 12)

FLAG = 0xE14D
FLAG_END = 0xE14D ^ 0xFFFF

def mux_pdu(mc, payload, end=False, mpl=None, flip=0, flag=None):
    """Level 2 MUX-PDU: Golay protected 24 bit header (MC, MPL), payload,
    closing flag (inverted when the MUX-SDU ends in this PDU).  flip is a
    mask of header bits to corrupt."""
    if mpl is None:
        mpl = len(payload)
    assert mpl < 256
    hdr = golay_encode(mc | (mpl << 4)) ^ flip
    if flag is None:
        flag = FLAG_END if end else FLAG
    return struct.pack('<I', hdr)[:3] + payload + struct.pack('>H', flag)

def bitswap(b):
    return bytes(int('{:08b}'.format(x)[::-1], 2) for x in b)

CRC8 = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0xE0 if c & 1 else c >> 1
    CRC8.append(c)

def crc8(data):
    c = 0
    for b in data:
        c = CRC8[c ^ b]
    return c

def al2(payload, seq=None, bad=False):
    body = (bytes([seq]) if seq is not None else b'') + payload
    return body + bytes([crc8(body) ^ (0x55 if bad else 0)])

def crc16_x25(data):
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x8408 if c & 1 else c >> 1
    return c ^ 0xFFFF

def srp(h245, seq=0, hdr=249, ls=0xFF, crc_bad=False):
    body = bytes([hdr, seq, ls]) + h245
    crc = crc16_x25(body) ^ (0x1234 if crc_bad else 0)
    return body + struct.pack('<H', crc)

# ---------------------------------------------------------------- H.245 --
def msc(kind, idx, nroot_inner):
    """MultimediaSystemControlMessage header: kind 0 request, 1 response."""
    w = PW()
    w.flag(0).cint(kind, 0, 3)          # ext, CHOICE of 4
    w.flag(0)                           # RequestMessage / ResponseMessage extensible
    w.cint(idx, 0, nroot_inner - 1)
    return w

def elem(w, e):
    # e = ('lc', n, rep) or ('sub', [elems], rep); rep 0 = untilClosingFlag
    kind, val, rep = e
    if kind == 'lc':
        w.cint(0, 0, 1).cint(val, 0, 65535)
    else:
        w.cint(1, 0, 1).cint(len(val), 2, 255)
        for s in val:
            elem(w, s)
    if rep == 0:
        w.cint(1, 0, 1)
    else:
        w.cint(0, 0, 1).cint(rep, 1, 65535)

def h245_mes(seq, descs):
    w = msc(0, 6, 11)
    w.seqext(0)
    w.cint(seq, 0, 255)
    w.cint(len(descs), 1, 15)
    for mc, elems in descs:
        w.flag(elems is not None)
        w.cint(mc, 1, 15)
        if elems is not None:
            w.cint(len(elems), 1, 256)
            for e in elems:
                elem(w, e)
    return w.bytes()

def h223_params(w, al, seg):
    """H223LogicalChannelParameters.  al: 1 al1Framed, 2 al1NotFramed,
    3 al2 without seq, 4 al2 with seq, 5 al3 (tuple ('al3', ctrl, buf)),
    0 nonStandard (tuple ('ns', t35country, t35ext, manufacturer, data))."""
    w.seqext(0)
    if isinstance(al, tuple) and al[0] == 'al3':
        w.choice(5, 6, ext=True).cint(al[1], 0, 2).cint(al[2], 0, 16777215)
    elif isinstance(al, tuple) and al[0] == 'ns':
        w.choice(0, 6, ext=True)
        w.cint(1, 0, 1).cint(al[1], 0, 255).cint(al[2], 0, 255).cint(al[3], 0, 65535)  # h221NonStandard
        w.length(len(al[4])).octets(al[4])
    else:
        w.choice(al, 6, ext=True)
    w.flag(seg)

def h245_olc(lc, al, seg, rev=None):
    """rev: None or (al, seg) for the reverse channel."""
    w = msc(0, 3, 11)
    w.seqext(0).flag(rev is not None)
    w.cint(lc, 1, 65535)
    w.seqext(0).flag(0)                  # forward parameters, no portNumber
    w.choice(1, 6, ext=True)             # dataType nullData
    w.choice(1, 3, ext=True)             # h223LogicalChannelParameters
    h223_params(w, al, seg)
    if rev is not None:
        w.seqext(0).flag(1)
        w.choice(1, 6, ext=True)
        w.choice(0, 2, ext=True)
        h223_params(w, *rev)
    return w.bytes()

def h245_olcack(lc, rev_lc=None):
    w = msc(1, 5, 19)
    w.seqext(0).flag(rev_lc is not None)
    w.cint(lc, 1, 65535)
    if rev_lc is not None:
        w.seqext(0).flag(0).flag(0)       # no portNumber, no multiplexParameters
        w.cint(rev_lc, 1, 65535)
    return w.bytes()

def vc0(h245, **kw):
    return srp(h245, **kw)

# ------------------------------------------------------------ transports --
A, B = '192.0.2.10', '192.0.2.20'

def iax_full(scall, dcall, oseq, iseq, ts, typ, csub, ies=b''):
    return struct.pack('!HHIBBBB', 0x8000 | scall, dcall, ts, oseq, iseq, typ, csub) + ies

def iax_mini(scall, ts, data):
    return struct.pack('!HH', scall, ts & 0xffff) + data

DATAFMT_H223 = struct.pack('!BBI', 0xff, 4, 2)

def sip(body, call, status=None):
    if status:
        h = ('SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\nFrom: <sip:alice@192.0.2.10>;tag=1\r\n'
             'To: <sip:bob@192.0.2.20>;tag=2\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
             % (call, call, len(body)))
    else:
        h = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\n'
             'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n'
             'Contact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
             % (call, call, len(body)))
    return h.encode() + body

def sdp(ip, port):
    return ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
            'm=audio %d RTP/AVP 100\r\na=rtpmap:100 CLEARMODE/8000\r\n' % (ip, ip, port)).encode()

def rtp(payload, seq, pt=100):
    return struct.pack('!BBHII', 0x80, pt, seq, seq * 160, 0x4321) + payload

# Multiplex tables sent in frames 3 / 4
MES_A = [
    (1, [('lc', 1, 0)]),
    (2, [('lc', 5, 4), ('lc', 3, 0)]),
    (3, [('sub', [('lc', 5, 2), ('lc', 6, 1)], 3), ('lc', 3, 0)]),
    (4, [('sub', [('lc', 3, 1), ('lc', 5, 1)], 0)]),
    (5, [('sub', [('lc', 0, 1), ('lc', 0, 0)], 0)]),        # reproducer of the sublist size fix
    (6, [('sub', [('sub', [('lc', 5, 1), ('lc', 6, 1)], 2), ('lc', 3, 1)], 0)]),
    (7, [('lc', 3, 3)]),
    (8, [('lc', 6, 0)]),
    (8, [('lc', 3, 0)]),                                    # same MC twice in one PDU
    (10, [('lc', 4, 0)]),
    (11, [('lc', 5, 0)]),
    (12, [('lc', 6, 0)]),
    (13, [('lc', 9, 0)]),
        (15, None),                                             # no element list
]
MES_A2 = [(14, [('sub', [('sub', [('lc', 3, 65535), ('lc', 3, 65535)], 65535), ('lc', 3, 1)], 0)])]  # size above 32 bits

MES_B = [(1, [('lc', 4, 0)]), (2, [('lc', 5, 2), ('lc', 6, 0)]), (3, [('lc', 7, 0)])]


def main(out, verbose=False):
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    ts = [100]
    def iax_a(*pdus, cut=None):
        ts[0] += 20
        d = b''.join(pdus)
        p.udp(A, B, 4569, 4569, iax_mini(1, ts[0], bitswap(d if cut is None else d[:cut])))
    def iax_b(*pdus):
        ts[0] += 20
        p.udp(B, A, 4569, 4569, iax_mini(2, ts[0], bitswap(b''.join(pdus))))
    def c0(h245, **kw): return mux_pdu(0, vc0(h245, **kw), end=True)

    mark('IAX2 call with the H.223/H.245 data format')
    p.udp(A, B, 4569, 4569, iax_full(1, 0, 0, 0, 0, 6, 1, DATAFMT_H223))
    p.udp(B, A, 4569, 4569, iax_full(2, 1, 0, 1, 5, 6, 7, DATAFMT_H223))
    mark('MultiplexEntrySend from both sides (VC 0, SRP, CCSRL, H.245)')
    iax_a(c0(h245_mes(1, MES_A)))
    iax_b(c0(h245_mes(1, MES_B), seq=1))
    mark('OpenLogicalChannel / Ack for every adaptation layer, both directions')
    iax_a(c0(h245_olc(1, 4, 1), seq=2), c0(h245_olc(2, 1, 1), seq=3), c0(h245_olc(3, 2, 0), seq=4))
    iax_b(c0(h245_olcack(1), seq=2), c0(h245_olcack(2), seq=3), c0(h245_olcack(3), seq=4))
    iax_a(c0(h245_olc(4, 3, 1), seq=5), c0(h245_olc(5, ('al3', 1, 1024), 0), seq=6),
          c0(h245_olc(6, ('ns', 0xb5, 0, 0x534c, b'nonstd'), 0), seq=7))
    iax_b(c0(h245_olcack(4), seq=5), c0(h245_olcack(5), seq=6), c0(h245_olcack(6), seq=7))
    iax_b(c0(h245_olc(4, 4, 1), seq=8), c0(h245_olc(5, 3, 1), seq=9))
    iax_a(c0(h245_olcack(4), seq=8), c0(h245_olcack(5), seq=9), c0(h245_olcack(99), seq=10))
    mark('data: AL2 with sequence numbers, in one PDU and as two fragments')
    iax_a(mux_pdu(1, al2(b'hello', seq=0), end=True))
    iax_a(mux_pdu(1, al2(b'frag', seq=1)[:4]), mux_pdu(1, al2(b'frag', seq=1)[4:], end=True))
    mark('data: finite and until-closing elements, AL1 not framed')
    iax_a(mux_pdu(2, b'abcd' + b'1234567', end=True))
    iax_a(mux_pdu(3, b'AABA' b'AABA' b'AABA' + b'tail', end=True))
    mark('data: sublists repeated until the closing flag, nested sublists')
    iax_a(mux_pdu(4, b'ababab'))
    iax_a(mux_pdu(6, b'wxyzwxyz' b'v' b'wxyzwxyz'))
    mark('reproducer: sublist with an until-closing element (MC 5), decoded since the fix')
    resp = bytes([251, 1, 2, 3, 4, 5]); resp += struct.pack('<H', crc16_x25(resp))
    iax_a(mux_pdu(5, resp, end=True))
    mark('data: finite count only, MC defined twice in one PDU, MC without an entry, MC without element list')
    iax_a(mux_pdu(7, b'123'))
    iax_a(mux_pdu(8, b'twice'))
    iax_a(mux_pdu(9, b'unused'))
    iax_a(mux_pdu(15, b'nolist'))
    mark('data: AL2 without sequence numbers, AL3, non-standard AL, no OLC (no sub circuit)')
    iax_a(mux_pdu(10, al2(b'noseq'), end=True))
    iax_a(mux_pdu(11, b'al3 data', end=True))
    iax_a(mux_pdu(12, b'nonstd data', end=True))
    iax_a(mux_pdu(13, b'no olc', end=True))
    mark('data from the other side')
    iax_b(mux_pdu(1, al2(b'from B', seq=7), end=True))
    iax_b(mux_pdu(2, b'12345678', end=True))
    mark('stuffing PDUs, Golay corrected and uncorrectable headers, payload beyond MPL, 255 octets, several PDUs per frame')
    iax_a(mux_pdu(0, b''), mux_pdu(0, b''))
    iax_a(mux_pdu(1, al2(b'1bit', seq=2), end=True, flip=0x000010))
    iax_a(mux_pdu(1, al2(b'3bit', seq=3), end=True, flip=0x400101))
    iax_a(mux_pdu(1, b'garbage-header', flip=0x00000F))
    iax_a(mux_pdu(8, b'0123456789', mpl=4, end=True))
    iax_a(mux_pdu(2, bytes(range(1, 256)) [:255], end=True))
    iax_a(mux_pdu(1, al2(b'p1', seq=4), end=True), mux_pdu(1, al2(b'p2', seq=5), end=True), mux_pdu(0, b''))
    mark('PDU split over two mini frames (IAX2 desegmentation)')
    pdu = mux_pdu(1, al2(b'split across frames', seq=6), end=True)
    iax_a(pdu, cut=9)
    ts[0] += 20
    p.udp(A, B, 4569, 4569, iax_mini(1, ts[0], bitswap(pdu[9:])))
    mark('second MultiplexEntrySend redefines MC 1 and defines MC 14 (size above 32 bits), logical channel 1 opened again')
    iax_a(c0(h245_mes(2, [(1, [('lc', 2, 0)])] + MES_A2), seq=11))
    iax_a(mux_pdu(1, b'now AL1 framed', end=True))
    iax_a(mux_pdu(14, b'huge sublist', end=True))
    iax_a(c0(h245_olc(1, 2, 0), seq=12))
    iax_b(c0(h245_olcack(1), seq=12), c0(h245_olcack(1), seq=13))
    iax_a(c0(h245_mes(3, [(1, [('lc', 1, 0)])]), seq=13), mux_pdu(1, b'MES and data in one frame', end=True))
    iax_a(mux_pdu(1, b'and later', end=True))
    mark('RTP CLEARMODE (SDP) conversation: both directions')
    sp = Pcap  # keep name used below short
    p.udp(A, B, 5060, 5060, sip(sdp(A, 5004), 'c13h223'))
    p.udp(B, A, 5060, 5060, sip(sdp(B, 5006), 'c13h223', status=200))
    rs = [1000, 2000]
    def rtp_a(*pdus, cut=None):
        rs[0] += 1
        d = b''.join(pdus)
        p.udp(A, B, 5004, 5006, rtp(bitswap(d if cut is None else d[:cut]), rs[0]))
    def rtp_b(*pdus):
        rs[1] += 1
        p.udp(B, A, 5006, 5004, rtp(bitswap(b''.join(pdus)), rs[1]))
    rtp_a(c0(h245_mes(1, [(1, [('lc', 1, 0)]), (2, [('sub', [('lc', 2, 1), ('lc', 3, 1)], 0)])])),
          c0(h245_olc(1, 4, 1), seq=1), c0(h245_olc(2, 1, 1), seq=2), c0(h245_olc(3, 2, 0), seq=8))
    rtp_b(c0(h245_olcack(1), seq=1), c0(h245_olcack(2), seq=2), c0(h245_olcack(3), seq=8), c0(h245_mes(1, [(1, [('lc', 1, 0)])]), seq=3))
    rtp_a(mux_pdu(1, al2(b'rtp data', seq=0), end=True))
    rtp_a(mux_pdu(2, b'abcdef', end=True))
    rtp_b(c0(h245_olc(1, 3, 0), seq=4))
    rtp_a(c0(h245_olcack(1), seq=3))
    rtp_b(mux_pdu(1, al2(b'back'), end=True))
    pdu = mux_pdu(1, al2(b'cut', seq=1), end=True)
    rtp_a(pdu, cut=4)
    mark('TCP port 5555, only with Decode As h223 (tcp.port==5555,h223): PDUs split over segments')
    def tcp_a(d): p.tcp(A, B, 41111, 5555, d)
    def tcp_b(d): p.tcp(B, A, 5555, 41111, d)
    m1 = c0(h245_mes(1, [(1, [('lc', 1, 0)])]))
    tcp_a(m1[:7]); tcp_a(m1[7:])
    o1 = c0(h245_olc(1, 4, 1), seq=1); a1 = c0(h245_olcack(1), seq=1)
    tcp_a(o1 + mux_pdu(0, b'')[:2])
    tcp_a(mux_pdu(0, b'')[2:])
    tcp_b(a1)
    tcp_a(mux_pdu(1, al2(b'tcp data', seq=0), end=True)[:3])
    tcp_a(mux_pdu(1, al2(b'tcp data', seq=0), end=True)[3:] + mux_pdu(1, al2(b'tcp 2', seq=1), end=True))
    tcp_b(mux_pdu(0, b'') * 3)
    p.write(os.path.join(out, 'h223-coverage.pcap'))

    # ---- malformed capture ------------------------------------------------
    m = Pcap()
    mt = [100]
    def ma(*pdus):
        mt[0] += 20; m.udp(A, B, 4569, 4569, iax_mini(1, mt[0], bitswap(b''.join(pdus))))
    def mb(*pdus):
        mt[0] += 20; m.udp(B, A, 4569, 4569, iax_mini(2, mt[0], bitswap(b''.join(pdus))))
    m.udp(A, B, 4569, 4569, iax_full(1, 0, 0, 0, 0, 6, 1, DATAFMT_H223))
    m.udp(B, A, 4569, 4569, iax_full(2, 1, 0, 1, 5, 6, 7, DATAFMT_H223))
    ma(c0(h245_mes(1, [(1, [('lc', 1, 0)]), (2, [('lc', 3, 0), ('lc', 5, 0)]),
                       (3, [('sub', [('lc', 3, 0), ('lc', 5, 0)], 0)]), (4, [('lc', 7, 0)]),
                       (7, [('lc', 3, 3)])])))
    # a bidirectional channel: the reverse parameters have no subdissector
    ma(c0(h245_olc(1, 4, 1), seq=2), c0(h245_olc(5, 1, 1, rev=(1, 1)), seq=3))
    mb(c0(h245_olcack(1), seq=2), c0(h245_olcack(5, rev_lc=7), seq=3))
    ma(mux_pdu(4, b'reverse channel data', end=True))
    # a finite repeat count that is longer than the payload: exception
    ma(mux_pdu(7, b'ab', end=True))
    # AL2 problems: bad CRC, too short for a sequence number
    ma(mux_pdu(1, al2(b'bad crc', seq=0, bad=True), end=True))
    ma(mux_pdu(1, b'\x00', end=True))
    # empty sublist (only until-closing elements): expert info
    ma(mux_pdu(3, b'data'))
    # OLC without reverse channel after one with: stale reverse parameters in
    # the H.245 dissector make the Ack hit a DISSECTOR_ASSERT (see README)
    ma(c0(h245_olc(1, 2, 0), seq=4))
    mb(c0(h245_olcack(1), seq=4))
    # PDUs that end in the middle of the header or without a closing flag
    ma(mux_pdu(1, b'abc')[:3])
    ma(mux_pdu(1, b'abc')[:4])
    ma(b'\x00\x01')
    m.write(os.path.join(out, 'h223-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

#!/usr/bin/env python3
# Generates test/captures/li_ps_pdu_samples_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LI-PS-PDU (packet-li-ps-pdu.c, ETSI TS 102 232-1) coverage captures.

The LI-PS-PDU dissector has no port of its own: the LI5G dissector (ETSI TS 103
221-2, packet-li5g.c) hands payload format 1 (a PS-PDU) and payload format 17
(a PS-PDU Payload) to it, and LI5G is reached by name from an Exported PDU
(link type 252, tag "li5g"). Every frame is an LI5G PDU with such a payload.

The payloads are written by asnber.py (a BER encoder that reads the ASN.1
modules of asn1/li-ps-pdu, asn1/lix2 and asn1/HI2Operations from the Wireshark
tree). Round one builds PS-PDUs until every type, component and CHOICE
alternative of the PS-PDU has been used at least once; round two writes one
small PS-PDU for every alternative of the Payload and of its CC and IRI
contents. The modules Wireshark does not have (e-mail, L2 access, ...) get
opaque octets. Nothing comes from a real network.

Usage: mkli_ps_pdu.py <outdir>      (LIPS_LIST=1 prints the frame list)
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import asnber as A

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
W = os.path.join(SRCDIR, 'epan/dissectors/asn1', '')
FILES = [W + 'lix2/lix2.asn', W + 'HI2Operations/HI2Operations_ver18.asn',
         W + 'HI2Operations/UmtsHI2Operations.asn', W + 'HI2Operations/EpsHI2Operations.asn',
         W + 'li-ps-pdu/Common-Parameters.asn', W + 'li-ps-pdu/IPAccessPDU.asn',
         W + 'li-ps-pdu/LI-PS-PDU.asn']

# ---------------------------------------------------------------- framing


def tlv2(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload):
    return tlv2(12, b'li5g') + struct.pack('>HH', 0, 0) + payload


XID = bytes.fromhex('0123456789abcdef0123456789abcdef')


def li5g(payload, pformat, seq, pdir=2):
    attrs = struct.pack('>HHH', 8, 2, seq & 0xffff)
    return (struct.pack('>HHIIHH', 1, 1, 40 + len(attrs), len(payload), pformat, pdir) + XID +
            struct.pack('>Q', 0x1122334455667788) + attrs + payload)


def write_pcap(fn, pkts, linktype=252):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip_udp(payload, dport=514, sport=40514, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + udp


# ---------------------------------------------------------------- types decoded further (as in lix2)

def ov_numeric(digits):
    def ov(enc, d, m, ctx):
        s = digits[ctx.k % len(digits)]
        return (0, 18, False, s.encode())
    return ov


IMSIS = ['001010123456789', '310410987654321', '262011234567890', '20404123456789', '23415123456']
MSISDNS = ['12025550123', '491701234567', '447700900123', '61412345678', '4670123456']


def pco(k, uplink):
    if uplink:
        items = [
            (0xc023, bytes([1, 1, 0, 14, 4]) + b'user' + bytes([4]) + b'pass'),
            (0x0001, b''), (0x000d, b''), (0x0010, b''),
            (0x8021, bytes([1, 1, 0, 16, 0x81, 6, 0, 0, 0, 0, 0x83, 6, 0, 0, 0, 0])),
            (0x000a, b''), (0x0005, b''), (0x000c, b''), (0x0002, b''),
            (0xc021, bytes([1, 1, 0, 4])), (0x0020, b''),
        ]
    else:
        items = [
            (0xc023, bytes([2, 1, 0, 5, 0])),
            (0x0001, bytes.fromhex('20010db8000000000000000000000035')),
            (0x000d, bytes([192, 0, 2, 53])), (0x0010, struct.pack('>H', 1400)),
            (0x8021, bytes([2, 1, 0, 16, 0x81, 6, 192, 0, 2, 53, 0x83, 6, 192, 0, 2, 54])),
            (0x000a, b''), (0x0005, b'\x01'), (0x000c, b''), (0x0002, b''),
            (0xc021, bytes([2, 1, 0, 4])), (0x0020, b''),
        ]
    n = 1 + (k % len(items))
    return bytes([0x80]) + b''.join(struct.pack('>H', i) + bytes([len(c)]) + c for i, c in items[:n])


def ov_pco(enc, d, m, ctx):
    return (0, 4, False, pco(ctx.k, (ctx.field or '').startswith('request')))


def ov_flags(enc, d, m, ctx):
    n = 2 + ctx.k % 6
    return (0, 4, False, bytes((0x5a ^ (i * 0x35) ^ (ctx.k * 3)) & 0xff for i in range(n)))


# contents of GTPv2 style octet strings that HI2Operations decodes
IP_A = bytes([192, 0, 2, 1])
APN_LABEL = b'\x08internet\x03foo\x03com'
GTP = {'pDNAddressAllocation': b'\x01' + IP_A,
       'ePSBearerQoS': bytes([0x49, 0x09]) + b'\x00' * 20,
       'aPN': APN_LABEL,
       'aPN-AMBR': struct.pack('>II', 100000, 200000),
       'userLocationInfo': bytes([0x18]) + bytes([0x13, 0x00, 0x62, 0x00, 0x01]) + bytes([0x13, 0x00, 0x62, 0x00, 0x00, 0x01, 0x02]),
       'tFT': bytes([0x21, 0x31, 0x20, 0x00, 0x10, 0x0a, 0x30, 0xc0, 0xa8, 0x00, 0x01, 0xff, 0xff, 0xff, 0x00]),
       'operator-Identifier': b'\x13\x00\x62',
       'imsi': b'\x13\x00\x62\x11\x22\x33\x44',
       'imei': bytes.fromhex('5301234567890123'),
       'proSeRelayIMSI': b'\x13\x00\x62\x11\x22\x33\x44'}

OVERRIDES = {'IMSI': ov_numeric(IMSIS), 'MSISDN': ov_numeric(MSISDNS),
             'PDNPCO': ov_pco, 'PDNConnectionIndicationFlags': ov_flags}
SKIP = {'mSISDNs'}

# ---------------------------------------------------------------- encoder


def build_encoder():
    enc = A.Encoder(FILES, 'LI-PS-PDU', OVERRIDES)
    cnt = [0]

    def lix2_payload(name):
        def fo(e, t, mod, ctx):
            cnt[0] += 1
            c = A.Ctx(ctx.k + cnt[0])
            c.sparse = True
            c.skip = SKIP
            tt, mm = e.find('TS33128Payloads.' + name, mod)
            return e.enc(tt, mm, c, name)
        return fo

    def ippackets(e, t, mod, ctx):
        msg = b'<34>Nov 14 22:13:20 poi li-ps-pdu: packet %d' % ctx.k
        return ip_udp(msg)

    def domain(e, t, mod, ctx):
        return A.oid_body('0.4.0.2.2.5.1.43')

    enc.fo = {k: (lambda e, t, mod, ctx, v=v: v) for k, v in GTP.items()}
    enc.fo |= {'threeGPP33128DefinedIRI': lix2_payload('IRIPayload'),
              'threeGPP33128DefinedCC': lix2_payload('CCPayload'),
              'iPPackets': ippackets, 'li-psDomainId': domain}
    enc.skip = SKIP
    return enc


def recursion(depth):
    """LI5G (UDP 5000) -> PS-PDU Payload -> iPPackets -> IP -> UDP 5000 -> LI5G ..., depth levels."""
    def blen(n):
        return A.blen(n)

    pkt = ip_udp(b'hello', 9)
    for _ in range(depth):
        ipcc = A.tlv(2, False, 0, b'\x01') + A.tlv(2, True, 1, A.tlv(2, False, 0, pkt))
        ccp = A.tlv(2, True, 2, A.tlv(2, True, 2, ipcc))
        pdu = A.tlv(2, True, 1, A.tlv(0, True, 16, ccp))
        hdr = struct.pack('>HHIIHH', 0x0200, 2, 40, len(pdu), 17, 0) + b'\0' * 16 + b'\0' * 8
        pkt = ip_udp(hdr + pdu, 5000, 4000)
    return pkt


def write_malformed(enc, frames, n1):
    """Payloads cut in half or damaged, a payload of the wrong kind, and the nested IP recursion."""
    payloads = [f[len(exp_pdu(b'')) + 40 + 6:] for f in frames[:n1]]
    mal = []
    seq = [0]

    def m(p, pf, note):
        seq[0] += 1
        mal.append(exp_pdu(li5g(p, pf, seq[0])))
        mnotes.append(note)

    mnotes = []
    step = max(1, n1 // 12)
    for i in range(0, n1, step):
        p = payloads[i]
        m(p[:max(2, len(p) // 2)], 1, 'PS-PDU %d cut in half' % (i + 1))
    for i in range(1, n1, max(1, n1 // 10)):
        p = bytearray(payloads[i])
        p[len(p) // 2] ^= 0xa5
        m(bytes(p), 1, 'PS-PDU %d with a flipped octet' % (i + 1))
    for i in range(2, n1, max(1, n1 // 10)):
        p = bytearray(payloads[i])
        p[-4] ^= 0xff
        p[len(p) * 3 // 4] ^= 0x5a
        m(bytes(p), 1, 'PS-PDU %d with two damaged octets' % (i + 1))
    m(b'', 1, 'empty payload')
    m(b'\x30', 1, 'a SEQUENCE tag only')
    m(b'\x30\x80\x00\x00', 1, 'indefinite length SEQUENCE')
    m(b'\x30\x84\xff\xff\xff\xff', 1, 'length past the end')
    m(b'\x31\x03\x02\x01\x05', 1, 'PS-PDU as a SET: not a SEQUENCE, returns 0')
    m(b'\x02\x01\x05', 17, 'Payload of class universal: returns 0')
    m(b'\xa1\x03\x02\x01\x05', 17, 'Payload with something else than a sequence of CCPayload')
    m(A.tlv(2, True, 1, A.tlv(0, True, 16, A.tlv(2, True, 2, b'\xa1\x84\xff\xff\xff\xff'))), 17,
      'CC contents with a length past the end')
    # the IP packet of an IPCC that is cut short
    ipcc = A.tlv(2, False, 0, b'\x01') + A.tlv(2, True, 1, A.tlv(2, False, 0, ip_udp(b'x' * 20)[:25]))
    m(A.tlv(2, True, 1, A.tlv(0, True, 16, A.tlv(2, True, 2, A.tlv(2, True, 2, ipcc)))), 17, 'IPCC with a truncated IP packet')
    # an IPCC whose IP packet is LI5G over UDP 5000, nested: needs -o li5g.udp.port:5000
    m(A.tlv(2, True, 1, A.tlv(0, True, 16, A.tlv(2, True, 2, A.tlv(2, True, 2,
      A.tlv(2, False, 0, b'\x01') + A.tlv(2, True, 1, A.tlv(2, False, 0, recursion(3))))))), 17,
      'IPCC with nested LI5G over UDP 5000, 3 levels')
    m(A.tlv(2, True, 1, A.tlv(0, True, 16, A.tlv(2, True, 2, A.tlv(2, True, 2,
      A.tlv(2, False, 0, b'\x01') + A.tlv(2, True, 1, A.tlv(2, False, 0, recursion(130))))))), 17,
      'IPCC with nested LI5G over UDP 5000, 130 levels (past the layer depth limit of 500)')
    write_pcap(os.path.join(OUT, 'li-ps-pdu-coverage-malformed.pcap'), mal)
    if os.environ.get('LIPS_LIST'):
        for i, n in enumerate(mnotes, 1):
            print('M%3d %s' % (i, n))


def main():
    enc = build_encoder()
    top, tm = enc.find('PS-PDU', enc.mod)
    frames, notes = [], []
    seq = [0]

    def add(payload, pf, note):
        seq[0] += 1
        frames.append(exp_pdu(li5g(payload, pf, seq[0], 2 + seq[0] % 3)))
        notes.append(note)

    # round one: whole PS-PDUs until every node has been used
    stalled = 0
    for k in range(400):
        before = len(enc.covered)
        c = A.Ctx(k)
        c.sparse = True
        c.skip = SKIP
        b = enc.encode('PS-PDU', c)
        add(b, 1, 'round one %d' % (k + 1))
        stalled = stalled + 1 if len(enc.covered) == before else 0
        if not enc.cu(top, tm) or stalled > 30:
            break
    n1 = len(frames)
    # round two: the Payload alternatives, one PS-PDU Payload per alternative
    pl, pm = enc.find('Payload', enc.mod)
    for i, (name, at) in enumerate(pl['alts']):
        if not enc.feasible(at, pm):
            continue
        c = A.Ctx(i)
        c.minimal = True
        c.skip = SKIP
        add(enc.enc(at, pm, c, name), 17, 'payload %s, mandatory components only' % name)
    # round three: each alternative of the CC and IRI contents
    for tname in ('CCContents', 'IRIContents'):
        ct, cm = enc.find(tname, enc.mod)
        for i, (name, at) in enumerate(ct['alts']):
            if not enc.feasible(at, cm):
                continue
            c = A.Ctx(100 + i)
            c.skip = SKIP
            inner = enc.enc(at, cm, c, name)
            wrap = A.tlv(2, True, 0 if tname == 'CCContents' else 2, inner)
            # cCPayloadSequence / iRIPayloadSequence with one element
            elem = A.tlv(2, True, 2 if tname == 'CCContents' else 2, inner)
            if tname == 'CCContents':
                body = A.tlv(0, True, 16, elem)       # CCPayload SEQUENCE { cCContents [2] }
                add(A.tlv(2, True, 1, body), 17, 'CC contents %s' % name)
            else:
                body = A.tlv(0, True, 16, A.tlv(2, True, 2, inner))
                add(A.tlv(2, True, 0, body), 17, 'IRI contents %s' % name)
    # an e-mail CC (a module Wireshark does not have) with an indefinite length: shown as
    # bytes without the end-of-contents octets
    email = A.tlv(2, True, 1, b'')[:1] + b'\x80' + b'\x04\x04mail' + b'\x00\x00'
    cc = A.tlv(0, True, 16, A.tlv(2, True, 2, email))
    add(A.tlv(2, True, 1, cc), 17, 'e-mail CC with an indefinite length')
    write_pcap(os.path.join(OUT, 'li-ps-pdu-coverage.pcap'), frames)
    write_malformed(enc, frames, n1)
    if os.environ.get('LIPS_LIST'):
        for i, n in enumerate(notes, 1):
            print('%4d %6d %s' % (i, len(frames[i - 1]), n))
    print('%d main frames (%d in round one); unknown types: %s' % (len(frames), n1, sorted(enc.unknown)), file=sys.stderr)


if __name__ == '__main__':
    main()

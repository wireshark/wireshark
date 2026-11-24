#!/usr/bin/env python3
# Generates test/captures/lix2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic X2 xIRI payload (packet-lix2.c, "xiri") coverage captures.

The lix2 dissector decodes the XIRIPayload of 3GPP TS 33.128 (BER). It has no
port of its own: the LI5G dissector (ETSI TS 103 221-2, packet-li5g.c) hands
payload format 2 (xIRI) to it, and LI5G is reached by name from an Exported
PDU (link type 252, tag "li5g"). Every frame of the captures is an X2 xIRI PDU
of LI5G whose payload is an XIRIPayload.

The payloads are written by asnber.py (a BER encoder that reads
asn1/lix2/lix2.asn and IPAccessPDU.asn from the Wireshark tree). Round one
builds PDUs until every type, component and CHOICE alternative of the module
that XIRIPayload reaches has been used at least once (each PDU holds the
optional components that lead to something not used yet, nested CHOICEs pick
unused alternatives first); round two writes one small PDU with only the
mandatory components for every alternative of XIRIEvent. The types the
dissector decodes further (IMSI, MSISDN, the PCO, the connection indication
flags) get meaningful values. Nothing comes from a real network.

Usage: mklix2.py <outdir> [<asn1 dir of lix2>]
  LIX2_LIST=1 prints the frame list.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import asnber as A

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1/lix2')

# ---------------------------------------------------------------- LI5G framing


def tlv2(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(payload, name='li5g'):
    return tlv2(12, name.encode()) + struct.pack('>HH', 0, 0) + payload


def write_pcap(fn, pkts, linktype=252):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


XID = bytes.fromhex('0123456789abcdef0123456789abcdef')


def li5g_xiri(payload, seq=1, pdir=2, cid=0x1122334455667788, payload_len=None):
    """An X2 xIRI PDU (type 1, payload format 2) with a sequence number attribute."""
    attrs = struct.pack('>HHH', 8, 2, seq & 0xffff)
    pl = len(payload) if payload_len is None else payload_len
    return (struct.pack('>HHIIHH', 1, 1, 40 + len(attrs), pl, 2, pdir) + XID +
            struct.pack('>Q', cid) + attrs + payload)


# ---------------------------------------------------------------- types decoded further

def ov_numeric(digits):
    def ov(enc, d, m, ctx):
        s = digits[ctx.k % len(digits)]
        return (0, 18, False, s.encode())
    return ov


IMSIS = ['001010123456789', '310410987654321', '262011234567890', '20404123456789', '23415123456']
MSISDNS = ['12025550123', '491701234567', '447700900123', '61412345678', '4670123456']


def pco(k, uplink):
    """A protocol configuration options IE: configuration protocol octet and
    protocol / container items of the kind of each direction."""
    if uplink:
        items = [
            (0xc023, bytes([1, 1, 0, 14, 4]) + b'user' + bytes([4]) + b'pass'),    # PAP request
            (0x0001, b''),                                   # P-CSCF IPv6 address request
            (0x000d, b''),                                   # DNS server IPv4 address request
            (0x0010, b''),                                   # IPv4 link MTU request
            (0x8021, bytes([1, 1, 0, 16, 0x81, 6, 0, 0, 0, 0, 0x83, 6, 0, 0, 0, 0])),   # IPCP
            (0x000a, b''),                                   # IP address allocation via NAS
            (0x0005, b''),                                   # MS support of network requested bearer control
            (0x000c, b''),                                   # P-CSCF re-selection support
            (0x0002, b''),                                   # IM CN subsystem signalling flag
            (0xc021, bytes([1, 1, 0, 4])),                   # LCP
            (0x0020, b''),                                   # not defined
        ]
    else:
        items = [
            (0xc023, bytes([2, 1, 0, 5, 0])),                # PAP acknowledge
            (0x0001, bytes.fromhex('20010db8000000000000000000000035')),   # P-CSCF IPv6 address
            (0x000d, bytes([192, 0, 2, 53])),                # DNS server IPv4 address
            (0x0010, struct.pack('>H', 1400)),               # IPv4 link MTU
            (0x8021, bytes([2, 1, 0, 16, 0x81, 6, 192, 0, 2, 53, 0x83, 6, 192, 0, 2, 54])),   # IPCP
            (0x000a, b''),
            (0x0005, b'\x01'),
            (0x000c, b''),
            (0x0002, b''),
            (0xc021, bytes([2, 1, 0, 4])),
            (0x0020, b''),
        ]
    n = 1 + (k % len(items))
    body = b''.join(struct.pack('>H', i) + bytes([len(c)]) + c for i, c in items[:n])
    return bytes([0x80]) + body


def ov_pco(enc, d, m, ctx):
    return (0, 4, False, pco(ctx.k, (ctx.field or '').startswith('request')))


def ov_flags(enc, d, m, ctx):
    n = 2 + ctx.k % 6
    return (0, 4, False, bytes((0x5a ^ (i * 0x35) ^ (ctx.k * 3)) & 0xff for i in range(n)))


OVERRIDES = {'IMSI': ov_numeric(IMSIS), 'MSISDN': ov_numeric(MSISDNS),
             'PDNPCO': ov_pco, 'PDNConnectionIndicationFlags': ov_flags}


# ---------------------------------------------------------------- payloads

# mSISDNs is SEQUENCE OF MSISDN: the FN_BODY of MSISDN reads the whole tvb from
# the offset of the element, including its tag and length (a decoding error
# for every valid encoding); such a list goes to the malformed capture.
SKIP = {'mSISDNs'}

def payload_of(event_bytes):
    roid = A.tlv(2, False, 1, bytes([4, 19, 19, 3, 1]))
    return A.tlv(0, True, 16, roid + A.tlv(2, True, 2, event_bytes))


# IPAccessPDU.asn beside this script is the lix2 version from before it moved
# to asn1/li-ps-pdu and gained the LI-PS-PDU imports; the capture uses it.
def build():
    enc = A.Encoder([os.path.join(os.path.dirname(os.path.abspath(__file__)), 'IPAccessPDU.asn'), os.path.join(ASN, 'lix2.asn')],
                    'TS33128Payloads', OVERRIDES)
    enc.skip = SKIP
    top, tm = enc.find('XIRIPayload', enc.mod)
    clean, notes = [], []
    # round one: until everything XIRIPayload reaches has been used
    stalled = 0
    for k in range(1000):
        before = len(enc.covered)
        c = A.Ctx(k)
        c.sparse = True
        c.skip = SKIP
        b = enc.encode('XIRIPayload', c)
        clean.append(b)
        notes.append('round one %d' % (k + 1))
        stalled = stalled + 1 if len(enc.covered) == before else 0
        if not enc.cu(top, tm) or stalled > 30:
            break
    n1 = len(clean)
    # the mSISDNs list (left out above) for the malformed capture
    enc.skip = set()
    enc._cu_n = -1
    c = A.Ctx(0)
    c.sparse = True
    msisdn_list = enc.encode('XIRIPayload', c)
    enc.skip = SKIP
    # round two: every XIRIEvent alternative with the mandatory components only
    ev, em = enc.find('XIRIEvent', enc.mod)
    for i, (name, at) in enumerate(ev['alts']):
        c = A.Ctx(i)
        c.minimal = True
        c.skip = SKIP
        if not enc.feasible(at, em):
            continue
        clean.append(payload_of(enc.enc(at, em, c, name)))
        notes.append('event %s, mandatory components only' % name)
    return enc, clean, notes, n1, msisdn_list


def main():
    enc, payloads, notes, n1, msisdn_list = build()
    frames = [exp_pdu(li5g_xiri(p, seq=i + 1, pdir=2 + (i % 3))) for i, p in enumerate(payloads)]
    write_pcap(os.path.join(OUT, 'lix2-coverage.pcap'), frames)

    # malformed: truncated, bad lengths and garbage in some payloads
    mal, mnotes = [], []

    def m(p, note, **kw):
        mal.append(exp_pdu(li5g_xiri(p, seq=len(mal) + 1, **kw)))
        mnotes.append(note)

    for i in range(0, n1, max(1, n1 // 12)):
        p = payloads[i]
        m(p[:max(2, len(p) // 2)], 'payload %d cut in half' % (i + 1))
    for i in range(1, n1, max(1, n1 // 10)):
        p = bytearray(payloads[i])
        p[len(p) // 2] ^= 0xa5
        m(bytes(p), 'payload %d with a flipped octet' % (i + 1))
    for i in range(2, n1, max(1, n1 // 10)):
        p = bytearray(payloads[i])
        p[-4] ^= 0xff
        p[len(p) * 3 // 4] ^= 0x5a
        m(bytes(p), 'payload %d with two damaged octets' % (i + 1))
    m(msisdn_list, 'SEQUENCE OF MSISDN: tag and length of the element read as digits')
    m(b'', 'empty payload')
    m(b'\x30', 'a SEQUENCE tag only')
    m(b'\x30\x80\x00\x00', 'indefinite length SEQUENCE')
    m(b'\x30\x84\xff\xff\xff\xff', 'length past the end')
    m(A.tlv(0, True, 16, A.tlv(2, False, 1, b'\x04\x13') + A.tlv(2, True, 2, A.tlv(2, True, 99, b''))),
      'unknown event alternative')
    m(A.tlv(0, True, 16, A.tlv(2, True, 2, b'')), 'no payload OID, empty event')
    write_pcap(os.path.join(OUT, 'lix2-coverage-malformed.pcap'), mal)
    if os.environ.get('LIX2_LIST'):
        for i, n in enumerate(notes, 1):
            print('%4d %6d %s' % (i, len(payloads[i - 1]), n))
        for i, n in enumerate(mnotes, 1):
            print('M%3d %s' % (i, n))
    covered = sum(1 for _ in enc.covered)
    print('%d main frames (%d in round one), %d malformed; %d type nodes used' %
          (len(frames), n1, len(mal), covered), file=sys.stderr)


if __name__ == '__main__':
    main()

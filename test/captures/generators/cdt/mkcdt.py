#!/usr/bin/env python3
# Generates test/captures/cdt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Compressed Data Type
dissector (packet-cdt.c, generated from asn1/cdt; STANAG 4406 Annex E).

CDT is reached two ways:
  - by P_Mul (ACP 142) with the preference p_mul.decode:cdt: the
    reassembled Data PDUs of a message go to dissect_cdt();
  - by its object identifier 1.3.26.0.4406.0.4.2 through
    call_ber_oid_callback(): here from a CAMEL InitialDP ExtensionField
    whose type is the CDT OID, and from an X.411 (P1) message whose
    content-type is the CDT OID (a CDT that holds P1 holds CDT again).

All frames are Exported PDUs (DLT 252) naming "camel" or "p_mul". Every
packet is built from scratch with struct and zlib; no captured traffic
is used.

Usage: mkcdt.py <output directory>

Writes:
  cdt-coverage.pcap            P_Mul messages carrying CDT, CAMEL
                               extensions with CDT of every content type,
                               both algorithm and content type forms, CDT
                               in P1 in CDT, the branch reproducer frames
  cdt-coverage-malformed.pcap  content that cannot be decompressed or is
                               not an OCTET STRING, truncated CDT, the
                               nesting reproducer
"""

import os
import struct
import sys
import zlib


def L(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(t, v):
    return bytes([t]) + L(len(v)) + v


def oidv(s):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(reversed(enc))
    return out


def oid(s):
    return tlv(0x06, oidv(s))


CDT_OID = '1.3.26.0.4406.0.4.2'
# id-data: a P1 content type whose content (an Internet message) goes to IMF
ID_DATA = '1.2.840.113549.1.7.1'


# ---------------------------------------------------------------- CDT
def cdt(content, ctype=0, alg=0, ctype_oid=None, alg_oid=None, raw_content=None, raw_ctype=None):
    """CompressedData ::= SEQUENCE { compressionAlgorithm CHOICE
    { [0] INTEGER, [1] OID }, compressedContentInfo SEQUENCE {
    contentType CHOICE { [0] INTEGER, [1] OID }, [0] EXPLICIT OCTET STRING }}"""
    a = tlv(0x81, oidv(alg_oid)) if alg_oid else tlv(0x80, bytes([alg]))
    c = tlv(0x81, oidv(ctype_oid)) if ctype_oid else tlv(0x80, bytes([ctype]))
    if raw_ctype is not None:
        c = raw_ctype
    body = raw_content if raw_content is not None else tlv(0x04, zlib.compress(content, 9))
    return tlv(0x30, a + tlv(0x30, c + tlv(0xa0, body)))


# ---------------------------------------------------------------- P1
def printable(s):
    return tlv(0x13, s.encode())


def gdi():
    """GlobalDomainIdentifier [APPLICATION 3]: country, ADMD."""
    return tlv(0x63, tlv(0x61, printable('NO')) + tlv(0x62, printable('ADMD')))


def orname(org):
    """ORName [APPLICATION 0] with built-in standard attributes."""
    return tlv(0x60, tlv(0x30, tlv(0x61, printable('NO')) + tlv(0x62, printable('ADMD'))
                         + tlv(0x83, org.encode())))


def p1_message(content, ctype_oid=CDT_OID, local_id='msg-1'):
    """MTS-APDU message [0] { envelope SET, content OCTET STRING }."""
    msg_id = tlv(0x64, gdi() + tlv(0x16, local_id.encode()))
    trace = tlv(0x69, tlv(0x30, gdi() + tlv(0x31, tlv(0x80, b'260115120000Z') + tlv(0x82, b'\x00'))))
    recipient = tlv(0x31, orname('Recipient') + tlv(0x80, b'\x01') + tlv(0x81, b'\x00\xc0'))
    ct = oid(ctype_oid)
    env = tlv(0x31, msg_id + orname('Originator') + ct + trace + tlv(0xa2, recipient))
    return tlv(0xa0, env + tlv(0x04, content))


# ---------------------------------------------------------------- carriers
def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
            + struct.pack('>HH', 0, 0) + payload)


def camel(ext_value, invoke_id=1):
    """CAMEL Invoke initialDP whose ExtensionField has the CDT OID as
    type: InitialDPArg { serviceKey [0] 1, extensions [15] { ExtensionField
    { type OID, value [1] } } }."""
    ext = tlv(0x30, oid(CDT_OID) + tlv(0xa1, ext_value))
    arg = tlv(0x30, b'\x80\x01\x01' + tlv(0xaf, ext))
    return exp_pdu('camel', tlv(0xa1, tlv(0x02, bytes([invoke_id])) + b'\x02\x01\x00' + arg))


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


SRC = bytes([192, 0, 2, 1])
DST = bytes([198, 51, 100, 7])


def p_mul_pdu(head, tail):
    """head: length, priority, type, number/seq; checksum is filled in."""
    pdu = head + b'\0\0' + tail
    pdu = struct.pack('>H', len(pdu)) + pdu[2:]
    return pdu[:6] + struct.pack('>H', csum16(pdu)) + pdu[8:]


def p_mul_address(msg_id, no_pdus, expiry=0x7fffffff):
    head = struct.pack('>HBBH', 0, 1, 0x02, no_pdus)
    tail = SRC + struct.pack('>II', msg_id, expiry) + struct.pack('>HH', 1, 0) + DST + struct.pack('>I', 1)
    return exp_pdu('p_mul', p_mul_pdu(head, tail))


def p_mul_data(msg_id, seq, data):
    head = struct.pack('>HBBH', 0, 1, 0x00, seq)
    return exp_pdu('p_mul', p_mul_pdu(head, SRC + struct.pack('>I', msg_id) + data))


def p_mul_ack(msg_id):
    """Ack PDU from the destination: one Ack Info Entry, nothing missing."""
    head = struct.pack('>HBBH', 0, 0, 0x01, 0)
    return exp_pdu('p_mul', p_mul_pdu(head, DST + struct.pack('>H', 1)
                                      + struct.pack('>H', 10) + SRC + struct.pack('>I', msg_id)))


def p_mul_message(msg_id, data, frag):
    """Address PDU, Data PDUs of frag octets, Ack PDU."""
    parts = [data[i:i + frag] for i in range(0, len(data), frag)]
    return ([p_mul_address(msg_id, len(parts))]
            + [p_mul_data(msg_id, i + 1, p) for i, p in enumerate(parts)]
            + [p_mul_ack(msg_id)])


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1767225600 + i, 0, len(fr), len(fr)) + fr)


def imf(subject):
    return b'From: a@example.org\r\nSubject: ' + subject + b'\r\n\r\nbody\r\n'


def nested_p1(depth, leaf=b'end of the nesting'):
    """CDT(p1) -> P1(content-type CDT) -> CDT(p1) ... -> P1 (id-data)."""
    x = p1_message(imf(leaf), ctype_oid=ID_DATA, local_id='leaf')
    for i in range(depth):
        x = p1_message(cdt(x, ctype=2), local_id='level-%d' % (depth - i))
    return cdt(x, ctype=2)


EXTERNAL_BER = tlv(0x30, tlv(0x02, b'\x05') + tlv(0x04, b'external content') + tlv(0x01, b'\xff'))


def main_frames():
    f = []
    # 1-3 reproducer cdt_stale_tree: a P_Mul message of one Data PDU with
    #     a CDT (dissected as CDT with -o p_mul.decode:cdt), then a CDT
    #     reached by OID from a CAMEL extension; 4 the P_Mul Ack
    msg = p_mul_message(1, cdt(b'hello from p_mul ' * 4), 1000)
    f += msg[:2]
    f.append(camel(cdt(b'A' * 200)))
    f.append(msg[2])
    # 5-10 a P_Mul message of four Data PDUs: CDT with P1 content
    #      (reassembled), Ack
    f += p_mul_message(2, cdt(p1_message(imf(b'P1 content in P_Mul'), ctype_oid=ID_DATA), ctype=2), 60)
    # 11-16 CAMEL: content types unidentified (text), external (BER),
    #      p1 (a P1 message of id-data content), p3, p7, unknown 9
    f.append(camel(cdt(b'unidentified content', ctype=0)))
    f.append(camel(cdt(EXTERNAL_BER, ctype=1)))
    f.append(camel(cdt(p1_message(imf(b'plain P1 content'), ctype_oid=ID_DATA), ctype=2)))
    f.append(camel(cdt(b'p3 content', ctype=3)))
    f.append(camel(cdt(b'p7 content', ctype=4)))
    f.append(camel(cdt(b'content type 9', ctype=9)))
    # 17-20 content type as an OID (named, unnamed), algorithm as an OID
    #       and an unknown short-form algorithm
    f.append(camel(cdt(b'content type by OID', ctype_oid='1.2.840.113549.1.7.1')))
    f.append(camel(cdt(b'unnamed content type', ctype_oid='1.2.3.4.5')))
    f.append(camel(cdt(b'algorithm by OID', alg_oid='1.2.840.113549.1.9.16.3.8', ctype=0)))
    f.append(camel(cdt(b'algorithm 1', alg=1, ctype=0)))
    # 21 CDT(p1) -> P1 -> CDT(p1) -> P1 -> CDT(p1) -> P1 (three levels,
    #    the shallow form of reproducer cdt_p1_recursion)
    f.append(camel(nested_p1(2)))
    # 22 empty content after decompression
    f.append(camel(cdt(b'', ctype=0)))
    return f


def malformed_frames():
    f = []
    # 1 content that is not zlib, 2 an empty compressed content
    f.append(camel(cdt(b'', raw_content=tlv(0x04, b'not zlib data'))))
    f.append(camel(cdt(b'', raw_content=tlv(0x04, b''))))
    # 3 compressedContent holding an INTEGER instead of an OCTET STRING
    f.append(camel(cdt(b'', raw_content=tlv(0x02, b'\x01'))))
    # 4 zlib stream cut short
    f.append(camel(cdt(b'', raw_content=tlv(0x04, zlib.compress(b'x' * 100)[:-6]))))
    # 5 CompressedData cut short inside the content type
    f.append(camel(cdt(b'abc')[:9]))
    # 6 the external content is not BER
    f.append(camel(cdt(b'\xff\xff\xff\xff', ctype=1)))
    # 7 the P1 content is not a P1 message
    f.append(camel(cdt(b'\x04\x02no', ctype=2)))
    # 8-9 a content type OID of no octets and one cut short
    f.append(camel(cdt(b'empty OID', raw_ctype=tlv(0x81, b''))))
    f.append(camel(cdt(b'bad OID', raw_ctype=tlv(0x81, b'\x2a\x86'))))
    # 10 reproducer cdt_p1_recursion: CDT in P1 in CDT 500 deep, stops at
    #   the layer limit with "Content nested too deep"
    f.append(camel(nested_p1(500, b'')))
    # 11-14 the same through P_Mul (needs -o p_mul.decode:cdt)
    f += p_mul_message(9, nested_p1(500, b''), 60000)
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cdt-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cdt-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

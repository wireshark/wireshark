#!/usr/bin/env python3
# Generates test/captures/pnrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PNRP coverage captures. Usage: mkpnrp.py <outdir> [-v]
# PNRP is registered on UDP port 3540, so no Decode As is needed.
import os
import struct
import sys
from pcaplib import udp, write_pcap

SOLICIT, ADVERTISE, REQUEST, FLOOD, INQUIRE, AUTHORITY, ACK, LOOKUP = 1, 2, 3, 4, 7, 8, 9, 0x0b
HEADER_ACKED, TARGET_ID, VALIDATE_ID, FLAGS, FLOOD_CTL, SOLICIT_CTL, LOOKUP_CTL = \
    0x18, 0x38, 0x39, 0x40, 0x43, 0x44, 0x45
EXT_PAYLOAD, ID_ARRAY, CERT_CHAIN, WCHAR, CLASSIFIER, HASHED_NONCE, NONCE, SPLIT = \
    0x5a, 0x60, 0x80, 0x84, 0x85, 0x92, 0x93, 0x98
ROUTING, VALIDATE_CPA, REVOKE_CPA, IPV6_EP, IPV6_EP_ARRAY = 0x9a, 0x9b, 0x9c, 0x9d, 0x9e

def hdr(mtype, msgid=0x01020304, vmaj=2, vmin=0, ident=0x51):
    return struct.pack('>HHBBBBI', 0x0010, 0x000c, ident, vmaj, vmin, mtype, msgid)

def msg(ftype, body, length=None):
    return struct.pack('>HH', ftype, 4 + len(body) if length is None else length) + body

def ids(n, seed=0):
    return b''.join(bytes((seed + i * 16 + j) & 0xff for j in range(32)) for i in range(n))

def id_array(n):
    return msg(ID_ARRAY, struct.pack('>HHHH', n, 8 + 32 * n, 0x0060, 32) + ids(n))

def v6(n):
    return bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n])

def route(naddr, pad=True):
    b = ids(1, 7) + struct.pack('>BBHBB', 2, 0, 3540, 0x01, naddr) + b''.join(v6(i + 1) for i in range(naddr))
    b = msg(ROUTING, b)
    return b + (b'\0' * (-len(b) % 4) if pad else b'')

def padded(b):
    return b + b'\0' * (-len(b) % 4)

def nonce():
    return msg(NONCE, b'\x11' * 16)

def hnonce():
    return msg(HASHED_NONCE, b'\x22' * 16)

def endpoints(n):
    return b''.join(struct.pack('>H', 4000 + i) + v6(0x40 + i) for i in range(n))

def cpa(flags, nsvc=2, name=b'peer.example', npayload=1, oid=b'1.2.840.113549.1.1.1', key=b'K' * 24, sig=b'S' * 32):
    b = struct.pack('>HBBBBBB', 0, 1, 1, 0, 2, flags, 0)       # length patched below
    b += struct.pack('>Q', 0x01d0000000000000) + v6(0x77)
    if not flags & 0x01:
        b += b'\x33' * 16                                     # nonce when R is clear
    if flags & 0x04:
        b += b'\x44' * 20                                     # binary authority
    if flags & 0x08:
        b += b'\x55' * 20                                     # classifier hash
    if flags & 0x10:
        b += struct.pack('<H', len(name)) + name
    b += struct.pack('<HH', nsvc, 18) + endpoints(nsvc)
    pl = b''
    if npayload:
        ents = b''.join(v6(0x90 + i) + struct.pack('<HH', 5000 + i, 6) for i in range(npayload))
        pl = struct.pack('<IH', 1, len(ents)) + ents
    b += struct.pack('<HH', npayload, len(pl) + 4) + pl
    b += struct.pack('<HHHHB', 9 + len(oid) + len(key), len(oid), 0, len(key), 0) + oid + key
    b += struct.pack('<HHI', 8 + len(sig), len(sig), 0x800c) + sig
    return struct.pack('>H', len(b)) + b[2:]

def packet(*parts):
    return b''.join(parts)

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    def add(p): F.append(udp(3540, 3540, p))
    mark('reproducer: NONCE followed by HASHED_NONCE (second message was Malformed before the fix)')
    add(hdr(ACK) + nonce() + hnonce())
    mark('ACK: acked header, flags field with the N bit')
    add(hdr(ACK) + msg(HEADER_ACKED, struct.pack('>I', 0xcafebabe)) + msg(FLAGS, b'\x00\x01\x00\x00'))
    add(hdr(ACK) + msg(HEADER_ACKED, b'\xde\xad\xbe\xef') + msg(FLAGS, b'\x00\x00\x00\x00'))
    mark('SOLICIT: solicit controls, flags of another message type, hashed nonce')
    add(hdr(SOLICIT) + msg(SOLICIT_CTL, b'\x00\x01\x00\x00') + b'\0\0' + msg(FLAGS, b'\x00\x01\x00\x02') + hnonce())
    add(hdr(SOLICIT) + msg(SOLICIT_CTL, b'\x00\x00\x00\x00') + b'\0\0' + hnonce())
    mark('ADVERTISE and REQUEST: ID arrays, routing entries (with and without padding), nonces')
    add(hdr(ADVERTISE) + id_array(2) + route(2) + hnonce())
    add(hdr(ADVERTISE) + id_array(1) + hnonce() + route(1, pad=False))
    add(hdr(ADVERTISE) + id_array(3) + route(0) + route(4))
    add(hdr(REQUEST) + id_array(2) + nonce())
    mark('FLOOD: validate IDs, flood controls with D bit')
    add(hdr(FLOOD) + msg(VALIDATE_ID, ids(2)) + msg(FLOOD_CTL, b'\x00\x01\x00') + b'\0' + hnonce())
    add(hdr(FLOOD) + msg(VALIDATE_ID, ids(1, 9)) + msg(FLOOD_CTL, b'\x00\x00\x00') + b'\0' + nonce())
    mark('INQUIRE: flags with A, X, C bits and padding, nonce, routing entry')
    add(hdr(INQUIRE) + msg(FLAGS, b'\x00\x1c') + b'\0\0' + nonce() + route(1))
    add(hdr(INQUIRE) + msg(FLAGS, b'\xff\xe3') + b'\0\0' + nonce())
    mark('LOOKUP: lookup controls, target ID, IPv6 endpoint array, routing entry')
    add(hdr(LOOKUP) + msg(LOOKUP_CTL, struct.pack('>HHBBH', 0x0003, 0x0100, 4, 1, 0)) + msg(TARGET_ID, ids(1, 3))
        + msg(IPV6_EP_ARRAY, struct.pack('>HHHH', 2, 8 + 36, 0x009d, 18) + endpoints(2)) + route(2))
    add(hdr(LOOKUP) + msg(LOOKUP_CTL, struct.pack('>HHBBH', 0x0000, 0x0000, 0, 0, 0)) + msg(TARGET_ID, ids(2, 5))
        + msg(IPV6_EP_ARRAY, struct.pack('>HHHH', 1, 8 + 18, 0x009d, 18) + endpoints(1)))
    mark('AUTHORITY: flags (with padding, and as the last message), extended payload, cert chain, classifier, routing entry, CPAs with every flag')
    cls = 'class-A'.encode('utf-16-be')
    classifier = padded(msg(CLASSIFIER, struct.pack('>HHHH', len(cls) // 2, 8 + len(cls), WCHAR, 2) + cls))
    add(hdr(AUTHORITY) + msg(FLAGS, b'\x02\x09') + b'\0\0' + msg(EXT_PAYLOAD, b'\x01\x02\x03\x04') +
        padded(msg(CERT_CHAIN, b'C' * 13)) + classifier + route(1))
    add(hdr(AUTHORITY) + msg(FLAGS, b'\x00\x01') + b'\0\0' + msg(VALIDATE_CPA, cpa(0x00)))
    add(hdr(AUTHORITY) + msg(FLAGS, b'\x00\x01') + b'\0\0' + msg(VALIDATE_CPA, cpa(0x1d, nsvc=1, npayload=2)))
    add(hdr(AUTHORITY) + msg(VALIDATE_CPA, cpa(0x04, npayload=0)) + msg(FLAGS, b'\x00\x08'))
    add(hdr(AUTHORITY) + msg(VALIDATE_CPA, cpa(0x0a, name=b'')) + msg(FLAGS, b'\x00\x00') )
    mark('AUTHORITY split over two datagrams with SPLIT_CONTROLS (reassembly)')
    inner = padded(msg(CERT_CHAIN, b'D' * 21)) + route(2) + msg(VALIDATE_CPA, cpa(0x11))
    cut = 30
    add(hdr(AUTHORITY, msgid=0x77000001) + msg(SPLIT, struct.pack('>HH', len(inner), 0)) + inner[:cut])
    add(hdr(AUTHORITY, msgid=0x77000001) + msg(SPLIT, struct.pack('>HH', len(inner), cut)) + inner[cut:])
    mark('unknown field type with data')
    add(hdr(REQUEST) + msg(0x0777, b'\xaa\xbb\xcc\xdd\xee') + nonce())
    return F, marks

def malformed_frames():
    F = []
    def add(p): F.append(udp(3540, 3540, p))
    add(hdr(ACK) + msg(NONCE, b'\x11' * 16) + struct.pack('>HH', 0x0777, 2) + b'\0' * 8)        # length below 4
    add(hdr(ACK) + msg(0x0777, b'', length=4) + b'\0' * 8)                                      # unknown, no data: not accepted
    add(hdr(ACK, ident=0x52) + msg(NONCE, b'\x11' * 16))                                         # wrong ident
    add(hdr(ACK) + b'\0\0')                                                                      # too short
    add(b'\x00\x10\x00\x0d' + hdr(ACK)[4:] + nonce())                                           # wrong header length
    add(b'\x00\x11\x00\x0c' + hdr(ACK)[4:] + nonce())                                           # wrong first field
    add(hdr(AUTHORITY) + msg(VALIDATE_CPA, cpa(0x1d)[:40]))                                      # CPA cut short
    add(hdr(LOOKUP) + msg(IPV6_EP_ARRAY, struct.pack('>HHHH', 2, 8 + 36, 0x009d, 18) + endpoints(1)[:10]))
    # split controls whose reassembled data holds another SPLIT_CONTROLS with offset 0: the switch happens only once
    inner = msg(SPLIT, struct.pack('>HH', 6, 0) + b'abcdef')[:8] + b'abcdef'
    add(hdr(AUTHORITY, msgid=0x77000009) + msg(SPLIT, struct.pack('>HH', len(inner), 0)) + inner[:8])
    add(hdr(AUTHORITY, msgid=0x77000009) + msg(SPLIT, struct.pack('>HH', len(inner), 8)) + inner[8:])
    # a second part that does not fit
    add(hdr(AUTHORITY, msgid=0x7700000a) + msg(SPLIT, struct.pack('>HH', 40, 100)) + b'x' * 10)
    add(hdr(AUTHORITY) + msg(SPLIT, struct.pack('>HH', 40, 0)) + b'x' * 10)                      # fragment only
    add(hdr(AUTHORITY) + msg(CERT_CHAIN, b'C' * 3, length=30))                                   # length past the end
    add(hdr(AUTHORITY) + msg(CLASSIFIER, struct.pack('>HHHH', 3, 8 + 6, WCHAR, 2) + b'\0a\0b'))   # classifier cut short
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'pnrp-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'pnrp-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')

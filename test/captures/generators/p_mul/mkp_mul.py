#!/usr/bin/env python3
# Generates test/captures/p_mul_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the P_Mul (ACP142) coverage captures. Usage: mkp_mul.py <outdir> [-v]
# Every frame is an Exported PDU ("p_mul") frame, the only default way
# to reach P_Mul (no UDP port is registered by default).
import os
import struct
import sys
from pcaplib import csum, exported_pdu, write_pcap

DATA, ACK, ADDR, DISCARD, ANNOUNCE, REQUEST, REJECT, RELEASE, FECADDR = 0, 1, 2, 3, 4, 5, 6, 7, 8
XADDR, XFECADDR = 0x12, 0x18

def ip(a):
    return bytes(int(x) for x in a.split('.'))

def fletcher(buf, offset):
    n = len(buf)
    c0 = c1 = 0
    for b in buf:
        c0 += b
        if c0 > 254: c0 -= 255
        c1 += c0
        if c1 > 254: c1 -= 255
    ctmp = n - offset - 1
    cs = (ctmp * c0 - c1)
    cs = int(cs - 255 * int(cs / 255))   # C remainder (truncates toward zero)
    if cs < 0: cs += 255
    ret = cs << 8
    cs = (c1 - (ctmp + 1) * c0)
    cs = int(cs - 255 * int(cs / 255))
    if cs < 0: cs += 255
    return ret | cs

def pdu(ptype, f1, mapbits, f3, rest, ck='ip', length=None, trail=b''):
    """f1: priority/unused octet, mapbits: top two bits of the type octet,
    f3: the 16 bit field after it, rest: everything after the checksum."""
    body = struct.pack('>BBH', f1, (mapbits << 6) | ptype, f3) + b'\0\0' + rest
    total = 2 + len(body)
    L = total if length is None else length
    buf = struct.pack('>H', L) + body
    if ck == 'ip':
        c = csum(buf)
    elif ck == 'fletcher':
        c = fletcher(buf, 6)
    else:
        c = 0xdead
    buf = buf[:6] + struct.pack('>H', c) + buf[8:]
    return buf + trail

def address(src, mid, npdus, dests, expiry=0x60000000, res=0, ptype=ADDR, mapbits=0, fec=None, **kw):
    r = ip(src) + struct.pack('>II', mid, expiry)
    if fec is not None:
        fid, params = fec
        r += struct.pack('>BB', len(params), fid) + params
    r += struct.pack('>HH', len(dests), res)
    for d, seq in dests:
        r += ip(d) + struct.pack('>I', seq) + b'\x5a' * res
    return pdu(ptype, 3, mapbits, npdus, r, **kw)

def data(src, mid, seq, payload, prio=1, **kw):
    return pdu(DATA, prio, 0, seq, ip(src) + struct.pack('>I', mid) + payload, **kw)

def ack(acker, entries, ts=None, **kw):
    """entries: list of (src, mid, [missing seq words]); the words are
    emitted verbatim so ranges (n, 0, m) can be written by the caller."""
    r = ip(acker) + struct.pack('>H', len(entries))
    for src, mid, seqs in entries:
        ln = 10 + 2 * len(seqs)
        if isinstance(src, tuple):          # (src, length override)
            src, ln = src
        r += struct.pack('>H', ln) + ip(src) + struct.pack('>I', mid)
        r += b''.join(struct.pack('>H', s) for s in seqs)
    if ts is not None:
        r += struct.pack('>Q', ts)
    return pdu(ACK, 2, 0, 0, r, **kw)

def simple(ptype, src, mid, mcgroup, f1=0, mapbits=0, f3=0, **kw):
    return pdu(ptype, f1, mapbits, f3, ip(src) + struct.pack('>I', mid) + ip(mcgroup), **kw)

def announce(src, mid, mcgroup, dests, **kw):
    r = ip(src) + struct.pack('>II', mid, 0x60000000) + ip(mcgroup) + b''.join(ip(d) for d in dests)
    return pdu(ANNOUNCE, 0, 0, len(dests), r, **kw)

def discard(src, mid, **kw):
    return pdu(DISCARD, 4, 0, 0, ip(src) + struct.pack('>I', mid), **kw)

S, A, B, C = '192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'
BER = bytes.fromhex('3009020101040461626364')   # SEQUENCE { INTEGER 1, OCTET STRING "abcd" }

def main_frames():
    F = []
    marks = []
    def mark(name):
        marks.append((name, len(F) + 1))
    mark('reproducer: relative message ids 0 and 5 (assert on the second pass before the fix)')
    F.append(address(S, 0, 0, [(A, 1)]))
    F.append(address(S, 5, 0, [(A, 1)]))

    mark('message 10: Address, 3 Data PDUs reassembled (BER payload), Acks, a retransmission, Dup ACK, Ack-Ack')
    F.append(address(S, 10, 3, [(A, 1), (B, 2)], mapbits=0))
    F.append(data(S, 10, 1, BER[:4]))
    F.append(data(S, 10, 2, BER[4:8]))
    F.append(data(S, 10, 3, BER[8:]))
    F.append(ack(A, [(S, 10, [])], ts=100))
    F.append(ack(B, [(S, 10, [2, 0, 3])]))           # a range, then complete
    F.append(data(S, 10, 2, BER[4:8]))               # retransmission of a Data PDU
    F.append(address(S, 10, 3, [(A, 1), (B, 2)]))    # retransmission of the Address PDU
    F.append(ack(A, [(S, 10, [])]))                  # duplicate ack
    F.append(ack(B, [(S, 10, [])], ts=10))
    F.append(address(S, 10, 0, []))                  # Ack-Ack

    mark('message 11: symmetric keys, missing previous Data PDU, illegal seq no, Data without Address')
    F.append(address(S, 11, 4, [(A, 1), (B, 2), (C, 3)], res=8, mapbits=1))
    F.append(data(S, 11, 1, b'one'))
    F.append(data(S, 11, 3, b'three'))               # PDU 2 missing
    F.append(data(S, 11, 4, b'four'))
    F.append(data(S, 11, 0, b'zero'))                # illegal sequence number
    F.append(address(S, 11, 4, [(A, 1), (B, 2), (C, 3)], res=8, mapbits=1))   # Address PDU retransmission before any ack
    F.append(data(S, 99, 1, b'orphan'))              # no Address PDU
    F.append(data(S, 99, 2, b'orphan2'))
    F.append(data('192.0.2.9', 99, 1, b'again', prio=3))
    F.append(ack(C, [(S, 11, [2])]))                 # one missing
    F.append(ack(C, [(S, 11, [2])]))                 # same again (Dup ACK)
    F.append(ack(A, [(S, 11, [1, 0, 2, 4, 3, 0, 7, 9, 0, 8])]))  # ranges, invalid range, end-of-list
    F.append(ack(B, [(S, 11, [4, 2])]))              # 4 missing, then 2: end of list indicator
    F.append(ack(B, [(S, 77, [])]))                  # ack for a message never announced
    F.append(ack(B, [(S, 77, [0, 3])]))              # invalid seq no 0
    F.append(ack(A, [(S, 10, []), (S, 11, []), (S, 99, [])], ts=11))  # three entries, timestamp 1.1

    mark('other PDU types: Discard, Announce, Request, Reject, Release, unknown type')
    F.append(discard(S, 13))
    F.append(discard(S, 13))                         # discard retransmission
    F.append(announce(S, 14, '224.0.1.5', [A, B]))
    F.append(announce(S, 14, '224.0.1.5', []))
    F.append(simple(REQUEST, A, 15, '224.0.1.5'))
    F.append(simple(REJECT, A, 15, '224.0.1.5', mapbits=2))
    F.append(simple(RELEASE, S, 15, '224.0.1.5'))
    F.append(pdu(0x0a, 0, 0, 0, ip(S) + struct.pack('>I', 16)))   # unknown PDU type

    mark('Address variants: map first/last, FEC, Extra, Extra FEC, a message split across Address PDUs')
    F.append(address(S, 20, 2, [(A, 1)], ptype=ADDR, mapbits=2))
    F.append(address(S, 20, 2, [(B, 1)], ptype=XADDR, mapbits=1))
    F.append(address(S, 21, 1, [(A, 1)], ptype=FECADDR, fec=(3, b'\x01\x02\x03\x04')))
    F.append(address(S, 21, 1, [(A, 1)], ptype=FECADDR, fec=(0, b'')))
    F.append(address(S, 22, 1, [(A, 1)], ptype=XFECADDR, fec=(7, b'\xaa\xbb'), mapbits=3))
    F.append(data(S, 21, 1, b'fec data'))

    mark('checksums: Fletcher, incorrect checksum')
    F.append(address(S, 30, 1, [(A, 1)], ck='fletcher'))
    F.append(address(S, 31, 1, [(A, 1)], ck='bad'))
    F.append(data(S, 35, 1, b'x', ck='bad'))
    return F, marks

def malformed_frames():
    F = []
    F.append(ack(A, [(S, 50, [])]))                                  # first PDU is an Ack: sets the relative message id offset
    F.append(pdu(DATA, 1, 0, 1, b'\x01\x02'))                        # truncated: Source/Message Id cut short
    F.append(pdu(ACK, 2, 0, 0, ip(A) + struct.pack('>H', 2) + struct.pack('>H', 10) + ip(S)))   # Ack entry cut
    F.append(address(S, 40, 1, [(A, 1)])[:30])                       # Address cut inside the destination list
    F.append(pdu(ADDR, 0, 0, 1, ip(S) + struct.pack('>II', 41, 0) + struct.pack('>HH', 3, 0)))  # destinations missing
    F.append(pdu(ANNOUNCE, 0, 0, 5, ip(S) + struct.pack('>II', 42, 0) + ip(A) + ip(B)))     # count too big
    F.append(ack(B, [((S, 8), 12, [])]))                             # entry length below 10 (invalid)
    F.append(address(S, 32, 1, [(A, 1)], length=99))                 # incorrect length field
    F.append(address(S, 33, 1, [(A, 1)], length=48))                 # shorter than the PDU: more data
    F.append(address(S, 34, 1, [(A, 1)], trail=b'\0\0\0'))          # data after the PDU
    F.append(bytes([0, 3, 0]))                                       # 3 octets only
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'p_mul-coverage.pcap'), [exported_pdu('p_mul', f) for f in F], linktype=252)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'p_mul-coverage-malformed.pcap'), [exported_pdu('p_mul', f) for f in M], linktype=252)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')

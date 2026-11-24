#!/usr/bin/env python3
# Generates test/captures/packclient_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PackClient coverage captures. Usage: mkpackclient.py <outdir> [-v]
# PackClient has no registered port: the TCP heuristic claims a stream whose
# first segment holds a complete, valid launcher PDU (PLH1, PLC1, PLA1, PLK1 or
# a launcher envelope). Core messages are dissected once the stream is bound.
# The malformed capture uses Decode As (see runcov.sh).
import hashlib
import os
import struct
import sys
from pcaplib import Tcp, write_pcap

PREFIX = 0x5A400000
DIGEST = hashlib.sha256(b'passive-synthetic-vector').digest()

def pdu(mtype, payload, length=None, prefix=PREFIX):
    body = 4 + len(payload)
    return struct.pack('<II', prefix | (body if length is None else length), mtype) + payload

def plh1(version=1, f06=0x20, f08=0, f0c=1, tick=0x0102030405060708, pid=4242, reserved=0):
    return struct.pack('<4sHHIIQII', b'PLH1', version, f06, f08, f0c, tick, pid, reserved)
def plc1(version=1): return struct.pack('<4sHH16s', b'PLC1', version, 0xBEEF, bytes(range(16)))
def pla1(version=1, reserved=0): return struct.pack('<4sHH32s', b'PLA1', version, reserved, bytes(range(32)))
def plk1(version=1, lz4=0, total=24, original=24):
    return struct.pack('<4sHBBQQ32s', b'PLK1', version, lz4, 0, total, original, DIGEST)
def envelope(clen=None, ct=bytes(range(32)), endian='>', version=1):
    clen = len(ct) if clen is None else clen
    return bytes([version]) + bytes(range(16)) + struct.pack(endian + 'I', clen) + ct + bytes(32)
def pv10(jpeg, length=None):
    return struct.pack('<4sI', b'PV10', len(jpeg) if length is None else length) + jpeg
JPEG = bytes.fromhex('ffd8ffe000104a46494600010100000100010000ffd9')

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    t = Tcp(49152, 59999)
    c = lambda d: F.append(t.c2s(d))
    s = lambda d: F.append(t.s2c(d))
    mark('launcher exchange bound by the heuristic: PLH1, PLC1, PLA1, PLK1 version 1 and 2 (LZ4 flag), a launcher envelope (big-endian length) and a core envelope (little-endian length)')
    c(pdu(0x15, plh1()))
    s(pdu(0x15, plc1()))
    c(pdu(0x15, pla1()))
    s(pdu(0x15, plk1(1, 0, 24, 24)))
    s(pdu(0x15, plk1(2, 1, 4096, 8192)))
    c(pdu(0x16, envelope(ct=bytes(range(32)))))
    s(pdu(0x16, envelope(ct=bytes(range(16)), endian='<')))
    mark('core messages: types 1, 2, 3, 10, 11, 17 with every command prefix, without a command and without a prefix, PV10 JPEG, an unknown type')
    c(pdu(0x01, b'\x00\x00\x00\x00INP|mouse,10,20\0trailing'))
    c(pdu(0x02, b'xxSYS|ping'))
    c(pdu(0x03, b'TLM|cpu=3;mem=40\0\0\0'))
    s(pdu(0x0a, b'\x01\x02SCR|capture 1\0'))
    s(pdu(0x0b, b'\x07Q|status'))
    c(pdu(0x11, b'PIPE|stdout\0'))
    c(pdu(0x01, b'nothing to see here'))
    c(pdu(0x02, b''))
    c(pdu(0x03, b'\x00\x00\x00\x00\0'))
    s(pdu(0x12, pv10(JPEG)))
    s(pdu(0x30, b'unknown type payload'))
    mark('two PDUs in one segment, and a PDU split over two segments (TCP PDU reassembly)')
    c(pdu(0x01, b'INP|a') + pdu(0x02, b'SYS|b'))
    big = pdu(0x03, b'TLM|' + b'x' * 300)
    c(big[:120]); c(big[120:])
    s(pdu(0x11, b'PIPE|' + b'y' * 1000))
    mark('two more streams bound by their first PDU: a PLK1 (version 2) and a launcher envelope')
    t2 = Tcp(49153, 59998)
    F.append(t2.c2s(pdu(0x15, plk1(2, 0, 100, 200))))
    F.append(t2.s2c(pdu(0x01, b'INP|from the second stream')))
    t3 = Tcp(49154, 59997)
    F.append(t3.c2s(pdu(0x16, envelope(ct=bytes(range(48))))))
    F.append(t3.s2c(pdu(0x15, pla1())))
    return F, marks

def malformed_frames():
    F = []
    base = 40000
    n = [0]
    def stream():
        t = Tcp(base + n[0], 59990 + n[0] % 1)   # all on server port 59990 (Decode As)
        n[0] += 1
        return t
    def one(*pdus):
        t = Tcp(base + n[0], 59990)
        n[0] += 1
        for d in pdus:
            F.append(t.c2s(d))
    one(pdu(0x15, plh1(version=2)))                           # PLH1 fixed fields invalid
    one(pdu(0x15, plh1(), length=40) + b'\0' * 4)             # PLH1 with the wrong body length
    one(pdu(0x15, plc1(version=2)))
    one(pdu(0x15, plc1(), length=40) + b'\0' * 12)
    one(pdu(0x15, pla1(reserved=1)))
    one(pdu(0x15, pla1(version=3)))
    one(pdu(0x15, plk1(version=3)))
    one(pdu(0x15, plk1(total=0)))
    one(pdu(0x15, plk1(total=0x08000001)))
    one(pdu(0x15, plk1(version=2, original=0)))
    one(pdu(0x15, plk1(version=2, original=0x08000001)))
    one(pdu(0x15, b'XXXX' + b'\0' * 20))                      # unknown object magic
    one(pdu(0x15, b'ab'))                                     # object shorter than 8 octets
    one(pdu(0x16, b'\x01' + bytes(16)))                       # envelope shorter than 0x35
    one(pdu(0x16, envelope(version=2)))
    one(pdu(0x16, envelope(clen=48)))                         # length matches neither order
    one(pdu(0x16, envelope(clen=17, ct=bytes(17))))           # not block aligned
    one(pdu(0x16, envelope(clen=0, ct=b'')))                  # empty ciphertext, ambiguous order
    one(pdu(0x16, envelope(ct=bytes(range(16)), endian='<')))  # core order
    one(pdu(0x12, b'PV1'))                                    # PV10 shorter than 8
    one(pdu(0x12, struct.pack('<4sI', b'XXXX', 2) + b'\xff\xd8'))
    one(pdu(0x12, pv10(JPEG, length=5)))
    one(pdu(0x12, pv10(b'\x00\x01\x02\x03')))                 # no SOI
    one(pdu(0x12, pv10(b'\xff\xd8\xff\xd8\xff\xd8')))         # no EOI
    one(pdu(0x12, pv10(b'\xff')))                             # JPEG shorter than 2
    one(pdu(0x12, pv10(b'\xff\xd8')))                         # JPEG of 2: no EOI
    one(pdu(0x01, b'INP|x', prefix=0x5A000000))               # invalid frame prefix
    one(b'\x00\x00\x40\x5a' + b'\x02\x00\x00\x00')            # body length 2
    one(pdu(0x01, b'', length=0))                             # body length 0
    one(pdu(0x01, b'INP|click\0'), pdu(0x16, envelope(ct=bytes(range(16)), endian='<')),
        pdu(0x16, envelope(ct=bytes(range(32)))))             # core-first stream: envelopes
    one(pdu(0x15, b'PLK1' + bytes(48)))                      # PLK1 magic with a body length of 56
    one(pdu(0x01, b'SYS|a') [:6])                             # PDU cut inside the length word
    # first segments the heuristic refuses (no Decode As): they stay plain TCP
    def heur(*pdus):
        t = Tcp(base + 100 + n[0], 59980)
        n[0] += 1
        for d in pdus:
            F.append(t.c2s(d))
    heur(pdu(0x15, plh1())[:20])                               # incomplete first PDU
    heur(pdu(0x15, plh1(version=2)))                           # PLH1 fixed fields invalid
    heur(pdu(0x15, plc1(version=2)))
    heur(pdu(0x15, pla1(reserved=1)))
    heur(pdu(0x15, plk1(version=3)))
    heur(pdu(0x15, plk1(total=0)))
    heur(pdu(0x15, plk1(total=0x08000001)))
    heur(pdu(0x15, plk1(version=2, original=0)))
    heur(pdu(0x15, plk1(version=2, original=0x08000001)))
    heur(pdu(0x15, plh1(), length=40) + bytes(4))              # unknown plaintext body length
    heur(pdu(0x15, b'XXXX' + bytes(28)))                       # right length, no known magic
    heur(pdu(0x16, envelope(version=2)))
    heur(pdu(0x16, envelope(ct=bytes(range(16)), endian='<')))
    heur(pdu(0x16, envelope(clen=17, ct=bytes(17))))
    heur(pdu(0x16, envelope(clen=0, ct=b'')))
    heur(pdu(0x16, b'\x01' + bytes(40)))
    heur(pdu(0x01, b'INP|x'))                                  # core type first
    heur(b'abc')
    heur(pdu(0x15, plh1(), prefix=0x5A000000))
    heur(struct.pack('<II', PREFIX | 2, 0x15) + bytes(8))
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'packclient-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'packclient-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')

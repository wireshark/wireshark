#!/usr/bin/env python3
# Generates test/captures/irdma_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the IBM i RDMA (irdma)
dissector (packet-irdma.c).

The irdma dissector registers no port or link type of its own: IBM i
TRCCNN traces are converted to exported PDUs, and the dissector is
reached through the exported PDU "dissector name" tag (pcap link type
252, tag 12 = "irdma").  Every packet is built with struct; nothing comes
from a real system.

A frame is the 46 octet pseudo header (destination and source MAC, QP
index, source and destination IP address as 16 octets each) followed by
the message: a QP (0x80 type bits), Link (0xA0) or Endpoint frame.

Usage: mkirdma.py <output directory>

Writes:
  irdma-coverage.pcap            QP, Link and Endpoint messages over IPv4
                                 (mapped, compatible) and IPv6 addresses:
                                 connect, buffers, data with sequence
                                 analysis (retransmission, out of order),
                                 reuse, user receive/send, link move,
                                 close and reconnect, reset
  irdma-coverage-malformed.pcap  frames too short, frame types 6/7, short
                                 QP/Link/Endpoint messages
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import socket
from netlib import write_pcap

def exp(name, payload):
    n = name.encode()
    n += b'\0' * ((-len(n)) % 4)
    return (struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload)

def ipbytes(a):
    if ':' in a:
        return socket.inet_pton(socket.AF_INET6, a)
    return b'\0' * 10 + b'\xff\xff' + socket.inet_aton(a)

def phdr(src, dst, qp=3, smac=1, dmac=2, compat_src=False):
    s = ipbytes(src)
    d = ipbytes(dst)
    if compat_src:
        s = b'\0' * 12 + socket.inet_aton(src)
    h = b'\x02\0\0\0\0' + bytes([dmac]) + b'\x02\0\0\0\0' + bytes([smac])
    h += struct.pack('>H', qp) + s + d
    assert len(h) == 46
    return h

GRP = b'\x01' + b'\x00\x00\x00\x10\x00' + b'\x02\x00\x00\x00\x00\x01'

def ep(t, sport, dport, link, body=b'', total=None, grp=GRP):
    m = struct.pack('>BB', t, 0) + grp + struct.pack('>HHH', sport, dport, link) + body
    if total is None:
        total = len(m)
    m = m[:1] + bytes([total & 0xff]) + m[2:]
    return m.ljust(total, b'\0') if total > len(m) else m

def conn(bufsz=16, usr=4):
    return struct.pack('>HH', bufsz, usr)

def bufmsg(rk0, ra0, rk1, ra1, flags_size):
    return struct.pack('>IIQQ', rk0, rk1, ra0, ra1) + struct.pack('>H', flags_size)

def move(rk0, ra0, rk1, ra1, flags_size, sendseq, r0, r1, usnt, usid):
    return bufmsg(rk0, ra0, rk1, ra1, flags_size) + struct.pack('>HHHIH', sendseq, r0, r1, usnt, usid)

def data(seq, bufid, off, ln, payload=b''):
    return struct.pack('>HHII', seq, bufid, off, ln) + payload

def reuse(seq, bufid):
    return struct.pack('>HH', seq, bufid)

def recvreq(ulen, off, blen, rid, rkey, raddr, payload=b''):
    return struct.pack('>IIIHIQ', ulen, off, blen, rid, rkey, raddr) + payload

def send(ulen, off, slen, rid, payload=b''):
    return struct.pack('>IIIH', ulen, off, slen, rid) + payload

frames = []
t0 = [1700000000.0]
def add(src, dst, payload, dt=0.01, **kw):
    t0[0] += dt
    frames.append((exp('irdma', phdr(src, dst, **kw) + payload), t0[0]))

C = '192.0.2.1'; S = '192.0.2.2'
CP, SP = 40000, 930

# ---- stream 1 over IPv4: connect, buffers
add(C, S, ep(0x01, CP, SP, 1, conn(16, 4)))
add(S, C, ep(0x02, SP, CP, 1, conn(16, 4)))
add(S, C, ep(0x03, SP, CP, 1, bufmsg(0x11, 0x1000, 0x12, 0x2000, 0x0010)))
add(C, S, ep(0x03, CP, SP, 1, bufmsg(0x21, 0x3000, 0, 0, 0x0008)))
add(C, S, ep(0x04, CP, SP, 1, struct.pack('>H', 8)))       # RNEGREQ
add(S, C, ep(0x05, SP, CP, 1, bufmsg(0x13, 0x4000, 0x14, 0x5000, 0x0010)))  # RNEGACK
# ---- data with analysis, reuse, retransmission and out of order
add(C, S, ep(0x21, CP, SP, 1, data(1, 0, 0, 100, b'A' * 32)))
add(S, C, ep(0x22, SP, CP, 1, reuse(1, 0)))
add(C, S, ep(0x21, CP, SP, 1, data(2, 0, 112, 3000, b'B' * 32)))
add(C, S, ep(0x21, CP, SP, 1, data(3, 1, 0, 8, b'C' * 8)))
add(C, S, ep(0x21, CP, SP, 1, data(3, 1, 0, 8, b'C' * 8)))         # retransmission
add(C, S, ep(0x21, CP, SP, 1, data(4, 1, 16, 8, b'D' * 8)))
add(S, C, ep(0x22, SP, CP, 1, reuse(4, 1)))
add(S, C, ep(0x22, SP, CP, 1, reuse(5, 0)))
add(C, S, ep(0x21, CP, SP, 1, data(5, 2, 0, 8, b'E' * 8)))         # bufid beyond the tracked ones
add(S, C, ep(0x22, SP, CP, 1, reuse(10, 2)))
add(C, S, ep(0x21, CP, SP, 1, data(5, 0, 0, 0x2000, b'F' * 8)))
# data from the server (the other flow): the first one before any buffer message
add(S, C, ep(0x21, SP, CP, 1, data(1, 1, 0, 64, b'G' * 16)))
add(S, C, ep(0x21, SP, CP, 1, data(2, 0, 64, 64, b'H' * 16)))
add(C, S, ep(0x22, CP, SP, 1, reuse(2, 0)))
add(C, S, ep(0x22, CP, SP, 1, reuse(1, 1)))
# a reuse of a buffer whose data was not captured (single buffer, sequence mismatch)
add(C, S, ep(0x22, CP, SP, 1, reuse(77, 0)))
# ---- user RDMA receive and send
add(S, C, ep(0x23, SP, CP, 1, recvreq(8192, 0, 4096, 1, 0x31, 0x6000, b'user data')))
add(C, S, ep(0x24, CP, SP, 1, send(8192, 0, 4096, 1, b'send1')))
add(C, S, ep(0x24, CP, SP, 1, send(8192, 4096, 4096, 1, b'send2')))   # expected offset
add(C, S, ep(0x24, CP, SP, 1, send(8192, 0, 4096, 2, b'send3')))      # next id, offset 0
add(C, S, ep(0x24, CP, SP, 1, send(8192, 0, 4096, 2, b'send4')))      # retransmission (same id, lower offset)
add(C, S, ep(0x25, CP, SP, 1, send(8192, 4096, 4096, 2, b'nak')))     # RECVNAK, the expected offset
# ---- link move to link 2
add(C, S, ep(0x11, CP, SP, 2, move(0x11, 0x1000, 0x12, 0x2000, 0xC010, 11, 9, 5, 4096, 1)))
add(S, C, ep(0x12, SP, CP, 2, move(0x11, 0x1000, 0, 0, 0x4010, 3, 4, 5, 0, 0) + struct.pack('>H', 2)))
add(C, S, ep(0x13, CP, SP, 2, struct.pack('>H', 7)))
add(C, S, ep(0x21, CP, SP, 2, data(6, 1, 0, 32, b'link2' * 6)))
add(C, S, ep(0x21, CP, SP, 1, data(7, 1, 48, 32, b'stale')))          # prior link (stale)
add(S, C, ep(0x30, SP, CP, 2, b'\0' * 8))                                # unknown EP message type
# ---- close and a reconnect with the same ports (new stream)
add(C, S, ep(0x06, CP, SP, 2, struct.pack('>I', 5)))
add(C, S, ep(0x01, CP, SP, 3, conn(32, 8)))
add(S, C, ep(0x02, SP, CP, 3, conn(32, 8)))
add(S, C, ep(0x09, SP, CP, 3, b'\0' * 4))                                # RESET
add(C, S, ep(0x09, CP, SP, 3, b'\0' * 4))

# ---- a stream that starts with REUSEBUF messages (no buffer information was captured)
add(S, C, ep(0x22, 940, 43000, 1, reuse(0, 0)))
add(S, C, ep(0x22, 940, 43000, 1, reuse(7, 0)))
add(S, C, ep(0x22, 940, 43000, 1, reuse(3, 1)))

# ---- stream 2: IPv6, a port with a name (931), compatible IPv4 source address
C6 = '2001:db8::1'; S6 = '2001:db8::2'
add(C6, S6, ep(0x01, 41000, 931, 1, conn(4, 1)), qp=5)
add(S6, C6, ep(0x02, 931, 41000, 1, conn(4, 1)), qp=5)
add(S6, C6, ep(0x03, 931, 41000, 1, bufmsg(0x41, 0x7000, 0x42, 0x8000, 0x0001)), qp=5)
add(C6, S6, ep(0x21, 41000, 931, 1, data(1, 0, 0, 100, b'v6')), qp=5)
add(C6, S6, ep(0x21, 41000, 931, 1, data(2, 1, 0, 4090, b'v6')), qp=5)
add(S6, C6, ep(0x22, 931, 41000, 1, reuse(1, 0)), qp=5)
add(C, S, ep(0x01, 41001, 932, 1, conn(2, 2)), qp=6, compat_src=True)
add(C, S, ep(0x01, 41002, 940, 1, conn(2, 2)), qp=7)
add(C, S, ep(0x01, 41003, 946, 1, conn(2, 2)), qp=8)
add(C, S, ep(0x21, 41003, 946, 1, data(1, 0, 0, 16, b'dd')), qp=8)

# ---- QP and Link management
add(C, S, struct.pack('>HH', 0x8000, 0x1234), qp=3)
add(S, C, struct.pack('>HH', 0x8001, 0x1234), qp=3)
add(S, C, struct.pack('>H', 0x8002) + b'\0\0', qp=3)               # unknown QP message
add(C, S, struct.pack('>HH', 0xA000, 7), qp=3)
add(S, C, struct.pack('>H', 0xA001) + b'\0\0', qp=3)               # unknown Link message

# ---- malformed capture
mal = []
def addm(payload, raw=None):
    t0[0] += 0.01
    mal.append((exp('irdma', payload), t0[0]))
addm(b'\0' * 30)                                           # shorter than the pseudo header
addm(phdr(C, S) + bytes([0xC0, 0, 0, 0]))                  # frame type 6
addm(phdr(C, S) + bytes([0xE0, 0, 0, 0]))                  # frame type 7
addm(phdr(C, S) + b'\x80')                                  # QP message of one octet
addm(phdr(C, S) + b'\xa0')                                  # Link message of one octet
addm(phdr(C, S) + ep(0x21, 1, 2, 1)[:19])                  # Endpoint message too short
addm(phdr(C, S) + ep(0x21, 1, 2, 1, data(1, 0, 0, 10))[:30])  # DATA cut in the middle of its header
addm(phdr(C, S) + ep(0x23, 1, 2, 1, recvreq(1, 0, 1, 1, 1, 1))[:40])
addm(phdr(C, S) + ep(0x24, 1, 2, 1, send(1, 0, 1, 1))[:30])
addm(phdr(C, S) + ep(0x03, 1, 2, 1, bufmsg(1, 2, 3, 4, 5))[:30])
addm(phdr(C, S) + ep(0x11, 1, 2, 1, move(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))[:50])
addm(phdr(C, S) + ep(0x12, 1, 2, 1, move(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))[:58])
addm(phdr(C, S) + ep(0x13, 1, 2, 1)[:20])
addm(phdr(C, S) + ep(0x01, 1, 2, 1, conn())[:22])
addm(phdr(C, S) + ep(0x06, 1, 2, 1, struct.pack('>I', 1))[:22])
addm(phdr(C, S) + ep(0x22, 1, 2, 1, reuse(1, 0))[:21])

# ---- out of order DATA and RECVACK (expert errors): their own stream
def addo(src, dst, payload):
    t0[0] += 0.01
    mal.append((exp('irdma', phdr(src, dst) + payload), t0[0]))
addo(C, S, ep(0x01, 42000, 930, 1, conn(16, 4)))
addo(C, S, ep(0x21, 42000, 930, 1, data(1, 0, 0, 100, b'A' * 8)))
addo(C, S, ep(0x21, 42000, 930, 1, data(9, 0, 112, 8, b'B' * 8)))      # out of order
addo(C, S, ep(0x24, 42000, 930, 1, send(8192, 0, 4096, 1, b'send1')))
addo(C, S, ep(0x24, 42000, 930, 1, send(8192, 100000, 4096, 9, b'x')))  # out of order

out = sys.argv[1] if len(sys.argv) > 1 else '.'
write_pcap(os.path.join(out, 'irdma-coverage.pcap'), frames, 252)
write_pcap(os.path.join(out, 'irdma-coverage-malformed.pcap'), mal, 252)
print(len(frames), len(mal))

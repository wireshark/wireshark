#!/usr/bin/env python3
# Generates test/captures/udpcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the UDPCP coverage captures. Usage: mkudpcp.py <outdir> [-v]

Everything is built with struct; addresses are from 192.0.2.0/24.
UDPCP has no default UDP port, so the main and malformed captures carry
the PDUs in Exported PDU frames (linktype 252) that name the "udpcp"
dissector and give the IPv4 addresses and UDP ports; the third capture
is plain Ethernet/IPv4/UDP and needs Decode As (runcov.sh uses -d).
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

C = (bytes([192, 0, 2, 1]), 6000)     # client
S = (bytes([192, 0, 2, 2]), 5000)     # server


def tag(t, v):
    pad = (-len(v)) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def exppdu(payload, src=None, dst=None, name='udpcp'):
    t = tag(12, name.encode())
    if src and dst:
        t += tag(20, src[0]) + tag(21, dst[0])
        t += tag(24, struct.pack('>I', 3))            # UDP
        t += tag(25, struct.pack('>I', src[1])) + tag(26, struct.pack('>I', dst[1]))
    return t + struct.pack('>HH', 0, 0) + payload


def write(fn, pkts, linktype):
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(p), len(p)))
            f.write(p)


def udpcp(mtype=1, ver=1, n=0, c=0, s=0, d=0, res=0, famt=1, fnum=0, mid=0,
          dlen=None, data=b'', csum=0):
    if dlen is None:
        dlen = len(data)
    return (struct.pack('>I', csum) +
            bytes([(mtype << 6) | (ver << 3) | (n << 2) | (c << 1) | s,
                   (d << 7) | res, famt, fnum]) +
            struct.pack('>HH', mid, dlen) + data)


def ex(payload, a, b):
    return exppdu(payload, a, b)


def build(items):
    return [ex(p, a, b) for (p, a, b) in items]


XML1 = b'<hello><world>1</world></hello>'
XML2 = b'<?xml version="1.0"?><note to="a">bye</note>'
BLOB = bytes(range(32, 60))

# ---- main capture ------------------------------------------------------
main = []
def m(p, a, b):
    main.append(ex(p, a, b))
    return len(main)

marks = {}
marks['sync'] = m(udpcp(mid=0), C, S)
marks['unfrag'] = m(udpcp(mid=1, data=XML1), C, S)
marks['ack1'] = m(udpcp(mtype=2, n=1, s=1, mid=1), S, C)
# three fragments of mid 2: not ACKd, not ACKd, last ACKd
f = XML2 + b' ' * 20 + BLOB
parts = [f[:24], f[24:48], f[48:]]
marks['frag2'] = []
for i, pt in enumerate(parts):
    marks['frag2'].append(m(udpcp(mid=2, famt=3, fnum=i, n=1 if i < 2 else 0,
                                  s=1 if i == 2 else 0, dlen=len(f), data=pt), C, S))
marks['ack2'] = m(udpcp(mtype=2, n=1, s=1, mid=2), S, C)
marks['csum'] = m(udpcp(mid=3, n=1, c=1, csum=0x12345678, data=BLOB), C, S)
marks['xml4'] = m(udpcp(mid=4, s=1, data=XML2), C, S)
marks['dupack'] = m(udpcp(mtype=2, n=1, s=1, d=1, mid=4), S, C)
# second direction: server sends data to the client
marks['rev0'] = m(udpcp(mid=0, data=b'<r/>'), S, C)
g = b'<reply>' + b'z' * 30 + b'</reply>'
marks['rev1'] = []
# out of order: fragment 1 first, then fragment 0
marks['rev1'].append(m(udpcp(mid=1, famt=2, fnum=1, s=1, dlen=len(g), data=g[16:]), S, C))
marks['rev1'].append(m(udpcp(mid=1, famt=2, fnum=0, dlen=len(g), data=g[:16]), S, C))
marks['rev1ack'] = m(udpcp(mtype=2, n=1, s=1, mid=1), C, S)
# fragmented message with a zero data length: nothing to reassemble
marks['zerolen'] = m(udpcp(mid=5, famt=2, fnum=0, dlen=0), C, S)
# not UDPCP: unknown message type, and shorter than the 12 byte header
marks['badtype'] = m(udpcp(mtype=3, mid=9, data=b'xx'), C, S)
marks['short'] = m(b'\0\0\0\0\x48\0\1\0\0\1', C, S)
# fix reproducer (batch 37): Exported PDU without addresses and ports, so no
# conversation exists before UDPCP creates one
marks['noconv'] = len(main) + 1
main.append(exppdu(udpcp(mid=1, data=b'<a/>')))
marks['noconv2'] = len(main) + 1
main.append(exppdu(udpcp(mtype=2, n=1, s=1, mid=1)))
write('udpcp-coverage.pcap', main, 252)

# ---- malformed capture -------------------------------------------------
D = (bytes([192, 0, 2, 3]), 6001)
mal = []
def x(p, a, b):
    mal.append(ex(p, a, b))
x(udpcp(mid=0), D, S)
x(udpcp(mid=1, res=0x15, data=b'<a/>'), D, S)                    # reserved bits
x(udpcp(mid=2, csum=0xdeadbeef, data=b'<a/>'), D, S)             # checksum without C
x(udpcp(mid=3, data=b'<a/>', dlen=9), D, S)                      # data length too large
x(udpcp(mid=4, dlen=2, data=b'<b/>'), D, S)                      # data length too small
x(udpcp(mtype=2, n=1, s=1, mid=4), S, D)
x(udpcp(mid=5, d=1, data=b'<a/>'), D, S)                         # D set on data
x(udpcp(mtype=2, mid=5), S, D)                                   # ACK without N and S
x(udpcp(mtype=2, n=1, mid=6), S, D)                              # ACK with N only
x(udpcp(mtype=2, s=1, mid=6), S, D)                              # ACK with S only
x(udpcp(mtype=2, n=1, s=1, mid=77), S, D)                        # ACK for a frame never seen
x(udpcp(mid=9, data=b'<a/>'), D, S)                              # SN jump: 9 where 6 is expected, no ACK
x(udpcp(mid=10, data=b'<a/>'), D, S)
x(udpcp(mid=2, data=b'<a/>'), D, S)                              # SN goes backwards
h = b'<x>' + b'q' * 20 + b'</x>'
x(udpcp(mid=11, famt=2, fnum=0, n=1, dlen=len(h) + 3, data=h[:12]), D, S)
x(udpcp(mid=11, famt=2, fnum=1, s=1, dlen=len(h) + 3, data=h[12:]), D, S)   # reassembled, wrong size
x(udpcp(mid=12, famt=2, fnum=0, n=1, dlen=40, data=h[:12]), D, S)
x(udpcp(mid=12, famt=2, fnum=0, n=1, dlen=40, data=h[:12]), D, S)           # same fragment again
x(udpcp(mid=12, famt=2, fnum=1, s=1, dlen=40, data=h[12:]), D, S)
x(udpcp(mid=13, famt=1, fnum=0, dlen=4, data=b'<a/>'), S, D)                # reverse direction data
x(udpcp(mid=14, famt=1, fnum=0, dlen=4, data=b'<a/>'), S, D)
# a UDPCP header cut after 11 octets is not UDPCP
x(udpcp(mid=1, data=b'')[:11], D, S)
write('udpcp-coverage-malformed.pcap', mal, 252)


# ---- Ethernet / IPv4 / UDP, needs Decode As -----------------------------
def csum16(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(src, dst, sp, dp, payload):
    udp = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum16(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp

e = []
A, B = C[0], S[0]
e.append(eth(A, B, 6000, 5000, udpcp(mid=0)))
e.append(eth(A, B, 6000, 5000, udpcp(mid=1, famt=2, fnum=0, dlen=8, data=b'<a>x')))
e.append(eth(A, B, 6000, 5000, udpcp(mid=1, famt=2, fnum=1, dlen=8, data=b'y</a>')))
e.append(eth(B, A, 5000, 6000, udpcp(mtype=2, n=1, s=1, mid=1)))
e.append(eth(A, B, 6000, 5000, udpcp(mid=2, data=b'<b/>')))
e.append(eth(A, B, 6000, 5000, udpcp(mid=7, data=b'<b/>')))
e.append(eth(B, A, 5000, 6000, udpcp(mid=0, data=b'<c/>')))
write('udpcp-coverage-udp.pcap', e, 1)

if VERBOSE:
    print(marks)
    print('main', len(main), 'malformed', len(mal), 'udp', len(e))

# Generates test/captures/simulcrypt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# --- pcap helpers (synthetic addresses only) ---
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64, flags_frag=0, options=b''):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ihl = 5 + len(options) // 4
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags_frag, ttl, proto, 0, s, d) + options
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]

def eth(payload, ethertype=0x0800, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst) + u)

def tcp(sport, dport, payload, seq=1, ack=1, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst) + t)

def ipv6(nxt, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)

def write(fn, pkts, linktype=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def exported_pdu(name, payload, tag=12):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', tag, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

class Flow:
    '''TCP connection with a handshake and tracked sequence numbers.'''
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', cisn=1000, sisn=5000, hs=False):
        self.cp, self.sp, self.c, self.s = cport, sport, client, server
        self.cseq, self.sseq = cisn, sisn
        self.pk = []
        if hs:
            self.pk.append(tcp(cport, sport, b'', self.cseq, 0, client, server, 0x02)); self.cseq += 1
            self.pk.append(tcp(sport, cport, b'', self.sseq, self.cseq, server, client, 0x12)); self.sseq += 1
            self.pk.append(tcp(cport, sport, b'', self.cseq, self.sseq, client, server, 0x10))
    def c2s(self, data):
        self.pk.append(tcp(self.cp, self.sp, data, self.cseq, self.sseq, self.c, self.s)); self.cseq += len(data)
    def s2c(self, data):
        self.pk.append(tcp(self.sp, self.cp, data, self.sseq, self.cseq, self.s, self.c)); self.sseq += len(data)

def tpkt(payload):
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload

def cotp_dt(payload, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + payload)

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body
# --- end helpers ---
# Generator for the SIMULCRYPT coverage captures: python3 mksimulcrypt.py <outdir>
# SIMULCRYPT has no port of its own: decode with
#   -d tcp.port==12345,simulcrypt -d udp.port==12346,simulcrypt
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def P(t, v=b''):
    if isinstance(v, int): v = bytes([v])
    return struct.pack('!HH', t, len(v)) + v

def M(mtype, *params, ver=3):
    body = b''.join(params)
    return struct.pack('!BHH', ver, mtype, len(body)) + body

def u16(v): return struct.pack('!H', v)
def s16(v): return struct.pack('!h', v)
def u32(v): return struct.pack('!I', v)

# MIKEY header without any payload (version 1, initiator pre-shared key
# message, last payload, no crypto sessions): no key material at all
MIKEY = bytes([1, 0, 0, 1]) + u32(0x01020304) + bytes([0, 0])
ACT = u16(2026) + bytes([11, 11, 5, 30, 15, 50])
SCAS = u32(0x99990001)      # CA_system_ID 0x9999 (MIKEY), subsystem 1
OTHER = u32(0x4aee0002)     # a CA_system_ID the dissector does not know

EC, SV = 12345, 40000      # ECMG port, client port
f = Flow(SV, EC)
main = []
# --- ECMG <-> SCS: channel and stream set-up with the MIKEY CA_system_ID
f.c2s(M(0x0001, P(0x000E, u16(1)), P(0x0001, OTHER), P(0x0002, 0)))
f.s2c(M(0x0003, P(0x000E, u16(1)), P(0x0002, 1), P(0x0003, s16(-50)), P(0x0004, s16(40)),
        P(0x0005, s16(-20)), P(0x0006, s16(30)), P(0x0016, s16(-5)), P(0x0017, s16(6)),
        P(0x0007, u16(100)), P(0x0008, u16(8)), P(0x0009, u16(20)), P(0x000A, 1),
        P(0x000B, 2), P(0x000C, u16(500))))
f.c2s(M(0x0101, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x0010, u16(50)),
        P(0x0011, 1), P(0x000D, b'\x01\x02\x03\x04\x05')))
f.s2c(M(0x0103, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x0001, OTHER), P(0x0010, u16(50)),
        P(0x0011, 0), P(0x1234, b'\xde\xad\xbe\xef')))
# CW provision with CP number/duration/CW combination, then the ECM response
# (the ECM datagram is shown as bytes: the CA_system_ID is not the MIKEY one)
f.c2s(M(0x0201, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x0012, u16(3)), P(0x0013, u16(10)),
        P(0x0014, u16(3) + b'\x11' * 8 + b'\x22' * 8), P(0x0018, b'\xaa\xbb\xcc'),
        P(0x000D, b'\x09\x08')))
f.s2c(M(0x0202, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x0012, u16(3)),
        P(0x0015, MIKEY), P(0x0019, u16(0x0102))))
# ECM datagram from a port that is not the ECMG port (UDP): shown as bytes only
main += f.pk
main.append(udp(12346, 40001, M(0x0202, P(0x000E, u16(2)), P(0x0015, b'\x01\x02\x03\x04'))))
f2 = Flow(SV + 2, EC, cisn=100, sisn=200)
f2.c2s(M(0x0004, P(0x000E, u16(1))))
f2.s2c(M(0x0005, P(0x000E, u16(1)), P(0x7000, u16(1)), P(0x7001, b'\x00\x01')))
f2.c2s(M(0x0104, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x000F + 0x10, b'')))   # zero length parameter
f2.s2c(M(0x0106, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x7000, u16(0x0011))))
f2.c2s(M(0x0002, P(0x000E, u16(1))))
f2.c2s(M(0x0102, P(0x000E, u16(1)), P(0x000F, u16(7))))
f2.s2c(M(0x0105, P(0x000E, u16(1)), P(0x000F, u16(7))))
main += f2.pk
# --- EMMG <-> MUX
e = Flow(SV + 3, EC, cisn=300, sisn=400)
e.c2s(M(0x0011, P(0x0001, u32(0x00010002)), P(0x0003, u16(1)), P(0x0002, 1), P(0x0006, u16(1000))))
e.s2c(M(0x0013, P(0x0003, u16(1)), P(0x0002, 0)))
e.c2s(M(0x0111, P(0x0001, u32(0x00010002)), P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x0007, 0),
        P(0x0006, u16(500))))
e.s2c(M(0x0113, P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x0006, u16(400)), P(0x0007, 1)))
e.c2s(M(0x0117, P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x0006, u16(600))))
e.s2c(M(0x0118, P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x0006, u16(300))))
e.c2s(M(0x0211, P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x0008, u16(9)),
        P(0x0005, bytes(range(1, 20))), P(0x0005, b'\x47\x00\x11'), P(0x4242, b'xyz')))
e.s2c(M(0x0015, P(0x0003, u16(1)), P(0x7000, u16(3)), P(0x7001, b'\x01\x02\x03')))
e.s2c(M(0x0116, P(0x0003, u16(1)), P(0x0004, u16(2)), P(0x7000, u16(2))))
e.c2s(M(0x0114, P(0x0003, u16(1)), P(0x0004, u16(2))))
e.s2c(M(0x0115, P(0x0003, u16(1)), P(0x0004, u16(2))))
e.c2s(M(0x0012, P(0x0003, u16(1))))
e.c2s(M(0x0014, P(0x0003, u16(1))))
main += e.pk
# --- EIS <-> SCS, with ECM_Group nesting up to the limit of four
def group(*inner): return P(0x0005, b''.join(inner))
ecm = group(P(0x0009, u16(5)), P(0x0008, OTHER), P(0x000A, b'\x01\x02\x03'),
            P(0x000B, ACT), P(0x000C, 1))
s = Flow(SV + 4, EC, cisn=500, sisn=600)
s.c2s(M(0x0401, P(0x0001, u16(1)), P(0x0002, 1), P(0x0003, 0), P(0x0004, u16(10))))
s.s2c(M(0x0403, P(0x0001, u16(1)), P(0x0002, 1), P(0x0003, 1), P(0x0004, u16(10))))
s.c2s(M(0x0408, P(0x0001, u16(1)), P(0x0006, u16(3)), P(0x0007, u32(77)), ecm,
        P(0x0016, u16(1)), P(0x000D, u16(2)), P(0x000E, u16(3)), P(0x000F, u16(4))))
s.s2c(M(0x040A, P(0x0001, u16(1)), P(0x0006, u16(3)), P(0x0010, 1), P(0x0011, u32(77)),
        P(0x0012, u32(78)), P(0x0013, 1), P(0x0014, u16(30)), P(0x0015, u16(40)), P(0x0008, OTHER),
        P(0x0777, b'\x01')))
s.c2s(M(0x0409, P(0x0001, u16(1)), P(0x0006, u16(3))))
s.s2c(M(0x040B, P(0x0001, u16(1)), P(0x7000, u16(0x0009)), P(0x7001, b'\x01\x02'),
        P(0x7002, b'bad SCG')))
s.c2s(M(0x040C, P(0x0001, u16(1))))
s.s2c(M(0x040D, P(0x0001, u16(1)), P(0x0006, u16(3)), P(0x0006, u16(4))))
s.c2s(M(0x0406, P(0x0001, u16(1))))
s.s2c(M(0x0405, P(0x0001, u16(1)), P(0x7000, u16(1))))
s.c2s(M(0x0402, P(0x0001, u16(1))))
s.c2s(M(0x0404, P(0x0001, u16(1))))
# ECM_Group nested three levels, then five levels (the fifth is reported and
# skipped), and the reproducer of the fixed unbounded recursion: nine levels
s.c2s(M(0x0408, group(P(0x0009, u16(1)), group(P(0x0009, u16(2)), group(P(0x0009, u16(3)))))))
def nest(n, inner=b''):
    for i in range(n): inner = group(inner)
    return inner
s.c2s(M(0x0408, nest(5, P(0x0009, u16(9)))))
s.c2s(M(0x0401 , nest(9)))
main += s.pk
# --- (P)SIG <-> MUX, MUX <-> CiM, (P)SIG <-> CiP and other message types
p = Flow(SV + 5, EC, cisn=700, sisn=800)
pp = P(0x000A, b'\x00\xb0\x0d\x00\x01\xc1\x00\x00') + P(0x000B, u32(1000))
p.c2s(M(0x0411, P(0x0001, 1), P(0x0002, u16(1)), P(0x0004, u16(2)), P(0x0005, u16(3)), P(0x0007, 1),
        P(0x0008, u16(16))))
p.s2c(M(0x0413, P(0x0002, u16(1)), P(0x0001, 2), P(0x0008, u16(16))))
p.c2s(M(0x0421, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x0001, 3), P(0x0006, u16(0x1fff)),
        P(0x0009, pp), P(0x0009, pp + pp), P(0x000C, ACT), P(0x000E, u16(100)), P(0x000F, u16(50)),
        P(0x0010, u16(20)), P(0x0011, u16(0x0100))))
p.s2c(M(0x0423, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x0001, 9), P(0x4001, b'??')))
p.c2s(M(0x0431, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x000D, b'\x01\x02\x03'),
        P(0x000A, b'\x42')))
p.c2s(M(0x0432, P(0x0002, u16(1))))
p.c2s(M(0x0441, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x000E, u16(10))))
p.s2c(M(0x0442, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x000E, u16(5))))
p.c2s(M(0x0443, P(0x0002, u16(1)), P(0x0003, u16(4)), P(0x000D, b'\x01\x02')))
p.s2c(M(0x0415, P(0x0002, u16(1)), P(0x7000, u16(2)), P(0x7001, b'\x00')))
p.s2c(M(0x0426, P(0x0002, u16(1)), P(0x7000, u16(1))))
# Interfaces without parameter tables: CP-SIG, user defined and reserved ranges
p.c2s(M(0x0311, P(0x0001, b'\x01\x02'), P(0x0002, b'abc')))
p.c2s(M(0x8001, P(0x0001, b'\x01')))
p.c2s(M(0x0599, P(0x0001, b'\x01')))
main += p.pk
# Two messages in one TCP segment, and one split over two segments
r = Flow(SV + 6, EC, cisn=900, sisn=1000)
r.c2s(M(0x0002, P(0x000E, u16(4))) + M(0x0102, P(0x000E, u16(4)), P(0x000F, u16(5))))
big = M(0x0201, P(0x000E, u16(4)), P(0x0014, b'\x00' * 40))
r.c2s(big[:20]); r.c2s(big[20:])
main += r.pk
write(os.path.join(outdir, 'simulcrypt-coverage.pcap'), main)

# Malformed capture: truncated parameters and values that are too short
bad = Flow(SV + 7, EC, cisn=1, sisn=2)
bad.c2s(struct.pack('!BHH', 3, 0x0001, 12) + P(0x000E, b'\x00\x01') + b'\x00\x0d\x00\x20')     # length past end
bad.c2s(M(0x0001, P(0x000E, b'\x01')))                       # one octet where two are needed
bad.c2s(M(0x0001, P(0x0001, b'\x99\x99')))                   # SuperCAS ID too short
bad.c2s(M(0x0408, P(0x000B, b'\x07\xea\x0b')))               # activation time too short
bad.c2s(M(0x0009, struct.pack('!HH', 0x000D, 0x7fff) + b'x'))
bad.c2s(M(0x0421, P(0x0009, b'\x00\x0a\x00')))               # truncated table/period pair
bad.c2s(M(0x0401, P(0x0005, b'\x00\x01\x00\x08\x00\x01')))   # truncated ECM group
bad.c2s(M(0x0211, P(0x0001, b'\x00\x01')))
write(os.path.join(outdir, 'simulcrypt-coverage-malformed.pcap'), bad.pk)

# MIKEY capture: the ECMG port is learned from a SuperCAS ID with the MIKEY
# CA_system_ID (0x9999) on the first pass only; it then takes the ECM
# datagrams of the ECMG for MIKEY. A second pass (tshark -2, redissection)
# starts from a reset table, so it differs from the first (see the README).
k = Flow(SV + 8, EC, cisn=1, sisn=2)
k.c2s(M(0x0001, P(0x000E, u16(1)), P(0x0001, SCAS), P(0x0002, 0)))
k.s2c(M(0x0202, P(0x000E, u16(1)), P(0x000F, u16(7)), P(0x0012, u16(3)), P(0x0015, MIKEY)))
k.s2c(M(0x0202, P(0x000E, u16(1)), P(0x0015, b'\x01\x00')))
k.c2s(M(0x0408, group(P(0x0009, u16(5)), P(0x0008, SCAS))))
write(os.path.join(outdir, 'simulcrypt-coverage-mikey.pcap'), k.pk)

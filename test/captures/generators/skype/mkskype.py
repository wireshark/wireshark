# Generates test/captures/skype_coverage.pcap.gz
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
# Generator for the SKYPE coverage captures: python3 mkskype.py <outdir>
# The UDP heuristic (skype_udp) is disabled by default: use
#   --enable-heuristic skype_udp -d udp.port==40002,skype -d tcp.port==40003,skype
# UDP port 40001 is reached by the heuristic (message types 0, 2, 3, 5, 7,
# 0xd and 0xf), 40002 and TCP 40003 through Decode As (any type).
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def sk(mid, mtype, body=b'', unk=0):
    return struct.pack('!HB', mid, (unk << 4) | mtype) + body

def u32(v): return struct.pack('!I', v)
IP1, IP2 = bytes([198, 51, 100, 7]), bytes([203, 0, 113, 9])

pk = []
def hu(m, sport=50001, dport=40001, src='192.0.2.1', dst='192.0.2.2'):
    pk.append(udp(sport, dport, m, src, dst))

# heuristic: the six message types it accepts, forth and back (the
# conversation data is created by the first packet and found by the others)
hu(sk(0x1111, 0, b'\x01\x02\x03\x04\x05'))
hu(sk(0x1112, 2, u32(0xdeadbeef) + u32(0x12345678) + b'encrypted-looking-bytes'))
hu(sk(0x1113, 3, b'\x02' + u32(1) + u32(0x01020304) + u32(0x0a0b0c0d) + b'ffr data!'))
hu(sk(0x1114, 5, IP1 + IP2), sport=40001, dport=50001, src='192.0.2.2', dst='192.0.2.1')
hu(sk(0x1115, 7, IP2 + IP1))
hu(sk(0x1116, 0xd, b'audio audio audio'), sport=40001, dport=50001, src='192.0.2.2', dst='192.0.2.1')
hu(sk(0x1117, 0xf, b'\xf0\xf1\xf2'))
# the unknown nibble of the third octet is shown in the Info column
hu(sk(0x1118, 2, u32(1) + u32(2) + b'xx', unk=5))
hu(sk(0x1119, 5, IP1 + IP2, unk=0xf))
# not accepted by the heuristic: type 1, and only three octets
hu(sk(0x111a, 1, b'abc'))
hu(sk(0x111b, 2))
# Decode As on UDP 40002: every type, including the ones with no meaning
for t in range(16):
    body = {2: u32(7) + u32(8) + b'zz', 3: b'\x01' + u32(1) + u32(2) + u32(3) + b'q',
            5: IP1 + IP2, 7: IP2 + IP1}.get(t, bytes([t]) * 4)
    hu(sk(0x2000 + t, t, body), sport=50002, dport=40002)
# the same conversation again (existing conversation data), reversed
hu(sk(0x2100, 5, IP2 + IP1), sport=40002, dport=50002, src='192.0.2.2', dst='192.0.2.1')
# TCP, Decode As: the type is not decoded
f = Flow(50003, 40003)
f.c2s(b'\x00\x01\x02\x03\x04\x05\x06\x07')
f.s2c(b'skype over tcp, not decoded')
pk += f.pk
write(os.path.join(outdir, 'skype-coverage.pcap'), pk)

# Malformed: bodies that are too short for their type under Decode As
m = []
def mu(b): m.append(udp(50004, 40002, b))
mu(sk(0x3000, 2, b'\x01\x02'))               # IV and CRC truncated
mu(sk(0x3001, 3, b'\x01\x00\x00'))           # FFR truncated
mu(sk(0x3002, 5, IP1))                       # NAT info, destination missing
mu(sk(0x3003, 7, b''))                       # NAT repeat, no addresses
mu(b'\x30\x01')                              # shorter than the three octet header
write(os.path.join(outdir, 'skype-coverage-malformed.pcap'), m)

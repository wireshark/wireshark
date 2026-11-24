# Generates test/captures/simple_coverage.pcap.gz
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
# Generator for the SIMPLE coverage captures: python3 mksimple.py <outdir>
# SIMPLE (STANAG 5602) has no port of its own: Decode As, here
#   -d udp.port==4321,simple -d tcp.port==4322,simple
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def simple(ptype, body=b'', seq=1, src=(1, 4), dst=(129, 6), transit=0x0102, sync=b'\x49\x36',
           length=None, psize=None, bad_sum=False):
    ln = 14 + len(body) + 2 if length is None else length
    ps = (len(body) + 8) // 2 if psize is None else psize
    hdr = sync + struct.pack('<HHBBBBBBH', ln, seq, src[0], src[1], dst[0], dst[1], ps, ptype, transit)
    pkt = hdr + body
    s = sum(pkt[:max(ln - 2, 0)]) & 0xffff
    if bad_sum: s ^= 0x5a5a
    return pkt + struct.pack('<H', s)

def word(fmt, label=0, sub=0, mli=0, cont=0, rest=b'\x11\x22\x33\x44\x55\x66\x77\x88'):
    if fmt == 0: w = fmt | (label << 2) | (sub << 7) | (mli << 10)
    elif fmt == 1: w = fmt | (cont << 2)
    else: w = fmt
    return struct.pack('<H', w) + rest

def link16(subtype, words, wc=None, stn=0o12345, net=3, rc=1, ssc2=2, npg=0x1234, ssc1=0x4321, loop=0x77):
    if wc is None: wc = 5 * len(words)
    return struct.pack('<BBBBHHHHH', subtype, rc, net, ssc2, npg, ssc1, stn, wc, loop) + b''.join(words)

def status(name=b'NODE-ALPHA', link16_host=1, link11_host=1, pu=0o17, stn=0o4321):
    return (b'\x01\x1e' + name.ljust(10, b'\0') + bytes([13, 77, 30, 45, 4, 1]) + bytes(range(16)) +
            struct.pack('<H', 0x7f) + b'FILE0001' + b'\0\0' + bytes([4, 1, 2, link16_host]) +
            struct.pack('<H', stn) + b'\0\0' + bytes([2, 1, pu, link11_host]) + b'\0' * 4)

pk = []
def U(m, dport=4321, sport=3000): pk.append(udp(sport, dport, m))
# Link 16: fixed format with initial, extension, continuation and "other" words
U(simple(1, link16(2, [word(0, 3, 2, 1), word(2), word(1, cont=5), word(3)])))
U(simple(1, link16(2, [word(0, 7, 0, 2)], stn=0o77777)), sport=3001)
U(simple(1, link16(0, [])))                               # uncoded free text: no words
U(simple(1, link16(1, [b'\x41' * 10])))                   # coded free text
# status
U(simple(61, status()))
U(simple(61, status(b'N', link16_host=0, link11_host=0)))
# other packet types are shown by name only; unknown and plain types
for t in (2, 3, 4, 5, 8, 10, 13, 20, 32, 62, 63, 65, 66, 100, 99, 0):
    U(simple(t, b'\x00\x01\x02\x03\x04\x05\x06\x07', seq=t))
# node and subnode names (unicast, broadcast, multicast, adjacent, unknown)
for src, dst in (((1, 1), (129, 2)), ((128, 4), (160, 5)), ((168, 6), (169, 7)), ((170, 202), (200, 203)),
                 ((10, 204), (11, 205)), ((12, 206), (13, 207)), ((14, 208), (15, 209)), ((16, 210), (17, 211)),
                 ((0, 0), (255, 255))):
    U(simple(63, b'\0' * 8, src=src, dst=dst))
# TCP, one message per segment
f = Flow(5000, 4322)
f.c2s(simple(1, link16(2, [word(0, 3, 2, 1), word(1, cont=1)])))
f.s2c(simple(61, status(b'TCP-NODE')))
pk += f.pk
write(os.path.join(outdir, 'simple-coverage.pcap'), pk)

# Malformed capture: bad sync bytes, length, packet size and checksum
m = []
def M(x): m.append(udp(3000, 4321, x))
M(simple(63, b'\0' * 8, sync=b'\x00\x00'))
M(simple(63, b'\0' * 8, sync=b'\x49\x00'))
M(simple(63, b'\0' * 8, length=15))
M(simple(63, b'\0' * 8, length=600))
M(simple(63, b'\0' * 8, length=200))
M(simple(63, b'\0' * 8, psize=0))
M(simple(63, b'\0' * 8, psize=200))
M(simple(63, b'\0' * 8, bad_sum=True))
M(simple(1, link16(2, [word(0, 3, 2, 1)], wc=15)))           # more words than present
M(simple(61, status()[:30]))                                   # truncated status
M(simple(63, b'')[:10])                                        # truncated header
M(simple(63, b'\0' * 8, length=14))                            # checksum position inside the header
M(simple(63, b'\0' * 8, length=2))
write(os.path.join(outdir, 'simple-coverage-malformed.pcap'), m)

#!/usr/bin/env python3
# Generates test/captures/omron_fins_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OMRON FINS coverage captures.  Usage: mkomron-fins.py <outdir>
Writes omron-fins-coverage.pcap (valid traffic: FINS over UDP 9600 and
FINS/TCP on TCP 9600, both registered by default) and
omron-fins-coverage-malformed.pcap (paths only malformed or unexpected input
reaches).  Everything is synthetic."""
import struct
import sys
import os

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_ip(proto, payload, src, dst):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), 1, 0, 64, proto, 0, s, d)
    ip = ip[:10] + struct.pack('!H', ip_csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + payload

class Cap:
    def __init__(self): self.pkts = []
    def add(self, p): self.pkts.append(p)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

C, S = '192.0.2.1', '192.0.2.2'

def udp(cap, sport, dport, data, fromclient=True):
    a, b = (C, S) if fromclient else (S, C)
    cap.add(eth_ip(17, struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data, a, b))

class Tcp:
    def __init__(self, cap, cport, sport):
        self.cap, self.cp, self.sp = cap, cport, sport
        self.cseq, self.sseq = 1000, 5000
    def seg(self, fromclient, data, flags=0x18):
        if fromclient:
            sp, dp, seq, ack, a, b = self.cp, self.sp, self.cseq, self.sseq, C, S
        else:
            sp, dp, seq, ack, a, b = self.sp, self.cp, self.sseq, self.cseq, S, C
        if flags == 0x02: ack = 0
        h = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)
        self.cap.add(eth_ip(6, h + data, a, b))
        n = len(data) + (1 if flags & 3 else 0)
        if fromclient: self.cseq += n
        else: self.sseq += n
    def handshake(self):
        self.seg(True, b'', 0x02); self.seg(False, b'', 0x12); self.seg(True, b'', 0x10)
    def c(self, d): self.seg(True, d)
    def s(self, d): self.seg(False, d)

u8 = lambda v: struct.pack('!B', v)
u16 = lambda v: struct.pack('!H', v)
u32 = lambda v: struct.pack('!I', v)

def fins(cmd, resp, payload, icf=None, dna=0, da1=0x0a, da2=0, sna=0, sa1=0x0b, sa2=0, sid=1, rsv=0, gct=2):
    if icf is None:
        icf = 0xc0 if resp else 0x80
    return bytes([icf, rsv, gct, dna, da1, da2, sna, sa1, sa2, sid]) + u16(cmd) + payload

def pat(n, seed=0):
    return bytes((0x30 + seed + i * 7) & 0xff for i in range(n))
def txt(n, seed=0):                      # printable
    return bytes(0x41 + ((seed + i) % 26) for i in range(n))

# (command, kind, length, response code or None).  'c' = command data of that
# length, 'r' = response data (2 octet response code first).  Every length is
# one the decoder consumes exactly; the loops take their item sizes.
T = []
def add(cmd, kind, *lens):
    for n in lens: T.append((cmd, kind, n))
add(0x0101, 'c', 6);  add(0x0101, 'r', 2, 3, 6)
add(0x0102, 'c', 7, 10); add(0x0102, 'r', 2)
add(0x0103, 'c', 8); add(0x0103, 'r', 2)
add(0x0105, 'c', 10); add(0x0105, 'r', 2)
add(0x0201, 'c', 6); add(0x0201, 'r', 8, 12)
add(0x0202, 'c', 6, 10); add(0x0202, 'r', 2)
add(0x0203, 'c', 6, 10); add(0x0203, 'r', 2)
add(0x0220, 'c', 8); add(0x0220, 'r', 3, 11, 19)
add(0x0221, 'c', 9, 17, 25); add(0x0221, 'r', 2)
add(0x0304, 'c', 15); add(0x0304, 'r', 2)
add(0x0305, 'c', 15); add(0x0305, 'r', 2)
add(0x0306, 'c', 8); add(0x0306, 'r', 10, 14)
add(0x0307, 'c', 8, 12); add(0x0307, 'r', 10)
add(0x0308, 'c', 3); add(0x0308, 'r', 2)
add(0x0401, 'c', 3, 2); add(0x0401, 'r', 2)
add(0x0402, 'c', 0); add(0x0402, 'r', 2)
add(0x0403, 'c', 0)
add(0x0501, 'c', 1); add(0x0501, 'r', 94, 69, 161)
add(0x0502, 'c', 1, 2); add(0x0502, 'r', 24, 45, 66)
add(0x0601, 'c', 0); add(0x0601, 'r', 28)
add(0x0602, 'c', 0); add(0x0602, 'r', 108)
add(0x0603, 'c', 0); add(0x0603, 'r', 16)
add(0x0620, 'c', 1); add(0x0620, 'r', 2, 14)
add(0x0701, 'c', 0); add(0x0701, 'r', 9)
add(0x0702, 'c', 5, 7); add(0x0702, 'r', 2)
add(0x0801, 'c', 0, 5); add(0x0801, 'r', 5)
add(0x0802, 'c', 0); add(0x0802, 'r', 4)
add(0x0803, 'c', 0, 5)
add(0x0920, 'c', 2); add(0x0920, 'r', 2, 20, 4, 36, 68)
add(0x0C01, 'c', 2); add(0x0C01, 'r', 2, 5)
add(0x0C02, 'c', 2); add(0x0C02, 'r', 2)
add(0x0C03, 'c', 2); add(0x0C03, 'r', 2)
add(0x2101, 'c', 2); add(0x2101, 'r', 2)
add(0x2102, 'c', 4); add(0x2102, 'r', 8, 18, 28)
add(0x2103, 'c', 0); add(0x2103, 'r', 2)
add(0x2201, 'c', 6); add(0x2201, 'r', 50, 70, 90)
add(0x2202, 'c', 20); add(0x2202, 'r', 12, 16)
add(0x2203, 'c', 22, 26); add(0x2203, 'r', 2)
add(0x2204, 'c', 2); add(0x2204, 'r', 2)
add(0x2205, 'c', 16, 28, 40); add(0x2205, 'r', 4)
add(0x2206, 'c', 4, 16); add(0x2206, 'r', 2)
add(0x2207, 'c', 28); add(0x2207, 'r', 2)
add(0x2208, 'c', 26); add(0x2208, 'r', 2)
add(0x2209, 'c', 14); add(0x2209, 'r', 2)
add(0x220A, 'c', 22); add(0x220A, 'r', 4)
add(0x220B, 'c', 22); add(0x220B, 'r', 4)
add(0x220C, 'c', 26); add(0x220C, 'r', 6)
add(0x220F, 'c', 3); add(0x220F, 'r', 9, 11, 13)
add(0x2210, 'c', 2); add(0x2210, 'r', 5, 6)
add(0x2211, 'c', 5, 8); add(0x2211, 'r', 2)
add(0x2301, 'c', 8, 14, 20); add(0x2301, 'r', 2)
add(0x2302, 'c', 0); add(0x2302, 'r', 2)
add(0x230A, 'c', 6); add(0x230A, 'r', 9, 12)
add(0x2601, 'c', 1, 8); add(0x2601, 'r', 2)
add(0x2602, 'c', 0); add(0x2602, 'r', 2)
add(0x2603, 'c', 0); add(0x2603, 'r', 3, 10)

MEMCODES = (0x00, 0x1B, 0x30, 0x72, 0x82, 0xB0, 0xBC, 0xC0, 0xF2)    # one octet, two octets, four octets

def payload(cmd, kind, n, seed):
    if kind == 'r':
        rc = ((seed % 5) << 8) | (seed % 7) if seed % 3 else 0
        body = pat(n - 2, seed) if n >= 2 else b''
        if cmd in (0x0C01, 0x2201) and n >= 30:
            body = body[:12] + txt(12, seed)[:0] + body[12:]
        return u16(rc)[:n] + body
    return pat(n, seed)

def build_main():
    cap = Cap()
    seed = 0
    # sport/dport: FINS over UDP 9600 on both sides
    for cmd, kind, n in T:
        seed += 1
        if cmd == 0x0104:
            continue
        p = payload(cmd, kind, n, seed)
        if cmd == 0x0101 and kind == 'c':
            p = b'\x82\x01\x02\x00\x00\x05'           # DM258, 5 items: shown in the info column
        if cmd == 0x0920 and kind == 'c':
            p = u16(0x8003)
        gw = seed % 4
        hdr = dict(dna=(0, 1, 0x7f, 0x80)[gw], da1=(0x0a, 0x3e, 0x3f, 0xff)[gw], da2=(0, 0xfe, 0x10, 0x20)[gw],
                   sna=(0, 2, 0x7f, 0x80)[(gw + 1) % 4], sa1=(0x0b, 0x7e, 0x3f, 0xff)[(gw + 1) % 4], sa2=(0, 0xfe, 0x1f, 0x30)[(gw + 1) % 4],
                   sid=seed & 0xff)
        if gw == 0: hdr['icf'] = 0xc1 if kind == 'r' else 0x81
        elif gw == 2: hdr['icf'] = 0xfe if kind == 'r' else 0xbe        # reserved bits set
        data = fins(cmd, kind == 'r', p, **hdr)
        if kind == 'c':
            udp(cap, 49800, 9600, data)
        else:
            udp(cap, 9600, 49800, data, False)
    # message read / clear and FAL/FALS read of 0x0920 (the command data decides)
    udp(cap, 49803, 9600, fins(0x0920, False, u16(0x0003)))
    udp(cap, 49803, 9600, fins(0x0920, False, u16(0xc001)))
    # multiple read (0x0104)
    cmd = 0x0104
    udp(cap, 49800, 9600, fins(cmd, False, b'\x82\x00\x10\x00' + b'\xb0\x00\x20\x00' + b'\x00\x00\x01\x05' + b'\x55\x00\x01\x00'))
    udp(cap, 9600, 49800, fins(cmd, True, u16(0) + b'\x00\x01' + b'\x1b\x02' + b'\x82\x12\x34' + b'\xb0\x56\x78' + b'\xc0\x01\x02\x03\x04' + b'\xf2\x05\x06\x07\x08' + b'\x30\x09'), False)
    udp(cap, 9600, 49800, fins(cmd, True, u16(0) + b'\x84\x01\x02'), False)
    # memory area codes in the 0x0101 command address column, 0x0101 command with an unknown area
    for area in (0x82, 0x80, 0xb0, 0x31, 0x00, 0x99):
        udp(cap, 49801, 9600, fins(0x0101, False, bytes([area]) + u16(0x1234) + b'\x00' + u16(3)))
    # unknown memory area in a multiple read response (warning, rest not decoded)
    udp(cap, 9600, 49801, fins(0x0104, True, u16(0) + b'\x77\x01\x02\x03\x04'), False)
    # unknown command code (warning), a response to a command that has none (warning)
    udp(cap, 49802, 9600, fins(0x9999, False, b'\x01\x02'))
    udp(cap, 9600, 49802, fins(0x9999, True, b'\x00\x00'), False)
    udp(cap, 9600, 49802, fins(0x0403, True, u16(0)), False)
    udp(cap, 9600, 49802, fins(0x0803, True, u16(0)), False)
    # FINS/TCP on TCP 9600
    t = Tcp(cap, 49900, 9600)
    t.handshake()
    magic = b'FINS'
    def tcp_pdu(command, body=b'', err=0):
        return magic + u32(len(body) + 8) + u32(command) + u32(err) + body
    t.c(tcp_pdu(0, u32(0)))                          # node address data send (client)
    t.s(tcp_pdu(1, u32(5) + u32(10)))                # node address data send (server)
    t.c(tcp_pdu(2, fins(0x0101, False, b'\x82\x00\x64\x00\x00\x02')))
    t.s(tcp_pdu(2, fins(0x0101, True, u16(0) + b'\x12\x34\x56\x78'), ))
    t.c(tcp_pdu(2, fins(0x0501, False, b'\x00')))
    t.s(tcp_pdu(2, fins(0x0501, True, u16(0) + txt(20) + txt(20, 3) + txt(40, 5) + pat(12))))
    t.s(tcp_pdu(3, b'', err=0x20))                   # frame send error notification
    t.c(tcp_pdu(6, b''))                             # connection confirmation
    t.s(tcp_pdu(6, b'', err=0x1))
    t.c(tcp_pdu(4, b'\x01\x02\x03\x04'))             # unknown FINS/TCP command
    # two PDUs in one segment and a PDU split over two segments
    t.c(tcp_pdu(2, fins(0x0701, False, b'')) + tcp_pdu(2, fins(0x0601, False, b'')))
    big = tcp_pdu(2, fins(0x0102, False, b'\x82\x00\x00\x00\x00\x10' + pat(32)))
    t.c(big[:20]); t.c(big[20:])
    t.s(tcp_pdu(2, fins(0x0102, True, u16(0))))
    cap.write(os.path.join(sys.argv[1], 'omron-fins-coverage.pcap'))

def build_malformed():
    m = Cap()
    # UDP: shorter than 12 octets, RSV not 0 (not FINS)
    udp(m, 49810, 9600, b'\x80\x00\x02\x00\x0a\x00\x00')
    udp(m, 49810, 9600, fins(0x0101, False, b'\x82\x00\x01\x00\x00\x01', rsv=1))
    # commands with a data length that must be 0, and lengths the decoders do not
    # consume exactly ("Unexpected Length", reported as malformed)
    udp(m, 49810, 9600, fins(0x0402, False, b'\x01\x02'))
    udp(m, 49810, 9600, fins(0x0403, False, b'\x01'))
    udp(m, 49810, 9600, fins(0x0101, False, b'\x82\x00\x01\x00\x00\x01\xff'))
    udp(m, 49810, 9600, fins(0x0201, True, b'\x00\x00\x01'))
    udp(m, 49810, 9600, fins(0x2601, False, b'\x01' * 9))
    udp(m, 49810, 9600, fins(0x0801, True, b'\x00\x00'))
    udp(m, 49810, 9600, fins(0x0102, False, b'\x82\x00\x01\x00\x00\x01'))
    udp(m, 49810, 9600, fins(0x2210, True, b'\x00\x00\x00\x00'))
    # cut off in the header or the data (exceptions)
    udp(m, 49810, 9600, fins(0x0101, False, b'')[:11])
    udp(m, 49810, 9600, fins(0x0101, True, b''))
    udp(m, 49810, 9600, fins(0x0104, True, u16(0) + b'\x82'))
    udp(m, 49810, 9600, fins(0x0104, True, u16(0) + b'\xc0\x01\x02'))
    udp(m, 49810, 9600, fins(0x0501, True, u16(0) + pat(30)))
    udp(m, 49810, 9600, fins(0x2201, True, u16(0) + pat(60)))
    for cmd in (0x0102, 0x0220, 0x0920, 0x2301, 0x220F, 0x0C01):
        udp(m, 49810, 9600, fins(cmd, True, u16(0) + pat(7)))
        udp(m, 49810, 9600, fins(cmd, False, pat(5)))
    # FINS/TCP: bad magic, length smaller than the header, length beyond the data,
    # unknown command, a FRAME SEND without room for a FINS header
    t = Tcp(m, 49910, 9600)
    t.handshake()
    t.c(b'XXXX' + u32(12) + u32(2) + u32(0) + b'\x80\x00\x02\x00')
    t.c(b'FINS' + u32(8) + u32(2) + u32(0))
    t.c(b'FINS' + u32(12) + u32(2) + u32(0) + b'\x80\x00\x02\x00')
    t.c(b'FINS' + u32(4000) + u32(2) + u32(0) + b'\x80\x00')
    m.write(os.path.join(sys.argv[1], 'omron-fins-coverage-malformed.pcap'))

if __name__ == '__main__':
    os.makedirs(sys.argv[1] if len(sys.argv) > 1 else '.', exist_ok=True)
    if len(sys.argv) < 2: sys.argv.append('.')
    build_main(); build_malformed()

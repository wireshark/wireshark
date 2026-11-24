#!/usr/bin/env python3
# Generates test/captures/nbifom_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- NBIFOM container in ESM messages (3GPP TS 24.161, 24.301 9.9.4.19) ----
# The dissector has no port or table entry of its own; it is called from
# the NAS-EPS dissector for the NBIFOM container IE (0x33) of an ESM
# message. The messages are plain NAS-EPS in GSMTAP (UDP 4729, LTE NAS,
# sub type "plain"). The direction (which parameters are valid) comes
# from the NAS message: Activate dedicated bearer accept / Modify bearer
# accept are uplink, Modify bearer request is downlink.
def gsmtap(nas):
    return struct.pack('!BBBBHBBIBBBB', 2, 4, 0x12, 0, 0, 0, 0, 1, 0, 0, 0, 0) + nas

def esm(msg, ies, ebi=5, pti=0, pre=b''):
    return gsmtap(bytes([(ebi << 4) | 0x02, pti, msg]) + pre + ies)

def nbifom_ie(params):
    c = b''.join(bytes([pid, len(pc)]) + pc for pid, pc in params)
    return bytes([0x33, len(c)]) + c

def rule(rid, access, op, prio, flags=0, fields=b'', spare=0):
    body = bytes([rid, (access << 6) | (spare << 3) | op, prio]) + struct.pack('!I', flags) + fields
    return bytes([len(body)]) + body

F_SRC4, F_DST4, F_SRC6, F_DST6, F_SPFX, F_DPFX, F_SPI, F_PROT = 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000
F_SSP, F_SEP, F_DSP, F_DEP, F_TOS, F_FL = 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000

ALL_FIELDS = (bytes([10, 1, 2, 3]) + bytes([10, 4, 5, 6]) + bytes(range(1, 17)) + bytes(range(17, 33))
              + bytes([64]) + bytes([128]) + struct.pack('!I', 0x12345678) + bytes([17])
              + struct.pack('!IIII', 1024, 2048, 80, 90) + bytes([0x2e]) + b'\x01\x02\x03')
ALL_FLAGS = F_SRC4 | F_DST4 | F_SRC6 | F_DST6 | F_SPFX | F_DPFX | F_SPI | F_PROT | F_SSP | F_SEP | F_DSP | F_DEP | F_TOS | F_FL

rules = [
    rule(1, 1, 1, 10, ALL_FLAGS, ALL_FIELDS),
    rule(2, 2, 2, 20),
    rule(3, 0, 3, 30, F_SRC4 | F_DST4, bytes([192, 168, 0, 1, 192, 168, 0, 2])),
    rule(4, 1, 4, 40, F_SRC6 | F_SPFX | F_DPFX, bytes(range(16)) + bytes([64, 48]), spare=5),
    rule(5, 2, 0, 50, F_DST6 | F_SPI | F_PROT, bytes(range(16)) + struct.pack('!I', 7) + bytes([6])),
    rule(6, 1, 1, 60, F_SSP | F_DSP | F_TOS | F_FL | 0x00c00000 | 0x0000ffff, struct.pack('!II', 1, 2) + bytes([0x10]) + b'\x00\x00\x2a'),
]

UL, DL = 0xc6, 0xc9
main = []
def add(msg, params, **kw):
    main.append(udp(A, B, 4729, 4729, esm(msg, nbifom_ie(params), **kw)))

# --- uplink (Activate dedicated EPS bearer context accept, Modify EPS bearer context accept)
add(UL, [(1, b'\x01')])
add(UL, [(1, b'\x02'), (2, b'\x01'), (3, b'\x00')])
add(0xca, [(2, b'\x02'), (3, b'\x1a')])
for st in (0x22, 0x25, 0x39, 0x3a, 0x3f, 0x6f, 0x82, 0x55):
    add(UL, [(3, bytes([st]))])
add(UL, [(4, b''.join(rules))])
add(UL, [(5, rules[0] + rules[1])])                     # IP flow mapping, decoded as routing rules
add(UL, [(4, rules[2]), (5, rules[3] + rules[4] + rules[5])])
add(UL, [(6, b'\x01')])                                 # RAN rules handling is downlink only
add(UL, [(7, b'\x01')]); add(UL, [(7, b'\x02')]); add(UL, [(7, b'\x03')]); add(UL, [(7, b'\x09')])
for v in (0x00, 0x05, 0x0a, 0x0f, 0x1f, 0xf0):
    add(UL, [(8, bytes([v]))])
add(UL, [(0, b'\x01'), (9, b'\xaa\xbb')])               # parameters without a decoding
add(UL, [(1, b'\x01\xde\xad')])                         # more bytes than the parameter holds
add(UL, [(7, b'\x01\x00\x00')])
add(UL, [(2, b'\x01'), (7, b'\x02'), (8, b'\x05'), (3, b'\x00'), (4, rules[1])])
# the other uplink messages that carry the container
add(0xc7, [(3, b'\x1a')], pre=b'\x1a')                  # Activate dedicated bearer reject: ESM cause first
add(0xcb, [(3, b'\x22')], pre=b'\x1a')                  # Modify bearer reject

# --- downlink (Modify EPS bearer context request, Deactivate EPS bearer context request)
add(DL, [(1, b'\x01')])
add(DL, [(1, b'\x02'), (2, b'\x02'), (3, b'\x00')])
add(DL, [(2, b'\x01'), (3, b'\x82')])
add(DL, [(4, b''.join(rules))])
add(DL, [(5, b'\x01\x02\x03')])                          # IP flow mapping is uplink only
add(DL, [(6, b'\x01')]); add(DL, [(6, b'\x02')]); add(DL, [(6, b'\x07')])
add(DL, [(7, b'\x01')])                                 # uplink only
add(DL, [(8, b'\x05')])                                 # uplink only
add(DL, [(0, b''), (9, b'\x00')])
add(DL, [(6, b'\x01\x02')])
add(0xcd, [(1, b'\x02'), (6, b'\x02')], pre=b'\x24')    # Deactivate request: ESM cause first
add(DL, [(4, rules[3]), (6, b'\x01'), (2, b'\x01')], ebi=6, pti=7)

bad = []
def addb(msg, ie, **kw):
    bad.append(udp(A, B, 4729, 4729, esm(msg, ie, **kw)))
# parameters whose length reaches past the container, routing rules cut short or with flags that
# promise more fields than the rule holds
addb(UL, bytes([0x33, 4, 1, 9, 1, 1]))
addb(UL, bytes([0x33, 3, 4, 8, 1]))
addb(UL, nbifom_ie([(4, rules[0][:20])]))
addb(UL, nbifom_ie([(4, rule(1, 1, 1, 1, ALL_FLAGS, ALL_FIELDS[:30]))]))
addb(UL, nbifom_ie([(4, rules[2][:5])]))
addb(UL, nbifom_ie([(4, b'\x03\x01')]))
addb(DL, bytes([0x33, 2, 1, 1]))
addb(DL, bytes([0x33, 1, 6]))
addb(UL, bytes([0x33, 3, 8, 1]))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'nbifom-coverage.pcap'), main)
    gz(os.path.join(out, 'nbifom-coverage.pcap'))
    os.rename(os.path.join(out, 'nbifom-coverage.pcap.gz'), os.path.join(out, 'nbifom_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'nbifom-coverage-malformed.pcap'), bad)

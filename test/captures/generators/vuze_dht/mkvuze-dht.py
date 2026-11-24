#!/usr/bin/env python3
# Generates test/captures/vuze_dht_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-vuze-dht.c (Vuze/Azureus DHT, UDP 11273).
    mkvuze-dht.py <outdir>
Writes vuze-dht-coverage.pcap and vuze-dht-coverage-malformed.pcap

The FIND_VALUE reply tests has_values the wrong way round (the dissector
parses contacts when has_values is true, the protocol puts values there),
so the frames that make it parse contacts and values are in the malformed
capture, not in the main one.
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        if flags == 0x02: ack = 0
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 2 else b''
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

PING, PING_R, STORE, STORE_R, FNODE, FNODE_R, FVAL, FVAL_R, ERR, KB, KB_R = 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1036, 1037

def addr(ip='192.0.2.9', port=49001):
    if ':' in ip:
        a = socket.inet_pton(socket.AF_INET6, ip)
    else:
        a = socket.inet_aton(ip)
    return bytes([len(a)]) + a + struct.pack('!H', port)

def odd_addr(n=6, port=7):
    return bytes([n]) + b'\xaa' * n + struct.pack('!H', port)

def contact(ver=24, a=None):
    return bytes([1, ver]) + (a or addr())

def req_header(action, ver, tid=1, a=None):
    h = struct.pack('!QII', 0x8877665544332211, action, tid) + bytes([ver])
    if ver >= 14: h += bytes([0])                       # vendor id
    if ver >= 9: h += struct.pack('!I', 0)              # network id
    if ver >= 9: h += bytes([ver])                      # local protocol version
    h += a or addr('192.0.2.1', 49000)
    h += struct.pack('!IQ', 0x55, 1700000000000)         # instance id, time
    if ver >= 51: h += bytes([1])                       # flags (DHT sleeping)
    if ver >= 53: h += bytes([0])
    return h

def rep_header(action, ver, tid=1):
    h = struct.pack('!IIQ', action, tid, 0x8877665544332211) + bytes([ver])
    if ver >= 14: h += bytes([0])
    if ver >= 9: h += struct.pack('!I', 0)
    h += struct.pack('!I', 0x66)
    if ver >= 51: h += bytes([0])
    if ver >= 53: h += bytes([1])
    return h

def vivaldi():
    return bytes([1, 16]) + struct.pack('!ffff', 1.5, -2.25, 0.5, 0.125)

def other_coord(n=6):
    return bytes([2, n]) + bytes(range(n))

def coords(ver, items):
    # the dissector reads network coordinates for protocol versions >= 15 only
    if ver < 15: return b''
    return bytes([len(items)]) + b''.join(items)

def key(b):
    return bytes([len(b)]) + b

def value(ver, data=b'value', stats=False, orig=None):
    v = b''
    if ver >= 11:
        v += struct.pack('!I', 0 if stats else 1)
    if stats:
        return v + struct.pack('!IIIB', 3, 4096, 77, 2)
    v += struct.pack('!QH', 1700000000000, len(data)) + data
    v += contact(ver, orig)
    v += bytes([0x04, 48, 3])      # flags, life hours, replication factor
    return v

def vgroup(ver, values):
    return struct.pack('!H', len(values)) + b''.join(values)

def pkt(payload, sport=49000, dport=11273, from_client=True):
    return udp(sport, dport, payload, from_client)

def main(outdir):
    f = []
    for ver in (3, 6, 8, 9, 11, 14, 16, 22, 24, 51, 53):
        tid = ver
        # PING
        f.append(pkt(req_header(PING, ver, tid)))
        f.append(pkt(rep_header(PING_R, ver, tid) + (coords(ver, [vivaldi(), other_coord()]) if ver >= 10 else b''),
                     11273, 49000, False))
        # STORE: two keys, two value groups, one holding a STATS reply (needs value version)
        keys = key(b'\x01' * 20) + key(b'')
        body = (struct.pack('!I', 0x12345) if ver >= 7 else b'') + bytes([2]) + keys
        groups = vgroup(ver, [value(ver), value(ver, b'', orig=addr('2001:db8::5', 6881))]) + vgroup(ver, [value(ver, stats=True)] if ver >= 11 else [value(ver, b'x' * 9)])
        body += bytes([2]) + groups
        f.append(pkt(req_header(STORE, ver, tid) + body))
        f.append(pkt(rep_header(STORE_R, ver, tid) + ((bytes([2]) + b'\x00\x01') if ver >= 6 else b''), 11273, 49000, False))
        # FIND_NODE request and reply with contacts (IPv4, IPv6) and network coordinates
        f.append(pkt(req_header(FNODE, ver, tid) + key(b'\x02' * 20) + (struct.pack('!II', 3, 100000) if ver >= 22 else b'')))
        rep = rep_header(FNODE_R, ver, tid)
        if ver >= 7: rep += struct.pack('!I', 0xdeadbeef)
        if ver >= 12: rep += struct.pack('!I', 1)
        if ver >= 13: rep += struct.pack('!I', 250000)
        rep += coords(ver, [vivaldi()])
        rep += struct.pack('!H', 3) + contact(ver) + contact(ver, addr('2001:db8::7', 6881)) + contact(ver, odd_addr())
        f.append(pkt(rep, 11273, 49000, False))
        # FIND_VALUE request (every flag value) and the reply with contacts: has_values false
        for flg in (0, 1, 2, 4, 8, 0x10, 0x20):
            f.append(pkt(req_header(FVAL, ver, tid) + key(b'\x03' * 20) + bytes([flg, 32])))
        rep = rep_header(FVAL_R, ver, tid)
        if ver >= 6: rep += bytes([0])              # has_continuation
        rep += bytes([0]) + struct.pack('!H', 1) + contact(ver) + coords(ver, [vivaldi()] if ver >= 16 else [])
        f.append(pkt(rep, 11273, 49000, False))
        # ERROR replies: wrong address (IPv4 and IPv6), key blocked, unknown error
        f.append(pkt(rep_header(ERR, ver, tid) + struct.pack('!I', 1) + addr('198.51.100.1', 5000), 11273, 49000, False))
        f.append(pkt(rep_header(ERR, ver, tid) + struct.pack('!I', 1) + addr('2001:db8::99', 5001), 11273, 49000, False))
        f.append(pkt(rep_header(ERR, ver, tid) + struct.pack('!I', 2) + bytes([4]) + b'\x01\x02\x03\x04' + struct.pack('!H', 3) + b'sig', 11273, 49000, False))
        f.append(pkt(rep_header(ERR, ver, tid) + struct.pack('!I', 77), 11273, 49000, False))
        # KEY_BLOCK request; the reply (1037) and unknown actions are not decoded further
        f.append(pkt(req_header(KB, ver, tid) + struct.pack('!I', 0x777) + bytes([5]) + b'block' + struct.pack('!H', 4) + b'sig!'))
        f.append(pkt(rep_header(KB_R, ver, tid) + b'\x00\x01', 11273, 49000, False))
        f.append(pkt(req_header(1500, ver, tid) + b'unknown action body'))
        f.append(pkt(rep_header(1501, ver, tid) + b'unknown action body', 11273, 49000, False))
    # an IPv6 and an odd length local address in a request header
    f.append(pkt(req_header(PING, 24, 90, addr('2001:db8::1', 49000))))
    f.append(pkt(req_header(PING, 24, 91, odd_addr(8))))
    f.append(pkt(req_header(PING, 24, 92, odd_addr(0))))
    # the reproducer of "has_values" (FIND_VALUE reply, version 20, contacts, has_values false)
    rep = rep_header(FVAL_R, 20, 93) + bytes([0, 0]) + struct.pack('!H', 1) + contact(20) + b'\0'
    f.append(pkt(rep, 11273, 49001, False))
    write_pcap(os.path.join(outdir, 'vuze-dht-coverage.pcap'), f)

    m = []
    for ver in (5, 6, 11, 16, 24, 53):
        # has_values true with what the dissector parses (contacts, coordinates, diversification type, value group)
        rep = rep_header(FVAL_R, ver, 1)
        if ver >= 6: rep += bytes([1])
        rep += bytes([1]) + struct.pack('!H', 2) + contact(ver) + contact(ver, addr('2001:db8::3'))
        rep += coords(ver, [vivaldi()] if ver >= 16 else [])
        if ver >= 6: rep += bytes([2])
        rep += vgroup(ver, [value(ver), value(ver, stats=True) if ver >= 11 else value(ver, b'zz')])
        m.append(pkt(rep, 11273, 49000, False))
        # has_values true with what the protocol puts there (diversification type, value group)
        rep = rep_header(FVAL_R, ver, 2)
        if ver >= 6: rep += bytes([0])
        rep += bytes([1])
        if ver >= 6: rep += bytes([1])
        rep += vgroup(ver, [value(ver)])
        m.append(pkt(rep, 11273, 49000, False))
        # has_values false with contacts (the protocol), as in the main capture but cut short
        rep = rep_header(FVAL_R, ver, 3)
        if ver >= 6: rep += bytes([0])
        rep += bytes([0]) + struct.pack('!H', 3) + contact(ver)
        m.append(pkt(rep, 11273, 49000, False))
    # truncated headers and bodies
    full = req_header(STORE, 24, 5) + bytes([1]) + key(b'k' * 20) + bytes([1]) + vgroup(24, [value(24)])
    for cut in (3, 8, 13, 20, 30, 50, len(full) - 30, len(full) - 3):
        m.append(pkt(full[:cut]))
    full = rep_header(FNODE_R, 24, 6) + struct.pack('!IIII', 1, 2, 3, 4) + coords(24, [vivaldi()]) + struct.pack('!H', 2) + contact(24)
    for cut in (len(full) - 5, len(full) - 30):
        m.append(pkt(full[:cut], 11273, 49000, False))
    # counts larger than the data
    m.append(pkt(req_header(STORE, 24, 7) + struct.pack('!I', 1) + bytes([200]) + key(b'a'), 49000))
    m.append(pkt(rep_header(FNODE_R, 24, 8) + struct.pack('!IIIB', 1, 2, 3, 255) + vivaldi(), 11273, 49000, False))
    m.append(pkt(rep_header(FNODE_R, 24, 9) + struct.pack('!IIIBH', 1, 2, 3, 0, 65535) + contact(24), 11273, 49000, False))
    m.append(pkt(rep_header(ERR, 24, 10) + struct.pack('!I', 2) + bytes([200]) + b'ab', 11273, 49000, False))
    m.append(pkt(req_header(FVAL, 24, 11) + bytes([200]) + b'ab'))
    # value with a byte count larger than the data
    m.append(pkt(req_header(STORE, 24, 12) + struct.pack('!I', 1) + bytes([1]) + key(b'q') + bytes([1]) + struct.pack('!HIQH', 1, 1, 1, 60000) + b'abc'))
    # single byte packets: request/reply decision and the first fields
    m.append(pkt(b'\x80'))
    m.append(pkt(b'\x00'))
    write_pcap(os.path.join(outdir, 'vuze-dht-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

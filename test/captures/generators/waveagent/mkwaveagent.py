#!/usr/bin/env python3
# Generates test/captures/waveagent_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-waveagent.c (WaveAgent, UDP heuristic).
    mkwaveagent.py <outdir>
Writes waveagent-coverage.pcap and waveagent-coverage-malformed.pcap
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

def put(buf, off, fmt, *vals):
    need = off + struct.calcsize('!' + fmt)
    if len(buf) < need:
        buf.extend(b'\0' * (need - len(buf)))
    struct.pack_into('!' + fmt, buf, off, *vals)

def text(s, n):
    return s.encode().ljust(n, b'\0')[:n]

def wa(ctl, payload=b'', ver=3, seq=1, tok=0x1234, flow=7, capstatus=0x03000001, sig=0xcc, plen=None):
    h = bytearray(44 if ver >= 3 else 40)
    h[0] = sig
    h[4] = seq
    h[15] = 0xe2
    put(h, 16, 'I', 0x0F87C3A5 | ((1 << 28) if ver >= 3 else 0))
    put(h, 20, 'I', len(payload) if plen is None else plen)
    put(h, 24, 'I', tok + 1)
    put(h, 28, 'I', ctl)
    put(h, 32, 'I', tok)
    put(h, 36, 'I', flow)
    if ver >= 3:
        put(h, 40, 'I', capstatus)
    b = bytes(h) + payload
    return b.ljust(52, b'\0')

def pkt(payload, from_client=True, sport=40000, dport=40001):
    if from_client:
        return udp(sport, dport, payload, True)
    return udp(dport, sport, payload, False)

def wlan_stats(ssid='lab-ap', rssi=-55, noise=-90, phy=0x0f, auth=8, cipher=16):
    b = bytearray(64)
    b[0:6] = b'\x02\0\0\0\x00\x0a'
    b[8:40] = text(ssid, 32)
    put(b, 40, 'I', len(ssid))
    put(b, 44, 'i', rssi)
    put(b, 48, 'i', noise)
    put(b, 52, 'I', phy)
    put(b, 56, 'I', auth)
    put(b, 60, 'I', cipher)
    return bytes(b)

def bss(ssid, rates, bssid, chan=6, privacy=1, mode=0, tag_len=None):
    b = bytearray(148)
    b[0:32] = text(ssid, 32)
    b[36:36 + len(rates)] = rates
    put(b, 52, 'I', len(rates) if tag_len is None else tag_len)
    b[56:62] = bssid
    put(b, 62, 'H', 0x0431)
    put(b, 64, 'i', -40)
    put(b, 72, 'I', chan)
    put(b, 76, 'I', privacy)
    put(b, 80, 'I', mode)
    return bytes(b)

def ip_slot(v6=False):
    b = bytearray(24)
    put(b, 0, 'H', 10 if v6 else 2)
    put(b, 2, 'H', 16 if v6 else 4)
    if v6:
        b[8:24] = socket.inet_pton(socket.AF_INET6, '2001:db8::77')
    else:
        b[8:12] = socket.inet_aton('192.0.2.77')
    return bytes(b)

def if_info(if_type, v6=False):
    b = bytearray(340)
    put(b, 0, 'I', 1)
    put(b, 4, 'I', if_type)
    put(b, 8, 'I', 1)
    b[12:18] = b'\x02\0\0\0\x00\x0b'
    put(b, 20, 'I', 54000)
    b[24:152] = text('Intel(R) Wireless', 128) if if_type == 2 else text('Ethernet adapter', 128)
    if if_type == 2:
        b[156:156 + 64] = wlan_stats()
    b[252:276] = ip_slot(v6)
    b[284:288] = socket.inet_aton('192.0.2.1')
    b[308:312] = socket.inet_aton('192.0.2.254')
    b[332:336] = socket.inet_aton('192.0.2.53')
    return bytes(b)

def if_change(if_type, entries):
    b = bytearray(8 + 8 * 156)
    put(b, 0, 'I', 1)
    put(b, 4, 'I', if_type)
    for i in entries:
        o = 8 + i * 156
        put(b, o, 'I', 2 if if_type == 2 else 1)       # l2 status (non-zero: valid entry)
        put(b, o + 4, 'I', 2 + (i & 1))                  # l3 status
        put(b, o + 8, 'I', 54000 + i)
        if if_type == 2:
            b[o + 12:o + 76] = wlan_stats(ssid='ap%d' % i)
        put(b, o + 108, 'Q', 0x0102030405060700 + i)
        v6 = bool(i & 1)
        b[o + 116:o + 140] = ip_slot(v6)
    return bytes(b)

def stats(ver, base=1000):
    n = 4 + 436 if ver >= 3 else 4 + 368
    b = bytearray(n)
    o = 4 if ver < 3 else 0
    if ver < 3:
        put(b, 0, 'I', 0x02000001)
    put(b, o, 'I', 5)
    put(b, o + 4, 'I', 4)
    put(b, o + 8, 'I', 1)
    for i, off in enumerate(list(range(12, 132, 8)) + [124, 132]):
        pass
    for off in range(12, 140, 8):
        put(b, o + off, 'Q', base + off)
    for off in (284, 292, 300, 308, 316, 324, 356):
        put(b, o + off, 'Q', base + off)
    if ver >= 3:
        for off in range(364, 436, 8):
            put(b, o + off, 'Q', base + off)
    return bytes(b)

def caps(ver):
    n = 4 + 428 if ver >= 3 else 4 + 416
    b = bytearray(n)
    o = 4 if ver < 3 else 0
    if ver < 3:
        put(b, 0, 'I', 0x02000001)
    put(b, o, 'I', 0x1f)
    b[o + 4:o + 132] = text('WaveAgent-PC-01', 128)
    b[o + 136:o + 264] = text('bindtag-lab', 128)
    b[o + 268:o + 396] = text('WaveAgent 3.1.0.4', 128)
    b[o + 400:o + 404] = socket.inet_aton('192.0.2.200')
    put(b, o + 404, 'I', 3000)
    put(b, o + 408, 'I', 2)
    put(b, o + 412, 'I', 40001)
    if ver >= 3:
        put(b, o + 416, 'I', 0x3)
        put(b, o + 420, 'I', 2)
        put(b, o + 424, 'I', 0x3)
    return bytes(b)

def flow_setup(ver, mode=1, ep=2, cbr=1, combined=1):
    b = bytearray(4 + 48 if ver < 3 else 72)
    o = 0
    if ver < 3:
        put(b, 0, 'I', 77)
    put(b, 7, 'B', mode)
    put(b, 8, 'I', 40010)
    put(b, 12, 'I', 3)
    put(b, 16, 'I', 40011)
    b[24:28] = socket.inet_aton('192.0.2.2')
    put(b, 40, 'I', 46)
    put(b, 44, 'I', (cbr & 1) | ((combined & 1) << 1))
    if ver >= 3:
        put(b, 48, 'I', 1)
        put(b, 52, 'I', 0x55)
        put(b, 56, 'I', 1000)
        put(b, 60, 'I', 50)
        put(b, 64, 'I', 100000)
    return bytes(b)

def main(outdir):
    f = []
    fr = lambda *a, **k: f.append(pkt(wa(*a, **k), True))
    def add(msg, client=True):
        f.append(pkt(msg, client))
    # messages without a payload (the control word is shown only)
    for ctl in (0x01, 0x02, 0x03, 0x04, 0x08, 0x12, 0x20, 0x21, 0x22, 0x80, 0x84, 0x86, 0x87, 0x88, 0x89, 0x7777):
        add(wa(ctl))
        add(wa(ctl, ver=2, seq=2), False)
    # a frame with the 0xdd signature and a long payload length field
    add(wa(0x12, sig=0xdd, plen=0x10000))
    for ver in (3, 2):
        add(wa(0x11, struct.pack('!IIII', 1, 1400, 100000, 5000), ver=ver))
        add(wa(0x23, struct.pack('!III', 1, 0, 8), ver=ver))
        for ctl in (0x24, 0x25, 0x8a):
            add(wa(ctl, struct.pack('!I', 1), ver=ver))
        add(wa(0x26, struct.pack('!II', 1, 0x0001000b), ver=ver))
        # interface info response: WLAN and Ethernet, IPv4 and IPv6
        add(wa(0x30, if_info(2), ver=ver), False)
        add(wa(0x30, if_info(1, v6=True), ver=ver), False)
        wl = bytearray(if_info(2)); put(wl, 156 + 48, 'i', 0x7fffffff)      # noise floor not reported
        add(wa(0x30, bytes(wl), ver=ver), False)
        # interface change info response: some of the 8 slots in use
        add(wa(0x31, if_change(2, [0, 1, 5, 7]), ver=ver), False)
        add(wa(0x31, if_change(1, [2, 3]), ver=ver), False)
        add(wa(0x31, if_change(1, []), ver=ver), False)
        # OID response
        add(wa(0x32, struct.pack('!III', 1, 0x0001000b, 0) + text('oid value 12345', 1024), ver=ver), False)
        # stats, capabilities, reserve, flow setup, learning message, command responses
        add(wa(0x2f, stats(ver), ver=ver), False)
        add(wa(0x81, caps(ver), ver=ver), False)
        add(wa(0x82, text('bindtag-lab', 128) + b'\0\0\0\0' + socket.inet_aton('192.0.2.200') + struct.pack('!I', 3000), ver=ver))
        add(wa(0x85, flow_setup(ver, 1, 2, 1, 1), ver=ver))
        add(wa(0x85, flow_setup(ver, 2, 1, 0, 0), ver=ver))
        add(wa(0x85, flow_setup(ver, 3, 0, 1, 0), ver=ver))
        add(wa(0x8b, socket.inet_aton('192.0.2.5') + struct.pack('!II', 40020, 3), ver=ver))
        for ctl in (0x8f, 0x3f):
            add(wa(ctl, struct.pack('!II', 0, 0) + text('OK', 128), ver=ver), False)
            add(wa(ctl, struct.pack('!II', 1, 22) + text('Invalid argument', 128), ver=ver), False)
        add(wa(0x41, struct.pack('!II', 1, 3), ver=ver))
    # scan results response: the two entries of the reproducer (6/9/12 Mbit/s in the second),
    # the 0xff HT rate marker, no rates, a rates length over 16, 20 entries (limited to 8)
    ent = [bss('first', b'\x82\x84', b'\x02\0\0\0\0\x0a'), bss('second', b'\x0c\x12\x18', b'\x02\0\0\0\0\x0b'),
           bss('ht', b'\x8c\x12\x98\x24\xff', b'\x02\0\0\0\0\x0c'), bss('norates', b'', b'\x02\0\0\0\0\x0d'),
           bss('longrates', bytes(range(2, 26, 2)) * 2, b'\x02\0\0\0\0\x0e', tag_len=24)]
    for ver in (3, 2):
        add(wa(0x2e, struct.pack('!IIII', 1, 2, 2, 0) + ent[0] + ent[1], ver=ver), False)
    add(wa(0x2e, struct.pack('!IIII', 1, 5, 5, 0) + b''.join(ent), ver=3), False)
    add(wa(0x2e, struct.pack('!IIII', 1, 40, 20, 0) + b''.join((ent * 2)[:8]), ver=3), False)
    # client connect request: few BSSIDs, 16 BSSIDs (the maximum), more than 16 (limited)
    for nb in (0, 3, 16, 100):
        b = bytearray(158)
        put(b, 0, 'I', 1); put(b, 4, 'I', 0x5); put(b, 8, 'I', 1)
        b[12:44] = text('connect-ssid', 32)
        for i in range(min(nb, 16)):
            b[46 + 6 * i:52 + 6 * i] = bytes([2, 0, 0, 0, 1, i + 1])
        put(b, 142, 'I', nb)
        put(b, 146, 'i', -70); put(b, 150, 'I', 30); put(b, 154, 'I', 3)
        add(wa(0x40, bytes(b)))
    # relay message: relay ids, then a complete WaveAgent message (every inner payload type is
    # dissected the same way as at the top level)
    for inner_ctl, inner_pl, v in ((0x24, struct.pack('!I', 1), 3), (0x8f, struct.pack('!II', 0, 0) + text('relayed ok', 128), 3),
                                   (0x12, b'', 2)):
        inner = wa(inner_ctl, inner_pl, ver=v, tok=0x99)
        add(wa(0x3e, struct.pack('!III', 0x11, 0x22, 0) + inner, ver=v))
    write_pcap(os.path.join(outdir, 'waveagent-coverage.pcap'), f)

    m = []
    for ctl, pl in ((0x2e, struct.pack('!IIII', 1, 2, 2, 0) + ent[0]), (0x30, if_info(2)[:100]), (0x31, if_change(2, [0, 1])[:200]),
                    (0x2f, stats(3)[:200]), (0x81, caps(3)[:300]), (0x85, flow_setup(3)[:30]), (0x40, b'\0' * 60),
                    (0x32, b'\0' * 100), (0x8f, b'\0' * 20)):
        m.append(pkt(wa(ctl, pl).ljust(52, b'\0')))
    # relay message with a truncated inner header
    m.append(pkt(wa(0x3e, b'\0' * 20)))
    m.append(pkt(wa(0x3e, struct.pack('!III', 1, 2, 0) + wa(0x30, if_info(2))[:60])))
    # too short for the dissector (51 octets) and wrong signature/magic/end byte: not WaveAgent
    # (own port pairs, so that a heuristic match of another dissector does not stick)
    good = wa(0x12)
    for i, bad in enumerate((good[:51], bytes([0xaa]) + good[1:], good[:15] + b'\xe3' + good[16:],
                             good[:16] + b'\x0f\x87\xc3\xa6' + good[20:])):
        m.append(pkt(bad, sport=41000 + i, dport=42000 + i))
    write_pcap(os.path.join(outdir, 'waveagent-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

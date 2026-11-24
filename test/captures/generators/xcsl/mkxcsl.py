#!/usr/bin/env python3
# Generates test/captures/xcsl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: a minimal pcap writer and Ethernet/IPv4/TCP/UDP builders.
# Everything is synthetic: addresses are 10.0.0.x / 02:00:00:00:00:0x.
import os
import struct
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.pkts = []
        self.t = 0
    def add(self, data):
        self.t += 1
        self.pkts.append((self.t, bytes(data)))
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype))
            for t, p in self.pkts:
                f.write(struct.pack('<IIII', 1700000000 + t, 0, len(p), len(p)))
                f.write(p)
        return len(self.pkts)

def ip4(a):
    return bytes(map(int, a.split('.')))

MAC1 = b'\x02\0\0\0\0\x01'
MAC2 = b'\x02\0\0\0\0\x02'

def ip_packet(proto, src, dst, payload, ident=1):
    tot = 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload

def udp_frame(sip, dip, sport, dport, payload, smac=MAC1, dmac=MAC2):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return dmac + smac + b'\x08\x00' + ip_packet(17, sip, dip, udp)

class Tcp:
    """One TCP connection; frames are appended to a Pcap."""
    def __init__(self, pcap, cport, sport, cip='10.0.0.1', sip='10.0.0.2'):
        self.p = pcap
        self.c = (cip, cport, MAC1)
        self.s = (sip, sport, MAC2)
        self.seq = [1000, 5000]
    def _pkt(self, d, payload, flags=0x18, advance=None):
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        seq = self.seq[d]
        ack = self.seq[1 - d]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
        ph = ip4(src[0]) + ip4(dst[0]) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.seq[d] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.p.add(dst[2] + src[2] + b'\x08\x00' + ip_packet(6, src[0], dst[0], tcp + payload))
    def handshake(self):
        self._pkt(0, b'', 0x02)
        self._pkt(1, b'', 0x12)
        self._pkt(0, b'', 0x10)
    def c2s(self, payload):
        self._pkt(0, payload)
    def s2c(self, payload):
        self._pkt(1, payload)
    def fin(self):
        self._pkt(0, b'', 0x11)
        self._pkt(1, b'', 0x11)
        self._pkt(0, b'', 0x10)

def llc_frame(dsap, ssap, ctrl, payload=b'', smac=MAC1, dmac=MAC2):
    body = bytes([dsap, ssap]) + ctrl + payload
    return dmac + smac + struct.pack('!H', len(body)) + body

def outdir():
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(d, exist_ok=True)
    return d


# ---- XCSL over TCP (heuristic dissector, any port) ----
def build(outdir):
    p = Pcap()
    t = Tcp(p, 33001, 33002)
    t.handshake()
    # request with parameters, success reply
    t.c2s(b'xcsl-1.0;1000;offhook;+31356871234')
    t.s2c(b'xcsl-1.0;1000;0')
    t.c2s(b'xcsl-1.0;1001;dial;+31356871234;+31356875678;3')
    # every result code
    for code in range(1, 9):
        t.s2c(b'xcsl-1.0;1001;%d' % code)
    t.s2c(b'xcsl-1.0;1002;0;answer one;answer two;answer three')
    t.s2c(b'xcsl-1.0;1003;3;reason text;detail')
    # ';' after "xcsl" is accepted as well as '-'; CR LF ends an item
    t.c2s(b'xcsl;1004;hangup\r\n')
    t.c2s(b'xcsl-1.1;1005;status;line 1;line 2\r\nxcsl-1.1;1006;status\r\n')
    # a result of 9 or more is shown as Undefined; a result with trailing text
    t.s2c(b'xcsl-1.0;1007;9')
    t.s2c(b'xcsl-1.0;1008;77;x')
    t.s2c(b'xcsl-1.0;1009;7x;y')
    # a non-numeric transaction id is shown as information
    t.c2s(b'xcsl-1.0;info text;ping')
    t.s2c(b'xcsl-1.0;info text;0')
    # empty items are skipped (including a trailing ';')
    t.c2s(b'xcsl-1.0;;1010;;dial;;+31356871234;')
    t.s2c(b'xcsl-1.0;1010;;0;;done;')
    # only the version
    t.c2s(b'xcsl-1.0')
    # 256 parameters: the item counter is 8 bits wide and wraps
    t.c2s(b'xcsl-1.0;1011;bulk;' + b';'.join(b'p%d' % i for i in range(256)))
    # not XCSL: wrong separator, too short, wrong case
    t.c2s(b'xcsl+1.0;1012;x')
    t.c2s(b'xcs')
    t.c2s(b'XCSL-1.0;1013;x')
    t.fin()
    n = p.write(os.path.join(outdir, 'xcsl-coverage.pcap'))
    print('xcsl-coverage.pcap', n)

    m = Pcap()
    t = Tcp(m, 33003, 33004)
    t.handshake()
    t.c2s(b'xcsl-1.0;')
    t.c2s(b'xcsl-1.0;1;a\x00b;c')
    t.c2s(b'xcsl-1.0;1;\xff\xfe;\x80')
    t.c2s(b'xcsl-1.0;1;;;;;;;')
    n = m.write(os.path.join(outdir, 'xcsl-coverage-malformed.pcap'))
    print('xcsl-coverage-malformed.pcap', n)

if __name__ == '__main__':
    build(outdir())

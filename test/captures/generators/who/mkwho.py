#!/usr/bin/env python3
# Generates test/captures/who_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-who.c (rwho, UDP 513).
    mkwho.py <outdir>
Writes who-coverage.pcap and who-coverage-malformed.pcap
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
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
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

def whod(host, loads, entries, vers=1, typ=1, send=1700000000, recv=1700000001, boot=1699990000,
         fill=b'\0\0'):
    h = bytes([vers, typ]) + fill + struct.pack('!II', send, recv)
    h += host.ljust(32, b'\0')[:32] if len(host) < 32 else host[:32]
    h += struct.pack('!III', *loads) + struct.pack('!I', boot)
    for tty, user, on, idle in entries:
        h += tty.ljust(8, b'\0')[:8] + user.ljust(8, b'\0')[:8] + struct.pack('!II', on, idle)
    return h

def main(outdir):
    f = []
    # header only, no users
    f.append(udp(513, 513, whod(b'idlehost', (0, 0, 0), [])))
    # a few users, idle times: 0, seconds, minutes, hours, days, negative
    ent = [(b'ttyp0', b'alice', 1699999000, 0), (b'ttyp1', b'bob', 1699998000, 59),
           (b'ttyp2', b'carol', 1699997000, 3600 * 3 + 61), (b'console', b'root', 1699996000, 86400 * 2 + 5),
           (b'ttyq3', b'dave', 1699995000, 0xfffffff0), (b'pts/12', b'longuser', 0, 0x7fffffff)]
    f.append(udp(513, 513, whod(b'build1.example.net', (150, 275, 1000), ent)))
    # a version 0/type 0 packet and nonzero filler
    f.append(udp(513, 513, whod(b'oldhost', (1, 2, 3), ent[:1], vers=0, typ=0, fill=b'\xaa\xbb')))
    # name of exactly 32 bytes without a terminator, and 8 byte tty/user without NUL
    f.append(udp(513, 513, whod(b'h' * 32, (99999, 0, 4294967295), [(b'12345678', b'abcdefgh', 1, 1)])))
    # the maximum number of entries (1024/24 = 42)
    many = [(b'tty%02d' % i, b'user%d' % i, 1699000000 + i, i * 7) for i in range(42)]
    f.append(udp(513, 513, whod(b'busyhost', (500, 600, 700), many)))
    # more than the maximum: only the first 42 are shown, the rest is ignored
    f.append(udp(513, 513, whod(b'overfull', (1, 1, 1), many + many[:3])))
    # type 2 (reboot) packet from the server side, source port 513 reply
    f.append(udp(513, 513, whod(b'rebooted', (0, 0, 0), []), from_client=False))
    # a trailing partial entry stays unparsed? no: a partial entry is malformed (malformed capture)
    write_pcap(os.path.join(outdir, 'who-coverage.pcap'), f)

    m = [f[1]]
    full = whod(b'cuthost', (1, 2, 3), ent[:2])
    m.append(udp(513, 513, full[:-10]))        # second entry truncated
    m.append(udp(513, 513, full[:62]))         # header ends inside the boot time
    m.append(udp(513, 513, full[:30]))         # inside the host name
    m.append(udp(513, 513, full[:3]))          # inside the header
    write_pcap(os.path.join(outdir, 'who-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

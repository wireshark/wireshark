#!/usr/bin/env python3
# Generates test/captures/gopher_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Gopher dissector
(packet-gopher.c).  Everything is built with struct; nothing comes from a
real network.  Usage: mkgopher.py <output directory>

Writes:
  gopher-coverage.pcap            requests (directory list, selector,
                                  search) and responses (menus with every
                                  item type, plain text, lines without
                                  tabs) on TCP port 70
  gopher-coverage-malformed.pcap  Gopher has no exception paths reachable
                                  by default; this holds lines that stop
                                  the menu parser (too short, one or two
                                  tabs, long names)
"""
import os
import sys
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()


TYPES = '+0123456789ghiIsT'

def item(t, name, sel='/sel', host='gopher.example.org', port='70'):
    return ('%s%s\t%s\t%s\t%s\r\n' % (t, name, sel, host, port)).encode()

def build(path_main, path_bad):
    f = []
    A, B = '10.0.0.1', '10.0.0.2'
    n = 0
    def conv(request, response, cport):
        c = Flow(cport, 70, f, A, B)
        c.open()
        c.c2s(request)
        c.s2c(response)
        c.close()

    menu = b''.join(item(t, 'Item of type %s' % t, '/sel/%d' % i, 'host%d.example.org' % i, str(70 + i))
                    for i, t in enumerate(TYPES)) + b'.\r\n'
    conv(b'\r\n', menu, 41000)                                    # directory list
    conv(b'/docs/readme.txt\r\n', b'This is a text file.\r\nSecond line.\r\n.\r\n', 41001)
    conv(b'/search\tgopher protocol\r\n', item('0', 'Hit 1') + item('1', 'Hit 2', '', 'h.example', '7070') + b'.\r\n', 41002)
    conv(b'\n', item('i', 'Welcome', '', 'error.host', '1') + item('3', 'Not found', '', 'error.host', '1'), 41003)
    # the reproducers of the fix: lines without a TAB
    conv(b'/a\r\n', b'0abcdefghij\r\n1x\tsel\thost.example\t70\r\n', 41004)
    conv(b'/b\r\n', b'iInformational line without tabs\r\n.\r\n', 41005)
    # a menu whose later line is not an item: parsing stops there
    conv(b'/c\r\n', item('0', 'ok') + b'iplain line\r\n' + item('0', 'not shown'), 41006)
    # long names and an empty name / selector
    conv(b'/d\r\n', item('1', 'N' * 70, 'S' * 255, 'h' * 100, '65535') + item('1', '', '', 'h', '7'), 41007)
    # a request from a client to a server on a second connection: server push of data and a short answer
    conv(b'x' * 200 + b'\r\n', b'3Bad request\t\terror.host\t1\r\n', 41008)
    conv(b'/h\r\n', b'0name\tsel\r\n', 41011)                      # only one tab: not a menu line
    conv(b'/i\r\n', b'0name\tsel\thost\r\n', 41012)                # two tabs
    conv(b'/j\r\n', b'ab\r\nxyz123\r\n', 41013)                    # line shorter than a menu line, followed by data
    conv(b'/e\r\n', b'ab\r\n', 41009)                              # shorter than any menu line
    # a response sent in two segments
    c = Flow(41010, 70, f, A, B)
    c.open()
    c.c2s(b'/f\r\n')
    c.s2c(item('0', 'part one'))
    c.s2c(item('0', 'part two') + b'.\r\n')
    c.close()
    pcap(path_main, f)

    g = []
    f = g
    conv(b'/g\r\n', b'1\t\t\t\r\n', 42000)                         # smallest menu line
    conv(b'/h\r\n', b'0name\tsel\r\n', 42001)                      # one tab
    conv(b'/i\r\n', b'0name\tsel\thost\r\n', 42002)                # two tabs
    conv(b'/j\r\n', b'\tsel\thost\t70\r\n', 42003)                 # no type or name, tabs only
    conv(b'/k\r\n', b'0' + b'n' * 400 + b'\tsel\thost\t70\r\n', 42004)   # line longer than the limit
    conv(b'/l\r\n', b'', 42005)
    pcap(path_bad, g)

if __name__ == '__main__':
    out = sys.argv[1]
    build(os.path.join(out, 'gopher-coverage.pcap'), os.path.join(out, 'gopher-coverage-malformed.pcap'))

#!/usr/bin/env python3
# Generates test/captures/x11_coverage.pcap.gz
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
        ack = 0 if flags == 0x02 else self.seq[1 - d]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''      # MSS on a SYN
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
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

# ---- pcapng ----
def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def _opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\0' * ((-len(val)) % 4)

class PcapNG:
    """Several interfaces; add(iface, data, flags=None) with optional epb_flags."""
    def __init__(self, linktypes=(1,)):
        self.linktypes = list(linktypes)
        self.pkts = []
        self.t = 0
    def add(self, data, iface=0, flags=None):
        self.t += 1
        self.pkts.append((iface, self.t, bytes(data), flags))
    def write(self, fn):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for iface, t, d, flags in self.pkts:
            ts = 1700000000 * 1000000 + t * 1000
            body = struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d
            body += b'\0' * ((-len(d)) % 4)
            if flags is not None:
                body += _opt(2, struct.pack('<I', flags)) + struct.pack('<HH', 0, 0)
            out += _blk(6, body)
        with open(fn, 'wb') as f:
            f.write(out)
        return len(self.pkts)

def exported_pdu(name, payload):
    """Exported PDU (linktype 252) record naming a dissector."""
    nm = name.encode()
    pad = (-len(nm)) % 4
    tag = struct.pack('!HH', 12, len(nm) + pad) + nm + b'\0' * pad
    return tag + struct.pack('!HH', 0, 0) + payload

def gsmtap(sub_type, payload, uplink=False, gtype=0x13):
    """GSMTAP v2 header (16 octets) for E1/T1 line traces."""
    arfcn = 0x4000 if uplink else 0
    return struct.pack('!BBBBHBBIBBBB', 2, 4, gtype, 0, arfcn, 0, 0, 0, sub_type, 0, 0, 0) + payload


# ---- X11 (TCP 6000-6063): initial connection, core requests, replies, events and errors in
# both byte orders, extensions through QueryExtension ----
class X:
    """One X11 client connection; requests are queued per direction and flushed as TCP segments."""
    def __init__(self, pcap, cport, order, sport=6000, handshake=True):
        self.t = Tcp(pcap, cport, sport)
        self.defer = False
        self.dq = []
        self.recording = False
        self.rec = []
        self.order = order                 # 'l' or 'B'
        self.o = '<' if order == 'l' else '>'
        self.seq = 0
        self.cq = []
        self.sq = []
        if handshake:
            self.t.handshake()
    def pk(self, fmt, *a):
        return struct.pack(self.o + fmt, *a)
    # --- transport
    def flush_c(self):
        if self.recording:
            return
        if self.cq:
            self.t.c2s(b''.join(self.cq))
            self.cq = []
    def flush_s(self):
        if self.sq:
            self.t.s2c(b''.join(self.sq))
            self.sq = []
    def flush(self):
        self.flush_c()
        self.flush_s()
    def done(self):
        self.flush()
        self.t.fin()
    # --- client to server
    def initial(self, auth_name=b'MIT-MAGIC-COOKIE-1', auth_data=bytes(range(16)), major=11, minor=0):
        self.cq.append(self.order.encode() + b'\0' + self.pk('HHHHH', major, minor, len(auth_name),
                       len(auth_data), 0) + pad4(auth_name) + pad4(auth_data))
        self.flush_c()
    def req(self, opcode, d1=0, body=b'', flush=False):
        body = pad4(body)
        if self.recording:
            self.rec.append(self.pk('BBH', opcode, d1, 1 + len(body) // 4) + body)
            self.seq += 1
            return self.seq
        self.cq.append(self.pk('BBH', opcode, d1, 1 + len(body) // 4) + body)
        self.seq += 1
        if flush:
            self.flush_c()
        return self.seq
    def bigreq(self, opcode, d1=0, body=b''):
        body = pad4(body)
        self.cq.append(self.pk('BBHI', opcode, d1, 0, 2 + len(body) // 4) + body)
        self.seq += 1
        return self.seq
    # --- server to client
    def reply(self, seq, d1=0, fixed=b'', extra=b'', flush=True):
        if self.recording:
            return
        if self.defer:
            self.dq.append(('reply', seq, d1, fixed, extra))
            return
        self.flush_c()
        body = fixed + b'\0' * max(0, 24 - len(fixed)) + extra
        body = pad4(body)
        self.sq.append(self.pk('BBHI', 1, d1, seq, (len(body) - 24) // 4) + body)
        if flush:
            self.flush_s()
    def event(self, etype, d1=0, rest=b'', seq=None, flush=False):
        if self.defer:
            self.dq.append(('event', etype, d1, rest, seq))
            return
        self.flush_c()
        rest = rest + b'\0' * (28 - len(rest))
        self.sq.append(self.pk('BBH', etype, d1, self.seq if seq is None else seq) + rest[:28])
        if flush:
            self.flush_s()
    def error(self, code, seq=None, value=0, minor=0, major=0, flush=True):
        self.flush_c()
        self.sq.append(self.pk('BBHIHB', 0, code, self.seq if seq is None else seq, value, minor, major) + bytes(21))
        if flush:
            self.flush_s()
    def release(self):
        """Deferred mode: all queued requests in one segment, then the replies and events."""
        self.defer = False
        self.flush_c()
        for item in self.dq:
            if item[0] == 'reply':
                self.reply(*item[1:])
            else:
                self.event(*item[1:], flush=True)
        self.dq = []
    def initial_reply(self, vendor=b'Synthetic X Server', screens=1, status=1, reason=b''):
        self.flush_c()
        if status != 1:
            r = pad4(reason)
            self.sq.append(bytes([status, len(reason)]) + self.pk('HHH', 11, 0, len(r) // 4) + r)
            self.flush_s()
            return
        vend = pad4(vendor)
        fmts = b''.join(self.pk('BBBBI', d, bpp, pad, 0, 0) for d, bpp, pad in ((1, 1, 32), (8, 8, 32), (24, 32, 32)))
        def visual(vid, cls, bits, ents):
            return self.pk('IBBHIII', vid, cls, bits, ents, 0xff0000, 0xff00, 0xff) + bytes(4)
        def depth(d, vis):
            return self.pk('BBHI', d, 0, len(vis), 0) + b''.join(vis)
        scr = b''
        for s in range(screens):
            deps = depth(1, []) + depth(24, [visual(0x21, 4, 8, 256), visual(0x22, 5, 8, 256), visual(0x23, 2, 8, 256)]) \
                + depth(8, [visual(0x24, 3, 8, 256)])
            scr += self.pk('IIIIIHHHHHHIBBBB', 0x2a + s, 0x20, 0xffffff, 0, 0x1a0000, 1024, 768, 270, 203, 1, 1,
                           0x21, 1, 1, 24, 3) + deps
        body = self.pk('IIIIHHBBBBBBBB', 0x10000, 0x400000, 0x1fffff, 256, len(vend) - (len(vend) - len(vendor)),
                       65535, screens, 3, 0, 0, 32, 32, 8, 255) + bytes(4) + vend + fmts + scr
        self.sq.append(bytes([1, 0]) + self.pk('HHH', 11, 0, len(body) // 4) + body)
        self.flush_s()

def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)

def lst(order, fmt, vals):
    return b''.join(struct.pack(order + fmt, v) for v in vals)

WIN = 0x400001
WIN2 = 0x400002
PIX = 0x400010
GC = 0x400020
GC2 = 0x400021
FONT = 0x400030
CMAP = 0x400040
CMAP2 = 0x400041
CUR = 0x400050
ROOT = 0x2a
A_WM_NAME = 39
A_STRING = 31
A_CARDINAL = 6

def wattrs(x, mask, vals):
    return x.pk('I', mask) + b''.join(x.pk('I', v) for v in vals)

def core_requests(x):
    """Every core request (and the replies of those that have one)."""
    p = x.pk
    # CreateWindow with every attribute, then ChangeWindowAttributes with some of them
    all_attrs = [0, 0x1234, 0, 0x5678, 1, 1, 2, 0xffff, 0x11, 1, 1, 0x00ffffff, 0x0f, 0x400040, 0x400050]
    x.req(1, 24, p('IIhhHHHHI', WIN, ROOT, 10, 20, 300, 200, 2, 1, 0x21) + wattrs(x, 0x7fff, all_attrs))
    x.req(1, 0, p('IIhhHHHHI', WIN2, WIN, -5, -6, 50, 40, 0, 0, 0) + wattrs(x, 0x800, [0x1ffffff]))
    x.req(1, 8, p('IIhhHHHHI', 0x400003, ROOT, 0, 0, 10, 10, 0, 2, 0x22) + wattrs(x, 0x2 | 0x8 | 0x20, [3, 4, 5]))
    x.req(2, 0, p('I', WIN) + wattrs(x, 0x202 | 0x4000, [0xdeadbeef, 0, 0x400050]))
    s = x.req(3, 0, p('I', WIN))
    x.reply(s, 1, p('IHBBIIBBBBIIIHH', 0x21, 1, 0, 1, 0xffffffff, 0, 0, 1, 2, 0, 0x400040, 0x7fffff, 0x800, 0, 0))
    x.req(4, 0, p('I', WIN2))
    x.req(5, 0, p('I', WIN))
    x.req(6, 1, p('I', WIN))
    x.req(7, 0, p('IIhh', WIN, ROOT, 1, 2))
    x.req(8, 0, p('I', WIN))
    x.req(9, 0, p('I', WIN))
    x.req(10, 0, p('I', WIN))
    x.req(11, 0, p('I', WIN))
    # ConfigureWindow with every field, with some fields, with none
    x.req(12, 0, p('IHH', WIN, 0x7f, 0) + p('hxxhxxHxxHxxHxxIBxxx', 1, 2, 3, 4, 5, WIN2, 0))
    x.req(12, 0, p('IHH', WIN, 0x05, 0) + p('hxxHxx', 7, 9))
    x.req(12, 0, p('IHH', WIN, 0, 0))
    x.req(13, 1, p('I', WIN))
    s = x.req(14, 0, p('I', WIN))
    x.reply(s, 24, p('IhhHHH', ROOT, 10, 20, 300, 200, 2))
    s = x.req(15, 0, p('I', WIN))
    x.reply(s, 0, p('IIH', ROOT, ROOT, 2), p('II', WIN2, 0x400003))
    # atoms and properties
    s = x.req(16, 0, p('HH', 7, 0) + b'WM_NAME')
    x.reply(s, 0, p('I', A_WM_NAME))
    s = x.req(16, 1, p('HH', 12, 0) + b'MY_NEW_ATOM!')
    x.reply(s, 0, p('I', 0x123))
    s = x.req(17, 0, p('I', A_WM_NAME))
    x.reply(s, 0, p('H', 7), b'WM_NAME')
    x.req(18, 0, p('IIIB', WIN, A_WM_NAME, A_STRING, 8) + b'\0\0\0' + p('I', 5) + b'hello')
    x.req(18, 1, p('IIIB', WIN, 40, A_CARDINAL, 16) + b'\0\0\0' + p('I', 3) + p('HHH', 1, 2, 3))
    x.req(18, 2, p('IIIB', WIN, 41, A_CARDINAL, 32) + b'\0\0\0' + p('I', 2) + p('II', 1, 0xdeadbeef))
    x.req(18, 0, p('IIIB', WIN, 41, A_CARDINAL, 8) + b'\0\0\0' + p('I', 0))
    x.req(18, 0, p('IIIB', WIN, 41, A_CARDINAL, 24) + b'\0\0\0' + p('I', 3) + b'abc')   # invalid format
    x.req(19, 0, p('II', WIN, 40))
    s = x.req(20, 1, p('IIIII', WIN, A_WM_NAME, 0, 0, 100))
    x.reply(s, 8, p('III', A_STRING, 0, 5), b'hello')
    s = x.req(21, 0, p('I', WIN))
    x.reply(s, 0, p('H', 3), p('III', 39, 40, 41))
    x.req(22, 0, p('III', WIN, 1, 0x1000))
    s = x.req(23, 0, p('I', 1))
    x.reply(s, 0, p('I', WIN))
    x.req(24, 0, p('IIIII', WIN2, 1, 31, 40, 0x1001))
    # SendEvent (the event is decoded) with a KeyPress, a ConfigureNotify and an unknown type
    ev = lambda t_, d1=0, rest=bytes(28): bytes([t_, d1]) + p('H', 0) + rest
    x.req(25, 1, p('II', WIN, 0x1) + ev(2 | 0x80, 38, p('IIIIhhhhHBx', 0x1000, ROOT, WIN, 0, 1, 2, 3, 4, 0x11, 1)))
    x.req(25, 0, p('II', WIN, 0) + ev(22, 0, p('IIIhhHHHBx', WIN, WIN, 0, 0, 0, 100, 100, 0, 0)))
    x.req(25, 0, p('II', WIN, 0x20) + ev(99, 0))
    # grabs
    s = x.req(26, 1, p('IHBBIII', WIN, 0xff, 1, 0, 0, CUR, 0))
    x.reply(s, 0)
    x.req(27, 0, p('I', 0))
    x.req(28, 0, p('IHBBIIBxH', WIN, 0x7c, 0, 1, 0, 0, 1, 0x8000))
    x.req(29, 3, p('IHH', WIN, 0x4, 0))
    x.req(30, 0, p('IIHH', CUR, 0, 0x4c, 0))
    s = x.req(31, 1, p('IIBBH', WIN, 0, 0, 1, 0))
    x.reply(s, 0)
    x.req(32, 0, p('I', 0))
    x.req(33, 1, p('IHBBBxxx', WIN, 0x8, 38, 1, 1))
    x.req(34, 38, p('IHH', WIN, 0x8000, 0))
    x.req(35, 5, p('I', 0))
    x.req(36, 0)
    x.req(37, 0)
    # pointer queries
    s = x.req(38, 0, p('I', WIN))
    x.reply(s, 1, p('IIhhhhH', ROOT, WIN, 10, 20, 5, 6, 0x1c05))
    s = x.req(39, 0, p('III', WIN, 0, 0xffffffff))
    x.reply(s, 0, p('I', 2), p('IHHIHH', 100, 1, 2, 200, 3, 4))
    s = x.req(40, 0, p('IIhh', WIN, WIN2, 3, 4))
    x.reply(s, 1, p('Ihh', WIN2, 7, 8))
    x.req(41, 0, p('IIhhHHhh', 0, WIN, 0, 0, 0, 0, 5, 5))
    x.req(42, 2, p('II', WIN, 0))
    s = x.req(43, 0)
    x.reply(s, 1, p('I', WIN))
    s = x.req(44, 0)
    x.reply(s, 0, bytes(range(24)), bytes(range(8)))
    # fonts
    x.req(45, 0, p('IHH', FONT, 5, 0) + b'fixed')
    x.req(46, 0, p('I', FONT))
    s = x.req(47, 0, p('I', FONT))
    x.reply(s, 0, bytes(60), bytes(12))
    s = x.req(48, 1, p('I', FONT) + b'\0a\0b\0c' + b'\0\0')
    x.reply(s, 0, p('hhhhiii', 10, 2, 8, 3, 5, 1, 1))
    s = x.req(48, 0, p('I', FONT) + b'\0a\0\xe9\0c\0d')
    x.reply(s, 0, p('hhhhiii', 10, 2, 8, 3, 5, 1, 1))
    s = x.req(49, 0, p('HH', 100, 3) + b'*-*')
    x.reply(s, 0, p('H', 2), b'\x05fixed\x04cursor')
    s = x.req(50, 0, p('HH', 10, 1) + b'*')
    x.reply(s, 0, bytes(0), b'')
    x.req(51, 0, p('HH', 2, 0) + b'\x07/fonts1\x07/fonts2')
    s = x.req(52, 0)
    x.reply(s, 0, p('H', 2), b'\x07/fonts1\x07/fonts2')
    # pixmaps, graphics contexts
    x.req(53, 24, p('IIHH', PIX, WIN, 64, 64))
    x.req(54, 0, p('I', PIX))
    gcv = [3, 0xffffffff, 0x112233, 0x445566, 2, 1, 1, 1, 1, 1, PIX, PIX, 1, 2, FONT, 1, 1, 3, 4, PIX, 4, 8, 1]
    x.req(55, 0, p('II', GC, WIN) + wattrs(x, 0x7fffff, gcv))
    x.req(55, 0, p('II', GC2, WIN) + wattrs(x, 0x1, [6]))
    x.req(56, 0, p('I', GC) + wattrs(x, 0x14, [0xaa, 3]))
    x.req(57, 0, p('III', GC, GC2, 0x7fffff))
    x.req(58, 0, p('IHH', GC, 2, 3) + b'\x04\x02\x01')
    x.req(59, 2, p('Ihh', GC, 1, 2) + p('hhHH', 0, 0, 10, 10) + p('hhHH', 5, 5, 20, 20))
    x.req(60, 0, p('I', GC2))
    # drawing
    x.req(61, 1, p('IhhHH', WIN, 0, 0, 100, 100))
    x.req(62, 0, p('IIIhhhhHH', PIX, WIN, GC, 0, 0, 5, 6, 30, 30))
    x.req(63, 0, p('IIIhhhhHHI', PIX, WIN, GC, 0, 0, 5, 6, 30, 30, 1))
    pts = p('hhhhhh', 1, 2, 3, 4, 5, 6)
    x.req(64, 0, p('II', WIN, GC) + pts)
    x.req(64, 1, p('II', WIN, GC) + pts)
    x.req(65, 0, p('II', WIN, GC) + pts)
    x.req(66, 0, p('II', WIN, GC) + p('hhhhhhhh', 0, 0, 10, 10, 20, 20, 30, 30))
    x.req(67, 0, p('II', WIN, GC) + p('hhHHhhHH', 0, 0, 10, 10, 20, 20, 30, 30))
    x.req(68, 0, p('II', WIN, GC) + p('hhHHhh', 0, 0, 10, 10, 0, 5760) + p('hhHHhh', 1, 2, 11, 12, 100, -200))
    x.req(69, 0, p('IIBBH', WIN, GC, 1, 0, 0) + pts)
    x.req(70, 0, p('II', WIN, GC) + p('hhHHhhHH', 0, 0, 10, 10, 20, 20, 30, 30))
    x.req(71, 0, p('II', WIN, GC) + p('hhHHhh', 0, 0, 10, 10, 0, 5760))
    x.req(72, 2, p('IIHHhhBBH', WIN, GC, 8, 2, 1, 2, 0, 24, 0) + bytes(range(8)))
    s = x.req(73, 2, p('IhhHHI', WIN, 0, 0, 4, 2, 0xffffffff))
    x.reply(s, 24, p('I', 0x21), bytes(32))
    # text
    x.req(74, 0, p('IIhh', WIN, GC, 10, 10) + bytes([5, 0]) + b'hello' + bytes([0xff]) + p('I', FONT)[::-1] + bytes([2, 1]) + b'ab')
    x.req(74, 0, p('IIhh', WIN, GC, 10, 10) + bytes([3, 2]) + b'abc')
    x.req(75, 0, p('IIhh', WIN, GC, 10, 10) + bytes([2, 0]) + b'\0a\0b' + bytes([0xff]) + p('I', FONT)[::-1] + bytes([1, 1]) + b'\x01\x02')
    x.req(76, 5, p('IIhh', WIN, GC, 10, 20) + b'hello')
    x.req(77, 3, p('IIhh', WIN, GC, 10, 20) + b'\0h\0e\0l')
    x.req(77, 3, p('IIhh', WIN, GC, 10, 20) + b'\0h\0\xe9\0i')
    x.req(77, 4, p('IIhh', WIN, GC, 10, 20) + b'\x12\x34\x00\xe9\x20\xac\xd8\x00')
    x.req(75, 0, p('IIhh', WIN, GC, 10, 10) + bytes([2, 0]) + b'\x12\x34\x00\xe9')
    # colormaps and colors
    x.req(78, 1, p('III', CMAP, WIN, 0x21))
    x.req(79, 0, p('I', CMAP))
    x.req(80, 0, p('II', CMAP2, CMAP))
    x.req(81, 0, p('I', CMAP))
    x.req(82, 0, p('I', CMAP))
    s = x.req(83, 0, p('I', WIN))
    x.reply(s, 0, p('H', 2), p('II', CMAP, CMAP2))
    s = x.req(84, 0, p('IHHHxx', CMAP, 0xffff, 0x8000, 0))
    x.reply(s, 0, p('HHHxxI', 0xffff, 0x8000, 0, 0x123456))
    s = x.req(85, 0, p('IHxx', CMAP, 3) + b'red')
    x.reply(s, 0, p('IHHHHHH', 0x123, 0xffff, 0, 0, 0xffff, 0, 0))
    s = x.req(86, 1, p('IHH', CMAP, 4, 1))
    x.reply(s, 0, p('HH', 4, 1), p('IIII', 1, 2, 3, 4) + p('I', 0x10))
    s = x.req(87, 0, p('IHHHH', CMAP, 4, 1, 1, 1))
    x.reply(s, 0, p('HHxxIII', 4, 0, 1, 2, 3), p('IIII', 1, 2, 3, 4))
    x.req(88, 0, p('II', CMAP, 0) + p('II', 1, 2))
    x.req(89, 0, p('I', CMAP) + p('IHHHBx', 5, 1, 2, 3, 7) + p('IHHHBx', 6, 4, 5, 6, 0) + p('IHHHBx', 7, 4, 5, 6, 0xff))
    x.req(90, 7, p('IIHxx', CMAP, 9, 3) + b'red')
    x.req(90, 0xf9, p('IIHxx', CMAP, 10, 4) + b'blue')
    s = x.req(91, 0, p('I', CMAP) + p('II', 1, 2))
    x.reply(s, 0, p('H', 2), p('HHHxx', 1, 2, 3) + p('HHHxx', 4, 5, 6))
    s = x.req(92, 0, p('IHxx', CMAP, 4) + b'blue')
    x.reply(s, 0, p('HHHHHH', 1, 2, 3, 4, 5, 6))
    # cursors
    x.req(93, 0, p('IIIHHHHHHHH', CUR, PIX, PIX, 1, 2, 3, 4, 5, 6, 0, 0))
    x.req(94, 0, p('IIIHHHHHHHH', CUR + 1, FONT, FONT, 68, 69, 0xffff, 0, 0, 0, 0, 0xffff))
    x.req(95, 0, p('I', CUR))
    x.req(96, 0, p('IHHHHHH', CUR + 1, 1, 2, 3, 4, 5, 6))
    s = x.req(97, 1, p('IHH', WIN, 32, 32))
    x.reply(s, 0, p('HH', 32, 32))
    # extensions, keyboard and pointer, hosts, misc
    s = x.req(98, 0, p('HH', 11, 0) + b'BIG-REQUESTS')
    x.reply(s, 0, bytes([1, 133, 0, 0]))
    s = x.req(98, 0, p('HH', 12, 0) + b'NOT-PRESENT!')
    x.reply(s, 0, bytes([0, 0, 0, 0]))
    s = x.req(99, 0)
    x.reply(s, 2, b'', b'\x0aBIG-REQUESTS\x05SHAPE')
    x.req(102, 0, p('I', 0xff) + bytes([50, 0, 0, 0]) + bytes([100, 0, 0, 0]) + p('HH', 440, 0) + p('HH', 100, 0)
          + p('HH', 2, 0) + bytes([1, 0, 0, 0]) + bytes([7, 0, 0, 0]) + bytes([1, 0, 0, 0]))
    x.req(102, 0, p('I', 0x3) + bytes([10, 0, 0, 0]) + bytes([20, 0, 0, 0]))
    s = x.req(103, 0)
    x.reply(s, 1, p('IIHH', 0xff, 50, 440, 100), bytes(32))
    x.req(104, 50)
    x.req(104, 0xe0)
    x.req(105, 0, p('hhhBB', 2, 1, 4, 1, 1))
    s = x.req(106, 0)
    x.reply(s, 0, p('HHH', 2, 1, 4))
    x.req(107, 0, p('hhBBxx', 600, 600, 1, 2))
    s = x.req(108, 0)
    x.reply(s, 0, p('HHBB', 600, 600, 1, 2))
    x.req(109, 0, p('BxH', 0, 4) + bytes([192, 0, 2, 1]))
    x.req(109, 1, p('BxH', 6, 16) + bytes(range(16)))
    x.req(109, 0, p('BxH', 0, 7) + bytes(range(7)))
    s = x.req(110, 0)
    x.reply(s, 1, p('H', 1), p('BxH', 0, 4) + bytes([192, 0, 2, 1]))
    x.req(111, 1)
    x.req(112, 2)
    x.req(113, 0, p('I', 0x400100))
    x.req(114, 0, p('IHh', WIN, 3, 1) + p('III', 39, 40, 41))
    x.req(115, 1)
    x.req(116, 3, bytes([1, 2, 3]))
    s = x.req(117, 0)
    x.reply(s, 3, b'', bytes([1, 2, 3]))
    x.req(100, 2, bytes([30, 2, 0, 0]) + lst(x.o, 'I', [0x61, 0x41, 0x62, 0x42]))
    x.req(127)
    x.flush()

KEYSYMS_CASE = [0x41, 0x5A, 0x61, 0x7A, 0xC0, 0xD6, 0xE0, 0xF6, 0xD8, 0xDE, 0xF8, 0xFE,
                0x1A1, 0x1B1, 0x1A3, 0x1A6, 0x1A9, 0x1AC, 0x1AE, 0x1AF, 0x1B3, 0x1B6, 0x1B9, 0x1BC, 0x1BE,
                0x1BF, 0x1C0, 0x1DE, 0x1E0, 0x1FE, 0x2A1, 0x2A6, 0x2AB, 0x2AC, 0x2B1, 0x2B6, 0x2BB, 0x2BC,
                0x2C5, 0x2DE, 0x2E5, 0x2FE, 0x3A3, 0x3AC, 0x3B3, 0x3BC, 0x3BD, 0x3BF, 0x3C0, 0x3DE, 0x3E0,
                0x3FE, 0x6A1, 0x6AF, 0x6B1, 0x6BF, 0x6E0, 0x6FF, 0x6C0, 0x6DF, 0x7A1, 0x7AB, 0x7B1, 0x7BB,
                0x7C1, 0x7D9, 0x7E1, 0x7F9, 0xFFFFFF, 0x0, 0x20AC]

def keyboard(x, shiftlock=False):
    """Keyboard mapping and modifier mapping, then key events over the keysym case conversions."""
    p = x.pk
    first = 20
    # keycodes 8-19: specials, with 4 keysyms per keycode
    specials = [  # keycode, keysyms
        (8, [0x61, 0x41, 0, 0]), (9, [0x31, 0x21, 0, 0]), (10, [0xff7f, 0, 0, 0]),
        (11, [0xff7e, 0, 0, 0]), (12, [0xffe5, 0, 0, 0]), (13, [0xffb1, 0xff9c, 0, 0]),
        (14, [0x62, 0x42, 0x63, 0x43]), (15, [0x64, 0, 0x65, 0]), (16, [0x66, 0x46, 0, 0]),
        (17, [0xffe6, 0, 0, 0]), (18, [0x67, 0, 0, 0]), (19, [0xffe1, 0, 0, 0])]
    # keycodes 20..: one keysym each (the case conversion table), kpk 1
    s = x.req(101, 0, bytes([first, len(KEYSYMS_CASE), 0, 0]))
    x.reply(s, 1, b'', lst(x.o, 'I', KEYSYMS_CASE))
    s = x.req(101, 0, bytes([8, 12, 0, 0]))
    ks = []
    for kc, syms in specials:
        ks += syms
    x.reply(s, 4, b'', lst(x.o, 'I', ks))
    # modifier mapping: shift 50 62, lock 12, control 37 105, mod1 11 (mode switch), mod2 10 (numlock),
    # mod3 none, mod4 133 134, mod5 64 108 (the dissector stops looking when it has found num lock,
    # so the mode switch row must come before it)
    if shiftlock:
        rows = [(50, 62, 17), (66, 0, 0), (37, 105, 0), (11, 0, 0), (10, 0, 0), (0, 0, 0), (133, 134, 0), (64, 108, 0)]
        kpm = 3
    else:
        rows = [(50, 62), (12, 0), (37, 105), (11, 0), (10, 0), (0, 0), (133, 134), (64, 108)]
        kpm = 2
    s = x.req(119, 0)
    x.reply(s, kpm, b'', bytes(b for r in rows for b in r))
    # a request with the same effect (SetModifierMapping with its reply)
    s = x.req(118, kpm, bytes(b for r in rows for b in r))
    x.reply(s, 0)
    x.flush_c()
    # a ChangeKeyboardMapping that adds a few keycodes
    x.req(100, 3, bytes([200, 4, 0, 0]) + lst(x.o, 'I', [0x61, 0x41, 0, 0, 0x1a1, 0x1b1, 0, 0, 0x7c1, 0x7e1, 0x7e2, 0]))
    x.req(100, 1, bytes([210, 1, 0, 0]) + lst(x.o, 'I', [0x65]))
    x.req(100, 10, bytes([250, 1, 0, 0]) + lst(x.o, 'I', [0x61] * 10))
    x.req(100, 3, bytes([200, 4, 0, 0]) + lst(x.o, 'I', [0x62, 0x42, 0, 0, 0x1a1, 0x1b1, 0, 0, 0x7c1, 0x7e1, 0x7e2, 0]))
    x.flush_c()
    # key events: all keycodes, with the state masks of interest
    states = [0, 1, 2, 3, 0x10, 0x11, 0x8, 0x9, 0x1a, 0x4, 0x80]
    def kev(etype, kc, st):
        return (bytes([etype, kc]) + p('H', x.seq) + p('IIIIhhhhH', 0x1000, ROOT, WIN, 0, 1, 2, 3, 4, st) + b'\x01\0')
    for i, st in enumerate(states):
        for kc in list(range(8, 20)) + list(range(first, first + len(KEYSYMS_CASE))) + [200, 201, 202, 210, 250]:
            if st not in (0, 1) and kc >= first and (kc - first) % 7:
                continue
            x.sq.append(kev(2 if i % 2 == 0 else 3, kc, st))
            if len(x.sq) >= 20:
                x.flush_s()
    x.flush_s()

def events(x):
    """The other core events and errors."""
    p = x.pk
    t = [0x1000, ROOT, WIN, WIN2, 5, 6, 7, 8, 0x1c05, 1, 0]
    def common(extra=b''):
        return p('IIIIhhhhHBx', 0x1000, ROOT, WIN, WIN2, 5, 6, 7, 8, 0x1c05, 1)
    x.event(4, 3, common())                                 # ButtonPress
    x.event(5, 1, common())                                 # ButtonRelease
    x.event(6, 1, common())                                 # MotionNotify
    x.event(7, 2, p('IIIIhhhhHBB', 0x1000, ROOT, WIN, WIN2, 5, 6, 7, 8, 0x1c05, 1, 3))   # EnterNotify
    x.event(8, 0, p('IIIIhhhhHBB', 0x1000, ROOT, WIN, 0, 5, 6, 7, 8, 0, 0, 1))           # LeaveNotify
    x.event(9, 3, p('IB', WIN, 1))                         # FocusIn
    x.event(10, 4, p('IB', WIN, 2))                        # FocusOut
    x.event(11, 0, bytes(range(1, 29)))                    # KeymapNotify
    x.event(12, 0, p('IhhHHH', WIN, 1, 2, 30, 40, 2))      # Expose
    x.event(13, 0, p('IHHHHHHB', PIX, 1, 2, 30, 40, 5, 1, 70))   # GraphicsExposure
    x.event(14, 0, p('IHB', PIX, 0, 70))                   # NoExposure
    x.event(15, 0, p('IB', WIN, 2))                        # VisibilityNotify
    x.event(16, 0, p('IIhhHHHB', WIN, WIN2, 1, 2, 30, 40, 1, 1))   # CreateNotify
    x.event(17, 0, p('II', WIN, WIN2))                     # DestroyNotify
    x.event(18, 0, p('IIB', WIN, WIN2, 1))                 # UnmapNotify
    x.event(19, 0, p('IIB', WIN, WIN2, 1))                 # MapNotify
    x.event(20, 0, p('II', WIN, WIN2))                     # MapRequest
    x.event(21, 0, p('IIIhh', WIN, WIN2, WIN, 3, 4) + b'\x01')   # ReparentNotify
    x.event(22, 0, p('IIIhhHHHB', WIN, WIN2, 0, 1, 2, 30, 40, 1, 1))   # ConfigureNotify
    x.event(23, 0, p('IIIhhHHHH', WIN, WIN2, WIN, 1, 2, 30, 40, 1, 0x7f))  # ConfigureRequest
    x.event(24, 0, p('IIhh', WIN, WIN2, 1, 2))             # GravityNotify
    x.event(25, 0, p('IHH', WIN, 30, 40))                  # ResizeRequest
    x.event(26, 1, p('IIB', WIN, WIN2, 1))                 # CirculateNotify
    x.event(27, 0, p('II', WIN, WIN2) + b'\0\0\0\0' + bytes([1]))   # CirculateRequest
    x.event(28, 0, p('IIIB', WIN, A_WM_NAME, 0x1000, 1))   # PropertyNotify
    x.event(29, 0, p('III', 0x1000, WIN, 1))               # SelectionClear
    x.event(30, 0, p('IIIIII', 0x1000, WIN, WIN2, 1, 31, 39))   # SelectionRequest
    x.event(31, 0, p('IIIII', 0x1000, WIN, 1, 31, 39))     # SelectionNotify
    x.event(32, 0, p('IIBBB', WIN, CMAP, 1, 1, 0))         # ColormapNotify
    x.event(33, 32, p('IIIIII', WIN, 1, 2, 3, 4, 5), flush=False)   # ClientMessage format 32
    x.event(33, 8, p('I', WIN) + bytes(range(20)))      # ClientMessage format 8
    x.event(33, 16, p('I', WIN) + p('HHHHHHHHHH', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
    x.event(34, 0, p('BBBB', 1, 8, 5, 0))                  # MappingNotify (modifier)
    x.event(34, 0, p('BBBB', 2, 8, 5, 0))                  # keyboard
    x.event(34, 0, p('BBBB', 3, 0, 0, 0))                  # pointer
    x.event(77, 0, bytes(28))                              # unknown event code
    x.event(2 | 0x80, 38, common())                        # a KeyPress from SendEvent
    x.flush_s()
    # errors with every code
    names = ['Request', 'Value', 'Window', 'Pixmap', 'Atom', 'Cursor', 'Font', 'Match', 'Drawable',
             'Access', 'Alloc', 'Colormap', 'GContext', 'IDChoice', 'Name', 'Length', 'Implementation']
    for code in range(1, 18):
        x.error(code, value=0x400000 + code, minor=0, major=code, flush=False)
    x.error(99, value=1, major=1, flush=False)
    x.flush_s()

EXTS = [  # name, major opcode, first event, first error
    ('BIG-REQUESTS', 133, 0, 0), ('SHAPE', 129, 64, 0), ('MIT-SHM', 130, 65, 128),
    ('XFIXES', 134, 104, 138), ('RENDER', 132, 0, 142), ('XKEYBOARD', 135, 85, 137),
    ('RANDR', 137, 107, 147), ('XInputExtension', 131, 66, 129), ('Present', 136, 0, 0),
    ('Generic Event Extension', 128, 0, 0), ('GLX', 138, 100, 150), ('Composite', 139, 0, 0),
    ('DRI3', 140, 0, 0)]

def extensions(x):
    p = x.pk
    for name, major, fe, fer in EXTS:
        nm = name.encode()
        s = x.req(98, 0, p('HH', len(nm), 0) + nm)
        x.reply(s, 0, bytes([1, major, fe, fer]))
    # the same name again
    nm = b'SHAPE'
    s = x.req(98, 0, p('HH', len(nm), 0) + nm)
    x.reply(s, 0, bytes([1, 129, 64, 0]))
    # requests with a reply: QueryVersion of several extensions
    s = x.req(129, 0)                      # SHAPE QueryVersion
    x.reply(s, 0, p('HH', 1, 1))
    s = x.req(134, 0, p('II', 5, 0))       # XFIXES QueryVersion
    x.reply(s, 0, p('II', 5, 0))
    s = x.req(132, 0, p('II', 0, 11))      # RENDER QueryVersion
    x.reply(s, 0, p('II', 0, 11))
    s = x.req(128, 0, p('HH', 1, 0))       # Generic Event Extension QueryVersion
    x.reply(s, 0, p('HH', 1, 0))
    s = x.req(135, 0, p('HH', 1, 0))       # XKEYBOARD UseExtension
    x.reply(s, 1, p('HH', 1, 0))
    s = x.req(137, 0, p('II', 1, 5))       # RANDR QueryVersion
    x.reply(s, 0, p('II', 1, 5))
    s = x.req(138, 7, p('IIII', 1, 2, 3, 4))      # GLX request
    x.reply(s, 0, bytes(24))
    def rc(op, body):
        body = pad4(body)
        return p('HH', 4 + len(body), op) + body
    cmds = (rc(2, p('II', 3, 0x1402) + p('hhh', 1, 2, 3)) + rc(2, p('II', 2, 0x1404) + p('ii', 1, -2))
            + rc(2, p('II', 2, 0x1406) + p('ff', 1.5, 2.5)) + rc(2, p('II', 2, 0x1401) + b'ab')
            + rc(7, p('ddd', 0.5, 1.0, 0.25)) + rc(8, p('fff', 0.5, 1.0, 0.25)) + rc(9, p('iii', 1, 2, 3))
            + rc(10, p('hhh', 1, 2, 3)) + rc(26, p('i', 7)))
    x.req(138, 1, p('I', 0x400200) + cmds)
    x.req(138, 1, p('I', 0x400200) + p('HH', 2, 2))      # a command that is too short
    s = x.req(133, 0)                      # BIG-REQUESTS Enable
    x.reply(s, 0, p('I', 4194303))
    x.req(139, 1, p('IBxxx', WIN, 1))      # Composite RedirectWindow without reply
    s = x.req(140, 6, p('IBBxx', WIN, 24, 32))     # DRI3 GetSupportedModifiers
    x.reply(s, 0, p('II', 2, 1), p('QQQ', 0x1, 0x2, 0x3) )
    x.req(130, 1, p('IIII', 1, 2, 3, 4))   # MIT-SHM
    x.req(200, 3, p('I', 1))               # a major opcode nobody registered
    # a request of a big size: a request with the length field 0 (BIG-REQUESTS)
    x.bigreq(70, 0, p('II', WIN, GC) + p('hhHHhhHH', 0, 0, 10, 10, 20, 20, 30, 30) + p('hhHH', 1, 2, 3, 4))
    x.flush_c()
    # extension events and errors
    x.event(64, 0, p('IIhhHHI', WIN, 0, 1, 2, 3, 4, 0x1000))                  # SHAPE ShapeNotify
    x.event(65, 0, p('IIII', WIN, 1, 2, 3))                                    # MIT-SHM Completion
    x.event(104, 0, p('IIII', WIN, WIN2, 1, 0x1000))                           # XFIXES SelectionNotify
    x.event(105, 1, p('IIIIIIIII', WIN, 1, 2, 3, 4, 5, 6, 7, 8))               # XFIXES CursorNotify
    x.event(85, 0, p('IBBBBHHHH', 0x1000, 3, 0, 4, 0, 0, 0, 0, 0))             # XKB
    x.event(107, 0, p('IIIIIHHHH', 0x1000, 0x1001, WIN, ROOT, 1, 2, 3, 4, 5))  # RANDR ScreenChangeNotify
    x.event(66, 0, p('IIIIhhhhHB', 0x1000, ROOT, WIN, 0, 1, 2, 3, 4, 5, 6))    # XInput device event
    x.event(100, 0, bytes(range(28)))                                           # GLX
    x.event(120, 0, bytes(28))                                                  # extension event nobody registered
    x.flush_s()
    for code in (128, 129, 137, 138, 142, 147, 150, 151, 200):
        x.error(code, value=0x400000, flush=False)
    x.error(1, value=0, minor=5, major=130, flush=False)
    x.flush_s()
    # generic events: XInput and Present (known sub-events), an unknown sub-event, an unregistered extension
    def ge(ext, evtype, body=b''):
        body = pad4(body)
        x.sq.append(bytes([35, ext]) + p('H', x.seq) + p('I', len(body) // 4) + p('H', evtype) + bytes(22) + body)
    for ev in (1, 2, 4, 7, 11, 12, 13, 15, 18, 21, 22, 25, 27, 30, 99):
        ge(131, ev, bytes(200))
    for ev in (1, 2, 3, 77):
        ge(136, ev, bytes(200))
    ge(222, 1, bytes(4))
    ge(128, 0, b'')
    x.flush_s()

def stream_split(p, order):
    """A conversation whose requests and replies are cut across TCP segments (desegmentation)."""
    x = X(p, 50010 if order == 'l' else 50011, order)
    pk = x.pk
    init = order.encode() + b'\0' + pk('HHHHH', 11, 0, 18, 16, 0) + pad4(b'MIT-MAGIC-COOKIE-1') + pad4(bytes(range(16)))
    # the initial request: first 5 octets, then up to the authorization data, then the rest
    x.t.c2s(init[:5]); x.t.c2s(init[5:30]); x.t.c2s(init[30:])
    x.initial_reply()
    x.flush()
    cr = pk('BBH', 1, 24, 8) + pk('IIhhHHHHI', WIN, ROOT, 0, 0, 100, 100, 0, 1, 0x21) + pk('I', 0)
    gp = pk('BBH', 3, 0, 2) + pk('I', WIN)
    ra = pk('BBH', 16, 0, 3) + pk('HH', 4, 0) + b'abcd'
    data = cr + gp + ra
    # cut inside the header of the second request (2 octets), then in the middle of the third
    cuts = [len(cr) + 2, len(cr) + len(gp) + 5]
    last = 0
    for c in cuts + [len(data)]:
        x.t.c2s(data[last:c])
        last = c
    x.seq += 3
    # a reply with the header cut after 5 octets, then in the middle of the body
    rep = pk('BBHI', 1, 1, 2, 3) + bytes(24) + bytes(12)
    x.t.s2c(rep[:5]); x.t.s2c(rep[5:20]); x.t.s2c(rep[20:])
    ev = pk('BBH', 12, 0, 3) + bytes(28)
    x.t.s2c(ev[:3]); x.t.s2c(ev[3:])
    # a reply and an event in one segment, the event cut
    rep2 = pk('BBHI', 1, 0, 3, 0) + bytes(24)
    x.t.s2c(rep2 + ev[:10]); x.t.s2c(ev[10:])
    x.t.fin()

def midstream(p, order):
    """Captures that start in the middle of a connection: the byte order must be guessed. One
    connection has all requests in one segment, followed by the replies; one connection per request
    follows (each checks the length rule of its opcode)."""
    base = 50020 if order == 'l' else 50021
    x = X(p, base, order, handshake=False)
    x.defer = True
    core_requests(x)
    x.release()
    r = X(Pcap(), 1, order, handshake=False)
    r.recording = True
    core_requests(r)
    for i, data in enumerate(r.rec):
        t = Tcp(p, 51000 + i + (400 if order == 'B' else 0), 6000)
        t.c2s(data)
    for data in (r.pk('BBH', 200, 0, 2) + bytes(4), r.pk('BBH', 127, 0, 1)):
        t = Tcp(p, 52100 + (50 if order == 'B' else 0) + len(data) % 7, 6000)
        t.c2s(data)
    # a segment that is too short to hold a request header
    t = Tcp(p, 52000 + (1 if order == 'B' else 0), 6000)
    t.c2s(b'\x01\x02')

def failures(p, order, with_auth=False):
    x = X(p, 50030 if order == 'l' else 50032, order)
    x.initial()
    x.initial_reply(status=0, reason=b'No protocol specified')
    x.done()
    if with_auth:
        x = X(p, 50031 if order == 'l' else 50033, order)
    if with_auth:
        x.initial(auth_name=b'XDM-AUTHORIZATION-1', auth_data=bytes(8))
        x.initial_reply(status=2, reason=b'Authenticate: waiting')
        x.done()

LE = lambda fmt, *a: struct.pack('<' + fmt, *a)
KEYPRESS8 = lambda seq: bytes([2, 8]) + LE('H', seq) + bytes(28)

def repro_modmap(p):
    """Reproducer of "X11: ...modifier mapping": a modifier map reply of 255 keycodes per modifier with
    no data (the reply is malformed), then a key event on a keycode that is mapped."""
    t = Tcp(p, 50040, 6000)
    t.handshake()
    t.c2s(LE('BBH', 118, 1, 3) + bytes([0x32, 0x42, 0x25, 0x40, 0x4d, 0, 0x85, 0x5c]))
    t.c2s(LE('BBHBBH', 101, 0, 2, 8, 1, 0))
    t.s2c(LE('BBHI', 1, 1, 2, 1) + bytes(24) + LE('I', 0x61))
    t.c2s(LE('BBH', 119, 0, 1))
    t.s2c(LE('BBHI', 1, 255, 3, 0) + bytes(24))
    t.s2c(KEYPRESS8(3))
    t.fin()

def repro_assert(p):
    """A keyboard mapping reply whose length wraps when multiplied by 4."""
    t = Tcp(p, 50041, 6000)
    t.handshake()
    t.c2s(LE('BBHBBH', 101, 0, 2, 8, 1, 0))
    t.s2c(LE('BBHI', 1, 1, 1, 0x80000000) + bytes(24))
    t.fin()

def repro_uninit(p):
    """ChangeKeyboardMapping with no keysyms per keycode, then a key event on that keycode."""
    t = Tcp(p, 50042, 6000)
    t.handshake()
    t.c2s(LE('BBH', 118, 1, 3) + bytes([0x32, 0x42, 0x25, 0x40, 0x4d, 0, 0x85, 0x5c]))
    t.c2s(LE('BBHBBH', 100, 1, 2, 8, 0, 0))
    t.s2c(KEYPRESS8(2))
    t.fin()

def malformed(m):
    repro_modmap(m)
    repro_assert(m)
    failures(m, 'l', with_auth=True)
    # a PutImage in a BIG-REQUESTS request counts its data 4 octets too long; length 0 twice; a huge
    # BIG-REQUESTS length; a generic event with a bogus length; truncated replies and events
    x = X(m, 50050, 'l')
    x.initial()
    x.initial_reply()
    p = x.pk
    x.bigreq(72, 2, p('IIHHhhBBH', WIN, GC, 8, 2, 1, 2, 0, 24, 0) + bytes(range(8)))
    x.flush_c()
    s = x.req(98, 0, p('HH', 11, 0) + b'BIG-REQUESTS')
    x.reply(s, 0, bytes([1, 133, 0, 0]))
    s = x.req(98, 0, p('HH', 23, 0) + b'Generic Event Extension')
    x.reply(s, 0, bytes([1, 128, 0, 0]))
    x.sq.append(bytes([35, 128]) + p('H', x.seq) + p('I', 0x40000000) + p('H', 0) + bytes(20))
    x.flush_s()
    x.cq.append(p('BBHI', 70, 0, 0, 0x7fffffff))               # huge BIG-REQUESTS length
    x.flush_c()
    x.cq.append(p('BBHI', 127, 0, 0, 0))                       # length 0 and 0
    x.flush_c()
    x.cq.append(p('BBHIIIB', 18, 0, 6, WIN, 40, 6, 16) + b'\0\0\0' + p('I', 0xC0000000)); x.seq += 1
    x.cq.append(p('BBHIIIB', 18, 0, 6, WIN, 40, 6, 32) + b'\0\0\0' + p('I', 0x40000000)); x.seq += 1
    x.flush_c()
    # a short reply (reply length longer than the data), a reply longer than 4 GB, an event that is cut
    x.t.s2c(p('BBHI', 1, 0, x.seq, 100) + bytes(24))
    x.t.s2c(p('BBHI', 1, 0, x.seq, 0x40000000) + bytes(24))
    x.t.s2c(p('BBH', 12, 0, 1) + bytes(10))
    x.t.s2c(p('BBHI', 35, 0, 0, 0xffffffff) + bytes(24))
    x.t.fin()
    # replies without a known request, in a conversation that starts mid-stream, with a bad sequence
    z = X(m, 50051, 'B', handshake=False)
    z.reply(77, 0, bytes(24), b'')
    z.event(2, 8, bytes(28))
    z.error(3, seq=9, value=1, minor=0, major=2)
    z.t.fin()
    t = Tcp(m, 52200, 6000)
    t.c2s(bytes([1, 0, 0, 0]))                                  # length 0, mid-stream
    t = Tcp(m, 52201, 6000)
    t.c2s(bytes([1, 0, 0, 0, 0, 0, 0, 0]))                      # length 0 and 0
    # a truncated initial reply and a truncated initial request
    w = X(m, 50052, 'l')
    w.t.c2s(b'l\0' + LE('HHHHH', 11, 0, 4000, 4000, 0) + b'MIT')
    w.t.s2c(bytes([1, 0]) + LE('HHH', 11, 0, 3000) + bytes(40))
    w.t.fin()

def build(outdir):
    p = Pcap()
    # ---- little-endian client: everything ----
    x = X(p, 50001, 'l')
    x.initial()
    x.initial_reply()
    core_requests(x)
    keyboard(x)
    events(x)
    extensions(x)
    x.done()
    # ---- big-endian client ----
    y = X(p, 50002, 'B')
    y.initial(auth_name=b'', auth_data=b'')
    y.initial_reply(screens=2)
    core_requests(y)
    keyboard(y, shiftlock=True)
    events(y)
    extensions(y)
    y.done()
    repro_uninit(p)
    for order in ('l', 'B'):
        failures(p, order)
        stream_split(p, order)
        midstream(p, order)
    n = p.write(os.path.join(outdir, 'x11-coverage.pcap'))
    print('x11-coverage.pcap', n)
    m = Pcap()
    malformed(m)
    n = m.write(os.path.join(outdir, 'x11-coverage-malformed.pcap'))
    print('x11-coverage-malformed.pcap', n)

if __name__ == '__main__':
    build(outdir())

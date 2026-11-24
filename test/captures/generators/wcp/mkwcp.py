#!/usr/bin/env python3
# Generates test/captures/wcp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Wellfleet Compression dissector
(packet-wcp.c).

WCP is reached by Ethernet type 0x80FF and by Frame Relay NLPID 0xB0.
The dissector keeps one 32767-byte history window per circuit and per
direction. Compressed packets (command 0, or extended command 0, "per
packet compression") are LZSS streams of literal bytes and
back-references into that window; uncompressed packets (command 1) are
copied into the window as they are. The decompressed data is handed to
the Frame Relay "uncompressed" dissector: an NLPID octet (0xCC) followed
by an IPv4 packet here.

The compressor below is a small LZSS encoder of our own: flag octets
with one bit per item, literal octets, short references (2 octets,
count 1 or 3-16) and long references (3 octets, count 1-256), offsets
up to 4095. Nothing comes from a real network.

The two directions of an Ethernet circuit are told apart by the
pseudo-header: a pcapng interface without if_fcslen reads as the "recv"
window, one with if_fcslen 0 as the "send" window.

Usage: mkwcp.py <output directory>

Writes:
  wcp-coverage.pcapng            main capture (clean)
  wcp-coverage-malformed.pcapng  paths only malformed input reaches
"""
import os
import random
import struct
import sys

WIN = 0x7fff          # MAX_WIN_BUF_LEN
MAXPKT = 2048         # MAX_WCP_BUF_LEN

LT_ETH = 1
LT_FR = 107


def pcapng(path, ifaces, frames):
    """ifaces: list of (linktype, fcslen or None). frames: (ifindex, data
    [, caplen])."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt, fcs in ifaces:
        opts = b''
        if fcs is not None:
            opts += struct.pack('<HHBxxx', 13, 1, fcs)
            opts += struct.pack('<HH', 0, 0)
        out += block(1, struct.pack('<HHI', lt, 0, 262144) + opts)
    t0 = 1700000000 * 1000000
    for i, fr in enumerate(frames):
        ifc, data = fr[0], fr[1]
        cap = fr[2] if len(fr) > 2 else len(data)
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    cap, len(data)) + data[:cap])
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IDENT = [1]


def nlpid_ip(total, tag=0):
    """NLPID 0xCC + an IPv4/UDP datagram; total counts the NLPID octet.
    The UDP payload is repeating text so that it compresses."""
    assert total >= 29
    plen = total - 29
    words = [b'wellfleet ', b'compression ', b'window ', b'history ',
             b'packet ', b'router ', b'circuit ', b'data ']
    r = random.Random(tag * 7919 + total)
    payload = b''
    while len(payload) < plen:
        payload += words[r.randrange(len(words))]
        if r.random() < 0.15:
            payload += b'%04d ' % r.randrange(10000)
    payload = payload[:plen]
    udp = struct.pack('!HHHH', 40000 + tag % 7, 40100, 8 + plen, 0) + payload
    IDENT[0] += 1
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), IDENT[0], 0,
                      64, 17, 0, bytes([10, 1, 1, 1 + tag % 5]),
                      bytes([10, 2, 2, 2]))
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    return b'\xcc' + iph + udp


class Window:
    """Model of one direction's history window in the dissector."""

    def __init__(self):
        self.hist = bytearray()   # logical stream of every stored octet
        self.cur = 0              # physical position of buf_cur
        self.init = 0             # "initialized" counter
        self.seq = 0

    # -- LZSS encoder
    def encode(self, data, rnd=None):
        """Return (compressed bytes, updated model) for data."""
        items = []
        i = 0
        h = self.hist
        init = self.init
        while i < len(data):
            pos = len(h)
            dmax = min(4095, init - 1)
            best = (0, 0)
            if dmax >= 0 and len(data) - i >= 1:
                lo = max(0, pos - 1 - dmax)
                seg = bytes(h[lo:pos])
                rem = len(data) - i
                p3 = data[i:i + 3]
                if len(p3) == 3:
                    end = len(seg)
                    cands = []
                    while len(cands) < 8:
                        k = seg.rfind(p3, 0, end)
                        if k < 0:
                            break
                        cands.append(k)
                        end = k + 2
                    for k in cands:
                        s = lo + k
                        d = pos - 1 - s
                        # extend; a run may not overlap the output
                        L = 0
                        maxl = min(256, rem, d + 1)
                        while L < maxl and h[s + L] == data[i + L]:
                            L += 1
                        if L > best[0]:
                            best = (L, d)
                        if L == maxl:
                            break
            L, d = best
            if L >= 3:
                items.append(('ref', d, L))
                h += data[i:i + L]
                init = min(WIN, init + L)
                i += L
            else:
                items.append(('lit', data[i]))
                h.append(data[i])
                init = min(WIN, init + 1)
                i += 1
        return self.pack(items), init

    @staticmethod
    def pack(items):
        out = b''
        for g in range(0, len(items), 8):
            grp = items[g:g + 8]
            flag = 0
            body = b''
            for n, it in enumerate(grp):
                if it[0] == 'ref':
                    flag |= 0x80 >> n
                    _, d, L = it
                    if 3 <= L <= 16:
                        body += bytes([((L - 1) << 4) | (d >> 8), d & 0xff])
                    else:
                        body += bytes([0x10 | (d >> 8), d & 0xff, L - 1])
                else:
                    body += bytes([it[1]])
            out += bytes([flag]) + body
        return out

    def store(self, data, uncompressed=False):
        """After a packet: account the stored octets."""
        # the encoder already appended to hist for compressed packets
        pass


def wcp_packet(cmd, seq, body, ext=None):
    if ext is not None:
        return bytes([0xf0 | ext]) + body
    return struct.pack('>H', (cmd << 12) | (seq & 0xfff)) + body


class Circuit:
    def __init__(self, ifc, eth=True, n=0):
        self.ifc = ifc
        self.n = n
        self.eth = eth
        self.win = Window()
        self.seq = 0
        self.frames = []

    def emit(self, payload):
        self.frames.append((self.ifc, self.frame(payload)))

    def frame(self, payload):
        if self.eth:
            return (bytes([2, 0, 0, 0, 0, 1 + self.n, 2, 0, 0, 0, 0, 2 + self.n])
                    + struct.pack('>H', 0x80ff) + payload)
        return b'\x04\x01\x03\xb0' + payload   # FR address, UI, NLPID

    def compressed(self, data, ppc=False):
        """A compressed data packet carrying data (the decompressed bytes).
        Updates the model like the dissector does."""
        w = self.win
        assert w.cur + len(data) <= WIN, 'would cross the window end'
        self.seq += 1
        comp, init = w.encode(data)
        w.init = init
        w.cur = (w.cur + len(data)) % WIN
        body = comp + b'\x00'            # check byte
        if ppc:
            self.emit(wcp_packet(0xf, 0, body, ext=0))
        else:
            self.emit(wcp_packet(0, self.seq, body))

    def uncompressed(self, data):
        w = self.win
        self.seq += 1
        w.hist += data
        w.cur = (w.cur + len(data)) % WIN
        self.emit(wcp_packet(1, self.seq, data + b'\x00'))

    def room(self):
        return WIN - self.win.cur


def fill_to(c, target_room, tag, lo=300, hi=MAXPKT):
    """Send compressed packets until exactly target_room octets are left
    before the end of the window (0: the window is full and wrapped)."""
    r = random.Random(tag)
    while True:
        need = c.room() - target_room
        if need <= hi:
            size = need
        else:
            size = r.randrange(lo, hi + 1)
            if need - size < 29 and need - size != 0:
                continue
        assert size >= 29
        c.compressed(nlpid_ip(size, tag + c.seq))
        if size == need:
            return


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    random.seed(1)
    ifaces = [(LT_ETH, None), (LT_ETH, 0), (LT_FR, None)]
    A = Circuit(0)
    B = Circuit(1)
    F = Circuit(2, eth=False)
    marks = []

    def mark(name):
        marks.append((name, len(A.frames) + len(B.frames) + len(F.frames)))

    # ---- extended commands (no data); all on interface 0 for ordering
    ctl = []

    def ext(ifc, ext_cmd, body=b'', cmd=0xf, c=A):
        pass
    mark('start')
    seqframes = []
    for ncount in (1, 2, 3, 4):
        # connect request: tid, rev, init, seq size, alg count, algs
        A.emit(bytes([0xf4]) + struct.pack('>H', 0x1234) + bytes([1, 1, 12, ncount])
               + bytes([1, 2, 3, 4][:ncount]))
    A.emit(bytes([0xf5]) + struct.pack('>H', 0x1234) + bytes([1, 12, 2]))
    A.emit(bytes([0xf9]) + struct.pack('>H', 0x1234) + bytes([1, 15, 1, 0]))
    A.emit(bytes([0xfa]) + struct.pack('>H', 0x1234) + bytes([1, 15, 1, 0]))
    A.emit(bytes([0xfb]) + struct.pack('>H', 0x1234))
    A.emit(bytes([0xfc]) + struct.pack('>H', 0x1234))
    for e in (6, 7, 8, 0xd, 0xe, 1, 2, 3):      # extended commands without a decoder
        A.emit(bytes([0xf0 | e]) + struct.pack('>H', 0x1234))
    for cmd in (2, 3, 4, 5, 8, 14):             # unknown commands
        A.emit(struct.pack('>H', (cmd << 12) | 7) + b'\x00\x01\x02')
    mark('control')

    # ---- circuit A: window fill, exactly. Uncompressed first.
    A.uncompressed(nlpid_ip(60, 1))
    A.uncompressed(nlpid_ip(120, 2))
    A.compressed(nlpid_ip(200, 3))
    A.compressed(nlpid_ip(200, 3))               # an exact repeat
    A.compressed(nlpid_ip(900, 4), ppc=True)     # per packet compression
    A.compressed(nlpid_ip(2048, 5))              # the largest packet
    mark('A-start')
    fill_to(A, 0, 100)
    assert A.win.cur == 0
    mark('A-filled')
    # the window has wrapped: references reach back across the end
    for k in range(6):
        A.compressed(nlpid_ip(400 + 100 * k, 3 + k), ppc=(k % 2 == 1))
    A.uncompressed(nlpid_ip(300, 9))
    mark('A-after-wrap')

    # ---- circuit B (the other direction of the same Ethernet circuit)
    B.compressed(nlpid_ip(500, 11))
    B.compressed(nlpid_ip(500, 11))
    fill_to(B, 400, 200)
    # a cmd 1 packet longer than the room left: copied in two pieces
    B.uncompressed(nlpid_ip(700, 12))
    B.compressed(nlpid_ip(600, 13))
    mark('B')

    # ---- Frame Relay circuit
    F.compressed(nlpid_ip(300, 21))
    F.compressed(nlpid_ip(300, 21), ppc=True)
    F.uncompressed(nlpid_ip(80, 22))
    fill_to(F, 150, 300)
    # exactly the room left: stores up to the end and wraps to the start
    F.uncompressed(nlpid_ip(150, 23))
    assert F.win.cur == 0
    F.compressed(nlpid_ip(350, 24))
    mark('F')

    frames = []
    # interleave the circuits so that they are decoded in capture order
    frames += A.frames[:0]
    allf = A.frames + B.frames + F.frames
    pcapng(os.path.join(outdir, 'wcp-coverage.pcapng'), ifaces, allf)
    print('main frames', len(allf), marks)
    malformed(outdir, ifaces)


def raw_items(c, items, ppc=False, check=b'\x00'):
    """Emit a compressed packet from explicit items, no model update."""
    body = Window.pack(items) + check
    if ppc:
        c.emit(wcp_packet(0xf, 0, body, ext=0))
    else:
        c.seq += 1
        c.emit(wcp_packet(0, c.seq, body))


def malformed(outdir, ifaces):
    fr = []

    def eth(n, payload):
        return (0, bytes([2, 0, 0, 0, 0, 1 + n, 2, 0, 0, 0, 0, 2 + n])
                + struct.pack('>H', 0x80ff) + payload)

    # 1. the second pass reproducer: a reference into an empty window fails
    # on the first pass, a later packet fills the window
    fr.append(eth(10, bytes([0x00, 0x01, 0x80, 0x00, 0x00, 0x00])))
    fr.append(eth(10, bytes([0x00, 0x02, 0x00]) + b'ABCDEFGH' + bytes([0x00])))
    # a short reference with count 1 into the data that is there now
    fr.append(eth(10, bytes([0x00, 0x03, 0x80, 0x00, 0x03, 0x00])))
    # 2. the window-stuck reproducer: the window is filled exactly
    c = Circuit(0, n=20)
    lit = b''.join(b'\x00' + bytes(range(i * 8, i * 8 + 8)) for i in range(32))
    c.emit(wcp_packet(0, 1, lit + b'\x00'))
    LR = bytes([0x10, 0xff, 0xff])
    for k in range(15):
        c.emit(wcp_packet(0, 2 + k, b'\xff' + LR * 8 + b'\x00'))
    c.emit(wcp_packet(0, 17, b'\xfe' + LR * 6 + bytes([0x10, 0xff, 0xfe]) + b'\x00'))
    for k in range(3):
        c.emit(wcp_packet(0, 18 + k, b'\x00Z\x00'))
    fr += c.frames
    # 3. failures that depend on the window state, with a window that
    # has some data and one that has little room left
    c = Circuit(0, n=30)
    c.compressed(nlpid_ip(400, 31))
    # offset beyond the initialized part of the window
    raw_items(c, [('lit', 0x41), ('ref', 3000, 5), ('lit', 0x42)])
    # count larger than offset + 1
    raw_items(c, [('lit', 0x41), ('ref', 2, 10)])
    # data count 3 with offset 1 (just fails), count 2 offset 1 fits
    raw_items(c, [('ref', 1, 2), ('ref', 1, 3)])
    # decompressed length over 2048 through long references
    raw_items(c, [('ref', 255, 256)] * 9)
    # ... through a literal after 8 long references (2048 exactly)
    raw_items(c, [('ref', 255, 256)] * 8 + [('lit', 0x41)])
    # ... and exactly 2048, which is fine
    raw_items(c, [('ref', 255, 256)] * 8)
    # references and literals ending in the middle of a field
    c.emit(wcp_packet(0, 9, bytes([0x80, 0x00]) + b'\x00'))
    c.emit(wcp_packet(0, 10, bytes([0x80, 0x10, 0x00]) + b'\x00'))
    c.emit(wcp_packet(0, 11, bytes([0x80, 0x10, 0x00, 0x02]) + b'\x00'))
    # only a flag octet
    c.emit(wcp_packet(0, 12, bytes([0x80]) + b'\x00'))
    fr += c.frames
    # a packet that does not fit in the room left: fill the window to
    # 100 octets from its end, then send 200 octets
    c = Circuit(0, n=40)
    fill_to(c, 100, 41)
    raw_items(c, [('lit', 0x41)] * 8 * 25)
    c.emit(wcp_packet(0, 99, b'\x00ABCDEFGH\x00'))
    # the same over per packet compression
    raw_items(c, [('lit', 0x42)] * 120, ppc=True)
    fr += c.frames
    # 4. compressed data of more than 2048 octets
    c = Circuit(0, n=50)
    raw_items(c, [('lit', 0x41)] * 1900)
    fr += c.frames
    # 5. uncompressed data longer than the window, shorter than 3 octets
    fr.append(eth(60, wcp_packet(1, 1, b'\xcc' + b'\x00' * 33000)))
    fr.append(eth(61, struct.pack('>H', 0x1002)))
    fr.append(eth(61, struct.pack('>H', 0x1003) + b'\x00'))
    fr.append(eth(61, bytes([0x10])))
    # a frame that is not even one header long
    fr.append(eth(62, b''))
    # 6. truncated extended commands, truncated data
    fr.append(eth(63, bytes([0xf4, 0x12])))
    fr.append(eth(63, bytes([0xf4]) + struct.pack('>H', 0x1234) + bytes([1, 1, 12, 4, 1, 2])))
    fr.append(eth(63, bytes([0xf5, 0x12, 0x34, 1])))
    fr.append(eth(63, bytes([0xf9, 0x12, 0x34, 1, 15])))
    fr.append(eth(63, bytes([0xfb, 0x12])))
    # captured shorter than the frame: compressed and uncompressed
    c = Circuit(0, n=70)
    lit = Window.pack([('lit', 0x41 + (i % 20)) for i in range(40)])
    pk = eth(70, wcp_packet(0, 1, lit + b'\x00'))
    fr.append((0, pk[1], len(pk[1]) - 20))
    pk = eth(70, wcp_packet(1, 2, nlpid_ip(100, 7) + b'\x00'))
    fr.append((0, pk[1], len(pk[1]) - 20))
    # truncated in the middle of the extended header
    fr.append((0, eth(71, bytes([0xf0, 0, 0, 0]))[1], 15))
    # per packet compression that is too short for a check byte
    fr.append(eth(72, bytes([0xf0])))
    # and the same on the other direction (second interface)
    fr.append((1,) + eth(10, bytes([0x00, 0x01, 0x80, 0x00, 0x00, 0x00]))[1:])
    fr.append((1,) + eth(10, bytes([0x00, 0x02, 0x00]) + b'ABCDEFGH' + bytes([0x00]))[1:])
    pcapng(os.path.join(outdir, 'wcp-coverage-malformed.pcapng'), ifaces, fr)
    print('malformed frames', len(fr))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

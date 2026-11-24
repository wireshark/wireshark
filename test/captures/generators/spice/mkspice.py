#!/usr/bin/env python3
# Generates test/captures/spice_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the SPICE coverage captures: mkspice.py <outdir>.
Everything is built with struct and zlib; nothing comes from a real
network. The "ticket" the client sends and the RSA public key the server
sends in the link reply are filler bytes, not real key material."""
import struct
import sys
import os
import gzip
import zlib

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

class Pcap:
    def __init__(self, fn):
        self.f = open(fn, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.t = 0
        self.n = 0
        self.ipid = 1
        self.cport = 40000

    def close(self):
        self.f.close()

class Conn:
    """One TCP connection; the client talks to the SPICE server on sport."""
    def __init__(self, pcap, sport=5930, syn=True):
        self.p = pcap
        pcap.cport += 1
        self.cport, self.sport = pcap.cport, sport
        self.cip = bytes([10, 0, 0, 1]); self.sip = bytes([10, 0, 0, 2])
        self.seq = {0: 1000, 1: 5000}
        if syn:
            self.send(True, b'', 0x02)
            self.send(False, b'', 0x12)
            self.send(True, b'', 0x10)

    def send(self, from_client, payload, flags=0x18):
        p = self.p
        d = 0 if from_client else 1
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        ack = self.seq[1 - d] if flags & 0x10 else 0
        t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack, 0x50,
                        flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
        c = csum(ph + t + payload)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        p.ipid += 1
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t) + len(payload), p.ipid,
                         0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        mc = b'\x02\0\0\0\0\x01'; ms = b'\x02\0\0\0\0\x02'
        eth = (ms + mc if from_client else mc + ms) + b'\x08\x00'
        pkt = eth + ip + t + payload
        p.t += 1; p.n += 1
        p.f.write(struct.pack('<IIII', p.t, 0, len(pkt), len(pkt)) + pkt)
        self.seq[d] += len(payload) + (1 if flags & 3 else 0)

    def c(self, b): self.send(True, b)
    def s(self, b): self.send(False, b)
    def split(self, from_client, b, *cuts):
        last = 0
        for x in list(cuts) + [len(b)]:
            self.send(from_client, b[last:x]); last = x

# ---------------------------------------------------------------- link
CH_MAIN, CH_DISPLAY, CH_INPUTS, CH_CURSOR, CH_PLAYBACK, CH_RECORD, CH_TUNNEL, \
    CH_SMARTCARD, CH_USBREDIR, CH_PORT = range(1, 11)
AUTH_SEL, AUTH_SPICE, AUTH_SASL, MINI = 1, 2, 4, 8
PUBKEY = bytes((i * 7 + 3) & 0xff for i in range(162))      # filler, not a key
TICKET = bytes((i * 5 + 1) & 0xff for i in range(128))      # filler, not RSA output

def link_hdr(body):
    return b'REDQ' + struct.pack('<III', 2, 2, len(body)) + body

def link_client(chan, cid=0, common=(AUTH_SPICE,), chcaps=(), conn_id=0x1234abcd, caps_off=18):
    b = struct.pack('<IBBIII', conn_id, chan, cid, len(common), len(chcaps), caps_off)
    b += b''.join(struct.pack('<I', x) for x in list(common) + list(chcaps))
    return link_hdr(b)

def link_server(common=(AUTH_SPICE,), chcaps=(), err=0):
    b = struct.pack('<I', err) + PUBKEY + struct.pack('<III', len(common), len(chcaps), 178)
    b += b''.join(struct.pack('<I', x) for x in list(common) + list(chcaps))
    return link_hdr(b)

def handshake(c, chan, cid=0, ccommon=(AUTH_SPICE,), scommon=(AUTH_SPICE,),
              cch=(), sch=(), select=AUTH_SEL and 1):
    """Link, optional authentication selection, ticket and link result."""
    c.c(link_client(chan, cid, ccommon, cch))
    c.s(link_server(scommon, sch))
    if ccommon and scommon and (ccommon[0] & AUTH_SEL) and (scommon[0] & AUTH_SEL):
        c.c(struct.pack('<I', select))
    c.c(TICKET)
    c.s(struct.pack('<I', 0))

# --------------------------------------------------------------- data PDUs
class Hdr:
    def __init__(self, mini=False):
        self.mini = mini
        self.serial = 0
    def __call__(self, typ, body, sublist=0):
        if self.mini:
            return struct.pack('<HI', typ, len(body)) + body
        self.serial += 1
        return struct.pack('<QHII', self.serial, typ, len(body), sublist) + body

def rect(l=0, t=0, r=16, b=16):
    return struct.pack('<IIII', l, t, r, b)

def clip(rects=None):
    if rects is None:
        return b'\x00'
    return b'\x01' + struct.pack('<I', len(rects)) + b''.join(rect(*x) for x in rects)

def dbase(surface=0, rects=None):
    return struct.pack('<I', surface) + rect() + clip(rects)

def imgdesc(typ, w=2, h=2, flags=0, iid=0x1122334455667788):
    return struct.pack('<QBBII', iid, typ, flags, w, h)

def mask(bitmap=1):
    return b'\x00' + struct.pack('<ii', 3, 4) + struct.pack('<I', bitmap) + (imgdesc(0) if bitmap else b'')[:0]

def mask_with_image(bitmap=1):
    # The dissector reads a mask (13) followed by an image descriptor (18)
    return struct.pack('<BiiI', 0, 3, 4, bitmap) + imgdesc(0)

def jpeg():
    return (b'\xff\xd8' + b'\xff\xe0' + struct.pack('>H', 16) + b'JFIF\0\x01\x01\x00\x00\x01\x00\x01\x00\x00' +
            b'\xff\xc0' + struct.pack('>H', 11) + b'\x08\x00\x08\x00\x08\x01\x01\x11\x00' +
            b'\xff\xda' + struct.pack('>H', 8) + b'\x01\x01\x00\x00\x3f\x00' + b'\x01\x02\x03\x04' + b'\xff\xd9')

def lz_common(typ, size, islz=True, glz=False):
    """size bytes of LZ/GLZ image payload (after the size field)."""
    b = b'  ZL' + struct.pack('>HH', 1, 2)
    if islz:
        b += b'\0\0\0'
    b += bytes([typ])
    b = b.ljust(size, b'\x5a')
    return b

def image(typ, variant=0):
    d = imgdesc(typ)
    if typ == 0:       # bitmap: 2 rows of stride 8
        return d + struct.pack('<BBIIII', 8, 0, 2, 2, 8, 0) + bytes(range(16))
    if typ == 1:       # quic: size, magic, versions, type, w, h, data
        q = b'QUIC' + struct.pack('<HHIII', 0, 1, 4, 2, 2) + b'\x00' * 8
        return d + struct.pack('<I', len(q)) + q
    if typ == 100:     # lz plt
        data = b'\x11' * 8
        sz = len(data) + 2
        return d + b'\x01' + struct.pack('<II', sz, 16) + b'  ZL' + struct.pack('>HH', 1, 1) + \
            struct.pack('>IIIII', 5, 2, 2, 8, 1) + data
    if typ == 101:     # lz rgb; variant picks the LZ image type
        lt = [8, 6, 9, 10, 5][variant % 5]
        p = lz_common(lt, 48, True)
        return d + struct.pack('<I', len(p)) + p
    if typ == 102:     # glz rgb
        lt = [8, 10, 9][variant % 3]
        p = lz_common(lt, 48, False)
        return d + struct.pack('<I', len(p)) + p
    if typ in (103, 106):
        return d
    if typ == 104:
        return d + struct.pack('<I', 7)
    if typ == 105:
        j = jpeg()
        return d + struct.pack('<I', len(j)) + j
    if typ == 107:
        raw = lz_common(8, 48, False)
        z = zlib.compress(raw)
        return d + struct.pack('<II', len(raw), len(z)) + z
    if typ == 108:
        j = jpeg()
        alpha = lz_common(8, max(48, len(j)), True)
        return d + b'\x00' + struct.pack('<II', len(j), len(j) + len(alpha)) + j + alpha
    raise ValueError(typ)

def brush(kind):
    if kind == 'solid': return b'\x01' + struct.pack('<I', 0x00ff8800)
    if kind == 'pattern': return b'\x02' + struct.pack('<Iii', 5, 1, 2)
    return b'\x00'

# ----------------------------------------------------------- the capture
def main(out):
    os.makedirs(out, exist_ok=True)
    pc = Pcap(os.path.join(out, 'spice-coverage.pcap'))

    # ============ main channel: link, no authentication selection
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_MAIN, 0, (AUTH_SPICE,), (AUTH_SPICE,), (0xf,), (0xf,))
    # common messages
    c.s(H(3, struct.pack('<II', 1, 20)))                                    # SET_ACK
    c.s(H(4, struct.pack('<IQ', 7, 123456789) + b'padding' * 3))            # PING with data
    c.s(H(4, struct.pack('<IQ', 8, 123456790)))                             # PING
    msg = b'Notify message'
    c.s(H(7, struct.pack('<QIIII', 1, 1, 2, 77, len(msg)) + msg + b'\0'))   # NOTIFY
    c.c(H(1, struct.pack('<I', 1)))                                         # ACK_SYNC
    c.c(H(2, b''))                                                          # ACK
    c.c(H(3, struct.pack('<IQ', 7, 123456789)))                             # PONG
    # server main messages
    c.s(H(103, struct.pack('>I', 0xdeadbeef) + struct.pack('<IIIIIII', 1, 3, 1, 1, 10, 5, 4096)))  # INIT
    c.s(H(104, struct.pack('<I', 3) + bytes([1, 0, 2, 0, 3, 0])))           # CHANNELS_LIST
    c.s(H(105, struct.pack('<HH', 3, 2)))                                   # MOUSE_MODE
    c.s(H(106, struct.pack('<I', 987654)))                                  # MULTI_MEDIA_TIME
    c.s(H(108, struct.pack('<I', 0)))                                       # AGENT_DISCONNECTED
    c.s(H(110, struct.pack('<I', 10)))                                      # AGENT_TOKEN
    c.s(H(115, struct.pack('<I', 12)))                                      # AGENT_CONNECTED_TOKENS
    c.s(H(113, struct.pack('<I', 7) + b'vm-name'))                          # NAME
    c.s(H(114, bytes(range(16))))                                           # UUID
    c.s(H(102, b''))                                                        # MIGRATE_CANCEL
    c.s(H(112, b''))                                                        # MIGRATE_END
    c.s(H(117, b''))                                                        # DST_SEAMLESS_ACK
    c.s(H(118, b''))                                                        # DST_SEAMLESS_NACK
    mig = struct.pack('<HHI', 5900, 5901, 4) + b'host' + struct.pack('<I', 4) + b'cert'
    c.s(H(101, mig))                                                        # MIGRATE_BEGIN
    c.s(H(111, mig))                                                        # MIGRATE_SWITCH_HOST
    c.s(H(116, mig + struct.pack('<I', 1)))                                 # MIGRATE_BEGIN_SEAMLESS
    # agent messages, server side
    def agent(typ, body, opaque=0):
        return struct.pack('<IIQI', 1, typ, opaque, len(body)) + body
    c.s(H(109, agent(1, struct.pack('<iiIB', 100, 200, 5, 0))))            # MOUSE_STATE
    c.s(H(109, agent(2, struct.pack('<II', 2, 1) + struct.pack('<IIIii', 600, 800, 32, 0, 0) * 2)))
    c.s(H(109, agent(3, struct.pack('<II', 4, 1))))                         # REPLY
    c.s(H(109, agent(4, b'clipboard text data')))                           # CLIPBOARD
    c.s(H(109, agent(5, struct.pack('<I', 1))))                             # DISPLAY_CONFIG
    c.s(H(109, agent(6, struct.pack('<II', 1, 0x3ff))))                     # ANNOUNCE_CAPABILITIES
    c.s(H(109, agent(7, struct.pack('<B', 1) + b'\0\0\0')))                 # CLIPBOARD_GRAB
    c.s(H(109, agent(8, struct.pack('<B', 1) + b'\0\0\0' + struct.pack('<I', 1))))  # REQUEST
    c.s(H(109, agent(9, b'')))                                              # CLIPBOARD_RELEASE
    # client main messages
    c.c(H(105, struct.pack('<H', 2)))                                       # MOUSE_MODE_REQUEST
    c.c(H(104, b''))                                                        # ATTACH_CHANNELS
    c.c(H(106, struct.pack('<I', 10)))                                      # AGENT_START
    c.c(H(107, agent(6, struct.pack('<II', 1, 0x3ff))))                     # AGENT_DATA (caps)
    c.c(H(107, agent(1, struct.pack('<iiIB', 1, 2, 3, 0))))                 # AGENT_DATA (mouse)
    # several PDUs in one TCP segment, and one PDU in three segments
    c.s(H(106, struct.pack('<I', 1)) + H(106, struct.pack('<I', 2)) + H(110, struct.pack('<I', 3)))
    b = H(104, struct.pack('<I', 3) + bytes([1, 0, 2, 0, 3, 0]))
    c.split(False, b, 5, 20)

    # ============ display channel: authentication selection (spice), full headers
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_DISPLAY, 0, (AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (AUTH_SEL | AUTH_SPICE | AUTH_SASL,),
              (0x7fff,), (0x7fff,), select=1)
    c.c(H(101, struct.pack('<BQBI', 1, 1 << 20, 1, 16 << 20)))             # DISPLAY_INIT
    c.s(H(101, struct.pack('<III', 1024, 768, 32)))                         # MODE
    c.s(H(102, b''))                                                        # MARK
    c.s(H(103, b''))                                                        # RESET
    c.s(H(105, struct.pack('<H', 2) + b''.join(struct.pack('<BQ', 1, i) for i in (5, 6))))  # INVAL_LIST
    c.s(H(108, b''))                                                        # INVAL_ALL_PALETTES
    c.s(H(104, dbase(1, [(0, 0, 4, 4), (4, 4, 8, 8)]) + struct.pack('<ii', 10, 20)))  # COPY_BITS
    for typ in (306, 307, 308):                                             # BLACKNESS, WHITENESS, INVERS
        c.s(H(typ, dbase(0) + mask_with_image(1)))
    # DRAW_FILL: solid, pattern and none brushes
    for kind in ('solid', 'pattern', 'none'):
        body = dbase(0) + brush(kind) + struct.pack('<H', 0xd) + mask_with_image(1)
        if kind != 'solid':
            body += image(0)
        c.s(H(302, body))
    c.s(H(312, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<II', 0x123456, 0x654321) + image(0)))
    for typ in (304, 305):                                                  # COPY, BLEND
        for it in (0, 1, 100, 101, 102, 103, 104, 105, 106, 107, 108):
            c.s(H(typ, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 1) +
                  mask_with_image(1) + image(it)))
    for v in range(1, 5):                                                   # all LZ_RGB / GLZ variants
        c.s(H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
              mask_with_image(1) + image(101, v)))
        c.s(H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
              mask_with_image(1) + image(102, v)))
    c.s(H(309, dbase(0) + struct.pack('<I', 1) + rect() + brush('solid') + b'\xaa\x01' +
          mask_with_image(1) + image(0)))                                   # ROP3
    c.s(H(313, dbase(0) + b'\x00\xff' + struct.pack('<I', 1) + rect() + image(0)))  # ALPHA_BLEND
    c.s(H(310, dbase(0)))                                                   # STROKE
    c.s(H(124, struct.pack('<I', 1) + clip([(0, 0, 8, 8)])))                # STREAM_CLIP rects
    c.s(H(124, struct.pack('<I', 1) + clip()))                              # STREAM_CLIP none
    sc = struct.pack('<IIBBQIIII', 0, 1, 1, 1, 1000, 640, 480, 640, 480) + rect()
    c.s(H(122, sc + clip()))                                                # STREAM_CREATE
    c.s(H(122, sc + clip([(1, 1, 5, 5)])))
    j = jpeg()
    c.s(H(123, struct.pack('<III', 1, 5000, len(j)) + j))                   # STREAM_DATA
    c.s(H(125, struct.pack('<I', 1)))                                       # STREAM_DESTROY
    c.s(H(316, struct.pack('<IIIII', 1, 6000, 320, 240, 0)[:16] + rect() + struct.pack('<I', 0)))  # DATA_SIZED
    c.s(H(126, b''))                                                        # STREAM_DESTROY_ALL
    c.s(H(314, struct.pack('<IIIII', 1, 800, 600, 32, 1)))                  # SURFACE_CREATE
    c.s(H(315, struct.pack('<I', 1)))                                       # SURFACE_DESTROY
    c.s(H(317, struct.pack('<HH', 2, 4) + struct.pack('<IIIIIII', 0, 0, 800, 600, 0, 0, 1) * 2))  # MONITORS_CONFIG
    c.s(H(318, b''))                                                        # DRAW_COMPOSITE
    c.s(H(319, struct.pack('<IIII', 1, 2, 3, 4)))                           # STREAM_ACTIVATE_REPORT
    # a big message split into several TCP segments, and two in one segment
    big = H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
            mask_with_image(1) + image(0))
    c.split(False, big, 7, 40, 90)
    c.s(H(126, b'') + H(315, struct.pack('<I', 2)))

    # ============ display channel with mini headers
    c = Conn(pc)
    H = Hdr(mini=True)
    handshake(c, CH_DISPLAY, 1, (AUTH_SEL | AUTH_SPICE | MINI,), (AUTH_SEL | AUTH_SPICE | MINI,),
              (0x1f,), (0x1f,), select=1)
    c.c(H(101, struct.pack('<BQBI', 1, 1 << 20, 1, 16 << 20)))
    c.s(H(101, struct.pack('<III', 1920, 1080, 32)))
    c.s(H(314, struct.pack('<IIIII', 0, 1920, 1080, 32, 1)))
    c.s(H(104, dbase(0) + struct.pack('<ii', 1, 1)))
    c.s(H(3, struct.pack('<II', 2, 10)))                                    # common message in mini form
    c.s(H(126, b''))
    c.c(H(2, b''))                                                          # common client message, mini

    # ============ inputs channel: server without authentication selection
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_INPUTS, 0, (AUTH_SEL | AUTH_SPICE,), (AUTH_SPICE,), (1,), (1,))
    c.s(H(101, struct.pack('<H', 0x7)))                                     # INIT
    c.s(H(102, struct.pack('<H', 0x2)))                                     # KEY_MODIFIERS
    c.s(H(111, b''))                                                        # MOUSE_MOTION_ACK
    c.c(H(101, struct.pack('<I', 0x1e)))                                    # KEY_DOWN
    c.c(H(102, struct.pack('<I', 0x1e)))                                    # KEY_UP
    c.c(H(103, struct.pack('<H', 0x5)))                                     # KEY_MODIFIERS
    c.c(H(112, struct.pack('<iiHB', 100, 200, 0x3, 0)))                     # MOUSE_POSITION
    c.c(H(111, struct.pack('<iiH', 3, -4, 0x5)))                            # MOUSE_MOTION
    c.c(H(113, struct.pack('<BH', 1, 0x1)))                                 # MOUSE_PRESS
    c.c(H(114, struct.pack('<BH', 1, 0x0)))                                 # MOUSE_RELEASE

    # ============ cursor channel
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_CURSOR, 0, (AUTH_SPICE,), (AUTH_SPICE,), (1,), (1,))
    def redcursor(flags, typ=0, w=2, h=2, data=None):
        if flags == 1:
            return struct.pack('<H', 1)
        b = struct.pack('<HQBHHHH', flags, 0xabcdef, typ, w, h, 1, 1)
        if flags == 4 or w == 0 or h == 0:
            return b
        if typ == 0: n = (w << 2) * h
        elif typ == 1: n = ((w + 7) & ~7) // 4 * h
        else: n = 0
        return b + (data if data is not None else b'\x80' * n)
    pt = struct.pack('<hh', 5, 6)
    c.s(H(101, pt + struct.pack('<HHB', 5, 2, 1) + redcursor(2)))           # INIT, alpha cursor
    c.s(H(101, pt + struct.pack('<HHB', 5, 2, 0) + redcursor(1)))           # INIT, NONE flags
    c.s(H(103, pt + b'\x01' + redcursor(2, 1, 8, 4)))                       # SET, mono cursor
    c.s(H(103, pt + b'\x01' + redcursor(4)))                                # SET, from cache
    c.s(H(103, pt + b'\x01' + redcursor(2, 0, 0, 0)))                       # SET, empty
    c.s(H(102, b''))                                                        # RESET
    c.s(H(104, pt))                                                         # MOVE
    c.s(H(105, b''))                                                        # HIDE
    c.s(H(106, struct.pack('<HH', 3, 4)))                                   # TRAIL
    c.s(H(107, struct.pack('<Q', 0xabcdef)))                                # INVAL_ONE
    c.s(H(108, b''))                                                        # INVAL_ALL
    c.c(H(2, b''))

    # ============ playback channel
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_PLAYBACK, 0, (AUTH_SPICE,), (AUTH_SPICE,), (0xf,), (0xf,))
    c.s(H(102, struct.pack('<IH', 1000, 1)))                                # MODE raw
    c.s(H(103, struct.pack('<IHII', 2, 1, 44100, 1000)))                    # START
    c.s(H(101, struct.pack('<I', 1010) + bytes(range(64))))                 # DATA
    c.s(H(105, struct.pack('<B', 2) + struct.pack('<HH', 100, 200)))        # VOLUME
    c.s(H(106, b'\x01'))                                                    # MUTE
    c.s(H(107, struct.pack('<I', 50)))                                      # LATENCY
    c.s(H(104, b''))                                                        # STOP
    c.c(H(2, b''))                                                          # client: ACK (no playback client msgs)
    c.c(H(101, b'x'))                                                       # a playback client message (ignored)

    # ============ record channel
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_RECORD, 0, (AUTH_SPICE,), (AUTH_SPICE,), (7,), (7,))
    c.c(H(102, struct.pack('<IH', 1000, 1)))                                # MODE
    c.s(H(102, b''))                                                        # STOP
    c.s(H(103, struct.pack('<B', 2) + struct.pack('<HH', 100, 200)))        # VOLUME
    c.s(H(104, b'\x00'))                                                    # MUTE

    # ============ usbredir, port and smartcard/tunnel channels
    c = Conn(pc)
    H = Hdr()
    handshake(c, CH_USBREDIR, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    c.c(H(101, b'usb data from the client'))
    c.s(H(101, b'usb data from the server'))
    c = Conn(pc)
    H = Hdr()
    # client announces mini headers, server does not: full headers are used
    handshake(c, CH_PORT, 0, (AUTH_SPICE | MINI,), (AUTH_SPICE,))
    c.s(H(201, struct.pack('<I', 5) + b'port1' + b'\x01'))                  # PORT_INIT
    c.s(H(202, b'\x03'))                                                    # PORT_EVENT
    c.s(H(101, b'port data'))                                               # data
    c.c(H(201, b'\x02'))                                                    # client PORT_EVENT
    c.c(H(101, b'client port data'))

    # ============ SASL authentication, then wrapped data
    c = Conn(pc)
    handshake_pre = c
    c.c(link_client(CH_MAIN, 0, (AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.s(link_server((AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.c(struct.pack('<I', 2))                                               # SASL selected
    mechs = b'GSSAPI,DIGEST-MD5,PLAIN'
    c.s(struct.pack('<I', len(mechs)) + mechs)                              # SASL_INIT_FROM_SERVER
    mech = b'DIGEST-MD5'
    cout = b'client out data'
    c.c(struct.pack('<I', len(mech)) + mech + struct.pack('<I', len(cout)) + cout)   # START_TO_SERVER
    sd = b'server start data'
    c.s(struct.pack('<I', len(sd)) + sd + struct.pack('<I', 0))             # START_FROM_SERVER (two PDUs)
    c.s(b'\x00')                                                            # START_FROM_SERVER_CONT: continue
    c.c(struct.pack('<I', len(cout)) + cout)                                # STEP_TO_SERVER
    c.s(struct.pack('<I', len(sd)) + sd)                                    # STEP_FROM_SERVER
    c.s(b'\x00')                                                            # STEP_FROM_SERVER_CONT
    c.s(struct.pack('<I', 0))                                               # TICKET_SERVER (link result)
    wrapped = bytes((i * 3) & 0xff for i in range(40))                      # placeholder, not ciphertext
    c.c(struct.pack('>I', len(wrapped)) + wrapped)                          # SASL_DATA, client
    c.s(struct.pack('>I', 20) + wrapped[:20] + struct.pack('>I', 12) + wrapped[:12])   # two PDUs
    c.s(struct.pack('>I', 0))                                               # empty PDU
    c.s(struct.pack('>I', len(wrapped)) + wrapped[:10])                     # split PDU ...
    c.s(wrapped[10:])
    # SASL with an empty client-out list and an empty server step
    c = Conn(pc)
    c.c(link_client(CH_MAIN, 0, (AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.s(link_server((AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.c(struct.pack('<I', 2))
    c.s(struct.pack('<I', len(mechs)) + mechs)
    c.c(struct.pack('<I', len(mech)) + mech + struct.pack('<I', 0))        # empty client-out
    c.s(struct.pack('<I', 0))
    c.s(b'\x00')
    c.c(struct.pack('<I', 0))                                               # empty step
    c.s(struct.pack('<I', 0))
    c.s(b'\x00')
    pc.close()

    # ========================================================== malformed
    pm = Pcap(os.path.join(out, 'spice-coverage-malformed.pcap'))
    # (1) reproducer: server message size wraps (0xFFFFFFEE + 18 == 0), no
    #     handler for the message: used to loop forever
    c = Conn(pm)
    H = Hdr()
    handshake(c, 0x7f, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    c.s(struct.pack('<QHII', 1, 101, 0xFFFFFFEE, 0))
    # (1b) the same in mini header mode (0xFFFFFFFA + 6 == 0)
    c = Conn(pm)
    handshake(c, CH_MAIN, 0, (AUTH_SPICE | MINI,), (AUTH_SPICE | MINI,), (1,), (1,))
    c.s(struct.pack('<HI', 101, 0xFFFFFFFA))
    # (1c) client direction, wrapping size with a known handler
    c = Conn(pm)
    handshake(c, CH_MAIN, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    c.c(struct.pack('<QHII', 1, 101, 0xFFFFFFEE, 0))
    # (2) server message that does not advance the offset (message size 0
    #     for an unknown message type): no-progress guard
    c = Conn(pm)
    handshake(c, 0x7f, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    c.s(struct.pack('<QHII', 1, 150, 0, 0))
    # (3) SASL: wrapped lengths in every SASL state
    for last in ('init', 'start', 'startfrom', 'step', 'stepfrom', 'data'):
        c = Conn(pm)
        c.c(link_client(CH_MAIN, 0, (AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
        c.s(link_server((AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
        c.c(struct.pack('<I', 2))
        bad = struct.pack('<I', 0xFFFFFFFC)
        if last == 'init':
            c.s(bad); continue
        mechs = b'PLAIN'
        c.s(struct.pack('<I', len(mechs)) + mechs)
        if last == 'start':
            c.c(bad); continue
        c.c(struct.pack('<I', 5) + b'PLAIN' + struct.pack('<I', 0))
        if last == 'startfrom':
            c.s(bad); continue
        c.s(struct.pack('<I', 0)); c.s(b'\x00')
        if last == 'step':
            c.c(bad); continue
        c.c(struct.pack('<I', 0))
        if last == 'stepfrom':
            c.s(bad); continue
        c.s(struct.pack('<I', 0)); c.s(b'\x00'); c.s(struct.pack('<I', 0))
        c.c(struct.pack('>I', 0xFFFFFFFC))
    # (4) SASL start-from-server-cont with a result other than "continue"
    c = Conn(pm)
    c.c(link_client(CH_MAIN, 0, (AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.s(link_server((AUTH_SEL | AUTH_SPICE | AUTH_SASL,), (0xf,)))
    c.c(struct.pack('<I', 2))
    c.s(struct.pack('<I', 5) + b'PLAIN')
    c.c(struct.pack('<I', 5) + b'PLAIN' + struct.pack('<I', 0))
    c.s(struct.pack('<I', 0))
    c.s(b'\x01')
    # (5) authentication selection: server data while the client is expected;
    #     an unknown selection
    c = Conn(pm)
    c.c(link_client(CH_MAIN, 0, (AUTH_SEL | AUTH_SPICE,), (1,)))
    c.s(link_server((AUTH_SEL | AUTH_SPICE,), (1,)))
    c.s(struct.pack('<I', 9))                                               # from the server
    c.c(struct.pack('<I', 9))                                               # unknown method
    # (6) link with an unknown channel type, unknown common and channel caps
    c = Conn(pm)
    c.c(link_client(0x55, 0, (AUTH_SPICE, 0x10), (1, 2)))
    c.s(link_server((AUTH_SPICE, 0x20), (1,), err=7))
    c.c(TICKET)
    c.s(struct.pack('<I', 2))
    # inputs and cursor channel caps, more than one word for bitmask channels
    c = Conn(pm)
    c.c(link_client(CH_MAIN, 0, (AUTH_SPICE,), (1, 2)))
    c.s(link_server((AUTH_SPICE,), (3, 4, 5)))
    c = Conn(pm)
    c.c(link_client(CH_DISPLAY, 0, (AUTH_SPICE,), (1, 2)))
    c.s(link_server((AUTH_SPICE,), (3, 4)))
    c = Conn(pm)
    c.c(link_client(CH_RECORD, 0, (AUTH_SPICE,), (1, 2)))
    c.s(link_server((AUTH_SPICE,), (3, 4)))
    c = Conn(pm)
    c.c(link_client(CH_PLAYBACK, 0, (AUTH_SPICE,), (1, 2)))
    c.s(link_server((AUTH_SPICE,), (3, 4)))
    c = Conn(pm)
    c.c(link_client(CH_INPUTS, 0, (AUTH_SPICE,), (1, 2)))
    c.s(link_server((AUTH_SPICE,), (3, 4)))
    # (7) data messages the dissector has no handler for
    def bad_conn(chan, msgs_c=(), msgs_s=(), common=(AUTH_SPICE,)):
        c = Conn(pm)
        H = Hdr()
        handshake(c, chan, 0, common, common)
        for t, b in msgs_c:
            c.c(H(t, b))
        for t, b in msgs_s:
            c.s(H(t, b))
    # common messages, unknown
    bad_conn(CH_MAIN, [(5, b'1234'), (1, b'abcd'), (4, b'')], [(1, b'1234'), (5, b'xx'), (6, b'')])
    # main, unknown client and server messages
    bad_conn(CH_MAIN, [(101, b'abcd'), (110, b'')], [(107, b'1234'), (150, b'')])
    # unknown agent message
    def agent(typ, body):
        return struct.pack('<IIQI', 1, typ, 0, len(body)) + body
    bad_conn(CH_MAIN, [(107, agent(10, b'abcd'))], [(109, agent(10, b'abcd'))])
    bad_conn(CH_DISPLAY, [(102, b'12'), (101 + 4, b'')],
             [(106, b''), (107, b''), (303, b''), (320, b''), (321, b''), (150, b'')])
    # display: masks without a bitmap, brushes of an unknown type, unknown image type
    c = Conn(pm)
    H = Hdr()
    handshake(c, CH_DISPLAY, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    c.s(H(306, dbase(0) + struct.pack('<BiiI', 0, 3, 4, 0)))                # mask without bitmap
    c.s(H(302, dbase(0) + b'\x09' + struct.pack('<H', 0xd) + mask_with_image(1)))   # brush type 9
    c.s(H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
          mask_with_image(1) + imgdesc(77) + b'\0' * 8))                    # unknown image type
    c.s(H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
          mask_with_image(1) + imgdesc(107) + struct.pack('<II', 48, 12) + b'not zlib data'))  # inflate error
    c.s(H(304, dbase(0) + struct.pack('<I', 1) + rect() + struct.pack('<HB', 0xd, 0) +
          mask_with_image(1) + image(0) + b'trailing'))                     # more bytes than dissected
    # DRAW_TEXT: the glyph flags item does not advance the offset (observation)
    c.s(H(311, dbase(0) + struct.pack('<I', 1) + rect() + brush('solid') +
          struct.pack('<HHHH', 1, 2, 3, 0x1234)))
    c.s(H(311, dbase(0) + struct.pack('<I', 1) + rect(4, 4, 4, 9) +
          struct.pack('<HHHH', 1, 2, 3, 0x1234)))
    # display client: unknown messages
    c.c(H(102, b'1234'))
    # cursor: colour cursors (size not computed), unknown messages
    c = Conn(pm)
    H = Hdr()
    handshake(c, CH_CURSOR, 0, (AUTH_SPICE,), (AUTH_SPICE,))
    for typ in (2, 3, 4, 5, 6, 9):
        c.s(H(103, struct.pack('<hh', 1, 1) + b'\x01' +
              struct.pack('<HQBHHHH', 2, 7, typ, 4, 4, 0, 0) + b'\x80' * 16))
    c.s(H(150, b''))
    c.c(H(101, b''))
    # inputs, playback, record, port, usbredir, tunnel, smartcard unknown messages
    bad_conn(CH_INPUTS, [(104, b'1234'), (150, b'')], [(150, b'')])
    bad_conn(CH_PLAYBACK, [], [(150, b'')])
    bad_conn(CH_RECORD, [(101, b'12'), (150, b'')], [(101, b''), (150, b'')])
    bad_conn(CH_PORT, [(150, b'')], [(150, b'')])
    bad_conn(CH_USBREDIR, [(150, b'')], [(150, b'')])
    bad_conn(CH_TUNNEL, [(101, b'1234'), (102, b'')], [(101, b'1234'), (150, b'')])
    bad_conn(CH_SMARTCARD, [(101, b'1234')], [(101, b'1234')])
    # a data PDU on a connection whose link had an unknown channel type
    bad_conn(0x66, [(101, b'')], [(101, b'')])
    # (8) truncated link and data PDUs; link header that claims more than it has
    c = Conn(pm)
    c.c(link_client(CH_MAIN)[:20])
    c = Conn(pm)
    c.c(link_client(CH_MAIN, 0, (AUTH_SPICE,), (1,)))
    c.s(link_server((AUTH_SPICE,), (1,))[:100])
    c = Conn(pm)
    H = Hdr()
    handshake(c, CH_MAIN, 0, (AUTH_SPICE,), (AUTH_SPICE,), (1,), (1,))
    c.s(H(103, struct.pack('>I', 1) + b'\0' * 8))                           # INIT, too short
    c.s(H(104, struct.pack('<I', 100) + b'\x01\x00'))                       # channel list longer than data
    # a ticket from the server while the client's is expected, and the TICKET_SERVER state seen from the client
    c = Conn(pm)
    c.c(link_client(CH_MAIN, 0, (AUTH_SPICE,), (1,)))
    c.s(link_server((AUTH_SPICE,), (1,)))
    c.s(TICKET)                                                             # server data in TICKET_CLIENT
    c.c(TICKET)
    c.c(struct.pack('<I', 0))                                               # client data in TICKET_SERVER
    c.s(struct.pack('<I', 0))
    pm.close()
    with open(os.path.join(out, 'spice-coverage.pcap'), 'rb') as f, \
         gzip.GzipFile(os.path.join(out, 'spice_coverage.pcap.gz'), 'wb', 9, mtime=0) as g:
        g.write(f.read())

if __name__ == '__main__':
    main(sys.argv[1])

#!/usr/bin/env python3
# Generates test/captures/udx_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the UDX coverage captures. Usage: mkudx.py <outdir>
#
# UDX's UDP heuristic ("UDX over UDP", udx_udp) is disabled by default, so
# the main frames are Exported PDU frames (link type 252) that name the
# "udx" dissector and carry the IPv4 addresses and UDP ports. The last
# frames are plain Ethernet/IPv4/UDP datagrams for the heuristic's header
# test (they need --enable-heuristic udx_udp; by default they are UDP).
# The file is pcapng so that both link types fit.
import os
import struct
import sys

def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v

def epdu(src, dst, sport, dport, payload):
    h = tlv(12, b'udx')
    h += tlv(20, bytes(src)) + tlv(21, bytes(dst))
    h += tlv(24, struct.pack('>I', 3))          # EXP_PDU_PT_UDP
    h += tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport))
    return h + tlv(0, b'') + payload

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_udp(src, dst, sport, dport, pl, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(pl), 0) + pl
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + ip + u

def pcapng_block(t, body):
    n = 12 + len(body)
    return struct.pack('<II', t, n) + body + struct.pack('<I', n)

def write(fn, frames, t0=1700000000):
    """frames: (linktype, timestamp seconds, bytes[, original length])"""
    out = pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (252, 1):
        out += pcapng_block(1, struct.pack('<HHI', lt, 0, 262144))
    for fr in frames:
        lt, ts, pk = fr[:3]
        orig = fr[3] if len(fr) > 3 else len(pk)
        us = int(round((t0 + ts) * 1e6))
        pad = (-len(pk)) % 4
        out += pcapng_block(6, struct.pack('<IIIII', 0 if lt == 252 else 1, us >> 32,
                                           us & 0xffffffff, len(pk), orig) + pk + bytes(pad))
    with open(fn, 'wb') as f:
        f.write(out)

A, B = [192, 0, 2, 1], [192, 0, 2, 2]
DATA, END, SACK, MSG, DESTROY, HB = 1, 2, 4, 8, 0x10, 0x20

class Capture:
    def __init__(self):
        self.frames = []

    def pkt(self, t, conv, d, flags, ident, seq=0, ack=0, win=65536, payload=b'',
            sacks=(), doff=None):
        """One UDX packet of conversation conv=(a, b, pa, pb), d=0 from a to b."""
        a, b, pa, pb = conv
        if flags & SACK:
            body = b''.join(struct.pack('<II', s, e) for s, e in sacks)
            if doff is None:
                doff = len(body) if payload else 0
            if len(body) > 255:
                doff = doff if doff is not None else 0
        else:
            body = bytes(doff or 0)
        h = struct.pack('<BBBBIIII', 0xff, 1, flags, (doff or 0) & 0xff, ident, win, seq, ack)
        pl = h + body + payload
        src, dst, sp, dp = (a, b, pa, pb) if d == 0 else (b, a, pb, pa)
        self.frames.append((252, t, epdu(src, dst, sp, dp, pl)))

def build():
    c = Capture()
    p = c.pkt
    # ---- Conversation 8 (first in the file, so that its stream number is 0): the first packet is from A, the stream's first
    # data from B (the server); payload arriving out of order is held and
    # released for Follow Stream, and a gap stays open
    C8 = (A, B, 40700, 40701)
    p(-10, C8, 0, HB, 0xB0, 0, 0)
    p(-9.99, C8, 1, DATA, 0xA0, 0, 0, payload=b'part 0|')
    p(-9.98, C8, 1, DATA, 0xA0, 2, 0, payload=b'part 2|')       # early, held
    p(-9.979, C8, 1, DATA, 0xA0, 4, 0, payload=b'part 4|')       # early, held
    p(-9.97, C8, 1, DATA, 0xA0, 1, 0, payload=b'part 1|')       # releases 1 and 2
    p(-9.96, C8, 1, DATA, 0xA0, 2, 0, payload=b'part 2|')       # already delivered
    p(-9.95, C8, 0, 0, 0xB0, 1, 3)
    p(-9.94, C8, 0, DATA, 0xB0, 1, 3, payload=b'client reply|')
    p(-9.93, C8, 1, DATA, 0xA0, 6, 2, payload=b'part 6|')       # held behind the gap at 5
    p(-9.929, C8, 1, DATA, 0xA0, 6, 2, payload=b'part 6|')       # a second copy held
    p(-9.92, C8, 1, DATA, 0xA0, 3, 2, payload=b'part 3|')       # releases 3, then 4
    p(-9.91, C8, 1, DATA, 0xA0, 5, 2, payload=b'part 5|')       # releases 5 and 6, drops the second 6

    C1 = (A, B, 40000, 40001)
    # ---- Conversation 1: three multiplexed streams. Ids: A->B packets carry
    # the receiver's id (0xB0 + n), B->A packets carry 0xA0 + n.
    p(0.000, C1, 0, DATA, 0xB0, 0, 0, payload=b'GET /index HTTP/1.0\r\n\r\n')   # no reverse yet
    p(0.010, C1, 1, 0, 0xA0, 0, 1)                                           # bare ACK: pairs
    p(0.020, C1, 0, DATA, 0xB0, 1, 0, payload=b'a' * 1000)
    p(0.021, C1, 0, DATA, 0xB0, 2, 0, payload=b'b' * 1000)
    p(0.030, C1, 1, DATA, 0xA0, 0, 3, payload=b'HTTP/1.0 200 OK\r\n\r\nbody0')
    p(0.040, C1, 0, DATA, 0xB0, 4, 1, payload=b'd' * 500)                    # seq 3 not captured
    p(0.041, C1, 0, DATA, 0xB0, 5, 1, payload=b'e' * 500)
    p(0.042, C1, 0, DATA, 0xB0, 6, 1, payload=b'f' * 500)
    p(0.050, C1, 1, SACK, 0xA0, 1, 3, sacks=[(4, 7)])                        # selective ack
    p(0.060, C1, 0, DATA, 0xB0, 3, 1, payload=b'c' * 500)                    # out of order
    p(0.110, C1, 0, DATA, 0xB0, 2, 1, payload=b'b' * 1000)                   # spurious
    p(0.120, C1, 1, 0, 0xA0, 1, 7)
    p(0.200, C1, 0, DATA, 0xB0, 7, 1, payload=b'g' * 100)
    p(0.201, C1, 0, DATA, 0xB0, 8, 1, payload=b'h' * 100)
    p(0.202, C1, 0, DATA, 0xB0, 9, 1, payload=b'i' * 100)
    p(0.210, C1, 1, SACK, 0xA0, 1, 7, sacks=[(8, 10)])
    p(0.260, C1, 0, DATA, 0xB0, 7, 1, payload=b'g' * 100)                    # fast retransmission
    p(0.300, C1, 0, DATA, 0xB0, 10, 1, payload=b'j' * 100)
    p(0.30030, C1, 0, DATA, 0xB0, 10, 1, payload=b'j' * 100)                 # duplicate datagram
    p(2.000, C1, 0, DATA, 0xB0, 10, 1, payload=b'j' * 100)                   # retransmission timeout
    p(3.000, C1, 0, DATA, 0xB0, 11, 1, payload=b'k' * 100)
    p(3.100, C1, 0, DATA, 0xB0, 11, 1, payload=b'k' * 100)                   # tail loss probe (repeat)
    p(3.500, C1, 0, DATA, 0xB0, 12, 1, payload=b'l' * 100)                   # tail loss probe (new data)
    p(3.510, C1, 0, DATA, 0xB0, 12, 1, payload=b'l' * 100)                   # plain retransmission
    p(3.600, C1, 1, 0, 0xA0, 1, 13)
    # zero window, probe, window update, keepalive
    p(4.000, C1, 1, 0, 0xA0, 1, 13, win=0)
    p(4.100, C1, 0, HB, 0xB0, 13, 1)
    p(4.200, C1, 1, 0, 0xA0, 1, 13, win=8192)
    p(4.300, C1, 0, HB, 0xB0, 13, 1)
    # MESSAGE (outside the stream), DATA|MESSAGE, MTU probe, END, DESTROY
    p(4.400, C1, 0, MSG, 0xB0, 13, 1, payload=b'datagram outside the stream')
    p(4.500, C1, 0, DATA, 0xB0, 13, 1, payload=b'mtu probe payload', doff=32)
    p(4.510, C1, 0, DATA, 0xB0, 14, 1, payload=b'p', doff=24)                # padding and one byte
    p(4.600, C1, 0, DATA | END, 0xB0, 15, 1, payload=b'last words')
    p(4.700, C1, 1, END, 0xA0, 1, 16)
    p(4.800, C1, 0, DESTROY, 0xB0, 16, 1)
    p(4.810, C1, 0, DESTROY | END, 0xB0, 16, 1)
    # selective acknowledgements: with payload and a delimited area, a long
    # list that runs to the end of the datagram, more blocks than the
    # dissector keeps, a range longer than the 1024 it walks, a range of
    # packets that were never captured
    p(4.900, C1, 0, DATA | SACK, 0xB0, 17, 1, payload=b'sack and data', sacks=[(0, 2), (5, 6)])
    p(5.000, C1, 1, SACK, 0xA0, 2, 18, sacks=[(i * 2, i * 2 + 1) for i in range(50)])
    p(5.010, C1, 1, SACK, 0xA0, 3, 18, sacks=[(i * 2, i * 2 + 1) for i in range(55)])
    p(5.020, C1, 1, SACK, 0xA0, 4, 18, sacks=[(0, 5000)])
    p(5.030, C1, 1, SACK, 0xA0, 5, 18, sacks=[(100, 110)])
    p(5.040, C1, 1, SACK, 0xA0, 6, 18, sacks=[(17, 18)])                      # new, selective
    # second stream: multiplexed over the same UDP flow
    p(6.000, C1, 0, DATA, 0xB1, 0, 0, payload=b'stream one request')
    p(6.010, C1, 1, DATA, 0xA1, 0, 1, payload=b'stream one reply')
    p(6.020, C1, 0, 0, 0xB1, 1, 1)
    p(6.030, C1, 1, DATA | END, 0xA1, 1, 1, payload=b'bye')
    # third stream: sequence numbers wrap
    p(7.000, C1, 0, DATA, 0xB2, 0xfffffffe, 0, payload=b'wrap-1')
    p(7.001, C1, 0, DATA, 0xB2, 0xffffffff, 0, payload=b'wrap-2')
    p(7.002, C1, 0, DATA, 0xB2, 0, 0, payload=b'wrap-3')
    p(7.003, C1, 0, DATA, 0xB2, 1, 0, payload=b'wrap-4')
    p(7.010, C1, 1, 0, 0xA2, 0, 2)
    p(7.020, C1, 1, DATA, 0xA2, 0, 0xffffffff, payload=b'reply to wrap')
    p(7.030, C1, 0, 0, 0xB2, 2, 1)

    # ---- Conversation 2: both endpoints have the same address, so the
    # direction comes from the ports
    C2 = ([127, 0, 0, 1], [127, 0, 0, 1], 45000, 45001)
    p(10.000, C2, 0, DATA, 0x10, 0, 0, payload=b'loopback request')
    p(10.001, C2, 1, DATA, 0x20, 0, 1, payload=b'loopback reply')
    p(10.002, C2, 0, 0, 0x10, 1, 1)
    p(10.003, C2, 1, 0, 0x20, 1, 1)

    # a packet that arrives below the lowest sequence number seen so far
    p(10.010, C2, 0, DATA, 0x30, 5, 0, payload=b'first seen is 5')
    p(10.011, C2, 0, DATA, 0x30, 3, 0, payload=b'then 3')

    # DATA|MESSAGE consumes a sequence number but stays out of Follow Stream
    p(10.030, C2, 0, DATA | MSG, 0x60, 0, 0, payload=b'data message')

    # ---- Conversation 3: pairing. Flows 10 and 11 cannot be paired (their
    # acknowledgements are past anything the other side sent); flow 12 sees
    # two equally good candidates and binds nothing; its next packet
    # separates them.
    C3 = (A, B, 40200, 40201)
    p(20.000, C3, 0, DATA, 1, 0, 0, payload=b'x1')
    p(20.001, C3, 0, DATA, 2, 0, 0, payload=b'x2')
    p(20.002, C3, 0, DATA, 2, 1, 0, payload=b'x2b')
    p(20.003, C3, 1, DATA, 10, 0, 50, payload=b'y0')
    p(20.004, C3, 1, DATA, 11, 0, 50, payload=b'y1')
    p(20.005, C3, 1, DATA, 12, 0, 1, payload=b'y2 tie')
    p(20.006, C3, 1, DATA, 12, 1, 2, payload=b'y2 resolved')

    # ---- Conversation 4: a flow that is older than the flow it pairs with
    C4 = (A, B, 40300, 40301)
    p(30.000, C4, 0, DATA, 1, 0, 9, payload=b'older')
    p(30.001, C4, 1, DATA, 2, 0, 5, payload=b'newer')
    p(30.002, C4, 0, DATA, 1, 1, 1, payload=b'older again')
    p(30.003, C4, 1, 0, 2, 1, 2)

    # ---- Conversation 5: heartbeats only; the paired flow never sent data
    C5 = (A, B, 40400, 40401)
    p(40.000, C5, 0, HB, 1, 0, 0)
    p(40.001, C5, 1, HB, 2, 0, 0)
    p(40.002, C5, 0, HB, 1, 0, 0)

    # ---- Conversation 6: at most 16 pairing attempts per flow. Flow 600
    # acknowledges something that was never sent for 15 packets and pairs
    # with its 16th; flow 601 needs a 17th and stays unpaired.
    C6 = (A, B, 40500, 40501)
    p(50.000, C6, 1, DATA, 500, 0, 0, payload=b'r0')
    p(50.001, C6, 1, DATA, 501, 0, 0, payload=b'r1')
    for i in range(15):
        p(50.010 + i * 0.001, C6, 0, 0, 600, 0, 1000)
    p(50.030, C6, 0, 0, 600, 0, 1)                               # 16th: paired
    for i in range(16):
        p(50.040 + i * 0.001, C6, 0, 0, 601, 0, 1000)
    p(50.060, C6, 0, 0, 601, 0, 1)                               # 17th: not tried
    p(50.061, C6, 0, 0, 601, 0, 1)

    # ---- Conversation 7: at most 256 flows per conversation. One reverse
    # flow and 255 flows the other way make 256; the 257th and 258th get no
    # analysis (no stream number) and a flow that exists is still analysed.
    C7 = (A, B, 40600, 40601)
    p(60.000, C7, 1, DATA, 1, 0, 0, payload=b'only reverse flow')
    for i in range(255):
        p(60.010 + i * 0.0001, C7, 0, 0, 1000 + i, 0, 0)
    p(60.100, C7, 0, 0, 2000, 0, 0)
    p(60.101, C7, 1, DATA, 2, 0, 0, payload=b'too many flows')
    p(60.102, C7, 0, 0, 1000, 0, 1)


    # ---- Conversation 9: a cumulative acknowledgement that walks over a
    # packet that was never captured (seq 1)
    C9 = (A, B, 40800, 40801)
    p(80.000, C9, 0, DATA, 1, 0, 0, payload=b'nine seq 0')
    p(80.001, C9, 0, DATA, 1, 2, 0, payload=b'nine seq 2')
    p(80.010, C9, 1, 0, 2, 0, 3)
    return c

def heur_frames(c):
    """Plain UDP datagrams for test_udx(); accepted ones claim the conversation."""
    t = 100.0
    def hdr(flags=DATA, doff=0, magic=0xff, ver=1, ident=7, seq=0, ack=0):
        return struct.pack('<BBBBIIII', magic, ver, flags, doff, ident, 65536, seq, ack)
    def add(port, pl, orig=None, ident=None):
        nonlocal t
        t += 0.001
        fr = eth_udp(A, B, port, port + 1, pl, int(t))
        orig_len = None
        if orig is not None:
            # captured shorter than reported
            orig_len = len(fr) + (orig - len(pl))
        c.frames.append((1, t, fr) + ((orig_len,) if orig_len else ()))
    add(43000, hdr() + b'accepted data')                       # accepted: DATA
    add(43000, hdr(HB, 0, seq=0))                               # claimed: bare heartbeat
    add(43000, b'\xff\x01\x00')                                 # claimed, shorter than a header
    add(43002, hdr(0, 0)[:19])                                  # captured 19 bytes: too short
    add(43004, hdr(magic=0xfe) + b'x')                          # wrong magic
    add(43006, hdr(ver=2) + b'x')                               # wrong version
    add(43008, hdr(flags=0x40) + b'x')                          # reserved flag
    add(43010, hdr(DATA, 200) + b'x')                           # data_offset past the end
    add(43012, hdr(DATA | SACK, 12) + bytes(12) + b'x')         # SACK area not a multiple of 8
    add(43014, hdr(0, 0) + b'abcd')                             # ACK with trailing bytes
    add(43016, hdr(SACK, 0) + bytes(13))                        # SACK blocks not a multiple of 8
    add(43018, hdr(SACK, 16) + struct.pack('<IIII', 0, 1, 4, 6))  # accepted: SACK only
    add(43020, hdr(MSG) + b'a message')                         # accepted: MESSAGE
    # a data packet truncated by the capture: the header test uses the
    # captured length
    add(43022, hdr(DATA) + b'x' * 100, orig=120)

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    c = build()
    heur_frames(c)
    write(os.path.join(outdir, 'udx-coverage.pcapng'), c.frames)
    # malformed capture: conditions only broken data reaches
    m = Capture()
    CM = (A, B, 41000, 41001)
    p = m.pkt
    p(0.0, CM, 0, DATA, 1, 0, 0, payload=b'start')
    # Exported PDU frames shorter than a header: dissect_udx() returns 0
    for n in (0, 5, 19):
        m.frames.append((252, 0.1 + n / 100, epdu(A, B, 41000, 41001, bytes([0xff, 1, 1, 0]) * 5)[:-20 + n]))
    # data_offset past the datagram (no SACK): padding clamped; SACK
    # area that is not a multiple of 8; zero data_offset SACK cut mid-block
    p(0.2, CM, 0, DATA, 1, 1, 0, payload=b'', doff=60)
    p(0.3, CM, 1, SACK, 2, 0, 1, sacks=[(0, 1)], doff=12)
    p(0.4, CM, 1, SACK, 2, 0, 1, sacks=[(0, 1)])
    m.frames.append((252, 0.45, m.frames[-1][2][:-3]))
    # many packets of one flow, each acknowledging more than was sent
    for i in range(40):
        p(1.0 + i * 0.001, CM, 1, DATA, 3, i, 5000 + i, payload=b'z')
    # reserved flag bits set (the header test would refuse them over UDP)
    m.frames.append((252, 2.0, epdu(A, B, 41002, 41003,
        struct.pack('<BBBBIIII', 0xff, 1, 0xff, 0, 1, 1, 1, 1) + b'bits')))
    write(os.path.join(outdir, 'udx-coverage-malformed.pcapng'), m.frames)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

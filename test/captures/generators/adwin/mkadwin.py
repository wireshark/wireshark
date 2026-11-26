#!/usr/bin/env python3
# ADwin coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ADwin communication protocol (packet-adwin.c): a PC talking to an ADwin
real-time system over UDP port 6543. The packet type is taken from the UDP
payload length, so every type is built to its exact length:

  UDPH1 old (52) and new (56): requests with an instruction and its arguments
  UDPR1 (32), UDPR2 (1008), UDPR3 (1408), UDPR4 (1416): responses
  GDSHR (64) and GDSHP (1356): Get Data Shifted Handshake request and data
  UDPH2 (412): unused, shown as such

Requests and responses are matched by the sequence number (the packet index).
The last three frames of the main capture reuse a sequence number: request,
response, request again; the response must stay linked to the first request
also in the second pass ("ADwin: Keep the request/response transaction per
frame").

Usage: mkadwin.py [<output directory>]

Writes adwin-coverage.pcap and adwin-coverage-malformed.pcap (frames cut
by the capture). Every packet is built here; nothing comes from a real
network.
"""

import os
import random
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, udp, write_pcap  # noqa: E402

PC = '192.0.2.1'
SYS = '192.0.2.2'
PC_MAC = '02:00:00:00:00:01'
SYS_MAC = '02:00:00:00:00:02'
PORT = 6543


def to_sys(payload, sport=40000):
    return eth(ipv4(udp(payload, sport, PORT, PC, SYS), 17, src=PC, dst=SYS),
               0x0800, dst=SYS_MAC, src=PC_MAC)


def to_pc(payload, dport=40000):
    return eth(ipv4(udp(payload, PORT, dport, SYS, PC), 17, src=SYS, dst=PC),
               0x0800, dst=PC_MAC, src=SYS_MAC)


class Pkt:
    """A zero-filled packet with little or big endian fields set by offset."""

    def __init__(self, size):
        self.b = bytearray(size)

    def u32(self, off, v, big=False):
        struct.pack_into('>I' if big else '<I', self.b, off, v & 0xffffffff)
        return self

    def u16(self, off, v, big=False):
        struct.pack_into('>H' if big else '<H', self.b, off, v)
        return self

    def f32(self, off, v):
        struct.pack_into('<f', self.b, off, v)
        return self

    def raw(self, off, data):
        self.b[off:off + len(data)] = data
        return self

    def done(self):
        return bytes(self.b)


def h1(instr, seq, size=52, pw=b'secret', link=0, timeout=2000, osys=0, dll=None):
    """UDPH1 request; the instruction specific part is set by the caller."""
    p = Pkt(size).u32(0, instr).u32(4, seq).raw(8, pw)
    p.u32(36, link).u32(40, timeout).u32(44, osys)
    if dll is not None:
        p.u32(52, dll)
    return p


def r1(status, seq, v1=0, v2=0, v3=0, v4=0, vf=None):
    p = Pkt(32).u32(0, status).u32(4, seq).u32(8, v1).u32(12, v2).u32(16, v3).u32(20, v4)
    if vf is not None:
        p.f32(8, vf)
    return p.done()


def r2(status, seq, rng):
    p = Pkt(1008).u32(0, status).u32(4, seq)
    for i in range(250):
        p.u32(8 + 4 * i, rng.getrandbits(32))
    return p.done()


def r3(seq, number, rng):
    p = Pkt(1408).u32(0, seq).u32(4, number)
    for i in range(350):
        p.u32(8 + 4 * i, rng.getrandbits(32))
    return p.done()


def r4(status, seq, number, dtype, rng):
    p = Pkt(1416).u32(0, status).u32(4, seq)
    for i in range(350):
        if dtype == 5:
            p.f32(8 + 4 * i, rng.uniform(-100, 100))
        else:
            p.u32(8 + 4 * i, rng.getrandbits(32))
    p.u32(1408, number).u32(1412, dtype)
    return p.done()


def gdshp(seq, number, rng):
    p = Pkt(1356).u32(0, seq, True).u32(4, number, True)
    for i in range(336):
        p.u32(12 + 4 * i, rng.getrandbits(32))
    return p.done()


def gdshr(seq, req_no, complete, is_range, start, end):
    return (Pkt(64).u32(0, seq, True).u32(4, req_no, True).u32(8, complete, True)
            .u32(12, is_range, True).u32(16, start, True).u32(20, end, True).done())


STATUSES = [0, 1, 2, 3, 4, 5, -100, -41, -40, -35, -33, -32, -31, -30, -26, -20, -15, -10, -5, -1]
OSYS = [0x00, 0x10, 0x20, 0x40, 0x80, 0x33]


def build():
    rng = random.Random(6543)
    f = []          # main capture
    seq = [100]

    def nextseq():
        seq[0] += 1
        return seq[0]

    def exchange(req, resp):
        f.append(to_sys(req))
        f.append(to_pc(resp))

    n = 0

    def ostat():
        nonlocal n
        n += 1
        return dict(osys=OSYS[n % len(OSYS)], link=0x1000 + n, timeout=1000 * n)

    # 3+1 instructions
    for code in (1, 2, 3, 5, 6, 9, 11, 12, 14, 15, 16, 17, 18, 19, 21, 22, 23, 99):
        s = nextseq()
        p = h1(0, s, **ostat()).u32(20, code)
        if code == 6:
            p.u32(24, 1101).f32(28, 1.5)
        elif code == 1:
            p.u32(24, 1001)
        elif code in (5, 12):
            p.u32(24, 2)
        elif code in (2, 3, 14):
            p.u32(24, 3)
        elif code == 11:
            p.u32(24, 7)
        elif code in (21, 22, 23):
            p.u32(24, 4)
        exchange(p.done(), r1(0, s, v1=42 * code, v2=code, v3=3, v4=4) if code != 6 else r1(0, s, vf=2.25))
    # Parameter values of the mapping (status, delays, debug, float parameters, timing analyzer)
    for par in (901, 911, 951, 1080, 1101, 1180, 4891, 10000, 10001, 5555):
        s = nextseq()
        exchange(h1(0, s, **ostat()).u32(20, 1).u32(24, par).done(), r1(0, s, v1=par))
    # Other instructions, UDPH1 old and new
    others = [4, 7, 8, 10, 13, 20, 24, 25, 50, 100, 107, 108, 124, 125, 207, 255, 1000, 1000000, 4242]
    for i, instr in enumerate(others):
        s = nextseq()
        size, dll = (52, None) if i % 2 == 0 else (56, 2003015 + i)
        p = h1(instr, s, size=size, dll=dll, **ostat())
        if instr == 4:
            p.u16(26, 1400).u32(28, 1).u32(32, 123456)
        elif instr == 50:
            p.u32(20, 1 << 20).u16(24, 1400).u32(28, 2).u32(32, 654321)
        elif instr in (7, 8):
            p.u32(20, 5).u16(24, 3).u16(26, 100).u32(28, 10).u32(32, 200)
        elif instr == 13:
            p.u32(20, 1).u32(24, 80)
        elif instr == 20:
            p.u32(20, 20)
        elif instr in (24, 25):
            p.u32(20, 3).u16(24, 2).u32(32, 64)
        elif instr == 100:
            p.u32(24, 6).u32(28, 1)
        elif instr == 107:
            p.u16(20, 5, True).u16(22, 100, True).u32(24, 0, True).u32(28, 1000, True)
        elif instr == 108:
            p.u32(20, 17)
        elif instr in (124, 125):
            p.u32(20, 4).u16(24, 1).u32(28, 9).u32(32, 128)
        elif instr == 207:
            p.u16(24, 2).u32(28, 3).u32(32, 4)
        elif instr == 1000:
            p.u32(20, 7)
        elif instr == 1000000:
            p.u32(20, 0x40000000).u32(24, 350)
        st = STATUSES[i % len(STATUSES)]
        exchange(p.done(), r1(st, s, v1=i, v2=2, v3=3, v4=4))
    # Responses, one of every type and error code
    for i, st in enumerate(STATUSES + [-25, 77]):
        s = nextseq()
        exchange(h1(7, s, **ostat()).u32(20, 3).u16(24, 1).u16(26, 350).u32(28, i * 350).u32(32, 350).done(),
                 r1(st, s) if i % 3 == 0 else r2(st, s, rng) if i % 3 == 1 else r4(st, s, i, 2, rng))
    s = nextseq()
    exchange(h1(7, s, **ostat()).u32(20, 3).u16(24, 1).u16(26, 250).u32(28, 0).u32(32, 250).done(), r2(77, s, rng))
    for dtype in (2, 3, 4, 5, 6, 20, 0, 99):
        s = nextseq()
        exchange(h1(7, s, **ostat()).u32(20, dtype).u16(24, 1).u16(26, 350).u32(28, 0).u32(32, 350).done(),
                 r4(0, s, 1, dtype, rng))
    # Fifo / data transfer with UDPR3 and Get Data Shifted Handshake
    s = nextseq()
    exchange(h1(24, s, **ostat()).u32(20, 5).u16(24, 1).u32(32, 350).done(), r3(s, 1, rng))
    s = nextseq()
    f.append(to_sys(h1(107, s, **ostat()).u16(20, 5, True).u16(22, 100, True).u32(24, 0, True).u32(28, 3, True).done()))
    f.append(to_pc(gdshp(s, 1, rng)))
    f.append(to_pc(gdshp(s, 2, rng)))
    f.append(to_sys(gdshr(s, 1, 2, 0, 3, 0)))
    f.append(to_sys(gdshr(s, 2, 2, 1, 1, 3)))
    f.append(to_sys(gdshr(s, 3, 3, 2, 0, 0)))
    f.append(to_sys(gdshr(s, 4, 3, 3, 9, 9)))
    # A response without a request, UDPH2 (unused), a length ADwin does not use
    f.append(to_pc(r1(0, 9999)))
    f.append(to_sys(bytes(412)))
    f.append(to_sys(bytes(100)))
    # Another client port: its own conversation
    f.append(to_sys(h1(1000, 7, **ostat()).u32(20, 3).done(), sport=40001))
    f.append(to_pc(r1(0, 7), dport=40001))
    # Sequence number reuse: request, response, request again. The response
    # stays linked to the first request in every pass.
    f.append(to_sys(h1(1000, 5000, **ostat()).done(), sport=40002))
    f.append(to_pc(r1(0, 5000), dport=40002))
    f.append(to_sys(h1(1000, 5000, **ostat()).done(), sport=40002))

    # Malformed: frames cut by the capture
    m = []
    for fr in (to_sys(h1(0, 1, **ostat()).u32(20, 6).done()),
               to_sys(h1(50, 2, size=56, dll=1002003).done()),
               to_pc(r1(0, 3)),
               to_pc(r2(0, 4, rng)),
               to_pc(r3(5, 1, rng)),
               to_pc(r4(0, 6, 1, 5, rng)),
               to_pc(gdshp(7, 1, rng)),
               to_sys(gdshr(8, 1, 1, 1, 1, 2)),
               to_sys(bytes(412))):
        for cut in (14 + 20 + 8 + 2, 14 + 20 + 8 + 22, 14 + 20 + 8 + 100):
            if cut < len(fr):
                m.append((fr[:cut], len(fr)))
    return f, m


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    clean, malformed = build()
    write_pcap(os.path.join(out, 'adwin-coverage.pcap'), clean)
    write_pcap(os.path.join(out, 'adwin-coverage-malformed.pcap'), malformed)
    print('%d + %d frames' % (len(clean), len(malformed)), file=sys.stderr)


if __name__ == '__main__':
    main()

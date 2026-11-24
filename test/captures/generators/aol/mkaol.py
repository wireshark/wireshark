#!/usr/bin/env python3
# AOL (P3 frame) coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""P3 frames for the AOL dissector (epan/dissectors/packet-aol.c).

Usage: mkaol.py [<output directory>]

Writes:
  aol-coverage.pcap            every P3 frame type, INIT in each layout the
                               dissector knows, data with and without a
                               token, heartbeats, PDUs split across TCP
                               segments and several in one segment, a
                               connection on port 15190 (for the tcp.port
                               preference)
  aol-coverage-malformed.pcap  P3 lengths below the 9 octet minimum and a
                               truncated INIT (exceptions)

TCP port 5190 goes to AOL by default (AIM registers it too, but AOL wins),
so no Decode As is needed. Every packet is built here; nothing comes from a
real network. Addresses are documentation addresses (192.0.2.0/24) and
locally administered MACs.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ipv4, tcp, write_pcap  # noqa: E402

AOL = 5190
ALT_PORT = 15190  # AOL here only with -o aol.tcp.port:5190,15190 or -d
SYN_OPTIONS = bytes.fromhex('020405b401030307')  # MSS, NOP, window scale


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def a4(n):
    return bytes([192, 0, 2, n])


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        s, d = a4(src), a4(dst)
        seg = tcp(payload, sport, dport, seq=seq, ack=ack, flags=flags,
                  options=SYN_OPTIONS if flags & 0x02 else b'', src=s, dst=d)
        ip = ipv4(seg, 6, src=s, dst=d, ident=len(self.frames) & 0xffff, flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst=mac(dst), src=mac(src)))

    def write(self, path):
        write_pcap(path, self.frames, snaplen=65535,
                   ts=lambda i: (1700000000 + i // 10, (i % 10) * 100000))


class Conn:
    """A TCP connection with a handshake and correct sequence numbers."""
    def __init__(self, cap, cport, sport=AOL, client=10, server=20):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.c, self.s = client, server
        self.cseq, self.sseq = 1000, 50000
        cap.tcp(client, server, cport, sport, self.cseq, 0, 0x02)
        cap.tcp(server, client, sport, cport, self.sseq, self.cseq + 1, 0x12)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(client, server, cport, sport, self.cseq, self.sseq, 0x10)

    def client(self, data):
        self.cap.tcp(self.c, self.s, self.cport, self.sport, self.cseq, self.sseq, 0x18, data)
        self.cseq += len(data)

    def server(self, data):
        self.cap.tcp(self.s, self.c, self.sport, self.cport, self.sseq, self.cseq, 0x18, data)
        self.sseq += len(data)

    def ack_client(self):
        self.cap.tcp(self.s, self.c, self.sport, self.cport, self.sseq, self.cseq, 0x10)

    def close(self):
        self.cap.tcp(self.c, self.s, self.cport, self.sport, self.cseq, self.sseq, 0x11)
        self.cap.tcp(self.s, self.c, self.sport, self.cport, self.sseq, self.cseq + 1, 0x11)
        self.cap.tcp(self.c, self.s, self.cport, self.sport, self.cseq + 1, self.sseq + 1, 0x10)


# ---------------------------------------------------------------------------
# P3 frames (WAOL.doc page 66)

DATA, SS, SSR, INIT, ACK, NAK, HEARTBEAT = range(0x20, 0x27)


def p3(tx, rx, ptype, data=b'', crc=0x1234, length=None):
    body = struct.pack('!BBB', tx, rx, ptype) + data
    return struct.pack('!BHH', 0x5a, crc, len(body) if length is None else length) + body + b'\x0d'


def init_data(platform=3, wmem=1, dos=0x0616, win=0x030a, tail=b''):
    """The 37 fixed octets of an INIT and what follows them."""
    return (struct.pack('<BBBBBBHBBHI', platform, 4, 0, 0, 16, 8, 0x0001, 5, 6, 0x0102, 1700000000)
            + struct.pack('!H', dos)
            + struct.pack('<HBBI', 0x0003, 1, 2, 0x00000004)
            + struct.pack('!H', win) + b'\0\0'
            + struct.pack('<BHHH', wmem, 640, 480, 256)
            + tail)


REGION_LANG_SPD = struct.pack('<H', 1) + struct.pack('<Q', 0x0807060504030201) + b'\x05'


def build_main():
    cap = Pcap()

    # ---- connection 1 (frames 1-27): login and every frame type
    c = Conn(cap, 40001)
    # WAOL > 1.5: filler, region, languages, speed (49 octets)
    c.client(p3(0x10, 0x7f, INIT, init_data(tail=b'\0' + REGION_LANG_SPD)))
    c.server(p3(0x10, 0x10, ACK))
    c.client(p3(0x11, 0x10, DATA, b'Dd' + b'screen name'))
    c.server(p3(0x11, 0x11, DATA, b'SD' + bytes(range(32))))
    c.client(p3(0x12, 0x11, SS))
    c.server(p3(0x12, 0x12, SSR))
    c.client(p3(0x13, 0x12, NAK))
    c.server(p3(0x13, 0x13, HEARTBEAT))
    c.client(p3(0x14, 0x13, HEARTBEAT))
    c.server(p3(0x14, 0x14, 0x27, b'??' + b'unknown'))           # unknown type
    c.client(p3(0x15, 0x14, 0x3f))                               # unknown, no data
    c.server(p3(0x15, 0x15, 0xe0 | DATA, b'hi' + b'x'))          # high type bits masked off
    c.client(p3(0x16, 0x15, DATA, b'Q'))                         # one octet: no token
    c.server(p3(0x16, 0x16, DATA, b'OK'))                        # token only
    c.client(p3(0x17, 0x16, ACK, b'aa'))                         # token on an ACK
    c.server(p3(0x17, 0x17, SS, b'Zz' + b'\x00\x01'))
    c.client(p3(0x18, 0x17, SSR, b'zZ' + b'\xff'))
    c.server(p3(0x18, 0x18, INIT))                               # INIT without data
    c.client(p3(0x19, 0x18, DATA, b'Dd' + b'\x00' * 1000))       # long data
    c.ack_client()
    c.client(b'Not a P3 frame')                                  # not AOL: rejected
    c.close()

    # ---- connection 2 (frames 28-39): every INIT layout
    c = Conn(cap, 40002)
    # WAOL 1.5: region, languages, speed, no filler (48 octets)
    c.client(p3(0x10, 0x7f, INIT, init_data(platform=0x0c, wmem=0, tail=REGION_LANG_SPD)))
    # WAOL 4.0: 52 octets, the octets after the fixed ones are not parsed
    c.client(p3(0x11, 0x7f, INIT, init_data(platform=3, win=0x0400, tail=bytes(range(15)))))
    # unknown platform, unknown memory mode
    c.client(p3(0x12, 0x7f, INIT, init_data(platform=7, wmem=2, dos=0x0700, win=0x0500,
                                             tail=b'\x01' + REGION_LANG_SPD)))
    # high type bits masked off
    c.client(p3(0x13, 0x7f, 0xc0 | INIT, init_data(tail=b'\0' + REGION_LANG_SPD)))
    # 47 octets: the speed is read from the end marker, so the end marker
    # is reported missing (a warning)
    c.client(p3(0x14, 0x7f, INIT, init_data(tail=REGION_LANG_SPD[:-1])))
    c.server(p3(0x10, 0x14, ACK))
    c.close()

    # ---- connection 3 (frames 40-57): reassembly
    c = Conn(cap, 40003)
    # a PDU over three segments
    p = p3(0x20, 0x10, DATA, b'Ab' + bytes(300))
    c.client(p[:100])
    c.client(p[100:200])
    c.client(p[200:])
    # a PDU split inside the 9 octet fixed part (and inside the length)
    p = p3(0x21, 0x10, DATA, b'Cd' + b'split header')
    c.client(p[:4])
    c.client(p[4:])
    p = p3(0x22, 0x10, HEARTBEAT)
    c.client(p[:7])
    c.client(p[7:])
    # several PDUs in one segment
    c.client(p3(0x23, 0x10, HEARTBEAT) + p3(0x24, 0x10, DATA, b'Ef' + b'one')
             + p3(0x25, 0x10, ACK) + p3(0x26, 0x10, DATA, b'Gh' + b'two'))
    # two PDUs and the start of a third, then the rest and a fourth
    p = p3(0x28, 0x10, DATA, b'Ij' + bytes(50))
    c.client(p3(0x27, 0x10, NAK) + p3(0x27, 0x10, SS) + p[:20])
    c.client(p[20:] + p3(0x29, 0x10, HEARTBEAT))
    # server side, several in one segment and split
    p = p3(0x10, 0x29, DATA, b'Kl' + bytes(80))
    c.server(p3(0x10, 0x29, ACK) + p[:30])
    c.server(p[30:])
    c.close()

    # ---- connection 4 (frames 58-70): further cases that decode
    # cleanly; the INIT has DOS version 6.22 and Windows 10.0
    c = Conn(cap, 40000)
    init = (bytes([3, 4, 0, 0, 16, 8]) + struct.pack('<H', 1) + bytes([5, 6]) + struct.pack('<HI', 0, 0)
            + struct.pack('!H', 0x0616) + struct.pack('<HBBI', 0, 1, 2, 0) + struct.pack('!H', 0x0a00)
            + b'\0\0' + bytes([1]) + struct.pack('<HHH', 640, 480, 256) + bytes([0])
            + struct.pack('<H', 1) + b'\0' * 8 + b'\x05')
    for p in (p3(0x10, 0x7f, 0x23, init, crc=0), p3(0x11, 0x10, 0x20, b'AT' + b'hello', crc=0),
              p3(0x12, 0x11, 0x26, crc=0), p3(0x13, 0x12, 0x20, b'\x01\x02', crc=0)):
        c.client(p)
    p = p3(0x14, 0x13, 0x20, b'ZZ' + b'x' * 100, crc=0)
    c.client(p[:7])
    c.client(p[7:])
    # a 65535 octet length the connection never delivers (left waiting
    # for reassembly)
    c.client(struct.pack('!BHH', 0x5a, 0, 0xffff) + b'\0' * 20)
    c.close()

    # ---- connection 5 (frames 71-78): AOL on port 15190
    c = Conn(cap, 40015, sport=ALT_PORT)
    c.client(p3(0x10, 0x7f, DATA, b'Pq' + b'other port'))
    c.server(p3(0x10, 0x10, DATA, b'Rs' + b'reply'))
    c.close()
    return cap


def build_malformed():
    cap = Pcap()
    c = Conn(cap, 41000)
    # a P3 frame with length 0 (6 octets, below
    # the 9 octet minimum), then end markers
    c.client(struct.pack('!BHH', 0x5a, 0, 0) + b'\x0d' * 4)
    c.close()
    c = Conn(cap, 41001)
    # lengths 1 and 2, each followed by a heartbeat
    c.client(struct.pack('!BHHB', 0x5a, 0, 1, 0x10) + b'\x0d' + p3(0x11, 0x10, HEARTBEAT))
    c.close()
    c = Conn(cap, 41002)
    c.client(struct.pack('!BHHBB', 0x5a, 0, 2, 0x10, 0x10) + b'\x0d' + p3(0x11, 0x10, HEARTBEAT))
    c.close()
    # INIT shorter than its 37 fixed octets, and one octet short of the
    # optional part
    c = Conn(cap, 41003)
    c.client(p3(0x10, 0x7f, INIT, init_data()[:20]))
    c.client(p3(0x11, 0x7f, INIT, init_data(tail=REGION_LANG_SPD[:-2])))
    c.close()
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main().write(os.path.join(out, 'aol-coverage.pcap'))
    build_malformed().write(os.path.join(out, 'aol-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

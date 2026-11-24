#!/usr/bin/env python3
# Generates test/captures/lisp_tcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LISP reliable transport
dissector (packet-lisp-tcp.c).

LISP reliable transport (draft-kouvelas-lisp-map-server-reliable-transport)
runs over TCP port 4342, which is registered, so no Decode As is needed.
Every packet is built from scratch with struct; no captured traffic is
used. Authentication data fields hold placeholder bytes only (zeros).

Usage: mklisp_tcp.py <output directory>

Writes:
  lisp-tcp-coverage.pcap            one TCP session with every message type
                                    (error notification, registration and
                                    its ACK/NACK/refresh/notification, the
                                    RLOC membership messages), messages
                                    split over TCP segments and several in
                                    one segment
  lisp-tcp-coverage-malformed.pcap  invalid lengths (including the 9 to 11
                                    range fixed on the branch), a bad end
                                    marker, truncated messages
"""

import os
import struct
import sys

MARK = 0x9FACADE9
AFI_IP, AFI_IP6, AFI_LCAF, AFI_MAC, AFI_DN = 1, 2, 16387, 6, 17
V4 = bytes([192, 0, 2, 1])
V6 = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
MAC = bytes.fromhex('0200c0a80001')
DN = b'eid.example\0'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, l4, src, dst):
    sa = bytes(map(int, src.split('.')))
    da = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, sa, da)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4, sa, da


class Tcp:
    """One TCP connection, client 192.0.2.1:50001 -> server 192.0.2.2:4342."""

    def __init__(self, cport=50001):
        self.c, self.s, self.cport, self.sport = '192.0.2.1', '192.0.2.2', cport, 4342
        self.cseq, self.sseq = 1000, 9000

    def seg(self, payload, flags, from_client):
        if from_client:
            src, dst, sp, dp, seq, ack = self.c, self.s, self.cport, self.sport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = self.s, self.c, self.sport, self.cport, self.sseq, self.cseq
        if flags == 0x02:
            ack = 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        hdr = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        l4 = hdr + payload
        ip, sa, da = ipv4(6, l4, src, dst)
        ck = csum(sa + da + struct.pack('!BBH', 0, 6, len(l4)) + l4)
        l4 = l4[:16] + struct.pack('!H', ck) + l4[18:]
        ip, _, _ = ipv4(6, l4, src, dst)
        syn = 1 if flags & 0x02 else 0
        if from_client:
            self.cseq += len(payload) + syn
            return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip
        self.sseq += len(payload) + syn
        return bytes.fromhex('020000000001020000000002') + b'\x08\x00' + ip

    def handshake(self):
        return [self.seg(b'', 0x02, True), self.seg(b'', 0x12, False), self.seg(b'', 0x10, True)]

    def data(self, payload, from_client=True):
        return self.seg(payload, 0x18, from_client)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def message(t, mid, data=b'', marker=MARK, length=None):
    ln = 12 + len(data) if length is None else length
    return struct.pack('!HHI', t, ln, mid) + data + struct.pack('!I', marker)


def short_message(t, length=8, marker=MARK):
    """A message without ID (length 8) or with a length field below 12."""
    return struct.pack('!HH', t, length) + struct.pack('!I', marker)


def afi_addr(kind):
    return {'none': struct.pack('!H', 0), 'v4': struct.pack('!H', AFI_IP) + V4,
            'v6': struct.pack('!H', AFI_IP6) + V6, 'mac': struct.pack('!H', AFI_MAC) + MAC,
            'dn': struct.pack('!H', AFI_DN) + DN}[kind]


def lcaf_iid(n, addr):
    body = struct.pack('!I', n) + addr
    return struct.pack('!H', AFI_LCAF) + struct.pack('!BBBBH', 0, 0, 2, 0, len(body)) + body


def prefix(plen, addr):
    return bytes([plen]) + addr


def locator(addr, prio=1, w=100, flags=0x5):
    return struct.pack('!BBBBH', prio, w, 255, 0, flags) + addr


def mapping(eid, masklen, locs, ttl=1440, act=0, auth=1):
    flags = (act << 13) | (0x1000 if auth else 0)
    return struct.pack('!IBBHH', ttl, len(locs), masklen, flags, 0) + eid + b''.join(locs)


NONCE = bytes.fromhex('1122334455667788')
AUTH = b'\x00' * 20   # placeholder authentication data
XTRID = bytes(range(16))
SITEID = bytes(range(0x20, 0x28))


def mapreg(recs, flags=0, tail=b'', auth=AUTH):
    w = flags
    return (struct.pack('!I', w)[1:] + bytes([len(recs)]) + NONCE + struct.pack('!HH', 1, len(auth)) + auth +
            b''.join(recs) + tail)


def build_main():
    F = []
    t = Tcp()
    F += t.handshake()
    d = lambda p, cl=True: F.append(t.data(p, cl))
    rl = [mapping(afi_addr('v4'), 24, [locator(afi_addr('v4')), locator(afi_addr('v6'), flags=0x3)])]
    # Error notification with offending message data
    d(message(16, 1, bytes([5]) + b'\x00\x00\x00' + struct.pack('!HHI', 17, 20, 7) + b'\xde\xad\xbe\xef'))
    d(message(16, 2, bytes([1]) + b'\x00\x00\x00' + struct.pack('!HHI', 99, 12, 8)), False)
    # Registration: Map-Register with and without xTR-ID
    d(message(17, 3, mapreg(rl, flags=0x080000 | 0x040000 | 0x000001)))
    d(message(17, 4, mapreg(rl, flags=0x020000, tail=XTRID + SITEID)))
    d(message(17, 5, mapreg([], flags=0x010000, auth=b'')))
    # Registration ACK for each EID prefix type
    for i, eid in enumerate(('v4', 'v6', 'mac', 'dn')):
        d(message(18, 6 + i, prefix(24, afi_addr(eid))), False)
    d(message(18, 10, prefix(24, lcaf_iid(1000, afi_addr('v4')))), False)
    # Registration NACK with each reason
    for i, reason in enumerate((1, 2, 3, 4, 9)):
        d(message(19, 11 + i, bytes([reason]) + b'\x00\x00' + prefix(32, afi_addr('v4'))), False)
    # Registration Refresh: scope 0 (no EID), 1..4, rejected-only flag
    d(message(20, 20, bytes([0]) + struct.pack('!H', 0x8000)), False)
    for i, sc in enumerate((1, 2, 3, 4, 7)):
        d(message(20, 21 + i, bytes([sc]) + struct.pack('!H', 0x0000 if i % 2 else 0x8000) +
                  prefix(24, afi_addr('v6' if i % 2 else 'v4'))), False)
    # Mapping Notification
    d(message(21, 30, XTRID + SITEID + mapping(afi_addr('v4'), 24, [locator(afi_addr('v4'))], act=1)), False)
    # RLOC membership messages
    d(message(22, 31, struct.pack('!HI', AFI_IP, 5000)))
    d(message(23, 32, struct.pack('!HII', AFI_IP, 5000, 77)), False)
    d(message(24, 33, struct.pack('!HII', AFI_IP6, 5001, 78) + bytes([1])), False)
    d(message(24, 34, struct.pack('!HII', AFI_IP6, 5001, 79) + bytes([3])), False)
    d(message(24, 35, struct.pack('!HII', AFI_IP6, 5001, 80) + bytes([9])), False)
    d(message(25, 36, struct.pack('!HI', AFI_IP, 5000)))
    d(message(26, 37, struct.pack('!HI', AFI_IP, 5000) + SITEID + afi_addr('v4')), False)
    d(message(26, 38, struct.pack('!HI', AFI_IP6, 5000) + SITEID + afi_addr('v6')), False)
    d(message(27, 39, struct.pack('!HI', AFI_IP, 5000) + SITEID + afi_addr('v4')), False)
    d(message(27, 40, struct.pack('!HI', AFI_IP, 5000) + SITEID + afi_addr('none')), False)
    d(message(28, 41, struct.pack('!HI', AFI_IP, 5000)))
    d(message(29, 42, struct.pack('!HII', AFI_IP, 5000, 1234)), False)
    d(message(30, 43, struct.pack('!HII', AFI_IP, 5000, 1234)), False)
    # unknown message types carry the data as is; the length 8 form has
    # no message ID
    d(message(5, 44, b'\x01\x02\x03'))
    d(message(40, 45, b''))
    d(short_message(16))
    # two messages in one segment, and one split over two segments (also
    # with the header split)
    m1 = message(22, 50, struct.pack('!HI', AFI_IP, 1))
    m2 = message(25, 51, struct.pack('!HI', AFI_IP, 1))
    d(m1 + m2)
    big = message(17, 52, mapreg(rl * 3, flags=0x020000, tail=XTRID + SITEID))
    d(big[:30])
    d(big[30:])
    h = message(30, 53, struct.pack('!HII', AFI_IP, 7, 8))
    d(h[:2], False)
    d(h[2:], False)
    d(m2[:13] + b'')
    d(m2[13:])
    return F


def build_malformed():
    F = []
    t = Tcp()
    F += t.handshake()
    d = lambda p, cl=True: F.append(t.data(p, cl))
    # message length 9 to 11 (fixed on the branch: the body used to be
    # dissected with a 16 bit length that wrapped to about 65530) and
    # below 8: expert info, body not dissected. Each PDU holds exactly
    # "length" octets.
    for ln in (9, 10, 11):
        d(struct.pack('!HH', 22, ln) + struct.pack('!I', MARK) + b'\x00' * (ln - 8))
    d(struct.pack('!HH', 22, 7) + b'\x00\x00\x00')       # below 8: marker past the PDU
    d(struct.pack('!HH', 22, 4))
    # bad end markers
    d(message(22, 60, struct.pack('!HI', AFI_IP, 5), marker=0x01020304))
    d(short_message(22, marker=0xffffffff))
    # unexpected AFIs in the EID prefix
    unk = struct.pack('!H', 99) + b'\x00' * 4
    d(message(18, 61, bytes([24]) + unk))
    d(message(19, 62, b'\x01\x00\x00' + bytes([24]) + unk))
    d(message(20, 63, b'\x01\x00\x00' + bytes([24]) + unk))
    d(message(17, 64, mapreg([mapping(unk, 24, [])])))
    # data after the decoded part: "Work-in-progress"
    d(message(18, 65, prefix(24, afi_addr('v4')) + b'\x01\x02'))
    d(message(22, 66, struct.pack('!HI', AFI_IP, 5) + b'\x01\x02'))
    # truncated messages and a length field larger than the data, each in
    # its own connection (the segment never completes the PDU unless TCP
    # desegmentation is off)
    cuts = [message(16, 67, b'\x01\x00\x00')[:16],
            message(26, 68, struct.pack('!HI', AFI_IP, 5) + SITEID + afi_addr('v4'))[:20],
            message(21, 69, XTRID + SITEID)[:30],
            message(20, 70, b'\x01\x00')[:15],
            struct.pack('!HHI', 22, 200, 71) + struct.pack('!HI', AFI_IP, 1)]
    for i, p in enumerate(cuts):
        u = Tcp(50010 + i)
        F += u.handshake()
        F.append(u.data(p))
    return F


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lisp-tcp-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lisp-tcp-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/bt_utp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the uTorrent Transport
Protocol dissector (packet-bt-utp.c, BEP 29) and the BitTorrent payload it
carries.

All packets are built from scratch with struct; no captured traffic is
used. BT-uTP has no port and its UDP heuristic (bt_utp_udp) is disabled
by default.

Usage: mkbt_utp.py <output directory>

Writes:
  bt_utp-coverage.pcapng            pcapng with an Ethernet interface (uTP
                                    streams: every packet type, extensions,
                                    BitTorrent messages, a multi-segment
                                    Piece, version 0 packets, packets the
                                    heuristic rejects) and an Exported PDU
                                    interface (BitTorrent messages for
                                    "bittorrent.utp", the reproducer of the
                                    NULL dereference fixed on the branch)
  bt_utp-coverage-malformed.pcapng  truncated packets (exceptions)
"""

import os
import struct
import sys

EPOCH = 1700000000
A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
C, D = bytes([192, 0, 2, 3]), bytes([192, 0, 2, 4])
E, F = bytes([192, 0, 2, 5]), bytes([192, 0, 2, 6])
G, H = bytes([192, 0, 2, 7]), bytes([192, 0, 2, 8])
LO = bytes([127, 0, 0, 1])
INFO_HASH = bytes(range(0x10, 0x24))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1, frag=0):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', src, dst, 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def eth(etype, payload):
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01' + struct.pack('>H', etype) + payload


def u4(src, dst, sport, dport, payload):
    return eth(0x0800, ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)))


# uTP version 1 header (BEP 29)
ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN = range(5)


def utp(typ, conn, seq, ack, data=b'', exts=(), wnd=0x100000, ts=0x11223344, tsdiff=0x1000):
    """exts: list of (type, body); the header carries the first type, each
    extension the type of the next one."""
    ext_bytes = b''
    first = exts[0][0] if exts else 0
    for i, (t, body) in enumerate(exts):
        nxt = exts[i + 1][0] if i + 1 < len(exts) else 0
        ext_bytes += bytes([nxt, len(body)]) + body
    return struct.pack('>BBHIIIHH', (typ << 4) | 1, first, conn, ts, tsdiff, wnd, seq, ack) + ext_bytes + data


def icmp_unreach(src, dst, quoted_ip):
    icmp = struct.pack('>BBHI', 3, 3, 0, 0) + quoted_ip
    icmp = icmp[:2] + struct.pack('>H', csum(icmp)) + icmp[4:]
    return eth(0x0800, ipv4(src, dst, 1, icmp))


def utp_v0(flags, conn, seq, ack, data=b'', ext=0, wnd=40):
    """Prerelease (version 0) header, 23 octets (libutp PacketFormat)."""
    return struct.pack('>IIIIBBBHH', conn, EPOCH, 123456, 2000, wnd, ext, flags, seq, ack) + data


# BitTorrent messages
def bt_msg(mtype, body=b''):
    return struct.pack('>IB', 1 + len(body), mtype) + body


def bt_handshake(peer):
    return b'\x13BitTorrent protocol' + b'\0\0\0\0\0\x10\0\x05' + INFO_HASH + peer


KEEPALIVE = b'\0\0\0\0'
CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED, HAVE, BITFIELD, REQUEST, PIECE, CANCEL = range(9)


def piece(index, begin, n, fill=b'P'):
    return bt_msg(PIECE, struct.pack('>II', index, begin) + (fill * n)[:n])


def clean_eth():
    P = []
    a = lambda d: P.append(u4(A, B, 6881, 6882, d))
    b = lambda d: P.append(u4(B, A, 6882, 6881, d))
    # Stream 0: A (receive ID 1000, send ID 1001) connects to B
    a(utp(ST_SYN, 1000, 1, 0))                                      # 1 SYN
    a(utp(ST_SYN, 1000, 1, 0))                                      # 2 SYN retransmission
    b(utp(ST_STATE, 1000, 50, 1, wnd=0x40000))                      # 3 STATE
    a(utp(ST_DATA, 1001, 2, 50, bt_handshake(b'-UT3550-' + b'A' * 12)))   # 4
    b(utp(ST_DATA, 1000, 51, 2, bt_handshake(b'-lt1230-' + b'B' * 12)))   # 5
    a(utp(ST_DATA, 1001, 3, 51, bt_msg(INTERESTED) + bt_msg(HAVE, struct.pack('>I', 7))))   # 6
    b(utp(ST_DATA, 1000, 52, 3, bt_msg(UNCHOKE), exts=[(1, b'\x80\x00\x00\x01')]))          # 7 SACK
    a(utp(ST_DATA, 1001, 4, 52, bt_msg(REQUEST, struct.pack('>III', 1, 0, 600)),
          exts=[(2, b'\0' * 8)]))                                                           # 8 ext bits
    # 9-11: a 613 octet Piece over three segments, the last one followed by a Have
    pc = piece(1, 0, 600)
    b(utp(ST_DATA, 1000, 53, 4, pc[:200]))
    b(utp(ST_DATA, 1000, 54, 4, pc[200:400]))
    b(utp(ST_DATA, 1000, 55, 4, pc[400:] + bt_msg(HAVE, struct.pack('>I', 1))))
    # 12: retransmission of the middle segment (inside the Piece, skipped)
    P.append(P[9])
    # 13: STATE with two extensions: SACK then extension bits
    a(utp(ST_STATE, 1001, 5, 55, exts=[(1, b'\xff\x00\x00\x00'), (2, b'\0' * 8)]))
    # 14: keepalive, a Not Interested and a Bitfield in one segment
    b(utp(ST_DATA, 1000, 56, 5, KEEPALIVE + bt_msg(NOT_INTERESTED) + bt_msg(BITFIELD, b'\xff\xc0')))
    # 15: data with an unknown message type: continuation data
    a(utp(ST_DATA, 1001, 6, 56, b'\0\0\0\x05\x63hello'))
    # 16: a Cancel cut after its length: "needs one more segment", not reassembled
    a(utp(ST_DATA, 1001, 7, 56, bt_msg(CANCEL, struct.pack('>III', 1, 0, 600)) + b'\0\0\0\x0d'))
    # 17: FIN with close reason Timeout
    a(utp(ST_FIN, 1001, 8, 56, exts=[(3, struct.pack('>I', 8))]))
    # 18: RESET with close reason 261, a SACK and an unknown extension type 9
    b(utp(ST_RESET, 1000, 57, 8, exts=[(3, struct.pack('>I', 261)), (1, b'\0\0\0\0'),
                                       (9, b'\1\2\3\4')]))
    # 19: STATE with a 6 octet close reason (Warning: unexpected length) and an unknown reason
    b(utp(ST_STATE, 1000, 58, 8, exts=[(3, struct.pack('>IH', 99, 0))]))
    # 20: SACK extension running to the end of the packet with another extension announced
    b(utp(ST_STATE, 1000, 59, 8, exts=[(1, b'\0\0\0\x01'), (2, b'')])[:-2])

    # Stream 1: first packet from D (no SYN seen): wildcard conversation; C answers
    # with ID-1 (D initiated)
    P.append(u4(D, C, 6881, 51413, utp(ST_DATA, 2000, 300, 20, bt_msg(CHOKE))))       # 21
    P.append(u4(C, D, 51413, 6881, utp(ST_STATE, 1999, 20, 300)))                   # 22
    P.append(u4(D, C, 6881, 51413, utp(ST_DATA, 2000, 301, 20, bt_msg(UNCHOKE))))     # 23
    # Stream 2: first packet from F with ID 3001, E answers with ID+1 (F initiated
    # from the other side's point of view)
    P.append(u4(F, E, 6881, 51414, utp(ST_STATE, 3001, 40, 10)))                    # 24
    P.append(u4(E, F, 51414, 6881, utp(ST_STATE, 3002, 10, 40)))                    # 25
    # Stream 3: both ends on 127.0.0.1, direction from the UDP ports
    P.append(u4(LO, LO, 6881, 6882, utp(ST_SYN, 4000, 1, 0)))                       # 26
    P.append(u4(LO, LO, 6882, 6881, utp(ST_STATE, 4000, 9, 1)))                     # 27
    P.append(u4(LO, LO, 6881, 6882, utp(ST_DATA, 4001, 2, 9, KEEPALIVE)))            # 28
    # 29-30: a Piece over two segments, the second one followed by a keepalive
    pc = piece(2, 0, 100)
    P.append(u4(LO, LO, 6882, 6881, utp(ST_DATA, 4000, 10, 2, pc[:60])))
    P.append(u4(LO, LO, 6882, 6881, utp(ST_DATA, 4000, 11, 2, pc[60:] + KEEPALIVE)))
    # 31-32: an Azureus Messaging Protocol BT_PIECE over two segments, the first one cut
    # inside the name length (BitTorrent stops quietly), the second followed by a Have
    amp = struct.pack('>I', 8) + b'BT_PIECE' + b'\x01' + struct.pack('>II', 3, 0) + b'Q' * 150
    amp = struct.pack('>I', len(amp)) + amp
    P.append(u4(LO, LO, 6882, 6881, utp(ST_DATA, 4000, 12, 2, amp[:7])))
    P.append(u4(LO, LO, 6882, 6881, utp(ST_DATA, 4000, 13, 2, amp[7:] + bt_msg(HAVE, b'\0\0\0\x03'))))
    # 33: an extended (BEP 10) handshake, bencoded
    P.append(u4(LO, LO, 6881, 6882, utp(ST_DATA, 4001, 3, 13,
                                        bt_msg(20, b'\0d1:md6:ut_pexi1ee1:v6:uTP0.1e'))))
    # 34: not uTP, in the UDP conversation of stream 0 (the conversation dissector rejects it)
    a(b'X' * 24)
    # 35: ICMP port unreachable from A quoting frame 11 (in an error packet there is no
    # segment length; the PDU tracking only gives the offset of the Have)
    P.append(icmp_unreach(A, B, P[10][14:]))

    # 36-38: version 0 (prerelease) packets, only with bt-utp.enable_version0
    # (otherwise UDP data); the dissector shows the first four payload octets
    # as a second Seq/Ack, so each carries four octets more
    P.append(u4(E, G, 50100, 50101, utp_v0(ST_SYN, 0x7f001234, 1, 0, b'\0\0\0\0')))
    P.append(u4(G, E, 50101, 50100, utp_v0(ST_STATE, 0x7f001234, 77, 1, b'\0\0\0\0')))
    P.append(u4(E, G, 50100, 50101, utp_v0(ST_DATA, 0x7f001235, 2, 77, b'\0\0\0\0' + bt_msg(HAVE, b'\0\0\0\x03'))))

    # 39-46: packets the heuristic rejects (each on its own ports)
    rej = lambda port, d: P.append(u4(G, H, port, 9000, d))
    # (State packets: Data with extension 1 looks like a Classic STUN Binding Response)
    rej(40001, b'\x41' * 19)                                                # shorter than 20
    rej(40002, utp(ST_STATE, 1, 0x1234, 1, exts=[(1, b'')])[:21])           # extension, 1 octet left
    rej(40003, utp(ST_STATE, 1, 0x1234, 1, exts=[(1, b'\0' * 4), (5, b'')])[:20] + b'\5\4\0\0\0\0')  # next ext 5
    rej(40004, utp(ST_STATE, 1, 0x1234, 1, exts=[(1, b'\0\0')]))             # extension length 2
    rej(40005, utp(ST_STATE, 1, 0x1234, 1, KEEPALIVE, wnd=0x400000))        # window above the maximum
    rej(40006, b'\x51' + utp(ST_STATE, 1, 0x1234, 1)[1:])                    # type 5
    rej(40007, b'\x52' + utp(ST_STATE, 1, 0x1234, 1)[1:21])                  # version 2, 21 octets (V0 too short)
    rej(40008, b'\x52' + utp(ST_STATE, 1, 0x1234, 1, b'\0\0\0\0')[1:])       # version 2, V0 flags 0x12
    return P


def clean_exppdu():
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v
    hdr = tag(12, b'bittorrent.utp') + struct.pack('>HH', 0, 0)
    # 47 (Exported PDU interface): the reproducer of bt_utp_exppdu_null_deref.py: BitTorrent messages
    # with no uTP layer below. Choke, Have and a keepalive.
    return [hdr + bt_msg(CHOKE) + bt_msg(HAVE, struct.pack('>I', 5)) + KEEPALIVE]


def malformed_eth():
    P = []
    m = lambda port, d: P.append(u4(A, B, port, 6882, d))
    # Version 0 SYN of 23 octets: the dissector reads Seq/Ack twice, past the end
    P.append(u4(E, G, 7011, 7012, utp_v0(ST_SYN, 0x7f005678, 1, 0)))
    # Extension length larger than the packet
    m(41001, utp(ST_STATE, 10, 1, 1, exts=[(1, b'\0' * 4)])[:-2])
    # Close reason with length 4 but two octets present
    m(41002, utp(ST_FIN, 10, 1, 1, exts=[(3, b'\0\0\0\0')])[:-2])
    # SYN then a segment ending with one to three octets of a BitTorrent length
    m(41003, utp(ST_SYN, 20, 1, 0))
    m(41003, utp(ST_DATA, 21, 2, 0, bt_msg(UNCHOKE) + b'\0\0'))
    # A handshake cut by the capture length (pstrlen and part of the name)
    m(41004, utp(ST_DATA, 30, 1, 0, b'\x13BitTorrent'))
    # A Have of length 1 (claims the Have type, too short a body)
    m(41005, utp(ST_DATA, 40, 1, 0, b'\0\0\0\x01\x04' + bt_msg(INTERESTED)))
    # An extended handshake with a bencoded dictionary with a string longer than the message (an exception in
    # the bencode dissector; the Have after it is still dissected)
    m(41008, utp(ST_DATA, 60, 1, 0, bt_msg(20, b'\0d3:abc99:xyz') + bt_msg(HAVE, b'\0\0\0\x09')))
    # A Piece over two segments, the second one ending with it. The first pass
    # dissects an empty remainder and shows the segment as Data, the second
    # pass skips it (one and two passes differ)
    P.append(u4(C, D, 41006, 41007, utp(ST_SYN, 50, 1, 0)))
    P.append(u4(D, C, 41007, 41006, utp(ST_STATE, 50, 9, 1)))
    pc = piece(2, 0, 100)
    P.append(u4(D, C, 41007, 41006, utp(ST_DATA, 50, 10, 1, pc[:60])))
    P.append(u4(D, C, 41007, 41006, utp(ST_DATA, 50, 11, 1, pc[60:])))
    return P


def write_pcapng(path, interfaces, frames):
    """interfaces: list of link types; frames: list of (interface, data)."""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        n = len(body) + 12
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    with open(path, 'wb') as f:
        f.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
        for lt in interfaces:
            f.write(block(1, struct.pack('<HHI', lt, 0, 65535)))
        for i, (ifc, data) in enumerate(frames):
            ts = (EPOCH + i) * 1000000
            f.write(block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [(0, p) for p in clean_eth()] + [(1, p) for p in clean_exppdu()]
    write_pcapng(os.path.join(out, 'bt_utp-coverage.pcapng'), [1, 252], frames)
    write_pcapng(os.path.join(out, 'bt_utp-coverage-malformed.pcapng'), [1],
                 [(0, p) for p in malformed_eth()])


if __name__ == '__main__':
    main()

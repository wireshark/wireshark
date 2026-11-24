#!/usr/bin/env python3
# Generates test/captures/drbd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DRBD dissector
(packet-drbd.c, Distributed Replicated Block Device).

DRBD is found by three heuristics, all disabled by default: "drbd_tcp"
(DRBD over TCP), "drbd_lb_tcp" (DRBD load balanced over TCP, each
segment wrapped in an 8 octet sequence/length header) and "drbd_rdma"
(DRBD over RDMA in InfiniBand payloads). Dissect the captures with
--enable-heuristic drbd_tcp --enable-heuristic drbd_lb_tcp
--enable-heuristic drbd_rdma.

A DRBD connection has a data and a control (meta) TCP connection; both
use the DRBD port 7789 on one of the nodes. Packets have an 8 octet
header (protocol 80, magic 0x83740267, or 95, magic 0x835a) or a 16
octet header with a volume number (protocol 100, magic 0x8620ec20).
The RDMA frames are RoCEv2 (InfiniBand transport over UDP port
4791), since pcap has no InfiniBand link-layer type. Authentication nonces
and hashes are random filler. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkdrbd.py <output directory>

Writes:
  drbd-coverage.pcap               DRBD over TCP, lb-tcp and RDMA (RoCEv2)
  drbd-coverage-malformed.pcap     short payloads, a stream that stops
                                   being DRBD
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import TcpConn, pcap, udp_frame

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)
PORT = 7789

MAGIC80 = 0x83740267
MAGIC95 = 0x835a
MAGIC100 = 0x8620ec20


def h80(cmd, payload):
    return struct.pack('!IHH', MAGIC80, cmd, len(payload)) + payload


def h95(cmd, payload):
    return struct.pack('!HHI', MAGIC95, cmd, len(payload)) + payload


def h100(cmd, payload, volume=0):
    return struct.pack('!IhHII', MAGIC100, volume, cmd, len(payload), 0) + payload


def u32(*v):
    return struct.pack('!%dI' % len(v), *v)


def u64(*v):
    return struct.pack('!%dQ' % len(v), *v)


def le64(v):
    return struct.pack('<Q', v)


def filler(n, seed):
    return bytes((seed * 31 + k * 7) & 0xff for k in range(n))


def cstr(s, n=64):
    b = s.encode()
    return b + bytes(n - len(b))


def block_ack(sector, block, size, seq):
    return u64(sector) + le64(block) + u32(size, seq)


def data_hdr(sector, block, seq, flags):
    return u64(sector) + le64(block) + u32(seq, flags)


def state(role, peer, conn, disk, pdsk, bits=0):
    return role | (peer << 2) | (conn << 4) | (disk << 9) | (pdsk << 13) | bits


TWOPC_HAS_FLAGS = 0x80000000
TWOPC_HAS_REACHABLE = 0x40000000


def twopc_req(tid, flags, init, target, nodes, rest):
    if flags & TWOPC_HAS_FLAGS:
        common = u32(tid, flags) + bytes([0, 0, init & 0xff, target & 0xff])
    else:
        common = u32(tid) + struct.pack('!ii', init, target)
    return common + u64(nodes) + rest


def tcp_frames():
    f = []
    data = TcpConn(41000, PORT, A, B)     # A -> B:7789, data stream
    meta = TcpConn(41001, PORT, B, A)     # B -> A:7789, control stream
    d = lambda pkt, srv=False: f.append(data.send(pkt, srv))
    m = lambda pkt, srv=False: f.append(meta.send(pkt, srv))

    # Connection setup: features (protocol 80 header), initial packets,
    # authentication with filler nonce and hash
    d(h80(0xfffe, u32(86, 0x0f, 121) + struct.pack('!ii', 0, 1) + bytes(12)))
    d(h80(0xfffe, u32(86, 0x0f, 121) + struct.pack('!ii', 1, 0) + bytes(12)), True)
    d(h80(0xfff2, b''))
    m(h80(0xfff1, b''))
    d(h100(0x10, filler(64, 1)))
    d(h100(0x11, filler(32, 2)), True)
    # Parameters: protocol C with an integrity algorithm, protocol update,
    # sync parameters (old and protocol 89 form)
    d(h100(0x0b, u32(3, 0, 1, 2, 1, 0) + b'crc32c\0'))
    d(h100(0x2d, u32(2, 1, 0, 0, 0, 1) + b'\0'))
    d(h100(0x0a, u32(10240) + cstr('sha1')))
    d(h100(0x23, u32(250000) + cstr('md5') + cstr('crc32c') + u32(20, 10, 100, 102400)))
    # UUIDs (old form, with every flag) and protocol 110 form with bitmap
    # UUIDs for nodes 0, 2 and 63 and two history UUIDs
    d(h100(0x0c, u64(0x1111, 0x2222, 0x3333, 0x4444, 512, 0x7ff)))
    d(h100(0x42, u64(0x1111, 512, 0x7ff, 0x8000000000000007, (1 << 63) | 5,
                     0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee)), True)
    # Sizes and state
    d(h100(0x0d, u64(1 << 30, 0, 1 << 30) + u32(1 << 20) + struct.pack('!HH', 0, 3)
           + u32(512, 4096, 0, 4096, 65536) + bytes([1, 0, 1, 0])))
    d(h100(0x0e, u32(state(1, 2, 10, 8, 8, 0xfe0000))), True)
    d(h100(0x0e, u32(state(2, 1, 16, 4, 5))))
    # State change requests: with a mask of some fields, with an empty
    # mask; and replies
    m(h100(0x12, u32(0x3 | 0x1f0, state(1, 0, 10, 0, 0))))
    m(h100(0x1d, struct.pack('!i', 1)), True)
    m(h100(0x2a, u32(0, 0x12345678)))
    m(h100(0x2b, struct.pack('!i', -11)), True)
    # Sync UUID, current UUID
    d(h100(0x0f, u64(0x5555)))
    d(h100(0x44, u64(0x6666, 0x0f)))
    # Data: P_DATA with every flag and 64 octets, replies; protocol 95
    # header for a data reply
    d(h100(0x00, data_hdr(2048, 0x1000, 1, 0x7ff) + filler(64, 3), volume=1))
    d(h95(0x01, data_hdr(4096, 0x2000, 2, 0x02) + filler(32, 4)), True)
    d(h100(0x02, data_hdr(8, 0x3000, 3, 0x04) + filler(16, 5)), True)
    d(h100(0x00, data_hdr(9, 0x3001, 4, 0)))              # no data
    # Barrier and barrier ack
    d(h100(0x03, struct.pack('<I', 7)))
    m(h100(0x1c, struct.pack('<I', 7) + u32(3)))
    # Bitmap, compressed bitmap, unplug (no payload decoders)
    d(h100(0x04, filler(16, 6)))
    d(h100(0x24, filler(8, 7)))
    d(h100(0x07, b''))
    # Data requests
    for cmd in (0x08, 0x09, 0x1e, 0x1f, 0x21, 0x32):
        d(h100(cmd, u64(100 + cmd) + le64(0x4000 + cmd) + u32(4096)))
    for cmd in (0x4c, 0x4d, 0x4e, 0x4f, 0x50):
        d(h100(cmd, u64(200 + cmd) + le64(0x5000 + cmd) + u32(4096) + struct.pack('!i', 2) + u64(0x99 + cmd)))
    # Delay probe, out of sync, dagtags
    d(h100(0x27, u32(5, 1000)))
    m(h100(0x27, u32(5, 1001)), True)
    d(h100(0x28, u64(300) + u32(8192)))
    d(h100(0x30, u64(0x123456789)))
    d(h100(0x43, u64(0x987654321) + struct.pack('!i', 2)))
    # Trim, zeroes, write same, deallocated
    d(h100(0x31, data_hdr(400, 0x6000, 5, 0x40) + u32(1 << 20)))
    d(h100(0x36, data_hdr(401, 0x6001, 6, 0x400) + u32(1 << 16)))
    d(h100(0x34, data_hdr(402, 0x6002, 7, 0x200) + u32(1 << 16) + filler(512, 8)))
    d(h100(0x33, u64(403) + u32(4096)))
    m(h100(0x54, block_ack(403, 0x6003, 4096, 8)))
    # Two-phase commits: prepare (old and flags form), prepare resize,
    # replies on the control stream, commit and abort
    d(h100(0x2e, twopc_req(1, 0, 0, -1, 0x6, u64(0x1) + u32(0x3, state(1, 0, 0, 0, 0)))))
    m(h100(0x45, u32(1) + struct.pack('!i', 0) + u64(0x7, 0x1, 0x0)))
    d(h100(0x47, twopc_req(1, 0, 0, -1, 0x6, u64(0x3) + u32(0x3, state(1, 0, 0, 0, 0)))))
    d(h100(0x2e, twopc_req(2, TWOPC_HAS_FLAGS | TWOPC_HAS_REACHABLE, 1, 2, 0x4,
                           bytes(8) + u32(0x1f0, state(0, 0, 10, 0, 0)))))
    m(h100(0x46, u32(2) + struct.pack('!i', 1) + u64(0x6, 0x2, 0x4)))
    d(h100(0x47, twopc_req(2, TWOPC_HAS_FLAGS | TWOPC_HAS_REACHABLE, 1, 2, 0x4,
                           u64(0x2, 0x7))))
    d(h100(0x2e, twopc_req(3, TWOPC_HAS_FLAGS, 1, 0, 0x1,
                           bytes(8) + u32(0x3, state(2, 0, 0, 0, 0)))))
    d(h100(0x2f, twopc_req(3, TWOPC_HAS_FLAGS, 1, 0, 0x1, u64(0x0, 0x0))))
    d(h100(0x35, twopc_req(4, 0, 0, 1, 0x2, u64(1 << 31) + struct.pack('!H', 1) + bytes(6))))
    m(h100(0x48, u32(4) + struct.pack('!i', 0) + u64(0x3, 0x1, 1 << 32)))
    d(h100(0x47, twopc_req(4, 0, 0, 1, 0x2, u64(0x1, 1 << 31))))
    # a commit and a reply without a prepare
    d(h100(0x47, twopc_req(99, 0, 3, 1, 0x2, u64(0, 0))))
    m(h100(0x45, u32(98) + struct.pack('!i', 3) + u64(0x2)))
    # Acks on the control stream
    m(h100(0x13, b''))
    m(h100(0x14, b''), True)
    for k, cmd in enumerate((0x15, 0x16, 0x51, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x52,
                             0x20, 0x22, 0x29, 0x4a, 0x2c)):
        m(h100(cmd, block_ack(500 + k, 0x7000 + k, 4096, 10 + k)))
    for k, res in enumerate((4710, 4711, 4712, 1)):
        m(h100(0x53, block_ack(600 + k, 0x8000 + k, 4096, 30 + k) + u64(res)))
    m(h100(0x49, le64(0x9000) + le64(0x9010) + u32(17)))
    m(h100(0x40, u64(0x0, 0x77)))
    m(h100(0x40, u64(0x8000000000000000, 0x78)))
    m(h100(0x41, u64(700, 0xf0f0000000000001) + u32(1 << 20)))
    m(h100(0x41, u64(701, 0x3) + u32(4096)))
    # An unknown command
    d(h100(0x60, b'\x01\x02\x03\x04'))
    # Several packets in one segment, then one packet split over two
    # segments (TCP reassembly)
    d(h100(0x13, b'') + h100(0x30, u64(1)) + h80(0x13, b''))
    big = h100(0x00, data_hdr(800, 0xa000, 40, 0) + filler(200, 9))
    d(big[:50])
    d(big[50:])
    # Disconnect
    d(h100(0x4b, b''))

    # DRBD load balanced over TCP (8 octet sequence/length wrapper)
    lb = TcpConn(41002, 7790, A, B)
    seq = [0]

    def lbw(payload, srv=False):
        seq[0] += 1
        f.append(lb.send(u32(seq[0], len(payload)) + payload, srv))
    lbw(h100(0x13, b'') + h100(0x28, u64(900) + u32(512)))
    lbw(h100(0x14, b''), True)
    lbw(b'\x00' * 12)                  # wrapper without a DRBD header
    # A stream that starts with a protocol 95 header
    c = TcpConn(41003, PORT, A, B)
    f.append(c.send(h95(0x13, b'')))
    f.append(c.send(h95(0x0f, u64(0x5556))))
    # A 6 octet segment on another connection: not DRBD
    f.append(TcpConn(41004, PORT, A, B).send(b'\x83\x74\x02\x67\x00\x13'))
    return f


# ---- RDMA: RoCEv2 (InfiniBand BTH over UDP port 4791)
def ib_frame(payload, dqp=0x000123, psn=1, opcode=0x04):
    pad = -len(payload) % 4
    bth = struct.pack('!BBHB3sB3s', opcode, (pad << 4), 0xffff, 0,
                      dqp.to_bytes(3, 'big'), 0, psn.to_bytes(3, 'big'))
    # the ICRC is not computed (filler)
    return udp_frame(49152, 4791, bth + payload + bytes(pad) + bytes(4), A, B)


def rdma_frames():
    f = []
    # flow control message, then DRBD packets
    f.append(ib_frame(u32(0x5257494e, 16, 4, 0xffffffff)))
    f.append(ib_frame(h100(0x13, b''), psn=2))
    f.append(ib_frame(h100(0x0e, u32(state(1, 2, 10, 8, 8))), psn=3))
    # P_DATA: the data follows by RDMA, so only the header is here
    f.append(ib_frame(h100(0x00, data_hdr(10, 0xb000, 1, 0)), psn=4))
    # flow control and two DRBD packets in one payload
    f.append(ib_frame(u32(0x5257494e, 8, 2, 1) + h100(0x14, b'') +
                      h100(0x15, block_ack(10, 0xb000, 4096, 1)), psn=5))
    # a twopc commit and reply (no conversation over RDMA)
    f.append(ib_frame(h100(0x47, twopc_req(5, 0, 0, 1, 0x2, u64(0, 0))), psn=6))
    f.append(ib_frame(h100(0x45, u32(5) + struct.pack('!i', 0) + u64(0x2)), psn=7))
    # a protocol 95 packet followed by 8 octets that are not DRBD
    f.append(ib_frame(h95(0x13, b'') + b'trailing', psn=8))
    # an InfiniBand payload that is not DRBD
    f.append(ib_frame(b'not drbd payload', psn=9))
    return f


def malformed_frames():
    f = []
    c = TcpConn(41010, PORT, A, B)
    f.append(c.send(h100(0x13, b'')))
    # 16 octets that are no DRBD header in a DRBD stream: the stream
    # dissector is reset
    f.append(c.send(b'\x11' * 20))
    c = TcpConn(41011, PORT, A, B)
    f.append(c.send(h100(0x0d, bytes(10))))           # sizes cut short
    f.append(c.send(h100(0x42, u64(1, 0, 0, 0, 0xff)))) # bitmap UUIDs missing
    f.append(c.send(h100(0x10, bytes(10))))            # nonce cut short
    f.append(c.send(h100(0x2e, u32(1))))               # twopc cut short
    # a 4 octet RDMA payload (too short for DRBD; RoCE reports it)
    f.append(ib_frame(b'\x52\x57\x49\x4e', psn=10))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'drbd-coverage.pcap'), tcp_frames() + rdma_frames())
    pcap(os.path.join(out, 'drbd-coverage-malformed.pcap'), malformed_frames())

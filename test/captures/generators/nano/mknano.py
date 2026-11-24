#!/usr/bin/env python3
# Generates test/captures/nano_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic Nano cryptocurrency protocol coverage captures.

Usage: mknano.py <outdir>

nano-coverage.pcap: UDP 7075 (keepalive, publish, confirm request and ack
with every block type) and TCP 7075 bootstrap sessions (frontier request,
bulk pull, bulk pull blocks, bulk push; blocks split over TCP segments).
nano-coverage-malformed.pcap: flows that only the (default off) Nano
heuristics reach, invalid block types, short packets (not added to the
tree).  Hashes, accounts and signatures are made-up byte patterns.
"""
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Pcap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

    def udp(self, sport, dport, payload, cip='192.0.2.1', sip='192.0.2.2'):
        u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), self.ipid, 0, 64, 17, 0,
                         bytes(map(int, cip.split('.'))), bytes(map(int, sip.split('.'))))
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pkts.append(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + u)


class Flow:
    def __init__(self, pcap, cport, sport=7075, cip='192.0.2.1', sip='192.0.2.2'):
        self.pcap = pcap
        self.c = (bytes(map(int, cip.split('.'))), cport, b'\x02\x00\x00\x00\x00\x01')
        self.s = (bytes(map(int, sip.split('.'))), sport, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {True: 1000, False: 5000}

    def seg(self, from_client, payload):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = src[0] + dst[0] + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.pcap.ipid, 0, 64, 6, 0, src[0], dst[0])
        self.pcap.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.pcap.pkts.append(dst[2] + src[2] + b'\x08\x00' + ip + tcp + payload)
        self.seq[from_client] = (seq + len(payload)) & 0xffffffff

    def c2s(self, *b):
        self.seg(True, b''.join(b))

    def s2c(self, *b):
        self.seg(False, b''.join(b))


# packet and block types
INVALID, NOT_A_TYPE, KEEPALIVE, PUBLISH, CONFIRM_REQ, CONFIRM_ACK, BULK_PULL, BULK_PUSH, \
    FRONTIER_REQ, BULK_PULL_BLOCKS = range(10)
B_INVALID, B_NOT_A_BLOCK, B_SEND, B_RECEIVE, B_OPEN, B_CHANGE, B_STATE = range(7)


def hdr(ptype, btype=0, magic=b'RC', vmax=18, vusing=18, vmin=17, ext=None):
    if ext is None:
        ext = btype << 8
    return magic + bytes([vmax, vusing, vmin, ptype]) + struct.pack('<H', ext)


def pat(n, seed):
    return bytes((seed + i) & 0xff for i in range(n))


def send_block(seed=1):
    return pat(32, seed) + pat(32, seed + 32) + pat(16, seed + 64) + pat(64, seed + 80) + pat(8, seed + 144)


def receive_block(seed=2):
    return pat(32, seed) + pat(32, seed + 32) + pat(64, seed + 64) + pat(8, seed + 128)


def open_block(seed=3):
    return pat(32, seed) + pat(32, seed + 32) + pat(32, seed + 64) + pat(64, seed + 96) + pat(8, seed + 160)


def change_block(seed=4):
    return pat(32, seed) + pat(32, seed + 32) + pat(64, seed + 64) + pat(8, seed + 128)


def state_block(seed=5):
    return (pat(32, seed) + pat(32, seed + 32) + pat(32, seed + 64) + pat(16, seed + 96) +
            pat(32, seed + 112) + pat(64, seed + 144) + pat(8, seed + 208))


BLOCKS = {B_SEND: send_block, B_RECEIVE: receive_block, B_OPEN: open_block, B_CHANGE: change_block,
          B_STATE: state_block}


def vote(seed=9):
    return pat(32, seed) + pat(64, seed + 32) + struct.pack('<Q', 0x0123456789abcdef)


def peer(ip, port):
    return ip + struct.pack('<H', port)


NONE = b'\0' * 18


def v4(a, b, c, d, port=7075):
    return peer(b'\0' * 10 + b'\xff\xff' + bytes([a, b, c, d]), port)


def v6(hexaddr, port=7075):
    return peer(bytes.fromhex(hexaddr), port)


def build_main(pc):
    # ---- UDP 7075
    pc.udp(7075, 7075, hdr(KEEPALIVE) + v4(198, 51, 100, 7) + v6('20010db8000000000000000000000001') +
           v4(203, 0, 113, 9, 7076) + NONE * 5)
    pc.udp(7075, 7075, hdr(KEEPALIVE, magic=b'RA') + NONE * 8)
    pc.udp(7075, 7075, hdr(KEEPALIVE, magic=b'RB', vmax=17, vusing=16, vmin=13) +
           b''.join(v6('2001db8000000000000000000000%04x' % i, 7075 + i) for i in range(1, 9)))
    for bt in (B_SEND, B_RECEIVE, B_OPEN, B_CHANGE, B_STATE):
        pc.udp(7075, 7075, hdr(PUBLISH, bt) + BLOCKS[bt](bt))
    for bt in (B_SEND, B_RECEIVE, B_OPEN, B_CHANGE, B_STATE):
        pc.udp(7075, 7075, hdr(CONFIRM_REQ, bt) + BLOCKS[bt](10 + bt))
    for bt in (B_SEND, B_RECEIVE, B_OPEN, B_CHANGE, B_STATE):
        pc.udp(7075, 7075, hdr(CONFIRM_ACK, bt) + vote(bt) + BLOCKS[bt](20 + bt))
    # block types that have no block, other packet types in UDP
    pc.udp(7075, 7075, hdr(PUBLISH, B_NOT_A_BLOCK) + b'\0' * 8)
    pc.udp(7075, 7075, hdr(CONFIRM_ACK, B_INVALID) + vote())
    pc.udp(7075, 7075, hdr(PUBLISH, 9) + b'\0' * 8)               # unknown block type
    for pt in (INVALID, NOT_A_TYPE, BULK_PULL, BULK_PUSH, FRONTIER_REQ, BULK_PULL_BLOCKS, 12):
        pc.udp(7075, 7075, hdr(pt))
    pc.udp(7075, 7075, hdr(KEEPALIVE, magic=b'RX') + NONE * 8)      # unknown network
    # ---- TCP bootstrap sessions
    # frontier request and responses
    f = Flow(pc, 41001)
    f.c2s(hdr(FRONTIER_REQ) + pat(32, 1) + struct.pack('<II', 0xffffffff, 100))
    f.s2c(pat(64, 7))
    f.s2c(pat(64, 8), pat(64, 9))
    f.s2c(b'\0' * 64)
    # bulk pull
    f = Flow(pc, 41002)
    f.c2s(hdr(BULK_PULL) + pat(32, 3) + pat(32, 4))
    f.s2c(bytes([B_SEND]) + send_block(11))
    f.s2c(bytes([B_RECEIVE]) + receive_block(12), bytes([B_OPEN]) + open_block(13))
    f.s2c(bytes([B_CHANGE]) + change_block(14))
    blk = bytes([B_STATE]) + state_block(15)
    f.seg(False, blk[:70])
    f.seg(False, blk[70:])
    f.s2c(bytes([B_NOT_A_BLOCK]))
    f.s2c(b'trailing data after the end of the pull')               # state back to invalid: rest of the segment
    # bulk pull blocks (the reproducer of "Nano: Fix the Bulk Pull Blocks subtree and a misaligned cast")
    f = Flow(pc, 41003)
    f.c2s(hdr(BULK_PULL_BLOCKS) + pat(32, 0x11) + pat(32, 0x22) + b'\x01' + struct.pack('<I', 5))
    f.s2c(bytes([B_SEND]) + send_block(21))
    f.s2c(bytes([B_NOT_A_BLOCK]))
    f = Flow(pc, 41004)
    f.c2s(hdr(BULK_PULL_BLOCKS) + pat(32, 0x33) + pat(32, 0x44) + b'\x00' + struct.pack('<I', 0))
    f.s2c(bytes([B_NOT_A_BLOCK]))
    # bulk push: the client sends blocks
    f = Flow(pc, 41005)
    f.c2s(hdr(BULK_PUSH))
    f.c2s(bytes([B_SEND]) + send_block(31), bytes([B_RECEIVE]) + receive_block(32))
    f.c2s(bytes([B_OPEN]) + open_block(33))
    f.c2s(bytes([B_CHANGE]) + change_block(34))
    blk = bytes([B_STATE]) + state_block(35)
    f.seg(True, blk[:5])
    f.seg(True, blk[5:])
    f.c2s(bytes([B_NOT_A_BLOCK]))
    # the header of a request in one segment with the next piece of data, and a header in two segments
    f = Flow(pc, 41006)
    req = hdr(FRONTIER_REQ) + pat(32, 5) + struct.pack('<II', 1, 2)
    f.seg(True, req[:4])
    f.seg(True, req[4:])
    f.s2c(pat(64, 12))


def build_malformed(pc):
    # ---- the heuristics (disabled by default) accept Nano traffic on other ports
    pc.udp(40000, 40001, hdr(KEEPALIVE) + v4(198, 51, 100, 7) + NONE * 7)
    pc.udp(40000, 40001, hdr(PUBLISH, B_SEND) + send_block(1))
    # each rejected packet has its own ports: after the first accepted one the conversation is claimed
    pc.udp(40002, 40001, b'XX' + b'\0' * 20)                          # rejected: wrong magic
    pc.udp(40003, 40001, b'RD' + b'\0' * 20)                          # rejected: wrong network
    pc.udp(40004, 40001, hdr(KEEPALIVE, vmax=31) + NONE * 8)          # rejected: version
    pc.udp(40005, 40001, hdr(KEEPALIVE, vmax=3, vusing=5, vmin=1) + NONE * 8)  # rejected: using > max
    pc.udp(40006, 40001, hdr(KEEPALIVE, vmax=5, vusing=3, vmin=4) + NONE * 8)  # rejected: min > using
    pc.udp(40007, 40001, hdr(16) + NONE * 8)                          # rejected: packet type
    pc.udp(40008, 40001, b'RC\x12\x12')                               # rejected: shorter than a header
    f = Flow(pc, 42001, 40001)
    f.c2s(hdr(BULK_PULL) + pat(32, 3) + pat(32, 4))
    f.s2c(bytes([B_SEND]) + send_block(11))
    f.s2c(bytes([B_NOT_A_BLOCK]))
    f = Flow(pc, 42002, 40001)
    f.c2s(b'XX' + b'\0' * 20)                                           # not Nano: stays unclaimed
    # ---- UDP packet shorter than a header (not dissected)
    pc.udp(7075, 7075, b'RC\x12\x12')
    # ---- TCP: invalid block type from the server and in a bulk push, truncated blocks
    f = Flow(pc, 41101)
    f.c2s(hdr(BULK_PULL) + pat(32, 3) + pat(32, 4))
    f.s2c(bytes([0x42]) + b'garbage garbage garbage')
    f = Flow(pc, 41102)
    f.c2s(hdr(BULK_PUSH))
    f.c2s(bytes([0x99]) + b'garbage')
    f = Flow(pc, 41103)
    f.c2s(hdr(BULK_PULL_BLOCKS) + pat(32, 3) + pat(32, 4) + b'\x00' + struct.pack('<I', 1))
    f.s2c((bytes([B_SEND]) + send_block(11))[:50])                    # truncated block, nothing follows
    # a client packet of an unknown type and a short client packet
    f = Flow(pc, 41104)
    f.c2s(hdr(KEEPALIVE) + NONE * 8)
    f.c2s(b'RC\x12')
    f.c2s(hdr(INVALID))
    # a server frontier response that is cut short
    f = Flow(pc, 41105)
    f.c2s(hdr(FRONTIER_REQ) + pat(32, 1) + struct.pack('<II', 0, 1))
    f.s2c(pat(40, 7))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pc = Pcap()
    build_main(pc)
    pc.write(os.path.join(out, 'nano-coverage.pcap'))
    n = len(pc.pkts)
    pc = Pcap()
    build_malformed(pc)
    pc.write(os.path.join(out, 'nano-coverage-malformed.pcap'))
    print('main frames:', n, 'malformed frames:', len(pc.pkts))


if __name__ == '__main__':
    main()

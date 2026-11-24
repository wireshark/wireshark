#!/usr/bin/env python3
# Generates test/captures/smb_direct_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-smb-direct.c (SMB Direct, MS-SMBD).

Usage: mksmb_direct.py <outdir> [-v]
Writes smb-direct-coverage.pcap (main), smb-direct-coverage-malformed.pcap.
Everything is built with struct; addresses are from 192.0.2.0/24.
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                     bytes([192, 0, 2, src]), bytes([192, 0, 2, dst]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload


def eth(payload, src, dst, etype=0x0800):
    return bytes.fromhex('02000000000%d02000000000%d' % (dst, src)) + struct.pack('!H', etype) + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)) + fr)


# --- RoCEv2 (UDP 4791, BTH) ------------------------------------------------
SEND_FIRST, SEND_MIDDLE, SEND_LAST, SEND_LAST_IMM, SEND_ONLY, SEND_ONLY_IMM = 0, 1, 2, 3, 4, 5
SEND_LAST_INVAL, SEND_ONLY_INVAL = 0x16, 0x17
WRITE_ONLY, READ_REQ = 0x0a, 0x0c


def roce(opcode, payload, src, dst, qp, psn, sport=49152):
    ext = b''
    if opcode in (SEND_LAST_IMM, SEND_ONLY_IMM):
        ext = struct.pack('!I', 0x1234)
    elif opcode in (SEND_LAST_INVAL, SEND_ONLY_INVAL):
        ext = struct.pack('!I', 0x5678)
    bth = struct.pack('!BBHB3sB3s', opcode, 0x40, 0xffff, 0, qp.to_bytes(3, 'big'), 0,
                      psn.to_bytes(3, 'big'))
    body = bth + ext + payload + b'\0\0\0\0'      # ICRC
    udp = struct.pack('!HHHH', sport, 4791, 8 + len(body), 0) + body
    return eth(ip4(17, udp, src, dst), src, dst)


class Roce:
    def __init__(self, c=1, s=2, cqp=0x11, sqp=0x22, sport=49152):
        self.frames = []
        self.ep = {c: [cqp, 0], s: [sqp, 0]}
        self.c, self.s, self.sport = c, s, sport

    def send(self, src, dst, payload, opcode=SEND_ONLY):
        qp, psn = self.ep[dst][0], self.ep[src][1]
        self.ep[src][1] += 1
        self.frames.append(roce(opcode, payload, src, dst, qp, psn, self.sport))

    def c2s(self, p, opcode=SEND_ONLY):
        self.send(self.c, self.s, p, opcode)

    def s2c(self, p, opcode=SEND_ONLY):
        self.send(self.s, self.c, p, opcode)


# --- SMB Direct messages ---------------------------------------------------
def neg_req(credits=255, send=1364, recv=8192, frag=1048576, minv=0x100, maxv=0x100):
    return struct.pack('<HHHHIII', minv, maxv, 0, credits, send, recv, frag)


def neg_rep(status=0, credits=255, granted=255, rw=1048576, send=1364, recv=8192, frag=1048576):
    return struct.pack('<HHHHHHIIIII', 0x100, 0x100, 0x100, 0, credits, granted, status, rw, send, recv, frag)


def data_msg(smb, remaining=0, credits=255, granted=255, flags=0, offset=24, pad=b''):
    return struct.pack('<HHHHIII', credits, granted, flags, 0, remaining, offset, len(smb)) + \
        struct.pack('<I', 0) + pad + smb


# --- SMB2 messages carried over it -------------------------------------------
def smb2_hdr(cmd, mid, flags=0, sesid=0, tid=0, status=0, credit=1):
    return b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ16s', 64, 0, status, cmd, credit, flags,
                                    0, mid, 0, tid, sesid, b'\0' * 16)


def neg_smb2_req():
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    return smb2_hdr(0, 0) + struct.pack('<HHHHI16sQ', 36, len(dialects), 1, 0, 0x7f, b'\x01' * 16, 0) + \
        b''.join(struct.pack('<H', d) for d in dialects) + b'\0\0'


def neg_smb2_rep():
    return smb2_hdr(0, 0, 1) + struct.pack('<HHHH16sIIIIQQHHI', 65, 1, 0x0302, 0, b'\x02' * 16,
                                           0x7f, 1048576, 1048576, 1048576, 0, 0, 128, 0, 0) + b'\0'


SES, TID = 0x1122334455667788, 5
FID = bytes(range(16))
TNAME = '\\\\192.0.2.2\\Share'.encode('utf-16-le')
FNAME = 'dir\\file.txt'.encode('utf-16-le')


def tcon_req(mid=1):
    return smb2_hdr(3, mid, 0, SES, 0) + struct.pack('<HHHH', 9, 0, 72, len(TNAME)) + TNAME


def tcon_rep(mid=1):
    return smb2_hdr(3, mid, 1, SES, TID) + struct.pack('<HBBIII', 16, 1, 0, 0, 0, 0x1f01ff)


def create_req(mid=2):
    return smb2_hdr(5, mid, 0, SES, TID) + struct.pack('<HBBIQQIIIIIHHII', 57, 0, 0, 2, 0, 0, 0x12019f,
                                                      0x80, 7, 1, 0x40, 120, len(FNAME), 0, 0) + FNAME


def create_rep(mid=2):
    return smb2_hdr(5, mid, 1, SES, TID) + struct.pack('<HBBIQQQQQQII', 89, 0, 0, 1, 0, 0, 0, 0, 4096, 100,
                                                      0x20, 0) + FID + struct.pack('<II', 0, 0)


def read_req(mid, length, offset=0):
    return smb2_hdr(8, mid, 0, SES, TID) + struct.pack('<HBBIQ16sIIIHH', 49, 0, 0, length, offset, FID,
                                                       0, 0, 0, 0, 0) + b'\0'


def read_rep(mid, data):
    return smb2_hdr(8, mid, 1, SES, TID) + struct.pack('<HBBIII', 17, 80, 0, len(data), 0, 0) + data


def write_req(mid, data, offset=0):
    return smb2_hdr(9, mid, 0, SES, TID) + struct.pack('<HHIQ16sIIHHI', 49, 112, len(data), offset, FID,
                                                       0, 0, 0, 0, 0) + data


def write_rep(mid, count):
    return smb2_hdr(9, mid, 1, SES, TID) + struct.pack('<HHIIHH', 17, 0, count, 0, 0, 0) + b'\0'


def close_req(mid):
    return smb2_hdr(6, mid, 0, SES, TID) + struct.pack('<HHI16s', 24, 0, 0, FID)


def close_rep(mid):
    return smb2_hdr(6, mid, 1, SES, TID) + struct.pack('<HHIQQQQQQI', 60, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def echo_req(mid):
    return smb2_hdr(13, mid, 0, SES, TID) + struct.pack('<HH', 4, 0)


def echo_rep(mid):
    return smb2_hdr(13, mid, 1, SES, TID) + struct.pack('<HH', 4, 0)


def split(msg, size):
    """cut an SMB2 message into SMB Direct data messages (remaining length)"""
    parts = [msg[i:i + size] for i in range(0, len(msg), size)]
    out = []
    rest = len(msg)
    for p in parts:
        rest -= len(p)
        out.append(data_msg(p, rest))
    return out


marks = []


def mark(name, frames):
    marks.append((name, len(frames) + 1))


# ===========================================================================
main = []

# --- 1: RoCEv2, QP pair 0x11 <-> 0x22, UDP 4791 -----------------------------
r = Roce(1, 2, 0x11, 0x22)
mark('RoCEv2 negotiate', r.frames)
r.c2s(neg_req())
r.s2c(neg_rep())
mark('SMB2 over single data messages (RC Send Only)', r.frames)
r.c2s(data_msg(neg_smb2_req()))
r.s2c(data_msg(neg_smb2_rep(), flags=1, credits=10, granted=20))
r.c2s(data_msg(tcon_req(1)))
r.s2c(data_msg(tcon_rep(1)))
r.c2s(data_msg(create_req(2)))
r.s2c(data_msg(create_rep(2)))
mark('empty data message (keepalive, 20 octets), with response requested', r.frames)
r.c2s(struct.pack('<HHHHIII', 255, 255, 1, 0, 0, 0, 0))
r.s2c(struct.pack('<HHHHIII', 255, 255, 0, 0, 0, 0, 0))
mark('multi-fragment read response: three data messages with remaining length', r.frames)
r.c2s(data_msg(read_req(3, 6000)))
for p in split(read_rep(3, bytes(range(256)) * 23 + bytes(112)), 2400):
    r.s2c(p)
mark('multi-fragment write request: four data messages, interleaved with the other direction', r.frames)
wr = write_req(4, b'W' * 3000)
parts = split(wr, 1000)
r.c2s(parts[0]); r.c2s(parts[1])
r.s2c(data_msg(echo_rep(99)))
r.c2s(parts[2]); r.c2s(parts[3])
r.s2c(data_msg(write_rep(4, 3000)))
mark('echo', r.frames)
r.c2s(data_msg(echo_req(5)))
r.s2c(data_msg(echo_rep(5)))
mark('other RC Send opcodes: Only Immediate, Only Invalidate, Last Immediate, Last Invalidate', r.frames)
r.c2s(data_msg(echo_req(6)), SEND_ONLY_IMM)
r.s2c(data_msg(echo_rep(6)), SEND_ONLY_INVAL)
# a message split over RC Send First/Middle/Last (Infiniband level reassembly)
m = data_msg(read_rep(7, b'R' * 3000))
r.s2c(m[:1000], SEND_FIRST)
r.s2c(m[1000:2000], SEND_MIDDLE)
r.s2c(m[2000:], SEND_LAST)
m = data_msg(write_req(8, b'X' * 2000))
r.c2s(m[:1200], SEND_FIRST)
r.c2s(m[1200:], SEND_LAST_IMM)
m = data_msg(write_rep(8, 2000))
r.s2c(m[:40], SEND_FIRST)
r.s2c(m[40:], SEND_LAST_INVAL)
mark('SMB-Direct level fragments each sent as RC Send First..Last', r.frames)
# remaining length fragments, each of which is split over several RC sends
big = read_rep(9, b'B' * 4000)
parts = split(big, 2200)
for p in parts:
    r.s2c(p[:900], SEND_FIRST)
    r.s2c(p[900:], SEND_LAST)
mark('close', r.frames)
r.c2s(data_msg(close_req(10)))
r.s2c(data_msg(close_rep(10)))
mark('not SMB Direct: RC Send with no valid header, RDMA Write Only (not a send)', r.frames)
r.c2s(b'\x07' * 40)                      # too long for len<=24 rules, not SMB Direct
r.c2s(b'\x01' * 16)                      # too short
r.c2s(neg_req()[:19])                    # 19 octets
r.c2s(struct.pack('<HHHHIII', 300, 3, 0, 0, 0, 24, 5) + b'\0' * 4 + b'hello')   # credits > 255
r.c2s(data_msg(echo_req(5), offset=32, pad=b'\0' * 8))               # data offset 32
r.c2s(struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 24, 0) + b'\0' * 4 + b'hello')     # data length 0
r.c2s(struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 24, 5) + b'\1\0\0\0' + b'hello')   # padding != 0
r.c2s(b'\x01\x00\x01\x00' + b'\0' * 28, SEND_ONLY)   # looks like a negotiate response but wrong
r.c2s(b'\x00' * 24, SEND_ONLY)
r.c2s(b'\x00\x01' + b'\0' * 30, WRITE_ONLY)
main += r.frames

# negotiate response with an error status
r = Roce(3, 4, 0x31, 0x32, 49153)
mark('negotiate error response (STATUS_NOT_SUPPORTED)', main)
r.c2s(neg_req(credits=1))
r.s2c(neg_rep(status=0xc00000bb))
r.c2s(neg_req(credits=1, minv=0x100, maxv=0x100))
r.s2c(neg_rep(status=0xdeadbeef))
main += r.frames

# --- 2: iWARP: TCP, MPA, DDP/RDMAP Send ------------------------------------
def tcp(payload, src, dst, sport, dport, seq, ack, flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ip4(6, t, src, dst), src, dst)


class Iwarp:
    def __init__(self, c, s, cport, sport):
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.cs, self.ss = 5000, 9000
        self.frames = []

    def c2s(self, p):
        self.frames.append(tcp(p, self.c, self.s, self.cp, self.sp, self.cs, self.ss)); self.cs += len(p)

    def s2c(self, p):
        self.frames.append(tcp(p, self.s, self.c, self.sp, self.cp, self.ss, self.cs)); self.ss += len(p)

    def fpdu(self, side, payload):
        pad = (-(len(payload) + 2)) % 4
        f = struct.pack('!H', len(payload)) + payload + b'\0' * pad + b'\0\0\0\0'
        (self.c2s if side == 'c' else self.s2c)(f)


def mpa_req_rep(kind, pd=b'', flags=0):
    key = b'MPA ID Req Frame' if kind == 'req' else b'MPA ID Rep Frame'
    return key + struct.pack('!BBH', flags, 1, len(pd)) + pd


def ddp_send(payload, opcode=3, msn=1, mo=0, last=True, inval=0):
    ctl = 0x40 | 0x01 if last else 0x01
    rd = 0x40 | opcode
    return struct.pack('!BBIIII', ctl, rd, inval, 0, msn, mo) + payload


mark('iWARP: MPA request/reply with IRD/ORD private data', main)
w = Iwarp(5, 6, 50000, 20445)
w.c2s(mpa_req_rep('req', struct.pack('!II', 8, 8)))
w.s2c(mpa_req_rep('rep', struct.pack('!II', 8, 8)))
mark('iWARP: SMB Direct negotiate and data over RDMAP Send, Send+Invalidate, Send+SE, Send+SE+Invalidate', main + w.frames)
w.fpdu('c', ddp_send(neg_req(), msn=1))
w.fpdu('s', ddp_send(neg_rep(), msn=1))
w.fpdu('c', ddp_send(data_msg(neg_smb2_req()), msn=2))
w.fpdu('s', ddp_send(data_msg(neg_smb2_rep()), opcode=4, msn=2, inval=0x1234))
w.fpdu('c', ddp_send(data_msg(tcon_req(1)), opcode=5, msn=3))
w.fpdu('s', ddp_send(data_msg(tcon_rep(1)), opcode=6, msn=3, inval=0x4321))
w.fpdu('c', ddp_send(data_msg(create_req(2)), msn=4))
w.fpdu('s', ddp_send(data_msg(create_rep(2)), msn=4))
mark('iWARP: multi-fragment read response (remaining length)', main + w.frames)
w.fpdu('c', ddp_send(data_msg(read_req(3, 3000)), msn=5))
for i, p in enumerate(split(read_rep(3, b'I' * 3000), 1100)):
    w.fpdu('s', ddp_send(p, msn=5 + i))
mark('iWARP: not an RDMAP Send (RDMA Write, tagged)', main + w.frames)
w.fpdu('c', struct.pack('!BBIQ', 0xc1, 0x40, 0x99, 0) + b'\0' * 32)      # tagged, RDMA Write
w.fpdu('c', ddp_send(b'\x55' * 40, msn=9))                            # Send, not SMB Direct
main += w.frames

# second iWARP connection with reassembly in other mode (same data)
w = Iwarp(5, 6, 50001, 20445)
w.c2s(mpa_req_rep('req'))
w.s2c(mpa_req_rep('rep'))
w.fpdu('c', ddp_send(neg_req(), msn=1))
w.fpdu('s', ddp_send(neg_rep(), msn=1))
w.fpdu('c', ddp_send(data_msg(echo_req(1)), msn=2))
w.fpdu('s', ddp_send(data_msg(echo_rep(1)), msn=2))
main += w.frames

open(os.path.join(OUT, 'smb-direct-coverage.pcap'), 'wb').close()
write_pcap(os.path.join(OUT, 'smb-direct-coverage.pcap'), main)
if VERBOSE:
    print(len(main), 'frames')
    for n, f in marks:
        print(f, n)

# ===========================================================================
# malformed: paths only damaged input reaches
mal = []
r = Roce(1, 2, 0x51, 0x52, 49160)
r.c2s(neg_req())
r.s2c(neg_rep())
# DataOffset past the end of the frame
r.c2s(struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 24, 100) + b'\0' * 4 + b'short')
# data length larger than the data present
r.c2s(struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 24, 5000) + b'\0' * 4 + b'short')
# first fragment cut off in the middle of the header
r.c2s(data_msg(echo_req(1))[:30])
# SMB2 payload truncated
r.c2s(data_msg(echo_req(1)[:40]))
# remaining length with a dangling first fragment, then a normal message
r.s2c(data_msg(b'A' * 100, 5000))
r.s2c(data_msg(b'B' * 100, 4800))
r.s2c(data_msg(read_rep(3, b'Z' * 100)))
# remaining length larger than anything that follows
r.s2c(data_msg(b'', 0xffffffff)[:20])
# fragment overlapping (two data messages whose remaining lengths disagree)
r.c2s(data_msg(read_req(4, 10), 100))
r.c2s(data_msg(read_req(4, 10), 100))
r.c2s(data_msg(read_req(4, 10), 0))
r.c2s(data_msg(read_req(4, 10), 0))
# an RC Send First never completed
big = data_msg(read_rep(9, b'B' * 4000))
r.s2c(big[:900], SEND_FIRST)
r.s2c(big[900:1800], SEND_MIDDLE)
mal += r.frames
w = Iwarp(5, 6, 50002, 20445)
w.c2s(mpa_req_rep('req'))
w.s2c(mpa_req_rep('rep'))
w.fpdu('c', ddp_send(data_msg(echo_req(1))[:34], msn=1))
w.fpdu('c', ddp_send(struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 24, 5000) + b'\0' * 4 + b'short', msn=2))
mal += w.frames
write_pcap(os.path.join(OUT, 'smb-direct-coverage-malformed.pcap'), mal)
if VERBOSE:
    print(len(mal), 'malformed frames')

#!/usr/bin/env python3
# Generates test/captures/icq_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic ICQ coverage captures (UDP 4000).
ICQ v5 client packets are scrambled by the protocol; they are built here
from constant placeholder bytes only (no scrambling code), so they decode
to whatever the constant bytes give. Server packets are plain.
Usage: mkicq.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from c9lib import pcap, udp_frame

C, S = '192.0.2.31', '192.0.2.32'
frames = []

def to_server(p):          # client -> server
    frames.append(udp_frame(C, S, 40000, 4000, p, len(frames) + 1))

def to_client(p):          # server -> client
    frames.append(udp_frame(S, C, 4000, 40000, p, len(frames) + 1))

def shdr(cmd, seq1=1, seq2=2, uin=1234, sess=0x11223344, ver=5):
    # version(2) unknown(1) sessionid(4) cmd(2) seq1(2) seq2(2) uin(4) checkcode(4)
    return (struct.pack('<H', ver) + b'\x00' + struct.pack('<I', sess)
            + struct.pack('<HHHII', cmd, seq1, seq2, uin, 0x5a5a5a5a))

def srv(cmd, body=b'', **kw):
    return shdr(cmd, **kw) + body

def ustr(s):                # 16 bit length prefix (including a NUL)
    s = s + b'\0'
    return struct.pack('<H', len(s)) + s

FE = b'\xfe'
def msg(mtype, data, length=None):
    return struct.pack('<HH', mtype, len(data) if length is None else length) + data

# ---------- server packets (not scrambled) ----------
for cmd in (0x000a, 0x001e, 0x0028, 0x0046, 0x0064, 0x01e0):      # no parameters
    to_client(srv(cmd))
to_client(srv(0x005a, bytes(12) + bytes([192, 0, 2, 1]) + bytes(4)))          # login reply
to_client(srv(0x006e, struct.pack('<I', 5555) + bytes([192, 0, 2, 5]) + struct.pack('<I', 4001)
              + bytes([10, 0, 0, 5]) + b'\x04' + b'\x00\x00\x00' + b'\x01\x00' + struct.pack('<I', 0x30002)))
to_client(srv(0x0078, struct.pack('<I', 5555)))                               # user offline
to_client(srv(0x024e, struct.pack('<I', 7777) + bytes([192, 0, 2, 6]) + struct.pack('<I', 4002)
              + bytes([10, 0, 0, 6]) + b'\x04' + struct.pack('<I', 0) + struct.pack('<I', 0) + struct.pack('<H', 6)))   # rand user through server
to_client(srv(0x024e, struct.pack('<I', 7778) + bytes([192, 0, 2, 7]) + struct.pack('<I', 4003)
              + bytes([10, 0, 0, 7]) + b'\x01' + struct.pack('<I', 0) + struct.pack('<I', 1) + struct.pack('<H', 7)))   # user to user
for cmd in (130, 140, 160, 180, 200, 230, 240, 250, 280, 0x7777):             # no handler: unknown command
    to_client(srv(cmd, b'\0' * 4))

# system delivered message / received message with every message type
def sys_msg(mtype, data, uin=4321, length=None):
    return srv(0x0104, struct.pack('<I', uin) + msg(mtype, data, length))

def recv_msg(mtype, data, uin=4321, length=None):
    return srv(0x00dc, struct.pack('<IHBBBB', uin, 2001, 2, 3, 4, 5) + msg(mtype, data, length))

msgs = [
    (0x0001, b'Hello there\0'),
    (0x0004, b'A page' + FE + b'http://example.org/\0'),
    (0x0006, b'nick' + FE + b'first' + FE + b'last' + FE + b'a@example.org' + FE + b'1' + FE + b'Please authorize me\0'),
    (0x0008, b'\x01\x00\x00'),
    (0x0008, b'\x00\x00\x00'),
    (0x000c, b'nick' + FE + b'first' + FE + b'last' + FE + b'a@example.org\0'),
    (0x000e, b'nick' + FE + b'first' + FE + b'last' + FE + b'a@example.org' + FE + b'x' + FE + b'Mail text\0'),
    (0x0013, b'0'),
    (0x0013, b'3' + FE + b'A' + FE + b'1' + FE + b'B' + FE + b'2' + FE + b'C' + FE + b'3' + FE),
    (0x0099, b'unknown message type'),
    (0xffff, b'field unknown'),
    (0x0004, FE + FE),                                                       # empty URL fields
    (0x0004, b'\xfe'),
    (0x000e, b'n' + FE + b'f' + FE + b'l' + FE + b'm' + FE + b'x' + FE),         # last field empty
    (0x0006, b'n' + FE + b'f' + FE + b'l' + FE + b'm' + FE + b'x' + FE),
    (0x000c, b'n' + FE + b'f' + FE + b'l' + FE),
]
for t, d in msgs:
    to_client(recv_msg(t, d))
for t, d in msgs[:4]:
    to_client(sys_msg(t, d))

# meta user
def meta(sub, result, data=b''):
    return srv(0x03de, struct.pack('<HB', sub, result) + data)

found = struct.pack('<I', 9999) + ustr(b'nick') + ustr(b'first') + ustr(b'last') + ustr(b'e@example.org') + b'\x01' + struct.pack('<H', 3) + struct.pack('<I', 4)
to_client(meta(0x019a, 0x0a, found))                                         # META_USER_FOUND
to_client(meta(0x0190, 0x0a, struct.pack('<H', len(found)) + found[:-5] + b'\x00' + struct.pack('<H', 3) + struct.pack('<I', 4)))   # EX_USER_FOUND, "who needs it"
to_client(meta(0x00e6, 0x0a, ustr(b'About me')))                              # META_ABOUT
info = b''.join(ustr(x) for x in (b'nick', b'first', b'last', b'p@example.org', b's@example.org', b'o@example.org',
                                    b'City', b'State', b'123', b'456', b'Street', b'789', b'12345'))
to_client(meta(0x00c8, 0x0a, info + struct.pack('<H', 61) + bytes([10, 1, 0, 1])))     # META_USER_INFO
to_client(meta(0x00c8, 0x14, info + struct.pack('<H', 1) + bytes([0, 0, 1, 0])))       # result: failure
to_client(meta(0x1234, 0x0a, b'\0' * 4))                                      # unknown subcommand

# multi: several packets, nested multi, the review reproducer (deep nesting)
ack = srv(0x000a)
def multi(*pkts):
    return srv(0x0212, bytes([len(pkts)]) + b''.join(struct.pack('<H', len(p)) + p for p in pkts))
to_client(multi(ack, srv(0x0078, struct.pack('<I', 1)), srv(0x0028)))
to_client(multi(multi(ack, ack), ack))
to_client(multi())
inner = ack
for _ in range(500):
    inner = multi(inner)
to_client(inner)

# ---------- other versions ----------
for v in (2, 3, 4):
    to_server(struct.pack('<H', v) + bytes(30))
to_server(struct.pack('<H', 6) + bytes(30))                                  # not ICQ
to_server(struct.pack('<H', 1) + bytes(30))

# ---------- v5 client packets: constant placeholder bytes ----------
def client(fill, size, uin=1234, check=0):
    body = bytes([fill]) * (size - 0x14)
    return struct.pack('<HI', 5, 0) + struct.pack('<I', uin) + body[:0] + bytes([fill]) * 8 + struct.pack('<I', check) + bytes([fill]) * (size - 0x18)

for fill, size, check in ((0x00, 0x20, 0), (0x00, 0x24, 0x12345678), (0x11, 0x2c, 0x1), (0x00, 0x1a, 0xffffffff),
                          (0x7f, 0x40, 0x0f0f0f0f), (0x00, 0x30, 0x80000000)):
    to_server(client(fill, size, check=check))
pcap(os.path.join(sys.argv[1], 'icq-coverage.pcap'), frames)

# ---------- malformed capture ----------
frames = []
# MSG_CONTACTS with the review's reproducer: with the fix on the branch the
# separators are found, but the pair offsets are still wrong and it ends in an exception
to_client(recv_msg(0x0013, b'2' + FE + b'Nick1' + FE + b'111' + FE + b'Nick2' + FE + b'222' + FE))
to_client(recv_msg(0x0013, b'1' + FE + b'Nick1' + FE + b'111'))
to_client(srv(0x03de, b'\x9a'))                                # cut inside the meta header
to_client(meta(0x019a, 0x0a, b'\x01\x02'))
to_client(meta(0x019a, 0xff, struct.pack('<I', 9999) + b'\xff\xff'))   # string length past the end
to_client(meta(0x00e6, 0x0a, b'\xff\xff'))
to_client(meta(0x00c8, 0x0a, ustr(b'nick')))
to_client(srv(0x00dc, b'\x01\x02'))
to_client(recv_msg(0x0001, b'x', length=500))
to_client(recv_msg(0x0006, b'nick' + FE))
to_client(srv(0x0104, b'\x01'))
to_client(srv(0x006e, b'\x01\x02'))
to_client(srv(0x024e, b'\x01\x02'))
to_client(srv(0x0078, b'\x01'))
to_client(srv(0x0212, b'\x05' + struct.pack('<H', 100)))       # multi: packet past the end
to_client(srv(0x0212, b''))
to_client(srv(0x005a, b'\x00' * 4))
to_client(shdr(0x000a)[:10])
to_client(struct.pack('<H', 5) + b'\x00')
to_client(struct.pack('<H', 5) + b'\x00\x00\x00\x00\x00')     # client header cut short
to_server(struct.pack('<H', 5) + bytes(6))
to_server(client(0x00, 0x18, check=0))
to_server(b'\x05')
pcap(os.path.join(sys.argv[1], 'icq-coverage-malformed.pcap'), frames)

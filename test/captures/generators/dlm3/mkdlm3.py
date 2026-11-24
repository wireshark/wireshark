#!/usr/bin/env python3
# Generates test/captures/dlm3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DLM3 coverage captures (Linux kernel DLM, TCP and
SCTP port 21064). Usage: mkdlm3.py <outdir>"""
import os
import struct
import sys
from pcaplib import Tcp, eth, ipv4, write_pcap

V31 = 0x00030001
V32 = 0x00030002

def hdr(ver, seq_or_ls, nodeid, length, cmd):
    return struct.pack('<IIIHBB', ver, seq_or_ls, nodeid, length, cmd, 0)

def msg_body(mtype, exflags=0, sbflags=0, flags=0, status=0, grmode=0,
             rqmode=0, bastmode=0, asts=0, result=0, extra=b''):
    b = struct.pack('<IIIIIIIIIIIIIiiiIi', mtype, 2, 0x1234, 0x00010001,
                    0x00020002, 0, 0, exflags, sbflags, flags, 7, 0xdeadbeef,
                    status, grmode, rqmode, bastmode, asts, result)
    return b + extra

def msg(ver, body, seq=0x11, nodeid=1):
    return hdr(ver, seq, nodeid, 16 + len(body), 1) + body

def rcom_body(rctype, result=0, buf=b''):
    return struct.pack('<IiQQQ', rctype, result, 0x0102030405060708, 5, 4) + buf

def rcom(ver, body, seq=0x22, nodeid=2):
    return hdr(ver, seq, nodeid, 16 + len(body), 2) + body

def rcom_lock_buf(name=b'resource-one', exflags=0x8, lvb=b'', namelen=None):
    b = struct.pack('<IIIIIIIIibbbBH', 0x4321, 0x00030003, 0x00040004, 0, 0,
                    exflags, 0x3, 9, -11, 5, 3, 2, 3, 1)
    nl = len(name) if namelen is None else namelen
    b += struct.pack('<H', nl) + name.ljust(64, b'\0')[:64]
    return b + lvb

def opts(ver, nextcmd, tlvs, inner, seq=0x33, nodeid=3, optlen=None):
    ol = len(tlvs) if optlen is None else optlen
    o = struct.pack('<BBHI', nextcmd, 0, ol, 0) + tlvs
    return hdr(ver, seq, nodeid, 16 + len(o) + len(inner), 3) + o + inner

def tlv(t, value):
    return struct.pack('<HHI', t, len(value), 0) + value

# --- SCTP ---
def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82f63b78 if c & 1 else c >> 1
        t.append(c)
    return t
_T = _crc32c_table()
def crc32c(b):
    c = 0xffffffff
    for x in b:
        c = _T[(c ^ x) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff

class Sctp:
    def __init__(self, sport=21064, dport=21064):
        self.sport, self.dport, self.tsn = sport, dport, 100
    def data(self, payload, src='192.0.2.11', dst='192.0.2.12'):
        clen = 16 + len(payload)
        chunk = struct.pack('!BBHIHHI', 0, 3, clen, self.tsn, 0, self.tsn - 100, 0) + payload
        chunk += b'\0' * ((4 - clen % 4) % 4)
        self.tsn += 1
        pkt = struct.pack('!HHII', self.sport, self.dport, 0x01020304, 0) + chunk
        pkt = pkt[:8] + struct.pack('<I', crc32c(pkt)) + pkt[12:]
        return eth(ipv4(132, pkt, src=src, dst=dst))

ALL_EXFLAGS = 0x7ffff
LVB = bytes(range(32))

def main_frames():
    f = []
    t = Tcp(40000, 21064, csrc='192.0.2.1', ssrc='192.0.2.2')
    # 1-14: version 3.1 messages, every message type, every flag
    f.append(t.c2s(msg(V31, msg_body(1, exflags=ALL_EXFLAGS, sbflags=7, flags=3,
                                     status=1, grmode=-1, rqmode=5, bastmode=0, asts=3))))
    f.append(t.c2s(msg(V31, msg_body(2, exflags=0x5, status=2, grmode=1, rqmode=4, bastmode=2, asts=1))))
    f.append(t.c2s(msg(V31, msg_body(3, status=3, grmode=3, asts=2, result=-11))))
    f.append(t.c2s(msg(V31, msg_body(4, result=-12))))
    f.append(t.s2c(msg(V31, msg_body(5, result=-22, sbflags=1), nodeid=2)))
    f.append(t.s2c(msg(V31, msg_body(6, result=-35, sbflags=2), nodeid=2)))
    f.append(t.s2c(msg(V31, msg_body(7, result=-0x10002), nodeid=2)))
    f.append(t.s2c(msg(V31, msg_body(8, result=-0x10001), nodeid=2)))
    f.append(t.s2c(msg(V31, msg_body(9, result=-53, grmode=2), nodeid=2)))
    f.append(t.s2c(msg(V31, msg_body(10, result=-57, bastmode=5, asts=2), nodeid=2)))
    f.append(t.c2s(msg(V31, msg_body(11, result=-71, extra=b'resource-name'))))
    f.append(t.c2s(msg(V31, msg_body(12, result=-95, extra=b'resource-name'))))
    f.append(t.s2c(msg(V31, msg_body(13, result=-110), nodeid=2)))
    # 14: purge, plus two more messages in the same segment
    f.append(t.c2s(msg(V31, msg_body(14, result=-115)) + msg(V31, msg_body(15, result=1))
                   + msg(V31, msg_body(1, extra=LVB))))
    # 15-16: a request split over two segments
    big = msg(V31, msg_body(1, exflags=0x8, extra=bytes(range(200))))
    f.append(t.c2s(big[:50]))
    f.append(t.c2s(big[50:]))
    # 17-25: version 3.1 recovery commands
    f.append(t.c2s(rcom(V31, rcom_body(1, buf=struct.pack('<IIQ', 1, 0, 0)))))  # status, minor 1
    f.append(t.c2s(rcom(V31, rcom_body(2, buf=b'names...'))))
    f.append(t.c2s(rcom(V31, rcom_body(3, buf=b'lookup-name'))))
    f.append(t.c2s(rcom(V31, rcom_body(4, buf=rcom_lock_buf(lvb=LVB)))))
    f.append(t.s2c(rcom(V31, rcom_body(5, buf=struct.pack('<IIQ', 32, ALL_EXFLAGS | 0x80000, 0)))))
    f.append(t.s2c(rcom(V31, rcom_body(6, result=-11))))  # no rc_buf
    f.append(t.s2c(rcom(V31, rcom_body(7, buf=b'\x01\x00\x00\x00'))))
    f.append(t.s2c(rcom(V31, rcom_body(8, buf=rcom_lock_buf(exflags=0, name=b'x' * 64)))))
    f.append(t.c2s(rcom(V31, rcom_body(4, buf=rcom_lock_buf(exflags=0, lvb=LVB)))))  # LVB not flagged
    # 26: lock with a name length above 64; 27: status reply too short;
    # 28: lock buffer too short; 29: status buffer too short
    f.append(t.c2s(rcom(V31, rcom_body(4, buf=rcom_lock_buf(namelen=80)))))
    f.append(t.s2c(rcom(V31, rcom_body(5, buf=b'\0' * 8))))
    f.append(t.c2s(rcom(V31, rcom_body(4, buf=b'\0' * 20))))
    f.append(t.c2s(rcom(V31, rcom_body(1, buf=b'\0' * 8))))
    # 30: version 3.0 status: the status buffer is not decoded (minor 0);
    # versions other than 3.1 and 3.2 get only the protocol item
    f.append(t.c2s(rcom(0x00030000, rcom_body(1, buf=struct.pack('<IIQ', 1, 0, 0)))))
    # 31: version 3.1 with a command other than message/recovery
    f.append(t.c2s(hdr(V31, 0, 1, 16, 4)))
    # 32: a segment that is not DLM3 (major version 2)
    f.append(t.c2s(hdr(0x00020001, 0, 1, 16, 1)))

    # --- version 3.2 on a second connection ---
    t2 = Tcp(40001, 21064, csrc='192.0.2.3', ssrc='192.0.2.2')
    f.append(t2.c2s(msg(V32, msg_body(1, exflags=0x9, status=1, rqmode=5, asts=1), seq=1)))  # 33
    f.append(t2.s2c(msg(V32, msg_body(5, result=0, grmode=5), seq=1, nodeid=2)))          # 34
    f.append(t2.c2s(rcom(V32, rcom_body(1, buf=struct.pack('<IIQ', 1, 0, 0)), seq=2)))    # 35
    f.append(t2.s2c(rcom(V32, rcom_body(5, buf=struct.pack('<IIQ', 32, 0x8, 0)), seq=2, nodeid=2)))  # 36
    f.append(t2.c2s(hdr(V32, 3, 1, 16, 4)))                                               # 37 ack
    f.append(t2.c2s(hdr(V32, 4, 1, 16, 5)))                                               # 38 fin
    inner_m = msg(V32, msg_body(3, status=2, grmode=4, asts=2), seq=0)
    f.append(t2.c2s(opts(V32, 1, tlv(0x0101, b'AAAA') + tlv(0x0202, b'BB') + tlv(3, b''), inner_m, seq=5)))  # 39
    inner_r = rcom(V32, rcom_body(4, buf=rcom_lock_buf(lvb=LVB)), seq=0)
    f.append(t2.c2s(opts(V32, 2, tlv(7, b'1234567'), inner_r, seq=6)))                    # 40
    f.append(t2.c2s(opts(V32, 1, b'', inner_m, seq=7)))                                   # 41 no options
    f.append(t2.c2s(opts(V32, 1, tlv(1, b'ab') + b'\x09\x00\x00', inner_m, seq=8)))       # 42 trailing octets
    f.append(t2.c2s(hdr(V32, 9, 1, 16, 9)))                                               # 43 unknown cmd

    # --- reproducer: dlm3_v32_header_twice.py ---
    t3 = Tcp(40002, 21064, csrc='192.0.2.5')
    m = struct.pack('<I', 1) + b''.join(struct.pack('<I', 0x1100 + i) for i in range(17))
    p1 = struct.pack('<IIIHBB', V32, 7, 0x0a, 16 + len(m), 1, 0) + m
    tl = struct.pack('<HHI', 0x0101, 4, 0) + b'AAAA' + struct.pack('<HHI', 0x0202, 2, 0) + b'BB'
    inner = struct.pack('<IIIHBB', V32, 0, 0x0a, 16 + len(m), 1, 0) + m
    o = struct.pack('<BBHI', 1, 0, len(tl), 0) + tl
    p2 = struct.pack('<IIIHBB', V32, 8, 0x0a, 16 + len(o) + len(inner), 3, 0) + o + inner
    f.append(t3.c2s(p1))                                                                  # 44
    f.append(t3.c2s(p2))                                                                  # 45

    # --- SCTP ---
    s = Sctp()
    f.append(s.data(msg(V31, msg_body(1, rqmode=3))))                                     # 46
    f.append(s.data(rcom(V32, rcom_body(3, buf=b'name')), src='192.0.2.12', dst='192.0.2.11'))  # 47
    return f

def malformed_frames():
    f = []
    t = Tcp(40010, 21064)
    # 1: v3.1 message shorter than a message.
    f.append(t.c2s(hdr(V31, 0, 1, 40, 1) + bytes(24)))
    # 2: v3.1 recovery command shorter than one.
    f.append(t.c2s(hdr(V31, 0, 1, 30, 2) + bytes(14)))
    # 3: v3.2 options shorter than the options header.
    f.append(t.c2s(hdr(V32, 0, 1, 20, 3) + bytes(4)))
    # 4: options length past the message.
    f.append(t.c2s(opts(V32, 1, tlv(1, b'ab'), b'', optlen=200)))
    # 5: TLV length past the options.
    f.append(t.c2s(opts(V32, 1, struct.pack('<HHI', 1, 50, 0) + b'ab', b'')))
    # 6: options with a nested message too short.
    f.append(t.c2s(opts(V32, 1, tlv(1, b'ab'), hdr(V32, 0, 1, 20, 1) + bytes(4))))
    # 7: options with a nested recovery command too short.
    f.append(t.c2s(opts(V32, 2, tlv(1, b'ab'), hdr(V32, 0, 1, 20, 2) + bytes(4))))
    # 8: options with an unknown next command.
    f.append(t.c2s(opts(V32, 4, tlv(1, b'ab'), hdr(V32, 0, 1, 16, 4))))
    # 9: v3.2 message too short; 10: v3.2 recovery command too short.
    f.append(t.c2s(hdr(V32, 0, 1, 40, 1) + bytes(24)))
    f.append(t.c2s(hdr(V32, 0, 1, 30, 2) + bytes(14)))
    # 11: header length 2 (shorter than the header).
    f.append(t.c2s(struct.pack('<IIIHBB', V31, 0, 1, 2, 1, 0)))
    # 12-13: SCTP: short and non-DLM3 data.
    s = Sctp()
    f.append(s.data(b'\x01\x00\x03\x00'))
    f.append(s.data(hdr(0x00030005, 0, 1, 16, 1)))
    # 14: lock buffer with a name length above 64 and the VALBLK flag: no LVB
    f.append(t.c2s(rcom(V31, rcom_body(4, buf=rcom_lock_buf(namelen=65)[:-10]))))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dlm3-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dlm3-coverage-malformed.pcap'), malformed_frames())

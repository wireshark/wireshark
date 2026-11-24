#!/usr/bin/env python3
# Generates test/captures/knet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the kNet (KristalliNet) captures.
Usage: mkknet.py <outdir> [-v].  Writes knet-coverage.pcap and knet-coverage-malformed.pcap."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

C, S = '192.0.2.10', '192.0.2.20'
PORT = 2345

def vle(n):
    """kNet variable length: 1 octet (< 128 and next octet without the top bit), 2 or 4 octets"""
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x80 | (n & 0x7f), n >> 7])
    return bytes([0x80 | (n & 0x7f), 0x80 | ((n >> 7) & 0x7f), (n >> 14) & 0xff, (n >> 22) & 0xff])

def ping(i=7):   return bytes([1, i])
def pong(i=7):   return bytes([2, i])
def flow(v=0x010203): return bytes([3]) + struct.pack('<I', v)[:3]
def pack_ack(a=0x000102, seq=0x11223344): return bytes([4]) + struct.pack('<I', a)[:3] + struct.pack('<I', seq)
def app(i=100, n=10): return bytes([i]) + bytes(i & 0x7f for i in range(n))
def conn(i, n=4): return bytes([i, 0, 0, 0]) + bytes(i & 0x7f for i in range(n))

def tcp_pdu(msg): return vle(len(msg)) + msg
sctp_pdu = tcp_pdu

def udp_msg(msg, flags=0, rmn=None):
    L = len(msg)
    b = bytes([L & 0xff, (flags << 4) | (L >> 8)])
    if rmn is not None:
        b += bytes([rmn]) if rmn < 0x80 else bytes([0x80 | (rmn & 0x7f), rmn >> 7])
    return b + msg

def udp_dgram(pid, msgs, inorder=False, rel=False, rmib=None):
    b0 = (0x80 if inorder else 0) | (0x40 if rel else 0) | (pid & 63)
    b = bytes([b0, (pid >> 6) & 0xff, (pid >> 14) & 0xff])
    if rel:
        b += rmib if isinstance(rmib, bytes) else struct.pack('<H', 1 if rmib is None else rmib)
    return b + b''.join(msgs)

def sctp_pkt(p, src, dst, sp, dp, data, tsn, stream_seq):
    chunk_len = 16 + len(data)
    ch = struct.pack('!BBHIHHI', 0, 3, chunk_len, tsn, 0, stream_seq, 0) + data
    ch += b'\0' * (-len(ch) % 4)
    hdr = struct.pack('!HHII', sp, dp, 0x1234, 0)
    p.raw(p.eth(p.ip(src, dst, 132, hdr + ch)))

def mk_main(path):
    p = Pcap()
    # --- UDP -------------------------------------------------------------
    n = [0]
    def u(msgs, **kw):
        n[0] += 1
        p.udp(C, S, 40000, PORT, udp_dgram(n[0], msgs, **kw))
    def ur(msgs, **kw):
        n[0] += 1
        p.udp(S, C, PORT, 40000, udp_dgram(n[0], msgs, **kw))
    # Unreliable datagrams with each non-connection message
    u([udp_msg(ping())])
    ur([udp_msg(pong())])
    u([udp_msg(flow())], inorder=True)
    u([udp_msg(pack_ack())], inorder=True)
    u([udp_msg(app(100, 20))])
    u([udp_msg(app(101, 1))])
    u([udp_msg(bytes([77]))])                 # one octet: message ID only
    # connection messages (4 octet IDs) are not the last message of the datagram,
    # the dissector's payload length is 3 octets too long for the last one
    u([udp_msg(conn(253, 8)), udp_msg(ping())])
    ur([udp_msg(conn(252, 8)), udp_msg(ping())])
    u([udp_msg(conn(251, 0)), udp_msg(ping())])
    u([udp_msg(conn(255, 0)), udp_msg(ping())])
    ur([udp_msg(conn(254, 0)), udp_msg(ping())])
    # Several messages in one datagram (separator in the info column)
    u([udp_msg(ping(1)), udp_msg(pong(2)), udp_msg(flow()), udp_msg(pack_ack()), udp_msg(app())])
    # message flags: fragment start, fragment, inorder, reliable (RMN of 1 and 2 octets)
    for fl in (0x8, 0x4, 0x2, 0xE, 0xC):
        u([udp_msg(app(120, 6), flags=fl)])
    u([udp_msg(app(121, 6), flags=0x1, rmn=5)])
    u([udp_msg(app(121, 6), flags=0x1, rmn=0x1234), udp_msg(ping(), flags=0x3, rmn=0x7f)])
    # reliable datagram: RMIB of 2 octets, and of 4 octets
    u([udp_msg(ping())], rel=True, rmib=0x0102)
    u([udp_msg(app(130, 4), flags=0x1, rmn=9)], rel=True, rmib=bytes([0x2b, 0x9a, 0x01, 0x00]), inorder=True)
    # large packet ID, content length with the high nibble set
    n[0] = 0x3fffff - 3
    u([udp_msg(app(140, 300))])
    u([udp_msg(app(141, 200), flags=0x1, rmn=3)])
    # padding after the last message (at most 2 octets: loop ends)
    p.udp(C, S, 40001, PORT, udp_dgram(900, [udp_msg(ping())]) + b'\0\0')
    # an empty message (content length 0) ends the loop
    p.udp(C, S, 40001, PORT, udp_dgram(901, [udp_msg(ping()), bytes([0, 0, 0, 0])]))
    # --- TCP ---------------------------------------------------------------
    sp = 41000
    p.tcp(C, S, sp, PORT, b'', flags=0x02)
    p.tcp(S, C, PORT, sp, b'', flags=0x12)
    p.tcp(C, S, sp, PORT, b'', flags=0x10)
    p.tcp(C, S, sp, PORT, tcp_pdu(ping(3)))
    p.tcp(S, C, PORT, sp, tcp_pdu(pong(3)))
    p.tcp(C, S, sp, PORT, tcp_pdu(flow()))
    p.tcp(S, C, PORT, sp, tcp_pdu(pack_ack()))
    # several PDUs in one segment
    p.tcp(C, S, sp, PORT, tcp_pdu(app(100, 20)) + tcp_pdu(ping(4)) + tcp_pdu(app(101, 1)))
    # a PDU split over two segments, and one split after the 2 octet header
    pdu = tcp_pdu(app(102, 50))
    p.tcp(C, S, sp, PORT, pdu[:20])
    p.tcp(C, S, sp, PORT, pdu[20:])
    pdu = tcp_pdu(app(103, 30))
    p.tcp(S, C, PORT, sp, pdu[:2])
    p.tcp(S, C, PORT, sp, pdu[2:])
    # 2 octet VLE length (200 octets)
    p.tcp(C, S, sp, PORT, tcp_pdu(app(104, 199)))
    # 4 octet VLE length (20000 octets) over three segments
    pdu = tcp_pdu(bytes([105]) + bytes(i & 0x7f for i in range(19999)))
    p.tcp(C, S, sp, PORT, pdu[:9000])
    p.tcp(C, S, sp, PORT, pdu[9000:15000])
    p.tcp(C, S, sp, PORT, pdu[15000:])
    p.tcp(S, C, PORT, sp, tcp_pdu(app(106, 5)))
    p.tcp(C, S, sp, PORT, b'', flags=0x11)
    p.tcp(S, C, PORT, sp, b'', flags=0x11)
    # --- SCTP ----------------------------------------------------------------
    t = 1
    for i, m in enumerate((ping(5), pong(5), flow(), pack_ack(), app(107, 12), app(108, 1))):
        sctp_pkt(p, C, S, 42000, PORT, sctp_pdu(m), t, i)
        t += 1
    p.write(path)

def mk_mal(path):
    p = Pcap()
    n = [0]
    def u(raw):
        p.udp(C, S, 40010, PORT, raw)
    # connection messages as the only/last message: payload 3 octets past the end
    for i in (253, 252, 251, 255, 254):
        n[0] += 1
        u(udp_dgram(n[0], [udp_msg(conn(i, 4))]))
    n[0] += 1; u(udp_dgram(n[0], [udp_msg(conn(255, 0))]))
    # datagram header cut short, RMIB cut short, message cut short, content length past the end
    u(b'\x01')
    u(b'\x01\x00\x00')
    u(b'\x41\x00\x00\x01')
    u(b'\xc1\x00\x00\x81')
    u(b'\x01\x00\x00\x10\x00')
    u(b'\x01\x00\x00\x02\x00\x01')
    u(b'\x01\x00\x00\x02\x10')
    u(udp_dgram(5, [bytes([0x20, 0x00]) + b'\x01\x02']))
    u(udp_dgram(6, [udp_msg(app(100, 10))[:6]]))
    u(udp_dgram(7, [bytes([0xff, 0x0f]) + b'\x01']))
    u(udp_dgram(8, [bytes([0x05, 0x10, 0x81]) + b'\x01\x02\x03\x04']))     # RMN of 2 octets cut short
    u(udp_dgram(9, [udp_msg(pack_ack())[:6]]))
    u(udp_dgram(10, [udp_msg(flow())[:4]]))
    # TCP: connection message in a PDU, sizes cut short, zero length
    sp = 43000
    def t(raw, s=None):
        p.tcp(C, S, s or sp, PORT, raw)
    t(tcp_pdu(conn(253, 4)))
    t(tcp_pdu(conn(255, 0)), sp + 1)
    t(tcp_pdu(pack_ack())[:6], sp + 2)       # incomplete PDU, never completed
    t(tcp_pdu(pack_ack()[:4]), sp + 3)       # content length says 8, 4 present in a PDU of its own
    t(bytes([0x00, 0x01, 0x02]), sp + 4)     # content length 0: not kNet
    t(bytes([0x05]), sp + 5)                 # one octet only: not kNet
    t(bytes([0x82]), sp + 6)                 # one octet, VLE says 2 octets
    t(bytes([0x82, 0x81]), sp + 7)           # VLE of 4 octets cut short
    t(vle(30000) + bytes([1, 2, 3]), sp + 8) # 4 octet VLE, short data
    # SCTP: connection message and truncated messages
    sctp_pkt(p, C, S, 42010, PORT, sctp_pdu(conn(251, 2)), 1, 0)
    sctp_pkt(p, C, S, 42010, PORT, sctp_pdu(pack_ack())[:5], 2, 1)
    sctp_pkt(p, C, S, 42010, PORT, b'\x05', 3, 2)
    sctp_pkt(p, C, S, 42010, PORT, b'\x82', 4, 3)
    sctp_pkt(p, C, S, 42010, PORT, b'\x00\x01', 5, 4)
    p.write(path)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mk_main(os.path.join(out, 'knet-coverage.pcap'))
    mk_mal(os.path.join(out, 'knet-coverage-malformed.pcap'))

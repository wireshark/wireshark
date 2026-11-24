#!/usr/bin/env python3
# Generates test/captures/dccp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCCP dissector
(packet-dccp.c, Datagram Congestion Control Protocol, RFC 4340, with
the CCID 3 options of RFC 4342 and the MP-DCCP options of RFC 9897).

DCCP is IP protocol 33. Every packet is built from scratch with struct,
with a correct checksum unless noted; no captured traffic is used. The
main capture is pcapng because one frame (a reproducer) is an Exported
PDU (link type 252) and all others are Ethernet.

Usage: mkdccp.py <output directory>

Writes:
  dccp-coverage.pcapng           handshakes over IPv4, IPv6 and ILNP,
                                 every packet type, long and short
                                 sequence numbers (absolute and
                                 relative), every option incl. feature
                                 negotiation, CCID 3 and MP-DCCP,
                                 partial checksum coverage, LTP, a
                                 NetPerfMeter heuristic and plain data
                                 payload, the reproducers of the fixes
  dccp-coverage-malformed.pcapng bad checksums, header lengths too
                                 small for the packet type, options
                                 cut short or with bad lengths that
                                 throw, the large MP_CONFIRM reproducer
"""

import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


# ---------------------------------------------------------------- DCCP
def dccp(sport, dport, ptype, seq, x=1, sub=b'', opts=b'', payload=b'',
         data_offset=None, ccval=0, cscov=0, res=0):
    """Generic header + type subheader + options (padded with zeros to
    a multiple of 4) + payload. Checksum left 0 (filled by ip4/ip6)."""
    if len(opts) % 4:
        opts += b'\0' * (4 - len(opts) % 4)
    if x:
        gen = struct.pack('>HHBBHBB', sport, dport, 0, (ccval << 4) | cscov, 0,
                          (res << 5) | (ptype << 1) | 1, 0) + seq.to_bytes(6, 'big')
    else:
        gen = struct.pack('>HHBBHB', sport, dport, 0, (ccval << 4) | cscov, 0,
                          (res << 5) | (ptype << 1)) + (seq & 0xffffff).to_bytes(3, 'big')
    hdr = gen + sub + opts
    if data_offset is None:
        data_offset = len(hdr) // 4
    hdr = hdr[:4] + bytes([data_offset]) + hdr[5:]
    return bytearray(hdr + payload)


def ack48(ack):
    return struct.pack('>H', 0) + ack.to_bytes(6, 'big')


def ack24(ack):
    return bytes([0]) + (ack & 0xffffff).to_bytes(3, 'big')


def coverage(seg):
    cs = seg[5] & 0x0f
    if cs == 0:
        return len(seg)
    return min(len(seg), (seg[4] + cs - 1) * 4)


def ip4(src, dst, seg, bad_csum=False, ident=[0]):
    seg = bytearray(seg)
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 33, len(seg))
    c = csum(ph + bytes(seg[:coverage(seg)]))
    if bad_csum:
        c ^= 0x5555
    struct.pack_into('>H', seg, 6, c)
    ident[0] += 1
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), ident[0], 0, 64, 33, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return MAC_B + MAC_A + b'\x08\x00' + ip + bytes(seg)


def ip6(src, dst, seg, nonce=None):
    """IPv6, or with nonce: a Destination Options header with an ILNP
    Nonce option, so that the addresses are ILNP NIDs (the low 64 bits)
    and the checksum pseudo-header uses only those."""
    seg = bytearray(seg)
    if nonce is None:
        ps, pd = src, dst
    else:
        ps, pd = src[8:], dst[8:]
    ph = ps + pd + struct.pack('>I', len(seg)) + b'\0\0\0' + bytes([33])
    struct.pack_into('>H', seg, 6, csum(ph + bytes(seg[:coverage(seg)])))
    if nonce is None:
        ext, nh = b'', 33
    else:
        opt = bytes([0x8b, len(nonce)]) + nonce
        body = bytes([33, 0]) + opt
        pad = (-len(body)) % 8
        if pad == 1:
            body += b'\0'
        elif pad:
            body += bytes([1, pad - 2]) + b'\0' * (pad - 2)
        ext = bytes([body[0], len(body) // 8 - 1]) + body[2:]
        nh = 60
    ip = struct.pack('>IHBB', 0x60000000, len(ext) + len(seg), nh, 64) + src + dst
    return MAC_B + MAC_A + b'\x86\xdd' + ip + ext + bytes(seg)


def epdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


# ---------------------------------------------------------------- options
def opt(t, data=b''):
    return bytes([t, len(data) + 2]) + data


def feat(t, number, values=b''):
    return opt(t, bytes([number]) + values)


def mp(sub, data=b''):
    return opt(46, bytes([sub]) + data)


# ---------------------------------------------------------------- pcapng
def pcapng(path, frames):
    """frames: list of (interface, data[, original length])"""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))      # Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 262144))    # Exported PDU
    for i, fr in enumerate(frames):
        ifc, data = fr[0], fr[1]
        olen = fr[2] if len(fr) > 2 else len(data)
        ts = (1700000000 + i) * 1000000 + 1000 * i
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), olen) + data)
    with open(path, 'wb') as f:
        f.write(out)


A4 = bytes([192, 0, 2, 10])
B4 = bytes([198, 51, 100, 20])
R4 = bytes([192, 0, 2, 1])       # reproducer addresses
S4 = bytes([198, 51, 100, 1])
A6 = bytes.fromhex('20010db8000000000000000000000010')
B6 = bytes.fromhex('20010db8000000000000000000000020')
L6 = bytes.fromhex('20010db8000a00000000000000000011')
M6 = bytes.fromhex('20010db8000b00000000000000000022')

SC_NPMP = 1852861808  # "npmp", NPMP_SERVICE_CODE


def E(fr):
    return (0, fr)


def main_frames():
    F = []
    # ---- 1-10: conversation 0, IPv4 192.0.2.10:40001 -> 198.51.100.20:5001,
    #      long sequence numbers, a full exchange with options
    c, s = 40001, 5001
    F.append(E(ip4(A4, B4, dccp(c, s, 0, 0x100000000000, sub=struct.pack('>I', SC_NPMP),
        opts=feat(32, 1, b'\x02\x03') + feat(34, 3, (100).to_bytes(6, 'big'))
             + feat(34, 2, b'\x01') + feat(32, 4, b'\x00') + feat(32, 6, b'\x01')
             + feat(32, 7, b'\x01') + feat(32, 8, b'\x00\x01') + feat(32, 9, b'\x00')
             + feat(32, 192, b'\x01') + opt(41, struct.pack('>I', 0x11111111))
             + b'\x01\x02\x00'))))
    F.append(E(ip4(B4, A4, dccp(s, c, 1, 0x200000000000,
        sub=ack48(0x100000000000) + struct.pack('>I', SC_NPMP),
        opts=feat(33, 1, b'\x02') + feat(35, 3, (100).to_bytes(6, 'big'))
             + feat(33, 2, b'\x01') + opt(36, b'cookie-0123456789')
             + opt(42, struct.pack('>IH', 0x11111111, 10))))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 0x100000000001, sub=ack48(0x200000000000),
        opts=opt(42, struct.pack('>II', 0x11111111, 100000)) + opt(38, b'\x00\x05')
             + opt(39, b'\x40\x01') + opt(43, struct.pack('>H', 5))
             + opt(37, b'\x01') + opt(43, struct.pack('>I', 70000))))))
    F.append(E(ip4(A4, B4, dccp(c, s, 4, 0x100000000002, sub=ack48(0x200000000000),
        opts=opt(44, struct.pack('>I', 0xdeadbeef)) + opt(40, b'\x00\x10\x20')
             + opt(37, b'\x01\x02\x03\x04\x05\x06'),
        payload=b'first data'))))
    F.append(E(ip4(B4, A4, dccp(s, c, 2, 0x200000000001,
        opts=opt(192, struct.pack('>I', 1000)) + opt(193, bytes(range(9)))
             + opt(194, struct.pack('>I', 125000)) + opt(42, struct.pack('>I', 7)),
        payload=b'reply data'))))
    F.append(E(ip4(B4, A4, dccp(s, c, 4, 0x200000000002, sub=ack48(0x100000000002),
        opts=opt(192, struct.pack('>I', 0xffffffff)) + opt(41, struct.pack('>I', 9)),
        payload=b'more'))))
    F.append(E(ip4(A4, B4, dccp(c, s, 8, 0x100000000003, sub=ack48(0x200000000002)))))
    F.append(E(ip4(B4, A4, dccp(s, c, 9, 0x200000000003, sub=ack48(0x100000000003)))))
    F.append(E(ip4(B4, A4, dccp(s, c, 5, 0x200000000004, sub=ack48(0x100000000003)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 6, 0x100000000004, sub=ack48(0x200000000004)))))
    F.append(E(ip4(B4, A4, dccp(s, c, 7, 0x200000000005, sub=ack48(0x100000000004)
                                + bytes([1, 0, 0, 0])))))
    # ---- 12-18: conversation 1: Request/Response with long numbers, then
    #      short sequence numbers (24 bit), relative to the handshake
    c, s = 40002, 5002
    F.append(E(ip4(A4, B4, dccp(c, s, 0, 0x0000fffffff0, sub=struct.pack('>I', 0)))))
    F.append(E(ip4(B4, A4, dccp(s, c, 1, 0x000000123456, sub=ack48(0x0000fffffff0)
                                + struct.pack('>I', 0)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 0x0000fffffff1, x=0, sub=ack24(0x123456)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 0x000100000005, x=0, payload=b'short seq wraps'))))
    F.append(E(ip4(B4, A4, dccp(s, c, 4, 0x000000123457, x=0, sub=ack24(0x000100000005),
                                payload=b'short ack'))))
    F.append(E(ip4(B4, A4, dccp(s, c, 2, 0x000000123458, x=0, ccval=5, payload=b'ccval 5'))))
    F.append(E(ip4(A4, B4, dccp(c, s, 7, 0x000100000006, sub=ack48(0x000000123458)
                                + bytes([2, 1, 2, 3])))))
    # ---- 19-43: conversation 2: packets without a handshake (absolute
    #      numbers), Listen, every Reset code and the reserved types
    c, s = 40003, 5003
    F.append(E(ip4(B4, A4, dccp(s, c, 10, 77, sub=struct.pack(">I", 7107696)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 1000, x=0, payload=b'no handshake'))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 1001, x=0, sub=ack24(500)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 1002, sub=ack48(501)))))
    # Sync and Response acknowledging a flow without a handshake
    F.append(E(ip4(A4, B4, dccp(c, s, 8, 1003, sub=ack48(501)))))
    F.append(E(ip4(B4, A4, dccp(s, c, 1, 502, sub=ack48(1003) + struct.pack('>I', 0)))))
    for code in list(range(13)) + [0x80]:
        F.append(E(ip4(B4, A4, dccp(s, c, 7, 600 + code, sub=ack48(1002)
                                    + bytes([code, code, 0, 0xff])))))
    for t in range(11, 16):
        F.append(E(ip4(A4, B4, dccp(c, s, t, 2000 + t, payload=b'reserved'))))
    # ---- conversation 3: option coverage in Data packets (each packet
    #      one group of options)
    c, s = 40004, 5004
    F.append(E(ip4(A4, B4, dccp(c, s, 0, 1, sub=struct.pack('>I', 0xffffffff)))))
    # feature options: every feature category, Sequence Window and Ack
    # Ratio with 1 to 7 octet values and an empty Confirm, MP_CAPABLE,
    # reserved and CCID specific features
    o = b''
    for n in range(1, 8):
        o += feat(34, 3, bytes(range(1, n + 1)))
    o += feat(35, 3) + feat(35, 5, b'\x02') + feat(34, 10, b'\x00\x01')
    o += feat(32, 0, b'\x05') + feat(32, 11, b'\x01') + feat(32, 0x80, b'\x01')
    o += feat(33, 0xc1, b'\x01\x02') + feat(33, 0xff)
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 2, opts=o, payload=b'features'))))
    # one octet options: padding, mandatory, slow receiver, reserved 3-31;
    # reserved 47-127 and CCID options 128-191 and 195-255; Quick-Start
    # Response (45) is not dissected ("Unknown")
    o = b'\x00\x01\x02\x03\x1f' + opt(47, b'\x01') + opt(127, b'') + opt(128, b'\xaa')
    o += opt(191, b'\x01\x02') + opt(195, b'') + opt(255, b'\xff') + opt(45, b'\x00\x01')
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 3, opts=o, payload=b'one octet'))))
    # options with lengths that are wrong but stay inside the option
    # (warnings): timestamp, timestamp echo, elapsed time, data checksum,
    # NDP count, loss event rate, receive rate
    o = opt(41, b'\x01\x02') + opt(42, b'\x01\x02') + opt(43, b'\x01\x02\x03')
    o += opt(44, b'\x01') + opt(37, b'\x01' * 7) + opt(192, b'\x01') + opt(194, b'\x01')
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 4, opts=o, payload=b'bad lengths'))))
    # MP-DCCP options with good lengths
    o = mp(0, mp(9, b'\x05')) + mp(1, b'\x01' + struct.pack('>II', 0x01020304, 0x0a0b0c0d))
    o += mp(2) + mp(3, b'\x00' + bytes(range(8))) + mp(4, (12345).to_bytes(6, 'big'))
    o += mp(5, bytes(range(20))) + mp(6, b'\x01' + struct.pack('>II', 1500, 20))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 5, opts=o, payload=b'mp 1'))))
    o = mp(7, b'\x01' + bytes([198, 51, 100, 7])) + mp(7, b'\x02' + bytes([198, 51, 100, 8]) + b'\x13\x88')
    o += mp(7, b'\x03' + A6) + mp(7, b'\x04' + B6 + b'\x13\x89') + mp(8, b'\x02')
    o += mp(10, bytes(range(1, 9))) + mp(11, b'\x01\x02') + mp(11)
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 6, opts=o, payload=b'mp 2'))))
    # MP-DCCP options with wrong lengths (warnings) and an unknown one
    o = mp(1, b'\x01\x02') + mp(3, b'\x00\x01') + mp(4, b'\x01\x02\x03\x04')
    o += mp(5, b'\x01') + mp(6, b'\x01\x02') + mp(7, b'\x01\x02\x03') + mp(8, b'\x01\x02')
    o += mp(9, b'\x01\x02') + mp(12, b'\x01') + mp(3, b'\x00' + bytes(69))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 7, opts=o, payload=b'mp bad'))))
    # MP_CONFIRM of several options, and nested MP_CONFIRM
    o = mp(0, mp(9, b'\x01') + mp(8, b'\x03') + mp(0, mp(4, (7).to_bytes(6, 'big'))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 8, opts=o, payload=b'confirm'))))
    # option with length 1 (< 2): the rest of the options is skipped
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 9, opts=b'\x29\x01\x00\x00', payload=b'len 1'))))
    # ---- conversation 4: IPv6, checksum coverage
    c, s = 40005, 5005
    F.append(E(ip6(A6, B6, dccp(c, s, 0, 10, sub=struct.pack('>I', 0)))))
    F.append(E(ip6(B6, A6, dccp(s, c, 1, 20, sub=ack48(10) + struct.pack('>I', 0)))))
    # CsCov 1: only the header is covered; CsCov 15: more than the packet
    F.append(E(ip6(A6, B6, dccp(c, s, 2, 11, cscov=1, payload=b'header only covered'))))
    F.append(E(ip6(A6, B6, dccp(c, s, 2, 12, cscov=15, payload=b'all covered'))))
    F.append(E(ip4(A4, B4, dccp(40004, 5004, 2, 10, cscov=2, payload=b'one word of data covered'))))
    # ---- ILNP: IPv6 with an ILNP Nonce destination option
    F.append(E(ip6(L6, M6, dccp(40006, 5006, 0, 1, sub=struct.pack('>I', 0)), nonce=b'\x11\x22\x33\x44')))
    F.append(E(ip6(M6, L6, dccp(5006, 40006, 1, 9, sub=ack48(1) + struct.pack('>I', 0)),
                   nonce=bytes(range(12)))))
    # ---- payload: LTP by port 1113 (low and high port), NetPerfMeter
    #      by heuristic, data
    ltp = bytes([0x0c, 0x01, 0x01, 0x00, 0x00])
    F.append(E(ip4(A4, B4, dccp(1113, 40007, 2, 1, payload=ltp))))
    F.append(E(ip4(A4, B4, dccp(0, 1113, 2, 2, payload=ltp))))
    npm = struct.pack('>BBHIQQH', 4, 0, 26, 1, 0x4bcdf3aa303c6774, 42, 0)
    F.append(E(ip4(A4, B4, dccp(40008, 9000, 2, 1, payload=npm))))
    F.append(E(ip4(A4, B4, dccp(40008, 9000, 2, 2, payload=b'\x04' + b'\0' * 30))))
    # ---- truncated: captured length smaller than the packet (checksum
    #      not checked)
    fr = ip4(A4, B4, dccp(40009, 5009, 2, 1, payload=b'T' * 100))
    F.append((0, fr[:80], len(fr)))
    # ---- a Data packet in two IPv4 fragments (with reassembly off the
    #      first fragment is dissected as fragmented: checksum not checked)
    fr = ip4(A4, B4, dccp(40010, 5010, 2, 1, payload=b'F' * 64))
    ip, seg = fr[14:34], fr[34:]
    for off, part, mf in ((0, seg[:48], 1), (48, seg[48:], 0)):
        h = bytearray(ip)
        struct.pack_into('>HHH', h, 2, 20 + len(part), 0x4242, (mf << 13) | (off // 8))
        struct.pack_into('>H', h, 10, 0)
        struct.pack_into('>H', h, 10, csum(bytes(h)))
        F.append(E(MAC_B + MAC_A + b'\x08\x00' + bytes(h) + part))
    # ---- reproducers of the fixes
    F.extend(reproducer_frames())
    # ---- both ports 0: no port lookup at all, plain data
    F.append(E(ip4(A4, B4, dccp(0, 0, 2, 1, payload=b'port zero'))))
    # ---- same source and destination address: direction by the ports
    F.append(E(ip4(A4, A4, dccp(40011, 5011, 2, 1, payload=b'to myself'))))
    F.append(E(ip4(A4, A4, dccp(5011, 40011, 2, 1, payload=b'and back'))))
    # ---- ICMP Destination Unreachable (port) quoting a DCCP Request
    #      header without payload: no payload dissection in an error packet
    #      and one quoting a Data packet with its payload
    for seg in (dccp(40012, 5012, 0, 1, sub=struct.pack('>I', 0)),
                dccp(40012, 5012, 2, 2, payload=b'quoted')):
        inner = ip4(A4, B4, seg)[14:]
        icmp = bytearray(struct.pack('>BBHI', 3, 3, 0, 0) + inner)
        struct.pack_into('>H', icmp, 2, csum(bytes(icmp)))
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 0x777, 0, 64, 1, 0, B4, A4)
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        F.append(E(MAC_A + MAC_B + b'\x08\x00' + ip + bytes(icmp)))
    return F


def rep_pkt(seg, src=R4, dst=S4):
    return ip4(src, dst, seg)


def reproducer_frames():
    F = []
    # dccp_relseq_twopass: a Data packet before the Request of the same
    # conversation shows the absolute sequence number in both passes
    data = struct.pack('>HHBBHBB', 5000, 5001, 4, 0, 0, (2 << 1) | 1, 0) + (1005).to_bytes(6, 'big') + b'data'
    req = struct.pack('>HHBBHBB', 5000, 5001, 5, 0, 0, (0 << 1) | 1, 0) + (1000).to_bytes(6, 'big') + struct.pack('>I', 0)
    F.append(E(rep_pkt(data)))
    F.append(E(rep_pkt(req)))
    # dccp_option_small_bugs 1 and 2 (ports 5002/5003): Change L with
    # length 2 (no feature number) and MP_FAST_CLOSE followed by padding

    def data_opts(opts, payload=b''):
        return struct.pack('>HHBBHBB', 5002, 5003, 4 + len(opts) // 4, 0, 0, (2 << 1) | 1, 0) + (1).to_bytes(6, 'big') + opts + payload
    F.append(E(rep_pkt(data_opts(b'\x20\x02' + b'\x01\x01', bytes(range(64))))))
    F.append(E(rep_pkt(data_opts(b'\x2e\x04\x02\xaa' + b'\x00\x00\x00\x00'))))
    # dccp_option_small_bugs 3 fixed up: a Reset with the 12 octets it
    # needs (data offset 7): the 48 bit ack at offset 2 of the subheader
    p3 = struct.pack('>HHBBHBB', 5002, 5003, 7, 0, 0, (7 << 1) | 1, 0) + (1).to_bytes(6, 'big') + struct.pack('>HHI', 0, 0x0102, 0x03040506) + bytes([1, 0, 0, 0])
    F.append(E(rep_pkt(p3)))
    # dccp_mp_confirm_recursion, 1200 octets (ports 5004/5005): MP-DCCP
    # options with length 2 (no MP option type) repeated over the
    # 1020 octets of options
    total = 1200
    hdr = struct.pack('>HHBBHBB', 5004, 5005, 255, 0, 0, (2 << 1) | 1, 0) + (1).to_bytes(6, 'big')
    body = (b'\x2e\x02\x00' * (total // 3 + 1))[:total - 20 - len(hdr)]
    F.append(E(rep_pkt(hdr + body)))
    # dccp_cksum_noip: DCCP in an Exported PDU without addresses
    dc = struct.pack('>HHBBHBB', 5000, 5001, 4, 0, 0, (2 << 1) | 1, 0) + (1).to_bytes(6, 'big') + b'hello'
    F.append((1, epdu('dccp', dc)))
    return F


def malformed_frames():
    F = []
    c, s = 41000, 6000
    # bad checksum
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 1, payload=b'bad'), bad_csum=True)))
    # data offset smaller than the generic header (X=1 and X=0)
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 2, data_offset=3))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 3, x=0, data_offset=2))))
    # data offset too small for each packet type's subheader
    F.append(E(ip4(A4, B4, dccp(c, s, 0, 4, sub=b'\0\0\0\0', data_offset=4))))
    F.append(E(ip4(A4, B4, dccp(c, s, 1, 5, sub=b'\0' * 12, data_offset=5))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 6, sub=b'\0' * 8, data_offset=5))))
    F.append(E(ip4(A4, B4, dccp(c, s, 3, 7, x=0, sub=b'\0' * 4, data_offset=3))))
    F.append(E(ip4(A4, B4, dccp(c, s, 7, 8, sub=b'\0' * 12, data_offset=6))))  # dccp_option_small_bugs 3
    F.append(E(ip4(A4, B4, dccp(c, s, 8, 9, sub=b'\0' * 8, data_offset=5))))
    # data offset larger than the packet
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 10, data_offset=40))))
    # option running past the options
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 11, opts=b'\x24\x10\x00\x00'))))
    # NDP count with an empty value, MP_SEQ with 9 octets, MP_HMAC with
    # 5 octets (field width errors)
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 12, opts=opt(37)))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 13, opts=mp(4, bytes(9))))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 14, opts=mp(5, bytes(5))))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 15, opts=mp(10, bytes(9))))))
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 16, opts=mp(8, bytes(5))))))
    # Change and Confirm with no feature number; MP option with no type
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 17, opts=opt(32) + opt(35) + opt(46)))))
    # header shorter than the generic header
    F.append(E(ip4(A4, B4, dccp(c, s, 2, 18)[:10])))
    # the original reproducers: MP_CONFIRM recursion over 65535 octets
    total = 65535
    hdr = struct.pack('>HHBBHBB', 5004, 5005, 255, 0, 0, (2 << 1) | 1, 0) + (1).to_bytes(6, 'big')
    body = (b'\x2e\x02\x00' * (total // 3 + 1))[:total - 20 - len(hdr)]
    F.append(E(rep_pkt(hdr + body)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(out, 'dccp-coverage.pcapng'), main_frames())
    pcapng(os.path.join(out, 'dccp-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

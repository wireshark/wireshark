#!/usr/bin/env python3
# Generates the radius captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic RADIUS coverage captures (nothing from a real network).

Usage: mkradius.py <outdir>
Writes radius-coverage.pcap, radius-coverage-malformed.pcap and the frame map.
Encrypted attribute values are placeholder bytes only; no cryptography here.
"""
import struct
import sys
import os

# ---------------------------------------------------------------- helpers
def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipb(a):
    return bytes(map(int, a.split('.')))

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ipb(src), ipb(dst))
    h = h[:10] + struct.pack('!H', ip_csum(h)) + h[12:]
    return h + payload

def eth(payload, smac=1, dmac=2):
    return bytes([2, 0, 0, 0, 0, dmac]) + bytes([2, 0, 0, 0, 0, smac]) + b'\x08\x00' + payload

def udp_ip(src, dst, sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def udp_frame(src, dst, sport, dport, payload, smac=1, dmac=2):
    return eth(ip4(src, dst, 17, udp_ip(src, dst, sport, dport, payload)), smac, dmac)

def tcp_frame(src, dst, sport, dport, seq, ack, payload, flags=0x18, smac=1, dmac=2):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ip4(src, dst, 6, t), smac, dmac)

def icmp_unreach(src, dst, inner_ip):
    body = struct.pack('!BBHI', 3, 3, 0, 0) + inner_ip
    body = body[:2] + struct.pack('!H', ip_csum(body)) + body[4:]
    return eth(ip4(src, dst, 1, body), 2, 1)

class Cap:
    def __init__(self):
        self.frames = []
        self.notes = []
    def add(self, fr, note=''):
        self.frames.append(fr)
        self.notes.append(note)
        return len(self.frames)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
                f.write(fr)

def auth(n):
    return bytes([(n * 17 + i * 5) & 0xff for i in range(16)])

def rad(code, ident, avps, a=None, length=None, pad=b''):
    body = b''.join(avps)
    if a is None:
        a = auth(ident)
    return struct.pack('!BBH', code, ident, (20 + len(body)) if length is None else length) + a + body + pad

def A(t, v=b''):
    if isinstance(v, str):
        v = v.encode()
    return struct.pack('!BB', t, 2 + len(v)) + v

def u32(n): return struct.pack('!I', n)
def u16(n): return struct.pack('!H', n)
def u64(n): return struct.pack('!Q', n)

def VSA(vendor, subs, tl=1, ll=1, flags=None):
    """One Vendor-Specific attribute (26) holding the sub-attributes (type, value[, flag])."""
    body = u32(vendor)
    if flags is None:
        flags = vendor in (24757, 5323)     # WiMAX and Telrad carry a flags octet
    for s in subs:
        t, v = s[0], s[1]
        if isinstance(v, str):
            v = v.encode()
        fl = s[2] if len(s) > 2 else 0
        hdr = len(v) + tl + ll + (1 if flags else 0)
        x = (struct.pack('!B', t) if tl == 1 else u16(t) if tl == 2 else u32(t))
        if ll == 1: x += struct.pack('!B', hdr)
        elif ll == 2: x += u16(hdr)
        if flags: x += struct.pack('!B', fl)
        body += x + v
    return A(26, body)

def EXT(t, et, v, more=None):
    """Extended (241-244) or long-extended (245/246, more flag) attribute."""
    x = struct.pack('!B', et)
    if t >= 245:
        x += struct.pack('!B', more or 0)
    return A(t, x + v)

def EVS(t, vendor, vtype, v, more=0):
    x = struct.pack('!B', 26)
    if t >= 245:
        x += struct.pack('!B', more)
    return A(t, x + u32(vendor) + struct.pack('!B', vtype) + v)

def tlv(t, v):
    return struct.pack('!BB', t, 2 + len(v)) + v

PH16 = bytes(range(0x40, 0x50))        # placeholder "ciphertext" bytes
PH32 = bytes(range(0x60, 0x80))
C, S, S2 = '192.0.2.10', '192.0.2.20', '192.0.2.30'

# ---------------------------------------------------------------- main capture
def build_main():
    cap = Cap()
    def req(code, ident, avps, port=1812, sport=40000, **kw):
        return udp_frame(C, S, sport, port, rad(code, ident, avps, **kw))
    def rsp(code, ident, avps, port=1812, sport=40000, a=None, **kw):
        return udp_frame(S, C, port, sport, rad(code, ident, avps, a=a or auth(100 + ident), **kw), 2, 1)

    # --- 1. Access-Request / Accept with the common attributes
    cap.add(req(1, 1, [A(1, 'alice'), A(2, PH16), A(4, ipb('192.0.2.1')), A(4, b'\x01\x02\x03'), A(5, u32(7)),
                       A(6, u32(2)), A(7, u32(1)), A(8, ipb('255.255.255.254')),
                       A(30, '555-0100'), A(31, '00-11-22-33-44-55'), A(61, u32(15)),
                       A(80, b'\x00' * 16), A(95, bytes(range(1, 17)))]), 'Access-Request common')
    cap.add(rsp(2, 1, [A(6, u32(2)), A(7, u32(1)), A(8, ipb('255.255.255.255')),
                       A(8, ipb('10.1.2.3')), A(8, b'\x01\x02'),
                       A(14, ipb('255.255.255.255')), A(14, ipb('0.0.0.0')), A(14, ipb('10.9.9.9')), A(14, b'\x01'),
                       A(11, 'filter1'), A(18, 'Welcome'), A(27, u32(3600)), A(28, u32(60)),
                       A(55, u32(1700000000)), A(55, b'\x01\x02'),
                       A(24, b'\x01\x02\x03'), A(24), A(80, b'\x00' * 16), A(4, b'\x01\x02\x03')]), 'Access-Accept')
    # --- Access-Request with wrong/odd lengths and a second ident -> Reject
    cap.add(req(1, 2, [A(1, 'bob'), A(2, PH16 + PH16[:1]), A(2), A(3, b'\x05' + PH16), A(3, b'\x05\x06'),
                       A(23, u32(0xfffffffe)), A(23, u32(0x1234)), A(23, b'\x01'),
                       A(56, u32(0x31000064)), A(56, u32(0x32000fff)), A(56, b'\x01'),
                       A(58, b'\x31vlan-a'), A(58, b'\x32'), A(58, b'\x99name'),
                       A(5, b'\x01'), A(5, b'\x01\x02'), A(5, b'\x01\x02\x03'), A(5, u64(5)), A(5, b'\x01' * 5), A(230, b'\x00\x00\x00\x2a'), A(230, b'\x01'), A(231, u32(0xffffffff)), A(231, u32(3)), A(231, u64(5)), A(231, b'\x01'), A(231, b'\x01\x02'), A(231, b'\x01' * 5)],
                port=1645, sport=40001), 'Access-Request odd lengths (CHAP, IPX, VLAN, integer widths)')
    cap.add(rsp(3, 2, [A(18, 'denied')], port=1645, sport=40001), 'Access-Reject')
    # --- Duplicate request, challenge, response; duplicate response
    r3 = rad(1, 3, [A(1, 'carol'), A(79, b'\x02\x01\x00\x0a\x01carol')], a=auth(3))
    cap.add(udp_frame(C, S, 40002, 1812, r3), 'Access-Request with EAP-Message (identity)')
    cap.add(udp_frame(C, S, 40002, 1812, r3), 'duplicate Access-Request')
    ch = rad(11, 3, [A(24, b'state123'), A(79, b'\x01\x02\x00\x06\x04\x00'), A(18, 'challenge')], a=auth(103))
    cap.add(udp_frame(S, C, 1812, 40002, ch, 2, 1), 'Access-Challenge with EAP-Message')
    cap.add(udp_frame(S, C, 1812, 40002, ch, 2, 1), 'duplicate Access-Challenge')
    # response with no request (other port) and response with no matching ident
    cap.add(rsp(2, 77, [A(2, PH16), A(1, 'orphan')], port=1812, sport=41000), 'Access-Accept without a request')
    cap.add(rsp(2, 99, [A(1, 'noident')], port=1812, sport=40002), 'Access-Accept, request has other ident')
    # --- Accounting
    cap.add(req(4, 10, [A(40, u32(1)), A(44, 'sess-1'), A(1, 'alice'), A(41, u32(5)), A(42, u32(1000)),
                        A(43, u32(2000)), A(46, u32(120)), A(49, u32(1)), A(45, u32(1))],
                port=1813, sport=40010), 'Accounting-Request')
    cap.add(rsp(5, 10, [], port=1813, sport=40010), 'Accounting-Response (no AVPs)')
    cap.add(req(4, 10, [A(40, u32(3)), A(44, 'sess-1'), A(1, 'alice')], port=1813, sport=40010, a=auth(210)),
            'Accounting-Request, same identifier again with another authenticator (a new call)')
    cap.add(rsp(2, 120, [A(18, 'early')], port=1812, sport=44000), 'Access-Accept before its request (never matched)')
    cap.add(req(1, 120, [A(1, 'late')], port=1812, sport=44000), 'Access-Request for the earlier Access-Accept')
    cap.add(udp_frame(C, S, 44001, 1812, rad(1, 121, [A(1, 'short')], length=900)), 'Access-Request whose length is beyond the packet (not RADIUS)')
    cap.add(udp_frame(C, S, 44002, 1812, rad(1, 122, [A(1, 'short')], length=5000, pad=b'\x00' * 100)), 'Access-Request with length > 4096 (not RADIUS)')
    cap.add(udp_frame(C, S, 44003, 1812, rad(77, 123, [A(1, 'x')])), 'unknown code (not RADIUS)')
    # --- Other request/response code pairs
    pairs = [(7, 8), (7, 9), (21, 22), (23, 24), (26, 27), (33, 34), (129, 130), (129, 131), (129, 132),
             (40, 41), (40, 42), (43, 44), (43, 45)]
    for i, (q, p) in enumerate(pairs):
        port = 3799 if q in (40, 43) else 1700 if q == 129 else 1812
        cap.add(req(q, 20 + i, [A(1, 'x%d' % i)], port=port, sport=42000 + i), 'request code %d' % q)
        cap.add(rsp(p, 20 + i, [A(18, 'r')], port=port, sport=42000 + i), 'response code %d' % p)
    # codes without request/response handling
    for q in (6, 10, 12, 13, 25, 29, 30, 31, 32, 50, 51):
        cap.add(req(q, 60 + q, [A(1, 'u')], port=1812, sport=43000 + q), 'code %d (no conversation)' % q)
    # padding after the RADIUS length
    cap.add(req(12, 90, [A(1, 'pad')], pad=b'\x00' * 6, sport=43100), 'Status-Server with trailing padding')
    # --- 2. special AVPs
    # Ascend data filter, IPv4 and IPv6, Call-Filter, Lucent filter
    def ascend_filter(ipv6, proto, sl, dl, sp, dp, sq, dq):
        if ipv6:
            ips = bytes(range(1, 17)) + bytes(range(17, 33))
        else:
            ips = ipb('10.0.0.1') + ipb('10.0.0.2')
        return struct.pack('!BBBB', 3 if ipv6 else 1, 1, 1, 0) + ips + struct.pack('!BBBB', sl, dl, proto, 1) \
            + u16(sp) + u16(dp) + struct.pack('!BB', sq, dq) + u16(0)
    f4 = ascend_filter(False, 6, 24, 32, 1024, 80, 2, 3)
    f6 = ascend_filter(True, 17, 64, 0, 53, 53, 4, 1)
    f4b = ascend_filter(False, 0, 0, 0, 0, 0, 0, 0)
    f4c = ascend_filter(False, 1, 8, 0, 0, 0, 0, 0)
    f4d = ascend_filter(False, 99, 0, 8, 7, 9, 1, 0)
    cap.add(req(1, 30, [A(1, 'ascend'), VSA(529, [(242, f4)]), VSA(529, [(242, f6)]), VSA(529, [(242, f4b)]),
                        VSA(529, [(242, f4c)]), VSA(529, [(242, f4d)]),
                        VSA(529, [(243, f4)]), VSA(529, [(242, b'\x00' * 10)]),
                        VSA(4846, [(242, f4)], tl=2), VSA(529, [(214, PH16)]), VSA(529, [(214, PH32)])],
                sport=40030), 'Access-Request Ascend/Lucent filters and Send-Secret')
    # Cosine, 3GPP, 3GPP2, various vendors
    cap.add(req(4, 31, [A(1, 'vendors'),
                        VSA(3085, [(5, u16(1) + u16(2))]), VSA(3085, [(5, b'\x01\x02')]),
                        VSA(10415, [(1, '262011234567890')]), VSA(10415, [(23, b'\x40\x01')]),
                        VSA(10415, [(21, b'\x06'), (11, b'\x00'), (19, b'\x01')]),
                        VSA(9, [(1, 'cisco-avpair=foo')]),
                        VSA(311, [(11, b'\x01' * 8), (16, b'\x80\x01' + PH16), (17, b'\x80\x02' + PH32)]),
                        VSA(311, [(12, PH32[:24])]),
                        VSA(99999, [(1, b'unknown-vendor'), (2, b'\x00\x00\x00\x01')]),
                        VSA(5535, [(58, PH32)]),
                        VSA(12356, [(23, bytes([0, 1, 2, 3, 4, 5]))]), VSA(12356, [(23, bytes([0, 1, 2, 3, 4]))]),
                        VSA(24757, [(8, ipb('10.0.0.8'))]), VSA(24757, [(8, bytes(range(16)))]), VSA(24757, [(8, b'\x01\x02\x03')]),
                        ], port=1813, sport=40031), 'Accounting-Request vendor attributes')
    # vendor formats: 2,1 / 4,0 / 2,2 / flags
    cap.add(req(4, 32, [A(1, 'formats'),
                        VSA(4846, [(1, b'\x00\x00\x00\x01')], tl=2), VSA(637, [(1, b'abc')], tl=2),
                        VSA(16445, [(1, b'abc')], tl=2),
                        VSA(429, [(1, b'\x00\x00\x00\x07')], tl=4, ll=0),
                        VSA(8164, [(1, b'\x00\x00\x00\x07'), (2, 'vpn-a')]),
                        VSA(2011, [(154, bytes(range(18)))]),
                        ], port=1813, sport=40032), 'Accounting-Request vendor type/length formats')
    # WiMAX continuation fragments (1,1,c)
    cap.add(req(4, 33, [A(1, 'wimax'),
                        VSA(24757, [(4, b'frag-one-', 0x80)], flags=True),
                        VSA(24757, [(4, b'frag-two-', 0x80)], flags=True),
                        VSA(24757, [(4, b'last', 0x00)], flags=True),
                        VSA(24757, [(4, b'solo', 0x00)], flags=True),
                        VSA(24757, [(2, b'\x01')], flags=True),
                        VSA(24757, [(5, b'\x80\x01' + PH16)], flags=True),
                        VSA(24757, [(3, u32(0xfffffff0))], flags=True),
                        VSA(24757, [(7, b'x' * 8, 0x80)], flags=True)], port=1813, sport=40033), 'WiMAX VSA fragments')
    # tagged attributes
    cap.add(req(1, 34, [A(1, 'tunnel'), A(64, b'\x01\x00\x00\x0d'), A(64, b'\x40\x00\x00\x0d'), A(65, b'\x01\x00\x00\x06'),
                        A(66, b'\x02' + b'192.0.2.99'), A(81, b'\x01vlan10'), A(81, b'plain'), A(83, b'\x01\x00\x00\x05'),
                        A(69, b'\x01\x80\x01' + PH16), A(69, b'\x01\x80\x01' + PH32 + PH16),
                        A(69, b'\x01\x80\x01\x44'), A(69, b'\x01\x80\x01'), A(69, b'\x01\x80'), A(69, b'\x01'),
                        A(69, b'\x40\x81\x02' + PH16)], port=1812, sport=40034), 'Tunnel attributes and Tunnel-Password')
    cap.add(rsp(2, 34, [A(69, b'\x01\x80\x01' + PH16), A(2, PH16), A(2, PH32 + b'\x01')], port=1812, sport=40034),
            'Access-Accept encrypted attributes with a request')
    # 64-bit and signed integers, TLVs, extended attributes
    cap.add(req(1, 35, [A(1, 'ints'), A(124, u64(0x0102030405060708)), A(124, b'\x01\x02'),
                        VSA(24757, [(3, u32(0xfffffff0))]), VSA(24757, [(3, u64(0xfffffffffffffff0))]),
                        VSA(24757, [(3, b'\x01')]), VSA(24757, [(3, b'\x01\x02')]), VSA(24757, [(3, b'\x01\x02\x03')]),
                        VSA(24757, [(3, b'\x01' * 5)]),
                        A(97, b'\x00\x40' + bytes(range(1, 9))), A(97, b'\x00'), A(97, b'\x01\x40' + b'\x00' * 8),
                        A(97, b'\x00\xff' + b'\x00' * 8), A(97, b'\x00\x00'), A(96, bytes(range(8))), A(96, b'\x01'),
                        A(95, b'\x01\x02')], port=1812, sport=40035), 'integer64, signed, IPv6 prefix and interface id')
    # TLV attributes
    tl_ok = tlv(1, b'\x20') + tlv(2, b'\x00\x40' + bytes(range(1, 9))) + tlv(3, ipb('10.0.0.1'))
    cap.add(req(1, 36, [A(1, 'tlv'), A(173, tl_ok), A(173, tlv(77, b'\x01\x02')), A(173, tlv(1, b'\x01') + tlv(3, ipb('1.2.3.4'))),
                        VSA(24757, [(1, tlv(1, b'rel-1') + tlv(2, b'\x01'))]),
                        VSA(5535, [(59, tlv(1, ipb('10.1.1.1')) + tlv(2, u32(24)) + tlv(3, u16(5)))]),
                        VSA(5535, [(59, tlv(1, ipb('10.1.1.1')))]),
                        VSA(24757, [(1, b'')]),
                        ], port=1812, sport=40036), 'TLV attributes')
    # extended attributes (RFC 6929)
    cap.add(req(1, 37, [A(1, 'ext'), EXT(241, 1, u32(2)), EXT(241, 8, b'operator'), EXT(241, 3, u32(1000)), EXT(242, 99, b'\x01\x02'),
                        EXT(245, 1, b'\x01\x02\x03'), EXT(246, 5, b'\x00' * 6, more=0x80), EXT(245, 8, b'longer', more=0),
                        EVS(241, 11344, 1, b'\x01\x02'), EVS(245, 11344, 2, b'\x01\x02\x03\x04', more=0x80),
                        EVS(245, 11344, 1, b'\xaa' * 5), EVS(244, 99999, 1, b'\x01'), EVS(246, 4, 9, b'\x01'),
                        EXT(241, 5, tlv(1, u32(1)) + tlv(2, u32(5)))],
                port=1812, sport=40037), 'extended attributes and EVS')
    # reproducer of the RADIUS decrypted_start fix: Tunnel-Password in a request/response pair
    # (covered above by frames with Tunnel-Password)
    # EAP-Message fragments, non-consecutive
    eap1 = b'\x02\x05' + u16(4 + 1 + 395) + b'\x01' + b'a' * 395
    cap.add(req(1, 38, [A(1, 'eap'), A(79, eap1[:253]), A(79, eap1[253:]), A(24, b'st'), A(79, b'\x01\x06\x00\x05\x01'),
                        A(79, b'\x01\x07\x00\x05\x01'), A(80, b'\x00' * 16)], sport=40038), 'EAP-Message fragments incl. non-consecutive')
    cap.add(req(1, 39, [A(1, 'eap2'), A(79, b'\x01\x08\x00\x05\x01'), A(79, b'\x01\x09' + b'\x00' * 3)], sport=40039),
            'EAP-Message segment ends the packet')
    # unknown attributes, unassigned types and vendor 26 with unknown sub-type
    cap.add(req(1, 40, [A(1, 'unk'), A(200, b'\x01\x02'), A(250, b'abc'), A(255), A(26, u32(9) + b'\x7f\x03x')],
                sport=40040), 'unknown attributes')
    # long VSA: 253 byte value
    cap.add(req(1, 41, [A(1, 'z' * 253), A(26, u32(9) + struct.pack('!BB', 1, 249) + b'v' * 247)], sport=40041), 'maximum length attributes')
    # --- 3. ICMP error containing RADIUS
    inner = ip4(C, S, 17, udp_ip(C, S, 40050, 1812, rad(1, 50, [A(1, 'err'), A(2, PH16)], a=auth(50))), ident=9)
    cap.add(icmp_unreach(S, C, inner), 'ICMP port unreachable carrying an Access-Request (in error packet)')
    inner = ip4(S, C, 17, udp_ip(S, C, 1812, 40050, rad(2, 50, [A(1, 'err')], a=auth(150))), ident=9)
    cap.add(icmp_unreach(C, S, inner), 'ICMP port unreachable carrying an Access-Accept')
    # --- 4. TCP
    seq = 1000; seqs = 5000
    cap.add(tcp_frame(C, S, 50000, 1812, seq - 1, 0, b'', flags=0x02), 'TCP SYN')
    cap.add(tcp_frame(S, C, 1812, 50000, seqs - 1, seq, b'', flags=0x12, smac=2, dmac=1), 'TCP SYN-ACK')
    cap.add(tcp_frame(C, S, 50000, 1812, seq, seqs, b'', flags=0x10), 'TCP ACK')
    p1 = rad(1, 70, [A(1, 'tcp-user'), A(2, PH16), A(5, u32(3))], a=auth(70))
    cap.add(tcp_frame(C, S, 50000, 1812, seq, seqs, p1), 'RADIUS over TCP, one PDU'); seq += len(p1)
    p2 = rad(2, 70, [A(18, 'welcome over tcp')], a=auth(170))
    p3 = rad(4, 71, [A(40, u32(1)), A(1, 'tcp-user')], a=auth(71))
    cap.add(tcp_frame(S, C, 1812, 50000, seqs, seq, p2 + p3[:12], smac=2, dmac=1), 'RADIUS over TCP, one PDU and the start of the next'); seqs += len(p2) + 12
    cap.add(tcp_frame(S, C, 1812, 50000, seqs, seq, p3[12:], smac=2, dmac=1), 'RADIUS over TCP, reassembled'); seqs += len(p3) - 12
    p4 = rad(1, 72, [A(1, 'big')] + [A(26, u32(9) + struct.pack('!BB', 1, 200) + b'x' * 198)] * 3, a=auth(72))
    cap.add(tcp_frame(C, S, 50000, 1812, seq, seqs, p4[:100]), 'RADIUS over TCP, first segment'); seq += 100
    cap.add(tcp_frame(C, S, 50000, 1812, seq, seqs, p4[100:]), 'RADIUS over TCP, second segment (reassembled)'); seq += len(p4) - 100
    cap.add(tcp_frame(C, S, 50000, 1812, seq, seqs, b'\x01\x02\x00'), 'RADIUS over TCP, 3 bytes only (not enough for the header)')
    return cap

# ---------------------------------------------------------------- malformed capture
def build_malformed():
    cap = Cap()
    def req(code, ident, avps, port=1812, sport=40000, **kw):
        return udp_frame(C, S, sport, port, rad(code, ident, avps, **kw))
    # fix reproducers
    cap.add(udp_frame(C, S, 40000, 1813, rad(4, 1, [b'\xf5\x03\x01', A(1, 'alice'), A(5, u32(7))])), 'FIX radius: Extended-Long length 3 (245)')
    cap.add(udp_frame(C, S, 40001, 1813, rad(4, 2, [b'\xf5\x03\x1a', A(1, 'bob'), A(5, u32(8))])), 'FIX radius: Extended-Long EVS length 3')
    cap.add(udp_frame(C, S, 40000, 1813, rad(4, 3, [A(26, u32(9) + b'\x01\x00' + A(1, 'evil')), A(5, u32(7))])), 'FIX radius: VSA with short inner length, offset must skip the VSA')
    # decrypted_start (fixed): Tunnel-Password whose first decrypted byte is non-printable is in main
    # AVP header problems
    cap.add(req(1, 4, [A(1, 'a'), b'\x05']), 'AVP header truncated (1 byte left)')
    cap.add(req(1, 5, [A(1, 'a'), b'\x05\x01']), 'AVP length < 2')
    cap.add(req(1, 6, [A(1, 'a'), b'\x05\x20\x00\x00']), 'AVP longer than the packet')
    cap.add(req(1, 7, [A(1, 'a'), b'\xf1\x02'], pad=b'\x01'), 'Extended AVP length < 3')
    cap.add(req(1, 8, [A(1, 'a'), b'\xf6\x03\x01']), 'Long extended AVP length < 4')
    cap.add(req(1, 9, [A(1, 'a'), A(26, b'\x00\x00')]), 'VSA without room for the vendor id')
    cap.add(req(1, 10, [A(1, 'a'), A(26, u32(9) + b'\x01\x01x')]), 'VSA inner length smaller than its header')
    cap.add(req(1, 11, [A(1, 'a'), A(26, u32(4846) + b'\x00\x01\x01')]), 'VSA inner length smaller than its header (2,1 format)')
    cap.add(req(1, 12, [A(64)]), 'tagged AVP without a value')
    cap.add(req(1, 17, [A(69)]), 'tagged encrypted AVP without a value')
    cap.add(req(1, 13, [A(173, b'\x01')]), 'TLV: not enough room for TLV header')
    cap.add(req(1, 14, [A(173, b'\x01\x01')]), 'TLV: length < 2')
    cap.add(req(1, 15, [A(173, b'\x01\x09\x00')]), 'TLV: longer than the attribute')
    cap.add(req(1, 16, [A(241, b'\x01\x02\x03')]), 'extended AVP valid shortest length')
    # coverage only: needs cfg/radius/dictionary (vendor Cov-Len2, format 1,2); without it these are unknown vendor 99998
    cap.add(req(1, 18, [VSA(99998, [(1, b'abc')], ll=2), VSA(99998, [(2, u32(5))], ll=2)]), 'COV vendor with a 2 octet length (cfg/radius/dictionary)')
    return cap

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main(); m.write(os.path.join(out, 'radius-coverage.pcap'))
    x = build_malformed(); x.write(os.path.join(out, 'radius-coverage-malformed.pcap'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for name, c in (('main', m), ('malformed', x)):
            f.write('# %s: %d frames\n' % (name, len(c.frames)))
            for i, n in enumerate(c.notes, 1):
                f.write('%d\t%s\n' % (i, n))

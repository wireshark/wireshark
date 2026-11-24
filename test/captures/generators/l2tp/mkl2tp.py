#!/usr/bin/env python3
# Generates test/captures/l2tp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the L2TP coverage captures. Usage: mkl2tp.py <outdir> [-v].
Synthetic data only: addresses from 192.0.2.0/24; hidden AVPs, message
digests and nonces are placeholder octets (no keys, no crypto)."""
import struct
import sys

PCAP_SNAP = 65535


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(map(int, a.split('.')))


def ip_frame(proto, payload, src, dst, caplen=None):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64,
                     proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + payload


def udp_frame(payload, src, dst, sport=1701, dport=1701):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ip_frame(17, udp, src, dst)


class Peer:
    """Two endpoints of a tunnel; send() builds frames for UDP or IP."""
    def __init__(self, a, b, aport=1701, bport=1701, ip=False):
        self.a, self.b, self.aport, self.bport, self.ip = a, b, aport, bport, ip

    def to_b(self, payload):
        if self.ip:
            return ip_frame(115, payload, self.a, self.b)
        return udp_frame(payload, self.a, self.b, self.aport, self.bport)

    def to_a(self, payload):
        if self.ip:
            return ip_frame(115, payload, self.b, self.a)
        return udp_frame(payload, self.b, self.a, self.bport, self.aport)


# ---------------------------------------------------------------- AVPs
def avp(t, val=b'', vendor=0, m=True, h=False, length=None):
    n = 6 + len(val) if length is None else length
    flags = (0x8000 if m else 0) | (0x4000 if h else 0) | n
    return struct.pack('!HHH', flags, vendor, t) + val


def msg(t, **kw):
    return avp(0, struct.pack('!H', t), **kw)


def u16(x):
    return struct.pack('!H', x)


def u32(x):
    return struct.pack('!I', x)


def u64(x):
    return struct.pack('!Q', x)


VCISCO, VERIC, VBBF, VCABLE = 9, 193, 3561, 4491

SCCRQ, SCCRP, SCCCN, STOPCCN, HELLO = 1, 2, 3, 4, 6
OCRQ, OCRP, OCCN, ICRQ, ICRP, ICCN, CDN = 7, 8, 9, 10, 11, 12, 14
WEN, SLI, MDMST, SRRQ, SRRP, ACK = 15, 16, 17, 18, 19, 20
FSQ, FSR, MSRQ, MSRP, MSE, MSI, MSEN, CSUN, CSURQ = 21, 22, 23, 24, 25, 26, 27, 28, 29


# ------------------------------------------------------------ headers
def v2ctl(avps, tid=0, sid=0, ns=0, nr=0, flags=0xC802, length=None, seq=True):
    body = b''.join(avps)
    hdr = struct.pack('!HHHH', 0, 0, tid, sid)
    if flags & 0x0800:
        hdr += struct.pack('!HH', ns, nr)
    ln = 2 + 2 + 4 + (4 if flags & 0x0800 else 0) + len(body) if length is None else length
    if flags & 0x4000:
        return struct.pack('!HH', flags, ln) + hdr[4:] + body
    return struct.pack('!H', flags) + hdr[4:] + body


def v2data(payload, tid=1, sid=1, flags=0x4002, ns=0, nr=0, offset=None, length=None):
    hdr = b''
    ln = None
    if flags & 0x4000:
        hdr_len = 2 + 2 + 4 + (4 if flags & 0x0800 else 0) + (2 + (offset or 0) if flags & 0x0200 else 0)
        ln = hdr_len + len(payload) if length is None else length
    b = struct.pack('!H', flags)
    if flags & 0x4000:
        b += struct.pack('!H', ln)
    b += struct.pack('!HH', tid, sid)
    if flags & 0x0800:
        b += struct.pack('!HH', ns, nr)
    if flags & 0x0200:
        b += struct.pack('!H', offset or 0) + b'\xee' * (offset or 0)
    return b + payload


def v3ctl(avps, ccid=0, ns=0, nr=0, sid=None, flags=0xC803, length=None):
    """Control message. sid is not None: L2TP over IP (session id 0 first)."""
    body = b''.join(avps)
    hdr = b''
    if flags & 0x4000:
        ln = 2 + 2 + 4 + (4 if flags & 0x0800 else 0) + len(body) if length is None else length
        hdr = struct.pack('!HH', flags, ln)
    else:
        hdr = struct.pack('!H', flags)
    hdr += u32(ccid)
    if flags & 0x0800:
        hdr += struct.pack('!HH', ns, nr)
    pre = u32(0) if sid is not None else b''
    return pre + hdr + body


def v3data_udp(sid, rest=b'', flags=0x0003):
    return struct.pack('!HH', flags, 0) + u32(sid) + rest


def v3data_ip(sid, rest=b''):
    return u32(sid) + rest


def l2_default(seq=1, s=True):
    return bytes([0x40 if s else 0]) + struct.pack('!I', seq)[1:]


def l2_atm(t=False, g=False, c=False, u=False, s=True, seq=1):
    b = (0x40 if s else 0) | (0x08 if t else 0) | (0x04 if g else 0) | (0x02 if c else 0) | (0x01 if u else 0)
    return bytes([b]) + struct.pack('!I', seq)[1:]


def l2_dmpt(v=1, s=True, h=False, flow=3, seq=7):
    b = (0x80 if v else 0) | (0x40 if s else 0) | (0x20 if h else 0) | (flow & 0x1f)
    return bytes([b, 0]) + u16(seq)


IPV4 = bytes.fromhex('45000018000000004 0fd0000'.replace(' ', '')) + ip4('192.0.2.77') + ip4('192.0.2.78') + b'data'
ETH = bytes.fromhex('020000000001020000000002') + b'\x08\x00' + IPV4
LLC_SNAP = bytes.fromhex('aaaa03000000') + b'\x08\x00' + IPV4
OAM_CELL = bytes(53)
PPP_LCP = bytes.fromhex('ff03c021010100080104' '05dc')


# --------------------------------------------------------------- main
def main():
    out = sys.argv[1]
    F = []           # main capture frames
    M = []           # malformed capture frames
    marks = []       # (first frame, text) for -v

    def mark(text):
        marks.append((len(F) + 1, text))

    # ======================= L2TPv2 over UDP ========================
    p2 = Peer('192.0.2.1', '192.0.2.2')
    mark('L2TPv2 tunnel setup')
    ns = [0, 0]

    def c2(avps, dirn='ab', tid=0, sid=0, **kw):
        if dirn == 'ab':
            F.append(p2.to_b(v2ctl(avps, tid, sid, ns[0], ns[1], **kw)))
            ns[0] += 1
        else:
            F.append(p2.to_a(v2ctl(avps, tid, sid, ns[1], ns[0], **kw)))
            ns[1] += 1

    c2([msg(SCCRQ), avp(2, bytes([1, 0])), avp(3, u32(3)), avp(4, u32(3)),
        avp(5, u64(0x1122334455667788)), avp(6, u16(0x0102)),
        avp(7, b'lac.example.net'), avp(8, b'Example Vendor'),
        avp(9, u16(11)), avp(10, u16(8)), avp(11, bytes(range(16)))])
    c2([msg(SCCRP), avp(2, bytes([1, 0])), avp(3, u32(1)), avp(4, u32(0)),
        avp(6, u16(7)), avp(7, b'lns.example.net'), avp(8, b'Example Vendor'),
        avp(9, u16(22)), avp(11, bytes(range(16))), avp(13, bytes(range(16, 32)))], 'ba', tid=11)
    c2([msg(SCCCN), avp(13, bytes(range(32, 48)))], tid=22)
    F.append(p2.to_a(v2ctl([], 11, 0, 1, 2, flags=0xC802, length=12)))      # ZLB
    c2([msg(HELLO)], tid=22)
    mark('L2TPv2 calls')
    c2([msg(ICRQ), avp(14, u16(33)), avp(15, u32(100)), avp(16, u32(9600)),
        avp(17, u32(56000)), avp(18, u32(3)), avp(19, u32(3)),
        avp(21, b'5551234'), avp(22, b'5559876'), avp(23, b'sub'), avp(25, u32(4))], tid=22)
    c2([msg(ICRP), avp(14, u16(44))], 'ba', tid=11, sid=33)
    lcp1 = bytes.fromhex('0104' '05dc' '0305' 'c223' '05' '0506' '11223344')
    c2([msg(ICCN), avp(24, u32(56000)), avp(26, lcp1), avp(27, lcp1[:4]), avp(28, lcp1[4:9]),
        avp(29, u16(2)), avp(30, b'user'), avp(31, bytes(8)), avp(32, bytes([0, 7])),
        avp(33, bytes(16)), avp(38, u32(64000)), avp(37, b'group1'), avp(36, b'\x01\x02\x03\x04')], tid=22, sid=44)
    c2([msg(OCRQ), avp(14, u16(55)), avp(15, u32(101)), avp(16, u32(1200)), avp(17, u32(33600)),
        avp(18, u32(1)), avp(19, u32(1)), avp(21, b'5550000'), avp(23, b'')], tid=22)
    c2([msg(OCRP), avp(14, u16(66)), avp(25, u32(3))], 'ba', tid=11, sid=55)
    c2([msg(OCCN), avp(24, u32(28800)), avp(19, u32(2))], 'ba', tid=11, sid=55)
    mark('L2TPv2 WEN, SLI, MDMST, SRRQ, ACK, CDN, StopCCN')
    c2([msg(WEN), avp(34, bytes(2) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6))], tid=22, sid=44)
    c2([msg(SLI), avp(35, bytes(2) + u32(0xffffffff) + u32(0x0a000000))], tid=22, sid=44)
    c2([msg(MDMST)], tid=22, sid=44)
    c2([msg(SRRQ)], tid=22)
    c2([msg(SRRP)], 'ba', tid=11)
    c2([msg(ACK)], tid=22)
    c2([msg(CDN), avp(1, u16(1) + u16(3) + b'No carrier'), avp(14, u16(44)),
        avp(12, u16(0x0102) + bytes([5]) + b'advice'),
        avp(46, u16(1) + u16(0xc021) + bytes([1]) + b'peer asked')], tid=22, sid=44)
    c2([msg(CDN), avp(1, u16(2)), avp(12, u16(0x0102)), avp(46, u16(1)), avp(46, u16(1) + u16(0x8021))], tid=22, sid=44)
    c2([msg(CDN), avp(1, u16(0) + u16(1)), avp(12, u16(1) + bytes([2])),
        avp(46, u16(1) + u16(0xc021) + bytes([2]))], tid=22, sid=55)
    c2([msg(STOPCCN), avp(9, u16(11)), avp(1, u16(6) + u16(0) + b'closing')], tid=22)
    c2([msg(STOPCCN), avp(1, u16(1))], tid=22)
    mark('L2TPv2 AVP length variants (short, empty, unknown)')
    short = [avp(1, b''), avp(1, u16(1)), avp(2, b''), avp(12, b''), avp(12, u16(1)), avp(12, u16(1) + b'\x02'),
             avp(21, b''), avp(22, b''), avp(23, b''), avp(30, b''), avp(46, b''), avp(46, u16(1)),
             avp(46, u16(1) + u16(2)), avp(34, b''), avp(34, u16(0)), avp(34, bytes(2) + u32(1) + u32(2)),
             avp(35, b''), avp(35, u16(0)), avp(35, bytes(2) + u32(1)), avp(74, b'\x00'), avp(75, b'\x00' * 4),
             avp(39, b''), avp(100, b'unknown'), avp(101, b''), avp(60, u32(0x0a000001))]
    c2([msg(HELLO)] + short[:13], tid=22)
    c2([msg(HELLO)] + short[13:], tid=22)
    c2([msg(CDN), avp(1, bytes([0, 1, 0, 2, 0x41, 0x42])), avp(1, u16(0) + u16(0) + b'')], tid=22, sid=44)
    c2([msg(CDN), avp(34, bytes(2) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5)),
        avp(34, bytes(2) + u32(1) + u32(2) + u32(3)), avp(34, bytes(2) + u32(1) + u32(2) + u32(3) + u32(4)),
        avp(34, bytes(2) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6)),
        avp(34, bytes(2) + u32(1) + u16(0)),
        avp(35, bytes(2) + u32(1) + u32(2))], tid=22, sid=44)
    mark('L2TPv2 mandatory/hidden bits, Extended Vendor ID, Connect Speed Update')
    c2([msg(HELLO), avp(7, b'plain', m=False), avp(7, bytes(range(20, 36)), h=True),
        avp(36, b'\x05\x06\x07\x08'),
        avp(58, bytes([0, 1])),                                 # length 8: see README
        avp(97, bytes(2) + u16(44) + u32(1000) + u32(2000)),    # CSU, v2 form (12)
        avp(97, bytes(8)),                                      # other length
        avp(97, bytes(20)),                                     # v3 form (20) in v2
        avp(61, u32(0x1234)), avp(73, bytes(8)),                # ccid and nonce in v2: no tunnel to store them in
        avp(59, bytes([0]) + bytes(16)),                        # message digest, v2: no tunnel
        avp(59, bytes([1]) + bytes(20))], tid=22)
    mark('L2TPv2 vendor AVPs')
    c2([msg(HELLO), avp(0, u16(5), vendor=VCISCO)], tid=22)         # Cisco message-type-like unknown first AVP
    vend = []
    vend += [avp(0, b'', vendor=VCISCO), avp(1, u32(0x01020304), vendor=VCISCO),
             avp(2, u16(5) + u16(0) + u16(7), vendor=VCISCO),
             avp(3, u32(0x55), vendor=VCISCO), avp(4, u32(0x66), vendor=VCISCO),
             avp(5, bytes(8), vendor=VCISCO), avp(5, bytes(4), vendor=VCISCO), avp(6, b'remote', vendor=VCISCO),
             avp(7, u16(5), vendor=VCISCO), avp(8, u16(1), vendor=VCISCO),
             avp(9, u64(1), vendor=VCISCO), avp(10, u16(1), vendor=VCISCO),
             avp(12, bytes(17), vendor=VCISCO), avp(13, bytes(16), vendor=VCISCO),
             avp(14, u16(1500), vendor=VCISCO), avp(99, b'??', vendor=VCISCO),
             avp(3, bytes(range(30, 34)), vendor=VCISCO, h=True)]
    c2([msg(HELLO)] + vend, tid=22)
    bb = [avp(1, b'circuit-1', vendor=VBBF), avp(2, b'remote-1', vendor=VBBF)]
    for t in list(range(129, 139)):
        bb.append(avp(t, u64(t * 1000), vendor=VBBF))
    for t in (139, 140, 141, 142):
        bb.append(avp(t, u32(t), vendor=VBBF))
    bb += [avp(144, bytes([1, 2, 3]), vendor=VBBF), avp(145, u32(1), vendor=VBBF),
           avp(254, u32(2), vendor=VBBF), avp(200, b'??', vendor=VBBF),
           avp(129, bytes(8), vendor=VBBF, h=True)]
    c2([msg(HELLO)] + bb[:12], tid=22)
    c2([msg(HELLO)] + bb[12:], tid=22)
    tcg1 = bytes([1, 2, 0x10, 0x11]) + ip4('192.0.2.50') + bytes([0x2e, 1, 5]) + u16(1400)
    tcg2 = bytes([2, 0]) + ip4('192.0.2.51') + bytes([0, 0, 0]) + u16(0)
    tcg3 = bytes([3, 3, 1, 2, 3]) + ip4('192.0.2.52') + bytes([0x1a, 0, 9]) + u16(900)
    er = [avp(0, u16(2), vendor=VERIC), avp(1, u16(30) + bytes([3]) + tcg1 + tcg2 + tcg3, vendor=VERIC),
          avp(3, u32(1) + u32(2) + u32(3), vendor=VERIC), avp(4, bytes([1]), vendor=VERIC),
          avp(6, b'stn-1', vendor=VERIC), avp(5, bytes([1]), vendor=VERIC),
          avp(7, bytes([1]), vendor=VERIC),
          avp(8, bytes([3]) + bytes([0x10, 0x11, 1, 0x20, 0x21, 2, 0x30, 0x31, 3]), vendor=VERIC),
          avp(8, bytes([1]) + bytes([0x10, 0x11, 1]) + b'\xaa', vendor=VERIC),
          avp(2, u16(5), vendor=VERIC), avp(9, bytes(4), vendor=VERIC),
          avp(10, bytes(4), vendor=VERIC), avp(1, u16(30) + bytes([0]), vendor=VERIC),
          avp(1, u16(30) + bytes([1]) + bytes(4), vendor=VERIC),
          avp(8, bytes([0]), vendor=VERIC), avp(9, bytes(2), vendor=VERIC, h=True)]
    c2([msg(HELLO)] + er[:8], tid=22)
    c2([msg(HELLO)] + er[8:], tid=22)
    for t in range(0, 7):
        c2([avp(0, u16(t), vendor=VERIC)], tid=22)                # message type shown in Info
    c2([avp(0, u16(9), vendor=VERIC)], tid=22)
    cl = [avp(101, u16(0x8001) + u32(0x1dcd6500), vendor=VCABLE), avp(103, u16(0x0002), vendor=VCABLE),
          avp(105, u16(0x8003) + u16(1) + u16(2) + u16(3) + u16(4), vendor=VCABLE),
          avp(105, u16(0x0004), vendor=VCABLE), avp(110, b'xyz', vendor=VCABLE),
          avp(101, bytes(6), vendor=VCABLE, h=True)]
    c2([msg(HELLO)] + cl, tid=22)
    c2([msg(HELLO), avp(7, b'other', vendor=12345), avp(8, bytes(4), vendor=12345, h=True),
        avp(1, b'', vendor=12345)], tid=22)
    mark('L2TPv2 control without length bit and odd first AVP')
    F.append(p2.to_b(v2ctl([msg(HELLO)], 22, 0, 9, 9, flags=0x8802)))             # no L bit
    F.append(p2.to_b(v2ctl([avp(7, b'first')], 22, 0, 10, 9, flags=0xC802)))      # first AVP is not a message type
    mark('L2TPv2 data')
    d = [
        v2data(PPP_LCP, flags=0x4002),                                       # length, no seq
        v2data(PPP_LCP, flags=0x4802, ns=1, nr=2),                           # sequence
        v2data(PPP_LCP, flags=0x4202, offset=0),                             # offset bit, size 0
        v2data(PPP_LCP, flags=0x4A02, ns=3, nr=4, offset=4),                 # offset with padding
        v2data(PPP_LCP, flags=0x4102),                                       # priority
        v2data(PPP_LCP[2:], flags=0x0002),                                   # no length bit
        v2data(b'', flags=0x4802, ns=5, nr=6),                               # length 12, no payload
        v2data(b'', flags=0x4002),                                           # length 8, no payload
        v2data(bytes.fromhex('ff030021') + IPV4, flags=0x4002), # PPP with an IPv4 packet
    ]
    for x in d:
        F.append(p2.to_b(x))
    F.append(p2.to_a(d[0]))
    mark('not L2TP: version 1, one octet')
    F.append(udp_frame(struct.pack('!HH', 0x4001, 12) + bytes(8), p2.a, p2.b, 5000, 1701))

    # ============ L2TPv3 over UDP: tunnel A with digests and sessions =====
    pa = Peer('192.0.2.11', '192.0.2.12')
    mark('L2TPv3 over UDP tunnel A: control')
    nsa = [0, 0]

    def c3(peer, avps, dirn, ccid=0, FR=None, **kw):
        FR = F if FR is None else FR
        if dirn == 'ab':
            FR.append(peer.to_b(v3ctl(avps, ccid, nsa[0], nsa[1], **kw)))
            nsa[0] += 1
        else:
            FR.append(peer.to_a(v3ctl(avps, ccid, nsa[1], nsa[0], **kw)))
            nsa[1] += 1

    dg_md5 = lambda: avp(59, bytes([0]) + bytes(range(100, 116)))
    dg_sha = lambda: avp(59, bytes([1]) + bytes(range(100, 120)))
    c3(pa, [msg(SCCRQ), avp(2, bytes([1, 0])), avp(3, u32(3)), avp(7, b'lcce-a'),
            avp(8, b'Example'), avp(10, u16(8)), avp(61, u32(0xa1a1)),
            avp(62, u16(5) + u16(2) + u16(7) + u16(0x0c)), avp(73, bytes(range(8))), dg_md5()], 'ab')
    c3(pa, [msg(SCCRP), avp(2, bytes([1, 0])), avp(3, u32(3)), avp(7, b'lcce-b'),
            avp(61, u32(0xb2b2)), avp(62, u16(5)), avp(73, bytes(range(8, 16))), dg_md5()], 'ba', ccid=0xa1a1)
    c3(pa, [msg(SCCCN), dg_sha()], 'ab', ccid=0xb2b2)
    F.append(pa.to_b(v3ctl([], 0xb2b2, 3, 3, length=12)))                              # ZLB (over UDP)
    c3(pa, [msg(HELLO), dg_md5()], 'ba', ccid=0xa1a1)
    c3(pa, [msg(HELLO), avp(59, bytes([1]) + bytes(16))], 'ab', ccid=0xb2b2)            # wrong SHA1 length
    c3(pa, [msg(HELLO), avp(59, bytes([0]) + bytes(20))], 'ba', ccid=0xa1a1)            # wrong MD5 length
    c3(pa, [msg(HELLO), avp(59, bytes([7]) + bytes(16))], 'ab', ccid=0xb2b2)            # unknown algorithm
    mark('L2TPv3 UDP tunnel A: sessions (ICRQ/ICRP/ICCN per session)')
    sess = [  # (client id, server id, pw type, l2 sublayer, cookie, cookie2)
        (0x10, 0x90, 5, 1, 4, 8),         # Ethernet, default L2-specific
        (0x11, 0x91, 2, 2, 8, 4),         # AAL5, ATM-specific
        (0x12, 0x92, 12, 3, 0, 0),        # DOCSIS DMPT
        (0x13, 0x93, 4, 0, 4, 4),         # Ethernet VLAN, no sublayer
        (0x14, 0x94, 7, 0x1234, 8, 8),    # PPP, unknown sublayer value
    ]
    for n, (cid, sid, pw, l2, ck1, ck2) in enumerate(sess):
        a_id, a_pw, a_ck = avp(63, u32(cid)), avp(68, u16(pw)), ([avp(65, bytes(range(1, ck1 + 1)))] if ck1 else [])
        if n == 2:        # PW type before the session id: the session is created by the PW type
            first = [a_pw]
            rest = [a_id, avp(15, u32(cid)), avp(66, b'remote-end'), avp(69, u16(l2)), avp(70, u16(1)), avp(71, u16(3))]
        elif n == 3:      # cookie before the session id
            first = a_ck
            rest = [a_id, avp(15, u32(cid)), a_pw, avp(69, u16(l2)), avp(70, u16(1)), avp(71, u16(3))]
        else:
            first = []
            rest = [avp(15, u32(cid)), a_id, avp(66, b'remote-end'), a_pw, avp(69, u16(l2)), avp(70, u16(1)),
                    avp(71, u16(3))] + a_ck + [avp(72, b'en')]
        c3(pa, [msg(ICRQ)] + first + rest, 'ab', ccid=0xb2b2)
        rp = [avp(63, u32(sid)), avp(64, u32(cid))]
        if n == 4:        # remote session id before the local one
            rp = rp[::-1]
        c3(pa, [msg(ICRP)] + rp + [avp(69, u16(l2))] +
            ([avp(65, bytes(range(11, ck2 + 11)))] if ck2 else []) + [avp(74, u64(10**9)), avp(75, u64(10**9))],
            'ba', ccid=0xa1a1)
        c3(pa, [msg(ICCN), avp(64, u32(sid)), avp(69, u16(l2)), avp(74, u64(2 * 10**9)), avp(75, u64(2 * 10**9))],
            'ab', ccid=0xb2b2)
    # session AVPs and a connection id in a message that does not store them
    c3(pa, [msg(HELLO), avp(69, u16(1)), avp(61, u32(0x5555)), avp(63, u32(0x66)), avp(64, u32(0x67)),
            avp(65, bytes(4)), avp(68, u16(5)), avp(73, bytes(8))], 'ab', ccid=0xb2b2)
    c3(pa, [msg(OCRQ), avp(63, u32(0x20)), avp(68, u16(5)), avp(69, u16(1))], 'ab', ccid=0xb2b2)
    c3(pa, [msg(OCRP), avp(63, u32(0xa0)), avp(64, u32(0x20)), avp(69, u16(1))], 'ba', ccid=0xa1a1)
    c3(pa, [msg(OCCN), avp(64, u32(0xa0)), avp(69, u16(1))], 'ab', ccid=0xb2b2)
    c3(pa, [msg(CSUN), avp(97, u32(0x10) + u64(1000) + u64(2000))], 'ab', ccid=0xb2b2)
    c3(pa, [msg(CSURQ), avp(97, bytes(2) + u16(7) + u32(1) + u32(2)), avp(60, u32(0xc0000201))], 'ba', ccid=0xa1a1)
    c3(pa, [msg(FSQ), avp(61, u32(1))], 'ab', ccid=0xb2b2)
    c3(pa, [msg(FSR)], 'ba', ccid=0xa1a1)
    for t in (MSRQ, MSRP, MSE, MSI, MSEN, 5, 13, 30):
        c3(pa, [msg(t)], 'ab', ccid=0xb2b2)
    # a retransmitted ICRQ/ICRP pair, the reproducer of the session list fix
    mark('L2TPv3 UDP tunnel A: retransmissions (session list fix)')
    for n in range(8):
        c3(pa, [msg(ICRQ), avp(15, u32(0x10)), avp(63, u32(0x10)), avp(68, u16(5)), avp(69, u16(1))], 'ab', ccid=0xb2b2)
        c3(pa, [msg(ICRP), avp(63, u32(0x90)), avp(64, u32(0x10)), avp(69, u16(1))], 'ba', ccid=0xa1a1)
    mark('L2TPv3 UDP tunnel A: data')
    A = pa
    F.append(A.to_a(v3data_udp(0x10, bytes([1, 2, 3, 4]) + l2_default(1) + ETH)))   # to the client: cookie of the ICRQ (4)
    F.append(A.to_b(v3data_udp(0x90, bytes(range(11, 19)) + l2_default(2) + ETH)))
    F.append(A.to_a(v3data_udp(0x11, bytes(range(1, 9)) + l2_atm(seq=1) + LLC_SNAP)))             # AAL5, AAL5 frame
    F.append(A.to_b(v3data_udp(0x91, bytes(range(11, 15)) + l2_atm(t=True, seq=2) + OAM_CELL)))  # AAL5, OAM cell
    F.append(A.to_a(v3data_udp(0x11, bytes(range(1, 9)) + l2_atm(g=True, c=True, u=True, s=False, seq=0) + LLC_SNAP)))
    F.append(A.to_a(v3data_udp(0x12, l2_dmpt(1, True, False, 3, 7) + bytes(188))))
    F.append(A.to_b(v3data_udp(0x92, l2_dmpt(0, False, True, 0x1f, 0xffff) + bytes(188))))
    F.append(A.to_a(v3data_udp(0x13, bytes([1, 2, 3, 4]) + ETH)))
    F.append(A.to_b(v3data_udp(0x93, bytes([1, 2, 3, 4]) + ETH)))
    F.append(A.to_a(v3data_udp(0x14, bytes(range(1, 9)) + PPP_LCP)))
    F.append(A.to_b(v3data_udp(0x94, bytes(range(1, 9)) + PPP_LCP)))
    F.append(A.to_b(v3data_udp(0x7777, ETH)))                          # session not in the tunnel
    F.append(A.to_a(v3data_udp(0x10)))                                  # only the session id
    F.append(A.to_a(v3data_udp(0xa0, bytes(8))))                        # outgoing call session
    # ============ L2TPv3 over UDP: tunnel B (other ports, Cisco AVPs, no digest) =========
    pb = Peer('192.0.2.13', '192.0.2.14', aport=50000, bport=1701)
    mark('L2TPv3 over UDP tunnel B: Cisco AVPs and session without PW type AVP')
    nsa = [0, 0]
    c3(pb, [msg(SCCRQ), avp(2, bytes([1, 0])), avp(7, b'cisco-a'), avp(61, u32(0x1111)),
            avp(13, bytes(8), vendor=VCISCO), avp(1, u32(0x1111), vendor=VCISCO)], 'ab')
    c3(pb, [msg(SCCRP), avp(2, bytes([1, 0])), avp(7, b'cisco-b'), avp(61, u32(0x2222)),
            avp(2, u16(5) + u16(2), vendor=VCISCO), avp(14, u16(1500), vendor=VCISCO)], 'ba', ccid=0x1111)
    c3(pb, [msg(SCCCN)], 'ab', ccid=0x2222)
    c3(pb, [msg(ICRQ), avp(3, u32(0x30), vendor=VCISCO), avp(5, bytes(4), vendor=VCISCO),
            avp(6, b'end', vendor=VCISCO), avp(7, u16(5), vendor=VCISCO), avp(8, u16(0), vendor=VCISCO),
            avp(9, u64(5), vendor=VCISCO), avp(10, u16(2), vendor=VCISCO)], 'ab', ccid=0x2222)
    c3(pb, [msg(ICRP), avp(3, u32(0xb0), vendor=VCISCO), avp(4, u32(0x30), vendor=VCISCO),
            avp(5, bytes(8), vendor=VCISCO), avp(0, b'', vendor=VCISCO)], 'ba', ccid=0x1111)
    c3(pb, [msg(ICCN)], 'ab', ccid=0x2222)
    c3(pb, [msg(CDN), avp(1, u16(1) + u16(0)), avp(63, u32(0x30))], 'ab', ccid=0x2222)
    c3(pb, [msg(STOPCCN), avp(1, u16(1)), avp(61, u32(0x1111))], 'ab', ccid=0x2222)
    c3(pb, [avp(7, b'first AVP is not a message type')], 'ab', ccid=0x2222)
    F.append(pb.to_b(v3ctl([avp(7, b'no length bit'), msg(HELLO)], 0x2222, 20, 5, flags=0x8803)))
    F.append(pb.to_a(v3data_udp(0x30, bytes(4) + ETH)))                    # cookie 4 from the Cisco AVP
    F.append(pb.to_b(v3data_udp(0xb0, bytes(8) + ETH)))
    # ============ L2TPv3 over UDP: data only, no control (defaults) =======
    pc = Peer('192.0.2.15', '192.0.2.16', aport=1701, bport=1701)
    mark('L2TPv3 over UDP data without control messages')
    F.append(pc.to_b(v3data_udp(0x4321, ETH)))
    F.append(pc.to_a(v3data_udp(0x4321, ETH)))
    F.append(pc.to_b(v3data_udp(0x4321)))
    # ============ L2TPv3 over IP ===============================
    pi = Peer('192.0.2.21', '192.0.2.22', ip=True)
    mark('L2TPv3 over IP tunnel: control (SID 0), digests, sessions, data')
    nsa = [0, 0]
    c3(pi, [msg(SCCRQ), avp(2, bytes([1, 0])), avp(7, b'ip-a'), avp(61, u32(0xaaaa)), avp(73, bytes(range(8))), dg_md5()],
       'ab', sid=0)
    c3(pi, [msg(SCCRP), avp(2, bytes([1, 0])), avp(7, b'ip-b'), avp(61, u32(0xbbbb)), avp(73, bytes(range(8, 16))), dg_sha()],
       'ba', ccid=0xaaaa, sid=0)
    c3(pi, [msg(SCCCN), dg_md5()], 'ab', ccid=0xbbbb, sid=0)
    F.append(pi.to_b(v3ctl([], 0xbbbb, 2, 2, sid=0, length=12)))                    # ZLB
    c3(pi, [msg(HELLO), dg_sha()], 'ba', ccid=0xaaaa, sid=0)
    c3(pi, [msg(ICRQ), avp(63, u32(0x40)), avp(68, u16(5)), avp(69, u16(2)), avp(65, bytes(8))], 'ab', ccid=0xbbbb, sid=0)
    c3(pi, [msg(ICRP), avp(63, u32(0xc0)), avp(64, u32(0x40)), avp(69, u16(2)), avp(65, bytes(8))], 'ba', ccid=0xaaaa, sid=0)
    c3(pi, [msg(ICCN), avp(64, u32(0xc0)), avp(69, u16(2))], 'ab', ccid=0xbbbb, sid=0)
    c3(pi, [msg(ICRQ), avp(63, u32(0x41)), avp(68, u16(2)), avp(69, u16(2))], 'ab', ccid=0xbbbb, sid=0)
    c3(pi, [msg(ICRP), avp(63, u32(0xc1)), avp(64, u32(0x41)), avp(69, u16(2))], 'ba', ccid=0xaaaa, sid=0)
    c3(pi, [msg(STOPCCN), avp(1, u16(1) + u16(0)), avp(61, u32(0xaaaa))], 'ab', ccid=0xbbbb, sid=0)
    F.append(pi.to_a(v3data_ip(0x40, bytes(8) + l2_default(3) + ETH)))
    F.append(pi.to_b(v3data_ip(0xc0, bytes(8) + l2_default(4) + ETH)))
    F.append(pi.to_a(v3data_ip(0x41, l2_atm(seq=3) + LLC_SNAP)))                    # AAL5 AAL5 frame
    F.append(pi.to_b(v3data_ip(0xc1, l2_atm(t=True, seq=4) + OAM_CELL)))            # AAL5 OAM cell
    F.append(pi.to_a(v3data_ip(0x40)))                                              # only the session id
    pj = Peer('192.0.2.23', '192.0.2.24', ip=True)
    F.append(pj.to_b(v3data_ip(0x5555, ETH)))                                       # IP data, no control
    F.append(pj.to_a(v3data_ip(0x5555, ETH)))
    F.append(pj.to_b(v3ctl([msg(HELLO)], 0x77, 1, 1, sid=0)))                       # first control is not SCCRQ

    # ================= the reproducers of the fixes ==================
    mark('Reproducer: Ericsson TEI to SC Map subset (and Transport Config)')
    nxt = avp(0, u16(HELLO))
    tei5 = avp(8, b'\x02' + b'\x10\x11\x12\x20\x21', vendor=VERIC)       # 5 octets of maps: one map, the subset must not cover the next AVP
    tei6 = avp(8, b'\x02' + b'\x10\x11\x12\x20\x21\x22', vendor=VERIC)   # two maps
    tc3 = avp(1, u16(30) + bytes([0]), vendor=VERIC)                     # exactly 3 octets
    F.append(p2.to_b(v2ctl([nxt, tei5, avp(7, b'next')], 22, 0, 40, 9)))
    F.append(p2.to_b(v2ctl([nxt, tei6, avp(7, b'next')], 22, 0, 41, 9)))
    F.append(p2.to_b(v2ctl([nxt, tc3, avp(7, b'next')], 22, 0, 42, 9)))

    # ================== malformed capture ==========================
    M.append(udp_frame(b'\x00', p2.a, p2.b, 5001, 1701))                                          # one octet: not L2TP
    # a tunnel with two sessions, so that the data frames below find them
    nsa = [0, 0]
    c3(pa, [msg(SCCRQ), avp(2, bytes([1, 0])), avp(61, u32(0xa1a1))], 'ab', FR=M)
    c3(pa, [msg(SCCRP), avp(2, bytes([1, 0])), avp(61, u32(0xb2b2))], 'ba', ccid=0xa1a1, FR=M)
    c3(pa, [msg(ICRQ), avp(63, u32(0x10)), avp(68, u16(5)), avp(69, u16(1)), avp(65, bytes(4))], 'ab', ccid=0xb2b2, FR=M)
    c3(pa, [msg(ICRP), avp(63, u32(0x90)), avp(64, u32(0x10)), avp(69, u16(1)), avp(65, bytes(8))], 'ba', ccid=0xa1a1, FR=M)
    c3(pa, [msg(ICRQ), avp(63, u32(0x11)), avp(68, u16(2)), avp(69, u16(2)), avp(65, bytes(8))], 'ab', ccid=0xb2b2, FR=M)
    c3(pa, [msg(ICRP), avp(63, u32(0x91)), avp(64, u32(0x11)), avp(69, u16(2)), avp(65, bytes(4))], 'ba', ccid=0xa1a1, FR=M)
    M.append(p2.to_b(v2ctl([nxt, avp(1, b'\x00', vendor=VERIC), avp(7, b'next')], 22, 0, 1, 1)))   # Ericsson TC AVP < 3
    M.append(p2.to_b(v2ctl([nxt, avp(1, b'', vendor=VERIC), avp(7, b'next')], 22, 0, 1, 1)))
    M.append(p2.to_b(v2ctl([nxt, avp(8, b'', vendor=VERIC), avp(7, b'next')], 22, 0, 1, 1)))        # TEI map AVP < 1
    M.append(p2.to_b(v2ctl([nxt, avp(8, b'\x01', vendor=VERIC), avp(7, b'next')], 22, 0, 1, 1)))    # num maps only
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(7, b'x', length=5)], 22, 0, 1, 1)))                     # AVP length < 6
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(7, b'x', length=0)], 22, 0, 1, 1)))
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(7, b'abc', length=60)], 22, 0, 1, 1)))                  # AVP past the end
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(24, b'\x00\x00')], 22, 0, 1, 1)))                       # speed cut short
    M.append(p2.to_b(v2ctl([msg(HELLO), b'\x80\x08\x00']), ))                                       # AVP header cut
    M.append(p2.to_b(v2ctl([msg(HELLO)], 22, 0, 1, 1, length=200)))                                 # length beyond the frame
    M.append(p2.to_b(v2ctl([msg(HELLO)], 22, 0, 1, 1)[:5]))                                         # header cut
    M.append(p2.to_b(v2data(PPP_LCP, flags=0x4202, offset=4)[:12]))                                 # offset beyond the end
    M.append(p2.to_b(struct.pack('!HHHH', 0x4A02, 0x30, 1, 1)))                                     # v2 data cut in Ns
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(34, bytes(2) + u32(1))[:12]], 22, 0, 1, 1)))
    M.append(pa.to_b(v3ctl([msg(HELLO), avp(7, b'x', length=3)], 0xb2b2, 99, 99)))
    M.append(pa.to_b(v3ctl([msg(HELLO)], 0xb2b2, 99, 99)[:6]))                                      # v3 control cut
    M.append(pa.to_b(struct.pack('!HH', 0x0003, 0)))                                                # v3 data without session id
    M.append(pa.to_a(v3data_udp(0x10, bytes([1, 2]))))                                              # cookie cut (4)
    M.append(pa.to_a(v3data_udp(0x11, bytes(range(1, 9)) + b'\x00\x00')))                           # ATM sublayer cut
    M.append(pi.to_b(b'\x00\x00'))                                                                  # IP: less than a session id
    M.append(pi.to_b(v3ctl([msg(HELLO)], 0xbbbb, 77, 77, sid=0)[:8]))                               # IP control cut
    M.append(p2.to_b(v2ctl([nxt, avp(58, bytes([0, 1, 0, 1]))], 22, 0, 1, 1)))                      # Extended Vendor ID, 4 octet ID: see README
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(105, u16(1) + u16(2), vendor=VCABLE)], 22, 0, 1, 1)))   # CableLabs pair cut
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(1, bytes([3, 0]) + bytes(8), vendor=VERIC)], 22, 0, 1, 1)))
    M.append(p2.to_b(v2ctl([msg(HELLO), avp(1, u16(30) + bytes([200]) + bytes(8), vendor=VERIC)], 22, 0, 1, 1)))  # more SAPIs than data

    def write(path, frames):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, PCAP_SNAP, 1))
            for i, fr in enumerate(frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

    write(out + '/l2tp-coverage.pcap', F)
    write(out + '/l2tp-coverage-malformed.pcap', M)
    if '-v' in sys.argv:
        for i, (n, t) in enumerate(marks):
            end = marks[i + 1][0] - 1 if i + 1 < len(marks) else len(F)
            print('%d-%d: %s' % (n, end, t))
        print('main frames: %d, malformed: %d' % (len(F), len(M)))


main()

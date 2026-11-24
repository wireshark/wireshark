#!/usr/bin/env python3
# Generates the profinet captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic PROFINET coverage captures (everything of the
# profinet plugin except the CBA dissectors).
# Usage: mkprofinet.py <outdir>
# Writes profinet-coverage.pcap (clean) and profinet-coverage-malformed.pcap.
# Everything is built with struct; nothing comes from a real network.
import struct
import sys
import os
import socket
import uuid

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---------------------------------------------------------------- helpers
MAC_A = bytes.fromhex('00 0e 8c 11 22 01'.replace(' ', ''))   # controller
MAC_B = bytes.fromhex('00 0e 8c 11 22 02'.replace(' ', ''))   # device
MAC_C = bytes.fromhex('00 0e 8c 11 22 03'.replace(' ', ''))   # second device
MAC_D = bytes.fromhex('00 0e 8c 11 22 04'.replace(' ', ''))   # SXP device
MAC_E = bytes.fromhex('00 0e 8c 11 22 05'.replace(' ', ''))   # SXP controller
MAC_F = bytes.fromhex('00 0e 8c 11 22 06'.replace(' ', ''))   # alarm / RSI station
MAC_G = bytes.fromhex('00 0e 8c 11 22 07'.replace(' ', ''))   # alarm / RSI controller
MAC_H = bytes.fromhex('00 0e 8c 11 22 08'.replace(' ', ''))   # GSD scenario device
MAC_I = bytes.fromhex('00 0e 8c 11 22 09'.replace(' ', ''))   # GSD scenario controller
MAC_DCP_MC = bytes.fromhex('010ecf000000')
MAC_PTCP_MC = bytes.fromhex('010ecf000020')
MAC_MRP_MC = bytes.fromhex('0180c2000002')
MAC_MRP_TEST = bytes.fromhex('0180c2000001')

MAIN = []       # (bytes) frames of the clean capture
MAL = []        # frames of the malformed capture
CUR = [MAIN]


def emit(fr, pad=True):
    if pad and len(fr) < 60:
        fr = fr + bytes(60 - len(fr))
    CUR[0].append(fr)


def be16(x):
    return struct.pack('>H', x)


def be32(x):
    return struct.pack('>I', x)


def eth(dst, src, etype, payload, vlan=None):
    h = dst + src
    if vlan is not None:
        h += struct.pack('>HH', 0x8100, vlan)
    return h + be16(etype) + payload


def rt(frame_id, payload, dst=MAC_B, src=MAC_A, vlan=None):
    return eth(dst, src, 0x8892, be16(frame_id) + payload, vlan)


def write_pcap(name, frames, linktype=1):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)


def write_pcapng(name, frames):
    """frames: bytes (Ethernet) or ('raw', bytes) for the raw IP interface."""
    def blk(btype, body):
        body += bytes((-len(body)) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def opt(code, val):
        return struct.pack('<HH', code, len(val)) + val + bytes((-len(val)) % 4)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1) + opt(4, b'synthetic PROFINET coverage capture') + opt(0, b''))
    for lt in (1, 101):
        out += blk(1, struct.pack('<HHI', lt, 0, 262144) + opt(2, b'eth0' if lt == 1 else b'raw0') + opt(0, b''))
    for i, fr in enumerate(frames):
        ifidx = 0
        if isinstance(fr, tuple):
            ifidx, fr = 1, fr[1]
        ts = (1700000000 + i // 1000) * 1000000 + (i % 1000) * 1000
        out += blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(out)


def ipsum(h):
    s = 0
    for i in range(0, len(h), 2):
        s += (h[i] << 8) | h[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, flags_frag=0):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, flags_frag, 64, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + be16(ipsum(ip)) + ip[12:]
    return ip + payload


def udp_frame(payload, sport=34964, dport=34964, src_ip='192.0.2.1', dst_ip='192.0.2.2',
              dst=MAC_B, src=MAC_A):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(dst, src, 0x0800, ipv4(17, u, src_ip, dst_ip))


def tcp_frame(payload, sport, dport, seq, ack=1, flags=0x18, src_ip='192.0.2.1', dst_ip='192.0.2.2',
              dst=MAC_B, src=MAC_A):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    return eth(dst, src, 0x0800, ipv4(6, t, src_ip, dst_ip))


# ------------------------------------------------------------------- DCP
class DCP:
    GET, SET, IDENT, HELLO = 3, 4, 5, 6

    @staticmethod
    def blk(opt, sub, data):
        b = bytes([opt, sub]) + be16(len(data)) + data
        if len(b) & 1:
            b += b'\0'
        return b

    @staticmethod
    def pdu(sid, stype, xid, blocks, delay=0x0001):
        return bytes([sid, stype]) + be32(xid) + be16(delay) + be16(len(blocks)) + blocks

    @staticmethod
    def frame(fid, p, dst=MAC_DCP_MC, src=MAC_A, vlan=None):
        return rt(fid, p, dst, src, vlan)


def dcp_frames():
    D = DCP
    uuid0 = bytes(16)
    uuid1 = uuid.UUID('12345678-1234-5678-9abc-def012345678').bytes
    ip = bytes([192, 168, 0, 5]) + bytes([255, 255, 255, 0]) + bytes([192, 168, 0, 1])
    fips = ip + bytes([8, 8, 8, 8]) + bytes([8, 8, 4, 4]) + bytes([1, 1, 1, 1]) + bytes([9, 9, 9, 9])
    nos = b'dev-1.plant'
    # (context, bodies): context says what goes in front of the data
    # i = BlockInfo (Ident Res, Hello Req, Get Res), q = BlockQualifier (Set Req), n = nothing
    def mk(ctx, opt, sub, data, val=0x0001):
        if opt == 7 and sub in (2, 4, 5) and ctx != 'i':
            # the dissector only decodes these with a BlockInfo
            return b'' if ctx == 'n' else D.blk(opt, sub, be16(val))
        pre = {'i': be16(val), 'q': be16(val), 'n': b''}[ctx]
        return D.blk(opt, sub, pre + data)

    seq = [0x1000]

    def xid():
        seq[0] += 1
        return seq[0]

    ctxs = [(D.IDENT, 1, 'i', 0xfeff, MAC_A, MAC_B), (D.HELLO, 0, 'i', 0xfefc, MAC_DCP_MC, MAC_B),
            (D.GET, 1, 'i', 0xfefd, MAC_A, MAC_B), (D.SET, 0, 'q', 0xfefd, MAC_B, MAC_A),
            (D.IDENT, 0, 'n', 0xfefe, MAC_DCP_MC, MAC_A)]
    # block specs: (name, builder(ctx)->bytes)
    def specs(ctx):
        s = []
        s.append(mk(ctx, 1, 1, bytes.fromhex('020000000009')))                 # IP/MAC
        s.append(mk(ctx, 1, 2, ip, 0x0001))                                    # IP/IP
        s.append(mk(ctx, 1, 2, ip, 0x0081 if ctx == 'i' else 0x0001))          # IP conflict flag
        s.append(mk(ctx, 1, 2, ip, 0x0002))
        s.append(mk(ctx, 1, 3, fips))                                          # full IP suite
        s.append(mk(ctx, 1, 9, b'\x01\x02\x03\x04'))                           # unknown IP sub
        s.append(mk(ctx, 2, 1, b'S7-1500'))                                    # type of station
        s.append(mk(ctx, 2, 2, nos))                                           # name of station
        s.append(mk(ctx, 2, 3, be16(0x002a) + be16(0x0403)))                   # dev id
        for role in (0x01, 0x02, 0x04, 0x08, 0x0f):
            s.append(mk(ctx, 2, 4, bytes([role, 0])))                          # device role
        s.append(mk(ctx, 2, 5, bytes([1, 2, 2, 1, 2, 2, 2, 3, 5, 6])))        # device options
        s.append(mk(ctx, 2, 6, b'port-001.dev-1.plant'))                       # alias
        s.append(mk(ctx, 2, 7, bytes([0, 1])))                                 # instance
        s.append(mk(ctx, 2, 8, be16(0x00fe) + be16(0x0001)))                   # OEM id
        s.append(mk(ctx, 2, 0x0a, be16(0x003f)))                               # RSI properties
        s.append(mk(ctx, 2, 0x0a, be16(0xff80)))
        s.append(mk(ctx, 2, 0x0b, be16(0x003f)))                               # protocol properties
        s.append(mk(ctx, 2, 0x0b, be16(0xffc0)))
        s.append(mk(ctx, 2, 0x55, b'\xde\xad\xbe\xef'))                        # unknown device sub
        s.append(mk(ctx, 3, 61, bytes([61, 1, 1])))                            # DHCP client id, 1 byte data = 1
        s.append(mk(ctx, 3, 61, bytes([61, 1, 0])))
        s.append(mk(ctx, 3, 61, bytes([61, 6]) + b'\x00abcde'))                # arbitrary client id
        s.append(mk(ctx, 3, 61, bytes([61, 0])))
        s.append(mk(ctx, 3, 255, bytes([255, 1, 1])))                          # control DHCP
        s.append(mk(ctx, 3, 77, bytes([1, 2, 3, 4])))                          # unknown DHCP sub
        s.append(mk(ctx, 3, 255, bytes([255, 1, 1, 0xaa, 0xbb])))              # DHCP with undefined trailer
        s.append(mk(ctx, 0xff, 0x01, b'\x00\x00'))                              # unknown all-selector sub
        s.append(mk(ctx, 6, 1, be16(1)))                                       # device initiative
        s.append(mk(ctx, 7, 1, uuid0 + b'domain-a'))                           # NME domain
        s.append(mk(ctx, 7, 1, uuid1 + b'domain-b'))
        s.append(mk(ctx, 7, 2, be16(0x0000)))                                  # NME manager prio
        s.append(mk(ctx, 7, 2, be16(0x2000)))
        s.append(mk(ctx, 7, 2, be16(0x8000)))
        s.append(mk(ctx, 7, 2, be16(0xa000)))
        s.append(mk(ctx, 7, 2, be16(0xb000)))
        s.append(mk(ctx, 7, 3, uuid0))                                         # NME parameter uuid
        s.append(mk(ctx, 7, 3, uuid1))
        s.append(mk(ctx, 7, 4, uuid0))                                         # NME agent
        s.append(mk(ctx, 7, 4, uuid1))
        s.append(mk(ctx, 7, 5, be16(0x1234) + be16(0x5678) + bytes([1, 2])))   # CIM interface
        s.append(mk(ctx, 7, 9, b''))                                           # NME reserved sub
        s.append(D.blk(0x80, 1, b'\x01\x02\x03'))                              # manufacturer specific
        s.append(D.blk(0xe0, 0, b''))
        s.append(D.blk(4, 0, b''))                                             # reserved option
        return s

    for sid, stype, ctx, fid, dst, src in ctxs:
        for b in specs(ctx):
            if not b:
                continue
            emit(D.frame(fid, D.pdu(sid, stype, xid(), b), dst, src))
    # fresh MAC pairs: the blocks that create the station conversation
    for n, (opt, sub, data) in enumerate(((2, 1, b'ET200'), (2, 2, b'fresh-name'), (2, 3, be16(1) + be16(2)),
                                          (2, 0x0a, be16(1)), (7, 5, be16(1) + be16(2) + bytes([1, 2])))):
        for k, (sid, stype, ctx, fid) in enumerate(((5, 1, 'i', 0xfeff), (4, 0, 'q', 0xfefd), (6, 0, 'i', 0xfefc))):
            a = bytes([0x00, 0x1b, 0x1b, 0x50 + n, k, 1])
            b = bytes([0x00, 0x1b, 0x1b, 0x50 + n, k, 2])
            if opt == 7 and ctx != 'i':
                continue
            emit(D.frame(fid, D.pdu(sid, stype, xid(), mk(ctx, opt, sub, data)), b, a))
            emit(D.frame(fid, D.pdu(sid, stype, xid(), mk(ctx, opt, sub, data)), a, b))
    emit(rt(0xfefe, bytes(6)), pad=False)                                   # too short for DCP
    # Ident request filters
    emit(D.frame(0xfefe, D.pdu(5, 0, xid(), D.blk(2, 2, nos) + D.blk(0xff, 0xff, b'')), MAC_DCP_MC, MAC_A))
    emit(D.frame(0xfefe, D.pdu(5, 0, xid(), D.blk(2, 6, b'port-001.x') + D.blk(2, 3, be16(42) + be16(1))),
                 MAC_DCP_MC, MAC_A, vlan=0xa000))
    # Get requests: option/suboption pairs
    for pairs in ([(1, 2)], [(2, 2), (2, 3)], [(1, 1), (1, 3), (2, 1), (2, 4), (2, 5), (2, 6), (2, 7), (2, 8)],
                  [(3, 61), (3, 255), (5, 3), (6, 1), (7, 1), (7, 5), (0xff, 0xff), (0x80, 1)]):
        emit(D.frame(0xfefd, D.pdu(3, 0, xid(), b''.join(bytes(p) for p in pairs)), MAC_B, MAC_A))
    # Set requests with control blocks, set responses, unsupported
    qual = lambda v: be16(v)
    for sub, data in ((1, qual(1)), (2, qual(1)), (3, qual(1) + be16(0x0100)), (5, qual(1)), (6, qual(0x0002)),
                      (6, qual(0x0004)), (9, b'\x00\x00')):
        emit(D.frame(0xfefd, D.pdu(4, 0, xid(), D.blk(5, sub, data)), MAC_B, MAC_A))
    emit(D.frame(0xfefd, D.pdu(4, 0, xid(), D.blk(5, 3, b'')), MAC_B, MAC_A))   # erroneous Set block
    for opt, sub, err in ((2, 2, 0), (1, 2, 1), (1, 2, 3), (3, 61, 5), (5, 1, 7), (2, 2, 9)):
        emit(D.frame(0xfefd, D.pdu(4, 1, xid(), D.blk(5, 4, bytes([opt, sub, err]))), MAC_A, MAC_B))
    emit(D.frame(0xfefd, D.pdu(4, 1, xid(), D.blk(5, 4, bytes([2, 2, 0])) + D.blk(5, 4, bytes([1, 2, 0]))), MAC_A, MAC_B))
    emit(D.frame(0xfefd, D.pdu(3, 5, xid(), b''), MAC_A, MAC_B))              # Get, unsupported
    emit(D.frame(0xfefd, D.pdu(7, 0, xid(), b'\x01\x02\x03\x04'), MAC_B, MAC_A))  # unknown service id
    emit(D.frame(0xfefd, D.pdu(3, 2, xid(), b'\x01\x02\x03\x04'), MAC_B, MAC_A))  # unknown service type
    # multi block responses
    emit(D.frame(0xfeff, D.pdu(5, 1, xid(),
        mk('i', 2, 1, b'S7-1500') + mk('i', 2, 2, nos) + mk('i', 2, 3, be16(42) + be16(1)) +
        mk('i', 2, 4, bytes([1, 0])) + mk('i', 2, 5, bytes([1, 2, 2, 1, 2, 2])) + mk('i', 1, 2, ip) +
        mk('i', 2, 7, bytes([0, 1])) + mk('i', 7, 5, be16(0x1234) + be16(0x5678) + bytes([1, 2])) +
        mk('i', 2, 8, be16(1) + be16(2)) + mk('i', 2, 0x0a, be16(3)) + mk('i', 1, 1, MAC_B)),
        MAC_A, MAC_B))
    emit(D.frame(0xfeff, D.pdu(5, 1, xid(),
        mk('i', 2, 2, b'dev-2.plant') + mk('i', 2, 3, be16(42) + be16(2)) + mk('i', 1, 2, ip)), MAC_A, MAC_C))
    # Device hello; set with several blocks
    emit(D.frame(0xfefd, D.pdu(4, 0, xid(),
        D.blk(5, 1, qual(1)) + mk('q', 2, 2, b'new-name') + mk('q', 1, 2, ip) + D.blk(5, 2, qual(1)) +
        D.blk(5, 3, qual(1) + be16(0x0100))), MAC_B, MAC_A))
    # DCP over UDP port 34962 (PN-RT is registered on UDP too)
    emit(udp_frame(be16(0xfefe) + D.pdu(5, 0, xid(), D.blk(2, 2, nos)), 34962, 34962, dst=MAC_DCP_MC))

# ------------------------------------------------------------------ PTCP
def tlv(t, body):
    return be16((t << 9) | len(body)) + body


def ptcp_frames():
    sub_uuid = uuid.UUID('aabbccdd-1122-3344-5566-778899aabbcc').bytes
    irdata = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff').bytes
    END = tlv(0, b'')
    t_sub = tlv(1, MAC_A + sub_uuid)
    t_time = tlv(2, be16(1) + be32(1700000000) + be32(123456789))
    t_ext = tlv(3, be16(0x0003) + be16(37))
    t_master = lambda p1: tlv(4, bytes([p1, 0x80, 0x10, 0x20]) + struct.pack('>h', -5) + b'\0\0')
    t_port = tlv(5, be32(100) + be32(200))
    t_delay = tlv(6, MAC_B + b'\0\0')
    t_ptime = tlv(7, be32(5000))
    t_org = tlv(0x7f, bytes.fromhex('080006') + b'\x01' + irdata)
    t_org_mc = tlv(0x7f, bytes.fromhex('010ecf') + b'\x01' + irdata)
    t_org_sub = tlv(0x7f, bytes.fromhex('080006') + b'\x02' + b'\x11\x22\x33')
    t_org_oui = tlv(0x7f, bytes.fromhex('112233') + b'\x01\x02\x03\x04')
    t_org_short = tlv(0x7f, b'\x01\x02')
    t_unknown = tlv(0x20, b'\xaa\xbb\xcc\xdd')
    blocks_all = t_sub + t_time + t_ext + t_master(0x01) + t_port + t_delay + t_ptime + t_org + END
    pad12 = bytes(12)
    mc = MAC_PTCP_MC
    # Announce (0xff00 clock, 0xff01 time)
    for fid in (0xff00, 0xff01):
        hdr = pad12 + be16(7) + bytes(6)
        emit(rt(fid, hdr + blocks_all, mc, MAC_A))
        emit(rt(fid, hdr + t_sub + t_master(0x81) + t_org_mc + t_org_sub + t_org_oui + t_org_short +
                t_unknown + END, mc, MAC_A))
    # FollowUp
    for fid in (0xff20, 0xff21):
        hdr = pad12 + be16(8) + bytes(2) + struct.pack('>i', -17)
        emit(rt(fid, hdr + blocks_all, mc, MAC_A))
    # Delay PDUs
    for fid in (0xff40, 0xff41, 0xff42, 0xff43):
        hdr = pad12 + be16(9) + bytes(2) + be32(333)
        emit(rt(fid, hdr + t_delay + t_ptime + t_port + END, MAC_PTCP_MC if fid == 0xff40 else MAC_B, MAC_A))
    # RTSync (with and without follow up): frame ids 0x20, 0x21, 0x80, 0x81
    for fid in (0x0020, 0x0021, 0x0080, 0x0081):
        hdr = be32(0) + be32(0) + be32(123456) + be16(10) + b'\x07' + b'\0' + be32(9) + b''
        emit(rt(fid, hdr + t_time + t_org + END, MAC_PTCP_MC, MAC_A))
        hdr0 = be32(0) + be32(0) + be32(0) + be16(11) + b'\x00' + b'\0' + be32(0)
        emit(rt(fid, hdr0 + END, MAC_PTCP_MC, MAC_A))
    # reserved frame ids inside the PTCP ranges
    emit(rt(0xff44, bytes(30), mc, MAC_A))
    emit(rt(0xff10, bytes(30), mc, MAC_A))


# ------------------------------------------------------------------- MRP
def mrp_frames():
    dom = uuid.UUID('11111111-2222-3333-4444-555555555555').bytes
    def pad4(b, hdr=2):
        return b

    def T(t, body, align=False, hdr_off=[0]):
        return bytes([t, len(body)]) + body

    def build(tlvs):
        # tlvs: list of (type, body, aligns)
        out = be16(1)
        sub = b''
        for t, body, aligns in tlvs:
            sub += bytes([t, len(body)]) + body
            if aligns and len(sub) % 4:
                sub += bytes(4 - len(sub) % 4)
        return out + sub

    END = (0, b'', False)
    common = (1, be16(0x0102) + dom, False)
    def test(prio, role=0, ring=1):
        return (2, be16(prio) + MAC_A + be16(role) + be16(ring) + be16(5) + be32(123456), True)
    def topo(prio, interval):
        return (3, be16(prio) + MAC_A + be16(interval), False)
    def link(t, interval, blocked):
        return (t, MAC_A + be16(1) + be16(interval) + be16(blocked), True)
    intest = (6, be16(3) + MAC_A + be16(1) + be16(0) + be16(2) + be32(99), True)
    intopo = lambda iv: (7, MAC_A + be16(3) + be16(iv), False)
    inlink = lambda t, iv, li: (t, MAC_A + be16(1) + be16(3) + be16(iv) + be16(li), True)
    poll = (0xa, MAC_A + be16(1) + be16(3), False)
    siemens = bytes.fromhex('080006')
    def opt(ed1, extra=b''):
        return (0x7f, siemens + bytes([ed1]) + extra, True)
    sub12 = lambda t: bytes([t, 0x12]) + be16(0x8000) + MAC_A + be16(0xa000) + MAC_B
    sub_blocks = []
    cases = []
    for prio in (0x0000, 0x2000, 0x8000, 0x8800, 0x9100, 0xa000, 0xb000, 0xffff, 0x0500):
        cases.append([common, test(prio), END])
    for iv, bl in ((10, 0), (3000, 1), (20, 2)):
        for t in (4, 5):
            cases.append([common, link(t, iv, bl), END])
    for pr, iv in ((0x8000, 10), (0x0000, 4000)):
        cases.append([common, topo(pr, iv), END])
    cases.append([common, test(0x8000, 1, 0), topo(0x8000, 20), link(4, 20, 0), END])
    cases.append([intest, END])
    cases.append([intopo(10), END])
    cases.append([intopo(3000), END])
    for t in (8, 9):
        for li in (0x0000, 0x8000, 0x0c00, 0x2000, 0x7f00, 0x1234):
            cases.append([inlink(t, 10 if li & 1 else 3000, li), END])
    cases.append([poll, END])
    cases.append([opt(0, be16(0x1234)), END])
    cases.append([opt(4, be16(0x1234)), END])
    cases.append([opt(1), END])
    cases.append([opt(2), END])
    cases.append([opt(3), END])
    cases.append([opt(7), END])
    cases.append([opt(1, sub12(1)), END])
    cases.append([opt(2, sub12(2)), END])
    cases.append([opt(0, be16(0x1234) + sub12(1)), END])
    cases.append([opt(5, bytes([0x00, 0x04, 0, 0, 0, 0])), END])
    cases.append([opt(1, bytes([0xf1, 4]) + b'abcd'), END])
    cases.append([opt(1, bytes([0x00, 0]) ), END])
    cases.append([(0x7f, bytes.fromhex('445566') + b'\x01\x02\x03', True), END])
    cases.append([(0x55, b'\x01\x02\x03\x04', False), END])
    for c in cases:
        emit(eth(MAC_MRP_TEST if (c[0][0] == 6 or c[0][0] == 7) else MAC_MRP_MC, MAC_A, 0x88e3, build(c)))
    emit(eth(MAC_MRP_MC, MAC_A, 0x88e3, build([common, test(0x8000), END]), vlan=0xe000))


# ------------------------------------------------------------------ MRRT
def mrrt_frames():
    dom = uuid.UUID('11111111-2222-3333-4444-555555555555').bytes
    def B(tlvs):
        return be16(1) + b''.join(bytes([t, len(b)]) + b for t, b in tlvs)
    common = (1, be16(0x0102) + dom)
    test = (2, MAC_A + b'\0\0')
    end = (0, b'')
    emit(rt(0xff60, B([common, test, end]), MAC_MRP_MC, MAC_A))
    emit(rt(0xff60, B([common, end]), MAC_MRP_MC, MAC_A))
    emit(rt(0xff60, B([(0x30, b'\x01\x02\x03\x04'), test, end]), MAC_MRP_MC, MAC_A))

# -------------------------------------------------------------- PN-IO RTA
# Smallest all-zero body (in octets, after the version) that decodes without an
# exception, per block type, found by dissecting every type with growing bodies.
ZERO_LEN = {
    0x0000: 4, 0x0001: 24, 0x0002: 24, 0x0008: 64, 0x0009: 64, 0x0010: 12, 0x0011: 4, 0x0012: 4,
    0x0013: 4, 0x0014: 4, 0x0015: 12, 0x0016: 12, 0x0017: 4, 0x0018: 4, 0x0019: 12, 0x001a: 4,
    0x001b: 4, 0x0020: 64, 0x0021: 64, 0x0022: 24, 0x0023: 64, 0x0024: 64, 0x0025: 4, 0x0026: 4,
    0x0027: 4, 0x0028: 4, 0x0029: 4, 0x002a: 4, 0x002b: 4, 0x002c: 4, 0x002d: 4, 0x002e: 4, 0x002f:
    4, 0x0030: 4, 0x0031: 4, 0x0032: 4, 0x0033: 4, 0x0034: 160, 0x0035: 4, 0x0036: 600, 0x0037: 300,
    0x0038: 300, 0x0101: 64, 0x0102: 40, 0x0103: 24, 0x0104: 4, 0x0105: 4, 0x0106: 12, 0x0108: 12,
    0x0109: 24, 0x010a: 12, 0x010b: 4, 0x010c: 12, 0x010d: 64, 0x010e: 4, 0x010f: 4, 0x0110: 40,
    0x0111: 40, 0x0112: 40, 0x0113: 40, 0x0114: 40, 0x0115: 4, 0x0116: 40, 0x0117: 40, 0x0118: 4,
    0x0119: 4, 0x011a: 4, 0x011b: 24, 0x0200: 12, 0x0201: 4, 0x0202: 12, 0x0204: 40, 0x0206: 40,
    0x0208: 12, 0x0209: 12, 0x020a: 4, 0x020b: 12, 0x020c: 4, 0x020e: 12, 0x020f: 40, 0x0210: 12,
    0x0211: 40, 0x0212: 40, 0x0213: 24, 0x0214: 24, 0x0215: 24, 0x0216: 24, 0x0217: 12, 0x0218: 12,
    0x0219: 4, 0x021a: 4, 0x021b: 12, 0x021c: 4, 0x021d: 12, 0x021e: 4, 0x021f: 4, 0x0220: 12,
    0x0221: 4, 0x0222: 12, 0x0223: 24, 0x0224: 12, 0x0225: 12, 0x0226: 12, 0x0227: 4, 0x0228: 12,
    0x0229: 12, 0x022a: 4, 0x022b: 12, 0x022c: 12, 0x022d: 4, 0x022e: 4, 0x0230: 24, 0x0231: 40,
    0x0232: 40, 0x0233: 24, 0x0234: 4, 0x0235: 4, 0x0236: 4, 0x0240: 24, 0x0241: 100, 0x0250: 12,
    0x0251: 40, 0x0260: 40, 0x0261: 12, 0x0272: 4, 0x0273: 4, 0x0274: 40, 0x0275: 24, 0x0276: 24,
    0x0278: 4, 0x027a: 24, 0x027b: 4, 0x027c: 4, 0x027d: 4, 0x027e: 4, 0x027f: 64, 0x0300: 4,
    0x0302: 4, 0x0303: 4, 0x0304: 4, 0x0305: 12, 0x0306: 12, 0x0307: 4, 0x0308: 4, 0x0309: 4,
    0x030a: 4, 0x0310: 4, 0x0311: 4, 0x0312: 4, 0x0313: 4, 0x0314: 4, 0x03ff: 4, 0x0400: 12, 0x0401:
    24, 0x0500: 4, 0x0501: 4, 0x0502: 4, 0x0503: 4, 0x0504: 4, 0x0505: 4, 0x0506: 4, 0x0600: 24,
    0x0601: 24, 0x0602: 4, 0x0608: 4, 0x0609: 4, 0x06e0: 4, 0x06e1: 24, 0x06e2: 4, 0x06e3: 4,
    0x06e4: 4, 0x06f0: 4, 0x0700: 4, 0x0701: 4, 0x0702: 4, 0x0703: 4, 0x0800: 4, 0x0801: 4, 0x0810:
    4, 0x0811: 4, 0x0900: 4, 0x0901: 4, 0x0902: 4, 0x0a00: 4, 0x0a01: 4, 0x0f00: 12, 0x0f01: 4,
    0x0f02: 4, 0x0f03: 4, 0x0f04: 4, 0x0f05: 4, 0x8001: 24, 0x8002: 24, 0x8008: 64, 0x8009: 64,
    0x8101: 40, 0x8102: 12, 0x8103: 12, 0x8104: 4, 0x8105: 4, 0x8106: 4, 0x8107: 4, 0x8108: 12,
    0x810d: 40, 0x810e: 4, 0x8110: 40, 0x8111: 40, 0x8112: 40, 0x8113: 40, 0x8114: 40, 0x8115: 4,
    0x8116: 40, 0x8117: 40, 0x8118: 40, 0x811c: 4, 0x83ff: 4, 0x86e0: 4, 0x86f0: 4, 0xb050: 12,
    0xb051: 12, 0xb060: 12, 0xb061: 12, 0xb070: 4
}

ZERO_LEN_VER = {
    (1, 1): {
        0x0000: 4, 0x0001: 4, 0x0002: 4, 0x0008: 4, 0x0009: 64, 0x0010: 24, 0x0011: 4, 0x0012:
        4, 0x0013: 4, 0x0014: 4, 0x0015: 4, 0x0016: 4, 0x0017: 4, 0x0018: 4, 0x0019: 4, 0x001a:
        4, 0x001b: 4, 0x0020: 4, 0x0021: 4, 0x0022: 4, 0x0023: 4, 0x0024: 4, 0x0025: 4, 0x0026:
        4, 0x0027: 4, 0x0028: 4, 0x0029: 4, 0x002a: 4, 0x002b: 4, 0x002c: 4, 0x002d: 4, 0x002e:
        4, 0x002f: 4, 0x0030: 4, 0x0031: 4, 0x0032: 4, 0x0033: 4, 0x0034: 160, 0x0035: 4,
        0x0036: 4, 0x0037: 4, 0x0038: 4, 0x0101: 4, 0x0102: 4, 0x0103: 4, 0x0104: 4, 0x0105: 4,
        0x0106: 4, 0x0107: 4, 0x0108: 4, 0x0109: 4, 0x010a: 4, 0x010b: 4, 0x010c: 4, 0x010d: 64,
        0x010e: 4, 0x010f: 4, 0x0110: 4, 0x0111: 4, 0x0112: 4, 0x0113: 4, 0x0114: 4, 0x0115: 4,
        0x0116: 4, 0x0117: 4, 0x0118: 4, 0x0119: 4, 0x011a: 4, 0x011b: 4, 0x0200: 4, 0x0201: 4,
        0x0202: 4, 0x0203: 4, 0x0204: 4, 0x0206: 40, 0x0208: 4, 0x0209: 24, 0x020a: 4, 0x020b:
        4, 0x020c: 4, 0x020e: 4, 0x020f: 4, 0x0210: 4, 0x0211: 4, 0x0212: 40, 0x0213: 4, 0x0214:
        24, 0x0215: 24, 0x0216: 4, 0x0217: 4, 0x0218: 4, 0x0219: 4, 0x021a: 4, 0x021b: 4,
        0x021c: 4, 0x021d: 4, 0x021e: 4, 0x021f: 4, 0x0220: 4, 0x0221: 4, 0x0222: 4, 0x0223: 4,
        0x0224: 4, 0x0225: 4, 0x0226: 4, 0x0227: 4, 0x0228: 4, 0x0229: 4, 0x022a: 4, 0x022b: 4,
        0x022c: 4, 0x022d: 4, 0x022e: 4, 0x0230: 4, 0x0231: 4, 0x0232: 4, 0x0233: 4, 0x0234: 4,
        0x0235: 4, 0x0236: 4, 0x0240: 4, 0x0241: 4, 0x0250: 4, 0x0251: 40, 0x0260: 4, 0x0261: 4,
        0x0270: 4, 0x0271: 4, 0x0272: 4, 0x0273: 4, 0x0274: 4, 0x0275: 4, 0x0276: 4, 0x0278: 4,
        0x027a: 4, 0x027b: 4, 0x027c: 4, 0x027d: 4, 0x027e: 4, 0x027f: 64, 0x0300: 4, 0x0302: 4,
        0x0303: 4, 0x0304: 4, 0x0305: 4, 0x0306: 4, 0x0307: 4, 0x0308: 4, 0x0309: 4, 0x030a: 4,
        0x0310: 4, 0x0311: 4, 0x0312: 4, 0x0313: 4, 0x0314: 4, 0x03ff: 4, 0x0400: 4, 0x0401: 4,
        0x0500: 4, 0x0501: 4, 0x0502: 4, 0x0503: 4, 0x0504: 4, 0x0505: 4, 0x0506: 4, 0x0600: 4,
        0x0601: 4, 0x0602: 4, 0x0608: 4, 0x0609: 4, 0x06e0: 4, 0x06e1: 4, 0x06e2: 4, 0x06e3: 4,
        0x06e4: 4, 0x06f0: 4, 0x0700: 4, 0x0701: 4, 0x0702: 4, 0x0703: 4, 0x0800: 4, 0x0801: 4,
        0x0810: 4, 0x0811: 4, 0x0900: 4, 0x0901: 4, 0x0902: 4, 0x0a00: 4, 0x0a01: 4, 0x0f00: 4,
        0x0f01: 4, 0x0f02: 4, 0x0f03: 4, 0x0f04: 4, 0x0f05: 4, 0x8001: 4, 0x8002: 4, 0x8008: 4,
        0x8009: 4, 0x8101: 4, 0x8102: 4, 0x8103: 4, 0x8104: 4, 0x8105: 4, 0x8106: 4, 0x8107: 4,
        0x8108: 4, 0x810d: 40, 0x810e: 4, 0x8110: 4, 0x8111: 4, 0x8112: 4, 0x8113: 4, 0x8114: 4,
        0x8115: 4, 0x8116: 4, 0x8117: 4, 0x8118: 4, 0x811a: 4, 0x811c: 4, 0x83ff: 4, 0x86e0: 4,
        0x86f0: 4, 0xb050: 4, 0xb051: 4, 0xb060: 4, 0xb061: 4, 0xb070: 4
    },
    (1, 2): {
        0x0000: 4, 0x0001: 4, 0x0002: 4, 0x0008: 4, 0x0009: 4, 0x0010: 4, 0x0011: 4, 0x0012: 4,
        0x0013: 4, 0x0014: 4, 0x0015: 4, 0x0016: 4, 0x0017: 4, 0x0018: 4, 0x0019: 4, 0x001a: 4,
        0x001b: 4, 0x0020: 4, 0x0021: 4, 0x0022: 4, 0x0023: 4, 0x0024: 4, 0x0025: 4, 0x0026: 4,
        0x0027: 4, 0x0028: 4, 0x0029: 4, 0x002a: 4, 0x002b: 4, 0x002c: 4, 0x002d: 4, 0x002e: 4,
        0x002f: 4, 0x0030: 4, 0x0031: 4, 0x0032: 4, 0x0033: 4, 0x0034: 160, 0x0035: 4, 0x0036:
        4, 0x0037: 4, 0x0038: 4, 0x0101: 4, 0x0102: 4, 0x0103: 4, 0x0104: 4, 0x0105: 4, 0x0106:
        4, 0x0107: 4, 0x0108: 4, 0x0109: 4, 0x010a: 4, 0x010b: 4, 0x010c: 4, 0x010d: 64, 0x010e:
        4, 0x010f: 4, 0x0110: 4, 0x0111: 4, 0x0112: 4, 0x0113: 4, 0x0114: 4, 0x0115: 4, 0x0116:
        4, 0x0117: 4, 0x0118: 4, 0x0119: 4, 0x011a: 4, 0x011b: 4, 0x0200: 4, 0x0201: 4, 0x0202:
        4, 0x0204: 4, 0x0206: 40, 0x0207: 4, 0x0208: 4, 0x0209: 4, 0x020a: 4, 0x020b: 4, 0x020c:
        4, 0x020e: 4, 0x020f: 4, 0x0210: 4, 0x0211: 4, 0x0212: 4, 0x0213: 4, 0x0214: 4, 0x0215:
        4, 0x0216: 4, 0x0217: 4, 0x0218: 4, 0x0219: 4, 0x021a: 4, 0x021b: 4, 0x021c: 4, 0x021d:
        4, 0x021e: 4, 0x021f: 4, 0x0220: 4, 0x0221: 4, 0x0222: 4, 0x0223: 4, 0x0224: 4, 0x0225:
        4, 0x0226: 4, 0x0227: 4, 0x0228: 4, 0x0229: 4, 0x022a: 4, 0x022b: 4, 0x022c: 4, 0x022d:
        4, 0x022e: 4, 0x0230: 4, 0x0231: 4, 0x0232: 4, 0x0233: 4, 0x0234: 4, 0x0235: 4, 0x0236:
        4, 0x0240: 4, 0x0241: 4, 0x0250: 4, 0x0251: 4, 0x0260: 4, 0x0261: 4, 0x0270: 4, 0x0271:
        4, 0x0272: 4, 0x0273: 4, 0x0274: 4, 0x0275: 4, 0x0276: 4, 0x0277: 4, 0x0278: 4, 0x0279:
        4, 0x027a: 4, 0x027b: 4, 0x027c: 4, 0x027d: 4, 0x027e: 4, 0x027f: 4, 0x0300: 4, 0x0302:
        4, 0x0303: 4, 0x0304: 4, 0x0305: 4, 0x0306: 4, 0x0307: 4, 0x0308: 4, 0x0309: 4, 0x030a:
        4, 0x0310: 4, 0x0311: 4, 0x0312: 4, 0x0313: 4, 0x0314: 4, 0x03ff: 4, 0x0400: 4, 0x0401:
        4, 0x0500: 4, 0x0501: 4, 0x0502: 4, 0x0503: 4, 0x0504: 4, 0x0505: 4, 0x0506: 4, 0x0600:
        4, 0x0601: 4, 0x0602: 4, 0x0608: 4, 0x0609: 4, 0x06e0: 4, 0x06e1: 4, 0x06e2: 4, 0x06e3:
        4, 0x06e4: 4, 0x06f0: 4, 0x0700: 4, 0x0701: 4, 0x0702: 4, 0x0703: 4, 0x0800: 4, 0x0801:
        4, 0x0810: 4, 0x0811: 4, 0x0900: 4, 0x0901: 4, 0x0902: 4, 0x0a00: 4, 0x0a01: 4, 0x0f00:
        4, 0x0f01: 4, 0x0f02: 4, 0x0f03: 4, 0x0f04: 4, 0x0f05: 4, 0x8001: 4, 0x8002: 4, 0x8008:
        4, 0x8009: 4, 0x8101: 4, 0x8102: 4, 0x8103: 4, 0x8104: 4, 0x8105: 4, 0x8106: 4, 0x8107:
        4, 0x8108: 4, 0x810d: 40, 0x810e: 4, 0x8110: 4, 0x8111: 4, 0x8112: 4, 0x8113: 4, 0x8114:
        4, 0x8115: 4, 0x8116: 4, 0x8117: 4, 0x8118: 4, 0x811a: 4, 0x811c: 4, 0x83ff: 4, 0x86e0:
        4, 0x86f0: 4, 0xb050: 4, 0xb051: 4, 0xb060: 4, 0xb061: 4, 0xb070: 4
    },
    (2, 0): {
        0x0000: 4, 0x0001: 4, 0x0002: 4, 0x0008: 4, 0x0009: 4, 0x0010: 4, 0x0011: 4, 0x0012: 4,
        0x0013: 4, 0x0014: 4, 0x0015: 4, 0x0016: 4, 0x0017: 4, 0x0018: 4, 0x0019: 4, 0x001a: 4,
        0x001b: 4, 0x0020: 4, 0x0021: 4, 0x0022: 4, 0x0023: 4, 0x0024: 4, 0x0025: 4, 0x0026: 4,
        0x0027: 4, 0x0028: 4, 0x0029: 4, 0x002a: 4, 0x002b: 4, 0x002c: 4, 0x002d: 4, 0x002e: 4,
        0x002f: 4, 0x0030: 4, 0x0031: 4, 0x0032: 4, 0x0033: 4, 0x0035: 4, 0x0036: 4, 0x0037: 4,
        0x0038: 4, 0x0101: 4, 0x0102: 4, 0x0103: 4, 0x0104: 4, 0x0105: 4, 0x0106: 4, 0x0107: 4,
        0x0108: 4, 0x0109: 4, 0x010a: 4, 0x010b: 4, 0x010c: 4, 0x010d: 64, 0x010e: 64, 0x010f:
        4, 0x0110: 4, 0x0111: 4, 0x0112: 4, 0x0113: 4, 0x0114: 4, 0x0115: 4, 0x0116: 4, 0x0117:
        4, 0x0118: 4, 0x0119: 4, 0x011a: 4, 0x011b: 4, 0x0200: 4, 0x0201: 4, 0x0202: 4, 0x0203:
        4, 0x0204: 4, 0x0205: 4, 0x0206: 4, 0x0207: 4, 0x0208: 4, 0x0209: 4, 0x020a: 4, 0x020b:
        4, 0x020c: 4, 0x020e: 4, 0x020f: 4, 0x0210: 4, 0x0211: 4, 0x0212: 4, 0x0213: 4, 0x0214:
        4, 0x0215: 4, 0x0216: 4, 0x0217: 4, 0x0218: 4, 0x0219: 4, 0x021a: 4, 0x021b: 4, 0x021c:
        4, 0x021d: 4, 0x021e: 4, 0x021f: 4, 0x0220: 4, 0x0221: 4, 0x0222: 4, 0x0223: 4, 0x0224:
        4, 0x0225: 4, 0x0226: 4, 0x0227: 4, 0x0228: 4, 0x0229: 4, 0x022a: 4, 0x022b: 4, 0x022c:
        4, 0x022d: 4, 0x022e: 4, 0x0230: 4, 0x0231: 4, 0x0232: 4, 0x0233: 4, 0x0234: 4, 0x0235:
        4, 0x0236: 4, 0x0240: 4, 0x0241: 4, 0x0250: 4, 0x0251: 4, 0x0260: 4, 0x0261: 4, 0x0270:
        4, 0x0271: 4, 0x0272: 4, 0x0273: 4, 0x0274: 4, 0x0275: 4, 0x0276: 4, 0x0277: 4, 0x0278:
        4, 0x0279: 4, 0x027a: 4, 0x027b: 4, 0x027c: 4, 0x027d: 4, 0x027e: 4, 0x027f: 4, 0x0300:
        4, 0x0302: 4, 0x0303: 4, 0x0304: 4, 0x0305: 4, 0x0306: 4, 0x0307: 4, 0x0308: 4, 0x0309:
        4, 0x030a: 4, 0x0310: 4, 0x0311: 4, 0x0312: 4, 0x0313: 4, 0x0314: 4, 0x03ff: 4, 0x0400:
        4, 0x0401: 4, 0x0500: 4, 0x0501: 4, 0x0502: 4, 0x0503: 4, 0x0504: 4, 0x0505: 4, 0x0506:
        4, 0x0600: 4, 0x0601: 4, 0x0602: 4, 0x0608: 4, 0x0609: 4, 0x06e0: 4, 0x06e1: 4, 0x06e2:
        4, 0x06e3: 4, 0x06e4: 4, 0x06f0: 4, 0x0700: 4, 0x0701: 4, 0x0702: 4, 0x0703: 4, 0x0800:
        4, 0x0801: 4, 0x0810: 4, 0x0811: 4, 0x0900: 4, 0x0901: 4, 0x0902: 4, 0x0a00: 4, 0x0a01:
        4, 0x0f00: 4, 0x0f01: 4, 0x0f02: 4, 0x0f03: 4, 0x0f04: 4, 0x0f05: 4, 0x8001: 4, 0x8002:
        4, 0x8008: 4, 0x8009: 4, 0x8101: 4, 0x8102: 4, 0x8103: 4, 0x8104: 4, 0x8105: 4, 0x8106:
        4, 0x8107: 4, 0x8108: 4, 0x810d: 40, 0x810e: 40, 0x8110: 4, 0x8111: 4, 0x8112: 4,
        0x8113: 4, 0x8114: 4, 0x8115: 4, 0x8116: 4, 0x8117: 4, 0x8118: 4, 0x811a: 4, 0x811c: 4,
        0x83ff: 4, 0x86e0: 4, 0x86f0: 4, 0xb050: 4, 0xb051: 4, 0xb060: 4, 0xb061: 4, 0xb070: 4
    },
    (9, 9): {
        0x0000: 4, 0x0001: 4, 0x0002: 4, 0x0008: 4, 0x0009: 4, 0x0010: 4, 0x0011: 4, 0x0012: 4,
        0x0013: 4, 0x0014: 4, 0x0015: 4, 0x0016: 4, 0x0017: 4, 0x0018: 4, 0x0019: 4, 0x001a: 4,
        0x001b: 4, 0x0020: 4, 0x0021: 4, 0x0022: 4, 0x0023: 4, 0x0024: 4, 0x0025: 4, 0x0026: 4,
        0x0027: 4, 0x0028: 4, 0x0029: 4, 0x002a: 4, 0x002b: 4, 0x002c: 4, 0x002d: 4, 0x002e: 4,
        0x002f: 4, 0x0030: 4, 0x0031: 4, 0x0032: 4, 0x0033: 4, 0x0035: 4, 0x0036: 4, 0x0037: 4,
        0x0038: 4, 0x0101: 4, 0x0102: 4, 0x0103: 4, 0x0104: 4, 0x0105: 4, 0x0106: 4, 0x0107: 4,
        0x0108: 4, 0x0109: 4, 0x010a: 4, 0x010b: 4, 0x010c: 4, 0x010d: 4, 0x010e: 4, 0x010f: 4,
        0x0110: 4, 0x0111: 4, 0x0112: 4, 0x0113: 4, 0x0114: 4, 0x0115: 4, 0x0116: 4, 0x0117: 4,
        0x0118: 4, 0x0119: 4, 0x011a: 4, 0x011b: 4, 0x0200: 4, 0x0201: 4, 0x0202: 4, 0x0203: 4,
        0x0204: 4, 0x0205: 4, 0x0206: 4, 0x0207: 4, 0x0208: 4, 0x0209: 4, 0x020a: 4, 0x020b: 4,
        0x020c: 4, 0x020e: 4, 0x020f: 4, 0x0210: 4, 0x0211: 4, 0x0212: 4, 0x0213: 4, 0x0214: 4,
        0x0215: 4, 0x0216: 4, 0x0217: 4, 0x0218: 4, 0x0219: 4, 0x021a: 4, 0x021b: 4, 0x021c: 4,
        0x021d: 4, 0x021e: 4, 0x021f: 4, 0x0220: 4, 0x0221: 4, 0x0222: 4, 0x0223: 4, 0x0224: 4,
        0x0225: 4, 0x0226: 4, 0x0227: 4, 0x0228: 4, 0x0229: 4, 0x022a: 4, 0x022b: 4, 0x022c: 4,
        0x022d: 4, 0x022e: 4, 0x0230: 4, 0x0231: 4, 0x0232: 4, 0x0233: 4, 0x0234: 4, 0x0235: 4,
        0x0236: 4, 0x0240: 4, 0x0241: 4, 0x0250: 4, 0x0251: 4, 0x0260: 4, 0x0261: 4, 0x0270: 4,
        0x0271: 4, 0x0272: 4, 0x0273: 4, 0x0274: 4, 0x0275: 4, 0x0276: 4, 0x0277: 4, 0x0278: 4,
        0x0279: 4, 0x027a: 4, 0x027b: 4, 0x027c: 4, 0x027d: 4, 0x027e: 4, 0x027f: 4, 0x0300: 4,
        0x0302: 4, 0x0303: 4, 0x0304: 4, 0x0305: 4, 0x0306: 4, 0x0307: 4, 0x0308: 4, 0x0309: 4,
        0x030a: 4, 0x0310: 4, 0x0311: 4, 0x0312: 4, 0x0313: 4, 0x0314: 4, 0x03ff: 4, 0x0400: 4,
        0x0401: 4, 0x0500: 4, 0x0501: 4, 0x0502: 4, 0x0503: 4, 0x0504: 4, 0x0505: 4, 0x0506: 4,
        0x0600: 4, 0x0601: 4, 0x0602: 4, 0x0608: 4, 0x0609: 4, 0x06e0: 4, 0x06e1: 4, 0x06e2: 4,
        0x06e3: 4, 0x06e4: 4, 0x06f0: 4, 0x0700: 4, 0x0701: 4, 0x0702: 4, 0x0703: 4, 0x0800: 4,
        0x0801: 4, 0x0810: 4, 0x0811: 4, 0x0900: 4, 0x0901: 4, 0x0902: 4, 0x0a00: 4, 0x0a01: 4,
        0x0f00: 4, 0x0f01: 4, 0x0f02: 4, 0x0f03: 4, 0x0f04: 4, 0x0f05: 4, 0x8001: 4, 0x8002: 4,
        0x8008: 4, 0x8009: 4, 0x8101: 4, 0x8102: 4, 0x8103: 4, 0x8104: 4, 0x8105: 4, 0x8106: 4,
        0x8107: 4, 0x8108: 4, 0x810d: 4, 0x810e: 4, 0x8110: 4, 0x8111: 4, 0x8112: 4, 0x8113: 4,
        0x8114: 4, 0x8115: 4, 0x8116: 4, 0x8117: 4, 0x8118: 4, 0x811a: 4, 0x811c: 4, 0x83ff: 4,
        0x86e0: 4, 0x86f0: 4, 0xb050: 4, 0xb051: 4, 0xb060: 4, 0xb061: 4, 0xb070: 4
    },
}


def block(btype, body, vh=1, vl=0, blen=None):
    if blen is None:
        blen = len(body) + 2
    return struct.pack('>HHBB', btype, blen, vh, vl) + body


def rta_pdu(blk, pdu_type=1, dst_ep=0x8000, src_ep=0x8001, seq=1, ack=0xffff, wsize=1, tack=1, ver=1):
    return (struct.pack('>HHBBHHH', dst_ep, src_ep, (ver << 4) | pdu_type, (tack << 4) | wsize, seq, ack, len(blk))
            + blk)


def rta(blk, fid=0xfe01, dst=MAC_G, src=MAC_F, **kw):
    return rt(fid, rta_pdu(blk, **kw), dst, src)


def zero_block_frames():
    for t, n in sorted(ZERO_LEN.items()):
        emit(rta(block(t, bytes(n))))
    # the same blocks with other versions: the versions a dissector knows and the ones it rejects
    for ver, table in sorted(ZERO_LEN_VER.items()):
        for t, n in sorted(table.items()):
            emit(rta(block(t, bytes(n), ver[0], ver[1])))


# ----------------------------------------------------- PN-IO over DCE/RPC
def u8(x): return bytes([x])
def u16(x): return struct.pack('>H', x)
def u32(x): return struct.pack('>I', x)
def u64(x): return struct.pack('>Q', x)
def pstr(b): return u16(len(b)) + b
def G(s): return uuid.UUID(s).bytes
NIL = bytes(16)

IF_DEV = uuid.UUID('dea00001-6c97-11d1-8271-00a02442df7d')
IF_CTL = uuid.UUID('dea00002-6c97-11d1-8271-00a02442df7d')
IF_SUP = uuid.UUID('dea00003-6c97-11d1-8271-00a02442df7d')
IF_PRM = uuid.UUID('dea00004-6c97-11d1-8271-00a02442df7d')
OBJ_UUID = uuid.UUID('dea00000-6c97-11d1-8271-00010000002a')

AR1 = G('11111111-2222-3333-4444-555555555501')
AR2 = G('11111111-2222-3333-4444-555555555502')
AR3 = G('11111111-2222-3333-4444-555555555503')

RPC_STATE = {'seq': 0, 'act': 0}


def dcerpc_dg(ptype, opnum, seq, body, act, if_uuid=IF_DEV, flags1=None):
    if flags1 is None:
        flags1 = 0x20 if ptype == 0 else 0x00
    hdr = struct.pack('<BBBB', 4, ptype, flags1, 0)
    hdr += bytes([0x10, 0, 0]) + b'\0'
    hdr += OBJ_UUID.bytes_le
    hdr += if_uuid.bytes_le
    hdr += act
    hdr += struct.pack('<IIIHHHHHBB', 0, 1, seq, opnum, 0xffff, 0xffff, len(body), 0, 0, 0)
    return hdr + body


def ndr_rqst(blocks, maxlen=None):
    n = len(blocks)
    return struct.pack('<IIIII', maxlen if maxlen is not None else n + 64, n, n + 64, 0, n) + blocks


def ndr_resp(blocks, status=bytes(4)):
    n = len(blocks)
    return status + struct.pack('<IIII', n, n + 64, 0, n) + blocks


def rpc_pair(opnum, req_blocks, resp_blocks, status=bytes(4), dev=MAC_C, ctl=MAC_A, if_uuid=IF_DEV,
             sport=49152, req_extra=b'', resp_extra=b'', respond=True):
    RPC_STATE['seq'] += 1
    seq = RPC_STATE['seq']
    act = struct.pack('<IHH8s', 0x70000000 + seq, 0x1234, 0x5678, bytes(8))
    emit(udp_frame(dcerpc_dg(0, opnum, seq, ndr_rqst(req_blocks), act, if_uuid), sport, 34964,
                   '192.0.2.1', '192.0.2.2', dev, ctl))
    if respond:
        emit(udp_frame(dcerpc_dg(2, opnum, seq, ndr_resp(resp_blocks, status), act, if_uuid), 34964, sport,
                       '192.0.2.2', '192.0.2.1', ctl, dev))


# --- blocks (all big endian inside a block) -------------------------------
def B(t, body, vh=1, vl=0):
    return block(t, body, vh, vl)


def ar_block_req(aruuid=AR1, artype=1, props=0x00000111, name=b'dev-1', mac=MAC_A, objuuid=None, sk=1):
    return B(0x0101, u16(artype) + aruuid + u16(sk) + mac + (objuuid or G('dea00000-6c97-11d1-8271-00010000002a'))
             + u32(props) + u16(600) + u16(0x8892) + pstr(name))


def iocr_block_req(typ=1, ref=1, frameid=0x8000, objs=((0, 1, 0), (1, 1, 1)), iocs=((0, 1, 2),), api=0,
                   props=0x00000001, datalen=40, mac=bytes(6), sc=32, rr=32, phase=1, seq=0, sendoff=0xffffffff,
                   napis=None, lt=0x8892):
    b = u16(typ) + u16(ref) + u16(lt) + u32(props) + u16(datalen) + u16(frameid) + u16(sc) + u16(rr) + u16(phase)
    b += u16(seq) + u32(sendoff) + u16(3) + u16(3) + u16(0xc000) + mac
    apis = [(api, objs, iocs)] if napis is None else napis
    b += u16(len(apis))
    for a, o, c in apis:
        b += u32(a) + u16(len(o)) + b''.join(u16(x) + u16(y) + u16(z) for x, y, z in o)
        b += u16(len(c)) + b''.join(u16(x) + u16(y) + u16(z) for x, y, z in c)
    return B(0x0102, b)


def alarm_cr_req(typ=1, props=0, ref=1):
    return B(0x0103, u16(typ) + u16(0x8892) + u32(props) + u16(1) + u16(3) + u16(ref) + u16(200) + u16(0xc000) + u16(0xa000))


def data_desc(kind, length, iocs=1, iops=1):
    return u16(kind) + u16(length) + u8(iocs) + u8(iops)


def expected_submod_req(apis):
    # apis: [(api, slot, ident, props, [(subslot, ident, props, [descs])])]
    b = u16(len(apis))
    for api, slot, ident, mprops, subs in apis:
        b += u32(api) + u16(slot) + u32(ident) + u16(mprops) + u16(len(subs))
        for sub, sident, sprops, descs in subs:
            b += u16(sub) + u32(sident) + u16(sprops) + b''.join(descs)
    return B(0x0104, b)


def ar_block_res(aruuid=AR1, artype=1, sk=1, mac=MAC_B):
    return B(0x8101, u16(artype) + aruuid + u16(sk) + mac + u16(0x8892))


def iocr_block_res(typ, ref, frameid):
    return B(0x8102, u16(typ) + u16(ref) + u16(frameid))


def alarm_cr_res(typ=1, ref=2):
    return B(0x8103, u16(typ) + u16(ref) + u16(200))


def module_diff(apis):
    # apis: [(api, [(slot, ident, state, [(subslot, ident, state)])])]
    b = u16(len(apis))
    for api, mods in apis:
        b += u32(api) + u16(len(mods))
        for slot, ident, state, subs in mods:
            b += u16(slot) + u32(ident) + u16(state) + u16(len(subs))
            for sub, sident, sstate in subs:
                b += u16(sub) + u32(sident) + u16(sstate)
    return B(0x8104, b)


def control_block(t, aruuid, command, sk=1, alarmseq=0, props=0):
    return B(t, u16(0) + aruuid + u16(sk) + u16(alarmseq) + u16(command) + u16(props))


def rw_header(t, idx, aruuid=AR1, api=0, slot=1, subslot=1, seq=1, reclen=0, extra=b'', vl=0):
    return B(t, u16(seq) + aruuid + u32(api) + u16(slot) + u16(subslot) + u16(0) + u16(idx) + u32(reclen) + extra, 1, vl)


def write_req_hdr(idx, data, **kw):
    return rw_header(0x0008, idx, reclen=len(data), extra=bytes(24), **kw) + data


def write_res_hdr(idx, reclen=0, status=bytes(4), addval1=0, addval2=0, **kw):
    return rw_header(0x8008, idx, reclen=reclen, extra=u16(addval1) + u16(addval2) + status + bytes(16), **kw)


def read_req_hdr(idx, reclen=0x1000, aruuid=AR1, **kw):
    return rw_header(0x0009, idx, aruuid=aruuid, reclen=reclen, extra=(bytes(24) if aruuid != NIL else NIL + bytes(8)), **kw)


def read_res_hdr(idx, data, **kw):
    return rw_header(0x8009, idx, reclen=len(data), extra=u16(0) + u16(0) + bytes(20), **kw) + data


def pn_connect_sequence(ar=AR1, dev=MAC_B, ctl=MAC_A, in_frame=0x8001, out_frame=0x8002, name=b'dev-1', sport=49152):
    """Connect, ParameterEnd, ApplicationReady, Release of one AR."""
    mods = [
        (0, 0, 0x00000001, 0, [(1, 0x00000101, 0, [data_desc(1, 0, 1, 1)]),
                               (0x8000, 0x00000201, 0, [data_desc(1, 0, 1, 1)])]),
        (1, 1, 0x00000020, 0, [(1, 0x00000301, 0x0001, [data_desc(1, 4, 1, 1)])]),
        (1, 2, 0x00000021, 0, [(1, 0x00000302, 0x0002, [data_desc(2, 2, 1, 1)])]),
        (1, 3, 0x00000022, 0, [(1, 0x00000303, 0x0023, [data_desc(1, 2, 1, 1), data_desc(2, 1, 1, 1)])]),
    ]
    req = (ar_block_req(ar, name=name, mac=ctl) +
           iocr_block_req(1, 1, in_frame, objs=((0, 1, 0), (0, 0x8000, 1), (1, 1, 2), (3, 1, 7)),
                          iocs=((2, 1, 10), (3, 1, 11)), datalen=40) +
           iocr_block_req(2, 2, out_frame, objs=((2, 1, 0), (3, 1, 3)),
                          iocs=((0, 1, 5), (0, 0x8000, 6), (1, 1, 7), (3, 1, 8)), datalen=40) +
           alarm_cr_req() + expected_submod_req(mods))
    resp = (ar_block_res(ar, mac=dev) + iocr_block_res(1, 1, in_frame) + iocr_block_res(2, 2, out_frame) +
            alarm_cr_res() + module_diff([(0, [(2, 0x00000021, 1, [(1, 0x00000302, 0)])])]))
    rpc_pair(0, req, resp, dev=dev, ctl=ctl, sport=sport)
    # Parameter end / application ready / release
    rpc_pair(4, control_block(0x0110, ar, 0x0001), control_block(0x8110, ar, 0x0001), dev=dev, ctl=ctl, sport=sport,
             if_uuid=IF_DEV)
    rpc_pair(4, control_block(0x0111, ar, 0x0002, alarmseq=3, props=0x0001),
             control_block(0x8111, ar, 0x0002, alarmseq=3, props=0x0001), dev=ctl, ctl=dev, sport=sport, if_uuid=IF_CTL)


IDX_SINGLE_WRITE = [0x8020, 0x801e, 0x802b, 0x802c, 0x802d, 0x802e, 0x802f, 0x8030, 0x8031, 0x8051, 0x8052,
                    0x8053, 0x8055, 0x8056, 0x8061, 0x8062, 0x8063, 0x8070, 0x8071, 0x8090, 0x80a0, 0x80b0,
                    0x80cf, 0x8200, 0x8201, 0x8202, 0x8203, 0x8204, 0x8205, 0x8206, 0x8207, 0x8208, 0x8209,
                    0x8210, 0x8211, 0xaff1, 0xaff2, 0xaff3, 0xe050, 0xe061]
IDX_SINGLE_READ = [0x8010, 0x8011, 0x8012, 0x8013, 0x801e, 0x8020, 0x8027, 0x8028, 0x8029, 0x8050, 0x8051, 0x8052,
                   0x8053, 0x8054, 0x8060, 0x8061, 0x8062, 0x8063, 0x8070, 0x8071, 0x8080, 0x8090, 0x80a0, 0x80af,
                   0x80cf, 0x80f0, 0x80f2, 0x80f3, 0x80f4, 0x80f5, 0x8200, 0x8201, 0x8202, 0x8203, 0x8204, 0x8205,
                   0x8206, 0x8207, 0x8208, 0x8209, 0x8210, 0x8211] + list(range(0xaff0, 0x10000)) [:16] + [
                   0xc010, 0xc011, 0xc012, 0xc013, 0xe002, 0xe010, 0xe011, 0xe012, 0xe013, 0xe030, 0xe031,
                   0xf010, 0xf011, 0xf012, 0xf013, 0xf020, 0xf820, 0xf821, 0xf830, 0xf831, 0xf870, 0xf871, 0xf880,
                   0xf8f1, 0xf902, 0xf904, 0xb050, 0xb051, 0xb060, 0xb061]
IDX_MULTI_READ = [0x8000, 0x8001, 0x800a, 0x800b, 0x800c, 0x802a, 0x802b, 0x802d, 0x802e, 0x802f, 0x8030, 0x8031,
                  0x8032, 0x803f, 0x8040, 0x804f, 0x8055, 0x8056, 0x8057, 0x8072, 0xc000, 0xc001, 0xc00a, 0xc00b,
                  0xc00c, 0xe000, 0xe001, 0xe00a, 0xe00b, 0xe00c, 0xe060, 0xf000, 0xf00a, 0xf00b, 0xf00c, 0xf80c,
                  0xf841, 0xf842]


def zblock(t, vh=1, vl=0):
    return B(t, bytes(ZERO_LEN[t]), vh, vl)


def pn_rw_frames(ar=AR1, dev=MAC_C, ctl=MAC_A, sport=49153):
    iandm0 = zblock(0x0020)
    for idx in IDX_SINGLE_WRITE:
        data = iandm0
        rpc_pair(3, write_req_hdr(idx, data, aruuid=ar), write_res_hdr(idx, aruuid=ar), dev=dev, ctl=ctl, sport=sport)
    for idx in sorted(set(IDX_SINGLE_READ)):
        rpc_pair(2, read_req_hdr(idx, aruuid=ar), read_res_hdr(idx, iandm0, aruuid=ar), dev=dev, ctl=ctl, sport=sport)
    for idx in IDX_MULTI_READ:
        rpc_pair(2, read_req_hdr(idx, aruuid=ar), read_res_hdr(idx, iandm0 + zblock(0x0021), aruuid=ar),
                 dev=dev, ctl=ctl, sport=sport)


def cyclic(fid, payload, cyc, status=0x35, trans=0, src=MAC_B, dst=MAC_A, vlan=None):
    payload = payload + bytes(max(0, 40 - len(payload)))     # an Ethernet frame has at least 60 octets
    return rt(fid, payload + u16(cyc) + bytes([status, trans]), dst, src, vlan)


def pn_cyclic_frames(in_frame=0x8001, out_frame=0x8002, dev=MAC_B, ctl=MAC_A):
    inp = bytes([0x80, 0x80]) + bytes([1, 2, 3, 4, 0x80]) + bytes([5, 6, 0x80]) + bytes([0x80, 0x80]) + bytes(28)
    outp = bytes([7, 8, 0x80]) + bytes([9, 0x80]) + bytes([0x80, 0x80, 0x80, 0x80]) + bytes(31)
    for i, st in enumerate((0x35, 0x34, 0x15, 0x37, 0xb5)):
        emit(cyclic(in_frame, inp[:40], 100 + i, st, src=dev, dst=ctl))
        emit(cyclic(out_frame, outp[:40], 100 + i, st, src=ctl, dst=dev))


def pn_frames():
    pn_connect_sequence()
    pn_cyclic_frames()
    # Read and Write records on another pair of stations: the "heuristic extraction" of PN-IO objects keeps a
    # global list of the station pairs seen in Read/Write blocks, which a one pass dissection of cyclic
    # frames that came earlier in the file does not know yet (see README, observations)
    pn_rw_frames(dev=MAC_C, ctl=MAC_A)


# ------------------------------------------------- alarms, RS, PE, AR data
def alarm_hdr(atype=1, api=0, slot=1, subslot=1):
    return u16(atype) + u32(api) + u16(slot) + u16(subslot)


def alarm_spec(seq=1, ch=1, manuf=0, sub=1, ar=0):
    return u16((ar << 15) | (sub << 13) | (manuf << 12) | (ch << 11) | seq)


def alarm_notification(atype, usis, low=True, modid=0x20, submodid=0x301, spec=None):
    body = alarm_hdr(atype) + u32(modid) + u32(submodid) + (spec if spec is not None else alarm_spec())
    for usi, data in usis:
        body += u16(usi) + data
    return B(0x0002 if low else 0x0001, body)


def chan_diag(ch=1, props=0x0800, etype=1):
    return u16(ch) + u16(props) + u16(etype)


def ext_chan_diag(ch=1, props=0x0800, etype=1, ext=1, add=0x1234):
    return chan_diag(ch, props, etype) + u16(ext) + u32(add)


def qual_chan_diag(ch=1, props=0x0800, etype=1, ext=1, add=0x1234, qual=0x00000002):
    return ext_chan_diag(ch, props, etype, ext, add) + u32(qual)


def rs_common(spec=0x0001, ts_status=0, minus=0, plus=0):
    return (G('aabbccdd-0011-2233-4455-66778899aabb') + u32(0) + u16(1) + u16(2) + u16(3) + u16(spec) +
            u16(ts_status) + (1700000000).to_bytes(6, 'big') + u32(123456) + u16(minus) + u16(plus))


def rs_event_block(btype, exts, ver=(1, 0)):
    body = rs_common()
    for et, data in exts:
        body += u8(et) + u8(len(data)) + data
    body += b''
    return u16(btype) + u16(len(body) + 4) + bytes(ver) + bytes(2) + body


def rs_event_info(blocks):
    return u16(len(blocks)) + b''.join(blocks)


def rs_frames():
    ident = u64(1) + u64(2) + u64(3) + u64(4) + bytes(32) + bytes(22)
    ts12 = u16(0x0005) + (1700000001).to_bytes(6, 'big') + u32(5)
    blocks = [
        rs_event_block(0x4000, [(1, u16(0x4000) + u32(0x00000001))]),
        rs_event_block(0x4001, [(1, b'\x01\x02\x03\x04')]),
        rs_event_block(0x4002, [(1, bytes(2) + bytes(16) + bytes(8))]),
        rs_event_block(0x4002, [(1, bytes(2) + bytes(16) + bytes(8) + ts12)]),
        rs_event_block(0x4003, [(1, b'\x05\x06')]),
        rs_event_block(0x4004, [(1, ident[:len(ident)])]),
        rs_event_block(0x4010, [(1, u16(0x8001))]),
        rs_event_block(0x7000, [(1, b'\xaa\xbb\xcc')]),
        rs_event_block(0x0001, []),
    ]
    for b in blocks:
        emit(rta(alarm_notification(1, [(0x8303, rs_event_info([b]))])))
    emit(rta(alarm_notification(1, [(0x8303, rs_event_info(blocks[:3]))], low=False), fid=0xfc01))
    for usi in (0x8300, 0x8301, 0x8302):
        emit(rta(alarm_notification(2, [(usi, u16(0x0001))])))


def alarm_frames():
    types = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 32, 33, 0x7f)
    for t in types:
        emit(rta(alarm_notification(t, [(0x8000, chan_diag(1, 0x0800, 3))]), fid=0xfe01))
    for et in (0x0001, 0x7ffe, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8007, 0x8008, 0x8009, 0x800a,
               0x800b, 0x800c, 0x8010, 0x8011, 0x9000):
        emit(rta(alarm_notification(1, [(0x8002, ext_chan_diag(2, 0x0a10, et, 0x0003, 0x11))]), fid=0xfc01))
    emit(rta(alarm_notification(1, [(0x8003, qual_chan_diag()), (0x8000, chan_diag()), (0x8002, ext_chan_diag())],
                                low=False)))
    emit(rta(alarm_notification(1, [(0x8100, B(0x0f00, bytes(2) + u32(0x00000003)))])))
    emit(rta(alarm_notification(1, [(0x8100, B(0x0f00, bytes(2) + u32(0x00000001)))])))
    emit(rta(alarm_notification(1, [(0x8100, B(0x0f00, bytes(2) + u32(0x00000002)))])))
    emit(rta(alarm_notification(1, [(0x8310, B(0x0f05, bytes([3])))])))
    emit(rta(alarm_notification(1, [(0x8320, u16(5) + u16(0x0001) + u16(2) + u16(3) + b'\x01\x02\x03\x04')])))
    emit(rta(alarm_notification(1, [(0x8320, u16(5) + u16(0x0002) + u16(2) + u16(3))])))
    emit(rta(alarm_notification(1, [(0x8320, b'\x01\x02\x03\x04\x05\x06')])))
    emit(rta(alarm_notification(1, [(0x8001, b'\x01\x02\x03\x04')])))
    emit(rta(alarm_notification(1, [(0x0042, b'\x01\x02\x03\x04\x05\x06\x07\x08')])))
    # alarm acknowledge
    for t in (0x8001, 0x8002):
        emit(rta(B(t, alarm_hdr() + alarm_spec() + bytes(4)), fid=0xfe01 if t == 0x8002 else 0xfc01))
    # DiagnosisData read records (version 1.0 and 1.1)
    emit(rta(B(0x0010, u16(0x0001) + u16(0x0800) + u16(0x8000) + chan_diag(1, 0x0800, 1))))
    emit(rta(B(0x0010, u32(0) + u16(1) + u16(1) + u16(0x0001) + u16(0x0800) + u16(0x8000) + chan_diag(1, 0x0800, 1), 1, 1)))
    emit(rta(B(0x0010, u32(0) + u16(1) + u16(1) + u16(0x8000) + u16(0x0800) + u16(0x1234) + b'\x01\x02', 1, 1)))
    emit(rta(B(0x0010, u32(0) + u16(1) + u16(1) + u16(0x8000) + u16(0x0800) + u16(0x8002) + ext_chan_diag(), 1, 1)))
    # alarm PDUs without data
    for pt in (2, 3):
        emit(rta(b'', pdu_type=pt))
    emit(rta(bytes([0, 0, 0, 0]), pdu_type=4))
    emit(rta(bytes([0xde, 0x81, 0x40, 0x09]), pdu_type=4))
    emit(rta(b'', pdu_type=3, fid=0xfc01))


# -------------------------------------------------------------- PROFIenergy
def pe_req(rid, mod, data=b'', ref=1, struct_id=0):
    return B(0x0800, bytes([rid, ref, mod, struct_id]) + data)


def pe_res(rid, struct_id, data=b'', ref=1, status=0):
    return B(0x0801, bytes([rid, ref, status, struct_id]) + data)


def pe_frames():
    f64 = bytes(8)
    reqs = [
        pe_req(0x01, 0x00, u32(5000)), pe_req(0x01, 0x01, u32(6000)),
        pe_req(0x03, 0x02, bytes([1, 0])),
        pe_req(0x10, 0x02, bytes([2, 0]) + u16(1) + u16(2)),
        pe_req(0x10, 0x04, bytes([2, 0]) + u16(1) + u16(2) + u16(0) + u16(3)),
        pe_req(0x11, 0x00, u16(0) + u16(0)), pe_req(0x11, 0x01, u16(0) + u16(7)),
        pe_req(0x11, 0x02, u16(2) + u16(0)), pe_req(0x11, 0x03, u16(2) + u16(7)),
        pe_req(0x12, 0x00, bytes([3, 0]) + u16(1) + u16(210) + f64 + u16(1) + u16(225) + u32(5) + u16(1) + u16(5) + u32(6)),
        pe_req(0x21, 0x01, u32(1000)),
        pe_req(0x05, 0x00, b'\x01\x02\x03\x04'),
        pe_req(0x05, 0x00, b''),
    ]
    for r in reqs:
        emit(rta(r))
    mode = lambda i: bytes([i, 1]) + bytes([1, 0]) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6) + u32(7) + u32(8)
    ress = [
        pe_res(0x01, 0x01, bytes([1, 0])),
        pe_res(0x01, 0x03, bytes([1, 0]) + u32(1) + u32(2) + u32(3)),
        pe_res(0x01, 0x02, bytes([1, 0]) + u32(1) + u32(2) + u32(3)),
        pe_res(0x02, 0x01, u32(5)),
        pe_res(0x03, 0x01, bytes([1, 0]) + bytes([1, 0, 1, 0]) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6) + u32(7) + u32(8)),
        pe_res(0x03, 0x02, bytes([2, 1]) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6) + u32(7) + u32(8)),
        pe_res(0x03, 0x07, b'\x01\x02\x03\x04'),
        pe_res(0x04, 0x01, bytes([1, 2]) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5)),
        pe_res(0x04, 0x02, bytes([1, 2]) + u32(1) + u32(2) + u32(3) + u32(4) + u32(5) + u32(6)),
        pe_res(0x04, 0x05, b'\x01\x02\x03\x04'),
        pe_res(0x05, 0x01, bytes([3, 0]) + bytes([1, 2, 3, 0])),
        pe_res(0x06, 0x01, bytes([1, 2])),
        pe_res(0x07, 0x01, bytes([1, 2, 3, 4, 5, 6, 0, 0]) + u32(1000)),
        pe_res(0x10, 0x02, bytes([2, 0]) + u16(1) + bytes([1, 2]) + u32(3) + u16(2) + bytes([1, 2]) + u32(4)),
        pe_res(0x10, 0x04, bytes([2, 0]) + u16(0) + u16(1) + bytes([1, 2]) + u32(3) + u16(0) + u16(2) + bytes([1, 2]) + u32(4)),
        pe_res(0x10, 0x01, bytes([3, 0]) + u16(10) + u8(1) + u16(1) + u8(0) + u32(7) +
               u16(14) + u8(1) + u16(210) + u8(0) + f64 + u16(22) + u8(1) + u16(225) + u8(0) + u32(8) + bytes(12)),
        pe_res(0x10, 0x03, bytes([2, 0]) + u16(12) + u8(2) + u8(0) + u16(1) + u16(1) + u32(7) +
               u16(16) + u8(2) + u8(0) + u16(1) + u16(210) + f64),
        pe_res(0x12, 0x01, bytes([2, 0]) + u16(1) + u16(2) + u16(3) + u16(4)),
        pe_res(0x20, 0x01, u32(1) + u32(2) + bytes([1]) + u16(4) + b'\xaa\xbb\xcc\xdd'),
        pe_res(0x21, 0x01, bytes([1, 0]) + u32(1) + u32(2) + u32(3)),
        pe_res(0x55, 0x01, b'\x01\x02\x03\x04'),
        pe_res(0x01, 0xff, bytes([0x12, 0])),
        pe_res(0x03, 0xff, bytes([0x12, 0])),
    ]
    for r in ress:
        emit(rta(r))
    # entity filter / status (with a module and submodule)
    emit(rta(B(0x0810, u16(1) + u32(0) + u16(2) + u16(1) + u32(0x20) + u16(2) + u16(1) + u32(0x301) + u16(2) + u32(0x302)
               + u16(2) + u32(0x21) + u16(0))))
    emit(rta(B(0x0811, u16(1) + u32(0) + u16(2) + u16(1) + u16(2) + u16(1) + bytes([2, 0]) + u16(2) + bytes([1, 0])
               + u16(2) + u16(0))))
    # PE via Write and Read records
    iandm0 = zblock(0x0020)
    rpc_pair(3, write_req_hdr(0x80a0, pe_req(0x10, 0x02, bytes([1, 0]) + u16(1))), write_res_hdr(0x80a0))
    rpc_pair(2, read_req_hdr(0x80a0), read_res_hdr(0x80a0, pe_res(0x10, 0x02, bytes([1, 0]) + u16(1) + bytes([1, 2]) + u32(3))))


# ------------------------------------------------- record data blocks (read)
def iocr_props(rt_class=1):
    return u32(rt_class)


def ar_data_block(vl=0):
    nm = b'ctrl-1'
    if vl == 0:
        one = (AR1 + u16(1) + u32(0x111) + G('dea00000-6c97-11d1-8271-00010000002a') + pstr(nm) + u16(2) +
               u16(1) + iocr_props() + u16(0x8001) + u16(5) + bytes([0x35, 0]) + u16(0x8892) + u16(0x8893) +
               u16(2) + iocr_props(2) + u16(0x8002) + u16(6) + bytes([0x34, 1]) + u16(0x8892) + u16(0x8893) +
               u16(1) + u16(1) + u16(2) + G('dea00000-6c97-11d1-8271-00010000002b') + pstr(b'prm') + u16(2) +
               u32(0) + u32(1))
        return B(0x0018, u16(2) + one + one[:0] + (AR2 + one[16:]))
    one = (AR1 + G('dea00000-6c97-11d1-8271-00010000002a') + G('dea00000-6c97-11d1-8271-00010000002b') +
           u32(0x111) + u16(1) + u16(1) + u16(1) + u16(2) + u16(0x8892) + u16(0x8893) + pstr(nm))
    one += bytes((-len(one)) % 4)
    one += pstr(b'')
    one += bytes((-len(one)) % 4)
    one += u16(1) + bytes(2)
    one += (iocr_props() + u16(1) + u16(0x8001) + u16(5) + bytes([0x35, 0x01]))
    one += u16(1) + bytes(2) + u32(0) + u16(1) + bytes(2) + zblock(0x0020)
    return B(0x0018, u16(1) + one, 1, 1)


def record_frames():
    iandm0 = zblock(0x0020)
    L = []
    L.append(ar_data_block(0))
    L.append(ar_data_block(1))
    L.append(B(0x001a, u16(2) + u32(0) + u32(1)))
    L.append(B(0x0019, u64(1700000000) + u16(2) + u64(5) + AR1 + bytes(4) + u32(7) + u64(6) + AR2 + bytes([0xde, 0x81, 0x40, 0x03]) + u32(8)))
    L.append(B(0x0012, u16(1) + u32(0) + u16(2) + u16(1) + u32(0x20) + u16(2) + u16(1) + u32(0x301) + u16(2) + u32(0x302)
               + u16(2) + u32(0x21) + u16(0)))
    L.append(B(0x0013, u16(1) + u32(0) + u16(1) + u16(1) + u32(0x20) + u16(1) + u16(1) + u32(0x301), 1, 0))
    L.append(B(0x0013, u16(1) + u32(0) + u16(1) + u16(1) + u32(0x20) + u16(1) + u16(1) + u32(0x301), 1, 1))
    L.append(B(0x0014, u16(1) + bytes([0x80, 0x80]) + b'\x01'))
    for t in (0x0030, 0x0031, 0x0032):
        L.append(B(t, u16(1) + u32(0) + u16(2) + u16(1) + u32(0x20) + u16(2) + u16(1) + u32(0x301) + u16(2) + u32(0x302)
                   + u16(2) + u32(0x21) + u16(0)))
    for st in (1, 2):
        L.append(B(0x0036, bytes(2) + AR1 + bytes(15) + bytes([st]) + bytes(64 * 4) + bytes(16) + b'V' + bytes([1, 2, 3]) +
                   bytes(32) + u16(1) + u16(2) + bytes(2)))
    L.append(B(0x0034, bytes(64) + bytes(64) + bytes([0, 42]) + bytes(16) + u16(1) + b'V' + bytes([1, 2, 3])))
    L.append(B(0x0035, u16(1) + u16(1) + B(0x0034, bytes(64) + bytes(64) + bytes([0, 42]) + bytes(16) + u16(1) + b'V' + bytes([1, 2, 3]))))
    L.append(B(0x0025, u16(1) + B(0x0034, bytes(64) + bytes(64) + bytes([0, 42]) + bytes(16) + u16(1) + b'V' + bytes([1, 2, 3]))))
    L.append(B(0x0024, bytes(54)))
    L.append(B(0x0119, u16(2) + u32(0) + u16(1) + u16(1) + u32(0) + u16(2) + u16(1)))
    L.append(B(0x011b, bytes(2) + AR1))
    L.append(B(0x0f00, bytes(2) + u32(3)))
    for b in L:
        emit(rta(b))


def p_frames_more():
    pass


# ------------------------------------------- PN-RT: ids, DFP, FRAG, RSI, secure
def crc16(data, crc=0):
    # CRC-16/ARC: the plain CRC16 of the dissector (poly 0x8005 reflected, init 0)
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xa001 if crc & 1 else 0)
    return crc & 0xffff


def dfp_frame(fid, subs, src=MAC_B, dst=MAC_A, first_crc=True, cycle=77, sf_crc='ok'):
    """DFP / CSF_SDU frame: first CRC over a virtual frame header, then subframes."""
    virt = dst + src + b'\x88\x92' + be16(fid)
    body = struct.pack('<H', crc16(virt) if first_crc else 0)
    for pos, data in subs:
        sub = bytes([pos, len(data), 7, 0x35]) + data
        if sf_crc == 'ok':
            c = crc16(sub)
        elif sf_crc == 'nocrc':
            c = 0
        elif sf_crc == 'badhi':
            c = 0x1234 if pos & 0x80 else crc16(sub)
        else:   # badlo: a wrong CRC where the dissector does not check it while sniffing
            c = 0x1234 if not pos & 0x80 else crc16(sub)
        body += sub + struct.pack('<H', c)
    body += bytes([0, 0])
    return cyclic(fid, body, cycle, src=src, dst=dst)


def rt_misc_frames():
    # the frame ID ranges of PN-RT, cyclic and acyclic
    pay = bytes(range(1, 21))
    for fid in (0x0000, 0x0010, 0x001f, 0x0022, 0x0050, 0x007f, 0x0082, 0x00c0, 0x00ff, 0x0100, 0x0200, 0x06ff,
                0x0700, 0x0900, 0x0fff, 0x1000, 0x1500, 0x2fff, 0x3000, 0x37ff, 0x3800, 0x3bff, 0x3c00, 0x3fff,
                0x4000, 0x5000, 0x7fff, 0x8000, 0x9000, 0xbbff, 0xbc00, 0xbd00, 0xbfff, 0xc000, 0xd000, 0xf7ff,
                0xf800, 0xfa00, 0xfbff, 0xfc00, 0xfd00, 0xfdff, 0xfe00, 0xfe04, 0xff02, 0xff1f, 0xff22,
                0xff44, 0xff5f, 0xff7f, 0xff90, 0xffff):
        emit(cyclic(fid, pay, 1000 + fid % 7, 0x35 if fid & 1 else 0x04, src=MAC_C, dst=MAC_A))
    # data status variants (frame info type fields of the input/output meaning)
    for st in range(0, 256, 17):
        emit(cyclic(0x8c00, pay, 5, st, trans=st & 1, src=MAC_C, dst=MAC_A))
    # UDP: cyclic frames in the PROFINET UDP range
    for fid in (0xc001, 0xf000, 0xf900):
        emit(udp_frame(be16(fid) + pay + u16(9) + bytes([0x35, 0]), 34962, 34962, dst=MAC_C, src=MAC_A))
    # VLAN-tagged cyclic frame
    emit(cyclic(0xc000, pay, 3, vlan=0xc000, src=MAC_C, dst=MAC_A))
    # DFP frames
    for fid in (0x8800, 0x8801, 0x1a00, 0x2000):
        emit(dfp_frame(fid, [(0x80, b'\x01\x02\x03'), (0x01, b'abcd'), (0x82, b'')]))
    emit(dfp_frame(0x8802, [(0x81, b'\x09\x08')], first_crc=False, sf_crc='nocrc'))
    emit(dfp_frame(0x8804, [(0x80, b'\x09\x08')], sf_crc='badhi'))      # not a DFP frame (bad CRC): plain data


def frag_frames():
    # fragments of a PN-RT frame carrying a DCP identify request. Every fragment has 42 octets, so that the
    # Ethernet minimum frame size does not add padding inside the reassembled frame.
    pdu = DCP.pdu(5, 0, 0x777, DCP.blk(2, 2, b'fragment-device-name') + DCP.blk(2, 3, be16(0x2a) + be16(7)) +
                  DCP.blk(2, 6, b'port-001.fragment') + DCP.blk(0xff, 0xff, b''))
    inner = be16(0x8892) + be16(0xfefe) + pdu
    inner += bytes(126 - len(inner))
    assert len(inner) == 126
    def frag(fid, num, more, data):
        assert len(data) == 42
        return rt(fid, bytes([len(data) // 8, (0x80 if more else 0) | num]) + data, MAC_DCP_MC, MAC_A)
    parts = [inner[:42], inner[42:84], inner[84:]]
    for fid in (0xff80, 0xff83):
        emit(frag(fid, 0, True, parts[0]))
        emit(frag(fid, 1, True, parts[1]))
        emit(frag(fid, 2, False, parts[2]))
    # a single, unfragmented frame (fragment 0, no more)
    single = be16(0x8892) + be16(0xfefe) + DCP.pdu(5, 0, 0x778, DCP.blk(2, 2, b'single'))
    emit(frag(0xff81, 0, False, single + bytes(42 - len(single))))
    # interleaved fragment ids
    emit(frag(0xff84, 0, True, parts[0]))
    emit(frag(0xff85, 0, True, parts[0]))
    emit(frag(0xff84, 1, True, parts[1]))
    emit(frag(0xff85, 1, True, parts[1]))
    emit(frag(0xff84, 2, False, parts[2]))
    emit(frag(0xff85, 2, False, parts[2]))
    # a fragment that announces more data than it holds: discarded
    emit(rt(0xff86, bytes([0x20, 0x00]) + b'\x01\x02\x03\x04', MAC_DCP_MC, MAC_A))
    # reassembled frame that is not PN-RT (an ethertype nothing registered)
    junk = be16(0x1234) + bytes(82)
    emit(frag(0xff87, 0, True, junk[:42]))
    emit(frag(0xff87, 1, False, junk[42:]))
    # reproducer of the reassembly key fixed on the branch: the key was (frame number << 2) | fragment id, so
    # fragment 0 of id 0xff8c in frame N and of id 0xff80 in frame N + 2 shared a key when N = 1 modulo 4
    # and the last fragment of id 0xff80 was reassembled with the wrong first fragment (the 0xaa octets
    # of frame N instead of the 0xbb octets of frame N + 2)
    while (len(CUR[0]) + 1) % 4 != 1:
        emit(cyclic(0x0022, bytes(10), 1, src=MAC_C, dst=MAC_A))
    emit(frag(0xff8c, 0, True, be16(0x1234) + b'\xaa' * 40))
    emit(cyclic(0x0022, bytes(10), 1, src=MAC_C, dst=MAC_A))
    emit(frag(0xff80, 0, True, be16(0x1234) + b'\xbb' * 40))
    emit(frag(0xff80, 1, False, b'\xcc' * 42))


# ----------------------------------------------------------------- RSI, security
def rsi_pdu(ptype, fopnum, body, dst_sap=0x0001, src_sap=0x0002, flags=0x01, seq=1, ack=0xffff, vl=None,
            ver=1):
    b = fopnum + body
    return (u16(dst_sap) + u16(src_sap) + u8((ver << 4) | ptype) + u8(flags) + u16(seq) + u16(ack) +
            u16(len(b) if vl is None else vl) + b)


def fop(opnum, offset=0, callseq=0):
    return u32((callseq << 29) | (opnum << 24) | offset)


def rsi_frame(pdu, fid=0xfe02, dst=MAC_F, src=MAC_G):
    return rt(fid, pdu, dst, src)


MORE = 0x20


def rsi_fragmented(opnum, data, ptype=5, dst=MAC_F, src=MAC_G, parts=2, dst_sap=0x0001, status=bytes(4),
                   fid=0xfe02, hdr=None):
    """Send `data` in `parts` RSI fragments (request, or response with ptype 6)."""
    if hdr is None:
        conn = u32(4096) + u16(0x00ff) + u16(0x0001) + u16(1) + u8(1) + u8(0)    # rsp max, vendor, device, instance, interface
        if opnum in (5, 6) or (opnum in (0, 10) and dst_sap == 0xffff):
            hdr = conn
        else:
            hdr = u32(4096)
    if ptype == 6:
        hdr = status
    data = data + bytes(max(0, 40 * parts - len(data)))    # every fragment must reach the Ethernet minimum without padding
    cut = [0] + [len(data) * i // parts for i in range(1, parts)] + [len(data)]
    off = 0
    for i in range(parts):
        chunk = data[cut[i]:cut[i + 1]]
        last = i == parts - 1
        flags = 0x01 | (0 if last else MORE)
        h = hdr if i == 0 else b''
        emit(rsi_frame(rsi_pdu(ptype, fop(opnum, off), h + chunk, dst_sap=dst_sap, flags=flags, seq=i + 1), fid, dst, src))
        off += len(chunk)


def rsi_frames():
    iandm0 = zblock(0x0020)
    # unfragmented requests: connect (CONN, destination SAP 0xffff), read, write (SVCS)
    conn_hdr = u32(4096) + u16(0x00ff) + u16(0x0001) + u16(1) + u8(1) + u8(0)
    emit(rsi_frame(rsi_pdu(5, fop(0), conn_hdr + control_block(0x0110, AR1, 0x0001), dst_sap=0xffff)))
    emit(rsi_frame(rsi_pdu(5, fop(2), u32(2048) + read_req_hdr(0x8000, reclen=0x100), dst_sap=0x0001)))
    emit(rsi_frame(rsi_pdu(5, fop(0), u32(2048) + control_block(0x0110, AR1, 0x0001), dst_sap=0x0001)))
    # ACK (with and without the notification flag), NACK, ERR, unknown PDU types
    emit(rsi_frame(rsi_pdu(3, b'', b'', flags=0x41)))
    emit(rsi_frame(rsi_pdu(3, b'', b'', flags=0x11)))
    emit(rsi_frame(rsi_pdu(4, b'', bytes(4))))
    emit(rsi_frame(rsi_pdu(4, b'', bytes([0xde, 0x81, 0x40, 0x09]))))
    # FREQ/FRSP with every operation number, not fragmented
    for opnum in range(0, 16):
        if opnum not in (1, 11, 12, 13, 14, 15):        # reserved operations: see the malformed capture
            if opnum not in (5, 6):
                emit(rsi_frame(rsi_pdu(5, fop(opnum, 0), u32(512) + bytes(12), dst_sap=0x0001)))
            if opnum in (0, 5, 6, 10):
                emit(rsi_frame(rsi_pdu(5, fop(opnum, 0), conn_hdr + bytes(8), dst_sap=0xffff)))
        emit(rsi_frame(rsi_pdu(6, fop(opnum, 0), bytes(4) + bytes(16)), dst=MAC_G, src=MAC_F))
    # fragmented requests (reassembled into the blocks of the operation)
    blocks_req = {
        0: ar_block_req(AR1) + control_block(0x0110, AR1, 1),
        2: read_req_hdr(0x0001, reclen=0),
        3: write_req_hdr(0xaff1, iandm0),
        4: control_block(0x0111, AR1, 2),
        5: iandm0, 6: iandm0, 7: iandm0,
        8: write_req_hdr(0xaff2, iandm0),
        9: write_req_hdr(0xaff3, iandm0),
        10: control_block(0x0110, AR1, 1),
        11: bytes(40),
    }
    blocks_rsp = dict(blocks_req)
    blocks_rsp.update({2: read_res_hdr(0x8000, iandm0), 3: write_res_hdr(0xaff1), 8: write_res_hdr(0xaff2),
                       9: write_res_hdr(0xaff3), 4: control_block(0x8111, AR1, 2)})
    for opnum, data in blocks_req.items():
        if opnum != 11:
            rsi_fragmented(opnum, data + bytes(8), 5, dst_sap=0x0001 if opnum != 0 else 0xffff)
    for opnum, data in blocks_rsp.items():
        rsi_fragmented(opnum, data + bytes(8), 6, dst=MAC_G, src=MAC_F)
    rsi_fragmented(10, control_block(0x0110, AR1, 1) + bytes(8), 5, dst_sap=0xffff)       # security association control, CONN form
    rsi_fragmented(3, write_req_hdr(0xaff1, iandm0) + bytes(8), 5, parts=3)
    # a final fragment that arrives without the first one
    emit(rsi_frame(rsi_pdu(5, fop(3, 64), b'\x01' * 32, flags=0x01, seq=9)))
    # an RSI frame inside a VLAN tagged frame
    emit(eth(MAC_F, MAC_G, 0x8892, be16(0xfe02) + rsi_pdu(3, b'', b'', flags=0x01), vlan=0x6000))


def meta(mode, counter, length, ctrl=0x01):
    return bytes([mode & 1, ctrl & 0x0f]) + u32(counter) + u16(length)


FILL = bytes(range(16))     # stands for the 16 octet SecurityChecksum (never computed)


def secure_frames():
    data = bytes(range(0x20, 0x34))                # 20 octets of user data
    # authentication only, cyclic: SecurityLength = data + cycle counter/status (4)
    for fid in (0x0100, 0x0800, 0x8010, 0x8c10, 0xbc10, 0xc010):
        pl = meta(0, 5, len(data) + 4) + data + u16(10) + bytes([0x35, 0]) + FILL
        emit(rt(fid, pl, MAC_A, MAC_C))
        pl = meta(1, 6, 24) + bytes(range(0x40, 0x58)) + FILL
        emit(rt(fid, pl, MAC_A, MAC_C))
    # secure DFP in an RTC3 frame
    sub = bytes([0x80, 3, 7, 0x35]) + b'\x01\x02\x03'
    sub += struct.pack('<H', crc16(sub))
    pl = struct.pack('<H', 0) + sub + bytes([0, 0])
    emit(rt(0x0300, meta(0, 7, len(pl) + 4) + pl + u16(11) + bytes([0x35, 0]) + FILL, MAC_A, MAC_C))
    # RTA with security: Data-RTA with a block, ACK, ERR and AE mode
    blk = zblock(0x0020)
    def rta_sec(mode, pdu, fid=0xfe41, counter=3):
        n = len(pdu)
        if mode == 0:
            return rt(fid, meta(0, counter, n) + pdu + FILL, MAC_G, MAC_F)
        return rt(fid, meta(1, counter, n) + pdu + FILL, MAC_G, MAC_F)
    emit(rta_sec(0, rta_pdu(blk)))
    emit(rta_sec(0, rta_pdu(blk), fid=0xfc41))
    emit(rta_sec(0, rta_pdu(b'', pdu_type=3)))
    emit(rta_sec(0, rta_pdu(b'', pdu_type=2)))
    emit(rta_sec(0, rta_pdu(bytes(4), pdu_type=4)))
    emit(rta_sec(1, rta_pdu(b'', pdu_type=3)))
    # RSI with security
    def rsi_sec(mode, pdu, counter=4, srcdst=(MAC_F, MAC_G)):
        n = len(pdu)
        return rt(0xfe42, meta(mode, counter, n) + pdu + FILL + bytes(12), srcdst[0], srcdst[1])
    emit(rsi_sec(0, rsi_pdu(3, b'', b'')))
    emit(rsi_sec(0, rsi_pdu(5, fop(2), u32(1024) + read_req_hdr(0x8000, reclen=0x80))))
    emit(rsi_sec(0, rsi_pdu(6, fop(2), bytes(4) + bytes(12)), srcdst=(MAC_G, MAC_F)))
    emit(rsi_sec(0, rsi_pdu(4, b'', bytes([0xde, 0x81, 0x40, 0x09]) + u16(0x2a) + u16(3) + b'extra!')))
    emit(rsi_sec(1, bytes(24)))


# -------------------------------------------------------------------- SXP
def sxp_pkt(payload, btype=0x0700, arid=0x0001, prio=1, flags=0x06, callseq=1):
    return struct.pack('>HHBBHBBBB', btype, 8 + len(payload), 1, 0, arid, prio, flags, callseq, 0) + payload


def svc_req(btype, body=b'', maxrsp=0x1000, ver=(1, 0)):
    n = 12 + len(body)
    return struct.pack('>HHBBBBI', btype, n - 4, ver[0], ver[1], 0, 0, maxrsp) + body


def svc_rsp(btype, body=b'', status=bytes(4)):
    n = 12 + len(body)
    return struct.pack('>HHBBBB', btype, n - 4, 1, 0, 0, 0) + status + body


def sxp_endpoint(eid=1, vendor=0x2a, dev=1, inst=1, res=0):
    return bytes([eid, res]) + u16(vendor) + u16(dev) + u16(inst)


def sxp_rta(payload, pdu_type=0x31, flags=0, seq=1, ack=0, var=None, dst=1, src=2):
    return (u16(dst) + u16(src) + u8(pdu_type) + u8(flags) + u16(seq) + u16(ack) +
            u16(len(payload) if var is None else var) + payload)


def sxp_station(name=b'sxp-dev-1'):
    return u16(3) + u16(len(name) + 3 + 2 - 4 + 4) + bytes([1, 0]) + bytes([len(name)]) + name


def sxp_frame(payload, dst=MAC_D, src=MAC_E, **kw):
    emit(rt(0xfe03, sxp_rta(payload, **kw), dst, src))


def sxp_services():
    iocr = iocr_block_req(1, 1, 0x8001, objs=((0, 1, 0),), iocs=(), datalen=40)
    ar = ar_block_req(AR3, name=b'sxp-ctrl', mac=MAC_A)
    blk = zblock(0x0020)
    sam = [B(0x06e4, bytes(ZERO_LEN[0x06e4])), B(0x06e0, bytes(ZERO_LEN[0x06e0])), B(0x06e2, bytes(ZERO_LEN[0x06e2])),
           B(0x06e3, bytes(ZERO_LEN[0x06e3]))]
    S = []
    S.append(svc_req(0x0720, sxp_endpoint() + ar + iocr))
    S.append(svc_rsp(0x8720, ar_block_res(AR3) + iocr_block_res(1, 1, 0x8001)))
    S.append(svc_req(0x0720, sxp_endpoint()))
    for t in range(0x0721, 0x072a):
        S.append(svc_req(t, write_req_hdr(0x8000, blk) if t & 1 == 0 else read_req_hdr(0x8000, reclen=0)))
        S.append(svc_rsp(t | 0x8000, write_res_hdr(0x8000) if t & 1 == 0 else read_res_hdr(0x8000, blk)))
    S.append(svc_req(0x0815, read_req_hdr(0x8000, reclen=0)))
    S.append(svc_req(0x0816, read_req_hdr(0x8000, reclen=0)))
    S.append(svc_req(0x072a, alarm_notification(1, [(0x8000, chan_diag())], low=False)))
    S.append(svc_req(0x072b, alarm_notification(1, [(0x8000, chan_diag())])))
    S.append(svc_rsp(0x872a, B(0x8001, alarm_hdr() + alarm_spec() + bytes(4))))
    S.append(svc_rsp(0x872b, B(0x8002, alarm_hdr() + alarm_spec() + bytes(4))))
    S.append(svc_req(0x072c, B(0x0001, b'\x01\x02\x03\x04\x05\x06')))
    S.append(svc_req(0x072c, b'\x01\x02'))                    # shorter than a block header
    S.append(svc_rsp(0x872c, B(0x0001, b'\x01\x02\x03\x04')))
    S.append(svc_rsp(0x872c, b'\x01\x02'))
    S.append(svc_req(0x072d, B(0x0001, b'') + u16(0x8001) + bytes(range(1, 21))))
    S.append(svc_req(0x072d))
    S.append(svc_req(0x0740, B(0x0001, b'') + u16(0x8001) + bytes(range(1, 11))))
    S.append(svc_req(0x0741, B(0x0001, b'') + u16(0x8002) + bytes(range(1, 11))))
    S.append(svc_req(0x0780, sxp_endpoint() + b''.join(sam)))
    S.append(svc_req(0x0781, sam[1] + sam[2]))
    S.append(svc_req(0x0781, sam[1]))
    S.append(svc_rsp(0x8780, B(0x86e0, bytes(ZERO_LEN[0x86e0]))))
    S.append(svc_rsp(0x8781, B(0x86e0, bytes(ZERO_LEN[0x86e0]))))
    S.append(svc_rsp(0x8781))
    S.append(svc_req(0x0710, bytes([0xde, 0x81, 0x40, 0x09]) + u16(0x2a) + u16(1) + b'vendor error data'))
    S.append(svc_req(0x0710, bytes([0xde, 0x81, 0x40, 0x09])))
    S.append(svc_req(0x0710))
    S.append(svc_req(0x0799, b'\x01\x02\x03\x04'))
    S.append(svc_rsp(0x8799, b'\x01\x02\x03\x04'))
    S.append(svc_req(0x0700, b''))
    return S


def sxp_frames():
    S = sxp_services()
    # over RTAv3 (FrameID 0xfe03), each service in one SXP packet
    for i, svc in enumerate(S):
        pkt = sxp_pkt(svc, btype=0x0700 if svc[0] < 0x80 else 0x0701, arid=0x0100 + i % 7, prio=i % 10, callseq=i)
        sxp_frame(pkt)
    # with and without the station block, several SXP packets in one RTA PDU
    sxp_frame(sxp_station() + sxp_pkt(S[0]))
    sxp_frame(sxp_station(b'a') + sxp_pkt(S[1], btype=0x0701) + sxp_pkt(S[3], arid=2))
    sxp_frame(u16(3) + u16(2) + bytes([1, 0]) + sxp_pkt(S[4]))
    # RTA-PDU variants: ACK, NACK, ERR (status, short), unknown type, wrong version
    sxp_frame(b'', pdu_type=0x33)
    sxp_frame(b'', pdu_type=0x32)
    sxp_frame(bytes([0xde, 0x81, 0x40, 0x09]), pdu_type=0x34)
    sxp_frame(bytes([0xde, 0x81]), pdu_type=0x34)
    sxp_frame(b'', pdu_type=0x31, var=0)
    sxp_frame(sxp_pkt(S[0]), pdu_type=0x31, flags=0x20)
    # fragmented requests: first / middle / last over RTAv3
    svc = svc_req(0x0720, sxp_endpoint() + ar_block_req(AR3, name=b'sxp-frag') + iocr_block_req(1, 1, 0x8001, objs=((0, 1, 0),), iocs=()))
    cut = [0, 40, 80, len(svc)]
    for k in range(3):
        flags = (0x02 if k == 0 else 0) | (0x04 if k == 2 else 0)
        sxp_frame(sxp_pkt(svc[cut[k]:cut[k + 1]], flags=flags, callseq=40, arid=0x0200))
    # two interleaved streams
    svc2 = svc_req(0x0721, read_req_hdr(0x8000, reclen=0) + bytes(60))
    sxp_frame(sxp_pkt(svc2[:40], flags=0x02, callseq=41, arid=0x0201))
    sxp_frame(sxp_pkt(svc[:40], flags=0x02, callseq=41, arid=0x0202))
    sxp_frame(sxp_pkt(svc2[40:], flags=0x04, callseq=41, arid=0x0201))
    sxp_frame(sxp_pkt(svc[40:], flags=0x04, callseq=41, arid=0x0202))
    # a response in two fragments from the device
    rsvc = svc_rsp(0x8721, read_res_hdr(0x8000, zblock(0x0020)) + bytes(30))
    sxp_frame(sxp_pkt(rsvc[:50], btype=0x0701, flags=0x02, callseq=42), dst=MAC_E, src=MAC_D)
    sxp_frame(sxp_pkt(rsvc[50:], btype=0x0701, flags=0x04, callseq=42), dst=MAC_E, src=MAC_D)
    # a fragment stream in which the first fragment comes last in the file: reproducer of the -2 difference
    # fixed on the branch (the Info column of the middle fragment depended on the pass)
    sxp_frame(sxp_pkt(b'\x11' * 16, flags=0x00, callseq=77, arid=0x0300))
    sxp_frame(sxp_pkt(struct.pack('>HH', 0x0720, 0x0040) + b'\x22' * 12, flags=0x02, callseq=77, arid=0x0300))
    # security metadata inside an SXP packet: authentication only; the encrypted form is only shown as data
    pl = svc_req(0x0721, read_req_hdr(0x8000, reclen=0))
    sxp_frame(sxp_pkt(meta(0, 9, len(pl)) + pl + FILL, callseq=50))
    sxp_frame(sxp_pkt(meta(1, 9, 24) + bytes(24) + FILL, callseq=51))
    # TCP, default ports 34964 and 34962 and the heuristic
    seq = [1000]
    def tcp(payload, sport, dport, src_ip='192.0.2.1', dst_ip='192.0.2.2', dst=MAC_D, src=MAC_E, sq=None):
        emit(tcp_frame(payload, sport, dport, seq[0], src_ip=src_ip, dst_ip=dst_ip, dst=dst, src=src))
        seq[0] += len(payload)
    for dport in (34964, 34962):
        tcp(sxp_pkt(S[0], callseq=60), 50000, dport)
        tcp(sxp_pkt(S[1], btype=0x0701, callseq=60), dport, 50000, '192.0.2.2', '192.0.2.1', MAC_E, MAC_D)
    tcp(sxp_pkt(S[0], callseq=61) + sxp_pkt(S[3], callseq=62), 50001, 34964)
    tcp(sxp_pkt(svc[:40], flags=0x02, callseq=63), 50001, 34964)
    tcp(sxp_pkt(svc[40:], flags=0x04, callseq=63), 50001, 34964)
    # the TCP heuristic on another port
    tcp(sxp_pkt(S[4], callseq=64), 50002, 40001)


# ------------------------------------------- PD blocks, ProfiDrive, security
class Pos:
    """Track the tvb offset of a block body for the align4 padding of the dissector.
    A block that sits at the start of an RTA PDU body starts at offset 12 (aligned); its body
    after the 4 octet block header and the 2 octet version starts at offset 2 modulo 4."""
    def __init__(self, start=2):
        self.b = b''
        self.start = start

    def add(self, data):
        self.b += data
        return self

    def align(self):
        self.b += bytes((-(self.start + len(self.b))) % 4)
        return self


def pdir_global(vl=0, nports=2):
    p = Pos().align().add(G('aabbccdd-0011-2233-4455-66778899aabb')).add(u32(1000)).add(u32(nports))
    for i in range(nports):
        p.add(u32(100 + i) + u32(200 + i))
        if vl >= 2:
            p.add(u32(300 + i) + u32(400 + i))
    return B(0x0206, p.b, 1, vl)


def pdir_frame(vl=0, ngroups=(1, 3, 9)):
    p = Pos().align()
    if vl > 0:
        p.add(u32(0x00000103))
    for k, n in enumerate(ngroups):
        size = (n + 7) // 8
        p.add(u32(0x1000 + k) + u16(40) + u16(1) + u16(2) + u16(0xc000 + k) + u16(0x8892) + u8(1) + u8(0x01) + u8(n)
              + bytes([0x5a] * size)).align()
    return B(0x0207, p.b, 1, vl)


def pdir_beginend(nports=2, nass=2, nph=2):
    p = Pos().align().add(u16(1)).add(u16(2)).add(u32(nports))
    for i in range(nports):
        p.add(u32(nass))
        for a in range(nass):
            p.add(b''.join(u32(100 * a + j) for j in range(6)))
        p.add(u32(nph))
        for ph in range(nph):
            p.add(u16(1) + u16(2) + u16(3) + u16(4) + u16(5) + u16(6) + u16(7) + u16(8))
    return B(0x0208, p.b)


def pdir_data(vl):
    body = Pos().align().add(u16(1)).add(u16(1)).b
    body += pdir_global(vl) + pdir_frame(vl)
    if vl >= 1:
        body += pdir_beginend()
    return B(0x0205, body, 1, vl)


def pdsync(vl):
    if vl == 0:
        p = Pos().align().add(u16(1) + u16(1) + G('11111111-2222-3333-4444-555555555555') + G('22222222-2222-3333-4444-555555555555')
                              + u32(1) + u32(2) + u32(3) + u32(4) + u16(5) + u16(6) + u16(7) + u16(8))
    else:
        p = Pos().align().add(G('11111111-2222-3333-4444-555555555555') + u32(1) + u32(2) + u32(3) + u32(4) + u16(5) +
                              u16(6) + u16(7) + u16(8) + u16(9) + bytes([1, 2, 6]) + b'domain')
    return B(0x0203, p.b, 1, vl)


def profidrive_frames():
    # read request (id 1) and write request (id 2) with all value formats, responses, errors
    def params(n):
        return b''.join(bytes([0x10, 1]) + u16(0x100 + i) + u16(i) for i in range(n))
    req_read = bytes([1, 1, 0, 2]) + params(2)
    req_read1 = bytes([2, 1, 0, 1]) + bytes([0x10, 3]) + u16(0x100) + u16(5)
    vals = (bytes([0x42, 2]) + u16(1) + u16(2) + bytes([0x41, 3, 1, 2, 3, 0]) + bytes([0x43, 1]) + u32(5) +
            bytes([0x08, 1]) + u32(0x3f800000) + bytes([9, 1]) + b'text\0' + bytes([0x77, 1, 0]))
    req_write = bytes([3, 2, 0, 6]) + params(6) + vals
    resp_read = bytes([1, 1, 0, 3]) + bytes([0x42, 2]) + u16(1) + u16(2) + bytes([0x41, 3, 1, 2, 3, 0]) + bytes([0x43, 1]) + u32(5)
    resp_write = bytes([3, 2, 0, 0])
    resp_err_r = bytes([1, 0x81, 0, 5]) + bytes([0x44, 2]) + u16(0x0001) + u16(0x1234) + \
        bytes([0x44, 2]) + u16(0x0004) + u16(0x1234) + bytes([0x44, 2]) + u16(0x0020) + u16(0x1234) + \
        bytes([0x44, 3]) + u16(0x0009) + u16(1) + u16(2) + bytes([0x41, 2, 1, 2])
    resp_err_w = bytes([4, 0x82, 0, 2]) + bytes([0x44, 2]) + u16(0x0001) + u16(1) + bytes([0x44, 2]) + u16(0x0023) + u16(5)
    resp_err_r23 = bytes([1, 0x81, 0, 2]) + bytes([0x44, 1]) + u16(0x0023) + bytes(4)
    for idx in (0xb02e, 0xb02f, 0x002f):
        for d in (req_read, req_read1, req_write):
            rpc_pair(3, write_req_hdr(idx, d), write_res_hdr(idx))
        for d in (resp_read, resp_write, resp_err_r, resp_err_w, resp_err_r23):
            rpc_pair(2, read_req_hdr(idx), read_res_hdr(idx, d))


def mrp_data_frames():
    # MRP instance data in the older and newer versions, with 0 to 2 nested instance blocks
    uu = G('99999999-2222-3333-4444-555555555555')
    nested = zblock(0x0214)
    inst_adj = B(0x0231, bytes(ZERO_LEN[0x0231]))
    inst_real = B(0x0232, bytes(ZERO_LEN[0x0232]))
    inst_chk = B(0x0233, bytes(ZERO_LEN[0x0233]))
    # PDInterfaceMrpDataAdjust
    p = Pos().align().add(uu).add(u16(2)).align().add(u8(0)).align().add(nested)
    emit(rta(B(0x0211, p.b, 1, 0)))
    emit(rta(B(0x0211, bytes(1) + u8(2) + inst_adj + inst_adj, 1, 1)))
    # PDInterfaceMrpDataReal
    p = Pos().align().add(uu).add(u16(2)).add(u8(6)).add(b'mrp-d1').add(u16(1)).align().add(nested)
    emit(rta(B(0x0212, p.b, 1, 0)))
    p = Pos().align().add(uu).add(u16(2)).add(u16(1)).add(u8(6)).add(b'mrp-d1').align().add(nested)
    emit(rta(B(0x0212, p.b, 1, 1)))
    emit(rta(B(0x0212, bytes(1) + u8(2) + inst_real + inst_real, 1, 2)))
    # PDInterfaceMrpDataCheck
    emit(rta(B(0x0213, Pos().align().add(uu).add(u32(1) + u32(1) + u32(1) + u32(0) + u32(0)).b, 1, 0)))
    emit(rta(B(0x0213, bytes(1) + u8(2) + inst_chk + inst_chk, 1, 1)))
    # more instances than allowed
    emit(rta(B(0x0211, bytes(1) + u8(0x20) + bytes(8), 1, 1)))
    emit(rta(B(0x0212, bytes(1) + u8(0x20) + bytes(8), 1, 2)))
    emit(rta(B(0x0213, bytes(1) + u8(0x20) + bytes(8), 1, 1)))


def pd_frames():
    for vl in (0, 1, 2):
        emit(rta(pdir_data(vl)))
    emit(rta(pdir_global(0, 0)))
    emit(rta(pdir_global(1, 1)))
    emit(rta(pdir_global(2, 3)))
    emit(rta(pdir_frame(0)))
    emit(rta(pdir_frame(1)))
    emit(rta(pdir_beginend(1, 0, 0)))
    emit(rta(pdir_beginend(2, 3, 2)))
    for vl in (0, 1):
        emit(rta(B(0x0209, Pos().align().add(u32(0x00000101)).add(u16(0x0001)).align().b if vl == 0 else
                   Pos().align().add(u32(0x101)).add(u32(0x202)).add(u16(1)).align().b, 1, vl)))
    emit(rta(B(0x0251, Pos().align().add(u32(1) * 6).b, 1, 0)))
    emit(rta(B(0x0251, u32(1) * 6 + u16(0x7f7f), 1, 1)))
    emit(rta(B(0x0251, u32(1) * 6 + u16(0x7f7f), 1, 5)))
    for sid, api in ((0x1234, 0), (0x8001, 0), (0x8000, 0), (0x1234, 1)):
        emit(rta(B(0x0108, u16(sid) + u32(api) + b'\x01\x02\x03\x04')))
    emit(rta(B(0x0108, u16(0x1234) + u32(0) + b'\x01\x02\x03\x04'), fid=0xfc01))


def sec_frames():
    # Get/Set security operations (without certificates or key material), SAM/SCM wrappers, EAP
    def secreq(op, data=b''):
        return B(0x011a, u16(op) + data + bytes(4))
    def secrsp(op, data=b''):
        return B(0x811a, u16(op) + data + bytes(4))
    cred = u32(0x00000001) + u32(0)
    emit(rta(secreq(1)))
    for op in (4, 5, 7, 9, 11):
        emit(rta(secreq(op, cred)))
    emit(rta(secreq(8, cred + bytes(2) + u16(0))))
    emit(rta(secreq(8, cred + bytes(2) + u16(1) + u16(0) + bytes(2))))
    emit(rta(secreq(10, cred + u16(0))))
    emit(rta(secreq(12, u64(1) + u64(2))))
    emit(rta(secreq(0x0100, b'\x03\x01\x00\x04')))
    emit(rta(secreq(0x0333, b'\x00\x01')))
    emit(rta(secrsp(1, u16(0x0001) + u16(5) + u16(0x0101) + u16(0x0201) + u16(0x0301) + u16(0x0401) + u16(0x0501))))
    emit(rta(secrsp(1, u16(0x0001) + u16(1) + u16(0x0601))))
    emit(rta(secrsp(2, bytes(2) + u16(2) + cred + cred)))
    emit(rta(secrsp(3, u64(1) + u64(2))))
    emit(rta(secrsp(4, bytes(2) + u16(0))))
    emit(rta(secrsp(5, u16(0))))
    emit(rta(secrsp(6, u16(0))))
    for op in (8, 9, 10, 11, 12, 13):
        emit(rta(secrsp(op)))
    emit(rta(secrsp(0x0100, b'\x03\x01\x00\x04')))
    emit(rta(secrsp(0x0200, b'')))
    # ARAlgorithmInfo: all usages
    for usages in ((1, 1, 1), (2, 2, 2), (3, 4, 5), (0, 0, 0)):
        body = bytes(2) + u16(usages[0] << 8 | 1) + u16(0x0100) + u16(usages[1] << 8 | 2) + u16(0x0100) + \
            u16(usages[2] << 8 | 1) + u16(0x0100) + u16(0x0103) + u16(0x0200) + u16(0x0104) + u16(0x0200) + bytes(8)
        emit(rta(B(0x06e2, body)))
    emit(rta(B(0x06e2, bytes(8))))
    emit(rta(B(0x06e3, bytes(2) + u32(0x00010002) + bytes(8))))
    emit(rta(B(0x06e3, bytes(2))))
    emit(rta(B(0x06e4, bytes(2) + bytes(22))))
    emit(rta(B(0x06e4, bytes(4))))
    emit(rta(B(0x06e0, u16(0x0100) + b'\x03\x01\x00\x04')))
    emit(rta(B(0x06e0, u16(0x0100) + b'\x03\x01\x00\x04\x00\x00')))
    emit(rta(B(0x06e0, u16(0x0100) + b'\x01')))
    emit(rta(B(0x06e0, u16(0x0100))))
    emit(rta(B(0x06e0, u16(0x0200) + b'\x00\x01')))
    emit(rta(B(0x86e0, u16(0x0100))))
    emit(rta(B(0x86e0, u16(0x0100) + b'\x03\x02\x00\x04')))
    emit(rta(B(0x86e0, u16(0x0001) + u16(0x0000))))
    emit(rta(B(0x06f0, u16(0x0001))))
    emit(rta(B(0x86f0, u16(0x0001) + u16(0x0000))))
    emit(rta(B(0x0107, bytes(2) + u16(1) + MAC_A + u32(0) + u32(8) + u32(0) + u32(1) + u32(0) + u32(8) + u32(0) + u32(2))))
    emit(rta(B(0x0109, bytes(2) + G('aabbccdd-0011-2233-4455-66778899aabb') + bytes(2) + u16(2) + u16(1) + u16(5) + u32(7) + u16(2) + u16(6) + u32(8))))


def status_frames():
    # ERR-RTA PDUs with every ErrorDecode / ErrorCode1 the dissector knows
    c1 = (list(range(1, 15)) + list(range(20, 28)) + [40] + list(range(50, 58)) + list(range(60, 81)) +
          list(range(100, 116)) + [200, 202, 204, 205, 206, 208, 209, 210, 211, 224, 225, 253, 255, 0, 150])
    for code1 in c1:
        emit(rta(bytes([0xdf if code1 & 1 else 0xde, 0x81, code1, 1 + code1 % 5]), pdu_type=4))
    for ecode in (0x00, 0x81, 0xcf, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xfd, 0xff):
        emit(rta(bytes([ecode, 0x81, 1, 1]), pdu_type=4))
    for code1 in range(0, 24):
        emit(rta(bytes([0xdf, 0x80, code1, 1 + code1 % 7]), pdu_type=4))
    for code1 in (0, 1, 2, 3, 4, 5, 6, 0x10, 0xfd, 0xff):
        emit(rta(bytes([0xde, 0x82, code1, 3]), pdu_type=4))
    for code1 in (0x01, 0x02, 0x04, 0x10, 0x80, 0xf0, 0x33):
        emit(rta(bytes([0xde, 0x83, code1, 3]), pdu_type=4))
    for dec in (0x00, 0x01, 0x7f, 0x84, 0xff):
        emit(rta(bytes([0xde, dec, 1, 1]), pdu_type=4))


# ---------------------------------------------- GSD scenario (preferences)
def gsd_xml(conversation=None):
    types = ['Integer8', 'Integer16', 'Integer32', 'Integer64', 'Unsigned8', 'Unsigned16', 'Unsigned32', 'Unsigned64',
             'Float32', 'Float64', 'Date', 'TimeOfDay with date indication', 'TimeOfDay without date indication',
             'TimeDifference with date indication', 'TimeDifference without date indication', 'NetworkTime',
             'NetworkTimeDifference', 'Float32+Status8', 'F_MessageTrailer4Byte', 'F_MessageTrailer5Byte',
             'Unsigned8+Unsigned8', 'Float32+Unsigned8', 'Boolean', 'TimeStamp', 'TimeStampDifference',
             'TimeStampDifferenceShort', 'OctetString2+Unsigned8', 'Unsigned16_S', 'N2', 'N4', 'V2', 'L2', 'R2', 'T2',
             'T4', 'D2', 'E2', 'C4', 'X2', 'X4', 'Unipolar2.16']
    items_in = ''.join('<DataItem DataType="%s"/>' % t for t in types[:20])
    items_out = ''.join('<DataItem DataType="%s"/>' % t for t in types[20:])
    conv_xml = '' if conversation is None else '<conversation device="%s" controller="%s"/>' % conversation
    return """<?xml version="1.0" encoding="UTF-8"?>
<ISO15745Profile xmlns="http://www.profibus.com/GSDML/2003/11/DeviceProfile">
  <ProfileHeader>
    <ProfileIdentification>PROFINET Device Profile</ProfileIdentification>
    <ProfileRevision>1.00</ProfileRevision>
    <ProfileName>Device Profile for PROFINET Devices</ProfileName>
    <ProfileSource>Synthetic test data</ProfileSource>
    <ProfileClassID>Device</ProfileClassID>
  </ProfileHeader>
  <ProfileBody>
    <DeviceIdentity VendorID="0x002a" DeviceID="0x0001"><InfoText TextId="T_DEV"/><VendorName Value="Test"/></DeviceIdentity>
    %s
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP 1" ModuleIdentNumber="0x00000001" PhysicalSlots="0..5" FixedInSlots="0" PhysicalSubslots="1">
          <ModuleInfo><Name TextId="T_DAP"/><InfoText TextId="T_DAPI"/></ModuleInfo>
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="Mod DI" FixedInSlots="1"/>
            <ModuleItemRef ModuleItemTarget="Mod DO" UsedInSlots="2 3"/>
            <ModuleItemRef ModuleItemTarget="Mod DIO" FixedInSlots="4..5"/>
            <ModuleItemRef ModuleItemTarget="Mod Data" UsedInSlots="6"/>
          </UseableModules>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DAP v" SubmoduleIdentNumber="0x00000101"><ModuleInfo><Name TextId="T_DAPV"/></ModuleInfo></VirtualSubmoduleItem>
          </VirtualSubmoduleList>
          <SystemDefinedSubmoduleList>
            <InterfaceSubmoduleItem ID="if" SubslotNumber="32768" SubmoduleIdentNumber="0x00000201"/>
            <PortSubmoduleItem ID="port 1" SubslotNumber="32769" SubmoduleIdentNumber="0x00000202"/>
          </SystemDefinedSubmoduleList>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="Mod DI" ModuleIdentNumber="0x00000020">
          <ModuleInfo><Name TextId="T_DI"/></ModuleInfo>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="v di" SubmoduleIdentNumber="0x00000301" PROFIsafeSupported="true" FixedInSubslots="1">
              <IOData><Input><DataItem DataType="OctetString" Length="2"/><DataItem DataType="F_MessageTrailer4Byte"/></Input></IOData>
              <RecordDataList><F_ParameterRecordDataItem Index="0x1000" Length="12"/></RecordDataList>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="Mod DO" ModuleIdentNumber="0x00000021">
          <ModuleInfo><Name TextId="T_DO"/></ModuleInfo>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="v do" SubmoduleIdentNumber="0x00000302" PROFIsafeSupported="true" FixedInSubslots="1">
              <IOData><Output><DataItem DataType="OctetString" Length="2"/><DataItem DataType="F_MessageTrailer4Byte"/></Output></IOData>
              <RecordDataList><F_ParameterRecordDataItem Index="0x1001" Length="12"/></RecordDataList>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="Mod DIO" ModuleIdentNumber="0x00000022">
          <ModuleInfo><Name TextId="T_DIO"/></ModuleInfo>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="v dio" SubmoduleIdentNumber="0x00000303" FixedInSubslots="1">
              <IOData><Input><DataItem DataType="Unsigned8"/></Input><Output><DataItem DataType="Unsigned16"/></Output></IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="Mod DIO 2" ModuleIdentNumber="0x00000022">
          <ModuleInfo><Name TextId="T_DIO"/></ModuleInfo>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="v dio2" SubmoduleIdentNumber="0x00000303" FixedInSubslots="1">
              <IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="Mod Data" ModuleIdentNumber="0x00000023">
          <ModuleInfo><Name TextId="T_DATA"/></ModuleInfo>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="v data" SubmoduleIdentNumber="0x00000304" FixedInSubslots="1">
              <IOData><Input>%s</Input><Output>%s</Output></IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
      <ExternalTextList>
        <PrimaryLanguage>
          <Text TextId="T_DAP" Value="Head station"/>
          <Text TextId="T_DAPV" Value="Head submodule"/>
          <Text TextId="T_DI" Value="Safe digital input"/>
          <Text TextId="T_DO" Value="Safe digital output"/>
          <Text TextId="T_DIO" Value="Digital IO"/>
          <Text TextId="T_DATA" Value="Data types"/>
          <Text TextId="T_NOVALUE"/>
        </PrimaryLanguage>
      </ExternalTextList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
""" % (conv_xml, items_in, items_out)


def write_gsd_files():
    d = os.path.join(OUT, 'gsd')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'device-gsd.xml'), 'w') as f:
        f.write(gsd_xml())
    # the "manual" configuration file is the same document with the station pairs added
    with open(os.path.join(OUT, 'gsd-config.xml'), 'w') as f:
        f.write(gsd_xml(conversation=(':'.join('%02x' % b for b in MAC_H), ':'.join('%02x' % b for b in MAC_I))))
    # files that are not GSD documents: skipped by the directory scan
    os.makedirs(os.path.join(OUT, 'gsd-bad'), exist_ok=True)
    with open(os.path.join(OUT, 'gsd-bad', 'not-xml.txt'), 'w') as f:
        f.write('this is not an XML document\n')
    with open(os.path.join(OUT, 'gsd-bad', 'other.xml'), 'w') as f:
        f.write('<?xml version="1.0"?><root xmlns="urn:other"><item/></root>\n')
    with open(os.path.join(OUT, 'gsd-bad', 'twodev.xml'), 'w') as f:
        f.write(gsd_xml().replace('<ProfileBody>', '<ProfileBody><DeviceIdentity VendorID="0x0001" DeviceID="zz"/>', 1))
    with open(os.path.join(OUT, 'gsd-bad', 'badids.xml'), 'w') as f:
        f.write(gsd_xml().replace('VendorID="0x002a"', 'VendorID="xyz"'))
    with open(os.path.join(OUT, 'gsd-bad', 'badslots.xml'), 'w') as f:
        f.write(gsd_xml().replace('UsedInSlots="6"', 'UsedInSlots="6 x"'))
    with open(os.path.join(OUT, 'gsd-bad', 'nofparam.xml'), 'w') as f:
        f.write(gsd_xml().replace('<F_ParameterRecordDataItem Index="0x1000" Length="12"/>', ''))


GSD = []     # frames of the GSD capture (needs the preferences, see runcov.sh and README)


def fparam(flag1=0x00, flag2=0x00, src=1, dst=0x1234, wd=150, ipar=0x11223344, crc=0x5566):
    ipar_bytes = u32(ipar) if (flag2 & 0x08) and not (flag2 & 0x20) else b''
    return bytes([flag1, flag2]) + u16(src) + u16(dst) + u16(wd) + ipar_bytes + u16(crc)


def gsd_frames():
    CUR[0] = GSD
    dev, ctl = MAC_H, MAC_I
    # the station is identified by the DCP identify response: vendor 0x002a, device 0x0001
    emit(DCP.frame(0xfeff, DCP.pdu(5, 1, 0x500, DCP.blk(2, 2, be16(1) + b'gsd-dev') + DCP.blk(2, 3, be16(1) + be16(0x2a) + be16(1)) +
                                   DCP.blk(2, 1, be16(1) + b'GSD test station')), ctl, dev))
    # IOCR and expected submodules without an AR block: the station information is kept under AR UUID 0
    iocr_in = iocr_block_req(1, 1, 0x8101, objs=((0, 1, 0), (0, 0x8000, 1), (0, 0x8001, 2), (1, 1, 3), (3, 1, 10)),
                             iocs=((2, 1, 12), (3, 1, 13)), datalen=40)
    iocr_out = iocr_block_req(2, 2, 0x8102, objs=((2, 1, 0), (3, 1, 7), (4, 1, 10)),
                              iocs=((0, 1, 12), (0, 0x8000, 13), (0, 0x8001, 14), (1, 1, 15), (3, 1, 16), (4, 1, 17)), datalen=40)
    dd = data_desc
    exp = expected_submod_req([
        (0, 0, 0x00000001, 0, [(1, 0x00000101, 0, [dd(1, 0)]), (0x8000, 0x00000201, 0, [dd(1, 0)]), (0x8001, 0x00000202, 0, [dd(1, 0)])]),
        (0, 1, 0x00000020, 0, [(1, 0x00000301, 0x0001, [dd(1, 6)])]),
        (0, 2, 0x00000021, 0, [(1, 0x00000302, 0x0002, [dd(2, 6)])]),
        (0, 3, 0x00000022, 0, [(1, 0x00000303, 0x0003, [dd(1, 1), dd(2, 2)])]),
        (0, 4, 0x00000023, 0, [(1, 0x00000304, 0x0023, [dd(1, 5), dd(2, 3)])]),
    ])
    for blk in (iocr_in, iocr_out, exp):
        emit(rta(blk, dst=dev, src=ctl))
    # PA profile submodules (API 0x9700) and the DAP of the PA profile
    pa = [0x00000001, 0x00000002, 0x00000102, 0x00000100, 0x00000200, 0x00010100, 0x00010900, 0x00010100 | 0x06,
          0x00020101, 0x00020103, 0x00020080, 0x00020001, 0x00020002, 0x00020300, 0x01020101,
          0x00030101, 0x00030900, 0x00030102, 0x01030101, 0x00030a01, 0x00040001]
    subs = [(i + 1, ident, 0x0001, [dd(1, 5)]) for i, ident in enumerate(pa)]
    emit(rta(expected_submod_req([(0x9700, 1, 0x00fd0001, 0, subs[:11]), (0x9700, 2, 0x00fd0002, 0, subs[11:])]), dst=dev, src=ctl))
    emit(rta(expected_submod_req([(0, 7, 0x00fd0001, 0, [(1, 0x00000001, 0x0001, [dd(1, 4)])])]), dst=dev, src=ctl))
    # reproducer of the GSD name overflow: a submodule whose module is in the GSD, then one of the PA profile
    emit(rta(expected_submod_req([(0, 1, 0x00000020, 0, [(1, 0x00000301, 0x0001, [dd(1, 6)])]),
                                  (0x9700, 5, 0x00fd0001, 0, [(1, 0x00010100, 0x0001, [dd(1, 4)])])]), dst=dev, src=ctl))
    # F-parameter records (indexes 0x1000 and 0x1001 of the GSD) with all flag combinations
    for k, (f1, f2) in enumerate(((0x00, 0x00), (0x10, 0x08), (0x20, 0x08), (0x30, 0x28), (0x00, 0x08), (0x20, 0x00))):
        idx = 0x1000 if k % 2 == 0 else 0x1001
        rpc_pair(3, write_req_hdr(idx, fparam(f1, f2), slot=1 if idx == 0x1000 else 2), write_res_hdr(idx),
                 dev=dev, ctl=ctl, sport=51000 + k)
    # cyclic frames with the PROFIsafe data: input (device to controller) and output
    inp = bytes([0x80]) + bytes([0x80]) * 2 + bytes([0x11, 0x22, 0x20, 0xaa, 0xbb, 0xcc]) + bytes([0x80]) + bytes(range(1, 8)) + bytes(40)
    for i, (sb, cb) in enumerate(((0x00, 0x00), (0x20, 0x20), (0x20, 0x00), (0x00, 0x20))):
        pin = bytes([0x80, 0x80, 0x80]) + bytes([0x11, 0x22, sb, 0xaa, 0xbb, 0xcc, 0x80]) + bytes([1, 0x80, 0x80]) + bytes(30)
        pout = bytes([0x33, 0x44, cb, 0x01, 0x02, 0x03, 0x80]) + bytes([5, 6, 0x80]) + bytes(30)
        emit(cyclic(0x8101, pin, 200 + i, src=dev, dst=ctl))
        emit(cyclic(0x8102, pout, 200 + i, src=ctl, dst=dev))
    # PA profile objects (API 0x9700): the data of the cyclic frames is a value with a status
    dev3, ctl3 = MAC_E, MAC_D
    emit(DCP.frame(0xfeff, DCP.pdu(5, 1, 0x501, DCP.blk(2, 3, be16(1) + be16(0x2a) + be16(1))), ctl3, dev3))
    pa_ids = [0x00000001, 0x00000102, 0x00010100, 0x00020101, 0x00030101]
    iocr_pa = iocr_block_req(1, 1, 0x8103, napis=[(0x9700, tuple((1, k + 1, 6 * k) for k in range(5)), ())], datalen=40)
    exp_pa = expected_submod_req([(0x9700, 1, 0x00fd0001, 0, [(k + 1, ident, 0x0001, [dd(1, 5)]) for k, ident in enumerate(pa_ids)])])
    for blk in (iocr_pa, exp_pa):
        emit(rta(blk, dst=dev3, src=ctl3))
    for i in range(2):
        emit(cyclic(0x8103, b''.join(struct.pack('>f', 1.5 * k) + bytes([0x80, 0x80]) [:5] + bytes([0x80]) for k in range(5)), 400 + i, src=dev3, dst=ctl3))
    # the same station pair seen only by its cyclic frames after Read/Write records: heuristic extraction
    dev2, ctl2 = MAC_C, MAC_G
    rpc_pair(3, write_req_hdr(0xaff1, zblock(0x0020)), write_res_hdr(0xaff1), dev=dev2, ctl=ctl2, sport=52000)
    rpc_pair(2, read_req_hdr(0xaff0), read_res_hdr(0xaff0, zblock(0x0020)), dev=dev2, ctl=ctl2, sport=52000)
    for i in range(3):
        emit(cyclic(0x8201, bytes(range(40)), 300 + i, src=dev2, dst=ctl2))
        emit(cyclic(0x8202, bytes(range(40)), 300 + i, src=ctl2, dst=dev2))
        emit(cyclic(0xc201, bytes(range(40)), 300 + i, src=dev2, dst=ctl2))
        emit(cyclic(0xbc01, bytes(range(40)), 300 + i, src=dev2, dst=ctl2))
    CUR[0] = MAIN


# ----------------------------------------------------------- reproducers
def repro_frames():
    """Frames of the bugs fixed on the branch (see README): they decode cleanly with the fixes."""
    # PROFINET: Fix crashes (NULL / short link-layer addresses): the same IODWriteReqHeader twice on a link
    # without MAC addresses (raw IP, PN-RT over UDP 34962)
    body = u16(1) + bytes(range(16)) + struct.pack('>IHHHHI', 0, 1, 1, 0, 0xaff0, 0) + bytes(24)
    blk = struct.pack('>HHBB', 0x0008, 2 + len(body), 1, 0) + body
    u = struct.pack('>HHHH', 34962, 34962, 8 + 2 + 12 + len(blk), 0) + be16(0xfe01) + rta_pdu(blk)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + be16(ipsum(ip)) + ip[12:] + u
    CUR[0].append(('raw', ip))
    CUR[0].append(('raw', ip))
    # exponential re-parsing of nested blocks: a chain of PDevData and of I&M5 blocks
    emit(rta(struct.pack('>HHBBH', 0x0201, 4, 1, 0, 0) * 8))
    chain = B(0x0034, bytes(64) + bytes(64) + bytes([0, 42]) + bytes(16) + u16(1) + b'V' + bytes([1, 2, 3]))
    for n in (6, 12):
        blocks = chain
        for i in range(n):
            blocks = B(0x0025, u16(2) + chain + blocks[:0] + (B(0x0025, u16(1) + chain) if i == 0 else b''))
        emit(rta(blocks))
    # RS_TimeStatus with the optional 12 octet time stamp (the extension length is 38)
    # is part of rs_frames(); PROFIenergy float64 measurement values are part of pe_frames()
    # GSD name overflow: see gsd_frames()
    # quadratic IOCR object lists: one IOCRBlockReq with many objects, two frames
    objs = tuple((i // 2000 + 1, i % 2000 + 1, 0xffff) for i in range(300))
    for k in range(2):
        emit(rta(iocr_block_req(1, 1, 0x8f01 + k, objs=objs, iocs=(), datalen=1000), dst=MAC_G, src=MAC_F))
    # many ARs with different AR UUIDs
    for i in range(100):
        a = bytes(12) + struct.pack('>I', 0x1000 + i)
        rpc_pair(0, ar_block_req(a, name=b'ar-%d' % i), ar_block_res(a), dev=MAC_F, ctl=MAC_G, sport=40000 + i)
    # AR state that changes later in the file (-2 must show the same): connect requests and responses with
    # different frame IDs and alarm references on one AR
    ar = G('11111111-2222-3333-4444-6666666666aa')
    rpc_pair(0, ar_block_req(ar, name=b'ar-state', mac=MAC_G) + iocr_block_req(1, 1, 0x8010, objs=((0, 1, 0),), iocs=()) +
             alarm_cr_req(ref=5),
             ar_block_res(ar, mac=MAC_F) + iocr_block_res(1, 1, 0x8011) + alarm_cr_res(ref=9), dev=MAC_F, ctl=MAC_G, sport=41000)
    rpc_pair(0, ar_block_req(ar, name=b'ar-state', mac=MAC_G) + iocr_block_req(1, 1, 0x8012, objs=((0, 1, 0),), iocs=()) +
             alarm_cr_req(ref=6),
             ar_block_res(ar, mac=MAC_F) + iocr_block_res(1, 1, 0x8013) + iocr_block_res(2, 2, 0x8014) + alarm_cr_res(ref=10),
             dev=MAC_F, ctl=MAC_G, sport=41001)
    # RTC1 frames after an SXP connect carrying an IOCRBlockReq with many objects
    objs2 = tuple((i // 1000 + 1, i % 1000 + 1, 0xffff) for i in range(300))
    ioc = iocr_block_req(1, 1, 0x8901, objs=objs2, iocs=(), datalen=300)
    svc = svc_req(0x0720, sxp_endpoint() + ioc)
    emit(rt(0xfe03, sxp_rta(sxp_pkt(svc, arid=0x0401)), MAC_C, MAC_G))
    for k in range(3):
        emit(cyclic(0x8901, b'\x55' * 300, k, src=MAC_C, dst=MAC_G))
    # a FRAG whose reassembled frame is a FRAG again (nesting)
    inner = bytes(16)
    for depth in range(3):
        fr = bytes([len(inner) // 8, 0]) + inner
        inner = be16(0x8892) + be16(0xff88) + fr if depth < 2 else fr
    emit(rt(0xff88, bytes([len(inner) // 8, 0]) + inner[:0] + inner, MAC_DCP_MC, MAC_A))
    # RSI with security: an ERR-RTA shorter than the checksum
    emit(rt(0xfe42, meta(0, 1, 16) + bytes([0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04]) + bytes([0xde, 0x81, 0x3c, 0x00]) +
            u16(0x2a) + u16(1) + FILL, MAC_F, MAC_G))


def more_frames():
    # parameter begin, in the right and a wrong length
    cmd = u16(0x0040)
    emit(rta(B(0x0118, bytes(2) + AR2 + u16(1) + bytes(2) + cmd + u16(0))))
    emit(rta(B(0x0118, bytes(2) + AR2 + u16(1) + bytes(2) + cmd + u16(0) + bytes(4))))
    emit(rta(control_block(0x8118, AR2, 0x0040)))
    # release of an AR: the release frame ends the AR for the RTC1 lookup
    rpc_pair(1, control_block(0x0114, AR2, 0x0004), control_block(0x8114, AR2, 0x0008), dev=MAC_F, ctl=MAC_G, sport=42000)
    # records of the CIM station blocks and the record access policy
    emit(rta(B(0x0273, u16(2) + bytes(range(8)) + bytes(range(8, 16)))))
    emit(rta(B(0x0278, u16(2) + bytes([1, 2]) + u16(3) + u32(100) + u32(0) + u32(200) +
               bytes([2, 3]) + u16(4) + u32(100) + u32(0) + u32(200))))
    emit(rta(B(0x0278, u16(0), 1, 1)))
    emit(rta(B(0x027c, u16(2) + bytes(range(8)) + bytes(range(8, 16)))))
    emit(rta(B(0x027b, u16(2) + bytes(range(8)) + bytes(range(8, 16)))))
    emit(rta(B(0x0313, u16(2) + u16(0x0001) + u16(0x0002) + u32(5) + u32(1) + u32(0xffffffff) + u32(0) + u32(0xffff) + u32(0)
               + u16(0x0003) + u16(0x0003) + u32(5) + u32(1) + u32(9) + u32(1) + u32(0xaf00) + u32(0xaff0) + bytes(5))))
    emit(rta(B(0x0314, u16(1) + bytes(16))))
    emit(rta(B(0x0314, u16(0))))
    emit(rta(B(0x0313, b'\x01')))
    # RS_AdjustObserver: SoE digital input and an adjust block of another type
    def adj(btype, body):
        return u16(btype) + u16(len(body) + 4) + bytes([1, 0]) + bytes(2) + body
    emit(rta(B(0x0900, u16(2) + adj(0xc010, u16(5) + u16(1000) + bytes([0x40]) + bytes(3)) + adj(0x1234, b'\x01\x02\x03\x04'))))
    emit(rta(B(0x0900, u16(0))))
    # IOCR blocks with an unknown IOCR type
    emit(rta(iocr_block_req(3, 1, 0x8310, objs=(), iocs=(), mac=bytes([1, 0x0e, 0xcf, 0, 0, 1]))))
    emit(rta(iocr_block_req(7, 1, 0x8311, objs=(), iocs=())))
    emit(rta(iocr_block_res(7, 1, 0x8311)))
    emit(rta(iocr_block_res(3, 1, 0x8311)))
    # AR with the system redundancy type seen on the station pair F/G, then cyclic frames with every
    # combination of the state, redundancy and data valid bits of the data status (input and output)
    for st in range(8):
        ds = 0x30 | ((st >> 2) << 2) | (((st >> 1) & 1) << 1) | (st & 1)
        emit(cyclic(0x8f10, bytes(range(40)), 50 + st, ds, src=MAC_F, dst=MAC_G))
        emit(cyclic(0x8f11, bytes(range(40)), 50 + st, ds, src=MAC_G, dst=MAC_F))
    # AR types that have their own text, and the AR UUID of the system redundancy type
    for at, props in ((3, 0x111), (0x10, 0x111), (0x20, 0x111), (6, 0x0), (6, 0x100), (0x99, 0x111)):
        a = bytes(12) + struct.pack('>I', 0x2000 + at)
        emit(rta(ar_block_req(a, artype=at, props=props, name=b'ar-type'), dst=MAC_F, src=MAC_G))


# ------------------------------------------------------------- malformed
def malformed_frames():
    CUR[0] = MAL
    D = DCP
    # DCP: NME domain name with a block too short for the UUID
    emit(D.frame(0xfeff, D.pdu(5, 1, 1, D.blk(7, 1, be16(1) + b'\x01\x02')), MAC_A, MAC_B))
    # DCP: block longer than the data length of the PDU
    emit(D.frame(0xfeff, bytes([5, 1]) + be32(2) + be16(0) + be16(4) + D.blk(2, 2, be16(1) + b'toolongname')[:12], MAC_A, MAC_B))
    # DCP: a block that does not advance
    emit(D.frame(0xfeff, bytes([5, 1]) + be32(3) + be16(0) + be16(2) + bytes([4, 0]), MAC_A, MAC_B))
    emit(D.frame(0xfeff, bytes([5, 1]) + be32(3) + be16(0) + be16(30) + bytes([2, 2, 0, 0xff]), MAC_A, MAC_B))
    # RT frame with fewer than 6 octets
    emit(rt(0x8000, b'\x01\x02'), pad=False)
    emit(dfp_frame(0x8803, [(0x01, b'\x09\x08')], sf_crc='badlo'))   # bad CRC of a subframe the sniffing does not check
    rsi_fragmented(11, bytes(40), 5)      # a reassembled reserved operation
    # RSI requests with reserved operation numbers
    for opnum in (1, 11, 15):
        emit(rsi_frame(rsi_pdu(5, fop(opnum, 0), u32(512) + bytes(12), dst_sap=0x0001)))
    emit(rt(0xfe42, meta(0, 4, 12) + rsi_pdu(9, b'', b'') + FILL + bytes(12), MAC_B, MAC_A))   # undefined PDU type, with security
    # SXP errors flagged by the dissector: reserved endpoint field, SAM block missing, data after the SAM blocks
    for svc in (svc_req(0x0720, sxp_endpoint(res=3)),
                svc_req(0x0780, sxp_endpoint() + zblock(0x06e4) + zblock(0x06e0)),
                svc_req(0x0780, sxp_endpoint() + zblock(0x06e4) + zblock(0x06e0) + zblock(0x06e2) + zblock(0x06e3) + b'\x01\x02\x03\x04')):
        emit(rt(0xfe03, sxp_rta(sxp_pkt(svc)), MAC_B, MAC_A))
    # GenerateKeyPairAndCSR request with a certification request information the BER dissector rejects,
    # and an empty EAP message
    emit(rta(B(0x011a, u16(6) + u32(1) + u32(0) + bytes(4))))
    emit(rta(B(0x011a, u16(0x0100) + bytes(4))))
    # the field hf_pn_io_gating_cycle is never registered: PDSyncData (versions 1.0 and 1.2) and the CIM
    # NetConf data blocks are reported as a dissector bug
    emit(rta(pdsync(0)))
    emit(rta(pdsync(2)))
    emit(rta(B(0x0270, bytes(300))))
    emit(rta(B(0x0271, bytes(300))))
    # two SXP fragments of one stream in a single TCP segment: reassembled only when the frame is dissected again
    svc = svc_req(0x0721, read_req_hdr(0x8000, reclen=0) + bytes(60))
    emit(tcp_frame(sxp_pkt(svc[:40], flags=0x02, callseq=90) + sxp_pkt(svc[40:], flags=0x04, callseq=90), 50100, 34964, 1,
                   dst=MAC_D, src=MAC_E))
    # a block that declares more octets than the PDU has, an RTA with a short PDU
    emit(rta(block(0x0020, bytes(10), blen=200)))
    emit(rta(bytes(6), pdu_type=1))
    # RTA with a PDU type that is not defined: the dissector asks for more octets than exist
    emit(rta(bytes(4), pdu_type=7))
    CUR[0] = MAIN


if __name__ == '__main__':
    marks = []
    for fn in (dcp_frames, ptcp_frames, mrp_frames, mrrt_frames, pn_frames, status_frames, pd_frames, mrp_data_frames,
               sec_frames, profidrive_frames, sxp_frames, repro_frames, rsi_frames, secure_frames, rt_misc_frames,
               frag_frames, record_frames, pe_frames, alarm_frames, rs_frames, zero_block_frames, more_frames):
        first = len(MAIN) + 1
        fn()
        marks.append('%5d-%-5d %s' % (first, len(MAIN), fn.__name__))
    malformed_frames()
    write_pcapng('profinet-coverage.pcapng', MAIN)
    write_pcap('profinet-coverage-malformed.pcap', MAL)
    gsd_frames()
    write_gsd_files()
    write_pcap('profinet-coverage-gsd.pcap', GSD)
    with open(os.path.join(OUT, 'frame-ranges.txt'), 'w') as f:
        f.write('\n'.join(marks) + '\n')

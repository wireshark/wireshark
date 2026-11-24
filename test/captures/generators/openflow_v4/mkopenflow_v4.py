#!/usr/bin/env python3
# Generates test/captures/openflow_v4_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: classic pcap writer with simple TCP streams (Ethernet/IPv4/TCP).
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
    """pcapng writer: interface 0 is Ethernet, interface 1 is Exported PDU."""
    def __init__(self):
        self.frames = []
        self.ipid = 1
    def raw(self, frame, iface=0):
        self.frames.append((iface, frame))
    def epdu(self, name, data):
        """A frame holding data for the dissector called name (Exported PDU)."""
        nm = name.encode()
        tag = struct.pack('!HH', 12, (len(nm) + 3) // 4 * 4) + nm + b'\0' * (-len(nm) % 4)
        self.raw(tag + struct.pack('!HH', 0, 0) + data, 1)
    @staticmethod
    def _blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    def write(self, fn):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += self._blk(1, struct.pack('<HHI', 1, 0, 0))
        out += self._blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (ifc, f) in enumerate(self.frames):
            out += self._blk(6, struct.pack('<IIIII', ifc, 0, 1000 * i, len(f), len(f)) + f)
        open(fn, 'wb').write(out)

class Flow:
    """One TCP connection; the 'switch' is the client, the controller listens."""
    def __init__(self, pcap, sport=40000, dport=6653, handshake=True):
        self.p = pcap
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self._tcp(True, b'', 0x02)
            self.cseq += 1
            self._tcp(False, b'', 0x12)
            self.sseq += 1
            self._tcp(True, b'', 0x10)
    def _tcp(self, from_switch, data, flags=0x18):
        if from_switch:
            sp, dp, seq, ack = self.sport, self.dport, self.cseq, self.sseq
            src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
            esrc, edst = '020000000001', '020000000002'
        else:
            sp, dp, seq, ack = self.dport, self.sport, self.sseq, self.cseq
            src, dst = bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])
            esrc, edst = '020000000002', '020000000001'
        opt = b''
        if flags & 0x02:
            ack = 0 if flags == 0x02 else ack
            opt = struct.pack('!BBHBBBB', 2, 4, 1460, 4, 2, 1, 1)
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opt)) // 4) << 4, flags, 65535, 0, 0) + opt + data
        ln = len(tcp)
        pseudo = src + dst + struct.pack('!BBH', 0, 6, ln)
        c = csum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + ln, self.p.ipid, 0, 64, 6, 0, src, dst)
        self.p.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.p.raw(bytes.fromhex(edst + esrc + '0800') + ip + tcp)
    def send(self, from_switch, *pdus, split=None):
        """Send PDUs in one segment; with split=[n,...] cut the stream at these offsets."""
        data = b''.join(pdus)
        cuts = [0] + list(split or []) + [len(data)]
        for a, b in zip(cuts, cuts[1:]):
            self._tcp(from_switch, data[a:b])
            if from_switch:
                self.cseq += b - a
            else:
                self.sseq += b - a

def eth_ip_udp(payload=b'abcdefgh', sport=1234, dport=5678):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('0a0000000002' '0a0000000001' '0800') + ip + udp

def hdr(ver, typ, body=b'', xid=1, length=None):
    return struct.pack('!BBHI', ver, typ, 8 + len(body) if length is None else length, xid) + body

def pad(n):
    return b'\0' * n

def pad8(b):
    return b + b'\0' * (-len(b) % 8)

def s(name, n):
    return name.encode().ljust(n, b'\0')[:n]

def mac(i):
    return bytes([2, 0, 0, 0, 0, i & 0xff])

V = 4
PKT = eth_ip_udp()

def m(typ, body=b'', xid=1, **kw):
    return hdr(V, typ, body, xid=xid, **kw)

def oxm(field, val, mask=None, cls=0x8000):
    body = val + (mask or b'')
    return struct.pack('!HBB', cls, (field << 1) | (1 if mask else 0), len(body)) + body

def match(*oxms):
    body = b''.join(oxms)
    ln = 4 + len(body)
    return struct.pack('!HH', 1, ln) + body + pad(-ln % 8)

def u8(v): return struct.pack('!B', v)
def u16(v): return struct.pack('!H', v)
def u24(v): return struct.pack('!I', v)[1:]
def u32(v): return struct.pack('!I', v)
def u64(v): return struct.pack('!Q', v)
def ip4(a): return bytes(int(x) for x in a.split('.'))
IP6 = bytes.fromhex('20010db8000000000000000000000001')
IP6M = bytes.fromhex('ffffffffffffffff0000000000000000')

# One OXM of every kind (value, optional mask)
ALL_OXM = [
    oxm(0, u32(1)), oxm(1, u32(2)), oxm(2, u64(7), u64(0xff)),
    oxm(3, mac(1)), oxm(3, mac(1), b'\xff\xff\xff\xff\xff\x00'), oxm(4, mac(2)),
    oxm(5, u16(0x0800)), oxm(6, u16(0x1064)), oxm(6, u16(0x1000), u16(0x1000)),
    oxm(7, u8(3)), oxm(8, u8(10)), oxm(9, u8(1)), oxm(10, u8(17)),
    oxm(11, ip4('10.0.0.1')), oxm(11, ip4('10.0.0.0'), ip4('255.255.255.0')), oxm(12, ip4('10.0.0.2')),
    oxm(13, u16(80)), oxm(14, u16(81)), oxm(15, u16(53)), oxm(16, u16(54)),
    oxm(17, u16(1)), oxm(18, u16(2)), oxm(19, u8(8)), oxm(20, u8(0)),
    oxm(21, u16(1)), oxm(22, ip4('10.1.1.1')), oxm(22, ip4('10.1.1.0'), ip4('255.255.255.0')),
    oxm(23, ip4('10.1.1.2')), oxm(24, mac(3)), oxm(25, mac(4)),
    oxm(26, IP6), oxm(26, IP6, IP6M), oxm(27, IP6), oxm(28, u32(0x12345)),
    oxm(29, u8(135)), oxm(30, u8(0)), oxm(31, IP6), oxm(32, mac(5)), oxm(33, mac(6)),
    oxm(34, u24(1000)), oxm(34, u32(1000)), oxm(35, u8(5)), oxm(36, u8(1)),
    oxm(37, u24(0x123456)), oxm(38, u64(0x1122334455667788), u64(0xffffffff)),
    oxm(39, u16(0x1ff)),
    oxm(5, u16(0x0800), u16(0xffff)),               # generic mask path via a field with a mask
    oxm(0x7f, b'\x01\x02'),                          # unknown basic field, value
    oxm(0x7e, b'\x01\x02\x03\x04', b'\xff\xff\x00\x00'),
    oxm(0, b'\x01\x02\x03\x04\x05\x06', cls=0x0001),   # NXM class (unknown body)
    oxm(1, b'\xaa\xbb\xcc\xdd\xee', cls=0x0000),
    struct.pack('!HBBI', 0xffff, 0x00, 8, 0x00002320) + b'\xde\xad\xbe\xef',  # experimenter OXM
]
EXPER = 0x00002320

def act_out(port=1, maxlen=0xffff): return struct.pack('!HHIH', 0, 16, port, maxlen) + pad(6)
def act_s4(t, v=0): return struct.pack('!HH', t, 8) + u32(v)
def act_ethertype(t, et=0x8847): return struct.pack('!HH', t, 8) + u16(et) + pad(2)
def act_ttl(t, ttl=64): return struct.pack('!HH', t, 8) + u8(ttl) + pad(3)
def act_setfield(o):
    b = o
    ln = 4 + len(b)
    ln += -ln % 8
    return struct.pack('!HH', 25, ln) + b + pad(ln - 4 - len(b))
def act_exp(): return struct.pack('!HHI', 0xffff, 16, EXPER) + b'\x01\x02\x03\x04\x05\x06\x07\x08'
def act_unknown(): return struct.pack('!HH', 99, 8) + b'\0\0\0\0'

ALL_ACTIONS = [
    act_out(), act_out(0xfffffffd), act_s4(11), act_s4(12), act_ttl(15), act_s4(16),
    act_ethertype(17, 0x8100), act_s4(18), act_ethertype(19), act_ethertype(20),
    act_s4(21, 3), act_s4(22, 9), act_ttl(23), act_s4(24),
    act_setfield(oxm(6, u16(0x1064))), act_setfield(oxm(3, mac(7))),
    act_ethertype(26, 0x88e7), act_s4(27), act_exp(), act_unknown(),
]

def instr_goto(t=1): return struct.pack('!HH', 1, 8) + u8(t) + pad(3)
def instr_meta(): return struct.pack('!HH', 2, 24) + pad(4) + u64(5) + u64(0xff)
def instr_acts(t, acts): return struct.pack('!HH', t, 8 + sum(len(a) for a in acts)) + pad(4) + b''.join(acts)
def instr_meter(i=1): return struct.pack('!HH', 6, 8) + u32(i)
def instr_exp(): return struct.pack('!HHI', 0xffff, 16, EXPER) + b'\x05\x06\x07\x08\x05\x06\x07\x08'
def instr_unknown(): return struct.pack('!HH', 77, 8) + b'\0\0\0\0'

ALL_INSTR = [instr_goto(), instr_meta(), instr_acts(3, [act_out(2)]), instr_acts(4, ALL_ACTIONS),
             instr_acts(5, []), instr_meter(), instr_exp(), instr_unknown()]

def port(n, name='eth', cfg=0xf, state=7, curr=0xffff, speed=1000000):
    return (u32(n) + pad(4) + mac(n) + pad(2) + s('%s%d' % (name, n), 16) +
            struct.pack('!IIIIIIII', cfg, state, curr, curr, curr, curr, speed, speed * 10))

def bucket(acts, weight=1, wport=0xffffffff, wgroup=0xffffffff):
    body = b''.join(acts)
    return struct.pack('!HHII', 16 + len(body), weight, wport, wgroup) + pad(4) + body

def band(typ, rate=1000, burst=10, prec=0):
    if typ == 1: return struct.pack('!HHII', 1, 16, rate, burst) + pad(4)
    if typ == 2: return struct.pack('!HHII', 2, 16, rate, burst) + u8(prec) + pad(3)
    if typ == 0xffff: return struct.pack('!HHII', 0xffff, 20, rate, burst) + u32(EXPER) + b'\x01\x02\x03\x04'
    return struct.pack('!HHII', typ, 16, rate, burst) + pad(4)

def flow_mod(cmd=0, mt=None, instrs=(), table=0, flags=0x1f, buffer=0xffffffff, out_port=0xffffffff, out_group=0xffffffff, cookie=1):
    return (u64(cookie) + u64(0xffff) + struct.pack('!BBHHHIIIH', table, cmd, 10, 20, 100, buffer, out_port, out_group, flags) + pad(2) +
            (mt if mt is not None else match(*ALL_OXM[:6])) + b''.join(instrs))

def mp_req(t, body=b'', flags=0): return m(18, struct.pack('!HH', t, flags) + pad(4) + body)
def mp_rep(t, body=b'', flags=0): return m(19, struct.pack('!HH', t, flags) + pad(4) + body)

def flow_stats_req(mt=None, table=0xff):
    return struct.pack('!B3xII4x', table, 0xffffffff, 0xffffffff) + u64(0) + u64(0) + (mt if mt is not None else match(oxm(0, u32(1))))

def table_prop(typ, body):
    ln = 4 + len(body)
    return struct.pack('!HH', typ, ln) + body + pad(-ln % 8)

def table_features(tid, props, name='tbl'):
    body = struct.pack('!B5x', tid) + s(name + str(tid), 32) + u64(0xff) + u64(0xff) + u32(3) + u32(1024) + b''.join(props)
    return u16(2 + len(body)) + body

def oxm_id(field, ln=4, cls=0x8000, hm=0): return struct.pack('!HBB', cls, (field << 1) | hm, ln)

def flow_stats_entry(mt, instrs, table=1):
    body = (struct.pack('!BxIIHHHH', table, 10, 20, 100, 30, 40, 0x3) + pad(4) + u64(7) + u64(8) + u64(9) + mt + b''.join(instrs))
    return u16(2 + len(body)) + body

def group_desc(typ, gid, buckets):
    body = struct.pack('!BxI', typ, gid) + b''.join(buckets)
    return u16(2 + len(body)) + body

def group_stats(gid, counters):
    body = pad(2) + u32(gid) + u32(2) + pad(4) + u64(100) + u64(200) + u32(5) + u32(6) + b''.join(u64(i) + u64(i * 2) for i in range(counters))
    return u16(2 + len(body)) + body

def meter_stats(mid, nb):
    body = u32(mid)[:0]
    rest = pad(6) + u32(2) + u64(10) + u64(20) + u32(3) + u32(4) + b''.join(u64(i) + u64(i * 3) for i in range(nb))
    return u32(mid) + u16(4 + 2 + len(rest)) + rest

def meter_config(mid, bands, flags=0xf):
    body = u16(flags) + u32(mid) + b''.join(bands)
    return u16(2 + len(body)) + body

def queue(qid, pn, props):
    body = pad(6) + b''.join(props)
    return u32(qid) + u32(pn) + u16(8 + 2 + len(body)) + body

def qprop(t, rate=100):
    if t in (1, 2):
        return struct.pack('!HH4xH6x', t, 16, rate)
    if t == 0xffff:
        return struct.pack('!HH4xI4x', t, 20, EXPER) + b'\x01\x02\x03\x04'
    return struct.pack('!HH4x', t, 12) + b'\x00\x00\x00\x00'

def build_inner():
    """Messages that are embedded in OFPT_ERROR."""
    return [
        m(14, flow_mod(instrs=ALL_INSTR[:4])),
        m(10, struct.pack('!IHBBQ', 5, len(PKT), 1, 0, 9) + match(oxm(0, u32(1))) + pad(2) + PKT),
        m(19, struct.pack('!HH4x', 5, 0) + b''.join(u32(1) + u32(i) + u64(1) + u64(2) + u64(3) + u32(4) + u32(5) for i in range(2))),
        m(13, struct.pack('!IIH6x', 0xffffffff, 0xfffffffd, 16) + act_out() + PKT),
        m(2, b'echo'),
    ]

def error_chain(depth):
    """OFPT_ERROR containing an OFPT_ERROR ... depth levels of nesting, innermost an Echo."""
    inner = m(2, b'x')
    for i in range(depth):
        inner = m(1, u16(1) + u16(i % 8) + inner, xid=100 + i)
    return inner

def build():
    pc = Pcap()
    f = Flow(pc)
    # hello: version bitmap, odd bitmap size (padding), unknown element, only unknown elements
    bm = struct.pack('!HHI', 1, 8, 0x12)
    f.send(True, m(0, bm))
    f.send(False, m(0, struct.pack('!HH', 1, 6) + b'\x12\x00' + pad(2)))
    f.send(False, m(0, struct.pack('!HHI', 1, 8, 0x12) + struct.pack('!HH', 99, 12) + b'\1\2\3\4\5\6\7\x08' + pad(4) + struct.pack('!HH', 1, 4) + pad(4)))
    f.send(True, m(0, b'abc'[:0]))
    # errors: every error type, and codes
    for et in range(14):
        if et == 0:
            f.send(True, m(1, u16(0) + u16(1) + b'incompatible version'))
        else:
            f.send(True, m(1, u16(et) + u16(1) + build_inner()[(et % 5)][:]))
    f.send(True, m(1, u16(0xffff) + u16(1) + u32(EXPER) + b'expdata'))
    f.send(True, m(1, u16(0x1234) + u16(1) + b'unknown'))
    for inner in build_inner():
        f.send(True, m(1, u16(1) + u16(0) + inner))
    # nesting: up to and beyond the limit of 4 nested messages
    for d in (1, 2, 3, 4, 5, 6, 8):
        f.send(True, error_chain(d))
    # echo, experimenter
    f.send(False, m(2, b'ping'), m(3, b'pong'), m(2))
    f.send(True, m(4, u32(EXPER) + u32(1) + b'data'))
    f.send(True, m(4, u32(EXPER) + u32(1)))
    # features
    f.send(False, m(5))
    f.send(True, m(6, struct.pack('!QIBB2xII', 0x0001020304050607, 256, 8, 1, 0x1ef, 0)))
    f.send(True, m(6, struct.pack('!QIBB2xII', 5, 0, 1, 0, 0, 0)))
    # config
    f.send(False, m(7))
    f.send(True, m(8, struct.pack('!HH', 0, 128)))
    f.send(False, m(9, struct.pack('!HH', 3, 0xffff)))
    f.send(False, m(9, struct.pack('!HH', 1, 0xffe5)))
    # packet in with every match, and data
    for i, o in enumerate(ALL_OXM[:8] + ALL_OXM[8:]):
        pass
    f.send(True, m(10, struct.pack('!IHBBQ', 0xffffffff, len(PKT), 0, 0, 1) + match(*ALL_OXM[:14]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, len(PKT), 1, 5, 2) + match(*ALL_OXM[14:30]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, len(PKT), 2, 6, 3) + match(*ALL_OXM[30:44]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + match(*ALL_OXM[44:]) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + match() + pad(2)))
    # standard (deprecated) match and unknown match type
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 0, 12) + pad(8) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 0, 4) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 7, 8) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 7, 4) + pad(4) + pad(2)))
    # flow removed
    for reason in range(4):
        f.send(True, m(11, struct.pack('!QHBBIIHHQQ', 0x1122, 100, reason, 3, 10, 500, 30, 40, 1000, 64000) + match(*ALL_OXM[:6])))
    # port status
    for reason in range(3):
        f.send(True, m(12, u8(reason) + pad(7) + port(1 + reason)))
    # packet out
    f.send(False, m(13, struct.pack('!IIH6x', 0xffffffff, 0xfffffffd, sum(map(len, ALL_ACTIONS))) + b''.join(ALL_ACTIONS) + PKT))
    f.send(False, m(13, struct.pack('!IIH6x', 7, 1, 16) + act_out()))
    # flow mod
    for cmd in range(5):
        f.send(False, m(14, flow_mod(cmd=cmd, instrs=ALL_INSTR)))
    f.send(False, m(14, flow_mod(mt=match(*ALL_OXM), instrs=[])))
    f.send(False, m(14, flow_mod(mt=match(*ALL_OXM[14:]), instrs=[instr_unknown()], flags=0)))
    # group mod
    for cmd in range(3):
        f.send(False, m(15, struct.pack('!HBxI', cmd, cmd, 5 + cmd) + bucket(ALL_ACTIONS[:5]) + bucket([act_out(3)], 5, 3, 4)))
    f.send(False, m(15, struct.pack('!HBxI', 0, 2, 5)))
    # port mod, table mod
    f.send(False, m(16, u32(1) + pad(4) + mac(1) + pad(2) + struct.pack('!IIII', 0x7f, 0x7f, 0xffff, 0) ))
    f.send(False, m(17, struct.pack('!B3xI', 0xff, 3)))
    # multipart requests
    for t in (0, 3, 8, 11, 13):
        f.send(False, mp_req(t))
    f.send(False, mp_req(1, flow_stats_req(), flags=1))
    f.send(False, mp_req(1, flow_stats_req(match(*ALL_OXM[:20]))))
    f.send(False, mp_req(2, flow_stats_req(match())))
    f.send(False, mp_req(4, u32(0xffffffff) + pad(4)))
    f.send(False, mp_req(5, u32(1) + u32(0xffffffff)))
    f.send(False, mp_req(6, u32(0xfffffffc) + pad(4)))
    f.send(False, mp_req(7))
    f.send(False, mp_req(9, u32(0xffffffff) + pad(4)))
    f.send(False, mp_req(10, u32(1) + pad(4)))
    f.send(False, mp_req(12))
    f.send(False, mp_req(12, table_features(0, []) + table_features(1, [])))
    f.send(False, mp_req(0xffff, u32(EXPER) + u32(7) + b'ext'))
    f.send(False, mp_req(0xffff, u32(EXPER) + u32(7)))
    f.send(False, mp_req(77, b'abcd'))
    # table features with all property types
    props = [
        table_prop(0, b''.join([struct.pack('!HH', 1, 4), struct.pack('!HH', 3, 4), struct.pack('!HHI', 0xffff, 8, EXPER)])),
        table_prop(1, struct.pack('!HH', 4, 4)),
        table_prop(2, bytes([1, 2, 3])),
        table_prop(3, bytes([2])),
        table_prop(4, b''.join([struct.pack('!HH', 0, 4), struct.pack('!HHI', 0xffff, 8, EXPER)])),
        table_prop(5, struct.pack('!HH', 22, 4)),
        table_prop(6, struct.pack('!HH', 0, 4)),
        table_prop(7, struct.pack('!HH', 0, 4)),
        table_prop(8, oxm_id(0) + oxm_id(3, 12, hm=1) + oxm_id(11, 8, hm=1)),
        table_prop(10, oxm_id(0) + oxm_id(5, 2)),
        table_prop(12, oxm_id(0, 4)),
        table_prop(13, oxm_id(0, 4)),
        table_prop(14, oxm_id(0, 4)),
        table_prop(15, oxm_id(0, 4)),
        table_prop(0xfffe, u32(EXPER) + u32(5) + b'data'),
        table_prop(0xffff, u32(EXPER) + u32(5)),
        table_prop(99, b'\1\2\3\4'),
        struct.pack('!HH', 9, 4) + pad(4),
    ]
    f.send(False, mp_req(12, table_features(0, props)))
    # multipart replies
    f.send(True, mp_rep(0, s('mfr', 256) + s('hw', 256) + s('sw', 256) + s('1234', 32) + s('dp', 256)))
    f.send(True, mp_rep(1, flow_stats_entry(match(*ALL_OXM[:8]), ALL_INSTR[:4]) + flow_stats_entry(match(), [instr_goto()], 2), flags=1))
    f.send(True, mp_rep(1, b''))
    f.send(True, mp_rep(2, u64(100) + u64(200) + u32(3) + pad(4)))
    f.send(True, mp_rep(3, b''.join(u8(i) + pad(3) + u32(10 + i) + u64(100) + u64(50) for i in range(3))))
    f.send(True, mp_rep(4, b''.join(u32(i) + pad(4) + b''.join(u64(i * 10 + j) for j in range(12)) + u32(5) + u32(6) for i in range(2))))
    f.send(True, mp_rep(5, b''.join(u32(1) + u32(i) + u64(1) + u64(2) + u64(3) + u32(4) + u32(5) for i in range(2))))
    f.send(True, mp_rep(6, group_stats(1, 2) + group_stats(2, 0)))
    f.send(True, mp_rep(7, group_desc(0, 1, [bucket([act_out(1)]), bucket(ALL_ACTIONS[:4])]) + group_desc(3, 2, [])))
    f.send(True, mp_rep(8, u32(0xf) + u32(0x7) + u32(1000) + u32(2000) + u32(3000) + u32(4000) + b''.join(u32(0xffff + i) for i in range(4))))
    f.send(True, mp_rep(9, meter_stats(1, 2) + meter_stats(2, 0)))
    f.send(True, mp_rep(10, meter_config(1, [band(1), band(2, prec=3)]) + meter_config(2, [])))
    f.send(True, mp_rep(11, struct.pack('!IIIBB2x', 256, 0x6, 0xf, 4, 8)))
    f.send(True, mp_rep(12, table_features(0, props) + table_features(1, [])))
    f.send(True, mp_rep(13, port(1) + port(2) + port(3, curr=0)))
    # barrier, queue get config
    f.send(False, m(20))
    f.send(True, m(21))
    f.send(False, m(22, u32(1) + pad(4)))
    f.send(True, m(23, u32(1) + pad(4) + queue(1, 1, [qprop(1), qprop(2), qprop(0xffff), qprop(9)]) + queue(2, 1, [])))
    # role, async
    f.send(False, m(24, u32(2) + pad(4) + u64(77)))
    f.send(True, m(25, u32(2) + pad(4) + u64(77)))
    f.send(False, m(26))
    async_body = b''.join(u32(i + 1) for i in range(6))
    f.send(True, m(27, async_body))
    f.send(False, m(28, async_body))
    # meter mod
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(1) + band(2)))
    f.send(False, m(29, u16(2) + u16(1) + u32(1)))
    # experimenter and unknown bands: the length of their body counts from the start of the
    # message, so these only decode while enough bands follow them
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(0xffff) + band(1) + band(1) + band(1)))
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(7) + band(1) + band(1) + band(1)))
    # lengths below the minimum are raised to it: an instruction of length 4 (the goto body
    # follows) and a bucket of length 8
    f.send(False, m(14, flow_mod(instrs=[struct.pack('!HH', 1, 4) + u8(1) + pad(3)])))
    f.send(False, m(15, struct.pack('!HBxI', 0, 0, 5) + struct.pack('!HHII', 8, 1, 1, 1) + pad(4)))
    # unknown message type
    f.send(True, m(99, b'unknown'))
    f.send(True, m(99))
    # reassembly: a flow mod over three segments, and several PDUs in a segment
    big = m(14, flow_mod(mt=match(*ALL_OXM), instrs=ALL_INSTR))
    f.send(False, big, split=[20, 150])
    f.send(True, m(2, b'a'), m(3, b'b'), m(20), m(2, b'cc'))
    # Exported PDU: the top-level dissector uses only the header length, data after it is ignored
    pc.epdu('openflow_v4', m(2, b'ping') + b'trailing data after the message')
    pc.epdu('openflow_v4', m(14, flow_mod(instrs=[instr_goto()])) + pad(40))
    pc.epdu('openflow_v4', m(1, u16(1) + u16(0) + m(2, b'in')) + b'garbage' * 4)
    pc.epdu('openflow_v4', error_chain(6))
    pc.write(os.path.join(OUT, 'openflow_v4-coverage.pcapng'))

def build_mal():
    pc = Pcap()
    f = Flow(pc)
    # nesting of 600 errors in a single PDU
    inner = m(2, b'x')
    for i in range(5000):
        inner = m(1, u16(1) + u16(0) + inner)
        if len(inner) > 65000:
            break
    inner = inner[:65000] if len(inner) > 65000 else inner
    f.send(True, inner[:2] + u16(len(inner)) + inner[4:])
    # hello element with a length below 4
    f.send(True, m(0, struct.pack('!HH', 1, 2) + pad(4)))
    f.send(True, m(0, struct.pack('!HH', 99, 3) + pad(4)))
    # these are always malformed: the length of the body uses the wrong base (see README)
    f.send(True, mp_rep(0xffff, u32(EXPER) + u32(7) + b'ext'))
    f.send(True, mp_rep(77, b'abcd'))
    f.send(True, mp_rep(10, meter_config(1, [band(0xffff)])))
    f.send(True, mp_rep(10, meter_config(1, [band(7)])))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + band(0xffff)))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + band(7)))
    # truncated bodies
    for t in (1, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 25, 27, 29, 4):
        f.send(True, m(t, b'\0\1'))
    for t in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0xffff):
        f.send(True, mp_req(t, b'\0\1'))
        f.send(True, mp_rep(t, b'\0\1'))
    f.send(True, m(1, u16(1)))
    f.send(True, m(1, u16(0xffff) + u16(1) + b'ab'))
    f.send(True, m(1, u16(1) + u16(1) + b'\x04\x02\x00\x04'))        # nested message with a bogus length
    f.send(True, m(1, u16(1) + u16(1) + b'\x04\x02\x00\x20' + pad(8)))
    # OXM and actions with bad lengths, instruction lengths below the header
    f.send(True, m(14, flow_mod(mt=struct.pack('!HHHBB', 1, 12, 0x8000, 0, 8) + pad(4))))
    f.send(True, m(14, flow_mod(mt=struct.pack('!HH', 1, 8) + oxm(0, u32(1))[:4], instrs=[]) ))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 4, 2) + pad(4)])))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 4, 8) + pad(4) + struct.pack('!HH', 0, 2) + pad(12)])))
    f.send(True, m(14, flow_mod(instrs=[instr_acts(4, [struct.pack('!HH', 25, 4)])])))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 0xffff, 4) + pad(4)])))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 77, 3) + pad(8)])))
    f.send(True, m(14, flow_mod(instrs=[instr_acts(4, [struct.pack('!HH', 0xffff, 4) + pad(8)])])))
    f.send(True, m(14, flow_mod(instrs=[instr_acts(4, [struct.pack('!HH', 99, 3) + pad(8)])])))
    f.send(True, m(14, flow_mod(mt=struct.pack('!HH', 0, 3) + pad(8))))
    f.send(True, m(14, flow_mod(mt=struct.pack('!HH', 5, 3) + pad(8))))
    f.send(True, m(14, flow_mod(mt=struct.pack('!HH', 1, 4 + 6) + struct.pack('!HBB', 0xffff, 0, 2) + pad(8))))
    f.send(True, m(15, struct.pack('!HBxI', 0, 0, 5) + struct.pack('!HHII', 4, 1, 1, 1) + pad(16)))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + struct.pack('!HHII', 0xffff, 4, 1, 1) + pad(8)))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + struct.pack('!HHII', 77, 4, 1, 1) + pad(8)))
    f.send(True, mp_rep(7, group_desc(0, 1, [struct.pack('!HHII', 4, 1, 1, 1) + pad(16)])))
    f.send(True, mp_rep(12, u16(80) + pad(60) + struct.pack('!HH', 0, 2) + pad(8)))
    f.send(True, mp_rep(12, table_features(0, [struct.pack('!HH', 1, 3) + pad(8)])))
    f.send(True, mp_rep(12, table_features(0, [struct.pack('!HH', 1, 4) + b'\x00\x01']), ))
    f.send(True, mp_rep(12, table_features(0, [struct.pack('!HH', 0xfffe, 4) + pad(8)])))
    f.send(True, mp_rep(9, u32(1) + u16(10) + pad(32)))
    f.send(True, mp_rep(10, u16(4) + pad(2) + pad(8)))
    f.send(True, mp_rep(5, pad(20)))
    f.send(True, m(23, u32(1) + pad(4) + u32(1) + u32(1) + u16(16) + pad(6) + struct.pack('!HH4x', 1, 4) + pad(8)))
    f.send(True, m(23, u32(1) + pad(4) + u32(1) + u32(1) + u16(16) + pad(6) + struct.pack('!HH4x', 0xffff, 8) + pad(8)))
    # message whose length field is below the header; Exported PDU where the header length exceeds the data
    pc.epdu('openflow_v4', hdr(4, 2, b'ab', length=6))
    pc.epdu('openflow_v4', hdr(4, 2, b'abcd', length=100))
    pc.epdu('openflow_v4', hdr(4, 14, b'', length=8))
    pc.write(os.path.join(OUT, 'openflow_v4-coverage-malformed.pcapng'))

if __name__ == '__main__':
    OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
    build()
    build_mal()

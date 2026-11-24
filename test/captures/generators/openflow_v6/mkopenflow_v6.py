#!/usr/bin/env python3
# Generates test/captures/openflow_v6_coverage.pcapng.gz
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
        if split is None and len(data) > 60000:
            split = [30000]
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

V = 6
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
    oxm(41, u8(1)), oxm(42, u16(0x12), u16(0x1f)), oxm(43, u32(5)),
    oxm(44, u16(0) + u16(0x0800)), oxm(44, u16(1) + u16(0x86dd)), oxm(44, u16(0xffff) + u16(7)),
    oxm(1, u64(0x11), cls=0x8001), oxm(2, u64(0x22), u64(0xff), cls=0x8001),   # packet registers
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
def act_copyfield(): return struct.pack('!HHHHHH', 28, 12, 32, 8, 16, 0)   # the dissector reads 12 octets (no OXM ids)
def act_meter(i=3): return struct.pack('!HH', 29, 8) + u32(i)

ALL_ACTIONS = [
    act_out(), act_out(0xfffffffd), act_s4(11), act_s4(12), act_ttl(15), act_s4(16),
    act_ethertype(17, 0x8100), act_s4(18), act_ethertype(19), act_ethertype(20),
    act_s4(21, 3), act_s4(22, 9), act_ttl(23), act_s4(24),
    act_setfield(oxm(6, u16(0x1064))), act_setfield(oxm(3, mac(7))),
    act_ethertype(26, 0x88e7), act_s4(27), act_copyfield(), act_meter(), act_exp(), act_unknown(),
]

def instr_goto(t=1): return struct.pack('!HH', 1, 8) + u8(t) + pad(3)
def instr_meta(): return struct.pack('!HH', 2, 24) + pad(4) + u64(5) + u64(0xff)
def instr_acts(t, acts): return struct.pack('!HH', t, 8 + sum(len(a) for a in acts)) + pad(4) + b''.join(acts)
def instr_meter(i=1): return struct.pack('!HH', 6, 8) + u32(i)
def instr_exp(): return struct.pack('!HHI', 0xffff, 16, EXPER) + b'\x05\x06\x07\x08\x05\x06\x07\x08'
def instr_unknown(): return struct.pack('!HH', 77, 8) + b'\0\0\0\0'

def oxs(field, val, cls=0x8002):
    return struct.pack('!HBB', cls, field << 1, len(val)) + val

def stats(*fields):
    body = b''.join(fields)
    ln = 4 + len(body)
    return pad(2) + u16(ln) + body + pad(-ln % 8)

ALL_FILL = []
def instr_big(n=0): return b''
def act_big(n=3000): return struct.pack('!HHI', 0xffff, 8 + n, EXPER) + bytes(n)

ALL_OXS = [oxs(0, u32(10) + u32(500)), oxs(1, u32(3) + u32(4)), oxs(3, u32(7)), oxs(4, u64(1000)), oxs(5, u64(64000)),
           oxs(9, b'abcd', cls=0xffff), oxs(8, b'abcdefgh', cls=0xffff)]

def instr_trigger(fields, flags=3):
    body = u32(flags) + stats(*fields)
    return struct.pack('!HH', 7, 4 + len(body)) + body

ALL_INSTR = [instr_goto(), instr_meta(), instr_acts(3, [act_out(2)]), instr_acts(4, ALL_ACTIONS),
             instr_acts(5, []), instr_meter(), instr_trigger(ALL_OXS[:5]), instr_exp(), instr_unknown()]

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


def flow_mod(cmd=0, mt=None, instrs=(), table=0, flags=0x1f, buffer=0xffffffff, out_port=0xffffffff, out_group=0xffffffff, cookie=1, importance=0):
    return (u64(cookie) + u64(0xffff) + struct.pack('!BBHHHIIIHH', table, cmd, 10, 20, 100, buffer, out_port, out_group, flags, importance) +
            (mt if mt is not None else match(*ALL_OXM[:6])) + b''.join(instrs) + instr_big())

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

def flow_desc(mt, instrs, st, table=1):
    body = (pad(2) + struct.pack('!BxHHHHH', table, 100, 30, 40, 0x3, 7) + u64(7) + mt + stats(*st) + b''.join(instrs) + instr_big())
    return u16(2 + len(body)) + body

def flow_stats_entry(mt, st, table=1, prio=100):
    # the dissector's header is 7 octets: length, 1 octet of padding, table, reason, priority
    body = pad(1) + struct.pack('!BBH', table, 1, prio) + mt + stats(*st, *ALL_FILL)
    return u16(2 + len(body)) + body

def group_desc(typ, gid, buckets):
    body = struct.pack('!BxI', typ, gid) + b''.join(buckets)
    return u16(2 + len(body)) + body

def group_stats(gid, counters):
    body = pad(2) + u32(gid) + u32(2) + pad(4) + u64(100) + u64(200) + u32(5) + u32(6) + b''.join(u64(i) + u64(i * 2) for i in range(counters))
    return u16(2 + len(body)) + body

def meter_stats(mid, nb):
    rest = pad(6) + u32(2) + u64(10) + u64(20) + u32(3) + u32(4) + b''.join(u64(i) + u64(i * 3) for i in range(nb))
    return u32(mid) + u16(4 + 2 + len(rest)) + rest

def meter_config(mid, bands, flags=0xf):
    body = u16(flags) + u32(mid) + b''.join(bands)
    return u16(2 + len(body)) + body

# ---- properties (OpenFlow 1.4) ----
def pd_eth(curr=0xffff):
    return struct.pack('!HH', 0, 32) + pad(4) + struct.pack('!IIIIII', curr, curr, curr, curr, 1000000, 10000000)

def pd_opt():
    return struct.pack('!HH', 1, 40) + pad(4) + struct.pack('!IIIIIIIHH', 0xf, 100, 200, 25, 300, 400, 50, 10, 20)

def port(n, props=(), cfg=0xf, state=7):
    body = b''.join(props)
    return (u32(n) + u16(40 + len(body)) + pad(2) + mac(n) + pad(2) + s('eth%d' % n, 16) + struct.pack('!II', cfg, state) + body)

def ps_eth():
    return struct.pack('!HH', 0, 40) + pad(4) + u64(1) + u64(2) + u64(3) + u64(4)

def ps_opt():
    return struct.pack('!HH', 1, 44) + pad(4) + struct.pack('!IIIIIIIHHHH', 0x7f, 100, 200, 25, 300, 400, 50, 1, 2, 3, 4)

def port_stats(n, props=()):
    body = b''.join(props)
    return u16(80 + len(body)) + pad(2) + u32(n) + u32(5) + u32(6) + b''.join(u64(n * 10 + j) for j in range(8)) + body

def queue_stats(pn, qid, props=()):
    body = b''.join(props)
    return u16(44 + len(body)) + pad(2) + u32(pn) + u32(qid) + u64(1) + u64(2) + u64(3) + u32(4) + u32(5) + body

def qs_exp(extra=4):
    return struct.pack('!HHII', 0xffff, 12 + extra, EXPER, 9) + b'\xaa' * extra

def qs_unknown():
    return struct.pack('!HH', 5, 8) + pad(4)

def tm_prop(t):
    if t == 2: return struct.pack('!HHI', 2, 8, 7)
    if t == 3: return struct.pack('!HHBBBB', 3, 8, 20, 80, 50, 0)
    if t == 0xffff: return struct.pack('!HHII', 0xffff, 16, EXPER, 3) + b'\1\2\3\4'
    return struct.pack('!HH', t, 8) + b'\1\2\3\4'

def table_desc(tid, props=()):
    body = b''.join(props)
    return u16(8 + len(body)) + u8(tid) + pad(1) + u32(3) + body

def qd_prop(t):
    if t in (1, 2): return struct.pack('!HH4xH6x', t, 16, 500)
    if t == 0xffff: return struct.pack('!HH4xII', 0xffff, 20, EXPER, 5) + b'\1\2\3\4'
    return struct.pack('!HH4x', t, 12) + b'\1\2\3\4'

def queue_desc(pn, qid, props=()):
    body = b''.join(props)
    return u32(pn) + u32(qid) + u16(14 + len(body)) + pad(4) + body   # the dissector's header is 14 octets, not 16

def fm_update(ev, instrs=(), mt=None, table=1):
    if ev in (0, 1, 2, 3):
        body = (u8(table) + u8(1 if ev == 2 else 0) + struct.pack('!HHH', 10, 20, 100) + pad(4) + u64(5) +
                (mt if mt is not None else match(oxm(0, u32(1)))) + b''.join(instrs) + instr_big())
        return u16(4 + len(body)) + u16(ev) + body
    if ev == 4:
        return u16(8) + u16(4) + u32(77)
    if ev in (5, 6):
        return u16(8) + u16(ev) + pad(4)
    return u16(8) + u16(ev) + pad(4)

def async_prop(t, v=0x7):
    if t >= 0xfffe:
        return struct.pack('!HHII', t, 16, EXPER, 3) + b'\1\2\3\4'
    if t > 11:
        return struct.pack('!HH', t, 8) + pad(4)
    return struct.pack('!HHI', t, 8, v)

def bundle_prop(t):
    if t == 1: return bundle_time_prop()
    if t == 0xffff: return struct.pack('!HHII', t, 16, EXPER, 1) + b'\1\2\3\4'
    return struct.pack('!HH', t, 8) + b'\1\2\3\4'

def pmod_prop(t):
    if t == 0: return struct.pack('!HHI', 0, 8, 0xffff)
    if t == 1: return struct.pack('!HHIIIII', 1, 24, 0xf, 100, 5, 25, 3)
    if t == 0xffff: return struct.pack('!HHII', t, 16, EXPER, 1) + b'\1\2\3\4'
    return struct.pack('!HH', t, 8) + b'\1\2\3\4'

def build_inner():
    """Messages that are embedded in other messages."""
    return [
        m(14, flow_mod(instrs=ALL_INSTR[:4])),
        m(10, struct.pack('!IHBBQ', 5, len(PKT), 1, 0, 9) + match(oxm(0, u32(1))) + pad(2) + PKT),
        m(19, struct.pack('!HH4x', 5, 0) + queue_stats(1, 1, [qs_exp()]) + queue_stats(1, 2)),
        m(13, struct.pack('!IH2x', 0xffffffff, 16) + match(oxm(0, u32(1))) + act_out() + PKT),
        m(2, b'echo'),
    ]

def chain(depth, typ):
    """typ 1: Error, 32: RequestForward, 34: BundleAdd; innermost an Echo."""
    inner = m(2, b'x')
    for i in range(depth):
        if typ == 1:
            inner = m(1, u16(1) + u16(i % 8) + inner, xid=100 + i)
        elif typ == 32:
            inner = m(32, inner, xid=100 + i)
        else:
            inner = m(34, u32(i) + pad(2) + u16(3) + inner, xid=100 + i)
    return inner

def proplen_loop(ver=None):
    """The reproducer of the endless loop (report-s7): OFPT_ERROR embedding a MULTIPART_REPLY
    QUEUE_STATS of length 40 whose stats length is 0x200. A property of length 0 at offset 72
    of the outer message used to move the offset back to 40."""
    ver = ver or V
    inner = struct.pack('!BBHI', ver, 19, 40, 2)
    inner += struct.pack('!HH4x', 5, 0)
    qs = struct.pack('!HH', 0x200, 0) + struct.pack('!II', 1, 2)
    qs += struct.pack("!HH", 0, 32) + b"\0" * 4
    qs += b'\0' * 8 + b'\0' * 8 + b'\0' * 8
    inner += qs
    assert 12 + len(inner) == 72
    inner += struct.pack('!HH', 0, 0)
    inner += b'\0' * 60
    body = struct.pack('!HH', 1, 0) + inner
    return struct.pack('!BBHI', ver, 1, 8 + len(body), 1) + body


def group_mod(cmd, typ, gid, buckets=(), bucket_id=0xfffffffc):
    return struct.pack('!HBxIH2xI', cmd, typ, gid, sum(len(x) for x in buckets), bucket_id) + b''.join(buckets)

def meter_desc(mid, bands, flags=0xf):
    body = u16(flags) + u32(mid) + b''.join(bands)
    return u16(2 + len(body)) + body

def pd_pipeline(t, oxms):
    body = b''.join(oxms)
    ln = 4 + len(body)
    return struct.pack('!HH', t, ln) + body + pad(-ln % 8)

def pd_recirc(ports):
    body = b''.join(u32(p) for p in ports)
    ln = 4 + len(body)
    return struct.pack('!HH', 4, ln) + body + pad(-ln % 8)

def pd_exp(n=4):
    return struct.pack("!HHII", 0xffff, 12 + n, EXPER, 7) + bytes(n)

def pd_unknown():
    return struct.pack('!HH', 9, 8) + b'\1\2\3\4'

def controller_status(short_id, uri, extra=()):
    body = b''
    prop = struct.pack('!HH', 0, 4 + len(uri)) + uri.encode()
    prop += pad(-len(prop) % 8)
    return u16(16 + len(prop)) + u16(short_id) + u32(2) + u8(1) + u8(1) + pad(6) + prop

def bundle_time_prop():
    return struct.pack('!HH', 1, 20) + u64(1000) + u32(500) + pad(4)

def bundle_feature_time():
    t = u64(1) + u32(2) + pad(4)
    return struct.pack('!HH', 1, 72) + pad(4) + t * 4

def build():
    pc = Pcap()
    f = Flow(pc)
    bm = struct.pack('!HHI', 1, 8, 0x12)
    f.send(True, m(0, bm))
    f.send(False, m(0, struct.pack('!HH', 1, 6) + b'\x12\x00' + pad(2)))
    f.send(False, m(0, struct.pack('!HHI', 1, 8, 0x12) + struct.pack('!HH', 99, 12) + b'\1\2\3\4\5\6\7\x08' + pad(4) + struct.pack('!HH', 1, 4) + pad(4)))
    f.send(True, m(0))
    # errors
    for et in range(18):
        if et == 0:
            f.send(True, m(1, u16(0) + u16(1) + b'incompatible version'))
        else:
            f.send(True, m(1, u16(et) + u16(1) + build_inner()[et % 5]))
    f.send(True, m(1, u16(0xffff) + u16(1) + u32(EXPER) + b'expdata'))
    f.send(True, m(1, u16(0x1234) + u16(1) + b'unknown'))
    for inner in build_inner():
        f.send(True, m(1, u16(1) + u16(0) + inner))
    # nesting: up to and beyond the limit of 4 nested messages, with each kind of container
    for d in (1, 3, 4, 5, 8):
        f.send(True, chain(d, 1))
    for d in (1, 2, 4, 5, 7):
        f.send(True, chain(d, 32))
    for d in (1, 2, 4, 5, 7):
        f.send(True, chain(d, 34))
    f.send(False, m(2, b'ping'), m(3, b'pong'), m(2))
    f.send(True, m(4, u32(EXPER) + u32(1) + b'data'))
    f.send(True, m(4, u32(EXPER) + u32(1)))
    f.send(False, m(5))
    f.send(True, m(6, struct.pack('!QIBB2xII', 0x0001020304050607, 256, 8, 1, 0x1ef, 0)))
    f.send(False, m(7))
    f.send(True, m(8, struct.pack('!HH', 0, 128)))
    f.send(False, m(9, struct.pack('!HH', 3, 0xffff)))
    # packet in
    f.send(True, m(10, struct.pack('!IHBBQ', 0xffffffff, len(PKT), 0, 0, 1) + match(*ALL_OXM[:14]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, len(PKT), 1, 5, 2) + match(*ALL_OXM[14:30]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, len(PKT), 2, 6, 3) + match(*ALL_OXM[30:44]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + match(*ALL_OXM[44:]) + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + match(oxm(41, u8(1))) + pad(2) + PKT))
    # empty matches: OXM type with length 4, standard and unknown type with length 4
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + match() + pad(2) + PKT))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 0, 4) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 7, 4) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 0, 12) + pad(8) + pad(4) + pad(2)))
    f.send(True, m(10, struct.pack('!IHBBQ', 4, 0, 1, 6, 3) + struct.pack('!HH', 7, 8) + pad(4) + pad(2)))
    # flow removed, port status
    for reason in range(4):
        f.send(True, m(11, struct.pack('!BBHHHQ', 3, reason, 100, 30, 40, 0x1122) + match(*ALL_OXM[:6]) + stats(*ALL_OXS[:5], *ALL_FILL)))
    f.send(True, m(11, struct.pack('!BBHHHQ', 3, 0, 100, 30, 40, 0x1122) + match() + stats(*ALL_OXS, *ALL_FILL)))
    f.send(True, m(11, struct.pack('!BBHHHQ', 3, 0, 100, 30, 40, 0x1122) + match() + stats(*ALL_FILL)))
    f.send(True, m(12, u8(0) + pad(7) + port(1)))
    f.send(True, m(12, u8(1) + pad(7) + port(2, [pd_eth()])))
    f.send(True, m(12, u8(2) + pad(7) + port(3, [pd_opt()])))
    f.send(True, m(12, u8(2) + pad(7) + port(3, [pd_eth(), pd_opt(), pd_eth()])))
    f.send(True, m(12, u8(2) + pad(7) + port(3, [pd_pipeline(2, ALL_OXM[:4]), pd_pipeline(3, ALL_OXM[4:9]), pd_recirc([1, 2, 3]), pd_exp(), pd_unknown()])))
    # packet out, flow mod
    f.send(False, m(13, struct.pack('!IH2x', 0xffffffff, sum(map(len, ALL_ACTIONS))) + match(oxm(0, u32(1))) + b''.join(ALL_ACTIONS) + PKT))
    f.send(False, m(13, struct.pack('!IH2x', 7, 16) + match() + act_out()))
    for cmd in range(3):
        f.send(False, m(14, flow_mod(cmd=cmd, instrs=ALL_INSTR, importance=cmd + 5)))
    for lo, hi in ((0, 14), (14, 28), (28, 42), (42, 70)):
        f.send(False, m(14, flow_mod(mt=match(*ALL_OXM[lo:hi]), instrs=[])))
    f.send(False, m(14, flow_mod(mt=match(*ALL_OXM[14:28]), instrs=[instr_unknown()], flags=0)))
    f.send(False, m(14, flow_mod(instrs=[struct.pack('!HH', 1, 4) + u8(1) + pad(3)])))
    for cmd in range(3):
        f.send(False, m(15, group_mod(cmd, cmd, 5 + cmd, [bucket(ALL_ACTIONS[:5]), bucket([act_out(3)], 5, 3, 4)])))
    f.send(False, m(15, group_mod(0, 2, 5)))
    f.send(False, m(15, group_mod(0, 0, 5, [struct.pack('!HHII', 8, 1, 1, 1) + pad(4)])))
    # port mod with properties, table mod with properties
    pm = u32(1) + pad(4) + mac(1) + pad(2) + struct.pack('!II', 0x7f, 0x7f)
    f.send(False, m(16, pm))
    f.send(False, m(16, pm + pmod_prop(0) + pmod_prop(1) + pmod_prop(0xffff) + pmod_prop(9)))
    tm = struct.pack('!B3xI', 0xff, 3)
    f.send(False, m(17, tm))
    f.send(False, m(17, tm + tm_prop(2) + tm_prop(3) + tm_prop(0xffff) + tm_prop(9)))
    # multipart requests
    for t in (0, 3, 8, 11, 13, 14, 7):
        f.send(False, mp_req(t))
    f.send(False, mp_req(1, flow_stats_req()))
    f.send(False, mp_req(17, flow_stats_req(match(*ALL_OXM[:5]))))
    f.send(False, mp_req(18))
    f.send(False, mp_req(10, u32(1) + pad(4)))
    f.send(False, mp_req(19, u32(1) + pad(4) + bundle_feature_time() + struct.pack('!HHII', 0xffff, 16, EXPER, 1) + b'\1\2\3\4' + struct.pack('!HH', 9, 8) + pad(4)))
    f.send(False, mp_req(19, u32(1) + pad(4)))
    f.send(False, mp_req(19, u32(1) + pad(4) + struct.pack('!HH', 9, 10) + b'\1' * 6 + pad(6)))
    f.send(False, mp_req(1, flow_stats_req(), flags=1))
    f.send(False, mp_req(1, flow_stats_req(match(*ALL_OXM[:14]))))
    f.send(False, mp_req(2, flow_stats_req(match())))
    f.send(False, mp_req(4, u32(0xffffffff) + pad(4)))
    f.send(False, mp_req(5, u32(1) + u32(0xffffffff)))
    f.send(False, mp_req(6, u32(0xfffffffc) + pad(4)))
    f.send(False, mp_req(9, u32(0xffffffff) + pad(4)))
    f.send(False, mp_req(15, u32(1) + u32(0xffffffff)))
    for ev in (0x1, 0x7f):
        f.send(False, mp_req(16, u32(3) + u32(0xffffffff) + u32(0xffffffff) + u16(ev) + u8(0xff) + u8(0) + match(oxm(0, u32(1)))))
    f.send(False, mp_req(12))
    f.send(False, mp_req(12, table_features(0, []) + table_features(1, [])))
    f.send(False, mp_req(0xffff, u32(EXPER) + u32(7) + b'ext'))
    f.send(False, mp_req(0xffff, u32(EXPER) + u32(7)))
    f.send(False, mp_req(77, b'abcd'))
    BIGPROP = table_prop(0xfffe, u32(EXPER) + u32(5) + b'data')
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
        table_prop(16, bytes([1, 2, 3])),
        table_prop(18, oxm_id(0) + oxm_id(3, 6)),
        table_prop(19, oxm_id(0, 4)),
        table_prop(20, oxm_id(0, 4)),
        table_prop(21, oxm_id(0, 4)),
        table_prop(22, oxm(44, u16(0) + u16(0x0800)) + oxm(44, u16(1) + u16(0x86dd))),
        table_prop(0xfffe, u32(EXPER) + u32(5) + b'data'),
        table_prop(0xffff, u32(EXPER) + u32(5)),
        table_prop(99, b'\1\2\3\4'),
        struct.pack('!HH', 9, 2) + pad(4),
    ]
    f.send(False, mp_req(12, table_features(0, props + [BIGPROP])))
    # multipart replies
    f.send(True, mp_rep(0, s('mfr', 256) + s('hw', 256) + s('sw', 256) + s('1234', 32) + s('dp', 256)))
    f.send(True, mp_rep(1, flow_desc(match(*ALL_OXM[:8]), ALL_INSTR[:4], ALL_OXS[:5]) + flow_desc(match(), [instr_goto()], [], 2), flags=1))
    f.send(True, mp_rep(1, flow_desc(match(*ALL_OXM[:8]), ALL_INSTR[:3], ALL_OXS[:2]) + flow_desc(match(), [instr_goto()], ALL_OXS, 2) + flow_desc(match(), [], [], 3)))
    f.send(True, mp_rep(17, flow_stats_entry(match(*ALL_OXM[:8]), ALL_OXS[:5]) + flow_stats_entry(match(), [], 2)))
    f.send(True, mp_rep(2, stats(*ALL_OXS[:5])))
    f.send(True, mp_rep(2, stats()))
    f.send(True, mp_rep(3, b''.join(u8(i) + pad(3) + u32(10 + i) + u64(100) + u64(50) for i in range(3))))
    f.send(True, mp_rep(4, port_stats(1) + port_stats(2, [ps_eth()]) + port_stats(3, [ps_opt()]) + port_stats(4, [ps_eth(), ps_opt()]) + port_stats(5, [struct.pack('!HH', 5, 4 + 1 + 40) + b'\0' + ps_eth()])))
    f.send(True, mp_rep(5, queue_stats(1, 1) + queue_stats(1, 2, [qs_exp(), qs_exp(8), qs_unknown()])))
    f.send(True, mp_rep(6, group_stats(1, 2) + group_stats(2, 0)))
    f.send(True, mp_rep(7, group_desc(0, 1, [bucket([act_out(1)]), bucket(ALL_ACTIONS[:4])]) + group_desc(3, 2, [])))
    f.send(True, mp_rep(8, u32(0xf) + u32(0x7) + u32(1000) + u32(2000) + u32(3000) + u32(4000) + b''.join(u32(0xffff + i) for i in range(4))))
    f.send(True, mp_rep(9, meter_stats(1, 2) + meter_stats(2, 0)))
    f.send(True, mp_rep(10, meter_desc(1, [band(1), band(2, prec=3)]) + meter_desc(2, [])))
    f.send(True, mp_rep(11, struct.pack('!IIIBB2x', 256, 0x6, 0xf, 4, 8)))
    f.send(True, mp_rep(12, table_features(0, props + [BIGPROP]) + table_features(1, [])))
    f.send(True, mp_rep(13, port(1) + port(2, [pd_eth()]) + port(3, [pd_opt(), pd_eth()])))
    f.send(True, mp_rep(14, table_desc(0) + table_desc(1, [tm_prop(2), tm_prop(3), tm_prop(0xffff), tm_prop(9)])))
    f.send(True, mp_rep(15, queue_desc(1, 1, [qd_prop(1), qd_prop(2), qd_prop(0xffff), qd_prop(9)]) + queue_desc(1, 2)))
    f.send(True, mp_rep(16, fm_update(0, [instr_goto(), instr_acts(4, [act_out()])]) + b''.join(fm_update(e, [instr_goto(), instr_acts(4, [act_out()])], mt=match()) for e in range(1, 4)) + fm_update(4) + fm_update(5) + fm_update(6)))
    f.send(True, mp_rep(16, fm_update(7)))
    f.send(False, m(20))
    f.send(True, m(21))
    f.send(False, m(24, u32(2) + pad(4) + u64(77)))
    f.send(True, m(25, u32(2) + pad(4) + u64(77)))
    f.send(False, m(26))
    f.send(True, m(27, b''.join(async_prop(t) for t in range(12)) + async_prop(0xfffe) + async_prop(0xffff) + async_prop(40)))
    f.send(False, m(28, b''.join(async_prop(t, 5) for t in range(12))))
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(1) + band(2)))
    f.send(False, m(29, u16(2) + u16(1) + u32(1)))
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(0xffff) + band(1) + band(1) + band(1)))
    f.send(False, m(29, u16(0) + u16(0xf) + u32(1) + band(7) + band(1) + band(1) + band(1)))
    # status messages, bundles
    f.send(True, m(35, struct.pack('!HHIBB6x', 16, 3, 2, 1, 1) + struct.pack('!HH', 0xffff, 16) + struct.pack('!II', EXPER, 1) + b'\1\2\3\4'))
    f.send(True, m(35, struct.pack('!HHIBB6x', 16, 3, 2, 1, 1) + struct.pack('!HH', 77, 8) + pad(4)))
    f.send(True, m(35, struct.pack('!HHIBB6x', 16, 3, 2, 1, 1) + struct.pack('!HH', 77, 2) + pad(4)))
    f.send(True, m(35, struct.pack('!HHIBB6x', 16, 3, 2, 1, 1) + struct.pack('!HHII', 0xffff, 14, EXPER, 1) + b'\1\2' + pad(2)))
    f.send(True, m(30, u32(2) + u8(1) + pad(3) + u64(9)))
    f.send(True, m(32, m(14, flow_mod(instrs=ALL_INSTR[:2]))))
    f.send(True, m(32, m(15, group_mod(0, 0, 5, [bucket([act_out(3)])]))))
    f.send(False, m(33, u32(1) + u16(0) + u16(3)))
    f.send(False, m(33, u32(1) + u16(1) + u16(3) + bundle_prop(1) + bundle_prop(0xffff) + bundle_prop(9)))
    f.send(False, m(34, u32(1) + pad(2) + u16(3) + m(14, flow_mod(instrs=ALL_INSTR[:2]))))
    f.send(False, m(34, u32(1) + pad(2) + u16(1) + m(2, b'in') + bundle_prop(0xffff) + bundle_prop(9)))
    f.send(True, m(99, b'unknown'))
    f.send(True, m(99))
    big = m(14, flow_mod(mt=match(*ALL_OXM[:14]), instrs=ALL_INSTR))
    f.send(False, big, split=[20, 150])
    f.send(True, m(2, b'a'), m(3, b'b'), m(20), m(2, b'cc'))
    # Exported PDU: only the header length is dissected
    pc.epdu('openflow_v6', m(2, b'ping') + b'trailing data after the message')
    pc.epdu('openflow_v6', m(14, flow_mod(instrs=[instr_goto()])) + pad(40))
    pc.epdu('openflow_v6', m(1, u16(1) + u16(0) + m(2, b'in')) + b'garbage' * 4)
    pc.epdu('openflow_v6', m(32, m(2, b'in')) + b'garbage' * 4)
    # === The frames below have error expert infos (length too short); they are the reproducers of the
    # endless loops in nested messages (and plain too short properties) ===
    MARK[0] = len(pc.frames)
    f = Flow(pc, sport=40001)
    f.send(True, proplen_loop())
    f.send(True, m(32, proplen_loop()))
    f.send(True, m(34, u32(1) + pad(2) + u16(3) + proplen_loop()))
    f.send(True, m(1, u16(1) + u16(0) + m(1, u16(1) + u16(0) + proplen_loop())))
    pc.epdu('openflow_v6', proplen_loop() + b'\0' * 40)
    pc.write(os.path.join(OUT, 'openflow_v6-coverage.pcapng'))

MARK = [0]

def build_mal():
    pc = Pcap()
    f = Flow(pc)
    # nested chains of 5000 messages in one PDU (errors, request forward, bundle add)
    for typ, per in ((1, 12), (32, 8), (34, 16)):
        inner = m(2, b'x')
        n = 0
        while len(inner) + per < 65000:
            if typ == 1:
                inner = m(1, u16(1) + u16(0) + inner)
            elif typ == 32:
                inner = m(32, inner)
            else:
                inner = m(34, u32(n) + pad(2) + u16(3) + inner)
            n += 1
        f.send(True, inner)
    f.send(True, m(0, struct.pack('!HH', 1, 2) + pad(4)))
    f.send(True, m(0, struct.pack('!HH', 99, 3) + pad(4)))
    for t in (1, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 27, 29, 4, 30, 31, 32, 33, 34, 35):
        f.send(True, m(t, b'\0\1'))
    for t in range(20):
        f.send(True, mp_req(t, b'\0\1'))
        f.send(True, mp_rep(t, b'\0\1'))
    f.send(True, m(1, u16(1)))
    f.send(True, m(1, u16(0xffff) + u16(1) + b'ab'))
    f.send(True, m(1, u16(1) + u16(1) + b'\x05\x02\x00\x04'))
    f.send(True, m(1, u16(1) + u16(1) + b'\x05\x02\x00\x20' + pad(8)))
    f.send(True, m(32, b'\x05\x02\x00\x04'))
    f.send(True, m(34, u32(1) + pad(2) + u16(3) + b'\x05\x02\x00\x04'))
    # lengths too short (error expert infos): match, meter band, actions, instructions, properties
    f.send(True, m(14, flow_mod(mt=struct.pack('!HH', 1, 2) + pad(4))))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 7, 8) + pad(4) + struct.pack('!HH', 0, 2)])))
    f.send(True, m(11, struct.pack('!BBHHHQ', 3, 0, 100, 30, 40, 0x1122) + match() + pad(2) + u16(2)))
    f.send(True, m(14, flow_mod(instrs=[instr_acts(4, [struct.pack('!HH', 0xffff, 8) + pad(4)])])))
    f.send(True, m(14, flow_mod(instrs=[instr_acts(4, [struct.pack('!HH', 99, 4)])])))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 0xffff, 8) + pad(8)])))
    f.send(True, m(14, flow_mod(instrs=[struct.pack('!HH', 77, 4) + pad(8)])))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + struct.pack('!HHII', 1, 8, 1, 1) + pad(8)))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + band(0xffff)))
    f.send(True, m(29, u16(0) + u16(0xf) + u32(1) + band(7)))
    pm = u32(1) + pad(4) + mac(1) + pad(2) + struct.pack('!II', 0x7f, 0x7f)
    f.send(True, m(16, pm + struct.pack('!HH', 0xffff, 12) + pad(8)))
    f.send(True, m(16, pm + struct.pack('!HH', 9, 4) + pad(8)))
    tm = struct.pack('!B3xI', 0xff, 3)
    f.send(True, m(17, tm + struct.pack('!HH', 0xffff, 12) + pad(8)))
    f.send(True, m(17, tm + struct.pack('!HH', 9, 4) + pad(8)))
    f.send(True, mp_rep(5, queue_stats(1, 1, [struct.pack('!HH', 0xffff, 12) + pad(8)])))
    f.send(True, mp_rep(5, queue_stats(1, 1, [struct.pack('!HH', 5, 4) + pad(8)])))
    f.send(True, mp_rep(15, queue_desc(1, 1, [struct.pack('!HH4x', 1, 4) + pad(8)])))
    f.send(True, mp_rep(15, queue_desc(1, 1, [struct.pack('!HH4x', 0xffff, 16) + pad(8)])))
    f.send(True, mp_rep(15, queue_desc(1, 1, [struct.pack('!HH4x', 7, 8) + pad(8)])))
    f.send(True, mp_rep(16, u16(2) + u16(0) + pad(8)))
    f.send(True, mp_rep(16, fm_update(9)))
    f.send(True, m(27, struct.pack('!HH', 0xfffe, 12) + pad(8)))
    f.send(True, m(27, struct.pack('!HH', 40, 4) + pad(8)))
    f.send(True, m(33, u32(1) + u16(1) + u16(3) + struct.pack('!HH', 0xffff, 12) + pad(8)))
    f.send(True, m(33, u32(1) + u16(1) + u16(3) + struct.pack('!HH', 9, 4) + pad(8)))
    f.send(True, mp_rep(1, b''))
    f.send(True, mp_rep(2, stats(oxs(2, b'', cls=0xffff))))   # experimenter OXS without the experimenter id
    f.send(True, mp_rep(2, pad(2) + u16(8) + oxs(0, u32(1) + u32(2)) + pad(4)))
    f.send(True, m(33, u32(1) + u16(1) + u16(3) + struct.pack('!HH', 9, 4) + pad(8)))
    f.send(True, mp_rep(18, controller_status(1, 'tcp:192.0.2.2:6653')))
    f.send(True, m(35, controller_status(3, 'ssl:192.0.2.3:6653')))
    # port properties: too short, experimenter, unknown
    f.send(True, m(12, u8(0) + pad(7) + port(1, [struct.pack('!HHI', 0xffff, 12, EXPER) + pad(8)])))
    f.send(True, m(12, u8(0) + pad(7) + port(1, [struct.pack('!HH', 9, 4) + pad(8)])))
    f.send(True, mp_rep(4, port_stats(1, [struct.pack('!HHI', 0xffff, 12, EXPER) + pad(8)])))
    f.send(True, mp_rep(4, port_stats(1, [struct.pack('!HH', 9, 4) + pad(8)])))
    f.send(True, mp_rep(4, port_stats(1, [pd_exp(), pd_unknown()])))
    f.send(True, m(35, struct.pack('!HHIBB6x', 16, 3, 2, 1, 1) + struct.pack('!HHI', 0xffff, 12, EXPER)))
    f.send(True, mp_req(19, u32(1) + pad(4) + struct.pack('!HH', 1, 3) + pad(8)))
    f.send(True, mp_req(12, table_features(0, [struct.pack('!HH', 22, 3) + pad(8)])))
    # always malformed: multipart reply experimenter/unknown body lengths
    f.send(True, mp_rep(0xffff, u32(EXPER) + u32(7) + b'ext'))
    f.send(True, mp_rep(77, b'abcd'))
    f.send(True, m(31, u8(1) + pad(7) + table_desc(1, [tm_prop(2), tm_prop(3)])))
    f.send(True, m(31, u8(1) + pad(7) + struct.pack('!HB', 2, 0)))
    desc = u16(0) + pad(2) + struct.pack('!BxHHHHH', 0, 0, 0, 0, 0, 0) + u64(0) + struct.pack('!HH4x', 1, 4) + struct.pack('!HH4x', 0, 4)
    desc = u16(len(desc)) + desc[2:]
    n = (65535 - 16) // len(desc)
    f.send(True, mp_rep(1, desc * n))
    f.send(True, mp_rep(1, desc * 3 + pad(5)))
    pc.epdu('openflow_v6', hdr(6, 2, b'ab', length=6))
    pc.epdu('openflow_v6', hdr(6, 2, b'abcd', length=100))
    pc.epdu('openflow_v6', hdr(6, 14, b'', length=8))
    pc.write(os.path.join(OUT, 'openflow_v6-coverage-malformed.pcapng'))

if __name__ == '__main__':
    OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
    build()
    build_mal()
    print('first frame of the error group:', MARK[0] + 1)

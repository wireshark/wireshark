#!/usr/bin/env python3
# Generates test/captures/riemann_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- helpers (struct only) ----
import struct
import sys

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s): return bytes(map(int, s.split('.')))

class Cap:
    def __init__(self, linktype=1):
        self.frames = []; self.linktype = linktype
        self.seq = {}; self.ipid = 1; self.ts = 1700000000.0
    def raw(self, data, caplen=None):
        self.frames.append((self.ts, bytes(data), caplen)); self.ts += 0.01
        return len(self.frames)
    def ip(self, src, dst, proto, payload, ttl=64, frag=0):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), self.ipid, frag, ttl, proto, 0, ip4(src), ip4(dst))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, pkt, et=0x0800, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02'):
        return d + s + struct.pack('!H', et) + pkt
    def ip6(self, src, dst, nh, payload, hop=64):
        return struct.pack('!IHBB', 0x60000000, len(payload), nh, hop) + src + dst + payload
    def udp(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0) + payload
        return self.raw(self.eth(self.ip(src, dst, 17, u, ttl=1 if dst.startswith('224.') else 64)))
    def udp6(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0)
        ph = src + dst + struct.pack('!IBBBB', 8+len(payload), 0, 0, 0, 17)
        c = csum(ph + u + payload) or 0xffff
        u = u[:6] + struct.pack('!H', c) + payload
        return self.raw(self.eth(self.ip6(src, dst, 17, u), et=0x86dd,
                                 d=b'\x33\x33\0\0\0\x09'))
    def tcp(self, src, dst, sp, dp, payload, flags=0x18, seq=None, urp=0):
        k = (src, dst, sp, dp)
        if seq is None: seq = self.seq.get(k, 1000 + (sp * 7919 + dp) % 100000)
        self.seq[k] = seq + len(payload) + (1 if flags & 3 else 0)
        ack = self.seq.get((dst, src, dp, sp), 0)
        if flags & 2:   # SYN: MSS option
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x70, flags, 65535, 0, urp) + b'\x02\x04\x05\xb4\x04\x02\x01\x01' + payload
        else:
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, urp) + payload
        return self.raw(self.eth(self.ip(src, dst, 6, t)))
    def hs(self, src, dst, sp, dp):
        # three-way handshake: SYN, SYN/ACK, ACK
        self.tcp(src, dst, sp, dp, b'', flags=0x02, seq=1000 + (sp * 7919 + dp) % 100000 - 1)
        self.tcp(dst, src, dp, sp, b'', flags=0x12, seq=5000)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
    def fin(self, src, dst, sp, dp):
        self.tcp(src, dst, sp, dp, b'', flags=0x11)
        self.tcp(dst, src, dp, sp, b'', flags=0x11)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for ts, d, cl in self.frames:
                c = d if cl is None else d[:cl]
                f.write(struct.pack('<IIII', int(ts), int((ts % 1)*1e6), len(c), len(d)) + c)


class CapNG(Cap):
    """pcapng with one interface per link type: raw(data, lt=1)"""
    def __init__(self, linktypes=(1, 252)):
        Cap.__init__(self, 1); self.lts = list(linktypes)
    def raw(self, data, caplen=None, lt=1):
        self.frames.append((self.ts, bytes(data), caplen, self.lts.index(lt))); self.ts += 0.01
        return len(self.frames)
    def write(self, path):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for ts, d, cl, ifx in self.frames:
            c = d if cl is None else d[:cl]
            t = int(ts * 1e6)
            out += blk(6, struct.pack('<IIIII', ifx, t >> 32, t & 0xffffffff, len(c), len(d)) + c)
        open(path, 'wb').write(out)

def expdu(name, payload):
    n = name.encode(); pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
# ---- end helpers ----
out = sys.argv[1] if len(sys.argv) > 1 else '.'
def vi(n):
    b = bytearray()
    while True:
        x = n & 0x7f; n >>= 7
        if n: b.append(x | 0x80)
        else:
            b.append(x); break
    return bytes(b)
def zz(n): return vi((n << 1) ^ (n >> 63) if n >= 0 else ((n << 1) ^ -1) & 0xffffffffffffffff)
def tag(fn, wire): return vi((fn << 3) | wire)
def f_int(fn, n): return tag(fn, 0) + vi(n)
def f_str(fn, s):
    s = s.encode() if isinstance(s, str) else s
    return tag(fn, 2) + vi(len(s)) + s
def f_sub(fn, body): return tag(fn, 2) + vi(len(body)) + body
def f_flt(fn, x): return tag(fn, 5) + struct.pack('<f', x)
def f_dbl(fn, x): return tag(fn, 1) + struct.pack('<d', x)
def attr(k, v): return f_str(1, k) + f_str(2, v)
def event_full(i=0):
    return (f_int(1, 1700000000 + i) + f_str(2, 'ok') + f_str(3, 'cpu') + f_str(4, 'web%d' % i) + f_str(5, 'cpu usage')
            + f_str(7, 'prod') + f_str(7, 'linux') + f_flt(8, 60.0) + f_sub(9, attr('dc', 'ams')) + f_sub(9, attr('rack', '12'))
            + f_int(10, 1700000000123456 + i) + tag(13, 0) + zz(-42) + f_dbl(14, 0.25) + f_flt(15, 1.5))
def state_full():
    return (f_int(1, 1700000001) + f_str(2, 'critical') + f_str(3, 'disk') + f_str(4, 'db1') + f_str(5, 'disk full')
            + f_int(6, 1) + f_str(7, 'prod') + f_str(7, 'storage') + f_flt(8, 30.0))
def msg_events(*evs): return b''.join(f_sub(6, e) for e in evs)
def msg_state(*sts): return b''.join(f_sub(4, s) for s in sts)
def msg_query(q): return f_sub(5, f_str(1, q))
def msg_ok(err=b'all fine here'): return f_int(2, 1) + f_str(3, err)
def tcp_pdu(m): return struct.pack('!I', len(m)) + m
CL, SV = '192.0.2.50', '192.0.2.60'
c = CapNG()
def U(m, sp=49300, dp=5555): return c.udp(CL, SV, sp, dp, m)
def T(m, sp=49301, dp=5555, src=CL, dst=SV): return c.tcp(src, dst, sp, dp, m)
# UDP port 5555 (no default port: Decode As udp.port 5555 -> riemann.udp)
U(msg_events(event_full(0)))                                                  # 1 event with every field
U(msg_events(f_str(3, 'mem') + f_str(4, 'web1'), f_str(3, 'swap') + f_str(4, 'web2') + f_int(1, 5)))   # 2 two events (Info lists service, host)
U(msg_state(state_full()))                                                    # 3 state with every field
U(msg_state(f_str(3, 'aaa') + f_str(4, 'bbb'), f_str(3, 'ccc') + f_str(4, 'ddd')))                    # 4 two states
U(msg_query('service = "cpu" and host =~ "web%"'))                            # 5 query
U(msg_ok())                                                                   # 6 ok and error
U(msg_events(event_full(1), event_full(2)))                                   # 7 two full events
# TCP port 5555 (Decode As tcp.port 5555 -> riemann.tcp)
T(tcp_pdu(msg_query('state = "ok"')))                                         # 8 query, length prefixed
T(tcp_pdu(msg_ok(b'ok, nothing to say')), src=SV, dst=CL, sp=5555, dp=49301)                  # 9 reply (error text makes it 16 octets: ok=1, error="ok")
T(tcp_pdu(msg_events(event_full(3))))                                         # 10 events
m = tcp_pdu(msg_state(state_full(), state_full()))
T(m[:30]); T(m[30:])                                                          # 11-12 PDU in two segments
T(tcp_pdu(msg_query('state = "ok" and x = 1')) + tcp_pdu(msg_ok(b'twice')))                    # 13 two PDUs in one segment
# Exported PDU naming the registered dissectors (default preferences)
c.raw(expdu('riemann.udp', msg_events(event_full(4), f_str(3, 'tail') + b'')), lt=252)      # 14 riemann.udp
c.raw(expdu('riemann.tcp', tcp_pdu(msg_state(state_full()))), lt=252)                       # 15 riemann.tcp
# the reproducers of the fixed string size bug (error expert info "String size N exceeds remaining data", the rest is consumed)
c.raw(expdu('riemann.udp', f_int(2, 1) + tag(3, 2) + vi(0xFFFFFFFF) + b'abcdef' + b'.' * 8), lt=252)   # 16 Msg.error with size 0xFFFFFFFF (was -1 as an int: the offset moved back)
c.raw(expdu('riemann.udp', f_sub(6, f_str(3, 'cpu') + tag(4, 2) + vi(0x7fffffff) + b'hostname1')), lt=252)  # 17 Event.host with a huge size
c.write(out + '/riemann-coverage.pcapng')
m = CapNG()
def X(body, name='riemann.udp'): m.raw(expdu(name, body), lt=252)
# the reproducers of the fixed string size bug: a string size larger than the data left (error expert info, rest consumed)
X(f_int(2, 1) + tag(3, 2) + vi(0xFFFFFFFF) + b'abcdef' + b'.' * 8)                       # 1: Msg.error with size 0xFFFFFFFF
X(f_sub(6, f_str(3, 'cpu') + tag(4, 2) + vi(0x7fffffff) + b'hostname1'))      # 2: Event.host with a huge size (event size correct, string longer)
X(f_sub(6, f_int(1, 5) + tag(2, 2) + vi(1000) + b'state') + b'.' * 8)                    # 3: Event.state longer than the data
X(msg_query('q') + f_sub(5, tag(1, 2) + vi(5000) + b'query text..'))          # 4: Query.string longer than the data
X(f_sub(6, f_sub(9, tag(1, 2) + vi(300) + b'key') + b'\0' * 4) + b'\0' * 8)   # 5: Attribute.key longer than the data
X(f_sub(4, f_int(1, 5) + tag(3, 2) + vi(0xFFFFFFFF) + b'abcdefgh') + b'\0' * 8)  # 6: State.service with size 0xFFFFFFFF
# wrong wire types (each verifier branch: integer, bytes, float, double expected)
X(f_sub(6, tag(1, 2) + vi(3) + b'abc' + tag(2, 0) + vi(3) + tag(8, 0) + vi(1) + tag(14, 5) + b'\0\0\0\0' + tag(15, 1) + b'\0' * 8 + tag(10, 2) + b'\x01\x02'))
X(f_sub(4, tag(1, 2) + b'\x01a' + tag(2, 0) + b'\x01' + tag(6, 2) + b'\x01a' + tag(8, 0) + b'\x01') + b'\0' * 4)       # 8: wrong wire types in a State
X(f_sub(6, f_sub(9, tag(1, 0) + vi(1) + tag(2, 0) + vi(1))) + b'\0' * 4)       # 9: attribute key/value as integers
X(msg_ok() + tag(5, 0) + vi(1) + tag(6, 0) + vi(1) + tag(4, 0) + vi(1) + tag(3, 0) + vi(1))   # 10: Msg fields with wrong wire types
X(f_sub(5, tag(1, 0) + vi(1)) + b'\0' * 12)                                   # 11: query string with wrong wire type
# unknown field numbers
X(msg_events(event_full()) + f_int(9, 1) + f_str(31, 'x'))                    # 12: unknown fields in Msg
X(f_sub(6, f_int(1, 5) + f_int(11, 5) + f_str(12, 'zz') + f_str(3, 'cpu')) + b'\0' * 4)   # 13: unknown fields in Event
X(f_sub(4, f_int(1, 5) + f_int(9, 5) + f_str(3, 'cpu')) + b'\0' * 8)           # 14: unknown field in State
X(f_sub(6, f_sub(9, f_str(1, 'k') + f_str(3, 'zz'))) + b'\0' * 8)              # 15: unknown field in Attribute
X(f_sub(5, f_str(1, 'q') + f_str(2, 'zz')) + b'\0' * 12)                       # 16: unknown field in Query
# insufficient data: the last field is longer than the size of its message
X(f_sub(6, f_str(3, 'cpu')[:-1] + b'') + b'\0' * 12)                           # 17: Event size one short (VERIFY_SIZE)
X(f_sub(4, f_str(3, 'abc')[:3]) + b'\0' * 12)                                  # 18: State size short
X(f_sub(5, f_str(1, 'abc')[:3]) + b'\0' * 12)                                  # 19: Query size short
X(f_sub(6, f_sub(9, f_str(1, 'abcdef')[:4])) + b'\0' * 12)                     # 20: Attribute size short
X(f_int(2, 1) + tag(3, 2) + vi(20) + b'abc' + b'.' * 8)                                   # 21: Msg error longer than the data
# varints that do not end within ten octets
X(f_int(2, 1) + b'\xff' * 11 + b'\x01' + b'\0' * 4)                            # 22: tag that is not a varint (the length of 10 is used)
X(f_sub(6, b'\xff' * 12) + b'\0' * 4)                                          # 23: Event whose tag is not a varint
X(f_sub(6, tag(1, 0) + b'\xff' * 11) + b'\0' * 4)                              # 24: Event.time that is not a varint
X(f_sub(6, tag(13, 0) + b'\xff' * 11) + b'\0' * 4)                             # 25: Event.metric_sint64 that is not a varint
X(f_sub(6, tag(3, 2) + b'\xff' * 11) + b'\0' * 4)                                          # 26: string size that is not a varint
X(f_sub(4, tag(1, 0) + b'\xff' * 11) + b'\0' * 4)                              # 27: State.time that is not a varint
# sizes larger than the packet
X(tag(6, 2) + vi(5000) + f_str(3, 'cpu') + b'\0' * 8)                          # 28: Event size beyond the packet
X(tag(4, 2) + vi(5000) + f_str(3, 'cpu') + b'\0' * 8)                          # 29: State size beyond the packet
X(f_int(2, 1) + f_str(3, b'e'*8) + b'\x32')                                    # 30: tag at the very end (no size)
# not Riemann: the heuristics of is_riemann
X(b'\x07' * 20)                                                                # 31: first tag is not a Msg field
X(f_int(2, 1))                                                                 # 32: fewer than 16 octets
X(msg_ok(b'twelve chars') + b'', name='riemann.tcp')                           # 33: TCP without the length prefix
m.write(out + '/riemann-coverage-malformed.pcapng')

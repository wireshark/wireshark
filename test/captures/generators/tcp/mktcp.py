#!/usr/bin/env python3
# Generates test/captures/tcp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-tcp.c.  Usage: mktcp.py <outdir> [-v]
Writes tcp-coverage.pcapng (main) and tcp-coverage-malformed.pcapng.
Addresses are from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and
2001:db8::/32 only.  Nothing here handles keys or computes ciphertext; the
MPTCP keys and HMAC fields are arbitrary octets."""
import os
import struct
import sys

# ---------------------------------------------------------------- pcapng
class Cap:
    def __init__(self):
        self.frames = []          # (ifid, ts_us, data)
        self.t = 1700000000.0
        self.marks = []
    def add(self, data, dt=0.001, ifid=0):
        self.t += dt
        self.frames.append((ifid, int(self.t * 1e6), bytes(data)))
        return len(self.frames)
    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))
    def write(self, path):
        def blk(t, body):
            body += b"\0" * (-len(body) % 4)
            return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack("<HHI", 1, 0, 262144))
        out += blk(1, struct.pack("<HHI", 252, 0, 262144))
        for ifid, ts, d in self.frames:
            out += blk(6, struct.pack("<IIIII", ifid, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        open(path, "wb").write(out)

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split("."))

def ip6(a):
    import socket
    return socket.inet_pton(socket.AF_INET6, a)

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100
MAC_C = b"\x02\0\0\0\0\x01"
MAC_S = b"\x02\0\0\0\0\x02"

_ipid = [1]
def tcp_packet(src, dst, sport, dport, seq, ack, flags, win=65535, opts=b"", payload=b"",
               urg=0, good=True, tos=0, ttl=64, df=True, raw_off=None, v6=False,
               reserved=0, fixed_cksum=None, to_server=True, ipopts=b""):
    """Return an Ethernet frame carrying TCP over IPv4 or IPv6."""
    while len(opts) % 4:
        opts += b"\0"
    off = raw_off if raw_off is not None else (20 + len(opts)) // 4
    fl = (off << 12) | (reserved << 9) | (flags & 0x1ff)
    hdr = struct.pack(">HHIIHHHH", sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      fl, win, 0, urg) + opts
    seg = hdr + payload
    if v6:
        ph = ip6(src) + ip6(dst) + struct.pack(">IBBBB", len(seg), 0, 0, 0, 6)
    else:
        ph = ip4(src) + ip4(dst) + struct.pack(">BBH", 0, 6, len(seg))
    ck = csum(ph + seg)
    if fixed_cksum is not None:
        ck = fixed_cksum
    elif not good:
        ck ^= 0x5a5a
    seg = seg[:16] + struct.pack(">H", ck) + seg[18:]
    eth = (MAC_S + MAC_C if to_server else MAC_C + MAC_S)
    if v6:
        ipv = struct.pack(">IHBB", (6 << 28) | (tos << 20), len(seg), 6, ttl) + ip6(src) + ip6(dst)
        return eth + b"\x86\xdd" + ipv + seg
    _ipid[0] += 1
    h = struct.pack(">BBHHHBBH", 0x40 | (5 + len(ipopts) // 4), tos, 20 + len(ipopts) + len(seg), _ipid[0] & 0xffff,
                    0x4000 if df else 0, ttl, 6, 0) + ip4(src) + ip4(dst) + ipopts
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return eth + b"\x08\x00" + h + seg

def tcp_special_checksum(kind, src="192.0.2.60", dst="198.51.100.60", sport=48500, dport=31011, v6=False):
    """kind: 'ffff' (true checksum 0x0000 sent as 0xffff), 'partial' (pseudo header sum
    incl. length, as written by checksum offload), 'partial_nolen' (without length)."""
    payload = b"\0\0"
    if kind == "ffff":
        for v in range(65536):
            payload = struct.pack(">H", v)
            seg = struct.pack(">HHIIHHHH", sport, dport, 7, 1, (5 << 12) | ACK | PSH, 65535, 0, 0) + payload
            ph = ip4(src) + ip4(dst) + struct.pack(">BBH", 0, 6, len(seg))
            if csum(ph + seg) == 0:
                break
        else:
            raise SystemExit("no payload")
        return tcp_packet(src, dst, sport, dport, 7, 1, ACK | PSH, payload=payload, fixed_cksum=0xffff)
    payload = b"offload"
    seg_len = 20 + len(payload)
    ph = ip4(src) + ip4(dst) + struct.pack(">BBH", 0, 6, seg_len if kind == "partial" else 0)
    s = sum(struct.unpack(">%dH" % (len(ph) // 2), ph))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return tcp_packet(src, dst, sport, dport, 7, 1, ACK | PSH, payload=payload, fixed_cksum=s)

def icmp_unreach(inner_ip_tcp8, src="198.51.100.20", dst="192.0.2.10", code=3):
    ic = struct.pack(">BBHI", 3, code, 0, 0) + inner_ip_tcp8
    ic = ic[:2] + struct.pack(">H", csum(ic)) + ic[4:]
    h = struct.pack(">BBHHHBBH", 0x45, 0xc0, 20 + len(ic), 9, 0, 64, 1, 0) + ip4(src) + ip4(dst)
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return MAC_C + MAC_S + b"\x08\x00" + h + ic

def inner_tcp(src, dst, sport, dport, seq, n=8):
    t = struct.pack(">HHIIHHHH", sport, dport, seq, 0, (5 << 12) | ACK, 0, 0, 0)[:n]
    h = struct.pack(">BBHHHBBH", 0x45, 0, 40, 5, 0x4000, 64, 6, 0) + ip4(src) + ip4(dst)
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + t

class Conn:
    """One TCP connection; tracks sequence numbers per direction."""
    def __init__(self, cap, c="192.0.2.10", s="198.51.100.20", cp=40001, sp=5001,
                 cisn=1000, sisn=70000, v6=False, cwin=65535, swin=65535):
        self.cap, self.c, self.s, self.cp, self.sp, self.v6 = cap, c, s, cp, sp, v6
        self.seq = {"c": cisn, "s": sisn}
        self.ack = {"c": 0, "s": 0}
        self.win = {"c": cwin, "s": swin}
    def send(self, d, payload=b"", flags=ACK, seq=None, ack=None, win=None, opts=b"",
             dt=0.001, advance=True, **kw):
        o = "s" if d == "c" else "c"
        if seq is None:
            seq = self.seq[d]
        if ack is None:
            ack = self.ack[d] if (flags & ACK) else 0
        if win is None:
            win = self.win[d]
        if d == "c":
            a = (self.c, self.s, self.cp, self.sp)
        else:
            a = (self.s, self.c, self.sp, self.cp)
        pkt = tcp_packet(a[0], a[1], a[2], a[3], seq, ack, flags, win, opts, payload,
                         v6=self.v6, to_server=(d == "c"), **kw)
        n = self.cap.add(pkt, dt)
        if advance:
            end = seq + len(payload) + (1 if flags & SYN else 0) + (1 if flags & FIN else 0)
            if ((end - self.seq[d]) & 0xffffffff) < 0x80000000 and end != self.seq[d]:
                self.seq[d] = end & 0xffffffff
            if flags & ACK:
                pass
            self.ack[o] = self.seq[d]
        return n
    def handshake(self, copts=b"", sopts=b"", dt=0.001):
        self.send("c", flags=SYN, opts=copts, dt=dt)
        self.send("s", flags=SYN | ACK, opts=sopts, dt=dt)
        self.send("c", dt=dt)
    def close(self, dt=0.001):
        self.send("c", flags=FIN | ACK, dt=dt)
        self.send("s", flags=FIN | ACK, dt=dt)
        self.send("c", dt=dt)

# options helpers
def o_mss(v): return struct.pack(">BBH", 2, 4, v)
def o_ws(v): return struct.pack(">BBB", 3, 3, v)
def o_sackp(): return b"\x04\x02"
def o_sack(*blocks): return struct.pack(">BB", 5, 2 + 8 * len(blocks)) + b"".join(struct.pack(">II", a, b) for a, b in blocks)
def o_ts(v, e): return struct.pack(">BBII", 8, 10, v, e)
NOP = b"\x01"
EOL = b"\x00"
def o_raw(kind, data): return struct.pack(">BB", kind, 2 + len(data)) + data


# Exported PDU TLV helpers (WIRESHARK_UPPER_PDU, linktype 252)
def tlv(tag, value):
    return struct.pack(">HH", tag, len(value) + (-len(value) % 4)) + value + b"\0" * (-len(value) % 4)
def ex_addr(src="192.0.2.1", dst="198.51.100.2", sport=40000, dport=5000):
    return (tlv(20, ip4(src)) + tlv(21, ip4(dst)) + tlv(24, struct.pack(">I", 2)) +
            tlv(25, struct.pack(">I", sport)) + tlv(26, struct.pack(">I", dport)))
def ex_name(name, payload, extra=b""):
    return tlv(12, name.encode()) + extra + struct.pack(">HH", 0, 0) + payload
def ex_table(table, val, payload, extra=b""):
    return (tlv(14, table.encode()) + tlv(32, struct.pack(">I", val)) + extra +
            struct.pack(">HH", 0, 0) + payload)
def bare_tcp(flags=SYN, opts=b"", sport=40000, dport=5000, seq=1000, ack=0, payload=b""):
    while len(opts) % 4:
        opts += b"\0"
    off = (20 + len(opts)) // 4
    return struct.pack(">HHIIHHHH", sport, dport, seq, ack, (off << 12) | flags, 65535, 0, 0) + opts + payload

# ---------------------------------------------------------------- option helpers
def o_echo(v, reply=False): return struct.pack(">BBI", 7 if reply else 6, 6, v)
def o_cc(kind, v): return struct.pack(">BBI", kind, 6, v)
def o_md5(): return o_raw(19, bytes(range(1, 17)))
def o_ao(keyid=1, rnext=2, mac=bytes(range(0x30, 0x3c))): return o_raw(29, bytes([keyid, rnext]) + mac)
def o_scps(vec=0xf8, conn=7): return struct.pack(">BBBB", 20, 4, vec, conn)
def o_snack(off, size): return struct.pack(">BBHH", 21, 6, off, size)
def o_qs(): return struct.pack(">BBBBI", 27, 8, 0x14, 0x25, 0x01020304)
def o_userto(v): return struct.pack(">BBH", 28, 4, v)
def o_tfo(cookie=None): return o_raw(34, cookie if cookie is not None else b"")
def o_exp(kind, exid, data=b""): return o_raw(kind, struct.pack(">H", exid) + data)
def o_rvbd_probe(vt, body): return o_raw(76, bytes([vt]) + body)
def o_trpy(flags, src, dst, sp, dp, cport=None):
    b = struct.pack(">H", flags) + ip4(src) + ip4(dst) + struct.pack(">HH", sp, dp)
    if cport is not None:
        b += struct.pack(">H", cport)
    return o_raw(78, b)

def mp(sub_flags, body=b""):
    return o_raw(30, bytes([sub_flags]) + body)
KEY_A = 0x0102030405060708
KEY_B = 0x1112131415161718
KEY_C = 0x2122232425262728
KEY_D = 0x3132333435363738
# token = hash of the receiver's key, filled in from tshark (mptcp.expected_token)
TOK = {0: {"B": 0, "D": 0}, 1: {"B": 0, "D": 0}}
IDSN = {0: {"A": 0, "B": 0}, 1: {"A": 0, "B": 0}}
try:
    exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mptcp_consts.py")).read())
except OSError:
    pass

FRAMES = {}
def section(cap, name):
    FRAMES[name] = [len(cap.frames) + 1, None]
def endsection(cap, name):
    FRAMES[name][1] = len(cap.frames)

def tsopt(a, b): return NOP + NOP + o_ts(a, b)

# ---------------------------------------------------------------- scenarios
def sec_basic(cap):
    section(cap, "handshake and ECN, TCP timestamps, data and FIN")
    c = Conn(cap, cp=41001, sp=31001)
    c.send("c", flags=SYN | ECE | CWR, opts=o_mss(1460) + o_sackp() + o_ts(1000, 0) + NOP + o_ws(7))
    c.send("s", flags=SYN | ACK | ECE, opts=o_mss(1380) + o_sackp() + o_ts(5000, 1000) + NOP + o_ws(8))
    c.send("c", opts=tsopt(1001, 5000))
    c.send("c", b"hello " * 20, flags=ACK | PSH, opts=tsopt(1002, 5000))
    c.send("s", opts=tsopt(5001, 1002))
    c.send("s", b"world " * 30, flags=ACK | PSH | CWR, opts=tsopt(5002, 1002))
    c.send("c", opts=tsopt(1003, 5002), flags=ACK | ECE)
    c.send("c", flags=FIN | ACK, opts=tsopt(1004, 5002))
    c.send("s", flags=ACK, opts=tsopt(5003, 1004))
    c.send("s", flags=FIN | ACK, opts=tsopt(5004, 1004))
    c.send("c", opts=tsopt(1005, 5004))
    # a second connection ends with RST, one with RST+ACK after SYN (refused)
    c = Conn(cap, cp=41002, sp=31001)
    c.handshake(o_mss(1460), o_mss(1460))
    c.send("c", b"abc")
    c.send("s", flags=RST | ACK)
    c = Conn(cap, cp=41003, sp=31001)
    c.send("c", flags=SYN, opts=o_mss(536))
    c.send("s", flags=RST | ACK, ack=c.seq["c"])
    # SYN retransmission and SYN/ACK retransmission, then reuse of the ports
    c = Conn(cap, cp=41004, sp=31001)
    c.send("c", flags=SYN, opts=o_mss(1460))
    c.send("c", flags=SYN, opts=o_mss(1460), seq=1000, dt=1.0)
    c.send("s", flags=SYN | ACK, opts=o_mss(1460))
    c.send("s", flags=SYN | ACK, opts=o_mss(1460), seq=70000, dt=1.0)
    c.send("c")
    c.send("c", b"x" * 10)
    c.send("s")
    c.close()
    c2 = Conn(cap, cp=41004, sp=31001, cisn=900000, sisn=3000)
    c2.handshake()
    c2.send("c", b"again")
    c2.send("s")
    endsection(cap, "handshake and ECN, TCP timestamps, data and FIN")

def sec_midstream(cap):
    section(cap, "capture starts mid-stream, window scaling unknown")
    c = Conn(cap, cp=41010, sp=31002, cisn=555000, sisn=888000)
    c.ack = {"c": 888000, "s": 555000}
    c.send("c", b"m" * 100, flags=ACK | PSH)
    c.send("s", ack=555100, win=100)
    c.send("c", b"m" * 100, flags=ACK | PSH)
    c.send("s", ack=555200, win=100)
    c.send("s", b"r" * 50, flags=ACK | PSH)
    c.send("c", ack=888050)
    endsection(cap, "capture starts mid-stream, window scaling unknown")

def sec_analysis(cap):
    section(cap, "sequence analysis: loss, retransmissions, windows, keep-alive")
    c = Conn(cap, cp=41020, sp=31003)
    c.handshake(o_mss(1460) + o_sackp() + o_ts(10, 0) + NOP + o_ws(7),
                o_mss(1460) + o_sackp() + o_ts(20, 10) + NOP + o_ws(7))
    c.send("c", b"A" * 100)
    c.send("s")
    c.send("c", b"B" * 100)
    c.send("s")
    c.seq["c"] += 100                       # one segment lost before the capture point
    c.send("c", b"D" * 100)                 # previous segment not captured
    base = 1000 + 1 + 200                   # = 1201, first missing byte
    for i in range(3):                      # duplicate ACKs with SACK
        c.send("s", ack=base, opts=NOP + NOP + o_sack((base + 100, base + 200)), dt=0.001)
    c.send("c", b"C" * 100, seq=base, dt=0.005)          # fast retransmission
    c.send("s", ack=base + 200)
    c.send("c", b"D" * 100, seq=base + 100, dt=1.0)      # spurious retransmission
    c.send("s", ack=base + 200, opts=NOP + NOP + o_sack((base + 100, base + 200)))  # DSACK
    c.send("c", b"E" * 100)
    c.send("c", b"E" * 100, seq=base + 200, dt=0.6)      # retransmission after a timeout
    c.send("s", ack=base + 300)
    c.seq["c"] += 100
    c.send("c", b"G" * 100)                              # skip one segment
    c.send("c", b"F" * 100, seq=base + 300, dt=0.0005)   # out of order
    c.send("s", ack=base + 500)
    # zero window
    c.send("s", ack=base + 500, win=0)
    c.send("c", b"Z", seq=base + 500, dt=1.0)            # zero window probe
    c.send("s", ack=base + 500, win=0)                   # zero window probe ack
    c.send("s", ack=base + 500, win=4)                   # window update (4 << 7 = 512)
    c.send("c", b"W" * 500, seq=base + 500)              # fills the window? (probe byte retransmitted)
    c.send("s", ack=base + 1000, win=4)
    c.send("c", b"V" * 512, seq=base + 1000)             # window full
    c.send("s", ack=base + 1512, win=1000)               # window update
    # keep-alives
    c.send("c", b"\0", seq=base + 1511, dt=5.0)          # keep-alive
    c.send("s", ack=base + 1512, win=1000)               # keep-alive ack
    c.send("c", b"", seq=base + 1511, dt=5.0)            # keep-alive without data
    c.send("s", ack=base + 1512, win=1000)
    # ACK of data never seen, lost ACK
    c.send("s", ack=base + 90000, win=1000)
    c.send("c", b"Q" * 10, seq=base + 1512, ack=70001)
    c.send("c", flags=ACK | PSH, seq=base + 1522, ack=70001)
    c.send("c", flags=ACK, seq=base + 1522, ack=70001)
    c.send("s", ack=base + 1522, win=1000)
    c.close()
    # reuse of the ports for a new connection
    d = Conn(cap, cp=41020, sp=31003, cisn=2000000, sisn=3000000)
    d.handshake()
    d.send("c", b"new")
    d.send("s")
    # RTT, bytes in flight, window scaling with shift 14
    e = Conn(cap, cp=41021, sp=31003)
    e.handshake(o_ws(14) + o_ts(1, 0) + o_sackp(), o_ws(0) + o_ts(2, 1) + o_sackp())
    for i in range(6):
        e.send("c", bytes([65 + i]) * 1000, opts=tsopt(i + 2, 2))
    e.send("s", ack=e.seq["c"] - 3000, opts=tsopt(3, 4))
    e.send("s", ack=e.seq["c"], opts=tsopt(4, 7))
    # a half-closed connection, FIN retransmitted, data after FIN
    f = Conn(cap, cp=41022, sp=31003)
    f.handshake()
    f.send("c", b"fin", flags=ACK | FIN)
    f.send("s")
    f.send("c", b"fin", seq=f.seq["c"] - 4, flags=ACK | FIN, dt=1.0)
    f.send("s", b"after", flags=ACK | PSH)
    f.send("s", flags=FIN | ACK)
    f.send("c")
    endsection(cap, "sequence analysis: loss, retransmissions, windows, keep-alive")

def sec_fastrt(cap):
    section(cap, "retransmission classes: SACK recovery and slow handshakes")
    def mkconn(cp, rtt=0.010, sack=True):
        c = Conn(cap, cp=cp, sp=31008)
        o = o_mss(1460) + (o_sackp() if sack else b"") + NOP + o_ws(0)
        c.send("c", flags=SYN, opts=o)
        c.send("s", flags=SYN | ACK, opts=o, dt=rtt)
        c.send("c", dt=rtt)
        return c
    # 1. one lost segment, three duplicate ACKs, retransmission 12 ms after the next segment
    c = mkconn(48001)
    c.send("c", b"a" * 100, dt=0.01); c.send("s", dt=0.01)
    base = c.seq["c"]
    c.seq["c"] += 100
    c.send("c", b"c" * 100, dt=0.01)
    for i in range(3):
        c.send("s", ack=base, dt=0.002)
    c.send("c", b"b" * 100, seq=base, dt=0.012)
    c.send("s", ack=base + 200, dt=0.01)
    # 2. two lost segments, SACK blocks above them, the second hole is retransmitted first
    c = mkconn(48002)
    base = c.seq["c"]
    c.seq["c"] += 200
    c.send("c", b"d" * 100, dt=0.01); c.send("c", b"e" * 100, dt=0.001)
    for i in range(3):
        c.send("s", ack=base, opts=NOP + NOP + o_sack((base + 200, base + 400)), dt=0.002)
    c.send("c", b"f" * 100, seq=base + 100, dt=0.012)
    c.send("c", b"g" * 100, seq=base, dt=0.005)
    c.send("s", ack=base + 400, dt=0.01)
    # 3. a lost segment that arrives late with no duplicate ACKs: out of order
    c = mkconn(48003)
    base = c.seq["c"]
    c.seq["c"] += 100
    c.send("c", b"h" * 100, dt=0.01)
    c.send("c", b"i" * 100, seq=base, dt=0.006)
    c.send("s", ack=base + 200, dt=0.01)
    # 4. all segments seen, receiver duplicate-acks the first (capture near the sender)
    c = mkconn(48004)
    base = c.seq["c"]
    for ch in b"jklm":
        c.send("c", bytes([ch]) * 100, dt=0.002)
    for i in range(3):
        c.send("s", ack=base, dt=0.002)
    c.send("c", b"j" * 100, seq=base, dt=0.012)
    c.send("s", ack=base + 400, dt=0.002)
    # 5. same with SACK blocks: retransmission of a segment that is not the first
    c = mkconn(48005)
    base = c.seq["c"]
    for ch in b"nopqr":
        c.send("c", bytes([ch]) * 100, dt=0.002)
    for i in range(3):
        c.send("s", ack=base, opts=NOP + NOP + o_sack((base + 200, base + 500)), dt=0.002)
    c.send("c", b"o" * 100, seq=base + 100, dt=0.012)
    c.send("c", b"n" * 100, seq=base, dt=0.012)
    c.send("s", ack=base + 500, dt=0.002)
    # 6. SACK recovery with a retransmission that comes too late (plain retransmission)
    c = mkconn(48006)
    base = c.seq["c"]
    c.seq["c"] += 100
    for ch in b"stu":
        c.send("c", bytes([ch]) * 100, dt=0.002)
    for i in range(3):
        c.send("s", ack=base, opts=NOP + NOP + o_sack((base + 100, base + 400)), dt=0.002)
    c.send("c", b"r" * 100, seq=base, dt=0.5)
    c.send("s", ack=base + 400, dt=0.002)
    # 7. Reno style: no SACK, partial acknowledgement after fast retransmit
    c = mkconn(48007, sack=False)
    base = c.seq["c"]
    c.seq["c"] += 100
    c.send("c", b"v" * 100, dt=0.002)
    c.seq["c"] += 100
    c.send("c", b"x" * 100, dt=0.002)
    for i in range(3):
        c.send("s", ack=base, dt=0.002)
    c.send("c", b"u" * 100, seq=base, dt=0.012)
    c.send("s", ack=base + 200, dt=0.002)
    c.send("c", b"w" * 100, seq=base + 200 - 100, dt=0.012)
    c.send("s", ack=base + 400, dt=0.002)
    # 8. large SACKed range (more than 2 MSS) with a single duplicate ACK, retransmission 5 ms later
    c = mkconn(48008)
    base = c.seq["c"]
    c.seq["c"] += 1460
    for i in range(4):
        c.send("c", bytes([100 + i]) * 1460, dt=0.001)
    c.send("s", ack=base, opts=NOP + NOP + o_sack((base + 1460, base + 1460 * 5)), dt=0.002)
    c.send("c", b"y" * 1460, seq=base, dt=0.005)
    c.send("s", ack=base + 1460 * 5, dt=0.002)
    # 9. a pure ACK precedes a segment that arrives out of order after the highest one
    c = mkconn(48009)
    base = c.seq["c"]
    c.send("c", b"z" * 100, dt=0.002)
    c.seq["c"] += 100
    c.send("c", b"A" * 100, dt=0.002)
    c.send("c", dt=0.001)                       # pure ACK
    c.send("c", b"B" * 100, seq=base + 100, dt=0.0005)
    c.send("s", ack=base + 300, dt=0.002)
    endsection(cap, "retransmission classes: SACK recovery and slow handshakes")

def sec_pipeline(cap):
    section(cap, "reassembly: PDUs sharing a segment")
    c = Conn(cap, cp=43020, sp=80)
    c.handshake()
    c.send("c", b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n")
    ra = b"HTTP/1.1 200 OK\r\nContent-Length: 1500\r\n\r\n" + b"a" * 1500
    rb = b"HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n" + b"b" * 600
    c.send("s", ra[:1000])
    c.send("s", ra[1000:] + rb[:20])          # end of the first PDU, start of the second
    c.send("s", rb[20:300])
    c.send("s", rb[300:])
    c.send("c", b"GET /b HTTP/1.1\r\nHost: a\r\n\r\n")
    # a request cut in the middle of the header, then three small pieces
    c.send("c", b"GET /c HTTP/1.1\r\nHo")
    c.send("c", b"st: a\r\n")
    c.send("c", b"\r\nGET /d HTTP/1.1\r\n")
    c.send("c", b"Host: a\r\n\r\n")
    # response in two segments where the headers are split, no length (until FIN)
    c.send("s", b"HTTP/1.1 200 OK\r\nCont")
    c.send("s", b"ent-Type: text/plain\r\n\r\nbody")
    c.send("s", b"more body", flags=ACK | FIN | PSH)
    c.send("c", flags=ACK | FIN)
    # the same, with the pieces of the first PDU out of order and the second PDU following
    d = Conn(cap, cp=43021, sp=80)
    d.handshake()
    b0 = d.seq["s"]
    d.send("c", b"GET /e HTTP/1.1\r\nHost: a\r\n\r\n")
    d.send("s", ra[:1000], seq=b0)
    d.send("s", ra[1000:] + rb[:20], seq=b0 + 1000 + 0, dt=0.0004)
    d.send("s", rb[20:], seq=b0 + 1000 + len(ra) - 1000 + 20, dt=0.0004)
    d.send("c", ack=b0 + len(ra) + len(rb), dt=0.001)
    # three PDUs of DNS split across segments in different ways
    def dns(i):
        q = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\x01a\x07example\x07invalid\x00" + struct.pack(">HH", 1, 1)
        return struct.pack(">H", len(q)) + q
    e = Conn(cap, cp=43022, sp=53)
    e.handshake()
    p1, p2, p3 = dns(21), dns(22), dns(23)
    e.send("c", p1[:15])
    e.send("c", p1[15:] + p2[:10])
    e.send("c", p2[10:] + p3[:3])
    e.send("c", p3[3:])
    e.send("c", p1 + p2[:20])
    e.send("c", p2[20:])
    endsection(cap, "reassembly: PDUs sharing a segment")

def sec_sack(cap):
    section(cap, "SACK blocks, lost segments and window scaling")
    c = Conn(cap, cp=41030, sp=31004)
    c.handshake(o_mss(1400) + o_sackp() + NOP + o_ws(2), o_mss(1400) + o_sackp() + NOP + o_ws(2))
    segs = []
    for i in range(8):
        segs.append(c.seq["c"])
        c.send("c", bytes([97 + i]) * 100)
    # receiver acks with growing SACK blocks (1..4 blocks)
    a = segs[0]
    c.send("s", ack=a, opts=NOP + NOP + o_sack((segs[2], segs[3])))
    c.send("s", ack=a, opts=NOP + NOP + o_sack((segs[2], segs[4])))
    c.send("s", ack=a, opts=NOP + NOP + o_sack((segs[2], segs[3]), (segs[4], segs[5])))
    c.send("s", ack=a, opts=o_sack((segs[2], segs[3]), (segs[4], segs[5]), (segs[6], segs[7])) + NOP + NOP)
    c.send("s", ack=a, opts=o_sack((segs[1], segs[2]), (segs[3], segs[4]), (segs[5], segs[6]), (segs[7], segs[7] + 100)))
    c.send("c", b"a" * 100, seq=segs[0], dt=0.004)
    c.send("c", b"b" * 100, seq=segs[1], dt=0.002)
    c.send("s", ack=c.seq["c"])
    c.close()
    endsection(cap, "SACK blocks, lost segments and window scaling")

def sec_options(cap):
    section(cap, "TCP options")
    port = [42000]
    def one(opts, sopts=b"", data=b"", flags=SYN, **kw):
        port[0] += 1
        c = Conn(cap, cp=port[0], sp=31005, **kw)
        c.send("c", flags=flags, opts=opts, payload=data)
        if sopts is not None:
            c.send("s", flags=SYN | ACK, opts=sopts)
        return c
    one(o_mss(1460) + NOP + o_ws(5) + NOP + NOP + o_sackp() + o_ts(1, 0), o_mss(536) + o_ws(14))
    one(o_echo(0x01020304) + o_echo(0x05060708, True) + o_ts(5, 6))
    one(o_cc(11, 1) + o_cc(12, 2) + o_cc(13, 3))
    one(o_md5() + NOP + NOP)
    one(o_ao())
    one(o_ao(7, 9, b"\x55" * 20))
    one(o_userto(0x8000 | 100), o_userto(300))
    one(o_qs(), o_qs())
    one(o_scps(0xf8, 7), o_scps(0x07, 0))
    one(o_scps(0x00, 0))
    one(o_tfo(), o_tfo(bytes(range(8))))
    one(o_tfo(bytes(range(16))), b"")
    one(o_tfo(bytes(range(8))), b"", data=b"fast open data")
    one(o_raw(0xfd, b"\x01\x02\x03") + o_raw(0xfe, b"\x04\x05"))
    one(o_raw(0xfe, b"\x00\x04abc") + o_raw(0xfd, b"\xf9\x89" + b"\x01\x02\x03\x04"), o_raw(0xfe, b"\xf9\x89"))
    one(o_raw(99, b"\xde\xad\xbe\xef") + o_raw(200, b"") + o_raw(0x7e, b"x" * 20))
    one(o_ts(0, 0) + o_sackp() + NOP + NOP)
    one(NOP + NOP + NOP + EOL + EOL + EOL, None)           # EOL padding
    one(o_mss(1460) + EOL, None)
    # RECBOUND, CORREXP and SNACK: SCPS option 20 first, then the others
    c = one(o_scps(0xf8, 1) + o_raw(22, b"") + o_raw(23, b"") + o_qs(), o_scps(0x60, 1))
    c.send("c", opts=o_snack(1, 2) + NOP + NOP, flags=ACK)
    c.send("c", b"scps" * 30, opts=o_snack(0, 1) + NOP + NOP, flags=ACK, dt=0.01)
    c.send("s", opts=o_snack(3, 4) + NOP + NOP, flags=ACK)
    # extended capabilities after capabilities
    c = one(o_scps(0xf8, 1), o_scps(0xf8, 1))
    c.send("c", opts=o_raw(20, b"\x03\x10\xaa\xbb\x04\x20\x01\x02\x03\x04\x05\x06"), flags=ACK)
    c.send("c", opts=o_raw(20, b"\x03\x00"), flags=ACK)
    # Riverbed probe and transparency
    cip, sip = "192.0.2.77", "198.51.100.77"
    p = one(o_rvbd_probe(0x01 | (0 << 4), b"\x00" + ip4(cip) + struct.pack(">H", 0x0505)))      # v1 query
    p = one(o_rvbd_probe(0x01 | (3 << 4), b"\x00" + ip4(cip) + struct.pack(">H", 0x0505)))      # v1 trace
    p = one(o_rvbd_probe(0x01 | (4 << 4), b"\x00" + ip4(cip) + struct.pack(">H", 0x0505)), None)  # v1 query SH
    one(o_rvbd_probe(0x01 | (2 << 4), b"\x00" + ip4(cip) + struct.pack(">H", 5)), None)  # v1 internal
    one(o_rvbd_probe(0x01 | (1 << 4), b"\x00" + ip4(cip) + ip4(sip) + struct.pack(">H", 7800)),
        o_rvbd_probe(0x01 | (1 << 4), b"\x00" + ip4(cip) + ip4(sip) + struct.pack(">H", 7800)))
    one(o_rvbd_probe(0x01 | (5 << 4), b"\x00" + ip4(cip) + ip4(cip) + ip4(sip) + struct.pack(">H", 7800)),
        o_rvbd_probe(0x01 | (5 << 4), b"\x00" + ip4(cip) + ip4(cip) + ip4(sip) + struct.pack(">H", 7800)))
    one(o_rvbd_probe(0x01 | (11 << 4), b"\x00" + ip4(cip)), None)    # v1 unknown type
    # v2 types: type << 1, version bit clear
    for t, body in ((6, bytes([0x05])), (6, bytes([0x04])), (8, bytes([0x01]) + ip4(cip)), (9, bytes([0x01]) + ip4(cip)),
                    (7, bytes([0x13])), (10, bytes([0x02])), (7, bytes([0x00]))):
        one(o_rvbd_probe(t << 1, body + b"\x00" * 0), None)
    c = Conn(cap, cp=42100, sp=31005)
    c.send("c", flags=SYN, opts=o_rvbd_probe(6 << 1, bytes([0x01])))
    c.send("s", flags=SYN | ACK, opts=o_rvbd_probe(6 << 1, bytes([0x01, 0, 0, 0])))
    c.send("s", flags=SYN | ACK, opts=o_rvbd_probe(6 << 1, bytes([0x01, 0, 0, 0])), dt=0.1)
    one(o_trpy(0x0001, cip, sip, 4000, 80), o_trpy(0x0706, cip, sip, 4001, 81, cport=4002))
    one(o_trpy(0x0102, cip, sip, 4000, 80, cport=4003), None)
    one(o_trpy(0x0004, cip, sip, 4000, 80), None)
    # accurate ECN options, both orders, all lengths
    for k in (0xac, 0xae):
        for n in (0, 3, 6, 9):
            one(o_raw(k, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"[:n]), None)
    # MSS and SACK permitted outside a SYN
    c = Conn(cap, cp=42200, sp=31005)
    c.handshake(o_mss(1460) + o_sackp(), o_mss(1460) + o_sackp())
    c.send("c", b"x", opts=o_mss(1000) + o_sackp())
    # TTL buckets and option shapes for the TCP fingerprint field
    for i, (ttl, o) in enumerate(((20, o_mss(1460) + NOP + o_ws(3) + NOP + NOP + o_sackp()),
                                  (60, o_mss(1400) + o_tfo(bytes(range(8))) + o_sackp() + NOP + o_ws(6)),
                                  (100, NOP + NOP + NOP + o_tfo(bytes(range(8))) + o_mss(1460)),
                                  (128, o_raw(0xfe, b"\xf9\x89" + b"\x01\x02\x03\x04") + NOP + o_mss(1360) + o_ts(5, 0)),
                                  (150, o_raw(0xfd, b"\x00\xac") + o_md5() + o_ao()),
                                  (250, o_mss(1460) + mp(0x01, bytes([0x81])) + mp(0x00, bytes([0x81]) + struct.pack(">Q", 5)) + o_ws(1)),
                                  (64, o_raw(0xfe, b"\x00") + NOP),
                                  (64, o_mss(1460) + NOP + NOP + EOL))):
        port[0] += 1
        cap.add(tcp_packet("192.0.2.%d" % (50 + i), "198.51.100.50", port[0], 31005, 1000, 0, SYN, opts=o, ttl=ttl))
    # Experimental options (RFC 6994 format when the preference is on): TARR, accurate ECN, TFO, others
    one(o_exp(0xfe, 0x00ac) + NOP + NOP, None)
    one(o_exp(0xfd, 0x00ac, b"\x14") + NOP, None)
    one(o_exp(0xfe, 0x00ac, b"\x14\x00\x00"), None)
    one(o_exp(0xfe, 0xacc0) + NOP + NOP, None)
    one(o_exp(0xfe, 0xacc1, b"\x01\x02\x03"), None)
    one(o_exp(0xfe, 0xacc0, b"\x01\x02\x03\x04\x05\x06"), None)
    one(o_exp(0xfe, 0xacc1, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"), None)
    one(o_exp(0xfe, 0xf989), None)
    one(o_exp(0xfe, 0xf989, b"\x01\x02\x03\x04\x05\x06\x07\x08"), None)
    one(o_exp(0xfd, 0xbeef, b"\x01\x02\x03\x04\x05\x06\x07\x08"), None)
    one(o_exp(0xfe, 0x0348), None)
    endsection(cap, "TCP options")

def sec_reassembly(cap):
    section(cap, "reassembly: HTTP and DNS over TCP")
    c = Conn(cap, cp=43001, sp=80)
    c.handshake(o_mss(1460) + o_sackp(), o_mss(1460) + o_sackp())
    req = b"POST /upload HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 30\r\n\r\n"
    c.send("c", req[:20])                    # header split
    c.send("s")
    c.send("c", req[20:] + b"0123456789")    # rest of header and part of the body
    c.send("s")
    c.send("c", b"0123456789" + b"0123456789")
    body = b"B" * 3000
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n" % len(body) + body
    for i in range(0, len(resp), 1000):
        c.send("s", resp[i:i + 1000])
        c.send("c")
    # pipelined: two requests in one segment, two responses in one segment
    c.send("c", b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
    r1 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    c.send("s", r1 + r1)
    # response until the connection closes (no length) over three segments, FIN with data
    c.send("c", b"GET /3 HTTP/1.0\r\n\r\n")
    c.send("s", b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"x" * 300)
    c.send("s", b"y" * 300)
    c.send("s", b"z" * 100, flags=FIN | ACK | PSH)
    c.send("c", flags=FIN | ACK)
    c.send("s")
    # retransmission of a segment inside a reassembly, and a retransmission after completion
    d = Conn(cap, cp=43002, sp=80)
    d.handshake()
    resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2500\r\n\r\n" + b"R" * 2500
    d.send("c", b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n")
    d.send("s", resp2[:800])
    d.send("s", resp2[800:1600])
    d.send("s", resp2[800:1600], seq=70001 + 800, dt=0.5)       # retransmission inside the PDU
    d.send("s", resp2[1600:2400], seq=70001 + 1600)
    d.send("s", resp2[2400:], seq=70001 + 2400)
    d.send("s", resp2[2400:], seq=70001 + 2400, dt=0.5)          # after completion
    # out-of-order delivery of a response (reassembled in runcov with the OOO preference)
    o = Conn(cap, cp=43003, sp=80)
    o.handshake()
    o.send("c", b"GET /ooo HTTP/1.1\r\nHost: a\r\n\r\n")
    r = b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n" + b"O" * 3000
    base = o.seq["s"]
    chunks = [(0, 1000), (1000, 2000), (2000, 3100)]
    o.send("s", r[0:1000], seq=base)
    o.send("s", r[2000:3041], seq=base + 2000, dt=0.0003)
    o.send("s", r[1000:2000], seq=base + 1000, dt=0.0003)
    o.send("c", ack=base + 3041)
    # DNS over TCP (length prefixed, tcp_dissect_pdus)
    def dns(i):
        q = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\x03www\x07example\x07invalid\x00" + struct.pack(">HH", 1, 1)
        return struct.pack(">H", len(q)) + q
    n = Conn(cap, cp=43010, sp=53)
    n.handshake()
    n.send("c", dns(1))
    n.send("c", dns(2) + dns(3))                       # two PDUs in one segment
    p = dns(4)
    n.send("c", p[:1])                                 # one octet of the length
    n.send("c", p[1:10])
    n.send("c", p[10:] + dns(5)[:5])                   # completes #4, starts #5
    n.send("c", dns(5)[5:] + dns(6))
    n.send("s", dns(7))
    p = dns(8)
    n.send("c", p[:2])                                 # length only
    n.send("c", p[2:12])
    n.send("c", p[2:12], seq=n.seq["c"] - 10, dt=0.3)  # retransmission inside the PDU
    n.send("c", p[12:])
    n.send("c", dns(9))
    # a PDU starting after a gap
    n.seq["c"] += 17
    n.send("c", dns(10))
    n.send("s", dns(11))
    # one PDU whose segments arrive out of order
    q = Conn(cap, cp=43011, sp=53)
    q.handshake()
    p = dns(12)
    b0 = q.seq["c"]
    q.send("c", p[:10], seq=b0)
    q.send("c", p[20:], seq=b0 + 20, dt=0.0002)
    q.send("c", p[10:20], seq=b0 + 10, dt=0.0002)
    q.send("s", ack=b0 + len(p))
    endsection(cap, "reassembly: HTTP and DNS over TCP")

def sec_urgent_ipv6(cap):
    section(cap, "urgent pointer, IPv6, IP options, ECN codepoints")
    c = Conn(cap, cp=44001, sp=23)
    c.handshake()
    c.send("c", b"0123456789", flags=ACK | URG | PSH, urg=5)
    c.send("c", b"0123456789", flags=ACK | URG, urg=10)
    c.send("c", b"0123456789", flags=ACK | URG, urg=100)
    c.send("c", b"0123456789", flags=ACK | URG, urg=0)
    c.send("c", b"0123456789", flags=ACK, urg=7)               # pointer without the flag
    c.send("s", b"", flags=ACK | URG, urg=3)
    c.send("c", b"0123456789", flags=ACK | URG, urg=1, opts=NOP + NOP + o_ts(1, 1))
    c = Conn(cap, cp=44002, sp=31006, v6=True)
    v6a, v6b = "2001:db8::1", "2001:db8::2"
    c.c, c.s = v6a, v6b
    c.handshake(o_mss(1440) + o_sackp() + o_ts(1, 0) + NOP + o_ws(6), o_mss(1440) + o_sackp() + o_ts(2, 1) + NOP + o_ws(6))
    c.send("c", b"v6 data" * 20, opts=tsopt(2, 2), tos=0x2e << 2 | 1)
    c.send("s", opts=tsopt(3, 2), tos=3)
    c.send("c", b"v6 data" * 20, opts=tsopt(3, 3), tos=2)
    c.send("c", b"lost", seq=c.seq["c"] + 100, opts=tsopt(4, 3))
    c.send("s", opts=tsopt(4, 3), ack=None)
    c.close()
    # IPv4 with options and with a TOS value, not-DF, TTL
    c = Conn(cap, cp=44003, sp=31006)
    c.handshake()
    c.send("c", b"opts", ipopts=b"\x94\x04\x00\x00", tos=0x10)
    c.send("c", b"ttl", ttl=1, df=False, tos=0xb8)
    c.send("s", ttl=255)
    # reserved bits and NS
    c = Conn(cap, cp=44004, sp=31006)
    c.send("c", flags=SYN | NS, opts=o_mss(1460))
    c.send("s", flags=SYN | ACK | NS)
    c.send("c", flags=ACK | NS | PSH, payload=b"ns", reserved=0)
    c.send("c", flags=ACK | PSH, payload=b"res", reserved=3)
    c.send("c", flags=FIN | RST | URG | ACK)      # unusual flag combination

    # Accurate ECN: SYN with AE|CWR|ECE, SYN/ACK with CWR, then ACE counters in the flag bits
    c = Conn(cap, cp=44005, sp=31006)
    c.send("c", flags=SYN | NS | CWR | ECE, opts=o_mss(1460) + o_sackp())
    c.send("s", flags=SYN | ACK | CWR, opts=o_mss(1460) + o_sackp())
    c.send("c", flags=ACK | NS)
    for fl in (ACK | PSH, ACK | CWR, ACK | ECE, ACK | NS | ECE, ACK | NS | CWR, ACK | NS | CWR | ECE, ACK | NS):
        c.send("c", b"ace", flags=fl)
        c.send("s", flags=ACK | (fl & (NS | CWR | ECE)))
    c.send("c", b"acc", opts=o_raw(0xac, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"), flags=ACK)
    # second flavour: SYN/ACK with AE set, ECE clear
    c = Conn(cap, cp=44006, sp=31006)
    c.send("c", flags=SYN | NS | CWR | ECE, opts=o_mss(1460) + o_sackp())
    c.send("s", flags=SYN | ACK | NS, opts=o_mss(1460) + o_sackp())
    c.send("c", flags=ACK | NS | CWR)
    c.send("c", b"x", flags=ACK | NS | CWR | ECE)
    # RST with a diagnostic payload (magic 0x33aa, reason code, PEN), vendor reason, other text, short
    c = Conn(cap, cp=44007, sp=31006)
    c.handshake()
    c.send("s", struct.pack(">HHI", 0x33aa, 9, 0), flags=RST | ACK)
    c = Conn(cap, cp=44008, sp=31006)
    c.handshake()
    c.send("s", struct.pack(">HHI", 0x33aa, 3, 32473), flags=RST | ACK)
    c = Conn(cap, cp=44009, sp=31006)
    c.handshake()
    c.send("c", b"Connection refused", flags=RST | ACK)
    c = Conn(cap, cp=44010, sp=31006)
    c.handshake()
    c.send("c", struct.pack(">HHI", 0x33aa, 3, 1) + b"x", flags=RST | ACK)
    c = Conn(cap, cp=44011, sp=31006)
    c.handshake()
    c.send("c", b"q", flags=RST | ACK)
    # TCP header inside ICMP destination unreachable (RFC 792: 8 octets of the TCP header)
    cap.add(icmp_unreach(inner_tcp("192.0.2.10", "198.51.100.20", 43001, 80, 1)))
    c = Conn(cap, cp=44012, sp=31006)
    c.handshake()
    c.send("c", b"icmp me")
    cap.add(icmp_unreach(inner_tcp("192.0.2.10", "198.51.100.20", 44012, 31006, c.seq["c"] - 7, 8), code=1))
    cap.add(icmp_unreach(inner_tcp("192.0.2.10", "198.51.100.20", 44012, 31006, c.seq["c"], 20), code=4))
    cap.add(icmp_unreach(inner_tcp("192.0.2.10", "198.51.100.20", 44012, 31006, c.seq["c"], 8), code=3))
    # checksums: 0xffff for a true 0x0000, offload partial sums (right on the wire, counted at check_checksum)
    cap.add(tcp_special_checksum("ffff"))
    cap.add(tcp_special_checksum("partial"))
    cap.add(tcp_special_checksum("partial_nolen", sport=48501))
    # RST with a NetScaler error code in the window field
    c = Conn(cap, cp=44013, sp=31006)
    c.handshake()
    c.send("s", flags=RST | ACK, win=8196)
    c = Conn(cap, cp=44014, sp=31006)
    c.handshake()
    c.send("c", flags=RST | ACK, win=8206)
    # SYN with TFO data whose SYN/ACK ignores the data (acks only the SYN)
    c = Conn(cap, cp=44015, sp=31006, cisn=5000, sisn=9000)
    c.send("c", b"fast open data", flags=SYN, opts=o_mss(1460) + o_tfo(bytes(range(8))) + o_sackp())
    c.send("s", flags=SYN | ACK, ack=5001, opts=o_mss(1460) + o_sackp())
    c.send("c", b"fast open data", seq=5001, flags=ACK)
    c.send("s", ack=5001 + 14)
    # SYN fingerprints: Linux-like, Windows-like, macOS-like, BGP MD5, MPTCP Linux
    cap.add(tcp_packet("192.0.2.71", "198.51.100.71", 48600, 31006, 1000, 0, SYN, win=64240, ttl=64,
                       opts=o_mss(1460) + o_sackp() + o_ts(1, 0) + NOP + o_ws(7)))
    cap.add(tcp_packet("192.0.2.72", "198.51.100.71", 48601, 31006, 1000, 0, SYN, win=64240, ttl=128,
                       opts=o_mss(1460) + NOP + o_ws(8) + NOP + NOP + o_sackp()))
    cap.add(tcp_packet("192.0.2.73", "198.51.100.71", 48602, 31006, 1000, 0, SYN | ECE | CWR, win=65535, ttl=64,
                       opts=o_mss(1460) + NOP + o_ws(6) + NOP + NOP + o_ts(1, 0) + o_sackp() + EOL * 2))
    cap.add(tcp_packet("192.0.2.74", "198.51.100.71", 48603, 31006, 1000, 0, SYN, win=16384, ttl=255,
                       opts=o_mss(1460) + o_md5()))
    cap.add(tcp_packet("192.0.2.75", "198.51.100.71", 48604, 31006, 1000, 0, SYN, win=64240, ttl=64,
                       opts=o_mss(1460) + o_sackp() + o_ts(1, 0) + NOP + o_ws(7) + mp(0x00, bytes([0x81]) + struct.pack(">Q", 9))))
    endsection(cap, "urgent pointer, IPv6, IP options, ECN codepoints")

def sec_mptcp(cap):
    section(cap, "MPTCP v0 and v1")
    mpc_flags_v0 = 0x01 | 0x80
    def keys(a, b=None):
        return struct.pack(">Q", a) + (struct.pack(">Q", b) if b is not None else b"")
    # ---- v0 ------------------------------------------------------------
    c = Conn(cap, cp=45001, sp=31007, cisn=100000, sisn=200000)
    c.send("c", flags=SYN, opts=o_mss(1460) + mp(0x00, bytes([mpc_flags_v0]) + keys(KEY_A)) + o_sackp())
    c.send("s", flags=SYN | ACK, opts=o_mss(1460) + mp(0x00, bytes([mpc_flags_v0]) + keys(KEY_B)) + o_sackp())
    c.send("c", opts=mp(0x00, bytes([mpc_flags_v0]) + keys(KEY_A, KEY_B)) + NOP + NOP)
    d1 = (IDSN[0]["A"] + 1) & 0xffffffff
    # DSS with 4 octet DSN and ack, mapping and checksum
    dss = lambda flags, body: mp(0x20, bytes([flags]) + body)
    c.send("c", b"M" * 100, opts=dss(0x05, struct.pack(">II", d1, 1) + struct.pack(">IHHH", 1, 100, 0xbeef, 0)))
    c.send("s", opts=dss(0x01, struct.pack(">I", d1 + 100)))
    # 8 octet DSN and 8 octet ack, no checksum
    c.send("c", b"N" * 100, opts=dss(0x0f, struct.pack(">Q", IDSN[0]["B"] + 1) + struct.pack(">Q", d1 + 100) + struct.pack(">IH", 101, 100)))
    # DATA_FIN with mapping of length 1
    c.send("s", opts=dss(0x01, struct.pack(">I", d1 + 200)))
    c.send("c", opts=dss(0x15, struct.pack(">I", d1 + 200) + struct.pack(">IIH", d1 + 200, 0, 1)))
    # address management
    hm = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    c.send("s", opts=mp(0x34, b"\x01" + ip4("203.0.113.5")))
    c.send("s", opts=mp(0x34, b"\x02" + ip4("203.0.113.6") + struct.pack(">H", 8080)))
    c.send("s", opts=mp(0x36, b"\x03" + ip6("2001:db8::5")))
    c.send("s", opts=mp(0x36, b"\x04" + ip6("2001:db8::6") + struct.pack(">H", 9090)))
    c.send("s", opts=mp(0x30, b"\x05" + ip4("203.0.113.7") + hm))
    c.send("s", opts=mp(0x31, b"\x06" + ip4("203.0.113.8") + struct.pack(">H", 80) + hm))
    c.send("s", opts=mp(0x30, b"\x07" + ip6("2001:db8::7") + hm))
    c.send("s", opts=mp(0x31, b"\x08" + ip6("2001:db8::8") + struct.pack(">H", 81) + hm))
    c.send("c", opts=mp(0x41, b"\x01") + NOP)
    c.send("c", opts=mp(0x41, b"\x01\x02\x03"))
    c.send("c", opts=mp(0x51, b"") + NOP)            # MP_PRIO without address id
    c.send("c", opts=mp(0x51, b"\x09"))
    c.send("c", opts=mp(0x50, b"\x09"))
    # subflow 2: MP_JOIN, token of KEY_B
    j = Conn(cap, cp=45002, sp=31007, cisn=300000, sisn=400000)
    j.send("c", flags=SYN, opts=o_mss(1460) + mp(0x11, b"\x02" + struct.pack(">II", TOK[0]["B"], 0x11223344)))
    j.send("s", flags=SYN | ACK, opts=o_mss(1460) + mp(0x10, b"\x03" + b"\x00" * 7 + b"\x01" + struct.pack(">I", 0x55667788)))
    j.send("c", opts=mp(0x10, b"\x00" + bytes(range(20))))
    # same data mapped on the second subflow (re-injection), then data-ack
    j.send("c", b"M" * 100, opts=dss(0x05, struct.pack(">II", d1, 1) + struct.pack(">IH", 1, 100)))
    j.send("s", opts=dss(0x01, struct.pack(">I", d1 + 100)))
    j.send("c", b"M" * 100, opts=dss(0x05, struct.pack(">II", d1, 1) + struct.pack(">IH", 1, 100)), seq=j.seq["c"] - 100, dt=0.5)
    j.send("c", opts=mp(0x60, b"\x00" + struct.pack(">Q", 0x0102030405060708)))  # MP_FAIL
    j.send("c", opts=mp(0x70, b"\x00" + struct.pack(">Q", KEY_B)), flags=ACK | RST)         # FASTCLOSE
    j.send("s", opts=mp(0x81, b"\x02"), flags=ACK | RST)                                  # TCPRST
    j.send("s", opts=mp(0x80, b"\x03"), flags=ACK | RST)
    # ---- v1 ------------------------------------------------------------
    c = Conn(cap, cp=45010, sp=31007, cisn=5000, sisn=9000)
    c.send("c", flags=SYN, opts=o_mss(1460) + mp(0x01, bytes([0x81])) + o_sackp())
    c.send("s", flags=SYN | ACK, opts=o_mss(1460) + mp(0x01, bytes([0x81]) + keys(KEY_D)) + o_sackp())
    c.send("c", opts=mp(0x01, bytes([0x81]) + keys(KEY_C, KEY_D)) + NOP + NOP)
    d1 = IDSN[1]["A"] + 1
    c.send("c", b"P" * 50, opts=mp(0x01, bytes([0x81]) + keys(KEY_C, KEY_D) + struct.pack(">HH", 50, 0xabcd)) + NOP + NOP)
    c.send("s", opts=dss(0x01, struct.pack(">I", (d1 + 50) & 0xffffffff)))
    c.send("c", b"Q" * 60, opts=dss(0x0c, struct.pack(">Q", d1 + 50) + struct.pack(">IHH", 51, 60, 0x1234)))
    c.send("s", opts=dss(0x03, struct.pack(">Q", d1 + 110)))
    j = Conn(cap, cp=45011, sp=31007, cisn=6000, sisn=7000)
    j.send("c", flags=SYN, opts=o_mss(1460) + mp(0x11, b"\x01" + struct.pack(">II", TOK[1]["D"], 0xa1a2a3a4)))
    j.send("s", flags=SYN | ACK, opts=o_mss(1460) + mp(0x10, b"\x02" + b"\x00" * 7 + b"\x01" + struct.pack(">I", 0xb1b2b3b4)))
    j.send("c", opts=mp(0x10, b"\x00" + bytes(range(20))))
    j.send("c", b"Q" * 60, opts=dss(0x0c, struct.pack(">Q", d1 + 50) + struct.pack(">IHH", 1, 60, 0x1234)))
    j.send("s", opts=dss(0x01, struct.pack(">I", (d1 + 110) & 0xffffffff)))
    j.send("c", b"Q" * 60, opts=dss(0x0c, struct.pack(">Q", d1 + 50) + struct.pack(">IHH", 1, 60, 0x1234)), seq=j.seq["c"] - 60, dt=0.5)
    # DSS with unusual flag combinations, infinite mapping (length 0)
    j.send("c", b"R" * 10, opts=dss(0x04, struct.pack(">IIH", 1, 70, 0)))
    j.send("c", opts=mp(0x70, b"\x00" + struct.pack(">Q", KEY_D)), flags=ACK | RST)
    # v1 MP_CAPABLE ACK with data and an infinite mapping (length 0), without checksum
    c.send("c", b"P" * 10, opts=mp(0x01, bytes([0x01]) + keys(KEY_C, KEY_D) + struct.pack(">H", 0)) + NOP + NOP)
    # an ACK carrying both keys without the SYN and SYN/ACK in the capture (v0 and v1)
    c = Conn(cap, cp=45040, sp=31007, cisn=11000, sisn=12000)
    c.ack = {"c": 12001, "s": 11001}
    c.seq = {"c": 11001, "s": 12001}
    c.send("c", b"nosyn", opts=mp(0x00, bytes([mpc_flags_v0]) + keys(KEY_A + 7, KEY_B + 7)) + NOP + NOP)
    c = Conn(cap, cp=45041, sp=31007, cisn=13000, sisn=14000)
    c.ack = {"c": 14001, "s": 13001}
    c.seq = {"c": 13001, "s": 14001}
    c.send("c", b"nosyn", opts=mp(0x01, bytes([0x81]) + keys(KEY_C + 7, KEY_D + 7)) + NOP + NOP)
    c.send("s", opts=mp(0x00, bytes([mpc_flags_v0]) + keys(KEY_B + 9)))
    # MP_CAPABLE with unsupported algorithm flags and wrong key echo
    c = Conn(cap, cp=45020, sp=31007)
    c.send("c", flags=SYN, opts=mp(0x00, bytes([0x00]) + keys(KEY_A)))
    c.send("s", flags=SYN | ACK, opts=mp(0x00, bytes([0x40]) + keys(KEY_B)))
    c.send("c", opts=mp(0x00, bytes([0x81]) + keys(KEY_A, KEY_C)))
    # option only on non-handshake packets of a plain connection (MPTCP on established connection)
    c = Conn(cap, cp=45030, sp=31007)
    c.handshake()
    c.send("c", b"plain", opts=dss(0x01, struct.pack(">I", 1)))
    c.send("s", opts=mp(0x60, b"\x00" + struct.pack(">Q", 5)))
    endsection(cap, "MPTCP v0 and v1")

def sec_expdu(cap):
    section(cap, "Exported PDU: tcp.option table, tcp dissector, reproducers")
    A = ex_addr()
    # tcp.option table: NULL guards of the option dissectors
    cap.add(ex_table("tcp.option", 4, b"\x04\x02", A), ifid=1)
    cap.add(ex_table("tcp.option", 34, b"\x22\x06ABCD", A), ifid=1)
    cap.add(ex_table("tcp.option", 30, b"\x1e\x04\x50\x00", A), ifid=1)
    cap.add(ex_table("tcp.option", 2, b"\x02\x04\x05\xb4", A), ifid=1)
    cap.add(ex_table("tcp.option", 3, b"\x03\x03\x05", A), ifid=1)
    cap.add(ex_table("tcp.option", 5, b"\x05\x0a" + struct.pack(">II", 1, 2), A), ifid=1)
    cap.add(ex_table("tcp.option", 21, b"\x15\x06\x00\x01\x00\x02", A), ifid=1)
    cap.add(ex_table("tcp.option", 20, b"\x14\x04\x80\x00", A), ifid=1)
    cap.add(ex_table("tcp.option", 254, b"\xfe\x06\xf9\x89ABCD".replace(b"ABCD", b"ABCD"), A), ifid=1)
    cap.add(ex_table("tcp.option", 76, b"\x4c\x0a\x02\x00\x00\x00\x00\x00", A), ifid=1)
    cap.add(ex_table("tcp.option", 8, o_ts(3, 4), A), ifid=1)
    # mss after a TCP packet of the same conversation
    cap.add(ex_name("tcp", bare_tcp(SYN, opts=o_scps(0x80, 1)), A), ifid=1)
    cap.add(ex_table("tcp.option", 2, b"\x02\x04\x05\xb4", A), ifid=1)
    cap.add(ex_table("tcp.option", 5, b"\x05\x0a" + struct.pack(">II", 1, 2), A), ifid=1)
    cap.add(ex_table("tcp.option", 21, b"\x15\x06\x00\x01\x00\x02", A), ifid=1)
    # scps extended capabilities of 302 octets in an established conversation (loop reproducer)
    cap.add(ex_table("tcp.option", 20, b"\x14\x00" + b"\x00" * 300, A), ifid=1)
    # tcp without addresses (checksum address type reproducer; clean at default preferences)
    cap.add(ex_name("tcp", bare_tcp(SYN, sport=40100, dport=5000)), ifid=1)
    cap.add(ex_name("tcp", bare_tcp(ACK | PSH, sport=40100, dport=5000, payload=b"noaddr", seq=1001, ack=1)), ifid=1)
    # port type absent
    cap.add(ex_name("tcp", bare_tcp(SYN, sport=40101, dport=5000), tlv(20, ip4("192.0.2.3")) + tlv(21, ip4("192.0.2.4"))), ifid=1)
    endsection(cap, "Exported PDU: tcp.option table, tcp dissector, reproducers")

def sec_reproducers(cap):
    section(cap, "reproducers of the fix commit")
    # SNACK option before the Timestamp option with a payload
    pk = tcp_packet("192.0.2.1", "198.51.100.2", 40000, 23, 1000, 1, 0x018,
                    opts=b"\x15\x06\x00\x01\x00\x02" + b"\x08\x0a" + b"\x00" * 8, payload=b"hello\r\n")
    cap.add(pk)
    # MPTCP mapping that starts inside the segment (assert at mptcp.analyze_mappings)
    c = Conn(cap, cp=46001, sp=5000, cisn=1000, sisn=0)
    mpc = b"\x1e\x0c\x01\x01" + struct.pack(">Q", 0x1122334455667788)
    c.send("c", flags=SYN, opts=mpc)
    c.send("c", b"A" * 100, opts=b"\x1e\x0e\x20\x04" + struct.pack(">IIH", 5000, 50, 100), seq=1001, ack=1)
    # many identical segments (duplicate detection list is capped at 64 entries)
    c = Conn(cap, cp=46002, sp=5000)
    c.handshake()
    pkt = tcp_packet(c.c, c.s, c.cp, c.sp, c.seq["c"], c.ack["c"], ACK | PSH, payload=b"X")
    for i in range(70):
        cap.add(pkt, 0.00001 if i else 0.01)
    endsection(cap, "reproducers of the fix commit")

def build_main(cap):
    sec_basic(cap)
    sec_midstream(cap)
    sec_analysis(cap)
    sec_sack(cap)
    sec_fastrt(cap)
    sec_options(cap)
    sec_reassembly(cap)
    sec_pipeline(cap)
    sec_urgent_ipv6(cap)
    sec_mptcp(cap)
    sec_expdu(cap)
    sec_reproducers(cap)

def udp_frame(payload, sport=9999, dport=9999, src="192.0.2.30", dst="198.51.100.30"):
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(u), 7, 0x4000, 64, 17, 0) + ip4(src) + ip4(dst)
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return MAC_S + MAC_C + b"\x08\x00" + h + u

def ip_trunc(frame, keep_tcp):
    """Cut the TCP part of an Ethernet/IPv4 frame to keep_tcp octets, fix the IP length."""
    f = bytearray(frame[:14 + 20 + keep_tcp])
    struct.pack_into(">H", f, 16, 20 + keep_tcp)
    struct.pack_into(">H", f, 24, 0)
    struct.pack_into(">H", f, 24, csum(bytes(f[14:34])))
    return bytes(f)

def build_malformed(cap):
    section(cap, "malformed")
    A, B = "192.0.2.40", "198.51.100.40"
    port = [47000]
    def syn(opts, **kw):
        port[0] += 1
        cap.add(tcp_packet(A, B, port[0], 31010, 1000, 0, SYN, opts=opts, **kw))
    def est(opts, payload=b"", **kw):
        # an established-looking packet (no SYN needed)
        port[0] += 1
        cap.add(tcp_packet(A, B, port[0], 31010, 1000, 5, ACK, opts=opts, payload=payload, **kw))
    # header problems
    full = tcp_packet(A, B, 47900, 31010, 1, 1, ACK | PSH, payload=b"data12345678")
    cap.add(ip_trunc(full, 10))                       # fewer than 20 octets of TCP
    cap.add(ip_trunc(full, 16))
    cap.add(tcp_packet(A, B, 47901, 31010, 1, 1, ACK, payload=b"data", raw_off=3))   # header length 12
    cap.add(tcp_packet(A, B, 47902, 31010, 1, 1, ACK, payload=b"data", raw_off=15))  # header length beyond the frame
    cap.add(tcp_packet(A, B, 47903, 31010, 1, 1, ACK, payload=b"data", raw_off=0))
    cap.add(ip_trunc(tcp_packet(A, B, 47904, 31010, 1, 1, ACK, opts=o_ts(1, 2), payload=b"data"), 24))  # options cut by the capture
    # truncated by capture (caplen) only: IP says more than present
    f = bytearray(tcp_packet(A, B, 47905, 31010, 1, 1, ACK | PSH, payload=b"d" * 50))
    cap.add(bytes(f[:14 + 20 + 20 + 5]))
    f = bytearray(tcp_packet(A, B, 47906, 31010, 1, 1, ACK | PSH, opts=o_ts(1, 2), payload=b"d" * 50))
    cap.add(bytes(f[:14 + 20 + 20 + 3]))
    # option structure errors
    syn(NOP + NOP + NOP + bytes([99]))                         # length byte past end of options
    syn(bytes([99, 1]) + NOP + NOP)                           # too-short length
    syn(bytes([99, 40]) + NOP + NOP)                          # option goes past the end
    syn(bytes([2, 4, 5, 0xb4, 0, 0, 3]) + b"\x01\x02\x03\x04"[:1])       # EOL then non-zero bytes
    syn(NOP * 8 + o_mss(1460))                                # four NOPs in a row
    syn(NOP * 3 + o_mss(100) + NOP)                           # NOP counting resets
    # wrong lengths for options with a fixed length
    wrong = [(2, 3), (2, 6), (3, 2), (3, 4), (4, 3), (4, 4), (6, 4), (7, 3), (8, 6), (8, 12), (11, 4), (12, 5), (13, 3),
             (19, 4), (19, 18), (27, 4), (28, 6), (22, 3), (23, 3), (21, 4), (21, 8), (0xac, 3), (0xae, 4), (0xac, 13), (78, 6),
             (76, 3), (20, 3), (20, 5), (29, 3), (5, 3), (5, 6), (5, 11), (5, 2), (5, 4)]
    for k, n in wrong:
        syn(bytes([k, n]) + b"\x11" * max(0, n - 2) + b"\x01" * (-n % 4))
    # rvbd probe, v1 with each type, too short for its fields
    for t in range(11):
        syn(o_rvbd_probe(0x01 | (t << 4), b"\x00" + b"\x11" * 3))
    for t in range(11):
        syn(o_rvbd_probe(t << 1, b""))
    # SCPS extended capabilities without a preceding SCPS capabilities option, with data cut short
    syn(o_raw(20, b"\x03\x10\xaa\xbb"))
    syn(o_raw(20, b"\x03\x30\xaa"))
    # TFO with SYN/ACK flavours
    syn(o_tfo(bytes(range(8))) + NOP + NOP, ipopts=b"")
    # MPTCP options with truncated bodies and odd lengths (each in its own subtype)
    for sub in range(0, 16):
        for ln in (3, 4, 6, 8, 12):
            est(mp((sub << 4) | 1, b"\x80" * (ln - 3)) if ln >= 3 else b"")
    for ln in (0, 2, 5, 8):
        est(o_raw(30, b"\x00\x81" + b"\x01" * (ln - 2 if ln >= 2 else 0)))
    est(mp(0x31, b"\x01" + ip4("203.0.113.9") + b"\x01\x02\x03\x04\x05"))     # ADD_ADDR with odd length
    est(mp(0x21, bytes([0x15]) + struct.pack(">I", 1)))                          # DSS with truncated mapping
    est(mp(0x21, bytes([0x0c]) + struct.pack(">Q", 1) + struct.pack(">I", 1)))
    est(mp(0x21, bytes([0x03]) + struct.pack(">I", 1)))                          # 8 octet ack, 4 present
    # SACK option with only the header (reads past the option when checking for D-SACK)
    est(o_raw(5, b""))
    est(o_raw(5, b"\x00\x00\x00\x00"))
    est(o_raw(5, struct.pack(">II", 0, 0)))
    None
    # window scale beyond the allowed 14, MSS of zero, zero timestamp
    syn(o_ws(15) + o_mss(0))
    syn(o_ws(255) + o_mss(65535))
    # bad checksums (also used with tcp.check_checksum)
    cap.add(tcp_packet(A, B, 47950, 31010, 1, 1, ACK | PSH, payload=b"bad checksum", good=False))
    cap.add(tcp_packet(A, B, 47950, 31010, 13, 1, ACK | PSH, payload=b"zero checksum", fixed_cksum=0))
    cap.add(tcp_packet(A, B, 47951, 31010, 1, 1, ACK | PSH, payload=b"", good=False))
    cap.add(tcp_packet("2001:db8::31", "2001:db8::32", 47952, 31010, 1, 1, ACK | PSH, payload=b"v6 bad", good=False, v6=True))
    cap.add(tcp_packet("2001:db8::31", "2001:db8::32", 47953, 31010, 1, 1, ACK | PSH, payload=b"v6 good", v6=True))
    # check summing with data that the capture cut short (not enough to verify)
    f = bytearray(tcp_packet(A, B, 47954, 31010, 1, 1, ACK | PSH, payload=b"d" * 100))
    cap.add(bytes(f[:14 + 20 + 20 + 30]))
    # sequence number wrap, retransmission across the wrap, window scaling of zero
    c = Conn(cap, cp=47960, sp=31010, cisn=0xfffffff0, sisn=0xffffff00)
    c.handshake(o_mss(1460) + o_ws(3), o_mss(1460) + o_ws(3))
    c.send("c", b"w" * 100)
    c.send("s", b"v" * 400)
    c.send("c")
    c.send("c", b"w" * 100, seq=0xfffffff1, dt=0.5)
    c.send("c", b"u" * 100)
    c.send("s", ack=c.seq["c"] - 100)
    c.send("c", b"far" * 10, seq=c.seq["c"] + 0x7fffffff)      # far in the future
    c.send("c", b"back" * 10, seq=c.seq["c"] - 0x70000000)      # far in the past
    c.send("s", ack=c.seq["c"] + 100000)
    # SYN carrying data, SYN/ACK with data, FIN with data and a window of zero
    c = Conn(cap, cp=47961, sp=31010)
    c.send("c", b"syn data", flags=SYN)
    c.send("s", b"synack data", flags=SYN | ACK)
    c.send("c", b"ack")
    c.send("s", flags=ACK | FIN, win=0)
    c.send("c", flags=ACK | RST, win=0)
    c.send("c", flags=ACK | RST)
    c.send("c", flags=0)                        # no flags at all
    c.send("c", b"nullscan", flags=0)
    c.send("c", flags=FIN | PSH | URG)          # xmas
    c.send("c", flags=SYN | FIN)
    c.send("c", flags=SYN | RST)
    c.send("c", flags=SYN | ACK | RST)
    # SYN with ACK number set / ACK field set without ACK flag
    c.send("c", flags=SYN, ack=1234, seq=555)
    cap.add(tcp_packet(A, B, 47962, 31010, 1, 77, PSH, payload=b"ack set, flag clear"))
    # reassembly corner cases: HTTP request cut by gaps, FIN with pending data, RST in the middle
    c = Conn(cap, cp=47963, sp=80)
    c.handshake()
    req = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n" + b"b" * 100
    c.send("c", req[:30])
    c.seq["c"] += 20
    c.send("c", req[50:90])                      # a gap
    c.send("c", req[:30], seq=c.seq["c"] - 40 - 20 - 30 + 0, dt=0.2)  # retransmission of the first part
    c.send("c", flags=FIN | ACK)
    c.send("s", flags=RST | ACK)
    c = Conn(cap, cp=47964, sp=80)
    c.handshake()
    c.send("c", req[:30])
    c.send("c", req[30:60], seq=c.seq["c"] - 15)    # overlapping segment, different offset
    c.send("c", req[60:], seq=c.seq["c"])
    c.send("c", req[:60], seq=1001, dt=0.2)         # a retransmission covering the whole PDU
    c.send("c", b"Z" * 10, seq=1001 + 10, dt=0.1)   # same range, different data
    # very large PDU lengths in DNS over TCP and a PDU split in many pieces
    n = Conn(cap, cp=47965, sp=53)
    n.handshake()
    n.send("c", struct.pack(">H", 60000) + b"\0" * 20)
    for i in range(30):
        n.send("c", b"\0" * 100)
    n.send("c", b"\0" * 100)
    # Decode As: TCP in UDP (-d udp.port==9999,tcp)
    cap.add(udp_frame(tcp_packet_hdr_only(SYN, 40500, 5000, 1000, 0, opts=o_mss(1460) + o_sackp())))
    cap.add(udp_frame(tcp_packet_hdr_only(SYN | ACK, 5000, 40500, 2000, 1001, opts=o_mss(1460) + o_sackp() + o_ts(1, 2)), sport=9999))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK | PSH, 40500, 5000, 1001, 2001, payload=b"tcp in udp")))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK | PSH, 40500, 5000, 1011, 2001, payload=b"tcp in udp", opts=o_ts(5, 6))))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK, 5000, 40500, 2001, 1021)))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK | PSH, 40500, 5000, 1001, 2001, payload=b"tcp in udp")))   # retransmission
    cap.add(udp_frame(tcp_packet_hdr_only(RST, 40500, 5000, 1021, 0)))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK, 40500, 5000, 1, 1)[:12]))
    cap.add(udp_frame(tcp_packet_hdr_only(ACK, 40500, 5000, 1, 1, opts=bytes([99, 40, 0, 0]))))
    # Exported PDU: truncated TCP in the "tcp" dissector, tcp.option with empty / short data
    A2 = ex_addr()
    cap.add(ex_name("tcp", bare_tcp(SYN)[:12], A2), ifid=1)
    cap.add(ex_name("tcp", bare_tcp(SYN, opts=o_raw(2, b"")), A2), ifid=1)
    for k in (2, 3, 4, 5, 8, 19, 20, 21, 27, 28, 29, 30, 34, 76, 78, 0xac, 0xfe):
        cap.add(ex_table("tcp.option", k, bytes([k, 2]), A2), ifid=1)
        cap.add(ex_table("tcp.option", k, bytes([k]), A2), ifid=1)
    cap.add(ex_table("tcp.option", 30, b"\x1e\x14\x00\x81" + b"\x01" * 8, A2), ifid=1)
    cap.add(ex_table("tcp.port", 80, b"GET / HTTP/1.1\r\n\r\n", A2), ifid=1)
    endsection(cap, "malformed")

def tcp_packet_hdr_only(flags, sport, dport, seq, ack, opts=b"", payload=b""):
    while len(opts) % 4:
        opts += b"\0"
    off = (20 + len(opts)) // 4
    return struct.pack(">HHIIHHHH", sport, dport, seq, ack, (off << 12) | flags, 65535, 0, 0) + opts + payload

if __name__ == "__main__":
    out = sys.argv[1]
    m = Cap()
    build_main(m)
    m.write(os.path.join(out, "tcp-coverage.pcapng"))
    mm = Cap()
    build_malformed(mm)
    mm.write(os.path.join(out, "tcp-coverage-malformed.pcapng"))
    if "-v" in sys.argv:
        print("main:", len(m.frames), "frames; malformed:", len(mm.frames))
        for k, (a, b) in FRAMES.items():
            print("%5d-%-5d %s" % (a, b, k))

#!/usr/bin/env python3
# Generates test/captures/dns_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic DNS coverage captures for packet-dns.c.

Usage: mkdns.py <outdir>

Writes:
  dns-coverage.pcap            main capture (valid DNS only)
  dns-coverage-malformed.pcap  malformed input (coverage only)
  dns-coverage-large.pcapng    large messages and an exported PDU for the
                               payload-size and record-count buckets of the
                               dns and dns_qr stats (coverage only)

Every packet is built with struct; all addresses are from the documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32) and the names are
under example.com/example.net.
"""
import struct
import sys
import os

# ---------------------------------------------------------------------------
# Link, IP, UDP, TCP, SCTP
# ---------------------------------------------------------------------------

CLI_MAC = bytes.fromhex("020000000001")
SRV_MAC = bytes.fromhex("020000000002")
CLI = bytes([192, 0, 2, 1])
SRV = bytes([192, 0, 2, 53])
CLI6 = bytes.fromhex("20010db8000000000000000000000001")
SRV6 = bytes.fromhex("20010db8000000000000000000000053")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


_ipid = [0]


def ipv4(src, dst, proto, payload):
    _ipid[0] = (_ipid[0] + 1) & 0xFFFF
    total = 20 + len(payload)
    assert total <= 0xFFFF, total
    ttl = 255 if dst[0] == 224 else 64
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, _ipid[0], 0, ttl, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src, dst, nh, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, 64, src, dst) + payload


def eth(src, dst, payload, etype=0x0800):
    return dst + src + struct.pack("!H", etype) + payload


def mac_for(ip):
    if ip in (CLI, CLI6):
        return CLI_MAC
    if ip in (SRV, SRV6):
        return SRV_MAC
    if len(ip) == 4 and ip[0] == 224:
        return bytes([0x01, 0x00, 0x5e, ip[1] & 0x7f, ip[2], ip[3]])
    return bytes([0x02, 0, 0, 0, ip[-2], ip[-1]])


def udp_pkt(src, sport, dst, dport, payload):
    u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    if len(src) == 16:
        ph = src + dst + struct.pack("!IxxxB", len(u), 17)
        c = csum(ph + u) or 0xFFFF
        u = u[:6] + struct.pack("!H", c) + u[8:]
    if len(src) == 16:
        return eth(mac_for(src), mac_for(dst), ipv6(src, dst, 17, u), 0x86DD)
    return eth(mac_for(src), mac_for(dst), ipv4(src, dst, 17, u))


def tcp_seg(src, sport, dst, dport, seq, ack, flags, payload=b""):
    if flags & 0x02:   # SYN: MSS, SACK permitted and window scale options
        opts = b"\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07"
        opts += b"\x00" * ((4 - len(opts) % 4) % 4)
    else:
        opts = b""
    t = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(mac_for(src), mac_for(dst), ipv4(src, dst, 6, t))


# CRC32c for the SCTP checksum
def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_CRCT = _crc32c_table()


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c = _CRCT[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def sctp_data(src, sport, dst, dport, tsn, payload, vtag=0x11223344):
    pad = (4 - len(payload) % 4) % 4
    chunk = struct.pack("!BBHIHHI", 0, 0x03, 16 + len(payload), tsn, 0, tsn & 0xFFFF, 0) + payload + b"\0" * pad
    hdr = struct.pack("!HHII", sport, dport, vtag, 0)
    c = crc32c(hdr + chunk)
    hdr = struct.pack("!HHI", sport, dport, vtag) + struct.pack("<I", c)
    return eth(mac_for(src), mac_for(dst), ipv4(src, dst, 132, hdr + chunk))


# ---------------------------------------------------------------------------
# Capture writing with a clock
# ---------------------------------------------------------------------------

class Cap:
    """Frames with a clock in microseconds."""
    def __init__(self, t0=1700000000.0):
        self.frames = []
        self.us = int(t0 * 1000000)

    @property
    def t(self):
        return self.us / 1e6

    def add(self, frame, dt=0.010):
        self.us += int(round(dt * 1000000))
        self.frames.append((self.us, frame))
        return len(self.frames)

    def wait(self, secs):
        self.us += int(round(secs * 1000000))

    def write_pcap(self, path, linktype=1):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
            for us, fr in self.frames:
                sec, usec = divmod(us, 1000000)
                f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)))
                f.write(fr)


def write_pcapng(path, frames):
    """frames: list of (time in microseconds, interface_id, data); interface 0 is Ethernet,
    interface 1 is Wireshark upper PDU (exported PDU)."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b"\0" * pad
        ln = 12 + len(body)
        return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", 1, 0, 262144))
    out += block(0x00000001, struct.pack("<HHI", 252, 0, 262144))
    for t, ifid, data in frames:
        ts = t
        body = struct.pack("<IIIII", ifid, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data
        out += block(0x00000006, body)
    with open(path, "wb") as f:
        f.write(out)


# ---------------------------------------------------------------------------
# DNS message builder with name compression
# ---------------------------------------------------------------------------

class N:
    """A domain name inside RDATA. labels may be str or bytes; compress=True
    lets the builder use (and record) compression pointers."""
    def __init__(self, name, compress=True):
        self.name = name
        self.compress = compress


def labels_of(name):
    if isinstance(name, (list, tuple)):
        return [l.encode() if isinstance(l, str) else l for l in name]
    if name in ("", "."):
        return []
    return [l.encode() for l in name.rstrip(".").split(".")]


def u8(v):
    return struct.pack("!B", v)


def u16(v):
    return struct.pack("!H", v)


def u32(v):
    return struct.pack("!I", v)


def cstr(s):
    if isinstance(s, str):
        s = s.encode()
    return u8(len(s)) + s


class Msg:
    def __init__(self, ident, flags):
        self.ident = ident
        self.flags = flags
        self.buf = bytearray(12)
        self.counts = [0, 0, 0, 0]
        self.names = {}
        self.compress = True

    def name(self, name, compress=True):
        compress = compress and self.compress
        labs = labels_of(name)
        for i in range(len(labs)):
            key = tuple(l.lower() for l in labs[i:])
            if compress and key in self.names:
                self.buf += u16(0xC000 | self.names[key])
                return
            if len(self.buf) < 0x3FFF and key not in self.names:
                self.names[key] = len(self.buf)
            self.buf += u8(len(labs[i])) + labs[i]
        self.buf += b"\0"

    def raw(self, data):
        self.buf += data

    def parts(self, parts):
        for p in parts:
            if isinstance(p, N):
                self.name(p.name, p.compress)
            else:
                self.buf += p

    def q(self, name, qtype, qclass=1):
        self.name(name)
        self.buf += u16(qtype) + u16(qclass)
        self.counts[0] += 1
        return self

    def rr(self, sec, name, rtype, rdata=(), rclass=1, ttl=3600, rdlen=None):
        """sec: 1 answer, 2 authority, 3 additional."""
        if isinstance(rdata, (bytes, bytearray)):
            rdata = [bytes(rdata)]
        self.name(name)
        self.buf += u16(rtype) + u16(rclass) + u32(ttl)
        pos = len(self.buf)
        self.buf += b"\0\0"
        self.parts(rdata)
        ln = len(self.buf) - pos - 2 if rdlen is None else rdlen
        self.buf[pos:pos + 2] = u16(ln)
        self.counts[sec] += 1
        return self

    def opt(self, options=(), udp=4096, ext_rcode=0, version=0, z=0x8000):
        self.buf += b"\0" + u16(41) + u16(udp) + u8(ext_rcode) + u8(version) + u16(z)
        body = b"".join(u16(c) + u16(len(d)) + d for c, d in options)
        self.buf += u16(len(body)) + body
        self.counts[3] += 1
        return self

    def bytes(self, counts=None):
        c = counts if counts is not None else self.counts
        self.buf[0:12] = struct.pack("!HHHHHH", self.ident, self.flags, *c)
        return bytes(self.buf)


def tcpmsg(m):
    b = m if isinstance(m, (bytes, bytearray)) else m.bytes()
    return u16(len(b)) + b


QF = 0x0100          # standard query, RD
RF = 0x8180          # standard response, RD RA
RFA = 0x8580         # + AA


def resp_flags(rcode=0, aa=False, opcode=0):
    return 0x8000 | (opcode << 11) | (0x400 if aa else 0) | 0x0100 | 0x0080 | rcode


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

class Udp:
    def __init__(self, cap, cli=CLI, cport=40000, srv=SRV, sport=53):
        self.cap, self.cli, self.cport, self.srv, self.sport = cap, cli, cport, srv, sport

    def c(self, m, dt=0.010):
        return self.cap.add(udp_pkt(self.cli, self.cport, self.srv, self.sport, m if isinstance(m, bytes) else m.bytes()), dt)

    def s(self, m, dt=0.010):
        return self.cap.add(udp_pkt(self.srv, self.sport, self.cli, self.cport, m if isinstance(m, bytes) else m.bytes()), dt)


class Tcp:
    def __init__(self, cap, cli=CLI, cport=41000, srv=SRV, sport=53):
        self.cap, self.cli, self.cport, self.srv, self.sport = cap, cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def open(self):
        self.cap.add(tcp_seg(self.cli, self.cport, self.srv, self.sport, self.cseq, 0, 0x02))
        self.cap.add(tcp_seg(self.srv, self.sport, self.cli, self.cport, self.sseq, self.cseq + 1, 0x12))
        self.cseq += 1
        self.sseq += 1
        self.cap.add(tcp_seg(self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq, 0x10))
        return self

    def c(self, data, dt=0.010):
        n = self.cap.add(tcp_seg(self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq, 0x18, data), dt)
        self.cseq += len(data)
        return n

    def s(self, data, dt=0.010):
        n = self.cap.add(tcp_seg(self.srv, self.sport, self.cli, self.cport, self.sseq, self.cseq, 0x18, data), dt)
        self.sseq += len(data)
        return n

    def close(self):
        self.cap.add(tcp_seg(self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq, 0x11))
        self.cap.add(tcp_seg(self.srv, self.sport, self.cli, self.cport, self.sseq, self.cseq + 1, 0x11))
        self.cseq += 1
        self.sseq += 1
        self.cap.add(tcp_seg(self.cli, self.cport, self.srv, self.sport, self.cseq, self.sseq, 0x10))


# ---------------------------------------------------------------------------
# RDATA helpers
# ---------------------------------------------------------------------------

def ip4(s):
    return bytes(int(x) for x in s.split("."))


def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


def bitmap(types):
    """NSEC/NSEC3/CSYNC type bit map (windows)."""
    wins = {}
    for t in types:
        wins.setdefault(t >> 8, set()).add(t & 0xFF)
    out = b""
    for w in sorted(wins):
        bits = wins[w]
        n = max(bits) // 8 + 1
        bm = bytearray(n)
        for b in bits:
            bm[b // 8] |= 0x80 >> (b % 8)
        out += u8(w) + u8(n) + bytes(bm)
    return out


def nxt_bitmap(types):
    n = max(types) // 8 + 1
    bm = bytearray(n)
    for b in types:
        bm[b // 8] |= 0x80 >> (b % 8)
    return bytes(bm)


def pattern(n, seed=1):
    return bytes(((i * 7 + seed * 13) & 0xFF) for i in range(n))


def svcparams(params):
    return b"".join(u16(k) + u16(len(v)) + v for k, v in params)


def echconfiglist(public_name=b"public.example.com"):
    contents = u8(7) + u16(0x0020) + u16(32) + pattern(32, 9)
    contents += u16(8) + u16(0x0001) + u16(0x0001) + u16(0x0001) + u16(0x0003)
    contents += u8(64) + u8(len(public_name)) + public_name + u16(0)
    cfg = u16(0xFE0D) + u16(len(contents)) + contents
    return u16(len(cfg)) + cfg


def loc_rdata(version=0, size=0x12, hp=0x16, vp=0x13, lat=0x80000000 + 3600000 * 52,
              lon=0x80000000 + 3600000 * 4, alt=10000000 + 1500):
    if version != 0:
        return u8(version) + pattern(15)
    return u8(0) + u8(size) + u8(hp) + u8(vp) + u32(lat) + u32(lon) + u32(alt)


def ntlmssp_negotiate():
    flags = 0xE2088297
    return b"NTLMSSP\0" + struct.pack("<IIHHIHHI", 1, flags, 0, 0, 40, 0, 0, 40) + \
        struct.pack("<BBH", 10, 0, 19041) + b"\0\0\0" + u8(15)


def der(tag, body):
    n = len(body)
    if n < 128:
        return u8(tag) + u8(n) + body
    if n < 256:
        return u8(tag) + b"\x81" + u8(n) + body
    return u8(tag) + b"\x82" + u16(n) + body


def spnego_init():
    spnego_oid = der(0x06, bytes.fromhex("2b0601050502"))
    krb5 = der(0x06, bytes.fromhex("2a864886f712010202"))
    mskrb5 = der(0x06, bytes.fromhex("2a864882f712010202"))
    mechtypes = der(0xA0, der(0x30, mskrb5 + krb5))
    neg = der(0xA0, der(0x30, mechtypes))
    return der(0x60, spnego_oid + neg)


# ---------------------------------------------------------------------------
# Main capture
# ---------------------------------------------------------------------------

Q_IDS = [0x1000]


def nid():
    Q_IDS[0] += 1
    return Q_IDS[0]


def qr(conv, qname, qtype, answers=(), auth=(), add=(), qclass=1, qflags=QF, rflags=RF,
       qopt=None, ropt=None, dt=0.010):
    """Query and response. answers/auth/add: list of (name, type, rdata[, class[, ttl]])."""
    i = nid()
    q = Msg(i, qflags).q(qname, qtype, qclass)
    if qopt is not None:
        q.opt(**qopt)
    conv.c(q, dt)
    r = Msg(i, rflags).q(qname, qtype, qclass)
    for sec, lst in ((1, answers), (2, auth), (3, add)):
        for a in lst:
            name, t, rd = a[0], a[1], a[2]
            cl = a[3] if len(a) > 3 else 1
            ttl = a[4] if len(a) > 4 else 3600
            r.rr(sec, name, t, rd, cl, ttl)
    if ropt is not None:
        r.opt(**ropt)
    return conv.s(r)


def build_main(out):
    cap = Cap()
    u = Udp(cap)
    E = "example.com"

    # --- 1. One query/response per RR type ---------------------------------
    qr(u, "www." + E, 1, [("www." + E, 5, [N("web." + E)]),
                          ("web." + E, 1, ip4("192.0.2.10")),
                          ("web." + E, 1, ip4("192.0.2.11"))],
       auth=[(E, 2, [N("ns1." + E)]), (E, 2, [N("ns2." + E)])],
       add=[("ns1." + E, 1, ip4("192.0.2.53")), ("ns1." + E, 28, ip6("2001:db8::53"))])
    # A in class CH (domain + octal address) and HS (not decoded)
    qr(u, "chaos." + E, 1, [("chaos." + E, 1, [N("ch." + E), u16(0o177)], 3)], qclass=3)
    qr(u, "hesiod." + E, 1, [("hesiod." + E, 1, ip4("192.0.2.12"), 4)], qclass=4)
    for t in (3, 4, 7, 8, 9):   # MD MF MB MG MR
        qr(u, "mail." + E, t, [("mail." + E, t, [N("mbox%d.%s" % (t, E))])])
    qr(u, E, 6, [(E, 6, [N("ns1." + E), N([b"host\\.master", "example", "com"]),
                         u32(2024010101), u32(7200), u32(3600), u32(1209600), u32(300)])], rflags=RFA)
    qr(u, "null." + E, 10, [("null." + E, 10, b"\x00\x01opaque")])
    qr(u, "wks." + E, 11, [("wks." + E, 11, ip4("192.0.2.20") + u8(6) + bytes([0x00, 0x00, 0x00, 0x40, 0, 0, 0, 0, 0, 0, 0x80])),
                           ("wks." + E, 11, ip4("192.0.2.20") + u8(17) + bytes([0, 0, 0, 0, 0, 0, 0x04])),
                           ("wks." + E, 11, ip4("192.0.2.20") + u8(1) + bytes([0x81]))])
    # PTR: in-addr.arpa, ip6.arpa, other names
    qr(u, "10.2.0.192.in-addr.arpa", 12, [("10.2.0.192.in-addr.arpa", 12, [N("web." + E)])])
    rev6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    qr(u, rev6, 12, [(rev6, 12, [N("v6host." + E)])])
    qr(u, "a.b.c.d.example.arpa", 12, [("a.b.c.d.example.arpa", 12, [N("other." + E)])])
    rev6x = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip7.arpa"
    qr(u, rev6x, 12, [(rev6x, 12, [N("v7host." + E)])])
    qr(u, "_services._dns-sd._udp." + E, 12, [("_services._dns-sd._udp." + E, 12, [N("_http._tcp." + E)])])
    qr(u, "hinfo." + E, 13, [("hinfo." + E, 13, cstr("INTEL-386") + cstr("UNIX"))])
    qr(u, "list." + E, 14, [("list." + E, 14, [N("owner." + E), N("errors." + E)])])
    qr(u, E, 15, [(E, 15, [u16(10), N("mail." + E)]), (E, 15, [u16(20), N("mail2.example.net")])])
    qr(u, "txt." + E, 16, [("txt." + E, 16, cstr("v=spf1 -all") + cstr("second string") + cstr(""))])
    dc = "2.dnscrypt-cert." + E
    cert = b"DNSC" + u16(1) + u16(0) + pattern(64, 2) + pattern(32, 3) + pattern(8, 4) + u32(1) + u32(1700000000) + u32(1731536000)
    assert len(cert) == 124
    qr(u, dc, 16, [(dc, 16, cstr(cert)), (dc, 16, cstr("not a certificate")),
                   (dc, 16, cstr(b"XXXX" + cert[4:]))])
    qr(u, "rp." + E, 17, [("rp." + E, 17, [N("admin." + E), N("rp-txt." + E)])])
    qr(u, E, 18, [(E, 18, [u16(1), N("afsdb." + E)])])
    qr(u, "x25." + E, 19, [("x25." + E, 19, cstr("311061700956"))])
    qr(u, "isdn." + E, 20, [("isdn." + E, 20, cstr("150862028003217") + cstr("004")),
                            ("isdn." + E, 20, cstr("150862028003217"))])
    qr(u, "rt." + E, 21, [("rt." + E, 21, [u16(10), N("relay." + E)])])
    qr(u, "nsap." + E, 22, [("nsap." + E, 22, bytes.fromhex("47000580ffff000000321000000a0b0c0d0e0f00"))])
    qr(u, "f.e.d.c.b.a.nsap.int", 23, [("f.e.d.c.b.a.nsap.int", 23, [N("nsap-host." + E)])])
    qr(u, "sig." + E, 24, [("sig." + E, 24, [u16(1), u8(5), u8(3), u32(86400), u32(1704067200), u32(1701388800),
                                             u16(12345), N(E), pattern(32, 5)])])
    qr(u, "key." + E, 25, [("key." + E, 25, u16(0x0100) + u8(3) + u8(5) + pattern(64, 6)),
                           ("key." + E, 25, u16(0x4201) + u8(3) + u8(1) + pattern(64, 7)),
                           ("key." + E, 25, u16(0xC000) + u8(3) + u8(8))])
    qr(u, "px." + E, 26, [("px." + E, 26, [u16(10), N("map822." + E), N("prmd-x400.example.net")])])
    qr(u, "gpos." + E, 27, [("gpos." + E, 27, cstr("-32.6882") + cstr("116.8652") + cstr("10.0"))])
    qr(u, "v6." + E, 28, [("v6." + E, 28, ip6("2001:db8::1"))])
    qr(u, "loc." + E, 29, [("loc." + E, 29, loc_rdata()),
                           ("loc." + E, 29, loc_rdata(lat=0x80000000 - 3600000 * 33, lon=0x80000000 - 3600000 * 70, alt=9990000)),
                           ("loc." + E, 29, loc_rdata(lat=0x80000000 + 324000001, lon=0x80000000 + 648000001)),
                           ("loc." + E, 29, loc_rdata(version=1))])
    qr(u, "nxt." + E, 30, [("nxt." + E, 30, [N("next." + E), nxt_bitmap([1, 15, 24, 30])])])
    # SRV owner name variants
    for owner in ("_sip._tcp." + E, "printer._ipp._tcp." + E, "inst._http._tcp", "_ldap._tcp.dc",
                  "_kerberos", "_x._udp"):
        qr(u, owner, 33, [(owner, 33, [u16(10), u16(60), u16(5060), N("srv-target." + E)])])
    qr(u, "4.3.2.1.5.5.5.0.0.8.1.e164.arpa", 35,
       [("4.3.2.1.5.5.5.0.0.8.1.e164.arpa", 35, [u16(100), u16(10), cstr("u"), cstr("E2U+sip"),
                                                cstr("!^.*$!sip:info@example.com!"), N("")]),
        ("4.3.2.1.5.5.5.0.0.8.1.e164.arpa", 35, [u16(100), u16(20), cstr("S"), cstr("SIP+D2U"), cstr(""),
                                                N("_sip._udp." + E)])])
    qr(u, "kx." + E, 36, [("kx." + E, 36, [u16(10), N("kx-host." + E)])])
    qr(u, "cert." + E, 37, [("cert." + E, 37, u16(1) + u16(12345) + u8(8) + pattern(48, 8)),
                            ("cert." + E, 37, u16(253) + u16(0) + u8(0))])
    qr(u, "a6." + E, 38, [("a6." + E, 38, u8(0) + ip6("2001:db8::a6")),
                          ("a6." + E, 38, [u8(64), ip6("::1:2:3:4")[8:], N("prefix." + E)]),
                          ("a6." + E, 38, [u8(128), N("prefix128." + E)])])
    qr(u, "dname." + E, 39, [("dname." + E, 39, [N("dname-target.example.net")])])
    qr(u, "apl." + E, 42, [("apl." + E, 42, u16(1) + u8(21) + u8(3) + bytes([192, 168, 32]) +
                            u16(2) + u8(32) + u8(0x80 | 4) + ip6("2001:db8::")[:4] +
                            u16(16) + u8(8) + u8(2) + b"\xab\xcd" +
                            u16(1) + u8(0) + u8(0))])
    qr(u, E, 43, [(E, 43, u16(12345) + u8(8) + u8(2) + pattern(32, 10))])
    qr(u, "ssh." + E, 44, [("ssh." + E, 44, u8(1) + u8(1) + pattern(20, 11)), ("ssh." + E, 44, u8(4) + u8(2))])
    qr(u, "ipsec." + E, 45, [("ipsec." + E, 45, u8(10) + u8(0) + u8(2) + pattern(16, 12)),
                             ("ipsec." + E, 45, u8(10) + u8(1) + u8(2) + ip4("192.0.2.45") + pattern(16, 13)),
                             ("ipsec." + E, 45, u8(10) + u8(2) + u8(3) + ip6("2001:db8::45") + pattern(16, 14)),
                             ("ipsec." + E, 45, [u8(10), u8(3), u8(4), N("gw." + E), pattern(16, 15)]),
                             ("ipsec." + E, 45, u8(10) + u8(1) + u8(0) + ip4("192.0.2.46")),
                             ("ipsec." + E, 45, u8(10) + u8(9) + u8(2) + pattern(8, 16))])
    qr(u, "www." + E, 46, [("www." + E, 46, [u16(1), u8(8), u8(3), u32(3600), u32(1704067200), u32(1701388800),
                                             u16(12345), N(E), pattern(64, 17)]),
                           ("www." + E, 46, [u16(28), u8(13), u8(3), u32(3600), u32(1704067200), u32(1701388800),
                                             u16(23456), N(E)])])
    qr(u, "alpha." + E, 47, [("alpha." + E, 47, [N("beta." + E), bitmap([1, 2, 6, 15, 16, 28, 46, 47, 48, 256, 257])])])
    qr(u, E, 48, [(E, 48, u16(257) + u8(3) + u8(8) + pattern(132, 18)),
                  (E, 48, u16(256) + u8(3) + u8(1) + pattern(67, 19)),
                  (E, 48, u16(0x0180) + u8(3) + u8(15) + pattern(32, 20)),
                  (E, 48, u16(256) + u8(3) + u8(13) + pattern(65, 46))])
    qr(u, "dhcid." + E, 49, [("dhcid." + E, 49, u16(2) + u8(1) + pattern(32, 21))])
    qr(u, "b4um86eghhds6nea196smvmlo4ors995." + E, 50,
       [("b4um86eghhds6nea196smvmlo4ors995." + E, 50, u8(1) + u8(1) + u16(10) + cstr(bytes.fromhex("aabbccdd")) +
         cstr(pattern(20, 22)) + bitmap([1, 2, 6, 46, 48, 51])),
        ("b4um86eghhds6nea196smvmlo4ors995." + E, 50, u8(1) + u8(0) + u16(0) + u8(0) + u8(0) + bitmap([16]))])
    qr(u, E, 51, [(E, 51, u8(1) + u8(0) + u16(10) + cstr(bytes.fromhex("aabbccdd")))])
    qr(u, "_443._tcp." + E, 52, [("_443._tcp." + E, 52, u8(3) + u8(1) + u8(1) + pattern(32, 23))])
    qr(u, "hip." + E, 55, [("hip." + E, 55, [u8(16), u8(2), u16(40), pattern(16, 24), pattern(40, 25),
                                             N("rvs1." + E), N("rvs2.example.net")]),
                           ("hip." + E, 55, u8(16) + u8(2) + u16(8) + pattern(16, 26) + pattern(8, 27))])
    qr(u, E, 59, [(E, 59, u16(12345) + u8(13) + u8(2) + pattern(32, 28))])
    qr(u, E, 60, [(E, 60, u16(257) + u8(3) + u8(13) + pattern(64, 29))])
    qr(u, "pgp." + E, 61, [("pgp." + E, 61, b"mQENBFakeOpenPGPKeyMaterialForTesting")])
    qr(u, E, 62, [(E, 62, u32(66) + u16(3) + bitmap([1, 2, 28]))])
    qr(u, E, 63, [(E, 63, u32(2024010101) + u8(1) + u8(1) + pattern(48, 30))])
    # SVCB / HTTPS
    qr(u, "_dns." + E, 64,
       [("_dns." + E, 64, [u16(1), N("dns1." + E), svcparams([
           (0, u16(1) + u16(3)),                 # mandatory=alpn,port
           (1, cstr("dot") + cstr("doq") + cstr("h2")),
           (3, u16(853)),
           (4, ip4("192.0.2.53") + ip4("192.0.2.54")),
           (6, ip6("2001:db8::53") + ip6("2001:db8::54")),
           (7, b"/dns-query{?dns}")])]),
        ("_dns." + E, 64, [u16(0), N("alias." + E)])])
    qr(u, E, 65,
       [(E, 65, [u16(1), N(""), svcparams([
           (1, cstr("h3")),
           (2, b""),
           (3, u16(8443)),
           (5, echconfiglist()),
           (8, b""),
           (9, b"x"),
           (32769, pattern(12, 31)),
           (65000, b"opaque-value"),
           (65001, b"")])]),
        (E, 65, [u16(2), N("svc2." + E)])])
    qr(u, "_dsync." + E, 66, [("_dsync." + E, 66, [u16(59), u8(1), u16(5300), N("dsync-target." + E)])])
    qr(u, "spf." + E, 99, [("spf." + E, 99, cstr("v=spf1 ip4:192.0.2.0/24 -all") + cstr("second"))])
    qr(u, "ilnp." + E, 104, [("ilnp." + E, 104, u16(10) + pattern(8, 32))])
    qr(u, "ilnp." + E, 105, [("ilnp." + E, 105, u16(10) + ip4("10.1.2.0"))])
    qr(u, "ilnp." + E, 106, [("ilnp." + E, 106, u16(10) + pattern(8, 33))])
    qr(u, "ilnp." + E, 107, [("ilnp." + E, 107, [u16(10), N("l64-subnet." + E)])])
    qr(u, "eui." + E, 108, [("eui." + E, 108, bytes.fromhex("00005e0053 2a".replace(" ", "")))])
    qr(u, "eui." + E, 109, [("eui." + E, 109, bytes.fromhex("00005efffe00532a"))])
    qr(u, "_sip." + E, 256, [("_sip." + E, 256, u16(10) + u16(1) + b"sip:info@example.com")])
    qr(u, E, 257, [(E, 257, u8(0) + cstr("issue") + b"ca.example.net"),
                   (E, 257, u8(0) + cstr("issuewild") + b";"),
                   (E, 257, u8(0x80) + cstr("iodef") + b"mailto:security@example.com"),
                   (E, 257, u8(0) + cstr("tbs") + b"Unknown")])
    qr(u, "amt." + E, 260, [("amt." + E, 260, u8(10) + u8(0)),
                            ("amt." + E, 260, u8(10) + u8(0x81) + ip4("192.0.2.60")),
                            ("amt." + E, 260, u8(10) + u8(2) + ip6("2001:db8::60")),
                            ("amt." + E, 260, [u8(10), u8(0x83), N("amtrelay." + E)]),
                            ("amt." + E, 260, u8(10) + u8(0x05) + pattern(4, 34))])
    qr(u, "resolver.arpa", 261, [("resolver.arpa", 261, cstr("qnamemin") + cstr("exterr=15-17") +
                                  cstr("infourl=https://resolver.example.com/"))])
    qr(u, E, 65281, [(E, 65281, u32(0) + u32(2) + u32(900) + u32(2) + ip4("192.0.2.81") + ip4("192.0.2.82"))])
    qr(u, "2.0.192.in-addr.arpa", 65282, [("2.0.192.in-addr.arpa", 65282, [u32(0), u32(2), u32(900), N(E)])])
    qr(u, "xpf." + E, 65422, [("xpf." + E, 65422, u8(4) + u8(17) + ip4("198.51.100.1") + ip4("192.0.2.53") + u16(12345) + u16(53)),
                              ("xpf." + E, 65422, u8(6) + u8(6) + ip6("2001:db8::1") + ip6("2001:db8::53") + u16(23456) + u16(53)),
                              ("xpf." + E, 65422, u8(5) + u8(0))])
    # A type with no dissector (EID) and an unassigned type
    qr(u, "eid." + E, 31, [("eid." + E, 31, pattern(6, 35))])
    qr(u, "unknown." + E, 65000, [("unknown." + E, 65000, pattern(5, 36))])

    # --- 2. The URI and CAA records of the fix ------------------------------
    # URI with an owner name longer than the target (dns_uri_lenbug) and with
    # a short owner name (dns_uri_shortowner), byte for byte as the reproducers.
    tgt = b"http://x"
    rd = struct.pack("!HH", 10, 20) + tgt
    owner = b"\x12averylongownername\x04test\x00"
    uri_long = u.s(struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + owner + struct.pack("!HHIH", 256, 1, 300, len(rd)) + rd)
    uri_short = u.s(struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\x01a\x00" + struct.pack("!HHIH", 256, 1, 300, len(rd)) + rd)
    # CAA tags that are a prefix of "issue" or empty: not "issue"
    caa = qr(u, "caa." + E, 257, [("caa." + E, 257, u8(0) + cstr("iss") + b"ca.example.net"),
                                  ("caa." + E, 257, u8(0) + cstr("") + b"ca.example.net"),
                                  ("caa." + E, 257, u8(0) + cstr("iodefx") + b"mailto:x@example.com")])

    # --- 3. Name forms -------------------------------------------------------
    # Bitstring label (RFC 2673), non-printable characters, root name
    m = Msg(nid(), RF)
    m.q("bits.example.com", 12)
    m.rr(1, "bits.example.com", 12, [b"\x41\x20\xc0\x00\x02\x01", N("ip6.arpa", False)])
    m.rr(1, "bits.example.com", 12, [N([b"we\x01ird", b"na me", "example", "com"])])
    u.c(Msg(m.ident, QF).q("bits.example.com", 12))
    u.s(m)
    qr(u, ".", 2, [(".", 2, [N("a.root-servers.example")]), (".", 2, [N("b.root-servers.example")])])
    # a pointer to a name that ends in another pointer
    m = Msg(nid(), RF)
    m.q("chain.example.com", 1)
    m.rr(1, "chain.example.com", 5, [N("c1.chain.example.com")])
    m.rr(1, "c1.chain.example.com", 5, [N("c2.c1.chain.example.com")])
    m.rr(1, "c2.c1.chain.example.com", 1, ip4("192.0.2.99"))
    u.c(Msg(m.ident, QF).q("chain.example.com", 1))
    u.s(m)

    # --- 4. EDNS(0) options ------------------------------------------------
    opts_q = [(3, b""), (5, bytes([8, 10, 13, 14, 15])), (6, bytes([1, 2, 4])), (7, bytes([1])),
              (8, u16(1) + u8(24) + u8(0) + bytes([198, 51, 100])),
              (9, b""), (10, pattern(8, 37)), (11, b""), (12, b"\0" * 16), (13, b"example.com."),
              (14, u16(20326) + u16(38696)), (20, u16(1) + u16(28)), (65001, b"local")]
    opts_r = [(3, b"ns1-site-a"), (8, u16(2) + u8(48) + u8(48) + ip6("2001:db8:1::")[:6]),
              (8, u16(3) + u8(8) + u8(0) + b"\x11"),
              (9, u32(604800)), (10, pattern(8, 37) + pattern(16, 38)), (11, u16(600)),
              (13, b""), (15, u16(18)), (15, u16(29) + b"synthesized answer"),
              (18, b"\x05agent\x07example\x03net\x00"), (19, u8(2) + u8(0) + u32(2024010101)),
              (19, u8(2) + u8(250) + pattern(6, 39)), (19, u8(2) + u8(0)), (21, u16(1) + u16(28)),
              (0x50fa, u16(1) + u8(16) + u8(16) + bytes([198, 51])), (2, u32(3600)), (2, u32(3600) + u32(86400)),
              (1, u16(1) + u16(1) + u16(0) + pattern(8, 40) + u32(3600))]
    qr(u, "edns." + E, 1, [("edns." + E, 1, ip4("192.0.2.41"))],
       qopt=dict(options=opts_q), ropt=dict(options=opts_r, udp=1232, ext_rcode=0, version=0, z=0x8001))

    # --- 5. Opcodes, rcodes and flags ---------------------------------------
    qr(u, "ad." + E, 1, [("ad." + E, 1, ip4("192.0.2.42"))], qflags=0x0130,
       rflags=0x8000 | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0040 | 0x0020 | 0x0010)
    qr(u, "nx." + E, 1, auth=[(E, 6, [N("ns1." + E), N("hostmaster." + E), u32(1), u32(7200), u32(3600),
                                     u32(1209600), u32(300)], 1, 300)], rflags=resp_flags(3, aa=True))
    qr(u, "fail." + E, 1, rflags=resp_flags(2))
    qr(u, "refused." + E, 1, rflags=resp_flags(5))
    qr(u, "odd." + E, 1, rflags=resp_flags(12))
    # BADCOOKIE via the extended RCODE (OPT)
    qr(u, "cookie." + E, 1, qopt=dict(options=[(10, pattern(8, 41))]),
       ropt=dict(options=[(10, pattern(8, 41) + pattern(16, 42))], ext_rcode=1), rflags=resp_flags(7))
    # Inverse query, status, notify, unknown opcode
    i = nid()
    m = Msg(i, 1 << 11)
    m.rr(1, "", 1, ip4("192.0.2.10"))
    u.c(m)
    m = Msg(i, 0x8000 | (1 << 11) | 0x80)
    m.q("web." + E, 1)
    m.rr(1, "web." + E, 1, ip4("192.0.2.10"))
    u.s(m)
    i = nid()
    u.c(Msg(i, 2 << 11))
    u.s(Msg(i, 0x8000 | (2 << 11) | 4))
    i = nid()
    m = Msg(i, (4 << 11) | 0x0400).q(E, 6)
    m.rr(1, E, 6, [N("ns1." + E), N("hostmaster." + E), u32(2024010102), u32(7200), u32(3600), u32(1209600), u32(300)])
    u.c(m)
    u.s(Msg(i, 0x8000 | (4 << 11) | 0x0400).q(E, 6))
    i = nid()
    u.c(Msg(i, 3 << 11).q("op3." + E, 1))
    u.s(Msg(i, 0x8000 | (3 << 11) | 4).q("op3." + E, 1))
    # Dynamic update with prerequisites, updates and a TSIG
    i = nid()
    m = Msg(i, 5 << 11)
    m.q(E, 6)
    m.rr(1, "host." + E, 255, b"", 255, 0)               # name in use
    m.rr(1, "new." + E, 1, b"", 254, 0)                  # name not in use
    m.rr(2, "new." + E, 1, ip4("192.0.2.77"), 1, 300)    # add
    m.rr(2, "old." + E, 255, b"", 255, 0)                # delete all RRsets
    m.rr(2, "host." + E, 1, ip4("192.0.2.78"), 254, 0)   # delete one RR
    m.rr(3, "update-key.", 250, [N("hmac-sha256."), u16(0), u32(1700000300), u16(300), u16(32),
                                 pattern(32, 43), u16(i), u16(0), u16(0)], 255, 0)
    u.c(m)
    m = Msg(i, 0x8000 | (5 << 11))
    m.q(E, 6)
    m.rr(3, "update-key.", 250, [N("hmac-sha256."), u16(1), u32(1700000300), u16(300), u16(0),
                                 u16(i), u16(18), u16(6), b"\x00\x00" + u32(1700000400)], 255, 0)
    u.s(m)
    # TKEY: GSS-API negotiation with NTLMSSP and with SPNEGO, and a DH mode key
    for key, mode in ((ntlmssp_negotiate(), 3), (spnego_init(), 3), (pattern(16, 44), 2)):
        i = nid()
        m = Msg(i, 0)
        m.q("tkey-%d.%s" % (i, E), 249, 255)
        m.rr(3, "tkey-%d.%s" % (i, E), 249, [N("gss-tsig."), u32(1700000000), u32(1700086400), u16(mode), u16(0),
                                              u16(len(key)), key, u16(4 if mode == 2 else 0), pattern(4, 45) if mode == 2 else b""],
             255, 0)
        u.c(m)
        m = Msg(i, 0x8000)
        m.q("tkey-%d.%s" % (i, E), 249, 255)
        m.rr(1, "tkey-%d.%s" % (i, E), 249, [N("gss-tsig."), u32(1700000000), u32(1700086400), u16(mode), u16(0),
                                              u16(0), u16(0)], 255, 0)
        u.s(m)

    # --- 6. Transaction tracking --------------------------------------------
    t = Udp(cap, cport=42000)
    i = nid()
    q = Msg(i, QF).q("retrans." + E, 1)
    t.c(q)
    t.c(q, 1.0)                               # retransmission
    r = Msg(i, RF).q("retrans." + E, 1).rr(1, "retrans." + E, 1, ip4("192.0.2.50"), 1, 30)
    t.s(r, 0.5)
    t.s(r, 0.2)                               # response retransmission
    cap.wait(20)
    t.c(q)                                    # same ID after the timer: new transaction
    t.s(r, 0.05)
    t.s(Msg(0x7777, RF).q("unsolicited." + E, 1).rr(1, "unsolicited." + E, 1, ip4("192.0.2.51")))
    t.c(Msg(nid(), QF).q("noanswer." + E, 1))
    # unanswered query repeated after the retransmission timer: new transaction
    i = nid()
    q = Msg(i, QF).q("timer." + E, 1)
    t.c(q)
    cap.wait(20)
    t.c(q)
    t.s(Msg(i, RF).q("timer." + E, 1).rr(1, "timer." + E, 1, ip4("192.0.2.52")))
    # ICMP port unreachable quoting a DNS query
    i = nid()
    q = Msg(i, QF).q("icmp." + E, 1).bytes()
    t.c(q)
    orig = udp_pkt(CLI, 42000, SRV, 53, q)[14:]
    icmp = struct.pack("!BBHI", 3, 3, 0, 0) + orig
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    cap.add(eth(SRV_MAC, CLI_MAC, ipv4(SRV, CLI, 1, icmp)))

    # --- 7. DNS over TCP ----------------------------------------------------
    c = Tcp(cap).open()
    i1, i2 = nid(), nid()
    m1 = Msg(i1, QF).q("tcp1." + E, 1).bytes()
    m2 = Msg(i2, QF).q("tcp2." + E, 28).bytes()
    c.c(tcpmsg(m1) + tcpmsg(m2))              # two messages in one segment
    r1 = tcpmsg(Msg(i1, RF).q("tcp1." + E, 1).rr(1, "tcp1." + E, 1, ip4("192.0.2.61")))
    r2 = tcpmsg(Msg(i2, RF).q("tcp2." + E, 28).rr(1, "tcp2." + E, 28, ip6("2001:db8::61")))
    c.s(r1[:7])                               # split across segments
    c.s(r1[7:] + r2)
    # one message split in two segments (dns_tcp_split)
    inner = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x01a\x01b\x03com\x00" + struct.pack("!HH", 1, 1)
    msg = struct.pack("!H", len(inner)) + inner
    c.c(msg[:5])
    split_frame = c.c(msg[5:])
    c.s(tcpmsg(Msg(1, RF).q("a.b.com", 1).rr(1, "a.b.com", 1, ip4("192.0.2.62"))))
    c.close()
    # Zone transfer: AXFR answered by several messages, then an IXFR
    c = Tcp(cap, cport=41001).open()
    i = nid()
    c.c(tcpmsg(Msg(i, 0).q(E, 252)))
    soa = [N("ns1." + E), N("hostmaster." + E), u32(2024010103), u32(7200), u32(3600), u32(1209600), u32(300)]
    m = Msg(i, 0x8400).q(E, 252)
    m.rr(1, E, 6, soa).rr(1, E, 2, [N("ns1." + E)]).rr(1, "ns1." + E, 1, ip4("192.0.2.53"))
    c.s(tcpmsg(m))
    m = Msg(i, 0x8400)
    m.rr(1, "www." + E, 1, ip4("192.0.2.10")).rr(1, E, 15, [u16(10), N("mail." + E)])
    c.s(tcpmsg(m))
    m = Msg(i, 0x8400)
    m.rr(1, E, 6, soa)
    c.s(tcpmsg(m))
    i = nid()
    q = Msg(i, 0).q(E, 251)
    q.rr(2, E, 6, [N("ns1." + E), N("hostmaster." + E), u32(2024010101), u32(7200), u32(3600), u32(1209600), u32(300)])
    c.c(tcpmsg(q))
    m = Msg(i, 0x8400).q(E, 251)
    m.rr(1, E, 6, soa)
    c.s(tcpmsg(m))
    c.close()

    # --- 8. DNS Stateful Operations (RFC 8490, RFC 8765) --------------------
    c = Tcp(cap, cport=41002).open()
    i = nid()
    dso = lambda ident, flags, tlvs: Msg(ident, flags).bytes() + b"".join(u16(tp) + u16(len(v)) + v for tp, v in tlvs)
    c.c(tcpmsg(dso(i, 6 << 11, [(1, u32(15000) + u32(3600000)), (3, b"\0" * 6)])))
    c.s(tcpmsg(dso(i, 0x8000 | (6 << 11), [(1, u32(15000) + u32(3600000))])))
    i = nid()
    sub = Msg(0, 0)
    sub.name("_ipp._tcp." + E)
    c.c(tcpmsg(dso(i, 6 << 11, [(0x40, bytes(sub.buf[12:]) + u16(12) + u16(1))])))
    c.s(tcpmsg(dso(i, 0x8000 | (6 << 11), [])))
    push = Msg(0, 0)
    push.compress = False      # the records are moved into a TLV: no pointers
    push.rr(1, "_ipp._tcp." + E, 12, [N("printer._ipp._tcp." + E)], 1, 4500)
    push.rr(1, "printer._ipp._tcp." + E, 16, cstr("txtvers=1"), 1, 4500)
    c.s(tcpmsg(dso(0, 6 << 11, [(0x41, bytes(push.buf[12:]))])))
    rec = Msg(0, 0)
    rec.compress = False
    rec.name("_ipp._tcp." + E)
    rec.raw(u16(12) + u16(1))
    rec.name("gone._ipp._tcp." + E)
    c.c(tcpmsg(dso(0, 6 << 11, [(0x43, bytes(rec.buf[12:]))])))
    c.c(tcpmsg(dso(0, 6 << 11, [(0x42, u16(i))])))
    c.s(tcpmsg(dso(0, 6 << 11, [(2, u32(60000)), (0x0100, b"\x01\x02\x03"), (0xF800, b"")])))
    c.close()

    # --- 9. mDNS and LLMNR ---------------------------------------------------
    MC = bytes([224, 0, 0, 251])
    mq = Msg(0, 0)
    mq.q("_ipp._tcp.local", 12)
    mq.q("printer.local", 1, 0x8001)                   # QU question
    mq.rr(1, "_ipp._tcp.local", 12, [N("Printer._ipp._tcp.local")], 1, 4500)   # known answer
    mq.opt(options=[(4, b"\x00\x00" + bytes.fromhex("020000000001")), (65002, b"")], udp=1440, z=0)
    cap.add(udp_pkt(CLI, 5353, MC, 5353, mq.bytes()))
    mr = Msg(0, 0x8400)
    mr.rr(1, "_ipp._tcp.local", 12, [N("Printer._ipp._tcp.local")], 1, 4500)
    mr.rr(3, "Printer._ipp._tcp.local", 33, [u16(0), u16(0), u16(631), N("printer.local")], 0x8001, 120)
    mr.rr(3, "Printer._ipp._tcp.local", 16, cstr("txtvers=1") + cstr("rp=queue"), 0x8001, 4500)
    mr.rr(3, "printer.local", 1, ip4("192.0.2.70"), 0x8001, 120)
    mr.rr(3, "printer.local", 47, [N("printer.local"), bitmap([1, 28])], 0x8001, 120)
    mr.opt(options=[(4, b"\x00\x00" + bytes.fromhex("020000000002"))], udp=1440, z=0)
    cap.add(udp_pkt(SRV, 5353, MC, 5353, mr.bytes()))
    LC = bytes([224, 0, 0, 252])
    i = nid()
    cap.add(udp_pkt(CLI, 50000, LC, 5355, Msg(i, 0).q("llmnrhost", 1).bytes()))
    cap.add(udp_pkt(SRV, 5355, CLI, 50000, Msg(i, 0x8000).q("llmnrhost", 1).rr(1, "llmnrhost", 1, ip4("192.0.2.53"), 1, 30).bytes()))
    i = nid()
    cap.add(udp_pkt(CLI, 50001, LC, 5355, Msg(i, 0x0400 | 0x0100).q("tentative", 28).bytes()))
    cap.add(udp_pkt(SRV, 5355, CLI, 50001, Msg(i, 0x8000 | 0x0400 | 0x0200 | 0x0100).q("tentative", 28)
                    .rr(1, "tentative", 28, ip6("2001:db8::53"), 1, 30).bytes()))

    # --- 10. Other transports ------------------------------------------------
    # Heuristic DNS on non-DNS UDP ports
    h = Udp(cap, cport=40111, sport=40222)
    qr(h, "heur." + E, 1, [("heur." + E, 1, ip4("192.0.2.80"))])
    # UDP payloads on other ports that the DNS heuristic rejects
    for n, payload in enumerate([
            struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0),                       # header only
            struct.pack("!HHHHHH", 1, 0x2800, 1, 0, 0, 0) + b"\0" * 8,            # opcode 5
            struct.pack("!HHHHHH", 1, 0x0100, 2, 0, 0, 0) + b"\0" * 8,            # query, 2 questions
            struct.pack("!HHHHHH", 1, 0x8180, 2, 0, 0, 0) + b"\0" * 8,            # response, 2 questions
            struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 11) + b"\0" * 8,           # 11 additional
            struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 1, 0) + b"\0" * 12,           # no question, no answer
            struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + b"\0" * 8]):          # too short
        cap.add(udp_pkt(CLI, 40600 + n, SRV, 40700 + n, payload))
    # IPv6
    v6 = Udp(cap, cli=CLI6, srv=SRV6, cport=40333)
    qr(v6, "ipv6." + E, 28, [("ipv6." + E, 28, ip6("2001:db8::80"))])
    # SCTP port 53
    i = nid()
    cap.add(sctp_data(CLI, 40444, SRV, 53, 1, Msg(i, QF).q("sctp." + E, 1).bytes()))
    cap.add(sctp_data(SRV, 53, CLI, 40444, 1, Msg(i, RF).q("sctp." + E, 1).rr(1, "sctp." + E, 1, ip4("192.0.2.81")).bytes(),
                      vtag=0x55667788))
    # DNS over HTTPS without TLS (HTTP/1.1, application/dns-message)
    c = Tcp(cap, cport=41003, sport=80).open()
    dq = Msg(0, QF).q("doh." + E, 1).opt(options=[(12, b"\0" * 8)]).bytes()
    c.c(b"POST /dns-query HTTP/1.1\r\nHost: doh.example.com\r\nAccept: application/dns-message\r\n"
        b"Content-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n" % len(dq) + dq)
    dr = Msg(0, RF).q("doh." + E, 1).rr(1, "doh." + E, 1, ip4("192.0.2.82")).opt().bytes()
    c.s(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nCache-Control: max-age=3600\r\n"
        b"Content-Length: %d\r\n\r\n" % len(dr) + dr)
    c.close()

    # --- 11. Statistics: label counts, payload sizes, TTLs, record counts ----
    s = Udp(cap, cport=43000)
    qr(s, "singlelabel", 1)                                       # 1 label (dns_stats_single)
    names = ["a", "a.b", "a.b.c", "a.b.c.d", "a.b.c.d.e", "a.b.c.d.e.f", "a.b.c.d.e.f.g", "a.b.c.d.e.f.g.h",
             "a.b.c.d.e.f.g.h.i", "a.b.c.d.e.f.g.h.i.j"]
    for nm in names[1:]:
        qr(s, nm + ".example", 16, [(nm + ".example", 16, cstr("labels"))])
    # header only query (12 octets) and a query of each size up to 2 KB
    i = nid()
    s.c(Msg(i, 0x0000))
    s.s(Msg(i, 0x8000 | 1))
    for size in (24, 48, 100, 200, 400, 800, 1600):
        i = nid()
        q = Msg(i, QF).q("pad%d.%s" % (size, E), 1)
        base = len(q.bytes()) + 11 + 4
        q.opt(options=[(12, b"\0" * max(0, size - base))])
        s.c(q)
        r = Msg(i, RF).q("pad%d.%s" % (size, E), 1).rr(1, "pad%d.%s" % (size, E), 1, ip4("192.0.2.90"))
        base = len(r.bytes()) + 11 + 4
        r.opt(options=[(12, b"\0" * max(0, size - base))])
        s.s(r)
    # TTL buckets in each section
    ttls = [0, 30, 1800, 43200, 302400, 2000000, 20000000, 40000000]
    i = nid()
    s.c(Msg(i, QF).q("ttl." + E, 1))
    r = Msg(i, RF).q("ttl." + E, 1)
    for n, ttl in enumerate(ttls):
        r.rr(1, "ttl." + E, 1, ip4("192.0.2.%d" % (100 + n)), 1, ttl)
    for n, ttl in enumerate(ttls):
        r.rr(2, E, 2, [N("ns%d.%s" % (n, E))], 1, ttl)
    for n, ttl in enumerate(ttls):
        r.rr(3, "ns%d.%s" % (n, E), 1, ip4("192.0.2.%d" % (200 + n)), 1, ttl)
    s.s(r)
    # record count buckets up to 33
    for cnt in (3, 5, 9, 17, 33):
        i = nid()
        s.c(Msg(i, QF).q("count%d.%s" % (cnt, E), 1))
        r = Msg(i, RF).q("count%d.%s" % (cnt, E), 1)
        for n in range(cnt):
            r.rr(1, "count%d.%s" % (cnt, E), 1, ip4("192.0.2.%d" % n), 1, 60)
        for n in range(cnt):
            r.rr(2, E, 2, [N("ns%d.%s" % (n, E))], 1, 60)
        for n in range(cnt):
            r.rr(3, "ns%d.%s" % (n, E), 1, ip4("198.51.100.%d" % n), 1, 60)
        s.s(r)

    cap.write_pcap(os.path.join(out, "dns-coverage.pcap"))
    return dict(uri_long=uri_long, uri_short=uri_short, caa=caa, split=split_frame, frames=len(cap.frames))


# ---------------------------------------------------------------------------
# Malformed capture
# ---------------------------------------------------------------------------

def build_malformed(out):
    cap = Cap(1700100000.0)
    u = Udp(cap)
    hdr = lambda i, f, qd, an, ns, ar: struct.pack("!HHHHHH", i, f, qd, an, ns, ar)
    rrh = lambda t, ln, cl=1: struct.pack("!HHIH", t, cl, 300, ln)
    x = b"\x01x\x00"
    # The reproducers from the review (dns_probe.py, dns_loop_probe.py, ...)
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(38, 2) + bytes([129, 0]))                      # A6 prefix 129
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(257, 7) + bytes([0, 200]) + b"issue")          # CAA tag length 200
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(256, 1) + b"\x00")                             # URI shorter than 4
    rd = bytes([1, 0]) + u16(0) + bytes([255]) + b"\x01" * 4 + bytes([255]) + b"\x02" * 4 + b"\x00\x01\x40"
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(50, len(rd)) + rd)                             # NSEC3 lengths
    od = u16(8) + u16(20) + u16(2) + b"\x20\x00" + b"\xff" * 20
    u.s(hdr(1, 0x8180, 0, 0, 0, 1) + b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(od)) + od)   # ECS address > 16
    rd = bytes([255, 1]) + u16(255) + b"\xaa" * 10
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(55, len(rd)) + rd)                             # HIP lengths
    rd = struct.pack("!IIII", 0, 0, 0, 0xFFFFFFFF) + bytes([192, 0, 2, 1])
    u.s(hdr(1, 0x8180, 0, 1, 0, 0) + x + rrh(65281, len(rd)) + rd)                          # WINS nservers
    u.c(hdr(1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + u16(1) + u16(1))                          # pointer to itself
    u.c(hdr(1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0e\xc0\x0c" + u16(1) + u16(1))                  # pointer loop
    sq = Udp(cap, cport=40999)
    q = hdr(0x1234, 0x0100, 1, 0, 0, 0) + b"\x10verylonghostpart\x07example\x03com\x00" + u16(1) + u16(1)
    sq.c(q)
    sq.s(hdr(0x1234, 0x8180, 1, 5, 0, 0) + q[12:] + b"\x10verylonghostpart\x07example\x03com\x00" + rrh(1, 4) + bytes([192, 0, 2, 7]))
    c = Tcp(cap, cport=41999).open()
    c.c(b"\x00\x00")                                                                       # TCP length 0
    c.close()
    # More malformed records
    def ans(t, rdata, cl=1, rdlen=None, owner=x):
        return hdr(nid(), 0x8180, 0, 1, 0, 0) + owner + rrh(t, len(rdata) if rdlen is None else rdlen, cl) + rdata
    u.s(ans(16, b"\x0aabc", rdlen=4) + b"\x00" * 8)                  # TXT string longer than the RR
    u.s(ans(99, b"\x0aabc", rdlen=4) + b"\x00" * 8)                  # SPF
    u.s(ans(261, b"\x0aabc", rdlen=4) + b"\x00" * 8)                 # RESINFO
    u.s(ans(11, ip4("192.0.2.1") + b"\x06\xff\xff", rdlen=6) + b"\0" * 4)   # WKS ends inside the bitmap
    u.s(ans(47, b"\x00\x00\x02\xff\xff", rdlen=4) + b"\0" * 4)       # NSEC bitmap over the end
    u.s(ans(30, b"\x00\xff\xff", rdlen=2) + b"\0" * 4)               # NXT bitmap over the end
    u.s(ans(25, u16(0x0100) + u8(3), rdlen=3) + b"\0" * 4)           # KEY too short for a key tag
    u.s(ans(48, u16(0x0100) + u8(3), rdlen=3) + b"\0" * 4)           # DNSKEY too short
    u.s(ans(1, b"\x80\x00", cl=3))                                    # A/CH with a 0x80 label type
    u.s(hdr(nid(), 0x8180, 0, 1, 0, 0) + b"\x03foo\x42" + rrh(1, 4) + ip4("192.0.2.1"))       # unknown extended label
    long_name = b"".join(u8(63) + b"a" * 63 for _ in range(4)) + b"\x00"
    u.s(hdr(nid(), 0x8180, 0, 1, 0, 0) + long_name + rrh(1, 4) + ip4("192.0.2.1"))            # name too long
    u.s(hdr(nid(), 0x8180, 0, 1, 0, 0) + b"\x01" + b"\x00" * 1 + rrh(1, 4))                    # truncated
    u.s(ans(1, ip4("192.0.2.1")) + b"extra")                                                   # extraneous data
    u.s(hdr(nid(), 0x8180, 0, 1, 0, 0) + x + struct.pack("!HHIH", 1, 1, 0x80000001, 4) + ip4("192.0.2.1"))  # TTL high bit
    # EDNS options with bad lengths
    def optmsg(opts):
        body = b"".join(u16(c) + u16(len(d)) + d for c, d in opts)
        return hdr(nid(), 0x8180, 0, 0, 0, 1) + b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(body)) + body
    for o in ((1, b"\0" * 4), (2, b"\0" * 6), (9, b"\0" * 2), (8, u16(1) + u8(24) + u8(0) + b"\x01" * 18)):
        u.s(optmsg([o]))
    # Bitstring labels that fill the 255 octet name buffer at each step
    def bitlabel(nbits, seed):
        return b"\x41" + u8(nbits) + pattern((nbits - 1) // 8 + 1, seed)
    full = b"".join(bitlabel(255, k) for k in range(3))          # 3 x 72 characters
    for name in (b"\x02ab" + full + bitlabel(255, 4),              # runs out inside the hex digits
                 full + bitlabel(113, 5) + bitlabel(8, 6),         # no room for the next "\\[x"
                 full + bitlabel(129, 7)):                         # no room for the "/129]"
        u.s(hdr(nid(), 0x8180, 0, 1, 0, 0) + x + rrh(12, len(name) + 1) + name + b"\x00")
    u.s(optmsg([(10, pattern(4))]))                                  # COOKIE shorter than the client cookie
    u.s(optmsg([(18, b"\x03abc")]))                                  # Report-Channel name runs off
    u.s(optmsg([(15, b"\x00")]))                                     # EDE shorter than 2
    u.s(optmsg([(5, b"\x01")]) + b"\x00\x05\x00\x09")                # option length past the RR
    # SVCB parameters with errors and warnings
    def svcb(params, prio=1):
        return ans(64, u16(prio) + b"\x00" + params)
    u.s(svcb(svcparams([(3, u16(1)), (1, cstr("h2"))])))                                        # key order
    u.s(svcb(svcparams([(1, cstr("h2")), (1, cstr("h3"))])))                                    # duplicate key
    u.s(svcb(svcparams([(0, u16(3) + u16(3) + u16(4))])))                                       # mandatory dup, missing
    u.s(svcb(svcparams([(0, b"\x00"), (1, b"\x00"), (2, b"\x01"), (3, b"\x00"), (4, b"\0" * 5),
                        (6, b"\0" * 5), (8, b"\x00")])))                                        # bad lengths
    u.s(svcb(svcparams([(1, cstr("h2") + b"\x05ab")])))                                        # ALPN past the value
    u.s(svcb(svcparams([(2, b"")])))                                                             # no-default-alpn alone
    u.s(svcb(u16(1) + u16(10) + b"ab"))                                                          # value too long
    u.s(svcb(b"\x00\x01\x00"))                                                                   # header truncated
    u.s(svcb(svcparams([(5, b"\x00\x05" + u16(0xFE0C) + u16(1) + b"\x00")])))                  # unknown ECH version
    # DSO with a TLV length mismatch and a unidirectional response
    c = Tcp(cap, cport=41998).open()
    dso = lambda ident, flags, tlvs: hdr(ident, flags, 0, 0, 0, 0) + b"".join(u16(tp) + u16(ln) + v for tp, ln, v in tlvs)
    c.c(tcpmsg(dso(0x99, 6 << 11, [(1, 6, b"\0" * 6), (2, 6, b"\0" * 6), (0x42, 1, b"\0")])))
    c.s(tcpmsg(dso(0, 0x8000 | (6 << 11), [(0x40, 9, b"\x01x\x00\x00\x01\x00\x01\x00\x00")])))
    c.close()
    # SVCB/HTTPS target and TSIG with gss-tsig (calls the GSS-API dissector on garbage)
    u.s(ans(250, b"\x08gss-tsig\x00" + b"\0" * 6 + u16(300) + u16(4) + b"\xde\xad\xbe\xef" + u16(1) + u16(0) + u16(0)))
    # A truncated DoH message: shorter than a header
    cap.write_pcap(os.path.join(out, "dns-coverage-malformed.pcap"))
    return len(cap.frames)


# ---------------------------------------------------------------------------
# Large capture (coverage of the stats buckets only)
# ---------------------------------------------------------------------------

def build_large(out):
    cap = Cap(1700200000.0)
    u = Udp(cap, cport=44000)
    E = "example.com"
    # payload size buckets above 2 KB
    for size in (3200, 6400, 12800, 25600, 51200):
        i = nid()
        q = Msg(i, QF).q("big%d.%s" % (size, E), 1)
        base = len(q.bytes()) + 11 + 4
        q.opt(options=[(12, b"\0" * (size - base))])
        u.c(q)
        r = Msg(i, RF).q("big%d.%s" % (size, E), 1).rr(1, "big%d.%s" % (size, E), 1, ip4("192.0.2.91"))
        base = len(r.bytes()) + 11 + 4
        r.opt(options=[(12, b"\0" * (size - base))])
        u.s(r)
    # answer/authority/additional count buckets above 33, records with no RDATA
    counts = [65, 129, 257, 513, 1025, 2049, 4097]
    plan = [(c, c, c) for c in counts[:5]] + [(2049, 2049, 0), (0, 0, 2049), (4097, 0, 0), (0, 4097, 0), (0, 0, 4097)]
    rr0 = u16(0xC00C) + u16(1) + u16(1) + u32(60) + u16(0)
    for na, ns, nr in plan:
        i = nid()
        qn = "many%d-%d-%d.%s" % (na, ns, nr, E)
        u.c(Msg(i, QF).q(qn, 1))
        body = Msg(i, RF).q(qn, 1).bytes() + rr0 * (na + ns + nr)
        body = struct.pack("!HHHHHH", i, RF, 1, na, ns, nr) + body[12:]
        assert len(body) < 65000, len(body)
        u.s(body)
    # a large query and response over TCP for the "> 64KB" buckets
    c = Tcp(cap, cport=44001).open()
    i = nid()
    q = Msg(i, QF).q("huge." + E, 1)
    base = len(q.bytes()) + 11 + 4
    q.opt(options=[(12, b"\0" * (65535 - base))])
    data = tcpmsg(q)
    for off in range(0, len(data), 16000):
        c.c(data[off:off + 16000])
    r = Msg(i, RF).q("huge." + E, 1)
    base = len(r.bytes()) + 11 + 4
    r.opt(options=[(12, b"\0" * (65535 - base))])
    data = tcpmsg(r)
    for off in range(0, len(data), 16000):
        c.s(data[off:off + 16000])
    c.close()
    frames = [(us, 0, fr) for us, fr in cap.frames]
    # Exported PDU for "dns" without addresses: the stats use "n/a"
    i = nid()
    for flags, m in ((QF, Msg(i, QF).q("exported." + E, 1)),
                     (RF, Msg(i, RF).q("exported." + E, 1).rr(1, "exported." + E, 1, ip4("192.0.2.92")))):
        tag = b"dns\0"
        pdu = u16(12) + u16(len(tag)) + tag + u16(0) + u16(0) + m.bytes()
        cap.wait(1)
        frames.append((cap.us, 1, pdu))
    write_pcapng(os.path.join(out, "dns-coverage-large.pcapng"), frames)
    return len(frames)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    info = build_main(out)
    nm = build_malformed(out)
    nl = build_large(out)
    print("main: %d frames (URI long owner frame %d, short owner %d, CAA prefix frame %d, TCP split %d)" %
          (info["frames"], info["uri_long"], info["uri_short"], info["caa"], info["split"]))
    print("malformed: %d frames, large: %d frames" % (nm, nl))

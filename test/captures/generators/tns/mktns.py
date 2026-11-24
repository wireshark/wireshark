#!/usr/bin/env python3
# Generates test/captures/tns_coverage.pcap.gz, tns_coverage_malformed.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the TNS coverage captures: mktns.py <outdir> [-v].

Writes tns-coverage.pcap (valid traffic, one TCP stream per group) and
tns-coverage-malformed.pcap (paths only malformed input reaches).
Every byte is built here with struct; the addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys
from decimal import Decimal

# TTC tokens
TTI_FUN, TTI_OER, TTI_RXH, TTI_RXD, TTI_RPA, TTI_STA, TTI_IOV = 3, 4, 6, 7, 8, 9, 11
TTI_DCB, TTI_SPB, TTI_ALL8 = 16, 23, 94
TYPE_VARCHAR, TYPE_NUMBER, TYPE_DATE = 1, 2, 12
TYPE_JSON, TYPE_VECTOR = 119, 127


# ---------------------------------------------------------------- encoding
def ub4(val):
    if val == 0:
        return b"\x00"
    if val <= 0xFF:
        return bytes([1, val])
    if val <= 0xFFFF:
        return bytes([2]) + struct.pack(">H", val)
    if val <= 0xFFFFFF:
        return bytes([3]) + struct.pack(">I", val)[1:]
    return bytes([4]) + struct.pack(">I", val)


def sb4(val):
    if val == 0:
        return b"\x00"
    b = bytearray(ub4(abs(val)))
    if val < 0:
        b[0] |= 0x80
    return bytes(b)


def dalc(s):
    return bytes([len(s)]) + s


def bwl(s):
    return ub4(0) if not s else ub4(len(s)) + dalc(s)


def oac(data_type, max_length, charset=0, csform=0, max_size=0,
        precision=0, scale=0, fv=0, flag=0, max_elements=0):
    return (bytes([data_type, flag, precision])
            + (bytes([scale & 0xFF]) if fv >= 8 else sb4(scale))
            + ub4(max_length) + ub4(max_elements) + ub4(0) + bwl(b"") + ub4(0)
            + ub4(charset) + bytes([csform]) + ub4(max_size)
            + (ub4(0) if fv >= 8 else b""))


def dcb_column(data_type, max_length, name, charset=0, csform=0,
               max_size=0, precision=0, scale=0, fv=0):
    return (oac(data_type, max_length, charset, csform, max_size, precision, scale, fv)
            + b"\x01" + bytes([len(name)]) + bwl(name) + bwl(b"") + bwl(b"")
            + ub4(0) + (ub4(0) if fv == 0 or fv >= 6 else b"")
            + (bwl(b"") + bwl(b"") if fv >= 17 else b"")
            + (ub4(0) if fv >= 20 else b"")
            + (ub4(0) + b"\x00\x00" if fv >= 24 else b""))


def describe_body(columns, fv=0):
    b = ub4(80) + ub4(len(columns))
    if columns:
        b += b"\x00"
    for col in columns:
        b += col
    b += bwl(b"") + ub4(0) * 4
    if fv == 0 or fv >= 6:
        b += bwl(b"")
    return b


def dcb(columns, fv=0):
    return bytes([TTI_DCB]) + dalc(b"\x00" * 16) + describe_body(columns, fv)


def dty(field_version):
    caps = bytearray(38)
    caps[7] = field_version
    return (bytes([2]) + b"\x69\x03\x69\x03\x01" + bytes([len(caps)]) + caps
            + bytes(8) + bytes(980) + b"\x00")


def kv(key, value, flags=0):
    return bwl(key) + bwl(value) + ub4(flags)


def number(value):
    """An Oracle NUMBER."""
    d = Decimal(value)
    if d == 0:
        return b"\x80"
    neg = d < 0
    d = abs(d)
    t = d.as_tuple()
    digits = "".join(map(str, t.digits))
    exp10 = t.exponent
    # value = int(digits) * 10**exp10; make the exponent even in base 100
    if exp10 % 2:
        digits += "0"
        exp10 -= 1
    if len(digits) % 2:
        digits = "0" + digits
    pairs = [int(digits[i:i + 2]) for i in range(0, len(digits), 2)]
    e100 = len(pairs) - 1 + exp10 // 2
    while pairs and pairs[-1] == 0:
        pairs.pop()
    while pairs and pairs[0] == 0:
        pairs.pop(0)
        e100 -= 1
    if not neg:
        return bytes([0x80 | (e100 + 65)]) + bytes(p + 1 for p in pairs)
    return bytes([(~(e100 + 65)) & 0x7F]) + bytes(101 - p for p in pairs) + b"\x66"


def sortable(fmt, v):
    raw = int.from_bytes(struct.pack(">" + fmt, v), "big")
    bits = 32 if fmt == "f" else 64
    raw = raw | (1 << (bits - 1)) if v >= 0 else ~raw & ((1 << bits) - 1)
    return raw.to_bytes(bits // 8, "big")


def chunked(data):
    out = b"\xfe"
    for i in range(0, len(data), 64):
        out += bytes([len(data[i:i + 64])]) + data[i:i + 64]
    return out + b"\x00"


def csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


# ------------------------------------------------------------- the capture
class Capture:
    def __init__(self):
        self.frames = []
        self.marks = []

    def mark(self, text):
        self.marks.append((len(self.frames) + 1, text))

    def stream(self, cport, sport=1521, cip=1, sip=2):
        return Stream(self, cport, sport, cip, sip)

    def write(self, name):
        with open(name, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


class Stream:
    def __init__(self, cap, cport, sport, cip, sip):
        self.cap = cap
        self.cip = bytes([192, 0, 2, cip])
        self.sip = bytes([192, 0, 2, sip])
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000

    def _tcp(self, src, dst, sp, dp, seq, ack, payload):
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", csum16(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload),
                         len(self.cap.frames) + 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", csum16(ip)) + ip[12:]
        if src == self.sip:
            eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
        else:
            eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
        return eth + ip + tcp + payload

    def client(self, payload):
        self.cap.frames.append(self._tcp(self.cip, self.sip, self.cport, self.sport,
                                         self.cseq, self.sseq, payload))
        self.cseq += len(payload)

    def server(self, payload):
        self.cap.frames.append(self._tcp(self.sip, self.cip, self.sport, self.cport,
                                         self.sseq, self.cseq, payload))
        self.sseq += len(payload)

    def send(self, to_server, payload):
        (self.client if to_server else self.server)(payload)


def hdr(ptype, body, long_form=False, length=None, chk=0):
    """A TNS packet: 2 byte length and checksum, or the 4 byte length of
    Oracle 12c; type, reserved byte, header checksum."""
    if long_form:
        n = 8 + len(body) if length is None else length
        return struct.pack("!IBBH", n, ptype, 0, 0) + body
    n = 8 + len(body) if length is None else length
    return struct.pack("!HHBBH", n, chk, ptype, 0, 0) + body


def tns_data(body, flags=0, long_form=False):
    return hdr(6, struct.pack("!H", flags) + body, long_form)


# -------------------------------------------------------------------- OSON
def fnv1a(name):
    h = 0x811C9DC5
    for c in name:
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    return h


class Node:
    """A container: kind 'arr' or 'obj', tag bits, children
    (for an object: (field id, child) pairs)."""

    def __init__(self, kind, children, tag=None):
        self.kind = kind
        self.children = children
        self.tag = tag if tag is not None else (0xC0 if kind == "arr" else 0x80)


def enc_node(node, pos, relative, id_len):
    if isinstance(node, (bytes, bytearray)):
        return bytes(node)
    n = len(node.children)
    tag = node.tag
    cw = {0x00: 1, 0x08: 2, 0x10: 4}[tag & 0x18]
    ow = 4 if tag & 0x20 else 2
    head = bytes([tag]) + n.to_bytes(cw, "big")
    ids = b""
    if node.kind == "obj":
        ids = b"".join(i.to_bytes(id_len, "big") for i, _ in node.children)
    hlen = len(head) + len(ids) + ow * n
    body, offs = b"", []
    kids = [c for _, c in node.children] if node.kind == "obj" else node.children
    for ch in kids:
        at = pos + hlen + len(body)
        offs.append(at - pos if relative else at)
        body += enc_node(ch, at, relative, id_len)
    return head + ids + b"".join(o.to_bytes(ow, "big") for o in offs) + body


def oson(root, names=(), flags=0x0100, version=1, long_names=()):
    """An OSON image. flags: 0x01 relative offsets, 0x08 4 byte ids and
    name count, 0x0400 2 byte ids and count, 0x0800 4 byte short name
    offsets and segment size, 0x1000 4 byte tree size."""
    relative = bool(flags & 1)
    id_len = 4 if flags & 0x08 else 2 if flags & 0x0400 else 1
    out = b"\xff\x4a\x5a" + bytes([version]) + struct.pack(">H", flags)
    out += len(names).to_bytes(id_len, "big")
    seg, offs = b"", b""
    ow = 4 if flags & 0x0800 else 2
    for nme in names:
        offs += len(seg).to_bytes(ow, "big")
        seg += bytes([len(nme)]) + nme
    out += len(seg).to_bytes(ow, "big")
    lseg, loffs = b"", b""
    if version == 3:
        for nme in long_names:
            loffs += struct.pack(">H", len(lseg))
            lseg += struct.pack(">H", len(nme)) + nme
        out += struct.pack(">HII", 0x0100, len(long_names), len(lseg))
    tree = enc_node(root, 0, relative, id_len)
    out += len(tree).to_bytes(4 if flags & 0x1000 else 2, "big") + b"\x00\x00"
    out += bytes(fnv1a(n) & 0xFF for n in names) + offs + seg
    if version == 3:
        out += b"".join(struct.pack(">H", fnv1a(n) & 0xFFFF) for n in long_names) + loffs + lseg
    return out + tree


def oson_scalar(tagged, flags=0x0010):
    w = 4 if flags & 0x1000 else 2
    return (b"\xff\x4a\x5a\x01" + struct.pack(">H", flags) + len(tagged).to_bytes(w, "big")
            + tagged)


DATE7 = bytes([120, 120, 1, 15, 11, 31, 1])                       # 2020-01-15 10:30:00
TS11 = DATE7 + struct.pack(">I", 123456789)
TSTZ = TS11[:7] + struct.pack(">I", 5) + bytes([20 + 2, 60 + 30])
IYM = struct.pack(">I", 0x80000000 + 3) + bytes([60 + 4])
IDS = struct.pack(">I", 0x80000000 + 2) + bytes([60 + 3, 60 + 4, 60 + 5]) + struct.pack(">I", 0x80000000 + 7)
VEC = bytes([0xDB, 0, 0x00, 0x12, 2]) + struct.pack(">I", 2) + bytes(8) + sortable("f", 1.5) + sortable("f", -2.5)
SCALARS = [
    [b"\x30", b"\x31", b"\x32"],
    [b"\x33\x03abc", b"\x37\x00\x02hi", b"\x38\x00\x00\x00\x01x", b"\x05quo\"\\\x01"],
    [b"\x34\x03" + number("12.5"), b"\x40", b"\x42" + number("100")[:2],
     b"\x21" + number("7"), b"\x63" + number("-3.5"), b"\x52" + number("5")],
    [b"\x3c" + DATE7, b"\x7d" + DATE7, b"\x39" + TS11, b"\x7c" + TSTZ],
    [b"\x7f" + sortable("f", 0.5), b"\x36" + sortable("d", -1.25),
     b"\x3d" + IYM, b"\x3e" + IDS],
    [b"\x7e\x02\xab\xcd", b"\x3a\x00\x01\xff", b"\x3b\x00\x00\x00\x00"],
    [b"\x7b\x01" + struct.pack(">I", len(VEC)) + VEC],
]


def oson_images():
    imgs = [oson(Node("arr", items)) for items in SCALARS]
    imgs.append(oson_scalar(b"\x33\x05hello"))
    imgs.append(oson_scalar(b"\x34\x02" + number("42"), 0x1010))
    imgs.append(oson(Node("arr", [b"\x31", b"\x32"], 0xC8)))
    imgs.append(oson(Node("arr", [b"\x30"], 0xD0)))
    imgs.append(oson(Node("arr", [b"\x31", b"\x30"], 0xE0)))
    imgs.append(oson(Node("arr", [b"\x31", Node("arr", [b"\x32"])]), flags=0x0101))
    names = [b"id", b"name"]
    obj = Node("obj", [(1, b"\x34\x02" + number("7")), (2, b"\x33\x03bob")])
    imgs.append(oson(obj, names, flags=0x0400))
    imgs.append(oson(obj, names, flags=0x0008 | 0x0800 | 0x1000))
    imgs.append(oson(Node("obj", [(1, b"\x31")], 0x88), names, flags=0x0400))
    imgs.append(oson(Node("obj", [(1, b"\x31")], 0x90), names, flags=0x0400))
    imgs.append(oson(Node("obj", [(1, b"\x34\x02" + number("1"))]), flags=0x0100, version=3,
                     long_names=[b"L" * 300]))
    imgs.append(oson_scalar(b"\x35\x00"))
    imgs.append(oson(Node("arr", [b"\x33\x08abcdefgh"] * 300, 0xC8)))
    imgs.append(oson(Node("arr", [b"\x7b\x02\x00\x00\x00\x00"])))
    return imgs


JLOC = bytes([0x00, 0x26]) + bytes(range(38))


def prefetched(img):
    image = dalc(img) if len(img) <= 252 else chunked(img)
    return ub4(len(JLOC)) + ub4(len(img)) + ub4(32600) + image + dalc(JLOC)


# ------------------------------------------------------------------ groups
def connect_pkt(cd, version=318):
    body = struct.pack("!HHHHHHHH", version, 300, 0x0801, 8192, 65535, 0x7f08, 0, 1)
    body += struct.pack("!HHI", len(cd), 58, 0x00100000) + bytes([0x41, 0x41])
    body += struct.pack("!IIQ", 0, 0, 0x1122334455667788) + bytes(8) + cd
    return hdr(1, body)


def accept_pkt(cd, version=313):
    body = struct.pack("!HHHHHHH", version, 0x0801, 8192, 65535, 1, len(cd), 24)
    body += bytes([0x41, 0x41]) + cd
    return hdr(2, body)


def dd_pkt(rows, data_len, long_form=False, length=None):
    body = struct.pack("!II", 3, data_len) + struct.pack("!I", len(rows))
    body += b"".join(struct.pack("!H", r) for r in rows)
    return hdr(15, body, long_form, length)


def group_packets(cap):
    """Every TNS packet type, both length forms, Data Descriptors."""
    cap.mark("packet types")
    s = cap.stream(40001)
    s.client(connect_pkt(b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)))"))
    s.server(accept_pkt(b"(ACCEPT)"))
    s.server(hdr(4, struct.pack("!BBH", 2, 3, 25) + b"(DESCRIPTION=(ERR=12514))"))
    s.server(hdr(5, struct.pack("!H", 22) + b"(ADDRESS=(HOST=other))"))
    s.client(hdr(9, bytes([1, 2]) + b"aborted by client"))
    s.client(hdr(12, bytes([1, 0, 2])))                  # marker
    s.client(hdr(13, bytes([1, 0, 3])))                  # attention
    s.client(hdr(14, struct.pack("!H", 5) + b"\x01\x02\x03"))   # control
    s.client(hdr(3, b""))                                 # acknowledge
    s.client(hdr(7, b""))                                 # null
    s.client(hdr(11, b""))                                # resend
    s.client(hdr(16, b"\x01\x02"))                        # type 16: unknown
    s.client(hdr(19, b""))
    # the 4 byte length form of 12c: a data packet and a marker
    s.client(tns_data(b"\x01\x00\x00\x00", long_form=True))
    s.server(hdr(12, bytes([1, 0, 1]), long_form=True))
    # Data Descriptors: rows add up to the data length (2 byte length form)
    payload = bytes(range(40))
    s.server(dd_pkt([30, 10], 40) + payload)
    # the 4 byte form
    s.server(dd_pkt([40], 40, long_form=True) + payload)
    # rows that do not add up: expert info (warning)
    s.server(dd_pkt([7, 8], 40) + payload)
    # header split after 10 bytes: the length is read once 12 bytes are in
    pkt = dd_pkt([40], 40) + payload
    s.server(pkt[:10])
    s.server(pkt[10:])
    s.server(dd_pkt([40], 40, long_form=True)[:11])
    s.server((dd_pkt([40], 40, long_form=True) + payload)[11:])


def thin_all8_vector(img, dtype=127):
    body = bytes([3, 94, 1, 1, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1])
    body += bytes(5) + bytes([0, 0]) + bytes([0]) + bytes(3) + bytes([0, 0, 0, 0])
    body += bytes([dtype, 0, 0, 0, 1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0])
    body += bytes([TTI_RXD, 1, 5, 1, 0xaa]) + dalc(img)
    return body


def group_reproducers(cap):
    cap.mark("reproducers")
    s = cap.stream(40002)
    cap.mark("vector bind, 9 byte image with norm flag (OOB read, fixed)")
    s.client(tns_data(thin_all8_vector(bytes([0xdb, 0, 0, 2, 3]) + struct.pack("!I", 16))))
    cap.mark("JSON bind, OSON string ff fe (invalid UTF-8 label, fixed)")
    img = b"\xff\x4a\x5a\x01" + struct.pack(">H", 0x0010) + struct.pack(">H", 3) + bytes([0x02, 0xff, 0xfe])
    s.client(tns_data(thin_all8_vector(img, 119)))


def rxd_reproducer(cap, rows_under, rows_over=None):
    """1500 columns without data length, then rows of one byte each (the first byte is the TTI_RXD token): each
    row costs 1500 empty items; TNS_MAX_EMPTY_COLUMNS is 100000."""
    ncols = 1500
    cap.mark("1500 columns without data length, then %d rows%s" % (
        rows_under - 1, "" if rows_over is None else " and %d rows (limit exceeded)" % (rows_over - 1)))
    s = cap.stream(40003 if rows_over is None else 40004)
    cols = [dcb_column(TYPE_VARCHAR, 0, b"C%d" % i) for i in range(ncols)]
    s.server(tns_data(dcb(cols)))
    s.server(tns_data(bytes([TTI_RXD] * rows_under)))
    if rows_over:
        s.server(tns_data(bytes([TTI_RXD] * rows_over)))


def group_json(cap):
    cap.mark("JSON columns: OSON images")
    s = cap.stream(40005)
    s.server(tns_data(dcb([dcb_column(TYPE_JSON, 8200, b"J")])))
    imgs = oson_images()
    s.server(tns_data(b"".join(bytes([TTI_RXD]) + prefetched(i) for i in imgs[:10])))
    s.server(tns_data(b"".join(bytes([TTI_RXD]) + prefetched(i) for i in imgs[10:])))


def group_values(cap):
    cap.mark("NUMBER, VECTOR values")
    s = cap.stream(40006)
    s.server(tns_data(dcb([dcb_column(TYPE_NUMBER, 22, b"N"), dcb_column(TYPE_VECTOR, 8200, b"V")])))
    rows = b""
    vec_img = lambda n, fmt=2, fl=0x12: (bytes([0xDB, 0, 0, fl, fmt]) + struct.pack(">I", n)
                                          + bytes(8) + b"".join(sortable("f", 0.5 * i - 3) for i in range(n)))
    for i, n in enumerate(["12.5", "0.5", "-1.5", "0.001", "-0.05", "100", "0", "123456.789", "-12.25"]):
        rows += bytes([TTI_RXD]) + dalc(number(n)) + prefetched(vec_img(20 if i == 0 else 2))
    s.server(tns_data(rows))


def ub8(v):
    n = (v.bit_length() + 7) // 8
    return bytes([n]) + v.to_bytes(n, "big")


def spb(opcode, body=b""):
    return bytes([TTI_SPB, opcode]) + body


def group_spb(cap):
    cap.mark("server piggybacks (every opcode)")
    s = cap.stream(40007)
    k = lambda text, binary, kw: bwl(text) + bwl(binary) + ub4(kw)
    msgs = [
        spb(1),                                            # query cache invalidation
        spb(3),                                            # trace event
        spb(7, ub4(16) + dalc(bytes(range(1, 17)))),       # logical transaction id
        spb(2, ub4(5) + dalc(b"12345")),                   # OS PID, shared server
        spb(5, ub4(1) + b"\x10" + ub4(2) + b"\x16" + k(b"NLS", b"x", 1) + k(b"", b"\x01", 2) + ub4(7)),
        spb(9, ub4(1) + b"\x08"),                          # extended sync
        spb(8, ub4(1) + b"\x08" + ub4(3) + ub4(942) + b"\x01" + ub4(4) + dalc(b"ctx!")),
        spb(4, ub4(1) + b"\x08" + ub4(1) + b"\x08" + ub4(3) + dalc(b"key") + ub4(2) + dalc(b"vl")
            + ub4(1) + ub4(5) + ub4(9) + ub4(777)),    # session return, keys
        spb(10, ub4(1) + b"\x08" + ub8(1) + ub8(0x1122334455667788) + ub8(0xabcdef)),
        spb(99),                                           # unknown opcode
    ]
    for m in msgs:
        s.server(tns_data(m))
    # two messages in one packet: the walker steps from one to the next
    s.server(tns_data(msgs[0] + msgs[1] + msgs[2]))


def opi_frames(cap):
    cap.mark("OPI parameters: VERSION2, OSESSKEY and OAUTH replies")
    s = cap.stream(40008)
    banner = b"Oracle Database 19c Enterprise Edition"
    # VERSION2: Orac at offset+2 (one unused byte, big endian version) and
    # at offset+3 (two unused bytes, little endian)
    s.server(tns_data(bytes([8, 0, len(banner)]) + banner + b"\x00" + struct.pack(">I", 0x13000000) + bytes(8)))
    s.server(tns_data(bytes([8, 0, 0, len(banner)]) + banner + struct.pack("<I", 0x13000000) + bytes(8)))
    # OSESSKEY v1: 4 bytes, then "....AUTH" with the 0x0c name length
    name = b"AUTH_SESSKEY"
    val = b"A" * 32
    s.server(tns_data(bytes([8, 1, 0, 0, 0, 0, 0, len(name)]) + name + bytes(4) + dalc(val) + bytes(24)))
    # OAUTH v1: name length 0x13
    name = b"AUTH_" + b"Y" * 14
    s.server(tns_data(bytes([8, 1, 0, 0, 0, 0, 0, len(name)]) + name + b"\x01\x00\x00\x00" + dalc(b"B" * 8) + bytes(24)))


def all8(seq, sql, options, binds=(), rows=(), cursor=0, al8=None, defines=(), fv=0):
    al8 = al8 if al8 is not None else [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    b = bytes([TTI_FUN, TTI_ALL8, seq])
    if fv >= 18:
        b += ub4(0)
    b += ub4(options) + ub4(cursor)
    b += bytes([1 if sql else 0]) + ub4(len(sql))
    b += bytes([1]) + ub4(len(al8))
    b += bytes([0, 0]) + ub4(0) + ub4(0) + ub4(0)
    b += bytes([1 if binds else 0]) + ub4(len(binds))
    b += bytes([0, 0, 0, 0, 0])
    b += bytes([1 if defines else 0]) + ub4(len(defines))
    b += bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])
    if fv >= 7:
        b += bytes([0, 0, 0])
    if fv >= 8:
        b += bytes([0, 0, 0, 0, 0])
    if fv >= 9:
        b += bytes([0, 0])
    b += (dalc(sql) if sql else b"") if fv >= 7 else sql
    for elem in al8:
        b += ub4(elem)
    for o in list(binds) + list(defines):
        b += o
    for r in rows:
        b += bytes([TTI_RXD]) + r
    return b


def oer(err_code=0, cursor=0, rowcount=0, call_status=0, msg=b"", fv=0):
    b = bytes([TTI_OER])
    b += ub4(call_status) + ub4(0) + ub4(rowcount) + ub4(err_code)
    b += ub4(0) + ub4(0) + ub4(cursor) + ub4(0)
    b += bytes(6)
    b += ub4(0) + ub4(0) + b"\x00" + ub4(0) + ub4(0)
    b += ub4(0) + bytes(2) + ub4(0) + ub4(0)
    b += bwl(b"")
    b += ub4(0) + ub4(0) + ub4(0)
    if fv >= 7:
        b += ub4(err_code) + ub4(rowcount)
    if fv >= 14:
        b += ub4(0) + ub4(0)
    if err_code:
        b += dalc(msg)
    return b


def rpa(words=(0x01692160, 0, 6, 1, 0, 0), al8txl=b"", kvs=(), registration=b"", rowcounts=None):
    b = bytes([TTI_RPA]) + ub4(len(words))
    for w in words:
        b += ub4(w)
    b += ub4(len(al8txl)) + al8txl
    b += ub4(len(kvs))
    for text, binary, keyword in kvs:
        b += ub4(len(text)) + (dalc(text) if text else b"") + ub4(len(binary)) \
            + (dalc(binary) if binary else b"") + ub4(keyword)
    b += ub4(len(registration)) + registration
    if rowcounts is not None:
        b += ub4(len(rowcounts))
        for n in rowcounts:
            b += ub4(n)
    return b


def group_rpa(cap):
    cap.mark("return parameters: al8txl, registration, binary key/value")
    s = cap.stream(40009)
    al8i4 = [1, 4, 0, 0, 0, 0, 0, 0, 0, 0x4000, 0, 0, 0]
    s.client(tns_data(all8(1, b"INSERT INTO T (ID) VALUES (:1)", 0x8029, binds=[oac(TYPE_NUMBER, 22)],
                           rows=[dalc(number(str(n))) for n in range(1, 4)], al8=al8i4)))
    s.server(tns_data(rpa(al8txl=bytes(range(8)), kvs=[(b"PYO", b"\x01\x02", 168), (b"", b"", 5)],
                          registration=b"reg-token", rowcounts=[1, 1, 1]) + oer(rowcount=3, cursor=3)))
    sql = (b"INSERT INTO T (ID, S) VALUES (1, 'it''s a -- string /* not a comment */') /* block */ "
           b"-- line comment\nRETURNING ID, S INTO :1, :2 /* open comment")
    s.client(tns_data(all8(4, sql, 0x8029, binds=[oac(TYPE_NUMBER, 22), oac(TYPE_VARCHAR, 100)],
                           rows=[dalc(number("1")) + dalc(b"x")], al8=al8i4)))
    s.server(tns_data(bytes([TTI_RPA]) + ub4(0) + ub4(0) + ub4(0) + ub4(0) + ub4(0) + oer(rowcount=1, cursor=3)))


def group_tpc_sec(cap):
    cap.mark("TPC switch with names, end-user security context piggyback")
    s = cap.stream(40010)
    gtrid, bqual = b"gtrid-1", b"bq-1"
    xid = (gtrid + bqual).ljust(128, b"\x00")
    switch = (bytes([TTI_FUN, 103, 1]) + ub4(0x01) + b"\x00" + ub4(0)
              + ub4(4660) + ub4(len(gtrid)) + ub4(len(bqual)) + b"\x01" + ub4(len(xid))
              + ub4(0) + ub4(60) + b"\x01\x01\x01" + b"\x01" + ub4(5) + b"\x01" + ub4(6)
              + xid + ub4(7) + b"INTRN" + b"EXTERN")
    s.client(tns_data(switch))
    s.server(tns_data(bytes([TTI_RPA]) + ub4(0) + ub4(0) + oer()))
    pgy = lambda func, seq: bytes([17, func, seq])
    sec = (pgy(205, 2) + ub4(1) + b"\x01" + ub4(2)
           + ub4(0) + ub4(3) + dalc(b"key") + ub4(4) + dalc(b"text") + ub4(5) + dalc(b"value")
           + ub4(0) + ub4(0) + ub4(0) + ub4(0))
    s.client(tns_data(sec + bytes([TTI_FUN, 14, 3])))


def group_aq(cap):
    cap.mark("Advanced Queuing, field version 24: recipients, exception queue, correlation, message id")
    FV = 24
    s = cap.stream(40011)
    toid = bytes(range(0x10, 0x20))
    msgid = bytes(range(0x20, 0x30))
    payload = b"hello queue"
    two = lambda v: ub4(0) if not v else ub4(len(v)) + dalc(v)
    k = lambda text, binary, kw: two(text) + two(binary) + ub4(kw)

    def props(corr=b"", exc=b"", enq=b""):
        b = ub4(0) + ub4(0) + sb4(-1) + two(corr) + ub4(0) + two(exc) + ub4(0)
        b += (ub4(len(enq)) + dalc(enq)) if enq else ub4(0)
        b += two(b"") + ub4(4) + b"\x0e"
        b += k(b"", b"", 64) + k(b"", b"", 65) + k(b"", b"\x00", 66) + k(b"", b"", 69)
        return b + ub4(0) * 4 + ub4(0)           # delivery flags, shard (21.1)

    s.client(tns_data(dty(FV)))
    enq = (bytes([TTI_FUN, 121, 1]) + ub4(0) + b"\x01" + ub4(3) + props(b"corr-1", b"EXCQ")
           + b"\x01" + ub4(2) + ub4(2) + b"\x00" + ub4(0) + ub4(0)
           + b"\x01" + ub4(16) + ub4(1) + b"\x00" + b"\x01" + ub4(len(payload))
           + b"\x01" + ub4(16) + ub4(0) + (b"\x00" + ub4(0)) * 4 + b"\x00"
           + (b"\x00" + ub4(0)) * 3 + b"\x00\x00" + b"\x00"
           + dalc(b"MYQ") + k(b"SUB1", b"", 1) + k(b"SUB2", b"", 2) + toid + payload)
    # the call token (ub8) of field version 18 and later follows the call id
    s.client(tns_data(enq))
    s.server(tns_data(bytes([TTI_RPA]) + msgid + ub4(0) + oer(fv=FV)))
    deq = (bytes([TTI_FUN, 122, 2]) + ub4(0) + b"\x01" + ub4(3) + b"\x01\x01\x01\x01"
           + b"\x01" + ub4(4) + ub4(3) + ub4(1) + ub4(1) + sb4(-1)
           + b"\x01" + ub4(16) + b"\x01" + ub4(6)
           + b"\x01" + ub4(16) + ub4(1) + b"\x01\x01" + ub4(16) + ub4(0)
           + b"\x01" + ub4(14) + b"\x00" + ub4(0) + b"\x01" + ub4(0)
           + dalc(b"MYQ") + dalc(b"SUB1") + msgid + dalc(b"corr-2") + toid + dalc(b"priority = 1"))
    s.client(tns_data(deq))
    s.server(tns_data(bytes([TTI_RPA]) + ub4(0) + oer(fv=FV)))


def group_rows(cap):
    cap.mark("row headers with a bit vector, LONG and UROWID values")
    s = cap.stream(40012)
    cols = [dcb_column(TYPE_VARCHAR, 10, b"A"), dcb_column(TYPE_VARCHAR, 10, b"B"),
            dcb_column(TYPE_VARCHAR, 10, b"C")]
    s.server(tns_data(dcb(cols)))
    rxh = bytes([TTI_RXH, 0]) + ub4(1) + ub4(0) + ub4(1) + ub4(0) + ub4(1) + b"\x01\x05" + bwl(b"")
    s.server(tns_data(rxh + bytes([TTI_RXD]) + dalc(b"a") + dalc(b"c")))
    # a bit vector message (21): number of columns sent, then one bit per column
    s.server(tns_data(bytes([21]) + ub4(2) + b"\x05" + bytes([TTI_RXD]) + dalc(b"x") + dalc(b"z")))
    s2 = cap.stream(40013)
    s2.server(tns_data(dcb([dcb_column(8, 100, b"L"), dcb_column(208, 100, b"U"), dcb_column(8, 100, b"L2")])))
    row1 = bytes([TTI_RXD]) + b"\x00" + ub4(0) + ub4(0) + ub4(0) + b"\xfe\x03abc\x02de\x00" + ub4(5) + ub4(0)
    row1 += b"\x03xyz" + ub4(3) + ub4(0)
    s2.server(tns_data(row1))
    row2 = bytes([TTI_RXD]) + b"\x02hi" + ub4(2) + ub4(0) + ub4(5) + b"\x01" + bytes(range(1, 6)) + b"\x00" + ub4(0) + ub4(0)
    s2.server(tns_data(row2))


def group_malformed_values(cap):
    cap.mark("malformed values and structures")
    s = cap.stream(41002)
    # a describe whose column count is larger than the data left
    s.server(tns_data(bytes([TTI_DCB]) + dalc(b"\x00" * 16) + ub4(80) + ub4(5000)))
    # a describe ending in a width byte with nothing behind it
    s.server(tns_data(bytes([TTI_DCB]) + dalc(b"\x00" * 16) + b"\x05"))
    # a chunked LONG whose chunk is longer than the packet
    s.server(tns_data(dcb([dcb_column(8, 100, b"L")])))
    s.server(tns_data(bytes([TTI_RXD]) + b"\xfe\x50abc"))
    # NUMBER, DATE and VECTOR values that cannot be rendered
    s2 = cap.stream(41003)
    s2.server(tns_data(dcb([dcb_column(TYPE_NUMBER, 22, b"N"), dcb_column(TYPE_DATE, 7, b"D"),
                            dcb_column(TYPE_VECTOR, 8200, b"V")])))
    vec = lambda fl, fmt, n, body=b"": bytes([0xDB, 0, 0, fl, fmt]) + struct.pack(">I", n) + body
    bad_vecs = [vec(0, 9, 1, b"\x00"), b"\xdb\x00\x00", vec(0x12, 2, 1), vec(0x20, 2, 100, bytes(8)),
                vec(0x20, 2, 4, struct.pack(">H", 50) + bytes(10)), vec(0, 2, 1000, bytes(8))]
    nums = [b"\xc1\xff", b"\x81", b"\x3e\x01"]
    dates = [bytes([120, 120, 13, 1, 1, 1, 1]), bytes([120, 120, 1, 1]), bytes([120, 120, 2, 30, 99, 1, 1])]
    for i in range(3):
        row = bytes([TTI_RXD]) + dalc(nums[i]) + dalc(dates[i]) + prefetched(bad_vecs[i])
        s2.server(tns_data(row))
    s2.server(tns_data(b"".join(bytes([TTI_RXD]) + dalc(b"\x80") + dalc(dates[0]) + prefetched(v)
                                 for v in bad_vecs[3:])))
    # malformed OSON documents
    s3 = cap.stream(41004)
    s3.server(tns_data(dcb([dcb_column(TYPE_JSON, 8200, b"J")])))
    good = oson(Node("obj", [(1, b"\x31")]), [b"a"])
    arr = lambda *c, **kw: oson(Node("arr", list(c), kw.get("tag", 0xC0)), flags=kw.get("flags", 0x0100))
    imgs = [
        b"\xff\x4a\x5a\x02\x01\x00\x00\x00",                  # version 2
        good[:7],                                                  # cut in the header
        good[:-1],                                                 # cut in the tree
        oson(Node("obj", [(0, b"\x31")]), [b"a"]),                  # field id 0
        oson(Node("obj", [(9, b"\x31")]), [b"a"]),                  # field id past the names
        oson(Node("arr", [b"\x31"]), flags=0x0100)[:-3] + b"\x00\x7f\x31",   # offset out of the tree
        oson(b"\x98\x00\x00\x00", [b"a"]),            # donor shared ids, donor is a shared one
        oson(Node("arr", [b"\x7b\x01\x00\x00\x00\x20" + bytes(4)])),   # vector image longer than the data
        oson(Node("arr", [b"\x7b\x01" + struct.pack(">I", 9) + vec(0, 9, 1, b"")])),  # unrenderable vector
        oson(Node("arr", [b"\x3c" + bytes([120, 120, 13, 1, 1, 1, 1])])),   # bad date
        oson(Node("arr", [b"\x33\xff"])),                           # string longer than the image
        oson_scalar(b"\x33\x09ab"),                                 # scalar document cut short
        oson_scalar(b"\x30")[:-1],                                   # scalar document with no node
        oson(good and Node("arr", [b"\x31"]), flags=0x0000)[:8],     # header cut after the flags
    ]
    # nesting past the limit: 40 levels of one-element arrays
    deep = b"\x31"
    node = Node("arr", [b"\x31"])
    for _ in range(40):
        node = Node("arr", [node])
    imgs.append(oson(node))
    # a long array of strings renders only up to the text limit
    for i in range(0, len(imgs), 8):
        s3.server(tns_data(b"".join(bytes([TTI_RXD]) + prefetched(x) for x in imgs[i:i + 8])))
    # LOB operation piggyback whose locator total is larger than the packet
    s4 = cap.stream(41005)
    pgy = lambda func, seq: bytes([17, func, seq])
    bad = pgy(96, 1) + b"\x01" + ub4(5000) + b"\x00" + ub4(0) + ub4(0) + ub4(0) + b"\x00\x00\x00"
    bad += ub4(0x80111) + b"\x00" + ub4(0) + ub4(0) + ub4(0) + b"\x00" + (b"\x00" + ub4(0)) * 3
    s4.client(tns_data(bad + bytes([TTI_FUN, 14, 2])))


def build_main(cap):
    group_packets(cap)
    group_reproducers(cap)
    rxd_reproducer(cap, 67)
    group_json(cap)
    group_values(cap)
    group_spb(cap)
    opi_frames(cap)
    group_rpa(cap)
    group_tpc_sec(cap)
    group_aq(cap)
    group_rows(cap)


def build_malformed(cap):
    cap.mark("DD header length 0 (assert, fixed)")
    s = cap.stream(41001)
    pdu = struct.pack("!HHBBH", 0, 0, 15, 0, 0) + struct.pack("!III", 3, 32, 0)
    s.client(pdu + b"\0" * (32 - 12))
    rxd_reproducer(cap, 67, 69)
    group_malformed_values(cap)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else "."
    for name, fn in (("tns-coverage.pcap", build_main), ("tns-coverage-malformed.pcap", build_malformed)):
        cap = Capture()
        fn(cap)
        cap.write(os.path.join(out, name))
        print("%s: %d frames" % (name, len(cap.frames)))
        if "-v" in sys.argv:
            for n, t in cap.marks:
                print("  frame %d: %s" % (n, t))


if __name__ == "__main__":
    main()

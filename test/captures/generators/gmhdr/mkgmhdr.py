#!/usr/bin/env python3
# Generates test/captures/gmhdr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates gmhdr-coverage.pcap and gmhdr-coverage-malformed.pcap
# Gigamon header (ethertype 0x22e5), header-as-trailer and timestamp trailer
# Usage: mkgmhdr.py <outdir>  (synthetic; nothing comes from a real network)
import struct
import sys
import os

# ---- pcap / frame helpers ----------------------------------------------
def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

CLI = [192, 0, 2, 1]
SRV = [192, 0, 2, 2]
CMAC = bytes([2, 0, 0, 0, 0, 1])
SMAC = bytes([2, 0, 0, 0, 0, 2])
_ipid = [1]

def ip4(src, dst, proto, payload):
    _ipid[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), _ipid[0] & 0xffff, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def eth(from_client, ippkt):
    if from_client:
        return SMAC + CMAC + b'\x08\x00' + ippkt
    return CMAC + SMAC + b'\x08\x00' + ippkt

def udp_frame(from_client, sport, dport, payload):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(from_client, ip4(src, dst, 17, u))

class Tcp:
    """One TCP connection; every send() is one PSH|ACK segment."""
    def __init__(self, frames, sport, dport, hs=True):
        self.f = frames; self.sport = sport; self.dport = dport
        self.cseq = 1000; self.sseq = 5000; self.acks = True
        if hs:
            self.seg(True, 0x02, b'')
            self.cseq += 1
            self.seg(False, 0x12, b'')
            self.sseq += 1
            self.seg(True, 0x10, b'')
    def seg(self, c, flags, data, seq=None):
        src, dst = (CLI, SRV) if c else (SRV, CLI)
        sp, dp = (self.sport, self.dport) if c else (self.dport, self.sport)
        s = (self.cseq if c else self.sseq) if seq is None else seq
        a = self.sseq if c else self.cseq
        if flags == 0x02:
            a = 0
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b''
        h = struct.pack('!HHIIBBHHH', sp, dp, s, a, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ps = struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 6, len(h) + len(data))
        ck = csum(ps + h + data)
        h = h[:16] + struct.pack('!H', ck) + h[18:]
        self.f.append(eth(c, ip4(src, dst, 6, h + data)))
    def send(self, c, data):
        self.seg(c, 0x18, data)
        if c: self.cseq += len(data)
        else: self.sseq += len(data)
        if self.acks: self.seg(not c, 0x10, b'')
    def fin(self):
        self.seg(True, 0x11, b''); self.cseq += 1
        self.seg(False, 0x11, b''); self.sseq += 1
        self.seg(True, 0x10, b'')

# ---- XDR / ONC RPC ------------------------------------------------------
def U(v): return struct.pack('!I', v & 0xffffffff)
def Q(v): return struct.pack('!Q', v & 0xffffffffffffffff)
def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)
def opaque(b): return U(len(b)) + pad4(b)
def xstr(s):
    if isinstance(s, str): s = s.encode()
    return opaque(s)
def rpc_call(xid, prog, vers, proc, body):
    return struct.pack('!IIIIII', xid, 0, 2, prog, vers, proc) + U(0) * 4 + body
def rpc_reply(xid, body):
    return struct.pack('!IIIIII', xid, 1, 0, 0, 0, 0) + body
def rm(b, last=True):
    return U((0x80000000 if last else 0) | len(b)) + b

def gfid(n): return bytes([(n * 7 + i * 13 + 1) & 0xff for i in range(16)])

# ---- gluster dicts -------------------------------------------------------
def dict_old(items, extra=0):
    """Old (v1) dict: size, count, then keylen vallen key\\0 value; padded."""
    body = U(len(items))
    for k, v in items:
        if isinstance(k, str): k = k.encode()
        if isinstance(v, str): v = v.encode()
        body += U(len(k)) + U(len(v)) + k + b'\0' + v
    return U(len(body)) + pad4(body)
EMPTY_D = U(0)
def dict4(items):
    """Version 4 dict: xdr_size, count, pairs_len, then (key, type, value)."""
    body = b''
    for k, t, v in items:
        if isinstance(k, str): k = k.encode()
        body += opaque(k + b'\0') + U(t)
        if t == 2: body += struct.pack('!q', v)
        elif t == 3: body += Q(v)
        elif t == 4: body += struct.pack('!d', v)
        elif t == 5: body += opaque(v if isinstance(v, bytes) else v.encode() + b'\0')
        elif t in (1, 6): body += opaque(v)
        elif t == 7: body += v
        elif t == 8: body += v
        else: raise ValueError(t)
    return U(len(body) + 8) + U(len(items)) + U(len(items)) + body
EMPTY_X = U(0) + U(0) + U(0)

# ---- gluster structures --------------------------------------------------
def iatt(n=0, ino=7):
    return (gfid(n) + Q(ino) + Q(2049) + U(0o100644) + U(1 + n) + U(1000) + U(100) +
            Q(0) + Q(4096 * (n + 1)) + U(4096) + Q(8 * (n + 1)) +
            U(1700000000) + U(11) + U(1700000001) + U(22) + U(1700000002) + U(33))
def iattx(n=0, ino=7):
    return (gfid(n) + Q(0x7ff) + Q(ino) + Q(2049) + Q(0) + Q(4096 * (n + 1)) + Q(8) +
            Q(0x10) + Q(0x20) + Q(1700000000) + Q(1700000001) + Q(1700000002) + Q(1700000003) +
            U(11) + U(22) + U(33) + U(44) + U(1 + n) + U(1000) + U(100) + U(4096) + U(0o100644))
def flock_old(t=1):
    return U(t) + U(0) + Q(0) + Q(100) + U(1234) + b'OWNER123'
def flock2(t=1, owner=b'ABCDE'):
    return U(t) + U(0) + Q(0) + Q(100) + U(1234) + opaque(owner)

# ---- transports ------------------------------------------------------------
class Udp:
    def __init__(self, frames, sport, dport=24007):
        self.f = frames; self.sport = sport; self.dport = dport
    def call(self, b): self.f.append(udp_frame(True, self.sport, self.dport, b))
    def reply(self, b): self.f.append(udp_frame(False, self.dport, self.sport, b))
class TcpRpc:
    def __init__(self, frames, sport, dport=24007):
        self.t = Tcp(frames, sport, dport)
    def call(self, b): self.t.send(True, rm(b))
    def reply(self, b): self.t.send(False, rm(b))

_xid = [0x1000]
def xid():
    _xid[0] += 1
    return _xid[0]
def pair(tr, prog, vers, proc, cbody, rbody, x=None):
    x = x or xid()
    tr.call(rpc_call(x, prog, vers, proc, cbody))
    tr.reply(rpc_reply(x, rbody))
    return x
def R(ret=0, err=0): return U(ret) + U(err)

# ---- token based payload encoder (gluster FOP structures) -------------------
ERRS = [0, 2, 13, 17, 28, 61, 107, 1024, 99999, 5]
FLAGS = [0, 1, 2, 3, 0x42, 0x8241, 0x2400, 0xffffffff, 0x10002, 0x1000]
MODES = [0o100644, 0o4755, 0o41777, 0, 0xffffffff, 0o2777, 0o600]
def pick(lst, v): return lst[v % len(lst)]
def dict_variants():
    return [EMPTY_D,
            dict_old([('key1', 'value')]),
            dict_old([('gfid-req', gfid(1)), ('trusted.afr.vol-client-0', b'\1\0\0\0\2\0\0\0\3\0\0\0'),
                      ('transaction_id', gfid(2)), ('originator_uuid', gfid(3)), ('path', '/a/b')]),
            dict_old([('glusterfs.xattr', 'x' * 7), ('empty', ''), ('k', 'v' * 3)])]
def dict4_variants():
    return [EMPTY_X,
            dict4([('k-int', 2, -5), ('k-uint', 3, 2 ** 40), ('k-double', 4, 1.5), ('k-str', 5, 'str'),
                   ('k-ptr', 6, b'opaque12'), ('k-gfid', 7, gfid(3)), ('k-iatt', 8, iattx(1)),
                   ('k-old-str', 1, b'old'), ('gfid-req', 6, gfid(2)),
                   ('trusted.afr.vol-client-1', 6, b'\1\0\0\0\2\0\0\0\3\0\0\0'),
                   ('transaction_id', 6, gfid(4)), ('originator_uuid', 6, gfid(5))]),
            dict4([('only', 5, 'x')]),
            dict4([('a', 3, 1), ('bb', 3, 2), ('ccc', 3, 3)])]
DV = dict_variants(); XV = dict4_variants()
_fc = [0]

def enc(toks, v, name=''):
    """toks: space separated token string. v: variant number."""
    out = b''
    k = 0
    toks = toks.split(' ') if isinstance(toks, str) else toks
    # re-join list tokens "L(Q Q U ...)" that were split on spaces
    j = []; cur = None
    for t in toks:
        if cur is not None:
            cur += ' ' + t
            if t.endswith(')'): j.append(cur); cur = None
        elif t.startswith('L(') and not t.endswith(')'):
            cur = t
        else:
            j.append(t)
    for t in j:
        k += 1
        if t == 'G': out += gfid(v * 5 + k)
        elif t == 'S':
            out += xstr('' if (name == 'LOOKUP' and v == 1 and k == 3) else pick(['/dir/file%d' % k, 'name-%d' % k, '', 'a-longer-brick-or-path-name/%d' % v], v + k))
        elif t == 'U': out += U(pick([0, 1, 4096, 0xffffffff, 7, 2], v + k))
        elif t == 'Q': out += Q(pick([0x1234, 0, 0x7fffffffffffffff, 65536, 99], v + k))
        elif t == 'F':
            out += U(pick(FLAGS, _fc[0])); _fc[0] += 1
        elif t == 'M': out += U(pick(MODES, v + k))
        elif t == 'P': out += U(pick([0x01, 0x7f, 0, 0x08, 0x30, 0x06, 0xffffffff], v))
        elif t == 'T': out += Q(4096) + Q(4096) + Q(1000000) + Q(500000) + Q(400000) + Q(65536) + Q(60000) + Q(55000) + Q(0xabc) + Q(pick([0x1, 0x3ff, 0, 0x0fff], v)) + Q(255)
        elif t == 'D': out += pick(DV, v + k)
        elif t == 'X': out += pick(XV, v + k)
        elif t == 'I': out += iatt(v + k)
        elif t == 'J': out += iattx(v + k)
        elif t == 'R':
            e = pick(ERRS, v)
            out += R(0 if e == 0 else -1, e)
        elif t == 'N': out += U(2 - v if v < 3 else 0) + U(pick([0, 2, 5], v))
        elif t == 'K': out += flock2(pick([0, 1, 2, 3], v), pick([b'ABCDE', b'', b'1234', b'x', b'0123456789abcdef'], v + k))
        elif t == 'Z': out += flock_old(pick([0, 1, 2], v))
        elif t == 'Y': out += U(pick([1, 2, 3], v)) + U(pick([0, 1, 2], v)) + bytes(range(16)) + U(v)
        elif t == 'O': out += opaque(pick([b'strongchecksum20bytes!', b'', b'abcde'], v))
        elif t.startswith('L('):
            inner = t[2:-1]
            n = 2 if v == 0 else (1 if v == 1 else 0)
            for i in range(n):
                out += U(1) + enc(inner, v + i, name)
            out += U(0)
        elif t == 'UNK':
            out += bytes(range(8 * (v + 1)))
        else:
            raise ValueError(t)
    return out


import zlib

DMAC = bytes([2, 0, 0, 0, 0, 2])
SMAC_ = bytes([2, 0, 0, 0, 0, 1])
GM = 0x22e5

def ip_udp(sport, dport, payload, src=CLI, dst=SRV):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ip4(src, dst, 17, u)
def ethertype_frame(etype, payload):
    return DMAC + SMAC_ + struct.pack('!H', etype) + payload
def tlv(t, data):
    return struct.pack('!BB', t, len(data)) + data
def gmhdr(tlvs, inner_etype, inner, extra=b''):
    """Gigamon header: length (counting itself), the TLVs, then the encapsulated ethertype"""
    body = b''.join(tlvs) + extra
    return struct.pack('!B', 1 + len(body)) + body + struct.pack('!H', inner_etype) + inner
def srcport_g(plfm, gid, bid, pid):
    v = (plfm << 19) | (gid << 15) | (bid << 10) | pid
    return tlv(2, v.to_bytes(3, 'big'))
def srcport_h(plfm, gid, bid, sid, pid):
    v = (plfm << 26) | (gid << 20) | (bid << 16) | (sid << 10) | pid
    return tlv(8, struct.pack('!I', v))
def ts(kind, secs, nsecs):
    return tlv(kind, struct.pack('!II', secs, nsecs))
def pktsize(n): return tlv(1, struct.pack('!H', n))
def fcs(v): return tlv(7, struct.pack('!I', v))

def gm_trailer_tlv(tlvs, extra4=b''):
    t = b''.join(tlvs)
    body = t + bytes([len(t)]) + struct.pack('!H', GM)
    return body + struct.pack('!H', csum(body)) + extra4
def crc32c_swap(x):
    return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24)
def gm_timestamp_trailer(orig_crc, port, secs, nsecs, good=True):
    t = struct.pack('!IHII', orig_crc, port, secs, nsecs)
    seed = crc32c_swap(~orig_crc & 0xffffffff)
    z = zlib.crc32(t, ~seed & 0xffffffff) & 0xffffffff
    new = crc32c_swap(z)
    if not good: new ^= 0x1
    return t + struct.pack('!I', new)

def udp_payload(n=22):
    return bytes((i * 7 + 3) & 0xff for i in range(n))

def bpdu():
    llc = b'\x42\x42\x03'
    cfg = struct.pack('!HBBBQIQHHHHH', 0, 0, 0, 0, 0x8000020000000001, 4, 0x8000020000000001, 0x8001, 1, 20, 2, 15)
    return llc + cfg

def build(outdir):
    f = []
    pl = udp_payload()
    ipk = lambda i=0: ip_udp(1000 + i, 2000 + i, pl)
    # ---- the Gigamon header (ethertype 0x22e5) ---------------------------------------------------
    # srcport_g with each platform id and the "g1".."g4" port names
    for i, (plfm, gid, bid, pid) in enumerate([(1, 1, 1, 25), (2, 2, 3, 26), (3, 15, 31, 27), (4, 0, 0, 28), (5, 7, 9, 24),
                                               (6, 1, 2, 29), (7, 3, 4, 1), (8, 5, 6, 1023), (9, 0, 0, 0), (10, 1, 1, 25),
                                               (11, 1, 1, 26), (12, 2, 2, 27), (13, 3, 3, 28), (14, 4, 4, 25), (15, 5, 5, 26),
                                               (16, 6, 6, 27), (17, 7, 7, 28), (31, 8, 8, 25), (0, 0, 0, 25)]):
        f.append(ethertype_frame(GM, gmhdr([srcport_g(plfm, gid, bid, pid)], 0x0800, ipk(i))))
    # srcport_h (platform / group / box / slot / port)
    for i, a in enumerate([(1, 1, 1, 1, 1), (4, 2, 3, 4, 5), (8, 9, 10, 11, 12), (13, 15, 63, 63, 1023), (16, 0, 0, 0, 0), (63, 15, 63, 63, 1023), (0, 0, 0, 0, 0)]):
        f.append(ethertype_frame(GM, gmhdr([srcport_h(*a)], 0x0800, ipk(i))))
    # packet size, each timestamp source, the original FCS
    f.append(ethertype_frame(GM, gmhdr([pktsize(64)], 0x0800, ipk())))
    f.append(ethertype_frame(GM, gmhdr([pktsize(1518), pktsize(0)], 0x0800, ipk())))
    for kind in (3, 4, 5, 6):
        f.append(ethertype_frame(GM, gmhdr([ts(kind, 1700000000 + kind, 123456789)], 0x0800, ipk(kind))))
    f.append(ethertype_frame(GM, gmhdr([ts(3, 0, 0)], 0x0800, ipk())))
    f.append(ethertype_frame(GM, gmhdr([ts(4, 0xffffffff, 999999999)], 0x0800, ipk())))
    f.append(ethertype_frame(GM, gmhdr([fcs(0xdeadbeef)], 0x0800, ipk())))
    # generic (unknown) fields: empty, short, long and with type 0 and 255
    f.append(ethertype_frame(GM, gmhdr([tlv(9, b'')], 0x0800, ipk())))
    f.append(ethertype_frame(GM, gmhdr([tlv(10, b'\x01\x02\x03'), tlv(0, b'\xaa'), tlv(255, bytes(range(40)))], 0x0800, ipk())))
    # several fields together, and the usual set of a monitoring node
    f.append(ethertype_frame(GM, gmhdr([srcport_h(1, 2, 3, 4, 5), pktsize(98), ts(6, 1700000100, 5), fcs(0x12345678), tlv(77, b'xy')], 0x0800, ipk())))
    f.append(ethertype_frame(GM, gmhdr([srcport_g(1, 1, 2, 25), pktsize(60), ts(3, 5, 6)], 0x0800, ipk())))
    # one octet of padding after the last field (the loop needs more than one octet)
    f.append(ethertype_frame(GM, gmhdr([pktsize(70)], 0x0800, ipk(), extra=b'\x00')))
    f.append(ethertype_frame(GM, gmhdr([pktsize(71)], 0x0800, ipk(), extra=b'\x00\x00\x00')))
    f.append(ethertype_frame(GM, gmhdr([], 0x0800, ipk())))
    # other encapsulated protocols: ARP, IPv6, and the 802.3 forms
    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + SMAC_ + bytes(CLI) + b'\0' * 6 + bytes(SRV)
    f.append(ethertype_frame(GM, gmhdr([srcport_g(1, 1, 1, 25)], 0x0806, arp)))
    s6, d6 = bytes(range(1, 17)), bytes(range(17, 33))
    u6 = struct.pack('!HHHH', 1000, 2000, 18, 0) + b'0123456789'
    ck6 = csum(s6 + d6 + struct.pack('!IHBB', len(u6), 0, 0, 17) + u6) or 0xffff
    u6 = u6[:6] + struct.pack('!H', ck6) + u6[8:]
    v6 = struct.pack('!IHBB', 0x60000000, len(u6), 17, 64) + s6 + d6 + u6
    f.append(ethertype_frame(GM, gmhdr([srcport_h(2, 1, 1, 1, 1)], 0x86dd, v6)))
    b = bpdu()
    f.append(ethertype_frame(GM, gmhdr([srcport_g(1, 1, 1, 26)], len(b), b)))                       # 802.3 with LLC
    f.append(ethertype_frame(GM, gmhdr([srcport_g(1, 1, 1, 26)], len(b), b + b'\0\0\0\0\0\0')))      # with padding after the length
    ipx = struct.pack('!HHBB', 0xffff, 30 + 4, 0, 4) + struct.pack('!I6sH', 0, b'\xff' * 6, 0x9999) + struct.pack('!I6sH', 0, SMAC_, 0x9999) + b'data'
    f.append(ethertype_frame(GM, gmhdr([pktsize(80)], len(ipx), ipx)))                              # 802.3 raw (IPX)
    nhdr = len(f)
    # ---- Gigamon header as a trailer -----------------------------------------------------------------
    def with_trailer(tr, i=0):
        return ethertype_frame(0x0800, ipk(i) + tr)
    for i, tl in enumerate([[srcport_g(1, 1, 1, 25)], [srcport_h(2, 3, 4, 5, 6), pktsize(64)], [ts(3, 1, 2), ts(5, 3, 4), fcs(0x55aa55aa)],
                            [tlv(9, b'abc'), srcport_g(8, 1, 2, 27)], [], [pktsize(1)]]):
        f.append(with_trailer(gm_trailer_tlv(tl), i))
    f.append(with_trailer(gm_trailer_tlv([srcport_g(1, 2, 3, 28), pktsize(99)], b'\xaa\xbb\xcc\xdd'), 7))   # four more octets (FCS) after it
    f.append(with_trailer(gm_trailer_tlv([pktsize(65)], b'\0\0\0\0'), 8))
    ntr = len(f)
    # ---- the timestamp trailer ---------------------------------------------------------------------------
    for i, (crc, port, s, n) in enumerate([(0x12345678, 1, 1700000000, 1), (0xffffffff, 0x8001, 0, 0), (0, 77, 0x7fffffff, 999999999), (0xdeadbeef, 3, 1, 500000000)]):
        f.append(with_trailer(gm_timestamp_trailer(crc, port, s, n), i + 10))
    # ... and a frame with a bad CRC: the trailer is not recognized, the octets stay "Ethernet trailer"
    f.append(with_trailer(gm_timestamp_trailer(0x1111, 1, 2, 3, good=False), 20))
    # a trailer that is too short, and one whose checksum is wrong
    f.append(with_trailer(b'\x01\x02\x03', 21))
    f.append(with_trailer(bytes([5]) + struct.pack('!H', GM) + b'\0\0', 22))
    nts = len(f)
    # the reproducers of the fix: header length 0 (the TLV loop used 65535 and read past the header) and
    # a field longer than the rest of the header
    f.append(ethertype_frame(GM, bytes([0x00]) + b'\x08\x00' + bytes(range(1, 40))))
    f.append(ethertype_frame(GM, bytes([8]) + b'\x09\xc8' + b'\0' * 5 + struct.pack('!H', 0x0800) + ipk()))
    pcap(os.path.join(outdir, 'gmhdr-coverage.pcap'), f)
    print('header: 1-%d, trailer: %d-%d, timestamp trailer: %d-%d, reproducers: %d-%d' % (nhdr, nhdr + 1, ntr, ntr + 1, nts, nts + 1, len(f)))

    # ---- malformed: wrong field lengths, bad 802.3 length, truncated ---------------------------------------------
    m = []
    for t_, n_ in ((2, 2), (2, 4), (1, 1), (1, 3), (3, 4), (4, 9), (5, 0), (6, 7), (7, 3), (7, 5), (8, 3), (8, 5)):
        m.append(ethertype_frame(GM, gmhdr([tlv(t_, bytes(n_))], 0x0800, ipk())))
    m.append(ethertype_frame(GM, gmhdr([pktsize(1)], 1400, b'\x42\x42\x03' + b'\0' * 20)))          # 802.3 length past the end
    m.append(ethertype_frame(GM, gmhdr([pktsize(1)], 100, b'\xff\xff' + b'\0' * 10)))
    m.append(ethertype_frame(GM, gmhdr([pktsize(80)], 60, b'\xff')))
    m.append(ethertype_frame(GM, bytes([200]) + b'\0' * 10))                                           # header longer than the frame
    m.append(ethertype_frame(GM, bytes([1])))                                                          # no ethertype
    m.append(ethertype_frame(GM, bytes([3, 0x01, 0x02])))                                              # field header cut
    m.append(ethertype_frame(GM, gmhdr([pktsize(1)], 0x0800, ip_udp(1, 2, b'')[:25])))                  # truncated IP
    m.append(ethertype_frame(GM, bytes([2, 3, 4])))
    m.append(ethertype_frame(GM, gmhdr([srcport_g(1, 1, 1, 25)], 0x0800, ipk())[:6]))
    m.append(with_trailer(gm_trailer_tlv([srcport_g(1, 2, 3, 28)])[:-1], 1))                            # trailer cut: not a trailer
    m.append(with_trailer(gm_trailer_tlv([tlv(2, b'\0\0')]), 2))                                       # bad field length inside a trailer
    m.append(with_trailer(gm_trailer_tlv([tlv(9, bytes(300 % 256))] + [pktsize(5)]), 3))
    t_ = gm_trailer_tlv([tlv(9, b'abcde')])
    m.append(with_trailer(t_[:0] + bytes([t_[0], 200]) + t_[2:], 4))                                   # field longer than the trailer
    pcap(os.path.join(outdir, 'gmhdr-coverage-malformed.pcap'), m)
    print('malformed frames: %d' % len(m))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build(out)

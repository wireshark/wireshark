#!/usr/bin/env python3
# Generates test/captures/reload_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RELOAD (RFC 6940) captures. Usage: mkreload.py <outdir> [-v]
# Writes reload-coverage.pcap (raw RELOAD over UDP and TCP, found by the
# heuristic dissectors, and framed on UDP 6084) and reload-coverage-malformed.pcap.
# No signature, certificate hash or key is real: the security blocks hold
# constant filler bytes, the one X.509 certificate is hand-made DER with an
# all-zero signature.
import struct
import sys
import os

CLI = bytes([192, 0, 2, 1]); SRV = bytes([192, 0, 2, 2]); SRV2 = bytes([192, 0, 2, 3])
E_C = b'\x02\x00\x00\x00\x00\x01'; E_S = b'\x02\x00\x00\x00\x00\x02'

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def ip4(proto, l4, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return (E_S + E_C if src == CLI else E_C + E_S) + b'\x08\x00' + ip + l4
def udp(payload, sport, dport, src=CLI, dst=SRV):
    return ip4(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload, src, dst)
def tcp(payload, sport, dport, seq, ack, src=CLI, dst=SRV):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    ph = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
    t = t[:16] + struct.pack('!H', csum(ph + t + payload)) + t[18:]
    return ip4(6, t + payload, src, dst)
def framed(seq, msg): return struct.pack('!BI', 128, seq) + struct.pack('!I', len(msg))[1:] + msg

def u8(v): return struct.pack('!B', v)
def u16(v): return struct.pack('!H', v)
def u32(v): return struct.pack('!I', v)
def u64(v): return struct.pack('!Q', v)
def o1(b): return u8(len(b)) + b
def o2(b): return u16(len(b)) + b
def o3(b): return struct.pack('!I', len(b))[1:] + b
def o4(b): return u32(len(b)) + b

def nid(n): return bytes([n]) * 16 if n < 256 else bytes(16)
def dest_node(n): return b'\x01' + o1(nid(n))
def dest_res(r): return b'\x02' + o1(o1(r))
def dest_comp(r): return b'\x03' + o1(o1(r))
def dest_short(v): return u16(0x8000 | v)
def ipv4(a, port): return b'\x01' + o1(bytes(a) + u16(port))
def ipv6(port): return b'\x02' + o1(bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [1]) + u16(port))

def der(tag, c):
    n = len(c)
    l = bytes([n]) if n < 128 else (b'\x81' + bytes([n]) if n < 256 else b'\x82' + u16(n))
    return bytes([tag]) + l + c
def make_cert():
    alg = der(0x30, bytes.fromhex('06092a864886f70d01010b') + b'\x05\x00')
    name = der(0x30, der(0x31, der(0x30, bytes.fromhex('0603550403') + der(0x0c, b'node'))))
    val = der(0x30, der(0x17, b'690101000000Z') + der(0x17, b'491231235959Z'))
    spki = der(0x30, der(0x30, bytes.fromhex('06092a864886f70d010101') + b'\x05\x00') + der(0x03, b'\x00' + der(0x30, der(0x02, b'\x00\xc1' + bytes(7)) + der(0x02, b'\x01\x00\x01'))))
    tbs = der(0x30, bytes.fromhex('a003020102') + der(0x02, b'\x01') + alg + name + val + name + spki)
    return der(0x30, tbs + alg + der(0x03, b'\x00' + bytes(8)))
CERT = make_cert()

def signature(identity_type=1, hashlen=4):
    if identity_type in (1, 2):
        ident = u8(2) + o1(bytes(range(hashlen)))     # hash_alg sha-1?, hash
    elif identity_type == 3:
        ident = b''
    else:
        ident = b'\x00\x00'
    return u8(2) + u8(1) + u8(identity_type) + o2(ident) + o2(b'\xaa' * 8)
def security(certs=(), identity_type=1, hashlen=4):
    cl = b''.join(u8(t) + o2(c) for t, c in certs)
    return o2(cl) + signature(identity_type, hashlen)

def contents(code, body, ext=b''):
    return u16(code) + o4(body) + o4(ext)
def message(tid, code, body, via=b'', dest=b'', opts=b'', ext=b'', sec=None, frag=0, ttl=64,
            maxresp=0, version=1, overlay=1, cfg=1, contents_override=None):
    c = contents_override if contents_override is not None else contents(code, body, ext)
    s = security() if sec is None else sec
    total = 38 + len(via) + len(dest) + len(opts) + len(c) + len(s)
    h = struct.pack('!IIHBBII', 0xd2454c4f, overlay, cfg, version, ttl, frag, total)
    h += u64(tid) + u32(maxresp) + u16(len(via)) + u16(len(dest)) + u16(len(opts))
    return h + via + dest + opts + c + s
def ext(t, crit, content): return u16(t) + u8(crit) + o4(content)

def ice(addr, link=1, found=b'f1', prio=100, ctype=1, relay=None, exts=()):
    r = addr + u8(link) + o1(found) + u32(prio) + u8(ctype)
    if ctype in (2, 3, 4): r += relay
    return r + o2(b''.join(o2(n) + o2(v) for n, v in exts))
def icelist(*c): return o2(b''.join(c))
CANDS = icelist(ice(ipv4((192, 0, 2, 9), 5000)),
                ice(ipv6(5001), 3, b'f2', 200, 2, ipv4((198, 51, 100, 7), 3478), [(b'n', b'v'), (b'x', b'')]),
                ice(ipv4((10, 0, 0, 1), 5002), 4, b'f3', 300, 3, ipv6(1)),
                ice(ipv4((10, 0, 0, 2), 5003), 5, b'', 400, 4, ipv4((1, 2, 3, 4), 5)),
                ice(ipv4((10, 0, 0, 3), 5004), 1, b'f5', 1, 9))
def attach(): return o1(b'ufrag') + o1(b'pass') + o1(b'active') + CANDS + u8(1)
def appattach(): return o1(b'uf') + o1(b'pw') + u16(5060) + o1(b'passive') + CANDS

def kind_resp(i, gen, reps): return u32(i) + u64(gen) + o2(b''.join(reps))
def kind(i, gen, vals): return u32(i) + u64(gen) + o4(vals)
def stored(value, sig=None, t=1700000000000, life=3600, meta_sig=False):
    sig = signature() if sig is None else sig
    inner = u64(t) + u32(life) + value + (b'' if meta_sig else sig)
    return o4(inner)
def dv(v, exists=1): return u8(exists) + o4(v)
def meta_dv(hl=4): return u8(1) + u32(100) + u8(2) + o1(b'h' * hl)
def sip_uri(): return u8(1) + o2(o2(b'sip:alice@example.com'))
def sip_route(): return u8(2) + o2(o2(b'q=1') + o2(dest_node(5) + dest_short(3)))
def turn(): return u8(1) + ipv4((192, 0, 2, 50), 3478)
def redir(): return o2(nid(7) + o2(b'ns') + u16(1) + u16(2))
def dkey(k): return o2(k)

def tid_gen():
    n = [0x1000]
    def g(): n[0] += 1; return n[0]
    return g
T = tid_gen()

class Out:
    def __init__(self): self.f = []; self.mark = []
    def add(self, p, snap=None): self.f.append((p, snap))
    def sect(self, name, fn):
        a = len(self.f) + 1; fn(); self.mark.append((name, a, len(self.f)))

def build():
    o = Out(); CP = 40000
    def U(msg, sport=CP, dport=6085, req=True):     # raw RELOAD, UDP heuristic
        o.add(udp(msg, sport, dport) if req else udp(msg, dport, sport, SRV, CLI))
    def REQ(m): U(m)
    def RSP(m): U(m, req=False)
    tcpseq = [1000]
    def TCP(msg, req=True):
        if req:
            o.add(tcp(msg, 41000, 6086, tcpseq[0], 5000)); tcpseq[0] += len(msg)
        else:
            o.add(tcp(msg, 6086, 41000, 5000, tcpseq[0], SRV, CLI))
    fseq = [1]
    def FR(msg, req=True):                           # framed on UDP 6084
        p = framed(fseq[0], msg); fseq[0] += 1
        o.add(udp(p, 41001, 6084) if req else udp(p, 6084, 41001, SRV, CLI))

    # --- forwarding header, ping, transactions
    def hdr():
        t = T(); REQ(message(t, 23, o2(b'')))
        RSP(message(t, 24, u64(0x1122334455667788) + u64(1700000000123)))
        REQ(message(T(), 23, o2(b'pad' * 3), ttl=3, maxresp=1400, overlay=0xdeadbeef, cfg=0, version=2))
        # duplicate request and duplicate response
        t = T(); REQ(message(t, 23, o2(b''))); REQ(message(t, 23, o2(b'')))
        RSP(message(t, 24, u64(1) + u64(2))); RSP(message(t, 24, u64(1) + u64(2)))
        # a response without a request
        RSP(message(T(), 24, u64(5) + u64(1700000000999)))
        # via, destination and options lists
        via = dest_node(1) + dest_short(2) + dest_res(b'res') + dest_comp(b'cmp') + b'\x09\x00'
        dest = dest_node(0) + dest_node(0xff) + dest_node(3)
        opt = (u8(2) + u8(0x0f) + o2(u8(1) + u8(2) + ipv4((192, 0, 2, 3), 6084) +
               o1(dest_node(8) + dest_short(1))))
        opt += u8(2) + u8(0) + o2(u8(2) + u8(1) + ipv6(2) + o1(b''))
        opt += u8(0x40) + u8(0x01) + o2(b'opaque')
        REQ(message(T(), 23, o2(b''), via=via, dest=dest, opts=opt))
        # certificates (X.509 and an unknown type) in the security block
        REQ(message(T(), 23, o2(b''), sec=security([(0, CERT), (1, b'opaque cert')], 2, 6)))
        # extensions: self tuning data, an unknown one, an empty self tuning
        e = ext(2, 0, u32(1000) + u32(10) + u32(20)) + ext(2, 1, b'') + ext(9, 1, b'unknown ext')
        REQ(message(T(), 23, o2(b''), ext=e))
    o.sect('Forwarding header, lists, options, ping, transactions, security block', hdr)

    def diag():
        # diagnostic ping request and response with every DiagnosticInfo kind
        flags = u64(0xffffffffffffffff)
        t = T()
        dreq = u64(1700000010000) + u64(1700000000000) + flags + u32(0)
        REQ(message(t, 23, o2(b''), ext=ext(3, 0, dreq)))
        infos = b''
        def di(k, v): return u16(k) + o2(v)
        infos += di(1, b'\x01') + di(2, u32(12)) + di(3, u32(1000)) + di(4, u32(10000))
        infos += di(5, b'libreload 1.0') + di(6, u64(86400)) + di(7, u64(3600)) + di(8, u32(1 << 20))
        infos += di(9, u64(1 << 30)) + di(10, u32(3) + u64(17) + u32(1) + u64(2))
        infos += di(11, u16(23) + u64(5) + u64(6) + u16(24) + u64(7) + u64(8) + u16(0xffff) + u64(1) + u64(2))
        infos += di(12, u32(100)) + di(13, u32(200)) + di(14, u8(4)) + di(15, u8(90)) + di(0x77, b'raw')
        dresp = u64(1700000010000) + u64(1700000000500) + u8(3) + o4(infos)
        RSP(message(t, 24, u64(9) + u64(1700000000600), ext=ext(3, 0, dresp)))
        # path track
        t = T()
        REQ(message(t, 101, dest_node(4) + u64(1700000010000) + u64(1700000000000) + flags + u32(0)))
        RSP(message(t, 102, dest_short(9) + u64(1700000010000) + u64(1700000000500) + u8(1) + o4(di(2, u32(7)))))
    o.sect('Diagnostics (ping extension, path track)', diag)

    def conn():
        REQ(message(T(), 3, attach()))               # attach request
        t = T(); REQ(message(t, 3, attach()))
        RSP(message(t, 4, attach()))
        REQ(message(T(), 29, appattach()))
        RSP(message(T(), 30, appattach()))
        REQ(message(T(), 1, u8(2) + u8(1) + u8(0x02)))  # probe request, three types
        REQ(message(T(), 1, u8(3) + u8(1) + u8(2) + u8(3)))
        RSP(message(T(), 2, o2(u8(1) + o1(u32(0x80000000)) + u8(2) + o1(u32(5)) + u8(3) + o1(u32(99)) + u8(4) + o1(b'exp'))))
        REQ(message(T(), 33, u8(1) + o4(o3(b'<config/>'))))      # config update (XML)
        REQ(message(T(), 33, u8(2) + o4(o3(o2(b'<kind/>') + o2(b'<kind2/>')))))
        REQ(message(T(), 33, u8(7) + o4(b'')))
        RSP(message(T(), 34, b'\x01'))
    o.sect('Probe, attach, app attach, config update', conn)

    def store():
        k_sip = kind(1, 1, stored(dkey(nid(1)) + dv(sip_uri())) + stored(dkey(nid(3)) + dv(sip_route()), t=1700000001000)
                     + stored(dkey(nid(2)) + dv(b''), life=0))
        k_turn = kind(2, 2, stored(dv(turn())))
        k_turn2 = kind(2, 3, stored(dv(b'')))
        k_cert = kind(3, 3, stored(u32(0) + dv(CERT)) + stored(u32(0xffffffff) + dv(CERT)))
        k_certu = kind(16, 4, stored(u32(1) + dv(b'')))
        k_redir = kind(104, 5, stored(dkey(nid(7)) + dv(redir())))
        k_unknown = kind(0x1234, 6, stored(dv(b'whatever')))
        k_nomodel = kind(5, 7, stored(dv(b'x')))
        k_inv = kind(0, 8, stored(dv(b'x')))
        k_opaque = kind(2, 9, stored(u8(1) + o4(b'\x99\x99\x99')))
        for kd in (k_sip, k_turn + k_turn2, k_cert + k_certu, k_redir, k_unknown, k_inv, k_opaque):
            REQ(message(T(), 7, o1(b'resource') + u8(0) + o4(kd)))
        t = T()
        REQ(message(t, 7, o1(b'res') + u8(1) + o4(k_turn)))
        resp = kind_resp(2, 1, [nid(1), nid(2), nid(0xff)]) + kind_resp(1, 2, [])
        RSP(message(t, 8, o2(resp)))
        RSP(message(T(), 8, o2(b'')))
    o.sect('Store requests (every data kind and model)', store)

    def fetch():
        def spec(k, gen, body): return u32(k) + u64(gen) + o2(body)
        arr = o2(u32(0) + u32(5) + u32(7) + u32(0xffffffff))
        dic = o2(o2(b'k1') + o2(nid(3)))
        specs = spec(3, 0, arr) + spec(1, 5, dic) + spec(2, 1, b'') + spec(0x1234, 0, b'') + spec(5, 0, b'')
        REQ(message(T(), 9, o1(b'resource') + o2(specs)))
        REQ(message(T(), 9, o1(b'r') + o2(b'')))
        # stat request
        REQ(message(T(), 25, o1(b'resource') + o2(spec(3, 0, arr) + spec(1, 5, dic))))
        # fetch answer: several kinds
        t = T()
        v_sip = stored(dkey(nid(1)) + dv(sip_uri())) + stored(dkey(nid(2)) + dv(sip_route()))
        fa = kind(1, 1, v_sip) + kind(2, 2, stored(dv(turn()))) + kind(3, 3, stored(u32(0) + dv(CERT))) + kind(104, 4, stored(dkey(nid(7)) + dv(redir())))
        RSP(message(t, 10, o4(fa)))
        RSP(message(T(), 10, o4(b'')))
        # stat answer: StoredMetaData
        sm = kind(3, 1, stored(u32(0) + meta_dv(), meta_sig=True) + stored(u32(1) + meta_dv(8), meta_sig=True)) \
            + kind(1, 2, stored(dkey(nid(4)) + meta_dv(), meta_sig=True)) + kind(2, 3, stored(meta_dv(), meta_sig=True)) \
            + kind(0x1234, 4, stored(meta_dv(), meta_sig=True))
        RSP(message(T(), 26, o4(sm)))
        RSP(message(T(), 26, o4(b'')))
        # find
        REQ(message(T(), 13, o1(b'resource') + o1(u32(1) + u32(2))))
        REQ(message(T(), 13, o1(b'resource') + o1(b'')))
        RSP(message(T(), 14, o2(u32(1) + o1(b'closest') + u32(3) + o1(b'c2'))))
        RSP(message(T(), 14, o2(b'')))
    o.sect('Fetch, stat and find', fetch)

    def overlay():
        t = T()
        REQ(message(T(), 15, nid(2) + o2(b'join-data')))               # join request (16)
        RSP(message(T(), 16, o2(b'answer')))
        REQ(message(T(), 17, nid(2) + o2(u8(1) + o2(nid(1) + nid(2)))))    # leave from successor
        REQ(message(T(), 17, nid(2) + o2(u8(2) + o2(nid(3)))))             # leave from predecessor
        REQ(message(T(), 17, nid(2) + o2(u8(7))))
        RSP(message(T(), 18, o2(b'bye')))
        REQ(message(T(), 19, u32(3600) + u8(1)))                           # chord update peer ready
        REQ(message(T(), 19, u32(3600) + u8(2) + o2(nid(1)) + o2(nid(2) + nid(3))))
        REQ(message(T(), 19, u32(3600) + u8(3) + o2(nid(1)) + o2(nid(2)) + o2(nid(3) + nid(4) + nid(5))))
        RSP(message(T(), 20, b'\x00'))                                      # update answer (nothing)
        REQ(message(T(), 21, u8(1) + dest_node(5) + o2(b'chord')))         # route query
        REQ(message(T(), 21, u8(0) + dest_short(5) + o2(b'')))
        RSP(message(T(), 22, nid(6)))
    o.sect('Join, leave, update, route query', overlay)

    def errors():
        def err(code, info): return u16(code) + o2(info)
        for code, info in ((2, b'forbidden'), (3, b''), (4, b'timeout'), (8, b'too large'), (13, b'ext'),
                           (19, b'x'), (20, b'above the named codes'), (104, b'misrouted'), (999, b'')):
            REQ(message(T(), 0xffff, err(code, info)))
        # generation counter too low: StoreAns follows
        REQ(message(T(), 0xffff, u16(5) + o2(o2(kind_resp(2, 1, [nid(1)])))))
        # unknown kind: kind id list
        REQ(message(T(), 0xffff, u16(12) + o2(o1(u32(2) + u32(1) + u32(77)))))
        # underlay destination unreachable: 32 octet string
        REQ(message(T(), 0xffff, u16(101) + b'unreachable-address-text-32-oct'.ljust(32, b'.')))
        # error as the answer to a request
        t = T(); REQ(message(t, 23, o2(b''))); RSP(message(t, 0xffff, u16(3) + o2(b'nope')))
        # an error message with an extension
        REQ(message(T(), 0xffff, u16(2) + o2(b''), ext=ext(2, 0, u32(1) + u32(2) + u32(3))))
    o.sect('Error responses', errors)

    def frag():
        t = T()
        full = message(t, 23, o2(b'x' * 200))
        hdr = full[:38]; payload = full[38:]
        def fr(off, data, flags):
            h = bytearray(hdr)
            h[12:16] = u32(flags | off)
            h[16:20] = u32(38 + len(data))
            return bytes(h) + data
        a, b, c = payload[:100], payload[100:200], payload[200:]
        REQ(fr(0, a, 0x80000000))
        REQ(fr(100, b, 0x80000000))
        REQ(fr(200, c, 0xc0000000))
        # out of order delivery: last first
        t2 = T(); full2 = message(t2, 23, o2(b'y' * 100)); p2 = full2[38:]
        h2 = bytearray(full2[:38])
        def fr2(off, data, flags):
            h = bytearray(h2); h[12:16] = u32(flags | off); h[16:20] = u32(38 + len(data)); return bytes(h) + data
        REQ(fr2(60, p2[60:], 0xc0000000))
        REQ(fr2(0, p2[:60], 0x80000000))
        # a single fragment that is the whole message (offset 0, last)
        REQ(fr2(0, p2, 0xc0000000))
        # a fragment flagged only 'last'
        REQ(message(T(), 23, o2(b''), frag=0x40000000))
        # fragment shown while its data is cut by the snaplen
        o.add(udp(fr2(0, p2[:60], 0x80000000) + b'', CP, 6085), snap=14 + 20 + 8 + 38 + 10)
    o.sect('Fragmentation and reassembly', frag)

    def transports():
        t = T(); TCP(message(t, 23, o2(b'tcp')))
        TCP(message(t, 24, u64(1) + u64(1700000000000)), req=False)
        TCP(message(T(), 3, attach()))
        t = T(); FR(message(t, 23, o2(b'framed')))
        FR(message(t, 24, u64(2) + u64(1700000000001)), req=False)
        FR(message(T(), 9, o1(b'r') + o2(b'')))
    o.sect('TCP heuristic and RELOAD Framing', transports)
    def repro():
        # "RELOAD: Fix an infinite loop and CPU blow-ups on malformed messages"
        # 1. dictionary keys: a FetchReq whose specifiers (kind 1, SIP-REGISTRATION)
        #    declare 0xffff octets of keys (used to loop 32768 times per specifier)
        spec = u32(1) + b'\0' * 8 + u16(2) + u16(0xffff)
        specs = spec * 40
        REQ(message(T(), 9, b'\x00' + u16(len(specs)) + specs))
        # 2. DiagnosticInfo list of INSTANCES_STORED infos with a length of 2
        #    (each used to walk the rest of the list)
        infos = u16(0x000a) + u16(2) + b'\0\0' + u16(0x000a) + u16(2)
        infos = (u16(0x000a) + u16(2) + b'\0\0') * 150
        diag = b'\0' * 8 + b'\0' * 8 + b'\x01' + o4(infos)
        RSP(message(T(), 102, b'\x80\x00' + diag))
        # same with the compact (old format) list, a different kind each
        infos = b''.join(u16(k) + u16(2) + b'\0\0' for k in (0x000a, 0x000b, 0x0005, 0x0001)) * 20
        diag = b'\0' * 8 + b'\0' * 8 + b'\x01' + o4(infos)
        RSP(message(T(), 102, b'\x80\x00' + diag))
    o.sect('Reproducers of the CPU blow-up fixes (dictionary keys, DiagnosticInfo list)', repro)
    return o

def build_malformed():
    o = Out()
    def U(msg): o.add(udp(msg, 40100, 6085))
    ok = message(T(), 23, o2(b''))
    U(message(T(), 24, b'\0' * 8))
    U(message(T(), 23, o2(b''), sec=security([], 3)))
    U(message(T(), 101, b'\x01'))
    # truncated tail: cut every few octets inside the message (snaplen-like short frames)
    for cut in (4, 9, 20, 33, 37, 40, 44, 50, 60, 70, len(ok) - 2):
        o.add(udp(ok[:cut], 40100, 6085))
    # lengths in the forwarding header that run past the message
    for v, d, op in ((200, 0, 0), (0, 200, 0), (0, 0, 200)):
        m = bytearray(message(T(), 23, o2(b'')))
        m[32:34] = u16(v); m[34:36] = u16(d); m[36:38] = u16(op)
        U(bytes(m))
    # message length smaller than the data and larger than the data
    m = bytearray(ok); m[16:20] = u32(len(ok) + 50); U(bytes(m))
    # contents: body length and extension length past the end
    for body_len, ext_len in ((1000, 0), (4, 1000)):
        c = u16(23) + u32(body_len) + o2(b'') + u32(ext_len)
        U(message(T(), 23, b'', contents_override=c))
    # the infinite loop reproducer: fetch request code with a DIAGNOSTIC_PING extension of 0xfffffff9 octets
    U(message(T(), 9, u16(0), ext=u16(3) + u8(0) + u32(0xfffffff9)))
    # extension with a content length past the extensions (the reproducer of the
    # infinite loop fix) and one with a short header
    U(message(T(), 23, o2(b''), ext=u16(9) + u8(0) + u32(0xffffff00) + b'abc'))
    U(message(T(), 23, o2(b''), ext=u16(9) + u8(0) + u32(0xfffffff9)))
    U(message(T(), 23, o2(b''), ext=b'\x00\x09\x00\x00\x00'))
    # security block problems: certificate longer than the list, unknown identity type, short hash
    U(message(T(), 23, o2(b''), sec=o2(u8(0) + u16(500) + b'abc') + signature()))
    U(message(T(), 23, o2(b''), sec=security([], 9)))
    U(message(T(), 23, o2(b''), sec=o2(b'') + u8(2) + u8(1) + u8(1) + o2(u8(2) + u8(200) + b'ab') + o2(b'zz')))
    # store request pieces too short
    def S(body, code=7): U(message(T(), code, body))
    S(o1(b'abcdefghij')[:5])
    S(o1(b'a'))
    S(o1(b'a') + u8(0) + u32(1000))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, u32(1000))))
    S(o1(b'a') + u8(0) + o4(u32(1) + u64(1) + u32(50)))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, u32(100) + b'zz')))
    # dictionary key longer than the entry, key and value too long
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(o2(b'k' * 200)))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, o4(u64(1) + u32(1) + u16(5)))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, o4(u64(1) + u32(1) + u16(0) + dv(b'abc') [:3]))))
    S(o1(b'a') + u8(0) + o4(kind(3, 1, stored(u32(0) + u8(1) + u32(5000)))))
    S(o1(b'a') + u8(0) + o4(kind(3, 1, stored(u32(0) + u8(1) + u32(5000)) + b'')[:-1]))
    S(o1(b'a') + u8(0) + o4(kind(3, 1, o4(u64(1) + u32(1) + u32(0) + u8(1) + u32(2000)))))
    S(o1(b'a') + u8(0) + o4(kind(2, 1, stored(u8(1) + o4(b'\x01' + b'\x00' * 5)))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(dkey(b'k') + u8(1) + o4(u8(2) + u16(3) + b'ab'))
                           )))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(dkey(b'k') + u8(1) + o4(u8(7) + u16(5000) + b'ab')))))
    S(o1(b'a') + u8(0) + o4(kind(104, 1, stored(dkey(b'k') + dv(o2(b'zz'))))))
    S(o1(b'a') + u8(0) + o4(kind(104, 1, stored(dkey(b'k') + dv(u16(1))))))
    S(o1(b'a') + u8(0) + o4(kind(104, 1, stored(dkey(b'k') + dv(o2(nid(1) + o2(b'ns') + u16(1) + u16(2)))))))
    S(o1(b'a') + u8(0) + o4(kind(2, 1, stored(dv(b'\x01')))))
    S(o1(b'a') + u8(0) + o4(kind(2, 1, stored(dv(u8(1) + b'\x01\x00')))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(dkey(b'k') + dv(u8(1) + o2(b'x'))))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(dkey(b'k') + dv(u8(2) + o2(o2(b'q') + u16(60000)))))))
    S(o1(b'a') + u8(0) + o4(kind(1, 1, stored(dkey(b'k') + dv(u8(2) + o2(o2(b'q') + o2(dest_node(1)[:-3])))))))
    S(o2(b''), 8)
    S(o2(u32(1) + u64(1) + o2(nid(1)))[:6], 8)
    S(o2(kind_resp(1, 1, [nid(1)])[:-3]) , 8)
    S(o2(kind_resp(1, 1, [nid(1)])[:14] + u16(200)), 8)
    # fetch / stat / find pieces
    S(o1(b'res') + o2(b'abc'), 9)
    S(o1(b'res') + o2(u32(3) + u64(0) + o2(o2(b'x' * 100))), 9)
    S(o1(b'res') + o2(u32(3) + u64(0) + o2(u32(0) + u32(1))), 9)
    S(o1(b'res') + o2(u32(1) + u64(0) + o2(u16(0xffff))), 9)
    S(o1(b'res') + o2(u32(1) + u64(0) + o2(u16(30) + o2(b'aaaa'))), 9)
    S(o1(b'res') + o2(u32(1) + u64(0) + o2(u16(6) + o2(b'a' * 4) + b'zz'))[:-1], 9)
    S(o1(b'res') + o2(u32(1) + u64(0) + o2(o2(b'k1') + o2(b'k2'))) + o2(b''), 9)
    S(u32(5000), 10)
    S(o4(b'abc'), 10)
    S(o4(kind(1, 1, u32(500))), 10)
    S(o4(kind(1, 1, o4(b'zz'))), 10)
    S(o4(kind(3, 1, stored(u32(0) + meta_dv()))), 26)
    S(u32(70000) + b'x' * 10, 26)
    S(u32(5000), 26)
    S(o4(b'a' * 20), 26)
    S(o1(b'res') + o1(u32(1)) , 13)
    S(o1(b'r') + o1(b'\xff' + b'\0' * 5), 13)
    S(o1(b'long' * 10), 13)
    S(o2(u32(1) + o1(b'abc') + u32(2) + o1(b'abcdef')), 14)
    S(o2(u32(1) + o1(b'abc') + u32(2) + o1(b'abcdef') [:5]) + b'', 14)
    S(o2(b'\x00\x00\x00\x01\xff'), 14)
    S(o2(b'\x00' * 100), 14)
    # attach, ICE and probe pieces
    for body in (b'\xff', o1(b'u') + b'\xff', o1(b'u') + o1(b'p') + b'\xff', o1(b'u') + o1(b'p') + o1(b'r') + u16(500),
                 o1(b'u') + o1(b'p') + o1(b'r') + u16(100) + b'a' * 20):
        S(body, 3); S(body, 29)
    cand_base = ipv4((1, 1, 1, 1), 1) + u8(1) + o1(b'f') + u32(1)
    for c in (cand_base + u8(1) + u16(50), cand_base + u8(2) + ipv4((1, 1, 1, 2), 2) + o2(o2(b'n') + o2(b'v' * 50)),
              cand_base + u8(1) + o2(o2(b'n' * 10) + o2(b'v')), cand_base[:5]):
        S(o1(b'u') + o1(b'p') + o1(b'r') + o2(c) + u8(0), 3)
        S(o1(b'u') + o1(b'p') + u16(5060) + o1(b'r') + o2(c), 29)
    S(o1(b'u') + o1(b'p') + o1(b'r') + o2(b'\x01' * 40) + u8(0), 3)
    S(u8(5), 1); S(o2(u8(1) + o1(b'ab')), 2)
    S(o2(u8(1) + o1(b'\0\0\0\0') + u8(2) + o1(b'\0\0') + u8(3) + o1(b'\0') + u8(4) + o1(b'\0\0')), 2)
    S(o2(b'\x01\xff'), 2); S(o2(b'\x01\x04\0\0\0\0\x02\x04\0\0\0\0\x03\x08'), 2); S(o2(u8(1) + o1(b'ab') + u8(9) + o1(b'abcdef'))[:-2], 2)
    S(u8(1) + o1(b'ab'), 1)
    S(o2(b'\x01\x02' + b'ab'), 2)
    S(o2(u8(1) + o1(b'a')), 2); S(o2(u8(2) + o1(b'abc')), 2); S(o2(u8(3) + o1(b'ab')), 2)
    S(o1(b'a') + u8(0) + o4(kind(5, 1, stored(dv(b'x')))), 7)
    S(o1(b'a') + u8(0) + o4(kind(1, 1, o4(u64(1) + u32(1) + b'\x00'))), 7)
    S(o4(kind(3, 1, o4(u64(1) + u32(1) + u32(0) + u8(1) + u32(100) + b'\x00' * 3))), 26)
    S(o2(u32(1) + o1(b'abc')[:2]), 14)
    S(u32(5000) + u16(12) + b'\x00\x00', 0xffff)
    S(u16(12) + o2(b'\x08'), 0xffff)
    U(message(T(), 0xffff, u16(4) + o2(b'x'), contents_override=u16(0xffff) + u32(2) + u16(500) + u32(0)))
    # config update, join/leave/update/route query, diagnostic and path track pieces
    S(u8(1) + o4(b'abc'), 33)
    S(u8(1) + u32(900) + b'abc', 33)
    S(u8(2) + o4(o3(o2(b'<k/>') + u16(500))), 33)
    S(u8(2) + o4(o3(b'')), 33)
    S(nid(1)[:5], 17); S(nid(1) + o2(b'\x01' + o2(nid(1) + nid(2))[:5]), 17)
    S(nid(1)[:4], 15)
    S(u32(1) + u8(2) + o2(nid(1) + nid(2))[:7], 19)
    S(u32(1) + u8(3) + o2(b'') + o2(nid(1)) + b'\x00\x20' + nid(1), 19)
    S(u8(1) + b'\x01', 21); S(u8(0) + dest_node(1)[:5], 21); S(b'\x01', 21)
    S(dest_node(1)[:10], 101)
    S(dest_node(4) + b'\0' * 40, 101)
    S(dest_node(4) + u64(1) + u64(2) + u64(3) + o4(b'\x00\x00\x00\x08' + u16(1) + u32(5000) + b'ab'), 101)
    S(dest_node(4) + u64(1) + u64(2) + u64(3) + o4(u32(500) + b'ab'), 101)
    S(dest_node(4) + u64(1) + u64(2) + u64(3) + u32(30) + u32(26) + u16(7) + u32(2) + b'ab' + u16(8) + u32(0) + b'x' * 20, 101)
    S(dest_node(4) + u64(1) + u64(2) + u64(3) + u32(12) + u32(8) + u16(7) + u32(0) + b'yy', 101)
    S(dest_short(1) + u64(1) + u64(2) + u8(1) + u32(5000), 102)
    S(dest_short(1) + u64(1) + u64(2) + u8(1) + o4(u16(1) + u16(50) + b'x'), 102)
    S(dest_short(1) + u64(1) + u64(2) + u8(1) + o4(u16(2) + u16(2) + b'zz' + u16(11) + u16(3)), 102)
    S(dest_short(1) + u64(1) + u64(2) + u8(1) + o4(u16(11) + u16(100) + b'\0' * 17), 102)
    S(b'\x00' * 3, 102)
    # diagnostic ping extension in other shapes
    dflags = u64(0)
    def pe(code, content): U(message(T(), code, o2(b''), ext=ext(3, 0, content)))
    pe(23, u64(1) + u64(2) + dflags + o4(b'\x00\x00\x00\x04' + b'\x00\x01\x00\x00\x00\x02' + b'ab'))
    pe(23, u64(1) + u64(2) + dflags + u32(100))
    pe(23, u64(1) + u64(2) + dflags + u32(3) + b'abc')
    pe(23, u64(1) + u64(2) + dflags + u32(10) + u32(100) + b'abcdef')
    pe(23, u64(1) + u64(2) + dflags + u32(12) + u32(8) + u16(3) + u32(0) + b'zz')
    pe(23, u64(1) + u64(2) + dflags + u32(20) + u32(16) + u16(3) + u32(2) + b'zz' + u16(4) + u32(0) + b'zz' + b'ab')
    pe(23, b'short')
    pe(24, u64(1) + u64(2) + u8(1) + u32(5000))
    pe(24, u64(1) + u64(2) + u8(1) + u32(20) + u16(1) + u16(200) + b'a' * 10)
    pe(24, u64(1) + u64(2) + u8(1) + u32(8) + u16(1) + u16(2) + b'\x00\x01' + u16(3) + u16(0))
    pe(24, u64(1) + u64(2))
    # diagnostic info of the instances and messages kinds cut short
    for kindid, val in ((10, b'\0' * 7), (11, b'\0' * 7), (5, b''), (6, b''), (1, b'')):
        pe(24, u64(1) + u64(2) + u8(1) + o4(u16(kindid) + o2(val)))
    # options: truncated option, extensive routing option with a short destination list
    U(message(T(), 23, o2(b''), opts=u8(2) + u8(0) + u16(500) + b'ab'))
    U(message(T(), 23, o2(b''), opts=u8(2) + u8(0) + o2(u8(1) + u8(2) + ipv4((1, 1, 1, 1), 1) + u8(200) + b'ab')))
    U(message(T(), 23, o2(b''), opts=u8(2) + u8(0) + o2(u8(1) + u8(2) + b'\x01\x08')))
    U(message(T(), 23, o2(b''), opts=b'\x02\x00\x00'))
    # destinations: truncated, unknown type, short node id and resource id
    for d in (b'\x01\x20' + b'a' * 4, b'\x05\x02ab', b'\x01\x04abcd', b'\x02\x03\x09ab', b'\x03\x02\x05a', b'\x01'):
        U(message(T(), 23, o2(b''), dest=d)); U(message(T(), 23, o2(b''), via=d))
    # a ping answer with extensions that overrun
    U(message(T(), 24, u64(1) + u64(1), ext=ext(2, 0, u32(1) + u32(2))))
    # the reproducers of the CPU blow-up fixes: dictionary keys (SIP) with a large key
    # block, and a DiagnosticInfo list whose entries claim long lengths
    spec = u32(1) + u64(0) + o2(o2(b'\x00' * 100)[:2] + b'\x00' * 20)
    S(o1(b'r') + o2(spec), 9)
    di = b''.join(u16(2) + u16(0xfff0) + b'\0' * 8 for _ in range(30))
    pe(24, u64(1) + u64(2) + u8(1) + o4(di))
    # snaplen-truncated frames
    o.add(udp(ok, 40100, 6085), snap=60)
    o.add(udp(framed(1, ok), 40101, 6084), snap=70)
    return o

if __name__ == '__main__':
    out = sys.argv[1]
    def wr(path, o):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, (p, snap) in enumerate(o.f):
                c = p if snap is None else p[:snap]
                f.write(struct.pack('<IIII', 1 + i // 4, 250000 * (i % 4), len(c), len(p)) + c)
    o = build()
    wr(os.path.join(out, 'reload-coverage.pcap'), o)
    m = build_malformed()
    wr(os.path.join(out, 'reload-coverage-malformed.pcap'), m)
    if '-v' in sys.argv:
        for n, a, b in o.mark: print('%4d-%4d  %s' % (a, b, n))
        print(len(o.f), 'frames;', len(m.f), 'malformed frames')

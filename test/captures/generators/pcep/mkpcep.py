#!/usr/bin/env python3
# Generates test/captures/pcep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the PCEP coverage captures.
# Usage: mkpcep.py <outdir>
# Writes pcep-coverage.pcap (clean) and pcep-coverage-malformed.pcap.
# Everything is synthetic: Ethernet/IPv4/TCP to port 4189.
import struct
import sys
import os


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.pkts = []

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


class Flow:
    def __init__(self, cap, cport, sport=4189):
        self.cap = cap
        self.c = [bytes([192, 0, 2, 1]), cport, 1000]
        self.s = [bytes([192, 0, 2, 2]), sport, 5000]

    def send(self, from_client, payload):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        tcp = struct.pack('>HHIIBBHHH', a[1], b[1], a[2], b[2], 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, a[0], b[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        ph = a[0] + b[0] + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        eth = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
        if not from_client:
            eth = bytes.fromhex('020000000001020000000002') + b'\x08\x00'
        self.cap.pkts.append(eth + ip + tcp)
        a[2] += len(payload)

    def c2s(self, p): self.send(True, p)
    def s2c(self, p): self.send(False, p)


def u8(*v): return bytes(v)
def u16(*v): return struct.pack('>%dH' % len(v), *v)
def u32(*v): return struct.pack('>%dI' % len(v), *v)
def ip4(a): return bytes(int(x) for x in a.split('.'))
def ip6(a):
    import socket
    return socket.inet_pton(socket.AF_INET6, a)
def pad4(b): return b + b'\0' * ((-len(b)) % 4)


# ---------------------------------------------------------------- framing
(OPEN, KEEPALIVE, PCREQ, PCREP, PCNTF, PCERR, CLOSE, PCMONREQ, PCMONREP, PCRPT,
 PCUPD, PCINIT, STARTTLS) = range(1, 14)


def obj(cls, typ, body, p=0, i=0, res=0, length=None):
    ln = 4 + len(body) if length is None else length
    return struct.pack('>BBH', cls, (typ << 4) | (res << 2) | (p << 1) | i, ln) + body


def msg(mtype, objs, ver=1, flags=0, length=None):
    body = b''.join(objs)
    ln = 4 + len(body) if length is None else length
    return struct.pack('>BBH', (ver << 5) | flags, mtype, ln) + body


def tlv(t, v, length=None):
    ln = len(v) if length is None else length
    return struct.pack('>HH', t, ln) + pad4(v)


# ---------------------------------------------------------------- TLVs
def tlvs_all():
    """One of every TLV the dissector knows, in a list of (name, bytes)."""
    t = []
    t.append(tlv(1, u32(0xff)))                                    # NO-PATH-VECTOR
    t.append(tlv(2, u32(30)))                                      # OVERLOAD-DURATION (generic)
    t.append(tlv(3, u32(7)))                                       # REQ-MISSING
    t.append(tlv(4, u16(1, 2, 0xffff)))                            # OF-list (padded)
    t.append(tlv(7, u32(1234) + b'vendor'))                        # VENDOR-INFORMATION
    t.append(tlv(16, u32(0x7f)))                                   # STATEFUL-PCE-CAPABILITY
    t.append(tlv(17, b'LSP-1'))                                    # SYMBOLIC-PATH-NAME
    t.append(tlv(18, ip4('192.0.2.1') + u16(1, 2) + ip4('192.0.2.1') + ip4('192.0.2.9')))
    t.append(tlv(19, ip6('2001:db8::1') + u16(3, 4) + ip6('2001:db8::1') + ip6('2001:db8::9')))
    t.append(tlv(20, u32(5)))                                      # LSP-ERROR-CODE
    t.append(tlv(21, b'rsvp error'))                               # RSVP-ERROR-SPEC
    t.append(tlv(23, struct.pack('>Q', 42)))                       # LSP-DB-VERSION
    t.append(tlv(24, b'speaker1'))                                 # SPEAKER-ENTITY-ID
    t.append(tlv(26, u16(0) + u8(3, 16)))                          # SR-PCE-CAPABILITY (deprecated)
    t.append(tlv(27, u8(0, 0, 0, 1)))                              # PATH-SETUP-TYPE (pre IANA)
    t.append(tlv(28, u8(0, 0, 0, 1)))                              # PATH-SETUP-TYPE
    t.append(tlv(29, u16(0, 1, 100, 10) + u16(0, 2, 200, 20)))     # OP-CONF-ASSOC-RANGE
    t.append(tlv(30, u32(0xc0000201)))                             # GLOBAL-ASSOCIATION-SOURCE
    t.append(tlv(31, b'\1\2\3\4\5\6\7\x08'))                       # EXTENDED-ASSOCIATION-ID (other type)
    t.append(tlv(35, u16(1, 2, 6, 99)))                            # ASSOC-Type-List
    t.append(tlv(40, u32(100, 0xc0000201, 5)))                     # SRCPAG-INFO
    t.append(tlv(56, b'policy-1'))                                 # SRPOLICY-POL-NAME
    t.append(tlv(57, u8(10, 0, 0, 0) + u32(65000) + ip6('2001:db8::5') + u32(0xc0000202) + u32(77)))
    t.append(tlv(58, b'cpath-1'))                                  # SRPOLICY-CPATH-NAME
    t.append(tlv(59, u32(200)))                                    # SRPOLICY-CPATH-PREFERENCE
    t.append(tlv(60, u16(4) + u8(0x1f, 0)))                        # MULTIPATH-CAP
    t.append(tlv(61, u32(10)))                                     # MULTIPATH-WEIGHT
    t.append(tlv(99, b'xyz'))                                      # unknown TLV
    return t


def tlv34(psts, subtlvs=b''):
    body = u8(0, 0, 0, len(psts)) + bytes(psts)
    body = pad4(body)
    return tlv(34, body + subtlvs)


def subtlv(t, v):
    return struct.pack('>HH', t, len(v)) + pad4(v)


def te_path_binding(bt, value=b'', flags=0x80):
    return tlv(55, u8(bt, flags) + u16(0) + value)


# ---------------------------------------------------------------- sub-objects
def so_ipv4(l, addr='192.0.2.10', pl=32, flags=0):
    return u8(l | 1, 8) + ip4(addr) + u8(pl, flags)


def so_ipv6(l, addr='2001:db8::10', pl=128, flags=0):
    return u8(l | 2, 20) + ip6(addr) + u8(pl, flags)


def so_label(l, ctype=1, u=0, label=b'\0\0\x10\x01', flags=None):
    ln = 4 + len(label)
    return u8(l | 3, ln, u if flags is None else flags, ctype) + label


def so_unnum(l, rid='192.0.2.11', ifid=5, b2=0, b3=0):
    return u8(l | 4, 12, b2, b3) + ip4(rid) + u32(ifid)


def so_as(l, asn=65001):
    return u8(l | 32, 4) + u16(asn)


def so_as_xro(l, hi=1, asn=65002, attr=0):
    return u8(l | 32, 8, attr, 0) + u16(hi, asn)


def so_srlg(l, srlg=77, attr=0):
    return u8(l | 34, 8) + u32(srlg)[0:4] + u8(0, attr)


def so_pks4(l, key=9, pce='192.0.2.50'):
    return u8(l | 64, 8) + u16(key) + ip4(pce)


def so_pks6(l, key=9, pce='2001:db8::50'):
    return u8(l | 65, 20) + u16(key) + ip6(pce)


def so_sr(l, nt, flags, sid=b'', nai=b'', typ=36):
    body = u8((nt << 4) | (flags >> 8), flags & 0xff) + sid + nai
    return u8(l | typ, 4 + len(sid) + len(nai)) + body


def so_srv6(l, nt, flags, behavior=1, sid=None, nai=b'', struct_=None):
    body = u8((nt << 4) | (flags >> 8), flags & 0xff) + u16(0) + u16(behavior)
    if sid is not None:
        body += sid
    body += nai
    if struct_ is not None:
        body += struct_
    return u8(l | 40, 2 + len(body)) + body


def so_exrs(l, inner):
    body = u16(0) + inner
    return u8(l | 33, 2 + len(body)) + body


# a nodes/adjacency NAI of every type, SR: (nt, bytes)
NAI = {
    1: ip4('192.0.2.1'),
    2: ip6('2001:db8::1'),
    3: ip4('192.0.2.1') + ip4('192.0.2.2'),
    4: ip6('2001:db8::1') + ip6('2001:db8::2'),
    5: u32(1, 2, 3, 4),
    6: ip6('2001:db8::1') + u32(11) + ip6('2001:db8::2') + u32(22),
}
LSE = u32((16001 << 12) | (5 << 9) | (1 << 8) | 64)


def sr_variants(l):
    out = []
    for nt in range(0, 8):
        nai = NAI.get(nt, b'')
        out.append(so_sr(l, nt, 0x001, LSE, nai))             # M: MPLS label with SID
    out.append(so_sr(l, 1, 0x000, u32(20), NAI[1]))           # SID only (no M), NAI
    out.append(so_sr(l, 1, 0x004, b'', NAI[1]))               # S: no SID
    out.append(so_sr(l, 0, 0x008, LSE, b'', typ=5))           # F: no NAI; pre IANA type
    return out


def srv6_variants(l):
    out = []
    sid = ip6('2001:db8:1::1')
    st = u8(32, 16, 16, 0) + u8(0, 0, 0, 0)
    out.append(so_srv6(l, 2, 0x000, 1, sid, NAI[2]))
    out.append(so_srv6(l, 4, 0x000, 2, sid, NAI[4]))
    out.append(so_srv6(l, 6, 0x000, 3, sid, NAI[6]))
    out.append(so_srv6(l, 2, 0x005, 4, None, NAI[2], st))        # S, T
    out.append(so_srv6(l, 2, 0x006, 5, sid, b'', st))            # F, T: F set, no NAI
    # V and T set: the NAI is present
    out.append(so_srv6(l, 2, 0x00c, 6, sid, NAI[2], st))
    return out


# ---------------------------------------------------------------- objects
def o_open(tlvs=b'', ver=1):
    return obj(1, 1, u8(0x20 | 0, 30, 120, 1) + tlvs)


def o_rp(flags=0x7f, rid=1, tlvs=b'', typ=1):
    return obj(2, typ, u32(flags) + u32(rid) + tlvs)


def o_nopath(ni=0, flags=0x8000, tlvs=b''):
    return obj(3, 1, u8(ni) + u16(flags) + u8(0) + tlvs)


def o_ep4():
    return obj(4, 1, ip4('192.0.2.1') + ip4('192.0.2.2'))


def o_ep6():
    return obj(4, 2, ip6('2001:db8::1') + ip6('2001:db8::2'))


def o_ep4p2mp(n=2):
    return obj(4, 3, u32(1) + ip4('192.0.2.1') + b''.join(ip4('192.0.2.%d' % (10 + k)) for k in range(n)))


def o_ep6p2mp(n=2):
    return obj(4, 4, u32(2) + ip6('2001:db8::1') + b''.join(ip6('2001:db8::%x' % (10 + k)) for k in range(n)))


def o_bandwidth(bits=0x49742400, typ=1):
    return obj(5, typ, u32(bits))


def o_metric(mtype=2, flags=3, val=0x41200000):
    return obj(6, 1, u16(0) + u8(flags, mtype) + u32(val))


def o_ero(subs, cls=7, typ=1):
    return obj(cls, typ, b''.join(subs))


def o_rro(subs, cls=8):
    return obj(cls, 1, b''.join(subs))


def o_lspa(tlvs=b'', flags=1):
    return obj(9, 1, u32(0x11, 0x22, 0x33) + u8(4, 5, flags, 0) + tlvs)


def o_iro(subs):
    return obj(10, 1, b''.join(subs))


def o_svec(n=3, flags=0x1f):
    return obj(11, 1, u32(flags) + b''.join(u32(0x100 + k) for k in range(n)))


def o_notif(nt, nv, tlvs=b''):
    return obj(12, 1, u8(0, 0, nt, nv) + tlvs)


def o_err(et, ev, tlvs=b'', typ=1):
    return obj(13, typ, u8(0, 0, et, ev) + tlvs)


def o_lb(maxlsp=4, minbw=0x49742400):
    return obj(14, 1, u8(0, 0, 0, maxlsp) + u32(minbw))


def o_close(reason=1, tlvs=b''):
    return obj(15, 1, u16(0) + u8(0, reason) + tlvs)


def o_pathkey(subs):
    return obj(16, 1, b''.join(subs))


def o_xro(subs, flags=1):
    return obj(17, 1, u16(0, flags) + b''.join(subs))


def o_monitoring(flags=0x1f, mid=5, tlvs=b''):
    return obj(19, 1, u32(flags) + u32(mid) + tlvs)


def o_pccid(v6=False):
    return obj(20, 2 if v6 else 1, ip6('2001:db8::7') if v6 else ip4('192.0.2.7'))


def o_of(code=1, tlvs=b''):
    return obj(21, 1, u16(code, 0) + tlvs)


def o_pceid(v6=False):
    return obj(25, 2 if v6 else 1, ip6('2001:db8::8') if v6 else ip4('192.0.2.8'))


def o_proctime(flags=1):
    return obj(26, 1, u16(0, flags) + u32(1, 2, 3, 4, 5))


def o_overload(dur=60):
    return obj(27, 1, u16(0, dur))


def o_unreach(v6=False, n=2):
    if v6:
        return obj(28, 2, b''.join(ip6('2001:db8:5::%x' % (k + 1)) for k in range(n)))
    return obj(28, 1, b''.join(ip4('198.51.100.%d' % (k + 1)) for k in range(n)))


def o_bnc(subs):
    return obj(31, 1, b''.join(subs))


def o_lsp(plsp=0x12345, flags=0xff, tlvs=b''):
    return obj(32, 1, u32((plsp << 12) | (flags & 0xfff)) + tlvs)


def o_srp(flags=1, srpid=3, tlvs=b''):
    return obj(33, 1, u32(flags, srpid) + tlvs)


def o_vendor(ent=1234, data=b'datadata'):
    return obj(34, 1, u32(ent) + data)


def o_bu(bits=0):
    return obj(35, 1, u32(1, 2))


def o_assoc(atype, aid, src, tlvs=b'', v6=False, flags=1):
    return obj(40, 2 if v6 else 1, u16(0, flags, atype, aid) + src + tlvs)


def o_pathattrib(flags=0xf, tlvs=b''):
    return obj(45, 1, u32(flags) + u32(0x77) + tlvs)


def c_tlvs(lst):
    return b''.join(lst)


# ---------------------------------------------------------------- main capture
def build_main(cap):
    f = Flow(cap, 51000)
    all_tlvs = tlvs_all()
    # ---- session set-up
    f.c2s(msg(OPEN, [o_open(tlv(16, u32(0x7f)) + tlv(17, b'name') + tlv(26, u16(0) + u8(3, 16)))]))
    f.s2c(msg(OPEN, [o_open(c_tlvs(all_tlvs[:12]))]))
    f.s2c(msg(KEEPALIVE, []))
    f.c2s(msg(KEEPALIVE, []))
    f.s2c(msg(STARTTLS, []))
    # TLVs in other carrier objects
    f.c2s(msg(OPEN, [o_open(c_tlvs(all_tlvs[12:]))]))
    f.c2s(msg(OPEN, [o_open(b'')]))
    # ---- path computation request: RP, END-POINTS in every type, bandwidth, metric, LSPA, ...
    for ep in (o_ep4(), o_ep6(), o_ep4p2mp(), o_ep6p2mp(), obj(4, 5, b'\0\0\0\0')):
        f.c2s(msg(PCREQ, [o_rp(0x7fff, 10, tlv(3, u32(1))), ep, o_bandwidth(), o_metric(),
                          o_lspa(tlv(17, b'x'))]))
    f.c2s(msg(PCREQ, [o_rp(0, 1), o_ep4(), o_bandwidth(0, 2), o_metric(1, 0), o_metric(2, 1),
                      o_lspa(), o_lb(), o_of(3, tlv(4, u16(1, 2)))]))
    # RP with every flag, old and new types
    f.c2s(msg(PCREQ, [o_rp(0xffffff, 0xdeadbeef, typ=2), o_ep4()]))
    # IRO with every sub-object type, XRO, SVEC
    f.c2s(msg(PCREQ, [o_rp(1, 20), o_ep4(),
                      o_iro([so_ipv4(0), so_ipv4(0x80, '192.0.2.20', 24), so_ipv6(0), so_ipv6(0x80),
                             so_unnum(0), so_unnum(0x80), so_as(0), so_as(0x80)]),
                      o_svec(3), o_svec(0)]))
    f.c2s(msg(PCREQ, [o_rp(1, 21), o_ep6(),
                      o_iro([so_exrs(0, so_ipv4(0) + so_ipv6(0x80) + so_unnum(0) + so_as_xro(0) + so_srlg(0)),
                             so_exrs(0x80, so_ipv4(0) + so_ipv6(0) + so_unnum(0) + so_as_xro(0) + so_srlg(0)
                                     + bytes([99, 4, 0, 0]))]),
                      o_xro([so_ipv4(0, flags=0), so_ipv4(0x80, flags=1), so_ipv6(0, flags=2), so_ipv6(0x80, flags=0),
                             so_unnum(0), so_unnum(0x80), so_as_xro(0), so_as_xro(0x80, 0, 65500, 1),
                             so_srlg(0), so_srlg(0x80, 5, 2), so_pks4(0), so_pks6(0), bytes([99, 4, 0, 0])])]))
    # BNC (branch node capability) with IPv4, IPv6 and an unknown sub-object
    f.c2s(msg(PCREQ, [o_rp(1, 22), o_ep4p2mp(), o_bnc([so_ipv4(0), so_ipv6(0x80), bytes([99, 4, 0, 0])])]))
    # ---- path computation reply: NO-PATH, ERO, RRO, METRIC, LOAD-BALANCING
    f.s2c(msg(PCREP, [o_rp(0, 10), o_nopath(0, 0x8000, tlv(1, u32(0x81))), o_nopath(1, 0)]))
    ero_subs = [so_ipv4(0), so_ipv4(0x80), so_ipv6(0), so_ipv6(0x80), so_label(0), so_label(0x80, 2, 1, b'\1\2\3\4\5'),
                so_unnum(0), so_unnum(0x80), so_as(0), so_as(0x80), so_pks4(0), bytes([99, 4, 0, 0])]
    f.s2c(msg(PCREP, [o_rp(0, 11), o_ero(ero_subs), o_metric(), o_bandwidth(), o_lb()]))
    rro_subs = [so_ipv4(0, flags=3), so_ipv4(0, flags=0), so_ipv6(0, flags=3), so_label(0, flags=1), so_label(0, 2, 0, flags=0),
                so_unnum(0, b2=3, b3=0x7f), so_unnum(0, b2=0), bytes([99, 4, 0, 0])]
    f.s2c(msg(PCREP, [o_rp(0, 12), o_rro(rro_subs), o_ero([so_ipv4(0)])]))
    # SR ERO and RRO, plus SERO / SRRO
    f.s2c(msg(PCREP, [o_rp(0, 13), o_ero(sr_variants(0) + sr_variants(0x80)[:3])]))
    f.s2c(msg(PCREP, [o_rp(0, 14), o_rro(sr_variants(0))]))
    f.s2c(msg(PCREP, [o_rp(0, 15), o_ero(srv6_variants(0) + srv6_variants(0x80)[:2])]))
    f.s2c(msg(PCREP, [o_rp(0, 16), o_rro(srv6_variants(0))]))
    # SERO / SRRO objects (classes 29 and 30) with IPv4/IPv6/label/unnumbered/AS and SR (not allowed there)
    f.s2c(msg(PCREP, [o_rp(0, 17), o_ero([so_ipv4(0), so_ipv6(0), so_label(0), so_unnum(0), so_as(0),
                                          so_sr(0, 1, 1, LSE, NAI[1]), so_srv6(0, 2, 0, 1, ip6('2001:db8::1'), NAI[2])],
                                         cls=29),
                      o_rro([so_ipv4(0), so_ipv6(0), so_label(0), so_unnum(0), so_sr(0, 1, 1, LSE, NAI[1]),
                             so_srv6(0, 2, 0, 1, ip6('2001:db8::1'), NAI[2])], cls=30)]))
    # sub-objects in objects that do not define them
    f.s2c(msg(PCREP, [o_rp(0, 18), o_rro([so_as(0), so_pks4(0)]), o_iro([so_label(0), so_pks4(0)]),
                      o_xro([so_label(0, 1, 0, b'\0\0\0\1')]), o_pathkey([so_pks4(0), so_ipv4(0)])]))
    # ---- notification / error / close
    f.s2c(msg(PCNTF, [o_rp(0, 1), o_notif(1, 1), o_notif(1, 2), o_notif(2, 1, tlv(2, u32(5))),
                      o_notif(2, 2), o_notif(9, 9)]))
    for chunk in range(0, 32, 8):
        f.c2s(msg(PCERR, [o_err(et, ev) for et in range(chunk, chunk + 8) for ev in (1, 2)]
                  + [o_err(99, 1, tlv(7, u32(1) + b'vendor'))]))
    f.c2s(msg(PCERR, [o_rp(0, 3)] + [o_err(et, 99) for et in (1, 3, 4, 5, 6, 10, 12, 13, 15, 16, 17, 18, 19, 20,
                                                              21, 23, 24, 25, 26, 27, 28, 29, 30, 31)]))
    f.c2s(msg(CLOSE, [o_close(1), o_close(2, tlv(24, b'bye')), o_close(3), o_close(9)]))
    # ---- path computation monitoring
    f.c2s(msg(PCMONREQ, [o_rp(0, 30), o_monitoring(0x1f, 5, tlv(3, u32(5))), o_pccid(False), o_pccid(True),
                         obj(20, 3, b'\0\0\0\0')]))
    f.s2c(msg(PCMONREP, [o_rp(0, 30), o_monitoring(0, 6), o_pceid(False), o_pceid(True), obj(25, 3, b'\0\0\0\0'),
                         o_proctime(1), o_proctime(0), o_overload(), o_unreach(False), o_unreach(True),
                         o_unreach(False, 1)]))
    # ---- stateful: PCRpt, PCUpd, PCInitiate
    f.c2s(msg(PCRPT, [o_srp(0, 0, tlv(28, u8(0, 0, 0, 1))),
                      o_lsp(0x11111, 0xfff, tlv(18, ip4('192.0.2.1') + u16(1, 2) + ip4('192.0.2.1') + ip4('192.0.2.9'))
                            + tlv(17, b'tunnel-1') + tlv(20, u32(3)) + tlv(23, struct.pack('>Q', 1))),
                      o_ero([so_ipv4(0), so_ipv4(0)]), o_rro([so_ipv4(0)]),
                      o_lspa(), o_bandwidth(), o_metric()]))
    f.s2c(msg(PCUPD, [o_srp(1, 4), o_lsp(0x11111, 0x1), o_ero(sr_variants(0)[:3])]))
    f.s2c(msg(PCINIT, [o_srp(1, 5, tlv(28, u8(0, 0, 0, 1))), o_lsp(0, 0x20, tlv(17, b'init')), o_ep4(),
                       o_ero([so_ipv4(0)]), o_lspa(), o_bandwidth(), o_metric()]))
    f.s2c(msg(PCINIT, [o_srp(0, 6, b''), o_lsp(0x22, 0, b'')]))
    # vendor information, BU
    f.s2c(msg(PCUPD, [o_vendor(1234, b'12345678'), o_vendor(5, b''), o_bu()]))
    # TE-PATH-BINDING TLVs (RFC 9604) and the other SR policy TLVs in an LSP
    f.c2s(msg(PCRPT, [o_srp(0, 7), o_lsp(0x33, 0x10, te_path_binding(0, u32(16001 << 12)) +
                                          te_path_binding(1, LSE) + te_path_binding(2, ip6('2001:db8::1')) +
                                          te_path_binding(3, ip6('2001:db8::1') + u32(1)) +
                                          te_path_binding(9, b'abcd') + te_path_binding(0) +
                                          tlv(56, b'polname') + tlv(58, b'cp') + tlv(59, u32(7))),
                      o_ero([so_ipv4(0)])]))
    # path setup type capability with sub-TLVs, PCECC and SR PCE capability, padding and without
    f.s2c(msg(OPEN, [o_open(tlv34([1, 2, 3]) + tlv34([1], subtlv(26, u16(0) + u8(1, 8))) +
                            tlv34([1, 2], subtlv(1, u32(7)) + subtlv(26, u16(0) + u8(3, 16)) + subtlv(99, b'abcdef')) +
                            tlv34([1, 2, 3, 4]) + tlv34([]))]))
    # associations: IPv4/IPv6, assoc types, extended association ids (policy association: type 6)
    c4 = tlv(31, u32(100) + ip4('192.0.2.200'))                    # 8: color + IPv4 endpoint
    c6 = tlv(31, u32(100) + ip6('2001:db8::200'))                  # 20: color + IPv6 endpoint
    cx = tlv(31, b'0123456789')                                    # other length
    f.c2s(msg(PCRPT, [o_srp(0, 8), o_lsp(0x44, 0),
                      o_assoc(6, 1, ip4('192.0.2.1'), c4 + tlv(30, u32(7))),
                      o_assoc(6, 2, ip4('192.0.2.1'), c6),
                      o_assoc(6, 3, ip4('192.0.2.1'), cx),
                      o_assoc(1, 4, ip4('192.0.2.1'), tlv(31, b'abcd')),
                      o_assoc(2, 5, ip6('2001:db8::1'), b'', True, 0),
                      o_assoc(6, 6, ip6('2001:db8::1'), c4, True),
                      o_assoc(6, 6, ip6('2001:db8::1'), b'', True),
                      ]))
    # multipath: PATH-ATTRIB and a few of its TLVs
    f.c2s(msg(PCRPT, [o_srp(0, 9), o_lsp(0x55, 0), o_pathattrib(0xf, tlv(61, u32(5))),
                      o_pathattrib(0x0, b''), o_ero([so_ipv4(0)])]))
    # OP-CONF-ASSOC-RANGE followed by another TLV (reproducer of the OP-CONF-ASSOC-RANGE fix)
    f.c2s(msg(OPEN, [o_open(tlv(29, u16(0, 1, 100, 10)) + tlv(16, u32(1)) + tlv(17, b'NAME'))]))
    f.c2s(msg(OPEN, [o_open(tlv(29, u16(0, 1)) + tlv(16, u32(1)) + tlv(17, b'NAME'))]))
    f.c2s(msg(OPEN, [o_open(tlv(29, u16(0, 1, 100, 10) + u16(0, 2, 7, 3) + u16(0, 3, 9, 1)) + tlv(30, u32(5)))]))
    # objects without a dissector and unknown classes
    f.c2s(msg(PCREQ, [obj(22, 1, u32(3)), obj(24, 1, u32(3)), obj(36, 1, u32(3)), obj(37, 1, u32(3)),
                      obj(38, 1, u32(3)), obj(39, 1, u32(3)), obj(41, 1, u32(3)), obj(42, 1, u32(3)),
                      obj(43, 1, u32(3)), obj(44, 1, u32(3))]))
    f.c2s(msg(PCREQ, [obj(0, 1, u32(3)), obj(18, 1, u32(3)), obj(23, 1, u32(3)), obj(46, 1, u32(3)),
                      obj(200, 1, u32(3), p=1, i=1)]))
    # object P and I flags, reserved bits
    f.c2s(msg(PCREQ, [o_rp(1, 99, b'') and obj(2, 1, u32(1, 99), p=1, i=1, res=3)]))
    # unknown message type, header flags and version
    f.c2s(msg(99, [o_rp(1, 5)], ver=2, flags=0x1f))
    # reassembly: one message over two segments, two messages in one segment
    m = msg(PCREQ, [o_rp(1, 50), o_ep4(), o_bandwidth(), o_metric()])
    f.c2s(m[:10])
    f.c2s(m[10:])
    f.s2c(msg(KEEPALIVE, []) + msg(KEEPALIVE, []))


Z = b'\0' * 32      # zero bytes after the last object, so that the expert items of bad objects fit in the frame


def msgz(mtype, objs, **kw):
    return msg(mtype, list(objs) + [Z], **kw)


def build_malformed(cap):
    f = Flow(cap, 52000)
    # object lengths below the header size
    f.c2s(msgz(PCREQ, [obj(2, 1, u32(1, 1), length=3)]))
    # every object with a body that is too short (error experts)
    for cls, typ in ((1, 1), (2, 1), (3, 1), (4, 1), (4, 2), (5, 1), (6, 1), (9, 1), (11, 1), (12, 1), (13, 1), (14, 1),
                     (15, 1), (17, 1), (19, 1), (20, 1), (20, 2), (21, 1), (25, 1), (25, 2), (26, 1), (27, 1), (32, 1),
                     (33, 1), (34, 1), (35, 1), (40, 1), (40, 2), (45, 1)):
        f.c2s(msgz(PCREQ, [obj(cls, typ, b'\0\0')]))
    f.c2s(msgz(PCREQ, [obj(28, 1, b'\0\0'), obj(28, 2, b'\0' * 10)]))
    # sub-objects with wrong lengths in every carrier
    bad = [u8(1, 4, 0, 0), u8(2, 8, 0, 0, 0, 0, 0, 0), u8(3, 4, 0, 0), u8(4, 8, 0, 0, 0, 0, 0, 0), u8(32, 8, 0, 0, 0, 0, 0, 0),
           u8(34, 4, 0, 0), u8(64, 4, 0, 0), u8(65, 8, 0, 0, 0, 0, 0, 0), u8(36, 4, 0, 0), u8(40, 4, 0, 0), u8(32, 4, 0, 0), u8(32, 6, 0, 0, 0, 0),
           u8(33, 2), u8(7, 3, 0), u8(99, 1), u8(1,)]
    for b in bad:
        for cls in (7, 8, 10, 16, 17, 29, 30, 31):
            f.c2s(msgz(PCREQ, [obj(cls, 1, u16(0, 0) + b if cls == 17 else b)]))
    # EXRS inside an IRO with bad inner objects
    f.c2s(msgz(PCREQ, [obj(10, 1, so_exrs(0, u8(1, 4, 0, 0)) + u8(0, 0))]))
    f.c2s(msgz(PCREQ, [obj(10, 1, u8(33, 4, 0, 0) + u8(1, 1, 1, 1))]))
    f.c2s(msgz(PCREQ, [obj(10, 1, u8(33, 3, 0))]))
    f.c2s(msgz(PCREQ, [obj(10, 1, u8(33, 6, 0, 0, 0, 0) + u8(99, 4, 0, 0))]))
    # sub-object longer than the object, one byte tail
    for cls in (7, 8, 10, 16, 17, 29, 30, 31):
        pre = u16(0, 0) if cls == 17 else b''
        f.c2s(msgz(PCREQ, [obj(cls, 1, pre + so_ipv4(0) + u8(1,)), obj(cls, 1, pre + u8(1, 20) + b'\0' * 6)]))
    # TLV running past the object
    f.c2s(msgz(OPEN, [obj(1, 1, u8(0x20, 30, 120, 1) + u16(17, 100) + b'ab')]))
    f.c2s(msgz(OPEN, [obj(1, 1, u8(0x20, 30, 120, 1) + u16(34, 12) + u8(0, 0, 0, 200) + b'\0' * 8)]))
    # message length beyond the data: TCP waits for the rest, so use a flow of its own
    Flow(cap, 52001).c2s(msgz(PCREQ, [o_rp(1, 1)], length=200))
    # object length larger than the message
    f.c2s(msgz(PCREQ, [obj(2, 1, u32(1, 1), length=60)]))
    # truncated body of several TLVs
    for t in (1, 3, 7, 16, 18, 19, 20, 23, 26, 27, 28, 30, 40, 55, 57, 59, 60, 61):
        f.c2s(msgz(OPEN, [obj(1, 1, u8(0x20, 30, 120, 1) + u16(t, 1) + b'\0\0\0')]))
    # odd-sized lists
    f.c2s(msgz(OPEN, [o_open(tlv(4, u8(1, 2, 3)) + tlv(35, u8(1, 2, 3)) + tlv(29, u8(0) * 7) + tlv(29, b'') +
                            tlv(55, u8(0, 0, 0, 0, 1, 2, 3, 4, 5, 6)))]))
    # SVEC with a trailing partial request id
    f.c2s(msgz(PCREQ, [obj(11, 1, u32(1, 5) + u8(1, 2))]))
    # END-POINTS P2MP with a trailing partial address
    f.c2s(msgz(PCREQ, [obj(4, 3, u32(1) + ip4('192.0.2.1') + ip4('192.0.2.2') + u8(1, 2)),
                      obj(4, 4, u32(1) + ip6('2001:db8::1') + ip6('2001:db8::2') + u8(1, 2))]))
    # unknown association object type (the expert item is longer than what is left)
    f.c2s(msgz(PCREQ, [obj(40, 3, u16(0, 0, 1, 1) + b'abcd')]))
    # SR / SRv6 sub-objects that are too short or have an NAI type that is not defined
    f.c2s(msgz(PCREQ, [obj(7, 1, so_sr(0, 0, 0x00c, b'')), obj(8, 1, so_sr(0, 0, 0x00c, b'')),
                      obj(7, 1, so_srv6(0, 3, 0x000, 7, ip6('2001:db8::1'), b'')),
                      obj(8, 1, so_srv6(0, 3, 0x000, 7, ip6('2001:db8::1'), b''))]))
    # ASSOCIATION with a body shorter than its address
    f.c2s(msgz(PCREQ, [obj(40, 1, u16(0, 0, 1, 1) + ip4('192.0.2.1')[:2])]))


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    c = Cap(); build_main(c); c.write(os.path.join(out, 'pcep-coverage.pcap'))
    m = Cap(); build_malformed(m); m.write(os.path.join(out, 'pcep-coverage-malformed.pcap'))
    print(len(c.pkts), len(m.pkts))

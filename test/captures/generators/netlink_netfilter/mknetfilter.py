#!/usr/bin/env python3
# Generates test/captures/netlink_netfilter_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the netfilter (nfnetlink) coverage captures.

Usage: mknetfilter.py <outdir>
Writes netlink-netfilter-coverage.pcap (LINKTYPE_NETLINK, 253) and
netlink-netfilter-coverage-malformed.pcapng.
Everything is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys

# ---- helpers (pcap/pcapng writers and netlink builders) ----------------
ARPHRD_NETLINK = 824
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_DUMP = 0x300
NLM_F_CREATE = 0x400
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
NETLINK_NETFILTER = 12


def pcap(fn, pkts, linktype=253):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def pcapng(fn, pkts):
    """pkts: list of (linktype, bytes); one interface per link type."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for lt, _ in pkts:
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifs[lt], ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(fn, 'wb') as f:
        f.write(out)


def sll(proto=NETLINK_GENERIC):
    return struct.pack('>HHH8sH', 4, ARPHRD_NETLINK, 0, b'\0' * 8, proto)


class Enc:
    def __init__(self, big=False):
        self.e = '>' if big else '<'

    def attr(self, t, payload=b'', flags=0):
        l = 4 + len(payload)
        return struct.pack(self.e + 'HH', l, t | flags) + payload + b'\0' * ((4 - l % 4) % 4)

    def u8(self, t, v, flags=0):
        return self.attr(t, struct.pack('B', v), flags)

    def u16(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'H', v), flags)

    def u32(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'I', v), flags)

    def u64(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'Q', v), flags)

    def s(self, t, v, flags=0):
        return self.attr(t, v + b'\0', flags)

    def nlmsg(self, mtype, payload, flags=NLM_F_REQUEST, seq=1, pid=0):
        return struct.pack(self.e + 'IHHII', 16 + len(payload), mtype, flags, seq, pid) + payload

    def genl(self, cmd, attrs=b'', version=1):
        return struct.pack(self.e + 'BBH', cmd, version, 0) + attrs

    def frame(self, mtype, cmd, attrs=b'', **kw):
        return sll() + self.nlmsg(mtype, self.genl(cmd, attrs), **kw)


def newfamily(e, fid, name, **kw):
    """CTRL_CMD_NEWFAMILY (1) telling the dissector fid -> name."""
    return e.frame(GENL_ID_CTRL, 1, e.u16(1, fid) + e.s(2, name), **kw)
# ---- end helpers --------------------------------------------------------

def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_udp(sport=5000, dport=5001, data=b'drop-me!'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                    bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + udp


def ipv6_udp(data=b'drop-v6'):
    src, dst = bytes(range(1, 17)), bytes(range(17, 33))
    udp = struct.pack('>HHHH', 5000, 5001, 8 + len(data), 0) + data
    pseudo = src + dst + struct.pack('>IBBBB', len(udp), 0, 0, 0, 17)
    pad = b'\0' if len(udp) % 2 else b''
    udp = udp[:6] + struct.pack('>H', csum(pseudo + udp + pad)) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


def eth(ethertype, payload):
    return bytes.fromhex('020000000002020000000001') + struct.pack('>H', ethertype) + payload



LE = Enc()
BE = Enc(True)
N = NLA_F_NESTED

(SUBSYS_NONE, SUBSYS_CT, SUBSYS_EXP, SUBSYS_QUEUE, SUBSYS_ULOG, SUBSYS_OSF, SUBSYS_IPSET,
 SUBSYS_ACCT, SUBSYS_CTTIMEOUT, SUBSYS_CTHELPER, SUBSYS_NFT, SUBSYS_NFT_COMPAT,
 SUBSYS_HOOK) = range(13)


def b8(v):
    return struct.pack('B', v)


def b16(v):
    return struct.pack('>H', v)


def b32(v):
    return struct.pack('>I', v)


def b32s(v):
    return struct.pack('>i', v)


def b64(v):
    return struct.pack('>Q', v)


def a(t, payload=b'', flags=0, e=LE):
    return e.attr(t, payload, flags)


def ab(t, payload=b'', flags=0):
    """An attribute in big endian byte order (for a whole big endian message)."""
    return BE.attr(t, payload, flags)


def nest(t, *children, e=LE, flags=0):
    return e.attr(t, b''.join(children), N | flags)


def s(t, v, e=LE):
    return e.attr(t, v + b'\0')


def nf(subsys, mtype, attrs=b'', e=LE, family=2, res_id=0, **kw):
    """A message of an nfnetlink subsystem: nlmsghdr, nfgenmsg, attributes."""
    hdr = struct.pack('>BBH', family, 0, res_id)
    return sll(NETLINK_NETFILTER) + e.nlmsg((subsys << 8) | mtype, hdr + attrs, **kw)


IP4A, IP4B = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 7])
IP6A, IP6B = bytes.fromhex('20010db8000000000000000000000001'), bytes.fromhex('20010db8000000000000000000000002')


# ---- conntrack ---------------------------------------------------------
def t_ip4(src=IP4A, dst=IP4B):
    return nest(1, a(1, src), a(2, dst), a(9, b'zz'))


def t_ip6(src=IP6A, dst=IP6B):
    return nest(1, a(3, src), a(4, dst))


def t_proto(num=6, sport=12345, dport=80):
    return nest(2, a(1, b8(num)), a(2, b16(sport)), a(3, b16(dport)), a(4, b16(1)), a(0, b'\0'))


def tuple_attrs(*parts):
    return b''.join(parts)


def ct_attrs():
    orig = nest(1, t_ip4(), t_proto(), a(3, b16(7)), a(9, b'x'))
    reply = nest(2, t_ip6(), t_proto(17, 53, 5353), a(0, b'\0'))
    master = nest(14, t_ip4(IP4B, IP4A), t_proto(1, 0, 0))
    status = a(3, b32(0x0000ffff))
    helper = nest(5, s(1, b'ftp'), a(2, b'\x01\x02\x03'), a(0, b''))
    seq_o = nest(15, a(1, b32(1000)), a(2, b32s(-5)), a(3, b32s(77)), a(0, b''))
    seq_r = nest(16, a(1, b32(2000)), a(2, b32s(5)), a(3, b32s(-77)))
    return (orig + reply + status + a(4, b'\0\0\0\0') + helper + a(7, b32(120)) + a(8, b32(5)) +
            a(12, b32(0x1234)) + master + seq_o + seq_r + a(18, b16(1)) + a(26, b32(0)) +
            a(40, b'?'))


def ct_not_nested():
    """The nested attributes without the nested flag are shown as data."""
    return (a(1, b'\1\2\3\4') + a(5, b'ftp\0') + a(14, b'\1\2\3\4') + a(15, b'\1\2\3\4') +
            nest(1, a(1, b'\1\2\3\4'), a(2, b'\1\2\3\4'), a(3, b'\0\1')))


# ---- expectations --------------------------------------------------------
def exp_attrs():
    return (nest(1, t_ip4(), t_proto()) + nest(2, t_ip4(IP4B, IP4A), t_proto(17, 5, 6)) +
            nest(3, t_ip4(b'\xff' * 4, b'\xff' * 4), t_proto(0xff, 0xffff, 0xffff)) +
            a(4, b32(30)) + a(5, b32(0xabcd)) + s(6, b'ftp') + a(7, b16(3)) +
            a(8, b32(5)) + a(9, b32(2)) + nest(10, a(1, b32(1)), nest(2, t_ip4(), t_proto()), a(3, b'x')) +
            s(11, b'ftp_expect') + a(30, b'x'))


def exp_not_nested():
    return (a(1, b'\1') + a(2, b'\1') + a(3, b'\1') + a(10, b'\1') +
            nest(10, a(2, b'\1\2\3\4')))


# ---- queue -----------------------------------------------------------------
def nfq_packet(hw=0x0800, payload=None, extra=b''):
    if payload is None:
        payload = ipv4_udp()
    return (a(1, struct.pack('>IHB', 77, hw, 1)) + extra + a(10, payload))


def nfq_full():
    return (a(1, struct.pack('>IHB', 77, 0x0800, 1)) + a(3, b32(0x55)) +
            a(4, b64(1700000000) + b64(123456789)) + a(5, b32(2)) + a(6, b32(3)) + a(7, b32(4)) +
            a(8, b32(5)) + a(9, struct.pack('>HH', 6, 0) + bytes.fromhex('020000000001') + b'\0\0') +
            a(12, b32(2)) + a(13, b32(60)) + a(14, b32(1)) + a(15, b'\0\0\0\0') +
            a(16, b32(1000)) + a(17, b32(1001)) + a(18, b'system_u:object_r') +
            a(19, b'\0\0\0\1') + a(20, bytes(14)) + a(21, b32(1)) + a(0, b'') +
            nest(11, a(1, b'\0'), orig_tuple(), a(3, b32(0x1f)), a(7, b32(30))) +
            a(10, ipv4_udp()))


def orig_tuple():
    return nest(1, t_ip4(), t_proto())


# ---- ipset -----------------------------------------------------------------
def cadt_all():
    """Create/list/save data: every attribute type that has a case."""
    return nest(7, nest(1, a(1, IP4A), a(2, IP6A), a(5, b'zz')) +
                nest(2, a(1, IP4B)) + a(3, b8(24)) + a(4, b16(100)) + a(5, b16(200)) +
                a(6, b32(3600)) + a(7, b8(6)) + a(8, b32(0x15)) +
                a(9, b32(1)) + a(10, b32(2)) + a(11, b32(3)) + a(12, b32(4)) +
                a(17, b32(5)) + a(18, b32(1024)) + a(19, b32(65536)) + a(20, b8(24)) +
                a(21, b8(12)) + a(22, b8(1)) + a(23, b32(1)) + a(24, b32(2)) + a(25, b32(1)) +
                a(26, b32(4096)) + a(13, b'x') + a(30, b'x'))


def ipset(cmd, attrs=b'', flags=NLM_F_REQUEST | NLM_F_ACK, **kw):
    return nf(SUBSYS_IPSET, cmd, attrs, flags=flags, **kw)


def adt_data():
    """Add/del/test data: CADT attributes up to 16, the comment and others."""
    return nest(7, nest(1, a(1, IP4A)) + a(3, b8(32)) + a(6, b32(60)) + a(8, b32(1)) +
                s(26, b'a comment') + a(17, b'\1\2\3\4\5\6') + a(18, b'name\0') + a(20, b32(5)) +
                a(30, b'\0'))


# ---- nftables --------------------------------------------------------------
def expr(name, *data, nested=True, name_attr=True, name_first=True):
    d = b''.join(data)
    n_ = s(1, name) if name_attr else b''
    dat = a(2, d, N if nested else 0)
    return nest(1, *( (n_, dat) if name_first else (dat, n_) ))


def nft_data(value=None, verdict=False, t=3):
    parts = []
    if value is not None:
        parts.append(a(1, value))
    if verdict:
        parts.append(nest(2, a(1, b32(1))))
    parts.append(a(0, b'\0'))
    return nest(t, *parts)


def rule(*parts, table=b'filter', chain=b'input'):
    return s(1, table) + s(2, chain) + b''.join(parts)


def exprs(*es):
    return nest(4, *es)


def nft_rule_all():
    es = exprs(
        expr(b'meta', a(1, b32(1)), a(2, b32(3))),                         # meta load mark => reg 1
        expr(b'meta', a(3, b32(2)), a(2, b32(12))),                        # meta set nftrace with reg 2
        expr(b'meta', a(2, b32(99))),                                      # key only, unknown key
        expr(b'meta', a(0, b'')),                                          # unspecified
        expr(b'cmp', a(1, b32(1)), a(2, b32(0)), nft_data(b'\x0a\x00\x00\x01')),
        expr(b'cmp', a(1, b32(1)), a(2, b32(77)), nft_data(bytes(range(12)))),   # long data, unknown op
        expr(b'cmp', a(1, b32(1)), a(2, b32(5)), nft_data(b'\x01\x02')),
        expr(b'cmp', a(1, b32(1)), a(2, b32(4)), nft_data(verdict=True)),  # verdict only: no data
        expr(b'cmp', a(1, b32(1)), a(2, b32(1)), a(3, b'\1\2\3\4'), a(0, b'')),   # data not nested
        expr(b'payload', a(1, b32(1)), a(2, b32(1)), a(3, b32(12)), a(4, b32(4))),     # load
        expr(b'payload', a(5, b32(2)), a(2, b32(2)), a(3, b32(0)), a(4, b32(2))),      # write
        expr(b'payload', a(5, b32(2)), a(2, b32(2)), a(3, b32(16)), a(4, b32(2)),
             a(6, b32(1)), a(7, b32(18)), a(8, b32(1)), a(0, b'')),                   # write with csum
        expr(b'payload', a(1, b32(1)), a(2, b32(9))),                                  # incomplete
        expr(b'immediate', a(1, b32(0)), nft_data(b'\x00\x00\x00\x01', t=2)),
        expr(b'immediate', a(1, b32(0)), nft_data(bytes(range(10)), t=2)),
        expr(b'immediate', a(1, b32(0)), nft_data(verdict=True, t=2)),
        expr(b'immediate', a(0, b''), a(2, b'\1\2\3\4')),                           # data not nested
        expr(b'nat', a(1, b32(0)), a(2, b32(2)), a(3, b32(1)), a(5, b32(2)), a(4, b32(3)),
             a(6, b32(4)), a(7, b32(6))),
        expr(b'nat', a(1, b32(1)), a(2, b32(10)), a(0, b'')),
        expr(b'nat', a(2, b32(2))),                                                    # no type
        expr(b'counter', a(1, b64(5)), a(2, b64(100))),                                # unknown expression
        expr(b'cmp', a(1, b32(1)), name_first=False),                                  # data before name
        expr(b'cmp', a(1, b32(1)), name_attr=False),                                   # no name
        expr(b'cmp', a(1, b32(1)), nested=False),                                      # data not nested
        nest(1, a(7, b'?')),                                                          # no name or data
        a(1, b'\1\2\3'),                                                              # element not nested
        a(2, b'\1'),                                                                  # other list type
    )
    return rule(es, nest(5, a(1, b32(2)), a(2, b32(1)), a(0, b'')),
                a(3, b64(0x1234)), a(6, b64(5)), s(7, b'user data'), a(8, b'\0\0\0\0'),
                a(9, b32(7)), a(10, b32(8)), a(11, b32(9)), a(0, b''))


def main_frames():
    f = []
    # 1: IPSET CREATE, the reproducer of "netlink-netfilter: Fix the IPSET command mask":
    # IPSET_ATTR_DATA{HASHSIZE, MEMSIZE} are decoded as CADT attributes, not as NAME/COMMENT
    f.append(ipset(2, s(2, b'set0') + nest(7, a(18, b32(1024)), a(26, b32(4096)))))
    # 2-9: conntrack
    f.append(nf(SUBSYS_CT, 0, ct_attrs(), flags=NLM_F_REQUEST | NLM_F_ACK))
    f.append(nf(SUBSYS_CT, 1, ct_not_nested()))
    f.append(nf(SUBSYS_CT, 1, ab(3, b32(0x0102)) + ab(7, b32(1)) + ab(12, b32(2)), e=BE, pid=5))
    # 5-8: expectations
    f.append(nf(SUBSYS_EXP, 0, exp_attrs()))
    f.append(nf(SUBSYS_EXP, 1, exp_not_nested()))
    f.append(nf(SUBSYS_EXP, 2, a(8, b32(7)) + a(5, b32(1))))
    f.append(nf(SUBSYS_EXP, 3, b''))
    f.append(nf(SUBSYS_EXP, 4, a(5, b32(1))))
    # 10-19: queue
    f.append(nf(SUBSYS_QUEUE, 0, nfq_full(), family=2, pid=9))
    f.append(nf(SUBSYS_QUEUE, 0, nfq_packet(), pid=9))
    f.append(nf(SUBSYS_QUEUE, 0, nfq_packet(0x86dd, ipv6_udp()), pid=9))
    f.append(nf(SUBSYS_QUEUE, 0, nfq_packet(0x9999, bytes(range(12))), pid=9))
    f.append(nf(SUBSYS_QUEUE, 0, a(10, ipv4_udp()) + a(10, b''), pid=9))          # payload without a header
    f.append(nf(SUBSYS_QUEUE, 1, a(2, struct.pack('>II', 1, 77)) + a(3, b32(9))))
    f.append(nf(SUBSYS_QUEUE, 1, a(2, struct.pack('>II', 3, 78))))
    f.append(nf(SUBSYS_QUEUE, 3, a(2, struct.pack('>II', 1, 79))))
    # queue attributes with the wrong length are skipped
    f.append(nf(SUBSYS_QUEUE, 0, a(1, b'\0' * 6) + a(2, b'\0' * 4) + a(3, b'\0\0') + a(4, b'\0' * 8) +
                a(5, b'\0') + a(6, b'\0') + a(7, b'\0') + a(8, b'\0') + a(9, b'\0\0') + a(12, b'\0') +
                a(13, b'\0') + a(16, b'\0') + a(17, b'\0') + nest(11, a(7, b32(1))), pid=9))
    # HWADDR: address length longer than the attribute; and 6
    f.append(nf(SUBSYS_QUEUE, 0, a(9, struct.pack('>HH', 6, 0) + bytes.fromhex('0200000000aa') + b'\0\0') +
                a(11, b'\0\0\0\0') + a(11, b'\1\2', 0), pid=9))
    f.append(nf(SUBSYS_QUEUE, 0, a(9, struct.pack('>HH', 40, 0) + bytes.fromhex('0200000000aa')), pid=9))
    # queue config: command, params, maxlen, mask, flags, with the wrong length, and unknown
    cfg = (a(1, struct.pack('>BBH', 1, 0, 2)) + a(2, struct.pack('>IB', 0xffff, 2)) +
           a(3, struct.pack('<I', 1024)) + a(4, struct.pack('<I', 0xff)) + a(5, struct.pack('<I', 3)) +
           a(0, b''))
    f.append(nf(SUBSYS_QUEUE, 2, cfg, res_id=3, pid=9))
    f.append(nf(SUBSYS_QUEUE, 2, a(1, b'\1\0') + a(2, b'\0' * 4) + a(3, b'\0\0') + a(4, b'\0') +
                a(5, b'\0\0\0') + a(40, b'x'), pid=9))
    f.append(nf(SUBSYS_QUEUE, 2, ab(3, struct.pack('>I', 1024)) + ab(4, struct.pack('>I', 0xff)) +
                ab(1, struct.pack('>BBH', 1, 0, 2)), e=BE, pid=9))
    f.append(nf(SUBSYS_QUEUE, 2, a(3, struct.pack('>I', 77), NLA_F_NET_BYTEORDER) +
                a(1, struct.pack('>BBH', 1, 0, 2), NLA_F_NET_BYTEORDER), pid=9))
    # 29-31: ulog: a packet (dissected by NFLOG), the config message and no attributes
    ulog = (struct.pack('<HH', 8, 1) + struct.pack('>HBB', 0x0800, 1, 0) +
            struct.pack('<HH', 8, 4) + b32(2) +
            struct.pack('<HH', 10, 10) + b'test: \0\0\0\0\0\0'[:6] + b'\0\0' +
            struct.pack('<HH', 4 + len(ipv4_udp()), 9) + ipv4_udp())
    f.append(nf(SUBSYS_ULOG, 0, ulog, pid=2))
    f.append(nf(SUBSYS_ULOG, 1, a(1, b'\0\0\0\0'), pid=0))
    # 32-45: ipset
    f.append(ipset(1, a(1, b8(7)) + a(10, b8(6))))
    f.append(ipset(2, s(2, b'set1') + s(3, b'hash:ip') + a(4, b8(5)) + a(5, b8(2)) + a(6, b32(1)) +
                   cadt_all()))
    f.append(ipset(7, s(2, b'set1') + a(6, b32(2)) + a(5, b'\0\0') + cadt_all()))
    f.append(ipset(8, s(2, b'set1') + cadt_all(), pid=3))
    f.append(ipset(9, s(2, b'set1') + adt_data(), pid=0))
    f.append(ipset(10, s(2, b'set1') + adt_data()))
    f.append(ipset(11, s(2, b'set1') + adt_data()))
    adt = nest(8, adt_data(), adt_data(), a(7, b'\1\2\3'), nest(9, a(1, b'\1')))
    f.append(ipset(9, s(2, b'set1') + adt + a(9, b32(4)), flags=NLM_F_REQUEST))
    f.append(ipset(3, s(2, b'set1')))
    f.append(ipset(12, s(2, b'set1') + a(7, b'\1\2\3\4') + a(8, b'\1\2\3\4')))                # not nested
    f.append(ipset(13, a(11, b32(5)) + a(10, b32(6)) + a(0, b'') + a(99, b'x')))
    f.append(ipset(14, s(2, b'set1') + a(6, b'\0')))                                        # flags of one byte
    f.append(ipset(2, s(2, b'set2') + nest(7, nest(1, a(1, IP4A)), a(3, b'\0\0'), a(6, b'\0'),
                                              a(8, b'\0\0'), nest(2, a(5, b'x')), a(4, b'\0\0\0\0'))))
    f.append(ipset(5, s(2, b'old') + s(2, b'new')))
    # 46-: nftables
    f.append(nf(SUBSYS_NFT, 6, nft_rule_all(), family=1, flags=NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK))
    # expressions and compat attributes without the nested flag are shown as data
    f.append(nf(SUBSYS_NFT, 6, rule(a(4, b'\1\2\3\4'), a(5, b'\1\2\3\4'))))
    for mt in (7, 8, 25, 28):
        f.append(nf(SUBSYS_NFT, mt, rule(a(3, b64(mt)))))
    f.append(nf(SUBSYS_NFT, 0, s(1, b'filter') + a(2, b32(0))))               # NEWTABLE: attributes not decoded
    f.append(nf(SUBSYS_NFT, 3, s(1, b'filter') + s(3, b'input')))
    # nfnetlink messages of the other subsystems: shown as data
    f.append(nf(SUBSYS_OSF, 0, a(1, b'\1\2\3\4')))
    f.append(nf(SUBSYS_ACCT, 1, s(1, b'acct0')))
    f.append(nf(SUBSYS_CTTIMEOUT, 1, s(1, b'timeout0')))
    f.append(nf(SUBSYS_NFT_COMPAT, 1, s(1, b'compat')))
    f.append(nf(SUBSYS_HOOK, 0, a(1, b'\0\0\0\1')))
    f.append(nf(SUBSYS_NONE, 20, a(1, b'\0\0\0\1')))
    f.append(nf(SUBSYS_ULOG, 0, b''))
    # a message with no attributes, and two messages in one packet
    f.append(nf(SUBSYS_CT, 1, b'', pid=1))
    f.append(sll(NETLINK_NETFILTER) +
             LE.nlmsg((SUBSYS_CT << 8) | 1, struct.pack('>BBH', 2, 0, 0) + a(12, b32(1)), pid=4) +
             LE.nlmsg((SUBSYS_EXP << 8) | 1, struct.pack('>BBH', 2, 0, 0) + a(5, b32(2)), pid=4))
    # control message in the netfilter family
    f.append(sll(NETLINK_NETFILTER) + struct.pack('<IHHII', 20, 3, 2, 9, 0) + struct.pack('<i', 0))
    return f


def malformed():
    f = []
    # Fixed width fields with another length: the field type throws
    bad = [
        (SUBSYS_CT, 1, a(7, b'\0\0')),                       # timeout of 2 bytes
        (SUBSYS_CT, 1, a(12, b'\0')),                        # id of 1 byte
        (SUBSYS_CT, 1, nest(1, nest(1, a(1, b'\1\2')))),     # IPv4 address of 2 bytes
        (SUBSYS_CT, 1, nest(1, nest(1, a(3, b'\1\2')))),     # IPv6 address of 2 bytes
        (SUBSYS_CT, 1, nest(1, nest(2, a(2, b'\1\2\3\4')))), # source port of 4 bytes
        (SUBSYS_CT, 1, nest(1, a(3, b'\1\2\3\4'))),          # zone of 4 bytes
        (SUBSYS_CT, 1, nest(15, a(1, b'\1\2'))),             # seqadj of 2 bytes
        (SUBSYS_CT, 1, nest(15, a(2, b'\1\2'))),
        (SUBSYS_CT, 1, a(3, b'\0\0')),                       # status shorter than 4 bytes: reads the end
        (SUBSYS_EXP, 0, a(4, b'\0\0')),
        (SUBSYS_EXP, 0, a(7, b'\0\0\0\0')),
        (SUBSYS_EXP, 0, a(8, b'\0\0')),
        (SUBSYS_EXP, 0, nest(10, a(1, b'\0'))),
        (SUBSYS_QUEUE, 0, a(9, struct.pack('>HH', 8, 0) + bytes(8))),   # address of 8 bytes
        (SUBSYS_IPSET, 9, nest(7, a(6, b32(1)) + nest(1, a(1, b'\1')))),
        (SUBSYS_IPSET, 2, nest(7, nest(1, a(2, b'\1\2')))),
        (SUBSYS_NFT, 6, rule(a(3, b'\0\0\0\0'))),                        # handle of 4 bytes
        (SUBSYS_NFT, 6, rule(a(6, b'\0'))),
        (SUBSYS_NFT, 6, rule(a(9, b'\0\0'))),
        (SUBSYS_NFT, 6, rule(nest(5, a(1, b'\0\0')))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'meta', a(1, b'\0\0'))))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'cmp', a(2, b64(1)))))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'payload', a(4, b'\0\0'))))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'immediate', a(1, b'\0'))))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'nat', a(1, b'\0'))))),
        (SUBSYS_NFT, 6, rule(exprs(expr(b'nat', a(7, b64(1)))))),
    ]
    for subsys, mtype, attrs in bad:
        f.append((253, nf(subsys, mtype, attrs)))
    # attribute lengths: below the header size, beyond the message, trailing bytes
    f.append((253, nf(SUBSYS_CT, 1, a(12, b32(1)) + struct.pack('<HH', 3, 7) + b'\0\0\0\0')))
    f.append((253, nf(SUBSYS_CT, 1, a(12, b32(1)) + struct.pack('<HH', 400, 7) + b'abcd')))
    f.append((253, nf(SUBSYS_CT, 1, a(12, b32(1)) + b'\0\0')))
    f.append((253, nf(SUBSYS_NFT, 6, rule(struct.pack('<HH', 400, 4) + b'abcd'))))
    # an nfgenmsg header cut short, and a message that ends after it
    f.append((253, sll(NETLINK_NETFILTER) + struct.pack('<IHHII', 18, (SUBSYS_CT << 8) | 1, 1, 1, 0) + b'\x02\x00'))
    f.append((253, sll(NETLINK_NETFILTER) + struct.pack('<IHHII', 17, (SUBSYS_CT << 8) | 1, 1, 1, 0) + b'\x02'))
    # message length field larger than the data, below the header size
    p = struct.pack('>BBH', 2, 0, 0) + a(12, b32(1))
    f.append((253, sll(NETLINK_NETFILTER) + struct.pack('<IHHII', 16 + len(p) + 40, (SUBSYS_CT << 8) | 1, 1, 1, 0) + p))
    f.append((253, sll(NETLINK_NETFILTER) + struct.pack('<IHHII', 8, (SUBSYS_CT << 8) | 1, 1, 1, 0) + p))
    # nesting: an NFQA_CT attribute 100 levels deep (each level nested CT tuple)
    inner = a(1, b32(1))
    for _ in range(100):
        inner = nest(1, inner)
    f.append((253, nf(SUBSYS_QUEUE, 0, nest(11, inner))))
    # an ULOG packet whose NFLOG TLVs are cut short
    f.append((253, nf(SUBSYS_ULOG, 0, struct.pack('<HH', 400, 1) + b'\0\0')))
    f.append((253, nf(SUBSYS_ULOG, 0, struct.pack('<HH', 2, 1))))
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'netlink-netfilter-coverage.pcap'), main_frames())
    pcapng(os.path.join(out, 'netlink-netfilter-coverage-malformed.pcapng'), malformed())


if __name__ == '__main__':
    main()

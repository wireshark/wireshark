#!/usr/bin/env python3
# Generates test/captures/ipv6_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the IPv6 dissector (packet-ipv6.c).

Usage: mkipv6.py <outdir>

Writes ipv6-coverage.pcapng (clean: no malformed packets, no error expert
infos) and ipv6-coverage-malformed.pcapng (paths only malformed or odd input
reaches).  Everything is built with struct; nothing comes from a network.
All addresses are documentation addresses (2001:db8::/32, 192.0.2.0/24).
"""
import socket
import struct
import sys

# ---------------------------------------------------------------- helpers


def a6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def a4(s):
    return socket.inet_aton(s)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def blk(btype, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack('<II', btype, tot) + body + b'\0' * pad + struct.pack('<I', tot)


class Cap:
    """pcapng writer with several interfaces; frames = (ifidx, data, orig)."""

    def __init__(self, linktypes):
        self.linktypes = linktypes
        self.frames = []
        self.notes = []

    def add(self, note, data, iface=0, orig=None):
        self.frames.append((iface, data, orig if orig else len(data)))
        self.notes.append(note)
        return len(self.frames)

    def write(self, path):
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (ifidx, data, orig) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000
            out += blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff,
                                      len(data), orig) + data)
        with open(path, 'wb') as f:
            f.write(out)


ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'
SRC = a6('2001:db8::1')
DST = a6('2001:db8::2')

NXT_HBH, NXT_TCP, NXT_UDP, NXT_V6, NXT_RT, NXT_FRAG, NXT_AH = 0, 6, 17, 41, 43, 44, 51
NXT_ICMP6, NXT_NONE, NXT_DST, NXT_V4 = 58, 59, 60, 4


def ip6(payload, nxt, src=SRC, dst=DST, tc=0, flow=0, hlim=64, plen=None):
    if plen is None:
        plen = len(payload)
    return struct.pack('>IHBB', (6 << 28) | (tc << 20) | flow, plen, nxt, hlim) \
        + src + dst + payload


def eth6(payload, nxt, **kw):
    return ETH + b'\x86\xdd' + ip6(payload, nxt, **kw)


def eth4(payload, proto, ttl=64):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                      a4('192.0.2.1'), a4('192.0.2.2'))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return ETH + b'\x08\x00' + hdr + payload


def l4csum(src, dst, nxt, seg, off):
    pseudo = src + dst + struct.pack('>IBBBB', len(seg), 0, 0, 0, nxt)
    c = csum(pseudo + seg)
    if c == 0:
        c = 0xffff
    return seg[:off] + struct.pack('>H', c) + seg[off + 2:]


def udp(data=b'ipv6-coverage', src=SRC, dst=DST, sport=40000, dport=40001):
    seg = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    return l4csum(src, dst, NXT_UDP, seg, 6)


def icmp6(typ, code, body, src=SRC, dst=DST):
    seg = struct.pack('>BBHI', typ, code, 0, 0) + body
    return l4csum(src, dst, NXT_ICMP6, seg, 2)


def pad_opts(opts, extra=2):
    """Pad an options area to a multiple of 8 (with the 2 header octets)."""
    n = (-(len(opts) + extra)) % 8
    if n == 1:
        opts += b'\x00'
    elif n:
        opts += bytes([1, n - 2]) + bytes(n - 2)
    return opts


def exthdr(nxt, opts):
    opts = pad_opts(opts)
    return struct.pack('>BB', nxt, (len(opts) + 2) // 8 - 1) + opts


def opt(t, data=b''):
    return bytes([t, len(data)]) + data


def hbh(nxt, opts):
    return exthdr(nxt, opts)


def dst_opts(nxt, opts):
    return exthdr(nxt, opts)


def rt(nxt, rtype, segleft, body):
    """Routing header; body is the type specific data after the 4 octets."""
    body += bytes((-len(body) - 4) % 8)
    return struct.pack('>BBBB', nxt, (len(body) + 4) // 8 - 1, rtype, segleft) + body


def frag(nxt, off, more, ident, data):
    return struct.pack('>BBHI', nxt, 0, (off & 0xfff8) | (1 if more else 0), ident) + data


def NAT64(pfx, plen, v4=a4('192.0.2.33')):
    """RFC 6052 layout of an IPv4 address in a /plen prefix."""
    b = bytearray(16)
    b[:len(pfx)] = pfx
    if plen == 96:
        b[12:16] = v4
    elif plen == 64:
        b[9:13] = v4
    elif plen == 56:
        b[7] = v4[0]
        b[9:12] = v4[1:]
    elif plen == 48:
        b[6:8] = v4[:2]
        b[9:11] = v4[2:]
    elif plen == 40:
        b[5:8] = v4[:3]
        b[9] = v4[3]
    elif plen == 32:
        b[4:8] = v4
    return bytes(b)


# ------------------------------------------------------------ main capture

U = udp()
LL = a6('fe80::1')
LL2 = a6('fe80::2')


def build_main():
    c = Cap([1, 252, 0, 101])
    add = c.add

    # --- basic header fields ---
    add('UDP over IPv6, traffic class 0, flow label 0', eth6(U, NXT_UDP))
    add('DSCP EF, ECN ECT(1), flow label 0xabcde, hop limit 1',
        eth6(U, NXT_UDP, tc=0xb9, flow=0xabcde, hlim=1))
    add('DSCP CS6, ECN CE', eth6(U, NXT_UDP, tc=0xc3, flow=1))
    add('TCP-less: no next header with payload', eth6(b'\x01\x02\x03\x04', NXT_NONE))
    add('Unknown next header 253 (experimental)', eth6(b'\x01\x02\x03\x04', 253))
    add('ICMPv6 echo reply',
        eth6(icmp6(129, 0, b'\x00\x01\x00\x01abcdefgh'), NXT_ICMP6))

    # --- addresses ---
    def addr_frame(note, src, dst, nxt=NXT_UDP):
        s, d = a6(src), a6(dst)
        add(note, eth6(udp(src=s, dst=d), NXT_UDP, src=s, dst=d))

    addr_frame('link-local unicast to all-nodes multicast (scope 2)', 'fe80::1', 'ff02::1')
    addr_frame('SLAAC (modified EUI-64) source and destination', 'fe80::211:22ff:fe33:4455',
               'fe80::211:22ff:fe33:4466')
    addr_frame('6to4 source and destination', '2002:c000:204:1::1', '2002:c633:6401:2::2')
    addr_frame('Teredo source and destination', '2001:0:4136:e378:8000:63bf:3fff:fdd2',
               '2001:0:4136:e378:8000:63bf:3fff:fdd3')
    addr_frame('ISATAP source and destination', 'fe80::5efe:c000:201', '2001:db8::200:5efe:c633:6402')
    addr_frame('NAT64 well-known prefix destination', '2001:db8::1', '64:ff9b::c000:221')
    addr_frame('NAT64 well-known prefix source', '64:ff9b::c633:6405', '2001:db8::2')
    addr_frame('unique local unicast', 'fd00::1', 'fd12:3456:789a::2')
    addr_frame('loopback destination', '::1', '::1')
    addr_frame('unspecified source, solicited-node multicast (flags 0, scope 2)',
               '::', 'ff02::1:ff00:2')
    addr_frame('IPv4-mapped destination', '2001:db8::1', '::ffff:192.0.2.1')
    addr_frame('reserved by IETF (4000::/3 range) and 3000::', '4000::1', '3000::1')
    addr_frame('multicast scope 5 site-local, transient flag (ff15::)', 'fe80::1', 'ff15::1234')
    addr_frame('multicast with P flag (ff3e::/32 SSM)', '2001:db8::1', 'ff3e:40:2001:db8::8000:1')
    addr_frame('multicast with R, P and T flags (embedded RP, ff7e::)', '2001:db8::1',
               'ff7e:240:2001:db8:1:1::1')
    addr_frame('multicast with the reserved flag bit (ff8e::) and organization scope (ff08::)',
               '2001:db8::1', 'ff8e::1')
    addr_frame('multicast scope 1 / 3 / 4 / 0xe', '2001:db8::1', 'ff01::2')
    addr_frame('multicast source address (warning)', 'ff02::5', '2001:db8::2')
    for note, s, d in [
        ('special purpose: benchmarking 2001:2::/48', '2001:2::1', '2001:2:0:1::2'),
        ('special purpose: ORCHIDv2 2001:20::/28', '2001:20::1', '2001:2f::2'),
        ('special purpose: IETF protocol assignments 2001::/23', '2001:1::1', '2001:1::2'),
        ('special purpose: discard-only 100::/64', '100::1', '100::2'),
        ('special purpose: SRv6 SIDs 5f00::/16', '5f00::1', '5f00::2'),
        ('special purpose: 64:ff9b:1::/48 local-use translation', '64:ff9b:1::1', '64:ff9b:1::2'),
        ('special purpose: AMT 2001:3::/32 and AS112 2620:4f:8000::/48', '2001:3::1', '2620:4f:8000::1'),
        ('special purpose: Direct Delegation 2001:4:112::/48, 2002::/16 6to4', '2001:4:112::1',
         '2002::1'),
    ]:
        addr_frame(note, s, d)

    # NAT64 network-specific prefixes (decoded only with a NAT64_NSP_list, see runcov.sh)
    nat64 = NAT64
    for plen, pfx in ((32, bytes.fromhex('2a001111')), (40, bytes.fromhex('2a00222233')),
                      (48, bytes.fromhex('2a0033334444')), (56, bytes.fromhex('2a004444555566')),
                      (64, bytes.fromhex('2a00555566667777')),
                      (96, bytes.fromhex('2a0066667777888899990000'))):
        d = nat64(pfx, plen)
        add('NAT64 address with a /%d prefix and 192.0.2.33 embedded (decoded with a NAT64 prefix list)' % plen,
            eth6(udp(dst=d), NXT_UDP, dst=d))

    # --- extension headers: hop-by-hop options ---
    add('HBH: Router Alert (MLD) and Pad1 padding', eth6(hbh(NXT_UDP, opt(5, b'\x00\x00') + b'\x00') + U, NXT_HBH))
    add('HBH: Router Alert RSVP, then PadN', eth6(hbh(NXT_UDP, opt(5, b'\x00\x01') + opt(1, b'\0\0\0')) + U, NXT_HBH))
    add('HBH: Path MTU option (min 1280, returned 1500, R flag)',
        eth6(hbh(NXT_UDP, opt(0x30, struct.pack('>HH', 1280, 1500 | 1))) + U, NXT_HBH))
    add('HBH: Quick-Start rate request (rate 10, QS TTL 60, nonce)',
        eth6(hbh(NXT_UDP, opt(0x26, bytes([0x0a, 60]) + struct.pack('>I', 0x12345678))) + U, NXT_HBH, hlim=61))
    add('HBH: Quick-Start rate report (rate 5)',
        eth6(hbh(NXT_UDP, opt(0x26, bytes([0x85, 0]) + struct.pack('>I', 0x9abcdef0))) + U, NXT_HBH))
    add('HBH: Quick-Start with an unassigned function (0xf0)',
        eth6(hbh(NXT_UDP, opt(0x26, bytes([0xf0, 0]) + struct.pack('>I', 0))) + U, NXT_HBH))
    add('HBH: CALIPSO with a two-word compartment bitmap',
        eth6(hbh(NXT_UDP, opt(7, struct.pack('>IBBH', 1, 2, 5, 0xbeef) + bytes(range(8)))) + U, NXT_HBH))
    add('HBH: CALIPSO without compartment bitmap',
        eth6(hbh(NXT_UDP, opt(7, struct.pack('>IBBH', 2, 0, 1, 0x1234))) + U, NXT_HBH))
    add('HBH: SMF_DPD H-DPD mode (hash assist value)',
        eth6(hbh(NXT_UDP, opt(8, b'\x81\x02\x03\x04')) + U, NXT_HBH))
    add('HBH: SMF_DPD I-DPD mode, tagger id (type 1, 3 octets) and identifier',
        eth6(hbh(NXT_UDP, opt(8, b'\x12\xaa\xbb\xcc\xdd\xee')) + U, NXT_HBH))
    add('HBH: SMF_DPD I-DPD mode, default tagger, identifier only',
        eth6(hbh(NXT_UDP, opt(8, b'\x00\x01\x02\x03\x04')) + U, NXT_HBH))
    add('HBH: RPL option (0x63, deprecated type), flags O R F',
        eth6(hbh(NXT_UDP, opt(0x63, bytes([0xe0, 7]) + struct.pack('>H', 256))) + U, NXT_HBH))
    add('HBH: RPL option (0x23)',
        eth6(hbh(NXT_UDP, opt(0x23, bytes([0x40, 1]) + struct.pack('>H', 512))) + U, NXT_HBH))
    for s, n in ((0, 0), (1, 2), (2, 8), (3, 16)):
        add('HBH: MPL option, seed-id length code %d' % s,
            eth6(hbh(NXT_UDP, opt(0x6d, bytes([(s << 6) | 0x30, 9]) + bytes(range(0x20, 0x20 + n)))) + U, NXT_HBH))
    add('HBH: IP_DFF option (0xee)',
        eth6(hbh(NXT_UDP, opt(0xee, bytes([0x40, 0x12, 0x34]))) + U, NXT_HBH))
    add('HBH: IOAM option with a bad type 7 (unknown IOAM type)',
        eth6(hbh(NXT_UDP, opt(0x31, bytes([0, 7]) + bytes(6))) + U, NXT_HBH))

    # IOAM
    def ioam_trace(ns, nodelen, flags, remlen, ttype, body, ioamtype=0):
        return opt(0x31, bytes([0, ioamtype]) + struct.pack('>HHI', ns,
                   (nodelen << 11) | (flags << 7) | remlen, ttype << 8) + body)
    add('HBH: IOAM pre-allocated trace, trace type 0xc00000 (hop limit/node id, interface ids), '
        '2 nodes and free space',
        eth6(hbh(NXT_UDP, ioam_trace(1, 2, 0, 1, 0xc00000, bytes(4) + bytes(range(16)))) + U, NXT_HBH))
    add('HBH: IOAM incremental trace, type 0x3c0000 (timestamps, transit delay, namespace data)',
        eth6(hbh(NXT_UDP, ioam_trace(2, 4, 3, 0, 0x3c0000, bytes(range(16)) + bytes(range(16, 32)), 1)) + U, NXT_HBH))
    # all defined and undefined trace type bits, wide fields, one node, opaque state snapshot
    node = bytes(range(100))
    oss = bytes([1]) + b'\x00\x00\x07' + b'\xde\xad\xbe\xef'
    add('HBH: IOAM trace with all trace type bits, one node of 100 octets, opaque state snapshot',
        eth6(hbh(NXT_UDP, ioam_trace(3, 25, 0xf, 0, 0xfffffe, node + oss)) + U, NXT_HBH))
    add('HBH: IOAM trace, only the opaque state snapshot bit, empty snapshot',
        eth6(hbh(NXT_UDP, ioam_trace(4, 0, 0, 0, 0x000002, bytes([0]) + b'\x00\x00\x01')) + U, NXT_HBH))
    add('HBH: IOAM trace, trace type 0x100000 (timestamp fraction not set, bit 3 only), 1 node',
        eth6(hbh(NXT_UDP, ioam_trace(5, 1, 0, 0, 0x100000, bytes(4))) + U, NXT_HBH))
    add('HBH: IOAM wide fields (trace type bits 8, 9, 10) and buffer occupancy (bit 11)',
        eth6(hbh(NXT_UDP, ioam_trace(6, 7, 0, 0, 0x00f000, bytes(range(28)))) + U, NXT_HBH))
    add('HBH: IOAM proof of transit', eth6(hbh(NXT_UDP, opt(0x31, bytes([0, 2]) + bytes(8))) + U, NXT_HBH))
    add('HBH: IOAM edge to edge', eth6(hbh(NXT_UDP, opt(0x31, bytes([0, 3]) + bytes(8))) + U, NXT_HBH))
    add('HBH: IOAM direct export with flow id and sequence number',
        eth6(hbh(NXT_UDP, opt(0x31, bytes([0, 4]) + struct.pack('>HBBI', 9, 0, 0xc0, 0xfc0000 << 8)
                              + struct.pack('>II', 77, 88))) + U, NXT_HBH))
    add('HBH: IOAM direct export without optional fields',
        eth6(hbh(NXT_UDP, opt(0x31, bytes([0, 4]) + struct.pack('>HBBI', 9, 0, 0, 0))) + U, NXT_HBH))
    # Jumbogram: plen 0, jumbo payload 70000, frame truncated by the snap length
    jh = hbh(NXT_NONE, opt(0xc2, struct.pack('>I', 70000)))
    jp = ip6(jh + b'\xaa' * 32, NXT_HBH, plen=0)
    add('HBH: jumbo payload option, jumbogram of 70000 octets cut by the snap length',
        ETH + b'\x86\xdd' + jp, orig=14 + 40 + 70000)
    jh = hbh(NXT_NONE, bytes(2) + opt(0xc2, struct.pack('>I', 65536)))
    add('HBH: Pad1, Pad1 and jumbo payload option, smallest jumbogram (65536 octets) cut by the snap length',
        ETH + b'\x86\xdd' + ip6(jh + b'\x55' * 16, NXT_HBH, plen=0), orig=14 + 40 + 65536)

    # --- destination options ---
    add('DST: Tunnel Encapsulation Limit 4', eth6(dst_opts(NXT_UDP, opt(4, b'\x04')) + U, NXT_DST))
    add('DST: PDM option', eth6(dst_opts(NXT_UDP, opt(0x0f, bytes([3, 4]) + struct.pack('>HHHH', 1, 2, 3, 4))) + U, NXT_DST))
    add('DST: Home Address option', eth6(dst_opts(NXT_UDP, opt(0xc9, a6('2001:db8:1::99'))) + U, NXT_DST))
    add('DST: Line-Identification option "line-01"',
        eth6(dst_opts(NXT_UDP, opt(0x8c, bytes([7]) + b'line-01')) + U, NXT_DST))
    add('DST: Line-Identification option, Line ID length beyond the option',
        eth6(dst_opts(NXT_UDP, opt(0x8c, bytes([9]) + b'abc')) + U, NXT_DST))
    add('DST: TPF information option', eth6(dst_opts(NXT_UDP, opt(0x41, b'\x00\x00\x00\x2a')) + U, NXT_DST))
    add('DST: APN6 option, 32-bit APN ID',
        eth6(dst_opts(NXT_UDP, opt(0x13, bytes([1, 0x80]) + struct.pack('>HI', 5, 0x11223344))) + U, NXT_DST))
    add('DST: APN6 option, 64-bit APN ID',
        eth6(dst_opts(NXT_UDP, opt(0x13, bytes([2, 0]) + struct.pack('>HII', 6, 1, 2))) + U, NXT_DST))
    add('DST: APN6 option, 128-bit APN ID',
        eth6(dst_opts(NXT_UDP, opt(0x13, bytes([3, 0]) + struct.pack('>HIIII', 7, 1, 2, 3, 4))) + U, NXT_DST))
    for t, n in ((0x1e, 'Experimental 0x1E'), (0x3e, '0x3E'), (0x5e, '0x5E'), (0x7e, '0x7E'),
                 (0x9e, '0x9E'), (0xbe, '0xBE'), (0xde, '0xDE'), (0xfe, '0xFE')):
        add('DST: experimental option %s' % n,
            eth6(dst_opts(NXT_UDP, opt(t, b'\x01\x02\x03\x04')) + U, NXT_DST))
    add('DST: unknown option 0x2f and deprecated Endpoint Identification (0x8a)',
        eth6(dst_opts(NXT_UDP, opt(0x2f, b'\x01\x02\x03\x04') + opt(0x8a, b'\x05\x06')) + U, NXT_DST))
    add('Chain: HBH, destination options, routing, destination options, UDP',
        eth6(hbh(NXT_DST, opt(5, b'\0\0')) + dst_opts(NXT_RT, opt(4, b'\x05'))
             + rt(NXT_DST, 2, 1, bytes(4) + a6('2001:db8::2')) + dst_opts(NXT_UDP, b'') + udp(), NXT_HBH))

    # ILNP nonce
    add('DST: ILNP nonce option (reaches the ILNP dissector)',
        eth6(dst_opts(NXT_UDP, opt(0x8b, b'\x11\x22\x33\x44')) + U, NXT_DST))
    add('DST: ILNP nonce option with an 8 octet nonce',
        eth6(dst_opts(NXT_UDP, opt(0x8b, b'\x11\x22\x33\x44\x55\x66\x77\x88')) + U, NXT_DST))

    # reproducer: option beyond octet 255 decoded shorter than its length
    # RPL option (0x63) with 12 octets of data in a hop-by-hop header at offset 258;
    # the trailing 8 octets look like a Router Alert option and must not be decoded as one.
    trail = bytes([0x05, 0x02, 0x12, 0x34]) + bytes([0x01, 2, 0, 0])
    big = opt(1, bytes(254)) + opt(0x63, bytes([0x80, 1]) + struct.pack('>H', 100) + trail)
    add('REPRODUCER HBH: RPL option at offset 258 with trailing data (opt_start was uint8_t)',
        eth6(hbh(NXT_UDP, big) + U, NXT_HBH))

    # --- routing headers ---
    addrs = [a6('2001:db8:a::1'), a6('2001:db8:a::2')]
    final = addrs[-1]
    add('Routing type 0 (deprecated), 2 addresses, 2 segments left',
        eth6(rt(NXT_UDP, 0, 2, bytes(4) + b''.join(addrs)) + udp(dst=final), NXT_RT))
    add('Routing type 0, 1 address, 0 segments left',
        eth6(rt(NXT_UDP, 0, 0, bytes(4) + addrs[0]) + U, NXT_RT))
    add('Routing type 0 with a multicast address',
        eth6(rt(NXT_UDP, 0, 1, bytes(4) + a6('ff02::9')) + udp(dst=a6('ff02::9')), NXT_RT))
    home = a6('2001:db8:b::7')
    add('Routing type 2 (Mobile IPv6), home address',
        eth6(rt(NXT_UDP, 2, 1, bytes(4) + home) + udp(dst=home), NXT_RT))
    add('Routing type 2 with a multicast home address',
        eth6(rt(NXT_UDP, 2, 1, bytes(4) + a6('ff0e::3')) + udp(dst=a6('ff0e::3')), NXT_RT))

    def rpl(cmpri, cmpre, pad, reserved, addrbytes, segleft, nxt=NXT_UDP):
        w = (cmpri << 28) | (cmpre << 24) | (pad << 20) | reserved
        return rt(nxt, 3, segleft, struct.pack('>I', w) + addrbytes)
    pfx = a6('2001:db8::2')
    add('Routing type 3 (RPL), CmprI 12, CmprE 12, 4 addresses of 4 octets',
        eth6(rpl(12, 12, 0, 0, bytes(range(1, 17)), 4) + udp(dst=pfx[:12] + bytes([13, 14, 15, 16])), NXT_RT))
    add('Routing type 3 (RPL), CmprI 14, CmprE 15, pad 1, 4 addresses',
        eth6(rpl(14, 15, 1, 0, bytes([0xa1, 0xa2, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0x00]), 2) + udp(dst=pfx[:15] + b'\xd1'), NXT_RT))
    add('Routing type 3 (RPL), CmprI 0, CmprE 0, 2 full addresses, 0 segments left',
        eth6(rpl(0, 0, 0, 0, a6('2001:db8:c::1') + a6('2001:db8:c::2'), 0) + U, NXT_RT))
    add('Routing type 3 (RPL) with an empty address list (length 0)',
        eth6(rt(NXT_UDP, 3, 0, struct.pack('>I', 0)) + U, NXT_RT))
    add('Routing type 3 (RPL) listing the destination, the source and a multicast address',
        eth6(rpl(0, 0, 0, 0, DST + SRC + a6('ff02::2') + DST, 0) + U, NXT_RT))
    add('Routing type 3 (RPL) with non-zero pad and reserved bits and CmprI = CmprE = 0',
        eth6(rt(NXT_UDP, 3, 0, struct.pack('>I', (0 << 28) | (0 << 24) | (3 << 20) | 0x5) + a6('2001:db8:d::1') + a6('2001:db8:d::2')) + U, NXT_RT))

    seg = [a6('2001:db8:5::%x' % i) for i in (1, 2, 3)]

    def srh(nxt, last, segleft, segs, tlvs=b'', flags=0, tag=0x1234):
        return rt(nxt, 4, segleft, struct.pack('>BBH', last, flags, tag) + b''.join(segs) + tlvs)
    add('Routing type 4 (SRH), 3 segments, 2 left',
        eth6(srh(NXT_UDP, 2, 2, seg) + udp(dst=seg[0]), NXT_RT))
    add('Routing type 4 (SRH), 1 segment, 0 left, flags and tag',
        eth6(srh(NXT_UDP, 0, 0, seg[:1], flags=0x40, tag=0xbeef) + U, NXT_RT))
    hmac = bytes([5, 22]) + struct.pack('>HI', 0x8000, 0xcafe) + bytes(range(16))
    add('Routing type 4 (SRH) with TLVs: Pad1, PadN, HMAC, experimental 124',
        eth6(srh(NXT_UDP, 1, 1, seg[:2], tlvs=bytes([0]) + bytes([4, 3, 0, 0, 0]) + hmac
                 + bytes([124, 2, 9, 9])) + udp(dst=seg[0]), NXT_RT))
    add('Routing type 4 (SRH) with an unknown TLV 253 and a HMAC TLV of length 6',
        eth6(srh(NXT_UDP, 0, 1, seg[:1], tlvs=bytes([253, 2, 1, 2]) + bytes([5, 6])
                 + struct.pack('>HI', 0, 1)) + udp(dst=seg[0]), NXT_RT))
    add('Routing type 4 (SRH) with a HMAC TLV of 7 octets',
        eth6(srh(NXT_UDP, 0, 1, seg[:1], tlvs=bytes([5, 7]) + bytes(2) + bytes(4) + b'\x99') + udp(dst=seg[0]), NXT_RT))
    add('Routing type 4 (SRH) with a PadN TLV of 0 octets and an unknown TLV 200 without data',
        eth6(srh(NXT_UDP, 0, 1, seg[:1], tlvs=bytes([4, 0]) + bytes([200, 0]) + bytes([0, 0, 0, 0])) + udp(dst=seg[0]), NXT_RT))
    # CRH
    add('Routing type 5 (CRH-16): 4 SIDs and a zero terminator, 3 segments left',
        eth6(rt(NXT_UDP, 5, 3, struct.pack('>HHHHHH', 0x11, 0x22, 0x33, 0x44, 0, 0)) + U, NXT_RT))
    add('REPRODUCER Routing type 5 (CRH-16): all SIDs non-zero, header ends after the last SID',
        eth6(struct.pack('>BBBB', NXT_UDP, 0, 5, 1) + struct.pack('>HH', 0x1111, 0x2222) + U, NXT_RT))
    add('REPRODUCER Routing type 6 (CRH-32): the only SID is non-zero',
        eth6(struct.pack('>BBBB', NXT_UDP, 0, 6, 0) + struct.pack('>I', 0x11111111) + U, NXT_RT))
    add('Routing type 6 (CRH-32): 3 SIDs, 2 segments left',
        eth6(rt(NXT_UDP, 6, 2, struct.pack('>III', 0x100, 0x200, 0x300)) + U, NXT_RT))
    add('Routing type 5 (CRH-16) followed by UDP, second reproducer shape',
        eth6(struct.pack('>BBBB', NXT_UDP, 0, 5, 1) + struct.pack('>HH', 0x1111, 0x2222) + U, NXT_RT))
    add('Routing type 1 (Nimrod, undecoded)', eth6(rt(NXT_UDP, 1, 0, bytes(12)) + U, NXT_RT))
    add('Routing type 253 (experiment 1, undecoded)', eth6(rt(NXT_UDP, 253, 0, bytes(4)) + U, NXT_RT))

    # --- fragmentation ---
    data = bytes(range(48))
    dg = udp(data)
    f1, f2, f3 = dg[:24], dg[24:48], dg[48:]
    add('Fragment 1 of 3 (offset 0, more) of a UDP datagram', eth6(frag(NXT_UDP, 0, True, 0x1001, f1), NXT_FRAG))
    add('Fragment 3 of 3 (offset 48, last), out of order', eth6(frag(NXT_UDP, 48, False, 0x1001, f3), NXT_FRAG))
    add('Fragment 2 of 3 (offset 24, more): reassembly completes',
        eth6(frag(NXT_UDP, 24, True, 0x1001, f2), NXT_FRAG))
    dg2 = udp(bytes(range(100, 140)))
    add('Atomic fragment (offset 0, no more fragments)', eth6(frag(NXT_UDP, 0, False, 0x2002, dg2), NXT_FRAG))
    # fragmentable part holds a destination options header and UDP
    inner = dst_opts(NXT_UDP, opt(4, b'\x02')) + udp(bytes(range(60, 100)))
    add('Fragments with a hop-by-hop header before the fragment header, first fragment',
        eth6(hbh(NXT_FRAG, opt(5, b'\0\0')) + frag(NXT_DST, 0, True, 0x3003, inner[:32]), NXT_HBH))
    add('Same datagram, last fragment',
        eth6(hbh(NXT_FRAG, opt(5, b'\0\0')) + frag(NXT_DST, 32, False, 0x3003, inner[32:]), NXT_HBH))
    # a second datagram of the same address pair with a different identification, interleaved
    dg4 = udp(bytes(range(200, 240)))
    add('Interleaved datagram 0x4004, first fragment', eth6(frag(NXT_UDP, 0, True, 0x4004, dg4[:24]), NXT_FRAG))
    add('Interleaved datagram 0x5005, first fragment', eth6(frag(NXT_UDP, 0, True, 0x5005, dg4[:24]), NXT_FRAG))
    add('Interleaved datagram 0x4004, last fragment', eth6(frag(NXT_UDP, 24, False, 0x4004, dg4[24:]), NXT_FRAG))
    add('Interleaved datagram 0x5005, last fragment', eth6(frag(NXT_UDP, 24, False, 0x5005, dg4[24:]), NXT_FRAG))
    add('Last fragment without its first fragment (never completes)',
        eth6(frag(NXT_UDP, 64, False, 0x6006, bytes(range(16))), NXT_FRAG))
    add('Fragment header with the reserved octet and reserved bits set (atomic)',
        eth6(struct.pack('>BBHI', NXT_UDP, 0x55, 0x0006, 0x7007) + dg2, NXT_FRAG))

    # --- tunnels and other carriers ---
    inner6 = ip6(U, NXT_UDP, src=a6('2001:db8:aa::1'), dst=a6('2001:db8:aa::2'))
    add('IPv6 in IPv6 (next header 41)', eth6(inner6, NXT_V6))
    inner4 = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(U), 1, 0, 64, NXT_UDP, 0,
                         a4('198.51.100.1'), a4('198.51.100.2'))
    inner4 = inner4[:10] + struct.pack('>H', csum(inner4)) + inner4[12:] + U
    add('IPv4 in IPv6 (next header 4)', eth6(inner4, NXT_V4))
    add('IPv6 in IPv4 (protocol 41)', eth4(inner6, 41))
    add('Destination options carried in IPv4 (protocol 60): the data argument is not an IPv6 header',
        eth4(dst_opts(NXT_UDP, opt(4, b'\x02')) + U, 60))
    add('Routing header carried in IPv4 (protocol 43)',
        eth4(rt(NXT_UDP, 2, 1, bytes(4) + home) + U, 43))
    add('Fragment header carried in IPv4 (protocol 44), single atomic fragment',
        eth4(frag(NXT_UDP, 0, False, 0x8008, U), 44))
    add('ICMPv6 destination unreachable carrying a truncated IPv6 packet (payload length exceeds the data)',
        eth6(icmp6(1, 4, ip6(U[:8], NXT_UDP, src=SRC, dst=DST, plen=len(U) + 100), src=DST, dst=SRC),
             NXT_ICMP6, src=DST, dst=SRC))
    add('AH after the IPv6 header (placeholder ICV)',
        eth6(struct.pack('>BBHII', NXT_UDP, 4, 0, 0x100, 1) + bytes(12) + U, NXT_AH))

    # --- IPv6 in GTP-U, reached through the IP heuristic dissector (dissect_ipv6_heur) ---
    def gtpu(inner):
        g = struct.pack('>BBHI', 0x30, 0xff, len(inner), 0x1234) + inner
        u = struct.pack('>HHHH', 2152, 2152, 8 + len(g), 0) + g
        return eth4(u, 17)
    add('GTP-U T-PDU carrying an IPv6 packet', gtpu(ip6(U, NXT_UDP)))

    # --- Exported PDU frames (interface 1): reproducer for the NULL data argument ---
    def tlv(t, v):
        return struct.pack('>HH', t, len(v)) + v
    for rtype in (0, 2, 3, 4, 5, 6):
        tags = tlv(14, b'ipv6.routing.type') + tlv(32, struct.pack('>I', rtype)) \
            + tlv(22, SRC) + tlv(23, DST) + tlv(0, b'')
        c.add('REPRODUCER Exported PDU: routing type %d dissector called with NULL data' % rtype,
              tags + bytes(range(1, 41)), iface=1)

    # --- other link types ---
    nullhdr = struct.pack('<I', 24)  # BSD AF_INET6
    c.add('DLT_NULL (BSD loopback) with IPv6', nullhdr + ip6(U, NXT_UDP), iface=2)
    c.add('DLT_RAW with IPv6 and a hop-by-hop header', ip6(hbh(NXT_UDP, opt(5, b'\0\0')) + U, NXT_HBH), iface=3)
    return c


# -------------------------------------------------------- malformed capture

def build_malformed():
    c = Cap([1, 252, 0, 101])
    add = c.add

    def gtpu(inner):
        g = struct.pack('>BBHI', 0x30, 0xff, len(inner), 0x1234) + inner
        u = struct.pack('>HHHH', 2152, 2152, 8 + len(g), 0) + g
        return eth4(u, 17)
    nat64 = NAT64

    # These two only work on the very first option lookup of a process:
    # ipv6_opt_type_hdr() keeps its table pointer in a static variable.
    # (PadN also goes through the lookup and would use the table up, so pad with Pad1.)
    add('Option header mismatch: Tunnel Encapsulation Limit in hop-by-hop options',
        eth6(bytes([NXT_UDP, 0]) + opt(4, b'\x01') + bytes(3) + U, NXT_HBH))
    add('Option header mismatch: Router Alert in destination options',
        eth6(bytes([NXT_UDP, 0]) + opt(5, b'\x00\x00') + bytes(2) + U, NXT_DST))
    ub = bytearray(nat64(bytes.fromhex('2a00555566667777'), 64))
    ub[8] = 1
    add('NAT64 /64 address with a non-zero u octet (with a NAT64 prefix list)',
        eth6(udp(dst=bytes(ub)), NXT_UDP, dst=bytes(ub)))
    for plen, pfx in ((32, '2a001111'), (40, '2a00222233'), (48, '2a0033334444')):
        ub = bytearray(nat64(bytes.fromhex(pfx), plen))
        ub[8] = 1
        add('NAT64 /%d address with a non-zero u octet (with a NAT64 prefix list)' % plen,
            eth6(udp(dst=bytes(ub)), NXT_UDP, dst=bytes(ub)))
    ub = bytearray(nat64(bytes.fromhex('2a004444555566'), 56))
    ub[8] = 1
    add('NAT64 /56 address with a non-zero u octet (with a NAT64 prefix list)',
        eth6(udp(dst=bytes(ub)), NXT_UDP, dst=bytes(ub)))
    add('GTP-U T-PDU carrying IPv6 with a hop-by-hop header (reported as not first: the previous layer is IP)',
        gtpu(ip6(hbh(NXT_UDP, opt(5, b'\0\0')) + U, NXT_HBH)))
    add('GTP-U T-PDU with an IPv6 version nibble but a payload length that does not match',
        gtpu(ip6(U, NXT_UDP, plen=len(U) - 4)))
    add('GTP-U T-PDU of 6 octets starting with version 6 (too short for the IPv6 heuristic)',
        gtpu(bytes([0x60, 0, 0, 0, 0, 0])))
    add('IPv6 version 4 in an ethertype 0x86dd frame', ETH + b'\x86\xdd' + bytes([0x45]) + bytes(39))
    add('Frame shorter than the IPv6 header (20 octets)', ETH + b'\x86\xdd' + ip6(b'', NXT_UDP)[:20])
    add('Payload length 0 with next header UDP', eth6(U, NXT_UDP, plen=0))
    add('Payload length 0 with hop-by-hop header but no jumbo option',
        eth6(hbh(NXT_UDP, opt(1, b'\0\0')) + U, NXT_HBH, plen=0))
    add('Payload length larger than the frame', eth6(U, NXT_UDP, plen=len(U) + 100))
    add('Payload length 0 and a hop-by-hop header cut after one octet (no room for the jumbo search)',
        ETH + b'\x86\xdd' + ip6(bytes([NXT_NONE]), NXT_HBH, plen=0))
    add('Payload length 0, Pad1 and a jumbo option of 100 (not above 65535)',
        eth6(hbh(NXT_UDP, bytes(1) + opt(0xc2, struct.pack('>I', 100))) + U, NXT_HBH, plen=0))
    add('Payload length 0, jumbo option of length 5 (not recognised by the search)',
        eth6(hbh(NXT_UDP, opt(0xc2, struct.pack('>IB', 70000, 0))) + U, NXT_HBH, plen=0))
    add('Payload length not 0, jumbo option with a length below 65536',
        eth6(hbh(NXT_UDP, opt(0xc2, struct.pack('>I', 100))) + U, NXT_HBH))
    add('Payload length 0 and jumbo option of 70000, jumbo payload length smaller than 65536 follows a fragment header',
        ETH + b'\x86\xdd' + ip6(hbh(NXT_FRAG, opt(0xc2, struct.pack('>I', 70000))) + frag(NXT_UDP, 0, False, 1, U[:16]), NXT_HBH, plen=0),
        orig=14 + 40 + 70000)
    add('Jumbo option with length 3', eth6(hbh(NXT_UDP, opt(0xc2, b'\0\0\1')) + U, NXT_HBH))
    add('Hop-by-hop header after a destination options header (not first)',
        eth6(dst_opts(NXT_HBH, b'') + hbh(NXT_UDP, opt(5, b'\0\0')) + U, NXT_DST))
    # reproducers
    add('REPRODUCER Line-Identification option with length 0',
        eth6(dst_opts(NXT_UDP, bytes([0x8c, 0])) + struct.pack('>HHHH', 40000, 9, 8 + 12, 0) + b'XXXXXXXXXXXX', NXT_DST))
    tel = bytes([0x04, 17, 0x07]) + bytes([0x05, 0x02, 0x12, 0x34]) + bytes([0x01, 10]) + bytes(10)
    add('REPRODUCER TEL option with length 17 at offset 2 (control)', eth6(dst_opts(NXT_NONE, tel), NXT_DST))
    add('REPRODUCER TEL option with length 17 at offset 258 (opt_start was uint8_t)',
        eth6(dst_opts(NXT_NONE, bytes([1, 254]) + bytes(254) + tel), NXT_DST))
    hb = struct.pack('>BB', NXT_NONE, 1) + opt(0x26, bytes([0x05, 50]) + struct.pack('>I', 0x12345678)) + opt(1, bytes(4))
    add('REPRODUCER Hop-by-hop with Quick-Start carried in IPv4 protocol 0 (data is an IPv4 header)', eth4(hb, 0))
    add('REPRODUCER Hop-by-hop with Quick-Start in IPv6 (control)', eth6(hb, NXT_HBH))
    # CRH reproducer in malformed shape: SID loop used to read one SID past the end
    add('CRH-16 with all SIDs non-zero, payload after it',
        eth6(struct.pack('>BBBB', NXT_UDP, 0, 5, 1) + struct.pack('>HH', 0x1111, 0x2222) + U, NXT_RT))
    add('CRH-16 with a large segments-left value (minimum length exceeds header length)',
        eth6(rt(NXT_UDP, 5, 30, struct.pack('>HHHH', 1, 2, 0, 0)) + U, NXT_RT))
    add('CRH-32 with segments-left 9 (minimum length exceeds header length)',
        eth6(rt(NXT_UDP, 6, 9, struct.pack('>II', 1, 2)) + U, NXT_RT))
    # Exported PDU with other table values
    def tlv(t, v):
        return struct.pack('>HH', t, len(v)) + v
    for rtype in (0, 2, 3, 4, 5, 6):
        tags = tlv(14, b'ipv6.routing.type') + tlv(32, struct.pack('>I', rtype)) \
            + tlv(22, SRC) + tlv(23, DST) + tlv(0, b'')
        c.add('REPRODUCER Exported PDU routing type %d, NULL data' % rtype, tags + bytes(range(1, 41)), iface=1)

    # option errors
    for name, o in [
        ('TEL length 2', opt(4, b'\x01\x02')),
        ('Router Alert length 4', opt(5, bytes(4))),
        ('PMTU length 2', bytes([0x30, 2, 0x05, 0x00])),
        ('QS length 8', opt(0x26, bytes([0x0a, 1]) + bytes(6))),
        ('RPL length 2', bytes([0x63, 2, 0xe0, 1]) + bytes(4)),
        ('TPF length 2', opt(0x41, bytes(2))),
        ('PDM length 4', opt(0x0f, bytes(4))),
        ('Home Address length 8', opt(0xc9, bytes(8)) + bytes(8)),
        ('DFF length 4', opt(0xee, bytes(4))),
        ('CALIPSO length 4', opt(7, bytes(4))),
        ('APN6 length 4, invalid ID type 0', opt(0x13, bytes([0, 0, 0, 1])) + bytes(4)),
        ('APN6 invalid ID type 4', opt(0x13, bytes([4, 0, 0, 1]) + bytes(4))),
        ('APN6 64-bit ID, length too small', opt(0x13, bytes([2, 0, 0, 1]) + bytes(4))),
        ('APN6 128-bit ID, length too small', opt(0x13, bytes([3, 0, 0, 1]) + bytes(8))),
        ('MPL with source seed id (code 0)', opt(0x6d, bytes([0x30, 1]))),
        ('IOAM length 0', bytes([0x31, 0]) + bytes(8)),
        ('IOAM trace with invalid RemLen and length 10', opt(0x31, bytes([0, 0]) + struct.pack('>HHI', 1, (2 << 11) | 20, 0xc00000 << 8))),
        ('IOAM trace with node length 0 and trace type 0xc00000', opt(0x31, bytes([0, 0]) + struct.pack('>HHI', 1, 0, 0xc00000 << 8) + bytes(4))),
        ('IOAM trace, node data does not match the trace type', opt(0x31, bytes([0, 0]) + struct.pack('>HHI', 1, (1 << 11), 0xc00000 << 8) + bytes(4))),
        ('IOAM trace, trailing octets after the nodes', opt(0x31, bytes([0, 1]) + struct.pack('>HHI', 1, (1 << 11), 0x800000 << 8) + bytes(6))),
        ('IOAM trace, opaque state snapshot missing', opt(0x31, bytes([0, 1]) + struct.pack('>HHI', 1, 0, 0x000002 << 8) + bytes(0))),
        ('IOAM trace, opaque state snapshot data too short', opt(0x31, bytes([0, 1]) + struct.pack('>HHI', 1, 0, 0x000002 << 8) + bytes([5, 0, 0, 1]))),
        ('IOAM trace, opaque state snapshot header cut', opt(0x31, bytes([0, 1]) + struct.pack('>HHI', 1, (1 << 11), 0x800002 << 8) + bytes(5))),
        ('IOAM direct export length 4', opt(0x31, bytes([0, 4, 0, 1]))),
        ('IOAM length 1', bytes([0x31, 1, 0])),
    ]:
        dstonly = name.split()[0] in ('TEL', 'PDM', 'Home', 'TPF')
        add('Option error: ' + name, eth6(dst_opts(NXT_UDP, o) + U, NXT_DST) if dstonly else eth6(hbh(NXT_UDP, o) + U, NXT_HBH))

    # routing header errors
    add('Routing type 0 with odd header length',
        eth6(struct.pack('>BBBB', NXT_UDP, 1, 0, 1) + bytes(12) + U, NXT_RT))
    add('Routing type 0, segments left larger than the address count',
        eth6(rt(NXT_UDP, 0, 5, bytes(4) + a6('2001:db8::5')) + U, NXT_RT))
    add('Routing type 2 with length 4 and segments left 2',
        eth6(struct.pack('>BBBB', NXT_UDP, 3, 2, 2) + bytes(4) + a6('2001:db8::5') + bytes(16) + U, NXT_RT))
    add('Routing type 3 (RPL) with CmprI 15, pad 15 and length 1 (negative address count)',
        eth6(rt(NXT_UDP, 3, 0, struct.pack('>I', (15 << 28) | (0 << 24) | (15 << 20)) + bytes(4)) + U, NXT_RT))
    add('Routing type 3 (RPL) carried in IPv4 (no IPv6 addresses)',
        eth4(rt(NXT_UDP, 3, 0, struct.pack('>I', 0) + a6('2001:db8::7')) + U, 43))
    mc = a6('ff02::77')
    add('Routing type 3 (RPL) with a multicast IPv6 destination address',
        eth6(rt(NXT_UDP, 3, 0, struct.pack('>I', 0) + a6('2001:db8::7')) + udp(dst=mc), NXT_RT, dst=mc))
    add('Routing type 3 (RPL), segments left larger than the address count',
        eth6(rt(NXT_UDP, 3, 9, struct.pack('>I', 0) + a6('2001:db8::7') + a6('2001:db8::8')) + U, NXT_RT))
    add('Routing type 4 (SRH), segments left larger than the segment count',
        eth6(rt(NXT_UDP, 4, 7, struct.pack('>BBH', 0, 0, 0) + a6('2001:db8::7')) + U, NXT_RT))
    srhseg = a6('2001:db8:5::1')
    add('SRH whose last octet is a TLV type (truncated TLV header)',
        eth6(rt(NXT_UDP, 4, 1, struct.pack('>BBH', 0, 0, 0) + srhseg + bytes(7) + bytes([0xfc])), NXT_RT))
    add('SRH with a TLV length that exceeds the header',
        eth6(rt(NXT_UDP, 4, 1, struct.pack('>BBH', 0, 0, 0) + srhseg + bytes([250, 40, 1, 2])) + U, NXT_RT))
    add('SRH with a HMAC TLV shorter than 6 octets (3 and 0)',
        eth6(rt(NXT_UDP, 4, 1, struct.pack('>BBH', 0, 0, 0) + srhseg + bytes([5, 3, 1, 2, 3]) + bytes([5, 0])) + U, NXT_RT))
    add('Routing header with undecoded type 100 and total length beyond the packet',
        eth6(struct.pack('>BBBB', NXT_UDP, 9, 100, 0) + bytes(20), NXT_RT))

    # fragments
    dg = udp(bytes(range(48)))
    add('Overlapping fragments with conflicting data, first',
        eth6(frag(NXT_UDP, 0, True, 0xa001, dg[:32]), NXT_FRAG))
    add('Overlapping fragments with conflicting data, second',
        eth6(frag(NXT_UDP, 24, False, 0xa001, b'\xff' * 32), NXT_FRAG))
    add('Fragment header carrying a jumbo payload', ETH + b'\x86\xdd' + ip6(
        hbh(NXT_FRAG, opt(0xc2, struct.pack('>I', 70000))) + frag(NXT_UDP, 8, True, 3, bytes(16)), NXT_HBH, plen=0),
        orig=14 + 40 + 70000)
    add('Fragment cut short (header incomplete)', eth6(bytes([NXT_UDP, 0, 0, 1]), NXT_FRAG))
    add('Hop-by-hop header longer than the packet', eth6(bytes([NXT_UDP, 9, 1, 2, 0, 0, 0, 0]), NXT_HBH))
    add('Option running beyond the extension header', eth6(bytes([NXT_UDP, 0, 0x2f, 20, 0, 0, 0, 0]), NXT_HBH))
    add('Unknown next header after option with data cut',
        eth6(dst_opts(NXT_UDP, opt(0xc9, a6('2001:db8:1::99'))[:12]), NXT_DST)[:14 + 40 + 8 + 4])
    add('CRH-32 whose current SID lies beyond the header', eth6(struct.pack('>BBBB', NXT_UDP, 0, 6, 9) + struct.pack('>I', 5), NXT_RT))
    add('RPL with address data cut short', eth6(struct.pack('>BBBB', NXT_UDP, 1, 3, 1) + struct.pack('>I', 0) + bytes(3), NXT_RT))
    add('Teredo / SLAAC / 6to4 truncated: IPv6 header cut after the source address',
        (ETH + b'\x86\xdd' + ip6(b'', NXT_UDP))[:14 + 40 - 8])
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    m = build_main()
    m.write(out + '/ipv6-coverage.pcapng')
    b = build_malformed()
    b.write(out + '/ipv6-coverage-malformed.pcapng')
    with open(out + '/ipv6-frames.txt', 'w') as f:
        for i, n in enumerate(m.notes, 1):
            f.write('%d: %s\n' % (i, n))
        f.write('--- malformed\n')
        for i, n in enumerate(b.notes, 1):
            f.write('%d: %s\n' % (i, n))
    print(len(m.frames), len(b.frames))

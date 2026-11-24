#!/usr/bin/env python3
# Generates test/captures/ipsec_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-ipsec.c (AH, ESP, IPComp).

Usage: mkipsec.py <outdir> [-v]

Writes ipsec-coverage.pcapng (clean: no malformed frames) and
ipsec-coverage-malformed.pcapng.  Everything is built with struct; the
ESP "payloads" are placeholder bytes (plain inner packets, constant 0xA5
ICV bytes).  There is no real key, ciphertext or ICV anywhere.  The only
key text is the all-zero placeholder in the TWOFISH regression SA.
"""
import struct
import sys
import zlib
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

# ---------------------------------------------------------------- pcapng
def blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)

def shb():
    return blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

def idb(linktype=1):
    return blk(1, struct.pack('<HHI', linktype, 0, 65535))

def dsb(stype, data):
    return blk(0x0000000A, struct.pack('<II', stype, len(data)) + data)

class Cap:
    def __init__(self):
        self.blocks = []
        self.n = 0
        self.ts = 1700000000 * 1000000
        self.marks = []

    def raw(self, b):
        self.blocks.append(b)

    def mark(self, text):
        self.marks.append((self.n + 1, text))

    def pkt(self, p, caplen=None, ifid=0):
        self.n += 1
        self.ts += 1000
        cl = len(p) if caplen is None else caplen
        data = p[:cl]
        self.blocks.append(blk(6, struct.pack('<IIIII', ifid, self.ts >> 32,
                               self.ts & 0xffffffff, cl, len(p)) + data))

    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(b''.join(self.blocks))
        if VERBOSE:
            print(name, self.n, 'frames')
            for i, (n, t) in enumerate(self.marks):
                end = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else self.n
                print('  %d-%d  %s' % (n, end, t))

# ---------------------------------------------------------------- headers
M1 = b'\x02\x00\x00\x00\x00\x01'
M2 = b'\x02\x00\x00\x00\x00\x02'
A1 = b'\xc0\x00\x02\x01'
A2 = b'\xc0\x00\x02\x02'
A3 = b'\xc6\x33\x64\x05'   # 198.51.100.5
V1 = bytes.fromhex('20010db8000000000000000000000001')
V2 = bytes.fromhex('20010db8000000000000000000000002')
V3 = bytes.fromhex('fd000000000000000000000000000009')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(proto, payload, src=A1, dst=A2, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nxt, payload, src=V1, dst=V2):
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, 64) + src + dst + payload

def eth4(p, src=M1, dst=M2):
    return dst + src + b'\x08\x00' + p

def eth6(p, src=M1, dst=M2):
    return dst + src + b'\x86\xdd' + p

def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0x1234) + data   # checksum never verified

def tcp(sport, dport, data, seq=1000, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 8192, 0, 0) + data

def icmp_echo(data=b'ping-placeholder'):
    b = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + data
    return b[:2] + struct.pack('!H', csum(b)) + b[4:]

def icmp6_echo(data=b'ping6'):
    return struct.pack('!BBHHH', 128, 0, 0, 1, 1) + data

UDPD = udp(40000, 9, b'hello esp placeholder')
UDPD6 = udp(40000, 9, b'hello esp placeholder')[:6] + b'\x12\x34' + udp(40000, 9, b'hello esp placeholder')[8:]
TCPD = tcp(40001, 9, b'GET-LIKE PLACEHOLDER')

def v4(proto, payload, **kw):
    return eth4(ip4(proto, payload, **kw))

def v6(nxt, payload, **kw):
    return eth6(ip6(nxt, payload, **kw))

# ---------------------------------------------------------------- AH / ESP / IPComp
def ah(nxt, icv_len, spi, seq, inner, length_field=None):
    # length field = (header length in 32-bit words) - 2
    hdr = 12 + icv_len
    lf = hdr // 4 - 2 if length_field is None else length_field
    return struct.pack('!BBHII', nxt, lf, 0, spi, seq) + b'\xa5' * icv_len + inner

def esp(spi, seq, body):
    return struct.pack('!II', spi, seq) + body

def esp_plain(spi, seq, inner, nxt, icv_len=0, pad='rfc', align=4):
    """Plain (NULL encryption) ESP payload: inner + padding + trailer + ICV
    (constant placeholder bytes)."""
    n = (-(len(inner) + 2)) % align
    if pad == 'rfc':
        padb = bytes(range(1, n + 1))
    elif pad == 'zero':
        padb = b'\0' * n
    elif pad == 'any':
        padb = bytes((0x55 + i) & 0xff for i in range(n))
    else:
        padb = pad
        n = len(padb)
    return esp(spi, seq, inner + padb + bytes([n, nxt]) + b'\xa5' * icv_len)

def ipcomp(nxt, cpi, body, flags=0):
    return struct.pack('!BBH', nxt, flags, cpi) + body

def deflate_raw(b):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(b) + c.flush()

# ---------------------------------------------------------------- IKE (for UDP-encap frames)
def ike_hdr():
    return (b'\x11' * 8 + b'\x00' * 8 + struct.pack('!BBBBII', 0, 0x20, 34, 0x08, 0, 28))

# ---------------------------------------------------------------- SA table (DSB, NULL algorithms only)
NULLA = 'NULL'
A96 = 'ANY 96 bit authentication [no checking]'
A64 = 'ANY 64 bit authentication [no checking]'
A128 = 'ANY 128 bit authentication [no checking]'
A192 = 'ANY 192 bit authentication [no checking]'
A256 = 'ANY 256 bit authentication [no checking]'

def sa(proto, src, dst, spi, enc=NULLA, ekey='', auth=NULLA, akey='', sn='32-bit', up='0'):
    return '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' % (
        proto, src, dst, spi, enc, ekey, auth, akey, sn, up)

SAS = [
    sa('IPv4', '192.0.2.1', '192.0.2.2', '0x4000'),
    sa('IPv4', '192.0.2.*', '*', '0x4001', auth=A96),
    sa('IPv4', '192.0.2.0/24', '192.0.2.2/32', '0x4002', auth=A128),
    sa('IPv4', '*', '*', '0x0000403*', auth=A64),
    sa('IPv4', '*', '*', '16644', auth=A192),         # decimal SPI 0x4104
    sa('IPv4', '*', '*', '0x4005', auth=A256),
    sa('IPv4', '*', '*', '0x4006', auth=A96, sn='64-bit', up='1'),
    sa('IPv4', '10.1.2.3', '10.4.5.6', '0x4007'),
    sa('IPv6', '2001:db8::1', '2001:db8::2', '0x4100'),
    sa('IPv6', '2001:db8::/32', '*', '0x4101', auth=A96),
    sa('IPv6', '*', '*', '0x4102', auth=A128),
    sa('IPv6', '2001:0db8:0000:0000:0000:0000:0000:0001', 'fd00::/8', '0x4103'),
    sa('Any', '*', '*', '0x4200'),
    sa('Any', '*', '*', '0x4201', auth=A96),
    # filters that never match: odd octet counts, wildcards in the middle, empty octets, over-long octets,
    # masks without a number or not on a nibble boundary, short IPv6 groups
    sa('IPv4', '192.*.2.1', '*', '0x4300'),
    sa('IPv4', '19255.0.2.1', '*', '0x4301'),
    sa('IPv4', '192.0.2', '*', '0x4302'),
    sa('IPv4', '192..2.1', '*', '0x4303'),
    sa('IPv4', '192.0.2.1/', '*', '0x4304'),
    sa('IPv4', '192.0.2.1/30', '*', '0x4305'),
    sa('IPv6', 'db8::1', '*', '0x4306'),
    sa('IPv6', ':1:2', '*', '0x4307'),
    sa('IPv6', '2001:db8::/', '*', '0x4308'),
    sa('IPv6', '2001:db8::/30', '*', '0x4309'),
    # valid key strings that are never used (NULL algorithms): odd number of hex digits, empty "0x", plain text
    sa('IPv4', '*', '*', '0x4310', ekey='0x123', akey='0xabc', auth=A96),
    sa('IPv4', '*', '*', '0x4311', ekey='0x', akey='0x', auth=A96),
    sa('IPv4', '*', '*', '0x4312', ekey='placeholder text', akey='placeholder text', auth=A96),
]

def build_main():
    c = Cap()
    c.raw(shb())
    c.raw(dsb(0x45535053, ''.join(SAS).encode() + b'\0'))
    # --- regression SAs, see the README (all three SPIs are unique)
    # 1. DSB that is not NUL-terminated (heap over-read in the callback)
    c.raw(dsb(0x45535053, b'"IPv4","*","*","0x7777","NULL","","NULL","","32-bit","0"X'))
    # 2. IPv6 filter with 5-digit groups (stack buffer overflow in get_ipv6_suffix)
    flt = ':1:' + ':'.join(['11111'] * 6)
    c.raw(dsb(0x45535053, ('"IPv6","%s","*","0x7778","NULL","","NULL","","32-bit","0"\n' % flt).encode() + b'\0'))
    # 3. TWOFISH-CBC SA (placeholder all-zero key text)
    c.raw(dsb(0x45535053, ('"IPv4","*","*","0x7779","TWOFISH-CBC","0x%s","NULL","","32-bit","0"\n' % ('00' * 16)).encode() + b'\0'))
    # SA records whose key does not parse: the loader rejects the record and stops reading that block,
    # so each one has its own block (the "keys" are not keys, only invalid hex text)
    for bad in (dict(ekey='0xG'), dict(ekey='0xG1'), dict(ekey='0x1G2'), dict(ekey='0x123G'), dict(akey='0x1G', auth=A96), dict(akey='0xG', auth=A96)):
        c.raw(dsb(0x45535053, sa('IPv4', '*', '*', '0x4320', **bad).encode() + b'\0'))
    c.raw(idb())
    c.raw(idb(252))      # Exported PDU

    # ---- AH
    c.mark('AH over IPv4: ICV 12/16/0/4/8/24 octets, next headers UDP, TCP, ICMP, IPv4, IPv6, IPComp, unknown (data), none')
    c.pkt(v4(51, ah(17, 12, 0x1111, 1, UDPD)))
    c.pkt(v4(51, ah(6, 16, 0x1111, 2, TCPD)))
    c.pkt(v4(51, ah(1, 12, 0x1111, 3, icmp_echo())))
    c.pkt(v4(51, ah(17, 0, 0x1111, 4, UDPD)))
    c.pkt(v4(51, ah(17, 4, 0x1111, 5, UDPD)))
    c.pkt(v4(51, ah(4, 12, 0x1111, 6, ip4(17, UDPD, src=A3, dst=A2))))
    c.pkt(v4(51, ah(41, 12, 0x1111, 7, ip6(17, UDPD6))))
    c.pkt(v4(51, ah(17, 8, 0x1111, 8, UDPD)))
    c.pkt(v4(51, ah(108, 12, 0x1111, 9, ipcomp(17, 2, deflate_raw(UDPD)))))
    c.pkt(v4(51, ah(253, 12, 0x1111, 10, b'experimental placeholder')))
    c.pkt(v4(51, ah(59, 12, 0x1111, 11, b'')))            # AH without payload, next header 'none'
    c.pkt(v4(51, ah(17, 24, 0xffffffff, 0xffffffff, UDPD)))  # long ICV, max SPI/sequence
    c.mark('AH over IPv6: UDP, TCP, ICMPv6, unknown next header')
    c.pkt(v6(51, ah(17, 12, 0x1112, 1, UDPD6)))
    c.pkt(v6(51, ah(6, 16, 0x1112, 2, TCPD)))
    c.pkt(v6(51, ah(58, 12, 0x1112, 3, icmp6_echo())))
    c.pkt(v6(51, ah(253, 12, 0x1112, 4, b'experimental placeholder')))

    # ---- IPComp
    c.mark('IPComp: DEFLATE (raw, zlib-wrapped, UDP and unknown next header), LZS and OUI (not inflated), unknown CPI, flags, empty, IPv6')
    c.pkt(v4(108, ipcomp(17, 2, deflate_raw(UDPD * 4))))
    c.pkt(v4(108, ipcomp(17, 2, zlib.compress(UDPD * 4))))
    c.pkt(v4(108, ipcomp(6, 2, deflate_raw(TCPD), flags=0x80)))
    c.pkt(v4(108, ipcomp(253, 2, deflate_raw(b'compressed experimental payload' * 3))))
    c.pkt(v4(108, ipcomp(17, 3, b'\xff' * 12)))
    c.pkt(v4(108, ipcomp(17, 1, b'\xff\xfe\xfd\xfcoui placeholder')))
    c.pkt(v4(108, ipcomp(17, 0x1234, b'\xde\xad\xbe\xef')))
    c.pkt(v4(108, ipcomp(17, 2, b'')))
    c.pkt(v6(108, ipcomp(17, 2, deflate_raw(UDPD6 * 4))))
    c.pkt(v6(108, ipcomp(58, 2, deflate_raw(icmp6_echo(b'x' * 40)))))

    # ---- First ESP frames: they must come first. get_full_ipv4_addr() and
    # get_full_ipv6_addr() cut a "/mask" off the SA's filter string in place
    # while evaluating it, so a masked filter only works for the first
    # packet that evaluates it (see the README).
    c.mark('First ESP frames, masked SA filters (192.0.2.0/24 and 2001:db8::/32) that match only while the mask is still in the filter string')
    c.pkt(v4(50, esp_plain(0x4002, 100, TCPD, 6, 16)))
    c.pkt(v6(50, esp_plain(0x4101, 100, UDPD6, 17, 12)))
    # ---- ESP sequence analysis (default preferences)
    c.mark('ESP sequence analysis, SPI 0x5000: in order, a gap, a repeat, a number below the expected one, wrap to 0')
    for seq in (1, 2, 3, 5, 5, 4, 5, 6, 7, 0xffffffff, 0, 1):
        c.pkt(v4(50, esp(0x5000, seq, b'\x11\x22\x33\x44' * 4)))
    c.mark('ESP sequence analysis, SPI 0x5001 interleaved with SPI 0x5002, IPv6 SPI 0x5003 and an ESP header without payload')
    c.pkt(v4(50, esp(0x5001, 100, b'\x00' * 8)))
    c.pkt(v4(50, esp(0x5002, 7, b'\x00' * 8)))
    c.pkt(v4(50, esp(0x5001, 101, b'\x00' * 8)))
    c.pkt(v4(50, esp(0x5002, 9, b'\x00' * 8)))
    c.pkt(v6(50, esp(0x5003, 1, b'\x00' * 12)))
    c.pkt(v6(50, esp(0x5003, 3, b'\x00' * 12)))
    c.pkt(v4(50, esp(0x5004, 1, b'')))
    c.pkt(v4(50, esp(0x5004, 2, b'')))

    # ---- NULL encryption heuristic (needs -o esp.enable_null_encryption_decode_heuristic:TRUE)
    c.mark('NULL-encrypted ESP (heuristic): ICV 12, 16, 24, 32 octets; inner UDP, TCP, ICMP, IPv4, IPv6, ICMPv6; padding 0..3')
    s = 0x6000
    for i, icv in enumerate((12, 16, 24, 32)):
        c.pkt(v4(50, esp_plain(s, 1 + i, UDPD, 17, icv)))
    c.pkt(v4(50, esp_plain(s, 5, TCPD, 6, 12)))
    c.pkt(v4(50, esp_plain(s, 6, icmp_echo(), 1, 12)))
    c.pkt(v4(50, esp_plain(s, 7, ip4(17, UDPD, src=A3), 4, 16)))
    c.pkt(v4(50, esp_plain(s, 8, ip6(17, UDPD6), 41, 12)))
    c.pkt(v4(50, esp_plain(s, 9, icmp6_echo(), 58, 12)))
    for n in range(4):
        c.pkt(v4(50, esp_plain(s, 10 + n, UDPD + b'x' * n, 17, 12)))
    c.pkt(v6(50, esp_plain(0x6001, 1, UDPD6, 17, 12)))
    c.pkt(v6(50, esp_plain(0x6001, 2, TCPD, 6, 16)))
    c.pkt(v4(50, esp_plain(0x6004, 1, b'\x45' * 24, 36, 12)))      # XTP rejects it: the heuristic fails
    c.mark('NULL-encrypted ESP: non-RFC padding (all zero, other bytes), no ICV, next header without dissector, pad length too large, packet too short')
    c.pkt(v4(50, esp_plain(0x6002, 1, UDPD, 17, 12, pad='zero', align=16)))
    c.pkt(v4(50, esp_plain(0x6002, 2, UDPD, 17, 12, pad='any', align=16)))
    c.pkt(v4(50, esp_plain(0x6002, 3, UDPD, 17, 12, pad=b'\x01\x02\x07')))
    c.pkt(v4(50, esp(0x6002, 4, b'\xfd' * 24)))
    c.pkt(v4(50, esp_plain(0x6002, 5, b'opaque inner', 253, 12)))
    c.pkt(v4(50, esp(0x6002, 6, b'\xfd' * 6 + bytes([200, 17]) + b'\xfd' * 12)))
    c.pkt(v4(50, esp(0x6002, 7, b'\xfd' * 4)))

    # ---- SA table (NULL algorithms), needs the decryption/authentication preferences
    c.mark('SA table: IPv4 exact, wildcard, masked (no longer matches, see README), wildcard/decimal SPI, ICV lengths 12/16/8/24/32, ESN; payload with NULL encryption')
    c.pkt(v4(50, esp_plain(0x4000, 1, UDPD, 17, 0)))
    c.pkt(v4(50, esp_plain(0x4001, 1, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4002, 1, TCPD, 6, 16), dst=A2))   # mask already lost
    c.pkt(v4(50, esp_plain(0x4030, 1, UDPD, 17, 8)))
    c.pkt(v4(50, esp_plain(0x4104, 1, UDPD, 17, 24)))
    c.pkt(v4(50, esp_plain(0x4005, 1, UDPD, 17, 32)))
    c.pkt(v4(50, esp_plain(0x4006, 1, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4006, 2, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4007, 1, UDPD, 17, 0), src=b'\x0a\x01\x02\x03', dst=b'\x0a\x04\x05\x06'))
    c.pkt(v4(50, esp_plain(0x4001, 2, icmp_echo(), 1, 12)))
    c.mark('SA table: no match (wrong address, wrong SPI), pad length too large, no dissector for the inner protocol, payload shorter than the ICV')
    c.pkt(v4(50, esp_plain(0x4000, 2, UDPD, 17, 0), src=A3))
    c.pkt(v4(50, esp_plain(0x4999, 1, UDPD, 17, 0)))
    c.pkt(v4(50, esp(0x4000, 3, b'\x01' * 6 + bytes([200, 17]))))
    c.pkt(v4(50, esp_plain(0x4000, 4, b'opaque inner', 253, 0)))
    c.pkt(v4(50, esp(0x4001, 3, b'\xa5' * 8)))
    c.pkt(v4(50, esp(0x4001, 4, b'\xa5' * 14)))
    c.mark('SA table: IPv6 exact, prefix (mask lost), wildcard, long form, Any protocol')
    c.pkt(v6(50, esp_plain(0x4100, 1, UDPD6, 17, 0)))
    c.pkt(v6(50, esp_plain(0x4101, 1, UDPD6, 17, 12)))
    c.pkt(v6(50, esp_plain(0x4102, 1, TCPD, 6, 16), src=V3, dst=V1))
    c.pkt(v6(50, esp_plain(0x4103, 1, UDPD6, 17, 0), src=V1, dst=V3))
    c.pkt(v6(50, esp_plain(0x4100, 2, UDPD6, 17, 0), src=V3))
    c.pkt(v6(50, esp_plain(0x4200, 1, UDPD6, 17, 0)))
    c.pkt(v4(50, esp_plain(0x4201, 1, UDPD, 17, 12)))
    c.mark('SA table: SAs with odd-length, empty and plain-text key strings (NULL algorithms, keys unused), an address with a last octet above 15')
    c.pkt(v4(50, esp_plain(0x4310, 1, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4311, 1, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4312, 1, UDPD, 17, 12)))
    c.pkt(v4(50, esp_plain(0x4000, 5, UDPD, 17, 0), src=b'\xc0\x00\x02\x64', dst=b'\xc0\x00\x02\x65'))
    c.mark('Regression SAs (DSB without NUL, IPv6 filter with 5-digit groups, TWOFISH-CBC with a bad length)')
    c.pkt(v4(50, esp(0x7777, 1, b'\xfd' * 16)))
    c.pkt(v6(50, esp(0x7778, 1, b'\xfd' * 16)))
    body = b'\x11' * 16 + b'\x22' * 20      # 16 octet IV + 20 octets: not a multiple of 16
    for i in range(3):
        c.pkt(v4(50, esp(0x7779, i + 1, body)))

    # ---- UDP encapsulation of ESP (udpencap), TCP/UDP port 4500
    c.mark('UDP port 4500: ESP in UDP, NAT keepalive, IKE with non-ESP marker')
    c.pkt(v4(17, udp(4500, 4500, esp(0x5100, 1, b'\x00' * 12))))
    c.pkt(v4(17, udp(4500, 4500, esp(0x5100, 2, b'\x00' * 12))))
    c.pkt(v4(17, udp(4500, 4500, b'\xff')))
    c.pkt(v4(17, udp(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr())))
    c.pkt(v6(17, udp(4500, 4500, esp(0x5101, 1, b'\x00' * 12))))
    c.pkt(v4(17, udp(4500, 4500, esp_plain(0x6003, 1, UDPD, 17, 12))))
    c.mark('Exported PDU (linktype 252) naming esp, ah and ipcomp: no IP addresses, so the SA protocol is unknown')
    def exp(name, payload):
        nm = name.encode()
        nm += b'\0' * ((-len(nm)) % 4)
        return struct.pack('!HH', 12, len(nm)) + nm + struct.pack('!HH', 0, 0) + payload
    c.pkt(exp('esp', esp_plain(0x4200, 9, UDPD, 17, 0)), ifid=1)
    c.pkt(exp('esp', esp_plain(0x4999, 9, UDPD, 17, 0)), ifid=1)
    c.pkt(exp('ah', ah(17, 12, 0x1113, 1, UDPD)), ifid=1)
    c.pkt(exp('ipcomp', ipcomp(17, 2, deflate_raw(UDPD * 4))), ifid=1)
    c.mark('AH followed by ESP (this evaluates the SA table, so it comes after the frames that need the SA masks)')
    c.pkt(v4(51, ah(50, 12, 0x1111, 8, esp(0x1234, 1, b'\x01\x02\x03\x04\x05\x06\x07\x08'))))
    c.write('ipsec-coverage.pcapng')

    # ---------------------------------------------------------------- malformed
    m = Cap()
    m.raw(shb())
    # SAs with AES-GCM algorithms but no key: only used with the authentication check
    # preference alone (no decryption); runcov.sh never enables "decode" for this capture.
    gsa = ''.join(sa('IPv4', '*', '*', '0x44%02x' % i, enc=e) for i, e in enumerate(
        ['AES-GCM [RFC4106]', 'AES-GCM with 8 octet ICV [RFC4106]',
         'AES-GCM with 12 octet ICV [RFC4106]', 'AES-GCM with 16 octet ICV [RFC4106]']))
    m.raw(dsb(0x45535053, gsa.encode() + b'\0'))
    m.raw(idb())
    m.mark('ESP with AES-GCM SAs and the authentication check preference (no decryption)')
    for i in range(4):
        m.pkt(v4(50, esp(0x4400 + i, 1, b'\xfd' * 40)))
    m.mark('Truncated and cut-short packets')
    m.pkt(v4(51, ah(17, 0, 0x1111, 1, UDPD, length_field=0)))   # AH length 0: header 8 octets, overlaps SPI/sequence
    m.pkt(v4(51, ah(17, 12, 0x1111, 1, b'')))                    # UDP next header, no payload
    m.pkt(v4(51, b'\x11\x04\x00\x00\x00'))                 # AH shorter than the fixed header
    m.pkt(v4(51, ah(17, 12, 0x1111, 1, UDPD), ), caplen=14 + 20 + 14)   # AH cut inside the ICV
    m.pkt(v4(51, ah(17, 12, 0x1111, 1, UDPD)[:6]))
    m.pkt(v4(50, b'\x00\x00\x50\x00'))                    # ESP with only the SPI
    m.pkt(v4(50, b'\x00\x00\x50\x00\x00\x00'))
    m.pkt(v4(108, b'\x11\x00'))                           # IPComp without CPI
    m.pkt(v4(108, b''))
    m.pkt(v4(17, udp(4500, 4500, b'\x01\x02')))           # UDP encap: too short for the SPI
    m.pkt(v4(17, udp(4500, 4500, b'\x00')))
    m.pkt(v4(17, udp(4500, 4500, b'\x00\x00\x00\x00' + ike_hdr()[:10])))
    full = v4(50, esp_plain(0x6010, 1, UDPD, 17, 12))
    m.mark('NULL-encrypted ESP whose inner dissector reports an error (IPv6 with a bad version: the failed heuristic attempt leaves the IPv6 error in the tree)')
    m.pkt(v4(50, esp_plain(0x6012, 1, b'\x45' * 24, 41, 12)))
    m.mark('NULL-encrypted ESP cut inside the ICV (snaplen), cut before the trailer')
    m.pkt(full, caplen=len(full) - 6)
    m.pkt(full, caplen=len(full) - 12)
    m.pkt(full, caplen=len(full) - 14)
    m.pkt(full, caplen=len(full) - 20)
    m.pkt(v4(50, esp_plain(0x6010, 2, TCPD, 6, 16)), caplen=14 + 20 + 8 + 8)
    m.pkt(v6(50, esp_plain(0x6011, 1, UDPD6, 17, 12)), caplen=14 + 40 + 8 + 6)
    m.write('ipsec-coverage-malformed.pcapng')

build_main()

#!/usr/bin/env python3
# Generates test/captures/icmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic ICMP coverage captures.

Usage: mkicmp.py <outdir>
Writes icmp-coverage.pcap (valid traffic) and icmp-coverage-malformed.pcap.
Every packet is built with struct; nothing comes from a real network.
"""
import struct
import sys
import os

T0 = 1700006400          # a multiple of 86400: midnight UTC
A = bytes([192, 0, 2, 1])
B = bytes([192, 0, 2, 2])
C = bytes([198, 51, 100, 7])
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip(payload, proto=1, src=A, dst=B, ident=1, frag=0, ttl=64, tl=None, ihl_opts=b''):
    ihl = 5 + len(ihl_opts) // 4
    tot = tl if tl is not None else ihl * 4 + len(payload)
    h = struct.pack('>BBHHHBBH4s4s', 0x40 | ihl, 0, tot, ident, frag, ttl, proto, 0, src, dst) + ihl_opts
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def icmp(t, c, rest, data=b'', fix=True, ck=None):
    """ICMP message: type, code, 4 bytes after the checksum, data."""
    m = struct.pack('>BBH', t, c, 0) + rest + data
    if fix:
        m = m[:2] + struct.pack('>H', csum(m) if ck is None else ck) + m[4:]
    return m


def eth(pl, et=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', et) + pl


def vlan(pl, vid, et=0x0800):
    return MAC_B + MAC_A + struct.pack('>HHH', 0x8100, vid, et) + pl


def gre(pl):
    return struct.pack('>HH', 0, 0x0800) + pl


udp8 = struct.pack('>HHHH', 33434, 53, 8, 0)
tcp8 = struct.pack('>HHI', 40000, 80, 0x01020304)


def orig(proto=17, l4=udp8, src=B, dst=C, pad=0, tl=None):
    d = ip(l4, proto=proto, src=src, dst=dst, tl=tl)
    return d + b'\0' * pad


def ext(objs, ver=2, ck=True, raw_ck=None):
    body = struct.pack('>BBH', ver << 4, 0, 0) + b''.join(objs)
    full = body
    for o in objs:   # the dissector sums up to the end of the first Interface Identification object
        if o[2] == 3:
            body = struct.pack('>BBH', ver << 4, 0, 0) + b''.join(objs[:objs.index(o) + 1])
            break
    if raw_ck is not None:
        return full[:2] + struct.pack('>H', raw_ck) + full[4:]
    if ck:
        c = csum(body)
        full = full[:2] + struct.pack('>H', c) + full[4:]
    return full


def obj(cls, ctype, data=b'', length=None):
    return struct.pack('>HBB', length if length is not None else 4 + len(data), cls, ctype) + data


def mpls_entry(label, exp, s, ttl):
    v = (label << 12) | (exp << 9) | (s << 8) | ttl
    return struct.pack('>I', v)


def iio(flags, role=0, ifindex=None, afi=None, addr=b'', name=None, mtu=None, length=None, name_len=None):
    d = b''
    if ifindex is not None:
        d += struct.pack('>I', ifindex)
    if afi is not None:
        d += struct.pack('>HH', afi, 0) + addr
    if name is not None:
        d += bytes([name_len if name_len is not None else len(name) + 1]) + name
    if mtu is not None:
        d += struct.pack('>I', mtu)
    return obj(2, (role << 6) | flags, d, length)


marks = []
frames = []   # (time_sec, time_usec, bytes, caplen or None)
malformed = []
tcur = [T0 + 600]    # frame time, seconds


def add(f, usec=0, dt=1, lst=None, secs=None, caplen=None):
    if secs is None:
        tcur[0] += dt
        secs = tcur[0]
    (frames if lst is None else lst).append((secs, usec, f, caplen))


def addip(p, proto=1, lst=None, **kw):
    add(eth(ip(p, proto=proto, **{k: v for k, v in kw.items() if k in
        ('src', 'dst', 'ident', 'frag', 'ttl', 'tl', 'ihl_opts')})), lst=lst,
        **{k: v for k, v in kw.items() if k in ('usec', 'dt', 'secs', 'caplen')})


def echo(t=8, ident=0x1234, seq=1, data=b'', code=0, src=A, dst=B, lst=None, ck=None, usec=0, fix=True, dt=1):
    addip(icmp(t, code, struct.pack('>HH', ident, seq), data, ck=ck, fix=fix), src=src, dst=dst, lst=lst, usec=usec, dt=dt)


def ts_le32(s, us):  return struct.pack('<II', s, us)
def ts_be32(s, us):  return struct.pack('>II', s, us)
def ts_le64(s, us):  return struct.pack('<QQ', s, us)
def ts_be64(s, us):  return struct.pack('>QQ', s, us)


def mark(n):
    marks.append((len(frames) + 1, n))


def gen_main():
    pay = bytes(range(0x10, 0x30))
    mark('echo timestamps')
    # ---- Echo, request/reply matching with each timestamp encoding ----
    for n, mk in enumerate((ts_le32, ts_be32, ts_le64, ts_be64)):
        t = tcur[0] + 1
        d = mk(t, 250000) + pay
        echo(8, 0x1000 + n, n + 1, d, usec=250000, dt=1)
        t2 = tcur[0]
        echo(0, 0x1000 + n, n + 1, mk(t2, 250000) + pay, src=B, dst=A, usec=260000, dt=0)
    mark('echo payload variants and tracking')
    # timestamp too far from the frame time: plain data
    echo(8, 0x1010, 1, ts_le32(T0 - 5 * 86400, 5) + pay)
    echo(0, 0x1010, 1, ts_le32(T0 - 5 * 86400, 5) + pay, src=B, dst=A)
    # microseconds out of range
    echo(8, 0x1011, 1, ts_le32(tcur[0] + 1, 2000000) + pay)
    echo(0, 0x1011, 1, ts_le32(tcur[0], 2000000) + pay, src=B, dst=A)
    # LE 64-bit timestamp with 8 bytes only after: LE32 nonzero usec path
    echo(8, 0x1012, 1, ts_le32(tcur[0] + 1, 123456))
    echo(0, 0x1012, 1, ts_le32(tcur[0], 123456), src=B, dst=A)
    # Payload of 4 bytes, and no payload; text payload (heuristic subdissector tries, then data)
    echo(8, 0x1013, 1, b'abcd')
    echo(0, 0x1013, 1, b'abcd', src=B, dst=A)
    echo(8, 0x1014, 1, b'')
    echo(0, 0x1014, 1, b'', src=B, dst=A)
    echo(8, 0x1015, 1, b'The quick brown fox jumps over the lazy dog')
    echo(0, 0x1015, 1, b'The quick brown fox jumps over the lazy dog', src=B, dst=A)
    # Reply checksum 0xffff (key forced to 0); request checksum 0xf7ff
    echo(8, 0, 0, b'')
    echo(0, 0, 0, b'', src=B, dst=A)
    # Request without a reply (needs -2: "no response found")
    echo(8, 0x1020, 1, pay)
    # Reply without request
    echo(0, 0x1021, 1, pay, src=B, dst=A)
    # Duplicate request and reply: the second reply finds the matched transaction
    echo(8, 0x1022, 1, pay)
    echo(0, 0x1022, 1, pay, src=B, dst=A)
    echo(0, 0x1022, 1, pay, src=B, dst=A)
    # Broadcast and multicast destinations: no transaction tracking
    echo(8, 0x1023, 1, pay, dst=bytes([255, 255, 255, 255]))
    echo(8, 0x1024, 1, pay, dst=bytes([224, 0, 0, 1]))
    # Wrong checksums, code != 0 for echo, nonzero code for others
    echo(8, 0x1025, 1, pay, ck=0x1234)
    echo(8, 0x1026, 1, pay, code=5)
    echo(0, 0x1026, 1, pay, code=5, src=B, dst=A)
    # Echo with TTL in the Info column set via IP; echoes with a large payload
    echo(8, 0x1027, 9, bytes(range(256)) * 3)
    echo(0, 0x1027, 9, bytes(range(256)) * 3, src=B, dst=A)

    mark('IP fragments, VLAN, GRE')
    # IP fragments of an echo request: dissected once reassembled
    big = icmp(8, 0, struct.pack('>HH', 0x1030, 1), bytes(range(200)))
    addip(big[:104], ident=77, frag=0x2000)
    addip(big[104:], ident=77, frag=104 // 8)
    # The first fragment alone: ICMP over a fragment is not dissected by IP

    # Echo inside a VLAN, and over GRE
    for vid in (100, 200):
        add(vlan(ip(icmp(8, 0, struct.pack('>HH', 0x1040, vid), pay)), vid))
        add(vlan(ip(icmp(0, 0, struct.pack('>HH', 0x1040, vid), pay), src=B, dst=A), vid))
    for n in range(2):
        inner = ip(icmp(8, 0, struct.pack('>HH', 0x1050, n), pay), src=bytes([10, 0, 0, 1]), dst=bytes([10, 0, 0, 2]))
        add(eth(ip(gre(inner), proto=47)))
        inner = ip(icmp(0, 0, struct.pack('>HH', 0x1050, n), pay), src=bytes([10, 0, 0, 2]), dst=bytes([10, 0, 0, 1]))
        add(eth(ip(gre(inner), proto=47, src=B, dst=A)))

    mark('destination unreachable, other errors')
    # ---- Destination unreachable: every code, RFC 4884 length and MTU ----
    od = orig(pad=0)
    for c in range(16):
        addip(icmp(3, c, b'\0\0\0\0', od))
    addip(icmp(3, 4, struct.pack('>HH', 0, 1400), od))                # frag needed with MTU
    addip(icmp(3, 99, b'\0\0\0\0', od))                               # unknown code
    odp = orig(pad=128 - 28)
    # RFC 4884: length 32 words, no extension (exactly 128 bytes)
    addip(icmp(3, 1, struct.pack('>BBH', 0, 32, 0), odp))
    addip(icmp(3, 4, struct.pack('>BBH', 0, 32, 1400), odp))        # length + MTU
    # Inner datagram longer than the length field says (first branch of the length test)
    odl = orig(pad=128 - 28 + 40, tl=28 + 128 + 40)
    addip(icmp(3, 3, struct.pack('>BBH', 0, 10, 0), odl))
    # Port unreachable for TCP and an embedded ICMP echo (in error packet)
    addip(icmp(3, 3, b'\0\0\0\0', orig(proto=6, l4=tcp8)))
    inner_echo = icmp(8, 0, struct.pack('>HH', 0x1060, 1), pay)
    addip(icmp(3, 1, b'\0\0\0\0', orig(proto=1, l4=inner_echo, src=B, dst=C)))
    inner_rep = icmp(0, 0, struct.pack('>HH', 0x1060, 1), pay)
    addip(icmp(3, 1, b'\0\0\0\0', orig(proto=1, l4=inner_rep, src=B, dst=C)))
    # Nested error inside an error (reproducer of "ICMP: Bound error nesting ...")
    nested = icmp(3, 1, b'\0\0\0\0', orig())
    addip(icmp(3, 1, b'\0\0\0\0', orig(proto=1, l4=nested, src=B, dst=C)))
    p = icmp(3, 1, b'\0\0\0\0', orig())
    for _ in range(3):
        p = icmp(11, 0, b'\0\0\0\0', ip(p, src=B, dst=C))
    addip(p)
    # Time exceeded, parameter problem, source quench, redirect
    addip(icmp(11, 0, b'\0\0\0\0', od))
    addip(icmp(11, 1, b'\0\0\0\0', od))
    addip(icmp(11, 0, struct.pack('>BBH', 0, 32, 0), odp))
    addip(icmp(12, 0, bytes([20, 0, 0, 0]), od))
    addip(icmp(12, 1, bytes([0, 0, 0, 0]), od))
    addip(icmp(12, 2, bytes([2, 32, 0, 0]), odp))
    addip(icmp(4, 0, b'\0\0\0\0', od))
    for c in range(4):
        addip(icmp(5, c, C, ip(udp8, proto=17, src=B, dst=C)))
    addip(icmp(5, 7, C, ip(udp8, proto=17, src=B, dst=C)))
    # Redirect whose embedded header has IP options
    addip(icmp(5, 1, C, ip(udp8, proto=17, src=B, dst=C, ihl_opts=b'\x01\x01\x01\x00')))
    # Alternate host address (deprecated), information request/reply
    addip(icmp(6, 0, b'\0\0\0\0'))
    addip(icmp(6, 3, b'\0\0\0\0'))
    addip(icmp(15, 0, struct.pack('>HH', 0x2000, 1)))
    addip(icmp(16, 0, struct.pack('>HH', 0x2000, 1)))
    # Mask request / reply
    addip(icmp(17, 0, struct.pack('>HH', 0x2001, 1), bytes([255, 255, 255, 0])))
    addip(icmp(18, 0, struct.pack('>HH', 0x2001, 1), bytes([255, 255, 255, 0])))
    addip(icmp(17, 3, struct.pack('>HH', 0x2001, 2), bytes([255, 255, 255, 0])))
    mark('Photuris, reserved, deprecated types')
    # Photuris, reserved and unknown types, deprecated types
    for c in range(7):
        addip(icmp(40, c, struct.pack('>HH', 0, 0x1234), b'\0' * 8))
    for t in (1, 2, 19, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 41, 77, 255):
        addip(icmp(t, 0, b'\0\0\0\0', b'\0' * 8))

    mark('router solicitation/advertisement')
    # ---- Router solicitation / advertisement with Mobile IP extensions ----
    addip(icmp(10, 0, b'\0\0\0\0'))
    addip(icmp(10, 3, b'\0\0\0\0'))
    ra = lambda code, n, size, life, body, ext=b'': icmp(9, code, struct.pack('>BBH', n, size, life), body + ext)
    r1 = struct.pack('>Ii', 0xc0000201, 0) + struct.pack('>Ii', 0xc0000202, -5)
    addip(ra(0, 2, 2, 1800, r1))
    addip(ra(16, 1, 2, 0, r1[:8]))
    addip(ra(3, 1, 2, 0xffff, r1[:8]))
    mip = (struct.pack('>BBHHH', 16, 6 + 8, 7, 1800, 0xffff) + bytes([192, 0, 2, 9]) + bytes([192, 0, 2, 10])
           + bytes([0])                                    # pad
           + bytes([19, 3, 24, 16, 8])                    # prefix lengths
           + bytes([24, 4, 1, 2, 3, 4])                   # challenge
           + bytes([0x99, 3, 7, 8, 9])                    # unknown extension with data
           + bytes([0x98, 0])                             # unknown, no data
           + bytes([16, 6, 0, 1, 0, 2, 0, 0]))            # agent advertisement, no COA
    addip(ra(0, 1, 2, 600, r1[:8], mip))
    addip(ra(16, 1, 2, 600, r1[:8], mip))
    # Entry size != 2: data
    addip(ra(0, 1, 3, 600, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c'))
    # Unknown MIP ext type with a length that fits (the fixed length - 4 bug uses length 2)
    addip(ra(0, 1, 2, 600, r1[:8], bytes([0x99, 2, 0xaa, 0xbb])))

    mark('extended echo')
    # ---- Extended echo (RFC 8335) and ICMP extension objects ----
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 1, 0x01)))                    # no extension
    ident_name = obj(3, 1, b'eth0')
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 2, 0x01), ext([ident_name])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 3, 0x00), ext([obj(3, 2, struct.pack('>I', 7))])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 4, 0x01),
               ext([obj(3, 3, struct.pack('>HBB', 1, 4, 0) + bytes([192, 0, 2, 5]))])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 5, 0x01),
               ext([obj(3, 3, struct.pack('>HBB', 1, 8, 0) + bytes([192, 0, 2, 5, 192, 0, 2, 6]))])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 6, 0x01),
               ext([obj(3, 3, struct.pack('>HBB', 2, 16, 0) + bytes(15) + b'\x01'),
                    obj(3, 1, b'second')])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 7, 0x01),
               ext([obj(3, 3, struct.pack('>HBB', 7, 6, 0) + b'abcdef')])))       # unknown AFI
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 8, 0x01), ext([obj(3, 9, b'xxxx')])))   # unknown c-type
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 9, 0x01), ext([obj(3, 1, b'')], ck=False)))  # zero checksum
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 10, 0x01), ext([obj(7, 1, b'abcdefgh')])))  # unknown class
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 11, 0x01), ext([obj(3, 1, b'x')], ver=3)))  # unsupported version
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 12, 0x01), ext([obj(3, 1, b'x')], ver=1)))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 13, 0x01), ext([obj(3, 1, b'x')], raw_ck=0x4321)))  # bad checksum
    addip(icmp(42, 3, struct.pack('>HBB', 0x4000, 14, 0x01)))                    # code != 0
    for state in range(7):
        for flags in (0, 7, 0x03, 0x04):
            if flags == 0 and state > 1:
                continue
            addip(icmp(43, state % 5, struct.pack('>HBB', 0x4000, state, (state << 5) | flags)))
    addip(icmp(43, 0, struct.pack('>HBB', 0x4000, 20, 0x04),
               ext([obj(3, 1, b'eth0')])))
    # Extension of 2 octets only (shorter than the common header)
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 21, 0x01), b'\x20\x00'))
    # ICMP extension header with no objects
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 22, 0x01), ext([])))
    # Object whose declared length is 4 (header only), with trailing space
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 23, 0x01), ext([obj(3, 1, b'')])))
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 24, 0x01), ext([obj(7, 1, b'')])))
    # Identification object that has only 4 octets of the header remaining
    addip(icmp(42, 0, struct.pack('>HBB', 0x4000, 25, 0x01), ext([obj(3, 1, b'')], ck=False)))

    mark('multi-part extensions')
    # Destination unreachable (and time exceeded) with multi-part extensions
    odx = orig(pad=128 - 28)
    def unreach(objs, t=3, c=1, ln=32, **kw):
        return icmp(t, c, struct.pack('>BBH', 0, ln, 0), odx + ext(objs, **kw))
    addip(unreach([obj(1, 1, mpls_entry(1000, 5, 1, 64))]))
    addip(unreach([obj(1, 1, mpls_entry(16, 0, 0, 255) + mpls_entry(0xfffff, 7, 1, 1) + b'\x01\x02')], t=11, c=0))
    addip(unreach([obj(1, 1, b'')]))
    addip(unreach([obj(1, 2, b'\0' * 4)]))                       # unknown MPLS c-type
    addip(unreach([obj(0, 1, b'0123456789abcdef')]))                # MPLS extended payload
    addip(unreach([obj(0, 1, b'')]))
    addip(unreach([obj(0, 2, b'xyz1')]))
    # Interface information objects
    for role in range(4):
        addip(unreach([iio(0x0f, role, ifindex=9, afi=1, addr=bytes([10, 1, 1, 1]), name=b'eth0', mtu=1500)]))
    addip(unreach([iio(0x08, 0, ifindex=3)]))
    addip(unreach([iio(0x04, 0, afi=1, addr=bytes([10, 1, 1, 2]))]))
    addip(unreach([iio(0x04, 1, afi=2, addr=bytes(15) + b'\x09')]))
    addip(unreach([iio(0x04, 0, afi=3, addr=b'\1\2\3\4')]))                    # unknown AFI (fixed negative length)
    addip(unreach([iio(0x02, 2, name=b'Gi0/0/1')]))
    addip(unreach([iio(0x01, 3, mtu=9000)]))
    addip(unreach([iio(0x00, 0)]))
    addip(unreach([iio(0x03, 0, name=b'ab', mtu=1)]))
    addip(unreach([iio(0x30 | 0x0a, 0, ifindex=1, name=b'x')]))   # reserved bits
    # five interface objects: "More than 4 Interface Information Objects"
    addip(unreach([iio(0x08, i % 4, ifindex=i) for i in range(5)]))
    # Unknown classes and object lengths
    addip(unreach([obj(9, 4, b'12345678'), obj(200, 0)]))
    addip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3)), iio(0x0a, 2, ifindex=4, name=b'lo')]))
    # Version 1 and checksum 0, bad checksum
    addip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3))], ver=1))
    addip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3))], ck=False))
    addip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3))], raw_ck=0xbeef))
    addip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3))], ver=5))
    # Extension padded so that the datagram is more than 128 bytes with a short inner datagram
    # and no length field (draft-ietf-mpls-icmp-02 style)
    addip(icmp(3, 1, b'\0\0\0\0', odx + ext([obj(1, 1, mpls_entry(77, 0, 1, 9))])))
    # Inner datagram larger than 128 octets (favor_icmp_mpls matters)
    biginner = orig(pad=200 - 28, tl=200)
    addip(icmp(3, 3, b'\0\0\0\0', biginner + ext([obj(1, 1, mpls_entry(77, 0, 1, 9))])))
    addip(icmp(11, 0, b'\0\0\0\0', biginner))
    # Extension that is cut: extended echo reply with a truncated object (declared length shorter than header)
    # (see the malformed capture for the invalid lengths)

    mark('timestamp')
    # ---- Timestamp request/reply ----
    # (originate, receive, transmit) as raw 4-byte values; frame time chosen per case
    def tsmsg(t, o, r, x, secs):
        d = (o + r + x)
        add(eth(ip(icmp(t, 0, struct.pack('>HH', 0x3000, 1), d))), secs=secs)
    ms = lambda h: struct.pack('>I', h * 3600 * 1000)
    # normal values at 01:00, big-endian
    tsmsg(13, ms(1), struct.pack('>I', 0), struct.pack('>I', 0), T0 + 3701)
    tsmsg(14, ms(1), ms(1) , ms(1), T0 + 3702)
    # little-endian values (be big, le < day)
    le = lambda v: struct.pack('<I', v)
    tsmsg(14, le(3600000), le(3600001), le(3600002), T0 + 3703)
    # both below a day: be smaller, le smaller, with rollover near midnight
    tsmsg(14, b'\0\0\x01\0', b'\0\x01\0\0', b'\0\0\0\0', T0 + 3704)
    # Both above a day with no high bit: deterministic guess
    tsmsg(14, bytes([0x10, 0x20, 0x30, 0x40]), bytes([0x40, 0x30, 0x20, 0x10]),
          bytes([0x10, 0x20, 0x30, 0x40]), T0 + 3705)
    # High bit set: "not milliseconds since midnight" case
    tsmsg(14, b'\0\0\x03\xe8', b'\xe8\x03\0\0', b'\0\0\x03\xe8', T0 + 3705)
    tsmsg(14, bytes([0x80, 0, 0, 5]), bytes([0, 0, 0, 5 | 0x80]), bytes([0xff, 0xff, 0xff, 0xff]), T0 + 3706)
    tsmsg(14, b'\0\x01\0\0', b'\0\0\x01\0', b'\0\0\0\x01', T0 + 20 * 3600)
    tsmsg(14, b'\0\0\x01\0', b'\0\x01\0\0', b'\0\0\0\x01', T0 + 20 * 3600 + 1)


def gen_malformed():
    L = malformed
    pay = b'0123456789abcdef'
    # Truncated frames: echo cut in the middle of the payload, error cut in the inner header
    full = eth(ip(icmp(8, 0, struct.pack('>HH', 0x5000, 1), pay)))
    add(full, lst=L, caplen=len(full) - 6)
    full = eth(ip(icmp(0, 0, struct.pack('>HH', 0x5000, 1), pay), src=B, dst=A))
    add(full, lst=L, caplen=14 + 20 + 12)
    full = eth(ip(icmp(3, 1, b'\0\0\0\0', orig())))
    add(full, lst=L, caplen=len(full) - 10)
    # Extension objects: length below the header, truncated object
    odx = orig(pad=128 - 28)
    def unreach(objs, **kw):
        return icmp(3, 1, struct.pack('>BBH', 0, 32, 0), odx + ext(objs, **kw))
    add(eth(ip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3), length=2)]))), lst=L)
    add(eth(ip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3), length=3)]))), lst=L)
    add(eth(ip(unreach([obj(1, 1, mpls_entry(5, 0, 1, 3) * 2, length=40)]))), lst=L)
    add(eth(ip(unreach([obj(7, 1, b'abcdefgh', length=60)]))), lst=L)
    add(eth(ip(unreach([iio(0x0f, 0, ifindex=9, afi=1, addr=bytes([10, 1, 1, 1]), name=b'eth0', mtu=1500, length=14)]))), lst=L)
    add(eth(ip(unreach([iio(0x0f, 0, ifindex=9, afi=1, addr=bytes([10, 1, 1, 1]), name=b'eth0', mtu=1500, length=60)]))), lst=L)
    add(eth(ip(unreach([obj(0, 1, b'abcdef', length=100)]))), lst=L)
    # Interface information: IP sub-object with an unknown AFI (fixed), name length 0 (fixed),
    # name length longer than the object, IP address sub-object cut
    add(eth(ip(unreach([iio(0x04, 0, afi=3, addr=b'\1\2\3\4')]))), lst=L)
    add(eth(ip(unreach([iio(0x02, 0, name=b'eth0xxx', name_len=0)]))), lst=L)
    add(eth(ip(unreach([iio(0x02, 0, name=b'eth', name_len=40)]))), lst=L)
    add(eth(ip(unreach([iio(0x04, 0, afi=1, addr=bytes([1, 2]), length=8)]))), lst=L)
    add(eth(ip(unreach([iio(0x04, 0, length=4)]))), lst=L)
    add(eth(ip(unreach([iio(0x02, 0, length=4)]))), lst=L)
    # Mobile IP: unknown extension of length 2 (fixed)
    add(eth(ip(icmp(9, 0, struct.pack('>BBH', 0, 2, 0), bytes([0x99, 2, 0xaa, 0xbb])))), lst=L)
    # MIP extension truncated
    add(eth(ip(icmp(9, 0, struct.pack('>BBH', 1, 2, 0), struct.pack('>Ii', 0xc0000201, 0)
                    + bytes([16, 20, 0, 1])))), lst=L)
    add(eth(ip(icmp(9, 0, struct.pack('>BBH', 0, 2, 0), bytes([24, 40, 1, 2])))), lst=L)
    # Extended echo: identification object with a short address, truncated address list
    ex = lambda o: icmp(42, 0, struct.pack('>HBB', 0x6000, 1, 1), ext(o))
    add(eth(ip(ex([obj(3, 3, struct.pack('>HBB', 1, 12, 0) + bytes([1, 2, 3, 4]))]))), lst=L)
    add(eth(ip(ex([obj(3, 3, struct.pack('>HBB', 2, 32, 0) + bytes(16))]))), lst=L)
    add(eth(ip(ex([obj(3, 3, b'\0')]))), lst=L)
    add(eth(ip(ex([obj(3, 2, b'\0\0')]))), lst=L)
    add(eth(ip(ex([obj(3, 1, b'abc', length=200)]))), lst=L)
    add(eth(ip(ex([obj(3, 1, b'abc', length=3)]))), lst=L)
    add(eth(ip(icmp(42, 0, struct.pack('>HBB', 0x6000, 1, 1), b'\x20\x00\x00\x00\x00\x08\x03'))), lst=L)
    # Timestamp message too short
    add(eth(ip(icmp(13, 0, struct.pack('>HH', 1, 1), b'\0' * 6))), lst=L)
    add(eth(ip(icmp(17, 0, struct.pack('>HH', 1, 1), b'\0\0'))), lst=L)
    # Router advertisement claiming more entries than the packet holds
    add(eth(ip(icmp(9, 0, struct.pack('>BBH', 9, 2, 100), b'\0' * 8))), lst=L)
    # Fragment: the second fragment only
    add(eth(ip(icmp(8, 0, b'\0\0\0\0', pay), frag=0x2000)), lst=L)
    # Short messages
    add(eth(ip(b'\x08\x00\x00')), lst=L)
    add(eth(ip(b'\x03\x01\x00\x00\x00')), lst=L)
    add(eth(ip(b'\x03\x01\x00\x00\x00\x20\x00\x00' + orig() + b'\0' * 10)), lst=L)


def write(path, fr):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for s, us, p, caplen in fr:
            cl = caplen if caplen is not None else len(p)
            f.write(struct.pack('<IIII', s, us, cl, len(p)) + p[:cl])


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    gen_main()
    gen_malformed()
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'icmp-coverage.pcap'), frames)
    write(os.path.join(out, 'icmp-coverage-malformed.pcap'), malformed)
    print(len(frames), len(malformed))
    if os.environ.get('MARKS'):
        print(marks)

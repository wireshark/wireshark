#!/usr/bin/env python3
# Generates test/captures/dhcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DHCP/BOOTP coverage captures for packet-dhcp.c.

Usage: mkdhcp.py <outdir>

Writes dhcp-coverage.pcap (well-formed packets, no error expert infos)
and dhcp-coverage-malformed.pcap (paths only malformed input reaches).
Every packet is built with struct; addresses are from the documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and
MAC addresses are locally administered.
"""
import os
import struct
import sys

# ---------------------------------------------------------------- pcap/IP

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


CLIENT_MAC = b'\x02\x00\x00\x00\x00\x01'
SERVER_MAC = b'\x02\x00\x00\x00\x00\x02'


def udp_frame(payload, sport=68, dport=67, src='0.0.0.0', dst='255.255.255.255',
              smac=CLIENT_MAC, dmac=b'\xff' * 6):
    s, d = ip4(src), ip4(dst)
    ulen = 8 + len(payload)
    pseudo = s + d + struct.pack('!BBH', 0, 17, ulen)
    udp = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    uc = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', uc) + udp[8:]
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0x10, 20 + len(udp), 0, 0, 128, 17, 0, s, d)
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    return dmac + smac + b'\x08\x00' + iph + udp


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------- BOOTP

MAGIC = b'\x63\x82\x53\x63'


def bootp(options=b'', op=1, htype=1, hlen=6, hops=0, xid=0x3903f326, secs=0,
          flags=0, ciaddr='0.0.0.0', yiaddr='0.0.0.0', siaddr='0.0.0.0',
          giaddr='0.0.0.0', chaddr=CLIENT_MAC, sname=b'', file=b'', magic=True,
          secs_raw=None):
    hdr = struct.pack('!BBBBI', op, htype, hlen, hops, xid)
    hdr += secs_raw if secs_raw is not None else struct.pack('!H', secs)
    hdr += struct.pack('!H', flags)
    hdr += ip4(ciaddr) + ip4(yiaddr) + ip4(siaddr) + ip4(giaddr)
    hdr += chaddr.ljust(16, b'\0')[:16]
    hdr += sname.ljust(64, b'\0')[:64]
    hdr += file.ljust(128, b'\0')[:128]
    return hdr + (MAGIC if magic else b'') + options


def opt(code, data=b''):
    assert len(data) < 256, (code, len(data))
    return bytes([code, len(data)]) + data


END = b'\xff'


def dns(name):
    out = b''
    for label in name.split('.'):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b'\0'


def dhcp(msgtype, *opts, op=None, vc=None, end=True, request=True, **kw):
    """DHCP message: option 53 first, then option 60 (if any), then opts."""
    o = opt(53, bytes([msgtype])) if msgtype is not None else b''
    if vc is not None:
        o += opt(60, vc)
    o += b''.join(opts)
    if end:
        o += END
    if op is None:
        op = 1 if msgtype in (1, 3, 4, 7, 8, 10, 14) else 2
    return bootp(o, op=op, **kw)


def c2s(payload, **kw):
    """Client to server (broadcast)."""
    return udp_frame(payload, **kw)


def s2c(payload, **kw):
    """Server to client."""
    a = dict(sport=67, dport=68, src='192.0.2.1', dst='192.0.2.100',
             smac=SERVER_MAC, dmac=CLIENT_MAC)
    a.update(kw)
    return udp_frame(payload, **a)

# ---------------------------------------------------------------- frames

frames = []
sections = []     # (first frame, last frame, description)
mframes = []
msections = []


class Section:
    def __init__(self, lst, secs, desc):
        self.lst, self.secs, self.desc = lst, secs, desc

    def __enter__(self):
        self.start = len(self.lst) + 1
        return self

    def __exit__(self, *a):
        self.secs.append((self.start, len(self.lst), self.desc))


def section(desc):
    return Section(frames, sections, desc)


def msection(desc):
    return Section(mframes, msections, desc)


def add(fr):
    frames.append(fr)


def madd(fr):
    mframes.append(fr)

# Basic option types from default_dhcp_opt[], valid values for each.
BASIC = {
    'ipv4': [1, 16, 28, 32, 50, 54],
    'time_in_s_secs': [2],
    'ipv4_list': [3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65, 68, 69,
                  70, 71, 72, 73, 74, 75, 76, 92, 112, 118, 136, 138, 142, 148, 150],
    'string': [12, 14, 15, 17, 18, 40, 47, 56, 62, 64, 66, 67, 86, 87, 100, 101,
               113, 137, 147, 161, 209, 210, 252],
    'val_u_short': [13, 22, 26, 57],
    'val_boolean': [19, 20, 27, 29, 30, 31, 34, 36, 39, 157],
    'val_u_byte': [23, 37, 46, 116, 156],
    'time_in_u_secs': [24, 35, 38, 51, 58, 59, 91, 108, 153, 211],
    'val_u_short_list': [25],
}


def basic_value(t, code):
    if t == 'ipv4':
        return ip4('192.0.2.%d' % code)
    if t == 'ipv4_list':
        return ip4('192.0.2.%d' % code) + ip4('198.51.100.%d' % code)
    if t == 'string':
        return ('opt%d.example' % code).encode()
    if t == 'val_u_short':
        return struct.pack('!H', 576 + code)
    if t == 'val_boolean':
        return b'\x01'
    if t == 'val_u_byte':
        return bytes([code])
    if t == 'time_in_s_secs':
        return struct.pack('!i', -3600)
    if t == 'time_in_u_secs':
        return struct.pack('!I', 0xffffffff if code == 51 else 86400 + code)
    if t == 'val_u_short_list':
        return struct.pack('!HHH', 68, 296, 576)
    raise ValueError(t)


# ---- 1. A normal DORA exchange, Release, Inform, every message type
with section('DHCP DORA exchange (Discover, Offer, Request, ACK) with common options'):
    prl = opt(55, bytes([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252, 200]))
    add(c2s(dhcp(1, opt(61, b'\x01' + CLIENT_MAC), opt(50, ip4('192.0.2.100')),
                 opt(12, b'client1'), prl, opt(57, b'\x05\xdc'),
                 flags=0x8000)))
    add(s2c(dhcp(2, opt(54, ip4('192.0.2.1')), opt(51, b'\x00\x01\x51\x80'),
                 opt(58, b'\x00\x00\xa8\xc0'), opt(59, b'\x00\x01\x27\x50'),
                 opt(1, ip4('255.255.255.0')), opt(28, ip4('192.0.2.255')),
                 opt(3, ip4('192.0.2.1')), opt(6, ip4('192.0.2.1') + ip4('192.0.2.2')),
                 opt(15, b'example.com'), yiaddr='192.0.2.100', siaddr='192.0.2.1')))
    add(c2s(dhcp(3, opt(61, b'\x01' + CLIENT_MAC), opt(50, ip4('192.0.2.100')),
                 opt(54, ip4('192.0.2.1')), opt(12, b'client1'), prl)))
    add(s2c(dhcp(5, opt(54, ip4('192.0.2.1')), opt(51, b'\x00\x01\x51\x80'),
                 opt(1, ip4('255.255.255.0')), opt(3, ip4('192.0.2.1')),
                 yiaddr='192.0.2.100')))
    add(c2s(dhcp(7, opt(54, ip4('192.0.2.1')), opt(61, b'\x01' + CLIENT_MAC),
                 ciaddr='192.0.2.100'), src='192.0.2.100', dst='192.0.2.1',
            dmac=SERVER_MAC))
    add(c2s(dhcp(8, opt(61, b'\x01' + CLIENT_MAC), prl, ciaddr='192.0.2.100'),
            src='192.0.2.100'))

with section('Every other DHCP message type (4, 6, 9-18) and an unknown type 19'):
    for t in (4, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19):
        if t in (10, 14, 16):
            add(c2s(dhcp(t, opt(54, ip4('192.0.2.1')), ciaddr='192.0.2.100',
                         giaddr='192.0.2.254'), sport=67, src='192.0.2.254',
                    dst='192.0.2.1', dmac=SERVER_MAC))
        else:
            add(s2c(dhcp(t, opt(54, ip4('192.0.2.1')), opt(56, b'message %d' % t))))

# ---- 2. Header variants
with section('BOOTP and header variants'):
    # Plain BOOTP request and reply without the DHCP magic cookie (64 byte
    # vendor area), boot file and server name given.
    add(c2s(bootp(op=1, magic=False, secs=10) + b'\0' * 64))
    add(s2c(bootp(op=2, magic=False, yiaddr='192.0.2.100', siaddr='192.0.2.1',
                  sname=b'bootserver.example', file=b'/tftpboot/pxelinux.0') +
            bytes(range(64))))
    # BOOTP with the magic cookie but no message type option
    add(s2c(bootp(opt(1, ip4('255.255.255.0')) + END, op=2, yiaddr='192.0.2.101',
                  file=b'boot.img')))
    # Seconds elapsed looks little-endian (Windows), relay hops, giaddr
    add(c2s(dhcp(1, opt(12, b'winclient'), secs_raw=b'\x05\x00', hops=1,
                 giaddr='192.0.2.254'), sport=67, src='192.0.2.254',
            dst='192.0.2.1', dmac=SERVER_MAC))
    # IEEE 802 hardware type, length 6
    add(c2s(dhcp(1, htype=6)))
    # Hardware type 7 (ARCNET), length 1; type 32 (InfiniBand) length 0
    add(c2s(dhcp(1, htype=7, hlen=1, chaddr=b'\x42')))
    add(c2s(dhcp(1, htype=32, hlen=0, chaddr=b'')))
    # Hardware length 16 (no padding) and 20 (not given)
    add(c2s(dhcp(1, htype=8, hlen=16, chaddr=bytes(range(1, 17)))))
    add(c2s(dhcp(1, htype=8, hlen=20, chaddr=bytes(range(1, 17)))))
    # Unknown opcode 3
    add(c2s(dhcp(1, op=3)))
    # Padding options, and padding after the End option
    add(c2s(dhcp(1, b'\0\0\0', opt(12, b'pad'), b'\0', end=False) + END + b'\0' * 7))
    # proxyDHCP on port 4011 (PXE)
    add(c2s(dhcp(3, opt(60, b'PXEClient:Arch:00000:UNDI:002001'),
                 opt(97, b'\x00' + bytes(range(16))), op=1, ciaddr='192.0.2.100'),
            sport=68, dport=4011, src='192.0.2.100', dst='192.0.2.1',
            dmac=SERVER_MAC))
    add(s2c(dhcp(5, opt(60, b'PXEClient'), opt(54, ip4('192.0.2.1')),
                 opt(43, b'\x06\x01\x08\xff'), siaddr='192.0.2.1',
                 file=b'pxelinux.0'), sport=4011, dport=68))

# ---- 3. Option overload and RFC 3396 long options
with section('Option overload (52) into file, sname and both; option 52 inside the file field'):
    f_opts = opt(15, b'file.example') + opt(66, b'tftp.example') + END
    s_opts = opt(12, b'snamehost') + b'\0\0' + END
    add(s2c(dhcp(5, opt(52, b'\x01'), opt(54, ip4('192.0.2.1')), file=f_opts)))
    add(s2c(dhcp(5, opt(52, b'\x02'), opt(54, ip4('192.0.2.1')), sname=s_opts)))
    add(s2c(dhcp(5, opt(52, b'\x03'), opt(54, ip4('192.0.2.1')),
                 file=f_opts, sname=s_opts)))
    # Overload option repeated inside the file field (warning)
    add(s2c(dhcp(5, opt(52, b'\x01'), file=opt(52, b'\x01') + END)))
    # Message type and vendor class id only in the overloaded file field
    add(s2c(bootp(opt(52, b'\x01') + END, op=2,
                  file=opt(53, b'\x05') + opt(60, b'PXEClient') +
                  opt(43, b'\x06\x01\x03\xff') + END)))

with section('RFC 3396 long options split into several blocks'):
    # Host name in two blocks; domain search in three blocks, one of them empty
    add(s2c(dhcp(5, opt(12, b'very-long-'), opt(12, b'host-name'))))
    ds = dns('a.example.com') + dns('b.example.org')
    add(s2c(dhcp(5, opt(119, ds[:7]), opt(119, b''), opt(119, ds[7:]))))
    # Unregistered option 224 split; reassembled data is shown raw
    add(s2c(dhcp(5, opt(224, b'\x01\x02'), opt(224, b'\x03\x04'))))
    # Option split between the options field, the file field and sname
    add(s2c(dhcp(5, opt(52, b'\x03'), opt(15, b'split.'),
                 file=opt(15, b'exam') + END, sname=opt(15, b'ple.com') + END)))

# ---- 4. Basic-type options
with section('Every basic-type option (ipv4, lists, strings, booleans, bytes, shorts, times)'):
    allb = []
    for t, codes in BASIC.items():
        for c in codes:
            allb.append(opt(c, basic_value(t, c)))
    # split into frames of about 20 options
    for i in range(0, len(allb), 20):
        add(s2c(dhcp(5, *allb[i:i + 20])))

with section('Options without a dissector (opaque; 224-234 decode with the dhcpuat profile)'):
    codes = [80, 84, 88, 89, 95, 96, 98, 102, 109, 110, 111, 115, 126, 127, 128, 129,
             135, 139, 140, 141, 143, 144, 149, 163, 175, 176, 177, 208, 213, 220,
             221, 222, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 254]
    vals = {225: ip4('192.0.2.1') + ip4('192.0.2.2'), 226: b'custom string',
            227: b'\x01\x02\x03', 228: b'\x01', 229: b'\x07', 230: b'\x01\x02',
            231: b'\x00\x01\x00\x02', 232: b'\x00\x00\x01\x00',
            233: b'\xff\xff\xff\x00', 234: b'\x00\x00\x0e\x10', 224: ip4('192.0.2.224'),
            80: b''}
    o = [opt(c, vals.get(c, bytes([c, c]))) for c in codes]
    add(s2c(dhcp(5, *o[:22])))
    add(s2c(dhcp(5, *o[22:])))

# ---- 5. Special options
with section('Options 21, 33, 78, 79, 85, 93, 94, 145, 151, 152, 154, 155, 158, 159'):
    add(s2c(dhcp(5,
        opt(21, ip4('192.0.2.0') + ip4('255.255.255.0') + ip4('198.51.100.0') + ip4('255.255.255.0')),
        opt(33, ip4('203.0.113.0') + ip4('192.0.2.1')),
        opt(78, b'\x80\x00' + ip4('192.0.2.10') + ip4('192.0.2.11')),
        opt(79, b'\x00DEFAULT,scope2'),
        opt(85, ip4('192.0.2.20') + ip4('192.0.2.21')),
        opt(93, b'\x00\x00\x00\x07\x00\x0b\x00\x29\x00\x30'),
        opt(94, b'\x01\x02\x01'),
        opt(145, b'\x01\x02'),
        opt(151, b'\x00Success'),
        opt(152, b'\xe9\x00\x00\x00'),
        opt(154, b'\xe9\x00\x10\x00'),
        opt(155, b'\xe9\x00\x20\x00'),
        opt(158, b'\x05' + ip4('192.0.2.30') + b'\x09' + ip4('192.0.2.31') + ip4('192.0.2.32')),
        opt(159, b'\x06\x08\x12\x34'),
    )))
    add(s2c(dhcp(5,
        opt(78, b'\x00' + ip4('192.0.2.12')),
        opt(94, b'\x02\x00\x00'),
        opt(151, b'\x01'),
        opt(93, b'\x00\x09'),   # ambiguous EFI BC/x64 (warning)
    )))
    add(s2c(dhcp(5, opt(78, b'\x80'))))

with section('Option 61 / 97 client identifier variants'):
    for cid in (
        b'\x01' + CLIENT_MAC,                                 # Ethernet
        b'\x06' + CLIENT_MAC,                                 # IEEE 802
        b'\x07' + b'\x11\x22\x33\x44\x55\x66',                # ARCNET hw type
        b'\x00' + bytes(range(16)),                           # UUID
        b'\xff\x00\x00\x00\x01\x00\x01\x00\x01\x2a\x5b\x3c\x4d' + CLIENT_MAC,  # DUID-LLT Ethernet
        b'\xff\x00\x00\x00\x02\x00\x01\x00\x06\x2a\x5b\x3c\x4d',               # DUID-LLT, no address
        b'\xff\x00\x00\x00\x03\x00\x01\x00\x20\x2a\x5b\x3c\x4d\x01\x02\x03\x04',  # DUID-LLT other hw
        b'\xff\x00\x00\x00\x04\x00\x02\x00\x00\x01\x37\xde\xad\xbe\xef',       # DUID-EN with id
        b'\xff\x00\x00\x00\x05\x00\x03\x00\x01' + CLIENT_MAC,                  # DUID-LL Ethernet
        b'\xff\x00\x00\x00\x06\x00\x03\x00\x01',                               # DUID-LL, no address
        b'\xff\x00\x00\x00\x07\x00\x03\x00\x07\x0a\x0b',                       # DUID-LL other hw
        b'\xff\x00\x00\x00\x08\x00\x04' + bytes(range(16)),                    # DUID-UUID (not decoded)
        b'\x00client.example',                                # type 0 string
        b'\x05\x01\x02',                                      # opaque
        b'',                                                  # empty
    ):
        add(c2s(dhcp(1, opt(61, cid))))
    for cid in (b'\x01' + CLIENT_MAC, b'\x06' + CLIENT_MAC, b'\x07' + b'\x11\x22\x33\x44\x55\x66',
                b'\x00' + bytes(range(16)), b'\x00\x01\x02', b''):
        add(c2s(dhcp(1, opt(97, cid))))

with section('Option 63 NetWare/IP, 77 user class, 81 client FQDN, 83 iSNS'):
    add(s2c(dhcp(5, opt(63,
        b'\x01\x00' + b'\x02\x00' + b'\x03\x00' + b'\x04\x00' + b'\x05\x01\x01' +
        b'\x06\x08' + ip4('192.0.2.40') + ip4('192.0.2.41') + b'\x07\x04' + ip4('192.0.2.42') +
        b'\x08\x01\x03' + b'\x09\x01\x05' + b'\x0a\x01\x00' + b'\x0b\x04' + ip4('192.0.2.43') +
        b'\x00\x02\xaa\xbb' + b'\x0c\x01\x00'),
        opt(62, b'nwip.example'))))
    # User class: RFC 3004 instances, Microsoft binary format, and plain text
    add(c2s(dhcp(1, opt(77, b'\x05class\x03abc'))))
    ms = (struct.pack('!H', 3) + b'\x01\x02\x03' + b'\0' +
          struct.pack('!H', 8) + 'Name'.encode('utf-16-le') +
          struct.pack('!H', 4) + 'Ds'.encode('utf-16-le') +
          struct.pack('!H', 4) + b'\x0a\x0b\x0c\x0d' +
          struct.pack('!H', 2) + 'N'.encode('utf-16-le') + struct.pack('!H', 0))
    add(c2s(dhcp(8, opt(77, ms), vc=b'MSFT 5.0')))
    add(c2s(dhcp(1, opt(77, b'iPXE'))))
    # Client FQDN: wire format (E bit), ASCII, and flags/rcodes only
    add(c2s(dhcp(3, opt(81, b'\x05\x00\x00' + dns('client1.example.com')))))
    add(c2s(dhcp(3, opt(81, b'\x0b\xff\xff' + b'client2.example.com'))))
    add(s2c(dhcp(5, opt(81, b'\x03\x00\x00'))))
    # iSNS: all bitmaps enabled with heartbeat and secondary servers; then
    # bitmaps not enabled but with other bits set (notes); minimal
    add(s2c(dhcp(5, opt(83,
        b'\x00\x07' + b'\x00\x3f' + b'\x00\x0f' + b'\x00\x00\x00\x7f' +
        ip4('192.0.2.50') + ip4('192.0.2.51') + ip4('192.0.2.52') + ip4('192.0.2.53')))))
    add(s2c(dhcp(5, opt(83,
        b'\x00\x06' + b'\x00\x3e' + b'\x00\x0e' + b'\x00\x00\x00\x7e' + ip4('192.0.2.51')))))
    add(s2c(dhcp(5, opt(83,
        b'\x00\x01' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00\x00\x01' + ip4('192.0.2.51')))))

with section('Option 90 authentication'):
    rd = b'\x00\x00\x00\x00\x00\x00\x00\x01'
    # Delayed authentication, HMAC-MD5, monotonic counter: Discover has no
    # secret id/hash; Offer carries them (opaque test bytes, not a real MAC)
    add(c2s(dhcp(1, opt(90, b'\x01\x01\x00' + rd))))
    add(s2c(dhcp(2, opt(90, b'\x01\x01\x00' + rd + b'\x00\x00\x00\x2a' + bytes(range(16))))))
    # Delayed authentication, other algorithm, other RDM, with and without info
    add(s2c(dhcp(5, opt(90, b'\x01\x02\x01' + b'RDVALUE1' + b'info'))))
    add(s2c(dhcp(5, opt(90, b'\x01\x02\x01' + b'RDVALUE1'))))
    # Configuration token protocol with and without a token
    add(s2c(dhcp(5, opt(90, b'\x00\x00\x00' + rd + b'token'))))
    add(s2c(dhcp(5, opt(90, b'\x00\x00\x00' + rd))))

with section('Options 99, 114, 117, 119, 120, 121, 146, 160, 162, 212, 249'):
    add(s2c(dhcp(5,
        opt(99, b'\x00US' + b'\x01\x02CA' + b'\x00\x00' + b'\x03\x07Anytown' + b'\x80\x00'),
        opt(114, b'https://portal.example/'),
        opt(117, b'\x00\x00\x00\x06\x00\x29\x00\x2c\x00\x41'),
        opt(119, dns('example.com') + b'\x03sub\xc0\x00'),
        opt(121, b'\x18' + ip4('192.0.2.0')[:3] + ip4('192.0.2.1') + b'\x00' + ip4('192.0.2.1') +
            b'\x20' + ip4('203.0.113.5') + ip4('192.0.2.1') + b'\x09\x80\x00' + ip4('192.0.2.1')),
        opt(146, b'\x02' + ip4('192.0.2.53') + ip4('192.0.2.54') + dns('dns.example')),
        opt(160, b'http://polycom.example/'),
        opt(249, b'\x10\xc6\x33' + ip4('192.0.2.1')),
    )))
    add(s2c(dhcp(5, opt(120, b'\x00' + dns('sip1.example.com') + dns('sip2.example.com')))))
    add(s2c(dhcp(5, opt(120, b'\x01' + ip4('192.0.2.60') + ip4('192.0.2.61')))))
    # DNR: ADN-only instance, then one with addresses and service parameters
    i1 = struct.pack('!H', 1) + bytes([len(dns('resolver.example'))]) + dns('resolver.example')
    svc = struct.pack('!HH', 1, 4) + b'\x03dot' + struct.pack('!HH', 3, 2) + struct.pack('!H', 853)
    adn = dns('dot.example')
    addrs = ip4('192.0.2.70') + ip4('192.0.2.71')
    i2 = struct.pack('!H', 2) + bytes([len(adn)]) + adn + bytes([len(addrs)]) + addrs + svc
    add(s2c(dhcp(5, opt(162, struct.pack('!H', len(i1)) + i1 + struct.pack('!H', len(i2)) + i2))))
    # 6RD with one and with three border relays
    sixrd = b'\x10\x20' + b'\x20\x01\x0d\xb8' + b'\0' * 12 + ip4('192.0.2.80')
    add(s2c(dhcp(5, opt(212, sixrd))))
    add(s2c(dhcp(5, opt(212, sixrd + ip4('192.0.2.81') + ip4('192.0.2.82')))))


def lci(lat, lon, alt, lat_res=30, lon_res=30, alt_type=1, alt_res=24, datum=1,
        lat_raw=None, lon_raw=None, alt_raw=None):
    la = lat_raw if lat_raw is not None else int(round(lat * (1 << 25)))
    lo = lon_raw if lon_raw is not None else int(round(lon * (1 << 25)))
    al = alt_raw if alt_raw is not None else int(round(alt * (1 << 8)))
    la &= (1 << 34) - 1
    lo &= (1 << 34) - 1
    al &= (1 << 30) - 1
    b = bytearray(16)
    v = (lat_res << 34) | la
    b[0:5] = v.to_bytes(5, 'big')
    v = (lon_res << 34) | lo
    b[5:10] = v.to_bytes(5, 'big')
    v = (alt_type << 36) | (alt_res << 30) | al
    b[10:15] = v.to_bytes(5, 'big')
    b[15] = datum
    return bytes(b)


with section('Option 123 coordinate-based location (RFC 3825 LCI) and CableLabs DSS_ID'):
    for l in (
        lci(37.375, -121.9375, 15.5),                       # positive latitude, negative longitude
        lci(-33.875, 151.25, -20.25, lat_res=5, lon_res=8, alt_res=10, datum=2),  # negative lat & alt
        lci(48.5, 2.25, 3.0, alt_type=2, alt_res=0, datum=3),   # floors
        lci(10.0, 20.0, 0.0, alt_type=0, alt_res=0),            # unknown altitude type
        lci(91.0, 0.0, 0.0),                                    # latitude out of range
        lci(10.0, 0.0, 0.0, lat_res=35),                        # latitude uncertainty
        lci(10.0, 181.0, 0.0),                                  # longitude out of range
        lci(10.0, 10.0, 0.0, lon_res=40),                       # longitude uncertainty
        lci(10.0, 10.0, 0.0, alt_raw=(1 << 29) - 1),            # altitude out of range
        lci(10.0, 10.0, 0.0, alt_res=31),                       # altitude uncertainty
        lci(10.0, 10.0, 2.0, alt_type=2, alt_res=5),            # floors with bad uncertainty
        lci(10.0, 10.0, 0.0, alt_type=3),                       # altitude type invalid
        lci(10.0, 10.0, 0.0, datum=0),                          # datum invalid
        lci(10.0, 10.0, 0.0, datum=4),
    ):
        add(s2c(dhcp(5, opt(123, l))))
    add(s2c(dhcp(5, opt(123, b'\x01\x08dss1.exa'))))

with section('Option 82 relay agent information, every suboption'):
    radius = b'\x01\x05bob' + b'\x1a\x0c\x00\x00\x00\x09\x01\x06abcd'
    cl = (b'\x01\x04' + b'\x01\x02\x03\x00' +     # superseded format (option code+len)
          b'\x01\x02\x03\x01' + b'\x02\x02\x02\x00' + b'\x04\x03\x01\x02\x03' +
          b'\x05\x04gold' + b'\x06\x03MSO' + b'\x07\x0ehttps://a.b/cd')
    vi = struct.pack('!IB', 4491, len(cl)) + cl + struct.pack('!IB', 9, 3) + b'\x01\x02\x03'
    add(c2s(dhcp(1, opt(82,
        b'\x01\x05eth0/' + b'\x02\x06' + CLIENT_MAC + b'\x03\x01\x00' +
        b'\x04\x04\x00\x00\x00\x01' + b'\x05\x04' + ip4('192.0.2.0') +
        b'\x06\x04subs' + bytes([7, len(radius)]) + radius + b'\x08\x04auth'),
        hops=1, giaddr='192.0.2.254'), sport=67, src='192.0.2.254', dst='192.0.2.1',
        dmac=SERVER_MAC))
    add(c2s(dhcp(1, opt(82,
        bytes([9, len(vi)]) + vi + b'\x0a\x01\x80' + b'\x0b\x04' + ip4('192.0.2.1') +
        b'\x0c\x03rid' + b'\x0d\x02\x00\x03' + b'\x0e\x03net' + b'\x0f\x02ap' +
        b'\x10\x06' + b'\x02\x00\x00\x00\x00\x09' + b'\x11\x03op1' + b'\x12\x05realm' +
        b'\x13\x00' + b'\x96\x04' + ip4('192.0.2.0') + b'\x97\x01\xff' + b'\x98\x04' +
        ip4('192.0.2.1') + b'\x00\x00' + b'\x64\x02\x01\x02'),
        hops=1, giaddr='192.0.2.254'), sport=67, src='192.0.2.254', dst='192.0.2.1',
        dmac=SERVER_MAC))
    add(c2s(dhcp(1, opt(82, b'\x97\x07' + b'\x00\x00\x01' + b'\x00\x00\x00\x05' +
                         b'\x97\x04blue'), giaddr='192.0.2.254'),
            sport=67, src='192.0.2.254', dst='192.0.2.1', dmac=SERVER_MAC))

with section('Option 43 vendor-specific: PXEClient'):
    pxe = (b'\x01\x04' + ip4('224.0.1.1') + b'\x02\x02\xe8\x03' + b'\x03\x02\xe9\x03' +
           b'\x04\x01\x05' + b'\x05\x01\x0a' + b'\x06\x01\x0f' + b'\x07\x04' + ip4('224.0.1.2') +
           b'\x08\x0e' + b'\x80\x00\x01' + ip4('192.0.2.1') + b'\x80\x01\x01' + ip4('192.0.2.2') +
           b'\x09\x0c' + b'\x80\x00\x04Boot' + b'\x80\x01\x02HD' +
           b'\x0a\x06\x0aPress' + b'\x0b\x03\x01\x02\x03' + b'\x0c\x02\x00\x01' +
           b'\x47\x04\x80\x00\x00\x00' + b'\x00')
    add(s2c(dhcp(2, opt(43, pxe + END), vc=b'PXEClient', siaddr='192.0.2.1')))
    lcm = (b'\xb3\x03lcm' + b'\xb4\x03dom' + b'\xb5\x02\x01\x02' + b'\xbe\x02wg' +
           b'\xbf\x01\x01' + b'\xc0\x01\x00' + b'\xc1\x04\x00\x00\x00\x02' + b'\xc2\x03SN1')
    add(s2c(dhcp(2, opt(43, lcm), vc=b'PXEClient')))

with section('Option 43 vendor-specific: CableLabs (docsis, pktc, CableHome, OpenCable2.0, RPD, ECM, ...)'):
    clo = (b'\x01\x03\x02\x04\x05' + b'\x02\x04ECM:' + b'\x03\x04\x45\x43\x4d\x00' +
           b'\x04\x03SN0' + b'\x05\x02HW' + b'\x06\x02SW' + b'\x07\x02BR' +
           b'\x08\x03\x00\x10\x18' + b'\x09\x02MN' + b'\x0a\x02VN' + b'\x0b\x01\x01' +
           b'\x0c\x02SD' + b'\x0d\x02FR' + b'\x0e\x02FW' + b'\x0f\x02CF' + b'\x10\x01\x00' +
           b'\x12\x02VS' + b'\x00')
    clo2 = (b'\x08\x06001018' + b'\x1f\x06' + CLIENT_MAC + b'\x20\x04\x00\x00\x00\x07' +
            b'\x21\x01\x00' + b'\x33\x02VN' + b'\x34\x02\x01\x02' + b'\x35\x02\x03\x04' +
            b'\x36\x03X50' + b'\x37\x01\x00' + b'\x80\x02\xaa\xbb' + END + b'junk')
    for vc in (b'docsis3.0', b'pktc1.0', b'CableHome1.0', b'OpenCable2.0', b'RPD',
               b'RMD', b'ECM', b'PTA', b'DEMARC', b'TR', b'SROUTER'):
        add(c2s(dhcp(1, opt(43, clo if vc in (b'docsis3.0', b'CableHome1.0') else clo2), vc=vc)))

with section('Option 43 vendor-specific: Aruba AP, Aruba Instant AP, Apple BSDP, Cisco, Aerohive, Alcatel-Lucent, generic'):
    add(s2c(dhcp(5, opt(43, b'192.0.2.90'), vc=b'ArubaAP')))
    add(s2c(dhcp(5, opt(43, b'org1,192.0.2.91,secret'), vc=b'ArubaInstantAP')))
    bsdp = (b'\x01\x01\x01' + b'\x02\x02\x01\x01' + b'\x03\x04' + ip4('192.0.2.1') +
            b'\x04\x02\x80\x00' + b'\x05\x02\x03\x20' + b'\x06\x05/path' +
            b'\x07\x04\x81\x00\x10\x01' + b'\x08\x04\x01\x00\x10\x02' +
            b'\x09\x15' + b'\x81\x00\x10\x01\x05Image' + b'\x01\x00\x10\x02\x00' +
            b'\x01\x00\x10\x03\x01X' +
            b'\x0a\x00' + b'\x0b\x04\x01\x00\x81\x00' + b'\x0c\x02\x05\xdc' +
            b'\x0d\x01\x00' + b'\x00' + END)
    add(c2s(dhcp(8, opt(43, bsdp), vc=b'AAPLBSDPC/i386/MacPro3,1'), src='192.0.2.100'))
    cisco = (b'\x01\x01\x03' + b'\x02\x01\x01' + b'\x03\x02\x00\x01' + b'\x04\x04\x00\x00\x00\xca' +
             b'\x05\x01\x01' + b'\x06\x01\x01' + b'\x07\x05N9K-C' + b'\x08\x04uuid' +
             b'\x09\x04fab1' + b'\x0a\x04\x00\x00\x00\x01' + b'\x0b\x03SAL' +
             b'\x0c\x0aeth1/20.20' + b'\x0d\x02\x01\x02')
    add(c2s(dhcp(1, opt(43, cisco), vc=b'cisco')))
    add(s2c(dhcp(5, opt(43, b'\xe1\x08xiq.host' + b'\xe2\x04' + ip4('192.0.2.92') +
                         b'\xe3\x01\x00'), vc=b'AEROHIVE')))
    add(s2c(dhcp(5, opt(43, b'\x3a\x02\x00\x64' + b'\x40\x04' + ip4('192.0.2.93') +
                         b'\x41\x04' + ip4('192.0.2.94') + b'\x42\x01\x01' +
                         b'\x43\x07sip:a.b' + b'\x00' + END))))
    # Generic RFC 2132 encapsulated options (padding, end) and plain bytes
    add(s2c(dhcp(5, opt(43, b'\x00\x01\x02\xaa\xbb\x02\x00' + END + b'\x99'))))
    add(s2c(dhcp(5, opt(43, b'\x01\x05\xaa'))))
    add(s2c(dhcp(5, opt(43, b'\x01'))))
    # Starts like Alcatel-Lucent (58) but with the wrong length: generic
    add(s2c(dhcp(5, opt(43, b'\x3a\x03\x00\x01\x02'))))

with section('Option 60 vendor class identifier: PacketCable MTA capabilities'):
    def mta(prefix, tlvs):
        body = b''.join(t + b'%02X' % (len(v) // 2) + v for t, v in tlvs)
        return prefix + b'05' + b'%02X' % (len(body) // 2) + body
    tl1 = [(b'01', b'02'), (b'02', b'02'), (b'03', b'01'), (b'04', b'00'), (b'05', b'01'),
           (b'06', b'01'), (b'07', b'00'), (b'08', b'0102'), (b'09', b'01'), (b'0A', b'01'),
           (b'0a', b'00'), (b'0B', b'0306090F'), (b'0b', b'10'), (b'0C', b'01'), (b'0c', b'01'),
           (b'0D', b'01'), (b'0d', b'00'), (b'0E', b'01'), (b'0e', b'01'), (b'0F', b'01'),
           (b'0f', b'01'), (b'10', b'09'), (b'11', b'01'), (b'12', b'0007')]
    tl2 = [(b'01', b'01'), (b'13', b'02'), (b'14', b'01'), (b'15', b'01'), (b'16', b'00'),
           (b'17', b'02003F02010702020F02030F'), (b'18', b'01'), (b'19', b'01'),
           (b'1A', b'01'), (b'1a', b'00'), (b'1F', b'ABCD'), (b'01', b'99'),
           (b'13', b'99'), (b'14', b'99')]
    add(c2s(dhcp(1, vc=mta(b'pktc1.0:', tl1))))
    add(c2s(dhcp(1, vc=mta(b'pktc1.5:', tl2))))
    add(c2s(dhcp(1, vc=mta(b'pktc2.0:', [(b'01', b'02'), (b'0B', b'99'), (b'03', b'99')]))))

with section('Option 60: DOCSIS cable modem capabilities, DOCSIS 3.0, Apple BSDP client, other'):
    def cm(prefix, tlvs):
        body = b''.join(b'%02X' % t + b'%02X' % len(v) + v.hex().upper().encode() for t, v in tlvs)
        return prefix + b'05' + b'%02X' % (len(body) // 2) + body
    cm1 = [(1, b'\x01'), (2, b'\x02'), (3, b'\x01'), (4, b'\x00'), (5, b'\x01'), (6, b'\x01'),
           (7, b'\x10'), (8, b'\x10'), (9, b'\x01'), (10, b'\x02'), (11, b'\x18'), (12, b'\x01')]
    add(c2s(dhcp(1, vc=cm(b'docsis1.1:', cm1))))
    add(c2s(dhcp(1, vc=cm(b'docsis2.0:', [(0x0d, b'\x00\x40'), (0x0e, b'\x00\x0a'), (0x10, b'\x00\x01\x00\x07')]))))
    add(c2s(dhcp(1, vc=b'docsis3.0:053F0105')))
    add(c2s(dhcp(1, vc=b'AAPLBSDPC/i386/iMac')))
    add(c2s(dhcp(1, vc=b'android-dhcp-14')))

with section('Option 122 CableLabs client configuration (RFC 3495, default preference)'):
    ccc = (b'\x01\x04' + ip4('192.0.2.1') + b'\x02\x04' + ip4('192.0.2.2') +
           b'\x03' + bytes([1 + len(dns('prov.example'))]) + b'\x00' + dns('prov.example') +
           b'\x04\x0c' + struct.pack('!III', 1, 2, 3) + b'\x05\x0c' + struct.pack('!III', 4, 5, 6) +
           b'\x06' + bytes([len(dns('REALM.EXAMPLE'))]) + dns('REALM.EXAMPLE') +
           b'\x07\x01\x01' + b'\x08\x01\x28' + b'\x09\x02\x00\x03' + b'\x0d\x01\x00')
    add(s2c(dhcp(5, opt(122, ccc))))
    ccc2 = (b'\x01\x05' + ip4('192.0.2.1') + b'\x00' + b'\x03\x05\x01' + ip4('192.0.2.3') +
            b'\x03\x02\x02\x00' + b'\x04\x02\x00\x00' + b'\x05\x02\x00\x00' +
            b'\x07\x01\x00' + b'\x08\x02\x05\x00' + b'\x09\x01\x01' + b'\x07\x02\x01\x00')
    add(s2c(dhcp(5, opt(122, ccc2))))

with section('Option 122 with PKT-SP-PROV-I05 and IETF draft 5 contents (decode with the preference)'):
    i05 = (b'\x01\x04dhc1' + b'\x02\x04dhc2' + b'\x03\x04snmp' + b'\x04\x04dns1' +
           b'\x05\x04dns2' + b'\x06\x07\x05REALM\x00' + b'\x0a\x02\x00\x00' +
           b'\x0b\x02\x00\x00' + b'\x0c\x00' + b'\x07\x00' + b'\x07\x01\x01' +
           b'\x08\x01\x28' + b'\x09\x03cms' + b'\x0a\x0c' + struct.pack('!III', 1, 2, 3) +
           b'\x0b\x0c' + struct.pack('!III', 4, 5, 6) + b'\x0c\x01\x02' + b'\x0d\x01\x00')
    add(s2c(dhcp(5, opt(122, i05))))
    add(s2c(dhcp(5, opt(122, b'\x08\x01\x1f' + b'\x08\x01\x05'))))

with section('Option 124 V-I vendor class and 125 V-I vendor-specific information'):
    add(c2s(dhcp(1, opt(124, b'\x01'))))
    vcd = b'\x04abcd\x02xy'
    add(c2s(dhcp(1, opt(124, struct.pack('!IB', 4491, len(vcd)) + vcd +
                         struct.pack('!IB', 3561, 4) + b'\x08abc' +   # whole-option length only
                         struct.pack('!IB', 9, 0)))))
    modem = bytes([1, 1, 1, 2, 1, 3, 3, 1, 1, 4, 1, 1, 5, 1, 0, 6, 1, 1, 7, 1, 16, 8, 2, 0x01, 0x00,
                   9, 1, 1, 10, 1, 2, 10, 1, 3, 11, 1, 24, 11, 1, 70, 12, 1, 1, 13, 2, 0, 64,
                   14, 2, 0, 10, 15, 1, 1, 16, 4, 0, 1, 0, 15, 16, 2, 0, 1,
                   17, 1, 1, 18, 7, 0x10, 2, 0, 0, 0, 0, 1, 18, 2, 1, 2, 19, 1, 1, 20, 1, 1,
                   21, 1, 0x3f, 22, 1, 1, 23, 1, 0, 24, 1, 4, 25, 1, 4, 26, 1, 4, 27, 1, 8,
                   28, 1, 2, 29, 1, 4, 30, 1, 32, 31, 1, 16, 32, 1, 16, 33, 1, 1, 34, 1, 1,
                   35, 1, 1, 36, 1, 1, 37, 1, 1, 38, 1, 64, 39, 1, 1, 40, 1, 0, 40, 1, 210,
                   40, 1, 250, 41, 4, 0, 0, 0xff, 0xff, 41, 1, 0, 42, 2, 0, 0, 44, 1, 0,
                   43, 1, 0, 50, 0])
    modem2 = bytes([0x20, 1, 4, 0x1c, 1, 9, 0x1e, 2, 1, 0, 0x07, 2, 1, 0])
    cl125 = (b'\x01\x03\x02\x04\x05' + b'\x02\x08' + ip4('192.0.2.1') + ip4('192.0.2.2') +
             b'\x03\x02\x01\x02' + b'\x04\x01\x02' + bytes([5, len(modem)]) + modem +
             b'\x06\x01\x00' + b'\x00\x01\x00' + b'\x02\x00' + b'\x03\x00')
    add(c2s(dhcp(1, opt(125, struct.pack('!IB', 4491, len(cl125)) + cl125))))
    add(c2s(dhcp(1, opt(125, struct.pack('!IB', 4491, len(modem2) + 2) + bytes([5, len(modem2)]) + modem2))))
    tr = (b'\x01\x06' + b'00D0B7' + b'\x02\x03SN1' + b'\x03\x03CPE' + b'\x04\x06001122' +
          b'\x05\x03SN2' + b'\x06\x02GW' + b'\x07\x01\x00' + b'\x00\x01\x00')
    gen = b'\x01\x02\xaa\xbb\x02\x00'
    add(c2s(dhcp(1, opt(125, struct.pack('!IB', 3561, len(tr)) + tr +
                         struct.pack('!IB', 9, len(gen)) + gen))))

with section('Option 242 Avaya IP telephone'):
    av = (b'MCIPADD=192.0.2.1,192.0.2.2,MCPORT=1719,TLSSRVR=192.0.2.3,HTTPSRVR=192.0.2.4,'
          b'HTTPDIR=dir,STATIC=0,DOT1X=1,ICMPDU=1,ICMPRED=0,L2Q=1,L2QVLAN=10,LOGLOCAL=0,'
          b'PHY1STAT=1,PHY2STAT=2,PROCPSWD=1234,PROCSTAT=0,SNMPADD=192.0.2.5,SNMPSTRING=public,'
          b'VLANTEST=60')
    av = av.replace(b'MCPORT=1719,', b'')
    add(s2c(dhcp(5, opt(242, av[:250]))))
    add(s2c(dhcp(5, opt(242, b'STATIC=9,DOT1X=7,ICMPDU=7,ICMPRED=7,L2Q=7,LOGLOCAL=7,PHY1STAT=7,PROCSTAT=7'))))

with section('Reproducers of the fixed bugs (dhcp_small_fixes.py)'):
    # 1 opt 61 type 255 DUID-EN, 11 bytes
    add(c2s(dhcp(1, opt(61, b'\xff\x00\x00\x00\x01\x00\x02\x00\x00\x01\x37'))))
    # 2 opt 123 CableLabs DSS_ID with two IDs
    add(c2s(dhcp(1, opt(123, b'\x01\x05abcde' + b'\x02\x03xyz'))))
    # 3 opt 242 Avaya L2QVLAN=10
    add(c2s(dhcp(1, opt(242, b'L2QVLAN=10,L2Q=1'))))
    # 4 opt 82.9 CableLabs tag 4 (PBB service) then tag 6
    cl = b'\x04\x02\xaa\xbb' + b'\x06\x03MSO'
    s9 = struct.pack('!IB', 4491, len(cl)) + cl
    add(c2s(dhcp(1, opt(82, bytes([9, len(s9)]) + s9))))
    # 5 opt 60 pktc1.0: TLV 01 (version) value "12"
    add(c2s(dhcp(1, vc=b'pktc1.0:' + b'0503' + b'010112')))
    # 6 opt 122 (I05 with the preference): suboption length, AP-REQ backoff
    add(c2s(dhcp(1, opt(122, b'\x01\x03abc' + b'\x0b\x0c' + bytes(range(1, 13))))))
    # 7 opt 122 (RFC 3495): TGT flag with length 2, then provisioning timer
    add(c2s(dhcp(1, opt(122, b'\x07\x02\x01\x00' + b'\x08\x01\x05'))))

REPRO_FIRST = sections[-1][0]

# ---------------------------------------------------------------- malformed
# One bad option per frame: a repeated option code would be concatenated
# as an RFC 3396 long option.

def mbad(code, data, vc=None, msgtype=5):
    madd(s2c(dhcp(msgtype, opt(code, data), vc=vc)))


with msection('Basic types with wrong lengths'):
    for code, data in ((1, b'\x01\x02\x03'), (3, b'\x01\x02\x03\x04\x05'), (19, b'\x01\x02'),
                       (23, b''), (13, b'\x01'), (25, b'\x01\x02\x03'), (2, b'\x01'),
                       (51, b'\x01'), (232, b'\x01')):
        mbad(code, data)

with msection('Special options with bad lengths or values'):
    for code, data in (
            (21, b'\x01\x02\x03'), (33, b'\x01'), (52, b''), (77, b'\x01'), (77, b'\x01a\x00'),
            (78, b''), (78, b'\x00\x01\x02'), (81, b'\x01'), (85, b'\x01\x02\x03\x04\x05'),
            (90, b'\x01'), (90, b'\x01\x01\x00' + b'\0' * 8 + b'\x01\x02'),
            (93, b'\x00\x01\x02'), (117, b'\x00'), (117, b'\x00\x00\x00'), (117, b'\x00\x05'),
            (120, b'\x00\x01'), (120, b'\x01\x01\x02'), (120, b'\x01\x01\x02\x03\x04\x05'),
            (120, b'\x02\x00'), (121, b'\x01'), (121, b'\x21\x00\x00\x00\x00'),
            (121, b'\x18\x01\x02\x03\x04'), (123, b'\x00' * 70),
            (124, b'\x00\x00\x00\x09\x05\x01'), (124, b'\x00\x00'),
            (125, b'\x00\x00\x00\x09\x05\x01'), (125, b'\x00\x00\x00\x09\x00\x01'),
            (146, b'\x00' * 3), (151, b''), (152, b'\x01'), (154, b'\x01'), (155, b'\x01'),
            (158, b'\x01'), (159, b'\x01'), (212, b'\x01'), (212, b'\x00' * 23),
            (242, b'ab'), (242, b'abcdef'), (242, b'FOO=1,BAR'), (242, b'L2QVLAN=xx,VLANTEST=yy'),
            (83, b'\x00'), (83, b'\x00\x00\x00\x00\x00\x03' + b'\x00' * 8),
            (99, b'\x00US\x01\x05ab'), (162, b'\x00'), (63, b'\x05'), (63, b'\x01\x01\x00'),
            (82, b'\x01'), (82, b'\x01\x05ab'),
            (82, b'\x09\x08' + struct.pack('!IB', 4491, 2) + b'\x09\x00'),
    ):
        mbad(code, data)
    madd(c2s(dhcp(3, opt(90, b'\x01\x01\x00' + b'\0' * 8 + b'\x01\x02'))))
    # DNR instance errors
    for inst in (b'\x00\x02\x00\x01', b'\x00\x09\x00\x01\x00', b'\x00\x04\x00\x01\x05\x00',
                 b'\x00\x03\x00\x01\x00', b'\x00\x08\x00\x01\x02\x01a\x03\x01\x02',
                 b'\x00\x05\x00\x01\x02\x01a'):
        mbad(162, inst)

with msection('Vendor suboption errors (43, 60, 122, 125)'):
    for vc, v in ((b'PXEClient', b'\x01'), (b'PXEClient', b'\x0d\x01\x00'),
                  (b'PXEClient', b'\xc8\x01\x00'), (b'PXEClient', b'\x02\x01\x00'),
                  (b'PXEClient', b'\x04\x02\x00\x00'), (b'docsis3.0', b'\x01'),
                  (b'docsis3.0', b'\x02\x05ab'), (b'docsis3.0', b'\x08\x02ab'),
                  (b'docsis3.0', b'\x1f\x02ab'), (b'docsis3.0', b'\x0b\x02ab'),
                  (b'AAPLBSDPC', b'\x01'), (b'AAPLBSDPC', b'\x01\x05\x01'),
                  (b'cisco', b'\x01'), (b'cisco', b'\x01\x05\x01'),
                  (b'AEROHIVE', b'\xe1'), (b'AEROHIVE', b'\xe1\x05ab'),
                  (None, b'\x3a\x02\x00\x01\x3b\x00'), (None, b'\x01\x03ab')):
        mbad(43, v, vc=vc)
    for v in (struct.pack('!IB', 4491, 1) + b'\x01', struct.pack('!IB', 4491, 3) + b'\x01\x05\x00',
              struct.pack('!IB', 3561, 1) + b'\x01', struct.pack('!IB', 3561, 3) + b'\x01\x05\x00',
              struct.pack('!IB', 9, 1) + b'\x01', struct.pack('!IB', 9, 3) + b'\x01\x05\x00',
              struct.pack('!IB', 4491, 3) + b'\x02\x01\x00'):
        mbad(125, v)
    # RFC 3495 (default) errors, then I05 errors (with the preference)
    for c in (b'\x01', b'\x01\x04\x01', b'\x03\x00', b'\x03\x02\x01\x01', b'\x04\x02\x00\x00',
              b'\x06\x00', b'\x07\x01', b'\x08\x01', b'\x09\x01\x00', b'\x03\x01\x00'):
        mbad(122, c)
    for c in (b'\x07\x01', b'\x08\x01', b'\x0a\x01\x00', b'\x0b\x01\x00', b'\x0c\x01'):
        mbad(122, c)
    # PacketCable MTA capabilities with bogus lengths and MIB bit fields
    for vc in (b'pktc1.0:05zz', b'pktc1.0:0503zz', b'pktc1.0:0506' + b'170303' + b'000000',
               b'pktc1.0:0507' + b'17030200zz'):
        madd(s2c(dhcp(5, vc=vc)))

with msection('Structural errors: missing End, overload without End, RFC 3396 empty, truncated'):
    madd(c2s(dhcp(1, end=False)))
    madd(s2c(dhcp(5, opt(52, b'\x03'), file=opt(15, b'abc'), sname=opt(15, b'def'))))
    madd(s2c(dhcp(5, opt(12, b''), opt(12, b''))))
    madd(s2c(dhcp(5, end=False) + b'\x0c'))
    madd(s2c(dhcp(5, end=False) + b'\x0c\x05ab'))
    madd(s2c(bootp(op=1)[:100]))
    madd(udp_frame(b'\x01\x02\x03', sport=68, dport=4011))


def load_sweep():
    """Frames of the edge-case sweep (dhcp_option_sweep.py)."""
    import runpy
    here = os.path.dirname(os.path.abspath(__file__))
    pass
    import dhcp_common
    got = []
    dhcp_common.write_pcap = lambda path, frs: got.extend(frs)
    runpy.run_path(os.path.join(here, 'dhcp_option_sweep.py'))
    return got


with msection('Edge-case sweep reproducer (dhcp_option_sweep.pcap)'):
    for fr in load_sweep():
        madd(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dhcp-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'dhcp-coverage-malformed.pcap'), mframes)
    print('main: %d frames' % len(frames))
    for a, b, d in sections:
        print('  %d-%d: %s' % (a, b, d))
    print('malformed: %d frames' % len(mframes))
    for a, b, d in msections:
        print('  %d-%d: %s' % (a, b, d))


if __name__ == '__main__':
    main()

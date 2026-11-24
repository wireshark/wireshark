#!/usr/bin/env python3
# Generates test/captures/edonkey_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the eDonkey dissector
(packet-edonkey.c: eDonkey, eMule extensions, Overnet and Kademlia).

eDonkey is registered by default on TCP ports 4661-4663 and UDP ports
4665 and 4672. TCP messages have a 5 octet header (protocol octet 0xe3
eDonkey, 0xc5 eMule extensions or 0xd4 eMule compressed, and a little
endian length) and a message type; UDP messages a protocol and a type
octet (0xe3, 0xc5, Kademlia 0xe4/0xe5 compressed and the KAdu variants
0xa4/0xa5). Every packet is built from scratch with struct (zlib for the
compressed messages); no captured traffic is used. Addresses are from
192.0.2.0/24 and 198.51.100.0/24, hashes are made-up patterns.

Usage: mkedonkey.py <output directory> [-v]   (-v prints frame ranges)

Writes:
  edonkey-coverage.pcap            see FRAMES in the README; every TCP
                                   message type of eDonkey and eMule,
                                   eMule compressed messages, multipacket
                                   entries, meta tags of every type, search
                                   queries, TCP reassembly, every UDP
                                   eDonkey, eMule and Overnet message, every
                                   Kademlia message and tag type, search
                                   expressions, compressed Kademlia, and the
                                   KADEMLIA_PUBLISH_REQ pre-scan of a BSOB
                                   tag (fixed)
  edonkey-coverage-malformed.pcap  messages cut short, an empty list item,
                                   an unknown Kademlia tag type and search
                                   operator (warnings), oversized lengths
"""

import os
import struct
import sys
import zlib

# ---------------------------------------------------------------- frames


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


IDENT = [0]


def ipv4(src, dst, proto, l4):
    IDENT[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), IDENT[0] & 0xffff, 0x4000, 64,
                    proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return bytes([2, 0]) + ip4(dst) + bytes([2, 0]) + ip4(src) + b'\x08\x00' + h + l4


def udp_frame(src, sport, dst, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return ipv4(src, dst, 17, u)


def tcp_seg(src, sport, dst, dport, seq, ack, flags, payload=b''):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
    return ipv4(src, dst, 6, t)


class Tcp:
    """A TCP connection, captured after its handshake (a SYN adds chat and
    scanner expert infos the tests would have to filter out); send() adds
    data segments."""

    def __init__(self, out, cli, cport, srv, sport):
        self.out, self.cli, self.cport, self.srv, self.sport = out, cli, cport, srv, sport
        self.seq = {0: 1000, 1: 5000}

    def send(self, data, from_server=False):
        d = 1 if from_server else 0
        a, ap, b, bp = (self.srv, self.sport, self.cli, self.cport) if d else \
                       (self.cli, self.cport, self.srv, self.sport)
        self.out.append(tcp_seg(a, ap, b, bp, self.seq[d], self.seq[1 - d], 0x18, data))
        self.seq[d] += len(data)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------- eDonkey values


def h16(n):
    """A made-up 16 octet hash."""
    return bytes((n * 17 + i * 11) & 0xff for i in range(16))


def user_hash(n):
    """A client user hash as eMule makes it: octets 5 and 14 are 14 and
    111 (what the dissector checks to tell a client Hello)."""
    h = bytearray(h16(n))
    h[5], h[14] = 0x0e, 0x6f
    return bytes(h)


def u8(v):
    return struct.pack('<B', v)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


def estr(s):
    if isinstance(s, str):
        s = s.encode()
    return u16(len(s)) + s


def addr(ip, port):
    return ip4(ip) + u16(port)


def tag(ttype, name, value):
    """eDonkey meta tag: a one octet special name sets the short form
    (type | 0x80), anything else is a length-prefixed name."""
    if isinstance(name, int):
        return bytes([ttype | 0x80, name]) + value
    if isinstance(name, str):
        name = name.encode()
    return bytes([ttype]) + u16(len(name)) + name + value


def taglist(tags):
    return u32(len(tags)) + b''.join(tags)


def client_info(n, cid, port, tags):
    return user_hash(n) + ip4(cid) + u16(port) + taglist(tags)


def file_info(n, cid, port, tags):
    return h16(n) + cid + u16(port) + taglist(tags)


def tcp_msg(proto, mtype, body=b''):
    return bytes([proto]) + u32(1 + len(body)) + bytes([mtype]) + body


ED, EMULE, ECOMP = 0xe3, 0xc5, 0xd4
KAD, KADC, KADU, KADUC = 0xe4, 0xe5, 0xa4, 0xa5


def udp_msg(proto, mtype, body=b''):
    return bytes([proto, mtype]) + body


ALL_TAGS = [
    tag(0x01, 0x07, h16(40)),                               # hash, Part Hash
    tag(0x02, 0x01, estr('ubuntu-24.04.iso')),              # string, Name
    tag(0x03, 0x02, u32(123456789)),                        # dword, Size
    tag(0x03, 0x10, ip4('192.0.2.99')),                     # dword, IP
    tag(0x03, 'IP', ip4('192.0.2.98')),                     # dword, IP by name
    tag(0x03, 0x91, u32(0x00110002)),                       # dword, Server Version
    tag(0x03, 'srvversion', u32(7)),                        # dword, unknown name
    tag(0x04, 0x15, struct.pack('<f', 1.5)),                # float, Availability
    tag(0x05, 0x0d, b'\x01'),                               # bool, Fail
    tag(0x06, 0x17, u16(9) + b'\xff\x01'),                  # bool array of 9
    tag(0x07, 'blob', u32(3) + b'abc'),                     # blob
    tag(0x08, 0x21, u16(4672)),                             # word, UDP Client Port
    tag(0x09, 0x20, b'\x01'),                               # byte, Compression
    tag(0x11, 0x03, b'A'),                                  # STR1, Type
    tag(0x14, 0x04, b'iso!'),                               # STR4, Format
    tag(0x20, 'Format', b'0123456789abcdef'),               # STR16 by name
    tag(0x02, 0x55, estr('mod 1.0')),                       # Mod Version
    tag(0x02, '\x01', estr('name by long id')),             # long name, special id
    tag(0x00, 0x99, b''),                                   # unknown type 0
]

LONG_NAME_TAGS = [                                          # the same with long names
    tag(0x01, 'hash', h16(41)),
    tag(0x04, 'rating', struct.pack('<f', 4.5)),
    tag(0x05, 'flag', b'\x00'),
    tag(0x06, 'parts', u16(16) + b'\xff\xff\x00'),
    tag(0x07, 'data', u32(0)),
    tag(0x08, 'port', u16(4662)),
    tag(0x09, 'level', b'\x07'),
    tag(0x0a, 'bsob', b''),                                 # BSOB: not decoded, unknown length
]


def search_name(s):
    return b'\x01' + estr(s)


def search_meta(value, name):
    return b'\x02' + estr(value) + estr(name)


def search_limit(limit, minmax, name):
    return b'\x03' + u32(limit) + u8(minmax) + estr(name)


def search_bool(op, a, b):
    return b'\x00' + u8(op) + a + b


SEARCH = search_bool(0, search_name('linux'),
                     search_bool(1, search_meta('Audio', b'\x03'),
                                 search_bool(2, search_limit(1000000, 1, b'\x02'),
                                             search_limit(100, 2, 'bitrate'))))

# ---------------------------------------------------------------- Kademlia values


def ktag(ktype, name, value):
    """Kademlia tag: type, length-prefixed name, value."""
    if isinstance(name, int):
        name = bytes([name])
    elif isinstance(name, str):
        name = name.encode()
    return bytes([ktype]) + u16(len(name)) + name + value


def ktaglist(tags):
    return u8(len(tags)) + b''.join(tags)


def kpeer(n, ip, uport, tport, ver):
    return h16(n) + struct.pack('<I', int.from_bytes(ip4(ip), 'big')) + u16(uport) + u16(tport) + u8(ver)


KAD_TAGS = [
    ktag(0x01, 0xf8, h16(50)),                       # hash, BUDDYHASH
    ktag(0x02, 0x01, estr('kad file.ogg')),          # string, FILENAME
    ktag(0x09, 0xff, b'\x01'),                       # uint8 SOURCETYPE
    ktag(0x09, 0xf3, b'\x05'),                       # uint8 ENCRYPTION
    ktag(0x09, 0xf7, b'\x03'),                       # uint8 FILERATING
    ktag(0x08, 0xfd, u16(4662)),                     # uint16 SOURCEPORT
    ktag(0x0b, 0x02, u64(5000000000)),               # uint64 FILESIZE
    ktag(0x03, 0xfe, u32(0xc0000207)),               # uint32 SOURCEIP
    ktag(0x03, 0xfb, u32(0xc6336401)),               # uint32 SERVERIP
    ktag(0x03, 0xd4, u32(128)),                      # uint32 MEDIA_BITRATE
    ktag(0x04, 0x99, struct.pack('<f', 2.25)),       # float, unknown name
    ktag(0x0a, 0x07, b'\x04\xde\xad\xbe\xef'),       # BSOB, PART_HASH
]


def kexpr_bool(op, a, b):
    return b'\x00' + u8(op) + a + b


def kexpr_str(s):
    return b'\x01' + estr(s)


def kexpr_meta(value, name):
    return b'\x02' + estr(value) + estr(name)


def kexpr_32(v, cond, name):
    return b'\x03' + u32(v) + u8(cond) + estr(name)


def kexpr_64(v, cond, name):
    return b'\x08' + u64(v) + u8(cond) + estr(name)


KEXPR = kexpr_bool(0, kexpr_str('debian'),
                   kexpr_bool(1, kexpr_meta('Video', b'\x03'),
                              kexpr_bool(2, kexpr_32(700, 3, b'\xd3'),
                                         kexpr_64(1 << 33, 9, b'\x02'))))

# ---------------------------------------------------------------- captures

SRV, CLI1, CLI2, PEER = '198.51.100.1', '192.0.2.10', '192.0.2.11', '192.0.2.50'
RANGES = []


def mark(f, label):
    RANGES.append((len(f) + 1, label))


def main_frames():
    f = []
    # ---- TCP client <-> server (4661)
    mark(f, 'TCP client-server 4661: Hello, ID change, server messages, '
            'searches, sources, offers')
    s = Tcp(f, CLI1, 40001, SRV, 4661)
    s.send(tcp_msg(ED, 0x01, client_info(1, '192.0.2.10', 4662, ALL_TAGS)))   # Hello to server
    s.send(tcp_msg(ED, 0x38, estr('server version 17.15\nwelcome')), True)    # server message
    s.send(tcp_msg(ED, 0x40, ip4('192.0.2.10')), True)                        # ID change, 4 octets
    s.send(tcp_msg(ED, 0x40, ip4('192.0.2.10') + u32(0x19)), True)            # + TCP flags
    s.send(tcp_msg(ED, 0x40, ip4('192.0.2.10') + u32(0x19) + u32(4663)), True)
    s.send(tcp_msg(ED, 0x40, ip4('192.0.2.10') + u32(0x19) + u32(4663) + ip4('192.0.2.10') +
                   u32(4664)), True)                                          # all fields
    s.send(tcp_msg(ED, 0x34, u32(1234) + u32(567890)), True)                  # server status
    s.send(tcp_msg(ED, 0x41, h16(2) + addr(SRV, 4661) +
                   taglist([tag(0x02, 0x01, estr('Example server')),
                            tag(0x02, 0x0b, estr('made up'))])), True)        # server info data
    s.send(tcp_msg(ED, 0x14))                                                 # get server list (no body)
    s.send(tcp_msg(ED, 0x32, u8(2) + addr('198.51.100.2', 4661) + addr('198.51.100.3', 4242)), True)
    s.send(tcp_msg(ED, 0x15, u32(2) +
                   file_info(3, b'\xfc\xfc\xfc\xfc', 0xfcfc, [tag(0x02, 0x01, estr('a.txt'))]) +
                   file_info(4, b'\xfb\xfb\xfb\xfb', 0xfbfb, [tag(0x03, 0x02, u32(10))])))
    s.send(tcp_msg(ED, 0x16, SEARCH))                                         # search files
    s.send(tcp_msg(ED, 0x33, u32(1) + file_info(5, ip4('192.0.2.30'), 4662,
                                                [tag(0x02, 0x01, estr('linux.iso'))]) + b'\x01'),
           True)                                                              # results + more
    s.send(tcp_msg(ED, 0x21))                                                 # more results
    s.send(tcp_msg(ED, 0x1a, search_name('alice')))                           # search user
    s.send(tcp_msg(ED, 0x16, b'\x07'))                                        # unknown search type
    s.send(tcp_msg(ED, 0x43, u32(1) + client_info(6, '192.0.2.31', 4662,
                                                  [tag(0x02, 0x01, estr('alice'))])), True)
    s.send(tcp_msg(ED, 0x15, u32(1) + file_info(3, ip4('192.0.2.10'), 4662, LONG_NAME_TAGS)))
    s.send(tcp_msg(ED, 0x19, h16(5) + u32(700000)))                           # get sources
    s.send(tcp_msg(ED, 0x23, h16(5) + u32(0) + u64(5000000000)))              # obfu, 64 bit size
    s.send(tcp_msg(ED, 0x42, h16(5) + u8(2) + addr('192.0.2.30', 4662) + addr('192.0.2.31', 4662)),
           True)                                                              # found sources
    s.send(tcp_msg(ED, 0x44, h16(5) + u8(2) + addr('192.0.2.30', 4662) + b'\x00' +
                   addr('192.0.2.31', 4662) + b'\x80' + user_hash(7)), True)  # obfu sources
    s.send(tcp_msg(ED, 0x1c, ip4('0.0.1.2')))                                 # client callback req
    s.send(tcp_msg(ED, 0x35, addr('192.0.2.12', 4662)), True)                 # server callback req
    s.send(tcp_msg(ED, 0x36, ip4('0.0.1.2')), True)                           # callback fail
    s.send(tcp_msg(ED, 0x05, b'\x00\x01'), True)                              # bad proto (default)
    s.send(tcp_msg(ED, 0x18))                                                 # disconnect
    s.send(tcp_msg(ED, 0x7e, b'opaque body'))                                 # unknown type
    # two messages in one segment, one message over three segments
    s.send(tcp_msg(ED, 0x34, u32(1) + u32(2)) + tcp_msg(ED, 0x38, estr('two in one')), True)
    big = tcp_msg(ED, 0x38, estr('X' * 3000))
    s.send(big[:10], True)
    s.send(big[10:1400], True)
    s.send(big[1400:], True)

    # ---- TCP client <-> client (4662), eDonkey messages
    mark(f, 'TCP client-client 4662: Hello (client form), file requests, parts, '
            'hashsets, shared files')
    c = Tcp(f, CLI1, 40002, CLI2, 4662)
    c.send(tcp_msg(ED, 0x01, b'\x10' + client_info(8, '192.0.2.10', 4662,
                                                   [tag(0x02, 0x01, estr('bob')),
                                                    tag(0x03, 0x11, u32(0x3c))]) +
                   addr(SRV, 4661)))                                          # client Hello
    c.send(tcp_msg(ED, 0x4c, client_info(9, '192.0.2.11', 4662, [tag(0x02, 0x01, estr('carol'))]) +
                   addr(SRV, 4661)), True)                                    # Hello answer
    c.send(tcp_msg(ED, 0x58, h16(5)))                                         # file request
    c.send(tcp_msg(ED, 0x59, h16(5) + estr('linux.iso')), True)               # answer
    c.send(tcp_msg(ED, 0x4f, h16(5)))                                         # status request
    c.send(tcp_msg(ED, 0x50, h16(5) + u16(10) + b'\xff\x03'), True)           # file status
    c.send(tcp_msg(ED, 0x50, h16(5) + u16(0)), True)                          # complete file
    c.send(tcp_msg(ED, 0x51, h16(5)))                                         # hashset request
    c.send(tcp_msg(ED, 0x52, h16(5) + u16(2) + h16(10) + h16(11)), True)      # hashset answer
    c.send(tcp_msg(ED, 0x54, h16(5)))                                         # slot request
    c.send(tcp_msg(ED, 0x55), True)                                           # slot given
    c.send(tcp_msg(ED, 0x47, h16(5) + u32(0) + u32(9728000) + u32(0) + u32(184320) +
                   u32(9912320) + u32(0)))                                    # request parts
    c.send(tcp_msg(ED, 0x46, h16(5) + u32(0) + u32(16) + bytes(range(16))), True)  # sending part
    c.send(tcp_msg(ED, 0x46, h16(5) + u32(16) + u32(16)), True)               # part without data
    c.send(tcp_msg(ED, 0x49, h16(5)))                                         # end of download
    c.send(tcp_msg(ED, 0x48, h16(12)), True)                                  # no such file
    c.send(tcp_msg(ED, 0x4d, ip4('192.0.2.11') + ip4('192.0.2.12')), True)    # new client id
    c.send(tcp_msg(ED, 0x4e, estr('hello there')))                            # client message
    c.send(tcp_msg(ED, 0x4a))                                                 # view files
    c.send(tcp_msg(ED, 0x4b, u32(1) + file_info(13, ip4('192.0.2.11'), 4662,
                                                [tag(0x02, 0x01, estr('song.ogg'))])), True)
    c.send(tcp_msg(ED, 0x5d))                                                 # get shared dirs
    c.send(tcp_msg(ED, 0x5f, u32(2) + estr('/music') + estr('/video')), True) # shared dirs
    c.send(tcp_msg(ED, 0x5e, estr('/music')))                                 # get shared files
    c.send(tcp_msg(ED, 0x60, estr('/music') + u32(1) + file_info(14, ip4('192.0.2.11'), 4662, [])),
           True)                                                              # shared files
    c.send(tcp_msg(ED, 0x61), True)                                           # shared denied
    c.send(tcp_msg(ED, 0x58, h16(5) + b'trailing'))                           # trailing data

    # ---- TCP client <-> client (4662), eMule extensions and compression
    mark(f, 'TCP client-client 4662: eMule extensions, multipackets, eMule compressed')
    e = Tcp(f, CLI2, 40003, CLI1, 4662)
    e.send(tcp_msg(EMULE, 0x01, u16(0x3c) + taglist([tag(0x09, 0x20, b'\x01'),
                                                      tag(0x09, 0x22, b'\x04')])))
    e.send(tcp_msg(EMULE, 0x02, u16(0x3c) + taglist([tag(0x08, 0x21, u16(4672))])), True)
    e.send(tcp_msg(EMULE, 0x60, u16(42) + bytes(10)), True)                   # queue ranking
    e.send(tcp_msg(EMULE, 0x61, b'\x05' + estr('nice file')))                 # file desc (default)
    e.send(tcp_msg(EMULE, 0x81, h16(5)))                                      # sources request
    e.send(tcp_msg(EMULE, 0x82, h16(5) + u16(2) + addr('192.0.2.30', 4662) +
                   addr('192.0.2.31', 4662)), True)                           # sources answer
    e.send(tcp_msg(EMULE, 0x87, b'\x02' + u32(0x12345678)))                   # sec ident state
    e.send(tcp_msg(EMULE, 0x87, b'\x01' + u32(1)), True)
    e.send(tcp_msg(EMULE, 0x87, b'\x00' + u32(2)))
    e.send(tcp_msg(EMULE, 0x85, u8(8) + bytes(range(8))), True)               # public key
    e.send(tcp_msg(EMULE, 0x86, u8(4) + b'\x01\x02\x03\x04'))                 # signature
    e.send(tcp_msg(EMULE, 0x86, u8(4) + b'\x01\x02\x03\x04' + b'\x01'), True) # + IP used
    e.send(tcp_msg(EMULE, 0x40, h16(5) + u32(0) + u32(8) + bytes(8)), True)   # data compressed
    e.send(tcp_msg(EMULE, 0x40, h16(5) + u32(8) + u32(0)), True)              # without data
    e.send(tcp_msg(EMULE, 0xa1, h16(5) + u64(1 << 32) + u32(4) + b'zzzz'), True)
    e.send(tcp_msg(EMULE, 0xa1, h16(5) + u64(1 << 33) + u32(0)), True)
    e.send(tcp_msg(EMULE, 0xa3, h16(5) + u64(0) + u64(1) + u64(2) + u64(3) + u64(4) + u64(5)))
    e.send(tcp_msg(EMULE, 0xa2, h16(5) + u64(1 << 32) + u64((1 << 32) + 4) + b'data'), True)
    e.send(tcp_msg(EMULE, 0xa2, h16(5) + u64(0) + u64(0)), True)
    e.send(tcp_msg(EMULE, 0x99, h16(5) + h16(15) + u16(0)))                   # callback
    e.send(tcp_msg(EMULE, 0x9b, h16(5) + u16(3) + bytes(range(20))))          # AICH request
    e.send(tcp_msg(EMULE, 0x9c, h16(5) + u16(3) + bytes(range(20)) + u16(2) +
                   u16(1) + bytes(20) + u16(2) + b'\x11' * 20), True)         # AICH answer
    e.send(tcp_msg(EMULE, 0x9e, h16(5)))                                      # AICH hash req (default)
    e.send(tcp_msg(EMULE, 0x9d, h16(5) + bytes(20)), True)
    # multipacket: file request with part status and source count, status
    # request, sources request, AICH root hash request
    e.send(tcp_msg(EMULE, 0x92, h16(5) + b'\x58' + u16(10) + b'\xff\x03' + u16(7) +
                   b'\x4f\x81\x9e'))
    # file request followed directly by a status request (no part status),
    # then a file request at the end (too short for a part count)
    e.send(tcp_msg(EMULE, 0x92, h16(5) + b'\x58\x4f\x58'))
    # file request with part status and no source count (next op 0x81)
    e.send(tcp_msg(EMULE, 0x92, h16(5) + b'\x58' + u16(3) + b'\x05' + b'\x81\x9e'))
    # file request with a part count above 442 (not a part status)
    e.send(tcp_msg(EMULE, 0x92, h16(5) + b'\x58' + u16(500) + b'\x4f'))
    # multipacket answer: file name, file status, AICH root hash, then an
    # unknown opcode
    e.send(tcp_msg(EMULE, 0x93, h16(5) + b'\x59' + estr('linux.iso') + b'\x50' + u16(9) +
                   b'\xff\x01' + b'\x9d' + bytes(range(20)) + b'\x77'), True)
    # multipacket ext with the 64 bit file length
    e.send(tcp_msg(EMULE, 0xa4, h16(5) + u64(5000000000) + b'\x4f\x81'))
    e.send(tcp_msg(EMULE, 0x4f, h16(5)))                                      # eDonkey type via eMule
    e.send(tcp_msg(EMULE, 0xf0, b'??'), True)                                 # unknown eMule type
    # eMule compressed: a server message and a file status, zlib streams
    body = estr('compressed server message ' * 4)
    e.send(bytes([ECOMP]) + u32(1 + len(zlib.compress(body))) + b'\x38' + zlib.compress(body), True)
    body = h16(5) + u16(16) + b'\xff\xff'
    e.send(bytes([ECOMP]) + u32(1 + len(zlib.compress(body))) + b'\x50' + zlib.compress(body), True)
    # eMule compressed whose data is not a zlib stream
    e.send(bytes([ECOMP]) + u32(5) + b'\x38' + b'\x00\x01\x02\x03')
    # Kademlia protocol octet on TCP (known protocol, no TCP dissector)
    e.send(bytes([KAD]) + u32(3) + b'\x10\x00\x00')
    # a message of type only (length 1)
    e.send(tcp_msg(EMULE, 0x60), True)

    # ---- TCP segments the eDonkey dissector rejects (left to TCP)
    mark(f, 'TCP 4662: segments that are not eDonkey (too short, unknown protocol octet)')
    r = Tcp(f, CLI1, 40004, CLI2, 4662)
    r.send(b'\xe3\x01\x00')                                                   # under 5 octets
    r = Tcp(f, CLI1, 40005, CLI2, 4662)
    r.send(b'\x00\x01\x00\x00\x00\x01')                                       # unknown protocol

    # ---- UDP eDonkey client <-> server (4665)
    mark(f, 'UDP 4665: eDonkey server UDP messages')
    U = lambda body, back=False: f.append(  # noqa: E731
        udp_frame(SRV, 4665, CLI1, 40100, body) if back else udp_frame(CLI1, 40100, SRV, 4665, body))
    U(udp_msg(ED, 0x96, u32(0x55aa0001)))                                     # status request
    U(udp_msg(ED, 0x97, u32(0x55aa0001) + u32(1000) + u32(200000)), True)     # minimal status
    U(udp_msg(ED, 0x97, u32(0x55aa0002) + u32(1000) + u32(200000) + u32(5000)), True)
    U(udp_msg(ED, 0x97, u32(0x55aa0003) + u32(1000) + u32(200000) + u32(5000) + u32(100) +
              u32(200)), True)
    U(udp_msg(ED, 0x97, u32(0x55aa0004) + u32(1000) + u32(200000) + u32(5000) + u32(100) +
              u32(200) + u32(0x3f) + u32(12) + u16(4665) + u16(4661) + u32(0xdeadbeef)), True)
    U(udp_msg(ED, 0xa2, u32(0x1234f0ff)))                                     # get info, challenge
    U(udp_msg(ED, 0xa2, u16(0)))                                              # without challenge
    U(udp_msg(ED, 0xa2, b'\x01'))                                             # one octet
    U(udp_msg(ED, 0xa3, u32(0x1234f0ff) + taglist([tag(0x02, 0x01, estr('srv')),
                                                    tag(0x03, 0x91, u32(0x000f0011))])), True)
    U(udp_msg(ED, 0xa3, estr('Example server') + estr('description')), True)
    U(udp_msg(ED, 0xa4))                                                      # get server list
    U(udp_msg(ED, 0xa1, u8(1) + addr('198.51.100.4', 4661)), True)            # server list
    U(udp_msg(ED, 0x98, search_bool(0, search_name('a'), search_name('b'))))  # search file
    U(udp_msg(ED, 0x99, file_info(16, ip4('192.0.2.32'), 4662, [tag(0x02, 0x01, estr('b.txt'))])),
      True)
    U(udp_msg(ED, 0x9a, h16(5)))                                              # get sources
    U(udp_msg(ED, 0x9b, h16(5) + u8(1) + addr('192.0.2.30', 4662)), True)     # found sources
    U(udp_msg(ED, 0x9c, addr('192.0.2.10', 4662) + ip4('0.0.2.3')))           # callback request
    U(udp_msg(ED, 0x9e, ip4('0.0.2.3')), True)                                # callback fail
    U(udp_msg(ED, 0x55, b'unknown'))                                          # unknown type
    U(udp_msg(ED, 0x9a, h16(5) + b'xx'))                                      # trailing data
    U(udp_msg(ECOMP, 0x01, b'\x01\x02'))                                       # no UDP form of 0xd4
    U(b'\x00\x01\x02')                                                         # unknown protocol

    # ---- UDP eMule and Overnet (4672)
    mark(f, 'UDP 4672: eMule UDP messages, Overnet')
    V = lambda body, back=False: f.append(  # noqa: E731
        udp_frame(PEER, 4672, CLI1, 4672, body) if back else udp_frame(CLI1, 4672, PEER, 4672, body))
    V(udp_msg(EMULE, 0x90, h16(5)))                                           # reask, UDP v1-2
    V(udp_msg(EMULE, 0x90, h16(5) + u16(3)))                                  # + source count
    V(udp_msg(EMULE, 0x90, h16(5) + u16(10) + b'\xff\x03' + u16(4)))          # + status + count
    V(udp_msg(EMULE, 0x91, u16(17)), True)                                    # reask ack
    V(udp_msg(EMULE, 0x91, u16(10) + b'\xff\x03' + u16(17)), True)            # + file status
    V(udp_msg(EMULE, 0x92, h16(5)), True)                                     # file not found
    V(udp_msg(EMULE, 0x93), True)                                             # queue full, empty
    V(udp_msg(ED, 0x0a, h16(20) + addr('192.0.2.50', 4672) + b'\x00'))        # Overnet connect
    V(udp_msg(ED, 0x0b, u16(2) + h16(21) + addr('192.0.2.51', 4672) + b'\x01' +
              h16(22) + addr('192.0.2.52', 4672) + b'\x02'), True)
    V(udp_msg(ED, 0x0c, h16(20) + addr('192.0.2.50', 4672) + b'\x00'))        # publicize
    V(udp_msg(ED, 0x0d), True)                                                # publicize ack
    V(udp_msg(ED, 0x0e, b'\x02' + h16(23)))                                   # search
    V(udp_msg(ED, 0x0f, h16(23) + u8(1) + h16(24) + addr('192.0.2.53', 4672) + b'\x00'), True)
    V(udp_msg(ED, 0x10, h16(23) + b'\x00' + u16(0) + u16(100)))               # search info
    V(udp_msg(ED, 0x11, h16(23) + h16(25) + taglist([tag(0x02, 0x01, estr('ov.txt'))])), True)
    V(udp_msg(ED, 0x12, h16(23)), True)                                       # search end
    V(udp_msg(ED, 0x13, h16(26) + h16(27) + taglist([tag(0x03, 0x02, u32(5))])))  # publish
    V(udp_msg(ED, 0x14, h16(26)), True)                                       # publish ack
    V(udp_msg(ED, 0x15, h16(20) + addr('192.0.2.50', 4672)))                  # identify reply
    V(udp_msg(ED, 0x16, u16(4662)), True)                                     # identify ack
    V(udp_msg(ED, 0x18, h16(28) + u16(4662)))                                 # firewall connection
    V(udp_msg(ED, 0x19, h16(28)), True)
    V(udp_msg(ED, 0x1a, h16(28)), True)
    V(udp_msg(ED, 0x1b, u16(4662)))                                           # IP query
    V(udp_msg(ED, 0x1c, ip4('192.0.2.10')), True)                             # IP query answer
    V(udp_msg(ED, 0x1d), True)                                                # IP query end
    V(udp_msg(ED, 0x1e, b'\x01\x02'))                                         # identify (default)

    # ---- Kademlia (4672)
    mark(f, 'UDP 4672: Kademlia 1 and 2, KAdu, compressed Kademlia, PUBLISH_REQ pre-scan')
    K = lambda body, back=False: f.append(  # noqa: E731
        udp_frame(PEER, 4672, CLI1, 4672, body) if back else udp_frame(CLI1, 4672, PEER, 4672, body))
    me = kpeer(30, '192.0.2.10', 4672, 4662, 0x08)
    K(udp_msg(KAD, 0x00, me))                                                 # bootstrap req
    K(udp_msg(KAD, 0x08, u16(2) + kpeer(31, '192.0.2.51', 4672, 4662, 0) +
              kpeer(32, '192.0.2.52', 4672, 4662, 1)), True)                  # bootstrap res
    K(udp_msg(KAD, 0x10, me))                                                 # hello req
    K(udp_msg(KAD, 0x18, kpeer(31, '192.0.2.50', 4672, 4662, 0)), True)       # hello res
    K(udp_msg(KAD, 0x01, h16(30) + u16(4662) + u8(8)))                        # kad2 bootstrap req
    K(udp_msg(KAD, 0x09, h16(31) + u16(4662) + u8(8) + u16(1) +
              kpeer(32, '192.0.2.52', 4672, 4662, 8)), True)                  # kad2 bootstrap res
    K(udp_msg(KAD, 0x11, h16(30) + u16(4662) + u8(8) + ktaglist(KAD_TAGS)))  # kad2 hello req
    K(udp_msg(KAD, 0x19, h16(31) + u16(4662) + u8(8) + ktaglist([])), True)  # kad2 hello res
    for t, ver in ((0x20, 0x02), (0x21, 0x0b), (0x20, 0x04), (0x20, 0x55)):   # requests
        K(udp_msg(KAD, t, u8(ver) + h16(33) + h16(34)))
    K(udp_msg(KAD, 0x28, h16(33) + u8(1) + kpeer(35, '192.0.2.55', 4672, 4662, 0)), True)
    K(udp_msg(KAD, 0x29, h16(33) + u8(1) + kpeer(35, '192.0.2.55', 4672, 4662, 8)), True)
    K(udp_msg(KAD, 0x30, h16(36) + b'\x00'))                                  # search, not restrictive
    K(udp_msg(KAD, 0x30, h16(36) + b'\x01' + KEXPR))                          # search with expression
    K(udp_msg(KAD, 0x30, h16(36) + b'\x01'))                                  # restrictive, no expr
    K(udp_msg(KAD, 0x32, h16(37)))                                            # search notes
    K(udp_msg(KAD, 0x33, h16(36) + u16(0)))                                   # kad2 search key
    K(udp_msg(KAD, 0x34, h16(38) + u16(0) + u64(5000000000)))                 # kad2 search source
    K(udp_msg(KAD, 0x35, h16(37)))                                            # kad2 search notes
    K(udp_msg(KAD, 0x35, h16(37) + b'\x10'))                                  # ... with uload
    K(udp_msg(KAD, 0x38, h16(36) + u16(1) + h16(39) + ktaglist(KAD_TAGS[:4])), True)
    K(udp_msg(KAD, 0x3a, h16(37) + u16(0)), True)                             # search notes res
    K(udp_msg(KAD, 0x3b, h16(31) + h16(36) + u16(2) + h16(40) + ktaglist([]) + h16(41) +
              ktaglist([ktag(0x02, 0x01, estr('x'))])), True)                 # kad2 search res
    # KADEMLIA_PUBLISH_REQ with a SOURCETYPE tag: the pre-scan has to step
    # over every tag type, including the BSOB (whose length was read at
    # the start of the message before the fix)
    mark(f, 'PUBLISH_REQ: SOURCETYPE after a BSOB tag (the fix), keyword publish')
    pre = [ktag(0x01, 0xf8, h16(42)), ktag(0x02, 0x01, estr('src')), ktag(0x08, 0xfd, u16(1)),
           ktag(0x03, 0xfe, u32(0xc0000207)), ktag(0x04, 0xf7, struct.pack('<f', 1.0)),
           ktag(0x0b, 0x02, u64(1)), ktag(0x0a, 0x0b, b'\x03\x09\x00\x00'),
           ktag(0x09, 0xff, b'\x01')]
    K(udp_msg(KAD, 0x40, bytes(16) + u16(1) + h16(43) + ktaglist(pre)))
    K(udp_msg(KAD, 0x40, h16(44) + u16(1) + h16(45) +
              ktaglist([ktag(0x02, 0x01, estr('kw.txt')), ktag(0x03, 0x02, u32(77))])))
    K(udp_msg(KAD, 0x43, h16(44) + u16(1) + h16(45) + ktaglist([ktag(0x02, 0x01, estr('k'))])))
    K(udp_msg(KAD, 0x44, h16(46) + h16(47) + ktaglist([ktag(0x09, 0xff, b'\x04')])))
    K(udp_msg(KAD, 0x48, h16(44)), True)                                      # publish res
    K(udp_msg(KAD, 0x48, h16(44) + b'\x20'), True)                            # ... with uload
    K(udp_msg(KAD, 0x4b, h16(44) + b'\x30'), True)                            # kad2 publish res
    K(udp_msg(KAD, 0x50, u16(4662)))                                          # firewalled req
    K(udp_msg(KAD, 0x58, struct.pack('<I', 0xc000020a)), True)                # firewalled res
    K(udp_msg(KAD, 0x59), True)                                               # firewalled ack (empty)
    K(udp_msg(KAD, 0x51, h16(48) + h16(49) + u16(4662)))                      # find buddy req
    K(udp_msg(KAD, 0x5a, h16(48) + h16(49) + u16(4662)), True)                # find buddy res
    K(udp_msg(KAD, 0x52, h16(48) + h16(49) + u16(4662)))                      # callback req
    K(udp_msg(KAD, 0x42, h16(37) + h16(38)))                                  # publish notes (no case)
    K(udp_msg(KAD, 0x32, h16(37) + b'extra'))                                 # trailing data
    K(udp_msg(KADU, 0x10, me))                                                # KAdu hello req
    K(udp_msg(KADC, 0x11, zlib.compress(h16(30) + u16(4662) + u8(8) + ktaglist(KAD_TAGS[:6]))))
    K(udp_msg(KADUC, 0x08, zlib.compress(u16(1) + kpeer(31, '192.0.2.51', 4672, 4662, 0))), True)
    K(udp_msg(KADC, 0x11, b'\x78\x9c\xff\xff\xff'))                           # not a zlib stream
    K(udp_msg(KAD, 0x11))                                                     # type only
    return f


def malformed_frames():
    f = []
    s = Tcp(f, CLI1, 40010, SRV, 4661)
    s.send(tcp_msg(ED, 0x40, b'\x01'))                                        # ID change cut short
    s.send(tcp_msg(ED, 0x01, user_hash(1) + ip4('192.0.2.10') + u16(4662) + u32(5)))  # 5 tags, none
    s.send(tcp_msg(ED, 0x32, u8(3) + addr('198.51.100.2', 4661)))             # list longer than data
    s.send(tcp_msg(ED, 0x38, u16(500) + b'short'))                            # string past the end
    s.send(tcp_msg(ED, 0x15, u32(1) + h16(3) + bytes(6) + u32(1) +
                   bytes([0x07]) + u16(1) + b'\x01' + u32(0xffffff00)))       # blob length too big
    s.send(tcp_msg(EMULE, 0x92, h16(5) + b'\x50' + u16(400)))                 # file status cut short
    e = Tcp(f, CLI2, 40011, CLI1, 4662)
    e.send(tcp_msg(EMULE, 0x9c, h16(5) + u16(1) + bytes(20) + u16(3) + bytes(10)))
    # UDP
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x11, h16(30) + u16(4662) + u8(8) +
                       ktaglist([ktag(0x06, 0x01, b'\x01\x02')]))))
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x11, h16(30) + u16(4662) + u8(8) +
                       ktaglist([ktag(0x02, 'Artist', estr('nobody')), ktag(0x02, '', estr(''))]))))
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x30, h16(36) + b'\x01' + b'\x05\x00')))
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x38, h16(36) + u16(2) + h16(39))))
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x40, h16(36) + u16(1))))
    f.append(udp_frame(CLI1, 40100, SRV, 4665, udp_msg(ED, 0x97, u32(1) + u32(2))))
    f.append(udp_frame(CLI1, 40100, SRV, 4665, udp_msg(ED, 0x0b, u16(0xffff))))
    f.append(udp_frame(CLI1, 4672, PEER, 4672, b'\xe3'))                       # one octet
    # deep search expression nesting
    deep = b''.join(b'\x00\x00' for _ in range(200)) + kexpr_str('x') * 201
    f.append(udp_frame(CLI1, 4672, PEER, 4672, udp_msg(KAD, 0x30, h16(36) + b'\x01' + deep)))
    deep = b''.join(b'\x00\x00' for _ in range(200)) + search_name('x') * 201
    f.append(udp_frame(CLI1, 40100, SRV, 4665, udp_msg(ED, 0x98, deep)))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    frames = main_frames()
    write_pcap(os.path.join(out, 'edonkey-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'edonkey-coverage-malformed.pcap'), malformed_frames())
    if '-v' in sys.argv:
        for i, (start, label) in enumerate(RANGES):
            end = RANGES[i + 1][0] - 1 if i + 1 < len(RANGES) else len(frames)
            print('%d-%d: %s' % (start, end, label))


if __name__ == '__main__':
    main()

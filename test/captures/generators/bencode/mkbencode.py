#!/usr/bin/env python3
# Generates test/captures/bencode_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the bencode dissector
(packet-bencode.c).

Bencode has no port of its own. The captures reach it through the Bazaar
smart protocol (bzr, TCP port 4155), whose messages carry prefixed bencode
values (the header and each 's' body part), and through BitTorrent (TCP
port 6881) extended messages with extension ID 0 (the extension
handshake). Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkbencode.py <output directory>

Writes:
  bencode-coverage.pcap            strings, integers, lists, dictionaries,
                                   nesting up to the limit, BitTorrent / DHT
                                   style dictionaries, truncated values that
                                   give "Truncated Data" without an error,
                                   and the list depth reproducer
  bencode-coverage-malformed.pcap  invalid strings, integers, keys, values,
                                   nesting past the limit, invalid types
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(sport, dport, payload, seq=1, ack=1, src=IP_C, dst=IP_S, ident=1):
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident, 0,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + tcp + payload


# bencode encoders -----------------------------------------------------------

def bstr(s):
    if isinstance(s, str):
        s = s.encode()
    return b'%d:' % len(s) + s


def bint(i):
    return b'i%de' % i


def blist(*items):
    return b'l' + b''.join(items) + b'e'


def bdict(*pairs):
    """pairs: (key, encoded value); keys are kept in the order given."""
    return b'd' + b''.join(bstr(k) + v for k, v in pairs) + b'e'


# carriers -------------------------------------------------------------------

def prefixed(b):
    return struct.pack('>I', len(b)) + b


def bzr(header, *parts):
    """A Bazaar message: protocol line, prefixed bencode header, one 's'
    body part per further value, end marker."""
    return (b'bzr message 3 (bzr 1.6)\n' + prefixed(header)
            + b''.join(b's' + prefixed(p) for p in parts) + b'e')


class Builder:
    def __init__(self):
        self.frames = []
        self.port = 40000

    def bzr(self, header, *parts):
        """One bzr message in its own TCP connection (client to port 4155)."""
        self.port += 1
        self.frames.append(tcp_frame(self.port, 4155, bzr(header, *parts),
                                     ident=len(self.frames) + 1))
        return len(self.frames)


def bt_handshake(info_hash, peer_id):
    return (bytes([19]) + b'BitTorrent protocol' + bytes.fromhex('0000000000100005')
            + info_hash + peer_id)


def bt_extended(ext_id, payload):
    return struct.pack('>IBB', 2 + len(payload), 20, ext_id) + payload


# frames ---------------------------------------------------------------------

def main_frames():
    B = Builder()
    # 1: strings at the top level: a word, the empty string, a string with
    # a two digit length, one with binary octets
    B.bzr(bstr('spam'), bstr(''), bstr('a twelve chr'), bstr(bytes(range(0xf8, 0x100))))
    # 2: integers: positive, zero, negative, the int64 limits
    B.bzr(bint(42), bint(0), bint(-17), bint(2**63 - 1), bint(-2**63))
    # 3: empty list and empty dictionary
    B.bzr(blist(), bdict())
    # 4: a list of every type
    B.bzr(blist(bstr('spam'), bint(42), blist(bstr('a'), bstr('b')),
                bdict(('k', bstr('v'))), bstr('')))
    # 5: a dictionary with string, integer, list, dictionary and empty
    # string values ("Key: ...  Value: ..." on the entries)
    B.bzr(bdict(('bar', bstr('spam')), ('foo', bint(42)), ('neg', bint(-1)),
                ('list', blist(bint(1), bint(2))), ('sub', bdict(('x', bint(1)))),
                ('empty', bstr(''))))
    # 6: a bzr request as bzr sends one: header dictionary, then the
    # request tuple as a list
    B.bzr(bdict(('Software version', bstr('2.7.0'))),
          blist(bstr('BzrDir.open_2.1'), bstr('/srv/repo/')))
    # 7: nesting at the limit: 11 lists (levels 0-10), a list holding a
    # string at level 10, and dictionaries 10 deep around an integer
    B.bzr(b'l' * 11 + b'e' * 11,
          b'l' * 10 + bstr('deep') + b'e' * 10,
          b'd1:a' * 10 + bint(10) + b'e' * 10)
    # 8: DHT style query and response (binary node IDs and compact node
    # info, as in BEP 5)
    node_id = bytes(range(20))
    nodes = b''.join(bytes([i]) * 20 + bytes([10, 0, 0, i]) + struct.pack('>H', 6881)
                     for i in (1, 2, 3))
    B.bzr(bdict(('a', bdict(('id', bstr(node_id)), ('target', bstr(bytes(range(20, 40)))))),
                ('q', bstr('find_node')), ('t', bstr('aa')), ('y', bstr('q'))),
          bdict(('r', bdict(('id', bstr(node_id)), ('nodes', bstr(nodes)))),
                ('t', bstr('aa')), ('y', bstr('r'))))
    # 9: a .torrent style metainfo dictionary with peers (compact) and
    # an info dictionary
    B.bzr(bdict(('announce', bstr('http://tracker.example/announce')),
                ('info', bdict(('length', bint(1048576)), ('name', bstr('file.bin')),
                               ('piece length', bint(262144)),
                               ('pieces', bstr(bytes(range(40)))))),
                ('interval', bint(1800)),
                ('peers', bstr(bytes([192, 0, 2, 7]) + struct.pack('>H', 51413)))))
    # 10-14: truncated values: the dissector shows "Truncated Data"
    # without an expert info. Digits with no colon, an integer with no
    # end, a list and a dictionary with no end, a lone "d", a list whose
    # last element is cut, and an empty value
    B.bzr(b'123', b'i12', blist(bint(1))[:-1], bdict(('a', bint(1)))[:-1])
    B.bzr(b'd', b'l', b'l123')
    B.bzr(b'')
    B.bzr(bdict(('k', blist(bint(1), bstr('two')))))
    B.bzr(b'99')
    # 15: the list depth reproducer (bencode_list_depth_leak_bzr.py):
    # 600 empty lists inside a list, through bzr
    B.bzr(b'l' + b'le' * 600 + b'e')
    frames = B.frames
    # 16-17: BitTorrent handshake and extension handshake (BEP 10) to
    # port 6881, then the reply's extension handshake
    ih = bytes(range(0x40, 0x54))
    hs = bt_handshake(ih, b'-WS0001-000000000001')
    ext = bdict(('m', bdict(('ut_metadata', bint(1)), ('ut_pex', bint(2)))),
                ('p', bint(6881)), ('reqq', bint(250)), ('v', bstr('Synthetic 1.0')),
                ('yourip', bstr(bytes([192, 0, 2, 1]))))
    frames.append(tcp_frame(50000, 6881, hs + bt_extended(0, ext), seq=1, ack=1,
                            ident=len(frames) + 1))
    ext2 = bdict(('m', bdict(('ut_pex', bint(1)))), ('metadata_size', bint(31235)),
                 ('v', bstr('Synthetic 2.0')))
    hs2 = bt_handshake(ih, b'-WS0001-000000000002')
    frames.append(tcp_frame(6881, 50000, hs2 + bt_extended(0, ext2), seq=1,
                            ack=1 + len(hs) + 6 + len(ext), src=IP_S, dst=IP_C,
                            ident=len(frames) + 1))
    return frames


def malformed_frames():
    B = Builder()
    # 1-5: invalid strings: a single digit, a length past the end, a
    # leading zero, a non-digit, a length that wraps 32 bits
    B.bzr(b'5')
    B.bzr(b'5:ab')
    B.bzr(b'01:a')
    B.bzr(b'1x:a')
    B.bzr(b'4294967296:a')
    # 6-14: invalid integers: too short, past INT64_MAX, past INT64_MIN,
    # past UINT64_MAX, a misplaced minus, minus zero, a leading zero, a
    # non-digit, and "i-e" (a minus and no digits, accepted as 0 without
    # an expert info; see the README)
    B.bzr(b'ie')
    B.bzr(b'i9223372036854775808e')
    B.bzr(b'i-9223372036854775809e')
    B.bzr(b'i99999999999999999999e')
    B.bzr(b'i1-2e')
    B.bzr(b'i-0e')
    B.bzr(b'i03e')
    B.bzr(b'i1xe')
    B.bzr(b'i-e')
    # 15-16: nesting past the limit: 12 lists, a dictionary 11 deep
    B.bzr(b'l' * 12 + b'e' * 12)
    B.bzr(b'd1:a' * 11 + bint(1) + b'e' * 11)
    # 17-19: dictionary with an integer key, an invalid value, a value
    # too short to be one
    B.bzr(b'di1ei2ee')
    B.bzr(b'd1:axe')
    B.bzr(b'd1:a1')
    # 20-21: an invalid type at the top level and inside a list
    B.bzr(b'x')
    B.bzr(b'li1exe')
    # 22: invalid integer as a dictionary value and in a list
    B.bzr(b'd1:ai-0ee', b'li-0ee')
    # 23-25: a dictionary key that starts with ':', a string length with a
    # character below '0', an invalid type below '0'
    B.bzr(b'd:ae')
    B.bzr(b'1-:a')
    B.bzr(b'#')
    return B.frames


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bencode-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bencode-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

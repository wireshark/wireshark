#!/usr/bin/env python3
# Generates test/captures/cbor_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CBOR dissector
(packet-cbor.c).

Most frames are Exported PDUs (DLT 252) naming the dissector "cbor" or
"cborseq"; the rest are HTTP messages on TCP port 80 whose Content-Type
selects CBOR (application/cbor, application/cwt, application/cbor-seq and
the +cbor / +cbor-seq suffixes) or, for an unknown media type, the HTTP
payload heuristic (CBOR over HTTP, disabled by default). Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkcbor.py <output directory>

Writes:
  cbor-coverage.pcap            every major type with every argument size,
                                definite and indefinite strings, arrays
                                and maps, tags, simple values and floats,
                                CBOR sequences, CBOR in byte strings, the
                                branch reproducers that decode cleanly
  cbor-coverage-malformed.pcap  invalid minor types, invalid chunks,
                                lengths past the end or too large, the
                                nesting limit, the other reproducers
"""

import os
import struct
import sys


# ---------------------------------------------------------------- CBOR
def head(major, arg, size=None):
    """Item head with an argument; size forces 0 (inline), 1, 2, 4 or 8
    octets."""
    if size is None:
        size = 0 if arg < 24 else 1 if arg < 256 else 2 if arg < 65536 else 4 if arg < 2 ** 32 else 8
    m = major << 5
    if size == 0:
        return bytes([m | arg])
    return bytes([m | {1: 24, 2: 25, 4: 26, 8: 27}[size]]) + arg.to_bytes(size, 'big')


def uint(v, size=None):
    return head(0, v, size)


def nint(v, size=None):
    return head(1, -1 - v, size)


def bstr(b, size=None):
    return head(2, len(b), size) + b


def tstr(s, size=None):
    b = s.encode() if isinstance(s, str) else s
    return head(3, len(b), size) + b


def array(items, size=None):
    return head(4, len(items), size) + b''.join(items)


def cmap(pairs, size=None):
    return head(5, len(pairs), size) + b''.join(k + v for k, v in pairs)


def tag(t, item, size=None):
    return head(6, t, size) + item


BREAK = b'\xff'


def indef(major, items):
    return bytes([(major << 5) | 31]) + b''.join(items) + BREAK


FALSE, TRUE, NULL, UNDEF = b'\xf4', b'\xf5', b'\xf6', b'\xf7'


def half(h):
    return b'\xf9' + struct.pack('>H', h)


def f32(v=None, raw=None):
    return b'\xfa' + (struct.pack('>I', raw) if raw is not None else struct.pack('>f', v))


def f64(v=None, raw=None):
    return b'\xfb' + (struct.pack('>Q', raw) if raw is not None else struct.pack('>d', v))


# ---------------------------------------------------------------- framing
def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
            + struct.pack('>HH', 0, 0) + payload)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


CLI = (192, 0, 2, 10)
SRV = (198, 51, 100, 20)


class Tcp:
    """One TCP connection (no handshake needed for HTTP) on port 80."""

    def __init__(self, cport):
        self.cport = cport
        self.seq = {True: 1000, False: 50000}
        self.ident = 1

    def seg(self, to_server, data):
        src, dst = (CLI, SRV) if to_server else (SRV, CLI)
        sport, dport = (self.cport, 80) if to_server else (80, self.cport)
        hdr = struct.pack('>HHIIBBHHH', sport, dport, self.seq[to_server],
                          self.seq[not to_server], 0x50, 0x18, 65535, 0, 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(data))
        c = csum(pseudo + hdr + data)
        tcp = hdr[:16] + struct.pack('>H', c) + hdr[18:] + data
        self.seq[to_server] += len(data)
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ident, 0x4000,
                         64, 6, 0, bytes(src), bytes(dst))
        self.ident += 1
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        eth = (bytes.fromhex('020000000002') + bytes.fromhex('020000000001')
               if to_server else
               bytes.fromhex('020000000001') + bytes.fromhex('020000000002'))
        return ('eth', eth + b'\x08\x00' + ip + tcp)


def http_req(path, ctype, body):
    h = 'POST %s HTTP/1.1\r\nHost: cbor.example\r\n' % path
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def http_resp(ctype, body):
    h = 'HTTP/1.1 200 OK\r\n'
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def write_pcapng(path, frames):
    """pcapng with two interfaces: 0 Ethernet, 1 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))
    out += block(1, struct.pack('<HHI', 252, 0, 262144))
    for i, (kind, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', 0 if kind == 'eth' else 1,
                                    ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def cbor(payload):
    return ('exp', exp_pdu('cbor', payload))


def cborseq(payload):
    return ('exp', exp_pdu('cborseq', payload))


# ---------------------------------------------------------------- main capture
def nested_bstr(depth):
    p = b'\x00'
    for _ in range(depth):
        p = bstr(p)
    return p


def main_frames():
    f = []
    # 1 unsigned integers, every argument size
    f.append(cbor(array([uint(0), uint(23), uint(24), uint(0x1234), uint(0x12345678),
                         uint(2 ** 64 - 1), uint(5, 8)])))
    # 2 negative integers, every argument size
    f.append(cbor(array([nint(-1), nint(-24), nint(-25), nint(-1000), nint(-100000),
                         nint(-2 ** 63), nint(-2, 8)])))
    # 3 byte strings: inline, 1/2/4/8 octet lengths, printable text,
    #   indefinite with chunks, empty indefinite
    f.append(cbor(array([bstr(b''), bstr(b'\x01\x02'), bstr(bytes(range(30))),
                         bstr(bytes(300)), bstr(b'\xde\xad\xbe\xef\x00', 4),
                         bstr(b'\xca\xfe\x00', 8), bstr(b"it's text"),
                         indef(2, [bstr(b'\x01'), bstr(b'\x02\x03', 1)]),
                         indef(2, [])])))
    # 4 text strings: empty, quotes, 1/2/4/8 octet lengths, UTF-8,
    #   indefinite with chunks, empty indefinite
    f.append(cbor(array([tstr(''), tstr('say "hi"'), tstr('x' * 30), tstr('y' * 260),
                         tstr('four', 4), tstr('eight', 8), tstr('grüße ☃'),
                         indef(3, [tstr('ab'), tstr('cd', 1)]), indef(3, [])])))
    # 5 arrays: empty, 1/2/4/8 octet counts, indefinite, empty indefinite
    f.append(cbor(array([array([]), array([uint(1)], 1), array([uint(2)], 2),
                         array([uint(3)], 4), array([uint(4)], 8),
                         indef(4, [uint(1), tstr('two'), array([])]), indef(4, [])])))
    # 6 maps: empty, 1/2/4/8 octet counts, indefinite, empty indefinite
    f.append(cbor(cmap([(uint(1), cmap([])),
                        (uint(2), cmap([(tstr('a'), uint(1))], 1)),
                        (uint(3), cmap([(nint(-1), TRUE)], 2)),
                        (uint(4), cmap([(bstr(b'k'), NULL)], 4)),
                        (uint(5), cmap([(uint(0), FALSE)], 8)),
                        (tstr('i'), indef(5, [tstr('x'), uint(1), tstr('y'), array([])])),
                        (tstr('e'), indef(5, []))])))
    # 7 tags: inline, 1/2/4/8 octet tag numbers, known and unknown
    f.append(cbor(array([tag(0, tstr('2013-03-21T20:04:00Z')), tag(1, uint(1363896240)),
                         tag(2, bstr(b'\x01\x00')), tag(32, tstr('http://cbor.example/')),
                         tag(256, array([])), tag(55799, cmap([])),
                         tag(0x10000, uint(1)), tag(2 ** 40, NULL), tag(1, uint(0), 8),
                         tag(20, uint(0))])))
    # 8 simple values and floats
    f.append(cbor(array([FALSE, TRUE, NULL, UNDEF, b'\xf0', b'\xf8\x20', b'\xf8\x15',
                         half(0x0001), half(0x8001), half(0x3c00), half(0xc000),
                         half(0x7c00), half(0xfc00), half(0x7e00), half(0x0000),
                         f32(3.5), f32(raw=0x7fc00000), f32(raw=0xff800000),
                         f64(1.1), f64(raw=0x7ff0000000000000), f64(raw=0x7ff8000000000000),
                         f64(-0.0)])))
    # 9 a lone break code at the top
    f.append(cbor(BREAK))
    # 10 100 nested arrays (below the limit of 500 / 4 = 125 levels)
    f.append(cbor(b'\x81' * 100 + uint(0)))
    # 11 reproducer cbor_bstr_nesting frame 1: 600 nested byte strings;
    #    one byte string unless cbor.dissect_embeded_bstr is set
    f.append(cbor(nested_bstr(600)))
    # 12 reproducer cbor_tree_depth frame 1: [-1]
    f.append(cbor(b'\x81\x20'))
    # 13 byte strings holding CBOR (one item, a sequence) and ones that do
    #    not (a break, an invalid minor type, an item with trailing data,
    #    a truncated item)
    f.append(cbor(cmap([(uint(1), bstr(cmap([(uint(1), tstr('x'))]))),
                        (uint(2), bstr(uint(1) + uint(2) + tstr('three'))),
                        (uint(3), bstr(b'\xff')),
                        (uint(4), bstr(b'\x1c')),
                        (uint(5), bstr(b'\x01\xff')),
                        (uint(6), bstr(b'\x62a')),
                        (uint(7), bstr(b'\x40'))])))
    # 14 a byte string holding a byte string holding CBOR text
    f.append(cbor(bstr(bstr(tstr('deep')))))
    # 15-16 CBOR sequences: three items, empty
    f.append(cborseq(uint(1) + tstr('a') + array([uint(2), bstr(b'\x05')])))
    f.append(cborseq(b''))
    # 17 a sequence with one item
    f.append(cborseq(cmap([(tstr('k'), f32(0.5))])))

    # 18-27 HTTP on TCP port 80
    t = Tcp(40000)
    f.append(t.seg(True, http_req('/a', 'application/cbor', cmap([(tstr('req'), uint(1))]))))
    f.append(t.seg(False, http_resp('application/cbor-seq', uint(1) + uint(2) + uint(3))))
    f.append(t.seg(True, http_req('/b', 'application/cwt',
                                  tag(61, tag(18, array([bstr(b'\xa1\x01\x26'), cmap([]),
                                                         bstr(b'\xa1\x01\x63abc'), bstr(bytes(8))]))))))
    f.append(t.seg(False, http_resp('application/senml+cbor',
                                    array([cmap([(nint(-2), tstr('urn:dev:1')), (uint(2), f32(23.5))])]))))
    f.append(t.seg(True, http_req('/c', 'application/missing-blocks+cbor-seq', uint(7) + NULL)))
    # body with a media type no dissector claims: the CBOR over HTTP
    # heuristic (disabled by default) takes it as one item, a sequence, or
    # rejects it
    f.append(t.seg(False, http_resp('application/x-unknown', cmap([(uint(1), uint(2))]))))
    f.append(t.seg(True, http_req('/d', 'application/x-unknown', uint(1) + tstr('b'))))
    f.append(t.seg(False, http_resp('application/x-unknown', b'hello world')))
    return f


# ---------------------------------------------------------------- malformed capture
def malformed_frames():
    f = []
    # 1-8 invalid minor types 28-30 in every major type
    f.append(cbor(b'\x1c'))
    f.append(cbor(b'\x3d'))
    f.append(cbor(b'\x5e'))
    f.append(cbor(b'\x7c'))
    f.append(cbor(b'\x9d'))
    f.append(cbor(b'\xbe'))
    f.append(cbor(b'\xdc' + b'\x00'))
    f.append(cbor(b'\xfd'))
    # 9-10 indefinite strings with a chunk of the wrong type
    f.append(cbor(b'\x5f\x61a\xff'))
    f.append(cbor(b'\x7f\x41a\xff'))
    # 11-12 negative integers below INT64_MIN, -2^64 (cbor_tree_depth frame 8)
    f.append(cbor(nint(-2 ** 63 - 1)))
    f.append(cbor(b'\x3b' + b'\xff' * 8))
    # 13 byte string longer than INT32_MAX (cbor_tree_depth frame 6)
    f.append(cbor(b'\x5b\x7f\xff\xff\xff\xff\xff\xff\xffab'))
    # 14 byte string of INT32_MAX octets (offset overflows; exception with
    #    a tree)
    f.append(cbor(b'\x5a\x7f\xff\xff\xffab'))
    # 15 text string of 2^31-1 (cbor_tree_depth frame 7) and 16 of 2^64-1
    f.append(cbor(b'\x7b\x00\x00\x00\x00\x7f\xff\xff\xffab'))
    f.append(cbor(b'\x7b' + b'\xff' * 8 + b'ab'))
    # 17 text string past the end of the data
    f.append(cbor(b'\x65ab'))
    # 18 5000 nested arrays (cbor_tree_depth frame 2)
    f.append(cbor(b'\x81' * 5000 + b'\x00'))
    # 19 nested indefinite byte strings (cbor_tree_depth frame 3)
    f.append(cbor(b'\x5f' * 5000 + b'\x40' + b'\xff' * 5000))
    # 20 nested indefinite text strings
    f.append(cbor(b'\x7f' * 300 + b'\x60' + b'\xff' * 300))
    # 21 map with a huge pair count (cbor_tree_depth frame 4)
    f.append(cbor(b'\xbb' + b'\xff' * 8 + b'\x00\x01'))
    # 22 3000 self-describe tags (cbor_tree_depth frame 5)
    f.append(cbor(b'\xd9\xd9\xf7' * 3000 + b'\x00'))
    # 23 300 nested arrays (cbor_bstr_nesting frame 2)
    f.append(cbor(b'\x81' * 300 + b'\x00'))
    # 24 nested map keys past the limit
    f.append(cbor(b'\xa1' * 200 + b'\x00' + b'\x00' * 200))
    # 25 array cut short, 26 map cut short, 27 indefinite array without break
    f.append(cbor(b'\x83\x01'))
    f.append(cbor(b'\xa2\x01\x02\x03'))
    f.append(cbor(b'\x9f\x01\x02'))
    # 28 invalid item inside an array, a map and a tag (diagnostic "/invalid/")
    f.append(cbor(array([uint(1), b'\x1e'])))
    f.append(cbor(cmap([(uint(1), b'\x5d')])))
    f.append(cbor(tag(1, b'\x7e')))
    # 31 the same in a sequence
    f.append(cborseq(uint(1) + b'\x9c' + uint(2)))
    # 32 truncated float and simple
    f.append(cbor(b'\xfb\x00\x00'))
    f.append(cbor(b'\xf8'))
    # 34 an invalid chunk inside an indefinite string inside an indefinite string
    f.append(cbor(b'\x5f\x5f\x5c\xff\xff'))
    f.append(cbor(b'\x7f\x7f\x7d\xff\xff'))
    # 36 a byte string chunk with an invalid minor type in an indefinite string
    f.append(cbor(b'\x5f\x41a\x5c'))
    # 37 HTTP: application/cbor body that is cut short
    t = Tcp(40001)
    f.append(t.seg(True, http_req('/m', 'application/cbor', b'\x82\x01')))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'cbor-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'cbor-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

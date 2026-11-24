#!/usr/bin/env python3
# Generates test/captures/daap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Digital Audio Access
Protocol dissector (packet-daap.c).

DAAP (and DACP, the remote control protocol built on it) runs over HTTP
on TCP port 3689. The HTTP bodies with the media type
application/x-dmap-tagged hold a tree of tags: a 4 octet name, a 4 octet
big-endian length and the data; container tags hold more tags. Every
packet is built from scratch with struct (zlib only for the PNG CRCs);
no captured traffic is used.

Usage: mkdaap.py <output directory>

Writes:
  daap-coverage.pcap            HTTP requests and responses on several
                                connections with every tag the dissector
                                knows, nesting, the depth limit, album art
                                (PNG), and the reproducer of the depth fix
  daap-coverage-malformed.pcap  bodies cut short, tags longer than the
                                body, value tags with sizes the field
                                cannot take
"""

import os
import struct
import sys
import zlib

CLIENT = (192, 0, 2, 10)
SERVER = (192, 0, 2, 20)
PORT = 3689


def ip_checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload, src, dst):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        if src == CLIENT:
            eth = b'\x02\x00\x00\x00\x00\x14\x02\x00\x00\x00\x00\x0a\x08\x00'
        else:
            eth = b'\x02\x00\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x14\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from the client to the DAAP server with correct
    sequence numbers, a handshake and a close."""
    def __init__(self, cap, cport):
        self.cap, self.cport = cap, cport
        self.cseq, self.sseq = 1000 + cport, 7000 + cport
        cap.tcp(cport, PORT, self.cseq, 0, 0x02, b'', CLIENT, SERVER)
        cap.tcp(PORT, cport, self.sseq, self.cseq + 1, 0x12, b'', SERVER, CLIENT)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, PORT, self.cseq, self.sseq, 0x10, b'', CLIENT, SERVER)

    def client(self, *datas):
        for data in datas:
            self.cap.tcp(self.cport, PORT, self.cseq, self.sseq, 0x18, data, CLIENT, SERVER)
            self.cseq += len(data)

    def server(self, *datas):
        for data in datas:
            self.cap.tcp(PORT, self.cport, self.sseq, self.cseq, 0x18, data, SERVER, CLIENT)
            self.sseq += len(data)
        # The client acknowledges the response
        self.cap.tcp(self.cport, PORT, self.cseq, self.sseq, 0x10, b'', CLIENT, SERVER)

    def close(self):
        self.cap.tcp(self.cport, PORT, self.cseq, self.sseq, 0x11, b'', CLIENT, SERVER)
        self.cseq += 1
        self.cap.tcp(PORT, self.cport, self.sseq, self.cseq, 0x11, b'', SERVER, CLIENT)
        self.sseq += 1
        self.cap.tcp(self.cport, PORT, self.cseq, self.sseq, 0x10, b'', CLIENT, SERVER)


def get(path):
    return ('GET %s HTTP/1.1\r\nHost: 192.0.2.20:3689\r\n'
            'Client-DAAP-Version: 3.10\r\nViewer-Only-Client: 1\r\n\r\n' % path).encode()


def post(path, body, ctype='application/x-dmap-tagged'):
    return ('POST %s HTTP/1.1\r\nHost: 192.0.2.20:3689\r\nContent-Type: %s\r\n'
            'Content-Length: %d\r\n\r\n' % (path, ctype, len(body))).encode() + body


def response(body, ctype='application/x-dmap-tagged'):
    return ('HTTP/1.1 200 OK\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\n'
            'DAAP-Server: synthetic/1.0\r\nContent-Type: %s\r\n'
            'Content-Length: %d\r\n\r\n' % (ctype, len(body))).encode() + body


def split(data, *cuts):
    out, prev = [], 0
    for c in cuts:
        out.append(data[prev:c])
        prev = c
    out.append(data[prev:])
    return out


# Tags

def tag(name, data):
    return name.encode() + struct.pack('>I', len(data)) + data


def cont(name, *items):
    return tag(name, b''.join(items))


def s(name, text):
    return tag(name, text.encode())


def u8(name, v):
    return tag(name, struct.pack('>B', v))


def u16(name, v):
    return tag(name, struct.pack('>H', v))


def u32(name, v):
    return tag(name, struct.pack('>I', v))


def u64(name, v):
    return tag(name, struct.pack('>Q', v))


CONTAINERS = ['mcon', 'msrv', 'mccr', 'mdcl', 'mlog', 'mupd', 'avdb', 'mlcl',
              'mlit', 'mbcl', 'adbs', 'aply', 'apso', 'mudl', 'abro', 'abar',
              'arsv', 'abal', 'abcp', 'abgn', 'prsv', 'arif', 'casp', 'cmgt',
              'cmst']
STRINGS = ['minm', 'msts', 'mcnm', 'mcna', 'asal', 'asar', 'ascm', 'asfm',
           'aseq', 'asgn', 'asdt', 'asul', 'ascp', 'asct', 'ascn', 'aslc',
           'asky', 'aeSN', 'aeNN', 'aeEN', 'assn', 'assa', 'assl', 'assc',
           'asss', 'asaa', 'aspu', 'aeCR', 'cana', 'cang', 'canl', 'cann']
U64 = ['mper', 'aeGR', 'aeGU', 'asai', 'asls']
U32 = ['asda', 'asdm', 'assr', 'assz', 'asst', 'assp', 'astm', 'aeNV',
       'ascd', 'ascs', 'aeSV', 'aePI', 'aeCI', 'aeGI', 'aeAI', 'aeSI',
       'aeES', 'asbo', 'aeGH', 'aeGD', 'aeGE', 'cant', 'cast', 'cmsr',
       'cmvo', 'meds']
U16 = ['mcty', 'asbt', 'asbr', 'asdc', 'asdn', 'astc', 'astn', 'asyr', 'ased']
U8 = ['mikd', 'msau', 'msty', 'asrv', 'asur', 'asdk', 'muty', 'msas',
      'aeHV', 'aeHD', 'aePC', 'aePP', 'aeMK', 'aeSG', 'apsm', 'aprm',
      'asgp', 'aePS', 'cafs', 'caps', 'carp', 'cash', 'cavs']
BOOLS = ['mslr', 'msal', 'msup', 'mspi', 'msex', 'msbr', 'msqy', 'msix',
         'msrs', 'asco', 'asdb', 'abpl', 'aeSP', 'asbk']


def png():
    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    raw = b'\x00\x00'   # one row, filter 0, one grey pixel
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\x00'))
            + chunk(b'IEND', b''))


def server_info():
    return cont('msrv',
                u32('mstt', 200),
                tag('mpro', bytes([0, 2, 0, 10])),
                tag('apro', bytes([0, 3, 0, 12])),
                s('minm', 'Synthetic Library'),
                u8('mslr', 0), u8('msal', 0), u8('msup', 0), u8('mspi', 0),
                u8('msex', 0), u8('msbr', 0), u8('msqy', 0), u8('msix', 0),
                u8('msrs', 0),
                u32('mstm', 1800),
                u32('msdc', 1),
                u8('msau', 2),
                u8('msas', 3),
                u32('aeSV', 0x00030000))


def content_codes():
    items = [cont('mdcl', u32('mcnm', 0), s('mcna', 'dmap.itemid'), u16('mcty', 5))]
    # mcnm as a string (it is a string tag in this dissector)
    items = [cont('mdcl', s('mcnm', 'miid'), s('mcna', 'dmap.itemid'), u16('mcty', 5)),
             cont('mdcl', s('mcnm', 'minm'), s('mcna', 'dmap.itemname'), u16('mcty', 9)),
             cont('mdcl', s('mcnm', 'mlcl'), s('mcna', 'dmap.listing'), u16('mcty', 12))]
    return cont('mccr', u32('mstt', 200), *items)


def song(i):
    """A listing item with every string, number and boolean song tag."""
    items = [u8('mikd', 2), u32('miid', 0x100 + i), u64('mper', 0x0123456789abcdef + i),
             s('minm', 'Song %d' % i)]
    for n in STRINGS:
        if n not in ('minm', 'msts', 'mcnm', 'mcna'):
            items.append(s(n, '%s value %d' % (n, i)))
    for n in U64:
        if n != 'mper':
            items.append(u64(n, 0xfedcba9876543210 - i))
    for k, n in enumerate(U32):
        items.append(u32(n, 1000 * (k + 1) + i))
    for k, n in enumerate(U16):
        items.append(u16(n, 10 * (k + 1) + i))
    for k, n in enumerate(U8):
        if n not in ('mikd', 'msau', 'msas', 'muty'):
            items.append(u8(n, k + 1))
    for n in ('asco', 'asdb', 'aeSP', 'asbk'):
        items.append(u8(n, 0))
    # Tags in the name table that are not decoded further
    items.append(u8('ashp', 1))
    items.append(u32('aeSU', 3))
    # A tag that is not in the table at all
    items.append(u32('zzzz', 0xdeadbeef))
    return cont('mlit', *items)


def main_capture(path):
    cap = Pcap()

    # Connection 1: login, server info, content codes, update, databases
    c = TcpStream(cap, 50001)
    c.client(get('/server-info'))
    c.server(response(server_info()))
    c.client(get('/content-codes'))
    c.server(response(content_codes()))
    c.client(get('/login'))
    c.server(response(cont('mlog', u32('mstt', 200), u32('mlid', 0x1234abcd))))
    c.client(get('/update?session-id=305441741'))
    c.server(response(cont('mupd', u32('mstt', 200), u32('musr', 42), u8('muty', 0))))
    c.client(get('/databases?session-id=305441741'))
    c.server(response(cont('avdb', u32('mstt', 200), u8('muty', 0),
                           u32('mtco', 1), u32('mrco', 1),
                           cont('mlcl', cont('mlit', u32('miid', 1),
                                              u64('mper', 0x1122334455667788),
                                              s('minm', 'Library'),
                                              u32('mimc', 3), u32('mctc', 2))))))
    c.close()

    # Connection 2: songs (with every song tag), with a deleted id listing,
    # sent over three TCP segments
    c = TcpStream(cap, 50002)
    c.client(get('/databases/1/items?session-id=305441741&revision-number=42'))
    body = cont('adbs', u32('mstt', 200), u8('muty', 1), u32('mtco', 3), u32('mrco', 3),
                cont('mlcl', song(1), song(2), song(3)),
                cont('mudl', u32('miid', 0x99), u32('miid', 0x9a)))
    r = response(body)
    c.server(*split(r, 200, 1600))
    # Playlists and playlist songs
    c.client(get('/databases/1/containers?session-id=305441741'))
    c.server(response(cont('aply', u32('mstt', 200), u8('muty', 0), u32('mtco', 2), u32('mrco', 2),
                           cont('mlcl',
                                cont('mlit', u32('miid', 0x20), u64('mper', 0x20), s('minm', 'Library'),
                                     u8('abpl', 0), u32('mimc', 3)),
                                cont('mlit', u32('miid', 0x21), u64('mper', 0x21), s('minm', 'Smart'),
                                     u32('mpco', 0x20), u8('aeSP', 0), u8('aePS', 4),
                                     u8('apsm', 1), u8('aprm', 2), u32('aePI', 7), u8('aeSG', 0),
                                     u8('aePP', 0), u32('mimc', 1))))))
    c.client(get('/databases/1/containers/33/items?session-id=305441741'))
    c.server(response(cont('apso', u32('mstt', 200), u8('muty', 0), u32('mtco', 1), u32('mrco', 1),
                           cont('mlcl', cont('mlit', u8('mikd', 2), u32('miid', 0x101),
                                              u32('mcti', 0x5001))))))
    c.close()

    # Connection 3: browsing, resolve, an error status, album art
    c = TcpStream(cap, 50003)
    for path_, top, sub, names in (('artists', 'abro', 'abar', ['Artist A', 'Artist B']),
                                   ('albums', 'abro', 'abal', ['Album A']),
                                   ('composers', 'abro', 'abcp', ['Composer A']),
                                   ('genres', 'abro', 'abgn', ['Rock', 'Jazz'])):
        c.client(get('/databases/1/browse/%s?session-id=305441741' % path_))
        c.server(response(cont(top, u32('mstt', 200), u8('muty', 0), u32('mtco', len(names)),
                               u32('mrco', len(names)),
                               cont(sub, *[cont('mlit', s('minm', n)) for n in names]))))
    c.client(get('/resolve?session-id=305441741'))
    c.server(response(cont('arsv', u32('mstt', 200),
                           cont('prsv', cont('arif', u32('miid', 0x101), s('asul', 'daap://x'))))))
    c.client(get('/logout?session-id=1'))
    c.server(response(cont('mlog', u32('mstt', 403), s('msts', 'Forbidden'))))
    c.client(get('/databases/1/items/257/extra_data/artwork?session-id=305441741'))
    c.server(response(png(), ctype='image/png'))
    # Album art sent with the DMAP media type: the dissector hands it to PNG
    c.client(get('/databases/1/items/258/extra_data/artwork?session-id=305441741&mw=1&mh=1'))
    c.server(response(png()))
    c.close()

    # Connection 4: DACP remote control
    c = TcpStream(cap, 50004)
    c.client(get('/ctrl-int/1/playstatusupdate?revision-number=1&session-id=1'))
    c.server(response(cont('cmst', u32('mstt', 200), u32('cmsr', 77), u8('caps', 4),
                           u8('cash', 1), u8('carp', 2), u8('cafs', 0), u8('cavs', 0),
                           tag('canp', struct.pack('>IIII', 0x29, 0x20, 0, 0x101)),
                           s('cann', 'Song 1'), s('cana', 'Artist A'), s('canl', 'Album A'),
                           s('cang', 'Rock'), u32('asai', 0x55), u32('cmmk', 1),
                           u32('cant', 120000), u32('cast', 240000))))
    c.client(get('/ctrl-int/1/getproperty?properties=dmcp.volume&session-id=1'))
    c.server(response(cont('cmgt', u32('mstt', 200), u32('cmvo', 50))))
    c.client(get('/ctrl-int/1/getspeakers?session-id=1'))
    c.server(response(cont('casp', u32('mstt', 200),
                           cont('mdcl', u8('caia', 1), s('minm', 'Computer'),
                                u64('msma', 0), u32('cmvo', 100)),
                           cont('mdcl', s('minm', 'Kitchen'), u64('msma', 0x0011223344),
                                u32('cmvo', 30)))))
    # A request body with the DMAP media type (edit commands), a bag
    c.client(post('/databases/1/edit?session-id=1',
                  cont('medc', cont('mbcl', u32('meds', 3), u8('mikd', 3),
                                    s('minm', 'New playlist')))))
    c.server(response(cont('medc', u32('mstt', 200), u32('miid', 0x30))))
    c.client(post('/databases/1/edit?session-id=1',
                  cont('mbcl', u32('meds', 3), u8('mikd', 3), s('minm', 'New playlist'))))
    c.server(response(cont('mcon', u32('mstt', 200), u32('miid', 0x31))))
    c.close()

    # Connection 5: limits. A tag with a size above INT_MAX ends the
    # listing; containers nested 120 deep reach the depth limit (a
    # warning); the reproducer of the depth fix (
    # daap_depth_leak.py, there in an exported PDU), an mlcl with 120 mlit
    # siblings, every one of which is decoded now; empty tags.
    c = TcpStream(cap, 50005)
    c.client(get('/databases/1/items?session-id=2'))
    body = cont('adbs', u32('mstt', 200), tag('mlcl', b'')) + b'mlcl' + struct.pack('>I', 0x80000000)
    c.server(response(body))
    c.client(get('/databases/1/groups?session-id=2'))
    deep = s('minm', 'deepest')
    for k in range(120):
        deep = cont(CONTAINERS[k % len(CONTAINERS)], deep)
    c.server(response(deep))
    c.client(get('/databases/1/items?session-id=3'))
    item = tag('mlit', tag('minm', b'x'))
    c.server(response(tag('mlcl', item * 120)))
    c.client(get('/databases/1/items?session-id=4'))
    c.server(response(cont('adbs', tag('mlcl', b''), tag('minm', b''), u8('mslr', 0))))
    c.close()

    cap.write(path)


def malformed_capture(path):
    cap = Pcap()
    c = TcpStream(cap, 51001)
    bodies = [
        b'ms',                                      # too short for the first tag
        b'mlcl\x00\x00',                            # too short for the size
        cont('mlcl', s('minm', 'x'))[:-1] + b'',    # placeholder, replaced below
        tag('mstt', b'\x00\x00\x00\x00\x00'),        # uint32 field with 5 octets
        tag('mstt', b''),                           # uint32 field with 0 octets
        tag('mper', b'\x00' * 9),                   # uint64 field with 9 octets
        tag('miid', b'\x00' * 6),                   # id field with 6 octets
        tag('mrco', b'\x00' * 6),                   # count with 6 octets
        tag('musr', b'\x00' * 6),                   # revision with 6 octets
        tag('mstm', b'\x00' * 6),                   # timeout with 6 octets
        tag('astm', b'\x00' * 6),                   # data with 6 octets
        tag('mpro', b'\x00\x02'),                   # version with 2 octets
        tag('canp', b'\x00' * 8),                   # now playing with 8 octets
        b'mlcl' + struct.pack('>I', 100) + s('minm', 'x'),   # container longer than body
        b'minm' + struct.pack('>I', 50) + b'abc',   # string longer than body
        b'mstt\x00\x00\x00\x04\x00\x00',            # value cut short
    ]
    bodies[2] = b'mlcl' + struct.pack('>I', 9) + b'minm\x00\x00\x00\x01'   # inner tag cut
    for i, b in enumerate(bodies):
        c.client(get('/m/%d' % i))
        c.server(response(b))
    c.close()
    cap.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(os.path.join(out, 'daap-coverage.pcap'))
    malformed_capture(os.path.join(out, 'daap-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

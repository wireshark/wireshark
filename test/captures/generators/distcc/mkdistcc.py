#!/usr/bin/env python3
# Generates test/captures/distcc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build synthetic distcc (protocol version 1) captures with struct.

Usage: mkdistcc.py <outdir>
Writes distcc-coverage.pcap and distcc-coverage-malformed.pcap.
Nothing comes from a real network; addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def eth_ip_tcp(src, dst, sp, dp, seq, ack, flags, data):
    tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + data
    pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
                     ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + tcp)


class Conn:
    """A TCP connection from a client port to distccd on port 3632."""
    def __init__(self, frames, cport, client='192.0.2.10', server='192.0.2.20'):
        self.f, self.cport, self.c, self.s = frames, cport, client, server
        self.cseq, self.sseq = 100000 * cport % 2**32, 700000 * cport % 2**32
        self.f.append(eth_ip_tcp(self.c, self.s, cport, 3632, self.cseq, 0, 0x02, b''))
        self.f.append(eth_ip_tcp(self.s, self.c, 3632, cport, self.sseq, self.cseq + 1, 0x12, b''))
        self.cseq += 1
        self.sseq += 1
        self.f.append(eth_ip_tcp(self.c, self.s, cport, 3632, self.cseq, self.sseq, 0x10, b''))

    def c2s(self, data):
        self.f.append(eth_ip_tcp(self.c, self.s, self.cport, 3632, self.cseq, self.sseq, 0x18, data))
        self.cseq += len(data)

    def s2c(self, data):
        self.f.append(eth_ip_tcp(self.s, self.c, 3632, self.cport, self.sseq, self.cseq, 0x18, data))
        self.sseq += len(data)

    def close(self):
        self.f.append(eth_ip_tcp(self.c, self.s, self.cport, 3632, self.cseq, self.sseq, 0x11, b''))
        self.f.append(eth_ip_tcp(self.s, self.c, 3632, self.cport, self.sseq, self.cseq + 1, 0x11, b''))
        self.f.append(eth_ip_tcp(self.c, self.s, self.cport, 3632, self.cseq + 1, self.sseq + 1, 0x10, b''))


def tok(name, value):
    """A token: four letters and the value as eight hex digits."""
    return name.encode() + b'%08x' % value


def blob(name, data):
    return tok(name, len(data)) + data


def argv(args):
    return tok('ARGC', len(args)) + b''.join(blob('ARGV', a.encode()) for a in args)


def source(lines):
    text = ''.join('int f%d(int x) { return x * %d; }\n' % (i, i) for i in range(lines))
    return ('# 1 "foo.c"\n' + text).encode()


def objfile(n):
    return b'\x7fELF\x02\x01\x01' + bytes(9) + bytes((i * 7) & 0xff for i in range(n - 16))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            data, orig = fr if isinstance(fr, tuple) else (fr, len(fr))
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), orig))
            f.write(data)


def main_capture():
    fr = []
    # Session 1: everything fits; arguments in one segment, source in another.
    c = Conn(fr, 40001)
    c.c2s(tok('DIST', 1) + argv(['gcc', '-O2', '-c', 'foo.c', '-o', 'foo.o']))
    c.c2s(blob('DOTI', source(3)))
    c.s2c(tok('DONE', 1) + tok('STAT', 0)
          + blob('SERR', b"foo.c:2: warning: unused variable 'y'\n")
          + blob('SOUT', b'compiled\n') + blob('DOTO', objfile(64)))
    c.close()
    # Session 2: a large source file split over three segments and a
    # large object file split over two (TCP reassembly).
    c = Conn(fr, 40002)
    src = source(40)
    first = tok('DIST', 1) + argv(['cc', '-c', 'bar.c']) + tok('DOTI', len(src))
    c.c2s(first + src[:500])
    c.c2s(src[500:1100])
    c.c2s(src[1100:])
    obj = objfile(1600)
    resp = tok('DONE', 1) + tok('STAT', 0) + blob('SERR', b'note: bar.c\n') \
        + blob('SOUT', b'ok\n') + tok('DOTO', len(obj))
    c.s2c(resp + obj[:900])
    c.s2c(obj[900:])
    c.close()
    # Session 3: one token per segment, a failed compile (wait status
    # 0x100, exit code 1) with a compiler error.
    c = Conn(fr, 40003)
    c.c2s(tok('DIST', 1))
    c.c2s(tok('ARGC', 4))
    for a in (b'gcc', b'-c', b'baz.c', b'-Wall'):
        c.c2s(blob('ARGV', a))
    c.c2s(blob('DOTI', b'int main(void) { return y; }\n'))
    c.s2c(tok('DONE', 1))
    c.s2c(tok('STAT', 0x100))
    c.s2c(blob('SERR', b"baz.c:1: error: 'y' undeclared\n"))
    c.s2c(blob('SOUT', b'failed\n'))
    c.close()
    return fr


def malformed_capture():
    fr = []
    c = Conn(fr, 41001)
    # The parameter is not hex: the dissector stops.
    c.c2s(tok('DIST', 1) + b'ARGCzzzzzzzz')
    # An unknown token: the rest is shown as data.
    c.c2s(b'HELO00000001')
    # Fewer than 12 octets.
    c.c2s(b'DIST0001')
    # Zero length string parameters.
    c.c2s(blob('ARGV', b'') + blob('DOTI', b''))
    c.s2c(tok('DONE', 1) + blob('SERR', b'') + blob('SOUT', b'') + blob('DOTO', b''))
    # Parameters longer than the frame, in frames cut short by the
    # snapshot length (no reassembly is tried, "[Short ... PDU]").
    for n, name in enumerate(('ARGV', 'DOTI', 'SERR', 'SOUT', 'DOTO')):
        c2 = Conn(fr, 41010 + n)
        full = eth_ip_tcp(c2.c, c2.s, c2.cport, 3632, c2.cseq, c2.sseq, 0x18,
                          blob(name, b'x' * 200))
        fr.append((full[:54 + 12 + 50], len(full)))
    # Parameter values larger than the remaining data, without truncation
    # and at the end of a stream (reassembly asked for, never completed).
    c = Conn(fr, 41020)
    c.c2s(tok('ARGV', 0xffffffff) + b'abc')
    c = Conn(fr, 41021)
    c.s2c(tok('DOTO', 0x7fffffff) + b'abc')
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'distcc-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'distcc-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()

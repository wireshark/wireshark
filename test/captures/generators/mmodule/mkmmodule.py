#!/usr/bin/env python3
# Generates the mmodule captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic M-Module (Bachmann) coverage files for file-mmodule.c.

usage: mkmmodule.py <outdir> [-v]
mmodule-coverage.m (main: every entry tag, an ELF object code entry),
mmodule-coverage-*.m (other file tags/version types), the HTTP capture
mmodule-coverage-http.pcap (media type
application/vnd.wolfram.mathematica.package, no magic or checksum check)
and mmodule-coverage-malformed.pcap (entry count/size checks, the
reproducer of the fix).  The module contents are made-up bytes.
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

HDR = 0x30


def w(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    if VERBOSE:
        print(name, len(data))


def mfile(ftag=2, vtype=3, entries=(), nentries=None, entsz=0x30, checksum=True,
          total=None, tstamp=1700000000, pad=0):
    """entries: list of (tag, mode, name, content bytes).  Entries start at
    offset entsz (the header is entsz bytes), contents follow the table."""
    n = len(entries)
    table = b''
    contents = b''
    start = HDR + entsz * n
    for tag, mode, name, content in entries:
        e = struct.pack('<IIII IIII', tag, mode, len(content), start + len(contents),
                        vtype, 1, 2, 3) + name.encode().ljust(13, b'\0')
        table += e.ljust(entsz, b'\0')
        contents += content
    body = table + contents + b'\0' * pad
    while (HDR + len(body)) % 4:
        body += b'\0'
    words = [ftag, 5, 6, tstamp, vtype, 7, 8, 9,
             HDR + len(body) if total is None else total,
             n if nentries is None else nentries, entsz, 0]
    head = struct.pack('<12I', *words)
    data = head + body
    if checksum:
        s = sum(struct.unpack('<%dI' % (len(data) // 4), data)) & 0xffffffff
        words[11] = (-s) & 0xffffffff
        data = struct.pack('<12I', *words) + body
    return data


def elf():
    """A 64 octet ELF64 header only (relocatable, x86-64)."""
    return (b'\x7fELF\x02\x01\x01\0' + b'\0' * 8 + struct.pack('<HHIQQQIHHHHHH',
            1, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0))


TAGS = [1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 100, 200, 77]
entries = [(1, 1, 'module.o', elf())]
for i, t in enumerate(TAGS[1:]):
    entries.append((t, [1, 2, 4][i % 3], 'file%d.dat' % t, b'content %d' % t))
entries.append((9, 1, '', b''))                        # empty content
main = mfile(2, 3, entries)
w('mmodule-coverage.m', main)

# every file tag and version type once; the file tag check is 1..10
variants = []
for ft in range(1, 11):
    variants.append((ft, [1, 2, 3][ft % 3], [(4, 1, 'x.txt', b'abc')]))
for ft, vt, es in variants:
    w('mmodule-coverage-f%d.m' % ft, mfile(ft, vt, es))
# no entries at all (nentries 0, entsz 0x30)
w('mmodule-coverage-empty.m', mfile(3, 1, []))
# a larger entry size than the 0x2d needed (extra padding in each entry)
w('mmodule-coverage-entsz.m', mfile(2, 2, [(3, 1, 'lib.lib', b'lib'), (24, 1, 'a.zip', b'PK')], entsz=0x40))

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def http_pcap(fname, responses):
    """responses: list of (content type or None, body, extra header)"""
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    ts = 0
    for k, (ctype, body) in enumerate(responses):
        hdr = 'HTTP/1.1 200 OK\r\n'
        if ctype:
            hdr += 'Content-Type: %s\r\n' % ctype
        hdr += 'Content-Length: %d\r\n\r\n' % len(body)
        data = hdr.encode() + body
        seq = 1000
        sport = 40000 + k
        for i in range(0, len(data), 1400):
            segd = data[i:i + 1400]
            src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
            tcp = struct.pack('!HHIIBBHHH', 80, sport, seq, 1, 0x50, 0x18, 65535, 0, 0)
            ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(segd))
            tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + segd)) + tcp[18:]
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(segd), 1, 0, 64, 6, 0, src, dst)
            ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
            pkt = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp + segd
            out.append(struct.pack('<IIII', 1, ts, len(pkt), len(pkt)) + pkt)
            ts += 1
            seq += len(segd)
    open(os.path.join(OUT, fname), 'wb').write(b''.join(out))
    if VERBOSE:
        print(fname, len(responses), 'responses')
http_pcap('mmodule-coverage-http.pcap', [
    ('application/vnd.wolfram.mathematica.package', main),
    ('application/vnd.wolfram.mathematica.package', mfile(8, 2, [(24, 1, 'a.zip', b'PK')])),
    ('application/vnd.wolfram.mathematica.package', mfile(4, 1, [])),
])

bad = []
# reproducer of the fix: entry size zero with 0xFFFFFFFF entries
bad.append(('entsz-zero', mfile(2, 1, [], nentries=0xFFFFFFFF, entsz=0)))
bad.append(('entsz-small', mfile(2, 1, [(3, 1, 'a', b'abc')], entsz=0x2c)))
bad.append(('entsz-one', mfile(2, 1, [], nentries=3, entsz=1)))
# entry count larger than the file can hold
bad.append(('nentries', mfile(2, 1, [(3, 1, 'a', b'abc')], nentries=1000)))
bad.append(('nentries-max', mfile(2, 1, [(3, 1, 'a', b'abc')], nentries=0xFFFFFFFF)))
# the count is exactly len/entsz: the last entry does not fit
n = len(mfile(2, 1, [(3, 1, 'a', b'abc')], entsz=0x30)) // 0x30
bad.append(('nentries-edge', mfile(2, 1, [(3, 1, 'a', b'abc')], nentries=n)))
# content past the end of the file; ELF content that is not an ELF header
e = mfile(2, 1, [(3, 1, 'a', b'abc')])
bad.append(('content-past', e[:HDR + 8] + struct.pack('<I', 10000) + e[HDR + 12:]))
bad.append(('elf-junk', mfile(2, 1, [(1, 1, 'o', b'not an elf object at all, just text')])))
bad.append(('elf-short', mfile(2, 1, [(1, 1, 'o', b'\x7fELF\x02\x01')])))
# files with the wrong checksum, length or tag: the wiretap reader refuses
# them, over HTTP the dissector reads them anyway
bad.append(('cksum', mfile(2, 1, [(3, 1, 'a', b'abc')], checksum=False)))
bad.append(('len', mfile(2, 1, [(3, 1, 'a', b'abc')], total=0x1234)))
bad.append(('short', b'\0' * 0x20))
for n_, d in bad:
    w('mmodule-bad-%s.m' % n_, d)
# the entry checks only (small, committed for the test): reproducer first
http_pcap('mmodule-coverage-bad.pcap', [
    ('application/vnd.wolfram.mathematica.package', d) for n_, d in bad[:5]])
http_pcap('mmodule-coverage-malformed.pcap', [
    ('application/vnd.wolfram.mathematica.package', d) for n_, d in bad])

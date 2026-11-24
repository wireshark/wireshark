#!/usr/bin/env python3
# Generates test/captures/file_ttl_coverage.ttl.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic TTL (TraceTronic logger) files for the file-ttl dissector.

usage: mkfile-ttl.py <outdir>
file-ttl-coverage.ttl: the main capture (format version 10: 4096 octet
header with the log file information and an XML logger configuration,
blocks of trace data entries).  Read with
-X read_format:"MIME Files Format" (magic "TTL ").
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
INFO = 4080


def fixed(s, n):
    s = s.encode() if isinstance(s, str) else s
    return s[:n].ljust(n, b'\0')


def logfile_info(sorted_flag=b'1'):
    d = fixed('SN-0001', 20) + bytes([1, 2, 3, 4]) + fixed('2023-11-15 08:13:20', 20)
    d += struct.pack('<Q', 1700000000 * 1000000) + fixed('Supplier', 28) + fixed('synthetic description', 128)
    d += struct.pack('<HH', 3, 1) + fixed('config.xml', 64) + sorted_flag + struct.pack('<H', 1)
    d += fixed('2023-11-15 08:14:20', 20) + struct.pack('<Q', 1700000060 * 1000000)
    d += bytes([1, 2]) + bytes([3, 4]) + fixed('MOST25 1.0', 32) + fixed('MOST150 2.0', 32)
    d += fixed('2023-11-15 08:15:20', 20) + struct.pack('<Q', 1700000120 * 1000000)
    d += b'\0' * 512 + struct.pack('<I', 7)
    d += b'\xee' * (INFO - len(d))
    assert len(d) == INFO
    return d


def entry(etype, payload, dest=0x0123, src=0x0456, status=0, ts=1700000000 * 1000000):
    size = 16 + len(payload)
    e = struct.pack('<HHHHQ', (etype << 12) | size, dest, src, status, ts) + payload
    return e


def ttl(version=10, block=4096, header=None, info=None, xml=b'', blocks=(), magic=b'TTL '):
    inf = logfile_info() if info is None else info
    hdr_size = 16 + len(inf) + len(xml) if header is None else header
    h = magic + struct.pack('<III', version, block, hdr_size) + inf + xml
    return h + b'\0' * (max(hdr_size, len(h)) - len(h)) if hdr_size >= len(h) else h


def main():
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    xml = b'<?xml version="1.0" encoding="UTF-8"?><config><logger name="synthetic"/></config>'
    es = [entry(6, b''), entry(6, b'\0' * 8), entry(3, b'journal text\0\0\0\0'), entry(1, b'\1\2\3\4'),
          entry(7, b'sw data'), entry(8, b'\0\0\0\0'), entry(5, b'\xaa' * 8), entry(2, b'')]
    block = b''.join(es)
    BS = 256
    data = ttl(version=10, block=BS, xml=xml)
    hdr_len = len(data)
    assert hdr_len == 16 + INFO + len(xml)
    # trace data: several blocks, the last one shorter than the block size
    blocks = b''
    for i in range(3):
        b = block + entry(6, b'\0' * (BS - len(block) - 16))
        assert len(b) == BS, len(b)
        blocks += b
    blocks += block
    w('file-ttl-coverage.ttl', data + blocks)
    # version 9: no 4080 octet log file information required, short header, no XML
    v9 = ttl(version=9, block=BS, info=logfile_info(), header=16 + INFO) + blocks[:BS]
    w('file-ttl-coverage-v9.ttl', v9)
    # header size above the log file information without XML configuration: a XML text
    # which is not XML, and no entries at all (block size 0 flagged)
    w('file-ttl-coverage-badxml.ttl', ttl(version=10, block=BS, xml=b'not xml at all, just text' * 2) + blocks[:BS])
    # ----- malformed
    w('file-ttl-coverage-malformed-blocksize0.ttl', ttl(version=10, block=0, xml=xml) + blocks[:BS])
    w('file-ttl-coverage-malformed-header-short.ttl', ttl(version=10, block=BS, header=8, info=logfile_info()) + blocks[:BS])
    w('file-ttl-coverage-malformed-header-huge.ttl', ttl(version=10, block=BS, header=0x90000000, info=logfile_info())[:16 + 100])
    # a file that ends inside the log file information of a version 10 file
    w('file-ttl-coverage-malformed-info-short.ttl', ttl(version=10, block=BS, header=4096, info=logfile_info())[:3000])
    # a header size that ends before the info: only the info up to it is shown
    w('file-ttl-coverage-header-1000.ttl', ttl(version=10, block=BS, header=1000, info=logfile_info()))
    # block size wraps the offset (fix: "TTL: Stop at a block size that wraps the offset")
    w('file-ttl-coverage-blocksize-ffffffff.ttl', ttl(version=10, block=0xFFFFFFFF, xml=xml) + blocks[:100])
    # block size larger than the remaining data; entries with a size shorter than the header
    w('file-ttl-coverage-blocksize-big.ttl', ttl(version=10, block=0x10000, xml=xml) + blocks)
    bad = struct.pack('<HHHHQ', (6 << 12) | 4, 0, 0, 0, 0) + b'\0' * 20
    w('file-ttl-coverage-malformed-entry.ttl', ttl(version=10, block=BS, xml=xml) + bad + b'\0' * 4)
    # a block whose entries do not advance (size field 0 in an entry)
    w('file-ttl-coverage-zero-entries.ttl', ttl(version=10, block=BS, xml=xml) + b'\0' * 64)
    # many entries in one block (layer depth: the file dissector calls the entry dissector per entry)
    many = b''.join(entry(6, b'') for _ in range(300))
    w('file-ttl-coverage-many.ttl', ttl(version=10, block=len(many), xml=xml) + many)
    # 600 entries: every entry adds a protocol layer, and after about 497 the frame exceeds the
    # layer limit (a Dissector Bug exception; known, see the README). Not a coverage file.
    many = b''.join(entry(6, b'') for _ in range(600))
    w('file-ttl-coverage-many600.ttl', ttl(version=10, block=len(many), xml=xml) + many)
    # Exported PDU naming file-ttl
    pdus = [b'TTL ' + b'\0' * 8, (data + blocks)[:4600], b'XTL ' + b'\0' * 20]
    with open(os.path.join(OUT, 'file-ttl-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, b in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 8) + b'file-ttl' + struct.pack('>HH', 0, 0) + b
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()

#!/usr/bin/env python3
# Generates test/captures/file_blf_coverage.blf.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Vector BLF files for the file-blf dissector.

usage: mkfile-blf.py <outdir>
file-blf-coverage.blf: the main capture. It is read both by the MIME
Files Format reader (-X read_format:"MIME Files Format": the file-blf
dissector decodes the whole file) and natively (wiretap's BLF reader turns
the objects into packets, and the Ethernet status and PHY state objects
into Exported PDUs for the blf-ethernetstatus-obj and
blf-ethernetphystate-obj dissectors).
file-blf-coverage-malformed.blf and more small files: bad lengths and
the reproducers of the fixes (chained containers with a too short object
length, a zlib container inside a zlib container).
"""
import struct
import sys
import os
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
T_CONTAINER = 10


def systemtime(y, mo, wd, d, h, mi, s, ms):
    return struct.pack('<8H', y, mo, wd, d, h, mi, s, ms)


def file_header(hdr_len=144, start=None, end=None, comp=0):
    start = start or systemtime(2023, 11, 3, 15, 8, 13, 20, 123)
    end = end or systemtime(2023, 11, 3, 15, 9, 0, 0, 5)
    h = b'LOGG' + struct.pack('<IIBBBBQQII', hdr_len, 0x03040100, 1, comp, 2, 3, 0, 0, 0, 3)
    h += start + end + struct.pack('<I', 0)
    return h + b'\0' * (hdr_len - len(h)) if hdr_len >= len(h) else h


def obj(otype, payload, htype=1, version=0, ts=1000000, flags=2, hdr_len=None, obj_len=None, pad=True,
        extra_hdr=b''):
    """A log object: base header, the version 1 or 2 header, the payload."""
    if htype == 1:
        hdr2 = struct.pack('<IHHQ', flags, 7, version, ts)
    elif htype == 2:
        hdr2 = struct.pack('<IBBHQQ', flags, 1, 0, version, ts, ts + 5)
    else:
        hdr2 = b''
    hdr2 += extra_hdr
    hl = 16 + len(hdr2) if hdr_len is None else hdr_len
    ol = hl + len(payload) if obj_len is None else obj_len
    d = b'LOBJ' + struct.pack('<HHII', hl, htype, ol, otype) + hdr2 + payload
    return d + (b'\0' * ((-len(d)) % 4) if pad else b'')


def container(inner, comp=0, uncomp=None, obj_len=None):
    body = zlib.compress(inner, 9) if comp == 2 else inner
    uncomp = len(inner) if uncomp is None else uncomp
    pl = struct.pack('<HHIII', comp, 0, 0, uncomp, 0) + body
    # container objects have only the 16 octet base header
    ol = 16 + len(pl) if obj_len is None else obj_len
    d = b'LOBJ' + struct.pack('<HHII', 16, 1, ol, T_CONTAINER) + pl
    return d + b'\0' * ((-len(d)) % 4)


def apptext(source, reserved, text, textlen=None):
    t = text if isinstance(text, bytes) else text.encode()
    return struct.pack('<IIII', source, reserved, len(t) if textlen is None else textlen, 0) + t


def objects_a(native=False):
    """Objects of the first (uncompressed) container."""
    o = b''
    xml = (b'<?xml version="1.0" encoding="UTF-8"?><channels><channel id="1" type="CAN"/>'
           b'<channel id="2" type="Ethernet"/></channels>')
    # application text: comment, database channel, metadata (XML, plain, continued), attachment, trace line
    o += obj(65, apptext(0, 0, 'a comment from the measurement'), version=0)
    o += obj(65, apptext(1, (1 | (3 << 8) | (1 << 16) | (1 << 24)), 'C:\\db\\vehicle.dbc;Cluster1;'))
    o += obj(65, apptext(1, 1 | (2 << 8) | (10 << 16), 'ethernet.arxml;'))
    o += obj(65, apptext(2, (0x02 << 24) | len(xml), xml), version=0)
    o += obj(65, apptext(2, (0x01 << 24) | 10, 'plain meta'), version=0)
    o += obj(65, apptext(2, (0x03 << 24) | 40, 'first part of a longer metadata text'), version=0)
    o += obj(65, apptext(2, (0x03 << 24) | 40, 'second part of the text'), version=0)
    o += obj(65, apptext(3, 0, 'attachment.txt'))
    o += obj(65, apptext(4, 0x10, 'trace line shown in the window'))
    o += obj(65, apptext(4, 0, 'hidden trace line'))
    o += obj(65, apptext(9, 0x05, 'unknown application text source'))
    # system variable, trigger condition
    name, data = b'Sys::Counter', struct.pack('<q', 42)
    o += obj(72, struct.pack('<IIQIIQ', 1, 0, 0, len(name), len(data), 0) + name + data)
    tb, tc = b'Trigger1', b'x > 3'
    o += obj(128, struct.pack('<III', 1, len(tb), len(tc)) + tb + tc)
    # Ethernet: frame, frame ex, status (versions 0 and 1), phy state, rx error
    eth = (bytes([2, 0, 0, 0, 0, 1]) + struct.pack('<H', 1) + bytes([2, 0, 0, 0, 0, 2]) +
           struct.pack('<HHHHH', 1, 0x0800, 0, 0, 20 + 8 + 8) + b'\0' * 8)
    ip = (struct.pack('>BBHHHBBH4s4s', 0x45, 0, 36, 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) +
          struct.pack('>HHHH', 4000, 5000, 16, 0) + b'blf data')
    o += obj(71, eth + ip)
    frame = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip
    exh = struct.pack('<HHHHQIHHII', 32, 1, 2, 3, 1000, 0x1234, 1, len(frame), 77, 0)
    o += obj(120, exh + frame, version=0)
    for ver, flags in ((0, 0x3ff), (1, 0x3ff), (1, 0x0), (0, 0x0001)):
        st = struct.pack('<HHBBBBBBBBI', 1, flags, 1, 2, 1, 0, 1, 1, 2, 4, 100000000)
        if ver >= 1:
            st += struct.pack('<Q', 123456789)
        o += obj(103, st, version=ver)
    for fl in (0x7, 0x0, 0x3):
        o += obj(133, struct.pack('<HHBBBB', 1, fl, 2, 3, 4, 0))
    if not native:
        o += obj(102, struct.pack('<HHHHIHI', 18, 1, 1, 0, 0, 0, 0) + b'\0' * 4)
    return o


def objects_b(truncated=False):
    """CAN XL, a sample of the other channel types, header variants."""
    o = b''
    data = bytes(range(8))
    xl = struct.pack('<BBBBIHHIBBHHHHBBIBBBBIIIIIQQQQQQ'.replace('BBBB', 'BBBB'),
                     1, 0x12, 1, 0, 1000, 64, 0, 0x123, 1, 0, 8, 8, 0x1111, 0x2222, 1, 0, 0x55, 3, 0, 0, 0,
                     0x3333, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6) + data
    o += obj(139, xl)
    # CAN XL fields: the unpacked layout above may not match; use a precise one too
    pl = bytearray()
    pl += bytes([1, 0x12, 1, 0]) + struct.pack('<IHH', 1000, 64, 0) + struct.pack('<I', 0x123)
    pl += bytes([1, 0]) + struct.pack('<HHHH', 8, 8, 0x1111, 0x2222) + bytes([1, 0]) + struct.pack('<I', 0x55)
    pl += bytes([3, 0]) + struct.pack('<H', 0) + struct.pack('<IIII', 0x3333, 1, 2, 3)
    pl += struct.pack('<I', 4) + struct.pack('<6Q', 1, 2, 3, 4, 5, 6)
    o += obj(139, bytes(pl) + data)
    # generic 16 bit channel objects, one per range of the dissector
    for t in (1, 2, 4, 4, 11, 25, 29, 29, 45, 47, 50, 54, 55, 66, 70, 73, 74,
              76, 86, 89, 93, 95, 98, 100, 100, 106, 112, 114, 134,
              134):
        o += obj(t, struct.pack('<H', 3) + b'\0' * 30)
    # 8 bit channels
    for t in (101, 104, 140):
        o += obj(t, bytes([4]) + b'\0' * 40)
    # channel after an offset
    o += obj(102, struct.pack('<HHHHIHI', 18, 5, 1, 0, 0, 0, 0) + b'\0' * 4)
    for t in (46, 113, 122, 123):
        o += obj(t, b'\0' * 4 + struct.pack('<H', 6) + b'\0' * 20)
    o += obj(97, b'\0' * 6 + struct.pack('<H', 7) + b'\0' * 20)
    for t in (57, 64, 75, 87):
        o += obj(t, b'\0' * 12 + struct.pack('<H', 8) + b'\0' * 20)
    # object types the dissector does not know, and without a channel
    o += obj(0, b'\0' * 8)
    o += obj(118, b'\0' * 8)
    o += obj(200, b'\0' * 8)
    # headers: version 2 object header (with the original time stamp), a longer header with
    # remaining octets, a header type that has no further fields
    o += obj(1, struct.pack('<HBBI8s', 1, 0, 8, 0x100, data), htype=2)
    o += obj(1, struct.pack('<HBBI8s', 1, 0, 8, 0x101, data), htype=1, extra_hdr=b'\xaa' * 8)
    o += obj(1, struct.pack('<HBBI8s', 1, 0, 8, 0x102, data), htype=3, hdr_len=24, extra_hdr=b'\xbb' * 8)
    # a truncated object (the file ends inside it): object length larger than the data
    if truncated:
        o += obj(1, struct.pack('<HBBI8s', 1, 0, 8, 0x103, data), obj_len=400, pad=False)
    return o


def main():
    w = lambda n, d: open(os.path.join(OUT, n), 'wb').write(d)
    a, b = objects_a(), objects_b()
    # the truncated object ends the second container; the third holds more
    c = obj(65, apptext(0, 0, 'last container')) + obj(4, struct.pack('<H', 1) + b'\0' * 30)
    main_file = (file_header() + container(a) + container(b, comp=2) + container(c, comp=2) +
                 obj(65, apptext(0, 0, 'object outside of a container')))
    w('file-blf-coverage.blf', main_file)
    # the objects that wiretap's BLF reader accepts (it makes packets and Exported PDUs of them)
    w('file-blf-coverage-native.blf', file_header() + container(objects_a(True)))
    # header variations: a header date with month 0, a short file header
    w('file-blf-coverage-dates.blf',
      file_header(start=systemtime(1601, 0, 0, 0, 0, 0, 0, 0), end=systemtime(2038, 12, 6, 31, 23, 59, 59, 999)) +
      container(obj(65, apptext(0, 0, 'x'))))
    # an object that is longer than the data left (the file ends inside it): shown as TRUNCATED
    w('file-blf-coverage-truncated.blf', file_header() + container(objects_b(True)))
    # ----- malformed
    m = file_header(hdr_len=40) + b'\0' * 8                       # header length below the minimum
    m += container(obj(65, apptext(0, 0, 'in container')), obj_len=24)  # container shorter than its fields
    m += container(obj(1, b'\0' * 16), comp=2, uncomp=7)
    m += b'LOBJ' + struct.pack('<HHII', 16, 1, 16, 1)             # ends right after a base header
    m += container(obj(65, apptext(0, 0, 'zero length')), obj_len=0)    # container of length 0: parsing stops
    w('file-blf-coverage-malformed.blf', m)
    # each of these makes the payload length wrong, so the dissection ends in an exception
    w('file-blf-coverage-malformed-objlen.blf', file_header() + obj(1, b'\0' * 16, obj_len=20))
    w('file-blf-coverage-malformed-hdrlen.blf', file_header() + obj(1, b'\0' * 16, hdr_len=8))
    w('file-blf-coverage-short.blf', b'LOGG' + b'\0' * 3)           # not BLF (shorter than 8)
    # reproducer 1: chained containers whose object length is one less than the fields
    K = 26
    ov = file_header()
    for i in range(K):
        ov += b'LOBJ' + struct.pack('<HHII', 16, 1, 31, 10) + struct.pack('<HHIII', 0, 0, 0, 0, 0)
    ov += b'\0' * 16
    w('file-blf-coverage-overlap.blf', ov)
    # reproducer 2: a zlib container inside a zlib container (inner inflates to 1 MiB of zeros)
    c = zlib.compressobj(9)
    inner = c.compress(b'\0' * (1 << 20)) + c.flush()
    inner_obj = struct.pack('<4sHHII', b'LOBJ', 16, 1, 32 + len(inner), 10) + \
        struct.pack('<HHIII', 2, 0, 0, 1 << 20, 0) + inner
    outer = zlib.compress(inner_obj, 9)
    nested = file_header() + struct.pack('<4sHHII', b'LOBJ', 16, 1, 32 + len(outer), 10) + \
        struct.pack('<HHIII', 2, 0, 0, len(inner_obj), 0) + outer + b'\0' * 16
    w('file-blf-coverage-nested.blf', nested)
    # an uncompressed container inside a container is still decoded (linear work)
    inner = container(obj(65, apptext(0, 0, 'nested plain container')))
    w('file-blf-coverage-nested-plain.blf', file_header() + container(inner) + container(inner, comp=2))
    # Exported PDU naming file-blf (the first PDU is not BLF)
    pdus = [b'XOGG' + b'\0' * 30, main_file[:700] , ov[:300]]
    with open(os.path.join(OUT, 'file-blf-coverage-exppdu.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, bb in enumerate(pdus):
            pdu = struct.pack('>HH', 12, 8) + b'file-blf' + struct.pack('>HH', 0, 0) + bb
            f.write(struct.pack('<IIII', 1000 + i, 0, len(pdu), len(pdu)) + pdu)


main()

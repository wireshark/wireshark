#!/usr/bin/python3
# Generates test/captures/metamako_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Metamako trailer coverage captures.
Usage: mkmetamako.py <outdir> [-v]
Writes metamako-coverage.pcap and metamako-coverage-malformed.pcap
(Ethernet frames, IP protocol 253 plus a Metamako trailer).
Everything is synthetic."""
import struct
import sys
import os
import zlib

P = struct.pack
BASE = 1700000000

def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff

def eth_ip(payload=b'metamako test data'):
    h = P('>BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, 253, 0) + bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2])
    h = h[:10] + P('>H', csum(h)) + h[12:]
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00') + h + payload

def tlv(tag, data=b'', last=False):
    """A TLV in packet order: len data words, then the header word. For a
    TLV without data words the 24 octets of payload are the first three
    octets of `data`."""
    words = len(data) // 4
    if tag < 0x1F:
        if words:
            hdr = data[-4:]            # tag data continues in the header word
            body = data[:-4]
            body_words = len(body) // 4
            h = hdr[:3] + bytes([(min(body_words, 3) << 6) | (0x20 if last else 0) | tag])
            return body + h
        h = (data + b'\0\0\0')[:3] + bytes([(0x20 if last else 0) | tag])
        return h
    # secondary tag header: 10-bit length in bits 6-15, tag extension in 16-31
    ext = tag - 0x1F
    w = (ext << 16) | ((words - 1) << 6) | (0x20 if last else 0) | 0x1F
    return data + P('>I', w)

def trailer(tlvs=(), secs=BASE + 1, nsecs=123456789, flags=0x01, dev=0x0102, port=7,
            fcs=None, origfcs=b'\xde\xad\xbe\xef', pad=b''):
    """Original FCS, TLVs (earliest first), seconds, nanoseconds,
    flags/device/port."""
    ext = b''.join(tlvs)
    if ext:
        flags |= 0x02
    return pad + origfcs + ext + P('>II', secs, nsecs) + P('>BHB', flags, dev, port)

def with_fcs(frame):
    return frame + P('<I', zlib.crc32(frame) & 0xffffffff)

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(P('<IIII', BASE + i, 0, len(p), len(p)))
            f.write(p)

def build():
    main = []
    def add(tr, fcs=False, payload=b'metamako test data', ts=None):
        fr = eth_ip(payload) + tr
        main.append(with_fcs(fr) if fcs else fr)
    # 1-5: no extensions, flags
    add(trailer())                                  # 1
    add(trailer(flags=0x34, dev=65535, port=255))   # 2: degraded, control block 0x78, ...
    add(trailer(flags=0x25))                        # 3
    add(trailer(flags=0xfd, nsecs=999999999))       # 4: all flags except has_ext
    add(trailer(flags=0x00, dev=0, port=0))         # 5
    # 6-7: with FCS (valid)
    add(trailer(), fcs=True)                        # 6
    add(trailer(flags=0x05), fcs=True)              # 7
    # 8-: TLVs, one tag per frame (the earliest TLV has the last flag)
    add(trailer([tlv(0, b'\x00\x12\x34', True)]))               # 8: ingress sequence number 0x1234
    add(trailer([tlv(1, b'\x80\x00\x01', True)]))               # 9: sub-nanoseconds
    add(trailer([tlv(2, bytes.fromhex('0102030405060708'), True)]))    # 10: CRC64 hash (len 1)
    add(trailer([tlv(3, b'\x00\x0a\xbc', True)]))               # 11: egress sequence number
    add(trailer([tlv(0x1F, b'hello-world-tag\0', True)]))  # 12: tag string
    add(trailer([tlv(4, b'\x01\x02\x03', True)]))               # 13: unknown tag, no data words
    add(trailer([tlv(5, bytes.fromhex('a1a2a3a4b1b2b3b4c1c2c3c4'), True)]))   # 14: unknown tag, 2 data words
    add(trailer([tlv(0x1F + 0x21, bytes(range(120)), True)]))   # 15: unknown secondary tag, 120 octets (label truncated)
    add(trailer([tlv(0x1F + 7, bytes.fromhex('00112233'), True)]))   # 16: unknown secondary tag, one word
    # 17-19: several TLVs in one trailer, in different order, with FCS
    add(trailer([tlv(0x1F, b'a-tag-string-xyz\0', True), tlv(3, b'\x00\x00\x05'),
                 tlv(2, bytes.fromhex('1112131415161718')), tlv(1, b'\x40\x00\x00'),
                 tlv(0, b'\x00\x00\x09'), tlv(6, b'\1\2\3')]))   # 17
    add(trailer([tlv(0, b'\x00\x00\x01', True), tlv(1, b'\x00\x00\x02'), tlv(3, b'\x00\x00\x03')], flags=0x07),
        fcs=True)                                                # 18
    add(trailer([tlv(0, b'\x00\xff\xfe', True)] + [tlv(4, b'\0\0\0')] * 20))   # 19: many TLVs
    # 20: padding before the original FCS
    add(trailer([tlv(0, b'\x00\x00\x02', True)], pad=b'\x11\x22\x33'))
    # 21: trailer without the TLV flag still has an original FCS
    add(trailer(flags=0x01), payload=b'x' * 40)
    # 22-26: not recognised by the heuristic: timestamp far from the capture
    # time (more than 30 days), nanoseconds out of range, seconds below the
    # lower bound, a trailer shorter than 16 octets, and no trailer
    add(trailer(secs=BASE - 90 * 86400))            # 22
    add(trailer(secs=BASE + 90 * 86400))            # 23
    add(trailer(nsecs=1000000000))                  # 24
    add(trailer(secs=100))                          # 25
    main.append(eth_ip() + b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a')   # 26: short trailer
    main.append(eth_ip())                           # 27: no trailer
    # 28: the quadratic reproducer: 60000 TLVs
    n = 60000
    big = [tlv(4, b'\0\0\0', True)] + [tlv(4, b'\0\0\0')] * (n - 1)
    add(trailer(big))
    marks = len(main)

    mal = []
    def madd(tr, fcs=False, payload=b'metamako test data'):
        fr = eth_ip(payload) + tr
        mal.append(with_fcs(fr) if fcs else fr)
    # a wrong FCS (the checksum is verified by default)
    fr = eth_ip() + trailer()
    mal.append(fr + P('<I', (zlib.crc32(fr) ^ 0x55) & 0xffffffff))
    fr = eth_ip() + trailer([tlv(0, b'\0\x01\x02', True)])
    mal.append(fr + P('<I', (zlib.crc32(fr) ^ 0x55) & 0xffffffff))
    # a TLV that is not flagged "last": the walk runs to the start of the trailer
    madd(trailer([tlv(4, b'\0\0\0')]))
    # a secondary TLV whose length reaches before the trailer start
    madd(trailer([P('>I', (0 << 16) | (1000 << 6) | 0x1F)]))
    # a TLV length longer than the trailer
    madd(trailer([P('>I', (3 << 6) | 0x20 | 0x04)]))
    # a trailer with only the TLV header and a flagged extension, no original FCS
    madd(b'\x00\x00\x00\x24' + P('>II', BASE + 1, 5) + P('>BHB', 0x02, 1, 1), payload=b'')
    return main, mal, marks

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, marks = build()
    pcap(os.path.join(out, 'metamako-coverage.pcap'), main)
    pcap(os.path.join(out, 'metamako-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main frames %d, malformed %d' % (len(main), len(mal)))

#!/usr/bin/env python3
# Generates test/captures/s5066dts_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the STANAG 5066 DTS coverage captures. Usage: mks5066dts.py <outdir>"""
import sys
import os
import struct
from pcaplib import PcapNg, TcpStream

LT_5066 = 237      # LINKTYPE_STANAG_5066_D_PDU
TCPPORT = 5066

def table16(poly=0x9299):
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t.append(c)
    return t
T16 = table16()
def crc16(data, seed=0):
    c = seed
    for b in data:
        c = T16[(c ^ b) & 0xff] ^ (c >> 8)
    return c & 0xffff
def table32(poly=0xF3A4E550):
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t.append(c)
    return t
T32 = table32()
def crc32(data, seed=0):
    c = seed
    for b in data:
        c = (c >> 8) ^ T32[(c ^ b) & 0xff]
    return c & 0xffffffff

def addr(asz, dst=0x1234567, src=0x7654321):
    """asz nibbles of destination followed by asz nibbles of source"""
    digits = [(dst >> (4 * (asz - 1 - i))) & 0xf for i in range(asz)] + [(src >> (4 * (asz - 1 - i))) & 0xf for i in range(asz)]
    b = bytearray()
    for i in range(0, len(digits), 2):
        b.append((digits[i] << 4) | digits[i + 1])
    return bytes(b)

def dpdu(ptype, eow=0, eow_content=0, eot=0, asz=4, specific=b'', cpdu=b'', hsize=None,
         bad_hcrc=False, bad_ccrc=False, pad=b'', dst=0x1234567, src=0x7654321):
    hs = 6 + len(specific) if hsize is None else hsize
    a = addr(asz, dst, src)
    hdr = bytes([(ptype << 4) | eow, eow_content, eot, (asz << 5) | hs]) + a + specific
    h = crc16(hdr)
    if bad_hcrc:
        h ^= 0x5555
    out = b'\x90\xeb' + hdr + struct.pack('<H', h)
    if cpdu or ptype in (0, 2, 4, 7, 8):
        c = crc32(cpdu)
        if bad_ccrc:
            c ^= 0x12345678
        out += cpdu + struct.pack('<I', c)
    return out + pad

def sz(flags, n):
    """first two specific octets: six flag bits and the 10 bit segmented C_PDU size"""
    return struct.pack('>H', ((flags & 0x3f) << 10) | n)

def main(out):
    p = PcapNg()
    def raw(d):
        p.add(d, lt=LT_5066)
    D = b'segment of a C_PDU, STANAG 5066 data'
    # ---- every D_PDU type
    raw(dpdu(0, specific=sz(0b110000, len(D)) + b'\x05', cpdu=D))                       # data only, first and last segment
    raw(dpdu(0, specific=sz(0b001111, 3) + b'\xff', cpdu=b'abc', eot=77))
    raw(dpdu(1, specific=b'\x09' + bytes([0xff, 0x00, 0x55]), asz=4))                    # ack only with acks
    raw(dpdu(1, specific=b'\x04', asz=7))                                                # ack only, no acks
    raw(dpdu(2, specific=sz(0b100110, 4) + b'\x07\x08' + b'\xaa\xbb', cpdu=b'data'))     # data+ack with acks
    raw(dpdu(2, specific=sz(0b011001, 2) + b'\x01\x02', cpdu=b'hi'))                     # no acks
    raw(dpdu(3, specific=b'\x1f\x03\x04', asz=4))                                        # reset/win resync
    raw(dpdu(3, specific=b'\x00\x00\x00', asz=3, dst=0x123, src=0x456))
    raw(dpdu(4, specific=sz(0b110101, 5) + b'\x09', cpdu=b'12345'))                      # expedited data only
    raw(dpdu(5, specific=b'\x10' + b'\x01\x02\x03', asz=4))                              # expedited ack only with acks
    raw(dpdu(5, specific=b'\x10', asz=7))
    raw(dpdu(7, specific=sz(0b101010, 6) + b'\x07' + struct.pack('>HHH', 600, 12, 30), cpdu=b'nonarq'))   # non-ARQ data
    raw(dpdu(8, specific=sz(0b010101, 4) + b'\x08' + struct.pack('>HHH', 800, 0, 99), cpdu=b'expd'))      # expedited non-ARQ data
    raw(dpdu(15, specific=b'\x35', asz=6))                                               # warning
    raw(dpdu(9, specific=b'\x01\x02\x03', asz=4))                                        # an unassigned type
    # ---- management: plain, extended message, HDR DRC request (EOW 7), HFTRP token (EOW 15)
    raw(dpdu(6, specific=b'\x13\x42', asz=5))                                            # management without extension
    raw(dpdu(6, specific=b'\x93\x43' + b'\xde\xad\xbe\xef\x00\x01', asz=4))             # extended message as bytes
    raw(dpdu(6, eow=7, eow_content=0x21, specific=b'\x07\x44' + struct.pack('>IH', 2400, 64), asz=4))   # HDR DRC request (the dissector reads the EOW type from the first management octet, see README)
    for tok in (1, 2, 3, 4, 5, 6, 9):
        raw(dpdu(6, eow=15, eow_content=tok, specific=b'\x0f\x45' + struct.pack('>HIIIIH', 20, 0x01020304, 10 + tok, 20, 30, 5), asz=4))
    raw(dpdu(6, eow=15, eow_content=1, specific=b'\x0f\x46', asz=5))                     # HFTRP token without the extension
    # ---- every EOW type (in a DATA_ONLY... and ACK_ONLY D_PDU): 0-6, user defined 8-14
    for e in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14):
        raw(dpdu(1, eow=e, eow_content=0xA5 ^ e, specific=b'\x01', asz=7))
    for c in (0x01, 0x80, 0xff, 0x55):
        raw(dpdu(1, eow=2, eow_content=c, specific=b'\x01', asz=7))
        raw(dpdu(1, eow=3, eow_content=c, specific=b'\x01', asz=7))
        raw(dpdu(1, eow=4, eow_content=c, specific=b'\x01', asz=7))
        raw(dpdu(1, eow=5, eow_content=c, specific=b'\x01', asz=7))
        raw(dpdu(1, eow=6, eow_content=c, specific=b'\x01', asz=7))
        raw(dpdu(1, eow=1, eow_content=c, specific=b'\x01', asz=7))
    # ---- address sizes
    for a in (1, 2, 3, 5, 6, 7):
        raw(dpdu(0, specific=sz(0b110000, 20) + b'\x01', cpdu=bytes(range(20)), asz=a, dst=0x7 if a == 1 else 0x123456, src=0x5 if a == 1 else 0xabcdef))
    # ---- incorrect checksums (shown in the item text)
    raw(dpdu(0, specific=sz(0b110000, 4) + b'\x01', cpdu=b'bad!', bad_hcrc=True))
    raw(dpdu(0, specific=sz(0b110000, 4) + b'\x02', cpdu=b'bad!', bad_ccrc=True))
    # ---- header sizes too small for the fields (the reproducers of "S5066DTS: Do not wrap the ack size");
    # the fields are read past the header, so the frames carry padding after the D_PDU
    P = bytes(range(32))
    raw(dpdu(1, specific=b'', asz=7, hsize=6, pad=P))                                    # ack only, header size 6
    raw(dpdu(2, specific=sz(0b110000, 3) + b'\x01\x02', cpdu=b'abc', hsize=8, pad=P))    # data+ack, header size 8
    raw(dpdu(5, specific=b'', asz=7, hsize=6, pad=P))                                    # expedited ack only
    raw(dpdu(6, specific=b'\x03\x47', asz=4, hsize=7, pad=P))                            # management, header size 7
    raw(dpdu(6, eow=15, eow_content=1, specific=b'\x0f\x48', asz=4, hsize=7, pad=P))
    # ---- TCP: D_PDUs to the configured port 5066 (the pref "s5066dts.tcp.port"), several per segment, split
    t = TcpStream(p, 40000, TCPPORT)
    # TcpStream writes Ethernet frames through its Pcap p; it needs PcapNg add(data, lt)
    t.c(dpdu(0, specific=sz(0b110000, len(D)) + b'\x01', cpdu=D))
    t.c(dpdu(1, specific=b'\x02\x00', asz=7))
    d = dpdu(0, specific=sz(0b110000, 40) + b'\x03', cpdu=bytes(range(40)))
    t.c(d[:20]); t.c(d[20:35]); t.c(d[35:])
    t.c(dpdu(2, specific=sz(0b100000, 2) + b'\x04\x05' + b'\x01', cpdu=b'ok'))
    t.s(dpdu(1, specific=b'\x02', asz=7))                      # server to client: destination port not configured
    t.c(b'\x00\x01' + dpdu(0, specific=sz(0b110000, 3) + b'\x06', cpdu=b'sync'))    # junk before the D_PDU
    t.c(b'\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')          # sync byte 1 only
    t.fin()
    p.write(os.path.join(out, 's5066dts-coverage.pcapng'))

    # ===== malformed
    m = PcapNg()
    def mraw(d):
        m.add(d, lt=LT_5066)
    # HDR_DRC_REQUEST and HFTRP EOW types in D_PDUs that are not management: error expert infos
    mraw(dpdu(1, eow=7, eow_content=0x21, specific=b'\x01', asz=7))
    mraw(dpdu(0, eow=7, specific=sz(0b110000, 2) + b'\x01', cpdu=b'ab'))
    mraw(dpdu(1, eow=15, eow_content=1, specific=b'\x01', asz=7))
    mraw(dpdu(2, eow=15, eow_content=2, specific=sz(0b110000, 2) + b'\x01\x02', cpdu=b'ab'))
    # not D_PDUs: too short, no sync pattern, sync first byte only
    mraw(b'\x90\xeb\x00\x00')
    mraw(b'\x91\xeb' + bytes(20))
    mraw(b'\x90\xec' + bytes(20))
    # truncated D_PDUs: in the address, in the specific header, in the C_PDU, without the CRC
    d = dpdu(0, specific=sz(0b110000, 30) + b'\x01', cpdu=bytes(30))
    mraw(d[:8] + bytes(8))
    mraw(d[:16])
    mraw(d[:20])
    mraw(d[:-6])
    mraw(d[:-1])
    mraw(dpdu(1, specific=b'\x01\x02\x03\x04\x05\x06', asz=4)[:-8] + bytes(8))
    # sizes beyond the data: the C_PDU size 1023 and a header size of 31
    mraw(dpdu(0, specific=sz(0b110000, 1023) + b'\x01', cpdu=bytes(8)))
    mraw(dpdu(1, specific=b'\x01', asz=7, hsize=31))
    mraw(dpdu(6, specific=b'\x13\x42', asz=4, hsize=31, pad=bytes(40)))
    mraw(dpdu(6, eow=15, eow_content=1, specific=b'\x13\x42', asz=4, hsize=31, pad=bytes(10)))
    mraw(dpdu(1, specific=b'', asz=7, hsize=6))                                   # undersized header without padding (exception)
    mraw(dpdu(2, specific=sz(0b110000, 3) + b'\x01\x02', cpdu=b'abc', hsize=8))
    mraw(dpdu(6, specific=b'\x03\x47', asz=4, hsize=7))
    # a D_PDU with the maximum address size and a short header
    mraw(dpdu(0, specific=sz(0b110000, 2) + b'\x01', cpdu=b'ab', asz=0))
    # TCP: two D_PDUs in one segment (the length of the second one is taken from the first: the offset is not used)
    t = TcpStream(m, 40002, TCPPORT)
    t.c(dpdu(1, specific=b'\x02\x00', asz=7) + dpdu(0, specific=sz(0b110000, 3) + b'\x02', cpdu=b'xyz'))
    t.c(dpdu(0, specific=sz(0b110000, 3) + b'\x02', cpdu=b'xyz') + dpdu(1, specific=b'\x02\x00', asz=7))
    t.fin()
    # TCP: a D_PDU with the size of a huge segment, split in pieces, and a bad stream
    t = TcpStream(m, 40001, TCPPORT)
    t.c(dpdu(0, specific=sz(0b110000, 1000) + b'\x01', cpdu=bytes(1000)))
    t.c(b'\x90\xeb\x00')
    t.c(dpdu(1, specific=b'\x01', asz=7)[:5])
    t.c(b'\x90')
    t.c(b'\xeb' + bytes(30))
    t.fin()
    m.write(os.path.join(out, 's5066dts-coverage-malformed.pcapng'))

main(sys.argv[1])

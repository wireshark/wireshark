#!/usr/bin/python3
# Generates test/captures/meta_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the META coverage captures. Usage: mkmeta.py <outdir> [-v]
Writes meta-coverage.pcap and meta-coverage-malformed.pcap (Exported PDU,
link type 252, dissector name "meta"). Everything is synthetic."""
import struct
import sys
import os
import zlib

P = struct.pack
SCHEMA_PCAP, SCHEMA_DXT = 1, 2

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return P('>HH', 12, len(n) + pad) + n + b'\0' * pad + P('>HH', 0, 0) + payload

def write_pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            f.write(P('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def item(iid, typ, data=b''):
    """A META item: id, type, length, data padded to 4 octets."""
    return P('<HBB', iid, typ, len(data)) + data + b'\0' * (-len(data) % 4)

def meta(schema, proto, items=b'', body=b'', hdrlen=None):
    return P('<HHHH', schema, len(items) if hdrlen is None else hdrlen, proto, 0) + items + body

def frame(*a, **k):
    return exp_pdu('meta', meta(*a, **k))

def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff

def udp_ip(n=0):
    pl = b'meta test %d' % n
    u = P('>HHHH', 40000 + n, 49999, 8 + len(pl), 0) + pl
    ps = bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2]) + P('>BBH', 0, 17, len(u))
    u = u[:6] + P('>H', csum(ps + u)) + u[8:]
    h = P('>BBHHHBBH', 0x45, 0, 20 + len(u), n, 0, 64, 17, 0) + bytes([192, 0, 2, 1]) + bytes([192, 0, 2, 2])
    return h[:10] + P('>H', csum(h)) + h[12:] + u

def eth(n=0):
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + udp_ip(n)

def eth_fcs(n=0):
    f = eth(n)
    return f + P('<I', zlib.crc32(f))

# item ids
DIR, SIG, INC, DEC, CUT, TS, AAL5 = 1, 2, 3, 4, 5, 6, 7
PHY, LDEV, RDEV, TAP = 256, 257, 258, 259
IMSI, IMEI, CELL, TLLI, NSAPI, APN, RAT, CALLING, CALLED = 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032
T_NONE, T_BOOL, T_U8, T_U16, T_U32, T_U64, T_STR = 0, 1, 2, 3, 4, 5, 16

def all_items(direction=0):
    return b''.join([
        item(DIR, T_U8, P('<B', direction)),
        item(TS, T_U64, P('<Q', 0x0123456789abcdef)),
        item(PHY, T_U16, P('<H', 12)),
        item(NSAPI, T_U8, P('<B', 5)),
        item(IMSI, T_U64, bytes.fromhex('2143658709214365')),
        item(IMEI, T_U64, bytes.fromhex('3254769810325476')),
        item(APN, T_STR, b'internet.example'),
        item(RAT, T_U8, P('<B', 1)),
        item(CELL, T_U64, bytes.fromhex('21f35412340500' '01')),
        item(SIG, T_NONE), item(INC, T_NONE), item(DEC, T_NONE),
        item(LDEV, T_U16, P('<H', 7)), item(RDEV, T_U16, P('<H', 8)),
        item(TAP, T_U16, P('<H', 9)),
        item(TLLI, T_U32, P('<I', 0xc0123456)),
        item(CALLING, T_STR, b'491234567'), item(CALLED, T_STR, b'498765432'),
        item(CUT, T_U32, P('<I', 100)),        # known id, not decoded (default)
        item(999, T_U8, b'\x01'),              # unknown id
        item(998, T_STR, b'a longer unknown item of 29 octets'[:29]),
        item(997, T_NONE),                     # unknown id without data
    ])

def sscop_aal5(sdu, n=0):
    """AAL5 CPCS-PDU: SDU, padding, 8 octet trailer (UU, CPI, length, CRC)."""
    pad = -(len(sdu) + 8) % 48
    body = sdu + b'\0' * pad + P('>BBH', 0, 0, len(sdu))
    return body + P('>I', zlib.crc32(body) & 0xffffffff)

def atm_hdr(vpi, vci):
    return P('>I', (vpi << 20) | (vci << 4))

def build():
    main = []
    def add(*a, **k):
        main.append(frame(*a, **k))
    # DXT schema
    add(SCHEMA_DXT, 1, body=eth(1))                                  # 1: no items
    add(SCHEMA_DXT, 1, all_items(0), eth(2))                         # 2: every item, up
    add(SCHEMA_DXT, 1, item(DIR, T_U8, b'\1'), eth(3))               # 3: down
    add(SCHEMA_DXT, 36, item(DIR, T_U8, b'\0'), eth_fcs(4))          # 4: Ethernet with FCS
    add(SCHEMA_DXT, 41, body=bytes.fromhex('0010 0020 00 00') + bytes(48)[:46])   # 5: ATM
    # ERF AAL5: the AAL5 protocol item selects the payload type
    for i, p in enumerate((2, 3, 5, 6, 9)):                          # 6-10
        add(SCHEMA_DXT, 49, item(AAL5, T_U8, P('<B', p)),
            atm_hdr(1, 32 + i) + sscop_aal5(b'\x0a' if p == 3 else
                b'\x00\x00\x00\x01' + bytes(range(16)) + b'\x00\x00\x00\x10'))
    add(SCHEMA_DXT, 49, body=atm_hdr(1, 40) + bytes(range(48)))      # 11: no item (reproducer: uninitialised ATM info)
    add(SCHEMA_DXT, 106, body=bytes.fromhex('0001 0102 0300') + b'\x00' * 6 + b'\xaa\xbb')   # 12: HDLC -> MTP2
    add(SCHEMA_DXT, 82, body=bytes.fromhex('01 00 00 10 00 10 00 00') + bytes(8))   # 13: FP hint
    # protocols with no handler in meta.proto: data dissector
    for p in (61, 69, 127, 193, 194):                                # 14-18
        add(SCHEMA_DXT, p, body=bytes(range(12)))
    add(SCHEMA_DXT, 0x1234, body=b'\0' * 8)                          # 19: reproducer (NULL handle)
    add(SCHEMA_DXT, 0x7fff, item(TLLI, T_U32, P('<I', 0x12345678)), b'\0' * 8)   # 20: reproducer (TLLI)
    # PCAP schema: direction, timestamp, signaling, incomplete, other items
    add(SCHEMA_PCAP, 1, b''.join([item(DIR, T_U8, b'\0'), item(TS, T_U64, P('<Q', 99)),
        item(SIG, T_NONE), item(INC, T_NONE), item(300, T_U32, P('<I', 1)),
        item(DIR, T_U8, b'\1')]), eth(5))                            # 21
    add(SCHEMA_PCAP, 1, body=b'data without items')                  # 22
    # unknown schema: every item is skipped
    add(3, 1, item(1, T_U8, b'\1') + item(2, T_NONE) + item(1000, T_STR, b'text'), b'payload')  # 23
    add(3, 1, body=b'payload')                                       # 24
    marks = len(main)

    mal = []
    def madd(*a, **k):
        mal.append(frame(*a, **k))
    madd(SCHEMA_DXT, 1, item(DIR, T_U8, b'\0'), eth(6), hdrlen=12)      # header length does not match the items
    madd(SCHEMA_DXT, 1, item(DIR, T_U8, b'\0'), eth(7), hdrlen=2)
    madd(SCHEMA_DXT, 1, hdrlen=40, body=b'\1\0\2\0')                # items run past the end
    # ATM AAL2 (UMTS FP): the FP dissector needs per-frame info that only
    # a file reader supplies, so it reports an error
    madd(SCHEMA_DXT, 76, body=P('>II', 0x00000007, (3 << 20) | (33 << 4)) + bytes(32))
    madd(SCHEMA_DXT, 76, body=b'\0\0\0\1')                          # AAL2: header words missing
    madd(SCHEMA_DXT, 49, body=b'\0\0')                              # ERF AAL5: ATM header missing
    madd(SCHEMA_DXT, 106, body=b'\0')                               # HDLC shorter than the FCS
    mal.append(exp_pdu('meta', b'\2\0\0'))                          # shorter than the header
    madd(SCHEMA_DXT, 1, item(IMSI, T_U64, b'\1\2\3'), b'\0' * 4)    # item data past the end
    # item offset past 65535: 252 items of 260 octets and two of 4
    # (the offset check catches the first, the second wraps a 16-bit offset
    # inside the item and raises an exception; see README)
    big = item(500, T_STR, bytes(255)) * 252
    madd(SCHEMA_DXT, 1, big + item(501, T_U32, bytes(4)), eth(8), hdrlen=65535)
    madd(SCHEMA_DXT, 1, big + item(501, T_NONE) * 2, eth(9), hdrlen=65535)
    return main, mal, marks

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, marks = build()
    write_pcap(os.path.join(out, 'meta-coverage.pcap'), main)
    write_pcap(os.path.join(out, 'meta-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main frames %d; malformed %d' % (len(main), len(mal)))

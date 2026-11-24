#!/usr/bin/env python3
# Generates test/captures/gsm_l2rcop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the GSM L2RCOP coverage captures. Usage: mkgsm_l2rcop.py <outdir>

Writes gsm_l2rcop-coverage.pcap (valid frames) and
gsm_l2rcop-coverage-malformed.pcap (bad FCS, truncated frames). The L2RCOP data is
carried in RLP IS frames, which are carried in GSMTAP (UDP port 4729, type 0x14, GSM RLP). Everything is
synthetic; the FCS is the CRC-24 of 3GPP TS 24.022 section 4.4 computed with
the table of the specification.
"""
import struct
import sys
import socket

FCS_TABLE = [
    0x00B29D2D, 0x00643A5B, 0x0044D87A, 0x00927F0C, 0x00051C38, 0x00D3BB4E, 0x00F3596F, 0x0025FE19,
    0x008694BC, 0x005033CA, 0x0070D1EB, 0x00A6769D, 0x003115A9, 0x00E7B2DF, 0x00C750FE, 0x0011F788,
    0x00DA8E0F, 0x000C2979, 0x002CCB58, 0x00FA6C2E, 0x006D0F1A, 0x00BBA86C, 0x009B4A4D, 0x004DED3B,
    0x00EE879E, 0x003820E8, 0x0018C2C9, 0x00CE65BF, 0x0059068B, 0x008FA1FD, 0x00AF43DC, 0x0079E4AA,
    0x0062BB69, 0x00B41C1F, 0x0094FE3E, 0x00425948, 0x00D53A7C, 0x00039D0A, 0x00237F2B, 0x00F5D85D,
    0x0056B2F8, 0x0080158E, 0x00A0F7AF, 0x007650D9, 0x00E133ED, 0x0037949B, 0x001776BA, 0x00C1D1CC,
    0x000AA84B, 0x00DC0F3D, 0x00FCED1C, 0x002A4A6A, 0x00BD295E, 0x006B8E28, 0x004B6C09, 0x009DCB7F,
    0x003EA1DA, 0x00E806AC, 0x00C8E48D, 0x001E43FB, 0x008920CF, 0x005F87B9, 0x007F6598, 0x00A9C2EE,
    0x0049DA1E, 0x009F7D68, 0x00BF9F49, 0x0069383F, 0x00FE5B0B, 0x0028FC7D, 0x00081E5C, 0x00DEB92A,
    0x007DD38F, 0x00AB74F9, 0x008B96D8, 0x005D31AE, 0x00CA529A, 0x001CF5EC, 0x003C17CD, 0x00EAB0BB,
    0x0021C93C, 0x00F76E4A, 0x00D78C6B, 0x00012B1D, 0x00964829, 0x0040EF5F, 0x00600D7E, 0x00B6AA08,
    0x0015C0AD, 0x00C367DB, 0x00E385FA, 0x0035228C, 0x00A241B8, 0x0074E6CE, 0x005404EF, 0x0082A399,
    0x0099FC5A, 0x004F5B2C, 0x006FB90D, 0x00B91E7B, 0x002E7D4F, 0x00F8DA39, 0x00D83818, 0x000E9F6E,
    0x00ADF5CB, 0x007B52BD, 0x005BB09C, 0x008D17EA, 0x001A74DE, 0x00CCD3A8, 0x00EC3189, 0x003A96FF,
    0x00F1EF78, 0x0027480E, 0x0007AA2F, 0x00D10D59, 0x00466E6D, 0x0090C91B, 0x00B02B3A, 0x00668C4C,
    0x00C5E6E9, 0x0013419F, 0x0033A3BE, 0x00E504C8, 0x007267FC, 0x00A4C08A, 0x008422AB, 0x005285DD,
    0x001F18F0, 0x00C9BF86, 0x00E95DA7, 0x003FFAD1, 0x00A899E5, 0x007E3E93, 0x005EDCB2, 0x00887BC4,
    0x002B1161, 0x00FDB617, 0x00DD5436, 0x000BF340, 0x009C9074, 0x004A3702, 0x006AD523, 0x00BC7255,
    0x00770BD2, 0x00A1ACA4, 0x00814E85, 0x0057E9F3, 0x00C08AC7, 0x00162DB1, 0x0036CF90, 0x00E068E6,
    0x00430243, 0x0095A535, 0x00B54714, 0x0063E062, 0x00F48356, 0x00222420, 0x0002C601, 0x00D46177,
    0x00CF3EB4, 0x001999C2, 0x00397BE3, 0x00EFDC95, 0x0078BFA1, 0x00AE18D7, 0x008EFAF6, 0x00585D80,
    0x00FB3725, 0x002D9053, 0x000D7272, 0x00DBD504, 0x004CB630, 0x009A1146, 0x00BAF367, 0x006C5411,
    0x00A72D96, 0x00718AE0, 0x005168C1, 0x0087CFB7, 0x0010AC83, 0x00C60BF5, 0x00E6E9D4, 0x00304EA2,
    0x00932407, 0x00458371, 0x00656150, 0x00B3C626, 0x0024A512, 0x00F20264, 0x00D2E045, 0x00044733,
    0x00E45FC3, 0x0032F8B5, 0x00121A94, 0x00C4BDE2, 0x0053DED6, 0x008579A0, 0x00A59B81, 0x00733CF7,
    0x00D05652, 0x0006F124, 0x00261305, 0x00F0B473, 0x0067D747, 0x00B17031, 0x00919210, 0x00473566,
    0x008C4CE1, 0x005AEB97, 0x007A09B6, 0x00ACAEC0, 0x003BCDF4, 0x00ED6A82, 0x00CD88A3, 0x001B2FD5,
    0x00B84570, 0x006EE206, 0x004E0027, 0x0098A751, 0x000FC465, 0x00D96313, 0x00F98132, 0x002F2644,
    0x00347987, 0x00E2DEF1, 0x00C23CD0, 0x00149BA6, 0x0083F892, 0x00555FE4, 0x0075BDC5, 0x00A31AB3,
    0x00007016, 0x00D6D760, 0x00F63541, 0x00209237, 0x00B7F103, 0x00615675, 0x0041B454, 0x00971322,
    0x005C6AA5, 0x008ACDD3, 0x00AA2FF2, 0x007C8884, 0x00EBEBB0, 0x003D4CC6, 0x001DAEE7, 0x00CB0991,
    0x00686334, 0x00BEC442, 0x009E2663, 0x00488115, 0x00DFE221, 0x00094557, 0x0029A776, 0x00FF0000,
]

def fcs(b):
    d = 0
    for c in b:
        d = (d >> 8) ^ FCS_TABLE[c ^ (d & 0xff)]
    return bytes([(d >> 0) & 0xff, (d >> 8) & 0xff, (d >> 16) & 0xff])

def fcs3(b):
    """The 3 octet FCS as the dissector computes and compares it."""
    d = 0
    for c in b:
        d = (d >> 8) ^ FCS_TABLE[c ^ (d & 0xff)]
    v = ((d & 0xff) << 16) | (d & 0xff00) | ((d & 0xff0000) >> 16)
    return struct.pack('>I', v)[1:]

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def gsmtap(payload, typ=0x14, ts=1, arfcn=0, fn=0, sub=0):
    return struct.pack('>BBBBHBBIBBBB', 2, 4, typ, ts, arfcn, 0, 0, fn, sub, 0, 0, 0) + payload

def frame(payload, sport=4729):
    udp = struct.pack('>HHHH', sport, 4729, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                    socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + h + udp

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def rlp_u(uftype, pf=0, cr=1, payload=b'', good=True):
    o0 = cr | (0x1f << 3)
    o1 = 0x01 | (pf << 1) | (uftype << 2)
    b = bytes([o0, o1]) + payload
    return b + (fcs3(b) if good else b'\xde\xad\x00')

def rlp_s(sftype, nr, pf=0, cr=0):
    o0 = cr | (sftype << 1) | (0x1e << 3)
    o1 = 0x01 | (pf << 1) | (nr << 2)
    b = bytes([o0, o1])
    return b + fcs3(b)

def rlp_is(ns, nr, sftype, data, pf=0, cr=0, good=True):
    o0 = cr | (sftype << 1) | ((ns & 0x1f) << 3)
    o1 = ((ns >> 5) & 1) | (pf << 1) | (nr << 2)
    b = bytes([o0, o1]) + data
    return b + (fcs3(b) if good else b'\xba\xd0\x01')

def xid(*params):
    """params: (type, value bytes); ends with a delimiter parameter."""
    out = b''
    for t, v in params:
        out += bytes([(t << 4) | len(v)]) + v
    return out + b'\x00'

def isf(n, payload, good=True):
    """An RLP IS frame carrying an L2RCOP payload (padded to 24 octets
    only where the caller says so)."""
    return rlp_is(n & 0x3d, (n * 3) & 0x3f, n & 3, payload, pf=n & 1, cr=(n >> 1) & 1, good=good)

def main(out):
    ok, bad = [], []
    chunks = []
    # status octets: SA/SB/X bits in every combination
    for sa in (0, 1):
        for sb in (0, 1):
            for x in (0, 1):
                chunks.append(bytes([(sa << 7) | (sb << 6) | (x << 5) | 0x1f]))
    # last status change, remainder full of characters
    chunks.append(bytes([0x1e]) + b'+++ATH0\r')
    chunks.append(bytes([0xde]) + b'')
    # destructive break and its acknowledge
    chunks.append(bytes([0x1d]))
    chunks.append(bytes([0x3c]))
    # N characters, N = 1..26, one chunk per frame, and with flow control
    for n in range(1, 27):
        chunks.append(bytes([n | (0x20 if n & 1 else 0)]) + bytes(65 + (i % 26) for i in range(n)))
    # extended address: 1..63 characters (63 does not fit with the rest, so up to 40)
    for n in (1, 2, 17, 37, 40):
        chunks.append(bytes([0x1b, n]) + bytes(97 + (i % 26) for i in range(n)))
    # several chunks in one frame, ending with a status change
    chunks.append(bytes([0x02]) + b'AB' + bytes([0x1b, 3]) + b'xyz' + bytes([0x01]) + b'Q' + bytes([0x1f]))
    chunks.append(bytes([0x04]) + b'abcd' + bytes([0x1d]))
    chunks.append(bytes([0x05]) + b'12345' + bytes([0x1e]) + b'rest')
    chunks.append(bytes([0x03]) + b'xyz' + bytes([0x1c]))
    # "cannot happen" cases that end the dissection: address 0 and an
    # extended address of 0
    chunks.append(bytes([0x00]) + b'ignored')
    chunks.append(bytes([0x03]) + b'abc' + bytes([0x00, 0x00]))
    chunks.append(bytes([0x1b, 0x00]) + b'ignored')
    chunks.append(bytes([0x1b, 0x40 | 0x02]) + b'hi')   # upper bits of the ext octet are masked
    for i, c in enumerate(chunks):
        ok.append(isf(i, c))
    # Not in the main capture: characters beyond the frame, a truncated
    # extended address, wrong FCS
    bad.append(isf(1, bytes([0x10]) + b'short'))
    bad.append(isf(2, bytes([0x1b])))
    bad.append(isf(3, bytes([0x1b, 0x20]) + b'short'))
    bad.append(isf(4, bytes([0x1e]) + b'ok', good=False))
    bad.append(isf(5, bytes([0x02]) + b'ab' + bytes([0x1b])))
    bad.append(isf(6, b''))
    pcap(out + '/gsm_l2rcop-coverage.pcap', [frame(gsmtap(p)) for p in ok])
    pcap(out + '/gsm_l2rcop-coverage-malformed.pcap', [frame(gsmtap(p)) for p in bad])
    print(len(ok), len(bad))

main(sys.argv[1] if len(sys.argv) > 1 else '.')

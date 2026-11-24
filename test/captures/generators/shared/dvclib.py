# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Dynamic virtual channel (MS-RDPEDYC) PDUs and a ZGFX (RDP8 bulk compression)
# encoder that only writes literal tokens, back references and uncompressed
# runs.  Copied into the directories of the RDP family generators.
import struct


def vint(n, cb):
    return struct.pack(('<B', '<H', '<I')[cb], n)


def hdr(cmd, cb=0, sp=0):
    return bytes([(cmd << 4) | (sp << 2) | cb])


def create_req(cid, name, cb=0, pri=0):
    return hdr(1, cb, pri) + vint(cid, cb) + name.encode() + b'\0'


def create_resp(cid, status=0, cb=0):
    return hdr(1, cb) + vint(cid, cb) + struct.pack('<i', status)


def caps_req(version=3, prios=(0x0cc, 0x1ea, 0x395, 0x7d1)):
    b = hdr(5) + b'\0' + struct.pack('<H', version)
    if version > 1:
        b += struct.pack('<4H', *prios)
    return b


def caps_resp(version=3):
    return hdr(5) + b'\0' + struct.pack('<H', version)


def data_first(cid, total, payload, cb=0, lb=0, compressed=False):
    return hdr(6 if compressed else 2, cb, lb) + vint(cid, cb) + vint(total, lb) + payload


def data(cid, payload, cb=0, compressed=False):
    return hdr(7 if compressed else 3, cb) + vint(cid, cb) + payload


def close(cid, cb=0):
    return hdr(4, cb) + vint(cid, cb)


def softsync_req(tunnels, flags=0x03):
    """tunnels: list of (tunnelType, [dvcIds])"""
    body = struct.pack('<HH', flags, len(tunnels))
    for tt, ids in tunnels:
        body += struct.pack('<IH', tt, len(ids)) + b''.join(struct.pack('<I', i) for i in ids)
    return hdr(8) + b'\0' + struct.pack('<I', len(body)) + body


def softsync_resp(tunnels):
    return hdr(9) + b'\0' + struct.pack('<I', len(tunnels)) + b''.join(struct.pack('<I', t) for t in tunnels)


# ---------------------------------------------------------------- ZGFX
LIT_TABLE = [  # (prefixLength, prefixCode, valueBase)
    (5, 24, 0x00), (5, 25, 0x01), (6, 52, 0x02), (6, 53, 0x03), (6, 54, 0xFF), (7, 110, 0x04),
    (7, 111, 0x05), (7, 112, 0x06), (7, 113, 0x07), (7, 114, 0x08), (7, 115, 0x09), (7, 116, 0x0A),
    (7, 117, 0x0B), (7, 118, 0x3A), (7, 119, 0x3B), (7, 120, 0x3C), (7, 121, 0x3D), (7, 122, 0x3E),
    (7, 123, 0x3F), (7, 124, 0x40), (7, 125, 0x80), (8, 252, 0x0C), (8, 253, 0x38), (8, 254, 0x39),
    (8, 255, 0x66)]
MATCH_TABLE = [  # (prefixLength, prefixCode, valueBits, valueBase)
    (5, 17, 5, 0), (5, 18, 7, 32), (5, 19, 9, 160), (5, 20, 10, 672), (5, 21, 12, 1696),
    (6, 44, 14, 5792), (6, 45, 15, 22176), (7, 92, 18, 54944), (7, 93, 20, 317088),
    (8, 188, 20, 1365664), (8, 189, 21, 2414240), (9, 380, 22, 4511392), (9, 381, 23, 8705696),
    (9, 382, 24, 17094304)]


class Bits:
    def __init__(self):
        self.bits = []

    def put(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def raw(self, data):
        assert len(self.bits) % 8 == 0
        for b in data:
            self.put(b, 8)

    def finish(self):
        pad = (-len(self.bits)) % 8
        self.bits += [0] * pad
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for b in self.bits[i:i + 8]:
                v = (v << 1) | b
            out.append(v)
        out.append(pad)
        return bytes(out)


def z_lit(bs, byte):
    """A literal: through the table when the value is in it, else 0 + 8 bits."""
    for plen, pcode, base in LIT_TABLE:
        if base == byte:
            bs.put(pcode, plen)
            return
    bs.put(0, 1)
    bs.put(byte, 8)


def z_lit_raw(bs, byte):
    bs.put(0, 1)
    bs.put(byte, 8)


def z_match(bs, distance, count):
    for plen, pcode, vbits, vbase in MATCH_TABLE:
        if vbase <= distance < vbase + (1 << vbits):
            bs.put(pcode, plen)
            bs.put(distance - vbase, vbits)
            break
    else:
        raise ValueError(distance)
    if count == 3:
        bs.put(0, 1)
        return
    k = 0
    while 4 << (k + 1) <= count:
        k += 1
    bs.put(1, 1)
    bs.put((1 << k) - 1, k)          # k ones
    bs.put(0, 1)
    bs.put(count - (4 << k), 2 + k)


def z_unencoded(bs, data):
    bs.put(17, 5)
    bs.put(0, 5)
    bs.put(len(data), 15)
    bs.align()
    bs.raw(data)


def zseg_raw(data):
    """A segment that is not compressed (flags without PACKET_COMPRESSED)."""
    return bytes([0x04]) + data


def zseg_literals(data, table=True):
    bs = Bits()
    for b in data:
        (z_lit if table else z_lit_raw)(bs, b)
    return bytes([0x24]) + bs.finish()


def zseg_with_match(data):
    """Literals of the first half, then a back reference that repeats it, then
    an unencoded run of the rest."""
    h = data[:max(3, len(data) // 2)]
    bs = Bits()
    for b in h:
        z_lit(bs, b)
    z_match(bs, len(h), len(h))
    z_unencoded(bs, data[len(h):])
    return bytes([0x24]) + bs.finish(), h + h + data[len(h):]


def zsingle(seg):
    return bytes([0xe0]) + seg


def zmulti(segs, total):
    out = bytes([0xe1]) + struct.pack('<HI', len(segs), total)
    for s in segs:
        out += struct.pack('<I', len(s)) + s
    return out

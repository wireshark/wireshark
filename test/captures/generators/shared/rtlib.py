# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers shared by the radiotap family generators (synthetic data only).
import struct
import random
import zlib

ALIGN_SIZE = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1),
    7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1),
    14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3),
    20: (4, 8), 21: (2, 12), 22: (8, 12), 23: (2, 12), 24: (2, 12), 26: (1, 1),
    27: (2, 4),
}
EXT, RTNS, VENNS, TLVBIT = 31, 29, 30, 28


def write_pcap(path, linktype, pkts, t0=1700000000, step=1000):
    """pkts: list of bytes or (bytes, usec)"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        us = 0
        for p in pkts:
            if isinstance(p, tuple):
                p, us = p
            else:
                us += step
            sec = t0 + us // 1000000
            f.write(struct.pack('<IIII', sec, us % 1000000, len(p), len(p)))
            f.write(p)


MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')
MAC3 = bytes.fromhex('020000000003')


def nulldata(seq=0, fc=0x0148, qos=False, to_ds=True, retry=False):
    """Null data (or QoS null) frame, no IEs, no payload"""
    sub = 0xc8 if qos else 0x48
    flags = (0x01 if to_ds else 0x02) | (0x08 if retry else 0)
    f = struct.pack('<BBH', sub, flags, 0) + MAC1 + MAC2 + MAC3 + struct.pack('<H', (seq & 0xfff) << 4)
    if qos:
        f += struct.pack('<H', 0)
    return f


def ack(ra=MAC1):
    return struct.pack('<BBH', 0xd4, 0, 0) + ra


def rts(dur=100):
    return struct.pack('<BBH', 0xb4, 0, dur) + MAC1 + MAC2


def beacon(ssid=b'', seq=0, ts=0):
    # fixed params only, one SSID IE, no vendor IEs
    f = struct.pack('<BBH', 0x80, 0, 0) + b'\xff' * 6 + MAC2 + MAC2 + struct.pack('<H', (seq & 0xfff) << 4)
    f += struct.pack('<QHH', ts, 100, 0x0401) + bytes([0, len(ssid)]) + ssid
    return f


def add_fcs(frame):
    return frame + struct.pack('<I', zlib.crc32(frame) & 0xffffffff)


def build(blocks, tlv=None, ver=0, pad=0, length_adj=0):
    """blocks: list of ('rt', [(idx, bytes)...]) or ('ven', oui, subns, bits, data)
    A ('rt') block may also hold index 29/30/28 implicitly: next block type
    decides bit 29/30.  tlv: list of (type, bytes) appended after the last
    word when the last word has bit 28."""
    words = []
    n = len(blocks)
    for i, b in enumerate(blocks):
        w = 0
        if b[0] == 'rt':
            for idx, _ in b[1]:
                w |= 1 << idx
        else:
            w = b[3]
        if i + 1 < n:
            w |= 1 << EXT
            w |= 1 << (VENNS if blocks[i + 1][0] == 'ven' else RTNS)
        words.append(w)
    if tlv is not None:
        words[-1] |= 1 << TLVBIT
    hdr_len = 4 + 4 * len(words)
    body = b''

    def al(a):
        nonlocal body
        while (hdr_len + len(body)) % a:
            body += b'\0'
    for i, b in enumerate(blocks):
        if b[0] == 'rt':
            for idx, data in b[1]:
                if idx in ALIGN_SIZE:
                    al(ALIGN_SIZE[idx][0])
                body += data
        else:
            body += b[4]
        if i + 1 < n and blocks[i + 1][0] == 'ven':
            nb = blocks[i + 1]
            al(2)
            body += nb[1] + bytes([nb[2]]) + struct.pack('<H', len(nb[4]))
    if tlv is not None:
        al(4)
        for t, d in tlv:
            body += struct.pack('<HH', t, len(d)) + d + b'\0' * ((-len(d)) % 4)
    total = hdr_len + len(body)
    out = struct.pack('<BBH', ver, pad, total + length_adj)
    for w in words:
        out += struct.pack('<I', w)
    return out + body


def simple(fields, tlv=None, **kw):
    """fields: list of (idx, bytes) in one radiotap namespace word"""
    return build([('rt', sorted(fields, key=lambda x: x[0]))], tlv=tlv, **kw)

#!/usr/bin/env python3
# Generates test/captures/ossp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSSP / ESMC coverage captures.

Usage: mkossp.py <outdir>

OSSP (Organization Specific Slow Protocol, IEEE 802.3 Annex 57B) carries
the ITU-T ESMC (Ethernet Synchronization Messaging Channel). Frames are
Ethernet slow protocols (ethertype 0x8809, subtype 0x0a), which reach OSSP
by default.

Writes ossp-coverage.pcapng (clean, the Option I quality levels, which is
the default of the ossp.option_network preference), ossp-coverage-malformed.pcapng
(reserved bits, wrong TLV types and lengths, unknown quality levels,
short frames) and ossp-coverage-opt2.pcapng (the Option II quality levels,
clean with -o ossp.option_network:2; runcov.sh only). Synthetic: nothing comes from a real network.
"""
import struct
import sys
import os

def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)

def pcapng(path, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += _blk(1, struct.pack('<HHI', 1, 0, 262144))
    for i, p in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

def eth(payload, src=1, pad=True):
    p = b'\x01\x80\xc2\x00\x00\x02' + b'\x02\x00\x00\x00\x00' + bytes((src,)) + b'\x88\x09' + payload
    return p + b'\0' * (max(0, 60 - len(p)) if pad else 0)

ITU = b'\x00\x19\xa7'

def esmc(flags, ql, ext=None, tail=b'', ver=1, rsv=b'\0\0\0', qltype=1, qllen=4,
         extype=2, exlen=20, ssm_hi=0):
    p = b'\x0a' + ITU + b'\x00\x01'
    p += bytes((flags,)) + rsv
    p += bytes((qltype,)) + struct.pack('>H', qllen) + bytes((ssm_hi | ql,))
    if ext is not None:
        essm, clockid, flag, eeec, eec, res = ext
        p += bytes((extype,)) + struct.pack('>H', exlen) + bytes((essm,)) + clockid
        p += bytes((flag, eeec, eec)) + res
    return p + tail

def hdr(event=0, ver=1, rsv=0):
    return (ver << 4) | (event << 3) | rsv

# Option I and II codes of the dissector: (essm, ssm)
OPT1 = [(0, 2), (0, 4), (0, 8), (0, 11), (0, 15), (255, 2), (255, 4), (255, 8), (255, 11),
        (255, 15), (32, 2), (33, 2), (34, 11), (35, 2)]
OPT2 = [(0, 0), (0, 1), (0, 4), (0, 7), (0, 10), (0, 13), (0, 14), (0, 15), (255, 0), (255, 1),
        (255, 4), (255, 7), (255, 10), (255, 13), (255, 14), (255, 15), (32, 1), (33, 1),
        (34, 10), (35, 1)]
CLOCK = bytes((0x00, 0x1b, 0x21, 0xff, 0xfe, 0x12, 0x34, 0x56))

def clean(codes=OPT1):
    f = []
    seen = set()
    n = 0
    for essm, ssm in codes:
        if (essm, ssm) in seen:
            continue
        seen.add((essm, ssm))
        ev = n % 2
        n += 1
        if essm == 0:
            f.append(eth(esmc(hdr(ev), ssm), src=1 + n))
        else:
            f.append(eth(esmc(hdr(ev), ssm, (essm, CLOCK, 0x03 if n % 3 else 0, n % 256, (n * 7) % 256,
                                            b'\0' * 5)), src=1 + n))
    if codes is not OPT1:
        return f
    # with padding after the TLVs
    f.append(eth(esmc(hdr(0), 2, tail=b'\xa5' * 20)))
    f.append(eth(esmc(hdr(1), 2, (255, CLOCK, 0x01, 1, 2, b'\0' * 5), tail=b'\x5a' * 5)))
    # a QL TLV followed by less than an extended QL TLV (a frame without the
    # padding to the minimum frame length): no extended TLV
    f.append(eth(esmc(hdr(0), 4, tail=b'\x02\x00\x14' + b'\0' * 5), pad=False))
    # other TLV (not Extended QL) after the QL TLV: not decoded
    f.append(eth(esmc(hdr(0), 4, tail=b'\x03' + b'\0' * 30)))
    # a different OUI (Cisco, known by the manuf table) and an unknown one
    f.append(eth(b'\x0a\x00\x00\x0c' + b'\0' * 20))
    f.append(eth(b'\x0a\xaa\xbb\xcc' + b'\0' * 20))
    # an unknown ITU-T subtype
    f.append(eth(b'\x0a' + ITU + b'\x00\x02' + b'\0' * 20))
    return f

def malformed():
    f = []
    f.append(eth(esmc(hdr(0, ver=2), 2)))                     # version 2
    f.append(eth(esmc(hdr(0, rsv=5), 2)))                     # reserved bits
    f.append(eth(esmc(hdr(0), 2, rsv=b'\0\x01\0')))           # reserved octets
    f.append(eth(esmc(hdr(0), 2, qltype=7)))                  # QL TLV type
    f.append(eth(esmc(hdr(0), 2, qllen=9)))                   # QL TLV length
    f.append(eth(esmc(hdr(0), 2, ssm_hi=0x30)))               # unused bits of the QL
    f.append(eth(esmc(hdr(0), 9)))                            # unknown quality level
    f.append(eth(esmc(hdr(0), 3, (255, CLOCK, 0, 0, 0, b'\0' * 5))))   # unknown QL with eSSM
    f.append(eth(esmc(hdr(0), 2, (255, CLOCK, 0x80, 0, 0, b'\0' * 5))))   # reserved flag bits
    f.append(eth(esmc(hdr(0), 2, (255, CLOCK, 0, 0, 0, b'\0\0\0\0\x07'))))  # reserved octets
    f.append(eth(esmc(hdr(0), 2, (255, CLOCK, 0, 0, 0, b'\0' * 5), exlen=3)))   # ext TLV length
    f.append(eth(b'\x0a' + ITU + b'\x00\x01\x10'))            # short: no TLV
    f.append(eth(b'\x0a' + ITU + b'\x00\x01\x10\0\0\0\x01'))  # short: truncated QL TLV
    f.append(eth(b'\x0a' + ITU))                              # no ITU subtype
    f.append(eth(b'\x0a\x00\x19'))                            # short OUI
    # not padded to the minimum frame length: short frames
    p = b'\x01\x80\xc2\x00\x00\x02\x02\0\0\0\0\1\x88\x09\x0a' + ITU + b'\x00\x01\x10\0\0\0\x01\x00\x04\x02'
    f.append(p)
    return f

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'ossp-coverage.pcapng'), clean())
    pcapng(os.path.join(d, 'ossp-coverage-malformed.pcapng'), malformed())
    pcapng(os.path.join(d, 'ossp-coverage-opt2.pcapng'), clean(OPT2))   # -o ossp.option_network:2

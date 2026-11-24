#!/usr/bin/env python3
# Generates test/captures/atn_sl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic ATN Security Label captures for
# epan/dissectors/packet-atn-sl.c. Every packet is built here with
# struct; nothing comes from a real network.
#
# Stack: Ethernet / LLC (FE FE 03) / CLNP DT (20-octet ATN NSAPs) with a
# security option (code 0xc5, type 0xc0 "globally unique") whose value is
# the ATN security label. ATN SL is reached only through Decode As:
#   tshark -d osi.opt_security,atn_sl -r atn_sl-coverage.pcap
#
# Usage: mkatn_sl.py <outdir>
import os
import struct
import sys

SR = bytes([0x06, 0x04, 0x2b, 0x1b, 0x00, 0x00])
NSAP_A = bytes([0x47, 0x00, 0x27, 0x81]) + bytes(range(1, 16)) + b'\x21'
NSAP_B = bytes([0x47, 0x00, 0x27, 0xc1]) + bytes(range(1, 16)) + b'\x01'

TT_VALUES = [0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
             0x30, 0x60]
SC_VALUES = [1, 2, 3, 4, 5]


def label(si, si_len=None, sr=SR):
    """Security registration length + ID, SI length, security information."""
    if si_len is None:
        si_len = len(si)
    return bytes([len(sr)]) + sr + bytes([si_len]) + si


def tt(v, set_len=1):
    return bytes([1, 0x0f, set_len, v])


def sc(v, set_len=1):
    return bytes([1, 0x03, set_len, v])


def frame(optval, n, sec_type=0xc0):
    opt = bytes([0xc5, 1 + len(optval), sec_type]) + optval
    hdr_len = 9 + 1 + 20 + 1 + 20 + len(opt)
    payload = b'\x00' * 4
    clnp = bytes([0x81, hdr_len, 1, 0x1e, 0x1c]) + \
        struct.pack('>HH', hdr_len + len(payload), 0)
    clnp += bytes([20]) + NSAP_A + bytes([20]) + NSAP_B + opt + payload
    llc = b'\xfe\xfe\x03' + clnp
    return (b'\x02\x00\x00\x00\x00\x01' + bytes([2, 0, 0, 0, 0, n & 0xff]) +
            struct.pack('>H', len(llc)) + llc)


def main_cases():
    c = []
    # 1-20: every known traffic type, alone
    for v in TT_VALUES:
        c.append(label(tt(v)))
    # 21: unknown traffic type
    c.append(label(tt(0x99)))
    # 22-26: every security classification, alone
    for v in SC_VALUES:
        c.append(label(sc(v)))
    # 27: unknown security classification
    c.append(label(sc(0x77)))
    # 28: TT + SC
    c.append(label(tt(0x10) + sc(0x05)))
    # 29: SC + TT (reversed order)
    c.append(label(sc(0x02) + tt(0x23)))
    # 30: TT twice
    c.append(label(tt(0x21) + tt(0x60)))
    # 31: reproducer (atn_sl_edge.py frame 5): SI length 7 with
    #     TT + SC in the option; only the TT tag lies inside the SI
    c.append(label(tt(0x10) + sc(0x05), si_len=7))
    # 32: security registration length 5
    c.append(label(tt(0x10), sr=SR[:5]))
    # 33: security registration length 6 but another ID
    c.append(label(tt(0x10), sr=bytes([0x06, 0x04, 0x2b, 0x1b, 0x00, 0x01])))
    # 34: SI length 9 (> max 8)
    c.append(label(tt(0x10) + sc(0x05) + b'\x00', si_len=9))
    # 35: SI length 0
    c.append(label(b''))
    # 36-38: SI length 1, 2, 3 (partial tag only)
    c.append(label(bytes([1])))
    c.append(label(bytes([1, 0x0f])))
    c.append(label(bytes([1, 0x0f, 1])))
    # 39-41: SI length 5, 6, 7 (one tag and part of a second; the part is
    #        present only inside the SI)
    c.append(label(tt(0x11) + bytes([1])))
    c.append(label(sc(0x01) + bytes([1, 0x0f])))
    c.append(label(tt(0x12) + bytes([1, 0x03, 1])))
    # 42: bad tag name length in the first tag
    c.append(label(bytes([2, 0x0f, 1, 0x10])))
    # 43: bad tag name length in the second tag
    c.append(label(tt(0x13) + bytes([0, 0x03, 1, 0x01])))
    # 44: TT set length 2
    c.append(label(bytes([1, 0x0f, 2, 0x10, 0x11])))
    # 45: SC set length 0
    c.append(label(bytes([1, 0x03, 0, 0x01])))
    # 46: TT ok, then SC set length 2
    c.append(label(tt(0x14) + bytes([1, 0x03, 2, 0x01])))
    # 47: unknown tag name
    c.append(label(bytes([1, 0x42, 1, 0x10])))
    # 48: SC ok, then unknown tag name
    c.append(label(sc(0x04) + bytes([1, 0x42, 1, 0x10])))
    # 49: truncated security registration (tvb_memeql fails)
    c.append(bytes([6]) + SR[:3])
    # 50: security registration length 0, nothing else
    c.append(bytes([0]))
    return c


def malformed_cases():
    return [
        b'',                                            # 1: empty option body
        bytes([6]) + SR,                                # 2: SI length missing
        label(bytes([1, 0x0f, 1]), si_len=8),           # 3: SI past option end
        label(bytes([1]), si_len=4),                    # 4: tag name missing
        label(bytes([1, 0x0f]), si_len=4),              # 5: TT set length missing
        label(bytes([1, 0x0f, 1]), si_len=4),           # 6: TT value missing
        label(bytes([1, 0x03, 1]), si_len=4),           # 7: SC value missing
        label(tt(0x10) + bytes([1, 0x03]), si_len=8),   # 8: second tag cut
        label(tt(0x10) + bytes([1]), si_len=8),         # 9: second tag name missing
    ]


def write_pcap(path, cases, sec_types=None):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, c in enumerate(cases):
            st = sec_types[i] if sec_types and i in sec_types else 0xc0
            fr = frame(c, i + 1, st)
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000,
                                len(fr), len(fr)) + fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = main_cases()
    # 51: a valid label in a security option of type "source address
    #     specific" (0x40): CLNP does not hand it to ATN SL
    m.append(label(tt(0x10) + sc(0x05)))
    write_pcap(os.path.join(out, 'atn_sl-coverage.pcap'), m, {len(m) - 1: 0x40})
    write_pcap(os.path.join(out, 'atn_sl-coverage-malformed.pcap'),
               malformed_cases())


if __name__ == '__main__':
    main()

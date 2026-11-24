#!/usr/bin/env python3
# Generates test/captures/dpnss_link_coverage.eyesdn.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DPNSS link layer
dissector (packet-dpnss-link.c).

The DPNSS link layer is reached through EyeSDN files (wiretap/eyesdn.c):
each record has a direction octet whose bits 7:1 give the protocol
(5 = DPNSS, 6 = DASS2, both dissected as DPNSS link) and bit 0 the sender
(1 = TE, 0 = NT). A link frame has two address octets (frame group, C/R
bit, extension; reserved bit, DLC ID, DLC ID number, extension) and a
frame type; UI frames carry a DPNSS message. Every record is built from
scratch with struct; no captured traffic is used.

Usage: mkdpnss_link.py <output directory>

Writes:
  dpnss-link-coverage.eyesdn            UI (even and odd) frames with
                                        DPNSS messages, an empty UI frame,
                                        SABMR, UA and unknown frame types,
                                        every address bit, DPNSS and DASS2
                                        records from TE and NT
  dpnss-link-coverage-malformed.eyesdn  frames shorter than the header
  dpnss-link-coverage-exppdu.pcap       reproducer dpnss_link_exppdu.pcap:
                                        an Exported PDU "dpnss_link" frame
"""

import os
import struct
import sys

EYESDN_ENCAP_DPNSS = 5
EYESDN_ENCAP_DASS2 = 6


def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def link(group, cr, ext1, res, dlcid, dlcnr, ext2, ftype, payload=b''):
    a1 = (group << 2) | (cr << 1) | ext1
    a2 = (res << 7) | (dlcid << 6) | (dlcnr << 1) | ext2
    return bytes([a1, a2, ftype]) + payload


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    D, A = EYESDN_ENCAP_DPNSS, EYESDN_ENCAP_DASS2
    recs = [
        # 1: SABMR, control frame group, command, real channel 1, from TE
        (D, 1, 0, link(0x03, 1, 1, 0, 0, 1, 1, 0xef)),
        # 2: UA, response, from NT
        (D, 0, 0, link(0x03, 0, 1, 0, 0, 1, 1, 0x63)),
        # 3: UI (even) with a DPNSS ISRM(C), information frame group
        (D, 1, 0, link(0x11, 0, 1, 0, 0, 1, 1, 0x03, b'\x00\x11*50*2001#5551234')),
        # 4: UI (odd) with a DPNSS NAM, from NT
        (D, 0, 0, link(0x11, 1, 1, 0, 0, 1, 1, 0x13, b'\x09*69*12#')),
        # 5: UI (even) with a DPNSS CCM, virtual channel 31, reserved bit
        (D, 1, 0, link(0x11, 0, 1, 1, 1, 31, 1, 0x03, b'\x05')),
        # 6: UI (odd) without a DPNSS message
        (D, 0, 0, link(0x11, 0, 1, 0, 1, 2, 1, 0x13)),
        # 7: unknown frame type 0x01 with data, address extension bits 0
        (D, 1, 0, link(0x11, 0, 0, 0, 0, 3, 0, 0x01, b'\x01\x02')),
        # 8: unknown frame group 0x3f, UA
        (D, 0, 0, link(0x3f, 1, 1, 1, 1, 0, 1, 0x63)),
        # 9: DASS2 record: UI (even) with a DPNSS CRM, from TE
        (A, 1, 0, link(0x11, 0, 1, 0, 0, 4, 1, 0x03, b'\x08\x10')),
        # 10: DASS2 record: SABMR on channel 2, from NT
        (A, 0, 2, link(0x03, 1, 1, 0, 0, 4, 1, 0xef)),
        # 11: UI (even) with a link-by-link LLM(C)
        (D, 1, 0, link(0x11, 0, 1, 0, 1, 5, 1, 0x03, b'\x40*1#')),
        # 12: UI (odd) with an end-to-end EEM(C)
        (D, 0, 0, link(0x11, 1, 1, 0, 1, 5, 1, 0x13, b'\x22*3*1*2#')),
    ]
    eyesdn(os.path.join(out, 'dpnss-link-coverage.eyesdn'), recs)

    bad = [
        (D, 1, 0, b''),            # empty record
        (D, 1, 0, b'\x45'),        # first address octet only
        (D, 0, 0, b'\x45\x03'),    # no frame type
    ]
    eyesdn(os.path.join(out, 'dpnss-link-coverage-malformed.eyesdn'), bad)

    # Reproducer dpnss_link_exppdu.pcap: Exported PDU "dpnss_link". The
    # direction comes from the pseudo-header, which only EyeSDN fills in.
    n = b'dpnss_link'
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    pcap(os.path.join(out, 'dpnss-link-coverage-exppdu.pcap'), 252,
         [tags + bytes([0x45, 0x01, 0x03, 0x09]) + b'*1*X#12'])


if __name__ == '__main__':
    main()

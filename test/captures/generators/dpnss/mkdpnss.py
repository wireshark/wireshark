#!/usr/bin/env python3
# Generates test/captures/dpnss_coverage.eyesdn.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DPNSS dissector
(packet-dpnss.c, Digital Private Network Signalling System No 1).

DPNSS messages are carried in UI frames of the DPNSS link layer, which
is reached through EyeSDN files (wiretap/eyesdn.c): each record has a
direction octet whose bits 7:1 give the protocol (5 = DPNSS) and bit 0
the sender (TE or NT). The first octet of a DPNSS message holds the
message group (call control, end-to-end, link-by-link) and type; then
come a Service Indicator Code, a clearing or rejection cause, a
maintenance action or a usage identifier, and a selection or indication
field of Supplementary Information Strings ("*id*par*par#") followed by
a destination address. Every record is built from scratch with struct;
no captured traffic is used.

Usage: mkdpnss.py <output directory>

Writes:
  dpnss-coverage.eyesdn            every message group and type, every
                                   Service Indicator Code form, strings
                                   with zero to five parameters, empty
                                   parameters, unknown identifiers,
                                   destination addresses
  dpnss-coverage-malformed.eyesdn  a string without '#', fields cut short
"""

import os
import struct
import sys

EYESDN_ENCAP_DPNSS = 5


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
    """records: (uton, payload) pairs, written as DPNSS on channel 0."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (uton, payload) in enumerate(records):
            usecs = 1000 * i
            secs = 1700000000 + i
            hdr = struct.pack('>I', usecs)[1:] + struct.pack('>Q', secs)[3:]
            hdr += bytes([0, (EYESDN_ENCAP_DPNSS << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def ui(msg, odd=False):
    """DPNSS link UI frame: information frame group, real channel 1."""
    return bytes([0x45, 0x03, 0x13 if odd else 0x03]) + msg


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    msgs = [
        # Call control group (0)
        # 1: ISRM(C), speech SIC, OLI/CLI with A/B party address, charge
        # reporting with four parameters, destination address
        b'\x00\x11*50*2001#*188*10*60*1*GBP#5551234',
        # 2: ISRM(I), data rates SIC with a synchronous second octet
        b'\x01\xa3\xcb*1*A B#',
        # 3: RM(C), data rates 2 SIC with an asynchronous second octet
        b'\x02\xb4\x55*2*0#',
        # 4: RM(I), SIC type 0 with a second octet of type 0
        b'\x03\x80\x00*3*1*2#',
        # 5: CCM without an indication field
        b'\x05',
        # 6: CCM with an indication field
        b'\x05*69*12#',
        # 7: NIM
        b'\x06*86*7#',
        # 8-10: reproducer dpnss_par_overrun.pcap: NAM whose last
        # parameter is followed by more strings
        b'\x09*3*AB#*1#',
        b'\x09*3*AB#*1*CD#123',
        b'\x09*3*AB*CD#*1*X#123',
        # 11: CRM (clearing cause) without an indication field
        b'\x08\x10',
        # 12: CRM with an indication field
        b'\x08\x21*93*4#',
        # 13: RRM (rejection cause) with an indication field
        b'\x0a\x05*97*3#',
        # 14: RRM without an indication field
        b'\x0a\x06',
        # 15: SSRM(I)
        b'\x0b*18*A*B*C#4000',
        # 16: SSRM(C) with a selection field
        b'\x0c*167*1*2*3#',
        # 17: SSRM(C) without a selection field
        b'\x0c',
        # 18: CS (not dissected)
        b'\x04\x01\x02',
        # 19: CA (not dissected)
        b'\x07',
        # 20: unknown call control message type 13
        b'\x0d\x00',
        # End-to-end group (2)
        # 21: EEM(C), a string with five parameters (the fifth is ignored)
        b'\x22*188*1*2*3*4*5#',
        # 22: EEM(I), empty parameters and an identifier with a suffix
        b'\x23*189**2*#*39F*6#',
        # 23: SCRM with an indication field
        b'\x24\x12*254#',
        # 24: SCIM without an indication field
        b'\x25\x13',
        # 25: ERM(C), speech SIC, only a destination address
        b'\x26\x12123456',
        # 26: ERM(I), data rates SIC, synchronous type 4, identifier 255
        b'\x27\xa5\x04*255*1#',
        # 27: NSIM with an extended usage identifier
        b'\x28\x85\x01\xde\xad\xbe\xef',
        # 28: NSIM without extension
        b'\x28\x05\x01\x02',
        # 29: unknown end-to-end message type 0
        b'\x20\x00',
        # Link-by-link group (4)
        # 30: LLM(C)
        b'\x40*226*1*2*3#',
        # 31: LLM(I)
        b'\x41*248*100*2*Y#',
        # 32: LLRM (rejection cause) with an indication field
        b'\x42\x07*50*3000#',
        # 33: LLRM without an indication field
        b'\x42\x08',
        # 34: SM with a data SIC, asynchronous type 6
        b'\x44\xa6\x06*1#',
        # 35: LMM
        b'\x45\x01*2*1#',
        # 36: LMRM
        b'\x46\x02*3*0*1#',
        # 37: unknown link-by-link message type 3
        b'\x43\x00',
        # 38: unknown message group 1
        b'\x10\x00',
        # 39: SM, SIC type 7 with an asynchronous type 7 second octet
        b'\x44\xf0\x07*4#',
        # 40: ISRM(C), SIC type 5 and an unnumbered string identifier
        b'\x00\x50*ABC*1#99',
    ]
    records = [(i % 2, ui(m, odd=bool(i % 3 == 2))) for i, m in enumerate(msgs)]
    eyesdn(os.path.join(out, 'dpnss-coverage.eyesdn'), records)

    bad = [
        # a string without its '#'
        b'\x09*50*123',
        # SIC with the extension bit and no second octet
        b'\x00\x91',
        # CRM without its clearing cause
        b'\x08',
        # NSIM without its usage identifier
        b'\x28',
        # LMM without its maintenance action
        b'\x45',
    ]
    eyesdn(os.path.join(out, 'dpnss-coverage-malformed.eyesdn'),
           [(0, ui(m)) for m in bad])


if __name__ == '__main__':
    main()

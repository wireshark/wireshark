#!/usr/bin/env python3
# Generates test/captures/csm_encaps_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CSM_ENCAPS dissector
(packet-csm-encaps.c).

CSM_ENCAPS (Mindspeed Comcerto) runs directly over Ethernet with
ethertype 0x889B. The 12 octet header holds a big endian opcode, a
sequence number, a control octet (ACK, ACK suppress, ACK to host and
endian bits), a big endian channel, a length, an index, the type and
class octets and a little endian function code; "length - 6" octets of
little endian 16 bit parameters follow (reserved, parameter 1-40, then
"Parameter"). Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkcsm_encaps.py <output directory>

Writes:
  csm_encaps-coverage.pcap            ACKs to and from the host, queries,
                                      responses (error parameter), class
                                      type commands (function code 0),
                                      every opcode, every control bit,
                                      every parameter up to length 255
  csm_encaps-coverage-malformed.pcap  headers cut short, a length past
                                      the end of the frame
"""

import os
import struct
import sys

MAC_HOST = bytes.fromhex('020000000001')
MAC_DEV = bytes.fromhex('020000000002')
ETHERTYPE = 0x889B


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, to_host):
    src, dst = (MAC_DEV, MAC_HOST) if to_host else (MAC_HOST, MAC_DEV)
    fr = dst + src + struct.pack('>H', ETHERTYPE) + payload
    return fr


def csm(opcode, seq, ctrl, channel, length, index, typ, cls, fc, params=None):
    """Header plus 'length - 6' octets of parameters, rounded up to whole
    16 bit parameters as the dissector reads them (counting values 0x100,
    0x101, ... unless given)."""
    hdr = struct.pack('>HBBHBBBB', opcode, seq, ctrl, channel, length, index, typ, cls)
    hdr += struct.pack('<H', fc)
    n = max(0, length - 6)
    if params is None:
        body = b''.join(struct.pack('<H', 0x100 + k) for k in range((n + 1) // 2))
    else:
        body = b''.join(struct.pack('<H', p) for p in params)
    return hdr + body


def main_frames():
    F = []
    # 1: ACK from the host (ACK bit only)
    F.append(eth(csm(0x0001, 1, 0x80, 0x0001, 6, 0, 0, 0, 0x0000), False))
    # 2: ACK to the host (ACK and ACK to host bits)
    F.append(eth(csm(0x0001, 2, 0xa0, 0x0001, 6, 0, 0, 0, 0x0000), True))
    # 3: query from the host, function code 0x8004, reserved and 3 params
    F.append(eth(csm(0x0001, 3, 0x00, 0x0002, 14, 0, 1, 0x80, 0x8004,
                     [0x0000, 0x0011, 0x0022, 0x0033]), False))
    # 4: response to the host: parameter 1 is the error code
    F.append(eth(csm(0x0001, 3, 0x00, 0x0002, 10, 0, 2, 0x80, 0x8004,
                     [0x0000, 0x0005]), True))
    # 5: change command with function code 0: named by class and type
    #    (class 0x12, type 0 -> class type 0x1200)
    F.append(eth(csm(0x0001, 4, 0x40, 0xffff, 8, 1, 0, 0x12, 0x0000,
                     [0x0000]), False))
    # 6: indication with endian bit and ACK suppress bit, length 6 (no
    #    parameters)
    F.append(eth(csm(0x0001, 5, 0x41, 0x0003, 6, 2, 3, 0x01, 0x0101), True))
    # 7: length below 6 (nothing after the header)
    F.append(eth(csm(0x0001, 6, 0x00, 0x0003, 0, 0, 4, 0x02, 0x0202), True))
    # 8: no operation opcode
    F.append(eth(csm(0x0000, 7, 0x00, 0x0000, 6, 0, 0, 0, 0x0000), False))
    # 9: reliable data transfer opcode, an odd length (the last parameter
    #    covers the octet after the length)
    F.append(eth(csm(0x0002, 8, 0x00, 0x0004, 11, 0, 5, 0x03, 0x0303,
                     [0x0000, 0x1111, 0x2222]), False))
    # 10: unknown opcode, response with ACK bit (no error parameter)
    F.append(eth(csm(0x00ff, 9, 0x80, 0x0004, 10, 0, 2, 0x03, 0x0303,
                     [0x0000, 0x0007]), True))
    # 11: response with every parameter: length 255 (reserved,
    #     parameters 1-40 and 84 "Parameter" items, the last one
    #     covering the octet after the length)
    F.append(eth(csm(0x0001, 10, 0x00, 0x0005, 255, 3, 2, 0x04, 0x0404), True))
    # 12: query with exactly parameters 1-40 (length 88)
    F.append(eth(csm(0x0001, 11, 0x20, 0x0005, 88, 4, 1, 0x04, 0x0404), False))
    # 13: response with function code 0 (class type) and an error code
    F.append(eth(csm(0x0001, 12, 0x00, 0x0006, 10, 0, 2, 0x05, 0x0000,
                     [0x0000, 0x0009]), True))
    return F


def malformed_frames():
    F = []
    # 1: only the opcode and sequence number
    F.append(eth(struct.pack('>HB', 1, 1), False))
    # 2: header without the function code (11 octets)
    F.append(eth(csm(0x0001, 2, 0x00, 1, 6, 0, 1, 0, 0)[:11], False))
    # 3: length 40 but only two parameters present
    F.append(eth(csm(0x0001, 3, 0x00, 1, 40, 0, 1, 0, 0x1234,
                     [0x0000, 0x0001]), False))
    # 4: length 255 with no parameters present
    F.append(eth(csm(0x0001, 4, 0x00, 1, 255, 0, 2, 0, 0x1234, []), True))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'csm_encaps-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'csm_encaps-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

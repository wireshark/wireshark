#!/usr/bin/env python3
# Generates test/captures/dpaux_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DPAUX dissector
(packet-dpaux.c, DisplayPort AUX channel).

DPAUX is reached through DPAUXMON (link-layer type 275,
LINKTYPE_DISPLAYPORT_AUX): a DPAUXMON data packet (type 0) carries an
origin octet (1 = source, 0 = sink) and then the AUX transaction. A
request from the source has a command nibble (native/I2C bit, MOT bit,
2 bit command), a 20 bit address and LEN (length - 1), then the write
data. A reply from the sink has the reply command and the read data;
the dissector looks up the last request to name the address and, for
native reads, decodes the DPCD registers 0x00000-0x00004. Every packet
is built from scratch with struct; no captured traffic is used.

Usage: mkdpaux.py <output directory>

Writes:
  dpaux-coverage.pcap            native and I2C-over-AUX requests of every
                                 command, replies of every reply code, DPCD
                                 capability registers, LEN 0xff and replies
                                 longer than 256 octets
  dpaux-coverage-malformed.pcap  requests cut short, write data missing
  dpaux-coverage-exppdu.pcap     an Exported PDU "dpaux" frame (no DPAUXMON
                                 data, so it is dissected as from the sink)
"""

import os
import struct
import sys


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def src(b):
    """DPAUXMON data packet from the source."""
    return bytes([0x00, 0x01]) + b


def snk(b):
    """DPAUXMON data packet from the sink."""
    return bytes([0x00, 0x00]) + b


def req(native, mot, cmd, addr, ln, data=b''):
    """AUX request: native/I2C, MOT, command, 20 bit address, LEN (length - 1)."""
    first = (0x80 if native else 0) | (0x40 if mot else 0) | (cmd << 4) | ((addr >> 16) & 0x0f)
    return bytes([first, (addr >> 8) & 0xff, addr & 0xff, ln]) + data


def rep(code, data=b''):
    """AUX reply: reply command in bits 5:4 of the first octet."""
    return bytes([code << 4]) + data


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [
        # 1-3: replies with no request before them (transaction N/A)
        snk(rep(0, b'\x11\x22')),
        snk(rep(0, b'\x33')),
        snk(rep(1)),
        # 4-5: native write of one octet to LINK_BW_SET, AUX ACK
        src(req(True, False, 0, 0x00100, 0, b'\x0a')),
        snk(rep(0)),
        # 6-7: native read of the DPCD capability registers 0-4
        src(req(True, False, 1, 0x00000, 4)),
        snk(rep(0, bytes([0x12, 0x14, 0xe4, 0xc1, 0xe1]))),
        # 8-9: the other link rate and bit values
        src(req(True, False, 1, 0x00000, 4)),
        snk(rep(0, bytes([0x11, 0x06, 0x02, 0x00, 0x00]))),
        # 10-11: native read of 16 octets that are not decoded registers
        src(req(True, False, 1, 0x00200, 15)),
        snk(rep(0, bytes(range(0x30, 0x40)))),
        # 12-13: native read from 0x00003, registers 3 and 4 then others
        src(req(True, False, 1, 0x00003, 3)),
        snk(rep(0, bytes([0x01, 0x20, 0x00, 0xff]))),
        # 14-15: I2C write with MOT to the EDID address 0x50, I2C ACK
        src(req(False, True, 0, 0x00050, 0, b'\x00')),
        snk(rep(0)),
        # 16-17: I2C read of 16 EDID octets without MOT
        src(req(False, False, 1, 0x00050, 15)),
        snk(rep(0, bytes([0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]) + bytes(8))),
        # 18-19: I2C write status update request, AUX DEFER
        src(req(False, True, 2, 0x00050, 0, b'\x00')),
        snk(rep(2)),
        # 20-21: I2C command 3 (a read by the command bit), reply code 3
        src(req(False, False, 3, 0x00050, 1)),
        snk(rep(3, b'\xaa\xbb')),
        # 22-23: native read of one octet; a reply with one data octet
        src(req(True, False, 1, 0x00002, 0)),
        snk(rep(0, b'\x84')),
        # 24-26: reproducer dpaux_len_wrap.pcap: native write with LEN 0xff
        # (256 octets), native read of 5 octets from 0 and its reply
        src(req(True, False, 0, 0x00000, 0xff, bytes(range(256)))),
        src(req(True, False, 1, 0x00000, 4)),
        snk(rep(0, bytes([0x12, 0x0a, 0x84, 0x01, 0x01]))),
        # 27-28: native read with LEN 0xff from 0x00000 and a reply of 300
        # octets (more than 256)
        src(req(True, False, 1, 0x00000, 0xff)),
        snk(rep(0, bytes([0x14, 0x1e, 0x44, 0x40, 0x80]) + bytes(i & 0xff for i in range(295)))),
        # 29: NACK after a request (reply code 1, no data)
        snk(rep(1)),
    ]
    pcap(os.path.join(out, 'dpaux-coverage.pcap'), 275, frames)

    bad = [
        # request with only two octets: LEN missing
        src(bytes([0x90, 0x00])),
        # native write of 8 octets with only 2 present
        src(req(True, False, 0, 0x00100, 7, b'\x01\x02')),
        # empty AUX transaction from the source
        src(b''),
        # empty reply from the sink
        snk(b''),
    ]
    pcap(os.path.join(out, 'dpaux-coverage-malformed.pcap'), 275, bad)

    # Exported PDU, dissector name "dpaux": no dpaux_info, so from the sink
    n = b'dpaux'
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    pcap(os.path.join(out, 'dpaux-coverage-exppdu.pcap'), 252,
         [tags + rep(0, b'\x12\x34'), tags + rep(2)])


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/epl_v1_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EPL_V1 dissector
(packet-epl_v1.c, ETHERNET Powerlink V1.0).

EPL V1 runs directly over Ethernet with ethertype 0x3E3F, registered by
default. Every frame starts with the service (low 7 bits), destination
and source node; SoC, EoC, PReq, PRes, AInv and ASnd follow with their
own fields. A managing node (node 0, 02:00:00:00:01:00) polls
controlled nodes 1-3. Every packet is built from scratch with struct;
no captured traffic is used.

Usage: mkepl_v1.py <output directory>

Writes:
  epl_v1-coverage.pcap            every service, every flag, net
                                  commands idle and active, poll data
                                  with and without data, ASnd Ident and
                                  Generic channels, unknown channels,
                                  frames that are not EPL V1
  epl_v1-coverage-malformed.pcap  poll sizes and ASnd sizes past the
                                  end, frames cut short
"""

import os
import struct
import sys

ETHERTYPE = 0x3E3F
MN = 0


def mac(node):
    return bytes((2, 0, 0, 0, 1, node))


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(src, dst, payload, pad=True):
    d = b'\xff' * 6 if dst == 255 else mac(dst)
    fr = d + mac(src) + struct.pack('>H', ETHERTYPE) + payload
    if pad and len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


def hdr(service, dest, src):
    return struct.pack('<BBB', service, dest, src)


def soc(flags, netcmd, nettime, cycle, service=0x01):
    return eth(MN, 255, hdr(service, 255, MN) +
               struct.pack('<BHII', flags, netcmd, nettime, cycle) +
               bytes(range(0x40, 0x60)))


def eoc(netcmd):
    return eth(MN, 255, hdr(0x02, 255, MN) + b'\0' +
               struct.pack('<H', netcmd) + b'\0' * 6 + bytes(range(0x60, 0x80)))


def preq(dest, flags, data):
    return eth(MN, dest, hdr(0x03, dest, MN) +
               struct.pack('<BH', flags, len(data)) + b'\0' * 4 + data)


def pres(src, flags, data):
    return eth(src, 255, hdr(0x04, 255, src) +
               struct.pack('<BH', flags, len(data)) + b'\0' * 4 + data)


def ainv(dest, channel):
    return eth(MN, dest, hdr(0x05, dest, MN) + bytes((channel,)))


def asnd(src, channel, body, size=None):
    return eth(src, MN, hdr(0x06, MN, src) +
               struct.pack('<BH', channel, len(body) if size is None else size) + body)


def ident(node):
    return struct.pack('<IIIIII', node, 0x0102, 0x00030004, 7, 36, 24)


def main_frames():
    F = []
    # 1: SoC, net command idle, no flags
    F.append(soc(0x00, 0, 1000, 2000))
    # 2: PReq to CN 1 with 4 octets of OUT data, RD
    F.append(preq(1, 0x01, b'\x11\x22\x33\x44'))
    # 3: PRes from CN 1 with 6 octets of IN data, RD
    F.append(pres(1, 0x01, b'\xa1\xa2\xa3\xa4\xa5\xa6'))
    # 4: PReq to CN 2 without data, MS
    F.append(preq(2, 0x20, b''))
    # 5: PRes from CN 2 without data, every flag (MS EX RS WA ER RD)
    F.append(pres(2, 0x3f, b''))
    # 6: EoC, net command idle
    F.append(eoc(0))
    # 7: AInv Ident to CN 1
    F.append(ainv(1, 1))
    # 8: ASnd Ident from CN 1
    F.append(asnd(1, 1, ident(1)))
    # 9: AInv Generic Channel to CN 2
    F.append(ainv(2, 255))
    # 10: ASnd Generic Channel from CN 2
    F.append(asnd(2, 255, b'generic channel data'))
    # 11: SoC, net command active, MS and PS
    F.append(soc(0xc0, 1, 3000, 2000))
    # 12: EoC, net command active
    F.append(eoc(1))
    # 13: AInv with an unknown channel
    F.append(ainv(3, 7))
    # 14: ASnd with an unknown channel (dissected as generic data)
    F.append(asnd(3, 7, b'\x01\x02\x03'))
    # 15: SoC with bit 7 of the service octet set (masked off)
    F.append(soc(0x80, 2, 5000, 2000, service=0x81))
    # 16: ASnd Generic Channel with size 0
    F.append(asnd(2, 255, b''))
    # 17: an unknown service (7): not EPL V1, shown as data
    F.append(eth(MN, 255, hdr(0x07, 255, MN)))
    # 18: a 2 octet frame (no padding): too short for EPL V1, data
    F.append(eth(MN, 255, b'\x01\xff', pad=False))
    return F


def malformed_frames():
    F = []
    # 1: PReq whose poll size runs past the end
    F.append(eth(MN, 1, hdr(0x03, 1, MN) + struct.pack('<BH', 1, 1000) + b'\0' * 4 + b'\x11' * 4))
    # 2: PRes whose poll size runs past the end
    F.append(eth(1, 255, hdr(0x04, 255, 1) + struct.pack('<BH', 1, 1000) + b'\0' * 4, pad=False))
    # 3: ASnd Generic whose size runs past the end
    F.append(asnd(2, 255, b'abc', size=500))
    # 4: ASnd Ident cut short
    F.append(eth(1, MN, hdr(0x06, MN, 1) + struct.pack('<BH', 1, 24) + b'\1\0', pad=False))
    # 5: SoC cut short
    F.append(eth(MN, 255, hdr(0x01, 255, MN) + b'\0\0', pad=False))
    # 6: EoC cut short
    F.append(eth(MN, 255, hdr(0x02, 255, MN), pad=False))
    # 7: AInv without the channel octet
    F.append(eth(MN, 1, hdr(0x05, 1, MN), pad=False))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'epl_v1-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'epl_v1-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

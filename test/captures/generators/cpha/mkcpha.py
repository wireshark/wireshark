#!/usr/bin/env python3
# Generates test/captures/cpha_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CPHA dissector
(packet-cpha.c, Check Point High-Availability Protocol).

CPHA runs over UDP port 8116. The header holds a magic number (0x1A90),
the protocol version, cluster number, opcode, source interface, random
ID, source and destination machine IDs and, for every version but 1
(4.1), a policy ID and a filler. The payload depends on the opcode:
FWHA_MY_STATE (machine and interface states), interface probes,
interface configuration replies, LB configuration and policy changes.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcpha.py <output directory>

Writes:
  cpha-coverage.pcap            every opcode, every report code, every
                                state, HA mode and status, version 1
                                (4.1) and later versions, a bad magic
                                number and a frame too short for one
  cpha-coverage-malformed.pcap  headers and payloads cut short
"""

import os
import struct
import sys

PORT = 8116
MAC = [bytes.fromhex('00000c000001'), bytes.fromhex('00000c000002')]
IP = [bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])]
MCAST_MAC = bytes.fromhex('01005e000001')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip_cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp(src, payload, sport=PORT, dport=PORT):
    """UDP/IPv4 from machine src (0 or 1) to the other one."""
    s, d = IP[src], IP[1 - src]
    ulen = 8 + len(payload)
    ph = s + d + struct.pack('>BBH', 0, 17, ulen)
    u = struct.pack('>HHHH', sport, dport, ulen, 0) + payload
    ck = ip_cksum(ph + u) or 0xffff
    u = u[:6] + struct.pack('>H', ck) + u[8:]
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, s, d)
    iph = iph[:10] + struct.pack('>H', ip_cksum(iph)) + iph[12:]
    return MAC[1 - src] + MAC[src] + struct.pack('>H', 0x0800) + iph + u


def hdr(version, opcode, cluster=1, src_if=2, random_id=0x1234, src_id=0, dst_id=1,
        policy=7, filler=0):
    h = struct.pack('>HHHHHHHH', 0x1A90, version, cluster, opcode, src_if,
                    random_id, src_id, dst_id)
    if version != 1:
        h += struct.pack('>HH', policy, filler)
    return h


def my_state(id_num, report_code, ha_mode, time_unit, states=b'', ifs=b''):
    return struct.pack('>HHHH', id_num, report_code, ha_mode, time_unit) + states + ifs


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    f = []
    # 1: FWHA_MY_STATE, NG FP0 (2), machine and interface information for
    #    three cluster members (states, then interface counts and the last
    #    packet seen from each cluster member).
    f.append(udp(0, hdr(2, 1) + my_state(3, 3, 2, 100, bytes([4, 2, 0]),
                                         struct.pack('>bbbb', 3, 1, 2, 0) + struct.pack('>bbb', 0, 1, -1))))
    # 2: FWHA_MY_STATE, 4.1 (version 1, no policy ID or filler), machine
    #    information only, states Initializing and Ready, primary up mode.
    f.append(udp(1, hdr(1, 1, src_id=1, dst_id=0) + my_state(2, 1, 3, 50, bytes([1, 3]))))
    # 3: FWHA_MY_STATE, R77.30 (2920), interface information only, one up
    #    mode, two members.
    f.append(udp(0, hdr(2920, 1) + my_state(2, 2, 4, 10, b'',
                                            struct.pack('>bbbb', 2, 2, 2, 2) + struct.pack('>bb', 5, 6))))
    # 4: FWHA_MY_STATE with report code 0 (nothing included), undefined
    #    and not active modes in the next frame.
    f.append(udp(1, hdr(2921, 1, src_id=1, dst_id=0) + my_state(2, 0, 0, 10)))
    f.append(udp(0, hdr(2921, 1) + my_state(1, 1, 1, 10, bytes([0]))))
    # 6: FWHA_QUERY_STATE, with 4 octets of padding (without any payload
    #    the empty Payload item throws, see the malformed capture).
    f.append(udp(0, hdr(3, 2) + bytes(4)))
    # 7, 8: interface probe request and reply.
    f.append(udp(0, hdr(6, 3) + struct.pack('>I', 2)))
    f.append(udp(1, hdr(6, 4, src_id=1, dst_id=0) + struct.pack('>I', 2)))
    # 9, 10: interface configuration request (padding only) and reply.
    f.append(udp(0, hdr(530, 5) + bytes(4)))
    f.append(udp(1, hdr(530, 6, src_id=1, dst_id=0) + struct.pack('>I', 3) +
                 MAC[1] + struct.pack('>H', 1) + IP[1]))
    # 11: interface configuration reply, untrusted interface.
    f.append(udp(1, hdr(530, 6, src_id=1, dst_id=0) + struct.pack('>I', 3) +
                 bytes.fromhex('00000c000003') + struct.pack('>H', 0) + bytes([198, 51, 100, 1])))
    # 12: LB configuration with a negative slot and hash list length.
    f.append(udp(0, hdr(1501, 7) + struct.pack('>hhIi', -1, 2, 0xdeadbeef, -5)))
    # 13: LB configuration report reply: shown as data.
    f.append(udp(1, hdr(1501, 8, src_id=1, dst_id=0) + bytes.fromhex('0001000200030004')))
    # 14-16: policy change with each status.
    for st in (1, 2, 3):
        f.append(udp(st & 1, hdr(2000, 9, policy=8) + struct.pack('>I', st)))
    # 17: FWHAP_SYNC: shown as data.
    f.append(udp(0, hdr(2900, 10) + bytes.fromhex('cafebabe0102')))
    # 18: opcode 0, 19: unknown opcode 99, both as data.
    f.append(udp(0, hdr(2900, 0) + b'\x00\x01'))
    f.append(udp(0, hdr(2900, 99) + b'\x02\x03'))
    # 20: unknown protocol version 9999.
    f.append(udp(0, hdr(9999, 2) + bytes(4)))
    # 21: bad magic number: not CPHA (data).
    f.append(udp(0, struct.pack('>HH', 0x1A91, 2) + bytes(16)))
    # 22: three octets: too short for the magic number and version.
    f.append(udp(0, b'\x1a\x90\x00'))
    pcap(os.path.join(outdir, 'cpha-coverage.pcap'), f)

    m = []
    # 1: magic and version only: the opcode read throws (no tree).
    m.append(udp(0, struct.pack('>HH', 0x1A90, 2)))
    # 2: header cut after the destination machine ID (version 2).
    m.append(udp(0, hdr(2, 1)[:16]))
    # 3: FWHA_MY_STATE with 200 IDs and three states present.
    m.append(udp(0, hdr(2, 1) + my_state(200, 3, 2, 100, bytes([4, 2, 0]))))
    # 4: interface configuration reply cut inside the Ethernet address.
    m.append(udp(0, hdr(2, 6) + struct.pack('>I', 1) + MAC[0][:3]))
    # 5: LB configuration cut after the slot number.
    m.append(udp(0, hdr(2, 7) + struct.pack('>h', 1)))
    # 6: policy change and probe with two octets.
    m.append(udp(0, hdr(2, 9) + b'\x00\x01'))
    m.append(udp(0, hdr(2, 3) + b'\x00\x01'))
    # 8, 9: FWHA_QUERY_STATE with nothing after the header (versions 2
    #    and 1): the zero length Payload item at the end of the data
    #    throws.
    m.append(udp(0, hdr(2, 2)))
    m.append(udp(0, hdr(1, 2)))
    pcap(os.path.join(outdir, 'cpha-coverage-malformed.pcap'), m)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

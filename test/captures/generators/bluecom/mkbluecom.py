#!/usr/bin/env python3
# Generates test/captures/bluecom_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bachmann bluecom dissector
(packet-bluecom.c), ethertype 0x892D. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkbluecom.py <output directory>

Writes:
  bluecom-coverage.pcap            every block command (SYNC, DATA,
                                   IDENTIFY, SEARCH, CONNECT) as request,
                                   response and both, with and without the
                                   optional second Ethernet address, all
                                   search address types, several blocks in a
                                   frame, a 16-bit segment code, VLAN tagged,
                                   and the clean frames of the reproducer
                                   bluecom_mix.pcap
  bluecom-coverage-malformed.pcap  short blocks, block lengths past the
                                   frame, more blocks announced than present,
                                   a truncated protocol header
"""

import os
import struct
import sys

MASTER = bytes.fromhex('020000000001')
SLAVE = bytes.fromhex('020000000002')
ETH_BLUECOM = 0x892D

REQ, RSP, PRIM = 0x01, 0x02, 0x80
SYNC, DATA, IDENTIFY, SEARCH, CONNECT = 0, 1, 2, 3, 4


def eth(payload, src=MASTER, dst=SLAVE, vlan=None):
    if vlan is not None:
        return dst + src + struct.pack('>HHH', 0x8100, vlan, ETH_BLUECOM) + payload
    return dst + src + struct.pack('>H', ETH_BLUECOM) + payload


def hdr(flags, nb, seg, version=1, fmt=0, auth=0):
    return struct.pack('>BBBBHI', version, fmt, flags, nb, seg, auth)


def blk(cmd, data, src=0x1001, dst=0x2001, trans=1, state=0, bflags=0,
        frag=0, ts=0, length=None):
    if length is None:
        length = len(data)
    return struct.pack('>HHHBBBxxxHHQ', src, dst, trans, cmd, state, bflags,
                       length, frag, ts) + data


def name(s):
    return s.encode().ljust(32, b'\0')


def ip(*a):
    return bytes(a)


def sync(start, cycle, ratio, ident, vlan, ext=None):
    d = struct.pack('>IIBBH', start, cycle, ratio, ident, vlan)
    if ext:
        d += ext[0] + ext[1]
    return d


def identify(err, start, addr, nm, mac, mac2=None):
    return struct.pack('>II', err, start) + addr + name(nm) + mac + (mac2 or b'')


def search_req(addrtype, data):
    return struct.pack('>II', addrtype, 0) + data


def search_rsp(err, start, lin, lout, addr, nm, mac, mac2=None):
    return struct.pack('>IIHH', err, start, lin, lout) + addr + name(nm) + mac + (mac2 or b'')


def connect_req(lin, lout, cycle, offline, addr, nm, mac, mac2=None):
    return (struct.pack('>HHIHH', lin, lout, cycle, offline, 0) + addr + name(nm)
            + mac + (mac2 or b''))


def connect_rsp(err, lin, lout):
    return struct.pack('>IHH', err, lin, lout)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


MAC_X = bytes.fromhex('020000000005')
MAC_Y = bytes.fromhex('020000000006')


def main_frames():
    F = []
    # 1: SYNC (primary), Identify false, no Ethernet address extension
    F.append(eth(hdr(PRIM, 1, 1) + blk(SYNC, sync(1000, 500, 4, 0, 0), dst=0x2000,
                                       ts=0x0000000065540000), dst=bytes.fromhex('ffffffffffff')))
    # 2: SYNC with Identify true and the two Ethernet addresses
    F.append(eth(hdr(PRIM, 1, 1) + blk(SYNC, sync(2000, 1000, 2, 1, 0x0064, (MAC_X, MAC_Y)),
                                       dst=0x2000), dst=bytes.fromhex('ffffffffffff')))
    # 3-4: IDENTIFY without and with the second Ethernet address
    F.append(eth(hdr(RSP, 1, 1) + blk(IDENTIFY, identify(0, 77, ip(192, 0, 2, 9), 'slave-a',
                                                          SLAVE), src=0x2001, dst=0x1001,
                                      state=3), src=SLAVE, dst=MASTER))
    F.append(eth(hdr(RSP, 1, 1) + blk(IDENTIFY, identify(1, 78, ip(192, 0, 2, 10), 'slave-b',
                                                          SLAVE, MAC_Y), src=0x2002, dst=0x1001),
                 src=SLAVE, dst=MASTER))
    # 5-7: SEARCH requests by name, by IP address range, unknown address type
    F.append(eth(hdr(REQ, 1, 1) + blk(SEARCH, search_req(1, name('slave-a')))))
    F.append(eth(hdr(REQ, 1, 1) + blk(SEARCH, search_req(2, ip(192, 0, 2, 1) + ip(192, 0, 2, 50)
                                                         + bytes(24)))))
    F.append(eth(hdr(REQ, 1, 1) + blk(SEARCH, search_req(7, bytes(range(32))))))
    # 8-9: SEARCH responses: error 5 without the second Ethernet address
    # (the summary error is read big-endian like the field), error 0x01020304
    # with it
    F.append(eth(hdr(RSP, 1, 1) + blk(SEARCH, search_rsp(5, 0, 8, 8, ip(192, 0, 2, 1), 'slave',
                                                          SLAVE), src=0x2001, dst=0x1001),
                 src=SLAVE, dst=MASTER))
    F.append(eth(hdr(RSP, 1, 1) + blk(SEARCH, search_rsp(0x01020304, 99, 16, 32,
                                                          ip(192, 0, 2, 2), 'slave-c', SLAVE, MAC_X),
                                      src=0x2003, dst=0x1001), src=SLAVE, dst=MASTER))
    # 10: SEARCH with both the request and response flags: request by name
    # followed by a response (no second Ethernet address)
    F.append(eth(hdr(REQ | RSP, 1, 1) + blk(SEARCH, search_req(1, name('both'))
                                            + search_rsp(6, 1, 2, 3, ip(192, 0, 2, 3), 'both', SLAVE))))
    # 11: SEARCH with neither flag: only the Info text
    F.append(eth(hdr(PRIM, 1, 1) + blk(SEARCH, bytes(8))))
    # 12-13: CONNECT request without and with the second Ethernet address
    F.append(eth(hdr(REQ, 1, 1) + blk(CONNECT, connect_req(64, 128, 1000, 10, ip(192, 0, 2, 9),
                                                            'slave-a', SLAVE))))
    F.append(eth(hdr(REQ, 1, 1) + blk(CONNECT, connect_req(32, 16, 2000, 3, ip(192, 0, 2, 10),
                                                            'slave-b', SLAVE, MAC_Y))))
    # 14: CONNECT response, error 7
    F.append(eth(hdr(RSP, 1, 1) + blk(CONNECT, connect_rsp(7, 64, 128), src=0x2001, dst=0x1001),
                 src=SLAVE, dst=MASTER))
    # 15: CONNECT with both flags (request with the second address, then a
    # response; the request part has the second address since data follows)
    F.append(eth(hdr(REQ | RSP, 1, 1) + blk(CONNECT, connect_req(1, 2, 3, 4, ip(192, 0, 2, 4),
                                                                  'both', SLAVE, MAC_X)
                                            + connect_rsp(0, 1, 2))))
    # 16: DATA, user data
    F.append(eth(hdr(0, 1, 1) + blk(DATA, b'cyclic-data-0001', bflags=1, frag=0)))
    # 17: DATA with a 16-bit segment code (0x1234) and three blocks
    # (reproducer frame 4, with the block count matching)
    F.append(eth(hdr(0, 3, 0x1234) + blk(DATA, b'abc') * 3))
    # 18: empty DATA block and an unknown command (dissected as data)
    F.append(eth(hdr(0, 2, 2) + blk(DATA, b'') + blk(9, b'unknown-cmd', bflags=2)))
    # 19: no blocks
    F.append(eth(hdr(0, 0, 3)))
    # 20: five blocks of every command in one frame (primary request)
    F.append(eth(hdr(PRIM | REQ, 5, 4)
                 + blk(SYNC, sync(1, 2, 3, 0, 4))
                 + blk(DATA, b'\x01\x02\x03\x04')
                 + blk(IDENTIFY, identify(0, 1, ip(192, 0, 2, 11), 'multi', SLAVE))
                 + blk(SEARCH, search_req(2, ip(192, 0, 2, 1) + ip(192, 0, 2, 2) + bytes(24)))
                 + blk(CONNECT, connect_req(8, 8, 100, 2, ip(192, 0, 2, 11), 'multi', SLAVE))))
    # 21: VLAN tagged SYNC
    F.append(eth(hdr(PRIM, 1, 1) + blk(SYNC, sync(3000, 250, 1, 0, 0x0064)), vlan=100))
    # 22-24: the clean frames of bluecom_mix.pcap (1, 2 and 6):
    # SEARCH response with error 5, SEARCH request by IP address, IDENTIFY
    # with both flags
    F.append(eth(hdr(2, 1, 1) + blk(3, struct.pack('>IIHHI', 5, 0, 8, 8, 0xc0000201)
                                    + b'slave'.ljust(32, b'\0') + b'\x02\0\0\0\0\x05')))
    F.append(eth(hdr(1, 1, 1) + blk(3, struct.pack('>II', 2, 0) + ip(192, 0, 2, 1)
                                    + ip(192, 0, 2, 9) + b'\0' * 24)))
    F.append(eth(hdr(3, 1, 1) + blk(2, b'\0' * 50)))
    return F


def malformed_frames():
    F = []
    # 1-3: bluecom_mix.pcap frames 3-5: a 4-octet CONNECT request; 255 blocks
    # announced and 3 present; a block length of 0xffff after a short SYNC
    F.append(eth(hdr(1, 1, 1) + blk(4, b'\0' * 4)))
    F.append(eth(hdr(0, 255, 0x1234) + blk(1, b'abc') * 3))
    F.append(eth(hdr(0, 2, 1) + blk(0, b'\0' * 12)
                 + struct.pack('>HHHBBBxxxHHQ', 1, 2, 3, 0, 0, 0, 0xffff, 0, 0)))
    # 4-8: each command with a block too short (the exception is caught and
    # the next block is dissected)
    F.append(eth(hdr(0, 2, 1) + blk(SYNC, b'\0' * 6) + blk(DATA, b'next')))
    F.append(eth(hdr(0, 2, 1) + blk(IDENTIFY, b'\0' * 20) + blk(DATA, b'next')))
    F.append(eth(hdr(REQ, 2, 1) + blk(SEARCH, search_req(1, b'short')) + blk(DATA, b'next')))
    F.append(eth(hdr(RSP, 2, 1) + blk(SEARCH, bytes(10)) + blk(DATA, b'next')))
    F.append(eth(hdr(RSP, 2, 1) + blk(CONNECT, bytes(3)) + blk(DATA, b'next')))
    # 9: SEARCH request by IP address cut before the addresses
    F.append(eth(hdr(REQ, 1, 1) + blk(SEARCH, search_req(2, b''))))
    # 10: truncated protocol header
    F.append(eth(hdr(0, 1, 1)[:5]))
    # 11: block header cut short
    F.append(eth(hdr(0, 1, 1) + blk(DATA, b'')[:10]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bluecom-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'bluecom-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

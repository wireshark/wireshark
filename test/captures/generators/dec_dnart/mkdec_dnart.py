#!/usr/bin/env python3
# Generates test/captures/dec_dnart_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DEC DNA Routing Protocol
dissector (packet-dec-dnart.c, DECnet Phase IV routing and NSP).

DEC DNA is registered for ethertype 0x6003, Cisco HDLC protocol 0x6003
and PPP protocol 0x0027, so it is reached without Decode As. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkdec_dnart.py <output directory>

Writes pcapng files with three interfaces:
  0  LINKTYPE_ETHERNET (1)
  1  LINKTYPE_C_HDLC (104)
  2  LINKTYPE_PPP (9)

  dec-dnart-coverage.pcapng            every routing control message, short
                                       and long data packets carrying every
                                       NSP message, and the reproducer of
                                       "DEC DNA: Do not wrap the router list
                                       lengths"
  dec-dnart-coverage-malformed.pcapng  truncated messages and a bad routing
                                       checksum
"""

import os
import struct
import sys

T0 = 1700000000

ETH, CHDLC, PPP = 0, 1, 2


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(shb() + idb(1) + idb(104) + idb(9))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.01, data))


def dnaddr(area, node):
    """DECnet Phase IV address as a 16 bit little endian value."""
    return (area << 10) | node


def dnmac(area, node):
    """The Ethernet address of a DECnet Phase IV node, AA-00-04-00-xx-xx."""
    return b'\xaa\x00\x04\x00' + struct.pack('<H', dnaddr(area, node))


NODE_A = dnmac(1, 10)       # 1.10
NODE_B = dnmac(1, 20)       # 1.20
ROUTER = dnmac(2, 5)        # 2.5
ALL_ROUTERS = bytes.fromhex('ab0000030000')
ALL_ENDNODES = bytes.fromhex('ab0000040000')
OTHER = bytes.fromhex('020000000001')   # not a DECnet address


def dna(body):
    """DEC DNA payload: a 16 bit little endian length, then the message."""
    return struct.pack('<H', len(body)) + body


def eth(payload, dst=NODE_B, src=NODE_A):
    return (ETH, dst + src + struct.pack('>H', 0x6003) + dna(payload))


def chdlc(payload):
    return (CHDLC, struct.pack('>BBH', 0x0f, 0x00, 0x6003) + dna(payload))


def ppp(payload):
    return (PPP, struct.pack('>BBH', 0xff, 0x03, 0x0027) + dna(payload))


def u16(v):
    return struct.pack('<H', v)


# ---------------------------------------------------------------- routing
def init_msg(src, tiinfo, blksize, ver, timer, reserved=b''):
    # The reserved count octet counts itself.
    rem = bytes([len(reserved) + 1]) + reserved if reserved else b'\x00'
    return bytes([0x01]) + u16(src) + u16(tiinfo) + u16(blksize) + bytes(ver) + u16(timer) + rem


def verif_msg(src, fcn=b''):
    rem = bytes([len(fcn) + 1]) + fcn if fcn else b'\x00'
    return bytes([0x03]) + u16(src) + rem


def hello_test(src, data=b''):
    return bytes([0x05]) + u16(src) + data


def routing_msg(level, src, segs, bad=False):
    flags = 0x07 if level == 1 else 0x09
    body = bytes([flags]) + u16(src) + b'\x00'
    s = 1
    for count, start, info in segs:
        body += u16(count) + u16(start) + u16(info)
        s += count + start + info
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    if bad:
        s ^= 0x5555
    return body + u16(s)


def router_list(entries):
    out = b''
    for name, routers in entries:
        rl = b''
        for rid, state in routers:
            rl += rid + bytes([state])
        out += name + bytes([len(rl)]) + rl
    return out


def router_hello(rid, iinfo, prio, timer, rlist, ver=(2, 0, 0), lead=b'',
                 image_len=None):
    if image_len is None:
        image_len = len(rlist)
    return (lead + bytes([0x0b]) + bytes(ver) + rid + bytes([iinfo]) + u16(1498)
            + bytes([prio, 0]) + u16(timer) + b'\x00' + bytes([image_len]) + rlist)


def endnode_hello(rid, iinfo, seed, neighbor, timer, test=b'', ver=(2, 0, 0)):
    return (bytes([0x0d]) + bytes(ver) + rid + bytes([iinfo]) + u16(1498)
            + b'\x00' + seed + neighbor + u16(timer) + b'\x00' + test)


# ---------------------------------------------------------------- data
def short_hdr(dst, src, visits=0, flags=0x02):
    return bytes([flags]) + u16(dst) + u16(src) + bytes([visits])


def long_hdr(dst, src, visits=0, flags=0x26):
    return (bytes([flags]) + b'\x00\x00' + dst + b'\x00\x00' + src
            + bytes([0, visits, 0, 0]))


def nsp(mtype, dst, src=None, rest=b''):
    out = bytes([mtype]) + u16(dst)
    if src is not None:
        out += u16(src)
    return out + rest


def end_user(fmt, obj, name=b'', grp=0, usr=0, with_name=None):
    # Formats 1 and 2 have a name
    if with_name is None:
        with_name = fmt != 0
    out = bytes([fmt, obj])
    if fmt == 2:
        out += u16(grp) + u16(usr)
    if with_name:
        out += bytes([len(name)]) + name
    return out


def lstr(s):
    return bytes([len(s)]) + s


def connect_data(dst_eu, src_eu, menuver, extra=b''):
    return dst_eu + src_eu + bytes([menuver]) + extra


def frames_main():
    F = []
    A = dnaddr(1, 10)
    B = dnaddr(1, 20)
    R = dnaddr(2, 5)

    # 1-6: routing initialization, verification, hello and test
    F.append(eth(init_msg(A, 0x0002, 1498, (2, 0, 0), 15, b'\x11\x22'), ALL_ROUTERS))
    F.append(eth(init_msg(B, 0x000b, 576, (1, 3, 0), 60), ALL_ROUTERS))
    F.append(eth(verif_msg(A, b'\x01\x02\x03\x04\x05\x06\x07\x08')))
    F.append(eth(verif_msg(B), NODE_A, NODE_B))
    F.append(eth(hello_test(A, b'\xaa' * 10)))
    F.append(eth(hello_test(B), NODE_A, NODE_B))

    # 7-9: level 1 and level 2 routing messages (the checksum is folded)
    F.append(eth(routing_msg(1, R, [(3, 1, (2 << 10) | 7), (0xfff0, 0xff00, 0x7fff)]),
                 ALL_ROUTERS, ROUTER))
    F.append(eth(routing_msg(2, R, [(63, 1, (1 << 10) | 4)]), ALL_ROUTERS, ROUTER))
    F.append(eth(routing_msg(2, R, [(1, 1, 5), (1, 2, 6), (1, 3, 7)]),
                 ALL_ROUTERS, ROUTER))

    # 10-14: Ethernet router hello messages
    rl = router_list([
        (b'ETHNET1', [(NODE_A, 0x80 | 64), (OTHER, 0x10)]),
        (b'ETHNET2', []),
    ])
    F.append(eth(router_hello(ROUTER, 0x22, 64, 15, rl), ALL_ENDNODES, ROUTER))
    # Padding before the routing flags (0x82: the padding octet count, 2, includes itself)
    F.append(eth(router_hello(OTHER, 0x41, 7, 15,
                              router_list([(b'ETHNET3', [(ROUTER, 0x85)])]),
                              lead=b'\x82\x00'), ALL_ENDNODES, OTHER))
    # Lists that do not hold whole entries: a 3 octet list and a 10
    # octet list whose entry claims one router of 7 octets
    F.append(eth(router_hello(ROUTER, 0x01, 1, 15, b'\x01\x02\x03'),
                 ALL_ENDNODES, ROUTER))
    F.append(eth(router_hello(ROUTER, 0x01, 1, 15, b'ETHNET4\x07\x00\x00'),
                 ALL_ENDNODES, ROUTER))
    # The reproducer of "DEC DNA: Do not wrap the router list lengths"
    # (dnart_hello_item_underflow.pcap): an 8 octet list
    # whose entry claims 5 octets of routers, then filler.
    F.append((ETH, bytes.fromhex(
        '020000000002020000000001600300000b010203aa00040001040'
        '0dc0507000a00000841424344454647'
        '05aa000400020480') + b'\x11' * 40))

    # 15-16: Ethernet endnode hello messages
    F.append(eth(endnode_hello(NODE_A, 0x3f, b'\x01' * 8, ROUTER, 10, b'\xcc' * 4),
                 ALL_ROUTERS))
    F.append(eth(endnode_hello(NODE_B, 0x03, b'\x00' * 8, OTHER, 10),
                 ALL_ROUTERS, NODE_B))

    # 17: routing control message type 7 (not defined)
    F.append(eth(bytes([0x0f, 0x00, 0x00])))

    # 18-23: NSP connection set-up over short data packets
    sh = short_hdr(B, A, 1)
    F.append(eth(sh + nsp(0x18, 0, 0x1001, bytes([0x05, 0x02]) + u16(1460)
                          + connect_data(end_user(1, 0, b'FAL'),
                                         end_user(2, 0, b'USER', 0x0102, 0x0304),
                                         0x01, lstr(b'SYSTEM') + lstr(b'') + lstr(b'ACCT')))))
    F.append(eth(short_hdr(A, B, 2, 0x0a) + nsp(0x24, 0x1001), NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B, 2, 0x12) + nsp(0x28, 0x1001, 0x2001,
                 bytes([0x01, 0x01]) + u16(1024)
                 + connect_data(end_user(2, 17, b'MAIL', 0x10, 0x20),
                                end_user(1, 0, b'ME'), 0x00)), NODE_A, NODE_B))
    F.append(eth(sh + nsp(0x18, 0, 0x1002, bytes([0x09, 0x00]) + u16(512)
                          + connect_data(end_user(0, 25), end_user(0, 17),
                                         0x02, b'userdata'))))
    F.append(eth(sh + nsp(0x68, 0, 0x1003, bytes([0x0d, 0x03]) + u16(512)
                          + connect_data(end_user(2, 0, b'X', 1, 2),
                                         end_user(1, 0, b'Y'), 0x00))))
    F.append(eth(sh + nsp(0x08, 0x2001, rest=b'NOP test data')))

    # 24-31: data segments (long data packets): BOM with ACK and ACKOTH,
    # continuation with a NAK and a NAK of other data, EOM without ACK,
    # BOM/EOM with an ACK but no ACKOTH
    lh = long_hdr(NODE_B, NODE_A, 3)
    F.append(eth(lh + nsp(0x20, 0x2001, 0x1001, u16(0x8000 | 5) + u16(0xa000 | 2)
                          + u16(6) + b'first part ')))
    F.append(eth(lh + nsp(0x00, 0x2001, 0x1001, u16(0x9000 | 5) + u16(0x9000 | 3)
                          + u16(0x1000 | 7) + b'middle part ')))
    F.append(eth(long_hdr(NODE_B, NODE_A, 0, 0x4e)
                 + nsp(0x40, 0x2001, 0x1001, u16(8) + b'last part')))
    F.append(eth(long_hdr(NODE_A, NODE_B, 0, 0x3e)
                 + nsp(0x60, 0x1001, 0x2001, u16(0x8000 | 8) + u16(1) + b'reply'),
                 NODE_A, NODE_B))
    F.append(eth(lh + nsp(0x20, 0x2001, 0x1001, u16(9) + b'abc')))
    F.append(eth(lh + nsp(0x40, 0x2001, 0x1001, u16(10) + b'')))
    F.append(eth(short_hdr(B, A) + nsp(0x60, 0x2001, 0x1001,
                                       u16(0x8000 | 0x1000 | 9) + u16(0xa000 | 4) + u16(11))))
    # A BOM/EOM data segment over Cisco HDLC and over PPP
    F.append(chdlc(short_hdr(B, A) + nsp(0x60, 0x2001, 0x1001, u16(12) + b'hdlc')))

    # 32-34: interrupt messages
    F.append(eth(sh + nsp(0x30, 0x2001, 0x1001, u16(1) + b'intr')))
    F.append(eth(sh + nsp(0x30, 0x2001, 0x1001, u16(0x8000 | 1) + u16(0xa000 | 11)
                          + u16(2) + b'intr')))
    F.append(eth(sh + nsp(0x30, 0x2001, 0x1001, u16(0x9000 | 2) + u16(3))))

    # 35-40: link service messages
    F.append(eth(sh + nsp(0x10, 0x2001, 0x1001, u16(1))))
    for lsf, fc in ((0x00, 0), (0x01, 0), (0x02, 4), (0x05, 1)):
        F.append(eth(sh + nsp(0x10, 0x2001, 0x1001, u16(0x8000 | 1) + u16(0xa000 | 11)
                              + u16(2) + bytes([lsf, fc]))))
    F.append(eth(sh + nsp(0x10, 0x2001, 0x1001, u16(0x9000 | 2) + u16(3) + bytes([0x06, 2]))))

    # 41-46: data and other data acknowledgements
    F.append(eth(short_hdr(A, B) + nsp(0x04, 0x1001, 0x2001, u16(0x8000 | 11)), NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x04, 0x1001, 0x2001, u16(0x9000 | 11) + u16(0xa000 | 3)),
                 NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x04, 0x1001, 0x2001, u16(0x8000 | 12) + u16(0x0003)),
                 NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x14, 0x1001, 0x2001, u16(0x8000 | 2)), NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x14, 0x1001, 0x2001, u16(0x8000 | 2) + u16(0x9000 | 12)),
                 NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x14, 0x1001, 0x2001, u16(0x9000 | 3) + u16(0x0001)),
                 NODE_A, NODE_B))

    # 47-50: disconnects, an unknown NSP message type, a hello and test
    # message over PPP
    F.append(eth(sh + nsp(0x38, 0x2001, 0x1001, u16(9) + b'\x00')))
    F.append(eth(short_hdr(A, B) + nsp(0x48, 0x1001, 0x2001, u16(42)), NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x58, 0x1001, 0x2001, b'\x01\x02'), NODE_A, OTHER))
    F.append(ppp(hello_test(A, b'ppp')))

    # 51-54: NAKs and ACKs of the other subchannel
    F.append(eth(sh + nsp(0x30, 0x2001, 0x1001, u16(0x8000 | 3) + u16(0x9000 | 12)
                          + u16(4))))
    F.append(eth(sh + nsp(0x10, 0x2001, 0x1001, u16(0x8000 | 4) + u16(0x9000 | 12)
                          + u16(5) + bytes([0x02, 1]))))
    F.append(eth(short_hdr(A, B) + nsp(0x04, 0x1001, 0x2001, u16(0x8000 | 13) + u16(0x9000 | 5)),
                 NODE_A, NODE_B))
    F.append(eth(short_hdr(A, B) + nsp(0x14, 0x1001, 0x2001, u16(0x8000 | 5) + u16(0xa000 | 13)),
                 NODE_A, NODE_B))
    # 55: a long data packet between addresses that are not DECnet ones
    F.append(eth(long_hdr(OTHER, ALL_ROUTERS, 1, 0x46)
                 + nsp(0x60, 0x2001, 0x1001, u16(0x3000 | 14) + b'x'), OTHER, OTHER))
    # 56: a router hello listing routers whose addresses differ from
    # the DECnet prefix AA-00-04-00 in the second, third and fourth octet
    F.append(eth(router_hello(ROUTER, 0x02, 9, 15, router_list([
        (b'ETHNET5', [(bytes.fromhex('aa0104000a04'), 0x80),
                      (bytes.fromhex('aa0005000a04'), 0x81),
                      (bytes.fromhex('aa0004010a04'), 0x02)])])), ALL_ENDNODES, ROUTER))
    return F


def frames_malformed():
    F = []
    A = dnaddr(1, 10)
    R = dnaddr(2, 5)
    F.append(eth(b''))                                          # no routing flags
    F.append(eth(routing_msg(2, R, [(1, 1, 5)], bad=True)))     # bad checksum
    F.append(eth(routing_msg(1, R, [(1, 1, 5)])[:-1]))         # 1 octet checksum
    F.append(eth(init_msg(A, 2, 1498, (2, 0, 0), 15, b'\x11\x22')[:-1]))
    F.append(eth(verif_msg(A, b'\x01\x02\x03')[:-1]))
    F.append(eth(long_hdr(NODE_B, NODE_A)[:12]))
    F.append(eth(router_hello(ROUTER, 0x22, 64, 15, b'', image_len=40)))
    F.append(eth(router_hello(ROUTER, 0x22, 64, 15, b'ETHNET1\x0e' + NODE_A + b'\x80',
                              image_len=22)))
    F.append(eth(endnode_hello(NODE_A, 0x03, b'\x00' * 8, ROUTER, 10)[:20]))
    F.append(eth(short_hdr(2, 1) + nsp(0x18, 0, 0x1001, bytes([0x05, 0x02]) + u16(1460)
                                       + end_user(1, 0, b'FAL')[:-1] + b'\x40')))
    F.append(eth(short_hdr(2, 1) + nsp(0x18, 0, 0x1001, bytes([0x05, 0x02]) + u16(1460)
                                       + connect_data(end_user(0, 25), end_user(0, 17),
                                                      0x01, b'\x09AB'))))
    F.append(eth(short_hdr(2, 1) + nsp(0x10, 0x2001, 0x1001, u16(0x8000 | 1) + u16(0xa000))))
    F.append(eth(short_hdr(2, 1) + nsp(0x20, 0x2001, 0x1001, u16(0x8000 | 1))))
    F.append(eth(short_hdr(2, 1) + nsp(0x30, 0x2001, 0x1001, u16(0x8000 | 1))))
    F.append(eth(short_hdr(2, 1) + nsp(0x04, 0x2001, 0x1001, b'\x01')))
    F.append(eth(short_hdr(2, 1) + nsp(0x14, 0x2001, 0x1001, u16(0x8000 | 1) + b'\x01')))
    F.append(eth(short_hdr(2, 1) + nsp(0x38, 0x2001, 0x1001, b'\x01')))
    F.append(eth(short_hdr(2, 1)[:3]))
    F.append(eth(b'\x85\x00\x00'))                              # padding past the end
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'dec-dnart-coverage.pcapng'), frames_main())
    write(os.path.join(out, 'dec-dnart-coverage-malformed.pcapng'), frames_malformed())


if __name__ == '__main__':
    main()

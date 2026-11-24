#!/usr/bin/env python3
# Generates test/captures/netlink-route_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic rtnetlink (NETLINK_ROUTE) captures for packet-netlink-route.c.

Usage: mkroute.py <outdir>
Writes route-coverage.pcap (clean) and route-coverage-malformed.pcap.
LINKTYPE_NETLINK (253): 16 byte cooked header whose protocol field (0)
selects NETLINK_ROUTE, then netlink messages, host (little endian) byte
order unless a frame says otherwise.
"""
import struct
import sys
import os

NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000

def sll(proto=0):
    return struct.pack('>HHH8sH', 4, 824, 0, b'\0' * 8, proto)

def nla(t, payload=b'', e='<'):
    l = 4 + len(payload)
    return struct.pack(e + 'HH', l, t) + payload + b'\0' * ((4 - l % 4) % 4)

def nlmsg(t, payload, seq=1, flags=0, pid=0, e='<', length=None):
    if length is None:
        length = 16 + len(payload)
    return struct.pack(e + 'IHHII', length, t, flags, seq, pid) + payload

def pcap(frames, fn):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def ifinfo(fam=2, typ=1, idx=2, flags=0x10043, change=0xffffffff):
    return struct.pack('<BBHiII', fam, 0, typ, idx, flags, change)

def ifaddr(fam=2, plen=24, flags=0x80, scope=0, idx=2):
    return struct.pack('<BBBBI', fam, plen, flags, scope, idx)

def rtmsg(fam=2, dl=24, sl=0, tos=0, table=254, proto=2, scope=0, typ=1, flags=0):
    return struct.pack('<BBBBBBBBI', fam, dl, sl, tos, table, proto, scope, typ, flags)

def ndmsg(fam=2, idx=2, state=0x02, flags=0x01, typ=1):
    return struct.pack('<BBHiHBB', fam, 0, 0, idx, state, flags, typ)

def u32(v): return struct.pack('<I', v)
def u8(v): return struct.pack('B', v)

IP4 = bytes([192, 0, 2, 1])
IP6 = bytes.fromhex('20010db8000000000000000000000001')
MAC = bytes.fromhex('020000000001')
STATS = b''.join(u32(i + 1) for i in range(21))
STATS64 = b''.join(struct.pack('<Q', (i + 1) << 32 | i) for i in range(21))
MAP = struct.pack('<QQQHBB', 0x1000, 0x2000, 0x3000, 5, 1, 2)

def ifla_all():
    return (nla(3, b'eth0\0') + nla(4, u32(1500)) + nla(13, u32(1000)) + nla(16, u8(6)) +
            nla(30, u32(0)) + nla(31, u32(4)) + nla(32, u32(4)) + nla(27, u32(7)) +
            nla(40, u32(65535)) + nla(41, u32(65536)) + nla(33, u8(1)) + nla(34, u32(3)) +
            nla(1, MAC) + nla(2, b'\xff' * 6) + nla(7, STATS) + nla(23, STATS64) +
            nla(6, b'fq_codel\0') + nla(14, MAP) + nla(47, u32(5)) + nla(48, u32(4)) +
            nla(50, u32(68)) + nla(51, u32(9000)))

def ifla_other():
    """Attributes without a decoder of their own: shown as data."""
    return b''.join(nla(t, b'\x01\x02\x03\x04') for t in
                    [0, 5, 8, 9, 10, 11, 12, 15, 17, 18, 19, 20, 21, 22, 24, 25, 26, 28, 29, 35,
                     36, 37, 38, 39, 42, 43, 44, 45, 46, 49, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 70])

def ifa_all(v6=False):
    a = IP6 if v6 else IP4
    return (nla(1, a) + nla(2, a) + nla(3, b'eth0:1\0') + nla(4, IP4 if not v6 else IP6) +
            nla(8, u32(0x80 | 0x100)) + nla(5, a) + nla(6, struct.pack('<IIII', 1, 2, 3, 4)) +
            nla(7, a) + nla(9, u32(10)) + nla(10, u32(0)) + nla(11, u8(1)))

def rta_all():
    return (nla(1, IP4) + nla(2, IP4) + nla(3, u32(2)) + nla(4, u32(3)) + nla(5, IP4) +
            nla(6, u32(100)) + nla(7, IP4) + nla(8, nla(2, u32(1500))) + nla(15, u32(254)) +
            nla(16, u32(7)) + nla(17, bytes(8)) + nla(18, b'\x02' + IP4) + nla(20, u8(0)) +
            nla(25, u32(1000)) + nla(26, u8(1)) + nla(27, u8(6)) + nla(28, struct.pack('<H', 22)) +
            nla(29, struct.pack('<H', 80)) + nla(30, u32(9)) + nla(0) + nla(12, bytes(32)))

TYPES = [16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 36, 37, 38, 40, 41, 42,
         44, 45, 46, 48, 49, 50, 52, 58, 62, 64, 66, 67, 68, 72, 73, 74, 78, 79, 80, 81, 82, 84,
         85, 86, 88, 89, 90, 92, 94, 96, 100, 101, 102, 104, 105, 106, 108, 109, 110, 112, 113,
         114, 116, 117, 118, 120, 121, 122]

def main(out):
    os.makedirs(out, exist_ok=True)
    fr = []
    seq = [0]
    def add(t, payload, flags=0, pid=0, e='<'):
        seq[0] += 1
        fr.append(sll() + nlmsg(t, payload, seq[0], flags, pid, e))
    REQ = 0x301     # request | root | match (dump)
    # --- links
    add(16, ifinfo() + ifla_all(), flags=0x0, pid=0)
    add(16, ifinfo(typ=772, idx=1, flags=0x1090049) + ifla_all() + ifla_other(), pid=1234)
    add(17, ifinfo() + nla(3, b'veth0\0'), flags=0x5, pid=1)
    add(18, ifinfo(fam=0, idx=0, flags=0, change=0) + nla(29, u32(1)), flags=REQ)
    add(19, ifinfo() + nla(4, u32(9000)) + nla(3, b'eth0\0'), flags=0x5)
    # legacy GETLINK (rtgenmsg only, 3 padding bytes after the message) is in the
    # malformed capture: the attribute parser is called without data left
    # NLA_F_NESTED / NLA_F_NET_BYTEORDER on attributes with a decoder (type is masked)
    add(16, ifinfo() + nla(4 | NLA_F_NESTED, u32(1500)) + nla(3 | NLA_F_NESTED, b'lo\0') +
        nla(4 | NLA_F_NET_BYTEORDER, struct.pack('>I', 1280)))
    # all IFLA types without a decoder, and a nested one with attributes inside
    add(16, ifinfo() + nla(18 | NLA_F_NESTED, nla(1, b'veth\0') + nla(2, nla(1, u32(1)))))
    # --- addresses
    add(20, ifaddr() + ifa_all(), pid=1)
    add(20, ifaddr(fam=10, plen=64, flags=0xc0, scope=0xfe) + ifa_all(True), pid=1)
    add(21, ifaddr(plen=32, scope=253) + nla(1, IP4) + nla(2, IP4), flags=0x5)
    add(22, ifaddr(fam=0, plen=0, flags=0, idx=0), flags=REQ)
    add(22, b'\x00', flags=REQ)                      # legacy GETADDR
    add(20, ifaddr() + nla(1 | NLA_F_NESTED, IP4) + nla(3 | NLA_F_NET_BYTEORDER, b'eth0\0'))
    # --- routes
    add(24, rtmsg() + rta_all(), flags=0x501, pid=1)
    add(24, rtmsg(fam=10, dl=64, proto=9, scope=253, typ=2, flags=0x200) + nla(1, IP6) + nla(5, IP6) +
        nla(4, u32(2)) + nla(3, struct.pack('<H', 2)) + nla(4, u8(1)), flags=0x501)
    add(25, rtmsg(proto=3, scope=253, typ=3) + nla(1, IP4) + nla(4 | NLA_F_NESTED, u32(3)) +
        nla(3 | NLA_F_NET_BYTEORDER, struct.pack('>I', 2)), flags=0x5)
    add(26, rtmsg(fam=0, dl=0, table=0, proto=0, typ=0), flags=REQ)
    add(26, b'\x02', flags=REQ)                      # legacy GETROUTE
    # --- neighbours
    add(28, ndmsg(state=0x80, flags=0x02) + nla(1, IP4) + nla(2, MAC), flags=0x501)
    add(29, ndmsg(fam=10, state=0x40, typ=2) + nla(1, IP6), flags=0x5)
    add(30, ndmsg(fam=0, idx=0, state=0, flags=0, typ=0), flags=REQ)
    add(30, b'\x02', flags=REQ)                      # legacy GETNEIGH
    # --- every other message type: header and a short body
    for t in TYPES:
        if t in (16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 28, 29, 30):
            continue
        add(t, b'\x02\0\0\0' + u32(2) + u32(0), flags=0x1)
    # message types below 16 (netlink control messages) and a multipart dump
    add(1, b'', flags=0)
    add(2, struct.pack('<i', 0) + nlmsg(18, b'\0' * 16, 1, 0x301)[:16], flags=0x4)   # ACK
    add(3, struct.pack('<i', 0), flags=0x2)
    # three messages in one packet (dump reply), then DONE
    seq[0] += 1
    parts = b''.join(nlmsg(16, ifinfo(idx=i) + nla(3, b'eth%d\0' % i) + nla(4, u32(1500)), seq[0], 0x2, 77)
                     for i in (1, 2, 3))
    parts += nlmsg(3, struct.pack('<i', 0), seq[0], 0x2, 77)
    fr.append(sll() + parts)
    # big endian encoded messages (guessed from the message length)
    seq[0] += 1
    fr.append(sll() + nlmsg(16, struct.pack('>BBHiII', 2, 0, 1, 2, 0x43, 0xffffffff) +
                            nla(3, b'be0\0', '>') + nla(4, struct.pack('>I', 1500), '>') +
                            nla(14, struct.pack('>QQQHBB', 1, 2, 3, 4, 5, 6), '>'), seq[0], 0, 0, '>'))
    seq[0] += 1
    fr.append(sll() + nlmsg(20, struct.pack('>BBBBI', 2, 24, 0, 0, 2) + nla(1, IP4, '>') +
                            nla(8, struct.pack('>I', 0x80), '>'), seq[0], 0, 0, '>'))
    pcap(fr, os.path.join(out, 'route-coverage.pcap'))
    nclean = len(fr)

    # ------------------------------------------------------------------
    mal = []
    seq[0] = 0
    def madd(t, payload, flags=0, pid=0):
        seq[0] += 1
        mal.append(sll() + nlmsg(t, payload, seq[0], flags, pid))
    madd(16, ifinfo() + nla(14, MAP[:8]))                         # short MAP
    madd(16, ifinfo() + nla(7, STATS[:4]))                        # short STATS
    madd(16, ifinfo() + nla(23, STATS))                           # STATS64 with 4 byte counters
    madd(16, ifinfo() + nla(4, b'\x01\x02\x03\x04\x05'))          # MTU with 5 bytes
    madd(16, ifinfo() + nla(3, b''))                              # empty IFNAME
    madd(16, ifinfo() + nla(3, b'unterminated'))
    madd(16, ifinfo() + nla(1, b''))                              # empty HW address
    madd(16, ifinfo() + nla(33, b''))                             # empty CARRIER
    madd(18, b'\x00', flags=0x301)                                  # legacy GETLINK: rtgenmsg only
    madd(18, b'\x11' + b'\0' * 3 + nla(29, u32(1))[:8], flags=0x301)  # shorter than ifinfomsg, with data
    madd(16, ifinfo()[:7])                                        # truncated ifinfomsg
    madd(20, ifaddr() + nla(1, b'\x01\x02\x03\x04\x05'))          # address of 5 bytes
    madd(20, ifaddr() + nla(8, b'\x01\x02'))                      # 2 byte flags
    madd(20, ifaddr()[:5])
    madd(24, rtmsg() + nla(3, b'\x01\x02') + nla(4, b'\x01'))     # IIF/OIF with odd lengths (raw data)
    madd(24, rtmsg()[:6])
    madd(30, ndmsg()[:6])
    madd(16, ifinfo() + struct.pack('<HH', 200, 3) + b'\0' * 4)   # attribute longer than the message
    madd(16, ifinfo() + struct.pack('<HH', 2, 3) + b'\0' * 4)     # attribute shorter than its header
    madd(16, ifinfo() + struct.pack('<HH', 0, 0))
    # "Netlink: Bound message length and attribute nesting": message length 2^32-16
    # makes the offset run backwards; a length beyond the packet
    mal.append(sll() + nlmsg(1, b'', 1) + nlmsg(1, b'', 2, length=0xfffffff0))
    mal.append(sll() + nlmsg(16, ifinfo() + nla(3, b'eth0\0'), 3, length=0x10000))
    mal.append(sll() + nlmsg(16, ifinfo(), 4, length=15))
    pcap(mal, os.path.join(out, 'route-coverage-malformed.pcap'))
    print('clean frames', nclean, 'malformed frames', len(mal))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

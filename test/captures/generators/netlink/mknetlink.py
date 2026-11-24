#!/usr/bin/env python3
# Generates test/captures/netlink_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Linux netlink (LINKTYPE_NETLINK 253) captures for packet-netlink.c.
# Usage: mknetlink.py <outdir> [-v]
# The attribute code of packet-netlink.c is driven by its subdissectors, so
# the capture carries rtnetlink (route) messages and generic netlink
# (nlctrl, NET_DM) messages. The reproducers of "Netlink: Bound message
# length and attribute nesting" are frames 41-47 (nesting) of the main
# capture and the length wrap in the malformed capture.
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def cooked(family, hatype=0x0338, pkttype=4):
    return struct.pack('>HHH8sH', pkttype, hatype, 0, b'\0' * 8, family)

def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)

def attr(atype, payload=b'', flags=0, be=False, rlen=None, pad=True):
    l = 4 + len(payload)
    e = '>' if be else '<'
    return struct.pack(e + 'HH', l if rlen is None else rlen, atype | flags) + (pad4(payload) if pad else payload)

def nlmsg(mtype, payload=b'', flags=0, seq=1, pid=0, be=False, length=None):
    e = '>' if be else '<'
    return struct.pack(e + 'IHHII', 16 + len(payload) if length is None else length, mtype, flags, seq, pid) + payload

NESTED = 0x8000; NETBO = 0x4000
RTM_NEWLINK, RTM_GETLINK, RTM_NEWADDR, RTM_NEWROUTE = 16, 18, 20, 24
REQ, MULTI, ACK, ECHO, DUMPINTR, DUMPFILT = 1, 2, 4, 8, 0x10, 0x20
ROOT, MATCH, ATOMIC = 0x100, 0x200, 0x400
REPLACE, EXCL, CREATE, APPEND = 0x100, 0x200, 0x400, 0x800
ROUTE, USERSOCK, GENERIC = 0, 2, 16

def ifinfo(idx=2, flags=0x1003, family=0, be=False):
    return struct.pack('>BBHiII' if be else '<BBHiII', family, 0, 1, idx, flags, 0xffffffff)

frames = []; marks = []
def add(family, msgs, label, **kw):
    frames.append(cooked(family, **kw) + (msgs if isinstance(msgs, bytes) else b''.join(msgs)))
    marks.append((len(frames), label))

# 1-8: control messages and messages no subdissector claims
add(ROUTE, nlmsg(1), 'NLMSG_NOOP')
add(ROUTE, nlmsg(2, struct.pack('<i', -1) + nlmsg(RTM_GETLINK, b'', REQ | ACK, 7)), 'NLMSG_ERROR (-1) with the failed header')
add(ROUTE, nlmsg(2, struct.pack('<i', 0) + nlmsg(RTM_NEWLINK, b'', REQ | ACK, 8)), 'NLMSG_ERROR acknowledgement (0)')
add(ROUTE, nlmsg(3, struct.pack('<i', 0), MULTI), 'NLMSG_DONE')
add(ROUTE, nlmsg(4, b'', 0), 'NLMSG_OVERRUN')
add(USERSOCK, nlmsg(0x20, b'user protocol data', REQ), 'USERSOCK message (no subdissector): data')
add(USERSOCK, nlmsg(0x20), 'USERSOCK message of 16 octets')
add(255, nlmsg(0x1234, b'\x01\x02\x03\x04', 0, 3, 1234), 'Unknown family 255')
# 9-13: header flags
add(ROUTE, nlmsg(RTM_GETLINK, ifinfo(), REQ | ROOT | MATCH), 'GETLINK, request + root + match (get flags)')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), REQ | ACK | CREATE | EXCL | REPLACE | APPEND, 5), 'NEWLINK, request + create/excl/replace/append (new flags)')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), MULTI | DUMPINTR | DUMPFILT | ECHO, 6, 99), 'NEWLINK reply, multi + dump flags (standard flags)')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), ROOT | MATCH | ATOMIC, 6, 99), 'NEWLINK without the request flag, bits 0x700')
add(ROUTE, nlmsg(RTM_GETLINK, ifinfo(), REQ | ATOMIC), 'GETLINK, request + atomic')
# 14-: attributes through rtnetlink
nm = attr(3, b'eth0\0')                                 # IFNAME, padding of 3
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + nm + attr(4, struct.pack('<I', 1500)) + attr(1, bytes(6)), 0, 10, 5),
    'NEWLINK with IFNAME (padding), MTU, ADDRESS')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(4, struct.pack('>I', 9000), NETBO, be=False), 0, 11, 5),
    'attribute with the net byteorder flag (value read big endian)')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(0x55, b'abcd', NESTED), 0, 12, 5), 'attribute with the nested flag, unknown type')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(0x7fff, b'xyzw') + attr(0, b'')), 'unknown attribute types 0x7fff and 0')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(3, b'ab\0', rlen=100)), 'attribute length beyond the message (clamped)')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(4, struct.pack('<I', 1500)) + attr(3, b'', rlen=2) + b'\x00' * 8), 'attribute length below 4 stops the list')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(4, struct.pack('<I', 1500)) + b'\x00\x00'), 'trailing octets shorter than an attribute header')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(3, b'eth0\0', pad=False)), 'last attribute without its padding')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(3, b'eth01\0\0\0', rlen=13)), 'attribute length 13 followed by padding')
# legacy GETLINK: one octet of ifinfomsg, so the attributes start unaligned
add(ROUTE, nlmsg(RTM_GETLINK, b'\x00' + b'\x00' * 3 + attr(3, b'lo\0'), REQ | ROOT | MATCH), 'legacy GETLINK: unaligned attribute start (3 padding octets)')
add(ROUTE, nlmsg(RTM_GETLINK, b'\x00' + b'\x00' * 2 + attr(3, b'lo\0'), REQ), 'legacy GETLINK with 2 padding octets')
add(ROUTE, nlmsg(22, b'\x02\x18\x80\x00' + struct.pack('<I', 2) + attr(1, bytes([192, 0, 2, 1])) + attr(2, bytes([192, 0, 2, 2])) + attr(3, b'eth0:1\0'), REQ), 'GETADDR with attributes')
add(ROUTE, nlmsg(RTM_NEWADDR, b'\x02\x18\x80\x00' + struct.pack('<I', 2) + attr(1, bytes([192, 0, 2, 1])) + attr(8, struct.pack('<I', 0x80)), 0, 3, 9), 'NEWADDR with address and flags')
add(ROUTE, nlmsg(RTM_NEWROUTE, b'\x02\x18\x00\x00\x00\xfe\x02\x01' + struct.pack('<I', 0) + attr(1, bytes([198, 51, 100, 0])) + attr(4, struct.pack('<I', 2)), 0, 3, 9), 'NEWROUTE with destination and oif')
# big endian capture host
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(be=True) + attr(3, b'eth0\0', be=True) + attr(4, struct.pack('>I', 1500), be=True), REQ, 20, 0, be=True),
    'big endian NEWLINK')
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(be=True) + attr(4, struct.pack('>I', 9000), NETBO, be=True), 0, 21, 5, be=True), 'big endian, net byteorder attribute')
add(ROUTE, nlmsg(3, struct.pack('>i', 0), MULTI, be=True), 'big endian NLMSG_DONE')
# several messages in one frame
add(ROUTE, [nlmsg(RTM_NEWLINK, ifinfo() + attr(3, b'eth0\0'), MULTI, 30, 5), nlmsg(RTM_NEWLINK, ifinfo(3) + attr(3, b'eth1\0'), MULTI, 30, 5), nlmsg(3, struct.pack('<i', 0), MULTI, 30, 5)], 'three messages in one frame (multi-part dump)')
add(ROUTE, [nlmsg(1), nlmsg(0x20, b'x' * 3)], 'NOOP followed by a route message of type 0x20 (data)')
add(USERSOCK, [nlmsg(0x20, b'first'), nlmsg(0x21, b'second' * 3)], 'two USERSOCK messages')
add(ROUTE, nlmsg(1) + b'\x01\x02\x03\x04\x05', 'a trailing 5 octets after the message')
add(ROUTE, nlmsg(1) + struct.pack('<I', 4) + b'\x00' * 12, 'second message with length 4 (< 16) stops the loop')
add(ROUTE, nlmsg(1) + struct.pack('<I', 0) + b'\x00' * 12, 'second message with length 0')
add(ROUTE, nlmsg(1, length=16) + nlmsg(1, length=15), 'second message with length 15')
# the cooked header
add(ROUTE, nlmsg(1), 'non-netlink hardware type 1 (not dissected)', hatype=1)
add(ROUTE, nlmsg(RTM_GETLINK, ifinfo(), REQ), 'packet type 0 (incoming)', pkttype=0)
add(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(3, b'eth0\0'), 0, 40, 4321), 'kernel to user: pid nonzero (received direction)')

# generic netlink: nlctrl with the array forms (ops, multicast groups)
def ctrl(cmd, attrs, flags=0, seq=1, pid=0, be=False, version=2):
    return nlmsg(0x10, struct.pack('<BBH', cmd, version, 0) + attrs, flags, seq, pid, be=be)
ops = attr(1, attr(1, struct.pack('<I', 5)) + attr(2, struct.pack('<I', 0x0e)), 0) + attr(2, attr(1, struct.pack('<I', 6)) + attr(2, struct.pack('<I', 0x01)))
grps = attr(1, attr(1, b'config\0') + attr(2, struct.pack('<I', 7))) + attr(2, attr(1, b'scan\0') + attr(2, struct.pack('<I', 8)))
fam = (attr(2, b'NET_DM\0') + attr(1, struct.pack('<H', 0x20)) + attr(3, struct.pack('<I', 2)) + attr(4, struct.pack('<I', 0)) +
       attr(5, struct.pack('<I', 19)) + attr(6, ops) + attr(7, grps))
add(GENERIC, ctrl(1, fam, 0, 100), 'CTRL_CMD_NEWFAMILY NET_DM = 0x20 with ops and multicast groups')
add(GENERIC, ctrl(3, attr(2, b'NET_DM\0'), REQ, 101), 'CTRL_CMD_GETFAMILY request')
GENL_NETDM = 0x20
def netdm(attrs, flags=0, seq=1, cmd=5):
    return nlmsg(GENL_NETDM, struct.pack('<BBH', cmd, 1, 0) + attrs, flags, seq)
def nest(depth):
    body = b''
    total = 4 * depth
    for i in range(depth):
        body += struct.pack('<HH', min(total - 4 * i, 0xffff), 17)
    return body
mk = len(frames) + 1
add(GENERIC, netdm(nest(1)), 'NET_DM HW_ENTRIES nested 1 level')
add(GENERIC, netdm(nest(31)), 'nested 31 levels')
add(GENERIC, netdm(nest(32)), 'nested 32 levels')
add(GENERIC, netdm(nest(33)), 'nested 33 levels (limit reached, expert info)')
add(GENERIC, netdm(nest(64)), 'nested 64 levels')
add(GENERIC, netdm(nest(1000)), 'nested 1000 levels')
add(GENERIC, netdm(nest(16383)), 'nested 16383 levels (reproducer of the stack overflow)')

pcap(os.path.join(sys.argv[1], 'netlink-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, l in marks: print(n, l)
    print(len(frames), 'frames')

# malformed
mal = []
def madd(family, msgs, **kw): mal.append(cooked(family, **kw) + (msgs if isinstance(msgs, bytes) else b''.join(msgs)))
madd(ROUTE, nlmsg(1) + nlmsg(1, length=0xFFFFFFF0))                          # the wrap reproducer
madd(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), length=0x1000))                      # length beyond the frame
madd(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), length=0xFFFFFFFF))
madd(ROUTE, nlmsg(RTM_NEWLINK, ifinfo(), length=0x00000100, be=True))        # big endian guess with a bad length
madd(ROUTE, nlmsg(RTM_GETLINK, b'\x00', REQ))                                 # legacy header: 1 octet, no room for the padding
madd(ROUTE, nlmsg(RTM_GETLINK, b'\x00\x00\x00', REQ))                         # padding 3 > length 2
madd(ROUTE, nlmsg(RTM_NEWLINK, ifinfo() + attr(4, struct.pack('<I', 1500), rlen=0xffff, pad=False)[:6]))  # attribute cut by the frame
madd(ROUTE, nlmsg(RTM_NEWLINK, ifinfo()[:7]))                                 # truncated ifinfomsg
madd(ROUTE, nlmsg(2, b'\x01\x00'))                                            # error message cut short
madd(ROUTE, nlmsg(1)[:15] + b'')                                              # fewer than 16 octets
madd(GENERIC, ctrl(1, attr(6, attr(1, attr(1, b'\x01\x00')))))                # nested array cut short
madd(ROUTE, b'')                                                              # only the cooked header
pcap(os.path.join(sys.argv[1], 'netlink-coverage-malformed.pcap'), mal)

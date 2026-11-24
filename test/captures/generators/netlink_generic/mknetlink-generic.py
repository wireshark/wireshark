#!/usr/bin/env python3
# Generates test/captures/netlink_generic_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic generic netlink captures (LINKTYPE_NETLINK 253) for
# packet-netlink-generic.c. Usage: mknetlink-generic.py <outdir> [-v]
# Generic netlink maps dynamic family ids to names with CTRL_CMD_NEWFAMILY
# messages earlier in the same capture; later messages of that id are
# handed to the family's dissector. The reproducer of
# "netlink-generic: Update the family map only on the first pass" is
# frames 5-12 (a family id reused, tshark -2 shows the same names).
import struct
import sys
import os

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def cooked(family=16):
    return struct.pack('>HHH8sH', 4, 0x0338, 0, b'\0' * 8, family)

def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)
def attr(atype, payload=b'', be=False, flags=0):
    return struct.pack('>HH' if be else '<HH', 4 + len(payload), atype | flags) + pad4(payload)
def u32(v, be=False): return struct.pack('>I' if be else '<I', v)
def u16(v, be=False): return struct.pack('>H' if be else '<H', v)

def msg(fid, cmd, attrs=b'', flags=0, seq=1, pid=0, be=False, version=2, raw=None):
    body = struct.pack('<BBH', cmd, version, 0) + attrs if raw is None else raw
    return struct.pack('>IHHII' if be else '<IHHII', 16 + len(body), fid, flags, seq, pid) + body

CTRL = 0x10
frames = []; marks = []
def add(m, label):
    frames.append(cooked() + m); marks.append((len(frames), label))

def ops_array(entries, be=False):
    out = b''
    for i, (opid, fl) in enumerate(entries, 1):
        sub = b''
        if opid is not None: sub += attr(1, u32(opid, be), be)
        if fl is not None: sub += attr(2, u32(fl, be), be)
        out += attr(i, sub, be)
    return out
def grp_array(entries, be=False):
    out = b''
    for i, (name, gid) in enumerate(entries, 1):
        sub = b''
        if name is not None: sub += attr(1, name, be)
        if gid is not None: sub += attr(2, u32(gid, be), be)
        out += attr(i, sub, be)
    return out
def newfam(fid, name, extra=b'', be=False):
    a = b''
    if name is not None: a += attr(2, name + b'\0', be)
    if fid is not None: a += attr(1, u16(fid, be), be)
    return a + extra

# 1-4: requests and the nlctrl commands
add(msg(CTRL, 3, attr(2, b'TESTFAM\0'), 1, 1), 'CTRL_CMD_GETFAMILY request by name')
add(msg(CTRL, 3, attr(1, u16(0x21)), 1, 2), 'CTRL_CMD_GETFAMILY request by id')
add(msg(CTRL, 10, b'', 1, 3), 'CTRL_CMD_GETPOLICY, no attributes')
add(msg(CTRL, 0, b'', 0, 4), 'CTRL_CMD_UNSPEC, header only')
# 5-12: family id to name mapping
add(msg(CTRL, 1, newfam(0x21, b'TESTFAM', attr(3, u32(1)) + attr(4, u32(0)) + attr(5, u32(7)) +
        attr(6, ops_array([(1, 0x01), (2, 0x02), (3, 0x04), (4, 0x08), (5, 0x10), (6, 0x1f), (7, 0)])) +
        attr(7, grp_array([(b'mcast1\0', 5), (b'mcast2\0', 6)])))), 'NEWFAMILY 0x21 TESTFAM with ops (all flag bits) and groups')
add(msg(0x21, 1, b'abcd', 0, 10), 'TESTFAM message with payload (no family dissector)')
add(msg(0x21, 2, b'', 0, 11), 'TESTFAM message, header only')
add(msg(0x77, 1, b'xy', 0, 12), 'message of an unmapped id 0x77 (Unknown)')
add(msg(CTRL, 1, newfam(0x21, b'OTHERFAM')), 'NEWFAMILY 0x21 again, now OTHERFAM (the id is reused)')
add(msg(0x21, 1, b'efgh', 0, 13), 'message of 0x21 after the remap: OTHERFAM')
add(msg(CTRL, 1, newfam(0x21, b'TESTFAM')), 'NEWFAMILY 0x21 TESTFAM once more')
add(msg(0x21, 3, b'ijkl', 0, 14), 'message of 0x21: TESTFAM again')
# 13-17: entries the map must not take
add(msg(CTRL, 1, newfam(CTRL, b'evil')), 'NEWFAMILY with the nlctrl id 0x10: not taken')
add(msg(CTRL, 3, attr(2, b'x\0'), 1, 20), 'a later nlctrl message is still nlctrl')
add(msg(CTRL, 1, newfam(0, b'ZEROFAM')), 'NEWFAMILY with id 0: not taken')
add(msg(CTRL, 1, newfam(0x23, None)), 'NEWFAMILY without a name: not taken')
add(msg(CTRL, 1, newfam(None, b'NOID')), 'NEWFAMILY without an id: not taken')
add(msg(0x23, 1, b'zz', 0, 21), 'message of 0x23 (never mapped)')
# 19-: attributes of nlctrl with unusual lengths and types
add(msg(CTRL, 1, attr(1, u32(0x24)) + attr(2, b'WRONGLEN\0') + attr(3, u16(1)) + attr(4, u32(0) + u32(0)) + attr(5, u16(3))),
    'attributes with the wrong length: ID 4 octets, VERSION 2, HDRSIZE 8, MAXATTR 2')
add(msg(CTRL, 1, newfam(0x25, b'OPSFAM', attr(6, ops_array([(None, None), (1, None), (None, 0x1f)]) + attr(9, b'abcd')) +
        attr(7, grp_array([(None, None), (b'name only\0', None), (None, 9)])))), 'ops and groups with missing sub-attributes')
add(msg(CTRL, 1, attr(6, attr(1, attr(1, u16(1)) + attr(2, u16(2))) + attr(2, attr(1, b'ab') + attr(2, b'abc'))) +
        attr(7, attr(1, attr(1, b'g\0') + attr(2, u16(3))) )), 'op id and flags, group id with the wrong length')
add(msg(CTRL, 1, attr(0, b'abcd') + attr(8, b'pol1') + attr(9, b'pol2') + attr(10, b'op12') + attr(11, b'unk1') + attr(0x1234, b'unk2') +
        attr(2, b'POLFAM\0') + attr(1, u16(0x26))), 'UNSPEC, POLICY, OP_POLICY, OP and unknown nlctrl attributes')
add(msg(CTRL, 1, attr(6, attr(0, b'abcd') + attr(1, attr(0, b'zzzz') + attr(3, b'tttt')))) , 'ops array with UNSPEC and unknown op attributes')
add(msg(CTRL, 1, attr(7, attr(1, attr(0, b'zzzz') + attr(3, b'tttt')))), 'groups array with UNSPEC and unknown group attributes')
# big endian
add(msg(CTRL, 1, newfam(0x30, b'BEFAM', attr(3, u32(1, True), True) + attr(6, ops_array([(1, 0x03)], True), True) +
        attr(7, grp_array([(b'bgrp\0', 4)], True), True), True), be=True), 'big endian NEWFAMILY 0x30 BEFAM')
add(msg(0x30, 1, b'be', 0, 30, be=True), 'big endian message of 0x30')
# a dissector reached through the family name
GENL_NETDM = 0x31
add(msg(CTRL, 1, newfam(GENL_NETDM, b'NET_DM')), 'NEWFAMILY 0x31 NET_DM')
add(msg(GENL_NETDM, 5, attr(1, u32(1)) + attr(2, u32(2)) , 0, 31), 'NET_DM message (family dissector)')
add(msg(GENL_NETDM, 1, b'', 0, 32), 'NET_DM message, header only')
# a family name that is not NUL terminated and long names
add(msg(CTRL, 1, attr(2, b'N' * 100) + attr(1, u16(0x32))), 'NEWFAMILY with a long name without NUL')
add(msg(0x32, 1, b'nn', 0, 33), 'message of the long-named family')
# multicast NEWFAMILY style: two messages in one frame
frames.append(cooked() + msg(CTRL, 1, newfam(0x33, b'TWO'), 2, 40) + msg(0x33, 1, b'q', 2, 41) + msg(CTRL, 1, newfam(0x34, b'THREE'), 2, 42) + msg(0x34, 1, b'r', 2, 43))
marks.append((len(frames), 'two NEWFAMILY and two family messages in one frame'))

pcap(os.path.join(sys.argv[1], 'netlink-generic-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, l in marks: print(n, l)
    print(len(frames), 'frames')

mal = []
def madd(m): mal.append(cooked() + m)
madd(msg(CTRL, 1, raw=b'\x01\x02'))                                  # genl header cut
madd(msg(CTRL, 1, attr(6, struct.pack('<HH', 0xffff, 1))[:4]))       # nested ops attribute cut
madd(msg(CTRL, 1, struct.pack('<HH', 8, 2) + b'ab'))                 # attribute longer than the frame
madd(msg(CTRL, 1, attr(6, struct.pack('<HH', 4, 1) + b'\x02\x00')))  # short ops sub attribute
madd(msg(CTRL, 1, attr(7, attr(1, struct.pack('<HH', 9, 1) + b'x'))))
madd(msg(0x21, 1, raw=b''))                                          # no genl header at all
madd(msg(0x21, 0, raw=b'\x01\x02'))                                    # mapped family, cut genl header
madd(msg(CTRL, 1, attr(1, u16(0x40)) + b'\x01'))
pcap(os.path.join(sys.argv[1], 'netlink-generic-coverage-malformed.pcap'), mal)

# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the netlink-ovs_* coverage generators (copied into
# each directory). Frames are LINKTYPE_NETLINK (253): 16 octet cooked
# header (hatype 824), netlink message header, generic netlink header,
# OVS header (dp_ifindex) and attributes. Every frame is synthetic.
import struct
import sys
import os

LE = '<'
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000


def sll(proto=16):
    return struct.pack('>HHH8sH', 4, 824, 0, b'\0' * 8, proto)


def nla(t, payload=b'', flags=0):
    l = 4 + len(payload)
    return struct.pack(LE + 'HH', l, t | flags) + payload + b'\0' * ((4 - l % 4) % 4)


def nest(t, *children, flags=NLA_F_NESTED):
    return nla(t, b''.join(children), flags)


def nlmsg(t, payload, pid=0, seq=1, flags=0):
    return struct.pack(LE + 'IHHII', 16 + len(payload), t, flags, seq, pid) + payload


def genl(cmd, payload, version=1):
    return struct.pack(LE + 'BBH', cmd, version, 0) + payload


def u8(v): return struct.pack('B', v)
def u16(v): return struct.pack(LE + 'H', v)
def u32(v): return struct.pack(LE + 'I', v)
def i32(v): return struct.pack(LE + 'i', v)
def u64(v): return struct.pack(LE + 'Q', v)
def be16(v): return struct.pack('>H', v)
def be32(v): return struct.pack('>I', v)
def be64(v): return struct.pack('>Q', v)
def cstr(s): return s.encode() + b'\0'


def family(fid, name):
    attrs = nla(1, u16(fid)) + nla(2, cstr(name))
    return sll() + nlmsg(0x10, genl(1, attrs))


def gmsg(fid, cmd, body, ifindex=1, pid=0, seq=1, flags=0):
    """Generic netlink message of family fid with the OVS header."""
    return sll() + nlmsg(fid, genl(cmd, i32(ifindex) + body), pid=pid, seq=seq, flags=flags)


def rawmsg(fid, cmd, payload, pid=0):
    """Generic netlink message with arbitrary bytes after the genl header."""
    return sll() + nlmsg(fid, genl(cmd, payload), pid=pid)


def pcap(frames, fn):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)) + fr)


def chain(t, depth, leaf=b''):
    inner = leaf
    for _ in range(depth):
        inner = struct.pack(LE + 'HH', 4 + len(inner), t) + inner
    return inner


def write(name, main, mal, outdir):
    os.makedirs(outdir, exist_ok=True)
    pcap(main, os.path.join(outdir, name + '-coverage.pcap'))
    pcap(mal, os.path.join(outdir, name + '-coverage-malformed.pcap'))
    print('%s: main %d frames, malformed %d frames' % (name, len(main), len(mal)))


def raw(t, payload=b''):
    """Attribute without the padding to 4 octets: at the very end of a
    frame the field read by a handler runs past the data (exception)."""
    return struct.pack(LE + 'HH', 4 + len(payload), t) + payload

#!/usr/bin/env python3
# Generates test/captures/pcnfsd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pcnfsd.c. usage: mkpcnfsd.py <outdir>
#
# PC-NFS (ONC RPC program 150001, versions 1 and 2) over UDP; the RPC
# dissector finds it by its heuristic (no port needed).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import gz, udp, udp6, write_pcap

out = sys.argv[1]
PROG = 150001

def xs(b):
    if isinstance(b, str): b = b.encode('latin-1')
    return struct.pack('!I', len(b)) + b + b'\0' * (-len(b) % 4)

def obscure(s):
    '''PC-NFS "obscure" of a string: XOR 0x5b of the ASCII bytes'''
    return bytes((c ^ 0x5b) if c < 0x80 else c for c in (s.encode('latin-1') if isinstance(s, str) else s))

def call(xid, vers, proc, args=b''):
    return struct.pack('!IIIIII', xid, 0, 2, PROG, vers, proc) + struct.pack('!IIII', 0, 0, 0, 0) + args

def reply(xid, results=b''):
    return struct.pack('!IIIIII', xid, 1, 0, 0, 0, 0) + results

def rlist(items):
    '''XDR list: value-follows 1 + item for each, then 0'''
    return b''.join(struct.pack('!I', 1) + i for i in items) + struct.pack('!I', 0)

frames = []
xid = [0x1000]
def rpc(sport, vers, proc, args=b'', res=b'', dport=40001, reply_too=True):
    xid[0] += 1
    frames.append(udp(sport, dport, call(xid[0], vers, proc, args)))
    if reply_too:
        frames.append(udp(dport, sport, reply(xid[0], res), src='192.0.2.2', dst='192.0.2.1'))

# version 1 (procedures AUTH/PR_INIT/PR_START are dissected as unknown)
rpc(31000, 1, 0)
rpc(31000, 1, 1, xs('host') + xs(obscure('alice')) + xs(obscure('secret')))
rpc(31000, 1, 2, xs('printer'))
rpc(31000, 1, 3, xs('lp') + xs('file'))
# version 2: NULL and procedures without argument dissectors
rpc(31001, 2, 0)
for proc in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14):
    rpc(31001, 2, proc, struct.pack('!II', proc, 0x11223344))

# MAPID: request list (uid, gid, uname, gname lookups) and the replies
reqs = [struct.pack('!II', 0, 1000) + xs(''), struct.pack('!II', 1, 100) + xs(''),
        struct.pack('!II', 2, 0) + xs('alice'), struct.pack('!II', 3, 0) + xs('staff')]
res = [struct.pack('!III', 0, 0, 1000) + xs('alice'), struct.pack('!III', 1, 0, 100) + xs('staff'),
       struct.pack('!III', 2, 1, 0) + xs(''), struct.pack('!III', 3, 2, 0) + xs('staff')]
rpc(31002, 2, 12, xs('mapid comment') + rlist(reqs), xs('reply comment') + rlist(res))
rpc(31002, 2, 12, xs('') + rlist([]), xs('') + rlist([]))

# AUTH: obscured ident and password, an empty password, a non-ASCII byte
def auth(client, ident, pw, comment):
    return xs(client) + xs(ident) + xs(pw) + xs(comment)
def auth_res(status, uid, gid, gids, home, umask, comment):
    return (struct.pack('!IIII', status, uid, gid, len(gids)) +
            b''.join(struct.pack('!I', g) for g in gids) + xs(home) +
            struct.pack('!I', umask) + xs(comment))
rpc(31003, 2, 13, auth('client1', obscure('alice'), obscure('p4ssw0rd!'), 'login'),
    auth_res(0, 1000, 100, [100, 10, 20], '/home/alice', 0o22, 'ok'))
# empty password: the dissector adds the text "<EMPTY>" as a 7 byte item over the
# bytes that follow, so a comment follows (empty ones are in the malformed capture)
rpc(31003, 2, 13, auth('client2', obscure('bob'), b'', 'comment of bob'),
    auth_res(1, 0, 0, [], '', 0o77, ''))
rpc(31003, 2, 13, auth('client3', b'', obscure('x'), 'empty ident'),
    auth_res(0, 1001, 100, [100], '/home/b', 0o2, 'second'))
# '[' obscures to NUL: the obscured string has an internal NUL
rpc(31003, 2, 13, auth('client4', obscure('a[b'), obscure('[['), 'nul'),
    auth_res(0, 1002, 100, [7], '/h', 0o22, 'nul'))
# a byte with the high bit set is not changed by the obscuring
rpc(31003, 2, 13, auth('client5', b'\xc3\xa9\x30', b'\xff\x01', 'high bit'),
    auth_res(0, 1003, 100, [8, 9], '/h', 0o22, 'high'))
# call without reply (reply seen from the other side only)
rpc(31004, 2, 13, auth('client6', obscure('carol'), obscure('pw'), ''), reply_too=False)
rpc(31004, 2, 12, xs('only call') + rlist(reqs[:1]), reply_too=False)
# IPv6 transport
xid[0] += 1
frames.append(udp6(31005, 40001, call(xid[0], 2, 13, auth('c7', obscure('dave'), obscure('pw'), 'v6'))))
frames.append(udp6(40001, 31005, reply(xid[0], auth_res(0, 1004, 100, [1], '/h6', 0o22, 'v6')),
                   src='2001:db8::2', dst='2001:db8::1'))
write_pcap(out + '/pcnfsd-coverage.pcap', frames)

frames = []
xid[0] = 0x2000
# malformed: an empty password or ident with nothing after it: the 7 byte
# "<EMPTY>" item runs past the end of the data
rpc(31009, 2, 13, auth('client2', obscure('bob'), b'', ''), reply_too=False)
rpc(31009, 2, 13, xs('c') + xs(b'') + xs(b'') + xs(''), reply_too=False)
# malformed: truncated arguments and results, a huge group count
a = auth('client1', obscure('alice'), obscure('secret'), 'c')
for cut in (0, 3, 8, 16, 24, 32):
    rpc(31010, 2, 13, a[:cut], reply_too=False)
r = auth_res(0, 1000, 100, [100, 10], '/home/alice', 0o22, 'ok')
for cut in (0, 4, 12, 16, 20, 30):
    rpc(31010, 2, 13, a, r[:cut])
rpc(31011, 2, 13, a, auth_res(0, 1, 2, [], '/h', 0, 'x')[:12] + struct.pack('!I', 0x7fffffff) + b'\0' * 8)
rpc(31011, 2, 13, a, struct.pack('!IIII', 0, 1, 2, 0x20000000) + b'\0' * 16)
rpc(31011, 2, 13, a, struct.pack('!IIII', 0, 1, 2, 0xffffffff) + b'\0' * 16)
m = xs('c') + rlist(reqs)
for cut in (0, 4, 8, 12, 16, 24, 30):
    rpc(31012, 2, 12, m[:cut], (xs('c') + rlist(res))[:cut])
rpc(31012, 2, 12, xs('c') + struct.pack('!I', 1) + struct.pack('!II', 5, 0) + xs('n'), reply_too=False)
write_pcap(out + '/pcnfsd-coverage-malformed.pcap', frames)
gz(out + '/pcnfsd-coverage.pcap')
print('ok')

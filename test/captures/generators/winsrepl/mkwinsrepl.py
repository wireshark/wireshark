#!/usr/bin/env python3
# Generates test/captures/winsrepl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the WINS-Replication dissector
(packet-winsrepl.c) on TCP port 42.

Usage: mkwinsrepl.py <output directory> [-v]
Writes winsrepl-coverage.pcap (main) and winsrepl-coverage-malformed.pcap.
Every packet is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys
from pcaplib import pcap, Tcp

def ip(s):
    return bytes(int(x) for x in s.split('.'))

def pdu(mtype, body, opcode=0x00008000, ctx=0x1000, size=None):
    rest = struct.pack('>III', opcode, ctx, mtype) + body
    return struct.pack('>I', len(rest) if size is None else size) + rest

def start(ctx, minor=2, major=5):
    return struct.pack('>IHH', ctx, minor, major)

def owner(addr, maxv, minv, typ):
    return ip(addr) + struct.pack('>QQI', maxv, minv, typ)

def repl(cmd, body=b''):
    return struct.pack('>I', cmd) + body

def table_reply(owners, initiator='192.0.2.1', count=None):
    return struct.pack('>I', len(owners) if count is None else count) + b''.join(owners) + ip(initiator)

def nbname(name, typ, scope=b''):
    return name.encode().ljust(15, b' ') + bytes([typ]) + scope

def wname(pre, name, flags, group, vers, addrs, unknown='0.0.0.0', name_len=None):
    """A WINS name record. pre is the length of the PDU before it (to
    compute the 4-byte alignment padding)."""
    b = struct.pack('>I', len(name) if name_len is None else name_len) + name
    n = pre + len(b)
    b += b'\0' * (4 - (n & 3))
    b += struct.pack('>I', flags) + struct.pack('<I', group) + struct.pack('>Q', vers)
    typ = flags & 3
    if typ in (0, 1):
        b += ip(addrs[0])
    else:
        b += struct.pack('<I', len(addrs)) + b''.join(ip(o) + ip(a) for o, a in addrs)
    return b + ip(unknown)

def send_reply(names_fn, count=None):
    """names_fn: list of callables taking the offset of the record in the PDU."""
    body = b''
    # PDU header: size, opcode, ctx, mtype = 16; repl cmd 4; num names 4
    off = 24
    recs = b''
    for fn in names_fn:
        r = fn(off + len(recs))
        recs += r
    return repl(3, struct.pack('>I', len(names_fn) if count is None else count) + recs)

main, labels = [], []
def mark(label):
    labels.append((len(main) + 1, label))

c = Tcp(34567, 42)
mark('handshake'); main += c.handshake()
mark('start association, reply');
main += c.send(pdu(0, start(0x1111)), True)
main += c.send(pdu(1, start(0x2222, 2, 5), ctx=0x1111), False)
mark('table query, table reply with 0, 1 and 3 owners')
main += c.send(pdu(3, repl(0), ctx=0x2222), True)
main += c.send(pdu(3, repl(1, table_reply([])), ctx=0x1111), False)
o3 = [owner('192.0.2.10', 5000, 1, 0), owner('192.0.2.11', 123456789012, 77, 1), owner('198.51.100.7', 9, 0, 2)]
main += c.send(pdu(3, repl(0), ctx=0x2222), True)
main += c.send(pdu(3, repl(1, table_reply(o3)), ctx=0x1111), False)
mark('send request, send reply with every name type')
main += c.send(pdu(3, repl(2, owner('192.0.2.10', 5000, 1, 0)), ctx=0x2222), True)

def rec(name, flags, group, vers, addrs, unknown='0.0.0.0', name_len=None):
    return lambda pre: wname(pre, name, flags, group, vers, addrs, unknown, name_len)

N = nbname('SERVER', 0x20)
names = [
    rec(nbname('SERVER', 0x20), 0x00, 0, 1001, ['192.0.2.10']),                      # unique, active, B-node
    rec(nbname('WORKGROUP', 0x00), 0x01, 1, 1002, ['192.0.2.11'], '192.0.2.99'),     # normal group
    rec(nbname('DOMAIN', 0x1c), 0x02 | 0x04 | 0x10 | 0x20, 1, 1003,
        [('192.0.2.10', '192.0.2.20'), ('192.0.2.10', '192.0.2.21')]),               # special group, released, local, P-node
    rec(nbname('MULTIHOME', 0x00), 0x03 | 0x08 | 0x40 | 0x80, 0, 1004,
        [('192.0.2.12', '198.51.100.1'), ('192.0.2.12', '198.51.100.2'), ('192.0.2.12', '198.51.100.3')]),  # multihomed, tombstoned, M-node, static
    rec(nbname('DELETED', 0x03), 0x0c | 0x60, 0, 1005, ['192.0.2.13']),              # unique, deleted, H-node
    rec(nbname('SCOPED', 0x20, b'\x05scope\x03com\x00'), 0x00, 0, 1006, ['192.0.2.14']),  # name with a scope part
    rec(nbname('ALIGNED', 0x1b, b'\x00\x00\x00'), 0x00, 0, 1007, ['192.0.2.15']),           # already 4-byte aligned after the name
    rec(nbname('NOADDR', 0x1d), 0x02, 1, 1008, []),                                  # special group with 0 addresses
]
mark('send reply with the 8 names above')
main += c.send(pdu(3, send_reply(names), ctx=0x1111), False)
mark('send reply with 0 names, with 1 name')
main += c.send(pdu(3, send_reply([]), ctx=0x1111), False)
main += c.send(pdu(3, send_reply([names[0]]), ctx=0x1111), False)
mark('update, update2, inform, inform2')
for cmd in (4, 5, 8, 9):
    main += c.send(pdu(3, repl(cmd, table_reply(o3[:2], '192.0.2.50')), ctx=0x2222), True)
mark('unknown replication command 6 (no decoding after it)')
main += c.send(pdu(3, repl(6, b'\0' * 8), ctx=0x2222), True)
mark('unknown message type 9')
main += c.send(pdu(9, b'\0' * 4, ctx=0x2222), True)
mark('two PDUs in one segment')
main += c.send(pdu(3, repl(0), ctx=0x2222) + pdu(3, repl(0), ctx=0x2222), True)
mark('send reply split over three segments (reassembly)')
big = pdu(3, send_reply(names), ctx=0x1111)
for i in range(0, len(big), 150):
    main += c.send(big[i:i + 150], False)[:-1]
main += [c._seg(True, 0x10)]
mark('stop association')
main += c.send(pdu(2, struct.pack('>I', 4), ctx=0x2222), True)
main += c.fin()

# A second connection to a non-default client port with a start from the other side
c2 = Tcp(34600, 42, src='192.0.2.3', dst='192.0.2.4')
mark('second connection: start, stop with reason 0')
main += c2.handshake()
main += c2.send(pdu(0, start(0x3333, 0, 0), ctx=0), True)
main += c2.send(pdu(1, start(0x4444, 1, 2), ctx=0x3333), False)
main += c2.send(pdu(2, struct.pack('>I', 0), ctx=0x4444), True)
main += c2.fin()
nmain = len(main)

mal = []
cm = Tcp(34700, 42, src='192.0.2.5', dst='192.0.2.6')
mal += cm.handshake()
# name_len 0: expert, returns
mal += cm.send(pdu(3, repl(3, struct.pack('>I', 1) + struct.pack('>I', 0)), ctx=1), False)
# name_len 8: shorter than a NetBIOS name
mal += cm.send(pdu(3, repl(3, struct.pack('>I', 1) + struct.pack('>I', 8) + b'ABCDEFGH' + bytes(32)), ctx=1), False)
# name_len huge (fuzzed): the bytes do not exist
mal += cm.send(pdu(3, repl(3, struct.pack('>I', 1) + struct.pack('>I', 0x7fffffff) + nbname('HUGE', 0) + bytes(40)), ctx=1), False)
# many names announced, few present
mal += cm.send(pdu(3, repl(3, struct.pack('>I', 100000) + wname(24, nbname('ONE', 0), 0, 0, 1, ['192.0.2.1'])), ctx=1), False)
# partner count larger than the PDU
mal += cm.send(pdu(3, repl(1, struct.pack('>I', 50000) + owner('192.0.2.1', 1, 1, 0)), ctx=1), False)
# special group with a huge address count
mal += cm.send(pdu(3, repl(3, struct.pack('>I', 1) + wname(24, nbname('GRP', 0x1c), 0x02, 1, 1, [])[:-8]
                           + struct.pack('<I', 0xffffffff) + bytes(8)), ctx=1), False)
# truncated PDUs: header only, stop without reason, start cut, command cut
mal += cm.send(pdu(3, b''), True)
mal += cm.send(pdu(2, b''), True)
mal += cm.send(pdu(0, b'\0\0\0\1\0'), True)
mal += cm.send(pdu(3, b'\0\0'), True)
mal += cm.send(pdu(3, repl(2, bytes(10))), True)
# size field smaller than the header
mal += cm.send(struct.pack('>III', 4, 0, 0) + b'xx', True)
# size field larger than the data (PDU never completes)
mal += cm.send(pdu(3, repl(0), size=2000), False)

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
pcap(os.path.join(out, 'winsrepl-coverage.pcap'), main)
pcap(os.path.join(out, 'winsrepl-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, l in labels: print(n, l)
    print('main', nmain, 'malformed', len(mal))

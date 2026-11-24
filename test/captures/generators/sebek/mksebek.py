#!/usr/bin/env python3
# Generates test/captures/sebek_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SEBEK coverage captures: mksebek.py <outdir> [-v].  All data is synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import socket
import struct
from c17lib import Cap, udp

MAGIC = 0xd0d0d0d0

def ip(s):
    return socket.inet_aton(s)

def v2(typ=1, counter=1, pid=100, uid=0, fd=1, cmd=b'bash', data=b'ls -l\n', length=None, ver=2):
    if length is None:
        length = len(data)
    return (struct.pack('>IHHIIIIII', MAGIC, ver, typ, counter, 1700000000 + counter, 250000, pid, uid, fd)
            + cmd.ljust(12, b'\0')[:12] + struct.pack('>I', length) + data)

def v3(typ=0, counter=1, ppid=1, pid=200, uid=1000, fd=0, inode=4242, cmd=b'sshd', data=b'secret\n', length=None, ver=3):
    if length is None:
        length = len(data)
    return (struct.pack('>IHHIIIIIIII', MAGIC, ver, typ, counter, 1700000000 + counter, 500000, ppid, pid, uid, fd, inode)
            + cmd.ljust(12, b'\0')[:12] + struct.pack('>I', length) + data)

def sock(dst='198.51.100.7', dport=22, src='192.0.2.2', sport=40022, call=3, proto=6):
    return ip(dst) + struct.pack('>H', dport) + ip(src) + struct.pack('>HHB', sport, call, proto)

def send(c, payload, dport=1101):
    c.add(udp(1101, dport, payload, '192.0.2.77', '192.0.2.255'))

def main(out, verbose=False):
    c = Cap(1)
    c.mark('Version 2 records: read and write types, command with a NUL, a 12 character command, empty data')
    send(c, v2(1, 1))
    send(c, v2(0, 2, cmd=b'cat', data=b'passwd\n', uid=33, fd=4))
    send(c, v2(1, 3, cmd=b'123456789012', data=b'x'))
    send(c, v2(1, 4, cmd=b'', data=b'.'))
    c.mark('Version 3 records: data, a command of 12 characters without NUL, empty command')
    send(c, v3(0, 5))
    send(c, v3(1, 6, cmd=b'abcdefghijkl', data=b'typed text'))
    send(c, v3(0, 7, cmd=b'', data=b'.'))
    c.mark('Version 3 socket records (type 2) for connect, bind and others')
    for i, call in enumerate((1, 2, 3, 4, 5)):
        send(c, v3(2, 8 + i, cmd=b'nc', data=sock(call=call, proto=(6, 17, 1, 6, 17)[i]), fd=3 + i))
    c.mark('Unknown version, a datagram shorter than the version field and a one octet datagram')
    send(c, v2(1, 20, ver=7))
    send(c, b'\xd0\xd0\xd0\xd0')
    send(c, b'\0')

    m = Cap(1)
    m.mark('Records without data (the data item has no octets left: exceptions with a tree) and truncated records')
    send(m, v2(1, 39, data=b''))
    send(m, v3(0, 40, data=b''))
    full2 = v2(1, 40)
    full3 = v3(0, 41)
    for n in (8, 20, 33, 43, 47):
        send(m, full2[:n])
    for n in (8, 26, 41, 45, 55, 59):
        send(m, full3[:n])
    s = v3(2, 42, data=sock())
    for n in (len(s) - 1, len(s) - 3, len(s) - 7, len(s) - 12):
        send(m, s[:n])

    c.write(os.path.join(out, 'sebek-coverage.pcap'))
    m.write(os.path.join(out, 'sebek-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

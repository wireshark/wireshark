#!/usr/bin/env python3
# Generates test/captures/netdump_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Netdump (Linux netdump/diskdump over UDP) captures.
# Usage: mknetdump.py <outdir> [-v]
# Netdump has no registered port; the captures use UDP 6666 and are
# dissected with Decode As (-d udp.port==6666,netdump).
import struct
import sys
import os

MAGIC = 0x0000000a4e455444   # arbitrary 8 octet magic number

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def ip_udp(payload, src='192.0.2.10', dst='192.0.2.20', sport=6666, dport=6666):
    def a(s): return bytes(int(x) for x in s.split('.'))
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0) + a(src) + a(dst)
    s = sum(struct.unpack('>10H', ip)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + udp

def req(seq, cmd, frm, to, magic=MAGIC):
    return struct.pack('>QIIII', magic, seq, cmd, frm, to)

def reply(version, seq, code, info, payload=b''):
    return struct.pack('>BII', version, seq, code) + struct.pack('<I', info) + payload

frames = []; marks = []
def add(p, label):
    frames.append(ip_udp(p) if not isinstance(p, tuple) else ip_udp(*p))
    marks.append((len(frames), label))

# requests (24 octets): every command, plus one unknown
for cmd, nm in enumerate(('COMM_NONE', 'COMM_SEND_MEM', 'COMM_EXIT', 'COMM_REBOOT', 'COMM_HELLO',
                          'COMM_GET_NR_PAGES', 'COMM_GET_PAGE_SIZE', 'COMM_START_NETDUMP_ACK',
                          'COMM_GET_REGS', 'COMM_SHOW_STATE')):
    add(req(cmd + 1, cmd, 0x1000 * cmd, 0x1000 * cmd + 0xfff), 'Request ' + nm)
add(req(0x7fffffff, 99, 0xffffffff, 0), 'Request, unknown command 99')
add(req(0xffffffff, 1, 0, 0xffffffff, magic=0xffffffffffffffff), 'Request, all-ones magic')
# replies: every code, with and without payload
for code, nm in enumerate(('REPLY_NONE', 'REPLY_ERROR', 'REPLY_LOG', 'REPLY_MEM', 'REPLY_RESERVED',
                           'REPLY_HELLO', 'REPLY_NR_PAGES', 'REPLY_PAGE_SIZE', 'REPLY_START_NETDUMP',
                           'REPLY_END_NETDUMP', 'REPLY_REGS', 'REPLY_MAGIC', 'REPLY_SHOW_STATE')):
    add(reply(1, code + 100, code, 0x01020304 + code, b'payload for ' + nm.encode()), 'Reply ' + nm)
add(reply(2, 0xffffffff, 77, 0xffffffff, bytes(range(256)) * 4), 'Reply, unknown code, 1024 octet payload')
add(reply(0, 5, 3, 0x1000, b'\x00' * 23), 'Reply, 36 octets (not a request)')
add(reply(0, 5, 3, 0x1000, b'\x00' * 12), 'Reply, 25 octets')
# a request-sized reply is shown as a request (24 octets); a longer request is a reply
add(req(1, 4, 0, 0) + b'\x00', 'Request with one extra octet is a reply')
# other port, same dissector through another Decode As
frames.append(ip_udp(req(9, 5, 0, 0), sport=1234, dport=6667)); marks.append((len(frames), 'Request on UDP 6667 (Decode As)'))

pcap(os.path.join(sys.argv[1], 'netdump-coverage.pcap'), frames)
if '-v' in sys.argv:
    for n, l in marks: print(n, l)
    print(len(frames), 'frames')

# malformed: replies shorter than the 13 octet header and a reply without payload
mal = []
for n in (1, 5, 9, 12):
    mal.append(ip_udp(bytes(range(n))))
mal.append(ip_udp(bytes(23)))
# a reply with the 13 octet header and no payload: the payload item at the end of the data is an exception
mal.append(ip_udp(reply(1, 1, 0, 0)))
pcap(os.path.join(sys.argv[1], 'netdump-coverage-malformed.pcap'), mal)

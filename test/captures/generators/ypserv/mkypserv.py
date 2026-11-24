#!/usr/bin/env python3
# Generates test/captures/ypserv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the YPSERV coverage captures with struct only (nothing is captured).
# Usage: mkypserv.py <outdir>
#   ypserv-coverage.pcap            ONC RPC over UDP and TCP (program 100004),
#                                   reached by the default RPC heuristics
#   ypserv-coverage-malformed.pcap  truncated calls and replies
import struct
import sys
import os

C_IP, S_IP = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(proto, payload, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + payload

def udp_frame(src, dst, sport, dport, payload):
    return ip4(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload, src, dst)

def tcp_frame(src, dst, sport, dport, seq, payload, ack=1, flags=0x18):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return ip4(6, t, src, dst)

def xstr(s):
    s = s.encode() if isinstance(s, str) else s
    return struct.pack('!I', len(s)) + s + b'\0' * ((4 - len(s) % 4) % 4)

def call(xid, prog, vers, proc, args):
    return struct.pack('!IIIIIIIIII', xid, 0, 2, prog, vers, proc, 0, 0, 0, 0) + args

def reply(xid, res):
    return struct.pack('!IIIIII', xid, 1, 0, 0, 0, 0) + res

def rm(payload):
    return struct.pack('!I', 0x80000000 | len(payload)) + payload

class Conv:
    """Builds call/reply frames over UDP or TCP (with a handshake) with increasing xids."""
    def __init__(self, prog, frames, tcp=False, port=800, cport=40000):
        self.prog, self.frames, self.tcp = prog, frames, tcp
        self.port, self.cport = port, cport
        self.xid = 0x1000
        self.seq = {0: 1001, 1: 9001}
        if tcp:
            frames.append(tcp_frame(C_IP, S_IP, cport, port, 1000, b'', 0, 0x02))
            frames.append(tcp_frame(S_IP, C_IP, port, cport, 9000, b'', 1001, 0x12))
            frames.append(tcp_frame(C_IP, S_IP, cport, port, 1001, b'', 9001, 0x10))
    def _send(self, payload, from_server):
        if self.tcp:
            payload = rm(payload)
            d = 1 if from_server else 0
            s = self.seq[d]
            self.seq[d] += len(payload)
            if from_server:
                self.frames.append(tcp_frame(S_IP, C_IP, self.port, self.cport, s, payload, self.seq[0]))
            else:
                self.frames.append(tcp_frame(C_IP, S_IP, self.cport, self.port, s, payload, self.seq[1]))
        else:
            if from_server:
                self.frames.append(udp_frame(S_IP, C_IP, self.port, self.cport, payload))
            else:
                self.frames.append(udp_frame(C_IP, S_IP, self.cport, self.port, payload))
    def call(self, vers, proc, args=b''):
        self.xid += 1
        self._send(call(self.xid, self.prog, vers, proc, args), False)
    def reply(self, res=b''):
        self._send(reply(self.xid, res), True)
    def pair(self, vers, proc, args=b'', res=b''):
        self.call(vers, proc, args)
        self.reply(res)
    def call_only(self, vers, proc, args=b''):
        self.call(vers, proc, args)

PROG = 100004
(NULL, DOMAIN, DOMAIN_NONACK, MATCH, FIRST, NEXT, XFR, CLEAR, ALL, MASTER,
 ORDER, MAPLIST) = range(12)

def i32(v): return struct.pack('!i', v)
def u32(v): return struct.pack('!I', v)

YPSTAT = [1, 2, 0, -1, -2, -3, -4, -5, -6, -7, -8]       # all named statuses
XFRSTAT = [1, 2] + list(range(-1, -15, -1))              # all named transfer statuses

def sequence(c, full=True):
    d, m, k = xstr('example.org'), xstr('passwd.byname'), xstr('alice')
    # version 2
    c.pair(2, NULL)
    c.pair(2, DOMAIN, d, u32(1))
    c.pair(2, DOMAIN, xstr('other'), u32(0))
    c.pair(2, DOMAIN_NONACK, d, u32(1))
    c.pair(2, MATCH, d + m + k, i32(1) + xstr('alice:x:1000:1000:Alice:/home/alice:/bin/sh'))
    c.pair(2, MATCH, d + m + xstr('nobody'), i32(-3) + xstr(''))
    c.pair(2, FIRST, d + m, i32(1) + xstr('first value') + xstr('first key'))
    c.pair(2, NEXT, d + m + k, i32(1) + xstr('next value') + xstr('next key'))
    c.pair(2, NEXT, d + m + xstr('last'), i32(-3) + xstr('') + xstr(''))
    c.pair(2, XFR, d + m + u32(0x5f000000) + xstr('nis-master.example.org') +
           u32(0x12345678) + u32(0x40000000) + u32(861), u32(0x12345678) + i32(1))
    c.pair(2, CLEAR, b'', b'')
    # the RPC layer calls the procedure dissector only if there is data
    c.pair(2, CLEAR, u32(0), u32(0))
    c.pair(2, ALL, d + m,
           u32(1) + i32(1) + xstr('value one') + xstr('key one') +
           u32(1) + i32(1) + xstr('value two') + xstr('key two') +
           u32(1) + i32(1) + xstr('') + xstr('key three') +
           u32(0))
    c.pair(2, ALL, d + xstr('empty.map'), u32(0))
    c.pair(2, MASTER, d + m, i32(1) + xstr('nis-master.example.org'))
    c.pair(2, ORDER, d + m, i32(1) + u32(0x5f123456))
    c.pair(2, MAPLIST, d,
           i32(1) + u32(1) + xstr('passwd.byname') + u32(1) + xstr('hosts.byname') +
           u32(1) + xstr('group.byname') + u32(0))
    c.pair(2, MAPLIST, xstr('emptydom'), i32(1) + u32(0))
    if not full:
        return
    # every named status in a MATCH reply (negative ones have an error)
    for st in YPSTAT:
        c.pair(2, MATCH, d + m + k, i32(st) + xstr('v' if st >= 0 else ''))
    c.pair(2, MATCH, d + m + k, i32(-99) + xstr(''))              # unknown negative status
    for st in (-1, -2, -6):
        c.pair(2, FIRST, d + m, i32(st) + xstr('') + xstr(''))
    for st in (-1, -5):
        c.pair(2, MASTER, d + m, i32(st) + xstr(''))
    for st in (-1, -3):
        c.pair(2, ORDER, d + m, i32(st) + u32(0))
    c.pair(2, MAPLIST, xstr('nodomain'), i32(-2) + u32(0))
    c.pair(2, ALL, d + xstr('nomap'), u32(1) + i32(-1) + xstr('') + xstr('') + u32(0))
    # every named transfer status in an XFR reply, and an unknown one
    for st in XFRSTAT + [-99]:
        c.pair(2, XFR, d + m + u32(1) + xstr('peer') + u32(7) + u32(0x40000000) + u32(1023),
               u32(7) + i32(st))
    # version 1: the procedures are not decoded
    c.pair(1, NULL)
    for proc in range(1, 12):
        c.pair(1, proc, d + m, u32(1))

def main(out):
    F = []
    sequence(Conv(PROG, F), full=True)                                 # UDP
    sequence(Conv(PROG, F, tcp=True, port=1023), full=False)           # TCP
    pcap(os.path.join(out, 'ypserv-coverage.pcap'), F)

    M = []
    c = Conv(PROG, M)
    d, m, k = xstr('example.org'), xstr('passwd.byname'), xstr('alice')
    c.pair(2, DOMAIN, d, b'')                                          # no reply data
    c.pair(2, DOMAIN, b'', u32(1))                                     # no domain
    c.pair(2, DOMAIN, struct.pack('!I', 5000) + b'abc', u32(1))        # domain longer than the call
    c.pair(2, MATCH, d + m, i32(1) + struct.pack('!I', 5000) + b'ab')  # key missing, value too long
    c.pair(2, MATCH, d, b'')
    c.pair(2, FIRST, d, i32(1) + xstr('v'))                            # key missing
    c.pair(2, NEXT, d + m, i32(-1))                                    # value and key missing
    c.pair(2, XFR, d + m + u32(1), u32(1))                             # call cut in the peer, reply cut
    c.pair(2, XFR, d + m + u32(1) + xstr('p') + u32(1) + u32(2), b'')  # call cut in the port
    c.pair(2, ALL, d + m, u32(1) + i32(1) + xstr('v'))                 # entry cut in the key
    c.pair(2, ALL, d + m, u32(1))                                      # entry cut in the status
    c.pair(2, ALL, d, b'')                                             # map missing, empty reply
    c.pair(2, MASTER, d + m, i32(1))                                   # peer missing
    c.pair(2, ORDER, d + m, i32(1))                                    # order number missing
    c.pair(2, ORDER, d, b'')
    c.pair(2, MAPLIST, d, i32(1) + u32(1) + xstr('map'))               # list not terminated
    c.pair(2, MAPLIST, d, i32(1) + u32(1) + struct.pack('!I', 900) + b'x')   # map name too long
    c.call_only(2, XFR, b'')
    pcap(os.path.join(out, 'ypserv-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/ypbind_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the YPBIND coverage captures with struct only (nothing is captured).
# Usage: mkypbind.py <outdir>
#   ypbind-coverage.pcap            ONC RPC over UDP and TCP (program 100007),
#                                   reached by the default RPC heuristics
#   ypbind-coverage-malformed.pcap  truncated calls and replies
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

PROG = 100007
ADDR = bytes([192, 0, 2, 10])

def succ(addr=ADDR, port=861):
    return struct.pack('!I', 1) + addr + struct.pack('!I', port)

def fail(err):
    return struct.pack('!II', 2, err)

def sequence(c):
    # version 2: DOMAIN with a successful reply and with every error code
    c.pair(2, 1, xstr('example.org'), succ())
    c.pair(2, 1, xstr('nis.example'), fail(1))
    c.pair(2, 1, xstr('missing'), fail(2))
    c.pair(2, 1, xstr('nomem'), fail(3))
    c.pair(2, 1, xstr('weird'), fail(99))
    # a response type that is neither SUCC_VAL nor FAIL_VAL
    c.pair(2, 1, xstr('badtype'), struct.pack('!I', 7))
    # SETDOMAIN: domain, server address, port, version
    c.pair(2, 2, xstr('example.org') + ADDR + struct.pack('!II', 861, 2))
    # NULL procedures
    c.pair(2, 0)
    c.pair(1, 0)
    # version 1: DOMAIN and SETDOMAIN are not decoded
    c.pair(1, 1, xstr('example.org'), succ())
    c.pair(1, 2, xstr('example.org') + ADDR + struct.pack('!II', 861, 1))

def main(out):
    F = []
    sequence(Conv(PROG, F))                       # UDP
    sequence(Conv(PROG, F, tcp=True, port=1023))  # TCP with record marking
    pcap(os.path.join(out, 'ypbind-coverage.pcap'), F)

    M = []
    c = Conv(PROG, M)
    c.pair(2, 1, xstr('example.org'), struct.pack('!I', 1))            # SUCC_VAL without address
    c.pair(2, 1, xstr('example.org'), struct.pack('!I', 1) + ADDR)     # no port
    c.pair(2, 1, xstr('example.org'), struct.pack('!I', 2))            # FAIL_VAL without error
    c.pair(2, 1, xstr('example.org'), b'')                             # empty reply
    c.pair(2, 1, struct.pack('!I', 5000) + b'abc')                     # domain longer than the call
    c.pair(2, 1, b'')                                                  # no domain
    c.pair(2, 2, xstr('example.org') + ADDR)                           # SETDOMAIN cut in the port
    c.pair(2, 2, xstr('example.org') + ADDR + struct.pack('!I', 861))  # cut in the version
    c.call_only(2, 2, b'')
    pcap(os.path.join(out, 'ypbind-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

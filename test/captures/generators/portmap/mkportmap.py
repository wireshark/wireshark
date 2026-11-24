#!/usr/bin/env python3
# Generates test/captures/portmap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Portmap / rpcbind coverage captures. Usage: mkportmap.py <outdir> [-v]
# Portmap is the ONC RPC program 100000 on UDP and TCP port 111 (default).
import os
import struct
import sys
from pcaplib import udp, write_pcap, Tcp

PM = 100000
NULL, SET, UNSET, GETPORT, DUMP, CALLIT = 0, 1, 2, 3, 4, 5
def u(*v): return struct.pack('>%dI' % len(v), *v)
def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return u(len(b)) + b + b'\0' * (-len(b) % 4)
def opaque(b): return xstr(b)

def call(xid, prog, vers, proc, args=b''):
    return u(xid, 0, 2, prog, vers, proc, 0, 0, 0, 0) + args
def reply(xid, res=b'', stat=0):
    return u(xid, 1, 0, 0, 0, stat) + res

def mapping(prog, vers, proto, port): return u(prog, vers, proto, port)
def rpcb(prog, vers, netid, addr, owner): return u(prog, vers) + xstr(netid) + xstr(addr) + xstr(owner)

def callit_args(prog, vers, proc, args=b''): return u(prog, vers, proc) + opaque(args)
def nested(vers, levels, xid):
    """A CALLIT in portmap version `vers` whose indirect call is again CALLIT,
    `levels` deep, and the reply that goes with it. The RPC library finds the
    indirect procedure of a reply through the first word of the reply data, so
    each reply level starts with the argument length of the call at that level
    (the port in version 2, the length of the universal address in version 3)."""
    if vers == 2:
        inners = [callit_args(PM, 2, GETPORT, mapping(100003, 3, 17, 0))]
        last_key, last = 16, u(2049)
    else:
        inners = [callit_args(100003, 3, 0)]
        last_key, last = 0, b''
    for i in range(levels - 1):
        inners.append(callit_args(PM, vers, CALLIT, inners[-1]))
    keys = [len(x) for x in reversed(inners[:-1])] + [last_key]
    r = last
    for k in reversed(keys):
        r = (u(k) if vers == 2 else xstr(b'a' * k)) + opaque(r)
    return call(xid, PM, vers, CALLIT, inners[-1]), reply(xid, r)
def nested_call(levels, xid_base): return nested(2, levels, xid_base)[0]
def nested_reply(levels, xid_base): return nested(2, levels, xid_base)[1]

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    cl, sv = 800, 111
    def c(d, sport=cl): F.append(udp(sport, sv, d))
    def s(d, dport=cl): F.append(udp(sv, dport, d, src='192.0.2.2', dst='192.0.2.1'))
    def cu(d, sport=cl): F.append(udp(sport, sv, d))
    def su(d, dport=cl): F.append(udp(sv, dport, d, src='192.0.2.2', dst='192.0.2.1'))

    mark('portmap version 1 (procedures decoded as unknown) and version 2 NULL')
    cu(call(16385, PM, 1, NULL)); su(reply(0x4001))
    cu(call(16386, PM, 1, GETPORT, mapping(100003, 2, 17, 0))); su(reply(16386, u(2049)))
    cu(call(16387, PM, 2, NULL)); su(reply(0x4003))

    mark('version 2 GETPORT over UDP (learns the RPC conversation), TCP, unknown program')
    cu(call(16388, PM, 2, GETPORT, mapping(100003, 3, 17, 0))); su(reply(16388, u(2049)))
    cu(call(16389, PM, 2, GETPORT, mapping(100005, 1, 6, 0))); su(reply(16389, u(0)))
    cu(call(16390, PM, 2, GETPORT, mapping(100003, 3, 6, 0))); su(reply(16390, u(2049)))
    cu(call(16391, PM, 2, GETPORT, mapping(390000, 1, 17, 0))); su(reply(16391, u(0)))
    cu(call(16392, PM, 2, GETPORT, mapping(100003, 3, 255, 0))); su(reply(16392, u(2049)))

    mark('version 2 SET, UNSET, DUMP')
    cu(call(16393, PM, 2, SET, mapping(300001, 1, 6, 4000))); su(reply(16393, u(1)))
    cu(call(16394, PM, 2, UNSET, mapping(300001, 1, 6, 4000))); su(reply(16394, u(0)))
    cu(call(16395, PM, 2, DUMP))
    su(reply(16395, u(1) + mapping(PM, 2, 6, 111) + u(1) + mapping(100003, 3, 17, 2049) + u(1) + mapping(390000, 1, 6, 5000) + u(0)))
    cu(call(16396, PM, 2, DUMP)); su(reply(16396, u(0)))

    mark('version 2 CALLIT: NFS NULL, a nested portmap GETPORT, nesting up to the limit and past it (expert info)')
    cu(call(16397, PM, 2, CALLIT, callit_args(100003, 3, 0)))
    su(reply(16397, u(2049) + opaque(b'')))
    cu(call(16398, PM, 2, CALLIT, callit_args(PM, 2, GETPORT, mapping(100003, 3, 17, 0))))
    su(reply(16398, u(111) + opaque(u(2049))))
    cu(call(16399, PM, 2, CALLIT, callit_args(PM, 2, CALLIT, callit_args(100003, 3, 0))))
    su(reply(16399, u(111) + opaque(u(2049) + opaque(b''))))
    cu(nested_call(4, 16400)); su(nested_reply(4, 16400))
    cu(nested_call(6, 16401)); su(nested_reply(6, 16401))
    cu(call(16402, PM, 2, CALLIT, callit_args(PM, 2, 77, b'\x01\x02\x03\x04')))     # an indirect call to an unknown procedure
    su(reply(16402, u(111) + opaque(b'\x05\x06\x07\x08')))

    mark('rpcbind version 3: SET, UNSET, GETADDR, DUMP, CALLIT, GETTIME and others')
    cu(call(16404, PM, 3, NULL)); su(reply(0x4014))
    cu(call(16405, PM, 3, SET, rpcb(300001, 1, 'tcp', '192.0.2.2.15.160', 'root'))); su(reply(16405, u(1)))
    cu(call(16406, PM, 3, UNSET, rpcb(300001, 1, 'tcp', '', 'root'))); su(reply(16406, u(1)))
    cu(call(16407, PM, 3, 3, rpcb(100003, 3, 'udp', '', ''))); su(reply(16407, xstr('192.0.2.2.8.1')))
    cu(call(16408, PM, 3, 3, rpcb(390000, 1, 'tcp', '', ''))); su(reply(16408, xstr('')))
    cu(call(16409, PM, 3, DUMP))
    su(reply(16409, u(1) + rpcb(PM, 3, 'tcp', '0.0.0.0.0.111', 'superuser') + u(1) + rpcb(PM, 4, 'udp6', '::.0.111', 'superuser') + u(0)))
    cu(call(16410, PM, 3, CALLIT, callit_args(100003, 3, 0))); su(reply(16410, xstr('192.0.2.2.8.1') + opaque(b'')))
    cu(call(16411, PM, 3, 6)); su(reply(16411, u(1700000000)))                 # GETTIME
    cu(call(16412, PM, 3, 7, xstr('192.0.2.2.8.1'))); su(reply(16412, b'\0' * 8))   # UADDR2TADDR
    cu(call(16413, PM, 3, 8, b'\0' * 8)); su(reply(16413, xstr('192.0.2.2.8.1')))   # TADDR2UADDR
    cu(call(16414, PM, 3, CALLIT, callit_args(PM, 3, CALLIT, callit_args(100003, 3, 0))))
    su(reply(16414, xstr('0.0.0.0.0.111') + opaque(xstr('192.0.2.2.8.1') + opaque(b''))))

    for lv, xid in ((3, 0x4031), (4, 0x4032), (6, 0x4033)):
        cl_, rp_ = nested(3, lv, xid)
        F.append(udp(802, sv, cl_, src='192.0.2.5'))
        F.append(udp(sv, 802, rp_, src='192.0.2.2', dst='192.0.2.5'))
    mark('rpcbind version 4: BCAST, GETVERSADDR, INDIRECT, GETADDRLIST, GETSTAT')
    cu(call(16424, PM, 4, 3, rpcb(100003, 3, 'udp', '', ''))); su(reply(16424, xstr('192.0.2.2.8.1')))
    cu(call(16425, PM, 4, 5, callit_args(100003, 3, 0))); su(reply(16425, xstr('192.0.2.2.8.1') + opaque(b'')))
    cu(call(16426, PM, 4, 9, rpcb(100003, 3, 'udp', '', ''))); su(reply(16426, xstr('192.0.2.2.8.1')))
    cu(call(16427, PM, 4, 10, callit_args(100003, 3, 0))); su(reply(16427, xstr('192.0.2.2.8.1') + opaque(b'')))
    cu(call(16428, PM, 4, 11, rpcb(100003, 3, 'udp', '', ''))); su(reply(16428, u(0)))
    cu(call(16429, PM, 4, 12)); su(reply(16429, b'\0' * 12))
    cu(call(16430, PM, 4, 4)); su(reply(16430, u(0)))

    mark('replies with an RPC error, a call with trailing octets and the NFS conversation learned from GETPORT')
    cu(call(16434, PM, 2, 99)); su(reply(16434, stat=3))
    cu(call(0x4060, 100003, 3, 0, b''), sport=cl); su(reply(0x4060))                 # NFS NULL to port 111 (not portmap)

    mark('TCP: DUMP and CALLIT with record marking')
    t = Tcp(801, 111)
    def rm(d): return struct.pack('>I', 0x80000000 | len(d)) + d
    F.append(t.c2s(rm(call(16444, PM, 2, DUMP))))
    F.append(t.s2c(rm(reply(16444, u(1) + mapping(PM, 2, 6, 111) + u(1) + mapping(100003, 3, 6, 2049) + u(0)))))
    F.append(t.c2s(rm(call(16445, PM, 2, CALLIT, callit_args(100003, 3, 0)))))
    F.append(t.s2c(rm(reply(16445, u(2049) + opaque(b'')))))
    return F, marks

def malformed_frames():
    F = []
    cl, sv = 800, 111
    def c(d): F.append(udp(cl, sv, d))
    def s(d): F.append(udp(sv, cl, d, src='192.0.2.2', dst='192.0.2.1'))
    c(call(16385, PM, 2, GETPORT, b'\0\0\0\x01'))                  # GETPORT arguments cut short
    c(call(16386, PM, 2, SET, b'\0' * 8))                          # SET cut short
    c(call(16387, PM, 2, UNSET, b'\0' * 8))
    c(call(16388, PM, 2, CALLIT, u(PM, 2)))                        # CALLIT cut short
    c(call(16389, PM, 3, SET, u(1, 1) + u(500) + b'abc'))          # rpcb with a string past the end
    c(call(16390, PM, 2, DUMP)); s(reply(16390, u(1) + u(1, 2, 6)))    # dump entry cut short
    c(call(16391, PM, 2, GETPORT, mapping(100003, 3, 17, 0))); s(reply(16391, b''))   # reply without port
    c(call(16392, PM, 2, CALLIT, callit_args(PM, 2, CALLIT, callit_args(100003, 3, 0))[:-6]))
    s(reply(16392, u(0)))                                          # CALLIT reply with no result data
    c(call(16393, PM, 3, CALLIT, callit_args(100003, 3, 0))); s(reply(16393, u(100) + b'abc'))   # rmtcallres string cut
    c(nested_call(40, 16394)); s(nested_reply(40, 16394))            # a few levels past the limit, many more than needed
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'portmap-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'portmap-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s_ in marks: print(s_, n)
        print(len(F), 'frames', len(M), 'malformed frames')

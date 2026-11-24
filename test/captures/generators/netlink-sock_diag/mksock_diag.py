#!/usr/bin/env python3
# Generates test/captures/netlink-sock_diag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NETLINK_SOCK_DIAG captures for packet-netlink-sock_diag.c.

Usage: mksock_diag.py <outdir>
Writes sock_diag-coverage.pcap (clean) and sock_diag-coverage-malformed.pcap.
LINKTYPE_NETLINK (253), cooked protocol 4 (NETLINK_SOCK_DIAG). A message
with port id 0 is a request (user space to kernel), any other port id a
reply, which selects the request or the reply layout of each family.
"""
import struct
import sys
import os

NLA_F_NESTED = 0x8000
AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET = 1, 2, 10, 16, 17

def sll(proto=4):
    return struct.pack('>HHH8sH', 4, 824, 0, b'\0' * 8, proto)

def nla(t, payload=b'', e='<'):
    l = 4 + len(payload)
    return struct.pack(e + 'HH', l, t) + payload + b'\0' * ((4 - l % 4) % 4)

def nlmsg(t, payload, seq=1, flags=0, pid=0, e='<', length=None):
    if length is None:
        length = 16 + len(payload)
    return struct.pack(e + 'IHHII', length, t, flags, seq, pid) + payload

def pcap(frames, fn):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def u32(v): return struct.pack('<I', v)
COOKIE = struct.pack('<II', 0xdeadbeef, 0x01020304)
IP4A = bytes([192, 0, 2, 1]); IP4B = bytes([198, 51, 100, 7])
IP6A = bytes.fromhex('20010db8000000000000000000000001')
IP6B = bytes.fromhex('20010db8000000000000000000000002')

def meminfo(n=6):
    return b''.join(u32(1000 * (i + 1)) for i in range(n))

# ---- requests (pid 0)
def unix_req(inode=0, show=0x7f, states=0xffffffff, cookie=COOKIE):
    return struct.pack('<BBHII', AF_UNIX, 0, 0, states, inode) + u32(show) + cookie

def inet_req(fam=AF_INET, proto=6, ext=0x3, states=0x0fff, sport=22, dport=4242, iface=0, cookie=COOKIE, e='<'):
    sid = struct.pack('>HH', sport, dport)
    if fam == AF_INET:
        sid += IP4A + bytes(12) + IP4B + bytes(12)
    else:
        sid += IP6A + IP6B
    return struct.pack('<BBBB', fam, proto, ext, 0) + struct.pack(e + 'I', states) + sid + struct.pack(e + 'I', iface) + cookie

def netlink_req(proto=255, inode=0, show=0x7, cookie=COOKIE):
    return struct.pack('<BBHI', AF_NETLINK, proto, 0, inode) + u32(show) + cookie

def packet_req(proto=3, inode=0, show=0x3f, cookie=COOKIE):
    return struct.pack('<BBHI', AF_PACKET, proto, 0, inode) + u32(show) + cookie

# ---- replies
def unix_rep(typ=1, state=1, inode=0xaaaa, attrs=b'', cookie=COOKIE, pad=0):
    return struct.pack('<BBBBI', AF_UNIX, typ, state, pad, inode) + cookie + attrs

def inet_rep(fam=AF_INET, state=1, sport=22, dport=40000, iface=2, rq=5, wq=6, inode=0x1234,
             attrs=b'', cookie=COOKIE, pad=0):
    sid = struct.pack('>HH', sport, dport)
    if fam == AF_INET:
        sid += IP4A + bytes([pad] * 12) + IP4B + bytes(12)
    else:
        sid += IP6A + IP6B
    return (struct.pack('<BBBB', fam, state, 0, 0) + sid + u32(iface) + cookie +
            u32(0) + u32(rq) + u32(wq) + u32(1000) + u32(inode) + attrs)

def netlink_rep(typ=3, proto=0, state=7, port=100, dport=0, inode=0x77, attrs=b'', cookie=COOKIE):
    return (struct.pack('<BBBB', AF_NETLINK, typ, proto, state) + u32(port) + u32(dport) + u32(0) +
            u32(inode) + cookie + attrs)

def packet_rep(typ=3, proto=0x0300, inode=0x55, attrs=b'', cookie=COOKIE):
    return struct.pack('<BBHI', AF_PACKET, typ, proto, inode) + cookie + attrs

def main(out):
    os.makedirs(out, exist_ok=True)
    fr = []
    seq = [0]
    def add(t, payload, pid=0, flags=0, e='<'):
        seq[0] += 1
        fr.append(sll() + nlmsg(t, payload, seq[0], flags, pid, e))
    REQ = 0x301
    # ---- requests, one per family and several show masks
    for show in (0x7f, 0x01, 0x10, 0x20, 0):
        add(20, unix_req(show=show), flags=REQ)
    add(20, unix_req(inode=0x1234, show=0x3f), flags=REQ)
    add(20, inet_req(AF_INET), flags=REQ)
    add(20, inet_req(AF_INET6, proto=17, ext=0x1f, states=0xfff, sport=53, dport=0), flags=REQ)
    add(20, inet_req(AF_INET, proto=6, states=1 << 10, iface=3), flags=REQ)
    for show in (0x7, 0x1, 0x4, 0):
        add(20, netlink_req(show=show), flags=REQ)
    add(20, netlink_req(proto=0, inode=0x77), flags=REQ)
    for show in (0x3f, 0x1, 0x8, 0):
        add(20, packet_req(show=show), flags=REQ)
    add(20, packet_req(proto=0x08, inode=9), flags=REQ)
    # ---- unix replies
    path = b'/run/user/1000/bus\0'
    add(20, unix_rep(attrs=nla(0, path) + nla(2, u32(0x1111)) + nla(4, struct.pack('<II', 0x11111111, 0x22222222)) +
                     nla(5, meminfo(6)) + nla(6, b'\x03') + nla(1, struct.pack('<II', 7, 8)) +
                     nla(3, u32(5)) + nla(7, u32(1000))), pid=4242)
    add(20, unix_rep(typ=2, state=10, attrs=nla(0, b'\0abstract-name') + nla(6, b'\x00') + nla(5, meminfo(1))),
        pid=4242)
    add(20, unix_rep(typ=5, state=7, attrs=nla(0, b'\0') + nla(6, b'\x01') + nla(6, b'\x02') + nla(6, b'\x07')),
        pid=4242)
    add(20, unix_rep(attrs=nla(0, b'plain\0')), pid=4242)
    add(20, unix_rep(attrs=nla(5, meminfo(8)) + nla(4, b'\0' * 8) + nla(2, u32(0))), pid=4242)
    # attributes carrying NLA_F_NESTED are not decoded (raw data)
    add(20, unix_rep(attrs=nla(4 | NLA_F_NESTED, struct.pack('<II', 1, 2))), pid=4242)
    # ---- inet replies
    for fam in (AF_INET, AF_INET6):
        add(20, inet_rep(fam, attrs=nla(1, meminfo(4)) + nla(7, meminfo(9)) + nla(8, b'\x03') +
                         nla(2, bytes(104)) + nla(3, bytes(12)) + nla(4, b'cubic\0') + nla(5, b'\x10') +
                         nla(6, b'\x00') + nla(9, bytes(16)) + nla(10, b'\x06') + nla(11, b'\x01') +
                         nla(12, u32(1)) + nla(13, u32(2)) + nla(14, b'') + nla(15, u32(0x7)) +
                         nla(16, bytes(20)) + nla(17, u32(0)) + nla(18, bytes(8)) + nla(19, b'tls\0') +
                         nla(20, b'') + nla(21, struct.pack('<Q', 1)) + nla(22, u32(0)) + nla(0, u32(0))),
            pid=4242)
    for st in range(1, 13):
        add(20, inet_rep(AF_INET, state=st, rq=st, wq=0, attrs=nla(8, b'\x00') if st == 7 else b''), pid=7)
    add(20, inet_rep(AF_INET, pad=1), pid=7)               # non-zero padding after the address
    add(20, inet_rep(AF_INET6, attrs=nla(8, b'\x04')), pid=7)  # invalid shutdown value
    # ---- netlink and packet replies
    add(20, netlink_rep(attrs=nla(0, meminfo(6)) + nla(1, u32(0xffffffff)) + nla(2, bytes(24)) +
                        nla(3, bytes(24)) + nla(4, u32(1))), pid=9)
    add(20, netlink_rep(typ=2, proto=9, state=1, port=1, dport=2), pid=9)
    add(20, netlink_rep(typ=7, proto=16), pid=9)
    add(20, packet_rep(attrs=nla(6, meminfo(6)) + nla(0, bytes(20)) + nla(1, bytes(16)) + nla(2, bytes(24)) +
                       nla(3, bytes(24)) + nla(4, u32(1)) + nla(5, u32(1000)) + nla(7, bytes(16))), pid=9)
    add(20, packet_rep(typ=2, proto=0x0008), pid=9)
    # ---- other message types and families
    add(18, b'\x02\x06\x00\x00' + bytes(48), flags=REQ)             # TCPDIAG_GETSOCK (compat)
    add(19, b'\x02\x06\x00\x00' + bytes(48), flags=REQ)             # DCCPDIAG_GETSOCK
    add(21, inet_req(AF_INET), flags=REQ)                            # SOCK_DESTROY
    add(20, b'\x00' + bytes(23), flags=REQ)                          # AF_UNSPEC: no decoder
    add(20, bytes([31]) + bytes(23), pid=5)                          # AF_BLUETOOTH reply
    # big endian messages: states, inode and queue counters follow the message byte order
    seq[0] += 1
    fr.append(sll() + nlmsg(20, struct.pack('>BBBBI', AF_INET, 6, 0x3, 0, 0x0fff) +
                            struct.pack('>HH', 22, 99) + IP4A + bytes(12) + IP4B + bytes(12) +
                            struct.pack('>I', 2) + COOKIE, seq[0], REQ, 0, '>'))
    seq[0] += 1
    fr.append(sll() + nlmsg(20, struct.pack('>BBBBI', AF_UNIX, 1, 1, 0, 0xaaaa) + COOKIE +
                            nla(4, struct.pack('>II', 3, 4), '>') + nla(5, b''.join(struct.pack('>I', i) for i in range(6)), '>'),
                            seq[0], 0, 5, '>'))
    # the reproducer of "netlink-sock_diag: Fix several small decoding errors":
    # RQLEN {rq, wq} = {0x11111111, 0x22222222} and SHUTDOWN (the send queue was
    # shown as 0x11111111 and the shutdown byte twice)
    add(20, struct.pack('<BBBBI', AF_UNIX, 1, 10, 0, 1234) + struct.pack('<II', 0xaaaa, 0xbbbb) +
        nla(4, struct.pack('<II', 0x11111111, 0x22222222)) + nla(6, b'\x03'), pid=4242)
    pcap(fr, os.path.join(out, 'sock_diag-coverage.pcap'))
    nclean = len(fr)

    # ------------------------------------------------------------------
    mal = []
    seq[0] = 0
    def madd(t, payload, pid=0, flags=0):
        seq[0] += 1
        mal.append(sll() + nlmsg(t, payload, seq[0], flags, pid))
    madd(20, unix_rep(attrs=nla(0, b'')), pid=1)                      # empty name
    madd(20, unix_rep(attrs=nla(4, b'\x01\x02\x03\x04')), pid=1)      # short RQLEN
    madd(20, unix_rep(attrs=nla(6, b'\x01\x02')), pid=1)              # shutdown, 2 bytes
    madd(20, unix_rep(attrs=nla(5, b'\x01\x02\x03')), pid=1)          # meminfo, 3 bytes
    madd(20, unix_rep(attrs=nla(2, b'\x01\x02')), pid=1)              # short peer
    madd(20, inet_rep(attrs=nla(1, bytes(12))), pid=1)                # short MEMINFO
    madd(20, inet_rep(attrs=nla(8, b'')), pid=1)                      # empty shutdown
    madd(20, unix_rep()[:10], pid=1)                                  # truncated replies
    madd(20, inet_rep()[:30], pid=1)
    madd(20, netlink_rep()[:12], pid=1)
    madd(20, packet_rep()[:8], pid=1)
    madd(20, unix_req()[:12])                                          # truncated requests
    madd(20, inet_req()[:20])
    madd(20, netlink_req()[:10])
    madd(20, packet_req()[:6])
    madd(20, b'')
    madd(20, unix_rep(attrs=struct.pack('<HH', 200, 4) + bytes(4)), pid=1)   # attribute past the message
    madd(20, unix_rep(attrs=struct.pack('<HH', 2, 4) + bytes(4)), pid=1)
    mal.append(sll() + nlmsg(1, b'', 1) + nlmsg(1, b'', 2, length=0xfffffff0))   # Netlink core
    mal.append(sll() + nlmsg(20, unix_rep(), 3, 0, 1, length=0x10000))
    pcap(mal, os.path.join(out, 'sock_diag-coverage-malformed.pcap'))
    print('clean frames', nclean, 'malformed frames', len(mal))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

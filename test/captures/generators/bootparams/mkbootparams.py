#!/usr/bin/env python3
# Generates test/captures/bootparams_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Boot Parameters
dissector (packet-bootparams.c, ONC RPC program 100026, version 1).

All packets are built from scratch with struct; no captured traffic is
used. A diskless client (192.0.2.20) broadcasts or sends ONC RPC calls
over UDP to a bootparams server (198.51.100.5); the RPC dissector matches
the replies to the calls by XID.

Usage: mkbootparams.py <output directory>

Writes:
  bootparams-coverage.pcap            NULL, WHOAMI and GETFILE calls and
                                      replies, IPv4 and unknown address
                                      types, empty and padded strings
  bootparams-coverage-malformed.pcap  truncated calls and replies
                                      (exceptions)
"""

import struct
import sys

CLIENT = (192, 0, 2, 20)
SERVER = (198, 51, 100, 5)
CPORT = 1023
SPORT = 32771          # an rpcbind assigned port; RPC is found heuristically
PROG = 100026
EPOCH = 1700000000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def xstr(s):
    """XDR string: length, data, padded to a multiple of 4."""
    return struct.pack('>I', len(s)) + s + b'\0' * (-len(s) % 4)


def bp_addr(addr, typ=1):
    """bp_address: type 1 is an IPv4 address with one octet in the low
    byte of each of four 32 bit words (as the bootparams XDR does)."""
    if typ != 1:
        return struct.pack('>I', typ)
    return struct.pack('>I', 1) + b''.join(struct.pack('>I', o) for o in addr)


def auth_unix(machine=b'diskless1', uid=0, gid=0):
    body = struct.pack('>I', EPOCH) + xstr(machine) + struct.pack('>III', uid, gid, 1) + \
        struct.pack('>I', gid)
    return struct.pack('>II', 1, len(body)) + body


def rpc_call(xid, proc, args, vers=1, cred=None):
    if cred is None:
        cred = auth_unix()
    return struct.pack('>IIIIII', xid, 0, 2, PROG, vers, proc) + cred + \
        struct.pack('>II', 0, 0) + args


def rpc_reply(xid, results, accept_stat=0):
    return struct.pack('>IIIII', xid, 1, 0, 0, 0) + struct.pack('>I', accept_stat) + results


class Pcap:
    def __init__(self):
        self.frames = []

    def call(self, payload, dst=SERVER):
        self.ip(ipv4(CLIENT, dst, 17, udp4(CLIENT, dst, CPORT, SPORT, payload),
                     len(self.frames) + 1))

    def reply(self, payload):
        self.ip(ipv4(SERVER, CLIENT, 17, udp4(SERVER, CLIENT, SPORT, CPORT, payload),
                     len(self.frames) + 1))

    def ip(self, ip):
        eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
        self.frames.append(eth + ip)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', EPOCH + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


def main_capture():
    c = Pcap()
    # 1-2: NULL call and reply (AUTH_NULL credentials)
    c.call(rpc_call(0x1001, 0, b'', cred=struct.pack('>II', 0, 0)))
    c.reply(rpc_reply(0x1001, b''))
    # 3-4: WHOAMI: client address 192.0.2.20; reply with host, domain and
    # router 192.0.2.1
    c.call(rpc_call(0x1002, 1, bp_addr(CLIENT)))
    c.reply(rpc_reply(0x1002, xstr(b'diskless1') + xstr(b'example.org') +
                      bp_addr((192, 0, 2, 1))))
    # 5-6: GETFILE root; reply with server host, server address and path
    c.call(rpc_call(0x1003, 2, xstr(b'diskless1') + xstr(b'root')))
    c.reply(rpc_reply(0x1003, xstr(b'bootserver') + bp_addr(SERVER) +
                      xstr(b'/export/root/diskless1')))
    # 7-8: GETFILE swap
    c.call(rpc_call(0x1004, 2, xstr(b'diskless1') + xstr(b'swap')))
    c.reply(rpc_reply(0x1004, xstr(b'bootserver') + bp_addr(SERVER) +
                      xstr(b'/export/swap/diskless1')))
    # 9-10: GETFILE dump; empty strings in the reply (file not provided)
    c.call(rpc_call(0x1005, 2, xstr(b'diskless1') + xstr(b'dump')))
    c.reply(rpc_reply(0x1005, xstr(b'') + bp_addr(SERVER) + xstr(b'')))
    # 11-12: WHOAMI with an unknown address type (2): no address follows;
    # reply with an empty domain and an unknown router address type
    c.call(rpc_call(0x1006, 1, bp_addr(None, typ=2)))
    c.reply(rpc_reply(0x1006, xstr(b'diskless2') + xstr(b'') + bp_addr(None, typ=0)))
    # 13-14: GETFILE with a 4 octet file ID (no padding) and a host name
    # needing 3 octets of padding
    c.call(rpc_call(0x1007, 2, xstr(b'h') + xstr(b'home')))
    c.reply(rpc_reply(0x1007, xstr(b'nfs1') + bp_addr((198, 51, 100, 6)) +
                      xstr(b'/export/home')))
    return c


def malformed_capture():
    c = Pcap()
    # 1: WHOAMI call with a cut IPv4 address
    c.call(rpc_call(0x2001, 1, bp_addr(CLIENT)[:10]))
    # 2-3: WHOAMI reply without the router address type
    c.call(rpc_call(0x2002, 1, bp_addr(CLIENT)))
    c.reply(rpc_reply(0x2002, xstr(b'diskless1') + xstr(b'example.org')))
    # 4: GETFILE call with a string length beyond the packet
    c.call(rpc_call(0x2003, 2, xstr(b'diskless1') + struct.pack('>I', 1000) + b'root'))
    # 5-6: GETFILE reply cut in the server address
    c.call(rpc_call(0x2004, 2, xstr(b'diskless1') + xstr(b'root')))
    c.reply(rpc_reply(0x2004, xstr(b'bootserver') + bp_addr(SERVER)[:12]))
    # 7-8: GETFILE reply without the path
    c.call(rpc_call(0x2005, 2, xstr(b'diskless1') + xstr(b'root')))
    c.reply(rpc_reply(0x2005, xstr(b'bootserver') + bp_addr(SERVER)))
    return c


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(out + '/bootparams-coverage.pcap')
    malformed_capture().write(out + '/bootparams-coverage-malformed.pcap')

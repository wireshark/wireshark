#!/usr/bin/env python3
# Generates test/captures/clearcase_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the ClearCase NFS
dissector (packet-clearcase.c).

ClearCase registers ONC RPC program 390512 version 3 with one procedure,
NULL (0). The capture holds portmapper lookups for the program and NULL
calls and replies over UDP and over TCP (with record marking), with
AUTH_NULL and AUTH_UNIX credentials. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkclearcase.py <output directory>

Writes:
  clearcase-coverage.pcap   portmapper GETPORT for program 390512 over
                            UDP and TCP, NULL calls and replies over UDP
                            and TCP, a reply in two TCP segments
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 111
CC_PROG = 390512
CC_PORT = 371   # the albd (ClearCase) port, any free port works


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip_frame(src, dst, proto, l4, ident):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + l4


def udp_frame(sport, dport, payload, src, dst, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    return ip_frame(src, dst, 17, udp, ident)


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    # SYNs carry an MSS option (a SYN without options looks like a scanner)
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    return ip_frame(src, dst, 6, tcp + payload, ident)


class Conn:
    """One TCP connection with a three way handshake."""

    def __init__(self, frames, cport, sport):
        self.f = frames
        self.cport = cport
        self.sport = sport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, self.sport, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(self.sport, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)




# ONC RPC ----------------------------------------------------------------

def auth_null():
    return struct.pack('>II', 0, 0)


def auth_unix(stamp, machine, uid, gid, gids):
    m = machine.encode()
    body = struct.pack('>II', stamp, len(m)) + m + b'\0' * (-len(m) % 4)
    body += struct.pack('>III', uid, gid, len(gids)) + b''.join(struct.pack('>I', g) for g in gids)
    return struct.pack('>II', 1, len(body)) + body


def rpc_call(xid, prog, vers, proc, args=b'', cred=None):
    return (struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) + (cred or auth_null())
            + auth_null() + args)


def rpc_reply(xid, results=b''):
    return struct.pack('>II', xid, 1) + struct.pack('>I', 0) + auth_null() \
        + struct.pack('>I', 0) + results


def rm(msg, last=True):
    """TCP record marking: one fragment."""
    return struct.pack('>I', (0x80000000 if last else 0) | len(msg)) + msg


def getport(xid, prot):
    # PMAPPROC_GETPORT(prog 390512, vers 3, prot, port 0)
    return rpc_call(xid, 100000, 2, 3, struct.pack('>IIII', CC_PROG, 3, prot, 0))


def main_frames():
    F = []
    unix = auth_unix(1700000000, 'ccclient', 1000, 100, [100, 4, 24])
    # 1-2: portmapper GETPORT for ClearCase over UDP and its reply
    F.append(udp_frame(800, PORT, getport(0x1001, 17), IP_C, IP_S, ident=1))
    F.append(udp_frame(PORT, 800, rpc_reply(0x1001, struct.pack('>I', CC_PORT)), IP_S, IP_C,
                       ident=2))
    # 3-4: ClearCase NULL call (AUTH_NULL) over UDP and reply
    F.append(udp_frame(801, CC_PORT, rpc_call(0x2001, CC_PROG, 3, 0), IP_C, IP_S, ident=3))
    F.append(udp_frame(CC_PORT, 801, rpc_reply(0x2001), IP_S, IP_C, ident=4))
    # 5-6: NULL call with AUTH_UNIX over UDP and reply
    F.append(udp_frame(801, CC_PORT, rpc_call(0x2002, CC_PROG, 3, 0, cred=unix), IP_C, IP_S,
                       ident=5))
    F.append(udp_frame(CC_PORT, 801, rpc_reply(0x2002), IP_S, IP_C, ident=6))
    # 7-9: TCP connection to the portmapper
    c = Conn(F, 802, PORT)
    # 10-11: GETPORT for ClearCase over TCP and reply
    c.add(True, rm(getport(0x1002, 6)))
    c.add(False, rm(rpc_reply(0x1002, struct.pack('>I', CC_PORT))))
    # 12-14: FIN
    c.close()
    # 15-17: TCP connection to ClearCase
    c = Conn(F, 803, CC_PORT)
    # 18-19: NULL call and reply
    c.add(True, rm(rpc_call(0x3001, CC_PROG, 3, 0, cred=unix)))
    c.add(False, rm(rpc_reply(0x3001)))
    # 20: two NULL calls in one segment
    c.add(True, rm(rpc_call(0x3002, CC_PROG, 3, 0)) + rm(rpc_call(0x3003, CC_PROG, 3, 0)))
    # 21: both replies in one segment
    c.add(False, rm(rpc_reply(0x3002)) + rm(rpc_reply(0x3003)))
    # 22-23: a call in two segments (cut inside the credentials)
    m = rm(rpc_call(0x3004, CC_PROG, 3, 0, cred=unix))
    c.add(True, m[:30])
    c.add(True, m[30:])
    # 24: reply
    c.add(False, rm(rpc_reply(0x3004)))
    # 25-27: FIN
    c.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'clearcase-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

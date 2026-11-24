#!/usr/bin/env python3
# Generates test/captures/dsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DSI dissector
(packet-dsi.c, AppleTalk Data Stream Interface over TCP).

DSI runs over TCP port 548. A 16 octet header (flags, command, request
ID, data offset or error code, length, reserved) is followed by "length"
octets: Open Session options, an Attention flag, the AFP server status
of a GetStatus reply, or AFP requests and replies for Command and
Write. The AFP payloads are small but valid (FPGetSrvrParms, FPWrite,
FPCloseVol). Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkdsi.py <output directory>

Writes:
  dsi-coverage.pcap            every DSI command as request and reply,
                               Open Session options, Attention flags,
                               the full server status, error codes, TCP
                               reassembly and several PDUs per segment
  dsi-coverage-malformed.pcap  Open Session options and Attention cut
                               short, a length past the end
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import TcpConn, pcap

PORT = 548


def dsi(flags, cmd, reqid, code, payload, length=None):
    return struct.pack('!BBHiII', flags, cmd, reqid, code,
                       len(payload) if length is None else length, 0) + payload


def req(cmd, reqid, payload=b'', offset=0):
    return dsi(0, cmd, reqid, offset, payload)


def rep(cmd, reqid, payload=b'', error=0):
    return dsi(1, cmd, reqid, error, payload)


def pstr(s):
    s = s.encode()
    return bytes([len(s)]) + s


def server_status():
    """AFP server status (FPGetSrvrInfo reply) with every variable
    field: machine type, versions, UAMs, icon, signature, network
    addresses of every type, directory names and the UTF-8 name."""
    flags = 0x8fff & ~0x0000          # all defined bits
    name = pstr('Synthetic DSI Server')
    fixed = 10 + len(name)
    fixed += fixed & 1
    fixed += 8                        # signature, address, directory, UTF-8 offsets
    mach = pstr('Xserve')
    vers = bytes([3]) + pstr('AFP2.2') + pstr('AFPX03') + pstr('AFP3.1')
    uams = bytes([3]) + pstr('No User Authent') + pstr('DHCAST128') + pstr('DHX2')
    icon = bytes(i & 0xff for i in range(256))
    sig = bytes(range(0x10, 0x20))
    addrs = [
        bytes([6, 1]) + bytes([192, 0, 2, 2]),
        bytes([8, 2]) + bytes([192, 0, 2, 2]) + struct.pack('!H', 548),
        bytes([6, 3]) + struct.pack('!HBB', 1000, 42, 4),
        bytes([2 + 15, 4]) + b'afp.example.com',
        bytes([2 + 9, 5]) + b'192.0.2.2',
        bytes([2, 4]),
        bytes([18, 6]) + bytes.fromhex('20010db8000000000000000000000002'),
        bytes([20, 7]) + bytes.fromhex('20010db8000000000000000000000002') + struct.pack('!H', 548),
        bytes([4, 9]) + b'\xaa\xbb',
    ]
    addr = bytes([len(addrs)]) + b''.join(addrs)
    dirs = bytes([2]) + pstr('afpserver/dsi.example.com@EXAMPLE.COM') + pstr('LDAP')
    utf8 = 'Synthetic DSI Server é'.encode()
    utf8 = struct.pack('!H', len(utf8)) + utf8
    var = b''
    offs = {}
    for k, v in (('mach', mach), ('vers', vers), ('uams', uams), ('icon', icon),
                 ('sig', sig), ('addr', addr), ('dirs', dirs), ('utf8', utf8)):
        offs[k] = fixed + len(var)
        var += v
    hdr = struct.pack('!HHHHH', offs['mach'], offs['vers'], offs['uams'], offs['icon'], flags) + name
    if len(hdr) & 1:
        hdr += b'\0'
    hdr += struct.pack('!HHHH', offs['sig'], offs['addr'], offs['dirs'], offs['utf8'])
    assert len(hdr) == fixed
    return hdr + var


def open_opts(opts):
    return b''.join(bytes([t, len(v)]) + v for t, v in opts)


FP_GETSRVRPARMS = 16
FP_WRITE = 33
FP_CLOSEVOL = 2


def getsrvrparms_reply():
    vols = [(0x80, 'Macintosh HD'), (0x00, 'Public')]
    body = struct.pack('!I', 0x2a000000) + bytes([len(vols)])
    for flags, name in vols:
        body += bytes([flags]) + pstr(name)
    return body


def main_frames():
    c = TcpConn(49152, PORT)
    f = []
    # 1-2: GetStatus with the full AFP server status
    f.append(c.send(req(3, 0)))
    f.append(c.send(rep(3, 0, server_status()), True))
    # 3-4: OpenSession: attention quantum, replay cache size, an unknown
    # option; the reply with the server quantum
    f.append(c.send(req(4, 1, open_opts([(1, struct.pack('!I', 1024)),
                                          (2, struct.pack('!I', 128)),
                                          (7, b'\x01\x02\x03')]))))
    f.append(c.send(rep(4, 1, open_opts([(0, struct.pack('!I', 0x100000))])), True))
    # 5-6: Command FPGetSrvrParms and its reply
    f.append(c.send(req(2, 2, bytes([FP_GETSRVRPARMS, 0]))))
    f.append(c.send(rep(2, 2, getsrvrparms_reply()), True))
    # 7-8: Write FPWrite with 64 octets of data (data offset 12), reply
    data = bytes(range(64))
    f.append(c.send(req(6, 3, struct.pack('!BBHII', FP_WRITE, 0, 0x0101, 0, len(data)) + data, offset=12)))
    f.append(c.send(rep(6, 3, struct.pack('!I', len(data))), True))
    # 9-10: Command FPCloseVol and an error reply (kFPParamErr -5019)
    f.append(c.send(req(2, 4, struct.pack('!BBH', FP_CLOSEVOL, 0, 0x0001))))
    f.append(c.send(rep(2, 4, b'', error=-5019), True))
    # 11-15: Attention from the server: server message, notification
    # with a bitmap, shutting down in 5 minutes, disconnect, no flag
    for i, flag in enumerate((0x2000, 0x3003, 0x8005, 0x9000)):
        f.append(c.send(req(8, 0x8000 + i, struct.pack('!H', flag)), True))
    f.append(c.send(req(8, 0x8004), True))
    # 16-17: Tickle both ways
    f.append(c.send(req(5, 5)))
    f.append(c.send(req(5, 0x8005), True))
    # 18: two Tickles in one segment
    f.append(c.send(req(5, 6) + req(5, 7)))
    # 19-20: a Command split over two segments (TCP reassembly)
    big = req(2, 8, bytes([FP_GETSRVRPARMS, 0]))
    f.append(c.send(big[:10]))
    f.append(c.send(big[10:]))
    f.append(c.send(rep(2, 8, getsrvrparms_reply()), True))
    # 22: the unnamed command 7 (shown as data)
    f.append(c.send(req(7, 9, b'\xde\xad\xbe\xef')))
    # 23: a Tickle reply
    f.append(c.send(rep(5, 10), True))
    # 24-25: CloseSession request and reply
    f.append(c.send(req(1, 11)))
    f.append(c.send(rep(1, 11), True))
    # 26-27: on another connection, unknown flags (2) and command 0x20
    # (not a DSI PDU start: the rest of the segment is taken), unknown
    # flags with a known command
    c = TcpConn(49154, PORT)
    f.append(c.send(dsi(2, 0x20, 12, 0, b'junk')))
    f.append(c.send(dsi(3, 5, 13, 0, b'')))
    return f


def malformed_frames():
    c = TcpConn(49153, PORT)
    f = []
    # 1: Open Session option length past the end
    f.append(c.send(req(4, 1, bytes([1, 4, 0, 0]))))
    # 2: Open Session option of length 0x40 with 2 octets
    f.append(c.send(req(4, 2, bytes([7, 0x40, 1, 2]))))
    # 3: Attention flag of one octet
    f.append(c.send(req(8, 3, b'\x20'), True))
    # 4: GetStatus reply with a status cut short
    f.append(c.send(rep(3, 6, server_status()[:20]), True))
    return f


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dsi-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dsi-coverage-malformed.pcap'), malformed_frames())

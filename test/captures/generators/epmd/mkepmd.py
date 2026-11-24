#!/usr/bin/env python3
# Generates test/captures/epmd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EPMD dissector
(packet-epmd.c, Erlang Port Mapper Daemon).

EPMD runs over TCP port 4369 (registered by default). Requests to the
daemon start with a 2 octet length and a type octet; responses start
with the type octet, except the NAMES response, which starts with the
daemon's port number (0x00001111) as a 4 octet integer followed by
"name <node> at port <port>\\n" lines. A PORT2_RESP sets up a
conversation that hands the node's port to the Erlang distribution
protocol dissector. Every packet is built from scratch with struct; no
captured traffic is used (addresses from 192.0.2.0/24).

Usage: mkepmd.py <output directory>

Writes:
  epmd-coverage.pcap            every request and response type, OK and
                                error results, extra data, the 2 and 4
                                octet creation, NAMES lists, unknown
                                types, packets the heuristic rejects
  epmd-coverage-malformed.pcap  malformed NAMES lines, truncated
                                requests and responses
"""

import os
import struct
import sys

EPMD_PORT = 4369


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload):
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags,
                      65535, 0, 0)
    ph = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
    c = csum(ph + hdr + payload)
    hdr = hdr[:16] + struct.pack('>H', c) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload)


def eth(payload, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    return dst + src + struct.pack('>H', 0x0800) + payload


class Conn:
    """A TCP connection without the handshake; sequence and
    acknowledgement numbers follow the data sent."""

    def __init__(self, cport, sport=EPMD_PORT, cli=(192, 0, 2, 1), srv=(192, 0, 2, 2)):
        self.c = (cli, cport, b'\x02\0\0\0\0\x01')
        self.s = (srv, sport, b'\x02\0\0\0\0\x02')
        self.seq = {0: 1000, 1: 5000}

    def pkt(self, to_server, data):
        a, b = (self.c, self.s) if to_server else (self.s, self.c)
        d = 0 if to_server else 1
        fr = eth(tcp(a[0], b[0], a[1], b[1], self.seq[d], self.seq[1 - d],
                     0x18, data), a[2], b[2])
        self.seq[d] += len(data)
        return fr


def req(typ, body=b''):
    return struct.pack('>HB', 1 + len(body), typ) + body


def alive2(port, ntype, proto, high, low, name, extra=None):
    b = struct.pack('>HBBHHH', port, ntype, proto, high, low, len(name)) + name
    if extra is not None:
        b += struct.pack('>H', len(extra)) + extra
    return req(ord('x'), b)


def port2_resp(result, port=0, ntype=0, proto=0, high=0, low=0, name=b'', extra=None):
    b = struct.pack('>BB', ord('w'), result)
    if result:
        return b
    b += struct.pack('>HBBHHH', port, ntype, proto, high, low, len(name)) + name
    if extra is not None:
        b += struct.pack('>H', len(extra)) + extra
    return b


def names(*lines):
    return struct.pack('>I', EPMD_PORT) + b''.join(lines)


def main_frames():
    F = []
    # 1-2: ALIVE2_REQ with extra data, ALIVE2_RESP OK
    c = Conn(40001)
    F.append(c.pkt(True, alive2(25672, 77, 0, 6, 5, b'alpha', b'\x01\x02\x03')))
    F.append(c.pkt(False, struct.pack('>BBH', ord('y'), 0, 7)))
    # 3-4: ALIVE2_REQ with elen 0, ALIVE2_RESP error (with the creation
    #      field, as the daemon sends it)
    c = Conn(40002)
    F.append(c.pkt(True, alive2(25673, 72, 0, 5, 0, b'beta', b'')))
    F.append(c.pkt(False, struct.pack('>BBH', ord('y'), 1, 0)))
    # 5-6: ALIVE2_REQ without the extra length, ALIVE2_X_RESP with a 4
    #      octet creation
    c = Conn(40003)
    F.append(c.pkt(True, alive2(25674, 110, 0, 6, 5, b'gamma')))
    F.append(c.pkt(False, struct.pack('>BBI', ord('v'), 0, 0x12345678)))
    # 7-8: ALIVE2_REQ (R4 erlang node, unknown protocol), ALIVE2_X_RESP
    #      with a 2 octet creation
    c = Conn(40004)
    F.append(c.pkt(True, alive2(25675, 109, 1, 4, 1, b'delta', b'')))
    F.append(c.pkt(False, struct.pack('>BBH', ord('v'), 0, 9)))
    # 9-10: ALIVE2_REQ (R4 hidden node), ALIVE2_X_RESP error
    c = Conn(40005)
    F.append(c.pkt(True, alive2(25676, 104, 0, 3, 2, b'eps', b'')))
    F.append(c.pkt(False, struct.pack('>BBI', ord('v'), 3, 0)))
    # 11: ALIVE2_RESP error as 2 octets: rejected by the heuristic
    #     (shorter than 3 octets), shown as TCP data
    F.append(c.pkt(False, struct.pack('>BB', ord('y'), 1)))
    # 12-13: PORT2_REQ, PORT2_RESP OK with extra data; the conversation
    #        on the node's port goes to the Erlang distribution dissector
    c = Conn(40006)
    F.append(c.pkt(True, req(ord('z'), b'alpha')))
    F.append(c.pkt(False, port2_resp(0, 25672, 77, 0, 6, 5, b'alpha', b'\xaa\xbb')))
    # 14: a packet to the node's port (Erlang distribution, after the
    #     PORT2_RESP); a send_name handshake message
    d = Conn(40100, 25672)
    F.append(d.pkt(True, struct.pack('>HBHI', 7 + 5, ord('n'), 6, 0x0003499c) + b'alpha'))
    # 15-16: PORT2_REQ, PORT2_RESP OK with elen 0
    c = Conn(40007)
    F.append(c.pkt(True, req(ord('z'), b'beta')))
    F.append(c.pkt(False, port2_resp(0, 25673, 72, 0, 5, 0, b'beta', b'')))
    # 17-18: PORT2_REQ, PORT2_RESP OK without the extra length
    c = Conn(40008)
    F.append(c.pkt(True, req(ord('z'), b'gamma')))
    F.append(c.pkt(False, port2_resp(0, 25674, 110, 0, 6, 5, b'gamma')))
    # 19-20: PORT2_REQ for an unknown node, PORT2_RESP error (padded to
    #        4 octets: the 2 octet form is shorter than the heuristic
    #        accepts and 3 octets throw in check_epmd(), see README)
    c = Conn(40009)
    F.append(c.pkt(True, req(ord('z'), b'nobody')))
    F.append(c.pkt(False, port2_resp(1) + b'\0\0'))
    # 21-22: old ALIVE_REQ, ALIVE_OK_RESP OK
    c = Conn(40010)
    F.append(c.pkt(True, req(ord('a'), struct.pack('>H', 25677) + b'zeta')))
    F.append(c.pkt(False, struct.pack('>BBH', ord('Y'), 0, 2)))
    # 23-24: old ALIVE_REQ, ALIVE_OK_RESP error
    c = Conn(40011)
    F.append(c.pkt(True, req(ord('a'), struct.pack('>H', 25678) + b'eta')))
    F.append(c.pkt(False, struct.pack('>BBH', ord('Y'), 2, 0)))
    # 25: old PORT_REQ
    c = Conn(40012)
    F.append(c.pkt(True, req(ord('p'), b'theta')))
    # 26-27: NAMES_REQ (padded to 4 octets; the 3 octet request throws in
    #        check_epmd(), see the malformed capture) and its response: three nodes (5, 4 and 1 digit
    #        ports), the last line without a newline
    c = Conn(40013)
    F.append(c.pkt(True, req(ord('n'), b'\0')))
    F.append(c.pkt(False, names(b'name alpha at port 25672\n',
                                b'name beta at port 4370\n',
                                b'name g at port 7')))
    # 28-29: NAMES_REQ, response with no nodes
    c = Conn(40014)
    F.append(c.pkt(True, req(ord('n'), b'\0')))
    F.append(c.pkt(False, names()))
    # 30: DUMP_REQ (byte 0 is a response type, byte 2 'd' is no request
    #     type the heuristic knows: accepted because of byte 0, type 'd')
    c = Conn(40015)
    F.append(c.pkt(True, struct.pack('>BBBB', ord('Y'), 0, ord('d'), 0)))
    # 31: KILL_REQ (accepted through byte 0 'v')
    F.append(c.pkt(True, struct.pack('>HBB', ord('v') << 8 | 1, ord('k'), 0)))
    # 32: unknown request type 0x01 (byte 0 'w')
    F.append(c.pkt(True, struct.pack('>BBBB', ord('w'), 0, 1, 0)))
    # 33: unknown response type 0x01 (byte 2 is 'n')
    F.append(c.pkt(False, struct.pack('>BBBB', 1, 0, ord('n'), 0)))
    # 34: rejected by the heuristic: shorter than 3 octets (TCP data)
    F.append(c.pkt(True, b'\x00\x01'))
    # 35: rejected by the heuristic: no known type (TCP data)
    F.append(c.pkt(True, b'\x00\x05\x01\x02\x03'))
    return F


def malformed_frames():
    F = []
    c = Conn(41001)
    # 1: NAMES response with every malformed line form: no "name ", no
    #    space after the name, no " at port ", no port number, a port
    #    that is no number, a port too large for 16 bits
    F.append(c.pkt(False, names(b'node x at port 1\n',
                                b'name nospace\n',
                                b'name x on port 1\n',
                                b'name x at port \n',
                                b'name x at port abc\n',
                                b'name x at port 99999\n')))
    # 2: ALIVE2_REQ whose name runs past the end
    c = Conn(41002)
    F.append(c.pkt(True, req(ord('x'), struct.pack('>HBBHHH', 1, 77, 0, 6, 5, 40) + b'ab')))
    # 3: ALIVE2_REQ whose extra data runs past the end
    F.append(c.pkt(True, alive2(1, 77, 0, 6, 5, b'ab') + struct.pack('>H', 50) + b'x'))
    # 4: PORT2_RESP OK cut after the port
    c = Conn(41003)
    F.append(c.pkt(False, port2_resp(0, 25672, 77, 0, 6, 5, b'alpha', b'')[:4]))
    # 5: PORT2_RESP whose extra data runs past the end
    F.append(c.pkt(False, port2_resp(0, 25672, 77, 0, 6, 5, b'alpha') + struct.pack('>H', 9)))
    # 6: ALIVE_OK_RESP without creation
    F.append(c.pkt(False, struct.pack('>BBB', ord('Y'), 0, 0)))
    # 7: ALIVE_REQ without the port
    F.append(c.pkt(True, struct.pack('>HB', 1, ord('a'))))
    # 8: a real 3 octet NAMES_REQ: check_epmd() reads 4 octets and throws
    c = Conn(41004)
    F.append(c.pkt(True, req(ord('n'))))
    # 9: ALIVE2_X_RESP OK without creation (3 octets, throws the same way)
    F.append(c.pkt(False, struct.pack('>BBB', ord('v'), 0, 0)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'epmd-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'epmd-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

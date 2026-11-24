#!/usr/bin/env python3
# Generates test/captures/ipmi_vita_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the IPMI VITA 46.11 command
set dissector (packet-ipmi-vita.c).

The command set is decoded by the IPMI dissector (packet-ipmi.c) when the
"Dissect bus commands" preference (ipmi.dissect_bus_commands) is on. The
messages are carried the way a real management console sends them: IPMI
v1.5 sessions without authentication, inside RMCP (class IPMI) in UDP port
623, so no Decode As is needed. A request is followed by its response in
the same session sequence so that the dissector matches them and the
response handlers can use what they learned from the request (parameter
selectors, command codes, ...).

Every packet is built from scratch with struct. The payloads are
synthetic constant values (counting, zero and 0xff fills, selector
sweeps); nothing is captured from a real network and no credentials or
keys are present.

Usage: mkipmi_vita.py <output directory>

Writes:
  ipmi_vita-coverage.pcap            VITA 46.11 (VSO) commands, request and response pairs
  ipmi_vita-coverage-malformed.pcap  requests and responses that are too
                                    short for their command, with the
                                    exceptions they raise
"""

import os
import struct
import sys

CONSOLE = bytes.fromhex('020000000010')
BMC = bytes.fromhex('020000000020')
IP_C = bytes([192, 168, 1, 10])
IP_B = bytes([192, 168, 1, 20])
NETFN = 0x2c
SIG = b'\x03'


def pcap(path, frames):
    """frames: list of (timestamp in seconds, bytes)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, fr in frames:
            f.write(struct.pack('<IIII', 1700000000 + int(t), int((t % 1) * 1e6), len(fr), len(fr)))
            f.write(fr)


def cks(data):
    return (-sum(data)) & 0xff


def ipmb(netfn, cmd, data, seq, rs_sa, rq_sa, cc=None, good=True):
    """Responder address, NetFn/LUN, header checksum, requester address,
    sequence/LUN, command, [completion code], data, data checksum."""
    h = bytes([rs_sa, netfn << 2])
    c1 = cks(h)
    body = bytes([rq_sa, seq << 2, cmd])
    if cc is not None:
        body += bytes([cc])
    body += data
    c2 = cks(body)
    if not good:
        c1 ^= 0x55
        c2 ^= 0x55
    return h + bytes([c1]) + body + bytes([c2])


def udp_frame(payload, to_bmc, ident):
    if to_bmc:
        src, dst, sip, dip, sp, dp = CONSOLE, BMC, IP_C, IP_B, 40000, 623
    else:
        src, dst, sip, dip, sp, dp = BMC, CONSOLE, IP_B, IP_C, 623, 40000
    udp = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), ident & 0xffff, 0, 64, 17, 0) + sip + dip
    s = sum(struct.unpack('>10H', ip))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    return dst + src + struct.pack('>H', 0x0800) + ip + udp


def ipmi_frame(cmd, data, resp, cc, seq, rs_sa, ident, good=True):
    """RMCP (class IPMI) with an IPMI v1.5 session wrapper without
    authentication around one IPMB style message."""
    if resp:
        m = ipmb(NETFN | 1, cmd, SIG + data, seq, 0x81, rs_sa, cc, good)
    else:
        m = ipmb(NETFN, cmd, SIG + data, seq, rs_sa, 0x81, None, good)
    sess = struct.pack('<BIIB', 0, seq, 0x1234, len(m)) + m
    return udp_frame(struct.pack('BBBB', 6, 0, 0xff, 7) + sess, not resp, ident)


def nested_frame(cmd, data, cc, seq, depth, ident):
    """A response wrapped in `depth` Send Message responses (NetFn App,
    command 0x34): the command is dissected `depth` levels down. At level
    3 and below the dissector no longer keeps request data."""
    m = ipmb(NETFN | 1, cmd, SIG + data, seq, 0x81, 0x20, cc)
    for _ in range(depth):
        m = ipmb(0x07, 0x34, m, seq, 0x81, 0x20, 0)
    sess = struct.pack('<BIIB', 0, seq, 0x1234, len(m)) + m
    return udp_frame(struct.pack('BBBB', 6, 0, 0xff, 7) + sess, False, ident)


def build(units):
    """Units: ('q', cmd, data, rs_sa) one request; ('r', cmd, cc, data,
    rs_sa) one response (no request before it); ('p', cmd, rs_sa, data,
    cc, data) a request and its response. Each unit is six seconds after
    the previous one, so unanswered requests expire (maximum delay of a
    response is 5 seconds) and cannot be matched by a later response."""
    frames = []
    n = 0
    for i, u in enumerate(units):
        t = 6.0 * i
        seq = i % 63 + 1
        if u[0] == 'q':
            _, cmd, d, rs = u
            frames.append((t, ipmi_frame(cmd, bytes.fromhex(d), False, 0, seq, rs, n)))
            n += 1
        elif u[0] == 'n':
            _, cmd, cc, d, depth = u
            frames.append((t, nested_frame(cmd, bytes.fromhex(d), cc, seq, depth, n)))
            n += 1
        elif u[0] == 'r':
            _, cmd, cc, d, rs = u
            frames.append((t, ipmi_frame(cmd, bytes.fromhex(d), True, cc, seq, rs, n)))
            n += 1
        else:
            _, cmd, rs, d, cc, d2 = u
            frames.append((t, ipmi_frame(cmd, bytes.fromhex(d), False, 0, seq, rs, n)))
            frames.append((t + 0.001, ipmi_frame(cmd, bytes.fromhex(d2), True, cc, seq, rs, n + 1)))
            n += 2
    return frames


# --- Clean messages -----------------------------------------------------
#
# The units were found by running candidates (payload length and fill
# sweeps, parameter selector sweeps, byte-by-byte value sweeps) through
# the dissector and keeping the ones that decode without malformed
# packets or errors and that between them show every distinct decoded
# item; the reproducers of the fixed bugs and the hand written messages
# come first.
REPRO = []

MAIN = [
    ('r', 0, 0, '000000000000', 32),
    ('r', 0, 0, 'ffffffffffff', 32),
    ('r', 0, 0, '404142434445', 32),
    ('r', 0, 0, '0202030405060708', 32),
    ('r', 0, 0, '1002030405060708', 32),
    ('r', 0, 0, '2002030405060708', 32),
    ('r', 0, 0, '5702030405060708', 32),
    ('r', 0, 0, '0120030405060708', 32),
    ('r', 0, 192, '', 32),
    ('r', 0, 193, '', 32),
    ('r', 0, 204, '', 32),
    ('r', 0, 213, '', 32),
    ('q', 1, '00000000', 32),
    ('q', 1, '01020304', 32),
    ('q', 1, 'ffffffff', 32),
    ('p', 1, 32, '010203040506', 0, '010203040506'),
    ('p', 1, 32, 'ffffffffffff', 0, 'ffffffffffff'),
    ('p', 1, 32, '0000000000000000', 0, '0000000000000000'),
    ('q', 1, '0101030405060708', 32),
    ('q', 1, '0103030405060708', 32),
    ('q', 1, '0102030105060708', 32),
    ('q', 1, '0102030205060708', 32),
    ('q', 1, '0102030305060708', 32),
    ('q', 1, '0102030505060708', 32),
    ('q', 1, '0102030605060708', 32),
    ('q', 1, '0102030705060708', 32),
    ('q', 1, '0102030805060708', 32),
    ('q', 1, '0102030f05060708', 32),
    ('q', 1, '010203c005060708', 32),
    ('r', 1, 192, '', 32),
    ('r', 1, 193, '', 32),
    ('r', 1, 204, '', 32),
    ('r', 1, 213, '', 32),
    ('r', 2, 0, '00', 32),
    ('r', 2, 0, '40', 32),
    ('r', 2, 0, '0102', 32),
    ('r', 2, 0, '052a4f7499be', 32),
    ('r', 2, 0, '0f0000000000000000000000000000000000000000000000', 32),
    ('r', 2, 0, '100000000000000000000000000000000000000000000000', 32),
    ('r', 2, 0, '550000000000000000000000000000000000000000000000', 32),
    ('r', 2, 0, '0f02030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('r', 2, 0, '1002030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('r', 2, 0, '5502030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('r', 2, 0, '080000000000000000000000', 32),
    ('r', 2, 0, '810000000000000000000000', 32),
    ('r', 2, 0, '0202030405060708', 32),
    ('r', 2, 0, '0302030405060708', 32),
    ('r', 2, 0, '0402030405060708', 32),
    ('r', 2, 0, '0502030405060708', 32),
    ('r', 2, 0, '0602030405060708', 32),
    ('r', 2, 0, '0702030405060708', 32),
    ('r', 2, 0, '8002030405060708', 32),
    ('r', 2, 0, '8102030405060708', 32),
    ('r', 2, 0, 'c002030405060708', 32),
    ('r', 2, 0, '010f030405060708', 32),
    ('r', 2, 0, '01c0030405060708', 32),
    ('r', 2, 0, '01e0030405060708', 32),
    ('r', 2, 0, '01ff030405060708', 32),
    ('r', 2, 0, '02ffffffffffffffffffffff', 32),
    ('r', 2, 0, '03ffffffffffffffffffffff', 32),
    ('r', 2, 0, '04ffffffffffffffffffffff', 32),
    ('r', 2, 0, '05ffffffffffffffffffffff', 32),
    ('r', 2, 0, '06ffffffffffffffffffffff', 32),
    ('r', 2, 0, '07ffffffffffffffffffffff', 32),
    ('r', 2, 0, '08ffffffffffffffffffffff', 32),
    ('r', 2, 0, '81ffffffffffffffffffffff', 32),
    ('r', 2, 192, '', 32),
    ('r', 2, 193, '', 32),
    ('r', 2, 204, '', 32),
    ('r', 2, 213, '', 32),
    ('q', 3, '00', 32),
    ('q', 3, '40', 32),
    ('q', 3, '0102', 32),
    ('q', 3, '052a4f7499be', 32),
    ('q', 3, '0f0000000000000000000000000000000000000000000000', 32),
    ('q', 3, '100000000000000000000000000000000000000000000000', 32),
    ('q', 3, '550000000000000000000000000000000000000000000000', 32),
    ('q', 3, '0f02030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('q', 3, '1002030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('q', 3, '5502030405060708090a0b0c0d0e0f101112131415161718', 32),
    ('q', 3, '080000000000000000000000', 32),
    ('q', 3, '810000000000000000000000', 32),
    ('q', 3, '0202030405060708', 32),
    ('q', 3, '0302030405060708', 32),
    ('q', 3, '0402030405060708', 32),
    ('q', 3, '0502030405060708', 32),
    ('q', 3, '0602030405060708', 32),
    ('q', 3, '0702030405060708', 32),
    ('q', 3, '8002030405060708', 32),
    ('q', 3, '8102030405060708', 32),
    ('q', 3, 'c002030405060708', 32),
    ('q', 3, '010f030405060708', 32),
    ('q', 3, '01c0030405060708', 32),
    ('q', 3, '01e0030405060708', 32),
    ('q', 3, '01ff030405060708', 32),
    ('q', 3, '02ffffffffffffffffffffff', 32),
    ('q', 3, '03ffffffffffffffffffffff', 32),
    ('q', 3, '04ffffffffffffffffffffff', 32),
    ('q', 3, '05ffffffffffffffffffffff', 32),
    ('q', 3, '06ffffffffffffffffffffff', 32),
    ('q', 3, '07ffffffffffffffffffffff', 32),
    ('q', 3, '08ffffffffffffffffffffff', 32),
    ('q', 3, '81ffffffffffffffffffffff', 32),
    ('q', 4, '0000', 32),
    ('q', 4, '0102', 32),
    ('q', 4, 'ffff', 32),
    ('q', 4, '0101030405060708', 32),
    ('q', 4, '0103030405060708', 32),
    ('q', 5, '00', 32),
    ('p', 5, 32, '0000', 0, '0000'),
    ('r', 5, 192, '', 32),
    ('r', 5, 193, '', 32),
    ('r', 5, 204, '', 32),
    ('r', 5, 213, '', 32),
    ('q', 6, '0000', 32),
    ('p', 6, 32, '01020304', 0, '01020304'),
    ('p', 6, 32, '40414243', 0, '40414243'),
    ('p', 6, 32, '052a4f74', 0, '052a4f74'),
    ('p', 6, 32, '000400000000000000000000', 0, '000400000000000000000000'),
    ('p', 6, 32, '0202030405060708', 0, '0202030405060708'),
    ('p', 6, 32, '0602030405060708', 0, '0602030405060708'),
    ('p', 6, 32, '0802030405060708', 0, '0802030405060708'),
    ('p', 6, 32, '0f02030405060708', 0, '0f02030405060708'),
    ('p', 6, 32, '1002030405060708', 0, '1002030405060708'),
    ('p', 6, 32, '2002030405060708', 0, '2002030405060708'),
    ('p', 6, 32, '5502030405060708', 0, '5502030405060708'),
    ('p', 6, 32, '5702030405060708', 0, '5702030405060708'),
    ('p', 6, 32, '6002030405060708', 0, '6002030405060708'),
    ('p', 6, 32, '0103030405060708', 0, '0103030405060708'),
    ('p', 6, 32, '0105030405060708', 0, '0105030405060708'),
    ('p', 6, 32, '0106030405060708', 0, '0106030405060708'),
    ('p', 6, 32, '0102010405060708', 0, '0102010405060708'),
    ('p', 6, 32, '0102040405060708', 0, '0102040405060708'),
    ('p', 6, 32, '0102060405060708', 0, '0102060405060708'),
    ('p', 6, 32, '0102070405060708', 0, '0102070405060708'),
    ('p', 6, 32, '0102030105060708', 0, '0102030105060708'),
    ('p', 6, 32, '0102030205060708', 0, '0102030205060708'),
    ('p', 6, 32, 'ff00ffffffffffffffffffff', 0, 'ff00ffffffffffffffffffff'),
    ('p', 6, 32, 'ffff05ffffffffffffffffff', 0, 'ffff05ffffffffffffffffff'),
    ('r', 6, 192, '', 32),
    ('r', 6, 193, '', 32),
    ('r', 6, 204, '', 32),
    ('r', 6, 213, '', 32),
    ('q', 7, '0000000000', 32),
    ('q', 7, '0102030405', 32),
    ('q', 7, 'ffffffffff', 32),
    ('q', 7, '4041424344', 32),
    ('q', 7, '052a4f7499', 32),
    ('q', 8, '0000', 32),
    ('p', 8, 32, '40414243444546', 0, '40414243444546'),
    ('p', 8, 32, '052a4f7499bee3', 0, '052a4f7499bee3'),
    ('p', 8, 32, '0102030405060708', 0, '0102030405060708'),
    ('p', 8, 32, '000000010000000000000000', 0, '000000010000000000000000'),
    ('p', 8, 32, '0302030405060708', 0, '0302030405060708'),
    ('p', 8, 32, '0402030405060708', 0, '0402030405060708'),
    ('p', 8, 32, '0602030405060708', 0, '0602030405060708'),
    ('p', 8, 32, '0702030405060708', 0, '0702030405060708'),
    ('p', 8, 32, '0802030405060708', 0, '0802030405060708'),
    ('p', 8, 32, '0102030205060708', 0, '0102030205060708'),
    ('p', 8, 32, '0102030505060708', 0, '0102030505060708'),
    ('p', 8, 32, '0102030605060708', 0, '0102030605060708'),
    ('p', 8, 32, '0102030705060708', 0, '0102030705060708'),
    ('p', 8, 32, '02ffffffffffffffffffffff', 0, '02ffffffffffffffffffffff'),
    ('p', 8, 32, 'ffffff00ffffffffffffffff', 0, 'ffffff00ffffffffffffffff'),
    ('r', 8, 192, '', 32),
    ('r', 8, 193, '', 32),
    ('r', 8, 204, '', 32),
    ('r', 8, 213, '', 32),
    ('q', 9, '0000', 32),
    ('q', 9, '0102', 32),
    ('q', 9, 'ffff', 32),
    ('q', 9, '4041', 32),
    ('q', 9, '052a', 32),
    ('q', 9, 'c002030405060708', 32),
    ('q', 9, '0101030405060708', 32),
    ('q', 9, '01c0030405060708', 32),
    ('q', 10, '010203', 32),
    ('q', 10, '404142', 32),
    ('q', 10, '052a4f', 32),
    ('q', 10, '000f00000000000000000000', 32),
    ('q', 10, '000001000000000000000000', 32),
    ('q', 10, '0103030405060708', 32),
    ('q', 10, '0104030405060708', 32),
    ('q', 10, '0105030405060708', 32),
    ('q', 10, '0106030405060708', 32),
    ('q', 10, '0107030405060708', 32),
    ('q', 10, '0108030405060708', 32),
    ('q', 10, '0102040405060708', 32),
    ('q', 10, '0102050405060708', 32),
    ('q', 10, '0102060405060708', 32),
    ('q', 10, '0102070405060708', 32),
    ('q', 10, '0102080405060708', 32),
    ('p', 11, 32, '00', 0, '00'),
    ('p', 11, 32, '01', 0, '01'),
    ('p', 11, 32, 'ff', 0, 'ff'),
    ('p', 11, 32, '05', 0, '05'),
    ('p', 11, 32, '0202030405060708', 0, '0202030405060708'),
    ('p', 11, 32, '0302030405060708', 0, '0302030405060708'),
    ('p', 11, 32, '0402030405060708', 0, '0402030405060708'),
    ('p', 11, 32, '0602030405060708', 0, '0602030405060708'),
    ('p', 11, 32, '0702030405060708', 0, '0702030405060708'),
    ('p', 11, 32, '0802030405060708', 0, '0802030405060708'),
    ('r', 11, 192, '', 32),
    ('r', 11, 193, '', 32),
    ('r', 11, 204, '', 32),
    ('r', 11, 213, '', 32),
    ('q', 12, '0000', 32),
    ('q', 12, '0102', 32),
    ('q', 12, '0101030405060708', 32),
    ('q', 13, '00', 32),
    ('p', 13, 32, '0000', 0, '0000'),
    ('r', 13, 192, '', 32),
    ('r', 13, 193, '', 32),
    ('r', 13, 204, '', 32),
    ('r', 13, 213, '', 32),
    ('q', 20, '00', 32),
    ('p', 20, 32, '00000000', 0, '00000000'),
    ('p', 20, 32, 'ffffffff', 0, 'ffffffff'),
    ('r', 20, 192, '', 32),
    ('r', 20, 193, '', 32),
    ('r', 20, 204, '', 32),
    ('r', 20, 213, '', 32),
    ('q', 21, '000000', 32),
    ('q', 21, 'ffffff', 32),
    ('q', 21, '0102010405060708', 32),
    ('q', 22, '00', 32),
    ('p', 22, 32, '000000', 0, '000000'),
    ('p', 22, 32, 'ffffff', 0, 'ffffff'),
    ('p', 22, 32, '0102010405060708', 0, '0102010405060708'),
    ('r', 22, 192, '', 32),
    ('r', 22, 193, '', 32),
    ('r', 22, 204, '', 32),
    ('r', 22, 213, '', 32),
    ('p', 24, 32, '0000', 0, '0000'),
    ('q', 24, '0102', 32),
    ('q', 24, 'ffff', 32),
    ('r', 24, 192, '', 32),
    ('r', 24, 193, '', 32),
    ('r', 24, 204, '', 32),
    ('r', 24, 213, '', 32),
    ('r', 27, 0, '0000', 32),
    ('r', 27, 192, '', 32),
    ('r', 27, 193, '', 32),
    ('r', 27, 204, '', 32),
    ('r', 27, 213, '', 32),
    ('q', 28, '0000000000', 32),
    ('q', 28, '0102030405', 32),
    ('q', 28, 'ffffffffff', 32),
    ('q', 28, '0101030405060708', 32),
    ('p', 29, 32, '40', 0, '40'),
    ('r', 29, 0, '0000', 32),
    ('r', 29, 0, '0102', 32),
    ('q', 29, '000000', 32),
    ('q', 29, '010203', 32),
    ('q', 29, 'ffffff', 32),
    ('q', 29, '0102010405060708', 32),
    ('q', 29, '0102020405060708', 32),
    ('q', 29, '0102040405060708', 32),
    ('q', 29, '0102050405060708', 32),
    ('q', 29, '0102060405060708', 32),
    ('q', 29, '0102070405060708', 32),
    ('q', 29, '0102080405060708', 32),
    ('q', 29, '01020f0405060708', 32),
    ('q', 29, '0102c00405060708', 32),
    ('p', 29, 32, 'ff01ffffffffffffffffffff', 0, 'ff01ffffffffffffffffffff'),
    ('r', 29, 192, '', 32),
    ('r', 29, 193, '', 32),
    ('r', 29, 204, '', 32),
    ('r', 29, 213, '', 32),
    ('p', 30, 32, '00', 0, '00'),
    ('p', 30, 32, '01', 0, '01'),
    ('p', 30, 32, 'ff', 0, 'ff'),
    ('p', 30, 32, '05', 0, '05'),
    ('p', 30, 32, '0202030405060708', 0, '0202030405060708'),
    ('p', 30, 32, '0302030405060708', 0, '0302030405060708'),
    ('p', 30, 32, '0402030405060708', 0, '0402030405060708'),
    ('p', 30, 32, '0602030405060708', 0, '0602030405060708'),
    ('p', 30, 32, '0702030405060708', 0, '0702030405060708'),
    ('p', 30, 32, '0802030405060708', 0, '0802030405060708'),
    ('p', 30, 32, '0f02030405060708', 0, '0f02030405060708'),
    ('p', 30, 32, '1002030405060708', 0, '1002030405060708'),
    ('p', 30, 32, '5502030405060708', 0, '5502030405060708'),
    ('p', 30, 32, '5702030405060708', 0, '5702030405060708'),
    ('r', 30, 192, '', 32),
    ('r', 30, 193, '', 32),
    ('r', 30, 204, '', 32),
    ('r', 30, 213, '', 32),
    ('q', 31, '00000000', 32),
    ('q', 31, '01020304', 32),
    ('q', 31, 'ffffffff', 32),
    ('p', 31, 32, '000000000000', 0, '000000000000'),
    ('q', 31, '0101030405060708', 32),
    ('q', 31, '0103030405060708', 32),
    ('r', 31, 128, '', 32),
    ('r', 31, 129, '', 32),
    ('r', 31, 192, '', 32),
    ('r', 31, 193, '', 32),
    ('r', 31, 204, '', 32),
    ('r', 31, 213, '', 32),
    ('r', 32, 0, '00', 32),
    ('q', 32, '0000000000', 32),
    ('q', 32, '000000000000', 32),
    ('q', 32, 'ffffffffffff', 32),
    ('q', 32, '052a4f7499be', 32),
    ('q', 32, 'ffffffffffffff', 32),
    ('q', 32, '052a4f7499bee3', 32),
    ('q', 32, 'ffffffffffffffff', 32),
    ('q', 32, 'ffffffffffffffffff', 32),
    ('q', 32, '052a4f7499bee3082d', 32),
    ('q', 32, '0102030405060708090a', 32),
    ('q', 32, 'ffffffffffffffffffff', 32),
    ('q', 32, '052a4f7499bee3082d52', 32),
    ('q', 32, '0102030405060708090a0b0c', 32),
    ('q', 32, 'ffffffffffffffffffffffff', 32),
    ('q', 32, '404142434445464748494a4b', 32),
    ('q', 32, '052a4f7499bee3082d52779c', 32),
    ('q', 32, '0102030405060708090a0b0c0d0e', 32),
    ('q', 32, 'ffffffffffffffffffffffffffff', 32),
    ('q', 32, '404142434445464748494a4b4c4d', 32),
    ('q', 32, '052a4f7499bee3082d52779cc1e6', 32),
    ('q', 32, '0102030405060708090a0b0c0d0e0f10', 32),
    ('q', 32, 'ffffffffffffffffffffffffffffffff', 32),
    ('q', 32, '404142434445464748494a4b4c4d4e4f', 32),
    ('q', 32, '052a4f7499bee3082d52779cc1e60b30', 32),
    ('q', 32, 'ffffffffffffffffffffffffffffffffffffffff', 32),
    ('q', 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4', 32),
    ('q', 32, 'ffffffffffffffffffffffffffffffffffffffffffffffff', 32),
    ('q', 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e3358', 32),
    ('q', 32, '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 32),
    ('q', 32, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 32),
    ('q', 32, '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', 32),
    ('q', 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80', 32),
    ('q', 32, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 32),
    ('p', 32, 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8', 128, ''),
    ('r', 32, 192, '', 32),
    ('r', 32, 193, '', 32),
    ('r', 32, 204, '', 32),
    ('r', 32, 213, '', 32),
    ('q', 33, '00', 32),
    ('p', 33, 32, 'ffffffffffffffffff', 0, 'ffffffffffffffffff'),
    ('p', 33, 32, '052a4f7499bee3082d', 0, '052a4f7499bee3082d'),
    ('p', 33, 32, '0102030405060708090a', 0, '0102030405060708090a'),
    ('p', 33, 32, 'ffffffffffffffffffff', 0, 'ffffffffffffffffffff'),
    ('p', 33, 32, '052a4f7499bee3082d52', 0, '052a4f7499bee3082d52'),
    ('p', 33, 32, '0102030405060708090a0b0c', 0, '0102030405060708090a0b0c'),
    ('p', 33, 32, 'ffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffff'),
    ('p', 33, 32, '404142434445464748494a4b', 0, '404142434445464748494a4b'),
    ('p', 33, 32, '052a4f7499bee3082d52779c', 0, '052a4f7499bee3082d52779c'),
    ('p', 33, 32, '0102030405060708090a0b0c0d0e', 0, '0102030405060708090a0b0c0d0e'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffff'),
    ('p', 33, 32, '404142434445464748494a4b4c4d', 0, '404142434445464748494a4b4c4d'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e6', 0, '052a4f7499bee3082d52779cc1e6'),
    ('p', 33, 32, '00000000000000000000000000000000', 0, '00000000000000000000000000000000'),
    ('p', 33, 32, '0102030405060708090a0b0c0d0e0f10', 0, '0102030405060708090a0b0c0d0e0f10'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffffffff'),
    ('p', 33, 32, '404142434445464748494a4b4c4d4e4f', 0, '404142434445464748494a4b4c4d4e4f'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e60b30', 0, '052a4f7499bee3082d52779cc1e60b30'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffffffffffffffff'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4', 0, '052a4f7499bee3082d52779cc1e60b30557a9fc4'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffffffffffffffffffffffff'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e3358', 0, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e3358'),
    ('p', 33, 32, '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', 0, '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
    ('p', 33, 32, '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f', 0, '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80', 0, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80'),
    ('p', 33, 32, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 0, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
    ('p', 33, 32, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8', 0, '052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8'),
    ('r', 33, 192, '', 32),
    ('r', 33, 193, '', 32),
    ('r', 33, 204, '', 32),
    ('r', 33, 213, '', 32),
    ('q', 64, '00000000', 32),
    ('q', 64, '01020304', 32),
    ('q', 64, 'ffffffff', 32),
    ('p', 64, 32, '010203040506', 0, '010203040506'),
    ('p', 64, 32, 'ffffffffffff', 0, 'ffffffffffff'),
    ('p', 64, 32, '0000000000000000', 0, '0000000000000000'),
    ('q', 64, '0101030405060708', 32),
    ('q', 64, '0103030405060708', 32),
    ('q', 64, '0102030105060708', 32),
    ('q', 64, '0102030205060708', 32),
    ('q', 64, '0102030305060708', 32),
    ('q', 64, '0102030505060708', 32),
    ('q', 64, '0102030605060708', 32),
    ('q', 64, '0102030705060708', 32),
    ('q', 64, '0102030805060708', 32),
    ('q', 64, '0102030f05060708', 32),
    ('q', 64, '010203c005060708', 32),
    ('r', 64, 192, '', 32),
    ('r', 64, 193, '', 32),
    ('r', 64, 204, '', 32),
    ('r', 64, 213, '', 32),
    ('p', 65, 32, '00', 0, '00'),
    ('p', 65, 32, '01', 0, '01'),
    ('p', 65, 32, 'ff', 0, 'ff'),
    ('p', 65, 32, '0202030405060708', 0, '0202030405060708'),
    ('r', 65, 192, '', 32),
    ('r', 65, 193, '', 32),
    ('r', 65, 204, '', 32),
    ('r', 65, 213, '', 32),
    ('q', 66, '000000', 32),
    ('q', 66, '010203', 32),
    ('q', 66, '404142', 32),
    ('q', 66, 'ffff01ffffffffffffffffff', 32),
    ('p', 67, 32, '00', 0, '00'),
    ('p', 67, 32, '01', 0, '01'),
    ('p', 67, 32, 'ff', 0, 'ff'),
    ('p', 67, 32, '0202030405060708', 0, '0202030405060708'),
    ('r', 67, 192, '', 32),
    ('r', 67, 193, '', 32),
    ('r', 67, 204, '', 32),
    ('r', 67, 213, '', 32),
    ('q', 68, '00', 32),
    ('p', 68, 32, '000000000000', 0, '000000000000'),
    ('r', 68, 192, '', 32),
    ('r', 68, 193, '', 32),
    ('r', 68, 204, '', 32),
    ('r', 68, 213, '', 32),
    ('q', 0, '', 32),
    ('q', 2, '', 32),
    ('r', 3, 0, '', 32),
    ('r', 4, 0, '', 32),
    ('r', 7, 0, '', 32),
    ('r', 9, 0, '', 32),
    ('r', 10, 0, '', 32),
    ('r', 12, 0, '', 32),
    ('r', 21, 0, '', 32),
    ('q', 27, '', 32),
    ('r', 28, 0, '', 32),
    ('r', 66, 0, '', 32),
]

# --- Malformed messages -------------------------------------------------
MALFORMED = [
    ('r', 0, 0, '0102', 32),
    ('r', 0, 0, '4041', 32),
    ('r', 0, 0, 'ffffff', 32),
    ('r', 0, 0, '0000000000', 32),
    ('r', 1, 0, '0000000000', 32),
    ('r', 2, 0, '01', 32),
    ('q', 3, '01', 32),
    ('q', 4, '00', 32),
    ('r', 5, 0, '00', 32),
    ('q', 6, '00', 32),
    ('r', 6, 0, '052a', 32),
    ('r', 6, 0, '000000', 32),
    ('r', 6, 0, '010203', 32),
    ('r', 6, 0, 'ffffff', 32),
    ('r', 6, 0, '404142', 32),
    ('q', 7, '010203', 32),
    ('q', 7, 'ffffff', 32),
    ('q', 7, '00000000', 32),
    ('q', 8, '00', 32),
    ('r', 8, 0, '05', 32),
    ('r', 8, 0, '0102030405', 32),
    ('r', 8, 0, 'ffffffffff', 32),
    ('r', 8, 0, '4041424344', 32),
    ('r', 8, 0, '000000000000', 32),
    ('q', 9, '00', 32),
    ('q', 9, '01', 32),
    ('q', 9, 'ff', 32),
    ('q', 9, '40', 32),
    ('q', 9, '05', 32),
    ('q', 10, '0000', 32),
    ('q', 10, '0102', 32),
    ('q', 10, 'ffff', 32),
    ('q', 10, '4041', 32),
    ('q', 10, '052a', 32),
    ('q', 12, '00', 32),
    ('r', 13, 0, '00', 32),
    ('r', 20, 0, '000000', 32),
    ('q', 21, '00', 32),
    ('p', 24, 32, '00', 0, '00'),
    ('q', 24, '01', 32),
    ('q', 24, 'ff', 32),
    ('r', 27, 0, '00', 32),
    ('q', 28, '00000000', 32),
    ('q', 28, '01020304', 32),
    ('q', 28, 'ffffffff', 32),
    ('q', 29, '0000', 32),
    ('p', 31, 32, '0000', 0, '0000'),
    ('q', 31, '0102', 32),
    ('q', 31, 'ffff', 32),
    ('r', 31, 128, '01', 32),
    ('r', 31, 129, '01', 32),
    ('q', 32, '000000', 32),
    ('r', 33, 0, '010203040506', 32),
    ('r', 33, 0, 'ffffffffffff', 32),
    ('r', 33, 0, '0000000000000000000000000000', 32),
    ('r', 64, 0, '0000000000', 32),
    ('q', 66, '0000', 32),
    ('q', 66, '0102', 32),
    ('q', 66, 'ffff', 32),
    ('q', 66, '4041', 32),
    ('r', 68, 0, '0000000000', 32),
]


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    pcap(os.path.join(outdir, 'ipmi_vita-coverage.pcap'), build(REPRO + MAIN))
    pcap(os.path.join(outdir, 'ipmi_vita-coverage-malformed.pcap'), build(MALFORMED))


if __name__ == '__main__':
    main(sys.argv[1])

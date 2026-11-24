#!/usr/bin/env python3
# Generates test/captures/enrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ENRP dissector
(packet-enrp.c, Endpoint Handlespace Redundancy Protocol, RFC 5353).

ENRP runs over SCTP (PPI 12 or port 9901) and UDP port 9901, all
registered by default. A message is type, flags, length, sender and
receiver server IDs and a list of TLV parameters (RFC 5354): addresses,
transport parameters with nested addresses, pool handle, pool element,
member selection policies, server information, operation errors with
error causes (which nest parameters and whole ENRP messages), cookie, PE
identifier and checksum. Every packet is built from scratch with struct;
no captured traffic is used.

Usage: mkenrp.py <output directory>

Writes:
  enrp-coverage.pcap            every message type and flag, every
                                parameter, policy and error cause,
                                padding, nested messages up to the
                                recursion limit, bundled SCTP DATA chunks
  enrp-coverage-malformed.pcap  parameter and cause lengths below 4,
                                parameters and messages cut short
"""

import os
import struct
import sys

from pktlib import pcap, udp_frame, sctp_frame, sctp_data_chunk  # noqa: E402

PORT = 9901
PPI = 12

SRV_A = 0x0a0a0001
SRV_B = 0x0b0b0002


def pad4(b):
    return b + bytes((-len(b)) % 4)


def param(typ, value, length=None, pad=True):
    """TLV parameter; length defaults to 4 + len(value), padded to 4."""
    p = struct.pack('!HH', typ, 4 + len(value) if length is None else length) + value
    return pad4(p) if pad else p


def ipv4(a):
    return param(0x01, bytes(a))


def ipv6(last):
    return param(0x02, bytes.fromhex('20010db8000000000000000000000000')[:15] + bytes([last]))


def dccp_tp(port, svc, *addrs):
    return param(0x03, struct.pack('!HHI', port, 0, svc) + b''.join(addrs))


def sctp_tp(port, use, *addrs):
    return param(0x04, struct.pack('!HH', port, use) + b''.join(addrs))


def tcp_tp(port, use, *addrs):
    return param(0x05, struct.pack('!HH', port, use) + b''.join(addrs))


def udp_tp(port, *addrs):
    return param(0x06, struct.pack('!HH', port, 0) + b''.join(addrs))


def udplite_tp(port, *addrs):
    return param(0x07, struct.pack('!HH', port, 0) + b''.join(addrs))


def policy(ptype, *vals, raw=None):
    v = struct.pack('!I', ptype) + (raw if raw is not None else b''.join(struct.pack('!I', x) for x in vals))
    return param(0x08, v)


def pool_handle(name):
    return param(0x09, name)


def pool_element(pe_id, home, life, *params):
    return param(0x0a, struct.pack('!III', pe_id, home, life) + b''.join(params))


def server_info(sid, *params):
    return param(0x0b, struct.pack('!I', sid) + b''.join(params))


def cause(code, info=b''):
    return pad4(struct.pack('!HH', code, 4 + len(info)) + info)


def op_error(*causes):
    return param(0x0c, b''.join(causes))


def cookie(data):
    return param(0x0d, data)


def pe_id(x):
    return param(0x0e, struct.pack('!I', x))


def pe_checksum(x):
    return param(0x0f, struct.pack('!H', x))


def msg(typ, flags, body):
    return struct.pack('!BBH', typ, flags, 4 + len(body)) + body


def ids(s=SRV_A, r=SRV_B):
    return struct.pack('!II', s, r)


def sample_pe(n):
    return pool_element(0x100 + n, SRV_A, 30000 + n,
                        sctp_tp(5000 + n, 1, ipv4((10, 1, 0, n)), ipv6(n)),
                        policy(0x00000001))


def main_frames():
    F = []

    def u(m, rev=False):
        F.append(udp_frame(PORT, PORT, m, rev=rev, ident=len(F) + 1))

    # 1: Presence, reply required, with a pool handle, a pool element
    #    (SCTP transport with IPv4 and IPv6 addresses, round robin) and
    #    a server information parameter
    u(msg(1, 0x01, ids() + pool_handle(b'echo-pool') + sample_pe(1)
          + server_info(SRV_A, sctp_tp(9901, 1, ipv4((10, 0, 0, 1)))) + pe_checksum(0xbeef)))
    # 2: Presence, no reply required, no parameters
    u(msg(1, 0x00, ids(SRV_B, SRV_A)), rev=True)
    # 3: Handle table request, own children only; 4: all PEs
    u(msg(2, 0x01, ids()))
    u(msg(2, 0x00, ids()))
    # 5: Handle table response, more to send, accepted: every transport
    #    parameter and every selection policy
    pes = [
        pool_element(0x201, SRV_B, 1000,
                     dccp_tp(5001, 0x11223344, ipv4((10, 2, 0, 1))),
                     policy(0x00000002, 7)),
        pool_element(0x202, SRV_B, 1000,
                     tcp_tp(5002, 0, ipv4((10, 2, 0, 2)), ipv6(2)),
                     policy(0x00000003)),
        pool_element(0x203, SRV_B, 1000,
                     udp_tp(5003, ipv4((10, 2, 0, 3))),
                     policy(0x00000004, 9)),
        pool_element(0x204, SRV_B, 1000,
                     udplite_tp(5004, ipv6(4)),
                     policy(0x00000005, 3)),
        pool_element(0x205, SRV_B, 1000, policy(0x40000001, 0x80000000)),
        pool_element(0x206, SRV_B, 1000, policy(0x40000002, 0x40000000, 0x20000000)),
        pool_element(0x207, SRV_B, 1000, policy(0x40000003, 0xffffffff, 0)),
        pool_element(0x208, SRV_B, 1000, policy(0x40000004, 0x10000000)),
        pool_element(0x209, SRV_B, 1000, policy(0xb0002002, 0x80000000, 0x40000000, 1500)),
        pool_element(0x20a, SRV_B, 1000, policy(0xb0002001, 5, 0x20000000, 250)),
        # PLUD is named but has no case of its own: shown as a value
        pool_element(0x20b, SRV_B, 1000, policy(0xb0001003, 1, 2, 3)),
        # unknown policy with and without a value
        pool_element(0x20c, SRV_B, 1000, policy(0x12345678, raw=b'\x01\x02\x03\x04')),
        pool_element(0x20d, SRV_B, 1000, policy(0x12345679, raw=b'')),
    ]
    u(msg(3, 0x02, ids(SRV_B, SRV_A) + pool_handle(b'echo-pool') + b''.join(pes)), rev=True)
    # 6: Handle table response, rejected
    u(msg(3, 0x01, ids(SRV_B, SRV_A)), rev=True)
    # 7: Handle update, add, takeover suggested; 8: delete
    u(msg(4, 0x01, ids() + struct.pack('!HH', 0, 0) + pool_handle(b'echo-pool') + sample_pe(2)))
    u(msg(4, 0x00, ids() + struct.pack('!HH', 1, 0) + pool_handle(b'echo-pool') + pe_id(0x102)))
    # 9: List request; 10: list response with server information
    u(msg(5, 0x00, ids()))
    u(msg(6, 0x00, ids(SRV_B, SRV_A)
          + server_info(SRV_B, sctp_tp(9901, 1, ipv4((10, 0, 0, 2))))
          + server_info(0x0c0c0003, udp_tp(9901, ipv6(3)))), rev=True)
    # 11: List response, rejected
    u(msg(6, 0x01, ids(SRV_B, SRV_A)), rev=True)
    # 12-14: Init takeover, its ack, takeover server
    u(msg(7, 0x00, ids() + struct.pack('!I', 0x0d0d0004)))
    u(msg(8, 0x00, ids(SRV_B, SRV_A) + struct.pack('!I', 0x0d0d0004)), rev=True)
    u(msg(9, 0x00, ids() + struct.pack('!I', 0x0d0d0004)))
    # 15: Error with an operation error holding every cause
    causes = [
        cause(1, param(0x8001, b'\xaa\xbb\xcc')),           # unrecognized parameter
        cause(2, msg(0x20, 0x00, b'\x01\x02\x03\x04')),       # unrecognized message
        cause(3, pe_id(0x999)),                             # invalid values
        cause(4),                                           # non-unique PE identifier
        cause(5, policy(0x00000001)),                       # policy inconsistent
        cause(6),                                           # lack of resources
        cause(7, sctp_tp(5000, 0, ipv4((10, 3, 0, 1)))),    # inconsistent transport
        cause(8),                                           # data/control config
        cause(9),                                           # unknown pool handle
        cause(10),                                          # security
        cause(0x77, b'\x01\x02\x03\x04\x05'),               # unknown, info, padding
        cause(0x78),                                        # unknown, no information
    ]
    u(msg(10, 0x00, ids(SRV_B, SRV_A) + op_error(*causes)), rev=True)
    # 16: Error whose unrecognized message is a known ENRP message
    u(msg(10, 0x00, ids(SRV_B, SRV_A) + op_error(cause(2, msg(5, 0, ids())))), rev=True)
    # 17: unknown message type
    u(msg(0x42, 0x5a, b'\xde\xad\xbe\xef\x01\x02'))
    # 18: cookie (with data and empty), PE identifier, unknown parameters
    #     with and without a value, an IPv4 address, a parameter whose
    #     padding runs to the end of the message
    u(msg(1, 0x00, ids() + cookie(b'cookie-data!!') + cookie(b'') + pe_id(0xcafe)
          + param(0x4444, b'\x01\x02') + param(0x4445, b'') + ipv4((192, 0, 2, 1))
          + param(0x4446, b'\x09', pad=False) + b'\x00\x00\x00'))
    # 19: Error messages nested through "unrecognized message" causes
    #     until the recursion limit (warning, decoding stops there)
    inner = msg(5, 0, ids())
    for _ in range(6):
        inner = msg(10, 0, ids() + op_error(cause(2, inner)))
    u(inner)
    # 20: the same, but the chain starts inside a transport parameter, so
    #     the limit is reached when a nested message starts
    inner = msg(5, 0, ids())
    for _ in range(6):
        inner = msg(10, 0, ids() + op_error(cause(2, inner)))
    u(msg(1, 0, ids() + sctp_tp(9901, 1, op_error(cause(2, inner)))))
    # 21: Presence after the deeply nested messages: decoded normally
    u(msg(1, 0x01, ids() + pool_handle(b'after')))
    # 22: twelve List Requests bundled in one SCTP packet (PPI 12), the
    #     reproducer of the recursion depth fix: every one is decoded
    chunks = [sctp_data_chunk(100 + i, 0, i, PPI, msg(5, 0, ids(0x1000 + i, 0x2000 + i)))
              for i in range(12)]
    F.append(sctp_frame(PORT, PORT, 0x01020304, chunks))
    # 23: SCTP on port 9901 with PPI 0 (by port), a handle update and a
    #     presence bundled
    chunks = [sctp_data_chunk(200, 1, 0, 0, msg(4, 0, ids() + struct.pack('!HH', 0, 0)
                                                + pool_handle(b'p') + sample_pe(3))),
              sctp_data_chunk(201, 1, 1, PPI, msg(1, 0, ids()))]
    F.append(sctp_frame(40001, PORT, 0x05060708, chunks))
    return F


def malformed_frames():
    F = []

    def u(m):
        F.append(udp_frame(PORT, PORT, m, ident=len(F) + 1))

    # parameter length below 4
    u(msg(1, 0, ids() + struct.pack('!HH', 0x09, 2)))
    # error cause length below 4
    u(msg(10, 0, ids() + param(0x0c, struct.pack('!HH', 4, 1) + bytes(4))))
    # parameter longer than the message (IPv4 address with length 40)
    u(msg(1, 0, ids()) + struct.pack('!HH', 0x01, 40) + bytes(4))
    # IPv6 parameter cut short
    u(msg(1, 0, ids() + param(0x02, bytes(8))))
    # policy cut short (LU-DPF without its values)
    u(msg(3, 0, ids() + pool_element(1, 2, 3, policy(0xb0002002, raw=b''))))
    # message header only
    u(b'\x01\x00\x00\x04')
    # error cause with length 0xFFFD (rounds up past 16 bits)
    u(msg(10, 0, ids() + param(0x0c, struct.pack('!HH', 0x77, 0xfffd) + bytes(8))))
    # an exception inside the first of two bundled SCTP messages: the
    # second is still decoded
    chunks = [sctp_data_chunk(1, 0, 0, PPI, msg(1, 0, ids()) + struct.pack('!HH', 0x02, 20)),
              sctp_data_chunk(2, 0, 1, PPI, msg(5, 0, ids()))]
    F.append(sctp_frame(PORT, PORT, 0x0a0b0c0d, chunks))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'enrp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'enrp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

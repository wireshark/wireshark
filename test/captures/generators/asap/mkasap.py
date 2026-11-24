#!/usr/bin/env python3
# Generates test/captures/asap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ASAP dissector (packet-asap.c).

All packets are built from scratch with struct; no captured traffic is
used. A pool element / pool user (192.0.2.1) talks ASAP (RFC 5352) to an
ENRP server (192.0.2.2) over SCTP (PPI 11, and port 3863 with PPI 0), UDP
port 3863 and TCP port 3863.

Usage: mkasap.py <output directory>

Writes:
  asap-coverage.pcap               every message type, every parameter,
                                   every policy and error cause, bundled
                                   and fragmented SCTP messages, ASAP over
                                   UDP and TCP, the branch reproducers
  asap-coverage-malformed.pcapng   paths that end in an exception, the TCP
                                   segment with two messages, and frames
                                   without a time stamp (Simple Packet
                                   Blocks) for the statistics
"""

import os
import struct
import sys

PE = '192.0.2.1'
ENRP = '192.0.2.2'
PPI_ASAP = 11


# --------------------------------------------------------------------------
# Link, IP and transport layers (checksums of TCP/UDP/SCTP left at 0; they
# are not verified by default)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip(proto, payload, src=PE, dst=ENRP):
    a = bytes(map(int, src.split('.')))
    b = bytes(map(int, dst.split('.')))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    eth = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01' if src == PE else b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02'
    return eth + b'\x08\x00' + h + payload


def udp(sport, dport, data, src=PE, dst=ENRP):
    return ip(17, struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data, src, dst)


def tcp(sport, dport, data, seq, ack=1, src=PE, dst=ENRP):
    return ip(6, struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, 0x18, 65535, 0, 0) + data,
              src, dst)


def sctp(sport, dport, chunks, vtag=0x11223344, src=PE, dst=ENRP):
    return ip(132, struct.pack('!HHII', sport, dport, vtag, 0) + b''.join(chunks), src, dst)


def data_chunk(tsn, ppi, payload, flags=3, sid=0, ssn=0):
    ln = 16 + len(payload)
    return struct.pack('!BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppi) + payload + b'\0' * ((-ln) % 4)


# --------------------------------------------------------------------------
# ASAP encoding

def param(t, v, pad=True):
    ln = 4 + len(v)
    return struct.pack('!HH', t, ln) + v + (b'\0' * ((-ln) % 4) if pad else b'')


def msg(t, body, flags=0, length=None):
    return struct.pack('!BBH', t, flags, 4 + len(body) if length is None else length) + body


def cause(code, info=b''):
    ln = 4 + len(info)
    return struct.pack('!HH', code, ln) + info + b'\0' * ((-ln) % 4)


REGISTRATION, DEREGISTRATION, REGISTRATION_RESPONSE, DEREGISTRATION_RESPONSE = 1, 2, 3, 4
HANDLE_RESOLUTION, HANDLE_RESOLUTION_RESPONSE, KEEP_ALIVE, KEEP_ALIVE_ACK = 5, 6, 7, 8
UNREACHABLE, SERVER_ANNOUNCE, COOKIE, COOKIE_ECHO, BUSINESS_CARD, ERROR = 9, 10, 11, 12, 13, 14


def ipv4(a):
    return param(1, bytes(map(int, a.split('.'))))


def ipv6(last):
    return param(2, bytes.fromhex('20010db8000000000000000000000000')[:15] + bytes([last]))


def dccp_tp(port, service, *addrs):
    return param(3, struct.pack('!HHI', port, 0, service) + b''.join(addrs))


def sctp_tp(port, use, *addrs):
    return param(4, struct.pack('!HH', port, use) + b''.join(addrs))


def tcp_tp(port, use, *addrs):
    return param(5, struct.pack('!HH', port, use) + b''.join(addrs))


def udp_tp(port, *addrs):
    return param(6, struct.pack('!HH', port, 0) + b''.join(addrs))


def udplite_tp(port, *addrs):
    return param(7, struct.pack('!HH', port, 0) + b''.join(addrs))


def policy(ptype, *words):
    return param(8, struct.pack('!I', ptype) + b''.join(struct.pack('!I', w) for w in words))


def handle(name):
    return param(9, name)


def pool_element(peid, home, life, *params):
    return param(10, struct.pack('!IIi', peid, home, life) + b''.join(params))


def server_info(sid, *params):
    return param(11, struct.pack('!I', sid) + b''.join(params))


def operation_error(*causes):
    return param(12, b''.join(causes))


def cookie(data):
    return param(13, data)


def pe_id(peid):
    return param(14, struct.pack('!I', peid))


def pe_checksum(c):
    return param(15, struct.pack('!H', c))


def hropt(items):
    return param(0x803f, struct.pack('!I', items))


RR, WRR, RAND, WRAND, PRI = 1, 2, 3, 4, 5
LU, LUD, PLU, RLU = 0x40000001, 0x40000002, 0x40000003, 0x40000004
PLUD, WRANDDPF, LUDPF = 0xb0001003, 0xb0002001, 0xb0002002

POOL = b'echo-pool'   # 9 octets: the Pool Handle parameter has 3 octets of padding


def pe(peid, *extra):
    """A typical pool element: user transport, policy, ASAP transport."""
    return pool_element(peid, 0x2000, 30000,
                        sctp_tp(7, 0, ipv4('192.0.2.%d' % (peid & 0xff)), ipv6(peid & 0xff)),
                        policy(RR), *extra)


# --------------------------------------------------------------------------
# Capture writers

class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data):
        self.frames.append(data)

    def write(self, name):
        with open(name, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.frames):
                f.write(struct.pack('<IIII', i, 0, len(p), len(p)) + p)


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    ln = 12 + len(body)
    return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)


class Pcapng:
    """Enhanced Packet Blocks, or Simple Packet Blocks (no time stamp)."""
    def __init__(self):
        self.blocks = []
        self.n = 0

    def add(self, data, simple=False, ts=None):
        if simple:
            self.blocks.append(pcapng_block(3, struct.pack('<I', len(data)) + data))
        else:
            ts = (self.n if ts is None else ts) * 1000000
            self.blocks.append(pcapng_block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff,
                                                           len(data), len(data)) + data))
        self.n += 1

    def write(self, name):
        shb = pcapng_block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        idb = pcapng_block(1, struct.pack('<HHI', 1, 0, 0))
        with open(name, 'wb') as f:
            f.write(shb + idb + b''.join(self.blocks))


class Assoc:
    """One SCTP association (both directions), TSNs counted per direction."""
    def __init__(self, sport, dport, vtag, ppi=PPI_ASAP):
        self.sport, self.dport, self.vtag, self.ppi = sport, dport, vtag, ppi
        self.tsn = {True: 1000, False: 5000}
        self.ssn = {}

    def chunk(self, m, to_server=True, sid=0, flags=3, ppi=None):
        tsn = self.tsn[to_server]
        self.tsn[to_server] += 1
        key = (to_server, sid)
        ssn = self.ssn.get(key, 0)
        if flags & 1:
            self.ssn[key] = (ssn + 1) & 0xffff
        return data_chunk(tsn, self.ppi if ppi is None else ppi, m, flags=flags, sid=sid, ssn=ssn)

    def pkt(self, chunks, to_server=True):
        if to_server:
            return sctp(self.sport, self.dport, chunks, self.vtag, PE, ENRP)
        return sctp(self.dport, self.sport, chunks, self.vtag ^ 0xffffffff, ENRP, PE)

    def send(self, m, to_server=True, **kw):
        return self.pkt([self.chunk(m, to_server, **kw)], to_server)


# --------------------------------------------------------------------------
# Main capture

def every_cause():
    return operation_error(
        cause(1, param(0x7777, b'\x01\x02\x03')),                     # Unrecognized parameter
        cause(2, msg(0x20, param(0x7777, b'xyz'))),                   # Unrecognized message (nested)
        cause(2, msg(REGISTRATION, handle(POOL))),                    # Unrecognized message, known type
        cause(3, policy(PRI, 7)),                                     # Invalid values
        cause(4),                                                     # Non-unique PE identifier
        cause(5, policy(0x12345678, 1, 2)),                           # Pooling policy inconsistent
        cause(6),                                                     # Lack of resources
        cause(7, tcp_tp(80, 1, ipv4('192.0.2.80'))),                  # Inconsistent transport type
        cause(8),                                                     # Inconsistent data/control
        cause(9),                                                     # Unknown pool handle
        cause(10),                                                    # Rejected (security)
        cause(0x99, b'\xde\xad\xbe\xef'),                             # unknown cause with info
        cause(0x9a),                                                  # unknown cause, no info
        cause(0x9b, b'\x55'))                                         # unknown, 1 octet + 3 padding


def main_capture(out):
    p = Pcap()
    a = Assoc(40001, 3863, 0x0a0b0c0d)

    # 1: Registration with a pool element that carries every transport
    # parameter, both address types, every transport use, and a PE checksum
    p.add(a.send(msg(REGISTRATION, handle(POOL) + pool_element(
        0x1001, 0x2000, 30000,
        sctp_tp(7, 1, ipv4('192.0.2.1'), ipv6(1)),
        tcp_tp(8080, 0, ipv4('192.0.2.1'), ipv6(1)),
        udp_tp(9000, ipv4('192.0.2.1'), ipv6(1)),
        udplite_tp(9001, ipv6(1)),
        dccp_tp(9002, 0x12345678, ipv4('192.0.2.1')),
        policy(WRAND, 10),
        sctp_tp(3863, 1, ipv4('192.0.2.1'))) + pe_checksum(0xbeef))))
    # 2: Registration Response, R bit set, with an Operation Error
    p.add(a.send(msg(REGISTRATION_RESPONSE, handle(POOL) + pe_id(0x1001) +
                     operation_error(cause(9)), flags=1), to_server=False))
    # 3: Registration Response, accepted
    p.add(a.send(msg(REGISTRATION_RESPONSE, handle(POOL) + pe_id(0x1001)), to_server=False))
    # 4, 5: Deregistration and its response
    p.add(a.send(msg(DEREGISTRATION, handle(POOL) + pe_id(0x1001))))
    p.add(a.send(msg(DEREGISTRATION_RESPONSE, handle(POOL) + pe_id(0x1001)), to_server=False))
    # 6: Handle Resolution with a Handle Resolution Option
    p.add(a.send(msg(HANDLE_RESOLUTION, handle(POOL) + hropt(3))))
    # 7: Handle Resolution Response: pool elements with every policy type
    policies = [policy(RR), policy(WRR, 5), policy(RAND), policy(WRAND, 6), policy(PRI, 2),
                policy(LU, 0x40000000), policy(RLU, 0xffffffff),
                policy(LUD, 0x80000000, 0x10000000), policy(PLU, 0x20000000, 0x08000000),
                policy(LUDPF, 0x40000000, 0x80000000, 25), policy(WRANDDPF, 8, 0x40000000, 50),
                policy(PLUD, 1, 2, 3), policy(0x7fffffff)]
    p.add(a.send(msg(HANDLE_RESOLUTION_RESPONSE, handle(POOL) + policy(RR) + b''.join(
        pool_element(0x3000 + i, 0x2000, 30000, sctp_tp(7, 0, ipv4('192.0.2.%d' % (10 + i))), pol)
        for i, pol in enumerate(policies))), to_server=False))
    # 8: Endpoint Keep-Alive, H bit set; 9: its Acknowledgement
    p.add(a.send(msg(KEEP_ALIVE, struct.pack('!I', 0x2000) + handle(POOL) + pe_id(0x1001), flags=1),
                 to_server=False))
    p.add(a.send(msg(KEEP_ALIVE_ACK, handle(POOL) + pe_id(0x1001))))
    # 10: Endpoint Unreachable
    p.add(a.send(msg(UNREACHABLE, handle(POOL) + pe_id(0x3001))))
    # 11: Server Announce with transport addresses and a Server Information parameter
    p.add(a.send(msg(SERVER_ANNOUNCE, struct.pack('!I', 0x2000) +
                     sctp_tp(3863, 1, ipv4('192.0.2.2'), ipv6(2)) +
                     server_info(0x2001, sctp_tp(9901, 1, ipv4('192.0.2.3')))), to_server=False))
    # 12: Cookie, 13: Cookie Echo, 14: Cookie with an empty and a 1 octet cookie
    p.add(a.send(msg(COOKIE, cookie(b'cookie-data-0123')), to_server=False))
    p.add(a.send(msg(COOKIE_ECHO, cookie(b'cookie-data-0123'))))
    p.add(a.send(msg(COOKIE, cookie(b'') + cookie(b'\x01')), to_server=False))
    # 15: Business Card
    p.add(a.send(msg(BUSINESS_CARD, handle(POOL) + pe(0x1001) + pe(0x1002))))
    # 16: Error with every cause (two Unrecognized message causes with
    # nested messages, which are neither tapped nor shown in Info)
    p.add(a.send(msg(ERROR, every_cause()), to_server=False))
    # 17: undefined message type with unknown parameters of 5, 0 and 1 octets
    p.add(a.send(msg(0x20, param(0x7777, b'\x01\x02\x03\x04\x05') + param(0x7778, b'') + param(0x7779, b'\x01'))))
    # 18: messages without parameters: Deregistration of length 4 and a
    # Keep-Alive of length 8 (just the server identifier), bundled
    p.add(a.pkt([a.chunk(msg(DEREGISTRATION, b'')),
                 a.chunk(msg(KEEP_ALIVE, struct.pack('!I', 0x2000)), sid=1)]))
    # 19: message Length without the padding of the last parameter
    # (the last parameter is cut to the message end)
    body = handle(POOL) + handle(b'pool1')
    p.add(a.send(msg(HANDLE_RESOLUTION, body, length=4 + len(body) - 3)))
    # 20: three messages bundled in one SCTP packet
    p.add(a.pkt([a.chunk(msg(HANDLE_RESOLUTION, handle(POOL)), sid=0),
                 a.chunk(msg(KEEP_ALIVE_ACK, handle(POOL) + pe_id(0x1002)), sid=1),
                 a.chunk(msg(DEREGISTRATION, handle(POOL) + pe_id(0x1002)), sid=2)]))
    # 21-23: a Handle Resolution Response in three SCTP fragments
    big = msg(HANDLE_RESOLUTION_RESPONSE, handle(POOL) + policy(LU, 0x10000000) +
              b''.join(pe(0x4000 + i) for i in range(12)))
    third = len(big) // 3
    p.add(a.send(big[:third], to_server=False, flags=2))
    p.add(a.send(big[third:2 * third], to_server=False, flags=0))
    p.add(a.send(big[2 * third:], to_server=False, flags=1))
    # 24: ASAP on SCTP port 3863 with PPI 0 (found by the port)
    b = Assoc(40002, 3863, 0x01020304, ppi=0)
    p.add(b.send(msg(HANDLE_RESOLUTION, handle(POOL))))
    # 25, 26: ASAP over UDP port 3863, request and response
    p.add(udp(40003, 3863, msg(HANDLE_RESOLUTION, handle(POOL) + hropt(1))))
    p.add(udp(3863, 40003, msg(HANDLE_RESOLUTION_RESPONSE, handle(POOL) + policy(RAND) + pe(0x1001)),
              ENRP, PE))
    # 27, 28: ASAP over TCP port 3863, one message per segment
    m1 = msg(REGISTRATION, handle(POOL) + pe(0x1003))
    m2 = msg(REGISTRATION_RESPONSE, handle(POOL) + pe_id(0x1003))
    p.add(tcp(40004, 3863, m1, seq=1, ack=1))
    p.add(tcp(3863, 40004, m2, seq=1, ack=1 + len(m1), src=ENRP, dst=PE))
    # 29: reproducer asap_dccp_service_code.py: DCCP transport
    # parameter with a 32-bit service code, over UDP
    p.add(udp(40000, 3863, msg(REGISTRATION, dccp_tp(5000, 0x12345678, ipv4('192.0.2.9')))))
    # 30, 31: reproducer asap_in_error_pkt.py: an Error with an
    # Operation Error, then the first fragment of a Registration and a
    # complete Keep-Alive in the same SCTP packet; the last fragment follows
    err = msg(ERROR, param(0x0c, struct.pack('!HH', 9, 4)))
    reg = msg(REGISTRATION, param(9, b'poolhandle') + param(10, struct.pack('!III', 1, 2, 1000) +
              param(4, struct.pack('!HH', 5000, 0) + param(1, bytes([192, 0, 2, 9])))))
    half = len(reg) // 2
    ka = msg(KEEP_ALIVE, struct.pack('!I', 0xabcdef01) + param(9, b'pool'))
    p.add(sctp(3863, 3863, [data_chunk(1, 11, err, sid=0, ssn=0),
                            data_chunk(2, 11, reg[:half], flags=2, sid=1, ssn=0),
                            data_chunk(4, 11, ka, sid=2, ssn=0)]))
    p.add(sctp(3863, 3863, [data_chunk(3, 11, reg[half:], flags=1, sid=1, ssn=0)]))
    p.write(os.path.join(out, 'asap-coverage.pcap'))


# --------------------------------------------------------------------------
# Malformed / extra capture (pcapng)

def malformed_capture(out):
    p = Pcapng()
    a = Assoc(40011, 3863, 0x55667788)
    bad = [
        msg(REGISTRATION, b'', length=0)[:2],                          # truncated header
        msg(REGISTRATION, struct.pack('!HH', 9, 40) + b'abcd'),          # parameter past the message
        msg(REGISTRATION, struct.pack('!HH', 9, 0) + b'abcd'),           # parameter length 0
        msg(REGISTRATION, struct.pack('!HH', 9, 2) + b'abcd'),           # parameter length 2
        msg(REGISTRATION, struct.pack('!HH', 0x7777, 2) + b'abcd'),      # unknown, length 2
        msg(COOKIE, struct.pack('!HH', 13, 2) + b'abcd'),                # cookie, length 2
        msg(REGISTRATION, param(1, b'\x01\x02')),                        # short IPv4
        msg(REGISTRATION, param(2, b'\x01' * 8)),                        # short IPv6
        msg(REGISTRATION, param(10, b'\0' * 6)),                         # short pool element
        msg(REGISTRATION, param(8, b'')),                                # policy without type
        msg(REGISTRATION, policy(LUDPF, 1)),                             # short LU-DPF
        msg(REGISTRATION, param(15, b'')),                               # empty checksum
        msg(ERROR, operation_error(struct.pack('!HH', 4, 0))),           # cause length 0
        msg(ERROR, param(12, struct.pack('!HH', 4, 40))),                # cause past the param
        msg(ERROR, param(12, struct.pack('!HH', 0x99, 2))),              # unknown cause, length 2
        msg(ERROR, operation_error(cause(2, b''))),                      # empty unrecognized msg
        msg(KEEP_ALIVE, b'\x00\x01'),                                    # short server identifier
    ]
    for m in bad:
        p.add(a.send(m))
    # parameters nested beyond the dissection depth limit
    deep = ipv4('192.0.2.1')
    for i in range(600):
        deep = sctp_tp(1, 0, deep) if i % 2 else pool_element(i, 0, 0, deep)
        if len(deep) > 60000:
            break
    p.add(a.send(msg(REGISTRATION, deep[:65000])))
    # an Unrecognized message cause with an exception inside the nested
    # message (the in_error_pkt flag is restored by FINALLY), then a
    # complete message in the same packet
    p.add(a.pkt([a.chunk(msg(ERROR, operation_error(cause(2, msg(1, struct.pack('!HH', 9, 0)))))),
                 a.chunk(msg(HANDLE_RESOLUTION, handle(POOL)), sid=1)]))
    # reproducer asap_tcp_no_framing.py: two messages in one TCP
    # segment (ASAP over TCP has no PDU framing; the second is not dissected)
    m1 = msg(HANDLE_RESOLUTION, handle(b'pool'))
    m2 = msg(KEEP_ALIVE, struct.pack('!I', 0xabcdef01) + handle(b'pool'))
    p.add(tcp(40000, 3863, m1 + m2, seq=1))
    # frames without a time stamp (Simple Packet Blocks) for -z asap,stat
    b = Assoc(40012, 3863, 0x99aabbcc)
    p.add(b.send(msg(HANDLE_RESOLUTION, handle(POOL))), simple=True)
    p.add(b.send(msg(HANDLE_RESOLUTION, handle(POOL))), simple=True)
    # a Handle Resolution with a time stamp before the earlier ones (Last
    # Seen stays)
    p.add(b.send(msg(HANDLE_RESOLUTION, handle(POOL))), ts=2)
    p.write(os.path.join(out, 'asap-coverage-malformed.pcapng'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(out)
    malformed_capture(out)

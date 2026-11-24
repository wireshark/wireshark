#!/usr/bin/env python3
# Generates test/captures/dcc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DCC dissector
(packet-dcc.c, Distributed Checksum Clearinghouse).

DCC runs over UDP port 6277. Every PDU starts with a 24 octet header
(length, version, operation, client ID and four opaque operation
numbers); udp_dissect_pdus() splits a datagram into PDUs by the length
field. Requests go to port 6277, responses come from it. Every packet
is built from scratch with struct; no captured traffic is used.

Usage: mkdcc.py <output directory>

Writes:
  dcc-coverage.pcap            NOP, OK, report, query response, every
                               admin request (trace bits, flood
                               operations, values), admin responses
                               (client record, text lines), operations
                               without a body, two PDUs in one datagram
  dcc-coverage-malformed.pcap  PDUs cut short or with a length shorter
                               than the header
"""

import os
import struct
import sys

CLIENT = bytes([192, 0, 2, 10])
SERVER = bytes([192, 0, 2, 20])
CPORT = 40000
DCC_PORT = 6277


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(payload, response, ident=[0]):
    src, dst, sp, dp = (SERVER, CLIENT, DCC_PORT, CPORT) if response else \
                       (CLIENT, SERVER, CPORT, DCC_PORT)
    ulen = 8 + len(payload)
    udp = struct.pack('>HHHH', sp, dp, ulen, 0)
    ph = src + dst + struct.pack('>BBH', 0, 17, ulen)
    c = csum(ph + udp + payload) or 0xffff
    udp = udp[:6] + struct.pack('>H', c)
    ident[0] += 1
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + ulen, ident[0], 0, 64, 17,
                      0, src, dst)
    iph = iph[:10] + struct.pack('>H', csum(iph)) + iph[12:]
    mac_c, mac_s = bytes.fromhex('020000000010'), bytes.fromhex('020000000020')
    eth = (mac_c + mac_s) if response else (mac_s + mac_c)
    return eth + b'\x08\x00' + iph + udp + payload


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


SIG = bytes(range(0xa0, 0xb0))


def pdu(op, body, client_id=32768, le=False, length=None, vers=4, nums=None):
    """Header plus body. le: operation numbers written little endian,
    so the pid, report and retransmission numbers have a non-zero low
    16 bits at offsets 4, 8 and 12 and the dissector picks little
    endian; otherwise they are small big endian numbers."""
    e = '<' if le else '>'
    if nums is None:
        nums = struct.pack(e + 'IIII', 0xc0000201, 1234, 7, 1)
    if length is None:
        length = 24 + len(body)
    return struct.pack('>HBBI', length, vers, op, client_id) + nums + body


def ck(t, fill):
    return struct.pack('>BB', t, 18) + bytes([fill]) * 16


def admin_req(aop, val, date=1700000000):
    return struct.pack('>iIB3s', date, val, aop, b'\0\0\0') + SIG


def main_frames():
    F = []
    # 1-2: NOP request (big endian operation numbers) and OK response
    F.append(udp_frame(pdu(1, SIG), False))
    ok = struct.pack('>BBH', 4, 0, 250) + b'Rhyolite DCC 1.3.163'.ljust(64, b'\0') + SIG
    F.append(udp_frame(pdu(6, ok, client_id=100), True))
    # 3-4: report with three checksums (little endian operation numbers)
    #      and the query response with three targets
    rep = struct.pack('>I', 1) + ck(1, 0x11) + ck(7, 0x77) + ck(8, 0x88) + SIG
    F.append(udp_frame(pdu(2, rep, le=True), False))
    F.append(udp_frame(pdu(4, struct.pack('>III', 3, 0x00fffff0, 0x00fffff1) + SIG,
                           client_id=100, le=True), True))
    # 5-6: report with checksums of every type 0-13 and an unknown type
    #      99 (15 checksums, the most the loop shows), and a query
    #      response with 15 targets incl. every named target value
    rep = struct.pack('>I', 0x00fffff3) + b''.join(ck(t, t) for t in range(14)) + ck(99, 0xee) + SIG
    F.append(udp_frame(pdu(2, rep), False))
    tg = [0x00fffff0, 0x00fffff1, 0x00fffff2, 0x00fffff3, 0x01000000] + list(range(1, 11))
    F.append(udp_frame(pdu(4, b''.join(struct.pack('>I', t) for t in tg) + SIG,
                           client_id=100), True))
    # 7-8: report with 16 checksums: the loop stops after 15 and the
    #      rest is shown from the signature on; query response with 16
    rep = struct.pack('>I', 2) + b''.join(ck(t % 14, t) for t in range(16)) + SIG
    F.append(udp_frame(pdu(2, rep), False))
    F.append(udp_frame(pdu(4, b''.join(struct.pack('>I', t) for t in range(16)) + SIG,
                           client_id=100), True))
    # 9-12: admin trace on (all bits), trace off (some bits), every
    #       flood operation, then an unknown flood operation
    F.append(udp_frame(pdu(5, admin_req(8, 0x7f)), False))
    F.append(udp_frame(pdu(5, admin_req(9, 0x15)), False))
    for fo in range(8):
        F.append(udp_frame(pdu(5, admin_req(3, fo)), False))
    F.append(udp_frame(pdu(5, admin_req(3, 42)), False))
    # admin values for the other operations, an unknown one and -1 (255)
    for aop in (1, 2, 4, 5, 6, 7, 10, 0xff, 77):
        F.append(udp_frame(pdu(5, admin_req(aop, 4096)), False))
    # admin response with exactly one client record
    cl = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [5]) + struct.pack('>III', 32769, 1700000100, 42)
    F.append(udp_frame(pdu(5, cl + SIG, client_id=100), True))
    # admin response with text lines (LF, CRLF and a last line without one)
    txt = b'version 1.3.163\nclients 3\r\n2 queries'
    F.append(udp_frame(pdu(5, txt + SIG, client_id=100), True))
    # admin response that is only the signature (no text)
    F.append(udp_frame(pdu(5, SIG, client_id=100), True))
    # operations shown without a body: invalid, query, error, delete,
    # unknown
    F.append(udp_frame(pdu(0, SIG), False))
    F.append(udp_frame(pdu(3, struct.pack('>I', 1) + ck(5, 0x55) + SIG), False))
    F.append(udp_frame(pdu(7, b'no such client'.ljust(128, b'\0') + SIG, client_id=100), True))
    F.append(udp_frame(pdu(8, struct.pack('>i', 1700000000) + ck(2, 0x22) + b'\0\0' + SIG), False))
    F.append(udp_frame(pdu(200, b''), False))
    # two PDUs in one datagram: a NOP and an OK
    F.append(udp_frame(pdu(1, SIG) + pdu(1, SIG, le=True), False))
    F.append(udp_frame(pdu(6, ok, client_id=100) + pdu(4, struct.pack('>I', 9) + SIG,
                                                      client_id=100), True))
    # NOPs whose endianness guess stops at the report number (low half
    # of the octets 8-9 zero) and at the retransmission number
    F.append(udp_frame(pdu(1, SIG, nums=struct.pack('<IIII', 1, 5, 0x10000, 3)), False))
    F.append(udp_frame(pdu(1, SIG, nums=struct.pack('<IIII', 1, 5, 6, 0x10000)), False))
    return F


def malformed_frames():
    F = []
    # NOP cut short in the signature
    F.append(udp_frame(pdu(1, SIG)[:36], False))
    # length larger than the datagram
    F.append(udp_frame(pdu(1, SIG, length=200), False))
    # length smaller than the header
    F.append(udp_frame(pdu(1, SIG, length=10), False))
    # length 0
    F.append(udp_frame(pdu(1, SIG, length=0), False))
    # only 10 octets
    F.append(udp_frame(pdu(1, SIG)[:10], False))
    # OK cut short in the brand
    F.append(udp_frame(pdu(6, struct.pack('>BBH', 4, 0, 0) + b'abc'), True))
    # admin request without the signature
    F.append(udp_frame(pdu(5, struct.pack('>iIB', 0, 0, 8)), False))
    # admin response shorter than a signature
    F.append(udp_frame(pdu(5, b'abc', client_id=100), True))
    # report: a partial checksum before the signature
    F.append(udp_frame(pdu(2, struct.pack('>I', 1) + ck(1, 1)[:6] + SIG), False))
    # query response with a partial target
    F.append(udp_frame(pdu(4, b'\0\0' + SIG, client_id=100), True))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcc-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcc-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

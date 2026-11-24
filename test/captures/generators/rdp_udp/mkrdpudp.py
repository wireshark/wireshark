#!/usr/bin/env python3
# Generates test/captures/rdp_udp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDPUDP (MS-RDPEUDP, versions 1 and 2) captures for packet-rdpudp.c.
# Usage: mkrdpudp.py <outdir> [-v]
# The data carries TLS / DTLS records: only handshake messages in the clear
# (a ClientHello and a ServerHello); nothing is encrypted.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session, Tcp, udp

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
MARKS = []

SYN, FIN, ACK, DATA, FEC, CN, CWR = 1, 2, 4, 8, 0x10, 0x20, 0x40
AOA, SYNLOSSY, ACKDELAYED, CORRID, SYNEX = 0x100, 0x200, 0x400, 0x800, 0x1000
RND = bytes(range(32))


def mark(cap, title):
    MARKS.append((len(cap.frames) + 1, title))


def tls_client_hello(dtls=False, seq=0):
    body = (b'\xfe\xfd' if dtls else b'\x03\x03') + RND + b'\0'
    if dtls:
        body += b'\0'                                       # no cookie
    body += struct.pack('>H', 4) + b'\x13\x01\x00\x2f' + b'\x01\x00'
    if dtls:
        hs = b'\x01' + struct.pack('>I', len(body))[1:] + struct.pack('>H', 0) + b'\0\0\0' + struct.pack('>I', len(body))[1:] + body
        return b'\x16\xfe\xff' + struct.pack('>H', 0) + struct.pack('>Q', seq)[2:] + struct.pack('>H', len(hs)) + hs
    hs = b'\x01' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs


def tls_server_hello():
    body = b'\x03\x03' + RND + b'\0' + b'\x13\x01' + b'\0'
    hs = b'\x02' + struct.pack('>I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('>H', len(hs)) + hs


def v1(snack=0xffffffff, win=64, flags=0, body=b''):
    return struct.pack('>IHH', snack, win, flags) + body


def syn_body(isn=1000, up=1232, down=1232):
    return struct.pack('>IHH', isn, up, down)


def synex(version=None, cookie=bytes(32)):
    if version is None:
        return struct.pack('>H', 0)
    b = struct.pack('>HH', 1, version)
    if version == 0x101:
        b += cookie
    return b


def v2(prefix_type, flags, body, swap=True, logwin=0):
    """An RDPUDP2 packet: prefix byte, 16-bit flags (log window in the top bits), body; byte 0 and 7 swapped."""
    pkt = bytearray(bytes([(prefix_type << 1) | 0]) + struct.pack('<H', flags | (logwin << 12)) + body)
    while len(pkt) < 8:
        pkt += b'\0'
    if swap:
        pkt[0], pkt[7] = pkt[7], pkt[0]
    return bytes(pkt)


def ack_part(seq, nack_extra=b'', n=0, ts=0x123456, gap=3, scale=2):
    return struct.pack('<H', seq) + struct.pack('<I', ts)[:3] + bytes([gap, (scale << 4) | n]) + nack_extra


def build_main():
    cap = Cap()
    C = lambda p, port=50100, **kw: udp(cap, True, p, sport=port, **kw)
    S = lambda p, port=50100, **kw: udp(cap, False, p, sport=port, **kw)

    mark(cap, 'version 1 reliable connection: SYN, SYN+ACK, ACK with ack vector, data with a TLS ClientHello and ServerHello, FEC, ack of acks, congestion flags, FIN')
    C(v1(flags=SYN, body=syn_body()), 50101)
    S(v1(1000, 64, SYN | ACK, syn_body(2000)), 50101)
    C(v1(2000, 64, ACK, struct.pack('>H', 0)), 50101)                                      # ACK, empty vector
    C(v1(2000, 64, ACK, struct.pack('>H', 4) + bytes([0x00, 0x40, 0x80, 0xc0])), 50101)    # ACK with vector items
    C(v1(2000, 64, DATA, struct.pack('>II', 1001, 1001) + tls_client_hello()), 50101)
    S(v1(1001, 64, DATA | ACK, struct.pack('>H', 1) + b'\0' + struct.pack('>II', 2001, 2001) + tls_server_hello()), 50101)
    C(v1(2001, 64, ACK | FEC, struct.pack('>H', 0) + struct.pack('>IIBB', 1, 2, 3, 4)), 50101)
    C(v1(2001, 64, AOA, struct.pack('>I', 5)), 50101)
    C(v1(2001, 64, ACK | CN | CWR | ACKDELAYED, struct.pack('>H', 0)), 50101)
    S(v1(1002, 64, FIN | ACK, struct.pack('>H', 0)), 50101)
    C(v1(1002, 64, FIN), 50101)

    mark(cap, 'version 1 with correlation id and SynEx (versions 1 and 2 without cookie hash, no version)')
    C(v1(flags=SYN | CORRID | SYNEX, body=syn_body() + bytes(range(16)) + bytes(16) + synex(1)), 50102)
    S(v1(1000, 64, SYN | ACK | CORRID | SYNEX, syn_body(2000) + bytes(range(16)) + bytes(16) + synex(0x1)), 50102)
    C(v1(flags=SYN | SYNEX, body=syn_body() + synex(None)), 50103)
    S(v1(1000, 64, SYN | ACK | SYNEX, syn_body(2000) + synex(2)), 50103)
    C(v1(2000, 64, ACK, struct.pack('>H', 0)), 50102)

    mark(cap, 'lossy connection (DTLS): SYN with SYNLOSSY, DTLS ClientHello in a data PDU')
    C(v1(flags=SYN | SYNLOSSY, body=syn_body()), 50104)
    S(v1(1000, 64, SYN | ACK | SYNLOSSY, syn_body(2000)), 50104)
    C(v1(2000, 64, DATA, struct.pack('>II', 1001, 1001) + tls_client_hello(True)), 50104)
    S(v1(1001, 64, ACK, struct.pack('>H', 0)), 50104)

    mark(cap, 'version 2: SYN with SynEx version 0x101 (cookie hash), SYN+ACK switching to version 2 for the following packets')
    C(v1(flags=SYN | CORRID | SYNEX, body=syn_body() + bytes(range(16)) + bytes(16) + synex(0x101, bytes(range(32)))), 50105)
    S(v1(1000, 64, SYN | ACK | CORRID | SYNEX, syn_body(2000) + bytes(range(16)) + bytes(16) + synex(0x101, bytes(range(32, 64)))), 50105)
    P = 50105
    mark(cap, 'version 2 packets: ACK, overhead, delay ack, ack of acks, data (TLS records, also split over two packets), ack vectors (bitmap and run length, with and without time stamp), dummy data')
    C(v2(0, 0x0001, ack_part(1)), P)
    C(v2(0, 0x0001, ack_part(9, bytes(3), n=3)), P)
    C(v2(0, 0x0040, bytes([12])), P)
    C(v2(0, 0x0100, struct.pack('<BH', 4, 100)), P)
    C(v2(0, 0x0010, struct.pack('<H', 7)), P)
    ch = tls_client_hello()
    C(v2(0, 0x0004, struct.pack('<HH', 1, 1) + ch[:20]), P)                    # first part of a TLS record: desegmentation
    C(v2(0, 0x0004, struct.pack('<HH', 2, 2) + ch[20:]), P)                    # second part
    S(v2(0, 0x0004 | 0x0001, ack_part(2) + struct.pack('<HH', 1, 1) + tls_server_hello()), P)
    C(v2(0, 0x0008, struct.pack('<HB', 100, 3) + bytes([0x00, 0x7f, 0x05])), P)               # ack vector, bitmaps
    C(v2(0, 0x0008, struct.pack('<HB', 200, 0x80 | 4) + struct.pack('<I', 0x1234)[:3] + b'\x02' + bytes([0xc5, 0x85, 0x01, 0xff])), P)
    C(v2(8, 0x0004, struct.pack('<H', 3)), P)                                   # dummy data
    C(v2(0, 0x0004 | 0x0008 | 0x0010 | 0x0040 | 0x0100 | 0x0001,
         ack_part(3) + bytes([6]) + struct.pack('<BH', 4, 100) + struct.pack('<H', 8) + struct.pack('<H', 4)
         + struct.pack('<HB', 50, 1) + bytes([0x81]) + struct.pack('<H', 4) + tls_client_hello()[:10], logwin=5), P)
    # sequence numbers that wrap and go back
    ccs = b'\x14\x03\x03\x00\x01\x01'                  # a TLS change cipher spec record
    for seq in (7000, 14000, 21000, 28000, 35000, 42000, 49000, 56000, 63000, 100, 200, 50000, 5, 30000, 100):
        C(v2(0, 0x0004, struct.pack('<HH', seq, seq) + ccs), P)
    C(v2(0, 0x0004, struct.pack('<HH', 9, 70) + ch[:20]), P)                   # the same partial record twice: the stored chunk is replaced
    C(v2(0, 0x0004, struct.pack('<HH', 10, 70) + ch[:20]), P)
    mark(cap, 'packets of the other conversations after the switch')
    S(v2(0, 0x0001 | 0x0004, ack_part(5) + struct.pack('<HH', 6, 6) + b'\x14\x03\x03\x00\x01\x01'), P)

    mark(cap, 'the server address of an RDP session on TCP (message and channel PDUs), the same helpers on UDP without a session')
    sess = Session(cap, 50300, ['cliprdr'], msgchan=True)
    sess.chan('cliprdr', struct.pack('<HHI', 1, 0, 0), False)
    sess.chan('cliprdr', struct.pack('<HHI', 1, 0, 0), True)
    cap.exp('rdp_drdynvc', bytes([0x10, 5]) + b'foo\0', False, sport=50301, pt=3)                       # a conversation that does not exist yet
    cap.exp('rdp_drdynvc', bytes([0x10, 6]) + b'bar\0', False, sport=50301, pt=3)                       # one without RDPUDP data
    cookie = bytes(range(16))
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x1234, 0) + cookie, True, sport=50101, pt=3)   # a conversation with RDPUDP data
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x1235, 0) + cookie, True, sport=50302, pt=3)   # no conversation
    cap.exp('rdp_drdynvc', bytes([0x10, 7]) + b'baz\0', False, sport=50302, pt=3)
    tt = Tcp(cap, sport=50400)                                                                          # a TCP connection that is not RDP
    tt.open()
    cap.exp('rdp_drdynvc', bytes([0x10, 8]) + b'qux\0', False, sport=50400, pt=2)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x1236, 0) + cookie, True, sport=50302, pt=3)   # a conversation without RDPUDP data
    mark(cap, 'ACK-less SYN and a SYN that comes after data (the server address is the destination of the first SYN only)')
    S(v1(flags=SYN | ACK, body=syn_body()), 50106)
    C(v1(flags=SYN, body=syn_body()), 50106)
    cap.write(os.path.join(OUT, 'rdpudp-coverage.pcapng'))
    if VERBOSE:
        print('rdpudp-coverage.pcapng', len(cap.frames), 'frames')
        for i, (n, t) in enumerate(MARKS):
            end = MARKS[i + 1][0] - 1 if i + 1 < len(MARKS) else len(cap.frames)
            print('  %d-%d: %s' % (n, end, t))


def build_malformed():
    cap = Cap()
    C = lambda p, port=50200: udp(cap, True, p, sport=port)
    S = lambda p, port=50200: udp(cap, False, p, sport=port)
    C(b'\x00\x00\x00')                                               # short
    C(v1(flags=SYN, body=b'\0\0'))
    C(v1(flags=SYN | CORRID, body=syn_body() + bytes(10)), 50201)
    C(v1(flags=SYN | SYNEX, body=syn_body()), 50202)
    C(v1(flags=SYN | SYNEX, body=syn_body() + synex(0x101, b'\0' * 5)), 50203)
    C(v1(flags=ACK, body=struct.pack('>H', 1000)), 50204)
    C(v1(flags=FEC, body=bytes(5)), 50205)
    C(v1(flags=AOA, body=bytes(2)), 50206)
    C(v1(flags=DATA, body=bytes(6)), 50207)
    # a version 2 conversation with packets cut short
    C(v1(flags=SYN | SYNEX, body=syn_body() + synex(0x101, bytes(32))), 50208)
    S(v1(1000, 64, SYN | ACK | SYNEX, syn_body(2000) + synex(0x101, bytes(32))), 50208)
    for f, body in ((0x0001, bytes(3)), (0x0040, b''), (0x0100, b'\0'), (0x0010, b''), (0x0004, b'\0'), (0x0008, b'\0'),
                    (0x0008, struct.pack('<HB', 1, 0x7f) + b'\0\0'), (0x0004, struct.pack('<HH', 1, 1)), (0x0004 | 1, bytes(3))):
        C(v2(0, f, body), 50208)
    C(b'\x00' * 5, 50208)                                            # shorter than 8 octets
    cap.write(os.path.join(OUT, 'rdpudp-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()

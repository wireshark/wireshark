#!/usr/bin/env python3
# Generates test/captures/s5066sis_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the STANAG 5066 SIS coverage captures. Usage: mks5066sis.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, TcpStream

PORT = 5066

def sis(ptype, body=b'', ed1=False, size=None):
    """sync, version (not in edition 1), size of what follows the size field, type, body"""
    payload = bytes([ptype]) + body
    n = len(payload) if size is None else size
    if ed1:
        return b'\x90\xeb' + struct.pack('>H', n) + payload
    return b'\x90\xeb\x00' + struct.pack('>H', n) + payload

def a(asz=4, grp=0, v=0x0a000001):
    """address: size in half bytes (3 bits), group flag, 28 bit address"""
    return struct.pack('>I', (asz << 29) | (grp << 28) | (v & 0x0fffffff))

def st(tx=1, conf=0, order=0, ext=0, retries=3):
    return bytes([(tx << 4) | (conf << 2) | (order << 1) | ext, retries << 4])

def ctl(conn=1, updu=7, seg=0, app=0x0010):
    return bytes([(conn << 4), updu]) + struct.pack('>HH', seg, app)

def unidata_req(sap, data, prio=2, ttl=60, hdr=b''):
    return sis(20, bytes([(prio << 4) | sap]) + a() + st() + ttl.to_bytes(3, 'big') + struct.pack('>H', len(data) + len(hdr)) + hdr + data)

def exp_req(sap, data, ttl=30, hdr=b''):
    return sis(24, bytes([sap]) + a(grp=1) + st(tx=2) + ttl.to_bytes(3, 'big') + struct.pack('>H', len(data) + len(hdr)) + hdr + data)

def unidata_ind(ptype, sap, src_sap, txmode, dsize, extra=b'', hdr=b'', data=b'', prio=1):
    first = ((prio << 4) | sap) if ptype == 21 else sap
    return sis(ptype, bytes([first]) + a() + bytes([(txmode << 4) | src_sap]) + a(asz=4, v=0x0a000002) + struct.pack('>H', dsize) + extra + hdr + data)

def blocks(errs, nrx):
    b = struct.pack('>H', len(errs)) + b''.join(struct.pack('>HH', p, s) for p, s in errs)
    return b + struct.pack('>H', len(nrx)) + b''.join(struct.pack('>HH', p, s) for p, s in nrx)

def main(out):
    p = Pcap()
    t = TcpStream(p, 40100, PORT)
    D = b'U_PDU data of the unidata primitive'
    # ---- bind, unbind, hard links, availability
    t.c(sis(1, bytes([0x65]) + st(tx=1, conf=2, order=1, ext=1, retries=5) + b'\x0a'))      # bind request: SAP 6, rank 5
    t.s(sis(3, bytes([0x60]) + struct.pack('>H', 2048)))                                     # bind accepted
    t.c(sis(1, bytes([0x00]) + st(tx=0, conf=0, order=0, ext=0, retries=0) + b'\x00'))      # SAP 0
    t.s(sis(4, b'\x05'))                                                                      # rejected
    t.s(sis(4, b'\x77'))                                                                      # unknown reason
    t.c(sis(2))                                                                               # unbind request
    t.s(sis(5, b'\x03'))                                                                      # unbind indication
    t.s(sis(5, b'\x99'))
    t.c(sis(6, bytes([0x75]) + a(grp=1)))                                                     # hard link establish
    t.c(sis(7, a()))
    t.s(sis(8, bytes([1, 0x35]) + a()))                                                       # established
    t.s(sis(9, bytes([3, 0x36]) + a()))                                                       # rejected
    t.s(sis(10, bytes([2, 0x67]) + a()))                                                      # terminated
    t.s(sis(11, bytes([1, 0x15]) + a()))                                                      # indication
    t.c(sis(12, bytes([0x25]) + a()))                                                         # accept
    t.c(sis(13, bytes([4, 0x45]) + a()))                                                      # reject
    t.s(sis(14, bytes([1, 0])))                                                               # subnet availability
    t.s(sis(14, bytes([0, 7])))
    t.c(sis(15))                                                                              # data flow on / off / keep alive
    t.c(sis(16))
    t.c(sis(17))
    t.c(sis(0))                                                                               # type 0 (unknown)
    t.c(sis(99, b'\x01\x02\x03'))                                                             # unknown type
    # ---- management messages
    t.c(sis(18, b'\x01' + b'management request body'))
    t.s(sis(19, b'\x02' + b'management indication body'))
    t.c(sis(18, b'\x01'))                                                                     # no body
    t.s(sis(19, b'\x02'))
    # ---- unidata request with and without the client transport header (SAP 2, 6, 7)
    t.c(unidata_req(1, D))
    t.c(unidata_req(2, D, hdr=ctl(app=0x0010)))
    t.c(unidata_req(6, D, hdr=ctl(conn=2, updu=1, seg=3, app=0x0011)))
    t.c(unidata_req(7, D, hdr=ctl(conn=3, updu=2, seg=0xffff, app=0x00ff)))
    t.c(unidata_req(15, b''))
    # ---- unidata indication: ARQ, non-ARQ, non-ARQ with errors, Rockwell Collins layout, with the header
    t.s(unidata_ind(21, 1, 2, 1, len(D), data=D))
    t.s(unidata_ind(21, 6, 6, 2, len(D), hdr=ctl(app=0x0010), data=D))
    t.s(unidata_ind(21, 1, 1, 3, len(D), extra=blocks([(0, 4), (10, 2)], [(20, 3)]), data=D))
    t.s(unidata_ind(21, 1, 1, 1, len(D), extra=b'\x00\x01\x00\x02', data=D))                # RC layout: extra four octets
    t.s(unidata_ind(21, 7, 7, 3, len(D), extra=blocks([(1, 1)], []), hdr=ctl(app=0x00ff), data=D))
    # ---- confirm, reject
    t.s(sis(22, bytes([0x01]) + a() + struct.pack('>H', 5) + b'abcde'))
    t.s(sis(22, bytes([0x02]) + a() + struct.pack('>H', 4) + b'abcd' + ctl(app=0x0010)))
    t.s(sis(22, bytes([0x07]) + a() + struct.pack('>H', 0) + ctl(app=0x00ff)))
    t.s(sis(23, bytes([0x31]) + a() + struct.pack('>H', 5) + b'abcde'))
    t.s(sis(23, bytes([0x16]) + a() + struct.pack('>H', 3) + b'abc' + ctl(app=0x0011)))
    # ---- expedited
    t.c(exp_req(1, D))
    t.c(exp_req(2, D, hdr=ctl()))
    t.c(exp_req(7, D, hdr=ctl(app=0x00ee)))
    t.s(unidata_ind(25, 1, 1, 1, len(D), data=D))
    t.s(unidata_ind(25, 6, 6, 3, len(D), extra=blocks([(0, 1)], [(2, 2), (4, 4)]), hdr=ctl(), data=D))
    t.s(unidata_ind(25, 1, 1, 1, len(D), extra=b'\x00\x00\x00\x00', data=D))
    t.s(sis(26, bytes([0x01]) + a() + struct.pack('>H', 3) + b'xyz'))
    t.s(sis(26, bytes([0x06]) + a() + struct.pack('>H', 3) + b'xyz' + ctl()))
    t.s(sis(27, bytes([0x21]) + a() + struct.pack('>H', 3) + b'xyz'))
    t.s(sis(27, bytes([0x17]) + a() + struct.pack('>H', 3) + b'xyz' + ctl()))
    # ---- several PDUs in a segment, and a PDU split over segments
    t.c(sis(17) + sis(17) + unidata_req(1, b'pair'))
    big = unidata_req(1, bytes(range(200)))
    t.c(big[:3]); t.c(big[3:20]); t.c(big[20:])
    # ---- not S5066: wrong version byte (the TCP dissector declines)
    t.c(b'\x90\xeb\x01\x00\x01\x11')
    t.c(b'\x91\xeb\x00\x00\x01\x11')
    t.fin()
    p.write(os.path.join(out, 's5066sis-coverage.pcap'))

    # ---- edition 1 (no version byte, a four octet header); needs the preference s5066sis.edition_one
    e = Pcap()
    t = TcpStream(e, 40101, PORT)
    t.c(sis(1, bytes([0x65]) + st() + b'\x0a', ed1=True))
    t.s(sis(3, bytes([0x60]) + struct.pack('>H', 1024), ed1=True))
    t.c(sis(20, bytes([0x15]) + a() + st() + (30).to_bytes(3, 'big') + struct.pack('>H', 5) + b'hello', ed1=True))
    t.s(sis(17, ed1=True))
    t.fin()
    e.write(os.path.join(out, 's5066sis-coverage-edition1.pcap'))

    # ===== malformed
    m = Pcap()
    t = TcpStream(m, 41100, PORT)
    # PDUs cut short in every primitive: the fixed fields run past the PDU
    for ptype, n in ((1, 2), (3, 1), (4, 0), (5, 0), (6, 3), (7, 2), (8, 3), (9, 3), (10, 3), (11, 3), (12, 3), (13, 3), (14, 1),
                     (18, 0), (19, 0), (20, 8), (21, 8), (22, 4), (23, 4), (24, 8), (25, 8), (26, 4), (27, 4)):
        t.c(sis(ptype, bytes(n)))
    # a data size beyond the PDU, errors/not-received block counts beyond the PDU
    t.c(sis(22, bytes([0x01]) + a() + struct.pack('>H', 500) + b'abc'))
    t.c(sis(23, bytes([0x01]) + a() + struct.pack('>H', 500) + b'abc'))
    t.c(sis(26, bytes([0x01]) + a() + struct.pack('>H', 500) + b'abc'))
    t.c(sis(27, bytes([0x01]) + a() + struct.pack('>H', 500) + b'abc'))
    t.c(unidata_ind(21, 1, 1, 3, 5, extra=struct.pack('>H', 5000) + b'\0' * 8, data=b'abcde'))
    t.c(unidata_ind(21, 1, 1, 3, 5, extra=struct.pack('>H', 0) + struct.pack('>H', 5000) + b'\0' * 8, data=b'abcde'))
    t.c(unidata_ind(25, 1, 1, 3, 5, extra=struct.pack('>H', 5000) + b'\0' * 8, data=b'abcde'))
    t.c(unidata_ind(25, 1, 1, 3, 5, extra=struct.pack('>H', 0) + struct.pack('>H', 5000) + b'\0' * 8, data=b'abcde'))
    # non-ARQ with errors and no blocks: the four count octets look like the Rockwell Collins layout
    t.c(unidata_ind(21, 1, 1, 3, len(D), extra=blocks([], []), data=D))
    # a client transport header that does not fit
    t.c(unidata_req(6, b'', hdr=ctl()[:4]))
    t.c(sis(21, bytes([0x06]) + a() + bytes([0x16]) + a() + struct.pack('>H', 0)))
    # unidata request with a size larger than the data (the data dissector gets what there is)
    t.c(sis(20, bytes([0x21]) + a() + st() + (30).to_bytes(3, 'big') + struct.pack('>H', 900) + b'short'))
    # size field of 0 and 1, and a size field larger than the segment
    t.c(sis(18, b'', size=0))
    t.c(sis(19, b'', size=0))
    t.c(sis(17, b'', size=0))
    t.c(sis(17, b'\x01', size=7))
    t.c(sis(18, b'\x01abc', size=60))
    # reassembly of a PDU that never completes
    t.c(sis(20, bytes([0x15]) + a() + st(), size=500))
    t.fin()
    m.write(os.path.join(out, 's5066sis-coverage-malformed.pcap'))

main(sys.argv[1])

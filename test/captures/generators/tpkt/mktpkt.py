#!/usr/bin/env python3
# Generates test/captures/tpkt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds tpkt-coverage.pcap and tpkt-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import Flow, write

def tpkt(payload, extra=0):
    return struct.pack('!BBH', 3, 0, 4 + len(payload) + extra) + payload

def cr(cookie=b''):
    # COTP CR: LI, 0xe0, dst-ref, src-ref, class, then optional user data
    body = b'\xe0\0\0\0\x01\0' + cookie
    return bytes([len(body)]) + body
def cc(extra=b''):
    body = b'\xd0\0\x01\0\x02\0' + extra
    return bytes([len(body)]) + body
def dt(data, eot=True):
    return b'\x02\xf0' + (b'\x80' if eot else b'\x00') + data

def atpkt(payload, ver=b'03', rsv=b'00', sep=b'\n', length=None, upper=False):
    n = len(payload) if length is None else length
    return ver + rsv + (b'%04X' if upper else b'%04x') % n + sep + payload

def main(out):
    fr = []
    # --- TCP 102: TPKT with COTP, default preferences
    f = Flow(50001, 102)
    fr.append(f.seg(tpkt(cr())))                                         # 1
    fr.append(f.seg(tpkt(cc()), client=False))                           # 2
    fr.append(f.seg(tpkt(dt(b'Hello world'))))                           # 3
    fr.append(f.seg(tpkt(dt(b'Zone')) + tpkt(dt(b'Ztwo')) + tpkt(dt(b'Zthree'), 0), client=False))  # 4 three TPKTs
    p = tpkt(dt(bytes(range(200))))
    fr.append(f.seg(p[:50]))                                             # 5 payload split
    fr.append(f.seg(p[50:120]))                                          # 6
    fr.append(f.seg(p[120:]))                                            # 7
    p = tpkt(dt(b'Zheader split in the middle'))
    fr.append(f.seg(p[:2]))                                              # 8 header split (2 octets)
    fr.append(f.seg(p[2:]))                                              # 9
    fr.append(f.seg(tpkt(dt(b'tail')) + p[:3]))                          # 10 complete PDU then 3 octets of the next
    fr.append(f.seg(p[3:]))                                              # 11
    fr.append(f.seg(b'\xffcontinuation data of a PDU we did not see', client=False))   # 12 not version 3
    fr.append(f.seg(b'\x03\x00\x00\x02' + b'X' * 10))                    # 13 length < 4
    fr.append(f.seg(tpkt(dt(b'ok again'))))                              # 14
    fr.append(f.seg(b'\x04\x05\x00\x00\x00'))                              # RDP fast-path (heuristic of the "tpkt" list)
    fr.append(f.seg(b'\x00\x06\x00\x00\x00\x00', client=False))
    # COTP in several TPKTs: DT without EOT then with EOT
    fr.append(f.seg(tpkt(dt(b'part one ', eot=False)) + tpkt(dt(b'part two'))))   # 15
    # --- a second connection: PDU split over many small segments with the 4 octet header split in 1+3
    g = Flow(50002, 102)
    p = tpkt(cr(b'\xc1\x02\x01\x00'))
    fr.append(g.seg(p[:1]))                                              # 16
    fr.append(g.seg(p[1:4]))                                             # 17
    fr.append(g.seg(p[4:10]))                                            # 18
    fr.append(g.seg(p[10:]))                                             # 19
    # --- RDP port 3389: TPKT recognised by the heuristic registered for the port
    r = Flow(50003, 3389)
    neg = struct.pack('<BBHI', 1, 0, 8, 3)
    fr.append(r.seg(tpkt(cr(b'Cookie: mstshash=carol\r\n' + neg))))      # 20
    fr.append(r.seg(tpkt(cc(struct.pack('<BBHI', 2, 0, 8, 1))), client=False))   # 21
    fr.append(r.seg(b'\x03\x00'))                                       # shorter than a TPKT header: not TPKT
    fr.append(r.seg(b'\x03\x00\x00\x02' + b'abcdef'))                   # TPKT length below 4: not TPKT
    fr.append(r.seg(b'\x16\x03\x01\x00\x10' + bytes(16)))                # 22 TLS record: rejected by TPKT, no longer TPKT
    # --- heuristic "TPKT over TCP" (disabled by default) on a port nobody claims: seen as plain TCP
    h = Flow(50004, 5099)
    fr.append(h.seg(tpkt(dt(b'heuristic only'))))                        # 23
    # --- ASCII TPKT in MGCP (TCP 2427 and 2727)
    m = Flow(50005, 2427)
    crcx = b'CRCX 1000 ds/e1-1/1@gw.example.net MGCP 1.0\r\nC: A3C47F21456789F0\r\nL: p:10, a:PCMU\r\nM: recvonly\r\n'
    fr.append(m.seg(atpkt(crcx)))                                        # 24
    fr.append(m.seg(atpkt(b'200 1000 OK\r\n') + atpkt(b'200 1001 OK\r\n'), client=False))   # 25 two in one segment
    fr.append(m.seg(atpkt(b'DLCX 1002 ds/e1-1/1@gw.example.net MGCP 1.0\r\n') + atpkt(b'DLCX 1003 ds/e1-1/2@gw.example.net MGCP 1.0\r\n')))  # 26
    fr.append(m.seg(b'ABCDEFGH12345678', client=False))                  # 27 8 alphanumerics but not "0": "Continuation"
    fr.append(m.seg(b'DLCX 1004 ds/e1-1/1@gw.example.net MGCP 1.0\r\n'))  # 28 plain MGCP on the TCP port
    fr.append(m.seg(b'200 1\n', client=False))                               # fewer than 8 octets: plain MGCP
    fr.append(m.seg(atpkt(b'DLCX 1005 ds/e1-1/1@gw.example.net MGCP 1.0\r\n' + b'X: ' + b'y' * 160 + b'\r\n', ver=b'0a', rsv=b'0A', upper=True)))  # hex digits of both cases, length 0x00B7
    m2 = Flow(50006, 2727)
    fr.append(m2.seg(atpkt(b'NTFY 2000 ds/e1-1/1@gw.example.net MGCP 1.0\r\nX: 0\r\nO: L/hd\r\n', ver=b'0A', rsv=b'ff')))   # 29 version/reserved with letters
    fr.append(m2.seg(atpkt(b'200 2000 OK\r\n', ver=b'0F', rsv=b'0b', sep=b' '), client=False))   # 30
    write(os.path.join(out, 'tpkt-coverage.pcap'), fr)
    nm = len(fr)

    mf = []
    a = Flow(51001, 102)
    mf.append(a.seg(tpkt(dt(b'claims more than it carries'), extra=100)))    # length beyond the data (reassembly pending)
    a2 = Flow(51002, 2427)
    mf.append(a2.seg(atpkt(b'200 1 OK\r\n', length=500)))                    # ASCII length beyond the data
    a3 = Flow(51003, 2427)
    mf.append(a3.seg(atpkt(b'200 1 OK\r\n') + atpkt(b'200 2 OK\r\n', ver=b'0g', rsv=b'zz', length=0xffff)))  # non-hex digits
    a4 = Flow(51004, 102)
    mf.append(a4.seg(tpkt(b'\x00\x00\x00\x00\x00\x00\x00')))                 # COTP with a bogus header
    mf.append(a4.seg(tpkt(b'\x10\xe0\x00\x00\x00\x01\x00')))                 # COTP CR whose length indicator is too long
    write(os.path.join(out, 'tpkt-coverage-malformed.pcap'), mf)
    print('main', nm, 'malformed', len(mf))

main(sys.argv[1] if len(sys.argv) > 1 else '.')

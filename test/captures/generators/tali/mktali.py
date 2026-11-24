#!/usr/bin/env python3
# Generates test/captures/tali_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-tali.c (TALI over TCP, heuristic).
# Usage: mktali.py <outdir>
import os
import struct
import sys
from pcaplib import Pcap, eth, ip4, tcp

DLT_EN10MB = 1
CPORT, SPORT = 40001, 40002

def tali(op, payload=b''):
    return b'TALI' + op.encode() + struct.pack('<H', len(payload)) + payload

def mtp3_label(dpc, opc, sls):
    return struct.pack('<I', (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28))

SCCP_UDT = bytes([0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xf0, 0x02, 0x42, 0xf0, 0x03, 0xaa, 0xbb, 0xcc])
MTP3_SLTM = bytes([0x01]) + mtp3_label(0x0101, 0x0202, 3) + bytes([0x11, 0x40]) + b'ABCD'
ISUP_REL = bytes([0x05, 0x00, 0x0c, 0x02, 0x00, 0x02, 0x80, 0x90])

class Flow:
    def __init__(self, pcap, cport=CPORT, sport=SPORT, c='192.0.2.1', s='192.0.2.2'):
        self.p, self.cport, self.sport, self.c, self.s = pcap, cport, sport, c, s
        self.seq = {True: 1000, False: 5000}
        self.ident = 1
    def seg(self, from_client, payload, flags=0x18):
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        ack = self.seq[not from_client] if flags & 0x10 else 0
        if flags & 0x02:
            # MSS option on SYN and SYN/ACK
            t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[from_client], ack, 6 << 4, flags, 65535, 0, 0) + b'\x02\x04\x05\xb4' + payload
        else:
            t = tcp(payload, sp, dp, self.seq[from_client], ack, flags)
        self.ident += 1
        self.p.add(eth(ip4(6, t, src, dst, ident=self.ident), 0x0800,
                       *( (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01') if from_client else (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'))))
        self.seq[from_client] += len(payload) + (1 if flags & 0x03 else 0)
    def handshake(self):
        self.seg(True, b'', 0x02)
        self.seg(False, b'', 0x12)
        self.seg(True, b'', 0x10)
    def close(self):
        self.seg(True, b'', 0x11)
        self.seg(False, b'', 0x11)

def main(out):
    p = Pcap(DLT_EN10MB)
    f = Flow(p)
    f.handshake()                                           # 1-3
    # 4-5: test message and its allo reply (opcodes with payload and without)
    f.seg(True, tali('test', b'TESTDATA'))
    f.seg(False, tali('allo', b''))
    # 6-9: proh / proa / moni / mona
    f.seg(True, tali('proh', b'\x00\x01'))
    f.seg(False, tali('proa'))
    f.seg(True, tali('moni', b'\x01'))
    f.seg(False, tali('mona', b'\x02\x03'))
    # 10-12: SCCP, MTP3 and ISUP payloads
    f.seg(True, tali('sccp', SCCP_UDT))
    f.seg(False, tali('mtp3', MTP3_SLTM))
    f.seg(True, tali('isot', ISUP_REL))
    # 13: saal (data)
    f.seg(False, tali('saal', b'\x00\x00\x00\x04'))
    # 14: two PDUs in one segment
    f.seg(True, tali('test', b'ONE') + tali('test', b'TWO'))
    # 15-16: one PDU over two segments (payload split)
    pdu = tali('test', b'SPLIT-PAYLOAD-0123456789')
    f.seg(False, pdu[:16])
    f.seg(False, pdu[16:])
    # 17-18: header complete in the first segment, payload in the second
    pdu = tali('mtp3', MTP3_SLTM)
    f.seg(True, pdu[:10])
    f.seg(True, pdu[10:])
    # 19-21: a PDU in three segments with the next PDU starting in the last
    pdu = tali('test', bytes(range(65, 65 + 40)))
    nxt = tali('allo')
    f.seg(False, pdu[:12])
    f.seg(False, pdu[12:30])
    f.seg(False, pdu[30:] + nxt)
    # 22: a PDU with a 255 octet payload and 23: a header-only 'proa' followed by 'test'
    f.seg(True, tali('test', bytes(255)))
    f.seg(False, tali('proa') + tali('test', b'X'))
    f.close()                                               # 24-25
    # a second connection that starts in the middle (no handshake): the
    # first segment has a complete header, the heuristic finds it
    g = Flow(p, 40010, 40011, '192.0.2.3', '192.0.2.4')
    g.seg(True, tali('test', b'MIDSTREAM'))
    g.seg(False, tali('allo'))
    p.write(os.path.join(out, 'tali-coverage.pcap'))

    m = Pcap(DLT_EN10MB)
    h = Flow(m, 40020, 40021, '192.0.2.5', '192.0.2.6')
    h.handshake()
    h.seg(True, tali('test', b'X'))
    # a PDU announcing 100 octets but ended by FIN: truncated at the end of the stream
    h.seg(True, tali('test', bytes(100))[:30])
    h.close()
    # fewer than ten octets, not recognised as TALI
    k = Flow(m, 40022, 40023, '192.0.2.7', '192.0.2.8')
    k.seg(True, b'TALItest\x00')
    # unknown opcode: not TALI
    k.seg(True, b'TALIxxxx\x00\x00')
    m.write(os.path.join(out, 'tali-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')

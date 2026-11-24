#!/usr/bin/env python3
# Generates test/captures/hl7_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HL7 dissector (packet-hl7.c).

HL7 v2 over TCP uses the Lower Layer Protocol: 0x0B, the message
(segments terminated by CR), 0x1C 0x0D. TCP port 2575 is registered, and
a heuristic recognises 0x0B "MSH|" on any other port (then sets the
conversation dissector). The messages contain invented patients (no
real data). Every packet is built with struct; addresses 192.0.2.0/24.

Usage: mkhl7.py <output directory>
Writes hl7-coverage.pcap and hl7-coverage-malformed.pcap.
"""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_pkt(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opts = struct.pack('!BBH', 2, 4, 1460) if flags & 0x02 else b''
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    ps = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ps + tcp)) + tcp[18:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

class Flow:
    def __init__(self, cport, sport=2575, c=(192,0,2,1), s=(192,0,2,2), handshake=True):
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.pkts = []
        if handshake:
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.pkts.append(tcp_pkt(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def c2s(self, data):
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data)); self.cseq += len(data)
    def s2c(self, data):
        self.pkts.append(tcp_pkt(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data)); self.sseq += len(data)

SOB = b'\x0b'
EOB = b'\x1c\r'

def msg(*segs, term=b'\r'):
    """LLP block: SOB, segments each ended by term, EOB."""
    return SOB + b''.join(s.encode() + term for s in segs) + EOB

MSH = 'MSH|^~\\&|SENDER|FAC|RECV|FAC2|20240101120000||%s|%s|P|2.3'

def adt_a01(ctl='MSG0001'):
    return msg(MSH % ('ADT^A01', ctl),
               'EVN|A01|20240101120000',
               'PID|1||123456^^^HOSP^MR||DOE^JANE^Q||19700101|F|||1 MAIN ST^^TOWN^ST^12345||555-0100',
               'NK1|1|DOE^JOHN|SPO',
               'PV1|1|I|WARD^101^A||||1234^DOCTOR^ALICE',
               'AL1|1|DA|PENICILLIN',
               'DG1|1||I10^Hypertension',
               'IN1|1|PLAN1|ACME', 'ZZZ|custom|segment')

def main_frames():
    F = []
    # connection 1: port 2575 (registered), one message per segment
    f = Flow(40000)
    f.c2s(adt_a01())
    f.s2c(msg('MSH|^~\\&|RECV|FAC2|SENDER|FAC|20240101120001||ACK|ACK0001|P|2.3', 'MSA|AA|MSG0001'))
    # several message types and events (known and unknown)
    for mt in ('ORM^O01', 'ORU^R01', 'SIU^S12', 'MDM^T02', 'VXU^V04', 'QRY^A19', 'DFT^P03', 'BAR^P01', 'ZZZ^Z99', 'ADT^A08'):
        f.c2s(msg(MSH % (mt, 'CTL' + mt[:3]), 'PID|1||999^^^HOSP^MR||ROE^RICHARD',
                  'OBR|1|ORD1||CBC^Complete blood count', 'OBX|1|NM|WBC||6.5|10*3/uL|4-11|N',
                  'ORC|NW|ORD1', 'MSA|AA|X', 'ERR|0', 'QRD|20240101', 'QRF|X', 'SCH|1', 'TXA|1', 'RXA|0',
                  'RXE|1', 'NTE|1||a note', 'FT1|1', 'GT1|1', 'DB1|1', 'ARQ|1', 'SPM|1', 'ABC|1'))
    # message type without an event, message type with the event
    f.c2s(msg(MSH.replace('||%s', '||%s') % ('ACK', 'NOEVENT'), 'MSA|AE|MSG0001|error'))
    F += f.pkts

    # connection 2: framing: two messages in one segment, a message over
    # three segments, LF and CRLF terminated segments, a message and the
    # start of the next one
    g = Flow(40001)
    g.c2s(adt_a01('A') + adt_a01('B'))
    m = adt_a01('C')
    g.c2s(m[:20]); g.c2s(m[20:90]); g.c2s(m[90:])
    g.c2s(msg(MSH % ('ADT^A04', 'LF1'), 'PID|1||1', 'PV1|1|O', term=b'\n'))
    g.c2s(msg(MSH % ('ADT^A04', 'CRLF1'), 'PID|1||1', 'PV1|1|O', term=b'\r\n'))
    m = adt_a01('D'); n = adt_a01('E')
    g.c2s(m + n[:30]); g.c2s(n[30:])
    # reproducer (hl7_sob_offset): a complete message followed by bytes
    # that do not start with the LLP start-of-block byte
    g.c2s(msg(MSH % ('ADT^A01', 'R1'), 'PID|1||123') + b'garbage-no-sob|x|y\r\x1c\r')
    F += g.pkts

    # connection 3: other separators and field forms
    h = Flow(40002)
    h.c2s(msg('MSH#^~\\&#S#F#R#F2#20240101##ADT^A01#SEP1#P#2.3', 'PID#1##5'))     # field separator '#'
    h.c2s(msg('MSH|^~\\&|||||||ORU^R01|EMPTY|P|2.3', 'PID||||||||', '|||', 'ZZZ', 'PID|a|', '||x||'))
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101||ORU|NOSEP', 'OBX|1|ST'))              # type with no event or more separators
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101||ORU^|ENDSEP|P|2.3', 'OBX|1|ST|x'))   # event separator but no event
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101||AB|SHORT|P|2.3', 'OBX|1|ST|x'))      # 2 octet type
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101|||CTL|P|2.3', 'OBX|1|ST|x'))          # empty message type field
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101||ADT^A01^ZZZ|MORE|P|2.3', 'OBX|1|ST|x'))   # third component
    h.c2s(msg('MSH|^~\\&|S|F|R|F2|20240101||ADT^A01|LONGSEG|P|2.3', 'OBX|1|TX|' + 'x' * 600))
    F += h.pkts

    # connection 4: not the registered port: heuristic (0x0B "MSH|", also
    # lower case "msh|"), a message over two segments, then conversation
    k = Flow(40003, 3000)
    m = adt_a01('H1')
    k.c2s(m[:15]); k.c2s(m[15:])                               # first segment: heuristic + desegment
    k.s2c(msg('MSH|^~\\&|RECV|FAC2|SENDER|FAC|20240101||ACK|H1ACK|P|2.3', 'MSA|AA|H1'))
    k.c2s(adt_a01('H2'))
    k.c2s(msg('msh|^~\\&|S|F|R|F2|20240101||ADT^A01|LOWER|P|2.3', 'PID|1||1'))
    F += k.pkts
    # not HL7: starts with 0x0B but not MSH| (heuristic rejects) on port 3001
    q = Flow(40004, 3001)
    q.c2s(SOB + b'not an hl7 message\r' + EOB)
    q.c2s(b'\x0bMS')                                              # too short for the heuristic
    F += q.pkts
    return F

def malformed_frames():
    F = []
    f = Flow(41000)
    # MSH with fewer than 9 fields
    f.c2s(msg('MSH|^~\\&|S|F|R'))
    # MSH with only the encoding characters
    f.c2s(msg('MSH|^~\\&'))
    # MSH shorter than the separators
    f.c2s(msg('MSH|^~'))
    # MSH cut by the end of block
    f.c2s(SOB + b'MSH|^~\\&|S|F|R|F2|2024||ADT^A01' + EOB)
    # message type field at the very end of the tvb
    f.c2s(SOB + b'MSH|^~\\&|S|F|R|F2|2024||AD' + EOB)
    # a block holding only the start byte and an end of block
    f.c2s(SOB + EOB)
    # no end of block at all (reassembly never completes)
    f.c2s(SOB + b'MSH|^~\\&|S|F|R|F2|2024||ADT^A01|X|P|2.3\rPID|1\r')
    # message without a terminating CR in its segments (LF only, then EOB)
    g = Flow(41001, 3000)
    g.c2s(SOB + b'MSH|^~\\&|S|F|R|F2|2024||ADT^A01|X|P|2.3' + EOB)
    g.c2s(SOB + b'MSH|^~\\&|S|F|R|F2|2024||ADT^A01|X|P|2.3\rPID|1' + EOB)
    g.c2s(b'tail without start of block' + EOB)
    g.c2s(b'\x00' + b'MSH|^~\\&|S|F|R|F2|2024||ADT^A01|X|P|2.3\r' + EOB)
    F += f.pkts + g.pkts
    return F

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hl7-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hl7-coverage-malformed.pcap'), malformed_frames())

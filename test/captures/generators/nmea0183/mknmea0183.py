#!/usr/bin/env python3
# Generates test/captures/nmea0183_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-nmea0183.c (NMEA 0183 sentences,
UdPbC broadcasts with tag blocks, and the binary RrUdP/RaUdp/RpUdP file
transfer messages).

Usage: mknmea0183.py <outdir> [-v]

Writes nmea0183-coverage.pcapng (clean; Exported PDU frames naming the
"nmea0183" dissector, plus a few Ethernet/UDP frames that need the UDP
heuristic) and nmea0183-coverage-malformed.pcapng.  Everything is made up.

Every sentence of the decoder table is built from a sample body and in
five more variants made from it: all fields empty, only the first half
of the fields, no data after the sentence id, the odd and the even fields
empty.  Variants that make the dissector throw are listed in the
MOVED set and go to the malformed capture.
"""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = args[0] if args else '.'

# sentence id -> (talker, [sample bodies without talker and id; "," first])
S = {
 'AAM': ('GP', ['A,A,0.10,N,WPT1', 'V,V,0.5,K,WPT2']),
 'ABK': ('AI', ['002190000,A,12,1,3', '002190000,B,6,2,4']),
 'ACA': ('AI', ['1,5030.00,N,00430.00,E,4930.00,N,00330.00,E,5,2087,0,2088,1,0,0,A,1,123519.00']),
 'ACK': ('AG', ['003']),
 'ACS': ('AI', ['1,002190000,123519.00,13,05,2020']),
 'AIR': ('AI', ['002190000,1,0,2,1,002190001,3,0']),
 'AKD': ('EC', ['123519.00,EC,RM,1,1001,A,EC,RM,2', ',EC,RM,1,1001,A,,,', '123519.00,EC,RM,1,1001,,EC,,']),
 'ALA': ('EC', ['120000.00,EC,RM,2,1001,A,V,Engine alarm']),
 'ALM': ('GP', ['2,1,13,1940,00,5A7F,7E,0A3B,FD2C,A10F65,C5EF53,B1D9E2,A3F6C8,0A2,001']),
 'ALR': ('II', ['120000.00,001,A,V,Engine overheated', '120000.00,002,V,A,Fire']),
 'APB': ('GP', ['A,A,0.10,R,N,V,V,011,M,DEST,011,M,011,M,A', 'V,V,0.5,L,K,A,A,5,T,WPT,6,T,,,A']),
 'BEC': ('GP', ['225444,4917.24,N,12309.57,W,051.9,T,031.6,M,001.3,N,004']),
 'BOD': ('GP', ['045.,T,023.,M,DEST,START']),
 'BWC': ('GP', ['225444,4917.24,N,12309.57,W,051.9,T,031.6,M,001.3,N,004,A']),
 'BWR': ('GP', ['225444,4917.24,S,12309.57,E,051.9,T,031.6,M,001.3,N,004,D']),
 'BWW': ('GP', ['045.,T,023.,M,TOWPT,FROMWPT']),
 'CBR': ('AI', ['002190000,12,3,10,30,100,60,0,11,31,200,30,1']),
 'CUR': ('II', ['A,1,2,10.0,270.0,T,1.5,3,260.0,T,B']),
 'DBT': ('SD', ['12.3,f,3.7,M,2.0,F']),
 'DCN': ('LC', ['13,01,12345.6,A,02,23456.7,A,03,34567.8,A,A,A,A,1.2,3']),
 'DDC': ('II', ['D,50,N,C']),
 'DOR': ('II', ['S,123519.00,FD,01,02,3,A,0,Door open', 'E,123519.00,FD,01,02,5,A,1,Door event', 'F,123519.00,FD,01,02,,F,0,Door fault']),
 'DPT': ('SD', ['12.3,0.5,100']),
 'DSC': ('CD', ['20,3380400790,12,00,00,1423108312,2019,/,,B,E']),
 'DSE': ('CD', ['1,1,A,3380400790,00,EXPANSION']),
 'DSI': ('CD', ['1,1,002190000,090,A,ZONE,S,INFO,EXP']),
 'DSR': ('CD', ['1,1,002190000,S,INFO,EXP']),
 'DTM': ('GP', ['W84,,0.0,N,0.0,E,0.0,W84', '999,A,0.1,S,0.2,W,3.0,W72']),
 'ETL': ('II', ['123519.00,O,1,2,B,1', '123519.00,A,1,0,S,2', '123519.00,O,XX,,B,1']),
 'FSI': ('CD', ['0600,0400,o,5']),
 'GBS': ('GP', ['015054.00,1.2,1.5,3.2,07,0.5,1.0,0.2', '015054.00,1.2,1.5,3.2,,,,,']),
 'GGA': ('GP', ['123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,1.5,0123', '123519,4807.038,S,01131.000,W,2,08,0.9,545.4,M,46.9,M,,',
                '123519,4807.038,N,01131.000,E,1,08,0.9,545.4,F,46.9,F,,', '123,48,N,011,E,0,00,,,,,,', ',,,,,,,,,,,,,']),
 'GLC': ('LC', ['2800,13000.0,A,25000.0,A,46000.0,B,,,,,,', '2800,0,0,0,0,0,0,0,0,0,0', '2800,13000.0,A,25000.0,A,46000.0,B,1,A,2,A,3,A,B']),
 'GLL': ('GP', ['4916.45,N,12311.12,W,225444,A,A', '4916.45,S,12311.12,E,225444,V,N', ',,,,,,']),
 'GMP': ('GP', ['123519.00,UTM,32,1234567.89,2345678.90,DA,12,0.9,45.0,10.0,1.5,0001', '123519.00,UTM,32,1.0,2.0,DNNN,12,0.9,45.0,10.0,,']),
 'GNS': ('GN', ['111648.00,0235.0368,S,04422.6048,W,ANNN,10,0.8,10.0,-24.4,5.0,0000', '111648.00,,,,,,,,,,,', '111648.00,0235.0368,S,04422.6048,W,A,10,0.8,10.0,-24.4,,']),
 'GRS': ('GN', ['123519.00,1,0.1,-0.2,0.3,0.4,-0.5', '123519.00,0,0.1']),
 'GSA': ('GP', ['A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1', 'M,1,70000,xx,,,,,,,,,,,,,']),
 'GST': ('GP', ['172814.0,0.006,0.023,0.020,273.6,0.023,0.020,0.031']),
 'GSV': ('GP', ['2,1,08,01,40,083,46,02,17,308,41,12,07,344,39,14,22,228,45', '2,2,08,15,01,100,,20,02,200,30', '1,1,01,70000,10,100,20,x,5,6,7', '1,1,00']),
 'HBT': ('II', ['5,A,1', ',A,2']),
 'HDG': ('HE', ['98.3,0.0,E,12.6,W']),
 'HDT': ('HE', ['274.07,T', '274.07,X']),
 'HMR': ('HE', ['123.4,125.0,2.0,1.6,A,123.4,A,M,0.5,E,125.0,A,M,0.6,W,0.0']),
 'HMS': ('HE', ['10.0,11.0,2.0']),
 'HSC': ('HE', ['123.4,T,124.0,M']),
 'HTC': ('AG', ['A,10.0,R,M,T,15.0,5.0,100.0,5.0,10.0,2.0,100.0,T']),
 'HTD': ('AG', ['A,10.0,R,M,T,15.0,5.0,100.0,5.0,10.0,2.0,100.0,T,A,A,A,123.0']),
 'LCD': ('LC', ['2800,1,2,3,4,5,6,7,8,9,10,11,12']),
 'LR1': ('AI', ['1,002190001,002190000,SHIP NAME,CALL,1234567', '1,002190001,002190000,,CALL,1234567']),
 'LR2': ('AI', ['1,002190001,13052020,123519.00,5030.00,N,00430.00,E,120.0,T,5.5,N']),
 'LR3': ('AI', ['1,002190001,PORT,13052020,123519.00,5.5,10,100,20,70,5', '1,002190001,,,,,,,,,']),
 'LRF': ('AI', ['1,002190000,SHIP NAME,ABEFIJ,ABEFIJ', '1,002190000,SHIP,AB,,']),
 'LRI': ('AI', ['1,0,002190000,002190001,5030.00,N,00430.00,E,4930.00,N,00330.00,E']),
 'MLA': ('GL', ['1,1,5,100,0,0100,0200,0300,0400,0500,0600,0700,0800,0900,0A00']),
 'MSK': ('CR', ['293.0,A,200,M,10,1']),
 'MSS': ('CR', ['50,20,293.0,200,1']),
 'MTW': ('WI', ['15.5,C']),
 'MWD': ('WI', ['120.0,T,115.0,M,12.0,N,6.2,M']),
 'MWV': ('WI', ['45.0,R,12.3,N,A']),
 'OSD': ('II', ['123.4,A,125.0,B,5.5,B,100.0,1.5,N']),
 'RMA': ('LC', ['A,4916.45,N,12311.12,W,1.0,2.0,5.5,120.0,12.0,W,A']),
 'RMB': ('GP', ['A,0.66,L,001,002,4913.30,N,12310.20,W,1.5,45.0,5.5,V,A']),
 'RMC': ('GP', ['123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A', '123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,E,A',
                '123519,V,4807.038,S,01131.000,W,022.4,084.4,230394,,,N', '123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,X,A', '123519,A,4807.038,N,01131.000,E,022.4,084.4,231370,1.0,,D']),
 'ROT': ('TI', ['-12.5,A', '3.0,V']),
 'RPM': ('II', ['S,1,2400,5.0,A']),
 'RSA': ('II', ['10.0,A,-3.0,A']),
 'RSD': ('RA', ['1.0,2.0,3.0,4.0,5.0,6.0,7.0,8.0,9.0,10,N,N']),
 'RTE': ('GP', ['2,1,c,0,W1,W2,W3', '1,1,w,1']),
 'SFI': ('CD', ['2,1,0500,m,0600,s,0700,m', '1,1,0500']),
 'SSD': ('AI', ['CALL,NAME,10,20,5,5,1,A']),
 'STN': ('II', ['12']),
 'TLB': ('RA', ['1,TGT1,2,TGT2', '3']),
 'TLL': ('RA', ['1,5030.00,N,00430.00,E,TARGET,123519.00,T,R']),
 'TTM': ('RA', ['1,5.0,45.0,T,10.0,90.0,T,0.5,6.0,N,TGT,T,R,123519.00,A']),
 'TUT': ('GP', ['GP,2,1,1,C,TEXT']),
 'TXT': ('GP', ['01,01,02,ANTSTATUS=OPEN']),
 'VBW': ('VD', ['1.2,0.3,A,1.3,0.4,A,0.2,A,0.3,A']),
 'VDR': ('II', ['10.0,T,11.0,M,1.5,N']),
 'VHW': ('VW', ['45.0,T,43.0,M,5.5,N,10.2,K', '45.0,X,43.0,X,5.5,X,10.2,X']),
 'VLW': ('VW', ['10.1,N,1.2,N,9.8,N,0.9,N', '10.1,X,1.2,X,9.8,X,0.9,X']),
 'VPW': ('II', ['1.0,N,0.5,M']),
 'VSD': ('II', ['70,5.5,10,PORT,123519.00,13,05,0,0']),
 'VTG': ('GP', ['054.7,T,034.4,M,005.5,N,010.2,K,A', '054.7,X,034.4,X,005.5,X,010.2,X,N']),
 'WCV': ('GP', ['5.5,N,WPT1,A']),
 'WNC': ('GP', ['10.0,N,18.5,K,TO,FROM']),
 'WPL': ('GP', ['4917.16,N,12310.64,W,WPT1']),
 'XDR': ('II', ['A,0.5,D,PITCH,A,0.7,D,ROLL', 'C,15.5,C,TEMP']),
 'XTE': ('GP', ['A,A,0.67,L,N,A']),
 'XTR': ('GP', ['1.5,L']),
 'ZDA': ('GP', ['201530.00,04,07,2002,00,00']),
 'ZDL': ('GP', ['123519.00,100.0,L']),
 'ZFO': ('GP', ['123519.00,001530.00,WPT']),
 'ZTG': ('GP', ['123519.00,001530.00,WPT']),
 'ZZZ': ('GP', ['1,,3,abc']),
}

MOVED = set()
KEYS = []
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'moved.txt')):
    MOVED = set(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'moved.txt')).read().split())


def cs(body):
    c = 0
    for b in body.encode('latin-1'):
        c ^= b
    return c


def sentence(body, first='$', crlf=b'\r\n', checksum=None):
    c = cs(body) if checksum is None else checksum
    return ('%s%s*%02X' % (first, body, c)).encode('latin-1') + crlf


def exp_pdu(payload):
    n = b'nmea0183'
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


class Cap:
    """pcapng writer: interface 0 is Exported PDU (252), interface 1 Ethernet"""
    def __init__(self):
        self.recs = []; self.ts = 1700000000; self.marks = []
    def mark(self, t):
        self.marks.append((len(self.recs) + 1, t))
    def pkt(self, p, caplen=None, iface=0):
        self.ts += 1
        cl = len(p) if caplen is None else caplen
        self.recs.append((iface, self.ts, p[:cl], len(p)))
    def write(self, name):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 252, 0, 65535))
        out += blk(1, struct.pack('<HHI', 1, 0, 65535))
        for iface, ts, data, olen in self.recs:
            out += blk(6, struct.pack('<IIIII', iface, (ts * 1000000) >> 32, (ts * 1000000) & 0xffffffff, len(data), olen) + data)
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(out)
        if VERBOSE:
            print(name, len(self.recs), 'frames')
            for i, (n, t) in enumerate(self.marks):
                end = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else len(self.recs)
                print('  %d-%d  %s' % (n, end, t))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_frame(payload, sport=45000, dport=10110, ipid=1):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 255]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('ffffffffffff') + bytes.fromhex('020000000001') + b'\x08\x00' + ip + udp


def variants(sid, talker, body):
    """(name, full sentence body) for a sample"""
    f = body.split(',')
    yield 'full', talker + sid + ',' + body
    yield 'empty', talker + sid + ',' * len(f)
    yield 'half', talker + sid + ',' + ','.join(f[:max(1, len(f) // 2)])
    yield 'nodata', talker + sid
    yield 'odd', talker + sid + ',' + ','.join(x if i % 2 == 0 else '' for i, x in enumerate(f))
    yield 'even', talker + sid + ',' + ','.join(x if i % 2 == 1 else '' for i, x in enumerate(f))


def build():
    c = Cap(); m = Cap()
    m.mark('Malformed: the file descriptor length reproducers, valid sentences that throw, the sentence variants that throw (all GLC variants, see README), then missing checksum character, short sentences, UdPbC and binary packets cut inside the header, tag block without end')
    c.mark('Every sentence of the decoder table (' + str(len(S)) + ' ids incl. an unknown one): sample bodies and their variants (full, all fields empty, first half, no data, odd fields empty, even fields empty)')
    for sid in sorted(S):
        talker, bodies = S[sid]
        for bi, body in enumerate(bodies):
            for vn, b in variants(sid, talker, body):
                key = '%s/%d/%s' % (sid, bi, vn)
                if vn == 'nodata' and bi:
                    continue
                pdu = exp_pdu(sentence(b))
                if key not in MOVED:
                    KEYS.append(key)
                (m if key in MOVED else c).pkt(pdu)
    c.mark('Sentence framing: ! start delimiter, other first character, wrong checksum, no CR LF, LF only, sentence longer than 82 octets, lower case sentence id, talker IDs of several kinds, proprietary talker, a query sentence')
    c.pkt(exp_pdu(sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A', first='!')))
    c.pkt(exp_pdu(sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A', first='%')))
    c.pkt(exp_pdu(sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A', checksum=0)))
    c.pkt(exp_pdu(sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A', crlf=b'')))
    c.pkt(exp_pdu(sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A', crlf=b'\n')))
    c.pkt(exp_pdu(sentence('GPTXT,01,01,02,' + 'X' * 90)))
    c.pkt(exp_pdu(sentence('gpgll,4916.45,N,12311.12,W,225444,A,A')))
    for t in ('AB', 'AD', 'BD', 'CS', 'EC', 'GA', 'GL', 'GN', 'GP', 'HC', 'II', 'IN', 'LC', 'P ', 'QZ', 'RA', 'SD', 'TI', 'VD', 'WI', 'YX', 'ZZ', 'Pxx'):
        c.pkt(exp_pdu(sentence(t + 'HDT,274.07,T')))
    c.pkt(exp_pdu(sentence('PGRMZ,93,f,3')))
    c.pkt(exp_pdu(sentence('GPQ,GLL')))
    c.mark('UdPbC broadcasts: one sentence, several sentences, tag blocks (one, several, an unterminated one), a sentence without CR LF')
    ub = b'UdPbC\0'
    g = sentence('GPGLL,4916.45,N,12311.12,W,225444,A,A')
    h = sentence('GPHDT,123.4,T')
    c.pkt(exp_pdu(ub + g))
    c.pkt(exp_pdu(ub + g + h + g))
    tb = lambda s: b'\\' + s + b'*' + b'%02X' % cs(s.decode()) + b'\\'
    c.pkt(exp_pdu(ub + tb(b's:AB123,c:1700000000') + g))
    c.pkt(exp_pdu(ub + tb(b's:AB123') + g + tb(b'c:1700000001') + tb(b'n:2') + h))
    c.pkt(exp_pdu(ub + g[:-2]))
    c.pkt(exp_pdu(ub + g + h[:-2]))
    c.mark('Binary file transfer: RrUdP, RaUdp, RpUdP; data message sequence 1 (file descriptor with a data type and status) and 2, query, ack, header only; the file descriptor length reproducers are in the malformed capture')
    def bhdr(prefix=b'RrUdP\0', mtype=1, seq=1, maxseq=3, blk=0x1234):
        return prefix + struct.pack('>H', 1) + b'SRC001' + b'DST001' + struct.pack('>HIII', mtype, blk, seq, maxseq)
    def fd(fdl, tl, status=b'status', flen=100, dtype=b'TEXT'):
        return struct.pack('>IIHBBB', fdl, flen, 0x0102, 1, 2, tl) + dtype[:tl].ljust(tl, b'A') + status
    for pre in (b'RrUdP\0', b'RaUdp\0', b'RpUdP\0'):
        st = b'status'
        c.pkt(exp_pdu(bhdr(pre) + fd(13 + 4 + len(st), 4, st) + b'DATA' * 4))
    c.pkt(exp_pdu(bhdr(seq=2) + b'binary data' * 3))
    c.pkt(exp_pdu(bhdr(mtype=2, seq=1)))
    c.pkt(exp_pdu(bhdr(mtype=3, seq=1) + b'\0\0'))
    c.pkt(exp_pdu(bhdr()))
    c.pkt(exp_pdu(bhdr(mtype=1, seq=1) + fd(13, 0, b'') + b'DATA'))
    # the file descriptor length check (fdl < type_len + 13) adds an expert info of the
    # Malformed group, and a packet that ends after the descriptor throws: both are in the
    # malformed capture
    for fdl, tl in ((12, 0), (0, 0), (0xFFFFFFFF, 0), (13, 5)):
        m.pkt(exp_pdu(bhdr() + fd(fdl, tl) + b'DATA' * 4))
    m.pkt(exp_pdu(bhdr(mtype=1, seq=1) + fd(14, 0, b'x')))
    m.pkt(exp_pdu(bhdr() + fd(12, 0)[:20]))
    m.pkt(exp_pdu(sentence('IIETL,120000,ABCD,1,2,BC')))
    m.pkt(exp_pdu(sentence('GPAAM,,A,0.10,N,WPT1')))
    m.pkt(exp_pdu(b'$GPGGA*00\r\n'))
    m.pkt(exp_pdu(b'$GPZZZ*00\r\n'))
    c.mark('Over UDP port 10110 (needs the heuristic, --enable-heuristic nmea0183_udp, or Decode As): a sentence, a UdPbC datagram, a binary message, a non-NMEA datagram, a short datagram')
    c.pkt(udp_frame(g), iface=1)
    c.pkt(udp_frame(ub + g + h), iface=1)
    c.pkt(udp_frame(bhdr(seq=2) + b'abc'), iface=1)
    c.pkt(udp_frame(bhdr(b'RaUdp\0', seq=2) + b'abc'), iface=1)
    c.pkt(udp_frame(bhdr(b'RpUdP\0', seq=2) + b'abc'), iface=1)
    c.pkt(udp_frame(sentence('GPHDT,1.0,T')), iface=1)
    c.pkt(udp_frame(sentence('PGRMZ,93,f,3')), iface=1)
    c.pkt(udp_frame(sentence('ZZHDT,1.0,T')), iface=1)
    c.pkt(udp_frame(b'not nmea at all, just text'), iface=1)
    c.pkt(udp_frame(b'$GP'), iface=1)
    c.pkt(udp_frame(b'$GPHDT,'), iface=1)
    c.pkt(udp_frame(b'$XXXXX,12345*00\r\n'), iface=1)
    c.pkt(udp_frame(b'$PXXX,1*00\r\n'), iface=1)
    c.pkt(udp_frame(b'$PGRM,1*00\r\n'), iface=1)

    m.pkt(exp_pdu(b'$GPGLL,4916.45,N,12311.12,W,225444,A,A'))
    m.pkt(exp_pdu(b'$GPGLL*0'))
    m.pkt(exp_pdu(b'$GPGLL*'))
    m.pkt(exp_pdu(b'$GPGLL,*0'))
    m.pkt(exp_pdu(b'$GPGLL,4916.45,N,12311.12,W,225444,A,A*'))
    m.pkt(exp_pdu(b'$GPG'))
    m.pkt(exp_pdu(b'$G'))
    m.pkt(exp_pdu(b'$'))
    m.pkt(exp_pdu(b'UdPbC\0'))
    m.pkt(exp_pdu(b'UdPbC\0\\s:abc'))
    m.pkt(exp_pdu(b'UdPbC\0$'))
    m.pkt(exp_pdu(b'UdPbC'))
    for n in (6, 8, 14, 20, 22, 26, 30, 34, 38, 42, 46, 50):
        m.pkt(exp_pdu(bhdr()[:n] if n <= 34 else (bhdr() + fd(19, 4, b'status') + b'DATAx')[:n]))
    m.pkt(exp_pdu(bhdr() + struct.pack('>I', 19)))
    m.pkt(exp_pdu(bhdr(b'RaUdp\0') + fd(100, 4)))
    # every sentence cut at every position (checksum and CRLF missing or partial)
    for sid in sorted(S):
        talker, bodies = S[sid]
        s = sentence(talker + sid + ',' + bodies[0])
        for cut in (len(talker + sid) + 1, len(s) // 2, len(s) - 4, len(s) - 2):
            m.pkt(exp_pdu(s[:cut]))
        m.pkt(exp_pdu(s), caplen=len(exp_pdu(s)) - 6)
    c.mark('A char field holding the non-printable octet 0xBD (tshark -V aborted on it while the FT_CHAR fields were BASE_NONE)')
    c.pkt(exp_pdu(sentence('GPAAM,\xbd,A,0.10,N,WPT1')))
    if '-k' in sys.argv:
        open(os.path.join(OUT, 'keys.txt'), 'w').write('\n'.join(KEYS) + '\n')
    c.write('nmea0183-coverage.pcapng')
    m.write('nmea0183-coverage-malformed.pcapng')


build()

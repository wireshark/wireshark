#!/usr/bin/env python3
# Generates test/captures/iec104_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-iec104.c: IEC 60870-5-104 (TCP 2404), the shared
ASDU dissector with IEC 60870-5-7 secure authentication, IEC 60870-5-101 and
-103 (no default port: TCP 2405 and 2406 need Decode As).
Usage: mkiec104.py <outdir> [-v]   (needs pcaplib.py beside it)
All authentication/HMAC/key fields are constant placeholder octets."""
import struct
import sys
import os
from pcaplib import csum, eth, ip4, pcap

CLI, SRV = '192.0.2.10', '192.0.2.20'
MC, MS = '02:00:00:00:00:0a', '02:00:00:00:00:14'

class Flow:
    """one TCP connection; segments are built in order"""
    def __init__(self, sport, dport, frames):
        self.sport, self.dport, self.frames = sport, dport, frames
        self.seq = {0: 1000, 1: 5000}
        self.ident = 1
    def _pkt(self, d, flags, payload):
        sp, dp = (self.sport, self.dport) if d == 0 else (self.dport, self.sport)
        src, dst = (CLI, SRV) if d == 0 else (SRV, CLI)
        ack = self.seq[1 - d]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack if flags & 0x10 else 0,
                          5 << 4, flags, 8192, 0, 0)
        ip = ip4(src, dst, 6, tcp + payload, ident=self.ident); self.ident += 1
        # TCP checksum
        pseudo = bytes(map(int, src.split('.'))) + bytes(map(int, dst.split('.'))) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = ip4(src, dst, 6, tcp + payload, ident=self.ident - 1)
        e = eth(MS, MC, 0x0800, ip) if d == 0 else eth(MC, MS, 0x0800, ip)
        self.frames.append(e)
        self.seq[d] += len(payload) + (1 if flags & 0x03 else 0)
    def handshake(self):
        self._pkt(0, 0x02, b''); self._pkt(1, 0x12, b''); self._pkt(0, 0x10, b'')
    def send(self, d, payload):
        self._pkt(d, 0x18, payload)
        self._pkt(1 - d, 0x10, b'')
    def send_noack(self, d, payload):
        self._pkt(d, 0x18, payload)

# ---------------------------------------------------------------- 104 framing
def apci_i(tx, rx, asdu):
    return struct.pack('<BBHH', 0x68, 4 + len(asdu), tx << 1, rx << 1) + asdu
def apci_s(rx):
    return struct.pack('<BBHH', 0x68, 4, 1, rx << 1)
def apci_u(code):
    return struct.pack('<BBBBBB', 0x68, 4, code, 0, 0, 0)

SZ = dict(SIQ=1, DIQ=1, QDS=1, VTI=1, BSI=4, NVA=2, SVA=2, FLT=4, BCR=5, SEP=1, SPE=1,
          QDP=1, OCI=1, SCD=4, CP16=2, CP24=3, CP56=7, SCO=1, DCO=1, RCO=1, QOS=1,
          COI=1, QOI=1, QCC=1, FBP=2, QRP=1, TSC=2, QPM=1, QPA=1, NOF=2, LOF=3,
          FRQ=1, NOS=1, SRQ=1, SCQ=1, LSQ=1, CHS=1, AFQ=1, LOS=1, SOF=1, AID=2)
TYPES = {
 1: 'SIQ', 2: 'SIQ CP24', 3: 'DIQ', 4: 'DIQ CP24', 5: 'VTI QDS', 6: 'VTI QDS CP24',
 7: 'BSI QDS', 8: 'BSI QDS CP24', 9: 'NVA QDS', 10: 'NVA QDS CP24', 11: 'SVA QDS',
 12: 'SVA QDS CP24', 13: 'FLT QDS', 14: 'FLT QDS CP24', 15: 'BCR', 16: 'BCR CP24',
 17: 'SEP CP16 CP24', 18: 'SPE QDP CP16 CP24', 19: 'OCI QDP CP16 CP24', 20: 'SCD QDS',
 21: 'NVA', 30: 'SIQ CP56', 31: 'DIQ CP56', 32: 'VTI QDS CP56', 33: 'BSI QDS CP56',
 34: 'NVA QDS CP56', 35: 'SVA QDS CP56', 36: 'FLT QDS CP56', 37: 'BCR CP56',
 38: 'SEP CP16 CP56', 39: 'SPE QDP CP16 CP56', 40: 'OCI QDP CP16 CP56',
 41: 'AID BCR CP56', 45: 'SCO', 46: 'DCO', 47: 'RCO', 48: 'NVA QOS', 49: 'SVA QOS',
 50: 'FLT QOS', 51: 'BSI', 58: 'SCO CP56', 59: 'DCO CP56', 60: 'RCO CP56',
 61: 'NVA QOS CP56', 62: 'SVA QOS CP56', 63: 'FLT QOS CP56', 64: 'BSI CP56',
 70: 'COI', 100: 'QOI', 101: 'QCC', 103: 'CP56', 104: 'FBP', 105: 'QRP', 106: 'CP16',
 107: 'TSC CP56', 110: 'NVA QPM', 111: 'SVA QPM', 112: 'FLT QPM', 113: 'QPA',
 120: 'NOF LOF FRQ', 121: 'NOF NOS LOF SRQ', 122: 'NOF NOS SCQ', 123: 'NOF NOS LSQ CHS',
 124: 'NOF NOS AFQ', 126: 'NOF LOF SOF CP56', 127: 'NOF CP56 CP56',
}

def comp(name, k):
    """bytes of one information element, varied with k so that flag bits differ"""
    n = SZ[name]
    if name == 'CP56':      # ms, min, hour (summer time bit), day|dow, month, year
        return struct.pack('<HBBBBB', (1000 * k + 123) % 60000, (k * 7) % 60 | (0x80 if k % 3 == 2 else 0),
                           (k * 5) % 24 | (0x80 if k % 2 else 0), 1 + (k * 3) % 28 | ((1 + k % 7) << 5),
                           1 + k % 12, 24 + k % 3)
    if name == 'CP24':
        return struct.pack('<HB', (777 * k) % 60000, (k * 11) % 60 | (0x80 if k % 4 == 3 else 0))
    if name == 'BCR':
        return struct.pack('<iB', 100000 * k - 1, (k % 32) | (0xe0 if k % 2 else 0))
    pats = (0x00, 0xff, 0x55, 0xaa, 0x81, 0x7e)
    return bytes((pats[(k + i) % 6] ^ (i if k > 5 else 0)) & 0xff for i in range(n))

def obj_data(tid, k):
    return b''.join(comp(c, k) for c in TYPES[tid].split())

def asdu(tid, cot=3, n=1, sq=0, addr=1, oa=0, objs=None, ioa=100, nega=0, test=0):
    h = struct.pack('<BBBBH', tid, (sq << 7) | n, cot | (nega << 6) | (test << 7), oa, addr)
    b = b''
    for i in range(n):
        if sq and i:
            b += obj_data(tid, i + tid % 40)
        else:
            b += struct.pack('<I', ioa + 10 * i)[:3] + obj_data(tid, i + tid % 40)
    return h + (b if objs is None else objs)

def cp56(k=1): return comp('CP56', k)

# ---------------------------------------------------------- authentication
PH = b'\xa5'            # placeholder octet for HMAC / challenge / key data
def seg(asn, fir, fin, data):
    return bytes([(0x80 if fin else 0) | (0x40 if fir else 0) | asn]) + data
def sasdu(tid, segdata, cot=3, addr=1):
    return struct.pack('<BBBBH', tid, 1, cot, 0, addr) + segdata

def build(out, verbose):
    f104, marks = [], []
    def mk(desc): marks.append((len(f104) + 1, desc))
    fl = Flow(49152, 2404, f104)
    mk('TCP handshake'); fl.handshake()
    tx = {0: 0, 1: 0}
    def ifr(d, a, desc=None):
        if desc: mk(desc)
        fl.send(d, apci_i(tx[d], tx[1 - d], a)); tx[d] += 1
    # U and S frames
    for code, desc in ((0x07, 'STARTDT act'), (0x0b, 'STARTDT con'), (0x13, 'STOPDT act'),
                       (0x23, 'STOPDT con'), (0x43, 'TESTFR act'), (0x83, 'TESTFR con'), (0xc3, 'U frame, unknown function')):
        mk('U: ' + desc); fl.send(0 if code in (0x07, 0x13, 0x43) else 1, apci_u(code))
    mk('S frame'); fl.send(0, apci_s(0)); fl.send(1, apci_s(5))
    # every type in three shapes, cycling through the causes of transmission
    cot = 1
    for tid in sorted(TYPES):
        d = 0 if tid >= 45 and tid not in (70, 120, 121, 124, 126) else 1
        shapes = ((1, 0), (2, 0), (3, 1))
        for n, sq in shapes:
            if tid in (41, 127) and n == 3: n = 2     # keep the APDU well below 253
            cot = cot % 47 + 1
            ifr(d, asdu(tid, cot=cot, n=n, sq=sq, addr=tid, ioa=1000 * tid, nega=(cot % 5 == 0),
                        test=(cot % 7 == 0)),
                'type %d, %d object(s), SQ=%d' % (tid, n, sq) if n == 1 else None)
    # F_SG_NA_1 segment (variable length), several lengths
    for los in (0, 1, 5, 20):
        a = struct.pack('<BBBBH', 125, 1, 5, 0, 7) + b'\x04\x05\x00' + struct.pack('<HBB', 0x1234, 2, los) + b'\x5a' * los
        ifr(1, a, 'F_SG_NA_1 segment, length %d' % los)
    # unknown type identifications: default branch
    for tid in (22, 29, 42, 65, 71, 80, 88, 102, 108, 109, 114, 119, 128, 200, 255):
        ifr(1, struct.pack('<BBBBH', tid, 1, 3, 0, 1) + b'\x01\x02\x03' + bytes([tid, 9, 8, 7]), 'unknown type %d' % tid if tid in (22, 255) else None)
    ifr(1, struct.pack('<BBBBH', 22, 1, 3, 0, 1) + b'\x01\x02\x03', 'unknown type without data')
    # COT edge cases: causes up to 63 incl. unknown ones, NEGA/TEST bits
    for c in (0, 20, 36, 37, 41, 44, 45, 46, 47, 48, 63):
        ifr(1, asdu(1, cot=c, test=(c % 2), nega=(c % 3 == 0)))
    # --- authentication (IEC 60870-5-7), placeholder data
    mk('S_CH_NA_1 challenge, one segment')
    ifr(0, sasdu(81, seg(1, 1, 1, struct.pack('<IHBBH', 1, 1, 1, 1, 16) + PH * 16)))
    mk('S_CH_NA_1 challenge in two segments (reassembly)')
    ifr(0, sasdu(81, seg(2, 1, 0, struct.pack('<IHBBH', 2, 1, 1, 1, 24) + PH * 6)))
    ifr(0, sasdu(81, seg(2, 0, 1, PH * 18)))
    mk('S_RP_NA_1 reply')
    ifr(1, sasdu(82, seg(1, 1, 1, struct.pack('<IHH', 1, 1, 16) + PH * 16)))
    ifr(1, sasdu(82, seg(2, 1, 1, struct.pack('<IHH', 2, 1, 0))))
    mk('S_AR_NA_1 aggressive mode request')
    ifr(0, sasdu(83, seg(1, 1, 1, asdu(45, cot=6, n=1, addr=1, ioa=500) + struct.pack('<IH', 3, 1) + PH * 8)))
    ifr(0, sasdu(83, seg(2, 1, 1, asdu(45, cot=6, n=1, addr=1, ioa=500) + struct.pack('<IH', 3, 1))))
    mk('S_KR_NA_1 session key status request')
    ifr(0, struct.pack('<BBBBH', 84, 1, 6, 0, 1) + struct.pack('<H', 1))
    mk('S_KS_NA_1 session key status, every HMAC algorithm')
    for hal in (0, 3, 4, 6, 9):
        hl = {3: 8, 4: 16, 6: 12}.get(hal, 0)
        ifr(1, sasdu(85, seg(1, 1, 1, struct.pack('<IHBBBH', 4, 1, 1, 1, hal, 8) + PH * 8 + PH * hl)))
    mk('S_KC_NA_1 session key change')
    ifr(0, sasdu(86, seg(1, 1, 1, struct.pack('<IHH', 5, 1, 32) + PH * 32)))
    mk('S_ER_NA_1 authentication error with text')
    ifr(1, sasdu(87, seg(1, 1, 1, struct.pack('<IHHB', 6, 1, 2, 4) + cp56(3) + struct.pack('<H', 5) + b'error')))
    ifr(1, sasdu(87, seg(2, 1, 1, struct.pack('<IHHB', 7, 1, 2, 1) + cp56(4) + struct.pack('<H', 0))))
    mk('S_* type with an unknown tail (the default branch of the segment code)')
    ifr(1, sasdu(88, seg(1, 1, 1, b'\x01\x02\x03abc')))
    # --- TCP framing of APDUs
    mk('two APDUs in one TCP segment')
    a1 = apci_i(tx[0], tx[1], asdu(1, ioa=1)); tx[0] += 1
    a2 = apci_i(tx[0], tx[1], asdu(3, ioa=2)); tx[0] += 1
    fl.send(0, a1 + a2)
    mk('one APDU split over two TCP segments (reassembly)')
    a = apci_i(tx[0], tx[1], asdu(13, n=2, ioa=7)); tx[0] += 1
    fl.send_noack(0, a[:9]); fl.send(0, a[9:])
    mk('APDU split inside the APCI')
    a = apci_i(tx[0], tx[1], asdu(36, ioa=9)); tx[0] += 1
    fl.send_noack(0, a[:3]); fl.send(0, a[3:])
    mk('noise octets before the start byte')
    a = apci_i(tx[0], tx[1], asdu(1, ioa=11)); tx[0] += 1
    fl.send(0, b'\x01\x02\x03' + a)
    mk('three APDUs, the last one cut (U, S, I start)')
    fl.send(1, apci_u(0x43) + apci_s(3) + apci_u(0x83))
    mk('S frame followed by an I frame in one segment')
    a = apci_i(tx[1], tx[0], asdu(9, ioa=13)); tx[1] += 1
    fl.send(1, apci_s(tx[0]) + a)
    mk('retransmission of the previous segment')
    fl._pkt(1, 0x18, apci_u(0x43)); fl.seq[1] -= 6; fl.send(1, apci_u(0x43))
    mk('FIN')
    fl._pkt(0, 0x11, b''); fl._pkt(1, 0x11, b''); fl._pkt(0, 0x10, b'')
    n104 = len(f104)

    # --- 101 on TCP 2405 and 103 on TCP 2406 (Decode As needed)
    def cs(b): return sum(b) & 0xff
    f101 = []
    f1 = Flow(50101, 2405, f101); f1.handshake()
    def v101(ctrl, addr, a):
        body = bytes([ctrl, addr]) + a
        return bytes([0x68, len(body), len(body), 0x68]) + body + bytes([cs(body), 0x16])
    def fx101(ctrl, addr):
        body = bytes([ctrl, addr]); return bytes([0x10]) + body + bytes([cs(body), 0x16])
    f1.send(0, b'\xe5')
    for ctrl in (0x40, 0x49, 0x5a, 0x7b, 0x00, 0x0b, 0x20, 0x8b):      # primary / secondary
        f1.send(0 if ctrl & 0x40 else 1, fx101(ctrl, 5))
    def a101(tid, cot, ioa, n=1, sq=0):   # 1 octet COT, 1 octet ASDU address, 2 octet IOA (the defaults)
        body = b''
        for i in range(n):
            body += (struct.pack('<H', ioa + 10 * i) if (not sq or i == 0) else b'') + obj_data(tid, i)
        return struct.pack('<BBBB', tid, (sq << 7) | n, cot, 9) + body
    for tid in (1, 3, 9, 13, 30, 36, 45, 100, 103):
        f1.send(0 if tid >= 45 else 1, v101(0x73 if tid >= 45 else 0x08, 5, a101(tid, 6 if tid >= 45 else 3, 200)))
    f1.send(1, v101(0x08, 5, a101(1, 3, 50, n=3, sq=1)))
    f1.send_noack(0, v101(0x73, 5, a101(100, 6, 0))[:7]); f1.send(0, v101(0x73, 5, a101(100, 6, 0))[7:])
    f1.send(0, b'\xe5' + fx101(0x49, 5))
    n101 = len(f101)
    f103 = []
    f3 = Flow(50103, 2406, f103); f3.handshake()
    def v103(ctrl, addr, a):
        body = bytes([ctrl, addr]) + a
        return bytes([0x68, len(body), len(body), 0x68]) + body + bytes([cs(body), 0x16])
    def hd(t, n, cot, fun=160, inf=1): return bytes([t, n, cot, 1, fun, inf])
    f3.send(1, b'\xe5')
    for ctrl in (0x40, 0x49, 0x5a, 0x7b, 0x00, 0x0b, 0x20, 0x8b):
        f3.send(0 if ctrl & 0x40 else 1, bytes([0x10, ctrl, 1]) + bytes([(ctrl + 1) & 0xff, 0x16]))
    f3.send(1, v103(0x08, 1, hd(1, 1, 1) + b'\x02' + struct.pack('<HBB', 12345, 30, 5)[:4] + b'\x00'))
    f3.send(1, v103(0x08, 1, hd(1, 2, 2) + (b'\x01' + struct.pack('<HBB', 1, 2, 3) + b'\x00') * 2))
    f3.send(1, v103(0x08, 1, hd(5, 1, 3) + b'\x03' + b'SIEMENS ' + b'1234'))
    f3.send(1, v103(0x08, 1, hd(6, 1, 8) + comp('CP56', 2)))
    f3.send(1, v103(0x08, 1, hd(8, 1, 10) + b'\x07'))
    f3.send(1, v103(0x08, 1, hd(9, 2, 2) + struct.pack('<HH', 100, 200)))
    f3.send(1, v103(0x08, 1, hd(205, 1, 1) + struct.pack('<IHBB', 777, 100, 5, 6)))
    f3.send(1, v103(0x08, 1, hd(77, 1, 1) + b'\x00'))
    f3.send(0, v103(0x73, 1, hd(6, 1, 8) + comp('CP56', 5)))
    f3.send(0, v103(0x73, 1, hd(7, 1, 9) + b'\x00'))
    f3.send(0, v103(0x73, 1, hd(20, 1, 20) + b'\x02\x07'))
    f3.send(0, v103(0x73, 1, hd(45, 1, 20) + b'\x01'))
    f3.send(0, v103(0x73, 1, hd(46, 1, 20) + b'\x02'))
    f3.send(0, v103(0x73, 1, hd(99, 1, 20) + b'\x02'))
    f3.send(0, b'\xe5' + bytes([0x10, 0x49, 1, 0x4a, 0x16]))
    n103 = len(f103)

    allf = f104 + f101 + f103
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'iec104-coverage.pcap'), allf)

    # ------------------------------------------------------- malformed capture
    mal = []
    m = Flow(49300, 2404, mal); m.handshake()
    m.send(0, bytes([0x68, 3, 7, 0, 0]) + apci_u(0x43))            # APDU shorter than 4 octets (then a TESTFR)
    m.send(0, bytes([0x68, 4, 0, 0, 0, 0]))                        # I frame without ASDU
    m.send(0, apci_i(0, 0, asdu(1)[:4]))                            # ASDU too short for the header
    m.send(0, apci_i(1, 0, asdu(1)[:7]))                            # ASDU without information object
    m.send(0, apci_i(2, 0, asdu(1, n=3)[:-2]))                      # objects cut short
    m.send(0, apci_i(3, 0, asdu(1, n=5, sq=1)[:-1]))                # SQ=1, cut short
    m.send(0, apci_i(4, 0, asdu(1)[:9]))                            # IOA cut
    m.send(0, apci_i(5, 0, asdu(1) + b'\x00\x01'))                  # trailing octets (invalid length)
    m.send(0, apci_i(6, 0, asdu(36, n=2)[:-5]))
    m.send(0, apci_i(7, 0, struct.pack('<BBBBH', 125, 1, 5, 0, 7) + b'\x04\x05\x00'))                         # F_SG_NA_1 with the generic object only
    m.send(0, apci_i(8, 0, struct.pack('<BBBBH', 125, 1, 5, 0, 7) + b'\x04\x05\x00\x34\x12\x02\x40' + b'\x5a' * 4))   # segment longer than data
    m.send(0, apci_i(9, 0, struct.pack('<BBBBH', 84, 1, 6, 0, 1) + b'\x01'))           # S_KR_NA_1 cut
    m.send(0, apci_i(10, 0, sasdu(81, seg(1, 1, 1, struct.pack('<IHBBH', 1, 1, 1, 1, 200) + PH * 4))))   # CLN beyond the data
    m.send(0, apci_i(11, 0, sasdu(82, seg(1, 1, 1, struct.pack('<IHH', 1, 1, 100) + PH * 4))))
    m.send(0, apci_i(12, 0, sasdu(83, seg(1, 1, 1, asdu(45, cot=6) [:6]))))
    m.send(0, apci_i(13, 0, sasdu(83, seg(1, 1, 1, bytes([83, 1, 6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))))) # nested S_AR_NA_1
    m.send(0, apci_i(14, 0, sasdu(85, seg(1, 1, 1, struct.pack('<IHBBBH', 4, 1, 1, 1, 4, 30) + PH * 5))))
    m.send(0, apci_i(15, 0, sasdu(86, seg(1, 1, 1, struct.pack('<IHH', 5, 1, 200) + PH * 3))))
    m.send(0, apci_i(16, 0, sasdu(87, seg(1, 1, 1, struct.pack('<IHHB', 6, 1, 2, 4) + cp56(3) + struct.pack('<H', 500) + b'e'))))
    m.send(0, apci_i(17, 0, sasdu(81, seg(1, 1, 1, b''))))
    m.send(0, apci_i(18, 0, sasdu(81, seg(3, 0, 0, b'')) ))        # empty non-final segment
    m.send(0, apci_i(19, 0, sasdu(81, seg(3, 0, 1, b'')) ))
    m.send(0, apci_i(20, 0, b'\x01'))
    m.send(0, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))   # no start byte
    m.send(0, apci_i(21, 0, sasdu(82, seg(1, 1, 1, struct.pack('<IHH', 1, 1, 0) + b'xyz'))))   # trailing octets after an S_RP_NA_1
    m.send(0, apci_i(22, 0, sasdu(87, seg(1, 1, 1, struct.pack('<IHHB', 6, 1, 2, 4) + cp56(3) + struct.pack('<H', 2) + b'errors'))))
    m.send(0, bytes([0x68]))                                         # lone start byte
    m.send(0, bytes([0x68, 0xff]) + b'\x00' * 20)                    # length 255 (> 253)
    n_m104 = len(mal)
    m1 = Flow(50101, 2405, mal); m1.handshake()
    m1.send(0, bytes([0x68, 5, 6, 0x68, 0x73, 5, 0, 0x16]))        # length bytes differ
    m1.send(0, bytes([0x68, 5, 5, 0x69, 0x73, 5, 0, 0x16]))        # second start byte wrong
    m1.send(0, bytes([0x68, 4, 4, 0x68, 0x73, 5]) + b'\x00' * 4)   # data length smaller than ctrl+addr
    m1.send(0, bytes([0x68, 2, 2, 0x68, 0x73, 5, 0, 0x17]))        # wrong stop character
    m1.send(0, bytes([0x10, 0x49, 5, 0, 0x00]))                    # bad stop char fixed frame
    m1.send(0, bytes([0x68, 3]))                                    # needs more data
    m1.send(0, v101(0x73, 5, a101(1, 3, 20)[:6]))                    # ASDU cut short
    m1.send(0, v101(0x73, 5, a101(13, 3, 20, n=2)[:-3]))
    m3 = Flow(50103, 2406, mal); m3.handshake()
    m3.send(0, bytes([0x01, 0x02, 0x03]))                              # not an IEC 103 frame
    m3.send(0, bytes([0x68, 5, 5, 0x68, 0x73, 1, 6, 1, 8, 0, 0]))   # truncated
    m3.send(0, bytes([0x10, 0x49]))
    m3.send(0, v103(0x73, 1, hd(6, 1, 8) + b'\x01\x02'))
    m3.send(0, v103(0x08, 1, hd(1, 3, 1) + b'\x01\x02'))
    pcap(os.path.join(out, 'iec104-coverage-malformed.pcap'), mal)
    if verbose:
        for n, d in marks:
            print(n, d)
        print('104:', n104, 'frames; 101:', n101, '(from', n104 + 1, '); 103:', n103, '(from', n104 + n101 + 1, ')')
        print('total', len(allf), 'malformed', len(mal))

if __name__ == '__main__':
    build(sys.argv[1], '-v' in sys.argv)

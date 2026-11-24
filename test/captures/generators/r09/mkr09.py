#!/usr/bin/env python3
# Generates test/captures/r09_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the R09.x (VDV 04.05 public transport priority telegrams) coverage captures.
R09 is carried in the PtActivation of the CAM public transport container
(cam.ptat = 1), so each telegram is wrapped in a CAM v2 PDU sent over
GeoNetworking/BTP-B to port 2001.
Usage: mkr09.py <outdir> [-v]"""
import struct
import sys
import os

class BitWriter:
    def __init__(self):
        self.b = []
    def put(self, v, n):
        for i in range(n - 1, -1, -1):
            self.b.append((v >> i) & 1)
        return self
    def bits(self, t):
        self.b.extend(int(c) for c in t)
        return self
    def signed(self, v, lo, n):
        return self.put(v - lo, n)
    def raw(self, data):
        for x in data:
            self.put(x, 8)
        return self
    def bytes(self):
        b = self.b + [0] * (-len(self.b) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))

def pcapng_write(path, frames):
    def blk(t, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535))
    for i, fr in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

ETH_DST = bytes.fromhex('ffffffffffff')
def gn_frame(btp_dst, payload, n=0):
    """GeoNetworking SHB with BTP-B"""
    src = bytes.fromhex('0200000000') + bytes([n & 255])
    eth = ETH_DST + src + struct.pack('>H', 0x8947)
    addr = bytes([0x14, 0xf0]) + bytes.fromhex('0200000000') + bytes([n & 255])
    lpv = addr + struct.pack('>IiiHH', 1000 + n, 488000000, 110000000, (1 << 15) | 1500, 900)
    pl = struct.pack('>HH', btp_dst, 0) + payload
    bh = bytes([(0 << 4) | 1, 0, 0x50, 1])
    ch = bytes([2 << 4, 0x50, 0x02, 0x80]) + struct.pack('>H', len(pl)) + bytes([1, 0])
    return eth + bh + ch + lpv + struct.pack('>I', 0) + pl

def cam_pt(ptype, data, embark=0, with_act=True, sid=0x01020304, station=9):
    """CAM v2 with a basic vehicle high frequency container and a
    PublicTransportContainer (EmbarkationStatus, optional PtActivation)"""
    w = BitWriter()
    w.put(2, 8).put(2, 8).put(sid, 32)                           # ItsPduHeader: version 2, CAM
    w.put(0x3039, 16)                                            # generationDeltaTime
    w.bits('0')                                                  # CamParameters ext marker
    w.bits('01')                                                 # no LF, special vehicle container present
    w.bits('0').put(station, 8)                                  # BasicContainer: ext, stationType
    w.signed(488000000, -900000000, 31).signed(110000000, -1800000000, 32)
    w.put(100, 12).put(50, 12).put(900, 12)                      # PositionConfidenceEllipse
    w.signed(54000, -100000, 20).put(3, 4)                       # altitude
    w.bits('0' '0')                                              # HF container: ext, basicVehicle
    w.bits('0' * 7)                                              # no optionals
    w.put(1800, 12).signed(4, 1, 7)                              # heading
    w.put(1400, 14).signed(2, 1, 7)                              # speed
    w.put(0, 2)                                                  # driveDirection forward
    w.signed(46, 1, 10).put(0, 3)                                # vehicleLength
    w.signed(21, 1, 6)                                           # vehicleWidth
    w.signed(-5, -160, 9).put(10, 7)                             # longitudinalAcceleration
    w.signed(30, -1023, 11).put(2, 3)                            # curvature
    w.bits('0').put(0, 2)                                        # curvatureCalculationMode
    w.signed(-100, -32766, 16).put(1, 4)                         # yawRate
    w.bits('0' '000')                                            # SpecialVehicleContainer: ext, publicTransportContainer
    w.bits('1' if with_act else '0')                             # PublicTransportContainer: ptActivation present
    w.bits(str(embark))                                          # embarkationStatus
    if with_act:
        w.put(ptype, 8)                                          # ptActivationType
        w.put(len(data) - 1, 5).raw(data)                        # ptActivationData SIZE(1..20)
    return w.bytes()

def bcd(digits):
    d = digits + ('' if len(digits) % 2 == 0 else '0')
    return bytes(int(d[i:i + 2], 16) for i in range(0, len(d), 2))

def telegram(tl, zv=0, zw=0, mp=0x12, pr=1, ha=0, ln='123', kn='42', zn='12345', zl=3, fn='123', un='7'):
    """Offsets as read by packet-r09.c: ib1 ib2 | MP (1 or 2 octets) | PR/HA octet 4 |
    LN octets 4-5 (BCD, first nibble skipped) | KN octet 6 | ZN octets 7-8 (odd digit count) |
    ZL octet 8 (tl == 6) | FN octets 8-9 (first nibble skipped) and UN octet 10 (tl == 8)"""
    b = bytearray(11)
    b[0] = 0x91
    b[1] = (zv << 7) | (zw << 4) | tl
    if tl == 0:
        b[2] = mp & 255
        return bytes(b[:3])
    b[2:4] = struct.pack('>H', mp)
    if tl >= 2:
        b[4] = (pr << 6) | (ha << 4)
    if tl >= 3:
        b[4] |= int(ln[0], 16)           # LN skips the first nibble (the PR/HA octet's high nibble); digits 1.. follow
        b[5] = int(ln[1:3], 16) if len(ln) >= 3 else 0
    if tl >= 4:
        b[6] = int(kn, 16)
    if tl >= 6:
        b[7:9] = bytes.fromhex(zn[:4])
        b[8] = (b[8] & 0xf8) | (zl & 7) if tl == 6 else b[8]
    if tl == 8:
        b[8] = int(fn[0], 16)
        b[9] = int(fn[1:3], 16)
        b[10] = int(un + '0', 16) if len(un) == 1 else int(un, 16)
    n = {0: 3, 1: 4, 2: 5, 3: 6, 4: 7, 5: 7, 6: 9, 7: 9, 8: 11}[tl]
    return bytes(b[:n])

def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    verbose = '-v' in sys.argv
    m = []; bad = []
    k = [0]
    def F(tgt, ptype, data, **kw):
        k[0] += 1
        tgt.append(gn_frame(2001, cam_pt(ptype, data, **kw), n=k[0]))
    # 1-9: every length (TL 0-8), with the values that move the fields
    F(m, 1, telegram(0, zv=0, zw=0, mp=0x01))                             # 1
    F(m, 1, telegram(1, zv=1, zw=3, mp=0x0102))                           # 2
    F(m, 1, telegram(2, zv=0, zw=7, mp=0x0fff, pr=0, ha=0))               # 3 PR/HA, no meaning
    F(m, 1, telegram(3, zv=1, zw=1, mp=0x1234, pr=1, ha=1, ln='0123'))    # 4 line number
    F(m, 1, telegram(4, zv=0, zw=2, mp=0xffff, pr=2, ha=2, ln='9456', kn='07'))   # 5 course number
    F(m, 1, telegram(5, zv=1, zw=4, mp=0x0001, pr=3, ha=3, ln='1999', kn='99'))   # 6 TL 5 (no extra field)
    F(m, 1, telegram(6, zv=0, zw=5, mp=0x4321, pr=3, ha=0, ln='0001', kn='10', zn='12345', zl=5))  # 7 destination number and train length
    F(m, 1, telegram(7, zv=1, zw=6, mp=0x00ff, pr=0, ha=2, ln='0555', kn='20', zn='54321'))        # 8 TL 7
    F(m, 1, telegram(8, zv=0, zw=0, mp=0x7777, pr=1, ha=1, ln='0777', kn='33', zn='00001', fn='456', un='9'))  # 9 vehicle number, operator
    # 10-13: more values: train length range, maximal and minimal digits
    F(m, 1, telegram(6, zl=0, zn='00000'))                                # 10
    F(m, 1, telegram(6, zl=7, zn='99999'))                                # 11
    F(m, 1, telegram(8, ln='0000', kn='00', zn='00000', fn='000', un='0'))  # 12
    F(m, 1, telegram(8, ln='0999', kn='99', zn='99999', fn='999', un='9'))  # 13
    # 14-16: trailing octets after the telegram, and the longest PtActivationData (20 octets)
    F(m, 1, telegram(3, ln='0123') + b'\xaa\xbb')                         # 14
    F(m, 1, telegram(8, ln='0123', kn='45', zn='67890', fn='789', un='1') + b'\x00' * 9)  # 15 20 octets
    F(m, 1, telegram(0, mp=0xff) + b'\x00' * 17)                          # 16 20 octets, TL 0
    # 17-21: not R09: infobyte 1 is not 0x91 (the dissector declines), other activation types, no activation
    F(m, 1, b'\x00\x01\x02\x03')                                          # 17 not R09
    F(m, 0, telegram(3))                                                  # 18 undefinedCodingType
    F(m, 2, telegram(3))                                                  # 19 vdv-50149CodingType
    F(m, 1, b'', with_act=False, embark=1)                                # 20 no activation
    # 21: embarkation status and ZW/ZV extremes
    F(m, 1, telegram(2, zv=1, zw=7, mp=0), embark=1)                      # 21
    n = len(m)
    # malformed: telegrams shorter than their TL needs
    F(bad, 1, b'\x91')
    F(bad, 1, b'\x91\x00')
    F(bad, 1, b'\x91\x01\x00\x01'[:3])
    F(bad, 1, telegram(2)[:4])
    F(bad, 1, telegram(3)[:5])
    F(bad, 1, telegram(4)[:6])
    F(bad, 1, telegram(6)[:8])
    F(bad, 1, telegram(8)[:10])
    # digits that are not BCD digits
    F(bad, 1, bytes([0x91, 0x08, 0, 1, 0x0f, 0xab, 0xcd, 0xef, 0xfa, 0xbc, 0xde]))
    pcapng_write(os.path.join(out, 'r09-coverage.pcapng'), m)
    pcapng_write(os.path.join(out, 'r09-coverage-malformed.pcapng'), bad)
    if verbose:
        print('main frames', n, 'malformed frames', len(bad))

main()

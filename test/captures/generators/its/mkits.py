#!/usr/bin/env python3
# Generates test/captures/its_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ITS coverage captures for packet-its.c (asn1/its).
Usage: mkits.py <outdir>

Writes its-coverage.pcapng (main capture) and its-coverage-malformed.pcapng.
Everything is synthetic.  Interface 0 is Ethernet (GeoNetworking, ethertype
0x8947, BTP-A/BTP-B to the well-known ITS ports), interface 1 is Exported
PDU naming "its".  The PDUs are

 * hand-encoded UPER (the BitWriter below): the two reproducers of the
   fixed DSRC import bug (IVIM LaneIds, CPMv1 OffsetPoint) and a few more
   CPMv1 / IVIM structures;
 * its_selected.hex: random UPER bodies after a valid ITS header that
   selectits.py found to decode without malformed or expert items and that
   each add decoded fields (broad sample of every PDU type);

The malformed capture holds random PDUs, truncations and PDUs without a
sub-dissector (they throw, a dissector bug) (not added to the
tree).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct
from common import pcapng

HERE = os.path.dirname(os.path.abspath(__file__))


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
    def length(self, n):
        """unconstrained length determinant (n < 16384)"""
        return self.put(n, 8) if n < 128 else self.put(0x8000 | n, 16)
    def bytes(self):
        b = self.b + [0] * (-len(self.b) % 8)
        return bytes(int(''.join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def header(w, ver, msg, sid=0x01020304):
    return w.put(ver, 8).put(msg, 8).put(sid, 32)


# ---- hand-encoded PDUs
def offset_point(w, x, y, z=None):
    """OffsetPoint: nodeOffsetPointxy node-XY1 and optional node-Z1 (all UPER)"""
    w.bits('1' if z is not None else '0')
    w.put(0, 3).signed(x, -512, 10).signed(y, -512, 10)        # NodeOffsetPointXY node-XY1
    if z is not None:
        w.put(0, 3).signed(z, -512, 10)                          # NodeOffsetPointZ node-Z1


def cpmv1(areas, nobj=0, sid=0x01020304, station=15):
    """CPMv1 with a FreeSpaceAddendumContainer: areas = callables writing a FreeSpaceArea"""
    w = BitWriter()
    header(w, 1, 14, sid)
    w.put(0x1234, 16)                                            # generationDeltaTime
    w.bits('0' '0001')                                           # CpmParameters: ext, only freeSpaceAddendum
    w.bits('0' '0')                                              # CpmManagementContainer: ext, no segment info
    w.put(station, 8)                                            # stationType
    w.signed(488000000, -900000000, 31).signed(110000000, -1800000000, 32)   # lat, lon
    w.put(100, 12).put(50, 12).put(900, 12)                      # PosConfidenceEllipse
    w.signed(54000, -100000, 20).put(3, 4)                       # altitude, confidence
    w.bits('0').put(len(areas) - 1, 7)                           # FreeSpaceAddendumContainer
    for a in areas:
        w.bits('0' '00')                                         # FreeSpaceAddendum: ext, no sensorIDList, shadowingApplies default
        w.put(95, 7)                                             # freeSpaceConfidence
        a(w)
    w.put(nobj, 8)                                               # numberOfPerceivedObjects
    return w.bytes()


def area_circular(x, y, z, radius=50):
    def f(w):
        w.bits('0' '01')                                         # FreeSpaceArea: ext 0, freeSpaceCircular
        w.bits('1')                                              # nodeCenterPoint present
        offset_point(w, x, y, z)
        w.put(radius, 14)
    return f


def area_polygon(points):
    def f(w):
        w.bits('0' '00')                                         # freeSpacePolygon
        w.bits('0').put(len(points) - 3, 4)                      # PolyPointList SIZE(3..16, ...)
        for x, y, z in points:
            offset_point(w, x, y, z)
    return f


def area_ellipse(x, y, z):
    def f(w):
        w.bits('0' '10')                                         # freeSpaceEllipse
        w.bits('1' '0')                                          # nodeCenterPoint present, semiHeight absent
        offset_point(w, x, y, z)
        w.put(30, 14).put(60, 14).put(900, 12)                   # minor, major, orientation
    return f


def ivim_laneids(lanes):
    c = BitWriter()
    c.bits('0')                                                  # MapReference: roadsegment
    c.bits('0').put(7, 16)                                       # RoadSegmentReferenceID: no region, id
    c.bits('0' '0000')                                           # MlcParts: ext 0, 1 item
    c.bits('1')                                                  # MlcPart: laneIds present
    c.bits('0').put(0, 5)                                        # Zid
    c.bits('0').put(len(lanes) - 1, 4)                           # LaneIds
    for l in lanes:
        c.put(l, 8)
    cont = c.bytes()
    w = BitWriter()
    header(w, 2, 6)
    w.bits('1')                                                  # IviStructure: optional present
    w.bits('0' '0000').put(0, 10).put(1, 14).bits('0').put(0, 15).put(0, 3)
    w.bits('0' '000')                                            # IviContainers: 1 item
    w.bits('1' '0' '000001')                                     # IviContainer: ext alt index 1 -> mlc
    w.put(len(cont), 8)
    w.raw(cont)
    return w.bytes()



CAM_NORMAL = dict(lat=488000000, lon=110000000, alt=54000, hdg=1800, hdgc=4, spd=1400, spdc=2,
                  vlen=46, vw=21, acc=-5, accc=10, curv=30, yaw=-100)
CAM_UNAVAILABLE = dict(lat=900000001, lon=1800000001, alt=800001, hdg=3601, hdgc=127, spd=16383, spdc=127,
                       vlen=1023, vw=62, acc=161, accc=102, curv=1023, yaw=32767)
CAM_OUTOFRANGE = dict(lat=-900000000, lon=-1800000000, alt=-100000, hdg=3600, hdgc=126, spd=16382, spdc=126,
                      vlen=1022, vw=61, acc=-160, accc=101, curv=-1023, yaw=-32766)
CAM_STILL = dict(CAM_NORMAL, spd=0, spdc=1, curv=0, yaw=0, acc=0, hdg=0, hdgc=1)


def cam_v2(sid=0x01020304, ext=None, station=5, **kw):
    """CAM v2 (basic vehicle HF container, no LF/special) with optional
    extensionContainers: ext = list of (containerId, content bytes);
    kw overrides the values of CAM_NORMAL"""
    v = dict(CAM_NORMAL, **kw)
    w = BitWriter()
    header(w, 2, 2, sid)
    w.put(0x3039, 16)                                            # generationDeltaTime
    w.bits('1' if ext else '0')                                  # CamParameters ext marker
    w.bits('00')                                                 # no LF, no special vehicle
    w.bits('0').put(station, 8)                                  # BasicContainer: ext, stationType
    w.signed(v['lat'], -900000000, 31).signed(v['lon'], -1800000000, 32)
    w.put(100, 12).put(50, 12).put(900, 12)                      # PositionConfidenceEllipse
    w.signed(v['alt'], -100000, 20).put(3, 4)                    # altitude
    w.bits('0' '0')                                              # HF container: ext, basicVehicle
    w.bits('0' * 7)                                              # no optionals
    w.put(v['hdg'], 12).signed(v['hdgc'], 1, 7)                  # heading
    w.put(v['spd'], 14).signed(v['spdc'], 1, 7)                  # speed
    w.put(0, 2)                                                  # driveDirection forward
    w.signed(v['vlen'], 1, 10).put(0, 3)                         # vehicleLength
    w.signed(v['vw'], 1, 6)                                      # vehicleWidth
    w.signed(v['acc'], -160, 9).put(v['accc'], 7)                # longitudinalAcceleration
    w.signed(v['curv'], -1023, 11).put(2, 3)                     # curvature
    w.bits('0').put(0, 2)                                        # curvatureCalculationMode
    w.signed(v['yaw'], -32766, 16).put(1, 4)                     # yawRate
    if ext:
        w.bits('0').put(0, 6).bits('1')                                  # one extension addition, present
        c = BitWriter()
        c.bits('0').put(len(ext) - 1, 3)                         # SIZE(1..8,...)
        for cid, data in ext:
            c.bits('0').put(cid - 1, 4)                          # containerId (1..16,...)
            c.length(len(data)).raw(data)
        cb = c.bytes()
        w.length(len(cb)).raw(cb)
    return w.bytes()


def addgrpc_requestor(fuel=4, battery=3):
    c = BitWriter()
    c.bits('0' '11').put(fuel, 4).bits('0').put(battery, 2)     # RequestorDescription-addGrpC
    return c.bytes()


def srem(entity=b'\x0a\x0b\x0c\x0d', regs=((3, None), (1, b'\x55\xaa')), msg_regs=((3, b'\x01'),)):
    """SREM (v2, msgId 9): requestor with RegionalExtension (addGrpC decoded
    by dissect_regextval_pdu, other region ids go to the data dissector) and
    message level regional extensions"""
    w = BitWriter()
    header(w, 2, 9)
    w.bits('0')                         # SignalRequestMessage ext
    w.bits('0001' if msg_regs else '0000')                       # timeStamp, sequenceNumber, requests, regional
    w.put(12345, 16)                                             # second
    w.bits('0')                                                  # RequestorDescription ext
    w.bits('0000000' + ('1' if regs else '0'))                   # optionals, regional last
    w.bits('0').raw(entity)                                      # id: entityID
    if regs:
        w.put(len(regs) - 1, 2)
        for rid, data in regs:
            w.put(rid, 8)
            data = addgrpc_requestor() if data is None else data
            w.length(len(data)).raw(data)
    if msg_regs:
        w.put(len(msg_regs) - 1, 2)
        for rid, data in msg_regs:
            w.put(rid, 8).length(len(data)).raw(data)
    return w.bytes()


def hand_frames():
    out = []
    out.append(('srem_regional', srem()))
    out.append(('srem_regional1', srem(regs=((3, None),), msg_regs=())))
    out.append(('ivim_laneids', ivim_laneids([3])))
    out.append(('ivim_laneids3', ivim_laneids([3, 4, 5])))
    out.append(('cpmv1_circular', cpmv1([area_circular(10, -20, 5)])))
    out.append(('cpmv1_circular_noz', cpmv1([area_circular(-10, 20, None, 7)])))
    out.append(('cpmv1_ellipse', cpmv1([area_ellipse(5, 6, -3), area_circular(0, 0, 511, 9)])))
    out.append(('cpmv1_polygon', cpmv1([area_polygon([(1, 2, None), (3, -4, 7), (-5, 6, -8)])], nobj=0)))
    return out


# ---- containers
EPDU_TAGS = struct.pack('>HH', 12, 4) + b'its\0' + struct.pack('>HH', 0, 0)

ETH_DST = bytes.fromhex('ffffffffffff')
def gn_frame(btp_dst, payload, btp='b', n=0, info=0):
    src = bytes.fromhex('0200000000') + bytes([n & 255])
    eth = ETH_DST + src + struct.pack('>H', 0x8947)
    addr = bytes([0x14, 0xf0]) + bytes.fromhex('0200000000') + bytes([n & 255])
    lpv = addr + struct.pack('>IiiHH', 1000 + n, 488000000, 110000000, (1 << 15) | 1500, 900)
    btph = struct.pack('>HH', btp_dst, info if btp == 'b' else 3001)
    pl = btph + payload
    bh = bytes([(0 << 4) | 1, 0, 0x50, 1])
    ch = bytes([(1 if btp == 'a' else 2) << 4, 0x50, 0x02, 0x80]) + struct.pack('>H', len(pl)) + bytes([1, 0])
    return eth + bh + ch + lpv + struct.pack('>I', 0) + pl


def load_ext():
    r = []
    for line in open(os.path.join(HERE, 'its_ext_selected.txt')):
        cid, h = line.split()
        r.append((int(cid), bytes.fromhex(h)))
    return r


def load_selected():
    p = os.path.join(HERE, 'its_selected.hex')
    r = []
    for line in open(p):
        v, m, h = line.split()
        r.append((int(v), int(m), bytes.fromhex('%02x%02x01020304' % (int(v), int(m))) + bytes.fromhex(h)))
    return r


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    sel = load_selected()
    main_frames = []
    def E(pdu): main_frames.append((1, EPDU_TAGS + pdu))
    for name, pdu in hand_frames():
        E(pdu)
    for v, m, pdu in sel:
        E(pdu)
    # CAM v2 with extension containers (WrappedExtensionContainer, ids 1..6
    # decode, the other ids are skipped)
    ext = load_ext()
    E(cam_v2())
    for kw in (CAM_UNAVAILABLE, CAM_OUTOFRANGE, CAM_STILL):
        E(cam_v2(**kw))
    for cid, data in ext:
        E(cam_v2(ext=[(cid, data)], station=5 + cid))
    first = {}
    for cid, data in ext:
        first.setdefault(cid, data)
    E(cam_v2(ext=sorted(first.items())))
    E(cam_v2(ext=[(7, b'\x01\x02'), (16, b'')]))
    # GeoNetworking / BTP to the well-known ports: first selected PDU of each kind
    ports = {(2, 1): 2002, (1, 1): 2002, (2, 2): 2001, (1, 2): 2001, (2, 6): 2006, (1, 6): 2006,
             (2, 14): 2009, (1, 14): 2009, (3, 16): 2018, (1, 8): 2011, (2, 9): 2007, (2, 10): 2008,
             (0, 11): 2010, (1, 4): 2004, (2, 4): 2004, (1, 5): 2003, (2, 5): 2003, (2, 13): 2013}
    done = set(); n = 0
    for v, m, pdu in sel:
        if (v, m) in ports and (v, m) not in done:
            done.add((v, m))
            main_frames.append((0, gn_frame(ports[(v, m)], pdu, 'b' if n % 2 == 0 else 'a', n)))
            n += 1
    for pdu, port in ((srem(), 2007), (ivim_laneids([3]), 2006), (cpmv1([area_circular(1, 2, 3)]), 2009),
                      (cam_v2(**CAM_UNAVAILABLE), 2001)):
        main_frames.append((0, gn_frame(port, pdu, 'b', n)))
        n += 1
    pcapng(os.path.join(outdir, 'its-coverage.pcapng'), [1, 252], main_frames)

    # malformed: random bodies, truncated hand frames
    r = random.Random(20260)
    bad = []
    pairs = [(2,1),(1,1),(2,2),(1,2),(1,4),(2,4),(1,5),(2,5),(1,6),(2,6),(0,7),(1,8),(2,9),(2,10),(0,11),
             (1,13),(2,13),(1,14),(2,14),(2,15),(3,16),(1,18),(1,19),(2,21)]
    for i in range(1500):
        v, m = pairs[i % len(pairs)]
        body = bytes(r.getrandbits(8) for _ in range(r.randint(0, 120)))
        if r.random() < 0.5:
            body = bytes(b & r.getrandbits(8) for b in body)
        bad.append((1, EPDU_TAGS + struct.pack('>BBI', v, m, r.getrandbits(32)) + body))
    for name, pdu in hand_frames():
        for cut in (7, len(pdu) // 2, len(pdu) - 1):
            bad.append((1, EPDU_TAGS + pdu[:cut]))
    bad.append((1, EPDU_TAGS + b'\x02'))
    # No sub-dissector for the version/message id: the expert info is added
    # with length -1, which throws (packet-its.c:8535, see README)
    for v, m in [(2, 3), (2, 12), (2, 17), (2, 20), (9, 99)]:
        bad.append((1, EPDU_TAGS + struct.pack('>BBI', v, m, 0x0a0b0c0d) + b'\x00\x01\x02\x03'))
    pcapng(os.path.join(outdir, 'its-coverage-malformed.pcapng'), [1, 252], bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/btbredr_rf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth BR/EDR baseband
pseudoheader dissector (packet-btbredr_rf.c, protocols "btbredr_rf" and
"btbredr_fhs") on LINKTYPE_BLUETOOTH_BREDR_BB (255).

All packets are built from scratch with struct; no captured traffic is
used.  The packet header HEC and the payload CRC are computed here, so the
dissector's HEC and CRC checks pass unless a frame is meant to fail them.

Devices (BD_ADDR = NAP:UAP:LAP):
  P  00:1b:dc:0a:a1:b2  peripheral, answers an inquiry with an FHS
  C  00:1b:7d:0c:c1:d2  central, pages P and assigns LT_ADDR 1
  D  00:1b:e3:0d:d1:e2  announced by an FHS on an unknown access code,
                        LT_ADDR 3 (connection without a peripheral)

Usage: mkbtbredr_rf.py <output directory>

Writes:
  btbredr_rf-coverage.pcap            main capture (see README.md)
  btbredr_rf-coverage-malformed.pcap  truncated packets, the known
                                      two-pass difference, eSCO removal
  btbredr_rf-coverage-exppdu.pcap     Exported PDU naming "btbredr_fhs"
                                      without dissector data
"""

import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

LINKTYPE_BREDR_BB = 255
LINKTYPE_EXPORTED_PDU = 252

GIAC = 0x9e8b33
DIAC = 0x9e8b00


class Dev:
    def __init__(self, nap, uap, lap):
        self.nap, self.uap, self.lap = nap, uap, lap


P = Dev(0x0a1b, 0xdc, 0x0aa1b2)
C = Dev(0x0a1b, 0x7d, 0x0cc1d2)
D = Dev(0x0a1b, 0xe3, 0x0dd1e2)
X_LAP, X_UAP = 0x0ee1f2, 0x5c        # unknown access code that sends D's FHS
U_LAP = 0x334455                     # never announced, no UAP known
REPRO_LAP, REPRO_UAP = 0x123456, 0x5a

# Flags
F_DEWHITENED = 0x0001
F_SP = 0x0002
F_NP = 0x0004
F_DECRYPTED = 0x0008
F_LAP_VALID = 0x0010
F_DATA = 0x0020
F_ALIAS = 0x0040
F_UAP_VALID = 0x0080
F_HEC_CHECKED = 0x0100
F_HEC_PASS = 0x0200
F_CRC_CHECKED = 0x0400
F_CRC_PASS = 0x0800
F_MIC_CHECKED = 0x1000
F_MIC_PASS = 0x2000

OK = F_DEWHITENED | F_DECRYPTED | F_DATA | F_CRC_CHECKED | F_CRC_PASS | \
    F_HEC_CHECKED | F_HEC_PASS | F_LAP_VALID | F_UAP_VALID | F_SP | F_NP

# Payload/transport
ANY, SCO, ESCO, ACL, CPB = 0x00, 0x10, 0x20, 0x30, 0x40
BR, EDR2, EDR3 = 0, 1, 2

# LLIDs
LL_CONT, LL_START, LL_LMP = 1, 2, 3


def rev8(v):
    v = ((v >> 1) & 0x55) | ((v << 1) & 0xaa)
    v = ((v >> 2) & 0x33) | ((v << 2) & 0xcc)
    v = ((v >> 4) & 0x0f) | ((v << 4) & 0xf0)
    return v


def check_hec(uap, h):
    h &= 0x3ffff
    h ^= rev8(uap) & 0xff
    for _ in range(10):
        if h & 1:
            h ^= (0xe5 << 1)
        h >>= 1
    return h == 0


def header(uap, ltaddr, ptype, flow=1, arqn=0, seqn=0):
    """Packet header in the Core spec layout (HEC in bits 10-17)."""
    d = ltaddr | (ptype << 3) | (flow << 7) | (arqn << 8) | (seqn << 9)
    for hec in range(256):
        h = d | (hec << 10)
        if check_hec(uap, h):
            return h
    raise Exception("no hec")


def broken_hec(uap, data):
    lfsr = uap
    for i in range(9, -1, -1):
        if lfsr & 0x80:
            lfsr ^= 0x65
        lfsr = ((lfsr << 1) | (((lfsr >> 7) ^ (data >> i)) & 1)) & 0xff
    return rev8(lfsr)


def broken_header(uap, ltaddr, ptype, flow=1, arqn=0, seqn=0):
    """Packet header in the "broken" layout (HEC in bits 0-7) that some
    capture devices produce."""
    h = (ltaddr << 15) | (ptype << 11) | (flow << 10) | (arqn << 9) | (seqn << 8)
    h |= broken_hec(uap, (h >> 8) & 0x3f)
    assert not check_hec(uap, h)
    return h


def crc16(uap, data):
    crc = rev8(uap) << 8
    for b in data:
        crc ^= b
        for _ in range(8):
            x = crc & 1
            crc >>= 1
            if x:
                crc ^= 0x8408
    return crc


def with_crc(uap, data):
    return data + struct.pack('<H', crc16(uap, data))


def bb(lap, hdr, flags, payload=b'', pt=ACL | BR, uap=0, chan=37, sp=-45, np_=-90,
       aa=0, chb=0, cpb=0, ref_lap=None):
    """LINKTYPE_BLUETOOTH_BREDR_BB pseudoheader (22 octets) + payload."""
    if ref_lap is None:
        ref_lap = lap
    return struct.pack('<BbbBBBh', chan, sp, np_, aa, pt, chb, cpb) + \
        struct.pack('<I', lap) + struct.pack('<I', ref_lap)[:3] + bytes([uap]) + \
        struct.pack('<I', hdr) + struct.pack('<H', flags) + payload


def hdr1(llid, body, flow=1):
    return bytes([llid | (flow << 2) | (len(body) << 3)]) + body


def hdr2(llid, body, flow=1):
    return struct.pack('<H', llid | (flow << 2) | (len(body) << 3)) + body


def fhs(dev, ltaddr=0, clk=0x123456, cod=0x5a020c, eir=1, sr=1, sp=2, psm=0):
    w = 0x2b3c4d5e1 | (dev.lap << 34) | (eir << 58) | (sr << 60) | (sp << 62)
    return struct.pack('<QBH', w, dev.uap, dev.nap) + struct.pack('<I', cod)[:3] + \
        struct.pack('<I', ltaddr | (clk << 3) | (psm << 29))


def l2cap(cid, body):
    return struct.pack('<HH', len(body), cid) + body


# --- Captures ---------------------------------------------------------------

def write_pcap(fn, pkts, linktype=LINKTYPE_BREDR_BB):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000, len(p), len(p)))
            f.write(p)


def write_pcapng(fn, pkts, linktype):
    def block(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    with open(fn, 'wb') as f:
        f.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
        f.write(block(1, struct.pack('<HHI', linktype, 0, 65535)))
        for i, p in enumerate(pkts):
            ts = (1700000000 + i) * 1000000
            f.write(block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p))


def exported_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


main = []
seq = {'seqn': 0}


def add(p):
    main.append(p)
    return len(main)


def cdata(ptype, payload, pt=ACL | BR, ltaddr=1, flags=OK, seqn=None, arqn=1, dev=C,
          crc=True, **kw):
    """A packet on the central's channel access code."""
    if seqn is None:
        seqn = seq['seqn']
        seq['seqn'] ^= 1
    body = with_crc(dev.uap, payload) if crc else payload
    return bb(dev.lap, header(dev.uap, ltaddr, ptype, arqn=arqn, seqn=seqn), flags, body,
              pt=pt, uap=dev.uap, **kw)


def lmp(op, params=b'', tid=0):
    if op >= 0x100:
        return bytes([(0x7c + (op >> 8) - 1) << 1 | tid, op & 0xff]) + params
    return bytes([op << 1 | tid]) + params


# 1-2: ID packets (inquiry access codes): no packet header
add(bb(GIAC, 0, F_SP | F_LAP_VALID, pt=0xff, uap=0, chan=0))
add(bb(DIAC, 0x0001, F_DEWHITENED | F_NP | F_ALIAS, pt=ANY | BR, chan=1))
# 3: inquiry response FHS from P (GIAC, HEC with the DCI 0x00)
add(bb(GIAC, header(0, 0, 2), OK & ~F_UAP_VALID, with_crc(0, fhs(P)), pt=ANY | BR, chan=2))
# 4: inquiry response FHS from P again, broken header layout, ACL BR
add(bb(GIAC, broken_header(0, 0, 2), OK & ~F_UAP_VALID, with_crc(0, fhs(P, clk=0x123460)),
       pt=ACL | BR, chan=3))
# 5: page response FHS on P's access code: C assigns LT_ADDR 1 -> connection
add(bb(P.lap, header(P.uap, 0, 2), OK & ~F_UAP_VALID, with_crc(P.uap, fhs(C, ltaddr=1, sr=0, sp=0, eir=0)),
       pt=ACL | BR, chan=4))
# 6-7: POLL and NULL on the new connection (no payload)
add(cdata(1, b'', crc=False, flags=OK & ~F_DATA))
add(cdata(0, b'', crc=False, flags=OK & ~F_DATA, ltaddr=1))
# 8-14: LMP in DM1 (LLID 3)
add(cdata(3, hdr1(LL_LMP, lmp(0x25, struct.pack('<BHH', 11, 0x000f, 0x1234)))))      # version_req
add(cdata(3, hdr1(LL_LMP, lmp(0x26, struct.pack('<BHH', 11, 0x0002, 0x4321), 1))))    # version_res
add(cdata(3, hdr1(LL_LMP, lmp(0x27, bytes.fromhex('bffecffedbff7b87')))))            # features_req
add(cdata(3, hdr1(LL_LMP, lmp(0x01, b'\x00'))))                                      # name_req
add(cdata(3, hdr1(LL_LMP, lmp(0x02, b'\x00\x05abcde', 1))))                          # name_res
add(cdata(3, hdr1(LL_LMP, lmp(0x33))))                                               # host_connection_req
add(cdata(3, hdr1(LL_LMP, lmp(0x03, b'\x33', 1))))                                   # accepted
# 15: LMP_eSCO_link_req: handle 5, LT_ADDR 2, EV3 both ways, 30 octets
add(cdata(3, hdr1(LL_LMP, lmp(0x40c, struct.pack('<BBBBBBBBHHBB', 5, 2, 0, 0, 6, 2, 7, 7, 30, 30, 3, 0)))))
# 16: LMP_setup_complete in a DM1 of the ACL EDR table
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), pt=ACL | EDR2))
# 17-18: eSCO EV3 on LT_ADDR 2 both ways (matches the eSCO link)
voice = bytes(range(0x40, 0x40 + 30))
add(cdata(7, voice, pt=ESCO | BR, ltaddr=2))
add(cdata(7, voice[::-1], pt=ESCO | BR, ltaddr=2))
# 19: complete L2CAP signalling PDU (Echo Request) in a DM1
sig_echo = l2cap(0x0001, bytes([0x08, 0x01]) + struct.pack('<H', 4) + b'ping')
add(cdata(3, hdr1(LL_START, sig_echo)))
# 20: complete L2CAP PDU in a DH1 on a dynamic channel
add(cdata(4, hdr1(LL_START, l2cap(0x0040, b'hello, world'))))
# 21-22: L2CAP PDU (60 octets) in a DH3 start + DM1 continuation -> reassembled
big = l2cap(0x0041, bytes((i * 7) & 0xff for i in range(56)))
add(cdata(11, hdr2(LL_START, big[:45])))
add(cdata(3, hdr1(LL_CONT, big[45:])))
# 23-25: L2CAP PDU (400 octets) in a DH5 start, a 2-DH3 and a 3-DH1 continuation
big2 = l2cap(0x0042, bytes((i * 13 + 5) & 0xff for i in range(396)))
add(cdata(15, hdr2(LL_START, big2[:300])))
add(cdata(10, hdr2(LL_CONT, big2[300:380]), pt=ACL | EDR2))
add(cdata(8, hdr2(LL_CONT, big2[380:]), pt=ACL | EDR3))
# 26-28: start (DM3), retransmission of the start (same SEQN), continuation
big3 = l2cap(0x0043, bytes((i * 3) & 0xff for i in range(40)))
s = seq['seqn']
add(cdata(10, hdr2(LL_START, big3[:30]), seqn=s))
add(cdata(10, hdr2(LL_START, big3[:30]), seqn=s))
seq['seqn'] = s ^ 1
add(cdata(3, hdr1(LL_CONT, big3[30:])))
# 29: continuation with no fragment start pending -> Missing Fragment Start
add(cdata(3, hdr1(LL_CONT, b'orphan-fragment')))
# 30: Empty PDU (LLID 1, length 0)
add(cdata(3, hdr1(LL_CONT, b'')))
# 31: LLID 0 (undefined) -> asynchronous data
add(cdata(4, hdr1(0, b'\x01\x02\x03\x04')))
# 32: AUX1 (no CRC)
add(cdata(9, hdr1(LL_START, l2cap(0x0045, b'aux1-data')), crc=False))
# 33-35: DM5, 2-DH1, 3-DH3 complete L2CAP PDUs
add(cdata(14, hdr2(LL_START, l2cap(0x0046, b'dm5' * 20))))
add(cdata(4, hdr2(LL_START, l2cap(0x0047, b'2-dh1')), pt=ACL | EDR2))
add(cdata(11, hdr2(LL_START, l2cap(0x0048, b'3-dh3' * 10)), pt=ACL | EDR3))
# 36-37: 2-DH5, 3-DH5 complete
add(cdata(14, hdr2(LL_START, l2cap(0x0049, b'2-dh5' * 30)), pt=ACL | EDR2))
add(cdata(15, hdr2(LL_START, l2cap(0x004a, b'3-dh5' * 40)), pt=ACL | EDR3))
# 38: ACL EDR AUX1
add(cdata(9, hdr1(LL_START, l2cap(0x004b, b'edr-aux1')), pt=ACL | EDR2, crc=False))
# 39-42: SCO HV1, HV2, HV3 on LT_ADDR 1 (SCO on an ACL logical transport), DV
add(cdata(5, bytes(range(10)), pt=SCO | BR, crc=False))
add(cdata(6, bytes(range(20)), pt=SCO | BR, crc=False))
add(cdata(7, bytes(range(30)), pt=SCO | BR, crc=False))
add(cdata(8, bytes(range(10)) + with_crc(C.uap, hdr1(LL_LMP, lmp(0x31))), pt=SCO | BR, crc=False))
# 43-45: SCO table NULL, POLL, DM1 (LMP)
add(cdata(0, b'', pt=SCO | BR, crc=False, flags=OK & ~F_DATA))
add(cdata(1, b'', pt=SCO | BR, crc=False, flags=OK & ~F_DATA))
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), pt=SCO | BR))
# 46: SCO undefined type 4 -> only the remaining data
add(cdata(4, b'\xaa\xbb\xcc', pt=SCO | BR, crc=False))
# 47-49: eSCO BR NULL, EV4, EV5 on LT_ADDR 5 (no eSCO link known)
add(cdata(0, b'', pt=ESCO | BR, ltaddr=5, crc=False, flags=OK & ~F_DATA))
add(cdata(12, bytes(120), pt=ESCO | BR, ltaddr=5))
add(cdata(13, bytes(180), pt=ESCO | BR, ltaddr=5))
# 50: eSCO BR undefined type 2
add(cdata(2, b'\x01\x02', pt=ESCO | BR, ltaddr=5, crc=False))
# 51-55: eSCO EDR POLL, 2-EV3, 3-EV3, 2-EV5, 3-EV5
add(cdata(1, b'', pt=ESCO | EDR2, ltaddr=5, crc=False, flags=OK & ~F_DATA))
add(cdata(6, bytes([0x11]) * 60, pt=ESCO | EDR2, ltaddr=5))
add(cdata(7, bytes([0x22]) * 90, pt=ESCO | EDR3, ltaddr=5))
add(cdata(12, bytes([0x33]) * 360, pt=ESCO | EDR2, ltaddr=5))
add(cdata(13, bytes([0x44]) * 540, pt=ESCO | EDR3, ltaddr=5))
# 56: eSCO EDR undefined type 4
add(cdata(4, b'\x01', pt=ESCO | EDR2, ltaddr=5, crc=False))
# 57-58: ACL BR DM1/DH1 undefined type 5 and ACL EDR undefined type 6
add(cdata(5, b'\x05\x05', crc=False))
add(cdata(6, b'\x06\x06', pt=ACL | EDR3, crc=False))
# 59-65: CPB BR NULL, DM1, DH1, DM3, DH3, DM5, DH5 (LT_ADDR 0, broadcast)
add(cdata(0, b'', pt=CPB | BR, ltaddr=0, crc=False, flags=OK & ~F_DATA))
add(cdata(3, hdr1(LL_START, l2cap(0x0002, b'cpb-dm1')), pt=CPB | BR, ltaddr=0))
add(cdata(4, hdr1(LL_START, l2cap(0x0002, b'cpb-dh1')), pt=CPB | BR, ltaddr=0))
add(cdata(10, hdr2(LL_START, l2cap(0x0002, b'cpb-dm3')), pt=CPB | BR, ltaddr=0))
add(cdata(11, hdr2(LL_START, l2cap(0x0002, b'cpb-dh3')), pt=CPB | BR, ltaddr=0))
add(cdata(14, hdr2(LL_START, l2cap(0x0002, b'cpb-dm5')), pt=CPB | BR, ltaddr=0))
add(cdata(15, hdr2(LL_START, l2cap(0x0002, b'cpb-dh5')), pt=CPB | BR, ltaddr=0))
# 66: CPB BR reserved type 1
add(cdata(1, b'\x01', pt=CPB | BR, ltaddr=0, crc=False))
# 67-74: CPB EDR NULL, DM1, 2-DH1, 3-DH1, 2-DH3, 3-DH3, 2-DH5, 3-DH5
# (3 Mb/s packets use transport 0x42, before the fix they were not recognised)
add(cdata(0, b'', pt=CPB | EDR2, ltaddr=0, crc=False, flags=OK & ~F_DATA))
add(cdata(3, hdr1(LL_START, l2cap(0x0002, b'cpb-edr-dm1')), pt=CPB | EDR2, ltaddr=0))
add(cdata(4, hdr2(LL_START, l2cap(0x0002, b'cpb-2-dh1')), pt=CPB | EDR2, ltaddr=0))
add(cdata(8, hdr2(LL_START, l2cap(0x0002, b'cpb-3-dh1')), pt=CPB | EDR3, ltaddr=0))
add(cdata(10, hdr2(LL_START, l2cap(0x0002, b'cpb-2-dh3')), pt=CPB | EDR2, ltaddr=0))
add(cdata(11, hdr2(LL_START, l2cap(0x0002, b'cpb-3-dh3')), pt=CPB | EDR3, ltaddr=0))
add(cdata(14, hdr2(LL_START, l2cap(0x0002, b'cpb-2-dh5')), pt=CPB | EDR2, ltaddr=0))
add(cdata(15, hdr2(LL_START, l2cap(0x0002, b'cpb-3-dh5')), pt=CPB | EDR3, ltaddr=0))
# 75: CPB EDR 3 undefined type 9
add(cdata(9, b'\x09', pt=CPB | EDR3, ltaddr=0, crc=False))
# 76-79: "Any" transport NULL, POLL, DM1, undefined type 4
add(cdata(0, b'', pt=ANY | BR, crc=False, flags=OK & ~F_DATA))
add(cdata(1, b'', pt=ANY | EDR2, crc=False, flags=OK & ~F_DATA))
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), pt=ANY | BR))
add(cdata(4, b'\x04\x04', pt=ANY | BR, crc=False))
# 80: unknown transport (5) -> generic Type, payload not interpreted
add(cdata(3, b'\x55\x55\x55', pt=0x50, crc=False))
# 81-84: FHS packets in the SCO, ACL EDR, Any and ACL BR tables on C's
# access code, announcing P (already known) with LT_ADDR 0: no state change
add(cdata(2, fhs(P, clk=0x200000), pt=SCO | BR, ltaddr=0))
add(cdata(2, fhs(P, clk=0x200100), pt=ACL | EDR2, ltaddr=0))
add(cdata(2, fhs(P, clk=0x200200), pt=ANY | BR, ltaddr=0))
add(cdata(2, fhs(P, clk=0x200300), pt=ACL | BR, ltaddr=0))
# 85: FHS from an unknown access code (UAP from the pseudoheader) announcing
# D with LT_ADDR 3: device and connection without a peripheral address
add(bb(X_LAP, header(X_UAP, 0, 2), OK, with_crc(X_UAP, fhs(D, ltaddr=3)), uap=X_UAP))
# 86: DM1 LMP on D's connection
add(cdata(3, hdr1(LL_LMP, lmp(0x25, struct.pack('<BHH', 9, 0x0002, 0x0001))), dev=D, ltaddr=3))
# 87-93: broken header layout for every transport table (UAP from C's FHS)
for ptype, pt in ((7, SCO | BR), (7, ESCO | BR), (6, ESCO | EDR2), (3, ACL | BR),
                  (4, ACL | EDR3), (3, CPB | BR), (4, CPB | EDR2)):
    if pt in (SCO | BR,):
        body = bytes(30)
    elif pt & 0xf0 == ESCO:
        body = with_crc(C.uap, bytes(30 if pt == ESCO | BR else 60))
    elif ptype == 3:
        body = with_crc(C.uap, hdr1(LL_LMP, lmp(0x31)))
    else:
        body = with_crc(C.uap, hdr2(LL_START, l2cap(0x0002, b'broken')))
    add(bb(C.lap, broken_header(C.uap, 5, ptype), OK, body, pt=pt, uap=C.uap))
# 94-95: broken layout with the "Any" transport and an unknown transport
add(bb(C.lap, broken_header(C.uap, 5, 1), OK & ~F_DATA, b'', pt=ANY | BR, uap=C.uap))
add(bb(C.lap, broken_header(C.uap, 5, 1), OK & ~F_DATA, b'', pt=0x60, uap=C.uap))
# 96: not dewhitened: whitened header and data
add(bb(C.lap, 0x2a5a5, F_DATA | F_UAP_VALID, b'\x5a\xa5\x5a\xa5', uap=C.uap))
# 97: dewhitened but not decrypted: encrypted data
add(cdata(3, b'\x13\x57\x9b\xdf\x02\x46', flags=OK & ~F_DECRYPTED, crc=False))
# 98: CRC not checked: payload not interpreted, only data
add(cdata(3, with_crc(C.uap, hdr1(LL_LMP, lmp(0x31))), flags=OK & ~(F_CRC_CHECKED | F_CRC_PASS), crc=False))
# 99: incorrect CRC (UAP valid) -> warning
add(cdata(3, hdr1(LL_LMP, lmp(0x31)) + b'\xde\xad', crc=False))
# 100: incorrect eSCO CRC -> warning (eSCO link, LT_ADDR 2)
add(cdata(7, voice + b'\xbe\xef', pt=ESCO | BR, ltaddr=2, crc=False))
# 101: incorrect HEC for the known UAP -> warning
h = header(C.uap, 1, 3) ^ (1 << 12)
add(bb(C.lap, h, OK & ~F_UAP_VALID, with_crc(C.uap, hdr1(LL_LMP, lmp(0x31)))))
# 102: dewhitened, unknown access code and no UAP -> HEC not checked
add(bb(U_LAP, 0x1234, OK & ~F_UAP_VALID, b'\x01\x02\x03'))
# 103: data present flag clear but data follows -> Unexpected data
add(cdata(0, b'\x01\x02', flags=OK & ~F_DATA, crc=False))
# 104: reserved flag bits set, only signal power valid, channel aliasing
add(cdata(1, b'', crc=False, flags=(OK & ~(F_DATA | F_NP)) | 0xc000 | F_ALIAS))
# 105: only noise power valid, MIC checked and passed
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), flags=(OK & ~F_SP) | F_MIC_CHECKED | F_MIC_PASS))
# 106: no power valid, reference LAP not valid
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), flags=OK & ~(F_SP | F_NP | F_LAP_VALID), ref_lap=0))
# 107: EV3 on LT_ADDR 1 (ACL connection) -> Incorrect (e)SCO LT_ADDR
add(cdata(7, voice, pt=ESCO | BR, ltaddr=1))
# 108: HV1 on the eSCO LT_ADDR 2 -> Incorrect (e)SCO LT_ADDR and length
add(cdata(5, bytes(10), pt=SCO | BR, ltaddr=2, crc=False))
# 109: 2-EV3 on LT_ADDR 2 (60 octets, link set up for 30) -> Incorrect length
add(cdata(6, bytes(60), pt=ESCO | EDR2, ltaddr=2))
# 110: EV5 cut to 20 octets (no CRC check: UAP not valid)
add(cdata(13, bytes(20) + b'\0\0', pt=ESCO | BR, ltaddr=5, crc=False, flags=OK & ~F_UAP_VALID))
# 111: EV3 with only the CRC left (no isochronous data)
add(cdata(7, b'\0\0', pt=ESCO | BR, ltaddr=5, crc=False, flags=OK & ~F_UAP_VALID))
# 112: EV3 with the CRC not checked: data only
add(cdata(7, voice, pt=ESCO | BR, ltaddr=5, flags=OK & ~(F_CRC_CHECKED | F_CRC_PASS)))
# 113: DM1 with only the CRC (shorter than its payload header)
add(cdata(3, b'', flags=OK & ~F_UAP_VALID))
# 114: DH3 whose payload length exceeds the packet
add(cdata(11, struct.pack('<H', LL_START | (200 << 3)) + b'short'))
# 115: DH1 whose payload length exceeds the packet
add(cdata(4, bytes([LL_START | (20 << 3)]) + b'short'))
# 116: DM1 LMP on LT_ADDR 0 (no connection): source from the device
add(cdata(3, hdr1(LL_LMP, lmp(0x31)), ltaddr=0))
# 117: L2CAP start without a connection (LT_ADDR 6): fragment, no reassembly
add(cdata(3, hdr1(LL_START, l2cap(0x0040, b'x' * 20)[:14]), ltaddr=6))
# 118: L2CAP continuation without a connection (LT_ADDR 6) and correct CRC
add(cdata(3, hdr1(LL_CONT, b'0123456789'), ltaddr=6))
# 119: reproducer btbredr_rf_cont_stale_tvb.py (byte for byte): DM1
# continuation on an unknown access code; before the fix the whole payload
# went to L2CAP as a complete PDU
pl = b'\x04\x00\x01\x00\x0a\x0b\x0c\x0d'
add(bb(REPRO_LAP, header(REPRO_UAP, 1, 3, flow=0),
       F_DEWHITENED | F_DECRYPTED | F_DATA | F_CRC_CHECKED | F_CRC_PASS | F_UAP_VALID,
       bytes([0x01 | (len(pl) << 3)]) + pl + b'\0\0', pt=0x30, uap=REPRO_UAP,
       chan=5, sp=0, np_=0))
# 120: CPB EDR 3 Mb/s 3-DH3 carrying a complete L2CAP PDU on D's access code
add(cdata(11, hdr2(LL_START, l2cap(0x0002, b'connectionless-3mbps')), pt=CPB | EDR3,
          ltaddr=0, dev=D))
# 121: DH1 with trailing octets after the CRC -> remaining data
add(cdata(4, hdr1(LL_START, l2cap(0x0040, b'trail')), ) + b'\xee\xee')

# 122: NULL in the ACL EDR table
add(cdata(0, b'', pt=ACL | EDR2, crc=False, flags=OK & ~F_DATA))
# 123-124: LMP_eSCO_link_req renegotiating LT_ADDR 2 for 2-EV3 (60 octets),
# then a 2-EV3 of that length: no warning now (compare frame 109)
add(cdata(3, hdr1(LL_LMP, lmp(0x40c, struct.pack('<BBBBBBBBHHBB', 5, 2, 0, 0, 6, 2, 6, 6, 60, 60, 3, 1)))))
add(cdata(6, bytes(range(60)), pt=ESCO | EDR2, ltaddr=2))

# --- Malformed / extra capture ---------------------------------------------
mal = []
# 1: shorter than the flags (21 octets) -> flags treated as 0, then exception
mal.append(bb(C.lap, header(C.uap, 1, 3), OK)[:21])
# 2: pseudoheader cut in the packet header
mal.append(bb(C.lap, header(C.uap, 1, 3), OK)[:18])
# 3: FHS cut after 10 octets
mal.append(bb(P.lap, header(P.uap, 0, 2), OK, fhs(C, ltaddr=1)[:8] + b'\0\0', uap=P.uap))
# 4-5: the known two-pass difference (btbredr_rf_two_pass_device_info.py):
# a DM1 on 0x2468ac before the inquiry FHS that announces that LAP
E = Dev(0x0002, 0x5a, 0x2468ac)
flm = F_DEWHITENED | F_DECRYPTED | F_DATA | F_CRC_CHECKED | F_CRC_PASS
mal.append(bb(E.lap, header(E.uap, 1, 3), flm, with_crc(E.uap, hdr1(LL_START, b'\x01\x02\x03\x04'))))
mal.append(bb(GIAC, header(0, 0, 2), flm, with_crc(0, fhs(E, clk=0x100))))
# 6-7: FHS from an unknown access code announcing D with LT_ADDR 3 (no
# peripheral), then an FHS on E's access code assigning LT_ADDR 3 to D:
# updates the existing connection's peripheral address
mal.append(bb(X_LAP, header(X_UAP, 0, 2), OK, with_crc(X_UAP, fhs(D, ltaddr=3)), uap=X_UAP))
mal.append(bb(E.lap, header(E.uap, 0, 2), flm, with_crc(E.uap, fhs(D, ltaddr=3))))
# 8-11: page FHS on E's code: F with LT_ADDR 1, then F's LMP_eSCO_link_req,
# LMP_remove_eSCO_link_req and an EV3 on the eSCO LT_ADDR 4
F = Dev(0x0002, 0x6b, 0x1357bd)
mal.append(bb(E.lap, header(E.uap, 0, 2), flm, with_crc(E.uap, fhs(F, ltaddr=1))))
mal.append(bb(F.lap, header(F.uap, 1, 3), flm,
              with_crc(F.uap, hdr1(LL_LMP, lmp(0x40c, struct.pack('<BBBBBBBBHHBB', 7, 4, 0, 0, 6, 2, 7, 7, 30, 30, 3, 0)))), uap=F.uap))
mal.append(bb(F.lap, header(F.uap, 1, 3, seqn=1), flm,
              with_crc(F.uap, hdr1(LL_LMP, lmp(0x40d, b'\x07\x13'))), uap=F.uap))
mal.append(bb(F.lap, header(F.uap, 4, 7), flm, with_crc(F.uap, bytes(30)), pt=ESCO | BR, uap=F.uap))
# 12: LMP truncated (eSCO link req with 2 parameter octets)
mal.append(bb(F.lap, header(F.uap, 1, 3), flm, with_crc(F.uap, hdr1(LL_LMP, lmp(0x40c, b'\x07\x04'))), uap=F.uap))
# 13: L2CAP complete PDU whose signalling command is cut
mal.append(bb(F.lap, header(F.uap, 1, 3), flm, with_crc(F.uap, hdr1(LL_START, l2cap(0x0001, b'\x08\x01\x10\x00ab'))), uap=F.uap))
# 14: the original two-pass reproducer bytes (LAP 0x123456 / UAP 0x5a)
mal.append(bb(0x9e8b33, header(0, 0, 2), flm,
              struct.pack('<Q', 0x123456 << 34) + bytes([0x5a]) + struct.pack('<H', 0x0200) +
              b'\x00\x01\x02' + struct.pack('<I', 0) + b'\0\0'))
# 15-16: start leaving 4 octets, then a longer continuation: the
# continuation is handed to L2CAP as a complete PDU ("Length too short")
big4 = l2cap(0x0044, b'0123456789abcdef')
mal.append(bb(F.lap, header(F.uap, 1, 4, seqn=1), flm, with_crc(F.uap, hdr1(LL_START, big4[:16])), uap=F.uap))
mal.append(bb(F.lap, header(F.uap, 1, 3, seqn=0), flm, with_crc(F.uap, hdr1(LL_CONT, b'0123456789')), uap=F.uap))
# 17: LMP_eSCO_link_req and LMP_remove_eSCO_link_req without a connection
mal.append(bb(U_LAP, header(0x11, 1, 3), flm | F_UAP_VALID,
              with_crc(0x11, hdr1(LL_LMP, lmp(0x40c, struct.pack('<BBBBBBBBHHBB', 9, 3, 0, 0, 6, 2, 7, 7, 30, 30, 3, 0)))), uap=0x11))
mal.append(bb(U_LAP, header(0x11, 1, 3, seqn=1), flm | F_UAP_VALID,
              with_crc(0x11, hdr1(LL_LMP, lmp(0x40d, b'\x09\x13'))), uap=0x11))

os.makedirs(OUT, exist_ok=True)
write_pcap(os.path.join(OUT, 'btbredr_rf-coverage.pcap'), main)
write_pcap(os.path.join(OUT, 'btbredr_rf-coverage-malformed.pcap'), mal)
# Exported PDU naming "btbredr_fhs" (reproducer btbredr_rf_fhs_null_data.py)
# and "btbredr_rf" (no bluetooth_data: interface from the record or the
# default) carrying an inquiry FHS, a page FHS and a DM1; once in pcap (no
# interface ID) and once in pcapng (interface ID 0)
exp = [exported_pdu('btbredr_fhs', bytes(18)), exported_pdu('btbredr_fhs', fhs(P)),
       exported_pdu('btbredr_rf', bb(GIAC, header(0, 0, 2), OK & ~F_UAP_VALID, with_crc(0, fhs(P)), pt=ANY | BR)),
       exported_pdu('btbredr_rf', bb(P.lap, header(P.uap, 0, 2), OK & ~F_UAP_VALID,
                                     with_crc(P.uap, fhs(C, ltaddr=1)))),
       exported_pdu('btbredr_rf', cdata(3, hdr1(LL_LMP, lmp(0x31)), seqn=0))]
write_pcap(os.path.join(OUT, 'btbredr_rf-coverage-exppdu.pcap'), exp, linktype=LINKTYPE_EXPORTED_PDU)
write_pcapng(os.path.join(OUT, 'btbredr_rf-coverage-exppdu.pcapng'), exp, linktype=LINKTYPE_EXPORTED_PDU)
print(len(main), 'main frames,', len(mal), 'malformed frames')

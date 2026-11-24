#!/usr/bin/env python3
# Generates test/captures/lcsap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LCS-AP coverage captures.

Usage: mklcsap.py <outdir> [<wireshark asn1 dir>]

Every LCS-AP message is encoded with aper.py from the LCS-AP ASN.1
modules in the Wireshark tree (epan/dissectors/asn1/lcsap), with every
optional component and every IE of each IE set present and one CHOICE
alternative per variant. APDUs carry LPP (UPER, two octets) or LPPa
(encoded from the LPPa modules). Nothing comes from a real network.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASNROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1')
LCS = ['LCS-AP-CommonDataTypes.asn', 'LCS-AP-Constants.asn', 'LCS-AP-Containers.asn',
       'LCS-AP-IEs.asn', 'LCS-AP-PDU-Contents.asn', 'LCS-AP-PDU-Descriptions.asn']
LPPA = ['LPPA-CommonDataTypes.asn', 'LPPA-Constants.asn', 'LPPA-Containers.asn',
        'LPPA-IEs.asn', 'LPPA-PDU-Contents.asn', 'LPPA-PDU-Descriptions.asn']
NVARIANTS = 9

LPP_ACK = b'\x2c\x05'          # LPP-Message: endTransaction, acknowledgement only
XML = b'<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf"/>'
STATE = {}


def lppa_pdu():
    sp = STATE['lppa']
    procs = sp.procedures('LPPA-ELEMENTARY-PROCEDURES', 'LPPA-PDU-Descriptions')
    o = procs[0]
    return sp.pdu('LPPA-PDU', 'LPPA-PDU-Descriptions', 0, o, aper.Ctx(k=0))


def apdu_bytes(ctx):
    proc = ctx.vals.get('proc')
    if proc == 'id-Connectionless-Information-Transfer' or ctx.k % 2 == 1:
        return lppa_pdu()
    return LPP_ACK


def ov_apdu(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, apdu_bytes(ctx), None, mod)


def ov_payload_type(sp, w, t, mod, ctx):
    # 0 lPP, 1 lPPa; the APDU that follows uses the same parity of k
    sp.enc_enum(w, t, ctx.k % 2)


def ov_plmn(sp, w, t, mod, ctx):
    t = {'k': 'OCTETS', 'size': ('3', '3', False)}
    sp.enc_octets(w, t, [b'\x00\xf1\x10', b'\x62\x02\x21', b'\x13\x00\x14'][ctx.k % 3], None, mod)


def ov_imsi(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, bytes.fromhex(['001010123456789f'[:12], '262021234567f9'[:14], '310150123456f7'[:12]][ctx.k % 3]), None, mod)


def ov_civic(sp, w, t, mod, ctx):
    data = b'not xml at all' if ctx.vals.get('civic_bad') else XML
    sp.enc_octets(w, t, data, None, mod)


def ov_posmeth(sp, w, t, mod, ctx):
    # method in bits 8-4, usage in bits 3-1
    sp.enc_octets(w, t, bytes([((ctx.k * 3 + 1) % 32) << 3 | (ctx.k % 5)]), None, mod)


def ov_gnss(sp, w, t, mod, ctx):
    # method bits 8-7, GNSS id bits 6-4, usage bits 3-1
    sp.enc_octets(w, t, bytes([(ctx.k % 4) << 6 | ((ctx.k * 3) % 8) << 3 | (ctx.k % 8)]), None, mod)


OVERRIDES = {
    'APDU': ov_apdu,
    'Payload-Type': ov_payload_type,
    'PLMN-ID': ov_plmn,
    'IMSI': ov_imsi,
    'Civic-Address': ov_civic,
    'Positioning-Method-And-Usage': ov_posmeth,
    'GNSS-Positioning-Method-And-Usage': ov_gnss,
}


def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:]
    return hdr + payload


MME = [192, 0, 2, 1]
SMLC = [192, 0, 2, 2]


def eth(rev):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    if rev:
        a, b = b, a
    return b + a + b'\x08\x00'


class Sctp:
    def __init__(self, port=9082, ppid=29, sport=None):
        self.port, self.ppid = port, ppid
        self.sport = sport or port
        self.tsn = {False: 1000, True: 5000}
        self.ssn = {False: 0, True: 0}

    def frame(self, payload, rev):
        tsn = self.tsn[rev]
        self.tsn[rev] += 1
        ssn = self.ssn[rev]
        self.ssn[rev] = (ssn + 1) & 0xffff
        chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, ssn, self.ppid) + payload
        chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
        sp_, dp = (40000, self.port) if not rev else (self.port, 40000)
        sctp = struct.pack('>HHII', sp_, dp, 0x01020304, 0) + chunk
        src, dst = (SMLC, MME) if rev else (MME, SMLC)
        return eth(rev) + ipv4(src, dst, 132, sctp)


def write_pcap(name, frames, link=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def ie(ie_id, value):
    assert len(value) < 128
    return struct.pack('>H', ie_id) + b'\x00' + bytes([len(value)]) + value


def coi(ies):
    return b'\x00' + struct.pack('>H', len(ies)) + b''.join(ies)


def pdu(value):
    assert len(value) < 128
    return b'\x00\x01\x00' + bytes([len(value)]) + value


def main():
    sp = aper.Spec([os.path.join(ASNROOT, 'lcsap', f) for f in LCS], OVERRIDES)
    STATE['lppa'] = aper.Spec([os.path.join(ASNROOT, 'lppa', f) for f in LPPA])
    procs = sp.procedures('LCS-AP-ELEMENTARY-PROCEDURES', 'LCS-AP-PDU-Descriptions')
    sctp = Sctp()
    frames, pdus, ranges = [], [], []
    code = {}
    for o, om in procs:
        for kind, f in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if f not in o:
                continue
            start = len(frames)
            nv = NVARIANTS if o['&procedureCode'] != 'id-Reset' else 2
            for k in range(nv):
                ctx = aper.Ctx(k=k, vals={'proc': o['&procedureCode']})
                b = sp.pdu('LCS-AP-PDU', 'LCS-AP-PDU-Descriptions', kind, (o, om), ctx)
                pdus.append(b)
                frames.append(sctp.frame(b, kind != 0))
            ctx = aper.Ctx(k=0, full=False, vals={'proc': o['&procedureCode']})
            b = sp.pdu('LCS-AP-PDU', 'LCS-AP-PDU-Descriptions', kind, (o, om), ctx)
            frames.append(sctp.frame(b, kind != 0))
            ranges.append((o['&procedureCode'], f, start + 1, len(frames)))

    # Reproducer of the PayloadType fix: file-scope PayloadType carried over
    # between packets. 1: APDU only (type unknown, not handed to LPP), 2: LPP
    # type then two APDUs (both must reach LPP now), 3: type only.
    start = len(frames)
    apdu = b'\x02' + LPP_ACK
    frames.append(sctp.frame(pdu(coi([ie(1, apdu)])), False))
    frames.append(sctp.frame(pdu(coi([ie(15, b'\x00'), ie(1, apdu), ie(1, apdu)])), False))
    frames.append(sctp.frame(pdu(coi([ie(15, b'\x00')])), False))
    ranges.append(('PayloadType reproducer', '', start + 1, len(frames)))

    # a second SCTP flow on another port: needs the ppid only (heuristic by PPI)
    s2 = Sctp(port=50000, ppid=29)
    start = len(frames)
    frames.append(s2.frame(pdus[0], False))
    ranges.append(('PPI 29 on another port', '', start + 1, len(frames)))
    write_pcap(os.path.join(OUT, 'lcsap-coverage.pcap'), frames)

    # Malformed capture
    mal = []
    for b in pdus[::9]:
        mal.append(sctp.frame(b[:len(b) // 2], False))
    for b in pdus[1::13]:
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(sctp.frame(bytes(x), True))
    loc = [p for p in procs if p[0]['&procedureCode'] == 'id-Location-Service-Request'][0]
    ctx = aper.Ctx(k=0, vals={'proc': 'Location-Response', 'civic_bad': True})
    mal.append(sctp.frame(sp.pdu('LCS-AP-PDU', 'LCS-AP-PDU-Descriptions', 1, loc, ctx), True))
    mal.append(sctp.frame(b'\x00', False))
    write_pcap(os.path.join(OUT, 'lcsap-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()

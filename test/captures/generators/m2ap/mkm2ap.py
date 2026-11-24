#!/usr/bin/env python3
# Generates test/captures/m2ap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic M2AP coverage captures.

Usage: mkm2ap.py <outdir> [<wireshark asn1 dir>]

Every M2AP message is encoded with aper.py from the M2AP ASN.1 modules in
the Wireshark tree (epan/dissectors/asn1/m2ap), with every optional
component and every IE of each IE set present and one CHOICE alternative
per variant. Nothing comes from a real network.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASNROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1')
FILES = ['M2AP-CommonDataTypes.asn', 'M2AP-Constants.asn', 'M2AP-Containers.asn',
         'M2AP-Ies.asn', 'M2AP-PDU-Contents.asn', 'M2AP-PDU-Descriptions.asn']
NVARIANTS = 6


def ov_plmn(sp, w, t, mod, ctx):
    # MCC 001 MNC 01, MCC 262 MNC 02, MCC 310 MNC 150 (three digit MNC)
    sp.enc_octets(w, t, [b'\x00\xf1\x10', b'\x62\x02\x21', b'\x13\x00\x14'][ctx.k % 3], None, mod)


def ov_ip(sp, w, t, mod, ctx):
    # variants: IPv4, IPv6, an invalid length (the expert info is in the
    # malformed capture only), so rotate between 4 and 16 octets here
    data = [bytes([192, 0, 2, 10 + ctx.k]), bytes(range(0x20, 0x30))][ctx.k % 2]
    if ctx.vals.get('ipbad'):
        data = b'\x01\x02\x03\x04\x05'
    sp.enc_octets(w, t, data, None, mod)


def ov_private(sp, w, t, mod, ctx):
    # two PrivateIE-Fields: id local and id global (OBJECT IDENTIFIER),
    # each with a short open type value (no dissector is registered)
    sp.enc_len(w, 2, 1, 65535)
    w.b(0, 1)
    w.align()
    w.b(0x1234 + ctx.k, 16)
    w.b(ctx.k % 3, 2)
    inner = aper.Bits()
    inner.octets(b'\x01\x02\x03' + bytes([ctx.k]))
    sp.opentype(w, inner)
    w.b(1, 1)
    w.lendet(3)
    w.octets(b'\x2b\x06\x01')
    w.b(2, 2)
    inner = aper.Bits()
    inner.octets(b'\xaa')
    sp.opentype(w, inner)


OVERRIDES = {
    'PrivateIE-Container': ov_private,
    'PLMN-Identity': ov_plmn,
    'IPAddress': ov_ip,
}


def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:] + payload


MCE = [192, 0, 2, 1]
ENB = [192, 0, 2, 2]


def eth(rev):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    if rev:
        a, b = b, a
    return b + a + b'\x08\x00'


class Sctp:
    def __init__(self, port=36443, ppid=43):
        self.port, self.ppid = port, ppid
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
        src, dst = (ENB, MCE) if rev else (MCE, ENB)
        return eth(rev) + ipv4(src, dst, 132, sctp)


def write_pcap(name, frames, link=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    sp = aper.Spec([os.path.join(ASNROOT, 'm2ap', f) for f in FILES], OVERRIDES)
    procs = sp.procedures('M2AP-ELEMENTARY-PROCEDURES', 'M2AP-PDU-Descriptions')
    sctp = Sctp()
    frames, pdus, ranges = [], [], []
    for o, om in procs:
        for kind, f in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if f not in o:
                continue
            start = len(frames)
            for k in range(NVARIANTS):
                ctx = aper.Ctx(k=k, vals={'proc': o['&procedureCode']})
                b = sp.pdu('M2AP-PDU', 'M2AP-PDU-Descriptions', kind, (o, om), ctx)
                pdus.append(b)
                frames.append(sctp.frame(b, kind != 0))
            ctx = aper.Ctx(k=0, full=False, vals={'proc': o['&procedureCode']})
            b = sp.pdu('M2AP-PDU', 'M2AP-PDU-Descriptions', kind, (o, om), ctx)
            frames.append(sctp.frame(b, kind != 0))
            ranges.append((o['&procedureCode'], f, start + 1, len(frames)))

    # the same PDU on another SCTP port, found by PPID 43 only
    s2 = Sctp(port=50000, ppid=43)
    start = len(frames)
    frames.append(s2.frame(pdus[0], False))
    ranges.append(('PPI 43 on another port', '', start + 1, len(frames)))
    write_pcap(os.path.join(OUT, 'm2ap-coverage.pcap'), frames)

    # Malformed capture
    mal = []
    for b in pdus[::7]:
        mal.append(sctp.frame(b[:len(b) // 2], False))
    for b in pdus[1::11]:
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(sctp.frame(bytes(x), True))
    # IPAddress of 5 octets: the error expert info of the template code
    o, om = procs[0]
    ctx = aper.Ctx(k=0, vals={'proc': o['&procedureCode'], 'ipbad': True})
    mal.append(sctp.frame(sp.pdu('M2AP-PDU', 'M2AP-PDU-Descriptions', 0, (o, om), ctx), False))
    mal.append(sctp.frame(b'\x00', False))
    write_pcap(os.path.join(OUT, 'm2ap-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()

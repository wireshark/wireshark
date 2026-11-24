#!/usr/bin/env python3
# Generates test/captures/e1ap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic E1AP coverage captures.

Usage: mke1ap.py <outdir> [<asn1 dir>]

Every E1AP message is encoded with aper.py from the E1AP ASN.1 modules
in the Wireshark tree (epan/dissectors/asn1/e1ap), with every optional
component and every IE of each IE set present, and one CHOICE
alternative per variant. Nothing comes from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1/e1ap')
FILES = ['E1AP-CommonDataTypes.asn', 'E1AP-Constants.asn', 'E1AP-Containers.asn',
         'E1AP-IEs.asn', 'E1AP-PDU-Contents.asn', 'E1AP-PDU-Descriptions.asn']
NVARIANTS = 3


# ---- overrides for IEs the hand-written code looks into ----

def ov_plmn(sp, w, t, mod, ctx):
    # MCC 001 MNC 01, or MCC 262 MNC 012 (three digit MNC)
    sp.enc_octets(w, t, [b'\x00\xf1\x10', b'\x62\x02\x21'][ctx.k % 2], None, mod)


def ov_burst(sp, w, t, mod, ctx):
    # NR RRC ReferenceTime-r16 in UNALIGNED PER: days 17 bits, seconds 17,
    # milliseconds 10, ten nanoseconds 17
    b = aper.Bits()
    b.b(100 + ctx.k, 17)
    b.b(3600, 17)
    b.b(250, 10)
    b.b(12345, 17)
    sp.enc_octets(w, t, b.get(), None, mod)


TLA = [bytes([192, 0, 2, 10]),
       bytes.fromhex('20010db8000000000000000000000010'),
       bytes([192, 0, 2, 11]) + bytes.fromhex('20010db8000000000000000000000011'),
       bytes([10, 1])]


def ov_tla(sp, w, t, mod, ctx):
    # IPv4, IPv6, IPv4 + IPv6, and a 16-bit address the code does not show
    a = TLA[ctx.k % 4]
    sp.enc_bits(w, t, len(a) * 8, a, None, mod)


def ov_private(sp, w, t, mod, ctx):
    # PrivateIE-Container: SEQUENCE (SIZE(1..65535)) OF PrivateIE-Field;
    # the PrivateMessage-IEs set is empty, so write a local id and, in the
    # malformed capture, a global id (call_per_oid_callback() returns a
    # wrong offset, so whatever follows it is misread)
    glob = ctx.vals.get('private_global', False)
    w.align()
    w.b(1 if glob else 0, 16)
    # local id 7, criticality ignore, value 2 octets
    w.b(0, 1)               # PrivateIE-ID: local
    w.align()
    w.b(7, 16)
    w.b(1, 2)               # ignore
    sp.opentype(w, _bytes(b'\xab\xcd'))
    if not glob:
        return
    # global id 1.3.6.1.4.1.53148.99 (an OID without a registered dissector)
    w.b(1, 1)               # PrivateIE-ID: global
    oid = bytes([0x2b, 6, 1, 4, 1, 0x83, 0xa0, 0x1c, 99])
    w.lendet(len(oid))
    w.octets(oid)
    w.b(0, 2)               # reject
    sp.opentype(w, _bytes(b'\x01\x02\x03'))


def _bytes(data):
    b = aper.Bits()
    b.octets(data)
    return b


OVERRIDES = {
    'PLMN-Identity': ov_plmn,
    'BurstArrivalTime': ov_burst,
    'TransportLayerAddress': ov_tla,
    'PrivateIE-Container': ov_private,
}


# ---- packet framing ----

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


CP = [192, 0, 2, 1]     # gNB-CU-CP
UP = [192, 0, 2, 2]     # gNB-CU-UP


class Sctp:
    def __init__(self, port=38462, ppid=64):
        self.port = port
        self.ppid = ppid
        self.tsn = {False: 1000, True: 5000}
        self.ssn = {False: 0, True: 0}

    def frame(self, payload, rev):
        tsn = self.tsn[rev]
        self.tsn[rev] += 1
        ssn = self.ssn[rev]
        self.ssn[rev] = (ssn + 1) & 0xffff
        chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, ssn, self.ppid) + payload
        chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
        sctp = struct.pack('>HHII', self.port, self.port, 0x01020304, 0) + chunk
        src, dst = (UP, CP) if rev else (CP, UP)
        return eth(rev) + ipv4(src, dst, 132, sctp)


def eth(rev):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    if rev:
        a, b = b, a
    return b + a + b'\x08\x00'


def tcp_frame(payload, seq, ack, rev, flags=0x18, port=38500):
    sp_, dp = (40000, port) if not rev else (port, 40000)
    tcp = struct.pack('>HHIIBBHHH', sp_, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    src, dst = (UP, CP) if rev else (CP, UP)
    return eth(rev) + ipv4(src, dst, 6, tcp)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    sp = aper.Spec([os.path.join(ASN, f) for f in FILES], OVERRIDES)
    procs = sp.procedures('E1AP-ELEMENTARY-PROCEDURES', 'E1AP-PDU-Descriptions')
    sctp = Sctp()
    frames = []
    pdus = []
    for o, om in procs:
        for kind, f in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if f not in o:
                continue
            for k in range(NVARIANTS):
                b = sp.pdu('E1AP-PDU', 'E1AP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=k))
                pdus.append(b)
                frames.append(sctp.frame(b, kind != 0))
            # and once with the mandatory IEs only
            b = sp.pdu('E1AP-PDU', 'E1AP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=0, full=False))
            frames.append(sctp.frame(b, kind != 0))
    write_pcap(os.path.join(OUT, 'e1ap-coverage.pcap'), frames)

    # Malformed capture: E1AP over TCP (needs Decode As, e1ap_tcp has no
    # default port) and truncated or corrupted PDUs.
    mal = []
    seq = 1
    for b in pdus[:3]:
        rec = struct.pack('>I', len(b)) + b
        mal.append(tcp_frame(rec, seq, 1, False))
        seq += len(rec)
    # two PDUs in one segment, the second one split over two segments
    r1 = struct.pack('>I', len(pdus[3])) + pdus[3]
    r2 = struct.pack('>I', len(pdus[4])) + pdus[4]
    mal.append(tcp_frame(r1 + r2[:5], seq, 1, False))
    seq += len(r1) + 5
    mal.append(tcp_frame(r2[5:], seq, 1, False))
    seq += len(r2) - 5
    priv = [o for o in procs if o[0]['&procedureCode'] == 'id-privateMessage'][0]
    mal.append(sctp.frame(sp.pdu('E1AP-PDU', 'E1AP-PDU-Descriptions', 0, priv,
                                 aper.Ctx(vals={'private_global': True})), False))
    for b in pdus[:len(pdus):7]:
        mal.append(sctp.frame(b[:len(b) // 2], False))
    for i, b in enumerate(pdus[1:len(pdus):11]):
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(sctp.frame(bytes(x), True))
    write_pcap(os.path.join(OUT, 'e1ap-coverage-malformed.pcap'), mal)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()

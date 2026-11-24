#!/usr/bin/env python3
# Generates test/captures/lppa_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LPPa coverage captures.

Usage: mklppa.py <outdir> [<wireshark asn1 dir>]

Every LPPa message (every elementary procedure, as initiating message,
successful outcome and unsuccessful outcome where the procedure has
them) is encoded with aper.py from the LPPa ASN.1 modules in the
Wireshark tree (epan/dissectors/asn1/lppa), with every optional
component and every IE of each IE set present and one CHOICE
alternative per variant, plus one message with only the mandatory
parts. The LPPa PDUs are carried in Exported PDU frames that name the
"lppa" dissector, and in the four S1AP LPPa transport messages (uplink and
downlink, UE associated and not) on SCTP port 36412, PPID 18. Nothing
comes from a real network. The main capture is a pcapng file with two
interfaces (Exported PDU and Ethernet).
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASNROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1')
LPPA = ['LPPA-CommonDataTypes.asn', 'LPPA-Constants.asn', 'LPPA-Containers.asn',
        'LPPA-IEs.asn', 'LPPA-PDU-Contents.asn', 'LPPA-PDU-Descriptions.asn']
NVARIANTS = 9


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


OVERRIDES = {'PrivateIE-Container': ov_private}

S1AP = ['S1AP-CommonDataTypes.asn', 'S1AP-Constants.asn', 'S1AP-Containers.asn',
        'S1AP-IEs.asn', 'S1AP-PDU-Contents.asn', 'S1AP-PDU-Descriptions.asn',
        'S1AP-SonTransfer-IEs.asn']
STATE = {}


def ov_lppa_pdu(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, STATE['lppa_pdus'][ctx.k % len(STATE['lppa_pdus'])], None, mod)


def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = sum((hdr[i] << 8) | hdr[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:] + payload


class Sctp:
    """One SCTP association MME (192.0.2.1) - eNB (192.0.2.2), S1AP PPID 18."""
    def __init__(self, port=36412, ppid=18):
        self.port, self.ppid = port, ppid
        self.tsn = {False: 1000, True: 5000}
        self.ssn = {False: 0, True: 0}

    def frame(self, payload, rev):
        tsn = self.tsn[rev]
        self.tsn[rev] += 1
        ssn = self.ssn[rev]
        self.ssn[rev] += 1
        chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, ssn, self.ppid) + payload
        chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
        sp_, dp = (self.port, 40000) if rev else (40000, self.port)
        sctp = struct.pack('>HHII', sp_, dp, 0x01020304, 0) + chunk
        a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        src, dst = ([192, 0, 2, 2], [192, 0, 2, 1]) if rev else ([192, 0, 2, 1], [192, 0, 2, 2])
        return (b + a if rev else a + b) + b'\x08\x00' + ipv4(src, dst, 132, sctp)


def pcapng_block(typ, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    n = 12 + len(body)
    return struct.pack('<II', typ, n) + body + struct.pack('<I', n)


def write_pcapng(name, frames):
    """frames: (link type, bytes); interface 0 = Exported PDU (252), 1 = Ethernet."""
    out = pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += pcapng_block(1, struct.pack('<HHI', 252, 0, 65535))
    out += pcapng_block(1, struct.pack('<HHI', 1, 0, 65535))
    for i, (link, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += pcapng_block(6, struct.pack('<IIIII', 0 if link == 252 else 1, ts >> 32,
                                           ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(name, 'wb') as f:
        f.write(out)



def exported_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def write_pcap(name, frames, link=252):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    sp = aper.Spec([os.path.join(ASNROOT, 'lppa', f) for f in LPPA], OVERRIDES)
    procs = sp.procedures('LPPA-ELEMENTARY-PROCEDURES', 'LPPA-PDU-Descriptions')
    frames, pdus, ranges = [], [], []
    for o, om in procs:
        for kind, f in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if f not in o:
                continue
            start = len(frames)
            for k in range(NVARIANTS):
                ctx = aper.Ctx(k=k)
                b = sp.pdu('LPPA-PDU', 'LPPA-PDU-Descriptions', kind, (o, om), ctx)
                pdus.append(b)
                frames.append(exported_pdu('lppa', b))
            ctx = aper.Ctx(k=0, full=False)
            b = sp.pdu('LPPA-PDU', 'LPPA-PDU-Descriptions', kind, (o, om), ctx)
            frames.append(exported_pdu('lppa', b))
            ranges.append((o['&procedureCode'], f, start + 1, len(frames)))
    allf = [(252, f) for f in frames]
    # LPPa in S1AP: the four LPPa transport procedures, every IE of each
    # present (the LPPa-PDU is one of the LPPa messages above), then with
    # the mandatory IEs only
    STATE['lppa_pdus'] = pdus[::7]
    s1 = aper.Spec([os.path.join(ASNROOT, 's1ap', f) for f in S1AP], {'LPPa-PDU': ov_lppa_pdu})
    sprocs = s1.procedures('S1AP-ELEMENTARY-PROCEDURES', 'S1AP-PDU-Descriptions')
    sctp = Sctp()
    start = len(allf)
    for o, om in sprocs:
        if o['&procedureCode'] not in ('id-downlinkUEAssociatedLPPaTransport',
                                       'id-uplinkUEAssociatedLPPaTransport',
                                       'id-downlinkNonUEAssociatedLPPaTransport',
                                       'id-uplinkNonUEAssociatedLPPaTransport'):
            continue
        for k in range(len(STATE['lppa_pdus'])):
            b = s1.pdu('S1AP-PDU', 'S1AP-PDU-Descriptions', 0, (o, om), aper.Ctx(k=k))
            allf.append((1, sctp.frame(b, 'Uplink' not in o['&procedureCode'])))
        ranges.append((o['&procedureCode'] + ' in S1AP', '', start + 1, len(allf)))
        start = len(allf)
    write_pcapng(os.path.join(OUT, 'lppa-coverage.pcapng'), allf)

    mal = []
    for b in pdus[::9]:
        mal.append(exported_pdu('lppa', b[:len(b) // 2]))
    for b in pdus[1::13]:
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(exported_pdu('lppa', bytes(x)))
    priv = [p for p in procs if p[0]['&procedureCode'] == 'id-privateMessage'][0]
    mal.append(exported_pdu('lppa', sp.pdu('LPPA-PDU', 'LPPA-PDU-Descriptions', 0, priv,
                                           aper.Ctx(vals={'private_global': True}))))
    mal.append(exported_pdu('lppa', b'\x00'))
    write_pcap(os.path.join(OUT, 'lppa-coverage-malformed.pcap'), mal)
    os.remove(os.path.join(OUT, 'lppa-coverage.pcap')) if os.path.exists(os.path.join(OUT, 'lppa-coverage.pcap')) else None
    for r in ranges:
        print(r)
    print(len(allf), len(mal))


if __name__ == '__main__':
    main()

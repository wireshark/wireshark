#!/usr/bin/env python3
# Generates test/captures/f1ap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic F1AP coverage captures.

Usage: mkf1ap.py <outdir> [<asn1 dir>]

Every F1AP message is encoded with aper.py from the F1AP ASN.1 modules
in the Wireshark tree (epan/dissectors/asn1/f1ap), with every optional
component and every IE of each IE set present, and one CHOICE
alternative per variant. Nothing comes from a real network.
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys

import aper

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
ASN = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/asn1/f1ap')
FILES = ['F1AP-CommonDataTypes.asn', 'F1AP-Constants.asn', 'F1AP-Containers.asn',
         'F1AP-IEs.asn', 'F1AP-PDU-Contents.asn', 'F1AP-PDU-Descriptions.asn']
NVARIANTS = 3
VALS = {'zero': 160, 'omit': ('sCS-Common',), 'byfield': {}}


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


# NR RRC SIB13-r16 (UNALIGNED PER) holding an almost empty E-UTRA
# SIB21-r14 and an almost empty E-UTRA TDD-Config
_bits = '00' + format(2, '08b') + '0' * 16 + format(0, '08b') + format(2, '08b') + '0' * 16
_bits += '0' * (-len(_bits) % 8)
SIB13 = int(_bits, 2).to_bytes(len(_bits) // 8, 'big')


def ov_sib13(sp, w, t, mod, ctx):
    sp.enc_octets(w, t, SIB13, None, mod)


def ov_srbid(sp, w, t, mod, ctx):
    v = ctx.vals.get('srb', ctx.k % 4)
    sp.enc_int(w, v, 0, 3, t['range'][2])


def ov_rrc(sp, w, t, mod, ctx):
    # 6 and 8 octets are the UL-CCCH and UL-CCCH1 lengths that
    # InitialULRRCMessageTransfer tells apart
    n = ctx.vals.get('rrclen', 160)
    sp.enc_octets(w, t, bytes(n), None, mod)


OVERRIDES = {
    'SRBID': ov_srbid,
    'RRCContainer': ov_rrc,
    'SIB13-message': ov_sib13,
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


CP = [192, 0, 2, 1]     # gNB-CU
UP = [192, 0, 2, 2]     # gNB-DU


class Sctp:
    def __init__(self, port=38472, ppid=62):
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


def ie(iid, val):
    return struct.pack('!HBB', iid, 0, len(val)) + val


def relcmd(ies):
    body = b'\x00' + struct.pack('!H', len(ies)) + b''.join(ies)
    return b'\x00\x06\x00' + bytes([len(body)]) + body


def multi(sctp, payloads):
    """One SCTP packet with several DATA chunks (one F1AP PDU each)."""
    chunks = b''
    for i, p in enumerate(payloads):
        tsn = sctp.tsn[False]
        sctp.tsn[False] += 1
        ssn = sctp.ssn[False]
        sctp.ssn[False] = (ssn + 1) & 0xffff
        c = struct.pack('>BBHIHHI', 0, 3, 16 + len(p), tsn, 0, ssn, sctp.ppid) + p
        chunks += c + b'\0' * ((4 - len(c) % 4) % 4)
    s = struct.pack('>HHII', sctp.port, sctp.port, 0x01020304, 0) + chunks
    return eth(False) + ipv4(CP, UP, 132, s)


def reproducers(sctp):
    """UEContextReleaseCommand PDUs bundled in one SCTP packet: the first
    holds only an RRCContainer, the second only SRBID 0, the third a second
    SRBID. Before the fix the SRBID handler dissected the first PDU's
    container again (as NR RRC DL-CCCH) under the later PDUs."""
    rrc = b'\x00\x10\x20\x30\x40\x50'
    pdu1 = relcmd([ie(50, bytes([len(rrc)]) + rrc)])
    pdu2 = relcmd([ie(64, b'\x00')])
    pdu3 = relcmd([ie(64, b'\x40')])
    return [multi(sctp, [pdu1, pdu2, pdu3]), multi(sctp, [pdu1])]


def vv(o, k, minimal=False):
    v = dict(VALS)
    if o['&procedureCode'] == 'id-InitialULRRCMessageTransfer':
        v['rrclen'] = 6 if minimal else [6, 8, 160][k % 3]
    return v


def main():
    sp = aper.Spec([os.path.join(ASN, f) for f in FILES], OVERRIDES)
    procs = sp.procedures('F1AP-ELEMENTARY-PROCEDURES', 'F1AP-PDU-Descriptions')
    sctp = Sctp()
    frames = []
    pdus = []
    for o, om in procs:
        for kind, f in enumerate(['&InitiatingMessage', '&SuccessfulOutcome', '&UnsuccessfulOutcome']):
            if f not in o:
                continue
            for k in range(NVARIANTS):
                b = sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=k, vals=vv(o, k)))
                pdus.append(b)
                frames.append(sctp.frame(b, kind != 0))
            # and once with the mandatory IEs only
            b = sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', kind, (o, om), aper.Ctx(k=0, full=False, vals=vv(o, 0, True)))
            frames.append(sctp.frame(b, kind != 0))
    # SIB types of the SIB messages in GNBCUConfigurationUpdate
    cu = [o for o in procs if o[0]['&procedureCode'] == 'id-gNBCUConfigurationUpdate'][0]
    for st in range(2, 31):
        v = dict(VALS, intfield={'sIBtype': st})
        if st == 13:
            v['byfield'] = {'sIBmessage': SIB13}
        frames.append(sctp.frame(sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', 0, cu,
                                        aper.Ctx(k=st % 3, vals=v)), False))
    # two PDUs with an RRC container on SRB 1 in one packet
    ul = [o for o in procs if o[0]['&procedureCode'] == 'id-ULRRCMessageTransfer'][0]
    two = [sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', 0, ul,
                  aper.Ctx(k=1, vals=dict(VALS, srb=1))) for i in range(2)]
    frames.append(multi(sctp, two))
    frames.extend(reproducers(sctp))
    write_pcap(os.path.join(OUT, 'f1ap-coverage.pcap'), frames)

    # Malformed capture: F1AP over TCP (needs Decode As, f1ap_tcp has no
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
    mal.append(sctp.frame(sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', 0, priv,
                                 aper.Ctx(vals={'private_global': True})), False))
    # sCS-Common (omitted from the main capture): its container is
    # decoded by dissect_nr_rrc_subCarrierSpacingCommon_PDU, which throws
    rc = [o for o in procs if o[0]['&procedureCode'] == 'id-GNBDUResourceConfiguration'][0]
    for k in range(2):
        v = dict(VALS, omit=(), byfield={'sCS-Common': b'\x00'})
        mal.append(sctp.frame(sp.pdu('F1AP-PDU', 'F1AP-PDU-Descriptions', 0, rc,
                                     aper.Ctx(k=k, vals=v)), False))
    for b in pdus[:len(pdus):7]:
        mal.append(sctp.frame(b[:len(b) // 2], False))
    for i, b in enumerate(pdus[1:len(pdus):11]):
        x = bytearray(b)
        x[len(x) // 3] ^= 0xff
        mal.append(sctp.frame(bytes(x), True))
    write_pcap(os.path.join(OUT, 'f1ap-coverage-malformed.pcap'), mal)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()

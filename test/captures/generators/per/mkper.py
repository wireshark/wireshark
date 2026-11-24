#!/usr/bin/env python3
# Generates test/captures/per_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for the PER runtime (packet-per.c), made through the
PER based dissectors that default transports and Exported PDU reach:
H.245 (aligned PER), LTE RRC and ULP/SUPL (unaligned PER), and the TETRA
reproducer.  Values are random but seeded; the PDUs are encoded with
asn1tools (needs: pip install asn1tools) from the ASN.1 in the Wireshark
tree.  Usage: mkper.py <outdir> [<wireshark source dir>]"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import glob
import struct
import sys
from randgen import Gen
from s8net import csum
from nperlib import W

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
A = (sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR)) + '/epan/dissectors/asn1/'


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload


def tcp_frame(sport, dport, payload, seq=1):
    sip = bytes([192, 0, 2, 1]); dip = bytes([192, 0, 2, 2])
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    ph = sip + dip + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, sip, dip)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp



# ---- NGAP over SCTP 38412: a handful of hand-encoded aligned PER PDUs that
# reach the open type, PrintableString and 40-bit integer code of packet-per.c
def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp_frame(payload, tsn, ppid=60, up=True):
    sport, dport = (40000, 38412) if up else (38412, 40000)
    pad = (-len(payload)) % 4
    chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, 0, ppid) + payload + b'\0' * pad
    vtag = 0x01020304 if up else 0x05060708
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + chunk)
    sctp = struct.pack('>HHI', sport, dport, vtag) + struct.pack('<I', c) + chunk
    src, dst = (bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) if up else (bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1]))
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), 1, 0, 64, 132, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + sctp


def ngap_ie(i, crit, val):
    return W().cint(i, 0, 65535).cint(crit, 0, 2).length(len(val)).raw(val).data()


def ngap_pdu(kind, proc, ies, crit=1):
    w = W().bit(0).cint(len(ies), 0, 65535)
    for x in ies:
        w.raw(x)
    val = w.data()
    return W().bit(0).cint(kind, 0, 2).cint(proc, 0, 255).cint(crit, 0, 2).length(len(val)).raw(val).data()


def printable(s):
    return W().bit(0).cint(len(s), 1, 150).octets(s.encode()).data()


def pcapng(fname, frames):
    """frames: list of (linktype, bytes); interfaces created on demand."""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for i, (lt, data) in enumerate(frames):
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 65535))
        out += blk(6, struct.pack('<IIIII', ifs[lt], 0, 1000000 + i * 1000, len(data), len(data)) + data)
    open(fname, 'wb').write(out)


def main():
    frames = []
    tags = []
    malformed = []

    def add(tag, lt, data):
        if tag in bad:
            malformed.append((lt, data))
        else:
            frames.append((lt, data))
            tags.append(tag)
    bad = set(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bad.txt')).read().split()) \
        if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bad.txt')) else set()
    # H.245: aligned PER, Exported PDU
    g = Gen([A + 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn'], 'per', 11)
    for i in range(160):
        v, b = g.pdu('MultimediaSystemControlMessage')
        add('h245-%d' % i, 252, exp_pdu('h245dg', b))
    # Fragmented OCTET STRINGs (X.691 10.9.3.8): 16K multiples and a tail
    gh = Gen([A + 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn'], 'per', 12)
    for i, n in enumerate((16384, 16384 * 2, 16385, 16384 * 3 + 7, 65535, 70000)):
        b = gh.spec.encode('MultimediaSystemControlMessage', ('indication', ('nonStandard', {
            'nonStandardData': {'nonStandardIdentifier': ('object', '1.2.3.4'), 'data': bytes(n)}})))
        add('h245-frag-%d' % i, 252, exp_pdu('h245dg', b))
    # LTE RRC: unaligned PER
    g = Gen(sorted(glob.glob(A + 'lte-rrc/*.asn')), 'uper', 21)
    for ch, top, n in (('dl_dcch', 'DL-DCCH-Message', 60), ('ul_dcch', 'UL-DCCH-Message', 60),
                       ('bcch_dl_sch', 'BCCH-DL-SCH-Message', 40), ('pcch', 'PCCH-Message', 10),
                       ('mcch', 'MCCH-Message', 10), ('dl_ccch', 'DL-CCCH-Message', 10),
                       ('ul_ccch', 'UL-CCCH-Message', 10)):
        for i in range(n):
            try:
                v, b = g.pdu(top)
            except Exception:
                continue
            add('rrc-%s-%d' % (ch, i), 252, exp_pdu('lte_rrc.' + ch, b))
    # NR RRC, 3G RRC, LPP, T.124: unaligned PER
    for dirn, pfx, seed, chans in (
            ('nr-rrc', 'nr-rrc.', 41, (('dl.dcch', 'DL-DCCH-Message', 40), ('ul.dcch', 'UL-DCCH-Message', 40),
                                       ('bcch.dl.sch', 'BCCH-DL-SCH-Message', 20), ('pcch', 'PCCH-Message', 5),
                                       ('dl.ccch', 'DL-CCCH-Message', 5), ('ul.ccch', 'UL-CCCH-Message', 5))),
            ('rrc', 'rrc.', 51, (('dl.dcch', 'DL-DCCH-Message', 40), ('ul.dcch', 'UL-DCCH-Message', 40),
                                 ('dl.ccch', 'DL-CCCH-Message', 10), ('ul.ccch', 'UL-CCCH-Message', 10),
                                 ('pcch', 'PCCH-Message', 5), ('bcch.fach', 'BCCH-FACH-Message', 10),
                                 ('mcch', 'MCCH-Message', 10), ('dl.shcch', 'DL-SHCCH-Message', 5))),
            ('lpp', 'lpp', 61, ((None, 'LPP-Message', 40),)),
            ('t124', 't124', 71, ((None, 'ConnectGCCPDU', 30),))):
        g = Gen(sorted(glob.glob(A + dirn + '/*.asn')), 'per' if dirn == 't124' else 'uper', seed)
        for ch, top, n in chans:
            for i in range(n):
                try:
                    v, b = g.pdu(top)
                except Exception:
                    continue
                name = (pfx + ch) if ch else pfx
                if dirn == 't124':
                    b = g.spec.encode('ConnectData', {'t124Identifier': ('object', '0.0.20.124.0.1'), 'connectPDU': b})
                add('%s-%s-%d' % (dirn, ch, i), 252, exp_pdu(name, b))
    # ULP (SUPL) over TCP 7275
    g = Gen(sorted(glob.glob(A + 'ulp/*.asn')), 'uper', 31)
    seq = 1
    for i in range(60):
        v, b = g.pdu('ULP-PDU')
        v['length'] = len(b)
        b = g.spec.encode('ULP-PDU', v)
        add('ulp-%d' % i, 1, tcp_frame(40000 + i, 7275, b))
    # NGAP over SCTP
    PLMN = bytes([0x00, 0xf1, 0x10])
    def ng(i, pdu, up=True):
        add('ngap-%d' % i, 1, sctp_frame(pdu, i + 1, up=up))
    ng(0, ngap_pdu(0, 0, [ngap_ie(1, 0, printable('amf-one'))]), up=False)
    ng(1, ngap_pdu(0, 35, [ngap_ie(82, 1, printable('gnb-one'))]))
    ng(2, ngap_pdu(0, 35, [ngap_ie(82, 1, printable('x' * 150))]))
    cause = W().choice(0, 6).enum(3, 45, True).data()
    ng(3, ngap_pdu(0, 4, [ngap_ie(10, 1, W().cint(0x123456789a, 0, 2**40 - 1).data()),
                          ngap_ie(85, 1, W().cint(7, 0, 2**32 - 1).data()), ngap_ie(15, 1, cause)]))
    ng(4, ngap_pdu(0, 4, [ngap_ie(15, 1, W().choice(2, 6).enum(1, 4, True, 9).data())]), up=False)
    ng(5, ngap_pdu(1, 0, [ngap_ie(1, 0, printable('a'))]), up=False)
    nas = W().length(5).raw(b'\x7e\x00\x41\x00\x01').data()
    ng(6, ngap_pdu(0, 46, [ngap_ie(10, 0, W().cint(2**40 - 1, 0, 2**40 - 1).data()),
                           ngap_ie(85, 0, W().cint(2**32 - 1, 0, 2**32 - 1).data()), ngap_ie(38, 0, nas)]))
    # TETRA 64-bit integer reproducer
    import per_integer_uint64
    add('tetra-0', 1, per_integer_uint64.FRAME)
    # Malformed variants: truncated and bit-flipped copies of the Exported
    # PDU frames (only used for the malformed capture)
    import random
    rng = random.Random(99)
    for k, (lt, data) in enumerate(list(frames)):
        if lt != 252 or len(data) > 2000 or k % 2:
            continue
        hdr = 4 + struct.unpack('!H', data[2:4])[0] + 4
        body = data[hdr:]
        if len(body) < 3:
            continue
        cut = rng.randrange(1, len(body))
        malformed.append((lt, data[:hdr + cut]))
        m = bytearray(data)
        for _ in range(2):
            m[hdr + rng.randrange(len(body))] ^= 1 << rng.randrange(8)
        malformed.append((lt, bytes(m)))
        m = bytearray(data)
        m[hdr + rng.randrange(len(body))] = 0xff
        malformed.append((lt, bytes(m)))
    pcapng(os.path.join(OUT, 'per-coverage.pcapng'), frames)
    open(os.path.join(OUT, 'frames.txt'), 'w').write(''.join('%d %s\n' % (i + 1, t) for i, t in enumerate(tags)))
    pcapng(os.path.join(OUT, 'per-coverage-malformed.pcapng'), malformed)


if __name__ == '__main__':
    main()

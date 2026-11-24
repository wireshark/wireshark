#!/usr/bin/env python3
# Generates test/captures/e212_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the E.212 helper dissector
(packet-e212.c: IMSIs and MCC/MNC pairs).

E.212 has no transport of its own; other dissectors call it for the
IMSIs and PLMN identities they carry. This capture reaches it the way
real traffic does:

  - GTPv2-C over UDP port 2123: IMSIs in BCD (dissect_e212_imsi(), MCC
    and MNC in the address), User Location Info with CGI, SAI, RAI, TAI,
    ECGI and LAI, Serving Network and PLMN ID (the one big endian MNC
    user), with 2 and 3 digit MNCs, non-decimal digits, the all-ones
    PLMN and IMSIs too short or too long;
  - Diameter over TCP port 3868: Subscription-Id-Data of type
    END_USER_IMSI and the S6a User-Name (UTF-8 IMSIs,
    dissect_e212_utf8_imsi()), 3GPP-IMSI-MCC-MNC and
    3GPP-User-Location-Info with an NR cell global identity;
  - NAS-EPS and NAS-5GS messages in an Exported PDU interface (link type
    252, the way Wireshark exports them from S1AP and NGAP): EPS mobile
    identities with an IMSI (the high nibble MCC/MNC layout) and a GUTI
    (GUMMEI), a 5G-GUTI (GUAMI) and a 5GS TAI.

The short IMSIs are the reproducer of "E.212: Do not read the MCC and
MNC past the IMSI". Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mke212.py <output directory>

Writes:
  e212-coverage.pcapng          interface 0 Ethernet (GTPv2-C, Diameter),
                                interface 1 Exported PDU (NAS)
  e212-coverage-malformed.pcap  Diameter 3GPP-IMSI-MCC-MNC of 3
                                characters (diameter_3gpp reads 5)
"""

import os
import struct
import sys

from pcaplib import TcpFlow, eth_ipv4_udp, write_pcap, write_pcapng  # noqa: E402

VENDOR_3GPP = 10415


def bcd(digits):
    """BCD with swapped nibbles and a 0xf filler; 'a'-'f' are nibbles."""
    n = [int(c, 16) for c in digits]
    if len(n) % 2:
        n.append(0xf)
    return bytes(n[i] | (n[i + 1] << 4) for i in range(0, len(n), 2))


def plmn(mcc, mnc, big_endian_mnc=False):
    """3GPP TS 24.008 PLMN identity. mcc, mnc: digit strings ('a'-'f'
    allowed). A 2 digit MNC gets the 0xf filler."""
    m = [int(c, 16) for c in mcc]
    n = [int(c, 16) for c in mnc]
    if len(n) == 2:
        n3 = 0xf
        n1, n2 = n
    elif big_endian_mnc:
        n3, n1, n2 = n          # MNC digit 1 in the high nibble of octet 2
    else:
        n1, n2, n3 = n
    return bytes([m[1] << 4 | m[0], n3 << 4 | m[2], n2 << 4 | n1])


# ---------------------------------------------------------------- GTPv2

def gtpv2_ie(t, value, inst=0):
    return struct.pack('>BHB', t, len(value), inst) + value


def gtpv2(msg_type, ies, seq, teid=0x11223344):
    body = struct.pack('>I', teid) + seq.to_bytes(3, 'big') + b'\0' + ies
    return struct.pack('>BBH', 0x48, msg_type, len(body)) + body


def uli(p_cgi, p_sai, p_rai, p_tai, p_ecgi, p_lai):
    v = bytes([0x3f])
    v += p_cgi + struct.pack('>HH', 0x1001, 0x2002)
    v += p_sai + struct.pack('>HH', 0x1001, 0x3003)
    v += p_rai + struct.pack('>HH', 0x1001, 0x0044)
    v += p_tai + struct.pack('>H', 0x5005)
    v += p_ecgi + struct.pack('>I', 0x0123456)
    v += p_lai + struct.pack('>H', 0x1001)
    return v


# (IMSI digits or raw bytes, PLMN parts)
GTP_CASES = [
    # 2 digit MNC in the operator list (Germany 262 01)
    ('262011234567890', plmn('262', '01')),
    # 3 digit MNC (USA 310 410)
    ('310410123456789', plmn('310', '410')),
    # 3 digit MNC with a 2 digit prefix in the list: shown as 2 digits
    ('234150123456789', plmn('234', '150')),
    # unknown MCC/MNC, 5 digit IMSI (no MSIN), filler as third MNC digit
    ('99899', plmn('998', '99')),
    # non-decimal digits in MCC and MNC
    ('2a2b1123456789', plmn('2a2', 'b1')),
    ('2621c1234567890', plmn('262', '1c0')),
    # non-decimal first or third MCC digit, second MNC digit, third MNC
    # digit (IMSI: MNC digits 1 and 3)
    ('a62011234567890', plmn('a62', '01')),
    ('26a011234567890', plmn('26a', '0a')),
    ('262a11234567890', plmn('262', '01a')),
    ('9989a1234567890', plmn('998', '99a')),
]


def gtpv2_frames():
    F = []
    seq = 1
    for imsi, p in GTP_CASES:
        ies = gtpv2_ie(1, bcd(imsi))
        ies += gtpv2_ie(86, uli(p, p, p, p, p, p))
        ies += gtpv2_ie(83, p)
        ies += gtpv2_ie(120, p)
        F.append(eth_ipv4_udp(gtpv2(32, ies, seq), 2123, 2123, '192.0.2.1', '192.0.2.2'))
        seq += 1
    # PLMN ID IE (big endian MNC) with a 3 digit MNC, and the all-ones PLMN
    ies = gtpv2_ie(120, plmn('310', '410', True)) + gtpv2_ie(120, b'\xff\xff\xff', 1)
    ies += gtpv2_ie(83, b'\xff\xff\xff')
    ies += gtpv2_ie(1, b'\xff' * 8)
    F.append(eth_ipv4_udp(gtpv2(32, ies, seq), 2123, 2123, '192.0.2.1', '192.0.2.2'))
    seq += 1
    # IMSIs too short for an MCC and MNC (the reproducer: 1 and 2 octets
    # at the end of the message), a 4 digit IMSI, an IMSI of 16 digits
    for imsi in ('26', '2620', '2620112345678901'):
        F.append(eth_ipv4_udp(gtpv2(32, gtpv2_ie(1, bcd(imsi)), seq), 2123, 2123,
                              '192.0.2.1', '192.0.2.2'))
        seq += 1
    return F


# ------------------------------------------------------------- Diameter

def avp(code, data, flags=0x40, vendor=None):
    if vendor is not None:
        flags |= 0x80
    hdr = 12 if vendor is not None else 8
    ln = hdr + len(data)
    out = struct.pack('>IB', code, flags) + ln.to_bytes(3, 'big')
    if vendor is not None:
        out += struct.pack('>I', vendor)
    return out + data + b'\0' * ((4 - ln % 4) % 4)


def diameter(code, app, avps, hbh, request=True):
    ln = 20 + len(avps)
    return (bytes([1]) + ln.to_bytes(3, 'big') + bytes([0x80 if request else 0])
            + code.to_bytes(3, 'big') + struct.pack('>III', app, hbh, hbh) + avps)


def base_avps(session):
    return avp(263, session) + avp(264, b'mme.example.org') + avp(296, b'example.org')


def sub_imsi(data):
    return avp(443, avp(450, struct.pack('>I', 1)) + avp(444, data))


UTF8_IMSIS = [
    b'262011234567890',     # 2 digit MNC in the list
    b'310410123456789',     # 3 digit MNC
    b'00101',               # exactly 5 digits: 2 digit MNC
    b'99899123',            # unknown, 3 digit MNC
    b'2a2011234567890',     # non-decimal MCC
    b'262a11234567890',     # non-decimal MNC
    b'3104a0123456789',     # non-decimal third MNC digit
    b'2620',                # too short for MCC and MNC (the reproducer)
    b'26',
    b'2620112345678901',    # 16 digits
    b'26201#234567890',     # a character below '0'
]


def diameter_frames():
    fl = TcpFlow(40000, 3868, '192.0.2.10', '192.0.2.20')
    F = fl.handshake()
    # 1: CCR with IMSI Subscription-Ids
    m = diameter(272, 4, base_avps(b'cc;1') + b''.join(sub_imsi(i) for i in UTF8_IMSIS), 1)
    F.append(fl.send(m))
    # 2: S6a Update-Location-Request: User-Name is an IMSI, Visited-PLMN-Id
    m = diameter(316, 16777251, base_avps(b's6a;1') + avp(1, b'262011234567890')
                 + avp(1407, plmn('262', '01'), 0xc0, VENDOR_3GPP), 2)
    F.append(fl.send(m))
    # 3-4: S6a requests with short and non-decimal User-Names
    F.append(fl.send(diameter(316, 16777251, base_avps(b's6a;2') + avp(1, b'2620'), 3)))
    F.append(fl.send(diameter(316, 16777251, base_avps(b's6a;3') + avp(1, b'26201'), 4)))
    # 5: Gx CCR with 3GPP-IMSI-MCC-MNC (2 and 3 digit MNC, non-decimal),
    #    3GPP-SGSN-MCC-MNC and 3GPP-User-Location-Info with an NCGI
    ncgi = bytes([135]) + plmn('001', '01') + struct.pack('>Q', 0x0123456789)[3:]
    m = diameter(272, 16777238, base_avps(b'gx;1')
                 + avp(8, b'26201', 0x80, VENDOR_3GPP)
                 + avp(8, b'310410', 0x80, VENDOR_3GPP)
                 + avp(8, b'2a2b1', 0x80, VENDOR_3GPP)
                 + avp(18, b'99899', 0x80, VENDOR_3GPP)
                 + avp(22, ncgi, 0x80, VENDOR_3GPP), 5)
    F.append(fl.send(m))
    return F


# ------------------------------------------------------------------ NAS

def exp_tag(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad


def exported(name, payload):
    return exp_tag(12, name.encode()) + struct.pack('>HH', 0, 0) + payload


def imsi_mid(digits, type_id=1):
    """Mobile identity with the IMSI digits after the type nibble."""
    odd = len(digits) % 2
    n = [int(digits[0], 16) << 4 | (0x08 if odd else 0) | type_id]
    rest = digits[1:]
    if len(rest) % 2:
        rest += 'f'
    return bytes(n) + bytes(int(rest[i], 16) | int(rest[i + 1], 16) << 4
                            for i in range(0, len(rest), 2))


def nas_eps_detach(mid):
    return bytes([0x07, 0x45, 0x71, len(mid)]) + mid


def nas_eps_identity_resp(mid):
    return bytes([0x07, 0x56, len(mid)]) + mid


def nas_frames():
    F = []
    # EPS mobile identity IMSI, odd number of digits (15), 2 digit MNC
    F.append(exported('nas-eps_plain', nas_eps_detach(imsi_mid('262011234567890'))))
    # IMSI with an even number of digits (14) and a 3 digit MNC
    F.append(exported('nas-eps_plain', nas_eps_detach(imsi_mid('31041012345678'))))
    # Identity responses (mobile identity of TS 24.008): 5 digit IMSI,
    # unknown MCC/MNC, no octet for a third MNC digit; 4 digit IMSI, too
    # short for MCC and MNC (the reproducer); 15 digits
    F.append(exported('nas-eps_plain', nas_eps_identity_resp(imsi_mid('99899'))))
    F.append(exported('nas-eps_plain', nas_eps_identity_resp(imsi_mid('2620'))))
    F.append(exported('nas-eps_plain', nas_eps_identity_resp(imsi_mid('310410123456789'))))
    # unknown MCC/MNC with a filler where the third MNC digit would be
    F.append(exported('nas-eps_plain', nas_eps_identity_resp(imsi_mid('99899f12'))))
    # GUTI: GUMMEI with a 3 digit MNC
    guti = bytes([0xf6]) + plmn('310', '410') + struct.pack('>HBI', 0x8001, 0x02, 0xc0ffee01)
    F.append(exported('nas-eps_plain', nas_eps_detach(guti)))
    # NAS-5GS Registration request: 5G-GUTI (GUAMI) and the last visited
    # registered TAI (5GS TAI)
    guti5 = bytes([0xf2]) + plmn('001', '01') + bytes([0x01, 0x00, 0x41]) + struct.pack('>I', 0x12345678)
    reg = bytes([0x7e, 0x00, 0x41, 0x79]) + struct.pack('>H', len(guti5)) + guti5
    reg += bytes([0x52]) + plmn('262', '01') + b'\x00\x00\x07'
    F.append(exported('nas-5gs', reg))
    return F


def malformed_frames():
    fl = TcpFlow(40010, 3868, '192.0.2.10', '192.0.2.20')
    m = diameter(272, 16777238, base_avps(b'gx;9') + avp(8, b'262', 0x80, VENDOR_3GPP), 9)
    return [fl.send(m)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [(0, f) for f in gtpv2_frames() + diameter_frames()]
    frames += [(1, f) for f in nas_frames()]
    write_pcapng(os.path.join(out, 'e212-coverage.pcapng'), [1, 252], frames)
    write_pcap(os.path.join(out, 'e212-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

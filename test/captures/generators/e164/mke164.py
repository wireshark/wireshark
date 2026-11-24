#!/usr/bin/env python3
# Generates test/captures/e164_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the E.164 helper dissector
(packet-e164.c).

E.164 has no transport of its own: other dissectors call it for the
numbers they carry. This capture reaches it the way real traffic does:

  - Diameter over TCP port 3868: Subscription-Id-Data with
    Subscription-Id-Type END_USER_E164 (UTF-8 digits) and the 3GPP
    MSISDN and GMLC-Number AVPs (BCD digits, dissect_e164_msisdn() and
    dissect_e164_isdn()), for a country code of every length and the
    special codes 881, 882 and 883 (with the 4 digit 883 510 codes),
    numbers with non-decimal digits and numbers shorter than their
    country code (the reproducer of "E.164: Do not read the country code
    past the number");
  - SIP over UDP port 5060: request and To/From URIs with "+" numbers
    (UTF-8), and an ISUP IAM body (application/ISUP) whose called and
    calling party numbers (dissect_e164_number()) and generic number
    (dissect_e164_cc()) are international ISDN numbers;
  - RTSP over TCP port 554: an X-Vig-Msisdn header (dissect_e164_number()
    for a calling party number that is not international).

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mke164.py <output directory>

Writes:
  e164-coverage.pcap            the frames above
  e164-coverage-malformed.pcap  a MSISDN AVP and an E.164
                                Subscription-Id-Data AVP of zero length
"""

import os
import struct
import sys

from pcaplib import TcpFlow, eth_ipv4_udp, write_pcap  # noqa: E402

VENDOR_3GPP = 10415


def avp(code, data, flags=0x40, vendor=None):
    if vendor is not None:
        flags |= 0x80
        hdr_len = 12
    else:
        hdr_len = 8
    ln = hdr_len + len(data)
    out = struct.pack('>IB', code, flags) + ln.to_bytes(3, 'big')
    if vendor is not None:
        out += struct.pack('>I', vendor)
    return out + data + b'\0' * ((4 - ln % 4) % 4)


def diameter(code, app, avps, hbh=0, request=True):
    ln = 20 + len(avps)
    return (bytes([1]) + ln.to_bytes(3, 'big') + bytes([0x80 if request else 0x00])
            + code.to_bytes(3, 'big') + struct.pack('>III', app, hbh, hbh) + avps)


def base_avps(session, client=True):
    host = b'client.example.org' if client else b'server.example.org'
    return (avp(263, session) + avp(264, host) + avp(296, b'example.org'))


def sub_id(data, stype=0):
    return avp(443, avp(450, struct.pack('>I', stype)) + avp(444, data))


def bcd(digits):
    """BCD with swapped nibbles and a 0xf filler; 'a'-'e' give nibbles
    0xa-0xe."""
    n = [int(c, 16) for c in digits]
    if len(n) % 2:
        n.append(0xf)
    return bytes(n[i] | (n[i + 1] << 4) for i in range(0, len(n), 2))


# Numbers whose first digits take every branch of the country code
# length table, and the special codes
NUMBERS = [
    '0123456', '15551234567', '201234567', '271234567', '2121234567',
    '301234567', '311234567', '321234567', '331234567', '341234567',
    '361234567', '391234567', '3511234567', '4201234567', '441234567',
    '5021234567', '5901234567', '511234567', '6711234567', '6811234567',
    '6911234567', '611234567', '71234567890', '811234567', '821234567',
    '841234567', '861234567', '8521234567', '881612345678',
    '882161234567', '88312012345', '8835101234567', '901234567',
    '911234567', '921234567', '931234567', '941234567', '951234567',
    '981234567', '9711234567', '961234567',
]
# Non-decimal digits in the country code or the identification code
NONDEC_UTF8 = [':1234567', '4:1234567', '881:12345', '882:1234567',
               '883:1234567', '883510:12345']
NONDEC_BCD = ['a1234567', '4a1234567', '881a2345', '882a234567',
              '883a234567', '883510a2345']
# Numbers shorter than their country code or identification code
SHORT = ['8', '88', '882', '881', '883', '8835', '88351', '4471']


def diameter_frames():
    fl = TcpFlow(40000, 3868, '192.0.2.1', '192.0.2.2')
    F = fl.handshake()
    hbh = 0x1000
    msgs = []
    # 1: CCR with E.164 Subscription-Ids in UTF-8, every country code form
    msgs.append(diameter(272, 4, base_avps(b'cc;1') + b''.join(
        sub_id(n.encode()) for n in NUMBERS)))
    # 2: CCR with non-decimal and short numbers (the reproducer)
    msgs.append(diameter(272, 4, base_avps(b'cc;2') + b''.join(
        sub_id(n.encode()) for n in NONDEC_UTF8 + SHORT)))
    # 3: S6a ULA-style answer with the 3GPP MSISDN (BCD) for every form
    msgs.append(diameter(316, 16777251, base_avps(b's6a;1', False) + b''.join(
        avp(701, bcd(n), 0xc0, VENDOR_3GPP) for n in NUMBERS), request=False))
    # 4: MSISDN with non-decimal and short numbers, GMLC-Number (ISDN)
    msgs.append(diameter(316, 16777251, base_avps(b's6a;2', False) + b''.join(
        avp(701, bcd(n), 0xc0, VENDOR_3GPP) for n in NONDEC_BCD + SHORT)
        + avp(1474, bcd('447700900123'), 0xc0, VENDOR_3GPP)
        + avp(1474, bcd('88216123'), 0xc0, VENDOR_3GPP), request=False))
    for i, m in enumerate(msgs):
        m = m[:12] + struct.pack('>II', hbh + i, hbh + i) + m[20:]
        F.append(fl.send(m, reverse=(i >= 2)))
    return F


def isup_number(nai, npi_byte, digits):
    odd = 0x80 if len(digits) % 2 else 0
    return bytes([odd | nai, npi_byte]) + bcd(digits)


def isup_iam():
    called = isup_number(0x04, 0x10, '4420794601234')
    msg = bytes([0x01, 0x00, 0x20, 0x01, 0x0a, 0x00])
    # pointers: called party number, optional part
    msg += bytes([2, 1 + 1 + len(called)])
    msg += bytes([len(called)]) + called
    calling = isup_number(0x04, 0x13, '33123456789')
    msg += bytes([0x0a, len(calling)]) + calling
    generic = bytes([0x06]) + isup_number(0x04, 0x13, '8835101234')
    msg += bytes([0xc0, len(generic)]) + generic
    return msg + b'\x00'


def sip_frames():
    isup = isup_iam()
    hdrs = ('INVITE sip:+442079460123@example.org SIP/2.0\r\n'
            'Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-e164-1\r\n'
            'Max-Forwards: 70\r\n'
            'From: <tel:+33123456789>;tag=1\r\n'
            'To: <sip:+442079460123@example.org;user=phone>\r\n'
            'Call-ID: e164-1@192.0.2.10\r\n'
            'CSeq: 1 INVITE\r\n'
            'Contact: <sip:+33123456789@192.0.2.10>\r\n'
            'Content-Type: application/ISUP;version=itu-t92+;base=itu-t92+\r\n'
            'Content-Length: %d\r\n\r\n' % len(isup))
    inv = hdrs.encode() + isup
    resp = ('SIP/2.0 100 Trying\r\n'
            'Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-e164-1\r\n'
            'From: <tel:+33123456789>;tag=1\r\n'
            'To: <sip:+442079460123@example.org;user=phone>\r\n'
            'Call-ID: e164-1@192.0.2.10\r\n'
            'CSeq: 1 INVITE\r\n'
            'Content-Length: 0\r\n\r\n').encode()
    return [eth_ipv4_udp(inv, 5060, 5060, '192.0.2.10', '192.0.2.20'),
            eth_ipv4_udp(resp, 5060, 5060, '192.0.2.20', '192.0.2.10')]


def rtsp_frames():
    fl = TcpFlow(40001, 554, '192.0.2.30', '192.0.2.40')
    F = fl.handshake()
    F.append(fl.send(b'OPTIONS rtsp://192.0.2.40/stream RTSP/1.0\r\n'
                     b'CSeq: 1\r\n'
                     b'X-Vig-Msisdn: 447700900123\r\n\r\n'))
    F.append(fl.send(b'RTSP/1.0 200 OK\r\nCSeq: 1\r\n'
                     b'Public: DESCRIBE, SETUP, PLAY\r\n\r\n', reverse=True))
    return F


def malformed_frames():
    fl = TcpFlow(40010, 3868, '192.0.2.1', '192.0.2.2')
    F = []
    # MSISDN of zero length: no digits
    F.append(fl.send(diameter(316, 16777251, base_avps(b's6a;9', False)
                              + avp(701, b'', 0xc0, VENDOR_3GPP), request=False)))
    # Subscription-Id-Data of zero length (E.164 number without digits)
    m = diameter(272, 4, base_avps(b'cc;9') + sub_id(b''))
    F.append(fl.send(m))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'e164-coverage.pcap'),
               diameter_frames() + sip_frames() + rtsp_frames())
    write_pcap(os.path.join(out, 'e164-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

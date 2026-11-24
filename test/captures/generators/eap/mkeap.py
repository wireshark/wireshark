#!/usr/bin/env python3
# Generates test/captures/eap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EAP dissector
(packet-eap.c).

EAP has no port of its own; it is carried in EAPOL (Ethernet type
0x888E) between a supplicant and an authenticator and in RADIUS
EAP-Message attributes (UDP 1812) between the authenticator and the
server. This capture uses both, the way real authentications do. It
holds every EAP code and the message formats of every method the
dissector knows: Identity (with the 3GPP NAI forms and the encrypted
IMSI form), Notification, Nak, MD5-Challenge, GTC, LEAP (its four step
state machine), MS-CHAPv2, SIM, AKA and AKA', the TLS based methods
(TLS, TTLS, PEAP, FAST, TEAP: flags, start, fragmentation and
reassembly, TEAP outer TLVs, retransmissions), PAX, PSK, SAKE, GPSK,
IKEv2, MS-Authentication-TLV and the Expanded Type (with WPS).

The TLS based methods carry a plaintext TLS ClientHello only; the
tunnelled (encrypted) content and every key or MAC field are made-up
octets: nothing is encrypted, derived or verified. Every packet is built
from scratch with struct; no captured traffic is used. The frames
include the reproducers of "EAP: Fix a zero-width AT_RES assert, the
TEAP recursion and lengths" (AKA AT_RES of length 0, SAKE and MS-Auth
TLV attribute lists, a LEAP name longer than 255 octets, an MD5 value
size larger than the data, nested TEAP EAP-Payload TLVs).

Usage: mkeap.py <output directory>

Writes:
  eap-coverage.pcap            the frames above
  eap-coverage-malformed.pcap  bad EAP lengths, attributes cut short,
                               an EAP-TLS reassembly with a missing
                               fragment, TEAP nesting past the depth
                               limit
"""

import os
import struct
import sys

from pcaplib import eth, eth_ipv4_udp, write_pcap  # noqa: E402

SUPP = bytes.fromhex('020000000011')
AUTH = bytes.fromhex('020000000022')
PAE = bytes.fromhex('0180c2000003')

REQ, RESP, SUCCESS, FAILURE, INITIATE, FINISH = 1, 2, 3, 4, 5, 6


class Ids:
    """EAP identifiers, so that no request or response repeats the
    identifier of the previous one (that would be a retransmission)."""

    def __init__(self):
        self.n = 0

    def next(self):
        self.n = (self.n + 1) & 0xff
        return self.n


IDS = Ids()


def eap(code, body=b'', ident=None, length=None):
    if ident is None:
        ident = IDS.next()
    if length is None:
        length = 4 + len(body)
    return struct.pack('>BBH', code, ident, length) + body


def eapol_frame(e, code=None):
    """EAPOL-EAP frame; requests go from the authenticator to the
    supplicant, the rest from the supplicant to the PAE group."""
    if code is None:
        code = e[0]
    if code in (REQ, SUCCESS, FAILURE, INITIATE):
        src, dst = AUTH, SUPP
    else:
        src, dst = SUPP, PAE
    fr = eth(struct.pack('>BBH', 2, 0, len(e)) + e, 0x888E, src, dst)
    if len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


def req(t, body=b''):
    return eapol_frame(eap(REQ, bytes([t]) + body))


def resp(t, body=b''):
    return eapol_frame(eap(RESP, bytes([t]) + body))


def identity_req():
    return req(1)


# ------------------------------------------------------------- identity

REALM = 'wlan.mnc001.mcc001.3gppnetwork.org'
IDENTITIES = [
    b'0001011234567890@' + REALM.encode(),          # AKA permanent
    b'1262011234567890@wlan.mnc001.mcc262.3gppnetwork.org',  # SIM, 2 digit MNC
    b'6310410123456789@wlan.mnc410.mcc310.3gppnetwork.org',  # AKA', 3 digit
    b'2pseudonym-aka@' + REALM.encode(),
    b'3pseudonym-sim@' + REALM.encode(),
    b'7pseudonym-akap@' + REALM.encode(),
    b'4reauth-aka@' + REALM.encode(),
    b'5reauth-sim@' + REALM.encode(),
    b'8reauth-akap@' + REALM.encode(),
    b'Cconservative@' + REALM.encode(),
    b'anonymous@' + REALM.encode(),
    b'Gunknownprefix@' + REALM.encode(),            # invalid prefix
    b'0001011234567890@epc.mnc001.mcc001.3gppnetwork.org',
    b'1001011234567890@gan.mnc001.mcc001.3gppnetwork.org',
    b'user@nai.5gc.mnc001.mcc001.3gppnetwork.org',  # 3GPP realm, no prefix
    b'0001011234567890@wlan.mncXX.mcc001.3gppnetwork.org',  # MNC not a number
    b'user@example.org',                            # not a 3GPP realm
    b'user@a.mnc001.mcc001.example.org',            # 5 labels, not 3GPP
    b'user',                                        # no realm
    b'a@b@c',                                       # two @
    # encrypted IMSI: with a 3GPP realm, without a realm, a Realm= without
    # '@', a realm that is not 3GPP, no certificate serial number
    b'\x00QUJDREVGR0hJSktMTU5PUA==,CertificateSerialNumber=1234,Realm=@' + REALM.encode(),
    b'\x00QUJDREVGR0hJSktMTU5PUA==,CertificateSerialNumber=1234',
    b'\x00QUJDREVGR0hJSktMTU5PUA==,CertificateSerialNumber=1234,Realm=example.org',
    b'\x00QUJDREVGR0hJSktMTU5PUA==,CertificateSerialNumber=1234,Realm=@example.org',
    b'\x00QUJDREVGR0hJSktMTU5PUA==,OtherField=1',
    b'\x00\x01\x02',                                # encrypted, not printable
    b'\x00',                                        # only the null octet
    'usér@example.org'.encode(),               # non-ASCII (UTF-8)
]


# ------------------------------------------------------------------ TLS

def tls_client_hello():
    """A plaintext TLS 1.2 ClientHello record (no extensions)."""
    hello = b'\x03\x03' + bytes(range(32)) + b'\x00' + b'\x00\x04\x00\x2f\x00\x35' + b'\x01\x00'
    hs = b'\x01' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs


def tls_body(t, flags, data=b'', tls_len=None, outer_len=None):
    b = bytes([t, flags])
    if tls_len is not None:
        b += struct.pack('>I', tls_len)
    if outer_len is not None:
        b += struct.pack('>I', outer_len)
    return b + data


def teap_tlv(t, value, mandatory=False):
    return struct.pack('>HH', t | (0x8000 if mandatory else 0), len(value)) + value


def tls_frames():
    F = []
    hello = tls_client_hello()
    # EAP-TLS: start, ClientHello in three fragments with ACKs, unfragmented
    F.append(identity_req())
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x20))))                   # Start
    a, b, c = hello[:20], hello[20:40], hello[40:]
    F.append(eapol_frame(eap(RESP, tls_body(13, 0xc0, a, len(hello)))))     # L M
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x00))))                     # ACK
    F.append(eapol_frame(eap(RESP, tls_body(13, 0x40, b))))                 # M
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x00))))                     # ACK
    F.append(eapol_frame(eap(RESP, tls_body(13, 0x00, c))))                 # last
    # a retransmission of the last fragment (same identifier): data
    last = eap(RESP, tls_body(13, 0x00, c), ident=IDS.n)
    F.append(eapol_frame(last))
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x80, hello, len(hello)))))  # L only
    F.append(eapol_frame(eap(SUCCESS)))
    # EAP-TTLS v0 start and ClientHello
    F.append(identity_req())
    F.append(eapol_frame(eap(REQ, tls_body(21, 0x20))))
    F.append(eapol_frame(eap(RESP, tls_body(21, 0x00, hello))))
    # PEAP v1 start and ClientHello
    F.append(identity_req())
    F.append(eapol_frame(eap(REQ, tls_body(25, 0x21))))
    F.append(eapol_frame(eap(RESP, tls_body(25, 0x01, hello))))
    # EAP-FAST v1 start with an Authority ID Data (type 4) and another type
    F.append(identity_req())
    aid = b'\x11' * 16
    F.append(eapol_frame(eap(REQ, tls_body(43, 0x21) + struct.pack('>HH', 4, len(aid)) + aid)))
    F.append(eapol_frame(eap(REQ, tls_body(43, 0x21) + struct.pack('>HH', 7, 2) + b'\x00\x01')))
    F.append(eapol_frame(eap(RESP, tls_body(43, 0x01, hello))))
    # TEAP v1: start with outer TLVs only (Authority-ID TLV), ClientHello
    # with outer TLVs after it, an outer TLV length larger than the data,
    # a fragmented message with outer TLVs, an EAP-Payload TLV that holds
    # an EAP-TEAP message with an EAP-Payload TLV (nested twice)
    F.append(identity_req())
    outer = teap_tlv(7, b'\x22' * 16)
    F.append(eapol_frame(eap(REQ, tls_body(55, 0x31, outer, outer_len=len(outer)))))
    outer2 = teap_tlv(7, b'\x33' * 8)
    F.append(eapol_frame(eap(RESP, tls_body(55, 0x11, hello + outer2, outer_len=len(outer2)))))
    F.append(eapol_frame(eap(REQ, tls_body(55, 0x11, outer2, outer_len=len(outer2) + 4))))
    data = hello + outer2
    F.append(eapol_frame(eap(RESP, tls_body(55, 0xd1, data[:30], len(data), len(outer2)))))
    F.append(eapol_frame(eap(REQ, tls_body(55, 0x01))))
    F.append(eapol_frame(eap(RESP, tls_body(55, 0x01, data[30:]))))
    inner = eap(SUCCESS, ident=0x77)
    for _ in range(2):
        tlv = teap_tlv(9, inner)
        inner = eap(REQ, tls_body(55, 0x11, tlv, outer_len=len(tlv)), ident=0x70)
    F.append(eapol_frame(eap(REQ, inner[4:])))
    F.append(eapol_frame(eap(FAILURE)))
    return F


# ---------------------------------------------------------- other methods

def sim_attr(t, value):
    """SIM/AKA attribute: value padded to a multiple of 4 with the header."""
    raw = bytes([t, 0]) + value
    raw += b'\0' * ((4 - len(raw) % 4) % 4)
    return bytes([t, len(raw) // 4]) + raw[2:]


def identity_attr(t, ident, extra_pad=0):
    v = struct.pack('>H', len(ident)) + ident
    raw = bytes([t, 0]) + v
    raw += b'\0' * ((4 - len(raw) % 4) % 4 + extra_pad)
    return bytes([t, len(raw) // 4]) + raw[2:]


def method_frames():
    F = []
    # Identity: every form
    F.append(identity_req())
    for ident in IDENTITIES:
        F.append(eapol_frame(eap(RESP, b'\x01' + ident)))
    # Identity request without data (length 5) and with a prompt
    F.append(req(1, b'Hello'))
    # Notification, Nak
    F.append(req(2, b'Password will expire'))
    F.append(resp(2))
    F.append(resp(3, b'\x15'))
    # MD5-Challenge: normal, extra data, value size larger than the data
    F.append(req(4, b'\x10' + b'\x42' * 16 + b'server'))
    F.append(resp(4, b'\x10' + b'\x43' * 16))
    F.append(req(4, b'\x20' + b'\x22' * 4))
    # GTC request and response
    F.append(req(6, b'Password: '))
    F.append(resp(6, b'secret-response'))
    # Initiate and Finish (RFC 5296), unknown code 7
    F.append(eapol_frame(eap(INITIATE, b'\x01\x00')))
    F.append(eapol_frame(eap(FINISH, b'\x01\x00')))
    F.append(eapol_frame(eap(7, b'\x00')))
    # Unknown method 5 (OTP), a request of only the type (length 5)
    F.append(req(5, b'otp-challenge'))
    F.append(req(13))

    # LEAP: the four steps after an Identity, then a fifth message and a
    # Failure (which resets the state); name longer than 255 octets
    F.append(identity_req())
    F.append(req(17, b'\x01\x00\x08' + b'\x01' * 8 + b'leapuser'))
    F.append(resp(17, b'\x01\x00\x18' + b'\x02' * 24 + b'leapuser'))
    F.append(req(17, b'\x01\x00\x08' + b'\x03' * 8 + b'leapuser'))
    F.append(resp(17, b'\x01\x00\x18' + b'\x04' * 24 + b'leapuser'))
    F.append(req(17, b'\x01\x00\x08' + b'\x05' * 8 + b'u' * 300))
    F.append(eapol_frame(eap(FAILURE)))
    F.append(req(17, b'\x01\x00\x08' + b'\x06' * 8))

    # MS-CHAPv2: challenge with name, response (49 octet value), response
    # with an other value size, success, failure, change password (other
    # opcode), length field not matching, only the opcode
    def mschap(op, msid, data):
        return bytes([op, msid]) + struct.pack('>H', 4 + len(data)) + data
    F.append(req(26, mschap(1, 1, b'\x10' + b'\x31' * 16 + b'server')))
    F.append(resp(26, mschap(2, 1, b'\x31' + b'\x32' * 16 + b'\0' * 8 + b'\x33' * 24 + b'\0' + b'user')))
    F.append(resp(26, mschap(2, 2, b'\x08' + b'\x34' * 8 + b'user')))
    F.append(req(26, mschap(3, 1, b'S=0123456789ABCDEF0123456789ABCDEF01234567 M=OK')))
    F.append(req(26, mschap(4, 1, b'E=691 R=1 C=00112233445566778899aabbccddeeff V=3')))
    F.append(resp(26, mschap(7, 1, b'\x00' * 8)))
    F.append(resp(26, bytes([3, 1]) + struct.pack('>H', 99)))
    F.append(resp(26, b'\x03'))
    F.append(resp(26, b'\x03\x01'))

    # EAP-SIM: Start with version list and AT_IDENTITY (3GPP NAI, with
    # padding), Challenge with RAND and MAC, Notification, Client-Error,
    # an attribute of length 0 (bad length), only the subtype
    sim_id = b'1262011234567890@wlan.mnc001.mcc262.3gppnetwork.org'
    F.append(req(18, b'\x0a\x00\x00' + sim_attr(15, b'\x00\x02\x00\x01') + sim_attr(10, b'\x00\x00')))
    F.append(resp(18, b'\x0a\x00\x00' + identity_attr(14, sim_id) + sim_attr(7, b'\x00\x00' + b'\x51' * 16)))
    F.append(req(18, b'\x0b\x00\x00' + sim_attr(1, b'\x00\x00' + b'\x52' * 32) + sim_attr(11, b'\x00\x00' + b'\x53' * 16)))
    F.append(req(18, b'\x0c\x00\x00' + sim_attr(12, b'\x40\x00')))
    F.append(resp(18, b'\x0e\x00\x00' + sim_attr(22, b'\x00\x01')))
    F.append(resp(18, b'\x0c\x00\x00' + b'\x0c\x00\x00\x00'))
    F.append(resp(18, b'\x0d'))

    # EAP-AKA: Identity with AT_IDENTITY (and extra padding), Challenge
    # with RAND, AUTN, MAC, response with RES (64 bits), RES length 0
    # (the reproducer), AUTS, Notification, Client-Error, unknown, bad
    # length, subtype only; EAP-AKA' challenge with KDF input
    aka_id = b'0001011234567890@' + REALM.encode()
    F.append(req(23, b'\x05\x00\x00' + sim_attr(13, b'\x00\x00')))
    F.append(resp(23, b'\x05\x00\x00' + identity_attr(14, aka_id, 4)))
    F.append(req(23, b'\x01\x00\x00' + sim_attr(1, b'\x00\x00' + b'\x61' * 16)
                 + sim_attr(2, b'\x00\x00' + b'\x62' * 16) + sim_attr(11, b'\x00\x00' + b'\x63' * 16)))
    F.append(resp(23, b'\x01\x00\x00' + sim_attr(3, struct.pack('>H', 64) + b'\x64' * 8)))
    F.append(resp(23, b'\x01\x00\x00' + bytes([3, 1]) + struct.pack('>H', 0)))
    F.append(resp(23, b'\x04\x00\x00' + sim_attr(4, b'\x65' * 14)))
    F.append(req(23, b'\x0c\x00\x00' + sim_attr(12, b'\x80\x00')))
    F.append(resp(23, b'\x0e\x00\x00' + sim_attr(22, b'\x00\x00')))
    F.append(resp(23, b'\x01\x00\x00' + sim_attr(0x99, b'\x00\x00')))
    F.append(resp(23, b'\x01\x00\x00' + b'\x03\x00\x00\x00'))
    F.append(resp(23, b'\x02'))
    F.append(req(50, b'\x01\x00\x00' + sim_attr(1, b'\x00\x00' + b'\x66' * 16)
                 + sim_attr(23, b'\x00\x0b' + b'WLAN' + b'\0' * 3) + sim_attr(24, b'\x00\x01')))

    # PAX: STD-1, STD-2 with and without ADE, STD-3 with and without
    # ADE, ACK with and without ADE, SEC-1 (not decoded), unknown opcode
    def pax(op, flags, body):
        return bytes([op, flags, 1, 0, 0]) + body
    icv = b'\x71' * 16
    F.append(req(46, pax(1, 0, struct.pack('>H', 32) + b'\x72' * 32 + icv)))
    F.append(resp(46, pax(2, 0, struct.pack('>H', 32) + b'\x73' * 32 + struct.pack('>H', 4) + b'peer'
                          + struct.pack('>H', 16) + b'\x74' * 16 + icv)))
    F.append(resp(46, pax(2, 4, struct.pack('>H', 32) + b'\x73' * 32 + struct.pack('>H', 4) + b'peer'
                          + struct.pack('>H', 16) + b'\x74' * 16 + struct.pack('>H', 2) + b'\x01\x02' + icv)))
    F.append(req(46, pax(3, 0, struct.pack('>H', 16) + b'\x75' * 16 + icv)))
    F.append(req(46, pax(3, 4, struct.pack('>H', 16) + b'\x75' * 16 + struct.pack('>H', 2) + b'\x03\x04' + icv)))
    F.append(resp(46, pax(0x21, 0, icv)))
    F.append(resp(46, pax(0x21, 4, struct.pack('>H', 2) + b'\x05\x06' + icv)))
    F.append(req(46, pax(0x11, 2, b'\x76' * 8)))
    F.append(req(46, pax(0x7f, 0, b'')))

    # PSK: the four messages and a reserved T value is not possible (2
    # bits), so the four T values
    F.append(req(47, b'\x00' + b'\x81' * 16 + b'server@example.org'))
    F.append(resp(47, b'\x40' + b'\x81' * 16 + b'\x82' * 16 + b'\x83' * 16 + b'peer@example.org'))
    F.append(req(47, b'\x80' + b'\x81' * 16 + b'\x84' * 16 + b'\x85' * 21))
    F.append(resp(47, b'\xc0' + b'\x81' * 16 + b'\x86' * 21))

    # SAKE v2: Challenge (RAND_S, SERVERID), Challenge response (RAND_P,
    # PEERID, SPI_P, MIC_P), Confirm (MIC_S, SPI_S, MSK_LIFE, ENCR_DATA,
    # IV, PADDING, NEXT_TMPID), Auth-Reject, Identity (PERM_ID_REQ,
    # ANY_ID_REQ, unknown), an attribute longer than the rest, an
    # unknown subtype, version 1
    def sake(sub, attrs):
        return bytes([2, 1, sub]) + b''.join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    F.append(req(48, sake(1, [(1, b'\x91' * 16), (5, b'server@example.org')])))
    F.append(resp(48, sake(1, [(2, b'\x92' * 16), (6, b'peer@example.org'), (8, b'\x00\x01'),
                               (4, b'\x93' * 16)])))
    F.append(req(48, sake(2, [(3, b'\x94' * 16), (7, b'\x00\x01'), (132, b'\x00\x00\x00\x00\x0e\x10'),
                              (128, b'\x95' * 16), (129, b'\x96' * 16), (130, b'\x00\x00'),
                              (131, b'tmpid')])))
    F.append(req(48, sake(3, [])))
    F.append(req(48, sake(4, [(10, b'\x00\x00'), (9, b'\x00\x00'), (200, b'\x01')])))
    F.append(resp(48, sake(4, [(6, b'peer')]) + b'\x06\x10ab'))
    F.append(req(48, sake(9, [(1, b'\x91' * 4)])))
    F.append(req(48, bytes([1, 1, 1]) + b'\x01\x04\x00\x00'))
    # the reproducer: one SPI_S attribute (was never shown)
    F.append(req(48, sake(1, [(7, b'\xab\xcd')])))

    # GPSK: GPSK-1 to GPSK-4 (with and without PD payload), Fail,
    # Protected Fail, reserved opcode
    csuite = struct.pack('>IH', 0, 1)
    clist = struct.pack('>H', 12) + csuite + struct.pack('>IH', 0, 2)
    mac = b'\xa1' * 16
    F.append(req(51, b'\x01' + struct.pack('>H', 6) + b'server' + b'\xa2' * 32 + clist))
    F.append(resp(51, b'\x02' + struct.pack('>H', 4) + b'peer' + struct.pack('>H', 6) + b'server'
                  + b'\xa3' * 32 + b'\xa2' * 32 + clist + csuite + struct.pack('>H', 3) + b'\x01\x02\x03' + mac))
    F.append(resp(51, b'\x02' + struct.pack('>H', 4) + b'peer' + struct.pack('>H', 6) + b'server'
                  + b'\xa3' * 32 + b'\xa2' * 32 + clist + csuite + struct.pack('>H', 0) + mac))
    F.append(req(51, b'\x03' + b'\xa3' * 32 + b'\xa2' * 32 + struct.pack('>H', 6) + b'server'
                 + csuite + struct.pack('>H', 2) + b'\x04\x05' + mac))
    F.append(req(51, b'\x03' + b'\xa3' * 32 + b'\xa2' * 32 + struct.pack('>H', 6) + b'server'
                 + csuite + struct.pack('>H', 0) + mac))
    F.append(resp(51, b'\x04' + struct.pack('>H', 1) + b'\x06' + mac))
    F.append(resp(51, b'\x04' + struct.pack('>H', 0) + mac))
    F.append(req(51, b'\x05' + struct.pack('>I', 2)))
    F.append(req(51, b'\x06' + struct.pack('>I', 3) + mac))
    F.append(req(51, b'\x00\x00'))

    # IKEv2: an IKE header without payloads, with ICV data, with the
    # length flag (not dissected), only the flags
    ike = bytes(range(8)) + b'\0' * 8 + bytes([0, 0x20, 34, 0x08]) + struct.pack('>II', 0, 28)
    F.append(req(49, b'\x00' + ike))
    F.append(resp(49, b'\x20' + ike + b'\xb1' * 12))
    F.append(req(49, b'\xc0' + struct.pack('>I', 100) + ike))
    F.append(resp(49, b'\x00'))

    # MS-Authentication-TLV: Result, Crypto-Binding, SoH (unknown here);
    # the reproducer: two Result TLVs
    cb = struct.pack('>HH', 0x800c, 56) + bytes([0, 0, 0, 0]) + b'\xc1' * 32 + b'\xc2' * 20
    F.append(req(33, struct.pack('>HHH', 0x8003, 2, 1) + cb))
    F.append(resp(33, struct.pack('>HHH', 0x8003, 2, 1) * 2))
    F.append(resp(33, struct.pack('>HH', 0x0021, 4) + b'\xc3' * 4))

    # Expanded Type: WPS (WFA vendor 0x00372a, type 1) and an unknown
    # vendor
    F.append(req(254, b'\x00\x37\x2a' + struct.pack('>I', 1) + b'\x01\x00'))
    F.append(resp(254, b'\x00\x00\x09' + struct.pack('>I', 7) + b'\xd1\xd2'))

    # More corner cases. MS-CHAPv2 challenge and response without data,
    # with a value but no name, failure without a message
    F.append(req(26, mschap(1, 3, b'')))
    F.append(req(26, mschap(1, 4, b'\x04' + b'\x35' * 4)))
    F.append(resp(26, mschap(2, 3, b'')))
    F.append(resp(26, mschap(2, 4, b'\x31' + b'\x32' * 16 + b'\0' * 8 + b'\x33' * 24 + b'\0')))
    F.append(req(26, mschap(4, 2, b'')))
    # More identities: realms that are almost 3GPP (mcc and org labels),
    # an MCC that is not a number, encrypted IMSIs without a comma and
    # with a third field that is not a realm
    for ident in (b'u@a.xyz001.mcc001.3gppnetwork.org',
                  b'u@a.mnc001.xyz001.3gppnetwork.org',
                  b'u@a.mnc001.mcc001.3gppnetwork.net',
                  b'0001011234567890@wlan.mnc001.mcc0X1.3gppnetwork.org',
                  b'\x00QUJDREVGR0hJSktMTU5PUA==',
                  b'\x00QUJD,CertificateSerialNumber=1,Other=@' + REALM.encode()):
        F.append(eapol_frame(eap(RESP, b'\x01' + ident)))
    # SIM and AKA AT_IDENTITY that fill the attribute exactly (no padding)
    exact = b'1262011234567890@wlan.mnc001.mcc0262.3gppnetwork.org'
    assert len(exact) == 52
    F.append(resp(18, b'\x0a\x00\x00' + identity_attr(14, exact)))
    F.append(resp(23, b'\x05\x00\x00' + identity_attr(14, exact)))
    # SAKE attribute with length 1 (stops the attribute list)
    F.append(req(48, bytes([2, 1, 1]) + b'\x01\x01\x00\x00'))
    # EAP-TLS fragment with M but no L outside a reassembly: not
    # reassembled
    F.append(identity_req())
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x40, tls_client_hello()))))
    # TEAP without outer TLVs
    F.append(eapol_frame(eap(RESP, tls_body(55, 0x01, tls_client_hello()))))
    # IKEv2 with M only (not dissected), with I but no ICV data
    F.append(req(49, b'\x40' + bytes(range(28))))
    F.append(resp(49, b'\x20' + ike))
    # a request with EAP length 4 (no type in the length)
    F.append(eapol_frame(eap(REQ, b'\x01', length=4)))
    # MS-Auth TLV whose length runs past the EAP length (bad length) but
    # not past the frame
    e = eap(RESP, b'\x21' + struct.pack('>HH', 0x0021, 8) + b'\xc4' * 8)
    e = e[:2] + struct.pack('>H', len(e) - 4) + e[4:]
    F.append(eapol_frame(e))
    # the remaining reproducers: AKA RES length 0 is above; LEAP name of
    # 300 octets above; MD5 value size 0x20 with 4 octets above
    F.append(eapol_frame(eap(SUCCESS)))
    return F


# ---------------------------------------------------------------- RADIUS

def radius(code, ident, attrs):
    body = b''.join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return struct.pack('>BBH', code, ident, 20 + len(body)) + b'\x5e' * 16 + body


def radius_frames():
    F = []
    e1 = eap(RESP, b'\x01user@example.org', ident=0x30)
    F.append(eth_ipv4_udp(radius(1, 1, [(1, b'user@example.org'), (79, e1)]),
                          40000, 1812, '192.0.2.50', '192.0.2.60'))
    e2 = eap(REQ, b'\x04\x10' + b'\x44' * 16, ident=0x31)
    F.append(eth_ipv4_udp(radius(11, 1, [(79, e2), (24, b'state-1')]),
                          1812, 40000, '192.0.2.60', '192.0.2.50'))
    e3 = eap(RESP, b'\x04\x10' + b'\x45' * 16, ident=0x31)
    F.append(eth_ipv4_udp(radius(1, 2, [(1, b'user@example.org'), (79, e3), (24, b'state-1')]),
                          40000, 1812, '192.0.2.50', '192.0.2.60'))
    F.append(eth_ipv4_udp(radius(2, 2, [(79, eap(SUCCESS, ident=0x31))]),
                          1812, 40000, '192.0.2.60', '192.0.2.50'))
    return F


def malformed_frames():
    F = []
    # EAP length 3 and EAP length larger than the frame
    F.append(eapol_frame(eap(SUCCESS, length=3)))
    F.append(eapol_frame(eap(RESP, b'\x01user', length=200)))
    # MS-CHAPv2 response with a value size beyond the data
    F.append(resp(26, bytes([2, 1]) + struct.pack('>H', 8) + b'\x40' + b'\x00' * 3))
    # SIM attribute length beyond the data, AT_IDENTITY with an actual
    # length larger than the attribute (negative padding)
    F.append(resp(18, b'\x0a\x00\x00' + b'\x0e\x05\x00\x04abcd'))
    F.append(resp(18, b'\x0a\x00\x00' + b'\x0e\x01\x00\x08'))
    F.append(resp(23, b'\x05\x00\x00' + b'\x0e\x01\x00\x08'))
    # AKA AT_RES with a RES longer than the attribute
    F.append(resp(23, b'\x01\x00\x00' + bytes([3, 1]) + struct.pack('>H', 256)))
    # MS-Auth SoH TLV with a length past the end
    F.append(resp(33, struct.pack('>HH', 0x0021, 10) + b'\xc3' * 4))
    # PAX STD-1 with an A length beyond the data, GPSK-1 cut short,
    # PSK first message cut short, MS-Auth Crypto-Binding cut short
    F.append(req(46, bytes([1, 0, 1, 0, 0]) + struct.pack('>H', 64) + b'\x01' * 8))
    F.append(req(51, b'\x01' + struct.pack('>H', 60) + b'server'))
    F.append(req(47, b'\x00' + b'\x81' * 8))
    F.append(req(33, struct.pack('>HH', 0x800c, 56) + b'\x00' * 8))
    # EAP-TLS reassembly with a missing fragment: TLS length 200, two
    # fragments of 20 octets
    F.append(eapol_frame(eap(REQ, b'\x01')))
    F.append(eapol_frame(eap(RESP, tls_body(13, 0xc0, b'\x16' * 20, 200))))
    F.append(eapol_frame(eap(REQ, tls_body(13, 0x00))))
    F.append(eapol_frame(eap(RESP, tls_body(13, 0x00, b'\x16' * 20))))
    # TEAP EAP-Payload TLVs nested beyond the dissection depth limit (the
    # reproducer of the recursion)
    inner = eap(SUCCESS, ident=0)
    for i in range(600):
        tlv = teap_tlv(9, inner)
        inner = eap(REQ, tls_body(55, 0x11, tlv, outer_len=len(tlv)), ident=(i + 1) & 0xff)
    F.append(eapol_frame(inner))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'eap-coverage.pcap'),
               tls_frames() + method_frames() + radius_frames())
    write_pcap(os.path.join(out, 'eap-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/pana_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)

# ---- pana ----
# PANA over UDP, found by the UDP heuristic (pana_udp, enabled by default).
CLIENT = 40000
SERVER = 716
SESSION = 0x0badcafe
R, S, C, A, P, I = 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400
INIT, AUTH, TERM, NOTIF, RELAY = 1, 2, 3, 4, 5


def avp(code, value, flags=0, vendor=None, length=None):
    hdr = struct.pack('>HHHH', code, flags | (0x8000 if vendor is not None else 0),
                      len(value) if length is None else length, 0)
    if vendor is not None:
        hdr += struct.pack('>I', vendor)
    return hdr + value + bytes((-len(value)) % 4)


def pdu(mtype, flags, seq, avps=b'', session=SESSION, length=None):
    n = 16 + len(avps) if length is None else length
    return struct.pack('>HHHHII', 0, n, flags, mtype, session, seq) + avps


def u32(v):
    return struct.pack('>I', v)


def eap_identity():
    return struct.pack('>BBHB', 1, 1, 5, 1)       # EAP Request, Identity


def f(p, down=False, ident=1):
    if down:
        return eth(ipv4(udp(p, SERVER, CLIENT, src=IP_B, dst=IP_A), src=IP_B, dst=IP_A, ident=ident),
                   0x0800, dst=MAC_A, src=MAC_B)
    return udp_frame(p, CLIENT, SERVER, ident)


def nested(depth, seq=1):
    inner = pdu(AUTH, R, seq, avp(5, bytes(range(1, 9))))
    for i in range(depth):
        inner = pdu(RELAY, R, seq + i + 1, avp(11, inner))
    return inner


def build(out):
    main = Pcap()
    nonce = bytes(4) + bytes(range(4, 16))          # first four octets zero
    main.add(f(pdu(INIT, R, 100), ident=1))                                              # 1 PANA-Client-Initiation request
    main.add(f(pdu(AUTH, R | S, 101, avp(5, nonce) + avp(3, u32(1)) + avp(6, u32(2))), ident=2))   # 2 PANA-Auth request: Nonce, Integrity-Algorithm, PRF-Algorithm
    main.add(f(pdu(AUTH, S, 101, avp(2, eap_identity()) + avp(7, u32(0)) + avp(4, struct.pack('>i', -5))), down=True, ident=3))  # 3 answer: EAP-Payload, Result-Code, Key-Id
    main.add(f(pdu(AUTH, R, 102, avp(1, bytes(20)) + avp(8, u32(3600)) + avp(5, b'abcde')), ident=4))    # 4 request: AUTH, Session-Lifetime, Nonce with padding
    main.add(f(pdu(AUTH, R | S | C | A | P | I, 103, avp(7, u32(2))), down=True, ident=5))  # 5 all six flags, request from the server, Result-Code
    main.add(f(pdu(AUTH, A, 102, avp(7, u32(1))), down=True, ident=6))                   # 6 answer to 102 with the A flag
    main.add(f(pdu(TERM, R, 104, avp(9, u32(1))), ident=7))                              # 7 PANA-Termination request, Termination-Cause
    main.add(f(pdu(TERM, 0, 104), down=True, ident=8))                                   # 8 answer, no AVPs
    main.add(f(pdu(NOTIF, R | P, 105, avp(10, b'pac-info')), ident=9))                   # 9 PANA-Notification request, PaC-Information
    main.add(f(pdu(NOTIF, P, 105), down=True, ident=10))                                 # 10 answer
    main.add(f(nested(1, 200), ident=11))                                                # 11 PANA-Relay with one Relayed-Message
    main.add(f(nested(4, 300), ident=12))                                                # 12 four nested Relayed-Messages (the limit)
    main.add(f(pdu(AUTH, R, 106, avp(5, nonce) + avp(7, u32(0), vendor=0x1234)), ident=13))  # 13 second AVP with the V flag (Vendor-Id offset fix)
    main.add(f(pdu(AUTH, R, 107, avp(7, b'\x00\x00\x00\x07', vendor=0x00005678) + avp(5, nonce)), ident=14))  # 14 first AVP with the V flag
    main.add(f(pdu(AUTH, R, 108, avp(5, nonce) + avp(99, b'\1\2\3\4\5\6')), ident=15))   # 15 unknown AVP code
    main.add(f(pdu(AUTH, 0, 999, avp(7, u32(0))), down=True, ident=16))                  # 16 answer without a request
    main.add(f(pdu(AUTH, R, 110, avp(13, u32(1)) ), ident=17))                           # 17 AVP code 13 as first AVP
    main.add(f(pdu(INIT, R | I, 111), ident=18))                                         # 18 second frame with the I flag
    n = main.write(os.path.join(out, 'pana-coverage.pcap'))

    bad = Pcap()
    bad.add(f(nested(8, 400), ident=1))                                                  # 1 eight nested Relayed-Messages: nesting limit error
    bad.add(f(pdu(RELAY, R, 2, avp(11, b'\0' * 8)), ident=2))                            # 2 Relayed-Message shorter than a PANA header
    bad.add(f(pdu(RELAY, R, 3, avp(11, pdu(AUTH, R, 4, length=8))), ident=3))            # 3 nested PDU with a length below 16
    bad.add(f(pdu(RELAY, R, 5, avp(11, pdu(AUTH, R, 6)[:12] + bytes(0))), ident=4))      # 4 nested PDU of 12 octets
    bad.add(f(pdu(AUTH, R, 7, avp(5, bytes(8)) + struct.pack('>HHHH', 3, 0, 4, 0)), ident=5))  # 5 second AVP cut off (no value)
    bad.add(f(pdu(AUTH, R, 8, avp(5, bytes(8)) + avp(3, b'\1\2')), ident=6))             # 6 Integrity-Algorithm with a two octet value
    bad.add(f(pdu(AUTH, R, 9, avp(5, bytes(8)) + avp(7, b'\0\0')), ident=7))             # 7 Result-Code with two octets
    bad.add(f(pdu(AUTH, R, 10, avp(5, bytes(8)) + avp(2, b'\1\1')), ident=8))            # 8 EAP-Payload that is too short
    bad.add(f(pdu(AUTH, R, 11, avp(5, bytes(8)) + avp(5, bytes(200), length=400)), ident=9))  # 9 AVP length beyond the PDU
    bad.add(f(pdu(AUTH, R, 12, avp(5, bytes(8)) + avp(4, b'\0\0\0\1', vendor=1, length=2)), ident=10))  # 10 vendor AVP, data length 2
    bad.add(f(pdu(AUTH, R, 13, avp(5, bytes(8)) + struct.pack('>HHHH', 3, 0x8000, 4, 0)), ident=11))  # 11 vendor AVP without a vendor id
    # packets the heuristic rejects, one check each
    ok_avp = avp(5, bytes(8))
    good = pdu(AUTH, R, 20, ok_avp)
    bad.add(f(good[:10], ident=20))                                                      # 12 shorter than 12 octets
    bad.add(f(pdu(AUTH, R, 21, length=8), ident=21))                                     # 13 length field below 16
    bad.add(f(pdu(AUTH, R, 22, ok_avp, length=60), ident=22))                            # 14 length field differs from the packet
    bad.add(f(b'\x00\x01' + good[2:], ident=23))                                         # 15 reserved field not zero
    bad.add(f(pdu(AUTH, R | 0x0001, 24, ok_avp), ident=24))                              # 16 reserved flag bit set
    bad.add(f(pdu(0, R, 25, ok_avp), ident=25))                                          # 17 message type 0
    bad.add(f(pdu(9, R, 26, ok_avp), ident=26))                                          # 18 message type 9
    bad.add(f(pdu(AUTH, R, 27, bytes(4)), ident=27))                                     # 19 AVP area shorter than one AVP
    bad.add(f(pdu(AUTH, R, 28, avp(0, bytes(8))), ident=28))                             # 20 first AVP code 0
    bad.add(f(pdu(AUTH, R, 29, avp(14, bytes(8))), ident=29))                            # 21 first AVP code 14
    bad.add(f(pdu(AUTH, R, 30, avp(5, bytes(8), flags=0x0100)), ident=30))               # 22 reserved AVP flag set
    bad.add(f(pdu(AUTH, R, 31, avp(5, bytes(8), length=100)), ident=31))                 # 23 first AVP longer than the PDU
    bad.add(f(good[:20] + bytes(0), ident=32))                                           # 24 truncated first AVP (length field says 24)
    bad.add(f(good, ident=33), snap=14 + 20 + 8 + 20)                                     # 25 captured length 20 of a 40 octet PDU (first AVP not captured)
    nb = bad.write(os.path.join(out, 'pana-coverage-malformed.pcap'))
    print('main', n, 'malformed', nb)


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

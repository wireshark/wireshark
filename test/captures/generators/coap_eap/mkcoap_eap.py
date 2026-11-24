#!/usr/bin/env python3
# Generates test/captures/coap_eap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CoAP-EAP dissector
(packet-coap-eap.c, RFC 9820).

CoAP-EAP is the payload of CoAP messages with Content-Format 269
(application/coap-eap): an EAP packet (RFC 3748), optionally followed by
a CBOR map (CoAP-EAP_Info: 1 cipher suites, 2 RID-C, 3 RID-I, 4 session
lifetime), or a trigger URI (Step 0). CoAP hands it over through the
media_type table; a preference can also register it on a UDP port.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcoap_eap.py <output directory>

Writes:
  coap-eap-coverage.pcap            a full CoAP-EAP exchange (trigger,
                                    EAP Identity, EAP-PSK, Success and
                                    Failure) with every CoAP-EAP_Info
                                    key, values of the wrong type,
                                    unknown keys, a block-wise transfer,
                                    the UDP port preference path and the
                                    reproducers of the fixed bugs
  coap-eap-coverage-malformed.pcap  EAP headers cut short, bad EAP
                                    lengths, broken CBOR
"""

import os
import struct
import sys

# ------------------------------------------------------------ link layer


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ether_ip(src, dst, proto, l4):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto,
                     0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return b'\x02\x00' + ip4(dst) + b'\x02\x00' + ip4(src) + b'\x08\x00' + \
        ip + l4


def udp(src, dst, sp, dp, payload):
    u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return ether_ip(src, dst, 17, u[:6] + struct.pack('>H', c) + u[8:])


def tcp(src, dst, sp, dp, payload, seq=1000, ack=1, flags=0x18):
    t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535,
                    0, 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    return ether_ip(src, dst, 6, t[:16] + struct.pack('>H', csum(ph + t)) +
                    t[18:])


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 100,
                                (i % 100) * 10000, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------------------------ CoAP

CON, NON, ACK = 0, 1, 2
POST, CREATED, CHANGED, CONTINUE = 2, 65, 68, 95
URI_PATH, LOCATION_PATH, CONTENT_FORMAT, BLOCK1 = 11, 8, 12, 27


def opt_nibble(v):
    if v < 13:
        return v, b''
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack('>H', v - 269)


def coap(ttype, code, mid, token=b'', opts=(), payload=b''):
    out = bytes([0x40 | (ttype << 4) | len(token), code]) + \
        struct.pack('>H', mid) + token
    last = 0
    for num, val in sorted(opts, key=lambda o: o[0]):
        dn, dext = opt_nibble(num - last)
        ln, lext = opt_nibble(len(val))
        out += bytes([(dn << 4) | ln]) + dext + lext + val
        last = num
    if payload:
        out += b'\xff' + payload
    return out


CF_EAP = (CONTENT_FORMAT, struct.pack('>H', 269))


def path(*parts):
    return [(URI_PATH, p.encode()) for p in parts]


# ------------------------------------------------------------------- EAP

def eap(code, ident, typ=None, data=b''):
    if code in (3, 4):
        return struct.pack('>BBH', code, ident, 4)
    body = (bytes([typ]) if typ is not None else b'') + data
    return struct.pack('>BBH', code, ident, 4 + len(body)) + body


def psk1(rand_s, id_s):
    # EAP-PSK first message: flags (T=0), RAND_S, ID_S
    return b'\x00' + rand_s + id_s


def psk2(rand_s, rand_p, mac_p, id_p):
    # EAP-PSK second message: flags (T=1), RAND_S, RAND_P, MAC_P, ID_P
    return b'\x40' + rand_s + rand_p + mac_p + id_p


# ------------------------------------------------------------------ CBOR

def head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack('>H', n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack('>I', n)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', n)


def cuint(n):
    return head(0, n)


def cbstr(b):
    return head(2, len(b)) + b


def ctstr(t):
    return head(3, len(t)) + t.encode()


def carray(*items):
    return head(4, len(items)) + b''.join(items)


def cmap(*pairs):
    return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)


# --------------------------------------------------------------- captures

DEV, CTL = '192.0.2.10', '192.0.2.20'


def main_frames():
    fr = []

    def d2c(msg, sp=5683, dp=5683):
        fr.append(udp(DEV, CTL, sp, dp, msg))

    def c2d(msg, sp=5683, dp=5683):
        fr.append(udp(CTL, DEV, sp, dp, msg))

    # 1-2: Step 0, the trigger with the URI of the first EAP resource
    d2c(coap(NON, POST, 0x0100, b'\x01', [*path('.well-known', 'coap-eap'),
                                          CF_EAP], b'/a/x'))
    c2d(coap(NON, CHANGED, 0x0900, b'\x01'))
    # 3-4: Step 1, EAP Request/Identity with cipher suites and RID-I
    c2d(coap(CON, POST, 0x0901, b'\x02\x01', [*path('a', 'x'), CF_EAP],
             eap(1, 1, 1) +
             cmap((cuint(1), carray(cuint(0), cuint(1), cuint(2), cuint(3),
                                    cuint(4), cuint(9))),
                  (cuint(3), cbstr(b'\x0a\x0b')))))
    # Response/Identity with the chosen cipher suite and RID-C
    d2c(coap(ACK, CREATED, 0x0901, b'\x02\x01', [
        (LOCATION_PATH, b'a'), (LOCATION_PATH, b'y'), CF_EAP],
        eap(2, 1, 1, b'anonymous@example.org') +
        cmap((cuint(1), carray(cuint(0))), (cuint(2), cbstr(b'\x01')))))
    # 5-6: EAP-PSK first and second message (no CBOR)
    c2d(coap(CON, POST, 0x0902, b'\x02\x02', [*path('a', 'y'), CF_EAP],
             eap(1, 2, 47, psk1(bytes(range(16)), b'controller'))))
    d2c(coap(ACK, CHANGED, 0x0902, b'\x02\x02', [CF_EAP],
             eap(2, 2, 47, psk2(bytes(range(16)), bytes(range(16, 32)),
                                bytes(range(32, 48)), b'device'))))
    # 7-8: EAP Success with the session lifetime, an unknown key and a
    #      text key (skipped), and a lifetime as a 64 bit integer
    c2d(coap(CON, POST, 0x0903, b'\x02\x03', [*path('a', 'z'), CF_EAP],
             eap(3, 3) +
             cmap((cuint(4), cuint(8760)), (cuint(7), ctstr('ignored')),
                  (ctstr('x'), carray(cuint(1), cuint(2))),
                  (cuint(0x100000005), cuint(1)))))
    d2c(coap(ACK, CHANGED, 0x0903, b'\x02\x03'))
    # 9-10: a second exchange that ends in EAP Failure
    c2d(coap(CON, POST, 0x0904, b'\x03\x01', [*path('a', 'x'), CF_EAP],
             eap(1, 7, 1) + cmap((cuint(4), cuint(0x1_0000_0000)))))
    c2d(coap(CON, POST, 0x0905, b'\x03\x02', [*path('a', 'x'), CF_EAP],
             eap(4, 8)))
    # 11: values of the wrong type are skipped whole: a cipher suite list
    #     whose first element is a map (no leading comma), a lifetime given
    #     as an array, RID-I as an integer, an indefinite cipher suite array
    c2d(coap(CON, POST, 0x0906, b'\x04', [*path('a', 'w'), CF_EAP],
             eap(1, 9, 1) +
             cmap((cuint(1), carray(cmap((cuint(5), carray(cuint(6),
                                                           cuint(7)))),
                                    cuint(2), ctstr('x'), cuint(3))),
                  (cuint(4), carray(cuint(4), carray(cuint(5)))),
                  (cuint(3), cuint(77)),
                  (cuint(2), cbstr(b'\x05')))))
    c2d(coap(CON, POST, 0x0907, b'\x05', [*path('a', 'w'), CF_EAP],
             eap(1, 10, 1) +
             cmap((cuint(1), b'\x9f\x00\x01\xff'),
                  (cuint(2), cmap((cuint(1), cuint(2)))),
                  (cuint(4), cuint(60)))))
    # 13: a map that claims more pairs than present, a key without value
    c2d(coap(CON, POST, 0x0908, b'\x06', [*path('a', 'w'), CF_EAP],
             eap(1, 11, 1) + head(5, 3) + cuint(4) + cuint(30) + cuint(2)))
    c2d(coap(CON, POST, 0x0909, b'\x07', [*path('a', 'w'), CF_EAP],
             eap(1, 12, 1) + head(5, 3) + cuint(4) + cuint(30)))
    # a cipher suite array that claims more elements than present
    c2d(coap(CON, POST, 0x090b, b'\x0d', [*path('a', 'w'), CF_EAP],
             eap(1, 16, 1) + head(5, 1) + cuint(1) + head(4, 3) + cuint(0) +
             cuint(1)))
    # 15: an empty CoAP-EAP payload (only the marker is not allowed, so a
    #     payload starting with an EAP code but with no CoAP-EAP data is
    #     not possible; a trigger with an empty-looking URI instead)
    d2c(coap(NON, POST, 0x0101, b'\x08', [*path('.well-known', 'coap-eap'),
                                          CF_EAP], b'\x00'))
    # 16-19: EAP-PSK split over three Block1 blocks, reassembled by CoAP
    big = eap(2, 13, 47, psk1(bytes(range(16)), b'D' * 50)) + \
        cmap((cuint(1), carray(cuint(1))))
    blocks = [big[0:32], big[32:64], big[64:]]
    for i, b in enumerate(blocks):
        m = int(i < 2)
        d2c(coap(CON, POST, 0x0110 + i, b'\x09', [
            *path('a', 'b'), CF_EAP,
            (BLOCK1, bytes([(i << 4) | (m << 3) | 1]))], b))
    c2d(coap(ACK, CHANGED, 0x0112, b'\x09',
             [(BLOCK1, bytes([(2 << 4) | 1]))]))
    # 20-21: EAP Initiate (code 5) and Finish (code 6), RFC 6696
    c2d(coap(CON, POST, 0x090a, b'\x0a', [*path('a', 'r'), CF_EAP],
             eap(5, 14, 1, b'\x00')))
    d2c(coap(ACK, CHANGED, 0x090a, b'\x0a', [CF_EAP],
             eap(6, 14, 1, b'\x00')))
    # 22-23: CoAP on UDP port 5690, CoAP-EAP only with the udp_port
    #        preference (otherwise UDP data); one with Content-Format 269,
    #        one without
    d2c(coap(NON, POST, 0x0120, b'\x0b', [*path('a', 'p'), CF_EAP],
             eap(2, 15, 1, b'port@example.org')), sp=40001, dp=5690)
    d2c(coap(NON, POST, 0x0121, b'\x0c', [*path('a', 'p'),
                                          (CONTENT_FORMAT, b'')], b'text'),
        sp=40001, dp=5690)
    # 24-27: reproducer coap_eap_cbor_misalign.py
    rep = [
        bytes([0xa2, 0x01, 0x82, 0x82, 0x18, 0x02, 0x03, 0x04, 0x18, 0x3c]),
        bytes([0xa2, 0x04, 0x82, 0x02, 0x03, 0x02, 0x42, 0x01, 0x02]),
        bytes([0xa2, 0x01, 0xa1, 0x03, 0x04, 0x04, 0x18, 0x3c]),
        bytes([0xa2, 0x19, 0x01, 0x2c, 0x01, 0x1b, 0, 0, 0, 1, 0, 0, 0, 4,
               0x18, 0x3c]),
    ]
    for i, c in enumerate(rep):
        msg = bytes([0x40, 0x02]) + struct.pack('>H', 0x100 + i) + \
            bytes([0xc2, 0x01, 0x0d, 0xff]) + bytes([2, 7, 0, 5, 1]) + c
        fr.append(udp('192.0.2.1', '192.0.2.2', 40000 + i, 5683, msg))
    # 28: reproducer coap_eap_media_null_data.py: an MP3 over HTTP whose
    #     ID3v2 picture claims application/coap-eap
    e = bytes([1, 1, 0, 5, 1])
    apic = b'\x00' + b'application/coap-eap\x00' + b'\x03' + b'\x00' + e
    frame = b'APIC' + struct.pack('>I', len(apic)) + b'\x00\x00' + apic
    n = len(frame)
    tag = b'ID3\x03\x00\x00' + bytes([(n >> 21) & 0x7f, (n >> 14) & 0x7f,
                                      (n >> 7) & 0x7f, n & 0x7f]) + frame
    hdr = ('HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\n'
           'Content-Length: %d\r\n\r\n' % len(tag)).encode()
    fr.append(tcp('192.0.2.1', '192.0.2.2', 80, 40000, hdr + tag))
    # the same with an empty picture: CoAP-EAP gets no data
    apic = b'\x00' + b'application/coap-eap\x00' + b'\x03' + b'\x00'
    frame = b'APIC' + struct.pack('>I', len(apic)) + b'\x00\x00' + apic
    n = len(frame)
    tag = b'ID3\x03\x00\x00' + bytes([(n >> 21) & 0x7f, (n >> 14) & 0x7f,
                                      (n >> 7) & 0x7f, n & 0x7f]) + frame
    hdr = ('HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\n'
           'Content-Length: %d\r\n\r\n' % len(tag)).encode()
    fr.append(tcp('192.0.2.1', '192.0.2.2', 80, 40001, hdr + tag))
    return fr


def malformed_frames():
    fr = []

    def c2d(payload, mid):
        fr.append(udp(CTL, DEV, 5683, 5683,
                      coap(CON, POST, mid, b'', [CF_EAP], payload)))
    c2d(b'\x01\x01\x00', 1)                     # shorter than 4 octets
    c2d(eap(1, 1, 1)[:2] + b'\x00\x02\x01', 2)  # EAP length 2
    c2d(b'\x01\x01\x00\x20\x01', 3)             # EAP length beyond payload
    c2d(eap(1, 1, 1) + carray(cuint(1)), 4)     # CBOR not a map
    c2d(eap(1, 1, 1) + b'\xbf\x01\x02\xff', 5)  # indefinite map
    c2d(eap(1, 1, 1) + b'\xb9\x00', 6)          # map head cut short
    c2d(eap(1, 1, 1) + b'\xa1\x01\x9a\x00', 7)  # cipher suites cut short
    c2d(eap(1, 1, 1) + b'\xa1\x01\x82\x1b\x00', 8)  # suite cut short
    c2d(eap(1, 1, 1) + b'\xa1\x03\x45\x01', 9)  # RID-I cut short
    c2d(eap(1, 1, 1) + b'\xa1\x04\x1a\x00', 10)  # lifetime cut short
    c2d(eap(1, 1, 1) + b'\xa1\x1a\x00', 11)     # key cut short
    c2d(eap(1, 1, 1) + b'\xa2\x07\x5a\xff\xff\xff\xff\x01\x02', 12)
    c2d(eap(1, 1, 1) + b'\xa1\x01\x82\xfc\x01', 13)  # reserved minor
    c2d(eap(1, 1, 1) + b'\xa1\xfc\x01', 14)     # reserved key
    c2d(eap(1, 1, 1) + b'\xa1\x01\x82\x5f\x41\x00\xff\x01', 15)
    c2d(eap(1, 1, 1) + b'\xbc\x01', 16)          # reserved map minor
    return fr


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(outdir, 'coap-eap-coverage.pcap'), main_frames())
    write_pcap(os.path.join(outdir, 'coap-eap-coverage-malformed.pcap'),
               malformed_frames())


if __name__ == '__main__':
    main()

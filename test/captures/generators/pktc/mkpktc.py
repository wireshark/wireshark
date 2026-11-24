#!/usr/bin/env python3
# Generates test/captures/pktc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PKTC coverage captures (PacketCable security, UDP 1293, and
the MTA FQDN protocol, UDP 2246).
Usage: mkpktc.py <outdir>.  Writes pktc-coverage.pcap and
pktc-coverage-malformed.pcap (Ethernet).  Every packet is built with
struct; nothing comes from a real network.  The Kerberos messages carry
opaque placeholder octets in their encrypted parts: no key, encryption or
decryption is involved."""
import os
import sys
import struct

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(payload, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    h = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 17, 8 + len(payload))
    c = csum(ph + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), c) + payload

ETH_A = bytes([2, 0, 0, 0, 0, 1])
ETH_B = bytes([2, 0, 0, 0, 0, 2])
def eth(payload, etype=0x0800, src=ETH_A, dst=ETH_B):
    return dst + src + struct.pack('>H', etype) + payload

def eth_udp(payload, sport, dport, **kw):
    return eth(ipv4(udp(payload, sport, dport), **kw))

def pcap(fn, pkts, lt=1, snaplen=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, lt))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

# ---- DER helpers --------------------------------------------------------
def der(tag, content):
    l = len(content)
    if l < 0x80:
        ln = bytes([l])
    elif l < 0x100:
        ln = bytes([0x81, l])
    else:
        ln = bytes([0x82]) + struct.pack('>H', l)
    return bytes([tag]) + ln + content
def seq(*c): return der(0x30, b''.join(c))
def ctx(n, c): return der(0xa0 | n, c)
def integer(v): return der(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=False))
def octets(b): return der(0x04, b)
def gstr(s): return der(0x1b, s.encode())
def gtime(s): return der(0x18, s.encode())

PLACEHOLDER = b'opaque placeholder octets, not ciphertext'
def enc_data(etype=17, kvno=1):
    return seq(ctx(0, integer(etype)), ctx(1, integer(kvno)), ctx(2, octets(PLACEHOLDER)))
def principal(*names):
    return seq(ctx(0, integer(1)), ctx(1, seq(*[gstr(n) for n in names])))
def ticket():
    return der(0x61, seq(ctx(0, integer(5)), ctx(1, gstr('PKTC.EXAMPLE')), ctx(2, principal('mta', 'host')), ctx(3, enc_data())))
def ap_req():
    return der(0x6e, seq(ctx(0, integer(5)), ctx(1, integer(14)), ctx(2, der(0x03, b'\x00\x00\x00\x00\x00')),
                         ctx(3, ticket()), ctx(4, enc_data())))
def ap_rep():
    return der(0x6f, seq(ctx(0, integer(5)), ctx(1, integer(15)), ctx(2, enc_data())))
def krb_error():
    return der(0x7e, seq(ctx(0, integer(5)), ctx(1, integer(30)), ctx(4, gtime('20260115120000Z')),
                         ctx(5, integer(123456)), ctx(6, integer(31)), ctx(9, gstr('PKTC.EXAMPLE')),
                         ctx(10, principal('krbtgt', 'PKTC.EXAMPLE')), ctx(11, gstr('PacketCable error'))))
def krb_safe(user):
    body = seq(ctx(0, octets(user)), ctx(1, gtime('20260115120000Z')), ctx(2, integer(1)), ctx(3, integer(7)),
               ctx(4, seq(ctx(0, integer(2)), ctx(1, octets(bytes([192, 0, 2, 1]))))))
    cksum = seq(ctx(0, integer(8)), ctx(1, octets(b'\x01' * 12)))
    return der(0x74, seq(ctx(0, integer(5)), ctx(1, integer(20)), ctx(2, body), ctx(3, cksum)))

# ---- PKTC key management (UDP 1293) ----------------------------------------
KM_WAKEUP, KM_APREQ, KM_APREP, KM_SPR, KM_REKEY, KM_ERR = 1, 2, 3, 4, 5, 6
DOI_IPSEC, DOI_SNMP = 1, 2
def hdr(kmmid, doi, ver=0x10):
    return bytes([kmmid, doi, ver])
def engine_id():
    return bytes([0x80, 0x00, 0x11, 0x8b, 0x01, 192, 0, 2, 1])
def asd_snmp(user=b'mta-user'):
    e = engine_id()
    return bytes([len(e)]) + e + struct.pack('>II', 7, 123456) + bytes([len(user)]) + user
def ciphers(pairs):
    return bytes([len(pairs)]) + b''.join(bytes(p) for p in pairs)
HMAC = bytes(range(20))
NONCE = struct.pack('>I', 0xdeadbeef)

def pktc(payload):
    return eth_udp(payload, 1293, 1293)

good = []
bad = []
good.append(pktc(hdr(KM_WAKEUP, DOI_SNMP) + NONCE + b'mta/host@PKTC.EXAMPLE\0'))                      # 1 wake up
good.append(pktc(hdr(KM_APREQ, DOI_SNMP) + ap_req() + NONCE + asd_snmp() + ciphers([(0x21, 0x20), (0x22, 0x21), (0x55, 0x66)]) + b'\x01' + HMAC))   # 2 AP request SNMPv3
good.append(pktc(hdr(KM_APREQ, DOI_IPSEC) + ap_req() + NONCE + struct.pack('>I', 0x12345678) +
                 ciphers([(1, 3), (2, 4), (1, 5), (2, 6), (1, 7), (2, 0xb), (1, 0xc), (0x77, 0x88)]) + b'\x00' + HMAC))   # 3 AP request IPsec
good.append(pktc(hdr(KM_APREP, DOI_SNMP) + ap_rep() + asd_snmp(b'') + ciphers([(0x21, 0x20)]) +
                 struct.pack('>II', 86400, 3600) + b'\x01\x01' + HMAC))                                # 4 AP reply SNMPv3
good.append(pktc(hdr(KM_APREP, DOI_IPSEC) + ap_rep() + struct.pack('>I', 0x9abcdef0) + ciphers([(2, 0xc)]) +
                 struct.pack('>II', 0xfffff000, 0) + b'\x00\x00' + HMAC))                              # 5 AP reply IPsec, negative lifetime
good.append(pktc(hdr(KM_SPR, DOI_IPSEC) + HMAC))                                                        # 6 security parameters recovered
good.append(pktc(hdr(KM_REKEY, DOI_IPSEC) + NONCE + b'mta/host@PKTC.EXAMPLE\0' + b'260115120000Z' +
                 struct.pack('>I', 0x11223344) + ciphers([(1, 3)]) + struct.pack('>II', 86400, 60) + b'\x01' + HMAC))   # 7 rekey
good.append(pktc(hdr(KM_REKEY, DOI_IPSEC) + NONCE + b'x\0' + b'not a timestamp' [:13] +
                 struct.pack('>I', 1) + ciphers([]) + struct.pack('>II', 0, 0) + b'\x00' + HMAC))       # 8 rekey, bad timestamp, no ciphersuite
good.append(pktc(hdr(KM_ERR, DOI_IPSEC) + krb_error()))                                                 # 9 error reply
good.append(pktc(hdr(0x07, 0x09, 0x21)))                                                                # 10 unknown KMMID and DOI
good.append(pktc(hdr(KM_WAKEUP, DOI_IPSEC, 0x00) + NONCE + b'\0'))                                      # 11 empty principal

# ---- MTA FQDN (UDP 2246) -------------------------------------------------------
def fq_user(msgtype, tail=b'', ver=1, ent=4491):
    return bytes([msgtype]) + struct.pack('>I', ent) + bytes([ver]) + tail
MAC = bytes([2, 0, 0, 0, 0, 1])
PKH = b'\x11' * 20
def fq_req(user, port=2246):
    return eth_udp(ap_req() + krb_safe(user), 40000, port)
def fq_rep(user):
    return eth_udp(ap_rep() + krb_safe(user), 2246, 40000)
good.append(fq_req(fq_user(1, MAC + PKH + struct.pack('>I', 0))))                                       # 12 FQDN request, not revoked
good.append(fq_req(fq_user(1, MAC + PKH + struct.pack('>I', 0x5f000000))))                              # 13 FQDN request, revoked (the reproducer)
good.append(fq_rep(fq_user(2, b'mta1.example.com' + bytes([192, 0, 2, 7]))))                            # 14 FQDN reply
good.append(fq_rep(fq_user(3)))                                                                         # 15 error reply
good.append(fq_req(fq_user(1, MAC + PKH + struct.pack('>I', 0xffffffff))))                              # 16 revoked, last second

# ---- malformed and error paths ---------------------------------------------------
bad.append(pktc(hdr(KM_APREQ, 9) + ap_req() + NONCE + b'\0\0\0\0' + b'\x00' + b'\x01' + HMAC))      # 1 unknown DOI in AP request
bad.append(pktc(hdr(KM_REKEY, DOI_SNMP) + NONCE + b'x\0' + b'260115120000Z' + asd_snmp() + ciphers([(0x21, 0x20)]) +
                struct.pack('>II', 1, 1) + b'\x00' + HMAC))                                            # 2 SNMPv3 rekey: unknown KMMID for the DOI
bad.append(pktc(hdr(KM_APREP, 9) + ap_rep() + b'\0\0\0\0' + b'\x00' + struct.pack('>II', 1, 1) + b'\0\0' + HMAC))  # 3 unknown DOI in AP reply
bad.append(pktc(hdr(KM_WAKEUP, DOI_SNMP) + NONCE + b'no terminator'))                                  # 4 principal without NUL (exception)
bad.append(pktc(hdr(KM_APREQ, DOI_IPSEC)))                                                              # 5 AP request without Kerberos blob
bad.append(pktc(hdr(KM_SPR, DOI_IPSEC) + HMAC[:10]))                                                    # 6 short hmac
bad.append(pktc(b'\x01\x02'))                                                                           # 7 two octets: no version
bad.append(eth_udp(der(0x6a, seq(ctx(0, integer(5)), ctx(1, integer(10)))) + krb_safe(fq_user(1)), 40000, 2246))   # 8 FQDN with an AS-REQ first
bad.append(eth_udp(ap_req() + der(0x75, seq(ctx(0, integer(5)), ctx(1, integer(21)))), 40000, 2246))   # 9 FQDN with a KRB-PRIV instead of KRB-SAFE
bad.append(fq_req(fq_user(1, MAC + PKH[:5])))                                                           # 10 request cut short
bad.append(fq_rep(fq_user(2, b'ab')))                                                                   # 11 reply shorter than the address
bad.append(fq_req(fq_user(4, b'abc')))                                                                  # 12 unknown message type

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'pktc-coverage.pcap'), good, 1)
    pcap(os.path.join(out, 'pktc-coverage-malformed.pcap'), bad, 1)

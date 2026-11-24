#!/usr/bin/env python3
# Generates test/captures/mudurl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MUDURL coverage captures. Usage: mkmudurl.py <outdir>
mudurl-coverage.pcap            main capture: TLS handshakes whose certificates
                                carry the MUD URL extension (1.3.6.1.5.5.7.1.25)
mudurl-coverage-malformed.pcap  wrong tags and truncated values in that extension
Everything is synthetic; the certificates have made-up names, a dummy public key
and a placeholder signature."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---------------------------------------------------------------- DER
def tl(tag, body):
    n = len(body)
    if n < 0x80: l = bytes([n])
    elif n < 0x100: l = bytes([0x81, n])
    else: l = bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + l + body
def seq(*a): return tl(0x30, b''.join(a))
def oid(s):
    p = [int(x) for x in s.split('.')]
    b = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        t = [v & 0x7f]
        v >>= 7
        while v: t.insert(0, 0x80 | v & 0x7f); v >>= 7
        b += bytes(t)
    return tl(0x06, b)
def integer(v):
    b = v.to_bytes((v.bit_length() // 8) + 1, 'big')
    return tl(0x02, b)
def utf8(s): return tl(0x0c, s.encode())
def ia5(s): return tl(0x16, s if isinstance(s, bytes) else s.encode())
def octets(b): return tl(0x04, b)
def bitstr(b): return tl(0x03, b'\0' + b)
def boolean(v): return tl(0x01, b'\xff' if v else b'\0')

OID_MUD = '1.3.6.1.5.5.7.1.25'

def name(cn):
    return seq(tl(0x31, seq(oid('2.5.4.3'), utf8(cn))))

def ext(o, value_der, critical=False):
    return seq(oid(o), *( [boolean(True)] if critical else [] ), octets(value_der))

def cert(cn, mud_exts, extra=True, serial=1):
    tbs = seq(
        tl(0xa0, integer(2)),                              # v3
        integer(serial),
        seq(oid('1.2.840.113549.1.1.11'), tl(0x05, b'')),
        name('Example MUD CA'),
        seq(tl(0x17, b'200101000000Z'), tl(0x17, b'400101000000Z')),
        name(cn),
        seq(seq(oid('1.2.840.113549.1.1.1'), tl(0x05, b'')),
            bitstr(seq(integer(0xC0FFEE0123456789), integer(65537)))),     # dummy "key"
        tl(0xa3, seq(*( ([ext('2.5.29.19', seq(boolean(True)), True),
                         ext('2.5.29.17', seq(tl(0x82, cn.encode())))] if extra else []) + mud_exts))))
    return seq(tbs, seq(oid('1.2.840.113549.1.1.11'), tl(0x05, b'')), bitstr(b'\xa5' * 32))

def mud(url, critical=False):
    return ext(OID_MUD, ia5(url), critical)

# ---------------------------------------------------------------- TLS / TCP / pcap
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_ip_tcp(src, dst, sport, dport, seqn, ack, flags, payload):
    opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seqn, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(tcp))
    c = csum(ph + tcp)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
    if src[3] == 2:
        eth = bytes.fromhex('020000000001' '020000000002') + b'\x08\x00'
    return eth + ip + tcp

def hs(t, body): return bytes([t]) + len(body).to_bytes(3, 'big') + body
def rec(body, typ=22): return bytes([typ, 3, 3]) + struct.pack('>H', len(body)) + body

def client_hello():
    return rec(hs(1, b'\x03\x03' + bytes(range(32)) + b'\0' + b'\0\x02\x00\x2f' + b'\x01\x00'))
def server_hello():
    return hs(2, b'\x03\x03' + bytes(range(32, 64)) + b'\0' + b'\x00\x2f' + b'\x00')
def certificate(certs):
    lst = b''.join(len(c).to_bytes(3, 'big') + c for c in certs)
    return hs(11, len(lst).to_bytes(3, 'big') + lst)
def hello_done(): return hs(14, b'')

class Pcap:
    def __init__(self): self.pkts = []
    def add(self, p): self.pkts.append(p)
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)

C = [192, 0, 2, 1]; S = [192, 0, 2, 2]

def session(pc, sport, certs, base=1000):
    ch = client_hello()
    flight = rec(server_hello() + certificate(certs) + hello_done())
    cseq, sseq = base, base * 7
    pc.add(eth_ip_tcp(C, S, sport, 443, cseq, 0, 0x02, b''))
    pc.add(eth_ip_tcp(S, C, 443, sport, sseq, cseq + 1, 0x12, b''))
    pc.add(eth_ip_tcp(C, S, sport, 443, cseq + 1, sseq + 1, 0x10, b''))
    pc.add(eth_ip_tcp(C, S, sport, 443, cseq + 1, sseq + 1, 0x18, ch))
    cseq += 1 + len(ch); sseq += 1
    off = 0
    while off < len(flight):
        chunk = flight[off:off + 1200]
        pc.add(eth_ip_tcp(S, C, 443, sport, sseq + off, cseq, 0x18, chunk))
        off += len(chunk)
    pc.add(eth_ip_tcp(C, S, sport, 443, cseq, sseq + len(flight), 0x10, b''))

def main():
    pc = Pcap()
    # 1: one certificate, URL as in the MUD RFC example, non-critical
    session(pc, 40001, [cert('lightbulb.example.com', [mud('https://lighting.example.com/lightbulb2000')])])
    # 2: a chain, the leaf has a critical MUD extension, the CA none
    session(pc, 40002, [cert('thermostat.example.com', [mud('https://iot.example.net/thermostat/v1', True)], serial=2),
                        cert('Example MUD CA', [], serial=3)], base=2000)
    # 3: a URL longer than 127 octets (long form length), and an empty one
    session(pc, 40003, [cert('camera.example.com', [mud('https://mud.example.org/' + 'device/' * 20 + 'camera.json')], serial=4),
                        cert('empty.example.com', [mud('')], extra=False, serial=5)], base=3000)
    # 4: a certificate without the extension next to one with two URLs (a repeated extension)
    session(pc, 40004, [cert('plain.example.com', [], serial=6),
                        cert('twice.example.com', [mud('https://a.example/x.json'), mud('https://b.example/y.json')], serial=7)], base=4000)
    pc.write('mudurl-coverage.pcap')

    pm = Pcap()
    # value with the wrong tag (UTF8String), truncated string, length beyond the extension,
    # trailing bytes after the string, and a SEQUENCE where an IA5String is expected
    bad = [ext(OID_MUD, utf8('https://wrong.tag.example/x')),
           ext(OID_MUD, b'\x16\x20https://short'),
           ext(OID_MUD, b'\x16\x84\xff\xff\xff\xffxx'),
           ext(OID_MUD, ia5(b'https://ok.example/x') + b'\x00\x00\x00'),
           ext(OID_MUD, seq(ia5(b'https://seq.example/x'))),
           ext(OID_MUD, b''),
           ext(OID_MUD, ia5(b'https://\xe9\xe8.example/\x01\x02'))]
    for i, e in enumerate(bad):
        session(pm, 41000 + i, [cert('bad%d.example.com' % i, [e], serial=10 + i)], base=5000 + 1000 * i)
    pm.write('mudurl-coverage-malformed.pcap')

main()

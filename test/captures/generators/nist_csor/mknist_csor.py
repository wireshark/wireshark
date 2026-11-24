#!/usr/bin/env python3
# Generates test/captures/nist_csor_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the NIST CSOR coverage captures: mknist_csor.py <outdir>
# The NIST CSOR dissector only registers BER OIDs (AES-CBC/OFB/CFB, SHAKE output
# length). It is reached through an AlgorithmIdentifier in a CMS message
# (application/pkcs7-mime in HTTP). No key or ciphertext is generated: the
# "encrypted" content is a placeholder text.
import struct
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def tlv(tag, body):
    n = len(body)
    if n < 128: l = bytes([n])
    elif n < 256: l = bytes([0x81, n])
    else: l = bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + l + body
def seq(*items): return tlv(0x30, b''.join(items))
def sset(*items): return tlv(0x31, b''.join(items))
def integer(v): return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=False))
def octets(b): return tlv(0x04, b)
def oid(s):
    p = [int(x) for x in s.split('.')]
    body = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        chunk = [v & 0x7f]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7f)); v >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)
def ctx(n, body, constructed=True): return tlv((0xa0 if constructed else 0x80) | n, body)

OID_DATA = '1.2.840.113549.1.7.1'
OID_ENCRYPTED = '1.2.840.113549.1.7.6'
OID_SIGNED = '1.2.840.113549.1.7.2'
IV = bytes(range(0x10, 0x20))

def encrypted_data(alg_oid, params):
    eci = seq(oid(OID_DATA), seq(oid(alg_oid), params) if params is not None else seq(oid(alg_oid)),
              ctx(0, b'PLACEHOLDER, NOT ENCRYPTED', constructed=False))
    return seq(oid(OID_ENCRYPTED), ctx(0, seq(integer(0), eci)))

def signed_data(alg_oid, params):
    alg = seq(oid(alg_oid), params) if params is not None else seq(oid(alg_oid))
    return seq(oid(OID_SIGNED), ctx(0, seq(integer(1), sset(alg), seq(oid(OID_DATA)), sset())))

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
ETH_R = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
frames = []
st = {'c': 1000, 's': 5000}
def tcp(payload, up, flags=0x18, sport=49152, dport=80):
    seq_, ack = (st['c'], st['s']) if up else (st['s'], st['c'])
    s_, d_ = (CLI, SRV) if up else (SRV, CLI)
    sp, dp = (sport, dport) if up else (dport, sport)
    opts = b''
    if flags & 2:
        opts = struct.pack('>BBH', 2, 4, 1460)
        if not flags & 0x10: ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq_, ack, 0x50 + (len(opts) // 4 << 4), flags, 65535, 0, 0) + opts
    c = csum(s_ + d_ + struct.pack('>BBH', 0, 6, len(h) + len(payload)) + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    seg = h + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 1, 0, 64, 6, 0, s_, d_)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    frames.append((ETH if up else ETH_R) + ip + seg)
    key = 'c' if up else 's'
    st[key] += len(payload) + (1 if flags & 3 else 0)

def handshake():
    tcp(b'', True, 0x02); tcp(b'', False, 0x12); tcp(b'', True, 0x10)

def post(der, ctype='application/pkcs7-mime; smime-type=enveloped-data'):
    hdr = ('POST /smime HTTP/1.1\r\nHost: mail.example.com\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (ctype, len(der))).encode()
    tcp(hdr + der, True)
    tcp(b'HTTP/1.1 204 No Content\r\n\r\n', False)

AES = {'id-aes128-CBC': '2.16.840.1.101.3.4.1.2', 'id-aes128-OFB': '2.16.840.1.101.3.4.1.3', 'id-aes128-CFB': '2.16.840.1.101.3.4.1.4',
       'id-aes192-CBC': '2.16.840.1.101.3.4.1.22', 'id-aes192-OFB': '2.16.840.1.101.3.4.1.23', 'id-aes192-CFB': '2.16.840.1.101.3.4.1.24',
       'id-aes256-CBC': '2.16.840.1.101.3.4.1.42', 'id-aes256-OFB': '2.16.840.1.101.3.4.1.43', 'id-aes256-CFB': '2.16.840.1.101.3.4.1.44'}

def main_frames():
    pass
    for name, o in AES.items():
        if name.endswith('CFB'):
            post(encrypted_data(o, seq(octets(IV), integer(8 if '128' in name else 128 if '256' in name else 1))))
        else:
            post(encrypted_data(o, octets(IV)))
    post(signed_data('2.16.840.1.101.3.4.2.17', integer(32)))     # id-shake128-len
    post(signed_data('2.16.840.1.101.3.4.2.18', integer(64)))     # id-shake256-len

def malformed_frames():
    pass
    c = AES['id-aes128-CFB']
    post(encrypted_data(AES['id-aes128-CBC'], octets(IV[:8])))                    # IV of 8 octets
    post(encrypted_data(AES['id-aes192-OFB'], octets(IV + IV)))                   # IV of 32 octets
    post(encrypted_data(c, seq(octets(IV), integer(0))))                          # number of bits 0
    post(encrypted_data(c, seq(octets(IV), integer(129))))                        # number of bits 129
    post(encrypted_data(c, seq(octets(IV))))                                      # numberOfBits missing
    post(encrypted_data(c, octets(IV)))                                           # wrong type of parameters
    post(encrypted_data(AES['id-aes256-CBC'], integer(5)))                        # wrong tag for the IV
    post(signed_data('2.16.840.1.101.3.4.2.17', octets(b'x')))                   # wrong tag for the length
    post(signed_data('2.16.840.1.101.3.4.2.18', tlv(0x02, b'\x00' * 12)))         # integer too large
    post(encrypted_data(AES['id-aes128-CBC'], octets(IV))[:-20])                  # truncated message

def write_pcap(name, frs):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frs):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

if __name__ == '__main__':
    main_frames()
    write_pcap('nist-csor-coverage.pcap', frames)
    n = len(frames)
    frames.clear(); st.update(c=1000, s=5000)
    malformed_frames()
    write_pcap('nist-csor-coverage-malformed.pcap', frames)
    print(n, 'main frames,', len(frames), 'malformed frames')

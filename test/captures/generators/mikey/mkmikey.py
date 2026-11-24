#!/usr/bin/env python3
# Generates test/captures/mikey_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MIKEY coverage captures. Usage: mkmikey.py <outdir> [-v]
Synthetic; addresses from 192.0.2.0/24. All key, MAC, signature and
certificate contents are placeholder bytes (no keys, no crypto)."""
import struct
import sys
import os
import base64

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def eth(payload, ethertype=0x0800, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', ethertype) + payload
def ipv4(payload, proto=17, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
def tcp(payload, sport, dport, seq, ack, flags):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# payload type numbers
LAST, KEMAC, PKE, DH, SIGN, T, ID, CERT, CHASH, V, SP, RAND, ERR = range(13)
TR, IDR = 13, 14
KEY, EXT, SAKKE = 20, 21, 26

def hdr(nxt, mtype=0, ncs=1, mapt=0, csb=0x01020304, v=0x80, prf=0, ver=1, ids=None):
    b = struct.pack('!BBBBIBB', ver, mtype, nxt, v | prf, csb, ncs, mapt)
    if mapt == 0:
        ids = ids if ids is not None else [(0, 0xdeadbeef, 0x11)] * ncs
        for no, ssrc, roc in ids:
            b += struct.pack('!BII', no, ssrc, roc)
    return b
def t_ntp(nxt, ty=1): return bytes([nxt, ty]) + struct.pack('!II', 0xe8000000, 0x80000000)
def t_ctr(nxt): return bytes([nxt, 2]) + b'\x00\x00\x00\x07'
def t_bad(nxt): return bytes([nxt, 9]) + b'\0' * 8
def rand(nxt, n=16): return bytes([nxt, n]) + bytes(range(n))
def idp(nxt, ty=0, s=b'alice@example.org'): return bytes([nxt, ty]) + struct.pack('!H', len(s)) + s
def idr(nxt, role=1, ty=1, s=b'sip:bob@example.org'): return bytes([nxt, role, ty]) + struct.pack('!H', len(s)) + s
def keydata(nxt, ty=0, kv=0, key=bytes(16), salt=None, kvdata=None):
    b = bytes([nxt, (ty << 4) | kv]) + struct.pack('!H', len(key)) + key
    if ty in (1, 3):
        s = salt if salt is not None else bytes(14)
        b += struct.pack('!H', len(s)) + s
    if kv == 2:
        f, t = kvdata or (b'\x00\x00\x00\x01', b'\x00\x00\x00\xff')
        b += bytes([len(f)]) + f + bytes([len(t)]) + t
    elif kv == 1:
        s = kvdata if kvdata is not None else b'\x00\x01'
        b += bytes([len(s)]) + s
    return b
def kemac(nxt, enc=0, data=bytes(20), mac=0, macdata=None):
    m = macdata if macdata is not None else (b'' if mac == 0 else bytes(20))
    return bytes([nxt, enc]) + struct.pack('!H', len(data)) + data + bytes([mac]) + m
def pke(nxt, c=1, data=bytes(32)): return bytes([nxt]) + struct.pack('!H', (c << 14) | len(data)) + data
def dh(nxt, group=0, kv=0):
    n = {0: 192, 1: 96, 2: 128}.get(group, 16)
    return bytes([nxt, group]) + bytes(range(n)) + bytes([kv])
def sign(ty=0, data=bytes(64)): return struct.pack('!H', (ty << 12) | len(data)) + data
def vp(nxt, alg=1, mac=None):
    m = mac if mac is not None else (b'' if alg == 0 else bytes(20))
    return bytes([nxt, alg]) + m
def sp(nxt, no=0, proto=0, params=()):
    pb = b''.join(bytes([t, len(v)]) + v for t, v in params)
    return bytes([nxt, no, proto]) + struct.pack('!H', len(pb)) + pb
def err(nxt, no=0): return bytes([nxt, no, 0, 0])
def ext(nxt, ty, data): return bytes([nxt, ty]) + struct.pack('!H', len(data)) + data
def sakke(nxt, data=bytes(24)): return bytes([nxt, 1, 1]) + struct.pack('!H', len(data)) + data

def der(tag, c):
    n = len(c)
    l = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82]) + struct.pack('!H', n))
    return bytes([tag]) + l + c
def cert_der():
    oid_sha256rsa = der(6, bytes.fromhex('2a864886f70d01010b'))
    alg = der(0x30, oid_sha256rsa + der(5, b''))
    name = der(0x30, der(0x31, der(0x30, der(6, b'\x55\x04\x03') + der(0x0c, b'test'))))
    val = der(0x30, der(0x17, b'200101000000Z') + der(0x17, b'400101000000Z'))
    spki = der(0x30, der(0x30, der(6, bytes.fromhex('2a864886f70d010101')) + der(5, b'')) + der(3, b'\x00' + der(0x30, der(2, b'\x00\x80' + bytes(15)) + der(2, b'\x01\x00\x01'))))
    tbs = der(0x30, der(0xa0, der(2, b'\x02')) + der(2, b'\x01') + alg + name + val + name + spki)
    return der(0x30, tbs + alg + der(3, b'\x00' + bytes(32)))
def cert(nxt, ty=0, data=None):
    d = data if data is not None else cert_der()
    return bytes([nxt, ty]) + struct.pack('!H', len(d)) + d

SRTP_PARAMS = [(0, b'\x01'), (1, b'\x10'), (2, b'\x01'), (3, b'\x14'), (4, b'\x0e'), (5, b'\x00'), (6, b'\x00'), (7, b'\x01'),
               (8, b'\x01'), (9, b'\x00'), (10, b'\x01'), (11, b'\x0a'), (12, b'\x00')]

frames = []
ranges = []
def add(fr): frames.append(fr)
def U(m, sp_=2269, dp=2269): return eth(ipv4(udp(m, sp_, dp)))
def mark(name): ranges.append((name, len(frames) + 1))

def build():
    mark('message types, timestamps, IDs')
    # every data type with the payloads that belong to it
    for mt in list(range(11)) + [26, 27, 99]:
        add(U(hdr(T, mt) + t_ntp(ID) + idp(RAND) + rand(0)))
    add(U(hdr(T, 0) + t_ntp(0, 0)))
    add(U(hdr(T, 0) + t_ctr(0)))
    add(U(hdr(T, 0) + t_bad(0)))                                            # unknown timestamp type: stop
    add(U(hdr(ID, 0) + idp(IDR) + idr(0, 2, 0)))
    for role in range(8):
        add(U(hdr(IDR, 2) + idr(0, role, role % 3)))
    for ty in range(4):
        add(U(hdr(ID, 2) + idp(0, ty)))
    # header variants: no V flag, PRF, more than one SRTP id, other CS ID map type, no SRTP ids
    add(U(hdr(RAND, 0, v=0, prf=1) + rand(0, 4)))
    add(U(hdr(RAND, 0, ncs=3, ids=[(0, 1, 2), (1, 3, 4), (2, 5, 6)]) + rand(0, 8)))
    add(U(hdr(RAND, 0, ncs=0) + rand(0, 8)))
    add(U(hdr(RAND, 0, ncs=2, mapt=1) + rand(0, 8)))

    mark('security policy')
    add(U(hdr(SP, 0) + sp(0, 0, 0, SRTP_PARAMS)))
    add(U(hdr(SP, 0) + sp(SP, 0, 0, SRTP_PARAMS[:4]) + sp(0, 1, 0, SRTP_PARAMS[4:9])))
    add(U(hdr(SP, 0) + sp(0, 2, 1, [(0, b'\x01'), (1, b'\x02')])))                     # not SRTP: generic parameters
    add(U(hdr(SP, 0) + sp(0, 2, 0, [(200, b'\x01\x02'), (14, b'\xaa')])))              # unknown parameter types
    # reproducer of the fixed unregistered hf lookup (parameter type 13 == SP_MAX)
    add(U(hdr(SP, 0) + sp(0, 0, 0, [(13, b'\x00')])))
    add(U(hdr(SP, 0) + sp(0, 0, 0, [])))

    mark('pre-shared key (placeholder key bytes)')
    # NULL encryption with PSK_INIT decodes the key data sub-payload
    for ty in range(4):
        for kv in range(3):
            add(U(hdr(T, 0) + t_ntp(RAND) + rand(KEMAC) + kemac(0, 0, keydata(0, ty, kv), 0)))
    add(U(hdr(KEMAC, 0) + kemac(0, 0, keydata(0, 1, 2, kvdata=(b'', b'')), 1)))
    add(U(hdr(KEMAC, 0) + kemac(0, 0, keydata(0, 0, 1, kvdata=b''), 1)))
    add(U(hdr(KEMAC, 0) + kemac(0, 0, keydata(0, 1, 0, salt=b''), 1)))
    add(U(hdr(KEMAC, 0) + kemac(0, 0, b'', 0)))
    add(U(hdr(KEMAC, 1) + kemac(0, 0, keydata(0, 0, 0), 0)))                           # NULL encryption but not a PSK message
    add(U(hdr(KEMAC, 0) + kemac(0, 1, bytes(24), 1)))                                  # AES-CM: only the encrypted data
    add(U(hdr(KEMAC, 0) + kemac(0, 2, bytes(24), 0)))
    add(U(hdr(KEMAC, 0) + kemac(0, 9, bytes(24), 5, b'abc')))                          # unknown MAC algorithm: stop
    add(U(hdr(V, 1) + vp(0, 1)))
    add(U(hdr(V, 1) + vp(0, 0)))
    add(U(hdr(V, 1) + vp(0, 7, b'')))                                                  # unknown algorithm: stop

    mark('public key, DH and certificates')
    add(U(hdr(PKE, 2) + pke(CERT) + cert(SIGN, 0) + sign(0, bytes(8))))
    for c in (0, 1, 2):
        add(U(hdr(PKE, 2) + pke(0, c, bytes(16))))
    for ty in range(4):
        add(U(hdr(CERT, 2) + cert(0, ty)))
    add(U(hdr(DH, 4) + dh(SIGN, 0) + sign(1)))
    add(U(hdr(DH, 4) + dh(0, 1)))
    add(U(hdr(DH, 4) + dh(0, 2)))
    add(U(hdr(DH, 4) + dh(0, 5)))                                                      # unknown group: stop
    add(U(hdr(DH, 4) + dh(0, 0, 1)))                                                   # key validity not 0: stop
    for st in (0, 1, 2, 5):
        add(U(hdr(SIGN, 7) + sign(st)))
    add(U(hdr(SIGN, 7) + sign(0, b'')))                                                # empty signature stops the loop
    add(U(hdr(T, 7) + t_ntp(ID) + idp(CERT) + cert(SIGN) + sign(0, bytes(16))))

    mark('error, general extension, SAKKE, other payloads')
    for e in range(0, 14):
        add(U(hdr(ERR, 6) + err(0, e)))
    add(U(hdr(EXT, 0) + ext(EXT, 0, b'vendor') + ext(EXT, 1, b'a=sdp-id') + ext(EXT, 2, bytes(8)) + ext(EXT, 3, bytes(4)) +
          ext(EXT, 4, bytes(4)) + ext(EXT, 5, bytes(2)) + ext(EXT, 6, bytes(2)) + ext(0, 7, bytes(3))))
    add(U(hdr(EXT, 0) + ext(0, 99, b'')))
    add(U(hdr(SAKKE, 26) + sakke(0)))
    add(U(hdr(SAKKE, 27) + sakke(SAKKE) + sakke(0, b'')))
    add(U(hdr(CHASH, 0) + bytes([0, 1, 0, 0])))                                        # CHASH has no dissector: stop
    add(U(hdr(TR, 0) + bytes([0, 0, 0])))                                              # payload without a field
    add(U(hdr(77, 0) + bytes([0, 0, 0])))                                              # payload type beyond the table
    add(U(hdr(12, 0) + err(0, 5)))
    add(U(hdr(RAND, 0) + rand(0, 0)))

    mark('transports')
    msg = hdr(T, 0) + t_ntp(RAND) + rand(ID) + idp(KEMAC) + kemac(SP, 0, keydata(0, 1, 2), 1) + sp(0, 0, 0, SRTP_PARAMS)
    add(U(msg))
    add(U(msg, 3000, 2269))
    add(U(msg, 2269, 3000))
    sip, dip = '192.0.2.1', '192.0.2.2'
    iss, irs = 100, 900
    tc = lambda p, fl, s, a, sa=sip, da=dip, sp_=40001, dp=2269: eth(ipv4(tcp(p, sp_, dp, s, a, fl), 6, sa, da))
    add(tc(b'', 0x02, iss, 0))
    add(eth(ipv4(tcp(b'', 2269, 40001, irs, iss + 1, 0x12), 6, dip, sip), 0x0800, 2, 1))
    add(tc(b'', 0x10, iss + 1, irs + 1))
    add(tc(msg, 0x18, iss + 1, irs + 1))
    add(eth(ipv4(tcp(hdr(0, 1) + b'', 2269, 40001, irs + 1, iss + 1 + len(msg), 0x18), 6, dip, sip), 0x0800, 2, 1))
    # base64 text instead of binary (first octet is not 0x01)
    add(U(base64.b64encode(msg)))
    add(U(base64.b64encode(hdr(T, 1) + t_ctr(0))))
    # HTTP body of type application/mikey
    body = hdr(T, 0) + t_ntp(RAND) + rand(0)
    http = (b'POST /mikey HTTP/1.1\r\nHost: kms.example.org\r\nContent-Type: application/mikey\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
    add(eth(ipv4(tcp(http, 40002, 80, 500, 1, 0x18), 6)))
    # SDP key-mgmt attribute (session level and media level) in a SIP INVITE
    b64 = base64.b64encode(msg).decode()
    sdp = ('v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n'
           'a=key-mgmt:mikey %s\r\nm=audio 49170 RTP/SAVP 0\r\na=key-mgmt:mikey %s\r\n' % (b64, b64)).encode()
    sipm = (b'INVITE sip:bob@example.org SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nFrom: <sip:alice@example.org>;tag=1\r\n'
            b'To: <sip:bob@example.org>\r\nCall-ID: mikey1@192.0.2.1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n' % len(sdp)) + sdp
    add(U(sipm, 5060, 5060))
    # a MIKEY message that is a full PSK exchange with every payload type before the SIGN
    full = (hdr(T, 2) + t_ntp(RAND) + rand(ID) + idp(CERT) + cert(KEMAC) + kemac(SP, 0, bytes(20), 1) + sp(PKE, 1, 0, SRTP_PARAMS[:3]) +
            pke(DH, 2, bytes(8)) + dh(V, 1) + vp(IDR, 1) + idr(EXT, 2) + ext(SAKKE, 1, b'x') + sakke(ERR, bytes(4)) + err(SIGN, 3) + sign(0, bytes(16)))
    add(U(full))

def build_malformed():
    out = []
    ok = hdr(T, 0) + t_ntp(0)
    out.append(U(hdr(RAND, 0, ver=2) + rand(0, 8)))                    # version 2: taken for base64 text
    out.append(U(hdr(CERT, 2) + cert(0, 1, b'http://ca.example.org/cert.der')))   # URL type is parsed as DER
    out.append(U(hdr(PKE, 2) + pke(CERT) + cert(SIGN, 0)))             # SIGN payload missing
    out.append(U(bytes([1, 0])))                                       # shorter than 3 octets
    out.append(U(hdr(RAND, 0)[:9]))                                    # header cut
    out.append(U(hdr(RAND, 0, ncs=5)))                                 # SRTP ID list past the end
    out.append(U(hdr(KEMAC, 0) + bytes([0, 0, 0xff, 0xff])))           # KEMAC data length past the end
    out.append(U(hdr(KEMAC, 0) + bytes([0, 0, 0, 2, 0, 0, 1])))        # cut before the MAC algorithm
    out.append(U(hdr(KEMAC, 0) + kemac(0, 1, bytes(8), 1)[:-5]))       # MAC cut
    out.append(U(hdr(PKE, 2) + bytes([0, 0x3f, 0xff, 1, 2])))
    out.append(U(hdr(DH, 4) + bytes([0, 0, 1, 2, 3])))                 # DH value cut
    out.append(U(hdr(SIGN, 7) + bytes([0x0f, 0xff, 1, 2])))
    out.append(U(hdr(T, 0) + bytes([0, 1, 0, 0])))                     # NTP time cut
    out.append(U(hdr(ID, 0) + bytes([0, 0, 0xff, 0xff, 65, 66])))      # ID longer than the packet
    out.append(U(hdr(IDR, 0) + bytes([0, 1, 0, 0xff, 0xff, 65, 66])))
    out.append(U(hdr(CERT, 2) + bytes([0, 0, 0xff, 0xff, 1])))
    out.append(U(hdr(CERT, 2) + cert(0, 0, b'\x30\x82\x01\x00\x30')))  # bad certificate DER
    out.append(U(hdr(V, 1) + bytes([0, 1, 1, 2])))                     # MAC cut
    out.append(U(hdr(SP, 0) + bytes([0, 0, 0, 0xff, 0xff])))           # SP length past the end
    out.append(U(hdr(SP, 0) + bytes([0, 0, 0, 0, 3, 1, 9, 1])))        # SP parameter length past the end
    out.append(U(hdr(RAND, 0) + bytes([0, 200, 1, 2, 3])))
    out.append(U(hdr(ERR, 0) + bytes([0, 1])))
    out.append(U(hdr(KEMAC, 0) + kemac(0, 0, bytes([0, 0x20, 0, 50, 1, 2]), 0)))   # key data length past its payload
    out.append(U(hdr(KEMAC, 0) + kemac(0, 0, bytes([0, 0x10, 0, 4, 1, 2, 3, 4]), 0)))  # salt length missing
    out.append(U(hdr(EXT, 0) + bytes([0, 1, 0xff, 0xff, 1])))
    out.append(U(hdr(SAKKE, 0) + bytes([0, 1, 1, 0xff, 0xff])))
    out.append(U(base64.b64encode(hdr(RAND, 0))[:7]))                  # truncated base64
    out.append(U(b'!!!notbase64'))
    return out

build()

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'mikey-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'mikey-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for n, s in ranges: print(n, s)
        print(len(frames), 'frames')

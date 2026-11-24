#!/usr/bin/env python3
# Helper module for the edhoc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""EDHOC sessions over CoAP whose messages 2-4 can be decrypted with the
EDHOC secrets table (keyed by G_X: PRK_2e, TH_2, PRK_3e2m, TH_3, PRK_4e3m,
TH_4). The secrets are made-up values; the dissector does not compute the
transcript hashes or the key exchange, so none are needed here. The
keystream (EDHOC_KDF over HKDF-Expand) and the AEAD of messages 3 and 4
use the Python 'cryptography' library.

Sessions (CoAP POST requests to UDP 5683 and their responses):
  1  method 3 (DH-DH), suite 2 (AES-CCM-16-64-128, SHA-256): messages 1-4
  2  method 0 (SIGN-SIGN), suite 4 (ChaCha20/Poly1305, SHA-256): 1-4,
     PRK_3e2m = PRK_4e3m = PRK_2e, with EAD items
  3  suite 25 (SHAKE256): message 2 cannot be decrypted (no KDF)
  4  suite 2, a message 2 with a ciphertext longer than 255 * 32 octets
     (the KDF cannot make the keystream)
  5  message 3 with a broken tag

Usage: edhoc_decrypt.py <out.pcap>    writes the capture
       edhoc_decrypt.py -k            prints the -o uat:edhoc_secrets options
"""
import hashlib
import hmac
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305

# ---------------------------------------------------------------- pcap

IDENT = [0]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def udp_frame(src, sport, dst, dport, payload):
    IDENT[0] += 1
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IDENT[0], 0x4000, 64, 17, 0,
                    ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    mac = lambda a: bytes([2, 0]) + ip4(a)  # noqa: E731
    return mac(dst) + mac(src) + b'\x08\x00' + h + u


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

# ---------------------------------------------------------------- CBOR


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack('!H', n)
    return bytes([major << 5 | 26]) + struct.pack('!I', n)


def cint(v):
    return head(0, v) if v >= 0 else head(1, -1 - v)


def cbstr(b):
    return head(2, len(b)) + b


def ctstr(s):
    return head(3, len(s)) + s.encode()


def carr(n):
    return head(4, n)


def cmap(n):
    return head(5, n)

# ---------------------------------------------------------------- EDHOC


SUITES = {2: ('ccm8', 16, 13), 4: ('chacha', 32, 12), 25: ('ccm8', 16, 13)}


def edhoc_kdf(prk, label, ctx, length):
    """EDHOC_KDF: HKDF-Expand (SHA-256) with info = (label, ctx, length)."""
    info = cint(label) + cbstr(ctx) + cint(length)
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def made_up(tag, n=32):
    out, i = b'', 0
    while len(out) < n:
        out += hashlib.sha256(b'wireshark edhoc coverage %s %d' % (tag.encode(), i)).digest()
        i += 1
    return out[:n]


def enc0_aad(th):
    return carr(3) + ctstr('Encrypt0') + cbstr(b'') + cbstr(th)


def aead(suite, key, iv, plain, aad):
    alg, _, _ = SUITES[suite]
    if alg == 'ccm8':
        return AESCCM(key, tag_length=8).encrypt(iv, plain, aad)
    return ChaCha20Poly1305(key).encrypt(iv, plain, aad)


SECRETS = []


def coap(mid, payload, cf, response=False):
    code = 0x44 if response else 0x02         # 2.04 Changed / POST
    typ = 0x60 if response else 0x40          # ACK / CON
    opts = b''
    if not response:
        opts += bytes([0xb4]) + b'edhc'       # Uri-Path (11)
        opts += bytes([0x11, cf])             # Content-Format (12), delta 1
    else:
        opts += bytes([0xc1, cf])             # Content-Format (12)
    return bytes([typ, code]) + struct.pack('!H', mid) + opts + b'\xff' + payload


class Session:
    def __init__(self, name, cli, cport, srv, method, suite, gy_len=32):
        self.name, self.cli, self.cport, self.srv = name, cli, cport, srv
        self.method, self.suite, self.gy_len = method, suite, gy_len
        self.gx = made_up(name + ' G_X', gy_len)
        self.sec = {k: made_up(name + ' ' + k) for k in
                    ('PRK_2e', 'TH_2', 'PRK_3e2m', 'TH_3', 'PRK_4e3m', 'TH_4')}
        if method in (0, 2):                  # responder signs
            self.sec['PRK_3e2m'] = self.sec['PRK_2e']
        if method in (0, 1):                  # initiator signs
            self.sec['PRK_4e3m'] = self.sec['PRK_3e2m']
        SECRETS.append((self.gx, self.sec))
        self.mid = 0x100

    def req(self, payload, cf=64):
        self.mid += 1
        return udp_frame(self.cli, self.cport, self.srv, 5683, coap(self.mid, payload, cf))

    def rsp(self, payload, cf=64):
        return udp_frame(self.srv, 5683, self.cli, self.cport, coap(self.mid, payload, cf, True))

    def msg1(self, c_i=b'\x37'):
        suites = carr(2) + cint(6) + cint(self.suite) if self.suite != 6 else cint(6)
        return cint(self.method) + suites + cbstr(self.gx) + cbstr(c_i)

    def msg2(self, plain):
        ks = edhoc_kdf(self.sec['PRK_2e'], 0, self.sec['TH_2'], len(plain))
        ct = bytes(a ^ b for a, b in zip(plain, ks))
        return cbstr(made_up(self.name + ' G_Y', self.gy_len) + ct)

    def msg34(self, plain, label_k, label_iv, prk, th, bad=False):
        _, klen, ivlen = SUITES[self.suite]
        key = edhoc_kdf(self.sec[prk], label_k, self.sec[th], klen)
        iv = edhoc_kdf(self.sec[prk], label_iv, self.sec[th], ivlen)
        ct = aead(self.suite, key, iv, plain, enc0_aad(self.sec[th]))
        if bad:
            ct = ct[:-1] + bytes([ct[-1] ^ 1])
        return cbstr(ct)


EAD_PAD = cint(0) + cbstr(b'\x00\x00')        # padding EAD item
EAD_CRIT = cint(-5) + cbstr(b'\x01')          # critical, unknown


def frames():
    f = []
    # 1: DH-DH, AES-CCM-16-64-128
    s = Session('s1', '192.0.2.20', 40020, '192.0.2.21', 3, 2)
    c_r = b'\x27'
    f.append(s.req(s.msg1()))
    p2 = cbstr(c_r) + cmap(1) + cint(4) + cbstr(b'\x0a') + cbstr(made_up('s1 MAC_2', 8))
    f.append(s.rsp(s.msg2(p2)))
    p3 = cint(-12) + cbstr(made_up('s1 MAC_3', 8))     # ID_CRED_I as a compressed kid
    f.append(s.req(cbstr(c_r) + s.msg34(p3, 3, 4, 'PRK_3e2m', 'TH_3'), cf=65))
    f.append(s.rsp(s.msg34(b'', 8, 9, 'PRK_4e3m', 'TH_4')))
    # 2: SIGN-SIGN, ChaCha20/Poly1305, with EAD items
    s = Session('s2', '192.0.2.22', 40022, '192.0.2.23', 0, 4)
    f.append(s.req(s.msg1(c_i=b'\x01\x02') + EAD_PAD))
    p2 = cint(-8) + cint(-3) + cbstr(made_up('s2 sig2', 64)) + EAD_PAD
    f.append(s.rsp(s.msg2(p2)))
    p3 = cmap(1) + cint(4) + cbstr(b'\x0b\x0c') + cbstr(made_up('s2 sig3', 64)) + EAD_CRIT
    f.append(s.req(s.msg34(p3, 3, 4, 'PRK_3e2m', 'TH_3')))     # no C_R prefix (cf 64)
    f.append(s.rsp(s.msg34(EAD_PAD, 8, 9, 'PRK_4e3m', 'TH_4')))
    # 3: suite 25 (SHAKE256): no KDF for it
    # (Wireshark's COSE table gives X448 57 octets)
    s = Session('s3', '192.0.2.24', 40024, '192.0.2.25', 3, 25, gy_len=57)
    f.append(s.req(s.msg1()))
    f.append(s.rsp(s.msg2(cbstr(b'\x01') + cint(1) + cbstr(bytes(8)))))
    # 4: a message 2 longer than the KDF can expand (255 * 32 octets)
    s = Session('s4', '192.0.2.26', 40026, '192.0.2.27', 3, 2)
    f.append(s.req(s.msg1()))
    big = cbstr(b'\x01') + cint(1) + cbstr(bytes(8200))
    f.append(s.rsp(cbstr(made_up('s4 G_Y') + bytes(len(big)))))
    # 5: message 3 with a broken tag
    s = Session('s5', '192.0.2.28', 40028, '192.0.2.29', 3, 2)
    f.append(s.req(s.msg1()))
    f.append(s.rsp(s.msg2(cbstr(b'\x05') + cint(2) + cbstr(made_up('s5 MAC_2', 8)))))
    f.append(s.req(s.msg34(cint(3) + cbstr(made_up('s5 MAC_3', 8)), 3, 4, 'PRK_3e2m', 'TH_3',
                           bad=True)))
    return f


def uat_options():
    out = []
    for gx, sec in SECRETS:
        vals = [gx] + [sec[k] for k in ('PRK_2e', 'TH_2', 'PRK_3e2m', 'TH_3', 'PRK_4e3m', 'TH_4')]
        out.append('uat:edhoc_secrets:' + ','.join(v.hex() for v in vals))
    return out


if __name__ == '__main__':
    fr = frames()
    if '-k' in sys.argv:
        print('\n'.join(uat_options()))
    else:
        write_pcap(sys.argv[1] if len(sys.argv) > 1 else 'edhoc_decrypt.pcap', fr)

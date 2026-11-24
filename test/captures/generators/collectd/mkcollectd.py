#!/usr/bin/env python3
# Generates test/captures/collectd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the collectd network plugin
dissector (packet-collectd.c).

collectd sends UDP datagrams to port 25826. A datagram is a sequence of
parts: a 16 bit type, a 16 bit length (including the 4 octet header) and
the part data. String parts (host, plugin, plugin instance, type, type
instance, message) are NUL terminated, integer parts (time, interval,
severity) hold a 64 bit number, a values part holds a count, one type
octet per value and 8 octets per value. A signature part holds an
HMAC-SHA-256 of the user name and everything after it; an encryption
part holds a user name, an IV and AES-256-OFB ciphertext (key
SHA-256(password)) of a SHA-1 hash followed by more parts.

Every packet is built from scratch with struct; no captured traffic is
used. AES is implemented here (encryption only, which is all OFB needs)
so that the script needs nothing outside the standard library.

The signed and encrypted packets use user "u" with password "pw"; set the
"collectd Authentication" table with
    -o 'uat:collectd:"u","pw"'
to verify and decrypt them.

Usage: mkcollectd.py <output directory>

Writes:
  collectd-coverage.pcap            every part type, value type and
                                    severity, notifications, signed and
                                    encrypted packets, the reproducers
  collectd-coverage-malformed.pcap  parts with bad lengths, garbage, bad
                                    signatures and hashes
"""

import hashlib
import hmac
import os
import struct
import sys

SRC = (192, 0, 2, 10)
DST = (198, 51, 100, 20)
PORT = 25826

USER = b'u'
PASS = b'pw'

# ---------------------------------------------------------------- AES-256

SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        # multiply p by 3
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        # divide q by 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ (((q << 1) | (q >> 7)) & 0xff) ^ (((q << 2) | (q >> 6)) & 0xff) \
            ^ (((q << 3) | (q >> 5)) & 0xff) ^ (((q << 4) | (q >> 4)) & 0xff)
        SBOX[p] = x ^ 0x63
        if p == 1:
            break
    SBOX[0] = 0x63


_init_sbox()


def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1


def expand_key(key):
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = xtime(rcon)
        elif i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def aes_encrypt_block(rk, block):
    s = [a ^ b for a, b in zip(block, rk[0])]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        # ShiftRows (column major state)
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 14:
            n = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                n += [a[i] ^ t ^ xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = n
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def aes256_ofb(key, iv, data):
    rk = expand_key(key)
    out = bytearray()
    block = list(iv)
    for i in range(0, len(data), 16):
        block = list(aes_encrypt_block(rk, block))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], block))
    return bytes(out)


# FIPS-197 appendix C.3 self test
assert aes_encrypt_block(expand_key(bytes(range(32))),
                         bytes.fromhex('00112233445566778899aabbccddeeff')) \
    == bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')

# ---------------------------------------------------------------- packets


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src=SRC, dst=DST):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(data, ident=1, sport=40000):
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(sport, PORT, data), ident=ident))


def part(t, data):
    return struct.pack('>HH', t, 4 + len(data)) + data


def s(t, text):
    return part(t, text + b'\0')


def host(h):
    return s(0x0000, h)


def plugin(p):
    return s(0x0002, p)


def plugin_inst(p):
    return s(0x0003, p)


def ptype(p):
    return s(0x0004, p)


def type_inst(p):
    return s(0x0005, p)


def message(m):
    return s(0x0100, m)


def integer(t, v):
    return part(t, struct.pack('>Q', v))


T0 = 1700000000                 # 2023-11-14 22:13:20 UTC


def time_v4(sec):
    return integer(0x0001, sec)


def time_hr(sec, frac=0):
    return integer(0x0008, (sec << 30) | frac)


def interval_v4(sec):
    return integer(0x0007, sec)


def interval_hr(sec, frac=0):
    return integer(0x0009, (sec << 30) | frac)


def severity(v):
    return integer(0x0101, v)


def values(vals, count=None):
    """vals: list of (type, value); gauge values are little endian
    doubles, all others big endian 64 bit integers."""
    types = bytes(t for t, _ in vals)
    data = b''
    for t, v in vals:
        if t == 1:
            data += struct.pack('<d', v)
        elif t == 2:
            data += struct.pack('>q', v)
        else:
            data += struct.pack('>Q', v)
    n = len(vals) if count is None else count
    return part(0x0006, struct.pack('>H', n) + types + data)


def sign(rest, user=USER, password=PASS):
    mac = hmac.new(password, user + rest, hashlib.sha256).digest()
    return part(0x0200, mac + user) + rest


def encr(inner, user=USER, password=PASS, iv=bytes(range(16))):
    plain = hashlib.sha1(inner).digest() + inner
    ct = aes256_ofb(hashlib.sha256(password).digest(), iv, plain)
    return part(0x0210, struct.pack('>H', len(user)) + user + iv + ct)


def message_offsets_repro():
    """collectd_message_offsets.py frames 1, 3 and 4 (frame 2
    has a part with a bad length and is in the malformed capture)."""
    return [
        host(b'h1') + time_hr(1 << 10) + severity(4) + message(b'hello world'),
        host(b'h3') + part(0x100, b''),
        host(b'h4') + plugin(b'cpu') + ptype(b'cpu') + values([(1, 1.5)]),
    ]


def encr_recursion_repro(levels):
    """collectd_encr_recursion.py, with fewer levels: enough
    to reach the depth limit, not 1500."""
    p = part(0x0000, b'host\0')
    for _ in range(levels):
        p = encr(p)
    return p


def main_frames():
    pk = []
    # 1: collectd 4 style (TIME and INTERVAL in seconds)
    pk.append(host(b'v4host') + time_v4(T0) + interval_v4(10)
              + plugin(b'load') + ptype(b'load')
              + values([(1, 0.25), (1, 0.5), (1, 0.75)]))
    # 2: collectd 5 style: several values parts with changing instances
    pk.append(host(b'web1.example.org') + time_hr(T0 + 1, 1 << 29) + interval_hr(10, 1 << 28)
              + plugin(b'cpu') + plugin_inst(b'0') + ptype(b'cpu')
              + type_inst(b'user') + values([(2, 123456)])
              + type_inst(b'system') + values([(2, 65432)])
              + plugin(b'interface') + plugin_inst(b'eth0') + ptype(b'if_octets')
              + values([(0, 1000), (0, 2000)])
              + plugin(b'memory') + ptype(b'memory') + type_inst(b'free')
              + values([(1, 1048576.0)]))
    # 3: every value type, including an unknown one
    pk.append(host(b'web2.example.org') + time_hr(T0 + 2) + interval_hr(10)
              + plugin(b'test') + ptype(b'mixed')
              + values([(0, 18446744073709551615), (1, -2.5), (2, -42),
                        (3, 7), (9, 0x0123456789abcdef)]))
    # 4: values without host, time, interval, plugin instance or type
    #    instance ("Host=(null)" in the Info column)
    pk.append(plugin(b'orphan') + ptype(b'gauge') + values([(1, 3.0)]))
    # 5: notification, failure
    pk.append(host(b'web1.example.org') + time_hr(T0 + 5) + severity(1)
              + plugin(b'df') + ptype(b'df_complex')
              + message(b'Filesystem / is almost full'))
    # 6: two notifications with collectd 4 time: warning, then okay
    pk.append(host(b'web2.example.org') + time_v4(T0 + 6) + severity(2)
              + message(b'Load is high') + severity(4) + message(b'Load is normal'))
    # 7: unknown severity, message without a time part
    pk.append(host(b'web3.example.org') + severity(8) + message(b'Unknown severity'))
    # 8-10: the reproducers of the assembled item fixes
    pk += message_offsets_repro()
    # 11: unknown part types (with and without data)
    pk.append(host(b'web1.example.org') + part(0x0300, b'\x01\x02\x03\x04')
              + part(0x7fff, b'') + plugin(b'x') + ptype(b'y') + values([(1, 1.0)]))
    # 12: signed packet (verified with the UAT entry)
    pk.append(sign(host(b'signed.example.org') + time_hr(T0 + 12) + interval_hr(10)
                   + plugin(b'cpu') + ptype(b'cpu') + values([(2, 99)])))
    # 13: signed by a user who is not in the UAT (not verified)
    pk.append(sign(host(b'other.example.org') + plugin(b'cpu') + ptype(b'cpu')
                   + values([(2, 100)]), user=b'nobody', password=b'secret'))
    # 14: encrypted packet
    pk.append(encr(host(b'secret.example.org') + time_hr(T0 + 14) + interval_hr(10)
                   + plugin(b'cpu') + ptype(b'cpu') + values([(2, 77)])))
    # 15: encrypted packet holding a signed packet
    pk.append(encr(sign(host(b'both.example.org') + time_hr(T0 + 15)
                        + severity(2) + message(b'Signed and encrypted')),
                   iv=b'\xa5' * 16))
    # 16: encrypted twice
    pk.append(encr(encr(host(b'twice.example.org') + plugin(b'cpu') + ptype(b'cpu')
                        + values([(0, 5)])), iv=b'\x5a' * 16))
    # 17: encrypted for a user who is not in the UAT (not decrypted)
    pk.append(encr(host(b'hidden.example.org'), user=b'nobody', password=b'secret'))
    # 18: the reproducer of the encryption depth limit, 32 levels deep:
    #     with the UAT entry it decodes to the innermost host part at the
    #     default gui.max_tree_depth and stops with the "nested too deeply"
    #     warning with gui.max_tree_depth:40; without it, one encrypted part
    pk.append(encr_recursion_repro(32))
    return pk


def malformed_frames():
    pk = []
    good = host(b'bad.example.org')
    # 1: collectd_message_offsets.py frame 2: part length 3
    pk.append(host(b'h2') + part(0x100, b'msg\0') + struct.pack('>HH', 7, 3))
    # 2: part longer than the rest of the packet
    pk.append(good + struct.pack('>HH', 0, 100) + b'abc\0')
    # 3: 2 octets of garbage at the end
    pk.append(good + b'\x00\x00')
    # 4: integer part with only 8 octets left
    pk.append(good + struct.pack('>HHI', 8, 8, 0))
    # 5: integer part with length 10
    pk.append(good + struct.pack('>HH', 8, 10) + b'\0' * 10)
    # 6: values part with less than 15 octets left
    pk.append(good + struct.pack('>HH', 6, 10) + b'\0' * 6)
    # 7: values part with a bad length (16)
    pk.append(good + struct.pack('>HHH', 6, 16, 1) + b'\0' * 10)
    # 8: values part whose count does not match its length
    pk.append(good + plugin(b'p') + ptype(b't') + values([(1, 1.0), (1, 2.0)], count=5))
    # 9: signature part with less than 36 octets left
    pk.append(good + struct.pack('>HH', 0x200, 20) + b'\0' * 16)
    # 10: signature part with length 30
    pk.append(good + struct.pack('>HH', 0x200, 30) + b'\0' * 36)
    # 11: signature that does not match (with the UAT entry)
    pk.append(sign(good + plugin(b'p'), password=b'wrong'))
    # 12: encryption part with less than 42 octets left
    pk.append(good + struct.pack('>HH', 0x210, 30) + b'\0' * 26)
    # 13: encryption part with length 40
    pk.append(good + struct.pack('>HH', 0x210, 40) + b'\0' * 42)
    # 14: encryption part with a user name length past the part
    pk.append(good + struct.pack('>HHH', 0x210, 50, 30) + b'\0' * 44)
    # 15: encrypted with the wrong password (bad hash with the UAT entry)
    pk.append(encr(good, password=b'wrong'))
    # 16: string part with a length of 4 (empty, no NUL) and a bad part in
    #     an encrypted packet
    pk.append(encr(host(b'') + struct.pack('>HH', 0, 2)))
    # 17: interval part with length 16
    pk.append(good + struct.pack('>HH', 9, 16) + b'\0' * 12)
    # 18: severity part with length 8
    pk.append(good + struct.pack('>HH', 0x101, 8) + b'\0' * 12)
    return pk


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'collectd-coverage.pcap'),
               [frame(p, ident=i + 1) for i, p in enumerate(main_frames())])
    write_pcap(os.path.join(out, 'collectd-coverage-malformed.pcap'),
               [frame(p, ident=i + 1) for i, p in enumerate(malformed_frames())])


if __name__ == '__main__':
    main()

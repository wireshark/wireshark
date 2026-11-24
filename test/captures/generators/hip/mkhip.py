#!/usr/bin/env python3
# Generates test/captures/hip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Writes the HIP coverage captures. Usage: mkhip.py <outdir> [-v]
All packets are built with struct. Addresses are from 192.0.2.0/24 and
2001:db8::/32. HITs, keys, signatures, HMACs and puzzle/DH values are
constant placeholder octets; nothing here is key material."""
import struct
import sys
import os

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
IP6_A = bytes.fromhex("20010db8000000000000000000000001")
IP6_B = bytes.fromhex("20010db8000000000000000000000002")
HIT_A = bytes.fromhex("20010010") + b"\x00" * 11 + b"\x01"
HIT_B = bytes.fromhex("20010010") + b"\x00" * 11 + b"\x02"

I1, R1, I2, R2, UPDATE, NOTIFY, CLOSE, CLOSE_ACK = 1, 2, 3, 4, 16, 17, 18, 19


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ph(n, byte=0x11):
    """Placeholder octets."""
    return bytes([byte]) * n


def tlv(t, value, pad=True):
    b = struct.pack("!HH", t, len(value)) + value
    if pad:
        b += b"\0" * (-len(b) % 8)
    return b


def hip(ptype, params=b"", ver=1, controls=0, nxt=59, hits=(HIT_A, HIT_B),
        hlen=None, pbit=0x80, sbit=1, res=0, cksum=0):
    body = hits[0] + hits[1] + params
    total = 8 + len(body)
    if hlen is None:
        hlen = total // 8 - 1
    return (struct.pack("!BBBBHH", nxt, hlen, pbit | ptype, (ver << 4) | res | sbit,
                        cksum, controls) + body)


def fix_cksum(h, src, dst, v6):
    """Fill in the HIP checksum (pseudo-header as in packet-hip.c)."""
    n = len(h)
    if v6:
        pseudo = src + dst + struct.pack("!II", n, 139)
    else:
        pseudo = src + dst + struct.pack("!HH", 139, n)
    c = csum(pseudo + h[:4] + b"\0\0" + h[6:])
    return h[:4] + struct.pack("!H", c) + h[6:]


class Cap:
    def __init__(self):
        self.frames = []     # (bytes, caplen or None)
        self.ipid = 0x4000

    def n(self):
        return len(self.frames) + 1

    def ip(self, h, v6=False, badsum=False, src=None, dst=None, snap=None, cksum=True):
        if v6:
            s, d = src or IP6_A, dst or IP6_B
            if cksum:
                h = fix_cksum(h, s, d, True)
            if badsum:
                h = h[:4] + b"\xde\xad" + h[6:]
            iph = struct.pack("!IHBB16s16s", 0x60000000, len(h), 139, 64, s, d)
            self.frames.append((MAC_B + MAC_A + b"\x86\xdd" + iph + h, snap))
        else:
            s, d = src or IP_A, dst or IP_B
            if cksum:
                h = fix_cksum(h, s, d, False)
            if badsum:
                h = h[:4] + b"\xde\xad" + h[6:]
            self.ipid += 1
            iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(h), self.ipid, 0, 64, 139, 0, s, d)
            iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
            self.frames.append((MAC_B + MAC_A + b"\x08\x00" + iph + h, snap))

    def udp(self, h, nulls=b"\0\0\0\0", sport=10500, dport=10500, v6=False):
        payload = nulls + h
        u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        if v6:
            iph = struct.pack("!IHBB16s16s", 0x60000000, len(u), 17, 64, IP6_A, IP6_B)
            pseudo = IP6_A + IP6_B + struct.pack("!IBBBB", len(u), 0, 0, 0, 17)
            u = u[:6] + struct.pack("!H", csum(pseudo + u) or 0xffff) + u[8:]
            self.frames.append((MAC_B + MAC_A + b"\x86\xdd" + iph + u, None))
        else:
            self.ipid += 1
            iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(u), self.ipid, 0, 64, 17, 0, IP_A, IP_B)
            iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
            self.frames.append((MAC_B + MAC_A + b"\x08\x00" + iph + u, None))

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, (fr, snap) in enumerate(self.frames):
                cap = fr if snap is None else fr[:snap]
                f.write(struct.pack("<IIII", 1000 + i, 0, len(cap), len(fr)))
                f.write(cap)


# --- parameters ------------------------------------------------------------

def p_esp_info(old=0x11223344, new=0x55667788):
    return tlv(65, struct.pack("!HHII", 0, 1, old, new))


def p_r1_counter(v2=False):
    return tlv(129 if v2 else 128, struct.pack("!I", 0) + b"\0\0\0\0\0\0\0\x05")


def p_puzzle(k=10):
    return tlv(257, struct.pack("!BBH", k, 37, 0xbeef) + ph(8, 0x22))


def p_solution(k=10):
    return tlv(321, struct.pack("!BBH", k, 0, 0xbeef) + ph(8, 0x22) + ph(8, 0x33))


def p_seq(n=7):
    return tlv(385, struct.pack("!I", n))


def p_ack(*ids):
    return tlv(449, b"".join(struct.pack("!I", i) for i in ids))


def p_dh(groups):
    v = b""
    for gid, ln in groups:
        v += struct.pack("!BH", gid, ln) + ph(ln, 0x44)
    return tlv(513, v)


def p_hip_transform(*ids):
    return tlv(577, b"".join(struct.pack("!H", i) for i in ids))


def p_esp_transform(*ids):
    return tlv(4095, struct.pack("!H", 0) + b"".join(struct.pack("!H", i) for i in ids))


def p_cipher(*ids):
    return tlv(579, b"".join(struct.pack("!H", i) for i in ids))


def p_encrypted(n=24):
    return tlv(641, struct.pack("!I", 0) + ph(n, 0x55))


def p_cert():
    return tlv(768, bytes([1, 1, 1, 4]) + ph(12, 0x66))


def p_notification(code, data=b"abcd"):
    return tlv(832, struct.pack("!HH", 0, code) + data)


def p_echo(t, data=b"opaque"):
    return tlv(t, data)


def p_reg(t, lt, types, lt2=None):
    v = struct.pack("!B", lt)
    if t == 930:
        v += struct.pack("!B", lt2)
    return tlv(t, v + bytes(types))


def p_hmac(t=61505):
    return tlv(t, ph(20, 0x77))


def p_sig(t=61697, ver=1, alg=5):
    if ver == 2:
        return tlv(t, struct.pack("!H", alg) + ph(64, 0x88))
    return tlv(t, struct.pack("!B", alg) + ph(64, 0x88))


def p_locator(locs):
    v = b""
    for lt, pref in locs:
        if lt == 0:
            v += struct.pack("!BBBBI", 0, 0, 4, pref, 600) + IP6_A
        elif lt == 1:
            v += struct.pack("!BBBBI", 0, 1, 5, pref, 600) + struct.pack("!I", 0x01020304) + IP6_B
        else:
            v += (struct.pack("!BBBBI", 1, 2, 9, pref, 600) + struct.pack("!HBBII", 10500, 17, 1, 1000, 0x0a0b0c0d) + IP6_A)
    return tlv(193, v)


def p_addr_port(t):
    return tlv(t, struct.pack("!HBB", 10500, 17, 0) + IP6_B)


def host_id_v1(alg, di=(0, b""), t=0, e=b"\x01\x00\x01", n=ph(64, 0x99), flags=0x0200, proto=0xff):
    hdr = struct.pack("!HBB", flags, proto, alg)
    if alg == 3:
        key = struct.pack("!B", t) + ph(20, 0xaa) + ph(64 + 8 * t, 0xbb) * 3
    elif alg == 5:
        if len(e) < 256:
            key = struct.pack("!B", len(e)) + e + n
        else:
            key = b"\0" + struct.pack("!H", len(e)) + e + n
    else:
        key = ph(32, 0xcc)
    hi = hdr + key
    dtype, dval = di
    return tlv(705, struct.pack("!HH", len(hi), (dtype << 12) | len(dval)) + hi + dval)


def host_id_v2(alg, key, di=(0, b"")):
    dtype, dval = di
    return tlv(705, struct.pack("!HH", len(key), (dtype << 12) | len(dval))
               + struct.pack("!H", alg) + key + dval)


def rsa_key(e, n):
    if len(e) < 256:
        return struct.pack("!B", len(e)) + e + n
    return b"\0" + struct.pack("!H", len(e)) + e + n


def dsa_key(t):
    return struct.pack("!B", t) + ph(20, 0xaa) + ph(64 + 8 * t, 0xbb) * 3


def main(outdir, verbose):
    c = Cap()
    marks = []

    def mark(name):
        marks.append((c.n(), name))

    mark("I1, R1 (v1)")
    c.ip(hip(I1))
    c.ip(hip(I1, controls=1), v6=True)
    c.ip(hip(R1, p_r1_counter() + p_puzzle()
             + p_dh([(3, 192)])
             + p_hip_transform(1, 2, 3, 99) + p_esp_transform(1, 8, 9, 99)
             + host_id_v1(5, di=(1, b"host.example.net\0"))
             + p_echo(897) + p_reg(930, 10, [1, 2, 3], 20)
             + p_cert() + p_sig(61633)))
    mark("DIFFIE_HELLMAN with two groups (second group ID reproducer)")
    c.ip(hip(R1, p_dh([(3, 192), (4, 64)]) + p_puzzle() + p_sig(61633)))
    c.ip(hip(R1, p_dh([(1, 48), (0x0b, 256)]) + p_hip_transform(1) + p_sig(61633)), v6=True)
    mark("HOST_ID v1: RSA (1 and 3 octet e_len), DSA, NAI, unknown")
    c.ip(hip(R1, host_id_v1(5, di=(2, b"user@example.net")) + p_hmac()))
    c.ip(hip(R1, host_id_v1(5, e=ph(300, 0x12), n=ph(128, 0x13)) + p_hmac()))
    c.ip(hip(R1, host_id_v1(3, t=0, di=(1, b"dsa.example.net")) + p_hmac()))
    c.ip(hip(R1, host_id_v1(3, t=2) + p_hmac()))
    c.ip(hip(R1, host_id_v1(3, t=60) + p_hmac()))
    c.ip(hip(R1, host_id_v1(9) + p_hmac()))
    mark("I2, R2")
    c.ip(hip(I2, p_esp_info() + p_r1_counter() + p_solution() + p_dh([(3, 192)])
             + p_hip_transform(1) + p_esp_transform(1) + p_encrypted()
             + host_id_v1(5) + p_hmac() + p_sig(61697)))
    c.ip(hip(R2, p_esp_info() + p_hmac(61569) + p_sig(61633) + p_reg(934, 5, [1, 2])
             + p_reg(936, 3, [1]) + p_reg(932, 8, [2])))
    mark("UPDATE: SEQ, ACK, LOCATOR, ESP_INFO, RVS/relay parameters")
    c.ip(hip(UPDATE, p_esp_info() + p_locator([(0, 0), (1, 1)]) + p_seq()
             + p_ack(1, 2, 3) + p_hmac() + p_sig()))
    c.ip(hip(UPDATE, p_locator([(2, 1), (2, 0)]) + p_seq(8) + p_hmac() + p_sig()), v6=True)
    c.ip(hip(UPDATE, p_tlv_from() + p_hmac(65500) + p_tlv_via_rvs() + p_addr_port(63998)
             + p_addr_port(64002) + p_addr_port(950) + p_hmac(65520) + p_sig()))
    mark("NOTIFY, CLOSE, CLOSE_ACK, NAT traversal, transaction pacing, unknown parameter")
    c.ip(hip(NOTIFY, p_notification(7) + p_notification(16384) + p_notification(99, b"") + p_hmac()))
    c.ip(hip(CLOSE, p_echo(897, b"close") + p_echo(63661, b"x") + p_hmac() + p_sig()))
    c.ip(hip(CLOSE_ACK, p_echo(961, b"closeack") + p_echo(63425, b"yy") + p_hmac() + p_sig()))
    c.ip(hip(I1, tlv(608, struct.pack("!H", 0) + struct.pack("!HHH", 1, 2, 7)) + tlv(610, struct.pack("!I", 1000))
             + tlv(4000, ph(7, 0xee))))
    c.ip(hip(0x55 & 0x7f))              # unknown packet type
    mark("HIPv2")
    c.ip(hip(R1, p_r1_counter(True) + p_puzzle(12) + tlv(511, bytes([7, 8, 9, 0x0b, 0x77]))
             + p_cipher(1, 2, 4, 9) + tlv(715, bytes([0x10, 0x20, 0x30]))
             + tlv(2049, struct.pack("!HH", 0xfff, 0x1))
             + host_id_v2(5, rsa_key(b"\x01\x00\x01", ph(128, 0x99)), di=(1, b"v2.example.net"))
             + p_sig(61633, 2, 0x5), ver=2))
    c.ip(hip(I2, p_solution(12) + p_dh([(7, 64)]) + host_id_v2(5, rsa_key(ph(300, 0x12), ph(128, 0x13)), di=(2, b"alice@example.net"))
             + p_hmac() + p_sig(61697, 2, 7), ver=2), v6=True)
    c.ip(hip(I2, host_id_v2(3, dsa_key(0)) + p_hmac() + p_sig(61697, 2, 3), ver=2))
    c.ip(hip(I2, host_id_v2(3, dsa_key(1)) + p_hmac() + p_sig(61697, 2, 3), ver=2))
    c.ip(hip(I2, host_id_v2(7, struct.pack("!H", 1) + ph(64, 0x31)) + p_hmac() + p_sig(61697, 2, 7), ver=2))
    c.ip(hip(I2, host_id_v2(9, struct.pack("!H", 1) + ph(40, 0x32)) + p_hmac() + p_sig(61697, 2, 9), ver=2))
    c.ip(hip(I2, host_id_v2(0x77, ph(10, 0x33)) + p_hmac(), ver=2))       # unknown algorithm
    mark("HOST_ID with invalid lengths (warnings only), unknown locator type")
    c.ip(hip(R1, tlv(705, struct.pack("!HH", 12, 0) + struct.pack("!HBB", 0x200, 0xff, 5)
                     + b"\0" + struct.pack("!H", 600) + ph(4)) + p_hmac()))
    c.ip(hip(R1, tlv(705, struct.pack("!HH", 700, 0) + struct.pack("!HBB", 0x200, 0xff, 5)
                     + b"\x03" + ph(3) + ph(700, 0x11)) + p_hmac()))
    c.ip(hip(R1, tlv(705, struct.pack("!HH", 4, 0) + struct.pack("!HBB", 0x200, 0xff, 5)) + p_hmac()))
    c.ip(hip(I2, host_id_v2(5, rsa_key(ph(600, 1), ph(10))), ver=2))
    c.ip(hip(I2, host_id_v2(5, b"\x05" + ph(3)), ver=2))                   # e_len > hi_len
    c.ip(hip(I2, host_id_v2(5, rsa_key(b"\x01\x00\x01", ph(600, 0x13))), ver=2))   # n too long
    c.ip(hip(I2, host_id_v2(5, b"\0\x02\x58" + ph(8)), ver=2))
    c.ip(hip(I2, host_id_v2(7, b"\x00"), ver=2))                           # ECDSA too short
    c.ip(hip(I2, host_id_v2(3, dsa_key(60)), ver=2))                       # T too large
    c.ip(hip(UPDATE, tlv(193, bytes([0, 9, 4, 0]) + ph(20, 0x1)) + p_hmac()))
    mark("HIP in UDP 10500")
    c.udp(hip(I1, nxt=59, cksum=0))
    c.udp(hip(R1, p_r1_counter() + p_puzzle() + p_dh([(3, 192)]) + p_sig(61633), cksum=0))
    c.udp(fix_cksum(hip(UPDATE, p_seq() + p_hmac()), IP_A, IP_B, False))   # non-zero, valid checksum
    c.udp(hip(I1, cksum=0), v6=True)
    mark("end")
    main_n = len(c.frames)
    c.write(os.path.join(outdir, "hip-coverage.pcap"))
    if verbose:
        for n, name in marks:
            print(n, name)
        print("main frames", main_n)
    mal(outdir)


def p_tlv_from():
    return tlv(65498, IP6_A)


def p_tlv_via_rvs():
    return tlv(65502, IP6_A + IP6_B)


def mal(outdir):
    m = Cap()
    # Bad checksum (error expert info)
    m.ip(hip(I1), badsum=True)
    m.udp(hip(UPDATE, p_seq() + p_hmac(), cksum=0xabcd))
    m.ip(hip(I1), v6=True, badsum=True)
    # Not UDP-encapsulated HIP: no four null octets
    m.udp(hip(I1), nulls=b"\0\0\0\1")
    m.udp(b"")
    m.udp(b"", nulls=b"\0\0")
    # Capture cut short: no checksum verification
    m.ip(hip(R1, p_r1_counter() + p_puzzle() + p_sig(61633)), snap=90)
    # Header length beyond the packet; truncated TLVs
    m.ip(hip(R1, p_puzzle(), hlen=20))
    m.ip(hip(R1, p_puzzle()[:10], hlen=6))
    m.ip(hip(I1)[:20])
    # HOST_ID v1 problems: e_len too large, hi_len too large, short
    m.ip(hip(R1, tlv(705, struct.pack("!HH", 2, 0) + b"\x02\x00")))
    m.ip(hip(R1, tlv(705, struct.pack("!HH", 5, 1 << 12) + struct.pack("!HBB", 0x200, 0xff, 3) + b"\x00"), ))
    # HOST_ID v2 problems
    m.ip(hip(I2, host_id_v2(3, ph(10, 1)), ver=2))                         # DSA truncated
    # Signature (v2) shorter than the algorithm field
    m.ip(hip(I2, tlv(61697, b"\x05"), ver=2))
    m.ip(hip(I2, tlv(61697, b""), ver=2))
    # Unknown locator type; locator cut short
    m.ip(hip(UPDATE, tlv(193, bytes([0, 1, 4, 0, 0, 0, 2, 88]) + ph(8))))
    m.ip(hip(UPDATE, tlv(193, bytes([0, 0, 4, 0]) + ph(10))))
    m.ip(hip(UPDATE, tlv(193, bytes([0, 2, 9, 1]) + ph(10))))
    # TLV lengths: overrun, zero length parameters, odd lengths
    m.ip(hip(R1, struct.pack("!HH", 257, 5000) + ph(8)))
    m.ip(hip(R1, struct.pack("!HH", 513, 3) + b"\x03\xff\xff\0"))
    m.ip(hip(R1, tlv(513, struct.pack("!BH", 3, 4000) + ph(10))))
    m.ip(hip(R1, tlv(321, b"")))
    m.ip(hip(R1, tlv(257, b"")))
    m.ip(hip(R1, tlv(65, b"\0\0")))
    m.ip(hip(R1, tlv(65502, ph(10))))
    m.ip(hip(R1, tlv(65498, ph(4))))
    m.ip(hip(R1, tlv(4095, b"\0")))
    m.ip(hip(R1, tlv(930, b"")))
    m.ip(hip(R1, tlv(641, b"")))
    m.ip(hip(R1, tlv(832, b"\0\0")))
    m.ip(hip(R1, tlv(768, b"\0\0")))
    m.write(os.path.join(outdir, "hip-coverage-malformed.pcap"))


if __name__ == "__main__":
    main(sys.argv[1], "-v" in sys.argv)

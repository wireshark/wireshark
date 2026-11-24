#!/usr/bin/env python3
# Generates test/captures/corosync_totemnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Totemnet dissector of
the Corosync cluster engine (packet-corosync-totemnet.c).

Totemnet is the transport layer of Corosync on UDP ports 5404-5405. A
packet is either a plain Totem SRP message or an encrypted one: a SHA-1
HMAC digest (20 octets), a salt (16 octets) and the Totem SRP message
encrypted with the SOBER-128 stream cipher, optionally followed by a
crypto type octet (0 = SOBER, corosync 1.x). The keys are derived from
a private key and the salt with SOBER-128 as in corosync's totemnet.c;
the dissector tries every key of the corosync_totemnet.private_keys
preference. Every packet is built from scratch with struct; SOBER-128
is implemented below (tables from wsutil/sober128.c, 32 bit words). No
captured traffic is used.

Usage: mkcorosync_totemnet.py <output directory>

Writes:
  corosync-totemnet-coverage.pcap            plain and encrypted Totem
                                             SRP messages, with and
                                             without the crypto type
                                             octet, with each of the
                                             configured keys
  corosync-totemnet-coverage-malformed.pcap  packets that are too short
                                             or cannot be decrypted
"""

import hashlib
import hmac
import os
import struct
import sys

KEYS = ['wrongkey', 'secret', 'other key']

MULTAB = [
    0x00000000, 0xd02b4367, 0xed5686ce, 0x3d7dc5a9, 0x97ac41d1, 0x478702b6,
    0x7afac71f, 0xaad18478, 0x631582ef, 0xb33ec188, 0x8e430421, 0x5e684746,
    0xf4b9c33e, 0x24928059, 0x19ef45f0, 0xc9c40697, 0xc62a4993, 0x16010af4,
    0x2b7ccf5d, 0xfb578c3a, 0x51860842, 0x81ad4b25, 0xbcd08e8c, 0x6cfbcdeb,
    0xa53fcb7c, 0x7514881b, 0x48694db2, 0x98420ed5, 0x32938aad, 0xe2b8c9ca,
    0xdfc50c63, 0x0fee4f04, 0xc154926b, 0x117fd10c, 0x2c0214a5, 0xfc2957c2,
    0x56f8d3ba, 0x86d390dd, 0xbbae5574, 0x6b851613, 0xa2411084, 0x726a53e3,
    0x4f17964a, 0x9f3cd52d, 0x35ed5155, 0xe5c61232, 0xd8bbd79b, 0x089094fc,
    0x077edbf8, 0xd755989f, 0xea285d36, 0x3a031e51, 0x90d29a29, 0x40f9d94e,
    0x7d841ce7, 0xadaf5f80, 0x646b5917, 0xb4401a70, 0x893ddfd9, 0x59169cbe,
    0xf3c718c6, 0x23ec5ba1, 0x1e919e08, 0xcebadd6f, 0xcfa869d6, 0x1f832ab1,
    0x22feef18, 0xf2d5ac7f, 0x58042807, 0x882f6b60, 0xb552aec9, 0x6579edae,
    0xacbdeb39, 0x7c96a85e, 0x41eb6df7, 0x91c02e90, 0x3b11aae8, 0xeb3ae98f,
    0xd6472c26, 0x066c6f41, 0x09822045, 0xd9a96322, 0xe4d4a68b, 0x34ffe5ec,
    0x9e2e6194, 0x4e0522f3, 0x7378e75a, 0xa353a43d, 0x6a97a2aa, 0xbabce1cd,
    0x87c12464, 0x57ea6703, 0xfd3be37b, 0x2d10a01c, 0x106d65b5, 0xc04626d2,
    0x0efcfbbd, 0xded7b8da, 0xe3aa7d73, 0x33813e14, 0x9950ba6c, 0x497bf90b,
    0x74063ca2, 0xa42d7fc5, 0x6de97952, 0xbdc23a35, 0x80bfff9c, 0x5094bcfb,
    0xfa453883, 0x2a6e7be4, 0x1713be4d, 0xc738fd2a, 0xc8d6b22e, 0x18fdf149,
    0x258034e0, 0xf5ab7787, 0x5f7af3ff, 0x8f51b098, 0xb22c7531, 0x62073656,
    0xabc330c1, 0x7be873a6, 0x4695b60f, 0x96bef568, 0x3c6f7110, 0xec443277,
    0xd139f7de, 0x0112b4b9, 0xd31dd2e1, 0x03369186, 0x3e4b542f, 0xee601748,
    0x44b19330, 0x949ad057, 0xa9e715fe, 0x79cc5699, 0xb008500e, 0x60231369,
    0x5d5ed6c0, 0x8d7595a7, 0x27a411df, 0xf78f52b8, 0xcaf29711, 0x1ad9d476,
    0x15379b72, 0xc51cd815, 0xf8611dbc, 0x284a5edb, 0x829bdaa3, 0x52b099c4,
    0x6fcd5c6d, 0xbfe61f0a, 0x7622199d, 0xa6095afa, 0x9b749f53, 0x4b5fdc34,
    0xe18e584c, 0x31a51b2b, 0x0cd8de82, 0xdcf39de5, 0x1249408a, 0xc26203ed,
    0xff1fc644, 0x2f348523, 0x85e5015b, 0x55ce423c, 0x68b38795, 0xb898c4f2,
    0x715cc265, 0xa1778102, 0x9c0a44ab, 0x4c2107cc, 0xe6f083b4, 0x36dbc0d3,
    0x0ba6057a, 0xdb8d461d, 0xd4630919, 0x04484a7e, 0x39358fd7, 0xe91eccb0,
    0x43cf48c8, 0x93e40baf, 0xae99ce06, 0x7eb28d61, 0xb7768bf6, 0x675dc891,
    0x5a200d38, 0x8a0b4e5f, 0x20daca27, 0xf0f18940, 0xcd8c4ce9, 0x1da70f8e,
    0x1cb5bb37, 0xcc9ef850, 0xf1e33df9, 0x21c87e9e, 0x8b19fae6, 0x5b32b981,
    0x664f7c28, 0xb6643f4f, 0x7fa039d8, 0xaf8b7abf, 0x92f6bf16, 0x42ddfc71,
    0xe80c7809, 0x38273b6e, 0x055afec7, 0xd571bda0, 0xda9ff2a4, 0x0ab4b1c3,
    0x37c9746a, 0xe7e2370d, 0x4d33b375, 0x9d18f012, 0xa06535bb, 0x704e76dc,
    0xb98a704b, 0x69a1332c, 0x54dcf685, 0x84f7b5e2, 0x2e26319a, 0xfe0d72fd,
    0xc370b754, 0x135bf433, 0xdde1295c, 0x0dca6a3b, 0x30b7af92, 0xe09cecf5,
    0x4a4d688d, 0x9a662bea, 0xa71bee43, 0x7730ad24, 0xbef4abb3, 0x6edfe8d4,
    0x53a22d7d, 0x83896e1a, 0x2958ea62, 0xf973a905, 0xc40e6cac, 0x14252fcb,
    0x1bcb60cf, 0xcbe023a8, 0xf69de601, 0x26b6a566, 0x8c67211e, 0x5c4c6279,
    0x6131a7d0, 0xb11ae4b7, 0x78dee220, 0xa8f5a147, 0x958864ee, 0x45a32789,
    0xef72a3f1, 0x3f59e096, 0x0224253f, 0xd20f6658,
]

SBOX = [
    0xa3aa1887, 0xd65e435c, 0x0b65c042, 0x800e6ef4, 0xfc57ee20, 0x4d84fed3,
    0xf066c502, 0xf354e8ae, 0xbb2ee9d9, 0x281f38d4, 0x1f829b5d, 0x735cdf3c,
    0x95864249, 0xbc2e3963, 0xa1f4429f, 0xf6432c35, 0xf7f40325, 0x3cc0dd70,
    0x5f973ded, 0x9902dc5e, 0xda175b42, 0x590012bf, 0xdc94d78c, 0x39aab26b,
    0x4ac11b9a, 0x8c168146, 0xc3ea8ec5, 0x058ac28f, 0x52ed5c0f, 0x25b4101c,
    0x5a2db082, 0x370929e1, 0x2a1843de, 0xfe8299fc, 0x202fbc4b, 0x833915dd,
    0x33a803fa, 0xd446b2de, 0x46233342, 0x4fcee7c3, 0x3ad607ef, 0x9e97ebab,
    0x507f859b, 0xe81f2e2f, 0xc55b71da, 0xd7e2269a, 0x1339c3d1, 0x7ca56b36,
    0xa6c9def2, 0xb5c9fc5f, 0x5927b3a3, 0x89a56ddf, 0xc625b510, 0x560f85a7,
    0xace82e71, 0x2ecb8816, 0x44951e2a, 0x97f5f6af, 0xdfcbc2b3, 0xce4ff55d,
    0xcb6b6214, 0x2b0b83e3, 0x549ea6f5, 0x9de041af, 0x792f1f17, 0xf73b99ee,
    0x39a65ec0, 0x4c7016c6, 0x857709a4, 0xd6326e01, 0xc7b280d9, 0x5cfb1418,
    0xa6aff227, 0xfd548203, 0x506b9d96, 0xa117a8c0, 0x9cd5bf6e, 0xdcee7888,
    0x61fcfe64, 0xf7a193cd, 0x050d0184, 0xe8ae4930, 0x88014f36, 0xd6a87088,
    0x6bad6c2a, 0x1422c678, 0xe9204de7, 0xb7c2e759, 0x0200248e, 0x013b446b,
    0xda0d9fc2, 0x0414a895, 0x3a6cc3a1, 0x56fef170, 0x86c19155, 0xcf7b8a66,
    0x551b5e69, 0xb4a8623e, 0xa2bdfa35, 0xc4f068cc, 0x573a6acd, 0x6355e936,
    0x03602db9, 0x0edf13c1, 0x2d0bb16d, 0x6980b83c, 0xfeb23763, 0x3dd8a911,
    0x01b6bc13, 0xf55579d7, 0xf55c2fa8, 0x19f4196e, 0xe7db5476, 0x8d64a866,
    0xc06e16ad, 0xb17fc515, 0xc46feb3c, 0x8bc8a306, 0xad6799d9, 0x571a9133,
    0x992466dd, 0x92eb5dcd, 0xac118f50, 0x9fafb226, 0xa1b9cef3, 0x3ab36189,
    0x347a19b1, 0x62c73084, 0xc27ded5c, 0x6c8bc58f, 0x1cdde421, 0xed1e47fb,
    0xcdcc715e, 0xb9c0ff99, 0x4b122f0f, 0xc4d25184, 0xaf7a5e6c, 0x5bbf18bc,
    0x8dd7c6e0, 0x5fb7e420, 0x521f523f, 0x4ad9b8a2, 0xe9da1a6b, 0x97888c02,
    0x19d1e354, 0x5aba7d79, 0xa2cc7753, 0x8c2d9655, 0x19829da1, 0x531590a7,
    0x19c1c149, 0x3d537f1c, 0x50779b69, 0xed71f2b7, 0x463c58fa, 0x52dc4418,
    0xc18c8c76, 0xc120d9f0, 0xafa80d4d, 0x3b74c473, 0xd09410e9, 0x290e4211,
    0xc3c8082b, 0x8f6b334a, 0x3bf68ed2, 0xa843cc1b, 0x8d3c0ff3, 0x20e564a0,
    0xf8f55a4f, 0x2b40f8e7, 0xfea7f15f, 0xcf00fe21, 0x8a6d37d6, 0xd0d506f1,
    0xade00973, 0xefbbde36, 0x84670fa8, 0xfa31ab9e, 0xaedab618, 0xc01f52f5,
    0x6558eb4f, 0x71b9e343, 0x4b8d77dd, 0x8cb93da6, 0x740fd52d, 0x425412f8,
    0xc5a63360, 0x10e53ad0, 0x5a700f1c, 0x8324ed0b, 0xe53dc1ec, 0x1a366795,
    0x6d549d15, 0xc5ce46d7, 0xe17abe76, 0x5f48e0a0, 0xd0f07c02, 0x941249b7,
    0xe49ed6ba, 0x37a47f78, 0xe1cfffbd, 0xb007ca84, 0xbb65f4da, 0xb59f35da,
    0x33d2aa44, 0x417452ac, 0xc0d674a7, 0x2d61a46a, 0xdc63152a, 0x3e12b7aa,
    0x6e615927, 0xa14fb118, 0xa151758d, 0xba81687b, 0xe152f0b3, 0x764254ed,
    0x34c77271, 0x0a31acab, 0x54f94aec, 0xb9e994cd, 0x574d9e81, 0x5b623730,
    0xce8a21e8, 0x37917f0b, 0xe8a9b5d6, 0x9697adf8, 0xf3d30431, 0x5dcac921,
    0x76b35d46, 0xaa430a36, 0xc2194022, 0x22bca65e, 0xdaec70ba, 0xdfaea8cc,
    0x777bae8b, 0x242924d5, 0x1f098a5a, 0x4b396b81, 0x55de2522, 0x435c1cb8,
    0xaeb8fe1d, 0x9db3c697, 0x5b164f83, 0xe0c16376, 0xa319224c, 0xd0203b35,
    0x433ac0fe, 0x1466a19a, 0x45f0b24f, 0x51fda998, 0xc0d52d71, 0xfa0896a8,
    0xf9e6053f, 0xa4b0d300, 0xd499cbcc, 0xb95e3d40,
]

M32 = 0xffffffff
N = 17


class Sober128:
    def __init__(self):
        self.R = [1, 1]
        for i in range(2, N):
            self.R.append((self.R[i - 1] + self.R[i - 2]) & M32)
        self.konst = 0x6996c53a
        self.flag = True
        self.initR = None
        self.sbuf = 0
        self.nbuf = 0

    def _step(self, z):
        R = self.R
        r0 = R[z % N]
        R[z % N] = (R[(z + 15) % N] ^ R[(z + 4) % N] ^ ((r0 << 8) & M32) ^
                    MULTAB[(r0 >> 24) & 0xff])

    def _cycle(self):
        self._step(0)
        self.R = self.R[1:] + self.R[:1]

    def _nl(self, z):
        R = self.R
        t = (R[z % N] + R[(z + 16) % N]) & M32
        t ^= SBOX[(t >> 24) & 0xff]
        t = ((t >> 8) | (t << 24)) & M32
        t = (((t + R[(z + 1) % N]) & M32) ^ self.konst) + R[(z + 6) % N]
        t &= M32
        t ^= SBOX[(t >> 24) & 0xff]
        return (t + R[(z + 13) % N]) & M32

    def _diffuse(self):
        for z in range(N):
            self._step(z)
            t = self._nl(z + 1)
            self.R[(z + 1 + 4) % N] ^= t

    def _absorb(self, buf):
        for i in range(len(buf) // 4):
            k = struct.unpack('<I', buf[i * 4:i * 4 + 4])[0]
            self.R[15] = (self.R[15] + k) & M32
            self._cycle()
            self.R[4] ^= self._nl(0)
        self.R[15] = (self.R[15] + len(buf)) & M32
        self._diffuse()

    def add_entropy(self, buf):
        if self.flag:
            self._absorb(buf)
            while True:
                self._cycle()
                k = self._nl(0)
                if k & 0xff000000:
                    break
            self.konst = k
            self.initR = list(self.R)
            self.flag = False
        else:
            self.R = list(self.initR)
            self._absorb(buf)
        self.nbuf = 0

    def read(self, n):
        """Key stream bytes (the dissector XORs them into the data). For
        n >= 68 the C code uses unrolled rounds that are equivalent to
        cycling word by word."""
        out = bytearray()
        while n >= 4:
            self._cycle()
            out += struct.pack('<I', self._nl(0))
            n -= 4
        if n:
            self._cycle()
            out += struct.pack('<I', self._nl(0))[:n]
        return bytes(out)


def encrypt(key, salt, plain, crypto_type=None):
    """Encrypt like corosync's totemnet.c, with the private key handling
    of the dissector: the key is copied into a buffer of
    (strlen + 4) & 0xfc octets, NUL padded."""
    klen = (len(key) + 4) & 0xfc
    pk = key.encode()[:max(klen - 1, 0)].ljust(klen, b'\0')
    kg = Sober128()
    kg.add_entropy(pk)
    kg.add_entropy(salt)
    keys = kg.read(48)
    iv, cipher_key, hmac_key = keys[0:16], keys[16:32], keys[32:48]
    st = Sober128()
    st.add_entropy(cipher_key)
    st.add_entropy(iv)
    ks = st.read(len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, ks))
    digest = hmac.new(hmac_key, salt + cipher, hashlib.sha1).digest()
    return digest + salt + cipher + (b'' if crypto_type is None else bytes([crypto_type]))


# ---- Totem SRP messages (little endian) ----------------------------------

ORF, MCAST, MERGE, JOIN, COMMIT, CANCEL = range(6)
AF_INET = 2


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


def header(mtype, encap, nodeid):
    return struct.pack('BB', mtype, encap) + b'\x22\xff' + u32(nodeid)


def ip(nodeid):
    return u32(nodeid) + u16(AF_INET) + bytes([192, 0, 2, nodeid]) + b'\0' * 12


def ring_id(nodeid, seq):
    return ip(nodeid) + u64(seq)


def srp_addr(nodeid):
    return ip(nodeid) + ip(nodeid)


def orf_token(sender, seq, token_seq, aru, ring, rtr=()):
    return (header(ORF, 0, sender) + u32(seq) + u32(token_seq) + u32(aru) + u32(sender) +
            ring + u32(0) + u32(1) + u32(0) + u32(len(rtr)) + b''.join(rtr))


def mcast(sender, encap, seq, ring, payload):
    return (header(MCAST, encap, sender) + srp_addr(sender) + u32(seq) + u32(seq) + ring +
            u32(sender) + u32(0) + payload)


def join(sender, ring_seq, procs, failed):
    return (header(JOIN, 0, sender) + srp_addr(sender) + u32(len(procs)) + u32(len(failed)) +
            u64(ring_seq) + b''.join(srp_addr(p) for p in procs) +
            b''.join(srp_addr(p) for p in failed))


def commit(sender, ring, members):
    entries = b''.join(ring_id(1, 0x1000) + u32(10) + u32(10) + u32(1) for _ in members)
    return (header(COMMIT, 0, sender) + u32(1) + ring + u32(0) + u32(1) + u32(len(members)) +
            b''.join(srp_addr(m) for m in members) + entries)


def merge_detect(sender, ring):
    return header(MERGE, 0, sender) + srp_addr(sender) + ring


def cancel(sender, ring):
    return header(CANCEL, 0, sender) + ring


# ---- frames ----------------------------------------------------------------

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(src_node, payload, dst=None, ident=1, port=5405):
    src = bytes([192, 0, 2, src_node])
    dst = dst or bytes([239, 192, 104, 1])
    udp = struct.pack('>HHHH', port - 1, port, 8 + len(payload), 0)
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, 8 + len(payload))
    c = csum(pseudo + udp + payload) or 0xffff
    udp = udp[:6] + struct.pack('>H', c)
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), ident, 0, 64, 17, 0,
                      src, dst)
    iph = iph[:10] + struct.pack('>H', csum(iph)) + iph[12:]
    smac = b'\x02\x00\x00\x00\x00' + bytes([src_node])
    dmac = (b'\x01\x00\x5e' + bytes([dst[1] & 0x7f, dst[2], dst[3]]) if dst[0] >= 224
            else b'\x02\x00\x00\x00\x00' + bytes([dst[3]]))
    return dmac + smac + b'\x08\x00' + iph + udp + payload


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1767225600 + i, 0, len(fr), len(fr)))
            f.write(fr)


def salt(n):
    return bytes((n * 16 + k) & 0xff for k in range(16))


def main_frames():
    F = []
    ring = ring_id(1, 0x1004)
    node2 = bytes([192, 0, 2, 2])
    # 1: plain ORF token (no key decrypts it)
    F.append(udp_frame(1, orf_token(1, 7, 20, 18, ring), node2))
    # 2: ORF token encrypted with "secret", crypto type octet 0 (SOBER)
    F.append(udp_frame(2, encrypt('secret', salt(2), orf_token(2, 8, 21, 19, ring), 0),
                       bytes([192, 0, 2, 3])))
    # 3: mcast encrypted with "secret" and the crypto type octet (the key
    #    and form of the previous packet are tried first)
    F.append(udp_frame(1, encrypt('secret', salt(3),
                                  mcast(1, 2, 22, ring, b'corosync cpg payload'), 0)))
    # 4: mcast encrypted with "secret" without the crypto type octet
    #    (corosync 0.x)
    F.append(udp_frame(2, encrypt('secret', salt(4),
                                  mcast(2, 2, 23, ring, b'no crypto type octet'))))
    # 5: join encrypted with "other key" and the crypto type octet
    F.append(udp_frame(3, encrypt('other key', salt(5), join(3, 0x1008, [1, 2, 3], []), 0)))
    # 6: commit token encrypted with "other key", 3 members
    F.append(udp_frame(1, encrypt('other key', salt(6), commit(1, ring_id(1, 0x1008),
                                                               [1, 2, 3]), 0), node2))
    # 7: encapsulated mcast encrypted with "secret" (keys tried again)
    inner = mcast(3, 2, 19, ring, b'retransmitted payload')
    F.append(udp_frame(2, encrypt('secret', salt(7), mcast(2, 1, 24, ring, inner), 0)))
    # 8: plain merge detect after encrypted packets
    F.append(udp_frame(3, merge_detect(3, ring_id(3, 0x1008))))
    # 9: plain token hold cancel
    F.append(udp_frame(2, cancel(2, ring_id(1, 0x1008))))
    # 10: ORF token with a retransmission entry, encrypted with "secret"
    #     without the crypto type octet, 68 octets or more of cipher text
    F.append(udp_frame(1, encrypt('secret', salt(10),
                                  orf_token(1, 30, 40, 39, ring,
                                            [ring_id(2, 0x1004) + u32(40)])), node2))
    return F


def malformed_frames():
    F = []
    # 1: 20 octets: too short to be encrypted, too short for Totem SRP
    F.append(udp_frame(1, header(ORF, 0, 1) + b'\0' * 12))
    # 2: encrypted with "secret" but crypto type octet 1 (NSS): not
    #    decrypted, dissected as plain Totem SRP
    F.append(udp_frame(2, encrypt('secret', salt(12), cancel(2, ring_id(1, 0x1008)), 1)))
    # 3: encrypted with a key that is not configured
    F.append(udp_frame(3, encrypt('unknown', salt(13), cancel(3, ring_id(1, 0x1008)), 0)))
    # 4: encrypted with "secret", cipher text cut short (digest mismatch)
    F.append(udp_frame(1, encrypt('secret', salt(14), cancel(1, ring_id(1, 0x1008)), 0)[:-9]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'corosync-totemnet-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'corosync-totemnet-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

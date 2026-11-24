#!/usr/bin/env python3
# Generates test/captures/ssh_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SSH dissector
(packet-ssh.c). Nothing comes from a real network.

No key is used anywhere: no key log, no pcapng secrets, no shared secret.
SSH packets are only readable by the dissector when the negotiated cipher
is "none" (and the MAC "none"); the first connection negotiates that, so
the "decrypted" packet code (user authentication, channels, SFTP, rekey
...) runs without any decryption. Connections that negotiate real ciphers
only show the key exchange; their "encrypted" packets are filler bytes
that stay opaque.

Usage: mkssh.py <output directory>

Writes:
  ssh-coverage.pcap            see README.md
  ssh-coverage-malformed.pcap  bad lengths, unknown messages, short
                               and truncated key exchange messages
"""
import os
import struct
import sys

P = lambda fmt, *a: struct.pack('>' + fmt, *a)
CMAC = bytes.fromhex("020000000001")
SMAC = bytes.fromhex("020000000002")
SRV_IP = "192.0.2.2"
CLI_IP = "192.0.2.1"


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


class Stream:
    """One TCP connection; all segments are appended to the shared list."""

    def __init__(self, frames, cport=40000, sport=22, cip=CLI_IP, sip=SRV_IP):
        self.frames = frames
        self.cl = (cip, cport)
        self.sv = (sip, sport)
        self.seq = {0: 1000, 1: 50000}

    def seg(self, srv, payload=b"", flags=0x18, seq=None, opt=False):
        src, dst = (self.sv, self.cl) if srv else (self.cl, self.sv)
        d = 1 if srv else 0
        if seq is None:
            seq = self.seq[d]
            self.seq[d] += (0 if opt else len(payload)) + (1 if flags & 0x03 else 0)
        ack = self.seq[1 - d] if flags & 0x10 else 0
        hl = 6 if opt else 5
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, hl << 4, flags, 65535, 0, 0) + payload
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip4(src[0]), ip4(dst[0]))
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        pseudo = ip4(src[0]) + ip4(dst[0]) + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
        eth = (SMAC if srv else CMAC) + (CMAC if srv else SMAC) + b"\x08\x00"
        self.frames.append(eth + iph + tcp)

    def handshake(self):
        mss = b"\x02\x04\x05\xb4"
        self.seg(False, mss, 0x02, opt=True)
        self.seg(True, mss, 0x12, opt=True)
        self.seg(False, b"", 0x10)

    def close(self):
        self.seg(False, b"", 0x11)
        self.seg(True, b"", 0x11)
        self.seg(False, b"", 0x10)

    def c(self, payload):
        self.seg(False, payload)

    def s(self, payload):
        self.seg(True, payload)

    def split(self, srv, payload, cuts):
        """Send payload in pieces cut at the given offsets."""
        last = 0
        for c in list(cuts) + [len(payload)]:
            self.seg(srv, payload[last:c])
            last = c


# ----------------------------------------------------------------------
# SSH encoding helpers

def sstr(b):
    if isinstance(b, str):
        b = b.encode()
    return P('I', len(b)) + b


def mpint(n):
    """RFC 4251 mpint of a non-negative integer."""
    if n == 0:
        return P('I', 0)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\0' + b
    return sstr(b)


def fill(n, seed=0):
    """Made-up filler of n octets (not ciphertext)."""
    return bytes((seed * 31 + k * 7 + (k >> 3)) & 0xff for k in range(n))


def pkt(payload, padlen=None):
    """SSH binary packet without encryption or MAC."""
    if padlen is None:
        padlen = 8 - ((5 + len(payload)) % 8)
        if padlen < 4:
            padlen += 8
    plen = 1 + len(payload) + padlen
    return P('IB', plen, padlen) + payload + bytes((0x50 + k) & 0xff for k in range(padlen))


def kexinit(cookie, kex, hostkey="ssh-ed25519", enc="aes128-ctr", mac="hmac-sha2-256",
            comp="none", enc_s2c=None, mac_s2c=None, comp_s2c=None, lang="", follows=0):
    p = bytes([20]) + cookie
    for nl in (kex, hostkey, enc, enc_s2c or enc, mac, mac_s2c or mac, comp, comp_s2c or comp, lang, lang):
        p += sstr(nl)
    p += bytes([follows]) + b"\0\0\0\0"
    return pkt(p)


def cookie(n):
    return bytes((n * 16 + k) & 0xff for k in range(16))


def hostkey(kind):
    if kind == 'rsa':
        return sstr(sstr("ssh-rsa") + mpint(65537) + mpint((1 << 2047) + 12345))
    if kind == 'dss':
        return sstr(sstr("ssh-dss") + mpint((1 << 1023) + 7) + mpint((1 << 159) + 1)
                    + mpint((1 << 1000) + 3) + mpint((1 << 1020) + 5))
    if kind == 'ecdsa':
        return sstr(sstr("ecdsa-sha2-nistp256") + sstr("nistp256") + sstr(b"\x04" + fill(64, 3)))
    if kind == 'ed25519':
        return sstr(sstr("ssh-ed25519") + sstr(fill(32, 4)))
    return sstr(sstr("ssh-unknown-type") + fill(20, 5))      # unknown type


def hostblob(kind):
    """Same host key without the outer length (as in userauth blobs)."""
    return hostkey(kind)[4:]


def hostsig(kind):
    if kind == 'rsa':
        return sstr(sstr("ssh-rsa") + mpint((1 << 2040) + 99))
    if kind == 'dss':
        return sstr(sstr("ssh-dss") + mpint((1 << 319) + 1))
    return sstr(sstr("ssh-ed25519") + sstr(fill(64, 7)))     # other: length + data


def ecdh_init(q=None):
    return pkt(bytes([30]) + sstr(q if q is not None else fill(32, 1)))


def ecdh_reply(kind='ed25519', q=None, sigkind='ed25519'):
    return pkt(bytes([31]) + hostkey(kind) + sstr(q if q is not None else fill(32, 2)) + hostsig(sigkind))


def dh_init(e=None):
    return pkt(bytes([30]) + mpint(e if e is not None else (1 << 2000) + 17))


def dh_reply(kind='rsa', f=None, sigkind='rsa'):
    return pkt(bytes([31]) + hostkey(kind) + mpint(f if f is not None else (1 << 2001) + 19) + hostsig(sigkind))


NEWKEYS = pkt(bytes([21]))


def banner(s):
    return s.encode() + b"\r\n"


# --- messages for the "none" cipher connection --------------------------

def m_service_request(name="ssh-userauth"):
    return pkt(bytes([5]) + sstr(name))


def m_service_accept(name="ssh-userauth"):
    return pkt(bytes([6]) + sstr(name))


def ext(name, value):
    return sstr(name) + sstr(value)


def m_ext_info(exts):
    return pkt(bytes([7]) + P('I', len(exts)) + b"".join(exts))


def m_userauth(user, service, method, rest=b""):
    return pkt(bytes([50]) + sstr(user) + sstr(service) + sstr(method) + rest)


def m_disconnect(reason=11, desc="bye", lang=""):
    return pkt(bytes([1]) + P('I', reason) + sstr(desc) + sstr(lang))


def m_ignore(data=b"xyz"):
    return pkt(bytes([2]) + sstr(data))


def m_debug(always=1, msg="debug text", lang=""):
    return pkt(bytes([4]) + bytes([always]) + sstr(msg) + sstr(lang))


def chan_open(typ, sender, window=2097152, maxpkt=32768):
    return pkt(bytes([90]) + sstr(typ) + P('III', sender, window, maxpkt))


def chan_confirm(recipient, sender, window=2097152, maxpkt=32768):
    return pkt(bytes([91]) + P('IIII', recipient, sender, window, maxpkt))


def chan_data(recipient, data):
    return pkt(bytes([94]) + P('I', recipient) + sstr(data))


def chan_edata(recipient, code, data):
    return pkt(bytes([95]) + P('II', recipient, code) + sstr(data))


def chan_req(recipient, name, want, rest=b""):
    return pkt(bytes([98]) + P('I', recipient) + sstr(name) + bytes([want]) + rest)


def chan_simple(code, recipient):
    return pkt(bytes([code]) + P('I', recipient))


def term_modes():
    out = b""
    for op, val in ((1, 3), (2, 28), (3, 127), (4, 21), (5, 4), (6, 0), (7, 0), (8, 17), (9, 19),
                    (10, 26), (11, 25), (12, 18), (13, 23), (14, 22), (15, 15), (16, 20), (17, 0),
                    (18, 0), (30, 0), (31, 1), (32, 1), (33, 1), (34, 0), (35, 0), (36, 1), (37, 1),
                    (38, 1), (39, 1), (40, 1), (41, 1), (42, 1), (43, 1), (44, 1), (45, 0), (46, 1),
                    (47, 0), (48, 1), (49, 1), (50, 1), (51, 1), (52, 1), (53, 1), (54, 1), (55, 1),
                    (56, 1), (57, 1), (58, 1), (59, 1), (60, 1), (61, 1), (62, 1), (70, 1), (71, 1),
                    (72, 1), (73, 1), (74, 1), (75, 1), (90, 1), (91, 1), (92, 0), (93, 1),
                    (128, 38400), (129, 38400), (200, 7)):
        out += bytes([op]) + P('I', val)
    return out + bytes([0])


def sftp(typ, body=b""):
    return P('IB', 1 + len(body), typ) + body


def sftp_attrs(flags=0x0f, size=1234):
    out = P('I', flags)
    if flags & 1:
        out += P('Q', size)
    if flags & 2:
        out += P('II', 1000, 100)
    if flags & 4:
        out += P('I', 0o100644)
    if flags & 8:
        out += P('II', 1700000000, 1700000100)
    return out


# ----------------------------------------------------------------------

def conn_none(fr, cport=40000, port=22):
    """Cipher none, MAC none: everything after NEWKEYS is readable."""
    s = Stream(fr, cport, port)
    s.handshake()
    kex = "curve25519-sha256,kex-strict-c-v00@openssh.com"
    kexs = "curve25519-sha256,kex-strict-s-v00@openssh.com"
    s.c(banner("SSH-2.0-OpenSSH_9.9"))
    s.s(banner("SSH-2.0-OpenSSH_9.9 Debian-1"))
    s.c(kexinit(cookie(1), kex, enc="none", mac="none"))
    s.s(kexinit(cookie(2), kexs, enc="none", mac="none"))
    s.c(ecdh_init())
    s.s(ecdh_reply() + NEWKEYS)                  # two SSH packets in one segment
    s.c(NEWKEYS)
    # user authentication
    s.c(m_service_request())
    s.s(m_ext_info([ext("server-sig-algs", "ssh-ed25519,rsa-sha2-256,rsa-sha2-512"),
                    ext("delay-compression", sstr("zlib@openssh.com,none") + sstr("zlib@openssh.com,none")),
                    ext("no-flow-control", "p"), ext("elevation", "y"),
                    ext("publickey-algorithms@roumenpetrov.info", "x509v3-ssh-rsa,ssh-rsa"),
                    ext("ping@openssh.com", "0"), ext("global-requests-ok", ""),
                    ext("other-extension", "some value")]) + m_service_accept())
    s.c(m_userauth("alice", "ssh-connection", "none"))
    s.s(pkt(bytes([51]) + sstr("publickey,password") + bytes([0])))
    blob_ed = hostblob('ed25519')
    s.c(m_userauth("alice", "ssh-connection", "publickey",
                   bytes([0]) + sstr("ssh-ed25519") + sstr(blob_ed)))
    s.s(pkt(bytes([60]) + sstr("ssh-ed25519") + sstr(blob_ed)))
    sig = sstr("ssh-ed25519") + sstr(fill(64, 8))
    s.c(m_userauth("alice", "ssh-connection", "publickey",
                   bytes([1]) + sstr("ssh-ed25519") + sstr(blob_ed) + sstr(sig)))
    # every key type as the public key blob (rsa, dss, ecdsa, unknown)
    for kind, alg in (('rsa', "ssh-rsa"), ('dss', "ssh-dss"), ('ecdsa', "ecdsa-sha2-nistp256"),
                      ('unknown', "ssh-unknown-type")):
        s.c(m_userauth("alice", "ssh-connection", "publickey",
                       bytes([0]) + sstr(alg) + sstr(hostblob(kind))))
    s.c(m_userauth("alice", "ssh-connection", "publickey-hostbound-v00@openssh.com",
                   bytes([1]) + sstr("ssh-ed25519") + sstr(blob_ed) + hostkey('ed25519') + sstr(sig)))
    s.c(m_userauth("alice", "ssh-connection", "password", bytes([0]) + sstr("secret-password")))
    s.c(m_userauth("alice", "ssh-connection", "password",
                   bytes([1]) + sstr("old-password") + sstr("new-password")))
    s.s(pkt(bytes([52])))                                         # USERAUTH_SUCCESS
    # transport messages, connection protocol
    s.s(pkt(bytes([80]) + sstr("hostkeys-00@openssh.com") + bytes([0]) + hostkey('ed25519') + hostkey('rsa')))
    s.c(pkt(bytes([80]) + sstr("no-more-sessions@openssh.com") + bytes([1])))
    s.s(pkt(bytes([81])))
    s.c(pkt(bytes([80]) + sstr("hostkeys-prove-00@openssh.com") + bytes([1]) + hostkey('ed25519')))
    s.s(pkt(bytes([82])))
    s.c(m_ignore(b"padding data"))
    s.s(m_debug())
    s.c(pkt(bytes([192]) + sstr(b"ping data")))                # PING: ext ping offered
    s.s(pkt(bytes([193]) + sstr(b"ping data")))                # PONG
    s.c(pkt(bytes([200])))                                     # other local extension
    # session channel with SFTP (client channel 10, server channel 20)
    s.c(chan_open("session", 10))
    s.s(chan_confirm(10, 20))
    s.c(chan_req(20, "env", 0, sstr("LANG") + sstr("C.UTF-8")))
    s.c(chan_req(20, "pty-req", 1, sstr("xterm") + P('IIII', 80, 24, 640, 480) + sstr(term_modes())))
    s.s(chan_simple(99, 10))
    s.c(chan_req(20, "subsystem", 1, sstr("sftp")))
    s.s(chan_simple(99, 10))
    s.c(chan_data(20, sftp(1, P('I', 3))))                     # SFTP INIT
    s.s(chan_data(10, sftp(2, P('I', 3))))                     # SFTP VERSION
    s.c(chan_data(20, sftp(3, P('I', 1) + sstr("/tmp/a.txt") + P('I', 0x1a) + sftp_attrs(0x0f))))
    s.s(chan_data(10, sftp(102, P('I', 1) + sstr(b"\x00\x00\x00\x01\x02\x03\x04\xff"))))
    # a big SFTP WRITE spread over three CHANNEL_DATA, followed by a CLOSE
    # that starts in the last chunk, and an SFTP READ cut in the middle
    h = b"\x00\x00\x00\x01\x02\x03\x04\xff"
    big = sftp(6, P('I', 2) + sstr(h) + P('Q', 0) + sstr(fill(3000, 9)))
    closep = sftp(4, P('I', 3) + sstr(h))
    readp = sftp(5, P('I', 4) + sstr(h) + P('Q', 0) + P('I', 32768))
    stream = big + closep + readp
    n1, n2 = 1400, len(big) + 7
    s.c(chan_data(20, stream[:n1]))
    s.c(chan_data(20, stream[n1:n2]))
    s.c(chan_data(20, stream[n2:len(stream) - 5]))
    s.c(chan_data(20, stream[len(stream) - 5:]))
    s.s(chan_data(10, sftp(101, P('I', 2) + P('I', 0) + sstr("OK") + sstr("en"))))
    # one segment holding two SSH packets, and an SSH packet in two segments
    s.s(chan_data(10, sftp(101, P('I', 3) + P('I', 0) + sstr("OK") + sstr("en")))
        + chan_data(10, sftp(101, P('I', 4) + P('I', 1) + sstr("EOF") + sstr("en"))))
    big2 = chan_data(20, sftp(7, P('I', 5) + sstr("/home/alice/some/long/path/name/to/stat")))
    s.split(False, big2, [3, 30])
    s.s(pkt(bytes([93]) + P('II', 10, 65536)))                  # window adjust
    # a PDU whose length field is cut in two
    pa = sftp(11, P('I', 6) + sstr("/home/alice"))
    s.c(chan_data(20, pa[:2]))
    s.c(chan_data(20, pa[2:]))
    # a PDU in four chunks: the length field arrives one octet at a time, then the rest in two parts
    pc = sftp(5, P('I', 8) + sstr(h) + P('Q', 8192) + P('I', 4096))
    for part in (pc[:1], pc[1:2], pc[2:14], pc[14:]):
        s.c(chan_data(20, part))
    s.s(chan_data(10, sftp(101, P('I', 6) + P('I', 0) + sstr("OK") + sstr("en"))))
    # shell channel (client 11, server 21), exec channel (12 / 22), plain channel (13 / 23)
    s.c(chan_open("session", 11))
    s.s(chan_confirm(11, 21))
    s.c(chan_req(21, "shell", 1))
    s.s(chan_simple(99, 11))
    s.c(chan_data(21, b"ls -l\n"))
    s.s(chan_data(11, b"total 0\n-rw-r--r-- 1 alice alice 0 Jan  1 00:00 a\n"))
    s.s(chan_edata(11, 1, b"warning on stderr\n"))
    s.c(chan_open("session", 12))
    s.s(chan_confirm(12, 22))
    s.c(chan_req(22, "exec", 1, sstr("uname -a")))
    s.s(chan_data(12, b"Linux host 6.1.0\n"))
    s.s(chan_req(12, "exit-status", 0, P('I', 0)))
    s.c(chan_open("direct-tcpip", 13))
    s.s(chan_confirm(13, 23))
    s.s(chan_data(13, b"\x01\x02\x03raw bytes"))                # channel without a handler
    s.c(chan_req(23, "keepalive@openssh.com", 1))
    for ch in (10, 11, 12, 13):
        s.c(chan_simple(96, ch + 10))                           # EOF
        s.s(chan_simple(97, ch))                                # CLOSE
        s.c(chan_simple(97, ch + 10))
    # rekey in the "decrypted" stream
    s.c(kexinit(cookie(3), kex, enc="none", mac="none"))
    s.s(kexinit(cookie(4), kexs, enc="none", mac="none"))
    s.c(ecdh_init(fill(32, 11)))
    s.s(ecdh_reply('ed25519', fill(32, 12)))
    s.s(NEWKEYS)
    s.c(NEWKEYS)
    s.c(m_ignore(b"after rekey"))
    s.s(m_disconnect(11, "by application", "en"))
    s.close()
    return s


def conn_enc(fr, cport, port, kex, hk, enc, mac, kind, mk_init, mk_reply, version="SSH-2.0-libssh_0.10.6",
             nenc=3, sig=None, ):
    s = Stream(fr, cport, port)
    s.handshake()
    s.c(banner(version))
    s.s(banner("SSH-2.0-OpenSSH_8.4p1"))
    s.c(kexinit(cookie(cport & 0xf), kex, hostkey=hk, enc=enc, mac=mac))
    s.s(kexinit(cookie(0x10 + (cport & 0xf)), kex, hostkey=hk, enc=enc, mac=mac))
    return s


def encrypted_flow(s, sizes, mac_len=0, plaintext_len=False):
    """Filler 'encrypted' packets: client and server alternate."""
    srv = False
    for i, n in enumerate(sizes):
        body = fill(n, 20 + i)
        if plaintext_len:
            body = P('I', n - 4 - mac_len) + body[4:]
        s.seg(srv, body)
        srv = not srv


def build_clean(outdir):
    fr = []
    conn_none(fr, 40000, 22)

    # B: ecdh-sha2-nistp256, aes128-ctr, hmac-sha2-256, no keys
    s = conn_enc(fr, 40001, 22, "ecdh-sha2-nistp256", "ecdsa-sha2-nistp256", "aes128-ctr",
                 "hmac-sha2-256", 'ecdsa', None, None)
    s.c(m_ignore(b"before the key exchange") + pkt(bytes([30]) + sstr(b"\x04" + fill(64, 1))))
    s.s(pkt(bytes([31]) + hostkey('ecdsa') + sstr(b"\x04" + fill(64, 2)) + hostsig('ed25519')) + NEWKEYS)
    s.c(NEWKEYS)
    encrypted_flow(s, [52, 100, 36, 68, 164])
    s.close()

    # C: diffie-hellman-group14-sha256 with rsa host key, hmac-sha1 over aes256-ctr, SSH-1.99 banner
    s = Stream(fr, 40002, 22)
    s.handshake()
    s.c(banner("SSH-1.99-Cisco-1.25"))
    s.s(banner("SSH-1.99-Cisco-1.25"))
    s.c(kexinit(cookie(5), "diffie-hellman-group14-sha256,diffie-hellman-group1-sha1", hostkey="ssh-rsa",
                enc="aes256-ctr,aes128-cbc", mac="hmac-sha1,hmac-md5", comp="zlib@openssh.com,none"))
    s.s(kexinit(cookie(6), "diffie-hellman-group14-sha256", hostkey="ssh-rsa",
                enc="aes256-ctr", mac="hmac-sha1", comp="none"))
    s.c(dh_init())
    s.s(dh_reply('rsa') + NEWKEYS)
    s.c(NEWKEYS)
    encrypted_flow(s, [52, 100, 84, 36])
    s.close()

    # D: group exchange, dss host key, aes128-cbc + hmac-md5 and hmac-ripemd160, request messages
    s = Stream(fr, 40003, 22)
    s.handshake()
    s.c(banner("SSH-2.0-dropbear_2022.83"))
    s.s(banner("SSH-2.0-dropbear_2022.83"))
    s.c(kexinit(cookie(7), "diffie-hellman-group-exchange-sha256", hostkey="ssh-dss",
                enc="aes128-cbc", mac="hmac-md5", mac_s2c="hmac-ripemd160"))
    s.s(kexinit(cookie(8), "diffie-hellman-group-exchange-sha256", hostkey="ssh-dss",
                enc="aes128-cbc", mac="hmac-md5", mac_s2c="hmac-ripemd160"))
    s.c(pkt(bytes([30]) + P('I', 2048)))                                  # REQUEST_OLD
    s.c(pkt(bytes([34]) + P('III', 1024, 2048, 8192)))                    # REQUEST
    s.s(pkt(bytes([31]) + mpint((1 << 2047) + 1) + mpint(2)))             # GROUP
    s.c(pkt(bytes([32]) + mpint((1 << 2040) + 3)))                        # INIT
    s.s(pkt(bytes([33]) + hostkey('dss') + mpint((1 << 2041) + 5) + hostsig('dss')) + NEWKEYS)
    s.c(NEWKEYS)
    encrypted_flow(s, [52, 84, 36])
    s.close()

    # E: chacha20-poly1305 (implicit MAC), curve25519-sha256@libssh.org, hostkey of unknown type
    s = Stream(fr, 40004, 22)
    s.handshake()
    s.c(banner("SSH-2.0-paramiko_3.4.0"))
    s.s(banner("SSH-2.0-paramiko_3.4.0"))
    kx = "curve25519-sha256@libssh.org"
    s.c(kexinit(cookie(9), kx, hostkey="ssh-unknown-type", enc="chacha20-poly1305@openssh.com", mac="hmac-sha2-256"))
    s.s(kexinit(cookie(10), kx, hostkey="ssh-unknown-type", enc="chacha20-poly1305@openssh.com", mac="hmac-sha2-256"))
    s.c(ecdh_init())
    s.s(ecdh_reply('unknown', None, 'ed25519') + NEWKEYS)
    s.c(NEWKEYS)
    encrypted_flow(s, [52, 100, 36])
    s.close()

    # F: AES-GCM (length in the clear, implicit MAC), curve448
    for i, (enc, kx) in enumerate((("aes128-gcm@openssh.com", "curve448-sha512"),
                                   ("aes256-gcm@openssh.com", "ecdh-sha2-nistp384"))):
        s = Stream(fr, 40005 + i, 22)
        s.handshake()
        s.c(banner("SSH-2.0-OpenSSH_9.3"))
        s.s(banner("SSH-2.0-OpenSSH_9.3"))
        s.c(kexinit(cookie(11 + i), kx, enc=enc, mac="hmac-sha2-256"))
        s.s(kexinit(cookie(13 + i), kx, enc=enc, mac="hmac-sha2-256"))
        s.c(ecdh_init())
        s.s(ecdh_reply() + NEWKEYS)
        s.c(NEWKEYS)
        encrypted_flow(s, [52 + 16, 100 + 16, 36 + 16], mac_len=16, plaintext_len=True)
        s.close()

    # G: post-quantum hybrid key exchanges
    for i, (kx, pc, ps, tl, enc) in enumerate((
            ("sntrup761x25519-sha512@openssh.com", 1158, 1039, 32, "aes256-ctr"),
            ("mlkem768x25519-sha256", 1184, 1088, 32, "aes256-ctr"),
            ("mlkem768nistp256-sha256", 1184, 1088, 65, "aes128-ctr"),
            ("mlkem1024nistp384-sha384", 1568, 1568, 97, "aes192-ctr"))):
        s = Stream(fr, 40010 + i, 22)
        s.handshake()
        s.c(banner("SSH-2.0-OpenSSH_10.0"))
        s.s(banner("SSH-2.0-OpenSSH_10.0"))
        s.c(kexinit(cookie(15 + i), kx, enc=enc))
        s.s(kexinit(cookie(19 + i), kx, enc=enc))
        s.c(pkt(bytes([30]) + sstr(fill(pc + tl, 30 + i))))
        s.s(pkt(bytes([31]) + hostkey('ed25519') + sstr(fill(ps + tl, 40 + i)) + hostsig('ed25519')) + NEWKEYS)
        s.c(NEWKEYS)
        encrypted_flow(s, [52, 36])
        s.close()

    # H: heuristic (port 2222): split banners, two banner lines in one segment,
    # and key exchange packets split over segments
    s = Stream(fr, 40020, 2222)
    s.handshake()
    s.split(False, banner("SSH-2.0-split_banner_1"), [6, 12])
    s.s(banner("SSH-2.0-first_line") + banner("SSH-2.0-second_line") + banner("SSH-2.0-third_line"))
    ki = kexinit(cookie(23), "ecdh-sha2-nistp256", hostkey="ecdsa-sha2-nistp256", enc="aes128-ctr")
    s.split(False, ki, [2, 60, 200])
    s.split(True, kexinit(cookie(24), "ecdh-sha2-nistp256", hostkey="ecdsa-sha2-nistp256", enc="aes128-ctr"), [3])
    s.c(pkt(bytes([30]) + sstr(b"\x04" + fill(64, 1))))
    s.split(True, pkt(bytes([31]) + hostkey('ecdsa') + sstr(b"\x04" + fill(64, 2)) + hostsig('ed25519')) + NEWKEYS, [100])
    s.c(NEWKEYS)
    encrypted_flow(s, [52, 100])
    s.close()

    # I: SSH-1 protocol
    s = Stream(fr, 40021, 22)
    s.handshake()
    s.c(banner("SSH-1.5-OpenSSH_1.2.27"))
    s.s(banner("SSH-1.5-OpenSSH_1.2.27"))
    def v1(plen, msg, body):
        pad = 8 - plen % 8
        return P('I', plen) + bytes(pad) + bytes([msg]) + body
    s.s(v1(0x1d, 2, fill(0x1d - 1, 1)))          # SSH_SMSG_PUBLIC_KEY
    s.c(v1(0x15, 3, fill(0x15 - 1, 2)))          # SSH_CMSG_SESSION_KEY
    s.s(fill(100, 3))
    s.split(False, v1(0x25, 4, fill(0x25 - 1, 4)), [2, 20])
    s.close()

    # J: cipher none with a real MAC name: the packets cannot be checked and stay
    # "encrypted" (the MAC is the 20 filler octets after each packet)
    s = Stream(fr, 40030, 22)
    s.handshake()
    s.c(banner("SSH-2.0-mac_none_cipher"))
    s.s(banner("SSH-2.0-mac_none_cipher"))
    mk = "hmac-sha1-etm@openssh.com"
    s.c(kexinit(cookie(30), "curve25519-sha256", enc="none", mac=mk))
    s.s(kexinit(cookie(31), "curve25519-sha256", enc="none", mac=mk))
    s.c(ecdh_init())
    s.s(ecdh_reply() + NEWKEYS)
    s.c(NEWKEYS)
    s.c(m_ignore(b"mac check") + fill(20, 1))
    s.s(m_ignore(b"mac check 2") + fill(20, 2))
    s.close()

    # J2: the reproducer of the over-read of calc_mac: a MAC named hmac-x-1024 (128 octets,
    # more than the 48 octets the dissector can compute; refused since the fix)
    s = Stream(fr, 40031, 22)
    s.handshake()
    s.c(banner("SSH-2.0-client"))
    s.s(banner("SSH-2.0-server"))
    s.c(kexinit(cookie(32), "curve25519-sha256", enc="none", mac="hmac-x-1024"))
    s.s(kexinit(cookie(33), "curve25519-sha256", enc="none", mac="hmac-x-1024"))
    s.c(ecdh_init())
    s.s(ecdh_reply() + NEWKEYS)
    s.c(NEWKEYS)
    s.c(m_ignore(b"") + b"\x66" * 128)
    s.close()

    # K: capture started in the middle of a connection (no banner, server first)
    s = Stream(fr, 40032, 22)
    s.handshake()
    s.s(fill(84, 50))
    s.c(fill(68, 51))
    s.close()

    # L: other ciphers and MACs that are only named (no keys): every cipher and MAC name
    # the dissector knows, and one it does not
    for i, (enc, mac) in enumerate((("chacha20-poly1305", "hmac-sha2-256"), ("aes128-gcm", "hmac-sha2-256"),
                                    ("aes256-gcm", "hmac-sha2-256"), ("aes192-cbc", "hmac-sha2-512"),
                                    ("aes256-cbc", "umac-64@openssh.com"), ("3des-cbc", "hmac-sha2-256-etm@openssh.com"),
                                    ("aes128-cbc", "hmac-sha2-256"), ("aes192-ctr", "hmac-md5-96"))):
        s = Stream(fr, 40040 + i, 22)
        s.handshake()
        s.c(banner("SSH-2.0-named_ciphers"))
        s.s(banner("SSH-2.0-named_ciphers"))
        s.c(kexinit(cookie(40 + i), "ecdh-sha2-nistp521", hostkey="ecdsa-sha2-nistp521", enc=enc, mac=mac, comp="zlib,none"))
        s.s(kexinit(cookie(50 + i), "ecdh-sha2-nistp521", hostkey="ecdsa-sha2-nistp521", enc=enc, mac=mac, comp="zlib"))
        s.c(ecdh_init())
        s.s(ecdh_reply() + NEWKEYS)
        s.c(NEWKEYS)
        encrypted_flow(s, [52, 68], mac_len=0)
        s.close()

    # M: not SSH at all on a port the heuristic looks at
    s = Stream(fr, 40050, 2223)
    s.handshake()
    s.c(b"hello, this is not ssh\r\n")
    s.close()

    pcap(os.path.join(outdir, "ssh-coverage.pcap"), fr)


def none_setup(fr, cport, kexname="curve25519-sha256", port=22):
    """Cipher none, MAC none connection up to the first NEWKEYS."""
    s = Stream(fr, cport, port)
    s.handshake()
    s.c(banner("SSH-2.0-OpenSSH_9.9"))
    s.s(banner("SSH-2.0-OpenSSH_9.9"))
    s.c(kexinit(cookie(1), kexname, enc="none", mac="none"))
    s.s(kexinit(cookie(2), kexname, enc="none", mac="none"))
    s.c(ecdh_init())
    s.s(ecdh_reply() + NEWKEYS)
    s.c(NEWKEYS)
    return s


def kex_conn(fr, cport, kex, enc="aes128-ctr", hk="ssh-ed25519", port=22):
    s = Stream(fr, cport, port)
    s.handshake()
    s.c(banner("SSH-2.0-bad_kex"))
    s.s(banner("SSH-2.0-bad_kex"))
    s.c(kexinit(cookie(60 + cport % 7), kex, hostkey=hk, enc=enc))
    s.s(kexinit(cookie(70 + cport % 7), kex, hostkey=hk, enc=enc))
    return s


def build_malformed(outdir):
    fr = []
    # decrypted-stream problems (cipher none)
    s = none_setup(fr, 41000)
    s.c(m_userauth("alice", "ssh-connection", "keyboard-interactive", sstr("") + sstr("")))
    s.c(m_userauth("alice", "ssh-connection", "unknownmethod", b"\x01\x02\x03"))
    blob_ed = hostblob('ed25519')
    s.c(m_userauth("alice", "ssh-connection", "publickey",
                   bytes([0]) + sstr("ssh-ed25519") + sstr(blob_ed + b"\xaa\xbb\xcc")))      # blob longer than parsed
    s.s(pkt(bytes([60]) + sstr("ssh-ed25519") + sstr(blob_ed + b"\xaa\xbb\xcc")))             # same in PK_OK
    s.c(m_userauth("alice", "ssh-connection", "publickey",
                   bytes([1]) + sstr("ssh-ed25519") + sstr(blob_ed)
                   + sstr(sstr("ssh-ed25519") + sstr(fill(8, 1)) + b"extra")))               # signature longer than parsed
    s.s(pkt(bytes([53]) + sstr("banner text\n") + sstr("en")))                                # USERAUTH_BANNER
    s.s(pkt(bytes([3]) + P('I', 5)))                                                          # UNIMPLEMENTED
    s.s(pkt(bytes([8])))                                                                      # NEWCOMPRESS
    s.c(pkt(bytes([130]) + b"client protocol"))                                              # reserved for clients
    s.c(pkt(bytes([80]) + sstr("tcpip-forward") + bytes([1]) + sstr("0.0.0.0") + P('I', 8080)))
    s.c(chan_data(99, b"data on a channel nobody opened"))                                   # no channels at all
    s.c(chan_edata(99, 1, b"extended data on a channel nobody opened"))
    s.s(pkt(bytes([100]) + P('I', 13)))                                                      # CHANNEL_FAILURE with a body
    s.s(pkt(bytes([92]) + P('II', 5, 2) + sstr("no") + sstr("")))                            # OPEN_FAILURE
    s.c(pkt(bytes([192]) + b"x"))                                                            # local extension, no ping offered
    s.c(pkt(bytes([193])))
    s.c(pkt(bytes([2]) + sstr(b"short"), padlen=2))                                          # padding below 4
    s.c(P('I', 12) + bytes([200]) + bytes([2]) + sstr(b"") + b"\0\0\0")                       # padding > packet
    # channel opened later; the request names the channel before the confirmation
    s.c(chan_req(77, "subsystem", 1, sstr("sftp")))
    s.c(chan_open("session", 5))
    s.s(chan_confirm(5, 77))
    s.c(chan_data(77, sftp(1, P('I', 3))))
    # a server opened channel
    s.s(chan_open("forwarded-tcpip", 3))
    s.c(chan_confirm(3, 4))
    s.s(chan_req(4, "exec", 0, sstr("x")))
    s.s(chan_data(3, b"to the client"))
    s.c(chan_data(4, b"to the server"))
    # a trailing partial packet at the end of the stream (cut off)
    s.c(chan_data(77, fill(100, 3))[:40])
    s.close()

    # key exchange packets with invalid lengths, one connection per method
    s = kex_conn(fr, 41001, "diffie-hellman-group14-sha256", hk="ssh-rsa")
    s.c(pkt(bytes([30]) + P('I', 0)))                                  # e with length 0
    s.s(pkt(bytes([31]) + hostkey('rsa') + P('I', 2000) + hostsig('rsa')[:8]))
    s = kex_conn(fr, 41002, "diffie-hellman-group-exchange-sha256", hk="ssh-rsa")
    s.c(pkt(bytes([32]) + P('I', 5000)))                                # e too long
    s.s(pkt(bytes([33]) + hostkey('rsa') + P('I', 0) + hostsig('rsa')))
    s = kex_conn(fr, 41003, "ecdh-sha2-nistp256", hk="ecdsa-sha2-nistp256")
    s.c(pkt(bytes([30]) + P('I', 0)))
    s.s(pkt(bytes([31]) + hostkey('ecdsa') + P('I', 0) + hostsig('ed25519')))
    # host key and signature whose declared length differs from what is parsed
    bad_hk = sstr(sstr("ssh-ed25519") + sstr(fill(32, 4)) + b"xxxx")
    bad_sig = sstr(sstr("ssh-ed25519") + sstr(fill(64, 7)) + b"yyyyyy")
    s = kex_conn(fr, 41004, "curve25519-sha256")
    s.c(ecdh_init())
    s.s(pkt(bytes([31]) + bad_hk + sstr(fill(32, 2)) + bad_sig))
    # post-quantum hybrid: lengths 0 and wrong sizes
    for i, (kx, pc, ps, tl) in enumerate((("mlkem768x25519-sha256", 1184, 1088, 32),
                                          ("mlkem1024nistp384-sha384", 1568, 1568, 97))):
        s = kex_conn(fr, 41005 + i, kx)
        s.c(pkt(bytes([30]) + P('I', 0)))
        s.s(pkt(bytes([31]) + hostkey('ed25519') + P('I', 0) + hostsig('ed25519')))
        s.c(pkt(bytes([30]) + sstr(fill(pc + tl - 7, 1))))
        s.s(pkt(bytes([31]) + hostkey('ed25519') + sstr(fill(ps + tl + 9, 2)) + hostsig('ed25519')))
        s.c(pkt(bytes([32]) + b"unknown hybrid message"))
    # unknown key exchange method (the dissector logs a warning)
    s = kex_conn(fr, 41007, "unknown-kex-sha1")
    s.c(pkt(bytes([30]) + sstr(fill(32, 1))))
    s.s(pkt(bytes([31]) + hostkey('ed25519') + sstr(fill(32, 2)) + hostsig('ed25519')))
    # packet lengths
    s = kex_conn(fr, 41008, "curve25519-sha256")
    s.c(P('I', 0x7ffffff0) + bytes([4, 30]) + fill(40, 1))              # overly large length (shown when reassembly is off)
    s = kex_conn(fr, 41009, "curve25519-sha256")
    s.c(ecdh_init()[:30])                                              # cut off
    s.s(kexinit(cookie(80), "curve25519-sha256")[:100])
    s.close()
    # SSH 1: overly large length, then packets
    s = Stream(fr, 41010, 22)
    s.handshake()
    s.c(banner("SSH-1.5-bad"))
    s.s(banner("SSH-1.5-bad"))
    s.s(P('I', 0x7ffffff0) + bytes(8) + bytes([2]) + fill(60, 5))
    s.c(P('I', 30) + bytes(2) + fill(20, 6))                           # cut off
    s.close()
    # truncated banner and an unterminated banner at the end of the capture
    s = Stream(fr, 41011, 22)
    s.handshake()
    s.c(b"SSH-2.0-no_newline")
    s.close()
    # SSH over SCTP is not covered (no SCTP capture), nothing more here
    pcap(os.path.join(outdir, "ssh-coverage-malformed.pcap"), fr)


if __name__ == "__main__":
    build_clean(sys.argv[1])
    build_malformed(sys.argv[1])

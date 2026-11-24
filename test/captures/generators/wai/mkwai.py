#!/usr/bin/env python3
# Generates test/captures/wai_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-wai.c (WAI, WAPI authentication, ethertype 0x88b4).
    mkwai.py <outdir>
Writes wai-coverage.pcap and wai-coverage-malformed.pcap

No cryptography: certificates, signatures, challenges and MACs are filler
bytes.
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        if flags == 0x02: ack = 0
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02\x01\x01' if flags & 2 else b''
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

AE = b'\x02\0\0\0\0\x0a'
ASUE = b'\x02\0\0\0\0\x0b'
ADDID = AE + ASUE
ADDID_OPT = b'\x0a\0\0\0\0\x0a' + ASUE      # first octet has bit 3 set: optional field present

def ident(data=b'AE-identity-0001', id_=1):
    return struct.pack('!HH', id_, len(data)) + data

def cert(n=48, id_=1, fill=0x30):
    return struct.pack('!HH', id_, n) + bytes([fill]) * n

def ecdh(content=b'\x2a\x86\x48\xce\x3d\x03\x01\x01', id_=1):
    return struct.pack('!BH', id_, len(content)) + content

def keydata(n):
    return bytes([n]) + bytes(range(n))

def chal(b=0x77):
    return bytes([b]) * 32

def idlist(n=2):
    body = b'\0' + struct.pack('!H', n) + b''.join(ident(b'id-%d' % i) for i in range(n))
    return b'\x03' + struct.pack('!H', len(body)) + body

def sig(idata=b'ASUE-identity-01', siglen=48, plen=24):
    alg_body = bytes([1, 1]) + struct.pack('!BH', 1, plen) + b'\x55' * plen
    alg = struct.pack('!H', len(alg_body)) + alg_body
    val = struct.pack('!H', siglen) + b'\x99' * siglen
    body = ident(idata) + alg + val
    return b'\x01' + struct.pack('!H', len(body)) + body

def multicert(n1=40, n2=44):
    body = chal(0x11) + chal(0x22) + b'\0' + cert(n1) + b'\0' + cert(n2, 2, 0x31)
    return b'\x02' + struct.pack('!H', len(body)) + body

FLAG = lambda v=0: bytes([v])

def wai(subtype, data, seq=1, frag=0, more=0, version=1, type_=1, length=None):
    hdr = struct.pack('!HBBHHHBB', version, type_, subtype, 0, 12 + len(data) if length is None else length, seq, frag, more)
    return struct.pack('!6s6sH', MAC_S, MAC_C, 0x88b4) + hdr + data

def main(outdir):
    f = []
    add = lambda *a, **k: f.append(wai(*a, **k))
    # 1 pre-authentication, 2 STAKey request
    add(1, FLAG(0x80) + b'\x01' + ADDID + b'\xc0' * 16 + b'\x11' * 20, seq=1)
    add(2, FLAG(0x7f) + b'\x05\x02' + ADDID + b'\xc1' * 16 + b'\x12' * 20, seq=2)
    # 3 authentication activation
    add(3, FLAG(0x02) + b'\xa1' * 32 + ident(b'Local-ASU-id') + cert(60) + ecdh(), seq=3)
    add(3, FLAG(0x00) + b'\xa1' * 32 + ident(b'Local-ASU-id') + cert(60, 2) + ecdh(b'detailed parameters', 2), seq=4)
    add(3, FLAG(0xff) + b'\xa1' * 32 + ident(b'') + cert(36, 7) + ecdh(b'', 9), seq=5)
    # 4 access authentication request: without and with the optional identity list
    base = b'\xa2' * 32 + chal(0x33) + keydata(5) + ident(b'AE-identity') + cert(50) + ecdh()
    add(4, FLAG(0x00) + base + sig(), seq=6)
    add(4, FLAG(0x08) + base + idlist(3) + sig(), seq=7)
    add(4, FLAG(0x08) + b'\xa2' * 32 + chal(0x33) + keydata(0) + ident(b'AE-identity') + cert(50) + ecdh() + idlist(0) + sig(), seq=8)
    # 5 access authentication response: plain, optional with two server signatures, optional with one
    base = chal(0x44) + chal(0x45) + b'\x00' + keydata(4) + keydata(0) + ident(b'STA-AE') + ident(b'STA-ASUE')
    add(5, FLAG(0x00) + base + sig(), seq=9)
    add(5, FLAG(0x08) + base + multicert() + sig(b'server-sig-1') + sig(b'server-sig-2') + sig(b'ae-signature'), seq=10)
    add(5, FLAG(0x08) + base + multicert() + sig(b'server-sig-1') + sig(b'ae-signature'), seq=11)
    # 6 certificate authentication request: without and with the optional identity list
    base = chal(0x51) + chal(0x52) + cert(70) + cert(72, 2)
    add(6, ADDID + base, seq=12)
    add(6, ADDID_OPT + base + idlist(2), seq=13)
    # 7 certificate authentication response: one and two server signatures
    add(7, ADDID + multicert() + sig(b'server-sig-1'), seq=14)
    add(7, ADDID + multicert(80, 90) + sig(b'server-sig-1') + sig(b'server-sig-2'), seq=15)
    # the reproducer of "WAI: Fix certificate length handling and short key messages",
    # frame 1: a certificate of 0x8000 octets (the return value of dissect_certificate() was an int16_t)
    add(7, ADDID + multicert(0x8000, 44) + sig(b'server-sig-1'), seq=16)
    # 8 unicast key negotiation request
    add(8, FLAG(0x04) + b'\xb1' * 16 + b'\x01' + ADDID + chal(0x61), seq=17)
    # 9 response, 10 confirmation: WIE and the message authentication code
    add(9, FLAG(0x00) + b'\xb2' * 16 + b'\x01' + ADDID + chal(0x62) + chal(0x63) + b'\0\0' + b'\x44' * 40 + b'\x13' * 20, seq=18)
    add(9, FLAG(0x00) + b'\xb2' * 16 + b'\x01' + ADDID + chal(0x62) + chal(0x63) + b'\0\0' + b'\x13' * 20, seq=19)
    add(10, FLAG(0x00) + b'\xb3' * 16 + b'\x01' + ADDID + chal(0x64) + b'\x45' * 30 + b'\x14' * 20, seq=20)
    add(10, FLAG(0x00) + b'\xb3' * 16 + b'\x01' + ADDID + chal(0x64) + b'\x14' * 20, seq=21)
    # 11 multicast key announcement, 12 response
    add(11, FLAG(0x00) + b'\x01\x02' + ADDID + b'\xd0' * 16 + b'\xd1' * 16 + keydata(16) + b'\x15' * 20, seq=22)
    add(12, FLAG(0x00) + b'\x01\x02' + ADDID + b'\xd1' * 16 + b'\x16' * 20 + b'\0' * 4, seq=23)
    # subtype 0 and an unknown version (names unknown), subtype 13 (not WAI: returns 0)
    add(0, b'\xee' * 40, seq=24)
    add(8, FLAG(0x04) + b'\xb1' * 16 + b'\x01' + ADDID + chal(0x61), seq=25, version=2)
    add(13, b'\xee' * 40, seq=26)
    # fragmented messages: access authentication response (3 fragments), and a certificate
    # authentication request in 2 fragments, each fragment of a different length
    msg = FLAG(0x00) + chal(0x44) + chal(0x45) + b'\x00' + keydata(4) + keydata(0) + ident(b'STA-AE') + ident(b'STA-ASUE') + sig(siglen=60)
    a, b, c = msg[:50], msg[50:120], msg[120:]
    add(5, a, seq=100, frag=0, more=1)
    add(5, b, seq=100, frag=1, more=1)
    add(5, c, seq=100, frag=2, more=0)
    msg = ADDID + chal(0x51) + chal(0x52) + cert(70) + cert(72, 2)
    add(6, msg[:60], seq=101, frag=0, more=1)
    add(6, msg[60:], seq=101, frag=1, more=0)
    # a last fragment (fragment number > 0) with no earlier fragment: nothing to reassemble
    add(8, FLAG(0x04) + b'\xb1' * 16 + b'\x01' + ADDID + chal(0x61), seq=102, frag=3, more=0)
    # a fragment (more fragments) number 5 of a message that is never completed
    add(4, b'\x00' * 40, seq=103, frag=5, more=1)
    write_pcap(os.path.join(outdir, 'wai-coverage.pcap'), f)

    m = []
    add = lambda *a, **k: m.append(wai(*a, **k))
    # the reproducer: Unicast Key Negotiation Response (96 fixed octets + 5) and
    # Confirmation (62 + 0), shorter than the 20 octet MAC
    add(9, FLAG(0) + b'\x01' * 16 + b'\x00' + ADDID + b'\x33' * 32 + b'\x44' * 32 + b'\x55' * 5, seq=1)
    add(10, FLAG(0) + b'\x01' * 16 + b'\x00' + ADDID + b'\x33' * 32 + b'\x66' * 2, seq=2)
    add(10, FLAG(0) + b'\x01' * 16 + b'\x00' + ADDID + b'\x33' * 32, seq=3)
    add(9, FLAG(0) + b'\x01' * 16 + b'\x00' + ADDID + b'\x33' * 32 + b'\x44' * 32 + b'\x55' * 19, seq=4)
    # truncated data of every kind (the length field matches the frame)
    full = {
        1: FLAG(0x80) + b'\x01' + ADDID + b'\xc0' * 16 + b'\x11' * 20,
        2: FLAG(0x7f) + b'\x05\x02' + ADDID + b'\xc1' * 16 + b'\x12' * 20,
        3: FLAG(0x02) + b'\xa1' * 32 + ident() + cert(60) + ecdh(),
        4: FLAG(0x08) + b'\xa2' * 32 + chal(0x33) + keydata(5) + ident() + cert(50) + ecdh() + idlist(3) + sig(),
        5: FLAG(0x08) + chal(0x44) + chal(0x45) + b'\x00' + keydata(4) + keydata(0) + ident() + ident() + multicert() + sig() + sig() + sig(),
        6: ADDID_OPT + chal(0x51) + chal(0x52) + cert(70) + cert(72, 2) + idlist(2),
        7: ADDID + multicert() + sig() + sig(),
        8: FLAG(0x04) + b'\xb1' * 16 + b'\x01' + ADDID + chal(0x61),
        11: FLAG(0x00) + b'\x01\x02' + ADDID + b'\xd0' * 16 + b'\xd1' * 16 + keydata(16) + b'\x15' * 20,
        12: FLAG(0x00) + b'\x01\x02' + ADDID + b'\xd1' * 16 + b'\x16' * 20,
    }
    seq = 10
    for st, d in sorted(full.items()):
        for cut in (len(d) // 3, (len(d) * 2) // 3, len(d) - 7):
            seq += 1
            add(st, d[:cut].ljust(34, b'\0') if cut < 34 else d[:cut], seq=seq)
    # a certificate whose length field is larger than the data
    add(3, FLAG(0x02) + b'\xa1' * 32 + ident() + struct.pack('!HH', 1, 5000) + b'\x30' * 20, seq=60)
    # a signature with an identity list of 65535 entries (the list runs out of data)
    add(4, FLAG(0x08) + b'\xa2' * 32 + chal(0x33) + keydata(5) + ident() + cert(50) + ecdh()
        + b'\x03' + struct.pack('!H', 5) + b'\0' + struct.pack('!H', 65535) + ident(b'only-one') + b'\0' * 20, seq=61)
    # the length field is larger than the frame: not WAI
    add(8, b'\x04' * 50, seq=62, length=1000)
    # fragments with a gap (fragment 2 missing) and a duplicate
    add(5, b'\x00' * 40, seq=70, frag=0, more=1)
    add(5, b'\x00' * 40, seq=70, frag=2, more=1)
    add(5, b'\x00' * 40, seq=70, frag=2, more=0)
    add(5, b'\x00' * 40, seq=70, frag=0, more=1)
    # too short for the header
    m.append(struct.pack('!6s6sH', MAC_S, MAC_C, 0x88b4) + b'\x00\x01\x01\x08\x00\x00\x00\x30' + b'\0' * 40)
    write_pcap(os.path.join(outdir, 'wai-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

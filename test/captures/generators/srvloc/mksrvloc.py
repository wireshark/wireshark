#!/usr/bin/env python3
# Generates test/captures/srvloc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the SRVLOC coverage captures: mksrvloc.py <outdir>.
Everything is built with struct; nothing comes from a real network."""
import struct
import sys
import os
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

class Pcap:
    def __init__(self, fn):
        self.f = open(fn, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.t = 0
        self.n = 0
        self.cip = bytes([10, 0, 0, 1]); self.sip = bytes([10, 0, 0, 2])
        self.seq = {0: 1000, 1: 5000}
        self.ipid = 1

    def _ip(self, proto, src, dst, l4):
        self.ipid += 1
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), self.ipid, 0, 64,
                         proto, 0, src, dst)
        return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4

    def _out(self, from_client, ip):
        mc = b'\x02\0\0\0\0\x01'; ms = b'\x02\0\0\0\0\x02'
        eth = (ms + mc if from_client else mc + ms) + b'\x08\x00'
        pkt = eth + ip
        self.t += 1; self.n += 1
        self.f.write(struct.pack('<IIII', self.t, 0, len(pkt), len(pkt)) + pkt)

    def udp(self, from_client, payload, sport=40000, dport=427):
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        if not from_client:
            sport, dport = dport, sport
        u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        ph = src + dst + struct.pack('!BBH', 0, 17, len(u))
        c = csum(ph + u) or 0xffff
        u = u[:6] + struct.pack('!H', c) + u[8:]
        self._out(from_client, self._ip(17, src, dst, u))

    def tcp(self, from_client, payload, flags=0x18, cport=40001, sport=427):
        d = 0 if from_client else 1
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (cport, sport) if from_client else (sport, cport)
        t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d], 0x50,
                        flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
        c = csum(ph + t + payload)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        self._out(from_client, self._ip(6, src, dst, t + payload))
        self.seq[d] += len(payload) + (1 if flags & 3 else 0)

    def close(self):
        self.f.close()

# ---- SRVLOC builders ----
SRVREQ, SRVRPLY, SRVREG, SRVDEREG, SRVACK, ATTRRQST, ATTRRPLY, DAADVERT, \
    SRVTYPERQST, SRVTYPERPLY, SAADVERT = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
UTF8, UCS2 = 106, 1000

def s16(b):
    return struct.pack('!H', len(b)) + b

def u2(s):
    return s.encode('utf-16-be')

def v1(func, body, flags=0, enc=UTF8, xid=1, lang=b'en', length=None):
    n = 12 + len(body) if length is None else length
    return struct.pack('!BBHBB2sHH', 1, func, n, flags, 0, lang, enc, xid) + body

def v2(func, body, flags=0, xid=1, lang=b'en', ver=2, next_ext=0):
    n = 14 + len(lang) + len(body)
    return (struct.pack('!BB', ver, func) + n.to_bytes(3, 'big') +
            struct.pack('!H', flags) + next_ext.to_bytes(3, 'big') +
            struct.pack('!HH', xid, len(lang)) + lang + body)

def authblk1():
    return struct.pack('!QHH', 0xe0e0e0e000000000, 2, 4) + b'sig!'

def authblk2(spi=b'spi1'):
    return struct.pack('!HHIH', 2, 10 + len(spi), 1700000000, len(spi)) + spi

def url1(url, flags=0, enc=UTF8, life=600):
    e = url if enc != UCS2 else u2(url.decode())
    b = struct.pack('!H', life) + s16(e)
    if flags & 0x20:
        b += authblk1()
    return b

def url2(url, auths=0):
    b = struct.pack('!BH', 0, 600) + s16(url) + bytes([auths])
    for i in range(auths):
        b += authblk2(b'spi%d' % i)
    return b

def v1msgs():
    m = []
    S = lambda b, enc=UTF8: s16(b if enc != UCS2 else u2(b.decode()))
    m.append(v1(SRVREQ, S(b'10.0.0.9') + S(b'(printer-model=*)'), flags=0xc0 & 0x40, xid=10))
    m.append(v1(SRVREQ, S(b'', UCS2) + S(b'(x=y)', UCS2), enc=UCS2, flags=0x40, xid=11))
    m.append(v1(SRVRPLY, struct.pack('!HH', 0, 2) + url1(b'service:printer:lpr://a') +
                url1(b'service:printer:lpr://b'), xid=12))
    m.append(v1(SRVRPLY, struct.pack('!HH', 0, 1) + url1(b'service:x://u', 0x20, ), flags=0x20, xid=13))
    m.append(v1(SRVRPLY, struct.pack('!HH', 0, 1) + url1(b'service:x://u2', 0, UCS2),
                enc=UCS2, xid=14))
    m.append(v1(SRVRPLY, struct.pack('!HH', 1, 0), xid=15))      # language not supported
    m.append(v1(SRVRPLY, struct.pack('!HH', 99, 0), xid=16))     # unknown error
    m.append(v1(SRVREG, url1(b'service:printer:lpr://c') + S(b'(a=1),(b=2)') , xid=17))
    m.append(v1(SRVREG, url1(b'service:printer:lpr://d', 0x20) + S(b'(a=1)') + authblk1(),
                flags=0x30, xid=18))
    m.append(v1(SRVDEREG, S(b'service:printer:lpr://c') + S(b'a,b'), xid=19))
    m.append(v1(SRVDEREG, S(b'service:printer:lpr://d') + authblk1() + S(b'') + authblk1(),
                flags=0x30, xid=20))
    m.append(v1(SRVACK, struct.pack('!H', 0), xid=21))
    m.append(v1(SRVACK, struct.pack('!H', 2), xid=22))
    m.append(v1(ATTRRQST, S(b'') + S(b'service:x://u') + S(b'default') + S(b'a,b'), xid=23))
    m.append(v1(ATTRRPLY, struct.pack('!HH', 0, 0), xid=24))
    al = b'(a=1),(b=2),keyword,(c=3,4)'
    m.append(v1(ATTRRPLY, struct.pack('!H', 0) + s16(al), xid=25))
    m.append(v1(ATTRRPLY, struct.pack('!H', 0) + s16(al) + authblk1(), flags=0x10, xid=26))
    m.append(v1(ATTRRPLY, struct.pack('!H', 0) + s16(u2('(a=1),(b=\u00e9)')), enc=UCS2, xid=27))
    m.append(v1(ATTRRPLY, struct.pack('!H', 1) + s16(b'(a=1)'), xid=28))
    m.append(v1(DAADVERT, struct.pack('!H', 0) + S(b'service:directory-agent://10.0.0.5') +
                S(b'default'), xid=29))
    m.append(v1(DAADVERT, struct.pack('!H', 3) + S(b'x') + S(b'y'), xid=30))
    m.append(v1(SRVTYPERQST, S(b'') + struct.pack('!H', 0xffff) + S(b'default'), xid=31))
    m.append(v1(SRVTYPERQST, S(b'10.0.0.9') + S(b'NA') + S(b'default'), xid=32))
    m.append(v1(SRVTYPERPLY, struct.pack('!HH', 0, 2) + S(b'service:a') + S(b'service:b'), xid=33))
    m.append(v1(SRVTYPERPLY, struct.pack('!HH', 5, 0), xid=34))
    m.append(v1(12, b'\x01\x02\x03', xid=35))
    m.append(v1(SAADVERT, b'\x01\x02\x03', xid=36))
    # flags: all set, and each language/dialect
    m.append(v1(SRVACK, struct.pack('!H', 0), flags=0xf8, xid=37, lang=b'de'))
    return m

def v2msgs():
    m = []
    m.append(v2(SRVREQ, s16(b'10.0.0.9') + s16(b'service:printer') + s16(b'default') +
                s16(b'(a=1)') + s16(b'spi'), flags=0x2000, xid=100))
    m.append(v2(SRVREQ, s16(b'') + s16(b'') + s16(b'') + s16(b'') + s16(b''), xid=101))
    m.append(v2(SRVRPLY, struct.pack('!HH', 0, 2) + url2(b'service:a://x', 1) +
                url2(b'service:b://y', 2), xid=102))
    m.append(v2(SRVRPLY, struct.pack('!HH', 0, 0), xid=103))
    m.append(v2(SRVRPLY, struct.pack('!HH', 4, 0), xid=104))       # scope not supported
    m.append(v2(SRVRPLY, struct.pack('!HH', 99, 0), xid=105))
    m.append(v2(SRVREG, url2(b'service:a://x', 1) + s16(b'service:a') + s16(b'default') +
                s16(b'(a=1),(b=2),kw') + b'\x00', flags=0x4000, xid=106))
    m.append(v2(SRVREG, url2(b'service:a://y') + s16(b'') + s16(b'') + s16(b'') + b'\x02',
                xid=107))
    m.append(v2(SRVDEREG, s16(b'default') + url2(b'service:a://x') + s16(b'tag1,tag2'), xid=108))
    m.append(v2(SRVDEREG, s16(b'') + url2(b'service:a://x') + s16(b''), xid=109))
    m.append(v2(SRVACK, struct.pack('!H', 0), xid=110))
    m.append(v2(SRVACK, struct.pack('!H', 7), xid=111))
    m.append(v2(ATTRRQST, s16(b'10.0.0.9') + s16(b'service:a://x') + s16(b'default') +
                s16(b'a,b') + s16(b'spi'), xid=112))
    m.append(v2(ATTRRQST, s16(b'') + s16(b'') + s16(b'') + s16(b'') + s16(b''), xid=113))
    m.append(v2(ATTRRPLY, struct.pack('!H', 0) + s16(b'(a=1),(b=2),kw') + b'\x00', xid=114))
    m.append(v2(ATTRRPLY, struct.pack('!H', 0) + s16(b'') + b'\x01', xid=115))
    m.append(v2(ATTRRPLY, struct.pack('!H', 12) + s16(b'(a=1)') + b'\x00', xid=116))
    m.append(v2(DAADVERT, struct.pack('!HI', 0, 1700000000) + s16(b'service:directory-agent://10.0.0.5') +
                s16(b'default') + s16(b'(a=1)') + s16(b'spi') + b'\x01' + authblk2(), xid=117))
    m.append(v2(DAADVERT, struct.pack('!HI', 10, 0) + s16(b'') + s16(b'') + s16(b'') + s16(b'') +
                b'\x00', xid=118))
    m.append(v2(SRVTYPERQST, s16(b'10.0.0.9') + struct.pack('!H', 0xffff) + s16(b'default'), xid=119))
    m.append(v2(SRVTYPERQST, s16(b'') + s16(b'NA') + s16(b'default'), xid=120))
    m.append(v2(SRVTYPERQST, s16(b'') + s16(b'') + s16(b''), xid=121))
    m.append(v2(SRVTYPERPLY, struct.pack('!H', 0) + s16(b'service:a,service:b'), xid=122))
    m.append(v2(SRVTYPERPLY, struct.pack('!H', 0) + s16(b''), xid=123))
    # SA advert with the authentication count (reproducer: count was shown as length)
    m.append(v2(SAADVERT, s16(b'service:service-agent://10.0.0.7') + s16(b'default') +
                s16(b'(a=1)') + b'\x02' + authblk2(b'k1') + authblk2(b'k2'), xid=124))
    m.append(v2(SAADVERT, s16(b'') + s16(b'') + s16(b'') + b'\x00', xid=125))
    m.append(v2(SRVTYPERPLY, struct.pack('!H', 5) + s16(b''), xid=128))
    m.append(v2(12, b'\x01\x02\x03', xid=126))
    m.append(v2(SRVACK, struct.pack('!H', 0), flags=0xe000, xid=127, lang=b'en-US', next_ext=0))
    return m

def main(out):
    os.makedirs(out, exist_ok=True)
    p = Pcap(os.path.join(out, 'srvloc-coverage.pcap'))
    msgs1, msgs2 = v1msgs(), v2msgs()
    nudp = 0
    BAD = {15, 16, 22, 28, 30, 34, 35, 36, 104, 105, 111, 116, 118, 126, 128}
    allm = msgs1 + msgs2
    errm = [m for m in allm if struct.unpack('!H', m[10:12])[0] in BAD]
    good = [m for m in allm if struct.unpack('!H', m[10:12])[0] not in BAD]
    for i, m in enumerate(good):
        p.udp(i % 2 == 0, m)
        nudp += 1
    # also from another source port (multicast style requests)
    p.udp(True, msgs2[0], sport=40001)
    nudp += 1
    # TCP: handshake, then PDUs: whole, two in one segment, one split in
    # three segments (reassembly), v1 and v2
    p.tcp(True, b'', flags=0x02)
    p.tcp(False, b'', flags=0x12)
    p.tcp(True, b'', flags=0x10)
    p.tcp(True, msgs2[0])
    p.tcp(False, msgs2[2])
    p.tcp(True, msgs2[6][:20])
    p.tcp(True, msgs2[6][20:50])
    p.tcp(True, msgs2[6][50:])
    p.tcp(False, msgs2[10] + msgs2[1])
    p.tcp(True, msgs1[2][:3])           # less than the 5 bytes tcp_dissect_pdus wants
    p.tcp(True, msgs1[2][3:])
    p.tcp(False, msgs1[4] + msgs1[11][:6])
    p.tcp(False, msgs1[11][6:])
    p.tcp(True, msgs2[24])
    p.close()

    # malformed: truncated PDUs, short, bad lengths
    p = Pcap(os.path.join(out, 'srvloc-coverage-malformed.pcap'))
    for m in errm + [msgs1[0][:8], msgs1[0][:14], msgs1[2][:20], msgs1[7][:16], msgs1[9][:20],
              msgs1[10][:30], msgs1[14][:13], msgs1[16][:20], msgs1[19][:18],
              msgs1[22][:14], msgs1[24][:15],
              msgs2[0][:12], msgs2[0][:20], msgs2[2][:30], msgs2[6][:30], msgs2[8][:20],
              msgs2[14][:20], msgs2[17][:40], msgs2[23][:30],
              # a large attr list length with nothing behind it
              v2(ATTRRPLY, struct.pack('!HH', 0, 500) + b'(a=1)'),
              # url count larger than the data
              v2(SRVRPLY, struct.pack('!HH', 0, 200) + url2(b'x')),
              v1(SRVRPLY, struct.pack('!HH', 0, 200) + url1(b'x')),
              # v2 auth block that is cut
              v2(SAADVERT, s16(b'') + s16(b'') + s16(b'') + b'\x03' + authblk2()),
              # invalid UCS-2 (odd length) attribute list
              v1(ATTRRPLY, struct.pack('!H', 0) + s16(b'\x00(\x00a\x00'), enc=UCS2),
              b'\x02', b'\x01\x01\x00']:
        p.udp(True, m)
    p.tcp(True, b'', flags=0x02, cport=40002)
    p.tcp(False, b'', flags=0x12, cport=40002)
    # TCP: a PDU claiming more data than ever arrives, then a short length
    p.tcp(True, msgs2[2][:30], cport=40002)
    p.tcp(True, v1(SRVACK, b'\x00', length=3)[:6], cport=40002)
    p.close()
    with open(os.path.join(out, 'srvloc-coverage.pcap'), 'rb') as f, \
         gzip.GzipFile(os.path.join(out, 'srvloc_coverage.pcap.gz'), 'wb', 9, mtime=0) as g:
        g.write(f.read())

if __name__ == '__main__':
    main(sys.argv[1])

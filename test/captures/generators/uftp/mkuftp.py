#!/usr/bin/env python3
# Generates test/captures/uftp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UFTP version 3 captures (packet-uftp.c).

Usage: mkuftp.py <outdir>

Writes uftp-coverage.pcap (clean frames) and uftp-coverage-malformed.pcap
(frames that only malformed input reaches). UFTP is registered on UDP
port 1044, so no Decode As is needed. The same dissector hands version
0x40 and 0x50 packets to the UFTP 4 and UFTP 5 dissectors; the capture
has one small packet of each for that.
"""
import struct
import sys
import os

S = struct.pack
SRC = bytes([192, 0, 2, 1])
GRP = bytes([239, 192, 7, 1])
DST = bytes([192, 0, 2, 2])


def pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(S('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(S('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def frame(payload, sport=40000, dport=1044, src=SRC, dst=GRP):
    u = S('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = S('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, src, dst)
    mac = b'\x01\x00\x5e\x40\x07\x01' if dst == GRP else b'\x02\x00\x00\x00\x00\x02'
    return mac + b'\x02\x00\x00\x00\x00\x01\x08\x00' + ip + u


def pat(n, seed=0):
    # printable, never all zero
    return bytes(0x20 + ((seed + i * 7) % 90) for i in range(n))


def dests(*ids):
    return b''.join(S('>I', i) for i in ids)


def hdr(func, body, ver=0x31, gid=0x11223344, blsize=None):
    return S('>BBHIII', ver, func, len(body) if blsize is None else blsize, gid,
             0xc0000201, 0xefc00701) + body


def announce(dl=(), key=b'', flags=0, destcount=None, keylen=None):
    return (S('>BBHHHHHBBHIBBBBHHI', 1, flags, len(dl) if destcount is None else destcount,
              30, 5, 10, 15, 3, 2, 1400, 0xefc00702, 1, 2, 3, 4,
              len(key) if keylen is None else keylen, 0, 65537)
            + pat(32, 1) + key + dests(*dl))


def register(dl=(), key=b'', destcount=None, keylen=None):
    return (S('>B3sHH', 2, b'\0\0\0', len(dl) if destcount is None else destcount,
              len(key) if keylen is None else keylen) + pat(32, 2) + key + dests(*dl))


def clientkey(key=b'', verify=b'', keylen=None, verifylen=None):
    return (S('>B3sHHI', 3, b'\0\0\0', len(key) if keylen is None else keylen,
              len(verify) if verifylen is None else verifylen, 65537) + key + verify)


def regconf(dl=(), destcount=None):
    return S('>BBH', 4, 0, len(dl) if destcount is None else destcount) + dests(*dl)


def fileinfo(ver, file_id, ftype, name, dl=(), destcount=None, fsize=0x10203040506,
             ft=1700000123):
    b = (S('>BBHIHHQ', 5, ftype, file_id, 77, 3, len(dl) if destcount is None else destcount, fsize)
         + (S('>I', ft) if ver == 0x31 else b'') + name.ljust(300, b'\0') + dests(*dl))
    return b


def keyinfo(keys=(), destcount=None):
    b = S('>BBBB', 6, 0, len(keys) if destcount is None else destcount, 48) + S('>II', 1700000000, 500)
    for i, k in enumerate(keys):
        b += S('>I', k) + pat(48, i)
    return b


def infoack(file_id=1, flags=0, dl=(), destcount=None):
    return (S('>BBHHH', 7, flags, file_id, len(dl) if destcount is None else destcount, 0)
            + pat(12, 3) + dests(*dl))


def fileseg(file_id=1, pass_=1, section=2, seq=77, data=b''):
    return S('>BBHBBHI', 8, 0, file_id, pass_, 0, section, seq) + data


def done(file_id=1, pass_=1, section=2, dl=(), destcount=None):
    return (S('>BBHHH', 9, pass_, section, file_id, len(dl) if destcount is None else destcount)
            + dests(*dl))


def status(file_id=1, pass_=1, seq=3, section=2, naks=b''):
    return S('>BBHBBHI', 10, 0, file_id, pass_, seq, section, len(naks)) + naks


def prstatus(file_id=1, pass_=1, seq=3, section=2, dl=(), destcount=None):
    return (S('>BBHBBHHH', 11, 0, file_id, pass_, seq, section,
              len(dl) if destcount is None else destcount, 0) + dests(*dl))


def complete(file_id=1, cstat=0, dl=(), destcount=None):
    return (S('>BBHHH', 12, cstat, file_id, len(dl) if destcount is None else destcount, 0)
            + dests(*dl))


def doneconf(file_id=1, dl=(), destcount=None):
    return (S('>BBHHH', 13, 0, file_id, len(dl) if destcount is None else destcount, 0)
            + dests(*dl))


def hbreq(key=b'', sig=b'', keylen=None, siglen=None):
    return (S('>B3sIHHI', 14, b'\0\0\0', 0xdeadbeef, len(key) if keylen is None else keylen,
              len(sig) if siglen is None else siglen, 65537) + key + sig)


def hbresp(auth=1):
    return S('>BBHI', 15, auth, 0, 0xdeadbeef)


def keyreq():
    return S('>B3s', 16, b'\0\0\0')


def proxykey(key=b'', sig=b'', keylen=None, siglen=None):
    return (S('>B3sIHHI', 17, b'\0\0\0', 0x01020304, len(key) if keylen is None else keylen,
              len(sig) if siglen is None else siglen, 65537) + key + sig)


def encrypted(sig=b'', payload=b'', siglen=None, paylen=None):
    return (S('>IIHH', 1700000000, 250, len(sig) if siglen is None else siglen,
              len(payload) if paylen is None else paylen) + sig + payload)


def abort(flags=0, text=b'transfer aborted'):
    return S('>BBHI', 99, flags, 0, 0xc0000203) + text.ljust(300, b'\0')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    P = []

    def add(func, body, **kw):
        fk = {k: kw.pop(k) for k in ('ver', 'gid', 'blsize') if k in kw}
        P.append(frame(hdr(func, body, **fk), **kw))

    D2 = (0xc0000202, 0xc0000203)
    add(1, announce(D2, pat(24, 4)))                                      # 1
    add(1, announce((), b'', flags=7))                                    # 2
    add(1, announce(D2 + (0xc0000204,), b'', flags=1))                    # 3
    add(2, register(D2, pat(16, 5)), dst=DST)                             # 4
    add(2, register(), dst=DST)                                           # 5
    add(3, clientkey(pat(32, 6), pat(12, 7)), dst=DST)                    # 6
    add(3, clientkey(pat(32, 6), b''), dst=DST)                           # 7
    add(3, clientkey(b'', pat(12, 7)), dst=DST)                           # 8
    add(3, clientkey(), dst=DST)                                          # 9
    add(4, regconf(D2))                                                   # 10
    add(4, regconf())                                                     # 11
    add(5, fileinfo(0x31, 1, 0, b'/data/file one.bin', D2))               # 12
    add(5, fileinfo(0x31, 2, 1, b'dir/'))                                 # 13
    add(5, fileinfo(0x30, 3, 2, b'/data/link', D2), ver=0x30)             # 14
    add(5, fileinfo(0x30, 4, 0, b'x'), ver=0x30)                          # 15
    add(6, keyinfo((0xc0000202, 0xc0000203)))                             # 16
    add(6, keyinfo())                                                     # 17
    add(7, infoack(1, 1, D2), dst=DST)                                    # 18
    add(7, infoack(0, 0), dst=DST)                                        # 19
    add(8, fileseg(1, 1, 2, 77, pat(100)))                                # 20
    add(8, fileseg(65535, 255, 65535, 0xffffffff, b'x'))                  # 21
    add(9, done(1, 1, 2, D2))                                             # 22
    add(9, done(0, 3, 0), dst=GRP)                                        # 23
    add(10, status(1, 1, 3, 2, pat(16, 8)), dst=DST)                      # 24
    add(10, status(1, 2, 4, 3), dst=DST)                                  # 25
    add(11, prstatus(1, 1, 3, 2, D2), dst=DST)                            # 26
    add(11, prstatus(2, 2, 4, 5), dst=DST)                                # 27
    add(12, complete(1, 0, D2), dst=DST)                                  # 28
    add(12, complete(2, 3), dst=DST)                                      # 29
    add(13, doneconf(1, D2))                                              # 30
    add(13, doneconf(0))                                                  # 31
    add(14, hbreq(pat(24, 9), pat(16, 10)), dst=DST)                      # 32
    add(14, hbreq(), dst=DST)                                             # 33
    add(14, hbreq(pat(8, 1), b''), dst=DST)                               # 34
    add(14, hbreq(b'', pat(8, 2)), dst=DST)                               # 35
    add(15, hbresp(1))                                                    # 36
    add(16, keyreq(), dst=DST)                                            # 37
    add(17, proxykey(pat(24, 11), pat(16, 12)), dst=DST)                  # 38
    add(17, proxykey(), dst=DST)                                          # 39
    add(17, proxykey(pat(8, 1), b''), dst=DST)                            # 40
    add(17, proxykey(b'', pat(8, 2)), dst=DST)                            # 41
    add(80, encrypted(pat(32, 13), pat(48, 14)))                          # 42
    add(80, encrypted())                                                  # 43
    add(99, abort(1), dst=DST)                                            # 44
    add(99, abort(0, b'x'), dst=DST)                                      # 45
    # the dispatcher hands other versions to the UFTP 4 and 5 dissectors
    v4 = S('>BBHIIBBBB', 0x40, 13, 1, 0xc0000201, 0x11223344, 1, 0x20, 0x1a, 0) + S('>BBH', 13, 1, 0)
    v5 = S('>BBHIIBBBB', 0x50, 13, 1, 0xc0000201, 0x11223344, 1, 0x20, 0x1a, 0) + S('>BBH', 13, 1, 0)
    P.append(frame(v4))                                                   # 46
    P.append(frame(v5))                                                   # 47
    pcap(os.path.join(out, 'uftp-coverage.pcap'), P)

    M = []

    def madd(func, body, **kw):
        fk = {k: kw.pop(k) for k in ('ver', 'gid', 'blsize') if k in kw}
        M.append(frame(hdr(func, body, **fk), **kw))

    # every message type with a body shorter than its fixed part
    for func in list(range(1, 18)) + [80, 99]:
        madd(func, b'\0\x01')
    madd(5, b'\0' * 100, ver=0x30)
    # counts and lengths larger than the message
    madd(1, announce(destcount=500))
    madd(1, announce(keylen=500))
    madd(2, register(destcount=500))
    madd(2, register(keylen=500))
    madd(3, clientkey(keylen=500))
    madd(3, clientkey(verifylen=500))
    madd(4, regconf(destcount=500))
    madd(5, fileinfo(0x31, 1, 0, b'x', destcount=500))
    madd(5, fileinfo(0x30, 1, 0, b'x', destcount=500), ver=0x30)
    madd(6, keyinfo(destcount=200))
    madd(7, infoack(destcount=500))
    madd(9, done(destcount=500))
    madd(11, prstatus(destcount=500))
    madd(12, complete(destcount=500))
    madd(13, doneconf(destcount=500))
    madd(14, hbreq(keylen=500))
    madd(14, hbreq(siglen=500))
    madd(17, proxykey(keylen=500))
    madd(17, proxykey(siglen=500))
    madd(80, encrypted(siglen=500))
    madd(80, encrypted(paylen=500))
    # a truncated FILESEG, STATUS (with NAKs but nothing after the count) and
    # ABORT (message cut short by the end of the packet)
    madd(8, fileseg()[:12])
    madd(10, S('>BBHBBHI', 10, 0, 1, 1, 3, 2, 5))
    madd(99, abort()[:20])
    # unknown function codes
    madd(0, b'\0' * 40)
    madd(18, b'\0' * 40)
    madd(200, b'\0' * 40)
    # packets the dissector refuses: unknown version, too short for the
    # header, blsize that does not match the length
    madd(8, fileseg(data=b'x'), ver=0x32)
    madd(8, fileseg(data=b'x'), ver=0x00)
    M.append(frame(b'\x31\x08\x00\x00'))
    madd(8, fileseg(data=b'x'), blsize=5)
    madd(8, fileseg(data=b'x'), blsize=500)
    pcap(os.path.join(out, 'uftp-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()

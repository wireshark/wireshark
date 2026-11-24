#!/usr/bin/env python3
# Generates test/captures/uftp4_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UFTP version 4 captures (packet-uftp4.c).

Usage: mkuftp4.py <outdir>

Writes uftp4-coverage.pcap (clean frames) and
uftp4-coverage-malformed.pcap (frames that only malformed input reaches).
UFTP v5 is reached through the "uftp" dissector (UDP port 1044, version
byte 0x40), so no Decode As is needed.
"""
import struct
import sys
import os

S = struct.pack
SRC = bytes([192, 0, 2, 1])
GRP = bytes([239, 192, 7, 1])
DST = bytes([192, 0, 2, 2])
TS0 = 1700000000 * 1000000 + 250000   # microseconds


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


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def pat(n, seed=0):
    return bytes((seed + i * 7) & 0xff for i in range(n))


def dests(*ids):
    return b''.join(S('>I', i) for i in ids)


def uhdr(func, seq=1, src=0xc0000201, gid=0x11223344, inst=1, grtt=0x20, gsize=0x1a):
    return S('>BBHIIBBBB', 0x40, func, seq, src, gid, inst, grtt, gsize, 0)


def msg(func, body, **kw):
    return uhdr(func, **kw) + body


# ---------- blobs and extensions ----------
def rsablob(modlen=128, exp=65537):
    return S('>BBHI', 1, 0, modlen, exp) + pat(modlen, 3)


def ecblob(curve=23, keylen=64):
    return S('>BBH', 2, curve, keylen) + pat(keylen, 5)


def encinfo(flags=0, keytype=3, hashtype=3, key=b'', dh=b'', sig=b'', extlen=None):
    total = 44 + len(key) + len(dh) + len(sig)
    return (S('>BBBBBBHHH', 1, total // 4, flags, 0, keytype, hashtype,
              len(key), len(dh), len(sig)) + pat(32, 9) + key + dh + sig)


def tfmccdata(send=0x1234, seq=7, rate=0x2a31, extlen=8):
    return S('>BBHHH', 2, extlen // 4, send, seq, rate) + b'\0' * (extlen - 8)


def tfmccack(flags=0, seq=9, rate=0x3b22, client=0xc0000203, ts=TS0 + 5):
    return S('>BBBBHHIQ', 3, 5, flags, 0, seq, rate, client, ts)


def freespace(space=0x0000123456789abc):
    return S('>BBHQ', 7, 3, 0, space)


# ---------- messages (body after the 16 byte header) ----------
def announce(exts=b'', dl=(), flags=0, v6=False, robust=20, cc=2, blocksize=1024,
             ts=TS0, hlen=None):
    if v6:
        flags |= 4
        addrs = pat(16, 0x20) + pat(16, 0x40)
    else:
        addrs = GRP + bytes([239, 192, 7, 2])
    hl = 16 + len(addrs) + len(exts) if hlen is None else hlen
    return (S('>BBBBBBH', 1, hl // 4, flags, robust, cc, 0, blocksize)
            + S('>Q', ts) + addrs + exts + dests(*dl))


def register(dh=b'', dl=(), ts=TS0 + 10, hlen=None):
    hl = 44 + len(dh) if hlen is None else hlen
    return (S('>BBH', 2, hl // 4, len(dh)) + S('>Q', ts) + pat(32, 0x11)
            + dh + b'\0' * (hl - 44 - len(dh)) + dests(*dl))


def clientkey(blob=b'', verify=b''):
    hl = pad4(b'x' * (8 + len(blob) + len(verify)))
    hl = len(hl)
    return (S('>BBHHH', 3, hl // 4, 0, len(blob), len(verify)) + blob + verify
            + b'\0' * (hl - 8 - len(blob) - len(verify)))


def regconf(dl=()):
    return S('>BBH', 4, 1, 0) + dests(*dl)


def keyinfo(keys=(), ivctr=0x0102030405060708):
    body = S('>BBH', 5, 3, 0) + S('>Q', ivctr)
    for i, k in enumerate(keys):
        body += S('>I', k) + pat(48, i)
    return body


def keyinfoack(verify=pat(12, 8)):
    # the dissector reads a 3 octet reserved field after the header length
    # and the 12 octet verify data after it: 17 octets in all
    return S('>BB3s', 6, 4, b'\0\0\0') + verify


def keyreq():
    return S('>BBH', 16, 1, 0)


def fileinfo(file_id=1, ftype=0, fsize=0x0000010203040506, name=b'', link=b'',
             ft=1700000123, ts=TS0 + 20, dl=(), res=0):
    name = pad4(name)
    link = pad4(link)
    hl = 28 + len(name) + len(link)
    return (S('>BBHB3sBB', 7, hl // 4, file_id, ftype, b'\0\0\0',
              len(name) // 4, len(link) // 4)
            + fsize.to_bytes(6, 'big') + S('>IQ', ft & 0xffffffff, ts)
            + name + link + dests(*dl))


def fileinfoack(file_id=1, flags=0, ts=TS0 + 30, dl=()):
    return S('>BBHB3sQ', 8, 4, file_id, flags, b'\0\0\0', ts) + dests(*dl)


def fileseg(file_id=1, section=0, block=0, exts=b'', data=b''):
    hl = 8 + len(exts)
    return S('>BBHHH', 9, hl // 4, file_id, section, block) + exts + data


def done(file_id=1, section=0, dl=()):
    return S('>BBHHH', 10, 2, file_id, section, 0) + dests(*dl)


def status(file_id=1, section=0, exts=b'', naks=b''):
    hl = 8 + len(exts)
    return S('>BBHHH', 11, hl // 4, file_id, section, 0) + exts + naks


def complete(file_id=1, cstat=0, exts=b'', dl=()):
    hl = 8 + len(exts)
    return S('>BBHB3s', 12, hl // 4, file_id, cstat, b'\0\0\0') + exts + dests(*dl)


def doneconf(dl=()):
    return S('>BBH', 13, 1, 0) + dests(*dl)


def hbreq(blob=b'', sig=b'', nonce=0xdeadbeef):
    hl = len(pad4(b'x' * (12 + len(blob) + len(sig))))
    return (S('>BBHHHI', 14, hl // 4, 0, len(blob), len(sig), nonce) + blob + sig
            + b'\0' * (hl - 12 - len(blob) - len(sig)))


def hbresp(auth=1, nonce=0xdeadbeef):
    return S('>BBBBI', 15, 2, auth, 0, nonce)


def proxykey(key=b'', dh=b'', sig=b'', nonce=0x01020304):
    hl = len(pad4(b'x' * (12 + len(key) + len(dh) + len(sig))))
    return (S('>BBHHH', 17, hl // 4, len(key), len(dh), len(sig)) + S('>I', nonce)
            + key + dh + sig + b'\0' * (hl - 12 - len(key) - len(dh) - len(sig)))


def congctrl(items=(), rate=0x4b13, seq=3, ts=TS0 + 40):
    hl = 16
    body = S('>BBHHH', 20, hl // 4, 0, seq, rate) + S('>Q', ts)
    for (d, fl, rtt, r) in items:
        body += S('>IBBH', d, fl, rtt, r)
    return body


def ccack(exts=b''):
    hl = 4 + len(exts)
    return S('>BBH', 21, hl // 4, 0) + exts


def encrypted(payload=b'', sig=b'', ivctr=0x1122334455667788):
    return S('>QHH', ivctr, len(sig), len(payload)) + sig + payload


def abort(flags=0, client=0xc0000203, text=b'transfer aborted'):
    return S('>BBBBI', 19, 77, flags, 0, client) + text.ljust(300, b'\0')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    P = []

    def add(b, **kw):
        P.append(frame(b, **kw))

    rsa = rsablob(128)
    ec = ecblob(23, 64)
    # 1-6 ANNOUNCE
    add(msg(1, announce(dl=(0xc0000202, 0xc0000203))))                      # 1
    add(msg(1, announce(encinfo(1, 3, 3, rsa, ec, pat(64, 1)), dl=(0xc0000202,),
                        flags=1), grtt=0x05, gsize=0x13))                     # 2
    add(msg(1, announce(encinfo(0, 6, 4, ec, b'', b''), v6=True, flags=2,
                        dl=(0xc0000202, 0xc0000203, 0xc0000204)), grtt=0xf0,
            gsize=0xff))                                                     # 3
    add(msg(1, announce(encinfo(0, 7, 5, b'', rsa, pat(16)) , dl=())))       # 4
    add(msg(1, announce(encinfo(0, 3, 3) + S('>BBH', 99, 1, 0), dl=(1,))))   # 5
    add(msg(1, announce(encinfo(0, 3, 3, ecblob(25, 132), ecblob(24, 96)))))  # 6
    # 7-10 REGISTER, CLIENT_KEY, REG_CONF
    add(msg(2, register(dh=ec, dl=(0xc0000202,))), src=DST, dst=SRC)         # 7
    add(msg(2, register()), src=DST, dst=SRC)                                # 8
    add(msg(3, clientkey(rsa, pat(64, 2))), src=DST, dst=SRC)                # 9
    add(msg(3, clientkey(ec, b'')), src=DST, dst=SRC)                        # 10
    add(msg(3, clientkey(b'', pat(32, 4))), src=DST, dst=SRC)                # 11
    add(msg(3, clientkey(b'\x09\0\0\x04abcd', b'')), src=DST, dst=SRC)       # 12 unknown blob type
    add(msg(4, regconf((0xc0000202, 0xc0000203))))                           # 13
    add(msg(4, regconf()))                                                   # 14
    # 15-18 KEYINFO, KEYINFO_ACK
    add(msg(5, keyinfo(keys=(0xc0000202, 0xc0000203))))          # 15
    add(msg(5, keyinfo()))                                                   # 16
    add(msg(6, keyinfoack()), src=DST, dst=SRC)                              # 17
    add(msg(16, keyreq()), src=DST, dst=SRC)                                 # 18
    # 19-23 FILEINFO, FILEINFO_ACK
    add(msg(7, fileinfo(1, 0, name=b'/data/file one.bin', dl=(0xc0000202, 0xc0000203))))  # 19
    add(msg(7, fileinfo(2, 2, name=b'link', link=b'/target/path', dl=())))   # 20
    add(msg(7, fileinfo(3, 1, name=b'dir/', ft=0x0000_0001_6000_0000)))      # 21
    add(msg(7, fileinfo(4, 3)))                                              # 22
    add(msg(8, fileinfoack(1, 1, dl=(0xc0000202,))), src=DST, dst=SRC)       # 23
    add(msg(8, fileinfoack(2, 0)), src=DST, dst=SRC)                         # 24
    # FILESEG with and without extensions
    add(msg(9, fileseg(1, 0, 0, data=pat(100))))                             # 25
    add(msg(9, fileseg(1, 0, 1, tfmccdata(), pat(64))))                      # 26
    add(msg(9, fileseg(1, 1, 2, tfmccdata(rate=0xfff9) + S('>BBH', 99, 1, 0), pat(16))))  # 27 clamped rate + unknown ext
    add(msg(9, fileseg(1, 1, 3, tfmccdata(extlen=12) + tfmccdata(seq=8), pat(16))))      # 28 ext length > fixed size
    add(msg(9, fileseg(1, 2, 4, data=b'\x55')))                                            # 29
    # DONE
    add(msg(10, done(1, 0, (0xc0000202, 0xc0000203))))                       # 30
    add(msg(10, done(0, 3)))                                                 # 31
    # STATUS
    add(msg(11, status(1, 0, tfmccack(5), pat(12))), src=DST, dst=SRC)       # 32
    add(msg(11, status(1, 2, b'', b'\x01')), src=DST, dst=SRC)                   # 33
    add(msg(11, status(2, 3, tfmccack(0x0f) + tfmccack(0x00, client=0xc0000204), pat(4))), src=DST, dst=SRC)  # 34
    add(msg(11, status(2, 4, S('>BBH', 99, 1, 0), b'\x02')), src=DST, dst=SRC)   # 35
    # COMPLETE
    add(msg(12, complete(1, 0, freespace(), (0xc0000202,))), src=DST, dst=SRC)  # 36
    add(msg(12, complete(0, 1)), src=DST, dst=SRC)                           # 37
    add(msg(12, complete(2, 3, S('>BBH', 99, 1, 0))), src=DST, dst=SRC)      # 38
    add(msg(13, doneconf((0xc0000202,))))                                    # 39
    add(msg(13, doneconf()))                                                 # 40
    # HB_REQ / HB_RESP
    add(msg(14, hbreq(rsa, pat(64, 3))), src=DST, dst=SRC)                   # 41
    add(msg(14, hbreq(ec, b'')), src=DST, dst=SRC)                           # 42
    add(msg(14, hbreq(b'', pat(32, 1))), src=DST, dst=SRC)                   # 43
    add(msg(14, hbreq(b'\x07abc', b'')), src=DST, dst=SRC)                   # 44 unknown blob
    add(msg(15, hbresp(0)))                                                  # 45
    add(msg(15, hbresp(1)))                                                  # 46
    add(msg(15, hbresp(2)))                                                  # 47
    # PROXY_KEY
    add(msg(17, proxykey(rsa, ec, pat(64, 5))), src=DST, dst=SRC)            # 48
    add(msg(17, proxykey(ec, rsa, b'')), src=DST, dst=SRC)                   # 49
    add(msg(17, proxykey(b'', b'', pat(32, 2))), src=DST, dst=SRC)           # 50
    add(msg(17, proxykey(b'\x05abc', b'\x06abc', b'')), src=DST, dst=SRC)    # 51
    # CONG_CTRL
    add(msg(20, congctrl([(0xc0000202, 0x01, 0x10, 0x1234), (0xc0000203, 0x0a, 0x40, 0x4321),
                          (0xc0000204, 0x04, 0xff, 0xfff8), (0xc0000205, 0x08, 0x00, 0x0000)])))  # 52
    add(msg(20, congctrl()))                                                 # 53
    add(msg(21, ccack(tfmccack(1))), src=DST, dst=SRC)                       # 54
    add(msg(21, ccack()), src=DST, dst=SRC)                                  # 55
    add(msg(21, ccack(S('>BBH', 99, 1, 0))), src=DST, dst=SRC)               # 56
    # ENCRYPTED, ABORT
    add(msg(18, encrypted(pat(80, 0x44), pat(32, 7))))                                   # 57
    add(msg(18, encrypted(b'', b'')))                                             # 58
    add(msg(19, abort(1)), src=DST, dst=SRC)                                 # 59
    add(msg(19, abort(0, text=b'x')), src=DST, dst=SRC)                      # 60
    # fix reproducers: KEYINFO with more than 255 destinations and CONG_CTRL
    # with more than 255 items (the counts used to be uint8_t)
    add(msg(5, keyinfo(keys=range(0xc0010000, 0xc0010000 + 260))))      # 61
    add(msg(20, congctrl([(0xc0020000 + i, i & 0xf, i & 0xff, 0x2000 + i)
                          for i in range(300)])))                            # 62
    # unicast, source ports, announce with a long destination list
    add(msg(1, announce(dl=tuple(range(0xc0000300, 0xc0000300 + 50)))), dst=DST)  # 63
    pcap(os.path.join(out, 'uftp4-coverage.pcap'), P)

    M = []

    def madd(b, **kw):
        M.append(frame(b, **kw))

    # fix: an announce whose header length is smaller than the fixed part
    madd(msg(1, announce(hlen=16)))                                          # 1
    madd(msg(1, announce(hlen=40, v6=True)))                                 # 2
    # lengths too short for every message
    for func in range(1, 22):
        madd(uhdr(func) + b'\0' * 4)
    # hlen larger than the message
    for func in range(1, 22):
        madd(uhdr(func) + bytes([func, 0x3f]) + b'\0' * 14)
    # message too short for the length it announces
    madd(msg(1, announce(encinfo(0, 3, 3, rsa)[:60])))
    madd(msg(1, announce(encinfo(0, 3, 3, rsa, ec, pat(64, 1)), hlen=64)))
    madd(msg(1, announce(encinfo(0, 3, 3, b'\x01\0\xff\xff', b'', b''))))      # RSA blob too long
    madd(msg(1, announce(encinfo(0, 3, 3, b'\x01\0', b'', b''))))             # short RSA blob
    madd(msg(1, announce(encinfo(0, 3, 3, b'\x02\0\xff\xff', b'', b''))))      # EC blob too long
    madd(msg(1, announce(encinfo(0, 3, 3, b'\x02\0', b'', b''))))             # short EC blob
    madd(msg(1, announce(encinfo(0, 3, 3, b'', b'\x01\0\xff\xff\0\0\0\0', b''))))
    madd(msg(1, announce(encinfo(0, 3, 3, b'', b'\x02\0\xff\xff', b''))))
    madd(msg(1, announce(exts=pat(20))))
    # clientkey/hbreq/proxykey with too-short or oversized blobs
    madd(msg(3, clientkey(b'\x01\0\xff\xff\0\0\0\0', b'')))
    madd(msg(3, clientkey(b'\x02\0\xff\xff', b'')))
    madd(msg(14, hbreq(b'\x01\0\xff\xff\0\0\0\0', b'')))
    madd(msg(14, hbreq(b'\x02\0\xff\xff', b'')))
    madd(msg(17, proxykey(b'\x01\0\xff\xff\0\0\0\0', b'', b'')))
    madd(msg(17, proxykey(b'', b'\x02\0\xff\xff', b'')))
    # blobs too short for their own header (3 bytes and 5 bytes)
    madd(msg(3, clientkey(b'\x02\0\0', b'')))
    madd(msg(14, hbreq(b'\x02\0\0', b'')))
    madd(msg(17, proxykey(b'\x02\0\0', b'\x01\0\0\0\0', b'')))
    # extensions that are too short, whose own length is too small or that
    # are longer than the data
    madd(msg(9, S('>BBHHH', 9, 3, 1, 0, 0) + S('>BBH', 2, 1, 0) + b'\x55' * 4))
    madd(msg(9, S('>BBHHH', 9, 4, 1, 0, 0) + S('>BBHHH', 2, 1, 0, 0, 0) + b'\x55' * 4))
    madd(msg(9, S('>BBHHH', 9, 4, 1, 0, 0) + S('>BBHHH', 2, 9, 0, 0, 0) + b'\x55' * 4))
    madd(msg(11, S('>BBHHH', 11, 4, 1, 0, 0) + S('>BBHHHH', 3, 1, 0, 0, 0, 0)[:8] + b'\x55' * 4))
    madd(msg(11, S('>BBHHH', 11, 7, 1, 0, 0) + S('>BBHHHHIQ', 3, 1, 0, 0, 0, 0, 0, 0)))
    madd(msg(11, S('>BBHHH', 11, 7, 1, 0, 0) + S('>BBHHHHIQ', 3, 20, 0, 0, 0, 0, 0, 0)))
    madd(msg(12, S('>BBHB3s', 12, 4, 1, 0, b'\0\0\0') + S('>BBHHH', 7, 3, 0, 0, 0)))
    madd(msg(12, S('>BBHB3s', 12, 5, 1, 0, b'\0\0\0') + S('>BBHQ', 7, 1, 0, 0)))
    madd(msg(12, S('>BBHB3s', 12, 5, 1, 0, b'\0\0\0') + S('>BBHQ', 7, 40, 0, 0)))
    madd(msg(21, S('>BBH', 21, 3, 0) + S('>BBHH', 3, 1, 0, 0)))
    madd(msg(19, S('>BBBBI', 19, 1, 0, 0, 0) + b'\0' * 304))
    # field counts beyond the data
    madd(msg(6, S('>BB3s', 6, 4, b'\0\0\0') + b'\x01' * 12))                  # exactly KEYINFO_ACK_LEN octets
    madd(msg(7, S('>BBHBBHBB', 7, 7, 1, 0, 0, 0, 200, 200) + b'\0' * 20))
    madd(msg(2, S('>BBH', 2, 11, 500) + b'\0' * 40))
    madd(msg(3, S('>BBHHH', 3, 2, 0, 500, 500)))
    madd(msg(14, S('>BBHHHI', 14, 3, 0, 500, 500, 0)))
    madd(msg(17, S('>BBHHHI', 17, 3, 500, 500, 500, 0)))
    madd(msg(18, S('>QHH', 0, 0, 500) + b'\0' * 10))
    madd(msg(18, S('>QHH', 0, 500, 0) + b'\0' * 10))
    madd(msg(19, abort()[:100]))
    # unknown function code
    madd(msg(42, b'\0' * 12))
    madd(msg(0, b'\0' * 12))
    # a v5 header that is shorter than UFTP_LEN + 4
    madd(uhdr(1) + b'\0' * 2)
    # non-UFTP content on the port (version byte 0x00 is rejected)
    madd(b'\x00' * 32)
    # short packets for the dispatcher
    madd(b'\x50' * 10)
    pcap(os.path.join(out, 'uftp4-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()

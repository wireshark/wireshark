#!/usr/bin/env python3
# Generates test/captures/ntp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NTP coverage capture (packet-ntp.c).

Usage: mkntp.py <output directory> [-v]   (-v prints the frame ranges)

Writes ntp-coverage.pcapng (main capture) and ntp-coverage-malformed.pcapng.
Everything is built with struct; addresses are from 192.0.2.0/24.
NTS extensions carry placeholder bytes only: nothing is encrypted and the
NTS-KE frames (Exported PDU) hold made-up cookie bytes.
"""
import os
import struct
import sys

LT_ETH, LT_EXPPDU = 1, 252


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Exported PDU. Timestamps advance 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 262144))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


CLI = bytes([192, 0, 2, 10])
SRV = bytes([192, 0, 2, 123])
MAC_C = b'\x02\0\0\0\0\x0a'
MAC_S = b'\x02\0\0\0\0\x7b'
ipid = [0]


def ip4(proto, payload, src, dst):
    ipid[0] += 1
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ipid[0], 0,
                     64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload


def eth(ip, to_server=True):
    if to_server:
        return MAC_S + MAC_C + b'\x08\x00' + ip
    return MAC_C + MAC_S + b'\x08\x00' + ip


def udp(sport, dport, payload, to_server=True, src=None, dst=None):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    if to_server:
        s, d = src or CLI, dst or SRV
    else:
        s, d = src or SRV, dst or CLI
    return eth(ip4(17, u, s, d), to_server)


def tcp(sport, dport, payload, seq, to_server=True):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload
    s, d = (CLI, SRV) if to_server else (SRV, CLI)
    return eth(ip4(6, t, s, d), to_server)


def req(sport, payload):
    return (0, udp(sport, 123, payload, True))


def rsp(sport, payload):
    return (0, udp(123, sport, payload, False))


def ts(sec, frac=0x12345678):
    return struct.pack('!II', sec, frac)


T0 = 3900000000


def ntp_std(li=0, vn=4, mode=3, stratum=0, poll=6, prec=-20, rdelay=0x00010000,
            rdisp=0x00020000, refid=b'\0\0\0\0', ref=T0 - 100, org=0, rec=0,
            xmt=T0, tail=b''):
    h = struct.pack('!BBbbII', (li << 6) | (vn << 3) | mode, stratum, poll,
                    prec, rdelay, rdisp) + refid
    for t in (ref, org, rec, xmt):
        h += ts(t) if t else ts(0, 0)
    return h + tail


def ext(typ, body, length=None):
    """NTP extension field: body padded to a multiple of 4; length is the
    field length (default 4 + padded body)."""
    body += b'\0' * ((4 - len(body) % 4) % 4)
    return struct.pack('!HH', typ, length if length is not None else 4 + len(body)) + body


def ph(n, k=0):
    """Placeholder bytes (not crypto)."""
    return bytes((k + i * 7) & 0xff for i in range(n))


def nts_auth(nonce_len=16, ct_len=48, k=1):
    return ext(0x0404, struct.pack('!HH', nonce_len, ct_len) + ph(nonce_len, k)
               + ph(ct_len, k + 50))


# ----------------------------------------------------------------- NTS-KE
def exp_pdu_ntske(payload, to_server, sport=50000):
    n = b'nts-ke'
    t = struct.pack('!HH', 12, 8) + n + b'\0\0'
    src, dst = (CLI, SRV) if to_server else (SRV, CLI)
    ps, pd = (sport, 4460) if to_server else (4460, sport)
    t += struct.pack('!HH4s', 20, 4, src) + struct.pack('!HH4s', 21, 4, dst)
    t += struct.pack('!HHI', 24, 4, 2)
    t += struct.pack('!HHI', 25, 4, ps) + struct.pack('!HHI', 26, 4, pd)
    t += struct.pack('!HH', 0, 0)
    return (1, t + payload)


def ke_rec(typ, body, crit=True):
    return struct.pack('!HH', (0x8000 if crit else 0) | typ, len(body)) + body


def ke_response(cookies, aead=15):
    p = ke_rec(1, struct.pack('!H', 0)) + ke_rec(4, struct.pack('!H', aead), False)
    for c in cookies:
        p += ke_rec(5, c, False)
    return p + ke_rec(0, b'')


COOKIE1 = ph(100, 3)
COOKIE2 = ph(104, 9)
COOKIE3 = ph(96, 17)
UID1 = ph(32, 21)
UID2 = ph(32, 33)
UID3 = ph(32, 44)


def ctrl(opcode, resp=False, err=False, more=False, seq=1, status=0, assoc=0,
         off=0, data=b'', count=None, auth=b'', vn=4, pad=True):
    b0 = (vn << 3) | 6
    b1 = (0x80 if resp else 0) | (0x40 if err else 0) | (0x20 if more else 0) | opcode
    if count is None:
        count = len(data)
    p = struct.pack('!BBHHHHH', b0, b1, seq, status, assoc, off, count) + data
    if auth:
        if pad:
            p += b'\0' * ((8 - len(p) % 8) % 8)
        p += auth
    return p


def priv(reqcode, resp, numitems, itemsize, items=b'', impl=3, auth=False,
         errcode=0, seq=0, vn=2, more=False, tail=b''):
    b0 = (0x80 if resp else 0) | (0x40 if more else 0) | (vn << 3) | 7
    b1 = (0x80 if auth else 0) | seq
    p = struct.pack('!BBBB', b0, b1, impl, reqcode)
    p += struct.pack('!HHH', (errcode << 12) | numitems, 0, 0)[:0]
    p += struct.pack('!H', (errcode << 12) | numitems) + struct.pack('!H', itemsize)
    return p + items + tail


def fill(sizes, k=1, zero=()):
    """One mode 7 item from a list of field sizes; fields whose index is in
    zero are all zero (v6 flag, ...)."""
    out = b''
    for i, s in enumerate(sizes):
        if i in zero:
            out += b'\0' * s
        else:
            out += bytes(((k + len(out) + j) % 251) + 1 for j in range(s))
    return out


V6 = 1  # marker used below for "v6 flag set"


def setv6(item, off, on):
    v = struct.pack('!I', 1 if on else 0)
    return item[:off] + v + item[off + 4:]


def main_frames(verbose=False):
    F = []
    marks = []

    def mark(name):
        marks.append((len(F) + 1, name))

    # ---------------------------------------------------------- NTS-KE
    mark('NTS-KE (Exported PDU) and NTS cookies')
    F.append(exp_pdu_ntske(ke_response([COOKIE1]), False))          # 1
    # ---------------------------------------------------------- client/server
    mark('Client/server mode 3 and 4, versions, reference IDs')
    F.append(req(40001, ntp_std(mode=3, poll=0, prec=-18, xmt=T0)))
    F.append(rsp(40001, ntp_std(mode=4, stratum=2, poll=-3, prec=-24,
                                refid=bytes([192, 0, 2, 1]), org=T0, rec=T0 + 1, xmt=T0 + 2)))
    F.append(req(40002, ntp_std(vn=3, mode=3, poll=10, prec=0, xmt=T0 + 5)))
    F.append(rsp(40002, ntp_std(vn=3, mode=4, stratum=1, refid=b'GPS\0',
                                org=T0 + 5, rec=T0 + 6, xmt=T0 + 6, li=1)))
    F.append(rsp(40002, ntp_std(vn=3, mode=4, stratum=1, refid=b'ABCD', li=2)))
    F.append(rsp(40002, ntp_std(vn=2, mode=4, stratum=1, refid=b'GOES', li=3)))
    F.append(rsp(40002, ntp_std(vn=1, mode=4, stratum=1, refid=b'\0\0\0\0')))
    for kod, st in ((b'RATE', 0), (b'DENY', 0), (b'NTSN', 0), (b'ZZZZ', 0),
                    (b'\0\0\0\0', 0)):
        F.append(rsp(40002, ntp_std(mode=4, stratum=st, refid=kod)))
    mark('Symmetric, broadcast, reserved modes, unknown versions')
    F.append(req(123, ntp_std(mode=1, stratum=3, refid=bytes([192, 0, 2, 9]))))
    F.append(req(123, ntp_std(mode=2, stratum=3, refid=bytes([192, 0, 2, 9]))))
    F.append(req(123, ntp_std(mode=5, stratum=4, refid=bytes([192, 0, 2, 8]))))
    F.append(req(123, ntp_std(mode=0, stratum=16)))
    F.append(req(123, ntp_std(vn=0, mode=3)))
    F.append(req(123, ntp_std(vn=5, mode=3)))
    F.append(req(123, ntp_std(vn=6, mode=3, stratum=17)))
    # Timestamps: zero, the 2036 wrap and a year before 1970
    F.append(rsp(40002, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                ref=0, org=0, rec=0, xmt=50)))
    F.append(rsp(40002, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                ref=0xffffffff, org=2000000000, rec=1, xmt=0x7fffffff)))
    # -------------------------------------------------------- extension fields
    mark('Extension fields, MACs')
    F.append(req(40003, ntp_std(tail=ext(0x010a, struct.pack('!II', 7, 0x80000000) + b'\0\0\0\0'))))
    F.append(rsp(40003, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                tail=ext(0x010a, struct.pack('!II', 1, 0x40000000) + b'\0\0\0\0'))))
    for typ in (0x0002, 0x0502, 0x8302, 0xC002, 0x1234):
        F.append(req(40003, ntp_std(tail=ext(typ, ph(12)))))
    # extension of 20, odd length 18 (not a multiple of 4), bigger one
    F.append(req(40003, ntp_std(tail=ext(0x0777, ph(16)) + ext(0x0778, ph(60)))))
    F.append(req(40003, ntp_std(tail=struct.pack('!HH', 0x0779, 18) + ph(14)
                                + struct.pack('!I', 4) + ph(16))))
    # MAC variants: MD5 (20), SHA-1 (24), SHA-512 (68), crypto-NAK (4 zero)
    F.append(req(40004, ntp_std(tail=struct.pack('!I', 1) + ph(16))))
    F.append(req(40004, ntp_std(tail=struct.pack('!I', 2) + ph(20))))
    F.append(req(40004, ntp_std(tail=struct.pack('!I', 3) + ph(64))))
    F.append(rsp(40004, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                tail=struct.pack('!I', 0))))
    # extension followed by MACs; a short trailer (< 20) takes the last
    # extension as MAC data; trailing bytes without an extension
    F.append(req(40004, ntp_std(tail=ext(0x0780, ph(12)) + struct.pack('!I', 5) + ph(16))))
    F.append(req(40004, ntp_std(tail=ext(0x0781, ph(12)) + ext(0x0782, ph(12)) + ph(8))))
    F.append(req(40004, ntp_std(tail=ph(5))))
    F.append(req(40004, ntp_std(tail=ph(2))))
    # a 2nd extension too short for its length, so the first one is last
    F.append(req(40004, ntp_std(tail=ext(0x0783, ph(12)) + struct.pack('!HH', 0x0784, 40) + ph(12))))
    F.append(req(40004, ntp_std(tail=ext(0x0785, ph(12)) + struct.pack('!HH', 0x0786, 8) + ph(12))))
    # -------------------------------------------------------- NTS
    mark('NTS: UID, cookie and authenticator extensions (placeholders)')
    # client request uses a cookie from the NTS-KE response (frame 1)
    F.append(req(40010, ntp_std(xmt=T0 + 10, tail=ext(0x0104, UID1) + ext(0x0204, COOKIE1)
                                + nts_auth())))
    # server response: same UID, authenticator, then a new cookie in clear
    F.append(rsp(40010, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                org=T0 + 10, xmt=T0 + 11,
                                tail=ext(0x0104, UID1) + nts_auth(k=2)
                                + ext(0x0204, COOKIE2))))
    # the next request uses the cookie the server gave
    F.append(req(40010, ntp_std(xmt=T0 + 20, tail=ext(0x0104, UID2) + ext(0x0204, COOKIE2)
                                + nts_auth(k=3))))
    F.append(rsp(40010, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                org=T0 + 20, xmt=T0 + 21,
                                tail=ext(0x0104, UID2) + nts_auth(k=4) + ext(0x0204, COOKIE3))))
    # unknown cookie, unknown UID, no UID, authenticator first
    F.append(req(40011, ntp_std(tail=ext(0x0104, UID3) + ext(0x0204, ph(40, 5)) + nts_auth(k=5))))
    F.append(rsp(40011, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                tail=ext(0x0104, UID3) + nts_auth(k=6))))
    F.append(req(40011, ntp_std(tail=nts_auth(k=7))))
    F.append(rsp(40011, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1]),
                                tail=nts_auth(k=8))))
    # NTS extensions in other modes (symmetric): no key handling
    F.append(req(40011, ntp_std(mode=1, tail=ext(0x0104, UID1) + nts_auth(k=9))))
    # NTS cookie placeholder extension in a broadcast packet
    F.append(req(40011, ntp_std(mode=5, tail=ext(0x0104, UID1) + ext(0x0204, COOKIE1) + nts_auth(k=9))))
    # cookie extension that is also a symmetric one
    F.append(req(40012, ntp_std(mode=3, tail=ext(0x0204, COOKIE3) + ext(0x0104, UID3))))
    # the authenticator's ciphertext is shorter than the AEAD tag
    # (fixed bug N1; without keys the check is not reached): placeholder
    F.append(req(40013, ntp_std(tail=ext(0x0104, UID1) + ext(0x0204, COOKIE2)
                                + nts_auth(nonce_len=16, ct_len=8))))
    # another NTS-KE response with new cookies and a second one reuse
    F.append(exp_pdu_ntske(ke_response([ph(80, 61), ph(64, 71)], 30), False))
    # ---------------------------------------------------------- mode 6
    mark('Mode 6 control messages')
    sy_status = 0x0618
    peer_status = 0x9014
    vars_sys = (b'version="ntpd 4.2.8p15@1.3728-o Thu Jan  1 00:00:00 UTC 2026 (1)", '
                b'processor="x86_64", system="Linux/6.1", leap=0, stratum=2, '
                b'precision=-24, rootdelay=1.234, rootdisp=2.5, refid=192.0.2.1, '
                b'reftime=0xe8d5cf8e.12345678, clock=0xe8d5cf90.9a8b7c6d, peer=1234, '
                b'tc=6, mintc=3, offset=0.012, frequency=-3.14, sys_jitter=0.01, '
                b'clk_jitter=0.02, clk_wander=0.003')
    F.append(req(41000, ctrl(2, seq=1, data=b'')))
    F.append(rsp(41000, ctrl(2, resp=True, seq=1, status=sy_status, data=vars_sys)))
    F.append(req(41000, ctrl(2, seq=2, assoc=1234, data=b'srcadr,srcport,reftime')))
    F.append(rsp(41000, ctrl(2, resp=True, seq=2, status=peer_status, assoc=1234,
                             data=b"srcadr=192.0.2.1,\r\nsrcport=123, name='ntp.example',\tflags=0x0, "
                                  b'filtdelay=\t0.1 0.2 0.3, junk, "q",,')))
    F.append(rsp(41000, ctrl(2, resp=True, seq=2, err=True, status=0x0700, assoc=1234)))
    F.append(rsp(41000, ctrl(2, resp=True, seq=3, more=True, status=sy_status,
                             data=b'a=1, b=2')))
    # READSTAT
    F.append(req(41001, ctrl(1, seq=10)))
    F.append(rsp(41001, ctrl(1, resp=True, seq=10, status=sy_status,
                             data=struct.pack('!HHHH', 1234, 0x9614, 1235, 0x9024)
                             + struct.pack('!HH', 1236, 0xa014))))
    F.append(req(41001, ctrl(1, seq=11, assoc=1234)))
    F.append(rsp(41001, ctrl(1, resp=True, seq=11, status=peer_status, assoc=1234,
                             data=b'srcadr=192.0.2.1, stratum=2')))
    # the fixed bug: count not a multiple of 4 with associd 0 (also 6)
    F.append(rsp(41002, ctrl(1, resp=True, seq=12, data=b'\x00', count=1)))
    F.append(rsp(41002, ctrl(1, resp=True, seq=13, status=sy_status,
                             data=struct.pack('!HH', 1237, 0x9014) + b'\0\0', count=6)))
    # WRITEVAR, READCLOCK, WRITECLOCK
    F.append(req(41003, ctrl(3, seq=20, assoc=0, data=b'leapsmearinterval=0')))
    F.append(rsp(41003, ctrl(3, resp=True, seq=20, status=sy_status)))
    F.append(req(41003, ctrl(3, seq=21, assoc=1234, data=b'flags=1')))
    F.append(rsp(41003, ctrl(3, resp=True, seq=21, status=peer_status, assoc=1234)))
    F.append(req(41004, ctrl(4, seq=22, assoc=1236)))
    F.append(rsp(41004, ctrl(4, resp=True, seq=22, status=0x0102, assoc=1236,
                             data=b'timecode="", poll=3, noreply=0, badformat=0')))
    F.append(req(41004, ctrl(5, seq=23, assoc=1236, data=b'flag1=1')))
    F.append(rsp(41004, ctrl(5, resp=True, seq=23, status=0x0300, assoc=1236)))
    # SETTRAP / UNSETTRAP / unspecified / unknown opcodes (no data, with status)
    for op, sq in ((6, 30), (31, 31), (0, 32), (13, 33), (20, 34)):
        F.append(req(41005, ctrl(op, seq=sq, assoc=0)))
        F.append(rsp(41005, ctrl(op, resp=True, seq=sq, status=0x0003)))
    # ASYNCMSG with and without association
    F.append(rsp(41006, ctrl(7, resp=True, seq=40, status=sy_status, assoc=0,
                             data=b'1.2.3.4 peer event: reachable')))
    F.append(rsp(41006, ctrl(7, resp=True, seq=41, status=peer_status, assoc=1234,
                             data=b'peer 192.0.2.1 event')))
    # Authenticated opcodes: CONFIGURE, SAVECONFIG, READ_MRU, READ_ORDLIST_A, REQ_NONCE
    md5 = struct.pack('!I', 5) + ph(16)
    sha = struct.pack('!I', 6) + ph(20)
    for op, data in ((8, b'server 192.0.2.50 iburst'), (9, b'ntp.conf.save'),
                     (10, b'nonce=abcdef0123456789, limit=8, mincount=2'),
                     (11, b'addr.0=192.0.2.1, count.0=4'),
                     (12, b'')):
        F.append(req(41007, ctrl(op, seq=50 + op, data=data, auth=md5)))
        F.append(rsp(41007, ctrl(op, resp=True, seq=50 + op, status=sy_status, data=data, auth=sha)))
    # authenticator of a size that is neither 20 nor 24; none (nothing after);
    # data length with and without padding; request not aligned
    F.append(req(41008, ctrl(2, seq=70, data=b'a=1', auth=ph(12))))
    F.append(req(41008, ctrl(2, seq=71, data=b'abcd', auth=md5)))
    F.append(req(41008, ctrl(2, seq=72, data=b'abcdefghij', auth=sha)))
    F.append(req(41008, ctrl(2, seq=73, data=b'abcdefghijkl')))
    F.append(req(41008, ctrl(2, seq=74, data=b'')))
    F.append(req(41008, ctrl(2, seq=75, data=b'', auth=md5, pad=False)))
    F.append(rsp(41008, ctrl(8, resp=True, seq=76, data=b'abc')))
    # a long count (over 65523): the authenticator offset used to wrap
    longdata = (b'0123456789abcdef' * 4096)[:65530]
    F.append((1, exp_pdu_ntp(ctrl(12, resp=True, seq=80, status=sy_status, data=longdata,
                                  auth=sha))[1]))
    # --------------------------------------------------------- mode 7
    mark('Mode 7 (private) requests and responses')
    m7_frames(F)
    mark('NTP over TCP and in PTP')
    F.append((0, tcp(50123, 123, ntp_std(mode=3, xmt=T0 + 99), 1)))
    F.append((0, tcp(123, 50123, ntp_std(mode=4, stratum=2, refid=bytes([192, 0, 2, 1])), 1, False)))
    F.append((0, ptp_ntp(ntp_std(mode=3, xmt=T0 + 100))))
    F.append((0, ptp_ntp(ctrl(2, seq=90, data=b'a=b'), tlv_type=0x0003)))
    mark('End')
    if verbose:
        for (n, name), nxt in zip(marks, marks[1:]):
            print('%d-%d: %s' % (n, nxt[0] - 1, name))
        print('total', len(F))
    return F


def exp_pdu_ntp(payload):
    n = b'ntp'
    t = struct.pack('!HH', 12, 4) + n + b'\0' + struct.pack('!HH', 0, 0)
    return (1, t + payload)


def ptp_ntp(ntp, tlv_type=0x0003):
    """PTPv2 Sync over UDP 319 with an IANA organization extension TLV
    holding an NTP message (subtype 1)."""
    body = struct.pack('!HH', 0, 0)[:2] + ntp
    tlv_val = bytes([0x00, 0x00, 0x5e]) + bytes([0, 0, 1]) + body
    if len(tlv_val) % 2:
        tlv_val += b'\0'
    tlv = struct.pack('!HH', tlv_type, len(tlv_val)) + tlv_val
    hdr_len = 34 + 10 + len(tlv)
    ptp = struct.pack('!BBHBBH', 0x00, 0x02, hdr_len, 0, 0, 0)
    ptp += struct.pack('!q', 0) + b'\0' * 4 + bytes([2, 0, 0, 0, 0, 0, 0, 1]) + struct.pack('!HHBb', 1, 5, 0, 0)
    ptp += struct.pack('!HI', 0, 0) + struct.pack('!I', 0)
    return udp(319, 319, ptp + tlv, True, src=CLI, dst=bytes([224, 0, 1, 129]))


# --------------------------------------------------------- mode 7 layouts
def sizes_of(*s):
    out = []
    for x in s:
        out.extend(x if isinstance(x, list) else [x])
    return out


def m7_frames(F):
    sport = 42000
    # name: (code, request sizes, response sizes, v6 flag offset or None)
    peerlist = sizes_of(4, 2, 1, 1, 4, 4, 16)
    peerlist_sum = sizes_of(4, 4, 2, [1] * 6, 4, 8, 4, 4, 4, 16, 16)
    peer_info_resp = sizes_of(4, 4, 2, [1] * 14, 2, 2, 4, 4, 4, 4, 4, 4, 32, 4, 8, 1, 4, 4, 8,
                              4, [4] * 7, 4, 4, 4, 16, 16)
    peer_stats_resp = sizes_of(4, 4, 2, 1, [4] * 16, [1] * 4, 4, 4, 16, 16)
    sys_info = sizes_of(4, 1, 1, 1, 1, 4, 4, 4, 8, 4, 1, 3, 4, 4, 8, 4, 4, 4, 16)
    config = sizes_of(4, [1] * 6, 2, 4, 128, 4, 4, 16)
    getrestrict = sizes_of(4, 4, 4, 2, 2, 4, 4, 16, 16)
    resflags = sizes_of(4, 4, 2, 2, 2, 4, 16, 16)
    layouts = [
        (0, peerlist, peerlist), (1, peerlist_sum, peerlist_sum),
        (2, peerlist, peer_info_resp), (3, peerlist, peer_stats_resp),
        (4, sys_info, sys_info), (5, [4] * 13, [4] * 13),
        (6, sizes_of(4, [2] * 4, [4] * 7), sizes_of(4, [2] * 4, [4] * 7)),
        (7, sizes_of(4, 2, 2, 4, 4, 4, 128), sizes_of(4, 2, 2, 4, 4, 4, 128)),
        (8, sizes_of(8, 8, 4, 4), sizes_of(8, 8, 4, 4)),
        (9, [4] * 4, [4] * 4), (10, config, config),
        (11, sizes_of(4, 4, 16), sizes_of(4, 4, 16)),
        (12, [4], [4]), (13, [4], [4]),
        (16, getrestrict, getrestrict), (17, resflags, resflags),
        (18, resflags, resflags), (19, resflags, resflags),
        (21, [4], [4]), (22, sizes_of(4, 4, 16), sizes_of(4, 4, 16)),
        (26, [8], [8]), (27, [8], [8]), (28, [4] * 9, [4] * 9),
        (29, sizes_of(4, 4, 2, 2, [4] * 4, 4, 16, 16), sizes_of(4, 4, 2, 2, [4] * 4, 4, 16, 16)),
        (30, sizes_of(4, 4, 2, 2, 4, 16, 16), sizes_of(4, 4, 2, 2, 4, 16, 16)),
        (31, sizes_of(4, 4, 2, 2, 4, 16, 16), sizes_of(4, 4, 2, 2, 4, 16, 16)),
        (32, [4], [4]), (33, [4], [4]), (34, [4] * 15, [4] * 15),
        (36, [4], sizes_of(4, [1] * 4, [4] * 5, 8, 8, 4, 4)),
        (37, sizes_of(4, 4, 8, 4), sizes_of(4, 4, 8, 4)),
        (38, sizes_of([4] * 4, 2, 2, [4] * 10), sizes_of([4] * 4, 2, 2, [4] * 10)),
        (39, [4], sizes_of(4, 1, 1, 2, 4, 64, 256)),
    ]
    for code, rq, rs in layouts:
        sport += 1
        F.append((0, udp(sport, 123, priv(code, False, 1, sum(rq), fill(rq, code)), True)))
        F.append((0, udp(123, sport, priv(code, True, 2, sum(rs), fill(rs, code) + fill(rs, code + 40)), False)))
    # MON_GETLIST (20) and MON_GETLIST_1 (42), v4 and v6 (the flag is at
    # offset 24 and 32; the address is read at offset 16)
    ml = sizes_of([4] * 5, 2, 1, 1, 4, 4)
    ml1 = sizes_of([4] * 7, 2, 1, 1, 4, 4)
    for code, sz, flagoff, v6 in ((20, ml, 24, 0), (20, ml + [16], 24, 1),
                                  (42, ml1, 32, 0), (42, ml1 + [16, 16], 32, 1)):
        item = setv6(fill(sz, 9), flagoff, v6)
        F.append((0, udp(43000 + code + v6, 123, priv(code, False, 1, len(item), item), True)))
        F.append((0, udp(123, 43000 + code + v6, priv(code, True, 2, len(item), item + item), False)))
    # items whose v6 flag is set: the flag is the 4 byte field after the v4 part
    for code, sz, v6off in ((0, peerlist, 8), (2, peerlist, 8), (3, peerlist, 8),
                            (11, sizes_of(4, 4, 16), 4), (22, sizes_of(4, 4, 16), 4)):
        item = setv6(fill(sz, code), v6off, True)
        F.append((0, udp(44000 + code, 123, priv(code, False, 1, len(item), item), True)))
    for code, sz, idx in ((1, peerlist_sum, len(peerlist_sum) - 4),
                          (2, peer_info_resp, len(peer_info_resp) - 4),
                          (3, peer_stats_resp, len(peer_stats_resp) - 4),
                          (4, sys_info, len(sys_info) - 3)):
        item = setv6(fill(sz, code), sum(sz[:idx]), True)
        F.append((0, udp(123, 44100 + code, priv(code, True, 1, len(item), item), False)))
    # IF_STATS / IF_RELOAD: the v6 flag is read at offset 48
    for code in (44, 45):
        for v6 in (0, 1):
            sz = sizes_of(4, 4, 4, 4, 32, [4] * 11, 2, 1, 1, 4) if not v6 else \
                sizes_of(16, 16, 16, 4, 32, [4] * 11, 2, 1, 1, 4)
            item = fill(sz, code)
            item += b'\0' * (136 - len(item))
            item = setv6(item, 48, v6)
            F.append((0, udp(45000 + code + v6, 123, priv(code, False, 1, 136, item), True)))
            F.append((0, udp(123, 45000 + code + v6, priv(code, True, 1, 136, item), False)))
    # unknown request code with an item; other implementations (no items
    # are dissected); error codes; more bit; sequence number; response
    F.append((0, udp(46000, 123, priv(99, False, 1, 8, ph(8)), True)))
    F.append((0, udp(123, 46000, priv(99, True, 0, 0), False)))
    F.append((0, udp(46001, 123, priv(4, False, 0, 0, impl=2), True)))
    F.append((0, udp(46001, 123, priv(4, False, 0, 0, impl=0, vn=3), True)))
    F.append((0, udp(123, 46001, priv(4, True, 0, 0, errcode=4, more=True, seq=5), False)))
    # authenticated request (auth bit): timestamp, key ID and MAC at 184
    items = fill(peerlist, 3)
    body = priv(0, False, 1, len(items), items, auth=True, seq=3)
    body += b'\0' * (184 - len(body)) + ts(T0 + 7) + struct.pack('!I', 9) + ph(16)
    F.append((0, udp(46002, 123, body, True)))
    body = priv(0, False, 1, len(items), items, auth=True, seq=4)
    body += b'\0' * (184 - len(body)) + ts(T0 + 8) + struct.pack('!I', 9)
    F.append((0, udp(46002, 123, body, True)))
    # an authenticated response does not read the authenticator
    body = priv(0, True, 1, len(items), items, auth=True, seq=4)
    F.append((0, udp(123, 46002, body, False)))


def malformed_frames():
    F = []
    F.append(req(47000, ntp_std()[:20]))                       # short header
    F.append(req(47000, ntp_std()[:47]))                       # one octet short
    F.append(req(47001, ctrl(2)[:8]))                          # control, cut at associd
    F.append(rsp(47001, ctrl(2, resp=True, count=100, data=b'a=1')))  # count > data
    F.append(rsp(47001, ctrl(1, resp=True, count=64, data=b'')))      # READSTAT, no data
    F.append(rsp(47001, ctrl(12, resp=True, count=40, data=b'x' * 8, auth=b'')))
    F.append((0, udp(47002, 123, priv(99, False, 1, 0), True)))       # unknown code, size 0
    F.append((0, udp(47002, 123, priv(0, False, 3, 4, b'\0' * 12), True)))   # itemsize 4
    F.append((0, udp(123, 47002, priv(2, True, 2, 40, b'\0' * 80), False)))
    F.append((0, udp(47002, 123, priv(20, False, 1, 8, b'\0' * 8), True)))  # monlist item short
    F.append((0, udp(47002, 123, priv(44, False, 1, 20, b'\0' * 20), True)))
    F.append((0, udp(47002, 123, priv(4, False, 1, 8, ph(8), auth=True), True)))  # auth cut
    F.append((0, udp(47002, 123, priv(4, True, 0xfff, 0xfff, b''), True)))     # many items, none present
    F.append((0, udp(47002, 123, struct.pack('!BB', 0x17, 0), True)))         # mode 7 cut
    # NTS authenticator whose nonce and ciphertext lengths exceed the field
    F.append(req(47003, ntp_std(tail=ext(0x0104, UID1) + ext(0x0204, COOKIE1)
                                + ext(0x0404, struct.pack('!HH', 400, 400) + ph(40)))))
    F.append(req(47003, ntp_std(tail=ext(0x0404, struct.pack('!HH', 0xffff, 8) + ph(28)))))
    # ext too long for the packet
    F.append(req(47004, ntp_std(tail=struct.pack('!HH', 0x0777, 64) + ph(12))))
    # an extension whose length is not a multiple of 4 followed by a MAC,
    # and one shorter than 8 (no preceding length check passes the prescan)
    F.append(req(47004, ntp_std(tail=struct.pack('!HH', 0x0777, 22) + ph(18)
                                + struct.pack('!I', 4) + ph(16))))
    F.append(req(47004, ntp_std(tail=struct.pack('!HH', 0x0777, 17) + ph(13)
                                + struct.pack('!I', 4) + ph(16))))
    # a mode 6 request with an authenticator that is cut short
    F.append(req(47005, ctrl(8, data=b'abc', auth=ph(10))))
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
    pcapng(os.path.join(out, 'ntp-coverage.pcapng'), main_frames('-v' in sys.argv))
    pcapng(os.path.join(out, 'ntp-coverage-malformed.pcapng'), malformed_frames())

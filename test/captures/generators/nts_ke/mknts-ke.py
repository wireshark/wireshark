#!/usr/bin/env python3
# Generates test/captures/nts_ke_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NTS-KE coverage capture (packet-nts-ke.c).

Usage: mknts-ke.py <output directory> [-v]   (-v prints the frame ranges)

Writes nts-ke-coverage.pcapng (main capture) and
nts-ke-coverage-malformed.pcapng. NTS-KE runs inside TLS; a capture
without TLS keys cannot reach it, so the records are in Exported PDU
frames naming the "nts-ke" dissector. A TCP handshake to port 4460 (no
TLS) gives the Exported PDU frames a TCP conversation, so that the
request/response direction is known. Cookies are made-up bytes.
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


def tcp(sport, dport, flags, seq, ack, payload=b'', to_server=True):
    # SYN and SYN/ACK carry MSS, SACK permitted and window scale options
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 2 else b''
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                    flags, 8192, 0, 0) + opts + payload
    s, d = (CLI, SRV) if to_server else (SRV, CLI)
    return (0, eth(ip4(6, t, s, d), to_server))


def udp(sport, dport, payload, to_server=True):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    s, d = (CLI, SRV) if to_server else (SRV, CLI)
    return (0, eth(ip4(17, u, s, d), to_server))


def exp_pdu(payload, to_server, sport=50000, dport=4460, with_ports=True):
    t = struct.pack('!HH', 12, 8) + b'nts-ke\0\0'
    src, dst = (CLI, SRV) if to_server else (SRV, CLI)
    if with_ports:
        ps, pd = (sport, dport) if to_server else (dport, sport)
        t += struct.pack('!HH4s', 20, 4, src) + struct.pack('!HH4s', 21, 4, dst)
        t += struct.pack('!HHI', 24, 4, 2)
        t += struct.pack('!HHI', 25, 4, ps) + struct.pack('!HHI', 26, 4, pd)
    t += struct.pack('!HH', 0, 0)
    return (1, t + payload)


def rec(typ, body, crit=True):
    return struct.pack('!HH', (0x8000 if crit else 0) | typ, len(body)) + body


def ph(n, k=0):
    return bytes((k + i * 7) & 0xff for i in range(n))


def u16s(*v):
    return b''.join(struct.pack('!H', x) for x in v)


END = rec(0, b'')
NEXT0 = rec(1, u16s(0))
AEAD15 = rec(4, u16s(15), False)


def ntp_server_response(uid, new_cookie, dport):
    """NTP server response with the UID of a request, an authenticator
    (placeholder bytes) and a new cookie in clear: the cookie is looked
    up by UID and copied."""
    def ext(typ, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('!HH', typ, 4 + len(body)) + body
    ts = struct.pack('!II', 3900000000, 5)
    n = struct.pack('!BBbbII4s', 0x24, 2, 6, -20, 0x10000, 0x20000, bytes([192, 0, 2, 1])) + ts * 4
    n += ext(0x0104, uid) + ext(0x0404, struct.pack('!HH', 16, 32) + ph(48, 91))
    n += ext(0x0204, new_cookie)
    u = struct.pack('!HHHH', 123, dport, 8 + len(n), 0) + n
    return (0, eth(ip4(17, u, SRV, CLI), False))


def ntp_cookie_request(cookie, uid, sport):
    """NTP client request with a UID and a cookie extension (placeholder
    authenticator): makes the cookie "used"."""
    def ext(typ, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('!HH', typ, 4 + len(body)) + body
    ts = struct.pack('!II', 3900000000, 5)
    n = struct.pack('!BBbbII4s', 0x23, 0, 6, -20, 0x10000, 0x20000, b'\0\0\0\0') + ts * 4
    n += ext(0x0104, uid) + ext(0x0204, cookie)
    n += ext(0x0404, struct.pack('!HH', 16, 32) + ph(48, 90))
    u = struct.pack('!HHHH', sport, 123, 8 + len(n), 0) + n
    return (0, eth(ip4(17, u, CLI, SRV), True))


COOKIES = [ph(104, 3 + i) for i in range(8)]


def main_frames(verbose=False):
    F = []
    marks = []

    def mark(name):
        marks.append((len(F) + 1, name))

    mark('TCP handshake to port 4460 (no TLS)')
    F.append(tcp(50000, 4460, 0x02, 1000, 0))
    F.append(tcp(4460, 50000, 0x12, 5000, 1001, to_server=False))
    F.append(tcp(50000, 4460, 0x10, 1001, 5001))
    mark('Request and response on the known TCP conversation')
    F.append(exp_pdu(NEXT0 + rec(4, u16s(15, 17), False) + END, True))      # request
    F.append(exp_pdu(NEXT0 + AEAD15 + b''.join(rec(5, c, False) for c in COOKIES[:8])
                     + rec(6, b'ntp.example.net', False) + rec(7, u16s(123), False)
                     + rec(3, u16s(1)) + END, False))                       # response
    mark('Other records and values')
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(5, COOKIES[0], False)
                     + rec(5, COOKIES[0], False) + rec(2, u16s(1)) + END, False))   # duplicate cookie, error 1
    F.append(exp_pdu(rec(1, u16s(0, 1, 0x1234)) + rec(4, u16s(30, 40000), False)
                     + rec(5, COOKIES[1], False) + rec(0x7ffe, ph(6), False) + END, True))
    F.append(exp_pdu(rec(1, u16s(1)) + AEAD15 + rec(5, COOKIES[2], False) + END, False))  # no NTPv4
    F.append(exp_pdu(NEXT0 + rec(4, u16s(200), False) + rec(5, COOKIES[3], False) + END, False))  # unknown AEAD
    F.append(exp_pdu(NEXT0 + rec(4, u16s(0), False) + rec(5, COOKIES[3], False) + END, False))  # AEAD 0
    F.append(exp_pdu(NEXT0 + rec(4, u16s(30), False) + rec(5, ph(100, 77), False) + END, False))  # AEAD_AES_128_GCM_SIV
    F.append(exp_pdu(rec(1, b'') + rec(6, b'', False) + rec(5, b'', False) + END, True))   # empty bodies
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(2, u16s(0)) + rec(2, u16s(2)) + rec(2, u16s(0xffff))
                     + rec(3, u16s(0)) + rec(3, u16s(0x4141)) + END, False))
    mark('Unknown conversation (direction not known), no ports')
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(5, COOKIES[4], False) + END, False, sport=51111))
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(5, COOKIES[5], False) + END, True, sport=51111))
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(5, COOKIES[6], False) + END, False, with_ports=False))
    mark('Second request/response on the first conversation')
    F.append(exp_pdu(NEXT0 + AEAD15 + END, True))
    F.append(exp_pdu(NEXT0 + AEAD15 + rec(5, COOKIES[7], False) + END, False))
    mark('NTP requests that use cookies')
    F.append(ntp_cookie_request(COOKIES[0], ph(32, 21), 40001))
    F.append(ntp_cookie_request(COOKIES[0], ph(32, 22), 40002))   # same cookie, another UID
    F.append(ntp_cookie_request(COOKIES[1], ph(32, 23), 40003))
    F.append(ntp_server_response(ph(32, 21), ph(104, 50), 40001))   # new cookie by UID
    F.append(ntp_server_response(ph(32, 21), ph(104, 50), 40001))   # same cookie again
    F.append(ntp_server_response(ph(32, 99), ph(104, 51), 40001))   # UID not known
    mark('64 KiB records: reproducer of the quadratic cookie scan')
    n_next, n_cookie = 16000, 8000
    big = (rec(4, u16s(15), False) + struct.pack('!HH', 0x8001, 2 * n_next)
           + struct.pack('!H', 1) * n_next + struct.pack('!HH', 0x0005, 0) * n_cookie + END)
    F.append(exp_pdu(big, False))
    # the same size with protocol 0 offered: every cookie record is a
    # (empty) cookie that is not stored; and 2000 cookies of 4 octets
    big2 = (rec(4, u16s(15), False) + struct.pack('!HH', 0x8001, 4) + u16s(1, 0)
            + b''.join(rec(5, ph(4, i & 255), False) for i in range(2000)) + END)
    F.append(exp_pdu(big2, True, sport=51112))
    mark('End')
    if verbose:
        for (n, name), nxt in zip(marks, marks[1:]):
            print('%d-%d: %s' % (n, nxt[0] - 1, name))
        print('total', len(F))
    return F


def malformed_frames():
    F = []
    # a connection with a known direction for the first frames
    F.append(tcp(50100, 4460, 0x02, 1000, 0))
    F.append(tcp(4460, 50100, 0x12, 5000, 1001, to_server=False))
    F.append(tcp(50100, 4460, 0x10, 1001, 5001))

    def e(payload, to_server=True):
        return exp_pdu(payload, to_server, sport=50100)
    # odd bodies of Next Protocol and AEAD records (fixed: no read past the body)
    F.append(e(rec(1, u16s(0) + b'\x07') + AEAD15 + END))
    F.append(e(NEXT0 + rec(4, u16s(15) + b'\x01', False) + END))
    F.append(e(rec(1, b'\x00') + END))
    F.append(e(NEXT0 + rec(4, b'\x0f', False) + rec(5, ph(40), False) + END))
    # critical bit missing: next protocol, end, error, warning
    F.append(e(rec(1, u16s(0), False) + rec(3, u16s(1), False) + rec(2, u16s(1), False)
               + rec(0, b'', False)))
    # no end record, no next protocol record, two next protocol records
    F.append(e(AEAD15 + rec(5, ph(40), False)))
    F.append(e(NEXT0 + NEXT0 + AEAD15 + END))
    # records after the end record
    F.append(e(NEXT0 + END + rec(5, ph(40), False) + END))
    # end record with a body
    F.append(e(NEXT0 + rec(0, ph(6)) ))
    # error and warning records, port record with the wrong length
    F.append(e(NEXT0 + rec(2, ph(3)) + rec(3, ph(1)) + rec(7, ph(4), False) + rec(7, b'', False) + END))
    # a record whose body is longer than the PDU
    F.append(e(NEXT0 + struct.pack('!HH', 5, 400) + ph(20)))
    # record header only partly present (3 octets after a record)
    F.append(e(NEXT0 + END + b'\x00\x05\x00'))
    # less than a record
    F.append(e(b'\x80\x00'))
    F.append(e(b''))
    # a cookie record body longer than the PDU after AEAD and NEXT
    F.append(e(NEXT0 + AEAD15 + struct.pack('!HH', 5, 4000) + ph(10)))
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != '-v' else '.'
    pcapng(os.path.join(out, 'nts-ke-coverage.pcapng'), main_frames('-v' in sys.argv))
    pcapng(os.path.join(out, 'nts-ke-coverage-malformed.pcapng'), malformed_frames())

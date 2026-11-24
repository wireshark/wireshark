#!/usr/bin/env python3
# Generates test/captures/manolito_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic MANOLITO captures.  Usage: mkmanolito.py <outdir>
Writes manolito-coverage.pcap and manolito-coverage-malformed.pcap."""
import os
import struct
import sys

PORT = 41170


def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip_udp(payload, sport=PORT, dport=PORT):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


def hdr(seq=1, src='0.0.0.0', dst='192.0.2.2', opts=0x00000000, cks=0x12345678):
    import socket
    return (struct.pack('>II', cks, seq) + socket.inet_aton(src) + socket.inet_aton(dst)
            + struct.pack('>I', opts))


def s(name, text):
    """String field: 2 byte name, type 1, length, text."""
    return name.encode() + bytes([1, len(text)]) + text.encode()


def i(name, value, length):
    """Integer field of 1..5 bytes."""
    return name.encode() + bytes([0, length]) + value.to_bytes(length, 'big')


def crc16(data, page):
    """CRC-16/CCITT (0x1021, MSB first, init 0) over the UTF-16LE form of the message in a Windows code page."""
    crc = 0
    for b in data:
        u = b
        if b >= 0x80:
            try:
                u = ord(bytes([b]).decode(page))
            except UnicodeDecodeError:
                u = b          # undefined in the page: hashed as itself
        for c in (u & 0xff, u >> 8):
            crc ^= c << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def build():
    main, bad = [], []

    def f(frame, page='cp1252'):
        """Append a frame with the checksum of its message (after the 4 checksum octets)."""
        pl = frame[42:]
        crc = struct.pack('>HH', crc16(pl[4:], page), 0) if len(pl) > 4 else pl[:4]
        main.append(frame[:42] + crc + pl[4:])
    # pings: header only (20 bytes), and the truncated one (19 bytes)
    f(ip_udp(hdr(1)))
    f(ip_udp(hdr(2, opts=0x01020304)[:19]))
    f(ip_udp(hdr(3, src='192.0.2.9')))
    # Search Hit: CK first
    f(ip_udp(hdr(10) + s('CK', 'a1b2c3d4e5f60718') + s('FN', 'song.mp3') + i('FL', 3456789, 4)
             + i('BR', 128, 2) + i('FC', 44100, 3) + i('SL', 215, 2) + s('NN', 'alice')))
    # User Information: NC first, every integer length 1..5
    f(ip_udp(hdr(11) + i('NC', 12, 1) + i('SF', 1234, 2) + i('SK', 2 ** 36 + 5, 5) + i('PT', 41170, 2)
             + s('CN', 'Manolito') + s('CV', '3.0.1') + i('VL', 3, 1) + s('NI', 'net0')))
    # Search Query: FN first
    f(ip_udp(hdr(12) + b'FN\x01\x09' + bytes.fromhex('5a61bff3b3e6202020') + s('NN', 'bob')), 'cp1250')   # Windows-1250 text
    # Search Query (by hash): ID first
    f(ip_udp(hdr(13) + s('ID', 'deadbeefdeadbeef') + i('AD', 7, 1) + s('HN', 'host') + s('ST', 'x')))
    # Download Request: PT first
    f(ip_udp(hdr(14) + i('PT', 6699, 2) + s('FN', 'file.mp3') + s('ME', 'hello')))
    # Chat: ME first
    f(ip_udp(hdr(15) + s('ME', 'hi there') + s('NN', 'carol')))
    # no recognised first field: unknown field names, empty string, bad integer length (ignored)
    f(ip_udp(hdr(16) + s('ZZ', '') + i('QQ', 5, 1)))
    f(ip_udp(hdr(17) + b'XY\x00\x06' + b'123456' + s('ME', 'after bad int length')))
    f(ip_udp(hdr(18) + b'XY\x00\x00'))   # integer of length 0
    # second packet types in one packet: the first recognised field wins
    f(ip_udp(hdr(19) + s('CK', 'abcd') + s('NC', 'x') + s('PT', 'y')))
    f(ip_udp(hdr(20) + s('ZZ', 'q') + s('NC', 'x') + s('FN', 'late')))
    f(ip_udp(hdr(21, src='10.1.2.3', dst='10.4.5.6', opts=0xffffffff, cks=0) + b'ME\x01\xc8' + bytes.fromhex('f9ece5ed20f2e5eced') + b'x' * 191), 'cp1255')   # Windows-1255 text
    # source port elsewhere (still destination port 41170)
    f(ip_udp(hdr(22) + s('ME', 'other source port'), sport=50000))

    # ---- malformed capture
    g = bad.append
    g(ip_udp(hdr(30) + b'ME\x07\x04abcd'))                  # unknown type 7: expert info
    g(ip_udp(hdr(31) + s('ME', 'ok') + b'NN\x02\x00'))      # unknown type 2
    g(ip_udp(hdr(32) + b'ME\x01\x20abc'))                   # string longer than the packet
    g(ip_udp(hdr(33) + b'PT\x00\x04\x00\x01'))              # integer longer than the packet
    g(ip_udp(hdr(34)[:10]))                                 # truncated header
    g(ip_udp(hdr(35) + b'ME'))                              # truncated field header
    g(ip_udp(hdr(36) + b'ME\x01'))                          # length missing
    g(ip_udp(hdr(37)[:17]))                                 # 1 byte of options
    return main, bad


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m, b = build()
    pcap(os.path.join(out, 'manolito-coverage.pcap'), m)
    pcap(os.path.join(out, 'manolito-coverage-malformed.pcap'), b)

#!/usr/bin/env python3
# Generates test/captures/lsd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LSD (BitTorrent Local Service Discovery) coverage captures.
# Usage: mklsd.py <outdir>.  Writes lsd-coverage.pcap and
# lsd-coverage-malformed.pcap.  LSD is a UDP heuristic dissector (default
# on): destination 239.192.152.143 (or any IPv6 destination) port 6771.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT = 6771

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def v4(payload, dst=bytes([239, 192, 152, 143]), dport=PORT, ident=1):
    src = bytes([192, 0, 2, 1])
    u = struct.pack('!HHHH', 6771, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 1, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + u
    return bytes.fromhex('01005e40988f') + bytes.fromhex('020000000001') + b'\x08\x00' + ip

def v6(payload, ident=1):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('ff1500000000000000000000efc0988f')    # ff15::efc0:988f
    u = struct.pack('!HHHH', 6771, PORT, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    ip = struct.pack('!IHBB16s16s', 0x60000000, len(u), 17, 1, src, dst) + u
    return bytes.fromhex('3333efc0988f') + bytes.fromhex('020000000001') + b'\x86\xdd' + ip

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

IH = b'0123456789abcdef0123456789abcdef01234567'   # made-up info hash
def msg(host=b'239.192.152.143:6771', port=b'6881', ih=IH, cookie=b'a1b2c3d4', eol=b'\r\n', end=True):
    s = b'BT-SEARCH * HTTP/1.1' + eol
    if host is not None: s += b'Host: ' + host + eol
    if port is not None: s += b'Port: ' + port + eol
    if ih is not None: s += b'Infohash: ' + ih + eol
    if cookie is not None: s += b'cookie: ' + cookie + eol
    if end: s += eol
    return s

fr = []
fr.append(v4(msg()))                                            # 1 with cookie
fr.append(v4(msg(cookie=None)))                                 # 2 without cookie
fr.append(v6(msg(host=b'[ff15::efc0:988f]:6771', port=b'51413')))     # 3 IPv6 destination
fr.append(v4(msg(eol=b'\n')))                                   # 4 bare LF line ends
fr.append(v4(msg(port=b'0', cookie=b'')))                       # 5 port 0, empty cookie
fr.append(v4(msg(port=b'65535', host=b'239.192.152.143')))      # 6 port 65535, host without port
fr.append(v4(b'BT-SEARCH * HTTP/1.1\r\nhost:   239.192.152.143:6771\r\nPORT:6881\r\nINFOHASH:   ' + IH + b'\r\nCOOKIE: x\r\n\r\n'))  # 7 mixed case, extra blanks
fr.append(v4(msg(cookie=None).rstrip(b'\r\n') + b'\r\nX-Extra: ignored\r\n\r\n'))   # 8 a fourth line that is not a cookie
fr.append(v4(msg(ih=IH[:20])))                                  # 9 short info hash
pcap(os.path.join(OUT, 'lsd-coverage.pcap'), fr)

bad = []
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost\r\nPort\r\nInfohash\r\n'))                    # 1 no colons
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort: 99999\r\nInfohash: y\r\ncookie: z\r\n'))   # 2 overflowing port
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nXort: 1\r\nInfohash: y\r\ncookie'))      # 3 wrong port field, cookie without colon
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort: abc\r\nInfohash: y\r\n'))          # 4 non-numeric port
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort\r\nInfohash: y\r\n'))               # 5 Port without value
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\n'))                                                # 6 header only
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\n'))                                      # 7 stops after Host
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort: 1\r\n'))                           # 8 stops after Port
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort: 1\r\nInfohash: y'))                # 9 no line end after Infohash
bad.append(v4(b'BT-SEARCH * HTTP/1.1\r\nHost: x\r\nPort: 1\r\nXnfohash: y\r\n'))            # 10 wrong infohash field
bad.append(v4(b'BT-SEARCH'))                                                               # 11 no line end at all
bad.append(v4(b''))                                                                        # 12 empty datagram
bad.append(v4(msg(), dst=bytes([239, 192, 152, 144])))                                      # 13 another multicast group: not LSD
bad.append(v4(msg(), dport=6772))                                                          # 14 another port: not LSD
pcap(os.path.join(OUT, 'lsd-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))

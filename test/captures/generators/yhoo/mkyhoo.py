#!/usr/bin/env python3
# Generates test/captures/yhoo_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the YHOO coverage capture with struct only (nothing is captured).
# Usage: mkyhoo.py <outdir>
#   yhoo-coverage.pcap            Ethernet/IPv4/TCP on port 5050
#   yhoo-coverage-malformed.pcap  frames the heuristic rejects or that are cut
# YHOO is disabled by default (protocol and heuristic "yhoo_tcp"), and port
# 5050 is also claimed by another dissector, so tshark needs
#   --enable-protocol yhoo --enable-heuristic yhoo_tcp -o tcp.try_heuristic_first:TRUE
import struct
import sys
import os

def pcap(path, frames, snap=None):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            cap = fr if snap is None else fr[:snap]
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(cap), len(fr)))
            f.write(cap)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def tcp_frame(sport, dport, seq, payload, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2])):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + t

def yhoo(magic, service, content, msgtype=1, nick1='alice', nick2='bob', conn=1, magicid=2, unk=3, length=None):
    body = struct.pack('<IIIIII', len(content) if length is None else length, service, conn, magicid, unk, msgtype)
    body += nick1.encode().ljust(36, b'\0') + nick2.encode().ljust(36, b'\0') + content
    return magic + b'\0' * (8 - len(magic)) + body

SERVICES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 70, 157, 188, 189, 190, 193, 194,
            198, 208, 550, 746]
MSGTYPES = [0, 1, 2, 4, 1515563606, 77]

def main(out):
    frames = []
    seq = {}
    def send(cport, srv_is_src, payload):
        key = (cport, srv_is_src)
        s = seq.get(key, 1000)
        seq[key] = s + len(payload)
        if srv_is_src:
            frames.append(tcp_frame(5050, cport, s, payload))
        else:
            frames.append(tcp_frame(cport, 5050, s, payload))
    # every service of the value strings, requests (YPNS) to the server and
    # responses (YHOO) from it, with every message type
    for i, svc in enumerate(SERVICES):
        resp = i % 2
        content = ('content %d for service %d' % (i, svc)).encode()
        p = yhoo(b'YHOO' if resp else b'YPNS', svc, content, msgtype=MSGTYPES[i % len(MSGTYPES)],
                 nick1='alice%d' % i, nick2='bob', conn=0x1000 + i, magicid=0xabcd0000 + i)
        send(40000 + i % 4, resp, p)
    # unknown service
    send(40010, 0, yhoo(b'YPNS', 999, b'unknown service'))
    # content of one octet (the smallest PDU that is accepted: 105 octets)
    send(40010, 1, yhoo(b'YHOO', 6, b'x', msgtype=4))
    # nicks filling all 36 octets, binary content
    send(40011, 0, yhoo(b'YPNS', 6, bytes(range(32, 127)), nick1='n' * 36, nick2='m' * 36))
    # YPNS with length field not matching the content
    send(40012, 0, yhoo(b'YPNS', 6, b'short claim', length=3))
    pcap(os.path.join(out, 'yhoo-coverage.pcap'), frames)

    # rejected by the heuristic or truncated
    M = []
    def m(sport, dport, payload):
        M.append(tcp_frame(sport, dport, 1, payload))
        M[-1] = tcp_frame(sport + len(M), dport, 1, payload) if dport == 5050 and sport != 5050 else M[-1]
    full = yhoo(b'YPNS', 6, b'hello')
    m(40020, 5050, full[:104])                       # 1 octet short of the minimum
    m(40020, 5050, full[:20])                        # truncated header
    m(40020, 5050, b'')                              # no payload
    m(40020, 5050, yhoo(b'YPNX', 6, b'bad magic'))   # magic is not YPNS/YHOO
    m(40020, 5050, yhoo(b'ypns', 6, b'lowercase'))   # case matters
    m(40021, 6000, full)                             # not port 5050
    m(6000, 40021, yhoo(b'YHOO', 6, b'also not 5050'))
    m(5050, 5050, yhoo(b'YHOO', 6, b'both ports'))   # accepted
    # captured length cut below 105 with a longer original frame
    pcap(os.path.join(out, 'yhoo-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/hpfeeds_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HPFEEDS dissector (packet-hpfeeds.c).

HPFEEDS (HoneyPot Feeds) is a TCP protocol: a 32 bit length (including
the length field), an opcode (0 error, 1 info, 2 auth, 3 publish, 4
subscribe) and fields made of one octet lengths and strings. It has no
registered port (Decode As on tcp.port only), so the captures use TCP
20000 and need "-d tcp.port==20000,hpfeeds". Authentication secrets are
constant placeholder bytes, not hashes. Every packet is built with
struct; addresses are from 192.0.2.0/24.

Usage: mkhpfeeds.py <output directory>
Writes hpfeeds-coverage.pcap and hpfeeds-coverage-malformed.pcap.
"""
import struct
import sys
import os

PORT = 20000

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_pkt(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opts = struct.pack('!BBH', 2, 4, 1460) if flags & 0x02 else b''
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    ps = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ps + tcp)) + tcp[18:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

class Flow:
    """TCP connection with a handshake and tracked sequence numbers."""
    def __init__(self, cport, sport=PORT, c=(192,0,2,1), s=(192,0,2,2), handshake=True):
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.pkts = []
        if handshake:
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.pkts.append(tcp_pkt(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def c2s(self, data):
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data)); self.cseq += len(data)
    def s2c(self, data):
        self.pkts.append(tcp_pkt(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data)); self.sseq += len(data)

def msg(opcode, body):
    return struct.pack('!IB', 5 + len(body), opcode) + body

def s8(b):
    return bytes([len(b)]) + b

def info(name=b'hpfeeds-broker', nonce=b'\x01\x02\x03\x04'):
    return msg(1, s8(name) + nonce)

def auth(ident=b'client1', secret=bytes(20)):
    return msg(2, s8(ident) + secret)

def publish(ident, chan, payload):
    return msg(3, s8(ident) + s8(chan) + payload)

def subscribe(ident, chan):
    return msg(4, s8(ident) + chan)

def error(text):
    return msg(0, text)

JSON1 = b'{"sensor": "a1", "count": 3, "ok": true}'
JSON2 = b'{"event": "login", "list": [1, 2, 3]}'

def main_frames():
    F = []
    # connection 1 (frames 1-...): handshake, info, auth, subscribe, publishes
    f = Flow(40000)
    f.s2c(info())
    f.c2s(auth())
    f.c2s(subscribe(b'client1', b'honeypot.events'))
    f.c2s(subscribe(b'client1', b'a'))
    f.c2s(publish(b'client1', b'honeypot.events', JSON1))          # JSON heuristic
    f.c2s(publish(b'client1', b'honeypot.events', b'\x00\x01\x02binary payload'))
    f.s2c(publish(b'server', b'dionaea.capture', JSON2))
    f.s2c(error(b'authentication failed'))
    f.s2c(info(b'x', b'n'))                                        # shortest name and nonce
    F += f.pkts

    # connection 2: two PDUs in one segment, a PDU over three segments,
    # a PDU whose header (length field) is split over two segments
    g = Flow(40001)
    g.s2c(info(b'broker-2', bytes(range(32))))
    g.c2s(auth(b'c2') + subscribe(b'c2', b'chan.a') + publish(b'c2', b'chan.a', b'two in one'))
    p = publish(b'c2', b'chan.b', JSON1)
    g.c2s(p[:10]); g.c2s(p[10:30]); g.c2s(p[30:])
    p = publish(b'c2', b'chan.c', b'split length field')
    g.c2s(p[:2]); g.c2s(p[2:])
    # a long ident (255 octets) and a 255 octet channel
    g.c2s(publish(b'i' * 255, b'c' * 255, b'long names'))
    F += g.pkts

    # connection 3: the stats tree reproducer (channel names that are
    # prefixes of each other, and an empty channel name)
    h = Flow(40002)
    h.c2s(publish(b'id', b'abc', b'X' * 100))
    h.c2s(publish(b'id', b'a', b'Y' * 7))
    h.c2s(publish(b'id', b'', b'Z' * 3))
    h.c2s(publish(b'id', b'abc', b'X' * 10))
    h.c2s(publish(b'id', b'abcd', b'W' * 5))
    h.c2s(publish(b'id', b'a', b'V' * 1))
    F += h.pkts

    # connection 4: heuristic JSON dissector reached with a channel and a
    # payload that is not JSON; publish with an exactly 0 octet channel
    k = Flow(40003)
    k.c2s(publish(b'k', b'not.json', b'plain text, not JSON at all'))
    k.c2s(publish(b'k', b'json.again', JSON2))
    F += k.pkts
    return F

def malformed_frames():
    F = []
    f = Flow(41000)
    f.c2s(msg(9, b'abc'))                         # unknown opcode (expert info)
    f.c2s(msg(0xff, b''))                         # unknown opcode, empty
    f.c2s(msg(3, bytes([200]) + b'short'))        # publish with ident length past the end
    f.c2s(msg(3, s8(b'id') + bytes([50]) + b'short'))   # channel length past the end
    f.c2s(msg(3, b''))                            # publish without anything
    f.c2s(msg(1, bytes([100]) + b'abc'))          # info with server length past the end
    f.c2s(msg(2, bytes([100]) + b'abc'))          # auth with ident length past the end
    f.c2s(msg(4, bytes([100]) + b'abc'))          # subscribe with ident length past the end
    f.c2s(subscribe(b'client1', b''))             # empty channel: nothing left to add (exception)
    f.c2s(publish(b'client1', b'honeypot.events', b''))  # empty payload (exception)
    f.c2s(info(b'', b''))                         # empty name and nonce (exception)
    f.c2s(struct.pack('!IB', 5, 0))               # error without message
    f.c2s(struct.pack('!I', 3) + b'xy')           # length smaller than the header
    f.c2s(msg(3, s8(b'abc') + b'\x01'))           # publish where the channel length is the last octet
    F += f.pkts
    g = Flow(41001)
    g.c2s(struct.pack('!IB', 0x7fffffff, 3) + b'oversized length')    # length far past the data (reassembly waits)
    g.c2s(struct.pack('!I', 0) + b'\x03' + b'zero length')
    F += g.pkts
    return F

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hpfeeds-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hpfeeds-coverage-malformed.pcap'), malformed_frames())

#!/usr/bin/env python3
# Generates test/captures/zmtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ZMTP coverage captures: mkzmtp.py <outdir>.
ZMTP (ZeroMQ) has no registered TCP port: it is reached with Decode As or
the "zmtp.tcp.port" preference (the captures use ports 5555-5562; tests
and runcov.sh use -o zmtp.tcp.port:5555-5562).  Data payloads can be
handed to another dissector with the UAT "zmtp_tcp_protocols".
CURVE and PLAIN messages hold filler bytes; nothing is encrypted."""
import struct
import sys
import os

A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MA, MB = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'

def ipck(ip):
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    return ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]

class Conn:
    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.id = 1
    def _pkt(self, fromc, payload, seq, ack):
        if fromc:
            s, d, sp, dp, ms, md = A, B, self.cport, self.sport, MA, MB
        else:
            s, d, sp, dp, ms, md = B, A, self.sport, self.cport, MB, MA
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        self.id += 1
        ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), self.id, 0, 64, 6, 0, s, d))
        return md + ms + b'\x08\x00' + ip + tcp + payload
    def c(self, payload):
        p = self._pkt(True, payload, self.cseq, self.sseq); self.cseq += len(payload); return p
    def s(self, payload):
        p = self._pkt(False, payload, self.sseq, self.cseq); self.sseq += len(payload); return p

def greeting(mech, server, major=3, minor=1):
    return b'\xff' + b'\0' * 8 + b'\x7f' + bytes([major, minor]) + mech.encode().ljust(20, b'\0') + bytes([1 if server else 0]) + b'\0' * 31

def short(flags, body):
    return bytes([flags, len(body)]) + body

def long_(flags, body, length=None):
    return bytes([flags]) + struct.pack('>Q', len(body) if length is None else length) + body

def cmd(name, body=b'', long=False):
    b = bytes([len(name)]) + name.encode() + body
    return long_(6, b) if long else short(4, b)

def prop(key, value=b''):
    k = key.encode()
    return bytes([len(k)]) + k + struct.pack('>I', len(value)) + value

def fill(n, v):
    return bytes([(v + i) & 0xff for i in range(n)])

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main(out):
    f = []
    # ---- NULL mechanism, port 5555
    c = Conn(40500, 5555)
    f.append(c.c(greeting('NULL', False)))                                         # 1
    f.append(c.s(greeting('NULL', True)))                                          # 2
    f.append(c.c(cmd('READY', prop('Socket-Type', b'DEALER') + prop('Identity', b'client-1'))))   # 3
    f.append(c.s(cmd('READY', prop('Socket-Type', b'ROUTER') + prop('Identity')))) # 4 empty value
    f.append(c.c(short(0, b'hello')))                                              # 5 short, last
    f.append(c.c(short(1, b'first part, more follows')))                           # 6 short, more
    f.append(c.c(long_(2, fill(300, 0x80))))                                       # 7 long, last, binary
    f.append(c.s(long_(3, b'text ' * 52)))                                         # 8 long, more, text
    f.append(c.c(short(0, b'')))                                                   # 9 empty
    f.append(c.c(short(0, b'A\x01\x02\x03')))                                      # 10 starts like text, is binary
    f.append(c.c(cmd('PING', b'\x00\x0a' + b'ctx')))                               # 11 PING with context
    f.append(c.s(cmd('PONG', b'ctx')))                                             # 12
    f.append(c.c(cmd('PING', b'\x01\x00')))                                        # 13 PING without context
    f.append(c.s(cmd('ERROR', bytes([13]) + b'Invalid state')))                    # 14
    f.append(c.c(cmd('FOO', b'unknown command')))                                  # 15
    f.append(c.c(cmd('READY', prop('Socket-Type', b'PUB'), long=True)))            # 16 long command
    f.append(c.c(cmd('HELLO', b'\x00\x01') + cmd('WELCOME', fill(20, 1)) + cmd('INITIATE', prop('k', b'v'))))  # 17 mechanism NULL: unexpected commands, three in a segment
    f.append(c.s(short(0, b'one') + short(1, b'two') + short(0, b'three')))       # 18 three messages in a segment
    p = long_(2, b'split message body ' * 4)
    f.append(c.c(p[:30])); f.append(c.c(p[30:]))                                   # 19-20 a message split across segments
    # fix reproducer: the long-form header is cut after the flags and 4 length bytes, at a
    # non-zero offset of the segment (used to throw once more than 9 octets were captured)
    p = long_(2, b'header split in the segment')
    f.append(c.c(short(0, b'abcdefgh') + p[:5]))                                   # 21
    f.append(c.c(p[5:]))                                                           # 22
    f.append(c.s(short(1, bytes(range(32, 127)))))                                 # 23 printable text, all of it

    # ---- PLAIN, port 5556
    c = Conn(40501, 5556)
    f.append(c.c(greeting('PLAIN', False)))                                        # 24
    f.append(c.s(greeting('PLAIN', True)))                                         # 25
    f.append(c.c(cmd('HELLO', bytes([5]) + b'admin' + bytes([6]) + b'secret')))    # 26 PLAIN HELLO
    f.append(c.c(cmd('HELLO', b'\x00\x00')))                                       # 27 empty user and password
    f.append(c.s(cmd('WELCOME')))                                                  # 28 unexpected under PLAIN
    f.append(c.c(cmd('INITIATE', prop('Socket-Type', b'REQ') + prop('Identity', b'id'))))   # 29
    f.append(c.s(cmd('READY', prop('Socket-Type', b'REP'))))                       # 30
    f.append(c.s(cmd('ERROR', bytes([6]) + b'Denied')))                            # 31
    f.append(c.c(short(0, b'plain payload')))                                      # 32

    # ---- CURVE, port 5557 (structure only: filler bytes, nothing is encrypted)
    c = Conn(40502, 5557)
    f.append(c.c(greeting('CURVE', False)))                                        # 33
    f.append(c.s(greeting('CURVE', True)))                                         # 34
    f.append(c.c(cmd('HELLO', b'\x01\x00' + fill(70, 0) + fill(32, 0x10) + fill(8, 0x20) + fill(80, 0x30))))   # 35 version 1.0
    f.append(c.c(cmd('HELLO', b'\x02\x00' + fill(190, 0x40))))                     # 36 unsupported version 2.0
    f.append(c.s(cmd('WELCOME', fill(16, 0x50) + fill(128, 0x60))))                # 37
    f.append(c.c(cmd('INITIATE', fill(96, 0x70) + fill(8, 0x80) + fill(48, 0x90), long=False)))   # 38
    f.append(c.s(cmd('READY', fill(8, 0xa0) + fill(40, 0xb0))))                    # 39
    f.append(c.c(short(1, fill(40, 0xc0))))                                        # 40 data (not interpreted)
    f.append(c.s(long_(2, fill(300, 0xd0))))                                       # 41

    # ---- NULL with data payloads for the UAT (ports 5558 json, 5559 dns, 5560 unknown dissector, 5561 empty name)
    for port, name, body in ((5558, 'json', b'{"zmtp": [1, 2, 3], "ok": true}'),
                             (5559, 'dns', b'\x12\x34\x01'),
                             (5560, 'nosuchproto', b'payload for a missing dissector'),
                             (5561, 'empty', fill(20, 0x01))):
        c = Conn(40503 + port - 5558, port)
        f.append(c.c(greeting('NULL', False)))
        f.append(c.c(short(0, body)))
    write_pcap(os.path.join(out, 'zmtp-coverage.pcap'), f)

    b = []
    c = Conn(40600, 5555)
    b.append(c.c(greeting('NULL', False)))
    # fix reproducer: 8-byte length of 2^32+4, was truncated to a 13 octet PDU
    b.append(c.c(long_(2, b'BCDE', length=(1 << 32) + 4)))
    c = Conn(40601, 5555)
    b.append(c.c(greeting('FOO', True)))                                           # unknown mechanism (stays NULL)
    b.append(c.c(short(5, b'xx')))                                                 # flags 5: no length rule (needs more data)
    c = Conn(40602, 5555)
    b.append(c.c(greeting('NULL', False) + short(0, b'x')))
    b.append(c.c(cmd('READY', b'\x0bSocket-Type\x00\x00\x00\x09DEALER')))          # value shorter than declared
    b.append(c.c(cmd('READY', b'\x05Ident\x00\x00\x00\x00' + b'\x30')))            # trailing octet, key length beyond the end
    b.append(c.c(cmd('ERROR', bytes([20]) + b'short')))                            # reason longer than the command
    b.append(c.c(cmd('PING', b'\x01')))                                            # PING without full TTL
    b.append(c.c(short(4, bytes([30]) + b'SHORT')))                                # command name longer than the command
    b.append(c.c(cmd('HELLO', b'\x03\x01')))                                       # PLAIN-looking HELLO under NULL: nothing read
    c = Conn(40603, 5556)
    b.append(c.c(greeting('PLAIN', False)))
    b.append(c.c(cmd('HELLO', bytes([9]) + b'admin')))                             # username longer than the command
    b.append(c.c(cmd('HELLO', bytes([2]) + b'ab')))                                # no password length byte
    b.append(c.c(cmd('INITIATE', b'\x05abc')))                                     # metadata cut
    c = Conn(40604, 5557)
    b.append(c.c(greeting('CURVE', False)))
    b.append(c.c(cmd('HELLO', b'\x01\x00' + fill(40, 0))))                         # CURVE HELLO shorter than its fields
    b.append(c.c(cmd('WELCOME', fill(10, 0))))
    b.append(c.c(cmd('INITIATE', fill(50, 0))))
    b.append(c.c(cmd('READY', fill(3, 0))))
    c = Conn(40605, 5558)
    b.append(c.c(greeting('NULL', False)))
    b.append(c.c(short(0, b'{"truncated": ')))                                     # JSON that does not parse as a whole
    c = Conn(40606, 5559)
    b.append(c.c(greeting('NULL', False)))
    b.append(c.c(short(0, b'\x12\x34\x01\x00\x00\x01')))                           # DNS cut inside the header
    b.append(c.c(short(0, b'\x00\x01\x02')))
    # a data message with a declared length the capture does not hold
    c = Conn(40607, 5555)
    b.append(c.c(greeting('NULL', False)))
    b.append(c.c(bytes([0, 200]) + b'only a few bytes'))
    write_pcap(os.path.join(out, 'zmtp-coverage-malformed.pcap'), b)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

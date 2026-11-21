#!/usr/bin/env python3
# Generates test/captures/acap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
# Generate the ACAP coverage captures. Usage: mkacap.py <outdir>
# ACAP (RFC 2244) over TCP port 674 (registered by default). Built with
# struct, nothing comes from a real network.
#   acap-coverage.pcap            main capture
#   acap-coverage-malformed.pcap  paths only odd input reaches
import os, struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 10])
IP_S = bytes([192, 0, 2, 20])
PORT = 674


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self, cport=40000):
        self.frames = []
        self.cport = cport
        self.seq = {'c': 1000, 's': 5000}

    def tcp(self, who, payload=b'', flags=0x18, sport=None, dport=None):
        if who == 'c':
            src, dst = (MAC_C, IP_C), (MAC_S, IP_S)
            sp, dp = self.cport, PORT
            seq, ack = self.seq['c'], self.seq['s']
        else:
            src, dst = (MAC_S, IP_S), (MAC_C, IP_C)
            sp, dp = PORT, self.cport
            seq, ack = self.seq['s'], self.seq['c']
        if sport is not None:
            sp = sport
        if dport is not None:
            dp = dport
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        seg = t + payload
        pseudo = src[1] + dst[1] + struct.pack('>BBH', 0, 6, len(seg))
        t = t[:16] + struct.pack('>H', csum(pseudo + seg)) + t[18:]
        seg = t + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), len(self.frames) + 1, 0, 64, 6, 0, src[1], dst[1])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        self.frames.append(dst[0] + src[0] + b'\x08\x00' + ip + seg)
        self.seq[who] += len(payload) + (1 if flags & 0x03 else 0)

    def handshake(self):
        self.tcp('c', flags=0x02)
        self.tcp('s', flags=0x12)
        self.tcp('c', flags=0x10)

    def send(self, who, data):
        self.tcp(who, data, 0x18)
        self.tcp('c' if who == 's' else 's', flags=0x10)

    def close(self):
        self.tcp('c', flags=0x11)
        self.tcp('s', flags=0x11)
        self.tcp('c', flags=0x10)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, r in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000, i, len(r), len(r)) + r)


def main_capture():
    c = Cap()
    c.handshake()
    # greeting, capability response
    c.send('s', b'* ACAP (IMPLEMENTATION "Example ACAP server v1.0") (SASL "PLAIN" "DIGEST-MD5") (STARTTLS)\r\n')
    c.send('c', b'a001 STARTTLS\r\n')
    c.send('s', b'a001 OK "Begin TLS negotiation now"\r\n')
    c.send('c', b'a002 AUTHENTICATE "PLAIN" {20+}\r\n')
    c.send('s', b'+ ""\r\n')
    c.send('c', b'AHVzZXIAcGFzc3dvcmQ=\r\n')
    c.send('s', b'a002 OK "Authenticated"\r\n')
    # a command with a literal over several lines (only the first line is shown)
    c.send('c', b'a003 STORE ("/option/~/comm.example/foo" "value" {5}\r\nabcde)\r\n')
    c.send('s', b'a003 NO (TRANSIENT) "Try again"\r\n')
    # search with a context, entries
    c.send('c', b'a004 SEARCH "/addressbook/" DEPTH 0 RETURN ("addressbook.Alias") EQUAL "addressbook.Alias" "i;octet" "Fred"\r\n')
    c.send('s', b'a004 ENTRY "Fred" "Fred Foobar"\r\n')
    c.send('s', b'a004 OK (MODTIME "20261121120000") "Search completed"\r\n')
    # a single token (no data)
    c.send('c', b'NOOP\r\n')
    c.send('s', b'OK\r\n')
    # leading blanks: empty tag
    c.send('c', b'  indented request\r\n')
    c.send('s', b' indented response\r\n')
    # no line terminator (the segment holds a partial line), LF only
    c.send('c', b'a005 LISTEXT "/" ("*"')
    c.send('c', b'a006 NOOP\n')
    # a segment with more than one line, tab and escape characters
    c.send('c', b'a007 NOOP\r\na008 NOOP\r\n')
    c.send('s', b'* ALERT\t(ctl\x01\x7f) "text"\r\n')
    # a long line
    c.send('c', b'a009 STORE ("/x" "' + b'v' * 400 + b'")\r\n')
    # a segment starting with a blank only
    c.send('c', b' \r\n')
    # several lines in one segment, one of them empty
    c.send('s', b'* ENTRY "a" "1"\r\n* ENTRY "b" "2"\r\n\r\na010 OK\r\n')
    c.close()
    # second connection: server-to-client packets only on the port, one
    # connection in which client and server both use port 674
    d = Cap(cport=674)
    d.handshake()
    d.send('c', b'a001 NOOP\r\n')
    d.send('s', b'a001 OK\r\n')
    c.frames += d.frames
    # binary first byte: not ACAP
    e = Cap(cport=40001)
    e.handshake()
    e.send('c', b'\x00\x01\x02binary data\r\n')
    e.send('s', b'\x16\x03\x01\x00\x05hello')
    e.send('c', b'\r\n')       # a segment of line terminators only
    e.close()
    c.frames += e.frames
    c.write(os.path.join(OUT, 'acap-coverage.pcap'))


def malformed_capture():
    c = Cap()
    c.handshake()
    c.send('c', b'a001 NOOP\r')                 # bare CR
    c.send('c', b'\x80a002 NOOP\r\n')            # high-bit first byte
    c.send('c', b'~~~' + b'\xff\xfe' * 10 + b'\r\n')   # non printable bytes inside
    c.send('s', b'a\r\n')
    c.send('c', b'a ' * 300 + b'\r\n')            # many tokens
    c.write(os.path.join(OUT, 'acap-coverage-malformed.pcap'))


main_capture()
malformed_capture()

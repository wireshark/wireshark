#!/usr/bin/env python3
# Generates test/captures/aasp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
# Generate the AASP coverage captures. Usage: mkaasp.py <outdir>
# AASP (Aastra Signalling Protocol) is the body of SIP messages with the
# content type message/x-aasp-signalling, so the captures are SIP over
# UDP port 5060 (nothing else reaches the dissector, no Decode As needed).
# Built with struct, nothing comes from a real network.
#   aasp-coverage.pcap            main capture
#   aasp-coverage-malformed.pcap  paths only malformed input reaches
import os, struct, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 10])
IP_B = bytes([192, 0, 2, 20])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(payload, sport=5060, dport=5060, src=(MAC_A, IP_A), dst=(MAC_B, IP_B), ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0, src[1], dst[1])
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return dst[0] + src[0] + b'\x08\x00' + ip + u


class Cap:
    def __init__(self):
        self.frames = []

    def sip(self, body, ctype=b'message/x-aasp-signalling', n=None, method=b'INFO'):
        i = len(self.frames) + 1
        h = (method + b' sip:phone@192.0.2.20 SIP/2.0\r\n'
             b'Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%d\r\n'
             b'From: <sip:pbx@192.0.2.10>;tag=1\r\n'
             b'To: <sip:phone@192.0.2.20>;tag=2\r\n'
             b'Call-ID: aasp-%d@192.0.2.10\r\n'
             b'CSeq: %d %s\r\n' % (i, i, i, method))
        if ctype:
            h += b'Content-Type: ' + ctype + b'\r\n'
        h += b'Content-Length: %d\r\n\r\n' % (len(body) if n is None else n)
        self.frames.append(udp_frame(h + body, ident=i))

    def msg(self, *cmds):
        self.sip(b'a=' + b''.join(cmds))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, r in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000, i, len(r), len(r)) + r)


def b(*x):
    return bytes(x)


def main_capture():
    c = Cap()
    # 1: commands without attributes, with generic data and an unknown id
    c.msg(b(0x80, 0x01, 0x02), b(0x81, 0x10), b(0x83, 0x41, 0x42, 0x43),
          b(0x84, 0x01), b(0x85, 0x02, 0x03), b(0x88, 0x05), b(0xA5, 0x31, 0x32),
          b(0x90, 0x01), b(0xFE))
    # 2: the push buttons
    c.msg(*[b(x) for x in range(0xC8, 0xD6)] + [b(0xD6, 0x01)])
    # 3: Context Info with every attribute type (1, 3, 7: 2 bytes;
    # 0, 4: 3 bytes; 2: 5 bytes; an unknown one ends the loop)
    c.msg(b(0x86, 0x01, 0x11, 0x03, 0x12, 0x07, 0x13, 0x00, 0x14, 0x15,
            0x04, 0x16, 0x17, 0x02, 0x18, 0x19, 0x1a, 0x1b, 0x09, 0x20))
    c.msg(b(0x86), b(0x86, 0x05))
    # 4: Button Pressed
    c.msg(b(0x87, 0x00, 0x00, 0x00, 0x00, 0x35), b(0x87, 0x01, 0x02, 0x03, 0x04, 0x23))
    # 5: Set Text (the fix: a command of exactly 4 octets has no length
    # byte and is shown as data; 5 octets is shown as a text of 5 octets)
    c.msg(b(0x89, 0x00, 0x00, 0x00, 0x05) + b'Hello', b(0xFE))
    c.msg(b(0x89, 0x01, 0x02, 0x03), b(0xFE))
    c.msg(b(0x89, 0x01))
    c.msg(b(0x89, 0x01, 0x02, 0x03))        # the last command of the message, 4 octets
    c.msg(b(0x89, 0x00, 0x00, 0x00, 0x03) + b'abcde')   # text longer than the length
    # 6: Date Time Info with every item
    c.msg(b(0xA4, 0x01, 0x15, 0x02, 0x0b, 0x03, 0x2f,
            0x04, 0x02, 0x41, 0x42,
            0x05, 0x03) + b'Mon' + b(0x06, 0x03) + b'Nov' + b(0x07, 0x02) + b'KW'
          + b(0x08, 0x0d, 0x09, 0x1e, 0x0a, 0x55, 0x0b, 0x0c))
    c.msg(b(0xA4))
    # 7: Do Command
    c.msg(b(0xA9, 0x01, 0x04) + b'1234', b(0xFE))
    c.msg(b(0xA9))
    c.msg(b(0xA9, 0x01, 0x02) + b'5678')     # text longer than the length
    # 8: no "a=" prefix: text; a body of one and two octets (not dissected)
    c.sip(b'plain text body')
    c.sip(b'ab')
    c.sip(b'')
    # 9: other content type: not AASP
    c.sip(b'a=' + b(0x80, 0x01), ctype=b'application/octet-stream')
    # 10: empty Set Text and CDPN at the end of their commands
    c.msg(b(0x89, 0x00, 0x00, 0x00, 0x00), b(0xFE))
    c.msg(b(0xA9, 0x01, 0x00), b(0xFE))
    # 11: commands cut short: "Command too short" expert info
    c.msg(b(0x87, 0x00))
    c.msg(b(0xA4, 0x05, 0x09, 0x41))
    c.msg(b(0x86, 0x02, 0x00))
    c.write(os.path.join(OUT, 'aasp-coverage.pcap'))


def malformed_capture():
    c = Cap()
    c.msg(b(0x87, 0x00))                           # Button Pressed too short
    c.msg(b(0x89, 0x00, 0x00, 0x00, 0x09) + b'abc')  # Set Text length beyond the data
    c.msg(b(0xA9, 0x01, 0x09) + b'12')             # Do Command length beyond the data
    c.msg(b(0xA4, 0x04, 0x09, 0x41))               # Date Time item length beyond the data
    c.msg(b(0xA4, 0x05, 0x09, 0x41))
    c.msg(b(0xA4, 0x06, 0x09, 0x41))
    c.msg(b(0xA4, 0x07, 0x09, 0x41))
    c.msg(b(0xA4, 0x01))                           # items without their value
    c.msg(b(0xA4, 0x02), b(0xFE))
    c.msg(b(0xA4, 0x03))
    c.msg(b(0xA4, 0x08))
    c.msg(b(0xA4, 0x09))
    c.msg(b(0xA4, 0x0a))
    c.msg(b(0x86, 0x02, 0x00))                     # Context Info attributes cut short
    c.msg(b(0x86, 0x00))
    c.msg(b(0x86, 0x01))
    c.msg(b(0xA9, 0x01))                           # Do Command without the length byte
    c.write(os.path.join(OUT, 'aasp-coverage-malformed.pcap'))


main_capture()
malformed_capture()

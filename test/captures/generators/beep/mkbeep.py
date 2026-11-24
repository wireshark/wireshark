#!/usr/bin/env python3
# Generates test/captures/beep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BEEP (Blocks Extensible
Exchange Protocol, RFC 3080/3081) dissector (packet-beep.c).

All packets are built from scratch with struct; no captured traffic is
used. Clients in 192.0.2.0/24 talk to a server 192.0.2.2 on TCP port
10288 (the dissector's default port).

Note: the dissector takes the size field as the number of payload octets
after the MIME header line and its CRLF (a default, empty MIME header is
just CRLF). RFC 3080 counts the MIME headers in the size. The main capture
uses the dissector's counting so that the payload and the END trailer
line up.

Usage: mkbeep.py <output directory>

Writes:
  beep-coverage.pcap            MSG/RPY/ERR/ANS/NUL/SEQ frames, MIME
                                headers, intermediate and complete
                                messages, payloads spanning frames, two
                                messages in one frame, and the two pass
                                reproducer from beep_two_pass.py
  beep-coverage-malformed.pcap  bad more flag, invalid terminators, CR and
                                LF terminators (with
                                beep.strict_header_terminator:FALSE),
                                header without terminator, size above
                                INT32_MAX, messages after SEQ and END in
                                one frame, recursion over 1000 messages
"""

import os
import struct
import sys

SERVER = bytes([192, 0, 2, 2])
SPORT = 10288


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Conn:
    """A TCP connection from a client to SERVER:10288 (no handshake)."""

    def __init__(self, client_last, cport, cseq=1000, sseq=5000):
        self.client = bytes([192, 0, 2, client_last])
        self.cport = cport
        self.seq = {True: cseq, False: sseq}   # True: client to server

    def pkt(self, payload, to_server=True):
        if to_server:
            src, dst, sp, dp = self.client, SERVER, self.cport, SPORT
        else:
            src, dst, sp, dp = SERVER, self.client, SPORT, self.cport
        seq, ack = self.seq[to_server], self.seq[not to_server]
        self.seq[to_server] += len(payload)
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, 0x18, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        smac, dmac = (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02') if to_server else \
                     (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01')
        return dmac + smac + b'\x08\x00' + ip + tcp


def msg(cmd, chan, msgno, more, seqno, payload, mime=None, ansno=None, size=None, end=True):
    """A BEEP frame; size counts the payload only (as the dissector does)."""
    if size is None:
        size = len(payload)
    hdr = '%s %d %d %s %d %d' % (cmd, chan, msgno, more, seqno, size)
    if ansno is not None:
        hdr += ' %d' % ansno
    out = hdr.encode() + b'\r\n'
    out += (mime.encode() + b'\r\n') if mime is not None else b'\r\n'
    out += payload
    if end:
        out += b'END\r\n'
    return out


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


CT_XML = 'Content-Type: application/beep+xml'


def clean():
    fr = []
    c = Conn(1, 40000)
    # 1-2: greetings, the server's with a Content-Type MIME header. With a
    # MIME header the blank line's CRLF is part of the payload.
    g = b'\r\n<greeting><profile uri="http://iana.org/beep/SASL/ANONYMOUS"/></greeting>\r\n'
    fr.append(c.pkt(msg('RPY', 0, 0, '.', 0, g, mime=CT_XML), False))
    fr.append(c.pkt(msg('RPY', 0, 0, '.', 0, b'<greeting/>\r\n'), True))
    # 3-4: start channel 1 and its reply
    st = b'\r\n<start number="1"><profile uri="http://example.com/beep/echo"/></start>\r\n'
    fr.append(c.pkt(msg('MSG', 0, 1, '.', len(b'<greeting/>\r\n'), st, mime=CT_XML), True))
    fr.append(c.pkt(msg('RPY', 0, 1, '.', len(g), b'<profile uri="http://example.com/beep/echo"/>\r\n'), False))
    # 5-6: a message on channel 1 and an ERR reply
    fr.append(c.pkt(msg('MSG', 1, 0, '.', 0, b'hello'), True))
    fr.append(c.pkt(msg('ERR', 1, 0, '.', 0, b"<error code='550'>not here</error>\r\n"), False))
    # 7-8: a message in two frames, intermediate ('*') with a MIME header,
    # then complete ('.') without one
    p1 = b'\r\nfirst part, '
    p2 = b'second part'
    fr.append(c.pkt(msg('MSG', 1, 1, '*', 5, p1, mime='Content-Type: text/plain'), True))
    fr.append(c.pkt(b'MSG 1 1 . %d %d\r\n' % (5 + len(p1), len(p2)) + p2 + b'END\r\n', True))
    # 9: SEQ
    fr.append(c.pkt(b'SEQ 1 128 4096\r\n', False))
    # 10-13: one-to-many exchange: MSG, two ANS and NUL
    fr.append(c.pkt(msg('MSG', 1, 2, '.', 5 + len(p1) + len(p2), b'ping'), True))
    fr.append(c.pkt(msg('ANS', 1, 2, '.', 36, b'pong1', ansno=0), False))
    fr.append(c.pkt(msg('ANS', 1, 2, '.', 41, b'pong2', ansno=1), False))
    fr.append(c.pkt(msg('NUL', 1, 2, '.', 46, b''), False))
    # 14-15: a 30 octet payload in two frames: 10 octets in the first, the
    # remaining 20 and END at the start of the second
    pay = b'0123456789abcdefghijABCDEFGHIJ'
    full = msg('MSG', 1, 3, '.', 50, pay)
    cut = full.index(b'\r\n\r\n') + 4 + 10
    fr.append(c.pkt(full[:cut], True))
    fr.append(c.pkt(full[cut:], True))
    # 16: two messages in one frame
    fr.append(c.pkt(msg('MSG', 1, 4, '.', 80, b'abc', end=False) + msg('MSG', 1, 5, '.', 83, b'def'), True))
    # 17-18: replies
    fr.append(c.pkt(msg('RPY', 1, 3, '.', 51, b'ok'), False))
    fr.append(c.pkt(msg('RPY', 1, 4, '.', 53, b'ok'), False))
    # 19: END in a frame of its own, after a message whose payload ended
    # with the previous frame
    fr.append(c.pkt(msg('RPY', 1, 5, '.', 55, b'ok', end=False), False))
    fr.append(c.pkt(b'END\r\n', False))
    # 21: close channel 1
    fr.append(c.pkt(msg('MSG', 0, 2, '.', len(b'<greeting/>\r\n') + len(st),
                        b'\r\n<close number="1" code="200"/>\r\n', mime=CT_XML), True))
    fr.append(c.pkt(msg('RPY', 0, 2, '.', len(g) + 47, b'<ok/>\r\n'), False))
    # 23-25: a reply in two frames, intermediate with a MIME header, then
    # complete without one (server direction)
    fr.append(c.pkt(msg('MSG', 1, 6, '.', 86, b'list'), True))
    r1 = b'\r\nitem one\r\n'
    r2 = b'item two\r\n'
    fr.append(c.pkt(msg('RPY', 1, 6, '*', 57, r1, mime='Content-Type: text/plain'), False))
    fr.append(c.pkt(b'RPY 1 6 . %d %d\r\n' % (57 + len(r1), len(r2)) + r2 + b'END\r\n', False))
    # 26-27: the reproducer from beep_two_pass.py verbatim on
    # its own connection: 3 of 20 payload octets, then 17 more octets
    # (the dissector does not count the MIME CRLF) and "D\r\n"
    r = Conn(3, 40001, cseq=1000, sseq=1)
    p1 = b'MSG 0 1 . 0 20\r\n' + b'\r\n' + b'ABC'
    p2 = b'DEFGHIJKLMNOPQR' + b'END\r\n'
    fr.append(r.pkt(p1, True))
    fr.append(r.pkt(p2, True))
    return fr


def malformed():
    fr = []
    c = Conn(5, 40010)
    # bad more flag
    fr.append(c.pkt(b'MSG 0 1 x 0 4\r\n\r\nabcdEND\r\n'))
    # invalid terminator after the header (MSG, ANS), after SEQ, after END
    fr.append(c.pkt(b'MSG 0 2 . 0 4 junk\r\n\r\nabcd'))
    fr.append(c.pkt(b'ANS 0 2 . 0 4 0junk\r\n\r\nabcd', False))
    fr.append(c.pkt(b'SEQ 0 1 4096junk\r\n', False))
    fr.append(c.pkt(b'MSG 0 3 . 0 4\r\n\r\nabcdENDjunk\r\n'))
    # messages after SEQ and END in one frame (one and two passes differ)
    fr.append(c.pkt(b'SEQ 0 1 4096\r\n' + b'MSG 0 4 . 0 1\r\n\r\nxEND\r\n'))
    fr.append(c.pkt(b'MSG 0 5 . 0 1\r\n\r\nxEND\r\n' + b'MSG 0 6 . 0 1\r\n\r\nyEND\r\n'))
    # CR and LF terminators: with strict terminators an exception (no CRLF
    # found), without them the nonstandard terminator warnings
    fr.append(c.pkt(b'MSG 0 7 . 0 4\n\nabcdEND\n'))
    fr.append(c.pkt(b'MSG 0 8 . 0 4\r\rabcdEND\r'))
    fr.append(c.pkt(b'MSG 0 9 . 0 4\r\nContent-Type: text/plain\nabcdEND\r\n'))
    fr.append(c.pkt(b'SEQ 0 1 4096\n'))
    # MIME header line not terminated in strict mode
    fr.append(c.pkt(b'MSG 0 10 . 0 4\r\nContent-Type: text/plain'))
    # Header cut short
    fr.append(c.pkt(b'MSG 0'))
    # size above INT32_MAX
    fr.append(c.pkt(b'MSG 0 11 . 0 3000000000\r\n\r\nabc'))
    # an intermediate message and a complete one in one frame: the MIME
    # flag of the second differs on the later passes
    fr.append(c.pkt(b'MSG 1 1 * 0 1\r\n\r\nxMSG 1 1 . 1 1\r\nyEND\r\n'))
    # payload interleaved with the other direction
    fr.append(c.pkt(b'MSG 1 2 . 2 20\r\n\r\n0123456789'))
    fr.append(c.pkt(b'RPY 1 1 . 0 2\r\n\r\nokEND\r\n', False))
    fr.append(c.pkt(b'abcdefghijEND\r\n'))
    # a payload over three frames: the third loses track
    fr.append(c.pkt(b'MSG 1 3 . 22 30\r\n\r\n0123456789'))
    fr.append(c.pkt(b'abcdefghij'))
    fr.append(c.pkt(b'ABCDEFGHIJEND\r\n'))
    # 1000 empty messages in one frame: the recursion stops at the depth
    # limit
    fr.append(c.pkt(b'MSG 2 0 . 0 0\r\n\r\n' * 1000))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'beep-coverage.pcap'), clean())
    write_pcap(os.path.join(out, 'beep-coverage-malformed.pcap'), malformed())


if __name__ == '__main__':
    main()

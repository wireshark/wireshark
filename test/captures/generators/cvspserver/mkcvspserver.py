#!/usr/bin/env python3
# Generates test/captures/cvspserver_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the CVS pserver dissector
(packet-cvspserver.c).

The CVS password server is on TCP port 2401. The dissector shows every
line of a segment as a data item and tells a request from a response by
the port. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkcvspserver.py <output directory>

Writes:
  cvspserver-coverage.pcap  two TCP connections with handshake and FIN:
                            a successful login (I LOVE YOU) followed by
                            CVS client/server protocol requests and
                            responses (several lines per segment, a
                            quoted string with a line end inside it,
                            CRLF line ends, an empty line, a last line
                            without a line end, UTF-8 and invalid UTF-8),
                            and a failed verification (I HATE YOU)
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 2401


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip_frame(proto, l4, src, dst, ident, smac=None, dmac=None):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    if smac is None:
        smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + l4


def udp_frame(sport, dport, payload, src, dst, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    return ip_frame(17, udp, src, dst, ident)


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    # SYNs carry an MSS option (a SYN without options looks like a scanner)
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    return ip_frame(6, tcp + payload, src, dst, ident)


class Conn:
    """One TCP connection with a three way handshake."""

    def __init__(self, frames, cport, sport):
        self.f = frames
        self.cport = cport
        self.sport = sport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, self.sport, data, self.cseq,
                           self.sseq if flags != 0x02 else 0, IP_C, IP_S, flags,
                           ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(self.sport, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


# The CVS password scrambling (src/scramble.c): 'A' followed by each
# character mapped through a fixed table.
SHIFTS = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    114, 120, 53, 79, 96, 109, 72, 108, 70, 64, 76, 67, 116, 74, 68, 87,
    111, 52, 75, 119, 49, 34, 82, 81, 95, 65, 112, 86, 118, 110, 122, 105,
    41, 57, 83, 43, 46, 102, 40, 89, 38, 103, 45, 50, 42, 123, 91, 35,
    125, 55, 54, 66, 124, 126, 59, 47, 92, 71, 115, 78, 88, 107, 106, 56,
    36, 121, 117, 104, 101, 100, 69, 73, 99, 63, 94, 93, 39, 37, 61, 48,
    58, 113, 32, 90, 44, 98, 60, 51, 33, 97, 62, 77, 84, 80, 85, 223,
]


def scramble(pw):
    return 'A' + ''.join(chr(SHIFTS[ord(ch)]) for ch in pw)


def main_frames():
    F = []
    # Connection 1, frames 1-3: handshake
    c = Conn(F, 40010, PORT)
    # 4: login request, five lines
    c.add(True, ('BEGIN AUTH REQUEST\n/var/lib/cvsroot\nanonymous\n%s\nEND AUTH REQUEST\n'
                 % scramble('example')).encode('latin-1'))
    # 5: login accepted
    c.add(False, b'I LOVE YOU\n')
    # 6: three requests in one segment
    c.add(True, b'Root /var/lib/cvsroot\n'
                b'Valid-responses ok error Valid-requests Checked-in New-entry M E F MT\n'
                b'valid-requests\n')
    # 7: two response lines
    c.add(False, b'Valid-requests Root Valid-responses valid-requests Directory Entry '
                 b'Modified Unchanged Argument Argumentx ci co update\nok\n')
    # 8: a log message given as a quoted argument that holds a line end;
    # the quoted line end does not end the line
    c.add(True, b'Argument -m\nArgument "Fix the build\nand the tests"\nArgument --\n'
                b'Directory .\n/var/lib/cvsroot/module\nci\n')
    # 9: CRLF line ends, an empty line, and a last line without a line end
    c.add(False, b'M Checking in file.c;\r\n\r\nM new revision: 1.2; previous revision: 1.1'
                 b'\r\nE cvs commit: warn')
    # 10: the rest of the response: UTF-8 and an octet that is not UTF-8
    c.add(False, b'M done \xc3\xa4\xc3\xb6\xc3\xbc\nE bad \xff octet\nok\n')
    # 11: a lone line end (one empty line)
    c.add(True, b'\n')
    # 12-14: FIN
    c.close()

    # Connection 2, frames 15-17: handshake
    c = Conn(F, 40011, PORT)
    # 18: verification request with a wrong password (CRLF line ends)
    c.add(True, ('BEGIN VERIFICATION REQUEST\r\n/var/lib/cvsroot\r\nanonymous\r\n%s\r\n'
                 'END VERIFICATION REQUEST\r\n' % scramble('wrong')).encode('latin-1'))
    # 19: refused, with an error message line before it
    c.add(False, b'E Fatal error, aborting.\nI HATE YOU\n')
    # 20-22: FIN
    c.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cvspserver-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

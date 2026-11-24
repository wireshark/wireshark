#!/usr/bin/env python3
# Generates test/captures/daytime_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic capture that exercises the Daytime Protocol
dissector (packet-daytime.c, RFC 867).

Daytime is on UDP and TCP port 13. The client sends anything (or, over
TCP, nothing) and the server answers with the date and time as a line of
text. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkdaytime.py <output directory>

Writes:
  daytime-coverage.pcap  UDP requests and responses on port 13, a TCP
                         connection with handshake, a client segment,
                         the server's time line and FIN, and the
                         reproducer of the fix on the branch: a request
                         and response on UDP port 1313 (Decode As)
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 13


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

    def close_server(self):
        # RFC 867: the server closes the connection after sending
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x10)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def altport_reproducer():
    """daytime_altport.py, byte for byte: a response from UDP
    port 1313 (Decode As) with the UDP checksum left at 0."""
    data = b'Sun Nov  1 12:00:00 2026\r\n'
    u = struct.pack('!HHHH', 1313, 40000, 8 + len(data), 0) + data
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                    bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1]))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\x00' + h + u


def altport_request():
    """The request that goes with the reproducer: UDP to port 1313."""
    data = b'\n'
    u = struct.pack('!HHHH', 40000, 1313, 8 + len(data), 0) + data
    pseudo = struct.pack('>4s4sBBH', bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]), 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(pseudo + u)) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                    bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + h + u


def main_frames():
    F = []
    U = lambda *a: F.append(udp_frame(*a, ident=len(F) + 1))
    # 1-2: UDP request (a single line end) and the response, the format
    # RFC 867 gives as an example
    U(40001, PORT, b'\n', IP_C, IP_S)
    U(PORT, 40001, b'Sunday, November 1, 2026 12:00:00-UTC\r\n', IP_S, IP_C)
    # 3-4: UDP request with some text, response in the ctime() format
    U(40002, PORT, b'what time is it?', IP_C, IP_S)
    U(PORT, 40002, b'Sun Nov  1 12:00:01 2026\n', IP_S, IP_C)
    # 5: a response with octets outside ASCII and no line end
    U(PORT, 40003, b'01-11-2026 12:00:02 \xc3\xa9t\xe9', IP_S, IP_C)
    # 6-8: TCP handshake, 9: the client sends a line (Request over TCP),
    # 10: the server answers, 11-13: the server closes
    c = Conn(F, 40004, PORT)
    c.add(True, b'\r\n')
    c.add(False, b'Sun, 01 Nov 2026 12:00:03 +0000\r\n')
    c.close_server()
    # 14-16: a second TCP connection in which the client sends nothing
    # and the server sends the time in two segments (17-18), 19-21 FIN
    c = Conn(F, 40005, PORT)
    c.add(False, b'2026-11-01T12:00:04Z')
    c.add(False, b'\r\n')
    c.close_server()
    # 22-23: the reproducer of "Daytime: Tell a response from a request on
    # any port in the tree": a request to UDP port 1313 and the response
    # from it (daytime_altport.py). Daytime only with
    # -d udp.port==1313,daytime.
    F.append(altport_request())
    F.append(altport_reproducer())
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'daytime-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

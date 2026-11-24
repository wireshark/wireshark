#!/usr/bin/env python3
# Generates test/captures/atmtcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ATM over TCP dissector
(packet-atmtcp.c).

All packets are built from scratch with struct; no captured traffic is
used. Two Linux hosts run atmtcp (drivers/atm/atmtcp.c): 10.0.0.1 is
connected to 10.0.0.2 on TCP port 2812, the port ATMTCP is registered on.
Each message is a struct atmtcp_hdr (VPI, VCI, length, network byte
order) followed by the data; a length of 0xffffffff (ATMTCP_HDR_MAGIC)
marks a control message (struct atmtcp_control, host byte order).

Usage: mkatmtcp.py <output directory>

Writes:
  atmtcp-coverage.pcap            one connection: handshake, OPEN and CLOSE
                                  control messages and their replies, data
                                  on two VCs in both directions, an empty
                                  data message, FIN
  atmtcp-coverage-malformed.pcap  messages shorter than the 8 octet header
"""

import struct
import sys

ATMTCP_PORT = 2812
A = (10, 0, 0, 1)
B = (10, 0, 0, 2)
MAGIC = 0xffffffff
CTRL_OPEN, CTRL_CLOSE = 1, 2


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''  # MSS, SACK permitted
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 64240, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
        eth = (b'\x02\x00\x00\x00\x00' + bytes(dst[3:4]) + b'\x02\x00\x00\x00\x00' +
               bytes(src[3:4]) + b'\x08\x00')
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t, i * 1000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class Conn:
    """A TCP connection from A to B with correct sequence numbers."""
    def __init__(self, cap, sport=51000):
        self.cap, self.sport = cap, sport
        self.seq = {A: 100000, B: 900000}

    def send(self, src, payload=b'', flags=0x18, ack_back=True):
        dst = B if src == A else A
        sp, dp = (self.sport, ATMTCP_PORT) if src == A else (ATMTCP_PORT, self.sport)
        self.cap.tcp(src, dst, sp, dp, self.seq[src], self.seq[dst], flags, payload)
        self.seq[src] += len(payload) + (1 if flags & 0x03 else 0)
        if ack_back and payload:
            self.ack(dst)

    def ack(self, src):
        self.send(src, flags=0x10, ack_back=False)

    def handshake(self):
        c = self.cap
        c.tcp(A, B, self.sport, ATMTCP_PORT, self.seq[A], 0, 0x02)
        self.seq[A] += 1
        c.tcp(B, A, ATMTCP_PORT, self.sport, self.seq[B], self.seq[A], 0x12)
        self.seq[B] += 1
        self.ack(A)

    def close(self):
        self.send(A, flags=0x11, ack_back=False)
        self.send(B, flags=0x11, ack_back=False)
        self.ack(A)


def hdr(vpi, vci, length):
    return struct.pack('>HHI', vpi, vci, length)


def control(vpi, vci, ctype, vcc, result=0):
    """struct atmtcp_control after the header: type, vcc (kernel pointer),
    struct sockaddr_atmpvc, struct atm_qos, result; host (little endian)
    byte order."""
    addr = struct.pack('<HhhxxI', 8, 0, vpi, vci)                 # AF_ATMPVC, itf 0
    trafprm = struct.pack('<B3x8i', 3, 0, 353207, 0, 0, 0, 0, 0, 0)  # ATM_UBR
    qos = trafprm + trafprm + struct.pack('<B3x', 5)              # AAL5
    return hdr(vpi, vci, MAGIC) + struct.pack('<iQ', ctype, vcc) + addr + qos + struct.pack('<i', result)


def data(vpi, vci, payload):
    return hdr(vpi, vci, len(payload)) + payload


def llc_snap_ip(n):
    """An RFC 2684 LLC/SNAP routed IPv4 PDU as AAL5 payload."""
    body = bytes((n + i) & 0xff for i in range(n))
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, 0, 64, 253, 0,
                     bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)))
    ip = ip[:10] + struct.pack('>H', checksum(ip)) + ip[12:]
    return b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ip + body


def main_capture(cap):
    c = Conn(cap)
    c.handshake()                                                 # 1-3
    c.send(A, control(0, 32, CTRL_OPEN, 0xffff8881001a2b00))      # 4 OPEN, 5 ACK
    c.send(B, control(0, 32, CTRL_OPEN, 0xffff8881001a2b00))      # 6 OPEN reply, 7 ACK
    c.send(A, data(0, 32, llc_snap_ip(12)))                       # 8 data, 9 ACK
    c.send(B, data(0, 32, llc_snap_ip(40)))                       # 10, 11
    c.send(A, data(0, 32, b''))                                   # 12 empty data, 13 ACK
    c.send(A, control(4095, 65535, CTRL_OPEN, 0xffff8881001a2c00))  # 14 OPEN on the largest VPI/VCI, 15
    c.send(B, control(4095, 65535, CTRL_OPEN, 0xffff8881001a2c00))  # 16, 17
    c.send(A, data(4095, 65535, llc_snap_ip(1400)))               # 18 large data, 19
    c.send(B, data(4095, 65535, b'\x00' * 48))                    # 20 one cell of zeros, 21
    c.send(A, control(0, 32, CTRL_CLOSE, 0xffff8881001a2b00))     # 22 CLOSE, 23
    c.send(B, control(0, 32, CTRL_CLOSE, 0xffff8881001a2b00))     # 24 CLOSE reply, 25
    c.close()                                                     # 26-28


def malformed_capture(cap):
    c = Conn(cap, sport=51001)
    c.handshake()                                                 # 1-3
    c.send(A, hdr(0, 32, 12)[:6])                                 # 4 header cut in the length, 5
    c.send(A, b'\x00\x00')                                        # 6 VPI only, 7


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    main_capture(cap)
    cap.write(outdir + '/atmtcp-coverage.pcap')
    cap = Pcap()
    malformed_capture(cap)
    cap.write(outdir + '/atmtcp-coverage-malformed.pcap')


if __name__ == '__main__':
    main()

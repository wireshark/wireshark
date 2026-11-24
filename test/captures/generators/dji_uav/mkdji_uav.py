#!/usr/bin/env python3
# Generates test/captures/dji_uav_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DJI UAV (TCP port 2001) coverage captures.
Usage: mkdji_uav.py <outdir>
Every packet is built with struct; addresses are from 192.0.2.0/24."""
import os
import struct
import sys


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64,
                    proto, 0, s, d)
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return h + payload


def eth(payload, src_mac, dst_mac):
    return dst_mac + src_mac + struct.pack('!H', 0x0800) + payload


def tcp_seg(sp, dp, seq, ack, data, src, dst, flags=0x18):
    pseudo = (bytes(int(x) for x in src.split('.')) +
              bytes(int(x) for x in dst.split('.')) +
              struct.pack('!BBH', 0, 6, 20 + len(data)))
    t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0) + data
    c = _csum(pseudo + t)
    t = t[:16] + struct.pack('!H', c) + t[18:]
    return t


MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')


class Tcp:
    """TCP stream (no handshake); c2s/s2c add one segment."""
    def __init__(self, frames, cport, sport=2001, csrc='192.0.2.1', ssrc='192.0.2.2'):
        self.f = frames
        self.cport, self.sport, self.csrc, self.ssrc = cport, sport, csrc, ssrc
        self.cseq, self.sseq = 1000, 5000

    def _add(self, c2s, seq, ack, data, flags=0x18):
        if c2s:
            t = tcp_seg(self.cport, self.sport, seq, ack, data, self.csrc, self.ssrc, flags)
            self.f.append(eth(ipv4(6, t, self.csrc, self.ssrc), MAC_C, MAC_S))
        else:
            t = tcp_seg(self.sport, self.cport, seq, ack, data, self.ssrc, self.csrc, flags)
            self.f.append(eth(ipv4(6, t, self.ssrc, self.csrc), MAC_S, MAC_C))

    def c2s(self, data):
        self._add(True, self.cseq, self.sseq, data)
        self.cseq += len(data)

    def s2c(self, data):
        self._add(False, self.sseq, self.cseq, data)
        self.sseq += len(data)


def pdu(seq, cmd, data=b'', flags=0, length=None, csum=None):
    """DJI UAV PDU: magic 0x55BB, length (whole PDU), flags, seqno (LE),
    command, data, XOR checksum."""
    if length is None:
        length = 8 + len(data)
    body = struct.pack('>H', 0x55BB) + struct.pack('<BBHB', length, flags, seq, cmd) + data
    if csum is None:
        csum = 0
        for b in body:
            csum ^= b
    return body + bytes([csum])


def bcd(v):
    return ((v // 10) << 4) | (v % 10)


def set_time(seq, extra=b''):
    # year(lo) year(hi) month date hour minute second, in BCD
    t = bytes([bcd(23), bcd(20), bcd(11), bcd(14), bcd(22), bcd(13), bcd(20)])
    return pdu(seq, 0x20, t + extra)


def main_capture():
    f = []
    a = Tcp(f, 40000)
    a.c2s(set_time(1))                                  # 1 Set Time
    a.s2c(pdu(1, 0x20, b'\x00'))                        # 2 its response
    a.c2s(pdu(2, 0x21, b'\x01\x02\x03\x04', flags=0x40))  # 3 unknown command
    a.s2c(pdu(2, 0x21))                                 # 4 response, no data
    a.s2c(pdu(2, 0x21, b'\xaa'))                        # 5 second response to seq 2
    a.s2c(pdu(0, 0x24, b'\x10\x20\x30'))                # 6 response without request
    a.c2s(set_time(3, b'\xde\xad\xbe\xef'))             # 7 Set Time, 4 unexpected
    a.s2c(pdu(3, 0x20, b'\x00'))                        # 8
    a.c2s(pdu(4, 0x05, b'\x11') + pdu(5, 0x06, b'\x22\x33'))  # 9 two PDUs
    a.s2c(pdu(4, 0x05, b'\x00') + pdu(5, 0x06, b'\x00'))      # 10 two PDUs
    big = pdu(6, 0x30, bytes(range(22)))                # 30 octets
    a.c2s(big[:10])                                     # 11 first part
    a.c2s(big[10:])                                     # 12 rest, reassembled
    a.s2c(pdu(6, 0x30, b'\x00\x01'))                    # 13
    a.c2s(pdu(7, 0x40, b'\x99'))                        # 14 never answered
    a.c2s(b'HELLO, not a DJI UAV PDU')                  # 15 no magic: Data
    # Reproducer of the fix (djiuav_seqno_reuse.py): two exchanges that
    # reuse sequence number 5, on their own connection.
    r = Tcp(f, 40001)
    r.c2s(pdu(5, 0x21))                                 # 16
    r.s2c(pdu(5, 0x21))                                 # 17
    r.c2s(pdu(5, 0x21))                                 # 18
    r.s2c(pdu(5, 0x21))                                 # 19
    # Magic but fewer than 8 octets, on a new connection: Data
    s = Tcp(f, 40002)
    s.c2s(b'\x55\xbb\x09')                              # 20
    return f


def malformed_capture():
    f = []
    a = Tcp(f, 40010)
    a.c2s(pdu(1, 0x20, length=8))                       # 1 Set Time, no time
    a.c2s(pdu(2, 0x21, length=6) + b'\x00\x00')         # 2 length < 8
    a.s2c(pdu(2, 0x21, length=7) + b'\x00')             # 3 response length 7
    a.c2s(pdu(3, 0x22, length=0) + b'\x00' * 4)         # 4 length 0
    a.s2c(struct.pack('>H', 0x55BB) + b'\x40\x00\x03\x00\x22\x00')  # 5 length 64, 8 octets
    return f


def write_pcap(path, frames):
    with open(path, 'wb') as fp:
        fp.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            usec = i * 125000
            fp.write(struct.pack('<IIII', 1700000000 + usec // 1000000,
                                 usec % 1000000, len(fr), len(fr)))
            fp.write(fr)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dji-uav-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'dji-uav-coverage-malformed.pcap'), malformed_capture())

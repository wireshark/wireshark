#!/usr/bin/env python3
# Generates test/captures/cp2179_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CP2179 (Cooper 2179)
dissector (packet-cp2179.c).

CP2179 is a serial protocol; Wireshark reaches it with Decode As on a
TCP port (Telnet encapsulated, with 0xFF 0xFF unescaped by default), on
the RTAC Serial payload, or through an Exported PDU naming "cp2179".
A request is
    address (16 bit LE) | function | command | nchars (16 bit LE) | data | CRC
and a response
    address | function | status | port status | nchars | data | CRC.
The dissector keeps each request of a conversation and decodes a response
with the latest earlier request that has the same address word.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcp2179.py <output directory>

Writes:
  cp2179-coverage.pcapng            TCP (decode as port 2179), RTAC Serial
                                    and Exported PDU frames with every
                                    message type, the reproducers of the
                                    requested points fix
  cp2179-coverage-malformed.pcapng  messages cut short and data field
                                    lengths past the end
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 2179

IF_ETH, IF_RTAC, IF_EPDU = 0, 1, 2


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident, 0,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + tcp + payload


class Conn:
    """One TCP connection from the master to the RTU on port 2179, with a
    three way handshake so sequence numbers are tracked from the start."""

    def __init__(self, frames, cport):
        self.f = frames
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, PORT, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(PORT, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append((IF_ETH, fr))
        return len(self.f)

    def req(self, data):
        return self.add(True, data)

    def rsp(self, data):
        return self.add(False, data)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


def addr(rtu, master):
    return struct.pack('<H', (master << 11) | rtu)


CRC = b'\x12\x34'


def req(a, fc, cmd, data=b'', nchars=None):
    if nchars is None:
        nchars = len(data)
    return a + bytes([fc, cmd]) + struct.pack('<H', nchars) + data + CRC


def rsp(a, fc, status, port, data=b'', nchars=None):
    if nchars is None:
        nchars = len(data)
    return a + bytes([fc, status, port]) + struct.pack('<H', nchars) + data + CRC


def telnet_escape(data):
    return data.replace(b'\xff', b'\xff\xff')


def rtacser(payload, event=0x02, lines=0x5f, sec=1700000000, usec=250000):
    return struct.pack('>IIBBH', sec, usec, event, lines, 0) + payload


def exported_pdu(payload, name=b'cp2179'):
    # As in the reproducers (cp2179_*.py): the name unpadded
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + payload


def i16(*vals):
    return b''.join(struct.pack('<h', v) for v in vals)


def u16(*vals):
    return b''.join(struct.pack('<H', v) for v in vals)


def f32(*vals):
    return b''.join(struct.pack('<f', v) for v in vals)


# pcapng writer ----------------------------------------------------------------

def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (interface, data); interface 0 is Ethernet, 1 RTAC Serial
    (linktype 250), 2 Exported PDU (linktype 252)."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in (1, 250, 252):
            f.write(pcapng_block(1, struct.pack('<HHI', lt, 0, 262144)))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


# frames ---------------------------------------------------------------------

def main_frames():
    F = []
    A = addr(1, 1)          # RTU 1, master 1 on TCP
    c = Conn(F, 40001)      # 1-3 handshake

    # Basic scan (function 0x00), one request and response per command
    c.req(req(A, 0x00, 0x01))                                   # 4 simple status
    c.rsp(rsp(A, 0x00, 0x00, 0x00, u16(0x8001, 0x00F0)))        # 5
    c.req(req(A, 0x00, 0x04))                                   # 6 2 bit status
    c.rsp(rsp(A, 0x00, 0x00, 0x00, u16(0x0F01, 0xF00E)))        # 7
    # 16 bit analog: -1 is FF FF, sent Telnet escaped as FF FF FF FF
    c.req(req(A, 0x00, 0x08))                                   # 8
    c.rsp(telnet_escape(rsp(A, 0x00, 0x00, 0x00, i16(100, -1, -32768))))  # 9
    c.req(req(A, 0x00, 0x40))                                   # 10 accumulator
    c.rsp(rsp(A, 0x00, 0x00, 0x00, u16(1, 65000, 4242)))        # 11
    c.req(req(A, 0x00, 0x09))                                   # 12 SS + analog
    c.rsp(rsp(A, 0x00, 0x00, 0x00, u16(1, 2)))                  # 13 (not decoded)

    # Scan for special calculations (function 0x03)
    c.req(req(A, 0x03, 0x80))                                   # 14 all
    c.rsp(rsp(A, 0x03, 0x01, 0x00, f32(1.5, -2.25, 1000.0)))    # 15
    c.req(req(A, 0x03, 0x00, bytes([3, 7])))                    # 16 range 3, 7
    c.rsp(rsp(A, 0x03, 0x01, 0x00, f32(3.0, 7.0)))              # 17
    c.req(req(A, 0x03, 0x00, bytes([9, 11])))                   # 18 range 9, 11
    c.rsp(rsp(A, 0x03, 0x01, 0x00, f32(9.0, 11.0, 13.0, 15.0))) # 19 more values

    # Scan inclusive (function 0x01) 16 bit analog
    c.req(req(A, 0x01, 0x08, bytes([10, 13])))                  # 20 points 10-13
    c.rsp(rsp(A, 0x01, 0x00, 0x00, i16(10, -11, 12, -13)))      # 21
    c.req(req(A, 0x01, 0x08, bytes([20, 15])))                  # 22 end < start
    c.rsp(rsp(A, 0x01, 0x00, 0x00, i16(20, 21)))                # 23 no points

    # Supervisory control (function 0x10): select open/close, operate
    c.req(req(A, 0x10, 0x10, bytes([5])))                       # 24 SBO open
    c.rsp(rsp(A, 0x10, 0x00, 0x00, bytes([5])))                 # 25
    c.req(req(A, 0x10, 0x11, bytes([6])))                       # 26 SBO close
    c.rsp(rsp(A, 0x10, 0x00, 0x00, bytes([6])))                 # 27
    c.req(req(A, 0x10, 0x20))                                   # 28 operate
    c.rsp(rsp(A, 0x10, 0x00, 0x02))                             # 29

    # RTU internal control (function 0x20)
    c.req(req(A, 0x20, 0x00))                                   # 30 init RTU
    c.rsp(rsp(A, 0x20, 0x00, 0x02))                             # 31
    c.req(req(A, 0x20, 0x11, bytes([4])))                       # 32 reset acc 4
    c.rsp(rsp(A, 0x20, 0x00, 0x00, bytes([4])))                 # 33

    # Time tagged information (function 0x04); requests are not kept, so a
    # response pairs with the reset accumulator request
    c.req(req(A, 0x04, 0x40))                                   # 34 single record
    rec1 = bytes([0x01, 20, 24, 13, 45, 30]) + i16(1000, -1000)
    rec2 = bytes([0x02, 20, 25, 23, 59, 59]) + i16(7, -7)
    c.rsp(rsp(A, 0x04, 0x00, 0x00, bytes([0x82]) + rec1 + rec2))  # 35 more, 2
    c.req(req(A, 0x04, 0x60))                                   # 36 dump all
    c.rsp(rsp(A, 0x04, 0x00, 0x00, bytes([0x00])))              # 37 no records
    c.req(req(A, 0x04, 0x00))                                   # 38 retransmit
    c.req(req(A, 0x04, 0x20))                                   # 39 retransmit dump

    # RST response, unknown function, unclassified, no request found
    c.rsp(rsp(A, 0x08, 0x00, 0x00))                             # 40 RST
    c.req(req(A, 0x0A, 0x00))                                   # 41 scan by table
    c.req(A + bytes(8))                                         # 42 unclassified
    c.rsp(rsp(addr(5, 2), 0x00, 0x00, 0x00, u16(1, 2)))         # 43 no request
    c.req(b'\x01\x08\x00\x00\x00')                              # 44 too short
    c.close()                                                   # 45-47

    # RTAC Serial (decode as cp2179); no Telnet unescaping
    B = addr(2, 2)
    F.append((IF_RTAC, rtacser(req(B, 0x00, 0x08), event=0x01)))           # 48
    F.append((IF_RTAC, rtacser(rsp(B, 0x00, 0x00, 0x00, i16(-1, 255)))))   # 49

    # Exported PDU: the reproducers of "CP2179: Do not read more requested
    # points than the request had" (cp2179_*.py)
    R = addr(1, 1)
    # A basic scan request (no requested points) and a special calc
    # response: the request's point list was NULL
    F.append((IF_EPDU, exported_pdu(req(R, 0x00, 0x00))))                  # 50
    F.append((IF_EPDU, exported_pdu(rsp(R, 0x03, 0x01, 0x00, f32(1.0, 2.0)))))  # 51
    # A scan inclusive request for one point and a response with 200
    # values: read past the one entry list
    F.append((IF_EPDU, exported_pdu(req(R, 0x01, 0x08, bytes([5, 5])))))   # 52
    F.append((IF_EPDU, exported_pdu(rsp(R, 0x01, 0x00, 0x00, i16(*range(200))))))  # 53
    return F


def malformed_frames():
    F = []
    A = addr(1, 1)
    c = Conn(F, 40002)
    c.req(req(A, 0x00, 0x08))                                   # 4
    # analog response with an odd data length: last value cut
    c.rsp(rsp(A, 0x00, 0x00, 0x00, b'\x01\x00\x02'))            # 5
    # data field length past the end
    c.rsp(rsp(A, 0x00, 0x00, 0x00, u16(1, 2), nchars=200))      # 6
    c.req(req(A, 0x03, 0x80))                                   # 7
    # special calc response with nchars + 9 == length but a cut float
    c.rsp(rsp(A, 0x03, 0x01, 0x00, b'\x00\x00\xc0'))            # 8
    c.req(req(A, 0x03, 0x00, bytes([1, 2])))                    # 9
    c.rsp(rsp(A, 0x03, 0x01, 0x00, b'\x00\x00\x80\x3f\x00'))    # 10
    c.req(req(A, 0x01, 0x08, bytes([1, 4])))                    # 11
    c.rsp(rsp(A, 0x01, 0x00, 0x00, b'\x01'))                    # 12
    # time tagged response: records longer than the packet
    c.req(req(A, 0x20, 0x11, bytes([4])))                       # 13
    c.rsp(rsp(A, 0x04, 0x00, 0x00, bytes([0x05]) + bytes(20), nchars=200))  # 14
    # SBO select request with nchars 1 but no CRC room
    c.req(A + bytes([0x10, 0x10, 0x01, 0x00, 0x05, 0x00, 0x00]))  # 15
    # special calc range request cut after the count
    c.req(A + bytes([0x03, 0x00, 0x02, 0x00, 0x01]))            # 16
    # scan inclusive request with an odd number of points
    c.req(A + bytes([0x01, 0x08, 0x02, 0x00, 0x01, 0x02, 0x03]))  # 17
    c.close()
    # reproducers as they are in the review (also in the main capture)
    F.append((IF_EPDU, exported_pdu(req(A, 0x00, 0x00))))
    F.append((IF_EPDU, exported_pdu(rsp(A, 0x03, 0x01, 0x00, f32(1.0, 2.0)))))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'cp2179-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'cp2179-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

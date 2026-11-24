#!/usr/bin/env python3
# Generates test/captures/fmtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the FMTP coverage captures (synthetic data only).

usage: mkfmtp.py <outdir> [-v]

fmtp-coverage.pcap            valid FMTP over TCP (found by the heuristic)
                              and connections whose first PDU is not FMTP
fmtp-coverage-malformed.pcap  paths that only malformed PDUs reach
"""
import os
import struct
import sys

CLI = [192, 0, 2, 1]
SRV = [192, 0, 2, 2]
PORT = 8500


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def tcp_frame(src, dst, sport, dport, seq, ack, flags, payload, ident=1):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags,
                      65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), ident, 0, 64, 6, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return eth + ip + tcp


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000, i * 1000, len(fr), len(fr)))
            f.write(fr)


SYN, FIN, PSH, ACK = 0x02, 0x01, 0x08, 0x10


class Conn:
    """One TCP connection; data() appends segments to the shared frame list."""
    def __init__(self, frames, sport, handshake=True):
        self.f = frames
        self.sport = sport
        self.cs = 1000      # client sequence number
        self.ss = 5000      # server sequence number
        if handshake:
            self._tx(True, SYN, b'')
            self.cs += 1
            self._tx(False, SYN | ACK, b'')
            self.ss += 1
            self._tx(True, ACK, b'')

    def _tx(self, c2s, flags, payload):
        if c2s:
            fr = tcp_frame(CLI, SRV, self.sport, PORT, self.cs, self.ss, flags, payload)
        else:
            fr = tcp_frame(SRV, CLI, PORT, self.sport, self.ss, self.cs, flags, payload)
        self.f.append(fr)

    def send(self, c2s, payload):
        self._tx(c2s, PSH | ACK, payload)
        if c2s:
            self.cs += len(payload)
        else:
            self.ss += len(payload)

    def close(self):
        self._tx(True, FIN | ACK, b'')
        self.cs += 1
        self._tx(False, FIN | ACK, b'')
        self.ss += 1
        self._tx(True, ACK, b'')


def pdu(typ, data=b'', ver=2, res=0, length=None):
    if isinstance(data, str):
        data = data.encode()
    if length is None:
        length = 5 + len(data)
    return struct.pack('>BBHB', ver, res, length, typ) + data


OPER, OPERATOR, IDENT, SYSTEM = 1, 2, 3, 4


def build(frames):
    marks = []

    def mark(name):
        marks.append((name, len(frames) + 1))

    # ---- connection 1: identification, system messages, data
    mark('connection 1: handshake')
    c = Conn(frames, 40001)
    # A first segment with an identification message of 7 or more octets
    # is taken by the Q.931 over TPKT heuristic (see the README), so the
    # header comes in a segment of its own.
    mark('identification both ways (header and data in two segments)')
    p = pdu(IDENT, 'ENXX-EGLL')
    c.send(True, p[:5])
    c.send(True, p[5:])
    c.send(False, pdu(IDENT, 'EGLL-ENXX'))
    c.send(True, pdu(IDENT, ''))                      # empty identification
    mark('system: startup, shutdown, heartbeat, unknown')
    c.send(True, pdu(SYSTEM, '01'))                   # Startup
    c.send(False, pdu(SYSTEM, '01'))
    c.send(True, pdu(SYSTEM, '03'))                   # Heartbeat
    c.send(False, pdu(SYSTEM, '03'))
    c.send(True, pdu(SYSTEM, '00'))                   # Shutdown
    c.send(True, pdu(SYSTEM, '99'))                   # unknown message
    c.send(True, pdu(SYSTEM, '0301'))                 # longer than the code
    mark('operational and operator messages')
    c.send(True, pdu(OPER, '(FPL-SAS123-IS-A320/M-SDE3FGHIRWY/LB1-ENGM1000-N0450F360 DCT-EGLL-0100)'))
    c.send(False, pdu(OPER, b'\x00\x01\x02\x03\xff'))
    c.send(True, pdu(OPERATOR, 'PLEASE CALL SUPERVISOR'))
    c.send(False, pdu(OPERATOR, ''))                 # operator message, empty
    mark('two PDUs in one segment')
    c.send(True, pdu(SYSTEM, '03') + pdu(OPER, 'ABC'))
    mark('PDU over two segments')
    p = pdu(OPER, 'X' * 100)
    c.send(True, p[:40])
    c.send(True, p[40:])
    mark('header split after 3 octets')
    p = pdu(IDENT, 'SPLIT-HEADER')
    c.send(False, p[:3])
    c.send(False, p[3:])
    mark('header only, then the data')
    p = pdu(IDENT, 'LATE-DATA')
    c.send(True, p[:5])
    c.send(True, p[5:])
    mark('segment with the end of a PDU and a whole PDU')
    p = pdu(OPER, 'Y' * 30)
    c.send(False, p[:20])
    c.send(False, p[20:] + pdu(SYSTEM, '03'))
    mark('maximum length PDU (10245 octets, 8 segments)')
    p = pdu(OPER, bytes((i * 7) & 0xff for i in range(10240)))
    for i in range(0, len(p), 1460):
        c.send(True, p[i:i + 1460])
    mark('unknown type is not accepted in a known conversation')
    c.send(False, pdu(7, 'UNKNOWN TYPE'))
    c.close()

    # ---- first PDU not FMTP: the heuristic declines each of these
    mark('first PDU rejected by the heuristic')
    for i, seg in enumerate([
            pdu(SYSTEM, '01', ver=3),                  # version
            pdu(SYSTEM, '01', res=1),                  # reserved
            pdu(SYSTEM, '01', length=4),               # length below header
            pdu(SYSTEM, '01', length=5 + 10240 + 1),   # length above maximum
            pdu(0, '01'),                              # type below range
            pdu(5, '01'),                              # type above range
            b'\x02\x00\x00',                           # fewer than 5 octets
    ]):
        c2 = Conn(frames, 40010 + i, handshake=False)
        c2.send(True, seg)

    # ---- connection 3: the largest allowed length of the first PDU,
    # shortest identification and a server-first connection
    mark('connection 3: server speaks first')
    c3 = Conn(frames, 40020)
    p = pdu(IDENT, 'EGLL-ENXX')
    c3.send(False, p[:5])
    c3.send(False, p[5:])
    c3.send(True, pdu(IDENT, 'ENXX-EGLL'))
    c3.send(True, pdu(SYSTEM, '03'))
    c3.close()
    return marks


def build_malformed(frames):
    # An identification message of 7 or more octets as the first segment
    # is claimed by the Q.931 over TPKT heuristic (Q.931 inside TPKT).
    c0 = Conn(frames, 41000)
    c0.send(True, pdu(IDENT, 'ENXX-EGLL'))
    c0.send(False, pdu(IDENT, 'EGLL-ENXX'))
    c = Conn(frames, 41001)
    p = pdu(IDENT, 'ENXX-EGLL')
    c.send(True, p[:5])
    c.send(True, p[5:])
    # System message with no code: reading the code runs past the PDU
    c.send(True, pdu(SYSTEM, ''))
    # System message with a one octet code
    c.send(True, pdu(SYSTEM, '0'))
    # length field below the header size in a known conversation
    c.send(True, pdu(OPER, 'ABC', length=3))
    c.send(True, pdu(OPER, 'ABC', length=0))
    # length field far above the data: waits for more (never completes)
    c.send(False, pdu(OPER, 'ABC', length=20000))
    c2 = Conn(frames, 41002)
    # Identification PDU where the first segment is cut short and the
    # connection closes
    c2.send(True, pdu(IDENT, 'ENXX-EGLL'))
    c2.send(True, pdu(SYSTEM, '03', length=50))
    c2.close()
    # first segment: header only for a System message
    c3 = Conn(frames, 41003, handshake=False)
    c3.send(True, pdu(SYSTEM, ''))
    c4 = Conn(frames, 41004, handshake=False)
    c4.send(True, pdu(IDENT, ''))
    c4.send(True, pdu(SYSTEM, '01'))


def main(out):
    verbose = '-v' in sys.argv
    f = []
    marks = build(f)
    write_pcap(os.path.join(out, 'fmtp-coverage.pcap'), f)
    if verbose:
        for n, i in marks:
            print('%5d  %s' % (i, n))
    print('fmtp-coverage.pcap', len(f), 'frames')
    m = []
    build_malformed(m)
    write_pcap(os.path.join(out, 'fmtp-coverage-malformed.pcap'), m)
    print('fmtp-coverage-malformed.pcap', len(m), 'frames')


if __name__ == '__main__':
    main(sys.argv[1])

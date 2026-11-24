#!/usr/bin/env python3
# Generates test/captures/artemis_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Artemis dissector
(packet-artemis.c, the ActiveMQ Artemis core protocol).

All packets are built from scratch with struct; no captured traffic is
used. A client (192.0.2.10, 2001:db8::10) talks to a broker (192.0.2.20,
2001:db8::20) on TCP port 5445, which the dissector registers by default.

A PDU is a 4-octet length (not counting itself), a type octet, an
8-octet channel ID and a body.

Usage: mkartemis.py <output directory>

Writes:
  artemis-coverage.pcap            PDUs of several types, one PDU per
                                   segment, several PDUs per segment,
                                   PDUs split over segments (also in the
                                   length field), an empty body, a stream
                                   picked up in the middle, IPv6
  artemis-coverage-malformed.pcap  lengths under 9 and lengths that wrap
"""

import os
import struct
import sys

CLIENT4, BROKER4 = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])
CLIENT6 = bytes.fromhex('20010db8000000000000000000000010')
BROKER6 = bytes.fromhex('20010db8000000000000000000000020')
PORT = 5445

# Some packet types from PacketImpl.java
PING, DISCONNECT, CREATESESSION, CREATESESSION_RESP = 10, 11, 30, 31
SESS_CREATECONSUMER, SESS_START, NULL_RESPONSE = 40, 67, 21
SESS_SEND, SESS_RECEIVE_MSG, SESS_ACKNOWLEDGE = 71, 75, 51


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def pdu(ptype, channel, body=b''):
    return struct.pack('>IBQ', 9 + len(body), ptype, channel) + body


def raw_pdu(length, rest):
    """A PDU with any length field."""
    return struct.pack('>I', length) + rest


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload, v6):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        tlen = len(hdr) + len(payload)
        if v6:
            pseudo = struct.pack('>16s16sIxxxB', src, dst, tlen, 6)
        else:
            pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, tlen)
        hdr = hdr[:16] + struct.pack('>H', csum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        if v6:
            ip = struct.pack('>IHBB16s16s', 0x60000000, len(l4), 6, 64, src, dst)
            et = b'\x86\xdd'
        else:
            ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4),
                             len(self.frames) & 0xffff, 0x4000, 64, 6, 0, src, dst)
            ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
            et = b'\x08\x00'
        if src in (CLIENT4, CLIENT6):
            eth = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01' + et
        else:
            eth = b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02' + et
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000,
                                   len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class Stream:
    """A TCP connection with correct sequence numbers."""
    def __init__(self, cap, cport, v6=False, handshake=True):
        self.cap, self.cport, self.v6 = cap, cport, v6
        self.c, self.b = (CLIENT6, BROKER6) if v6 else (CLIENT4, BROKER4)
        self.cseq, self.bseq = 1000 + cport, 900000 + cport
        if handshake:
            self.cap.tcp(self.c, self.b, cport, PORT, self.cseq, 0, 0x02, b'', v6)
            self.cseq += 1
            self.cap.tcp(self.b, self.c, PORT, cport, self.bseq, self.cseq, 0x12, b'', v6)
            self.bseq += 1
            self.cap.tcp(self.c, self.b, cport, PORT, self.cseq, self.bseq, 0x10, b'', v6)

    def send(self, data, flags=0x18):
        self.cap.tcp(self.c, self.b, self.cport, PORT, self.cseq, self.bseq, flags, data, self.v6)
        self.cseq += len(data)

    def recv(self, data, flags=0x18):
        self.cap.tcp(self.b, self.c, PORT, self.cport, self.bseq, self.cseq, flags, data, self.v6)
        self.bseq += len(data)

    def ack_client(self):
        self.recv(b'', 0x10)

    def ack_broker(self):
        self.send(b'', 0x10)

    def close(self):
        self.send(b'', 0x11)
        self.cseq += 1
        self.recv(b'', 0x11)
        self.bseq += 1
        self.ack_broker()


def body(n, seed=0):
    return bytes((seed + i * 7) & 0xff for i in range(n))


def main_capture():
    p = Pcap()
    s = Stream(p, 50000)                                         # 1-3
    # 4-5: one PDU per segment each way
    s.send(pdu(CREATESESSION, 1, b'\x00\x00\x00\x05guest' + body(40)))
    s.recv(pdu(CREATESESSION_RESP, 1, b'\x00\x00\x00\x7f'))
    # 6: three PDUs in one segment; 7: the broker acknowledges
    s.send(pdu(SESS_CREATECONSUMER, 2, body(20, 1)) + pdu(SESS_START, 2) +
           pdu(PING, 0, struct.pack('>q', 30000)))
    s.ack_client()
    # 8-10: one 2000-octet PDU over three segments
    big = pdu(SESS_SEND, 2, body(1987, 2))
    assert len(big) == 2000
    for i in range(0, 2000, 800):
        s.send(big[i:i + 800])
    s.ack_client()                                               # 11
    # 12-13: the length field itself split (two octets, then the rest)
    p2 = pdu(SESS_SEND, 2, body(100, 3))
    s.send(p2[:2])
    s.send(p2[2:])
    # 14-15: a PDU ending, a whole PDU and the start of a third in one
    # segment, then the rest of the third
    a, b_, c = pdu(SESS_SEND, 2, body(50, 4)), pdu(SESS_SEND, 2, body(60, 5)), pdu(SESS_SEND, 2, body(70, 6))
    s.send(a[:20])
    s.send(a[20:] + b_ + c[:30])
    s.send(c[30:])                                               # 16
    # 17: a PDU with an empty body (length 9), and the broker's empty reply
    s.send(pdu(SESS_ACKNOWLEDGE, 2))
    s.recv(pdu(NULL_RESPONSE, 2))                                # 18
    # 19-23: the broker delivers a 5000-octet message over four segments
    # and a NULL_RESPONSE right after it in the last one
    msg = pdu(SESS_RECEIVE_MSG, 2, body(4987, 7)) + pdu(NULL_RESPONSE, 2)
    for i in range(0, len(msg), 1460):
        s.recv(msg[i:i + 1460])
    s.ack_broker()                                               # 23
    # 24: a channel ID with every octet set, an unknown type 255
    s.send(pdu(255, 0xffffffffffffffff, b'\x01\x02'))
    # 25: disconnect, 26-28: close
    s.send(pdu(DISCONNECT, 0, b'\x00' * 8))
    s.close()
    # 29-31: a connection picked up in the middle (no handshake)
    m = Stream(p, 50001, handshake=False)
    m.send(pdu(SESS_SEND, 7, body(30, 8)) + pdu(SESS_SEND, 7, body(31, 9)))
    m.recv(pdu(NULL_RESPONSE, 7) + pdu(NULL_RESPONSE, 7))
    m.ack_broker()
    # 32-38: IPv6, a PDU split in two each way
    v = Stream(p, 50002, v6=True)
    x = pdu(CREATESESSION, 1, body(300, 10))
    v.send(x[:150])
    v.send(x[150:])
    y = pdu(CREATESESSION_RESP, 1, body(200, 11))
    v.recv(y[:5])
    v.recv(y[5:])
    return p


def malformed_capture():
    p = Pcap()
    # 1-5 (after the handshake): lengths 0, 8 (under 9: "Frame length is
    # too short", an error expert info), then a valid PDU
    s = Stream(p, 51000)
    s.send(raw_pdu(0, b''))
    s.send(raw_pdu(8, b'\x0a' + b'\x00' * 7))
    s.send(pdu(PING, 0, b'\x00' * 8))
    # Length 0xffffffff: plus 4 wraps to 3, under the fixed length
    s.send(raw_pdu(0xffffffff, b'\x0a' + b'\x00' * 8))
    s.close()
    # Lengths 0xfffffffc (plus 4 wraps to 0) and 0xfffffffb (wraps to
    # 0xffffffff), each on its own connection
    for port, length in ((51001, 0xfffffffc), (51002, 0xfffffffb), (51003, 0x80000009)):
        t = Stream(p, port)
        t.send(raw_pdu(length, b'\x47' + b'\x00' * 8 + b'tail'))
        t.close()
    # A PDU longer than the data, then the connection closes
    u = Stream(p, 51004)
    u.send(pdu(SESS_SEND, 2, body(500))[:100])
    u.close()
    return p


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'artemis-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'artemis-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

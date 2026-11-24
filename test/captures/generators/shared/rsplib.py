# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Packet helpers for the SGP.22 and SGP.32 coverage captures: pcapng with
an Ethernet and an Exported PDU interface, TCP connections, HTTP and CoAP."""

import struct

PHONE = (bytes([192, 0, 2, 1]), bytes.fromhex('020000000001'))
SERVER = (bytes([192, 0, 2, 2]), bytes.fromhex('020000000002'))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_packet(proto, src, dst, payload):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0, src, dst)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + payload


class Tcp:
    """A TCP connection; frames are appended to the list."""

    def __init__(self, frames, cport, sport, cip=PHONE, sip=SERVER):
        self.f = frames
        self.c = (cip, cport)
        self.s = (sip, sport)
        self.seq = {True: 1000, False: 5000}

    def _pkt(self, from_client, flags, payload):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', a[1], b[1], seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = a[0][0] + b[0][0] + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        self.seq[from_client] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.f.append(b[0][1] + a[0][1] + b'\x08\x00' + ip_packet(6, a[0][0], b[0][0], tcp))

    def handshake(self):
        self._pkt(True, 0x02, b'')
        self._pkt(False, 0x12, b'')
        self._pkt(True, 0x10, b'')

    def send(self, from_client, payload, seg=1400):
        for i in range(0, max(len(payload), 1), seg):
            self._pkt(from_client, 0x18, payload[i:i + seg])

    def close(self):
        self._pkt(True, 0x11, b'')
        self._pkt(False, 0x11, b'')
        self._pkt(True, 0x10, b'')


CT = b'Content-Type: application/x-gsma-rsp-asn1\r\n'


def http_post(path, body, host=b'smdp.example', ct=True):
    return (b'POST ' + path + b' HTTP/1.1\r\nHost: ' + host + b'\r\n' +
            (CT if ct else b'') + b'User-Agent: gsma-rsp-lpad\r\nX-Admin-Protocol: gsma/rsp/v2.5.0\r\n'
            b'Content-Length: %d\r\n\r\n' % len(body) + body)


def http_ok(body, ct=True):
    return (b'HTTP/1.1 200 OK\r\nX-Admin-Protocol: gsma/rsp/v2.5.0\r\n' + (CT if ct else b'') +
            b'Content-Length: %d\r\n\r\n' % len(body) + body)


def udp_frame(sport, dport, payload, from_client=True):
    a, b = (PHONE, SERVER) if from_client else (SERVER, PHONE)
    udp = struct.pack('!HHHH', sport if from_client else dport, dport if from_client else sport,
                      8 + len(payload), 0) + payload
    return b[1] + a[1] + b'\x08\x00' + ip_packet(17, a[0], b[0], udp)


def coap(mtype, code, mid, token=b'', path=(), payload=b''):
    """A CoAP message with Uri-Path options."""
    msg = struct.pack('!BBH', 0x40 | (mtype << 4) | len(token), code, mid) + token
    last = 0
    for seg in path:
        s = seg.encode()
        assert len(s) < 13
        msg += bytes([((11 - last) << 4) | len(s)]) + s
        last = 11
    if payload:
        msg += b'\xff' + payload
    return msg


def _block(btype, body):
    pad = (4 - len(body) % 4) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload


class Pcapng:
    """pcapng: interface 0 Ethernet, interface 1 Exported PDU (252)."""

    def __init__(self, t0=1793491200):
        self.t = t0
        self.n = 0
        self.out = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in (1, 252):
            self.out += _block(1, struct.pack('<HHI', lt, 0, 262144))

    def add(self, frame, iface=0):
        ts = (self.t + self.n) * 1000000
        self.out += _block(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                          len(frame), len(frame)) + frame)
        self.n += 1

    def eth(self, frames):
        for f in frames:
            self.add(f, 0)

    def exp(self, name, payload):
        self.add(exp_pdu(name, payload), 1)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.out)

#!/usr/bin/env python3
# Generates test/captures/omapi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the OMAPI dissector
(packet-omapi.c, ISC Object Management API, TCP port 7911).

Every packet is built with struct; nothing comes from a real network. The
signature of a message is a placeholder (zero bytes), no authentication
code is computed.

Usage: mkomapi.py <output directory>

Writes:
  omapi-coverage.pcap            startup (status) messages, every opcode,
                                 messages with values, empty values and no
                                 value, objects, signatures
  omapi-coverage-malformed.pcap  truncated messages
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IPA = bytes((192, 0, 2, 1))
IPB = bytes((192, 0, 2, 2))

def ip4(proto, payload, src=IPA, dst=IPB, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload

def eth(payload, et=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', et) + payload

def udp_frame(payload, sport, dport, src=IPA, dst=IPB):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('>BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
    return eth(ip4(17, u, src, dst))

class Tcp:
    """Minimal TCP flow: handshake, then data segments in both directions."""
    def __init__(self, sport, dport, cseq=1000, sseq=70000):
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = cseq, sseq
        self.frames = []

    def _seg(self, to_server, payload, flags):
        if to_server:
            src, dst, sp, dp, seq, ack = IPA, IPB, self.sport, self.dport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = IPB, IPA, self.dport, self.sport, self.sseq, self.cseq
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, 0x50, flags, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        mac_s, mac_d = (MAC_A, MAC_B) if to_server else (MAC_B, MAC_A)
        self.frames.append(eth(ip4(6, t, src, dst), src=mac_s, dst=mac_d))
        adv = len(payload) + (1 if flags & 3 else 0)
        if to_server:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._seg(True, b'', 0x02)
        self._seg(False, b'', 0x12)
        self._seg(True, b'', 0x10)

    def send(self, to_server, payload):
        self._seg(to_server, payload, 0x18)
        self._seg(not to_server, b'', 0x10)

def write_pcap(path, frames, linktype=1, snap=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)



def nv16(name, val):
    """name (16 bit length) and value (32 bit length); None = no value (~0)."""
    out = struct.pack('>H', len(name)) + name
    if val is None:
        return out + struct.pack('>I', 0xffffffff)
    return out + struct.pack('>I', len(val)) + val


def omapi(opcode, handle=0, ident=1, rid=0, msgs=(), objs=(), authid=0, sig=b'', authlen=None):
    b = struct.pack('>II', authid, len(sig) if authlen is None else authlen)
    b += struct.pack('>IIII', opcode, handle, ident, rid)
    for n, v in msgs:
        b += nv16(n, v)
    b += b'\x00\x00'
    for n, v in objs:
        b += nv16(n, v)
    b += b'\x00\x00'
    return b + sig


STATUS = struct.pack('>II', 100, 24)


def main_capture(path):
    t = Tcp(40000, 7911)
    t.handshake()
    t.send(True, STATUS)                                        # startup message, client
    t.send(False, STATUS)                                       # startup message, server
    t.send(True, STATUS + omapi(1, msgs=[(b'type', b'host')], objs=[(b'name', b'client1')]))   # startup and a message
    names = (1, 2, 3, 4, 5, 6, 7, 8, 99)
    for i, op in enumerate(names):
        t.send(i % 2 == 0, omapi(op, handle=i, ident=10 + i, rid=i % 3,
                                  msgs=[(b'type', b'lease'), (b'create', b'\x00\x00\x00\x01')],
                                  objs=[(b'ip-address', b'\xc0\x00\x02\x05'), (b'state', b'\x00\x00\x00\x02')]))
    # empty value, no value, long value
    t.send(True, omapi(1, msgs=[(b'type', b''), (b'exclusive', None), (b'name', b'x' * 300)],
                       objs=[(b'hostname', b''), (b'dummy', None), (b'blob', bytes(range(200)))]))
    # no messages and no objects
    t.send(True, omapi(2))
    # authenticated message: authid != 0 and a signature of 16 octets (zero placeholder)
    t.send(True, omapi(3, authid=5, ident=30, msgs=[(b'type', b'host')], sig=bytes(16)))
    t.send(False, omapi(4, authid=5, ident=31, rid=30, sig=bytes(16), objs=[(b'name', b'a')]))
    t.send(False, omapi(5, ident=32, rid=30, msgs=[(b'message', b'object not found'), (b'result', b'\x00\x00\x00\x14')]))
    # padding: a message split from the following one is not reassembled, each segment is one message
    t.send(True, omapi(6, handle=7, ident=33))
    write_pcap(path, t.frames)


def malformed_capture(path):
    t = Tcp(40001, 7911)
    t.handshake()
    t.send(True, b'\x00\x00\x00\x64\x00')                       # 5 octets: not OMAPI at all
    full = omapi(1, msgs=[(b'type', b'host')], objs=[(b'name', b'client1')])
    for cut in (24, 26, 30, 40, len(full) - 3):                  # cut in the header, a name, a value
        t.send(True, full[:cut])
    t.send(True, omapi(1, msgs=[(b'type', b'host')], authid=1, authlen=40) )   # signature beyond the data
    # a value length beyond the packet
    t.send(True, struct.pack('>IIIIII', 0, 0, 1, 0, 1, 0) + struct.pack('>H', 4) + b'type' + struct.pack('>I', 500) + b'abc')
    # an object name length beyond the packet
    t.send(True, struct.pack('>IIIIII', 0, 0, 1, 0, 1, 0) + b'\x00\x00' + struct.pack('>H', 300) + b'abc')
    write_pcap(path, t.frames)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'omapi-coverage.pcap'))
    malformed_capture(os.path.join(out, 'omapi-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

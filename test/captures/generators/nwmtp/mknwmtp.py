#!/usr/bin/env python3
# Generates test/captures/nwmtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NW MTP dissector
(packet-nwmtp.c, NexusWare C7 MTP over UDP).

The protocol has no registered port: it is reached with Decode As (the
tests and runcov.sh use -d udp.port==9000,nw_mtp). A PDU is a 12 octet
header (transport type, data type, link index, user context, length)
followed by an MTP3 MSU; several PDUs can share one datagram. Every packet
is built with struct; nothing comes from a real network.

Usage: mknwmtp.py <output directory>

Writes:
  nwmtp-coverage.pcap            every data type, both transport types, MSUs
                                 of several service indicators (MTP3 and SCCP
                                 are dissected by their own dissectors),
                                 several PDUs per datagram
  nwmtp-coverage-malformed.pcap  truncated headers, a length beyond the data
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



def label(dpc, opc, sls):
    return struct.pack('<I', (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28))


def msu(si, ni, dpc, opc, sls, payload):
    return bytes([((ni & 3) << 6) | (si & 0xf)]) + label(dpc, opc, sls) + payload


def sccp_udt(data):
    called = bytes([2, 0x42, 0x00])
    calling = bytes([2, 0x42, 0x00])
    return (bytes([0x09, 0x00, 3, 5, 7]) + called + calling + bytes([len(data)]) + data)


def pdu(dtype, payload, ttype=2, link=1, ctx=0x01020304, length=None):
    return struct.pack('>BBHII', ttype, dtype, link, ctx, len(payload) if length is None else length) + payload


MSUS = [
    msu(0, 2, 3, 4, 2, bytes([0x11, 0x05])),                       # SNM COO
    msu(1, 2, 7, 8, 1, bytes([0x11, 0x40]) + b'ABCD'),             # SLTM
    msu(2, 2, 7, 8, 1, bytes([0x21, 0x40]) + b'ABCD'),             # SLTA
    msu(0, 2, 5, 6, 3, bytes([0x21, 0x07])),                       # SNM ECO
    msu(0xf, 3, 3, 4, 2, bytes(range(5))),                         # unknown service indicator
    msu(9, 2, 3, 4, 2, bytes(range(12))),                          # unknown service indicator
    msu(1, 2, 9, 10, 4, bytes([0x11, 0x80]) + b'ABCDEFGH'),        # SLTM, longer pattern
]


def main_capture(path):
    fr = []
    port = 9000
    n = [0]

    def add(payload):
        n[0] += 1
        fr.append(udp_frame(payload, 40000 + n[0], port))
    # every data type with an MSU (prio 0-3, retrieved MSUs) and without
    for dt in (0, 1, 2, 3, 16, 17, 18):
        add(pdu(dt, MSUS[dt % len(MSUS)], link=dt))
    for dt in (32, 33, 34, 35, 99):
        add(pdu(dt, b'', link=dt))                                    # state messages: no MSU
    add(pdu(34, b'', ttype=3))                                         # TCP transport type
    add(pdu(0, MSUS[0], ttype=7))                                      # unknown transport type
    # several PDUs in one datagram
    add(pdu(0, MSUS[0]) + pdu(1, MSUS[1]) + pdu(35, b'', link=2) + pdu(3, MSUS[5], ttype=3))
    add(pdu(34, b'') + pdu(35, b''))
    # a huge length: the dissector stops after the PDU
    add(pdu(0, MSUS[4], length=0xffffffff))
    write_pcap(path, fr)


def malformed_capture(path):
    fr = []
    n = [0]

    def add(payload):
        n[0] += 1
        fr.append(udp_frame(payload, 41000 + n[0], 9000))
    p = pdu(0, MSUS[0])
    for cut in (1, 2, 8, 11):                                          # header cut short
        add(p[:cut])
    add(pdu(0, MSUS[0], length=200))                                   # length beyond the data
    add(pdu(0, MSUS[0][:3], length=3))                                 # MSU cut inside the routing label
    add(pdu(0, MSUS[0], length=0xfffffff5))
    write_pcap(path, fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'nwmtp-coverage.pcap'))
    malformed_capture(os.path.join(out, 'nwmtp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

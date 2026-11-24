# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal aligned-PER writer and E2AP/SCTP pcap helpers for the e2ap_*.py reproducers.
import struct


class BW:
    def __init__(self):
        self.bits = []

    def b(self, val, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((val >> i) & 1)
        return self

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)
        return self

    def octets(self, data):
        self.align()
        for c in data:
            self.b(c, 8)
        return self

    def lendet(self, n):
        # aligned unconstrained length determinant (n < 128)
        self.align()
        return self.b(n, 8)

    def opentype(self, data):
        self.lendet(len(data))
        return self.octets(data)

    def u16a(self, v):
        self.align()
        return self.b(v, 16)

    def u8a(self, v):
        self.align()
        return self.b(v, 8)

    def pstr(self, s, lb, ub):
        # PrintableString (SIZE(lb..ub, ...)) aligned
        self.b(0, 1)  # extension bit
        rng = ub - lb + 1
        if rng < 256:
            self.b(len(s) - lb, (rng - 1).bit_length())
        elif rng == 256:
            self.u8a(len(s) - lb)
        else:
            self.u16a(len(s) - lb)
        self.align()
        for c in s.encode():
            self.b(c, 8)
        return self

    def get(self):
        self.align()
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for bit in self.bits[i:i + 8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)


def ie(ie_id, crit, value):
    w = BW()
    w.u16a(ie_id)
    w.b(crit, 2)
    w.opentype(value)
    return w.get()


def container(ies):
    """SEQUENCE { protocolIEs ProtocolIE-Container, ... } -> bytes"""
    w = BW()
    w.b(0, 1)          # extension bit of the message SEQUENCE
    w.u16a(len(ies))   # SIZE(0..65535)
    for x in ies:
        w.octets(x)
    return w.get()


def pdu(choice, proc, crit, value):
    w = BW()
    w.b(0, 1)          # E2AP-PDU extension bit
    w.b(choice, 2)     # 0 initiating, 1 successful, 2 unsuccessful
    w.u8a(proc)
    w.b(crit, 2)
    w.opentype(value)
    return w.get()


def sctp_frame(payload, ppid=70, tsn=1):
    chunk_len = 16 + len(payload)
    data = struct.pack('>BBHIHHI', 0, 3, chunk_len, tsn, 0, tsn & 0xffff, ppid) + payload
    data += b'\0' * ((4 - len(data) % 4) % 4)
    sctp = struct.pack('>HHII', 36421, 37464, 1, 0) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(sctp), 1, 0, 64, 132, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + sctp
    eth = bytes.fromhex('020000000002' '020000000001' '0800') + ip
    return eth


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

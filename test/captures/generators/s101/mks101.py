#!/usr/bin/env python3
# Generates test/captures/s101_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the S101 coverage captures. Usage: mks101.py <outdir>"""
import sys
import os
from pcaplib import Pcap, TcpStream

PORT = 9000

# ---- a little BER for the Glow payloads
def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b
def T(tag, *parts):
    c = b''.join(parts)
    return bytes([tag]) + blen(len(c)) + c
def ctx(n, *p): return T(0xa0 | n, *p)
def app(n, *p): return T(0x60 | n, *p)
def INT(v): return bytes([2, 1, v & 0xff])
def UTF(s): return T(0x0c, s.encode())
def node(num, ident):
    return app(3, ctx(0, INT(num)), ctx(1, T(0x31, ctx(0, UTF(ident)))))
def root(*nodes):
    return app(0, app(11, *[ctx(0, n) for n in nodes]))

# ---- S101 framing (the checksum is CRC-16/X-25 over the message, not a secret)
def crc_upd(reg, b):
    reg ^= b
    for _ in range(8):
        reg = (reg >> 1) ^ 0x8408 if reg & 1 else reg >> 1
    return reg
def esc(b):
    out = b''
    for x in b:
        out += bytes([0xfd, x ^ 0x20]) if x >= 0xf8 else bytes([x])
    return out
HDR = lambda flags: bytes([0x00, 0x0e, 0x00, 0x01, flags, 0x01, 0x02, 0x1f, 0x02])
def s101(payload, flags=0xc0, bad_crc=False, hdr=None):
    hdr = HDR(flags) if hdr is None else hdr
    reg = 0xffff
    for x in hdr + payload:
        reg = crc_upd(reg, x)
    fcs = (~reg) & 0xffff
    if bad_crc:
        fcs ^= 0x1234
    return bytes([0xfe]) + hdr + esc(payload + bytes([fcs & 0xff, fcs >> 8])) + b'\xff'
def keepalive(resp=False):
    body = bytes([0x00, 0x0e, 0x02 if resp else 0x01, 0x01])
    reg = 0xffff
    for x in body:
        reg = crc_upd(reg, x)
    fcs = (~reg) & 0xffff
    return bytes([0xfe]) + body + esc(bytes([fcs & 0xff, fcs >> 8])) + b'\xff'
def s101v2(payload, flags=0xc0, lensize=2, length=None, hdr=None):
    """Variant 2 (0xF8): no escaping, no checksum, the length is in the header."""
    hdr = HDR(flags) if hdr is None else hdr
    n = len(hdr) + len(payload) if length is None else length
    return bytes([0xf8, lensize]) + (n.to_bytes(lensize, 'big') if lensize else b'') + hdr + payload


def main(out):
    p = Pcap()
    G1 = root(node(1, 'device'))
    G2 = root(node(2, 'router'), node(3, 'matrix'))
    BIG = root(*[node(i, 'node%03d' % i) for i in range(1, 40)])
    t = TcpStream(p, 50001, PORT)
    # 1-: single packets from both sides, keepalives
    t.c(s101(G1))
    t.s(s101(G2))
    t.c(keepalive(False))
    t.s(keepalive(True))
    # escaped bytes in the payload (0xFD, 0xFE, 0xFF and 0xF8 are escaped)
    t.s(s101(root(node(4, 'esc'), ) + b'', 0xc0))
    t.s(s101(root(node(5, '\xfd\xfe\xff'.encode('latin-1').decode('latin-1')))))
    # two S101 frames in one segment, three with a keepalive in between
    t.c(s101(G1) + s101(G2))
    t.s(s101(G1) + keepalive(True) + s101(G2))
    # a message in three fragments (first, middle, last) reassembled
    k = len(BIG) // 3
    t.s(s101(BIG[:k], 0x80))
    t.s(s101(BIG[k:2 * k], 0x00))
    t.s(s101(BIG[2 * k:], 0x40))
    # a fragmented message with several frames in a segment: first + middle, then last
    t.s(s101(BIG[:k], 0x80) + s101(BIG[k:2 * k], 0x00))
    t.s(s101(BIG[2 * k:], 0x40))
    # empty packet flag
    t.s(s101(b'', 0x20))
    # bad CRC (a warning)
    t.c(s101(G1, bad_crc=True))
    t.fin()

    # second connection: variant 2 frames (0xF8 header with the message length)
    t = TcpStream(p, 50002, PORT)
    t.c(s101v2(G1))
    t.s(s101v2(G2))
    t.c(s101v2(G1, lensize=4))
    # two variant 2 frames in a segment: the second one does not start at offset 0
    t.s(s101v2(G1) + s101v2(G2))
    t.s(s101v2(G2) + s101(G1) + s101v2(G1, lensize=3))
    # variant 2 fragments
    t.s(s101v2(BIG[:k], 0x80))
    t.s(s101v2(BIG[k:2 * k], 0x00))
    t.s(s101v2(BIG[2 * k:], 0x40))
    t.fin()

    # third connection from another host: fragments of two senders do not mix (the id comes from the source)
    a = TcpStream(p, 50003, PORT, caddr='10.0.0.3', saddr='10.0.0.2')
    b = TcpStream(p, 50004, PORT, caddr='10.0.0.4', saddr='10.0.0.2')
    a.c(s101(BIG[:k], 0x80))
    b.c(s101(G1[:5] + G1[5:], 0xc0))
    a.c(s101(BIG[k:], 0x40))
    a.fin(); b.fin()
    p.write(os.path.join(out, 's101-coverage.pcap'))

    # ===== malformed and warnings
    m = Pcap()
    t = TcpStream(m, 51001, PORT)
    t.s(s101(BIG[2 * k:], 0x40))                    # last fragment without a first: reassembly error
    t.s(s101(BIG[k:2 * k], 0x00))                   # middle fragment without a first
    t.s(s101(BIG[:k], 0x80))
    t.s(s101(BIG[k:2 * k], 0x00))
    t.s(s101(BIG[2 * k:], 0x40, bad_crc=True))      # last fragment with a bad CRC
    # the first fragment sent again (a new message starts); the reassembled message is not the sent one (see README)
    t.s(s101(BIG[:k], 0x80))
    t.s(s101(BIG[:k], 0x80))
    t.s(s101(BIG[k:], 0x40))
    t.s(s101(b'\x30\x03\x02\x01\x05'))              # payload that is not Glow
    t.s(s101(b'', 0x40))                            # last fragment, empty
    t.s(s101(b''))                                  # an empty single packet: no Glow to dissect
    # frames the header check rejects: wrong slot, wrong message, wrong command, wrong version, flags, dtd, app bytes
    for h in (bytes([1, 0x0e, 0, 1, 0xc0, 1, 2, 0x1f, 2]), bytes([0, 0x0f, 0, 1, 0xc0, 1, 2, 0x1f, 2]),
              bytes([0, 0x0e, 3, 1]), bytes([0, 0x0e, 0, 2, 0xc0, 1, 2, 0x1f, 2]),
              bytes([0, 0x0e, 0, 1, 0xc1, 1, 2, 0x1f, 2]), bytes([0, 0x0e, 0, 1, 0xc0, 2, 2, 0x1f, 2]),
              bytes([0, 0x0e, 0, 1, 0xc0, 1, 3, 0x1f, 2])):
        t.s(b'\xfe' + h + b'\x01\x02\x03\xff')
    t.s(b'\x55\x01\x02\x03\x04\x05\x06')              # not a frame at all (wrong start byte)
    t.s(b'\xfe\x00\x0e')                              # less than the minimum length
    t.s(b'\xfe\x00\x0e\x01\x01\xfd')                  # keepalive cut inside the CRC escape
    t.s(b'\xfe\x00\x0e\x00\x01\xc0\x01\x02\x1f\x02' + b'\x30\x03\x02\x01\x05')   # no EOF
    t.s(b'\xfe\x00\x0e\x01')                          # keepalive header only
    t.s(b'\xfe\x00\x0e\x01\x01\x12\x34\xff\xfe\x00\x0e')   # keepalive then a truncated frame
    # a header byte sent escaped (0xFD, byte xor 0x20): the slot as FD 20 in variant 1 and in variant 2 (the CRC does not match)
    t.s(b'\xfe\xfd\x20\x0e\x01\x01\x12\x34\xff')
    t.s(b'\xfe\x00\xfd\x2e\x00\x01\xc0\x01\x02\x1f\x02' + G1 + b'\x12\x34\xff')
    t.s(b'\xf8\x02\x00\x20\xfd\x20\x0e\x00\x01\xc0\x01\x02\x1f\x02' + G1)
    # variant 2 with odd lengths
    t.s(s101v2(G1, length=3))                         # message length shorter than the header
    t.s(s101v2(G1, length=500))                       # message length beyond the data
    t.s(s101v2(G1, lensize=1))                        # a one octet length is not handled as a length
    t.s(s101v2(G1, lensize=8))
    t.s(s101v2(G1, lensize=0))
    t.s(b'\xf8\x02\x00')                              # cut in the length
    t.s(b'\xf8\x02\x00\x0d\x00\x0e\x00\x01\xc0')      # cut in the header
    t.s(s101v2(b'', 0xc0, length=9))
    t.s(s101v2(BIG[k:2 * k], 0x00))                   # middle fragment without a first (variant 2)
    t.fin()
    m.write(os.path.join(out, 's101-coverage-malformed.pcap'))

main(sys.argv[1])

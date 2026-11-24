#!/usr/bin/env python3
# Generates test/captures/iso7816_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISO 7816 coverage captures. Usage: mkiso7816.py <outdir>
# Everything is synthetic. The APDUs travel in ISO 14443-4 I-blocks (pcap
# link type 264), which is how ISO 7816 is reached with the ISO 14443
# payload decoded as ISO 7816 (Decode As iso14443.subdissector -> iso7816);
# ATR and the dissector without direction are also sent as Exported PDUs.
import struct
import sys
import os


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))

EVT_PICC_PCD_NOCRC = 0xFB
EVT_PCD_PICC_NOCRC = 0xFA


def rec(event, payload):
    return struct.pack('!BBH', 0, event, len(payload)) + payload


class Session:
    def __init__(self):
        self.frames = []
        self.blk = 0

    def cmd(self, apdu):
        self.frames.append(rec(EVT_PCD_PICC_NOCRC, bytes([0x02 | self.blk]) + apdu))

    def rsp(self, data):
        self.frames.append(rec(EVT_PICC_PCD_NOCRC, bytes([0x02 | self.blk]) + data))
        self.blk ^= 1

    def exch(self, apdu, resp=b'\x90\x00'):
        self.cmd(apdu)
        self.rsp(resp)


def apdu(cla, ins, p1, p2, data=None, le=None):
    b = bytes([cla, ins, p1, p2])
    if data is not None:
        b += bytes([len(data)]) + data
    if le is not None:
        b += bytes([le])
    return b


def make_atr(groups, hist=b'', tck=None, ts=0x3B):
    """groups: list of dict(ta, tb, tc, td) for TA1.. (td None = last)."""
    out = bytes([ts])
    k = len(hist)
    t0 = k
    first = groups[0]
    for key, bit in (('ta', 0x10), ('tb', 0x20), ('tc', 0x40), ('td', 0x80)):
        if first.get(key) is not None:
            t0 |= bit
    out += bytes([t0])
    for i, g in enumerate(groups):
        for key in ('ta', 'tb', 'tc', 'td'):
            if g.get(key) is not None:
                out += bytes([g[key]])
        # TD(i) determines whether the next group is present, it is the
        # last byte appended for the group
    out += hist
    if tck is not None:
        out += bytes(tck)
    return out


def td(next_bits, t):
    return next_bits | t


def main(outdir):
    s = Session()
    # ATRs: every FI and DI value in TA1, TB/TC, TD chains, TCK
    # (TS, T0, TA1, TD1(T=0), TD2 (T=1) ... )
    atrs = []
    for fi in range(16):
        di = (fi * 3 + 1) % 16
        atrs.append(make_atr([dict(ta=(fi << 4) | di)], hist=b'\x80\x31'))
    for di in range(16):
        atrs.append(make_atr([dict(ta=0x10 | di)], hist=b''))
    # all interface characters, two groups, historical bytes and TCK
    atrs.append(make_atr([dict(ta=0x11, tb=0x25, tc=0x01, td=0xF1),
                          dict(ta=0x03, tb=0x04, tc=0x05, td=0x01)], hist=b'ABC', tck=[0x5a]))
    # TD chain of three groups (TB2, TD2, then TC3), TCK
    atrs.append(make_atr([dict(ta=0x13, td=0xA0), dict(tb=0x05, td=0x41), dict(tc=0x07)],
                         hist=b'\x01\x02\x03\x04', tck=[0x00]))
    # inverse convention TS = 0x3F
    atrs.append(make_atr([dict(ta=0x95)], hist=b'xy', ts=0x3F))
    # ATR without any interface bytes, no historical bytes, only TS and T0
    atrs.append(bytes([0x3B, 0x00]))
    for a in atrs:
        s.cmd(apdu(0x00, 0xA4, 0x04, 0x00, b'\xa0\x00\x00\x00\x03'))
        s.rsp(a)
    # the select file command with every selection control and option
    for p1 in (0, 1, 2, 3, 4, 8, 9, 0x0f):
        for p2 in (0x00, 0x04, 0x08, 0x0c, 0x01):
            s.exch(apdu(0x00, 0xA4, p1, p2, b'\x3f\x00', 0x00), b'\x6f\x00\x90\x00')
    # read binary with and without a short file identifier
    s.exch(apdu(0x00, 0xB0, 0x00, 0x10, le=0x20), bytes(32) + b'\x90\x00')
    s.exch(apdu(0x00, 0xB0, 0x85, 0x00, le=0x10), bytes(16) + b'\x90\x00')
    # read record: record number and usage in P2, EF
    s.exch(apdu(0x00, 0xB2, 0x01, 0x0c, le=0x00), b'\x01\x02\x90\x00')
    s.exch(apdu(0x00, 0xB2, 0x02, 0x0d, le=0x00), b'\x01\x02\x90\x00')
    s.exch(apdu(0x00, 0xB2, 0x03, 0x14, le=0x00), b'\x01\x02\x90\x00')
    s.exch(apdu(0x00, 0xB2, 0x03, 0xf5, le=0x00), b'\x01\x02\x90\x00')
    # get response
    s.exch(apdu(0x00, 0xC0, 0x00, 0x00, le=0x10), bytes(16) + b'\x90\x00')
    s.exch(apdu(0x00, 0xC0, 0x01, 0x02, le=0x10), b'\x6a\x86')
    # get data: RFU, application data, others
    for p1, p2 in ((0x00, 0x10), (0x03, 0x00), (0x01, 0x42), (0x01, 0xFF), (0x00, 0x42),
                   (0x00, 0xFF), (0x40, 0x00), (0x02, 0x00), (0x3f, 0xff)):
        s.exch(apdu(0x00, 0xCA, p1, p2, le=0x00), b'\x5f\x20\x01\x41\x90\x00')
    # verify, external authenticate (P1 zero and non zero), get challenge,
    # manage channel, erase binary, envelope, put data, ...
    s.exch(apdu(0x00, 0x20, 0x00, 0x81, b'\x31\x32\x33\x34'), b'\x63\xc2')
    s.exch(apdu(0x00, 0x82, 0x00, 0x00, bytes(8)), b'\x69\x82')
    s.exch(apdu(0x00, 0x82, 0x01, 0x83, bytes(8)), b'\x90\x00')
    s.exch(apdu(0x00, 0x84, 0x00, 0x00, le=0x08), bytes(8) + b'\x90\x00')
    s.exch(apdu(0x00, 0x70, 0x00, 0x00, le=0x01), b'\x01\x90\x00')
    s.exch(apdu(0x00, 0x0E, 0x00, 0x00), b'\x90\x00')
    s.exch(apdu(0x00, 0xC2, 0x00, 0x00, bytes(4)), b'\x90\x00')
    for ins in (0xD0, 0xD2, 0xD6, 0xDA, 0xDC, 0xE2):
        s.exch(apdu(0x00, ins, 0x00, 0x01, b'\xaa\xbb\xcc'), b'\x90\x00')
    # unknown instruction, Lc = 0, Lc with Le, only Le, no body
    s.exch(apdu(0x00, 0x44, 0x01, 0x02, b'\x01\x02', 0x05), b'\x90\x00')
    s.exch(bytes([0x00, 0x44, 0x01, 0x02, 0x00, 0x05]), b'\x6d\x00')
    s.exch(apdu(0x00, 0x44, 0x01, 0x02, le=0x00), b'\x6d\x00')
    s.exch(apdu(0x00, 0x44, 0x01, 0x02), b'\x6d\x00')
    # response with no body and with a 1 octet "body", length 1 or 0
    s.exch(apdu(0x00, 0xA4, 0x00, 0x00), b'\x61\x10')
    s.exch(apdu(0x00, 0xA4, 0x00, 0x00), b'\x6c')
    # class bytes: secure messaging and logical channels, every class range
    for cla in (0x01, 0x02, 0x03, 0x04, 0x08, 0x0c, 0x0f, 0x10, 0x40, 0x7f, 0x80, 0x84, 0x9f,
                0xa0, 0xaf, 0xb0, 0xcf, 0xd0, 0xfe, 0xff):
        s.exch(apdu(cla, 0xA4, 0x04, 0x00, b'\x01\x02'), b'\x90\x00')
    # responses without a matching request, two responses in a row
    s.rsp(b'\x90\x00')
    s.rsp(b'\x6a\x82')
    s.cmd(apdu(0x00, 0xCA, 0x01, 0x00, le=0))
    s.cmd(apdu(0x00, 0xCA, 0x01, 0x01, le=0))
    s.rsp(b'\x90\x00')
    write_pcap(os.path.join(outdir, 'iso7816-coverage.pcap'), 264, s.frames)
    write_epdu(outdir)
    write_malformed(outdir)


def epdu(name, payload):
    n = name.encode() + b'\0'
    n += bytes((-len(n)) % 4)
    return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload


def write_epdu(outdir):
    f = []
    # the ATR dissector reached directly (by name) and the ISO 7816
    # dissector without a direction (it declines the packet)
    f.append(epdu('iso7816.atr', make_atr([dict(ta=0x96, tb=0x00, td=0x01)], hist=b'\x80\x31', tck=[0x71])))
    f.append(epdu('iso7816.atr', b'\x3b'))
    f.append(epdu('iso7816.atr', b'\x00\x00\x00'))
    f.append(epdu('iso7816', apdu(0x00, 0xA4, 0x04, 0x00, b'\xa0\x00')))
    write_pcap(os.path.join(outdir, 'iso7816-coverage-epdu.pcap'), 252, f)


def write_malformed(outdir):
    s = Session()
    # ATR with more than one octet after the historical bytes (TCK)
    s.cmd(apdu(0x00, 0xA4, 0x04, 0x00))
    s.rsp(make_atr([dict(ta=0x11)], hist=b'ab', tck=[1, 2, 3]))
    # ATR announcing more historical bytes than present, TD chain cut short
    s.cmd(apdu(0x00, 0xA4, 0x04, 0x00))
    s.rsp(bytes([0x3B, 0x0F, 0x01]))
    s.cmd(apdu(0x00, 0xA4, 0x04, 0x00))
    s.rsp(bytes([0x3B, 0xF0, 0x11, 0x22, 0x33]))
    s.cmd(apdu(0x00, 0xA4, 0x04, 0x00))
    s.rsp(bytes([0x3B, 0x80]))
    # commands cut short: class and instruction only, one parameter
    s.cmd(bytes([0x00, 0xA4]))
    s.rsp(b'\x90\x00')
    s.cmd(bytes([0x00, 0xA4, 0x04]))
    s.rsp(b'\x90')
    # Lc larger than the data that follows
    s.cmd(bytes([0x00, 0xD6, 0x00, 0x00, 0x10, 1, 2, 3]))
    s.rsp(b'\x6a\x80')
    # instruction not 7816 style (class), a class byte only
    s.cmd(bytes([0x20]))
    s.rsp(b'')
    write_pcap(os.path.join(outdir, 'iso7816-coverage-malformed.pcap'), 264, s.frames)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/synphasor_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Synchrophasor dissector
(packet-synphasor.c, IEEE C37.118.2-2011 frames: header, configuration 1, 2
and 3, data and command frames).

Usage: mksynphasor.py <output directory>

Writes:
  synphasor-coverage.pcapng            frames over UDP 4713 and TCP 4712: all
                                       frame types, every data format of the
                                       configuration (integer/float phasors,
                                       frequency and analog values, polar and
                                       rectangular), digital words, CFG-3 with
                                       named channels, WGS84 data, command frames,
                                       time quality flags
  synphasor-coverage-malformed.pcapng  bad CRC, error status flags, data frames
                                       without or with a mismatching configuration,
                                       truncated frames, fragmented CFG-3

Every packet is built with struct; addresses are from 192.0.2.0/24.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, TcpConn, udp

DATA, HDR, CFG1, CFG2, CMD, CFG3 = 0, 1, 2, 3, 4, 5


def crc(b):
    c = 0xFFFF
    for x in b:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def frame(ftype, body, idcode=7, soc=1700000000, tq=0, frac=1000, version=2, size=None, bad_crc=False):
    n = 14 + len(body) + 2 if size is None else size
    h = struct.pack('>BBHHI', 0xAA, (ftype << 4) | version, n, idcode, soc) + bytes([tq]) + frac.to_bytes(3, 'big')
    b = h + body
    c = crc(b) ^ (1 if bad_crc else 0)
    return b + struct.pack('>H', c)


def name16(s):
    return s.encode('latin-1').ljust(16, b' ')[:16]


class Pmu:
    def __init__(self, name='STATION A', idcode=1, ph_float=False, an_float=False, fr_float=False, polar=False,
                 phasors=(('VA', 'V', 1), ('IA', 'A', 2)), analogs=(('POWER', 0, 0), ('RMS', 1, 5)),
                 ndg=1, fnom50=False, cfgcnt=3, dgnames=None):
        self.name, self.idcode = name, idcode
        self.ph_float, self.an_float, self.fr_float, self.polar = ph_float, an_float, fr_float, polar
        self.phasors, self.analogs, self.ndg = list(phasors), list(analogs), ndg
        self.fnom50, self.cfgcnt = fnom50, cfgcnt
        self.dgnames = dgnames

    def fmt(self):
        return ((8 if self.fr_float else 0) | (4 if self.an_float else 0) | (2 if self.ph_float else 0)
                | (1 if self.polar else 0))

    def cfg2(self):
        b = name16(self.name) + struct.pack('>HHHHH', self.idcode, self.fmt(), len(self.phasors),
                                             len(self.analogs), self.ndg)
        for n, u, c in self.phasors:
            b += name16(n)
        for n, t, c in self.analogs:
            b += name16(n)
        for k in range(self.ndg * 16):
            b += name16('D%d.%d' % (k // 16, k % 16))
        for n, u, c in self.phasors:
            b += struct.pack('>I', ((1 if u == 'A' else 0) << 24) | (c & 0xffffff))
        for n, t, c in self.analogs:
            b += struct.pack('>I', (t << 24) | (c & 0xffffff))
        for k in range(self.ndg):
            b += struct.pack('>HH', 0x0f0f, 0xffff)
        b += struct.pack('>HH', 1 if self.fnom50 else 0, self.cfgcnt)
        return b

    def cfg3(self, long_names=False, lat=45.5, lon=-122.5, elev=30.0, svc=b'P', ptypes=None):
        def nm(s):
            e = s.encode('latin-1')
            return bytes([len(e)]) + e
        b = nm(self.name * (3 if long_names else 1)) + struct.pack('>H', self.idcode) + bytes(range(1, 17))
        b += struct.pack('>HHHH', self.fmt(), len(self.phasors), len(self.analogs), self.ndg)
        for n, u, c in self.phasors:
            b += nm(n * (4 if long_names else 1))
        for n, t, c in self.analogs:
            b += nm(n)
        for k in range(self.ndg * 16):
            b += nm('' if k % 5 == 4 else 'D%d.%d' % (k // 16, k % 16))
        for i, (n, u, c) in enumerate(self.phasors):
            t = (ptypes or [0x00, 0x03, 0x05, 0x08, 0x0c])[i % 5]
            flags = (0x8000 if i & 1 else 0) | 0x0420
            b += struct.pack('>HBB', flags, t, 0x40 + i) + struct.pack('>ff', 0.5 + i, 0.25 * i)
            # the flag/type word above is the 4 octet field, the scale factor and the offset follow
        for n, t, c in self.analogs:
            b += struct.pack('>ff', 1.5, -2.0)
        for k in range(self.ndg):
            b += struct.pack('>HH', 0x0f0f, 0xffff)
        b += (struct.pack('>f', lat) + struct.pack('>f', lon) + struct.pack('>f', elev) + svc
              + struct.pack('>II', 4, 2500) + struct.pack('>HH', 1 if self.fnom50 else 0, self.cfgcnt))
        return b

    def data_size(self):
        return (2 + len(self.phasors) * (8 if self.ph_float else 4) + (8 if self.fr_float else 4)
                + len(self.analogs) * (4 if self.an_float else 2) + self.ndg * 2)

    def data(self, stat=0x0000, k=0, absent=False):
        b = struct.pack('>H', stat)
        for i in range(len(self.phasors)):
            if self.ph_float:
                b += struct.pack('>ff', 100.0 + i + k, 0.5 * i)
            elif self.polar:
                b += struct.pack('>Hh', 1000 + 10 * i + k, -32768 if absent and i == 0 else 1234 * (i + 1))
            else:
                b += struct.pack('>hh', -32768 if absent and i == 0 else 500 + i, -32768 if absent and i == 1 else 700 - i)
        if self.fr_float:
            b += struct.pack('>ff', 60.0 + 0.01 * k, 0.02)
        else:
            b += struct.pack('>hh', -35 + k, 12)
        for i in range(len(self.analogs)):
            b += struct.pack('>f', 3.5 + i) if self.an_float else struct.pack('>h', 100 * (i + 1) - 7)
        for i in range(self.ndg):
            b += struct.pack('>H', 0x0f00 | k)
        return b


def cfg_body(pmus, rate=30, timebase=1000000, cfg3=False, cont=0, **kw):
    if cfg3:
        b = struct.pack('>H', cont) + bytes([0]) + timebase.to_bytes(3, 'big') + struct.pack('>H', len(pmus))
        for p in pmus:
            b += p.cfg3(**kw)
    else:
        b = bytes([0]) + timebase.to_bytes(3, 'big') + struct.pack('>H', len(pmus))
        for p in pmus:
            b += p.cfg2()
    return b + struct.pack('>h', rate)


def main(out):
    SRC, DST = '192.0.2.50', '192.0.2.60'
    fr = []

    def u(p, sport=4713, dport=4713, src=SRC, dst=DST):
        fr.append(udp(p, sport, dport, src=src, dst=dst, ident=len(fr) + 1))

    # ------------------------------------------------ header and command frames
    u(frame(HDR, b'PMU 7 header: example station, firmware 1.0'))
    u(frame(HDR, b'\0'))
    for cmd in (0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0000, 0x0007, 0x0009, 0x0100, 0x2000):
        u(frame(CMD, struct.pack('>H', cmd), idcode=7), src=DST, dst=SRC)
    u(frame(CMD, struct.pack('>H', 8) + bytes(range(6))), src=DST, dst=SRC)          # extended frame, even
    u(frame(CMD, struct.pack('>H', 2) + b'ex'), src=DST, dst=SRC)                    # other command with data
    # ------------------------------------------------ configurations and data of every format
    configs = [
        Pmu('STATION A', 1, False, False, False, False),
        Pmu('STATION B', 2, True, True, True, True, ndg=2, fnom50=True),
        Pmu('STATION C', 3, False, True, False, True, analogs=(('A1', 0, 1), ('A2', 2, 0x800001), ('A3', 3, 9),
                                                              ('A4', 100, 7)), ndg=0),
        Pmu('STATION D', 4, True, False, True, False, phasors=(), analogs=(), ndg=0),
        Pmu('STATION E', 5, False, False, True, True, phasors=(('V1', 'V', 0xffffff), ('V2', 'V', 3), ('I1', 'A', 4)),
            analogs=(), ndg=3),
    ]
    idc = 100
    for cfg_type in (CFG1, CFG2):
        for p in configs:
            idc += 1
            u(frame(cfg_type, cfg_body([p], rate=30 if idc % 2 else -5), idcode=idc, tq=(idc % 16) | 0x40))
            if cfg_type == CFG2:
                for k in range(2):
                    u(frame(DATA, p.data(stat=(k * 0x0010) | 0x0005, k=k), idcode=idc, tq=0x03, frac=500 * (k + 1)))
                u(frame(DATA, p.data(absent=True), idcode=idc))
    # a configuration with two PMUs and the data of both
    p1, p2 = configs[0], configs[1]
    u(frame(CFG2, cfg_body([p1, p2], rate=60), idcode=200, tq=0x2f, frac=0xabcdef))
    u(frame(DATA, p1.data(stat=0x0c10) + p2.data(stat=0x00ff, k=1), idcode=200))
    u(frame(DATA, p1.data(stat=0x1000) + p2.data(stat=0x03ff, k=2), idcode=200, tq=0x0b))
    # a new CFG-2 for the same id replaces the old one: data in the new format
    u(frame(CFG2, cfg_body([configs[2]], rate=10), idcode=200))
    u(frame(DATA, configs[2].data(k=3), idcode=200))
    # time quality flags and versions
    for i, tq in enumerate((0x00, 0x80, 0x40, 0x20, 0x10, 0x0f, 0xb0, 0x5a)):
        u(frame(DATA, configs[3].data(k=i), idcode=109, tq=tq, version=1 + (i & 1)))
    # ------------------------------------------------ CFG-3
    c3 = [Pmu('PMU ONE', 11, False, False, False, False), Pmu('PMU TWO', 12, True, True, True, True, ndg=2)]
    u(frame(CFG3, cfg_body(c3, cfg3=True, svc=b'M'), idcode=300))
    u(frame(DATA, c3[0].data() + c3[1].data(k=1), idcode=300))
    # a second CFG-3 for the same id replaces the first (data rate of one frame per five seconds)
    u(frame(CFG3, cfg_body(c3, cfg3=True, svc=b'P', rate=-5), idcode=300))
    u(frame(DATA, c3[0].data(absent=True) + c3[1].data(k=2), idcode=300))
    u(frame(CFG3, cfg_body([Pmu('LONG NAMES', 13, polar=True, phasors=(('V' * 3, 'V', 1), ('I' * 3, 'A', 1),
                                                                      ('X' * 3, 'V', 1), ('Y' * 3, 'V', 1),
                                                                      ('Z' * 3, 'V', 1), ('W', 'V', 1), ('E', 'V', 1)))],
                             cfg3=True, long_names=True, lat=float('inf'), lon=float('inf'), elev=float('inf'),
                             svc=b'p'), idcode=301))
    u(frame(DATA, Pmu('LONG NAMES', 13, polar=True, phasors=(('V' * 3, 'V', 1), ('I' * 3, 'A', 1), ('X' * 3, 'V', 1),
                                                           ('Y' * 3, 'V', 1), ('Z' * 3, 'V', 1), ('W', 'V', 1),
                                                           ('E', 'V', 1))).data(absent=True), idcode=301))
    u(frame(CFG3, cfg_body([Pmu('SVC CLASS', 14, an_float=False, ph_float=True)], cfg3=True, svc=b'm', lat=0.0,
                           lon=1.0, elev=2.0), idcode=302))
    u(frame(DATA, Pmu('SVC CLASS', 14, an_float=False, ph_float=True).data(), idcode=302))
    u(frame(CFG3, cfg_body([Pmu('NO CHANNELS', 15, phasors=(), analogs=(), ndg=0)], cfg3=True, svc=b'Z'), idcode=303))
    u(frame(DATA, Pmu('NO CHANNELS', 15, phasors=(), analogs=(), ndg=0).data(), idcode=303))
    u(frame(CFG3, cfg_body([Pmu('', 16, phasors=(('', 'V', 1),), analogs=(('', 0, 0),), ndg=1)], cfg3=True), idcode=304))
    u(frame(DATA, Pmu('', 16, phasors=(('', 'V', 1),), analogs=(('', 0, 0),), ndg=1).data(), idcode=304))
    # names that are not printable ASCII (the reproducer of "Synphasor: Replace non-printable
    # bytes in channel names"): CFG-2 and CFG-3 with raw 0xff/0xfe/0xc3 octets in the names
    bad = Pmu('ST\xff\xfe\xc3(X', 17, phasors=(('V\xff\xfe\xc3(1', 'V', 1), ('I\x01\x7fA', 'A', 2)),
              analogs=(('AN\xc3(', 0, 0),), ndg=0)
    u(frame(CFG2, cfg_body([bad]), idcode=305))
    u(frame(DATA, bad.data(), idcode=305))
    u(frame(CFG3, cfg_body([bad], cfg3=True), idcode=306))
    u(frame(DATA, bad.data(), idcode=306))
    n_udp = len(fr)
    # ------------------------------------------------ TCP 4712
    t = TcpConn(40500, 4712, SRC, DST, isn_c=100, isn_s=900)
    t.handshake()
    p = configs[1]
    cfgf = frame(CFG2, cfg_body([p], rate=25), idcode=400)
    t.send(frame(HDR, b'tcp stream header'), client=True)
    t.send(cfgf + frame(DATA, p.data(k=1), idcode=400))                    # two frames in a segment
    d2 = frame(DATA, p.data(k=2), idcode=400)
    t.send(d2[:20])                                                        # a frame in two segments
    t.send(d2[20:])
    t.send(frame(DATA, p.data(k=3), idcode=400) + frame(CMD, struct.pack('>H', 1), idcode=400)[:10])
    t.send(frame(CMD, struct.pack('>H', 1), idcode=400)[10:])
    t.send(frame(CMD, struct.pack('>H', 5), idcode=400), client=False)
    tcpf = t.frames
    # Exported PDU naming the dissector (the rtacser.data hand-off)
    ep = exported_pdu('synphasor', frame(CMD, struct.pack('>H', 3), idcode=204))
    pcapng(os.path.join(out, 'synphasor-coverage.pcapng'),
           [(0, f) for f in fr] + [(0, f) for f in tcpf] + [(1, ep)], (LT_ETH, LT_EXPORTED_PDU))
    print('main capture: %d frames (1-%d UDP, %d-%d TCP, %d Exported PDU)'
          % (len(fr) + len(tcpf) + 1, n_udp, n_udp + 1, n_udp + len(tcpf), n_udp + len(tcpf) + 1))

    # ---------------------------------------------------------------- malformed
    m = []

    def mu(p, src=SRC, dst=DST):
        m.append(udp(p, 4713, 4713, src=src, dst=dst, ident=len(m) + 1))
    a = configs[0]
    mu(frame(CFG2, cfg_body([a]), idcode=500))
    mu(frame(DATA, a.data(stat=0x4000), idcode=500))                         # data error bits
    mu(frame(DATA, a.data(stat=0x8000), idcode=500))
    mu(frame(DATA, a.data(stat=0xc000), idcode=500))
    mu(frame(DATA, a.data(stat=0x2000), idcode=500))                         # PMU not synchronised
    mu(frame(DATA, a.data(stat=0xe03f), idcode=500))
    mu(frame(DATA, a.data() + b'\0\0', idcode=500))                          # size does not match the configuration
    mu(frame(DATA, a.data()[:-2], idcode=500))
    mu(frame(DATA, a.data(), idcode=501))                                    # no configuration for this id
    mu(frame(DATA, a.data(), idcode=500, bad_crc=True))                      # bad checksum
    mu(frame(CFG2, cfg_body([a]), idcode=502, bad_crc=True))
    mu(frame(HDR, b'bad crc header', bad_crc=True))
    mu(frame(CFG3, cfg_body(c3, cfg3=True), idcode=503, bad_crc=True))
    mu(frame(CMD, struct.pack('>H', 8) + bytes(range(5)), idcode=504), src=DST, dst=SRC)    # odd extended frame data
    mu(frame(DATA, a.data(), idcode=500, version=0, tq=0xff))                # unknown version, all quality bits
    mu(frame(0x7, b'\x01\x02\x03\x04'))                                      # unknown frame type
    mu(frame(6, b'\x01\x02\x03\x04\x05\x06'))
    mu(frame(CFG3, cfg_body(c3, cfg3=True, cont=3), idcode=505))              # fragmented CFG-3
    mu(frame(DATA, c3[0].data() + c3[1].data(), idcode=505))
    # configurations that are cut short (CRC valid): exceptions in the dissector
    full = cfg_body([configs[1]])
    for cut in (30, 60, 90, 140, len(full) - 5):
        mu(frame(CFG2, full[:cut], idcode=510 + cut % 7))
    full3 = cfg_body(c3, cfg3=True)
    for cut in (4, 12, 40, 60, 100, 200, len(full3) - 5):
        mu(frame(CFG3, full3[:cut], idcode=520 + cut % 11))
    mu(frame(CFG1, full[:20], idcode=530))
    mu(b'\xaa\x23\x00\x10\x00\x07' + bytes(10))                                # frame size 16 with a short body
    mu(frame(DATA, b'', idcode=1))                                             # the shortest frame
    mu(b'\xaa\x03\x00\x20' + bytes(14))                                        # size field above the data
    mu(b'\xab' + bytes(30))                                                    # not a synchrophasor frame
    mu(bytes([0xaa]) + bytes(8))                                               # shorter than a header
    pcapng(os.path.join(out, 'synphasor-coverage-malformed.pcapng'), [(0, f) for f in m], (LT_ETH,))
    print('malformed capture: %d frames' % len(m))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

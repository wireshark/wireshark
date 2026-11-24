#!/usr/bin/env python3
# Generates test/captures/asterix_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ASTERIX dissector
(packet-asterix.c).

All packets are built from scratch with struct; no captured traffic is
used. Surveillance sensors (10.0.1.10-10.0.1.13) send ASTERIX to a
display system (10.0.1.1) on UDP port 8600, and one sensor sends over
TCP port 8600.

Some records are written item by item below (a radar target report, a
system track, north markers, records for the UAP probe of categories 1
and 7). The others, one record with every item of each UAP, are built
by astgen.py, which reads packet-asterix-generated.h to find out the
items of each UAP and their structure, and makes up the octets.

Usage: mkasterix.py <output directory> [packet-asterix-generated.h]

Writes:
  asterix-coverage.pcap            the main capture (default editions)
  asterix-coverage-malformed.pcap  paths that end in an error expert
                                   info or an exception
  asterix-editions-<n>.pcap and    a record with every item of every UAP
  cfg/profiles/asterix-ed<n>/      of the n-th edition of each category,
                                   and a profile that selects those
                                   editions (coverage only)
"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))

import struct
import sys

import astgen

GENERATED = os.path.join(SRCDIR, 'epan/dissectors/packet-asterix-generated.h')
PORT = 8600
DISPLAY = (10, 0, 1, 1)
RADAR = (10, 0, 1, 10)      # mode S radar: cat 48, 34, 1, 2
TRACKER = (10, 0, 1, 11)    # tracker: cat 62, 63, 65
ADSB = (10, 0, 1, 12)       # ADS-B ground station: cat 21, 23
OTHER = (10, 0, 1, 13)      # every other category


def mac(ip):
    return b'\x02\x00\x00\x00' + bytes(ip[2:4])


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def ip(self, proto, src, dst, l4):
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, proto, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        self.frames.append(mac(dst) + mac(src) + b'\x08\x00' + ip + l4)

    def udp(self, payload, src=RADAR, sport=PORT, dst=DISPLAY, dport=PORT):
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
        ck = ip_checksum(pseudo + hdr + payload) or 0xffff
        self.ip(17, src, dst, hdr[:6] + struct.pack('>H', ck) + payload)

    def tcp(self, src, sport, dst, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        self.ip(6, src, dst, hdr + payload)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from a sensor to the display system on port 8600."""
    def __init__(self, cap, src, sport):
        self.cap, self.src, self.sport = cap, src, sport
        self.cseq, self.sseq = 1000, 9000
        cap.tcp(src, sport, DISPLAY, PORT, self.cseq, 0, 0x02)
        cap.tcp(DISPLAY, PORT, src, sport, self.sseq, self.cseq + 1, 0x12)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(src, sport, DISPLAY, PORT, self.cseq, self.sseq, 0x10)

    def send(self, *datas):
        for data in datas:
            self.cap.tcp(self.src, self.sport, DISPLAY, PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)
        self.cap.tcp(DISPLAY, PORT, self.src, self.sport, self.sseq, self.cseq, 0x10)

    def close(self):
        self.cap.tcp(self.src, self.sport, DISPLAY, PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(DISPLAY, PORT, self.src, self.sport, self.sseq, self.cseq, 0x11)
        self.sseq += 1
        self.cap.tcp(self.src, self.sport, DISPLAY, PORT, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


# --------------------------------------------------------------------------
# Hand-written items

datablock = astgen.datablock


def fspec(*frns):
    """FSPEC for the given FRNs (1-based); FX bits as needed."""
    bits = [(f - 1) + (f - 1) // 7 for f in frns]
    n = max(bits) // 8 + 1
    fs = bytearray(n)
    for b in bits:
        fs[b // 8] |= 0x80 >> (b % 8)
    for i in range(n - 1):
        fs[i] |= 1
    return bytes(fs)


def record(items):
    """items: {FRN: octets}; the record is the FSPEC and the items in FRN order."""
    return fspec(*items) + b''.join(items[f] for f in sorted(items))


def u8(v):  return struct.pack('>B', v)
def u16(v): return struct.pack('>H', v)
def s16(v): return struct.pack('>h', v)
def u24(v): return struct.pack('>I', v)[1:]
def s32(v): return struct.pack('>i', v)


def icao(text):
    """Eight characters in the 6-bit ICAO alphabet (48 bits)."""
    v = 0
    for ch in text:
        if 'A' <= ch <= 'Z':
            c = ord(ch) - ord('A') + 1
        elif ch == ' ':
            c = 0x20
        elif '0' <= ch <= '9':
            c = ord(ch)
        else:
            c = 0                   # shown as '?'
        v = (v << 6) | c
    return v.to_bytes(6, 'big')


def tod(seconds):
    return u24(round(seconds * 128))


SAC_SIC = b'\x19\x0a'       # SAC 25, SIC 10


def cat48_target(track=1234, code=0o7500, fl=350, callsign='RYR1234 ', rho=45.5, theta=123.0,
                 spec=None, extra=None):
    """A Mode S target report (category 48, edition 1.32)."""
    items = {
        1: SAC_SIC,
        2: tod(43200.5),
        # 020: TYP 5 (Mode S Roll-Call + PSR), then TST..FOEFRI, then the
        # third octet (ADSB/SCN/PAI) ends the item
        3: b'\xa1\x01\x40',
        4: u16(round(rho * 256)) + u16(round(theta / 360 * 65536)),
        5: u16(code),                       # 070: Mode-3/A, octal
        6: s16(fl * 4),                     # 090: flight level
        # 130: compound with SRL (subfield 1) and SAM (subfield 3, -70 dBm)
        7: b'\xa0' + b'\x10' + struct.pack('b', -70),
        8: b'\x4c\xa1\x23',                 # 220: aircraft address
        9: icao(callsign),                  # 240: aircraft identification
        # 250: two BDS registers (BDS 4,0 and 6,0)
        10: u8(2) + bytes(range(1, 8)) + b'\x40' + bytes(range(8, 15)) + b'\x60',
        11: u16(track),                     # 161: track number
        13: u16(round(450 / 3600 * 16384)) + u16(round(270 / 360 * 65536)),
        14: b'\x41\x00',                    # 170: two octets
        16: b'\x0f\x1a',                    # 030: warnings 7 and 13
        27: b'\x04\xde\xad\xbe',            # SP, 4 octets
    }
    if spec is not None:
        # RE (reserved expansion) with every item of the default RE edition
        items[28] = spec.encode('dissect_cat_48_ed_major_1_ed_minor_32_datafield_27_uap', 48)
    if extra:
        items.update(extra)
    return record(items)


def cat34_north_marker(sector=None):
    """Category 34: north marker (000 = 1) or sector crossing (000 = 2, 020)."""
    items = {1: SAC_SIC, 2: u8(1 if sector is None else 2), 3: tod(43200.0)}
    if sector is not None:
        items[4] = u8(round(sector / 360 * 256))
    items[5] = u16(round(4.0 * 128))         # 041: antenna rotation 4 s
    return record(items)


def cat62_track(spec, track=77):
    """A system track (category 62, edition 1.21)."""
    items = {
        1: b'\x00\x01',
        4: tod(43201.0),
        # 105: WGS-84 position, 180/2^25 degrees
        5: s32(round(46.0569 * 2**25 / 180)) + s32(round(-14.5058 * 2**25 / 180)),
        9: u16(0o1200),                    # 060: Mode 3/A
        10: b'\x00' + icao('ABC 12 9'),   # 245: target identification
        12: u16(track),                    # 040: track number
        13: b'\x00',                       # 080: track status, one octet
        # 136: measured flight level, negative (-2.5)
        17: s16(-10),
        35: b'\x02\x99',                   # SP, 2 octets
    }
    items[34] = spec.encode('dissect_cat_62_ed_major_1_ed_minor_21_datafield_33_uap', 62)
    return record(items)


# --------------------------------------------------------------------------

def default_keys(spec):
    return [k for k in spec.order if spec.default_ed[k[0]] == k[1]]


def sensor_of(cat):
    return {48: RADAR, 34: RADAR, 1: RADAR, 2: RADAR,
            62: TRACKER, 63: TRACKER, 65: TRACKER,
            21: ADSB, 23: ADSB}.get(cat, OTHER)


def cat1_rec(uap, frns):
    """Category 1 records for the UAP probe. Common to plot and track:
    010 (2 octets), 020 (extended, one octet here). Plot only: 040 at FRN 3
    (4 octets). Track only: 161 at FRN 3 (2 octets)."""
    items = {1: SAC_SIC, 2: b'\x20' if uap == 'plot' else b'\xa0'}
    if 3 in frns:
        items[3] = (u16(0x1234) + u16(0x4000)) if uap == 'plot' else u16(42)
    return record(items)


def main_capture(spec, path):
    c = Pcap()
    # 1: a radar target report with every kind of item, and a second one
    # (different track) in the same data block
    c.udp(datablock(48, [cat48_target(spec=spec),
                         cat48_target(track=1235, code=0o2000, fl=-5, callsign='DLH4U   ',
                                      rho=200.25, theta=359.5)]))
    # 2: two data blocks in one datagram: north marker and sector crossing,
    # then a target report
    c.udp(datablock(34, [cat34_north_marker(), cat34_north_marker(sector=90)]) +
          datablock(48, [cat48_target(track=7, callsign='TEST 12?')]))
    # 3: a target report with a spare bit set in 161 (warning only)
    c.udp(datablock(48, [cat48_target(track=0x8000 | 99)]))
    # 4: a system track with a five octet FSPEC (SP and RE at FRN 34, 35)
    c.udp(datablock(62, [cat62_track(spec)]), src=TRACKER)
    # 5: a system track with only 380 (aircraft derived data), whose
    # subfield 12 starts at octet 7 of the datagram
    c.udp(datablock(62, [record({11: b'\x01\x10' + b'\x00\x00'})]), src=TRACKER)
    # 6-8: the UAP probe. 6: two category 1 records that are the same as
    # plot and as track: four interpretations. 7: a plot and a track
    # record: three interpretations (plot, track; and the plot record read
    # as a six octet track, its last two octets as a plot or a track
    # record, then the track). 8: category 7 uplink, one interpretation.
    c.udp(datablock(1, [cat1_rec('plot', ()), cat1_rec('plot', ())]))
    c.udp(datablock(1, [cat1_rec('plot', (3,)), cat1_rec('track', (3,))]))
    up = spec.record((7, '1.12', 'uplink'))
    c.udp(datablock(7, [up]))
    # 10-: one datagram per category (default edition and every UAP), with
    # a record that has every item
    for key in default_keys(spec):
        c.udp(datablock(key[0], [spec.record(key)]), src=sensor_of(key[0]))

    # TCP: one sensor sends data blocks over TCP
    s = TcpStream(c, OTHER, 41000)
    blocks = [datablock(48, [cat48_target(track=500 + i)]) for i in range(4)]
    s.send(blocks[0] + datablock(34, [cat34_north_marker()]))   # two in one segment
    s.send(*split(blocks[1], 20, 60))                           # over three segments
    s.send(*split(blocks[2], 2))                                # split in the header
    s.send(blocks[3])
    s.close()
    c.write(path)
    return c


def malformed_capture(spec, path):
    c = Pcap()
    good = datablock(48, [cat48_target()])
    # data block checks: fewer than 4 octets left, a length under 4, a
    # length past the datagram
    c.udp(good + b'\x30\x00')
    c.udp(good + b'\x30\x00\x02\x00')
    c.udp(good + b'\x30\x01\x00\x00\x00')
    # unknown category
    c.udp(datablock(99, [b'\x80\x01\x02']))
    # FSPEC with a bit set for a spare FRN (62 FRN 2), and one that goes on
    # past the last FRN (category 2 has 14)
    c.udp(datablock(62, [record({1: b'\x00\x01', 2: b''})]))
    c.udp(datablock(2, [b'\x81\x01\x01\x00' + SAC_SIC]))
    # extended item without an end (48 020, FX set in every octet)
    c.udp(datablock(48, [record({1: SAC_SIC, 3: b'\xa1\x01\x41\x01\x01\x01'})]))
    # compound with an FSPEC longer than its subfields allow (48 130)
    c.udp(datablock(48, [record({1: SAC_SIC, 7: b'\x81\x80\x10\x10'})]))
    # a record that runs past the end of its data block into the next:
    # 010 takes the first octet of the next data block as its SIC
    c.udp(b'\x30\x00\x05\x80\x19' + b'\x30\x00\x06\x80\x19\x0a')
    rec = cat48_target()
    # a record cut by the end of the datagram (exception)
    c.udp(struct.pack('>BH', 48, 20) + rec[:17])
    # the UAP probe: no possible interpretation (a spare FRN in both UAPs),
    # more than 100 interpretations (7 ambiguous records, 128), deeper than
    # 15 records, and a record cut by the end of the datagram (caught
    # while probing)
    c.udp(datablock(1, [b'\x01\x01\x02' + SAC_SIC]))
    c.udp(datablock(1, [cat1_rec('plot', ())] * 7))
    c.udp(datablock(1, [cat1_rec('plot', (3,))] * 16))
    c.udp(struct.pack('>BH', 1, 12) + cat1_rec('plot', (3,)) + cat1_rec('plot', (3,))[:1])
    # TCP: a data block length under 3 (asks for more data), then data
    s = TcpStream(c, OTHER, 41001)
    s.send(good + b'\x30\x00\x01\x00')
    s.close()
    c.write(path)


def editions_captures(spec, out, cfg):
    """For coverage of the edition preferences only: capture n holds a
    record with every item of each UAP of the n-th edition of every
    category, and profile asterix-ed<n> selects those editions."""
    rounds = max(len(v) for v in spec.editions.values())
    for n in range(rounds):
        c = Pcap()
        prefs = []
        for cat, eds in sorted(spec.re_editions.items()):
            ed = eds[min(n, len(eds) - 1)]
            spec.re_edition[cat] = ed
            prefs.append('asterix.cat_%d_re: cat_%d_ed_%s' % (cat, cat, ed.replace('.', '_')))
        for cat, eds in sorted(spec.editions.items()):
            ed = eds[min(n, len(eds) - 1)]
            enum = 'cat_%d_ed_%s' % (cat, ed.replace('.', '_'))
            prefs.append('asterix.cat_%d: %s' % (cat, enum))
            for key in spec.order:
                if key[0] == cat and key[1] == ed:
                    c.udp(datablock(cat, [spec.record(key)]), src=sensor_of(cat))
        c.write(os.path.join(out, 'asterix-editions-%d.pcap' % n))
        prof = os.path.join(cfg, 'profiles', 'asterix-ed%d' % n)
        os.makedirs(prof, exist_ok=True)
        with open(os.path.join(prof, 'preferences'), 'w') as fh:
            fh.write('\n'.join(prefs) + '\n')
    return rounds


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    spec = astgen.Spec(sys.argv[2] if len(sys.argv) > 2 else GENERATED)
    main_capture(spec, os.path.join(out, 'asterix-coverage.pcap'))
    malformed_capture(spec, os.path.join(out, 'asterix-coverage-malformed.pcap'))
    here = os.path.dirname(os.path.abspath(__file__))
    editions_captures(spec, out, os.path.join(out, 'cfg'))


if __name__ == '__main__':
    main()

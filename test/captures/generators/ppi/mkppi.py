#!/usr/bin/env python3
# Generates test/captures/ppi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PPI coverage captures.
Usage: mkppi.py <outdir>.  Writes ppi-coverage.pcap and
ppi-coverage-malformed.pcap (DLT 192, LINKTYPE_PPI).  Every packet is
built with struct; nothing comes from a real network."""
import struct
import sys
import zlib
import os

LT = 192

def pcap(fn, pkts, snaplen=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, LT))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def field(t, data):
    return struct.pack('<HH', t, len(data)) + data

def ppi(fields, payload, dlt=105, flags=0, length=None, pad_last=0):
    body = b''.join(fields)
    ln = 8 + len(body) if length is None else length
    return struct.pack('<BBHI', 0, flags, ln, dlt) + body + b'\0' * pad_last + payload

# 802.11-Common (20 octets of data)
def common(tsft=0x1122334455, flags=0, rate=2, freq=2412, cflags=0x00a0,
           hop=0, pat=0, sig=-60, noise=-90):
    return field(2, struct.pack('<QHHHHBBbb', tsft, flags, rate, freq, cflags, hop, pat, sig, noise))

# 802.11n MAC extensions (12 octets of data)
def mac(flags=0, ampdu=0, delims=0):
    return field(3, struct.pack('<IIB3s', flags, ampdu, delims, b'\0\0\0'))

# 802.11n MAC+PHY extensions (48 octets of data)
def macphy(flags=0, ampdu=0, delims=0, mcs=7, ness=1, rssi=(50, 40, 41, 42, 43, 30, 31, 32, 33),
           extfreq=2417, extflags=0x0080, dbm=(-50, -90, -51, -91, -52, -92, -53, -93),
           evm=(10, 20, 30, 40)):
    d = struct.pack('<IIB', flags, ampdu, delims)
    d += struct.pack('<BB', mcs, ness) + bytes(rssi)
    d += struct.pack('<HH', extfreq, extflags) + struct.pack('<8b', *dbm)
    d += struct.pack('<4I', *evm)
    assert len(d) == 48
    return field(4, d)

def dot11(seq=1, fcs=False, ndata=28):
    # Data frame, To DS, LLC/SNAP ARP payload
    h = struct.pack('<BBH6s6s6sH', 0x08, 0x01, 0x013a, bytes.fromhex('020000000001'),
                    bytes.fromhex('020000000002'), bytes.fromhex('020000000003'), seq << 4)
    body = h + bytes.fromhex('aaaa03000000' '88b5') + bytes([seq & 0xff]) * ndata
    if fcs:
        body += struct.pack('<I', zlib.crc32(body) & 0xffffffff)
    return body

def eth(n=40):
    return bytes.fromhex('020000000001' '020000000002' '88b5') + b'ppi-payload' + bytes(n)

F_FCS, F_MS, F_BADFCS, F_PHYERR = 1, 2, 4, 8
CH_TURBO, CH_CCK, CH_OFDM, CH_2G, CH_5G, CH_PASSIVE, CH_DYN, CH_GFSK = \
    0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800

def u32pad(b):
    return b + b'\0' * ((-len(b)) % 4)

# Geolocation tags (the separate ppi_gps/vector/sensor/antenna dissectors
# have their own coverage capture; one small tag of each here)
def geotag(t, version, present, body):
    return field(t, struct.pack('<BBHI', version, 0, 8 + len(body), present) + body)

good = []
n = 0
def add(p):
    good.append(p)

# 1-8: the channel flag combinations of 802.11-Common
add(ppi([common(cflags=CH_2G | CH_GFSK, hop=3, pat=7, flags=F_MS)], dot11()))        # 1 FHSS, TSFT in ms
add(ppi([common(cflags=CH_2G, flags=F_FCS, rate=2)], dot11(2, fcs=True)))             # 2 DSSS, FCS present
add(ppi([common(cflags=CH_5G | CH_OFDM, freq=5180, rate=12, flags=F_FCS | F_BADFCS | F_PHYERR)],
        dot11(3, fcs=True)))                                                          # 3 11a, bad FCS, PHY error
add(ppi([common(cflags=CH_2G | CH_CCK, rate=22)], dot11(4)))                          # 4 11b
add(ppi([common(cflags=CH_2G | CH_OFDM, rate=12)], dot11(5)))                         # 5 pure g, OFDM rate
add(ppi([common(cflags=CH_2G | CH_OFDM, rate=2)], dot11(6)))                          # 6 pure g, DSSS rate -> 11b
add(ppi([common(cflags=CH_2G | CH_DYN, rate=48)], dot11(7)))                          # 7 g (dynamic)
add(ppi([common(cflags=CH_5G | CH_OFDM | CH_TURBO, freq=5200, rate=12)], dot11(8)))   # 8 108a (dynamic turbo)
add(ppi([common(cflags=CH_2G | CH_OFDM | CH_TURBO, rate=12)], dot11(9)))              # 9 108 pure g (super g)
# 10-14: no usable channel flags, the PHY comes from the rate
add(ppi([common(cflags=0, rate=2, freq=2412)], dot11(10)))                            # 10 DSSS rate -> b
add(ppi([common(cflags=0, rate=12, freq=2412)], dot11(11)))                           # 11 OFDM rate on 2.4 GHz -> g
add(ppi([common(cflags=0, rate=12, freq=5180)], dot11(12)))                           # 12 OFDM rate on 5 GHz -> a
add(ppi([common(cflags=0, rate=12, freq=0)], dot11(13)))                              # 13 OFDM rate, no frequency
add(ppi([common(tsft=0, cflags=CH_2G | CH_CCK, rate=0, freq=0, sig=-128, noise=0)], dot11(14)))  # 14 every "invalid" value
add(ppi([common(cflags=CH_2G, rate=2, freq=2484, sig=0, noise=-128)], dot11(15)))     # 15 signal 0, valid noise absent
# 16-19: 11n extensions
add(ppi([common(cflags=CH_2G | CH_OFDM, rate=12),
         mac(flags=0x0f, ampdu=0, delims=0)], dot11(16)))                             # 16 MAC ext, greenfield/HT40/SGI/dup
add(ppi([macphy(flags=0x02)], dot11(17)))                                             # 17 MAC+PHY
add(ppi([common(cflags=CH_2G, rate=2), macphy(mcs=255, ness=0, rssi=(255,) * 9,
         extfreq=0, extflags=0x0f40 & 0xffff, dbm=(-128,) * 8, evm=(0, 0, 0, 0))],
        dot11(18)))                                                                   # 18 MAC+PHY, everything invalid
add(ppi([common(cflags=CH_5G | CH_OFDM, freq=5745, rate=12), macphy(flags=0x04, extfreq=5765,
         extflags=CH_5G | CH_OFDM | CH_TURBO | CH_PASSIVE | CH_DYN | CH_GFSK | CH_CCK)],
        dot11(19, fcs=False)))                                                        # 19 ext channel flags
# 20: aggregation and 802.3 extensions
add(ppi([field(8, struct.pack('<I', 0x12345678))], dot11(20)))                        # 20 Aggregation Extension
add(ppi([field(9, struct.pack('<II', 1, 0x0f))], eth(), dlt=1))                       # 21 802.3 Extension, Ethernet payload
add(ppi([field(9, struct.pack('<II', 0, 0))], eth(), dlt=1))                          # 22 802.3 Extension, all clear
# 23-28: tags without their own dissector
add(ppi([field(5, b'\x01\x02\x03\x04')], dot11(23)))                                  # 23 Spectrum-Map
add(ppi([field(6, b'process-info')], dot11(24)))                                      # 24 Process-Info
add(ppi([field(7, b'capture-info')], dot11(25)))                                      # 25 Capture-Info
add(ppi([field(30000, b'intel'), field(30001, b'thaga'), field(100, b'rsvd'),
         field(0xC017, b'fluke'), field(0xCACE, b'cace')], dot11(26)))                # 26 private and reserved types
# 27: the geolocation tags (each as its own field)
add(ppi([geotag(30002, 2, 0x00000006, struct.pack('<II', 1800000000, 1800000000)),
         geotag(30003, 2, 0x00000001, struct.pack('<I', 1)),
         geotag(30004, 1, 0x00000003, struct.pack('<HB', 1, 0) + b'\0'),
         geotag(30005, 1, 0x00000003, struct.pack('<IB', 1, 5) + b'\0\0\0')], dot11(27)))
# 28: the alignment flag: fields start on a 32 bit boundary, the last odd sized field is padded
add(ppi([common(cflags=CH_2G, rate=2), field(6, b'odd')], dot11(28), flags=1, pad_last=1))
# 29: header without fields
add(ppi([], dot11(29)))
# 30: payload of another link type, Ethernet
add(ppi([], eth(), dlt=1))
# 31: a PPI header inside a PPI header (LINKTYPE_PPI inside)
inner = ppi([common(cflags=CH_2G | CH_CCK, rate=22)], dot11(31))
add(ppi([], inner, dlt=192))

# Aggregated MPDUs (A-MPDU), same A-MPDU id across frames.
AGG, MORE, CRCERR = 0x10, 0x20, 0x40
def mpdu(ampdu, flags, seq, n=40, phy=False):
    f = macphy(flags=flags, ampdu=ampdu, delims=2) if phy else mac(flags=flags, ampdu=ampdu, delims=2)
    return ppi([common(cflags=CH_2G | CH_OFDM, rate=12), f], dot11(seq, ndata=n))
add(mpdu(0x100, AGG | MORE, 40))                 # 32 first MPDU of aggregate 0x100
add(mpdu(0x200, AGG | MORE, 50, phy=True))       # 33 first MPDU of 0x200, interleaved
add(mpdu(0x100, AGG | MORE, 41, n=60))           # 34
add(mpdu(0x100, AGG, 42, n=30))                  # 35 last of 0x100: lists the fragments, dissects the MPDUs
add(mpdu(0x200, AGG | MORE | CRCERR, 51, phy=True))  # 36 delimiter CRC error ends 0x200
add(mpdu(0x300, AGG, 60))                        # 37 an aggregate of one MPDU
# the quadratic-tree reproducer: one aggregate of 40 MPDUs with the same id
for i in range(39):
    add(mpdu(0x400, AGG | MORE, 70 + i % 8, n=8))
add(mpdu(0x400, AGG, 80, n=8))

# an aggregate whose last MPDU is empty: the fragment list ends at an earlier frame
add(mpdu(0x600, AGG | MORE, 90))
add(ppi([common(cflags=CH_2G | CH_OFDM, rate=12), mac(flags=AGG, ampdu=0x600, delims=0)], b''))

# Malformed and error paths
bad = []
def badd(p):
    bad.append(p)
# header length below 8
badd(struct.pack('<BBHI', 0, 0, 4, 105) + dot11(1))
badd(struct.pack('<BBHI', 0, 0, 0, 105))
# field longer than the remaining header
badd(struct.pack('<BBHI', 0, 0, 8 + 8, 105) + struct.pack('<HH', 2, 100) + b'\0' * 4 + dot11(2))
# fields with the wrong length for their type
badd(ppi([field(2, b'\0' * 8)], dot11(3)))
badd(ppi([field(3, b'\0' * 4)], dot11(4)))
badd(ppi([field(4, b'\0' * 12)], dot11(5)))
badd(ppi([field(8, b'\0' * 8)], dot11(6)))
badd(ppi([field(9, b'\0' * 4)], dot11(7)))
# A-MPDU longer than the maximum of 65535 octets
for i in range(18):
    badd(mpdu(0x500, AGG | MORE, i, n=4000))
# a field that runs past the end of the packet
badd(struct.pack('<BBHI', 0, 0, 8 + 24, 105) + struct.pack('<HH', 2, 20) + b'\0' * 8)
# a PPI header whose payload is LINKTYPE_PPI, nested too deep
p = dot11(1)
for i in range(8):
    p = ppi([], p, dlt=192 if i else 105)
badd(p)
# geolocation tags with errors (also in the geolocation capture)
badd(ppi([geotag(30002, 2, 0x80000001, struct.pack('<I', 1) * 2)], dot11(9)))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ppi-coverage.pcap'), good)
    pcap(os.path.join(out, 'ppi-coverage-malformed.pcap'), bad)

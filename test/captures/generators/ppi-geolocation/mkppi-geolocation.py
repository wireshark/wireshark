#!/usr/bin/env python3
# Generates test/captures/ppi-geolocation_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the PPI-GEOLOCATION coverage captures (GPS, Vector, Sensor and
Antenna tags, and the common conversion routines).
Usage: mkppi-geolocation.py <outdir>.  Writes ppi-geolocation-coverage.pcap
and ppi-geolocation-coverage-malformed.pcap (DLT 192, LINKTYPE_PPI).  Every
packet is built with struct; nothing comes from a real network."""
import struct
import sys
import os

LT = 192

def pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LT))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
            f.write(p)

def eth():
    return bytes.fromhex('020000000001' '020000000002' '88b5') + b'ppi-geolocation' + bytes(20)

def ppi(fields):
    body = b''.join(fields)
    return struct.pack('<BBHI', 0, 0, 8 + len(body), 1) + body + eth()

def tag(ptype, version, present, body, length=None, pad=0):
    ln = 8 + len(body) if length is None else length
    data = struct.pack('<BBHI', version, pad, ln, present) + body
    return struct.pack('<HH', ptype, len(data)) + data

GPS, VECTOR, SENSOR, ANTENNA = 30002, 30003, 30004, 30005

def s(text, n=32):
    return text.encode().ljust(n, b'\0')[:n]

def fx37(deg):   # 3.7 fixed point latitude / longitude
    return int(round((deg + 180) * 1e7))
def fx64(v):     # 6.4 fixed point
    return int(round((v + 180000) * 1e4)) & 0xffffffff
def fx36(v):     # 3.6 fixed point
    return int(round(v * 1e6))

good = []
bad = []
def add(*fields):
    good.append(ppi(list(fields)))
def badd(*fields):
    bad.append(ppi(list(fields)))

# ---- GPS (30002) -----------------------------------------------------
G_FLAGS, G_LAT, G_LON, G_ALT, G_ALTG, G_TIME, G_FRAC, G_EPH, G_EPV, G_EPT, G_DESC, G_APPID, G_APPDATA = \
    [1 << b for b in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 28, 29, 30)]
gps_all = (G_FLAGS | G_LAT | G_LON | G_ALT | G_ALTG | G_TIME | G_FRAC | G_EPH | G_EPV | G_EPT |
           G_DESC | G_APPID | G_APPDATA)
gps_body = (struct.pack('<I', 0x1ff) +                         # every GPS flag
            struct.pack('<IIII', fx37(59.3293), fx37(18.0686), fx64(28.5), fx64(2.25)) +
            struct.pack('<II', 1700000000, 123456789) +        # time and fractional time (one 8 octet item)
            struct.pack('<III', fx36(1.5), fx36(2.5), 5000000) +
            s('gps description') + struct.pack('<I', 0xcafe) + bytes(range(60)))
add(tag(GPS, 2, gps_all, gps_body))                              # 1 every item, 144 octets, v2
add(tag(GPS, 1, gps_all, gps_body))                              # 2 the same with version 1
add(tag(GPS, 2, G_FLAGS | G_LAT | G_LON | G_ALT, struct.pack('<I', 0x03) +
        struct.pack('<III', fx37(-33.8688), fx37(151.2093), fx64(-12.5))))  # 3 a fix without time, one flags
add(tag(GPS, 2, G_TIME, struct.pack('<I', 1700000001)))          # 4 time without fractional time
add(tag(GPS, 2, G_FRAC, struct.pack('<I', 500000000)))           # 5 fractional time without time
add(tag(GPS, 2, G_ALTG | G_EPH | G_EPV | G_EPT, struct.pack('<IIII', fx64(0), fx36(0), fx36(0), 0)))  # 6
add(tag(GPS, 2, G_DESC | G_APPID, s('only a description') + struct.pack('<I', 7)))  # 7
add(tag(GPS, 2, 0, b''))                                         # 8 no item present

# ---- Vector (30003) --------------------------------------------------
V_FLAGS, V_CHARS, V_RX, V_RY, V_RZ = [1 << b for b in range(5)]
V_OA, V_OB, V_OC = [1 << b for b in (5, 6, 7)]       # v1 off r f u / v2 off x y z
V_VR, V_VF, V_VU, V_VT, V_AR, V_AF, V_AU, V_AT = [1 << b for b in range(8, 16)]
V_ER, V_EO, V_EV, V_EA = [1 << b for b in range(16, 20)]
V_DESC, V_APPID, V_APPDATA = [1 << b for b in (28, 29, 30)]
def f(n, v=1.0):
    return struct.pack('<I', fx64(v * n)) * 1
vec1_present = V_FLAGS | V_CHARS | V_RX | V_RY | V_RZ | V_OA | V_OB | V_OC | V_VR | V_VF | V_VU | V_VT | \
    V_AR | V_AF | V_AU | V_AT | V_ER | V_EO | V_EV | V_EA | V_DESC | V_APPID | V_APPDATA
vec1_body = (struct.pack('<II', 0x07, 0x1f1f) +
             struct.pack('<III', fx36(10.5), fx36(20.5), fx36(30.5)) +
             struct.pack('<IIIIIIIIIIII', *[fx64(i + 0.5) for i in range(12)]) +
             struct.pack('<IIII', fx36(1.0), fx64(1.0), fx64(2.0), fx64(3.0)) +
             s('vector v1') + struct.pack('<I', 5) + bytes(range(60)))
add(tag(VECTOR, 1, vec1_present, vec1_body))                      # 9 every item, version 1, flags 7
add(tag(VECTOR, 1, V_FLAGS | V_CHARS, struct.pack('<II', 0x00, 0x1f1f ^ 0x1f1f)))  # 10 v1 flags and chars clear
vec2_present = V_FLAGS | V_CHARS | V_RX | V_RY | V_RZ | V_OA | V_OB | V_OC | V_ER | V_EO | V_DESC | V_APPID | V_APPDATA
def vec2_body(flags, chars):
    return (struct.pack('<II', flags, chars) +
            struct.pack('<III', fx36(1.5), fx36(2.5), fx36(3.5)) +
            struct.pack('<III', fx64(4.0), fx64(5.0), fx64(6.0)) +
            struct.pack('<II', fx36(0.5), fx64(0.25)) +
            s('vector v2') + struct.pack('<I', 6) + bytes(range(60)))
for flags in (0x1, 0x0, 0x3, 0x5, 0x7):                           # 11-15 every RelativeTo value, forward on/off
    add(tag(VECTOR, 2, vec2_present, vec2_body(flags, 0x1f1f)))
add(tag(VECTOR, 2, V_CHARS | V_RX, struct.pack('<II', 0x1f, fx36(5))))        # 16 chars without flags
add(tag(VECTOR, 2, V_FLAGS | V_OA, struct.pack('<II', 0x2, fx64(1))))         # 17 flags without chars
add(tag(VECTOR, 2, V_EO, struct.pack('<I', fx64(1))))                          # 18 error only
add(tag(VECTOR, 3, 0, b'unknown version data'))                                # 19 unknown version: data only

# ---- Sensor (30004) --------------------------------------------------
S_TYPE, S_SCALE, S_X, S_Y, S_Z, S_T, S_E = [1 << b for b in range(7)]
S_DESC, S_APPID, S_APPDATA = [1 << b for b in (28, 29, 30)]
sens_all = S_TYPE | S_SCALE | S_X | S_Y | S_Z | S_T | S_E | S_DESC | S_APPID | S_APPDATA
def sens_body(t, scale):
    return (struct.pack('<Hb', t, scale) + struct.pack('<IIIII', fx64(1), fx64(2), fx64(3), fx64(4), fx64(5)) +
            s('sensor') + struct.pack('<I', 9) + bytes(range(60)))
for t, scale, ver in ((0, 0, 1), (1, 1, 2), (2, -1, 1), (3, 2, 2), (100, 0, 1), (101, -2, 1),
                      (1000, 0, 2), (1001, 0, 1), (1002, 0, 2), (2000, 0, 1), (2001, 0, 2), (5, 0, 1)):
    add(tag(SENSOR, ver, sens_all, sens_body(t, scale)))          # 20-31 every sensor type, 127 octets
add(tag(SENSOR, 1, S_X | S_T, struct.pack('<II', fx64(7), fx64(8))))            # 32 values without the type
add(tag(SENSOR, 1, S_TYPE | S_E, struct.pack('<HI', 1, fx64(9))))               # 33 type and error only

# ---- Antenna (30005) -------------------------------------------------
A_FLAGS, A_GAIN, A_HBW, A_VBW, A_PGAIN, A_BEAM = [1 << b for b in range(6)]
A_SERIAL, A_MODEL, A_DESC, A_APPID, A_APPDATA = [1 << b for b in (26, 27, 28, 29, 30)]
ant_all = A_FLAGS | A_GAIN | A_HBW | A_VBW | A_PGAIN | A_BEAM | A_SERIAL | A_MODEL | A_DESC | A_APPID | A_APPDATA
def ant_body(flags):
    return (struct.pack('<IB', flags, 12) + struct.pack('<III', fx36(60.5), fx36(30.5), fx36(3.25)) +
            struct.pack('<H', 4) + s('SN-1234') + s('model x') + s('antenna') +
            struct.pack('<I', 11) + bytes(range(60)))
add(tag(ANTENNA, 1, ant_all, ant_body(0xffffffff)))              # 34 every item and every flag, 187 octets
add(tag(ANTENNA, 2, ant_all, ant_body(0)))                       # 35 no flag set, version 2
add(tag(ANTENNA, 1, ant_all, ant_body(0x5)))                     # 36
add(tag(ANTENNA, 1, A_GAIN | A_BEAM, struct.pack('<BH', 3, 1)))  # 37 gain and beam id only
# all four tags in one PPI header
add(tag(GPS, 2, G_LAT | G_LON, struct.pack('<II', fx37(1), fx37(2))),
    tag(VECTOR, 2, V_RX, struct.pack('<I', fx36(1))),
    tag(SENSOR, 1, S_TYPE | S_X, struct.pack('<HI', 1, fx64(1))),
    tag(ANTENNA, 1, A_GAIN, struct.pack('<B', 2)))                       # 38

# version 1 vector with rotations and offsets relative to the forward direction and the current position
add(tag(VECTOR, 1, V_FLAGS | V_RX | V_RY | V_RZ | V_OA | V_OB | V_OC,
        struct.pack('<I', 0) + struct.pack('<III', fx36(1.5), fx36(2.5), fx36(3.5)) +
        struct.pack('<III', fx64(1.0), fx64(2.0), fx64(3.0))))                  # 39

# ---- Malformed and error paths ----------------------------------------
# unknown version
badd(tag(GPS, 3, G_LAT, struct.pack('<I', fx37(1))))
badd(tag(SENSOR, 3, S_X, struct.pack('<I', fx64(1))))
badd(tag(ANTENNA, 3, A_GAIN, struct.pack('<B', 1)))
# length field below 8
for t in (GPS, VECTOR, SENSOR, ANTENNA):
    badd(tag(t, 1 if t != GPS else 2, 1, b'\0' * 4, length=4))
    badd(tag(t, 2, 1, b'\0' * 4, length=0))
# length field above the maximum
badd(tag(GPS, 2, G_LAT, struct.pack('<I', 1), length=145))
badd(tag(VECTOR, 2, V_RX, struct.pack('<I', 1), length=145))
badd(tag(SENSOR, 1, S_X, struct.pack('<I', 1), length=128))
badd(tag(ANTENNA, 1, A_GAIN, struct.pack('<B', 1), length=188))
# unknown present bits (bit 10 and the extension bit 31)
badd(tag(GPS, 2, 1 << 10, struct.pack('<I', 1)))
badd(tag(GPS, 2, G_LAT | (1 << 31), struct.pack('<II', fx37(1), 1)))
badd(tag(VECTOR, 1, V_RX | (1 << 25), struct.pack('<II', 1, 1)))
badd(tag(VECTOR, 2, V_RX | (1 << 31), struct.pack('<II', 1, 1)))
badd(tag(SENSOR, 1, S_X | (1 << 10), struct.pack('<II', 1, 1)))
badd(tag(ANTENNA, 1, A_GAIN | (1 << 7), struct.pack('<BI', 1, 1)))
# present bits claiming more than the tag holds: each item is skipped
for t, v, allbits in ((GPS, 2, gps_all), (VECTOR, 1, vec1_present), (VECTOR, 2, vec2_present),
                      (SENSOR, 1, sens_all), (ANTENNA, 1, ant_all)):
    badd(tag(t, v, allbits, b''))
    for n in (1, 2, 3, 7, 31, 59):
        badd(tag(t, v, allbits, bytes(n)))
# GPS time truncated to four octets with the fractional time present
badd(tag(GPS, 2, G_TIME | G_FRAC, struct.pack('<I', 1)))
# a tag shorter than its field header
badd(struct.pack('<HH', GPS, 2) + b'\x02\x00')
badd(struct.pack('<HH', VECTOR, 1) + b'\x02')

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ppi-geolocation-coverage.pcap'), good)
    pcap(os.path.join(out, 'ppi-geolocation-coverage-malformed.pcap'), bad)

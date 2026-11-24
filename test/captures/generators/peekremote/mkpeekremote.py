#!/usr/bin/env python3
# Generates test/captures/peekremote_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-peekremote.c. usage: mkpeekremote.py <outdir>
#
# OmniPeek remote capture over UDP (port 5000, which the tapa dissector also
# claims, so it needs Decode As udp.port==5000,peekremote; plus the heuristic on
# any other UDP port for the magic number header): the legacy 20 byte header (version
# 0), the new header version 2 (55 bytes), and version 3 (radiotap).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import zlib
from lib import gz, ipv4, udp, udp6, udp_payload, write_pcap

out = sys.argv[1]

# --- 802.11 frames with an FCS
def fcs(b): return b + struct.pack('<I', zlib.crc32(b) & 0xffffffff)
def mac(n): return bytes((0x02, 0, 0, 0, 0, n))
def ie(i, d): return bytes((i, len(d))) + d
def beacon(seq=1, ssid=b'peek'):
    body = struct.pack('<QHH', 123456789, 100, 0x0401) + ie(0, ssid) + ie(1, b'\x82\x84\x8b\x96') + ie(3, b'\x06')
    return fcs(struct.pack('<HH', 0x0080, 0) + b'\xff' * 6 + mac(1) + mac(1) + struct.pack('<H', seq << 4) + body)
def probe_req(seq=2):
    return fcs(struct.pack('<HH', 0x0040, 0) + b'\xff' * 6 + mac(2) + b'\xff' * 6 + struct.pack('<H', seq << 4) + ie(0, b'') + ie(1, b'\x02\x04'))
def ack():
    return fcs(struct.pack('<HH', 0x00d4, 0) + mac(2))
def qos_data(seq=3, payload=None):
    payload = payload or (b'\xaa\xaa\x03\0\0\0\x08\x00' + ipv4(17, udp_payload(31111, 32222, b'wifi')))
    return fcs(struct.pack('<HH', 0x0288, 44) + mac(1) + mac(2) + mac(3) + struct.pack('<H', seq << 4) + b'\x00\x00' + payload)
def data_frame(seq=4):
    return fcs(struct.pack('<HH', 0x0208, 44) + mac(1) + mac(2) + mac(3) + struct.pack('<H', seq << 4) + b'\xaa\xaa\x03\0\0\0\x08\x00' + ipv4(17, udp_payload(31001, 31002, b'plain data')))

FRAMES80211 = [beacon(), probe_req(), ack(), qos_data(), data_frame()]

# --- legacy header (version 0): 20 bytes
def legacy(frame, sig=-60, noise=-90, speed=12, channel=6, sigp=80, noisep=10, flags=0, status=0, ts=0x0102030405060708, plen=None):
    plen = len(frame) if plen is None else plen
    return struct.pack('>bbHHBBQBBBB', sig, noise, plen, plen, flags, status, ts, speed, channel, sigp, noisep) + frame

# --- new header (version 2, 55 bytes)
EXT_20L, EXT_20U, EXT_40, EXT_HGI, EXT_FGI = 1, 2, 4, 8, 0x10
EXT_AMPDU, EXT_AMSDU, EXT_AC, EXT_MCSUSED, EXT_80, EXT_SP = 0x20, 0x40, 0x80, 0x100, 0x200, 0x400
EXT_HE, EXT_160, EXT_EHT, EXT_320, EXT_QGI = 0x20000, 0x40000, 0x80000, 0x100000, 0x200000
def nss(n): return (n - 1) << 14
def v2(frame, extflags=0, mcs=7, channel=6, freq=2437, band=0, sigp=70, noisep=5, sig=-55, noise=-92,
       sigs=(-56, -57, -58, -59), noises=(-91, -92, -93, -94), flags=0, status=0, ts=0x1122334455667788,
       typ=0, hsize=55, ver=2):
    h = struct.pack('>IBI', 0x00ffabcd, ver, hsize)
    h += struct.pack('>IHHIII', typ, mcs, channel, freq, band, extflags)
    h += struct.pack('>BBbb', sigp, noisep, sig, noise) + struct.pack('>bbbb', *sigs) + struct.pack('>bbbb', *noises)
    h += struct.pack('>HHBBQ', len(frame), len(frame), flags, status, ts)
    return h + frame

# --- version 3: magic, version, header size 13, type, then radiotap
def radiotap_flags(frame, flags=0x10):
    return struct.pack('<BBHIB', 0, 0, 9, 2, flags) + frame
def v3(frame, hsize=13, typ=0, ver=3):
    return struct.pack('>IBII', 0x00ffabcd, ver, hsize, typ) + radiotap_flags(frame)

pkts = []   # (dport, payload)
def P(payload, dport=5000): pkts.append((dport, payload))

# legacy header on UDP 5000: DSSS (11b), OFDM on a b/g channel (11g) and an a
# channel (11a), a rate that is neither, the 802.11 frame kinds, the flags and status bits
for rate in (2, 4, 11, 22):
    P(legacy(beacon(), speed=rate, channel=1))
for rate in (12, 18, 24, 36, 48, 72, 96, 108):
    P(legacy(qos_data(), speed=rate, channel=11))
P(legacy(beacon(), speed=12, channel=36))
P(legacy(probe_req(), speed=108, channel=149, sigp=100))
P(legacy(ack(), speed=0, channel=6))
P(legacy(data_frame(), speed=200, channel=14))
P(legacy(beacon(), speed=12, channel=6, flags=0x01))            # control frame flag
P(legacy(beacon(), speed=12, channel=6, flags=0x02))            # CRC error
P(legacy(beacon(), speed=12, channel=6, flags=0x04))            # frame error
P(legacy(beacon(), speed=12, channel=1, flags=0x08))            # 6GHz band valid, not 6GHz (2.4 GHz channel 1)
P(legacy(beacon(), speed=12, channel=1, flags=0x18))            # 6GHz band valid and 6GHz
P(legacy(beacon(), speed=12, channel=37, flags=0x18))           # 6GHz channel 37
P(legacy(beacon(), speed=12, channel=36, flags=0x08))
P(legacy(beacon(), speed=12, channel=6, flags=0xe0))            # reserved flag bits
P(legacy(beacon(), status=0x01))                                # protected
P(legacy(beacon(), status=0x02))                                # decrypt error
P(legacy(beacon(), status=0x04))                                # short preamble
P(legacy(beacon(), status=0xf8))                                # reserved status bits
P(legacy(beacon(), sig=0, noise=0, sigp=0, noisep=0, ts=0))
P(legacy(beacon(), sig=-128, noise=127, sigp=255, noisep=255, ts=0xffffffffffffffff))

# version 2 header: 11n, 11ac, 11ax, 11be with bandwidths, guard intervals, NSS
P(v2(beacon(), extflags=EXT_20L, mcs=0))
P(v2(qos_data(), extflags=EXT_20U | EXT_HGI, mcs=7))
P(v2(qos_data(), extflags=EXT_40 | EXT_FGI | EXT_AMPDU, mcs=15, channel=11, freq=2462))
P(v2(qos_data(), extflags=EXT_40 | EXT_HGI | EXT_AMSDU | nss(2), mcs=31))
P(v2(qos_data(), extflags=EXT_SP | EXT_MCSUSED | nss(4), mcs=3))
P(v2(qos_data(), extflags=EXT_QGI, mcs=2))
P(v2(qos_data(), extflags=EXT_AC | EXT_80 | EXT_HGI | nss(2), mcs=9, channel=36, freq=5180, band=1))
P(v2(qos_data(), extflags=EXT_AC | EXT_160 | EXT_FGI | nss(3), mcs=8, channel=100, freq=5500, band=1))
P(v2(qos_data(), extflags=EXT_AC | EXT_40 | nss(1), mcs=5, channel=149, freq=5745, band=1))
P(v2(qos_data(), extflags=EXT_AC | nss(1), mcs=0))
P(v2(qos_data(), extflags=EXT_AC | EXT_80 | EXT_160 | nss(4), mcs=9))
P(v2(qos_data(), extflags=EXT_HE | EXT_80 | EXT_HGI | nss(2), mcs=11, channel=36, freq=5180, band=1))
P(v2(qos_data(), extflags=EXT_HE | EXT_160 | EXT_FGI | nss(4), mcs=9, channel=100, freq=5500, band=1))
P(v2(qos_data(), extflags=EXT_HE | EXT_40 | EXT_QGI | nss(1), mcs=0, channel=11, freq=2462))
P(v2(qos_data(), extflags=EXT_HE | nss(1), mcs=5))
P(v2(qos_data(), extflags=EXT_EHT | EXT_320 | EXT_FGI | nss(2), mcs=13, channel=1, freq=5955, band=2))
P(v2(qos_data(), extflags=EXT_EHT | EXT_160 | EXT_HGI | nss(4), mcs=12, channel=1, freq=5955, band=2))
P(v2(qos_data(), extflags=EXT_EHT | EXT_80 | EXT_QGI | nss(1), mcs=0, channel=1, freq=5955, band=2))
P(v2(qos_data(), extflags=EXT_EHT | EXT_40 | nss(3), mcs=7))
P(v2(qos_data(), extflags=EXT_EHT | nss(1), mcs=4))
# header fields: no frequency, flags and status bits, all the frame kinds, other port (heuristic)
P(v2(beacon(), freq=0))
P(v2(probe_req(), flags=0x07, status=0x07, typ=5))
P(v2(ack(), flags=0xff, status=0xff))
P(v2(data_frame(), sigp=100))
P(v2(beacon()), dport=5001)
P(v2(qos_data(), extflags=EXT_HE | nss(1), mcs=1), dport=40000)
# an IPv6 transport for the heuristic
# version 3: radiotap
P(v3(beacon()))
P(v3(qos_data(), typ=1))
P(v3(ack()), dport=40001)

frames = []
for i, (dport, payload) in enumerate(pkts):
    frames.append(udp(5000, dport, payload) if i % 5 else udp(5000 + (i % 3), dport, payload))
frames.append(udp6(5000, 5000, legacy(beacon())))
frames.append(udp6(40002, 5000, v2(qos_data(), extflags=EXT_AC | EXT_80 | nss(2), mcs=4)))
write_pcap(out + '/peekremote-coverage.pcap', frames)

# --- malformed: bad header sizes (error expert info), unknown versions, short data
mal = []
def M(payload, dport=5000): mal.append(udp(5000, dport, payload))
M(v2(beacon(), hsize=54))
M(v2(beacon(), hsize=56))
M(v2(beacon(), hsize=9))
M(v2(beacon(), hsize=8))
M(v2(beacon(), hsize=1000))
M(v2(beacon(), hsize=0xffffffff))
M(v2(beacon(), ver=0))
M(v2(beacon(), ver=1))
M(v2(beacon(), ver=4))
M(v2(beacon(), ver=255, hsize=9))
M(v2(beacon(), ver=255, hsize=20))
M(v3(beacon(), hsize=12))
M(v3(beacon(), hsize=14))
M(v3(beacon(), hsize=9))
M(v3(beacon(), hsize=8))
M(v3(beacon(), hsize=100000))
for cut in (0, 1, 3, 4, 5, 8, 9, 10, 12, 13, 17, 25, 30, 41, 45, 50, 54, 55, 56):
    M(v2(beacon(), extflags=EXT_AC | nss(2))[:cut])
for cut in (0, 1, 5, 12, 13, 14, 20):
    M(v3(beacon())[:cut], dport=5001)
for cut in (0, 1, 5, 6, 7, 8, 15, 16, 17, 18, 19, 20, 21, 25):
    M(legacy(beacon())[:cut])
M(b'\x00\xff\xab')
M(b'\x00\xff\xab\xcd')
M(legacy(b''))
M(legacy(beacon(), plen=0xffff))
write_pcap(out + '/peekremote-coverage-malformed.pcap', mal)

# --- through Aruba ERM (udp.port 5555, Decode As aruba_erm.type): the
# legacy header with signal 100 is a TX packet without FCS. Types 1 (peek) and 5 (peekremote-ng)
def aruba(payload): return udp(5555, 5555, payload)
fa = [aruba(legacy(beacon()[:-4], sigp=100)), aruba(legacy(beacon(), sigp=90)),
      aruba(v2(beacon(), sigp=100))]
write_pcap(out + '/peekremote-coverage-aruba.pcap', fa)
gz(out + '/peekremote-coverage.pcap')
print('ok')

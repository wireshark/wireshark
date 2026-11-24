#!/usr/bin/env python3
# Generates test/captures/aruba_erm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Aruba encapsulated remote
mirroring dissector (packet-aruba-erm.c).

All packets are built from scratch with struct (zlib only for the 802.11
FCS); no captured traffic is used. An access point (10.40.0.2) mirrors
802.11 frames to a collector (10.40.0.100) over UDP.

The ERM format is not in the packets: the user picks it with Decode As
("aruba_erm.type"). So that every format can be checked against one
capture, each format is sent to its own UDP port, 41000 + type:

  41000  type 0  pcap record header + 802.11 with FCS
  41001  type 1  Peek remote (legacy, 20 octet header)
  41002  type 2  Airmagnet (not decoded)
  41003  type 3  pcap record header + radio header + 802.11
  41004  type 4  PPI
  41005  type 5  Peek remote-ng (magic 00 ff ab cd, version 2 and 3)
  41006  type 6  radiotap

Aruba ERM has no default port. Dissect one format with, for type N:

  tshark -o aruba_erm.udp.port:41000-41006 \
         -d aruba_erm.type,aruba_erm.typeN -Y udp.dstport==4100N

Without -d every frame gets the "Use Decode As" note.

Usage: mkaruba_erm.py <output directory>

Writes:
  aruba_erm-coverage.pcap            all seven formats
  aruba_erm-coverage-malformed.pcap  payloads cut short for each format
"""

import os
import struct
import sys
import zlib

AP = (10, 40, 0, 2)
COLLECTOR = (10, 40, 0, 100)
BASE_PORT = 41000

STA = bytes.fromhex('020000000101')
BSSID = bytes.fromhex('24dec6000201')
GW = bytes.fromhex('020000000102')
BCAST = b'\xff' * 6


def ip_checksum(hdr):
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(port, payload):
    udp = struct.pack('>HHHH', port, port, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                     bytes(AP), bytes(COLLECTOR))
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    return bytes.fromhex('020000000064') + bytes.fromhex('24dec6000200') + b'\x08\x00' + ip + udp


def write_pcap(path, frames):
    with open(path, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            fh.write(struct.pack('<IIII', 1700000000 + i, 0, len(f), len(f)) + f)


# --------------------------------------------------------------------------
# 802.11 frames

def fcs(frame):
    return frame + struct.pack('<I', zlib.crc32(frame) & 0xffffffff)


def arp(op, sha, spa, tha, tpa):
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, sha, bytes(spa), tha, bytes(tpa))


def wlan_data(seq):
    """Data frame to the DS: an ARP request from the station."""
    hdr = struct.pack('<HH6s6s6sH', 0x0108, 44, BSSID, STA, BCAST, seq << 4)
    return hdr + b'\xaa\xaa\x03\x00\x00\x00\x08\x06' + \
        arp(1, STA, (10, 40, 1, 10), b'\0' * 6, (10, 40, 1, 1))


def wlan_qos_data(seq):
    """QoS data frame from the DS: the ARP reply."""
    hdr = struct.pack('<HH6s6s6sHH', 0x0288, 44, STA, BSSID, GW, seq << 4, 0x0000)
    return hdr + b'\xaa\xaa\x03\x00\x00\x00\x08\x06' + \
        arp(2, GW, (10, 40, 1, 1), STA, (10, 40, 1, 10))


def wlan_beacon(seq, channel=6):
    hdr = struct.pack('<HH6s6s6sH', 0x0080, 0, BCAST, BSSID, BSSID, seq << 4)
    body = struct.pack('<QHH', 123456789 + seq, 100, 0x0401)
    body += b'\x00\x07' + b'aruba-1'
    body += b'\x01\x08' + bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
    body += b'\x03\x01' + bytes([channel])
    return hdr + body


def wlan_ack():
    return struct.pack('<HH6s', 0x00d4, 0, STA)


def wlan_probe_req(seq):
    hdr = struct.pack('<HH6s6s6sH', 0x0040, 0, BCAST, STA, BCAST, seq << 4)
    return hdr + b'\x00\x00' + b'\x01\x04' + bytes([0x02, 0x04, 0x0b, 0x16])


# --------------------------------------------------------------------------
# ERM payloads

def pcaprec(frame, ts=1700000000, usec=250000):
    return struct.pack('>IIII', ts, usec, len(frame), len(frame))


def type0(frame):
    f = fcs(frame)
    return pcaprec(f) + f


def type3(frame, rate, channel, signal):
    f = frame if signal == 100 else fcs(frame)
    return pcaprec(f) + struct.pack('>HBB', rate, channel, signal) + f


TSF = [0x0001020304050000]


def tsf():
    """A distinct TSF for each frame: the 802.11 radio dissector takes
    frames with the same TSF for parts of one A-MPDU."""
    TSF[0] += 1000
    return TSF[0]


def peek_legacy(frame, rate, channel, signal, flags=0, status=0, aruba_tx=False):
    f = frame if aruba_tx else fcs(frame)
    return struct.pack('>bbHHBBQBBBB', -40 if not aruba_tx else -30, -95, len(f), len(f),
                       flags, status, tsf(), rate, channel, signal, 10) + f


def peek_v2(frame, mcs, channel, freq, band, extflags, flags=0, status=0):
    f = fcs(frame)
    hdr = struct.pack('>4sBI', b'\x00\xff\xab\xcd', 2, 55)
    hdr += struct.pack('>IHHIII', 0, mcs, channel, freq, band, extflags)
    hdr += struct.pack('>BBbb4b4bHHBBQ', 70, 5, -45, -92, -45, -47, -50, -128,
                       -92, -93, -94, -128, len(f), len(f), flags, status, tsf())
    assert len(hdr) == 55
    return hdr + f


def peek_v3(frame):
    return struct.pack('>4sBII', b'\x00\xff\xab\xcd', 3, 13, 0) + radiotap(frame, True, 5180, 0x0140, -50)


def radiotap(frame, rx, freq, chflags, signal, rate=12):
    """Radiotap with flags, rate, channel and antenna signal. A received
    frame has "FCS at end" set; a transmitted one has no FCS."""
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    flags = 0x10 if rx else 0x00
    hdr = struct.pack('<BBHI', 0, 0, 15, present)
    hdr += struct.pack('<BBHHb', flags, rate, freq, chflags, signal)
    return hdr + (fcs(frame) if rx else frame)


def ppi(frame, rx=True, rate=22, freq=2437, chflags=0x00a0):
    """PPI header with an 802.11-Common field, DLT 105 (802.11)."""
    common = struct.pack('<QHHHHBBbb', 123456789, 0x0001 if rx else 0x0000, rate, freq,
                         chflags, 0, 0, -48, -95)
    field = struct.pack('<HH', 2, len(common)) + common
    hdr = struct.pack('<BBHI', 0, 0, 8 + len(field), 105) + field
    return hdr + (fcs(frame) if rx else frame)


def main(outdir):
    frames = []

    def add(t, payload):
        frames.append(udp_frame(BASE_PORT + t, payload))

    # Type 0: pcap record + 802.11 with FCS
    add(0, type0(wlan_beacon(1)))
    add(0, type0(wlan_data(2)))
    add(0, type0(wlan_qos_data(3)))
    add(0, type0(wlan_ack()))

    # Type 1: legacy Peek remote. 11b and 11g rates on 2.4 GHz, 11a on
    # 5 GHz, 6 GHz band flags, a transmitted frame (signal 100 %, no FCS)
    # and an MCS rate that is neither DSSS nor OFDM
    add(1, peek_legacy(wlan_beacon(10), 2, 6, 60))
    add(1, peek_legacy(wlan_data(11), 108, 11, 75, status=0x02))
    add(1, peek_legacy(wlan_qos_data(12), 12, 36, 80, flags=0x08))
    add(1, peek_legacy(wlan_beacon(13, 37), 12, 37, 80, flags=0x18))
    add(1, peek_legacy(wlan_probe_req(14), 22, 1, 100, aruba_tx=True))
    add(1, peek_legacy(wlan_ack(), 13, 6, 50, flags=0x01))

    # Type 2: Airmagnet, not decoded (error expert info by design)
    add(2, bytes(range(32)))
    add(2, type0(wlan_beacon(20)))

    # Type 3: pcap record + radio header. Data rate in 0.5 Mb/s units:
    # DSSS 1, 2, 5.5 and 11 Mb/s, OFDM on channel 6 (11g) and on
    # channels 36 and 149 (11a), 6.5 Mb/s (neither), signal 100 % (TX,
    # no FCS); every DSSS and OFDM rate the PHY guess knows
    add(3, type3(wlan_beacon(30), 2, 1, 55))
    add(3, type3(wlan_data(31), 4, 6, 60))
    add(3, type3(wlan_qos_data(32), 11, 11, 65))
    add(3, type3(wlan_probe_req(33), 22, 13, 100))
    add(3, type3(wlan_data(34), 108, 6, 70))
    add(3, type3(wlan_beacon(35, 36), 12, 36, 80))
    add(3, type3(wlan_qos_data(36), 96, 149, 100))
    add(3, type3(wlan_ack(), 13, 6, 45))
    # The other DSSS (22 and 33 Mb/s) and OFDM rates
    for i, (rate, channel) in enumerate(((44, 1), (66, 6), (18, 1), (24, 11), (36, 44),
                                         (48, 6), (72, 165))):
        add(3, type3(wlan_data(37 + i), rate, channel, 50 + i))

    # Type 4: PPI with the 802.11-Common field, received (FCS) and sent
    add(4, ppi(wlan_beacon(40)))
    add(4, ppi(wlan_data(41), rx=False, rate=108, freq=5180, chflags=0x0140))

    # Type 5: Peek remote-ng. Version 2 with 11n (20 and 40 MHz), 11ac
    # (80 MHz, short GI, 2 streams), 11ax (160 MHz), 11be (320 MHz) and a
    # zero frequency; version 3 (radiotap inside)
    add(5, peek_v2(wlan_data(50), 7, 6, 2437, 1, 0x00000100))
    add(5, peek_v2(wlan_qos_data(51), 15, 6, 2437, 1, 0x00004104 | 0x08))
    add(5, peek_v2(wlan_qos_data(52), 9, 36, 5180, 2, 0x00004280 | 0x08 | 0x20))
    add(5, peek_v2(wlan_beacon(53, 36), 11, 36, 5180, 2, 0x00060000 | 0x10))
    add(5, peek_v2(wlan_data(54), 13, 37, 0, 4, 0x00180000 | 0x00200000, flags=0x18))
    add(5, peek_v3(wlan_qos_data(55)))

    # Type 6: radiotap. Received on 2.4 and 5 GHz (FCS at end) and a
    # frame sent by the AP (no FCS, -30 dBm)
    add(6, radiotap(wlan_beacon(60), True, 2437, 0x00a0, -55, rate=2))
    add(6, radiotap(wlan_qos_data(61), True, 5180, 0x0140, -60, rate=108))
    add(6, radiotap(wlan_data(62), False, 2437, 0x00c0, -30, rate=12))

    write_pcap(os.path.join(outdir, 'aruba_erm-coverage.pcap'), frames)

    bad = []

    def addbad(t, payload):
        bad.append(udp_frame(BASE_PORT + t, payload))

    good = {0: type0(wlan_data(70)), 1: peek_legacy(wlan_data(71), 2, 6, 60),
            2: bytes(16), 3: type3(wlan_data(73), 2, 6, 60),
            4: ppi(wlan_data(74)), 5: peek_v2(wlan_data(75), 7, 6, 2437, 1, 0),
            6: radiotap(wlan_data(76), True, 2437, 0x00a0, -55)}
    for t in range(7):
        for n in (1, 7, 15, 17, 19):
            addbad(t, good[t][:n])
    write_pcap(os.path.join(outdir, 'aruba_erm-coverage-malformed.pcap'), bad)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

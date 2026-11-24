#!/usr/bin/env python3
# Generates test/captures/cisco_wids_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Wireless IDS
capture dissector (packet-cisco-wids.c, filter name "cwids").

CWIDS records are sent over UDP with no registered port: dissect with
-d udp.port==5555,cwids. A UDP datagram holds one or more records, each
a 28 octet header (version, timestamp, unknown, channel, unknown,
original length, capture length, unknown) followed by an IEEE 802.11
frame without FCS. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkcisco-wids.py <output directory>
Writes:
  cisco-wids-coverage.pcap            single and multiple records with
                                      management, control and data frames
  cisco-wids-coverage-malformed.pcap  802.11 frames cut short (caught by
                                      the dissector), headers cut short
                                      and capture lengths past the end
"""
import os
import struct
import sys

PORT = 5555
SENSOR = (192, 0, 2, 1)
COLLECTOR = (192, 0, 2, 2)
AP = bytes.fromhex('020000000010')
STA = bytes.fromhex('020000000020')
BCAST = b'\xff' * 6


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def cwids_frame(records, ident):
    data = b''.join(records)
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(40000, PORT, data, SENSOR, COLLECTOR), SENSOR, COLLECTOR, ident))


def record(wlan, channel=1, version=1, ts=0x000102030405, reallen=None, caplen=None):
    if reallen is None:
        reallen = len(wlan)
    if caplen is None:
        caplen = len(wlan)
    return (struct.pack('>H', version) + struct.pack('>Q', ts)[2:] + b'\x00'
            + bytes([channel]) + bytes.fromhex('a1a2a3a4a5a6')
            + struct.pack('>HH', reallen, caplen) + bytes.fromhex('b1b2b3b4b5b6b7b8') + wlan)


def beacon(ssid=b'cwids-test', channel=1, seq=1):
    hdr = struct.pack('<HH', 0x0080, 0) + BCAST + AP + AP + struct.pack('<H', seq << 4)
    fixed = struct.pack('<QHH', 0x1122334455, 100, 0x0401)
    tags = (bytes([0, len(ssid)]) + ssid + bytes([1, 4, 0x82, 0x84, 0x8b, 0x96])
            + bytes([3, 1, channel]))
    return hdr + fixed + tags


def probe_request(seq=2):
    hdr = struct.pack('<HH', 0x0040, 0) + BCAST + STA + BCAST + struct.pack('<H', seq << 4)
    return hdr + bytes([0, 0]) + bytes([1, 4, 0x02, 0x04, 0x0b, 0x16])


def ack():
    return struct.pack('<HH', 0x00d4, 0) + STA


def data_frame(payload, seq=3, ident=1):
    """Data frame STA -> AP (To DS), LLC/SNAP, IPv4 UDP to the discard port."""
    src, dst = (10, 0, 0, 1), (10, 0, 0, 2)
    inner = ipv4(17, udp(40001, 9, payload, src, dst), src, dst, ident)
    return (struct.pack('<HH', 0x0108, 44) + AP + STA + AP + struct.pack('<H', seq << 4)
            + bytes.fromhex('aaaa03000000') + b'\x08\x00' + inner)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    # 1: one record, a beacon on channel 1
    F.append(cwids_frame([record(beacon())], 1))
    # 2: one record, a data frame on channel 6
    F.append(cwids_frame([record(data_frame(b'cwids-data', ident=2), channel=6,
                                 ts=0xffffffffffff)], 2))
    # 3: three records in one datagram: probe request (channel 11), ACK
    # (channel 11), beacon on channel 36
    F.append(cwids_frame([record(probe_request(), channel=11),
                          record(ack(), channel=11, version=2),
                          record(beacon(b'five', 36, 4), channel=36, ts=0)], 3))
    # 4: a record whose original length is larger than the capture length
    # (the 802.11 frame itself is complete)
    F.append(cwids_frame([record(ack(), channel=165, reallen=1500)], 4))
    return F


def malformed_frames():
    F = []
    # 1: a beacon cut in the fixed parameters, followed by a good record:
    # the bounds error is caught and the next record is dissected
    F.append(cwids_frame([record(beacon()[:30]), record(ack())], 1))
    # 2: a record with capture length 0
    F.append(cwids_frame([record(b'')], 2))
    # 3: a header cut short
    F.append(cwids_frame([record(ack())[:20]], 3))
    # 4: a capture length past the end of the datagram
    F.append(cwids_frame([record(ack(), caplen=200)], 4))
    # 5: a data frame whose IPv4 packet is cut short
    F.append(cwids_frame([record(data_frame(b'cut', ident=5)[:40])], 5))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cisco-wids-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cisco-wids-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

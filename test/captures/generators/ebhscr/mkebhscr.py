#!/usr/bin/env python3
# Generates test/captures/ebhscr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EBHSCR dissector
(packet-ebhscr.c, Elektrobit High Speed Capture and Replay).

EBHSCR packets are stored with the pcap link-layer type LINKTYPE_EBHSCR
(279). Each has a 32 octet header: major number (payload type), slot
and channel, a 4 bit version and 12 bit status, a length, start and
stop time stamps and an 8 octet major number specific header. The
payload is CAN or CAN FD (SocketCAN layout), an Ethernet frame with or
without FCS, an NMEA sentence, time state values, a LIN frame, digital
IO, FlexRay (frame, symbol, slot status and start of cycle packets),
DSI3, MIPI CSI-2 or a CSI-2 frame; major numbers 0x43-0x4F are user
defined. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkebhscr.py <output directory>

Writes:
  ebhscr-coverage.pcap            every major number with and without
                                  payload, every status flag, FlexRay
                                  on channels A and B, user defined and
                                  unknown major numbers, the FlexRay
                                  reproducer of the stack tvb fix and an
                                  NMEA length larger than the payload
  ebhscr-coverage-malformed.pcap  header cut short, a 1 octet LIN
                                  payload, an invalid DSI3 channel,
                                  payloads cut short
"""

import os
import struct
import sys

LINKTYPE_EBHSCR = 279


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, LINKTYPE_EBHSCR))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


TS = [1000]


def ebhscr(major, payload=b'', status=0, mjr=0, slot=0, channel=0, version=0,
           length=None):
    """32 octet header: major number, slot (top 2 bits) and channel (6
    bits), version and status, length, start and stop time stamps and
    the major number specific header (a 64 bit value)."""
    if length is None:
        length = len(payload)
    TS[0] += 1000
    hdr = struct.pack('>BBH', major, (slot << 6) | channel, (version << 12) | (status & 0x0fff))
    hdr += struct.pack('>I', length) + struct.pack('>QQ', TS[0], TS[0] + 500)
    hdr += struct.pack('>Q', mjr)
    assert len(hdr) == 32
    return hdr + payload


# SocketCAN frames, CAN ID in host byte order (little endian here)
def can(cid, data):
    return struct.pack('<IB3x', cid, len(data)) + data.ljust(8, b'\0')


def canfd(cid, data, flags=0x01):
    return struct.pack('<IBBxx', cid, len(data), flags) + data.ljust(64, b'\0')


def ether(fcs):
    fr = bytes.fromhex('0200000000020200000000010800')
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    s = sum(struct.unpack('>10H', ip))
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    fr += ip + struct.pack('>HHHH', 5000, 5001, 8, 0)
    fr = fr.ljust(60, b'\0')
    if fcs:
        import zlib
        fr += struct.pack('<I', zlib.crc32(fr))
    return fr


def flexray_frame(fid, cc, payload, nfi=1, sfi=0, stfi=0):
    # 5 octet FlexRay header: reserved, PPI, NFI, SFI, STFI, 11 bit ID,
    # 7 bit payload length (words), 11 bit header CRC, cycle count
    b0 = (nfi << 5) | (sfi << 4) | (stfi << 3) | ((fid >> 8) & 0x7)
    pl = len(payload) // 2
    hdr = bytes([b0, fid & 0xff]) + struct.pack('>I', (pl << 25) | (0x123 << 14) | (cc << 8))[:3]
    hdr = hdr[:4] + bytes([cc])
    return hdr + payload + b'\x11\x22\x33'


def main_frames():
    F = []
    # ---- CAN (0x53)
    # 1: CAN frame (status 0), 2: CAN FD frame (status bit 0)
    F.append(ebhscr(0x53, can(0x123, b'\x01\x02\x03\x04'), channel=1))
    F.append(ebhscr(0x53, canfd(0x456, bytes(range(12))), status=0x001, channel=2))
    # 3: CAN with the protocol status flag: the major number specific
    #    header holds the error counters and state bits
    F.append(ebhscr(0x53, can(0x7ff, b'\xaa'), status=0x002,
                    mjr=0x0000_0000_0000_0000 | (5 << 0) | (1 << 3) | (1 << 4) | (1 << 5) |
                    (3 << 8) | (0x12 << 16) | (0x34 << 24) | (0x56 << 32)))
    # 4: CAN header only (no data), with the overflow status bits
    F.append(ebhscr(0x53, b'', status=0x00c))
    # ---- Ethernet (0x50)
    # 5: frame with FCS, link up at 1000M, master
    F.append(ebhscr(0x50, ether(True), mjr=(1 << 32) | (2 << 28) | (1 << 33)))
    # 6: frame without FCS (FCS not appended bit)
    F.append(ebhscr(0x50, ether(False), mjr=(1 << 34) | (1 << 32) | (1 << 28), channel=1 << 2))
    # 7: header only, link up at an unknown and 100G speed: Info shows
    #    controller number, link and speed
    F.append(ebhscr(0x50, b'', mjr=(1 << 32) | (15 << 28), channel=2 << 2))
    F.append(ebhscr(0x50, b'', mjr=(1 << 32) | (8 << 28), channel=3 << 2))
    # 9: header only, link down
    F.append(ebhscr(0x50, b'', mjr=0))
    # 10: receive errors in the status (warning)
    F.append(ebhscr(0x50, ether(True), status=0x0fff, mjr=(1 << 32) | (0 << 28)))
    # ---- NMEA (0x51)
    # 11: NMEA sentence, 12: header only
    nmea = b'$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47'
    F.append(ebhscr(0x51, nmea))
    F.append(ebhscr(0x51, b''))
    # 13: length field larger than the payload: the Info column shows
    #     the captured sentence (fixed: it read the length field)
    F.append(ebhscr(0x51, b'$GPGLL,4916.45,N,12311.12,W,225444,A', length=1000))
    # ---- Time state (0x52)
    # 14: every valid bit, every value
    ts = struct.pack('>qqqhH', 123456789, -1000, 5000, 37, 1) + b'\0' * 2
    F.append(ebhscr(0x52, ts, status=0x01f, mjr=0x20))
    # 15: no valid bits, unknown time source, 16: header only (PTP HW)
    F.append(ebhscr(0x52, ts, status=0, mjr=0x77))
    F.append(ebhscr(0x52, b'', status=0x001, mjr=0x03))
    # 17: payload shorter than the 28 octets of values
    F.append(ebhscr(0x52, b'\0' * 8, status=0x01f, mjr=0x10))
    # 18-19: other time sources with one valid bit each
    F.append(ebhscr(0x52, ts, status=0x002, mjr=0x01))
    F.append(ebhscr(0x52, ts, status=0x004 | 0x008, mjr=0x50))
    # ---- LIN (0x55)
    # 20: LIN frame: PID, data, checksum; LIN 1.3 classic checksum bit
    F.append(ebhscr(0x55, bytes([0x80 | 0x12]) + b'\x01\x02\x03\x04' + b'\x55',
                    status=0x001, mjr=(0x12 << 56)))
    # 21: LIN wake-up packet, header only
    F.append(ebhscr(0x55, b'', status=0x010, mjr=(0x0040 << 40)))
    # 22: LIN with error status bits and only PID and checksum
    F.append(ebhscr(0x55, b'\x3c\xff', status=0x0fe0 | 0x002, mjr=(0x1ff << 32) | 0xff))
    # 23: LIN with no status bits
    F.append(ebhscr(0x55, b'\x01' + b'\x00' * 8 + b'\x77'))
    # ---- DIO (0x56)
    # 24: DIO event, rising edge, GPIO id; 25: header only with overflow
    F.append(ebhscr(0x56, b'\x01\x00', mjr=(1 << 56) | (1 << 48) | (0x05 << 40), channel=3))
    F.append(ebhscr(0x56, b'', status=0x001, mjr=(3 << 56) | (1 << 60)))
    # ---- FlexRay (0x57)
    # 26-27: the reproducer of the stack tvb fix: a frame packet and a
    #        symbol packet on channel A
    F.append(ebhscr(0x57, bytes([0x00, 0x08, 0x02, 0x01, 0x05]) + b'\xaa\xbb' + b'\x00\x00\x00'))
    F.append(ebhscr(0x57, b'', status=0x0004, mjr=0x00000000_05000000))
    # 28: frame packet on channel B with every error status bit
    F.append(ebhscr(0x57, flexray_frame(100, 7, b'\x01\x02\x03\x04'), status=0x0ff3,
                    channel=0x02 | 0x04, mjr=(0xffff << 48) | (0xffff << 32) | 0x1234))
    # 29: frame packet, sync and startup frame, channel A and B bits
    F.append(ebhscr(0x57, flexray_frame(5, 63, b'\x10' * 8, sfi=1, stfi=1), channel=0x03,
                    mjr=(0x8000 << 48) | 7))
    # 30: null frame on channel B
    F.append(ebhscr(0x57, flexray_frame(6, 1, b'', nfi=0), channel=0x02))
    # 31: symbol packet on channel B, symbol length 0x7f with SYERR
    F.append(ebhscr(0x57, b'', status=0x0004 | 0x0ff0, channel=0x02,
                    mjr=0x00000000_ff000000 | (0x5555 << 32)))
    # 32: slot status packet, 33: start of cycle packet
    F.append(ebhscr(0x57, b'', status=0x0008 | 0x0ff0,
                    mjr=(0xaaaa << 48) | (0x5555 << 32) | 123456))
    F.append(ebhscr(0x57, b'', status=0x000c, mjr=(0x02 << 56) | (0x21 << 48) | 99, channel=0x01))
    F.append(ebhscr(0x57, b'', status=0x000c, mjr=(0x2b << 56) | (0x3f << 48) | 100, channel=0x02))
    # ---- DSI3 (0x5C)
    # 35: slave channel, no flags, with data; 36: slave with every flag
    F.append(ebhscr(0x5C, b'\x12\x34\x56', channel=0, mjr=(0x05 << 56)))
    F.append(ebhscr(0x5C, b'\x01', status=0x00f, channel=0,
                    mjr=(0xff << 56) | (0xff << 48) | (0x03 << 40) | (0x1f << 32)))
    # 37: slave with only st3 flags, header only
    F.append(ebhscr(0x5C, b'', channel=0, mjr=(0x01 << 32)))
    # 38: master channel with data; 39: master with every flag
    F.append(ebhscr(0x5C, b'\xaa\xbb', channel=1, mjr=(0x0c << 56)))
    F.append(ebhscr(0x5C, b'', status=0x001, channel=1,
                    mjr=(0xff << 56) | (0x0f << 40) | (0x3f << 32)))
    F.append(ebhscr(0x5C, b'\x01', channel=1, mjr=(0x20 << 32)))
    # ---- MIPI CSI-2 (0x59)
    # 41: packet header and data; 42: header and flags, payload shorter
    #     than the packet header; 43: packet header only
    csi = bytes([0x2a, 0x01, 0x00, 0x3f]) + struct.pack('<HH', 0xbeef, 4)
    F.append(ebhscr(0x59, csi + b'\x01\x02\x03\x04', mjr=(0x0000_0000 << 32) | (7 << 16) | 3))
    F.append(ebhscr(0x59, b'\x01\x02', status=0x00f, mjr=(0x07 << 56) | (1 << 16) | 1))
    F.append(ebhscr(0x59, csi, mjr=(0x01 << 56)))
    # ---- CSI-2 frame (0x5E)
    # 44: frame header with 8 sections and pixel data
    secs = b''
    for i in range(8):
        secs += struct.pack('>IIHHHBB', 1024 * i, 1024, 64, 16, 0, 0, 0x2a + i)
    F.append(ebhscr(0x5E, secs + b'\x10\x20\x30\x40', mjr=(0x01 << 56) | (5 << 32)))
    # 45: section error bits (warnings) and status bits, no pixel data
    secs = b''
    for i in range(8):
        secs += struct.pack('>IIHHHBB', 0, 0, 0, 0, 0, (i % 15) + 1 if i else 0, 0x1e)
    F.append(ebhscr(0x5E, secs, status=0x007, mjr=(0x0f << 56)))
    # 46: payload shorter than the 128 octet frame header
    F.append(ebhscr(0x5E, b'\0' * 16))
    # ---- user defined (0x43-0x4F) and unknown major numbers
    # 47-49: user defined with data, without data, last user number
    F.append(ebhscr(0x43, b'user data'))
    F.append(ebhscr(0x4F, b''))
    F.append(ebhscr(0x48, b'\x01\x02', status=0x123))
    # 50-51: unknown major numbers 0x00 and 0x60, header version 1
    F.append(ebhscr(0x00, b'\xde\xad', version=1))
    F.append(ebhscr(0x60, b'', slot=3, channel=0x3f, version=15))
    return F


def malformed_frames():
    F = []
    # 1: shorter than the 32 octet header (error expert info)
    F.append(ebhscr(0x53, b'')[:20])
    # 2: LIN with a 1 octet payload (PID only): before the fix the data
    #    length wrapped to 0xFFFFFFFF; now an error expert info
    F.append(ebhscr(0x55, b'\x12'))
    # 3: DSI3 with an invalid channel (error expert info)
    F.append(ebhscr(0x5C, b'\x01', channel=5))
    # 4: FlexRay frame packet whose payload length is longer than the data
    F.append(ebhscr(0x57, bytes([0x20, 0x09, 20 << 1, 0x00, 0x01]) + b'\x01\x02'))
    # 5: CAN payload cut short
    F.append(ebhscr(0x53, b'\x01\x02\x03'))
    # 6: Ethernet payload of 4 octets
    F.append(ebhscr(0x50, b'\x01\x02\x03\x04'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ebhscr-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ebhscr-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

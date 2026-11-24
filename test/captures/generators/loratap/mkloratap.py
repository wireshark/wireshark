#!/usr/bin/env python3
# Generates test/captures/loratap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LoRaTap coverage captures (LINKTYPE_LORATAP 270).
# Usage: mkloratap.py <outdir>.  Writes loratap-coverage.pcap and
# loratap-coverage-malformed.pcap.  All data is made up; the LoRaWAN
# payloads carry placeholder bytes only (no keys, no real MIC).
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def pcap(fname, frames, linktype=270):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def v0(freq=868100000, bw=1, sf=7, rssi=(80, 90, 85, 40), sync=0x34,
       payload=b'', length=15, ver=0, pad=0, extra=b''):
    h = struct.pack('>BBHIBBBBBBB', ver, pad, length, freq, bw, sf,
                    rssi[0], rssi[1], rssi[2], rssi[3], sync)
    return h + extra + payload

def v1(flags=0x08, sync=0x34, payload=b'', gw=bytes(range(1, 9)), ts=123456,
       cr=5, dr=0, ifc=2, rf=1, tag=7, length=35, freq=868300000, bw=1,
       sf=9, rssi=(70, 100, 255, 0xf4), extra=b'', pad=0):
    h = struct.pack('>BBHIBBBBBBB', 1, pad, length, freq, bw, sf,
                    rssi[0], rssi[1], rssi[2], rssi[3], sync)
    h += gw + struct.pack('>IB', ts, flags) + struct.pack('>BHBB', cr, dr, ifc, rf)
    h += struct.pack('>H', tag)
    return h + extra + payload

devaddr = struct.pack('<I', 0x01020304)
# LoRaWAN unconfirmed data up, FPort 1, placeholder payload and MIC
lw_data = bytes([0x40]) + devaddr + b'\x00\x01\x00' + b'\x01' + b'hello' + b'\x11\x22\x33\x44'
# LoRaWAN join request
lw_join = bytes([0x00]) + bytes(range(8)) + bytes(range(8, 16)) + b'\x01\x02' + b'\xaa\xbb\xcc\xdd'

fr = []
# --- version 0
fr.append(v0(payload=lw_data))                                   # 1 LoRaWAN, 125 kHz SF7
fr.append(v0(bw=2, sf=8, sync=0x12, payload=b'private lora data'))   # 2 private syncword -> Data
fr.append(v0(bw=4, sf=12, rssi=(255, 0, 139, 0x80), payload=lw_join))   # 3 500 kHz, N/A RSSI, negative SNR
fr.append(v0(bw=3, sf=6, sync=0x56, payload=b'\x00'))            # 4 unknown bandwidth and syncword
fr.append(v0(payload=lw_data, length=19, extra=b'\xde\xad\xbe\xef'))   # 5 header extended by 4 octets (future extension)
fr.append(v0(sync=0x12, payload=b''))                                    # 6 header only, empty payload
fr.append(v0(ver=2, payload=lw_data))                            # 7 unknown version handled as v0
fr.append(v0(pad=0x5a, payload=lw_data))                         # 8 non-zero padding octet
# --- version 1 (flags: 0x01 FSK, 0x02 IQ inverted, 0x04 implicit header,
# 0x38 checksum 1 OK 2 bad 4 none, 0xc0 padding)
fr.append(v1(flags=0x08, payload=lw_data))                       # 9 CRC OK -> LoRaWAN
fr.append(v1(flags=0x10, payload=lw_data))                       # 10 CRC bad -> Data only
fr.append(v1(flags=0x20, sync=0x12, payload=b'no crc'))          # 11 No CRC, private -> Data
fr.append(v1(flags=0x09 | 0x02 | 0x04, dr=50000, cr=8, payload=lw_data))  # 12 FSK + IQ + implicit + CRC OK
fr.append(v1(flags=0xc8, cr=0, ifc=255, rf=0, payload=lw_join))  # 13 padding bits set, cr none
fr.append(v1(flags=0x28, cr=6, length=39, extra=b'\x00\x01\x02\x03', payload=lw_data))  # 14 extended v1 header (both bits of checksum field)
fr.append(v1(flags=0x08, cr=7, sync=0x12, payload=b''))                     # 15 header only
fr.append(v1(flags=0x00, payload=lw_data))                       # 16 checksum field 0 (unknown) -> Data
fr.append(v1(flags=0x08, bw=4, sf=10, rssi=(0, 255, 255, 0x7f), payload=lw_data))  # 17 500 kHz, extreme RSSI/SNR
pcap(os.path.join(OUT, 'loratap-coverage.pcap'), fr)

bad = []
bad.append(v0(payload=lw_data)[:9])                              # 1 header truncated in the channel
bad.append(v0(payload=lw_data, length=200))                      # 2 header length beyond the frame
bad.append(v1(payload=lw_data)[:20])                             # 3 v1 truncated before the gateway EUI ends
bad.append(v1(payload=lw_data)[:30])                             # 4 v1 truncated in the flags/cr
bad.append(v0(payload=lw_data, length=0))                        # 5 header length 0 (payload overlaps header)
bad.append(v0(payload=b'')) # 8 empty LoRaWAN payload
bad.append(v1(payload=lw_data[:6])) # 9 short LoRaWAN payload
bad.append(b'\x00\x00\x00')                                      # 6 less than 4 octets
bad.append(v1(payload=lw_data, length=34))                       # 7 v1 header length shorter than the fields
pcap(os.path.join(OUT, 'loratap-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))

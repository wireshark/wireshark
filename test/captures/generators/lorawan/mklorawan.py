#!/usr/bin/env python3
# Generates test/captures/lorawan_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LoRaWAN coverage captures: LoRaWAN frames inside LoRaTap
# (LINKTYPE_LORATAP 270, syncword 0x34), the way a gateway capture reaches
# the dissector.  Usage: mklorawan.py <outdir>.  Writes
# lorawan-coverage.pcap and lorawan-coverage-malformed.pcap.
# There are no keys anywhere: every MIC and every encrypted payload is a
# placeholder byte string, no cryptography is done (decryption and MIC
# verification are therefore not covered).  The only calculation is the
# plain CRC-16 of the Class-B beacon, which is a checksum, not a MAC.
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

def tap(payload, sf=7, sync=0x34):
    # LoRaTap version 0 header, 15 octets
    return struct.pack('>BBHIBBBBBBB', 0, 0, 15, 868100000, 1, sf, 80, 90, 85, 40, sync) + payload

def crc16(data, crc=0):
    # CRC-16 polynomial 0x1021, seed 0, no reflection (what the beacon uses)
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc

MIC = b'\x11\x22\x33\x44'          # placeholder, not a real MIC
dev = struct.pack('<I', 0x01020304)
dev2 = struct.pack('<I', 0x0a0b0c0d)

def data_frame(mhdr, fctrl, fcnt, fopts=b'', fport=None, payload=b'', addr=dev, mic=MIC):
    b = bytes([mhdr]) + addr + bytes([fctrl | len(fopts)]) + struct.pack('<H', fcnt) + fopts
    if fport is not None:
        b += bytes([fport]) + payload
    return b + mic

def beacon17(gps, info=0, lat=0x123456, lng=0x654321):
    h = b'\x00\x00' + struct.pack('<I', gps)
    h += struct.pack('<H', crc16(h))
    g = bytes([info]) + struct.pack('<I', lat)[:3] + struct.pack('<I', lng)[:3]
    return h + g + struct.pack('<H', crc16(g))

def beacon19(gps, info=1, lat=0x800001, lng=0x7fffff, rfu2=0):
    h = b'\x00\x00\x00' + struct.pack('<I', gps)
    h += struct.pack('<H', crc16(h))
    g = bytes([info]) + struct.pack('<I', lat)[:3] + struct.pack('<I', lng)[:3] + bytes([rfu2])
    return h + g + struct.pack('<H', crc16(g))

U, D = 'up', 'down'
fr = []
L = lambda p, **k: fr.append(tap(p, **k))

# --- Join
L(bytes([0x00]) + bytes(range(1, 9)) + bytes(range(11, 19)) + b'\x01\x02' + MIC)   # 1 Join Request
L(bytes([0x00]) + bytes(range(0xf0, 0xf8)) + bytes(range(0xe0, 0xe8)) + b'\xff\xff' + MIC, sf=12)  # 2 Join Request, other EUIs
L(bytes([0x20]) + bytes(range(0x30, 0x40)))                                      # 3 Join Accept 16 octets (encrypted, no keys)
L(bytes([0x20]) + bytes(range(0x30, 0x50)))                                      # 4 Join Accept 32 octets (with CFList)
# --- Data up, FOpts with every uplink MAC command
up_a = bytes([0x02, 0x03, 0x07, 0x04, 0x05, 0x03, 0x06, 0x5a, 0x1f, 0x07, 0x03, 0x08, 0x09])
up_b = bytes([0x0a, 0x01, 0x0d, 0x10, 0x07, 0x11, 0x03, 0x12, 0x13, 0x01, 0x80])   # ends with an unknown command
L(data_frame(0x40, 0x80, 1, up_a, 1, b'hello'))                                  # 5 Unconfirmed Data Up, ADR, FOpts, FPort 1, payload
L(data_frame(0x80, 0x60, 2, up_b, 2, b'\x01\x02\x03'))                            # 6 Confirmed Data Up, ADRACKReq + ACK, FOpts
L(data_frame(0x40, 0x10, 3, b'', 0, b'\x02\x03\x07'))                             # 7 FPort 0, MAC commands in the (encrypted) payload
L(data_frame(0x40, 0x00, 4, b'', None))                                           # 8 no FPort, no payload
L(data_frame(0x40, 0x00, 5, b'', 9, b''))                                         # 9 FPort without payload
L(data_frame(0x80, 0x00, 6, bytes([0x03, 0x00, 0xff, 0xff, 0xff]), 5, b'x', addr=dev2))  # 10 other device, unknown FOpts from RFU commands
L(data_frame(0x40, 0x00, 7, b'', 3, bytes(range(120)), addr=dev2))                # 11 longer payload
# --- Data down, FOpts with every downlink MAC command
dn_a = bytes([0x02, 0x10, 0x03, 0x03, 0x31, 0xff, 0x00, 0x21, 0x04, 0x07, 0x05, 0x23, 0x01, 0x02, 0x03])
dn_b = bytes([0x06, 0x07, 0x04, 0x10, 0x86, 0x01, 0x8f, 0x08, 0x0f, 0x09, 0x1b, 0x10])
dn_c = bytes([0x0a, 0x0f, 0x00, 0x00, 0x00, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x80, 0x13, 0x01, 0x02, 0x03])
dn_d = bytes([0x11, 0x01, 0x02, 0x03, 0x04, 0x12, 0x11, 0x22, 0x33, 0x44, 0x55, 0x90])
L(data_frame(0x60, 0x20, 1, dn_a, 1, b'ok'))                                      # 12 Unconfirmed Data Down, ACK
L(data_frame(0xa0, 0x30, 2, dn_b, 1, b'ok'))                                      # 13 Confirmed Data Down, ACK + FPending
L(data_frame(0x60, 0x80, 3, dn_c, 2, b''))                                        # 14
L(data_frame(0xa0, 0x00, 4, dn_d, 2, b'\x00'))                                    # 15 ends with an unknown command
L(data_frame(0x60, 0x00, 5, b'', 0, b'\x06\x0d'))                                 # 16 FPort 0 down
# --- Class-B beacons
L(beacon17(1000000000))                                                           # 17 17 octets
L(beacon19(1100000000))                                                           # 18 19 octets with RFU
# --- RFU, proprietary
L(bytes([0xc0]) + b'abc')                                                         # 19 RFU message type
L(bytes([0xe0]) + b'proprietary data')                                            # 20 Proprietary
# --- Same, with LoRaTap version 1 header, CRC OK
def tap1(payload):
    h = struct.pack('>BBHIBBBBBBB', 1, 0, 35, 868300000, 1, 9, 70, 80, 75, 20, 0x34)
    h += bytes(range(1, 9)) + struct.pack('>IB', 99, 0x08) + struct.pack('>BHBB', 5, 0, 1, 0) + struct.pack('>H', 1)
    return h + payload
fr.append(tap1(data_frame(0x40, 0x00, 8, b'', 1, b'v1')))                          # 21
pcap(os.path.join(OUT, 'lorawan-coverage.pcap'), fr)

bad = []
B = lambda p: bad.append(tap(p))
B(bytes([0x00]) + bytes(5))                                                       # 1 Join Request truncated
B(bytes([0x20]) + bytes(7))                                                       # 2 Join Accept with bad length
B(bytes([0x41]) + b'abc')                                                         # 3 MHDR with major version 1 (error expert)
B(bytes([0x5c]) + b'abc')                                                         # 4 MHDR with RFU bits
B(data_frame(0x60, 0x0f, 1, b'', None)[:11])                                      # 5 FOpts length 15 beyond the frame
B(bytes([0x40]) + dev + b'\x00\x01\x00')                                          # 6 no MIC
B(bytes([0x40]) + dev + b'\x00')                                                  # 7 header truncated
B(bytes([0x40]))                                                                  # 8 MHDR only
B(b'')                                                                            # 9 empty payload
B(bytes([0xc0]))                                                                  # 17 RFU, no payload
B(beacon17(1000000000)[:12])                                                      # 10 truncated 17 octet beacon-like frame (data path)
b17 = bytearray(beacon17(1000000000)); b17[6] ^= 0xff; b17[15] ^= 0xff
B(bytes(b17))                                                                     # 11 bad CRCs
b19 = bytearray(beacon19(1100000000)); b19[7] ^= 0xff; b19[17] ^= 0xff
B(bytes(b19))                                                                     # 12 bad CRCs, 19 octets
B(data_frame(0x40, 0x00, 1, bytes([0x03]), 1, b'x'))                              # 13 FOpts cut in the middle of a command (LinkADRAns wants 2 octets)
B(data_frame(0x60, 0x00, 1, bytes([0x03, 1, 2]), 1, b'x'))                        # 14 down LinkADRReq cut in a command
B(data_frame(0x60, 0x00, 1, bytes([0x0d, 1, 2]), 1, b'x'))                        # 15 down DeviceTimeAns cut
B(b'\x00\x00' + bytes(14))                                                        # 16 beacon-like 16 octets (RFU, join request path)
pcap(os.path.join(OUT, 'lorawan-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))

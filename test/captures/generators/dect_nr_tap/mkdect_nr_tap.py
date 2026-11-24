#!/usr/bin/env python3
# Generates test/captures/dect_nr_tap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DECT NR+ TAP (LINKTYPE 304) coverage captures.

Usage: mkdect_nr_tap.py <outdir>

Writes dect_nr_tap-coverage.pcap (clean) and
dect_nr_tap-coverage-malformed.pcap. Every packet is built with struct;
nothing comes from a real network.
"""
import os
import struct
import sys

LINKTYPE_DECT_NR_TAP = 304

# TLV types
DATA_TYPE, HEADER_STATUS, PCC_RSSI2, PCC_SNR, PDC_RSSI2, PDC_SNR = 1, 2, 3, 4, 5, 6
TRANSACTION_ID, CHANNEL, TRACE_LINE, MODEM_HI, MODEM_LO, IS_TX = 7, 8, 9, 10, 11, 12


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535,
                            LINKTYPE_DECT_NR_TAP))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):       # (data, original length)
                data, orig = fr
            else:
                data, orig = fr, len(fr)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), orig))
            f.write(data)


def tlv(t, v, length=None):
    """A TLV of 8 octets: type, length, 4 value/padding octets.
    16 bit values carry length 2 and two padding octets, modem time and
    trace line length 4."""
    if length is None:
        length = 4 if t in (MODEM_HI, MODEM_LO, TRACE_LINE) else 2
    if isinstance(v, bytes):
        val = v
    elif length == 4:
        val = struct.pack('<I', v)
    else:
        val = struct.pack('<h' if v < 0 else '<H', v) + b'\0\0'
    return struct.pack('<HH', t, length) + val


def frame(tlvs, payload, version=1, reserved1=0, reserved2=0, pad_to_64=True,
          tlvs_length=None):
    body = b''.join(tlvs)
    if pad_to_64:
        while len(body) < 64:
            body += tlv(TRANSACTION_ID, 0x1234)
    if tlvs_length is None:
        tlvs_length = len(body)
    hdr = struct.pack('<BBHHH', version, reserved1, tlvs_length,
                      8 + tlvs_length, reserved2)
    return hdr + body + payload


# DECT NR+ payloads for dect_nr (big endian, see dectnr_lib.py)
def phf1(nw_id=0x10, tx=0x1111):
    # Type 1 (40 bit) PHF
    return struct.pack('>BBHB', 0x00, nw_id, tx, 0x00)


def phf2(nw_id=0x10, tx=0x1111, rx=0x2222, fb=0):
    return struct.pack('>BBHBHBH', 0x00, nw_id, tx, 0x00, rx, 0x00, fb)


def mac_unicast(sn=1, rx=0x0a0b0c0d, tx=0x01020304, data=b'hello'):
    # MAC header type 2 (unicast), user plane data flow 1 IE (type 3)
    # holding a DLC service type 0 PDU (no routing header) with a CVG
    # header format 1 and a Data IE
    sdu = bytes([1 << 4]) + bytes([(1 << 6) | 1, len(data)]) + \
        struct.pack('>H', sn & 0xfff) + data
    return (bytes([0x02]) + struct.pack('>HII', sn & 0x0fff, rx, tx) +
            bytes([(1 << 6) | 3, len(sdu)]) + sdu)


ZERO_PAYLOAD = bytes(13)            # as in the reproducer: zero PHF + MAC
HI, LO = 0x11223344, 0x55667788


def clean_frames():
    f = []
    # 1-3: reproducer dect_nr_tap_modem_time.py (LO/HI, HI/LO, HI/HI)
    f.append(frame([tlv(DATA_TYPE, 1), tlv(MODEM_LO, LO), tlv(MODEM_HI, HI)],
                   ZERO_PAYLOAD))
    f.append(frame([tlv(DATA_TYPE, 1), tlv(MODEM_HI, HI), tlv(MODEM_LO, LO)],
                   ZERO_PAYLOAD))
    f.append(frame([tlv(DATA_TYPE, 1), tlv(MODEM_HI, HI), tlv(MODEM_HI, HI)],
                   ZERO_PAYLOAD))
    # 4: every TLV type, 40 bit PCC with a PDC, TX, reserved fields set
    f.append(frame([tlv(DATA_TYPE, 1), tlv(HEADER_STATUS, 0),
                    tlv(PCC_RSSI2, -87), tlv(PCC_SNR, 37),
                    tlv(PDC_RSSI2, -84), tlv(PDC_SNR, -13),
                    tlv(TRANSACTION_ID, 4242), tlv(CHANNEL, 1657),
                    tlv(TRACE_LINE, 123), tlv(MODEM_HI, 1),
                    tlv(MODEM_LO, 2), tlv(IS_TX, 1)],
                   phf1() + mac_unicast(1), version=2, reserved1=7,
                   reserved2=0x0102))
    # 5: 80 bit PCC with a PDC, RX
    f.append(frame([tlv(DATA_TYPE, 2), tlv(HEADER_STATUS, 0),
                    tlv(PCC_RSSI2, 20), tlv(PCC_SNR, -1),
                    tlv(PDC_RSSI2, 21), tlv(PDC_SNR, 6),
                    tlv(CHANNEL, 1659), tlv(IS_TX, 0)],
                   phf2() + mac_unicast(2, rx=0x01020304, tx=0x0a0b0c0d)))
    # 6: 40 bit PCC, PDC absent (PDC CRC error), RX ends before the PDC
    f.append(frame([tlv(DATA_TYPE, 3), tlv(HEADER_STATUS, 2),
                    tlv(PCC_RSSI2, -100), tlv(PCC_SNR, 10)], phf1()))
    # 7: 80 bit PCC, PDC absent, invalid header status
    f.append(frame([tlv(DATA_TYPE, 4), tlv(HEADER_STATUS, 1),
                    tlv(PCC_RSSI2, -60), tlv(PCC_SNR, 40)], phf2(fb=0)))
    # 8: PCC CRC error: no PCC or PDC, dect_nr is not called;
    #    unknown header status value
    f.append(frame([tlv(DATA_TYPE, 5), tlv(HEADER_STATUS, 7),
                    tlv(MODEM_LO, 1000), tlv(MODEM_HI, 0)], b''))
    # 9: unknown data type (40 bit default PHF), unknown TLV type with 4
    #    value octets, a TLV with length 6 (shown as invalid, used as 4)
    f.append(frame([tlv(DATA_TYPE, 9), tlv(99, b'\xde\xad\xbe\xef', 4),
                    tlv(TRACE_LINE, 77, length=6)], ZERO_PAYLOAD))
    # 10: unknown TLVs with lengths 0 and 2 (padding 4 and 2), no data
    #     type TLV (the 40 bit default)
    f.append(frame([tlv(200, b'\0\0\0\0', 0), tlv(201, b'\xab\xcd\0\0', 2)],
                   ZERO_PAYLOAD))
    # 11: modem time halves LO LO HI, then HI HI LO: the last of a half
    #     pairs with the other half
    f.append(frame([tlv(MODEM_LO, 1), tlv(MODEM_LO, 2), tlv(MODEM_HI, 3),
                    tlv(MODEM_HI, 4), tlv(MODEM_HI, 5), tlv(MODEM_LO, 6)],
                   ZERO_PAYLOAD))
    # 12: two complete modem times (LO HI, HI LO) and a lone HI
    f.append(frame([tlv(MODEM_LO, 0xffffffff), tlv(MODEM_HI, 0xffffffff),
                    tlv(MODEM_HI, 0), tlv(MODEM_LO, 0x80000000),
                    tlv(MODEM_HI, 9)], ZERO_PAYLOAD))
    # 13: only two TLVs (16 octets); the payload makes up the 72 octet
    #     minimum
    f.append(frame([tlv(DATA_TYPE, 2), tlv(IS_TX, 1)],
                   phf2(nw_id=0x20, tx=0x3333, rx=0x4444) +
                   mac_unicast(3, data=b'x' * 36), pad_to_64=False))
    # 14: no TLVs at all, 64 octets of DECT NR+ data
    f.append(frame([], phf1(nw_id=0x30) + mac_unicast(4, data=b'y' * 41),
                   pad_to_64=False))
    return f


def malformed_frames():
    f = []
    # 1: shorter than the 72 octet minimum: not DECT NR+ TAP
    f.append(frame([tlv(DATA_TYPE, 1)], b'', pad_to_64=False))
    # 2: 100 octets on the wire, none captured
    f.append((b'', 100))
    # 3: TLVs Length beyond the end of the packet
    f.append(frame([tlv(DATA_TYPE, 1)], b'', tlvs_length=200))
    # 4: TLVs Length not a multiple of 8: the last TLV runs into the
    #    payload and past the end
    f.append(frame([], bytes(68), pad_to_64=False, tlvs_length=68))
    # 5: a 16 bit TLV with length 0 takes 10 octets, so the TLVs overrun
    #    the TLVs Length
    f.append(frame([tlv(CHANNEL, 5, length=0)] * 8, b'', pad_to_64=False))
    # 6: 40 bit PCC with a truncated PHF
    f.append(frame([tlv(DATA_TYPE, 1)], b'\x00\x10', pad_to_64=True))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dect_nr_tap-coverage.pcap'), clean_frames())
    pcap(os.path.join(out, 'dect_nr_tap-coverage-malformed.pcap'),
         malformed_frames())


if __name__ == '__main__':
    main()

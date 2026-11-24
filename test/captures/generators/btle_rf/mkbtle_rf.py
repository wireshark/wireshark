#!/usr/bin/env python3
# Generates test/captures/btle_rf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-btle_rf.c coverage.
# Usage: mkbtle_rf.py <outdir>
# Writes btle_rf-coverage.pcap (main) and btle_rf-coverage-malformed.pcap,
# link type 256 (Bluetooth LE LL with the btle_rf pseudo header). Every
# packet is built here with struct; nothing is captured from a real
# network.
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
AA_ADV = 0x8e89bed6

# Pseudo header flags
DEWHITENED = 0x0001
SIGPOWER = 0x0002
NOISEPOWER = 0x0004
DECRYPTED = 0x0008
REF_AA = 0x0010
AA_OFFENSES = 0x0020
ALIASED = 0x0040
CRC_CHECKED = 0x0400
CRC_VALID = 0x0800
MIC_CHECKED = 0x1000
MIC_VALID = 0x2000


def pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 256))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000, i * 1250, len(p), len(p)) + p)


# BT LE CRC (bit by bit, LSB first; polynomial 0x00065B), sent with each
# octet bit reversed as packet-btle.c expects
def ble_crc(data, init=0x555555):
    def rev24(v):
        return int('{:024b}'.format(v)[::-1], 2)
    state = rev24(init)
    for b in data:
        for i in range(8):
            bit = ((b >> i) & 1) ^ (state & 1)
            state >>= 1
            if bit:
                state ^= 0xda6000
    # state now holds the CRC with its first transmitted bit in bit 0
    return state.to_bytes(3, 'little')


def ll(aa, pdu, ci=None):
    return struct.pack('<I', aa) + (bytes([ci]) if ci is not None else b'') + pdu + ble_crc(pdu)


def rf(chan, flags, pdu_type=0, aux=0, phy=0, sig=0, noise=0, aa_off=0, ref_aa=0):
    flags |= (pdu_type << 7) | (aux << 12) | (phy << 14)
    return struct.pack('<BbbBIH', chan, sig, noise, aa_off, ref_aa, flags)


def addr(n):
    return bytes([n, 0x00, 0x00, 0xdb, 0x0b, 0xc0])


AD = bytes([7, 0x09]) + b'RF-cov'


def adv(pdu_type, payload, chsel=0):
    return bytes([pdu_type | (chsel << 5), len(payload)]) + payload


def ext(flags, fields, data=b''):
    body = bytes([flags]) + fields
    return adv(0x07, bytes([len(body)]) + body + data)


def data(llid, payload, sn=0, nesn=0):
    return bytes([llid | (nesn << 2) | (sn << 3), len(payload)]) + payload


CONN_AA, CONN_CRC = 0x50654321, 0xaabbcc


def connect_ind():
    lld = struct.pack('<I', CONN_AA) + CONN_CRC.to_bytes(3, 'little') + b'\x02'
    lld += struct.pack('<HHHH', 3, 24, 0, 200) + b'\xff\xff\xff\xff\x1f' + b'\x25'
    return adv(0x05, addr(0x01) + addr(0x02) + lld, chsel=1)


def biginfo(seed):
    d = struct.pack('<IIBBBBB', 0x123 | (8 << 15) | (1 << 27), 2 | (100 << 8), 0, 4, 0x10, 0x40, 0)
    d = d[:11] + b'\x40\x00' + struct.pack('<I', seed) + struct.pack('<I', 10000) + \
        struct.pack('<H', 0x1234) + b'\xff\xff\xff\xff\x1f' + b'\x00\x00\x00\x00\x80'
    return bytes([len(d) + 1, 0x2c]) + d


def main():
    pkts = []
    ok = CRC_CHECKED | CRC_VALID
    # 1-8: RF channels: the three advertising channels, data channels on
    # both sides of channel 12, the last data channel and an illegal one
    # (AUX_SCAN_REQ on the data channels, ADV_NONCONN_IND elsewhere)
    for ch in (0, 12, 39, 1, 11, 13, 38, 40):
        if 0 < ch < 39 and ch != 12:
            pkts.append(rf(ch, ok) + ll(AA_ADV, adv(0x03, addr(0x16) + addr(0x10))))
        else:
            pkts.append(rf(ch, ok) + ll(AA_ADV, adv(0x02, addr(0x10) + AD)))
    # 9-13: signal and noise power, access address offenses and reference
    # access address in every combination that is not an error
    pkts.append(rf(0, ok | SIGPOWER | NOISEPOWER, sig=-45, noise=-95) + ll(AA_ADV, adv(0x02, addr(0x11))))
    pkts.append(rf(12, ok | AA_OFFENSES | REF_AA, ref_aa=AA_ADV) + ll(AA_ADV, adv(0x02, addr(0x11))))      # matched
    pkts.append(rf(12, ok | AA_OFFENSES | REF_AA, aa_off=1, ref_aa=AA_ADV) + ll(AA_ADV, adv(0x02, addr(0x11))))  # bit errors
    pkts.append(rf(39, ok | AA_OFFENSES) + ll(AA_ADV, adv(0x02, addr(0x11))))                              # no offenses, no reference
    pkts.append(rf(39, ok | REF_AA, ref_aa=AA_ADV) + ll(AA_ADV, adv(0x02, addr(0x11))))                   # reference only
    # 14-17: dewhitened, aliased channel, CRC not checked (calculated by
    # btle), CRC checked and invalid
    pkts.append(rf(0, ok | DEWHITENED | ALIASED) + ll(AA_ADV, adv(0x00, addr(0x12) + AD, chsel=1)))
    pkts.append(rf(0, 0) + ll(AA_ADV, adv(0x00, addr(0x12) + AD)))
    pkts.append(rf(0, CRC_CHECKED) + ll(AA_ADV, adv(0x00, addr(0x12) + AD)))
    pkts.append(rf(0, ok | CRC_VALID) + ll(AA_ADV, connect_ind()))
    # 18-21: PHYs: LE 2M, LE Coded with the coding indicator (S=8 and S=2),
    # reserved
    pkts.append(rf(5, ok, pdu_type=1, phy=1) + ll(AA_ADV, ext(0x01, addr(0x13), AD)))
    pkts.append(rf(5, ok, pdu_type=1, phy=2) + ll(AA_ADV, ext(0x01, addr(0x13), AD), ci=0))
    pkts.append(rf(5, ok, pdu_type=1, phy=2) + ll(AA_ADV, ext(0x01, addr(0x13), AD), ci=1))
    pkts.append(rf(5, ok, pdu_type=1, phy=3) + ll(AA_ADV, ext(0x01, addr(0x13), AD)))
    # 22-25: auxiliary advertising PDU types (AUX_ADV_IND, AUX_CHAIN_IND,
    # AUX_SYNC_IND, AUX_SCAN_RSP): bits 12-13, the MIC flags of data PDUs
    for aux in range(4):
        pkts.append(rf(7, ok, pdu_type=1, aux=aux) +
                    ll(AA_ADV, ext(0x01 | (0x40 if aux else 0), addr(0x14) + (b'\x08' if aux else b''), AD)))
    # 26-31: data on the connection, both directions, decrypted with the
    # MIC checked (valid and invalid), and with unspecified direction
    pkts.append(rf(9, ok, pdu_type=2) + ll(CONN_AA, data(1, b'')))
    pkts.append(rf(9, ok | DECRYPTED | MIC_CHECKED | MIC_VALID, pdu_type=3) + ll(CONN_AA, data(3, b'\x12', 0, 1)))
    pkts.append(rf(9, ok | DECRYPTED | MIC_CHECKED | MIC_VALID, pdu_type=2) + ll(CONN_AA, data(3, b'\x13', 1, 1)))
    pkts.append(rf(9, ok | DECRYPTED | MIC_CHECKED, pdu_type=3) + ll(CONN_AA, data(2, struct.pack('<HH', 5, 4) + b'\x1b\x03\x00\x01\x02', 1, 0)))
    pkts.append(rf(9, ok, pdu_type=0) + ll(CONN_AA, data(1, b'', 0, 0)))
    pkts.append(rf(9, ok, pdu_type=7) + ll(CONN_AA, data(1, b'', 1, 1)))          # reserved: guessed
    # 32-33: connected isochronous, both directions
    pkts.append(rf(11, ok, pdu_type=4) + ll(0x3c3c5a01, data(0, b'\x01\x02')))
    pkts.append(rf(11, ok, pdu_type=5) + ll(0x3c3c5a01, data(0, b'\x03\x04')))
    # 34-36: periodic BIGInfo, then broadcast isochronous by PDU type and
    # by access address (unspecified PDU type)
    bi = biginfo(0x00415555)
    pkts.append(rf(39, ok) + ll(AA_ADV, adv(0x07, bytes([1 + 6 + len(bi)]) + b'\x01' + addr(0x15) + bi)))
    pkts.append(rf(13, ok, pdu_type=6) + ll(0x00415555, data(0, b'\x05\x06')))
    pkts.append(rf(13, ok, pdu_type=0) + ll(0x00415555, data(3, b'\x01\x13\x09\x00')))
    pcap(OUT + '/btle_rf-coverage.pcap', pkts)

    bad = []
    # Shorter than the pseudo header: not dissected as btle_rf
    for n in (0, 1, 9):
        bad.append((rf(0, ok) + ll(AA_ADV, adv(0x02, addr(0x10))))[:n])
    # Pseudo header only, no access address
    bad.append(rf(0, ok))
    # AccessAddress offenses without a reference address: illegal
    bad.append(rf(0, ok | AA_OFFENSES, aa_off=4) + ll(AA_ADV, adv(0x02, addr(0x10))))
    # Coded PHY, cut in the coding indicator
    bad.append(rf(0, ok, phy=2) + struct.pack('<I', AA_ADV))
    pcap(OUT + '/btle_rf-coverage-malformed.pcap', bad)


main()

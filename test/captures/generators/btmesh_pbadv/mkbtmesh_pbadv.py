#!/usr/bin/env python3
# Generates test/captures/btmesh_pbadv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Bluetooth Mesh PB-ADV coverage captures for
packet-btmesh-pbadv.c.

Usage: mkbtmesh_pbadv.py <outdir>

Writes btmesh_pbadv-coverage.pcap (main capture) and
btmesh_pbadv-coverage-malformed.pcap.

Every packet is built with struct: Bluetooth LE Link Layer (DLT 251)
ADV_NONCONN_IND advertising PDUs with a valid CRC, each carrying one PB-ADV
AD structure (AD type 0x29).  The provisioner advertises as
02:00:00:00:00:01, the device as 02:00:00:00:00:10.
"""
import os
import struct
import sys

PROVISIONER = 0x01
DEVICE = 0x10


def ble_crc(pdu, init=0x555555):
    state = int('{:024b}'.format(init)[::-1], 2)
    for byte in pdu:
        for _ in range(8):
            nb = (state ^ byte) & 1
            byte >>= 1
            state >>= 1
            if nb:
                state |= 1 << 23
                state ^= 0x5a6000
    return struct.pack('<I', state)[:3]


def ble_adv(advdata, n):
    adva = bytes([n, 0x00, 0x00, 0x00, 0x00, 0x02])
    payload = adva + advdata
    pdu = bytes([0x02, len(payload)]) + payload          # ADV_NONCONN_IND
    return struct.pack('<I', 0x8E89BED6) + pdu + ble_crc(pdu)


def ad(t, data):
    return bytes([len(data) + 1, t]) + data


def fcs(data):
    """Provisioning PDU FCS (3GPP TS 27.010 CRC-8)."""
    crc = 0xff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xe0 if crc & 1 else crc >> 1
    return 0xff - crc


# PB-ADV PDUs ------------------------------------------------------------
def pbadv(link, trn, gp):
    return struct.pack('>IB', link, trn) + gp


def link_open(link, uuid):
    return pbadv(link, 0, bytes([(0 << 2) | 3]) + uuid)


def link_ack(link):
    return pbadv(link, 0, bytes([(1 << 2) | 3]))


def link_close(link, reason):
    return pbadv(link, 0, bytes([(2 << 2) | 3, reason]))


def tr_ack(link, trn):
    return pbadv(link, trn, bytes([0x01]))


def tr_start(link, trn, segn, total, data, fcsv=None):
    f = fcs(data) if fcsv is None else fcsv
    return pbadv(link, trn, bytes([(segn << 2) | 0]) + struct.pack('>HB', total, f))


def transaction(link, trn, prov):
    """Split a Provisioning PDU into Transaction Start (20 octets) and
    Continuation (23 octets) PDUs."""
    segs = [prov[:20]] + [prov[i:i + 23] for i in range(20, len(prov), 23)]
    segn = len(segs) - 1
    out = [tr_start(link, trn, segn, len(prov), prov) + segs[0]]
    for i, s in enumerate(segs[1:], 1):
        out.append(pbadv(link, trn, bytes([(i << 2) | 2]) + s))
    return out


UUID = bytes.fromhex("70cf7c9732a345b691494810d2e9cbf4")
INVITE = bytes([0x00, 0x05])
CAPS = bytes([0x01, 0x01]) + struct.pack('>H', 1) + bytes([0, 0, 0]) + \
    struct.pack('>H', 0) + bytes([0]) + struct.pack('>H', 0)
START = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
PUBKEY_D = bytes([0x03]) + bytes(range(0x41, 0x81))
INPUT_COMPLETE = bytes([0x04])
CONFIRMATION = bytes([0x05]) + bytes(range(0xa0, 0xb0))
RANDOM = bytes([0x06]) + bytes(range(0xb0, 0xc0))
DATA = bytes([0x07]) + bytes(range(0xc0, 0xe1))
COMPLETE = bytes([0x08])
FAILED = bytes([0x09, 0x04])


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 251))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main_capture(path):
    P, D = PROVISIONER, DEVICE
    f = []
    add = lambda n, pdu: f.append(ble_adv(ad(0x29, pdu), n))
    A = 0x0A0B0C0D
    add(P, link_open(A, UUID))                                    # 1
    add(D, link_ack(A))                                           # 2
    # 3-5: reproducer of btmesh_pbadv_onepass.py: a 65 octet
    # Public Key PDU in a Transaction Start and two Continuations,
    # reassembled and dissected on the first pass (FCS 0x00 as in the
    # reproducer, the dissector does not check it)
    prov = bytes([0x03]) + bytes(range(1, 65))
    link = struct.pack('>IB', A, 0x00)
    segs = [prov[0:20], prov[20:43], prov[43:]]
    add(P, link + bytes([(2 << 2) | 0x00]) + struct.pack('>H', len(prov)) + b'\x00' + segs[0])
    add(P, link + bytes([(1 << 2) | 0x02]) + segs[1])
    add(P, link + bytes([(2 << 2) | 0x02]) + segs[2])
    add(D, tr_ack(A, 0x00))                                       # 6
    # 7-8: unsegmented Transaction Start (SegN 0): Provisioning Invite
    add(P, tr_start(A, 0x01, 0, len(INVITE), INVITE) + INVITE)
    add(D, tr_ack(A, 0x01))
    # 9-10: Capabilities from the device
    add(D, tr_start(A, 0x80, 0, len(CAPS), CAPS) + CAPS)
    add(P, tr_ack(A, 0x80))
    # 11-12: Start
    add(P, tr_start(A, 0x02, 0, len(START), START) + START)
    add(D, tr_ack(A, 0x02))
    # 13-15: device Public Key with the Transaction Start last: the
    # Continuations come first and the Start completes the reassembly
    t = transaction(A, 0x81, PUBKEY_D)
    for p in (t[2], t[1], t[0]):
        add(D, p)
    add(P, tr_ack(A, 0x81))                                       # 16
    add(D, tr_start(A, 0x82, 0, 1, INPUT_COMPLETE) + INPUT_COMPLETE)   # 17
    add(P, tr_start(A, 0x03, 0, len(CONFIRMATION), CONFIRMATION) + CONFIRMATION)  # 18
    add(D, tr_start(A, 0x83, 0, len(CONFIRMATION), CONFIRMATION) + CONFIRMATION)  # 19
    add(P, tr_start(A, 0x04, 0, len(RANDOM), RANDOM) + RANDOM)    # 20
    add(D, tr_start(A, 0x84, 0, len(RANDOM), RANDOM) + RANDOM)    # 21
    # 22-23: Provisioning Data
    for p in transaction(A, 0x05, DATA):
        add(P, p)
    add(D, tr_ack(A, 0x05))                                       # 24
    add(D, tr_start(A, 0x85, 0, 1, COMPLETE) + COMPLETE)          # 25
    add(P, link_close(A, 0))                                      # 26
    # 27-30: reproducer of btmesh_pbadv_retransmit.py:
    # Transaction Start and Continuation sent again after the reassembly
    # completed
    B = 0x0A0B0C0F
    prov = bytes([0x07]) + bytes(range(1, 34))
    link = struct.pack('>IB', B, 0x02)
    start = link + bytes([(1 << 2) | 0x00]) + struct.pack('>H', len(prov)) + b'\x00' + prov[:20]
    cont = link + bytes([(1 << 2) | 0x02]) + prov[20:]
    for p in (start, cont, start, cont):
        add(3, p)
    # 31-37: two links interleaved, the same Transaction Number on both;
    # the first Continuation of link C is repeated before its reassembly
    # completes (same data: an overlap, no conflict)
    C, E = 0x11111111, 0x22222222
    add(P, link_open(C, bytes(range(16))))
    tc = transaction(C, 0x00, PUBKEY_D)
    te = transaction(E, 0x00, DATA)
    add(4, te[0])
    add(P, tc[0])
    add(4, te[1])
    add(P, tc[1])
    add(P, tc[1])
    add(P, tc[2])
    # 38-41: Provisioning Failed, Link Close with Timeout and Fail
    add(D, tr_start(C, 0x80, 0, len(FAILED), FAILED) + FAILED)
    add(P, link_close(C, 1))
    add(4, link_close(E, 2))
    add(D, link_ack(C))
    write_pcap(path, f)


def malformed_capture(path):
    f = []
    add = lambda n, pdu: f.append(ble_adv(ad(0x29, pdu), n))
    # 1-3: reproducer of btmesh_pbadv_segidx0.py: a
    # Continuation with Segment Index 0 (error expert, not reassembled)
    prov = bytes([0x05]) + bytes(range(1, 17)) + bytes(range(0x40, 0x4d))
    link = struct.pack('>IB', 0x0A0B0C0E, 0x01)
    for p in (link + bytes([(0 << 2) | 0x02]) + b'\xee' * 23,
              link + bytes([(1 << 2) | 0x00]) + struct.pack('>H', len(prov)) + b'\x00' + prov[:20],
              link + bytes([(1 << 2) | 0x02]) + prov[20:]):
        add(2, p)
    # 4: reproducer of btmesh_pbadv_unsegmented_start.py:
    # unsegmented Provisioning Invite without its attention octet
    add(1, struct.pack('>IB', 0x11223344, 0x00) + bytes([0x00]) + struct.pack('>H', 1) +
        bytes([0x00]) + bytes([0x00]))
    L = 0x33333333
    add(1, pbadv(L, 0, bytes([(5 << 2) | 3]) + b'\x01\x02'))     # 5: unknown bearer opcode
    add(1, pbadv(L, 0, bytes([(1 << 2) | 3]) + b'\x01'))         # 6: Link ACK with data
    add(1, pbadv(L, 0, bytes([(2 << 2) | 3, 0, 0])))             # 7: Link Close, extra octet
    add(1, pbadv(L, 0, bytes([(0 << 2) | 3]) + UUID[:8]))        # 8: Link Open cut short
    add(1, pbadv(L, 0, bytes([(2 << 2) | 3])))                   # 9: Link Close, no reason
    add(1, struct.pack('>IB', L, 0))                             # 10: no Generic Provisioning PDU
    add(1, pbadv(L, 1, bytes([0x00, 0x00])))                     # 11: Transaction Start cut short
    # 12-13: total length shorter than the segments
    t = transaction(L, 2, DATA)
    add(1, tr_start(L, 2, 1, 21, DATA) + DATA[:20])
    add(1, t[1])
    # 14-15: segmented PDU with an unknown Provisioning PDU type
    bad = bytes([0x3f]) + bytes(30)
    for p in transaction(L, 3, bad):
        add(1, p)
    # 16: unsegmented Transaction Start with no payload
    add(1, tr_start(L, 4, 0, 0, b''))
    write_pcap(path, f)


def main(outdir):
    main_capture(os.path.join(outdir, 'btmesh_pbadv-coverage.pcap'))
    malformed_capture(os.path.join(outdir, 'btmesh_pbadv-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

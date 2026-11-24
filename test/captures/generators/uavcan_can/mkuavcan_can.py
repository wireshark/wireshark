#!/usr/bin/env python3
# Generates test/captures/uavcan_can_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UAVCAN/CAN (v1, Cyphal/CAN) captures (packet-uavcan-can.c).

Usage: mkuavcan_can.py <outdir>

Writes uavcan-can-coverage.pcap (clean frames) and
uavcan-can-coverage-malformed.pcap (frames that only malformed input
reaches), both SocketCAN (link type 227). UAVCAN/CAN is not reached by
default: it registers no CAN ID and no heuristic, only a Decode As entry
for the CAN next level dissector table, so the tests and runcov.sh set
Decode As "can.subdissector == 0" to UAVCAN/CAN.
"""
import struct
import sys
import os

S = struct.pack
EFF = 0x80000000
ERR = 0x20000000


def pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(S('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 227))
        for i, fr in enumerate(frames):
            f.write(S('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)


def can(cid, data, eff=True, fd=False, flags=0):
    """SocketCAN frame: classic (16 octets) or CAN FD (72 octets)."""
    n = len(data)
    if fd:
        return S('>IBBBB', cid | (EFF if eff else 0), n, flags, 0, 0) + data.ljust(64, b'\0')
    assert n <= 8
    return S('>IBBBB', cid | (EFF if eff else 0), n, 0, 0, 0) + data.ljust(8, b'\0')


def msg_id(subject, src, prio=4, anon=False):
    return (prio << 26) | (int(anon) << 24) | (subject << 8) | src


def svc_id(service, dst, src, req, prio=4):
    return (prio << 26) | (1 << 25) | (int(req) << 24) | (service << 14) | (dst << 7) | src


def tail(sot, eot, toggle, tid):
    return bytes([(sot << 7) | (eot << 6) | (toggle << 5) | (tid & 31)])


def crc16(data, init=0xffff):
    """CRC-16/CCITT-FALSE as used by Cyphal for multi-frame transfers."""
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def single(cid, payload, tid=0, fd=False):
    return can(cid, payload + tail(1, 1, 1, tid), fd=fd)


def multi(cid, payload, tid=0, mtu=7, fd=False, crc=None, bad_toggle_at=None):
    """Frames of a multi-frame transfer; the CRC follows the payload."""
    c = crc16(payload) if crc is None else crc
    stream = payload + S('>H', c)
    chunks = [stream[i:i + mtu] for i in range(0, len(stream), mtu)]
    out = []
    toggle = 1
    for i, ch in enumerate(chunks):
        t = toggle ^ (1 if bad_toggle_at == i else 0)
        out.append(can(cid, ch + tail(i == 0, i == len(chunks) - 1, t, tid), fd=fd))
        toggle ^= 1
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []
    # --- single frame messages (classic CAN) ---
    F.append(single(msg_id(7509, 5), S('<IBBB', 1234567, 0, 0, 7), 1))                 # 1 Heartbeat
    F.append(single(msg_id(7509, 6, prio=0), S('<IBBB', 99, 3, 3, 0), 2))              # 2 Heartbeat, other health/mode
    F.append(single(msg_id(8166, 0, prio=7, anon=True), bytes([1, 2, 3, 4, 5, 6, 0]), 3))  # 3 node ID allocation request (anonymous)
    F.append(single(msg_id(100, 9, prio=2), b'\x01\x02\x03', 4))                       # 4 unknown subject id, "Reserved" name
    F.append(single(msg_id(0, 10, prio=1), b'', 5))                                    # 5 tail byte only
    F.append(single(msg_id(8191, 11, prio=3), b'\xff' * 7, 31))                        # 6 maximum subject id
    # --- single frame messages (CAN FD) ---
    F.append(single(msg_id(8166, 0, anon=True), bytes([1, 2, 3, 4, 5, 6, 0, 42, 0, 0, 0]), 6, fd=True))      # 7 with node id
    F.append(single(msg_id(8165, 0, prio=7, anon=True), S('<H', 0xffff) + bytes(range(16)), 7, fd=True))      # 8 NodeIDAllocationData 2.0 request
    F.append(single(msg_id(8165, 21, prio=7), S('<H', 42) + bytes(range(16)), 8, fd=True))                    # 9 allocation response
    F.append(single(msg_id(8184, 12), S('<Q', 1700000000123456)[:7] + b'\x02' + b'\x05hello', 9, fd=True))    # 10 Synchronization / diagnostic
    # --- single frame services ---
    F.append(single(svc_id(384, 5, 6, True), b'\x03abc' + b'\x00\x00', 10))                 # 11 Access request, empty value
    F.append(single(svc_id(384, 6, 5, False), bytes(7) + b'\x00\x00\x00', 11, fd=True))          # 12 Access response
    F.append(single(svc_id(385, 5, 6, True), S('<H', 3), 12))                           # 13 List request
    F.append(single(svc_id(385, 6, 5, False), b'\x04name', 13))                         # 14 List response
    F.append(single(svc_id(405, 5, 6, True), b'\x05/path', 14))                         # 15 GetInfo request
    F.append(single(svc_id(405, 6, 5, False), S('<HQ', 0, 4096)[:7] + S('<Q', 1700000000)[:5] + b'\x00\x0f', 15, fd=True))  # 16 GetInfo response
    F.append(single(svc_id(406, 5, 6, True), S('<IIB', 1, 0, 3) + b'dir', 16, fd=True))  # 17 List.0.X request
    F.append(single(svc_id(406, 6, 5, False), b'\0\0\0\0\x04file', 17, fd=True))          # 18 List.0.X response
    F.append(single(svc_id(407, 5, 6, True), b'\x03\0\0\0\x03src\x03dst', 18, fd=True))   # 19 Modify request
    F.append(single(svc_id(407, 6, 5, False), S('<H', 2), 19))                          # 20 Modify response
    F.append(single(svc_id(408, 5, 6, True), S('<Q', 100)[:5] + b'\x04path', 20, fd=True))  # 21 Read request
    F.append(single(svc_id(408, 6, 5, False), S('<HH', 0, 3) + b'xyz', 21, fd=True))      # 22 Read response
    F.append(single(svc_id(409, 5, 6, True), S('<Q', 0)[:5] + b'\x04path' + S('<H', 3) + b'abc', 22, fd=True))  # 23 Write request
    F.append(single(svc_id(409, 6, 5, False), S('<H', 13), 23))                         # 24 Write response
    F.append(single(svc_id(434, 5, 6, True), b'\x01', 24))                              # 25 service without a DSDL decoder
    # --- multi-frame transfers ---
    # 26-28: Heartbeat-sized message with a CRC, three frames of 7
    F += multi(msg_id(7509, 5), S('<IBBB', 5, 1, 1, 1) + b'\x11' * 9, 3)                 # 26-28
    # 29-31: Write request in three frames, interleaved with a second transfer
    a = multi(svc_id(409, 5, 6, True), S('<Q', 0)[:5] + b'\x04path' + S('<H', 12) + b'abcdefghijkl', 4)
    b = multi(msg_id(100, 9), bytes(range(20)), 5)
    for x, y in zip(a, b):
        F += [x, y]
    F += a[len(b):] + b[len(a):]
    # CAN FD multi-frame transfer, two frames of 63 octets
    F += multi(svc_id(408, 6, 5, False), S('<HH', 0, 100) + bytes(range(100)), 6, mtu=63, fd=True)
    # service response in two frames with a transfer id of 31
    F += multi(svc_id(405, 6, 5, False), S('<HQ', 0, 4096)[:7] + S('<Q', 1700000000)[:5] + b'\x00\x0f', 31)
    # a transfer id reused by a second transfer from the same source
    F += multi(msg_id(7509, 5), S('<IBBB', 6, 0, 0, 0) + b'\x22' * 9, 3)
    # CRC split across the last two frames
    F += multi(msg_id(100, 14), bytes(range(6)), 8)
    # --- frames the dissector refuses ---
    F.append(can(msg_id(7509, 5), S('<IBBB', 1, 0, 0, 0) + b'\x81'))                  # version 0 frame (start, no toggle)
    F.append(can(0x123, b'\x01\x02\x03\x04', eff=False))                                # standard identifier
    F.append(can(msg_id(7509, 5) | ERR, b'\x00' * 8))                                   # error frame
    F.append(can(msg_id(7509, 31), b'\x01\x02\x03\x04\x05\x06\x07\x21'))            # middle frame of an unknown transfer
    # --- reproducer of the fixed NULL dereference: a middle frame that was
    # refused on the first pass and a later start frame with the same lookup
    # id, which makes the first frame acceptable on a later pass ---
    cid = msg_id(100, 5)
    F.append(can(cid, b'\x11\x22\x01'))
    F.append(can(cid, b'\x33\x44\xa1'))
    pcap(os.path.join(out, 'uavcan-can-coverage.pcap'), F)

    M = []
    # toggle bit error: the second frame repeats the toggle of the first
    M += multi(msg_id(7509, 7), S('<IBBB', 5, 1, 1, 1) + b'\x11' * 9, 4, bad_toggle_at=1)
    # CRC error
    M += multi(msg_id(7509, 8), S('<IBBB', 5, 1, 1, 1) + b'\x11' * 9, 5, crc=0x1234)
    # reassembled payload shorter than the CRC (fixed): a start frame without
    # payload and an end frame with one octet
    cid = msg_id(7509, 5)
    M += [can(cid, b'\xa2'), can(cid, b'\x41\x42')]
    # end frame that starts a transfer: start frame with the end bit is a
    # single frame; a start frame followed directly by an end frame with
    # no payload (reassembled length zero)
    cid = msg_id(7509, 9)
    M += [can(cid, b'\xa3'), can(cid, b'\x63')]
    # an empty frame (no tail byte)
    M += [can(msg_id(7509, 12), b'')]
    pcap(os.path.join(out, 'uavcan-can-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()

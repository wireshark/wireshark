#!/usr/bin/env python3
# Generates test/captures/uavcan_dsdl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UAVCAN DSDL captures (packet-uavcan-dsdl.c).

Usage: mkuavcan_dsdl.py <outdir>

Writes uavcan-dsdl-coverage.pcap (clean frames) and
uavcan-dsdl-coverage-malformed.pcap (frames that only malformed input
reaches), both SocketCAN (link type 227). The DSDL dissectors have no
port, table or heuristic of their own: they are called by UAVCAN/CAN
with the subject or service id for the single frame and the reassembled
multi-frame payloads, and UAVCAN/CAN itself is reached only through
Decode As (CAN next level dissector 0 = UAVCAN/CAN), which the tests
and runcov.sh set.
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
    tid = [0]

    def sf(cid, payload, fd=True):
        F.append(single(cid, payload, tid[0] & 31, fd=fd))
        tid[0] += 1

    def mf(cid, payload, **kw):
        F.extend(multi(cid, payload, tid[0] & 31, **kw))
        tid[0] += 1

    def pstr(b):
        return bytes([len(b)]) + b

    # ---- messages ----
    for health, mode in ((0, 0), (1, 1), (2, 2), (3, 3)):                       # 1-4 Heartbeat
        sf(msg_id(7509, 5 + health), S('<IBBB', 1000 * (health + 1), health, mode, health * 17), fd=False)
    sf(msg_id(8166, 0, anon=True), bytes([1, 2, 3, 4, 5, 6, 0]), fd=False)         # 5 PnP v1, no node id
    sf(msg_id(8166, 0, anon=True), bytes([1, 2, 3, 4, 5, 6, 0, 42, 0, 0]))         # 6 PnP v1 with node id (> 8 octets)
    sf(msg_id(8166, 42, anon=False), bytes([6, 5, 4, 3, 2, 1, 1, 17, 0]))          # 7 PnP v1 response, 9 octets
    sf(msg_id(8165, 0, prio=7, anon=True), S('<H', 0xffff) + bytes(range(16)))     # 8 PnP v2 request (anonymous)
    sf(msg_id(8165, 21, prio=7), S('<H', 42) + bytes(range(16, 32)))               # 9 PnP v2 response
    for sev in range(8):                                                           # 10-17 Synchronization, every severity
        sf(msg_id(8184, 12 + sev), S('<Q', 1700000000123456 + sev)[:7] + bytes([sev]) + pstr(b'text%d' % sev))
    sf(msg_id(100, 20), b'\x01\x02\x03')                                          # 18 unhandled subject
    # ---- service requests and responses ----
    def rq(svc, payload, fd=True):
        sf(svc_id(svc, 5, 6, True), payload, fd=fd)

    def rs(svc, payload, fd=True):
        sf(svc_id(svc, 6, 5, False), payload, fd=fd)

    # Access.1.0 request: register name then a Value
    name = pstr(b'uavcan.node.id')
    rq(384, name + b'\x00\x00')                                                    # 19 empty (the decoder reads one more octet)
    rq(384, name + b'\x01' + pstr(b'a string value'))                              # 20 string
    rq(384, name + b'\x02')                                                        # 21 unstructured
    rq(384, name + b'\x03')                                                        # 22 bit array
    rq(384, name + b'\x04\x00')                                                    # 23 int64 array, size 0 (Empty)
    rq(384, name + b'\x04\x02' + S('<qq', -5, 1 << 40))                            # 24 Integer64
    rq(384, name + b'\x05\x03' + S('<iii', -1, 2, 3))                              # 25 Integer32
    rq(384, name + b'\x06\x03' + S('<hhh', -1, 2, 3))                              # 26 Integer16
    rq(384, name + b'\x07\x04' + S('<bbbb', -1, 2, 3, 4))                          # 27 Integer8
    rq(384, name + b'\x08\x02' + S('<QQ', 1, 1 << 63))                             # 28 Natural64
    rq(384, name + b'\x09\x03' + S('<III', 1, 2, 3))                               # 29 Natural32
    rq(384, name + b'\x0a\x03' + S('<HHH', 1, 2, 3))                               # 30 Natural16
    rq(384, name + b'\x0b\x05' + bytes([1, 2, 3, 4, 5]))                           # 31 Natural8
    rq(384, name + b'\x0c\x02' + S('<dd', 1.5, -2.25))                             # 32 Real64
    rq(384, name + b'\x0d\x03' + S('<fff', 1.5, -2.25, 0.0))                       # 33 Real32
    rq(384, name + b'\x0e\x02' + S('<HH', 0x3c00, 0x4000))                         # 34 Real16
    rq(384, name + b'\x0f\x01\x00')                                                # 35 tag outside the table (Empty)
    # Access.1.0 response: timestamp, flags, value
    rs(384, S('<Q', 1700000000000000)[:7] + b'\x03' + b'\x04\x01' + S('<q', -7))   # 36 mutable, persistent, Integer64
    rs(384, bytes(7) + b'\x00' + b'\x01' + pstr(b'text'))                           # 37 string, not mutable
    rs(384, bytes(7) + b'\x01' + b'\x00\x00')                                       # 38 empty
    # List.1.0
    rq(385, S('<H', 7))                                                             # 39
    rs(385, pstr(b'uavcan.pub.heartbeat.id'))                                        # 40
    # GetInfo.0.X (file server)
    rq(405, pstr(b'/etc/config.bin'))                                               # 41
    for k, flags in enumerate((0x0f, 0x00, 0x05, 0x0a)):                            # 42-45
        rs(405, S('<H', (0, 2, 13, 65535)[k]) + (4096 << k).to_bytes(5, 'little')
           + (1700000000 + k).to_bytes(5, 'little') + b'\x00' + bytes([flags]))
    # List.0.X
    rq(406, S('<I', 3) + b'\0\0\0\0' + pstr(b'/etc'))                               # 46
    rs(406, b'\0\0\0\0' + pstr(b'config.bin'))                                      # 47
    # Modify.1.X
    rq(407, bytes([3, 0, 0, 0]) + pstr(b'/tmp/a') + pstr(b'/tmp/b'))                 # 48
    rq(407, bytes([0, 0, 0, 0]) + pstr(b'') + pstr(b'x'))                           # 49
    for k, err in enumerate((0, 21, 22, 27, 28, 38)):                               # 50-55
        rs(407, S('<H', err))
    # Read.1.X
    rq(408, (1000).to_bytes(5, 'little') + pstr(b'/etc/config.bin'))                # 56
    rs(408, S('<HH', 0, 5) + b'hello')                                              # 57
    rs(408, S('<HH', 5, 0))                                                         # 58
    # Write.1.X
    rq(409, (0).to_bytes(5, 'little') + pstr(b'/tmp/out') + S('<H', 6) + b'abcdef')  # 59
    rq(409, (6).to_bytes(5, 'little') + pstr(b'/tmp/out') + S('<H', 0))             # 60
    rs(409, S('<H', 0))                                                             # 61
    rs(409, S('<H', 65535))                                                         # 62
    # unhandled services
    rq(100, b'\x01\x02')                                                            # 63
    rs(100, b'\x01\x02')                                                            # 64
    rq(300, b'\x01', fd=False)                                                     # 65
    # ---- multi-frame transfers, so the DSDL dissectors get reassembled data ----
    mf(svc_id(409, 5, 6, True), (0).to_bytes(5, 'little') + pstr(b'/tmp/big') + S('<H', 40) + bytes(range(40)))
    mf(svc_id(408, 6, 5, False), S('<HH', 0, 30) + bytes(range(30)))
    mf(msg_id(8184, 3), S('<Q', 1700000001000000)[:7] + b'\x02' + pstr(b'multi-frame diagnostic text'))
    mf(svc_id(384, 5, 6, True), name + b'\x06\x04' + S('<hhhh', 1, 2, 3, 4))
    mf(svc_id(384, 6, 5, False), bytes(7) + b'\x03' + b'\x0d\x02' + S('<ff', 1.5, 2.5))
    mf(svc_id(406, 5, 6, True), S('<I', 9) + b'\0\0\0\0' + pstr(b'/etc/long/directory/name'))
    pcap(os.path.join(out, 'uavcan-dsdl-coverage.pcap'), F)

    M = []
    # payloads shorter than the fields the decoders read
    for sid, body in ((7509, b'\x01\x02'), (8166, b'\x01\x02\x03'), (8165, b'\x01\x02\x03'),
                      (8184, b'\x01\x02\x03')):
        M.append(single(msg_id(sid, 5), body, 1))
    for svc, req, body in ((384, True, b''), (384, False, b'\x01\x02'), (385, True, b''),
                           (385, False, b''), (405, True, b''), (405, False, b'\x01'),
                           (406, True, b'\x01'), (406, False, b'\x01'), (407, True, b'\x01'),
                           (407, False, b''), (408, True, b'\x01'), (408, False, b''),
                           (409, True, b'\x01'), (409, False, b'')):
        M.append(single(svc_id(svc, 5, 6, req), body, 2))
    # Empty value tag at the very end of the payload: the decoder reads the next octet
    M.append(single(svc_id(384, 5, 6, True), b'\x03abc\x00', 3))
    M.append(single(svc_id(384, 6, 5, False), bytes(7) + b'\x01\x00', 3, fd=True))
    # Access request with a string longer than the frame, array larger than the data
    M.append(single(svc_id(384, 5, 6, True), b'\x10abc', 3))
    M.append(single(svc_id(384, 5, 6, True), b'\x01a\x04\x05' + S('<q', 1), 3, fd=True))
    # Write request and Read response whose data length is larger than the frame
    M.append(single(svc_id(409, 5, 6, True), (0).to_bytes(5, 'little') + b'\x01a' + S('<H', 500) + b'xyz', 4, fd=True))
    M.append(single(svc_id(408, 6, 5, False), S('<HH', 0, 500) + b'xyz', 4, fd=True))
    # Modify request whose destination path is missing
    M.append(single(svc_id(407, 5, 6, True), bytes([1, 0, 0, 0]) + b'\x03src', 5, fd=True))
    pcap(os.path.join(out, 'uavcan-dsdl-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main()

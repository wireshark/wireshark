#!/usr/bin/env python3
# Generates test/captures/ecpri_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the eCPRI dissector
(packet-ecpri.c, eCPRI specification V2.0).

eCPRI runs directly over Ethernet with ethertype 0xAEFE. Every message
has a 4 octet common header (revision, C bit for a further message in
the same frame, message type, payload size); concatenated messages are
aligned on 4 octets. Message types 0 (IQ data) and 2 (real-time
control) are passed to the O-RAN FH CUS dissector as well; types 0-8
and 11 are decoded by eCPRI, 9 and 10 are not, and reserved and vendor
specific types are skipped. One-way delay measurements are matched by
measurement ID to calculate the delay. Every packet is built from
scratch with struct; no captured traffic is used. The O-RAN C-plane
and U-plane payloads are the first two (also synthetic) messages of
the O-RAN coverage capture (test/captures/oran_coverage.pcap.gz).

Usage: mkecpri.py <output directory>

Writes:
  ecpri-coverage.pcap            every message type and action/event
                                 type, delay measurement exchanges,
                                 concatenated messages with alignment,
                                 a frame too short for eCPRI, and the
                                 reproducer of the IWF Operation fix
  ecpri-coverage-malformed.pcap  error expert infos: payload sizes too
                                 small or too big, bad data lengths,
                                 time stamps, faults and notifications,
                                 delay control action types, a last C
                                 bit set, payloads past the frame
"""

import os
import struct
import sys

DU = bytes.fromhex('020000000001')
RU = bytes.fromhex('020000000002')

# O-RAN C-plane (section type 1, two sections) and the U-plane message
# that follows it: payloads after the eCPRI common header.
ORAN_C = bytes.fromhex('01000080900120400201000000100004fffe000a00200404fffe000b')
ORAN_U = bytes.fromhex(
    '0100008090012040001000049100040181414100886c30260f8c44c3c1691c68'
    '521d9748468249cca07e04020181611090703227100c84e3d171206a531e1788'
    '669251d0a27f040281c1812098743428108cc503e179246c541e97c886a259d4'
    'a48004030201a130a0783629110d0523f181286e551f1808a6b261d8a6810020'
    '04049100040583424180c88c402e138e45c441a93c785a219949470289ecb086'
    '040603826190d090422f140e85e451b1407a5b221989671291f0b287040683c2'
    '81a0d8944430148ec60461b9447c5c2299c9872299f4b48804070402a1b0e098'
    '4631150f062471c1487e5d231a09a732a1f8b689')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, to_ru=True, pad=True):
    src, dst = (DU, RU) if to_ru else (RU, DU)
    fr = dst + src + struct.pack('>H', 0xAEFE) + payload
    if pad:
        fr += b'\0' * max(0, 60 - len(fr))
    return fr


def msg(mtype, payload, c=0, rev=1, size=None):
    if size is None:
        size = len(payload)
    return bytes([(rev << 4) | c, mtype]) + struct.pack('>H', size) + payload


def concat(*msgs):
    """Messages with the C bit on all but the last, each padded to a
    multiple of 4 octets."""
    out = b''
    for i, (mtype, payload) in enumerate(msgs):
        m = msg(mtype, payload, c=0 if i == len(msgs) - 1 else 1)
        if i != len(msgs) - 1:
            m += b'\0' * (-len(m) % 4)
        out += m
    return out


def t1(pcid, seq, data):
    return struct.pack('>HH', pcid, seq) + data


def t3(pcid, seq, data):
    return struct.pack('>II', pcid, seq) + data


def rma(rid, rw, rr, elem, addr, data, dlen=None):
    if dlen is None:
        dlen = len(data)
    return bytes([rid, (rw << 4) | rr]) + struct.pack('>H', elem) + addr + \
        struct.pack('>H', dlen) + data


def owd(mid, action, sec, ns, comp=0, dummy=b''):
    return bytes([mid, action]) + struct.pack('>Q', sec)[2:] + struct.pack('>I', ns) + \
        struct.pack('>q', comp) + dummy


def reset(rid, code, vendor=b''):
    return struct.pack('>HB', rid, code) + vendor


def event(eid, etype, seq, elements, num=None):
    if num is None:
        num = len(elements)
    body = bytes([eid, etype, seq, num])
    for elem, rc, fn, info in elements:
        body += struct.pack('>HHI', elem, (rc << 12) | fn, info)
    return body


def iwf_startup(pcid, hfn, sfn, ts, fec, scr, rate, data=b''):
    return struct.pack('>HBBI', pcid, hfn, sfn, ts) + \
        bytes([(fec << 7) | (scr << 6) | rate]) + data


def iwf_delay(pcid, dcid, action, a, b):
    return struct.pack('>HBBII', pcid, dcid, action, a, b)


def main_frames():
    F = []
    # 1-2: O-RAN C-plane and U-plane (message types 2 and 0), also shown
    #      by eCPRI as PC_ID, SEQ_ID and opaque data
    F.append(eth(msg(2, ORAN_C)))
    F.append(eth(msg(0, ORAN_U)))
    # 3: bit sequence (type 1)
    F.append(eth(msg(1, t1(0x1234, 0x0001, bytes(range(16))))))
    # 4: bit sequence with only PC_ID and SEQ_ID
    F.append(eth(msg(1, t1(0x1234, 0x0002, b''))))
    # 5: generic data transfer (type 3)
    F.append(eth(msg(3, t3(0x01020304, 0x00000001, b'generic data'))))
    # 6-9: remote memory access (type 4): read request, response with
    #      data, write request, write without response, failure
    addr = bytes.fromhex('00000000a000')
    F.append(eth(msg(4, rma(1, 0, 0, 0x0010, addr, b'', dlen=0))))
    F.append(eth(msg(4, rma(1, 0, 1, 0x0010, addr, bytes(range(8)))), False))
    F.append(eth(msg(4, rma(2, 1, 0, 0x0011, addr, b'\xde\xad\xbe\xef'))))
    F.append(eth(msg(4, rma(3, 2, 0, 0xffff, addr, b'\x01\x02'))))
    # 10: failure and a reserved read/write and request/response code
    F.append(eth(concat((4, rma(2, 1, 2, 0x0011, addr, b'')),
                        (4, rma(4, 7, 9, 0x0012, addr, b'')))))
    # 11-12: one-way delay measurement 1: request (with dummy bytes)
    #        and response: the delay is calculated in the second pass
    F.append(eth(msg(5, owd(1, 0, 1000, 500, comp=0x10000, dummy=b'\0' * 8))))
    F.append(eth(msg(5, owd(1, 2, 1000, 2500, comp=0x20000)), False))
    # 13-15: measurement 2: request with follow-up (no time stamp),
    #        follow-up with the time stamp, response with dummy bytes
    F.append(eth(msg(5, owd(2, 1, 0, 0, dummy=b'\0' * 4))))
    F.append(eth(msg(5, owd(2, 5, 2000, 100, comp=-0x8000))))
    F.append(eth(msg(5, owd(2, 2, 2000, 900, dummy=b'\0' * 2)), False))
    # 16-17: remote request and remote request with follow-up (no time
    #        stamp, seconds only), the latter with a compensation value
    #        (warning)
    F.append(eth(msg(5, owd(3, 3, 0, 0)), False))
    F.append(eth(msg(5, owd(4, 4, 5, 0, comp=0x12340000)), False))
    # 18: request without a response, 19: response without a request
    #     (warnings in the second pass), reserved action type 6
    F.append(eth(msg(5, owd(5, 0, 3000, 1))))
    F.append(eth(msg(5, owd(6, 2, 3000, 2)), False))
    F.append(eth(msg(5, owd(7, 6, 0, 0)), False))
    # 21-23: remote reset (type 6): request, response with vendor
    #        payload, reserved reset codes 0 and 0x80
    F.append(eth(msg(6, reset(0x0001, 1))))
    F.append(eth(msg(6, reset(0x0001, 2, b'\x11\x22\x33')), False))
    F.append(eth(concat((6, reset(2, 0)), (6, reset(3, 0x80)))))
    # 24: event indication (type 7): fault indication with eCPRI and
    #     vendor faults, raise and cease, all elements
    F.append(eth(msg(7, event(1, 0, 0, [(0x0001, 0, 0x000, 0x11), (0xffff, 1, 0x001, 0x22),
                                        (0x0002, 0, 0x123, 0), (0x0003, 1, 0x800, 0x33)])), False))
    # 25: fault indication acknowledge, 26: notification indication
    F.append(eth(msg(7, event(1, 1, 0, []))))
    F.append(eth(msg(7, event(2, 2, 1, [(0x0004, 0, 0x400, 0), (0x0004, 0, 0x401, 0),
                                        (0x0004, 0, 0x402, 0), (0x0004, 0, 0x403, 0),
                                        (0x0004, 0, 0x404, 0), (0x0004, 0, 0x7ff, 0),
                                        (0x0005, 2, 0xfff, 1)])), False))
    # 27: synchronization request, acknowledge and end indication, and a
    #     reserved event type, concatenated
    F.append(eth(concat((7, event(3, 3, 0, [])), (7, event(3, 4, 1, [])),
                        (7, event(3, 5, 2, [])), (7, event(4, 0x80, 0, [])))))
    # 28-29: IWF start-up (type 8), every line rate, FEC and scrambling
    F.append(eth(msg(8, iwf_startup(0x0102, 3, 4, 123456789, 1, 0, 0x08))))
    F.append(eth(concat(*[(8, iwf_startup(r, 0, 0, r, r & 1, (r >> 1) & 1, r, b'\x01' * (r % 3)))
                          for r in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 0x1f)])))
    # 30: IWF operation and IWF mapping (types 9 and 10, not decoded),
    #     each with the C bit and a payload that looks like a remote
    #     reset header, then a remote reset: three messages (before the
    #     fix the type 9 and 10 payloads were taken for further headers)
    fake = msg(6, reset(0x0102, 0), c=1) + b'\0'
    F.append(eth(concat((9, fake), (10, fake), (6, reset(0x0009, 1)))))
    # 31-32: IWF delay control (type 11): request with zero delays and
    #        response with delays A and B in units of 1/16 ns
    F.append(eth(msg(11, iwf_delay(0x0001, 1, 0, 0, 0))))
    F.append(eth(msg(11, iwf_delay(0x0001, 1, 1, 160, 0x00010008)), False))
    # 33: reserved (12, 63) and vendor specific (64, 255) message types
    F.append(eth(concat((12, b'\x01'), (63, b''), (64, b'vendor'), (255, b'\xff' * 5))))
    # 34: concatenated messages of every decoded type, unaligned sizes
    F.append(eth(concat((1, t1(1, 1, b'\x01')), (3, t3(2, 2, b'\x02\x03')),
                        (4, rma(5, 0, 0, 1, addr, b'', dlen=0)),
                        (6, reset(4, 1, b'\x05')),
                        (7, event(5, 1, 0, [])), (11, iwf_delay(2, 2, 0, 0, 0)))))
    # 35-36: protocol revisions 0 and 15
    F.append(eth(msg(6, reset(5, 1), rev=0)))
    F.append(eth(msg(6, reset(6, 1), rev=15)))
    # 37: no Ethernet padding, message ends at the end of the frame
    F.append(eth(msg(3, t3(7, 7, b'end')), pad=False))
    # 38: only 3 octets after the Ethernet header: too short for the
    #     common header, eCPRI rejects it (data)
    F.append(eth(b'\x10\x00\x00', pad=False))
    # 39: payload size 0 for a reserved type (header only), unpadded
    F.append(eth(msg(20, b''), pad=False))
    return F


def malformed_frames():
    F = []
    # 1: payload size beyond the frame (frame length too small)
    F.append(eth(msg(3, t3(1, 1, b'xy'), size=200), pad=False))
    # 2: concatenated message whose payload runs past the end
    F.append(eth(msg(6, reset(1, 1), c=1) + b'\0' + msg(3, b'\0' * 8, size=100), pad=False))
    # 3-11: payload sizes too small for types 0-8
    for t, n in ((0, 2), (1, 3), (2, 1), (3, 7), (4, 11), (5, 19), (6, 2), (7, 3), (8, 8)):
        F.append(eth(msg(t, b'\x00' * n)))
    # 12-13: payload size 0 for type 0 and 2 with the C bit: not advanced
    F.append(eth(msg(0, b'', c=1) + msg(6, reset(1, 1))))
    F.append(eth(msg(2, b'\x00\x00', c=1) + b'\0\0' + msg(6, reset(1, 1))))
    # 14-15: remote memory access data length too small and too big
    addr = bytes(6)
    F.append(eth(msg(4, rma(1, 1, 0, 1, addr, b'\x01\x02\x03\x04', dlen=2))))
    F.append(eth(msg(4, rma(1, 1, 0, 1, addr, b'\x01\x02', dlen=9))))
    # 16: time stamp for a remote request (error)
    F.append(eth(msg(5, owd(9, 3, 1, 1))))
    # 17: time stamp for a request with follow-up
    F.append(eth(msg(5, owd(9, 1, 1, 1))))
    # 18: fault indication without faults
    F.append(eth(msg(7, event(1, 0, 0, []))))
    # 19: fault indication with a notification, notification indication
    #     with a fault
    F.append(eth(concat((7, event(1, 0, 0, [(1, 0, 0x400, 0)])),
                        (7, event(1, 2, 0, [(1, 0, 0x001, 0)])))))
    # 20-21: number of faults too big and too small for the payload
    F.append(eth(msg(7, event(1, 0, 0, [(1, 0, 1, 0)], num=3))))
    F.append(eth(msg(7, event(1, 0, 0, [(1, 0, 1, 0), (1, 0, 2, 0)], num=1))))
    # 22: synchronization request with faults and a long payload
    F.append(eth(msg(7, event(1, 3, 0, [(1, 0, 1, 0)]))))
    # 23: reserved event type with faults
    F.append(eth(msg(7, event(1, 9, 0, [(1, 0, 1, 0)]))))
    # 24: IWF delay control with a wrong payload size
    F.append(eth(msg(11, b'\x00' * 8)))
    # 25-26: request with non-zero delays, response with zero delays
    F.append(eth(msg(11, iwf_delay(1, 1, 0, 16, 0))))
    F.append(eth(msg(11, iwf_delay(1, 1, 1, 0, 0))))
    # 27: last message with the C bit set
    F.append(eth(msg(6, reset(1, 1), c=1), pad=False))
    # 28: original reproducer: type 9 with C bit and a type 5 header of
    #     payload size 0 after it
    payload = bytes([0x10, 0x06, 0x00, 0x03, 0x00, 0x01, 0x02, 0x00])
    F.append(eth(msg(9, payload, c=1) + msg(5, b''), pad=False))
    # 29: payload size beyond the frame for a type decoded field by field
    F.append(eth(msg(5, owd(1, 0, 1, 1)[:10], size=20), pad=False))
    # 30: C bit set with a header that ends 2 octets before the frame
    F.append(eth(msg(6, reset(1, 1), c=1) + b'\0' + b'\x10\x06', pad=False))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ecpri-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ecpri-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

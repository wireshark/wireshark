#!/usr/bin/env python3
# Generates test/captures/iso10681_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISO 10681 (FlexRay
transport protocol) dissector (packet-iso10681.c).

ISO 10681-2 is reached through FlexRay: the FlexRay IDs have to be bound
with the preference iso10681.flexray.flexrayids (combined ID: 4 bit bus,
4 bit channel, 16 bit frame ID, 8 bit cycle) or with Decode As
(flexray.subdissector). Every packet is built from scratch with struct;
no captured traffic is used.

Usage: mkiso10681.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_FLEXRAY (210)             FlexRay frames
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming "iso10681"
                                        (no FlexRay information: rejected)

  iso10681-coverage.pcapng            Start Frames (acknowledged or not),
                                      Consecutive Frames 1, 2 and EOB,
                                      Last Frames, every Flow Control
                                      status, reassembly (also over
                                      several cycles), 20 and 17 segment
                                      transfers (reproducer of the fix)
  iso10681-coverage-malformed.pcapng  bad types, 256 Consecutive Frames
                                      with one sequence number, truncated
                                      frames
"""

import os
import struct
import sys

T0 = 1700000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(shb() + idb(210) + idb(252))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.001, data))


def flexray(frame_id, cycle, payload, channel_b=False):
    """LINKTYPE_FLEXRAY: measurement header, error flags, 5 byte header,
    payload (even length), 3 byte CRC."""
    if len(payload) % 2:
        payload += b'\0'
    pl = len(payload) // 2
    hdr = bytes([0x20 | ((frame_id >> 8) & 7), frame_id & 0xff, (pl << 1) & 0xfe, 0, cycle & 0x3f])
    return (0, bytes([0x81 if channel_b else 0x01, 0]) + hdr + payload + b'\0\0\0')


TA, SA = 0x1234, 0x5678


def addr(t=TA, s=SA):
    return struct.pack('>HH', t, s)


def start(fid, cyc, data, total, ack=False, a=None, **kw):
    return flexray(fid, cyc, (a or addr()) + bytes([0x40 | (1 if ack else 0), len(data)])
                   + struct.pack('>H', total) + data, **kw)


def cons(fid, cyc, kind, seq, data, a=None, **kw):
    """kind 1, 2 or 7 (EOB): Consecutive Frame 1, 2, EOB."""
    return flexray(fid, cyc, (a or addr()) + bytes([(4 + kind) << 4 | (seq & 15) if kind != 7 else 0x70 | (seq & 15),
                                                   len(data)]) + data, **kw)


def last(fid, cyc, data, total, a=None, **kw):
    return flexray(fid, cyc, (a or addr()) + bytes([0x90, len(data)]) + struct.pack('>H', total) + data, **kw)


def fc(fid, cyc, status, b1=0, b2=0, b3=0, a=None, **kw):
    return flexray(fid, cyc, (a or addr()) + bytes([0x80 | status, b1, b2, b3]), **kw)


def pat(n, base=0):
    return bytes((base + i) & 0xff for i in range(n))


def build_main():
    fr = []
    F = 10
    # Unacknowledged transfer: Start Frame, CF1, CF2, CF EOB; 32 bytes, 8 per frame
    d = pat(32, 0x10)
    fr.append(start(F, 0, d[0:8], 32))
    fr.append(fc(F, 0, 3, 0x0b, 0x01, 0x00))
    fr.append(cons(F, 0, 1, 1, d[8:16]))
    fr.append(cons(F, 0, 2, 2, d[16:24]))
    fr.append(cons(F, 0, 7, 3, d[24:32]))
    # Acknowledged transfer, the last frame is a Last Frame; flow control
    # in the direction of the receiver (swapped addresses), the final Ack
    d = pat(20, 0x40)
    fr.append(start(F, 0, d[0:8], 20, ack=True))
    fr.append(fc(F, 0, 3, 0x1a, 0x02, 0x00, a=addr(SA, TA)))      # CTS
    fr.append(cons(F, 0, 1, 1, d[8:16]))
    fr.append(last(F, 0, d[16:20], 20))
    fr.append(fc(F, 0, 4, 0x00, 0x00, 0x00, a=addr(SA, TA)))      # Ack
    # Every flow status
    fr.append(fc(F, 0, 3, 0x00, 0x00, 0x40, a=addr(SA, TA)))
    fr.append(fc(F, 0, 3, 0xff, 0xff, 0xff, a=addr(SA, TA)))
    fr.append(fc(F, 0, 3, 0x41, 0x00, 0x10, a=addr(SA, TA)))
    fr.append(fc(F, 0, 4, 0x01, 0x00, 0x10, a=addr(SA, TA)))      # Retry request
    fr.append(fc(F, 0, 5, 0, 0, 0, a=addr(SA, TA)))               # Wait
    fr.append(fc(F, 0, 6, 0, 0, 0, a=addr(SA, TA)))               # Abort
    fr.append(fc(F, 0, 7, 0, 0, 0, a=addr(SA, TA)))               # Overflow
    fr.append(fc(F, 0, 9, 0, 0, 0, a=addr(SA, TA)))               # unknown status
    # A transfer with all eight bytes of the last frame not needed: the
    # Consecutive Frame carries more than the remaining length
    d = pat(21, 0x60)
    fr.append(start(F, 0, d[0:8], 21))
    fr.append(cons(F, 0, 1, 1, d[8:16]))
    fr.append(cons(F, 0, 2, 2, d[16:21] + b'\xff\xff\xff', ))   # FPL 8, only 5 needed
    # Transfers on other frame IDs and the other channel, interleaved
    da = pat(24, 0x80)
    db = pat(24, 0xc0)
    fa = [start(11, 0, da[0:8], 24, a=addr(0x0101, 0x0202)), cons(11, 0, 1, 1, da[8:16], a=addr(0x0101, 0x0202)),
          cons(11, 0, 7, 2, da[16:24], a=addr(0x0101, 0x0202))]
    fb = [start(11, 0, db[0:8], 24, a=addr(0x0303, 0x0404), channel_b=True),
          cons(11, 0, 2, 1, db[8:16], a=addr(0x0303, 0x0404), channel_b=True),
          last(11, 0, db[16:24], 24, a=addr(0x0303, 0x0404), channel_b=True)]
    for x, y in zip(fa, fb):
        fr += [x, y]
    # A transfer over several cycles: only reassembled when the cycle is ignored
    # (preference iso10681.spread_over_cycles)
    d = pat(24, 0x20)
    fr.append(start(12, 1, d[0:8], 24))
    fr.append(cons(12, 2, 1, 1, d[8:16]))
    fr.append(cons(12, 3, 7, 2, d[16:24]))
    # 20 segments, sequence numbers wrapping after 15: SF + 19 CF + LF
    d = pat(21 * 4, 0)
    fr.append(start(10, 4, d[0:4], 84))
    for i in range(1, 20):
        fr.append(cons(10, 4, 1 + (i % 2), i, d[4 * i:4 * i + 4]))
    fr.append(last(10, 4, d[80:84], 84))
    # Reproducer, ISO 10681 Last Frame with 16 or more segments (it hit
    # DISSECTOR_ASSERT(frag_id < 16)): Start Frame, 15 Consecutive Frames
    # and a Last Frame; the announced length of 256 is not reached
    d4 = bytes(range(4))
    fr.append(start(10, 5, d4, 0x0100, a=bytes([0x12, 0x34, 0x56, 0x78])))
    for seq in range(1, 16):
        fr.append(cons(10, 5, 1, seq, d4, a=bytes([0x12, 0x34, 0x56, 0x78])))
    fr.append(last(10, 5, d4, 0x0100, a=bytes([0x12, 0x34, 0x56, 0x78])))
    # A Consecutive Frame after the message is complete
    fr.append(cons(10, 5, 1, 1, d4))
    # Consecutive Frame without Start Frame, Last Frame without Start Frame
    fr.append(cons(13, 0, 1, 1, pat(8)))
    fr.append(last(13, 0, pat(4), 12))
    # Start Frame with a message length smaller than the segment: the
    # message is complete in the first frame
    fr.append(start(14, 0, pat(8), 4))
    # Frame ID not bound to ISO 10681 (the preference range does not cover it)
    fr.append(flexray(40, 0, addr() + bytes([0x40, 8, 0, 8]) + pat(8)))
    # An Exported PDU naming "iso10681" has no FlexRay information
    name = b'iso10681\0\0\0\0'
    fr.append((1, struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0)
               + bytes([0x12, 0x34, 0x56, 0x78, 0x40, 4, 0, 4]) + pat(4)))
    return fr


def build_malformed():
    fr = []
    a = addr()
    # Bad message types (0 to 3 and 10 to 15)
    for t in (0x00, 0x10, 0x20, 0x30, 0xa0, 0xb0, 0xf0):
        fr.append(flexray(10, 0, a + bytes([t | 1, 4]) + pat(4)))
    # Reproducer, too many Consecutive Frames with the same sequence number
    # (a Start Frame announcing 60000 bytes, then 256 CFs with sequence 1)
    fr.append(start(11, 0, pat(4), 60000))
    for i in range(256):
        fr.append(cons(11, 0, 1, 1, bytes([i] * 4)))
    # Truncated frames
    fr.append(flexray(12, 0, a))
    fr.append(flexray(12, 0, a[:2]))
    fr.append(flexray(12, 0, a + bytes([0x40])))
    fr.append(flexray(12, 0, a + bytes([0x40, 4, 0])))
    fr.append(flexray(12, 0, a + bytes([0x50, 4])[:2]))
    fr.append(flexray(12, 0, a + bytes([0x90, 4, 0])))
    fr.append(flexray(12, 0, a + bytes([0x83, 0, 0])))
    fr.append(flexray(12, 0, a + bytes([0x84, 0])))
    # Segment length larger than the frame
    fr.append(flexray(12, 0, a + bytes([0x40, 0x30, 0, 0x30]) + pat(4)))
    fr.append(flexray(12, 0, a + bytes([0x51, 0x30]) + pat(4)))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main()
    write(os.path.join(out, 'iso10681-coverage.pcapng'), m)
    write(os.path.join(out, 'iso10681-coverage-malformed.pcapng'), build_malformed())
    print('main frames: %d' % len(m))


if __name__ == '__main__':
    main()

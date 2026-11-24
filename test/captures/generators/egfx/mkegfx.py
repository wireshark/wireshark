#!/usr/bin/env python3
# Generates the egfx captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP graphics pipeline (MS-RDPEGFX) captures for packet-rdp_egfx.c
# and epan/tvbuff_rdp.c (ZGFX).  Usage: mkegfx.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import (
    Bits, caps_req, caps_resp, create_req, create_resp, data, data_first, z_lit, z_lit_raw,
    z_match, z_unencoded, zmulti, zseg_literals, zseg_raw, zsingle,
)

VERBOSE = '-v' in sys.argv
OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
MARKS = []
NAME = 'Microsoft::Windows::RDS::Graphics'


def mark(cap, title):
    MARKS.append((len(cap.frames) + 1, title))


def finish(cap, name):
    cap.write(os.path.join(OUT, name))
    if VERBOSE:
        print(name, len(cap.frames), 'frames')
        for i, (n, t) in enumerate(MARKS):
            end = MARKS[i + 1][0] - 1 if i + 1 < len(MARKS) else len(cap.frames)
            print('  %d-%d: %s' % (n, end, t))


def pdu(cmd, body=b'', flags=0, length=None):
    return struct.pack('<HHI', cmd, flags, 8 + len(body) if length is None else length) + body


def caps_set(version, flags=0, data=None):
    d = struct.pack('<I', flags) if data is None else data
    return struct.pack('<II', version, len(d)) + d


def caps_adv(sets):
    return pdu(0x12, struct.pack('<H', len(sets)) + b''.join(sets))


def rect(l, t, r, b):
    return struct.pack('<HHHH', l, t, r, b)


V8, V81, V10, V101, V102, V103, V104, V105, V106E, V106, V107, V111, V112, V113 = (
    0x00080004, 0x00080105, 0x000A0002, 0x000A0100, 0x000A0200, 0x000A0301, 0x000A0400, 0x000A0502,
    0x000A0600, 0x000A0601, 0x000A0701, 0x000b0101, 0x000b0200, 0x000b0300)
ALL_VERSIONS = [V8, V81, V10, V101, V102, V103, V104, V105, V106E, V106, V107, V111, V112, V113, 0x00090009]


def server_pdus():
    """Server to client PDUs of one frame cycle, one for every command."""
    out = []
    out.append(pdu(0x13, caps_set(V105, 0x1f2)))                                               # caps confirm
    out.append(pdu(0x13, caps_set(V101, data=bytes(16))))
    out.append(pdu(0x0e, struct.pack('<III', 1920, 1080, 2) + struct.pack('<iiiiI', 0, 0, 1919, 1079, 1)
                   + struct.pack('<iiiiI', 1920, 0, 3839, 1079, 0) + bytes(300)))                 # reset graphics
    out.append(pdu(0x09, struct.pack('<HHHB', 1, 1920, 1080, 0x20)))                              # create surface
    out.append(pdu(0x0f, struct.pack('<HHII', 1, 0, 0, 0)))                                       # map surface to output
    out.append(pdu(0x0b, struct.pack('<II', 1000, 7)))                                            # start frame
    out.append(pdu(0x01, struct.pack('<HH', 1, 0x0b) + b'\x21' + rect(0, 0, 64, 64) + struct.pack('<I', 8) + bytes(8)))
    out.append(pdu(0x02, struct.pack('<HHIB', 1, 0x09, 5, 0x20) + struct.pack('<I', 4) + bytes(4)))
    out.append(pdu(0x03, struct.pack('<HI', 1, 5)))                                               # delete encoding context
    out.append(pdu(0x04, struct.pack('<HIH', 1, 0xff00ff00, 1) + rect(0, 0, 10, 10)))             # solid fill
    out.append(pdu(0x05, struct.pack('<HH', 1, 2) + rect(0, 0, 8, 8) + struct.pack('<H', 1) + struct.pack('<HH', 4, 4)))
    out.append(pdu(0x06, struct.pack('<H', 1) + struct.pack('<Q', 0x1122334455667788) + struct.pack('<H', 3) + rect(0, 0, 8, 8)))
    out.append(pdu(0x07, struct.pack('<HHH', 3, 1, 1) + struct.pack('<HH', 4, 4)))               # cache to surface
    out.append(pdu(0x08, struct.pack('<H', 3)))                                                   # evict cache entry
    out.append(pdu(0x0c, struct.pack('<I', 7)))                                                   # end frame
    out.append(pdu(0x0a, struct.pack('<H', 1)))                                                   # delete surface
    out.append(pdu(0x10, bytes(6)))                                                               # cache import offer
    out.append(pdu(0x11, bytes(6)))                                                               # cache import reply
    out.append(pdu(0x15, struct.pack('<HQII', 1, 0x1234, 640, 480)))                              # map surface to window
    out.append(pdu(0x17, struct.pack('<HHIIII', 1, 0, 0, 0, 800, 600)))                           # scaled output
    out.append(pdu(0x18, struct.pack('<HQIIII', 1, 0x1234, 640, 480, 800, 600)))                  # scaled window
    out.append(pdu(0x19, struct.pack('<H', 1) + bytes(6)))                                        # protect surface
    out.append(pdu(0x1a, struct.pack('<HHH', 1, 100, 50) + bytes(6) + b'\x21' + bytes(2) + struct.pack('<H', 128)
                   + bytes(6) + struct.pack('<HH', 4, 4) + bytes(8) + struct.pack('<H', 16) + bytes(16)))   # watermark
    out.append(pdu(0x14, bytes(4)))                                                               # diagnostic (unknown to the dissector)
    out.append(pdu(0x7777, bytes(4)))                                                             # unknown command
    return out


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    S = lambda p: s.chan('drdynvc', p, False)
    C = lambda p: s.chan('drdynvc', p, True)
    mark(cap, 'session and creation of the graphics channel')
    S(caps_req(3))
    C(caps_resp(3))
    S(create_req(3, NAME))
    C(create_resp(3))

    def gfx(payload):
        if len(payload) <= 15000:
            S(data(3, payload))
            return
        # more than a static channel PDU can hold: DVC fragments
        S(data_first(3, len(payload), payload[:15000], lb=2))
        for i in range(15000, len(payload), 15000):
            S(data(3, payload[i:i + 15000]))

    mark(cap, 'client to server: caps advertise with every capability version, frame acknowledge, QoE acknowledge (not compressed)')
    C(data(3, caps_adv([caps_set(v, f) for v, f in zip(ALL_VERSIONS, (0, 0x1, 0x2, 0, 0x10, 0x20, 0x40, 0x80, 0x100, 0x1ff, 0, 0x3, 0x5, 0x7f, 0))])))
    C(data(3, caps_adv([caps_set(V8, 0)])))
    mark(cap, 'frame tracking: acknowledge before the frame starts, start, end, acknowledge, QoE acknowledge, frames seen only by their end/ack')
    C(data(3, pdu(0x0d, struct.pack('<III', 0, 5, 10))))                    # ack of a frame that was not started yet
    gfx(zsingle(zseg_raw(pdu(0x0b, struct.pack('<II', 1, 5)))))             # start of frame 5 (ack known)
    gfx(zsingle(zseg_raw(pdu(0x0c, struct.pack('<I', 5)))))
    C(data(3, pdu(0x0d, struct.pack('<III', 0, 5, 11))))                    # ack again
    C(data(3, pdu(0x16, struct.pack('<IIHH', 5, 12345, 3, 4))))             # QoE ack of frame 5
    gfx(zsingle(zseg_raw(pdu(0x0c, struct.pack('<I', 98)))))                # end of a frame never started
    C(data(3, pdu(0x16, struct.pack('<IIHH', 99, 12345, 3, 4))))            # QoE ack of an unknown frame
    gfx(zsingle(zseg_raw(pdu(0x0c, struct.pack('<I', 99)))))                # end of a frame whose QoE ack came first
    gfx(zsingle(zseg_raw(pdu(0x0b, struct.pack('<II', 2, 6)))))
    gfx(zsingle(zseg_raw(pdu(0x0c, struct.pack('<I', 6)))))
    C(data(3, pdu(0x0d, struct.pack('<III', 0, 6, 12))))
    C(data(3, pdu(0x16, struct.pack('<IIHH', 6, 777, 1, 2))))
    C(data(3, pdu(0x0d, struct.pack('<III', 0, 99, 13))))                   # ack of the frame that only ended

    mark(cap, 'server to client: one PDU for every command in a ZGFX segment (uncompressed)')
    allp = server_pdus()
    for i in range(0, len(allp), 4):
        gfx(zsingle(zseg_raw(b''.join(allp[i:i + 4]))))
    mark(cap, 'ZGFX segments: literals through the table, raw literals, back reference to earlier output, unencoded run, multipart')
    p1 = pdu(0x0b, struct.pack('<II', 5, 21)) + pdu(0x0c, struct.pack('<I', 21))
    gfx(zsingle(zseg_literals(p1)))
    bs = Bits()
    z_match(bs, len(p1), len(p1))                                           # repeats the previous frame's output
    gfx(zsingle(bytes([0x24]) + bs.finish()))
    for n in (1, 4, 12, 32, 92, 292, 792, 2992, 7992, 29992, 59992):
        # a PDU of 8 + n octets, then a back reference that repeats exactly that PDU: every
        # distance range and count length of the match tokens
        body = struct.pack('<HH', 1, 0) + b'\x20' + bytes(n - 5) if n > 5 else bytes(n)
        one = pdu(0x10, body) if n <= 5 else pdu(0x01, body)
        gfx(zsingle(zseg_raw(one)))
        bs = Bits()
        z_match(bs, len(one), len(one))
        gfx(zsingle(bytes([0x24]) + bs.finish()))
    gfx(zsingle(zseg_literals(p1, table=False)))
    full = pdu(0x0b, struct.pack('<II', 5, 22)) + pdu(0x0c, struct.pack('<I', 22)) + pdu(0x10, bytes(10))
    h = full[:max(3, len(full) // 2)]
    # literals of the first part, unencoded run of the rest (distance 0 match with count)
    bs = Bits()
    for b in h:
        z_lit(bs, b)
    z_unencoded(bs, full[len(h):])
    gfx(zsingle(bytes([0x24]) + bs.finish()))
    a, b = pdu(0x0b, struct.pack('<II', 5, 23)), pdu(0x0c, struct.pack('<I', 23))
    gfx(zmulti([zseg_raw(a), zseg_literals(b)], len(a) + len(b)))
    gfx(zmulti([zseg_raw(a)], len(a)))
    big = pdu(0x01, struct.pack('<HH', 1, 0) + b'\x20' + rect(0, 0, 64, 64) + struct.pack('<I', 40000) + bytes(40000))
    gfx(zsingle(zseg_raw(big)))
    gfx(zsingle(zseg_raw(b'')))                                             # empty segment
    gfx(zsingle(zseg_raw(bytes(8))))                                        # not more than the header
    gfx(zsingle(zseg_raw(pdu(0x0b, struct.pack('<II', 5, 24)) + bytes(5))))  # trailing padding
    mark(cap, 'EGFX over the UDP transport (Exported PDUs, RDPMT tunnel linked to the TCP connection)')
    cookie = bytes(range(16))
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', create_req(4, NAME), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data(4, zsingle(zseg_raw(pdu(0x0b, struct.pack('<II', 5, 30)) + pdu(0x0c, struct.pack('<I', 30))))), False, sport=50050, pt=3)
    cap.exp('rdp_egfx', zsingle(zseg_raw(pdu(0x0b, struct.pack('<II', 5, 31)))), False, sport=50060)       # EGFX without an RDP session
    finish(cap, 'egfx-coverage.pcapng')


def build_malformed():
    cap = Cap()
    MARKS.clear()
    mark(cap, 'reproducers: unknown ZGFX descriptor (used after free on the second pass), pduLength that wraps the offset, multipart with no segments')
    X = lambda payload, c2s=False: cap.exp('rdp_egfx', payload, c2s, sport=50000)
    desc = b'\x00' + bytes.fromhex('120000000c000000') + b'\x00' * 4
    X(desc)
    X(desc)
    pdu1 = struct.pack('<HHI', 0x00ff, 0, 16) + b'\0' * 8
    pdu2 = struct.pack('<HHI', 0x00ff, 0, 0xFFFFFFF0)
    X(b'\xe0\x04' + pdu1 + pdu2 + b'\0' * 4)
    X(b'\xe1' + struct.pack('<HI', 0, 64))
    mark(cap, 'ZGFX that cannot be decompressed (errors), PDUs that run past the data')
    X(b'\xe0')
    X(b'\xe1' + struct.pack('<HI', 1, 0))
    X(b'\xe1' + struct.pack('<HI', 1, 10_000_000) + struct.pack('<I', 5) + zseg_raw(b'abcd'))
    X(b'\xe1' + struct.pack('<HI', 2, 4) + struct.pack('<I', 5) + zseg_raw(b'abcd') + struct.pack('<I', 5) + zseg_raw(b'efgh'))
    X(b'\xe1' + struct.pack('<HI', 1, 8) + struct.pack('<I', 5) + zseg_raw(b'abcd'))
    X(b'\xe1' + struct.pack('<HI', 1, 4) + struct.pack('<I', 500) + zseg_raw(b'abcd'))
    X(b'\xe0' + bytes([0x24]) + b'\xff\x00')                                 # padding count and tokens that do not fit
    X(b'\xe0' + bytes([0x24]) + b'\x01\x08')
    X(b'\xe0' + bytes([0x24, 0xd0, 0x00, 0x00, 0x00]))                       # prefix 11 + unknown literal prefix
    bs = Bits()
    z_match(bs, 5, 3)                                                        # back reference with an empty history
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    bs = Bits()
    bs.put(17, 5); bs.put(0, 5); bs.put(30000, 15); bs.align()               # unencoded run longer than the data
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    bs = Bits()
    bs.put(0x1b, 5)                                                          # truncated match
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    bs = Bits()
    z_match(bs, 1, 70000)
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    bs = Bits()
    z_lit(bs, 1)
    z_match(bs, 1, 40000)
    z_match(bs, 1, 40000)
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    X(b'\xe0\x04' + pdu(0x7777, b'', length=4) + bytes(8))                   # pduLength below 8
    X(b'\xe0\x04' + pdu(0x7777, bytes(4), length=0x1000) + bytes(8))         # pduLength past the data
    X(b'\xe0\x04' + pdu(0x12, struct.pack('<H', 5) + struct.pack('<II', V8, 0xffff) + bytes(8)))
    X(b'\xe0\x04' + pdu(0x0e, struct.pack('<III', 1, 1, 1000)))
    X(b'\xe0\x04' + pdu(0x1a, bytes(10)))
    mark(cap, 'ZGFX token streams that end inside a token, unknown match prefix, multipart with a corrupt segment, too long literal run')
    def bits(*pairs):
        b = Bits()
        for v, n in pairs:
            b.put(v, n)
        return X(b'\xe0' + bytes([0x24]) + b.finish())
    bits((17, 5))                                  # distance bits missing
    bits((17, 5), (3, 5))                          # distance, then no count bits
    bits((17, 5), (3, 5), (1, 1))                  # count prefix 1, nothing after it
    bits((17, 5), (3, 5), (1, 1), (1, 1))          # unary count cut short
    bits((17, 5), (3, 5), (1, 1), (0, 1), (1, 1))  # count bits cut short
    bits((17, 5), (0, 5))                          # unencoded run: no count
    bits((17, 5), (0, 5), (50, 15))                # unencoded run longer than the data
    bits((0, 1))                                   # literal without its byte
    bits((2, 2), (0, 8))                           # match prefix 10 followed by 00000000: no such token
    bits((1, 1))                                   # 1 and then nothing
    X(b'\xe1' + struct.pack('<HI', 1, 100) + struct.pack('<I', 2) + bytes([0x24, 0xff]))
    X(b'\xe1' + struct.pack('<HI', 1, 100) + struct.pack('<I', 1) + bytes([0x24]))
    X(b'\xe0' + zseg_raw(bytes(70000)))                                       # segment longer than 64 KiB - 1
    b = Bits()
    for i in range(65536):
        z_lit_raw(b, 0x41)
    X(b'\xe0' + bytes([0x24]) + b.finish())                                  # literal output longer than a segment
    b = Bits()
    for i in range(65536):
        z_lit(b, 0)
    X(b'\xe0' + bytes([0x24]) + b.finish())                                  # the same with table literals
    b = Bits()
    z_lit(b, 7)
    z_match(b, 1, 40000)
    z_unencoded(b, bytes(30000))                                              # unencoded run that does not fit what is left of the segment
    X(b'\xe0' + bytes([0x24]) + b.finish())
    bs = Bits()
    z_match(bs, 5, 3)
    z_match(bs, 3, 3)
    X(b'\xe0' + bytes([0x24]) + bs.finish())
    mark(cap, 'the 2.5 MB history buffer wraps: a match written across the end, a match read across the end, a raw segment and an unencoded run across the end')
    XW = lambda payload: cap.exp('rdp_egfx', payload, False, sport=50099)   # a conversation of its own: history starts empty
    pos = [0]

    def fill(target):
        # raw segments until the history index is `target` (modulo the buffer size)
        while pos[0] % 2500000 != target:
            n = min(65000, (target - pos[0]) % 2500000 or 2500000)
            if n < 9:
                n = 9 if (target - pos[0]) % 2500000 >= 9 else 65000
            XW(b'\xe0' + zseg_raw(pdu(0x10, bytes(n - 8))))
            pos[0] += n
    fill(2499980)
    bs = Bits()
    z_match(bs, 100, 30)                           # 30 octets written across the end of the history
    XW(b'\xe0' + bytes([0x24]) + bs.finish())
    pos[0] += 30
    bs = Bits()
    z_match(bs, 100, 100)                          # source across the end of the history
    XW(b'\xe0' + bytes([0x24]) + bs.finish())
    pos[0] += 100
    fill(2499990)
    XW(b'\xe0' + zseg_raw(pdu(0x10, bytes(92))))   # raw segment across the end
    pos[0] += 100
    fill(2499990)
    bs = Bits()
    z_unencoded(bs, bytes(100))                    # unencoded run across the end
    XW(b'\xe0' + bytes([0x24]) + bs.finish())
    finish(cap, 'egfx-coverage-malformed.pcapng')


def build_errors():
    """The reproducers of the fixes and a few more PDUs that raise expert infos (small, committed)."""
    cap = Cap()
    MARKS.clear()
    mark(cap, 'unknown ZGFX descriptor twice (it was used after free on the second pass), pduLength wrapping the offset (endless loop), multipart announcing 64 octets with no segment (uninitialized heap)')
    X = lambda payload, c2s=False: cap.exp('rdp_egfx', payload, c2s, sport=50000)
    desc = b'\x00' + bytes.fromhex('120000000c000000') + b'\x00' * 4
    X(desc)
    X(desc)
    pdu1 = struct.pack('<HHI', 0x00ff, 0, 16) + b'\0' * 8
    pdu2 = struct.pack('<HHI', 0x00ff, 0, 0xFFFFFFF0)
    X(b'\xe0\x04' + pdu1 + pdu2 + b'\0' * 4)
    X(b'\xe1' + struct.pack('<HI', 0, 64))
    mark(cap, 'pduLength below 8 and past the data')
    X(b'\xe0\x04' + pdu(0x7777, b'', length=4) + bytes(8))
    X(b'\xe0\x04' + pdu(0x7777, bytes(4), length=0x1000) + bytes(8))
    finish(cap, 'egfx-coverage-errors.pcapng')


if __name__ == '__main__':
    build_main()
    build_errors()
    build_malformed()

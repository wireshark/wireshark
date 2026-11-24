#!/usr/bin/env python3
# Generates test/captures/hsms_coverage.pcap.gz, hsms_unknown_format.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-hsms.c (HSMS, SEMI E37, TCP port 5000).
The dissector has no default port: it is reached with the port preference
hsms.tcp.port or Decode As (tests and runcov.sh use -o hsms.tcp.port:5000).
Usage: mkhsms.py <outdir>"""
import struct
import sys
import os
from pylib import Pcap, Tcp

PORT = 5000

# item format codes (octal) and value sizes
LIST, BIN, BOOL, ASCII, JIS8, C2 = 0o00, 0o10, 0o11, 0o20, 0o21, 0o22
I8, I1, I2, I4 = 0o30, 0o31, 0o32, 0o34
F8, F4 = 0o40, 0o44
U8, U1, U2, U4 = 0o50, 0o51, 0o52, 0o54

def item(fc, payload=b'', count=None, lb=None):
    """Item with format code and length bytes (shortest unless lb given).
    For a list 'count' is the number of items, payload their encodings."""
    n = count if fc == LIST else len(payload)
    if lb is None:
        lb = 1 if n < 256 else 2 if n < 65536 else 3
    enc = b'' if lb == 0 else n.to_bytes(lb, 'big')
    return bytes([(fc << 2) | lb]) + enc + payload

def lst(*items, lb=None):
    return item(LIST, b''.join(items), count=len(items), lb=lb)

def msg(session, b2, b3, ptype, stype, system, data=b''):
    body = struct.pack('>HBBBBI', session, b2, b3, ptype, stype, system) + data
    return struct.pack('>I', len(body)) + body

def data_msg(stream, func, system, data=b'', w=True, session=1):
    return msg(session, (0x80 if w else 0) | stream, func, 0, 0, system, data)

def main(out):
    p = Pcap(1)
    t = Tcp(p, sport=50000, dport=PORT)
    t.hs()
    sysn = [0x1000]
    def nxt():
        sysn[0] += 1; return sysn[0]
    H_, E_ = True, False   # host to equipment, equipment to host
    # --- control messages ---
    t.seg(msg(0xffff, 0, 0, 0, 1, nxt()))                       # Select.req
    t.seg(msg(0xffff, 0, 0, 0, 2, sysn[0]), fwd=False)          # Select.rsp (status 0)
    t.seg(msg(0xffff, 0, 1, 0, 2, nxt()), fwd=False)            # Select.rsp (status 1, communication already active)
    t.seg(msg(0xffff, 0, 0, 0, 5, nxt()))                       # Linktest.req
    t.seg(msg(0xffff, 0, 0, 0, 6, sysn[0]), fwd=False)          # Linktest.rsp
    t.seg(msg(0x0001, 3, 4, 0, 7, nxt()), fwd=False)            # Reject.req
    t.seg(msg(0x0001, 0, 0, 0, 3, nxt()))                       # Deselect.req
    t.seg(msg(0x0001, 0, 0, 0, 4, sysn[0]), fwd=False)          # Deselect.rsp
    t.seg(msg(0x0001, 0, 0, 0, 9, nxt()))                       # Separate.req
    t.seg(msg(0x0001, 0, 0, 0, 11, nxt()))                      # stype 11 (subsidiary standard)
    # --- data messages ---
    t.seg(data_msg(1, 1, nxt()))                                 # S1F1 are you there, no data
    t.seg(data_msg(1, 2, sysn[0], lst(lst(item(ASCII, b'MDLN-A'), item(ASCII, b'1.0.2'))), w=False), fwd=False)
    t.seg(data_msg(1, 3, nxt(), lst(item(U4, struct.pack('>II', 1, 2)), item(U1, b'\x07'))))
    t.seg(data_msg(2, 41, nxt(), lst(item(ASCII, b'START'), lst(lst(item(ASCII, b'LOTID'), item(ASCII, b'LOT42'))))))
    t.seg(data_msg(2, 42, sysn[0], lst(item(BIN, b'\x00'), lst()), w=False), fwd=False)
    # Every value type, one item with several values
    t.seg(data_msg(6, 11, nxt(), lst(
        item(BIN, bytes([1, 2, 3, 255])),
        item(BOOL, b'\x01\x00\x01'),
        item(ASCII, b'plain text'),
        item(ASCII, b''),
        item(I8, struct.pack('>qq', -1, 2 ** 40)),
        item(I1, struct.pack('>bb', -128, 127)),
        item(I2, struct.pack('>hh', -2, 300)),
        item(I4, struct.pack('>ii', -70000, 70000)),
        item(F8, struct.pack('>dd', 1.5, -2.25)),
        item(F4, struct.pack('>ff', 0.5, 1024.0)),
        item(U8, struct.pack('>QQ', 0, 2 ** 63)),
        item(U1, bytes([0, 255])),
        item(U2, struct.pack('>HH', 1, 65535)),
        item(U4, struct.pack('>II', 1, 4294967295)))))
    # Length bytes 2 and 3
    t.seg(data_msg(7, 3, nxt(), lst(item(BIN, bytes(300), lb=2), item(ASCII, b'x' * 20, lb=3), lb=2)))
    t.seg(data_msg(7, 4, sysn[0], item(U1, bytes([5]), lb=3), w=False), fwd=False)
    # Empty items of the scalar types, nested lists three deep
    t.seg(data_msg(5, 1, nxt(), lst(item(U2, b''), item(I4, b''), item(BOOL, b''),
                                     lst(lst(lst(item(U1, b'\x01'), lst()))))))
    # JIS-8 and 2-byte characters: items are shown but not decoded (the
    # dissector stops after the first one)
    t.seg(data_msg(5, 3, nxt(), lst(item(JIS8, b'\x82\xa0'), item(U1, b'\x01'))))
    t.seg(data_msg(5, 5, nxt(), lst(item(C2, b'\x00A\x00B'), item(U1, b'\x01'))))
    # A top level item with zero length bytes: nothing is added
    t.seg(data_msg(5, 7, nxt(), bytes([(ASCII << 2) | 0])))
    # Item length not a multiple of the value size (item is dropped)
    t.seg(data_msg(5, 9, nxt(), item(U4, b'\x00\x00\x01')))
    # Response requested bit clear, stream 127, function 255
    t.seg(data_msg(127, 255, nxt(), w=False))
    # Two messages in one segment, and one message split over two segments
    t.seg(msg(0xffff, 0, 0, 0, 5, nxt()) + msg(0xffff, 0, 0, 0, 6, sysn[0]))
    m = data_msg(1, 13, nxt(), lst(item(ASCII, b'split across segments')))
    t.seg(m[:9]); t.seg(m[9:])
    # Presentation type other than SECS-II: note expert info, data not decoded
    t.seg(msg(1, 0x81, 1, 1, 0, nxt(), lst(item(U1, b'\x01'))))
    t.seg(b'', True, 0x11); t.seg(b'', False, 0x11)
    p.write(os.path.join(out, 'hsms-coverage.pcap'))

    # ---------------- malformed / rejected ----------------
    m = Pcap(1)
    t = Tcp(m, sport=50001, dport=PORT)
    t.hs()
    # Reproducer of the fix: unknown item format code 01 (division by zero)
    t.seg(msg(1, 0x81, 1, 0, 0, 0x12345678, bytes([(0o01 << 2) | 1, 0x01, 0x00])))
    # More unknown format codes (error expert info), also inside a list
    t.seg(msg(1, 0x81, 1, 0, 0, 0x12345679, bytes([(0o77 << 2) | 1, 0x02, 0x00, 0x00])))
    t.seg(data_msg(1, 3, 0x1234567a, lst(item(U1, b'\x01'), bytes([(0o13 << 2) | 2, 0x00, 0x04, 1, 2, 3, 4]))))
    first3 = len(m.frames)
    # Items cut short or with a length beyond the message
    t.seg(data_msg(1, 3, 0x1234567b, bytes([(U4 << 2) | 1, 8, 0, 0, 0, 1])))
    t.seg(data_msg(1, 3, 0x1234567c, bytes([(ASCII << 2) | 1, 200]) + b'short'))
    t.seg(data_msg(1, 3, 0x1234567d, bytes([(LIST << 2) | 1, 5]) + item(U1, b'\x01')))
    t.seg(data_msg(1, 3, 0x1234567e, bytes([(U1 << 2) | 3, 0, 0])))
    # Lists nested deeper than the dissection depth limit
    deep = item(U1, b'\x01')
    for _ in range(600):
        deep = item(LIST, deep, count=1)
    t.seg(data_msg(1, 3, 0x1234567f, deep))
    # Frames that fail the checks in dissect_hsms_message (not HSMS):
    t.seg(msg(1, 0, 1, 0, 0, 0x20000001))                            # data message without stream
    t.seg(msg(1, 0, 0, 0, 8, 0x20000002))                            # stype 8
    t.seg(msg(1, 0, 0, 0, 10, 0x20000003))                           # stype 10
    t.seg(msg(1, 0, 0, 0, 200, 0x20000004))                          # stype above 127
    t.seg(msg(1, 1, 0, 0, 1, 0x20000005))                            # Select.req with status bytes
    t.seg(msg(1, 0, 0, 0, 1, 0x20000006, b'data'))                   # Select.req with data
    t.seg(msg(1, 1, 0, 0, 2, 0x20000007))                            # Select.rsp with byte 2
    t.seg(msg(1, 0, 0, 0, 2, 0x20000008, b'data'))                   # Select.rsp with data
    t.seg(msg(1, 0, 0, 0, 5, 0x20000009))                            # Linktest.req, session not 0xffff
    t.seg(msg(0xffff, 1, 0, 0, 5, 0x2000000a))                       # Linktest.req with byte 2
    t.seg(msg(0xffff, 0, 1, 0, 6, 0x2000000b))                       # Linktest.rsp with byte 3
    t.seg(msg(0xffff, 0, 0, 0, 6, 0x2000000c, b'data'))              # Linktest.rsp with data
    t.seg(msg(1, 0, 0, 0, 7, 0x2000000d, b'data'))                   # Reject.req with data
    t.seg(struct.pack('>I', 6) + bytes(6))                           # shorter than the header
    t.seg(struct.pack('>I', 100) + bytes(14))                        # length field disagrees
    m.write(os.path.join(out, 'hsms-coverage-malformed.pcap'))
    # Small capture with only the unknown item format frames, for the test
    # of the fix (the main capture has no error expert infos)
    u = Pcap(1); u.frames = m.frames[:6]
    u.write(os.path.join(out, 'hsms-unknown-format.pcap'))
    import gzip
    with open(os.path.join(out, 'hsms-unknown-format.pcap'), 'rb') as f:
        raw = f.read()
    with open(os.path.join(out, 'hsms_unknown_format.pcap.gz'), 'wb') as f:
        f.write(gzip.compress(raw, 9, mtime=0))

main(sys.argv[1])

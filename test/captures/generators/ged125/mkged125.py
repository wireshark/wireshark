#!/usr/bin/env python3
# Generates test/captures/ged125_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GED-125 coverage captures. Usage: mkged125.py <outdir>
# GED-125 has no default port: the captures use TCP port 7000 (Decode As).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import pcap, Flow

def u(*w):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in w)

def msg(mtype, body=b'', length=None):
    return struct.pack('>II', len(body) if length is None else length, mtype) + body

# ---- floating fields: type, length, value
def fl(t, payload=b'', length=None):
    return bytes([t, len(payload) if length is None else length]) + payload
def fstr(t, s): return fl(t, s.encode())
def fuint(t, n): return fl(t, u(n))
def fmedia(t, kind, lib, s):
    """H/S/O/F: protocol, library designator, string; the length covers all"""
    return fl(t, kind + lib + s)
def fmedia_t(t, s): return fl(t, b'T' + s)
def fmedia_d(t, ptype, pfmt, s): return fl(t, b'D' + u(ptype, pfmt) + s)
def fecc(t, tag, s): return fl(t, u(tag) + s)
def farr(t, tag, idx, s): return fl(t, u(tag) + bytes([idx]) + s)

# floating field set with every type that has a handler (and zero length unknown types)
def all_floats():
    f = b''
    f += fstr(1, 'text')
    f += fstr(18, '5551234')          # ANI
    f += fl(19, b'\x01\x02\x03uui')     # UUI (unspecified bytes)
    for t in list(range(20, 35)) + [37, 38, 39, 40]:
        f += fstr(t, 'v%d' % t)
    f += fuint(35, 7)                   # Trunk_Group_ID (uint)
    f += fuint(36, 9)                   # TRUNK_NUMBER (uint)
    f += fuint(41, 3)                   # Cause code
    f += fecc(42, 0x12345678, b'name')  # exp call var name
    f += fecc(43, 0x12345678, b'value') # exp call var value
    f += fecc(42, 5, b'')               # no string after the tag
    f += farr(44, 0x00010002, 3, b'arrayval')
    f += farr(44, 0x00010002, 4, b'')
    f += fuint(45, 1) + fuint(46, 0)     # booleans
    f += fmedia(47, b'H', b'A', b'http://example.org/a.wav')
    f += fmedia(48, b'S', b'S', b'rtsp://example.org/s')
    f += fmedia(49, b'O', b'A', b'other')
    f += fmedia(50, b'F', b'S', b'file.wav')
    f += fmedia_t(47, b'text to speak')
    f += fmedia_d(48, 5, 4, b'1234')
    f += fmedia_d(49, 3, 2, b'')
    for t in range(51, 59):
        f += fstr(t, 'x%d' % t)
    f += fl(0) + fl(3) + fl(60)         # unhandled types, zero length
    f += fl(13, length=0)
    f += fstr(1, 'last')                # keep the loop going past the media fields
    return f + b'\x01\x01Z'             # final field plus padding

def sc(sub, dlg, seq, body=b''):
    return msg(47, u(sub, dlg, seq) + body)

def build():
    main = []
    f = Flow(40001, 7000, main)
    f.open()
    F = all_floats()
    s = f.c2s   # VRU -> ICM
    r = f.s2c   # ICM -> VRU
    s(msg(3, u(1, 3, 600)))                               # OPEN_REQ
    r(msg(4, u(1, 1, 0, 1, 0, 1)))                        # OPEN_CONF
    s(msg(5, u(2)))                                       # HEARTBEAT_REQ
    r(msg(6, u(2)))                                       # HEARTBEAT_CONF
    s(msg(9, u(3)))                                       # INIT_DATA_REQ
    r(msg(10, u(3)))                                      # INIT_DATA_CONF
    # trunk group data: invoke id and trunk count in range, then over the limits
    s(msg(11, u(3, 2, 10, 20, 100, 200, 300, 400) + struct.pack('>HHHH', 1, 4, 2, 2)))
    s(msg(11, u(70000, 2000, 1, 1, 1, 1, 1, 1) + struct.pack('>HH', 9, 1)))
    s(msg(12, u(3, 17, 1, 2, 3, 4, 5, 6, 7, 8, 9)))        # INIT_SERVICE_DATA_EVENT
    for opst in (0, 5, 40, 100, 200):
        s(msg(13, u(3, 0xFFFFFFC4, opst, 1, 2, 3)))        # INIT_VRU_DATA_EVENT
    s(msg(13, u(3, 0, 0) + b'\x01\x02'))                   # status variable with a trailing short piece
    s(msg(14, u(3, 1700000000, 1699990000)))              # INIT_DATA_END_EVENT
    s(msg(1, u(4, 0x20)))                                 # FAILURE_CONF
    r(msg(2, u(0x21)))                                    # FAILURE_EVENT
    s(msg(15, u(100, 1, 2, 3) + F))                       # DELIVERED
    s(msg(16, u(101, 1, 2, 3) + fstr(18, '5550000') + fstr(20, 'dnis') + b'\0\0\0'))   # ORIGINATED
    s(msg(17, u(100, 5) + fstr(1, 'cleared') + b'\0\0\0'))                          # CALL_CLEARED
    s(msg(18, u(200, 100, 101, 3)))                       # CONFERENCED
    s(msg(19, u(100, 8)))                                 # DIVERTED
    s(msg(20, u(100, 102, 3)))                            # NEW_TRANSACTION
    s(msg(21, u(100) + fstr(22, 'cv1') + fstr(23, 'cv2') + b'\0\0\0'))              # SET_CALL_VARIABLES
    for opst in (0, 3, 33, 70, 150):
        s(msg(22, u(1700000000, 3600, opst, 5, 6)))       # VRU_STATUS_EVENT
    s(msg(23, u(3, 3, 1) + struct.pack('>HHH', 1, 2, 3)))    # TRKGRP_STATUS_EVENT
    s(msg(23, u(3, 5000, 0) + struct.pack('>HH', 1, 2)))     # count over 1023
    s(msg(24, u(17, 1)))                                  # SERVICE_STATUS_EVENT
    s(msg(41, u(7, 100) + fstr(18, 'ani') + fstr(20, 'dnis') + b'\0\0\0'))      # ROUTE_REQUEST_EVENT
    r(msg(42, u(7, 2) + fstr(22, 'label') + b'\0\0\0'))   # ROUTE_SELECT
    s(msg(43, u(7, 0)))                                   # ROUTE_END_EVENT
    r(msg(44, u(7, 0xe)))                                 # ROUTE_END
    s(msg(45, u(5, 0xFFFFFFFE)))                          # TIME_SYNCH_REQ (lag -2)
    r(msg(46, u(5)))                                      # TIME_SYNCH_CONF
    s(msg(48, u(0)))                                      # SIMULATOR_RESET_EVENT
    s(msg(49, struct.pack('>H', 0x03ff) + fstr(1, 'abc') + b'\0\0\0'))      # REGISTER_VARIABLES
    s(msg(7, u(9, 0) + fstr(1, 'bye') + b'\0\0\0'))       # CLOSE_REQ
    r(msg(8, u(9)))                                       # CLOSE_CONF

    # ---- service control messages, each sub type
    g = Flow(40002, 7000, main)
    g.open()
    s, r = g.c2s, g.s2c
    s(sc(1, 5, 1, u(4)))                                  # INIT_SERVICE_CTRL_REQ
    r(sc(2, 5, 1, u(4)))                                  # CONF
    r(sc(3, 5, 2, u(4, 0xff)))                            # DATA
    r(sc(4, 5, 3, u(4)))                                  # END
    s(sc(5, 6, 1, u(1, 2, 3) + F))                        # NEW_CALL
    s(sc(6, 6, 2, u(1, 2, 3) + fstr(18, 'ani') + b'\0\0\0'))   # REQUEST_INSTRUCTION
    r(sc(7, 6, 3, u(5) + fstr(38, 'script') + b'\0\0\0'))      # RUN_SCRIPT_REQ
    s(sc(8, 6, 4, u(5, 0) + fstr(22, 'result') + b'\0\0\0'))   # RUN_SCRIPT_RESULT
    r(sc(9, 6, 5, u(1) + fstr(22, 'label') + b'\0\0\0'))       # CONNECT
    s(sc(10, 6, 6, u(4) + fstr(1, 'txt') + b'\0\0\0'))         # EVENT_REPORT
    s(sc(11, 6, 7, u(5, 0x12)))                           # DIALOGUE_FAILURE_CONF
    s(sc(12, 6, 8, u(0x22)))                              # DIALOGUE_FAILURE_EVENT
    s(sc(13, 7, 1, u(4, 3, 2) + struct.pack('>HHHH', 1, 4, 2, 3)))   # INIT_SERVICE_CTRL_TRKGRP
    s(sc(14, 7, 2, u(4, 17, 1, 2, 3)))                    # INIT_SERVICE_CTRL_SERVICE
    for opst in (0, 4, 50, 90, 140):
        s(sc(15, 7, 3, u(4, 1700000000, 0, opst, 9, 8)))    # INIT_SERVICE_CTRL_VRU
    s(sc(16, 8, 1, u(3, 2) + struct.pack('>HHHH', 1, 4, 2, 2)))      # TRKGRP_STATUS
    s(sc(17, 8, 2, u(17, 1)))                             # SERVICE_STATUS
    for opst in (0, 2, 40, 80, 130):
        s(sc(18, 8, 3, u(1700000000, 0, opst, 7)))        # VRU_STATUS
    s(sc(19, 9, 1, u(4, 8)))                              # CANCEL
    s(sc(20, 9, 2, u(0)))                                 # RELEASE normal
    s(sc(20, 9, 3, u(1)))                                 # RELEASE no route
    s(sc(21, 9, 4, u(100, 17) + fstr(18, 'ani') + b'\0\0\0'))   # NEW_DIALOGUE
    r(sc(22, 9, 5, fstr(37, 'ivr') + b'\0\0\0'))          # CONNECT_TO_RESOURCE
    s(sc(23, 9, 6))                                       # RESOURCE_CONNECTED
    r(sc(24, 9, 7, fstr(33, 'ced') + b'\0\0\0'))          # MICROAPP_CONTEXT
    r(sc(25, 9, 8, u(4, 0, 1) + fmedia(47, b'H', b'A', b'http://x/p.wav') + fmedia_t(48, b'Hello') + fmedia_d(49, 1, 4, b'42') + b'\0\0\0'))  # MICROAPP_PLAY
    r(sc(26, 9, 9, u(4, 1) + fmedia(47, b'S', b'S', b'stream') + b'\0\0\0'))   # PLAY_CONTINUE
    r(sc(27, 9, 10, u(4, 35, 5000, 3000, 2, 3, 1, 10, 1, 0) + fstr(1, 'c') + b'\0\0\0'))   # COLLECT_DATA
    r(sc(28, 9, 11, u(4, 5000, 2, 3, 0x1ff, 1, 1) + fstr(1, 'm') + b'\0\0\0'))     # MENU
    for code in (0, 1, 1001, 1999, 7):
        s(sc(29, 9, 12, u(4, code) + fstr(56, 'err') + b'\0\0\0'))      # MICROAPP_RESULT
    r(sc(30, 9, 13, fstr(37, 'tmp') + b'\0\0\0'))         # TEMPORARY_CONNECT
    pad = fstr(1, 'p') + b'\0\0\0'
    s(sc(5, 0xFFFFFFFF, 0, u(1, 2, 3) + pad))             # DialogueID/SendSeqNo expert
    s(sc(5, 0, 0xFFFFFFFF, u(1, 2, 3) + pad))
    s(sc(5, 0xFFFFFFFF, 0xFFFFFFFF, u(1, 2, 3) + pad))    # both -1: no expert
    s(sc(31, 9, 14, u(0)))                                # unknown sub type: warning
    s(sc(0, 9, 15, u(0)))

    # ---- PDU framing: several PDUs in a segment (reproducer of the PDU length
    # offset fix), a PDU split over segments, unknown second PDU
    h = Flow(40003, 7000, main)
    h.open()
    h.c2s(msg(5, u(1)) + msg(45, u(2, 3)) + msg(6, u(4)))             # ged125_pdu_len_offset.py
    h.c2s(msg(5, u(1)) + msg(99, u(0xdeadbeef)) + msg(6, u(4)))        # unknown second message type
    big = msg(15, u(100, 1, 2, 3) + F)
    h.c2s(big[:14]); h.c2s(big[14:40]); h.c2s(big[40:])                # split PDU
    h.c2s(msg(5, u(1))[:6])                                            # too short for the dissector: TCP
    h.c2s(msg(5, u(1))[6:])
    h.close()

    # ---- the media specifier / floating field sweep of the fix, restricted to valid
    # values (the full sweep is in the malformed capture)
    k = Flow(40004, 7000, main)
    k.open()
    for mp, extra in ((b'H', 2), (b'S', 2), (b'O', 2), (b'F', 2), (b'T', 1), (b'D', 9)):
        for n in (0, 1, 2, 3, 9, 10):
            body = u(100, 1, 2, 3)
            if mp == b'D':
                val = mp + u(2, 4) + b'x' * max(n - 9, 0) if n >= 9 else b''
            elif mp == b'T':
                val = mp + b'y' * max(n - 1, 0) if n >= 1 else b''
            else:
                val = mp + b'A' + b'z' * (n - 2) if n >= 2 else b''
            body += fl(47, val) + b'\0\0\0'
            k.c2s(msg(15, body))
    k.c2s(msg(15, u(1, 1, 1, 1) + farr(44, 7, 1, b'ABCDEFG') + b'\0\0\0'))
    k.close()

    # ================= malformed
    mal = []
    x = Flow(40010, 7000, mal)
    x.open()
    # the floating field sweep: all types, lengths 0..12 and all media protocols
    for ft in range(0, 61):
        for L in range(0, 13):
            for proto in b'HSOFTDX':
                x.c2s(msg(7, u(1, 0) + bytes([ft, L, proto]) + b'A' * 20)) if (ft in (1, 19, 35, 41, 42, 44, 47, 49) and L in (0, 1, 3, 5, 12)) or (ft in (47,48,49,50) and proto in b'HDT') else None
    # lengths that wrap and go past the segment
    for hl in (0xfffffff8, 0xfffffffb, 0xffffffff, 0x7ffffff8):
        y = Flow(40011 + hl % 7, 7000, mal)
        y.open()
        y.c2s(msg(7, b'\x13\x02AB' + b'\0' * 8, hl))
    # floating field with length beyond the message
    z = Flow(40020, 7000, mal)
    z.open()
    z.c2s(msg(15, u(1, 1, 1, 1) + bytes([18, 200]) + b'short' + b'\0' * 3))
    z.c2s(msg(47, u(5, 1, 1) + u(1, 2, 3) + bytes([18, 100]) + b'abc'))
    z.c2s(msg(47, u(5, 1, 1, 1)))                                  # NEW_CALL truncated
    z.c2s(msg(3, u(1)))                                             # OPEN_REQ truncated
    z.c2s(msg(11, u(1)))                                            # truncated trunk group data
    z.c2s(msg(48, b''))                                             # SIMULATOR_RESET without data
    z.c2s(msg(49, b'\x01'))                                         # REGISTER_VARIABLES, one octet
    z.c2s(msg(22, u(1, 2)))                                         # VRU_STATUS_EVENT without op status
    z.c2s(msg(1, u(1, 2), length=500))                              # claims 500 bytes, FIN follows
    # no floating field at all: the "Float Message" subtree is added with length 4 beyond the end
    z.c2s(sc(5, 6, 1, u(1, 2, 3)))
    z.c2s(msg(7, u(9, 0)))
    z.c2s(msg(21, u(100)))
    z.fin_c()
    return main, mal

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal = build()
    pcap(os.path.join(out, 'ged125-coverage.pcap'), main)
    pcap(os.path.join(out, 'ged125-coverage-malformed.pcap'), mal)

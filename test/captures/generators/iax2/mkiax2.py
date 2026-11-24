#!/usr/bin/env python3
# Generates test/captures/iax2_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-iax2.c (Inter-Asterisk eXchange v2, UDP 4569).
Usage: mkiax2.py <outdir> [-v]   (needs pcaplib.py beside it)
Authentication fields (challenge, MD5/RSA results, keys, provisioning data)
hold constant placeholder text, never real credentials or keys."""
import struct
import sys
import os
from pcaplib import eth, ip4, pcapng, udp

C, S = '192.0.2.1', '192.0.2.2'
MC, MS = '02:00:00:00:00:01', '02:00:00:00:00:02'

# frame types
DTMF_END, VOICE, VIDEO, CONTROL, NULL, IAX, TEXT, IMAGE, HTML, CNG, MODEM, DTMF_BEGIN = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12

def ie(i, data=b''):
    return bytes([i, len(data)]) + data
def s(i, text): return ie(i, text.encode())
def u16(i, v): return ie(i, struct.pack('>H', v))
def u32(i, v): return ie(i, struct.pack('>I', v))
def sockaddr(family=2, port=4569, addr=(192, 0, 2, 9)):
    return ie(18, struct.pack('<H', family) + struct.pack('>H', port) + bytes(addr) + b'\0' * 8)
def caps2(v=0, mask=0x04): return ie(55, bytes([v]) + struct.pack('>Q', mask))
def fmt2(v=0, mask=0x04): return ie(56, bytes([v]) + struct.pack('>Q', mask))

def full(scall, dcall, ts, oseq, iseq, ftype, csub, body=b'', retrans=False):
    return struct.pack('>HHIBBBB', 0x8000 | scall, (0x8000 if retrans else 0) | dcall, ts, oseq, iseq, ftype, csub) + body
def mini(scall, ts, payload):
    return struct.pack('>HH', scall, ts) + payload
def minivideo(scall, ts, payload, marker=False):
    return struct.pack('>HHH', 0, 0x8000 | scall, ts | (0x8000 if marker else 0)) + payload
def trunk(ts, calls, with_ts):
    out = struct.pack('>HBBI', 0, 1, 1 if with_ts else 0, ts)
    for scall, data, cts in calls:
        out += (struct.pack('>HHH', len(data), scall, cts) if with_ts else struct.pack('>HH', scall, len(data))) + data
    return out

def datagram(src, sport, dport, payload, ident=1):
    dst = S if src == C else C
    return eth(MS if src == C else MC, MC if src == C else MS, 0x0800,
               ip4(src, dst, 17, udp(sport, dport, payload), ident=ident))

def build(out, verbose):
    fr, marks = [], []
    n = [0]
    def pk(src, payload, desc=None, ifc=0):
        n[0] += 1
        if desc: marks.append((len(fr) + 1, desc))
        fr.append((ifc, datagram(src, 4569, 4569, payload, ident=n[0] & 0xffff)))

    # ---------------------------------------------------------------- call 1
    A, B = 1000, 2000     # source call numbers of caller (client) and callee (server)
    ts0 = 0
    new = (u16(11, 2) + s(2, '5551234') + s(1, '5559876') + s(3, '5551234') + s(4, 'Test Caller')
           + s(5, 'default') + s(6, 'testuser') + ie(8, struct.pack('>I', 0x0000fffd)) + ie(9, struct.pack('>I', 4))
           + s(10, 'en') + s(13, '5559876') + u16(12, 0) + u16(14, 6) + ie(38, b'\x00') + ie(39, b'\x21')
           + u16(40, 0) + s(28, '5550000') + sockaddr() + caps2() + fmt2() + u16(41, 8) + s(45, 'ulaw')
           + u32(31, (25 << 25) | (6 << 21) | (15 << 16) | (12 << 11) | (30 << 5) | 10) + s(21 + 11, 'Test Phone')
           + ie(54, b'?') + s(32, 'ATA') + ie(25) + s(26, 'moh') + s(53, 'placeholder'))
    pk(C, full(A, 0, 0, 0, 0, IAX, 1, new), 'call 1: NEW with the commonly used IEs')
    pk(S, full(B, A, 5, 0, 1, IAX, 40, ie(54, b'placeholder-token')), 'CALLTOKEN')
    pk(S, full(B, A, 10, 1, 1, IAX, 8, u16(14, 6) + s(6, 'testuser') + s(15, 'placeholder-challenge')), 'AUTHREQ')
    pk(C, full(A, B, 20, 1, 2, IAX, 9, s(17, 'a' * 32) + s(16, 'a' * 32)), 'AUTHREP (placeholder MD5/RSA result)')
    pk(S, full(B, A, 30, 2, 2, IAX, 7, ie(9, struct.pack('>I', 4)) + u16(14, 6) + u16(21, 2000) + sockaddr(2, 4569, (192, 0, 2, 2)) + ie(23, b'\x05')), 'ACCEPT')
    pk(C, full(A, B, 40, 2, 3, IAX, 4), 'ACK')
    pk(S, full(B, A, 50, 3, 3, CONTROL, 3), 'Control RINGING')
    pk(S, full(B, A, 60, 4, 3, CONTROL, 4), 'Control ANSWER')
    pk(C, full(A, B, 70, 3, 5, CONTROL, 0xff), 'Control stop sounds')
    for i, c in enumerate((2, 1, 3, 4, 8, 10)):    # compressed and plain codec subclasses
        pk(C, full(A, B, 80 + 20 * i, 4 + i, 5, VOICE, 1 << c if c < 7 else 0x80 | c, bytes(range(40))), 'voice, full frame' if i == 0 else None)
    for i, cs in enumerate((0x01, 0x20, 0x40)):
        pk(C, full(A, B, 290 + i, 10, 5, VOICE, cs, bytes(40)), 'voice, plain subclass 0x%02x' % cs)
    pk(S, full(B, A, 295, 18, 5, VIDEO, 0x80 | 18, bytes(4) + bytes(8)), 'video from the callee (reverse direction)')
    pk(C, full(A, B, 300, 10, 5, VOICE, 0x80 | 15, bytes(40)), 'voice SLINEAR16 (compressed subclass)')
    pk(C, full(A, B, 310, 11, 5, VOICE, 0xff, bytes(10)), 'voice, subclass -1')
    pk(C, full(A, B, 320, 12, 5, VOICE, 0x03, bytes(10)), 'voice, unknown plain subclass')
    pk(C, full(A, B, 330, 13, 5, VOICE, 0x04, b''), 'voice, empty payload')
    pk(C, mini(A, 340, bytes(160)), 'mini voice frame')
    pk(S, mini(B, 350, bytes(160)), 'mini voice frame from the callee (no codec seen yet)')
    pk(C, mini(A, 360, b''), 'mini voice frame, empty')
    pk(C, full(A, B, 70000, 14, 5, VOICE, 0x04, bytes(20)), 'voice, timestamp beyond 16 bits')
    pk(C, mini(A, 4464, bytes(20)), 'mini voice after a 17-bit timestamp')
    # video
    pk(C, full(A, B, 400, 15, 5, VIDEO, 0x80 | 18, bytes(4) + b'\x01' * 20), 'video H.261 full frame')
    pk(C, full(A, B, 410, 16, 5, VIDEO, 0x40 | 0x80 | 19, bytes(4) + b'\x02' * 20), 'video H.263 full frame with the marker bit')
    pk(C, full(A, B, 420, 17, 5, VIDEO, 0x80 | 21, bytes(16)), 'video H.264 (no dissector)')
    pk(C, minivideo(A, 430, bytes(4) + b'\x03' * 10), 'mini video frame')
    pk(C, minivideo(A, 440, bytes(4) + b'\x03' * 10, marker=True), 'mini video frame with the marker')
    pk(C, minivideo(A, 450, b''), 'mini video frame, empty')
    # other frame types
    pk(C, full(A, B, 500, 18, 5, DTMF_BEGIN, ord('5')), 'DTMF begin')
    pk(C, full(A, B, 510, 19, 5, DTMF_END, ord('#')), 'DTMF end')
    pk(C, full(A, B, 520, 20, 5, TEXT, 0, b'hello world'), 'text')
    pk(C, full(A, B, 521, 21, 5, TEXT, 0, b''), 'text, empty')
    pk(C, full(A, B, 530, 22, 5, HTML, 1, b'http://192.0.2.1/test.html'), 'HTML link')
    pk(C, full(A, B, 531, 23, 5, HTML, 4, b''), 'HTML, other subclass')
    pk(C, full(A, B, 540, 24, 5, IMAGE, 1, bytes(10)), 'image')
    pk(C, full(A, B, 550, 25, 5, CNG, 20), 'comfort noise')
    pk(C, full(A, B, 560, 26, 5, MODEM, 1), 'modem T.38')
    pk(C, full(A, B, 561, 27, 5, MODEM, 2), 'modem V.150')
    pk(C, full(A, B, 562, 28, 5, MODEM, 9), 'modem unknown')
    pk(C, full(A, B, 570, 29, 5, NULL, 0), 'NULL')
    pk(C, full(A, B, 571, 30, 5, 0, 0), 'frame type 0')
    pk(C, full(A, B, 572, 31, 5, 99, 3), 'unknown frame type')
    pk(C, full(A, B, 573, 32, 5, CONTROL, 77), 'unknown control subclass')
    pk(C, full(A, B, 574, 33, 5, IAX, 99), 'unknown IAX subclass')
    pk(C, full(A, B, 575, 34, 5, IAX, 5, b''), 'IAX HANGUP, no IEs')
    pk(C, full(A, B, 580, 35, 5, DTMF_END, 0x01, retrans=True), 'retransmitted DTMF with a control character')
    # keepalive, lag and the rest of the IAX subclasses on this call
    pk(C, full(A, B, 600, 36, 5, IAX, 2), 'PING')
    pk(S, full(B, A, 601, 5, 37, IAX, 3), 'PONG')
    pk(C, full(A, B, 602, 37, 6, IAX, 11), 'LAGRQ')
    pk(S, full(B, A, 603, 6, 38, IAX, 12), 'LAGRP')
    pk(C, full(A, B, 604, 38, 7, IAX, 18), 'VNAK')
    pk(S, full(B, A, 605, 7, 39, IAX, 19, s(1, '5551234') + s(5, 'ctx')), 'DPREQ')
    pk(C, full(A, B, 606, 39, 8, IAX, 20, s(1, '5551234') + u16(20, 0x0001) + u16(19, 60)), 'DPREP')
    pk(S, full(B, A, 607, 8, 40, IAX, 21, s(1, '5559999')), 'DIAL')
    pk(C, full(A, B, 608, 40, 9, IAX, 28, s(26, 'default')), 'QUELCH')
    pk(S, full(B, A, 609, 9, 41, IAX, 29), 'UNQUELCH')
    pk(C, full(A, B, 610, 41, 10, IAX, 32, u16(24, 5)), 'MWI')
    pk(S, full(B, A, 611, 10, 42, IAX, 33, ie(23, b'\x63')), 'UNSUPPORTED')
    pk(C, full(A, B, 612, 42, 11, IAX, 34, u16(21, 77)), 'TRANSFER')
    pk(S, full(B, A, 613, 11, 43, IAX, 38, s(53, 'placeholder')), 'TXMEDIA')
    pk(C, full(A, B, 614, 43, 12, IAX, 39, s(44, 'k' * 32)), 'RTKEY (placeholder key text)')
    pk(S, full(B, A, 615, 12, 44, IAX, 31, s(6, 'page')), 'PAGE')
    pk(S, full(B, A, 616, 13, 44, IAX, 10), 'INVAL')
    # transfer on this call
    pk(C, full(A, B, 620, 44, 13, IAX, 22, u16(21, 3000) + sockaddr(2, 4569, (192, 0, 2, 7)) + u32(27, 5)), 'TXREQ with peer address and call number')
    pk(S, full(B, A, 621, 14, 45, IAX, 23, u32(27, 5)), 'TXCNT')
    pk(C, full(A, B, 622, 45, 14, IAX, 24, u32(27, 5)), 'TXACC')
    pk(S, full(B, A, 623, 15, 46, IAX, 25, u32(27, 5)), 'TXREADY')
    pk(C, full(A, B, 624, 46, 15, IAX, 26, u32(27, 5)), 'TXREL')
    pk(S, full(B, A, 625, 16, 47, IAX, 27, u32(27, 5)), 'TXREJ')
    pk(C, full(A, B, 626, 47, 16, IAX, 22, u16(21, 3001) + sockaddr(2, 4569, (192, 0, 2, 8)) + u32(27, 6)), 'second TXREQ')
    pk(C, full(A, B, 627, 48, 16, IAX, 22, u16(21, 3002) + sockaddr(2, 4569, (192, 0, 2, 5)) + u32(27, 7)), 'third TXREQ (too many transfers)')
    pk(C, full(A, B, 628, 49, 16, IAX, 22, sockaddr(10, 4569, (0, 0, 0, 0)) + u16(21, 3003)), 'TXREQ with an IPv6 apparent address (unsupported)')
    pk(C, full(A, B, 650, 50, 16, IAX, 5, ie(22, b'Normal clearing') + ie(42, b'\x10')), 'HANGUP with cause')
    pk(S, full(B, A, 660, 17, 51, IAX, 4), 'ACK of the hangup')

    # ---------------------------------------------------------------- call 2: registration, provisioning, misc
    R, Q = 1100, 2100
    pk(C, full(R, 0, 0, 0, 0, IAX, 13, s(6, 'testuser') + u16(19, 60) + s(44 + 0, 'x')[:0] + s(15, 'p')[:0]), 'call 2: REGREQ')
    pk(S, full(Q, R, 5, 0, 1, IAX, 14, u16(14, 2) + s(15, 'placeholder-challenge') + s(6, 'testuser')), 'REGAUTH')
    pk(C, full(R, Q, 10, 1, 1, IAX, 13, s(6, 'testuser') + s(16, 'a' * 32) + u16(19, 60)), 'REGREQ with MD5 result (placeholder)')
    pk(S, full(Q, R, 15, 1, 2, IAX, 15, s(6, 'testuser') + u16(19, 60) + sockaddr() + u32(31, 0x34a5a8aa) + s(2, '5551234')), 'REGACK')
    pk(C, full(R, Q, 20, 2, 2, IAX, 17, s(6, 'testuser') + s(23 - 1, 'bye')), 'REGREL')
    pk(S, full(Q, R, 25, 2, 3, IAX, 16, ie(22, b'No such user')), 'REGREJ')
    pk(C, full(R, Q, 30, 3, 3, IAX, 6, ie(22, b'Rejected') + ie(42, b'\x15')), 'REJECT')
    pk(C, full(1200, 0, 0, 0, 0, IAX, 30), 'POKE (new call)')
    pk(S, full(2200, 1200, 1, 0, 1, IAX, 3), 'PONG for the POKE')
    pk(C, full(1300, 0, 0, 0, 0, IAX, 35, s(32, 'Test') + s(33, 'svc') + u16(34, 1) + u32(37, 7) + s(29, 'prov=1') + ie(30, b'p' * 16)), 'PROVISION (placeholder data)')
    pk(C, full(1300, 0, 1, 1, 0, IAX, 36, u32(35, 1000) + ie(36, b'f' * 20)), 'FWDOWNL')
    pk(C, full(1300, 0, 2, 2, 0, IAX, 37, u32(35, 1000) + ie(36, b'f' * 20)), 'FWDATA')

    # every IE with a defined length, one NEW per IE group (the field/length checks)
    ies = (s(1, 'abc') + s(2, 'abc') + s(3, 'abc') + s(4, 'abc') + s(5, 'abc') + s(6, 'abc') + s(7, 'placeholder')
           + ie(8, struct.pack('>I', 0xffff)) + ie(9, struct.pack('>I', 8)) + s(10, 'en') + u16(11, 2) + u16(12, 1)
           + s(13, 'a') + u16(14, 1) + s(15, 'abc') + s(16, 'abc') + s(17, 'abc'))
    pk(C, full(1400, 0, 0, 0, 0, IAX, 1, ies), 'call 3: NEW with IEs 1-17')
    ies2 = (ie(19, struct.pack('>h', -1)) + u16(20, 5) + u16(21, 3) + s(22, 'cause') + ie(23, b'\x03') + ie(24, struct.pack('>h', 3))
            + ie(25) + ie(26) + u32(27, 1) + s(28, 'rdnis') + s(29, 'prov') + s(30, 'aesprov') + u32(31, 0x1234)
            + s(32, 'dev') + s(33, 'svc') + u16(34, 3) + u32(35, 4) + s(36, 'blockdata') + u32(37, 5) + ie(38, b'\x01')
            + ie(39, b'\x02') + u16(40, 3) + u16(41, 4) + ie(42, b'\x05') + u16(43, 2) + s(44, 'k' * 8) + s(45, 'ulaw')
            + u32(46, 1) + u32(47, 2) + u32(48, 3) + u16(49, 4) + u32(50, 5) + u32(51, 6) + s(52, 'var=val'))
    pk(C, full(1400, 2400, 1, 1, 0, IAX, 21, ies2), 'IEs 19-52')
    ies3 = (s(53, 'osp') + ie(54, b'') + caps2(0, 0xffffffffffffffff) + fmt2(0, 0x8000) + caps2(1, 5)[:0] + u32(255, 3)
            + ie(0, b'\x01') + ie(58, b'\x01\x02') + ie(100, b'\x01\x02\x03\x04') + ie(101, b'\x01\x02\x03') + ie(102, b'abcdefg'))
    pk(C, full(1400, 2400, 2, 2, 0, IAX, 21, ies3), 'IEs 53-56, DATAFORMAT, unknown IEs of every length')
    pk(C, full(1400, 2400, 3, 3, 0, IAX, 21, caps2(1, 5) + fmt2(2, 7)), 'IEs with an unknown version byte')

    # ---------------------------------------------------------------- frames of calls whose NEW was not captured
    pk(C, full(4000, 5000, 100, 1, 1, VOICE, 0x04, bytes(20)), 'full frame of an unknown call')
    pk(C, full(4000, 5000, 101, 1, 1, IAX, 5), 'IAX frame of an unknown call')
    pk(C, mini(4000, 102, bytes(20)), 'mini frame of an unknown call')
    pk(C, minivideo(4000, 103, bytes(10)), 'mini video frame of an unknown call')
    pk(C, full(4001, 0, 100, 1, 1, VOICE, 0x04, bytes(20)), 'full frame, destination call 0, unknown call')

    # ---------------------------------------------------------------- trunk frames
    pk(C, trunk(1000, [(1000, bytes(20), 10), (1001, bytes(20), 20), (1000, bytes(20), 30)], True), 'trunk with timestamps, 3 entries for 2 calls')
    pk(C, trunk(1020, [(1000, bytes(20), 0), (1002, bytes(8), 0)], False), 'trunk without timestamps')
    pk(C, trunk(1040, [], True), 'trunk with no calls')
    pk(C, trunk(1060, [], False), 'trunk without timestamps, no calls')
    pk(C, trunk(1080, [(1003, b'', 0)], False), 'trunk, one empty call')
    pk(C, trunk(1100, [(i + 1, b'', 0) for i in range(1500)], False), 'trunk with 1500 empty calls (reproducer of the quadratic call counting)')
    pk(C, b'\x00\x00\x01\x00' + struct.pack('>I', 1120) + struct.pack('>HH', 5, 2) + b'\xaa\xbb', 'trunk call whose length exceeds the data (reproducer of the 2 octet subtree overrun)')
    pk(C, trunk(1140, [(1000, b'\x01' * 4, 1), (2000, b'\x02' * 5, 2)], True)[:-2], 'trunk with timestamps, last call cut by the end of the frame')

    os.makedirs(out, exist_ok=True)
    pcapng(os.path.join(out, 'iax2-coverage.pcapng'), fr, ifaces=(1,))

    # ------------------------------------------------------------------ malformed capture
    mal, mfr = [], []
    def pm(src, payload, ifc=0):
        n[0] += 1
        mfr.append((ifc, datagram(src, 4569, 4569, payload, ident=n[0] & 0xffff)))
    E, F = 1600, 2600
    pm(C, full(E, 0, 0, 0, 0, IAX, 1, u16(11, 2)))
    pm(S, full(F, E, 1, 0, 1, IAX, 7))
    # fixed-length IEs with the wrong length
    pm(C, full(E, F, 2, 1, 1, IAX, 21, ie(255, b'\x01\x02\x03')))                    # DATAFORMAT length 3
    pm(C, full(E, F, 3, 2, 1, IAX, 21, ie(8, b'\x01\x02')))                          # CAPABILITY length 2
    pm(C, full(E, F, 4, 3, 1, IAX, 21, ie(9, b'\x01\x02')))                          # FORMAT length 2
    pm(C, full(E, F, 5, 4, 1, IAX, 21, ie(55, b'\x00' + b'\x01' * 4)))               # CAPABILITY2 length 5
    pm(C, full(E, F, 6, 5, 1, IAX, 21, ie(56, b'\x00' + b'\x01' * 4)))               # FORMAT2 length 5
    pm(C, full(E, F, 7, 6, 1, IAX, 21, ie(11, b'\x01\x02\x03\x04') + ie(24, b'\x01') + ie(46, b'\x01\x02') + ie(41, b'\x01')))
    pm(C, full(E, F, 8, 7, 1, IAX, 21, ie(18, b'\x02\x00\x11\xd9\xc0\x00')))         # apparent address too short
    pm(C, full(E, F, 9, 8, 1, IAX, 21, s(1, 'abc')[:3]))                              # IE truncated
    pm(C, full(E, F, 10, 9, 1, IAX, 21, bytes([6, 200]) + b'abc'))                    # IE length beyond the data
    pm(C, full(E, F, 11, 10, 1, IAX, 21, ie(31, b'\x01\x02')))                        # DATETIME short
    pm(C, full(E, F, 12, 11, 1, IAX, 21, b'\x06'))                                    # IE type without length
    pm(C, full(E, F, 13, 12, 1, TEXT, 0, b'\xff\xfe\xfd text'))                       # not UTF-8
    pm(C, full(E, F, 14, 13, 1, HTML, 1, b'http://x/\xff'))
    # truncated headers
    pm(C, b'\x80\x01')                                                                 # full frame without header
    pm(C, full(E, F, 15, 0, 0, IAX, 1)[:10])
    pm(C, b'\x00')                                                                     # one octet
    pm(C, b'\x00\x01\x02')                                                             # mini frame without timestamp
    pm(C, b'\x00\x00\x80')                                                             # mini video without scall
    pm(C, b'\x00\x00\x80\x01\x00')                                                     # mini video with a short timestamp
    pm(C, b'\x00\x00\x01')                                                             # trunk header cut
    pm(C, b'\x00\x00\x01\x01\x00\x00\x00')                                             # trunk ts cut
    pm(C, trunk(1, [(1, bytes(10), 1)], True)[:-5])
    pm(C, trunk(1, [(1, bytes(10), 1)], False)[:-5])
    pm(C, trunk(1, [(1, bytes(10), 1)], True) + b'\x00\x01\x00')                      # trailing bytes
    pm(C, full(E, F, 16, 14, 1, IAX, 1, bytes([1]))[:-0])                              # IE type without length, subclass NEW
    # circuit conflicts: wrong call numbers for an established call
    pm(C, full(E, F + 1, 17, 15, 1, VOICE, 0x04, bytes(8)))
    pm(S, full(F, E + 1, 18, 1, 1, VOICE, 0x04, bytes(8)))
    pm(S, full(F + 1, E, 19, 1, 1, VOICE, 0x04, bytes(8)))
    pm(C, full(E + 5, F, 20, 1, 1, VOICE, 0x04, bytes(8)))
    # a NEW that reuses the circuit of a running call
    pm(C, full(E, 0, 21, 0, 0, IAX, 1, u16(11, 2)))
    pm(C, full(E, F, 22, 1, 1, VOICE, 0x04, bytes(8)))
    # H.223 data call: the dissector of the data format (packet-h223.c) asks for more data, so
    # desegment_iax() reassembles; H.223 shows different items in the first and second pass, so
    # these frames are not in the main capture
    D1, D2 = 1500, 2500
    pm(C, full(D1, 0, 0, 0, 0, IAX, 1, u32(255, 2) + u16(11, 2)))
    pm(S, full(D2, D1, 1, 0, 1, IAX, 7, ie(9, struct.pack('>I', 4))))
    pm(C, full(D1, D2, 2, 1, 1, IAX, 4))
    for i in range(6):
        pm(C, full(D1, D2, 10 + 20 * i, 2 + i, 1, VOICE, 0x04, bytes([0x00] * 16)))
    pm(C, mini(D1, 200, bytes(16)))
    pm(C, full(D1, D2, 300, 8, 1, VOICE, 0x04, bytes([0xff, 0x7e, 0x7e, 0x01] * 8)))
    pm(S, full(D2, D1, 310, 1, 9, VOICE, 0x04, bytes(16)))
    pm(C, full(D1, D2, 320, 9, 2, IAX, 5))

    # H.223 streams with MUX flags (bit-reversed 0xe14d = 87 b2): a PDU completed by a later frame,
    # with and without the start of another PDU behind it
    for k, parts in enumerate(([bytes.fromhex('87b287b2' + '00' * 6), bytes.fromhex('11223344'), bytes.fromhex('87b287b2')],
                               [bytes.fromhex('87b2' + 'ff' * 4), bytes.fromhex('00' * 10), bytes.fromhex('87b2' + '01' * 3 + '87b2')],
                               [bytes.fromhex('87b287b2' + '00' * 4), bytes.fromhex('aabb87b287b25555'), bytes.fromhex('1122' + '87b287b2'), bytes.fromhex('3344')])):
        cn = 1800 + 10 * k
        pm(C, full(cn, 0, 0, 0, 0, IAX, 1, u32(255, 2)))
        pm(S, full(cn + 1, cn, 1, 0, 1, IAX, 7))
        pm(C, full(cn, cn + 1, 2, 1, 1, IAX, 4))
        for i, d in enumerate(parts):
            pm(C, full(cn, cn + 1, 10 + i, 2 + i, 1, VOICE, 0x04, d))
        pm(S, full(cn + 1, cn, 20, 1, 5, VIDEO, 0x80 | 18, bytes(8)))        # video frame from the callee: dst_vformat
    # the reproducer of "IAX2: Do not assert on a repeated frame in desegment_iax()":
    # PPP Multiplexing (PPPMux, 0x59) frames with several IAX2 voice frames of an H.223 call
    G1 = 1700
    pm(C, full(G1, 0, 0, 0, 0, IAX, 1, u32(255, 2)))
    pp = lambda a: b'\xff\x03\x00\x21' + ip4(C, S, 17, udp(4569, 4569, a))
    mux = b'\xff\x03\x00\x59'
    for i in range(3):
        sub = b'\x00\x21' + ip4(C, S, 17, udp(4569, 4569, full(G1, 0, 10 + i, 0, 0, VOICE, 0x04, b'\x00' * 16)))
        mux += struct.pack('>H', 0xc000 | len(sub)) + sub
    nm = len(mfr)
    mfr.append((1, mux))
    mfr.append((1, pp(full(G1, 0, 20, 0, 0, IAX, 5))))
    pcapng(os.path.join(out, 'iax2-coverage-malformed.pcapng'), mfr, ifaces=(1, 9))
    if verbose:
        for k, d in marks: print(k, d)
        print(len(fr), 'frames;', len(mfr), 'malformed frames (PPPMux reproducer: frame', nm + 1, ')')

if __name__ == '__main__':
    build(sys.argv[1], '-v' in sys.argv)

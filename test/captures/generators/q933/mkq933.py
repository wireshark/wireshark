#!/usr/bin/env python3
# Generates test/captures/q933_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Q.933 captures. Usage: mkq933.py <outdir> [-v]
Frame Relay (link type 107) frames on DLCI 0: Q.922 address, UI control
0x03, then the Q.933 message whose protocol discriminator 0x08 is also
the NLPID (the "fr.osinl" table reaches Q.933 by default)."""
import random
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv
random.seed(933)

def u8(v): return bytes([v & 0xff])
def u16(v): return struct.pack('>H', v)

def write_pcap(fn, frames, linktype=107):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, (data, note) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), len(data)))
            f.write(data)

def fr(q933, dlci=0, cr=0):
    # Q.922 two-octet address, control UI (0x03); the PDU starts with the NLPID/discriminator
    return bytes([((dlci >> 4) << 2) | (cr << 1), ((dlci & 0xf) << 4) | 1, 0x03]) + q933

def ie(ident, content=b''):
    return u8(ident) + u8(len(content)) + bytes(content)

def msg(mtype, ies=b'', cref=1, crlen=1, flag=False, disc=0x08):
    cr = bytearray((cref % (1 << (8 * crlen))).to_bytes(crlen, 'big')) if crlen else bytearray()
    if flag and cr: cr[0] |= 0x80
    return u8(disc) + u8(crlen) + bytes(cr) + u8(mtype) + ies

frames = []
LATE = []
def add(q933, note, user=True, **kw):
    frames.append((fr(q933, cr=0 if user else 1), note))
def one(ies, t=0x05, note=''):
    add(msg(t, b''.join(ies)), note)

MT = {0x00: 'ESCAPE', 0x01: 'ALERTING', 0x02: 'CALL PROCEEDING', 0x03: 'PROGRESS', 0x05: 'SETUP', 0x07: 'CONNECT',
      0x0f: 'CONNECT ACK', 0x45: 'DISCONNECT', 0x4d: 'RELEASE', 0x5a: 'RELEASE COMPLETE', 0x60: 'SEGMENT',
      0x75: 'STATUS ENQUIRY', 0x7d: 'STATUS', 0x62: 'unknown'}
for i, (t, n) in enumerate(sorted(MT.items())):
    add(msg(t, ie(0x14, b'\x0a') if i % 3 == 0 else b'', cref=0x10 + i, flag=bool(i & 1)), 'message ' + n, user=not (i & 1))
for crlen in (0, 1, 2, 3, 4):
    add(msg(0x7d, ie(0x28, b'hi'), cref=(0x1234 if crlen else 0), crlen=crlen, flag=True), 'call reference length %d' % crlen, user=False)
# single-octet IEs and shifts
one([b'\xd2', b'\xd0'], 0x05, 'repeat indicator')
one([b'\xa0', b'\xa1', b'\xb0', b'\xe0'], 0x05, 'single-octet IEs not decoded')
for cs in range(8):
    one([u8(0x90 | cs), ie(0x28, b'cs')], 0x7d, 'locking shift to codeset %d, IE' % cs)
    one([u8(0x98 | cs), ie(0x28, b'cs'), ie(0x28, b'cs0')], 0x7d, 'non-locking shift to codeset %d, IE' % cs)

# Bearer capability
def bc(*o): return ie(0x04, bytes(o))
bearer = [
    ('speech, mu-law', [0x80, 0x90, 0xa2]),
    ('speech, A-law', [0x80, 0x90, 0xa3]),
    ('3.1k audio', [0x90, 0x90, 0xa3]),
    ('unrestricted digital 64k, no layer 1', [0x88, 0x90]),
    ('unrestricted 384k', [0x88, 0x93]),
    ('2x64k', [0x88, 0x91]),
    ('1536k', [0x88, 0x95]), ('1920k', [0x88, 0x97]),
    ('video', [0x98, 0x90]), ('restricted digital', [0x89, 0x90]), ('digital with tones', [0x91, 0x90]),
    ('multirate', [0x88, 0x98, 0x85]),
    ('packet mode', [0x88, 0xc0]),
    ('ext clear in octet 3 (3a)', [0x08, 0x80, 0x90]),
    ('ISO coding', [0xa8, 0x90]),
    ('national coding', [0xc8, 0x90]),
    ('network coding', [0xe8, 0x90]),
    ('layer 1 V.110 with rate, intermediate rate, NIC, flow control', [0x88, 0x90, 0x21, 0x48, 0x00, 0x00, 0x10]),
    ('V.110 full chain', [0x88, 0x90, 0x01, 0x03, 0x24, 0x00, 0x80 | 0x13]),
    ('V.110 asynchronous 5a 5b 5c 5d', [0x88, 0x90, 0x21, 0x28, 0x2b, 0x23, 0xfe]),
    ('V.110 synchronous', [0x88, 0x90, 0x21, 0x08, 0x2b, 0x13, 0x92]),
    ('V.110 with bit set variations', [0x88, 0x90, 0x21, 0x05, 0x32, 0x42, 0xb3]),
    ('G.711 u-law layer 1', [0x80, 0x90, 0xa2]), ('G.721', [0x80, 0x90, 0xa4]), ('H.221', [0x98, 0x90, 0xa5]),
    ('H.223', [0x98, 0x90, 0xa6]), ('non-ITU rate adaption', [0x88, 0x90, 0x27, 0x80]),
    ('V.120 rate adaption full', [0x88, 0x90, 0x28, 0x08, 0xcb, 0xff]),
    ('V.120 headers', [0x88, 0x90, 0x28, 0x7f, 0xff]),
    ('X.31 HDLC', [0x88, 0x90, 0xa9]), ('G.728', [0x80, 0x90, 0xaa]), ('G.729', [0x80, 0x90, 0xab]),
    ('layer 1 only ext clear', [0x88, 0x90, 0x22]),
    ('layer 1 modem type', [0x88, 0x90, 0x21, 0x11, 0x92, 0x92, 0xd2]),
    ('layer 2 Q.921', [0x88, 0x90, 0xa2, 0xc2]),
    ('layer 2 X.25 link, mode', [0x88, 0x90, 0xa2, 0x46, 0x81]),
    ('layer 2 X.25 link, mode and window', [0x88, 0x90, 0xa2, 0x46, 0x01, 0x87]),
    ('layer 2 user-specified', [0x88, 0x90, 0xa2, 0x50, 0x81]),
    ('layer 2 user-specified and window', [0x88, 0x90, 0xa2, 0x50, 0x01, 0x8f]),
    ('layer 2 LLC', [0x88, 0x90, 0xa2, 0xcc]), ('layer 2 LAPB', [0x88, 0x90, 0xa2, 0xc6]),
    ('layer 3 X.25 PL', [0x88, 0x90, 0xa2, 0xc2, 0xe6]),
    ('layer 3 X.25 PL, mode', [0x88, 0x90, 0xa2, 0xc2, 0x66, 0x81]),
    ('layer 3 X.25 PL, mode, packet size', [0x88, 0x90, 0xa2, 0xc2, 0x66, 0x01, 0x84]),
    ('layer 3 X.25 PL, mode, size, window', [0x88, 0x90, 0xa2, 0xc2, 0x66, 0x01, 0x04, 0x87]),
    ('layer 3 ISO 8208', [0x88, 0x90, 0xa2, 0xc2, 0x67, 0x01, 0x04, 0x85]),
    ('layer 3 X.223', [0x88, 0x90, 0xa2, 0xc2, 0x68, 0x81]),
    ('layer 3 ISO 8473', [0x88, 0x90, 0xa2, 0xc2, 0xe9]),
    ('layer 3 T.70', [0x88, 0x90, 0xa2, 0xc2, 0xea]),
    ('layer 3 user-specified', [0x88, 0x90, 0xa2, 0xc2, 0x70, 0x84]),
    ('layer 3 TR 9577 IP', [0x88, 0x90, 0xa2, 0xc2, 0x6b, 0x66, 0x40]),
    ('layer 3 TR 9577 SNAP', [0x88, 0x90, 0xa2, 0xc2, 0x6b, 0x40, 0x00]),
    ('layer 3 TR 9577 ext set', [0x88, 0x90, 0xa2, 0xc2, 0xeb]),
    ('layer 3 other protocol', [0x88, 0x90, 0xa2, 0xc2, 0x61, 0x81]),
    ('layer 3 TR 9577 7a ext set', [0x88, 0x90, 0xa2, 0xc2, 0x6b, 0xc0]),
    ('layer 1 5c ext set', [0x88, 0x90, 0x21, 0x08, 0x05, 0x93]),
    ('layer 1 5d ext set', [0x88, 0x90, 0x21, 0x08, 0x05, 0x13, 0xf0]),
    ('layer 1 5b ext set', [0x88, 0x90, 0x21, 0x08, 0x85]),
]
for n, o in bearer:
    one([bc(*o)], note='bearer capability: ' + n)
one([ie(0x7c, bytes([0x88, 0x90, 0x21, 0x08, 0xcb]))], note='low layer compatibility')
one([ie(0x7c, bytes([0x80, 0x90, 0xa3, 0xc2, 0xe6]))], note='low layer compatibility 2')

LATE.append((msg(0x05, ie(0x04, bytes([0x88, 0x90, 0xa2, 0xc2, 0x6b]))), 'bearer capability: layer 3 TR 9577 as the last octet (reads two octets)'))
# Cause
def cause(loc, val, *extra, first=0x80):
    return ie(0x08, bytes([first | loc, 0x80 | val]) + b''.join(bytes(e) for e in extra))
for v, n in ((1, 'unallocated number'), (3, 'no route'), (16, 'normal clearing'), (17, 'user busy'), (18, 'no user responding'),
             (19, 'no answer'), (21, 'call rejected'), (22, 'number changed'), (27, 'destination out of order'),
             (28, 'invalid number format'), (31, 'normal unspecified'), (34, 'no circuit'), (38, 'network out of order'),
             (41, 'temporary failure'), (42, 'congestion'), (44, 'channel unavailable'), (47, 'resource unavailable'),
             (57, 'bearer not authorised'), (58, 'bearer not available'), (65, 'bearer not implemented'),
             (79, 'service not implemented'), (81, 'invalid call reference'), (88, 'incompatible destination'),
             (95, 'invalid message'), (96, 'mandatory IE missing'), (97, 'message type non-existent'),
             (99, 'IE non-existent'), (100, 'invalid IE contents'), (101, 'message not compatible'),
             (102, 'recovery on timer expiry'), (111, 'protocol error'), (127, 'interworking')):
    for loc in (0, 2, 3, 4, 5, 7, 10):
        if loc != 0 and v not in (16, 21, 1):
            continue
        one([cause(loc, v)], 0x45, 'cause %d %s, location %d' % (v, n, loc))
    one([cause(0, v, b'\x01')], 0x45, 'cause %d with one octet' % v)
one([cause(2, 1, b'\x80')], 0x45, 'cause 1 diagnostic 0x80')
one([cause(2, 21, b'\x00')], 0x45, 'cause 21 rejection reason user specific, condition')
one([cause(2, 21, b'\x00', b'\xaa\xbb')], 0x45, 'cause 21 user specific with data')
one([cause(2, 21, b'\x04', b'\x70')], 0x45, 'cause 21 IE missing, called party number')
one([cause(2, 21, b'\x08', b'\x04')], 0x45, 'cause 21 IE insufficient, bearer capability')
one([cause(2, 21, b'\x01', b'\x70')], 0x45, 'cause 21 other diagnostic')
one([cause(2, 21, b'\x0c', b'\x01\x02')], 0x45, 'cause 21 reason 0x0c')
one([cause(2, 88, b'\x84\x88\x90')], 0x45, 'cause 88 three IE ids')
one([cause(2, 96, b'\x70\xfc')], 0x45, 'cause 96 two IE ids')
one([cause(2, 97, b'\x0d')], 0x45, 'cause 97 message type')
one([cause(2, 97, b'\x7e')], 0x45, 'cause 97 unknown message type')
one([cause(2, 102, b'T30')], 0x45, 'cause 102 timer T30')
one([cause(2, 102, b'T3')], 0x45, 'cause 102 timer short')
one([cause(2, 16, b'\xde\xad\xbe')], 0x45, 'cause 16 with diagnostic')
one([ie(0x08, b'\x00\x90')], 0x45, 'cause ext bit clear in octet 3 then 3a')
one([ie(0x08, b'\x00\x80\x90')], 0x45, 'cause ext clear in octet 3, 3a, value')
one([ie(0x08, b'\x00')], 0x45, 'cause ext clear, nothing after')
one([ie(0x08, b'\x82')], 0x45, 'cause location only')
one([ie(0x08, b'\xa2\x90')], 0x45, 'cause ISO coding')
one([ie(0x08, b'\xc2\x90')], 0x45, 'cause national coding')
one([ie(0x08, b'\xe2\x90')], 0x45, 'cause network coding')
one([ie(0x08, b'\xe2')], 0x45, 'cause network coding, location only')
one([ie(0x08, b'\x82\x80\x81\x82\x83\x84')], 0x45, 'cause with recommendation octet')
one([ie(0x08, b'\x02\x00\x90')], 0x45, 'cause with recommendation octet, ext clear')
one([ie(0x08, b'')], 0x45, 'cause empty')
one([cause(0, 16), cause(0, 31)], 0x4d, 'two causes')

# Call state, change status, call identity, facility etc
for st in (0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 15, 17, 19, 22, 25, 61, 62, 0x30):
    one([ie(0x14, bytes([st]))], 0x7d, 'call state %02x' % st)
one([ie(0x14, bytes([0x2a]))], 0x7d, 'call state national coding')
one([ie(0x14, bytes([0x4a]))], 0x7d, 'call state ISO coding')
one([ie(0x14, bytes([0x6a]))], 0x7d, 'call state network coding')
one([ie(0x14, b'')], 0x7d, 'call state empty')
one([ie(0x01, b'\x81'), ie(0x01, b'\x00'), ie(0x01, b'')], 0x01 + 0x00, 'change status (preferred/new status), empty')
one([ie(0x10, b'\x01\x02')], 0x25, 'call identity')

# Channel identification
def chan(*o): return ie(0x18, bytes(o))
for n, o in (('basic, B1', [0x81 | 0x00]), ('basic, B2 exclusive', [0x8a]), ('basic, any', [0x83]), ('basic, none', [0x80]),
             ('basic D channel', [0x84]),
             ('interface identified, basic', [0xc1, 0x85]), ('interface id, 2 octets', [0x41, 0x05, 0x85]),
             ('interface id, 3 octets', [0x41, 0x05, 0x06, 0x87]), ('interface id cut', [0x41, 0x05]),
             ('PRI, channel 5 number', [0xa1, 0x83, 0x85]), ('PRI exclusive, channel 12', [0xa9, 0x83, 0x8c]),
             ('PRI, number extension', [0xa1, 0x83, 0x05, 0x86]),
             ('PRI slot map', [0xa1, 0x93, 0xff, 0xff, 0x7f]), ('PRI slot map, one octet', [0xa1, 0x93, 0x01]),
             ('PRI, H0 units', [0xa1, 0x86, 0x82]), ('PRI, H11 units', [0xa1, 0x88, 0x81]), ('PRI, H12 units', [0xa1, 0x89, 0x81]),
             ('PRI, any channel', [0xa3]), ('PRI, no channel', [0xa0]),
             ('PRI, ISO coding', [0xa1, 0xa3, 0x85]), ('PRI interface identified, slot map', [0xe1, 0x01, 0x83, 0x90, 0xaa]),
             ('PRI, no octet 3.2', [0xa1]), ('PRI, ext clear in octet 3.2 only', [0xa1, 0x03]),
             ('PRI interface id then channel', [0xe1, 0x89, 0x83, 0x8a]),
             ('empty', [])):
    one([chan(*o)], 0x02, 'channel identification: ' + n)

# Progress indicator, network specific facilities, notification, display etc
for loc, desc in ((0, 1), (1, 2), (2, 3), (4, 4), (5, 5), (7, 8), (10, 1), (0, 0x7f)):
    one([ie(0x1e, bytes([0x80 | loc, 0x80 | desc]))], 0x03, 'progress indicator location %d description %d' % (loc, desc))
one([ie(0x1e, b'\x80')], 0x03, 'progress indicator without description')
one([ie(0x1e, b'\xa0\x81')], 0x03, 'progress indicator ISO coding')
one([ie(0x1e, b'')], 0x03, 'progress indicator empty')
one([ie(0x20, b'\x00\x01'), ie(0x20, b'\x03\x00\x01x'), ie(0x20, b'\x05\xa1abc\xff'), ie(0x20, b'\x02\x00'), ie(0x20, b'\x01'), ie(0x20, b'')], 0x05, 'network specific facilities variants')
one([ie(0x20, b'\x04\x00abcd\x81'), ie(0x20, b'\x7f\x03ab')], 0x05, 'network specific facilities long id, id longer than IE')
one([ie(0x78, b'\x02\x21' + b'1234'), ie(0x78, b'\x03\x33' + b'5678\x80'), ie(0x78, b'\x00')], 0x05, 'transit network selection')
for d in (0, 1, 2, 3, 0x7f):
    one([ie(0x27, bytes([0x80 | d]))], 0x6e, 'notification indicator %d' % d)
one([ie(0x27, b'')], 0x6e, 'notification indicator empty')
one([ie(0x28, b'Hello'), ie(0x28, b''), ie(0x28, b'a\x01\x7f')], 0x7b, 'display, empty, binary')
for ln in (5, 6):
    one([ie(0x29, bytes(range(0x19, 0x19 + ln)))], 0x7b, 'date/time length %d' % ln)
for ln in (0, 4, 7):
    LATE.append((msg(0x7b, ie(0x29, bytes(range(0x19, 0x19 + ln)))), 'date/time length %d' % ln))
one([ie(0x2c, b'1234*#'), ie(0x2c, b'')], 0x7b, 'keypad facility')
one([ie(0x32, b'\x01'), ie(0x32, b'\x80')], 0x7b, 'information request (not dissected)')
for s in (0, 1, 3, 4, 5, 9, 0x3f, 0x40, 0x47, 0x4f, 0x20, 0x80):
    one([ie(0x34, bytes([s]))], 0x7b, 'signal %02x' % s)
LATE.append((msg(0x7b, ie(0x34, b'')), 'signal empty'))
LATE.append((msg(0x7b, ie(0x34, b'\x01\x02')), 'signal two octets'))
one([ie(0x36, b'\x01'), ie(0x38, b'\x01\x02'), ie(0x39, b'\x01\x02'), ie(0x3b, b'\x01\x02'), ie(0x3a, b'\x01\x02')], 0x7b, 'switchhook, feature, endpoint, SPID (not dissected)')
one([ie(0x40, bytes([0x83, 0x8d, 0x8d, 0x8d]))], 0x05, 'information rate')
one([ie(0x40, bytes([0x80, 0x0a, 0x0b, 0x0c]))], 0x05, 'information rate 2')
LATE.append((msg(0x05, ie(0x40, bytes([1, 2, 3]))), 'information rate, length 3'))

# Transit delay (3-octet 14-bit values)
one([ie(0x42, b'\x00\x01\x85')], 0x05, 'end-to-end transit delay, cumulative')
one([ie(0x42, b'\x00\x01\x85\x00\x02\x86')], 0x05, 'end-to-end transit delay, cumulative and requested')
one([ie(0x42, b'\x00\x01\x85\x00\x02\x86\x03\x00\x87')], 0x05, 'end-to-end transit delay, all three')
one([ie(0x43, b'\x01\x02\x83')], 0x05, 'transit delay selection and indication')   # smallfix 1 (last IE)
one([ie(0x43, b'\x01\x02\x83'), ie(0x28, b'x')], 0x05, 'transit delay selection, then another IE')
one([ie(0x43, b'\x7f\x7f\xff')], 0x05, 'transit delay maximum value')
for b, n in ((b'\x80\x00\x00', 'first octet ends'), (b'\x00\x80\x00', 'second octet ends'), (b'\x00\x01\x05', 'third octet does not end'),
             (b'\x00', 'one octet'), (b'\x00\x01', 'two octets')):
    LATE.append((msg(0x05, ie(0x43, b)), 'transit delay selection, ' + n))
LATE.append((msg(0x05, ie(0x42, b'\x00\x01\x85\x00')), 'end-to-end transit delay, requested cut short'))
LATE.append((msg(0x05, ie(0x42, b'\x00\x01\x85\x00\x01\x85\x00')), 'end-to-end transit delay, maximum cut short'))

# Packet layer parameters
for v in (0x00, 0x01, 0x1f, 0x80, 0xff):
    one([ie(0x44, bytes([v]))], 0x05, 'packet layer binary parameters %02x' % v)
one([ie(0x44, b'')], 0x05, 'packet layer binary parameters empty')
one([ie(0x45, b'\x87\x85'), ie(0x45, b'\x87'), ie(0x45, b'')], 0x05, 'packet layer window size')
one([ie(0x46, b'\x84\x85'), ie(0x46, b'\x84'), ie(0x46, b'')], 0x05, 'packet size')
one([ie(0x47, b'\x01\x00\x07'), ie(0x47, b'\x02\x00\x07'), ie(0x47, b'\x03\x00\x07'), ie(0x47, b'\x04\x00\x07'),
     ie(0x47, b'\x05\x30\x31'), ie(0x47, b'\x06\x31'), ie(0x47, b'\x07\x31'), ie(0x47, b'\x01'), ie(0x47, b'')], 0x05, 'closed user group')
one([ie(0x4a, b'\x81'), ie(0x4a, b'\x82'), ie(0x4a, b'\x83'), ie(0x4a, b'')], 0x05, 'reverse charging indication')

# Numbers
def num(ident, *o, digits=b''): return ie(ident, bytes(o) + digits)
for ident, nm in ((0x4c, 'connected'), (0x6c, 'calling'), (0x70, 'called'), (0x74, 'redirecting'), (0x76, 'redirection')):
    add(msg(0x05, num(ident, 0x81, digits=b'12125551234')), nm + ' number: E.164 ext set')
    add(msg(0x05, num(ident, 0x01, 0x80, digits=b'442012345678')), nm + ' number: E.164, presentation octet')
    add(msg(0x05, num(ident, 0x21, 0x83, digits=b'442012345678')), nm + ' number: national')
    add(msg(0x05, num(ident, 0x41, 0xa3, digits=b'8884445')), nm + ' number: subscriber, network provided')
    add(msg(0x05, num(ident, 0x01, 0x20, 0x81, digits=b'555')), nm + ' number: redirection reason')
    add(msg(0x05, num(ident, 0x09, 0x00, digits=b'priv')), nm + ' number: private plan')
    add(msg(0x05, num(ident, 0x00, 0x80, digits=b'??')), nm + ' number: unknown plan')
    add(msg(0x05, num(ident, 0x81)), nm + ' number: no digits ext set')
    add(msg(0x05, num(ident, 0x01)), nm + ' number: ext clear, nothing after')
    add(msg(0x05, num(ident, 0x01, 0x00)), nm + ' number: ext clear, 3a only')
    add(msg(0x05, num(ident, 0x01, 0x00, 0x00)), nm + ' number: ext clear twice, nothing after')
    add(msg(0x05, ie(ident, b'')), nm + ' number empty')
for ident, nm in ((0x6d, 'calling'), (0x71, 'called')):
    add(msg(0x05, ie(ident, b'\x80\x01\x02\x03')), nm + ' subaddress NSAP')
    add(msg(0x05, ie(ident, b'\xa8\x01\x02\x03')), nm + ' subaddress user-specified odd')
    add(msg(0x05, ie(ident, b'\x80')), nm + ' subaddress type only')
    add(msg(0x05, ie(ident, b'')), nm + ' subaddress empty')

# High layer compatibility
for n, o in (('telephony', [0x91, 0x81]), ('G3 fax', [0x91, 0x84]), ('video telephony', [0x91, 0x60, 0x01]),
             ('audiovisual ext', [0x91, 0x60, 0x80 | 0x01]), ('audiovisual 0x61', [0x91, 0x61, 0x81]),
             ('0x62', [0x91, 0x62, 0x81]), ('0x68', [0x91, 0x68, 0x82]), ('maintenance', [0x91, 0x5e, 0x82]),
             ('management', [0x91, 0x5f, 0x82]), ('maintenance ext set', [0x91, 0xde]),
             ('ISO coding', [0xb1, 0x81]), ('other presentation method', [0x92, 0x81]),
             ('first octet only', [0x91]), ('audiovisual no extra', [0x91, 0x60]),
             ('ext clear, other characteristic', [0x91, 0x10, 0x82]),
             ('ext clear, other characteristic cut', [0x91, 0x10])):
    one([ie(0x7d, bytes(o))], 0x05, 'high layer compatibility: ' + n)
one([ie(0x7d, b'')], 0x05, 'high layer compatibility empty')

# User-user
one([ie(0x7e, b'\x00\x01\x02\x03')], 0x20, 'user-user, user-specific protocol')
one([ie(0x7e, b'\x04hello')], 0x20, 'user-user, IA5')
one([ie(0x7e, b'\x05\x01\x02')], 0x20, 'user-user, ASN.1 (not over IP)')
one([ie(0x7e, b'\x08\x01\x02')], 0x20, 'user-user, other')
one([ie(0x7e, b'\x00')], 0x20, 'user-user, protocol only')
one([ie(0x7e, b'')], 0x20, 'user-user empty')


# Frame Relay specific IEs: report type, link integrity verification, PVC status
# in codeset 0 (0x51, 0x53, 0x57) and in codeset 5 (ANSI 0x01, 0x03, 0x07; ITU 0x51, 0x53, 0x57)
RT = ((0, 'full status'), (1, 'link verify'), (2, 'async PVC status'), (7, 'other'))
for v, n in RT:
    add(msg(0x7d, ie(0x51, bytes([v]))), 'report type %s (codeset 0)' % n)
    add(msg(0x7d, b'\x95' + ie(0x51, bytes([v]))), 'report type %s (codeset 5)' % n)
    add(msg(0x7d, b'\x95' + ie(0x01, bytes([v]))), 'report type %s (ANSI)' % n)
add(msg(0x7d, ie(0x51, b'')), 'report type empty')
add(msg(0x7d, ie(0x53, b'\x05\x04')), 'link integrity verification (codeset 0)')
add(msg(0x7d, b'\x95' + ie(0x53, b'\x7f\x80')), 'link integrity verification (codeset 5)')
add(msg(0x7d, b'\x95' + ie(0x03, b'\x01\x01')), 'link integrity verification (ANSI)')
add(msg(0x7d, ie(0x53, b'\x05')), 'link integrity verification, one octet')
add(msg(0x7d, ie(0x53, b'')), 'link integrity verification empty')
for ln, n in ((2, 'DLCI 2 octets (too short)'), (3, 'DLCI 10 bits, status'), (4, 'DLCI 16 bits, status'), (5, 'DLCI 23 bits, status'), (6, 'six octets')):
    pass
add(msg(0x7d, ie(0x57, bytes([0x00, 0x2f, 0x82]))), 'PVC status, 10-bit DLCI 16, active')
add(msg(0x7d, ie(0x57, bytes([0x04, 0x4f, 0x00, 0x84]))), 'PVC status, 16-bit DLCI, new')
add(msg(0x7d, ie(0x57, bytes([0x04, 0x4f, 0x00, 0x00, 0x85]))), 'PVC status, 23-bit DLCI, new and active')
add(msg(0x7d, ie(0x57, bytes([0x3f, 0x7f, 0x80]))), 'PVC status, largest 10-bit DLCI')
add(msg(0x7d, ie(0x57, bytes([0x00, 0x2f, 0x82, 0x00, 0x00, 0x00]))), 'PVC status, 6 octets')
add(msg(0x7d, ie(0x57, bytes([0x00, 0x2f]))), 'PVC status, two octets')
add(msg(0x7d, b'\x95' + ie(0x57, bytes([0x00, 0x2f, 0x82]))), 'PVC status (codeset 5)')
add(msg(0x7d, b'\x95' + ie(0x07, bytes([0x00, 0x2f, 0x81]))), 'PVC status (ANSI)')
add(msg(0x7d, b'\x95' + ie(0x07, bytes([0x00, 0x2f, 0x82, 0x00]))), 'PVC status (ANSI), 16-bit DLCI')
add(msg(0x7d, ie(0x57, b'')), 'PVC status empty')
# A full status enquiry / status exchange as on a real UNI
add(msg(0x75, ie(0x51, b'\x01') + ie(0x53, b'\x01\x00'), cref=0, crlen=0), 'status enquiry: link verify')
add(msg(0x7d, ie(0x51, b'\x01') + ie(0x53, b'\x01\x01'), cref=0, crlen=0), 'status: link verify', user=False)
add(msg(0x75, ie(0x51, b'\x00') + ie(0x53, b'\x02\x01'), cref=0, crlen=0), 'status enquiry: full status')
add(msg(0x7d, ie(0x51, b'\x00') + ie(0x53, b'\x02\x02') + ie(0x57, bytes([0x00, 0x2f, 0x82])) + ie(0x57, bytes([0x00, 0x3f, 0x80])), cref=0, crlen=0),
    'status: full status with two PVCs', user=False)
# Other codeset 0 IEs
add(msg(0x05, ie(0x19, b'\x81\x0f')), 'DLCI IE (not decoded)')
add(msg(0x05, ie(0x48, b'\x01\x02\x03\x04')), 'link layer core parameters (not decoded)')
add(msg(0x05, ie(0x49, b'\x01\x02')), 'link layer protocol parameters (not decoded)')
add(msg(0x05, ie(0x4d, b'\x80\x01')), 'connected subaddress (not decoded)')
add(msg(0x05, ie(0x50, b'\x81')), 'X.213 priority (not decoded)')
add(msg(0x05, ie(0x7f, b'\x01\x02')), 'escape (not decoded)')
# Segmented messages (Annex H)
def seg(cr, first, remaining, payload):
    oct0 = (0x80 if first else 0) | remaining
    return msg(0x60, ie(0x00, bytes([oct0, 0x05])) + payload, cref=cr, crlen=2)
disp = lambda s: ie(0x28, s)
add(seg(1, True, 2, disp(b'AAAA')), 'segment, first (2 remaining)')
add(seg(1, False, 1, disp(b'BBBB')), 'segment, middle')
add(seg(2, True, 1, disp(b'XXXX')), 'segment of another call reference, first')
add(seg(1, False, 0, disp(b'CCCC')), 'segment, last: reassembled')
add(seg(2, False, 0, disp(b'YYYY')), 'segment, last of the other call: reassembled')
add(seg(3, True, 0, disp(b'ZZZZ')), 'segment, single segment message')
add(seg(4, True, 2, disp(b'1111')), 'segment, first')
add(seg(4, True, 1, disp(b'3333')), 'segment, first again while one is open (restart)')
add(seg(4, False, 0, disp(b'4444')), 'segment, last')
add(seg(5, True, 1, disp(b'ab')), 'segment, short payload (4 octets or less of IEs)')
add(msg(0x60, ie(0x00, bytes([0x80, 0x05])), cref=6, crlen=2), 'segment, no payload')
LATE.append((msg(0x60, ie(0x00, bytes([0x80])) + ie(0x28, b'xxxxx'), cref=7, crlen=2), 'segmented message IE of length 1'))
add(msg(0x60, ie(0x28, b'noseg') + ie(0x28, b'more'), cref=8, crlen=2), 'segment message without a segmented message IE')
LATE.append((msg(0x60, ie(0x00, bytes([0x80, 0x05, 0x00])) + ie(0x28, b'xxxxx'), cref=9, crlen=2), 'segmented message IE of length 3'))
# segmented message IE in a non-SEGMENT message
add(msg(0x7b, ie(0x00, bytes([0x82, 0x05])) + ie(0x28, b'first part') , cref=10, crlen=2), 'first-segment IE in INFORMATION')
add(msg(0x7b, ie(0x00, bytes([0x02, 0x05])) + ie(0x28, b'not first') , cref=11, crlen=2), 'not-first-segment IE in INFORMATION')
LATE.append((msg(0x7b, ie(0x00, bytes([0x82, 0x05, 0x01])) + ie(0x28, b'x'), cref=12, crlen=2), 'segmented IE of length 3 in INFORMATION'))


# Reproducers of "Q.933: Fix field offsets, DLCI and channel identification"
REPRO1 = len(frames) + 1
add(msg(0x05, ie(0x43, b'\x01\x02\x83')), 'reproducer: transit delay selection (3-octet value) as the last IE')
add(msg(0x05, ie(0x18, b'\x61\x81\x83')), 'reproducer: channel identification, interface identified, not basic: channel type octet')
add(msg(0x05, ie(0x18, b'\x61\x81\x83') + ie(0x28, b'x')), 'reproducer: the same followed by an IE')
add(msg(0x7d, ie(0x57, bytes([0x04, 0x4f, 0x00, 0x00, 0x85]))), 'reproducer: DLCI of 4 octets, status 0x85')
add(msg(0x7d, ie(0x57, bytes([0x3f, 0x78, 0x00, 0x7f, 0x85]))), 'reproducer: DLCI of 4 octets, bits 6-12 set')
add(msg(0x7d, ie(0x57, bytes([0x04, 0x4f, 0x00, 0x40, 0x82]))), 'reproducer: DLCI of 4 octets, status 0x82')
REPRO2 = len(frames)

write_pcap(os.path.join(OUT, 'q933-coverage.pcap'), frames)

# ---------------------------------------------------------------- malformed
mal = []
def madd(q933, note, raw=False):
    mal.append((q933 if raw else fr(q933), note))
for q, n in LATE:
    madd(q, n)
madd(msg(0x7d, b'\x28\x10abc'), 'display IE longer than the message')
madd(msg(0x7d, b'\x28'), 'IE without length')
madd(msg(0x05)[:2], 'message cut after the call reference length')
madd(msg(0x05, cref=0x1234, crlen=2)[:3], 'call reference cut')
madd(msg(0x05)[:3], 'message type missing')
madd(msg(0x05, ie(0x04, b'\x88\x90\x21\x48')[:-1]), 'bearer capability cut')
madd(msg(0x60, ie(0x00, b'\x80')), 'segmented message IE of length 1')
madd(msg(0x60, ie(0x00, b'\x80\x05\x00')), 'segmented message IE of length 3')
madd(msg(0x7d, ie(0x57, bytes([0x00, 0x2f, 0x82]))[:-1]), 'PVC status cut')
def rnd(n): return bytes(random.getrandbits(8) for _ in range(n))
for cs in (None, 5, 6, 7, 4):
    for ident in range(0x00, 0x80):
        for _ in range(3):
            body = b''
            if cs is not None:
                body += u8(0x90 | cs)
            for _ in range(random.randint(1, 3)):
                n = random.choice([0, 1, 2, 3, 4, 5, 6, 8, 12, random.randint(0, 30)])
                body += ie(ident, rnd(n))
            madd(msg(random.choice([0x05, 0x45, 0x7d, 0x02, 0x62, 0x4d]), body), 'random IE %02x codeset %s' % (ident, cs))
seen = set()
for data, note in frames:
    q = data[3:]
    crlen = q[1] & 0xf
    body = q[3 + crlen:]
    off = 0
    while off + 2 <= len(body):
        ident = body[off]
        if ident & 0x80:
            off += 1; continue
        l = body[off + 1]
        content = body[off + 2: off + 2 + l]
        for k in range(len(content)):
            key = (ident, content[:k])
            if key in seen: continue
            seen.add(key)
            madd(msg(0x05, ie(ident, content[:k])), 'prefix of IE %02x: %d octets' % (ident, k))
        off += 2 + l
write_pcap(os.path.join(OUT, 'q933-coverage-malformed.pcap'), mal)

if VERBOSE:
    print('frames', len(frames), 'malformed', len(mal), 'reproducers', REPRO1, REPRO2)
    for i, (d, n) in enumerate(frames, 1):
        print(i, n)

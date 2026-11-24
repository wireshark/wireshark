#!/usr/bin/env python3
# Generates test/captures/q2931_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Q.2931 (ATM signalling) captures. Usage: mkq2931.py <outdir> [-v]
Frames are SunATM (link type 123) VPI 0 VCI 5 carrying SSCOP SD PDUs whose
payload is the Q.2931 message, so SSCOP's default payload (Q.2931) is used."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

def u8(v): return bytes([v & 0xff])
def u16(v): return struct.pack('>H', v)

def write_pcap(fn, frames, linktype=123):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

ns = [0]
def sscop_sd(payload, direction=0x80):
    pad = (-len(payload)) % 4
    ns[0] += 1
    body = payload + b'\0' * pad + u8((pad << 6) | 0x08) + struct.pack('>I', ns[0])[1:]
    return u8(direction | 0x06) + u8(0) + u16(5) + body

def msg(mtype, ies=b'', cref=b'\x00\x00\x01', ext=0x80, flag=False, crlen=None, mlen=None):
    cr = bytearray(cref)
    if flag and cr:
        cr[0] |= 0x80
    if crlen is None:
        crlen = len(cr)
    return (u8(0x09) + u8(crlen) + bytes(cr) + u8(mtype) + u8(ext) +
            u16(len(ies) if mlen is None else mlen) + ies)

def ie(ident, content=b'', ext=0x80, length=None):
    return u8(ident) + u8(ext) + u16(len(content) if length is None else length) + content

frames = []
notes = []
def add(payload, note, direction=0x80):
    frames.append(sscop_sd(payload, direction))
    notes.append(note)

# ---------------------------------------------------------------- messages
MT = [(0x01, 'ALERTING'), (0x02, 'CALL PROCEEDING'), (0x03, 'PROGRESS'), (0x05, 'SETUP'),
      (0x07, 'CONNECT'), (0x0b, 'SETUP ACK'), (0x0f, 'CONNECT ACK'), (0x46, 'RESTART'),
      (0x4d, 'RELEASE'), (0x4e, 'RESTART ACK'), (0x5a, 'RELEASE COMPLETE'), (0x6e, 'NOTIFY'),
      (0x75, 'STATUS ENQUIRY'), (0x7b, 'INFORMATION'), (0x7d, 'STATUS'), (0x80, 'ADD PARTY'),
      (0x81, 'ADD PARTY ACK'), (0x82, 'ADD PARTY REJ'), (0x83, 'DROP PARTY'),
      (0x84, 'DROP PARTY ACK'), (0x90, 'LEAF SETUP FAIL'), (0x91, 'LEAF SETUP REQ'),
      (0x33, 'unknown type')]
for i, (t, n) in enumerate(MT):
    add(msg(t, ie(0x14, b'\x0b') if i % 2 == 0 else b'', flag=bool(i & 1)), 'message ' + n,
        0x00 if i & 1 else 0x80)
# message type extension: follow instructions (bit 4) with each action indicator
for a in (0, 1, 2):
    add(msg(0x7d, ie(0x14, b'\x0b'), ext=0x90 | a), 'message instruction, action %d' % a)
add(msg(0x7d, ext=0xa0), 'message flag bit set, no follow')
add(msg(0x05, ie(0x14, b'\x00'), cref=b'', crlen=0), 'call reference length 0')
add(msg(0x05, ie(0x14, b'\x00'), cref=b'\x12', flag=True), 'call reference length 1')
add(msg(0x05, ie(0x14, b'\x00'), cref=b'\x12\x34\x56\x78\x9a'), 'call reference length 5')
add(msg(0x05), 'no IEs')

# ------------------------------------------------------------ IE helpers
def m(ies, t=0x05):
    return msg(t, ies)

# IE extension octet: coding standard, follow instruction, action indicator
for ext, n in ((0x80, 'ITU, regular'), (0x90, 'ITU, follow, clear call'), (0x91, 'follow, discard IE'),
               (0x92, 'follow, discard IE and report'), (0x95, 'follow, discard message'),
               (0x96, 'follow, discard message, report'), (0xa0, 'ISO coding'), (0xc0, 'national coding'),
               (0xe0, 'network coding'), (0xa8, 'ISO coding flag')):
    add(m(ie(0x14, b'\x0b', ext=ext)), 'IE extension octet: ' + n)
add(m(ie(0x7f, b'\x01\x02\x03')), 'unknown IE 0x7f (generic identifier transport)')
add(m(ie(0x10, b'\xaa'), t=0x7d), 'unknown IE 0x10')
add(m(ie(0x14, b'\x0b') + ie(0x70, b'\x80\x01') + ie(0x7f, b'')), 'several IEs, empty last')

# shifts
for code in (0, 3, 4, 5, 6, 7):
    add(m(ie(0x60, bytes([0x80 | code]))), 'locking shift codeset %d' % code)
    add(m(ie(0x61, bytes([0x88 | code]))), 'non-locking shift codeset %d' % code)
add(m(ie(0x60, b'')), 'locking shift, empty')

# narrowband bearer capability / LLC / HLC / progress (Q.931 helpers)
add(m(ie(0x04, bytes([0x88, 0x90, 0xa3]))), 'narrowband bearer capability')
add(m(ie(0x04, bytes([0x80, 0x90]))), 'narrowband bearer capability short')
add(m(ie(0x7c, bytes([0x88, 0x90, 0xa3]))), 'narrowband low layer compat')
add(m(ie(0x7d, bytes([0x91, 0x81]))), 'narrowband high layer compat')
add(m(ie(0x1e, bytes([0x80, 0x81]))), 'progress indicator')
add(m(ie(0x1e, bytes([0x82, 0x88]))), 'progress indicator 2')
add(m(ie(0x27, bytes([0x81]))), 'notification indicator (not dissected)')

# AAL parameters
def aal(t, *p): return ie(0x58, bytes([t]) + b''.join(p))
add(m(aal(0x00)), 'AAL for voice')
add(m(aal(0x01, b'\x85\x02', b'\x86\x10', b'\x87\x00\x02', b'\x88\x01', b'\x89\x01', b'\x8a\x00\x2f', b'\x8b\x2e')),
    'AAL1 every parameter')
add(m(aal(0x01, b'\x85\x01', b'\x86\x40', b'\x87\x00\x08', b'\x88\x02', b'\x89\x02')), 'AAL1 nx64 adaptive')
add(m(aal(0x02)), 'AAL2')
add(m(aal(0x03, b'\x8c\x00\x40', b'\x81\x00\x41', b'\x82\x00\x01\x03\xff', b'\x83\x01', b'\x84\x01')),
    'AAL3/4 parameters')
add(m(aal(0x05, b'\x8c\x05\xdc', b'\x81\x05\xdc', b'\x83\x02', b'\x84\x00')), 'AAL5 parameters')
add(m(aal(0x05, b'\x84\x04')), 'AAL5 frame relay SSCS')
add(m(aal(0x10, b'\x11\x22')), 'user-defined AAL, 2 octets')
add(m(aal(0x10, b'\x11\x22\x33\x44\x55\x66')), 'user-defined AAL, 6 octets (4 shown)')
add(m(ie(0x58, b'')), 'AAL parameters empty')
# cut short parameters: each stops without a malformed packet
for p in (b'\x85', b'\x86', b'\x87\x00', b'\x88', b'\x89', b'\x8a\x00', b'\x8b', b'\x8c\x00', b'\x81\x00',
          b'\x82\x00\x01\x03', b'\x83', b'\x84'):
    add(m(aal(0x03, p)), 'AAL parameter %02x cut short' % p[0])

# ATM traffic descriptor
def rate(i, v): return bytes([i]) + struct.pack('>I', v)[1:]
ids = (0x82, 0x83, 0x84, 0x85, 0x88, 0x89, 0x90, 0x91, 0xa0, 0xa1, 0xb0, 0xb1)
add(m(ie(0x59, b''.join(rate(i, 1000 + n) for n, i in enumerate(ids[:6])))), 'ATM traffic descriptor, peak and sustainable rates')
add(m(ie(0x59, b''.join(rate(i, 2000 + n) for n, i in enumerate(ids[6:])))), 'ATM traffic descriptor, sustainable and burst')
add(m(ie(0x59, rate(0x84, 353207) + b'\xbe' + b'\xbf\x4f')), 'ATM traffic descriptor, best effort and management options')
add(m(ie(0x59, rate(0x84, 100) + rate(0x85, 100) + b'\xbf\x00')), 'ATM traffic descriptor, options 0')
add(m(ie(0x59, b'\x82\x00')), 'ATM traffic descriptor rate cut short')
add(m(ie(0x59, b'\xbf')), 'ATM traffic descriptor options cut short')
add(m(ie(0x59, b'')), 'ATM traffic descriptor empty')

# Broadband bearer capability
for bc in (b'\x01', b'\x03\x00', b'\x10\x04', b'\x18\x0c\x00', b'\x01\x85', b'\x83\x00\x80', b'\x90\x80',
           b'\x81\x01', b'\x03\x05\x81', b'\x03\x09\x01', b'\x10\x0b\x00', b'\x03\x0a\x80', b'\x03\x07\x00',
           b'\x03\x06\x01', b'\x03\x02\x80', b'\x01\x08\x00'):
    add(m(ie(0x5e, bc)), 'broadband bearer capability %s' % bc.hex())
add(m(ie(0x5e, b'')), 'broadband bearer capability empty')

# Broadband high layer information
for t in (0, 1, 3, 4, 7):
    add(m(ie(0x5d, bytes([t, 0x01]))), 'broadband high layer information type %d' % t)
add(m(ie(0x5d, b'')), 'broadband high layer information empty')

# Broadband low layer information
def lli(*o): return ie(0x5f, bytes(o))
add(m(lli(0xa1)), 'low layer info: layer 1 only')
add(m(lli(0x42)), 'low layer info: layer 2, extension bit clear, nothing follows')
add(m(lli(0xc2)), 'low layer info: layer 2 Q.921 only')
for l2 in (0x01, 0x06, 0x0c, 0x10):
    add(m(lli(0x40 | l2, 0x81)), 'low layer info: layer 2 %02x then mode' % l2)
    add(m(lli(0x40 | l2, 0x01, 0x87)), 'low layer info: layer 2 %02x then window' % l2)
    add(m(lli(0x40 | l2, 0x01, 0x07, 0xe6)), 'low layer info: layer 2 %02x, window, layer 3' % l2)
add(m(lli(0xa1, 0x42, 0x01, 0x03, 0xe6, 0x01, 0x07)), 'low layer info: layers 1, 2, 3')
add(m(lli(0x6b)), 'low layer info: layer 3 ISO 9577 alone')
add(m(lli(0x66, 0x81)), 'low layer info: X.25 PL, mode')
add(m(lli(0x66, 0x01, 0x84)), 'low layer info: X.25 PL, mode, packet size')
add(m(lli(0x67, 0x01, 0x04, 0x85)), 'low layer info: ISO 8208, window size')
add(m(lli(0x68, 0x02, 0x05, 0x0a)), 'low layer info: X.223, window size, extra octet')
add(m(lli(0x41, 0x01)), 'low layer info: layer 2 mode, extension clear, nothing follows')
add(m(lli(0x50, 0x01)), 'low layer info: layer 2 user-specified, extension clear, nothing follows')
add(m(lli(0x66)), 'low layer info: X.25 PL cut short')
add(m(lli(0x66, 0x01)), 'low layer info: X.25 PL no packet size')
add(m(lli(0x66, 0x01, 0x04)), 'low layer info: X.25 PL no window size')
add(m(lli(0x70, 0x05)), 'low layer info: user-specified layer 3')
add(m(lli(0x4b, 0x01, 0x6b, 0x01)), 'low layer info: TR 9577, extension clear, odd')
add(m(lli(0x6b, 0xc0)), 'low layer info: TR 9577, IPI 0x80 octets')
add(m(lli(0x6b, 0x01)), 'low layer info: TR 9577, short additional')
add(m(lli(0x6b, 0x01, 0xc0)), 'low layer info: TR 9577 cut short, 2 additional octets')
# TR 9577 with SNAP (IPI 0x80): octet 7 = 0x01 ... additional layer 3 protocol = 0x80
snap = lambda oui, pid: bytes([0x80]) + oui + pid
# The additional L3 protocol: octet 7 bits 6-0 are the high 7 bits, octet 7a bit 6 the last bit.
# SNAP NLPID is 0x80 = 0b1000_0000 -> octet7 = 0x40 (|0x80 clear), octet 7a bit6 = 0.
for name, oui, pid in (('Ethernet OUI 00-00-00', b'\x00\x00\x00', b'\x08\x00'),
                       ('ATM Forum OUI', b'\x00\xa0\x3e', b'\x00\x01'),
                       ('other OUI', b'\x01\x02\x03', b'\x08\x00')):
    add(m(lli(0x6b, 0x40, 0x00, 0x00, *oui, *pid)), 'low layer info: TR 9577 SNAP, ' + name)
add(m(lli(0x6b, 0x40, 0x00, 0x00, 0x00, 0x80, 0xc2)), 'low layer info: TR 9577 SNAP cut short (len < 6)')
add(m(lli(0x6b, 0x20 | 0x0a, 0x00)), 'low layer info: TR 9577 IPv4 NLPID 0xcc (no SNAP)')
add(m(lli(0x6b, 0x66, 0x40)), 'low layer info: TR 9577 NLPID 0xcc')
add(m(lli(0x20)), 'low layer info: layer 1 odd')
add(m(lli(0x00)), 'low layer info: no layer')
add(m(ie(0x5f, b'')), 'low layer info empty')

# Cause IE
def cause(loc, val, *extra, ext=0x80):
    return ie(0x08, bytes([loc, 0x80 | val]) + b''.join(extra), ext=ext)
for loc in range(6):
    add(m(cause(loc, 31), t=0x4d), 'cause, location %d' % loc)
add(m(cause(1, 1, b'\x00'), t=0x4d), 'cause 1 unallocated number, condition 0')
add(m(cause(1, 1, b'\x4b'), t=0x4d), 'cause 1 with network service, behaviour, condition bits')
add(m(cause(2, 3, b'\x03'), t=0x4d), 'cause 3 no route to destination')
add(m(cause(2, 49, b'\x82'), t=0x4d), 'cause 49 QoS unavailable')
add(m(cause(2, 21, b'\x00'), t=0x4d), 'cause 21 rejected, user specific')
add(m(cause(2, 21, b'\x04', b'\x11\x22\x33'), t=0x4d), 'cause 21 rejected, user specific diagnostic')
add(m(cause(2, 21, b'\x08', b'\x70'), t=0x4d), 'cause 21 rejected, IE missing')
add(m(cause(2, 21, b'\x0c', b'\x5e'), t=0x4d), 'cause 21 rejected, IE insufficient')
add(m(cause(2, 21, b'\x10', b'\x01\x02'), t=0x4d), 'cause 21 rejected, other reason')
add(m(cause(2, 21, b'\x10'), t=0x4d), 'cause 21 rejected, no diagnostic')
add(m(cause(2, 22, b'\x70\x80\x00\x03\x80\x01\x02'), t=0x4d), 'cause 22 number changed with called party number')
for v, n in ((43, 'access info discarded'), (88, 'incompatible destination'), (96, 'mandatory IE missing'),
             (99, 'IE non-existent'), (100, 'invalid IE contents')):
    add(m(cause(2, v, b'\x58\x5e\x70'), t=0x4d), 'cause %d %s, three IE ids' % (v, n))
add(m(cause(2, 37, b'\x82\x83\x88\xbe'), t=0x4d), 'cause 37 cell rate unavailable')
add(m(cause(2, 82, b'\x00\x01\x00\x20'), t=0x4d), 'cause 82 channel non-existent, VPCI and VCI')
add(m(cause(2, 82, b'\x00\x01'), t=0x4d), 'cause 82 channel non-existent, VPCI only')
add(m(cause(2, 82, b'\x00'), t=0x4d), 'cause 82 channel non-existent, short')
add(m(cause(2, 97, b'\x05'), t=0x4d), 'cause 97 message type non-existent')
add(m(cause(2, 98, b'\x07'), t=0x4d), 'cause 98 message not compatible')
add(m(cause(2, 102, b'T30'), t=0x4d), 'cause 102 timer expired, T30')
add(m(cause(2, 102, b'T3'), t=0x4d), 'cause 102 timer short')
add(m(cause(2, 16, b'\xde\xad'), t=0x4d), 'cause 16 normal clearing with diagnostic')
add(m(ie(0x08, b'\x02'), t=0x4d), 'cause with only the location')
add(m(ie(0x08, b''), t=0x4d), 'cause empty')
add(m(ie(0x08, b'\x02\x90'), t=0x4d), 'cause without diagnostic')
# Two causes
add(m(cause(0, 16) + cause(2, 31)), 'two cause IEs')

# Reproducer 1 (fix "Q.2931: Bound cause IE recursion and fix IE loops"):
# a cause 22 IE holding another cause IE, again and again. The dissector stops
# at 8 levels with an expert info. Every level is 6 octets: id, ext, len(2), loc, cause.
def nested(levels):
    # innermost: a plain cause
    inner = cause(2, 31)
    for _ in range(levels):
        body = bytes([2, 0x80 | 22]) + inner
        inner = u8(0x08) + u8(0x80) + u16(len(body)) + body
    return inner
REPRO = len(frames) + 1
add(msg(0x4d, nested(3)), 'reproducer: cause 22 nesting 3 levels (below the limit)')
add(msg(0x4d, nested(7)), 'reproducer: cause 22 nesting 7 levels')
add(msg(0x4d, nested(12)), 'reproducer: cause 22 nesting 12 levels (past the limit of 8: expert info)')
# the original shape, whose IE length field is 0xffff in every level
lvl = bytes([0x08, 0x80, 0xff, 0xff, 0x00, 0x16])
add(msg(0x4d, lvl * 12 + cause(2, 31)), 'reproducer: original shape, length 0xffff, 12 levels')
REPRO_END = len(frames)

# Call state
for st in (0x00, 0x01, 0x03, 0x06, 0x0a, 0x0b, 0x0c, 0x0f, 0x16, 0x3d, 0x3e, 0x20):
    add(m(ie(0x14, bytes([st])), t=0x7d), 'call state %02x' % st)
add(m(ie(0x14, b''), t=0x7d), 'call state empty')

# Party numbers
for ident, name in ((0x70, 'called'), (0x6c, 'calling')):
    add(m(ie(ident, b'\xb1' + b'12125551234')), name + ' number, E.164, no octet 3a (ext bit set)')
    add(m(ie(ident, b'\x21\x80' + b'44201234')), name + ' number, E.164 national, presentation octet')
    add(m(ie(ident, b'\x01\x20' + b'999')), name + ' number, presentation restricted/screened')
    add(m(ie(ident, b'\x02\x00' + bytes([0x39]) + bytes(range(1, 20)))), name + ' number, NSAP 20 octets')
    add(m(ie(ident, b'\x82' + bytes([0x47]) + bytes(range(1, 20)))), name + ' number, NSAP 20 octets, ext bit set')
    add(m(ie(ident, b'\x02\x00' + bytes([0x39]) + bytes(range(1, 5)))), name + ' number, NSAP short')
    add(m(ie(ident, b'\x09\x00' + b'private')), name + ' number, private plan')
    add(m(ie(ident, b'\x00\x00' + b'\x01\x02')), name + ' number, unknown plan')
    add(m(ie(ident, b'\x81')), name + ' number, nothing after octet 3')
    add(m(ie(ident, b'\x01')), name + ' number, ext clear and nothing after')
    add(m(ie(ident, b'\x01\x00')), name + ' number, no digits')
    add(m(ie(ident, b'')), name + ' number empty')
for ident, name in ((0x71, 'called'), (0x6d, 'calling')):
    add(m(ie(ident, b'\x80' + bytes([0x45]) + bytes(range(1, 20)))), name + ' subaddress NSAP')
    add(m(ie(ident, b'\xa8' + b'\x01\x02\x03')), name + ' subaddress user-specified, odd')
    add(m(ie(ident, b'\x90')), name + ' subaddress, type only')
    add(m(ie(ident, b'')), name + ' subaddress empty')

# connection identifier
add(m(ie(0x5a, b'\x80\x00\x01\x00\x20')), 'connection identifier VPCI 1 VCI 32')
add(m(ie(0x5a, b'\x99\x00\x01\x00\x20')), 'connection identifier, no VP associated signalling, exclusive any VCI')
add(m(ie(0x5a, b'\x84\x00\x02\x00\x00')), 'connection identifier, no VCI')
add(m(ie(0x5a, b'\x80\x00\x01')), 'connection identifier, no VCI octets')
add(m(ie(0x5a, b'\x80\x00\x01\x00')), 'connection identifier, VCI cut short')
add(m(ie(0x5a, b'\x80\x00')), 'connection identifier, VPCI cut short')
add(m(ie(0x5a, b'\x80')), 'connection identifier, flags only')
add(m(ie(0x5a, b'')), 'connection identifier empty')

# end-to-end transit delay
add(m(ie(0x42, b'\x01\x00\x64')), 'transit delay cumulative')
add(m(ie(0x42, b'\x03\x00\x32')), 'transit delay maximum 50 ms')
add(m(ie(0x42, b'\x03\xff\xff')), 'transit delay maximum, any value')
add(m(ie(0x42, b'\x01\x00')), 'transit delay cut short (< 3 octets)')
add(m(ie(0x42, b'')), 'transit delay empty')

# QoS, repeat indicator, restart, sending complete
add(m(ie(0x5c, b'\x00\x00')), 'QoS class forward and backward')
add(m(ie(0x5c, b'\x01')), 'QoS forward only')
add(m(ie(0x5c, b'')), 'QoS empty')
add(m(ie(0x63, b'\x02')), 'broadband repeat indicator')
add(m(ie(0x63, b'')), 'broadband repeat indicator empty')
for v in (0, 1, 2, 3):
    add(m(ie(0x79, bytes([0x80 | v])), t=0x46), 'restart indicator class %d' % v)
add(m(ie(0x79, b''), t=0x46), 'restart indicator empty')
add(m(ie(0x62, b'\xa1')), 'sending complete')
add(m(ie(0x62, b'\xa1\xa1')), 'sending complete twice')
add(m(ie(0x62, b'')), 'sending complete empty')

# transit network selection
add(m(ie(0x78, b'\x21' + b'1234')), 'transit network selection national CIC')
add(m(ie(0x78, b'\x33' + b'5678')), 'transit network selection international X.121')
add(m(ie(0x78, b'\x00' + b'X')), 'transit network selection user specified')
add(m(ie(0x78, b'\x20')), 'transit network selection, type only')
add(m(ie(0x78, b'')), 'transit network selection empty')

# OAM traffic descriptor
add(m(ie(0x5b, b'\x81\x45')), 'OAM traffic descriptor, shaping and indicators')
add(m(ie(0x5b, b'\x00')), 'OAM traffic descriptor, first octet only')
add(m(ie(0x5b, b'\xaf\x41')), 'OAM traffic descriptor, management indicator')
add(m(ie(0x5b, b'\x80\x10')), 'OAM traffic descriptor, forward 0.1%')
add(m(ie(0x5b, b'')), 'OAM traffic descriptor empty')

# endpoint reference and state
add(m(ie(0x54, b'\x00\x00\x05'), t=0x80), 'endpoint reference 5')
add(m(ie(0x54, b'\x00\x80\x05'), t=0x81), 'endpoint reference 5, flag set')
add(m(ie(0x54, b'\x00\x00'), t=0x80), 'endpoint reference cut short')
add(m(ie(0x54, b'\x00'), t=0x80), 'endpoint reference type only')
add(m(ie(0x54, b''), t=0x80), 'endpoint reference empty')
for st in (0, 1, 6, 0x0a, 0x0b, 0x0c, 0x30):
    add(m(ie(0x55, bytes([st])), t=0x7d), 'endpoint state %02x' % st)
add(m(ie(0x55, b''), t=0x7d), 'endpoint state empty')

# A full SETUP / CONNECT call in one flow
add(msg(0x05, ie(0x58, bytes([0x05, 0x8c, 0x05, 0xdc, 0x81, 0x05, 0xdc, 0x83, 0x01, 0x84, 0x00])) +
        ie(0x59, rate(0x84, 353207) + rate(0x85, 353207) + b'\xbe') + ie(0x5e, b'\x03\x05\x00') +
        ie(0x5d, b'\x01\x01') + ie(0x5f, bytes([0xa1, 0x4c, 0x81, 0xe6, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01])) +
        ie(0x70, b'\x82' + bytes([0x39]) + bytes(range(1, 20))) + ie(0x6c, b'\x82' + bytes([0x39]) + bytes(range(1, 20))) +
        ie(0x5a, b'\x80\x00\x00\x00\x20') + ie(0x5c, b'\x00\x00') + ie(0x5b, b'\x80\x00') + ie(0x62, b'\xa1'),
        cref=b'\x00\x00\x42'), 'full SETUP')
add(msg(0x02, ie(0x5a, b'\x80\x00\x00\x00\x20'), cref=b'\x00\x00\x42', flag=True), 'CALL PROCEEDING', 0x00)
add(msg(0x07, ie(0x58, bytes([0x05, 0x8c, 0x05, 0xdc])) + ie(0x5a, b'\x80\x00\x00\x00\x20'),
        cref=b'\x00\x00\x42', flag=True), 'CONNECT', 0x00)
add(msg(0x0f, cref=b'\x00\x00\x42'), 'CONNECT ACK')
add(msg(0x4d, cause(2, 16), cref=b'\x00\x00\x42'), 'RELEASE')
add(msg(0x5a, cause(2, 16), cref=b'\x00\x00\x42', flag=True), 'RELEASE COMPLETE', 0x00)

# Reproducer 2 (fix, IE loops and field offsets): smallfix frames 5-7
SMALL = len(frames) + 1
add(msg(0x4d, ie(0x08, bytes([0x80, 0xab, 0x70])) + ie(0x14, b'\x0b')),
    'reproducer: cause 43 with one diagnostic octet, next IE is not a diagnostic')
add(msg(0x05, ie(0x58, bytes([0x05, 0x83, 0x01])) + ie(0x14, b'\x0b')),
    'reproducer: AAL5 mode parameter, next IE not read as identifier')
add(msg(0x05, ie(0x58, bytes([0x10, 0x11, 0x22, 0x33, 0x44]))), 'reproducer: user-defined AAL (0x10)')
SMALL_END = len(frames)

write_pcap(os.path.join(OUT, 'q2931-coverage.pcap'), frames)

# ---------------------------------------------------------------- malformed
mal = []
mnotes = []
def madd(payload, note, direction=0x80):
    mal.append(sscop_sd(payload, direction)); mnotes.append(note)

madd(msg(0x05, ie(0x58, bytes([0x05, 0x99, 0x00]))), 'AAL5 unknown parameter id')
madd(msg(0x05, ie(0x59, b'\x99\x00\x00\x01')), 'ATM traffic descriptor unknown id')
madd(msg(0x05, ie(0x42, b'\x07\x00\x01')), 'transit delay unknown id')
# The loop reads the next identifier from the second octet of the value: see README
madd(msg(0x05, ie(0x42, b'\x01\x00\x64\x03\x00\x32')), 'transit delay cumulative and maximum in one IE')
madd(msg(0x05, ie(0x62, b'\xa2')), 'sending complete unknown id')
madd(msg(0x4d, ie(0x08, b'\x02\x96\x01\x02')), 'cause 22 with a short number-changed IE (read past the end)')
madd(msg(0x4d, ie(0x08, b'\x02\x96')), 'cause 22 with nothing after the cause value')
madd(msg(0x05, ie(0x14, b'\x0b', length=20)), 'IE length past the end of the packet')
madd(msg(0x05, ie(0x14, b'\x0b')[:-2]), 'IE cut short')
madd(msg(0x05, b'\x14'), 'one octet of an IE')
madd(msg(0x05, b'\x14\x80'), 'IE without length')
madd(msg(0x05)[:5], 'message cut after call reference')
madd(msg(0x05)[:7], 'message cut before message length')
madd(msg(0x05, cref=b'\x01' * 15, crlen=15)[:12], 'call reference cut short')
madd(msg(0x05, ie(0x5f, bytes([0x6b, 0x40, 0x00, 0x00, 0x00, 0x80, 0xc2, 0x00]))), 'low layer SNAP cut at the PID')
madd(msg(0x4d, ie(0x08, bytes([0x02, 0x96, 0x08, 0x80, 0xff, 0xff, 0x01]))), 'cause 22 with IE length 0xffff')
madd(msg(0x4d, nested(40)), 'cause nesting 40 levels')
madd(msg(0x4d, ie(0x08, b'\x02\x96' + ie(0x14, b'\x01'))), 'cause 22 holding a call state IE')
madd(msg(0x4d, ie(0x08, bytes([0x02, 0x80 | 102, 0x54, 0x33]))), 'timer expired with 2 octets')
madd(msg(0x4d, ie(0x08, bytes([0x02, 0x80 | 21, 0x08]))), 'rejected, no diagnostic octet (missing IE)')
write_pcap(os.path.join(OUT, 'q2931-coverage-malformed.pcap'), mal)

if VERBOSE:
    print('frames', len(frames), 'malformed', len(mal))
    print('reproducer cause frames', REPRO, REPRO_END, 'smallfix', SMALL, SMALL_END)
    for i, n in enumerate(notes, 1):
        print(i, n)

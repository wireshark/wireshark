#!/usr/bin/env python3
# Generates test/captures/sapdiag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP Diag coverage captures.  Usage: mksapdiag.py <outdir>
# SAP Diag is reached through SAP NI on TCP 3200 (sapni.port); the
# captures are dissected with default preferences.  Nothing is captured
# from a network; the SNC frame carries arbitrary bytes and the compressed
# messages are LZC streams built by lib.lzc_compress (not crypto).
import os
import struct
import sys
from sapcov_lib import Cap, Flow, lzc_compress, ni, snc_frame

CLI, SRV = '192.0.2.1', '192.0.2.2'
n = [53000]
IGS = None


def flow(c, port=3200):
    n[0] += 1
    f = Flow(c, CLI, SRV, n[0], port)
    f.syn()
    return f


def z(k, fill=0):
    return bytes([fill]) * k


def ramp(k):
    return bytes((i % 250) + 1 for i in range(k))


def item(t, i=None, s=None, body=b''):
    '''Diag item: types 0x01-0x0c, 0x13 and 0x15 have a fixed size and no length; 0x10 has
    id, sid and a 2 byte length; 0x12 id, sid and a 4 byte length; 0x11 a 4 byte length.'''
    if t == 0x10:
        return bytes([t, i, s]) + struct.pack('!H', len(body)) + body
    if t == 0x12:
        return bytes([t, i, s]) + struct.pack('!I', len(body)) + body
    if t == 0x11:
        return bytes([t]) + struct.pack('!I', len(body)) + body
    return bytes([t]) + body


EOM = bytes([0x0c])


def msg(items, comp=0, mode=0, comflag=0x28, stat=0, err=0, mtype=1, minfo=0, rc=0):
    return bytes([mode, comflag, stat, err, mtype, minfo, rc, comp]) + b''.join(items) + EOM


def stz(*ss):
    return b''.join(s.encode() + b'\0' for s in ss)


def atom(etype, body=b'', attr=0, row=1, col=2):
    '''Dynt atom item: length, flags, etype, area/block/group, row, col, attr, body.'''
    b = bytes([0, 0, etype, 1, 2, 3]) + struct.pack('!HH', row, col) + bytes([attr]) + body
    return struct.pack('!H', len(b) + 2) + b


def menu_entry(text='File', acc='Ctrl+F', info='open'):
    b = bytes(range(1, 19)) + stz(text, acc, info)
    return struct.pack('!H', len(b) + 2) + b


def epp(version, parts=None, ccount=None):
    '''Extended Passport (SAP_EPP_MAGIC *TH*), version 1-3.'''
    M = b'*TH*'
    if version == 1:
        length = 0x99
    elif version == 2:
        length = 0xb9
    else:
        length = 0xe6
    body = bytearray(length)
    body[0:4] = M
    body[4] = version
    struct.pack_into('!H', body, 5, length)
    body[7:9] = b'\x00\x01'
    body[9:9 + 9] = b'COMPONENT'
    struct.pack_into('!H', body, 0x29, 7)
    body[0x2b:0x2b + 4] = b'USER'
    body[0x4b:0x4b + 6] = b'ACTION'
    struct.pack_into('!H', body, 0x73, 3)
    body[0x75:0x75 + 4] = b'PREV'
    if version > 1:
        body[0x95:0x95 + 6] = b'TRANSA'
    if version > 2:
        body[0xb5:0xb8] = b'001'
        struct.pack_into('!H', body, 0xb8, 5)
        body[0xba:0xca] = bytes(range(16))
        body[0xca:0xda] = bytes(range(16, 32))
        struct.pack_into('!I', body, 0xda, 9)
        vp = b''
        if parts:
            for last, pid, items in parts:
                its = b''.join(struct.pack('!HHBH', k, a, t, 7 + len(v)) + v for k, a, t, v in items)
                vp += M + bytes([1]) + struct.pack('!H', 12 + len(its)) + bytes([last]) + \
                    struct.pack('!HH', pid, len(items)) + its
        struct.pack_into('!HH', body, 0xde, len(parts) if parts else 0, 0xe2)
        body = bytearray(bytes(body[:0xe2]) + vp + M)
        struct.pack_into('!H', body, 5, len(body))
        return bytes(body)
    body[length - 4:] = M
    return bytes(body)


def dp():
    '''200 byte DP header; the first byte is 0xff.'''
    b = bytearray(200)
    b[0] = 0xff
    b[0x05] = 3
    b[0x0b:0x0f] = b'\0\0\0\x01'
    b[0x1e:0x22] = struct.pack('<I', 16)
    b[0x51:0x51 + 8] = b'TERMINAL'
    return bytes(b)


def build_items():
    '''(name, item bytes) in groups, every item dissected by dissect_sapdiag_item.'''
    A = lambda i, s, body: item(0x10, i, s, body)
    g = []
    # fixed items without length
    g.append([item(0x01, body=ramp(16)), item(0x02, body=z(20)), item(0x03, body=z(3)),
              item(0x07, body=z(76)), item(0x09, body=ramp(22)), item(0x0a, body=bytes([1, 2, 3])),
              item(0x0b, body=bytes([4, 5])), item(0x13, body=bytes([0, 6])), item(0x15, body=z(36))])
    # connection / client information (ST_USER)
    g.append([A(4, 2, struct.pack('!III', 0x02, 1100, 7)), A(4, 4, struct.pack('!4H', 14, 8, 12, 7)),
              A(4, 0x0b, ramp(32)), A(4, 0x0d, struct.pack('!4I', 600, 800, 580, 780)),
              A(4, 0x0f, struct.pack('!I', 120)), A(4, 0x16, struct.pack('!H', 17)),
              A(4, 0x17, struct.pack('!H', 17)), A(4, 0x19, bytes([1, 2])), A(4, 0x1d, b'42'),
              A(4, 0x24, struct.pack('!2I', 1080, 1920)), A(4, 0x25, struct.pack('!H', 3)),
              A(4, 0x26, struct.pack('!I', 5))])
    g.append([A(4, 0x1d, b'\x2a'), A(4, 9, b'7.70 Patch 3'), A(4, 0x1a, b'.'), A(4, 0x1b, b'E'),
              A(4, 0x1c, b'SAPUSER'), A(4, 0x1f, b'Windows 10'), A(4, 0x20, b'Edge'), A(4, 0x21, b'Office 16')])
    # R3 information
    g.append([A(6, 1, struct.pack('!H', 1)), A(6, 6, struct.pack('!H', 2)), A(6, 0x0a, struct.pack('!H', 1)),
              A(6, 0x11, ramp(32)), A(6, 0x16, struct.pack('!I', 4096)), A(6, 0x18, struct.pack('!H', 0x41)),
              A(6, 0x19, struct.pack('!H', 12)), A(6, 0x22, struct.pack('!I', 600)),
              A(6, 2, b'HDB'), A(6, 3, b'host1'), A(6, 7, b'SE16'), A(6, 0x0b, b'Message'),
              A(6, 0x0c, b'001'), A(6, 0x0d, b'SAPLSE16'), A(6, 0x0e, b'0100'), A(6, 0x0f, b'MENU'),
              A(6, 0x10, b'STATUS'), A(6, 0x21, b'ctx-id'), A(6, 0x24, b'4103'), A(6, 0x25, b'Belize')])
    g.append([A(6, 0x13, b'\0' + stz('F3', 'Back', 'Exit')), A(6, 0x14, b'\0\x03\0' + stz('Save')),
              A(6, 0x1f, bytes([2]) + ramp(16) + b'\x01' + ramp(16) + b'\x02'),
              A(6, 0x23, struct.pack('!I', 1100) + b'\0' + stz('1100', 'ISO-8859-1')),
              A(6, 0x27, struct.pack('!I', 4103) + b'\0' + stz('4103', 'UTF-16')),
              A(6, 0x29, stz('HDB 2.0', 'kernel 753', '1000'))])
    # dynpro / container / varinfo
    g.append([A(9, 0x0b, bytes([2]) + struct.pack('!4H', 1, 2, 3, 4) + bytes([2, 5])),
              A(9, 0x0b, bytes([1]) + struct.pack('!4H', 1, 2, 3, 4) + b'\0'),
              A(9, 0x12, b'FOCUS-FIELD'),
              A(10, 1, z(9)), A(10, 4, z(9)), A(10, 5, z(9)), A(10, 8, z(9)), A(10, 9, z(9)), A(10, 0x0a, z(9)),
              A(10, 6, stz('SUB', 'CONT', 'DYN'))])
    g.append([A(12, 3, stz('A', 'B', 'C', 'D')), A(12, 2, z(24)), A(12, 6, z(33)), A(12, 7, z(16)),
              A(12, 8, z(16)), A(12, 0x0c, struct.pack('!H', 2)), A(12, 0x0d, bytes([1]) + struct.pack('!HH', 3, 4)),
              A(12, 0x0e, z(16)), A(12, 4, b'OKCODE'), A(12, 9, b'Title'), A(12, 0x0a, b'ICON_OK'),
              A(12, 0x0b, b'cell text')])
    g.append([A(5, 1, ramp(30)), item(0x09, body=ramp(20)),
              A(0x0e, 1, struct.pack('!H', 3) + stz('value1') + struct.pack('!H', 4) + stz('value2')),
              A(0x0f, 1, bytes([0x06]) + struct.pack('!HH', 1, 2) + bytes([3]) + struct.pack('!HH', 3, 4) +
                struct.pack('!H', 2) + bytes([1, 2])),
              A(0x0f, 1, bytes([0x0a]) + struct.pack('!HH', 1, 2) + bytes([1, 2, 3, 4]) + struct.pack('!HH', 3, 4) +
                struct.pack('!H', 0)),
              A(0x14, 1, bytes([1]) + struct.pack('!III', 1000, 600, 400))])
    # data streams, tab strips, atoms
    g.append([item(0x11, body=b'data stream value'), item(0x12, 9, 0x10,
              atom(115, bytes([10, 1]) + struct.pack('!HH', 8, 6) + stz('OK', 'FC_OK')) +
              atom(116, bytes([10, 1, 1]) + struct.pack('!HHH', 9, 6, 12) + stz('Tab', 'FC_TAB', 'ID1')))])
    atoms = (atom(121, bytes([1, 10, 10]) + struct.pack('!H', 12) + b'input') +
             atom(122, bytes([1, 10, 10]) + struct.pack('!H', 12) + b'output') +
             atom(123, bytes([1, 10, 10]) + struct.pack('!H', 12) + b'keyword') +
             atom(127, struct.pack('!HH', 3, 30) + b'Frame text') +
             atom(129, bytes([1]) + struct.pack('!HHBHH', 6, 4, 2, 7, 5) + b'radio') +
             atom(130, struct.pack('!H', 1) + bytes([10, 10]) + struct.pack('!H', 12) + b'efield2') +
             atom(131, struct.pack('!H', 1) + bytes([10, 10]) + struct.pack('!H', 12) + b'ofield2') +
             atom(132, struct.pack('!H', 1) + bytes([10, 10]) + struct.pack('!H', 12) + b'keyword2') +
             atom(118) + atom(119) + atom(99, b'??') + atom(114, b'fname') + atom(120, b'xmlprop') +
             atom(121, bytes([1, 10, 10]) + struct.pack('!H', 12) + b'password', attr=0x02))
    g.append([item(0x12, 9, 2, atoms), A(9, 2, atom(115, bytes([10, 1]) + struct.pack('!HH', 8, 6) + stz('OK', 'FC')) +
                                              atom(114, b'fname2')), item(0x12, 9, 0x10, atom(118))])
    g.append([item(0x12, 0x0b, 1, menu_entry() + menu_entry('Edit', 'Ctrl+E', 'edit'))])
    # extended passports
    g.append([item(0x12, 4, 0x18, epp(1)), item(0x10, 4, 0x18, epp(2)),
              item(0x12, 4, 0x18, epp(3)),
              item(0x12, 4, 0x18, epp(3, [(0, 1, [(1, 2, 3, b'val'), (2, 2, 4, b'')]),
                                          (1, 2, [(5, 6, 7, b'xyz')])]))])
    # applications with a name but no dissection of the body
    other = []
    for i, ss in ((1, (1, 2, 3)), (2, (1, 2, 3)), (3, (1, 2)), (7, (1, 2, 3)), (0x12, (1, 2)), (0x13, (1, 2)),
                  (0x14, (2, 3)), (0x0a, (2, 3, 7)), (0x0b, (1, 2)), (0x0c, (1, 5)), (0x0e, (2, 3)),
                  (0x0f, (2,)), (0x09, (1, 3, 4)), (0x05, (2, 3)), (0x04, (1, 3)), (0x06, (4, 5))):
        for s in ss:
            other.append(A(i, s, b'\1\2\3\4'))
    g.append(other[:30])
    g.append(other[30:])
    g.append([item(0x08, body=b''), item(0x04, body=b'')][:0] + [item(0x10, 0x30, 0x30, b'unknown')])
    return g


def build_main(out):
    c = Cap()
    f = flow(c)
    groups = build_items()
    # DP header (the first message of a dialog step)
    f.send(ni(dp() + msg([item(0x10, 4, 2, struct.pack('!III', 2, 1100, 7))])))
    for k, g in enumerate(groups):
        f.send(ni(msg(g, mode=k & 1, comflag=0x28 | (k & 7))), bool(k % 2 == 0))
    # com flags
    for cf in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80):
        f.send(ni(msg([A_(4, 0x1c, b'USER')], comflag=cf)))
    # fixed messages
    f.send(ni(b'**DPTMMSG**\0' + b'dispatcher message\0'), False)
    f.send(ni(b'**DPTMOPC**\0' + b'\1\2\3\4'), False)
    # error message (UTF-16LE text)
    f.send(ni(bytes([0, 0, 0, 4, 1, 0, 0, 0]) + 'Session terminated'.encode('utf-16-le') + b'\0'), False)
    # a short message (header only, with no item)
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0])))
    # --- compressed messages (LZC) ------------------------------------------
    body = b''.join(groups[1] + groups[3] + groups[1]) + EOM
    hdr = bytes([0, 0x28, 0, 0, 1, 0, 0, 1])
    f.send(ni(hdr + lzc_compress(body)), False)
    f.send(ni(hdr + lzc_compress(b''.join(groups[0]) + EOM)), False)
    # --- SNC wrapped message: an SNC frame whose data is a Diag message ---
    inner = msg([A_(4, 0x1c, b'SNCUSER')])
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2]) + snc_frame(0x07, token=b'T', data=inner)))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 3]) + snc_frame(0x08, data=inner)), False)
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2]) + snc_frame(0x09, data=inner)))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2]) + snc_frame(0x07, token=b'T', data=lzc_compress(inner))))
    # --- RFC calls inside a Diag message (SAP RFC internal dissector) ----
    rfc = b''.join(rfc_item(a, b, v) for a, b, v in ((1, 2, b'Z_FUNCTION'), (2, 1, b'IMPORT_PARAM'),
                                                    (2, 5, b'EXPORT_PARAM'), (0xff, 0xff, b'')))
    f.send(ni(msg([item(0x10, 8, 1, rfc)])))
    c.write(os.path.join(out, 'sapdiag-coverage.pcap'))


def A_(i, s, body):
    return item(0x10, i, s, body)


def rfc_item(i1, i2, value):
    return bytes([i1, i2]) + struct.pack('!H', len(value)) + value + bytes([i1, i2])


def build_malformed(out):
    c = Cap()
    f = flow(c)
    # items cut short and with wrong lengths
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x10])))                      # APPL item with no id/sid
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x10, 4, 0x1c, 0x00])))      # no length
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x10, 4, 0x1c, 0x00, 0x20, 1, 2])))    # value cut short
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x12, 9, 2, 0xff, 0xff, 0xff, 0xff, 1])))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x11, 0xff, 0xff, 0xff, 0xff, 1])))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x01, 1, 2, 3])))              # SES cut short
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0, 0x08, 0x0c])))                 # OCK, unknown length
    # wrong item lengths for the fixed items
    items = [A_(4, s, z(1)) for s in (2, 4, 0x0b, 0x0d, 0x0f, 0x16, 0x17, 0x19, 0x24, 0x25, 0x26)]
    items += [A_(6, s, z(1)) for s in (1, 6, 0x0a, 0x11, 0x16, 0x18, 0x19, 0x22, 0x23, 0x27, 0x13, 0x14)]
    items += [A_(6, 0x1f, b''), A_(6, 0x1f, bytes([3]) + z(5)), A_(9, 0x0b, z(3)), A_(9, 0x0b, bytes([5]) + z(12))]
    items += [A_(10, s, z(2)) for s in (1, 4, 5, 8, 9, 0x0a)]
    items += [A_(12, s, z(1)) for s in (2, 6, 7, 8, 0x0c, 0x0d, 0x0e)]
    items += [A_(0x14, 1, z(2)), A_(5, 1, z(4)), item(0x09, body=b'')[:1], item(0x13, body=z(1)), item(0x0a, body=z(1)),
              item(0x0b, body=z(1)), A_(4, 0x1d, b''), A_(0x0e, 1, struct.pack('!H', 2) + b'nonul'), A_(0x0e, 1, struct.pack('!H', 3) + stz('v') + b'\0'), A_(8, 3, b'\1\2\3\4'),
              A_(0x0f, 1, b''), A_(0x0f, 1, bytes([4]) + z(5)), A_(0x0f, 1, bytes([1]) + z(10)),
              A_(0x0f, 1, bytes([1]) + z(11) + struct.pack('!H', 9) + bytes([1, 2]))]
    for it in items:
        f.send(ni(msg([it])))
    # atoms and menus
    bad = [atom(121, b'\1\1')[:6], b'\0\1' + z(5), atom(115, b'\1'), atom(115, bytes([1, 1, 0, 8, 0, 6]) + b'nonul'),
           atom(115, bytes([1, 1, 0, 8, 0, 6]) + stz('t') + b'nofc'),
           atom(116, b'\1'), atom(116, bytes([1, 1, 1, 0, 9, 0, 6, 0, 12]) + b'nonul'),
           atom(116, bytes([1, 1, 1, 0, 9, 0, 6, 0, 12]) + stz('t') + b'x'),
           atom(116, bytes([1, 1, 1, 0, 9, 0, 6, 0, 12]) + stz('t', 'f') + b'x'),
           atom(121, b'\1'), atom(127, b'\1'), atom(129, b'\1'), atom(130, b'\1'),
           atom(114, b'text')]
    f.send(ni(msg([item(0x12, 9, 2, bad[0])])))
    f.send(ni(msg([item(0x12, 9, 2, atom(114, b'first') + atom(121, b'\1\2\3\4\5\6\7\0'))])))   # starts with FNAME
    for b in bad[1:]:
        f.send(ni(msg([item(0x12, 9, 2, atom(121, bytes([1, 10, 10, 0, 12]) + b'x') + b)])))
    f.send(ni(msg([item(0x12, 0x0b, 1, b'\0')])))
    f.send(ni(msg([item(0x12, 0x0b, 1, struct.pack('!H', 3) + b'ab')])))
    f.send(ni(msg([item(0x12, 0x0b, 1, struct.pack('!H', 40) + z(20) + b'nonul')])))
    for cut in (21, 24, 30):
        f.send(ni(msg([item(0x12, 0x0b, 1, menu_entry('Edit', 'Ctrl+E', 'info')[:cut])])))
    f.send(ni(msg([item(0x12, 0x0b, 1, struct.pack('!H', 21) + bytes(range(1, 19)) + b'\0' + b'\0' )])))
    f.send(ni(msg([item(0x12, 0x0b, 1, struct.pack('!H', 22) + bytes(range(1, 19)) + b'\0' + b'\0' + b'x')])))
    # passports: bad magic, bad version, short, bad trailer, bad variable parts
    e3 = epp(3, [(0, 1, [(1, 2, 3, b'val')])])
    f.send(ni(msg([item(0x12, 4, 0x18, b'abc')])))
    f.send(ni(msg([item(0x12, 4, 0x18, b'XXXX' + epp(1)[4:])])))
    f.send(ni(msg([item(0x12, 4, 0x18, epp(1)[:4] + bytes([9]) + epp(1)[5:])])))
    f.send(ni(msg([item(0x12, 4, 0x18, epp(1)[:0x90])])))
    f.send(ni(msg([item(0x12, 4, 0x18, epp(1)[:-4] + b'XXXX')])))
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xe0] + struct.pack('!H', 0x10) + e3[0xe2:])])))   # variable offset too low
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xe2] + b'XXXX' + e3[0xe6:])])))                  # bad part magic
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xe2 + 5] + struct.pack('!H', 2) + e3[0xe2 + 7:])])))   # part length < 12
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xde] + struct.pack('!H', 5) + e3[0xe0:])])))     # more parts than data
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xe2 + 15] + struct.pack('!H', 3) + e3[0xe2 + 17:])])))   # item length < 7
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:0xe2 + 10] + struct.pack('!H', 9) + e3[0xe2 + 12:])])))   # item count too high
    f.send(ni(msg([item(0x12, 4, 0x18, e3[:-4] + b'XXXX')])))
    # UI event / uievent container ids too many
    f.send(ni(msg([A_(0x0f, 1, bytes([4]) + z(5) + struct.pack('!H', 3) + b'\0\0\0\0\0\0' + struct.pack('!H', 9) + bytes([1, 2]))])))
    # a dynt focus with more than 30 container ids, a message shorter than the header
    f.send(ni(msg([A_(9, 0x0b, bytes([1]) + struct.pack('!4H', 1, 2, 3, 4) + z(40))])))
    f.send(ni(bytes([0, 0x28, 0])))
    # error message with nothing after the header, DP header only
    f.send(ni(bytes([0, 0, 0, 4, 1, 0, 0, 0])), False)
    f.send(ni(dp() + z(4)))
    # compression: bad lengths and streams
    hdr = bytes([0, 0x28, 0, 0, 1, 0, 0, 1])
    good = lzc_compress(msg([A_(4, 0x1c, b'USER')]))
    f.send(ni(hdr + struct.pack('<I', 0) + good[4:]))                                  # reported length 0
    f.send(ni(hdr + struct.pack('<I', 0x7fffffff) + good[4:]))                        # too large
    f.send(ni(hdr + struct.pack('<I', len(good)) + good[4:7] + b'\x01' * 6))            # bad stream
    f.send(ni(hdr + struct.pack('<I', 5000) + good[4:]))                              # length differs
    f.send(ni(hdr + struct.pack('<I', 40) + bytes([0x12, 0x1f, 0x9d, 0x90]) + b'\1' * 30))   # LZH, bad data
    f.send(ni(hdr + struct.pack('<I', 40) + bytes([0x11, 0x1f, 0x9d, 0x95]) + b'\1' * 30))   # too many max bits
    f.send(ni(hdr + b'\1\2\3\4\5\6\7'))                                                # shorter than the header
    f.send(ni(hdr + lzc_compress(bytes(range(256)) * 8, maxbits=12)))      # a stream that is not Diag items
    # SNC frames with no data, short
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2]) + snc_frame(0x07, token=b'T')))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2]) + b'SNC'))
    f.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 2])))
    c.write(os.path.join(out, 'sapdiag-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)

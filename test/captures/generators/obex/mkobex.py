#!/usr/bin/env python3
# Generates test/captures/obex_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic OBEX coverage captures.  Usage: mkobex.py <outdir>

Writes obex-coverage.pcapng (Exported PDU "obex", with the pcapng packet
direction flag giving the Sent/Rcvd direction) and
obex-coverage-malformed.pcapng.  Everything is built with struct; the
authentication digests, nonces and keys are placeholder bytes."""
import struct
import sys
import os

# --- pcapng with Exported PDU and the epb_flags direction option ------------
def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)

def _opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\0' * ((-len(val)) % 4)

def write_pcapng(path, frames, linktype=252):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += _blk(1, struct.pack('<HHI', linktype, 0, 0))
    for i, (data, d) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        body = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(data), len(data))
        body += data + b'\0' * ((-len(data)) % 4)
        if d is not None:
            body += _opt(2, struct.pack('<I', {'in': 1, 'out': 2}[d])) + _opt(0, b'')
        out += _blk(6, body)
    open(path, 'wb').write(out)

def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

# --- OBEX building blocks ----------------------------------------------------
def uni(s):
    return s.encode('utf-16-be') + b'\0\0'

def h_uni(hid, s):
    v = uni(s)
    return bytes([hid]) + struct.pack('>H', 3 + len(v)) + v

def h_seq(hid, v):
    return bytes([hid]) + struct.pack('>H', 3 + len(v)) + v

def h_b1(hid, v):
    return bytes([hid, v])

def h_b4(hid, v):
    return bytes([hid]) + struct.pack('>I', v)

def pkt(op, extra=b'', *hdrs):
    body = extra + b''.join(hdrs)
    return bytes([op]) + struct.pack('>H', 3 + len(body)) + body

CONN = struct.pack('>BBH', 0x10, 0, 0x2000)
FINAL = 0x80

def app(*params):
    return b''.join(bytes([i, len(v)]) + v for i, v in params)

def ap(hdr_params):
    return h_seq(0x4c, app(*hdr_params))

UUIDS = {
 'ftp': 'F9EC7BC4953C11D2984E525400DC9E09',
 'pbap': '796135F0F0C511D809660800200C9A66',
 'syncml': '000000010000100080000002EE000002',
 'bip_push': 'E33D9545837 44AD79EC5C16BE31EDE8E'.replace(' ', ''),
 'bip_pull': '8EE9B3D0460811D5841A0002A5325B4E',
 'bip_adv': '9235335046 0811D5841A0002A5325B4E'.replace(' ', ''),
 'bip_auto': '940126C0460811D5841A0002A5325B4E',
 'bip_rc': '947E7420460811D5841A0002A5325B4E',
 'bip_rm': '94C7CD20460811D5841A0002A5325B4E',
 'bip_ref': '8E61F95D1A7911D48EA400805F9B9834',
 'avrcp': '7163DD544A7E11E2B47C0050C2490048',
 'map_mas': 'BB582B40420C11DBB0DE0800200C9A66',
 'map_mns': 'BB582B41420C11DBB0DE0800200C9A66',
 'bpp1': '00001118000010008000' '00805F9B34FB',
 'bpp2': '00001119000010008000' '00805F9B34FB',
 'bpp3': '00001120000010008000' '00805F9B34FB',
 'bpp4': '00001121000010008000' '00805F9B34FB',
 'bpp5': '00001122000010008000' '00805F9B34FB',
 'bpp6': '00001123000010008000' '00805F9B34FB',
}
UU = {k: bytes.fromhex(v) for k, v in UUIDS.items()}
UU['sync'] = b'IRMC-SYNC'
UU['unknown'] = bytes(range(16))

FILTER8 = bytes.fromhex('00000000ffffffff')
KEY16 = bytes(range(0xa0, 0xb0))     # placeholder, not a real key

MEDIA = ['x-bt/phonebook', 'x-bt/vcard', 'x-bt/vcard-listing', 'x-bt/message', 'x-bt/messageStatus',
 'x-bt/MAP-messageUpdate', 'x-bt/MAP-NotificationRegistration', 'x-bt/MASInstanceInformation',
 'x-bt/MAP-msg-listing', 'x-bt/MAP-event-report', 'x-obex/folder-listing', 'x-bt/CTN-EventReport',
 'x-bt/CTN-Listing', 'x-bt/CTN-NotificationRegistration', 'x-bt/Calendar', 'x-bt/CalendarStatus',
 'x-bt/CTN-forward', 'x-bt/InstanceDescription', 'x-bt/Update', 'text/x-ref-simple',
 'text/x-ref-list', 'x-obex/RUI', 'x-obex/bt-SOAP', 'x-bt/img-listing', 'x-bt/img-properties',
 'x-bt/img-capabilities', 'x-bt/img-print', 'x-bt/img-img', 'x-bt/img-thm', 'x-bt/img-attachment',
 'x-bt/img-display', 'x-bt/img-partial', 'x-bt/img-archive', 'x-bt/img-status',
 'x-bt/img-monitoring', 'text/plain']

XMLB = b'<?xml version="1.0"?><listing version="1.0"><file name="a"/></listing>\0'
TEXTB = b'BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Test\r\nEND:VCARD\r\n'
BINB = bytes([0x00, 0x80, 0xff, 0x01, 0x02, 0xfe])

F = []          # (data, dir)
def S(p, d='out'):   # request, sent
    F.append((exp_pdu('obex', p), d))
def R(p):            # response, received
    F.append((exp_pdu('obex', p), 'in'))

def connect(target=None, rsp_hdrs=()):
    hs = []
    if target is not None:
        hs.append(h_seq(0x46, target))
    S(pkt(0x80, CONN, *hs))
    R(pkt(0xA0, CONN, *rsp_hdrs))

# ============================================================ 1. Unknown profile
# Connect with the auth challenge, count, length, connection id, who
chal = (bytes([0, 16]) + KEY16 + bytes([1, 1, 0x07]) + bytes([2, 6, 0xFF]) + 'hello'.encode() +
        bytes([2, 3, 0x00]) + b'ab' + bytes([3, 2, 0x55, 0x66]))
resp = (bytes([0, 16]) + KEY16 + bytes([1, 4]) + b'user' + bytes([2, 16]) + KEY16 + bytes([3, 3, 1, 2, 3]))
S(pkt(0x80, CONN, h_b4(0xC0, 3), h_b4(0xC3, 1234), h_seq(0x4d, chal)))              # 1
R(pkt(0xC1, CONN, h_seq(0x4d, chal)))                                                  # Unauthorised
S(pkt(0x80, CONN, h_seq(0x4e, resp)))
R(pkt(0xA0, CONN, h_seq(0x4a, UU['unknown']), h_b4(0xCB, 0x01020304)))                # Who, not a target
# GET with all the common headers
S(pkt(0x83, b'', h_b4(0xCB, 5), h_uni(0x01, 'telecom/pb.vcf'), h_uni(0x05, 'A description'),
      h_uni(0x15, 'dest/name'), h_seq(0x42, b'text/x-vCard\0'), h_seq(0x44, b'20260711T120000Z\0'),
      h_b4(0xC4, 0x5F000000), h_b4(0xCF, 0x1234), h_b4(0xD6, 0x777), h_seq(0x51, b'\x00' * 16),
      h_seq(0x50, b'\x10\x01'), h_seq(0x50, b'\x01\x02\x03'),
      h_b1(0x97, 1), h_b1(0x98, 2), h_b1(0x94, 1), h_b1(0x93, 7)))
R(pkt(0x90, b'', h_b1(0x97, 0), h_b1(0x98, 0), h_b1(0x94, 0), h_b1(0x94, 2), h_b1(0x97, 2), h_b1(0x98, 1), h_b1(0x94, 9), h_b1(0x97, 9), h_b1(0x98, 9)))
# unknown-profile user defined headers of all four encodings
S(pkt(0x82, b'', h_uni(0x30, 'ud-unicode'), h_seq(0x70, b'bytes'), h_b1(0xB0, 9), h_b4(0xF0, 0xdeadbeef),
      h_uni(0x3f, 'x'), h_seq(0x7f, b'\x01'), h_b1(0xBF, 1), h_b4(0xFF, 1), h_b4(0xC5, 1),
      h_seq(0x4b, b'\xaa'), h_uni(0x02, 'odd'), h_b1(0x80, 1), h_b4(0xE0, 2)))
R(pkt(0xA0))
# Object class, who, http headers: HTTP is dissected over exactly its own value
http1 = b'GET /index.html HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
http2 = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
S(pkt(0x82, b'', h_seq(0x47, http1), h_seq(0x47, http2), h_uni(0x01, 'after-http.txt'), h_seq(0x49, b'end\0')))   # reproducer: HTTP header length
R(pkt(0xA0))

# Session parameters, all tags, right and wrong lengths
sess = (bytes([0, 6]) + bytes.fromhex('020000000001') + bytes([0, 4]) + b'\1\2\3\4' +
        bytes([1, 8]) + b'N' * 8 + bytes([1, 2]) + b'NN' +
        bytes([2, 16]) + b'S' * 16 + bytes([2, 4]) + b'SSSS' +
        bytes([3, 1, 9]) + bytes([3, 2, 9, 9]) +
        bytes([4, 4]) + struct.pack('>I', 60) + bytes([4, 1, 1]) +
        bytes([5, 1, 3]) + bytes([5, 2, 3, 3]) + bytes([9, 2, 7, 7]))
S(pkt(0x87, b'', h_seq(0x52, sess)))
R(pkt(0xA0, b'', h_seq(0x52, bytes([5, 1, 0]))))
for op in range(5):
    S(pkt(0x87, b'', h_seq(0x52, bytes([5, 1, op])), h_b1(0x93, op)))
    R(pkt(0xA0))
# Application parameters in the unknown profile: raw, with CTN and GPP content
# (the CTN/GPP profile dissectors are only reached through Decode As)
S(pkt(0x83, b'', ap([(1, b'\1'), (2, b'\0'), (3, b'\1'), (4, b'20260101T000000'), (5, b'20261231T235959'),
                    (6, struct.pack('>I', 0x7ff)), (7, b'\1'), (8, b'\2'), (9, struct.pack('>I', 600)),
                    (0x0A, b'a@b.invalid'), (0x0B, b'20260711T000000'), (0x0C, b'\1'), (0x0D, b'\x07'),
                    (0x0E, b'20260711T010203'), (0x41, b'\x00\x10'), (0x42, b'\x00\x02'), (0x43, b'\1'),
                    (0x44, b'\3'), (0x46, b'\x00\x20'), (0x20, b'\xaa')]), h_seq(0x42, b'x-bt/CTN-Listing\0')))
S(pkt(0x83, b'', ap([(0x41, b'\x00\x10'), (0x42, b'\x00\x02'), (0x43, b'\1'), (0x44, b'\3'), (0x46, b'\x00\x20'),
                    (0x45, b'\0'), (0x47, b'\0')])))
# wrong lengths for the same ids (CTN: 1,1,1; GPP 0x41 is 2: the CTN 0x41 length check uses the GPP table)
S(pkt(0x83, b'', ap([(1, b'\1\2'), (2, b''), (6, b'\1'), (9, b'\1'), (0x0C, b'\1\1'), (0x41, b'\1'),
                    (0x42, b'\1\2\3'), (0x43, b''), (0x46, b'\1')])))
# Disconnect
S(pkt(0x81)); R(pkt(0xA0))

# ============================================================ 2. Set Path / Put / Get state
connect(UU['ftp'], [h_b4(0xCB, 9)])
def setpath(flags, name=None, ok=True, extra=0):
    hs = [h_uni(0x01, name)] if name is not None else []
    S(pkt(0x85, bytes([flags, 0]), *hs))
    R(pkt(0xA0 if ok else 0xC4))
setpath(0x02, 'telecom')           # sets the path
setpath(0x03, 'other')             # up from /telecom to the root, then /other
setpath(0x02, 'pb')
setpath(0x03, '')                   # go up, empty name
setpath(0x03)                       # go up without name
setpath(0x02, 'a')
setpath(0x02, 'b')
setpath(0x01)                       # up
setpath(0x01)
setpath(0x01)                       # up from root-level
setpath(0x01)
setpath(0x02, 'nowhere', ok=False)  # error response: the path does not change
S(pkt(0x85, bytes([0, 0])))         # request, then response to see path
R(pkt(0xA0))
# Put / Get with Type and Name; continue with final flag clear
S(pkt(0x02, b'', h_uni(0x01, 'file1.txt'), h_seq(0x42, b'text/plain\0'), h_b4(0xC3, 10), h_seq(0x48, b'0123456789')))
R(pkt(0x90))
S(pkt(0x82, b'', h_seq(0x49, b'0123456789')))
R(pkt(0xA0))
S(pkt(0x83, b'', h_uni(0x01, 'file1.txt'), h_seq(0x42, b'text/plain\0')))
R(pkt(0x90, b'', h_seq(0x48, b'part one\0')))
S(pkt(0x03))
R(pkt(0xA0, b'', h_seq(0x49, b'part two')))
S(pkt(0xFF)); R(pkt(0xA0))                                           # Abort
S(pkt(0x86, b'', h_b1(0x94, 0), h_uni(0x01, 'src'), h_uni(0x15, 'dst')))   # Action
R(pkt(0xA0))
S(pkt(0x86))                                                         # Action without headers, length 3
R(pkt(0xA0))
# default opcode with data after a length-3 header: "Unexpected data"
S(pkt(0x08) + b'\xaa\xbb')
F[-1] = (exp_pdu('obex', bytes([0x08, 0x00, 0x03, 0xaa, 0xbb])), 'out')
# Response codes
for code in [0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x40, 0x41, 0x42,
             0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
             0x54, 0x55, 0x60, 0x61, 0x7f, 0x07, 0x62]:
    S(pkt(0x83, b'', h_uni(0x01, 'x')))
    R(pkt(code | FINAL, b'', h_uni(0x01, 'r')))
# Direction unknown (no pcapng direction flag)
F.append((exp_pdu('obex', pkt(0x83, b'', h_uni(0x01, 'x'))), None))
F.append((exp_pdu('obex', pkt(0xA0, b'', h_seq(0x49, b'end'))), None))
# Too short to hold the length
F.append((exp_pdu('obex', b'\x80\x00'), 'out'))
# Disconnect
S(pkt(0x81)); R(pkt(0xA0))

# ============================================================ 3. Authentication, Time etc. kept in 1; media types
connect(UU['pbap'])
for mt in MEDIA:
    typ = mt.encode() + b'\0'
    xml = mt in ('x-bt/vcard-listing', 'x-bt/MAP-msg-listing', 'x-bt/MAP-event-report', 'x-obex/folder-listing',
                 'x-bt/img-listing', 'x-bt/img-properties', 'x-bt/img-capabilities', 'x-obex/bt-SOAP')
    body = XMLB if xml else (BINB if mt in ('x-bt/img-img', 'x-bt/img-thm') else TEXTB)
    S(pkt(0x83, b'', h_seq(0x42, typ), h_uni(0x01, 'obj')))
    if xml:
        R(pkt(0xA0, b'', h_seq(0x49, body)))
    else:
        R(pkt(0xA0, b'', h_seq(0x48, body[:len(body) // 2]), h_seq(0x49, body[len(body) // 2:])))
# XML in an Object without a known type, binary bodies, ASCII bodies
S(pkt(0x82, b'', h_seq(0x42, b'application/x-nothing\0'), h_seq(0x49, XMLB)))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x49, XMLB)))                 # no type on this put
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x49, b'plain ascii\nline two\0')))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x49, b'no terminator')))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x49, b'ctl\x01chars\0')))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x48, b'')))
R(pkt(0xA0))
S(pkt(0x83, b'', h_seq(0x42, b'text/x-vCard\0')))    # type given, body with unknown type
R(pkt(0xA0, b'', h_seq(0x49, TEXTB)))

# ============================================================ 4. PBAP application parameters
S(pkt(0x83, b'', h_seq(0x42, b'x-bt/phonebook\0'), h_uni(0x01, 'telecom/pb.vcf'),
      ap([(1, b'\1'), (2, b'John'), (3, b'\2'), (4, b'\xff\xff'), (5, b'\0\1'), (6, FILTER8), (7, b'\1'),
          (0x0C, bytes.fromhex('8000000000000001')), (0x0E, b'\1'), (0x0F, b'\1'), (0x10, struct.pack('>I', 0x3ff))])))
R(pkt(0xA0, b'', ap([(8, b'\x01\x02'), (9, b'\3'), (0x0A, KEY16), (0x0B, KEY16), (0x0D, KEY16),
                    (0x10, struct.pack('>I', 0xffffffff)), (0x20, b'\xaa\xbb')]), h_seq(0x49, TEXTB)))
S(pkt(0x83, b'', ap([(1, b'\1\2'), (3, b'\2\2'), (4, b'\0'), (5, b'\0'), (6, b'\1'), (7, b'\1\1'), (8, b'\1'),
                    (9, b'\1\1'), (0x0A, b'\1'), (0x0B, b'\1'), (0x0C, b'\1'), (0x0D, b'\1'), (0x0E, b'\1\1'),
                    (0x0F, b'\1\1')])))
R(pkt(0xA0))
connect(UU['syncml']); S(pkt(0x83, b'', ap([(1, b'\1')]))); R(pkt(0xA0))
connect(UU['sync']); S(pkt(0x83, b'', ap([(1, b'\1')]))); R(pkt(0xA0))

# ============================================================ 5. MAP
for tgt in ('map_mas', 'map_mns'):
    connect(UU[tgt], [h_seq(0x4a, UU[tgt])])
MAPP = [(1, b'\0\x10'), (2, b'\0\1'), (3, b'\x1f'), (4, b'20260101T000000'), (5, b'20261231T235959'),
        (6, b'\3'), (7, b'rcpt'), (8, b'orig'), (9, b'\1'), (0x0A, b'\1'), (0x0B, b'\0'), (0x0C, b'\1'),
        (0x0D, b'\1'), (0x0E, b'\1'), (0x0F, b'\2'), (0x10, struct.pack('>I', 0xffffffff)), (0x11, b'\0\5'),
        (0x12, b'\0\6'), (0x13, b'\x20'), (0x14, b'\1'), (0x15, b'\1'), (0x16, b'\0'), (0x17, b'\1'),
        (0x18, b'\1'), (0x19, b'20260711T120000+0100'), (0x1a, b'\xaa')]
S(pkt(0x83, b'', h_seq(0x42, b'x-bt/MAP-msg-listing\0'), h_uni(0x01, 'inbox'), ap(MAPP)))
R(pkt(0xA0, b'', ap(MAPP[:12]), h_seq(0x49, XMLB)))
S(pkt(0x83, b'', ap([(1, b'\0'), (2, b'\0\1\2'), (3, b''), (6, b'\0\0'), (9, b''), (0x0A, b'\1\1'), (0x10, b'\1'),
                    (0x11, b'\1'), (0x12, b'\1'), (0x13, b'\1\1'), (0x19, b'x')])))
R(pkt(0xA0))

# ============================================================ 6. BIP
for tgt in ('bip_push', 'bip_pull', 'bip_adv', 'bip_auto', 'bip_rc', 'bip_rm', 'bip_ref'):
    connect(UU[tgt])
BIPP = [(1, b'\0\3'), (2, b'\0\0'), (3, b'\1'), (4, struct.pack('>I', 100)), (5, struct.pack('>I', 0)),
        (6, struct.pack('>I', 4096)), (7, b'\1'), (8, b'\2'), (9, bytes(range(16))), (0x0A, b'\1'), (0x0B, b'\xaa')]
desc = b'<image-descriptor version="1.0"><image encoding="JPEG" pixel="64*64" size="1024"/></image-descriptor>'
S(pkt(0x83, b'', h_seq(0x42, b'x-bt/img-listing\0'), ap(BIPP), h_uni(0x30, '1000001'), h_seq(0x71, b'<?xml version="1.0"?>' + desc),
      h_seq(0x72, b'x'), h_b1(0xB1, 1), h_b4(0xF1, 1), h_uni(0x31, 'u31'), h_seq(0x51, b'\0' * 16)))
R(pkt(0xA0, b'', h_uni(0x30, '2000002'), h_seq(0x71, b'plain, not xml'), h_seq(0x49, XMLB)))
S(pkt(0x83, b'', ap([(1, b'\0'), (2, b'\0'), (3, b'\1\1'), (4, b'\1'), (5, b'\1'), (6, b'\1'), (7, b''),
                    (8, b''), (9, b'\1'), (0x0A, b'')])))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x42, b'x-bt/img-img\0'), h_uni(0x30, 'h'), h_seq(0x49, BINB)))
R(pkt(0xA0))

# ============================================================ 7. AVRCP cover art
connect(UU['avrcp'])
S(pkt(0x83, b'', h_seq(0x42, b'x-bt/img-img\0'), h_uni(0x30, '0000001'), h_seq(0x71, desc), h_seq(0x70, b'u'),
      h_seq(0x4c, b'\x01\x01\x01')))
R(pkt(0xA0, b'', h_seq(0x49, BINB), h_uni(0x30, 'handle'), h_b4(0xF2, 2)))

# ============================================================ 8. BPP
for tgt in ('bpp1', 'bpp2', 'bpp3', 'bpp4', 'bpp5', 'bpp6'):
    connect(UU[tgt])
BPPP = [(1, struct.pack('>I', 0)), (2, struct.pack('>I', 20)), (3, struct.pack('>I', 77)), (4, struct.pack('>I', 9999)),
        (5, struct.pack('>I', 0))]
S(pkt(0x83, b'', h_seq(0x42, b'x-obex/RUI\0'), ap(BPPP)))
R(pkt(0xA0, b'', h_seq(0x49, TEXTB)))
S(pkt(0x83, b'', ap([(1, b'\1'), (2, b'\1\1'), (3, b''), (4, b'\1\2\3\4\5'), (9, b'\1')])))
R(pkt(0xA0))
S(pkt(0x82, b'', h_seq(0x42, b'x-obex/bt-SOAP\0'), h_seq(0x49, XMLB))); R(pkt(0xA0))

# ============================================================ 9. Unknown target, Who headers
connect(UU['unknown'])
S(pkt(0x83, b'', h_seq(0x46, b'short'), h_seq(0x4a, UU['ftp'][:15] + b'\0'))); R(pkt(0xA0))
connect(UU['ftp'], [h_seq(0x4a, UU['ftp'])])

# ============================================================ 10. Reassembly
def fragments(p, cuts):
    prev = 0
    out = []
    for c in cuts + [len(p)]:
        out.append(p[prev:c]); prev = c
    return out
put = pkt(0x82, b'', h_uni(0x01, 'big.vcf'), h_seq(0x42, b'x-bt/vcard\0'), h_b4(0xC3, 200),
          h_seq(0x49, TEXTB[:-1] + b'.' * 80 + b'\0'))
fr = fragments(put, [30, 70])
for i, x in enumerate(fr):
    S(x)
R(pkt(0xA0))
# a reassembled response
rsp = pkt(0xA0, b'', h_seq(0x48, b'1234567890' * 8), h_seq(0x49, b'abc\0'))
for x in fragments(rsp, [10, 50]):
    R(x)
# set path split in two, last fragment only 2 bytes (the last fragment is shorter than the OBEX header)
sp = pkt(0x85, bytes([0x03, 0]), h_uni(0x01, 'zz'))
for x in fragments(sp, [len(sp) - 2]):
    S(x)
R(pkt(0xA0))
# reproducer for "OBEX: Use the reassembled tvb": the last fragment is a single byte
name = h_uni(0x01, 'Name')
body = h_seq(0x49, b'ABCDEFGH')
total = 3 + len(name) + len(body)
pk = bytes([0x82]) + struct.pack('>H', total) + name + body
S(pk[:-1]); S(pk[-1:])
R(pkt(0xA0))
# unknown opcode default branch with last opcode CONNECT is covered by the Connect responses
# reassembled packet with a default (unknown) opcode and "unexpected" data (length field 3, rest of data)
ux = bytes([0x09, 0x00, 0x08]) + h_b4(0xC0, 1)
S(ux[:4]); S(ux[4:])
# an HTTP header reproducer chain: the HTTP header must not swallow what follows
# an incomplete chain, then a complete packet: fragments are swallowed by the pending chain
frag0 = bytes([0x82]) + struct.pack('>H', 200) + b'\x49' + struct.pack('>H', 197) + b'x' * 14
S(frag0); S(b'y' * 20); S(b'z' * 20)

write_pcapng(os.path.join(sys.argv[1], 'obex-coverage.pcapng'), F)
print(len(F), 'frames in main capture')

# ============================================================ malformed
F = []
connect(UU['pbap'])
S(pkt(0x83, b'', b'\x4c\x00\x0b' + b'\x06\x08' + b'\0' * 3))                  # app param runs off the end
S(pkt(0x83, b'', b'\x01\xff\xff' + b'\0\0'))                                 # header length beyond packet
S(pkt(0x83, b'', b'\x4d\x00\x08' + bytes([2, 200, 0xff, 0x41, 0x42])))       # auth challenge, bad sub length
S(pkt(0x83, b'', b'\x4e\x00\x08' + bytes([0, 16, 1, 2, 3])))                 # auth response, short key
S(pkt(0x83, b'', b'\x52\x00\x07' + bytes([0, 6, 1, 2])))                     # session parameter truncated
S(pkt(0x83, b'', b'\xc3\x00\x00'))                                           # 4 byte header cut off
S(pkt(0x83, b'', b'\x94'))                                                    # 1 byte header cut off
S(pkt(0x83, b'', b'\x30\x00'))                                               # header without length
S(pkt(0x83, b'', b'\x46\x00\x13' + b'\0' * 16))                              # target past the end
S(pkt(0x83, b'', b'\x48\x00\x20' + b'ab'))                                    # body past the end
S(pkt(0x83, b'', b'\x47\x00\x20' + b'ab'))                                    # HTTP past the end
S(pkt(0x80, b'\x10\x00'))                                                     # connect without max packet length
S(pkt(0x85, b'\x00'))                                                         # set path without constants
S(pkt(0x83, b'', ap([(1, b'\1'), (3, b'\2'), (6, b'\0\0\0\0')])[:-2]))        # PBAP filter cut short
S(pkt(0x83, b'', b'\x4c\x00\x07' + bytes([0x10, 4, 1])))                      # supported features cut short
connect(UU['map_mas'])
S(pkt(0x83, b'', b'\x4c\x00\x07' + bytes([0x10, 4, 0, 0])))
S(pkt(0x83, b'', b'\x4c\x00\x06' + bytes([0x04, 40, 0])))
connect(UU['bip_pull'])
S(pkt(0x83, b'', b'\x4c\x00\x07' + bytes([0x01, 2, 0])))
S(pkt(0x83, b'', b'\x30\x00\x07abcd'))
connect(UU['bpp1'])
S(pkt(0x83, b'', b'\x4c\x00\x07' + bytes([0x01, 4, 0])))
S(pkt(0x83, b'', b'\x4c\x00\x05' + bytes([0x01, 0])))
connect(UU['avrcp'])
S(pkt(0x83, b'', b'\x30\x00\x07abcd'))
# length field smaller than the data: a "packet length 3" header with trailing garbage and short fragments
S(b'\x82\x00')
S(b'\x82')
write_pcapng(os.path.join(sys.argv[1], 'obex-coverage-malformed.pcapng'), F)
print(len(F), 'frames in malformed capture')

# ============================================================ Bluetooth (OBEX over L2CAP CID and RFCOMM)
# HCI H4 with pseudo-header (linktype 201); needs Decode As in runcov.sh:
#   btl2cap.cid 0x40 -> obex, btl2cap.cid 0x41 -> btrfcomm, btrfcomm.dlci 4 -> obex
def h4(direction, cid, payload):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    acl = struct.pack('<HH', 0x2001, len(l2)) + l2
    return struct.pack('>I', direction) + b'\x02' + acl

def rfcomm_uih(dlci, payload):
    return bytes([(dlci << 2) | 0x03, 0xEF, (len(payload) << 1) | 1]) + payload + b'\0'

def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

BT = []
for d, cid, p in [(0, 0x40, pkt(0x80, CONN, h_seq(0x46, UU['ftp']))), (1, 0x40, pkt(0xA0, CONN)),
                  (0, 0x40, pkt(0x85, bytes([2, 0]), h_uni(0x01, 'dir'))), (1, 0x40, pkt(0xA0)),
                  (0, 0x40, pkt(0x83, b'', h_uni(0x01, 'f'))), (1, 0x40, pkt(0xA0, b'', h_seq(0x49, b'data'))),
                  (0, 0x40, pkt(0x80, CONN, h_seq(0x46, UU['pbap']))), (1, 0x40, pkt(0xA0, CONN)),
                  (0, 0x40, pkt(0x83, b'', ap([(4, b'\xff\xff')])))]:
    BT.append(h4(d, cid, p))
for d, dl, p in [(0, 4, pkt(0x80, CONN, h_seq(0x46, UU['map_mas']))), (1, 4, pkt(0xA0, CONN)),
                 (0, 4, pkt(0x83, b'', h_seq(0x42, b'x-bt/message\0'), ap([(1, b'\0\1')]))),
                 (1, 4, pkt(0xA0, b'', h_seq(0x49, TEXTB)))]:
    BT.append(h4(d, 0x41, rfcomm_uih(dl, p)))
write_pcap(os.path.join(sys.argv[1], 'obex-coverage-bt.pcap'), 201, BT)
print(len(BT), 'frames in the Bluetooth capture')

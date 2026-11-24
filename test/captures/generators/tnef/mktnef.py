#!/usr/bin/env python3
# Generates test/captures/tnef_coverage.tnef.gz, tnef_coverage_http.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds tnef-coverage.tnef (a TNEF file, read by the TNEF file reader),
# tnef-coverage-http.pcap (TNEF as application/ms-tnef over HTTP) and
# tnef-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import Flow, write

SIG = 0x223e9f78
PT_NULL, PT_I2, PT_LONG, PT_BOOLEAN, PT_STRING8, PT_UNICODE, PT_BINARY = 0x1, 0x2, 0x3, 0xb, 0x1e, 0x1f, 0x102
PT_CLSID, PT_SYSTIME, PT_ERROR, PT_OBJECT = 0x48, 0x40, 0xa, 0xd
MV = 0x1000

def attr(tag, data, lvl=1):
    ck = sum(data) & 0xffff
    return struct.pack('<BII', lvl, tag, len(data)) + data + struct.pack('<H', ck)

def tnef(attrs, key=0x1234, sig=SIG, tail=b''):
    return struct.pack('<IH', sig, key) + b''.join(attrs) + tail

def pad4(b, start=0):
    return b + b'\0' * ((-len(b)) % 4)

def prop(ptype, pid, body, named=None):
    """One MAPI property: tag, (named property header), value, padding to 4 octets."""
    if named is None:
        b = struct.pack('<HH', ptype, pid)
    else:
        guid, kind, val = named
        b = struct.pack('<HH', ptype, 0x8000 + pid) + guid
        if kind == 0:
            b += struct.pack('<II', 0, val)
        else:
            name = val.encode('utf-16-le')
            b += struct.pack('<II', 1, len(name)) + name + b'\0' * ((-len(name)) % 4)
    return pad4(b + body)

def counted(values):
    return struct.pack('<I', len(values)) + b''.join(struct.pack('<I', len(v)) + v for v in values)

def mapi(props):
    return struct.pack('<I', len(props)) + b''.join(props)

GUID = bytes(range(16))
FT = struct.pack('<II', 0xd53e8000, 0x01d9c0f2)

def all_props():
    p = []
    p.append(prop(PT_I2, 0x0e01, struct.pack('<H', 7)))
    p.append(prop(PT_LONG, 0x0e02, struct.pack('<I', 0x12345678)))
    p.append(prop(PT_BOOLEAN, 0x0e03, struct.pack('<H', 1)))
    p.append(prop(PT_STRING8, 0x0037, counted([b'Subject of the message'])))
    p.append(prop(PT_BINARY, 0x0ff9, counted([bytes(range(20))])))
    p.append(prop(PT_UNICODE, 0x0037, counted(['Unicode subject'.encode('utf-16-le')])))
    p.append(prop(PT_CLSID, 0x3d00, GUID))
    p.append(prop(PT_SYSTIME, 0x0039, FT))
    p.append(prop(PT_ERROR, 0x0e04, struct.pack('<I', 0x8004010f)))
    p.append(prop(PT_NULL, 0x0e05, struct.pack('<I', 0)))
    p.append(prop(PT_OBJECT, 0x0e06, struct.pack('<I', 0)))
    # multi-valued properties: cValues and a pointer (NULL, or non-NULL for the batch 37 reproducer)
    for i, t in enumerate((PT_I2, PT_LONG, PT_STRING8, PT_BINARY, PT_CLSID, PT_UNICODE, PT_SYSTIME)):
        p.append(prop(MV | t, 0x0e10 + i, struct.pack('<II', 1, 0x20000 + i)))
        p.append(prop(MV | t, 0x0e20 + i, struct.pack('<II', 0, 0)))
    # named properties: by id and by name (name length not a multiple of 4: padding)
    p.append(prop(PT_LONG, 0x0001, struct.pack('<I', 5), named=(GUID, 0, 0x8101)))
    p.append(prop(PT_STRING8, 0x0002, counted([b'named by string']), named=(GUID, 1, 'Keywords')))
    p.append(prop(PT_I2, 0x0003, struct.pack('<H', 3), named=(GUID, 1, 'Odd')))
    p.append(prop(PT_BOOLEAN, 0x0004, struct.pack('<H', 0), named=(GUID, 1, 'Fourlen!')))
    # a property of a type that is not decoded (no value octets follow)
    p.append(prop(0x0005, 0x0e30, b''))
    p.append(prop(PT_STRING8, 0x0e31, counted([b''])))
    return p

def dtr(y=2026, mo=11, d=12, h=13, mi=14, s=15, dow=4):
    return struct.pack('<7H', y, mo, d, h, mi, s, dow)

def addr(name, mail):
    return struct.pack('<H', len(name)) + name + struct.pack('<H', len(mail)) + mail

def main(out):
    A = []
    A.append(attr(0x00089006, struct.pack('<I', 0x00010000)))                    # TNEF version
    for cp in (1252, 1250, 1251, 437):                                           # OEM code page: ISO-8859-1 style, and others
        A.append(attr(0x00069007, struct.pack('<II', cp, 0)))
        A.append(attr(0x00018004, b'Subject ' + str(cp).encode() + b' \xe4\xf6\xfc'))   # subject in that code page
    A.append(attr(0x00078008, b'IPM.Microsoft Mail.Note\0'))                     # message class
    A.append(attr(0x00079008, b'IPM.Note\0'))                                    # original message class
    A.append(attr(0x00060000, addr(b'Alice Example', b'alice@example.net')))     # owner
    A.append(attr(0x00060001, addr(b'Bob Example', b'bob@example.net')))         # sent for
    for pr in (1, 2, 3, 0x0102):
        A.append(attr(0x0004800d, struct.pack('<H', pr)))                        # priority
    for tag in (0x00038005, 0x00038006, 0x00030006, 0x00030007, 0x00038012, 0x00038013, 0x00038020):
        A.append(attr(tag, dtr()))                                               # every date attribute
    for tag in (0x00018009, 0x0001800a, 0x0001800b, 0x00018010):                 # message id, parent id, conversation id, attachment title
        A.append(attr(tag, b'0123456789abcdef\0'))
    A.append(attr(0x00008000, b'\x00\x01\x02\x03\x04\x05'))                      # from (triples)
    A.append(attr(0x0002800c, b'Body text of the message\r\n'))                  # body
    A.append(attr(0x00068007, struct.pack('<I', 0x20)))                          # message status (byte-type attribute)
    A.append(attr(0x00040008, struct.pack('<I', 1)))                             # AID owner
    A.append(attr(0x00069003, mapi(all_props())))                                # MAPI properties
    A.append(attr(0x00069004, bytes(range(12))))                                 # recipient table
    A.append(attr(0x00069002, bytes(14), lvl=2))                                 # attachment rendering data
    A.append(attr(0x00069001, b'attach.txt\0', lvl=2))                           # transport file name
    A.append(attr(0x0006800f, bytes(range(256)) * 2, lvl=2))                     # attachment data
    A.append(attr(0x00069003, mapi(all_props()[:6]), lvl=2))                     # MAPI properties of the attachment
    A.append(attr(0x00069005, bytes(8), lvl=2))                                  # attachment
    A.append(attr(0x00060002, bytes(6)))                                         # delegate (not decoded further)
    A.append(attr(0x0007ffff, b'unknown attribute'))                             # an unknown tag with a ATP_TEXT-less type
    A.append(attr(0x0001ffff, b'unknown string attribute'))                      # unknown tag of type string
    data = tnef(A, tail=b'\0\0\0\0')                                             # a few octets of padding at the end
    open(os.path.join(out, 'tnef-coverage.tnef'), 'wb').write(data)
    print('tnef bytes', len(data))

    # HTTP: TNEF as application/ms-tnef (several responses on one connection)
    def http(body, ctype='application/ms-tnef'):
        return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype.encode() + b'\r\nContent-Length: ' + str(len(body)).encode() +
                b'\r\n\r\n' + body)
    fr = []
    f = Flow(55001, 80)
    req = b'GET /mail/winmail.dat HTTP/1.1\r\nHost: mail.example.net\r\n\r\n'
    for i, body in enumerate((
            tnef([attr(0x00089006, struct.pack('<I', 0x10000)), attr(0x00078008, b'IPM.Note\0')]),
            tnef([attr(0x00018004, b'plain subject'), attr(0x0004800d, struct.pack('<H', 3))], tail=b'12345'),
            tnef([attr(0x00069003, mapi(all_props()))]),
            tnef([]),                                                           # signature and key only
            tnef([attr(0x00060000, addr(b'', b''))]))):
        fr.append(f.seg(req))
        fr.append(f.seg(http(body), client=False))
    # the batch 37 reproducer: MV_STRING8 properties with non-NULL pointers, 4 of them in one message and many in another
    for n in (4, 40):
        props = [prop(MV | PT_STRING8, 0, struct.pack('<II', 1, 0x20000 + i)) for i in range(n)]
        fr.append(f.seg(req))
        fr.append(f.seg(http(tnef([attr(0x00069003, mapi(props))])), client=False))
    write(os.path.join(out, 'tnef-coverage-http.pcap'), fr)
    print('http frames', len(fr))

    m = []
    g = Flow(56001, 80)
    cases = [
        tnef([attr(0x00018004, b'x')], sig=0x11223344),                            # wrong signature (not a TNEF stream)
        tnef([attr(0x00069003, mapi([prop(PT_STRING8, 0x37, counted([b'one', b'two']))]))]),     # a single item expected, found two
        tnef([attr(0x00069003, mapi([prop(PT_BINARY, 0x37, counted([b'a', b'b', b'c']))]))]),
        tnef([attr(0x00069003, mapi([prop(PT_UNICODE, 0x37, counted([b'a\0', b'b\0']))]))]),
        tnef([attr(0x00018004, b'x')])[:-6],                                       # attribute cut short
        tnef([attr(0x00069003, mapi([prop(PT_LONG, 0x1, b'\0\0')]))]),             # property value cut short
        tnef([attr(0x00060000, b'\x10\x00ab')]),                                   # address longer than the data
        tnef([attr(0x00030006, b'\x01\x00\x02')]),                                 # short date
        tnef([attr(0x00069003, struct.pack('<I', 5) + struct.pack('<HH', PT_STRING8, 0x37) + struct.pack('<II', 1, 0xffffffff))]),
        struct.pack('<IH', SIG, 0) + struct.pack('<BII', 1, 0x00018004, 0xffffffff) + b'abcdef',   # attribute length beyond the data
        struct.pack('<IH', SIG, 0) + struct.pack('<BII', 1, 0x00069003, 3) + b'abcd',
        b'\x78\x9f\x3e\x22',                                                       # signature only
    ]
    for body in cases:
        m.append(g.seg(b'GET /x HTTP/1.1\r\nHost: m\r\n\r\n'))
        m.append(g.seg(http(body), client=False))
    write(os.path.join(out, 'tnef-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

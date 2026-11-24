#!/usr/bin/env python3
# Generates test/captures/scsi_osd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic iSCSI/SCSI captures for packet-scsi-osd.c (SCSI object based storage).

usage: mkosd.py <outdir>

Writes scsi-osd-coverage.pcap (clean) and scsi-osd-coverage-malformed.pcap.
The commands run over iSCSI (TCP port 3260) to an object storage device
(INQUIRY device type 0x11, LUN 0; LUN 1 is a second OSD).  OSD-1 commands use
a 200 byte CDB, OSD-2 ones a 236 byte CDB; both go into an iSCSI extended CDB AHS.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import random
import struct

from scsilib import Pcap  # noqa: E402

R = random.Random(1331)


def rnd(n):
    return bytes(R.randrange(256) for _ in range(n))


def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)
def u64(v): return struct.pack('>Q', v)


OSD1 = {'format': 0x8801, 'create': 0x8802, 'list': 0x8803, 'read': 0x8805, 'write': 0x8806,
        'append': 0x8807, 'flush': 0x8808, 'remove': 0x880a, 'create_partition': 0x880b,
        'remove_partition': 0x880c, 'get_attributes': 0x880e, 'set_attributes': 0x880f,
        'create_and_write': 0x8812, 'create_collection': 0x8815, 'remove_collection': 0x8816,
        'list_collection': 0x8817, 'set_key': 0x8818, 'flush_collection': 0x881a,
        'flush_partition': 0x881b, 'flush_osd': 0x881c}
OSD2 = {'create': 0x8882, 'list': 0x8883, 'read': 0x8885, 'write': 0x8886, 'append': 0x8887,
        'clear': 0x8889, 'remove': 0x888a, 'create_partition': 0x888b, 'remove_partition': 0x888c,
        'get_attributes': 0x888e, 'set_attributes': 0x888f, 'create_and_write': 0x8892,
        'copy_user_objects': 0x8893, 'create_user_tracking_collection': 0x8894,
        'remove_collection': 0x8896, 'list_collection': 0x8897, 'query': 0x88a0,
        'remove_member_objects': 0x88a1, 'get_member_attributes': 0x88a2,
        'set_member_attributes': 0x88a3}

# attribute parameters (28 bytes) start at CDB byte 52 in every command that has them
ATTR = 52
KNOWN = ((0x00000001, 0x82, 8), (0xfffffffe, 0x02, 1), (0xfffffffe, 0x03, 8), (0xfffffffe, 0x04, 8))


def cdb(sa, over=None, osd2=None):
    """OSD CDB: opcode 0x7f, additional CDB length, service action, random contents; `over`
    maps a CDB byte offset to the bytes to put there."""
    if osd2 is None:
        osd2 = bool(sa & 0x80) and sa >= 0x8880
    n = 236 if osd2 else 200
    b = bytearray(rnd(n))
    b[0] = 0x7f
    b[1] = 0
    b[2:7] = b'\x00' * 5
    b[7] = n - 8
    b[8:10] = u16(sa)
    b[10] = b[10] & 0x7f
    for k, v in (over or {}).items():
        b[k:k + len(v)] = v
    return bytes(b)


def attr_params(get_len=0, get_off=0xffffffff, get_alloc=0, ret_off=0xffffffff, set_len=0, set_off=0xffffffff):
    return u32(get_len) + u32(get_off) + u32(get_alloc) + u32(ret_off) + u32(set_len) + u32(set_off) + b'\x00' * 4


def list_osd1(typ, entries):
    """OSD-1 attribute list: type, reserved, 16 bit length, entries."""
    body = b''.join(entries)
    return bytes([typ, 0]) + u16(len(body)) + body


def list_osd2(typ, entries):
    body = b''.join(entries)
    return bytes([typ, 0, 0, 0]) + u32(len(body)) + body


def entry(osd2, page, number, value, typ=9, objid=None):
    e = b''
    if typ == 1:
        return u32(page) + u32(number)
    if typ == 0x0f:
        e += u64(objid or 0x10001)
    e += u32(page) + u32(number)
    if osd2:
        e += b'\x00' * 6
    e += u16(len(value)) + value
    if osd2 and len(value) & 7:
        e += b'\x00' * (8 - (len(value) & 7))
    return e


def root_list(osd2, ids):
    """LIST data in listing partitions: additional length, continuation id, list id, flags, ids."""
    body = b''.join(u64(i) for i in ids)
    flags = (0x01 << 2) if osd2 else 0x03
    d = u64(0) + u64(0xffffffff) + u32(99) + b'\x00' * 3 + bytes([flags]) + body
    return u64(len(d) - 8) + d[8:]


def decode_offset(raw, osd2):
    if not osd2:
        return ((raw & 0x0fffffff) << (raw >> 28)) << 8
    exp = raw >> 28
    if exp & 8:
        exp = -(((~exp) & 7) + 1)
    return (raw & 0x0fffffff) << (exp + 8)


def known_value(number):
    return {0x82: u64(0x1234), 0x02: bytes([0x80]), 0x03: u64(0x10000), 0x04: u64(0x10001)}[number]


def main(out):
    os.makedirs(out, exist_ok=True)
    main_cap(os.path.join(out, 'scsi-osd-coverage.pcap'))
    malformed_cap(os.path.join(out, 'scsi-osd-coverage-malformed.pcap'))


def osd_lists(osd2):
    """(data out list for set, data out list for get, data in list) with known attributes."""
    mk = list_osd2 if osd2 else list_osd1
    allk = [(pg, nb) for pg, nb, ln in KNOWN]
    setl = mk(9, [entry(osd2, pg, nb, known_value(nb)) for pg, nb in allk] + [entry(osd2, 0x30000001, 0x77, b'\x01\x02\x03')])
    getl = mk(1, [entry(osd2, pg, nb, b'', typ=1) for pg, nb in allk] + [entry(osd2, 0x30000001, 0x77, b'', typ=1)])
    retl = mk(9, [entry(osd2, pg, nb, known_value(nb)) for pg, nb in allk] + [entry(osd2, 0x30000001, 0x77, b'\x01\x02\x03')])
    return setl, getl, retl


def main_cap(path):
    p = Pcap(path)
    x = p.xchg
    mark = p.mark
    p.inquiry(0, 0x11)
    p.inquiry(1, 0x11)
    mark('sweep')
    for osd2, table in ((False, OSD1), (True, OSD2)):
        for name, sa in table.items():
            for variant in range(3):
                over = {11: bytes([R.choice((0x00, 0x10, 0x20, 0x30)) | (R.randrange(16) if name.startswith('list') else 0)]),
                        ATTR: attr_params(R.randrange(100), 0xffffffff, R.randrange(100), 0xffffffff, R.randrange(100), 0xffffffff)}
                x(cdb(sa, over, osd2), 0)
    mark('partitions')
    # partition life cycle: list, create, use, remove, create again, in OSD-1 and OSD-2 forms
    for osd2, table in ((False, OSD1), (True, OSD2)):
        pid = u64(0x10000 if not osd2 else 0x20000)
        listing = root_list(osd2, [0x10000 if not osd2 else 0x20000])
        list_over = {11: b'\x00', 16: pid, (32 if osd2 else 36): u64(len(listing)), ATTR: attr_params()}
        # the sequence of the reproducer of "SCSI-OSD: Do not update partition state on later passes":
        # LIST names the partition, REMOVE PARTITION removes it, CREATE PARTITION creates it again
        x(cdb(table['list'], list_over, osd2), 0, din=listing)
        for name in ('create_partition', 'read', 'remove_partition', 'create_partition', 'get_attributes'):
            x(cdb(table[name], {11: b'\x00', 16: pid}, osd2), 0)
        x(cdb(table['list'], list_over, osd2), 0, din=listing)
    mark('attrs')
    for osd2, table in ((False, OSD1), (True, OSD2)):
        setl, getl, retl = osd_lists(osd2)
        pad = b'\x00' * 256
        # SET ATTRIBUTES: the set list in the data out at offset 256 (raw offset value 1)
        for name in ('set_attributes', 'write', 'create', 'get_attributes', 'read'):
            sa = table[name]
            if name in ('set_attributes', 'write', 'create'):
                data = pad + setl
                over = {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, len(setl), 1)}
                x(cdb(sa, over, osd2), 0, dout=data)
            else:
                over = {11: bytes([0x30]), ATTR: attr_params(len(getl), 1, 512, 2, 0, 0xffffffff)}
                data_out = pad + getl
                itt = p.command(cdb(sa, over, osd2), 0, edtl=len(data_out), read=True, write=True,
                                data=data_out, bidir=1024)
                p.data_in(itt, b'\x00' * 512 + retl, status=0)
        # attribute page / single attribute set in the CDB
        for gs in (1, 2):
            x(cdb(table['set_attributes'], {11: bytes([gs << 4]), ATTR: rnd(28)}, osd2), 0)
            x(cdb(table['get_attributes'], {11: bytes([gs << 4]), ATTR: rnd(28)}, osd2), 0)
    mark('lists')
    # LIST and LIST COLLECTION, OSD-1: partitions / collections (root bit) and user objects
    for name, root in (('list', 1), ('list', 0), ('list_collection', 1), ('list_collection', 0)):
        ids = b''.join(u64(0x10000 + 7 * k) for k in range(5))
        d = u64(len(ids) + 24 - 8 + 8 - 8 + 8) + u64(0xffffffff) + u32(77) + b'\x00' * 3 + bytes([root | 0x02]) + ids
        d = u64(len(d) - 8) + d[8:]
        x(cdb(OSD1[name], {11: bytes([R.choice((0, 0x01, 0x02))]), 36: u64(256), 32: u32(5), 44: u64(0),
                           ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, 0, 0xffffffff)}, False), 0, din=d)
    # OSD-2 LIST / LIST COLLECTION: every object descriptor format, with attribute sub lists
    sub = b''
    attr_entries = b''.join(entry(True, pg, nb, known_value(nb)) for pg, nb, ln in KNOWN[:2])
    sublist = bytes([0x80]) + b'\x00' * 5 + u16(len(attr_entries)) + attr_entries
    for name, fmt in (('list', 0x01), ('list', 0x02), ('list', 0x21), ('list', 0x22),
                      ('list_collection', 0x11), ('list_collection', 0x12), ('list_collection', 0x22)):
        body = b''
        for k in range(3):
            body += u64(0x20000 + k)
            if fmt & 2:
                body += sublist
        d = u64(0) + u64(0xffffffff) + u32(78) + b'\x00' * 3 + bytes([fmt << 2]) + body
        d = u64(len(d) - 8) + d[8:]
        x(cdb(OSD2[name], {11: bytes([0x00]), 32: u64(len(d)), 40: u64(0), 48: u32(5),
                           ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, 0, 0xffffffff)}, True), 0, din=d)
    mark('query')
    # QUERY with a CDB continuation in the data out; descriptors of every type
    def descriptor(typ, payload, pad=0):
        body = payload + b'\x00' * pad
        return u16(typ) + b'\x00' + bytes([pad]) + u32(len(payload)) + body
    qentry = lambda pg, nb, lo, hi: b'\x00\x00' + u16(24 + len(lo) + len(hi)) + u32(pg) + u32(nb) + u16(len(lo)) + lo + u16(len(hi)) + hi  # noqa: E731
    qd = bytes([1, 0, 0, 0]) + qentry(1, 0x82, u64(10), u64(1000)) + qentry(0xfffffffe, 2, bytes([1]), bytes([5, 6, 7]))
    qd += b'\x00' * ((8 - len(qd) % 8) % 8)
    sa = OSD2['query']
    qd2 = bytes([0, 0, 0, 0]) + qentry(0x70000000, 5, b'\x01', b'\x02\x03\x04') + qentry(1, 0x82, b'abcd', b'abcd')
    descs = descriptor(0x0002, qd2) + descriptor(0x0002, qd) + descriptor(0x0001, rnd(16)) + descriptor(0x0100, rnd(8)) + \
        descriptor(0x0101, rnd(8)) + descriptor(0xffee, rnd(8)) + descriptor(0x0000, b'', 0) \
        + descriptor(0x0002, bytes([0, 0, 0, 0]) + qentry(1, 0x82, b'\x01', b'\x02\x03\x04') + b'')
    cont = bytes([1, 0]) + u16(sa) + b'\x00' * 36 + descs
    over = {11: bytes([0x00]), 32: u64(64), 48: u32(len(cont)),
            ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, 0, 0xffffffff)}
    d = u64(8 + 8 * 3 + 4 - 8 + 8) + b'\x00' * 3 + bytes([0x21 << 2]) + b''.join(u64(0x30000 + k) for k in range(3))
    d = u64(len(d) - 8) + d[8:]
    itt = p.command(cdb(sa, over, True), 0, edtl=len(cont), read=True, write=True, data=cont, bidir=len(d))
    p.data_in(itt, d, status=0)
    mark('offsets')
    # attribute list offsets with exponents (OSD-1 unsigned, OSD-2 signed)
    for osd2, table, raws in ((False, OSD1, (0x10000001, 0x20000001, 0xffffffff, 0x00000000)),
                              (True, OSD2, (0xf0000002, 0xe0000002, 0x10000001, 0xffffffff))):
        setl, getl, retl = osd_lists(osd2)
        for raw in raws:
            off = 0 if raw in (0, 0xffffffff) else decode_offset(raw, osd2)
            over = {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 64, raw, 0, 0xffffffff)}
            x(cdb(table['get_attributes' if osd2 else 'read'], over, osd2), 0, din=(b'\x00' * off + retl) if raw != 0xffffffff else rnd(64))
            over = {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, len(setl), raw)}
            x(cdb(table['set_attributes' if osd2 else 'write'], over, osd2), 0, dout=(b'\x00' * off + setl) if raw != 0xffffffff else rnd(32))
    mark('data')
    # list type 0x0f (attributes for CREATE), OSD-1: object id, page, number, length, value
    e = u64(0x10001) + u32(1) + u32(0x82) + u16(8) + u64(5) + u64(0x10002) + u32(0xfffffffe) + u32(3) + u16(8) + u64(0x10000)
    lst = bytes([0x0f, 0]) + u16(len(e)) + e
    x(cdb(OSD1['create'], {11: bytes([0x30]), ATTR: attr_params(len(lst), 1, 0, 0xffffffff, 0, 0xffffffff)}, False), 0,
      dout=b'\x00' * 256 + lst)
    # the ROOT partition id
    x(cdb(OSD1['read'], {11: b'\x00', 16: u64(0)}, False), 0)
    # attribute page (getset type 2) with data out and data in, and data of every command in both directions
    for osd2, table in ((False, OSD1), (True, OSD2)):
        for name, sa in table.items():
            if name in ('list', 'list_collection', 'query'):
                x(cdb(sa, {11: bytes([0x00]), 48: u32(0), ATTR: attr_params()}, osd2), 0, dout=rnd(24))
                continue
            over = {11: bytes([0x20]), 48: u32(0), ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, 0, 0xffffffff)}
            x(cdb(sa, over, osd2), 0, din=rnd(24))
            x(cdb(sa, {**over, 11: bytes([0x00])}, osd2), 0, dout=rnd(24))
            x(cdb(sa, over, osd2), 0, dout=rnd(24))          # attribute page type with data out
    mark('end')
    p.close()


def malformed_cap(path):
    p = Pcap(path)
    x = p.xchg
    p.inquiry(0, 0x11)
    # attribute with a length that is not the length of the attribute
    for osd2, table in ((False, OSD1), (True, OSD2)):
        mk = list_osd2 if osd2 else list_osd1
        bad = mk(9, [entry(osd2, 1, 0x82, b'\x00\x01')])
        x(cdb(table['set_attributes'], {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, len(bad), 1)}, osd2),
          0, dout=b'\x00' * 256 + bad)
        # unknown attribute list type
        bad = mk(0x55, [rnd(16)])
        x(cdb(table['set_attributes'], {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 0, 0xffffffff, len(bad), 1)}, osd2),
          0, dout=b'\x00' * 256 + bad)
        # invalid offset exponent
        x(cdb(table['get_attributes'], {11: bytes([0x30]), ATTR: attr_params(0, 0xffffffff, 64, 0x80000001, 0, 0xffffffff)}, osd2), 0, din=rnd(64))
        # unknown list format
        d = u64(8) + u64(0) + u32(0) + b'\x00' * 3 + bytes([0xfc if osd2 else 0x00]) + rnd(8)
        x(cdb(table['list'], {11: b'\x00', (32 if osd2 else 36): u64(len(d)), ATTR: attr_params()}, osd2), 0, din=d)
    # CDB continuation problems: length 20, wrong format, wrong service action, unknown descriptor
    # type, descriptor length that is not a multiple of eight
    sa = OSD2['query']
    def descriptor(typ, payload, pad=0):
        return u16(typ) + b'\x00' + bytes([pad]) + u32(len(payload)) + payload + b'\x00' * pad
    ok = bytes([1, 0]) + u16(sa) + b'\x00' * 36
    for cont, clen in ((ok, 20), (bytes([7, 0]) + u16(sa) + b'\x00' * 36, None),
                       (bytes([1, 0]) + u16(sa + 1) + b'\x00' * 36 + descriptor(0x0100, rnd(8)), None),
                       (ok + descriptor(0x1234, rnd(8)), None), (ok + descriptor(0x0100, rnd(5)), None)):
        over = {11: bytes([0x00]), 48: u32(clen if clen is not None else len(cont)),
                ATTR: attr_params()}
        x(cdb(sa, over, True), 0, dout=cont)
    # QUERY data in with an invalid format
    d = u64(8) + b'\x00' * 3 + bytes([0x7c]) + u64(1)
    x(cdb(sa, {11: b'\x00', 32: u64(len(d)), 48: u32(0), ATTR: attr_params()}, True), 0, din=d)
    # attribute lists whose offsets point into the data and an empty list
    p.close()


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

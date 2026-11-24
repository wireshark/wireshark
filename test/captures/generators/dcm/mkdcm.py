#!/usr/bin/env python3
# Generates test/captures/dcm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DICOM dissector
(packet-dcm.c).

DICOM upper layer PDUs run over TCP, port 104 by default, or on any port
found by the "dicom_tcp" heuristic when a stream starts with an
A-ASSOCIATE-RQ. Every packet is built from scratch with struct; no
captured traffic is used. The UIDs are the public UIDs from the DICOM
standard, and every name, date and instance UID is made up.

Usage: mkdcm.py <output directory>

Writes:
  dcm-coverage.pcap            association request/accept with every item
                               and sub-item type, reject, release and
                               abort with every source and reason, P-DATA
                               with command and data PDVs for every DIMSE
                               command and status class, every VR in
                               implicit and explicit little endian and
                               explicit big endian, defined and undefined
                               length sequences and items (nested), PDV
                               reassembly across PDUs and TCP segments,
                               several PDUs per segment, export objects,
                               a heuristic stream on port 11112 and the
                               reproducers of the fixed bugs
  dcm-coverage-malformed.pcap  invalid lengths, flags, contexts and
                               presentation context items, truncated
                               values and headers, PDUs cut short
"""

import os
import struct
import sys

# ---------------------------------------------------------------------------
# pcap / IPv4 / TCP
# ---------------------------------------------------------------------------

def ip2b(a):
    return bytes(int(x) for x in a.split('.'))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Capture:
    def __init__(self):
        self.frames = []

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


class Conn:
    """One TCP connection; seg() appends a data segment."""

    def __init__(self, cap, cli_port, srv_port=104, cli_ip='192.0.2.1', srv_ip='192.0.2.2'):
        self.cap = cap
        self.cli = (cli_ip, cli_port, b'\x02\x00\x00\x00\x00\x01')
        self.srv = (srv_ip, srv_port, b'\x02\x00\x00\x00\x00\x02')
        self.seq = {0: 1000, 1: 5000}

    def seg(self, from_cli, payload):
        s, d = (self.cli, self.srv) if from_cli else (self.srv, self.cli)
        k = 0 if from_cli else 1
        tcp = struct.pack('!HHIIBBHHH', s[1], d[1], self.seq[k], self.seq[1 - k],
                          0x50, 0x18, 65535, 0, 0) + payload
        self.seq[k] += len(payload)
        iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                          ip2b(s[0]), ip2b(d[0]))
        iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
        ph = ip2b(s[0]) + ip2b(d[0]) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        self.cap.frames.append(d[2] + s[2] + b'\x08\x00' + iph + tcp)
        return len(self.cap.frames)

    def c(self, payload):
        return self.seg(True, payload)

    def s(self, payload):
        return self.seg(False, payload)


# ---------------------------------------------------------------------------
# Upper layer PDUs
# ---------------------------------------------------------------------------

ILE_UID = b'1.2.840.10008.1.2'
ELE_UID = b'1.2.840.10008.1.2.1'
EBE_UID = b'1.2.840.10008.1.2.2'
APP_CTX = b'1.2.840.10008.3.1.1.1'

VERIFICATION = b'1.2.840.10008.1.1'
CT_STORAGE = b'1.2.840.10008.5.1.4.1.1.2'
MR_STORAGE = b'1.2.840.10008.5.1.4.1.1.4'
SC_STORAGE = b'1.2.840.10008.5.1.4.1.1.7'
US_STORAGE = b'1.2.840.10008.5.1.4.1.1.6.1'
PAT_FIND = b'1.2.840.10008.5.1.4.1.2.1.1'
PAT_MOVE = b'1.2.840.10008.5.1.4.1.2.1.2'
PAT_GET = b'1.2.840.10008.5.1.4.1.2.1.3'
STU_FIND = b'1.2.840.10008.5.1.4.1.2.2.1'
STU_MOVE = b'1.2.840.10008.5.1.4.1.2.2.2'
STU_GET = b'1.2.840.10008.5.1.4.1.2.2.3'
PSO_FIND = b'1.2.840.10008.5.1.4.1.2.3.1'
PSO_MOVE = b'1.2.840.10008.5.1.4.1.2.3.2'
PSO_GET = b'1.2.840.10008.5.1.4.1.2.3.3'
FILM_SESSION = b'1.2.840.10008.5.1.1.1'
STORAGE_COMMIT = b'1.2.840.10008.1.20.1'
JPEG_BASELINE = b'1.2.840.10008.1.2.4.50'
JPEG_LOSSLESS = b'1.2.840.10008.1.2.4.70'
DEFLATED = b'1.2.840.10008.1.2.1.99'
RLE = b'1.2.840.10008.1.2.5'
GE_PRIVATE = b'1.2.840.113619.5.2'


def item(t, data, length=None):
    return struct.pack('!BBH', t, 0, len(data) if length is None else length) + data


def ae(s):
    return s.ljust(16).encode()


def assoc_pdu(pdu_type, items, called='STORE-SCP', calling='SYNTH-SCU', version=1):
    body = struct.pack('!HH', version, 0) + ae(called) + ae(calling) + b'\0' * 32 + items
    return struct.pack('!BBI', pdu_type, 0, len(body)) + body


def pctx_rq(ctx, abss, xfers, extra=b''):
    body = struct.pack('!BBBB', ctx, 0, 0, 0) + item(0x30, abss)
    body += b''.join(item(0x40, x) for x in xfers) + extra
    return item(0x20, body)


def pctx_ac(ctx, result, xfer=ILE_UID, extra=b''):
    body = struct.pack('!BBBB', ctx, 0, result, 0)
    if xfer is not None:
        body += item(0x40, xfer)
    return item(0x21, body + extra)


def ui_maxlen(n):
    return item(0x51, struct.pack('!I', n))


def ui_rolesel(uid, scu, scp):
    return item(0x54, struct.pack('!H', len(uid)) + uid + bytes([scu, scp]))


def ui_extneg(uid, info):
    return item(0x56, struct.pack('!H', len(uid)) + uid + info)


def ui_async(inv, per):
    return item(0x53, struct.pack('!HH', inv, per))


def ui_identity(typ, resp, primary, secondary=None):
    body = struct.pack('!BBH', typ, resp, len(primary)) + primary
    if secondary is not None:
        body += struct.pack('!H', len(secondary)) + secondary
    return item(0x58, body)


def userinfo(*subitems):
    return item(0x50, b''.join(subitems))


def simple_rq(ctxs, called='STORE-SCP', calling='SYNTH-SCU'):
    """A-ASSOCIATE-RQ with an application context, the given presentation
    contexts [(id, abstract syntax, [transfer syntaxes])] and a max length."""
    items = item(0x10, APP_CTX)
    items += b''.join(pctx_rq(c, a, x) for c, a, x in ctxs)
    items += userinfo(ui_maxlen(16384))
    return assoc_pdu(1, items, called, calling)


def simple_ac(ctxs, called='STORE-SCP', calling='SYNTH-SCU'):
    """A-ASSOCIATE-AC accepting [(id, transfer syntax)]."""
    items = item(0x10, APP_CTX)
    items += b''.join(pctx_ac(c, 0, x) for c, x in ctxs)
    items += userinfo(ui_maxlen(16384))
    return assoc_pdu(2, items, called, calling)


def reject(result, source, reason):
    return struct.pack('!BBIBBBB', 3, 0, 4, 0, result, source, reason)


def release_rq():
    return struct.pack('!BBIHH', 5, 0, 4, 0, 0)


def release_rp():
    return struct.pack('!BBIHH', 6, 0, 4, 0, 0)


def abort(source, reason):
    return struct.pack('!BBIBBBB', 7, 0, 4, 0, 0, source, reason)


def pdv(ctx, flags, body):
    return struct.pack('!IBB', len(body) + 2, ctx, flags) + body


def pdata(*pdvs):
    b = b''.join(pdvs)
    return struct.pack('!BBI', 4, 0, len(b)) + b


CMD_MORE, CMD_LAST, DATA_MORE, DATA_LAST = 1, 3, 0, 2


# ---------------------------------------------------------------------------
# Data elements
# ---------------------------------------------------------------------------

ILE, ELE, EBE = 'ILE', 'ELE', 'EBE'
LONG_VR = (b'OB', b'OW', b'OF', b'OD', b'OL', b'SQ', b'UC', b'UR', b'UT', b'UN')
UNDEF = 0xFFFFFFFF


def end(sx):
    return '>' if sx == EBE else '<'


def pad(s, ch=b' '):
    if isinstance(s, str):
        s = s.encode()
    return s + ch if len(s) % 2 else s


def tag(sx, g, e, vr, val, vl=None):
    """One data element in the given transfer syntax."""
    E = end(sx)
    if vl is None:
        vl = len(val)
    if g == 0xFFFE or sx == ILE:
        return struct.pack(E + 'HHI', g, e, vl) + val
    if vr in LONG_VR:
        return struct.pack(E + 'HH2sHI', g, e, vr, 0, vl) + val
    return struct.pack(E + 'HH2sH', g, e, vr, vl) + val


def itag(g, e, val):
    """Implicit little endian element (command set)."""
    return struct.pack('<HHI', g, e, len(val)) + val


def us(sx, v):
    return struct.pack(end(sx) + 'H', v)


def item_d(sx, content):
    return tag(sx, 0xFFFE, 0xE000, None, content)


def item_u(sx, content):
    E = end(sx)
    return (struct.pack(E + 'HHI', 0xFFFE, 0xE000, UNDEF) + content +
            struct.pack(E + 'HHI', 0xFFFE, 0xE00D, 0))


def sq_d(sx, g, e, items):
    return tag(sx, g, e, b'SQ', items)


def sq_u(sx, g, e, items, vr=b'SQ'):
    E = end(sx)
    if sx == ILE:
        h = struct.pack('<HHI', g, e, UNDEF)
    else:
        h = struct.pack(E + 'HH2sHI', g, e, vr, 0, UNDEF)
    return h + items + struct.pack(E + 'HHI', 0xFFFE, 0xE0DD, 0)


def ds_vrs(sx, inst_uid, sop_class=CT_STORAGE, pixels=64):
    """One element of every VR the explicit syntaxes can carry."""
    E = end(sx)
    t = lambda g, e, vr, v: tag(sx, g, e, vr, v)
    d = b''
    d += t(0x0008, 0x0005, b'CS', pad('ISO_IR 100'))
    d += t(0x0008, 0x0012, b'DA', pad('20260101'))
    d += t(0x0008, 0x0013, b'TM', pad('120000.00'))
    d += t(0x0008, 0x0015, b'DT', pad('20260101120000.000000+0000'))
    d += t(0x0008, 0x0016, b'UI', pad(sop_class, b'\0'))
    d += t(0x0008, 0x0018, b'UI', pad(inst_uid, b'\0'))
    d += t(0x0008, 0x0050, b'SH', pad('ACC0001'))
    d += t(0x0008, 0x0054, b'AE', pad('ARCHIVE'))
    d += t(0x0008, 0x0060, b'CS', pad('CT'))
    d += t(0x0008, 0x0070, b'LO', pad('Synthetic Modality Works'))
    d += t(0x0008, 0x0081, b'ST', pad('1 Example Road, Nowhere'))
    d += t(0x0008, 0x0090, b'PN', pad('Doe^Jane'))
    d += t(0x0008, 0x0108, b'LT', pad('A long text value that is longer than fifty '
                                      'characters, so the summary is cut short'))
    d += t(0x0008, 0x0119, b'UC', pad('LONGCODEVALUE'))
    d += t(0x0008, 0x010E, b'UR', pad('http://example.com/codes'))
    d += t(0x0008, 0x030E, b'UT', pad('Unlimited text'))
    d += t(0x0008, 0x0309, b'UL', struct.pack(E + 'I', 7))
    d += t(0x0008, 0x2122, b'IS', pad('12'))
    d += t(0x0008, 0x2134, b'FD', struct.pack(E + 'd', 2.25))
    d += t(0x0010, 0x0010, b'PN', pad('Synthetic^Patient'))
    d += t(0x0010, 0x0020, b'LO', pad('PID-0001'))
    d += t(0x0010, 0x1010, b'AS', pad('042Y'))
    d += t(0x0010, 0x1020, b'DS', pad('1.75'))
    d += t(0x0010, 0x9431, b'FL', struct.pack(E + 'f', 1.5))
    d += t(0x0018, 0x6020, b'SL', struct.pack(E + 'i', -5))
    d += t(0x0018, 0x9219, b'SS', struct.pack(E + 'h', -3))
    d += t(0x0028, 0x0009, b'AT', struct.pack(E + 'HHHH', 0x0018, 0x1063, 0x0018, 0x1065))
    d += t(0x0028, 0x0010, b'US', us(sx, 8))
    d += t(0x0008, 0x041B, b'OB', b'\x01\x02\x03\x04')
    d += t(0x003A, 0x032E, b'OD', struct.pack(E + 'd', 0.5))
    d += t(0x0018, 0x1638, b'OF', struct.pack(E + 'ff', 0.5, 1.5))
    d += t(0x0066, 0x0040, b'OL', struct.pack(E + 'II', 1, 2))
    d += t(0x0028, 0x1201, b'OW', struct.pack(E + 'HHHH', 1, 2, 3, 4))
    d += t(0x0072, 0x006D, b'UN', b'TEXT')                 # UN, a string
    d += t(0x0072, 0x006D, b'UN', b'A\tB\r\n\0')           # UN, padded string
    d += t(0x0072, 0x006D, b'UN', b'\x01\x02\xff\x00')     # UN, binary
    d += t(0x0008, 0x0020, b'ZZ', b'\x01\x02')             # not a VR
    d += t(0x0008, 0x0080, b'LO', b'')                     # empty value
    d += t(0x7FE0, 0x0010, b'OB', bytes(range(256)) * (pixels // 256) + b'\x55' * (pixels % 256))
    return d


def ds_implicit_vrs(inst_uid, sop_class=CT_STORAGE):
    """Implicit VR little endian: the VR comes from the dictionary, which
    has multi-valued VRs, an empty VR, masked groups, private, retired and
    unknown tags."""
    t = lambda g, e, v: tag(ILE, g, e, None, v)
    d = b''
    d += t(0x0002, 0x0000, struct.pack('<I', 0))           # group length (known)
    d += t(0x0008, 0x0016, pad(sop_class, b'\0'))
    d += t(0x0008, 0x0018, pad(inst_uid, b'\0'))
    d += t(0x0008, 0x0202, b'\x01\x02')                    # retired, VR ""
    d += t(0x0008, 0x040C, struct.pack('<Q', 9))           # UV
    d += t(0x0008, 0x9999, b'unknown ')                    # not in the dictionary
    d += t(0x0009, 0x0000, struct.pack('<I', 0))           # private group length
    d += t(0x0009, 0x0010, b'SYNTH PRIVATE ')              # private, UN string
    d += t(0x0009, 0x1001, b'\x00\x01\x02\x03')            # private, UN binary
    d += t(0x000A, 0x0000, struct.pack('<I', 0))           # group length (masked)
    d += t(0x0014, 0x3050, b'\x00\x01')                    # OB or OW
    d += t(0x0018, 0x9810, struct.pack('<H', 3))           # US or SS
    d += t(0x0020, 0x3101, pad('SRC'))                     # (0020,31xx), retired
    d += t(0x0028, 0x0420, struct.pack('<H', 1))           # (0028,04x0) mask
    d += t(0x0028, 0x0812, struct.pack('<H', 2))           # (0028,08x2) mask
    d += t(0x0028, 0x3006, struct.pack('<HH', 1, 2))       # US or OW
    d += t(0x0066, 0x0040, struct.pack('<I', 1))           # OL
    d += t(0x0072, 0x0081, struct.pack('<Q', 1))           # OV
    d += t(0x0072, 0x0082, struct.pack('<q', -1))          # SV
    d += t(0x1000, 0x0012, struct.pack('<H', 1))           # group 1000 mask
    d += t(0x1010, 0x0004, struct.pack('<H', 1))           # group 1010 mask
    d += t(0x5002, 0x0005, struct.pack('<H', 1))           # repeating group 50xx
    d += t(0x6002, 0x0010, struct.pack('<H', 4))           # repeating group 60xx
    d += t(0x7F02, 0x0011, struct.pack('<H', 1))           # repeating group 7Fxx
    # Encapsulated pixel data: undefined length on an OB element, with an
    # empty basic offset table item
    d += sq_u(ILE, 0x7FE0, 0x0010, item_d(ILE, b''))
    return d


def ds_sequences(sx):
    """Defined and undefined length sequences and items, nested three
    deep, an empty sequence and an empty item."""
    t = lambda g, e, vr, v: tag(sx, g, e, vr, v)
    code = (t(0x0008, 0x0100, b'SH', pad('T-D1100')) +
            t(0x0008, 0x0102, b'SH', pad('SRT')) +
            t(0x0008, 0x0104, b'LO', pad('Thorax')))
    inner = sq_d(sx, 0x0040, 0xA730, item_d(sx, b'') + item_d(sx, code))
    middle = sq_u(sx, 0x0008, 0x2218, item_u(sx, code + inner))
    ref1 = (t(0x0008, 0x1150, b'UI', pad(CT_STORAGE, b'\0')) +
            t(0x0008, 0x1155, b'UI', pad('2.25.1001', b'\0')) + middle)
    ref2 = t(0x0008, 0x1155, b'UI', pad('2.25.1002', b'\0'))
    d = sq_d(sx, 0x0008, 0x1115, item_d(sx, ref1) + item_u(sx, ref2))
    d += t(0x0008, 0x0006, b'SQ', b'')                     # empty sequence
    d += sq_u(sx, 0x0008, 0x0051, item_u(sx, b''))         # empty undefined item
    d += sq_u(sx, 0x0040, 0x0275, item_d(sx, t(0x0032, 0x1060, b'LO', pad('Request'))) +
              item_u(sx, t(0x0032, 0x1060, b'LO', pad('Second'))))
    return d


# Command sets (always implicit little endian)

def cmd(field, msg_id=None, resp_id=None, status=None, sop_class=None,
        sop_inst=None, dataset=False, extra=b''):
    b = b''
    if sop_class is not None:
        b += itag(0x0000, 0x0002, pad(sop_class, b'\0'))
    b += itag(0x0000, 0x0100, struct.pack('<H', field))
    if msg_id is not None:
        b += itag(0x0000, 0x0110, struct.pack('<H', msg_id))
    if resp_id is not None:
        b += itag(0x0000, 0x0120, struct.pack('<H', resp_id))
    b += itag(0x0000, 0x0800, struct.pack('<H', 0x0000 if dataset else 0x0101))
    if status is not None:
        b += itag(0x0000, 0x0900, struct.pack('<H', status))
    if sop_inst is not None:
        b += itag(0x0000, 0x1000, pad(sop_inst, b'\0'))
    b += extra
    return itag(0x0000, 0x0000, struct.pack('<I', len(b))) + b


def subops(remaining, completed, failed, warning):
    return (itag(0x0000, 0x1020, struct.pack('<H', remaining)) +
            itag(0x0000, 0x1021, struct.pack('<H', completed)) +
            itag(0x0000, 0x1022, struct.pack('<H', failed)) +
            itag(0x0000, 0x1023, struct.pack('<H', warning)))


def split(b, *sizes):
    out = []
    for n in sizes:
        out.append(b[:n])
        b = b[n:]
    out.append(b)
    return out


# ---------------------------------------------------------------------------
# Main capture
# ---------------------------------------------------------------------------

def main_capture():
    cap = Capture()
    marks = {}

    # --- Stream 1: the main association, every item type --------------------
    c = Conn(cap, 50001)
    rq_items = item(0x10, APP_CTX)
    rq_items += pctx_rq(1, VERIFICATION, [ILE_UID])
    rq_items += pctx_rq(3, CT_STORAGE, [ELE_UID, ILE_UID, EBE_UID])
    rq_items += pctx_rq(5, MR_STORAGE, [EBE_UID])
    rq_items += pctx_rq(7, STU_FIND, [ILE_UID], extra=item(0x60, b'\x00\x01'))
    rq_items += pctx_rq(9, PAT_MOVE, [ILE_UID])
    rq_items += pctx_rq(11, STU_GET, [ELE_UID])
    rq_items += pctx_rq(13, SC_STORAGE, [GE_PRIVATE])
    rq_items += pctx_rq(15, b'1.2.826.0.1.3680043.2.9999.1', [JPEG_BASELINE])
    rq_items += pctx_rq(17, FILM_SESSION, [JPEG_LOSSLESS])
    rq_items += pctx_rq(19, STORAGE_COMMIT, [DEFLATED])
    rq_items += pctx_rq(21, US_STORAGE, [RLE])
    rq_items += pctx_rq(23, CT_STORAGE, [ILE_UID])
    rq_items += pctx_rq(25, SC_STORAGE, [ELE_UID])
    rq_items += pctx_rq(27, SC_STORAGE, [ELE_UID])
    rq_items += pctx_rq(29, SC_STORAGE, [ELE_UID])
    rq_items += pctx_rq(31, SC_STORAGE, [ELE_UID])
    rq_items += pctx_rq(33, SC_STORAGE, [ELE_UID])
    rq_items += pctx_rq(35, US_STORAGE, [VERIFICATION])
    rq_items += item(0x70, b'\x00\x00')                    # unknown item
    rq_items += userinfo(
        ui_maxlen(16384),
        item(0x52, b'1.2.826.0.1.3680043.2.9999.2'),
        item(0x55, b'SYNTH_SCU_1'),
        ui_async(0, 0),
        ui_rolesel(CT_STORAGE, 1, 0),
        ui_rolesel(b'1.2.826.0.1.3680043.2.9999.3', 0, 1),
        ui_extneg(STU_FIND, b'\x01\x01\x00\x01'),
        ui_extneg(PAT_FIND, b''),
        ui_extneg(PSO_FIND, b'\x01'),
        ui_extneg(PAT_FIND, b'\x01\x00'),
        ui_extneg(STU_FIND, b'\x01\x01\x01'),
        ui_extneg(PAT_MOVE, b'\x01'),
        ui_extneg(STU_MOVE, b''),
        ui_extneg(PSO_MOVE, b'\x00'),
        ui_extneg(PAT_GET, b'\x01'),
        ui_extneg(STU_GET, b'\x01'),
        ui_extneg(PSO_GET, b'\x01'),
        ui_extneg(CT_STORAGE, b'\x02\x00\x00\x00\x00\x00'),
        ui_extneg(b'1.2.826.0.1.3680043.2.9999.4', b'\x00\x00'),
        ui_identity(1, 0, b'synthuser'),
        ui_identity(2, 1, b'synthuser', b'not-a-password'),
        item(0x59, b'\x01\x02\x03\x04'))                   # unknown sub-item
    marks['rq'] = c.c(assoc_pdu(1, rq_items))
    ac_items = item(0x10, APP_CTX)
    ac_items += pctx_ac(1, 0, ILE_UID)
    ac_items += pctx_ac(3, 0, ELE_UID)
    ac_items += pctx_ac(5, 0, EBE_UID)
    ac_items += pctx_ac(7, 0, ILE_UID, extra=item(0x60, b'\x00\x01'))
    ac_items += pctx_ac(9, 0, ILE_UID)
    ac_items += pctx_ac(11, 0, ELE_UID)
    ac_items += pctx_ac(13, 0, GE_PRIVATE)
    ac_items += pctx_ac(15, 0, JPEG_BASELINE)
    ac_items += pctx_ac(17, 0, JPEG_LOSSLESS)
    ac_items += pctx_ac(19, 0, DEFLATED)
    ac_items += pctx_ac(21, 0, RLE)
    ac_items += pctx_ac(23, 0, ILE_UID)
    ac_items += pctx_ac(25, 1, ELE_UID)
    ac_items += pctx_ac(27, 2, ELE_UID)
    ac_items += pctx_ac(29, 3, None)
    ac_items += pctx_ac(31, 4, None)
    ac_items += pctx_ac(33, 5, None)
    ac_items += pctx_ac(35, 0, VERIFICATION)
    ac_items += userinfo(
        item(0x52, b'1.2.826.0.1.3680043.2.9999.5'),
        ui_maxlen(32768),
        item(0x55, b'SYNTH_SCP_1'),
        ui_async(5, 3),
        ui_rolesel(CT_STORAGE, 1, 1),
        ui_extneg(STU_FIND, b'\x01\x00\x01\x00'))
    marks['ac'] = c.s(assoc_pdu(2, ac_items))

    # C-ECHO on the verification context
    marks['echo'] = c.c(pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=1, sop_class=VERIFICATION))))
    c.s(pdata(pdv(1, CMD_LAST, cmd(0x8030, resp_id=1, status=0x0000, sop_class=VERIFICATION))))

    # C-STORE, explicit little endian, every VR, one PDU, export object
    inst_ele = '2.25.100001'
    marks['store_ele'] = c.c(pdata(
        pdv(3, CMD_LAST, cmd(0x0001, msg_id=2, sop_class=CT_STORAGE, sop_inst=inst_ele,
                             dataset=True, extra=itag(0x0000, 0x0700, struct.pack('<H', 0)))),
        pdv(3, DATA_LAST, ds_vrs(ELE, inst_ele) + ds_sequences(ELE))))
    # Warning status with an error comment and an offending element (AT VM 2)
    c.s(pdata(pdv(3, CMD_LAST, cmd(0x8001, resp_id=2, status=0xB000, sop_class=CT_STORAGE,
                                   sop_inst=inst_ele,
                                   extra=itag(0x0000, 0x0901, struct.pack('<HHHH', 0x0010, 0x0010, 0x0010, 0x0020)) +
                                   itag(0x0000, 0x0902, pad('Elements coerced'))))))

    # C-STORE, explicit big endian, data PDV in three fragments, each in its
    # own PDU and TCP segment; the pixel data makes the object > 4096 octets
    inst_ebe = '2.25.100002'
    data = ds_vrs(EBE, inst_ebe, MR_STORAGE, pixels=4096) + ds_sequences(EBE)
    f1, f2, f3 = split(data, 300, 1500)
    marks['store_ebe_1'] = c.c(pdata(
        pdv(5, CMD_LAST, cmd(0x0001, msg_id=3, sop_class=MR_STORAGE, sop_inst=inst_ebe, dataset=True)),
        pdv(5, DATA_MORE, f1)))
    c.c(pdata(pdv(5, DATA_MORE, f2)))
    marks['store_ebe_3'] = c.c(pdata(pdv(5, DATA_LAST, f3)))
    c.s(pdata(pdv(5, CMD_LAST, cmd(0x8001, resp_id=3, status=0x0000, sop_class=MR_STORAGE,
                                   sop_inst=inst_ebe))))

    # C-STORE, implicit little endian with the dictionary VRs
    inst_ile = '2.25.100003'
    marks['store_ile'] = c.c(pdata(
        pdv(23, CMD_LAST, cmd(0x0001, msg_id=4, sop_class=CT_STORAGE, sop_inst=inst_ile, dataset=True)),
        pdv(23, DATA_LAST, ds_implicit_vrs(inst_ile) + ds_sequences(ILE))))
    c.s(pdata(pdv(23, CMD_LAST, cmd(0x8001, resp_id=4, status=0x0001, sop_class=CT_STORAGE))))

    # C-FIND (implicit), pending responses with identifiers, then success
    ident = (tag(ILE, 0x0008, 0x0052, None, pad('STUDY')) +
             tag(ILE, 0x0010, 0x0010, None, pad('Synthetic*')) +
             sq_u(ILE, 0x0008, 0x1115, item_u(ILE, tag(ILE, 0x0008, 0x1155, None, b''))))
    marks['find'] = c.c(pdata(pdv(7, CMD_LAST, cmd(0x0020, msg_id=5, sop_class=STU_FIND, dataset=True)),
                              pdv(7, DATA_LAST, ident)))
    c.s(pdata(pdv(7, CMD_LAST, cmd(0x8020, resp_id=5, status=0xFF00, sop_class=STU_FIND, dataset=True)),
              pdv(7, DATA_LAST, ident)))
    c.s(pdata(pdv(7, CMD_LAST, cmd(0x8020, resp_id=5, status=0xFF01, sop_class=STU_FIND, dataset=True)),
              pdv(7, DATA_LAST, ident)))
    c.c(pdata(pdv(7, CMD_LAST, cmd(0x0FFF, resp_id=5))))
    c.s(pdata(pdv(7, CMD_LAST, cmd(0x8020, resp_id=5, status=0xFE00, sop_class=STU_FIND))))

    # C-MOVE with sub-operation counts
    marks['move'] = c.c(pdata(pdv(9, CMD_LAST, cmd(0x0021, msg_id=6, sop_class=PAT_MOVE, dataset=True,
                                                    extra=itag(0x0000, 0x0600, pad('ARCHIVE')))),
                              pdv(9, DATA_LAST, tag(ILE, 0x0008, 0x0052, None, pad('PATIENT')))))
    c.s(pdata(pdv(9, CMD_LAST, cmd(0x8021, resp_id=6, status=0xFF00, sop_class=PAT_MOVE,
                                   extra=subops(2, 1, 1, 1)))))
    c.s(pdata(pdv(9, CMD_LAST, cmd(0x8021, resp_id=6, status=0x0000, sop_class=PAT_MOVE,
                                   extra=subops(0, 5, 0, 0)))))
    c.s(pdata(pdv(9, CMD_LAST, cmd(0x8021, resp_id=6, status=0xA702, sop_class=PAT_MOVE,
                                   extra=subops(0, 0, 3, 0)))))

    # C-GET (explicit little endian identifier)
    marks['get'] = c.c(pdata(pdv(11, CMD_LAST, cmd(0x0010, msg_id=7, sop_class=STU_GET, dataset=True)),
                             pdv(11, DATA_LAST, tag(ELE, 0x0008, 0x0052, b'CS', pad('STUDY')) +
                                 ds_sequences(ELE))))
    c.s(pdata(pdv(11, CMD_LAST, cmd(0x8010, resp_id=7, status=0xA9AB, sop_class=STU_GET))))
    c.s(pdata(pdv(11, CMD_LAST, cmd(0x8010, resp_id=7, status=0xA7FF, sop_class=STU_GET))))

    # Non-storage data on a context with an unknown abstract syntax
    marks['unknown_abss'] = c.c(pdata(
        pdv(15, CMD_LAST, cmd(0x0130, msg_id=8, sop_class=b'1.2.826.0.1.3680043.2.9999.1', dataset=True,
                              extra=itag(0x0000, 0x1008, struct.pack('<H', 1)))),
        pdv(15, DATA_LAST, tag(ELE, 0x0008, 0x0070, b'LO', pad('Opaque')))))
    c.s(pdata(pdv(15, CMD_LAST, cmd(0x8130, resp_id=8, status=0xC123,
                                    extra=itag(0x0000, 0x0902, pad('Cannot do that'))))))

    # Normalized commands on the film session context; a command PDV in
    # two fragments, in two PDUs in one segment
    ncreate = cmd(0x0140, msg_id=9, sop_class=FILM_SESSION, dataset=True)
    n1, n2 = split(ncreate, 20)
    marks['ncmd_frag'] = c.c(pdata(pdv(17, CMD_MORE, n1)) + pdata(pdv(17, CMD_LAST, n2),
                             pdv(17, DATA_LAST, tag(ELE, 0x2000, 0x0010, b'IS', pad('1')))))
    c.s(pdata(pdv(17, CMD_LAST, cmd(0x8140, resp_id=9, status=0x0000, sop_class=FILM_SESSION,
                                    sop_inst='2.25.100009'))))
    for i, (rq, rsp, status, extra) in enumerate((
            (0x0110, 0x8110, 0x0107, itag(0x0000, 0x1005, struct.pack('<HH', 0x2000, 0x0010)) +
                                     itag(0x0000, 0x1001, pad('2.25.100009', b'\0'))),
            (0x0120, 0x8120, 0x0000, b''),
            (0x0150, 0x8150, 0xD001, b''),
            (0x0100, 0x8100, 0x0000, itag(0x0000, 0x1002, struct.pack('<H', 1))))):
        c.c(pdata(pdv(17, CMD_LAST, cmd(rq, msg_id=10 + i, sop_class=FILM_SESSION, extra=extra))))
        c.s(pdata(pdv(17, CMD_LAST, cmd(rsp, resp_id=10 + i, status=status, sop_class=FILM_SESSION))))
    # A response without message ID being responded to, and an unknown
    # command field
    c.s(pdata(pdv(17, CMD_LAST, cmd(0x8150, status=0x0000))))
    c.c(pdata(pdv(17, CMD_LAST, cmd(0x0777, msg_id=14))))

    # N-ACTION with a data set on the storage commitment (deflated) context
    c.c(pdata(pdv(19, CMD_LAST, cmd(0x0130, msg_id=15, sop_class=STORAGE_COMMIT, dataset=True,
                                    extra=itag(0x0000, 0x1008, struct.pack('<H', 1)))),
              pdv(19, DATA_LAST, tag(ELE, 0x0008, 0x1195, b'UI', pad('2.25.100015', b'\0')))))

    # C-STORE on the RLE context: one data PDV in eight fragments in eight
    # PDUs. Three PDUs in one segment, a PDU split over three segments (the
    # first with fewer than 6 octets), a PDU followed by the first 5 octets
    # of the next one, and two PDUs where the second starts in the segment
    # of the first one.
    inst_rle = '2.25.100016'
    data = ds_vrs(ELE, inst_rle, US_STORAGE, pixels=512)
    frags = split(data, 64, 64, 64, 64, 64, 64, 64)
    pdus = [pdata(pdv(21, CMD_LAST, cmd(0x0001, msg_id=16, sop_class=US_STORAGE,
                                        sop_inst=inst_rle, dataset=True)),
                  pdv(21, DATA_MORE, frags[0]))]
    pdus += [pdata(pdv(21, DATA_MORE, f)) for f in frags[1:-1]]
    pdus += [pdata(pdv(21, DATA_LAST, frags[-1]))]
    marks['rle_first'] = c.c(pdus[0] + pdus[1] + pdus[2])
    c.c(pdus[3][:4])
    c.c(pdus[3][4:30])
    c.c(pdus[3][30:])
    c.c(pdus[4] + pdus[5][:5])
    c.c(pdus[5][5:] + pdus[6][:20])
    marks['rle_last'] = c.c(pdus[6][20:] + pdus[7])
    c.s(pdata(pdv(21, CMD_LAST, cmd(0x8001, resp_id=16, status=0x0000, sop_class=US_STORAGE))))

    # Data on a context whose transfer syntax is not a transfer syntax
    # (decoded as explicit little endian)
    c.c(pdata(pdv(35, CMD_LAST, cmd(0x0001, msg_id=17, sop_class=US_STORAGE, sop_inst='2.25.100017',
                                    dataset=True)),
              pdv(35, DATA_LAST, tag(ELE, 0x0008, 0x0018, b'UI', pad('2.25.100017', b'\0')))))

    # Several PDUs in one segment, then release
    marks['multi'] = c.c(pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=18))) +
                         pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=19))) +
                         pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=20)), pdv(1, CMD_LAST, cmd(0x0030, msg_id=21))))
    c.s(pdata(pdv(1, CMD_LAST, cmd(0x8030, resp_id=18, status=0))) +
        pdata(pdv(1, CMD_LAST, cmd(0x8030, resp_id=19, status=0))))
    marks['release'] = c.c(release_rq())
    c.s(release_rp())
    marks['s1_end'] = len(cap.frames)

    # --- Stream 2: fragmented values and headers -----------------------------
    # The same object in PDV fragments that end inside a value, inside a
    # tag header at every position, and exactly at a tag boundary.
    # Reassembled by default; with dicom.pdv_reassemble:FALSE every
    # fragment is decoded on its own and the open tags are resumed.
    c = Conn(cap, 50002)
    marks['frag_rq'] = c.c(simple_rq([(1, CT_STORAGE, [ELE_UID]), (3, CT_STORAGE, [ILE_UID]),
                                      (5, MR_STORAGE, [EBE_UID])]))
    c.s(simple_ac([(1, ELE_UID), (3, ILE_UID), (5, EBE_UID)]))
    for ctx, sx, msg, abss in ((1, ELE, 30, CT_STORAGE), (5, EBE, 31, MR_STORAGE)):
        E = end(sx)
        inst = '2.25.1000%d' % msg
        h = tag(sx, 0x0008, 0x0016, b'UI', pad(abss, b'\0'))
        h += tag(sx, 0x0008, 0x0018, b'UI', pad(inst, b'\0'))
        long_val = tag(sx, 0x0008, 0x0108, b'LT', pad('x' * 120))
        cuts = [len(h) + 20, len(h) + 60]                  # inside a value, twice
        body = h + long_val
        # Headers cut after the group, the element, the VR, the VR of a
        # long VR, its reserved octets and the first half of its length
        for vr, val, pos in ((b'LO', pad('cut-after-group'), 2),
                             (b'LO', pad('cut-after-element'), 4),
                             (b'LO', pad('cut-after-vr'), 6),
                             (b'OB', pad('cut-after-long-vr'), 6),
                             (b'OB', pad('cut-after-reserved'), 8),
                             (b'OB', pad('cut-after-vl1'), 10)):
            cuts.append(len(body) + pos)
            body += tag(sx, 0x0008, 0x0070, vr, val)
        cuts.append(len(body))                             # at a tag boundary
        body += tag(sx, 0x0010, 0x0010, b'PN', pad('Frag^Ment'))
        prev = 0
        frags = []
        for cut in cuts:
            frags.append(body[prev:cut])
            prev = cut
        frags.append(body[prev:])
        out = [pdv(ctx, CMD_LAST, cmd(0x0001, msg_id=msg, sop_class=abss, sop_inst=inst,
                                      dataset=True))]
        out += [pdv(ctx, DATA_MORE, f) for f in frags[:-1]]
        out += [pdv(ctx, DATA_LAST, frags[-1])]
        n = c.c(pdata(*out[:4]))
        marks['frag_%s' % sx] = n
        c.c(pdata(*out[4:]))
        c.s(pdata(pdv(ctx, CMD_LAST, cmd(0x8001, resp_id=msg, status=0))))
    # Implicit: header cut after the group, the element and the first half
    # of the length, and a value over three fragments
    inst = '2.25.100032'
    body = tag(ILE, 0x0008, 0x0018, None, pad(inst, b'\0'))
    cuts = [len(body) + 2]
    body += tag(ILE, 0x0008, 0x0070, None, pad('cut-after-group'))
    cuts.append(len(body) + 4)
    body += tag(ILE, 0x0008, 0x0070, None, pad('cut-after-element'))
    cuts.append(len(body) + 6)
    body += tag(ILE, 0x0008, 0x0070, None, pad('cut-after-vl1'))
    cuts += [len(body) + 30, len(body) + 60]
    body += tag(ILE, 0x0008, 0x0108, None, pad('y' * 100))
    prev = 0
    frags = []
    for cut in cuts:
        frags.append(body[prev:cut])
        prev = cut
    frags.append(body[prev:])
    marks['frag_ILE'] = c.c(pdata(pdv(3, CMD_LAST, cmd(0x0001, msg_id=32, sop_class=CT_STORAGE,
                                                       sop_inst=inst, dataset=True)),
                                  *[pdv(3, DATA_MORE, f) for f in frags[:-1]],
                                  pdv(3, DATA_LAST, frags[-1])))
    c.s(pdata(pdv(3, CMD_LAST, cmd(0x8001, resp_id=32, status=0))))
    c.c(release_rq())
    c.s(release_rp())

    # --- Stream 3: blank AE titles, data without a command ------------------
    c = Conn(cap, 50003)
    marks['blank_rq'] = c.c(simple_rq([(1, CT_STORAGE, [ELE_UID])], called='', calling=''))
    c.s(simple_ac([(1, ELE_UID)], called='', calling=''))
    marks['blank_data'] = c.c(pdata(pdv(1, DATA_LAST, tag(ELE, 0x0010, 0x0010, b'PN', pad('No^Command')))))
    c.c(abort(0, 0))

    # --- Stream 4: found by the heuristic on port 11112 ---------------------
    c = Conn(cap, 50004, 11112, '192.0.2.3', '192.0.2.4')
    marks['heur_rq'] = c.c(simple_rq([(1, VERIFICATION, [ILE_UID])], called='HEUR-SCP'))
    c.s(simple_ac([(1, ILE_UID)], called='HEUR-SCP'))
    c.c(pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=1, sop_class=VERIFICATION))))
    c.s(pdata(pdv(1, CMD_LAST, cmd(0x8030, resp_id=1, status=0, sop_class=VERIFICATION))))
    c.c(release_rq())
    marks['heur_end'] = c.s(release_rp())

    # --- Streams 5-14: rejects -----------------------------------------------
    marks['reject_first'] = len(cap.frames) + 2
    for i, (res, src, rsn) in enumerate(((1, 1, 1), (2, 1, 2), (1, 1, 3), (1, 1, 7), (1, 1, 5),
                                         (1, 2, 1), (2, 2, 2), (1, 3, 1), (2, 3, 2), (3, 4, 0))):
        c = Conn(cap, 50010 + i)
        c.c(simple_rq([(1, VERIFICATION, [ILE_UID])], called='REJ-SCP'))
        c.s(reject(res, src, rsn))

    # --- Streams 15-23: aborts -----------------------------------------------
    marks['abort_first'] = len(cap.frames) + 3
    for i, (src, rsn) in enumerate(((0, 0), (1, 0), (2, 0), (2, 1), (2, 2), (2, 3), (2, 4),
                                    (2, 5), (2, 6))):
        c = Conn(cap, 50030 + i)
        c.c(simple_rq([(1, VERIFICATION, [ILE_UID])], called='ABRT-SCP'))
        c.s(simple_ac([(1, ILE_UID)], called='ABRT-SCP'))
        if src == 0:
            c.c(abort(src, rsn))
        else:
            c.s(abort(src, rsn))

    # --- Reproducers of the fixed bugs (dcm_*.py) ----------------
    marks['repro_first'] = len(cap.frames) + 1
    rep = repro_frames(cap)
    marks.update(rep)
    return cap, marks


def repro_rq_ac(c):
    c.c(simple_rq([(1, CT_STORAGE, [ELE_UID])], called='CALLED', calling='CALLING'))
    c.s(simple_ac([(1, ELE_UID)], called='CALLED', calling='CALLING'))


def repro_frames(cap):
    m = {}
    d1 = tag(ELE, 0x0008, 0x0016, b'UI', CT_STORAGE + b'\0') + tag(ELE, 0x0008, 0x0018, b'UI', b'1.2.3.4\0')
    d2 = tag(ELE, 0x7FE0, 0x0010, b'OB', b'\x55' * 64)

    # dcm_reasm_offset: PDU [fragment, last fragment, C-ECHO-RQ]; then a
    # fragment, and the last fragment and a C-ECHO-RQ PDU in one segment
    c = Conn(cap, 50060)
    repro_rq_ac(c)
    echo = pdv(1, CMD_LAST, itag(0x0000, 0x0100, struct.pack('<H', 0x0030)) +
               itag(0x0000, 0x0110, struct.pack('<H', 5)))
    m['reasm_1'] = c.c(pdata(pdv(1, DATA_MORE, d1), pdv(1, DATA_LAST, d2), echo))
    c.c(pdata(pdv(1, DATA_MORE, d1)))
    echo2 = pdv(1, CMD_LAST, itag(0x0000, 0x0100, struct.pack('<H', 0x0030)) +
                itag(0x0000, 0x0110, struct.pack('<H', 6)) + itag(0x0000, 0x0902, b'X' * 60))
    m['reasm_2'] = c.c(pdata(pdv(1, DATA_LAST, d2)) + pdata(echo2))

    # dcm_export_uid: C-STORE whose SOP Class UID is a known UID
    c = Conn(cap, 50061)
    repro_rq_ac(c)
    cm = itag(0x0000, 0x0100, struct.pack('<H', 0x0001)) + itag(0x0000, 0x0110, struct.pack('<H', 1))
    m['export_uid'] = c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_MORE, d1), pdv(1, DATA_LAST, d2)))

    # dcm_hdrfrag_2pass: undefined length sequence in a command PDV that
    # ends with a 2 octet tag header
    c = Conn(cap, 50062)
    repro_rq_ac(c)
    cm = itag(0x0000, 0x0100, struct.pack('<H', 0x0030))
    cm += struct.pack('<HHI', 0x0000, 0x1000, UNDEF)
    cm += struct.pack('<HHI', 0xFFFE, 0xE000, UNDEF)
    cm += itag(0x0000, 0x0110, struct.pack('<H', 7))
    cm += struct.pack('<HHI', 0xFFFE, 0xE00D, 0)
    cm += struct.pack('<HHI', 0xFFFE, 0xE0DD, 0)
    cm += struct.pack('<H', 0x0000)
    m['hdrfrag'] = c.c(pdata(pdv(1, CMD_LAST, cm)))

    # dcm_pdu_offset: A-RELEASE-RQ + A-ASSOCIATE-RQ in one segment, then
    # A-RELEASE-RQ + the first 8 octets of a P-DATA, and the rest
    c = Conn(cap, 50063)
    m['pdu_offset_1'] = c.c(release_rq() + simple_rq([(1, CT_STORAGE, [ELE_UID])], called='CALLED',
                                                     calling='CALLING'))
    c.s(simple_ac([(1, ELE_UID)], called='CALLED', calling='CALLING'))
    cm = itag(0x0000, 0x0100, struct.pack('<H', 0x0030)) + itag(0x0000, 0x0110, struct.pack('<H', 9))
    pd = pdata(pdv(1, CMD_LAST, cm))
    m['pdu_offset_2'] = c.c(release_rq() + pd[:8])
    m['pdu_offset_3'] = c.c(pd[8:])

    # dcm_null_vr: command PDV ending in 6 octets of a tag header, then an
    # explicit data PDV
    c = Conn(cap, 50064)
    repro_rq_ac(c)
    cm = itag(0x0000, 0x0100, struct.pack('<H', 0x0001))
    cm += struct.pack('<HHH', 0x0008, 0x0016, 0x0004)
    m['null_vr'] = c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST, b'\x00\x00ABCD')))
    return m


# ---------------------------------------------------------------------------
# Malformed capture
# ---------------------------------------------------------------------------

def malformed_capture():
    cap = Capture()
    port = [51000]

    def conn(srv_port=104, **kw):
        port[0] += 1
        return Conn(cap, port[0], srv_port, **kw)

    def assoc(c, ctxs=((1, CT_STORAGE, ELE_UID),)):
        c.c(simple_rq([(i, a, [x]) for i, a, x in ctxs]))
        c.s(simple_ac([(i, x) for i, a, x in ctxs]))

    cm = cmd(0x0030, msg_id=1)

    # dcm_pdv_len_overrun: a PDV running into the next PDU
    c = conn()
    assoc(c)
    p1 = pdv(1, CMD_LAST, itag(0x0000, 0x0100, struct.pack('<H', 0x0030)) +
             itag(0x0000, 0x0110, struct.pack('<H', 1)))
    bad = struct.pack('!IBB', 24, 1, 0x03) + itag(0x0000, 0x0110, struct.pack('<H', 2))
    body = p1 + bad
    pd2 = pdata(pdv(1, CMD_LAST, itag(0x0000, 0x0100, struct.pack('<H', 0x8030)) +
                    itag(0x0000, 0x0120, struct.pack('<H', 1))))
    c.c(struct.pack('!BBI', 4, 0, len(body)) + body + pd2)

    # PDV lengths: too small, odd
    c.c(pdata(struct.pack('!IBB', 2, 1, 3)))
    c.c(pdata(struct.pack('!IBBB', 3, 1, 3, 0) + b'\0'))
    # Invalid flags, unknown context (unparsed data)
    c.c(pdata(pdv(1, 0x07, cm)))
    c.c(pdata(pdv(1, 0x05, cm[:20]), pdv(1, 0x04, cm[20:28]), pdv(1, 0x06, cm[28:])))
    c.c(pdata(pdv(9, CMD_LAST, cm), pdv(9, DATA_LAST, b'\x08\x00\x18\x00\x00\x00')))
    # A context accepted with a transfer syntax that is not in the dictionary
    c2 = conn()
    assoc(c2, ((1, CT_STORAGE, GE_PRIVATE),))
    c2.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST, b'\x08\x00\x18\x00\x00\x00')))

    # Value longer than the last PDV; value cut in a last fragment; header
    # cut in a last fragment; AT with 2 octets; UV with its standard
    # 4 octet length (the dissector reads 2)
    c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST, tag(ELE, 0x0008, 0x0070, b'LO', b'abcd', vl=64))))
    v = tag(ELE, 0x0008, 0x0070, b'LO', pad('z' * 40))
    c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_MORE, v[:20]), pdv(1, DATA_LAST, v[20:30])))
    c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST, tag(ELE, 0x0008, 0x0018, b'UI', pad('1.2.3', b'\0')) +
                                         b'\x08\x00\x70\x00')))
    c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST, tag(ELE, 0x0028, 0x0009, b'AT', b'\x18\x00') +
                                         tag(ELE, 0x0008, 0x0070, b'LO', pad('after')))))
    c.c(pdata(pdv(1, CMD_LAST, cm), pdv(1, DATA_LAST,
                                         struct.pack('<HH2sHI', 0x0008, 0x040C, b'UV', 0, 8) +
                                         struct.pack('<Q', 9))))

    # A-ASSOCIATE items: item length 0, presentation context without an
    # abstract syntax, with two, without a transfer syntax, accept with two
    # transfer syntaxes
    c = conn()
    c.c(assoc_pdu(1, item(0x10, APP_CTX) + item(0x20, b'\x01\x00\x00\x00', 0)))
    c = conn()
    c.c(assoc_pdu(1, item(0x10, APP_CTX) +
                  item(0x20, b'\x01\x00\x00\x00' + item(0x40, ILE_UID)) +
                  item(0x20, b'\x03\x00\x00\x00' + item(0x30, CT_STORAGE) + item(0x30, MR_STORAGE) +
                       item(0x40, ILE_UID)) +
                  item(0x20, b'\x05\x00\x00\x00' + item(0x30, CT_STORAGE))))
    c.s(assoc_pdu(2, item(0x10, APP_CTX) +
                  item(0x21, b'\x05\x00\x00\x00' + item(0x40, ILE_UID) + item(0x40, ELE_UID))))

    # Port 104: PDU type 0 and 8, PDU length below 4, a PDU length that
    # wraps, a PDU cut short by the end of the capture
    for payload in (b'\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00',
                    b'\x08\x00\x00\x00\x00\x04\x00\x00\x00\x00',
                    b'\x05\x00\x00\x00\x00\x02\x00\x00'):
        conn().c(payload)
    c = conn()
    assoc(c)
    c.c(struct.pack('!BBI', 4, 0, 0xFFFFFFFA) + b'\0' * 8)
    # A PDU followed by exactly the 6 octet header of the next one
    c = conn()
    assoc(c)
    nxt = pdata(pdv(1, CMD_LAST, cmd(0x0030, msg_id=2)))
    c.c(pdata(pdv(1, CMD_LAST, cm)) + nxt[:6])
    c.c(nxt[6:])
    # A-ASSOCIATE-RQ items that run past the end of the PDU
    c = conn()
    c.c(assoc_pdu(1, item(0x10, APP_CTX) + item(0x50, ui_maxlen(1), 40)))
    c = conn()
    c.c(assoc_pdu(1, item(0x10, APP_CTX) + userinfo(item(0x54, b'\x00\x40ab'), item(0x58, b'\x02\x00\x00\x40'),
                                                    item(0x56, b'\x00\x40ab'))))

    # Heuristic: other ports, payloads too short, not version 1, payload
    # longer than the PDU, not an A-ASSOCIATE-RQ
    for payload in (b'\x01\x00\x00\x00\x00\x04\x00', b'\x01\x00\x00\x00\x00\x04\x00\x01',
                    b'\x01\x00\x00\x00\x00\x04\x00\x02\x00\x00',
                    b'\x01\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00\x00',
                    b'\x04\x00\x00\x00\x00\x04\x00\x01\x00\x00'):
        conn(11112, cli_ip='192.0.2.5', srv_ip='192.0.2.6').c(payload)
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap, marks = main_capture()
    cap.write(os.path.join(out, 'dcm-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'dcm-coverage-malformed.pcap'))
    for k, v in sorted(marks.items(), key=lambda kv: kv[1]):
        print('%-16s %d' % (k, v))


if __name__ == '__main__':
    main()

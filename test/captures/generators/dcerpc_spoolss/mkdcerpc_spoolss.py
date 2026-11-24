#!/usr/bin/env python3
# Generates test/captures/dcerpc_spoolss_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the SPOOLSS DCE/RPC dissector
(packet-dcerpc-spoolss.c, Print System Remote Protocol, hand-written).

Connection-oriented DCE/RPC over TCP: a client (192.0.2.50) binds to the
SPOOLSS interface (12345678-1234-abcd-ef00-0123456789ab version 1.0) on
port 49155 of a server (192.0.2.60) and sends requests for every opnum
the dissector knows; the server answers each. The DCE/RPC heuristic on
TCP finds the PDUs, so no Decode As is needed. Every packet is built from
scratch with struct (rpcgen.py); no captured traffic is used. The stubs
follow what the dissector reads, which for the relative-offset buffers
(PRINTER_INFO, JOB_INFO, DRIVER_INFO, FORM) is the MS-RPRN layout: fixed
structures first, then the strings, devmodes and security descriptors.

The reproducers of "SPOOLSS: Do not loop on key buffers or job levels,
convert each string once" (spoolss_*.py in the review) are rebuilt here
unchanged, byte for byte: the ones that decode cleanly with the fix are
in the main capture, spoolss_keybuffer_loop (a key buffer size larger
than the data) in the malformed one.

Usage: mkdcerpc_spoolss.py <output directory>

Writes:
  dcerpc_spoolss-coverage.pcap            every opnum and info level, NDR
                                          little endian, big endian and
                                          NDR64, and the clean reproducers
  dcerpc_spoolss-coverage-malformed.pcap  sizes and offsets beyond the data
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from rpcgen import TCP, RPC, pcap  # noqa: E402

UUID_SPOOLSS = '12345678-1234-abcd-ef00-0123456789ab'
VER = (1, 0)


def u16(*v):
    return struct.pack('<%dH' % len(v), *v)


def u32(*v):
    return struct.pack('<%dI' % len(v), *v)


def u64(v):
    return struct.pack('<Q', v)


def w(s):
    return s.encode('utf-16-le')


def wz(s):
    return w(s) + b'\0\0'


def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def hnd(n):
    """policy handle: attributes 0 and a 16 octet UUID"""
    return u32(0) + bytes([0x50, 0x52, 0x4e, 0x54]) + struct.pack('<I', n) + bytes(range(1, 9))


HND_SERVER = hnd(1)
HND_PRINTER = hnd(2)
HND_PRINTER2 = hnd(3)
HND_NOTIFY = hnd(4)
HND_ADDED = hnd(5)
HND_FAILED = hnd(6)
HND_JOB = hnd(7)

ERR_OK = 0
ERR_ACCESS_DENIED = 5
ERR_INVALID_HANDLE = 6
ERR_INSUFFICIENT_BUFFER = 122
ERR_MORE_DATA = 234
ERR_NO_MORE_ITEMS = 259
ERR_INVALID_PRINTER_NAME = 1801
ERR_UNKNOWN_PRINTER_DRIVER = 1797
ERR_NOT_SUPPORTED = 50

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 0, 1, 2, 3, 4
REG_MULTI_SZ, REG_QWORD = 7, 11


class Conn(TCP):
    """TCP connection that splits long payloads into 1460 octet segments"""
    MSS = 1460

    def send(self, from_client, payload):
        for i in range(0, len(payload), self.MSS):
            self.seg(from_client, payload[i:i + self.MSS])


class Spoolss(RPC):
    def __init__(self, frames, port, le=True, ndr64=False):
        self.conn = Conn(frames, port)
        super().__init__(self.conn, UUID_SPOOLSS, VER, le, ndr64)
        self.bind()

    def request(self, opnum, req, obj=None):
        self.call_id += 1
        body = struct.pack(self.e + 'IHH', len(req), 0, opnum)
        self.conn.send(True, self.pdu(0, body + req, self.call_id))

    def response(self, resp):
        body = struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp
        self.conn.send(False, self.pdu(2, body, self.call_id))


# --------------------------------------------------------------- NDR bits
def wstr(s):
    """conformant varying UTF-16 string with its NUL, padded to 4"""
    n = len(s) + 1
    return pad4(u32(n, 0, n) + wz(s))


def wstrn(s):
    """the same without padding, as the last item of a stub"""
    n = len(s) + 1
    return u32(n, 0, n) + wz(s)


def uptr(data, ref=0x00020000):
    """unique pointer followed by its referent (top level)"""
    if data is None:
        return u32(0)
    return u32(ref) + data


def ustr(s, ref=0x00020000):
    return uptr(None if s is None else wstr(s), ref)


def buffer_ptr(data, ref=0x00020004):
    """unique pointer to a spoolss BUFFER: size and octets"""
    if data is None:
        return u32(0)
    return pad4(u32(ref, len(data)) + data)


def systime(y, mo, dow, d, h, mi, s, ms):
    return struct.pack('<8H', y, mo, dow, d, h, mi, s, ms)


def nttime(v):
    return u32(v & 0xffffffff, v >> 32)


# ----------------------------------------------------- security descriptor
def sid(auth, *subs):
    return bytes([1, len(subs)]) + struct.pack('>Q', auth)[2:] + u32(*subs)


SID_ADMINS = sid(5, 32, 544)
SID_SYSTEM = sid(5, 18)
SID_EVERYONE = sid(1, 0)
SID_USER = sid(5, 21, 1001, 2002, 3003, 1104)


def ace(atype, flags, mask, s):
    body = u32(mask) + s
    return struct.pack('<BBH', atype, flags, 4 + len(body)) + body


def acl(aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body


def secdesc(mask=0x000f000c):
    """self-relative security descriptor: owner, group, DACL"""
    owner, group = SID_ADMINS, SID_SYSTEM
    dacl = acl([ace(0, 0x03, mask, SID_EVERYONE), ace(0, 0, 0x000f001c, SID_ADMINS),
                ace(1, 0, 0x00000008, SID_USER)])
    o = 20
    g = o + len(owner)
    d = g + len(group)
    return struct.pack('<BBHIIII', 1, 0, 0x8004, o, g, 0, d) + owner + group + dacl


# ----------------------------------------------------------------- DEVMODE
def devmode(name='Office Laser', quality=600, extra=b'', form='A4', paper=9,
            orient=1, source=7, color=2, duplex=1, tt=3, collate=1, dither=10,
            icmm=2, icmi=3, media=1, dflags=0, fields=0x1fffff7f, spec=0x0401):
    """DEVMODE as dissect_DEVMODE() reads it: a size, the 32 wchar device
    name, the counts, the field mask, the print settings, the 32 wchar
    form name, the display settings and the driver extra data"""
    b = (w(name) + b'\0' * 64)[:64]
    b += u16(spec, 0x0600, 220, len(extra))
    b += u32(fields)
    b += struct.pack('<HHHHHHHh', orient, paper, 2970, 2100, 100, 2, source, quality)
    b += u16(color, duplex, 600, tt, collate)
    b += (w(form) + b'\0' * 64)[:64]
    b += u16(96)
    b += u32(32, 2480, 3508, dflags, 60, icmm, icmi, media, dither, 0, 0, 0, 0)
    b += extra
    return u32(len(b)) + b


# ------------------------------------------- relative-offset buffer layout
class Rel:
    """A spoolss buffer: fixed structures, then a heap with the strings,
    devmodes and security descriptors they point to. Items:
      ('u32', v) ('u16', v) ('raw', bytes)
      ('rel', text)            relative offset to a string (None: 0)
      ('blob', bytes, align, add, absolute)
                               offset of a heap object plus add, relative
                               to the structure or to the buffer start
    """
    @staticmethod
    def size(items):
        n = 0
        for it in items:
            k = it[0]
            n += {'u32': 4, 'u16': 2, 'rel': 4, 'blob': 4}.get(k, 0)
            if k == 'raw':
                n += len(it[1])
        return n

    @staticmethod
    def build(structs, tail=b''):
        starts, pos = [], 0
        for st in structs:
            starts.append(pos)
            pos += Rel.size(st)
        heap_base = pos
        out, heap = bytearray(), bytearray()
        for st, start in zip(structs, starts):
            for it in st:
                k = it[0]
                if k == 'u32':
                    out += u32(it[1])
                elif k == 'u16':
                    out += u16(it[1])
                elif k == 'raw':
                    out += it[1]
                elif k == 'rel':
                    if it[1] is None:
                        out += u32(0)
                    else:
                        heap += b'\0' * ((-(heap_base + len(heap))) % 2)
                        off = heap_base + len(heap)
                        heap += wz(it[1])
                        out += u32(off - start)
                elif k == 'blob':
                    data, align, add, absolute = it[1:]
                    heap += b'\0' * ((-(heap_base + len(heap))) % align)
                    off = heap_base + len(heap)
                    heap += data
                    out += u32(off + add - (0 if absolute else start))
        return bytes(out + heap) + tail


def T(v):
    return ('u32', v)


def S(text):
    return ('rel', text)


# ---------------------------------------------------------- printer infos
def printer_info_0():
    return [S('\\\\PRINTSRV\\Office Laser'), S('\\\\PRINTSRV'), T(2), T(345), T(1234567),
            ('raw', systime(2024, 5, 5, 3, 7, 12, 34, 567)), T(17), T(4096),
            ('u16', 6), ('u16', 9200), T(7), T(8), T(9), T(10), T(11), T(0), T(13),
            T(14), T(15), T(16), T(0x55aa), T(18), T(0x00000400), T(20), T(21),
            ('u16', 22), ('u16', 23), ('u16', 24), ('u16', 25), ('u16', 26),
            ('u16', 27), ('u16', 28), ('u16', 29)]


def printer_info_1(name='Office Laser'):
    return [T(0x00800000), S('\\\\PRINTSRV\\%s,HP LaserJet 4,Room 101' % name),
            S('\\\\PRINTSRV\\' + name), S('Second floor, next to the kitchen')]


def printer_info_2(quality=600, comment='Colour laser for the office'):
    return [S('\\\\PRINTSRV'), S('\\\\PRINTSRV\\Office Laser'), S('OfficeLaser'),
            S('IP_192.0.2.80'), S('HP LaserJet 4'), S(comment), S('Room 101'),
            ('blob', devmode(quality=quality, extra=b'\x11\x22\x33\x44'), 4, 4, True),
            S('C:\\Windows\\system32\\sysprint.sep'), S('winprint'), S('RAW'), S(None),
            ('blob', secdesc(), 4, 0, True),
            T(0x00003fff), T(1), T(1), T(0), T(1439), T(0x00000400), T(4), T(12)]


def printer_info_3():
    return [T(0x00000004), ('raw', secdesc())]


def printer_info_5():
    return [S('\\\\PRINTSRV\\Office Laser'), S('IP_192.0.2.80;LPT1:'), T(0x00000a48),
            T(15000), T(45000)]


def printer_info_7():
    return [S('{4c9b3c19-2c5a-4b8e-9a1f-0123456789ab}'), T(1)]


PRINTER_INFOS = {0: printer_info_0, 1: printer_info_1, 2: printer_info_2,
                 3: printer_info_3, 5: printer_info_5, 7: printer_info_7}


# -------------------------------------------------------------- job infos
def job_info_1(jobid, doc, status=0x00000018, user='alice'):
    return [T(jobid), S('Office Laser'), S('\\\\PRINTSRV'), S(user), S(doc), S('RAW'),
            S(None), T(status), T(1), T(jobid - 40), T(3), T(1),
            ('raw', systime(2024, 5, 5, 3, 7, 12, 34, 567))]


def job_info_2(jobid, doc, status=0x000007ff, quality=-3):
    return [T(jobid), S('Office Laser'), S('\\\\WS042'), S('bob'), S(doc), S('bob'),
            S('NT EMF 1.008'), S('winprint'), S(''), S('HP LaserJet 4'),
            ('blob', devmode(name='Office Laser', quality=quality, dither=0, icmm=4,
                             icmi=4, media=3, dflags=2, tt=0, collate=0, color=1,
                             duplex=3, source=13), 4, 4, False),
            S('Printing'),
            ('blob', secdesc(0x00000010), 4, 0, True),
            T(status), T(1), T(2), T(0), T(0), T(12), T(482133),
            ('raw', systime(2024, 5, 5, 3, 7, 13, 0, 1)), T(2500), T(5)]


def job_info_3(jobid, nextid):
    return [T(jobid), T(nextid), T(0)]


# ----------------------------------------------------------- driver infos
ENV = 'Windows x64'
DPATH = 'C:\\Windows\\System32\\spool\\DRIVERS\\x64\\3\\'


def driver_info_1(name):
    return [S(name)]


def driver_info_2(name, cv=3):
    return [T(cv), S(name), S(ENV), S(DPATH + 'UNIDRV.DLL'), S(DPATH + 'HPLJ4.GPD'),
            S(DPATH + 'UNIDRVUI.DLL')]


def driver_info_3(name, cv=3, deps='UNIRES.DLL'):
    return [T(cv), S(name), S(ENV), S(DPATH + 'UNIDRV.DLL'), S(DPATH + 'HPLJ4.GPD'),
            S(DPATH + 'UNIDRVUI.DLL'), S(DPATH + 'UNIDRV.HLP'), S(deps), S(None),
            S('RAW')]


def driver_info_6(name, cv=2):
    return [T(cv), S(name), S(ENV), S(DPATH + 'UNIDRV.DLL'), S(DPATH + 'HPLJ4.GPD'),
            S(DPATH + 'UNIDRVUI.DLL'), S(DPATH + 'UNIDRV.HLP'), S('Local Port'),
            S('RAW'), S('UNIRES.DLL'), S(None), ('raw', nttime(0x01d6e5a7c0f4e000)),
            T(0), T(0x00010000), T(0x000a0000), S('HP'), S('http://www.example.com/'),
            S('HP_LaserJet_4'), S('Example Provider')]


def driver_info_8(name, cv=0):
    return [T(cv), S(name), S(ENV), S(DPATH + 'UNIDRV.DLL'), S(DPATH + 'HPLJ4.GPD'),
            S(DPATH + 'UNIDRVUI.DLL'), S(DPATH + 'UNIDRV.HLP'), S('UNIRES.DLL'),
            S('Local Port'), S('RAW'), S('HP LaserJet 4 Old'),
            ('raw', nttime(0x01d6e5a7c0f4e000)), T(0), T(0x00010000), T(0x000a0000),
            S('HP'), S('http://www.example.com/'), S('HP_LaserJet_4'), S('Example Provider'),
            S('winprint'), S(None), S('sRGB Color Space Profile.icm'),
            S('C:\\Windows\\INF\\prnhp001.inf'), T(0x000017ff),
            S('{d20ea372-dd35-4950-9ed8-a6335afe79f0}'),
            ('raw', nttime(0x01d0000000000000)), T(1), T(0x00060000)]


def driver_info_101(name):
    return [T(3), S(name), S(ENV), T(0), T(0)]


DRIVER_INFOS = {1: driver_info_1, 2: driver_info_2, 3: driver_info_3,
                6: driver_info_6, 8: driver_info_8, 101: driver_info_101}


def form_rel(flags, name, wdt, hgt, l=0, t=0, r=None, b=None):
    return [T(flags), S(name), T(wdt), T(hgt), T(l), T(t),
            T(wdt if r is None else r), T(hgt if b is None else b)]


# ---------------------------------------------------------------- frames
def conn_printers(frames, port):
    """Opening printers and the print server, printer infos of every
    level through EnumPrinters, GetPrinter and SetPrinter, and closing"""
    s = Spoolss(frames, port)

    # OpenPrinterEx of the print server: datatype, no devmode, user level 1
    req = ustr('\\\\PRINTSRV') + uptr(wstr('RAW'), 0x00020004) + u32(0) + u32(0)
    req += u32(0x00000002)
    req += u32(1) + u32(0x00020008) + u32(1, 28, 0x0002000c, 0x00020010, 7601, 6, 1, 0)
    req += wstr('WS042') + wstr('alice')
    s.call(0x45, req, HND_SERVER + u32(ERR_OK))

    # OpenPrinterEx of a printer: devmode, printer access mask, user level 1
    dm = devmode(quality=-1)
    req = ustr('\\\\PRINTSRV\\Office Laser') + u32(0)
    req += pad4(u32(len(dm)) + u32(0x00020004) + dm)
    req += u32(0x0002000c)
    req += u32(1) + u32(0x00020008) + u32(1, 28, 0, 0x00020010, 9200, 10, 0, 9)
    req += wstr('alice')
    s.call(0x45, req, HND_PRINTER + u32(ERR_OK))

    # OpenPrinterEx with a NULL name and an unknown user level, refused
    req = u32(0) + u32(0) + u32(0) + u32(0) + u32(0x00020000) + u32(2)
    s.call(0x45, req, b'\0' * 20 + u32(ERR_INVALID_PRINTER_NAME))

    # EnumPrinters with a server name, every printer info level
    for level in (1, 2, 0, 5, 7, 3):
        info = Rel.build([PRINTER_INFOS[level]()])
        req = u32(0x00000052) + ustr('\\\\PRINTSRV') + u32(level)
        req += buffer_ptr(b'\0' * len(info)) + u32(len(info))
        resp = buffer_ptr(info) + u32(len(info)) + u32(1) + u32(ERR_OK)
        s.call(0x00, req, resp)
    # EnumPrinters without a buffer: the size needed
    req = u32(0x00000002) + u32(0) + u32(4) + u32(0) + u32(0)
    s.call(0x00, req, u32(0) + u32(312) + u32(0) + u32(ERR_INSUFFICIENT_BUFFER))
    # EnumPrinters level 4 (not decoded) and every flag
    info = Rel.build([[T(0), S('\\\\PRINTSRV\\Office Laser'), S('\\\\PRINTSRV'), T(0x40)]])
    req = u32(0x0000007f) + u32(0) + u32(4) + buffer_ptr(b'\0' * len(info)) + u32(len(info))
    s.call(0x00, req, buffer_ptr(info) + u32(len(info)) + u32(1) + u32(ERR_OK))

    # GetPrinter of every level, a level not decoded and without a buffer
    for level in (0, 1, 2, 3, 5, 7):
        quality = -4 if level == 2 else 600
        info = Rel.build([printer_info_2(quality, 'GetPrinter level 2') if level == 2
                          else PRINTER_INFOS[level]()])
        req = HND_PRINTER + u32(level) + buffer_ptr(b'\0' * len(info)) + u32(len(info))
        s.call(0x08, req, buffer_ptr(info) + u32(len(info)) + u32(ERR_OK))
    req = HND_PRINTER + u32(8) + buffer_ptr(b'\0' * 16) + u32(16)
    s.call(0x08, req, buffer_ptr(u32(0x0002000c, 0, 0, 0)) + u32(16) + u32(ERR_OK))
    req = HND_PRINTER + u32(2) + u32(0) + u32(0)
    s.call(0x08, req, u32(0) + u32(1200) + u32(ERR_INSUFFICIENT_BUFFER))

    # SetPrinter level 3: devmode and security descriptor buffer
    dm = devmode(name='Office Laser', quality=300, form='Letter', paper=1, orient=2)
    sd = secdesc()
    req = HND_PRINTER + u32(3) + u32(3) + u32(0x00020000, 0x00020004)
    req += pad4(u32(len(dm)) + u32(0x00020008) + dm)
    req += pad4(u32(len(sd), 0, len(sd)) + sd)
    req += u32(0)
    s.call(0x07, req, u32(ERR_OK))
    # SetPrinter level 3 without devmode or descriptor, pause and purge
    for cmd in (1, 3, 4):
        s.call(0x07, HND_PRINTER + u32(0) + u32(3) + u32(0, 0) + u32(cmd), u32(ERR_OK))
    # SetPrinter level 2 (not decoded)
    s.call(0x07, HND_PRINTER + u32(2) + u32(2) + u32(2), u32(ERR_ACCESS_DENIED))

    # DeletePrinter, ClosePrinter of both handles
    s.call(0x06, HND_PRINTER, HND_PRINTER + u32(ERR_ACCESS_DENIED))
    s.call(0x1d, HND_SERVER, b'\0' * 20 + u32(ERR_OK))
    s.call(0x1d, HND_PRINTER, b'\0' * 20 + u32(ERR_OK))

    # AddPrinterEx (no request dissector): the handle has no name
    s.call(0x46, u32(0) * 8, HND_ADDED + u32(ERR_OK))
    s.call(0x46, u32(0) * 8, b'\0' * 20 + u32(ERR_ACCESS_DENIED))
    s.conn.fin()


def conn_jobs(frames, port):
    """A print job: StartDocPrinter, pages, WritePrinter, job infos through
    EnumJobs and GetJob, SetJob commands"""
    s = Spoolss(frames, port)
    req = ustr('\\\\PRINTSRV\\Office Laser') + u32(0) + u32(0) + u32(0) + u32(0x00000008)
    req += u32(1) + u32(0x00020004) + u32(1, 28, 0, 0, 7601, 6, 1, 0)
    s.call(0x45, req, HND_JOB + u32(ERR_OK))

    # StartDocPrinter: document info level 1 with three strings, then one
    # with a NULL output file
    req = HND_JOB + u32(1) + u32(1) + u32(0x00020000)
    req += u32(0x00020004, 0x00020008, 0x0002000c)
    req += wstr('Quarterly report.pdf') + wstr('C:\\out\\report.prn') + wstrn('RAW')
    s.call(0x11, req, u32(42) + u32(ERR_OK))
    s.call(0x12, HND_JOB, u32(ERR_OK))
    data = b'\x1b%-12345X@PJL JOB NAME="Quarterly report"\r\n' + bytes(range(256)) * 2
    req = HND_JOB + u32(len(data)) + pad4(data) + u32(len(data))
    s.call(0x13, req, u32(len(data)) + u32(ERR_OK))
    s.call(0x14, HND_JOB, u32(ERR_OK))
    s.call(0x17, HND_JOB, u32(ERR_OK))
    req = HND_JOB + u32(1) + u32(1) + u32(0x00020000) + u32(0x00020004, 0, 0x0002000c)
    req += wstr('memo.txt') + wstrn('NT EMF 1.008')
    s.call(0x11, req, u32(0) + u32(ERR_ACCESS_DENIED))

    # EnumJobs level 1 with three jobs, level 2 with two, level 3 (not
    # decoded, one expert info for both jobs) and without a buffer
    buf = Rel.build([job_info_1(42, 'Quarterly report.pdf'),
                     job_info_1(43, 'memo.txt', 0x00000001, 'bob'),
                     job_info_1(44, 'Mötley Crüe – tour dates.docx', 0x00000700, 'carol')])
    req = HND_JOB + u32(0, 10, 1) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x04, req, buffer_ptr(buf) + u32(len(buf)) + u32(3) + u32(ERR_OK))
    buf = Rel.build([job_info_2(42, 'Quarterly report.pdf'),
                     job_info_2(45, 'photo.jpg', 0x00000080, 600)])
    req = HND_JOB + u32(0, 10, 2) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x04, req, buffer_ptr(buf) + u32(len(buf)) + u32(2) + u32(ERR_OK))
    buf = Rel.build([job_info_3(42, 45), job_info_3(45, 0)])
    req = HND_JOB + u32(0, 10, 3) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x04, req, buffer_ptr(buf) + u32(len(buf)) + u32(2) + u32(ERR_OK))
    req = HND_JOB + u32(0, 10, 2) + u32(0) + u32(0)
    s.call(0x04, req, u32(0) + u32(1876) + u32(0) + u32(ERR_INSUFFICIENT_BUFFER))

    # GetJob level 1, level 2 (not decoded) and without a buffer
    buf = Rel.build([job_info_1(42, 'Quarterly report.pdf')])
    req = HND_JOB + u32(42, 1) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x03, req, buffer_ptr(buf) + u32(len(buf)) + u32(ERR_OK))
    buf = Rel.build([job_info_2(42, 'Quarterly report.pdf')])
    req = HND_JOB + u32(42, 2) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x03, req, buffer_ptr(buf) + u32(len(buf)) + u32(ERR_OK))
    s.call(0x03, HND_JOB + u32(46, 1) + u32(0) + u32(0), u32(0) + u32(0) + u32(87))

    # SetJob with every command and an unknown one
    for cmd in (1, 2, 3, 4, 5, 9):
        s.call(0x02, HND_JOB + u32(42, 0, cmd), u32(ERR_OK))
    s.call(0x1d, HND_JOB, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


def conn_drivers(frames, port):
    """Driver infos of every level through EnumPrinterDrivers and
    GetPrinterDriver2, the driver and package directories"""
    s = Spoolss(frames, port)
    req = ustr('\\\\PRINTSRV\\Office Laser') + u32(0) + u32(0) + u32(0) + u32(0x00000008)
    req += u32(1) + u32(0x00020004) + u32(1, 28, 0, 0, 7601, 6, 1, 0)
    s.call(0x45, req, HND_PRINTER2 + u32(ERR_OK))

    names = ['HP LaserJet 4', 'Microsoft Print To PDF', 'Generic / Text Only']
    for level in (1, 2, 3, 6, 8):
        buf = Rel.build([DRIVER_INFOS[level](n) for n in names])
        req = ustr('\\\\PRINTSRV') + ustr(ENV, 0x00020004) + u32(level)
        req += buffer_ptr(b'\0' * len(buf), 0x00020008) + u32(len(buf))
        resp = buffer_ptr(buf) + u32(len(buf)) + u32(len(names)) + u32(ERR_OK)
        s.call(0x0a, req, resp)
    # level 101 (only the start is decoded) and level 4 (not decoded)
    for level in (101, 4):
        buf = Rel.build([driver_info_101(n) if level == 101 else driver_info_1(n)
                         for n in names[:2]])
        req = u32(0) + u32(0) + u32(level) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
        resp = buffer_ptr(buf) + u32(len(buf)) + u32(2) + u32(ERR_OK)
        s.call(0x0a, req, resp)
    # long relative strings: 64 drivers with names of 100 to 163
    # characters, every string converted once
    long_names = ['Driver %02d ' % i + ''.join(chr(0x41 + (i + j) % 26) for j in range(90 + i))
                  for i in range(64)]
    buf = Rel.build([driver_info_1(n) for n in long_names])
    req = u32(0) + ustr(ENV) + u32(1) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x0a, req, buffer_ptr(buf) + u32(len(buf)) + u32(64) + u32(ERR_OK))

    for level in (1, 2, 3, 6, 8, 101, 5):
        dinfo = DRIVER_INFOS.get(level, driver_info_2)
        buf = Rel.build([dinfo('HP LaserJet 4')])
        req = HND_PRINTER2 + ustr(ENV) + u32(level)
        req += buffer_ptr(b'\0' * len(buf), 0x00020008) + u32(len(buf)) + u32(3, 0)
        resp = buffer_ptr(buf) + u32(len(buf)) + u32(3, 0) + u32(ERR_OK)
        s.call(0x35, req, resp)
    req = HND_PRINTER2 + ustr(ENV) + u32(3) + u32(0) + u32(0) + u32(3, 0)
    s.call(0x35, req, u32(0) + u32(2200) + u32(3, 0) + u32(ERR_INSUFFICIENT_BUFFER))

    d = 'C:\\Windows\\system32\\spool\\DRIVERS\\x64'
    req = ustr('\\\\PRINTSRV') + ustr(ENV, 0x00020004) + u32(1)
    req += buffer_ptr(b'\0' * 200, 0x00020008) + u32(200)
    resp = pad4(u32(0x00020000, len(wz(d))) + wz(d)) + u32(len(wz(d))) + u32(ERR_OK)
    s.call(0x0c, req, resp)
    req = u32(0) + u32(0) + u32(1) + u32(0) + u32(0)
    s.call(0x0c, req, u32(0) + u32(78) + u32(ERR_INSUFFICIENT_BUFFER))

    # GetPrinterDriverPackagePath
    cab = 'C:\\Windows\\System32\\DriverStore\\FileRepository\\prnhp001.inf_amd64\\prnhp001.cab'
    req = ustr('\\\\PRINTSRV') + wstr(ENV) + ustr('en-US', 0x00020004)
    req += wstr('{d20ea372-dd35-4950-9ed8-a6335afe79f0}')
    req += buffer_ptr(b'\0' * 256, 0x00020008) + u32(128)
    resp = pad4(u32(0x00020000, len(wz(cab))) + wz(cab)) + u32(len(wz(cab)) // 2) + u32(0)
    s.call(0x68, req, resp)
    req = u32(0) + wstr(ENV) + u32(0) + wstr('{00000000-0000-0000-0000-000000000000}')
    req += u32(0) + u32(0)
    s.call(0x68, req, u32(0) + u32(0) + u32(0x80070002))

    # GetCorePrinterDrivers: two core driver GUIDs in the key buffer
    ids = '{d20ea372-dd35-4950-9ed8-a6335afe79f0}\0{4d8bbc7c-0a4b-4b3d-9a4e-7c1e3f0d6c11}\0\0'
    req = ustr('\\\\PRINTSRV') + wstr(ENV) + u32(len(ids)) + pad4(u32(len(ids)) + w(ids)) + u32(2)
    resp = u32(2) + u32(len(ids))
    for i, g in enumerate((b'\x72\xa3\x0e\xd2\x35\xdd\x50\x49\x9e\xd8\xa6\x33\x5a\xfe\x79\xf0',
                           b'\x7c\xbc\x8b\x4d\x4b\x0a\x3d\x4b\x9a\x4e\x7c\x1e\x3f\x0d\x6c\x11')):
        resp += g + nttime(0x01d6e5a7c0f4e000 + i) + u64(0x000a000000010000 + i)
        resp += (wz('prnhp001.inf_amd64_%d' % i) + b'\0' * 520)[:520]
    resp += u32(0)
    s.call(0x66, req, resp)
    s.call(0x1d, HND_PRINTER2, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


def conn_forms(frames, port):
    """AddForm, SetForm, GetForm, EnumForms, DeleteForm"""
    s = Spoolss(frames, port)
    s.call(0x45, ustr('\\\\PRINTSRV') + u32(0) + u32(0) + u32(0) + u32(2) + u32(1)
           + u32(0x00020004) + u32(1, 28, 0, 0, 7601, 6, 1, 0), HND_SERVER + u32(ERR_OK))
    form = u32(0x00020000) + wstr('Index card 5x8') + u32(0, 0, 127000, 203200, 0, 0, 127000, 203200)
    s.call(0x1e, HND_SERVER + u32(1) + u32(1) + form, u32(ERR_OK))
    # a FORM_1 that ends after the name
    s.call(0x1e, HND_SERVER + u32(1) + u32(1) + u32(0x00020000) + wstrn('Envelope'),
           u32(ERR_ACCESS_DENIED))
    # form level 2 (not decoded)
    s.call(0x1e, HND_SERVER + u32(2) + u32(2), u32(ERR_NOT_SUPPORTED))
    req = HND_SERVER + wstr('Index card 5x8') + u32(1) + u32(1)
    req += u32(0x00020000) + wstr('Index card 5x8') + u32(0, 0, 127000, 203200, 1000, 1000, 126000, 202200)
    s.call(0x21, req, u32(ERR_OK))
    buf = Rel.build([form_rel(0, 'Index card 5x8', 127000, 203200, 1000, 1000, 126000, 202200)])
    req = HND_SERVER + wstr('Index card 5x8') + u32(1) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x20, req, buffer_ptr(buf) + u32(len(buf)) + u32(ERR_OK))
    req = HND_SERVER + wstr('Letter') + u32(2) + buffer_ptr(b'\0' * 64) + u32(64)
    s.call(0x20, req, buffer_ptr(b'\0' * 64) + u32(64) + u32(ERR_OK))
    buf = Rel.build([form_rel(1, 'Letter', 215900, 279400),
                     form_rel(1, 'A4', 210000, 297000),
                     form_rel(0, 'Index card 5x8', 127000, 203200),
                     form_rel(2, 'Tray 2 Custom', 100000, 150000, 5000, 5000, 95000, 145000)])
    req = HND_SERVER + u32(1) + buffer_ptr(b'\0' * len(buf)) + u32(len(buf))
    s.call(0x22, req, buffer_ptr(buf) + u32(len(buf)) + u32(4) + u32(ERR_OK))
    s.call(0x22, HND_SERVER + u32(1) + u32(0) + u32(0),
           u32(0) + u32(len(buf)) + u32(0) + u32(ERR_INSUFFICIENT_BUFFER))
    s.call(0x1f, HND_SERVER + wstrn('Index card 5x8'), u32(ERR_OK))
    s.call(0x1d, HND_SERVER, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


def printerdata(dtype, data):
    return u32(len(data)) + pad4(data)


def conn_printerdata(frames, port):
    """Printer data: Get/Set/Enum/Delete PrinterData(Ex), EnumPrinterKey,
    values of every type"""
    s = Spoolss(frames, port)
    s.call(0x45, ustr('\\\\PRINTSRV\\Office Laser') + u32(0) + u32(0) + u32(0) + u32(0x0c)
           + u32(1) + u32(0x00020004) + u32(1, 28, 0, 0, 7601, 6, 1, 0), HND_PRINTER + u32(ERR_OK))

    values = [
        ('ChangeID', REG_DWORD, u32(0x0001e240)),
        ('DefaultSpoolDirectory', REG_SZ, wz('C:\\Windows\\system32\\spool\\PRINTERS')),
        ('Architecture', REG_BINARY, bytes(range(16))),
        ('DsDriver', REG_MULTI_SZ, wz('one') + wz('two') + b'\0\0'),
        ('Short', REG_DWORD, u16(7)),            # a DWORD of two octets
        ('Empty', REG_SZ, b''),
        ('Path', REG_EXPAND_SZ, wz('%SystemRoot%\\spool')),
    ]
    for name, dtype, data in values:
        s.call(0x1a, HND_PRINTER + wstr(name) + u32(len(data)),
               u32(dtype) + printerdata(dtype, data) + u32(len(data)) + u32(ERR_OK))
    for name, dtype, data in values[:4]:
        s.call(0x1b, HND_PRINTER + wstr(name) + u32(dtype) + printerdata(dtype, data)
               + u32(len(data)), u32(ERR_OK))
    s.call(0x1a, HND_PRINTER + wstr('Missing') + u32(0),
           u32(0) + u32(0) + u32(0) + u32(2))

    # GetPrinterDataEx: the returned size covers the data size and data
    for key, name, dtype, data in (('PrinterDriverData', 'Model', REG_SZ, wz('HP LaserJet 4')),
                                   ('DsSpooler', 'printRate', REG_DWORD, u32(12)),
                                   ('DsSpooler', 'printBinNames', REG_BINARY, b'\x01\x02\x03')):
        region = printerdata(dtype, data)
        s.call(0x4e, HND_PRINTER + wstr(key) + wstr(name) + u32(64),
               u32(dtype) + u32(len(region)) + region + u32(len(region)) + u32(ERR_OK))
    s.call(0x4e, HND_PRINTER + wstr('DsSpooler') + wstr('none') + u32(0),
           u32(0) + u32(0) + u32(16) + u32(ERR_MORE_DATA))

    # SetPrinterDataEx
    for key, name, dtype, data in (('PrinterDriverData', 'Model', REG_SZ, wz('HP LaserJet 4')),
                                   ('DsSpooler', 'printRate', REG_DWORD, u32(12))):
        s.call(0x4d, HND_PRINTER + wstr(key) + wstr(name) + u32(dtype, len(data))
               + pad4(data) + u32(len(data)), u32(ERR_OK))

    # EnumPrinterData by index: a value with a name, one without
    for i, (name, dtype, data) in enumerate(values[:4]):
        vn = wz(name)
        resp = u32(len(vn) // 2) + pad4(vn) + u32(len(vn)) + u32(dtype)
        resp += printerdata(dtype, data) + u32(len(data)) + u32(ERR_OK)
        s.call(0x48, HND_PRINTER + u32(i, 256, 1024), resp)
    s.call(0x48, HND_PRINTER + u32(9, 0, 0),
           u32(0) + u32(64) + u32(0) + u32(0) + u32(512) + u32(ERR_NO_MORE_ITEMS))

    # EnumPrinterDataEx: values of every type, names and data after the
    # entries (offsets from the entry they belong to)
    vals = [('Model', REG_SZ, wz('HP LaserJet 4')),
            ('printRate', REG_DWORD, u32(12)),
            ('printBinNames', REG_BINARY, b'\x01\x02\x03\x04\x05'),
            ('printMediaReady', REG_MULTI_SZ, wz('A4') + wz('Letter') + b'\0\0'),
            ('printNone', REG_NONE, b''),
            ('printQword', REG_QWORD, u64(1 << 40)),
            ('printPath', REG_EXPAND_SZ, wz('%SystemRoot%'))]
    n = len(vals)
    heap = bytearray()
    heap_base = 20 * n
    ents = bytearray()
    for i, (name, dtype, data) in enumerate(vals):
        start = 20 * i
        name_off = heap_base + len(heap) - start
        heap += wz(name)
        heap += b'\0' * ((-(heap_base + len(heap))) % 4)
        val_off = heap_base + len(heap) - start
        heap += data
        heap += b'\0' * ((-(heap_base + len(heap))) % 4)
        ents += u32(name_off, len(wz(name)), dtype, val_off, len(data))
    region = bytes(ents + heap)
    s.call(0x4f, HND_PRINTER + wstr('DsSpooler') + u32(len(region)),
           u32(len(region)) + region + u32(len(region)) + u32(n) + u32(ERR_OK))
    s.call(0x4f, HND_PRINTER + wstr('Missing') + u32(0),
           u32(0) + u32(0) + u32(0) + u32(2))

    # EnumPrinterKey: the subkeys of "" and of PrinterDriverData (a name
    # that is not ASCII), then none
    keys = 'PrinterDriverData\0DsSpooler\0DsDriver\0\0'
    s.call(0x50, HND_PRINTER + wstr('') + u32(256),
           u32(len(keys)) + pad4(w(keys)) + u32(len(keys) * 2) + u32(ERR_OK))
    keys = 'Drücker\0Zwei\0Ελληνικά\0\0'
    s.call(0x50, HND_PRINTER + wstr('PrinterDriverData') + u32(256),
           u32(len(keys)) + pad4(w(keys)) + u32(len(keys) * 2) + u32(ERR_OK))
    s.call(0x50, HND_PRINTER + wstr('DsSpooler') + u32(0),
           u32(0) + u32(2) + u32(ERR_MORE_DATA))

    s.call(0x49, HND_PRINTER + wstrn('Architecture'), u32(ERR_OK))
    s.call(0x1d, HND_PRINTER, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


def notify_options(options, flags=1):
    """NOTIFY_OPTIONS_ARRAY_CTR behind a unique pointer: version, flags,
    count, the array (conformance, the options, then each option's
    fields)"""
    b = u32(0x00020000) + u32(2, flags, len(options)) + u32(0x00020004)
    b += u32(len(options))
    for i, (otype, fields) in enumerate(options):
        b += u16(otype, 0) + u32(0, 0, len(fields)) + u32(0x00020008 + 4 * i)
    for otype, fields in options:
        b = pad4(b) + u32(len(fields)) + u16(*fields)
    return b


def notify_info(entries, flags=0):
    """NOTIFY_INFO behind a unique pointer: conformance, version, flags,
    count, the entries, then the data their pointers refer to"""
    head = u32(0x00020000) + u32(len(entries), 2, flags, len(entries))
    body, deferred = bytearray(), bytearray()
    ref = 0x00020004
    for e in entries:
        ntype, field, kind = e[0], e[1], e[2]
        body += u16(ntype, field) + u32(1, 100 + field, 1)
        if kind == 'str':
            s = wz(e[3])
            body += u32(len(s)) + u32(ref)
            ref += 4
            deferred += b'\0' * ((-(len(head) + len(body) + len(deferred))) % 4)
            deferred += u32(len(s) // 2) + s
        elif kind == 'buf':
            data = e[3]
            body += u32(len(data)) + u32(ref)
            ref += 4
            deferred += b'\0' * ((-(len(head) + len(body) + len(deferred))) % 4)
            deferred += u32(len(data) // 2) + data
        elif kind == 'null':
            body += u32(0) + u32(0)
        elif kind == 'time':
            body += u32(16) + u32(ref)
            ref += 4
            deferred += b'\0' * ((-(len(head) + len(body) + len(deferred))) % 2)
            deferred += e[3]
        elif kind == 'val':
            body += u32(e[3], e[4])
        elif kind == 'none':
            pass
    return head + bytes(body) + bytes(deferred)


def conn_notify(frames, port):
    """Change notification: RFFPCNEX, ReplyOpenPrinter, RRPCN, RFNPCNEX,
    RouterReplyPrinter, FCPN, ReplyClosePrinter"""
    s = Spoolss(frames, port)
    s.call(0x45, ustr('\\\\PRINTSRV\\Office Laser') + u32(0) + u32(0) + u32(0) + u32(0x08)
           + u32(1) + u32(0x00020004) + u32(1, 28, 0, 0, 7601, 6, 1, 0), HND_NOTIFY + u32(ERR_OK))

    # RFFPCNEX: every flag, a printer option and a job option
    opts = notify_options([(0, list(range(0x1a)) + [0x40]), (1, list(range(0x18)) + [0x41])])
    req = HND_NOTIFY + u32(0xf5770f0f, 0) + ustr('\\\\WS042') + u32(123) + opts
    s.call(0x41, req, u32(ERR_OK))
    # an option of an unknown type and no server name
    opts = notify_options([(7, [1, 2])], flags=0)
    s.call(0x41, HND_NOTIFY + u32(0x00000100, 0) + u32(0) + u32(0) + opts, u32(ERR_OK))
    s.call(0x41, HND_NOTIFY + u32(0, 0) + u32(0) + u32(0) + u32(0), u32(ERR_NOT_SUPPORTED))

    # the server calls back: ReplyOpenPrinter
    s.call(0x3a, wstr('\\\\WS042') + u32(123, 1, 0, 0), HND_FAILED + u32(ERR_OK))
    s.call(0x3a, wstr('\\\\WS043') + u32(124, 1, 0, 0), b'\0' * 20 + u32(ERR_ACCESS_DENIED))

    # RRPCN with printer notifications of every kind
    st = systime(2024, 5, 5, 3, 7, 12, 34, 567)
    pentries = [(0, f, 'str', 'value %d' % f) for f in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11)]
    pentries += [(0, 13, 'val', 0x00000a48, 0), (0, 18, 'val', 0x00000400, 0),
                 (0, 7, 'buf', devmode()[4:24]), (0, 12, 'buf', secdesc()[:20]),
                 (0, 0x0c, 'null'), (0, 20, 'val', 3, 0), (0, 0x30, 'val', 1, 2)]
    s.call(0x42, HND_FAILED + u32(5, 0, 0, 0) + notify_info(pentries, 1), u32(0) + u32(ERR_OK))
    # job notifications of every kind, then an unknown notify type
    jentries = [(1, f, 'str', 'job value %d' % f) for f in (0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 13)]
    jentries += [(1, 10, 'val', 0x00000418, 0), (1, 16, 'time', st)]
    jentries += [(1, f, 'val', 1000 + f, 0) for f in (14, 15, 20, 21, 22, 23)]
    jentries += [(1, 9, 'buf', devmode()[4:24]), (1, 12, 'val', 0, 0), (1, 0x30, 'val', 0, 0),
                 (5, 1, 'none')]
    s.call(0x42, HND_FAILED + u32(6, 0, 0, 0) + notify_info(jentries), u32(0) + u32(ERR_OK))
    s.call(0x42, HND_FAILED + u32(7, 0, 0, 0) + u32(0), u32(0) + u32(ERR_OK))

    # RFNPCNEX: asks with options, answered with a notification
    opts = notify_options([(1, [0x0d, 0x0e])])
    entries = [(1, 0x0d, 'str', 'Quarterly report.pdf'), (1, 0x0e, 'val', 1, 0),
               (0, 18, 'val', 0x00000400, 0)]
    s.call(0x43, HND_NOTIFY + u32(1) + opts, pad4(notify_info(entries, 1)) + u32(ERR_OK))
    s.call(0x43, HND_NOTIFY + u32(2) + u32(0), u32(0) + u32(ERR_OK))

    s.call(0x3b, HND_FAILED + u32(0x00000200, 0, 8), u32(ERR_OK))
    s.call(0x38, HND_NOTIFY, u32(ERR_OK))
    s.call(0x3c, HND_FAILED, b'\0' * 20 + u32(ERR_OK))
    s.call(0x1d, HND_NOTIFY, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


GENERIC = [0x01, 0x05, 0x09, 0x0b, 0x0d, 0x0e, 0x0f, 0x10, 0x15, 0x16, 0x18, 0x19, 0x1c,
           0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
           0x30, 0x31, 0x32, 0x33, 0x34, 0x36, 0x37, 0x39, 0x3d, 0x3e, 0x3f, 0x40,
           0x51, 0x54, 0x59]


def conn_generic(frames, port):
    """The opnums without a request dissector: the response status only"""
    s = Spoolss(frames, port)
    for i, op in enumerate(GENERIC):
        req = HND_SERVER + u32(op)
        if op == 0x09:      # AddPrinterDriver has a response dissector
            resp = u32(ERR_UNKNOWN_PRINTER_DRIVER if i % 2 else ERR_OK)
        else:
            resp = u32(0, 0) + u32(ERR_OK if i % 3 else ERR_NOT_SUPPORTED)
        s.call(op, req, resp)
    s.conn.fin()


def conn_bigendian(frames, port):
    """A few calls in big endian NDR"""
    s = Spoolss(frames, port, le=False)

    def b32(*v):
        return struct.pack('>%dI' % len(v), *v)

    def bwstr(t):
        n = len(t) + 1
        return b32(n, 0, n) + (t + '\0').encode('utf-16-be')

    s.call(0x02, HND_JOB + b32(77, 0, 3), b32(ERR_OK))
    s.call(0x12, HND_JOB, b32(ERR_OK))
    data = b'big endian job data'
    s.call(0x13, HND_JOB + b32(len(data)) + pad4(data) + b32(len(data)), b32(len(data), 0))
    s.call(0x14, HND_JOB, b32(ERR_OK))
    s.call(0x1f, HND_SERVER + bwstr('Old form'), b32(ERR_OK))
    s.call(0x49, HND_PRINTER + bwstr('Architecture'), b32(ERR_INVALID_HANDLE))
    s.call(0x3b, HND_FAILED + b32(0x00000200, 0, 9), b32(ERR_OK))
    s.call(0x38, HND_NOTIFY, b32(ERR_OK))
    s.call(0x17, HND_JOB, b32(ERR_OK))
    s.conn.fin()


def conn_ndr64(frames, port):
    """A few calls in NDR64: 8 octet pointers and counts"""
    s = Spoolss(frames, port, ndr64=True)

    def wstr64(t):
        n = len(t) + 1
        return struct.pack('<QQQ', n, 0, n) + wz(t)

    s.call(0x02, HND_JOB + u32(78, 0, 2), u32(ERR_OK))
    s.call(0x50, HND_PRINTER + b'\0' * 4 + pad4(wstr64('DsDriver')) + u32(64),
           u32(10) + w('printer\0\0\0') + u32(20) + u32(ERR_OK))
    # GetCorePrinterDrivers: unique server name, reference environment,
    # one core driver aligned to 8 octets
    ids = '{d20ea372-dd35-4950-9ed8-a6335afe79f0}\0\0'
    req = struct.pack('<Q', 0x20000) + pad8(wstr64('\\\\PRINTSRV')) + pad4(wstr64(ENV))
    req += u32(len(ids)) + pad4(u32(len(ids)) + w(ids)) + u32(1)
    resp = u32(1) + u32(len(ids))
    resp += b'\x72\xa3\x0e\xd2\x35\xdd\x50\x49\x9e\xd8\xa6\x33\x5a\xfe\x79\xf0'
    resp += nttime(0x01d6e5a7c0f4e000) + u64(0x000a000000010000)
    resp += (wz('prnhp001.inf_amd64') + b'\0' * 520)[:520] + u32(0)
    s.call(0x66, req, resp)
    s.call(0x1d, HND_JOB, b'\0' * 20 + u32(ERR_OK))
    s.conn.fin()


def pad8(b):
    return b + b'\0' * ((-len(b)) % 8)


# ------------------------------------------------- the reproducers, as is
def repro_session(frames, port):
    t = TCP(frames, port)
    r = RPC(t, UUID_SPOOLSS, VER)
    r.bind()
    return r


REF = 0x00020000
HND_R = b'\x00' * 4 + b'\x11' * 16


def rbuffer_ptr(data):
    return pad4(u32(REF, len(data)) + data)


def repro_keybuffer_loop(frames):
    """spoolss_keybuffer_loop.py: key buffer sizes beyond the data"""
    r = repro_session(frames, 50301)
    key = u32(1, 0, 1) + b'\0\0'
    req = HND_R + pad4(key) + u32(0x100)
    resp = u32(0x1000) + 'A'.encode('utf-16-le') + b'\0\0'
    r.call(0x50, req, resp)
    r2 = repro_session(frames, 50302)
    req = u32(0) + u32(REF) + u32(2, 0, 2) + 'x\0'.encode('utf-16-le') + u32(0x100) + u32(0x1000) + 'B\0'.encode('utf-16-le')
    r2.call(0x66, req, None)


def repro_enum_nullbuf(frames):
    """spoolss_enum_nullbuf.py: NULL buffers with an entry count of 1"""
    r = repro_session(frames, 50311)
    r.call(0x04, HND_R + u32(0, 10, 1) + u32(0) + u32(0), u32(0) + u32(0) + u32(1) + u32(0))
    r = repro_session(frames, 50312)
    r.call(0x22, HND_R + u32(1) + u32(0) + u32(0), u32(0) + u32(0) + u32(1) + u32(0))
    r = repro_session(frames, 50313)
    r.call(0x0a, u32(0) + u32(0) + u32(1) + u32(0) + u32(0), u32(0) + u32(0) + u32(1) + u32(0))


def repro_enumjobs_level_loop(frames):
    """spoolss_enumjobs_level_loop.py: level 3, 0xffffffff jobs"""
    r = repro_session(frames, 50321)
    req = HND_R + u32(0, 10, 3) + u32(0) + u32(16)
    resp = rbuffer_ptr(b'\0' * 16) + u32(16) + u32(0xffffffff) + u32(0)
    r.call(0x04, req, resp)


def repro_relstr_quadratic(frames):
    """spoolss_relstr_quadratic.py: 16000 DRIVER_INFO_1 in 64000 octets"""
    n = 16000
    buf = b''.join(struct.pack('<I', (-4 * i) & 0xffffffff if i else 2) for i in range(n))
    r = repro_session(frames, 50331)
    req = u32(0) + u32(0) + u32(1) + u32(0) + u32(len(buf))
    resp = rbuffer_ptr(buf) + u32(len(buf)) + u32(n) + u32(0)
    r.call(0x0a, req, resp)


def repro_systemtime(frames):
    """spoolss_systemtime_uninit.py: RFNPCNEX job submitted time"""
    r = repro_session(frames, 50341)
    req = HND_R + u32(1) + u32(0)
    st = struct.pack('<8H', 2024, 5, 3, 7, 12, 34, 56, 789)
    data = struct.pack('<HH', 1, 0x10) + u32(1, 7, 1) + u32(16) + u32(0x00020004)
    resp = u32(REF) + u32(1, 2, 0, 1) + data + st + u32(0)
    r.call(0x43, req, resp)


# ----------------------------------------------------------- malformed
def malformed(frames):
    s = Spoolss(frames, 51001)
    # a buffer size larger than the stub (error expert info, no buffer)
    for op, req in ((0x04, HND_JOB + u32(0, 10, 1) + u32(0) + u32(64)),
                    (0x22, HND_SERVER + u32(1) + u32(0) + u32(64)),
                    (0x0a, u32(0) + u32(0) + u32(2) + u32(0) + u32(64)),
                    (0x08, HND_PRINTER + u32(2) + u32(0) + u32(64))):
        s.call(op, req, u32(REF, 0x10000) + b'\0' * 8 + u32(64) + u32(1) + u32(0))
    # EnumPrinterDataEx: more values than the size holds (the name and
    # value offsets point after the data, at the needed and returned
    # counts)
    region = u32(20, 4, REG_DWORD, 24, 4)
    s.call(0x4f, HND_PRINTER + wstr('DsSpooler') + u32(len(region)),
           u32(len(region)) + region + u32(0x61) + u32(1000) + u32(0))
    # EnumPrinterDataEx: a size beyond the stub
    s.call(0x4f, HND_PRINTER + wstr('DsSpooler') + u32(0),
           u32(0xfffffff0) + u32(0) + u32(0) + u32(0))
    # GetPrinterDataEx: a size beyond the stub
    s.call(0x4e, HND_PRINTER + wstr('k') + wstr('v') + u32(0),
           u32(REG_SZ) + u32(0xfffffff8) + u32(4) + u32(0))
    # EnumPrinterData: a value name length beyond the stub
    s.call(0x48, HND_PRINTER + u32(0, 0, 0), u32(0x80000000) + w('ab\0'))
    # EnumPrinterKey with a key buffer size beyond the stub, and the last
    # string without its NUL
    s.call(0x50, HND_PRINTER + wstr('') + u32(0), u32(0x40000000) + w('x\0'))
    s.call(0x50, HND_PRINTER + wstr('') + u32(0), u32(3) + w('abc'))
    # PRINTER_INFO_2 and JOB_INFO_2 with a devmode offset below 4
    info = Rel.build([printer_info_2()])
    info = info[:28] + u32(2) + info[32:]
    s.call(0x08, HND_PRINTER + u32(2) + u32(0) + u32(0), buffer_ptr(info) + u32(len(info)) + u32(0))
    buf = Rel.build([job_info_2(42, 'doc')])
    buf = buf[:40] + u32(0) + buf[44:]
    s.call(0x03, HND_JOB + u32(42, 1) + u32(0) + u32(0), b'')
    s.call(0x04, HND_JOB + u32(0, 1, 2) + u32(0) + u32(0),
           buffer_ptr(buf) + u32(len(buf)) + u32(1) + u32(0))
    # a relative string offset beyond the buffer
    buf = Rel.build([driver_info_1('x')])
    buf = u32(0x7fff0000) + buf[4:]
    s.call(0x0a, u32(0) + u32(0) + u32(1) + u32(0) + u32(0),
           buffer_ptr(buf) + u32(len(buf)) + u32(1) + u32(0))
    # GetCorePrinterDrivers response cut short in a core driver
    s.call(0x66, u32(0) + wstr(ENV) + u32(0) + u32(0) + u32(0), u32(3, 0) + b'\0' * 100)
    # notify info with a string longer than the stub
    entries = [(0, 1, 'str', 'x')]
    ni = notify_info(entries)
    ni = ni[:-6] + u32(0x1000) + w('x')
    s.call(0x42, HND_FAILED + u32(5, 0, 0, 0) + ni, u32(0) + u32(0))
    # SetPrinter with a security descriptor buffer length beyond the stub
    s.call(0x07, HND_PRINTER + u32(3) + u32(3) + u32(0, 1) + u32(100, 0, 0x7fffffff) + u32(0),
           u32(0))
    # OpenPrinterEx and ReplyOpenPrinter requests cut short before the
    # name is saved, answered with a handle: the handle has no name
    s.call(0x45, u32(0x00020000) + u32(9), HND_PRINTER2 + u32(ERR_OK))
    s.call(0x3a, u32(9, 0), HND_NOTIFY + u32(ERR_OK))
    # WritePrinter with a size beyond the stub
    s.call(0x13, HND_JOB + u32(0x10000) + b'abc', u32(0, 0))
    s.conn.fin()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = []
    conn_printers(frames, 50001)
    conn_jobs(frames, 50002)
    conn_drivers(frames, 50003)
    conn_forms(frames, 50004)
    conn_printerdata(frames, 50005)
    conn_notify(frames, 50006)
    conn_generic(frames, 50007)
    conn_bigendian(frames, 50008)
    conn_ndr64(frames, 50009)
    repro_enum_nullbuf(frames)
    repro_enumjobs_level_loop(frames)
    repro_relstr_quadratic(frames)
    repro_systemtime(frames)
    pcap(os.path.join(out, 'dcerpc_spoolss-coverage.pcap'), frames)

    frames = []
    repro_keybuffer_loop(frames)
    malformed(frames)
    pcap(os.path.join(out, 'dcerpc_spoolss-coverage-malformed.pcap'), frames)


if __name__ == '__main__':
    main()

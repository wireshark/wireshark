#!/usr/bin/env python3
# Generates test/captures/cip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CIP dissector
(epan/dissectors/packet-cip.c): explicit messages over EtherNet/IP
(TCP 44818, SendRRData and SendUnitData) and class 0/1 I/O over UDP 2222.

Every packet is built from scratch with struct; no captured traffic is
used. Addresses are from the documentation ranges (192.0.2.0/24,
198.51.100.0/24) and locally administered MAC addresses.

Usage: mkcip.py <output directory>

Writes:
  cip-coverage.pcap            request/response pairs for the generic
                               services and every attribute table, all
                               EPATH segment types, the Connection
                               Manager (Forward Open/Close, Large and
                               Concurrent Forward Open, Unconnected Send,
                               Get Connection Owner, error statuses),
                               PCCC, Modbus, Connection Configuration
                               Object, File, PDD, connected class 3 and
                               class 1 traffic, and the reproducers of
                               the fixes on the branch
  cip-coverage-malformed.pcap  truncated attributes and services, bad
                               segment types and formats, inconsistent
                               lengths
"""

import os
import struct
import sys

# ---------------------------------------------------------------- framing

CLI_MAC = bytes.fromhex('020000000a01')
SRV_MAC = bytes.fromhex('020000000a02')
CLI_IP = (192, 0, 2, 10)
SRV_IP = (192, 0, 2, 20)
ENIP_PORT = 44818
IO_PORT = 2222


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:] + payload


def eth(src_mac, dst_mac, payload):
    return dst_mac + src_mac + b'\x08\x00' + payload


class TcpStream:
    """One TCP connection from CLI_IP:cport to SRV_IP:44818 with
    consistent sequence and acknowledgement numbers."""

    def __init__(self, cport, cseq=1000, sseq=5000):
        self.cport = cport
        self.seq = {True: cseq, False: sseq}

    def frame(self, from_client, payload, flags=0x18):
        if from_client:
            src, dst, sport, dport = CLI_IP, SRV_IP, self.cport, ENIP_PORT
            smac, dmac = CLI_MAC, SRV_MAC
        else:
            src, dst, sport, dport = SRV_IP, CLI_IP, ENIP_PORT, self.cport
            smac, dmac = SRV_MAC, CLI_MAC
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        self.seq[from_client] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        return eth(smac, dmac, ipv4(6, tcp + payload, src, dst, ident=seq))


def udp_frame(src, dst, sport, dport, payload, smac=CLI_MAC, dmac=SRV_MAC, ident=1):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xffff
    hdr = hdr[:6] + struct.pack('!H', c)
    return eth(smac, dmac, ipv4(17, hdr + payload, src, dst, ident))


SESSION = 0x12345678


def enip_srrd(cip, context):
    cpf = struct.pack('<IHH', 0, 0, 2)
    cpf += struct.pack('<HH', 0x0000, 0)
    cpf += struct.pack('<HH', 0x00B2, len(cip)) + cip
    return struct.pack('<HHIIQI', 0x006F, len(cpf), SESSION, 0, context, 0) + cpf


def enip_sud(connid, seq, cip):
    cpf = struct.pack('<IHH', 0, 0, 2)
    cpf += struct.pack('<HHI', 0x00A1, 4, connid)
    data = struct.pack('<H', seq) + cip
    cpf += struct.pack('<HH', 0x00B1, len(data)) + data
    return struct.pack('<HHIIQI', 0x0070, len(cpf), SESSION, 0, 0, 0) + cpf


def enip_io(connid, seq32, data):
    cpf = struct.pack('<H', 2)
    cpf += struct.pack('<HHII', 0x8002, 8, connid, seq32)
    cpf += struct.pack('<HH', 0x00B1, len(data)) + data
    return cpf


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            sec = 1700000000 + i // 100
            usec = (i % 100) * 10000
            f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)) + fr)


# ---------------------------------------------------------------- CIP data

def u8(v):
    return struct.pack('<B', v)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def u64(v):
    return struct.pack('<Q', v)


def f32(v):
    return struct.pack('<f', v)


def sstr(s):
    s = s.encode('latin-1')
    return u8(len(s)) + s


def cstr(s):
    s = s.encode('latin-1')
    return u16(len(s)) + s


def cstr2(s):
    return u16(len(s)) + s.encode('utf-16-le')


def stringi(entries):
    """entries: list of (lang, type, charset, encoded string with length)."""
    out = u8(len(entries))
    for lang, typ, charset, data in entries:
        out += lang.encode() + u8(typ) + u16(charset) + data
    return out


# Logical segments
def seg(ltype, value, fmt=None):
    """ltype: 0 class, 4 instance, 8 member, 0xC conn point, 0x10 attribute,
    0x1C extended logical (value=(ext_type, value))."""
    if fmt is None:
        fmt = 8 if value < 0x100 else (16 if value < 0x10000 else 32)
    if fmt == 8:
        return bytes([0x20 | ltype, value])
    if fmt == 16:
        return bytes([0x21 | ltype, 0]) + u16(value)
    return bytes([0x22 | ltype, 0]) + u32(value)


def cls(v, fmt=None):
    return seg(0x00, v, fmt)


def inst(v, fmt=None):
    return seg(0x04, v, fmt)


def mbr(v, fmt=None):
    return seg(0x08, v, fmt)


def cpt(v, fmt=None):
    return seg(0x0C, v, fmt)


def att(v, fmt=None):
    return seg(0x10, v, fmt)


def ext_logical(ext_type, value, fmt):
    if fmt == 8:
        return bytes([0x3C, ext_type, value, 0])
    if fmt == 16:
        return bytes([0x3D, ext_type]) + u16(value)
    return bytes([0x3E, ext_type]) + u32(value)


def port_seg(port, link):
    """Port segment; link is an int (1 octet) or bytes (extended link
    address); port 15 and above uses the extended port field."""
    ext = port >= 15
    pid = 15 if ext else port
    if isinstance(link, int):
        if ext:
            return bytes([pid]) + u16(port) + bytes([link])
        return bytes([pid, link])
    s = bytes([0x10 | pid, len(link)])
    if ext:
        s += u16(port)
    s += link
    if len(link) % 2:
        s += b'\0'
    return s


def ekey(fmt=4, vendor=1, devtype=12, prod=34, compat=0x83, minor=5, serial=0x11223344):
    s = bytes([0x34, fmt]) + u16(vendor) + u16(devtype) + u16(prod) + bytes([compat, minor])
    if fmt == 5:
        s += u32(serial)
    return s


def ansi_sym(name):
    n = name.encode()
    s = bytes([0x91, len(n)]) + n
    if len(n) % 2:
        s += b'\0'
    return s


def simple_data(data):
    assert len(data) % 2 == 0
    return bytes([0x80, len(data) // 2]) + data


def symbolic(name):
    n = name.encode()
    s = bytes([0x60 | len(n)]) + n
    if len(s) % 2:
        s += b'\0'
    return s


def req(service, path, data=b''):
    assert len(path) % 2 == 0, path.hex()
    return bytes([service, len(path) // 2]) + path + data


def rsp(service, data=b'', status=0, addl=()):
    return bytes([service | 0x80, 0, status, len(addl)]) + b''.join(u16(a) for a in addl) + data


def gas(c, i, a, fmt=None):
    return req(0x0E, cls(c) + inst(i) + att(a))


def msp_req(services, path=None):
    """Multiple Service Packet request to the Message Router."""
    if path is None:
        path = cls(2) + inst(1)
    n = len(services)
    off = 2 + 2 * n
    offs = []
    body = b''
    for s in services:
        offs.append(off + len(body))
        body += s
    return req(0x0A, path, u16(n) + b''.join(u16(o) for o in offs) + body)


def msp_rsp(services, status=0):
    n = len(services)
    off = 2 + 2 * n
    offs = []
    body = b''
    for s in services:
        offs.append(off + len(body))
        body += s
    return rsp(0x0A, u16(n) + b''.join(u16(o) for o in offs) + body, status)


# ---------------------------------------------------------------- capture

class Capture:
    def __init__(self):
        self.frames = []
        self.labels = []
        self.ctx = 0x100
        self.streams = {}
        self.stream = self.get_stream(50000)

    def get_stream(self, cport):
        if cport not in self.streams:
            self.streams[cport] = TcpStream(cport, 1000 + cport, 5000 + cport)
        return self.streams[cport]

    def add(self, frame, label):
        self.frames.append(frame)
        self.labels.append(label)

    def pair(self, request, response, label, stream=None):
        st = stream or self.stream
        self.ctx += 1
        self.add(st.frame(True, enip_srrd(request, self.ctx)), label + ' (request)')
        if response is not None:
            self.add(st.frame(False, enip_srrd(response, self.ctx)), label + ' (response)')

    def one(self, from_client, cip, label, stream=None, context=None):
        st = stream or self.stream
        if context is None:
            self.ctx += 1
            context = self.ctx
        self.add(st.frame(from_client, enip_srrd(cip, context)), label)

    def sud(self, from_client, connid, seq, cip, label, stream=None):
        st = stream or self.stream
        self.add(st.frame(from_client, enip_sud(connid, seq, cip)), label)

    def io(self, from_client, connid, seq32, data, label, src=None, dst=None):
        if from_client:
            s, d, sm, dm = src or CLI_IP, dst or SRV_IP, CLI_MAC, SRV_MAC
        else:
            s, d, sm, dm = src or SRV_IP, dst or CLI_IP, SRV_MAC, CLI_MAC
        self.add(udp_frame(s, d, IO_PORT, IO_PORT, enip_io(connid, seq32, data), sm, dm,
                           ident=len(self.frames)), label)


def fwd_open(o2t, t2o, serial, conn_path, ot_params=0x4802, to_params=0x4802,
             ttt=0xA3, service=0x54, rpi=10000, timeout_mult=1, vendor=0x1234,
             orig_serial=0x89ABCDEF, cc_version=None, path=None):
    """Forward Open (0x54), Large Forward Open (0x5B, 32 bit network
    parameters) or Concurrent Forward Open (0x5C, with a CC version)."""
    if path is None:
        path = cls(6) + inst(1)
    d = bytes([0x0A, 0x0E]) + u32(o2t) + u32(t2o) + u16(serial) + u16(vendor) + u32(orig_serial)
    if cc_version is not None:
        d += bytes([cc_version, 0])
    d += bytes([timeout_mult, 0, 0, 0])
    if service == 0x5B:
        d += u32(rpi) + u32(ot_params) + u32(rpi) + u32(to_params)
    else:
        d += u32(rpi) + u16(ot_params) + u32(rpi) + u16(to_params)
    d += bytes([ttt, len(conn_path) // 2]) + conn_path
    return req(service, path, d)


def fwd_open_rsp(o2t, t2o, serial, app=b'', service=0x54, vendor=0x1234,
                 orig_serial=0x89ABCDEF, api=10000):
    d = u32(o2t) + u32(t2o) + u16(serial) + u16(vendor) + u32(orig_serial) + u32(api) + u32(api)
    d += bytes([len(app) // 2, 0]) + app
    return rsp(service, d)


def fwd_close(serial, conn_path, vendor=0x1234, orig_serial=0x89ABCDEF, service=0x4E):
    d = bytes([0x0A, 0x0E]) + u16(serial) + u16(vendor) + u32(orig_serial)
    d += bytes([len(conn_path) // 2, 0]) + conn_path
    return req(service, cls(6) + inst(1), d)


def fwd_close_rsp(serial, app=b'', vendor=0x1234, orig_serial=0x89ABCDEF, service=0x4E):
    return rsp(service, u16(serial) + u16(vendor) + u32(orig_serial) + bytes([len(app) // 2, 0]) + app)


def ucs(embedded, route, path=None):
    if path is None:
        path = cls(6) + inst(1)
    d = bytes([0x0A, 0x0E]) + u16(len(embedded)) + embedded
    if len(embedded) % 2:
        d += b'\0'
    d += bytes([len(route) // 2, 0]) + route
    return req(0x52, path, d)


def cc_crc(data):
    """Concurrent connection CRC: reflected CRC-32 with polynomial
    0xC0000018 (the table crc32_cc_table in packet-cip.c), initial value
    0xFFFFFFFF and no final XOR."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xC0000018 if crc & 1 else crc >> 1
    return crc


def cc_packet(seq, data):
    """Concurrent connection packet: type 1 header, length, sequence
    count, data and CRC over everything before the CRC."""
    length = 8 + len(data)
    body = u16(0x0001 | 0x0020 | (2 << 6)) + u16(length) + u32(seq) + data
    return body + u32(cc_crc(body))


def build_main():
    c = Capture()

    # ------------------------------------------------ reproducers
    # cip_msp_pdata_confusion: a Multiple Service Packet request, then a
    # frame from port 44818 (matched to the request by ENIP) that carries
    # an Unconnected Send request.
    rs = c.get_stream(50001)
    g1 = req(0x0E, cls(1) + inst(1) + att(1))
    msp = req(0x0A, cls(2) + inst(1), u16(1) + u16(4) + g1)
    u = req(0x52, cls(6) + inst(1), bytes([0x0A, 0x0E]) + u16(len(g1)) + g1
            + bytes([0x01, 0x00, 0x01, 0x00]))
    c.one(True, msp, 'Repro cip_msp_pdata_confusion: MSP request', rs, context=0x0102030405060708)
    c.one(False, u, 'Repro cip_msp_pdata_confusion: Unconnected Send request from the server',
          rs, context=0x0102030405060708)
    # cip_fwdopen_reqreuse_assert: a Forward Open request in both directions
    rs = c.get_stream(50002)
    fo = fwd_open(0x11111111, 0x22222222, 1, cls(4) + inst(1), ttt=0x01, vendor=1,
                  orig_serial=0x12345678)
    c.one(True, fo, 'Repro cip_fwdopen_reqreuse_assert: Forward Open request', rs, context=0x0102030405060708)
    c.one(False, fo, 'Repro cip_fwdopen_reqreuse_assert: Forward Open request from the server',
          rs, context=0x0102030405060708)

    # ------------------------------------------------ Identity object
    ident_gaa = (u16(1) + u16(12) + u16(34) + bytes([3, 7]) + u16(0x0F75) + u32(0x12345678)
                 + sstr('Synthetic CIP device') + u8(3) + u16(0xBEEF) + u8(10))
    c.pair(req(0x01, cls(1) + inst(1)), rsp(0x01, ident_gaa), 'Identity Get_Attributes_All instance')
    c.pair(req(0x01, cls(1) + inst(0)), rsp(0x01, u16(1) + u16(1) + u16(7) + u16(38)),
           'Identity Get_Attributes_All class')
    attrs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 15, 16, 17, 18, 19, 20, 21, 22, 31, 32, 33, 34,
             35, 37, 38]
    si = stringi([('eng', 0xDA, 4, sstr('Device')), ('deu', 0xD0, 4, cstr('Geraet')),
                  ('fra', 0xD5, 1000, cstr2('Appareil')), ('spa', 0xD9, 4, u16(1) + u16(3) + b'abc'),
                  ('ita', 0xD9, 1000, u16(2) + u16(2) + 'ab'.encode('utf-16-le')),
                  ('jpn', 0xD9, 1000, u16(4) + u16(1) + 'x'.encode('utf-32-le'))])
    vals = {1: u16(1), 2: u16(12), 3: u16(34), 4: bytes([3, 7]), 5: u16(0x0F75),
            6: u32(0x12345678), 7: sstr('Product'), 8: u8(3), 9: u16(0xBEEF), 10: u8(10),
            13: si, 15: stringi([('eng', 0xDA, 4, sstr('Name'))]),
            16: stringi([('eng', 0xDA, 4, sstr('Desc'))]), 17: stringi([('eng', 0xDA, 4, sstr('Here'))]),
            18: sstr('Vendor') + sstr('PC1') + sstr('1.0') + sstr('http://example.com')
            + sstr('Prod') + sstr('Model') + sstr('App'),
            19: u16(3), 20: u32(86400), 21: sstr('CAT-1'), 22: u16(18000), 31: cstr('Vendor Inc'),
            32: cstr('https://example.com/'), 33: u32(7), 34: u64(1700000000123456789),
            35: sstr('SN-0001'), 37: bytes([2, 1]), 38: u8(2) + bytes([1, 0, 2, 3])}
    galreq = req(0x03, cls(1) + inst(1), u16(len(attrs) + 2) + b''.join(u16(a) for a in attrs)
                 + u16(99) + u16(36))
    galrsp = u16(len(attrs) + 2)
    for a in attrs:
        galrsp += u16(a) + u16(0) + vals[a]
    galrsp += u16(99) + u16(0x14) + u16(36) + u16(0)
    c.pair(galreq, rsp(0x03, galrsp + b'\x01\x02'), 'Identity Get_Attribute_List (all attributes)')
    c.pair(gas(1, 1, 11), rsp(0x0E, b'eng'), 'Identity Get_Attribute_Single Active Language')
    c.pair(gas(1, 1, 12), rsp(0x0E, b'engdeufra'), 'Identity Get_Attribute_Single Supported Language List')
    c.pair(gas(1, 1, 14), rsp(0x0E, u16(1) + u32(0x01020304) + u16(30)), 'Identity Get_Attribute_Single Semaphore')
    c.pair(gas(1, 0, 4), rsp(0x0E, u16(3) + u16(1) + u16(2) + u16(3)), 'Identity class Optional Attribute List')
    c.pair(gas(1, 0, 5), rsp(0x0E, u16(2) + u16(0x4B) + u16(0x4C)), 'Identity class Optional Service List')
    c.pair(gas(1, 0, 3), rsp(0x0E, u16(1)), 'Identity class Number of Instances')
    c.pair(req(0x10, cls(1) + inst(1) + att(8), u8(3)), rsp(0x10), 'Identity Set_Attribute_Single State')
    c.pair(req(0x10, cls(1) + inst(1) + att(99), u8(3)), rsp(0x10, status=0x14),
           'Identity Set_Attribute_Single unknown attribute')
    c.pair(req(0x04, cls(1) + inst(1), u16(3) + u16(9) + u16(0xBEEF) + u16(10) + u8(5) + u16(99) + u8(1)),
           rsp(0x04, u16(2) + u16(9) + u16(0) + u16(10) + u16(0)), 'Identity Set_Attribute_List')
    c.pair(req(0x05, cls(1) + inst(1), u8(1)), rsp(0x05), 'Identity Reset with parameter')
    c.pair(req(0x05, cls(1) + inst(1)), rsp(0x05, b'\x00'), 'Identity Reset without parameter')
    # Common class attributes of a class without its own table
    c.pair(req(0x03, cls(0x64) + inst(0), u16(7) + b''.join(u16(a) for a in range(1, 8))),
           rsp(0x03, u16(7) + u16(1) + u16(0) + u16(2) + u16(2) + u16(0) + u16(5) + u16(3) + u16(0) + u16(5)
               + u16(4) + u16(0) + u16(1) + u16(1) + u16(5) + u16(0) + u16(1) + u16(0x0E) + u16(6) + u16(0)
               + u16(7) + u16(7) + u16(0) + u16(3)), 'Common class attributes (class 0x64)')

    # ------------------------------------------------ Message Router / CM
    c.pair(req(0x01, cls(2) + inst(1)),
           rsp(0x01, u16(3) + u16(1) + u16(2) + u16(6) + u16(32) + u16(2) + u16(5) + u16(6)),
           'Message Router Get_Attributes_All instance')
    c.pair(req(0x01, cls(2) + inst(0)),
           rsp(0x01, u16(1) + u16(1) + u16(0) + u16(0) + u16(7) + u16(4)),
           'Message Router Get_Attributes_All class')
    c.pair(req(0x01, cls(6) + inst(1)),
           rsp(0x01, b''.join(u16(i) for i in range(1, 9)) + u16(12) + b'\x05\x01' + u16(25)
               + u32(4000) + u32(3000)), 'Connection Manager Get_Attributes_All instance')
    c.pair(req(0x01, cls(6) + inst(0)), rsp(0x01, u16(1) + u16(1) + u16(7) + u16(13)),
           'Connection Manager Get_Attributes_All class')

    # ------------------------------------------------ File object
    fi = {1: u8(2), 2: stringi([('eng', 0xDA, 4, sstr('EDS'))]), 3: u16(1),
          4: stringi([('eng', 0xDA, 4, sstr('dev.eds'))]), 5: bytes([1, 2]), 6: u32(1234),
          7: u16(0xABCD), 8: u8(1), 9: u8(0x12), 10: u8(1), 11: u8(0), 12: u8(30)}
    r = u16(12)
    for a in range(1, 13):
        r += u16(a) + u16(0) + fi[a]
    c.pair(req(0x03, cls(0x37) + inst(0xC8), u16(12) + b''.join(u16(a) for a in range(1, 13))),
           rsp(0x03, r), 'File Get_Attribute_List')
    c.pair(gas(0x37, 0, 32),
           rsp(0x0E, u16(0xC8) + stringi([('eng', 0xDA, 4, sstr('EDS'))]) + stringi([('eng', 0xDA, 4, sstr('a.eds'))])
               + u16(0xC9) + stringi([('eng', 0xDA, 4, sstr('ICO'))]) + stringi([('eng', 0xDA, 4, sstr('a.ico'))])),
           'File class Directory')
    c.pair(req(0x08, cls(0x37) + inst(0), stringi([('eng', 0xDA, 4, sstr('New'))]) + u8(1)),
           rsp(0x08, u16(0xCA) + u8(2)), 'File Create with encoding')
    c.pair(req(0x08, cls(0x37) + inst(0), stringi([('eng', 0xDA, 4, sstr('New2'))])),
           rsp(0x08, status=0x02), 'File Create without encoding, error response')
    c.pair(req(0x4B, cls(0x37) + inst(0xC8), u8(200)), rsp(0x4B, u32(1000) + u8(200)), 'File Initiate_Upload')
    c.pair(req(0x4C, cls(0x37) + inst(0xC8), u32(1000) + u16(1) + bytes([1, 2])
               + stringi([('eng', 0xDA, 4, sstr('f.bin'))])),
           rsp(0x4C, u32(0) + u16(10) + u8(200)), 'File Initiate_Download')
    c.pair(req(0x4D, cls(0x37) + inst(0xC8), u32(16) + u32(100) + u8(200)),
           rsp(0x4D, u32(1000) + u8(200)), 'File Initiate_Partial_Read')
    c.pair(req(0x4E, cls(0x37) + inst(0xC8), u32(16) + u32(100) + u16(1) + bytes([1, 3])),
           rsp(0x4E, u32(1) + u16(5) + u8(200)), 'File Initiate_Partial_Write')
    c.pair(req(0x4F, cls(0x37) + inst(0xC8), u8(0)),
           rsp(0x4F, u8(0) + u8(1) + b'filedata' + u16(0x1234)), 'File Upload_Transfer')
    c.pair(req(0x50, cls(0x37) + inst(0xC8), u8(1) + u8(2) + b'filedata' + u16(0x1234)),
           rsp(0x50, u8(1)), 'File Download_Transfer')
    c.pair(req(0x51, cls(0x37) + inst(0xC8), b'\x01\x02'), rsp(0x51, b'\x03'), 'File Clear_File')

    # ------------------------------------------------ Time Sync object
    c.pair(req(0x01, cls(0x43) + inst(0)),
           rsp(0x01, u16(3) + u16(1) + u16(1) + u16(1) + u16(1) + u16(1) + u16(0x4B) + u16(7) + u16(30)),
           'Time Sync Get_Attributes_All class')
    clk = bytes(range(8))
    ts = {1: u8(1), 2: u8(1), 3: u64(1700000000123456), 4: u64(1700000000123456789),
          5: struct.pack('<q', -1500), 6: u64(20000), 7: struct.pack('<q', 3000),
          8: clk + u16(6) + u16(0x21) + u16(0x4E5D) + u16(37) + u16(0x3F) + u16(0x20) + u16(128) + u16(128),
          9: clk + u16(1) + u16(0xFFFF) + u32(0x7FFFFFFF),
          10: clk + u16(248) + u16(0xFE) + u16(0xFFFF) + u16(37) + u16(0x01) + u16(0xA0),
          11: u16(2), 12: u16(2) + u16(1) + u16(9) + u16(2) + u16(6),
          13: u16(1) + u16(1) + u16(1), 14: u16(1) + u16(1) + u16(1), 15: u16(1) + u16(1) + u16(0xFFFF),
          16: u8(128), 17: u8(128), 18: u8(0), 19: u16(0x88), 20: bytes([0x00, 0x00, 0x5E, 0]),
          21: u32(7) + b'Example', 22: u32(5) + b'1.2.3', 23: u32(4) + b'User',
          24: u16(1) + u16(1) + bytes([0, 0x1B, 0x19, 0, 1, 0, 0, 0]),
          25: u16(1) + u16(1) + b'IEEE 802.3\0\0\0\0\0\0' + u16(6) + bytes.fromhex('020000000a02') + bytes(10),
          26: u16(1) + u16(1) + u16(1) + u16(4) + bytes([192, 0, 2, 20]) + bytes(12),
          27: u16(1), 28: u64(1700000000123456) + struct.pack('<q', -5), 30: u16(37)}
    order = list(range(1, 29)) + [30]
    r = u16(len(order))
    for a in order:
        r += u16(a) + u16(0) + ts[a]
    c.pair(req(0x03, cls(0x43) + inst(1), u16(len(order)) + b''.join(u16(a) for a in order)),
           rsp(0x03, r), 'Time Sync Get_Attribute_List (all attributes)')

    # ------------------------------------------------ Base Energy
    be = {1: u16(1), 2: u16(3), 3: u16(100), 6: u16(0), 10: f32(1.5), 18: u16(0)}
    r = u16(6)
    for a in (1, 2, 3, 6, 10, 18):
        r += u16(a) + u16(0) + be[a]
    c.pair(req(0x03, cls(0x4E) + inst(1), u16(6) + b''.join(u16(a) for a in (1, 2, 3, 6, 10, 18))),
           rsp(0x03, r), 'Base Energy Get_Attribute_List')
    c.pair(req(0x08, cls(0x4E) + inst(0), u16(1) + u16(3) + u16(100) + u16(0x4F)),
           rsp(0x08, u16(2)), 'Base Energy Create')

    # ------------------------------------------------ Connection Configuration Object
    c.pair(req(0x01, cls(0xF3) + inst(0)),
           rsp(0x01, u16(1) + u32(10) + u32(2) + u16(3) + u32(0xCAFE)), 'CCO Get_Attributes_All class')
    c.pair(gas(0xF3, 0, 33), rsp(0x0E, u8(1)), 'CCO class Scanner Mode')
    c.pair(gas(0xF3, 1, 8), rsp(0x0E, cstr2('Conn A')), 'CCO instance Connection Name')
    cco_path = port_seg(1, 2) + cls(4) + inst(1) + cpt(0x65) + cpt(0x64)

    def cco_common(ot_rtf=0, to_rtf=0, extra=b''):
        flags = 0x0001 | (ot_rtf << 1) | (to_rtf << 4)
        d = u16(flags) + u16(1) + u16(12) + u16(34) + bytes([0x82, 1]) + u32(5)
        d += u8(1) + u8(0x01) + u32(10000) + u16(0x4810) + u32(20000) + u16(0x2810)
        d += bytes([len(cco_path) // 2, 0]) + cco_path
        d += u16(4) + b'\x01\x02\x03\x04' + u16(0) + cstr2('IO1')
        d += u16(1) + u16(4) + b'\xAA\xBB\xCC\xDD'
        d += u16(1) + u16(12) + u16(34) + bytes([0x82, 1])
        return d + extra
    large_ncp = u8(2) + u8(0x81) + u32(10000) + u32(0x48000010) + u32(20000) + u32(0x28000010)
    c.pair(req(0x01, cls(0xF3) + inst(1)),
           rsp(0x01, u8(0) + u8(0) + u16(0) + cco_common()), 'CCO Get_Attributes_All instance')
    c.pair(req(0x02, cls(0xF3) + inst(1), cco_common(5, 0, bytes(55) + u8(0) + u8(1) + large_ncp)),
           rsp(0x02), 'CCO Set_Attributes_All instance (safety, large NCP)')
    c.pair(req(0x02, cls(0xF3) + inst(2), cco_common(0, 0)), rsp(0x02),
           'CCO Set_Attributes_All instance (no optional data)')
    c.pair(req(0x02, cls(0xF3, 16), b'\x01\x02'), rsp(0x02, status=0x08),
           'CCO Set_Attributes_All (16 bit class, no instance), error')
    c.pair(req(0x01, cls(0xF3, 32)), rsp(0x01, b'\x01\x02'), 'CCO Get_Attributes_All (32 bit class, no instance)')
    c.pair(req(0x52, cls(0xF3) + inst(0), u16(1)), rsp(0x52, b'\x00\x00'), 'CCO Audit_Changes')
    c.pair(req(0x51, cls(0xF3) + inst(0), u16(0)), rsp(0x51), 'CCO Change_Complete')
    c.pair(req(0x4B, cls(0xF3) + inst(0), u16(0x2710)), rsp(0x4B, b'\x01\x00', status=0x0C),
           'CCO Kick_Timer, error response with data')
    c.pair(req(0x4F, cls(0xF3) + inst(0)), rsp(0x4F), 'CCO Change_Start')

    # ------------------------------------------------ Port object
    c.pair(req(0x01, cls(0xF4) + inst(0)),
           rsp(0x01, u16(2) + u16(2) + u16(2) + u16(1) + u16(4) + u16(1) + u16(4) + u16(2)),
           'Port Get_Attributes_All class')
    c.pair(req(0x01, cls(0xF4) + inst(1)),
           rsp(0x01, u16(4) + u16(2) + u16(2) + cls(0xF5) + inst(1) + sstr('Ethernet')
               + port_seg(2, 5)), 'Port Get_Attributes_All instance')
    pa = {8: u16(1) + u16(63), 9: ekey(4)[0:2] + ekey(4)[2:], 10: u32(0x7F),
          11: u8(2) + u8(2) + cls(0xF5) + inst(1) + u8(2) + cls(0xF6) + inst(1)}
    r = u16(4)
    for a in (8, 9, 10, 11):
        r += u16(a) + u16(0) + pa[a]
    c.pair(req(0x03, cls(0xF4) + inst(2), u16(4) + u16(8) + u16(9) + u16(10) + u16(11)),
           rsp(0x03, r), 'Port Get_Attribute_List')

    # ------------------------------------------------ PDD object
    c.pair(req(0x01, cls(0x108) + inst(0)),
           rsp(0x01, u16(1) + u16(5) + u16(5) + u16(2) + u16(18) + u16(19) + u16(1) + u16(0x4B)
               + u16(19) + u16(11) + u16(7) + u8(0x01) + u8(2) + u8(1) + u8(0) + sstr('CompA') + sstr('CompB')
               + u8(2) + b'\x01\x02' + b'\x03\x04' + u16(3) + b'\x05\x06\x07' + u32(0xF) + u8(1)),
           'PDD Get_Attributes_All class')
    c.pair(req(0x01, cls(0x108) + inst(1)),
           rsp(0x01, u8(1) + u8(0) + u32(0x1234) + u8(2) + u16(7) + u16(0)
               + u64(1700000000000000000) + u64(1700000001000000000) + sstr('Overtemp') + u32(1)
               + u8(0) + sstr('Cool down')), 'PDD Get_Attributes_All instance')
    c.pair(req(0x01, cls(0x108) + inst(2)),
           rsp(0x01, u8(0) + u8(0) + u32(0) + u8(0) + u16(1) + u16(0)), 'PDD Get_Attributes_All instance (short)')
    c.pair(req(0x01, cls(0x108) + inst(0), b'\x00'),
           rsp(0x01, u16(1) + u16(5) + u16(5) + u16(0) + u16(0) + u16(19) + u16(11) + u16(7) + u8(0)
               + u8(0) + u8(0) + u16(0)), 'PDD Get_Attributes_All class (short)')
    c.pair(req(0x4B, cls(0x108) + inst(0)), rsp(0x4B), 'PDD Reset Diagnostics Counter')
    c.pair(req(0x4C, cls(0x108) + inst(0), u16(1)), rsp(0x4C, u16(3)), 'PDD Get Next Active Instance')
    c.pair(req(0x4D, cls(0x108) + inst(0)), rsp(0x4D, u16(2) + u16(1) + u16(3)), 'PDD Get Active Instances')
    c.pair(req(0x4E, cls(0x108) + inst(0), u8(1)), rsp(0x4E, u16(1) + u16(4)),
           'PDD Get Instances By User Diagnostic Group')
    c.pair(req(0x4F, cls(0x108) + inst(0), u8(2)), rsp(0x4F, u16(1) + u16(5)),
           'PDD Get Active Instances By Status Signal')
    c.pair(req(0x50, cls(0x108) + inst(0), u8(0)), rsp(0x50, u16(2) + u16(1) + u16(2)),
           'PDD Get Instances By Component')
    c.pair(gas(0x108, 0, 11), rsp(0x0E, b'\x01\x00\x02'), 'PDD class Component Status List')
    c.pair(gas(0x108, 0, 12), rsp(0x0E, sstr('CompA') + sstr('CompB')), 'PDD class Component Name List')

    # ------------------------------------------------ PMV / PTV objects
    r = u16(2) + u16(1) + u16(4)
    pmv = {2: sstr('Flow'), 3: u16(0x1001), 4: f32(12.5), 5: u8(0x80), 6: f32(0.5), 7: f32(0.1),
           8: f32(0.05), 9: u32(0), 10: f32(0), 11: u8(0), 12: u16(0x1001), 13: u8(1), 14: f32(0),
           15: f32(0), 16: f32(100), 17: f32(100), 18: f32(200), 19: f32(-10), 20: u32(1), 21: u32(2),
           22: f32(0.1), 23: u32(3), 24: f32(20), 25: f32(1)}
    for a in range(2, 26):
        r += pmv[a]
    c.pair(req(0x01, cls(0x112) + inst(1)), rsp(0x01, r), 'PMV Get_Attributes_All instance')
    c.pair(req(0x01, cls(0x112) + inst(0)),
           rsp(0x01, u16(1) + u16(1) + u16(1) + u16(0) + u16(0) + u16(8) + u16(25) + u8(0)),
           'PMV Get_Attributes_All class')
    c.pair(req(0x01, cls(0x113) + inst(1)),
           rsp(0x01, u16(3) + cls(0x112) + inst(1) + sstr("Total") + u16(0x1001) + f32(5) + u8(0x80)
               + struct.pack('<d', 5.0) + u8(1) + f32(0) + u8(0)), 'PTV Get_Attributes_All instance')
    c.pair(gas(0x113, 1, 10), rsp(0x0E, u8(1)), 'PTV Totalizer Reset')

    # ------------------------------------------------ other generic services
    c.pair(req(0x11, cls(0x64) + inst(0), u8(3)), rsp(0x11, u8(3) + u8(1) + u8(2) + u8(3) + u8(4)),
           'Find_Next_Object_Instance')
    c.pair(req(0x08, cls(0x64) + inst(0), b'\x01\x02'), rsp(0x08, u16(5)), 'Create (generic)')
    c.pair(req(0x1C, cls(0x64) + inst(1)), rsp(0x1C, u8(1)), 'Group_Sync')
    c.pair(req(0x06, cls(0x64) + inst(1), b'\x01\x02'), rsp(0x06, b'\x01\x02'), 'Start with data')
    c.pair(req(0x07, cls(0x64) + inst(1)), rsp(0x07, status=0x0C, addl=[0x1234, 0x5678]),
           'Stop, error with additional status')
    c.pair(req(0x0E, cls(0x64) + inst(1) + att(1)), rsp(0x0E, b'\x01', status=0x1E),
           'Get_Attribute_Single, service error with data')
    c.pair(req(0x4B, cls(0x64) + inst(1), b'\x01\x02'), rsp(0x4B, b'\x03\x04'),
           'Vendor specific service (class generic)')
    c.pair(req(0x4C, cls(0x64) + inst(1)), rsp(0x4C), 'Vendor specific service without data')
    c.pair(req(0x0E, cls(0x64) + inst(1) + att(1)), rsp(0x0F), 'Response with a different service')

    # ------------------------------------------------ Multiple Service Packet
    services = [gas(1, 1, 1), gas(1, 1, 7), req(0x4B, cls(0x64) + inst(1), b'\x01\x02'),
                req(0x4B, cls(0x37) + inst(0xC8), u8(200)), req(0x52, cls(6) + inst(1),
                bytes([0x0A, 0x0E]) + u16(8) + gas(1, 1, 1) + bytes([1, 0, 1, 0]))]
    answers = [rsp(0x0E, u16(1)), rsp(0x0E, sstr('Name')), rsp(0x4B, b'\x05'),
               rsp(0x4B, u32(1000) + u8(200)), rsp(0x0E, u16(1))]
    c.pair(msp_req(services), msp_rsp(answers), 'Multiple Service Packet')
    c.pair(msp_req([gas(1, 1, 1), gas(1, 1, 2)]), msp_rsp([rsp(0x0E, u16(1)), rsp(0x0E, status=0x14)], status=0x1E),
           'Multiple Service Packet, service error')
    c.pair(msp_req([msp_req([gas(1, 1, 1)]), gas(1, 1, 3)]),
           msp_rsp([msp_rsp([rsp(0x0E, u16(1))]), rsp(0x0E, u16(34))]), 'Nested Multiple Service Packet')
    c.pair(msp_req([gas(1, 1, 1), gas(1, 1, 2)]), msp_rsp([rsp(0x0E, u16(1))]),
           'Multiple Service Packet, response with fewer services')
    c.pair(msp_req([]), msp_rsp([]), 'Multiple Service Packet without services')

    # ------------------------------------------------ EPATH segments
    paths = [
        ('16 bit class and instance, 32 bit attribute', cls(0x64, 16) + inst(1, 16) + att(1, 32)),
        ('32 bit class and instance, 16 bit attribute', cls(0x64, 32) + inst(0x10000, 32) + att(0x100, 16)),
        ('member segments', cls(0x64) + inst(1) + att(1) + mbr(1) + mbr(0x100, 16) + mbr(0x10000, 32)),
        ('connection points', cls(4) + inst(1) + cpt(0x65) + cpt(0x100, 16) + cpt(0x10000, 32)),
        ('extended logical', cls(0x64) + inst(1) + ext_logical(1, 5, 8) + ext_logical(2, 0x100, 16)
         + ext_logical(3, 0x10000, 32)),
        ('service ID segment', cls(0x64) + inst(1) + bytes([0x38, 0x0E])),
        ('electronic keys', ekey(4) + ekey(5, compat=0x03) + cls(0x64) + inst(1)),
        ('port segments', port_seg(1, 0) + port_seg(2, b'10.1.2.3') + port_seg(3, b'host1')
         + port_seg(20, 7) + port_seg(18, b'abc') + port_seg(5, 1) + cls(0x64) + inst(1)),
        ('network segments', bytes([0x41, 5, 0x42, 7, 0x43, 9]) + bytes([0x51, 2]) + u32(5000)
         + bytes([0x5F, 2]) + u16(0x0005) + u16(0xABCD) + cls(0x64) + inst(1)),
        ('symbolic segments', symbolic('Tag') + symbolic('Ab') + bytes([0x60, 0x22]) + b'abcd'
         + bytes([0x60, 0x41]) + b'xyz\0' + bytes([0x60, 0xC6, 7, 0]) + bytes([0x60, 0xC7]) + u16(300)
         + bytes([0x60, 0xC8]) + u32(70000)),
        ('ANSI symbol segments', ansi_sym('Program:Main') + ansi_sym('Tag1') + bytes([0x91, 0])
         + bytes([0x28, 3])),
        ('simple data segment', cls(0x64) + inst(1) + simple_data(b'\x01\x02\x03\x04') + simple_data(b'')),
    ]
    for label, p in paths:
        c.pair(req(0x0E, p), rsp(0x0E, b'\x01\x02'), 'EPATH ' + label)
    c.pair(req(0x4C, ansi_sym('Tag01') + bytes([0x28, 2]), u16(1)), rsp(0x4C, u16(0xC4) + u32(5)),
           'Symbol read (Logix Read Tag)')

    # ------------------------------------------------ PCCC object
    rid = u8(7) + u16(1) + u32(0x11223344)
    pccc = [
        ('cmd 06 fnc 03', u8(0x06) + u8(0) + u16(1) + u8(0x03) + b'\x00'),
        ('cmd 07 fnc 01', u8(0x07) + u8(0) + u16(2) + u8(0x01) + b'\x00'),
        ('cmd 0F fnc 80', u8(0x0F) + u8(0) + u16(3) + u8(0x80) + u8(0x01)),
        ('cmd 0F fnc 88', u8(0x0F) + u8(0) + u16(4) + u8(0x88) + u8(2) + u8(4) + u8(0xA2) + b'\x02\x07\x89'
         + u8(1) + u8(0x29)),
        ('cmd 0F fnc A2', u8(0x0F) + u8(0) + u16(5) + u8(0xA2) + bytes([2, 7, 0x89, 0, 0])),
        ('cmd 0F fnc AA', u8(0x0F) + u8(0) + u16(6) + u8(0xAA) + bytes([2, 7, 0x89, 0, 0]) + b'\x01\x02'),
        ('cmd 0F fnc 29', u8(0x0F) + u8(0) + u16(7) + u8(0x29) + b'\x01\x02\x03'),
        ('cmd 01', u8(0x01) + u8(0) + u16(8) + u8(0x00) + b'\x00'),
        ('cmd 06 fnc 00 without data', u8(0x06) + u8(0) + u16(9) + u8(0x00)),
    ]
    for label, cmd in pccc:
        c.pair(req(0x4B, cls(0x67) + inst(1), rid + cmd),
               rsp(0x4B, rid + u8(0x4F) + u8(0) + u16(1) + b'\x01\x02'), 'PCCC ' + label)
    c.pair(req(0x4B, cls(0x67) + inst(1), rid + u8(0x0F) + u8(0) + u16(10) + u8(0xA2) + bytes([2, 7, 0x89, 0, 0])),
           rsp(0x4B, rid + u8(0x4F) + u8(0xF0) + u16(10) + u8(0x07)), 'PCCC response with extended status')
    c.pair(req(0x4B, cls(0x67) + inst(1), rid + u8(0x06) + u8(0) + u16(11) + u8(0x03) + b'\x00'),
           rsp(0x4B, rid + u8(0x46) + u8(0) + u16(11)), 'PCCC response without data')
    c.pair(req(0x4B, cls(0x67) + inst(1), rid + u8(0x06) + u8(0) + u16(12) + u8(0x03) + b'\x00'),
           rsp(0x4B, rid + u8(0x46) + u8(0) + u16(12) + b'\x01\x02', addl=[0x0001]),
           'PCCC response with additional status')

    # ------------------------------------------------ Modbus object
    mbp = cls(0x44) + inst(1)
    c.pair(req(0x4B, mbp, u16(0) + u16(8)), rsp(0x4B, b'\x5A'), 'Modbus Read Discrete Inputs')
    c.pair(req(0x4C, mbp, u16(0) + u16(8)), rsp(0x4C, b'\xA5'), 'Modbus Read Coils')
    c.pair(req(0x4D, mbp, u16(0) + u16(2)), rsp(0x4D, u16(1) + u16(2)), 'Modbus Read Input Registers')
    c.pair(req(0x4E, mbp, u16(0) + u16(2)), rsp(0x4E, u16(3) + u16(4)), 'Modbus Read Holding Registers')
    c.pair(req(0x4F, mbp, u16(0) + u16(10) + b'\xFF\x03'), rsp(0x4F, u16(0) + u16(10)), 'Modbus Write Coils')
    c.pair(req(0x50, mbp, u16(0) + u16(2) + u16(5) + u16(6)), rsp(0x50, u16(0) + u16(2)),
           'Modbus Write Holding Registers')
    c.pair(req(0x51, mbp, bytes([0x03, 0x00, 0x00, 0x00, 0x02])), rsp(0x51, bytes([0x03, 0x04, 0, 1, 0, 2])),
           'Modbus Passthrough')
    c.pair(req(0x52, mbp, b'\x01\x02'), rsp(0x52, b'\x03\x04'), 'Modbus unknown service')
    c.pair(req(0x4E, mbp, u16(0) + u16(2)), rsp(0x4E, b'\x01\x00', status=0x2B), 'Modbus error response')
    c.pair(req(0x4E, mbp, u16(0) + u16(2)), rsp(0x4E, b'\x02', status=0x1E), 'Modbus service error response')
    c.pair(req(0x4E, mbp), rsp(0x4E), 'Modbus request and response without data')

    # ------------------------------------------------ Connection Manager
    mr_path = cls(2) + inst(1)
    # Class 3 connection to the Message Router
    c.pair(fwd_open(0x80000001, 0x00010001, 0x0101, mr_path, ot_params=0x43F4, to_params=0x43F4,
                    ttt=0xA3, timeout_mult=2), fwd_open_rsp(0x80000001, 0x00010001, 0x0101),
           'Forward Open class 3 to the Message Router')
    c.sud(True, 0x80000001, 1, gas(1, 1, 7), 'Class 3 connected request')
    c.sud(False, 0x00010001, 1, rsp(0x0E, sstr('Product')), 'Class 3 connected response')
    c.sud(True, 0x80000001, 2, msp_req([gas(1, 1, 1), gas(1, 1, 3)]), 'Class 3 connected MSP request')
    c.sud(False, 0x00010001, 2, msp_rsp([rsp(0x0E, u16(1)), rsp(0x0E, u16(34))]), 'Class 3 connected MSP response')
    c.pair(fwd_close(0x0101, mr_path), fwd_close_rsp(0x0101, b'\x01\x02'), 'Forward Close (class 3)')
    # Class 3 connection to an assembly (connected data shown as implicit)
    c.pair(fwd_open(0x80000002, 0x00010002, 0x0102, cls(4) + inst(1) + cpt(0x65), ttt=0xA3),
           fwd_open_rsp(0x80000002, 0x00010002, 0x0102), 'Forward Open class 3 to an assembly')
    c.sud(True, 0x80000002, 1, b'\x01\x02\x03\x04', 'Class 3 data to an assembly')
    c.sud(False, 0x00010002, 1, b'\x05\x06', 'Class 3 data from an assembly')
    c.pair(fwd_close(0x0102, cls(4) + inst(1) + cpt(0x65)), fwd_close_rsp(0x0102), 'Forward Close (assembly)')
    # Class 1 I/O connection
    io_path = ekey(4) + cls(4) + inst(1) + cpt(0x96) + cpt(0x64) + simple_data(b'\x00\x01\x02\x03')
    c.pair(fwd_open(0x80000003, 0x00010003, 0x0103, io_path, ot_params=0x4814, to_params=0x2814,
                    ttt=0x01, timeout_mult=9), fwd_open_rsp(0x80000003, 0x00010003, 0x0103, app=b'\x01\x02'),
           'Forward Open class 1 I/O')
    for k in range(2):
        c.io(True, 0x80000003, k + 1, u16(k + 1) + u32(1) + b'\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0',
             'Class 1 I/O O->T')
        c.io(False, 0x00010003, k + 1, u16(k + 1) + b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c',
             'Class 1 I/O T->O')
    c.pair(fwd_close(0x0103, io_path), fwd_close_rsp(0x0103), 'Forward Close (class 1)')
    # Large Forward Open
    c.pair(fwd_open(0x80000004, 0x00010004, 0x0104, cls(4) + inst(1) + cpt(0x97) + cpt(0x65),
                    ot_params=0x42000200, to_params=0x22000200, ttt=0x01, service=0x5B, timeout_mult=7),
           fwd_open_rsp(0x80000004, 0x00010004, 0x0104, service=0x5B), 'Large Forward Open')
    c.pair(fwd_close(0x0104, cls(4) + inst(1)), fwd_close_rsp(0x0104), 'Forward Close (large)')
    # Concurrent Forward Open with a concurrent connection network segment
    hops = (u8(4) + u8(0) + bytes([1, 0x01, 3]) + bytes([2, 0x11]) + bytes([192, 0, 2, 30])
            + bytes([3, 0x21]) + cstr('plc') + b'\0' + bytes([4, 0x31]) + b'\0')
    ccseg = bytes([0x5F, len(hops) // 2 + 1]) + u16(0x0002) + hops
    cc_path = ccseg + cls(4) + inst(1) + cpt(0x98) + cpt(0x66)
    c.pair(fwd_open(0x80000005, 0x00010005, 0x0105, cc_path, ot_params=0x4814, to_params=0x2814,
                    ttt=0x01, service=0x5C, cc_version=1),
           fwd_open_rsp(0x80000005, 0x00010005, 0x0105, service=0x5C), 'Concurrent Forward Open')
    c.io(True, 0x80000005, 1, cc_packet(1, u16(1) + u32(1) + b'\x11\x22'), 'Concurrent connection I/O O->T')
    c.io(False, 0x00010005, 1, cc_packet(1, u16(1) + b'\x33\x44'), 'Concurrent connection I/O T->O')
    c.pair(fwd_close(0x0105, cc_path, service=0x5E), fwd_close_rsp(0x0105, service=0x5E),
           'Concurrent Forward Close')
    # Null Forward Open and a listen only connection
    c.pair(fwd_open(0, 0, 0x0106, cls(4) + inst(1), ot_params=0x0000, to_params=0x0000, ttt=0x01),
           fwd_open_rsp(0, 0, 0x0106), 'Null Forward Open')
    c.pair(fwd_open(0x80000007, 0x00010007, 0x0107, cls(4) + inst(1) + cpt(0xFE) + cpt(0x64),
                    ot_params=0x4802, to_params=0x2810, ttt=0x01),
           fwd_open_rsp(0x80000007, 0x00010007, 0x0107), 'Forward Open listen only (no Forward Close)')
    # Forward Open response with a different connection triad
    c.pair(fwd_open(0x80000008, 0x00010008, 0x0108, cls(4) + inst(1), ttt=0x01),
           fwd_open_rsp(0x80000018, 0x00010018, 0x0118), 'Forward Open, response with another triad')
    # Forward Open error responses
    errs = [
        ('RPI not acceptable', [0x0112, 0x0101, 0x10, 0, 0x20, 0]),
        ('invalid configuration size', [0x0126, 10]),
        ('invalid O->T size', [0x0127, 4]),
        ('invalid T->O size', [0x0128, 6]),
        ('connection in use', [0x0100, 1, 2]),
        ('unknown extended status', [0x0999]),
    ]
    for k, (label, addl) in enumerate(errs):
        tri = u16(0x0200 + k) + u16(0x1234) + u32(0x89ABCDEF)
        c.pair(fwd_open(0x80000100 + k, 0x00010100 + k, 0x0200 + k, cls(4) + inst(1), ttt=0x01),
               rsp(0x54, tri + bytes([0, 0]), status=1, addl=addl), 'Forward Open error: ' + label)
    c.pair(fwd_open(0x80000110, 0x00010110, 0x0210, cls(4) + inst(1), ttt=0x01),
           rsp(0x54, u16(0x0210) + u16(0x1234) + u32(0x89ABCDEF), status=1),
           'Forward Open error without additional status or remaining path size')
    c.pair(fwd_open(0x80000111, 0x00010111, 0x0211, cls(4) + inst(1), ttt=0x01),
           rsp(0x54, u16(0x0211) + u16(0x1234) + u32(0x89ABCDEF) + bytes([2, 0]), status=2),
           'Forward Open error, resource unavailable')
    c.pair(fwd_close(0x0300, cls(4) + inst(1)),
           rsp(0x4E, u16(0x0300) + u16(0x1234) + u32(0x89ABCDEF) + bytes([0, 0]), status=1, addl=[0x0107]),
           'Forward Close error (connection not found)')
    # Unconnected Send
    route = port_seg(1, 0)
    c.pair(ucs(gas(1, 1, 7), route), rsp(0x0E, sstr('Routed')), 'Unconnected Send (embedded Get_Attribute_Single)')
    c.pair(ucs(req(0x4B, cls(0x67) + inst(1), rid + u8(0x06) + u8(0) + u16(20) + u8(0x03)), route),
           rsp(0x4B, rid + u8(0x46) + u8(0) + u16(20) + b'\x01'), 'Unconnected Send (embedded PCCC, odd length)')
    c.pair(ucs(req(0x4B, cls(0x37) + inst(0xC8), u8(200)), route),
           rsp(0x4B, u32(10) + u8(200)), 'Unconnected Send (embedded File Initiate_Upload)')
    c.pair(ucs(req(0x4B, cls(0x64) + inst(1)), route), rsp(0x4B, b'\x01\x02'),
           'Unconnected Send (embedded vendor service)')
    c.pair(ucs(gas(1, 1, 7), route), rsp(0x52, bytes([1, 0]), status=1, addl=[0x0204]),
           'Unconnected Send error: request timed out')
    c.pair(ucs(gas(1, 1, 7), route), rsp(0x52, bytes([1, 0]), status=4),
           'Unconnected Send error: path segment error')
    c.pair(ucs(gas(1, 1, 7), route), rsp(0x52, b'', status=8), 'Unconnected Send error: service not supported')
    c.pair(ucs(gas(1, 1, 7), route), rsp(0x0E, b'', status=0x14), 'Unconnected Send, embedded error')
    c.pair(ucs(fwd_open(0x80000009, 0x00010009, 0x0109, cls(4) + inst(1), ttt=0x01), port_seg(1, 3)),
           fwd_open_rsp(0x80000009, 0x00010009, 0x0109), 'Unconnected Send (embedded Forward Open)')
    # Get Connection Owner and other services
    c.pair(req(0x5A, cls(6) + inst(1), bytes([0, 3]) + cls(4) + inst(1) + cpt(0x65)),
           rsp(0x5A, bytes([1, 1, 0, 2]) + u16(0x0101) + u16(0x1234) + u32(0x89ABCDEF)),
           'Get Connection Owner')
    c.pair(req(0x56, cls(6) + inst(1), u16(1)), rsp(0x56, b'\x01\x02\x03\x04'), 'Get Connection Data')
    c.pair(req(0x57, cls(6) + inst(1)), rsp(0x57, status=0x08), 'Search Connection Data (no data)')
    # Orphan Forward Open response (request not captured)
    c.one(False, fwd_open_rsp(0x8000000A, 0x0001000A, 0x010A), 'Forward Open response without request')
    # Safety Forward Opens (analysis and safety application reply)
    sn = u16(100) + u32(1000)  # SNN: time (ms) and date
    unid = u32(0x01020304) + u16(5) + u32(0x00000010)

    def safety_seg(fmt, scid=True):
        sccrc = u32(0x11223344) if scid else u32(0)
        scts = (u32(5000) + u16(9000)) if scid else bytes(6)
        if fmt == 0:
            body = (u8(0) + sccrc + scts + u32(20000) + u16(0x4803) + unid + unid + u16(4) + u16(4)
                    + u16(100) + u8(2) + u8(1) + u32(0xAABBCCDD) + u32(0x00020001))
        elif fmt == 1:
            body = u8(0) + u32(0x00020001) + u32(20000) + u16(0x4803)
        else:
            body = (u8(0) + sccrc + scts + u32(20000) + u16(0x4803) + unid + unid + u16(4) + u16(4)
                    + u16(100) + u8(2) + u8(1) + u16(10) + u32(0xAABBCCDD) + u32(0x00020001) + u16(7) + u16(8))
        data = u8(fmt) + body
        if len(data) % 2:
            data += b'\0'
        return bytes([0x50, len(data) // 2]) + data
    sp = [
        ('safety extended, type 2a, consumer', safety_seg(2) + cls(0x3A) + inst(1) + cpt(0x80), 0x01, True),
        ('safety base, type 2b, producer', safety_seg(0, False) + cls(0x3A) + inst(2) + cpt(0x81), 0x81, True),
        ('safety extended, type 1 (with data)', simple_data(b'\x01\x02') + safety_seg(2) + cls(0x3A)
         + inst(3) + cpt(0x82), 0x01, True),
        ('safety router format', safety_seg(1) + cls(0x3A) + inst(4) + cpt(0x83), 0x01, False),
        ('safety reserved format', bytes([0x50, 2, 5, 0, 1, 2]) + cls(0x3A) + inst(5), 0x01, False),
    ]
    for k, (label, path, ttt, extended) in enumerate(sp):
        serial = 0x0400 + k
        if 'base' in label:
            app = u16(1) + u16(0x1234) + u32(0x55667788) + u16(serial)
        elif extended:
            app = u16(1) + u16(0x1234) + u32(0x55667788) + u16(serial) + u16(10) + u16(20)
        else:
            app = u16(1) + u16(0x1234) + u32(0x55667788) + u16(serial)
        c.pair(fwd_open(0x80000400 + k, 0x00010400 + k, serial, path, ot_params=0x4806, to_params=0x2806,
                        ttt=ttt, timeout_mult=[0, 3, 4, 5, 6][k]), fwd_open_rsp(0x80000400 + k, 0x00010400 + k, serial, app=app),
               'Forward Open ' + label)
        c.pair(fwd_close(serial, path), fwd_close_rsp(serial), 'Forward Close ' + label)

    # ------------------------------------------------ more branches
    # Symbol in a connection path and in a Multiple Service Packet
    c.pair(fwd_open(0x80000500, 0x00010500, 0x0500, ansi_sym('IOTag') + cls(4) + inst(1), ttt=0x01),
           fwd_open_rsp(0x80000500, 0x00010500, 0x0500), 'Forward Open with a symbol in the connection path')
    c.pair(fwd_close(0x0500, ansi_sym('IOTag')), fwd_close_rsp(0x0500), 'Forward Close (symbol path)')
    c.pair(msp_req([req(0x4C, ansi_sym('Tag01') + bytes([0x28, 2]), u16(1)), gas(1, 1, 1)]),
           msp_rsp([rsp(0x4C, u16(0xC4) + u32(5)), rsp(0x0E, u16(1))]), 'Multiple Service Packet with a symbol')
    # Motion axis connection with a configuration block in the data segment
    c.pair(fwd_open(0x80000501, 0x00010501, 0x0501, ekey(4) + cls(0x42) + inst(1) + cpt(2)
                    + simple_data(bytes([1, 0x01, 0, 0]) + u32(7) + b'\x00\x00'), ttt=0x01),
           fwd_open_rsp(0x80000501, 0x00010501, 0x0501), 'Forward Open motion axis (configuration block)')
    c.pair(fwd_close(0x0501, cls(0x42) + inst(1)), fwd_close_rsp(0x0501), 'Forward Close (motion axis)')
    # Packed segments in Port attribute 9 (Chassis Identity)
    c.pair(gas(0xF4, 1, 9), rsp(0x0E, bytes([0x21]) + u16(0x100)), 'Port Chassis Identity, packed 16 bit class')
    c.pair(gas(0xF4, 1, 9), rsp(0x0E, bytes([0x22]) + u32(0x10000)), 'Port Chassis Identity, packed 32 bit class')
    c.pair(gas(0xF4, 1, 9), rsp(0x0E, bytes([0x3C, 1, 5])), 'Port Chassis Identity, packed extended logical')
    # DATE_AND_TIME (Safety Supervisor attribute 17)
    c.pair(gas(0x39, 1, 17), rsp(0x0E, u32(3600000) + u16(18000)), 'Safety Supervisor Time')
    c.pair(gas(0x39, 1, 17), rsp(0x0E, u32(0) + u16(0)), 'Safety Supervisor Time (zero)')
    # STRINGN with an unsupported character size
    c.pair(gas(1, 1, 13), rsp(0x0E, stringi([('eng', 0xD9, 4, u16(3) + u16(1) + b'abc')])),
           'Identity International Product Name, STRINGN with 3 octet characters')
    # Get_Attribute_List: attribute without data, status codes that keep the data
    c.pair(req(0x03, cls(0x37) + inst(0), u16(1) + u16(32)), rsp(0x03, u16(1) + u16(32) + u16(0)),
           'File class Get_Attribute_List, Directory without data')
    c.pair(req(0x03, cls(1) + inst(1), u16(2) + u16(1) + u16(99)),
           rsp(0x03, u16(2) + u16(1) + u16(0) + u16(1) + u16(99) + u16(0x14), status=0x0A),
           'Get_Attribute_List, attribute list error')
    c.pair(req(0x03, cls(1) + inst(1), u16(1) + u16(1)), rsp(0x03, u16(1) + u16(1) + u16(0) + u16(1), status=0x1D),
           'Get_Attribute_List, invalid attribute value list')
    c.pair(gas(1, 1, 1), rsp(0x0E, u16(1), status=0x05), 'Get_Attribute_Single, error status with data')
    # Forward Close of an unknown connection
    c.pair(fwd_close(0x0777, cls(4) + inst(1)), fwd_close_rsp(0x0777), 'Forward Close of an unknown connection')
    # Unconnected Send errors that are reported by the router
    for es in (0x0311, 0x0312, 0x0315, 0x0318, 0x0100):
        c.pair(ucs(gas(1, 1, 7), route), rsp(0x52, bytes([1, 0]), status=1, addl=[es]),
               'Unconnected Send error 0x%04x' % es)
    c.pair(req(0x56, cls(6) + inst(1), u16(1)), rsp(0x56, b'\x01\x02', status=1, addl=[0x0100]),
           'Get Connection Data, error with data')
    # Connection Configuration Object: target configuration data, T->O safety
    c.pair(req(0x02, cls(0xF3) + inst(3), cco_common(0, 5, bytes(55)).replace(
        u16(0) + cstr2('IO1'), u16(2) + b'\x09\x08' + cstr2('IO1'))), rsp(0x02),
           'CCO Set_Attributes_All instance (T->O safety, target configuration)')
    # Object specific service from the ENIP table (DLR Verify_Fault_Location)
    c.pair(req(0x4B, cls(0x47) + inst(1)), rsp(0x4B, b'\x01\x02'), 'DLR Verify_Fault_Location')
    # A request over a connection on port 44818 at both ends (not classified,
    # so no request information)
    c.one(True, gas(1, 1, 1), 'Get_Attribute_Single between two 44818 ports', c.get_stream(ENIP_PORT))
    return c

def build_malformed():
    c = Capture()
    # Attributes cut short or with inconsistent counts
    bad = [
        (1, 1, 4, b'\x01', 'Identity Revision cut short'),
        (1, 1, 5, b'\x01', 'Identity Status cut short'),
        (1, 1, 11, b'en', 'Identity Active Language of 2 octets'),
        (1, 1, 12, b'engd', 'Identity Supported Language List of 4 octets'),
        (1, 1, 14, b'\x01\x02\x03\x04\x05\x06', 'Identity Semaphore of 6 octets'),
        (1, 1, 19, b'\x01', 'Identity Protection Mode cut short'),
        (1, 1, 7, b'\x09ab', 'Identity Product Name longer than the data'),
        (1, 1, 13, stringi([('eng', 0xDB, 4, b'xy')]), 'Identity International Product Name, unknown string type'),
        (1, 1, 38, b'\x01\x02', 'Identity Supported Device Type Revisions cut short'),
        (1, 0, 4, u16(5) + u16(1), 'Optional Attribute List count larger than the data'),
        (1, 0, 5, u16(5) + u16(1), 'Optional Service List count larger than the data'),
        (2, 1, 1, u16(5) + u16(1) + u16(2), 'Message Router Object List count larger than the data'),
        (0xF4, 1, 3, u16(4) + cls(1), 'Port Link Object path size larger than the data'),
    ]
    for a in (8, 9, 10, 12, 13, 14, 15, 19, 20, 21, 22, 23, 24, 25, 26, 28):
        bad.append((0x43, 1, a, b'\x01', 'Time Sync attribute %d cut short' % a))
    for a in (12, 13, 14, 15, 24, 25, 26):
        bad.append((0x43, 1, a, u16(3) + b'\x01\x00', 'Time Sync attribute %d port count larger than the data' % a))
    bad += [
        (0x43, 1, 21, u32(65) + b'x' * 65, 'Time Sync Product Description longer than 64'),
        (0x43, 1, 21, u32(10) + b'abc', 'Time Sync Product Description size larger than the data'),
        (0x43, 1, 22, u32(33) + b'x' * 33, 'Time Sync Revision Data longer than 32'),
        (0x43, 1, 22, u32(10) + b'abc', 'Time Sync Revision Data size larger than the data'),
        (0x43, 1, 23, u32(129) + b'x' * 129, 'Time Sync User Description longer than 128'),
        (0x43, 1, 23, u32(10) + b'abc', 'Time Sync User Description size larger than the data'),
    ]
    for cl, i, a, data, label in bad:
        c.pair(gas(cl, i, a), rsp(0x0E, data), label)
    # Bad path segments
    segs = [
        (bytes([0x23, 0, 0, 0]), 'class segment with the reserved format'),
        (cls(1) + bytes([0x27, 0, 0, 0]), 'instance segment with the reserved format'),
        (cls(1) + inst(1) + bytes([0x33, 0, 0, 0]), 'attribute segment with the reserved format'),
        (cls(4) + inst(1) + bytes([0x2F, 0, 0, 0]), 'connection point segment with the reserved format'),
        (bytes([0x5F, 0, 0, 0]), 'extended network segment without a subtype'),
        (bytes([0x5F, 9, 5, 0]), 'extended network segment longer than the data'),
        (bytes([0x60, 0xC9, 0, 0]), 'symbolic segment with an unknown numeric format'),
        (bytes([0x60, 0x60, 0, 0]), 'symbolic segment with an unknown extended format'),
        (bytes([0x34, 0x06]) + bytes(8), 'electronic key with an unknown format'),
        (bytes([0x35, 0x04]) + bytes(8), 'special segment with a reserved format'),
        (bytes([0x44, 0x00]), 'reserved network segment type'),
        (bytes([0x39, 0x0E]), 'service ID segment with a 16 bit format'),
        (bytes([0x82, 0x00]), 'reserved data segment type'),
        (bytes([0xA0, 0x00]), 'reserved segment type'),
    ]
    for p, label in segs:
        c.pair(req(0x0E, p), rsp(0x0E, b'\x01'), 'EPATH ' + label)
    c.pair(bytes([0x0E, 5]) + cls(1) + inst(1), None, 'Request path size larger than the data')
    # Services with missing or inconsistent data
    c.pair(req(0x03, cls(1) + inst(1)), rsp(0x03), 'Get_Attribute_List request without a count')
    c.pair(req(0x03, cls(1) + inst(1), u16(3) + u16(1)), rsp(0x03, u16(3) + u16(1) + u16(0) + u16(1)),
           'Get_Attribute_List count larger than the data')
    c.pair(req(0x04, cls(1) + inst(1)), rsp(0x04, b'\x01'), 'Set_Attribute_List request and response without a count')
    c.pair(req(0x04, cls(1) + inst(1), u16(3) + u16(8) + u8(3)), rsp(0x04, u16(3) + u16(8) + u16(0)),
           'Set_Attribute_List count larger than the data')
    c.pair(req(0x0A, cls(2) + inst(1), b'\x01'), rsp(0x0A, b'\x01'), 'Multiple Service Packet without a count')
    c.pair(req(0x0A, cls(2) + inst(1), u16(10) + u16(4)), None, 'Multiple Service Packet count larger than the data')
    c.pair(req(0x0A, cls(2) + inst(1), u16(2) + u16(200) + u16(6) + gas(1, 1, 1)), None,
           'Multiple Service Packet offset past the end')
    c.pair(req(0x0A, cls(2) + inst(1), u16(3) + u16(8) + u16(8) + u16(16) + gas(1, 1, 1) + gas(1, 1, 2)), None,
           'Multiple Service Packet offsets out of order')
    c.pair(req(0x03, cls(1) + inst(1), u16(1) + u16(1)), rsp(0x03, b'\x01'), 'Get_Attribute_List response cut short')
    c.pair(req(0x03, cls(0xF4) + inst(1), u16(1) + u16(9)), rsp(0x03, u16(1) + u16(9) + u16(0)),
           'Port Get_Attribute_List, Chassis Identity without data')
    c.pair(req(0x11, cls(0x64) + inst(0), u8(3)), rsp(0x11), 'Find_Next_Object_Instance response without data')
    c.pair(req(0x11, cls(0x64) + inst(0), u8(3)), rsp(0x11, u8(5) + u8(1) + u8(2)),
           'Find_Next_Object_Instance count larger than the data')
    # Connection Manager
    c.pair(fwd_open(0x80000601, 0x00010601, 0x0601, cls(4) + inst(1), ttt=0x01),
           rsp(0x54, u16(0x0601) + u16(0x1234) + u32(0x89ABCDEF), status=1, addl=[0x0112]),
           'Forward Open error RPI not acceptable without the RPI values')
    c.pair(fwd_close(0x0602, cls(4) + inst(1)), fwd_close_rsp(0x0602)[:-2] + bytes([5, 0]) + b'\x01\x02',
           'Forward Close response with application reply longer than the data')
    # Concurrent connection with an invalid packet type
    hops = u8(1) + u8(0) + bytes([1, 0x01, 3, 0])
    ccseg = bytes([0x5F, len(hops) // 2 + 1]) + u16(0x0002) + hops
    c.pair(fwd_open(0x80000603, 0x00010603, 0x0603, ccseg + cls(4) + inst(1), ttt=0x01, service=0x5C, cc_version=1),
           fwd_open_rsp(0x80000603, 0x00010603, 0x0603, service=0x5C), 'Concurrent Forward Open')
    c.io(True, 0x80000603, 1, u16(2) + u16(10) + u32(1) + b'\x01\x02' + u32(0), 'Concurrent connection packet type 2')
    c.io(True, 0x80000603, 2, cc_packet(2, b'\x01\x02')[:-4] + u32(0), 'Concurrent connection packet with a bad CRC')
    # Truncated messages
    c.pair(gas(1, 1, 1)[:3], rsp(0x0E)[:3], 'Truncated request and response')
    c.pair(req(0x52, cls(6) + inst(1), bytes([0x0A, 0x0E]) + u16(40) + gas(1, 1, 1)), None,
           'Unconnected Send with message size larger than the data')
    c.pair(req(0x54, cls(6) + inst(1), bytes([0x0A, 0x0E]) + u32(1)), None, 'Forward Open request cut short')
    c.pair(req(0x4B, cls(0x67) + inst(1), u8(7) + u16(1)), None, 'PCCC request cut short')
    return c

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, builder in (('cip-coverage.pcap', build_main),
                          ('cip-coverage-malformed.pcap', build_malformed)):
        c = builder()
        write_pcap(os.path.join(out, name), c.frames)
        with open(os.path.join(out, name.replace('.pcap', '.frames.txt')), 'w') as f:
            for i, l in enumerate(c.labels):
                f.write('%d\t%s\n' % (i + 1, l))
        print(name, len(c.frames), 'frames')


if __name__ == '__main__':
    main()

# Helper module for the enip capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Packet building helpers for the ENIP generator: Ethernet/IPv4/TCP/UDP
framing, EtherNet/IP encapsulation, CIP requests and responses, EPATH
segments and Connection Manager services. Taken from mkcip.py of the CIP
coverage capture. Everything is built with struct; no captured traffic
is used."""

import struct

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

    def __init__(self, cport, cseq=1000, sseq=5000, sport=ENIP_PORT):
        self.cport = cport
        self.sport = sport
        self.seq = {True: cseq, False: sseq}

    def frame(self, from_client, payload, flags=0x18):
        if from_client:
            src, dst, sport, dport = CLI_IP, SRV_IP, self.cport, self.sport
            smac, dmac = CLI_MAC, SRV_MAC
        else:
            src, dst, sport, dport = SRV_IP, CLI_IP, self.sport, self.cport
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

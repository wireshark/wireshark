#!/usr/bin/env python3
# Generates test/captures/cipsafety_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CIP Safety dissector
(epan/dissectors/packet-cipsafety.c).

CIP Safety connections are opened with a Forward Open whose connection
path holds a safety network segment (EtherNet/IP SendRRData on TCP
44818); the safety I/O then runs as class 0 data over UDP 2222 and is
dissected with the CRCs computed from the connection triads. The Safety
Supervisor (0x39) and Safety Validator (0x3A) objects are reached with
explicit messages. The Decode As entry points (cipsafety_bd/ed/bt/et)
and the plain "cipsafety" dissector are reached with Exported PDU
records, as in the reproducer of the fix on the branch.

Every packet is built from scratch with struct; no captured traffic is
used. Addresses are from the documentation ranges, the multicast group
from the organization-local scope.

Usage: mkcipsafety.py <output directory>

Writes:
  cipsafety-coverage.pcapng            two interfaces (Ethernet and
                                       Exported PDU): every I/O format
                                       (base/extended, short/long,
                                       unicast/multicast, consumer and
                                       producer direction) with correct
                                       CRCs, Supervisor services and
                                       attributes, Validator attributes,
                                       SERCOS III link attributes, the
                                       Exported PDU entry points
  cipsafety-coverage-malformed.pcapng  bad mode bytes, CRCs and
                                       complement data, short I/O, odd
                                       lengths, truncated attributes, the
                                       unmodified reproducer
"""

import os
import struct
import sys

# ---------------------------------------------------------------- framing

CLI_MAC = bytes.fromhex('020000000b01')
SRV_MAC = bytes.fromhex('020000000b02')
MC_MAC = bytes.fromhex('01005e400101')
CLI_IP = (192, 0, 2, 30)
SRV_IP = (192, 0, 2, 40)
MC_IP = (239, 192, 1, 1)
ENIP_PORT = 44818
IO_PORT = 2222
SESSION = 0x0BADC0DE


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
    def __init__(self, cport):
        self.cport = cport
        self.seq = {True: 1000 + cport, False: 9000 + cport}

    def frame(self, from_client, payload):
        if from_client:
            src, dst, sport, dport, smac, dmac = CLI_IP, SRV_IP, self.cport, ENIP_PORT, CLI_MAC, SRV_MAC
        else:
            src, dst, sport, dport, smac, dmac = SRV_IP, CLI_IP, ENIP_PORT, self.cport, SRV_MAC, CLI_MAC
        seq = self.seq[from_client]
        ack = self.seq[not from_client]
        self.seq[from_client] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
        return eth(smac, dmac, ipv4(6, tcp + payload, src, dst, ident=seq))


def udp_frame(src, dst, smac, dmac, payload, ident):
    hdr = struct.pack('!HHHH', IO_PORT, IO_PORT, 8 + len(payload), 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, 8 + len(payload))
    hdr = hdr[:6] + struct.pack('!H', csum(pseudo + hdr + payload) or 0xffff)
    return eth(smac, dmac, ipv4(17, hdr + payload, src, dst, ident))


def enip_srrd(cip, context, extra_items=b'', extra_count=0):
    cpf = struct.pack('<IHH', 0, 0, 2 + extra_count)
    cpf += struct.pack('<HH', 0x0000, 0)
    cpf += struct.pack('<HH', 0x00B2, len(cip)) + cip + extra_items
    return struct.pack('<HHIIQI', 0x006F, len(cpf), SESSION, 0, context, 0) + cpf


def sockaddr_item(item_type, addr, port=IO_PORT):
    return struct.pack('<HH', item_type, 16) + struct.pack('!HH4s', 2, port, bytes(addr)) + bytes(8)


def enip_io(connid, seq32, data):
    return (struct.pack('<H', 2) + struct.pack('<HHII', 0x8002, 8, connid, seq32)
            + struct.pack('<HH', 0x00B1, len(data)) + data)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (len(n) + 3) & ~3
    return struct.pack('>HH', 12, pad) + n.ljust(pad, b'\0') + struct.pack('>HH', 0, 0) + payload


def write_pcapng(path, frames):
    """frames: list of (interface, data); interface 0 is Ethernet, 1 is
    Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        length = 12 + len(body)
        return struct.pack('<II', btype, length) + body + struct.pack('<I', length)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack('<HHI', 1, 0, 65535))
    out += block(0x00000001, struct.pack('<HHI', 252, 0, 65535))
    for i, (iface, data) in enumerate(frames):
        ts = (1700000000 + i // 100) * 1000000 + (i % 100) * 10000
        out += block(0x00000006, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                              len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


# ---------------------------------------------------------------- CRCs

def _crc_msb(data, poly, bits, seed):
    """MSB-first CRC without reflection or final XOR, as the table driven
    crc8_0x37, crc8_0x3B, crc16_0x080F_seed and crc32_0x5D6DCB_seed in
    wsutil compute it."""
    top = 1 << (bits - 1)
    mask = (1 << bits) - 1
    crc = seed
    for b in data:
        crc ^= b << (bits - 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if crc & top else (crc << 1) & mask
    return crc


def crc8_37(data, seed=0):
    return _crc_msb(data, 0x37, 8, seed)


def crc8_3b(data, seed=0):
    return _crc_msb(data, 0x3B, 8, seed)


def crc16_080f(data, seed=0):
    return _crc_msb(data, 0x080F, 16, seed)


def crc24_5d6dcb(data, seed=0):
    return _crc_msb(data, 0x5D6DCB, 24, seed)


def triad_bytes(t):
    vendor, dev_serial, conn_serial = t
    return struct.pack('<HIH', vendor, dev_serial, conn_serial)


# ---------------------------------------------------------------- CIP data

def u8(v):
    return struct.pack('<B', v)


def u16(v):
    return struct.pack('<H', v)


def u32(v):
    return struct.pack('<I', v)


def sstr(s):
    return u8(len(s)) + s.encode()


def seg(ltype, value):
    if value < 0x100:
        return bytes([0x20 | ltype, value])
    return bytes([0x21 | ltype, 0]) + u16(value)


def cls(v, fmt=None):
    if fmt == 16:
        return bytes([0x21, 0]) + u16(v)
    if fmt == 32:
        return bytes([0x22, 0]) + u32(v)
    return seg(0x00, v)


def inst(v):
    return seg(0x04, v)


def att(v):
    return seg(0x10, v)


def cpt(v):
    return seg(0x0C, v)


def req(service, path, data=b''):
    return bytes([service, len(path) // 2]) + path + data


def rsp(service, data=b'', status=0, addl=()):
    return bytes([service | 0x80, 0, status, len(addl)]) + b''.join(u16(a) for a in addl) + data


def gas(c, i, a):
    return req(0x0E, cls(c) + inst(i) + att(a))


def snn(time_ms, date):
    return u32(time_ms) + u16(date)


def unid(time_ms=5000, date=12000, node=0x00000010):
    return snn(time_ms, date) + u32(node)


VENDOR = 0x1234
ORIG_SERIAL = 0x89ABCDEF
TARGET_VENDOR = 0x4321
TARGET_SERIAL = 0x55667788


def safety_segment(fmt, scid=True, max_fault=10, init_ts=0x1000, init_ro=5):
    sccrc = u32(0x11223344) if scid else u32(0)
    scts = snn(5000, 12000) if scid else bytes(6)
    if fmt == 0:
        body = (u8(0) + sccrc + scts + u32(20000) + u16(0x4803) + unid() + unid(6000, 100, 0x20)
                + u16(4) + u16(4) + u16(100) + u8(2) + u8(1) + u32(0xAABBCCDD) + u32(0x00020001))
    elif fmt == 1:
        body = u8(0) + u32(0x00020001) + u32(20000) + u16(0x4803)
    else:
        body = (u8(0) + sccrc + scts + u32(20000) + u16(0x4803) + unid() + unid(6000, 100, 0x20)
                + u16(4) + u16(4) + u16(100) + u8(2) + u8(1) + u16(max_fault) + u32(0xAABBCCDD)
                + u32(0x00020001) + u16(init_ts) + u16(init_ro))
    data = u8(fmt) + body
    if len(data) % 2:
        data += b'\0'
    return bytes([0x50, len(data) // 2]) + data


def fwd_open(o2t, t2o, serial, conn_path, ot_params, to_params, ttt):
    d = bytes([0x0A, 0x0E]) + u32(o2t) + u32(t2o) + u16(serial) + u16(VENDOR) + u32(ORIG_SERIAL)
    d += bytes([1, 0, 0, 0]) + u32(10000) + u16(ot_params) + u32(10000) + u16(to_params)
    d += bytes([ttt, len(conn_path) // 2]) + conn_path
    return req(0x54, cls(6) + inst(1), d)


def fwd_open_rsp(o2t, t2o, serial, app):
    d = u32(o2t) + u32(t2o) + u16(serial) + u16(VENDOR) + u32(ORIG_SERIAL) + u32(10000) + u32(10000)
    return rsp(0x54, d + bytes([len(app) // 2, 0]) + app)


def fwd_close(serial, conn_path):
    d = bytes([0x0A, 0x0E]) + u16(serial) + u16(VENDOR) + u32(ORIG_SERIAL) + bytes([len(conn_path) // 2, 0]) + conn_path
    return req(0x4E, cls(6) + inst(1), d)


def fwd_close_rsp(serial):
    return rsp(0x4E, u16(serial) + u16(VENDOR) + u32(ORIG_SERIAL) + bytes([0, 0]))


# ---------------------------------------------------------------- safety I/O messages

class Conn:
    """A safety connection: the originator triad (Forward Open) and the
    target triad (Forward Open reply application data)."""

    def __init__(self, serial, extended, init_ts=0x1000, init_ro=5):
        self.orig = (VENDOR, ORIG_SERIAL, serial)
        self.target = (TARGET_VENDOR, TARGET_SERIAL, serial)
        self.extended = extended
        self.ts = init_ts
        self.ro = init_ro
        self.seen_non_zero = False

    def rollover_for(self, ts):
        """Mirror get_timestamp_packet_data(): the rollover count used in the
        extended format CRCs."""
        if ts == 0 and not self.seen_non_zero:
            return 0
        self.seen_non_zero = True
        if ts < self.ts:
            self.ro += 1
        self.ts = ts
        return self.ro


def time_coord(triad, extended, ack, ts):
    """Time Coordination message (consumer to producer)."""
    if extended:
        crc = crc24_5d6dcb(u16(ts), crc24_5d6dcb(u8(ack), crc24_5d6dcb(triad_bytes(triad))))
        return u8(ack) + u16(ts) + bytes([crc & 0xff, (crc >> 8) & 0xff, crc >> 16])
    crc = crc16_080f(u16(ts), crc16_080f(u8(ack), crc16_080f(triad_bytes(triad))))
    return u8(ack) + u16(ts) + u8(ack ^ 0xFF) + u16(crc)


def base_data(triad, data, mode, ts):
    """Base format producer data with the time stamp section."""
    n = len(data)
    pid1 = crc8_37(triad_bytes(triad))
    if n <= 2:
        s1 = crc8_37(data, crc8_37(u8(mode & 0xE0), pid1))
        comp = bytes(b ^ 0xFF for b in data)
        s2 = crc8_3b(comp, crc8_3b(u8((mode ^ 0xFF) & 0xE0), pid1))
        msg = data + u8(mode) + u8(s1) + u8(s2)
    else:
        pid3 = crc16_080f(triad_bytes(triad))
        s3 = crc16_080f(data, crc16_080f(u8(mode & 0xE0), pid3))
        comp = bytes(b ^ 0xFF for b in data)
        cs3 = crc16_080f(comp, crc16_080f(u8((mode ^ 0xFF) & 0xE0), pid3))
        msg = data + u8(mode) + u16(s3) + comp + u16(cs3)
    ts_crc = crc8_37(u16(ts), crc8_37(u8(mode & 0x1F), pid1))
    return msg + u16(ts) + u8(ts_crc)


def base_time_correction(mcast, value):
    return u8(mcast) + u16(value) + u8(mcast ^ 0xFF) + u16(0x1234)


def extended_data(triad, data, mode, ts, ro):
    """Extended format producer data (CRC-S5, and CRC-S3 for 3 or more
    octets)."""
    n = len(data)
    pid5 = crc24_5d6dcb(triad_bytes(triad))
    if n <= 2:
        s5 = crc24_5d6dcb(data, crc24_5d6dcb(u8(mode & 0xE0), crc24_5d6dcb(u16(ro), pid5)))
        s5 = crc24_5d6dcb(u16(ts), s5)
        return data + u8(mode) + u8(s5 & 0xff) + u8((s5 >> 8) & 0xff) + u16(ts) + u8(s5 >> 16)
    pid3 = crc16_080f(triad_bytes(triad))
    s3 = crc16_080f(data, crc16_080f(u8(mode & 0xE0), crc16_080f(u16(ro), pid3)))
    comp = bytes(b ^ 0xFF for b in data)
    s5 = crc24_5d6dcb(comp, crc24_5d6dcb(u8(mode & 0x1F), crc24_5d6dcb(u16(ro), pid5)))
    s5 = crc24_5d6dcb(u16(ts), s5)
    return data + u8(mode) + u16(s3) + comp + u8(s5 & 0xff) + u8((s5 >> 8) & 0xff) + u16(ts) + u8(s5 >> 16)


def extended_time_correction(mcast, value):
    return u8(mcast) + u16(value) + bytes([0x11, 0x22, 0x33])


# ---------------------------------------------------------------- capture

class Capture:
    def __init__(self):
        self.frames = []
        self.labels = []
        self.ctx = 0x200
        self.stream = TcpStream(50100)

    def add(self, iface, frame, label):
        self.frames.append((iface, frame))
        self.labels.append(label)

    def pair(self, request, response, label, extra_items=b'', extra_count=0):
        self.ctx += 1
        self.add(0, self.stream.frame(True, enip_srrd(request, self.ctx)), label + ' (request)')
        if response is not None:
            self.add(0, self.stream.frame(False, enip_srrd(response, self.ctx, extra_items, extra_count)),
                     label + ' (response)')

    def io(self, from_client, connid, seq, data, label, multicast=False):
        if from_client:
            f = udp_frame(CLI_IP, SRV_IP, CLI_MAC, SRV_MAC, enip_io(connid, seq, data), len(self.frames))
        elif multicast:
            f = udp_frame(SRV_IP, MC_IP, SRV_MAC, MC_MAC, enip_io(connid, seq, data), len(self.frames))
        else:
            f = udp_frame(SRV_IP, CLI_IP, SRV_MAC, CLI_MAC, enip_io(connid, seq, data), len(self.frames))
        self.add(0, f, label)

    def epdu(self, name, payload, label):
        self.add(1, exp_pdu(name, payload), label)


def open_safety(c, serial, fmt, ttt, multicast=False, label='', init_ts=0x1000, init_ro=5, scid=True):
    """Forward Open (and reply) of a safety I/O connection to a Safety
    Validator connection point; returns the Conn and connection IDs."""
    o2t = 0x80000000 | serial
    t2o = 0x00010000 | serial
    path = safety_segment(fmt, scid=scid, init_ts=init_ts, init_ro=init_ro) + cls(0x3A) + inst(serial & 0xff) + cpt(0x80)
    to_params = 0x2806 if multicast else 0x4806
    extended = fmt == 2
    app = u16(1) + u16(TARGET_VENDOR) + u32(TARGET_SERIAL) + u16(serial)
    if extended:
        app += u16(init_ts) + u16(init_ro)
    extra, count = b'', 0
    if multicast:
        extra, count = sockaddr_item(0x8001, MC_IP), 1
    c.pair(fwd_open(o2t, t2o, serial, path, 0x4806, to_params, ttt), fwd_open_rsp(o2t, t2o, serial, app),
           'Forward Open ' + label, extra, count)
    return Conn(serial, extended, init_ts, init_ro), o2t, t2o, path


def build_main():
    c = Capture()

    # ------------------------------------------------ Exported PDU entry points
    # The reproducer cipsafety_nulldst (no network layer, so no IPv4
    # destination), with a valid mode byte (0x84 instead of 0x2c).
    payload = bytes([0x11, 0x84, 0x33, 0x44, 0x55, 0x66, 0x77])
    for name in ('cipsafety_bd', 'cipsafety_ed', 'cipsafety_bt', 'cipsafety_et', 'cipsafety'):
        c.epdu(name, payload, 'Repro cipsafety_nulldst (valid mode byte): Exported PDU to ' + name)
    # Longer data with the Decode As entry points (no CRC verification)
    c.epdu('cipsafety_bd', b'\x01\x02\x03\x04' + b'\xE8' + b'\x00\x00' + b'\xFE\xFD\xFC\xFB' + b'\x00\x00'
           + b'\x10\x00\x00', 'Exported PDU to cipsafety_bd, 4 octets of data')
    c.epdu('cipsafety_ed', b'\x01\x02\x03\x04' + b'\x14' + b'\x00\x00' + b'\xFE\xFD\xFC\xFB'
           + b'\x00\x00\x10\x00\x00', 'Exported PDU to cipsafety_ed, 4 octets of data')

    # ------------------------------------------------ I/O connections
    # 1. Extended format, originator is the consumer, unicast
    conn, o2t, t2o, path = open_safety(c, 0x0601, 2, 0x00, label='extended format, consumer, unicast')
    c.io(False, t2o, 1, extended_data(conn.target, b'\x01', 0x84, 0, conn.rollover_for(0)),
         'Extended 1 octet data, time stamp 0 (before time coordination)')
    c.io(True, o2t, 1, time_coord(conn.orig, True, 0x05, 0x0100), 'Extended Time Coordination')
    c.io(False, t2o, 2, extended_data(conn.target, b'\x01\x02', 0x85, 0x2000, conn.rollover_for(0x2000)),
         'Extended 2 octet data')
    c.io(False, t2o, 3, extended_data(conn.target, b'\x01\x02\x03\x04', 0xE8, 0x3000, conn.rollover_for(0x3000)),
         'Extended 4 octet data')
    c.io(False, t2o, 4, extended_data(conn.target, b'\x05\x06\x07', 0x14, 0x0010, conn.rollover_for(0x0010)),
         'Extended 3 octet data, time stamp rollover')
    c.pair(fwd_close(0x0601, path), fwd_close_rsp(0x0601), 'Forward Close extended consumer')

    # 2. Base format, originator is the consumer, unicast
    conn, o2t, t2o, path = open_safety(c, 0x0602, 0, 0x00, label='base format, consumer, unicast', scid=False)
    c.io(True, o2t, 1, time_coord(conn.orig, False, 0x8A, 0x0200), 'Base Time Coordination')
    c.io(False, t2o, 1, base_data(conn.target, b'\x01', 0x84, 0x0100), 'Base 1 octet data')
    c.io(False, t2o, 2, base_data(conn.target, b'\x01\x02', 0x14, 0x0200), 'Base 2 octet data')
    c.io(False, t2o, 3, base_data(conn.target, b'\x01\x02\x03\x04', 0xE8, 0x0300), 'Base 4 octet data')
    c.pair(fwd_close(0x0602, path), fwd_close_rsp(0x0602), 'Forward Close base consumer')

    # 3. Base format, multicast T->O
    conn, o2t, t2o, path = open_safety(c, 0x0603, 0, 0x00, multicast=True, label='base format, consumer, multicast')
    c.io(True, o2t, 1, time_coord(conn.orig, False, 0x01, 0x0300), 'Base Time Coordination (multicast connection)')
    c.io(False, t2o, 1, base_data(conn.target, b'\x07', 0x84, 0x0100) + base_time_correction(0x01, 0x0040),
         'Base 1 octet data with Time Correction (multicast)', multicast=True)
    c.io(False, t2o, 2, base_data(conn.target, b'\x07\x08\x09', 0x84, 0x0200) + base_time_correction(0x02, 0x0041),
         'Base 3 octet data with Time Correction (multicast)', multicast=True)
    c.pair(fwd_close(0x0603, path), fwd_close_rsp(0x0603), 'Forward Close base multicast')

    # 4. Extended format, multicast T->O
    conn, o2t, t2o, path = open_safety(c, 0x0604, 2, 0x00, multicast=True,
                                       label='extended format, consumer, multicast')
    c.io(True, o2t, 1, time_coord(conn.orig, True, 0x01, 0x0300), 'Extended Time Coordination (multicast connection)')
    c.io(False, t2o, 1, extended_data(conn.target, b'\x07', 0x84, 0x1100, conn.rollover_for(0x1100))
         + extended_time_correction(0x01, 0x0040), 'Extended 1 octet data with Time Correction (multicast)',
         multicast=True)
    c.io(False, t2o, 2, extended_data(conn.target, b'\x07\x08\x09\x0A', 0x84, 0x1200, conn.rollover_for(0x1200))
         + extended_time_correction(0x02, 0x0041), 'Extended 4 octet data with Time Correction (multicast)',
         multicast=True)
    c.pair(fwd_close(0x0604, path), fwd_close_rsp(0x0604), 'Forward Close extended multicast')

    # 5. Originator is the producer (output connection), extended and base
    conn, o2t, t2o, path = open_safety(c, 0x0605, 2, 0x80, label='extended format, producer')
    c.io(True, o2t, 1, extended_data(conn.orig, b'\x0A\x0B', 0x84, 0x2000, conn.rollover_for(0x2000)),
         'Extended output data')
    c.io(False, t2o, 1, time_coord(conn.target, True, 0x02, 0x0500), 'Extended Time Coordination (from the target)')
    c.pair(fwd_close(0x0605, path), fwd_close_rsp(0x0605), 'Forward Close extended producer')
    conn, o2t, t2o, path = open_safety(c, 0x0606, 0, 0x80, label='base format, producer')
    c.io(True, o2t, 1, base_data(conn.orig, b'\x0A\x0B\x0C', 0x84, 0x0100), 'Base output data')
    c.io(False, t2o, 1, time_coord(conn.target, False, 0x02, 0x0500), 'Base Time Coordination (from the target)')
    c.pair(fwd_close(0x0606, path), fwd_close_rsp(0x0606), 'Forward Close base producer')

    # ------------------------------------------------ Safety Supervisor services
    sup = cls(0x39) + inst(1)
    pw = bytes(range(16))
    c.pair(req(0x4C, sup, b'\x01\x02'), rsp(0x4C), 'Supervisor Recover')
    c.pair(req(0x4E, sup, b'\x03'), rsp(0x4E, b'\x01\x02'), 'Supervisor Perform Diagnostics')
    c.pair(req(0x4F, sup, pw + unid() + unid(6000, 100, 0x20)), rsp(0x4F), 'Supervisor Configure Request')
    c.pair(req(0x50, sup, u32(0x11223344) + snn(5000, 12000)), rsp(0x50, u32(0x11223344) + snn(5000, 12000)),
           'Supervisor Validate Configuration')
    c.pair(req(0x50, sup, u32(0x11223344) + snn(5000, 100)), rsp(0x50, b'\x00', status=0xD0, addl=[0x0001]),
           'Supervisor Validate Configuration, error with extended status')
    c.pair(req(0x50, sup, u32(0x11223344) + snn(5000, 100)), rsp(0x50, b'\x00', status=0xD0),
           'Supervisor Validate Configuration, error without extended status')
    c.pair(req(0x51, sup, pw + pw[::-1]), rsp(0x51, b'\x01', status=0x0F), 'Supervisor Set Password, error with data')
    c.pair(req(0x52, sup, u8(1) + pw + unid()), rsp(0x52, b'\x01'), 'Supervisor Configuration Lock')
    c.pair(req(0x53, sup, u8(2) + pw), rsp(0x53), 'Supervisor Mode Change')
    c.pair(req(0x54, sup, u8(2) + pw + unid() + u8(0xFF)), rsp(0x54), 'Supervisor Safety Reset type 2')
    c.pair(req(0x54, sup, u8(1) + pw + unid()), rsp(0x54), 'Supervisor Safety Reset type 1')
    c.pair(req(0x55, sup, u8(4) + b'\x01\x02\x03\x04'), rsp(0x55), 'Supervisor Reset Password')
    c.pair(req(0x56, sup, unid()), rsp(0x56), 'Supervisor Propose TUNID')
    c.pair(req(0x57, sup, unid()), rsp(0x57), 'Supervisor Apply TUNID')
    c.pair(req(0x58, sup, u16(1) + unid()), rsp(0x58), 'Supervisor Propose TUNID List')
    c.pair(req(0x59, sup), rsp(0x59), 'Supervisor Apply TUNID List (no data)')

    # ------------------------------------------------ Safety Supervisor attributes
    exc = u8(2) + b'\x01\x02' + u8(1) + b'\x03' + u8(1) + b'\x04'
    owners = u16(2) + unid() + u8(4) + cls(0x3A) + inst(1) + unid(7000, 200, 0x30) + u8(4) + cls(0x3A) + inst(2)
    sv = {1: u8(3), 5: sstr('Example'), 6: sstr('SM-1'), 7: sstr('1.0'), 8: sstr('A'), 9: sstr('SN1'),
          10: sstr('Cfg'), 11: u8(4), 12: u8(0), 13: exc, 14: exc, 15: u8(1), 16: u8(1),
          17: u32(3600000) + u16(18000), 18: u8(0), 19: u16(18000), 20: u16(18365), 21: struct.pack('<h', -5),
          22: u8(1), 23: u32(1000), 24: u8(0), 25: unid(), 26: u32(0x11223344) + snn(5000, 12000),
          27: unid(), 28: owners, 29: unid(8000, 300, 0x40), 99: u16(1)}
    order = [1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 99]
    r = u16(len(order))
    for a in order:
        r += u16(a) + u16(0) + sv[a]
    c.pair(req(0x03, sup, u16(len(order)) + b''.join(u16(a) for a in order)), rsp(0x03, r),
           'Supervisor Get_Attribute_List (all attributes)')
    c.pair(gas(0x39, 1, 2), rsp(0x0E, b'\x01\x05\x06'), 'Supervisor Attribute List')
    c.pair(gas(0x39, 0, 99), rsp(0x0E, u16(2)), 'Supervisor class Subclass')
    c.pair(gas(0x39, 1, 28), rsp(0x0E, u16(0)), 'Supervisor Output Connection Point Owners (none)')
    c.pair(gas(0x39, 1, 25), rsp(0x0E, unid(5000, 11688)), 'Supervisor CFUNID with a date')

    # ------------------------------------------------ Safety Validator
    val = cls(0x3A) + inst(1)
    gaa = (u8(3) + u8(0x81) + u16(10) + u8(2) + u16(4) + u16(5) + u8(2) + u16(100) + u16(110)
           + u8(2) + u8(2) + u8(3) + u8(1) + u16(1) + u8(1) + u16(2) + u16(3) + u16(0) + u16(500)
           + cls(4) + inst(1) + cpt(0x65))
    c.pair(req(0x01, val), rsp(0x01, gaa), 'Validator Get_Attributes_All instance')
    c.pair(req(0x01, cls(0x3A) + inst(0)), rsp(0x01, u16(1) + u16(4)), 'Validator Get_Attributes_All class')
    c.pair(req(0x01, cls(0x3A, 16) + inst(2)), rsp(0x01, b'\x01', status=0x05),
           'Validator Get_Attributes_All (16 bit class), error')
    c.pair(req(0x01, cls(0x3A, 32) + inst(2)), rsp(0x01, u8(0)), 'Validator Get_Attributes_All (32 bit class)')
    c.pair(req(0x4B, val, b'\x01\x02'), rsp(0x4B, b'\x03'), 'Validator vendor service')
    c.pair(req(0x4C, val), rsp(0x4C), 'Validator vendor service without data')
    vv = {14: u16(0x0100), 15: u8(3) + b'\x01\x02\x03'}
    r = u16(2)
    for a in (14, 15):
        r += u16(a) + u16(0) + vv[a]
    c.pair(req(0x03, val, u16(2) + u16(14) + u16(15)), rsp(0x03, r), 'Validator Get_Attribute_List')
    c.pair(gas(0x3A, 1, 13), rsp(0x0E, cls(4) + inst(1)), 'Validator Application Data Path')
    c.pair(gas(0x3A, 0, 8), rsp(0x0E, u16(7)), 'Validator class Safety Connection Fault Count')

    # A Get_Attributes_All response without a captured request (the
    # Validator heuristic sees a response without request information)
    c.ctx += 1
    c.add(0, c.stream.frame(False, enip_srrd(rsp(0x01, u8(3)), c.ctx)), 'Get_Attributes_All response without request')

    # ------------------------------------------------ SERCOS III Link
    sl = {1: bytes([1, 2, 3, 4, 5, 6]), 2: u32(250000), 3: u16(0x0003), 4: u16(1), 5: u16(2) + u16(3), 6: u16(7)}
    r = u16(6)
    for a in range(1, 7):
        r += u16(a) + u16(0) + sl[a]
    c.pair(req(0x03, cls(0x4C) + inst(1), u16(6) + b''.join(u16(a) for a in range(1, 7))), rsp(0x03, r),
           'SERCOS III Link Get_Attribute_List')
    return c


def build_malformed():
    c = Capture()
    # The unmodified reproducer: mode byte 0x2c has every check wrong
    payload = bytes([0x11, 0x2c, 0x33, 0x44, 0x55, 0x66, 0x77])
    for name in ('cipsafety_bd', 'cipsafety_ed', 'cipsafety_bt', 'cipsafety_et', 'cipsafety'):
        c.epdu(name, payload, 'Repro cipsafety_nulldst: Exported PDU to ' + name)
    c.epdu('cipsafety_bd', b'\x01\x02\x03', 'I/O shorter than the base length')
    c.epdu('cipsafety_bd', b'\x01\x02\x03\x04\x05' + b'\x84' + b'\x00' * 7, 'Base long data with an odd length')
    c.epdu('cipsafety_ed', b'\x01\x02\x03\x04\x05' + b'\x84' + b'\x00' * 7, 'Extended long data with an odd length')
    # Wrong CRCs, mode byte and complement data on a real connection
    conn, o2t, t2o, path = open_safety(c, 0x0701, 0, 0x00, label='base format, consumer')
    c.io(True, o2t, 1, time_coord(conn.orig, False, 0x05, 0x0100)[:-2] + b'\x00\x00', 'Base Time Coordination, bad CRC-S3')
    good = base_data(conn.target, b'\x01', 0x84, 0x0100)
    c.io(False, t2o, 1, good[:2] + b'\x00\x00' + good[4:6] + b'\x00', 'Base 1 octet data, bad CRC-S1/S2')
    good = base_data(conn.target, b'\x01\x02\x03', 0x84, 0x0200)
    c.io(False, t2o, 2, good[:4] + b'\x00\x00\x00' + good[7:], 'Base 3 octet data, bad CRC-S3 and complement')
    c.io(False, t2o, 3, base_data(conn.target, b'\x01', 0x2C, 0x0300), 'Base data with a bad mode byte')
    conn, o2t, t2o, path = open_safety(c, 0x0702, 2, 0x00, label='extended format, consumer')
    c.io(True, o2t, 1, time_coord(conn.orig, True, 0x05, 0x0100)[:-1] + b'\x00', 'Extended Time Coordination, bad CRC-S5')
    good = extended_data(conn.target, b'\x01', 0x84, 0x2000, 5)
    c.io(False, t2o, 1, good[:2] + b'\x00' + good[3:], 'Extended 1 octet data, bad CRC-S5')
    good = extended_data(conn.target, b'\x01\x02\x03', 0x84, 0x2100, 5)
    c.io(False, t2o, 2, good[:4] + b'\x00\x00\x00' + good[7:], 'Extended 3 octet data, bad CRC-S3 and complement')
    c.io(False, t2o, 3, b'\x01\x02', 'Extended data shorter than the base length')
    # Supervisor/Validator attributes cut short
    sup = cls(0x39) + inst(1)
    c.pair(req(0x56, sup, b'\xFF' * 10), rsp(0x56), 'Supervisor Propose TUNID cancel (all FF)')
    c.pair(req(0x57, sup, b'\xFF' * 10), rsp(0x57), 'Supervisor Apply TUNID cancel (all FF)')
    bad = [
        (0x39, 1, 13, u8(0), 'Exception Detail Alarm with an empty common detail'),
        (0x39, 1, 13, u8(1) + b'\x01' + u8(0), 'Exception Detail Alarm with an empty device detail'),
        (0x39, 1, 14, u8(1) + b'\x01' + u8(1) + b'\x02' + u8(0), 'Exception Detail Warning with an empty manufacturer detail'),
        (0x39, 1, 25, b'\x01\x02', 'CFUNID cut short'),
        (0x39, 1, 26, b'\x01\x02', 'SCID cut short'),
        (0x39, 1, 27, b'\x01\x02', 'TUNID cut short'),
        (0x39, 1, 28, b'\x01', 'Output Connection Point Owners cut short'),
        (0x39, 1, 28, u16(2) + unid(), 'Output Connection Point Owners entry cut short'),
        (0x39, 1, 28, u16(1) + unid() + u8(8) + b'\x20\x3A', 'Output Connection Point Owners path cut short'),
        (0x39, 1, 29, b'\x01\x02', 'Proposed TUNID cut short'),
        (0x3A, 1, 4, u8(3) + b'\x01\x00', 'Validator Time Coord Msg Min Multiplier cut short'),
        (0x3A, 1, 5, u8(3) + b'\x01\x00', 'Validator Network Time Expectation Multiplier cut short'),
        (0x3A, 1, 6, u8(3) + b'\x01', 'Validator Timeout Multiplier cut short'),
        (0x3A, 1, 9, u8(3) + b'\x01\x00', 'Validator Coordination Connection Instance cut short'),
        (0x3A, 1, 15, u8(3) + b'\x01', 'Validator Producer/Consumer Fault Counters cut short'),
        (0x4C, 1, 5, b'\x01\x02', 'SERCOS III Error counter Port1 and Port2 cut short'),
    ]
    for cl, i, a, data, label in bad:
        c.pair(gas(cl, i, a), rsp(0x0E, data), label)
    c.pair(req(0x03, cls(0x3A) + inst(1), u16(1) + u16(2)), rsp(0x03, u16(1) + u16(2) + u16(0)),
           'Validator Get_Attribute_List, Type without data')
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, builder in (('cipsafety-coverage.pcapng', build_main),
                          ('cipsafety-coverage-malformed.pcapng', build_malformed)):
        c = builder()
        write_pcapng(os.path.join(out, name), c.frames)
        with open(os.path.join(out, name.replace('.pcapng', '.frames.txt')), 'w') as f:
            for i, l in enumerate(c.labels):
                f.write('%d\t%s\n' % (i + 1, l))
        print(name, len(c.frames), 'frames')


if __name__ == '__main__':
    main()

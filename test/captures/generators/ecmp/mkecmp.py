#!/usr/bin/env python3
# Generates test/captures/ecmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ECMP dissector
(packet-ecmp.c, Emerson / Control Techniques ECMP).

ECMP requests and responses are carried one per TCP segment on port
6160; cyclic data goes over UDP port 6160. A TCP message starts with 4
octets the dissector skips, the destination and source addresses
(address scheme octet, plus a physical/logical address, a diagnostic
code or a name), a transaction ID, then for a request a response size
(chunks and maximum size), the command code and a list of option codes;
for a response a status, a chunk ID, the command code (bit 7 set) and
options. The command specific data follows: identify, info,
interrogate, parameter read/write/object info/get next objects, the
file commands, cyclic link setup, program control and status, cyclic
frames, tunnelled frames and Modbus PDUs. The dissector does no
framing of its own; the layouts below follow how it reads the fields,
including its off-by-one reads. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkecmp.py <output directory>

Writes:
  ecmp-coverage.pcap            every command as request and response,
                                every address scheme, option, data type
                                and file attribute, cyclic UDP frames
                                and the reproducer of the cyclic line
                                offset fix
  ecmp-coverage-malformed.pcap  messages and cyclic data cut short
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 10])
IP_S = bytes([192, 0, 2, 20])
PORT = 6160


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, 10000 * (i % 100), len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IDENT = [0]


def ipv4(proto, src, dst, payload):
    IDENT[0] += 1
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0], 0x4000,
                      64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def eth(fwd, payload):
    src, dst = (MAC_C, MAC_S) if fwd else (MAC_S, MAC_C)
    return dst + src + b'\x08\x00' + payload


def udp(fwd, sport, dport, data):
    src, dst = (IP_C, IP_S) if fwd else (IP_S, IP_C)
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    c = csum(src + dst + struct.pack('>BBH', 0, 17, len(u)) + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    return eth(fwd, ipv4(17, src, dst, u))


class TCP:
    """A TCP connection to port 6160, one ECMP message per segment."""

    def __init__(self, frames, cport):
        self.F = frames
        self.cport = cport
        self.seq = {True: 1000, False: 50000}
        self.seg(True, 0x02, b'')
        self.seq[True] += 1
        self.seg(False, 0x12, b'')
        self.seq[False] += 1
        self.seg(True, 0x10, b'')

    def seg(self, fwd, flags, data):
        src, dst = (IP_C, IP_S) if fwd else (IP_S, IP_C)
        sport, dport = (self.cport, PORT) if fwd else (PORT, self.cport)
        ack = self.seq[not fwd] if flags != 0x02 else 0
        # SYN and SYN-ACK carry an MSS option
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        t = struct.pack('>HHIIBBHHH', sport, dport, self.seq[fwd], ack,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
        c = csum(src + dst + struct.pack('>BBH', 0, 6, len(t)) + t)
        t = t[:16] + struct.pack('>H', c) + t[18:]
        self.F.append(eth(fwd, ipv4(6, src, dst, t)))
        self.seq[fwd] += len(data)

    def req(self, data):
        self.seg(True, 0x18, data)

    def rsp(self, data):
        self.seg(False, 0x18, data)

    def close(self):
        self.seg(True, 0x11, b'')
        self.seq[True] += 1
        self.seg(False, 0x11, b'')
        self.seq[False] += 1
        self.seg(True, 0x10, b'')


# ---- ECMP message building

ADDR_NONE = b'\x00'


def frame(dst, src, tid, rest):
    body = dst + src + bytes([tid]) + rest
    return struct.pack('>HH', 0, len(body)) + body


END = b'\x00'


def request(cmd, payload, tid=1, opts=END, chunks=0, maxsize=0x400, dst=ADDR_NONE,
            src=ADDR_NONE):
    rest = struct.pack('>H', (chunks << 12) | maxsize) + bytes([cmd]) + opts + payload
    return frame(dst, src, tid, rest)


def response(cmd, payload, tid=1, status=0, chunk=0, opts=END, dst=ADDR_NONE,
             src=ADDR_NONE):
    rest = bytes([status & 0xff, chunk, 0x80 | cmd]) + opts + payload
    return frame(dst, src, tid, rest)


def s16(s):
    return struct.pack('>H', len(s)) + s


# address schemes as get_address_scheme() reads them
def addr_std(menu, param):
    return struct.pack('>HH', menu, param)


def addr_slot(slot, menu, param):
    return bytes([slot]) + struct.pack('>HH', menu, param)


def addr_var(name):
    return s16(name)


def addr_null(size):
    # null scheme: one size octet, and the dissector steps over one more
    return bytes([size, 0])


# typed values as get_data_type() reads them
def val(t, v=b''):
    sizes = {0: 1, 1: 1, 2: 1, 3: 2, 4: 2, 5: 4, 6: 4, 7: 8, 8: 8, 9: 16, 10: 16,
             20: 4, 21: 8, 30: 2}
    if t in sizes:
        return v.rjust(sizes[t], b'\0')[:sizes[t]]
    if t == 32:
        return b'\0' + s16(v)
    if t >= 128:
        return v.ljust(t - 127, b'\0')[:t - 127]
    return v


def main_frames():
    F = []
    c = TCP(F, 40001)

    # ---- addresses and options
    # identify request: every address scheme and option
    c.req(request(0x00, bytes([3, 0, 1, 2]), tid=1,
                  opts=b'\x01' + b'\x02' + struct.pack('>Q', 123456789) + b'\x00',
                  dst=b'\x02\x15', src=b'\x01'))
    c.rsp(response(0x00, b'\x00\x04' + bytes([0x01, 0x02, 0x00, 0x05]) +
                   bytes([6]) +
                   b'\x00' + s16(b'Control Techniques') +
                   b'\x01' + s16(b'Unidrive') +
                   b'\x02' + s16(b'M700') +
                   b'\x03' + s16(b'1234567890') +
                   b'\x07' + s16(b'FW:V01.02.03#4;BL:@1.0;HW:\x80\xff') +
                   b'\x08' + struct.pack('>H', 8) + struct.pack('>II', 0x00ff8000, 0x00102030),
                   tid=1, dst=b'\x01', src=b'\x02\x15'))
    # identify with the diagnostic scheme and an unknown option, option
    # module category, a colour code out of range (warning)
    c.req(request(0x00, bytes([1, 8]), tid=2, opts=b'\x09\x00', dst=b'\x03\x02',
                  src=b'\x03\x01'))
    c.rsp(response(0x00, b'\x01\x02\x12\x34' + bytes([1]) +
                   b'\x08' + struct.pack('>H', 8) + struct.pack('>II', 0x01ffffff, 0xff000000),
                   tid=2))
    # identify response with an unknown category and a device name
    c.req(request(0x00, b'\x00', tid=3, dst=b'\x05'))
    c.rsp(response(0x00, b'\x02\x03\xaa\xbb\xcc' + bytes([2]) + b'\x06' + s16(b'drive-1') +
                   b'\x04' + s16(b'ORD-42'), tid=3))
    # named address scheme: the dissector reads the name length from the
    # scheme octet itself (0x04 0x04 -> 1028 octets) and steps over one
    # more octet after the name
    c.req(request(0x01, b'', tid=4, dst=b'\x04\x04' + b'N' * 1028 + b'\x00'))
    # ---- info
    c.req(request(0x01, b'', tid=5, chunks=2, maxsize=0xfff))
    c.rsp(response(0x01, struct.pack('>HHH', 1500, 100, 20) + b'\x02\x11\x22', tid=5))
    # info response with only the buffer size, response time and period
    c.req(request(0x01, b'', tid=6))
    c.rsp(response(0x01, struct.pack('>HHH', 512, 50, 10), tid=6))
    # info response with no default server addresses
    c.rsp(response(0x01, struct.pack('>HHH', 512, 50, 10) + b'\x00', tid=6))
    # ---- interrogate
    c.req(request(0x02, b'\x00\x05\x10\x11\x12\x13\x14', tid=7))
    c.rsp(response(0x02, b'\x00\x05\x10\x01\x11\x01\x12\x00\x13\x01\x7f\x05', tid=7))
    # interrogate for options (not implemented: warnings)
    c.req(request(0x02, b'\x01\x02\x01\x02', tid=8))
    c.rsp(response(0x02, b'\x01\x02\x01\x01\x02\x00', tid=8))
    # ---- read (0x10): standard, slot specific, variable, null and an
    #      unknown address scheme
    c.req(request(0x10, b'\x00\x02' + addr_std(1, 21) + addr_std(20, 1), tid=9))
    c.rsp(response(0x10, b'\x02' + b'\x00\x04' + val(4, b'\x05\xdc') + b'\x01\x01' + val(1, b'\xff')
                   + b'\x00', tid=9))
    c.req(request(0x10, b'\x01\x01' + addr_slot(3, 1, 2), tid=10))
    c.rsp(response(0x10, b'\x01\x00' + b'\x03' + val(3, b'\xff\x9c') + b'\x00', tid=10))
    c.req(request(0x10, b'\x03\x02' + addr_var(b'Speed') + addr_var(b'Torque'), tid=11))
    # read response: an error status followed by zero octets (skipped)
    # and a value with status "OK - Clamped" (a status of 0 would be
    # skipped too)
    c.rsp(response(0x10, b'\x02' + b'\xfc' + b'\x00\x00' + b'\x02\x06' + val(6, b'\x00\x01\x00\x00')
                   + b'\x00', tid=11))
    c.req(request(0x10, b'\x04\x01' + addr_null(4), tid=12))
    c.rsp(response(0x10, b'\x00\xf5', tid=12))
    c.req(request(0x10, b'\x07\x01' + b'\x00', tid=13))
    # every data type in a read response
    vals = b''
    for t, v in ((0, b'\x01'), (2, b'\x80'), (5, b'\xff\xff\xff\xfe'), (7, b'\x80' + b'\0' * 7),
                 (8, b'\xff' * 8), (9, b'\x01' * 16), (10, b'\x02' * 16),
                 (20, struct.pack('>f', 1.5)), (21, struct.pack('>d', -2.25)),
                 (30, b'ID'), (32, b'string value'), (130, b'\x01\x02\x03'), (255, b'\xaa' * 128)):
        vals += b'\x00' + bytes([t]) + val(t, v)
    c.rsp(response(0x10, bytes([13]) + vals + b'\x00', tid=13))
    # read response with an error status as the last response
    c.rsp(response(0x10, b'\x02' + b'\x00\x02' + val(2, b'\x01') + b'\xf3' + b'\x00', tid=13))
    # read response: unknown data type 31 (warning) as the last response
    c.rsp(response(0x10, b'\x01' + b'\x00\x1f\x00\x00', tid=13))
    # ---- read with type (0x11): decimal places and units
    c.req(request(0x11, b'\x00\x03' + addr_std(1, 1) + addr_std(1, 2) + addr_std(1, 3), tid=14))
    c.rsp(response(0x11, b'\x03' +
                   b'\x00' + b'\x04' + val(4, b'\x00\x10') + b'\x02' + b'\x0b' +
                   b'\x00' + b'\x05' + val(5, b'\x00\x00\x01\x00') + b'\xff' + b'\x00' +
                   b'\x00' + b'\x02' + val(2, b'\x07') + b'\x01' + b'\xff' + s16(b'furlongs')
                   + b'\x00', tid=14))
    # ---- write (0x12): typed values with decimal places
    c.req(request(0x12, b'\x00\x03' +
                  addr_std(1, 21) + b'\x04\x02' + val(4, b'\x05\xdc') +
                  addr_std(1, 22) + b'\x03\xff' + val(3, b'\xff\xff') +
                  addr_std(1, 23) + b'\x20\x00' + val(32, b'abc'), tid=15))
    c.rsp(response(0x12, b'\x03\x00\x01\x02' + b'\x00', tid=15))
    c.rsp(response(0x12, b'\x00\xf7', tid=15))
    # ---- object info (0x13): every info type
    c.req(request(0x13, b'\x00\x08' + b''.join(bytes([i]) + addr_std(1, i) for i in range(8)),
                  tid=16))
    c.rsp(response(0x13, b'\x09' +
                   b'\x00\x00' +
                   b'\x00\x01' + b'\x00\x01' +
                   b'\x00\x02' + b'\x00\x63' +
                   b'\x00\x03' + struct.pack('>I', 0xa5a5a5a5) +
                   b'\x00\x04' + b'\x03' + val(3, b'\xff\x00') +
                   b'\x00\x05' + b'\x06' + val(6, b'\x00\x00\xff\xff') +
                   b'\x00\x06' + b'U1' +
                   b'\x00\x07' + b'\x14' +
                   b'\x00\x09' + b'\x00', tid=16))
    c.rsp(response(0x13, b'\x00\xfd', tid=16))
    # object info request with the slot specific scheme
    c.req(request(0x13, b'\x01\x01' + b'\x03' + addr_slot(1, 2, 3), tid=17))
    # object info request with the variable scheme
    c.req(request(0x13, b'\x03\x01' + b'\x07' + addr_var(b'V'), tid=17))
    # ---- get next objects (0x14)
    c.req(request(0x14, b'\x00' + addr_std(1, 0) + b'\x05', tid=18))
    c.rsp(response(0x14, b'\x00\x02' + addr_std(1, 1) + addr_std(1, 2) + b'\x00', tid=18))
    c.rsp(response(0x14, b'\x00\x00', tid=18))
    c.req(request(0x14, b'\x03' + addr_var(b'Pos') + b'\x01', tid=19))
    c.rsp(response(0x14, b'\x01\x01' + addr_slot(2, 3, 4) + b'\x00', tid=19))
    # ---- file commands
    # FileOpen: non-blocking, relative to a directory handle, generic
    # additional scheme data
    c.req(request(0x20, b'\xc1' + b'\x01' + s16(b'/par/menu1.par') + struct.pack('>H', 7) +
                  b'\x03' + b'\x01\x02\x03', tid=20))
    c.rsp(response(0x20, b'\x01' + struct.pack('>H', 0x1234), tid=20))
    c.req(request(0x20, b'\x02\x00' + s16(b'new.txt'), tid=21))
    c.rsp(response(0x20, b'\xfb', tid=21))
    # FileRead, FileWrite, FileClose
    c.req(request(0x21, struct.pack('>HH', 0x1234, 16), tid=22))
    c.rsp(response(0x21, b'\x02' + s16(b'0123456789abcdef'), tid=22))
    c.rsp(response(0x21, b'\xf7', tid=22))
    c.req(request(0x22, struct.pack('>H', 0x1234) + s16(b'written data'), tid=23))
    c.rsp(response(0x22, b'\x01', tid=23))
    c.req(request(0x23, struct.pack('>HII', 0x1234, 28, 0xcbf43926), tid=24))
    c.rsp(response(0x23, b'\x01', tid=24))
    # FileInfo with every attribute
    c.req(request(0x24, struct.pack('>H', 0x1234) + b'\x06\x00\x01\x02\x03\x04\x05', tid=25))
    c.rsp(response(0x24, b'\x01\x07' +
                   b'\x00' + struct.pack('>I', 4096) +
                   b'\x01' + b'\x01' +
                   b'\x02' + struct.pack('>I', 0xdeadbeef) +
                   b'\x03' + b'\x3f' +
                   b'\x04' + struct.pack('>I', 1700000000) +
                   b'\x05' + struct.pack('>I', 1700003600) +
                   b'\x09' + b'\x00', tid=25))
    # FileDelete and FileState
    c.req(request(0x25, struct.pack('>H', 0x1234), tid=26))
    c.rsp(response(0x25, b'\x01', tid=26))
    c.req(request(0x26, struct.pack('>H', 0x1234), tid=27))
    c.rsp(response(0x26, b'\xee', tid=27))
    # FilePos: request with reference point, response with the offset
    c.req(request(0x27, struct.pack('>HBi', 0x1234, 1, -100), tid=28))
    c.rsp(response(0x27, b'\x01' + struct.pack('>I', 3996), tid=28))
    c.rsp(response(0x27, b'\xff', tid=28))
    # FileList: a file, a directory, an unknown item type (warning)
    c.req(request(0x28, struct.pack('>HB', 0x0001, 1), tid=29))
    c.rsp(response(0x28, b'\x01\x01' + b'\xab\xcd' + b'\x00' + s16(b'menu1.par'), tid=29))
    c.rsp(response(0x28, b'\x01\x01' + b'\xab\xcd' + b'\x01' + s16(b'logs'), tid=29))
    c.rsp(response(0x28, b'\x01\x01' + b'\xab\xcd' + b'\x07' + s16(b'x'), tid=29))
    c.rsp(response(0x28, b'\xfb', tid=29))
    # FileExists
    c.req(request(0x2a, s16(b'/par/menu1.par'), tid=30))
    c.rsp(response(0x2a, b'\x01', tid=30))
    # ---- cyclic link setup (0x31)
    # create with every attribute (mapping items with the standard and
    # slot specific schemes)
    attrs = (b'\x00\x01' + b'\x01\x01' + b'\x02\x01' + b'\x03' + struct.pack('>I', 250) +
             b'\x04' + struct.pack('>Q', 1000000) + b'\x05' + struct.pack('>Q', 500) +
             b'\x06\x00' + b'\x07' + struct.pack('>I', 3000) + b'\x01\x02\x03' +
             b'\x08' + b'\x04\x05\x06' + b'\x09' + b'\x00' + bytes([192, 0, 2, 30]) +
             b'\x0a\x10' + b'\x0b\x02' +
             b'\x0c' + b'\x00' + b'\x00' + addr_std(1, 21) +
             b'\x0c' + b'\x04' + b'\x01' + addr_slot(1, 2, 3) +
             b'\x0d\x01' + bytes([0x80, 4, 0x81, 4, 0x82, 32, 0x83, 1, 0x84, 1, 0x85, 16, 0x86, 8])
             + b'\x87' + struct.pack('>I', 1000) + b'\x7e')
    c.req(request(0x31, b'\x05\x00\x01' + bytes([24]) + attrs, tid=31))
    c.rsp(response(0x31, b'\x00\x00\x00', tid=31))
    # set (mode 10) and its response with attribute IDs
    c.req(request(0x31, b'\x05\x0a\x00\x01' + b'\x03' + struct.pack('>I', 125), tid=32))
    c.rsp(response(0x31, b'\x00\x00\x0a\x02\x03\x04', tid=32))
    # edit, finalise, delete, exist (request link direction; exist
    # response with the link state)
    for mode, resp in ((1, b''), (2, b''), (3, b''), (4, b'\x01')):
        c.req(request(0x31, bytes([5, mode, 1]), tid=33 + mode))
        c.rsp(response(0x31, bytes([0, 0, mode]) + resp, tid=33 + mode))
    # list: tx and rx link numbers
    c.req(request(0x31, b'\x00\x05\x03', tid=38))
    c.rsp(response(0x31, b'\x00\x00\x05\x02\x01\x02\x03\x05\x06\x07', tid=38))
    # info and get: attribute IDs in the request, values in the response
    c.req(request(0x31, b'\x05\x06\x03\x00\x01\x02', tid=39))
    c.rsp(response(0x31, b'\x00\x00\x06\x03\x00\x01\x01\x00\x02\x00', tid=39))
    c.req(request(0x31, b'\x05\x0b\x01\x02\x87\x0a', tid=40))
    c.rsp(response(0x31, b'\x00\x00\x0b\x02\x87' + struct.pack('>I', 1000) + b'\x0a\x08', tid=40))
    # get mappings
    c.req(request(0x31, b'\x05\x0c\x00\x08\x00', tid=41))
    c.rsp(response(0x31, b'\x00\x00\x0c\x01\x0c\x00\x00' + addr_std(1, 21), tid=41))
    # unknown mode 7 in the request and the response
    c.req(request(0x31, b'\x05\x07\x01\x02', tid=42))
    c.rsp(response(0x31, b'\xff\x01\x07\x01\x02', tid=42))
    # ---- program control and status
    c.req(request(0x60, b'\x00\x01\x00', tid=43))
    c.rsp(response(0x60, b'\x00', tid=43))
    c.req(request(0x60, b'\x01\x02\x02', tid=44))
    c.rsp(response(0x60, b'\xff', tid=44))
    c.req(request(0x61, b'\x00', tid=45))
    c.rsp(response(0x61, b'\x01\x00', tid=45))
    c.rsp(response(0x61, b'\x03\x02', tid=45))
    # ---- cyclic frame over TCP: standard and synchronised schemes
    c.req(request(0x70, b'\x05', tid=46))
    c.rsp(response(0x70, b'\x05\x04\x00' + bytes(range(8)), tid=46))
    c.rsp(response(0x70, b'\x05\x08\x01' + struct.pack('>QQ', 0x0011223344556677, 999999)
                   + bytes(range(16)), tid=46))
    # ---- tunnel frame: request with the check output flag, response
    c.req(request(0x73, b'\x07' + s16(b'tunnelled payload'), tid=47))
    c.rsp(response(0x73, b'\x07' + s16(b'reply'), tid=47))
    # ---- Modbus PDU: read holding registers
    c.req(request(0x74, struct.pack('>H', 5) + b'\x03\x07\xe4\x00\x03', tid=48))
    c.rsp(response(0x74, struct.pack('>H', 8) + b'\x03\x06\x30\x39\x03\x13\x00\x64', tid=48))
    # ---- statuses: chunks follow, processing (no data), errors
    c.req(request(0x01, b'', tid=49))
    c.rsp(response(0x01, struct.pack('>HHH', 512, 50, 10), tid=49, status=1, chunk=1))
    c.rsp(response(0x01, b'', tid=49, status=2, chunk=2))
    c.rsp(frame(ADDR_NONE, ADDR_NONE, 49, b'\xff\x00\x81'))
    c.rsp(frame(ADDR_NONE, ADDR_NONE, 0, b'\xfd\x00\x81'))
    # ---- unknown command (warning) in a request and a response, a
    #      transaction ID of 0
    c.req(request(0x55, b'\x01\x02', tid=0))
    c.rsp(response(0x55, b'\x03\x04', tid=0))
    c.close()

    # ---- cyclic data over UDP port 6160
    # request (no data shown)
    F.append(udp(True, PORT, PORT, bytes([0, 0, 50, 0, 0, 0x70, 0, 1])))
    # the reproducer of the cyclic line offset fix: a response with
    # exactly 32 octets of data (one full line of 32-bit values)
    F.append(udp(False, PORT, PORT, bytes([0, 0, 7, 0, 0, 0xC5, 0, 1, 0, 0]) + bytes(range(32))))
    # 70 octets: full and partial lines in every format
    F.append(udp(False, PORT, PORT, bytes([0, 0, 51, 0, 0, 0xF0, 0, 2, 4, 0]) +
                 bytes((i * 7) & 0xff for i in range(70))))
    # synchronised scheme: grandmaster and process time, 3 octets of data
    F.append(udp(False, PORT, PORT, bytes([0, 0, 52, 0, 0, 0xF0, 0, 3, 2, 1]) +
                 struct.pack('>QQ', 0x0011223344556677, 123456) + b'\x01\x02\x03'))
    # 256 octets: several full lines in every format
    F.append(udp(False, PORT, PORT, bytes([0, 0, 54, 0, 0, 0xF0, 0, 5, 1, 0]) + bytes(range(256))))
    # unknown command code in a cyclic message
    F.append(udp(True, PORT, PORT, bytes([0, 0, 55, 0, 0, 0x7f, 0, 6])))
    # shorter than the 6 octet minimum: not ECMP (UDP data)
    F.append(udp(True, PORT, PORT, b'\x00\x01\x02\x03\x04'))
    return F


def malformed_frames():
    F = []
    c = TCP(F, 40002)
    # identify response cut in the attributes
    c.rsp(response(0x00, b'\x00\x04\x01\x02\x00\x05\x03\x00' + s16(b'abc')[:3], tid=1))
    # read response: error status followed only by zero octets
    c.rsp(response(0x10, b'\x02\xfc\x00\x00\x00', tid=2))
    # read request cut in the address
    c.req(request(0x10, b'\x00\x02\x00\x01', tid=3))
    # cyclic setup create, attribute values cut short
    c.req(request(0x31, b'\x05\x00\x01\x02\x04\x00\x00', tid=4))
    # file read response announcing more data than present
    c.rsp(response(0x21, b'\x02' + struct.pack('>H', 100) + b'abc', tid=5))
    # Modbus PDU size beyond the frame
    c.req(request(0x74, struct.pack('>H', 50) + b'\x03\x00', tid=6))
    # message shorter than its header: 6 octets
    c.req(b'\x00\x00\x00\x02\x00\x00')
    # TCP message shorter than the 6 octet minimum
    c.req(b'\x00\x01')
    # UDP response with 5 octets of data (not a multiple of 2 or 4)
    F.append(udp(False, PORT, PORT, bytes([0, 0, 9, 0, 0, 0xF0, 0, 2, 0, 0]) + b'\x01\x02\x03\x04\x05'))
    # UDP response with no cyclic data: with a tree the 2 octet data
    # subtrees at the end of the frame throw before "No data" is shown
    F.append(udp(False, PORT, PORT, bytes([0, 0, 53, 0, 0, 0xF0, 0, 4, 8, 0])))
    # UDP synchronised response cut in the grandmaster
    F.append(udp(False, PORT, PORT, bytes([0, 0, 9, 0, 0, 0xF0, 0, 2, 0, 1]) + b'\x01\x02'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'ecmp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'ecmp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

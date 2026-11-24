#!/usr/bin/env python3
# Generates test/captures/sbus_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the S-Bus (SAIA Ether-S-Bus) coverage captures: mksbus.py <outdir> [-v].
All data is synthetic.  S-Bus runs over UDP port 5050 (registered by default)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import Cap, udp

def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc

def tlg(seq, attr, rest, ver=1, proto=0, crc=None, length=None):
    """rest: all bytes after the attribute (for a request: destination, command, ...)."""
    n = 8 + 1 + len(rest) + 2 if length is None else length
    body = struct.pack('>IBBHB', n, ver, proto, seq, attr) + rest
    return body + struct.pack('>H', crc16(body) if crc is None else crc)

def req(seq, cmd, args=b'', dest=1, **kw):
    return tlg(seq, 0, bytes([dest, cmd]) + args, **kw)

def rsp(seq, data=b'', **kw):
    return tlg(seq, 1, data, **kw)

def ack(seq, code=0, **kw):
    return tlg(seq, 2, struct.pack('>H', code), **kw)

CLOCK = bytes([0x24, 0x03, 0x24, 0x11, 0x09, 0x12, 0x34, 0x56])

def media_req(cmd, cnt, addr):
    return bytes([cnt - 1]) + struct.pack('>H', addr)

def blk(seq, btype, body, lfix=0):
    """Read/write block telegram: length octet (or 0xff when it does not fit)
    and telegram type, then the body.  lfix adjusts the length octet for the
    telegram types whose end offset does not follow the usual rule."""
    L = len(body) + lfix
    if L > 254:
        return req(seq, 0xA9, bytes([0xff, btype]) + body)
    return req(seq, 0xA9, bytes([L, btype]) + body)

def name24(s):
    return s + b'\0'

class Stream:
    def __init__(self, c, sport=40000, dport=5050, src='192.0.2.1', dst='192.0.2.2'):
        self.c = c; self.sport = sport; self.dport = dport; self.src = src; self.dst = dst
    def to_plc(self, p):
        self.c.add(udp(self.sport, self.dport, p, self.src, self.dst))
    def from_plc(self, p):
        self.c.add(udp(self.dport, self.sport, p, self.dst, self.src))

def main(out, verbose=False):
    c = Cap(1)
    s = Stream(c)
    seq = [0]
    def nxt():
        seq[0] += 1
        return seq[0]
    def pair(rq, rs):
        s.to_plc(rq(seq[0] + 1)); s.from_plc(rs(seq[0] + 1)); seq[0] += 1

    c.mark('Read counters, registers, timers (32 bit data) and flags, inputs, outputs (binary data, 1, 8 and 17 elements)')
    for cmd in (0x00, 0x06, 0x07):
        pair(lambda q, cmd=cmd: req(q, cmd, media_req(cmd, 3, 0x10)), lambda q: rsp(q, bytes(range(12))))
    for cmd in (0x02, 0x03, 0x05):
        for n in (1, 8, 17):
            pair(lambda q, cmd=cmd, n=n: req(q, cmd, media_req(cmd, n, 0x20)), lambda q, n=n: rsp(q, bytes([0xa5, 0x0f, 0x01][:(n + 7) // 8])))
    c.mark('Write counters, registers, timers, flags and outputs; ACK and NAK responses')
    for cmd in (0x0A, 0x0E, 0x0F):
        pair(lambda q, cmd=cmd: req(q, cmd, bytes([4 * 2 + 3]) + struct.pack('>H', 0x30) + bytes(range(8))), lambda q: ack(q, 0))
    for cmd in (0x0B, 0x0D):
        pair(lambda q, cmd=cmd: req(q, cmd, bytes([3 + 2]) + struct.pack('>H', 0x40) + bytes([15]) + b'\x55\xaa\x01'[:3]), lambda q: ack(q, 0))
    pair(lambda q: req(q, 0x0E, bytes([4 + 3]) + struct.pack('>H', 0x31) + bytes(4)), lambda q: ack(q, 1))
    pair(lambda q: req(q, 0x0E, bytes([4 + 3]) + struct.pack('>H', 0x32) + bytes(4)), lambda q: ack(q, 2))
    pair(lambda q: req(q, 0x0E, bytes([4 + 3]) + struct.pack('>H', 0x33) + bytes(4)), lambda q: ack(q, 3))
    pair(lambda q: req(q, 0x0E, bytes([4 + 3]) + struct.pack('>H', 0x34) + bytes(4)), lambda q: ack(q, 4))
    pair(lambda q: req(q, 0x0E, bytes([4 + 3]) + struct.pack('>H', 0x35) + bytes(4)), lambda q: ack(q, 9))
    c.mark('Real time clock: read and write')
    pair(lambda q: req(q, 0x04), lambda q: rsp(q, CLOCK))
    pair(lambda q: req(q, 0x0C, CLOCK), lambda q: ack(q, 0))
    c.mark('Display register, user memory, program lines, bytes, EEPROM registers')
    pair(lambda q: req(q, 0x01), lambda q: rsp(q, b'\x00\x00\x00\x7f'))
    pair(lambda q: req(q, 0x96, bytes([1]) + b'\x00\x05\x00\x02'), lambda q: rsp(q, bytes(range(8))))
    pair(lambda q: req(q, 0x1E, bytes([1]) + b'\x00\x10\x20'), lambda q: rsp(q, bytes(range(8))))
    pair(lambda q: req(q, 0x1F, bytes([2]) + b'\x00\x10\x24'), lambda q: rsp(q, bytes(range(12))))
    pair(lambda q: req(q, 0x23, bytes([4 * 2 + 2]) + b'\x00\x20\x00' + bytes(range(8))), lambda q: ack(q, 0))
    pair(lambda q: req(q, 0x24, bytes([4 * 2 + 2]) + b'\x00\x20\x10' + bytes(range(8))), lambda q: ack(q, 0))
    pair(lambda q: req(q, 0x47, bytes([3]) + b'\x01\x02\x03'), lambda q: rsp(q, b'\x01\x02\x03\x04'))
    pair(lambda q: req(q, 0x51, bytes([2 + 3]) + b'\x01\x02\x03' + b'\xaa\xbb\xcc'), lambda q: ack(q, 0))
    pair(lambda q: req(q, 0xA1, bytes([0, 1]) + b'\x00\x08'), lambda q: rsp(q, bytes(range(8))))
    pair(lambda q: req(q, 0xA3, bytes([8]) + bytes(range(8))), lambda q: ack(q, 0))
    c.mark('Status and information requests: PCD status of every CPU, station number, program version, status flags and ACCU, index register, instruction pointer, history, current block')
    for cmd in (0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B):
        pair(lambda q, cmd=cmd: req(q, cmd), lambda q, cmd=cmd: rsp(q, bytes([cmd & 7])))
    pair(lambda q: req(q, 0x1D), lambda q: rsp(q, b'\x2a'))
    pair(lambda q: req(q, 0x20), lambda q: rsp(q, b'PCD2.' + b'001' + b'\0'))
    pair(lambda q: req(q, 0x46), lambda q: rsp(q, b'\x0b'))
    pair(lambda q: req(q, 0x49), lambda q: rsp(q, b'\x12\x34'))
    pair(lambda q: req(q, 0x4A), lambda q: rsp(q, b'\x00\x01\x02'))
    pair(lambda q: req(q, 0x4B), lambda q: rsp(q, b'\x00\x01\x02\x00\x07'))
    pair(lambda q: req(q, 0x9D), lambda q: rsp(q, b'\x01\x00\x09'))
    pair(lambda q: req(q, 0x9E), lambda q: rsp(q, b'\x01\x02'))
    c.mark('Read system information: information 0 and other numbers')
    pair(lambda q: req(q, 0xAB, bytes([0, 0])), lambda q: rsp(q, b'\x01\x5b'))
    pair(lambda q: req(q, 0xAB, bytes([0, 6])), lambda q: rsp(q, bytes([5]) + b'\x01\x02\x03\x04\x05'))
    c.mark('Multi media: reads of several media in one telegram with data and ACK/NAK sub responses')
    sub_rd = lambda cmd, cnt, addr: bytes([3, cmd]) + media_req(cmd, cnt, addr)
    sub_wr = lambda cmd, addr, data: bytes([3 + len(data), cmd, len(data) + 3]) + struct.pack('>H', addr) + data
    mm = sub_rd(0x06, 2, 0x10) + sub_rd(0x02, 9, 0x20) + sub_rd(0x00, 1, 0x30)
    pair(lambda q: req(q, 0x13, bytes([len(mm) - 1]) + mm),
         lambda q: rsp(q, bytes([20]) + bytes([9, 1]) + bytes(range(8)) + bytes([2, 1, 0xff, 0x01]) + bytes([4, 1]) + bytes(4)))
    mm = sub_rd(0x06, 1, 0x10) + sub_wr(0x0E, 0x20, bytes(4))
    pair(lambda q: req(q, 0x13, bytes([len(mm) - 1]) + mm),
         lambda q: rsp(q, bytes([10]) + bytes([5, 1]) + bytes(4) + bytes([2, 2, 0, 1])))
    c.mark('Web server serial communication: requests and responses with and without data and sequence numbers')
    for aid in (1, 2, 7):
        pair(lambda q, aid=aid: req(q, 0xAF, bytes([4, aid, q & 0xff]) + b'abc'), lambda q: rsp(q, bytes([6, 0x11, q & 0xff]) + b'data'))
    pair(lambda q: req(q, 0xAF, bytes([1, 7, 5])), lambda q: rsp(q, bytes([1, 0x12])))
    pair(lambda q: req(q, 0xAF, bytes([1, 0x55, 5])), lambda q: rsp(q, bytes([1, 0x66])))
    pair(lambda q: req(q, 0xAF, bytes([1, 2, 5])), lambda q: rsp(q, bytes([2, 0x13, 9])))
    c.mark('Read/write block telegrams (file and block variants): start, data, end and abort of streams, delete, size, block list, with ACK and NAK')
    fn = name24(b'config.cfg')
    cases = [
        (0x00, blk(0, 0, bytes([0, 0x20]) + struct.pack('>I', 1000) + fn + b'\0' * 4), 0x00),
        (0x00, blk(0, 0, bytes([1, 0x21]) + struct.pack('>I', 2000) + fn + b'\0' * 4), 0x00),
        (0x00, blk(0, 0, bytes([2, 0x01]) + struct.pack('>H', 5) + struct.pack('>I', 3000) + b'\xaa' * 6), 0x00),
        (0x01, blk(0, 1, bytes([3]) + b'\xbb' * 20), 0x01),
        (0x02, blk(0, 2, bytes([4]) + b'\xcc' * 10 + struct.pack('>I', 0xdeadbeef)), 0x02),
        (0x07, blk(0, 7, b''), 0x07),
        (0x08, blk(0, 8, bytes([0x20, 0x20]) + struct.pack('>I', 16) + fn + b'\0', 1), 0x08),
        (0x08, blk(0, 8, bytes([0x01, 0x01]) + struct.pack('>H', 5) + struct.pack('>I', 16) + b'\xdd' * 4, 1), 0x08),
        (0x10, blk(0, 0x10, bytes([1, 0x20]) + fn), 0x10),
        (0x10, blk(0, 0x10, bytes([1, 0x01]) + struct.pack('>H', 9)), 0x10),
        (0x11, blk(0, 0x11, bytes([2])), 0x11),
        (0x17, blk(0, 0x17, b''), 0x17),
        (0x18, blk(0, 0x18, bytes([0x20]) + struct.pack('>II', 0, 16) + fn), 0x18),
        (0x18, blk(0, 0x18, bytes([0x01]) + struct.pack('>H', 4) + struct.pack('>II', 32, 16)), 0x18),
        (0x20, blk(0, 0x20, bytes([0x20]) + fn), 0x20),
        (0x20, blk(0, 0x20, bytes([0x01]) + struct.pack('>H', 3)), 0x20),
        (0x21, blk(0, 0x21, bytes([0x21]) + fn), 0x21),
        (0x21, blk(0, 0x21, bytes([0x01]) + struct.pack('>H', 3)), 0x21),
        (0x22, blk(0, 0x22, bytes([1])), 0x22),
        (0x99, blk(0, 0x99, b''), 0x99),
    ]
    for tlgtype, rq, _ in cases:
        q = nxt()
        rqb = bytearray(rq); struct.pack_into('>H', rqb, 6, q)
        body = bytes(rqb[:-2]); rqb = body + struct.pack('>H', crc16(body))
        s.to_plc(bytes(rqb))
        if tlgtype in (0x00, 0x01, 0x02):
            s.from_plc(rsp(q, bytes([1, 0, tlgtype])))
        elif tlgtype in (0x07, 0x08, 0x17, 0x20):
            s.from_plc(rsp(q, bytes([1, 0])))
        elif tlgtype == 0x10:
            s.from_plc(rsp(q, bytes([6 + 3, 0, 1]) + struct.pack('>I', 99) + b'\x01\x02\x03'))
        elif tlgtype == 0x11:
            s.from_plc(rsp(q, bytes([4, 1, 2]) + b'\x01\x02'))
        elif tlgtype == 0x18:
            s.from_plc(rsp(q, bytes([5, 1]) + b'\x01\x02\x03\x04'))
        elif tlgtype == 0x21:
            if q % 2:
                s.from_plc(rsp(q, bytes([9, 0]) + struct.pack('>II', 4096, 0x01020304)))
            else:
                s.from_plc(rsp(q, bytes([1, 0x83])))
        elif tlgtype == 0x22:
            s.from_plc(rsp(q, bytes([8 + 2, 0, 0x20]) + struct.pack('>HI', 3, 77) + b'\x01\x02'))
        else:
            s.from_plc(rsp(q, bytes([2, 0x81])))
    c.mark('Retransmitted requests (same sequence number): retry marked, response time from the last request')
    q = nxt()
    s.to_plc(req(q, 0x06, media_req(0x06, 1, 0x10)))
    s.to_plc(req(q, 0x06, media_req(0x06, 1, 0x10)))
    s.to_plc(req(q, 0x06, media_req(0x06, 1, 0x10)))
    s.from_plc(rsp(q, bytes(4)))
    c.mark('Commands the dissector does not decode (request and response with trailing data), ACK/NAK without a request, response without a request')
    q = nxt()
    s.to_plc(req(q, 0x28, b'\x01\x02'))
    s.from_plc(rsp(q, b'\x01\x02\x03'))
    q = nxt()
    s.to_plc(req(q, 0x5A))
    s.from_plc(ack(q, 0))
    s.from_plc(ack(900, 1))
    s.from_plc(rsp(901, b'\x00\x00\x00\x01'))
    c.mark('Other protocol versions and the protocol byte set to 1')
    s.to_plc(req(nxt(), 0x1D, ver=0))
    s.from_plc(rsp(seq[0], b'\x01', ver=0))
    s.to_plc(req(nxt(), 0x1D, proto=1))
    s.from_plc(rsp(seq[0], b'\x01', proto=1))
    c.mark('A conversation on another port with a response before its request (reproducer of the two pass fix: the response is not matched to the later request)')
    s2 = Stream(c, 40050)
    s2.from_plc(rsp(5, b'\x00\x00\x00\x2a'))
    s2.to_plc(req(5, 0x06, media_req(0x06, 1, 0x10)))
    s2.from_plc(rsp(5, b'\x00\x00\x00\x2b'))
    c.mark('A response to a retried request on another conversation')
    s3 = Stream(c, 40051)
    s3.to_plc(req(7, 0x00, media_req(0, 2, 0x44)))
    s3.to_plc(req(7, 0x00, media_req(0, 2, 0x44)))
    s3.from_plc(rsp(7, bytes(8)))
    s3.to_plc(req(7, 0x00, media_req(0, 2, 0x44)))

    m = Cap(1)
    sm = Stream(m, 40100)
    m.mark('Bad checksum (error expert info), a PDU whose length does not match the datagram (not S-Bus), version 2, attribute 3')
    sm.to_plc(req(1, 0x06, media_req(0x06, 1, 0x10), crc=0x1234))
    sm.to_plc(req(2, 0x06, media_req(0x06, 1, 0x10), length=40))
    sm.to_plc(req(3, 0x06, media_req(0x06, 1, 0x10), ver=2))
    sm.to_plc(tlg(4, 3, b'\x01\x06\x00\x00\x10'))
    sm.to_plc(b'\x00\x00\x00\x0c\x01\x00\x00\x01\x00\x01\x06')
    sm.to_plc(b'\x00\x00\x00\x08\x01\x00\x00\x01\x00')
    sm.to_plc(b'\x01\x02\x03')
    sm.to_plc(b'\x00\x00\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00')
    sm.to_plc(b'\x00\x01\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00')
    sm.to_plc(req(5, 0x06, media_req(0x06, 1, 0x10), proto=2))
    m.mark('Truncated and inconsistent telegrams (exceptions with a tree): reads cut short, counts that are too large, sub requests that run past the end')
    for cmd in (0x00, 0x02, 0x0A, 0x0B, 0x0C, 0x13, 0x1E, 0x23, 0x47, 0x51, 0xA1, 0xAB, 0xAF, 0xA9):
        full = req(20, cmd, bytes([200, 1, 2, 3, 4, 5]))
        sm.to_plc(full)
        sm.to_plc(req(21, cmd, b'\x02'))
    mmbad = bytes([60]) + bytes([3, 0x06, 1, 0, 0x10]) + bytes([40, 0x0e, 90, 0, 1])
    sm.to_plc(req(30, 0x13, mmbad))
    sm.from_plc(rsp(30, bytes([10, 1, 1])))
    sm.to_plc(req(31, 0x13, bytes([4, 3, 0x06, 1, 0, 0x10][:6]) + bytes(2)))
    sm.from_plc(rsp(31, bytes([40, 9, 1, 0])))
    sm.to_plc(req(32, 0x13, bytes([10]) + bytes([9, 0x02, 9, 0, 0x20]) + b'\0' * 5))
    sm.from_plc(rsp(32, bytes([10, 5, 2, 0])))
    sm.to_plc(req(33, 0xAB, bytes([0, 6])))
    sm.from_plc(rsp(33, bytes([200, 1, 2])))
    sm.to_plc(req(34, 0xAF, bytes([1, 1, 1])))
    sm.from_plc(rsp(34, bytes([200, 0x11, 1, 2])))
    sm.to_plc(req(35, 0xA9, bytes([200, 0x10, 1, 0x20]) + b'A' * 30))
    sm.to_plc(req(36, 0xA9, bytes([0xff, 0x00, 1, 0x20]) + struct.pack('>I', 9) + b'N' * 30))
    sm.from_plc(rsp(35, bytes([200, 0])))
    sm.from_plc(rsp(36, bytes([4, 0x80])))
    sm.to_plc(req(37, 0x06, media_req(0x06, 1, 1)))
    sm.from_plc(rsp(37, b''))
    sm.to_plc(req(38, 0x0B, bytes([200, 0, 1, 2]) + b'\0' * 3))

    c.write(os.path.join(out, 'sbus-coverage.pcap'))
    m.write(os.path.join(out, 'sbus-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

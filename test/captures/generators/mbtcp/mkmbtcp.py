#!/usr/bin/env python3
# Generates test/captures/mbtcp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Modbus dissector
(packet-mbtcp.c): Modbus/TCP on TCP 502, Modbus/UDP on UDP 502, Modbus/TCP
Security (Exported PDU "mbtls"), Modbus RTU (Exported PDU "mbrtu", and over
TCP/UDP with Decode As) and the common Modbus PDU decoder for every
function code, exception, request/response matching.

Usage: mkmbtcp.py <output directory> [-v]
Writes
  mbtcp-coverage.pcapng            main capture (default preferences)
  mbtcp-coverage-decodeas.pcapng   Modbus RTU over TCP 5020 and UDP 5021
                                   (-d tcp.port==5020,mbrtu -d udp.port==5021,mbrtu)
  mbtcp-coverage-malformed.pcapng  paths only malformed input reaches
"""
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ Modbus

FC_COILS, FC_DISCRETE, FC_HOLDING, FC_INPUT, FC_WSCOIL, FC_WSREG, FC_EXSTAT, FC_DIAG = 1, 2, 3, 4, 5, 6, 7, 8
FC_EVCTR, FC_EVLOG, FC_WMCOIL, FC_WMREG, FC_SLAVEID = 11, 12, 15, 16, 17
FC_RFILE, FC_WFILE, FC_MASK, FC_RW, FC_FIFO, FC_MEI = 20, 21, 22, 23, 24, 43

CLI, SRV = '192.0.2.11', '192.0.2.12'


def mbap(trans, unit, pdu, proto=0, length=None):
    n = 1 + len(pdu) if length is None else length
    return struct.pack('>HHHB', trans, proto, n, unit) + pdu


def crc16(b):
    crc = 0xFFFF
    for x in b:
        crc ^= x
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def rtu(unit, pdu, bad_crc=False):
    body = bytes([unit]) + pdu
    c = crc16(body) ^ (0x5555 if bad_crc else 0)
    return body + struct.pack('<H', c)


def pdu(fc, data=b''):
    return bytes([fc]) + data


def w(v): return struct.pack('>H', v)


def pairs():
    """(request PDU, response PDU or None) for every function code."""
    P = []
    # reads
    P.append((pdu(1, w(0x13) + w(37)), pdu(1, bytes([5]) + bytes([0xCD, 0x6B, 0xB2, 0x0E, 0x1B]))))
    P.append((pdu(2, w(0xC4) + w(22)), pdu(2, bytes([3]) + bytes([0xAC, 0xDB, 0x35]))))
    P.append((pdu(3, w(0x6B) + w(3)), pdu(3, bytes([6]) + w(0x022B) + w(0x0000) + w(0x0064))))
    P.append((pdu(3, w(0x00) + w(4)), pdu(3, bytes([8]) + w(1) + w(2) + w(3) + w(4))))
    P.append((pdu(4, w(8) + w(1)), pdu(4, bytes([2]) + w(0x000A))))
    P.append((pdu(4, w(0) + w(3)), pdu(4, bytes([6]) + w(0xFFFF) + w(0x8000) + w(0x7FFF))))
    # single writes
    P.append((pdu(5, w(0xAC) + w(0xFF00)), pdu(5, w(0xAC) + w(0xFF00))))
    P.append((pdu(5, w(0xAD) + w(0x0000)), pdu(5, w(0xAD) + w(0x0000))))
    P.append((pdu(6, w(1) + w(3)), pdu(6, w(1) + w(3))))
    P.append((pdu(7), pdu(7, b'\x6D')))
    # diagnostics: every subfunction
    for sf, req, rsp in [
            (0x00, b'\xA5\x37', b'\xA5\x37'), (0x00, b'', b''), (0x01, w(0xFF00), w(0xFF00)),
            (0x01, w(0), w(0)), (0x02, w(0), w(0x1234)), (0x03, b'\x0A\x00', b'\x0A\x00'),
            (0x04, w(0), None), (0x0A, w(0), w(0)), (0x0B, w(0), w(0x0100)), (0x0C, w(0), w(0x0002)),
            (0x0D, w(0), w(0x0003)), (0x0E, w(0), w(0x0104)), (0x0F, w(0), w(0)), (0x10, w(0), w(0x0001)),
            (0x11, w(0), w(0x0002)), (0x12, w(0), w(0x0003)), (0x14, w(0), w(0)), (0x15, w(0x1234), w(0x1234)),
            (0x15, b'', b'')]:
        P.append((pdu(8, w(sf) + req), None if rsp is None else pdu(8, w(sf) + rsp)))
    P.append((pdu(11), pdu(11, w(0xFFFF) + w(0x0108))))
    P.append((pdu(12), pdu(12, bytes([6 + 6]) + w(0) + w(0x0108) + w(0x0121) + bytes([0x20, 0x00, 0x04, 0x81, 0x42, 0x20]))))
    P.append((pdu(12), pdu(12, bytes([6]) + w(0) + w(0) + w(0))))
    # multiple writes
    P.append((pdu(15, w(0x13) + w(10) + bytes([2]) + b'\xCD\x01'), pdu(15, w(0x13) + w(10))))
    P.append((pdu(16, w(1) + w(2) + bytes([4]) + w(0x000A) + w(0x0102)), pdu(16, w(1) + w(2))))
    P.append((pdu(16, w(1) + w(1) + bytes([2]) + w(0x000A)), pdu(16, w(1) + w(1))))
    P.append((pdu(17), pdu(17, bytes([5]) + b'\x01\xFF\x00\x01\x02')))
    # file records
    P.append((pdu(20, bytes([14]) + bytes([6]) + w(4) + w(1) + w(2) + bytes([6]) + w(3) + w(9) + w(2)),
              pdu(20, bytes([10]) + bytes([5, 6]) + w(0x0DFE) + w(0x0020) + bytes([5, 6]) + w(0x33CD) + w(0x0040))))
    P.append((pdu(21, bytes([13 + 0]) + bytes([6]) + w(4) + w(7) + w(3) + w(0x06AF) + w(0x04BE) + w(0x100D)),
              pdu(21, bytes([13]) + bytes([6]) + w(4) + w(7) + w(3) + w(0x06AF) + w(0x04BE) + w(0x100D))))
    P.append((pdu(22, w(4) + w(0x00F2) + w(0x0025)), pdu(22, w(4) + w(0x00F2) + w(0x0025))))
    P.append((pdu(23, w(3) + w(6) + w(14) + w(3) + bytes([6]) + w(0xFF) + w(0xFF) + w(0xFF)),
              pdu(23, bytes([12]) + w(0xFE) + w(0x0ACD) + w(1) + w(2) + w(3) + w(4))))
    P.append((pdu(24, w(0x04DE)), pdu(24, w(8) + w(3) + w(0x01B8) + w(0x1284) + w(0)) ))
    # encapsulated interface: read device id (basic and extended), CANopen, unknown MEI
    objs = [(0, b'Acme'), (1, b'MB-1'), (2, b'V1.2')]
    ext = [(0x80, b'\x01\x02'), (0x81, b''), (4, b'Prod'), (7, b'x' * 3)]
    def devid(code, objs, conf=1):
        body = bytes([0x0E, code, conf, 0, 0, len(objs)])
        for i, v in objs:
            body += bytes([i, len(v)]) + v
        return pdu(43, body)
    P.append((pdu(43, bytes([0x0E, 1, 0])), devid(1, objs)))
    P.append((pdu(43, bytes([0x0E, 3, 0])), devid(3, objs + ext, 0x83)))
    P.append((pdu(43, bytes([0x0E, 4, 5])), devid(4, [(5, b'Model')], 0x81)))
    P.append((pdu(43, bytes([0x0D, 0, 1, 2])), pdu(43, bytes([0x0D, 0, 1, 2, 3, 4]))))
    P.append((pdu(43, bytes([0x55, 7, 7])), pdu(43, bytes([0x55, 8, 8, 8]))))
    # unknown/other functions: default decoders
    P.append((pdu(90, b'\x01\x02\x03'), pdu(90, b'\x04\x05')))
    P.append((pdu(0x41, b'\xAA\xBB'), pdu(0x41, b'\xCC')))
    P.append((pdu(100), pdu(100, b'\x00')))
    return P


def exceptions():
    out = []
    for fc in (1, 2, 3, 4, 5, 6, 8, 15, 16, 20, 21, 22, 23, 24, 43, 90):
        for code in (1, 2, 3, 4, 5, 6, 8, 10, 11, 0x7F):
            out.append((pdu(fc, b'\x00\x01\x00\x01'), pdu(fc | 0x80, bytes([code]))))
    return out


def tcp_frames(cport=49500, port=502):
    f = []
    c = TCP(CLI, cport, SRV, port)
    f += c.handshake()
    tid = [1]
    for i, (rq, rs) in enumerate(pairs()):
        unit = [1, 17, 255, 0, 247][i % 5]
        f.append(c.c2s(mbap(tid[0], unit, rq)))
        if rs is not None:
            f.append(c.s2c(mbap(tid[0], unit, rs)))
        tid[0] += 1
    for rq, rs in exceptions()[:60]:
        f.append(c.c2s(mbap(tid[0], 1, rq)))
        f.append(c.s2c(mbap(tid[0], 1, rs)))
        tid[0] += 1
    # exception code 0 (response treated as a normal PDU)
    f.append(c.c2s(mbap(900, 1, pdu(3, w(0) + w(1)))))
    f.append(c.s2c(mbap(900, 1, pdu(0x83, b'\x00'))))
    return f, c


def tcp_special(c, tid0=1000):
    """Pipelined requests, matching by transaction ID, reassembly."""
    f = []
    # three queries in one segment, answers in another order, in one segment
    q = [mbap(tid0 + i, 5, pdu(3, w(i) + w(2))) for i in range(3)]
    f.append(c.c2s(b''.join(q)))
    r = [mbap(tid0 + i, 5, pdu(3, bytes([4]) + w(i) + w(i + 1))) for i in (2, 0, 1)]
    f.append(c.s2c(b''.join(r)))
    # a query repeated with the same transaction ID: the later one matches
    f.append(c.c2s(mbap(tid0 + 10, 5, pdu(3, w(0x10) + w(1)))))
    f.append(c.c2s(mbap(tid0 + 10, 5, pdu(3, w(0x20) + w(1)))))
    f.append(c.s2c(mbap(tid0 + 10, 5, pdu(3, bytes([2]) + w(7)))))
    # same transaction and unit with another function code: no match
    f.append(c.s2c(mbap(tid0 + 10, 5, pdu(4, bytes([2]) + w(8)))))
    # responses without a request: coils (bit count from the byte count) and registers
    f.append(c.s2c(mbap(tid0 + 20, 6, pdu(1, bytes([2, 0xFF, 0x01])))))
    f.append(c.s2c(mbap(tid0 + 21, 6, pdu(3, bytes([4]) + w(1) + w(2)))))
    # query with a one-octet and a two-octet function data (short PDUs)
    f.append(c.c2s(mbap(tid0 + 30, 6, pdu(7))))
    f.append(c.c2s(mbap(tid0 + 31, 6, pdu(0x41, b'\x00'))))
    f.append(c.c2s(mbap(tid0 + 32, 6, pdu(3, b'\x00\x01\x00\x05'))))
    # a PDU split over two segments, one split inside the MBAP header, one with 5 segments
    big = mbap(tid0 + 40, 7, pdu(16, w(0) + w(20) + bytes([40]) + bytes(range(40))))
    f.append(c.c2s(big[:20]))
    f.append(c.c2s(big[20:]))
    hdrsplit = mbap(tid0 + 41, 7, pdu(3, w(0) + w(2)))
    f.append(c.c2s(hdrsplit[:3]))
    f.append(c.c2s(hdrsplit[3:]))
    long_rsp = mbap(tid0 + 41, 7, pdu(3, bytes([100]) + bytes(range(100))))
    for i in range(0, len(long_rsp), 30):
        f.append(c.s2c(long_rsp[i:i + 30]))
    # a segment holding a complete PDU followed by the start of the next
    a = mbap(tid0 + 50, 7, pdu(6, w(1) + w(2)))
    b = mbap(tid0 + 51, 7, pdu(6, w(2) + w(3)))
    f.append(c.c2s(a + b[:5]))
    f.append(c.c2s(b[5:]))
    # maximum length PDU (254) and a length of 2
    f.append(c.c2s(mbap(tid0 + 60, 7, pdu(16, w(0) + w(100) + bytes([200]) + bytes(200)))))
    f.append(c.c2s(mbap(tid0 + 61, 7, pdu(7))))
    return f


def udp_frames():
    f = []
    for i, (rq, rs) in enumerate(pairs()[:30]):
        unit = [1, 2, 3][i % 3]
        f.append(udp(mbap(2000 + i, unit, rq), CLI, 50000, SRV, 502))
        if rs is not None:
            f.append(udp(mbap(2000 + i, unit, rs), SRV, 502, CLI, 50000))
    # response without a request, exception
    f.append(udp(mbap(2100, 1, pdu(0x83, b'\x02')), SRV, 502, CLI, 50000))
    f.append(udp(mbap(2101, 1, pdu(3, w(0) + w(1))), CLI, 50001, SRV, 502))
    f.append(udp(mbap(2101, 1, pdu(0x83, b'\x0B')), SRV, 502, CLI, 50001))
    return f


def epdu_ports(name, payload, src, dst):
    nm = name.encode()
    pad = (4 - len(nm) % 4) % 4
    tags = struct.pack('!HH', 12, len(nm) + pad) + nm + b'\0' * pad
    tags += struct.pack('!HHI', 24, 4, 2) + struct.pack('!HHI', 25, 4, src) + struct.pack('!HHI', 26, 4, dst)
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def tls_frames():
    """Modbus/TCP Security (decrypted) through Exported PDU with TCP ports 802."""
    f = []
    for i, (rq, rs) in enumerate(pairs()[:8]):
        f.append(epdu_ports('mbtls', mbap(3000 + i, 1, rq), 49600, 802))
        if rs is not None:
            f.append(epdu_ports('mbtls', mbap(3000 + i, 1, rs), 802, 49600))
    return f


def rtu_raw_frames():
    """Raw Modbus RTU (Exported PDU "mbrtu"): query/response classified from
    the function code and length (no ports)."""
    f = []

    def add(unit, pd):
        f.append(exported_pdu('mbrtu', rtu(unit, pd)))
    add(1, pdu(3, w(0) + w(2)))                              # 8 octets: query
    add(1, pdu(3, bytes([4]) + w(1) + w(2)))                 # response
    add(2, pdu(4, w(0) + w(1)))
    add(2, pdu(4, bytes([2]) + w(5)))
    add(3, pdu(1, w(0) + w(9)))                              # coils, 8 octets, byte 2 != 3: query
    add(3, pdu(1, bytes([3, 1, 2, 3])))                      # response
    add(3, pdu(1, w(0x0300) + w(9)))                         # looks like a response (byte count 3)
    add(4, pdu(2, w(0) + w(9)))
    add(4, pdu(2, bytes([2, 0xFF, 0x01])))                   # 7 octets: response
    add(5, pdu(5, w(3) + w(0xFF00)))                         # cannot classify
    add(5, pdu(6, w(3) + w(7)))
    add(6, pdu(16, w(1) + w(2) + bytes([4]) + w(1) + w(2)))  # long: query
    add(6, pdu(16, w(1) + w(2)))                             # 8 octets: response
    add(7, pdu(15, w(1) + w(9) + bytes([2, 0xAA, 0x01])))
    add(7, pdu(15, w(1) + w(9)))
    add(8, pdu(0x83, b'\x02'))                               # exception: response
    add(8, pdu(0xAB, b'\x01'))                               # exception on an unknown function
    add(9, pdu(8, w(0) + b'\x12\x34'))                       # not classified
    add(9, pdu(43, bytes([0x0E, 1, 0])))
    add(9, pdu(43, b'\x0E\x01\x00\x01\x00\x00'))
    add(10, pdu(7))
    add(0xF7, pdu(0x90, b'\x01\x02'))
    return f


def rtu_stream(c, units=1):
    """RTU over a TCP stream (Decode As): framing by function code."""
    f = []
    f.append(c.c2s(rtu(1, pdu(3, w(0) + w(2)))))
    f.append(c.s2c(rtu(1, pdu(3, bytes([4]) + w(1) + w(2)))))
    f.append(c.c2s(rtu(1, pdu(1, w(0) + w(9)))))
    f.append(c.s2c(rtu(1, pdu(1, bytes([2, 0xFF, 0x01])))))
    f.append(c.c2s(rtu(1, pdu(5, w(3) + w(0xFF00)))))
    f.append(c.s2c(rtu(1, pdu(5, w(3) + w(0xFF00)))))
    f.append(c.c2s(rtu(1, pdu(6, w(3) + w(0x1234)))))
    f.append(c.s2c(rtu(1, pdu(6, w(3) + w(0x1234)))))
    f.append(c.c2s(rtu(2, pdu(16, w(1) + w(2) + bytes([4]) + w(1) + w(2)))))
    f.append(c.s2c(rtu(2, pdu(16, w(1) + w(2)))))
    f.append(c.c2s(rtu(2, pdu(15, w(1) + w(9) + bytes([2, 0xAA, 0x01])))))
    f.append(c.s2c(rtu(2, pdu(15, w(1) + w(9)))))
    f.append(c.c2s(rtu(2, pdu(4, w(1) + w(2)))))
    f.append(c.s2c(rtu(2, pdu(4, bytes([4]) + w(1) + w(2)))))
    f.append(c.c2s(rtu(2, pdu(2, w(1) + w(2)))))
    f.append(c.s2c(rtu(2, pdu(2, bytes([1, 3])))))
    f.append(c.s2c(rtu(2, pdu(0x83, b'\x02'))))
    # two RTU frames in one segment, one split over two segments
    a = rtu(3, pdu(3, w(0) + w(1)))
    b = rtu(3, pdu(3, w(2) + w(1)))
    f.append(c.c2s(a + b))
    r = rtu(3, pdu(3, bytes([2]) + w(9)))
    f.append(c.s2c(r[:3]))
    f.append(c.s2c(r[3:]))
    # unclassified functions use the length of the segment
    f.append(c.c2s(rtu(3, pdu(8, w(0) + b'\x12\x34'))))
    f.append(c.s2c(rtu(3, pdu(8, w(0) + b'\x12\x34'))))
    f.append(c.c2s(rtu(3, pdu(0x2B, b'\x0E\x01\x00'))))
    f.append(c.s2c(rtu(3, pdu(0x11, b'\x03\x01\xff\x00'))))
    return f


def decodeas_frames():
    f = []
    c = TCP(CLI, 49700, SRV, 5020)
    f += c.handshake()
    f += rtu_stream(c)
    # UDP
    for i, (u, pd) in enumerate([(1, pdu(3, w(0) + w(2))), (1, pdu(3, bytes([4]) + w(1) + w(2))),
                                  (2, pdu(6, w(1) + w(2))), (2, pdu(1, w(0) + w(9))),
                                  (2, pdu(1, bytes([2, 0xFF, 0x01]))), (3, pdu(0x83, b'\x01'))]):
        if i % 2 == 0:
            f.append(udp(rtu(u, pd), CLI, 50100, SRV, 5021))
        else:
            f.append(udp(rtu(u, pd), SRV, 5021, CLI, 50100))
    return f


def main_frames():
    f, c = tcp_frames()
    f += tcp_special(c)
    f += udp_frames()
    f += tls_frames()
    f += rtu_raw_frames()
    return f


def malformed_frames():
    f = []
    c = TCP(CLI, 49800, SRV, 502)
    f += c.handshake()
    # invalid protocol identifier, length 0/1 (invalid), length above 254,
    # unit/function missing
    f.append(c.c2s(mbap(1, 1, pdu(3, w(0) + w(1)), proto=7)))
    f.append(c.s2c(mbap(1, 1, pdu(3, bytes([2]) + w(1)), proto=1)))
    f.append(c.c2s(mbap(2, 1, b'', length=1)))
    f.append(c.c2s(mbap(3, 1, b'\x03\x00\x01\x00\x01', length=0)))
    f.append(c.c2s(mbap(4, 1, pdu(3, w(0) + w(300)) + bytes(250), length=300)))
    # UDP with a length of 0 and 1 (short PDU): the fixed Modbus/UDP case
    f.append(udp(mbap(5, 1, b'', length=1), CLI, 50000, SRV, 502))
    f.append(udp(mbap(6, 1, b'', length=0), CLI, 50000, SRV, 502))
    f.append(udp(mbap(7, 1, b'\x03', length=1), CLI, 50000, SRV, 502))
    f.append(udp(b'\x00\x08\x00\x00\x00\x02\x01', CLI, 50000, SRV, 502))    # too short for the header
    # not Modbus on a non-502 port: rejected; packets that cannot be classified
    f.append(udp(mbap(8, 1, pdu(3, w(0) + w(1)), proto=3), CLI, 6000, SRV, 6001))
    f.append(udp(mbap(9, 1, pdu(3, w(0) + w(1))), CLI, 502, SRV, 502))
    f.append(udp(mbap(10, 1, pdu(3, w(0) + w(1))), CLI, 6000, SRV, 502))
    # truncated PDUs of every kind of structure
    for pd in [pdu(1), pdu(1, b'\x00'), pdu(3, b'\x00\x01\x02'), pdu(5, w(1)), pdu(5, w(1) + w(0xFF00)[:1]),
               pdu(8), pdu(8, b'\x00'), pdu(8, w(1) + b'\x00'), pdu(8, w(3)), pdu(15, w(0) + w(8) + bytes([5]) + b'\x01'),
               pdu(16, w(0) + w(2) + bytes([4]) + b'\x01'), pdu(16, w(0) + w(2) + bytes([4]) + bytes(8)),
               pdu(20, bytes([14]) + bytes([6]) + w(4)), pdu(21, bytes([20]) + bytes([6]) + w(4) + w(7) + w(30)),
               pdu(21, bytes([7]) + bytes([6]) + w(4) + w(7) + w(0xFFFF)), pdu(22, w(1) + w(2)),
               pdu(23, w(0) + w(1) + w(2) + w(3)), pdu(23, w(0) + w(1) + w(2) + w(3) + bytes([200]) + b'\x01'),
               pdu(24), pdu(43), pdu(43, b'\x0E'), pdu(43, b'\x0E\x01')]:
        f.append(c.c2s(mbap(100, 2, pd)))
    for pd in [pdu(1), pdu(1, bytes([9, 1])), pdu(3, bytes([8, 0])), pdu(5), pdu(7), pdu(8), pdu(8, w(2)),
               pdu(11, b'\x00'), pdu(12), pdu(12, bytes([40]) + bytes(8)), pdu(12, bytes([200]) + bytes(8)),
               pdu(15, w(1)), pdu(20, bytes([5]) + bytes([9])), pdu(20, bytes([200, 100, 6]) + bytes(10)),
               pdu(21, bytes([20, 6]) + w(1) + w(2) + w(0xFFFF)), pdu(22, w(1)), pdu(23), pdu(24, w(1)),
               pdu(24, w(0) + w(1)), pdu(24, w(300) + w(1) + bytes(4)), pdu(43), pdu(43, b'\x0E\x01\x01\x00'),
               pdu(43, b'\x0E\x01\x01\x00\x00\x03' + bytes([0, 200]) + b'ab'),
               pdu(43, b'\x0E\x01\x01\x00\x00\x02' + bytes([1, 3]) + b'ab'),
               pdu(43, b'\x0E\x01\x01\x00\x00\x05' + bytes([8, 1, 0, 1, 7, 0])), pdu(0x83), pdu(0x93)]:
        f.append(c.s2c(mbap(100, 2, pd)))
    # a PDU that never completes (length 254, one segment)
    f.append(c.c2s(mbap(300, 1, pdu(3, w(0) + w(1)), length=254)))
    # odd register byte count and short PDUs (exceptions)
    f.append(c.c2s(mbap(301, 1, pdu(16, w(1) + w(1) + bytes([3]) + w(0x000A) + b'\x01'))))
    f.append(c.c2s(mbap(302, 6, pdu(3))))
    f.append(c.c2s(mbap(303, 6, pdu(3, b'\x00'))))
    f.append(c.c2s(mbap(304, 6, pdu(3, b'\x00\x01\x00'))))
    # raw RTU: bad CRC, short packets, exception with and without data
    for u, pd, bad in [(1, pdu(3, w(0) + w(2)), True), (2, pdu(0x83, b'\x02'), True)]:
        f.append(exported_pdu('mbrtu', rtu(u, pd, bad)))
    f.append(exported_pdu('mbrtu', bytes([1, 3, 0, 0])))                # 4 octets (rejected)
    f.append(exported_pdu('mbrtu', bytes([1, 3, 0, 0, 0])))             # 5 octets
    f.append(exported_pdu('mbrtu', bytes([1, 3, 0, 0, 0, 1])))
    f.append(exported_pdu('mbrtu', rtu(1, pdu(3, b''))))
    f.append(exported_pdu('mbrtu', rtu(1, pdu(0x83, b''))[:4] + b'\x00'))
    f.append(exported_pdu('mbrtu', rtu(1, b'\x03' + bytes(70000 % 65536 + 70000))))   # over 64 KiB
    # RTU over TCP 5020 / UDP 5021 (Decode As): unit 0, too short for RTU
    c2 = TCP(CLI, 49900, SRV, 5020)
    f += c2.handshake()
    f.append(c2.c2s(rtu(0, pdu(3, w(0) + w(2)))))
    f.append(c2.c2s(b'\x01\x03\x00'))
    f.append(udp(b'\x01\x03\x00', CLI, 50100, SRV, 5021))
    f.append(udp(rtu(0, pdu(3, w(0) + w(2))), CLI, 50100, SRV, 5021))
    f.append(exported_pdu('mbtls', mbap(1, 1, pdu(3, w(0) + w(1)))))     # no ports: cannot classify
    # mbtls with a length of one (short)
    f.append(epdu_ports('mbtls', mbap(5, 1, b'', length=1), 1, 802))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    pcapng(out + '/mbtcp-coverage.pcapng', mf)
    df = decodeas_frames()
    pcapng(out + '/mbtcp-coverage-decodeas.pcapng', df)
    xf = malformed_frames()
    pcapng(out + '/mbtcp-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main', len(mf), 'decodeas', len(df), 'malformed', len(xf))


main()

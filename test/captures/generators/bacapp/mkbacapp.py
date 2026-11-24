#!/usr/bin/env python3
# Generates test/captures/bacapp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BACnet APDU dissector
(epan/dissectors/packet-bacapp.c).

BACnet/IP: Ethernet / IPv4 / UDP 47808 / BVLC Original-Unicast-NPDU /
NPDU / APDU. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkbacapp.py <output directory>

Writes:
  bacapp-coverage.pcap            every APDU type, confirmed and
                                  unconfirmed services with their ACKs and
                                  errors, rejects, aborts, segmented
                                  requests and ACKs (reassembly, also past
                                  sequence number 255), and the property
                                  value decoders of fAbstractSyntaxNType
  bacapp-coverage-malformed.pcap  paths only bad input reaches (error
                                  expert infos, exceptions)
  bacapp-coverage-bsc.pcap        BACnet/SC header options (hint, token) as
                                  exported PDUs, which packet-bvlc.c passes
                                  to bacnet_dissect_scope/token()

A section table (first frame of each section) is printed on stdout.
"""

import os
import struct
import sys

# ---------------------------------------------------------------------------
# Frame building

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def bacnet_frame(apdu, src=1, dst=2, npdu_ctrl=0x04):
    npdu = bytes([0x01, npdu_ctrl])
    bvlc_payload = npdu + apdu
    bvlc = bytes([0x81, 0x0a]) + struct.pack('!H', 4 + len(bvlc_payload)) + bvlc_payload
    udp = struct.pack('!HHHH', 47808, 47808, 8 + len(bvlc), 0) + bvlc
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, src]), bytes([192, 0, 2, dst]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + b'\x08\x00'
    return eth + ip + udp


def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------------------
# BACnet tag encoding (ASHRAE 135 clause 20.2)

def _hdr(tagno, ctx, length):
    cls = 0x08 if ctx else 0
    if tagno >= 15:
        first, ext = 0xF0, bytes([tagno])
    else:
        first, ext = tagno << 4, b''
    if length <= 4:
        return bytes([first | cls | length]) + ext
    if length <= 253:
        return bytes([first | cls | 5]) + ext + bytes([length])
    if length <= 65535:
        return bytes([first | cls | 5]) + ext + bytes([254]) + struct.pack('!H', length)
    return bytes([first | cls | 5]) + ext + bytes([255]) + struct.pack('!I', length)


def tag(tagno, ctx, data):
    return _hdr(tagno, ctx, len(data)) + data


def op(n):
    return bytes([0xFE, n]) if n >= 15 else bytes([(n << 4) | 0x0E])


def cl(n):
    return bytes([0xFF, n]) if n >= 15 else bytes([(n << 4) | 0x0F])


def wrap(n, *items):
    return op(n) + b''.join(items) + cl(n)


def uenc(v):
    if v == 0:
        return b'\0'
    n = (v.bit_length() + 7) // 8
    return v.to_bytes(n, 'big')


def senc(v):
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return v.to_bytes(n, 'big', signed=True)


def strenc(s, charset=0):
    if isinstance(s, str):
        if charset == 3:
            s = s.encode('utf-32-be')
        elif charset == 4:
            s = s.encode('utf-16-be')
        elif charset == 5:
            s = s.encode('latin-1')
        else:
            s = s.encode('utf-8')
    if charset == 1:
        return bytes([1]) + struct.pack('!H', 932) + s
    return bytes([charset]) + s


def bitsenc(bits):
    nbytes = (len(bits) + 7) // 8 or 1
    unused = nbytes * 8 - len(bits)
    v = 0
    for i, b in enumerate(bits):
        if b == '1':
            v |= 1 << (nbytes * 8 - 1 - i)
    return bytes([unused]) + v.to_bytes(nbytes, 'big')


def oidenc(otype, inst):
    return struct.pack('!I', (otype << 22) | inst)

# application tagged
A_NULL = b'\x00'
def a_bool(v): return bytes([0x10 | (1 if v else 0)])
def a_uint(v): return tag(2, False, uenc(v))
def a_int(v): return tag(3, False, senc(v))
def a_real(f): return tag(4, False, struct.pack('!f', f))
def a_double(d): return tag(5, False, struct.pack('!d', d))
def a_oct(b): return tag(6, False, b)
def a_str(s, cs=0): return tag(7, False, strenc(s, cs))
def a_bits(b): return tag(8, False, bitsenc(b))
def a_enum(v): return tag(9, False, uenc(v))
def a_date(y=124, m=10, d=29, wd=2): return tag(10, False, bytes([y, m, d, wd]))
def a_time(h=13, mi=45, s=30, hs=12): return tag(11, False, bytes([h, mi, s, hs]))
def a_oid(t, i): return tag(12, False, oidenc(t, i))

# context tagged
def c_null(n): return tag(n, True, b'')
def c_bool(n, v): return tag(n, True, bytes([1 if v else 0]))
def c_uint(n, v): return tag(n, True, uenc(v))
c_enum = c_uint
def c_int(n, v): return tag(n, True, senc(v))
def c_real(n, f): return tag(n, True, struct.pack('!f', f))
def c_double(n, d): return tag(n, True, struct.pack('!d', d))
def c_oct(n, b): return tag(n, True, b)
def c_str(n, s, cs=0): return tag(n, True, strenc(s, cs))
def c_bits(n, b): return tag(n, True, bitsenc(b))
def c_date(n, y=124, m=10, d=29, wd=2): return tag(n, True, bytes([y, m, d, wd]))
def c_time(n, h=13, mi=45, s=30, hs=12): return tag(n, True, bytes([h, mi, s, hs]))
def c_oid(n, t, i): return tag(n, True, oidenc(t, i))

def datetime(y=124, m=10, d=29, wd=2, h=13, mi=45, s=30, hs=12):
    return a_date(y, m, d, wd) + a_time(h, mi, s, hs)

def c_datetime(n, *a):
    return wrap(n, datetime(*a))

# BACnetTimeStamp choices
def ts_time(): return c_time(0, 8, 0, 0, 0)
def ts_seq(v=42): return c_uint(1, v)
def ts_dt(): return wrap(2, datetime())

def error(cls=2, code=31):
    return a_enum(cls) + a_enum(code)

# BACnetAddress: network number + MAC
def address(net=5, mac=b'\xc0\x00\x02\x05\xba\xc0'):
    return a_uint(net) + a_oct(mac)

def hostnport(host, port=47808):
    return wrap(0, host) + c_uint(1, port)

# ---------------------------------------------------------------------------
# APDUs

def confirmed(invoke, service, params=b'', sa=True, maxresp=0x05):
    return bytes([0x02 if sa else 0x00, maxresp, invoke, service]) + params

def unconfirmed(service, params=b''):
    return bytes([0x10, service]) + params

def simple_ack(invoke, service):
    return bytes([0x20, invoke, service])

def complex_ack(invoke, service, params=b''):
    return bytes([0x30, invoke, service]) + params

def segment_ack(invoke, seq, window=4, nak=False, srv=False):
    return bytes([0x40 | (0x02 if nak else 0) | (0x01 if srv else 0), invoke, seq, window])

def error_pdu(invoke, service, params):
    return bytes([0x50, invoke, service]) + params

def reject(invoke, reason):
    return bytes([0x60, invoke, reason])

def abort(invoke, reason, srv=False):
    return bytes([0x70 | (1 if srv else 0), invoke, reason])

def seg_request(invoke, seq, window, service, chunk, more):
    flags = 0x08 | (0x04 if more else 0) | 0x02
    return bytes([flags, 0x05, invoke, seq, window, service]) + chunk

def seg_cack(invoke, seq, window, service, chunk, more):
    flags = 0x08 | (0x04 if more else 0)
    return bytes([0x30 | flags, invoke, seq, window, service]) + chunk

# ReadProperty-ACK carrying one property value
_inv = [0]
def next_invoke():
    _inv[0] = (_inv[0] + 1) % 256
    return _inv[0]

def rp_ack(otype, inst, prop, value, idx=None):
    p = c_oid(0, otype, inst) + c_uint(1, prop)
    if idx is not None:
        p += c_uint(2, idx)
    p += wrap(3, value)
    return complex_ack(next_invoke(), 12, p)

# Object types
DEVICE, AI, AO, AV, BI, BO, BV, CALENDAR, COMMAND, EVENT_ENROLLMENT = 8, 0, 1, 2, 3, 4, 5, 6, 7, 9
FILE, GROUP, LOOP, MSI, NOTIF_CLASS, PROGRAM, SCHEDULE, AVERAGING = 10, 11, 12, 13, 15, 16, 17, 18
TRENDLOG, LIFE_POINT, LIFE_ZONE, ACCUMULATOR, PULSE_CONV, EVENT_LOG = 20, 21, 22, 23, 24, 25
GLOBAL_GROUP, TRENDLOG_MULTI, LOAD_CONTROL, ACCESS_DOOR, TIMER = 26, 27, 28, 30, 31
ACCESS_ZONE, CRED_DATA_INPUT, DTPV, DTV, BITSTRING_VALUE = 36, 37, 43, 44, 39
CHANNEL, LIGHTING_OUTPUT, NETWORK_PORT, ELEVATOR_GROUP, ESCALATOR, LIFT = 53, 54, 56, 57, 58, 59
AUDIT_LOG, COLOR, COLOR_TEMP = 61, 63, 64


# ---------------------------------------------------------------------------

def main_frames():
    sections = []
    frames = []

    def sec(name):
        sections.append((len(frames) + 1, name))

    def add(apdu, src=1, dst=2):
        frames.append(bacnet_frame(apdu, src, dst))

    def req(apdu):  # client 192.0.2.1 -> server 192.0.2.2
        add(apdu, 1, 2)

    def rsp(apdu):
        add(apdu, 2, 1)

    # ------------------------------------------------------------------
    sec('Fixed-branch reproducers')
    # bacapp_tree_depth.py: 520 empty monitoredPropertyIdentifier pairs
    req(bytes([0x00, 0x05, 0x01, 28]) + b'\x4e\x4f' * 520)
    # bacapp_stale_state.py: an ACK without objectIdentifier, then one for access-door
    val = b'\x19\x55' + b'\x3e\x91\x01\x3f'
    rsp(bytes([0x30, 0x01, 12]) + val)
    rsp(bytes([0x30, 0x02, 12]) + b'\x0c\x07\x80\x00\x01' + val)
    # bacapp_priority_index.py: priority-array[200]
    rsp(bytes([0x30, 0x01, 12]) + b'\x0c\x00\x40\x00\x01' + b'\x19\x57' + b'\x29\xc8'
        + b'\x3e' + b'\x00' * 3 + b'\x3f')

    # ------------------------------------------------------------------
    sec('APDU types: simple ACK, segment ACK, reject, abort, unknown service')
    rsp(simple_ack(10, 15))
    rsp(simple_ack(11, 200))           # unknown service
    add(segment_ack(12, 3, 4), 1, 2)
    add(segment_ack(12, 3, 4, nak=True, srv=True), 2, 1)
    for i, r in enumerate((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 40, 70)):
        rsp(reject(20 + i, r))
    for i, r in enumerate((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 40, 70)):
        add(abort(40 + i, r, srv=bool(i & 1)), 2 if i & 1 else 1, 1 if i & 1 else 2)
    req(confirmed(60, 99, c_uint(0, 1)))    # unknown confirmed service
    rsp(complex_ack(60, 99, c_uint(0, 1)))  # unknown ACK
    req(unconfirmed(99, c_uint(0, 1)))      # unknown unconfirmed service
    req(confirmed(61, 3))                   # GetAlarmSummary, no parameters
    req(confirmed(61, 3, A_NULL))           # GetAlarmSummary with a stray octet
    req(confirmed(62, 12, sa=False, maxresp=0x7f))

    # ------------------------------------------------------------------
    sec('Unconfirmed services')
    req(unconfirmed(0, a_oid(DEVICE, 1234) + a_uint(1476) + a_enum(0) + a_uint(8)))
    req(unconfirmed(0, a_oid(DEVICE, 4194303) + a_uint(480) + a_enum(3) + a_uint(260)))
    req(unconfirmed(1, a_oid(DEVICE, 1234) + a_oid(AI, 1) + a_str('Zone Temp')))
    req(unconfirmed(7, c_uint(0, 1) + c_uint(1, 5000) + c_oid(2, AI, 7)))
    req(unconfirmed(7, c_str(3, 'Zone Temp')))
    req(unconfirmed(8))
    req(unconfirmed(8, c_uint(0, 0) + c_uint(1, 4194303)))
    req(unconfirmed(6, datetime()))
    req(unconfirmed(6))
    req(unconfirmed(9, datetime(255, 255, 255, 255, 255, 255, 255, 255)))
    req(unconfirmed(9))
    req(unconfirmed(5, c_oid(0, DEVICE, 5) + wrap(1, c_uint(0, 3)) + c_enum(2, 1)
                    + c_str(3, 'Fire alarm')))
    req(unconfirmed(5, c_oid(0, DEVICE, 5) + wrap(1, c_str(1, 'maint')) + c_enum(2, 0)
                    + c_str(3, 'Filter change')))
    req(unconfirmed(4, c_uint(0, 8) + c_uint(1, 1) + wrap(2, a_uint(7), c_real(0, 1.5))))
    req(unconfirmed(13, a_uint(260) + a_str('Model X') + a_str('SN-0001')))
    req(unconfirmed(14, a_uint(260) + a_str('Model X') + a_str('SN-0001') + a_oid(DEVICE, 77)))
    req(unconfirmed(14, a_uint(260) + a_str('Model X') + a_str('SN-0001') + a_oct(b'\x0a')))
    req(unconfirmed(14, a_uint(260) + a_str('Model X') + a_str('SN-0001') + a_oid(DEVICE, 77)
                    + a_oct(b'\x0a')))
    # WriteGroup: channel value choices
    req(unconfirmed(10, c_uint(0, 100) + c_uint(1, 8) + wrap(2,
        c_uint(0, 1), a_real(21.5),
        c_uint(0, 2), c_uint(1, 4), a_uint(7),
        c_uint(0, 3), A_NULL,
        c_uint(0, 4), a_bool(1),
        c_uint(0, 5), wrap(0, c_enum(0, 1), c_real(1, 75.0), c_uint(5, 8)),
        c_uint(0, 6), wrap(1, a_real(0.3), a_real(0.4)),
        c_uint(0, 7), wrap(2, c_enum(0, 1), wrap(1, a_real(0.3), a_real(0.3)), c_uint(3, 100)),
        c_uint(0, 8), c_oct(5, b'\x01\x02'),
        ) + c_bool(3, True)))

    # COV notifications
    covvals = (c_uint(0, 85) + wrap(2, a_real(22.5)) + c_uint(0, 111) + wrap(2, a_bits('0000'))
               + c_uint(0, 87) + c_uint(1, 8) + wrap(2, a_real(1.0)) + c_uint(3, 8))
    req(unconfirmed(2, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + c_uint(3, 3600)
                    + wrap(4, covvals)))
    req(unconfirmed(11, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_uint(2, 60) + c_datetime(3)
                    + wrap(4, c_oid(0, AI, 1), wrap(1,
                        c_uint(0, 85), wrap(2, a_real(1.5)), c_time(3),
                        c_uint(0, 87), c_uint(1, 3), wrap(2, A_NULL)),
                      c_oid(0, BV, 2), wrap(1, c_uint(0, 85), wrap(2, a_enum(1)))) ))

    # ------------------------------------------------------------------
    sec('Confirmed services and their ACKs/errors')
    inv = 100
    def cr(service, params=b'', **kw):
        req(confirmed(inv, service, params, **kw))

    # 0 AcknowledgeAlarm
    cr(0, c_uint(0, 1) + c_oid(1, AI, 2) + c_enum(2, 3) + wrap(3, ts_time()) + c_str(4, 'operator')
       + wrap(5, ts_dt()))
    cr(0, c_uint(0, 1) + c_oid(1, AI, 2) + c_enum(2, 70) + wrap(3, ts_seq()) + c_str(4, 'op')
       + wrap(5, ts_seq(7)))
    rsp(simple_ack(inv, 0)); inv += 1
    # 1 ConfirmedCOVNotification
    cr(1, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + c_uint(3, 0) + wrap(4, covvals))
    inv += 1
    # 2 ConfirmedEventNotification (all notification parameter types further down)
    cr(2, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + wrap(3, ts_dt()) + c_uint(4, 1)
       + c_uint(5, 100) + c_enum(6, 5) + c_str(7, 'High limit') + c_enum(8, 0) + c_bool(9, True)
       + c_enum(10, 0) + c_enum(11, 3)
       + wrap(12, wrap(5, c_real(0, 88.0), c_bits(1, '1000'), c_real(2, 2.0), c_real(3, 80.0))))
    inv += 1
    # 3 GetAlarmSummary ACK
    rsp(complex_ack(inv, 3, a_oid(AI, 1) + a_enum(3) + a_bits('011') + a_oid(BI, 2) + a_enum(2)
                    + a_bits('111'))); inv += 1
    # 4 GetEnrollmentSummary
    cr(4, c_enum(0, 1) + wrap(1, wrap(0, c_oid(0, DEVICE, 5)), c_uint(1, 9)) + c_enum(2, 0)
       + c_enum(3, 5) + wrap(4, c_uint(0, 1), c_uint(1, 255)) + c_uint(5, 3))
    rsp(complex_ack(inv, 4, a_oid(AI, 1) + a_enum(5) + a_enum(3) + a_uint(100) + a_uint(3)
                    + a_oid(BI, 2) + a_enum(1) + a_enum(0) + a_uint(1))); inv += 1
    # 5 SubscribeCOV
    cr(5, c_uint(0, 18) + c_oid(1, AI, 1) + c_bool(2, False) + c_uint(3, 0))
    cr(5, c_uint(0, 18) + c_oid(1, AI, 1))
    rsp(simple_ack(inv, 5)); inv += 1
    # 6 AtomicReadFile (stream and record) and ACKs
    cr(6, a_oid(FILE, 1) + wrap(0, a_int(0), a_uint(512)))
    rsp(complex_ack(inv, 6, a_bool(0) + wrap(0, a_int(0), a_oct(b'#!BACnet file data\n')))); inv += 1
    cr(6, a_oid(FILE, 2) + wrap(1, a_int(-1), a_uint(3)))
    rsp(complex_ack(inv, 6, a_bool(1) + wrap(1, a_int(14), a_uint(3), a_oct(b'rec1'),
                                             a_oct(b'rec2'), a_oct(b'rec3')))); inv += 1
    # 7 AtomicWriteFile and ACKs
    cr(7, a_oid(FILE, 1) + wrap(0, a_int(100), a_oct(b'appended data')))
    rsp(complex_ack(inv, 7, c_int(0, 100))); inv += 1
    cr(7, a_oid(FILE, 2) + wrap(1, a_int(-1), a_uint(2), a_oct(b'line A'), a_oct(b'line B')))
    rsp(complex_ack(inv, 7, c_int(1, 20))); inv += 1
    # 8 AddListElement, 9 RemoveListElement, errors
    cr(8, c_oid(0, NOTIF_CLASS, 1) + c_uint(1, 102) + wrap(3,
        a_bits('1111111'), a_time(0, 0, 0, 0), a_time(23, 59, 59, 99), c_oid(0, DEVICE, 7),
        a_uint(3), a_bool(1), a_bits('111'),
        a_bits('0000011'), a_time(8, 0, 0, 0), a_time(17, 0, 0, 0),
        wrap(1, address(0, b'\x05')), a_uint(4), a_bool(0), a_bits('100')))
    rsp(error_pdu(inv, 8, wrap(0, error(5, 9)) + c_uint(1, 2))); inv += 1
    cr(9, c_oid(0, GROUP, 1) + c_uint(1, 53) + c_uint(2, 0) + wrap(3,
        c_oid(0, AI, 1), wrap(1, c_uint(0, 85), c_uint(0, 87), c_uint(1, 3))))
    rsp(error_pdu(inv, 9, wrap(0, error(2, 47)) + c_uint(1, 1))); inv += 1
    # 10 CreateObject (type and identifier) and ACK, error
    cr(10, wrap(0, c_enum(0, AV)) + wrap(1, c_uint(0, 77), wrap(2, a_str('New AV')),
                                         c_uint(0, 117), wrap(2, a_enum(62)), c_uint(3, 16)))
    rsp(complex_ack(inv, 10, a_oid(AV, 33))); inv += 1
    cr(10, wrap(0, c_oid(1, AV, 34)))
    rsp(error_pdu(inv, 10, wrap(0, error(1, 7)) + c_uint(1, 0))); inv += 1
    # 11 DeleteObject
    cr(11, a_oid(AV, 33)); rsp(simple_ack(inv, 11)); inv += 1
    # 12 ReadProperty
    cr(12, c_oid(0, AI, 1) + c_uint(1, 85))
    cr(12, c_oid(0, AO, 1) + c_uint(1, 87) + c_uint(2, 8))
    rsp(error_pdu(inv, 12, error(2, 32))); inv += 1
    # 13 ReadPropertyConditional
    cr(13, wrap(0, c_enum(0, 0), wrap(1, c_uint(0, 85), c_uint(1, 1), c_enum(2, 3),
                                    wrap(3, a_real(50.0)), c_uint(0, 36), c_enum(2, 1),
                                    wrap(3, a_enum(0))))
       + wrap(1, c_uint(0, 77), c_uint(0, 85)))
    rsp(complex_ack(inv, 13, c_oid(0, AI, 1) + wrap(1, c_uint(2, 77), wrap(4, a_str('AI 1')),
                                                    c_uint(2, 85), wrap(4, a_real(51.0)))))
    inv += 1
    # 14 ReadPropertyMultiple and ACK with values and an error
    cr(14, c_oid(0, AI, 1) + wrap(1, c_uint(0, 85), c_uint(0, 87), c_uint(1, 16), c_uint(0, 8))
       + c_oid(0, DEVICE, 5) + wrap(1, c_uint(0, 76)))
    rsp(complex_ack(inv, 14,
        c_oid(0, AI, 1) + wrap(1, c_uint(2, 85), wrap(4, a_real(20.5)),
                               c_uint(2, 117), wrap(4, a_enum(62)),
                               c_uint(2, 87), c_uint(3, 16), wrap(4, A_NULL),
                               c_uint(2, 103), wrap(5, error(2, 32)),
                               c_uint(2, 36), wrap(4, a_enum(0)))
        + c_oid(0, DEVICE, 5) + wrap(1, c_uint(2, 76), wrap(4, a_oid(DEVICE, 5), a_oid(AI, 1)))))
    inv += 1
    # 15 WriteProperty with priority, 16 WritePropertyMultiple and error
    cr(15, c_oid(0, AO, 1) + c_uint(1, 85) + wrap(3, a_real(55.5)) + c_uint(4, 8))
    rsp(simple_ack(inv, 15)); inv += 1
    cr(15, c_oid(0, AO, 1) + c_uint(1, 87) + c_uint(2, 8) + wrap(3, A_NULL))
    rsp(error_pdu(inv, 15, error(2, 40))); inv += 1
    cr(16, c_oid(0, AV, 1) + wrap(1, c_uint(0, 85), wrap(2, a_real(1.0)), c_uint(3, 9),
                                  c_uint(0, 28), wrap(2, a_str('desc')))
       + c_oid(0, BV, 2) + wrap(1, c_uint(0, 85), c_uint(1, 0), wrap(2, a_enum(1))))
    rsp(error_pdu(inv, 16, wrap(0, error(2, 37)) + wrap(1, c_oid(0, AV, 1), c_uint(1, 85),
                                                       c_uint(2, 3)))); inv += 1
    # 17 DeviceCommunicationControl
    cr(17, c_uint(0, 60) + c_enum(1, 1) + c_str(2, 'secret'))
    rsp(simple_ack(inv, 17)); inv += 1
    # 18 ConfirmedPrivateTransfer, ACK and error
    cr(18, c_uint(0, 260) + c_uint(1, 7) + wrap(2, a_uint(1), c_str(1, 'x'), wrap(3, a_real(2.0))))
    rsp(complex_ack(inv, 18, c_uint(0, 260) + c_uint(1, 7) + wrap(2, a_bool(1))))
    rsp(complex_ack(inv, 18, c_uint(0, 8) + c_uint(1, 7)))
    rsp(error_pdu(inv, 18, wrap(0, error(7, 9)) + c_uint(1, 260) + c_uint(2, 7)
                  + wrap(3, a_uint(5), a_str('bad')))); inv += 1
    # 19 ConfirmedTextMessage
    cr(19, c_oid(0, DEVICE, 5) + wrap(1, c_uint(0, 1)) + c_enum(2, 1) + c_str(3, 'Hello'))
    rsp(simple_ack(inv, 19)); inv += 1
    # 20 ReinitializeDevice
    cr(20, c_enum(0, 1) + c_str(1, 'pw'))
    rsp(simple_ack(inv, 20)); inv += 1
    # 21-23 VT services and ACKs, VT close error
    cr(21, a_enum(1) + a_uint(5)); rsp(complex_ack(inv, 21, a_uint(9))); inv += 1
    cr(22, a_uint(9) + a_uint(10))
    rsp(error_pdu(inv, 22, wrap(0, error(7, 9)) + wrap(1, a_uint(10)))); inv += 1
    cr(23, a_uint(9) + a_oct(b'ls -l\r\n') + a_uint(0))
    rsp(complex_ack(inv, 23, c_bool(0, False) + c_uint(1, 3))); inv += 1
    # 24 Authenticate and ACK
    cr(24, c_uint(0, 0x12345678) + bytes([0x19]) + c_str(2, 'admin') + c_str(3, 'pass')
       + c_bool(4, True))
    rsp(complex_ack(inv, 24, a_uint(0x12345679))); inv += 1
    # 25 RequestKey
    cr(25, a_oid(DEVICE, 5) + wrap(1, address(1, b'\x0a')) + a_oid(DEVICE, 6)
       + wrap(1, address(2, b'\xc0\x00\x02\x06\xba\xc0')))
    rsp(simple_ack(inv, 25)); inv += 1
    # 26 ReadRange: by position, by sequence number, by time, time range (deprecated)
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + wrap(3, a_uint(1), a_int(10)))
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + c_uint(2, 1) + wrap(6, a_uint(100), a_int(-5)))
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + wrap(7, datetime(), a_int(5)))
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + wrap(4, datetime(), a_int(5)))
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + wrap(5, datetime(), datetime()))
    cr(26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131))
    inv += 1
    # 27 LifeSafetyOperation
    cr(27, c_uint(0, 1) + c_str(1, 'panel') + c_enum(2, 4) + c_oid(3, LIFE_POINT, 1))
    cr(27, c_uint(0, 1) + c_str(1, 'panel') + c_enum(2, 70))
    rsp(simple_ack(inv, 27)); inv += 1
    # 28 SubscribeCOVProperty (with and without index, increment)
    cr(28, c_uint(0, 18) + c_oid(1, AI, 1) + c_bool(2, True) + c_uint(3, 300)
       + wrap(4, c_uint(0, 85)) + c_real(5, 0.5))
    cr(28, c_uint(0, 18) + c_oid(1, AO, 1) + c_bool(2, False) + c_uint(3, 3661)
       + wrap(4, c_uint(0, 87), c_uint(1, 8)))
    rsp(simple_ack(inv, 28)); inv += 1
    # 29 GetEventInformation and ACK
    cr(29); cr(29, c_oid(0, AI, 1))
    rsp(complex_ack(inv, 29, wrap(0,
        c_oid(0, AI, 1), c_enum(1, 3), c_bits(2, '011'),
        wrap(3, ts_time(), ts_seq(), ts_dt()), c_enum(4, 0), c_bits(5, '111'),
        wrap(6, c_uint(0, 100), c_uint(1, 50), c_uint(2, 200)),
        c_oid(0, BI, 2), c_enum(1, 2), c_bits(2, '111'),
        wrap(3, ts_seq(1), ts_seq(2), ts_seq(3)), c_enum(4, 1), c_bits(5, '010'),
        wrap(6, c_uint(0, 1), c_uint(1, 2), c_uint(2, 3))) + c_bool(1, False))); inv += 1
    # 30 SubscribeCOVPropertyMultiple and error
    cr(30, c_uint(0, 18) + c_bool(1, True) + c_uint(2, 600) + c_uint(3, 5) + wrap(4,
        c_oid(0, AI, 1), wrap(1, wrap(0, c_uint(0, 85)), c_real(1, 0.1), c_bool(2, True),
                              wrap(0, c_uint(0, 111))),
        c_oid(0, AO, 2), wrap(1, wrap(0, c_uint(0, 87), c_uint(1, 5)), c_bool(2, False))))
    rsp(error_pdu(inv, 30, c_enum(0, 5) + a_enum(123))); inv += 1
    rsp(error_pdu(inv, 30, wrap(0, error(5, 123)) + wrap(1, c_oid(0, AI, 1),
                                                         wrap(1, c_uint(0, 85)),
                                                         wrap(2, error(2, 32)))))
    inv += 1
    # 31 ConfirmedCOVNotificationMultiple
    cr(31, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_uint(2, 60) + c_datetime(3)
       + wrap(4, c_oid(0, AI, 1), wrap(1, c_uint(0, 85), wrap(2, a_real(1.5)), c_time(3)),
              c_oid(0, MSI, 2), wrap(1, c_uint(0, 85), wrap(2, a_uint(3)),
                                     c_uint(0, 74), c_uint(1, 2), wrap(2, a_str('two')))))
    rsp(simple_ack(inv, 31)); inv += 1
    # 32 ConfirmedAuditNotification (audit notification info fields)
    audit = (wrap(0, ts_dt()) + wrap(1, ts_seq(9)) + wrap(2, c_oid(0, DEVICE, 5))
             + c_oid(3, AV, 1) + c_enum(4, 1) + c_str(5, 'src comment') + c_str(6, 'tgt comment')
             + c_uint(7, 12) + c_uint(8, 1001) + c_uint(9, 2)
             + wrap(10, wrap(1, address(3, b'\x22'))) + c_oid(11, AV, 1)
             + wrap(12, c_uint(0, 85), c_uint(1, 0)) + c_uint(13, 8)
             + wrap(14, a_real(1.0)) + wrap(15, a_real(2.0)) + wrap(16, error(2, 40)))
    cr(32, wrap(0, audit))
    cr(32, wrap(0, wrap(0, ts_time()), c_enum(4, 4), wrap(14, a_enum(1)),
                ))
    rsp(simple_ack(inv, 32)); inv += 1
    req(unconfirmed(12, wrap(0, wrap(0, ts_seq(1)), c_oid(3, AV, 2), c_enum(4, 3))))
    # 33 AuditLogQuery by target and by source, and ACK
    cr(33, c_oid(0, AUDIT_LOG, 1) + wrap(1, wrap(0,
        c_oid(0, DEVICE, 5), wrap(1, address(4, b'\x01')), c_oid(2, AV, 1), c_uint(3, 85),
        c_uint(4, 2), c_uint(5, 8), c_bits(6, '0110'), c_enum(7, 1))) + c_uint(2, 1) + c_uint(3, 10))
    cr(33, c_oid(0, AUDIT_LOG, 1) + wrap(1, wrap(1,
        c_oid(0, DEVICE, 6), wrap(1, address(4, b'\x02')), c_oid(2, AV, 2), c_bits(3, '1'),
        c_enum(4, 70))) + c_uint(3, 5))
    rsp(complex_ack(inv, 33, c_oid(0, AUDIT_LOG, 1) + wrap(1,
        c_uint(0, 1), wrap(1, wrap(0, a_date(), a_time()), wrap(1, c_bits(0, '010'))),
        c_uint(0, 2), wrap(1, wrap(0, a_date(), a_time()), wrap(1, wrap(1, audit))),
        c_uint(0, 3), wrap(1, wrap(0, a_date(), a_time()), wrap(1, c_real(2, -3.5))))
        + c_bool(2, True)))
    inv += 1
    # 34 AuthRequest, ACK, error
    cr(34, wrap(0, c_uint(0, 7), wrap(1, a_int(-1), a_int(100)),
                wrap(2, c_bits(1, '1100'))))
    rsp(complex_ack(inv, 34, wrap(0, c_uint(0, 9), c_datetime(1), wrap(2, a_int(3)),
                                  c_datetime(3), c_datetime(4), c_uint(5, 11),
                                  wrap(6, a_enum(1), a_enum(2)),
                                  wrap(7, wrap(0, c_str(0, 'ext-scope'), c_str(0, 'more'))),
                                  c_uint(8, 1), c_oct(9, b'\xaa' * 8))))
    rsp(error_pdu(inv, 34, wrap(0, error(9, 200)) + c_str(1, 'denied'))); inv += 1
    # values longer than 4 octets: Process Id, event type, notify type, from/to
    # state, time span, array index, error class and code
    B5 = b'\x00\x00\x00\x00\x01'
    cr(2, tag(0, True, B5) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + wrap(3, ts_seq())
       + c_uint(4, 1) + c_uint(5, 1) + tag(6, True, B5) + tag(8, True, B5) + c_bool(9, False)
       + tag(10, True, B5) + tag(11, True, B5))
    cr(28, c_uint(0, 18) + c_oid(1, AI, 1) + c_bool(2, True) + tag(3, True, B5)
       + wrap(4, c_uint(0, 85)))
    rsp(complex_ack(inv, 12, c_oid(0, AV, 1) + c_uint(1, 85) + tag(2, True, B5)
                    + wrap(3, a_real(1.0))))
    rsp(error_pdu(inv, 12, tag(9, False, B5) + tag(9, False, B5))); inv += 1
    # Errors: default class/code, proprietary values
    rsp(error_pdu(inv, 12, error(64, 300))); inv += 1
    rsp(error_pdu(inv, 5, error(5, 5))); inv += 1

    # ------------------------------------------------------------------
    sec('Notification parameters (ConfirmedEventNotification, event types 0-22, 23)')
    def evnotif(evtype, params, inv_=None):
        p = (c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + wrap(3, ts_seq(evtype))
             + c_uint(4, 1) + c_uint(5, 100) + c_enum(6, evtype) + c_enum(8, 0) + c_bool(9, False)
             + c_enum(10, 0) + c_enum(11, 3) + wrap(12, wrap(evtype, params)))
        return confirmed(inv_ if inv_ is not None else next_invoke(), 2, p)
    SF = c_bits(1, '0000')
    req(evnotif(0, c_bits(0, '1010') + SF))
    req(evnotif(1, wrap(0, c_bool(0, True)) + SF))
    for tagno, val in ((1, 1), (2, 3), (3, 1), (4, 2), (5, 3), (6, 4), (7, 7), (8, 2), (9, 1),
                       (10, 62), (11, None), (12, 1), (13, 3), (14, 2), (15, 1), (16, 2),
                       (17, 1), (18, 2), (19, 1), (20, 3), (21, 1), (22, 2), (23, 3), (24, 1),
                       (25, 0), (26, 1), (27, 2), (28, 1), (29, 5), (30, 9), (31, 1), (32, 2),
                       (33, 1), (34, 1), (35, 6), (36, 1), (37, 2), (38, 1), (39, 3), (40, 2),
                       (41, None), (42, 1), (43, 2), (44, 3), (45, 1), (46, 2), (47, 3), (48, 1),
                       (49, 1), (50, 2), (51, 1), (52, 2), (53, 1), (54, 2), (55, 1), (56, 1),
                       (57, 2), (58, 1), (59, 1), (60, 2), (63, None), (64, 4), (61, 2)):
        if tagno == 11 or tagno == 63:
            st = c_uint(tagno, 5)
        elif tagno == 41:
            st = c_int(tagno, -5)
        else:
            st = c_enum(tagno, val)
        if tagno in (19, 20, 22, 25, 32, 37, 44):
            st = c_enum(tagno, 200)   # proprietary range
        req(evnotif(1, wrap(0, st) + SF))
    req(evnotif(2, wrap(0, c_bits(0, '11')) + SF))
    req(evnotif(2, wrap(0, c_real(1, 1.25)) + SF))
    req(evnotif(3, wrap(0, a_real(1.0)) + SF + wrap(2, a_real(0.0))))
    req(evnotif(4, c_real(0, 10.0) + SF + c_real(2, 12.0) + c_real(3, 1.0)))
    req(evnotif(5, c_real(0, 100.0) + SF + c_real(2, 1.0) + c_real(3, 90.0)))
    req(evnotif(6, c_uint(0, 85) + wrap(2, a_real(1.0)) + c_uint(0, 111) + wrap(2, a_bits('0000'))))
    req(evnotif(7, c_oid(0, DEVICE, 5) + c_oid(1, TRENDLOG, 1) + c_datetime(2) + c_datetime(3)))
    req(evnotif(8, c_enum(0, 3) + c_enum(1, 1) + c_bits(2, '1000') + c_enum(3, 2)))
    req(evnotif(8, c_enum(0, 300) + c_enum(1, 300) + c_bits(2, '0000') + c_enum(3, 70)))
    req(evnotif(9, c_uint(0, 260) + c_uint(1, 4) + wrap(2,
        a_real(1.0), a_uint(2), wrap(0, c_oid(0, DEVICE, 5), c_oid(1, AI, 1), c_uint(2, 85),
                                     c_uint(3, 1), wrap(4, a_real(3.0))))))
    req(evnotif(10, wrap(0, c_oid(0, TRENDLOG, 1), c_uint(1, 131)) + c_uint(1, 10) + c_uint(2, 20)))
    req(evnotif(11, c_uint(0, 101) + SF + c_uint(2, 100)))
    req(evnotif(13, c_enum(0, 5) + SF + c_uint(2, 77) + wrap(3, ts_time())
                + wrap(4, c_oid(0, DEVICE, 5), c_oid(1, CRED_DATA_INPUT, 1))
                + wrap(5, c_enum(0, 6), c_uint(1, 2), c_oct(2, b'\x12\x34'))))
    req(evnotif(13, c_enum(0, 600) + SF + c_uint(2, 77) + wrap(3, ts_dt())
                + wrap(4, c_oid(1, CRED_DATA_INPUT, 1))))
    req(evnotif(14, c_double(0, 1e6) + SF + c_double(2, 0.5) + c_double(3, 9e5)))
    req(evnotif(15, c_int(0, -40) + SF + c_uint(2, 2) + c_int(3, -30)))
    req(evnotif(16, c_uint(0, 1000) + SF + c_uint(2, 5) + c_uint(3, 900)))
    req(evnotif(17, c_str(0, 'FAULT') + SF + c_str(2, 'FAULT')))
    req(evnotif(18, wrap(0, a_bits('0100')) + c_bits(1, '0100')))
    req(evnotif(18, wrap(0, c_uint(0, 1)) + c_bits(1, '0100')))
    req(evnotif(19, c_enum(0, 7) + SF + wrap(2, c_uint(0, 85), wrap(2, a_real(1.0)))))
    req(evnotif(19, c_enum(0, 7) + SF))
    req(evnotif(20, b''))
    req(evnotif(21, wrap(0, a_uint(3)) + SF))
    req(evnotif(21, wrap(0, c_datetime(0)) + SF))
    req(evnotif(22, c_enum(0, 1) + SF + c_datetime(2) + c_enum(3, 2) + c_uint(4, 30)))
    req(evnotif(22, c_enum(0, 300) + SF + c_enum(3, 300)))
    req(evnotif(23, c_uint(0, 1) + wrap(1, a_real(2.0))))
    # Unconfirmed event notification
    req(unconfirmed(3, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, BI, 1) + wrap(3, ts_time())
                    + c_uint(4, 1) + c_uint(5, 10) + c_enum(6, 1) + c_enum(8, 1) + c_enum(10, 0)
                    + c_enum(11, 0)))

    # ------------------------------------------------------------------
    sec('Property values (ReadProperty-ACK), event and fault parameters')

    def pv(otype, prop, value, idx=None, inst=1):
        rsp(rp_ack(otype, inst, prop, value, idx))

    pv(AI, 0, a_bits('110'))
    pv(AI, 35, a_bits('111'))
    pv(LOOP, 2, a_enum(1))
    pv(COMMAND, 2, wrap(0,
        c_oid(0, DEVICE, 5), c_oid(1, AO, 1), c_uint(2, 85), c_uint(3, 1),
        wrap(4, a_real(10.0)), c_uint(5, 8), c_uint(6, 5), c_bool(7, False), c_bool(8, True),
        c_oid(1, BO, 2), c_uint(2, 85), wrap(4, a_enum(1))), idx=1)
    # a stray closing tag inside the action command is stepped over
    pv(COMMAND, 2, wrap(0, c_oid(1, AO, 1), cl(9), c_uint(2, 85), wrap(4, a_real(1.0))), idx=2)
    # alarm-values / fault-values by object type
    for prop in (7, 39):
        pv(LIFE_POINT, prop, a_enum(3) + a_enum(2))
        pv(LIFE_ZONE, prop, a_enum(3))
        pv(ACCESS_DOOR, prop, a_enum(1))
        pv(TIMER, prop, a_enum(2))
        pv(ACCESS_ZONE, prop, a_enum(4))
        pv(BITSTRING_VALUE, prop, a_bits('1010') + a_bits('0101'))
        pv(MSI, prop, a_uint(2) + c_uint(1, 3) + wrap(0, c_uint(1, 4)))
    pv(AI, 37, a_enum(5))
    pv(DEVICE, 30, a_oid(DEVICE, 7) + address(1, b'\x0a')
       + a_oid(DEVICE, 8) + address(2, b'\xc0\x00\x02\x08\xba\xc0')
       + a_oid(DEVICE, 9) + address(3, b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x09\xba\xc0')
       + a_oid(DEVICE, 10) + address(4, b''))
    pv(DEVICE, 331, a_oid(DEVICE, 11) + address(0, b'\x01\x02'))
    pv(AI, 52, a_bits('11'))
    pv(GLOBAL_GROUP, 54, c_oid(0, AI, 1) + c_uint(1, 85) + c_uint(2, 1) + c_oid(3, DEVICE, 5)
       + c_oid(0, AI, 2) + c_uint(1, 77))
    pv(DEVICE, 55, a_oct(b'\x01' * 8) + address(1, b'\x0b'))
    pv(AI, 77, a_str('Zone Temperature'))
    for cs, s in ((1, 'dbcs'), (2, 'jis'), (3, 'ucs4'), (4, 'ucs2'), (5, 'caf\xe9'), (6, 'other')):
        pv(AV, 28, a_str(s, cs))
    pv(AV, 28, a_str('x' * 300))
    pv(AI, 79, a_enum(0))
    pv(AI, 79, a_enum(200))
    pv(DEVICE, 96, a_bits('1' * 64))
    pv(DEVICE, 97, a_bits('1' * 50))
    pv(NOTIF_CLASS, 102, a_bits('1111100') + a_time(255, 255, 255, 255) + a_time(23, 0, 0, 0)
       + wrap(1, address(0, b'\x05')) + a_uint(1) + a_bool(1) + a_bits('111'))
    pv(DEVICE, 107, a_enum(3))
    pv(AI, 111, a_bits('0100'))
    pv(DEVICE, 112, a_enum(0))
    pv(AI, 117, a_enum(62))
    pv(LIFT, 455, a_enum(47))
    pv(AO, 87, a_uint(16), idx=0)
    pv(AO, 87, A_NULL * 7 + a_real(10.0) + wrap(0, a_real(5.0)) + wrap(1, a_date(), a_time())
       + wrap(2, a_real(0.1), a_real(0.2)) + A_NULL * 4 + a_uint(4) + a_enum(1))
    pv(AO, 87, A_NULL + A_NULL, idx=15)
    pv(SCHEDULE, 38, a_uint(3), idx=0)
    pv(SCHEDULE, 38, wrap(0, c_date(0)) + wrap(2, a_time(8), a_real(21.0), a_time(17), A_NULL)
       + c_uint(3, 10)
       + wrap(0, wrap(1, a_date(124, 12, 24, 2), a_date(124, 12, 26, 4)))
       + wrap(2, a_time(0), a_enum(1)) + c_uint(3, 11)
       + wrap(0, c_oct(2, b'\x0c\x05\xff')) + wrap(2) + c_uint(3, 12)
       + c_oid(1, CALENDAR, 1) + wrap(2, a_time(6), a_bool(1)) + c_uint(3, 16))
    for prop in (19, 60, 78, 181, 355):
        pv(LOOP, prop, c_oid(0, AI, 1) + c_uint(1, 85))
    pv(TRENDLOG, 132, c_oid(0, AI, 1) + c_uint(1, 85) + c_uint(2, 0) + c_oid(3, DEVICE, 5))
    pv(LOOP, 109, wrap(0, c_oid(0, AV, 1), c_uint(1, 85), c_uint(2, 1)))
    pv(SCHEDULE, 123, a_uint(7), idx=0)
    pv(SCHEDULE, 123, wrap(0, a_time(8), a_real(21.0), a_time(17), A_NULL)
       + wrap(0) + c_null(0) + A_NULL + wrap(0, a_time(9), a_enum(1)) + wrap(0) + wrap(0))
    pv(SCHEDULE, 123, wrap(0, a_time(10), a_uint(2)), idx=3)
    pv(LOOP, 127, a_real(0.5))
    pv(AI, 127, A_NULL)
    # log-buffer by object type
    pv(TRENDLOG, 131,
       wrap(0, a_date(), a_time()) + wrap(1, c_bits(0, '100')) + c_bits(2, '0000')
       + wrap(0, a_date(), a_time()) + wrap(1, c_bool(1, True))
       + wrap(0, a_date(), a_time()) + wrap(1, c_real(2, 21.5))
       + wrap(0, a_date(), a_time()) + wrap(1, c_uint(3, 2))
       + wrap(0, a_date(), a_time()) + wrap(1, c_uint(4, 1000))
       + wrap(0, a_date(), a_time()) + wrap(1, c_int(5, -7))
       + wrap(0, a_date(), a_time()) + wrap(1, c_bits(6, '1100'))
       + wrap(0, a_date(), a_time()) + wrap(1, c_null(7))
       + wrap(0, a_date(), a_time()) + wrap(1, wrap(8, error(1, 2)))
       + wrap(0, a_date(), a_time()) + wrap(1, c_real(9, 3.0))
       + wrap(0, a_date(), a_time()) + wrap(1, wrap(10, a_uint(5), a_str('any')))
       + c_bits(2, '1000'))
    pv(TRENDLOG_MULTI, 131,
       wrap(0, a_date(), a_time()) + wrap(1, c_bits(0, '010'))
       + wrap(0, a_date(), a_time()) + wrap(1, wrap(1,
           c_bool(0, True), c_real(1, 1.5), c_uint(2, 3), c_uint(3, 4), c_int(4, -4),
           c_bits(5, '10'), c_null(6), wrap(7, error(1, 2)), wrap(8, a_real(9.0))))
       + wrap(0, a_date(), a_time()) + wrap(1, c_real(2, 1.0)))
    pv(EVENT_LOG, 131,
       wrap(0, a_date(), a_time()) + wrap(1, c_bits(0, '001'))
       + wrap(0, a_date(), a_time()) + wrap(1, wrap(1,
           c_uint(0, 1), c_oid(1, DEVICE, 5), c_oid(2, AI, 1), wrap(3, ts_seq(3)), c_uint(4, 1),
           c_uint(5, 100), c_enum(6, 2), c_enum(8, 0), c_bool(9, True), c_enum(10, 0),
           c_enum(11, 2), wrap(12, wrap(2, wrap(0, c_real(1, 2.0)), c_bits(1, '0000')))))
       + wrap(0, a_date(), a_time()) + wrap(1, c_real(2, -1.0)))
    pv(AUDIT_LOG, 131,
       wrap(0, a_date(), a_time()) + wrap(1, c_bits(0, '01'))
       + wrap(0, a_date(), a_time()) + wrap(1, wrap(1, wrap(0, ts_time()), c_enum(4, 2)))
       + wrap(0, a_date(), a_time()) + wrap(1, c_real(2, 1.0)))
    for prop in (159, 165, 211, 246, 249, 252, 265, 266, 277, 279, 286, 320, 321, 461, 491):
        pv(ACCESS_ZONE, prop, c_oid(0, DEVICE, 5) + c_oid(1, ACCESS_DOOR, prop))
    pv(DEVICE, 196, a_enum(3))
    pv(LOAD_CONTROL, 212, c_uint(0, 50))
    pv(LOAD_CONTROL, 214, c_uint(1, 2))
    pv(LOAD_CONTROL, 218, c_real(2, 10.5))
    pv(AI, 152, wrap(0, wrap(0, c_oid(0, DEVICE, 7)), c_uint(1, 3))
       + wrap(1, c_oid(0, AI, 1), c_uint(1, 85)) + c_bool(2, True) + c_uint(3, 100)
       + c_real(4, 0.5)
       + wrap(0, wrap(0, wrap(1, address(1, b'\x07'))), c_uint(1, 4))
       + wrap(1, c_oid(0, AI, 2), c_uint(1, 85), c_uint(2, 1)) + c_bool(2, False) + c_uint(3, 0))
    pv(CALENDAR, 23, c_date(0, 124, 1, 1, 1) + wrap(1, a_date(124, 7, 1, 1), a_date(124, 7, 31, 3))
       + c_oct(2, b'\x0d\x06\x07') + c_date(0, 255, 255, 255, 255) + c_date(0, 255, 3, 4, 255)
       + c_oct(2, b'\x20\x10\x10'))
    pv(DEVICE, 116, c_oid(0, DEVICE, 9) + wrap(1, address(0, b'')))
    pv(DEVICE, 206, wrap(1, address(1, b'\x0c')))
    pv(DEVICE, 202, c_oid(0, DEVICE, 10))
    pv(AI, 130, a_uint(3), idx=0)
    pv(AI, 130, ts_time() + ts_seq() + ts_dt())
    pv(TRENDLOG, 197, a_enum(1))
    pv(AI, 36, a_enum(0))
    pv(AI, 36, a_enum(100))
    pv(AI, 103, a_enum(7))
    pv(NOTIF_CLASS, 72, a_enum(1))
    pv(DEVICE, 208, a_enum(3))
    pv(ACCESS_DOOR, 231, a_enum(1))
    pv(LIFT, 450, a_enum(2))
    pv(ACCESS_DOOR, 233, a_enum(1))
    pv(ACCESS_DOOR, 235, a_enum(0))
    pv(LIFE_POINT, 158, a_enum(2))
    pv(PROGRAM, 92, a_enum(2))
    pv(PROGRAM, 90, a_enum(1))
    pv(PROGRAM, 100, a_enum(3))
    pv(DEVICE, 157, ts_dt())
    pv(LIFE_POINT, 160, a_enum(1))
    pv(LIFE_POINT, 175, a_enum(1) + a_enum(2))
    pv(LIFE_POINT, 163, a_enum(1))
    pv(LIFE_POINT, 161, a_enum(4))
    pv(LIFE_POINT, 164, a_enum(2))
    pv(LIFE_ZONE, 164, a_enum(3))
    pv(COLOR, 164, a_real(0.31) + a_real(0.32))
    pv(COLOR_TEMP, 164, a_uint(4000))
    pv(LIGHTING_OUTPUT, 164, a_real(75.0))
    pv(LIFE_POINT, 166, a_enum(3))
    pv(FILE, 41, a_enum(1))
    pv(ACCUMULATOR, 185, c_uint(0, 10) + c_uint(1, 100))
    pv(ACCUMULATOR, 187, c_real(0, 0.5))
    pv(ACCUMULATOR, 187, c_int(1, -2))
    pv(CRED_DATA_INPUT, 189, ts_dt())
    pv(AI, 189, datetime())
    pv(ACCUMULATOR, 184, c_datetime(0) + c_uint(1, 1000) + c_uint(2, 2000) + c_enum(3, 1))
    pv(DEVICE, 203, ts_seq(100))
    pv(ACCESS_DOOR, 226, a_enum(5))
    pv(ACCESS_DOOR, 228, c_oid(0, DEVICE, 5) + c_oid(1, ACCESS_DOOR, 2) + c_oid(1, ACCESS_DOOR, 3))
    pv(ACCESS_DOOR, 234, a_enum(1) + a_enum(2))
    pv(CRED_DATA_INPUT, 248, c_enum(0, 1) + c_uint(1, 2) + c_oct(2, b'\xde\xad'))
    pv(CRED_DATA_INPUT, 261, a_enum(1))
    pv(GROUP, 53, c_oid(0, AI, 1) + wrap(1, c_uint(0, 85), c_uint(0, 87), c_uint(1, 1))
       + c_oid(0, AO, 2) + wrap(1, c_uint(0, 77)))
    pv(ACCESS_ZONE, 296, a_enum(2))
    pv(ACCESS_ZONE, 300, a_enum(1))
    pv(ACCESS_ZONE, 303, a_enum(3))
    pv(ACCESS_ZONE, 318, a_enum(1))
    pv(DEVICE, 330, c_uint(0, 1) + c_datetime(1) + c_datetime(2)
       + wrap(3, c_uint(0, 1), c_uint(1, 2)))
    pv(DEVICE, 332, c_uint(0, 1) + c_enum(1, 2))
    pv(DEVICE, 338, a_enum(2))
    pv(LIGHTING_OUTPUT, 370, a_enum(1))
    pv(LIGHTING_OUTPUT, 385, a_enum(1))
    pv(COLOR, 385, a_enum(1))
    pv(COLOR_TEMP, 385, a_enum(2))
    for prop in (288, 302):
        pv(ACCESS_ZONE, prop, c_enum(0, 1) + wrap(1, c_oid(0, SCHEDULE, 1), c_uint(1, 85))
           + c_enum(2, 1) + wrap(3, c_oid(1, ACCESS_ZONE, 2)) + c_bool(4, True))
    pv(CRED_DATA_INPUT, 304, c_enum(0, 3) + c_uint(1, 260) + c_uint(2, 1))
    pv(DEVICE, 327, a_enum(1))
    pv(AI, 371, a_enum(77) + a_enum(85) + a_enum(4194307))
    pv(AI, 359, a_enum(5))
    pv(EVENT_ENROLLMENT, 362, wrap(0, c_oid(0, DEVICE, 7)) + c_uint(1, 3) + c_bool(2, True)
       + c_uint(3, 100) + wrap(0, wrap(1, address(1, b'\x09'))) + c_uint(1, 4)
       + c_bool(2, False) + c_uint(3, 0))
    pv(CRED_DATA_INPUT, 364, a_enum(2))
    pv(LIGHTING_OUTPUT, 378, a_enum(1))
    pv(COLOR, 378, a_enum(1))
    pv(COLOR_TEMP, 378, a_enum(2))
    pv(LIGHTING_OUTPUT, 380, c_enum(0, 2) + c_real(1, 50.0) + c_real(2, 10.0) + c_real(3, 1.0)
       + c_uint(4, 2000) + c_uint(5, 8))
    for prop in (16, 71, 114, 115, 142, 143, 149, 150, 179, 192, 254, 270, 278, 280, 281, 392):
        pv(AI, prop, datetime(124, 1, prop % 28 + 1, 255))
    pv(CRED_DATA_INPUT, 258, wrap(0, wrap(0, c_oid(0, DEVICE, 5), c_oid(1, CRED_DATA_INPUT, 1)),
                                  c_uint(1, 1), c_uint(1, 2), wrap(0, c_oid(1, CRED_DATA_INPUT, 2)))
       + c_bool(1, True) + c_uint(2, 30))
    pv(TIMER, 395, a_enum(3))
    pv(TIMER, 396, c_null(0) + wrap(1, a_real(1.0)) + wrap(2, datetime())
       + wrap(3, c_enum(0, 1), c_real(1, 10.0)) + a_uint(5) + c_null(0) + c_null(0), idx=1)
    pv(TIMER, 398, a_enum(1))
    pv(NETWORK_PORT, 407, hostnport(c_oct(1, b'\xc0\x00\x02\x01')))
    pv(NETWORK_PORT, 418, hostnport(c_str(2, 'bbmd.example.com')))
    pv(NETWORK_PORT, 418, hostnport(c_null(0)))
    pv(NETWORK_PORT, 408, a_enum(1))
    pv(NETWORK_PORT, 435, a_enum(2))
    pv(NETWORK_PORT, 414, wrap(0, hostnport(c_oct(1, b'\xc0\x00\x02\x01'))) + c_oct(1, b'\xff' * 4)
       + wrap(0, hostnport(c_oct(1, b'\xc0\x00\x02\x02'))))
    pv(NETWORK_PORT, 415, c_oct(0, b'\xc0\x00\x02\x09\xba\xc0') + c_uint(1, 60) + c_uint(2, 30))
    pv(NETWORK_PORT, 417, a_enum(1))
    pv(NETWORK_PORT, 426, a_enum(3))
    pv(NETWORK_PORT, 427, a_enum(5))
    pv(NETWORK_PORT, 428, c_uint(0, 10) + c_oct(1, b'\x01') + c_enum(2, 0) + c_uint(3, 1)
       + c_uint(0, 11) + c_oct(1, b'\x02') + c_enum(2, 1))
    pv(NETWORK_PORT, 429, c_oct(0, b'\x01\x02\x03') + c_oct(1, b'\xc0\x00\x02\x01\xba\xc0')
       + c_oct(0, b'\x04\x05\x06') + c_oct(1, b'\xc0\x00\x02\x02\xba\xc0'))
    pv(AO, 430, a_uint(16), idx=0)
    pv(AO, 430, ts_dt() + ts_seq(1) + ts_time())
    pv(AO, 432, ts_dt())
    pv(AO, 433, c_null(0))
    pv(AO, 433, wrap(1, c_oid(0, DEVICE, 5), c_oid(1, AO, 1)))
    pv(AO, 433, wrap(2, address(5, b'\x0d')))
    pv(AO, 434, a_uint(16), idx=0)
    pv(AO, 434, wrap(1, c_oid(1, AO, 2)) + c_null(0) + wrap(2, address(0, b'')))
    pv(LIFT, 447, wrap(0, c_uint(0, 3), c_enum(1, 1), c_uint(0, 5), c_enum(1, 2)))
    pv(LIFT, 448, a_enum(1))
    pv(LIFT, 457, a_enum(2))
    pv(LIFT, 449, a_enum(1))
    pv(LIFT, 453, a_enum(3))
    pv(LIFT, 456, a_enum(2))
    pv(ESCALATOR, 462, a_enum(1))
    pv(LIFT, 463, a_uint(2), idx=0)
    pv(LIFT, 463, a_enum(1) + a_enum(2))
    pv(ESCALATOR, 463, a_enum(3))
    pv(ELEVATOR_GROUP, 467, a_enum(2))
    pv(ELEVATOR_GROUP, 470, a_uint(2), idx=0)
    pv(ELEVATOR_GROUP, 470, c_uint(0, 4) + c_enum(1, 1) + c_uint(2, 7) + c_str(3, 'Lobby'))
    pv(ELEVATOR_GROUP, 471, c_uint(0, 2) + c_uint(2, 9))
    pv(LIFT, 472, a_uint(2), idx=0)
    pv(LIFT, 472, wrap(0, c_uint(0, 1), c_enum(1, 2), c_uint(0, 2), c_enum(1, 1)))
    pv(ESCALATOR, 477, a_enum(2))
    pv(AI, 481, a_uint(1), idx=0)
    pv(AI, 481, wrap(0, wrap(0, c_oid(0, DEVICE, 7)), c_uint(1, 3)) + c_bool(1, True)
       + c_uint(2, 300) + c_uint(3, 5)
       + wrap(4, c_oid(0, AI, 1), wrap(1, wrap(0, c_uint(0, 85)), c_real(1, 0.5), c_bool(2, True)),
              c_oid(0, AI, 2), wrap(1, wrap(0, c_uint(0, 85), c_uint(1, 2)), c_bool(2, False))))
    pv(DEVICE, 482, a_enum(2))
    pv(AI, 486, a_uint(2), idx=0)
    pv(AI, 486, c_str(0, 'site') + c_datetime(1) + c_str(0, 'floor') + a_uint(3) + c_str(0, 'x') + a_bool(1))
    pv(AI, 487, a_uint(2), idx=0)
    pv(AI, 487, a_enum(2) + a_enum(5))
    pv(AI, 488, a_uint(1), idx=0)
    pv(AI, 488, wrap(0, c_str(0, 'a'), a_uint(1), c_str(0, 'b'), c_datetime(1))
       + wrap(0, c_str(0, 'c')))
    pv(AI, 489, a_uint(1), idx=0)
    pv(AI, 489, a_enum(3))
    pv(AI, 490, a_enum(4))
    pv(AI, 494, a_uint(2), idx=0)
    pv(AI, 494, a_real(10.0) + a_bits('1000') + a_real(1.0))
    pv(AUDIT_LOG, 498, a_enum(2))
    pv(AUDIT_LOG, 500, a_bits('1' * 16))
    pv(AUDIT_LOG, 501, a_bits('1' * 20))
    pv(AUDIT_LOG, 504, a_uint(3), idx=0)
    pv(AUDIT_LOG, 504, A_NULL + a_enum(2) + a_oid(AI, 3))
    health = (c_datetime(0) + wrap(1, error(1, 2)) + c_uint(2, 85) + c_str(3, 'details'))
    pv(DEVICE, 510, health)
    pv(DEVICE, 4194307, health)
    hp = hostnport(c_oct(1, b'\xc0\x00\x02\x01'))
    pv(NETWORK_PORT, 4194312, c_str(0, 'wss://hub') + c_enum(1, 1) + c_datetime(2) + c_datetime(3)
       + wrap(4, hp) + c_oct(5, b'\x01' * 6) + c_oct(6, b'\x02' * 16) + wrap(7, error(7, 9))
       + c_str(8, 'err'))
    pv(NETWORK_PORT, 4194315, c_datetime(0) + wrap(1, hp) + c_oct(2, b'\x01' * 6)
       + c_oct(3, b'\x02' * 16) + wrap(4, error(7, 9)) + c_str(5, 'err'))
    for prop in (4194316, 4194324):
        pv(NETWORK_PORT, prop, c_enum(0, 1) + c_datetime(1) + c_datetime(2) + wrap(3, error(7, 9))
           + c_str(4, 'err'))
    pv(NETWORK_PORT, 4194318, a_enum(1))
    pv(NETWORK_PORT, 4194321, c_enum(0, 1) + c_datetime(1) + c_datetime(2) + wrap(3, hp)
       + c_oct(4, b'\x01' * 6) + c_oct(5, b'\x02' * 16) + wrap(6, error(7, 9)) + c_str(7, 'err'))
    pv(COLOR, 4194330, a_real(0.3) + a_real(0.3))
    pv(COLOR, 4194334, c_enum(0, 1) + wrap(1, a_real(0.3), a_real(0.31)) + c_uint(2, 3000)
       + c_uint(3, 100) + c_uint(4, 10) + c_uint(5, 5))
    pv(DEVICE, 4194339, wrap(0, address(1, b'\x05')) + wrap(1, a_oid(DEVICE, 99) + a_uint(480)
       + a_enum(3) + a_uint(260)) + c_datetime(2))
    token = (c_uint(0, 9) + c_datetime(1) + wrap(2, a_int(3), a_int(-4)) + c_datetime(3)
             + c_datetime(4) + c_uint(5, 11) + wrap(6, a_enum(1), a_enum(2))
             + wrap(7, c_bits(1, '101')) + c_uint(8, 1) + c_oct(9, b'\x55' * 8))
    pv(DEVICE, 4194343, token)
    pv(DEVICE, 4194345, c_datetime(0) + c_datetime(1) + wrap(2, a_uint(1), a_uint(2))
       + wrap(3, a_enum(0), a_enum(1)) + wrap(4, wrap(0, c_str(0, 'scope'))))
    pv(DEVICE, 4194346, c_str(0, 'name') + c_str(1, 'description'))
    pv(DEVICE, 4194347, c_uint(0, 77) + c_oct(1, b'\x01' * 32) + c_oct(2, b'\x02' * 32))
    authev = (c_datetime(0) + wrap(1, wrap(0, hp), c_uint(1, 5), c_bool(2, True), c_bool(3, False),
                                   c_bool(4, False))
              + wrap(2, c_bool(0, True), c_uint(1, 6)) + a_int(1) + c_str(4, 'ok'))
    authz = (c_datetime(0) + wrap(1, address(1, b'\x05')) + wrap(2, c_bool(0, True), c_uint(1, 6))
             + wrap(3, token) + a_real(2.0) + c_str(5, 'granted'))
    # posture [0], decision [3]/[4] are decoded with fApplicationTypesEnumerated
    # inside a switch on the tag number, so only application tags with those
    # numbers (NULL, Signed, Real) get past them
    pv(DEVICE, 4194348, A_NULL + wrap(1, error(9, 1)) + wrap(2, c_oid(0, DEVICE, 5),
       c_uint(1, 4194348)) + c_str(3, 'details') + wrap(4, authev) + wrap(5, authev)
       + wrap(6, authz) + wrap(7, authz))
    # present-value by object type
    pv(GROUP, 85, c_oid(0, AI, 1) + wrap(1, c_uint(2, 85), wrap(4, a_real(1.0))))
    pv(ACCESS_DOOR, 85, a_enum(1))
    pv(LIFE_POINT, 85, a_enum(2))
    pv(LIFE_ZONE, 85, a_enum(3))
    pv(CHANNEL, 85, wrap(0, c_enum(0, 1), c_real(1, 20.0)))
    pv(CHANNEL, 85, wrap(1, a_real(0.3), a_real(0.3)))
    pv(CHANNEL, 85, wrap(2, c_enum(0, 1), c_uint(2, 3000)))
    pv(CHANNEL, 85, c_uint(3, 3))
    pv(CHANNEL, 85, a_real(12.5))
    pv(CRED_DATA_INPUT, 85, c_enum(0, 1) + c_uint(1, 2) + c_oct(2, b'\x01\x02'))
    pv(GLOBAL_GROUP, 85, c_oid(0, AI, 1) + c_uint(1, 85) + c_uint(2, 1) + c_oid(3, DEVICE, 5)
       + wrap(4, a_real(3.0)) + c_oid(0, AI, 2) + c_uint(1, 85) + wrap(5, error(2, 32)))
    pv(LOAD_CONTROL, 85, a_enum(2))
    pv(DTPV, 85, datetime(255, 255, 255, 255))
    pv(DTV, 85, datetime())
    pv(COLOR, 85, a_real(0.3) + a_real(0.4))
    for v in (A_NULL, a_bool(1), a_uint(5), a_int(-5), a_real(1.5), a_double(2.5), a_oct(b'\x01\x02'),
              a_oct(b''), a_str('pv'), a_bits('101'), a_enum(3), a_date(), a_time(), a_oid(AI, 3)):
        pv(AV, 85, v)
    pv(AV, 85, c_uint(0, 5))
    pv(AV, 85, tag(1, True, b'\x01'))
    # reserved application tags and generic values in the default handling
    pv(AV, 4000, tag(13, False, b'\x01') + tag(14, False, b'') + tag(15, False, b'\x01\x02'))
    pv(AV, 4000, A_NULL + a_bool(0) + a_uint(2 ** 40) + a_uint(2 ** 63 + 5) + a_int(-2 ** 40)
       + a_real(-0.5) + a_double(1e-3) + a_oct(b'abc') + a_bits('1') + a_enum(2 ** 32 - 1)
       + a_date(255, 255, 255, 255) + a_date(255, 6, 7, 255) + a_date(124, 13, 32, 8)
       + a_time(255, 255, 255, 255) + a_time(0, 0, 0, 0) + a_oid(1000, 5) + a_oid(200, 6))
    pv(AV, 4000, c_uint(20, 5) + wrap(30, c_uint(2, 1)) + wrap(1, wrap(2, c_bool(3, True))))
    pv(AV, 4000, bytes([0x65, 255]) + struct.pack('!I', 10) + b'\x01' * 10)
    pv(AV, 4000, a_oct(b'\x02' * 300))
    pv(AV, 4000, a_enum(2 ** 40) + a_uint(2 ** 70) + a_int(2 ** 60) + a_uint(0))
    pv(AV, 77, a_str('n'), inst=4194303)
    # proprietary property
    pv(AV, 600, a_uint(1))

    # event-parameters (property 83 of event-enrollment)
    DOPR = wrap(1, c_oid(0, AI, 1), c_uint(1, 85))
    for params in (
            wrap(0, c_uint(0, 10), c_bits(1, '1111'), wrap(2, a_bits('1000'), a_bits('0100'))),
            wrap(1, c_uint(0, 10), wrap(1, c_enum(1, 1), c_enum(2, 3), c_bool(0, True))),
            wrap(2, c_uint(0, 10), wrap(1, c_bits(0, '11'))),
            wrap(2, c_uint(0, 10), wrap(1, c_real(1, 0.5))),
            wrap(3, c_uint(0, 10), DOPR),
            wrap(4, c_uint(0, 10), DOPR, c_real(2, 1.0), c_real(3, 2.0), c_real(4, 0.5)),
            wrap(5, c_uint(0, 10), c_real(1, 0.0), c_real(2, 100.0), c_real(3, 1.0)),
            wrap(6, c_uint(0, 85), wrap(2, a_real(1.0))),
            wrap(7, c_uint(0, 10), c_uint(1, 5)),
            wrap(8, c_uint(0, 10), wrap(1, c_enum(0, 3), c_enum(0, 300)), wrap(2, c_enum(0, 2)),
                 wrap(3, c_oid(0, LIFE_POINT, 1), c_uint(1, 160))),
            wrap(9, c_uint(0, 260), c_uint(1, 3), wrap(2, a_real(1.0), wrap(0, c_oid(0, AI, 1),
                 c_uint(1, 85)), c_uint(1, 4), a_uint(2))),
            wrap(10, c_uint(0, 10), c_uint(1, 5)),
            wrap(11, c_uint(0, 10), c_uint(1, 5), c_uint(2, 50)),
            wrap(13, wrap(0, c_enum(0, 1), c_enum(0, 700)), DOPR),
            wrap(14, c_uint(0, 10), c_double(1, -1.0), c_double(2, 1.0), c_double(3, 0.1)),
            wrap(15, c_uint(0, 10), c_int(1, -10), c_int(2, 10), c_uint(3, 1)),
            wrap(16, c_uint(0, 10), c_uint(1, 1), c_uint(2, 10), c_uint(3, 1)),
            wrap(17, c_uint(0, 10), wrap(1, c_str(0, 'ALARM'), c_str(0, 'FIRE'))),
            wrap(18, c_uint(0, 10), c_bits(1, '1100')),
            wrap(19, c_uint(0, 10)),
            c_null(20),
            wrap(21, c_uint(0, 10)),
            wrap(22, c_uint(0, 10), wrap(1, c_enum(0, 2), c_enum(0, 3)),
                 wrap(2, c_oid(0, TIMER, 1), c_uint(1, 189))),
            wrap(30, c_uint(0, 1))):
        pv(EVENT_ENROLLMENT, 83, params)
    # fault-parameters (property 358)
    for params in (
            c_null(0),
            wrap(1, wrap(0, c_str(0, 'FAULT'), c_str(0, 'ERR'))),
            wrap(2, c_uint(0, 260), c_uint(1, 2), wrap(2, a_real(1.0))),
            wrap(3, wrap(0, c_enum(0, 3), c_enum(0, 4)), wrap(1, c_oid(0, LIFE_POINT, 1),
                 c_uint(1, 160))),
            wrap(4, wrap(0, c_enum(7, 1), c_bool(0, True))),
            wrap(5, wrap(0, c_oid(0, AI, 1), c_uint(1, 111))),
            wrap(6, wrap(0, a_real(0.0)), wrap(1, a_real(100.0))),
            wrap(7, wrap(0, c_oid(0, MSI, 1), c_uint(1, 85))),
            wrap(9, c_uint(0, 1))):
        pv(AI, 358, params)

    # ------------------------------------------------------------------
    sec('WriteProperty of a Command action list, ReadRange-ACKs with item data')
    req(confirmed(next_invoke(), 15, c_oid(0, COMMAND, 1) + c_uint(1, 2) + c_uint(2, 1)
                  + wrap(3, wrap(0, c_oid(1, AO, 1), c_uint(2, 85), wrap(4, a_real(5.0)),
                                 c_uint(5, 9))) + c_uint(4, 16)))
    rsp(complex_ack(next_invoke(), 26,
        c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + c_bits(3, '110') + c_uint(4, 2)
        + wrap(5, wrap(0, a_date(), a_time()), wrap(1, c_real(2, 20.0)),
               wrap(0, a_date(), a_time()), wrap(1, c_real(2, 21.0)))
        + c_uint(6, 1000)))
    rsp(complex_ack(next_invoke(), 26,
        c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + c_bits(3, '001') + c_uint(4, 0) + wrap(5)))

    # ------------------------------------------------------------------
    sec('Segmented ComplexACK (ReadPropertyMultiple, 4 segments) with SegmentACKs')
    rpm = c_oid(0, DEVICE, 5) + wrap(1,
        c_uint(2, 77), wrap(4, a_str('Segmented Device')),
        c_uint(2, 76), wrap(4, b''.join(a_oid(AI, i) for i in range(40))),
        c_uint(2, 28), wrap(4, a_str('d' * 120)))
    req(confirmed(200, 14, c_oid(0, DEVICE, 5) + wrap(1, c_uint(0, 8))))
    chunks = [rpm[i:i + 120] for i in range(0, len(rpm), 120)]
    for i, ch in enumerate(chunks):
        rsp(seg_cack(200, i, 4, 14, ch, i < len(chunks) - 1))
        req(segment_ack(200, i, 4, srv=False))

    sec('Segmented Confirmed-Request (WritePropertyMultiple, 2 segments)')
    wpm = (c_oid(0, AV, 1) + wrap(1, c_uint(0, 85), wrap(2, a_real(1.0)), c_uint(0, 28),
                                  wrap(2, a_str('s' * 100)))
           + c_oid(0, AV, 2) + wrap(1, c_uint(0, 85), wrap(2, a_real(2.0)), c_uint(3, 8)))
    half = len(wpm) // 2
    req(seg_request(201, 0, 2, 16, wpm[:half], True))
    rsp(segment_ack(201, 0, 2, srv=True))
    req(seg_request(201, 1, 2, 16, wpm[half:], False))
    rsp(segment_ack(201, 1, 2, srv=True))
    rsp(simple_ack(201, 16))

    sec('Segmented ComplexACK past sequence number 255 (AtomicReadFile, 258 segments + retransmission)')
    data = bytes((i * 7) & 0xff for i in range(258 * 16))
    afile = a_bool(1) + wrap(0, a_int(0), tag(6, False, data))
    req(confirmed(202, 6, a_oid(FILE, 3) + wrap(0, a_int(0), a_uint(len(data)))))
    chunks = [afile[i * 16:(i + 1) * 16] for i in range(257)] + [afile[257 * 16:]]
    for i, ch in enumerate(chunks):
        last = (i == len(chunks) - 1)
        if last:
            # retransmission of segment 255 after segment 256 (sequence number wrapped)
            rsp(seg_cack(202, 255, 127, 6, chunks[255], True))
        rsp(seg_cack(202, i & 0xff, 127, 6, ch, not last))
    req(segment_ack(202, 1, 127))

    return frames, sections


def malformed_frames():
    frames = []
    def add(apdu, src=1, dst=2):
        frames.append(bacnet_frame(apdu, src, dst))
    def pv(otype, prop, value, idx=None):
        add(rp_ack(otype, 1, prop, value, idx), 2, 1)
    # LVT longer than the packet
    pv(AV, 85, bytes([0x65, 200]) + b'\x01')
    # Device instance claiming 5 octets
    add(unconfirmed(8, tag(0, True, b'\x01\x02\x03\x04\x05') + c_uint(1, 5)))
    # Vendor ID of 3 octets, restart reason of 2 octets
    add(unconfirmed(0, a_oid(DEVICE, 1) + a_uint(480) + a_enum(3) + a_uint(0x10000)))
    pv(DEVICE, 196, tag(9, False, b'\x00\x03'))
    add(unconfirmed(0, a_oid(DEVICE, 1) + a_uint(480) + a_enum(3) + a_uint(2 ** 33)))
    pv(DEVICE, 196, tag(9, False, b'\x00' * 4 + b'\x03'))
    add(unconfirmed(14, a_uint(260) + a_str('m') + a_str('s') + a_uint(1)))
    # property value without opening tag
    add(complex_ack(1, 12, c_oid(0, AI, 1) + c_uint(1, 85) + c_uint(3, 1)))
    # wrong tag encodings: not an opening tag where one is required
    add(confirmed(1, 28, c_uint(0, 1) + c_oid(1, AI, 1) + c_uint(4, 85)))
    add(confirmed(1, 30, c_uint(0, 1) + c_uint(4, 1)))
    add(confirmed(1, 30, c_uint(0, 1) + wrap(4, c_oid(0, AI, 1), c_uint(1, 1))))
    add(confirmed(1, 30, c_uint(0, 1) + wrap(4, c_oid(0, AI, 1), wrap(1, c_uint(0, 85)))))
    add(confirmed(1, 31, c_uint(0, 1) + c_uint(4, 1)))
    add(confirmed(1, 31, c_uint(0, 1) + wrap(4, c_oid(0, AI, 1), c_uint(1, 1))))
    add(confirmed(1, 1, c_uint(0, 1) + c_uint(4, 1)))
    add(confirmed(1, 8, c_oid(0, AI, 1) + c_uint(1, 85) + c_uint(3, 1)))
    add(confirmed(1, 10, wrap(0, c_enum(0, 1)) + tag(1, True, b'\x05')))
    add(confirmed(1, 16, c_oid(0, AV, 1) + c_uint(1, 5)))
    add(confirmed(1, 18, c_uint(0, 8) + c_uint(1, 1) + c_uint(2, 5)))
    add(confirmed(1, 34, wrap(0, wrap(2, c_uint(0, 1)))))
    add(unconfirmed(10, c_uint(0, 1) + c_uint(2, 1)))
    add(unconfirmed(14, a_uint(260) + a_str('m') + a_str('s')))
    add(unconfirmed(14, a_uint(260) + a_str('m') + a_str('s') + a_oid(DEVICE, 1) + a_uint(1)))
    pv(AI, 358, wrap(1, c_uint(1, 1)))
    pv(SCHEDULE, 38, c_uint(2, 1))
    pv(DEVICE, 330, c_uint(3, 1))
    pv(GLOBAL_GROUP, 85, c_uint(5, 1))
    add(error_pdu(1, 30, wrap(1, c_oid(0, AI, 1), c_uint(1, 85))))
    add(complex_ack(1, 13, c_oid(0, AI, 1) + c_uint(1, 1)))
    add(complex_ack(1, 13, c_oid(0, AI, 1) + wrap(1, c_uint(2, 85), c_uint(5, 1))))
    add(confirmed(1, 13, wrap(0, c_enum(0, 0), c_uint(1, 1))))
    pv(DEVICE, 4194345, wrap(4, c_str(0, 'x')))       # handled in fAuthorizationScope
    # truncated packets
    add(bytes([0x00, 0x05]))
    add(bytes([0x30, 0x01, 12]) + c_oid(0, AI, 1)[:3])
    add(unconfirmed(0, a_oid(DEVICE, 1)[:3]))
    add(confirmed(1, 12, c_oid(0, AI, 1) + c_uint(1, 85))[:-1])
    pv(AV, 85, bytes([0x82, 0x00]))   # bit string ... lvt 2, truncated
    pv(AV, 85, bytes([0x80]))         # bit string with lvt 0
    # VT-Close error without the session list, stage without bit string,
    # present-value with a reserved application tag, ReadRange-ACK without itemData
    add(error_pdu(1, 22, wrap(0, error(7, 9))), 2, 1)
    pv(AI, 494, a_real(20.0), idx=2)
    pv(AV, 85, tag(13, False, b'\x01'))
    add(complex_ack(1, 26, c_oid(0, TRENDLOG, 1) + c_uint(1, 131) + c_uint(2, 0) + c_bits(3, '001')
                    + c_uint(4, 0)), 2, 1)
    # context value claiming more octets than remain (capped, no expert info)
    pv(AV, 4000, bytes([0x1d, 10]) + b'\x00' * 4)
    # odd encodings that reach the remaining branches without an expert info:
    # stray closing tags after private transfer parameters (expected [2] and
    # another), a closing tag in a SubscribeCOVPropertyMultiple error, a
    # closing [2] in change-of-reliability, a name-value with context tag [2]
    add(confirmed(1, 18, c_uint(0, 8) + c_uint(1, 1) + wrap(2, a_uint(1)) + cl(2) + cl(3)))
    add(error_pdu(1, 30, wrap(0, error(5, 123)) + cl(1)), 2, 1)
    add(confirmed(1, 2, c_uint(0, 1) + c_oid(1, DEVICE, 5) + c_oid(2, AI, 1) + wrap(3, ts_seq())
                  + c_uint(4, 1) + c_uint(5, 1) + c_enum(6, 19) + c_enum(8, 0) + c_bool(9, False)
                  + c_enum(10, 0) + c_enum(11, 3) + wrap(12, op(19), c_enum(0, 7), cl(2))))
    pv(AI, 486, c_str(0, 'x') + c_uint(2, 1))
    # APDU type 8..15
    add(bytes([0x80, 0x01, 0x02]))
    add(bytes([0xf0]))
    # segmented request with a bad (huge) service choice and a lost segment
    add(seg_request(9, 0, 1, 12, c_oid(0, AI, 1), True))
    add(seg_request(9, 2, 1, 12, c_uint(1, 85), False))
    return frames


def bsc_frames():
    """BACnet/SC (BSCVLC) Heartbeat-Requests with hint (scope) and token data
    options, as exported PDUs for the "bscvlc" dissector (normally reached
    over WebSocket). packet-bvlc.c hands these options to
    bacnet_dissect_scope() and bacnet_dissect_token() in packet-bacapp.c."""
    def exported(name, payload):
        n = name.encode()
        n += b'\0' * (-len(n) % 4)
        return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload
    def opt(otype, data, more):
        return bytes([(0x80 if more else 0) | 0x20 | otype]) + struct.pack('!H', len(data)) + data
    scope = wrap(0, c_str(0, 'ext-scope')) + c_bits(1, '1010')
    token = (c_uint(0, 9) + c_datetime(1) + wrap(2, a_int(3)) + c_datetime(3) + c_datetime(4)
             + c_uint(5, 11) + wrap(6, a_enum(1), a_enum(2)) + wrap(7, c_bits(1, '1'))
             + c_uint(8, 1) + c_oct(9, b'\x55' * 8))
    frames = []
    # data options (control 0x01) and destination options (control 0x02)
    for ctrl in (0x01, 0x02):
        frames.append(exported('bscvlc', bytes([0x0a, ctrl]) + struct.pack('!H', 7)
                               + opt(4, scope, True) + opt(5, token, False)))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames, sections = main_frames()
    write_pcap(os.path.join(out, 'bacapp-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'bacapp-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'bacapp-coverage-bsc.pcap'), bsc_frames(), 252)
    for i, (start, name) in enumerate(sections):
        end = sections[i + 1][0] - 1 if i + 1 < len(sections) else len(frames)
        print('%4d-%-4d %s' % (start, end, name))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/lwm2mtlv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic LwM2M TLV coverage captures for
epan/dissectors/packet-lwm2mtlv.c.  The TLV payloads travel in CoAP over
UDP port 5683 with Content-Format 11542 (application/vnd.oma.lwm2m+tlv),
which is how the dissector is reached; the CoAP URI path gives the object
and resource IDs.  Every packet is built with struct; nothing comes from
a real network.

Usage: mklwm2mtlv.py <outdir>
Writes lwm2mtlv-coverage.pcap (main) and
lwm2mtlv-coverage-malformed.pcap (Ethernet link type).
"""
import os
import struct
import sys

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IPID = [0]


def udp_frame(payload, a_to_b=True, sport=49152, dport=5683):
    src, dst = (A, B) if a_to_b else (B, A)
    ms, md = (bytes.fromhex('020000000001'), bytes.fromhex('020000000002'))
    if not a_to_b:
        ms, md = md, ms
        sport, dport = dport, sport
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    IPID[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IPID[0], 0x4000, 64, 17, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return md + ms + b'\x08\x00' + h + u


# ---------------------------------------------------------------- CoAP

def opt(num_prev, num, val):
    d = num - num_prev
    l = len(val)

    def nib(v):
        return (v, b'') if v < 13 else ((13, bytes([v - 13])) if v < 269 else (14, struct.pack('!H', v - 269)))
    dn, de = nib(d)
    ln, le = nib(l)
    return bytes([(dn << 4) | ln]) + de + le + val, num


def coap(mtype, code, mid, token, path=(), ctype=11542, payload=b'', uri_host=None):
    opts = []
    if uri_host:
        opts.append((3, uri_host.encode()))
    for seg in path:
        opts.append((11, seg.encode()))
    if ctype is not None:
        opts.append((12, struct.pack('!H', ctype) if ctype > 255 else bytes([ctype])))
    out = b''
    prev = 0
    for n, v in opts:
        b, prev = opt(prev, n, v)
        out += b
    m = bytes([0x40 | (mtype << 4) | len(token), code]) + struct.pack('!H', mid) + token + out
    if payload:
        m += b'\xff' + payload
    return m


GET, POST, PUT = 1, 2, 3
CONTENT = 0x45    # 2.05
CHANGED = 0x44    # 2.04

# ---------------------------------------------------------------- TLV


def tlv(ttype, ident, value=b'', idlen=None, lenbytes=None):
    """ttype: 0 object instance, 1 resource instance, 2 multiple resources,
    3 resource with value.  lenbytes forces the number of length octets."""
    two = ident > 255 if idlen is None else idlen == 2
    n = len(value)
    if lenbytes is None:
        lenbytes = 0 if n < 8 else 1 if n < 256 else 2 if n < 65536 else 3
    t = (ttype << 6) | (0x20 if two else 0) | (lenbytes << 3)
    if lenbytes == 0:
        t |= n
    out = bytes([t]) + (struct.pack('!H', ident) if two else bytes([ident]))
    if lenbytes:
        out += n.to_bytes(lenbytes, 'big')
    return out + value


def res(ident, value, **kw):
    return tlv(3, ident, value, **kw)


def inst(ident, value, **kw):
    return tlv(1, ident, value, **kw)


def arr(ident, *insts, **kw):
    return tlv(2, ident, b''.join(insts), **kw)


def obj(ident, *resources, **kw):
    return tlv(0, ident, b''.join(resources), **kw)


def i8(v):
    return struct.pack('!b', v)


def i16(v):
    return struct.pack('!h', v)


def i32(v):
    return struct.pack('!i', v)


def i64(v):
    return struct.pack('!q', v)


def f32(v):
    return struct.pack('!f', v)


def f64(v):
    return struct.pack('!d', v)


def main_frames():
    F = []
    state = {'mid': 0x1000}

    def req(path, payload, code=PUT, mtype=0, **kw):
        state['mid'] += 1
        mid = state['mid']
        tok = struct.pack('!H', mid)
        F.append(udp_frame(coap(mtype, code, mid, tok, path, payload=payload, **kw)))
        return mid, tok

    def rsp(path, payload, req_mid_tok, code=CONTENT, **kw):
        mid, tok = req_mid_tok
        F.append(udp_frame(coap(2, code, mid, tok, path=(), payload=payload, **kw), a_to_b=False))

    # Device object (3), instance 0 read (response to a GET of /3/0)
    dev = (res(0, b'Open Mobile Alliance') + res(1, b'Lightweight M2M Client')
           + res(2, b'345000123') + res(3, b'1.0')
           + arr(6, inst(0, i8(1)), inst(1, i8(5)))
           + arr(7, inst(0, i16(3800)), inst(1, i16(5000)))
           + arr(8, inst(0, i8(125)), inst(1, i16(900)))
           + res(9, i8(85)) + res(10, i32(15))
           + arr(11, inst(0, i8(0)))
           + res(13, i32(1367491215)) + res(14, b'+01:00') + res(15, b'Europe/Berlin')
           + res(16, b'U') + res(17, b'Sensor') + res(18, b'1.0') + res(19, b'2.1')
           + res(20, i8(1)) + res(21, i32(1048576))
           + res(22, struct.pack('!HH', 66, 0)))
    mt = req(('3', '0'), b'', code=GET, ctype=None)
    rsp(('3', '0'), obj(0, dev), mt)
    # same data as the whole object (instance with two-octet identifier
    # and a 1/2/3 octet length field), and with a resource array of
    # resource instances using the fix for resource IDs: /3/0/6 holds only
    # resource instances, so the resource ID comes from the URI path
    req(('3', '0', '6'), inst(0, i8(1)) + inst(1, i8(5)) + inst(2, i8(2)), code=POST)
    req(('3', '0', '9'), res(9, i8(100)), code=PUT)
    req(('3', '0', '7'), inst(0, i16(3300)), code=PUT)
    req(('3', '0', '13'), res(13, i64(1367491215)), code=PUT)
    req(('3', '0', '4'), b'', code=POST, ctype=None)
    req(('3', '0', '4'), res(4, b'\x01\x02'), code=POST)          # no data type, bytes
    # Security object (0)
    sec = (res(0, b'coaps://lwm2m.example.com:5684') + res(1, b'\x00') + res(2, i8(3))
           + res(3, bytes(range(16))) + res(4, bytes(range(32, 48))) + res(5, bytes(16))
           + res(6, i8(3)) + res(7, bytes(6)) + res(8, bytes(16)) + res(9, b'+358401234567')
           + res(10, i16(123)) + res(11, i16(10)) + res(12, i16(600)) + res(13, b'\x01')
           + res(14, b'lwm2m.example.com') + res(15, b'\x03') + res(16, struct.pack('!H', 0xC0A8))
           + res(17, struct.pack('!HH', 21, 0)) + res(18, b'\x01\x02')
           + res(25, b'coap://backup.example.com') + res(26, struct.pack('!HH', 1, 1))
           + res(28, i16(5683)) + res(30, b'app.id'))
    req(('0', '0'), obj(0, sec), code=PUT)
    req(('0', '1'), obj(1, res(0, b'coap://bootstrap.example.com:5683') + res(1, b'\x01')), code=PUT)
    # Server object (1)
    srv = (res(0, i8(1)) + res(1, i32(86400)) + res(2, i8(1)) + res(3, i16(60))
           + res(4, b'') + res(5, i32(86400)) + res(6, b'\x01') + res(7, b'U')
           + res(8, b'') + res(9, b'') + res(10, struct.pack('!HH', 11, 0)) + res(11, b'\x00')
           + res(12, i32(1700000000)) + res(13, b'\x04') + res(14, b'\x05')
           + res(15, b'\x00') + res(16, b'\x01') + res(17, b'\x03') + res(18, i16(300))
           + res(19, b'\x0a') + res(20, b'\x02') + res(21, b'\x01') + res(22, b'UQ')
           + res(23, b'\x00') + res(24, struct.pack('!HH', 12, 0)) + res(25, b'1.1')
           + res(26, i8(1)) + res(27, b'\x02'))
    req(('1', '0'), obj(0, srv), code=PUT)
    # Access control (2) with an ACL multiple resource, connectivity
    # monitoring (4), firmware update (5)
    acl = (res(0, i16(3)) + res(1, i16(0)) + arr(2, inst(1, i8(15)), inst(2, i8(1)))
           + res(3, i16(123)))
    req(('2', '0'), obj(0, acl), code=PUT)
    cm = (res(0, i8(21)) + arr(1, inst(0, i8(21)), inst(1, i8(41))) + res(2, i8(-70))
          + res(3, i8(90)) + arr(4, inst(0, b'192.168.1.10'), inst(1, b'2001:db8::10'))
          + arr(5, inst(0, b'192.168.1.1')) + res(6, i8(50)) + arr(7, inst(0, b'internet'))
          + res(8, i32(26241)) + res(9, i16(1)) + res(10, i16(262)) + res(11, i16(8))
          + res(12, i16(77)) + res(13, i8(1)))
    req(('4', '0'), obj(0, cm), code=PUT)
    fw = (res(0, bytes(24)) + res(1, b'coap://fw.example.com/image') + res(2, b'')
          + res(3, i8(1)) + res(5, i8(0)) + res(6, b'FwPkg') + res(7, b'3.2.1')
          + arr(8, inst(0, i8(0)), inst(1, i8(1))) + res(9, i8(2)) + res(10, b'')
          + res(11, i8(1)) + res(12, i32(1700000500)) + res(13, i16(3600)) + res(14, b'\x01'))
    req(('5', '0'), obj(0, fw), code=PUT)
    # Location (6): floats of 4 and 8 octets, the velocity opaque for
    # every velocity type, the timestamp
    loc = (res(0, f32(60.1699)) + res(1, f32(24.9384)) + res(2, f32(12.5)) + res(3, f32(3.25))
           + res(4, bytes([0x00, 0x00, 0x2d, 0x00, 0x32]) [:4]) + res(5, i32(1700000000))
           + res(6, f32(1.5)))
    req(('6', '0'), obj(0, loc), code=PUT)
    loc8 = res(0, f64(60.169856)) + res(1, f64(24.938379)) + res(2, f64(-3.5))
    req(('6', '0'), obj(0, loc8), code=PUT)
    for vel in (bytes([0x00, 0x00, 0x2d, 0x00, 0x32]), bytes([0x14, 0x80, 0x2d, 0x00, 0x32, 0x05]),
                bytes([0x20, 0x00, 0x2d, 0x00, 0x32, 0x0a]),
                bytes([0x30, 0x00, 0x2d, 0x00, 0x32, 0x05, 0x06]),
                bytes([0x40, 0x00, 0x2d, 0x00, 0x32])):
        req(('6', '0', '4'), res(4, vel), code=PUT)
    # Connectivity statistics (7) and OSCORE (21)
    stat = (res(0, i32(5)) + res(1, i32(6)) + res(2, i32(1000)) + res(3, i32(2000))
            + res(4, i16(1200)) + res(5, i16(300)) + res(6, b'') + res(7, b'') + res(8, i32(3600)))
    req(('7', '0'), obj(0, stat), code=PUT)
    osc = (res(0, b'secret') + res(1, b'sender') + res(2, b'recipient') + res(3, i8(10))
           + res(4, i8(-7)) + res(5, b'salt') + res(6, b'\x01\x02\x03'))
    req(('21', '0'), obj(0, osc), code=PUT)
    # Objects unknown to the dissector, and requests without an object
    # path: values are shown by guesswork on 1, 2, 4 and 8 octet values
    gen = (res(0, b'text value') + res(1, b'\x01') + res(2, b'\x07') + res(3, b'\x01\x02')
           + res(4, struct.pack('!f', 2.5)) + res(5, struct.pack('!d', 1.25))
           + res(6, b'\xff\xfe\xfd') + res(7, b'') + res(8, b'\x80\x00\x00\x00\x00\x00\x00\x01')
           + arr(9, inst(0, b'one'), inst(1, b'\x00\x00\x00\x2a')))
    req(('9999', '0'), obj(0, gen), code=PUT)
    req(('9999', '0', '1'), res(1, b'\x01'), code=PUT)
    req(('9999', '0', '9'), inst(0, b'zero') + inst(1, b'\x00\x01'), code=PUT)
    req((), obj(0, gen), code=PUT)
    req(('3',), obj(0, res(0, b'a') + res(1, b'b')) + obj(1, res(0, b'c')), code=PUT)
    # Header forms: two-octet identifiers, every length-field size, a
    # nested object instance in an object instance, two-octet ID of an
    # object instance, a resource 1000
    req(('9999', '1'), obj(1, res(1000, b'long id', idlen=2) + res(1, bytes(300))
                           + res(2, bytes(20), lenbytes=1) + res(3, bytes(5), lenbytes=2)
                           + res(4, bytes(9), lenbytes=3), idlen=2), code=PUT)
    req(('9999', '2'), obj(2, obj(3, res(1, b'\x01'))), code=PUT)
    # a GET with a URI host: the host comes first in the media string
    req(('3', '0', '9'), res(9, i8(99)), code=PUT, uri_host='sensor.example.com')
    # CON/ACK pair for /3/0/9 and a response without a path at all
    r2 = req(('3', '0', '9'), b'', code=GET, ctype=None)
    rsp(('3', '0', '9'), res(9, i8(77)), r2)
    # a user-defined object and resource, only named when the UAT
    # preferences are set (see runcov.sh)
    req(('9998', '0'), obj(0, res(0, b'user string') + res(1, i16(-5)) + res(2, b'\x01')
                           + res(3, f32(1.5)) + res(4, i32(1700000000)) + res(5, b'\x02\x03')
                           + res(6, struct.pack('!HH', 3, 4)) + res(7, b'\x00\x00\x00\x07')
                           + res(8, f64(2.5)) + res(9, b'</1/0>')), code=PUT)
    # integers of 3, 5, 6, 7 and 8 octets (Power Source Voltage is an integer resource)
    req(('3', '0', '7'), arr(7, inst(0, b'\x01\x02\x03'), inst(1, bytes(range(1, 6))),
                             inst(2, bytes(range(1, 7))), inst(3, bytes(range(1, 8))),
                             inst(4, bytes(range(1, 9)))), code=PUT)
    return F


def malformed_frames():
    F = []
    state = {'mid': 0x2000}

    def req(path, payload, code=PUT, **kw):
        state['mid'] += 1
        mid = state['mid']
        F.append(udp_frame(coap(0, code, mid, struct.pack('!H', mid), path, payload=payload, **kw)))

    # TLV cut inside the header, inside the length field, inside the value
    req(('3', '0'), b'\xc8')
    req(('3', '0'), b'\xc8\x00')
    req(('3', '0'), b'\xc8\x00\x10abc')
    req(('3', '0'), b'\xc3\x01ab')
    # a length that reaches beyond the end of the payload
    req(('3', '0'), res(0, b'abc')[:-1])
    # float resources of an odd size and an object link that is too short
    req(('6', '0'), res(0, b'\x01\x02') + res(1, b'\x01\x02\x03\x04\x05\x06'))
    req(('6', '0'), res(2, b'\x01'))
    req(('3', '0'), res(22, b'\x00\x01'))
    # velocity opaque too short
    req(('6', '0', '4'), res(4, b'\x10'))
    # a resource with a zero length value for each data type
    req(('3', '0'), res(0, b'') + res(9, b'') + res(13, b'') + res(22, b''))
    # recursion: object instances nested deeply
    deep = res(1, b'x')
    for _ in range(600):
        deep = tlv(0, 1, deep)
    req(('9999', '0'), deep)
    # the same with resource arrays (type 2)
    deep = inst(1, b'y')
    for _ in range(600):
        deep = tlv(2, 1, deep)
    req(('9999', '3'), deep)
    # a path with a nonnumeric object and resource ID, an empty segment
    req(('abc', '0', 'xyz'), res(1, b'\x01'))
    req(('3', '', '4'), res(4, b'\x01'))
    # a path of more than five segments
    req(('3', '0', '6', '0', 'x', 'y'), inst(0, i8(1)))
    # a huge object ID (more than 32 bits)
    req(('99999999999', '0', '5'), res(5, b'\x01'))
    # invalid UTF-8 in a string resource
    req(('3', '0'), res(0, b'\xff\xfe\xfd'))
    # an element with a zero length header type of Resource Array and no value
    req(('9999', '4'), arr(1))
    # missing payload for the Content-Format
    req(('3', '0'), b'')
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'lwm2mtlv-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'lwm2mtlv-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

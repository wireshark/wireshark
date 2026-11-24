#!/usr/bin/env python3
# Generates test/captures/radius_packetcable_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic PacketCable RADIUS coverage captures (nothing from a
real network). The PacketCable dissector (packet-radius_packetcable.c) is not
reached by a port of its own: it decodes the CableLabs vendor-specific
attributes (vendor 4491) inside RADIUS accounting messages.

Usage: mkradius_packetcable.py <outdir>
"""
import struct
import sys
import os

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipb(a): return bytes(map(int, a.split('.')))

def udp_frame(src, dst, sport, dport, payload, smac=1, dmac=2):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, ipb(src), ipb(dst))
    h = h[:10] + struct.pack('!H', ip_csum(h)) + h[12:]
    return bytes([2, 0, 0, 0, 0, dmac]) + bytes([2, 0, 0, 0, 0, smac]) + b'\x08\x00' + h + udp

class Cap:
    def __init__(self):
        self.frames, self.notes = [], []
    def add(self, fr, note=''):
        self.frames.append(fr); self.notes.append(note)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)

def auth(n): return bytes([(n * 17 + i * 5) & 0xff for i in range(16)])
def rad(code, ident, avps, a=None):
    body = b''.join(avps)
    return struct.pack('!BBH', code, ident, 20 + len(body)) + (a or auth(ident)) + body
def A(t, v=b''):
    if isinstance(v, str): v = v.encode()
    return struct.pack('!BB', t, 2 + len(v)) + v
def u32(n): return struct.pack('!I', n)
def u16(n): return struct.pack('!H', n)
def u64(n): return struct.pack('!Q', n)
CL = 4491                                  # CableLabs
def CLA(t, v):
    """CableLabs vendor-specific attribute."""
    if isinstance(v, str): v = v.encode()
    return A(26, u32(CL) + struct.pack('!BB', t, 2 + len(v)) + v)

def bcid(ts=0x4d2e8a10, elem=b'ELEM0001', dst=b'0', off=b'-05:00 ', ctr=77):
    return u32(ts) + elem + dst + off + u32(ctr)

def em_hdr(msgtype=1, eltype=1, status=0, version=1, nattrs=12, prio=5, obj=0):
    return (u16(version) + bcid() + u16(msgtype) + u16(eltype) + b'CMS00001' + b'1' + b'+01:00 ' + u32(9)
            + b'20230101120000.000' + u32(status) + bytes([prio]) + u16(nattrs) + bytes([obj]))

def qos_desc(status_ind=3, flags=0, name=b'BESTEFFORT0000000'):
    """Flags are the bits 2..17 of the first word; every set bit adds a 4 octet field."""
    word = (status_ind & 3) | flags
    b = u32(word) + name[:16].ljust(16, b'\0')
    for i in range(16):
        if word & (1 << (i + 2)):
            b += u32(1000 + i)
    return b

def term_display(mask, **kw):
    b = bytes([0, 0, mask])
    b = b + b'G' * 80 * bool(mask & 1)
    return b

def build_main():
    cap = Cap()
    C, S = '192.0.2.50', '192.0.2.60'
    def acct(ident, avps, sport=45000):
        return udp_frame(C, S, sport, 1813, rad(4, ident, avps))
    def resp(ident, sport=45000):
        return udp_frame(S, C, 1813, sport, rad(5, ident, [], a=auth(200 + ident)), 2, 1)
    # --- event message headers: every message type, element type and status
    types = [(1, 1, 0), (2, 2, 1), (3, 3, 2), (4, 4, 3), (5, 1, 4), (6, 2, 5), (7, 3, 6), (11, 4, 7),
             (19, 1, 0x0b), (31, 2, 0x04), (33, 3, 0x08), (0, 0, 0), (99, 9, 0xfffffff3)]
    for i, (mt, et, st) in enumerate(types):
        cap.add(acct(1 + i, [A(1, 'ncs'), A(44, 'billing-%d' % i), CLA(1, em_hdr(mt, et, st, nattrs=3 + i)),
                             CLA(3, 'aaln/1@mta.example.net'), CLA(4, '2125550100'), CLA(5, '2125550199')]),
                'Event Message header, type %d element %d status %#x' % (mt, et, st))
        cap.add(resp(1 + i), 'Accounting-Response')
    # --- Call Termination Cause, Related Call Billing Correlation ID, Trunk Group ID
    cap.add(acct(30, [CLA(1, em_hdr(16, 1)), CLA(11, u16(1) + u32(16)), CLA(11, u16(2) + u32(0x1234)), CLA(11, u16(0) + u32(0)),
                      CLA(13, bcid()), CLA(13, bcid(0xffffffff, b'ELEM0002', b'1', b'+00:00 ', 1)),
                      CLA(24, u16(3) + u32(42)), CLA(24, u16(9) + u32(7)), CLA(24, u16(4) + u32(0xffffffff)),
                      CLA(24, u16(7) + u32(1))]),
            'Call Termination Cause, Related BCID, Trunk Group ID')
    # --- QoS descriptors: no optional fields, each field alone, all fields
    qos = [qos_desc(0, 0)]
    for i in range(16):
        qos.append(qos_desc(i % 4, 1 << (i + 2)))
    qos.append(qos_desc(3, sum(1 << (i + 2) for i in range(16)), b'ALLFIELDSSET'))
    qos.append(qos_desc(2, (1 << 2) | (1 << 5) | (1 << 17), b'sparse'))
    cap.add(acct(31, [CLA(1, em_hdr(7, 2))] + [CLA(32, q) for q in qos[:9]]), 'QoS Descriptors 1')
    cap.add(acct(32, [CLA(1, em_hdr(8, 2))] + [CLA(32, q) for q in qos[9:]]), 'QoS Descriptors 2')
    # --- time adjustment, redirected from info, electronic surveillance, terminal display
    cap.add(acct(33, [CLA(1, em_hdr(17, 1)), CLA(38, u64(1700000000)), CLA(38, u64(0xffffffffffffffff))]), 'Time Adjustment')
    cap.add(acct(34, [CLA(43, b'2125550100'.ljust(20, b'\0') + b'2125550123'.ljust(20, b'\0') + u16(2)),
                      CLA(43, b'a' * 20 + b'b' * 20 + u16(0))]), 'Redirected-From-Info')
    cap.add(acct(35, [CLA(44, b''), CLA(44, ipb('10.9.9.1') + ipb('10.9.9.2') + u16(5000) + u16(5001) + b'df-key-bytes'),
                      CLA(44, ipb('10.9.9.3') + ipb('10.9.9.4') + u16(1) + u16(2) + b'k'),
                      CLA(47, b''), CLA(47, b'security-bytes')]), 'Electronic Surveillance indication and DF security')
    tdi = []
    for mask in (0, 1, 2, 4, 8, 3, 5, 6, 7, 9, 10, 12, 11, 13, 14, 15):
        b = bytes([0, 0, mask])
        total = 1
        if mask & 1: total += 80
        if mask & 2: total += 40
        if mask & 4: total += 40
        if mask & 8: total += 40
        b = (bytes([0, 0, mask]) + bytes([0x41 + (mask % 26)]) * (total - 3)) if total > 3 else bytes([0, 0, mask])
        tdi.append(b)
    cap.add(acct(36, [CLA(54, t) for t in tdi[:8]]), 'Terminal Display Info 1')
    cap.add(acct(37, [CLA(54, t) for t in tdi[8:]]), 'Terminal Display Info 2')
    # --- other CableLabs attributes without a special dissector
    cap.add(acct(38, [CLA(6, 'dbid'), CLA(7, u32(1)), CLA(9, '2125550111'), CLA(16, 'charge'), CLA(17, '2125550122'),
                      CLA(18, 'service'), CLA(26, u32(5060)), CLA(29, u32(2)), CLA(30, u32(0x100)), CLA(31, 'oops'),
                      CLA(37, u32(1)), CLA(39, 'v=0'), CLA(40, 'v=1'), CLA(48, b'\x01\x02\x03\x04'),
                      CLA(50, u32(1)), CLA(51, u32(2)), CLA(57, 'misc'), CLA(74, bytes(range(16))), CLA(75, 'user'),
                      CLA(200, b'\x01\x02')]), 'Other CableLabs attributes')
    return cap

def build_malformed():
    cap = Cap()
    C, S = '192.0.2.50', '192.0.2.60'
    def acct(ident, avps, sport=45100):
        return udp_frame(C, S, sport, 1813, rad(4, ident, avps))
    cap.add(acct(1, [CLA(1, em_hdr(1, 1)[:40])]), 'Event Message header cut')
    cap.add(acct(2, [CLA(1, b'')]), 'Event Message header empty')
    cap.add(acct(3, [CLA(11, b'\x00\x01\x00')]), 'Call Termination Cause cut')
    cap.add(acct(4, [CLA(13, bcid()[:10])]), 'Related BCID cut')
    cap.add(acct(5, [CLA(24, b'\x00\x03\x00')]), 'Trunk Group ID cut')
    cap.add(acct(6, [CLA(32, u32(0xfffffffc) + b'x' * 16 + u32(1))]), 'QoS Descriptor with fewer fields than flags')
    cap.add(acct(7, [CLA(32, b'\x00\x00')]), 'QoS Descriptor cut')
    cap.add(acct(8, [CLA(38, b'\x00\x01')]), 'Time Adjustment cut')
    cap.add(acct(9, [CLA(43, b'a' * 30)]), 'Redirected-From-Info cut')
    cap.add(acct(10, [CLA(44, b'\x01\x02\x03')]), 'Electronic Surveillance indication cut')
    cap.add(acct(11, [CLA(54, b'\x00\x00')]), 'Terminal Display Info cut')
    cap.add(acct(12, [CLA(54, b'\x00\x00\x0f' + b'x' * 20)]), 'Terminal Display Info shorter than its bitmask')
    return cap

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main(); m.write(os.path.join(out, 'radius_packetcable-coverage.pcap'))
    x = build_malformed(); x.write(os.path.join(out, 'radius_packetcable-coverage-malformed.pcap'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for name, c in (('main', m), ('malformed', x)):
            f.write('# %s: %d frames\n' % (name, len(c.frames)))
            for i, n in enumerate(c.notes, 1):
                f.write('%d\t%s\n' % (i, n))

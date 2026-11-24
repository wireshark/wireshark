#!/usr/bin/env python3
# Generates test/captures/dis_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DIS (IEEE 1278.1) coverage captures.

Usage: mkdis.py <outdir>

Writes dis-coverage.pcapng (clean) and dis-coverage-malformed.pcapng.
Every packet is built with struct; nothing comes from a real network.
Interface 0 is Ethernet (DIS over UDP port 3000), interface 1 is
Wireshark Upper PDU (Exported PDU) for the Link 16 dissector called by
name.
"""
import os
import struct
import sys

# ---------------------------------------------------------------- pcapng

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(payload, sport=3000, dport=3000, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
                      bytes(src), bytes(dst))
    iph = iph[:10] + struct.pack('!H', ip_csum(iph)) + iph[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + iph + udp


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad   # EXP_PDU_TAG_DISSECTOR_NAME
    tags += struct.pack('!HH', 0, 0)
    return tags + payload


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def block(btype, body):
    body = pad4(body)
    ln = 12 + len(body)
    return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)


def write_pcapng(path, frames):
    """frames: list of (interface, data)"""
    out = bytearray()
    out += block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))      # Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 65535))    # Upper PDU
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 1000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


# ------------------------------------------------------------- DIS fields

def dis_header(pdu_type, body, version=7, family=1, exercise=1, ts=0x00001000, status=0):
    return struct.pack('!BBBBIHBB', version, exercise, pdu_type, family, ts,
                       12 + len(body), status, 0) + body


def po_pdu(po_type, body, version=7):
    # DIS header (family 140) followed by the 8 octet PO header
    po = struct.pack('!BBBBHH', 1, po_type, 1, 3, 20 + len(body), 1) + body
    return dis_header(0, po, version=version, family=140)


def eid(site, app, ent):
    return struct.pack('!HHH', site, app, ent)


def etype(kind, domain, country=225, cat=1, sub=2, spec=3, extra=4):
    return struct.pack('!BBHBBBB', kind, domain, country, cat, sub, spec, extra)


def vec3f(x, y, z):
    return struct.pack('!fff', x, y, z)


def vec3d(x, y, z):
    return struct.pack('!ddd', x, y, z)


def clock(hour, ts):
    return struct.pack('!II', hour, ts)


def vp_articulated(change=1, attached=0, ptype=4096 + 11, value=1.5):
    return struct.pack('!BBHIfI', 0, change, attached, ptype, value, 0)


def vp_attached(ind=1, attached=0, ptype=4096 + 1):
    return struct.pack('!BBHI', 1, ind, attached, ptype) + etype(2, 2, 225, 1, 1, 0, 0)


def vp_offset():
    return struct.pack('!BBH', 25, 1, 0) + vec3f(1.0, 2.0, 3.0)


def vp_association():
    return struct.pack('!BBBB', 4, 1, 2, 3) + eid(5, 6, 7) + struct.pack('!HBBH', 9, 1, 2, 300)


def vp_other(t=3):
    return struct.pack('!B', t) + bytes(range(1, 16))


def entity_state(e, kind, domain, appearance, params=(), marking_cs=1, marking=b'TEST', version=7):
    b = eid(*e) + struct.pack('!BB', 1, len(params))
    b += etype(kind, domain) + etype(kind, domain, 225, 9, 9, 9, 9)
    b += vec3f(10.0, -5.0, 0.5) + vec3d(1000.0, 2000.0, 3000.0) + vec3f(0.1, 0.2, 0.3)
    b += struct.pack('!I', appearance)
    b += struct.pack('!B', 4) + bytes(15) + vec3f(0.0, 0.1, 0.2) + vec3f(0.3, 0.4, 0.5)
    b += struct.pack('!B', marking_cs) + marking.ljust(11, b'\0')
    b += struct.pack('!I', 0x00000005)
    for p in params:
        b += p
    return dis_header(1, b, version=version)


def entity_state_update(e, appearance, params=()):
    b = eid(*e) + struct.pack('!BB', 0, len(params))
    b += vec3f(1.0, 2.0, 3.0) + vec3d(10.0, 20.0, 30.0) + vec3f(0.5, 0.6, 0.7)
    b += struct.pack('!I', appearance)
    for p in params:
        b += p
    return dis_header(67, b)


def fixed_datum(i, v):
    return struct.pack('!II', i, v)


def var_datum(i, bits, data):
    nbytes = (bits + 7) // 8
    d = data[:nbytes].ljust(nbytes, b'\0')
    pad = (8 - nbytes % 8) % 8
    return struct.pack('!II', i, bits) + d + bytes(pad)


FIXED = [fixed_datum(11000, 0x3fc00000), fixed_datum(52000, 7)]
VARIABLE = [var_datum(32000, 32, b'ABCD'), var_datum(32010, 12, b'\x12\x34'),
            var_datum(32020, 64, b'DIS-TEXT')]


def datum_body(fixed=FIXED, variable=VARIABLE):
    return struct.pack('!II', len(fixed), len(variable)) + b''.join(fixed) + b''.join(variable)


# ---------------------------------------------------------- Link 16 words

def link16_payload(headers):
    """Pack Link 16 words the way parse_Link16_Message_Data() unpacks them.

    Returns the JTIDS header (2 x 32 bits) followed by the word data.
    headers: 16 bit header value of each word (the rest of the word is a
    pattern)."""
    # JTIDS header word A: time slot type, RTI, STN (0x0007FFF0) and the
    # low 13 bits of the SDUSN in the top bits (cache >> 19).
    stn = 0o12345
    sdusn = 0x1234
    a = (1 << 0) | (1 << 3) | (stn << 4) | ((sdusn & 0x1fff) << 19)
    u32 = [a]
    b = (sdusn >> 13) & 0x7            # SDUSN high bits in the low 3 bits
    # the first word header is the top 16 bits of word B
    b |= headers[0] << 16 if headers else 0
    u32.append(b)
    i = 0
    n = len(headers)
    while i < n:
        # even word: header already placed; 2 x 32 bits of body
        u32 += [0x11111111 * ((i % 7) + 1), 0x01020304]
        i += 1
        if i >= n:
            break
        # odd word: header in the low 16 bits of the first of 3 x 32 bits;
        # the next even word header goes in the top 16 bits of the third.
        nxt = headers[i + 1] if i + 1 < n else 0
        u32 += [0xA5A50000 | headers[i], 0x0BADF00D, (nxt << 16) | 0x5A5A]
        i += 1
    return b''.join(struct.pack('!I', v) for v in u32)


def l16hdr(fmt, label=0, sub=0, mli=0):
    if fmt == 0:
        return fmt | (label << 2) | (sub << 7) | (mli << 10)
    if fmt == 1:
        return fmt | (label << 2)      # continuation label
    return fmt


def link16_net_header(npg=7, msgtype=0, ptt=0x0000000180000000):
    return struct.pack('!HBBBBHIQ', npg, 2, 1, 2, msgtype, 0, 0x1234, ptt)


def signal(e, radio, ens, tdl, rate, nsamples, data, ptype=26):
    b = eid(*e) + struct.pack('!HHHIHH', radio, ens, tdl, rate, len(data) * 8, nsamples) + data
    return dis_header(ptype, b)


# ------------------------------------------------------------------ PDUs

def transmitter(radio, major, detail, system, params=b'', plen=None, state=2, version=7):
    b = eid(1, 1, 1) + struct.pack('!H', radio)
    b += struct.pack('!BBHBBH', 7, 1, 225, 2, 3, 4)     # radio entity type
    b += struct.pack('!BBH', state, 1, 0)
    b += vec3d(1.0, 2.0, 3.0) + vec3f(0.0, 0.0, 1.0)
    b += struct.pack('!HHQff', 0, 0, 250000000, 25000.0, 10.0)
    b += struct.pack('!HHHH', 0xF000, major, detail, system)
    b += struct.pack('!HH', 4, 0x8001)
    if plen is None:
        plen = len(params)
    b += struct.pack('!B', plen) + bytes(3) + params
    return dis_header(25, b, version=version)


def iff(sysid, p1, p2, p3, p4, p5, p6, version=7, status=0x81, onoff=0xff):
    systype, name, mode, opts = sysid
    b = eid(1, 2, 3) + eid(1, 2, 99) + vec3f(1.0, 2.0, 3.0)
    b += struct.pack('!HHBB', systype, name, mode, opts)
    b += struct.pack('!BB', 1, 2)      # padding (v6) or designator/specific data (v7)
    b += struct.pack('!BBBB', onoff, 3, 0x7f, 0x0f)
    b += struct.pack('!HHHHHH', p1, p2, p3, p4, p5, p6)
    return dis_header(28, b, version=version)


def ee_pdu():
    b = eid(1, 1, 1) + eid(1, 1, 50) + struct.pack('!BBH', 1, 2, 0)
    # system 1: two beams, the first with two track/jam targets
    beams = b''
    for bid, targets in ((1, 2), (2, 0)):
        bm = struct.pack('!BBH', 13 + 2 * targets, bid, 7)
        bm += struct.pack('!ffffffffff', 9.4e9, 1e6, 60.0, 1000.0, 1.0, 0.1, 0.2, 0.3, 0.4, 0.5)
        bm += struct.pack('!BBBBI', 2, targets, 1, 0, 0x12345678)
        for t in range(targets):
            bm += eid(2, 2, 10 + t) + struct.pack('!BB', 1, 1)
        beams += bm
    b += struct.pack('!BBH', 5 + len(beams) // 4, 2, 0) + struct.pack('!HBB', 1010, 2, 1) + vec3f(1.0, 0.0, 0.0) + beams
    # system 2: no beams
    b += struct.pack('!BBH', 5, 0, 0) + struct.pack('!HBB', 2020, 1, 2) + vec3f(0.0, 1.0, 0.0)
    return dis_header(23, b)


def ua_pdu(shafts, apas, emitters, beams_total):
    b = eid(1, 1, 1) + eid(1, 1, 60) + struct.pack('!BBHBBBB', 1, 0, 3, 2, len(shafts), len(apas), len(emitters))
    for s in shafts:
        b += struct.pack('!hhf', s, s + 10, 1.5)
    for a in apas:
        b += struct.pack('!HH', a, a * 2)
    for i, nb in enumerate(emitters):
        b += struct.pack('!BBH', 5, nb, 0) + struct.pack('!HBB', 100 + i, 1, i + 1) + vec3f(0.0, 0.0, -float(i))
    for j in range(beams_total):
        b += struct.pack('!BBH', 6, (j % 255) + 1, 0) + struct.pack('!HHffff', 2, 1, 0.5, 0.1, 0.0, 0.2)
    return dis_header(29, b)


def aggregate(aggs, ents, silent_aggs, variable, marking=b'AGGREGATE'):
    b = eid(1, 1, 1) + struct.pack('!BB', 1, 1) + etype(11, 1, 225, 3, 4, 5, 6)
    b += struct.pack('!I', 3) + struct.pack('!B', 1) + marking.ljust(31, b'\0')
    b += vec3f(100.0, 200.0, 10.0) + vec3f(0.0, 0.0, 0.0) + vec3d(1.0, 2.0, 3.0) + vec3f(4.0, 5.0, 6.0)
    b += struct.pack('!HHHH', len(aggs), len(ents), silent_aggs, 0)
    for a in aggs:
        b += eid(*a)
    for e in ents:
        b += eid(*e)
    n = 6 * (len(aggs) + len(ents))
    b += b'\xAA' * ((4 - n % 4) % 4)
    b += bytes(12 * silent_aggs)
    b += struct.pack('!I', len(variable)) + b''.join(variable)
    return dis_header(33, b)


def vrecord(rtype, value, length=None):
    if length is None:
        length = 6 + len(value)
    pad = (8 - length % 8) % 8
    return struct.pack('!IH', rtype, length) + value + bytes(pad)


def app_control(records):
    b = eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBBBHHIBBH', 1, 5, 3, 0, 1, 2, 77, 1, 1, len(records))
    return dis_header(73, b + b''.join(records))


def build_main():
    F = []

    def dis(p):
        F.append((0, udp_frame(p)))

    # --- 1-9: Entity State PDUs: every appearance and category branch,
    # every variable parameter type, every marking character set
    dis(entity_state((1, 1, 1), 1, 1, 0x00010203, [vp_articulated(), vp_attached()]))
    dis(entity_state((1, 1, 2), 1, 2, 0x00800001, [vp_offset(), vp_association()], marking_cs=0))
    dis(entity_state((1, 1, 3), 1, 3, 0x11, [vp_other(3)], marking_cs=2))
    dis(entity_state((1, 1, 4), 1, 4, 0x12, marking_cs=3))
    dis(entity_state((1, 1, 5), 1, 5, 0x13, marking_cs=4))
    dis(entity_state((1, 1, 6), 1, 0, 0x14))
    dis(entity_state((1, 1, 7), 3, 1, 0x00010005, marking=b'INFANTRY'))
    dis(entity_state((1, 1, 8), 2, 2, 0x15, marking=b'MISSILE'))
    # same entity again (already in the map), protocol version 6 header
    dis(entity_state((1, 1, 1), 1, 1, 0x00010203, version=6))

    # --- 10-14: Entity State Update PDUs for the land, air, life form and
    # munition entities above and one never seen before (warning)
    dis(entity_state_update((1, 1, 1), 0x00010203, [vp_articulated()]))
    dis(entity_state_update((1, 1, 2), 0x00800001, [vp_attached()]))
    dis(entity_state_update((1, 1, 7), 0x00010005))
    dis(entity_state_update((1, 1, 8), 0x15, [vp_other(38)]))
    dis(entity_state_update((9, 9, 9), 0x16))

    # --- 15-16: reproducer dis_esu_2pass: ESU, then ES of the same entity
    dis(entity_state_update((20, 20, 1), 0x00010000))
    dis(entity_state((20, 20, 1), 1, 2, 0x00010000))
    # --- 17-19: reproducer dis_entity_key: same site/application, two
    # entities of different domain; the ESU is for the air entity
    dis(entity_state((21, 21, 1), 1, 1, 0x00010000))
    dis(entity_state((21, 21, 2), 1, 2, 0x00010000))
    dis(entity_state_update((21, 21, 2), 0x00010000))

    # --- 20-22: warfare: Fire, Detonation (with variable parameters), Collision
    burst = etype(2, 2, 225, 1, 1, 1, 0) + struct.pack('!HHHH', 1000, 100, 1, 0)
    b = eid(1, 1, 1) + eid(2, 2, 2) + eid(1, 1, 100) + eid(1, 1, 5) + struct.pack('!I', 3)
    b += vec3d(1.0, 2.0, 3.0) + burst + vec3f(300.0, 0.0, 0.0) + struct.pack('!f', 5000.0)
    dis(dis_header(2, b))
    b = eid(1, 1, 1) + eid(2, 2, 2) + eid(1, 1, 100) + eid(1, 1, 5) + vec3f(300.0, 0.0, -10.0)
    b += vec3d(1.0, 2.0, 3.0) + burst + vec3f(0.5, 0.5, 0.5) + struct.pack('!BBH', 1, 2, 0)
    b += vp_articulated() + vp_association()
    dis(dis_header(3, b))
    b = eid(1, 1, 1) + eid(2, 2, 2) + eid(1, 1, 6) + struct.pack('!BB', 1, 0)
    b += vec3f(1.0, 0.0, 0.0) + struct.pack('!f', 1500.0) + vec3f(0.0, 1.0, 0.0)
    dis(dis_header(4, b))

    # --- 23: Electromagnetic Emission
    dis(ee_pdu())
    # --- 24-25: Underwater Acoustic: small; reproducer (2 x 200 beams)
    dis(ua_pdu([100, -50], [1, 2], [1, 2], 3))
    dis(ua_pdu([], [], [200, 200], 400))

    # --- 26-27: Designator, Intercom Control
    b = eid(1, 1, 1) + struct.pack('!H', 1100) + eid(2, 2, 2) + struct.pack('!Hff', 2, 5.0, 1.064)
    b += vec3f(0.0, 0.0, 1.0) + vec3d(4.0, 5.0, 6.0) + struct.pack('!BBH', 2, 0, 0) + vec3f(0.0, 0.0, 0.0)
    dis(dis_header(24, b))
    b = struct.pack('!BB', 1, 2) + eid(1, 1, 1) + struct.pack('!HBBBB', 3, 4, 5, 2, 1) + eid(1, 1, 2) + struct.pack('!HH', 6, 7)
    dis(dis_header(32, b))

    # --- 28-37: Transmitter: every major modulation, SINCGARS, JTIDS/MIDS,
    # other parameters and no parameters
    sinc = struct.pack('!HHHBBIHBB', 1, 2, 3, 1, 0, 1000, 0x1234, 1, 0)
    jtids = struct.pack('!BBBBI', 1, 2, 3, 2, 0xABCDEF01)
    dis(transmitter(1, 1, 2, 5, sinc))
    dis(transmitter(2, 2, 1, 8, jtids))
    dis(transmitter(3, 3, 1, 1, b'\x01\x02\x03\x04'))
    dis(transmitter(4, 4, 1, 1))
    dis(transmitter(5, 5, 1, 1, version=6))
    dis(transmitter(6, 6, 1, 1, state=0))
    dis(transmitter(7, 7, 0, 1, state=1))
    dis(transmitter(8, 8, 0, 1))
    dis(transmitter(9, 0, 0, 1))
    dis(transmitter(10, 99, 0, 1, state=9))

    # --- 38-43: Signal: encoded audio (8 samples), raw binary without
    # samples, Link 16 with 4 words (initial, continuation, extension,
    # format 3) and PTT "NO STATEMENT", Link 16 with another message
    # type, Intercom Signal, reproducer dis_link16_setend
    dis(signal((1, 1, 1), 1, 0x0004, 0, 8000, 8, bytes(range(0, 256, 32))))
    dis(signal((1, 1, 1), 2, 0x4000 | 3, 0, 0, 0, b'\x10\x20\x30\x40'))
    words = [l16hdr(0, 3, 2, 3), l16hdr(1, 5), l16hdr(2), l16hdr(3)]
    data = link16_net_header(msgtype=0, ptt=0xFFFFFFFF00000000) + link16_payload(words)
    dis(signal((1, 1, 1), 3, 0x4000 | len(words), 100, 0, 0, data))
    dis(signal((1, 1, 1), 4, 0x4000, 100, 0, 0, link16_net_header(msgtype=2) + bytes(8)))
    dis(signal((1, 1, 1), 5, 0x0001, 0, 8000, 4, b'\x7f\x7f\x80\x80', ptype=31))
    # reproducer: message type 0, 2 words of zero
    b = eid(1, 1, 1) + struct.pack('!HHHIHH', 1, 2, 100, 8000, 0, 0)
    b += struct.pack('!HBBBBHI', 1, 1, 0, 0, 0, 0, 0) + bytes(8)
    b += bytes(8) + bytes(20)
    dis(dis_header(26, b))

    # --- 44-47: Receiver (states 0-2 and unknown)
    for st in (0, 1, 2, 7):
        b = eid(1, 1, 1) + struct.pack('!HHHf', 1, st, 0, -80.5) + eid(1, 1, 2) + struct.pack('!H', 3)
        dis(dis_header(27, b))

    # --- 48-53: IFF
    dis(iff((1, 2, 1, 0xff), 0o12 | 0x2000, 0o1234 | 0x2000, 0o4567 | 0xe000, 0o777 | 0x2000,
            (100 << 1) | 0x2000, 0x0001, version=6))
    dis(iff((5, 3, 2, 0x01), 0x0003 | 0x6000, 0, 0, 0, 0, 0x1001))
    dis(iff((8, 4, 1, 0x02), 0, 0o7, 0o70, (5 << 9) | (0 << 8) | (3 << 1) | 0, (20 << 1) | 1, 0x0202))
    dis(iff((8, 4, 1, 0x02), 0, 0, 0, (7 << 9) | (1 << 8) | (9 << 1) | 1, 0x2000, 0x0402))
    dis(iff((1, 2, 1, 0x00), 0, 0, 0, 0, 0, 0x0602))
    dis(iff((5, 3, 2, 0x00), 0, 0, 0, 0, 0, 0, onoff=0))

    # --- 54-65: simulation management; 56 is the Start/Resume reproducer
    # of dis_small_fixes (clock time hour 0x00200000)
    dis(dis_header(11, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!I', 1)))
    dis(dis_header(12, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!I', 2)))
    dis(dis_header(13, eid(1, 1, 1) + eid(2, 2, 2) + clock(0x00200000, 0) + clock(1, 0) + struct.pack('!I', 7)))
    dis(dis_header(14, eid(1, 1, 1) + eid(2, 2, 2) + clock(10, 0x7ffffffe) + struct.pack('!BBHI', 2, 1, 0, 4)))
    dis(dis_header(15, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!HHI', 1, 1, 5)))
    dis(dis_header(16, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 6, 1) + datum_body()))
    dis(dis_header(17, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 6, 2) + datum_body()))
    dis(dis_header(18, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 7, 1000) +
                   struct.pack('!II', 2, 1) + struct.pack('!III', 11000, 52000, 32000)))
    dis(dis_header(19, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 8, 0) + datum_body()))
    dis(dis_header(20, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 8, 0) + datum_body(FIXED[:1], [])))
    dis(dis_header(21, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 2, 0) + datum_body()))
    dis(dis_header(22, eid(1, 1, 1) + eid(2, 2, 2) + datum_body([], VARIABLE)))

    # --- 66-76: simulation management with reliability
    dis(dis_header(51, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHI', 1, 0, 0, 9)))
    dis(dis_header(52, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHI', 0, 0, 0, 10)))
    dis(dis_header(53, eid(1, 1, 1) + eid(2, 2, 2) + clock(0, 1) + clock(0, 0) + struct.pack('!BBHI', 1, 0, 0, 11)))
    dis(dis_header(54, eid(1, 1, 1) + eid(2, 2, 2) + clock(2, 3) + struct.pack('!BBBBI', 1, 2, 1, 0, 12)))
    dis(dis_header(55, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!HHI', 2, 2, 13)))
    dis(dis_header(56, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHII', 1, 0, 0, 14, 3) + datum_body()))
    dis(dis_header(57, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 14, 1) + datum_body()))
    dis(dis_header(58, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHII', 1, 0, 0, 15, 500) +
                   struct.pack('!II', 1, 2) + struct.pack('!III', 11000, 32000, 32010)))
    dis(dis_header(59, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHI', 1, 0, 0, 16) + datum_body()))
    dis(dis_header(60, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!BBHI', 0, 0, 0, 17) + datum_body([], [])))
    dis(dis_header(62, eid(1, 1, 1) + eid(2, 2, 2) + datum_body(FIXED, [])))

    # --- 77-78: Aggregate State: 2 aggregates, 1 entity, 1 silent aggregate
    # type, 2 variable datums; reproducer (1 aggregate, 0 entities)
    dis(aggregate([(3, 3, 1), (3, 3, 2)], [(4, 4, 1)], 1, VARIABLE[:2]))
    b = eid(1, 1, 1) + b'\x01\x01' + bytes(8) + struct.pack('!I', 0)
    b += b'\x01' + b'AGG'.ljust(31, b'\0')
    b += bytes(12 + 12 + 24 + 12)
    b += struct.pack('!HHHH', 1, 0, 0, 0)
    b += eid(3, 3, 3) + b'\xAA\xBB'
    b += struct.pack('!I', 1)
    b += struct.pack('!II', 0x1234, 32) + b'ABCD' + bytes(4)
    dis(dis_header(33, b))

    # --- 79: Environmental Process
    dis(dis_header(41, eid(1, 1, 1) + etype(4, 2, 1, 2, 3, 4, 5) + struct.pack('!BBHH', 1, 3, 0, 9)))

    # --- 80-81: Application Control: every record type, a record longer
    # than its value, a record with no value; reproducer
    init = struct.pack('!BB', 4, 0) + b'/exercises/'.ljust(256, b'\0') + b'demo.xml'.ljust(128, b'\0') + b'controller'.ljust(64, b'\0')
    recs = [
        vrecord(47200, struct.pack('!BHBBHd', 0, 1, 2, 3, 4, 0.5)),
        vrecord(47300, init),
        vrecord(47600, struct.pack('!HII', 2, 11000, 32000) + b'\xEE' * 8),
        vrecord(12345, b'WXYZ'),
        vrecord(23456, b''),
    ]
    dis(app_control(recs))
    b = eid(1, 1, 1) + eid(2, 2, 2) + b'\x00\x00\x00\x00' + struct.pack('!HHI', 1, 2, 3) + b'\x01\x01' + struct.pack('!H', 1)
    b += struct.pack('!IH', 12345, 10) + b'WXYZ' + bytes(6)
    dis(dis_header(73, b))

    # --- 82-89: Persistent Object family: every PO PDU type and "Other"
    dis(po_pdu(1, struct.pack('!HHHHIIIIIHH', 1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10) +
               b'TERRAIN'.ljust(32, b'\0') + struct.pack('!H', 2) + b'host.example'.ljust(32, b'\0')))
    dis(po_pdu(2, struct.pack('!I', 1) + eid(1, 1, 1) + eid(1, 1, 2) + struct.pack('!HHHBB', 1, 2, 3, 4, 0)))
    dis(po_pdu(3, struct.pack('!HH', 1, 2) + eid(1, 1, 2) + struct.pack('!B', 5)))
    dis(po_pdu(4, struct.pack('!HHHH', 1, 2, 3, 4) + eid(1, 1, 2) + struct.pack('!B', 6)))
    dis(po_pdu(5, struct.pack('!HHB', 1, 2, 7)))
    dis(po_pdu(6, struct.pack('!HHII', 1, 2, 1, 1700000000) + eid(1, 1, 2)))
    dis(po_pdu(7, struct.pack('!HHHHHH', 1, 2, 3, 4, 5, 6), version=6))
    dis(po_pdu(0, b''))

    # --- 90-: PDU types without a parser (header and PDU status only),
    # one for each PDU status layout; and the protocol version 5 header
    for t in (0, 5, 6, 7, 8, 9, 10, 30, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46,
              47, 48, 49, 50, 61, 63, 64, 65, 66, 68, 69, 70, 71, 72, 74, 129, 135, 201, 250):
        dis(dis_header(t, b'\x00\x01\x02\x03', status=0xff, ts=0x00002001))
    dis(dis_header(46, b'\x00\x01\x02\x03', version=5))

    # --- last: Link 16 called by name from an Exported PDU (reproducer
    # dis_link16_exppdu) and two more words
    F.append((1, exp_pdu('link16', bytes(10))))
    w = l16hdr(0, 2, 2, 1)
    F.append((1, exp_pdu('link16', struct.pack('<H', w) + bytes(8))))
    F.append((1, exp_pdu('link16', struct.pack('<H', l16hdr(2)) + bytes(8))))
    return F


def build_malformed():
    F = []

    def dis(p):
        F.append((0, udp_frame(p)))

    # header only, for PDU types with a parser: exceptions in each parser
    for t in (1, 2, 3, 4, 11, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
              31, 32, 33, 41, 51, 53, 54, 56, 58, 60, 67, 73):
        dis(dis_header(t, b'\x00\x01'))
    # PO family without its PO header
    F.append((0, udp_frame(struct.pack('!BBBBIHBB', 7, 1, 0, 140, 0, 12, 0, 0))))
    # less than 12 octets: not DIS
    F.append((0, udp_frame(b'\x07\x01\x01\x01\x00\x00\x00\x00')))
    # variable datum longer than the packet
    dis(dis_header(22, eid(1, 1, 1) + eid(2, 2, 2) + struct.pack('!II', 0, 1) + struct.pack('!II', 1, 8000) + b'x'))
    # Link 16 with more words than data
    dis(signal((1, 1, 1), 3, 0x4000 | 50, 100, 0, 0, link16_net_header() + link16_payload([0, 1])))
    # Application control record with a length smaller than its header
    dis(app_control([struct.pack('!IH', 99, 4) + bytes(4)]))
    # Entity state with variable parameters missing
    dis(entity_state((1, 1, 1), 1, 1, 0, [vp_articulated()])[:-8])
    # Link 16 exported PDU shorter than a word
    F.append((1, exp_pdu('link16', b'\x01')))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'dis-coverage.pcapng'), build_main())
    write_pcapng(os.path.join(out, 'dis-coverage-malformed.pcapng'), build_malformed())


if __name__ == '__main__':
    main()

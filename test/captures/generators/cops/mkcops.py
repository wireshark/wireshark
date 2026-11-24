#!/usr/bin/env python3
# Generates test/captures/cops_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the COPS dissector
(packet-cops.c): COPS (RFC 2748), COPS-PR (RFC 3084) and the PacketCable
Dynamic QoS and Multimedia client objects.

COPS runs over TCP: port 3288 (preference), 2126 (PacketCable) and 3918
(PacketCable Multimedia). A message is an 8 octet header (version/flags,
op code, client type, length) and objects of length, C-Num, C-Type and
data padded to 32 bits. COPS-PR data (PRID, PPRID, EPD, GPERR, CPERR,
ErrorPRID) is carried in Named Decision Data and Named ClientSI objects.
PacketCable sub-objects (S-Num/S-Type) are carried in Client Specific
Decision Data and Signaled ClientSI objects. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcops.py <output directory>

Writes:
  cops-coverage.pcap            every op code, every object and C-Type,
                                request/response matching, reassembly,
                                COPS-PR data with every BER type, every
                                PacketCable D-QoS and Multimedia object
                                and traffic profile version, and the
                                reproducer of the fix on the branch
  cops-coverage-malformed.pcap  objects that are too short or too long,
                                PacketCable objects running past their
                                COPS object, bad lengths
"""

import os
import struct
import sys

PEP = '192.0.2.1'
PDP = '192.0.2.2'
MAC_PEP = bytes.fromhex('020000000001')
MAC_PDP = bytes.fromhex('020000000002')


def a4(s):
    return bytes(map(int, s.split('.')))


def a6(s):
    head, _, tail = s.partition('::')
    h = [int(x, 16) for x in head.split(':') if x]
    t = [int(x, 16) for x in tail.split(':') if x]
    return struct.pack('>8H', *(h + [0] * (8 - len(h) - len(t)) + t))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Capture:
    def __init__(self):
        self.frames = []
        self.t = 0

    def add(self, frame, dt=10000):
        self.t += dt
        self.frames.append((self.t, frame))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', 1700000000 + t // 1000000, t % 1000000,
                                    len(fr), len(fr)))
                f.write(fr)


class Conn:
    """A TCP connection between the PEP (client port) and the PDP."""

    def __init__(self, cap, sport, dport):
        self.cap = cap
        self.sport, self.dport = sport, dport
        self.seq = {True: 1000, False: 50000}  # True: PEP -> PDP

    def seg(self, data, from_pep=True, dt=10000):
        src, dst = (PEP, PDP) if from_pep else (PDP, PEP)
        sp, dp = (self.sport, self.dport) if from_pep else (self.dport, self.sport)
        seq, ack = self.seq[from_pep], self.seq[not from_pep]
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + data
        ph = a4(src) + a4(dst) + struct.pack('>xBH', 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                         a4(src), a4(dst))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        smac, dmac = (MAC_PEP, MAC_PDP) if from_pep else (MAC_PDP, MAC_PEP)
        self.cap.add(dmac + smac + b'\x08\x00' + ip + tcp, dt)
        self.seq[from_pep] += len(data)

    def send(self, pdus, from_pep=True, dt=10000):
        self.seg(b''.join(pdus) if isinstance(pdus, list) else pdus, from_pep, dt)


# ---- COPS encoding -------------------------------------------------------

def obj(cnum, ctype, body, length=None):
    ln = 4 + len(body) if length is None else length
    b = struct.pack('>HBB', ln, cnum, ctype) + body
    return b + b'\0' * ((-len(b)) % 4)


def cops(op, client, objs, flags=0, extra=b'', length=None):
    body = b''.join(objs) + extra
    ln = 8 + len(body) if length is None else length
    return struct.pack('>BBHI', 0x10 | flags, op, client, ln) + body


REQ, DEC, RPT, DRQ, SSQ, OPN, CAT, CC, KA, SSC = range(1, 11)
SOL = 1


def handle(h, size=4):
    return obj(1, 1, h.to_bytes(size, 'big'))


def context(r, m):
    return obj(2, 1, struct.pack('>HH', r, m))


def pepid(s):
    return obj(11, 1, s)


def decision(cmd, flags):
    return obj(6, 1, struct.pack('>HH', cmd, flags))


# COPS-PR objects (same header layout, S-Num/S-Type)
def probj(snum, stype, body):
    return obj(snum, stype, body)


def ber_oid(*subids):
    enc = bytes([subids[0] * 40 + subids[1]])
    for s in subids[2:]:
        b = [s & 0x7f]
        s >>= 7
        while s:
            b.insert(0, 0x80 | (s & 0x7f))
            s >>= 7
        enc += bytes(b)
    return enc


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def prid(*subids):
    return probj(1, 1, tlv(0x06, ber_oid(*subids)))


def epd_all():
    """EPD with every BER type the dissector knows, and an unknown one."""
    return probj(3, 1,
                 tlv(0x05, b'') +                         # NULL
                 tlv(0x02, b'\x01\x00') +                 # INTEGER 256
                 tlv(0x04, b'eth0') +                     # OCTET STRING
                 tlv(0x06, ber_oid(1, 3, 6, 1, 2, 1)) +   # OBJECT IDENTIFIER
                 tlv(0x40, a4('198.51.100.7')) +          # [APPLICATION 0] IpAddress
                 tlv(0x42, b'\x00\x01\x00\x00') +         # [APPLICATION 2] Unsigned32
                 tlv(0x43, b'\x00\x00\x30\x39') +         # [APPLICATION 3] TimeTicks
                 tlv(0x44, b'\xde\xad\xbe\xef') +         # [APPLICATION 4] Opaque
                 tlv(0x4a, b'\xff\xff\xff\xff\xff\xff\xff\xfe') +  # [APPLICATION 10] Integer64
                 tlv(0x4b, b'\x01\x02\x03\x04\x05\x06\x07\x08') +  # [APPLICATION 11] Unsigned64
                 tlv(0x45, b'\x55\x66'))                  # [APPLICATION 5]: unknown


# PacketCable sub-objects
def sub(snum, stype, body):
    return struct.pack('>HBB', 4 + len(body), snum, stype) + body


def sub_len(snum, stype, length, fill=0x11):
    """A sub-object of exactly 'length' octets, contents counting up."""
    return struct.pack('>HBB', length, snum, stype) + \
        bytes((fill + k) & 0xff for k in range(length - 4))


# ---- main capture ---------------------------------------------------------

def main_capture(cap):
    # --- Conversation A: RSVP client (1), port 3288 ---
    a = Conn(cap, 40000, 3288)
    # A1 OPN: PEP ID, Last PDP address (IPv4), signaled ClientSI
    a.send(cops(OPN, 1, [pepid(b'pep-a.example\0'),
                         obj(14, 1, a4('192.0.2.9') + struct.pack('>HH', 0, 3288)),
                         obj(9, 1, b'\x01\x02\x03\x04')]))
    # A2 CAT: keep-alive timer 30, accounting timer 0
    a.send(cops(CAT, 1, [obj(10, 1, struct.pack('>HH', 0, 30)),
                         obj(15, 1, struct.pack('>HH', 0, 0))]), False)
    # A3 REQ handle 0x101: context, in/out interfaces, ClientSI and
    #    LPDP decisions of every C-Type
    a.send(cops(REQ, 1, [handle(0x101), context(1, 0),
                         obj(3, 1, a4('192.0.2.1') + struct.pack('>I', 3)),
                         obj(4, 2, a6('2001:db8::1') + struct.pack('>I', 4)),
                         obj(3, 2, a6('2001:db8::10') + struct.pack('>I', 5)),
                         obj(4, 1, a4('192.0.2.2') + struct.pack('>I', 6)),
                         obj(9, 1, b'rsvp-path-data'),
                         obj(7, 1, struct.pack('>HH', 0, 0)),
                         obj(7, 2, b'stateless'),
                         obj(7, 3, b'replacement'),
                         obj(7, 4, b'client'),
                         obj(7, 5, b'')]))
    # A4 DEC (solicited) for handle 0x101: install with trigger error,
    #    stateless, replacement and client specific data
    a.send(cops(DEC, 1, [handle(0x101), context(2, 1), decision(1, 1),
                         obj(6, 2, b'\xaa\xbb\xcc\xdd'), obj(6, 3, b'\x01'),
                         obj(6, 4, b'client-data')], SOL), False)
    # A5 RPT (solicited): success, answers the DEC
    a.send(cops(RPT, 1, [handle(0x101), obj(12, 1, struct.pack('>HH', 1, 0)),
                         obj(9, 1, b'\x00\x01')], SOL))
    # A6 DEC (unsolicited) for handle 0x101: remove, unknown flag
    a.send(cops(DEC, 1, [handle(0x101), context(4, 0), decision(2, 2)]), False)
    # A7 DRQ (solicited): reason Management, answers the DEC
    a.send(cops(DRQ, 1, [handle(0x101), obj(5, 1, struct.pack('>HH', 2, 0))], SOL))
    # A8 DRQ (solicited) for handle 0x103, never requested
    a.send(cops(DRQ, 1, [handle(0x103), obj(5, 1, struct.pack('>HH', 13, 0x1401))], SOL))
    # A9 SSQ with handle 0x104, A10 RPT (accounting) answering it
    a.send(cops(SSQ, 1, [handle(0x104)]), False)
    a.send(cops(RPT, 1, [handle(0x104), obj(12, 1, struct.pack('>HH', 3, 0))], SOL))
    # A11 SSQ with handle 0x105, A12 DRQ answering it
    a.send(cops(SSQ, 1, [handle(0x105)]), False)
    a.send(cops(DRQ, 1, [handle(0x105), obj(5, 1, struct.pack('>HH', 5, 0))], SOL))
    # A13 SSQ without a handle, A14 SSC answering it
    a.send(cops(SSQ, 1, []), False)
    a.send(cops(SSC, 1, []))
    # A15 KA from the PEP, A16 KA answer, A17 a second unsolicited answer
    a.send(cops(KA, 1, []))
    a.send(cops(KA, 1, [], SOL), False)
    a.send(cops(KA, 1, [], SOL), False)
    # A18 REQ handle 0x106, A19 RPT (failure) does not answer a REQ
    a.send(cops(REQ, 1, [handle(0x106), context(8, 5)]))
    a.send(cops(RPT, 1, [handle(0x106), obj(12, 1, struct.pack('>HH', 2, 0))], SOL))
    # A20 CC from the PEP with an Error (unknown object C-Num 20 C-Type 1)
    a.send(cops(CC, 1, [obj(8, 1, struct.pack('>HBB', 13, 20, 1))]))
    # A21 second OPN, A22 CC (solicited) answering it: redirect with
    #     IPv4 and IPv6 PDP addresses
    a.send(cops(OPN, 1, [pepid(b'pep-a.example\0'),
                         obj(14, 2, a6('2001:db8::9') + struct.pack('>HH', 0, 3288))]))
    a.send(cops(CC, 1, [obj(8, 1, struct.pack('>HH', 12, 0)),
                        obj(13, 1, a4('192.0.2.20') + struct.pack('>HH', 0, 3288)),
                        obj(13, 2, a6('2001:db8::20') + struct.pack('>HH', 0, 3289))],
                SOL), False)
    # A23 REQ with an 8 octet handle (lowest 32 bits used), an Integrity
    #     object and accounting timer 60; A24 DEC with the same timestamp
    #     (not matched: the response must come later)
    a.send(cops(REQ, 1, [obj(1, 1, bytes.fromhex('0000000100000107')), context(1, 0),
                         obj(15, 1, struct.pack('>HH', 0, 60)),
                         obj(16, 1, struct.pack('>II', 7, 1) + bytes(range(16)))]))
    a.send(cops(DEC, 1, [handle(0x107), decision(0, 0)], SOL), False, dt=0)
    # A25 unknown op code 11 with an unknown flag, unknown C-Num 20,
    #     every object with an unknown C-Type, 2 octets of
    #     trailing garbage
    a.send(cops(11, 1, [obj(1, 2, struct.pack('>I', 0x108)),
                        obj(20, 1, b'????'),
                        obj(3, 3, b'\0' * 8), obj(6, 6, b'\0' * 4),
                        obj(8, 2, b'\0' * 4), obj(9, 3, b'\0' * 4),
                        obj(10, 2, b'\0' * 4), obj(11, 2, b'x\0'),
                        obj(12, 2, b'\0' * 4), obj(13, 3, b'\0' * 8),
                        obj(15, 2, b'\0' * 4), obj(16, 2, b'\0' * 12)],
                2, extra=b'\xee\xee'))
    # A26 REQ with unknown values: R-Type, reason codes, error code,
    #     command code; a handle object without contents
    a.send(cops(REQ, 1, [obj(1, 1, b''), context(3, 0),
                         obj(5, 1, struct.pack('>HH', 99, 1)),
                         obj(8, 1, struct.pack('>HH', 99, 1)),
                         decision(7, 0)]))
    # A27 two REQs in one segment
    a.send([cops(REQ, 1, [handle(0x109), context(1, 0)]),
            cops(REQ, 1, [handle(0x10a), context(1, 0)])])
    # A28-A30 a REQ with a 600 octet ClientSI split over three segments
    big = cops(REQ, 1, [handle(0x10b), context(1, 0), obj(9, 1, bytes(range(256)) * 2 + b'x' * 88)])
    a.seg(big[:5])
    a.seg(big[5:300])
    a.seg(big[300:])
    # A31-A32 a DEC answering 0x10b and the start of the next one in one
    #     segment, then the rest
    d1 = cops(DEC, 1, [handle(0x10b), decision(1, 0)], SOL)
    d2 = cops(DEC, 1, [handle(0x109), decision(1, 0)], SOL)
    a.seg(d1 + d2[:10], False)
    a.seg(d2[10:], False)

    # --- Conversation B: COPS-PR, DiffServ client (2), port 3288 ---
    b = Conn(cap, 40001, 3288)
    # B1 OPN with a Named ClientSI: PRID and EPD with every BER type
    b.send(cops(OPN, 2, [pepid(b'pep-b\0'),
                         obj(9, 2, prid(1, 3, 6, 1, 2, 2, 2, 1, 1, 1) + epd_all())]))
    b.send(cops(CAT, 2, [obj(10, 1, struct.pack('>HH', 0, 0))]), False)
    # B3 REQ with a Named ClientSI: PRID, EPD
    b.send(cops(REQ, 2, [handle(0x201), context(8, 0),
                         obj(9, 2, prid(1, 3, 6, 1, 4, 1, 99999, 1, 2, 1) + epd_all())]))
    # B4 DEC with Named Decision Data: PPRID, then a PRID relative to it,
    #    EPD; a second Named Decision Data with a plain PRID and EPD, an
    #    unknown S-Num and every S-Num with S-Type 2
    b.send(cops(DEC, 2, [handle(0x201), context(8, 0), decision(1, 0),
                         obj(6, 5, probj(2, 1, tlv(0x06, ber_oid(1, 3, 6, 1, 4, 1, 99999))) +
                             probj(1, 1, tlv(0x06, bytes([1, 0x81, 0x00, 5]))) +
                             epd_all()),
                         obj(6, 5, prid(1, 3, 6, 1, 4, 1, 99999, 3, 1) +
                             probj(3, 1, tlv(0x02, b'\x07')) +
                             probj(7, 1, b'\x01\x02\x03\x04') +
                             probj(1, 2, b'\0' * 4) + probj(2, 2, b'\0' * 4) +
                             probj(3, 2, b'\0' * 4) + probj(4, 2, b'\0' * 4) +
                             probj(5, 2, b'\0' * 4) + probj(6, 2, b'\0' * 4))], SOL), False)
    # B5 RPT (failure) with a Named ClientSI: GPERR (unknown object and
    #    a plain error), CPERR (unknown object and a plain error),
    #    ErrorPRID
    b.send(cops(RPT, 2, [handle(0x201), obj(12, 1, struct.pack('>HH', 2, 0)),
                         obj(9, 2, probj(4, 1, struct.pack('>HBB', 13, 9, 1)) +
                             probj(4, 1, struct.pack('>HH', 1, 2)) +
                             probj(4, 1, struct.pack('>HH', 99, 0)) +
                             probj(5, 1, struct.pack('>HBB', 13, 8, 1)) +
                             probj(5, 1, struct.pack('>HH', 3, 4)) +
                             probj(5, 1, struct.pack('>HH', 99, 0)) +
                             probj(6, 1, tlv(0x06, ber_oid(1, 3, 6, 1, 4, 1, 99999, 3, 1))))],
                SOL))

    # --- Reproducer cops_small_fixes: CPERR summary, PCMM decision
    #     followed by an Error object (frames R1, R2) ---
    r1 = Conn(cap, 40099, 3288)
    r1.send(cops(DEC, 2, [obj(1, 1, b'\0\0\0\1'), obj(6, 5, obj(5, 1, b'\0\x02\0\x07'))]))
    r2 = Conn(cap, 40099, 3918)
    r2.send(cops(DEC, 0x800a, [obj(1, 1, b'\0\0\0\1'),
                               obj(6, 4, struct.pack('!HBBI', 8, 4, 1, 0x11223344)),
                               obj(8, 1, b'\0\x01\0\0')]))

    # --- Conversation C: PacketCable Multimedia (0x800a), port 3918 ---
    c = Conn(cap, 40002, 3918)
    MM = 0x800a
    c.send(cops(OPN, MM, [pepid(b'cmts-1\0')]))
    c.send(cops(CAT, MM, [obj(10, 1, struct.pack('>HH', 0, 60))]), False)

    def mmdec(h, subs, flags=0):
        return cops(DEC, MM, [handle(h), context(8, 0), decision(1, 0),
                              obj(6, 4, b''.join(subs))], flags)

    # C3 Gate-Set: transaction, AMID, subscriber IPv4 and IPv6, gate ID,
    #    gate spec, the three classifiers, flow spec, event generation
    #    info, usage limits, opaque data, PSID, UserID, SharedResourceID,
    #    message receipt key, an unknown S-Num/S-Type
    c.send(mmdec(0x301, [
        sub(1, 1, struct.pack('>HH', 0x0101, 4)),
        sub(2, 1, struct.pack('>HH', 1, 2)),
        sub(3, 1, a4('198.51.100.10')),
        sub(3, 2, a6('2001:db8::100')),
        sub(4, 1, struct.pack('>I', 0xabcd0001)),
        sub(5, 1, struct.pack('>BBBBHHHH', 0x03, 0x2e, 0xfc, 0xe5, 200, 300, 0, 400)),
        sub(6, 1, struct.pack('>HBB4s4sHHB3x', 17, 0x2e, 0xfc, a4('198.51.100.10'),
                              a4('203.0.113.5'), 5060, 5061, 64)),
        sub(6, 2, struct.pack('>HBB4s4s4s4sHHHHHBBB3x', 6, 0, 0, a4('198.51.100.0'),
                              a4('255.255.255.0'), a4('203.0.113.0'),
                              a4('255.255.255.0'), 1000, 1999, 80, 80, 7, 64, 1, 0)),
        sub(6, 3, struct.pack('>BBBBIHBB16s16sHHHHHBBB3x', 0x01, 0, 0xff, 0xff, 0x12345,
                              17, 64, 64, a6('2001:db8::100'), a6('2001:db8:1::5'),
                              1000, 1999, 5004, 5005, 8, 64, 1, 3)),
        sub_len(7, 1, 36),
        sub(8, 1, a4('203.0.113.50') + struct.pack('>HH', 1813, 0) +
            a4('203.0.113.51') + struct.pack('>HHI', 1813, 0, 1700000000) +
            b'elem0001' + b'+1000000' + struct.pack('>I', 42)),
        sub(9, 1, struct.pack('>Q', 1 << 40)),
        sub(10, 1, struct.pack('>I', 3600)),
        sub(11, 1, b'opaque!!'),
        sub(17, 1, struct.pack('>I', 0x77)),
        sub(21, 1, b'user@example'),
        sub(22, 1, struct.pack('>I', 0x5151)),
        sub(19, 1, struct.pack('>I', 0xcafe)),
        sub(20, 1, struct.pack('>I', 0)),
    ]), False)
    # C4 Gate-Set-Ack in a signaled ClientSI: transaction, AMID,
    #    subscriber, gate ID, gate state, version info, gate time info,
    #    gate usage info, synch options; answers C3
    c.send(cops(RPT, MM, [handle(0x301), obj(12, 1, struct.pack('>HH', 1, 0)),
                          obj(9, 1, b''.join([
                              sub(1, 1, struct.pack('>HH', 0x0101, 5)),
                              sub(2, 1, struct.pack('>HH', 1, 2)),
                              sub(3, 1, a4('198.51.100.10')),
                              sub(4, 1, struct.pack('>I', 0xabcd0001)),
                              sub(15, 1, struct.pack('>HH', 2, 65535)),
                              sub(16, 1, struct.pack('>HH', 5, 0)),
                              sub(12, 1, struct.pack('>I', 120)),
                              sub(13, 1, struct.pack('>Q', 123456789)),
                              sub(18, 1, struct.pack('>HBB', 0, 1, 1)),
                          ]))], SOL))
    # C5 Gate-Set-Err: three PacketCable errors (missing object, invalid
    #    object, other)
    c.send(cops(RPT, MM, [handle(0x302), obj(12, 1, struct.pack('>HH', 2, 0)),
                          obj(9, 1, b''.join([
                              sub(1, 1, struct.pack('>HH', 0x0102, 6)),
                              sub(14, 1, struct.pack('>HH', 6, 0x0601)),
                              sub(14, 1, struct.pack('>HH', 7, 0x0701)),
                              sub(14, 1, struct.pack('>HH', 13, 0)),
                          ]))], SOL))
    # C6 flow specs with one, two and three envelopes, DOCSIS service
    #    class name, upstream drop, an unknown gate command
    c.send(mmdec(0x303, [
        sub(1, 1, struct.pack('>HH', 0x0103, 99)),
        sub_len(7, 1, 36), sub_len(7, 1, 64), sub_len(7, 1, 92),
        sub(7, 2, struct.pack('>B3x', 7) + b'SCN_A\0\0\0'),
        sub(7, 9, struct.pack('>B3x', 1)),
    ]), False)
    # C7-C12 traffic profiles: I03, I04 and I05 layouts (told apart by
    #    length) with one, two and three envelopes
    #    The two envelope I05 lengths of best effort, UGS-AD and
    #    downstream, the two envelope UGS lengths and every I04 downstream
    #    length make the dissector read past the object; they are in the
    #    malformed capture.
    profiles = [
        (3, [32, 56, 84], [40, 72, 104], [44, 116]),        # best effort
        (4, [36, 64, 92], [44, 80, 116], [48, 88, 128]),    # NRTPS
        (5, [36, 64, 92], [44, 80, 116], [48, 88, 128]),    # RTPS
        (6, [24, 40, 60], [32, 80], [36, 92]),              # UGS
        (7, [32, 56, 84], [40, 72, 104], [44, 116]),        # UGS-AD
        (8, [32, 56, 80], [], [48, 128]),                   # downstream
    ]
    for k, (stype, i03, i04, i05) in enumerate(profiles):
        subs = [sub(1, 1, struct.pack('>HH', 0x0110 + k, 4))]
        for ln in i03 + i04 + i05:
            subs.append(sub_len(7, stype, ln, 0x20 + ln))
        c.send(mmdec(0x310 + k, subs), False)
    # C13 Synch Request, Gate Report State, Message Receipt
    c.send(mmdec(0x320, [sub(1, 1, struct.pack('>HH', 0x0120, 20)),
                         sub(18, 1, struct.pack('>HBB', 0, 0, 0))]), False)
    c.send(cops(RPT, MM, [handle(0x320), obj(12, 1, struct.pack('>HH', 3, 0)),
                          obj(9, 1, sub(1, 1, struct.pack('>HH', 0x0121, 15)) +
                              sub(15, 1, struct.pack('>HH', 1, 13)))], SOL))

    # --- Conversation D: PacketCable D-QoS (0x8008), port 2126 ---
    d = Conn(cap, 40003, 2126)
    DQ = 0x8008
    d.send(cops(OPN, DQ, [pepid(b'cmts-dqos\0')]))
    d.send(cops(CAT, DQ, [obj(10, 1, struct.pack('>HH', 0, 0))]), False)
    # D3 Gate-Set: transaction, subscriber IPv4 and IPv6, gate ID,
    #    activity count, gate spec, remote gate info, event generation
    #    info, electronic surveillance, a media connection event info
    #    (not decoded)
    d.send(cops(DEC, DQ, [handle(0x401), context(8, 0), decision(1, 0),
                          obj(6, 4, b''.join([
                              sub(1, 1, struct.pack('>HH', 0x0201, 4)),
                              sub(2, 1, a4('198.51.100.20')),
                              sub(2, 2, a6('2001:db8::200')),
                              sub(3, 1, struct.pack('>I', 0x1234)),
                              sub(4, 1, struct.pack('>I', 2)),
                              sub(5, 1, struct.pack('>BBBB4s4sHHB3xHHHH', 1, 17, 0, 1,
                                                    a4('198.51.100.20'), a4('203.0.113.9'),
                                                    5004, 5006, 0xb8, 200, 0, 30, 10) +
                                  struct.pack('>7I', 8000, 160, 8000, 160, 1500, 8000, 0)),
                              sub(6, 1, a4('203.0.113.1') + struct.pack('>HHIH', 2126, 0, 0x5678, 100) +
                                  b'\0' * 4 + bytes(range(16)) + b'\0\0'),
                              sub(7, 1, a4('203.0.113.50') + struct.pack('>HBB', 1813, 0, 0) +
                                  a4('203.0.113.51') + struct.pack('>HBBI', 1813, 1, 0, 1700000000) +
                                  b'elem0002' + b'+1000000' + struct.pack('>I', 43)),
                              sub(10, 1, a4('203.0.113.60') + struct.pack('>HH', 9000, 1) +
                                  a4('203.0.113.61') + struct.pack('>HHII', 9001, 0, 0x99, 1700000001) +
                                  b'elem0003' + b'+1000000' + struct.pack('>I', 44)),
                              sub(8, 1, b'\0' * 4),
                          ]))]), False)
    # D4 Gate-Set-Ack in a signaled ClientSI, answers D3
    d.send(cops(RPT, DQ, [handle(0x401), obj(12, 1, struct.pack('>HH', 1, 0)),
                          obj(9, 1, sub(1, 1, struct.pack('>HH', 0x0201, 5)) +
                              sub(3, 1, struct.pack('>I', 0x1234)) +
                              sub(4, 1, struct.pack('>I', 2)))], SOL))
    # D5 Gate-Set-Err with a PacketCable error, D6 Gate-Close with
    #    reasons (delete and close sub-codes), an unknown command
    d.send(cops(RPT, DQ, [handle(0x402), obj(12, 1, struct.pack('>HH', 2, 0)),
                          obj(9, 1, sub(1, 1, struct.pack('>HH', 0x0202, 6)) +
                              sub(9, 1, struct.pack('>HH', 2, 0)))], SOL))
    d.send(cops(RPT, DQ, [handle(0x403), obj(12, 1, struct.pack('>HH', 3, 0)),
                          obj(9, 1, sub(1, 1, struct.pack('>HH', 0x0203, 14)) +
                              sub(3, 1, struct.pack('>I', 0x1234)) +
                              sub(13, 1, struct.pack('>HH', 0, 3)) +
                              sub(13, 1, struct.pack('>HH', 1, 5)))], SOL))
    d.send(cops(DEC, DQ, [handle(0x404), decision(1, 0),
                          obj(6, 4, sub(1, 1, struct.pack('>HH', 0x0204, 99)))]), False)


# ---- malformed capture ----------------------------------------------------

def malformed_capture(cap):
    a = Conn(cap, 41000, 3288)
    # 1: object length 2 (< 4)
    a.send(cops(REQ, 1, [handle(0x501), struct.pack('>HBB', 2, 2, 1)]))
    # 2: COPS-PR object length 2
    a.send(cops(DEC, 2, [handle(0x502), obj(6, 5, struct.pack('>HBB', 2, 1, 1) + b'\0' * 4)], SOL), False)
    # 3: PRID with a BER length past the end
    a.send(cops(DEC, 2, [handle(0x503), obj(6, 5, probj(1, 1, b'\x06\x84\x7f\xff\xff\xff'))], SOL), False)
    # 4: IN-Int object without its contents
    a.send(cops(REQ, 1, [handle(0x504), obj(3, 1, b'')]))
    # 5: message length 4 (shorter than the header)
    a.send(cops(KA, 1, [], length=4))
    # 6: PEP ID without a terminating NUL (a note in the malformed group)
    a.send(cops(OPN, 1, [pepid(b'no-nul')]))
    c = Conn(cap, 41001, 3918)
    MM = 0x800a
    # 7: PacketCable MM sub-object length 2
    c.send(cops(DEC, MM, [handle(0x601), obj(6, 4, struct.pack('>HBB', 2, 1, 1) + b'\0' * 4)]), False)
    # 8: DOCSIS service class name of length 8 (< 12)
    c.send(cops(DEC, MM, [handle(0x602), obj(6, 4, sub(7, 2, b'\x07\0\0\0'))]), False)
    # 9-11: I04 downstream service, lengths 40, 72, 104: the dissector
    #       reads the I05 layout (with the peak rate) past the object
    for k, ln in enumerate((40, 72, 104)):
        c.send(cops(DEC, MM, [handle(0x603 + k), obj(6, 4, sub_len(7, 8, ln))]), False)
    # 12-16: traffic profiles whose length selects too many envelopes:
    #        I05 best effort 80, I04 and I05 UGS 56 and 64, I05 UGS-AD
    #        80, I05 downstream 88
    for k, (stype, ln) in enumerate(((3, 80), (6, 56), (6, 64), (7, 80), (8, 88))):
        c.send(cops(DEC, MM, [handle(0x610 + k), obj(6, 4, sub_len(7, stype, ln))]), False)
    # 17: a gate spec sub-object of 8 octets: the analysis stops at the
    #     end of the COPS object, before the Error object
    c.send(cops(DEC, MM, [handle(0x606), obj(6, 4, sub(5, 1, b'\0' * 4)),
                          obj(8, 1, struct.pack('>HH', 1, 0))]), False)
    d = Conn(cap, 41002, 2126)
    # 18: PacketCable D-QoS sub-object length 2
    d.send(cops(DEC, 0x8008, [handle(0x701), obj(6, 4, struct.pack('>HBB', 2, 1, 1) + b'\0' * 4)]), False)
    # 19: an object longer than the message
    d.send(cops(DEC, 0x8008, [handle(0x702), struct.pack('>HBB', 200, 6, 4) + b'\0' * 8]), False)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Capture()
    main_capture(cap)
    cap.write(os.path.join(out, 'cops-coverage.pcap'))
    cap = Capture()
    malformed_capture(cap)
    cap.write(os.path.join(out, 'cops-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

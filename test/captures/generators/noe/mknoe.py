#!/usr/bin/env python3
# Generates test/captures/noe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NOE dissector
(packet-noe.c, the Alcatel-Lucent NOE protocol of the UA3G opcodes 0x15
and 0x16).

NOE is reached through UA (opcodes 0x15 and 0x16), which UA/UDP carries
in Data packets on UDP ports 32000-32512 (registered by default). The
terminal sends from port 32000 (terminal to system) and the system from
port 40000 to it. Every packet is built from scratch with struct.

Usage: mknoe.py <output directory>

  noe-coverage.pcap            valid UA/UDP data packets: every method,
                               every event, TLV properties of every
                               length, every utf8 and boolean property
  noe-coverage-malformed.pcap  truncated messages, wrong lengths, an
                               Exported PDU naming "noe"
"""
import os
import struct
import sys

T0 = 1700000000

UTF8_PROPS = [(4, 124), (4, 156), (4, 157), (4, 158), (4, 159), (4, 160), (7, 147), (7, 148), (8, 138), (8, 133), (9, 30), (9, 33), (12, 142), (12, 143), (129, 138), (129, 133), (130, 138), (130, 133), (131, 138), (131, 133), (132, 55), (132, 72), (132, 121), (133, 55), (133, 56), (134, 55), (134, 56), (134, 59), (134, 72), (135, 55), (136, 63), (137, 55), (137, 63), (139, 55), (139, 145), (139, 146), (140, 55), (141, 55), (142, 114), (147, 138), (151, 55), (152, 30), (152, 33), (152, 87), (153, 55), (154, 142)]
BOOL_PROPS = [(1, 4), (1, 95), (1, 96), (1, 117), (1, 122), (3, 29), (3, 60), (5, 16), (6, 40), (6, 21), (8, 108), (8, 140), (9, 113), (9, 97), (12, 29), (128, 40), (128, 91), (128, 94), (129, 40), (130, 40), (130, 48), (130, 49), (130, 90), (130, 107), (131, 40), (132, 40), (133, 40), (134, 40), (134, 29), (134, 57), (134, 61), (134, 106), (135, 40), (135, 29), (135, 62), (136, 40), (137, 40), (138, 40), (138, 80), (139, 40), (139, 80), (140, 40), (141, 40), (142, 40), (143, 40), (144, 40), (145, 40), (145, 29), (147, 108), (147, 109), (148, 108), (149, 108), (151, 61), (152, 29), (152, 85), (153, 40), (154, 29), (154, 40), (154, 134), (154, 141), (154, 140)]


CLASSES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 128, 129, 130, 131, 132, 133, 134, 135, 136,
           137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
           153, 154)
EVENTS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
          24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 128, 129, 130, 131, 132, 133, 134, 135,
          136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
          153, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_pkt(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(payload), 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
    return eth + ip + udp + payload


TERM = bytes([192, 0, 2, 10])
SYS = bytes([192, 0, 2, 20])


def write(path, pkts, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', T0 + i, 0, len(p), len(p)))
            f.write(p)


class Session:
    """UA/UDP data packets between a terminal (port 32000) and the system."""

    def __init__(self, out):
        self.out = out
        self.seq = [0, 0]

    def connect(self):
        tlvs = b''.join(bytes([t, len(v)]) + v for t, v in
                        ((1, b'\x03'), (2, b'\x08'), (3, b'\x05\xdc'), (4, b'\x0a'), (5, b'\x01'),
                         (6, b'\x1e'), (7, b'\xb8'), (8, b'\x00\x64'), (9, b'\x05'), (10, b'\x01')))
        self.out.append(udp_pkt(TERM, SYS, 32000, 40000, b'\x00' + tlvs))

    def send(self, msgs, from_term):
        """One datagram holding the given UA messages."""
        i = 0 if from_term else 1
        payload = b'\x07' + struct.pack('>HH', self.seq[1 - i], self.seq[i]) + b''.join(msgs)
        self.seq[i] += 1
        if from_term:
            self.out.append(udp_pkt(TERM, SYS, 32000, 40000, payload))
        else:
            self.out.append(udp_pkt(SYS, TERM, 40000, 32000, payload))


def msg(server, method, body, ack=False):
    """A UA message that holds a NOE message: length (little endian),
    opcode (the NOE server), method (bit 7 is the acknowledge flag)."""
    p = bytes([server, (0x80 if ack else 0) | method]) + body
    return struct.pack('<H', len(p)) + p


def tlv(code, value, aidx=0, long=False):
    out = bytes([code])
    if code >= 128:
        out += bytes([aidx])
    if long or len(value) >= 128:
        out += struct.pack('>H', 0x8000 | len(value))
    else:
        out += bytes([len(value)])
    return out + value


def obj(cls, oid=1):
    """Class and, for dynamic classes, the object id."""
    return bytes([cls]) + (struct.pack('>H', oid) if cls >= 128 else b'')


def notify(event, body, server=0x15):
    return msg(server, 4, bytes([event]) + body)


def utf8(cp):
    """UTF-8 of a code point, with the old five and six octet forms."""
    if cp < 0x80:
        return bytes([cp])
    n = 2
    while cp >= 1 << (6 * (n - 1) + (7 - n)):
        n += 1
    out = bytearray()
    for _ in range(n - 1):
        out.insert(0, 0x80 | (cp & 0x3f))
        cp >>= 6
    out.insert(0, ((0xff << (8 - n)) & 0xff) | cp)
    return bytes(out)


def build_main():
    p = []
    s = Session(p)
    s.connect()
    # Every method with the call server (0x15) and the presentation server
    # (0x16), acknowledged and not
    s.send([msg(0x15, 0, obj(1) + tlv(5, b'\x02'))], True)                     # create, static class
    s.send([msg(0x16, 0, obj(133, 7) + tlv(55, b'OK'), True)], False)         # create ActionBox
    s.send([msg(0x15, 1, obj(133, 7))], True)                                   # delete
    s.send([msg(0x15, 1, obj(133, 7), True)], False)
    s.send([msg(0x15, 2, obj(131, 9) + tlv(133, b'a label', 0))], True)       # set property, array
    s.send([msg(0x15, 3, obj(1) + bytes([5, 6, 8]))], True)                    # get property
    s.send([msg(0x15, 3, obj(130, 4) + bytes([130, 2, 5]), True)], True)       # with array index
    s.send([msg(0x15, 5, obj(130, 4) + bytes([3]))], True)                      # delete item
    s.send([msg(0x15, 6, obj(130, 4) + bytes([0]) + tlv(130, b'item', 0))], True)   # insert item
    s.send([msg(0x15, 6, obj(130, 4) + bytes([1]))], True)                      # insert item without body
    s.send([msg(0x15, 7, b'\x00')], True)                                       # invalid method
    s.send([msg(0x15, 127, b'\x00\x01')], True)
    # Several messages in one datagram
    s.send([msg(0x15, 2, obj(1) + tlv(5, b'\x01')), msg(0x15, 1, obj(128, 3)),
            notify(2, utf8(0x41))], True)
    # Every class with a Create and a SetProperty of one property, empty
    # and one-octet bodies
    for c in CLASSES:
        s.send([msg(0x15, 0, obj(c, 100 + c) + tlv(5, b'\x01'))], True)
        s.send([msg(0x15, 2, obj(c, 100 + c) + tlv(18, b'\x00\x20'))], False)
    for c in (11, 13, 127, 155, 200, 255):                                      # unknown classes
        s.send([msg(0x15, 2, obj(c, 5) + tlv(5, b'\x01'))], True)
    s.send([msg(0x15, 0, obj(1))], True)                                        # no body
    s.send([msg(0x15, 0, obj(133, 7))], True)
    # Property lengths 0 to 6, long lengths (two octet), array properties
    for n in range(0, 7):
        s.send([msg(0x15, 2, obj(1) + tlv(46, bytes(range(1, n + 1))))], True)
    s.send([msg(0x15, 2, obj(1) + tlv(69, bytes(range(200)), long=True))], True)
    s.send([msg(0x15, 2, obj(1) + tlv(69, bytes(range(30)), long=True))], True)
    s.send([msg(0x15, 2, obj(1) + tlv(131, b'\x01\x02\x03', aidx=4) + tlv(132, b'\x07', aidx=255))], True)
    s.send([msg(0x15, 2, obj(1) + tlv(5, b'\x01') + tlv(6, b'\x02\x03') + tlv(7, b'\x01\x02\x03')
                + tlv(8, b'\x01\x02\x03\x04') + tlv(9, b'abcdefgh'))], True)
    # Every utf8 property (a string) and every boolean property (one octet)
    for c, code in UTF8_PROPS:
        s.send([msg(0x15, 2, obj(c, 11) + tlv(code, b'text ' + bytes([65 + code % 26]) * 3, aidx=2))], True)
    s.send([msg(0x15, 2, obj(1) + tlv(114, b'', ))], True)
    s.send([msg(0x15, 2, obj(142, 5) + tlv(114, b'http://example.test/' + b'x' * 130))], True)
    for c, code in BOOL_PROPS:
        s.send([msg(0x15, 2, obj(c, 12) + tlv(code, b'\x01', aidx=1))], False)
    # Notifications (events) of every kind; the key events with UTF-8
    # values of one to six octets
    for ev in EVENTS:
        if ev in (2, 3, 4, 5, 8, 25, 26, 27):
            body = b'\x41'
        elif ev in (10, 11, 12, 13, 14):
            body = (struct.pack('>H', 3) + bytes([2, 134]) + struct.pack('>HBBH', 9, 69, 1, 5)
                    + struct.pack('>I', 77) + b'error text')
        elif ev == 0:
            body = b'\x02'
        elif ev == 28:
            body = b'\x01\x00\x05'
        elif ev in (6, 7, 22):
            body = b'\x03'
        elif ev == 21:
            body = b'\x01\x01'
        elif ev in (15, 16, 17, 20, 23):
            body = struct.pack('>H', 321)
        elif ev == 9:
            body = struct.pack('>I', 1234)
        elif ev == 24:
            body = struct.pack('>HBH', 9, 1, 0x0102)
        else:
            body = struct.pack('>H', 9) + tlv(56, b'\x05') + tlv(5, b'abc')
        s.send([notify(ev, body, 0x15 if ev % 2 == 0 else 0x16)], True)
    for ev in (36, 100, 157, 165, 255):                                         # unknown events
        s.send([notify(ev, struct.pack('>H', 9) + tlv(56, b'\x05'))], True)
    s.send([notify(100, struct.pack('>H', 9))], True)                          # no TLV after the object id
    # Key events: values (UTF-8 encoded) for the key names, one to six
    # octets, control characters, named keys, plain characters and
    # unnamed ones
    for ev in (2, 3, 4, 5, 8):
        for cp in (0x00, 0x01, 0x0d, 0x1f, 0x20, 0x7f, 0xe0, 0xe7, 0xe8, 0xe9, 0xf9):
            s.send([notify(ev, utf8(cp) if cp < 0x80 else utf8(cp))], True)
            if ev != 2:
                break
    for cp in (0x41, 0x7e, 0xa0, 0xff, 0x100, 0x7ff, 0x20ac, 0xe100, 0xe101, 0xe110, 0xe139, 0xe13a,
               0xffff, 0x10000, 0x1f600, 0x1fffff, 0x200000, 0x3ffffff, 0x4000000, 0x7fffffff):
        s.send([notify(2, utf8(cp))], True)
    # five and six octet sequences (obsolete UTF-8 forms) and more octets
    s.send([notify(3, bytes([0xf8, 0x88, 0x80, 0x80, 0x80]))], True)
    s.send([notify(3, bytes([0xfc, 0x84, 0x80, 0x80, 0x80, 0x80]))], True)
    s.send([notify(3, bytes([0xfc, 0x84, 0x80, 0x80, 0x80, 0x80, 0x80]))], True)
    s.send([notify(2, b'')], True)
    # bytes after an event that needs fewer
    s.send([notify(0, b'\x01\x02\x03\x04')], True)
    s.send([notify(1, struct.pack('>H', 3))], True)
    return p


def build_malformed():
    p = []
    s = Session(p)
    s.connect()
    # Truncated messages: every method and event with too little data
    s.send([struct.pack('<H', 1) + b'\x15'], True)                              # no method
    s.send([struct.pack('<H', 2) + b'\x15\x00'], True)                          # create, no class
    s.send([msg(0x15, 0, bytes([133, 0]))], True)                                # class needs an object id
    s.send([msg(0x15, 2, obj(1) + b'\x05')], True)                              # property without length
    s.send([msg(0x15, 2, obj(1) + b'\x05\x04\x01')], True)                     # value shorter than its length
    s.send([msg(0x15, 2, obj(1) + b'\x83')], True)                              # array property, no index
    s.send([msg(0x15, 2, obj(1) + b'\x05\x81')], True)                          # two octet length cut
    s.send([msg(0x15, 2, obj(1) + b'\x05\xff\xff' + b'x' * 4)], True)         # length 32767
    s.send([msg(0x15, 2, obj(1) + b'\x05\x02ab' + b'\x06')], True)
    s.send([msg(0x15, 3, obj(1) + b'\x83')], True)                              # get property: no array index
    s.send([msg(0x15, 5, obj(130, 4))], True)                                    # delete item, no index
    s.send([msg(0x15, 6, obj(130, 4))], True)                                    # insert item, no index
    s.send([msg(0x15, 1, b'')], True)
    s.send([msg(0x15, 6, obj(130, 4) + b'\x00' + b'\x05\x03x')], True)
    for ev in (0, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 128):
        s.send([notify(ev, b'')], True)
        s.send([notify(ev, b'\x01')], True)
    s.send([notify(10, b'\x00\x01\x02')], True)                                # error event, short
    s.send([notify(10, b'\x00' * 13)], True)
    s.send([notify(24, b'\x00\x01\x02')], True)
    s.send([notify(28, b'\x01')], True)
    s.send([notify(9, b'\x01\x02')], True)
    s.send([notify(128, b'\x00\x01\x05\x04x')], True)                         # TLV cut
    s.send([notify(128, b'\x00')], True)
    # UA message length larger than the datagram, length zero
    s.send([struct.pack('<H', 400) + b'\x15\x02\x01\x05\x01\x01'], True)
    s.send([struct.pack('<H', 0) + b'\x15'], True)
    s.send([struct.pack('<H', 1) + b'\x16'], False)
    # UA/UDP data packets that only hold the header
    p.append(udp_pkt(TERM, SYS, 32000, 40000, b'\x07\x00\x00\x00'))
    return p


def exported_pdu_frames():
    n = b'noe\0'
    hdr = struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0)
    out = []
    for payload in (
            msg(0x15, 2, obj(1) + tlv(5, b'\x01')),                              # a complete message
            msg(0x17, 2, obj(1) + tlv(5, b'\x01')),                              # unknown server
            msg(0x16, 4, bytes([2]) + b'\x41'),
            struct.pack('<H', 1) + b'\x15',                                     # truncated
            b'\x00'):
        out.append(hdr + payload)
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    write(os.path.join(out, 'noe-coverage.pcap'), build_main())
    # the malformed capture: UDP frames, then Exported PDUs (link type 252
    # cannot share a pcap with Ethernet, so they go to their own file)
    write(os.path.join(out, 'noe-coverage-malformed.pcap'), build_malformed())
    write(os.path.join(out, 'noe-coverage-exported.pcap'), exported_pdu_frames(), linktype=252)


main()

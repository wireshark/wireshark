#!/usr/bin/env python3
# Generates test/captures/extreme_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Extreme Discovery Protocol
dissector (packet-extreme.c: EDP, ESRP, EAPS, ESL, ELSM, ELRP).

EDP runs in 802.3 frames to 00:e0:2b:00:00:00 with an LLC SNAP header
(OUI 00:e0:2b, PID 0x00bb), registered by default through the LLC OUI
table. Every packet is built with struct; nothing comes from a real
network.

Usage: mkextreme.py <output directory>
  extreme-coverage.pcap            valid EDP frames, good checksums
  extreme-coverage-malformed.pcap  short fixed size TLVs (the fixed bug),
                                   bad checksums, bad TLV lengths
"""
import os
import struct
import sys

DST = bytes.fromhex('00e02b000000')
SRC = bytes.fromhex('02aabbccdd01')


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def cksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def tlv(typ, body, length=None, marker=0x99):
    if length is None:
        length = 4 + len(body)
    return struct.pack('>BBH', marker, typ, length) + body


def edp(tlvs, seq=1, mac=None, data_length=None, ck=None, trail=b'', pad=True,
        version=1, midtype=0):
    mac = mac or SRC
    body = b''.join(tlvs)
    if data_length is None:
        data_length = 16 + len(body)
    hdr = struct.pack('>BBHHH', version, 0, data_length, 0, seq) + \
        struct.pack('>H', midtype) + mac
    pdu = hdr + body
    if ck is None:
        ck = cksum(pdu[:data_length])
    pdu = pdu[:4] + struct.pack('>H', ck) + pdu[6:] + trail
    llc = bytes.fromhex('aaaa03' '00e02b' '00bb')
    payload = llc + pdu
    fr = DST + SRC + struct.pack('>H', len(payload)) + payload
    if pad and len(fr) < 60:
        fr += b'\0' * (60 - len(fr))
    return fr


NULL = tlv(0, b'')


def display(s):
    return tlv(1, s)


def info(slot=0, port=2, vch=0xffff, ver=(12, 3, 1, 4), conn=b''):
    return tlv(2, struct.pack('>HHH', slot, port, vch) + bytes(6) +
               bytes(ver) + (conn or bytes(range(16))))


def vlan(flags=0x80, vid=100, ip='10.1.2.3', name=b'Default', res1=0):
    return tlv(5, struct.pack('>BBH', flags, res1, vid) + bytes(4) +
               bytes(int(x) for x in ip.split('.')) + name)


def esrp(proto=0, group=1, prio=100, state=1, ports=4, vip='192.168.0.1',
         mac=SRC, hello=2, res=0):
    return tlv(8, struct.pack('>BBHHH', proto, group, prio, state, ports) +
               bytes(int(x) for x in vip.split('.')) + mac +
               struct.pack('>HH', hello, res))


def eaps(ver=1, typ=5, vid=4000, mac=SRC, hello=1, fail=3, state=0, hseq=7):
    return tlv(0x0b, struct.pack('>BBH', ver, typ, vid) + bytes(4) + mac +
               struct.pack('>HHBBH', hello, fail, state, 0, hseq) + bytes(38))


def esl(ver=1, typ=1, vid=4001, mac=SRC, state=1, role=1, l1=5, f1=0, f2=1,
        l2=6, links=(1, 2, 3), numlinks=None, extra=b''):
    if numlinks is None:
        numlinks = len(links)
    return tlv(0x0e, struct.pack('>BBH', ver, typ, vid) + bytes(4) + mac +
               bytes(4) + struct.pack('>BBHHH', state, role, l1, f1, f2) +
               bytes(2) + struct.pack('>H', l2) + bytes(2) +
               struct.pack('>H', numlinks) +
               b''.join(struct.pack('>H', x) for x in links) + extra)


def elsm(typ=1, sub=0, magic=b'\x12\x34'):
    return tlv(0x0f, bytes([typ, sub]) + magic)


def elrp(body=b'\x01\x02\x03\x04\x05\x06\x07\x08'):
    return tlv(0x0d, body)


def link(body=bytes([0xc8, 3, 2, 0])):
    return tlv(0x15, body)


def unknown(typ=0x77, body=b'unknown data'):
    return tlv(typ, body)


main = [
    # 1: typical switch advertisement
    edp([display(b'Summit X450a-24t'), info(), vlan(), vlan(0x01, 0, '0.0.0.0', b''),
         NULL], seq=1),
    # 2: display string with an escape, VLAN flags, long name
    edp([display(b'switch\x01"1"\n'), vlan(0xff, 4094, '255.255.255.255',
                                         b'a-very-long-vlan-name-0123456789'), NULL], seq=2),
    # 3: info with another slot and port, version
    edp([info(3, 47, 0x0102, (15, 4, 0, 0)), NULL], seq=3),
    # 4-6: ESRP IP, IPX, L2, states
    edp([esrp(0, 1, 100, 1), NULL], seq=4),
    edp([esrp(1, 2, 200, 2, 0, '0.0.0.0', hello=5, res=9), NULL], seq=5),
    edp([esrp(2, 3, 255, 0), NULL], seq=6),
    # 7-10: EAPS types and states
    edp([eaps(typ=5, state=0), NULL], seq=7),
    edp([eaps(typ=6, state=1), NULL], seq=8),
    edp([eaps(typ=7, state=2), NULL], seq=9),
    edp([eaps(typ=8, state=3), eaps(typ=9, state=4), eaps(state=5), eaps(state=9),
         NULL], seq=10),
    # 11-14: ESL, link lists, roles and states
    edp([esl(), NULL], seq=11),
    edp([esl(role=2, state=2, links=()), NULL], seq=12),
    edp([esl(role=3, state=3, typ=2, links=(7,), numlinks=1, extra=b'\xde\xad'), NULL],
        seq=13),
    # numlinks larger than the data present, odd rest
    edp([esl(links=(1, 2), numlinks=10, extra=b'\x55'), NULL], seq=14),
    # numlinks smaller than the data present (rest shown)
    edp([esl(links=(1, 2, 3, 4), numlinks=1), NULL], seq=15),
    # 16-18: ELSM
    edp([elsm(1, 0), NULL], seq=16),
    edp([elsm(1, 1), NULL], seq=17),
    edp([elsm(9, 7, b'\0\0'), NULL], seq=18),
    # ELSM longer than its fixed part
    edp([tlv(0x0f, b'\x01\x01\xaa\xbb\xcc\xdd'), NULL], seq=19),
    # 20: ELRP
    edp([elrp(), NULL], seq=20),
    edp([elrp(b''), NULL], seq=21),
    # 22-25: link properties with 4 octets (all flag combinations) and others
    edp([link(), NULL], seq=22),
    edp([link(bytes([0x08, 0, 1, 0])), NULL], seq=23),
    edp([link(bytes([0x47, 1, 0, 0])), NULL], seq=24),
    edp([link(b'\x01\x02'), link(b'\x01\x02\x03\x04\x05\x06'), link(b''), NULL], seq=25),
    # 26: unknown TLVs
    edp([unknown(), unknown(0x03, b''), unknown(0x30, b'x' * 40), NULL], seq=26),
    # 27: all in one
    edp([display(b'all'), info(), vlan(), esrp(), eaps(), esl(), elsm(), elrp(),
         link(), unknown(), NULL], seq=27),
    # 28: TLVs after the NULL TLV are ignored
    edp([display(b'x'), NULL, display(b'ignored')], seq=28),
    # 29: no NULL TLV, header only
    edp([], seq=29),
    # 30: no NULL TLV; data length equal to the TLVs
    edp([display(b'no end'), vlan()], seq=30),
    # 31: data length shorter than the captured data (trailer ignored)
    edp([display(b'trailer'), NULL], seq=31, trail=b'\xaa' * 8),
    # 32: data length larger than the frame: checksum is not verified; the
    # NULL TLV ends the loop before the missing data is touched
    edp([display(b'short'), NULL], seq=32, data_length=200, ck=0x1234),
    # 33: machine id type not zero, other version
    edp([display(b'v2'), NULL], seq=33, midtype=0x0102, version=2),
    # 34: TLV with a marker other than 0x99
    edp([tlv(1, b'marker', marker=0x55), NULL], seq=34),
    # 35: VLAN TLV with exactly the fields and an empty name, and with 1 byte
    edp([vlan(name=b''), NULL], seq=35),
]

malformed = [
    # fixed size TLVs shorter than their fixed part (the fix)
    edp([tlv(2, b'\0' * 8), NULL]),                    # INFO, 12 of 40
    edp([tlv(2, b''), NULL]),                          # INFO, length 4
    edp([tlv(8, b'\0' * 10), NULL]),                   # ESRP
    edp([tlv(0x0b, b'\0' * 20), NULL]),                # EAPS
    edp([tlv(0x0e, b'\0' * 12), tlv(0x0e, b'\0' * 6), NULL]),   # ESL, as in the report
    edp([tlv(0x0e, b'\0' * 33), NULL]),                # ESL just below
    edp([tlv(0x0f, b'\x01'), NULL]),                   # ELSM
    # the reproducer shape: short ESL as the last TLV with nothing behind
    edp([tlv(0x0e, b'\0' * 4)], pad=False),
    # VLAN TLV cut at each field
    edp([tlv(5, b''), NULL]),
    edp([tlv(5, b'\x80'), NULL]),
    edp([tlv(5, b'\x80\x00\x00'), NULL]),
    edp([tlv(5, b'\x80\x00\x00\x64\0\0'), NULL]),
    edp([tlv(5, b'\x80\x00\x00\x64\0\0\0\0\x0a\x00'), NULL]),
    # bad checksum
    edp([display(b'bad checksum'), NULL], ck=0xdead),
    # TLV length below 4, above the data, and fewer than 4 bytes left
    edp([tlv(1, b'abcd', length=3), NULL]),
    edp([tlv(1, b'abcd', length=0x2000), NULL]),
    edp([display(b'x'), b'\x99\x00\x00'], data_length=16 + 5 + 3, trail=b'\0' * 4),
    # data length smaller than the header
    edp([display(b'x'), NULL], data_length=6),
    # truncated frame: data length beyond the captured data, no NULL TLV
    edp([display(b'x' * 20), vlan()], data_length=120, ck=0),
]

if __name__ == '__main__':
    out = sys.argv[1]
    pcap(os.path.join(out, 'extreme-coverage.pcap'), main)
    pcap(os.path.join(out, 'extreme-coverage-malformed.pcap'), malformed)

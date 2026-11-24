#!/usr/bin/env python3
# Generates test/captures/packetbb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PacketBB (RFC 5444) coverage captures. Usage: mkpacketbb.py <outdir> [-v]
# PacketBB is registered on UDP port 269 (default), so no Decode As is needed.
import os
import struct
import sys
from pcaplib import udp, write_pcap

def tlv(ttype, value=b'', typeext=None, index=None, multiindex=None, extlen=False, multivalue=False, force_value=None):
    flags = 0
    body = b''
    if typeext is not None:
        flags |= 0x80; body += bytes([typeext])
    if index is not None:
        flags |= 0x40; body += bytes([index])
    elif multiindex is not None:
        flags |= 0x20; body += bytes(multiindex)
    if value or force_value:
        flags |= 0x10
        if extlen:
            flags |= 0x08; body += struct.pack('>H', len(value))
        else:
            body += bytes([len(value)])
        if multivalue:
            flags |= 0x04
    return bytes([ttype, flags]) + body + value

def tlvblock(*tlvs):
    b = b''.join(tlvs)
    return struct.pack('>H', len(b)) + b

def addrblock(num, mids, head=b'', tail=b'', zerotail=0, prelens=None, size=4, tlvs=()):
    flags = 0
    b = bytes([num])
    if head:
        flags |= 0x80
    if tail:
        flags |= 0x40
    elif zerotail:
        flags |= 0x20
    if prelens is not None:
        flags |= 0x10 if len(prelens) == 1 else 0x08
    b += bytes([flags])
    if head:
        b += bytes([len(head)]) + head
    if tail:
        b += bytes([len(tail)]) + tail
    elif zerotail:
        b += bytes([zerotail])
    b += mids
    if prelens is not None:
        b += bytes(prelens)
    return b + tlvblock(*tlvs)

def message(mtype, addrsize, body, orig=None, hoplimit=None, hopcount=None, seq=None, length=None):
    flags = (addrsize - 1) & 0x0f
    hdr = b''
    if orig is not None:
        flags |= 0x80; hdr += orig
    if hoplimit is not None:
        flags |= 0x40; hdr += bytes([hoplimit])
    if hopcount is not None:
        flags |= 0x20; hdr += bytes([hopcount])
    if seq is not None:
        flags |= 0x10; hdr += struct.pack('>H', seq)
    total = 4 + len(hdr) + len(body)
    return struct.pack('>BBH', mtype, flags, total if length is None else length) + hdr + body

def packet(msgs=(), seq=None, tlvs=None):
    flags = 0
    h = b''
    if seq is not None:
        flags |= 0x08; h += struct.pack('>H', seq)
    if tlvs is not None:
        flags |= 0x04; h += tlvblock(*tlvs)
    return bytes([flags]) + h + b''.join(msgs)

def ip4(a): return bytes(int(x) for x in a.split('.'))
def ip6(n): return bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [n])

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    def add(p): F.append(udp(269, 269, p))
    mark('reproducer: 128 addresses, a TLV with a single index (value 0x42 was read from the wrong octet)')
    n = 128
    t = tlv(1, b'\x42', index=5)
    add(packet([message(0, 4, tlvblock() + addrblock(n, bytes(range(n)), head=bytes([192, 0, 2]), tlvs=[t]))]))
    mark('packet headers: empty, with sequence number, with packet TLVs (ICV, timestamp, unknown type)')
    add(packet([message(0, 4, tlvblock())]))
    add(packet([message(1, 4, tlvblock())], seq=0x1234))
    add(packet([message(0, 4, tlvblock())], tlvs=[tlv(5, b'\xaa' * 8), tlv(6, b'\x00\x01', extlen=True), tlv(99, b'\x01', typeext=7)]))
    add(packet([message(0, 4, tlvblock())], seq=7, tlvs=[tlv(0, b'\x10')]))
    mark('message headers: every optional field, every address size (4, 16, 6, other), message types HELLO, TC and unknown')
    add(packet([message(0, 4, tlvblock(), orig=ip4('192.0.2.1'), hoplimit=255, hopcount=0, seq=0x5555)]))
    add(packet([message(1, 16, tlvblock(), orig=ip6(1), hoplimit=10)]))
    add(packet([message(7, 6, tlvblock(), orig=bytes.fromhex('020000000009'), hopcount=3)]))
    add(packet([message(200, 8, tlvblock(), orig=bytes(range(8)), seq=1)]))
    add(packet([message(0, 4, tlvblock()), message(1, 16, tlvblock()), message(7, 4, tlvblock())]))
    mark('message TLVs: interval and validity time, MPR willingness, content sequence number, ICV, timestamp, unknown, extended length, type extension')
    mt = [tlv(0, b'\x4a'), tlv(1, b'\x62'), tlv(7, b'\x13'), tlv(8, b'\x12\x34', extlen=False), tlv(5, b'\x01\x02\x03'),
          tlv(6, b'\x00' * 4, extlen=True), tlv(77, b'\x01\x02', typeext=3), tlv(1, b'\x30'), tlv(9)]
    add(packet([message(0, 4, tlvblock(*mt))]))
    mark('address blocks: head, full tail, zero tail, prefix lengths')
    add(packet([message(0, 4, tlvblock() +
        addrblock(3, bytes([1, 2, 3]), head=bytes([192, 0, 2])) +
        addrblock(2, bytes([5, 6, 7, 8, 9, 10, 11, 12]), prelens=None) +
        addrblock(2, bytes([1, 2, 3, 4]), head=bytes([10]), tail=bytes([9]), prelens=[16]) +
        addrblock(2, bytes([1, 2, 3, 4]), head=bytes([10]), zerotail=1, prelens=[24, 25]) +
        addrblock(1, bytes([7]), tail=bytes([0, 1, 2]), prelens=[32]) +
        addrblock(0, b'') )]))
    mark('IPv6, MAC and custom address blocks')
    add(packet([message(0, 16, tlvblock() +
        addrblock(2, bytes(range(8)), size=16, head=ip6(0)[:12]) +
        addrblock(1, bytes([0xaa]) * 16, head=b'', tail=b'', size=16, prelens=[128]), orig=None)]))
    add(packet([message(0, 6, tlvblock() + addrblock(2, bytes(range(12)), size=6) + addrblock(1, bytes([1, 2, 3, 4, 5, 6]), size=6, prelens=[48]))]))
    add(packet([message(0, 8, tlvblock() + addrblock(2, bytes(range(16)), size=8, prelens=[64, 64]))]))
    mark('address TLVs: local interface, link status, other neighbour, link metric, MPR, neighbour address type, gateway, indexes and multivalue')
    at = [tlv(2, b'\x00', index=0), tlv(3, b'\x01', multiindex=(0, 1)), tlv(4, b'\x00'), tlv(7, b'\xa0\x0f', multiindex=(1, 1)),
          tlv(8, b'\x03'), tlv(9, b'\x02', index=2), tlv(10, b'\x01'), tlv(0, b'\x31', typeext=1), tlv(3, b'\x00\x01\x02', multiindex=(0, 2), multivalue=True),
          tlv(3, b'\x00\x01\x02\x03', multiindex=(0, 2), multivalue=True, extlen=True), tlv(1, b'\x30', multiindex=(2, 0), multivalue=True),
          tlv(55, b'\x01\x02'), tlv(1, b'')]
    add(packet([message(0, 4, tlvblock() + addrblock(3, bytes(range(1, 13)), size=4, head=b'', tlvs=at))]))
    add(packet([message(1, 4, tlvblock() + addrblock(2, bytes([1, 2]), head=bytes([192, 0, 2]), tlvs=[tlv(3, b'\x01', index=1), tlv(2, b'\x01', index=0)]) +
                       addrblock(1, bytes([3]), head=bytes([192, 0, 2]), tlvs=[tlv(8, b'\x01')]))]))
    return F, marks

def malformed_frames():
    F = []
    def add(p): F.append(udp(269, 269, p))
    ab = addrblock(2, bytes([1, 2]), head=bytes([192, 0, 2]))
    add(packet([message(0, 4, tlvblock(), length=100)]))                  # message longer than the packet
    add(packet([bytes([0, 3, 0])]))                                        # message header too short
    add(packet([message(0, 4, b'')]))                                      # no TLV block
    add(packet([message(0, 4, b'\x00')]))                                  # TLV block cut to 1 octet
    add(packet([message(0, 4, struct.pack('>H', 50))]))                   # TLV block length past the message
    add(packet([message(0, 4, tlvblock() + b'\x01')]))                    # address block of 1 octet
    add(packet([message(0, 4, b''), message(0, 4, tlvblock())]))           # first message has no TLV block (and is followed by more data)
    add(packet([message(0, 4, tlvblock() + ab[:-2])]))                     # no TLV block after the addresses
    add(packet([message(0, 4, tlvblock() + ab[:-1])]))                     # TLV block cut to 1 octet
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x80]))]))            # head: no octets left
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x80, 4, 1, 2, 3, 4]))]))   # head too long
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x80, 3, 1]))]))      # head cut short
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x20]))]))            # zero tail: no octets left
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x20, 4]))]))         # zero tail too long
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x40]))]))            # full tail: no octets left
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x40, 4, 1, 2, 3, 4]))]))   # full tail too long
    add(packet([message(0, 4, tlvblock() + bytes([2, 0x40, 2, 1]))]))      # full tail cut short
    add(packet([message(0, 4, tlvblock() + bytes([200, 0x00, 1, 2]))]))    # more addresses than the message holds
    add(packet([message(0, 4, tlvblock() + ab[:-2] + b'\x00\x30')]))       # address TLV block past the message
    add(packet([message(0, 4, tlvblock() + addrblock(2, bytes([1, 2]), head=bytes([192, 0, 2])) + b'\x00')]))  # TLV block cut after the addresses
    add(packet([bytes([0x04, 0, 5])]))                                     # packet TLV block longer than the packet
    add(packet([message(0, 4, tlvblock(bytes([1, 0x10, 9, 1, 2])))]))      # TLV value longer than the block
    add(bytes([0x08, 0]))                                                  # packet header cut short
    add(bytes([0x0c, 0, 1, 0, 9]))                                         # packet TLV block longer than the packet
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'packetbb-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'packetbb-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')

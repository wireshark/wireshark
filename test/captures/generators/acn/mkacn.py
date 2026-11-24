#!/usr/bin/env python3
# Generates test/captures/acn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ACN dissector (packet-acn.c).

All packets are built from scratch with struct; no captured traffic is used.
The packet layouts follow what packet-acn.c parses.

Usage: mkacn.py <output directory>

Writes:
  acn-coverage.pcap            ACN (SDT, DMP, ETC blobs), sACN (E1.31),
                               Magic Bullet and RDMnet (LLRP over UDP,
                               Broker/RPT/EPT over TCP)
  acn-coverage-malformed.pcap  paths that end in an exception or a
                               length-mismatch expert info today

Dissecting needs the heuristics "acn", "rdmnet_udp" and "rdmnet_tcp"
enabled and acn.dmx_enable set; see the README.
"""

import struct
import sys

# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / UDP or TCP)

ACN_PORT = 5568        # sACN / ACN, found by the heuristic
LLRP_PORT = 5569
MAGIC_PORT = 41042     # any port without a registered dissector
BROKER_PORT = 41043
CLIENT_PORT = 41044


def ip_checksum(hdr):
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000.0

    def eth_ip(self, proto, l4, src, dst):
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, proto, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
        self.frames.append(eth + ip + l4)
        self.t += 0.01

    def udp(self, payload, sport=ACN_PORT, dport=ACN_PORT, src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
        # UDP checksum 0: not computed, allowed for IPv4
        self.eth_ip(17, struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload, src, dst)

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''  # MSS, SACK permitted
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        data = pseudo + hdr + payload
        if len(data) % 2:
            data += b'\0'
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(data)) + hdr[18:]
        self.eth_ip(6, hdr + payload, src, dst)

    def write(self, path):
        out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        t = 1700000000
        for i, f in enumerate(self.frames):
            out += struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f
        with open(path, 'wb') as fh:
            fh.write(out)


class TcpStream:
    """A TCP connection with a handshake and correct sequence numbers."""
    def __init__(self, cap, cport=CLIENT_PORT, sport=BROKER_PORT):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.cseq, self.sseq = 1000, 5000
        cap.tcp(cport, sport, self.cseq, 0, 0x02)
        cap.tcp(sport, cport, self.sseq, self.cseq + 1, 0x12, src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, sport, self.cseq, self.sseq, 0x10)

    def client(self, data):
        self.cap.tcp(self.cport, self.sport, self.cseq, self.sseq, 0x18, data)
        self.cseq += len(data)

    def server(self, data):
        self.cap.tcp(self.sport, self.cport, self.sseq, self.cseq, 0x18, data,
                     src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
        self.sseq += len(data)


# --------------------------------------------------------------------------
# ACN PDU framing: flags and length, then optional vector, header and data.
# None leaves out the field and clears its flag, so the dissector reuses the
# value from the previous PDU at the same level.

def pdu(vector=None, header=None, data=None, L=False):
    flags = 0
    body = b''
    if vector is not None:
        flags |= 0x40
        body += vector
    if header is not None:
        flags |= 0x20
        body += header
    if data is not None:
        flags |= 0x10
        body += data
    if L:
        n = len(body) + 3
        assert n < 0x100000
        return bytes([0x80 | flags | (n >> 16), (n >> 8) & 0xff, n & 0xff]) + body
    n = len(body) + 2
    assert n < 0x1000
    return bytes([flags | (n >> 8), n & 0xff]) + body


def u8(v):  return struct.pack('>B', v & 0xff)
def u16(v): return struct.pack('>H', v & 0xffff)
def u32(v): return struct.pack('>I', v & 0xffffffff)


def cid(n):
    return bytes([0x5a, 0x1e, 0x00, n]) + bytes(range(1, 13))


def uid(manf, dev):
    return u16(manf) + u32(dev)


ACN_ID = b'ASC-E1.17\0\0\0'


def acn_packet(*roots, postamble=b''):
    return u16(0x10) + u16(len(postamble)) + ACN_ID + b''.join(roots) + postamble


def root(protocol_id, data, n=1, L=False):
    return pdu(u32(protocol_id), cid(n), data, L)


# --------------------------------------------------------------------------
# ACN SDT

def addr_null():           return u8(0)
def addr_ipv4(port, ip):   return u8(1) + u16(port) + bytes(ip)
def addr_ipv6(port):       return u8(2) + u16(port) + bytes([0xfd] + [0] * 14 + [1])
def addr_ipport(port):     return u8(3) + u16(port)


def channel_params():
    # expiry, NAK outbound flag, NAK holdoff, NAK modulus, NAK max wait
    return u8(10) + u8(0x80) + u16(100) + u16(20) + u16(2000)


def sdt(vector, data=None):
    return pdu(u8(vector) if vector is not None else None, None, data)


def wrapper(vector, *clients, channel=1, seq=1):
    return sdt(vector, u16(channel) + u32(seq) + u32(seq) + u32(1) + u16(1) + u16(2) + u16(3)
               + b''.join(clients))


def client(member, protocol_id, data, assoc=0):
    return pdu(u16(member), u32(protocol_id) + u16(assoc), data)


def dmp(vector, adt, data):
    return pdu(u8(vector) if vector is not None else None,
               u8(adt) if adt is not None else None, data)


def sdt_packets(cap):
    # Base layer SDT PDUs, one per vector
    base = [
        sdt(0, b''),                                                    # unknown
        sdt(3, b''),                                                    # channel params (no data here)
        sdt(4, cid(9) + u16(1) + u16(7) + u16(8) + u32(1) + u32(1)      # join
            + addr_ipv4(5568, (239, 192, 0, 1)) + channel_params() + u8(30)),
        sdt(5, cid(9) + u16(7) + u16(1) + u32(1) + u8(4)),              # join refuse
        sdt(6, cid(9) + u16(7) + u16(1) + u32(1) + u16(8)),             # join accept
        sdt(7, b''),                                                    # leave
        sdt(8, cid(9) + u16(7) + u16(1) + u32(5) + u8(7)),              # leaving
    ]
    cap.udp(acn_packet(root(1, b''.join(base))))
    base = [sdt(v, b'') for v in (9, 10, 11, 12, 13, 14)]               # connect .. ack
    base += [
        sdt(15, cid(9) + u16(7) + u16(1) + u32(10) + u32(3) + u32(6)),  # nak
        sdt(16, cid(9)),                                                # get session
        sdt(99, b''),                                                   # not valid
    ]
    cap.udp(acn_packet(root(1, b''.join(base))))
    # Join with each address type
    for a in (addr_null(), addr_ipv6(5568), addr_ipport(5568), u8(9)):
        cap.udp(acn_packet(root(1, sdt(4, cid(9) + u16(1) + u16(7) + u16(8) + u32(1) + u32(1)
                                       + a + channel_params() + u8(30)))))
    # Sessions: owner info block, member info block, other member ID.
    # The session count (2 and 1) is followed by that many protocol IDs.
    owner = u16(0) + u16(7) + addr_ipv4(5568, (239, 192, 0, 1)) + addr_ipv4(5568, (10, 0, 0, 1)) \
        + u16(2) + u32(1) + u32(2)
    member = u16(1) + cid(9) + u16(7) + addr_ipv4(5568, (239, 192, 0, 1)) + addr_ipport(5568) \
        + u16(8) + u16(1) + u32(2)
    cap.udp(acn_packet(root(1, sdt(17, owner) + sdt(17, member) + sdt(17, u16(5)))))

    # Wrapped SDT PDUs inside reliable and unreliable wrappers
    wrapped = [
        sdt(14, u32(77)),                                               # ack
        sdt(3, channel_params() + addr_ipv4(5568, (10, 0, 0, 9)) + u8(30)),  # channel params
        sdt(7, b''),                                                    # leave
        sdt(9, u32(2)),                                                 # connect
        sdt(10, u32(2)),                                                # connect accept
        sdt(11, u32(2) + u8(3)),                                        # connect refuse
        sdt(12, u32(2)),                                                # disconnect
        sdt(13, u32(2) + u8(9)),                                        # disconnecting
        sdt(None, u32(2)),                                              # vector reused
        sdt(17, b''),                                                   # no wrapped meaning
    ]
    cap.udp(acn_packet(root(1, wrapper(1, client(1, 1, b''.join(wrapped))))))
    cap.udp(acn_packet(root(1, wrapper(2, client(1, 1, sdt(14, u32(78))),
                                       client(2, 0x1234, b'\x01\x02\x03'),   # unknown protocol
                                       client(3, 1, sdt(14, u32(79)), assoc=7)))))
    # Client PDU without vector, header and data flags: reuses the previous
    cap.udp(acn_packet(root(1, wrapper(1, client(1, 1, sdt(14, u32(80))),
                                       pdu(None, None, None)))))


# --------------------------------------------------------------------------
# ACN DMP

# Address and data type: V R D1 D0 X1 X0 A1 A0
def adt(d, a, virtual=False, relative=False):
    return (0x80 if virtual else 0) | (0x40 if relative else 0) | (d << 4) | a


A_LEN = {0: 1, 1: 2, 2: 4}


def addr(a, value):
    return {0: u8, 1: u16, 2: u32}[a](value)


def range_addr(a, first, inc, count):
    return addr(a, first) + addr(a, inc) + addr(a, count)


def dmp_in_sdt(*dmps, rel=True):
    return acn_packet(root(1, wrapper(1 if rel else 2, client(1, 2, b''.join(dmps)))))


def dmp_packets(cap):
    # Get property, subscribe and friends: lists of addresses of every size
    pdus = []
    for v in (1, 6, 7, 8, 12):
        pdus.append(dmp(v, adt(0, 0), addr(0, 1) + addr(0, 2)))
        pdus.append(dmp(v, adt(0, 1, virtual=True), addr(1, 0x100)))
        pdus.append(dmp(v, adt(0, 2), addr(2, 0x10000)))
    pdus.append(dmp(1, adt(1, 1), range_addr(1, 0x10, 1, 4)))
    pdus.append(dmp(1, adt(2, 2, virtual=True), range_addr(2, 0x10, 4, 4)))
    pdus.append(dmp(1, adt(3, 0), range_addr(0, 0x10, 1, 4)))
    pdus.append(dmp(1, adt(0, 3), b'\x00\x00\x00\x01'))                 # reserved address size
    cap.udp(dmp_in_sdt(*pdus))

    # Set property, get property reply, event and sync event: address-data pairs
    for v in (2, 3, 4, 17):
        pdus = []
        for a in (0, 1, 2):
            # five octets is the most that fits: a pair needs data <= count + 4
            for size in (1, 2, 3, 4, 5):
                pdus.append(dmp(v, adt(0, a), addr(a, 0x20 + size) + bytes(range(0x11, 0x11 + size))))
        cap.udp(dmp_in_sdt(*pdus))
    pdus = []
    for a in (0, 1, 2):
        # range, single data item, each data size
        for size in (1, 2, 3, 4, 6):
            pdus.append(dmp(2, adt(1, a, virtual=(size == 2)), range_addr(a, 0x40, 2, 3)
                            + bytes(range(0x21, 0x21 + size))))
        # range, array of equal size items
        for size in (1, 2, 3, 4, 6):
            pdus.append(dmp(2, adt(2, a), range_addr(a, 0x80, 1, 2) + bytes(range(0x31, 0x31 + 2 * size))))
        # an array of one item, for the item sizes that only fit then
        for size in (4, 5):
            pdus.append(dmp(2, adt(2, a), range_addr(a, 0xa0, 1, 1) + bytes(range(0x41, 0x41 + size))))
        # range, mixed size items
        pdus.append(dmp(2, adt(3, a, virtual=(a == 1)), range_addr(a, 0xc0, 1, 2) + b'\x01\x02\x03'))
    cap.udp(dmp_in_sdt(*pdus))
    pdus = [
        dmp(2, adt(0, 3), b'\x00\x00\x00\x01\x02'),                     # reserved address size
        dmp(2, adt(2, 1), range_addr(1, 0x80, 1, 0) + b'\x01\x02'),     # count 0
        dmp(2, adt(0, 0), addr(0, 1) + bytes(range(16))),               # more pairs: not decodable
        dmp(2, None, addr(0, 2) + b'\x05'),                             # header reused
        dmp(None, adt(0, 1), addr(1, 3) + b'\x06'),                     # vector reused
        dmp(2, adt(0, 0), None),                                        # data reused
        dmp(0, adt(0, 0), b''),                                         # unknown vector
        dmp(99, adt(0, 0), b''),                                        # not valid
    ]
    cap.udp(dmp_in_sdt(*pdus, rel=False))
    # A range of more addresses than are shown
    cap.udp(dmp_in_sdt(dmp(2, adt(1, 1), range_addr(1, 0, 1, 1100) + b'\x7f'),
                       dmp(9, adt(1, 1), range_addr(1, 0, 1, 1100) + b'\x02')))
    # Ranges with counts near 2^32 (one data item, an array, reason codes)
    # once made tshark allocate memory until it was killed, and small ones
    # that must still be shown in full
    big = range_addr(2, 0x100, 1, 0xfffffff0)
    cap.udp(dmp_in_sdt(dmp(2, adt(1, 2), big + b'\x00'), rel=False))
    cap.udp(dmp_in_sdt(dmp(2, adt(2, 2), big + b'\x00'), rel=False))
    cap.udp(dmp_in_sdt(dmp(9, adt(1, 2), big + b'\x00'), rel=False))
    cap.udp(dmp_in_sdt(dmp(2, adt(1, 2), range_addr(2, 0x100, 1, 3) + b'\x7f'),
                       dmp(2, adt(2, 2), range_addr(2, 0x200, 2, 3) + b'\x01\x02\x03'), rel=False))

    # Map property: actual-virtual address pairs
    cap.udp(dmp_in_sdt(
        dmp(5, adt(0, 1), u8(adt(0, 1, virtual=True)) + addr(1, 1) + addr(1, 0x1001)),
        dmp(5, adt(1, 1), u8(adt(0, 2, virtual=True)) + range_addr(1, 1, 1, 4) + addr(2, 0x1002)),
        dmp(5, adt(2, 1), u8(adt(0, 1, virtual=True)) + range_addr(1, 1, 1, 2) + addr(1, 0x1003) + addr(1, 0x1004)),
        dmp(5, adt(3, 1), u8(adt(0, 1, virtual=True)) + range_addr(1, 1, 1, 2) + addr(1, 0x1005)),
        dmp(5, adt(0, 3), u8(adt(0, 1, virtual=True)) + b'\x00\x01'),
    ))
    # Failures: address-reason code pairs
    pdus = []
    for v in (9, 10, 11, 13):
        pdus.append(dmp(v, adt(0, 0), addr(0, 1) + u8(2)))
    for a in (0, 1, 2):
        pdus.append(dmp(10, adt(0, a), addr(a, 5) + u8(4)))
        pdus.append(dmp(10, adt(1, a), range_addr(a, 5, 1, 3) + u8(5)))
        pdus.append(dmp(10, adt(2, a), range_addr(a, 5, 1, 3) + u8(1) + u8(2) + u8(3)))
        pdus.append(dmp(10, adt(3, a), range_addr(a, 5, 1, 2) + u8(6) + u8(99)))
    pdus += [dmp(9, adt(d, 3), b'\x00\x00\x00\x01\x02') for d in range(4)]
    cap.udp(dmp_in_sdt(*pdus))
    # Maps
    cap.udp(dmp_in_sdt(dmp(14, adt(0, 0), b''), dmp(15, adt(0, 0), u8(7)), dmp(16, adt(0, 0), b'')))


# --------------------------------------------------------------------------
# ETC blobs in DMP set property messages

def bfield(ftype, value=b''):
    if ftype == 11:
        # variable length: two length octets that include themselves
        return u8(11) + u16(len(value) + 2) + value
    if ftype == 12:
        return u8(12)
    return u8(ftype) + value


FIXED = {1: 1, 2: 2, 3: 4, 4: 8, 5: 1, 6: 2, 7: 4, 8: 8, 9: 4, 10: 8}


def num(ftype, v=1):
    return bfield(ftype, (v & ((1 << (8 * FIXED[ftype])) - 1)).to_bytes(FIXED[ftype], 'big'))


def blob(btype, fields, version=1, range_type=3, range_number=0):
    return b'Blob' + u8(version) + u8(range_type) + u8(range_number) + u8(btype) + b''.join(fields)


def blob_pdu(b, address=0x123):
    return dmp(2, adt(0, 1), addr(1, address) + b)


# One field of each kind that displays without errors
MIXED = [num(1, 1), num(2, 0x203), num(3, 0x4050607), num(4, 0x0102030405060708),
         num(5, 0xfe), num(6, 0xfffe), num(7, 0xfffffffe), num(9, 0x3fc00000),
         num(10, 0x3ff8000000000000), bfield(11, b'Studio A'), bfield(11, b''),
         bfield(12), bfield(0x7f)]


def blob_packets(cap):
    # Every blob type, with fields of every kind
    simple = [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 24, 25, 27, 28,
              31, 32, 33, 200]
    pdus = []
    for t in simple:
        if t in (1, 2):
            continue
        pdus.append(blob_pdu(blob(t, MIXED[: 4 + t % 9])))
        if len(pdus) == 4:
            cap.udp(dmp_in_sdt(*pdus))
            pdus = []
    if pdus:
        cap.udp(dmp_in_sdt(*pdus))
    # Every kind of field in one blob, and a type 20 blob too short to tell
    # dimmer properties v2 from preset properties
    cap.udp(dmp_in_sdt(blob_pdu(blob(21, MIXED)), blob_pdu(blob(20, [num(1, 1), num(1, 2)]))))
    # IPv4 and IPv6 blobs: variable length fields holding addresses
    cap.udp(dmp_in_sdt(blob_pdu(blob(1, [bfield(11, bytes([10, 0, 0, 5])), bfield(11, bytes([255, 255, 255, 0])),
                                         bfield(12)])),
                       blob_pdu(blob(2, [bfield(11, bytes([0xfd] + [0] * 14 + [5])), bfield(12)]))))
    # Metadata: field 15 is a CID
    cap.udp(dmp_in_sdt(blob_pdu(blob(5, [num(1, i) for i in range(1, 15)] + [bfield(11, cid(3)), num(2, 16)]))))
    # Dimmer properties v2: type 20 with a string as field 12
    cap.udp(dmp_in_sdt(blob_pdu(blob(20, [num(2, i) for i in range(1, 12)] + [bfield(11, b'Dimmer 1'), num(1, 3)]))))
    # Preset properties: type 20 with a number as field 12, levels from field 17
    cap.udp(dmp_in_sdt(blob_pdu(blob(20, [num(2, i) for i in range(1, 17)] + [num(1, 0x80), num(1, 0x40),
                                                                              num(1, 0xff)]))))
    # Dimming rack properties v2: field 12 is a CID
    cap.udp(dmp_in_sdt(blob_pdu(blob(22, [num(1, i) for i in range(1, 12)] + [bfield(11, cid(4)), num(1, 1)]))))
    # Dimming rack status properties v2: active preset group IDs from field 22
    cap.udp(dmp_in_sdt(blob_pdu(blob(23, [num(2, i) for i in range(1, 22)] + [num(2, 1), num(2, 2)]))))
    # RPC: field names repeat from field 4
    cap.udp(dmp_in_sdt(blob_pdu(blob(26, [num(2, 1), num(2, 2), num(2, 3), num(2, 4), num(2, 5), num(2, 6)]))))
    # Energy management: from field 4, values without type or length
    cap.udp(dmp_in_sdt(blob_pdu(blob(29, [num(1, 1), num(1, 2), num(1, 3), u16(1), u32(2), u32(3), u32(4),
                                          u16(5)]))))
    # Time 3: time zone index, custom time zone, DST fields
    fields = [num(3, 1700000000), num(3, 2), bfield(11, b'Gothenburg'), bfield(11, b'SE'), num(3, 12),
              num(3, 57), num(1, 1), num(1, 0), bfield(11, b'CET'), num(1, 1), num(1, 3), num(1, 5),
              num(1, 0), num(1, 2), num(1, 0), num(1, 1), num(1, 10), num(1, 5), num(1, 0), num(1, 3),
              num(1, 0), num(1, 0), num(1, 1)]
    custom = list(fields)
    custom[1] = num(3, 0xffffffff)
    custom[9] = num(1, 77)
    cap.udp(dmp_in_sdt(blob_pdu(blob(30, fields)), blob_pdu(blob(30, custom))))
    # Blob after some address-data pairs, and a blob of unknown type
    cap.udp(dmp_in_sdt(dmp(2, adt(0, 1), addr(1, 7) + u8(1) + blob(250, [num(1, 1)]))))


# --------------------------------------------------------------------------
# sACN (E1.31) and its draft versions

DMX_DRAFT = 3          # protocol ID 3: draft, 32 octet source name
DMX = 4                # E1.31
DMX_3 = 0x50430001     # "PC" protocol ID
EXTENDED = 8


def source_name(s, n=64):
    return s.encode().ljust(n, b'\0')


def dmx_framing(protocol, universe, levels, seq=1, priority=100, options=0, sync=0, start=0):
    if protocol == DMX_DRAFT:
        hdr = source_name('Draft console', 32) + u8(priority) + u8(seq) + u16(universe)
        dmp_data = u16(start) + u16(1) + u16(len(levels)) + levels
    else:
        hdr = source_name('Console') + u8(priority) + u16(sync) + u8(seq) + u8(options) + u16(universe)
        dmp_data = u16(0) + u16(1) + u16(len(levels) + 1) + u8(start) + levels
    dmx_dmp = pdu(u8(2), u8(0xa1), dmp_data)
    return pdu(u32(2), None, hdr + dmx_dmp)


def sacn_packets(cap):
    full = bytes((i * 7) & 0xff for i in range(512))
    cap.udp(acn_packet(root(DMX, dmx_framing(DMX, 1, full, options=0x00))), dport=ACN_PORT)
    cap.udp(acn_packet(root(DMX, dmx_framing(DMX, 2, bytes([0, 1, 2, 3, 128, 254, 255] * 5), seq=2,
                                             options=0xe0, sync=7, start=0xdd))))
    cap.udp(acn_packet(root(DMX_DRAFT, dmx_framing(DMX_DRAFT, 3, bytes(range(40))))))
    cap.udp(acn_packet(root(DMX_3, dmx_framing(DMX_3, 4, bytes(range(255, 215, -1))))))
    # A framing vector without levels, and an unknown one
    cap.udp(acn_packet(root(DMX, pdu(u32(3), None, b'') + pdu(u32(99), None, b''))))
    # Synchronization
    cap.udp(acn_packet(root(EXTENDED, pdu(u32(1), None, u8(5) + u16(7) + u16(0)))))
    # Universe discovery: ordered, out of order, empty, and more than 16
    def discovery(universes, page=0, last=0):
        lst = pdu(u32(1), None, u8(page) + u8(last) + b''.join(u16(u) for u in universes), L=False)
        return pdu(u32(2), None, source_name('Console') + u32(0) + lst)
    cap.udp(acn_packet(root(EXTENDED, discovery([1, 2, 3]))))
    cap.udp(acn_packet(root(EXTENDED, discovery([10, 5, 20, 1]))))
    cap.udp(acn_packet(root(EXTENDED, discovery([]))))
    cap.udp(acn_packet(root(EXTENDED, discovery(list(range(1, 40)), page=1, last=2))))
    cap.udp(acn_packet(root(EXTENDED, pdu(u32(99), None, b''))))
    # ACN packet with a postamble
    cap.udp(acn_packet(root(DMX, dmx_framing(DMX, 1, bytes(24))),
                       postamble=u32(0xdeadbeef) + u8(1) + b'\x00\x00\x01' + u32(2) + bytes(range(16))))
    # Two root PDUs, the second one reusing the first one's vector
    cap.udp(acn_packet(root(1, sdt(7, b'')), pdu(None, cid(2), sdt(7, b''))))


# --------------------------------------------------------------------------
# Magic Bullet (ETC device configuration)

def magic(subtype, body, major=2, minor=0):
    return u8(15) + u8(subtype) + u8(major) + u8(minor) + body


def pstr(s):
    return u8(len(s)) + s.encode()


def magic_packets(cap):
    send = lambda p: cap.udp(p, sport=MAGIC_PORT, dport=MAGIC_PORT)
    send(magic(0, struct.pack('<I', 1114467), major=1))                 # v1 BOOTP
    send(magic(0, struct.pack('<I', 2), major=1))                       # v1 switch to net2
    for cmd, arg in [(1, b''), (2, b''), (3, bytes([10, 0, 0, 1])), (4, b''), (5, u32(10)),
                     (6, u32(10)), (7, b''), (8, u32(1)), (9, u32(30)),
                     (10, cid(5) + u32(2) + bytes([10, 0, 0, 7, 255, 255, 255, 0, 10, 0, 0, 254])),
                     (11, cid(5)), (12, cid(5) + u32(15)), (110163, b'')]:
        send(magic(1, u32(cmd) + arg))
    version = bytes([3, 1, 4, 0, 1]) + u16(926)
    addrs = bytes([10, 0, 0, 7, 255, 255, 255, 0, 10, 0, 0, 254, 10, 0, 0, 1])
    send(magic(2, addrs + version + pstr('Net3 Gateway') + pstr('Gateway') + pstr('Stage left')))
    send(magic(3, u32(1) + addrs + cid(5) + cid(6) + version + pstr('Net3 Gateway') + pstr('Gateway')
               + pstr('')))
    send(magic(9, b'\x00' * 8))                                         # invalid type


# --------------------------------------------------------------------------
# RDM, carried by LLRP and RPT

def rdm(cc, pid, pd=b'', dest=(0x6574, 0x00000001), src=(0x6574, 0x00000002), tn=1, subdev=0):
    port = 0 if cc & 1 else 1       # responses carry the response type (ACK) here
    body = u8(0x01) + u8(24 + len(pd)) + uid(*dest) + uid(*src) + u8(tn) + u8(port) + u8(0) \
        + u16(subdev) + u8(cc) + u16(pid) + u8(len(pd)) + pd
    return body + u16(0xcc + sum(body))


RDM_GET_DEVICE_INFO = rdm(0x20, 0x0060)
RDM_DEVICE_INFO = rdm(0x21, 0x0060, u16(0x0100) + u16(0x0101) + u16(0x0001) + u32(0x00010000) + u16(512)
                      + u8(1) + u8(1) + u16(1) + u16(0) + u8(0), src=(0x6574, 1), dest=(0x6574, 2))
RDM_IDENTIFY = rdm(0x30, 0x1000, u8(1))


# --------------------------------------------------------------------------
# RDMnet LLRP (UDP)

LLRP = 0x0A
BROADCAST_CID = bytes.fromhex('FBAD822CBD0C4D4CBDC87EABEBC85AFF')


def llrp(vector, inner, dest=BROADCAST_CID, tn=1):
    return acn_packet(root(LLRP, pdu(u32(vector), b'', dest + u32(tn) + inner, L=True), L=True))


def llrp_packets(cap):
    send = lambda p, **kw: cap.udp(p, sport=LLRP_PORT, dport=LLRP_PORT, **kw)
    # probe request: lower UID, upper UID, filter, known UIDs
    send(llrp(1, pdu(u8(1), b'', uid(0, 0) + uid(0xffff, 0xffffffff) + u16(0x0003)
                     + uid(0x6574, 1) + uid(0x6574, 2), L=True)))
    send(llrp(1, pdu(u8(1), b'', uid(0x6574, 0) + uid(0x6574, 0xffff) + u16(0), L=True)))
    # probe reply: UID, hardware address, component type
    send(llrp(2, pdu(u8(1), b'', uid(0x6574, 1) + bytes.fromhex('020000000001') + u8(1), L=True),
              dest=cid(1)), src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
    # RDM command and response
    send(llrp(3, pdu(u8(0xcc), b'', RDM_GET_DEVICE_INFO, L=True), dest=cid(2), tn=2))
    send(llrp(3, pdu(u8(0xcc), b'', RDM_DEVICE_INFO, L=True), dest=cid(1), tn=2),
         src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
    send(llrp(99, b''))                                                 # unknown vector


# --------------------------------------------------------------------------
# RDMnet over TCP: Broker, RPT and EPT

BROKER = 0x09
RPT = 0x05
EPT = 0x0B


def tcp_msg(*roots):
    body = b''.join(roots)
    return ACN_ID + u32(len(body)) + body


def broker(vector, data=b'', n=1):
    return root(BROKER, pdu(u16(vector), b'', data, L=True), n=n, L=True)


def client_entry_rpt(n, manf=0x6574, dev=1, ctype=0):
    return pdu(u32(RPT), b'', cid(n) + uid(manf, dev) + u8(ctype) + cid(0), L=True)


def rpt(vector, inner, src=(0x6574, 2), dst=(0x6574, 1), seq=1, n=2):
    return root(RPT, pdu(u32(vector), b'', uid(*src) + u16(0) + uid(*dst) + u16(0) + u32(seq) + u8(0)
                         + inner, L=True), n=n, L=True)


def rdm_cmd(r):
    return pdu(u8(0xcc), b'', r, L=True)


def ept(vector, inner, n=2):
    return root(EPT, pdu(u32(vector), b'', cid(1) + inner, L=True), n=n, L=True)


def rdmnet_tcp_packets(cap):
    s = TcpStream(cap)
    scope = source_name('default', 63)
    domain = source_name('local.', 231)
    s.client(tcp_msg(broker(1, scope + u16(1) + domain + u8(1) + client_entry_rpt(2, dev=2))))
    s.server(tcp_msg(broker(2, u16(0) + u16(1) + uid(0x6574, 0x100) + uid(0x6574, 2))))
    s.client(tcp_msg(broker(3, u8(0) + client_entry_rpt(2, dev=2, ctype=1), n=2)))
    s.server(tcp_msg(broker(4, bytes([10, 0, 0, 3]) + u16(8888))))
    s.server(tcp_msg(broker(5, bytes([0xfd] + [0] * 14 + [3]) + u16(8888))))
    s.client(tcp_msg(broker(6, n=2)))
    s.server(tcp_msg(broker(7, client_entry_rpt(2, dev=2) + client_entry_rpt(3, dev=3, ctype=1))))
    s.server(tcp_msg(broker(8, client_entry_rpt(4, dev=4))))
    s.server(tcp_msg(broker(9, client_entry_rpt(4, dev=4))))
    s.server(tcp_msg(broker(10, client_entry_rpt(3, dev=3))))
    # Dynamic UIDs.
    # The last entry of each list ends at the end of the PDU.
    s.client(tcp_msg(broker(11, uid(0xe574, 0) + cid(7) + uid(0xe574, 0) + cid(8), n=2)))
    s.server(tcp_msg(broker(12, uid(0xe574, 1) + cid(7) + u16(0) + uid(0xe574, 2) + cid(8) + u16(1))))
    s.client(tcp_msg(broker(13, uid(0xe574, 1) + uid(0xe574, 2), n=2)))
    s.client(tcp_msg(broker(15, n=2)))                                  # null (heartbeat)
    # a root PDU with a two octet length
    s.client(tcp_msg(root(BROKER, pdu(u16(15), b'', b'', L=True), n=2)))
    s.client(tcp_msg(broker(99, n=2)))                                  # unknown

    # RPT request, then a status and a notification for it
    s.client(tcp_msg(rpt(1, pdu(u32(1), b'', rdm_cmd(RDM_GET_DEVICE_INFO), L=True))))
    for v in range(1, 10):
        status = pdu(u16(v), b'', u16(0) + (b'status %d' % v if v < 8 else b''), L=True)
        s.server(tcp_msg(rpt(2, status, src=(0x6574, 1), dst=(0x6574, 2), seq=v, n=1)))
    s.server(tcp_msg(rpt(3, pdu(u32(1), b'', rdm_cmd(RDM_GET_DEVICE_INFO) + rdm_cmd(RDM_DEVICE_INFO), L=True),
                         src=(0x6574, 1), dst=(0x6574, 2), n=1)))
    s.client(tcp_msg(rpt(1, pdu(u32(1), b'', rdm_cmd(RDM_IDENTIFY), L=True), seq=2)))
    s.client(tcp_msg(rpt(99, b'', seq=3)))                              # unknown

    # EPT data and status: the vector is at the start of the PDU
    s.client(tcp_msg(ept(1, pdu(b'\x00' + u16(0x6574) + u16(1), b'', b'opaque data', L=True))))
    s.server(tcp_msg(ept(2, pdu(b'\x00' + u16(1), b'', cid(9) + b'unknown CID', L=True), n=1)))
    s.server(tcp_msg(ept(2, pdu(b'\x00' + u16(2), b'', u16(0x6574) + u16(7) + b'unknown vector', L=True), n=1)))
    s.client(tcp_msg(ept(99, b'')))                                     # unknown

    # Two messages in one segment, and a message split over two segments
    s.client(tcp_msg(broker(15, n=2)) + tcp_msg(broker(15, n=2)))
    m = tcp_msg(broker(7, client_entry_rpt(2, dev=2) + client_entry_rpt(3, dev=3)))
    s.server(m[:40])
    s.server(m[40:])
    s.client(tcp_msg(broker(14, u16(1), n=2)))                          # disconnect, shutdown
    # A message followed by sixteen octets that are not one
    s.client(tcp_msg(broker(15, n=2)) + b'NOT-ACN-DATA' + u32(0))

    # Data the heuristics must leave alone
    other = TcpStream(cap, cport=CLIENT_PORT + 2, sport=BROKER_PORT + 2)
    other.client(b'GET')                                                # too short
    other.client(tcp_msg(root(1, sdt(7, b''))))                         # ACN, but not RDMnet
    other.client(b' / HTTP/1.1\r\nHost: x\r\n\r\n')                 # not ACN
    cap.udp(b'\x01\x02\x03\x04 not ACN or Magic', sport=MAGIC_PORT + 2, dport=MAGIC_PORT + 2)


# --------------------------------------------------------------------------
# Paths that only malformed input reaches

def malformed_packets(cap):
    # Variblob lengths below two (no underflow), and a length past the end
    cap.udp(dmp_in_sdt(blob_pdu(blob(9, [u8(11) + u16(0), u8(11) + u16(1), num(1, 1)])),
                       blob_pdu(blob(9, [u8(11) + u16(500) + b'abc']))))
    # EPT data and status PDUs without room for the strings
    s = TcpStream(cap, cport=CLIENT_PORT + 1)
    s.client(tcp_msg(ept(1, pdu(u16(0x6574), b'', b'', L=True))))
    s.client(tcp_msg(ept(2, pdu(u16(1), b'', b'', L=True))))
    s.client(tcp_msg(ept(2, pdu(u16(2), b'', b'', L=True))))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    for gen in (sdt_packets, dmp_packets, blob_packets, sacn_packets, magic_packets, llrp_packets,
                rdmnet_tcp_packets):
        gen(cap)
    cap.write(out + '/acn-coverage.pcap')
    bad = Pcap()
    malformed_packets(bad)
    bad.write(out + '/acn-coverage-malformed.pcap')


if __name__ == '__main__':
    main()

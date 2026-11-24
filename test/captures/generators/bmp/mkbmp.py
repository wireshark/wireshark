#!/usr/bin/env python3
# Generates test/captures/bmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BMP dissector (packet-bmp.c).

BGP Monitoring Protocol, versions 3 (RFC 7854, 8671, 9069) and 4
(draft-ietf-grow-bmp-tlv), carried over TCP. BMP has no default port, so
dissect with -d tcp.port==11019,bmp. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkbmp.py <output directory>

Writes:
  bmp-coverage.pcap            every message type of v3 and v4, every peer
                               type and flag, every stat type, every TLV,
                               the Route Policy and Attribute Trace message,
                               reassembly across segments, and the
                               reproducers of the fixes on the branch
  bmp-coverage-malformed.pcap  bad TLV lengths, truncated messages and the
                               unfixed Per Peer Header length problem
"""

import os
import struct
import sys

BMP_PORT = 11019
ROUTER = (192, 0, 2, 1)     # monitored router (BMP client)
STATION = (192, 0, 2, 2)    # monitoring station


# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP)

def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=ROUTER, dst=STATION):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from the router to the monitoring station."""
    def __init__(self, cap, cport):
        self.cap, self.cport = cap, cport
        self.cseq, self.sseq = 1000 + cport, 5000 + cport
        cap.tcp(cport, BMP_PORT, self.cseq, 0, 0x02)
        cap.tcp(BMP_PORT, cport, self.sseq, self.cseq + 1, 0x12, src=STATION, dst=ROUTER)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, BMP_PORT, self.cseq, self.sseq, 0x10)

    def send(self, *datas):
        """Send each argument as one TCP segment from the router."""
        for data in datas:
            self.cap.tcp(self.cport, BMP_PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def close(self):
        self.cap.tcp(self.cport, BMP_PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(BMP_PORT, self.cport, self.sseq, self.cseq, 0x11, src=STATION, dst=ROUTER)
        self.sseq += 1
        self.cap.tcp(self.cport, BMP_PORT, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    out.append(data[last:])
    return out


# --------------------------------------------------------------------------
# BGP messages

def bgp(typ, body=b''):
    return b'\xff' * 16 + struct.pack('>HB', 19 + len(body), typ) + body


KEEPALIVE = bgp(4)


def bgpcap(code, value):
    return struct.pack('>BB', code, len(value)) + value


CAPS = (bgpcap(1, struct.pack('>HBB', 1, 0, 1))        # multiprotocol IPv4 unicast
        + bgpcap(1, struct.pack('>HBB', 2, 0, 1))      # multiprotocol IPv6 unicast
        + bgpcap(2, b'')                               # route refresh
        + bgpcap(65, struct.pack('>I', 64500)))        # 4-octet AS


def bgp_open(asn, bgp_id):
    opt = struct.pack('>BB', 2, len(CAPS)) + CAPS
    return bgp(1, struct.pack('>BHH4sB', 4, 23456 if asn > 65535 else asn, 180,
                              bytes(bgp_id), len(opt)) + opt)


def attr(flags, typ, value):
    if flags & 0x10:
        return struct.pack('>BBH', flags, typ, len(value)) + value
    return struct.pack('>BBB', flags, typ, len(value)) + value


def path_attrs(nh=(192, 0, 2, 9)):
    return (attr(0x40, 1, b'\x00')                                         # ORIGIN IGP
            + attr(0x40, 2, struct.pack('>BBII', 2, 2, 64500, 64501))      # AS_PATH (4-octet)
            + attr(0x40, 3, bytes(nh))                                     # NEXT_HOP
            + attr(0x80, 4, struct.pack('>I', 10))                         # MED
            + attr(0x40, 5, struct.pack('>I', 100)))                       # LOCAL_PREF


def bgp_update(nlri_count=1, withdrawn=0, base=10):
    wd = b''.join(struct.pack('>BBBB', 24, 172, 16, i) for i in range(withdrawn))
    pa = path_attrs()
    nlri = b''.join(struct.pack('>BBBB', 24, base, i // 256, i % 256) for i in range(nlri_count))
    return bgp(2, struct.pack('>H', len(wd)) + wd + struct.pack('>H', len(pa)) + pa + nlri)


def bgp_notification(code=6, sub=2, data=b''):
    return bgp(3, bytes([code, sub]) + data)


ROUTE_REFRESH = bgp(5, struct.pack('>HBB', 1, 0, 1))


# --------------------------------------------------------------------------
# BMP messages

def bmp(ver, typ, body):
    return struct.pack('>BIB', ver, 6 + len(body), typ) + body


def peer_hdr(ptype=0, flags=0, rd=b'\0' * 8, addr=(192, 0, 2, 9), asn=64500,
             bgp_id=(192, 0, 2, 9), sec=1700000000, usec=123456):
    a = bytes(addr) if flags & 0x80 else b'\0' * 12 + bytes(addr)
    return (struct.pack('>BB', ptype, flags) + rd + a
            + struct.pack('>I4sII', asn, bytes(bgp_id), sec, usec))


V6_PEER = bytes.fromhex('20010db8000000000000000000000009')
V6_LOCAL = bytes.fromhex('20010db8000000000000000000000001')


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def tlv4(t, v, idx=None):
    """BMPv4 TLV; with an index in Route Monitoring messages."""
    if idx is None:
        return struct.pack('>HH', t, len(v)) + v
    return struct.pack('>HHH', t, len(v), idx) + v


def rm_padded(ver, ptype, flags, rd=b'\0' * 8, addr=(192, 0, 2, 9), base=10):
    """Route Monitoring message long enough for the Per Peer Header item.

    dissect_bmp_pdu() takes the length of the "Per Peer Header" item from
    the Peer Type and Peer Flags octets (not fixed on the branch), so the
    message is made at least that long to decode cleanly with a tree."""
    need = 6 + ((ptype << 8) | flags)
    hdr = peer_hdr(ptype, flags, rd, addr)
    n = 1
    while 6 + len(hdr) + len(bgp_update(n, base=base)) < need:
        n += 1
    return bmp(ver, 0, hdr + bgp_update(n, base=base))


def stat(t, v):
    return struct.pack('>HH', t, len(v)) + v


def all_stats():
    s = []
    for t in (0, 1, 2, 3, 4, 5, 6, 11, 12, 13):
        s.append(stat(t, struct.pack('>I', 100 + t)))
    for t in (7, 8, 14, 15):
        s.append(stat(t, struct.pack('>Q', 1000 + t)))
    for t in (9, 10, 16, 17):
        s.append(stat(t, struct.pack('>HBQ', 1, 1, 2000 + t)))
    return s


def route_policy(flags, prefix_len, prefix, events):
    if flags & 0x80:
        p = prefix
    else:
        p = b'\0' * 12 + prefix
    total = sum(len(e) for e in events)
    return bmp(3, 0x64, struct.pack('>B', flags) + struct.pack('>HHI', 0, 64500, 1)
               + struct.pack('>B', prefix_len) + p + struct.pack('>IBH', 0x0a000001, len(events), total)
               + b''.join(events))


def rp_event(idx, tlvs, afi=1, safi=1):
    body = struct.pack('>BIIIHB', idx, 1700000000 + idx, 1000 * idx, idx, afi, safi) + b''.join(tlvs)
    return struct.pack('>H', 2 + len(body)) + body


def rp_policy_tlv(flags, peer, policies, cls=0):
    body = struct.pack('>BBB', flags, len(policies), cls)
    body += peer if flags & 0x80 else b'\0' * 12 + peer
    body += struct.pack('>4sI', bytes((192, 0, 2, 9)), 64501)
    for name, pid, pflag in policies:
        body += struct.pack('>HH', len(name), len(pid)) + name + pid + bytes([pflag])
    return tlv(1, body)


# --------------------------------------------------------------------------

def main_capture(path):
    cap = Pcap()

    # ---- Connection 1: BMP version 3 ------------------------------------
    s = TcpStream(cap, 40001)
    # Initiation: every information type, and an unknown one
    s.send(bmp(3, 4, tlv(0, b'synthetic BMP test') + tlv(1, b'Example Router OS 1.0')
                    + tlv(2, b'router1.example') + tlv(3, b'global') + tlv(4, b'lab')
                    + tlv(7, b'unknown-type')))
    # Peer Up, IPv4 global peer: sent and received OPEN, every TLV type
    s.send(bmp(3, 3, peer_hdr() + b'\0' * 12 + bytes((192, 0, 2, 1))
                    + struct.pack('>HH', 179, 50000)
                    + bgp_open(64500, (192, 0, 2, 1)) + bgp_open(64501, (192, 0, 2, 9))
                    + tlv(0, b'peer up') + tlv(1, b'sysdescr') + tlv(2, b'sysname')
                    + tlv(3, b'vrf-red') + tlv(4, b'admin-label') + tlv(9, b'\x01\x02')))
    # Peer Up, IPv6 peer (Per Peer Header item length 0x0080)
    s.send(bmp(3, 3, peer_hdr(0, 0x80, addr=V6_PEER) + V6_LOCAL + struct.pack('>HH', 50001, 179)
                    + bgp_open(64500, (192, 0, 2, 1)) + bgp_open(64502, (192, 0, 2, 10))
                    + tlv(0, b'IPv6 peer up')))
    # Route Monitoring, global peer, every Peer Flag
    s.send(bmp(3, 0, peer_hdr() + bgp_update(2, withdrawn=1)))
    s.send(rm_padded(3, 0, 0x40))                  # L (post-policy)
    s.send(rm_padded(3, 0, 0x20))                  # A (2-octet AS_PATH)
    s.send(rm_padded(3, 0, 0x1f))                  # O (Adj-RIB-Out) + reserved bits
    s.send(rm_padded(3, 0, 0x80, addr=V6_PEER))    # V (IPv6)
    # RD instance peers with RD types 0, 1, 2; local instance; Loc-RIB
    s.send(rm_padded(3, 1, 0x00, rd=struct.pack('>HHI', 0, 64500, 100)))
    s.send(rm_padded(3, 1, 0x00, rd=struct.pack('>H4sH', 1, bytes((192, 0, 2, 1)), 200)))
    s.send(rm_padded(3, 1, 0x00, rd=struct.pack('>HIH', 2, 4200000000, 300)))
    s.send(rm_padded(3, 2, 0x00))
    s.send(rm_padded(3, 3, 0x00))
    s.send(rm_padded(3, 3, 0x80, addr=V6_PEER))    # F (filtered) flag
    # Route Monitoring carrying a ROUTE-REFRESH and a KEEPALIVE
    s.send(bmp(3, 0, peer_hdr() + ROUTE_REFRESH))
    s.send(bmp(3, 0, peer_hdr() + KEEPALIVE))
    # Statistics Report: every stat type, an unknown one (note) and a known
    # type with a longer Stat Len (stepped over by its length)
    st = all_stats() + [stat(99, b'\x01\x02\x03'),
                        stat(0, struct.pack('>Q', 7)), stat(1, struct.pack('>I', 9))]
    s.send(bmp(3, 1, peer_hdr() + struct.pack('>I', len(st)) + b''.join(st)))
    # Peer Down: every reason
    s.send(bmp(3, 2, peer_hdr() + b'\x01' + bgp_notification(6, 2)))
    s.send(bmp(3, 2, peer_hdr() + b'\x02' + struct.pack('>H', 24)))
    s.send(bmp(3, 2, peer_hdr() + b'\x03' + bgp_notification(4, 0)))
    s.send(bmp(3, 2, peer_hdr() + b'\x04'))
    s.send(bmp(3, 2, peer_hdr() + b'\x05'))
    s.send(bmp(3, 2, peer_hdr(3, 0x00, addr=(0, 0, 0, 0)) + b'\x06' + tlv(3, b'loc-rib-vrf')
                    + b'\0' * 760))
    s.send(bmp(3, 2, peer_hdr() + b'\x07'))
    # Route Mirroring: BGP Message, Information (both codes), an unknown TLV
    s.send(bmp(3, 6, peer_hdr() + tlv(0, bgp_update(1)) + tlv(1, b'\x00\x00')
                    + tlv(1, b'\x00\x01')))
    # bmp_tlv_len_ignored.py frames 1 and 2: an unknown Route
    # Mirroring TLV and an Information TLV of length 4 are stepped over by
    # their length, so the KEEPALIVE after them is decoded
    s.send(bmp(3, 6, peer_hdr() + tlv(5, b'\x00\x01\x00\x00') + tlv(0, KEEPALIVE)))
    s.send(bmp(3, 6, peer_hdr() + tlv(1, b'\x00\x00\x00\x00') + tlv(0, KEEPALIVE)))
    # bmp_tlv_len_ignored.py frame 3: stat type 0 with length 8
    s.send(bmp(3, 1, peer_hdr() + struct.pack('>I', 2) + stat(0, struct.pack('>Q', 7))
                    + stat(1, struct.pack('>I', 9))))
    # Route Policy and Attribute Trace: IPv4 with every TLV type and an
    # unknown one, IPv6 with an IPv6 policy peer and two events
    ev1 = rp_event(1, [
        tlv(0, struct.pack('>I', 7) + b'vrf-blue'),
        rp_policy_tlv(0x60, bytes((192, 0, 2, 9)),
                      [(b'IMPORT-POLICY', b'10', 0x80), (b'DEFAULT', b'20', 0x40)], cls=1),
        tlv(2, path_attrs()),
        tlv(3, path_attrs((192, 0, 2, 99))),
        tlv(4, b'route accepted'),
        tlv(9, b'\xaa\xbb'),
    ])
    s.send(route_policy(0x00, 24, bytes((10, 1, 2, 0)), [ev1]))
    ev2 = rp_event(2, [rp_policy_tlv(0x80, V6_PEER, [(b'V6-OUT', b'1', 0x00)], cls=8)], afi=2)
    ev3 = rp_event(3, [tlv(4, b'second event')], afi=2)
    s.send(route_policy(0x80, 48, bytes.fromhex('20010db8000100000000000000000000'), [ev2, ev3]))
    # Unknown message type
    s.send(bmp(3, 7, b'\x01\x02\x03\x04'))
    # Termination: string, and each reason code (one TLV per message)
    s.send(bmp(3, 5, tlv(0, b'shutting down')))
    for r in (0, 1, 2, 3, 4, 9):
        s.send(bmp(3, 5, tlv(1, struct.pack('>H', r))))
    s.close()

    # ---- Connection 2: BMP version 4 ------------------------------------
    s = TcpStream(cap, 40002)
    s.send(bmp(4, 4, tlv(0, b'BMPv4 router') + tlv(2, b'router2.example')))
    # Route Monitoring with every BMPv4 TLV (indexed)
    s.send(bmp(4, 0, peer_hdr()
                    + tlv4(1, bgpcap(1, struct.pack('>HBB', 1, 0, 1)), 0)   # stateless parsing
                    + tlv4(2, struct.pack('>HHH', 0x8001, 1, 2), 0)    # group with 2 targets
                    + tlv4(2, struct.pack('>H', 0x8002), 0)            # group with no targets
                    + tlv4(3, b'vrf-v4', 0)                            # VRF/Table name
                    + tlv4(5, struct.pack('>I', 0x7ff), 1)             # path status, all bits
                    + tlv4(5, struct.pack('>IH', 0x2, 4), 1)           # path status + reason
                    + tlv4(4, bgp_update(2, base=20), 0)))             # BGP message
    # Stats and Peer Up use the same code as v3
    st = all_stats()[:3]
    s.send(bmp(4, 1, peer_hdr() + struct.pack('>I', len(st)) + b''.join(st)))
    s.send(bmp(4, 3, peer_hdr() + b'\0' * 12 + bytes((192, 0, 2, 1))
                    + struct.pack('>HH', 179, 50002)
                    + bgp_open(64500, (192, 0, 2, 1)) + bgp_open(64501, (192, 0, 2, 9))))
    # bmp_peer_down_v4_tlv.py: v4 Peer Down reason 1 with a
    # NOTIFICATION and nothing after it (no TLVs parsed from the BGP marker)
    s.send(bmp(4, 2, peer_hdr() + b'\x01' + bgp_notification(6, 2)))
    # v4 Peer Down reasons with TLVs after the reason data
    s.send(bmp(4, 2, peer_hdr() + b'\x01' + bgp_notification(6, 4) + tlv4(3, b'vrf-a')))
    s.send(bmp(4, 2, peer_hdr() + b'\x02' + struct.pack('>H', 7) + tlv4(3, b'vrf-b')
                    + tlv4(4, KEEPALIVE)))
    s.send(bmp(4, 2, peer_hdr() + b'\x03' + bgp_notification(2, 2) + tlv4(1, bgpcap(2, b''))))
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(3, b'vrf-c')))
    # Reason 6: a VRF/Table TLV (decoded by the v3 code), then a BMPv4 TLV
    s.send(bmp(4, 2, peer_hdr() + b'\x06' + tlv(3, b'vrf-d') + tlv4(5, struct.pack('>I', 1))))
    # Reason 6 with a TLV type the v3 code does not know: left to the v4 code
    s.send(bmp(4, 2, peer_hdr() + b'\x06' + tlv4(4, bgp_notification(6, 3))))
    # A Route Monitoring message spread over three segments, one split
    # inside the common header, and two messages in one segment
    m = bmp(4, 0, peer_hdr() + tlv4(4, bgp_update(30, base=30), 0))
    s.send(*split(m, 60, 140))
    m = bmp(3, 0, peer_hdr() + bgp_update(1, base=40))
    s.send(*split(m, 3))
    s.send(bmp(3, 0, peer_hdr() + KEEPALIVE) + bmp(3, 5, tlv(1, b'\x00\x00')))
    s.close()

    cap.write(path)


def malformed_capture(path):
    cap = Pcap()
    s = TcpStream(cap, 40003)
    # Termination with two TLVs: only the first is decoded (not fixed)
    s.send(bmp(3, 5, tlv(0, b'bye') + tlv(1, b'\x00\x02')))
    # Per Peer Header item length taken from the Peer Type and Flags octets
    # (not fixed): bmp_peer_hdr_len.py
    s.send(bmp(3, 0, peer_hdr(0, 0x80, addr=V6_PEER) + KEEPALIVE))
    s.send(bmp(3, 0, peer_hdr(3, 0x00) + KEEPALIVE))
    # BMPv4 VRF/Table name of length 0 and 300 (malformed notes)
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(3, b'')))
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(3, b'v' * 300)))
    # BMPv4 TLVs not fully parsed: path status of length 5, a BGP message
    # shorter than its TLV, a group whose length runs past the message
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(5, b'\x00\x00\x00\x01\x00')))
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(4, KEEPALIVE + b'\0\0')))
    s.send(bmp(4, 0, peer_hdr() + struct.pack('>HHH', 2, 40, 0) + b'\x00\x01'))
    # Truncated messages
    s.send(bmp(3, 0, peer_hdr()[:20]))
    s.send(bmp(3, 1, peer_hdr() + struct.pack('>I', 5) + stat(0, b'\0\0\0\1')))
    s.send(bmp(3, 3, peer_hdr() + b'\0' * 10))
    s.send(bmp(3, 4, tlv(0, b'abc')[:-1] + b''))
    s.send(bmp(3, 4, struct.pack('>HH', 0, 50) + b'short'))
    s.send(bmp(3, 2, peer_hdr() + b'\x02'))
    s.send(bmp(3, 6, peer_hdr() + struct.pack('>HH', 0, 100) + KEEPALIVE))
    s.send(bmp(3, 0x64, b'\x00' * 20))
    # Route Policy event whose TLV lengths do not add up
    ev = rp_event(1, [tlv(4, b'abc')])
    ev = struct.pack('>H', struct.unpack('>H', ev[:2])[0] + 3) + ev[2:]
    s.send(route_policy(0x00, 24, bytes((10, 1, 2, 0)), [ev]))
    # Peer Down reason 6 with a TLV length past the end
    s.send(bmp(3, 2, peer_hdr() + b'\x06' + struct.pack('>HH', 3, 99) + b'x'))
    # Peer Up TLV past the end
    s.send(bmp(3, 3, peer_hdr() + b'\0' * 12 + bytes((192, 0, 2, 1)) + struct.pack('>HH', 1, 2)
                    + bgp_open(1, (1, 1, 1, 1)) + bgp_open(2, (2, 2, 2, 2))
                    + struct.pack('>HH', 0, 99)))
    # An unknown BMPv4 TLV (warning, and "not fully parsed" error since the
    # default case does not step over the value) before a BGP message
    s.send(bmp(4, 0, peer_hdr() + tlv4(77, b'\x01\x02\x03', 0) + tlv4(4, KEEPALIVE, 0)))
    # Unknown BMPv4 TLV in a Peer Down (warning) and a length past the end
    s.send(bmp(4, 2, peer_hdr() + b'\x04' + tlv4(99, b'zz') + struct.pack('>HH', 3, 20) + b'ab'))
    s.close()
    cap.write(path)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(os.path.join(out, 'bmp-coverage.pcap'))
    malformed_capture(os.path.join(out, 'bmp-coverage-malformed.pcap'))

#!/usr/bin/env python3
# Generates test/captures/bpv6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bundle Protocol version
4, 5 and 6 dissector (packet-bpv6.c, protocol "bundle").

All packets are built from scratch with struct; no captured traffic is
used. Bundle agents 192.0.2.1 and 192.0.2.2 exchange bundles on UDP port
4556 and over a TCPCL version 3 session on TCP port 4556. Endpoint IDs
are made up (dtn://node1/..., ipn:1.1 ...).

Usage: mkbpv6.py <output directory>

Writes:
  bpv6-coverage.pcap            every primary header version, CBHE and
                                dictionary EIDs, every extension block
                                type, every administrative record type
                                with and without the fragment flag,
                                CFDP and AMP payloads, the bundle
                                version 7 hand-off, TCPCL transfers with
                                several bundles in one segment, and the
                                reproducers of the fixes on the branch
  bpv6-coverage-malformed.pcap  error paths (bad SDNVs, truncated blocks)
"""

import os
import struct
import sys

PORT = 4556
A = (192, 0, 2, 1)
B = (192, 0, 2, 2)
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IPID = [0]


def ipv4(src, dst, proto, payload):
    IPID[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IPID[0], 0x4000, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def eth(src_ip, payload):
    if src_ip == A:
        return MAC_B + MAC_A + b'\x08\x00' + payload
    return MAC_A + MAC_B + b'\x08\x00' + payload


def udp(payload, src=A, dst=B, sport=PORT, dport=PORT):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = csum(struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 17, len(u)) + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return eth(src, ipv4(src, dst, 17, u))


class Tcp:
    """One TCP connection A:sport -> B:4556 with correct sequence numbers."""

    def __init__(self, sport):
        self.sport = sport
        self.seq = {A: 1000, B: 5000}

    def seg(self, src, flags, payload=b''):
        dst = B if src == A else A
        sp, dp = (self.sport, PORT) if src == A else (PORT, self.sport)
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''     # MSS on SYN
        t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[src], self.seq[dst] if flags & 0x10 else 0,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        c = csum(struct.pack('!4s4sBBH', bytes(src), bytes(dst), 0, 6, len(t)) + t)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        self.seq[src] += len(payload) + (1 if flags & 0x03 else 0)
        return eth(src, ipv4(src, dst, 6, t))


# ---- Bundle building blocks ----

def v4_primary(procflags=0x10, cos=0x01, srr=0x00, offs=None, dict_bytes=None,
               ts=0x000000002a000001, life=3600, frag=None):
    if dict_bytes is None:
        dict_bytes, offs = dictionary()
    body = struct.pack('!8H', *offs) + struct.pack('!QI', ts, life) + sdnv(len(dict_bytes)) + dict_bytes
    if frag is not None:
        body += sdnv(frag[0]) + sdnv(frag[1])
    return bytes([4, procflags, cos, srr]) + sdnv(len(body)) + body


def v56_primary(version=6, flags=0x10, offs=(1, 1, 2, 1, 0, 0, 2, 1), ts=700000000, seq=1,
                life=3600, dict_bytes=b'', frag=None, hdrlen=None):
    body = (b''.join(sdnv(o) for o in offs) + sdnv(ts) + sdnv(seq) + sdnv(life)
            + sdnv(len(dict_bytes)) + dict_bytes)
    if frag is not None:
        body += sdnv(frag[0]) + sdnv(frag[1])
    return bytes([version]) + sdnv(flags) + sdnv(len(body) if hdrlen is None else hdrlen) + body


def dictionary(dst=('dtn', '//node2/app'), src=('dtn', '//node1/app'),
               rpt=('dtn', 'none'), cust=('dtn', '//node1/')):
    """Build a dictionary; returns (bytes, offsets in header order)."""
    d = b''
    pos = {}
    offs = []
    for s in (dst[0], dst[1], src[0], src[1], rpt[0], rpt[1], cust[0], cust[1]):
        if s not in pos:
            pos[s] = len(d)
            d += s.encode() + b'\0'
        offs.append(pos[s])
    return d, tuple(offs)


def v4_payload(data, flags=0x08):
    return bytes([1, flags]) + sdnv(len(data)) + data


def v6_payload(data, flags=0x08):
    return bytes([1]) + sdnv(flags) + sdnv(len(data)) + data


def block(btype, body, flags=0x00, eid_refs=None, length=None):
    b = bytes([btype]) + sdnv(flags)
    if eid_refs is not None:
        b += sdnv(len(eid_refs)) + b''.join(sdnv(s) + sdnv(p) for s, p in eid_refs)
    return b + sdnv(len(body) if length is None else length) + body


def dtn_time(secs, nsecs):
    return sdnv(secs) + sdnv(nsecs)




def status_report(frag, status, reason, eid=b'ipn:2.1', fragfields=(1000, 500)):
    r = bytes([0x10 | (0x01 if frag else 0), status, reason])
    if frag:
        r += sdnv(fragfields[0]) + sdnv(fragfields[1])
    for bit in range(6):
        if status & (1 << bit):
            r += dtn_time(700000100 + bit, 1000 * bit)
    return r + sdnv(700000000) + sdnv(7) + sdnv(len(eid)) + eid


def custody_signal(frag, ok, reason, eid=b'ipn:2.1', fragfields=(2000, 250)):
    r = bytes([0x20 | (0x01 if frag else 0), (0x80 if ok else 0) | reason])
    if frag:
        r += sdnv(fragfields[0]) + sdnv(fragfields[1])
    return r + dtn_time(700000200, 5) + sdnv(700000000) + sdnv(8) + sdnv(len(eid)) + eid


def cfdp_file_data(data=b'hello CFDP'):
    # Version 1 (0x20), file data PDU (0x10), 1 octet entity IDs and
    # transaction sequence number
    pdu = struct.pack('!I', 0) + data
    return bytes([0x30]) + struct.pack('!H', len(pdu)) + bytes([0x00, 0x01, 0x02, 0x03]) + pdu


# CBOR array [timestamp 0, h'00 "agent"']: AMP register-agent message
AMP = bytes.fromhex('8200') + bytes([0x47, 0x00, 0x65]) + b'agent'


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def bpv7():
    # A minimal bundle protocol version 7 bundle (CBOR) with a CRC-16
    # primary block, handed to bpv7
    prim = bytes.fromhex('89' '07' '00' '01' '82028201' '02' '82028201' '01' '820100'
                         '820000' '1a0036ee80' '42')
    crc = crc16_x25(prim + b'\0\0')
    return (b'\x9f' + prim + struct.pack('!H', crc)
            + bytes.fromhex('85' '01' '01' '00' '00' '44') + b'data' + b'\xff')


BPV7 = bpv7()


def tcpcl_contact(eid):
    return b'dtn!' + bytes([3, 0x00]) + struct.pack('!H', 0) + sdnv(len(eid)) + eid


def tcpcl_data(data, flags=0x03):
    return bytes([0x10 | flags]) + sdnv(len(data)) + data


def ltp_green(session, data, client=2):
    # Version 0, green end-of-block data segment (type 7), no extensions
    return (bytes([0x07]) + sdnv(1) + sdnv(session) + b'\x00'
            + sdnv(client) + sdnv(0) + sdnv(len(data)) + data)


def main_frames():
    F = []          # (description, frame)

    def u(desc, payload, src=A):
        F.append((desc, udp(payload, src=src, dst=B if src == A else A)))

    data = bytes.fromhex('2000060000010203040506070809')

    # Reproducer of the stale SSP offsets (bpv6_stale_ssp.py),
    # with a CFDP payload in the version 6 bundle
    u('v4 bundle, dictionary EIDs, data payload (bpv6_stale_ssp frame 1)',
      v4_primary() + v4_payload(data))
    u('v6 bundle, CBHE, SSP offsets 0x40/0x41: CFDP payload (bpv6_stale_ssp frame 2)',
      v56_primary(offs=(1, 0x41, 1, 0x40, 0, 0, 0, 0)) + v6_payload(cfdp_file_data()))
    u('v6 bundle, CBHE, SSP offsets 5/6: AMP payload',
      v56_primary(offs=(2, 6, 1, 5, 0, 0, 0, 0)) + v6_payload(AMP))
    u('v6 bundle, CBHE, SSP offsets 6/5: AMP payload',
      v56_primary(offs=(1, 5, 2, 6, 0, 0, 0, 0)) + v6_payload(AMP), src=B)
    # Version 4 after the CFDP bundle: payload stays data
    d, o = dictionary(dst=('dtn', '//node2/cfdp'), cust=('dtn', 'none'))
    u('v4 bundle, fragment, all flags, dictionary, data payload after a CFDP bundle',
      v4_primary(procflags=0x3d, cos=0x02, srr=0x3f, dict_bytes=d, offs=o, frag=(100, 400))
      + v4_payload(b'v4 data after CFDP', flags=0x0f))
    u('v4 bundle, CBHE (dictionary length 0), ipn EIDs, age block, valid CTEB',
      v4_primary(dict_bytes=b'', offs=(2, 1, 1, 1, 0, 0, 1, 1))
      + block(0x14, sdnv(5000000)) + block(0x0a, sdnv(9) + b'ipn:1.1')
      + v4_payload(b'v4 cbhe'))
    u('v4 bundle, payload block not last, followed by a last unknown block',
      v4_primary() + v4_payload(b'first', flags=0x00) + block(0x30, b'tail', flags=0x08))
    u('v4 bundle, CBHE, dtn:none destination/source, custody signal admin record',
      v4_primary(procflags=0x02, dict_bytes=b'', offs=(0, 0, 0, 0, 3, 4, 5, 6))
      + v4_payload(custody_signal(False, True, 0)))

    # Version 5 with multi-octet control flags
    flags = 0x3d | (0x02 << 7) | (0x1f << 14)
    u('v5 bundle, CBHE, control flags with priority and all report requests, fragment',
      v56_primary(version=5, flags=flags, frag=(10, 1000)) + v6_payload(b'v5 fragment'))
    u('v5 bundle, CBHE, dtn:none source and destination',
      v56_primary(version=5, flags=0x10, offs=(0, 0, 0, 0, 0, 0, 0, 0)) + v6_payload(b'none'))

    # Version 6 with a dictionary and every extension block type
    d, o = dictionary()
    exts = (block(0x02, b'\x01\x02\x03\x04')                       # BAB, not dissected
            + block(0x08, b'\x00meta')                             # metadata, not dissected
            + block(0x09, b'\x05\x06')                             # ESB, not dissected
            + block(0x14, sdnv(123000000))                         # bundle age
            + block(0x05, b'ipn\0' + b'3.1\0')                     # previous hop
            + block(0x20, b'\xaa\xbb', flags=0x40, eid_refs=[(0, 4), (12, 16)])  # unknown, EID references
            + block(0x13, bytes([0x0f, 0x07]) + sdnv(4242), flags=0x01)  # ECOS with flow label
            + block(0x13, bytes([0x03, 0x01]), flags=0x01)         # ECOS without flow label
            + block(0x0a, sdnv(77) + b'dtn://node1/', flags=0x00))  # CTEB, matches the custodian
    u('v6 bundle, dictionary EIDs, fragment, BAB, MEB, ESB, age, previous hop, EID references, ECOS, valid CTEB',
      v56_primary(flags=0x11 | (0x01 << 7), offs=o, dict_bytes=d, frag=(0, 64)) + exts + v6_payload(b'X' * 64))
    u('v6 bundle, payload block not last, followed by a last unknown block',
      v56_primary() + v6_payload(b'first', flags=0x00) + block(0x30, b'tail', flags=0x08))

    # Security blocks
    params = (sdnv(1) + sdnv(4) + b'\x11\x22\x33\x44'              # IV
              + sdnv(3) + sdnv(2) + b'\x55\x66'                    # key information
              + sdnv(4) + sdnv(2) + sdnv(3) + sdnv(9)              # content range
              + sdnv(5) + sdnv(1) + b'\x77'                        # integrity signature
              + sdnv(7) + sdnv(1) + b'\x88'                        # salt
              + sdnv(8) + sdnv(1) + b'\x99'                        # ICV
              + sdnv(2) + sdnv(0))                                 # type 2: not shown
    results = (sdnv(5) + sdnv(4) + b'\xde\xad\xbe\xef'
               + sdnv(4) + sdnv(2) + sdnv(1) + sdnv(2)
               + sdnv(1) + sdnv(1) + b'\x01'
               + sdnv(3) + sdnv(1) + b'\x03'
               + sdnv(7) + sdnv(1) + b'\x07'
               + sdnv(8) + sdnv(1) + b'\x08'
               + sdnv(9) + sdnv(0))
    bib = sdnv(1) + sdnv(0) + sdnv(5) + sdnv(1) + sdnv(len(params)) + params + sdnv(len(results)) + results
    bcb = sdnv(1) + sdnv(0) + sdnv(0xd4) + sdnv(0) + sdnv(6) + sdnv(8) + sdnv(4) + b'\xc0\xff\xee\x00'
    u('v6 bundle, BIB with every parameter and result type, BCB without parameters',
      v56_primary() + block(0x03, bib) + block(0x04, bcb) + v6_payload(b'secured'))

    # Administrative records; the first two are the reproducer
    # bpv6_admin_fragflag.py (not for a fragment / for a fragment)
    eid = b'ipn:1.2'
    rec1 = bytes([0x10, 0x01, 0x00]) + sdnv(1000) + sdnv(5) + sdnv(2000) + sdnv(7) + sdnv(len(eid)) + eid
    rec2 = (bytes([0x21, 0x80]) + sdnv(100) + sdnv(200) + sdnv(3000) + sdnv(0) + sdnv(2000) + sdnv(7)
            + sdnv(len(eid)) + eid)
    u('status report, not for a fragment, received (bpv6_admin_fragflag frame 1)',
      v56_primary(flags=0x02) + v6_payload(rec1), src=B)
    u('custody signal, for a fragment, succeeded (bpv6_admin_fragflag frame 2)',
      v56_primary(flags=0x02) + v6_payload(rec2), src=B)
    u('status report for a fragment, every status flag, reason 4',
      v56_primary(flags=0x02) + v6_payload(status_report(True, 0x3f, 4)), src=B)
    u('status report not for a fragment, deleted, reason 1',
      v56_primary(flags=0x02) + v6_payload(status_report(False, 0x10, 1)), src=B)
    u('custody signal not for a fragment, failed, reason 3',
      v56_primary(flags=0x02) + v6_payload(custody_signal(False, False, 3)), src=B)
    u('custody signal for a fragment, succeeded, reason 0',
      v56_primary(flags=0x02) + v6_payload(custody_signal(True, True, 0)), src=B)
    acs = bytes([0x40, 0x80]) + sdnv(10) + sdnv(5) + sdnv(3) + sdnv(2) + sdnv(200) + sdnv(1)
    u('aggregate custody signal with three fills',
      v56_primary(flags=0x02) + v6_payload(acs), src=B)
    u('announce record', v56_primary(flags=0x02) + v6_payload(b'\x50'), src=B)
    u('administrative record of unknown type 3', v56_primary(flags=0x02) + v6_payload(b'\x30'), src=B)

    # SDNVs above INT_MAX (were one ws_warning each; now truncated quietly)
    u('v6 bundle with timestamp, sequence number and lifetime above INT_MAX',
      v56_primary(ts=0x80000000, seq=0x100000000, life=0xffffffffff) + v6_payload(b'big'))

    # CTEB and ECOS checks (warnings)
    d, o = dictionary()
    u('CTEB custodian of the same length but different, CTEB with replicate set',
      v56_primary(offs=o, dict_bytes=d) + block(0x0a, sdnv(1) + b'dtn://node9/')
      + block(0x0a, sdnv(2) + b'dtn://node1/', flags=0x01) + v6_payload(b'c'))
    u('CTEB custodian of a different length, CTEB with EID references, ECOS without replicate and with EID references',
      v56_primary() + block(0x0a, sdnv(3) + b'ipn:22.1')
      + block(0x0a, sdnv(4) + b'ipn:2.1', flags=0x40, eid_refs=[(1, 2)])
      + block(0x13, bytes([0x00, 0x05]), flags=0x40, eid_refs=[(1, 2)]) + v6_payload(b'e'))
    # Reproducer bpv6_cteb_neglen.py: CTEB block length 0
    u('CTEB block length 0, shorter than the custody ID (bpv6_cteb_neglen)',
      v56_primary(offs=(1, 2, 3, 4, 5, 6, 7, 8)) + bytes([0x0a]) + sdnv(0) + sdnv(0) + sdnv(1)
      + sdnv(0x08) + sdnv(4) + b'ABCD')
    u('previous hop block of 4 octets, no EID', v56_primary() + block(0x05, b'ipn\0', flags=0x08))

    # Not bundle protocol 4-6
    u('bundle protocol version 7, handed to bpv7', BPV7)
    u('version octet 3: not a bundle', b'\x03\x00\x01\x02')
    u('CBOR unsigned integer: not a bundle', b'\x18\x07')
    u('truncated CBOR array: not a bundle', b'\x9f\x9f')

    # TCPCL version 3 session
    t = Tcp(40000)
    F.append(('TCP SYN', t.seg(A, 0x02)))
    F.append(('TCP SYN ACK', t.seg(B, 0x12)))
    F.append(('TCP ACK', t.seg(A, 0x10)))
    F.append(('TCPCL contact header', t.seg(A, 0x18, tcpcl_contact(b'dtn://node1/'))))
    F.append(('TCPCL contact header', t.seg(B, 0x18, tcpcl_contact(b'dtn://node2/'))))
    d, o = dictionary()
    big = v56_primary(offs=o, dict_bytes=d) + block(0x14, sdnv(1000000)) + v6_payload(bytes(range(256)) * 2)
    seg = tcpcl_data(big)
    half = len(seg) // 2
    F.append(('TCPCL DATA_SEGMENT, first TCP segment', t.seg(A, 0x10, seg[:half])))
    F.append(('TCPCL DATA_SEGMENT, second TCP segment: reassembled v6 bundle', t.seg(A, 0x18, seg[half:])))
    F.append(('TCPCL ACK_SEGMENT', t.seg(B, 0x18, bytes([0x20]) + sdnv(len(big)))))
    v4b = v4_primary() + v4_payload(b'over tcpcl')
    F.append(('TCPCL v4 bundle', t.seg(A, 0x18, tcpcl_data(v4b))))
    F.append(('TCPCL ACK_SEGMENT', t.seg(B, 0x18, bytes([0x20]) + sdnv(len(v4b)))))
    F.append(('TCPCL SHUTDOWN', t.seg(A, 0x18, b'\x50')))
    F.append(('TCP ACK', t.seg(B, 0x10)))

    # LTP green end-of-block data segments with Service Data Aggregation
    # (client service 2) carrying several bundles: Info "[multiple]"
    three = b''.join(sdnv(1) + v56_primary(offs=(2, 1, 1, 1, 0, 0, 1, 1), seq=n) + v6_payload(b'b%d' % n)
                     for n in range(3))
    F.append(('LTP SDA block with three CBHE bundles: [multiple]', udp(ltp_green(1, three), sport=1113, dport=1113)))
    two = b''.join(sdnv(1) + v56_primary(offs=o, dict_bytes=d, seq=n) + v6_payload(b'd%d' % n)
                   for n in range(2))
    F.append(('LTP SDA block with two dictionary bundles: [multiple]', udp(ltp_green(2, two), sport=1113, dport=1113)))
    return F


def malformed_frames():
    F = []

    def u(desc, payload):
        F.append((desc, udp(payload)))

    bad = b'\x80' * 11 + b'\x01'      # SDNV that does not terminate within 10 octets
    offs8 = b''.join(sdnv(x) for x in (1, 2, 3, 4, 5, 6, 7, 8))
    # Reproducer bpv6_errpath_offset.py (unfixed: length used as offset)
    body = offs8 + sdnv(1) + sdnv(1) + sdnv(3600) + bad
    u('v6 dictionary length SDNV error (bpv6_errpath_offset)',
      bytes([6, 0]) + sdnv(len(body)) + body + b'\x00' * 8 + bytes([1]) + sdnv(8) + sdnv(4) + b'WXYZ')
    u('v6 control flags SDNV too long', bytes([6]) + bad + b'\x00' * 4)
    u('v6 header length SDNV error', bytes([6, 0]) + bad + b'\x00' * 30)
    u('v4 header length SDNV error', bytes([4, 0, 0, 0]) + bad + b'\x00' * 30)
    u('v4 dictionary length SDNV error', bytes([4, 0, 0, 0, 40]) + b'\x00' * 28 + bad + b'\x00' * 8)
    u('v6 dictionary offsets beyond the header length',
      v56_primary(offs=(100,) * 8, dict_bytes=b'dtn\0', hdrlen=20) + v6_payload(b'x'))
    u('v6 timestamp SDNV error', bytes([6, 0, 30]) + offs8 + bad)
    u('v6 sequence number SDNV error', bytes([6, 0, 30]) + offs8 + sdnv(1) + bad + b'\x00' * 4)
    u('v6 lifetime SDNV error', bytes([6, 0, 30]) + offs8 + sdnv(1) + sdnv(1) + bad + b'\x00' * 4)
    u('v6 fragment offset SDNV error', v56_primary(flags=0x01) + bad)
    u('payload length SDNV error', v56_primary() + bytes([1, 8]) + bad)
    u('extension block length SDNV error', v56_primary() + bytes([0x14, 0]) + bad)
    u('EID reference SDNV error', v56_primary() + bytes([0x20, 0x40, 2]) + bad)
    u('EID reference SDNV error (second)', v56_primary() + bytes([0x20, 0x40, 2, 1]) + bad)
    u('previous hop block length 2', v56_primary() + block(0x05, b'ip', flags=0x08) + b'n\0')
    u('ECOS flow label SDNV error', v56_primary() + bytes([0x13, 0x01, 20, 0x04, 0x01]) + bad)
    u('BIB parameters length SDNV error', v56_primary() + bytes([0x03, 0x08, 20, 1, 0, 1, 1]) + bad)
    u('BIB parameter item length SDNV error', v56_primary() + bytes([0x03, 0x08, 20, 1, 0, 1, 1, 10, 1]) + bad)
    u('BIB result item length SDNV error', v56_primary() + bytes([0x03, 0x08, 20, 1, 0, 1, 0, 10, 1]) + bad)
    u('BIB truncated', v56_primary() + bytes([0x03, 0x08, 20, 1, 0, 1, 0, 50, 1, 40]))
    u('unknown block runs past the packet', v56_primary() + block(0x30, b'\x00', length=100))
    u('last block flag missing', v56_primary() + v6_payload(b'abc', flags=0))

    # Administrative record error paths
    def adm(rec, n=None):
        return v56_primary(flags=0x02) + bytes([1, 8]) + sdnv(len(rec) if n is None else n) + rec
    u('status report fragment offset SDNV error', adm(bytes([0x11, 0, 0]) + bad))
    u('status report fragment length SDNV error', adm(bytes([0x11, 0, 0, 1]) + bad))
    for bit in range(6):
        u('status report time %d SDNV error' % bit,
          adm(bytes([0x10, 1 << bit, 0]) + (bad if bit % 2 == 0 else sdnv(1) + bad)))
    u('status report timestamp copy SDNV error', adm(bytes([0x10, 0, 0]) + bad))
    u('status report sequence SDNV error', adm(bytes([0x10, 0, 0, 1]) + bad))
    u('status report endpoint length SDNV error', adm(bytes([0x10, 0, 0, 1, 1]) + bad))
    u('status report endpoint past the end', adm(bytes([0x10, 0, 0, 1, 1, 100]) + b'ipn'))
    u('custody signal fragment offset SDNV error', adm(bytes([0x21, 0]) + bad))
    u('custody signal fragment length SDNV error', adm(bytes([0x21, 0, 1]) + bad))
    u('custody signal time SDNV error', adm(bytes([0x20, 0]) + bad))
    u('custody signal timestamp copy SDNV error', adm(bytes([0x20, 0, 1, 1]) + bad))
    u('custody signal sequence SDNV error', adm(bytes([0x20, 0, 1, 1, 1]) + bad))
    u('custody signal endpoint length SDNV error', adm(bytes([0x20, 0, 1, 1, 1, 1]) + bad))
    u('ACS start SDNV error', adm(bytes([0x40, 0]) + bad))
    u('ACS length SDNV error', adm(bytes([0x40, 0, 1]) + bad))
    u('ACS gap SDNV error', adm(bytes([0x40, 0, 1, 1]) + bad, n=30))
    u('ACS gap length SDNV error', adm(bytes([0x40, 0, 1, 1, 1]) + bad, n=30))
    u('ACS past the payload length', adm(bytes([0x40, 0, 1, 1, 1, 1]), n=5))
    u('payload of an admin record truncated', adm(bytes([0x10]), n=1)[:-1])
    u('empty bundle version 6', b'\x06')
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (_, fr) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, frames in (('bpv6-coverage.pcap', main_frames()),
                         ('bpv6-coverage-malformed.pcap', malformed_frames())):
        write_pcap(os.path.join(out, name), frames)
        if '-v' in sys.argv:
            print(name)
            for i, (desc, _) in enumerate(frames, 1):
                print('%3d %s' % (i, desc))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/avsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the AVSP dissector (packet-avsp.c).

Arista Vendor Specific Protocol, ethertype 0xD28B, also carried in GRE
(gre.proto 0xD28B). Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkavsp.py <output directory>

Writes:
  avsp-coverage.pcap            every subtype and version, GREENT with 0, 1,
                                2 and 3 samples, TGen payload lengths that fit,
                                leave a trailer and run past the frame, AVSP in
                                GRE, AVSP nested in AVSP, and the 300-level
                                nesting reproducer (frame noted in the README)
  avsp-coverage-malformed.pcap  unknown subtype and versions, truncated
                                headers and samples
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
ETH_AVSP = 0xD28B


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=(192, 0, 2, 1), dst=(198, 51, 100, 1), ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, data, src=(192, 0, 2, 1), dst=(198, 51, 100, 1)):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def udp_pkt(seq=1, data=b'avsp-test'):
    """An IPv4 UDP datagram to the discard port: an inner payload that
    decodes cleanly. The source port carries seq to tell them apart."""
    return ipv4(17, udp(40000 + seq, 9, data), ident=seq)


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload


def inner_eth(seq=1, data=b'avsp-test'):
    """An inner Ethernet frame (for DzGRE and GREENT samples)."""
    return eth(bytes.fromhex('020000000004'), bytes.fromhex('020000000003'),
               0x0800, udp_pkt(seq, data))


def avsp_frame(avsp):
    return eth(MAC_B, MAC_A, ETH_AVSP, avsp)


# AVSP headers -------------------------------------------------------------

def ts64(version, sec, ns, etype):
    return struct.pack('>HHIIH', 0x0001, version, sec, ns, etype)


def ts48(version, sec, ns, etype):
    return struct.pack('>HHHIH', 0x0001, version, sec, ns, etype)


def greentap(version, session, sec, ns, etype):
    # As the dissector reads it: no Session ID, 16 bit seconds, 32 bit ns.
    # The layout comment in packet-avsp.c has a Session ID before the
    # seconds; the session argument is ignored here (see README).
    return struct.pack('>HHHIH', 0x0003, version, sec, ns, etype)


def greent_sample(sec, ns, ingress, egress, rate, cksum, data):
    return (struct.pack('>HHIIIHH', len(data), sec, ns, ingress, egress, rate, cksum)
            + data + b'\0' * ((-len(data)) % 4))


def greent(session, flags, samples, count=None):
    if count is None:
        count = len(samples)
    return struct.pack('>HHHBB', 0x0004, 0x0001, session, flags, count) + b''.join(samples)


def dzgre_a(switch, port, policy, reserved=0):
    return struct.pack('>HHHHHH', 0x0007, 0x0001, switch, port, policy, reserved)


def dzgre_b(port, policy):
    return struct.pack('>HHHH', 0x0008, 0x0001, port, policy)


def dzgre_ts(version, switch, port, policy, sec, ns, reserved=0):
    return struct.pack('>HHHHHHII', 0x0009, version, switch, port, policy, reserved, sec, ns)


def tgen(ctrl, seq, plen, payload):
    return struct.pack('>HHHHH', 0xCAFE, 0x0001, ctrl, seq, plen) + payload


def gre_ipv4(avsp):
    """Outer Ethernet / IPv4 / GRE (proto 0xD28B) / AVSP."""
    gre = struct.pack('>HH', 0, ETH_AVSP) + avsp
    return eth(MAC_B, MAC_A, 0x0800, ipv4(47, gre, src=(10, 1, 0, 1), dst=(10, 1, 0, 2)))


# pcap writer ----------------------------------------------------------------

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main_frames():
    F = []
    # 1-8: timestamp subtype, every version, inner IPv4 UDP datagram
    for n, v in enumerate((0x0010, 0x0011, 0x0110, 0x0111)):
        F.append(avsp_frame(ts64(v, 1000 + n, 500000000 + n, 0x0800) + udp_pkt(10 + n)))
    for n, v in enumerate((0x0020, 0x0021, 0x0120, 0x0121)):
        F.append(avsp_frame(ts48(v, 2000 + n, 600000000 + n, 0x0800) + udp_pkt(20 + n)))
    # 9: timestamp with a trailer after the inner IPv4 packet (avsp.trailer)
    F.append(avsp_frame(ts64(0x0010, 1, 2, 0x0800) + udp_pkt(30) + b'\xde\xad\xbe\xef'))
    # 10-11: GRE TAP, TAI and UTC
    F.append(avsp_frame(greentap(0x0020, 0, 3000, 700000000, 0x0800) + udp_pkt(40)))
    F.append(avsp_frame(greentap(0x0120, 0, 3001, 700000001, 0x0800) + udp_pkt(41)))
    # 12: GREENT with one sample
    F.append(avsp_frame(greent(5, 0x80, [greent_sample(10, 20, 101, 102, 4, 0x1111,
                                                       inner_eth(50))])))
    # 13: GREENT reproducer: two samples of 36 octets (as in
    # avsp_greent_offset.py frame 1); sample 2 is
    # ingress 2222 / egress 2223
    inner36 = (bytes.fromhex('020000000004020000000003') + struct.pack('>H', 0x0800)
               + bytes.fromhex('4500001c000100004011f7cec0000201c6336401') + b'\0' * 2)
    F.append(avsp_frame(greent(7, 0, [greent_sample(10, 20, 1111, 1112, 1, 0xabcd, inner36),
                                      greent_sample(10, 20, 2222, 2223, 1, 0xabcd, inner36)])))
    # 14: GREENT with no samples
    F.append(avsp_frame(greent(8, 0, [])))
    # 15: GREENT with three samples, lengths not a multiple of 4 (padding),
    # the last one a truncated sampled header (bounds error caught inside)
    s1 = inner_eth(51, b'x')            # 14 + 20 + 8 + 1 = 43 octets
    s2 = inner_eth(52, b'abcdef')       # 48 octets
    s3 = inner_eth(53, b'0123456789')[:30]  # cut inside the IPv4 header
    F.append(avsp_frame(greent(9, 0x01, [greent_sample(11, 21, 201, 202, 8, 0x2222, s1),
                                         greent_sample(12, 22, 203, 204, 8, 0x3333, s2),
                                         greent_sample(13, 23, 205, 206, 8, 0x4444, s3)])))
    # 16-19: DzGRE plan A, plan B, timestamped TAI and UTC
    F.append(avsp_frame(dzgre_a(100, 200, 300, 0xbeef) + inner_eth(60)))
    F.append(avsp_frame(dzgre_b(201, 301) + inner_eth(61)))
    F.append(avsp_frame(dzgre_ts(0x0011, 101, 202, 303, 4000, 800000000, 0x1234) + inner_eth(62)))
    F.append(avsp_frame(dzgre_ts(0x0111, 102, 203, 304, 4001, 800000001, 0x5678) + inner_eth(63)))
    # 20: TGen, payload length equal to the data, FCS inverted bit clear
    F.append(avsp_frame(tgen(0x0000, 1, 48, bytes(range(48)))))
    # 21: TGen, FCS inverted and reserved bits set, payload shorter than the
    # frame: the rest becomes the Ethernet trailer (set_actual_length)
    F.append(avsp_frame(tgen(0x0003, 2, 4, b'ABCD' + bytes(44))))
    # 22: TGen, payload length past the end of the frame: the payload is
    # whatever was captured
    F.append(avsp_frame(tgen(0x0001, 3, 1000, bytes(range(46)))))
    # 23: TGen with one octet of payload ("1 byte")
    F.append(avsp_frame(tgen(0x0000, 4, 1, b'Z' + bytes(45))))
    # 24-27: AVSP over GRE: timestamp, GRE TAP, DzGRE(B), TGen
    F.append(gre_ipv4(ts64(0x0110, 5000, 900000000, 0x0800) + udp_pkt(70)))
    F.append(gre_ipv4(greentap(0x0120, 0, 5001, 900000001, 0x0800) + udp_pkt(71)))
    F.append(gre_ipv4(dzgre_b(7, 8) + inner_eth(72)))
    F.append(gre_ipv4(tgen(0x0000, 5, 8, b'GRE-TGEN')))
    # 28: AVSP in AVSP: timestamp, then GRE TAP, then DzGRE(A), then an inner Ethernet frame
    F.append(avsp_frame(ts64(0x0010, 6000, 1, ETH_AVSP) + greentap(0x0020, 0, 6001, 2, ETH_AVSP)
                        + dzgre_a(1, 2, 3) + inner_eth(80)))
    # 29: the nesting reproducer (avsp_recursion.py): 300 nested
    # 64-bit TAI timestamp headers; stops with avsp.too_deep
    lvl = ts64(0x0010, 1, 2, ETH_AVSP)
    F.append(avsp_frame(lvl * 300 + b'\0' * 16))
    # 30-31: GRE TAP UTC and TAI carrying ethertype 0x1234 (not in
    # etype_vals, no dissector), so the AVSP Info text is kept
    F.append(avsp_frame(greentap(0x0120, 0, 7000, 3, 0x1234) + b'unregistered-etype--' + bytes(20)))
    F.append(avsp_frame(greentap(0x0020, 0, 7001, 4, 0x1234) + b'unregistered-etype--' + bytes(20)))
    return F


def malformed_frames():
    F = []
    # 1: unknown subtype
    F.append(avsp_frame(struct.pack('>HH', 0x0042, 1) + bytes(46)))
    # 2-8: unknown version of each subtype
    F.append(avsp_frame(struct.pack('>HH', 0x0001, 0x0099) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0x0003, 0x0099) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0x0004, 0x0002) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0x0007, 0x0002) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0x0008, 0x0002) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0x0009, 0x0099) + bytes(46)))
    F.append(avsp_frame(struct.pack('>HH', 0xCAFE, 0x0002) + bytes(46)))
    # 9: only a subtype
    F.append(avsp_frame(struct.pack('>H', 0x0001)))
    # 10: timestamp cut inside the seconds
    F.append(avsp_frame(struct.pack('>HHH', 0x0001, 0x0010, 0)))
    # 11: GREENT sample length past the end of the frame
    F.append(avsp_frame(greent(1, 0, [struct.pack('>HHIIIHH', 200, 1, 2, 3, 4, 5, 6) + bytes(20)])))
    # 12: GREENT sample count larger than the samples present
    F.append(avsp_frame(greent(2, 0, [greent_sample(1, 2, 3, 4, 5, 6, inner_eth(1))], count=5)))
    # 13: TGen cut inside its header
    F.append(avsp_frame(struct.pack('>HHHH', 0xCAFE, 1, 0, 1)))
    # 14: DzGRE timestamped cut inside the timestamp
    F.append(avsp_frame(struct.pack('>HHHHHHH', 0x0009, 0x0111, 1, 2, 3, 0, 0)))
    # 15: GRE TAP with no ethertype after the timestamp
    F.append(avsp_frame(struct.pack('>HHHI', 0x0003, 0x0020, 1, 2)))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'avsp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'avsp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

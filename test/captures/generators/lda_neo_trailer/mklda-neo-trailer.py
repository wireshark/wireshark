#!/usr/bin/env python3
# Generates test/captures/lda_neo_trailer_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LDA Neo Device trailer
dissector (packet-lda-neo-trailer.c). The 16 octet trailer follows the
payload of an Ethernet frame (signature "L", sequence number, CRC and
device ID, PCS code, port and speed, 80 bit picosecond timestamp) and is
found by the eth.trailer heuristic. Every packet is built with struct;
nothing comes from a real network.

Usage: mklda-neo-trailer.py <output directory>

Writes:
  lda-neo-trailer-coverage.pcap            valid trailers: 10G, 25G, 40G
                                           ports 49-56 (lane), CRC flag,
                                           device IDs, trailers after
                                           padding and decoy 'L' bytes
  lda-neo-trailer-coverage-malformed.pcap  invalid PCS code on 40G, port
                                           ID and speed (error expert
                                           infos), rejected timestamps
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src=IP_A, dst=IP_B, ident=1):
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def l4_sum(proto, src, dst, seg):
    ph = src + dst + struct.pack('>BBH', 0, proto, len(seg))
    return csum(ph + seg)


def udp_frame(sport, dport, payload, to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = l4_sum(17, src, dst, seg) or 0xffff
    seg = seg[:6] + struct.pack('>H', c) + seg[8:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(17, seg, src, dst, ident)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      0x50, flags, 8192, 0, 0) + payload
    seg = seg[:16] + struct.pack('>H', l4_sum(6, src, dst, seg)) + seg[18:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(6, seg, src, dst, ident)


class TcpFlow:
    """One TCP connection; data() returns frames with correct seq/ack."""

    def __init__(self, cport, sport, isn_c=1000, isn_s=5000):
        self.c, self.s = cport, sport
        self.seq_c, self.seq_s = isn_c, isn_s
        self.n = 0

    def _id(self):
        self.n += 1
        return self.n

    def open(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, 0, 0x02, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x12, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f

    def data(self, payload, from_client=True):
        if from_client:
            fr = tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x18, payload, True, self._id())
            self.seq_c += len(payload)
        else:
            fr = tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x18, payload, False, self._id())
            self.seq_s += len(payload)
        return fr

    def close(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x11, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x11, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f


def trailer(seq=1, crc_bad=False, dev=0, pcs33=False, pcs_pos=0, port=1, speed=0,
            secs=1700000000, ns=0, ps=0, sig=b'L', raw_ts=None):
    """16 octet LDA Neo trailer: signature, 16 bit sequence number,
    CRC/device ID, PCS, port/speed and an 80 bit big endian timestamp in
    picoseconds since the epoch."""
    t = sig + struct.pack('>H', seq)
    t += bytes([(dev << 1) | int(crc_bad)])
    t += bytes([(pcs_pos << 2) | int(pcs33)])
    t += bytes([(speed << 6) | port])
    if raw_ts is None:
        raw_ts = ((secs * 1000000000 + ns) * 1000 + ps).to_bytes(10, 'big')
    return t + raw_ts


def frame(i, trl, pad=b'', sport=40500):
    """UDP/IPv4 frame with `pad` and the trailer after the IP datagram
    (the Ethernet trailer); frame i is stamped 1700000000 + i by pcap()."""
    return udp_frame(sport, 40501, b'payload-%02d' % i + b'.' * 12, True, i + 1) + pad + trl


def main_frames():
    F = []
    ts = lambda i: 1700000000 + i       # the capture time of frame i (0 based)
    # 10G ports, PCS code 33 set and clear, CRC valid and invalid
    F.append(frame(0, trailer(1, port=1, speed=0, secs=ts(0), ns=1500, ps=7)))
    F.append(frame(1, trailer(2, crc_bad=True, dev=5, pcs33=True, pcs_pos=17,
                              port=2, speed=0, secs=ts(1), ns=999999999, ps=999)))
    # 25G port
    F.append(frame(2, trailer(0xffff, dev=127, pcs33=True, pcs_pos=63, port=48,
                              speed=1, secs=ts(2))))
    # 40G ports: 49 (the minimum, lane 0) to 56, PCS code clear
    for n, port in enumerate(range(49, 57)):
        F.append(frame(3 + n, trailer(10 + n, port=port, speed=2, secs=ts(3 + n),
                                      ns=n * 1000)))
    # port 0 (below the 40G range, no lane)
    F.append(frame(11, trailer(20, port=0, speed=0, secs=ts(11))))
    # trailer after padding bytes (offset > 0)
    F.append(frame(12, trailer(21, port=3, secs=ts(12)), pad=b'\0' * 6))
    # a decoy 'L' in the padding whose timestamp is not within a month of the
    # frame, followed by the real trailer
    F.append(frame(13, trailer(22, port=51, speed=2, secs=ts(13)),
                   pad=b'\0\0' + b'L' + b'\0' * 15 + b'\0' * 3))
    # a decoy 'L' whose "timestamp" has the high bits set
    F.append(frame(14, trailer(23, port=4, secs=ts(14)),
                   pad=b'L' + b'\xff' * 15))
    # a frame with other padding and no trailer at all (short frame)
    F.append(udp_frame(40500, 40501, b'x' * 4, True, 16))
    # a frame whose trailer has the wrong signature
    F.append(frame(16, trailer(24, port=5, secs=ts(16), sig=b'M')))
    return F


def malformed_frames():
    F = []
    ts = lambda i: 1700000000 + i
    # PCS code 33 set on 40G ports 49 and 56 (invalid)
    F.append(frame(0, trailer(1, pcs33=True, port=49, speed=2, secs=ts(0))))
    F.append(frame(1, trailer(2, pcs33=True, port=56, speed=2, secs=ts(1)), pad=b'\0' * 4))
    # port ID above 56 (invalid)
    F.append(frame(2, trailer(3, port=57, speed=0, secs=ts(2))))
    F.append(frame(3, trailer(4, port=63, speed=1, secs=ts(3)), pad=b'\0' * 3))
    # port speed 3 (invalid)
    F.append(frame(4, trailer(5, port=1, speed=3, secs=ts(4))))
    # everything invalid at once, with padding before the trailer
    F.append(frame(5, trailer(6, pcs33=True, port=52, speed=3, secs=ts(5)), pad=b'\0' * 5))
    F.append(frame(6, trailer(7, pcs33=True, port=60, speed=3, secs=ts(6)), pad=b'\0' * 5))
    # timestamp more than a month from the frame: rejected (accepted when
    # the validation preference is off)
    F.append(frame(7, trailer(8, port=1, secs=ts(7) + 40 * 86400)))
    F.append(frame(8, trailer(9, port=1, secs=ts(8) - 40 * 86400)))
    # 80 bit timestamp too large for 64 bit nanoseconds / datetime
    F.append(frame(9, trailer(10, port=1, raw_ts=b'\xff' * 10)))
    # frame shorter than the trailer is not considered
    F.append(udp_frame(40500, 40501, b'', True, 11))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'lda-neo-trailer-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'lda-neo-trailer-coverage-malformed.pcap'), malformed_frames())


main()

#!/usr/bin/env python3
# ALP coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ATSC 3.0 Link-Layer Protocol (packet-alp.c, A/330).

Usage: mkalp.py [<output directory>]

Writes:
  alp-coverage.pcap            link type 289 (ATSC ALP): IPv4, compressed
                               IPv4 and reserved packet types, single,
                               segmented and concatenated packets, sub-stream
                               identification, the Sony header extensions
                               (also with a time whose milliseconds carry
                               into the seconds), signalling packets with
                               a Link Mapping Table, and MPEG-2 transport
                               stream packets
  alp-coverage-malformed.pcap  packets that run out of data

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import ipv4, udp, write_pcap  # noqa: E402

LINKTYPE_ATSC_ALP = 289

SRC = bytes([198, 51, 100, 1])
DST = bytes([239, 0, 0, 1])


def ip_packet(payload=b'alp payload', sport=1000, dport=2000):
    return ipv4(udp(payload, sport, dport, src=SRC, dst=DST), 17, src=SRC, dst=DST)


def single(ptype, payload, sif=None, hef=None, he=b''):
    """Packet with payload configuration 0 and header mode 1 (single packet,
    3 octet header). sif is a sub-stream id, he a header extension."""
    v = (ptype << 21) | (0 << 20) | (1 << 19) | (len(payload) << 3)
    v |= (2 if sif is not None else 0) | (1 if he else 0)
    out = struct.pack('>I', v)[1:]
    if sif is not None:
        out += bytes([sif])
    return out + he + payload


def plain(ptype, payload):
    """Payload configuration 0, header mode 0: 2 octet header."""
    return struct.pack('>H', (ptype << 13) | len(payload)) + payload


def segment(ptype, payload, ssn, last, sif=None, he=b''):
    """Payload configuration 1, segmentation (sc=0)."""
    v = (ptype << 13) | (1 << 12) | len(payload)
    out = struct.pack('>H', v)
    out += bytes([(ssn << 3) | (4 if last else 0) | (2 if sif is not None else 0) | (1 if he else 0)])
    if sif is not None:
        out += bytes([sif])
    return out + he + payload


def concat(ptype, payload, count, sif=None, he=b''):
    """Payload configuration 1, concatenation (sc=1): count length fields of
    12 bits follow the 3 octet header (the dissector skips them)."""
    v = (ptype << 21) | (1 << 20) | (1 << 19) | (len(payload) << 4) | (count << 1)
    v |= 1 if sif is not None else 0
    out = struct.pack('>I', v)[1:]
    out += bytes(range(0x10, 0x10 + (count * 12 + (4 if count & 1 else 0)) // 8))
    if sif is not None:
        out += bytes([sif])
    return out + payload


def he_ext(htype, data):
    return bytes([htype, len(data) - 1]) + data


def sony_time(sec, ms, us, ns, flag=2):
    t = (flag << 62) | (sec << 30) | (ms << 20) | (us << 10) | ns
    return he_ext(0xF0, struct.pack('>Q', t))


def mc(sid=None, comp=None, dst=(239, 0, 0, 1), dport=2000):
    e = bytes([198, 51, 100, 1]) + bytes(dst) + struct.pack('>HH', 1000, dport)
    e += bytes([(0x80 if sid is not None else 0) | (0x40 if comp is not None else 0) | 0x01])
    if sid is not None:
        e += bytes([sid])
    if comp is not None:
        e += bytes([comp])
    return e


def plp(pid, mcs):
    return bytes([pid << 2 | 1, len(mcs)]) + b''.join(mcs)


def lmt(plps):
    return bytes([(len(plps) - 1) << 2 | 2]) + b''.join(plps)


def sig_info(stype, body, version=1, fmt=0, enc=0, ext=0):
    return bytes([stype]) + struct.pack('>H', ext) + bytes([version, (fmt << 6) | (enc << 4)]) + body


def signalling(body, length=None, sif=None, he=b''):
    """A signalling packet (type 4) with header mode 1. The length field
    is the length of the signalling information and what follows it."""
    if length is None:
        length = len(body)
    v = (4 << 21) | (1 << 19) | (length << 3) | (2 if sif is not None else 0) | (1 if he else 0)
    out = struct.pack('>I', v)[1:]
    if sif is not None:
        out += bytes([sif])
    return out + he + body


_cc = [0]


def ts_packets(n, pid=0x100, fill=0xff):
    """n transport stream packets of one PID with a running continuity
    counter, so the transport stream dissector sees no gaps."""
    out = []
    for _ in range(n):
        out.append(bytes([0x47, pid >> 8, pid & 0xff, 0x10 | (_cc[0] & 0xf)]) + bytes([fill]) * 184)
        _cc[0] += 1
    return out


def mpegts(numts, packets, ahf=False, hdm=False, dnp=0, tail=b''):
    """numts is the field value (0 means 16). packets are 188 octet TS
    packets: the first goes out whole (without its sync byte), the others
    without a header when hdm is set."""
    out = bytes([0xE0 | (numts << 1) | (1 if ahf else 0)])
    if ahf:
        out += bytes([(0x80 if hdm else 0) | dnp])
    out += packets[0][1:]
    for p in packets[1:]:
        out += p[4:] if hdm else p[1:]
    return out + tail


def coverage_packets():
    f = []
    ip = ip_packet()
    # IPv4 packets: header mode 0 and 1, with sub-stream id and extensions
    f.append(plain(0, ip))
    f.append(single(0, ip))
    f.append(single(0, ip, sif=7))
    f.append(single(0, ip, he=sony_time(1000000, 5, 6, 7)))
    f.append(single(0, ip, sif=9, he=he_ext(0xF1, bytes([0x54]))))
    f.append(single(0, ip, he=he_ext(0x42, b'extension data')))
    f.append(single(0, ip, he=he_ext(0xF0, b'\x01\x02\x03')))          # Sony type, other length
    f.append(single(0, ip, he=he_ext(0xF1, b'\x01\x02')))
    # The milliseconds of the Sony time carry into the seconds
    f.append(single(0, ip, he=sony_time(1000000, 1023, 999, 999)))
    f.append(single(0, ip, he=sony_time(1000000, 999, 999, 999)))
    f.append(single(0, ip, he=sony_time(2000000000, 0, 0, 0, flag=0)))
    # Other packet types: compressed IPv4, the reserved ones, extension
    for t in (1, 2, 3, 5, 6):
        f.append(plain(t, b'type %d payload' % t))
    f.append(single(2, b'compressed ip', sif=1))
    # Segmentation and concatenation
    f.append(segment(0, ip[:20], 0, False))
    f.append(segment(0, ip[20:], 1, True, sif=3))
    f.append(segment(0, b'segment with header extension', 2, True, he=he_ext(0xF1, bytes([0x08]))))
    f.append(segment(2, b'segment, sid and extension', 31, False, sif=4, he=he_ext(0x42, b'xx')))
    for count in range(8):
        f.append(concat(0, b'concatenated %d' % count, count))
    f.append(concat(0, b'with sid', 2, sif=5))
    # A packet with junk after it
    f.append(single(0, ip) + b'junk')
    f.append(single(0, ip) + b'j')
    f.append(single(0, b''))
    # Signalling: Link Mapping Table
    f.append(signalling(sig_info(1, lmt([plp(1, [mc(1, 1), mc(), mc(sid=2), mc(comp=3)])]))))
    f.append(signalling(sig_info(1, lmt([plp(1, [mc()]), plp(2, []), plp(3, [mc(5, 6)])])), sif=1))
    f.append(signalling(sig_info(1, lmt([plp(63, [mc(255, 255, dst=(239, 255, 255, 250), dport=65535)])]),
                                 version=2, fmt=1, enc=1, ext=0x1234),
                        he=sony_time(10, 1023, 0, 0)))
    f.append(signalling(sig_info(1, lmt([plp(i, [mc()]) for i in range(64)]), fmt=2, enc=2)))
    f.append(signalling(sig_info(2, b'ROHC-U description table', fmt=3, enc=3)))
    f.append(signalling(sig_info(0x7f, b'')))
    f.append(plain(4, b'') + sig_info(1, lmt([plp(1, [mc()])])))                # header mode 0
    # MPEG-2 transport stream
    f.append(mpegts(1, ts_packets(1)))
    f.append(mpegts(3, ts_packets(3), tail=b'x'))
    f.append(mpegts(2, ts_packets(2), tail=b'tail bytes'))
    f.append(mpegts(2, ts_packets(2), ahf=True, hdm=False, dnp=3))
    f.append(mpegts(3, ts_packets(3), ahf=True, hdm=True, dnp=5))
    f.append(mpegts(4, ts_packets(4), ahf=True, hdm=True, dnp=1))
    # Header deletion: the first header is kept, the others follow from the
    # continuity counter
    f.append(mpegts(5, ts_packets(5), ahf=True, hdm=True, dnp=2))
    f.append(mpegts(0, ts_packets(16), ahf=True, hdm=False, dnp=127))
    # No header: 16 packets and the default 128 deleted null packets
    f.append(mpegts(0, ts_packets(16), ahf=True, hdm=False, dnp=0))
    f.append(mpegts(0, ts_packets(16), ahf=True, hdm=True, dnp=0))
    f.append(mpegts(0, ts_packets(16)))
    return f


def malformed_packets():
    ip = ip_packet()
    f = []
    # A signalling packet whose length field is longer than the packet
    f.append(signalling(sig_info(1, lmt([plp(1, [mc()])])), length=200))
    f.append(signalling(sig_info(1, lmt([plp(1, [mc()])])), length=0))
    # Packets cut short: header, sub-stream id, extension, Link Mapping
    # Table and transport stream packets
    f.append(single(0, ip)[:2])
    f.append(single(0, ip, sif=1)[:3])
    f.append(single(0, ip, he=sony_time(1, 2, 3, 4))[:6])
    f.append(single(0, ip, he=sony_time(1, 2, 3, 4))[:11])
    f.append(signalling(sig_info(1, lmt([plp(1, [mc(1, 1)])]))[:20]))
    f.append(signalling(sig_info(1, b''))[:8])
    f.append(signalling(sig_info(1, lmt([plp(1, [mc()])]))[:10]))
    f.append(concat(0, b'x', 7)[:6])
    f.append(segment(0, b'x', 1, True)[:2])
    f.append(b'\xe0')
    f.append(b'\xe1')
    f.append(mpegts(3, ts_packets(3))[:300])
    f.append(mpegts(2, ts_packets(2), ahf=True, hdm=True, dnp=1)[:100])
    f.append(plain(0, ip)[:1])
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    ts = lambda i: (1700000000 + i, 0)
    write_pcap(os.path.join(out, 'alp-coverage.pcap'), coverage_packets(),
               linktype=LINKTYPE_ATSC_ALP, ts=ts)
    write_pcap(os.path.join(out, 'alp-coverage-malformed.pcap'), malformed_packets(),
               linktype=LINKTYPE_ATSC_ALP, ts=ts)


if __name__ == '__main__':
    main()

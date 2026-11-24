#!/usr/bin/env python3
# Generates test/captures/stt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the STT coverage captures: mkstt.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
import socket
from c17lib import Cap, eth, ipv4, ipv6, csum

SRC4, DST4 = '192.0.2.1', '192.0.2.2'
SRC6, DST6 = '2001:db8::1', '2001:db8::2'

def tcp_ck(seg, v6):
    """TCP checksum of a segment (checksum field zero) with the pseudo header."""
    if v6:
        ph = socket.inet_pton(socket.AF_INET6, SRC6) + socket.inet_pton(socket.AF_INET6, DST6) + struct.pack('>II', len(seg), 6)
    else:
        ph = socket.inet_aton(SRC4) + socket.inet_aton(DST4) + struct.pack('>BBH', 0, 6, len(seg))
    return csum(ph + seg)

def stt_tcp(pkt_len, seg_off, pkt_id, flags=0x010, sid=0x1234, dport=7471, doff=5, window=0xffff, urg=0):
    """The 20 octet header STT overloads on TCP: stream ID, destination port, packet length,
    segment offset, packet ID, data offset and flags, window, checksum (0), urgent pointer."""
    return struct.pack('>HHHHIBBHHH', sid, dport, pkt_len, seg_off, pkt_id, doff << 4 | (flags >> 8), flags & 0xff, window, 0, urg)

def stt_hdr(version=0, flags=0, l4off=0, mss=0, vlan=0, ctx=0x0102030405060708, reserved=0, pad=0):
    return struct.pack('>BBBBHHQH', version, flags, l4off, reserved, mss, vlan, ctx, pad)

def inner_frame(n, size=60):
    p = (b'stt inner frame %d ' % n) * 80
    p = p[:size]
    u = struct.pack('>HHHH', 6000 + n, 6001, 8 + len(p), 0) + p
    return eth(ipv4(17, u, '10.0.0.1', '10.0.0.2'))

def outer(seg, v6=False, ck=True, bad=False):
    """Put the STT TCP segment (header + data) into IPv4 or IPv6 with a valid or wrong checksum."""
    if ck:
        c = tcp_ck(seg, v6)
        c = (c ^ 0x5555) if bad else c
        seg = seg[:16] + struct.pack('>H', c) + seg[18:]
    if v6:
        return eth(ipv6(6, seg, SRC6, DST6), 0x86dd)
    return eth(ipv4(6, seg, SRC4, DST4))

def full(pkt_id, payload, v6=False, hdr=None, tcp=None, **kw):
    data = (hdr if hdr is not None else stt_hdr(**kw)) + payload
    t = tcp if tcp is not None else stt_tcp(len(data), 0, pkt_id)
    return outer(t + data, v6)

def segments(pkt_id, payload, sizes, v6=False, hdr=None, order=None):
    data = (hdr if hdr is not None else stt_hdr()) + payload
    segs = []
    off = 0
    for i, n in enumerate(sizes):
        chunk = data[off:off + n] if i < len(sizes) - 1 else data[off:]
        t = stt_tcp(len(data), off, pkt_id)
        # the first segment keeps the TCP header, the later ones carry only a fake header
        segs.append(outer(t + chunk, v6))
        off += n
    return segs

def main(out, verbose):
    c = Cap(1)
    c.mark('Unsegmented STT over IPv4: all header fields zero (checksum computed), then with a VLAN (priority 5, ID 100), the VLAN valid flag with ID 0, context IDs and the TCP and IPv4 payload flags')
    c.add(full(1, inner_frame(1)))
    c.add(full(2, inner_frame(2), vlan=(5 << 13) | 0x1000 | 100, ctx=0xdeadbeef00000001))
    c.add(full(3, inner_frame(3), vlan=0x1000, flags=0x0c, ctx=0))
    c.add(full(4, inner_frame(4), vlan=(7 << 13) | 0x0fff, flags=0x04))
    c.add(full(5, inner_frame(5), flags=0x01))
    c.mark('Offloaded segments (checksum partial flag with a layer 4 offset and a maximum segment size), reserved flag bits set')
    c.add(full(6, inner_frame(6), flags=0x0a, l4off=34, mss=1448))
    c.add(full(7, inner_frame(7), flags=0xfe, l4off=14, mss=536, reserved=0))
    c.mark('Stream IDs, urgent pointer and window values of the fake TCP header, and flags of the fake TCP header (all of them set)')
    c.add(full(8, inner_frame(8), tcp=stt_tcp(78 + 0, 0, 8, flags=0xfff, sid=0xffff, window=0, urg=0xabcd)))
    c.add(full(9, inner_frame(9), tcp=stt_tcp(0, 0, 9, flags=0x000, sid=0)))
    c.mark('STT over IPv6')
    c.add(full(10, inner_frame(10), v6=True, vlan=0x1000 | 9))
    c.mark('Segmented packets: two segments (twice), three segments and a packet in two IPv6 segments (reassembly)')
    big = inner_frame(11, 400)
    for s in segments(0x11, big, [200, 150]): c.add(s)
    big = inner_frame(12, 900)
    for s in segments(0x12, big, [300, 300]): c.add(s)
    big = inner_frame(13, 1200)
    for s in segments(0x13, big, [400, 400, 300]): c.add(s)
    big = inner_frame(14, 700)
    for s in segments(0x14, big, [250, 250], v6=True): c.add(s)
    c.mark('Segments that arrive out of order and a segment repeated')
    big = inner_frame(15, 1000)
    sg = segments(0x15, big, [350, 350, 200])
    c.add(sg[1]); c.add(sg[0]); c.add(sg[2]); c.add(sg[2])
    c.mark('A segment of a packet whose first segment is never captured')
    sg = segments(0x16, inner_frame(16, 800), [300, 300, 200])
    c.add(sg[1]); c.add(sg[2])
    c.mark('An STT frame whose Ethernet frame is 14 octets with an Ethernet type no dissector handles')
    c.add(full(18, eth(b'', 0x88b5)))

    c.mark('A TCP segment to another port, which the heuristic rejects (shown as TCP)')
    c.add(outer(stt_tcp(18, 0, 19, dport=40000) + b'', ck=False))

    m = Cap(1)
    m.mark('An STT header without any Ethernet frame; header errors (expert infos): unknown version, layer 4 offset set without offload and zero with offload, MSS set without offload, data offset that is not 20')
    m.add(full(21, inner_frame(21), version=1))
    m.add(full(22, inner_frame(22), flags=0x00, l4off=20))
    m.add(full(23, inner_frame(23), flags=0x02, l4off=0))
    m.add(full(24, inner_frame(24), flags=0x00, mss=1200))
    m.add(full(25, inner_frame(25), tcp=stt_tcp(78, 0, 25, doff=6)))
    m.add(full(26, inner_frame(26), tcp=stt_tcp(78, 0, 26, doff=15)))
    m.add(full(17, b'', tcp=stt_tcp(18, 0, 17)))
    m.mark('Wrong checksum (IPv4 and IPv6)')
    m.add(outer(stt_tcp(78, 0, 27) + stt_hdr() + inner_frame(27), bad=True))
    m.add(outer(stt_tcp(78, 0, 28) + stt_hdr() + inner_frame(28), v6=True, bad=True))
    m.mark('Truncated frames: STT header cut short, inner Ethernet cut, segments cut by the snap length')
    f = full(29, inner_frame(29))
    for n in (14 + 20 + 10, 14 + 20 + 20 + 5, 14 + 20 + 20 + 18 + 7, 14 + 20 + 20 + 18 + 14 + 9):
        m.add(f[:n])
    sg = segments(0x2a, inner_frame(30, 500), [200, 200, 100])
    for s in sg:
        m.add((s[:14 + 20 + 20 + 30], len(s)))
    m.mark('Segments with an offset past the packet length, a packet length shorter than the data and segments of a different packet ID that never complete')
    m.add(outer(stt_tcp(300, 5000, 0x31) + b'x' * 40))
    m.add(outer(stt_tcp(30, 0, 0x32) + stt_hdr() + inner_frame(32)))
    m.add(outer(stt_tcp(900, 0, 0x33) + stt_hdr() + inner_frame(33)))
    m.add(outer(stt_tcp(900, 200, 0x33) + b'y' * 100))
    c.write(os.path.join(out, 'stt-coverage.pcap'))
    m.write(os.path.join(out, 'stt-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

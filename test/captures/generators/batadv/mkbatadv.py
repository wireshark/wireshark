#!/usr/bin/env python3
# Generates test/captures/batadv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the B.A.T.M.A.N. Advanced
dissector (packet-batadv.c).

batadv is ethertype 0x4305. Packet versions 5 to 14 share one set of type
codes, version 15 has its own. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkbatadv.py <output directory>

Writes:
  batadv-coverage.pcap            every packet type of every version,
                                  aggregated OGMs, fragment reassembly
                                  (v12, v13, v14, v15), the TVLVs of IV OGM,
                                  OGM2 and unicast TVLV packets (GW, DAT,
                                  NC, TT with a matching VLAN CRC, ROAM,
                                  MCAST, unknown), unsupported versions and
                                  unknown types, and the reproducers of the
                                  fixes on the branch
  batadv-coverage-malformed.pcap  unknown TVLV versions, a bad TT VLAN CRC,
                                  truncated headers and other paths that
                                  only malformed input reaches
"""

import os
import struct
import sys

ETH_BATADV = 0x4305


def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4_udp(seq, data):
    """An IPv4 UDP datagram to the discard port with valid checksums."""
    src, dst = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1])
    sport = 40000 + seq
    ulen = 8 + len(data)
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, ulen)
    uh = struct.pack('>HHHH', sport, 9, ulen, 0)
    c = csum(pseudo + uh + data) or 0xffff
    udp = uh[:6] + struct.pack('>H', c) + data
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), seq, 0, 64,
                      17, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + udp


def inner_eth(seq, data=b'batadv-test'):
    """Inner Ethernet frame (what batadv carries) with a UDP datagram."""
    return mac(0x21) + mac(0x22) + struct.pack('>H', 0x0800) + ipv4_udp(seq, data)


def inner_batadv(payload):
    """Inner Ethernet frame carrying batadv again."""
    return mac(0x31) + mac(0x32) + struct.pack('>H', ETH_BATADV) + payload


def frame(payload, dst=0xff, src=0x02):
    return mac(dst) + mac(src) + struct.pack('>H', ETH_BATADV) + payload


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# --- versions 5..14 ------------------------------------------------------

def batman_v5(version, seq, tts, flags=0x60, gw=0x51, ttl=50, tq=200):
    return struct.pack('>BBBBBBH', 0x01, version, flags, ttl, gw, tq, seq) + \
        mac(0x10) + mac(0x11) + bytes([len(tts), 0]) + b''.join(tts)


def batman_v7(version, seq, tts, flags=0x40, tq=200, ttl=50):
    return struct.pack('>BBBBH', 0x01, version, flags, tq, seq) + \
        mac(0x10) + mac(0x11) + bytes([ttl, len(tts)]) + b''.join(tts)


def batman_v9(version, seq, tts, flags=0x70, tq=200, ttl=50, gw=0x00):
    return struct.pack('>BBBBH', 0x01, version, flags, tq, seq) + \
        mac(0x10) + mac(0x11) + bytes([ttl, len(tts), gw, 0]) + b''.join(tts)


def batman_v10(version, seq, tts, flags=0x10, tq=200, ttl=50, gw=0xa3):
    return struct.pack('>BBBBI', 0x01, version, flags, tq, seq) + \
        mac(0x10) + mac(0x11) + bytes([ttl, len(tts), gw, 0]) + b''.join(tts)


def batman_v11(version, seq, tts, flags=0x20, tq=200, ttl=50):
    return struct.pack('>BBBBI', 0x01, version, flags, tq, seq) + \
        mac(0x10) + mac(0x11) + bytes([ttl, len(tts)]) + b''.join(tts)


def tt_entry_v14(flags, n):
    return bytes([flags]) + mac(n)


def batman_v14(seq, entries, flags=0xf0, gw=0x29, tq=255, ttvn=3, crc=0xbeef):
    return struct.pack('>BBBBI', 0x01, 14, 50, flags, seq) + mac(0x10) + \
        mac(0x11) + struct.pack('>BBBBH', gw, tq, len(entries), ttvn, crc) + \
        b''.join(entries)


def tt(n):
    return mac(n)


def icmp_v6(msg, seq, uid=7, payload=b''):
    return struct.pack('>BBB', 0x02, 6, msg) + mac(0x12) + mac(0x13) + \
        struct.pack('>BBH', 50, uid, seq) + payload


def rr_v7(ptr):
    return bytes([ptr]) + b''.join(mac(0x40 + i) for i in range(16))


def icmp_v7(version, msg, seq, uid, rr=b'', payload=b''):
    return struct.pack('>BBBB', 0x02, version, msg, 50) + mac(0x12) + \
        mac(0x13) + struct.pack('>HB', seq, uid) + rr + payload


def icmp_v14(msg, seq, uid, rr=b'', payload=b''):
    return struct.pack('>BBBB', 0x02, 14, 50, msg) + mac(0x12) + \
        mac(0x13) + struct.pack('>HBB', seq, uid, 0) + rr + payload


def icmp_v15(msg, seq, uid, rr_ptr=0, rr=b'', payload=b''):
    return struct.pack('>BBBB', 0x43, 15, 50, msg) + mac(0x12) + \
        mac(0x13) + struct.pack('>BBH', uid, rr_ptr, seq) + rr + payload


def icmp_tp_v15(subtype, session, seq, ts, payload=b''):
    return struct.pack('>BBBB', 0x43, 15, 50, 15) + mac(0x12) + mac(0x13) + \
        struct.pack('>BBHII', 0x21, subtype, session, seq, ts) + payload


def unicast_v6(version, payload):
    return bytes([0x03, version]) + mac(0x14) + bytes([50]) + payload


def unicast_v14(ptype, version, payload, ttvn=4):
    return bytes([ptype, version, 50, ttvn]) + mac(0x14) + payload


def unicast_4addr(ptype, version, subtype, payload):
    return bytes([ptype, version, 50, 5]) + mac(0x14) + mac(0x15) + \
        bytes([subtype, 0]) + payload


def bcast_v6(version, seq, payload):
    return bytes([0x04, version]) + mac(0x16) + struct.pack('>H', seq) + payload


def bcast_v10(version, seq, payload):
    return bytes([0x04, version]) + mac(0x16) + struct.pack('>BI', 50, seq) + payload


def bcast_v14(ptype, version, seq, payload):
    return struct.pack('>BBBBI', ptype, version, 50, 0, seq) + mac(0x16) + payload


def vis_entry_v6(n, q):
    return mac(n) + bytes([q])


def vis_entry_v8(n, q):
    return mac(0x50) + mac(n) + bytes([q])


def vis_v6(version, vtype, seq, entries, trailer=b''):
    return struct.pack('>BBBBBB', 0x05, version, vtype, seq, len(entries), 50) + \
        mac(0x17) + mac(0x18) + mac(0x19) + b''.join(entries) + trailer


def vis_v10(version, vtype, seq, entries, trailer=b''):
    return struct.pack('>BBBBIB', 0x05, version, vtype, len(entries), seq, 50) + \
        mac(0x17) + mac(0x18) + mac(0x19) + b''.join(entries) + trailer


def vis_v14(vtype, seq, entries, trailer=b''):
    return struct.pack('>BBBBIBB', 0x05, 14, 50, vtype, seq, len(entries), 0) + \
        mac(0x17) + mac(0x18) + mac(0x19) + b''.join(entries) + trailer


def frag_v12(version, head, seq, data, flags_extra=0):
    return bytes([0x06, version]) + mac(0x14) + bytes([50, head | flags_extra]) + \
        mac(0x1a) + struct.pack('>H', seq) + data


def frag_v14(head, seq, data, flags_extra=0):
    return bytes([0x06, 14, 50, 6]) + mac(0x14) + bytes([head | flags_extra, 0]) + \
        mac(0x1a) + struct.pack('>H', seq) + data


def frag_v15(no, seq, total, data, prio=0):
    return bytes([0x41, 15, 50, (no << 4) | (prio << 1)]) + mac(0x14) + \
        mac(0x1a) + struct.pack('>HH', seq, total) + data


def tt_query(flags, ttvn, data, entries=b'', trailer=b'', version=14):
    return struct.pack('>BBBB', 0x07, version, 50, flags) + mac(0x1b) + \
        mac(0x1c) + struct.pack('>BH', ttvn, data) + entries + trailer


def roam_adv(version, trailer=b''):
    return bytes([0x08, version, 50, 0]) + mac(0x1b) + mac(0x1c) + mac(0x1d) + trailer


# --- version 15 ----------------------------------------------------------

def tvlv(t, v, body):
    return struct.pack('>BBH', t, v, len(body)) + body


def iv_ogm(seq, tv, flags=0x07, version=15):
    return struct.pack('>BBBBI', 0x00, version, 50, flags, seq) + mac(0x10) + \
        mac(0x11) + bytes([0, 255]) + struct.pack('>H', len(tv)) + tv


def ogm2(seq, throughput, tv=b'', version=15):
    return struct.pack('>BBBBI', 0x04, version, 50, 0, seq) + mac(0x10) + \
        struct.pack('>HI', len(tv), throughput) + tv


def elp(seq, interval, trailer=b'', version=15):
    return bytes([0x03, version]) + mac(0x10) + struct.pack('>II', seq, interval) + trailer


def coded(payload, version=15):
    return bytes([0x02, version, 50, 7]) + mac(0x1e) + mac(0x1f) + \
        struct.pack('>IBB', 0x11223344, 49, 8) + mac(0x20) + mac(0x23) + \
        mac(0x24) + struct.pack('>IH', 0x55667788, len(payload)) + payload


def unicast_tvlv(tv, version=15):
    return bytes([0x44, version, 50, 0]) + mac(0x14) + mac(0x15) + \
        struct.pack('>HH', len(tv), 0) + tv


def crc32c_raw(data, crc):
    """crc32c_calculate_no_swap(): reflected CRC-32C, no pre/post inversion."""
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc


def tt_change(flags, n, vid):
    return bytes([flags, 0, 0, 0]) + mac(n) + struct.pack('>H', vid)


def tt_vlan_crc(changes, vid):
    crc = 0
    for c in changes:
        if struct.unpack('>H', c[10:12])[0] != vid:
            continue
        e = crc32c_raw(c[10:12], 0)
        e = crc32c_raw(c[0:1], e)
        e = crc32c_raw(c[4:10], e)
        crc ^= e
    return crc


def tt_tvlv(flags, ttvn, vlans, changes, crcs=None, version=1):
    """vlans: list of vids; crcs: list of CRCs (computed if None)."""
    body = struct.pack('>BBH', flags, ttvn, len(vlans))
    for i, vid in enumerate(vlans):
        crc = tt_vlan_crc(changes, vid) if crcs is None else crcs[i]
        body += struct.pack('>IHH', crc, vid, 0)
    body += b''.join(changes)
    return tvlv(0x04, version, body)


GW = tvlv(0x01, 1, struct.pack('>II', 1000, 205))
DAT = tvlv(0x02, 1, b'')
NC = tvlv(0x03, 1, b'')
ROAM = tvlv(0x05, 1, mac(0x2a) + struct.pack('>H', 0x8005))
MCAST1 = tvlv(0x06, 1, bytes([0x1f, 0, 0, 0]))
MCAST2 = tvlv(0x06, 2, bytes([0x05, 0, 0, 0]))
UNKNOWN_TVLV = tvlv(0x07, 1, b'\xde\xad\xbe\xef')


def main(out):
    frames = []
    notes = []

    def add(note, *fr):
        start = len(frames) + 1
        frames.extend(fr)
        end = len(frames)
        notes.append('%d-%d: %s' % (start, end, note) if end > start
                     else '%d: %s' % (start, note))

    pad = b'\x00' * 22

    # BATMAN OGMs, versions 5-14
    add('BATMAN v5, two TTs, aggregated with a v5 OGM (gwflags 0) and padding',
        frame(batman_v5(5, 1, [tt(0x60), tt(0x61)]) + batman_v5(5, 2, [], gw=0) + pad))
    add('BATMAN v6, aggregated with a non-OGM type (stops)',
        frame(batman_v5(6, 3, [tt(0x62)]) + bytes([0x02, 6]) + b'\x00' * 20))
    add('BATMAN v7 aggregated, v8 followed by padding',
        frame(batman_v7(7, 4, [tt(0x63)]) + batman_v7(7, 5, [])),
        frame(batman_v7(8, 6, []) + b'\x00' * 20))
    add('BATMAN v9 (gwflags 0) aggregated with gwflags 0xff, then padding',
        frame(batman_v9(9, 7, [tt(0x64)]) + batman_v9(9, 8, [], gw=0xff) + pad))
    add('BATMAN v10 (then padding) and v12 aggregated (32 bit seqno)',
        frame(batman_v10(10, 70000, [tt(0x65)]) + b'\x00' * 24),
        frame(batman_v10(12, 70001, [], gw=0x08) + batman_v10(12, 70002, [])))
    add('BATMAN v11 and v13', frame(batman_v11(11, 80000, [tt(0x66)])),
        frame(batman_v11(13, 80001, []) + pad))
    add('BATMAN v14 with TT changes (del, roam), then 26 octets of padding; two aggregated (v14 also hands what follows each OGM to the data dissector)',
        frame(batman_v14(90000, [tt_entry_v14(0x01, 0x67), tt_entry_v14(0x02, 0x68)]) + b'\x00' * 26),
        frame(batman_v14(90001, [], flags=0) + batman_v14(90002, [tt_entry_v14(0, 0x69)])))
    add('BATMAN unsupported version 4', frame(batman_v5(4, 9, [])))

    # ICMP v6-v15
    add('ICMP v6 echo request with payload, echo reply',
        frame(icmp_v6(8, 10, payload=b'ping')), frame(icmp_v6(0, 10)))
    add('ICMP v7 with record route (ptr 3), uid 0x5a',
        frame(icmp_v7(7, 8, 11, 0x5a, rr=rr_v7(3))))
    add('ICMP v8-v13: dest unreachable, TTL exceeded, unknown type, RR ptr 0 and 17, RR ptr 16 with payload',
        frame(icmp_v7(8, 3, 12, 1)), frame(icmp_v7(9, 11, 13, 2)),
        frame(icmp_v7(10, 0x42, 14, 3, payload=b'xyz')),
        frame(icmp_v7(11, 8, 15, 4, rr=rr_v7(0))),
        frame(icmp_v7(12, 8, 16, 5, rr=rr_v7(17))),
        frame(icmp_v7(13, 0, 17, 6, rr=rr_v7(16), payload=b'tail')))
    add('ICMP v14 echo request with RR (ptr 1), uid 0xa5; echo reply without',
        frame(icmp_v14(8, 18, 0xa5, rr=rr_v7(1), payload=b'v14')),
        frame(icmp_v14(0, 19, 0x33)))
    add('ICMP unsupported version 5', frame(icmp_v6(8, 20)[:1] + b'\x05' + icmp_v6(8, 20)[2:]))
    add('ICMP v15 echo request with RR (ptr 2) and payload, reply without RR',
        frame(icmp_v15(8, 21, 0x77, 2, rr=b''.join(mac(0x70 + i) for i in range(16)), payload=b'v15')),
        frame(icmp_v15(0, 22, 0x78)))
    add('ICMP v15 throughput meter message and ack (with payload)',
        frame(icmp_tp_v15(0, 0x1234, 100000, 0xcafe)),
        frame(icmp_tp_v15(1, 0x1234, 100000, 0xcaff, payload=b'tp')))

    # Unicast
    add('UNICAST v6-v13 carrying Ethernet/IPv4/UDP',
        *[frame(unicast_v6(v, inner_eth(v))) for v in range(6, 14)])
    add('UNICAST v14 and v15 carrying Ethernet; v15 header only',
        frame(unicast_v14(0x03, 14, inner_eth(14))),
        frame(unicast_v14(0x40, 15, inner_eth(15))),
        frame(unicast_v14(0x40, 15, b'')))
    add('UNICAST unsupported version 5 (v5 types) and 16 (v15 types)',
        frame(unicast_v6(5, b'data')), frame(unicast_v14(0x40, 16, b'data')))

    # Unicast 4addr
    add('UNICAST_4ADDR v14 subtypes data, DHT get, put, cache reply; v15 unknown subtype',
        frame(unicast_4addr(0x09, 14, 1, inner_eth(20))),
        frame(unicast_4addr(0x09, 14, 2, inner_eth(21))),
        frame(unicast_4addr(0x42, 15, 3, inner_eth(22))),
        frame(unicast_4addr(0x42, 15, 4, inner_eth(23))),
        frame(unicast_4addr(0x42, 15, 0x55, b'')))
    add('UNICAST_4ADDR unsupported versions 13 and 16',
        frame(unicast_4addr(0x09, 13, 1, b'x')), frame(unicast_4addr(0x42, 16, 1, b'x')))

    # Broadcast
    add('BCAST v6-v9 carrying Ethernet; v9 header only',
        *[frame(bcast_v6(v, 30 + v, inner_eth(30 + v))) for v in range(6, 10)],
        frame(bcast_v6(9, 40, b'')))
    add('BCAST v10-v13 carrying Ethernet; v13 header only',
        *[frame(bcast_v10(v, 100000 + v, inner_eth(40 + v))) for v in range(10, 14)],
        frame(bcast_v10(13, 100020, b'')))
    add('BCAST v14 and v15 carrying Ethernet; v15 header only; v15 carrying batadv ICMP v15',
        frame(bcast_v14(0x04, 14, 200014, inner_eth(54))),
        frame(bcast_v14(0x01, 15, 200015, inner_eth(55))),
        frame(bcast_v14(0x01, 15, 200016, b'')),
        frame(bcast_v14(0x01, 15, 200017, inner_batadv(icmp_v15(8, 23, 0x79)))))
    add('BCAST unsupported versions 5 and 16',
        frame(bcast_v6(5, 1, b'x')), frame(bcast_v14(0x01, 16, 1, b'x')))

    # VIS
    add('VIS v6 and v7 (7 byte entries), v8 and v9 (13 byte entries), types server sync, client update, unknown; trailing data',
        frame(vis_v6(6, 0, 1, [vis_entry_v6(0x80, 200), vis_entry_v6(0x81, 100)])),
        frame(vis_v6(7, 1, 2, [vis_entry_v6(0x82, 50)], trailer=b'trail')),
        frame(vis_v6(8, 2, 3, [vis_entry_v8(0x83, 255)])),
        frame(vis_v6(9, 0, 4, [vis_entry_v8(0x84, 1), vis_entry_v8(0x85, 2)], trailer=b'x')))
    add('VIS v10-v13 and v14 (with trailing data)',
        *[frame(vis_v10(v, v % 2, 300000 + v, [vis_entry_v8(0x86 + v, v)])) for v in range(10, 14)],
        frame(vis_v10(13, 1, 300099, [], trailer=b'v13tr')),
        frame(vis_v14(1, 400000, [vis_entry_v8(0x90, 9), vis_entry_v8(0x91, 10)], trailer=b'v14')))
    add('VIS unsupported versions 5 and 15 (type 5 is unknown in v15)',
        frame(vis_v6(5, 0, 1, [])), frame(vis_v14(0, 1, [])[:1] + b'\x0f' + vis_v14(0, 1, [])[2:]))

    # Fragments v12/v13/v14: head (seq N) and tail (seq N+1), payload Ethernet
    e = inner_eth(60, b'fragmented over batadv v12')
    h = len(e) // 2
    add('UNICAST_FRAG v12 head then tail, reassembled into Ethernet/IPv4/UDP',
        frame(frag_v12(12, 1, 500, e[:h])), frame(frag_v12(12, 0, 501, e[h:], 0x02)))
    e = inner_eth(61, b'fragmented over batadv v13')
    h = len(e) // 2
    add('UNICAST_FRAG v13 tail first, then head',
        frame(frag_v12(13, 0, 601, e[h:])), frame(frag_v12(13, 1, 600, e[:h])))
    e = inner_eth(62, b'fragmented over batadv v14')
    h = len(e) // 2
    add('UNICAST_FRAG v14 head then tail (largetail set)',
        frame(frag_v14(1, 700, e[:h])), frame(frag_v14(0, 701, e[h:], 0x02)))
    # v15: fragment number 1 holds the first part, 0 the second; the result
    # is a batadv packet (unicast v15 carrying Ethernet)
    u = unicast_v14(0x40, 15, inner_eth(63, b'fragmented over batadv v15'))
    h = len(u) // 2
    add('UNICAST_FRAG v15 fragment 1 then 0 (priority 5), reassembled into batadv unicast v15',
        frame(frag_v15(1, 800, len(u), u[:h], prio=5)),
        frame(frag_v15(0, 800, len(u), u[h:], prio=5)))
    u = unicast_v14(0x40, 15, inner_eth(64, b'v15 fragments out of order'))
    h = len(u) // 2
    add('UNICAST_FRAG v15 fragment 0 then 1',
        frame(frag_v15(0, 801, len(u), u[h:])),
        frame(frag_v15(1, 801, len(u), u[:h])))
    add('UNICAST_FRAG v15 fragment number 3 (not supported, batadv_frag.py frame 5)',
        frame(frag_v15(3, 9, 4, b'abcd')))
    add('UNICAST_FRAG unsupported versions 11 and 16',
        frame(frag_v12(11, 1, 1, b'x')), frame(frag_v15(0, 1, 1, b'x')[:1] + b'\x10' + frag_v15(0, 1, 1, b'x')[2:]))

    # TT query v14
    add('TT_QUERY v14 request, full table request',
        frame(tt_query(0x00, 5, 0xabcd)), frame(tt_query(0x04, 6, 0x1234)))
    add('TT_QUERY v14 response with three entries and trailing data, empty response',
        frame(tt_query(0x01, 7, 3, b''.join([tt_entry_v14(0x00, 0xa0), tt_entry_v14(0x01, 0xa1),
                                              tt_entry_v14(0x03, 0xa2)]), trailer=b'end')),
        frame(tt_query(0x05, 8, 0)))
    add('TT_QUERY v14 unsupported type 2 with trailing data; unsupported version 13',
        frame(tt_query(0x02, 9, 0, trailer=b'??')), frame(tt_query(0x00, 1, 0, version=13)))

    # Roaming advertisement
    add('ROAM_ADV v14, with trailing data; unsupported version 13',
        frame(roam_adv(14)), frame(roam_adv(14, b'more')), frame(roam_adv(13)))

    # Unknown types
    add('Unknown packet type 0x0a (v14) and 0x05 (v15)',
        frame(bytes([0x0a, 14]) + b'unknown'), frame(bytes([0x05, 15]) + b'unknown'))

    # Version 15 IV OGM and TVLVs
    add('IV OGM v15 with a GW TVLV (batadv_tvlv_dead.py frame 1)',
        frame(iv_ogm(1, GW, flags=0)))
    add('IV OGM v15 with every TVLV: GW, DAT, NC, TT (OGM diff, one VLAN, two changes), ROAM, MCAST v1, unknown type',
        frame(iv_ogm(2, GW + DAT + NC +
                     tt_tvlv(0x01, 9, [0x8001],
                             [tt_change(0x01, 0xb0, 0x8001), tt_change(0x32, 0xb1, 0x8001)],
                             crcs=[0x01020304]) +
                     ROAM + MCAST1 + UNKNOWN_TVLV)))
    add('IV OGM v15 aggregated: MCAST v2 TVLV, no TVLV, then padding',
        frame(iv_ogm(3, MCAST2, flags=0x01) + iv_ogm(4, b'', flags=0x02) + b'\x00' * 24))
    add('IV OGM v15 aggregated with another packet type (stops)',
        frame(iv_ogm(5, b'') + bytes([0x04, 15]) + b'\x00' * 22))
    add('OGM2 v15 reproducer (batadv_ogm2_tvlvlen.py): throughput 6553.6 Mbit/s; two aggregated; two aggregated, the first with throughput 0x50000',
        frame(ogm2(1, 0x00010000)), frame(ogm2(2, 100) + ogm2(3, 100)),
        frame(ogm2(4, 0x00050000) + ogm2(5, 100)))
    add('OGM2 v15 with GW, TT (request, no VLAN) and MCAST TVLVs, aggregated with one with GW, then padding',
        frame(ogm2(6, 0x00050000, GW + tt_tvlv(0x02, 1, [], []) + MCAST1) +
              ogm2(7, 12345, GW) + b'\x00' * 20))
    add('Unicast TVLV v15 with a TT TVLV (batadv_tvlv_dead.py frame 2)',
        frame(unicast_tvlv(tvlv(0x04, 1, bytes([0x00, 7]) + struct.pack('>H', 0)))))
    changes = [tt_change(0x00, 0xc0, 0x8001), tt_change(0x10, 0xc1, 0x8001),
               tt_change(0x20, 0xc2, 0x0000), tt_change(0x00, 0xc3, 0x8001),
               tt_change(0x00, 0xc4, 0x0000)]
    add('Unicast TVLV v15 TT full table response, VLANs 0x8001 and 0x0000, five entries, matching CRCs',
        frame(unicast_tvlv(tt_tvlv(0x14, 10, [0x8001, 0x0000], changes))))
    add('Unicast TVLV v15 TT full table response with a VLAN that has no entries (batadv.tvlv_tt_vlan_empty warning)',
        frame(unicast_tvlv(tt_tvlv(0x14, 11, [0x8002], [tt_change(0, 0xc5, 0x8003)], crcs=[0]))))
    add('Unicast TVLV v15 TT response (not full table: CRC not checked) and ROAM TVLV',
        frame(unicast_tvlv(tt_tvlv(0x04, 12, [0x8001], changes[:1], crcs=[0xdeadbeef]) + ROAM)))
    add('CODED v15 with payload; header only',
        frame(coded(b'coded-payload')), frame(coded(b'')))
    add('ELP v15 with trailing data; without',
        frame(elp(1000, 500, b'pad')), frame(elp(1001, 500)))
    add('Unsupported version 16 of IV OGM, CODED, ELP, OGM2, ICMP, unicast TVLV',
        frame(iv_ogm(1, b'', version=16)), frame(coded(b'', version=16)),
        frame(elp(1, 1, version=16)), frame(ogm2(1, 1, version=16)),
        frame(icmp_v15(8, 1, 1)[:1] + b'\x10' + icmp_v15(8, 1, 1)[2:]),
        frame(unicast_tvlv(b'', version=16)))

    # Recursion reproducer (batadv_recursion.py, N=200): unicast v6 -> Ethernet -> batadv ...
    inner = b'\x00' * 4
    for _ in range(200):
        uni = bytes([0x03, 6]) + mac(1) + bytes([64])
        inner = mac(1) + mac(2) + struct.pack('>H', ETH_BATADV) + uni + inner
    add('Nesting reproducer: 200 nested unicast v6/Ethernet (batadv_recursion.py), stops with batadv.too_deep',
        inner)

    write_pcap(os.path.join(out, 'batadv-coverage.pcap'), frames)
    for n in notes:
        print(n)

    # ------------------------------------------------------------ malformed
    mal = []
    mnotes = []

    def madd(note, *fr):
        start = len(mal) + 1
        mal.extend(fr)
        end = len(mal)
        mnotes.append('%d-%d: %s' % (start, end, note) if end > start
                      else '%d: %s' % (start, note))

    madd('Unknown TVLV versions of GW, DAT, NC, TT, ROAM, MCAST (errors)',
         frame(iv_ogm(1, tvlv(0x01, 2, b'\0' * 8) + tvlv(0x02, 0, b'') + tvlv(0x03, 9, b'') +
                      tvlv(0x04, 2, b'\0' * 4) + tvlv(0x05, 3, b'\0' * 8) + tvlv(0x06, 3, b'\0' * 4))))
    madd('TT full table response with a bad VLAN CRC',
         frame(unicast_tvlv(tt_tvlv(0x14, 1, [0x8001], [tt_change(0, 0xd0, 0x8001)], crcs=[0x12345678]))))
    madd('TVLV length 0xfffc (batadv_tvlv_dead.py frame 3)',
         frame(iv_ogm(1, struct.pack('>BBH', 0x07, 1, 0xfffc))))
    madd('OGM2 TVLV length past the end of the frame; IV OGM likewise',
         frame(ogm2(8, 1)[:14] + struct.pack('>H', 40) + ogm2(8, 1)[16:] + GW),
         frame(iv_ogm(9, b'')[:22] + struct.pack('>H', 40) + GW))
    madd('TT TVLV with a VLAN count past the end; GW and ROAM TVLVs too short',
         frame(unicast_tvlv(tvlv(0x04, 1, bytes([0x14, 1]) + struct.pack('>H', 3) + b'\0' * 8))),
         frame(unicast_tvlv(tvlv(0x01, 1, b'\0' * 4))),
         frame(unicast_tvlv(tvlv(0x05, 1, b'\0' * 4))))
    madd('TT TVLV with a partial change entry',
         frame(unicast_tvlv(tt_tvlv(0x01, 1, [], [b'\0' * 6]))))
    madd('Truncated headers: BATMAN v14 TT change count past the end, ICMP v15, unicast, bcast, VIS entries, TT query response entries, coded, ELP, unicast TVLV, roam',
         frame(batman_v14(1, [])[:22] + bytes([5]) + batman_v14(1, [])[23:]),
         frame(icmp_v15(8, 1, 1)[:10]),
         frame(unicast_v14(0x40, 15, b'')[:6]),
         frame(bcast_v14(0x01, 15, 1, b'')[:8]),
         frame(vis_v14(0, 1, [])[:8] + bytes([4]) + vis_v14(0, 1, [])[9:]),
         frame(tt_query(0x01, 1, 9)),
         frame(coded(b'')[:20]),
         frame(elp(1, 1)[:10]),
         frame(unicast_tvlv(b'')[:12]),
         frame(roam_adv(14)[:12]),
         frame(bytes([0x01])))
    madd('Frag v14 head with no tail, two heads with the same seqno, v15 fragment with no partner',
         frame(frag_v14(1, 900, b'lonely head')),
         frame(frag_v14(1, 910, b'first')), frame(frag_v14(1, 910, b'second')),
         frame(frag_v15(1, 920, 10, b'half')))
    madd('Frag v15 reassembled into garbage (unknown batadv type)',
         frame(frag_v15(1, 930, 8, b'\x7f\x0f')), frame(frag_v15(0, 930, 8, b'garbage!')))
    write_pcap(os.path.join(out, 'batadv-coverage-malformed.pcap'), mal)
    print('malformed:')
    for n in mnotes:
        print(n)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

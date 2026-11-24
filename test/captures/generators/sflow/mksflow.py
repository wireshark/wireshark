#!/usr/bin/env python3
# Generates test/captures/sflow_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the sFlow (packet-sflow.c) dissector.

Usage: mksflow.py <outdir>

Writes sflow-coverage.pcap (clean) and sflow-coverage-malformed.pcap.  The
datagrams are sent to UDP port 6343 (the default).  Every packet is built
with struct; nothing comes from a real network.
"""
import struct
import sys
import os

P = lambda fmt, *a: struct.pack('>' + fmt, *a)


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def xdr_str(s):
    b = s if isinstance(s, bytes) else s.encode()
    return P('I', len(b)) + pad4(b)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, bytes(src), bytes(dst))
    return ip[:10] + P('H', csum(ip)) + ip[12:] + payload


def ipv6(src, dst, nxt, payload):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nxt, 64, bytes(src), bytes(dst)) + payload


def udp(sp, dp, payload):
    return P('HHHH', sp, dp, 8 + len(payload), 0) + payload


def udp6(sp, dp, payload, src, dst):
    u = P('HHHH', sp, dp, 8 + len(payload), 0) + payload
    c = csum(src + dst + P('II', len(u), 17) + u) or 0xFFFF
    return u[:6] + P('H', c) + u[8:]


def tcp(sp, dp, payload=b''):
    return P('HHIIBBHHH', sp, dp, 1, 2, 5 << 4, 0x18, 1000, 0, 0) + payload


def icmp_echo(data=b'ping'):
    m = P('BBHHH', 8, 0, 0, 1, 1) + data
    return m[:2] + P('H', csum(m)) + m[4:]


def eth(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + P('H', etype) + payload


A4 = (10, 1, 1, 1)
B4 = (10, 1, 1, 2)
A6 = bytes([0x20, 0x01, 0xdb, 8] + [0] * 11 + [1])
B6 = bytes([0x20, 0x01, 0xdb, 8] + [0] * 11 + [2])

# ----------------------------------------------------------------- addresses

def addr(kind):
    if kind == 0:
        return P('I', 0)
    if kind == 1:
        return P('I', 1) + bytes(B4)
    if kind == 2:
        return P('I', 2) + B6
    return P('I', kind)          # unknown address type, no contents


# ------------------------------------------------------------ flow records

def sampled_header(version, proto, frame, frame_len=None, hdr_len=None):
    hl = len(frame) if hdr_len is None else hdr_len
    fl = len(frame) if frame_len is None else frame_len
    out = P('II', proto, fl)
    if version == 5:
        out += P('I', 4)                     # payload removed
    out += P('I', hl) + pad4(frame[:hl] if hdr_len is not None else frame)
    return out


def r_header(proto=1, frame=None, **kw):
    frame = frame if frame is not None else eth(ipv4(A4, B4, 17, udp(1234, 5678, b'hello sflow')))
    return record(1, sampled_header(5, proto, frame, **kw))


def r_ethernet():
    return P('I', 1500) + b'\x02\0\0\0\0\x01\0\0' + b'\x02\0\0\0\0\x02\0\0' + P('I', 0x0800)


def r_ipv4():
    return P('IIIIIIII', 100, 6, 0x0a010101, 0x0a010102, 1234, 80, 0x18, 0x10)


def r_ipv6():
    return P('II', 200, 17) + A6 + B6 + P('IIII', 5000, 53, 0x2, 7)


def r_switch():
    return P('IIII', 100, 3, 200, 5)


def r_router(kind=1):
    return addr(kind) + P('II', 24, 16)


def r_gateway5(as_sets=((2, (65001, 65002)), (1, (65003,))), comm=(100, 200), nexthop=1):
    out = addr(nexthop) + P('IIII', 65000, 65010, 65020, len(as_sets))
    for t, ases in as_sets:
        out += P('II', t, len(ases)) + b''.join(P('I', a) for a in ases)
    out += P('I', len(comm)) + b''.join(P('I', c) for c in comm) + P('I', 150)
    return out


def r_gateway2(ases=(65001, 65002)):
    return P('IIII', 65000, 65010, 65020, len(ases)) + b''.join(P('I', a) for a in ases)


def r_gateway4(as_sets=((2, (65001, 65002)),), comm=(100,)):
    out = P('IIII', 65000, 65010, 65020, len(as_sets))
    for t, ases in as_sets:
        out += P('II', t, len(ases)) + b''.join(P('I', a) for a in ases)
    return out + P('I', len(comm)) + b''.join(P('I', c) for c in comm) + P('I', 150)


def r_user():
    return P('I', 1) + xdr_str('alice') + P('I', 2) + xdr_str('bobby!')


def r_url(direction=1):
    return P('I', direction) + xdr_str('http://example.test/index.html') + xdr_str('example.test')


def r_mpls_data(kind=1):
    return addr(kind) + P('I', 2) + P('II', 16001, 16002) + P('I', 1) + P('I', 3000)


def r_nat():
    return addr(1) + addr(2)


def r_mpls_tunnel():
    return xdr_str('tunnel-1') + P('II', 7, 3)


def r_mpls_vc():
    return xdr_str('vc-instance') + P('II', 42, 5)


def r_mpls_fec():
    return xdr_str('ftn-desc') + P('I', 24)


def r_mpls_lvp_fec():
    return P('I', 32)


def r_vlan_tunnel():
    return P('I', 2) + P('II', 0x81000064, 0x88a800c8)


def r_80211_payload(oui=0x000FAC, suite=4, payload=b'\xde\xad\xbe\xef\x01'):
    return P('I', (oui << 8) | suite) + P('I', len(payload)) + pad4(payload)


def r_80211_rx(dur=1500, ssid='office'):
    return xdr_str(ssid) + b'\x02\0\0\0\0\x03\0\0' + P('IIQIII', 3, 36, 54000000, 20, 90, dur)


def r_80211_tx(trans=1, pdur=300, rdur=0, ssid='guest'):
    return xdr_str(ssid) + b'\x02\0\0\0\0\x03\0\0' + P('IIIII', 4, trans, pdur, rdur, 6) + P('QI', 150000000, 15)


def record(fmt, body, enterprise=0):
    return P('II', (enterprise << 12) | fmt, len(body)) + body


# --------------------------------------------------------- counters records

def c_generic(ifindex=3):
    return (P('II', ifindex, 6) + P('Q', 1000000000) + P('II', 1, 3) + P('Q', 123456789) + \
        P('IIIIII', 100, 10, 5, 1, 2, 3) + P('Q', 987654321) + P('IIIII', 90, 9, 4, 0, 0) + P('I', 1))


def c_ethernet():
    return b''.join(P('I', i) for i in range(13))


def c_tokenring():
    return b''.join(P('I', i) for i in range(18))


def c_vg():
    return P('IQIQIIII', 1, 2, 3, 4, 5, 6, 7, 8) + P('IQI', 9, 10, 11) + P('QQQ', 12, 13, 14)


def c_vlan():
    return P('IQIIII', 100, 123456, 10, 2, 1, 0)


def c_lag():
    return b'\x02\0\0\0\0\x01\0\0' + b'\x02\0\0\0\0\x02\0\0' + P('II', 5, 0x0f0f0f0f) + b''.join(P('I', i) for i in range(8))


def c_80211():
    return b''.join(P('I', i) for i in range(20))


def c_processor():
    return P('III', 10, 20, 30) + P('QQ', 8 << 30, 3 << 30)


def c_radio():
    return P('III', 1000, 600, 100)


# ------------------------------------------------------------------ samples

def s5(fmt, body, enterprise=0):
    return P('II', (enterprise << 12) | fmt, len(body)) + body


def flow5(seq, records, out=5):
    return s5(1, P('IIIIIII', seq, 0x00000003, 512, 100000, 3, 1, out) + P('I', len(records)) + b''.join(records))


def flow5_expanded(seq, records, out_fmt=0, out_val=7):
    return s5(3, P('IIIIIIIIII', seq, 0, 3, 512, 100000, 3, 0, 1, out_fmt, out_val) + P('I', len(records)) + b''.join(records))


def counters5(seq, records):
    return s5(2, P('III', seq, 0x00000003, len(records)) + b''.join(records))


def counters5_expanded(seq, records):
    return s5(4, P('IIII', seq, 0, 3, len(records)) + b''.join(records))


def lag_stats():
    return b'\x02\0\0\0\0\x01' + b'\x02\0\0\0\0\x02' + P('II', 5, 0x0f0f0f0f) + b''.join(P('I', i) for i in range(8))


def dgram(version, samples, agent=1, seq=1, sub_agent=7):
    out = P('I', version) + addr(agent)[:4]
    if agent == 1:
        out += bytes(A4)
    elif agent == 2:
        out += A6
    if version == 5:
        out += P('I', sub_agent)
    out += P('III', seq, 123456, len(samples)) + b''.join(samples)
    return out


# v2/v4 samples
def flow24(seq, ptype, pdata, ext, out=5):
    body = P('IIIIIII', seq, 0x00000003, 512, 100000, 3, 1, out) + P('I', ptype) + pdata + P('I', len(ext))
    for t, e in ext:
        body += P('I', t) + e
    return P('I', 1) + body


def counters24(seq, ctype, body):
    return P('I', 2) + P('IIII', seq, 0x00000003, 20, ctype) + body


def v24_header(version, frame, proto=1, frame_len=None, hdr_len=None):
    return sampled_header(version, proto, frame, frame_len, hdr_len)


# ------------------------------------------------------------------ framing

def udp_frame(payload, src=A4, dst=B4, sp=40000, dp=6343, ident=1):
    return eth(ipv4(src, dst, 17, udp(sp, dp, payload), ident))


def pcap(fname, frames):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def clean():
    F = []

    def add(d, **kw):
        F.append(udp_frame(d, ident=len(F) + 1, **kw))

    udp_pkt = eth(ipv4(A4, B4, 17, udp(1234, 5678, b'hello sflow')))
    tcp_pkt = eth(ipv4(A4, B4, 1, icmp_echo(b'ping from the sampled header')))      # an ICMP echo request
    ip6_pkt = eth(ipv6(A6, B6, 17, udp(1234, 5678, b'hello v6')), 0x86dd)

    # ---- version 5 flow samples
    add(dgram(5, [flow5(1, [r_header(), record(2, r_ethernet()), record(3, r_ipv4()), record(4, r_ipv6()),
                              record(1001, r_switch()), record(1002, r_router(1))])], agent=1, seq=1))
    # agent over IPv6 (carried over IPv6/UDP), multiple outputs, router with IPv6 and unknown next hop
    F.append(eth(ipv6(A6, B6, 17, udp6(40000, 6343, dgram(5, [
        flow5(2, [record(1002, r_router(2)), record(1002, r_router(0)),
                  record(1003, r_gateway5()), record(1004, r_user()), record(1005, r_url(1))], out=0x80000003),
        flow5(3, [record(1003, r_gateway5(as_sets=(), comm=(), nexthop=2))], out=0x80000000)], agent=2, seq=2), A6, B6)), 0x86dd))
    add(dgram(5, [flow5(4, [record(1005, r_url(2)), record(1005, r_url(0)), record(1006, r_mpls_data(1)),
                              record(1006, r_mpls_data(2)), record(1007, r_nat()), record(1008, r_mpls_tunnel()),
                              record(1009, r_mpls_vc()), record(1010, r_mpls_fec()), record(1011, r_mpls_lvp_fec()),
                              record(1012, r_vlan_tunnel())], out=0x40000000)], agent=0, seq=3))
    add(dgram(5, [flow5(5, [record(1013, r_80211_payload()), record(1013, r_80211_payload(0x123456, 9, b'abc')),
                              record(1014, r_80211_rx(1500)), record(1014, r_80211_rx(0, 'x')),
                              record(1015, r_80211_tx(0, 0, 0)), record(1015, r_80211_tx(1, 300, 200)),
                              record(1015, r_80211_tx(3, 300, 200, 'A' * 32)), record(1016, b'')], out=0x00000002)], seq=4))
    # expanded flow samples, all output formats
    add(dgram(5, [flow5_expanded(6, [r_header(1), record(1001, r_switch())], 0, 7),
                  flow5_expanded(7, [record(3, r_ipv4())], 1, 3),
                  flow5_expanded(8, [record(4, r_ipv6())], 2, 0),
                  flow5_expanded(9, [record(4, r_ipv6())], 2, 4),
                  flow5_expanded(10, [], 3, 99)], seq=5))
    # raw header records: ethernet with UDP and TCP, IPv4, IPv6, MPLS, PPP, frame relay, unregistered header protocols
    mpls = P('I', (16001 << 12) | (0 << 9) | 1 << 8 | 64) + ipv4(A4, B4, 17, udp(1, 2, b'\xaa\xbb\xcc\xdd'))
    ppp = b'\xff\x03\x00\x21' + ipv4(A4, B4, 17, udp(1, 2, b'\xaa\xbb\xcc\xdd'))
    add(dgram(5, [flow5(11, [r_header(1, udp_pkt), r_header(1, tcp_pkt), r_header(1, ip6_pkt),
                               r_header(11, ipv4(A4, B4, 17, udp(1, 2, b'\xaa\xbb\xcc\xdd'))),
                               r_header(12, ipv6(A6, B6, 17, udp(1, 2, b'\xaa\xbb\xcc\xdd'))),
                               r_header(13, mpls), r_header(7, ppp), r_header(99, b'unknown header proto'),
                               r_header(3, b'\x10\x40' + b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\xaa\xaa\x03\0\0\0\x08\x00' + ipv4(A4, B4, 17, udp(1, 2, b'\xaa\xbb\xcc\xdd'))), r_header(15, bytes(24))])], seq=6))
    # truncated headers (the frame is longer than the sampled bytes), zero length header, odd lengths
    add(dgram(5, [flow5(12, [r_header(1, udp_pkt, frame_len=1514, hdr_len=30),
                               r_header(1, tcp_pkt, frame_len=1514, hdr_len=15),
                               r_header(1, udp_pkt, frame_len=1514, hdr_len=0),
                               r_header(11, ipv4(A4, B4, 6, tcp(1, 2) + bytes(10)), frame_len=1500, hdr_len=21)])], seq=7))
    # a sample inside a sample: sFlow in the sampled header (UDP port 6343), nested twice
    inner = dgram(5, [counters5(1, [record(1, c_generic(9))])], seq=90)
    mid = dgram(5, [flow5(13, [r_header(1, udp_frame(inner, ident=50))])], seq=91)
    add(dgram(5, [flow5(14, [r_header(1, udp_frame(mid, ident=51))])], seq=8))

    # ---- version 5 counters samples
    add(dgram(5, [counters5(20, [record(1, c_generic()), record(2, c_ethernet()), record(3, c_tokenring()),
                                   record(4, c_vg()), record(5, c_vlan()), record(7, c_lag())])], seq=9))
    add(dgram(5, [counters5(21, [record(6, c_80211()), record(1001, c_processor()), record(1002, c_radio())])], seq=10))
    add(dgram(5, [counters5_expanded(22, [record(1, c_generic(11))]),
                  s5(7, lag_stats())], seq=11))
    # several samples in one datagram, an unknown sample format (skipped by length), non standard enterprise records
    add(dgram(5, [counters5(23, [record(1, c_generic(12))]), s5(9, b'\1\2\3\4\5\6\7\x08'),
                  flow5(24, [record(1, b'\0\0\0\1\0\0\0\2', enterprise=4300), r_header()]),
                  counters5(25, [record(1, b'\0\0\0\5', enterprise=4301), record(1, c_generic(13))])], seq=12))
    # a sample of a non standard enterprise ends the datagram
    add(dgram(5, [s5(1, b'\0' * 12, enterprise=4302)], seq=13))

    # ---- version 4: flow samples (header, IPv4, IPv6, unknown packet data), extended data
    f4 = udp_pkt
    add(dgram(4, [flow24(1, 1, v24_header(4, f4), [(1, r_switch()), (2, r_router(1)), (3, r_gateway4()),
                                                    (4, b''), (5, b''), (99, b'')], out=5)], seq=1))
    add(dgram(4, [flow24(2, 2, b'', [], out=0x80000003), flow24(3, 3, b'', [], out=0x80000000),
                  flow24(4, 9, b'', [(2, r_router(2))], out=7)], seq=2, agent=2))
    # a version 4 sample of an unknown type ends the datagram (nothing of it is dissected)
    add(dgram(4, [flow24(5, 1, v24_header(4, tcp_pkt, frame_len=1514, hdr_len=30), [(3, r_gateway4(((1, (1, 2)),), ()))]),
                  P('I', 9) + bytes(8)], seq=3))
    # version 4 counters samples
    gen = c_generic()
    add(dgram(4, [counters24(1, 1, gen), counters24(2, 2, gen + bytes(52)), counters24(3, 3, gen + c_tokenring()),
                  counters24(4, 4, gen), counters24(5, 5, gen + c_vg()), counters24(6, 6, gen),
                  counters24(7, 7, c_vlan()), counters24(8, 99, b'')], seq=4))
    # ---- version 2
    add(dgram(2, [flow24(1, 1, v24_header(2, f4), [(1, r_switch()), (2, r_router(1)), (3, r_gateway2())], out=5),
                  counters24(2, 1, gen)], seq=5))
    # an unknown agent address type (or version) means the datagram is not sFlow: it stays plain UDP
    add(P('II', 5, 7) + bytes(40))
    return F


def malformed():
    F = []

    def add(d, **kw):
        F.append(udp_frame(d, ident=len(F) + 1, **kw))

    # unknown record formats (expert info), in a flow sample and a counters sample
    add(dgram(5, [flow5(1, [record(777, b'\1\2\3\4\5\6\7\x08'), r_header()])]))
    add(dgram(5, [counters5(2, [record(777, b'\1\2\3\4\5\6\7\x08')])]))
    # unknown address types inside records
    add(dgram(5, [flow5(3, [record(1002, r_router(9))])]))
    add(dgram(5, [flow5(4, [record(1007, addr(5) + addr(6))])]))
    # not sFlow: wrong version, unknown agent address type
    add(P('II', 3, 1) + bytes(40))
    add(P('II', 5, 7) + bytes(40))
    # sample length longer than the datagram
    add(P('III', 5, 0, 7)[:8] + P('IIII', 1, 1, 1000, 1) + P('II', 1, 4000) + bytes(8))
    # truncated datagrams
    d = dgram(5, [flow5(1, [r_header(), record(2, r_ethernet())])])
    add(d[:20])
    add(d[:60])
    add(d[:90])
    d = dgram(5, [counters5(2, [record(1, c_generic()), record(3, c_tokenring())])])
    add(d[:70])
    add(d[:120])
    add(dgram(4, [flow24(1, 1, v24_header(4, eth(ipv4(A4, B4, 17, udp(1, 2, b'x')))), [(3, r_gateway4())])])[:100])
    add(dgram(4, [counters24(1, 2, c_generic())])[:50])
    # header length larger than the sample data
    add(dgram(5, [flow5(5, [P('II', 1, 40) + P('IIII', 1, 100, 4, 400) + bytes(20)])]))
    # label / AS counts larger than the data
    add(dgram(5, [flow5(6, [record(1006, addr(1) + P('I', 200) + bytes(8))])]))
    add(dgram(5, [flow5(7, [record(1003, addr(1) + P('IIII', 1, 2, 3, 1000) + bytes(16))])]))
    add(dgram(5, [flow5(8, [record(1012, P('I', 50) + bytes(8))])]))
    # strings longer than the record
    add(dgram(5, [flow5(9, [record(1004, P('II', 1, 4000) + b'abcd')])]))
    # 802.11 tx with an SSID longer than 32 octets: the dissector clamps the length but not the offset
    add(dgram(5, [flow5(10, [record(1015, r_80211_tx(3, 300, 200, 'A' * 40))])]))
    # many samples with 255+ count (only 255 are walked)
    add(P('III', 5, 1, 0)[:8] + bytes(A4) + P('IIII', 1, 1, 1, 0x1ff))
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'sflow-coverage.pcap'), clean())
    pcap(os.path.join(out, 'sflow-coverage-malformed.pcap'), malformed())

#!/usr/bin/env python3
# Generates test/captures/sctp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the SCTP coverage captures (synthetic, built with struct only):
#   sctp-coverage.pcapng            main capture, decodes clean
#   sctp-coverage-malformed.pcapng  paths only malformed input reaches
# Usage: mksctp.py <outdir>
import struct
import sys
import os
import zlib

# --------------------------------------------------------------------------
# checksums
# --------------------------------------------------------------------------
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _CRC_TABLE[(c ^ b) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff


# --------------------------------------------------------------------------
# pcapng writer
# --------------------------------------------------------------------------
LT_ETH = 1
LT_SCTP = 248


def _blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


class Pcapng:
    def __init__(self, linktypes=(LT_ETH, LT_SCTP)):
        self.linktypes = linktypes
        self.frames = []
        self.ts = 1700000000 * 1000000

    def add(self, data, iface=0, dt=10000):
        self.ts += dt
        self.frames.append((iface, self.ts, data))
        return len(self.frames)

    def write(self, fn):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
        for iface, ts, data in self.frames:
            out += _blk(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff,
                                       len(data), len(data)) + data)
        with open(fn, 'wb') as f:
            f.write(out)


# --------------------------------------------------------------------------
# link, network, SCTP packet
# --------------------------------------------------------------------------
def _csum16(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(proto, payload, src, dst):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', _csum16(h)) + h[12:]
    return h + payload


def _a6(a):
    import socket
    return socket.inet_pton(socket.AF_INET6, a)


def ip6(proto, payload, src, dst):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), proto, 64,
                       _a6(src), _a6(dst)) + payload


def eth(payload, v6=False):
    return (b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' +
            struct.pack('!H', 0x86dd if v6 else 0x0800) + payload)


def sctp_packet(sport, dport, vtag, chunks, csum='crc32c'):
    """csum: crc32c, adler, zero, bad, both (a packet whose adler32 and
    crc32c are both right is impossible; 'both' is only used for zero)"""
    body = b''.join(chunks) if isinstance(chunks, (list, tuple)) else chunks
    hdr = struct.pack('!HHII', sport, dport, vtag, 0)
    raw = hdr + body
    if csum == 'crc32c':
        c = struct.pack('<I', crc32c(raw))
    elif csum == 'adler':
        c = struct.pack('!I', zlib.adler32(raw) & 0xffffffff)
    elif csum == 'bad':
        c = b'\xde\xad\xbe\xef'
    else:
        c = b'\0\0\0\0'
    return hdr[:8] + c + body


def frame4(pkt, src, dst):
    return eth(ip4(132, pkt, src, dst))


def frame6(pkt, src, dst):
    return eth(ip6(132, pkt, src, dst), True)


def frame_udp(pkt, src, dst, sport=9899, dport=9899):
    u = struct.pack('!HHHH', sport, dport, 8 + len(pkt), 0) + pkt
    return eth(ip4(17, u, src, dst))


# --------------------------------------------------------------------------
# chunks, parameters, causes
# --------------------------------------------------------------------------
def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def chunk(t, flags, value=b'', length=None):
    ln = 4 + len(value) if length is None else length
    return pad4(struct.pack('!BBH', t, flags, ln) + value)


def tlv(t, value=b'', length=None):
    ln = 4 + len(value) if length is None else length
    return struct.pack('!HH', t, ln) + value


def tlvs(items):
    """concatenate TLVs, padded except the last (the chunk length does not
    include the padding of the last one)"""
    out = b''
    for i, it in enumerate(items):
        out += it if i == len(items) - 1 else pad4(it)
    return out


def ipv4p(a):
    return tlv(5, bytes(int(x) for x in a.split('.')))


def ipv6p(a):
    return tlv(6, _a6(a))


def data(tsn, sid, ssn, ppid, payload, B=1, E=1, U=0, I=0):
    fl = (E) | (B << 1) | (U << 2) | (I << 3)
    return chunk(0, fl, struct.pack('!IHHI', tsn, sid, ssn, ppid) + payload)


def idata(tsn, sid, mid, pf, payload, B=1, E=1, U=0, I=0):
    # pf is the PPID for the first fragment, the FSN for the others
    fl = (E) | (B << 1) | (U << 2) | (I << 3)
    return chunk(64, fl, struct.pack('!IHHII', tsn, sid, 0, mid, pf) + payload)


def init_like(t, tag, arwnd, nout, nin, itsn, params):
    return chunk(t, 0, struct.pack('!IIHHI', tag, arwnd, nout, nin, itsn) + tlvs(params))


def sack(cum, arwnd, gaps=(), dups=(), ns=0):
    v = struct.pack('!IIHH', cum, arwnd, len(gaps), len(dups))
    for s, e in gaps:
        v += struct.pack('!HH', s, e)
    for d in dups:
        v += struct.pack('!I', d)
    return chunk(3, ns, v)


def nrsack(cum, arwnd, gaps=(), nrgaps=(), dups=(), ns=0):
    v = struct.pack('!IIHHHH', cum, arwnd, len(gaps), len(nrgaps), len(dups), 0)
    for s, e in gaps:
        v += struct.pack('!HH', s, e)
    for s, e in nrgaps:
        v += struct.pack('!HH', s, e)
    for d in dups:
        v += struct.pack('!I', d)
    return chunk(16, ns, v)


def hb(info=b'\x01\x02\x03\x04\x05\x06\x07\x08'):
    return chunk(4, 0, tlv(1, info))


def hback(info=b'\x01\x02\x03\x04\x05\x06\x07\x08'):
    return chunk(5, 0, tlv(1, info))


def cause(code, value=b''):
    return tlv(code, value)


def abort(causes, T=0):
    return chunk(6, T, tlvs(causes))


def error(causes):
    return chunk(9, 0, tlvs(causes))


def fwd_tsn(tsn, streams=()):
    v = struct.pack('!I', tsn)
    for sid, ssn in streams:
        v += struct.pack('!HH', sid, ssn)
    return chunk(192, 0, v)


def ifwd_tsn(tsn, streams=()):
    v = struct.pack('!I', tsn)
    for sid, u, mid in streams:
        v += struct.pack('!HHI', sid, u, mid)
    return chunk(194, 0, v)


def reconfig(params):
    return chunk(130, 0, tlvs(params))


def asconf(seq, params):
    return chunk(193, 0, struct.pack('!I', seq) + tlvs(params))


def asconf_ack(seq, params):
    return chunk(128, 0, struct.pack('!I', seq) + tlvs(params))


def pktdrop(embedded, flags=0, bw=1000000, q=4096, trunc=0):
    return chunk(0x81, flags,
                 struct.pack('!IIHH', bw, q, trunc, 0) + embedded)


M3UA_BEAT = bytes([1, 0, 3, 3, 0, 0, 0, 8])
M3UA_BEAT_DATA = bytes([1, 0, 3, 3, 0, 0, 0, 12, 0, 9, 0, 4])


def tag(n):
    return bytes((n + i) & 0xff for i in range(32))


# --------------------------------------------------------------------------
# the captures
# --------------------------------------------------------------------------
class Main:
    def __init__(self):
        self.p = Pcapng()
        self.n = 0
        self.marks = {}

    def add(self, fr, iface=0, dt=10000, mark=None):
        self.n = self.p.add(fr, iface, dt)
        if mark:
            self.marks[mark] = self.n
        return self.n


def build_main(out):
    m = Main()
    C, S = '192.0.2.1', '192.0.2.2'
    CP, SP = 40000, 50000
    Tc, Ts = 0x0c0c0c0c, 0x5a5a5a5a

    def c2s(chunks, csum='crc32c', src=C, dst=S, vtag=Ts, mark=None, dt=10000):
        return m.add(frame4(sctp_packet(CP, SP, vtag, chunks, csum), src, dst), mark=mark, dt=dt)

    def s2c(chunks, csum='crc32c', src=S, dst=C, vtag=Tc, mark=None, dt=10000):
        return m.add(frame4(sctp_packet(SP, CP, vtag, chunks, csum), src, dst), mark=mark, dt=dt)

    # ---- association 1: handshake with every INIT / INIT ACK parameter ----
    init_params = [
        ipv4p('192.0.2.1'), ipv6p('2001:db8::1'),
        tlv(9, struct.pack('!I', 60000)),                       # cookie preservative
        tlv(11, b'client.example.net\0'),                       # hostname
        tlv(12, struct.pack('!HHHH', 5, 6, 11, 42)),            # supported address types
        tlv(0x8000),                                            # ECN
        tlv(0x8001, struct.pack('!I', 1)),                      # zero checksum, DTLS
        tlv(0x8002, tag(1)),                                    # random
        tlv(0x8003, bytes([0, 3, 4, 192, 193, 200])),           # chunks to authenticate
        tlv(0x8004, struct.pack('!HHH', 1, 3, 7)),              # HMAC algorithms
        tlv(0x8006, struct.pack('!IBBBBB', 0x01020304, 0x07, 1, 0xc0, 9, 0)),  # DTLS KM
        tlv(0x8008, bytes([15, 64, 128, 130, 192, 193, 194, 77])),  # supported extensions
        tlv(0xc000),                                            # forward TSN supported
        tlv(0xc006, struct.pack('!I', 0x0000000b)),             # adaptation layer
        tlv(0x8010, b'\x11\x22\x33'),                           # unknown, skip
        tlv(0x4020, b'\x44\x55\x66\x77'),                       # unknown, report
        tlv(0x0f00, b''),                                       # unknown, empty
    ]
    m.add(frame4(sctp_packet(CP, SP, 0, [init_like(1, Tc, 65536, 10, 65535, 1000, init_params)]), C, S), mark='init')
    ack_params = [
        tlv(7, tag(7)[:24]),                                    # state cookie
        ipv4p('192.0.2.2'), ipv6p('2001:db8::2'), ipv4p('198.51.100.2'),
        tlv(11, b'server.example.net\0'),
        tlv(8, tlv(0x8010, b'\x01\x02')),                       # unrecognized parameter
        tlv(0x8006, struct.pack('!IBBB', 0x0a0b0c0d, 0x03, 0xc0, 1)),
        tlv(0x8008, bytes([192, 193])),
        tlv(0x8001, struct.pack('!I', 2)),                      # zero checksum, other EDMID
        tlv(0x8004, struct.pack('!H', 3)),
        tlv(0xc000),
    ]
    m.add(frame4(sctp_packet(SP, CP, Tc, [init_like(2, Ts, 131072, 65535, 10, 5000, ack_params)]), S, C), mark='initack')
    c2s([chunk(10, 0, tag(9)[:24])], mark='cookie_echo')
    s2c([chunk(11, 0)], mark='cookie_ack')

    # ---- DATA, SACK and TSN analysis ----
    c2s([data(1000, 0, 0, 0, b'hello world', I=1)], mark='data1000')                   # 4+... first DATA
    s2c([sack(1000, 65536)], mark='sack1000')                                        # acks TSN 1000
    c2s([data(1001, 1, 0, 3, M3UA_BEAT, U=1)], mark='m3ua_ppi')                      # PPID 3 -> M3UA
    c2s([data(1002, 2, 0, 0, b'two'), data(1003, 2, 1, 0, b'three')], mark='bundle2')  # two DATA chunks
    s2c([sack(1001, 65000, gaps=[(2, 2)], dups=[1000]), data(5000, 0, 0, 0, b'reply')],
        mark='sack_gap_data')                                                         # SACK + DATA
    # fragmented ordered message, SSN 3, in order
    c2s([data(1004, 0, 3, 0, b'A' * 40, B=1, E=0)], mark='frag_b')
    c2s([data(1005, 0, 3, 0, b'B' * 40, B=0, E=0)], mark='frag_m')
    c2s([data(1006, 0, 3, 0, b'C' * 23, B=0, E=1)], mark='frag_e')
    # out of order: first, last, middle (SSN 4)
    c2s([data(1007, 0, 4, 0, b'D' * 30, B=1, E=0)], mark='ooo_b')
    c2s([data(1009, 0, 4, 0, b'F' * 30, B=0, E=1)], mark='ooo_e')
    c2s([data(1008, 0, 4, 0, b'E' * 30, B=0, E=0)], mark='ooo_m')
    # unordered fragments on stream 1
    c2s([data(1010, 1, 0, 0, b'U' * 20, B=1, E=0, U=1)], mark='ufrag_b')
    c2s([data(1011, 1, 0, 0, b'V' * 20, B=0, E=1, U=1)], mark='ufrag_e')
    # M3UA message fragmented over two chunks: the reassembled message goes to M3UA
    c2s([data(1012, 3, 0, 3, M3UA_BEAT_DATA[:6], B=1, E=0)], mark='m3ua_frag_b')
    c2s([data(1013, 3, 0, 3, M3UA_BEAT_DATA[6:], B=0, E=1)], mark='m3ua_frag_e')
    # retransmissions: of the first fragment of SSN 3 (duplicate fragment), of 1000 (after ack)
    c2s([data(1004, 0, 3, 0, b'A' * 40, B=1, E=0)], mark='retrans_frag', dt=300000)
    c2s([data(1000, 0, 0, 0, b'hello world', I=1)], mark='retrans_acked', dt=300000)
    for i in range(3):
        c2s([data(1002, 2, 0, 0, b'two')], mark='retrans_%d' % i, dt=250000)
    s2c([sack(1013, 60000)], mark='sack1013')
    s2c([sack(1013, 0)], mark='sack_zero_wnd')                                       # zero a_rwnd
    # a SACK with a large gap count of acked TSNs (> 100)
    s2c([sack(1013, 60000, gaps=[(2, 120), (130, 140)])], mark='sack_big_gap')
    s2c([sack(1013, 60000, gaps=[(5, 9), (3, 4)])], mark='sack_gap_order')           # out of order
    s2c([nrsack(1013, 60000, gaps=[(2, 3)], nrgaps=[(5, 6), (8, 8)], dups=[1001, 1002], ns=1)],
        mark='nrsack')
    s2c([nrsack(1013, 60000, gaps=[(2, 150)], nrgaps=[(200, 400)])], mark='nrsack_big')
    # I-DATA: complete, fragmented in order, unordered
    c2s([idata(1014, 1, 0, 0, b'idata complete', I=1)], mark='idata_c')
    c2s([idata(1015, 1, 1, 0, b'I' * 30, B=1, E=0)], mark='idata_b')
    c2s([idata(1016, 1, 1, 1, b'J' * 30, B=0, E=0)], mark='idata_m')
    c2s([idata(1017, 1, 1, 2, b'K' * 12, B=0, E=1)], mark='idata_e')
    c2s([idata(1018, 2, 7, 0, b'L' * 12, B=1, E=0, U=1)], mark='idata_ub')
    c2s([idata(1019, 2, 7, 1, b'M' * 12, B=0, E=1, U=1)], mark='idata_ue')
    # a full I-DATA message carrying PPID 3 (M3UA)
    c2s([idata(1020, 4, 0, 3, M3UA_BEAT)], mark='idata_m3ua')
    # heartbeat, forward TSN, I-FORWARD-TSN, ECNE, CWR
    c2s([hb()], mark='heartbeat')
    s2c([hback()], mark='heartbeat_ack')
    c2s([fwd_tsn(1020, [(0, 4), (1, 2)])], mark='fwd_tsn')
    c2s([ifwd_tsn(1020, [(1, 0, 3), (2, 1, 9)])], mark='ifwd_tsn')
    s2c([chunk(12, 0, struct.pack('!I', 1010))], mark='ecne')
    c2s([chunk(13, 0, struct.pack('!I', 1010))], mark='cwr')
    # AUTH bundled with DATA, DTLS chunk, PAD chunk, unknown chunks
    c2s([chunk(15, 0, struct.pack('!HH', 1, 3) + tag(3)), data(1021, 0, 5, 0, b'authenticated')],
        mark='auth_data')
    c2s([chunk(0x41, 1, b"dtls record")], mark='dtls_chunk')       # type 67? (dtls)
    c2s([chunk(132, 0, b'\0' * 16)], mark='pad_chunk')
    c2s([chunk(0x20, 0, b'skip'), chunk(0x60, 0, b'report'), chunk(0xa0, 0, b''),
         chunk(0xe0, 0, b'\x01\x02\x03\x04\x05')], mark='unknown_chunks')
    c2s([chunk(0xff, 0, b'ietf ext')], mark='ietf_ext')

    # ---- stream reset and ASCONF ----
    c2s([reconfig([
        tlv(13, struct.pack('!IIIHH', 1, 0, 1021, 0, 1)),
        tlv(14, struct.pack('!IHH', 2, 0, 1)),
        tlv(15, struct.pack('!I', 3)),
    ])], mark='reconfig_req')
    s2c([reconfig([
        tlv(16, struct.pack('!II', 1, 1)),
        tlv(16, struct.pack('!III', 2, 4, 5000)),
        tlv(16, struct.pack('!IIII', 3, 1, 5001, 1022)),
        tlv(17, struct.pack('!IHH', 4, 4, 0)),
        tlv(18, struct.pack('!IHH', 5, 2, 0)),
        tlv(13, struct.pack('!II', 9, 0) + struct.pack('!I', 9)),    # no stream ids
        tlv(14, struct.pack('!I', 10)),
    ])], mark='reconfig_rsp')
    c2s([asconf(1, [ipv4p('192.0.2.1'),
                    tlv(0xc001, struct.pack('!I', 11) + ipv4p('198.51.100.1')),
                    tlv(0xc002, struct.pack('!I', 12) + ipv6p('2001:db8::5')),
                    tlv(0xc004, struct.pack('!I', 13) + ipv4p('198.51.100.1')),
                    tlv(0xc001, struct.pack('!I', 14) + tlv(11, b'alt.example.net\0'))])],
        mark='asconf')
    s2c([asconf_ack(1, [tlv(0xc005, struct.pack('!I', 11)),
                        tlv(0xc003, struct.pack('!I', 12) + cause(0xa0, ipv4p('192.0.2.1'))),
                        tlv(0xc003, struct.pack('!I', 13) + cause(0xa1, tlv(0xc001, struct.pack('!I', 5) + ipv4p('198.51.100.1'))) + cause(0xa4, ipv4p('198.51.100.1'))),
                        tlv(0xc005, struct.pack('!I', 14))])],
        mark='asconf_ack')

    # ---- multihoming: the same association from another address ----
    c2s([data(1022, 0, 6, 0, b'second path')], src='198.51.100.1', dst='198.51.100.2', mark='multihome')
    s2c([sack(1022, 65536)], src='198.51.100.2', dst='198.51.100.1', mark='multihome_sack')

    # ---- ERROR chunk with causes and PKTDROP ----
    s2c([error([cause(1, struct.pack('!HH', 77, 0)), cause(2, struct.pack('!I', 2) + struct.pack('!HH', 5, 9)),
                cause(3, struct.pack('!I', 123456)), cause(4), cause(5, ipv4p('203.0.113.9')),
                cause(6, chunk(0xfe, 0, b'\x01\x02\x03\x04')), cause(7), cause(8, tlv(0x8010, b'abcd')),
                cause(9, struct.pack('!I', 1999)), cause(10)])], mark='error1')
    s2c([error([cause(11, ipv4p('203.0.113.7') + ipv6p('2001:db8::7')),
                cause(12, b'user abort text'), cause(13, b'protocol violation text'),
                cause(100), cause(101), cause(102), cause(103),
                cause(0xa0, ipv4p('192.0.2.1')), cause(0xa1, ipv4p('192.0.2.1')),
                cause(0xa2, ipv6p('2001:db8::1')), cause(0xa3, b'\x00\x01\x02'),
                cause(0xa4, ipv4p('192.0.2.1')), cause(0x105, struct.pack('!H', 2)),
                cause(0x7777, b'unknown cause info'), cause(0x7778)])], mark='error2')
    inner_data = sctp_packet(SP, CP, Tc, [data(5001, 0, 1, 0, b'dropped')], 'crc32c')
    s2c([pktdrop(inner_data, 0x01 | 0x02)], mark='pktdrop')                             # M and B
    inner_trunc = sctp_packet(SP, CP, Tc, [data(5002, 0, 2, 0, b'truncated data')], 'zero')[:24]
    s2c([pktdrop(inner_trunc, 0x04, trunc=24)], mark='pktdrop_trunc')                  # T bit
    inner_init = sctp_packet(CP, SP, 0, [init_like(1, 0x77777777, 1000, 2, 2, 7, [ipv4p('192.0.2.1')])], 'zero')
    s2c([pktdrop(inner_init, 0)], mark='pktdrop_init')
    s2c([pktdrop(b'', 0)], mark='pktdrop_empty')
    # PKTDROP carrying a PKTDROP, a few levels deep
    nested = sctp_packet(SP, CP, Tc, [data(5003, 0, 3, 0, b'nested')], 'zero')
    for _ in range(6):
        nested = sctp_packet(SP, CP, Tc, [pktdrop(nested, 0)], 'zero')
    s2c([pktdrop(nested, 0)], mark='pktdrop_nested')

    # SIP over SCTP is found by the heuristic dissector
    c2s([data(1050, 5, 0, 0, b'OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/SCTP host.example.com;branch=z9hG4bK1\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=1\r\nCall-ID: sctp1@host.example.com\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')],
        mark='sip_heur')
    # a second message with the key of an earlier one (unordered stream 1)
    c2s([data(1140, 1, 0, 0, b'W' * 20, B=1, E=0, U=1)], mark='ufrag2_b')
    c2s([data(1141, 1, 0, 0, b'X' * 20, B=0, E=1, U=1)], mark='ufrag2_e')
    # I-DATA: the last fragment first
    c2s([idata(1142, 3, 20, 1, b'N' * 10, B=0, E=1)], mark='idata_e_first')
    c2s([idata(1143, 3, 20, 100, b'O' * 10, B=1, E=0)], mark='idata_b_second')
    # several beginnings and ends pending for one message (stream 9 and 10)
    for i, t in enumerate((1160, 1170, 1165, 1155)):
        c2s([data(t, 9, 0, 0, b'b%d' % i, B=1, E=0)], mark='begins_%d' % i)
    for i, t in enumerate((1180, 1175, 1178, 1190)):
        c2s([data(t, 10, 0, 0, b'e%d' % i, B=0, E=1)], mark='ends_%d' % i)
    # an end before its beginning with a higher TSN (stream 11)
    c2s([data(1100, 11, 0, 0, b'endfirst', B=0, E=1)], mark='end_before_begin_e')
    c2s([data(1110, 11, 0, 0, b'beginlater', B=1, E=0)], mark='end_before_begin_b')
    # an old end pending when a message completes (stream 12)
    c2s([data(1120, 12, 0, 0, b'old end', B=0, E=1)], mark='old_end')
    c2s([data(1121, 12, 0, 0, b'B' * 6, B=1, E=0)], mark='s12_b')
    c2s([data(1122, 12, 0, 0, b'M' * 6, B=0, E=0)], mark='s12_m')
    c2s([data(1123, 12, 0, 0, b'E' * 6, B=0, E=1)], mark='s12_e')
    # a second beginning pending when a message completes (stream 13)
    c2s([data(1130, 13, 0, 0, b'B' * 6, B=1, E=0)], mark='s13_b1')
    c2s([data(1135, 13, 0, 0, b'B' * 6, B=1, E=0)], mark='s13_b2')
    c2s([data(1131, 13, 0, 0, b'M' * 6, B=0, E=0)], mark='s13_m')
    c2s([data(1132, 13, 0, 0, b'E' * 6, B=0, E=1)], mark='s13_e')
    # a third message with the key of the earlier ones (unordered stream 1)
    c2s([data(1150, 1, 0, 0, b'Y' * 20, B=1, E=0, U=1)], mark='ufrag3_b')
    c2s([data(1151, 1, 0, 0, b'Z' * 20, B=0, E=1, U=1)], mark='ufrag3_e')
    # three beginnings pending when the message of the last one completes (stream 15)
    for i, t in enumerate((1300, 1310, 1320)):
        c2s([data(t, 15, 0, 0, b'B' * 6, B=1, E=0)], mark='s15_b%d' % i)
    c2s([data(1301, 15, 0, 0, b'M' * 6, B=0, E=0)], mark='s15_m')
    c2s([data(1302, 15, 0, 0, b'E' * 6, B=0, E=1)], mark='s15_e')
    # two old ends pending when a message completes (stream 16)
    c2s([data(1400, 16, 0, 0, b'old end 1', B=0, E=1)], mark='s16_e1')
    c2s([data(1401, 16, 0, 0, b'old end 2', B=0, E=1)], mark='s16_e2')
    c2s([data(1402, 16, 0, 0, b'B' * 6, B=1, E=0)], mark='s16_b')
    c2s([data(1403, 16, 0, 0, b'M' * 6, B=0, E=0)], mark='s16_m')
    c2s([data(1404, 16, 0, 0, b'E' * 6, B=0, E=1)], mark='s16_e')
    # NR-SACK with gaps and NR gaps out of order
    s2c([nrsack(1013, 60000, gaps=[(5, 9), (3, 4)], nrgaps=[(8, 9), (2, 3)])], mark='nrsack_order')

    # ---- shutdown ----
    c2s([chunk(7, 0, struct.pack('!I', 5001))], mark='shutdown')
    s2c([chunk(8, 0)], mark='shutdown_ack')
    c2s([chunk(14, 0)], mark='shutdown_complete')

    # ---- S1: unordered middle fragments past the per-message limit ----
    chunks = []
    for i in range(1030):
        chunks.append(data(20000 + i, 7, 0, 0, b'x', B=0, E=0, U=1))
    m.add(frame4(sctp_packet(CP, SP, Ts, chunks, 'crc32c'), C, S), mark='toomany')

    # ---- many chunks in one packet (more than the per-packet tvb array) ----
    m.add(frame4(sctp_packet(CP, SP, Ts, [chunk(132, 0)] * 2100, 'crc32c'), C, S), mark='manychunks')
    # more distinct PPIDs than the dissector remembers
    c2s([data(1030, 0, 7, 100, b'p0'), data(1031, 0, 8, 101, b'p1'), data(1032, 0, 9, 102, b'p2'),
         data(1033, 0, 10, 103, b'p3')], mark='ppids')

    # ---- association 2: IPv6, port 2905 (M3UA by port), HEARTBEAT, other checksums ----
    A6, B6 = '2001:db8::a', '2001:db8::b'
    ta, tb = 0x01010101, 0x02020202

    def a2b(chunks, csum='crc32c', mark=None, vtag=tb):
        return m.add(frame6(sctp_packet(2905, 2905, vtag, chunks, csum), A6, B6), mark=mark)

    def b2a(chunks, csum='crc32c', mark=None, vtag=ta):
        return m.add(frame6(sctp_packet(2905, 2905, vtag, chunks, csum), B6, A6), mark=mark)

    m.add(frame6(sctp_packet(2905, 2905, 0, [init_like(1, ta, 32768, 2, 2, 100, [ipv6p(A6)])], 'adler'), A6, B6),
          mark='a2_init')
    b2a([init_like(2, tb, 32768, 2, 2, 200, [tlv(7, tag(2)[:20]), ipv6p(B6)])], 'adler', mark='a2_initack')
    a2b([chunk(10, 0, tag(2)[:20])], 'adler', mark='a2_cookie')
    b2a([chunk(11, 0)], 'adler', mark='a2_cookie_ack')
    a2b([data(100, 0, 0, 3, M3UA_BEAT)], 'adler', mark='a2_data_m3ua')               # port 2905 and PPID 3
    a2b([data(101, 0, 1, 0, M3UA_BEAT)], 'adler', mark='a2_data_port')               # port 2905 only
    b2a([sack(101, 32768)], 'adler', mark='a2_sack')
    b2a([data(200, 0, 0, 0, M3UA_BEAT)], 'zero', mark='a2_zero_csum')
    a2b([sack(200, 32768, gaps=[(2, 3)])], 'zero', mark='a2_sack_gap')
    a2b([hb()], 'crc32c', mark='a2_hb')
    # TSN wrap: fragments 0xfffffffe .. 0x00000001 (absolute TSNs)
    wrapmsg = bytes([1, 0, 3, 3, 0, 0, 0, 40, 0, 9, 0, 32]) + b'0123456789abcdefghijklmnopqr'
    assert len(wrapmsg) == 40
    a2b([data(0xfffffffe, 1, 0, 0, wrapmsg[0:8], B=1, E=0)], mark='wrap_b')
    a2b([data(0xffffffff, 1, 0, 0, wrapmsg[8:16], B=0, E=0)], mark='wrap_m1')
    a2b([data(0x00000000, 1, 0, 0, wrapmsg[16:24], B=0, E=0)], mark='wrap_m2')
    a2b([data(0x00000001, 1, 0, 0, wrapmsg[24:32], B=0, E=0)], mark='wrap_m3')
    a2b([data(0x00000002, 1, 0, 0, wrapmsg[32:40], B=0, E=1)], mark='wrap_e')
    b2a([sack(0x00000002, 32768)], mark='a2_sack_wrap')
    # shutdown complete with the T bit (tag reflected) and an ABORT with the T bit
    a2b([chunk(14, 1)], mark='a2_sc_t', vtag=ta)
    b2a([abort([cause(12, b'bye')], T=1)], mark='a2_abort_t', vtag=tb)

    # ---- association 3: SCTP over UDP (port 9899), two directions ----
    U1, U2 = '192.0.2.31', '192.0.2.32'
    m.add(frame_udp(sctp_packet(7000, 7001, 0, [init_like(1, 0x31313131, 8192, 1, 1, 1, [ipv4p(U1)])], 'crc32c'),
                    U1, U2), mark='udp_init')
    m.add(frame_udp(sctp_packet(7001, 7000, 0x31313131, [init_like(2, 0x32323232, 8192, 1, 1, 1, [tlv(7, tag(3)[:16])])], 'crc32c'),
                    U2, U1), mark='udp_initack')
    m.add(frame_udp(sctp_packet(7000, 7001, 0x32323232, [data(1, 0, 0, 0, b'over udp')], 'crc32c'),
                    U1, U2), mark='udp_data')
    m.add(frame_udp(sctp_packet(7001, 7000, 0x31313131, [sack(1, 8192)], 'crc32c'), U2, U1), mark='udp_sack')

    # ---- association 4: DLT_SCTP (no IP header, so no addresses) ----
    m.add(sctp_packet(8000, 8001, 0, [init_like(1, 0x41414141, 4096, 1, 1, 1, [])], 'crc32c'), iface=1, mark='dlt_init')
    m.add(sctp_packet(8001, 8000, 0x41414141, [init_like(2, 0x42424242, 4096, 1, 1, 1, [tlv(7, tag(4)[:12])])], 'crc32c'),
          iface=1, mark='dlt_initack')
    m.add(sctp_packet(8000, 8001, 0x42424242, [data(1, 0, 0, 0, b'dlt data'), data(2, 0, 1, 0, b'dlt data 2')], 'crc32c'),
          iface=1, mark='dlt_data')
    m.add(sctp_packet(8001, 8000, 0x41414141, [sack(2, 4096)], 'crc32c'), iface=1, mark='dlt_sack')

    # ---- associations 5, 6: no handshake seen, DATA in both directions; ABORT/SHUTDOWN COMPLETE tags ----
    E1, E2 = '192.0.2.51', '192.0.2.52'
    m.add(frame4(sctp_packet(9000, 9001, 0xaaaa0001, [data(10, 0, 0, 0, b'first side')], 'crc32c'), E1, E2), mark='a5_d1')
    m.add(frame4(sctp_packet(9001, 9000, 0xbbbb0002, [data(20, 0, 0, 0, b'other side')], 'crc32c'), E2, E1), mark='a5_d2')
    m.add(frame4(sctp_packet(9000, 9001, 0xaaaa0001, [data(11, 0, 1, 0, b'first side 2')], 'crc32c'), E1, E2), mark='a5_d3')
    m.add(frame4(sctp_packet(9001, 9000, 0xbbbb0002, [sack(11, 100)], 'crc32c'), E2, E1), mark='a5_sack')
    m.add(frame4(sctp_packet(9001, 9000, 0xaaaa0001, [abort([cause(12, b'x')], T=0)], 'crc32c'), E2, E1), mark='a5_abort')
    # a second pair of ports on the same addresses
    m.add(frame4(sctp_packet(9100, 9101, 0xcccc0001, [data(1, 0, 0, 0, b'pair 2')], 'crc32c'), E1, E2), mark='a6_d1')
    m.add(frame4(sctp_packet(9101, 9100, 0xdddd0002, [data(1, 0, 0, 0, b'pair 2 back')], 'crc32c'), E2, E1), mark='a6_d2')
    # a packet that is only INIT_ACK (both tags known at once) and an INIT-less SHUTDOWN COMPLETE
    m.add(frame4(sctp_packet(9200, 9201, 0xeeee0001, [init_like(2, 0xeeee0002, 100, 1, 1, 1, [tlv(7, tag(5)[:8])])], 'crc32c'), E2, E1), mark='a7_initack')
    m.add(frame4(sctp_packet(9201, 9200, 0xeeee0002, [data(1, 0, 0, 0, b'after initack')], 'crc32c'), E1, E2), mark='a7_data')
    m.add(frame4(sctp_packet(9201, 9200, 0xeeee0002, [chunk(14, 1)], 'crc32c'), E1, E2), mark='a7_sc')
    m.add(frame4(sctp_packet(9200, 9201, 0xeeee0002, [chunk(14, 0)], 'crc32c'), E2, E1), mark='a7_sc2')
    # INIT with a different second tag and port reuse (new association with the same ports)
    m.add(frame4(sctp_packet(9200, 9201, 0, [init_like(1, 0xeeee0003, 100, 1, 1, 1, [])], 'crc32c'), E2, E1), mark='a8_init')

    # ---- the higher port number selects the payload dissector (M3UA on 2905) ----
    m.add(frame4(sctp_packet(1234, 2905, 0x0a0a0a0a, [data(1, 0, 0, 0, M3UA_BEAT)], 'crc32c'), '192.0.2.61', '192.0.2.62'),
          mark='high_port')
    # ---- ports whose sum collides in the association table ----
    m.add(frame4(sctp_packet(7, 13, 0x07070707, [data(1, 0, 0, 0, b'ports 7 13')], 'crc32c'), '192.0.2.63', '192.0.2.64'),
          mark='coll_1')
    m.add(frame4(sctp_packet(9, 11, 0x09090909, [data(1, 0, 0, 0, b'ports 9 11')], 'crc32c'), '192.0.2.65', '192.0.2.66'),
          mark='coll_2')
    # ---- equal ports: DATA first, then an INIT with its initiate tag in the same direction ----
    m.add(frame4(sctp_packet(6666, 6666, 0xb1b1b1b1, [data(1, 0, 0, 0, b'data first')], 'crc32c'), '192.0.2.67', '192.0.2.68'),
          mark='eq_data')
    m.add(frame4(sctp_packet(6666, 6666, 0, [init_like(1, 0xa1a1a1a1, 100, 1, 1, 1, [])], 'crc32c'), '192.0.2.67', '192.0.2.68'),
          mark='eq_init')
    # ---- port 0: the Exported PDU names the source port, or nothing ----
    m.add(frame4(sctp_packet(6000, 0, 0xc1c1c1c1, [data(1, 0, 0, 0, b'dest port 0')], 'crc32c'), '192.0.2.69', '192.0.2.70'),
          mark='port0_dst')
    m.add(frame4(sctp_packet(0, 0, 0xc2c2c2c2, [data(1, 0, 0, 0, b'both ports 0')], 'crc32c'), '192.0.2.71', '192.0.2.72'),
          mark='port0_both')

    # ---- an end first and its beginning later, the first TSN being a fragment ----
    m.add(frame4(sctp_packet(9300, 9301, 0xd1d1d1d1, [data(500, 14, 0, 0, b'last piece', B=0, E=1)], 'crc32c'), '192.0.2.73', '192.0.2.74'),
          mark='z_end')
    m.add(frame4(sctp_packet(9300, 9301, 0xd1d1d1d1, [data(505, 14, 0, 0, b'first piece', B=1, E=0)], 'crc32c'), '192.0.2.73', '192.0.2.74'),
          mark='z_begin')

    # ---- payload dissector selection ----
    # PPID 18 (SUA? no; use PPID 27 = SGSAP? use well known 46: not registered) -> data
    c2s([data(1040, 0, 11, 46, b'unregistered ppid')], mark='ppid_none')
    c2s([data(1041, 0, 12, 0, b'plain payload on an unregistered port')], mark='plain')

    m.p.write(os.path.join(out, 'sctp-coverage.pcapng'))
    return m


def build_malformed(out):
    m = Main()
    C, S = '192.0.2.1', '192.0.2.2'
    CP, SP = 41000, 51000
    Tc, Ts = 0x0c0c0c0d, 0x5a5a5a5b

    def c2s(chunks, csum='crc32c', vtag=Ts, mark=None, trunc=None):
        pkt = sctp_packet(CP, SP, vtag, chunks, csum)
        fr = frame4(pkt, C, S)
        if trunc is not None:
            m.n = len(m.p.frames) + 1
            m.p.ts += 10000
            # captured length shorter than the reported one
            body = fr[:trunc]
            m.p.frames.append((0, m.p.ts, body, len(fr)))
            return m.n
        return m.add(fr, mark=mark)

    # handshake so that TSN analysis and association tracking see an association
    m.add(frame4(sctp_packet(CP, SP, 0, [init_like(1, Tc, 65536, 4, 4, 1, [ipv4p(C)])]), C, S))
    m.add(frame4(sctp_packet(SP, CP, Tc, [init_like(2, Ts, 65536, 4, 4, 1, [tlv(7, tag(6)[:16])])]), S, C))
    # checksums
    c2s([data(1, 0, 0, 0, b'bad checksum')], csum='bad', mark='bad_checksum')
    c2s([data(2, 0, 1, 0, b'adler checksum')], csum='adler')
    c2s([data(3, 0, 2, 0, b'zero checksum')], csum='zero')
    # chunk length longer than the packet (expert), and shorter than the header
    c2s([chunk(0, 3, struct.pack('!IHHI', 4, 0, 3, 0) + b'abc', length=200)])
    c2s([chunk(0, 3, struct.pack('!IHHI', 5, 0, 4, 0) + b'abc', length=3)])
    c2s([chunk(0, 3, struct.pack('!IHHI', 5, 0, 4, 0), length=10)])                    # DATA header too short
    c2s([chunk(64, 3, struct.pack('!IHHII', 5, 0, 0, 0, 0), length=12)])              # I-DATA header too short
    c2s([chunk(1, 0, b'\0' * 8, length=12)])                                           # INIT too short
    c2s([chunk(2, 0, b'\0' * 8, length=12)])                                           # INIT ACK too short
    c2s([chunk(192, 0, b'', length=4)])                                                # FORWARD TSN too short
    c2s([chunk(194, 0, b'', length=4)])
    c2s([chunk(193, 0, b'', length=4)])                                                # ASCONF too short
    c2s([chunk(128, 0, b'', length=4)])                                                # ASCONF ACK too short
    c2s([chunk(0x81, 0, b'\0\0', length=6)])                                           # PKTDROP too short
    c2s([chunk(0x77, 0, b'', length=2)])                                               # bogus unknown chunk
    c2s([chunk(0x77, 0, b'', length=0)])
    # SACK gap blocks: start > end (error), a_rwnd 0
    c2s([sack(10, 0, gaps=[(9, 3)])])
    c2s([nrsack(10, 100, gaps=[(9, 3)], nrgaps=[(7, 2)])])
    # parameters: a padded-less middle parameter, padding after the final parameter, DTLS KM outside INIT
    c2s([chunk(1, 0, struct.pack('!IIHHI', 1, 2, 1, 1, 1) + tlv(5, b'\x01\x02\x03\x04') + tlv(8, b'\xaa\xbb\xcc') + tlv(5, b'\x05\x06\x07\x08'))])
    c2s([chunk(4, 0, tlv(1, b'\x01\x02\x03') + b'\0')])                                # padding after the final parameter
    c2s([chunk(4, 0, tlv(0x8006, struct.pack('!IB', 5, 1) + b'\x01'))])                # DTLS KM in HEARTBEAT
    c2s([chunk(1, 0, struct.pack('!IIHHI', 1, 2, 1, 1, 1) + tlv(0x8006, struct.pack('!IB', 5, 1)))])  # DTLS KM without ids
    # a parameter whose length field is shorter than the header
    c2s([chunk(4, 0, struct.pack('!HH', 1, 2) + b'\0\0')])
    # truncated captures: the checksum cannot be verified
    c2s([data(6, 0, 3, 0, b'T' * 60)], trunc=14 + 20 + 12 + 16 + 10)
    c2s([sack(6, 100, gaps=[(1, 2)])], trunc=14 + 20 + 12 + 14)
    c2s([init_like(1, 0x1234, 1, 1, 1, 1, [ipv4p(C), tlv(11, b'host.name\0')])], trunc=14 + 20 + 12 + 24 + 10)
    # a cause list cut inside a cause; a PKTDROP chunk with a bad inner packet
    c2s([abort([cause(1, b'\x00'), cause(2, b'\x00\x00\x00\x05')])])
    c2s([error([cause(6, chunk(0xfe, 0, b'', length=2))])])
    c2s([pktdrop(b'\x01\x02\x03\x04', 0)])
    # reassembly corner cases: zero length fragments, an end before the begin with a gap
    c2s([data(30, 5, 0, 0, b'', B=1, E=0)])
    c2s([data(31, 5, 0, 0, b'', B=0, E=1)])
    c2s([data(40, 6, 0, 0, b'BBBB', B=1, E=0)])
    c2s([data(45, 6, 0, 0, b'EEEE', B=0, E=1)])
    c2s([data(42, 6, 0, 0, b'MMMM', B=0, E=0)])
    # a message completed twice by the same TSNs after a restart of the stream
    c2s([data(40, 6, 0, 0, b'BBBB', B=1, E=0)])
    c2s([data(41, 6, 0, 0, b'MMMM', B=0, E=0)])
    c2s([data(42, 6, 0, 0, b'MMMM', B=0, E=0)])
    c2s([data(43, 6, 0, 0, b'MMMM', B=0, E=0)])
    c2s([data(44, 6, 0, 0, b'MMMM', B=0, E=0)])
    c2s([data(45, 6, 0, 0, b'EEEE', B=0, E=1)])
    # begin after end (TSN order inverted)
    c2s([data(90, 8, 0, 0, b'EEEE', B=0, E=1)])
    c2s([data(80, 8, 0, 0, b'BBBB', B=1, E=0)])
    # a payload dissector that raises an exception (short M3UA)
    c2s([data(101, 0, 1, 3, M3UA_BEAT[:5])])
    # IPv4 header only and bad association: a DATA with vtag 0
    c2s([data(100, 0, 0, 0, b'vtag zero')], vtag=0)
    # a packet shorter than the common header is not SCTP data: 12 bytes only, no chunk
    m.add(frame4(struct.pack('!HHII', CP, SP, Ts, 0), C, S))
    # an unreassemblable huge chunk count was covered by the main capture
    # 14 nested PKTDROP levels
    nested = sctp_packet(SP, CP, Tc, [data(5003, 0, 3, 0, b'nested')], 'zero')
    for _ in range(14):
        nested = sctp_packet(SP, CP, Tc, [pktdrop(nested, 0)], 'zero')
    c2s([pktdrop(nested, 0)])
    # chunks with the unrecognized-chunk cause nested into each other
    inner = chunk(0xfe, 0, b'\0\0\0\0')
    for _ in range(8):
        inner = chunk(9, 0, tlvs([cause(6, inner)]))
    c2s([inner])
    # parameters nested (add IP carrying add IP ...)
    nest = ipv4p('192.0.2.9')
    for i in range(10):
        nest = tlv(0xc001, struct.pack('!I', i) + nest)
    c2s([asconf(1, [ipv4p(C), nest])])

    # a truncated capture of a fragment: the message is not reassembled
    c2s([data(200, 0, 9, 0, b'F' * 60, B=1, E=0)], trunc=14 + 20 + 12 + 16 + 10)
    # a chunk with the length 0 (aborts "-z sctp,stat", see the README)
    c2s([chunk(0, 0, b'', length=0)], mark='zero_length_chunk')
    # an INIT with more than 2048 address parameters, then an IPv6 one
    c2s([init_like(1, 0x2222, 1, 1, 1, 1, [ipv4p('192.0.2.%d' % (i % 250)) for i in range(2050)] + [ipv6p('2001:db8::1')])],
        mark='init_2050_params')
    # one TSN retransmitted 105 times
    for i in range(105):
        m.add(frame4(sctp_packet(CP, SP, 0x5a5a5a5c, [data(7000, 0, 0, 0, b'again')], 'crc32c'), C, S), dt=10000)
    c2s([data(7001, 0, 1, 0, b'after the retransmissions')], vtag=0x5a5a5a5c)

    # write, with the truncated frames (4-tuples) supported
    marks = m.marks
    out_pcap = Pcapng()
    out_pcap.ts = m.p.ts
    blob = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in m.p.linktypes:
        blob += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    base = 1700000000 * 1000000
    for i, fr in enumerate(m.p.frames):
        if len(fr) == 4:
            iface, ts, d, orig = fr
        else:
            iface, ts, d = fr
            orig = len(d)
        blob += _blk(6, struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(d), orig) + d)
    with open(os.path.join(out, 'sctp-coverage-malformed.pcapng'), 'wb') as f:
        f.write(blob)
    with open(os.path.join(out, 'sctp-marks-malformed.txt'), 'w') as f:
        for k, v in sorted(marks.items(), key=lambda kv: kv[1]):
            f.write('%d %s\n' % (v, k))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main(out)
    build_malformed(out)
    with open(os.path.join(out, 'sctp-marks.txt'), 'w') as f:
        for k, v in sorted(m.marks.items(), key=lambda kv: kv[1]):
            f.write('%d %s\n' % (v, k))
    print('main frames:', m.n)


if __name__ == '__main__':
    main()

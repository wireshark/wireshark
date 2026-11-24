#!/usr/bin/env python3
# Generates test/captures/quic_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic QUIC coverage captures.

Usage: mkquic.py <outdir> [-v]

Writes quic-coverage.pcap (decodes without malformed frames or error
expert infos) and quic-coverage-malformed.pcap (truncated headers and
other input that raises exceptions or error expert infos).

Everything is the unprotected part of QUIC only: long and short headers,
Version Negotiation, Retry, coalescing, connection ID tracking and the
UDP heuristic. There is no packet protection code here and no ciphertext:
the payload of each protected packet is filler that cannot decrypt, so
the dissector reports decryption failures and the frames stay opaque.
"""
import struct
import sys

# ---------------------------------------------------------------- framing

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


CLI = bytes([10, 0, 0, 1])
SRV = bytes([10, 0, 1, 1])


def udp_frame(payload, to_server=True, i=0, cli=CLI, srv=SRV, sport=None, dport=4436):
    cport = 50000 + i if sport is None else sport
    if to_server:
        src, dst, sp, dp = cli, srv, cport, dport
        macs = bytes.fromhex('020000000002' '020000000001')
    else:
        src, dst, sp, dp = srv, cli, dport, cport
        macs = bytes.fromhex('020000000001' '020000000002')
    udp = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return macs + b'\x08\x00' + ip + udp


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for n, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + n, 0, len(fr), len(fr)))
            f.write(fr)


# ---------------------------------------------------------------- QUIC bits

V1 = 0x00000001
V2 = 0x6b3343cf


def varint(v, size=None):
    if size is None:
        size = 1 if v < 0x40 else 2 if v < 0x4000 else 4 if v < 0x40000000 else 8
    if size == 1:
        return struct.pack('!B', v)
    if size == 2:
        return struct.pack('!H', 0x4000 | v)
    if size == 4:
        return struct.pack('!I', 0x80000000 | v)
    return struct.pack('!Q', 0xc000000000000000 | v)


def filler(n, seed=1):
    """Bytes that are not ciphertext of anything: a counter pattern."""
    return bytes(((seed * 37 + k * 11 + (k >> 3)) & 0xff) for k in range(n))


def type_bits(version, kind):
    """Long header type bits (already shifted into the first byte)."""
    if version == V2:
        t = {'retry': 0, 'initial': 1, '0rtt': 2, 'handshake': 3}[kind]
    else:
        t = {'initial': 0, '0rtt': 1, 'handshake': 2, 'retry': 3}[kind]
    return t << 4


def cids(dcid, scid):
    return bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid


def initial(version, dcid, scid, token=b'', body=48, seed=1, tokenlen_size=None,
            length_size=None, first_low=0x03, fixed=True, length=None):
    first = 0x80 | (0x40 if fixed else 0) | type_bits(version, 'initial') | first_low
    payload = filler(4 + body, seed)       # packet number + payload
    ln = len(payload) if length is None else length
    return (bytes([first]) + struct.pack('!I', version) + cids(dcid, scid) +
            varint(len(token), tokenlen_size) + token +
            varint(ln, length_size) + payload)


def handshake(version, dcid, scid, body=48, seed=2, first_low=0x01):
    first = 0xc0 | type_bits(version, 'handshake') | first_low
    payload = filler(4 + body, seed)
    return (bytes([first]) + struct.pack('!I', version) + cids(dcid, scid) +
            varint(len(payload), 2 if len(payload) < 0x40 else None) + payload)


def zerortt(version, dcid, scid, body=48, seed=3):
    first = 0xc0 | type_bits(version, '0rtt') | 0x02
    payload = filler(4 + body, seed)
    return (bytes([first]) + struct.pack('!I', version) + cids(dcid, scid) +
            varint(len(payload)) + payload)


def short(dcid, body=40, seed=4, first=0x41):
    return bytes([first]) + dcid + filler(4 + body, seed)


def retry(version, dcid, scid, token, odcid=None, tag_seed=9):
    first = 0xc0 | type_bits(version, 'retry') | 0x0a
    out = bytes([first]) + struct.pack('!I', version) + cids(dcid, scid)
    if odcid is not None:           # draft 24 and older carry the ODCID
        out += bytes([len(odcid)]) + odcid
        return out + token
    return out + token + filler(16, tag_seed)   # random "tag": never verifies


def vneg(dcid, scid, versions, first=0x8b):
    return (bytes([first]) + struct.pack('!I', 0) + cids(dcid, scid) +
            b''.join(struct.pack('!I', v) for v in versions))


def cid(n, length=8):
    """A connection ID that is unique per n (two byte prefix)."""
    raw = struct.pack('!H', n) + bytes(((n * 16 + k * 3 + 1) & 0xff) for k in range(18))
    return raw[:length]


# ---------------------------------------------------------------- the capture

def main_frames(note):
    fr = []
    ranges = []

    def add(desc, payload, **kw):
        fr.append(udp_frame(payload, **kw))
        return len(fr)

    def group(name, start):
        ranges.append((name, start, len(fr)))

    D1, C1, S1 = cid(1), cid(2), cid(3)

    # ---- Group 1: a v1 connection on UDP 4436 (tuple 1)
    s = len(fr) + 1
    add('Client Initial', initial(V1, D1, C1, body=1100 - 60), i=1)
    # Server Initial coalesced with a Handshake
    add('Server Initial + Handshake',
        initial(V1, C1, S1, body=60, seed=5) + handshake(V1, C1, S1, body=70), i=1, to_server=False)
    add('Server Handshake', handshake(V1, C1, S1, body=90, seed=6), i=1, to_server=False)
    add('Client Handshake', handshake(V1, S1, C1, body=50, seed=7), i=1)
    # second Client Initial (large Client Hello) + 0-RTT: DCID is still D1
    add('Client Initial + 0-RTT', initial(V1, D1, C1, body=60, seed=8) + zerortt(V1, D1, C1), i=1)
    add('Client short', short(S1), i=1)
    add('Server short', short(C1, seed=5), i=1, to_server=False)
    # two short header packets in one datagram: the GSO heuristic splits at the DCID
    add('Client short x2 (GSO)', short(S1, body=30, seed=6) + short(S1, body=30, seed=7), i=1)
    # Initial + zero padding (not a packet): coalesced padding note
    add('Initial + padding', initial(V1, D1, C1, body=40, seed=9) + bytes(30), i=1)
    # Initial + packet with another DCID
    add('Initial + other DCID', initial(V1, D1, C1, body=40, seed=10) + handshake(V1, cid(9), C1), i=1)
    # Initial + long header with the fixed bit clear (greasing not negotiated)
    add('Initial + fixed bit 0',
        initial(V1, D1, C1, body=40, seed=11) + bytes([0xa1]) + struct.pack('!I', V1) + cids(D1, C1) +
        varint(30) + filler(30), i=1)
    # Server Initial with a token (protocol violation), 2-byte token length
    add('Server Initial with token', initial(V1, C1, S1, token=filler(20, 3), body=40, seed=12,
                                              tokenlen_size=2), i=1, to_server=False)
    # server 0-RTT (no 0-RTT keys in this direction)
    add('Server 0-RTT', zerortt(V1, C1, S1), i=1, to_server=False)
    # Initial with a 4 and an 8 byte Length field
    add('Client Initial, 4 byte Length', initial(V1, D1, C1, body=40, seed=13, length_size=4), i=1)
    add('Client Initial, 8 byte Length', initial(V1, D1, C1, body=40, seed=14, length_size=8), i=1)
    # a new connection on the same 5-tuple, then an old connection's short packet
    D1b, C1b, S1b = cid(11), cid(12), cid(13)
    add('Client Initial (2nd connection)', initial(V1, D1b, C1b, body=60, seed=15), i=1)
    add('Server short, old connection', short(C1, seed=16), i=1, to_server=False)
    add('Server Initial (2nd connection)', initial(V1, C1b, S1b, body=60, seed=17), i=1, to_server=False)
    add('Client short, old connection', short(S1, seed=18), i=1)
    # connection migration: the client moves to port 51000 (heuristic: short header)
    add('Client short, migrated', short(S1, seed=19), sport=51000)
    add('Server short to migrated', short(C1, seed=20), sport=51000, to_server=False)
    group('Connection 1 (v1), coalescing, GSO, migration', s)

    # ---- Group 2: Retry (v1), tuple 2
    s = len(fr) + 1
    D2, C2, R2, S2 = cid(21), cid(22), cid(23), cid(24)
    add('Client Initial', initial(V1, D2, C2, body=60, seed=21), i=2)
    add('Server Retry', retry(V1, C2, R2, filler(24, 2)), i=2, to_server=False)
    add('Client Initial with token (new DCID)', initial(V1, R2, C2, token=filler(24, 2), body=60, seed=22), i=2)
    add('Second Retry (ignored)', retry(V1, C2, cid(25), filler(24, 2), tag_seed=11), i=2, to_server=False)
    add('Server Initial', initial(V1, C2, S2, body=60, seed=23), i=2, to_server=False)
    # Retry with an unknown connection, with an empty token
    add('Retry, unknown connection', retry(V1, C2, R2, b''), i=3, to_server=False)
    add('Retry, unknown connection 2', retry(V1, cid(26), cid(27), filler(10, 4)), i=4, to_server=False)
    group('Retry (v1)', s)

    # ---- Group 3: Retry in draft 29, 25, 24 and version 2
    s = len(fr) + 1
    for i, (ver, odcid) in enumerate(((0xff00001d, False), (0xff000019, False), (0xff000018, True)), start=5):
        d, c, r = cid(30 + i), cid(40 + i), cid(50 + i)
        add('Client Initial', initial(ver, d, c, body=60, seed=i), i=i)
        add('Server Retry', retry(ver, c, r, filler(16, i), odcid=d if odcid else None), i=i, to_server=False)
        add('Client Initial', initial(ver, r, c, token=filler(16, i), body=60, seed=i + 20), i=i)
    # version 2: all packet types
    i = 8
    d, c, r, sv = cid(61), cid(62), cid(63), cid(64)
    add('v2 Client Initial', initial(V2, d, c, body=60, seed=31), i=i)
    add('v2 Retry', retry(V2, c, r, filler(16, 7)), i=i, to_server=False)
    add('v2 Client Initial with token', initial(V2, r, c, token=filler(16, 7), body=60, seed=32), i=i)
    add('v2 Server Initial + Handshake',
        initial(V2, c, sv, body=60, seed=33) + handshake(V2, c, sv, body=60), i=i, to_server=False)
    add('v2 Client Initial + 0-RTT', initial(V2, r, c, token=filler(16, 7), body=60, seed=34) +
        zerortt(V2, r, c), i=i)
    add('v2 Client Handshake', handshake(V2, sv, c), i=i)
    add('v2 Client short', short(sv, seed=35), i=i)
    group('Retry in drafts 29, 25, 24 and version 2, v2 packet types', s)

    # ---- Group 4: compatible version negotiation: Initial v1, server answers v2
    s = len(fr) + 1
    d, c, sv = cid(71), cid(72), cid(73)
    add('v1 Client Initial', initial(V1, d, c, body=60, seed=41), i=9)
    add('v2 Server Initial', initial(V2, c, sv, body=60, seed=42), i=9, to_server=False)
    add('v2 Client Handshake', handshake(V2, sv, c), i=9)
    group('Compatible version negotiation (v1 -> v2)', s)

    # ---- Group 5: other versions (header protection and salts differ)
    s = len(fr) + 1
    versions = [0xff00000b, 0xff000011, 0xff000016, 0xff00001b, 0xff00001d, 0xff000020,
                0xff000022, 0xfaceb001, 0xfaceb002, 0xfaceb003, 0xfaceb014, 0xfaceb015,
                0x51303530, 0x54303530, 0x54303531]
    for k, ver in enumerate(versions):
        i = 10 + k
        d, c, sv = cid(80 + k), cid(100 + k), cid(120 + k)
        add('Client Initial', initial(ver, d, c, body=60, seed=50 + k), i=i)
        add('Server Initial', initial(ver, c, sv, body=60, seed=70 + k), i=i, to_server=False)
    group('Initial packets of drafts 11-34, mvfst and Google versions', s)

    # ---- Group 6: Version Negotiation and forcing version negotiation (tuple 30..)
    s = len(fr) + 1
    d, c = cid(140), cid(141)
    add('Client Initial', initial(V1, d, c, body=60, seed=90), i=30)
    add('Version Negotiation', vneg(c, d, [V1, V2, 0xff00001d, 0x1a2a3a4a]), i=30, to_server=False)
    add('Client Initial after VN (fresh connection)', initial(V1, cid(142), c, body=60, seed=91), i=30)
    add('Version Negotiation without versions', vneg(c, cid(142), []), i=30, to_server=False)
    add('Version Negotiation, empty CIDs', vneg(b'', b'', [V1]), i=30, to_server=False)
    add('Client Initial, forcing VN',
        bytes([0xf0]) + struct.pack('!I', 0x1a2a3a4a) + cids(cid(143), cid(144)), i=31)
    add('Client Initial, forcing VN, extra data',
        initial(0xfafafafa, cid(145), cid(146), body=60, seed=93, length=60) + filler(20, 9), i=32)
    group('Version Negotiation and forcing version negotiation', s)

    # ---- Group 7: zero length connection IDs (tuple 33)
    s = len(fr) + 1
    d = cid(150)
    add('Client Initial, empty SCID', initial(V1, d, b'', body=60, seed=100), i=33)
    add('Server Initial, empty SCID', initial(V1, b'', b'', body=60, seed=101), i=33, to_server=False)
    add('Client Handshake, empty CIDs', handshake(V1, b'', b''), i=33)
    add('Client short, empty DCID', bytes([0x41]) + filler(60, 102), i=33)
    add('Server short, empty DCID', bytes([0x41]) + filler(60, 103), i=33, to_server=False)
    # maximum length (20) and single byte CIDs
    add('Client Initial, 20 byte CIDs', initial(V1, cid(151, 20), cid(152, 20), body=60, seed=104), i=34)
    add('Server Initial, 1 byte CIDs', initial(V1, cid(152, 20)[:1], cid(153, 1), body=60, seed=105),
        i=34, to_server=False)
    group('Zero, one and twenty byte connection IDs', s)

    # ---- Group 8: packets with no connection
    s = len(fr) + 1
    add('Lone Handshake', handshake(V1, cid(160), cid(161)), i=35)
    add('Lone 0-RTT', zerortt(V1, cid(162), cid(163)), i=36)
    add('Lone Handshake, no SCID', handshake(V1, cid(164), b''), i=37)
    group('Long header packets of unknown connections', s)

    # ---- Group 9: datagrams the heuristic rejects (plain UDP)
    s = len(fr) + 1
    add('too short', bytes([0xc0]) + struct.pack('!I', V1) + b'\x04abc', i=40)
    add('unknown version', bytes([0xc0]) + struct.pack('!I', 0x12345678) + cids(cid(1), cid(2)) + filler(40), i=41)
    add('DCID length 21', bytes([0xc0]) + struct.pack('!I', V1) + bytes([21]) + cid(1, 21) + b'\x00' + filler(40), i=42)
    add('SCID length 21', bytes([0xc0]) + struct.pack('!I', V1) + bytes([4]) + cid(1, 4) + bytes([21]) + filler(40), i=43)
    add('DCID runs past the end', bytes([0xc0]) + struct.pack('!I', V1) + bytes([20]) + cid(1, 8), i=44)
    add('short header, unknown DCID', short(bytes([0xee]) + cid(170, 7), body=40), i=45)
    add('short header, too small', bytes([0x41]) + filler(15), i=46)
    add('too small for QUIC', bytes([0xc0]) + filler(8), i=47)
    group('Datagrams the heuristic does not accept', s)

    # ---- Group 9b: several Retry packets before the client answers (CID list),
    # Client Initial whose DCID is a CID of another connection (fresh connection),
    # three coalesced packets and padding that looks like a fixed-bit short header
    s = len(fr) + 1
    dR, cR, R1, R2b = cid(180), cid(181), cid(182), cid(183)
    add('Client Initial', initial(V1, dR, cR, body=60, seed=110), i=60)
    add('Retry 1', retry(V1, cR, R1, filler(16, 5), tag_seed=1), i=60, to_server=False)
    add('Retry 2 (other SCID)', retry(V1, cR, R2b, filler(16, 5), tag_seed=2), i=60, to_server=False)
    add('Retry 3 (SCID of Retry 1)', retry(V1, cR, R1, filler(16, 5), tag_seed=3), i=60, to_server=False)
    add('Client Initial answers Retry', initial(V1, R1, cR, token=filler(16, 5), body=60, seed=111), i=60)
    dA, X, W = cid(190), cid(191), cid(192)
    dB, Y = cid(193), cid(194)
    add('A: Client Initial (SCID X)', initial(V1, dA, X, body=60, seed=112), i=61)
    add('A: Server Initial (SCID W)', initial(V1, X, W, body=60, seed=113), i=61, to_server=False)
    add('B: Client Initial', initial(V1, dB, Y, body=60, seed=114), i=62)
    add('B: Server Initial (SCID X)', initial(V1, Y, X, body=60, seed=115), i=62, to_server=False)
    add('A: Client Initial with DCID X (a CID of B)', initial(V1, X, cid(195), body=60, seed=116), i=61)
    d3, c3 = cid(196), cid(197)
    add('Initial + Handshake + Handshake',
        initial(V1, d3, c3, body=40, seed=117) + handshake(V1, d3, c3, body=40) +
        handshake(V1, d3, c3, body=40, seed=118), i=63)
    add('Initial + fixed-bit padding', initial(V1, d3, c3, body=40, seed=119) + bytes([0x41] * 24), i=63)
    group('Several Retry packets, CID of another connection, three coalesced packets', s)

    # ---- Group 10: the fixed coalesced packet assertion
    s = len(fr) + 1
    dcid = bytes(range(0x11, 0x19))

    def repro_initial(length, body):
        return (b'\xc0' + struct.pack('!I', 1) + bytes([len(dcid)]) + dcid + b'\x00' + b'\x00' +
                bytes([length]) + body)
    p1 = repro_initial(1, b'\x00')
    p2 = repro_initial(0x30, b'\x00' * 0x30)
    fr.append(udp_frame(p1 + p2, to_server=True, cli=bytes([192, 0, 2, 1]),
                        srv=bytes([198, 51, 100, 1]), sport=50000))
    # the same with the first packet alone, and with the Length field one short of the sample
    fr.append(udp_frame(p1, to_server=True, cli=bytes([192, 0, 2, 1]), srv=bytes([198, 51, 100, 1]), sport=50001))
    p3 = repro_initial(0x13, b'\x00' * 0x13)
    fr.append(udp_frame(p3 + p2, to_server=True, cli=bytes([192, 0, 2, 1]),
                        srv=bytes([198, 51, 100, 1]), sport=50002))
    group('Initial whose Length is too short for the header protection sample, coalesced', s)
    return fr, ranges


def malformed_frames():
    fr = []
    # truncated long header: the DCID length byte is the last byte
    # (heuristic needs 13 bytes)
    fr.append(udp_frame(bytes([0xc0]) + struct.pack('!I', V1) + bytes([4]) + cid(1, 4) + bytes([4]) + cid(2, 4), i=1))
    # Initial whose token length runs past the end
    fr.append(udp_frame(bytes([0xc0]) + struct.pack('!I', V1) + cids(cid(3), cid(4)) + varint(60) + b'xy', i=2))
    # Initial whose Length is longer than the datagram
    fr.append(udp_frame(initial(V1, cid(5), cid(6), body=20, length=900), i=3))
    # Initial whose Length is shorter than the data (garbage follows)
    fr.append(udp_frame(initial(V1, cid(7), cid(8), body=20, length=8) + filler(40, 1), i=4))
    # Version Negotiation with a version list that is not a multiple of 4
    fr.append(udp_frame(initial(V1, cid(9), cid(10)), i=5))
    fr.append(udp_frame(vneg(cid(10), cid(9), [V1, V2]) + b'\x01\x02', i=5, to_server=False))
    # Version Negotiation without any versions and cut inside the SCID
    fr.append(udp_frame(initial(V1, cid(11), cid(12)), i=6))
    fr.append(udp_frame(bytes([0x8b]) + struct.pack('!I', 0) + bytes([8]) + cid(12) + bytes([8]) + cid(11)[:3], i=6, to_server=False))
    # Retry without room for the integrity tag
    fr.append(udp_frame(initial(V1, cid(13), cid(14)), i=7))
    fr.append(udp_frame(bytes([0xf0]) + struct.pack('!I', V1) + cids(cid(14), cid(15)) + b'TOKEN', i=7, to_server=False))
    # Retry of draft 24 with the ODCID cut short
    fr.append(udp_frame(initial(0xff000018, cid(16), cid(17)), i=8))
    fr.append(udp_frame(bytes([0xf0]) + struct.pack('!I', 0xff000018) + cids(cid(17), cid(18)) + bytes([8]) + cid(16)[:3], i=8, to_server=False))
    # Retry that is exactly 16 bytes after the CIDs (empty token)
    fr.append(udp_frame(initial(V1, cid(19), cid(20)), i=9))
    fr.append(udp_frame(retry(V1, cid(20), cid(21), b''), i=9, to_server=False))
    # Handshake cut inside the Length
    fr.append(udp_frame(bytes([0xe0]) + struct.pack('!I', V1) + cids(cid(22), cid(23)), i=10))
    # short header with a known DCID but too short for the 4 byte PN sample
    d, c, sv = cid(24), cid(25), cid(26)
    fr.append(udp_frame(initial(V1, d, c, body=40), i=11))
    fr.append(udp_frame(initial(V1, c, sv, body=40), i=11, to_server=False))
    fr.append(udp_frame(bytes([0x41]) + sv + b'\x01\x02\x03', i=11))
    fr.append(udp_frame(bytes([0x41]) + sv + filler(10), i=11))
    # long DCID (21 bytes): decoded when the port is forced to QUIC (runcov.sh Decode As)
    fr.append(udp_frame(bytes([0xc0]) + struct.pack('!I', V1) + bytes([21]) + cid(27, 21) + bytes([22]) + cid(28, 22) +
                        b'\x00' + varint(40) + filler(40), i=12, dport=4446))
    # Client Initial with an Initial header ending in the middle of a sample (Length too small)
    fr.append(udp_frame(initial(V1, cid(29), cid(30), body=10, length=14), i=13))
    # Initial + Initial with an unparsable second header
    fr.append(udp_frame(initial(V1, cid(31), cid(32), body=40) + bytes([0xc0, 0, 0]), i=14))
    # forcing version negotiation, Initial type bits, nothing after the CIDs: the
    # packet length cannot be determined
    fr.append(udp_frame(bytes([0xc0]) + struct.pack('!I', 0x1a2a3a4a) + cids(cid(33), cid(34)), i=16))
    # The retry / short header pass dependency (see README, observations)
    A, C, S = bytes([0xa0] * 8), bytes([0xc0] * 8), bytes([0x50] * 8)
    fr.append(udp_frame(initial(V1, A, C, body=40), i=15))
    fr.append(udp_frame(bytes([0xf0]) + struct.pack('!I', 1) + bytes([8]) + C + bytes([8]) + S +
                        b'TOKEN-TOKEN' + bytes([0xee] * 16), i=15, to_server=False))
    fr.append(udp_frame(bytes([0x40]) + S + bytes([0x33] * 30), i=15))
    fr.append(udp_frame(initial(V1, S, C, body=40), i=15))
    return fr


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main, ranges = main_frames(None)
    write_pcap(out + '/quic-coverage.pcap', main)
    write_pcap(out + '/quic-coverage-malformed.pcap', malformed_frames())
    if '-v' in sys.argv:
        for name, a, b in ranges:
            print('%d-%d  %s' % (a, b, name))
        print('total', len(main))

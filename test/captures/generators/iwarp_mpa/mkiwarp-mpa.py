#!/usr/bin/env python3
# Generates test/captures/iwarp_mpa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the iWARP MPA dissector
(packet-iwarp-mpa.c, Marker PDU Aligned framing, RFC 5044) and, through
it, the DDP/RDMAP dissector.

MPA runs over TCP on no particular port; its heuristic dissector
("iwarp_mpa_tcp", enabled by default) recognises the MPA Request/Reply
frames ("MPA ID Req Frame" / "MPA ID Rep Frame") and then every segment of
the connection as an FPDU.  The dissector assumes one FPDU per TCP segment
when it computes the markers.  Every packet is built with struct; no
captured traffic is used.

Usage: mkiwarp-mpa.py <output directory>

Writes:
  iwarp-mpa-coverage.pcap            connections with and without markers
                                     and CRC, enhanced and legacy IRD/ORD
                                     negotiation, a rejected connection
  iwarp-mpa-coverage-malformed.pcap  bad private data length, the marker
                                     reproducer, wrong lengths
  iwarp-mpa-coverage-decodeas.pcap   a connection whose handshake is not in
                                     the capture (needs -d tcp.port==47100,iwarp_mpa)
"""
import os
import struct
import sys


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


MAC_I = bytes.fromhex('020000000001')
MAC_R = bytes.fromhex('020000000002')


def tcp_frame(from_init, sport, dport, seq, ack, payload, flags=0x18):
    src, dst = ((10, 0, 0, 1), (10, 0, 0, 2)) if from_init else ((10, 0, 0, 2), (10, 0, 0, 1))
    ps, pd = (sport, dport) if from_init else (dport, sport)
    tcp = struct.pack('!HHIIBBHHH', ps, pd, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    mac_dst, mac_src = (MAC_R, MAC_I) if from_init else (MAC_I, MAC_R)
    return mac_dst + mac_src + b'\x08\x00' + ip + tcp + payload


# ----------------------------------------------------------------- DDP / RDMAP

def ddp_send(msn, mo, data, last=True, opcode=3, qn=0, inval_stag=0):
    """Untagged DDP segment: control, RDMAP control (version 1 + opcode), 4
    octets (the invalidate STag for the invalidating Sends), QN, MSN, MO."""
    ctl = (0x40 if last else 0) | 0x01
    return (bytes([ctl, 0x40 | opcode]) + struct.pack('>I', inval_stag)
            + struct.pack('>III', qn, msn, mo) + data)


def ddp_write(stag, to, data, last=True):
    """Tagged DDP segment (RDMA Write)."""
    ctl = 0x80 | (0x40 if last else 0) | 0x01
    return bytes([ctl, 0x40]) + struct.pack('>IQ', stag, to) + data


def rdma_read_request(sink_stag, sink_to, size, src_stag, src_to):
    return (bytes([0x41, 0x41]) + struct.pack('>I', 0) + struct.pack('>III', 1, 0, 0)
            + struct.pack('>IQIIQ', sink_stag, sink_to, size, src_stag, src_to))


# ----------------------------------------------------------------------- MPA

REQ_KEY = b'MPA ID Req Frame'
REP_KEY = b'MPA ID Rep Frame'
PD = b'p' * 492      # private data that puts the first FPDU at relative sequence number 512


def mpa_req_rep(key, flags, rev, private=b'', pd_len=None):
    return key + bytes([flags, rev]) + struct.pack('>H', len(private) if pd_len is None else pd_len) + private


def fpdu(ulpdu, p0=0, markers=False, crc=False, bad_crc=False, trailing=b'', ulpdu_len=None):
    """One FPDU placed at stream offset p0 (relative to the first FPDU of
    the sender, which sits on a multiple of 512).  With markers, a 4 octet
    marker is inserted whenever the stream offset is a multiple of 512.
    Returns the segment payload and the number of octets."""
    base = struct.pack('>H', len(ulpdu) if ulpdu_len is None else ulpdu_len) + ulpdu
    base += b'\0' * ((-len(base)) % 4)
    out = bytearray()
    pos = p0
    start = p0
    def marker():
        return struct.pack('>HH', 0, (pos - start) & 0xffff)
    for b in base:
        if markers and pos % 512 == 0:
            out += marker()
            pos += 4
        out.append(b)
        pos += 1
    if markers and pos % 512 == 0:
        out += marker()
        pos += 4
    if crc:
        c = crc32c(bytes(out))
        if bad_crc:
            c ^= 0x1
        out += struct.pack('<I', c)
    else:
        out += b'\0\0\0\0'
    return bytes(out) + trailing


def marker_before_crc(markers_start_ok=True):
    """The ULPDU length for which the marker lands right before the CRC when
    the FPDU starts on a multiple of 512 (the case where pad_offset() is
    shifted by a marker)."""
    for n in range(1, 700):
        base = 2 + n
        base += (-base) % 4
        # markers at stream offsets 0, 512, ...: before the CRC when
        # (start + len(marked body without crc)) % 512 == 0
        pos = 0
        for i in range(base):
            if pos % 512 == 0:
                pos += 4
            pos += 1
        if pos % 512 == 0 and pos >= 512:
            return n
    return None


class Conn:
    """A TCP connection of an MPA initiator and responder."""
    def __init__(self, frames, sport, dport, iseq, rseq):
        self.f = frames
        self.sport, self.dport = sport, dport
        self.seq = {True: iseq, False: rseq}
        self.start = {True: None, False: None}

    def send(self, from_init, payload, flags=0x18):
        peer = not from_init
        self.f.append(tcp_frame(from_init, self.sport, self.dport, self.seq[from_init],
                                self.seq[peer], payload, flags))
        self.seq[from_init] += len(payload)

    def p0(self, from_init):
        """Stream offset of the next FPDU of this sender."""
        if self.start[from_init] is None:
            self.start[from_init] = self.seq[from_init]
        return self.seq[from_init] - self.start[from_init]


def aligned_conn(frames, sport, dport, req, rep):
    """Connection whose first FPDUs start on a multiple of 512: the ISNs are
    chosen so that seq + length of the Request/Reply is such a multiple."""
    iseq = (4096 * 4) - len(req)
    rseq = (4096 * 8) - len(rep)
    c = Conn(frames, sport, dport, iseq, rseq)
    return c


def handshake(c, req, rep):
    c.send(True, req)
    c.send(False, rep)


def main_frames():
    fr = []

    # ---- connection 1: no markers, no CRC
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x00, 1)
    c = aligned_conn(fr, 47001, 47002, req, rep)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'hello world 1')))
    c.send(False, fpdu(ddp_send(0, 0, b'hello back!!')))
    # padding of every length, small and larger segments
    for n in range(1, 9):
        c.send(True, fpdu(ddp_send(n, 0, bytes(range(n)))))
    # two FPDUs in one segment
    c.send(True, fpdu(ddp_send(9, 0, b'first')) + fpdu(ddp_send(10, 0, b'second one')))
    # an FPDU split over two segments
    big = fpdu(ddp_send(11, 0, bytes(range(200))))
    c.send(True, big[:100])
    c.send(True, big[100:])
    # one FPDU and the start of the next in one segment, the rest in the next
    n1 = fpdu(ddp_send(12, 0, b'A' * 30))
    n2 = fpdu(ddp_send(13, 0, b'B' * 30))
    c.send(True, n1 + n2[:20])
    c.send(True, n2[20:])
    c.send(False, fpdu(ddp_write(0x1000, 0x2000, b'write data')))
    c.send(False, fpdu(rdma_read_request(0x10, 0x20, 4096, 0x30, 0x40)))

    # ---- connection 2: CRC, good and bad
    req = mpa_req_rep(REQ_KEY, 0x40, 1)
    rep = mpa_req_rep(REP_KEY, 0x40, 1)
    c = aligned_conn(fr, 47003, 47004, req, rep)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'with crc'), crc=True))
    c.send(False, fpdu(ddp_send(0, 0, b'with crc'), crc=True))
    c.send(True, fpdu(ddp_send(1, 0, b'bad crc!'), crc=True, bad_crc=True))
    # CRC only requested by the responder
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x40, 1)
    c = aligned_conn(fr, 47005, 47006, req, rep)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'crc by responder'), crc=True))

    # ---- connection 3: markers and CRC; one FPDU per segment, sizes crossing 512
    req = mpa_req_rep(REQ_KEY, 0xc0, 1, PD)
    rep = mpa_req_rep(REP_KEY, 0xc0, 1, PD)
    c = aligned_conn(fr, 47007, 47008, req, rep)
    handshake(c, req, rep)
    n_mbc = marker_before_crc()
    for who, size in ((True, n_mbc - 18), (False, n_mbc - 18), (True, 10), (False, 20), (True, 300), (True, 480), (False, 700), (True, 1100),
                      (True, 2000), (False, 33), (True, 7), (True, 1), (False, 2), (False, 3),
                      (False, 4), (True, 600)):
        p0 = c.p0(who)
        c.send(who, fpdu(ddp_send(1, 0, bytes((i * 7) & 0xff for i in range(size))), p0=p0, markers=True, crc=True))

    # ---- connection 4: markers, no CRC, only the responder asks for them
    req = mpa_req_rep(REQ_KEY, 0x00, 1, PD)
    rep = mpa_req_rep(REP_KEY, 0x80, 1, PD)
    c = aligned_conn(fr, 47009, 47010, req, rep)
    handshake(c, req, rep)
    for who, size in ((True, 5), (False, 5), (True, 520), (False, 515), (True, 1000), (True, 100), (False, 9)):
        p0 = c.p0(who)
        c.send(who, fpdu(ddp_send(2, 0, bytes(size)), p0=p0, markers=True, crc=False))

    # ---- connection 5: markers, the requester asks for them
    req = mpa_req_rep(REQ_KEY, 0x80, 1, PD)
    rep = mpa_req_rep(REP_KEY, 0x00, 1, PD)
    c = aligned_conn(fr, 47011, 47012, req, rep)
    handshake(c, req, rep)
    for who, size in ((True, 400), (False, 400), (True, 600)):
        p0 = c.p0(who)
        c.send(who, fpdu(ddp_send(3, 0, bytes(size)), p0=p0, markers=True))

    # ---- connection whose sequence numbers wrap (matters with tcp.relative_sequence_numbers off)
    req = mpa_req_rep(REQ_KEY, 0xc0, 1, PD)
    rep = mpa_req_rep(REP_KEY, 0xc0, 1, PD)
    c = Conn(fr, 47033, 47034, 0xffffffff - 1500, 0xffffffff - 1200)
    handshake(c, req, rep)
    for who, size in ((True, 100), (False, 200), (True, 500), (True, 700), (False, 800), (True, 30), (False, 30), (True, 30)):
        c.send(who, fpdu(ddp_send(4, 0, bytes(size)), p0=c.p0(who), markers=True, crc=True))

    # ---- TCP segments that are not MPA
    c = Conn(fr, 49001, 49002, 1000, 2000)
    c.send(True, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    c.send(False, b'MPA ID Rxx FrameMPA ID Rxx Frame')
    c.send(True, b'short')
    c.send(False, b'MPA ID Req Frame' + b'MPA ID Req Fram')       # 31 octets, the Request key is cut

    # ---- enhanced RDMA negotiation, legacy IRD/ORD and other private data
    def enhanced(a, b, ird, c_, d, ord_):
        return struct.pack('>HH', (a << 15) | (b << 14) | ird, (c_ << 15) | (d << 14) | ord_)
    req = mpa_req_rep(REQ_KEY, 0x10, 1, enhanced(1, 0, 16, 0, 1, 32))
    rep = mpa_req_rep(REP_KEY, 0x10, 1, enhanced(0, 1, 8, 1, 0, 4) + b'extra private')
    c = Conn(fr, 47013, 47014, 100000, 200000)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'enhanced')))
    # the S bit without room for the 4 octets
    req = mpa_req_rep(REQ_KEY, 0x10, 1, b'\x01\x02')
    rep = mpa_req_rep(REP_KEY, 0x10, 1, b'')
    c = Conn(fr, 47015, 47016, 100000, 200000)
    handshake(c, req, rep)
    # legacy IRD/ORD (big endian), the broken little endian one, and both
    for sp, priv in ((47017, struct.pack('>II', 4, 8)), (47019, struct.pack('<II', 4, 8)), (47021, bytes(8)),
                     (47023, struct.pack('>II', 0x4000, 8)), (47025, b'private data 1234')):
        req = mpa_req_rep(REQ_KEY, 0x00, 1, priv)
        rep = mpa_req_rep(REP_KEY, 0x00, 1, priv)
        c = Conn(fr, sp, sp + 1, 100000, 200000)
        handshake(c, req, rep)
    # reserved flag bits and a revision other than 1 (warnings), a reject by the responder (note)
    req = mpa_req_rep(REQ_KEY, 0x05, 2)
    rep = mpa_req_rep(REP_KEY, 0x0a, 1)
    c = Conn(fr, 47027, 47028, 100000, 200000)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'after the reply')))
    req = mpa_req_rep(REQ_KEY, 0x00, 1, b'rejected')
    rep = mpa_req_rep(REP_KEY, 0x20, 1, b'go away')
    c = Conn(fr, 47029, 47030, 100000, 200000)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'not decoded as MPA')))
    return fr


def malformed_frames():
    fr = []
    # a second Request and Reply on a connection that is in full operation
    c = Conn(fr, 47031, 47032, 100000, 200000)
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x00, 1)
    handshake(c, req, rep)
    c.send(True, req)
    c.send(False, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'still fine')))
    # private data length of more than 512
    c = Conn(fr, 48001, 48002, 100000, 200000)
    c.send(True, mpa_req_rep(REQ_KEY, 0x00, 1, b'x' * 20, pd_len=600))
    # a Reply without a Request on its connection
    c = Conn(fr, 48003, 48004, 100000, 200000)
    c.send(False, mpa_req_rep(REP_KEY, 0x00, 1))
    c.send(True, fpdu(ddp_send(0, 0, b'no state')))
    # Request/Reply cut short
    c = Conn(fr, 48005, 48006, 100000, 200000)
    c.send(True, REQ_KEY[:12])
    # the marker reproducer: markers negotiated, one FPDU plus 2 trailing octets in a segment
    req = mpa_req_rep(REQ_KEY, 0x80, 1)
    rep = mpa_req_rep(REP_KEY, 0x80, 1)
    c = aligned_conn(fr, 48007, 48008, req, rep)
    handshake(c, req, rep)
    c.send(True, fpdu(ddp_send(0, 0, b'ok'), p0=c.p0(True), markers=True))
    f = fpdu(b'\x41' * 10, p0=c.p0(True), markers=True, trailing=b'\x42\x42')
    c.send(True, f)
    # an FPDU with markers split in two segments: the dissector assumes one FPDU
    # per segment, so the second part (marker and CRC only) is too short for it
    req = mpa_req_rep(REQ_KEY, 0x80, 1, PD)
    rep = mpa_req_rep(REP_KEY, 0x80, 1, PD)
    c = aligned_conn(fr, 48011, 48012, req, rep)
    handshake(c, req, rep)
    for tail in (8, 9, 10, 12, 16):
        n = marker_before_crc() - 18
        f = fpdu(ddp_send(0, 0, bytes(n)), p0=c.p0(True), markers=True)
        c.send(True, f[:-tail])
        c.send(True, f[-tail:])
    # ULPDU length that does not fit the segment (with and without markers)
    c.send(True, fpdu(ddp_send(0, 0, b'ok'), p0=c.p0(True), markers=True, ulpdu_len=3))
    c.send(True, fpdu(ddp_send(0, 0, b'ok'), p0=c.p0(True), markers=True, ulpdu_len=0))
    c.send(True, fpdu(ddp_send(0, 0, b'ok'), p0=c.p0(True), markers=True, ulpdu_len=60000))
    # FPDU shorter than the DDP header, no markers
    req = mpa_req_rep(REQ_KEY, 0x00, 1)
    rep = mpa_req_rep(REP_KEY, 0x00, 1)
    c = aligned_conn(fr, 48009, 48010, req, rep)
    handshake(c, req, rep)
    c.send(True, fpdu(b'\x41\x43'))
    c.send(True, fpdu(b'\x41\x43\x00\x00\x00\x00'))
    c.send(True, fpdu(b''))
    c.send(True, b'\x00\x01\x02')                    # shorter than the smallest FPDU
    c.send(True, struct.pack('>H', 60000) + b'\0' * 10)   # length of a very long PDU
    c.send(True, b'\xff' * 40)
    return fr


def decodeas_frames():
    """Connection on port 47100 whose MPA handshake is not in the capture
    (the dissector fakes the state: no markers, no CRC), then one with the
    handshake."""
    fr = []
    c = Conn(fr, 47100, 47101, 100000, 200000)
    c.send(True, fpdu(ddp_send(0, 0, b'in the middle')))
    c.send(False, fpdu(ddp_send(0, 0, b'in the middle too')))
    big = fpdu(ddp_send(1, 0, bytes(range(150))))
    c.send(True, big[:50])
    c.send(True, big[50:])
    c.send(True, b'\x00\x01\x02')
    # with the handshake, through Decode As
    req = mpa_req_rep(REQ_KEY, 0xc0, 1)
    rep = mpa_req_rep(REP_KEY, 0xc0, 1)
    c = aligned_conn(fr, 47102, 47100, req, rep)
    handshake(c, req, rep)
    for who, size in ((True, 10), (False, 600), (True, 520)):
        c.send(who, fpdu(ddp_send(0, 0, bytes(size)), p0=c.p0(who), markers=True, crc=True))
    # a Request split over two segments (only Decode As gets the first part)
    c = Conn(fr, 47105, 47100, 100000, 200000)
    rq = mpa_req_rep(REQ_KEY, 0x00, 1)
    c.send(True, rq[:12])
    c.send(True, rq[12:])
    c.send(False, mpa_req_rep(REP_KEY, 0x00, 1))
    c.send(True, fpdu(ddp_send(0, 0, b'after the split request')))
    # a Request that is not the first frame of its connection
    c = Conn(fr, 47103, 47100, 100000, 200000)
    c.send(True, fpdu(ddp_send(0, 0, b'first')))
    c.send(True, mpa_req_rep(REQ_KEY, 0x00, 1))
    c.send(False, mpa_req_rep(REP_KEY, 0x00, 1))
    c.send(True, fpdu(ddp_send(1, 0, b'second')))
    # a Reply with the reject bit
    c = Conn(fr, 47104, 47100, 100000, 200000)
    c.send(True, mpa_req_rep(REQ_KEY, 0x00, 1))
    c.send(False, mpa_req_rep(REP_KEY, 0x20, 1))
    c.send(True, fpdu(ddp_send(0, 0, b'after reject')))
    return fr


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'iwarp-mpa-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'iwarp-mpa-coverage-malformed.pcap'), malformed_frames())
    write_pcap(os.path.join(out, 'iwarp-mpa-coverage-decodeas.pcap'), decodeas_frames())


if __name__ == '__main__':
    main()

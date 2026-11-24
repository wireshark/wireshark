#!/usr/bin/env python3
# Generates test/captures/dvb_s2_bb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB-S2 coverage captures for packet-dvb-s2-bb.c (mode
adaptation header, Base Band Frame, GSE).

DVB-S2 Base Band Frames are carried in RTP, as a DVB-S2 gateway or
demodulator streams them: a SIP INVITE (UDP 5060) with an SDP offer
announces "a=rtpmap:96 DVB-S2/90000" on UDP port 30000, so the RTP
packets that follow are decoded as DVB-S2 without Decode As. Each RTP
payload is one BBFrame with an L.1, L.2, L.3 or L.4 mode adaptation
header. Every packet is built with struct; nothing comes from a real
network.

Usage: mkdvb_s2_bb.py <outdir>

Writes:
  dvb-s2-bb-coverage.pcap            GSE (complete PDUs, every label
                                     type, IPv4, IPv6, VLAN, NCR,
                                     signalling table, extension header,
                                     padding, EIP CRC32, fragmentation
                                     and reassembly over several BBFrames
                                     and input streams), generic
                                     packetized frames and Transport
                                     Streams with every UPL/ISSY/NPD
                                     combination, sliced over BBFrames
  dvb-s2-bb-coverage-malformed.pcap  header checks that give expert
                                     infos, bad CRCs, lengths beyond the
                                     frame, TS slicing with a lost frame,
                                     and the GSE Frag ID reuse case
"""
import os
import struct
import sys

# --- checksums -----------------------------------------------------------

CRC8_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0xD5) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    CRC8_TABLE.append(_c)


def crc8(data):
    crc = 0
    for b in data:
        crc = CRC8_TABLE[crc ^ b]
    return crc


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def ip_csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# --- link layer, IP, UDP, SIP, RTP ---------------------------------------

MAC_GW = bytes.fromhex("020000000002")
MAC_TERM = bytes.fromhex("020000000001")
IP_GW = bytes([10, 0, 0, 2])
IP_TERM = bytes([10, 0, 0, 1])
RTP_PORT = 30000


def ipv4(src, dst, proto, payload, ident=1):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                      0x4000, 64, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack(">H", ip_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp4(src, dst, sport, dport, payload):
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack(">BBH", 0, 17, len(u))
    c = ip_csum(ph + u) or 0xFFFF
    return u[:6] + struct.pack(">H", c) + u[8:]


def ipv4_udp(src, dst, sport, dport, payload, ident=1):
    return ipv4(src, dst, 17, udp4(src, dst, sport, dport, payload), ident)


def ipv6_udp(src, dst, sport, dport, payload):
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack(">IxxxB", len(u), 17)
    c = ip_csum(ph + u) or 0xFFFF
    u = u[:6] + struct.pack(">H", c) + u[8:]
    return struct.pack(">IHBB", 0x60000000, len(u), 17, 64) + src + dst + u


def eth_ip_udp(src_mac, dst_mac, src, dst, sport, dport, payload, ident):
    return (dst_mac + src_mac + b"\x08\x00" +
            ipv4_udp(src, dst, sport, dport, payload, ident))


SDP = (b"v=0\r\n"
       b"o=- 1 1 IN IP4 10.0.0.1\r\n"
       b"s=DVB-S2 BBFrames\r\n"
       b"c=IN IP4 10.0.0.1\r\n"
       b"t=0 0\r\n"
       b"m=video 30000 RTP/AVP 96\r\n"
       b"a=rtpmap:96 DVB-S2/90000\r\n")

SIP_INVITE = (b"INVITE sip:gw@10.0.0.2 SIP/2.0\r\n"
              b"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n"
              b"Max-Forwards: 70\r\n"
              b"From: <sip:term@10.0.0.1>;tag=1\r\n"
              b"To: <sip:gw@10.0.0.2>\r\n"
              b"Call-ID: dvbs2-1@10.0.0.1\r\n"
              b"CSeq: 1 INVITE\r\n"
              b"Contact: <sip:term@10.0.0.1:5060>\r\n"
              b"Content-Type: application/sdp\r\n"
              b"Content-Length: " + str(len(SDP)).encode() + b"\r\n"
              b"\r\n" + SDP)


class Capture:
    """Ethernet frames: the SIP INVITE, then RTP packets carrying one
    BBFrame each, from the gateway to the terminal (forward) or back
    (return)."""

    def __init__(self):
        self.frames = [eth_ip_udp(MAC_TERM, MAC_GW, IP_TERM, IP_GW, 5060,
                                  5060, SIP_INVITE, 1)]
        self.seq = {True: 1000, False: 5000}
        self.ident = 2

    def rtp(self, payload, forward=True):
        seq = self.seq[forward]
        self.seq[forward] = (seq + 1) & 0xFFFF
        ssrc = 0x11111111 if forward else 0x22222222
        r = struct.pack(">BBHII", 0x80, 96, seq, seq * 3000, ssrc) + payload
        if forward:
            fr = eth_ip_udp(MAC_GW, MAC_TERM, IP_GW, IP_TERM, RTP_PORT,
                            RTP_PORT, r, self.ident)
        else:
            fr = eth_ip_udp(MAC_TERM, MAC_GW, IP_TERM, IP_GW, RTP_PORT,
                            RTP_PORT, r, self.ident)
        self.ident += 1
        self.frames.append(fr)

    def udp_raw(self, payload):
        self.frames.append(eth_ip_udp(MAC_GW, MAC_TERM, IP_GW, IP_TERM,
                                      31000, 31000, payload, self.ident))
        self.ident += 1


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i // 10,
                                (i % 10) * 100000, len(fr), len(fr)))
            f.write(fr)


# --- mode adaptation and BB header ----------------------------------------

TSGS_PACKETIZED = 0x00
TSGS_GSE = 0x40
TSGS_HEM = 0x80
TSGS_TS = 0xC0
SIS = 0x20      # MIS bit set: single input stream
CCM = 0x10      # ACM bit set: constant coding and modulation
ISSYI = 0x08
NPD = 0x04


def bbheader(matype1, matype2, upl_bits, dfl_bits, sync, syncd, crc=None):
    h = struct.pack(">BBHHBH", matype1, matype2, upl_bits, dfl_bits, sync,
                    syncd)
    return h + bytes([crc8(h) if crc is None else crc])


def detect(frame):
    """The mode adaptation types detect_dvb_s2_modeadapt() finds."""
    found = set()

    def ok(off):
        return (len(frame) >= off + 10 and
                crc8(frame[off:off + 9]) == frame[off + 9])
    if ok(0):
        found.add(1)
    if frame[0] == 0xB8 and ok(2):
        found.add(2)
    if ok(3):
        found.add(4)
    if frame[0] == 0xB8 and ok(4):
        found.add(3)
    return found


def modeadapt(bb, mtype=3, acm=0x04, cni=0x20, frameno=0, ambiguous=False):
    """Mode adaptation header of type L.1-L.4 in front of a BBFrame,
    changing the frame number (or for L.2 the ACM byte) until only the
    wanted type is detected, unless an ambiguous header is wanted."""
    for k in range(256):
        if mtype == 1:
            ma = b""
        elif mtype == 2:
            ma = bytes([0xB8, (acm + k) & 0x7F if k else acm])
        elif mtype == 3:
            ma = bytes([0xB8, acm, cni, (frameno + k) & 0xFF])
        else:
            ma = bytes([acm, cni, (frameno + k) & 0xFF])
        fr = ma + bb
        d = detect(fr)
        if ambiguous:
            if mtype in d and len(d) > 1:
                return fr
        elif d == {mtype}:
            return fr
        if mtype == 1:
            break
    raise ValueError("cannot build an %s L.%d frame" %
                     ("ambiguous" if ambiguous else "unambiguous", mtype))


def bbframe(matype1, data, isi=0, upl=0, sync=0, syncd=0, dfl=None,
            mtype=3, acm=0x04, frameno=0, bbcrc=None, ambiguous=False):
    dfl_bits = len(data) * 8 if dfl is None else dfl
    return modeadapt(bbheader(matype1, isi, upl, dfl_bits, sync, syncd,
                              bbcrc) + data,
                     mtype=mtype, acm=acm, frameno=frameno,
                     ambiguous=ambiguous)


# --- GSE ------------------------------------------------------------------

LABEL6, LABEL3, LABEL0, LABEL_REUSE = 0, 1, 2, 3
LABELS = {LABEL6: bytes.fromhex("02aabbccdd01"), LABEL3: b"\x12\x34\x56",
          LABEL0: b"", LABEL_REUSE: b""}


def gse_hdr(start, stop, lt, length):
    return struct.pack(">H", (start << 15) | (stop << 14) | (lt << 12) |
                       (length & 0xFFF))


def gse_complete(lt, proto, pdu, ext=None):
    body = struct.pack(">H", proto) + LABELS[lt]
    if ext is not None:
        body += bytes([ext])
    body += pdu
    return gse_hdr(1, 1, lt, len(body)) + body


def gse_fragments(lt, fragid, proto, pdu, cuts, bad_crc=False,
                  totlen_delta=0):
    """Split a PDU into a start fragment, middle fragments and an end
    fragment. cuts are offsets into the data after the Frag ID (total
    length, protocol type, label, PDU)."""
    payload = struct.pack(">H", 2 + len(LABELS[lt]) + len(pdu) +
                          totlen_delta) + struct.pack(">H", proto) + \
        LABELS[lt] + pdu
    crc = crc32_mpeg2(payload) ^ (0xFFFFFFFF if bad_crc else 0)
    parts = []
    prev = 0
    for c in list(cuts) + [len(payload)]:
        parts.append(payload[prev:c])
        prev = c
    pkts = []
    for i, p in enumerate(parts):
        start = i == 0
        stop = i == len(parts) - 1
        body = bytes([fragid]) + p
        if stop:
            body += struct.pack(">I", crc)
        pkts.append(gse_hdr(start, stop, lt if start else LABEL_REUSE,
                            len(body)) + body)
    return pkts


def gse_padding(n):
    return b"\x00" * n


# --- payloads -------------------------------------------------------------

def udp_v4(n, sport=40000, dport=40001, ident=100):
    return ipv4_udp(bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]), sport,
                    dport, bytes((i * 7) & 0xFF for i in range(n)), ident)


def udp_v6(n):
    return ipv6_udp(bytes.fromhex("20010db8000000000000000000000001"),
                    bytes.fromhex("20010db8000000000000000000000002"),
                    40002, 40003, bytes((i * 5) & 0xFF for i in range(n)))


def vlan(vid, inner):
    return struct.pack(">HH", vid, 0x0800) + inner


def s2_tdt_table():
    """RCS2 Time and Date Table: table ID 0x70, interactive network ID,
    version, MJD date and BCD time."""
    return bytes([0x70]) + struct.pack(">HB", 0x0001, 0xC3) + \
        struct.pack(">HBBB", 61347, 0x12, 0x34, 0x56)


# --- Transport Streams over BBFrames -------------------------------------

def ts_packets(pid, count, cc0=0):
    """TS packets (with their 0x47 sync byte). PID 0 packets carry a PAT
    section, other PIDs null packets."""
    pkts = []
    for i in range(count):
        if pid == 0:
            sect = bytes([0x00]) + struct.pack(">H", 0xB00D) + \
                struct.pack(">HBBB", 0x0001, 0xC1, 0, 0) + \
                struct.pack(">HH", 0x0001, 0xE100)
            sect += struct.pack(">I", crc32_mpeg2(sect))
            payload = b"\x00" + sect
            hdr = struct.pack(">BHB", 0x47, 0x4000 | pid,
                              0x10 | ((cc0 + i) & 0xF))
        else:
            payload = b""
            hdr = struct.pack(">BHB", 0x47, 0x1FFF, 0x10)
        pkts.append(hdr + payload + b"\xff" * (184 - len(payload)))
    return pkts


def ts_userpackets(tsps, issy_len=0, npd=False):
    """Data field bytes for TS packets as DVB-S2 user packets: the sync
    byte is replaced by the CRC-8 of the previous user packet, and ISSY
    and DNP follow each packet."""
    out = b""
    prev_crc = 0
    for i, t in enumerate(tsps):
        tail = t[1:]
        if issy_len:
            tail += bytes([0x40 | i, 0x10, 0x20][:issy_len])
        if npd:
            tail += bytes([i & 0xFF])
        out += bytes([prev_crc]) + tail
        prev_crc = crc8(tail)
    return out


def ts_bbframes(cap, isi, upl, matype_extra, stream, sizes, forward=False,
                matype1_base=TSGS_TS, syncd_override=None):
    """Slice a user packet stream into BBFrames of the given data field
    sizes and send them, with SYNCD pointing at the first user packet
    that starts in each frame (0xFFFF if none)."""
    pos = 0
    for n, size in enumerate(sizes):
        data = stream[pos:pos + size]
        # the next user packet start at or after pos
        first = ((pos + upl - 1) // upl) * upl
        if first < pos + size:
            syncd = (first - pos) * 8
        else:
            syncd = 0xFFFF
        if syncd_override and n in syncd_override:
            syncd = syncd_override[n]
        cap.rtp(bbframe(matype1_base | matype_extra, data, isi=isi,
                        upl=upl * 8, sync=0x47, syncd=syncd,
                        frameno=isi + n), forward)
        pos += size
    return pos


# --- the captures ---------------------------------------------------------

def build_main():
    cap = Capture()
    gse = TSGS_GSE | SIS | CCM

    # 2: L.3, a complete IPv4 PDU with a 6 octet label
    cap.rtp(bbframe(gse, gse_complete(LABEL6, 0x0800, udp_v4(20))))
    # 3: DVB-S2X MODCOD in the ACM byte; IPv6 with a 3 octet label, VLAN
    # (broadcast label), a Bridged Frame type re-using the label, padding
    cap.rtp(bbframe(gse, gse_complete(LABEL3, 0x86DD, udp_v6(16)) +
                    gse_complete(LABEL0, 0x8100, vlan(100, udp_v4(8, ident=101))) +
                    gse_complete(LABEL_REUSE, 0x0001, b"\x01\x02\x03\x04") +
                    gse_padding(12), acm=0xC5, frameno=1))
    # 4: NCR, a signalling table (TDT), an optional extension header,
    # then the EIP CRC32 over the data field (SYNC = 1)
    data = (gse_complete(LABEL0, 0x0081, bytes.fromhex("000102030405")) +
            gse_complete(LABEL0, 0x0082, s2_tdt_table()) +
            gse_complete(LABEL0, 0x0101, b"\xAA\xBB", ext=0x08))
    data += struct.pack(">I", crc32_mpeg2(data))
    cap.rtp(bbframe(gse, data, sync=1, frameno=2))
    # 5-7: two PDUs fragmented over three BBFrames (Frag IDs 1 and 2),
    # interleaved, with a middle fragment
    big = udp_v4(150, ident=102)
    f1 = gse_fragments(LABEL6, 1, 0x0800, big, [60, 120])
    f2 = gse_fragments(LABEL3, 2, 0x86DD, udp_v6(40), [30])
    cap.rtp(bbframe(gse, f1[0], frameno=3))
    cap.rtp(bbframe(gse, f1[1] + f2[0], frameno=4))
    cap.rtp(bbframe(gse, f1[2] + f2[1] + gse_padding(6), frameno=5))
    # 8: an end fragment without a start (discarded, CRC unverified) and
    # the start of Frag ID 3
    orphan = gse_fragments(LABEL0, 9, 0x0800, udp_v4(10, ident=103), [12])
    f3old = gse_fragments(LABEL0, 3, 0x0800, udp_v4(30, ident=104), [20])
    cap.rtp(bbframe(gse, orphan[1] + f3old[0], frameno=6))
    # 9-10: a new start of Frag ID 3 replaces the unfinished one, its end
    # follows in the next frame
    f3 = gse_fragments(LABEL0, 3, 0x0800, udp_v4(24, ident=105), [26])
    cap.rtp(bbframe(gse, f3[0], frameno=7))
    cap.rtp(bbframe(gse, f3[1], frameno=8))
    # 11-14: multiple input streams: the same Frag ID 1 on ISI 5 and 6,
    # adaptive coding, interleaved
    mis = TSGS_GSE
    fa = gse_fragments(LABEL6, 1, 0x0800, udp_v4(40, ident=106), [30])
    fb = gse_fragments(LABEL6, 1, 0x86DD, udp_v6(30), [35])
    cap.rtp(bbframe(mis, fa[0], isi=5, frameno=9))
    cap.rtp(bbframe(mis, fb[0], isi=6, frameno=10))
    cap.rtp(bbframe(mis, fa[1], isi=5, frameno=11))
    cap.rtp(bbframe(mis | CCM, fb[1], isi=6, frameno=12))
    # 15: generic packetized stream (not GSE), user packets of 32 octets
    cap.rtp(bbframe(TSGS_PACKETIZED | SIS | CCM, bytes(range(64)),
                    upl=32 * 8, sync=0x00, syncd=0, frameno=13))
    # 16: L.2 mode adaptation header (sync and ACM only)
    cap.rtp(bbframe(gse, gse_complete(LABEL0, 0x0800, udp_v4(12, ident=107)),
                    mtype=2, acm=0x0B))
    # 17: L.4 mode adaptation header (ACM, CNI, frame number, no sync)
    cap.rtp(bbframe(gse, gse_complete(LABEL0, 0x0800, udp_v4(14, ident=108)),
                    mtype=4, acm=0x23, frameno=14))
    # 18: L.1, no mode adaptation header; DFL shorter than the frame
    # (zero padding after the data field)
    pdu = gse_complete(LABEL0, 0x0800, udp_v4(16, ident=109))
    cap.rtp(bbframe(gse, pdu + bytes(8), dfl=len(pdu) * 8, mtype=1))

    # Transport Streams on the return direction, one input stream per
    # user packet format: 188 octets (no ISSY, no DNP), 189 (DNP), 190
    # (short ISSY), 191 (short ISSY and DNP), 191 (long ISSY), 192 (long
    # ISSY and DNP)
    # 19-21: ISI 1, UPL 188, PAT packets: the first frame starts with a
    # user packet (SYNCD 0) and ends in the middle of the second; the
    # second frame lies inside that user packet (SYNCD 0xFFFF); the third
    # finishes it (reassembled from three frames) and holds two more
    upl = 188
    stream = ts_userpackets(ts_packets(0, 4))
    ts_bbframes(cap, 1, upl, CCM, stream, [188 + 50, 100, len(stream) - 338])
    for isi, upl, extra, issy, npd in (
            (2, 189, NPD, 0, True),
            (3, 190, ISSYI, 2, False),
            (4, 191, ISSYI | NPD, 2, True),
            (5, 191, ISSYI, 3, False),
            (6, 192, ISSYI | NPD, 3, True)):
        stream = ts_userpackets(ts_packets(0x1FFF, 3), issy, npd)
        ts_bbframes(cap, isi, upl, extra | CCM, stream,
                    [upl + 20, len(stream) - upl - 20])
    # low roll-off: from the frame with roll-off '11' on, the conversation
    # shows the low roll-off values
    cap.rtp(bbframe(gse | 0x03, gse_complete(LABEL0, 0x0800,
                                             udp_v4(10, ident=110)),
                    frameno=15))
    cap.rtp(bbframe(gse | 0x01, gse_complete(LABEL0, 0x0800,
                                             udp_v4(10, ident=111)),
                    frameno=16))
    # BBFrames sent in plain UDP to port 31000, without RTP or SDP: data
    # by default, DVB-S2 with the dvb_s2_udp heuristic or Decode As; the
    # second datagram is not a BBFrame (the heuristic rejects it)
    cap.udp_raw(bbframe(gse, gse_complete(LABEL0, 0x0800,
                                          udp_v4(10, ident=112)),
                        frameno=17))
    cap.udp_raw(b"not a BBFrame, only text in a UDP datagram")
    return cap.frames


def build_malformed():
    cap = Capture()
    gse = TSGS_GSE | SIS | CCM
    ok = gse_complete(LABEL0, 0x0800, udp_v4(10))
    # GSE with ISSYI, NPD and a non-zero UPL
    cap.rtp(bbframe(gse | ISSYI | NPD, ok, upl=188 * 8))
    # DFL longer than the frame
    cap.rtp(bbframe(gse, ok, dfl=(len(ok) + 50) * 8, frameno=1))
    # GSE-HEM (reserved TS/GS value)
    cap.rtp(bbframe(TSGS_HEM | SIS | CCM, ok, frameno=2))
    # Bad BB header CRC (decoded as the preferred L.3 type)
    cap.rtp(bytes([0xB8, 0x04, 0x20, 0x04]) +
            bbheader(gse, 0, 0, len(ok) * 8, 0, 0, crc=0x5A) + ok)
    # Ambiguous mode adaptation header (L.3 and L.4 CRCs both match)
    amb = None
    for fn in range(256):
        bb = bbheader(gse, 0, 0, len(ok) * 8, 0, 0) + ok
        for cni in range(256):
            fr = bytes([0xB8, 0x04, cni, fn]) + bb
            if {3, 4} <= detect(fr) or {3, 1} <= detect(fr):
                amb = fr
                break
        if amb:
            break
    cap.rtp(amb)
    # GSE length beyond the frame
    cap.rtp(bbframe(gse, gse_hdr(1, 1, LABEL0, 200) + b"\x08\x00" +
                    udp_v4(10), frameno=4))
    # GSE total length that does not match, and a bad GSE CRC32
    fr = gse_fragments(LABEL0, 4, 0x0800, udp_v4(20), [10], totlen_delta=3)
    cap.rtp(bbframe(gse, fr[0], frameno=5))
    cap.rtp(bbframe(gse, fr[1], frameno=6))
    fr = gse_fragments(LABEL0, 5, 0x0800, udp_v4(20), [10], bad_crc=True)
    cap.rtp(bbframe(gse, fr[0], frameno=7))
    cap.rtp(bbframe(gse, fr[1], frameno=8))
    # Bad EIP CRC32
    cap.rtp(bbframe(gse, ok + b"\x00\x00\x00\x00", sync=1, frameno=9))
    # GSE packet shorter than its fixed fields (start fragment of 1 octet)
    cap.rtp(bbframe(gse, gse_hdr(1, 0, LABEL0, 1) + b"\x07" + gse_padding(2),
                    frameno=10))
    # Frag ID 7 ends and starts again in the same BBFrame: the second
    # pass shows the first PDU as reassembled in the frame of the second
    # (dvbs2gse_samefrag.py)
    p1 = gse_fragments(LABEL0, 7, 0x0800, udp_v4(12, ident=200), [12])
    p2 = gse_fragments(LABEL0, 7, 0x0800, udp_v4(12, ident=201), [12])
    cap.rtp(bbframe(gse, p1[0], frameno=11))
    cap.rtp(bbframe(gse, p1[1] + p2[0], frameno=12))
    cap.rtp(bbframe(gse, p2[1], frameno=13))

    # Transport Streams with header fields that do not match the UPL
    stream = ts_userpackets(ts_packets(0x1FFF, 2))
    for isi, upl, extra in ((10, 188, ISSYI | NPD), (11, 189, ISSYI),
                            (12, 190, NPD), (13, 191, 0), (14, 191, NPD),
                            (15, 192, 0), (16, 100, 0), (17, 300, 0)):
        st = ts_userpackets(ts_packets(0x1FFF, 2), 0, False)
        st = st[:upl * 2] if len(st) >= upl * 2 else st + bytes(upl * 2 - len(st))
        cap.rtp(bbframe(TSGS_TS | SIS | CCM | extra, st, isi=isi,
                        upl=upl * 8, sync=0x47, syncd=0, frameno=isi))
    # TS sync byte copy that is not 0x47, SYNCD beyond the data field
    cap.rtp(bbframe(TSGS_TS | SIS | CCM, stream, isi=20, upl=188 * 8,
                    sync=0x46, syncd=0, frameno=20))
    cap.rtp(bbframe(TSGS_TS | SIS | CCM, stream, isi=21, upl=188 * 8,
                    sync=0x47, syncd=len(stream) * 8, frameno=21))
    # TS slicing with a lost BBFrame: the user packet reassembled from
    # the first and third frame has the wrong length
    stream = ts_userpackets(ts_packets(0x1FFF, 4))
    pos = 0
    for n, size in enumerate([188 + 50, 100, len(stream) - 338]):
        data = stream[pos:pos + size]
        first = ((pos + 187) // 188) * 188
        syncd = (first - pos) * 8 if first < pos + size else 0xFFFF
        if n != 1:
            cap.rtp(bbframe(TSGS_TS | SIS | CCM, data, isi=22, upl=188 * 8,
                            sync=0x47, syncd=syncd, frameno=30 + n))
        pos += size
    # A BBFrame shorter than the BB header
    cap.rtp(bytes([0xB8, 0x04, 0x20, 0x00]) + bytes([gse, 0, 0, 0]))
    return cap.frames


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-s2-bb-coverage.pcap"), build_main())
    write_pcap(os.path.join(out, "dvb-s2-bb-coverage-malformed.pcap"),
               build_malformed())

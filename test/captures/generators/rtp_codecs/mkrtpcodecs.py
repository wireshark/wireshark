#!/usr/bin/env python3
# Generates test/captures/rtp_codecs_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for the RTP player/sharkd download codec paths.

Usage: mkrtpcodecs.py <outdir>
Writes rtp_codecs_coverage.pcap (several SIP/SDP calls, each followed by
one RTP stream), rtp_codecs_coverage-malformed.pcap (error paths only) and
the <name>_tokens.txt files (the sharkd download tokens).
Only documentation addresses (192.0.2.0/24) and made-up MACs are used.
"""
import os
import struct
import sys

A = "192.0.2.1"   # caller, receives the RTP
B = "192.0.2.2"   # callee, sends the RTP


def ip2b(s):
    return bytes(int(x) for x in s.split("."))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     ip2b(src), ip2b(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + udp


def sdp(addr, port, pts, rtpmaps):
    s = ("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
         "m=audio %d RTP/AVP %s\r\n" % (addr, addr, port, " ".join(str(p) for p in pts)))
    for r in rtpmaps:
        s += "a=rtpmap:%s\r\n" % r
    return s


def sip(first, callid, body, cseq="1 INVITE"):
    resp = first.startswith("SIP/")
    h = ("%s\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK1\r\n"
         "From: <sip:a@%s>;tag=1\r\nTo: <sip:b@%s>%s\r\nCall-ID: %s\r\n"
         "CSeq: %s\r\nContact: <sip:a@%s>\r\nContent-Type: application/sdp\r\n"
         "Content-Length: %d\r\n\r\n" % (first, A, A, B, ";tag=2" if resp else "",
                                         callid, cseq, A, len(body)))
    return (h + body).encode()


def rtp(pt, seq, ts, ssrc, payload):
    return struct.pack("!BBHII", 0x80, pt, seq, ts, ssrc) + payload


def ramp16(n, step=300):
    """n big-endian 16-bit samples of a triangle-ish wave."""
    out = b""
    v = 0
    d = step
    for _ in range(n):
        out += struct.pack(">h", v)
        v += d
        if v > 20000 or v < -20000:
            d = -d
    return out


def _tbl(width, poly):
    out = []
    for i in range(256):
        reg = 0
        for b in range(7, -1, -1):
            top = ((reg >> (width - 1)) & 1) ^ ((i >> b) & 1)
            reg = (reg << 1) & ((1 << width) - 1)
            if top:
                reg ^= poly & ((1 << width) - 1)
        out.append(reg)
    return out


CRC6 = _tbl(6, 0x6f)
CRC10 = _tbl(10, 0x233)


def crc6(data):
    c = 0
    for b in data:
        c = CRC6[((c << 2) ^ b) & 0xff]
    return c


def crc10_update(acc, data):
    for b in data:
        acc = ((acc << 8) & 0x3ff) ^ CRC10[(acc >> 2) & 0xff] ^ b
    return acc


def iuup(pdu, frame, payload, good=True):
    """IuUP data PDU: type 0 (header CRC and payload CRC) or type 1 (header CRC)."""
    b0 = (pdu << 4) | frame
    b1 = 0x00
    c6 = crc6(bytes([b0, b1])) ^ (0 if good else 1)
    if pdu == 1:
        return bytes([b0, b1, c6 << 2]) + payload
    for p in range(1024):
        e0, e1 = p >> 2, (p << 6) & 0xff
        if crc10_update(crc10_update(0, payload), bytes([e0, e1])) == 0:
            break
    p ^= 0 if good else 1
    return bytes([b0, b1, (c6 << 2) | (p >> 8), p & 0xff]) + payload


class Gen:
    def __init__(self):
        self.frames = []
        self.tokens = {}
        self.n = 0

    def call(self, name, pts, rtpmaps, pkts):
        """pkts: list of (pt, payload)."""
        aport = 40000 + 10 * self.n
        bport = aport + 2
        ssrc = 0x11220000 + self.n
        callid = "codecs-%s@%s" % (name, A)
        self.n += 1
        self.frames.append(udp_frame(A, B, 5060, 5060, sip(
            "INVITE sip:b@%s SIP/2.0" % B, callid, sdp(A, aport, pts, rtpmaps))))
        self.frames.append(udp_frame(B, A, 5060, 5060, sip(
            "SIP/2.0 200 OK", callid, sdp(B, bport, pts, rtpmaps))))
        seq, ts = 1000, 0
        for pt, pl in pkts:
            self.frames.append(udp_frame(B, A, bport, aport, rtp(pt, seq, ts, ssrc, pl)))
            seq += 1
            ts += 160
        self.tokens[name] = "rtp:%s_%d_%s_%d_%x" % (B, bport, A, aport, ssrc)

    def write(self, outdir, name):
        with open(os.path.join(outdir, name + ".pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)
        with open(os.path.join(outdir, name + "_tokens.txt"), "w") as f:
            for k, v in self.tokens.items():
                f.write("%s %s\n" % (k, v))


def main(outdir):
    g = Gen()
    # g711: PCMU and PCMA in one stream, every code value, plus an empty payload
    g.call("g711", [0, 8], [],
           [(0, bytes(range(256))), (0, b"\xff" * 160), (8, bytes(range(256))),
            (8, b"\xd5" * 160), (0, b""), (8, b"\x55" * 40)])
    # L16: PT 11 mono (odd length: one stray byte, the fixed uninitialised read),
    # PT 10 stereo, dynamic L16/16000 is in the resample call
    g.call("l16", [11, 10], [],
           [(11, ramp16(80)), (11, b"\x10" * 3), (10, ramp16(80)),
            (10, b"\x10" * 6), (11, ramp16(40))])
    # L24: dynamic mono and stereo, lengths that are not a multiple of 3*ch
    g.call("l24", [97, 98], ["97 L24/8000/1", "98 L24/8000/2"],
           [(97, bytes(range(60))), (97, b"\x10" * 5), (98, bytes(range(60))),
            (98, b"\x20" * 7), (97, bytes(range(30)))])
    # opus: CELT 20 ms frames (any bytes decode) and a 1 byte packet
    opus = bytes([0xf8]) + bytes((i * 37 + 11) & 0xff for i in range(60))
    g.call("opus", [99], ["99 opus/48000/2"],
           [(99, opus), (99, bytes([0xf8])), (99, opus[:30])])
    # sample rate changes inside one stream (sharkd resampler): 8k, 44.1k,
    # 16k, back to 8k (no resampling), 44.1k again
    g.call("resample", [0, 11, 96], ["96 L16/16000/1"],
           [(0, b"\xff" * 160), (11, ramp16(700)), (11, ramp16(700)),
            (96, ramp16(320)), (96, ramp16(320)), (0, b"\x7f" * 160),
            (11, ramp16(700))])
    # upsampling needs a bigger resample buffer: first 48 kHz opus, then 8 kHz
    g.call("upsample", [99, 0], ["99 opus/48000/2"],
           [(99, opus), (0, bytes(range(256)) + bytes(range(144))), (0, b"\xff" * 160)])
    # IuUP (RTP player decodes it as AMR, which is not built into every
    # package): valid type 1 and type 0 (CRC) PDUs with correct CRCs, a
    # header without AMR data (NO_DATA), a payload of 294 bytes (over the
    # uint8 limit; the fixed assert) and AMR sizes that match no frame type
    g.call("iuup", [96], ["96 VND.3GPP.IUFP/16000"],
           [(96, iuup(1, 0, b"\x55" * 31)), (96, iuup(0, 1, b"\x55" * 13)),
            (96, iuup(1, 2, b"")), (96, iuup(1, 3, b"\x55" * 294)),
            (96, iuup(1, 4, b"\x55" * 7)), (96, iuup(1, 5, b"\x55" * 5))])
    # payload types without a codec: GSM, G.729, a dynamic type with no rtpmap
    g.call("nocodec", [3, 18, 100], [],
           [(3, b"\0" * 33), (18, b"\0" * 20), (100, b"\0" * 20)])
    g.write(outdir, "rtp_codecs_coverage")

    # Only for the coverage number (error expert infos): Opus packets that
    # the decoder rejects (63 frames; frame length past the end, which only
    # the decode call notices), an IuUP PDU of unknown type, a bad header
    # CRC and a bad payload CRC
    m = Gen()
    m.call("opusbad", [99], ["99 opus/48000/2"],
           [(99, opus), (99, bytes([0xfb, 0x3f])), (99, bytes([0xfb, 0x82, 0xfc])),
            (99, opus[:30])])
    m.call("iuupbad", [96], ["96 VND.3GPP.IUFP/16000"],
           [(96, bytes([0x20, 0, 0]) + b"\x55" * 31),
            (96, iuup(1, 0, b"\x55" * 31, good=False)),
            (96, iuup(0, 1, b"\x55" * 13, good=False))])
    m.write(outdir, "rtp_codecs_coverage-malformed")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")

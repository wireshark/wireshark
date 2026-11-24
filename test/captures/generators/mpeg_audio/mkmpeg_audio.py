#!/usr/bin/env python3
# Generates test/captures/mpeg_audio_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MPEG Audio coverage captures. The main capture is an HTTP
client fetching audio/mpeg and audio/mp3 objects over TCP; the bodies hold
MPEG-1/2/2.5 layer I/II/III frames, an ID3v2 and an ID3v1 tag. The
malformed capture uses Exported PDUs (mpeg-audio).
Usage: mkmpeg_audio.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import (
    exp_pdu, LINKTYPE_ETHERNET, LINKTYPE_WIRESHARK_UPPER_PDU, Tcp, TS, udp_frame, write_pcap,
)

BR = [  # [version 0=MPEG1,1=MPEG2,2=MPEG2.5][layer 0=I,1=II,2=III]
    [[0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
     [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
     [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]],
    [[0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
     [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
     [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]]]
BR.append(BR[1])
SAMPLES = [[384, 1152, 1152], [384, 1152, 576], [384, 1152, 576]]
FREQ = [[44100, 48000, 32000, 0], [22050, 24000, 16000, 0],
        [11025, 12000, 8000, 0]]
VBITS = {0: 3, 1: 2, 2: 0}      # header version bits
LBITS = {0: 3, 1: 2, 2: 1}      # header layer bits


def frame(ver, layer, brate, freq=0, pad=0, prot=1, priv=0, mode=0,
          modeext=0, cr=0, orig=0, emph=0, fill=0x00):
    h = (0x7FF << 21 | VBITS[ver] << 19 | LBITS[layer] << 17 | prot << 16 |
         brate << 12 | freq << 10 | pad << 9 | priv << 8 | mode << 6 |
         modeext << 4 | cr << 3 | orig << 2 | emph)
    hdr = struct.pack(">I", h)
    if brate == 0 or FREQ[ver][freq] == 0:
        return hdr + bytes([fill]) * 20
    data = BR[ver][layer][brate] * 1000 * SAMPLES[ver][layer] \
        // FREQ[ver][freq] // 8
    padb = (4 if layer == 0 else 1) if pad else 0
    return hdr + bytes([fill]) * (data - 4 + padb)


def id3v1(title=b"Title", artist=b"Artist", album=b"Album", year=b"2026",
          comment=b"Comment", track=1, genre=17, zero=0):
    t = (b"TAG" + title.ljust(30, b"\0") + artist.ljust(30, b"\0") +
         album.ljust(30, b"\0") + year + comment.ljust(28, b"\0") +
         bytes([zero, track, genre]))
    assert len(t) == 128
    return t


def id3v2():
    txt = b"\x00" + b"Synthetic"
    fr = b"TIT2" + struct.pack(">IH", len(txt), 0) + txt
    return b"ID3\x03\x00\x00" + bytes([0, 0, 0, len(fr)]) + fr


def http(body, ctype="audio/mpeg", path="/a.mp3"):
    req = ("GET %s HTTP/1.1\r\nHost: example.invalid\r\n\r\n" % path).encode()
    rsp = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
           "\r\n" % (ctype, len(body))).encode() + body
    return req, rsp


def build_main():
    bodies = []
    # 1: ID3v2 tag, three MPEG-1 layer III frames (padding, CRC, joint
    # stereo, private/copyright/original/emphasis), ID3v1 tag
    bodies.append(("audio/mpeg", id3v2() +
                   frame(0, 2, 9, 0, pad=1, mode=1, modeext=2, priv=1,
                         cr=1, orig=1, emph=1) +
                   frame(0, 2, 5, 1, prot=0, mode=2, emph=3) +
                   frame(0, 2, 2, 2, mode=3) + id3v1()))
    # 2: MPEG-1 layer I and II frames (layer I padding is four bytes)
    bodies.append(("audio/mpeg",
                   frame(0, 0, 3, 0, pad=1) + frame(0, 0, 2, 1, mode=1) +
                   frame(0, 1, 4, 0, pad=1, emph=2) + frame(0, 1, 3, 2)))
    # 3: MPEG-2 layers I-III
    bodies.append(("audio/mp3",
                   frame(1, 0, 2, 0) + frame(1, 1, 3, 1, pad=1) +
                   frame(1, 2, 4, 2, mode=1)))
    # 4: MPEG-2.5 layers I-III, an ID3v1 tag in the middle
    bodies.append(("audio/mpeg",
                   frame(2, 0, 2, 0) + frame(2, 1, 3, 1) +
                   id3v1(b"Mid", b"X", b"Y", b"1999", b"c", 0, 0) +
                   frame(2, 2, 2, 2, pad=1)))
    # 5: free-format frame (bitrate index 0), a frame with the reserved
    # sampling frequency, then bytes that are no frame header (resync on
    # 0xff) and a valid frame behind them
    bodies.append(("audio/mpeg",
                   frame(0, 2, 0, 0) + frame(0, 2, 9, 3) +
                   b"\x01\x02\x03\x04\xff\x00\xff\xf0abc" +
                   frame(0, 2, 2, 0)))
    # 6: junk without any frame: no resync target
    bodies.append(("audio/mpeg", b"\xff\x00\xff\x01\xff\xfe" + b"\x00" * 20))
    t = Tcp()
    t.handshake()
    for i, (ct, b) in enumerate(bodies):
        req, rsp = http(b, ct, "/%d.mp3" % i)
        t.send(True, req)
        t.send(False, rsp)
    t.close()
    # MPEG-TS over UDP: audio PES packets (stream 0xc0, MPEG-1 layer III
    # frames; the PES payload starts with 0xff so MPEG PES hands it to
    # the "mpeg" heuristic list)
    ts = TS()
    pkts = []
    for fr in (frame(0, 2, 9, 0), frame(0, 2, 5, 1) + frame(0, 2, 2, 2),
               frame(0, 1, 4, 0)):
        body = b"\x80\x00\x00" + fr
        pes = b"\x00\x00\x01\xc0" + struct.pack(">H", len(body)) + body
        pkts += ts.pes(0x100, pes)
    # an elementary stream that starts with 0xff but is no audio frame
    body = b"\x80\x00\x00" + b"\xff\x00\x00\x00\x00"
    pkts += ts.pes(0x100, b"\x00\x00\x01\xc0" + struct.pack(">H", len(body)) + body)
    frames = list(t.frames)
    for i in range(0, len(pkts), 7):
        frames.append(udp_frame(b"".join(pkts[i:i + 7]), dport=5004))
    return frames


def build_malformed():
    f = []
    # ID3v1 tag cut short
    f.append(id3v1()[:100])
    # a frame cut short (declared 417 octets, 40 present)
    f.append(frame(0, 2, 9, 0)[:40])
    # a layer I frame cut in the padding
    f.append(frame(0, 0, 3, 0, pad=1)[:-2])
    return [exp_pdu("mpeg-audio", x) for x in f]


if __name__ == "__main__":
    out = sys.argv[1]
    write_pcap(os.path.join(out, "mpeg-audio-coverage.pcap"), build_main(),
               LINKTYPE_ETHERNET)
    # A raw .mp3 file (wiretap/mpeg.c), only used by runcov.sh: it reaches
    # the "mpeg" heuristic with an ID3v2 tag at the start
    with open(os.path.join(out, "mpeg-audio-coverage.mp3"), "wb") as f:
        f.write(id3v2() + frame(0, 2, 9, 0, pad=1) + frame(0, 2, 5, 1) +
                id3v1() + frame(0, 2, 2, 2))
    write_pcap(os.path.join(out, "mpeg-audio-coverage-malformed.pcap"),
               build_malformed(), LINKTYPE_WIRESHARK_UPPER_PDU)

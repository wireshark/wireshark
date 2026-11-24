#!/usr/bin/env python3
# Generates test/captures/dektec_sdi_coverage.dtsdi.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DekTec DTSDI coverage files for the DekTec SDI
dissector (packet-dektec-sdi.c).

Usage: mkdektec_sdi.py <outdir>

A DTSDI file has one video format and storage mode for all its frames,
so each mode gets its own file:

  dektec_sdi-coverage.dtsdi            main file: 720p59.94, packed 10-bit
  dektec_sdi-coverage-sd16.dtsdi       525i59.94, 16-bit storage (SD-SDI)
  dektec_sdi-coverage-8bit.dtsdi       525i59.94, 8-bit storage
  dektec_sdi-coverage-malformed.dtsdi  720p59.94, packed 10-bit, truncated ANC

Every frame is built from 10-bit words with struct; nothing comes from a
real SDI source. The frames are almost all zero, so they compress very
well.
"""
import os
import struct
import sys

FLAG_FULL, FLAG_10B, FLAG_16B = 0x0001, 0x0080, 0x0100

# Full-frame word counts of the wiretap reader (dtsdi_full_frame_size)
WORDS = {0x02: 900900, 0x09: 2475000}


def parity(v):
    """Set bits 8 and 9 of an 8 bit ST 291 value (even parity, b9=!b8)."""
    v &= 0xff
    p = bin(v).count('1') & 1
    return v | (p << 8) | ((p ^ 1) << 9)


def checksum(words):
    s = 0
    for w in words:
        s = (s + (w & 0x1ff)) & 0x1ff
    if not s & 0x100:
        s |= 0x200
    return s


def anc(did, sdid, udw, bad_did=False, bad_sdid=False, bad_dc=False,
        bad_cs=False):
    """An ANC packet: ADF, DID, SDID/DBN, DC, UDW, checksum."""
    d = parity(did) ^ (0x100 if bad_did else 0)
    s = parity(sdid) ^ (0x100 if bad_sdid else 0)
    c = parity(len(udw)) ^ (0x100 if bad_dc else 0)
    body = [d, s, c] + [parity(u) for u in udw]
    cs = checksum(body)
    if bad_cs:
        cs ^= 0x001
    return [0x000, 0x3ff, 0x3ff] + body + [cs]


def xyz(f, v, h):
    p3, p2, p1, p0 = v ^ h, f ^ h, f ^ v, f ^ v ^ h
    return (0x200 | f << 8 | v << 7 | h << 6 | p3 << 5 | p2 << 4 | p1 << 3 |
            p0 << 2)


def eav(line=None, v=0, f=0):
    w = [0x3ff, 0x000, 0x000, xyz(f, v, 1)]
    if line is not None:            # HD: LN0, LN1, CRC0, CRC1
        ln0 = ((line & 0x7f) << 2)
        ln1 = (((line >> 7) & 0x0f) << 2)
        ln0 |= (0 if ln0 & 0x100 else 0x200)
        ln1 |= (0 if ln1 & 0x100 else 0x200)
        w += [ln0, ln1, 0x200, 0x200]
    return w


def sav(v=0, f=0):
    return [0x3ff, 0x000, 0x000, xyz(f, v, 0)]


class Frame:
    """One SDI frame; HD frames interleave a C (even words) and a Y
    (odd words) stream, SD frames have one stream."""

    def __init__(self, nwords, hd):
        self.n = nwords
        self.hd = hd
        self.words = {}

    def put(self, stream, pos, seq):
        for k, w in enumerate(seq):
            idx = 2 * (pos + k) + stream if self.hd else pos + k
            assert idx < self.n
            self.words[idx] = w & 0x3ff

    def positions(self):
        return self.n // 2 if self.hd else self.n

    def pack(self, storage):
        if storage == 16:
            b = bytearray(self.n * 2)
            for i, w in self.words.items():
                struct.pack_into('<H', b, 2 * i, w)
            return bytes(b)
        if storage == 8:
            b = bytearray(self.n)
            for i, w in self.words.items():
                b[i] = w >> 2
            return bytes(b)
        # packed 10-bit, least significant bit first
        b = bytearray((self.n * 10 + 7) // 8)
        for i, w in self.words.items():
            bit = i * 10
            v = w << (bit % 8)
            o = bit // 8
            for k in range(3):
                if o + k < len(b):
                    b[o + k] |= (v >> (8 * k)) & 0xff
        return bytes(b)


def dtsdi(path, data_type, storage, frames):
    flags = FLAG_FULL | {8: 0, 10: FLAG_10B, 16: FLAG_16B}[storage]
    data = [f.pack(storage) for f in frames]
    hdr = struct.pack('<III', 0x546b6544, 0x642e6365, 0x69647374)
    hdr += struct.pack('<BBH', 1, data_type, flags)      # format v2
    hdr += struct.pack('<II', len(data[0]), len(data))
    with open(path, 'wb') as f:
        f.write(hdr)
        for d in data:
            f.write(d)


# Payloads
AFD = [0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]    # ST 2016-3 AFD
ST352 = [0x89, 0x0a, 0x00, 0x01]                         # payload ID
AUDIO = [i * 7 & 0xff for i in range(24)]                # HD audio data
AUDIO_CTRL = [0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00]


def C(f, pos, seq):
    f.put(0, pos, seq)


def Y(f, pos, seq):
    f.put(1, pos, seq)


def hd_frames():
    n = WORDS[0x09]
    frames = []

    # 1: a complete line structure in both streams. Y: EAV of line 9
    #    (vertical blanking), ST 352 payload ID in HANC, SAV into VANC,
    #    AFD in VANC; EAV of line 42, SAV into active video, the next EAV
    #    ends it, a second SAV. C: one audio data packet in HANC, a
    #    Type 1 non-audio packet, SAV into VANC, VANC packet without user
    #    data words.  -> VANC 2, HANC 2 non-audio, audio 1
    f = Frame(n, True)
    Y(f, 10, eav(9, v=1))
    Y(f, 18, anc(0x41, 0x01, ST352))
    Y(f, 40, sav(v=1))
    Y(f, 50, anc(0x41, 0x05, AFD))
    Y(f, 100, eav(42))
    Y(f, 108, sav())
    Y(f, 1000, eav(43))
    Y(f, 1008, sav())
    C(f, 10, eav(9, v=1))
    C(f, 18, anc(0xe7, 0x2f, AUDIO))
    C(f, 60, anc(0x88, 0x00, [0x01, 0x02]))
    C(f, 80, sav(v=1))
    C(f, 90, anc(0x50, 0x01, []))
    frames.append(f)

    # 2: one packet of each kind; audio data and audio control packets
    #    (both counted as audio) in two lines of C.
    #    -> VANC 1, HANC 1 non-audio, audio 2
    f = Frame(n, True)
    Y(f, 10, eav(10, v=1))
    Y(f, 18, anc(0x41, 0x01, ST352))
    Y(f, 40, sav(v=1))
    Y(f, 50, anc(0x41, 0x05, AFD))
    C(f, 10, eav(10, v=1))
    C(f, 18, anc(0xe7, 0x2f, AUDIO))
    C(f, 100, eav(11, v=1))
    C(f, 108, anc(0xe3, 0x2f, AUDIO_CTRL))
    frames.append(f)

    # 3: reproducer of "DekTec SDI: Do not start active video after the
    #    last word": an SAV (active video) in the last four words of C
    #    and nothing else in C. Y: an ANC flag before any timing
    #    reference (ignored), "3FF 000 000" with bit 9 of the fourth word
    #    clear (not a timing reference), and an EAV so close to the end
    #    that it has no line number words.
    #    -> no packets, no active video
    f = Frame(n, True)
    last = f.positions()
    C(f, last - 4, sav())
    Y(f, 2, anc(0x41, 0x05, AFD))
    Y(f, 40, [0x3ff, 0x000, 0x000, 0x100])
    Y(f, last - 6, eav(None))
    frames.append(f)

    # 4: active video in Y, then an SAV in the last four words of Y; one
    #    VANC and one HANC packet in C.  -> VANC 1, HANC 1, no audio
    f = Frame(n, True)
    last = f.positions()
    Y(f, 10, eav(50))
    Y(f, 18, sav())
    Y(f, 2000, eav(51))
    Y(f, last - 4, sav())
    C(f, 10, eav(12, v=1))
    C(f, 18, anc(0x41, 0x01, ST352))
    C(f, 40, sav(v=1))
    C(f, 50, anc(0x41, 0x05, AFD))
    frames.append(f)

    # 5: bad parity of DID, SDID and DC and a bad checksum (warnings),
    #    a Type 1 VANC packet, a VANC packet with 255 user data words,
    #    field 2 timing references.  -> VANC 3, HANC 0, no audio
    f = Frame(n, True)
    Y(f, 10, eav(570, v=1, f=1))
    Y(f, 18, sav(v=1, f=1))
    Y(f, 30, anc(0x41, 0x05, AFD, bad_did=True, bad_sdid=True,
                 bad_dc=True, bad_cs=True))
    Y(f, 60, anc(0xc0, 0x05, [0x55] * 4))
    Y(f, 80, anc(0x43, 0x02, list(range(255))))
    frames.append(f)
    return frames


def sd_frames():
    n = WORDS[0x02]
    frames = []
    # 1: SD-SDI: EAV (no line numbers), HANC audio (DID 0xff) and a
    #    non-audio HANC packet, SAV into VANC with an AFD packet, then
    #    EAV, SAV into active video, EAV, SAV.
    f = Frame(n, False)
    f.put(0, 10, eav(None, v=1))
    f.put(0, 14, anc(0xff, 0x2f, AUDIO))
    f.put(0, 60, anc(0xfb, 0x2f, AUDIO))
    f.put(0, 100, anc(0x41, 0x01, ST352))
    f.put(0, 120, sav(v=1))
    f.put(0, 130, anc(0x41, 0x05, AFD))
    f.put(0, 200, eav(None))
    f.put(0, 204, sav())
    f.put(0, 1000, eav(None))
    f.put(0, 1004, sav())
    frames.append(f)
    # 2: the reproducer dektec_sdi_sav_at_end.py moved to 525i59.94: an
    #    SAV with V=1 and a VANC packet, and an SAV in the last 4 words.
    f = Frame(n, False)
    f.put(0, 100, [0x3ff, 0, 0, 0x200 | 0x80])
    f.put(0, 110, [0, 0x3ff, 0x3ff, 0x241, 0x107, 0x200, 0x248])
    f.put(0, n - 4, [0x3ff, 0, 0, 0x200])
    frames.append(f)
    return frames


def malformed_frames():
    n = WORDS[0x09]
    frames = []
    # 1: an ANC header in the last words of Y: truncated header
    f = Frame(n, True)
    last = f.positions()
    Y(f, 10, eav(9, v=1))
    Y(f, last - 5, [0x000, 0x3ff, 0x3ff, parity(0x41), parity(0x05)])
    frames.append(f)
    # 2: an ANC packet whose data count runs past the end of C
    f = Frame(n, True)
    C(f, 10, eav(9, v=1))
    C(f, last - 8, [0x000, 0x3ff, 0x3ff, parity(0x41), parity(0x05),
                    parity(200), 0, 0])
    frames.append(f)
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    dtsdi(os.path.join(out, 'dektec_sdi-coverage.dtsdi'), 0x09, 10,
          hd_frames())
    dtsdi(os.path.join(out, 'dektec_sdi-coverage-sd16.dtsdi'), 0x02, 16,
          sd_frames())
    f = Frame(WORDS[0x02], False)
    f.put(0, 10, eav(None, v=1))
    f.put(0, 14, anc(0x41, 0x01, ST352))
    dtsdi(os.path.join(out, 'dektec_sdi-coverage-8bit.dtsdi'), 0x02, 8, [f])
    dtsdi(os.path.join(out, 'dektec_sdi-coverage-malformed.dtsdi'), 0x09,
          10, malformed_frames())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/fp_mux_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Huawei FP Mux captures.

Usage: mkfp_mux.py <outdir>
Writes fp_mux-coverage.pcap and fp_mux-coverage-malformed.pcap.

FP Mux runs over UDP.  Its heuristic ("fp_mux_udp") is disabled by default, so
the tests and runcov.sh enable it with --enable-heuristic fp_mux_udp; the first
packet of a flow with at least two muxed payloads makes the dissector the
conversation dissector for the rest of the flow.  The payloads are UMTS FP
control frames (seven bit CRC in the first octet, so the FP heuristic of the
"fp_mux" list accepts them) or opaque data.
"""
import struct
import sys
import os

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            p, cap = fr if isinstance(fr, tuple) else (fr, None)
            c = p if cap is None else p[:cap]
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(c), len(p)))
            f.write(c)

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport, dport, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 3, 0, 64, 17, 0,
                    bytes(src), bytes(dst))
    ip = h[:10] + struct.pack('>H', csum(h)) + h[12:] + udp
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip

def crc7(data):
    r = 0
    for b in data:
        for i in range(7, -1, -1):
            top = ((r >> 6) & 1) ^ ((b >> i) & 1)
            r = (r << 1) & 0x7f
            if top:
                r ^= 0x45
    return r

def fp_control(ftype, body=b''):
    """UMTS FP control frame: header CRC (7 bits) + frame type bit (1) over
    the whole frame with the first octet masked to the frame type bit"""
    rest = bytes([ftype]) + body
    return bytes([(crc7(bytes([1]) + rest) << 1) | 1]) + rest

def crc16(data):
    r = 0
    for b in data:
        r ^= b << 8
        for _ in range(8):
            r = ((r << 1) ^ 0x8005) & 0xffff if r & 0x8000 else (r << 1) & 0xffff
    return r

def fp_rach(cfn, tctf=1, seed=0):
    """28 octet RACH data frame that the FP RACH heuristic accepts: header
    (CRC, CFN, TFI 0, propagation delay), 21 octets of transport block whose
    first two bits are the TCTF, a CRCI octet and the payload CRC"""
    hdr = bytes([cfn, 0, 7])
    tb = bytearray((seed + 11 * i + 3) & 0xff for i in range(21))
    tb[0] = (tb[0] & 0x3f) | (tctf << 6)
    body = bytes(tb) + b'\x00'
    return bytes([crc7(hdr) << 1]) + hdr + body + struct.pack('>H', crc16(body))

def chunk(uid, payload, ext=False):
    if ext:
        return struct.pack('>HH', uid, 0x8000 | len(payload)) + payload
    assert len(payload) < 128
    return struct.pack('>HB', uid, len(payload)) + payload

def opaque(n, seed=0):
    # an even first octet: not an FP control frame (frame type bit 0)
    b = bytes((seed + 5 * i + 1) & 0xff for i in range(n))
    return bytes([b[0] & 0xfe]) + b[1:]

SP, DP = 40000, 5000
main, mal = [], []

# flow 1: the first packet carries two payloads (control frames), so the
# heuristic frames the flow
c1 = fp_control(0x01, b'\x10\x20')
c2 = fp_control(0x02, b'\x30\x40\x50')
main.append(udp_frame(chunk(1, opaque(4, 9)) + chunk(2, opaque(5, 7)), SP, DP))
# a single payload now goes to the conversation dissector
main.append(udp_frame(chunk(3, opaque(4, 3)), SP, DP))
# opaque (not FP) payloads
main.append(udp_frame(chunk(4, opaque(10)) + chunk(5, opaque(20, 3)), SP, DP))
# extended length (15 bit) of exactly 128 and 300 octets, and a needlessly
# extended length of 12 octets (a warning)
main.append(udp_frame(chunk(6, opaque(128, 1), True) + chunk(7, opaque(300, 2), True), SP, DP))
main.append(udp_frame(chunk(8, opaque(12), True) + chunk(9, opaque(3)), SP, DP))
# uid 0 and 65535, minimum payload length 1 and 2
main.append(udp_frame(chunk(0, opaque(1)) + chunk(65535, opaque(2)), SP, DP))
# 64 payloads, the maximum
main.append(udp_frame(b''.join(chunk(i, opaque(4, i)) for i in range(64)), SP, DP))

# flow 2: a single payload in the first packet: the heuristic declines
# (it might be coincidence); plain UDP
main.append(udp_frame(chunk(1, opaque(30)), 41000, 5001))
# flow 3: payloads shorter than 3 octets are not FP Mux: plain UDP
main.append(udp_frame(chunk(1, opaque(2)) + chunk(2, opaque(2)), 41001, 5002))

# flow 4, the fix: source port 0 and a uid equal to the destination port;
# the payload holds a mux header again.  The conversation dissector would be
# FP Mux itself and recursed until the depth limit; now it is skipped.
DPORT = 5003
inner = b'\x02\x02\x03'
for _ in range(1000):
    if len(inner) > 0x7fff:
        break
    inner = struct.pack('>HH', DPORT, 0x8000 | len(inner)) + inner
main.append(udp_frame(inner + chunk(1, opaque(3)), 0, DPORT))
# and a further packet of that flow with a nested header
main.append(udp_frame(chunk(DPORT, chunk(DPORT, opaque(10)) + chunk(2, opaque(3))) + chunk(1, opaque(3)), 0, DPORT))

# ---- malformed
# flow 7: FP control frames in the payloads.  The FP heuristic accepts them
# (valid seven bit CRC) and the FP dissector then has no per-frame
# information and reports it (an error expert info); FP Mux saves and restores
# the FP info that the sub dissector attached for each payload.
FPF = (41020, 5020)
mal.append(udp_frame(chunk(1, c1) + chunk(2, c2), *FPF))
mal.append(udp_frame(chunk(3, fp_control(0x03, b'\x01\x02')), *FPF))
mal.append(udp_frame(chunk(1, c1) + chunk(2, c2) + chunk(1, c1), *FPF))
mal.append(udp_frame(chunk(1, fp_control(0x04, b'\x01')) + chunk(2, fp_control(0x05)), *FPF))
# flow 8: a RACH data frame in a payload.  The FP RACH heuristic frames the
# payload's own conversation, FP attaches per-frame FP, MAC and RLC info and
# FP Mux keeps it per payload (used when the packet is dissected again) and
# takes it off the packet again
FPR = (41021, 5021)
mal.append(udp_frame(chunk(1, fp_rach(10, 1)) + chunk(2, opaque(10)), *FPR))
mal.append(udp_frame(chunk(1, fp_rach(11, 0, 5)), *FPR))
mal.append(udp_frame(chunk(1, fp_rach(12, 1, 9)) + chunk(1, fp_rach(13, 0, 2)) + chunk(3, opaque(6)), *FPR))
# flow 5: framed by the first packet, then bad packets in the flow
FP5 = (41005, 5005)
mal.append(udp_frame(chunk(1, c1) + chunk(2, c2), *FP5))
# payload length 0
mal.append(udp_frame(chunk(1, b'') , *FP5))
mal.append(udp_frame(struct.pack('>HH', 1, 0x8000), *FP5))
# payload length beyond the data (short and extended)
mal.append(udp_frame(struct.pack('>HB', 1, 100) + opaque(10), *FP5))
mal.append(udp_frame(struct.pack('>HH', 1, 0x8000 | 1000) + opaque(10), *FP5))
# 65 payloads: too many
mal.append(udp_frame(b''.join(chunk(i, opaque(4, i)) for i in range(65)), *FP5))
# header cut short (2 octets, 3 octets with the extension flag)
mal.append(udp_frame(b'\x00\x01', *FP5))
mal.append(udp_frame(b'\x00\x01\x80', *FP5))
# flow 6: first packet fine in the heuristic's eyes but the payload length
# does not fit, so the heuristic declines
mal.append(udp_frame(chunk(1, opaque(5)) + struct.pack('>HB', 2, 90) + opaque(3), 41006, 5006))
# a packet of 3 octets and 2 octets: below the minimum for the heuristic
mal.append(udp_frame(b'\x00\x01\x05', 41007, 5007))
mal.append(udp_frame(b'\x00\x01', 41008, 5008))
# a first packet with a payload shorter than 3 octets after valid chunks
mal.append(udp_frame(chunk(1, opaque(5)) + chunk(2, opaque(2)), 41009, 5009))
# first packet whose last chunk has an extended header cut short
mal.append(udp_frame(chunk(1, opaque(5)) + b'\x00\x02\x80', 41010, 5010))
mal.append(udp_frame(chunk(1, opaque(5)) + b'\x00\x02', 41011, 5011))

# a datagram cut off right after the UDP header (empty captured payload)
full = udp_frame(chunk(1, opaque(10)) + chunk(2, opaque(10)), 41030, 5030)
mal.append((full, 42))

write_pcap(os.path.join(out, 'fp_mux-coverage.pcap'), main)
write_pcap(os.path.join(out, 'fp_mux-coverage-malformed.pcap'), mal)
print(len(main), len(mal))

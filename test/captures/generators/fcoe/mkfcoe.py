# Generates test/captures/fcoe_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic data only) ----
import struct
import sys
import os
import zlib

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            wl = len(fr)
            if isinstance(fr, tuple):
                fr, wl = fr
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), wl))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0, seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42, crc=None, ver=0):
    hdr = bytes([ver << 4]) + bytes(12) + bytes([sof])
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    return eth(hdr + fc + struct.pack('<I', crc) + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
# ---- end common helpers ----
#!/usr/bin/env python3
# Generator for the FCoE coverage captures.  Usage: mkfcoe.py <outdir>
# Writes fcoe-coverage.pcap (clean) and fcoe-coverage-malformed.pcap.

def abts(oxid, seqcnt=0, extra=b''):
    return fchdr(0x81, A, B, 0x00, FIRST | SEQLAST, oxid, seqcnt=seqcnt) + extra

SOFS = [0x28, 0x29, 0x2D, 0x2E, 0x31, 0x35, 0x36, 0x39]
EOFS = [0x41, 0x42, 0x44, 0x46, 0x49, 0x4E, 0x4F, 0x50]

def fcoe_old(fc, nib, ver=0, eof=0x42, crc=None, with_eof=True):
    """Pre-T11 header: 2 bytes (version, length in words, SOF nibble)."""
    v = (ver << 14) | ((len(fc) // 4) << 4) | nib
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    body = struct.pack('>H', v) + fc + struct.pack('<I', crc)
    if with_eof:
        body += bytes([eof])
    return eth(body, 0x8906)

def main(out):
    ok = []
    # 1-8: every SOF and every EOF in T11 format
    for i in range(8):
        ok.append(fcoe(abts(0x100 + i), sof=SOFS[i], eof=EOFS[i]))
    # 9: version 1
    ok.append(fcoe(abts(0x110), ver=1))
    # 11: frame length not a multiple of 4
    ok.append(fcoe(abts(0x112, extra=b'ab')))
    # 12: frame with an Ethernet FCS behind the trailer
    f = fcoe(abts(0x113)) + bytes.fromhex('deadbeef')
    ok.append(f)
    # 13: unexpected EOF value
    ok.append(fcoe(abts(0x114), eof=0x77))
    # 14: capture truncated in the trailer (no EOF)
    f = fcoe(abts(0x115))
    ok.append((f[:-5], len(f)))
    # 15: capture truncated in the CRC
    ok.append((f[:-7], len(f)))
    # 20-23: pre-T11 header, several SOF nibbles and EOFs
    for nib, eof in ((5, 0x42), (9, 0x41), (6, 0x42), (12, 0x50), (13, 0x42)):
        ok.append(fcoe_old(abts(0x120 + nib), nib, eof=eof))
    # pre-T11 with a version
    ok.append(fcoe_old(abts(0x130), 5, ver=1))
    # pre-T11 without the EOF byte
    ok.append(fcoe_old(abts(0x131), 5, with_eof=False))
    pcap(os.path.join(out, 'fcoe-coverage.pcap'), ok)

    bad = []
    bad.append(fcoe(abts(0x111), crc=0x12345678))   # bad FC CRC
    bad.append(fcoe_old(abts(0x130), 5, ver=1, crc=0x1111))
    bad.append(fcoe_old(abts(0x132)[:20], 5))
    # 16-19: reproducer of "FCoE: Do not let the frame length go negative"
    for tail in (b'\xaa\xbb\xcc\xdd', b'\x11\xaa\xbb\xcc\xdd',
                 b'\x11\x22\xaa\xbb\xcc\xdd', b'\x11\x22\x33\xaa\xbb\xcc\xdd'):
        body = bytes(13) + bytes([0x2E]) + tail[:-4] + bytes([0x42, 0, 0, 0]) + tail[-4:]
        bad.append(eth(body, 0x8906))
    # pre-T11 length below 4: empty FC frame
    bad.append(eth(bytes([0, 2]) + bytes(12), 0x8906))
    # FCoE frame without any FC payload
    bad.append(eth(bytes(13) + bytes([0x2E]) + bytes(8), 0x8906))
    # FCoE with fewer bytes than header and trailer
    bad.append(eth(bytes(13) + bytes([0x2E]) + bytes(5), 0x8906))
    # FCoE truncated header
    bad.append(eth(bytes(13), 0x8906))
    # FC header cut short
    bad.append(fcoe(abts(0x200)[:10]))
    pcap(os.path.join(out, 'fcoe-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

# Generates test/captures/fcsb3_coverage.pcap.gz
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
# Generator for the FC-SB3 coverage captures.  Usage: mkfcsb3.py <outdir>
# Writes fcsb3-coverage.pcap (clean) and fcsb3-coverage-malformed.pcap.
# FC-SB3 (FICON) is carried in FC frames of type 0x1B / 0x1C over FCoE.

ox = [0x1000]

def sb3(iu_type, dib, data=b'', chid=1, cuid=2, dev=0x0102, iui_flags=0, dh=0, ccw=0x0001, token=0x000102, pad_dib=True):
    """SB-3 header (8), IU header (8), DIB (16, from dib), data."""
    hdr = bytes([0, chid, 0, cuid]) + struct.pack('>H', dev) + bytes(2)
    iu = bytes([(iui_flags & 0x18) | iu_type, dh]) + struct.pack('>H', ccw) + bytes(1) + struct.pack('>I', token)[1:]
    d = dib
    if pad_dib:
        d = dib.ljust(16, b'\0')
    return hdr + iu + d + data

def dib(b0=0, b1=0, cnt=0, b4=0, b5=0, b6=0, b7=0, b8=0, iucnt=1, datacnt=0, lrc=0):
    return (bytes([b0, b1]) + struct.pack('>H', cnt) + bytes([b4, b5, b6, b7, b8, iucnt]) +
            struct.pack('>H', datacnt) + struct.pack('>I', lrc))

def frame(payload, ftype=0x1B, r_ctl=0x01, to_cu=True):
    ox[0] += 1
    s, d = (A, B) if to_cu else (B, A)
    return fcoe(fchdr(r_ctl, d, s, ftype, FIRST | LAST | SEQLAST, ox[0]) + payload)

def build():
    f = []
    # Command headers (IU 1) for several CCW commands, CCW flag and command flag bits
    cmds = [(0x01, 0xff, 0xff), (0x02, 0x80, 0x01), (0x03, 0x40, 0x02), (0x04, 0x20, 0x04),
            (0x05, 0x08, 0x08), (0x0c, 0x00, 0x10), (0x0f, 0xe8, 0x1f), (0x00, 0, 0)]
    for i, (cmd, ccwf, cmdf) in enumerate(cmds):
        f.append(frame(sb3(1, dib(cmd, ccwf, 0x0100 + i, b5=i, b7=cmdf, iucnt=1, datacnt=0, lrc=0x11223344),
                           iui_flags=0x18 if i & 1 else 0x10, dh=0xff if i == 0 else 0x80 >> (i % 4), dev=0x0100 + i, cuid=2),
                       ftype=0x1B))
    # Command header and data (IU 4), from the control unit side type 0x1C
    f.append(frame(sb3(4, dib(1, 0, 8, iucnt=2, datacnt=8), data=bytes(range(8)), ccw=0x0002, dev=0x0300), ftype=0x1C, to_cu=False))
    # Data IUs (0) with data
    f.append(frame(sb3(0, dib(iucnt=3, datacnt=16, lrc=0xdeadbeef), data=bytes(range(16)), ccw=0x0002), ftype=0x1B))
    f.append(frame(sb3(0, dib(iucnt=4, datacnt=0), ccw=0x0002), ftype=0x1B))
    # Status IUs (2): residual valid (rv), FFC 1 (queuing info valid), FFC 2, every status bit
    for fl, st in ((0x01, 0x00), (0x20, 0x80), (0x40, 0x40), (0x21, 0x20), (0x00, 0x10), (0x00, 0x08), (0x01, 0x04), (0x00, 0x02), (0x00, 0x01), (0x81, 0xff)):
        f.append(frame(sb3(2, dib(fl, st, 0x0012, b4=0x56, b5=0x78, b6=0x9a, b7=0xbc, iucnt=5), ccw=0x0002), ftype=0x1C, to_cu=False))
    # Status with supplemental status data (data byte count != 0)
    f.append(frame(sb3(2, dib(0x00, 0x0c, 0, datacnt=4), data=bytes([1, 2, 3, 4])), ftype=0x1C, to_cu=False))
    # Control IUs (3): each control function
    for fn, par in ((0x00, 0), (0x10, 1), (0x20, 2), (0x30, 3), (0x40, 4), (0x50, 0x980018), (0x50, 0x000000),
                    (0x70, 5), (0x80, 1 << 16), (0x80, 7 << 16), (0xa0, 6), (0xb0, 7), (0xc1, 13 << 16), (0xc1, 1 << 16), (0x77, 0x123456)):
        p = struct.pack('>I', par)
        f.append(frame(sb3(3, bytes([fn]) + p[1:] + bytes(5) + bytes([1, 0, 0, 0, 0, 0, 0])), ftype=0x1B))
    # Purge path response (0xd0): the error code is 60 octets into the DIB
    for err in (0, 3, 16, 99):
        d = bytes([0xd0]) + bytes(15) + bytes(44) + bytes([err]) + bytes(3)
        f.append(frame(sb3(3, d), ftype=0x1C, to_cu=False))
    # Link control IUs (5): every function; byte 1 is the function, bytes 2-3 the info
    def link(fn, info=0, ctc=0, iucnt=1, datacnt=0, data=b''):
        return sb3(5, bytes([0, fn]) + struct.pack('>HH', info, ctc) + bytes([0, 0, 0, iucnt]) + struct.pack('>HI', datacnt, 0), data=data)
    for fn, info in ((0x41, 0x0081), (0x49, 0), (0x09, 0x0007), (0x51, 0x0001), (0x59, 0x0300), (0x59, 0x0004),
                     (0x11, 0x0600), (0x11, 0x0900), (0x21, 0), (0x61, 0), (0xff, 0x1234)):
        f.append(frame(link(fn, info, ctc=0x0abc), ftype=0x1B))
    # TIR with logical path bit maps: 8 octets (two groups) and 4 octets
    f.append(frame(link(0x01, 0, datacnt=8, data=bytes(range(8))), ftype=0x1C, to_cu=False))
    f.append(frame(link(0x01, 0, datacnt=4, data=bytes(4)), ftype=0x1C, to_cu=False))
    f.append(frame(link(0x01, 0, datacnt=0), ftype=0x1C, to_cu=False))
    # Reserved IU types 6 and 7 are shown as data
    f.append(frame(sb3(6, dib(1), data=b'reserved'), ftype=0x1B))
    f.append(frame(sb3(7, dib(2), data=b''), ftype=0x1B))
    # More conversations: same and different channel, control unit, device
    for chid, cuid, dev in ((1, 2, 0x0102), (3, 2, 0x0102), (1, 4, 0x0102), (1, 2, 0x0200), (0xff, 0xff, 0xffff)):
        f.append(frame(sb3(1, dib(2, 0, 4), chid=chid, cuid=cuid, dev=dev, ccw=0x00ff), ftype=0x1B))
        f.append(frame(sb3(2, dib(0, 0x0c, 0), chid=chid, cuid=cuid, dev=dev, ccw=0x00ff), ftype=0x1C, to_cu=False))
    return f

def main(out):
    ok = build()
    pcap(os.path.join(out, 'fcsb3-coverage.pcap'), ok)

    bad = []
    def raw(payload, ftype=0x1B):
        return frame(payload, ftype=ftype)
    full = sb3(3, bytes([0xd0]) + bytes(15), data=bytes(60))
    # FC-SB3 payload shorter than the SB-3 header, than the IU header, than the DIB
    for n in (4, 8, 12, 16, 20, 31):
        bad.append(raw(sb3(1, dib(1))[:n]))
    # per IU type, cut after the first DIB octets
    for t in (0, 2, 3, 4, 5):
        bad.append(raw(sb3(t, bytes([0x01, 0x41]))[:20]))
    # purge path response too short for the error code
    bad.append(raw(sb3(3, bytes([0xd0]) + bytes(15), data=bytes(20))))
    # TIR whose bit maps are cut short
    bad.append(raw(sb3(5, bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x20, 0, 0, 0, 0]), data=bytes(6))))
    # selective reset with a short parameter
    bad.append(raw(sb3(3, bytes([0x50, 0, 0]), pad_dib=False)))
    pcap(os.path.join(out, 'fcsb3-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

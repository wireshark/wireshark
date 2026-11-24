# Generates test/captures/fcoib_coverage.pcap.gz
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
# Generator for the FCoIB coverage captures.  Usage: mkfcoib.py <outdir>
# Writes fcoib-coverage.pcap (clean, Ethernet Infiniband) and
# fcoib-coverage-malformed.pcap.

SOFS = [0x28, 0x29, 0x2D, 0x2E, 0x31, 0x35, 0x36, 0x39]
EOFS = [0x41, 0x42, 0x44, 0x46, 0x49, 0x4E, 0x4F, 0x50]

def abts(oxid, extra=b''):
    return fchdr(0x81, A, B, 0x00, FIRST | SEQLAST, oxid) + extra

def fcoib_payload(fc, sof=0x2E, eof=0x42, ver=0, sig=1, crc=None, resv=b'\0\0\0', trailer=True):
    hdr = bytes([sig << 6, 0, ver << 4]) + bytes(12) + bytes([sof])
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    p = hdr + fc + struct.pack('<I', crc) + bytes([eof]) + resv
    return p

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ib_ud(payload, dqp=0x1234, sqp=0x4321):
    """RoCE v2 (UDP 4791) UD SEND_ONLY packet: BTH, DETH, payload, ICRC.
    The Infiniband dissector offers the payload to the FCoIB heuristic."""
    pad = (-len(payload)) % 4
    body = payload + bytes(pad)
    bth = bytes([0x64, pad << 4, 0xff, 0xff, 0, (dqp >> 16) & 0xff, (dqp >> 8) & 0xff, dqp & 0xff,
                 0, 0, 0, 1])
    deth = struct.pack('>I', 0x11111111) + bytes([0, (sqp >> 16) & 0xff, (sqp >> 8) & 0xff, sqp & 0xff])
    data = bth + deth + body + bytes(4)
    udp = struct.pack('>HHHH', 49152, 4791, 8 + len(data), 0) + data
    sip = bytes([192, 0, 2, 1]); dip = bytes([192, 0, 2, 2])
    ih = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, sip, dip)
    ih = ih[:10] + struct.pack('>H', ip_csum(ih)) + ih[12:]
    return eth(ih + udp, 0x0800)

def main(out):
    ok = []
    # 1-8: every SOF and EOF
    for i in range(8):
        ok.append(ib_ud(fcoib_payload(abts(0x100 + i), SOFS[i], EOFS[i])))
    # 9: version 1
    ok.append(ib_ud(fcoib_payload(abts(0x110), ver=1)))
    # 10: frame length not a multiple of 4: the IB padding follows the
    # trailer, so the heuristic rejects it (decoded with Decode As in runcov.sh)
    ok.append(ib_ud(fcoib_payload(abts(0x111, b'ab'))))
    # 11-14: rejected by the heuristic: wrong signature, non-zero reserved
    # octets after the EOF, unknown SOF, unknown EOF
    ok.append(ib_ud(fcoib_payload(abts(0x112), sig=2)))
    ok.append(ib_ud(fcoib_payload(abts(0x113), resv=b'\0\0\1')))
    ok.append(ib_ud(fcoib_payload(abts(0x114), sof=0x77)))
    ok.append(ib_ud(fcoib_payload(abts(0x115), eof=0x77)))
    # 15: too short to hold the header and trailer
    ok.append(ib_ud(bytes([0x40]) + bytes(20)))
    pcap(os.path.join(out, 'fcoib-coverage.pcap'), ok)

    bad = []
    # bad FC CRC
    bad.append(ib_ud(fcoib_payload(abts(0x200), crc=0x12345678)))
    # FC header cut short
    bad.append(ib_ud(fcoib_payload(abts(0x201)[:12])))
    pcap(os.path.join(out, 'fcoib-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

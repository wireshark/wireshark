# Generates test/captures/fclctl_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import zlib

def write_pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0,
          seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42):
    hdr = bytes(13) + bytes([sof])
    crc = struct.pack('<I', zlib.crc32(fc) & 0xffffffff)
    return eth(hdr + fc + crc + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
XFER = 0x010000

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp4(payload, sport, dport, seq=1000, ack=1, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    sip = bytes(int(x) for x in src.split('.'))
    dip = bytes(int(x) for x in dst.split('.'))
    th = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ph = sip + dip + struct.pack('>BBH', 0, 6, len(th) + len(payload))
    cs = ip_csum(ph + th + payload)
    th = th[:16] + struct.pack('>H', cs) + th[18:]
    tot = 20 + len(th) + len(payload)
    ih = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, 1, 0, 64, 6, 0, sip, dip)
    ih = ih[:10] + struct.pack('>H', ip_csum(ih)) + ih[12:]
    return eth(ih + th + payload, 0x0800)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
frames = []
ox = [0x100]

def lc(lctl, param=0, ftype=0, d=B, s=A):
    ox[0] += 1
    frames.append(fcoe(fchdr(0xC0 | lctl, d, s, ftype, LAST | SEQLAST, ox[0], 0x2000, param=param),
                       sof=0x2D, eof=0x42))

# ACK1, ACK0 (parameter is the history bits), LCR, NTY, END
lc(0x00, 0x80000001); lc(0x01, 0x80000000); lc(0x07); lc(0x08); lc(0x09)
# P_RJT / F_RJT: retryable, non-retryable, unknown action code, every reason
reasons = [1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF,0x10,0x11,0x12,0x13,0x14,
           0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1F,0x20,0x21,0x22,
           0x23,0x24,0xFF, 0x1E, 0x77]
for i, r in enumerate(reasons):
    acode = (1, 2, 1, 2, 0x55)[i % 5]
    lc(0x02 if i % 2 == 0 else 0x03, (acode << 24) | (r << 16))
# P_BSY: both action codes and every reason, plus unknown ones
for a, r in ((1, 1), (2, 3), (1, 7), (2, 0xFF), (9, 1), (1, 0x55)):
    lc(0x04, (a << 24) | (r << 16))
# F_BSY (data frame) and F_BSY (link ctl) with fabric busy, N_Port busy and an unknown reason
for t in (0x10, 0x30, 0x50):
    lc(0x05, 0, ftype=t)
    lc(0x06, 0, ftype=t | 0x08)
# reserved link control code 0xA..0xF
lc(0x0A); lc(0x0F)
write_pcap(out + '/fclctl-coverage.pcap', frames)

mal = [fcoe(fchdr(0xC2, B, A, 0, LAST, 1, param=0x01010000))[:14 + 14 + 10],
       fcoe(fchdr(0xC3, B, A, 0, LAST, 2, param=0x02130000))[:14 + 14 + 22]]
write_pcap(out + '/fclctl-coverage-malformed.pcap', mal)

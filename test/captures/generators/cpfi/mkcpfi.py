#!/usr/bin/env python3
# Generates test/captures/cpfi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CPFI dissector
(packet-cpfi.c, CNT Cross Point Frame Injector).

CPFI carries a Fibre Channel frame between an 8 octet header and an 8
octet footer. Its header word 1 holds the frame type (9 for CPFI), the
source and destination TDA, the SOF type, speed, OPM error and from-LCM
bits; the footer holds a CRC-32 and the EOF type.

The dissector registers on UDP ports 5000 and 5001, but it returns 0
unless pinfo->src and pinfo->dst are Ethernet addresses, which they never
are after IPv4 or IPv6. It is reached instead with the DLT_USER table:
User 0 (DLT 147) with a 14 octet "eth_withoutfcs" header (which sets the
Ethernet addresses) and "cpfi" as the payload dissector:

  -o 'uat:user_dlts:"User 0 (DLT=147)","cpfi","14","eth_withoutfcs","0",""'

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcpfi.py <output directory>

Writes:
  cpfi-coverage.pcapng            interface 0 (Ethernet): UDP/IPv4 to
                                  ports 5000 and 5001, not dissected as
                                  CPFI; interface 1 (DLT 147): CPFI
                                  frames carrying FC ELS, FCP and FC-CT,
                                  every SOF, speed, EOF type, TDAs on
                                  and off the TIO cards, both arrow
                                  directions, frames that are not CPFI
                                  (frame type, too short, footer cut off)
  cpfi-coverage-malformed.pcapng  CPFI frames shorter than the header
"""

import os
import struct
import sys

T0 = 1700000000

# Ethernet addresses: the third octet minus 1 is the "instance".
MAC_A = bytes.fromhex('020003000001')   # instance 2
MAC_B = bytes.fromhex('020006000002')   # instance 5


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    return struct.pack('<II', 0x0A0D0D0A, 8 + len(body) + 4) + body + struct.pack('<I', 8 + len(body) + 4)


def idb(linktype, snaplen=65535):
    body = struct.pack('<HHI', linktype, 0, snaplen)
    return struct.pack('<II', 1, 8 + len(body) + 4) + body + struct.pack('<I', 8 + len(body) + 4)


def epb(ifid, i, data, origlen=None):
    if origlen is None:
        origlen = len(data)
    ts = (T0 + i) * 1000000
    body = struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), origlen) + pad4(data)
    return struct.pack('<II', 6, 8 + len(body) + 4) + body + struct.pack('<I', 8 + len(body) + 4)


def pcapng(path, frames):
    """frames: list of (interface, data[, original length])."""
    with open(path, 'wb') as f:
        f.write(shb())
        f.write(idb(1))
        f.write(idb(147))
        for i, fr in enumerate(frames):
            f.write(epb(fr[0], i, *fr[1:]))


def ip_cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_ip(sport, dport, payload):
    src = bytes([192, 0, 2, 1])
    dst = bytes([192, 0, 2, 2])
    ulen = 8 + len(payload)
    ph = src + dst + struct.pack('>BBH', 0, 17, ulen)
    udp = struct.pack('>HHHH', sport, dport, ulen, 0) + payload
    ck = ip_cksum(ph + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', ck) + udp[8:]
    iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    iph = iph[:10] + struct.pack('>H', ip_cksum(iph)) + iph[12:]
    eth = MAC_B + MAC_A + struct.pack('>H', 0x0800)
    return eth + iph + udp


def eth_hdr(src=MAC_A, dst=MAC_B):
    # Local experimental ethertype: the 14 octet header has no payload.
    return dst + src + struct.pack('>H', 0x88B5)


def word1(frame_type, src_tda, dst_tda, sof, speed, opm, lcm):
    return ((frame_type << 28) | (src_tda << 18) | (dst_tda << 8) |
            (sof << 4) | (speed << 2) | (opm << 1) | lcm)


def fc_hdr(r_ctl, d_id, s_id, typ, f_ctl, seq_id, seq_cnt, ox_id, rx_id, param=0):
    return (struct.pack('>B', r_ctl) + d_id.to_bytes(3, 'big') +
            struct.pack('>B', 0) + s_id.to_bytes(3, 'big') +
            struct.pack('>B', typ) + f_ctl.to_bytes(3, 'big') +
            struct.pack('>BBHHHI', seq_id, 0, seq_cnt, ox_id, rx_id, param))


# FC frames carried in CPFI.
def fc_plogi(ox=0x1234):
    # ELS PLOGI request (R_CTL 0x22, type 1, first and last of sequence).
    pl = struct.pack('>B3x', 0x03)
    pl += bytes(112)                     # service parameters (all zero)
    return fc_hdr(0x22, 0xFFFFFC, 0x010200, 0x01, 0x290000, 1, 0, ox, 0xFFFF) + pl


def fc_els_acc(ox=0x1234):
    pl = struct.pack('>B3x', 0x02) + bytes(112)
    return fc_hdr(0x23, 0x010200, 0xFFFFFC, 0x01, 0x990000, 1, 0, ox, 0x0042) + pl


def fc_fcp_cmnd(ox=0x2000):
    # FCP_CMND: LUN, CRN, task attributes, management flags, add len /
    # rd/wr, CDB (TEST UNIT READY), DL.
    pl = bytes(8) + struct.pack('>BBBB', 0, 0, 0, 0) + bytes(16) + struct.pack('>I', 0)
    return fc_hdr(0x06, 0x010300, 0x010200, 0x08, 0x290000, 2, 0, ox, 0xFFFF) + pl


def fc_fcp_rsp(ox=0x2000):
    pl = bytes(8) + struct.pack('>HBB', 0, 0, 0) + struct.pack('>III', 0, 0, 0)
    return fc_hdr(0x07, 0x010200, 0x010300, 0x08, 0x990000, 3, 0, ox, 0x0050) + pl


def fc_ct(ox=0x3000):
    # FC-CT GID_FT request to the directory server.
    ct = struct.pack('>B3sBBBBHHBBBB', 1, b'\0\0\0', 0xFC, 0x02, 0, 0, 0x0171, 0, 0, 0, 0, 0)
    ct += struct.pack('>I', 0x00000008)
    return fc_hdr(0x02, 0xFFFFFC, 0x010200, 0x20, 0x290000, 4, 0, ox, 0xFFFF) + ct


def cpfi(w1, fc, w2=0x00000000, crc=0x12345678, eof_type=0):
    return (struct.pack('>II', w1, w2) + fc +
            struct.pack('>II', crc, eof_type << 27))


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    u = []
    # Interface 0: CPFI on UDP/IPv4 ports 5000 and 5001 is not dissected
    # (the addresses are IPv4).
    pkt = cpfi(word1(9, 0x011, 0x022, 6, 1, 0, 0), fc_plogi())
    u.append((0, udp_ip(40000, 5000, pkt)))
    u.append((0, udp_ip(40001, 5001, pkt)))

    E = eth_hdr()
    R = eth_hdr(MAC_B, MAC_A)
    # Interface 1 (DLT 147): Ethernet header plus CPFI.
    # 3: PLOGI from 2.1.1 to 5.2.2 (dstTDA is the source of the frame):
    #    SOFi3, 2 GBIT, the arrow points right.
    u.append((1, E + cpfi(word1(9, 0x022, 0x011, 3, 1, 0, 0), fc_plogi(), w2=0xA5A5A5A5, eof_type=1)))
    # 4: LS_ACC back, SOFn3, 4 GBIT, OPM error, from LCM, EOFt; the
    #    destination is lower, so the arrow moves to point left.
    u.append((1, R + cpfi(word1(9, 0x011, 0x022, 4, 2, 1, 1), fc_els_acc(), eof_type=1)))
    # 5: FCP_CMND from a TIO card (dstTDA >= 0x380, " CPFI") to 2.3.4,
    #    SOFi2, 10 GBIT, EOFn.
    u.append((1, E + cpfi(word1(9, 0x034, 0x380, 1, 3, 0, 0), fc_fcp_cmnd(), eof_type=0)))
    # 6: FCP_RSP from 2.3.4 to a TIO card (srcTDA 0x3FF), SOFn2, EOFni.
    u.append((1, E + cpfi(word1(9, 0x3FF, 0x034, 2, 0, 0, 0), fc_fcp_rsp(), eof_type=2)))
    # 7: TIO card to TIO card, SOFf, EOFa.
    u.append((1, E + cpfi(word1(9, 0x381, 0x3FE, 0, 0, 0, 0), fc_ct(), eof_type=3)))
    # 8-15: the other SOF types (and one unknown, 15) with EOFdt, EOFdti,
    #    EOFrt, EOFrti and unknown EOF types 8 and 15.
    eofs = [4, 5, 6, 7, 8, 15, 0, 1]
    for k, sof in enumerate([5, 6, 7, 8, 9, 10, 11, 15]):
        src, dst = (0x045, 0x056) if (k + 1) % 2 else (0x056, 0x045)
        u.append((1, (E if (k + 1) % 2 else R) +
                  cpfi(word1(9, src, dst, sof, k & 3, k & 1, (k >> 1) & 1),
                       fc_fcp_cmnd(0x2100 + k // 2) if (k + 1) % 2 else fc_fcp_rsp(0x2100 + k // 2),
                       w2=k, crc=0xDEAD0000 + k, eof_type=eofs[k])))
    # 16: frame type 8 is not CPFI: the payload goes to "data".
    u.append((1, E + cpfi(word1(8, 0x011, 0x022, 6, 0, 0, 0), fc_plogi(0x1236))))
    # 17: only 15 octets after the header (less than a footer): not CPFI.
    u.append((1, E + struct.pack('>II', word1(9, 0x011, 0x022, 6, 0, 0, 0), 0) + bytes(7)))
    # 18: the frame is cut by the snapshot length before the footer:
    #     not CPFI (the footer was not captured).
    full = E + cpfi(word1(9, 0x011, 0x022, 6, 0, 0, 0), fc_plogi(0x1235))
    u.append((1, full[:14 + 8 + 30], len(full)))
    pcapng(os.path.join(outdir, 'cpfi-coverage.pcapng'), u)

    m = []
    # 1: CPFI header only, 4 octets: the frame type read throws.
    m.append((1, E + struct.pack('>H', 0x9000)))
    # 2: header and footer with no FC frame in between.
    m.append((1, E + cpfi(word1(9, 0x011, 0x022, 6, 0, 0, 0), b'')))
    # 3: FC frame cut short (8 octets of FC header).
    m.append((1, E + cpfi(word1(9, 0x011, 0x022, 6, 0, 0, 0), fc_plogi()[:8])))
    pcapng(os.path.join(outdir, 'cpfi-coverage-malformed.pcapng'), m)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

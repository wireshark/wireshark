#!/usr/bin/env python3
# Generates test/captures/mdshdr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the MDS Header dissector
(packet-mdshdr.c: Cisco MDS internal FC frame header and trailer).

MDS Header is registered for ethertype 0xFCFC, and (preference
mdshdr.decode_if_etype_zero, off by default) for ethertype 0.  Every
packet is built with struct; nothing comes from a real network.

Usage: mkmdshdr.py <output directory>
  mdshdr-coverage.pcap            every SOF and EOF value, header fields,
                                  frames without a trailer, trailing data
  mdshdr-coverage-malformed.pcap  headers cut short
  mdshdr-etype0.pcap              GRE frames with protocol type 0
                                  (only decoded with the preference)
"""
import os
import struct
import sys

A = bytes.fromhex('0e fc 00 00 00 01'.replace(' ', ''))
B = bytes.fromhex('0efc00000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, etype=0xFCFC):
    return B + A + struct.pack('>H', etype) + payload


def fc_abts(oxid=0x1234, did=0x010203, sid=0x040506):
    """FC header of an ABTS basic link service (no payload)."""
    return (struct.pack('>B', 0x81) + did.to_bytes(3, 'big') + b'\x00' +
            sid.to_bytes(3, 'big') + b'\x00' + (0x090000).to_bytes(3, 'big') +
            struct.pack('>BBHHHI', 0, 0, 0, oxid, 0xffff, 0))


def fc_els(oxid=0x2222):
    """FC header + a 4 octet ELS request (ECHO)."""
    return (struct.pack('>B', 0x22) + (0x010203).to_bytes(3, 'big') + b'\x00' +
            (0x040506).to_bytes(3, 'big') + b'\x01' + (0x380000).to_bytes(3, 'big') +
            struct.pack('>BBHHHI', 0, 0, 0, oxid, 0xffff, 0) + b'\x10\x00\x00\x00')


def mds(sof, payload, pktlen=None, eof=0x03, vsan=0x0050, didx=0x0123,
        sidx=0x0045, span=0, ver=0, crc=0x11223344, trailer=True, extra=b'',
        ctl=0):
    """MDS header (16 octets) + FC frame + 6 octet trailer."""
    trl = struct.pack('>BBI', eof, 0, crc) if trailer else b''
    if pktlen is None:
        pktlen = len(payload) + len(trl)
    hdr = bytearray(16)
    hdr[0] = ver
    hdr[1] = (ctl << 4) | (sof & 0xF)
    struct.pack_into('>H', hdr, 2, 0x0000 | (pktlen & 0x1FFF))
    struct.pack_into('>H', hdr, 5, (didx << 2) & 0x0FFC)
    struct.pack_into('>H', hdr, 6, sidx & 0x03FF)
    struct.pack_into('>H', hdr, 13, ((span & 0xF) << 12) | (vsan & 0x0FFF))
    return bytes(hdr) + payload + trl + extra


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    main_frames = []
    # 1-11: every SOF value (SOFc1, i1, n1, i2, n2, i3, n3, f, c4, i4, n4)
    for sof in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
        main_frames.append(eth(mds(sof, fc_abts(oxid=0x100 + sof))))
    # 12-13: unknown SOF values
    main_frames.append(eth(mds(0, fc_abts(oxid=0x200))))
    main_frames.append(eth(mds(12, fc_abts(oxid=0x201))))
    # 14-22: every EOF value (t, dt, a, n, dti, ni, rt, rti) and unknown
    for i, eof in enumerate((1, 2, 4, 3, 6, 7, 0xa, 0xe, 0xb)):
        main_frames.append(eth(mds(2, fc_abts(oxid=0x300 + i), eof=eof)))
    # 23: unknown EOF (0x5), trailer present
    main_frames.append(eth(mds(2, fc_abts(oxid=0x310), eof=5)))
    # 24-27: header fields: VSAN, SPAN bits, indexes, version, ctl
    main_frames.append(eth(mds(2, fc_abts(oxid=0x400), vsan=0xfff, didx=0x3ff, sidx=0x3ff)))
    main_frames.append(eth(mds(2, fc_abts(oxid=0x401), vsan=1, didx=0, sidx=0)))
    main_frames.append(eth(mds(2, fc_abts(oxid=0x402), span=0xf, vsan=0x123)))
    main_frames.append(eth(mds(2, fc_abts(oxid=0x403), ver=0, ctl=7)))
    # 28: an ELS frame with payload inside
    main_frames.append(eth(mds(0x8, fc_els())))
    # 29-30: trailing data after the MDS frame (not part of pktlen)
    main_frames.append(eth(mds(2, fc_abts(oxid=0x500), extra=b'\xde\xad\xbe\xef' * 4)))
    main_frames.append(eth(mds(3, fc_els(oxid=0x501), extra=b'\xaa' * 30)))
    # 31: pktlen 0 ("something wrong"): the whole rest goes to FC, no trailer
    main_frames.append(eth(mds(2, fc_abts(oxid=0x602) + b'\x00' * 6, pktlen=0, trailer=False)))
    # 32: pktlen larger than the frame: no trailer, the rest goes to FC
    main_frames.append(eth(mds(2, fc_abts(oxid=0x603) + b'\x00' * 6, pktlen=500, trailer=False)))
    # 33: Ethernet padding after the frame (reported length trimmed by pktlen)
    main_frames.append(eth(mds(2, fc_abts(oxid=0x604))) + b'\x00' * 20)
    # 34: a frame inside 802.1Q
    main_frames.append(B + A + struct.pack('>HHH', 0x8100, 0x0032, 0xFCFC) +
                       mds(2, fc_abts(oxid=0x700)))
    pcap(os.path.join(out, 'mdshdr-coverage.pcap'), main_frames)

    bad = []
    # truncated: 3 octets of MDS header (the SOF is read, the packet length is not)
    bad.append(eth(b'\x00\x02\x00'))
    # 1 octet
    bad.append(eth(b'\x00'))
    # header present but cut short (no FC header)
    bad.append(eth(mds(2, b'', pktlen=6, trailer=True)[:10]))
    # pktlen reaches the end but the FC header is cut short
    bad.append(eth(mds(2, fc_abts()[:10], trailer=True)))
    # FC frame cut short without trailer
    bad.append(eth(mds(2, fc_abts()[:12], pktlen=0, trailer=False)))
    # header, no FC data at all, pktlen 0
    bad.append(eth(mds(2, b'', pktlen=0, trailer=False)))
    # pktlen shorter than the trailer: no trailer, FC sees 4 or 5 octets
    bad.append(eth(mds(2, fc_abts(oxid=0x600), pktlen=4, trailer=False)))
    bad.append(eth(mds(2, fc_abts(oxid=0x601), pktlen=5, trailer=False)))
    # pktlen exactly the trailer size: trailer but no FC data
    bad.append(eth(mds(2, b'', trailer=True)))
    pcap(os.path.join(out, 'mdshdr-coverage-malformed.pcap'), bad)

    # GRE (protocol type 0, no flags) in IPv4: ethertype 0 dissector table
    z = []
    for sof in (2, 8):
        gre = struct.pack('>HH', 0, 0) + mds(sof, fc_abts(oxid=0x800 + sof))
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(gre), 1, 0, 64, 47, 0,
                         bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        z.append(eth(ip + gre, etype=0x0800))
    pcap(os.path.join(out, 'mdshdr-etype0.pcap'), z)


main()

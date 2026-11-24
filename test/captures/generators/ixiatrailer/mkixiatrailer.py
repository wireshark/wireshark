#!/usr/bin/env python3
# Generates test/captures/ixiatrailer_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Ixia Trailer coverage captures (synthetic, struct only).

Usage: mkixiatrailer.py <outdir>

  ixiatrailer-coverage.pcap            valid frames, decodes without errors
  ixiatrailer-coverage-malformed.pcap  invalid TLV lengths, truncated
                                       trailer, bad checksum
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(l4, proto=17, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + l4


def udp_frame(payload, trailer=b'', sport=1000, dport=2000):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return CMAC + SMAC + b'\x08\x00' + ipv4(u) + trailer


def tlv(t, v):
    return bytes([t, len(v)]) + v


def trailer(tlvs, good=True, plen=None, sig=0xaf12):
    """TLVs + length byte + signature + checksum."""
    body = tlvs + bytes([len(tlvs) if plen is None else plen]) + struct.pack('!H', sig)
    c = csum(body)
    if not good:
        c ^= 0x1234
    return body + struct.pack('!H', c)


def ts(sec, nsec):
    return struct.pack('!II', sec, nsec)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (p, caplen) in enumerate(frames):
            cl = len(p) if caplen is None else caplen
            f.write(struct.pack('<IIII', 1700000000 + i, 0, cl, len(p)))
            f.write(p[:cl])


def main(out):
    osz = tlv(1, struct.pack('!H', 1514))
    main_frames = []

    def add(p):
        main_frames.append((p, None))

    # 1: original packet size only (the minimum 9 byte trailer)
    add(udp_frame(b'ixia 01', trailer(osz)))
    # 2-7: every timestamp type, with the original packet size
    for n, t in enumerate((3, 4, 5, 6, 7, 8)):
        add(udp_frame(b'ixia ts%d' % t, trailer(osz + tlv(t, ts(1700000000 + n, 123456789 + n)))))
    # 8: two timestamps, unknown types shown as generic fields
    add(udp_frame(b'ixia generic', trailer(
        tlv(2, b'\x01\x02\x03') + tlv(9, b'') + tlv(0x20, b'abcdefgh') + osz
        + tlv(3, ts(1700000010, 5)) + tlv(6, ts(1700000011, 999999999)))))
    # 9: trailer followed by 4 bytes taken as an FCS (matched_with_fcs)
    add(udp_frame(b'ixia fcs', trailer(osz) + b'\xde\xad\xbe\xef'))
    # 10: 19 byte trailer followed by 4 bytes: the 23 byte special case
    add(udp_frame(b'ixia 23', trailer(osz + tlv(0x30, b'12345678')) + b'\x01\x02\x03\x04'))
    # 11: 19 byte trailer alone (not the 23 byte case, same trailer)
    add(udp_frame(b'ixia 19', trailer(osz + tlv(0x30, b'12345678'))))
    # 12: a long trailer (many TLVs, 252 bytes)
    tl = b''
    while len(tl) < 240:
        tl += tlv(0x40, bytes(range(8)))
    tl += tlv(1, struct.pack('!H', 64))
    add(udp_frame(b'ixia long', trailer(tl)))
    # 13: trailer with the maximum value length TLV
    add(udp_frame(b'ixia maxval', trailer(tlv(0x41, bytes(range(200))) + osz)))
    # Frames that are not Ixia trailers (the heuristic returns 0):
    # 14: short padding (less than 9 bytes of trailer)
    add(udp_frame(b'pad', b'\0' * 6))
    # 15: trailer without the 0xAF12 signature
    add(udp_frame(b'no sig', trailer(osz, sig=0xaf13)))
    # 16: signature but wrong length byte
    add(udp_frame(b'bad len', trailer(osz, plen=5)))
    # 17: signature and length but bad checksum
    add(udp_frame(b'bad sum', trailer(osz, good=False)))
    # 18: 13 or more bytes of other data without the signature
    add(udp_frame(b'junk', bytes(range(20))))
    # 19: FCS-sized trailer but the signature is not where an FCS trailer would have it
    add(udp_frame(b'junk2', b'\xaf\x12' + bytes(10)))
    pcap(os.path.join(out, 'ixiatrailer-coverage.pcap'), main_frames)

    mal = []
    # field length invalid for the original packet size (3, not 2)
    mal.append((udp_frame(b'm1', trailer(tlv(1, b'\x05\xea\x00') + tlv(1, struct.pack('!H', 60)))), None))
    # field length invalid for a timestamp (4, not 8)
    mal.append((udp_frame(b'm2', trailer(tlv(5, b'\1\2\3\4') + tlv(1, struct.pack('!H', 60)))), None))
    # TLV value runs past the end of the trailer: valid checksum but bounds exception
    mal.append((udp_frame(b'm3', trailer(tlv(1, struct.pack('!H', 60)) + bytes([0x50, 0xf0, 0x00]))), None))
    # a trailer cut by the snap length: heuristic must give up
    p = udp_frame(b'm4', trailer(tlv(1, struct.pack('!H', 60))))
    mal.append((p, len(p) - 3))
    pcap(os.path.join(out, 'ixiatrailer-coverage-malformed.pcap'), mal)


if __name__ == '__main__':
    main(sys.argv[1])

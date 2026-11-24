#!/usr/bin/env python3
# Generates test/captures/tapa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TAPA (Trapeze Access Point Access
Protocol) dissector (packet-tapa.c).

TAPA discovery runs over UDP port 5000: requests (serial number and model
items), replies (switch address), and the "new" TLV variants; unknown
discovery types are shown as raw bytes. Tunnel packets (types 0 and 1)
are reached over UDP port 5000 as well when the length at offset 2 is 0,
and over IP protocol 4 through the heuristic dissector (only when the IP
preference "try heuristic first" is set).

Usage: mktapa.py <output directory>

Writes:
  tapa-coverage.pcap            discovery requests/replies (old and new
                                TLV forms), unknown type, tunnel types 0
                                and 1, the TLV value offset reproducer
  tapa-coverage-malformed.pcap  TLVs with a length of 4 or less, cut
                                items, IP protocol 4 frames for the
                                heuristic (preference needed)
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def disc(typ, body, flags=0, length=None):
    if length is None:
        length = 4 + len(body)
    return struct.pack('>BBH', typ, flags, length) + body


def req_item(typ, val, pad=0):
    return struct.pack('>BBH', typ, pad, len(val)) + val


def new_tlv(typ, val, pad=0, length=None):
    if length is None:
        length = 4 + len(val)
    return struct.pack('>BBH', typ, pad, length) + val


def tunnel(typ, rest, b0=0x25, dmac=MAC_B, smac=MAC_A):
    return struct.pack('>BB', b0, typ) + bytes(8) + dmac + smac + rest


def main_frames():
    F = []
    U = lambda p, rev=False: udp(5000, 5000, p, rev=rev)
    # 1: request for the serial number
    F.append(U(disc(1, req_item(1, b'SN12345678'), flags=0x80)))
    # 2: request with serial number and model items
    F.append(U(disc(1, req_item(1, b'SN12345678') + req_item(2, b'MP-241', pad=3))))
    # 3: request with a model item and an unknown item type 9 (not text)
    F.append(U(disc(1, req_item(2, b'AP-9') + req_item(9, b'abcd'))))
    # 4: reply with the switch address, bias and padding
    F.append(U(disc(2, bytes([192, 0, 2, 77]) + bytes([7, 3]) + bytes(8)), rev=True))
    # 5: reply with the smallest padding (length 12)
    F.append(U(disc(2, bytes([198, 51, 100, 1]) + bytes([0, 0]) + bytes(2)), rev=True))
    # 6: new request with one text TLV and padding at the end
    F.append(U(disc(4, new_tlv(1, b'MP-432') + new_tlv(2, b'serial\x00' + b'Z')
                    + b'\0\0\0')))
    # 7: new request with a binary TLV (not ASCII)
    F.append(U(disc(4, new_tlv(3, b'\x00\x01\x02\xfe\xff') + new_tlv(7, b'ok'))))
    # 8: new reply with several TLVs
    F.append(U(disc(5, new_tlv(1, b'192.0.2.9') + new_tlv(5, b'x' * 20)
                    + new_tlv(6, b'\x80\x81')), rev=True))
    # 9: reproducer of the TLV value offset fix: the text value "HELLO"
    #    followed by a TLV with binary data (the text was checked 4 octets
    #    too far, in the next TLV header, and shown as BINARY-DATA)
    F.append(U(disc(4, new_tlv(1, b'HELLO') + new_tlv(3, b'\x01\x02\x03\x04'))))
    # 10: discovery with unknown type 3
    F.append(U(disc(3, b'\x01\x02\x03\x04\x05\x06\x07\x08'), rev=True))
    # 11: tunnel type 0 (0804, tags/seqno/pad), version 2
    F.append(U(tunnel(0, bytes.fromhex('0804') + bytes([1, 2, 3, 4, 5, 6]) + b'tunnel payload 0')))
    # 12: tunnel type 1 (seqno and length), version 3
    F.append(U(tunnel(1, struct.pack('>HH', 77, 20) + b'tunnel payload 1', b0=0x35)))
    # 13: tunnel type 1 without any data after the header
    F.append(U(tunnel(1, struct.pack('>HH', 1, 0), b0=0x05)))
    # 14: payload that is neither discovery nor tunnel (type 0x45)
    F.append(U(b'\x45\x00\x00\x30' + bytes(8)))
    # 15: too short for any test
    F.append(U(b'\x01\x00'))
    # 16: type 1 request with a bad item type at offset 4 (rejected, then
    #     not a tunnel because of the length)
    F.append(U(disc(1, req_item(5, b'abcdefgh'))))
    # 17: length above 1472 (rejected)
    F.append(U(disc(1, req_item(1, b'xy'), length=1500)))
    return F


def malformed_frames():
    F = []
    U = lambda p: udp(5000, 5000, p)
    # 1: new request: a TLV with length 4 (value length 0) -> expert
    F.append(U(disc(4, new_tlv(1, b'', length=4) + b'\0' * 8)))
    # 2: new request: TLV length below 4 (negative value length)
    F.append(U(disc(4, new_tlv(1, b'', length=2) + b'\0' * 8)))
    # 3: request whose item length runs past the end of the frame
    F.append(U(disc(1, struct.pack('>BBH', 1, 0, 200) + b'short')))
    # 4: request item with remaining that ends in the middle of a header
    F.append(U(disc(1, req_item(1, b'abc') + b'\x01\x00', length=14)))
    # 5: reply shorter than the fixed part
    F.append(U(disc(2, bytes([1, 2, 3, 4]) + bytes([0, 0]) + bytes(2))[:9]))
    # 6: tunnel cut inside the MAC addresses
    F.append(U(tunnel(0, b'')[:14]))
    # 7: tunnel type 0 cut after the MAC addresses
    F.append(U(tunnel(0, b'')))
    # 8-11: IP protocol 4 frames (heuristic, needs the IP preference "try
    #       heuristic first"); by default they are dissected as IP-in-IP
    F.append(eth(ip4(4, tunnel(0, bytes.fromhex('0804') + bytes(6) + b'ip tunnel'))))
    F.append(eth(ip4(4, tunnel(1, struct.pack('>HH', 5, 6) + b'ip tunnel'))))
    F.append(eth(ip4(4, b'\x45\x00\x00\x14' + bytes(16))))
    F.append(eth(ip4(4, b'\x01\x00')))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'tapa-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'tapa-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

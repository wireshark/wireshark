#!/usr/bin/env python3
# Generates test/captures/babel_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Babel dissector (packet-babel.c).

Babel Routing Protocol (RFC 8966, RFC 6126), UDP port 6696. Every packet
is built from scratch with struct over Ethernet / IPv6 / UDP between
link-local addresses; no captured traffic is used. Payloads larger than
64 KiB are carried in IPv6 jumbograms (RFC 2675).

Usage: mkbabel.py <output directory>

Writes:
  babel-coverage.pcap            every message type and address encoding,
                                 sub-TLVs, Hello flags, packet trailers
                                 (one longer than 255 octets) and two
                                 jumbograms with sub-TLVs past 64 KiB
  babel-coverage-malformed.pcap  invalid prefixes and address encodings,
                                 truncated messages and sub-TLVs, wrong
                                 magic and version, short packets
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_MC = bytes.fromhex('333300010006')
LL_A = bytes.fromhex('fe800000000000000000000000000001')
LL_B = bytes.fromhex('fe800000000000000000000000000002')
MC = bytes.fromhex('ff020000000000000000000000010006')
PORT = 6696


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def udp6(data, src=LL_A, dst=MC, sport=PORT, dport=PORT):
    """Ethernet / IPv6 / UDP. Above 65527 octets of data the datagram is a
    jumbogram: Hop-by-Hop Jumbo Payload option, IPv6 payload length 0 and
    UDP length 0 (RFC 2675)."""
    ulen = 8 + len(data)
    jumbo = ulen > 0xffff
    hdr = struct.pack('>HHHH', sport, dport, 0 if jumbo else ulen, 0)
    pseudo = src + dst + struct.pack('>IxxxB', ulen, 17)
    c = csum(pseudo + hdr + data) or 0xffff
    seg = hdr[:6] + struct.pack('>H', c) + data
    if jumbo:
        hbh = struct.pack('>BBBBI', 17, 0, 0xC2, 4, len(seg) + 8)
        ip = struct.pack('>IHBB', 0x60000000, 0, 0, 1) + src + dst + hbh + seg
    else:
        ip = struct.pack('>IHBB', 0x60000000, len(seg), 17, 1) + src + dst + seg
    dmac = MAC_MC if dst[0] == 0xff else bytes.fromhex('020000000002')
    return dmac + MAC_A + struct.pack('>H', 0x86DD) + ip


# Babel ----------------------------------------------------------------------

def packet(body, trailer=b'', magic=42, version=2, bodylen=None):
    if bodylen is None:
        bodylen = len(body)
    return struct.pack('>BBH', magic, version, bodylen) + body + trailer


def tlv(t, v=b''):
    return struct.pack('>BB', t, len(v)) + v


PAD1 = b'\x00'


def padn(n):
    return tlv(1, b'\0' * n)


def ack_req(nonce, interval):
    return tlv(2, struct.pack('>HHH', 0, nonce, interval))


def ack(nonce):
    return tlv(3, struct.pack('>H', nonce))


def hello(flags, seqno, interval, subtlvs=b''):
    return tlv(4, struct.pack('>HHH', flags, seqno, interval) + subtlvs)


def ihu(ae, rxcost, interval, addr=b'', subtlvs=b''):
    return tlv(5, struct.pack('>BBHH', ae, 0, rxcost, interval) + addr + subtlvs)


def router_id(rid):
    return tlv(6, b'\0\0' + rid)


def nh(ae, addr):
    return tlv(7, struct.pack('>BB', ae, 0) + addr)


def update(ae, flags, plen, omitted, interval, seqno, metric, prefix=b'', subtlvs=b''):
    return tlv(8, struct.pack('>BBBBHHH', ae, flags, plen, omitted, interval, seqno, metric)
               + prefix + subtlvs)


def request(ae, plen, prefix=b''):
    return tlv(9, struct.pack('>BB', ae, plen) + prefix)


def mh_request(ae, plen, seqno, hopcount, rid, prefix=b''):
    return tlv(10, struct.pack('>BBHBB', ae, plen, seqno, hopcount, 0) + rid + prefix)


def pc(index, nonce=b''):
    return tlv(17, struct.pack('>I', index) + nonce)


def mac(m):
    return tlv(16, m)


# sub-TLVs
SUB_PAD1 = b'\x00'


def sub(t, v=b''):
    return struct.pack('>BB', t, len(v)) + v


def sub_ts_hello(t):
    return sub(3, struct.pack('>I', t))


def sub_ts_ihu(t1, t2):
    return sub(3, struct.pack('>II', t1, t2))


def sub_diversity(*channels):
    return sub(2, bytes(channels))


RID1 = bytes.fromhex('0200000000000001')
RID2 = bytes.fromhex('0200000000000002')
V4_A = bytes([192, 0, 2, 1])
V6_A = bytes.fromhex('20010db8000000010000000000000001')
LL_IID = bytes.fromhex('0000000000000002')


# pcap writer ----------------------------------------------------------------

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def subtlv_u16_wrap_payload():
    """The Babel packet of babel_subtlv_u16_wrap.py: 65535
    octets of body ending with a Hello at offset 65526 whose PadN sub-TLV
    starts at 65534. Before the fix the sub-TLV offsets were 16 bit and the
    chain of PadN messages before it was walked again as sub-TLVs, forever
    (until the tree item limit)."""
    body = b''
    for _ in range(254):
        body += bytes([1, 255]) + b'\0' * 253 + bytes([1, 255])
    body += bytes([1, 242]) + b'\0' * 242
    assert 4 + len(body) == 65526
    body += bytes([4, 7, 0, 0, 0, 1, 0, 100]) + bytes([1])
    body += bytes([100, 2, 0, 0])
    return packet(body)


def big_payload():
    """A 65535 octet body ending with a Hello at offset 65528 whose
    diversity sub-TLV starts at 65536 (channel 7 at 65538), followed by a
    trailer holding a Hello with a timestamp sub-TLV at 65547 and a PC."""
    fill = 65528 - 4
    body = b''
    while fill > 257:
        body += padn(255)
        fill -= 257
    body += padn(fill - 2)
    body += hello(0x8000, 0x4242, 400, sub_diversity(7))
    assert 4 + len(body) == 65539
    trailer = hello(0, 0x4343, 500, sub_ts_hello(123456789)) + pc(77)
    return packet(body, trailer)


def main_frames():
    F = []
    # 1: multicast Hello, flags 0
    F.append(udp6(packet(hello(0x0000, 0x0001, 400))))
    # 2: unicast Hello (U flag 0x8000) to a link-local address
    F.append(udp6(packet(hello(0x8000, 0x0002, 0)), dst=LL_B))
    # 3: Hello with the other flag bits set but not U, and a timestamp
    # sub-TLV (RFC 9616)
    F.append(udp6(packet(hello(0x7fff, 0x0003, 400, sub_ts_hello(1234567890)))))
    # 4: Hello with sub-pad1, sub-padn, diversity (3 channels), an unknown
    # sub-TLV and an unknown mandatory one (type 0x85)
    F.append(udp6(packet(hello(0x8000, 0x0004, 400,
                               SUB_PAD1 + sub(1, b'\0\0') + sub_diversity(1, 6, 11)
                               + sub(9, b'xyz') + sub(0x85, b'\x01\x02')))))
    # 5: IHU, every address encoding: wildcard, IPv4, IPv6, link-local
    F.append(udp6(packet(ihu(0, 96, 1200) + ihu(1, 256, 1200, V4_A)
                         + ihu(2, 0xffff, 1200, V6_A) + ihu(3, 96, 1200, LL_IID))))
    # 6: IHU with a timestamp sub-TLV (origin and receive), followed by a
    # Hello (the dissector reads the receive timestamp subtree 4 octets past
    # the sub-TLV, see README) and an IHU with a link-local address and a
    # timestamp
    F.append(udp6(packet(ihu(3, 96, 1200, LL_IID, sub_ts_ihu(1000000, 2500000))
                         + hello(0, 6, 400) + ihu(0, 96, 1200, b'', sub_ts_ihu(3, 4))
                         + PAD1 * 4)))
    # 7: Router-ID, NH IPv4/IPv6/link-local
    F.append(udp6(packet(router_id(RID1) + nh(1, V4_A) + nh(2, V6_A) + nh(3, LL_IID))))
    # 8: Update IPv4: flag 0x80 sets the default prefix, the next update
    # omits 3 octets of it; wildcard retraction (AE 0)
    F.append(udp6(packet(router_id(RID1)
                         + update(1, 0x80, 24, 0, 400, 1, 96, bytes([198, 51, 100]))
                         + update(1, 0x40, 32, 3, 400, 1, 128, bytes([7]))
                         + update(0, 0, 0, 0, 400, 2, 0xffff))))
    # 9: Update IPv6 with default prefix and omitted octets, link-local,
    # update with a diversity and a timestamp ("Bogus") sub-TLV
    F.append(udp6(packet(router_id(RID2)
                         + update(2, 0x80, 64, 0, 400, 3, 96, V6_A[:8])
                         + update(2, 0xc0, 128, 8, 400, 3, 192, V6_A[8:])
                         + update(3, 0, 128, 0, 400, 4, 256, LL_IID)
                         + update(1, 0, 16, 0, 400, 5, 96, bytes([10, 1]),
                                  sub_diversity(2, 3) + sub_ts_hello(5) + SUB_PAD1))))
    # 10: Requests: wildcard, IPv4, IPv6, link-local, full-length IPv6
    F.append(udp6(packet(request(0, 0) + request(1, 24, bytes([198, 51, 100]))
                         + request(2, 48, V6_A[:6]) + request(3, 128, LL_IID)
                         + request(2, 128, V6_A)), dst=LL_B))
    # 11: Seqno (multi-hop) requests IPv4 and IPv6
    F.append(udp6(packet(mh_request(1, 32, 0x1234, 63, RID1, V4_A)
                         + mh_request(2, 64, 0x1235, 2, RID2, V6_A[:8]))))
    # 12: ack-req, ack, padn, pad1
    F.append(udp6(packet(ack_req(0xbeef, 300) + ack(0xbeef) + padn(5) + PAD1 + PAD1)))
    # 13: the other message types, shown by name only: ts/pc, old hmac,
    # source-specific update/request/seqno, challenge request/reply, an
    # unknown type
    F.append(udp6(packet(tlv(11, b'\0' * 6) + tlv(12, b'\0' * 22)
                         + tlv(13, b'\x01\x00\x18\x00\x00\x00\x01\x90\x00\x01\x00\x60'
                                   b'\x00\x00\x00\x00\x00\x00')
                         + tlv(14, b'\0' * 4) + tlv(15, b'\0' * 14)
                         + tlv(18, b'\x01\x02\x03\x04\x05\x06\x07\x08')
                         + tlv(19, b'\x01\x02\x03\x04\x05\x06\x07\x08')
                         + tlv(200, b'unknown'))))
    # 14: a Hello and a trailer with PC and MAC (RFC 8967)
    F.append(udp6(packet(hello(0, 14, 400), pc(1000, b'\x11' * 4) + mac(b'\xaa' * 32))))
    # 15: trailer longer than 255 octets (298): PC, a 255 octet padn,
    # pad1, a 32 octet MAC
    F.append(udp6(packet(hello(0x8000, 15, 400),
                         pc(4000000000) + padn(255) + PAD1 + mac(b'\xbb' * 32)), dst=LL_B))
    # 16: empty body, the whole payload is the trailer
    F.append(udp6(packet(b'', pc(16) + mac(b'\xcc' * 16))))
    # 17: PC in the body (index)
    F.append(udp6(packet(pc(17, b'\x01\x02') + PAD1 * 2)))
    # 18: the reproducer of babel_subtlv_u16_wrap.py, as an IPv6
    # jumbogram (the reproducer itself is an Exported PDU)
    F.append(udp6(subtlv_u16_wrap_payload()))
    # 19: a jumbogram with a diversity sub-TLV past 64 KiB and a trailer
    # Hello with a timestamp past 64 KiB
    F.append(udp6(big_payload()))
    return F


def malformed_frames():
    F = []
    # 1: version 3 (only "Version 3" in Info)
    F.append(udp6(packet(hello(0, 1, 400), version=3)))
    # 2: wrong magic: not Babel, left to data
    F.append(udp6(packet(hello(0, 1, 400), magic=43)))
    # 3: shorter than the header
    F.append(udp6(b'\x2a\x02'))
    # 4: invalid prefixes and addresses: IPv4 omitted > 4, IPv4 plen > 32,
    # IPv4 prefix shorter than plen, IPv6 omitted > 16, IPv6 too short,
    # link-local too short, plen > 128, AE 4 in NH and IHU and Request
    F.append(udp6(packet(update(1, 0, 24, 5, 400, 1, 96, b'\x01\x02\x03')
                         + update(1, 0, 40, 0, 400, 1, 96, b'\x01\x02\x03\x04\x05')
                         + update(1, 0, 32, 0, 400, 1, 96, b'\x01\x02')
                         + update(2, 0, 64, 17, 400, 1, 96, b'\x01' * 8)
                         + update(2, 0, 64, 0, 400, 1, 96, b'\x01' * 4)
                         + update(3, 0, 128, 0, 400, 1, 96, b'\x01' * 4)
                         + request(2, 200, b'\x01' * 16)
                         + nh(4, b'\x01\x02\x03\x04')
                         + request(4, 8, b'\x01'))))
    # 5: IHU with an unknown address encoding and a sub-TLV
    F.append(udp6(packet(ihu(4, 96, 1200, b'', sub_ts_ihu(1, 2)) + PAD1 * 8)))
    # 6: body length past the end of the packet
    F.append(udp6(packet(hello(0, 1, 400), bodylen=200)))
    # 7: message length past the end of the packet
    F.append(udp6(packet(b'\x04\x40\x00\x00\x00\x01\x01\x90')))
    # 8: IHU timestamp sub-TLV at the end of the packet (the receive
    # timestamp subtree runs 4 octets past it)
    F.append(udp6(packet(ihu(0, 96, 1200, b'', sub_ts_ihu(1, 2)))))
    # 9: Hello timestamp sub-TLV cut short
    F.append(udp6(packet(hello(0, 1, 400, sub(3, b'\x01\x02')))))
    # 10: sub-TLV length past the end of the message and the packet
    F.append(udp6(packet(hello(0, 1, 400, sub(2, b'\x01'))[:-1] + b'\x02\x50\x01')))
    # 11: message type only, no length octet
    F.append(udp6(packet(b'\x04', bodylen=1)))
    # 12: the Exported PDU reproducer's Babel packet with its last octets cut
    # (body length still 65535)
    F.append(udp6(subtlv_u16_wrap_payload()[:-6]))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'babel-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'babel-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

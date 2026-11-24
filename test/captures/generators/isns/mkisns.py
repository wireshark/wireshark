#!/usr/bin/env python3
# Generates test/captures/isns_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the iSNS (Internet Storage Name Service, RFC 4171) coverage
# captures. Usage: mkisns.py <outdir>
# Everything is synthetic (documentation addresses, made-up iSCSI names and
# World Wide Names).
import struct
import sys
import os


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))

# function ids
REQ = dict(DevAttrReg=1, DevAttrQry=2, DevGetNext=3, DeregDev=4, SCNReg=5,
           SCNDereg=6, SCNEvent=7, SCN=8, DDReg=9, DDDereg=10, DDSReg=11,
           DDSDereg=12, ESI=13, Heartbeat=14, RqstDomId=0x11, RlseDomId=0x12,
           GetDomId=0x13)
CLIENT, SERVER, AUTH, REPLACE, LAST, FIRST = 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400

IP6 = bytes(10) + b'\xff\xff' + bytes([192, 0, 2, 1])      # ::ffff:192.0.2.1


def attr(tag, data=b''):
    return struct.pack('!II', tag, len(data)) + data


def pdu(func, payload=b'', flags=CLIENT | LAST | FIRST, txid=1, seq=0, length=None):
    return struct.pack('!HHHHHH', 1, func, len(payload) if length is None else length,
                       flags, txid, seq) + payload


def num(n, size=4):
    return n.to_bytes(size, 'big')


def s(text):
    b = text.encode()
    return b + bytes((-len(b)) % 4)     # attribute values are padded to 4


# (tag, value) for every tag the dissector knows, with the required length
ATTRS = [
    (0, b''),                                    # delimiter
    (1, s('isns-entity-1.example.org')),
    (2, num(2)),                                  # entity protocol: iSCSI
    (3, IP6),
    (4, bytes(range(8))),
    (5, num(0x00010001)),                         # protocol version range (not decoded)
    (6, num(60)),
    (7, num(1)), (8, num(2)),
    (11, b'\x01\x02\x03\x04'), (12, b'\x05\x06\x07\x08'),     # not decoded
    (16, IP6),
    (17, num(0x00000cb2)),                        # portal port TCP 3250
    (18, s('portal-a')),
    (19, num(30)),
    (20, num(0x0001c350)),                        # ESI port UDP 50000
    (22, num(3)),
    (23, num(0x0000c351)),                        # SCN port TCP 50001
    (24, num(4)),
    (27, num(0x0000007f)),                        # portal security bitmap
    (28, b'\x01\x02\x03\x04'), (29, b'\x01\x02\x03\x04'), (31, b'\x01\x02\x03\x04'),
    (32, s('iqn.2001-04.org.example:storage.disk1')),
    (33, num(0x00000005)),                        # node type: control, target
    (34, s('disk one')),
    (35, num(0x000000ff)),                        # SCN bitmap
    (36, num(5)),
    (37, num(0x1122334455667788, 8)),
    (38, num(6)),
    (42, s('CHAP,None')),
    (48, s('iqn.2001-04.org.example:storage.disk1')),
    (49, IP6),
    (50, num(0x00000cbc)),
    (51, num(1)), (52, num(7)), (53, num(8)),
    (64, num(0x2000000000000001, 8)),
    (65, b'\x01\x02\x03'),
    (66, b'\x00\x01\x00\x00'),                    # not decoded
    (67, s('port-a')),
    (68, num(0x2000000000000002, 8)),
    (69, b'\x00\x00\xef'),
    (70, IP6),
    (71, num(0x30000000)), (72, bytes(32)), (74, num(1)), (75, num(2)), (76, num(3)),
    (73, s('FCP target')),
    (77, num(0x2000000000000003, 8)),
    (95, num(8)),
    (96, num(0x2000000000000004, 8)),
    (97, s('node-a')),
    (98, IP6),
    (99, num(0x0100000000000000, 8)),
    (101, s('iqn.2001-04.org.example:proxy')),
    (128, num(0x2000000000000005, 8)),
    (129, num(10)), (130, num(11)),
    (131, s('vf1')),
    (256, num(0x00001234)),
    (2049, num(1)), (2050, s('ddset-1')), (2051, num(1)), (2052, num(2)),
    (2065, num(3)), (2066, s('dd-1')),
    (2067, num(4)), (2068, s('iqn.2001-04.org.example:member')),
    (2069, num(0x12345678)),                      # the dissector wants 4 octets
    (2070, num(5)),
    (2071, IP6),
    (2072, num(0x00000cb2)),
    (2078, num(1)), (2079, num(6)),
    (65000, b'\xca\xfe\xba\xbe'),                  # unknown tag
]


def pkts_attrs(attrs, n):
    """Split the attributes in groups of n."""
    for i in range(0, len(attrs), n):
        yield b''.join(attr(t, v) for t, v in attrs[i:i + n])


def tcp_stream(cport=40000, sport=3205):
    seq = {True: 1000, False: 9000}

    def seg(data, to_server=True):
        sq = seq[to_server]
        seq[to_server] += len(data)
        a = seq[not to_server]
        sp, dp = (cport, sport) if to_server else (sport, cport)
        src, dst = ('192.0.2.1', '192.0.2.2') if to_server else ('192.0.2.2', '192.0.2.1')
        return eth(0x0800, ipv4(6, tcp(sp, dp, data, sq, a), src, dst),
                   dst=b'\x02\0\0\0\0\x02' if to_server else b'\x02\0\0\0\0\x01',
                   src=b'\x02\0\0\0\0\x01' if to_server else b'\x02\0\0\0\0\x02')
    return seg


def udp_pkt(sport, dport, data, to_server=True):
    src, dst = ('192.0.2.1', '192.0.2.2') if to_server else ('192.0.2.2', '192.0.2.1')
    return eth(0x0800, ipv4(17, udp(sport, dport, data), src, dst),
               dst=b'\x02\0\0\0\0\x02' if to_server else b'\x02\0\0\0\0\x01',
               src=b'\x02\0\0\0\0\x01' if to_server else b'\x02\0\0\0\0\x02')


def main(outdir):
    f = []
    seg = tcp_stream()
    tx = 1
    # 1-: every attribute tag, in DevAttrReg requests (client) and responses
    groups = list(pkts_attrs(ATTRS, 8))
    for i, g in enumerate(groups):
        f.append(seg(pdu(REQ['DevAttrReg'], g, CLIENT | LAST | FIRST | REPLACE, tx, 0)))
        f.append(seg(pdu(0x8001, num(0) + g, SERVER | LAST | FIRST, tx, 0), False))
        tx += 1
    # every function id as request and response; responses with an error code
    # and no attributes, requests with a source attribute and a delimiter
    for name, fid in REQ.items():
        if name == 'Heartbeat':
            continue
        a = attr(32, s('iqn.2001-04.org.example:initiator')) + attr(0)
        f.append(seg(pdu(fid, a, CLIENT | LAST | FIRST, tx, 0)))
        f.append(seg(pdu(0x8000 | fid, num(0 if tx % 2 else 3), SERVER | LAST | FIRST, tx, 0), False))
        tx += 1
    # response with an error code and attributes, empty attributes, flags
    f.append(seg(pdu(0x8002, num(0) + attr(34, b'') + attr(51, b'') + attr(32, s('x'))
                      + attr(0), SERVER | LAST | FIRST | AUTH, tx), False))
    # empty Portal Group Tag in a DevAttrReg (the NULL case)
    f.append(seg(pdu(1, attr(51, b'') + attr(32, s('iqn.2001-04.org.example:t')),
                      CLIENT | LAST | FIRST, tx + 1)))
    # two PDUs in one segment, a PDU split over two segments
    p1 = pdu(2, attr(32, s('iqn.2001-04.org.example:a')) + attr(0), CLIENT | LAST | FIRST, 90)
    p2 = pdu(2, attr(32, s('iqn.2001-04.org.example:b')) + attr(0), CLIENT | LAST | FIRST, 91)
    f.append(seg(p1 + p2))
    p3 = pdu(2, attr(32, s('iqn.2001-04.org.example:c')) + attr(0), CLIENT | LAST | FIRST, 92)
    f.append(seg(p3[:15]))
    f.append(seg(p3[15:]))
    # UDP: heartbeat, ESI to the client's ESI port, SCN to the SCN port
    hb = IP6 + struct.pack('!HHII', 3205, 3205, 30, 7)
    f.append(udp_pkt(3205, 3205, pdu(REQ['Heartbeat'], hb, SERVER | LAST | FIRST, 100), False))
    f.append(udp_pkt(40001, 3205, pdu(1, attr(32, s('iqn.2001-04.org.example:u')) + attr(0)
                                       + attr(20, num(0x0001c350)), CLIENT | LAST | FIRST, 101)))
    f.append(udp_pkt(3205, 40001, pdu(0x8001, num(0), SERVER | LAST | FIRST, 101), False))
    # ESI and SCN messages to the ports the client registered (conversation)
    f.append(udp_pkt(55555, 50000, pdu(13, attr(16, IP6) + attr(17, num(0x00000cb2)),
                                        SERVER | LAST | FIRST, 102), False))
    f.append(tcp_stream(50001, 55556)(pdu(8, attr(32, s('iqn.2001-04.org.example:t')) + attr(0),
                                          SERVER | LAST | FIRST, 103), False))
    write_pcap(os.path.join(outdir, 'isns-coverage.pcap'), 1, f)
    write_malformed(outdir)


def write_malformed(outdir):
    f = []
    seg = tcp_stream(40010)
    # unknown function ID: not accepted by iSNS (own stream: the rest of
    # a stream is not dissected after the first segment is rejected)
    f.append(tcp_stream(40020)(pdu(0x0100, attr(0), CLIENT | LAST | FIRST, 1)))
    f.append(tcp_stream(40021)(pdu(0x0001, attr(0), CLIENT | LAST | FIRST, 1)[:11]))
    f.append(tcp_stream(40022)(struct.pack('!HHHHHH', 2, 1, 0, 0, 0, 0)))
    # 1: second PDU of a message: attributes not decoded
    f.append(seg(pdu(1, attr(32, s('x')), CLIENT | LAST, 1)))
    f.append(seg(pdu(0x8001, b'\x00\x00\x00\x00', SERVER, 2), False))
    f.append(seg(pdu(2, attr(32, s('x')), 0, 3)))
    # fixed length attributes with a wrong length
    for t in (2, 3, 4, 6, 33, 35, 37, 50, 65, 69, 70, 2069, 2071, 128, 256):
        f.append(seg(pdu(1, attr(t, b'\x01\x02\x03\x04\x05'), CLIENT | LAST | FIRST, 10 + t % 100)))
    # delimiter with data (an empty attribute returns before the switch)
    f.append(seg(pdu(1, attr(0, b'\x00\x00\x00\x00') + attr(32, s('x')), CLIENT | LAST | FIRST, 4)))
    # attribute longer than the PDU / the segment
    f.append(seg(pdu(1, struct.pack('!II', 32, 1000) + b'iqn.x', CLIENT | LAST | FIRST, 5)))
    # attribute header cut short
    f.append(seg(pdu(1, attr(32, s('x')) + b'\x00\x00\x00\x20\x00', CLIENT | LAST | FIRST, 6)))
    # PDU shorter than the header (TCP)
    f.append(seg(b'\x00\x01\x00\x01\x00'))
    # heartbeat cut short
    f.append(udp_pkt(3205, 3205, pdu(14, bytes(10), SERVER | LAST | FIRST, 7), False))
    # UDP: wrong version, function id unknown, too short
    f.append(udp_pkt(40002, 3205, struct.pack('!HHHHHH', 2, 1, 0, 0, 0, 0)))
    f.append(udp_pkt(40002, 3205, struct.pack('!HHHHHH', 1, 0x77, 0, 0, 0, 0)))
    f.append(udp_pkt(40002, 3205, b'\x00\x01\x00\x01'))
    # response with FIRST set but only 2 octets of payload (error code)
    f.append(udp_pkt(3205, 40003, pdu(0x8001, b'\x00\x00', SERVER | LAST | FIRST, 9), False))
    # response with the first PDU flag clear and attributes
    f.append(udp_pkt(3205, 40003, pdu(0x8002, attr(32, s('x')), SERVER | LAST, 9), False))
    write_pcap(os.path.join(outdir, 'isns-coverage-malformed.pcap'), 1, f)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

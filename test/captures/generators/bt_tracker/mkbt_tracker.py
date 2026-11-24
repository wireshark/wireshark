#!/usr/bin/env python3
# Generates test/captures/bt_tracker_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BitTorrent UDP tracker
dissector (packet-bt-tracker.c, BEP 15 and BEP 41).

All packets are built from scratch with struct; no captured traffic is
used. A client 192.0.2.10 (port 51413) talks to a tracker 198.51.100.5
(port 6969); over IPv6 2001:db8::10 talks to 2001:db8::5. BT-Tracker has
no port and its UDP heuristic (bt_tracker_udp) is disabled by default; the
heuristic needs a Connect Request to recognise a conversation.

Usage: mkbt_tracker.py <output directory>

Writes:
  bt_tracker-coverage.pcap            every message type, every event,
                                      BEP 41 extensions, IPv4 and IPv6
                                      announce responses (also tunnelled),
                                      the scrape response reproducer and
                                      packets the heuristic rejects
  bt_tracker-coverage-malformed.pcap  truncated messages (exceptions)
"""

import os
import struct
import sys

MAGIC = 0x41727101980
CLIENT = bytes([192, 0, 2, 10])
TRACKER = bytes([198, 51, 100, 5])
V6_CLIENT = bytes.fromhex('20010db8000000000000000000000010')
V6_TRACKER = bytes.fromhex('20010db8000000000000000000000005')
CPORT, TPORT = 51413, 6969
EPOCH = 1700000000
CONN_ID = 0x0123456789abcdef
INFO_HASH = bytes(range(0x10, 0x24))
INFO_HASH2 = bytes(range(0xa0, 0xb4))
PEER_ID = b'-TR3000-' + b'0123456789ab'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload


def ipv6(src, dst, nh, payload):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), nh, 64, src, dst) + payload


def udp(src, dst, sport, dport, payload):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if len(src) == 4:
        pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, len(u))
    else:
        pseudo = struct.pack('>16s16sIxxxB', src, dst, len(u), 17)
    c = csum(pseudo + u) or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def eth(etype, payload):
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01' + struct.pack('>H', etype) + payload


def u4(src, dst, sport, dport, payload):
    return eth(0x0800, ipv4(src, dst, 17, udp(src, dst, sport, dport, payload)))


def u6(src, dst, sport, dport, payload):
    return eth(0x86dd, ipv6(src, dst, 17, udp(src, dst, sport, dport, payload)))


def to_tracker(p, sport=CPORT):
    return u4(CLIENT, TRACKER, sport, TPORT, p)


def to_client(p, dport=CPORT):
    return u4(TRACKER, CLIENT, TPORT, dport, p)


def connect_req(tid):
    return struct.pack('>QII', MAGIC, 0, tid)


def connect_resp(tid, conn=CONN_ID):
    return struct.pack('>IIQ', 0, tid, conn)


def announce_req(tid, event, ip=0, num_want=50, port=51413, downloaded=0, left=0x40000,
                 uploaded=0, key=0x5eed, conn=CONN_ID, info_hash=INFO_HASH):
    return (struct.pack('>QII', conn, 1, tid) + info_hash + PEER_ID +
            struct.pack('>QQQIIIiH', downloaded, left, uploaded, event, ip, key, num_want, port))


def announce_resp(tid, peers=b'', interval=1800, leechers=2, seeders=3):
    return struct.pack('>IIiii', 1, tid, interval, leechers, seeders) + peers


def peer4(a, port):
    return bytes(a) + struct.pack('>H', port)


def peer6(a, port):
    return bytes.fromhex(a) + struct.pack('>H', port)


def clean_frames():
    P = []
    # 1-2: Connect
    P.append(to_tracker(connect_req(0x1001)))
    P.append(to_client(connect_resp(0x1001)))
    # 3-4: Announce (event Started, no extensions) and a response with 3 peers
    P.append(to_tracker(announce_req(0x1002, 2)))
    P.append(to_client(announce_resp(0x1002, peer4((203, 0, 113, 1), 6881) +
                                     peer4((203, 0, 113, 2), 51413) + peer4((203, 0, 113, 3), 6889))))
    # 5: Announce, event Completed, explicit IP, BEP 41 URLData, NOP, URLData, End of Options,
    #    followed by octets after the End of Options (not dissected)
    P.append(to_tracker(announce_req(0x1003, 1, ip=0xc000020a, num_want=-1, downloaded=0x40000, left=0) +
                        bytes([2, 9]) + b'/announce' + bytes([1]) + bytes([2, 12]) + b'?passkey=abc' +
                        bytes([0]) + b'\xde\xad'))
    # 6: Announce response with no peers (exactly 20 octets, no Trackers subtree)
    P.append(to_client(announce_resp(0x1003, interval=-1, leechers=0, seeders=0)))
    # 7: Announce, event Stopped, NOP then an unknown extension type 9 (rest as unknown data)
    P.append(to_tracker(announce_req(0x1004, 3, uploaded=0x123456789) + bytes([1, 9, 1, 2, 3])))
    # 8: Announce response with one peer and a partial (2 octet) peer at the end
    P.append(to_client(announce_resp(0x1004, peer4((203, 0, 113, 9), 6881) + b'\x01\x02')))
    # 9: Announce, event None, ends with a URLData of length 0 at the end of the packet
    P.append(to_tracker(announce_req(0x1005, 0) + bytes([2, 0])))
    # 10: Announce, unknown event 7
    P.append(to_tracker(announce_req(0x1006, 7)))
    # 11-12: Scrape of two info hashes (plus 5 trailing octets) and its response
    P.append(to_tracker(struct.pack('>QII', CONN_ID, 2, 0x1007) + INFO_HASH + INFO_HASH2 + b'\0' * 5))
    P.append(to_client(struct.pack('>II', 2, 0x1007) + struct.pack('>iii', 10, 20, 5) +
                       struct.pack('>iii', 0, 0, 0)))
    # 13: the reproducer of bt_tracker_msgs.py frame 8: a Scrape Response whose
    #     third word (a seeder count) is 1, the Announce action; it used to be an Announce Request
    P.append(to_client(struct.pack('>II', 2, 3) + struct.pack('>iii', 1, 2, 3) * 2 + b'\0'))
    # 14: Error Response whose third word is 2 (the Scrape action)
    P.append(to_client(struct.pack('>II', 3, 0x1008) + b'\0\0\0\x02 invalid connection id'))
    # 15: Error Response
    P.append(to_client(struct.pack('>II', 3, 0x1009) + b'torrent not registered'))
    # 16: unknown message: no action in the first or third word
    P.append(to_client(struct.pack('>IIII', 7, 0x100a, 9, 0)))
    # 17-19: IPv6: Connect, then an Announce Response with two IPv6 peers
    P.append(u6(V6_CLIENT, V6_TRACKER, CPORT, TPORT, connect_req(0x2001)))
    P.append(u6(V6_TRACKER, V6_CLIENT, TPORT, CPORT, connect_resp(0x2001)))
    P.append(u6(V6_TRACKER, V6_CLIENT, TPORT, CPORT,
                announce_resp(0x2002, peer6('20010db8000000000000000000000021', 6881) +
                              peer6('20010db8000000000000000000000022', 51413))))
    # 20-21: tunnels: IPv6 in IPv4 (innermost IPv6, IPv6 peers) and IPv4 in IPv6 (IPv4 peers)
    inner6 = ipv6(V6_CLIENT, V6_TRACKER, 17, udp(V6_CLIENT, V6_TRACKER, 40001, TPORT, connect_req(0x3001)))
    P.append(eth(0x0800, ipv4(bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1]), 41, inner6)))
    inner6 = ipv6(V6_TRACKER, V6_CLIENT, 17, udp(V6_TRACKER, V6_CLIENT, TPORT, 40001,
                  announce_resp(0x3002, peer6('20010db8000000000000000000000031', 6881))))
    P.append(eth(0x0800, ipv4(bytes([198, 51, 100, 1]), bytes([192, 0, 2, 1]), 41, inner6)))
    inner4 = ipv4(CLIENT, TRACKER, 17, udp(CLIENT, TRACKER, 40002, TPORT, connect_req(0x3003)))
    P.append(eth(0x86dd, ipv6(V6_CLIENT, V6_TRACKER, 4, inner4)))
    inner4 = ipv4(TRACKER, CLIENT, 17, udp(TRACKER, CLIENT, TPORT, 40002,
                  announce_resp(0x3004, peer4((203, 0, 113, 41), 6881))))
    P.append(eth(0x86dd, ipv6(V6_TRACKER, V6_CLIENT, 4, inner4)))
    # 24-26: packets the heuristic rejects (other ports): shorter than 16 octets,
    #        no protocol ID, protocol ID with the Announce action
    P.append(u4(CLIENT, TRACKER, 40010, 7000, b'\x00' * 12))
    P.append(u4(CLIENT, TRACKER, 40011, 7000, struct.pack('>QII', MAGIC + 1, 0, 1)))
    P.append(u4(CLIENT, TRACKER, 40012, 7000, struct.pack('>QII', MAGIC, 1, 1)))
    return P


def malformed_frames():
    P = []
    # Each one after a Connect Request in its own conversation
    def conv(sport, body):
        P.append(to_tracker(connect_req(sport), sport))
        P.append(to_client(body, sport))
    # From bt_tracker_msgs.py frame 3: URLData longer than the packet
    ann = announce_req(1, 2)
    P.append(to_tracker(connect_req(1), 50001))
    P.append(to_tracker(ann + bytes([1, 2, 5]) + b'/ann?' + bytes([2, 0xff]) + b'xx', 50001))
    # URLData type at the very end, no length
    P.append(to_tracker(ann + bytes([2]), 50001))
    # Announce Request cut in the info hash
    P.append(to_tracker(ann[:30], 50001))
    # From bt_tracker_msgs.py frame 10: three octets
    conv(50002, b'\0\0\0')
    # 8 to 11 octets: the action at offset 8 cannot be read
    conv(50003, struct.pack('>II', 7, 1) + b'\0\0')
    # Connect Response cut in the connection ID
    conv(50004, struct.pack('>II', 0, 1) + b'\0\0\0\0\0')
    # Announce Response cut in the seeders
    conv(50005, struct.pack('>IIii', 1, 1, 1800, 1) + b'\0\0')
    # Scrape Request cut in the transaction ID
    P.append(to_tracker(struct.pack('>QI', CONN_ID, 2) + b'\0', 50005))
    return P


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', EPOCH + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bt_tracker-coverage.pcap'), clean_frames())
    write_pcap(os.path.join(out, 'bt_tracker-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/clique_rm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Clique reliable
multicast dissector (packet-clique-rm.c).

Clique RM is a heuristic UDP dissector, disabled by default
(--enable-heuristic clique_rm_udp). A packet starts with "Clique", a
version octet (1), a type octet and a 32 bit sender ID. Unreliable
types (whois request/reply, repair request, session) follow with their
fields; reliable types (0x0f and up: data, no data, failure, attempt
join, join, bye) carry a packet ID and a list of (sender, packet ID)
dependencies before their own fields. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkclique-rm.py <output directory>

Writes:
  clique-rm-coverage.pcap            every packet type, empty and filled
                                     lists, unknown types
  clique-rm-coverage-malformed.pcap  packets cut short, counts past the
                                     end, packets the heuristic rejects
"""

import os
import struct
import sys

PORT = 7900
GROUP = (239, 1, 2, 3)
MEMBERS = [(192, 0, 2, 1), (192, 0, 2, 2), (192, 0, 2, 3)]


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(payload, src, ident):
    dst = GROUP
    hdr = struct.pack('>HHHH', PORT, PORT, 8 + len(payload), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xffff
    l4 = hdr[:6] + struct.pack('>H', c) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0x4000, 1, 17, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    mac_dst = bytes([0x01, 0x00, 0x5e, dst[1] & 0x7f, dst[2], dst[3]])
    mac_src = bytes([0x02, 0, 0, 0, 0, src[3]])
    return mac_dst + mac_src + b'\x08\x00' + ip + l4


def write_pcap(path, frames):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    t = 1792000000
    for i, f in enumerate(frames):
        out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


SENDERS = [0x1a2b3c4d, 0x0badf00d, 0xcafe0001]


def hdr(ptype, sender, version=1):
    return b'Clique' + bytes([version, ptype]) + struct.pack('>I', sender)


def depends(items):
    return bytes([len(items)]) + b''.join(struct.pack('>II', s, p) for s, p in items)


def senders(ids):
    return bytes([len(ids)]) + b''.join(struct.pack('>I', s) for s in ids)


def reliable(ptype, sender, packet_id, deps, rest=b''):
    return hdr(ptype, sender) + struct.pack('>I', packet_id) + depends(deps) + rest


def data(flags, stream, payload):
    return bytes([flags]) + struct.pack('>HI', stream, len(payload)) + payload


def main_frames():
    a, b, c = SENDERS
    p = []
    # 1-3: whois request, whois reply, whois reply with an empty name
    p.append((0, hdr(0, a) + struct.pack('>I', b)))
    p.append((1, hdr(1, b) + bytes([len(b'bob@example')]) + b'bob@example'))
    p.append((2, hdr(1, c) + bytes([0])))
    # 4: repair request
    p.append((0, hdr(2, a) + struct.pack('>II', b, 41)))
    # 5-6: session without and with dependencies
    p.append((1, hdr(3, b) + depends([])))
    p.append((0, hdr(3, a) + depends([(b, 42), (c, 7), (a, 100)])))
    # 7: unknown unreliable type
    p.append((2, hdr(5, c) + b'\x00\x00\x00\x00'))
    # 8-9: data with dependencies and a payload, data with a one octet
    # payload and no dependencies (an empty payload throws, see the
    # malformed capture)
    p.append((0, reliable(0x0f, a, 101, [(b, 42), (c, 7)],
                          data(0x03, 1, b'Hello, multicast group!'))))
    p.append((1, reliable(0x0f, b, 43, [], data(0x00, 0xffff, b'!'))))
    # 10: no data (acknowledgement)
    p.append((2, reliable(0x10, c, 8, [(a, 101), (b, 43)])))
    # 11-12: failure with two senders and with none
    p.append((0, reliable(0x11, a, 102, [(c, 8)], senders([b, c]))))
    p.append((1, reliable(0x11, b, 44, [], senders([]))))
    # 13: attempt join with three senders
    p.append((2, reliable(0x12, c, 9, [], senders([a, b, c]))))
    # 14: join with one sender
    p.append((0, reliable(0x13, a, 103, [(c, 9)], senders([a]))))
    # 15: bye
    p.append((1, reliable(0x14, b, 45, [(a, 103)])))
    # 16: unknown reliable type
    p.append((2, reliable(0x20, c, 10, [], b'\xff\xff')))
    return [udp_frame(x, MEMBERS[m], i + 1) for i, (m, x) in enumerate(p)]


def malformed_frames():
    a, b, c = SENDERS
    p = []
    # 1: whois request without the request ID (exactly 12 octets)
    p.append(hdr(0, a))
    # 2: whois reply with a name length past the end
    p.append(hdr(1, b) + bytes([40]) + b'short')
    # 3: repair request cut short
    p.append(hdr(2, a) + b'\x00\x00')
    # 4: session with more dependencies than present
    p.append(hdr(3, a) + b'\x05' + struct.pack('>II', b, 1))
    # 5: data packet with a dependency count past the end
    p.append(hdr(0x0f, a) + struct.pack('>I', 1) + b'\xff' + b'\x00' * 8)
    # 6: data packet cut in the data header
    p.append(reliable(0x0f, a, 2, [], b'\x00\x00'))
    # 7: failure with a sender count past the end
    p.append(reliable(0x11, a, 3, [], b'\x10' + struct.pack('>I', b)))
    # 8: reliable packet without a packet ID
    p.append(hdr(0x10, a))
    # 9: data packet with an empty payload (the -1 length item at the end
    # of the packet throws)
    p.append(reliable(0x0f, b, 43, [], data(0x00, 0xffff, b'')))
    # 10-12: rejected by the heuristic (too short, wrong magic, version 2)
    p.append(b'Clique\x01\x00\x00')
    p.append(b'Cliquf\x01\x00' + b'\x00' * 8)
    p.append(hdr(0, a, version=2) + b'\x00' * 4)
    return [udp_frame(x, MEMBERS[i % 3], i + 1) for i, x in enumerate(p)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'clique-rm-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'clique-rm-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

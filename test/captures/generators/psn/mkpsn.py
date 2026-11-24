#!/usr/bin/env python3
# Generates test/captures/psn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PSN (PosiStageNet)
dissector (packet-psn.c).

PSN runs over UDP port 56565 (multicast 236.10.10.10). V2 packets are a
tree of chunks: a header (16 bit id, 16 bit "length | has-subchunks bit"),
V2 Info packets (0x6756) hold a packet header, the system name and a
tracker list with a name per tracker, V2 Data packets (0x6755) hold a
packet header and a tracker list with position, speed, orientation,
status, acceleration, target position and timestamp per tracker. V1
Data packets (0x6754) are fixed structures; V1 Info/Config packets are
XML text (0x503c is "<P"). Everything is built with struct.

Usage: mkpsn.py <output directory>

Writes:
  psn-coverage.pcap            V2 info and data, V1 data and XML packets
  psn-coverage-malformed.pcap  unknown chunk IDs, length mismatches,
                               truncated chunks
"""
import os
import struct
import sys

MAC_SRC = bytes.fromhex('02000000000a')
MAC_DST = bytes.fromhex('01005e0a0a0a')
IP_SRC = bytes([10, 0, 0, 10])
IP_DST = bytes([236, 10, 10, 10])


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, 10000 * (i % 100), len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp(payload, sport=56565, dport=56565):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(u), 0x100, 0, 16, 17, 0) + IP_SRC + IP_DST
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return MAC_DST + MAC_SRC + b'\x08\x00' + ip + u


def chunk(cid, data, sub=False, length=None):
    """A V2 chunk; length (default len(data)) can be lied about."""
    n = len(data) if length is None else length
    return struct.pack('<HH', cid, n | (0x8000 if sub else 0)) + data


def header(ts, vh, vl, frame, count):
    return struct.pack('<QBBBB', ts, vh, vl, frame, count)


def f3(x, y, z):
    return struct.pack('<fff', x, y, z)


TS0 = 1700000000 * 1000000


def info_packet(frame, name, trackers, extra=b''):
    """trackers: list of (id, [name chunk payloads or (cid, bytes)])"""
    tl = b''
    for tid, names in trackers:
        body = b''
        for n in names:
            cid, d = (0, n) if isinstance(n, bytes) else n
            body += chunk(cid, d)
        tl += chunk(tid, body, sub=bool(names))
    body = chunk(0, header(TS0 + frame * 1000, 2, 3, frame, 1))
    body += chunk(1, name)
    body += chunk(2, tl, sub=True)
    body += extra
    return chunk(0x6756, body, sub=True)


def tracker_data(items):
    """items: list of (chunk id, payload)"""
    return b''.join(chunk(c, d) for c, d in items)


def data_packet(frame, trackers, vh=2, vl=3, count=1):
    tl = b''
    for tid, items in trackers:
        tl += chunk(tid, tracker_data(items), sub=True)
    body = chunk(0, header(TS0 + frame * 1000, vh, vl, frame, count))
    body += chunk(1, tl, sub=True)
    return chunk(0x6755, body, sub=True)


def all_items(k):
    return [
        (0, f3(1.5 * k, -2.25, 100.0)),
        (1, f3(0.5, 0.25 * k, -0.125)),
        (2, f3(0.0, 1.5708, 3.14159)),
        (3, struct.pack('<f', 1.0)),
        (4, f3(9.8, 0.0, -9.8)),
        (5, f3(10.0, 20.0, 30.0)),
        (6, struct.pack('<Q', TS0 + 123456 + k)),
    ]


def v1_data(counter, frame, trackers, world=1, declared=None):
    n = len(trackers) if declared is None else declared
    p = struct.pack('<H', 0x6754)
    p += struct.pack('<IBBHHBBB', counter, 1, 7, world, n, frame, 1, 0) + b'\0\0\0'
    for tid, state, pos, vel in trackers:
        p += struct.pack('<HH', tid, state) + b'\0' * 4 + f3(*pos) + f3(*vel)
    p += struct.pack('<H', 0x4576)
    return p


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    F = []
    # V2 info packets
    F.append(udp(info_packet(1, b'Synthetic System', [(0, [b'Alpha']), (1, [b'Beta']), (2, [b'Gamma'])])))
    F.append(udp(info_packet(2, b'', [(5, [b'Solo tracker'])])))
    # tracker with an unknown name chunk id (skipped silently), a tracker
    # without name chunks
    F.append(udp(info_packet(3, b'Names', [(7, [(0, b'Named'), (9, b'other')]), (8, [])])))
    # V2 data packets
    F.append(udp(data_packet(1, [(0, all_items(1))])))
    F.append(udp(data_packet(2, [(0, all_items(1)), (1, all_items(2)), (2, all_items(3))])))
    F.append(udp(data_packet(3, [(300, [(0, f3(1, 2, 3))]), (301, [(3, struct.pack('<f', 2.0))])])))
    F.append(udp(data_packet(4, [(0, [(6, struct.pack('<Q', TS0))])], vh=2, vl=2, count=4)))
    F.append(udp(data_packet(5, [])))
    # V1 data
    F.append(udp(v1_data(1, 1, [(0, 1, (1, 2, 3), (0.1, 0.2, 0.3)),
                                (1, 0, (4, 5, 6), (0.4, 0.5, 0.6))])))
    F.append(udp(v1_data(2, 2, [])))
    F.append(udp(v1_data(3, 3, [(5, 3, (-1.0, -2.0, -3.0), (0.0, 0.0, 0.0))], world=7)))
    # V1 info / config / ack / other XML (0x503c = "<P")
    F.append(udp(b'<PSN><info><system>Test</system><tracker id="0" name="A"/></info></PSN>'))
    F.append(udp(b'<PSN_config><interface>eth0</interface></PSN_config>'))
    F.append(udp(b'<PSN_config_ACK><status>ok</status></PSN_config_ACK>'))
    F.append(udp(b'<Pxyz><value>1</value></Pxyz>'))
    # Not PSN: unknown first 16 bits (the heuristic is a port, so it is
    # simply not dissected), and a UDP payload of one octet.
    F.append(udp(b'\x00\x00\x00\x00\x00\x00'))
    F.append(udp(b'\x56'))
    pcap(os.path.join(outdir, 'psn-coverage.pcap'), F)

    # ---- malformed / error paths
    M = []
    # Unknown chunk IDs: in the info packet, the data packet, the tracker
    # data chunk
    M.append(udp(chunk(0x6756, chunk(0x77, b'xxxx'), sub=True)))
    M.append(udp(chunk(0x6755, chunk(0x77, b'xxxx'), sub=True)))
    M.append(udp(data_packet(1, [(0, [(0x55, b'abcd')])])))
    # Length mismatches: chunk longer / shorter than what is decoded
    M.append(udp(chunk(0x6756, chunk(0, header(TS0, 2, 3, 1, 1) + b'\0\0\0\0'), sub=True)))
    M.append(udp(chunk(0x6755, chunk(0, header(TS0, 2, 3, 1, 1) + b'\0\0\0\0'), sub=True)))
    for cid, plen in ((0, 12), (3, 8), (6, 12)):
        # tracker data chunk with more or fewer bytes than the type needs
        pl = b'\0' * plen
        M.append(udp(data_packet(1, [(0, [(cid, pl)])])))
    M.append(udp(chunk(0x6756, chunk(1, b'name') + chunk(0, b'\0' * 12), sub=True)))
    # Info packet: tracker list claiming sub chunks that are cut off
    p = info_packet(1, b'x', [(0, [b'abc'])])
    M.append(udp(p[:-3]))
    M.append(udp(p[:30]))
    M.append(udp(p[:6]))
    M.append(udp(p[:3]))
    # Data packet cut off
    p = data_packet(1, [(0, all_items(1))])
    for n in (10, 24, 40, 60, 100, len(p) - 1):
        M.append(udp(p[:n]))
    # A tracker data chunk longer than its tracker list chunk
    tr = chunk(0, f3(1, 2, 3), length=16)
    M.append(udp(chunk(0x6755, chunk(1, chunk(0, tr, sub=True), sub=True) , sub=True)))
    # An info tracker name chunk longer than its tracker chunk; the extra
    # octets are in the UDP payload after the packet
    nm = chunk(0, b'abc', length=12)
    M.append(udp(chunk(0x6756, chunk(2, chunk(0, nm, sub=True), sub=True), sub=True) + b'z' * 24))
    # Data packet where the outer length is longer than the packet
    M.append(udp(chunk(0x6755, chunk(0, header(TS0, 2, 3, 1, 1)), sub=True, length=500)))
    # V1 data claiming more trackers than present
    M.append(udp(v1_data(1, 1, [(0, 1, (1, 2, 3), (0.1, 0.2, 0.3))], declared=4)))
    M.append(udp(v1_data(1, 1, [])[:10]))
    M.append(udp(b'\x54\x67'))
    pcap(os.path.join(outdir, 'psn-coverage-malformed.pcap'), M)


if __name__ == '__main__':
    main(sys.argv[1])

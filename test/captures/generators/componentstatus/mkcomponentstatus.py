#!/usr/bin/env python3
# Generates test/captures/componentstatus_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Component Status
Protocol dissector (packet-componentstatus.c) of the RSPLIB RSerPool
implementation.

ComponentStatusProtocol runs on UDP port 2960. A message has a 24 octet
header (type, flags, length, version 0x0200, sender ID, sender
timestamp); a ComponentStatus Report (type 1) adds a report interval, a
128 octet location, a 128 octet status, a workload, an association count
and 24 octet association records. Every packet is built from scratch
with struct; no captured traffic is used.

Usage: mkcomponentstatus.py <output directory>

Writes:
  componentstatus-coverage.pcap            reports with every workload
                                           case, every sender/receiver
                                           group, 0 to 4 associations,
                                           the review reproducers, and
                                           packets the heuristic rejects
  componentstatus-coverage-malformed.pcap  reports cut short
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
DST = (198, 51, 100, 2)
PORT = 2960
BASE_TS = 1700000000


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=SRC, dst=DST, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src=SRC, dst=DST):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(data, ident=1, sport=PORT, dport=PORT, src=SRC, dst=DST):
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, udp(sport, dport, data, src, dst), src, dst, ident))


def assoc(receiver, duration, flags=0, protocol=132, ppid=46):
    return struct.pack('>QQHHI', receiver, duration, flags, protocol, ppid)


def report(sender, timestamp, interval, location, status, workload,
           assocs=(), nassoc=None, flags=0, length=None, mtype=1,
           version=0x0200, trailer=b''):
    body = (struct.pack('>I', interval) + location.ljust(128, b'\0')
            + status.ljust(128, b'\0')
            + struct.pack('>HH', workload, len(assocs) if nassoc is None else nassoc)
            + b''.join(assocs) + trailer)
    if length is None:
        length = 24 + len(body)
    return struct.pack('>BBHIQQ', mtype, flags, length, version, sender,
                       timestamp) + body


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (ts, data) in enumerate(frames):
            sec, usec = divmod(ts, 1000000)
            f.write(struct.pack('<IIII', BASE_TS + sec, usec, len(data), len(data)))
            f.write(data)


def reproducer(length):
    """The report of componentstatus_stat_share.py."""
    body = struct.pack('>I', 5000000) + b'here'.ljust(128, b'\0') + b'ok'.ljust(128, b'\0')
    body += struct.pack('>HH', 0x7fff, 1)
    body += struct.pack('>QQHHI', 0x0001000000000002, 2000000, 0, 132, 46)
    return struct.pack('>BBHIQQ', 1, 1, length, 0x0200, 0x0002000000000001, 1000000) + body


def main_frames():
    msgs = []
    # 1: the zero length reproducer (componentstatus_stat_zero_len.pcap):
    # a Length of 0 while every message so far has a length of 0 gives a
    # bytes share of 0 (it divided by zero before the fix).
    msgs.append(reproducer(0))
    # 2-3: the share reproducer (componentstatus_stat_share.pcap)
    msgs.append(reproducer(316))
    msgs.append(reproducer(316))
    # 4: a registrar (group 1) with workload 0, no associations, not final
    msgs.append(report(0x0100000000000010, 1234567890, 1000000,
                       b'Registrar Room 1', b'Running', 0x0000))
    # 5: a pool element with workload 0x7fff (50.00 %), final, two
    # associations: SCTP/ppid 46 with a duration and TCP with an unknown
    # duration (all ones)
    msgs.append(report(0x0200000000abcdef, 2000000000, 2500000,
                       b'Lab \xc3\x84', b'Busy', 0x7fff, flags=1,
                       assocs=[assoc(0x0100000000000010, 3500000, 0, 132, 46),
                               assoc(0x0300000000000099, 0xffffffffffffffff, 1, 6, 0)]))
    # 6: a pool user with no workload (0xffff, N/A), three associations
    # to group 0 (Unknown), a group past the list (5) and UDP; the
    # association count (5) does not match, as the dissector does not use
    # it; 23 trailing octets are not a full association.
    msgs.append(report(0x0300000000000001, 0, 0xffffffff,
                       b'', b'', 0xffff, nassoc=5, flags=0xff,
                       assocs=[assoc(0x0000000000000000, 0, 0xffff, 17, 0),
                               assoc(0x05ffffffffffffff, 1, 2, 255, 0xffffffff),
                               assoc(0x0200000000000002, 999999, 3, 132, 51)],
                       trailer=b'\x00' * 23))
    # 7: a sender group past the list (0xff), full workload 0xfffe (100.00 %),
    # a location and status that fill all 128 octets, four associations
    msgs.append(report(0xff00000000000042, 0xffffffffffffffff, 30000000,
                       b'L' * 128, b'S' * 128, 0xfffe, flags=1,
                       assocs=[assoc(0x0200000000000000 | i, 1000000 * i, i, 132, 46 + i)
                               for i in range(1, 5)]))
    # 8: a group 0 sender, workload 1 (0.00 %)
    msgs.append(report(0x0000000000000000, 1, 1, b'x', b'y', 0x0001))
    frames = [frame(m, ident=i + 1) for i, m in enumerate(msgs)]
    # 9: the sender port is 2960 only (reply direction to an ephemeral port)
    frames.append(frame(report(0x0200000000000005, 5, 5, b'south', b'ok', 0x1234,
                               assocs=[assoc(0x0100000000000010, 5)]),
                        ident=9, sport=PORT, dport=40000, src=DST, dst=SRC))
    # Packets the heuristics reject (shown as data): 10 shorter than 8
    # octets, 11 a message type of 2, 12 a version of 0x0100.
    frames.append(frame(b'\x01\x00\x00\x07\x00\x00\x02', ident=10))
    frames.append(frame(report(0x0002000000000001, 0, 0, b'', b'', 0, mtype=2), ident=11))
    frames.append(frame(report(0x0002000000000001, 0, 0, b'', b'', 0, version=0x0100), ident=12))
    times = [0, 1000000, 2500000, 3000000, 3250000, 4000000, 6000000, 6000001,
             7000000, 8000000, 9000000, 10000000]
    return list(zip(times, frames))


def malformed_frames():
    full = report(0x0002000000abcdef, 2000000000, 2500000, b'here', b'ok', 0x7fff,
                  assocs=[assoc(0x0001000000000010, 3500000)])
    cuts = [8, 20, 24, 100, 285, 287, 300]
    return [(i * 1000000, frame(full[:c], ident=i + 1)) for i, c in enumerate(cuts)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'componentstatus-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'componentstatus-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

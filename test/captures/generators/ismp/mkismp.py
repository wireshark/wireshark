#!/usr/bin/env python3
# Generates test/captures/ismp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISMP (Inter-Switch Message Protocol, Enterasys Discover
# Protocol) coverage captures. Usage: mkismp.py <outdir>
# Everything is synthetic (documentation IP addresses, locally administered
# MAC addresses).
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


ETH_ISMP = 0x81fd
MAC1 = b'\x02\x00\x00\x00\x00\x01'
MAC2 = b'\x02\x00\x00\x00\x00\x02'
MAC9 = b'\x02\x00\x00\x00\x00\x09'


def tuple_(t, data, length=None):
    return struct.pack('!HH', t, 4 + len(data) if length is None else length) + data


def edp(device_type=3, options=0, neighbors=(), tuples=(), n_neighbors=None,
        n_tuples=None, tail=b'', ip=b'\xc0\x00\x02\x01', rev=b'\x01\x02\x03\x04'):
    b = struct.pack('!H4s6sI6s4sH4sI', 2, ip, MAC1, 0x00010002, MAC2, ip,
                    device_type, rev, options)
    b += struct.pack('!H', len(neighbors) if n_neighbors is None else n_neighbors)
    for mac, state in neighbors:
        b += mac + struct.pack('!I', state)
    if n_tuples is not False:
        b += struct.pack('!H', len(tuples) if n_tuples is None else n_tuples)
    for t in tuples:
        b += t
    return b + tail


def ismp(msgtype, body=b'', seq=1, auth=b'', version=2, weird=False, code_len=None):
    h = struct.pack('!HHHB', version, msgtype, seq, len(auth) if code_len is None else code_len) + auth
    return (b'\x42\x42\x03' if weird else b'') + h + body


def frame(payload, dst=b'\x01\x00\x1d\x00\x00\x00', src=MAC1):
    return eth(ETH_ISMP, payload, dst=dst, src=src)


def main(outdir):
    f = []
    # 1: the reproducer of the neighbor state fix: one neighbor, interface name
    f.append(frame(ismp(2, edp(neighbors=[(MAC9, 0x11223344)],
                               tuples=[tuple_(2, b'eth0')]))))
    # 2-13: every device type with its options (all option bits set, then
    # none), no neighbors, no tuples (the packet ends after the neighbors)
    for dt in range(1, 13):
        opts = {1: 0x7fff, 2: 0x5555, 3: 0x1fff, 4: 0x7f, 5: 0xdeadbeef,
                6: 0x7, 7: 0x5, 8: 0x2, 9: 0x1, 10: 0x7, 11: 0x0,
                12: 0xffffffff}[dt]
        f.append(frame(ismp(2, edp(dt, opts, n_tuples=False)), src=MAC1, dst=b'\x01\x00\x1d\x00\x00\x00'))
    # 14: unknown device type, options shown as plain number
    f.append(frame(ismp(2, edp(77, 0x12345678, n_tuples=False))))
    # 15: three neighbors and all tuple types (hold time, interface name,
    # system description, IPX address, unknown type 0 and 99)
    ipx = struct.pack('!I', 0x0a0b0c0d) + b'\x02\x00\x00\x00\x00\x07'
    f.append(frame(ismp(2, edp(
        1, 0x4001,
        neighbors=[(MAC9, 1), (MAC2, 2), (MAC1, 0xffffffff)],
        tuples=[tuple_(1, struct.pack('!I', 180)),
                tuple_(2, b'ge.1.1'),
                tuple_(3, b'Example switch, firmware 1.0'),
                tuple_(4, ipx),
                tuple_(4, struct.pack('!I', 0x01020304) + b'\x02\x00\x00\x00\x00\x08'),
                tuple_(0, b'abcd'),
                tuple_(99, b'unknown')]))))
    # 16: tuples with different lengths: hold time of 2 octets, empty
    # interface name
    f.append(frame(ismp(2, edp(tuples=[tuple_(1, b'\x00\xb4'), tuple_(2, b'')]))))
    # 17: authentication data in the ISMP header, sequence number
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'eth1')]), seq=65535,
                        auth=b'\x01\x02\x03\x04\x05\x06\x07\x08')))
    # 18: the three octets 42 42 03 before the ISMP header
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'eth2')]), weird=True)))
    # 19: a message type other than EDP (only the ISMP header)
    f.append(frame(ismp(1, b'\x00' * 8)))
    f.append(frame(ismp(65535, b'')))
    # 21: zero tuples announced (num_tuples = 0), trailing data after it
    f.append(frame(ismp(2, edp(n_tuples=0))))
    # 22: the packet ends after the neighbor count (no tuple count)
    f.append(frame(ismp(2, edp(n_tuples=False))))
    write_pcap(os.path.join(outdir, 'ismp-coverage.pcap'), 1, f)
    write_malformed(outdir)


def write_malformed(outdir):
    f = []
    # 1: three neighbors announced, only one present
    f.append(frame(ismp(2, edp(neighbors=[(MAC9, 1)], n_neighbors=3, n_tuples=False))))
    # 2: one tuple count octet only after the neighbors
    f.append(frame(ismp(2, edp(n_tuples=False, tail=b'\x00'))))
    # 3: tuple length below the 4 octet header
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'', length=2)]))))
    # 4: IPX address of the wrong length
    f.append(frame(ismp(2, edp(tuples=[tuple_(4, b'\x01\x02\x03')]))))
    # 5: more tuples announced than present
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'eth0')], n_tuples=5))))
    # 6: tuple that is longer than the rest of the packet (skipped)
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'eth0', length=200)]))))
    # 7: the EDP header cut short
    f.append(frame(ismp(2, edp()[:20])))
    # 8: authentication length longer than the packet
    f.append(frame(ismp(2, b'', code_len=200)))
    # 9: only 2 octets
    f.append(frame(b'\x00\x02'))
    # 10: tuple header with fewer than 4 octets left although one more
    # tuple is announced
    f.append(frame(ismp(2, edp(tuples=[tuple_(2, b'eth0')], n_tuples=2, tail=b'\x00\x02\x00'))))
    write_pcap(os.path.join(outdir, 'ismp-coverage-malformed.pcap'), 1, f)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/vmware_hb_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic VMware heartbeat (UDP port 902) captures for packet-vmware-hb.c.

Usage: mkvmware-hb.py <outdir> [-v]
Writes vmware-hb-coverage.pcapng (main capture: no malformed packets or
error expert infos) and vmware-hb-coverage-malformed.pcapng (truncated
heartbeats). Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import eth, ipv4, udp, write_pcapng


def heartbeat(build=164009, server_id=0x11223344, key=b'', magic=0x1,
              change_gen=1, spec_gen=2, bundle=3, counter=1, ip=b'', sig=b''):
    return (struct.pack('<III', magic, build, server_id) + bytes([len(key)]) + key +
            struct.pack('<iiiI', change_gen, spec_gen, bundle, counter) + bytes([len(ip)]) + ip + sig)


def frame(payload, sport=902, dport=902, src=1, dst=2):
    return eth(2, 1, 0x0800, ipv4(17, udp(sport, dport, payload), src, dst))


def build_main():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    key = b'52 9c 3a 0e 11 22 33 44-55 66 77 88 99 aa bb cc'[:36]
    mark('Known ESXi build numbers (first, one of each major release, the last) and an unknown one')
    for i, b in enumerate((164009, 175625, 469512, 1331820, 2494585, 4564106, 8169922, 15843807,
                           20513097, 24755229, 25782009, 12345, 0, 0xffffffff)):
        add(frame(heartbeat(build=b, key=key, counter=i + 1, ip=b'192.0.2.10')))
    mark('Host keys of different lengths (0, 1, 36, 255) and non-ASCII octets')
    add(frame(heartbeat(key=b'', ip=b'192.0.2.11')))
    add(frame(heartbeat(key=b'k', ip=b'192.0.2.11')))
    add(frame(heartbeat(key=b'0123456789abcdef0123456789abcdef0123', ip=b'192.0.2.11')))
    add(frame(heartbeat(key=b'A' * 255, ip=b'192.0.2.11')))
    add(frame(heartbeat(key=b'caf\xc3\xa9 \xff\xfe key', ip=b'192.0.2.11')))
    mark('No IP address, an IP address of 1 and 15 octets, and a verification signature')
    add(frame(heartbeat(key=key, ip=b'')))
    add(frame(heartbeat(key=key, ip=b'1')))
    add(frame(heartbeat(key=key, ip=b'192.168.100.200')))
    add(frame(heartbeat(key=key, ip=b'192.0.2.12', sig=bytes(range(20)))))
    add(frame(heartbeat(key=key, ip=b'', sig=bytes(range(32)))))
    mark('Signed and unsigned counters and generations, other magic number and server ID, either port')
    add(frame(heartbeat(key=key, ip=b'192.0.2.13', change_gen=-1, spec_gen=-2147483648, bundle=2147483647, counter=0xffffffff)))
    add(frame(heartbeat(key=key, ip=b'192.0.2.13', magic=0xdeadbeef, server_id=0)))
    add(frame(heartbeat(key=key, ip=b'192.0.2.13'), sport=40000, dport=902))
    add(frame(heartbeat(key=key, ip=b'192.0.2.13'), sport=902, dport=40001, src=2, dst=1))
    return fr, marks


def build_malformed():
    fr, marks = [], []

    def mark(label):
        marks.append((len(fr) + 1, label))

    def add(d, i=0):
        fr.append((i, d))

    mark('Truncated heartbeats')
    full = heartbeat(key=b'key', ip=b'192.0.2.10')
    for n in (0, 3, 11, 12, 14, 40, len(full) - 11, len(full) - 1):
        add(frame(full[:n]))
    mark('Host key length and IP address length past the end')
    add(frame(struct.pack('<III', 1, 164009, 1) + bytes([200]) + b'short'))
    add(frame(heartbeat(key=b'k')[:-1] + bytes([100]) + b'192'))
    return fr, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vmware-hb-coverage', build_main), ('vmware-hb-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [1], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()

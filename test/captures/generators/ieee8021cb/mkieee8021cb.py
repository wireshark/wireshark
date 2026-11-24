#!/usr/bin/env python3
# Generates test/captures/ieee8021cb_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ieee8021cb.c (802.1CB redundancy tag, R-tag).
Usage: mkieee8021cb.py <outdir> [-v]   (needs pcaplib.py beside it)"""
import struct
import sys
import os
from pcaplib import exported_pdu, ip4, mac, pcapng, udp

A, B = '02:00:00:00:00:01', '02:00:00:00:00:02'

def rtag(seq, etype, res=0):
    return struct.pack('!HHH', res, seq, etype)

def udp4(n=0, extra=b''):
    return ip4('192.0.2.1', '192.0.2.2', 17, udp(40000 + n, 5001, b'cb%d' % n * 4 + extra))

arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, mac(B), bytes([192,0,2,1]),
                  b'\0' * 6, bytes([192,0,2,2]))

def main(out, verbose=False):
    fr, marks = [], []
    def add(desc, f):
        # packet-rtag.c also claims ethertype 0xF1C1 and wins, so this
        # dissector is reached through Exported PDU (dissector name tag)
        fr.append(exported_pdu('ieee8021cb', f)); marks.append((len(fr), desc))
    add('SEQ 0, IPv4/UDP', rtag(0, 0x0800) + udp4(0))
    add('SEQ 1, IPv4/UDP', rtag(1, 0x0800) + udp4(1))
    add('SEQ 0xffff, IPv4/UDP', rtag(0xffff, 0x0800) + udp4(2))
    add('SEQ 0x1234, ARP', rtag(0x1234, 0x0806) + arp)
    add('SEQ 7, reserved field set, experimental ethertype', rtag(7, 0x88B5, res=0xabcd) + bytes(range(46)))
    add('SEQ 8, ethertype 0x0042 (a length: not an ethertype)', rtag(8, 0x0042) + b'\x42\x42\x03' + b'\0' * 43)
    add('SEQ 9, IPv4/UDP over an 802.1Q tag in the payload', rtag(9, 0x8100) + struct.pack('!HH', 5, 0x0800) + udp4(3))
    add('SEQ 10, VLAN tag with ARP', rtag(10, 0x8100) + struct.pack('!HH', 6, 0x0806) + arp)
    # reproducer of "IEEE 802.1CB: Initialise the ethertype data": the IPv4 packet
    # is followed by a trailer, whose item uses ethertype_data.trailer_id
    add('reproducer: R-tag, IPv4/UDP then a 100 octet trailer',
        rtag(0x1234, 0x0800) + ip4('192.0.2.1', '192.0.2.2', 17, udp(40000, 5001, b'')) + b'\x5a' * 100)
    add('IPv4/UDP then a short trailer', rtag(12, 0x0800) + ip4('192.0.2.1', '192.0.2.2', 17, udp(1, 2, b'')) + b'\xa5' * 6)
    os.makedirs(out, exist_ok=True)
    pcapng(os.path.join(out, 'ieee8021cb-coverage.pcapng'), fr, ifaces=(252,))
    m = [rtag(1, 0x0800)[:1], rtag(1, 0x0800)[:3], rtag(1, 0x0800)[:5], rtag(1, 0x0800), rtag(1, 0x0800) + b'\x45\x00']
    mf = [exported_pdu('ieee8021cb', x) for x in m]
    pcapng(os.path.join(out, 'ieee8021cb-coverage-malformed.pcapng'), mf, ifaces=(252,))
    if verbose:
        for n, d in marks: print(n, d)
        print(len(fr), 'frames;', len(mf), 'malformed frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

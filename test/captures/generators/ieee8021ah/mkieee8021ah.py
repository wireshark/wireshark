#!/usr/bin/env python3
# Generates test/captures/ieee8021ah_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ieee8021ah.c (802.1ah I-tag, 802.1ad tags).
Usage: mkieee8021ah.py <outdir> [-v]   (needs pcaplib.py beside it)"""
import struct
import sys
import os
from pcaplib import eth, ip4, mac, pcap, udp

BD, BS = '02:00:00:00:00:01', '02:00:00:00:00:02'   # backbone MACs
CD, CS = '02:00:00:00:00:03', '02:00:00:00:00:04'   # customer MACs

def itag(pri=0, drop=0, nca=0, res1=0, res2=0, isid=1):
    return struct.pack('!I', (pri << 29) | (drop << 28) | (nca << 27) | (res1 << 26)
                       | (res2 << 24) | isid)

def inner(etype, payload, cd=CD, cs=CS):
    """customer addresses + ethertype + payload (the part after the I-tag)"""
    return mac(cd) + mac(cs) + struct.pack('!H', etype) + payload

def udp4(n=0):
    return ip4('192.0.2.1', '192.0.2.2', 17, udp(5000 + n, 5001, b'ah%d' % n * 6))

arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, mac(CS), bytes([192,0,2,1]),
                  b'\0' * 6, bytes([192,0,2,2]))

def main(out, verbose=False):
    fr = []
    marks = []
    def add(desc, f):
        fr.append(f); marks.append((len(fr), desc))
    # direct I-tag on ethertype 0x88E7
    add('I-tag, IPv4/UDP', eth(BD, BS, 0x88E7, itag() + inner(0x0800, udp4())))
    add('I-tag, all flags set, I-SID 0xffffff, Experimental ethertype',
        eth(BD, BS, 0x88E7, itag(7, 1, 1, 1, 3, 0xffffff) + inner(0x88B5, bytes(range(46)))))
    add('I-tag, priority 3, ARP',
        eth(BD, BS, 0x88E7, itag(3, 0, 0, 0, 0, 0x123456) + inner(0x0806, arp)))
    add('I-tag, IPv4 with trailing padding bytes (ethernet trailer)',
        eth(BD, BS, 0x88E7, itag(isid=77) + inner(0x0800, udp4(1) + b'\xa5' * 12)))
    add('I-tag, NCA=1 with zero customer addresses',
        eth(BD, BS, 0x88E7, itag(nca=1, isid=5) + inner(0x0800, udp4(2), '00:00:00:00:00:00', '00:00:00:00:00:00')))
    add('I-tag, payload ethertype 0x0042 (a length: not an ethertype)',
        eth(BD, BS, 0x88E7, itag(isid=6) + inner(0x0042, b'\x42\x42\x03' + b'\0' * 40)))
    # 802.1ad (0x88A8) followed by the I-tag: B-tag
    for vid, pri, dei in ((100, 5, 0), (4095, 0, 1)):
        add('B-tag %d then I-tag' % vid,
            eth(BD, BS, 0x88A8, struct.pack('!HH', (pri << 13) | (dei << 12) | vid, 0x88E7)
                + itag(isid=vid) + inner(0x0800, udp4(3))))
    # Q-in-Q: S-tag, C-tag
    add('Q-in-Q S-VID 200 C-VID 300, IPv4',
        eth(BD, BS, 0x88A8, struct.pack('!HHHH', (6 << 13) | 200, 0x88A8, (1 << 13) | (1 << 12) | 300, 0x0800)
            + udp4(4)))
    add('Q-in-Q S-VID 1 C-VID 2, ARP',
        eth(BD, BS, 0x88A8, struct.pack('!HHHH', 1, 0x88A8, 2, 0x0806) + arp))
    # 802.1ad tag followed by something else (single S-tag)
    add('single 802.1ad tag, IPv4',
        eth(BD, BS, 0x88A8, struct.pack('!HH', (2 << 13) | 10, 0x0800) + udp4(5)))
    add('single 802.1ad tag, ARP',
        eth(BD, BS, 0x88A8, struct.pack('!HH', (7 << 13) | (1 << 12) | 11, 0x0806) + arp))
    # nested: the I-tag payload is itself 802.1ad
    add('I-tag whose payload is a Q-in-Q tagged frame',
        eth(BD, BS, 0x88E7, itag(isid=9) + inner(0x88A8, struct.pack('!HH', 20, 0x0800) + udp4(6))))
    # Reproducer of "802.1ah: Fix the offset of the ethertype item"
    add('reproducer: I-tag then ethertype 0x88B5 (etype item offset)',
        eth(BD, BS, 0x88E7, itag(isid=0x123456) + inner(0x88B5, b'\x11' * 46)))
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'ieee8021ah-coverage.pcap'), fr)
    # malformed: truncated tags
    m = []
    m.append(eth(BD, BS, 0x88E7, itag()[:3]))                       # truncated I-tag
    m.append(eth(BD, BS, 0x88E7, itag() + mac(CD)))                 # truncated addresses
    m.append(eth(BD, BS, 0x88E7, itag() + mac(CD) + mac(CS) + b'\x08'))   # truncated ethertype
    m.append(eth(BD, BS, 0x88A8, b'\x00\x01'))                      # truncated B/S-tag
    m.append(eth(BD, BS, 0x88A8, struct.pack('!HH', 5, 0x88A8) + b'\x00'))   # truncated C-tag
    m.append(eth(BD, BS, 0x88A8, struct.pack('!HHH', 5, 0x88A8, 5)))         # no C ethertype
    m.append(eth(BD, BS, 0x88A8, struct.pack('!HH', 5, 0x88E7) + itag()[:2]))
    m.append(eth(BD, BS, 0x88A8, struct.pack('!HH', 5, 0x0800) + b'\x45\x00'))
    # a single 802.1ad tag with a short payload (the ethertype item is added at
    # offset 16 of the tag tvb, past its end; see README, "IEEE 802.1ah: Fix the offset of
    # the ethertype item" changed the wrong function)
    m.append(eth(BD, BS, 0x88A8, struct.pack('!HH', 5, 0x88B5) + b'\x01\x02\x03\x04'))
    pcap(os.path.join(out, 'ieee8021ah-coverage-malformed.pcap'), m)
    if verbose:
        for n, d in marks: print(n, d)
        print(len(fr), 'frames;', len(m), 'malformed frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

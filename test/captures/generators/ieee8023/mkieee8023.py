#!/usr/bin/env python3
# Generates test/captures/ieee8023_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-ieee8023.c (dissect_802_3(): the payload of
an Ethernet frame with a length field, LLC / IPX / CCSDS, called by eth, vlan,
vntag and gmhdr).  Usage: mkieee8023.py <outdir> [-v]   (needs pcaplib.py)"""
import struct
import sys
import os
from pcaplib import ip4, mac, pcapng, udp

A, B = '02:00:00:00:00:01', '02:00:00:00:00:02'
STP_DST = '01:80:c2:00:00:00'

def bpdu():
    root = struct.pack('!H6s', 0x8000, mac(A))
    bridge = struct.pack('!H6s', 0x8000, mac(B))
    return (struct.pack('!HBBB', 0, 0, 0, 0) + root + struct.pack('!I', 4) + bridge
            + struct.pack('!HHHHH', 0x8001, 0, 0x1400, 0x0200, 0x0f00))

LLC_STP = b'\x42\x42\x03'
LLC_SNAP = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'

def ipx(data=b'ipx', ptype=0):
    h = struct.pack('!HHBB4s6sH4s6sH', 0xffff, 30 + len(data), 0, ptype,
                    b'\0\0\0\1', mac(A), 0x1111, b'\0\0\0\2', mac(B), 0x1112)
    return h + data

def ccsds(n=20):
    # primary header: version 0, type 0, secondary header flag 1, APID 0x123;
    # sequence flags 3, count 5; data length field = octets after the header - 1
    return struct.pack('!HHH', 0x0800 | 0x123, 0xc000 | 5, n - 6 - 1) + bytes(range(1, n - 5))

def udp4(n=0):
    return ip4('192.0.2.1', '192.0.2.2', 17, udp(6000 + n, 6001, b'8023' * 3))

def f8023(payload, dst=B, src=A, length=None):
    """Ethernet frame with a length field instead of an ethertype"""
    return mac(dst) + mac(src) + struct.pack('!H', len(payload) if length is None else length) + payload

def pad(f, n=60):
    return f + b'\0' * max(0, n - len(f))

def main(out, verbose=False):
    fr, marks = [], []
    def add(desc, f, ifc=0):
        fr.append((ifc, f)); marks.append((len(fr), desc))
    # eth: LLC
    add('STP BPDU in LLC, zero padding to 60', pad(f8023(LLC_STP + bpdu(), STP_DST)))
    add('LLC SNAP IPv4/UDP, exact length', f8023(LLC_SNAP + udp4(0)))
    add('LLC SNAP IPv4/UDP, non-zero trailer', f8023(LLC_SNAP + udp4(1)) + b'\xc3' * 10)
    add('LLC SNAP IPv4/UDP with a short padding to 60', pad(f8023(LLC_SNAP + ip4('192.0.2.1', '192.0.2.2', 17, udp(1, 2, b'')))))
    # eth: IPX (first two octets 0xffff)
    add('IPX, exact length', f8023(ipx(b'ipx data')))
    add('IPX with padding', pad(f8023(ipx(b'p'))))
    # vlan, 802.1ad is not involved: 0x8100 tag followed by a length
    add('802.1Q, LLC STP BPDU', pad(f8023(LLC_STP + bpdu(), STP_DST)[:12] + struct.pack('!HH', 0x8100, 5)
                                 + struct.pack('!H', 3 + 35) + LLC_STP + bpdu()))
    add('802.1Q, LLC SNAP IPv4/UDP, trailer', mac(B) + mac(A) + struct.pack('!HHH', 0x8100, 6, len(LLC_SNAP + udp4(2)))
        + LLC_SNAP + udp4(2) + b'\x99' * 6)
    add('802.1Q, IPX', mac(B) + mac(A) + struct.pack('!HHH', 0x8100, 7, 33) + ipx())
    # vntag (0x8926)
    add('VNTAG, LLC STP BPDU', pad(mac(STP_DST) + mac(A) + struct.pack('!HIH', 0x8926, 0x00010002, 38) + LLC_STP + bpdu()))
    add('VNTAG, IPX', mac(B) + mac(A) + struct.pack('!HIH', 0x8926, 0x80030004, 33) + ipx())
    add('VNTAG, LLC SNAP IPv4/UDP, trailer', mac(B) + mac(A) + struct.pack('!HIH', 0x8926, 0, 8 + 20 + 8 + 12)
        + LLC_SNAP + udp4(3) + b'\x01\x02\x03')
    # gmhdr (0x22e5): header length 1 (no TLVs), then a length
    add('Gigamon header, LLC STP BPDU', pad(mac(STP_DST) + mac(A) + struct.pack('!HBH', 0x22e5, 1, 38) + LLC_STP + bpdu()))
    add('Gigamon header, IPX', mac(B) + mac(A) + struct.pack('!HBH', 0x22e5, 1, 33) + ipx())
    add('Gigamon header, LLC SNAP IPv4/UDP, trailer', mac(B) + mac(A) + struct.pack('!HBH', 0x22e5, 1, 8 + 20 + 8 + 12) + LLC_SNAP + udp4(4) + b'\x55' * 4)
    # FCS length 4 from the pcapng interface (interface 1): the FCS is removed
    # from the payload before the length is checked
    add('FCS interface: LLC STP BPDU with 4 octet FCS', pad(f8023(LLC_STP + bpdu(), STP_DST), 56) + b'\0' * 4, 1)
    add('FCS interface: IPX with 4 octet FCS', f8023(ipx(b'fcs')) + b'\xde\xad\xbe\xef', 1)
    # CCSDS Space Packets, recognised only with the eth.ccsds_heuristic_* preferences
    # (they decode as LLC with the defaults)
    add('CCSDS Space Packet (needs the eth CCSDS heuristics)', f8023(ccsds(20)))
    add('CCSDS Space Packet with padding', pad(f8023(ccsds(24))))
    os.makedirs(out, exist_ok=True)
    pcapng(os.path.join(out, 'ieee8023-coverage.pcapng'), fr, ifaces=(1, (1, 4)))
    # malformed
    m = []
    def addm(f, ifc=0): m.append((ifc, f))
    # length field larger than the payload (expert error)
    addm(f8023(LLC_STP + bpdu(), STP_DST, length=200))
    addm(mac(B) + mac(A) + struct.pack('!HHH', 0x8100, 5, 100) + LLC_STP + bpdu())          # vlan
    addm(mac(B) + mac(A) + struct.pack('!HIH', 0x8926, 0, 100) + LLC_STP + bpdu())          # vntag
    addm(mac(B) + mac(A) + struct.pack('!HBH', 0x22e5, 1, 100) + LLC_STP + bpdu())          # gmhdr
    # payload too short for the dissector it is given to (exception in the subdissector)
    addm(f8023(LLC_STP + bpdu()[:10]))
    addm(f8023(ipx()[:20]))
    addm(f8023(b'\xff\xff'))
    addm(f8023(b'\x01'))
    addm(f8023(b'', length=0))
    addm(f8023(ccsds(20)[:10]))
    # truncated captures: the trailer starts past the captured data
    f = f8023(LLC_SNAP + udp4(6)); m.append((0, f[:14 + 8 + 20], len(f)))
    f = f8023(ipx(b'x' * 30)); m.append((0, f[:14 + 30], len(f)))
    f = f8023(LLC_STP + bpdu()); m.append((0, f[:20], len(f)))
    addm(f8023(LLC_SNAP + udp4(5), length=len(LLC_SNAP + udp4(5)) + 2) + b'\0' * 4, 1)   # length goes past the data (FCS interface)
    # FCS interface: length field smaller than FCS, FCS but a short frame
    addm(f8023(LLC_STP + bpdu(), STP_DST)[:14 + 2] , 1)
    addm(f8023(b'\0') + b'\0\0\0\0', 1)
    pcapng(os.path.join(out, 'ieee8023-coverage-malformed.pcapng'), m, ifaces=(1, (1, 4)))
    if verbose:
        for n, d in marks: print(n, d)
        print(len(fr), 'frames;', len(m), 'malformed frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

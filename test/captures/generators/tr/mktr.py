#!/usr/bin/env python3
# Generates test/captures/tr_coverage.pcap.gz, tr_coverage_linux.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds tr-coverage.pcap, tr-coverage-linux.pcap (needs tr.fix_linux_botches:TRUE)
# and tr-coverage-malformed.pcap; all Token Ring (pcap linktype 6)
import struct
import sys
import os
from pcaplib import write, tr_frame, ipv4

def ip_udp(sport=1000, dport=2000, data=b'token ring'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    return ipv4(17, udp, src='198.51.100.1', dst='198.51.100.2')

SNAP_IP = b'\xaa\xaa\x03\x00\x00\x00\x08\x00'
def llc_ip(data=b'token ring'):
    return SNAP_IP + ip_udp(data=data)

def rif(n, bcast=0, size=1, direction=0, pairs=None):
    """Routing information field of n octets: RCF (broadcast type, length, direction, max frame size) + ring/bridge pairs."""
    rcf = struct.pack('BB', (bcast << 5) | n, (direction << 7) | (size << 4) | 0x0)
    body = pairs if pairs is not None else bytes((i * 17 + 3) & 0xff for i in range(n - 2))
    return rcf + body[:n - 2].ljust(n - 2, b'\0')

def main(out):
    fr = []
    T = lambda p, **kw: tr_frame(p, **kw)
    fr.append(T(llc_ip(), fc=0x40))                                           # 1 LLC SNAP IPv4, not source routed
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x800, 6, 4, 1, bytes(6), bytes(4), bytes(6), bytes(4))
    fr.append(T(b'\xaa\xaa\x03\x00\x00\x00\x08\x06' + arp, fc=0x40))          # 2 SNAP ARP
    # source routed frames: RCF only, and ring/bridge pairs of growing length
    for n, bc, sz, d in ((2, 0, 0, 0), (4, 1, 1, 1), (6, 2, 2, 0), (8, 3, 3, 1), (10, 4, 4, 0),
                         (14, 5, 5, 1), (20, 6, 6, 0), (30, 7, 7, 1)):
        fr.append(T(llc_ip(), fc=0x40, rif=rif(n, bc, sz, d)))               # 3-10
    fr.append(T(llc_ip(), fc=0x40, rif=rif(31, 4, 1, 0)))                     # 11 more RIF than the spec allows (extra bytes)
    fr.append(T(llc_ip(), fc=0x40, rif=rif(22, 0, 2, 0)))                     # 12
    # access control and frame control variants
    for i, ac in enumerate((0x00, 0x1f, 0x20, 0xe0, 0x08, 0x07, 0xff)):
        fr.append(T(llc_ip(), fc=0x40 | i, ac=ac))                            # 13-19 priority, frame bit, monitor count, reservation; PCF 0-6
    # LLC with other SAPs: NetBIOS UI, IPX (E0), SNAP with Cisco, null SAP, TEST, XID
    fr.append(T(b'\xf0\xf0\x03' + bytes(20), fc=0x40))                        # 20
    ipx = struct.pack('!HHBB', 0xffff, 30 + 4, 0, 0) + bytes(4) + b'\xff' * 6 + struct.pack('!H', 0x4005) + bytes(4) + bytes(range(6)) + struct.pack('!H', 0x4005) + b'data'
    fr.append(T(b'\xe0\xe0\x03' + ipx, fc=0x40))                              # 21
    fr.append(T(b'\x00\x00\xe3\x01\x02', fc=0x40))                            # 22 null SAP TEST
    fr.append(T(b'\xfc\xfc\xbf\x81\x01\x00', fc=0x40))                        # 23 XID
    fr.append(T(b'\x42\x42\x03\x00\x00\x00\x00\x00' + bytes(30), fc=0x40))    # 24 spanning tree SAP
    # MAC frames and reserved frame types
    fr.append(T(b'\x00\x04\x00\x05', fc=0x00, dst='c0:00:ff:ff:ff:ff'))   # 25 MAC: Active Monitor Present, no subvectors
    fr.append(T(bytes(range(40)), fc=0x80))                                   # 26 reserved frame type
    fr.append(T(bytes(range(20)), fc=0xc0))                                   # 27 type 3 ("Unknown")
    fr.append(T(llc_ip(), fc=0x40, src='40:00:00:00:00:09', dst='ff:ff:ff:ff:ff:ff'))   # 28 group destination
    fr.append(T(llc_ip(), fc=0x40, src='00:00:00:00:00:02', dst='00:00:00:00:00:01', rif=rif(2, 6, 7, 1)))   # 29
    # frame of exactly 15 octets (fixed header + one octet) and 16 octets
    write(os.path.join(out, 'tr-coverage.pcap'), fr, linktype=6)
    print('main frames', len(fr))

    # Linux 2.0.x workarounds (tr.fix_linux_botches:TRUE); decoded with the preference on
    L = []
    pad = lambda n: b'\x00' * n
    ipxpkt = lambda sock=0x4005: (struct.pack('!HHBB', 0xffff, 30 + 8, 0, 0) + bytes(4) + b'\xff' * 6 + struct.pack('!H', sock) +
                                   bytes(4) + bytes(range(6)) + struct.pack('!H', sock) + b'12345678')
    I = tr_frame(llc_ip(), fc=0x40)
    for x in (1, 2, 5, 9):                                                    # 1-4 the first x octets are repeated at offset x
        L.append(I[:x] + I)
    f = bytearray(tr_frame(pad(60), fc=0x40))                                 # not source routed, but RIF-looking octets and a SNAP after them
    f[14], f[15] = 0x02, 0x10
    f[16:24] = SNAP_IP
    f[24:24 + len(ip_udp())] = ip_udp()
    L.append(bytes(f[:24 + len(ip_udp())]))                                   # 5 AA AA 03
    for first2, ctrl in ((b'\xe0\xe0', b'\x03'), (b'\xe0\xaa', b'\x03')):
        h = bytearray(f[:16]) + first2 + ctrl + ipxpkt()
        L.append(bytes(h))                                                    # 6, 7 E0 E0 / E0 AA
    h = bytearray(f[:16]) + b'\x03' + pad(30)
    L.append(bytes(h))                                                        # 8 nothing recognisable after the RIF-looking octets
    h = bytearray(f[:16]) + SNAP_IP + ip_udp(); h[15] = 0x02
    L.append(bytes(h))                                                        # 9 first two octets equal: not tested
    # truncated records (captured 17 octets of 60): the checks beyond the captured data raise BoundsError, which is caught
    L.append((tr_frame(b'\x02\x10\x03', fc=0x40), 60))                        # 10
    # empty 18 octet RIF from the Linux 2.0.x driver: SNAP, IPX and the fake LLC/SNAP header
    g = bytearray(tr_frame(pad(80), fc=0x40))
    g[0x20:0x28] = SNAP_IP
    g[0x28:0x28 + len(ip_udp())] = ip_udp()
    L.append(bytes(g[:0x28 + len(ip_udp())]))                                 # 11 SNAP at 0x20
    L.append(bytes(tr_frame(pad(0x20 - 14), fc=0x40)) + b'\xe0\xe0\x03' + ipxpkt())   # 12 IPX at 0x20
    g3 = bytearray(tr_frame(pad(0x28 - 14), fc=0x40))
    g3[0x20:0x23] = b'\xf0\xf0\x03'; g3[0x27] = 0x11                         # fake LLC and SNAP with type 0x0011
    L.append(bytes(g3) + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ip_udp())            # 13 then the real LLC/SNAP
    g4 = bytearray(tr_frame(pad(0x20 - 16), fc=0x40, rif=rif(2, 0, 1, 0)))     # source routed with a 2 octet RIF
    L.append(bytes(g4) + SNAP_IP + ip_udp())                                  # 14 18 octet check, SR
    L.append(tr_frame(llc_ip(), fc=0x40, rif=rif(4, 0, 1, 0)))                # 15 SR with RIF of 4: no hack
    q = bytearray(range(0x30, 0x30 + 17)); q[1] = 0x41; q[14:17] = b'\x02\x10\x03'
    L.append((bytes(q), 60))                                                  # 16 17 distinct octets (the review reproducer, as LLC; truncated)
    q = bytearray(range(0x30, 0x30 + 19)); q[1] = 0x41; q[14:19] = b'\x02\x10\x11\x22\x00'
    L.append((bytes(q), 60))                                                        # 17 19 distinct octets
    write(os.path.join(out, 'tr-coverage-linux.pcap'), L, linktype=6)

    m = []
    m.append(T(b'\x00', fc=0x40))                                            # LLC with 1 octet
    m.append(bytes(range(0x30, 0x30 + 16)))                                   # 16 distinct octets: the reproducer of the old Linux check (MAC garbage)
    m.append(b'\x10\x40' + bytes(6) + bytes(6))                               # 14 octets: no RIF octet
    m.append(b'\x10\x40' + bytes(8))                                          # shorter than the header
    m.append(b'\x10')                                                         # one octet
    m.append(tr_frame(b'\x02\x70', fc=0x40, rif=rif(31, 0, 0, 0))[:16])       # RIF longer than the frame
    m.append(tr_frame(llc_ip()[:10], fc=0x40))                                # LLC and IP cut short
    write(os.path.join(out, 'tr-coverage-malformed.pcap'), m, linktype=6)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

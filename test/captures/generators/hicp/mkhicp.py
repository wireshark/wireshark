#!/usr/bin/env python3
# Generates test/captures/hicp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Writes the HICP coverage captures. Usage: mkhicp.py <outdir> [-v]
All packets are built with struct; addresses are from 192.0.2.0/24."""
import struct
import sys
import os

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
IP_BC = bytes([255, 255, 255, 255])


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.ipid = 0x2000

    def raw(self, frame):
        self.frames.append(frame)

    def udp(self, payload, sport=3250, dport=3250, src=IP_A, dst=IP_BC,
            smac=MAC_A, dmac=b"\xff" * 6):
        """One UDP datagram; fragmented into 1500 octet frames if big."""
        u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        self.ipid += 1
        off = 0
        step = 1480
        while off < len(u):
            chunk = u[off:off + step]
            more = 1 if off + step < len(u) else 0
            flags = (more << 13) | (off // 8)
            iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk),
                              self.ipid, flags, 64, 17, 0, src, dst)
            iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
            self.raw(dmac + smac + b"\x08\x00" + iph + chunk)
            off += step

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                t = 1000 + i
                f.write(struct.pack("<IIII", t, 0, len(fr), len(fr)))
                f.write(fr)


def main(outdir, verbose):
    c = Cap()
    marks = []

    def mark(name):
        marks.append((len(c.frames) + 1, name))

    def hp(s, **kw):
        c.udp(s.encode("latin-1") if isinstance(s, str) else s, **kw)

    # Requests
    mark("Module scan")
    hp("Module scan\0")
    hp("module scan\0")                       # case-insensitive
    mark("Configure")
    hp("Configure: 00-11-22-33-44-55;"
       "IP = 192.0.2.10;SN = 255.255.255.0;GW = 192.0.2.254;"
       "DHCP = OFF;HN = plc1;DNS1 = 192.0.2.53;DNS2 = 192.0.2.54;"
       "Password = secretplaceholder;New Password = placeholder2;"
       "New MAC = 00-11-22-33-44-66;\0")
    hp("Configure: 00-11-22-33-44-55;DHCP = ON;\0")
    hp("Configure = 00-11-22-33-44-55;\0")    # " = " separator
    mark("Wink")
    hp("Wink: 00-11-22-33-44-55;\0")
    hp("Wink\0")
    # Module scan response, all parameters
    mark("Module scan response")
    hp("Protocol version = 1.00;FB type = EtherNet/IP;Module version = 4.01.01;"
       "MAC = 00-11-22-33-44-55;IP = 192.0.2.10;SN = 255.255.255.0;"
       "GW = 192.0.2.254;DHCP = OFF;PSWD = OFF;HN = plc1;"
       "DNS1 = 192.0.2.53;DNS2 = 192.0.2.54;EXT = 1;\0",
       sport=3250, dport=3250, src=IP_B, dst=IP_A, smac=MAC_B, dmac=MAC_A)
    hp("Protocol version = 1.00;FB type = PROFINET IO;Module version = 3.12;"
       "MAC = 00-11-22-33-44-77;IP = 192.0.2.11;SN = 255.255.255.0;"
       "GW = 0.0.0.0;DHCP = ON;PSWD = ON;HN = plc2;"
       "DNS1 = 0.0.0.0;DNS2 = 0.0.0.0;EXT = 0;\0",
       src=IP_B, dst=IP_A, smac=MAC_B, dmac=MAC_A)
    hp("Protocol version = 1.00;MAC = 00-11-22-33-44-88;EXT = 5;\0",  # other EXT
       src=IP_B, dst=IP_A, smac=MAC_B, dmac=MAC_A)
    hp("Protocol version: 1.00;MAC: 00-11-22-33-44-99;IP: 192.0.2.12;\0",  # ": "
       src=IP_B, dst=IP_A, smac=MAC_B, dmac=MAC_A)
    # Configure / Wink responses
    mark("Responses")
    hp("To: 00-11-22-33-44-55;Reconfigured: 00-11-22-33-44-55;\0")
    hp("Reconfigured = 00-11-22-33-44-55;\0")
    hp("Invalid Password: 00-11-22-33-44-55;\0")
    hp("Invalid Configuration: 00-11-22-33-44-55;\0")
    hp("Executed: 00-11-22-33-44-55;\0")
    hp("To: 00-11-22-33-44-55;Executed = 00-11-22-33-44-55;\0")
    mark("Unknown and empty")
    hp("Vendor extension = x;\0")             # no keyword matches
    mark("Reproducer, quadratic parameter loop")
    hp(b";" * 64999 + b"\0")
    mark("end")
    main_n = len(c.frames)
    c.write(os.path.join(outdir, "hicp-coverage.pcap"))

    m = Cap()
    m.udp(b"\0")                              # one octet: no room for the SHICP check
    m.udp(b"Module scan")                      # no NUL: unterminated string
    m.udp(b"\xc0\xab\x01\x02\x03\x04\x05\x06")   # SHICP header: HICP declines
    m.udp(b"\xc1\xab\x01\x02\x03\x04\x05\x06")
    m.udp(b"M")                                # shorter than HICP_MIN_LENGTH
    m.udp(b"")                                 # empty datagram
    m.udp(b"MAC = \xff\xfe\x80;IP = \x80\x81;\0")      # bytes >= 0x80
    m.udp(b"Configure: 00;" + b"\xe9" * 40 + b"; IP = 1;Password = x;\0")
    m.write(os.path.join(outdir, "hicp-coverage-malformed.pcap"))
    if verbose:
        for n, name in marks:
            print(n, name)
        print("main frames", main_n)


if __name__ == "__main__":
    main(sys.argv[1], "-v" in sys.argv)

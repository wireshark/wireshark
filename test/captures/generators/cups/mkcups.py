#!/usr/bin/env python3
# Generates test/captures/cups_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CUPS Browsing Protocol
dissector (packet-cups.c).

CUPS browse packets are single text lines sent over UDP port 631:

    type state uri ["location" ["info" ["make-and-model"]]]\\n

where type and state are hexadecimal numbers. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcups.py <output directory>

Writes:
  cups-coverage.pcap            every printer type flag, every state, each
                                optional field present or absent, every
                                place where a line can end, the reproducer
                                of the printer type fix
  cups-coverage-malformed.pcap  lines that run off the end of the packet
"""

import os
import struct
import sys

SRC = (192, 0, 2, 1)
BCAST = (192, 0, 2, 255)
PORT = 631


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp(sport, dport, data, src, dst):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    return hdr[:6] + struct.pack('>H', c) + data


def frame(data, ident, src=SRC, dst=BCAST):
    return (bytes.fromhex('ffffffffffff020000000001') + b'\x08\x00'
            + ipv4(17, udp(PORT, PORT, data, src, dst), src, dst, ident))


def write_pcap(path, payloads):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(payloads):
            d = frame(p, i + 1)
            f.write(struct.pack('<IIII', 1700000000 + i * 30, 0, len(d), len(d)) + d)


URI = b'ipp://192.0.2.1:631/printers/'

MAIN = [
    # 1-2: the reproducer of the printer type fix (
    # cups_ptype_ascii.py): type 3 (class and remote, no other flag) and
    # a type of 9 hex digits, which made every flag malformed before.
    b'3 3 ' + URI + b'p "loc" "info" "model"\n',
    b'000000002 3 ' + URI + b'p "loc" "info" "model"\n',
    # 3: every flag set (0x3ffff), lower case hex, state idle
    b'3ffff 3 ' + URI + b'all "Room 101" "Every option" "ACME LaserJet 9000"\n',
    # 4: local single printer, no flags, state processing
    b'0 4 ' + URI + b'none "Lab" "Nothing" "Generic"\n',
    # 5: alternating flags (upper case hex), state stopped, CRLF line end
    b'2AAAA 5 ' + URI + b'even "Hall" "Even bits" "Model E"\r\n',
    # 6: the other alternating flags, an unknown state, several spaces
    b'15555   a   ' + URI + b'odd   "Hall"   "Odd bits"   "Model O"\n',
    # 7: implicit class with default, empty quoted strings
    b'30003 3 ' + URI + b'implicit "" "" ""\n',
    # 8-12: the optional fields end the line at each place
    b'1006 3 ' + URI + b'p1 "Location only"\n',
    b'1006 3 ' + URI + b'p2 "Loc" "Info"\n',
    b'1006 3 ' + URI + b'p3\n',
    b'1006 3 ' + URI + b'p4 "Loc" "Info" \n',
    b'1006 3 ' + URI + b'p5 "Loc" \r\n',
    # 13-16: a location and an info that are not quoted strings, an
    # unterminated quote, a tab after the URI
    b'1006 3 ' + URI + b'p6 Loc "Info" "Model"\n',
    b'1006 3 ' + URI + b'p6a "Loc" Info "Model"\n',
    b'1006 3 ' + URI + b'p7 "Loc" "Info" "unterminated\n',
    b'1006 3 ' + URI + b'p8\t"Loc"\n',
    # 17: the URI runs to the end of the packet (no whitespace after it)
    b'1006 3 ' + URI + b'p9',
    # 18-20: the line ends after the type, after the state, before the type
    b'1006\n',
    b'1006 3\r\n',
    b'\n',
    # 21-22: a type that is not hexadecimal, a state that is not
    # hexadecimal (both have length 0 and are not shown)
    b'xyz 3 ' + URI + b'p10 "Loc"\n',
    b'2 idle ' + URI + b'p11\n',
    # 23: a long make and model (the protocol allows 1450 octets)
    b'801e 3 ' + URI + b'long "Building 7, floor 3" "Shared printer" "'
    + b'ACME ' * 200 + b'"\n',
]

MALFORMED = [
    # The type runs to the end of the packet
    b'1006',
    # Spaces run to the end after the type
    b'1006   ',
    # The state runs to the end
    b'1006 3',
    # Spaces run to the end after the URI
    b'1006 3 ' + URI + b'p ',
    # A quoted location runs to the end after its closing quote
    b'1006 3 ' + URI + b'p "Loc"',
    # Spaces run to the end after the info
    b'1006 3 ' + URI + b'p "Loc" "Info"  ',
    # An empty payload
    b'',
]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cups-coverage.pcap'), MAIN)
    write_pcap(os.path.join(out, 'cups-coverage-malformed.pcap'), MALFORMED)


if __name__ == '__main__':
    main()

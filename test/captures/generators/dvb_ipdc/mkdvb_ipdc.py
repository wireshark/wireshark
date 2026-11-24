#!/usr/bin/env python3
# Generates test/captures/dvb_ipdc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DVB IPDC (ESG bootstrap) coverage capture: FLUTE/ALC packets
over IPv4/UDP to port 9214 on Ethernet (linktype 1).
Usage: mkdvb_ipdc.py <outdir>"""
import os
import struct
import sys

PORT = 9214


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth_ipv4_udp(src, dst, sport, dport, payload, ident):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", csum(ph + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0x4000,
                     16, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    mac = bytes([0x01, 0x00, 0x5e, dst[1] & 0x7f, dst[2], dst[3]])
    return mac + bytes([2, 0, 0, 0, 0, 1]) + b"\x08\x00" + ip + udp


def alc(tsi, toi, payload, fdt_id=None, sbn=0, esi=0, close_obj=False):
    """ALC/LCT v1, no congestion control info beyond 32 bits, 32 bit TSI
    and TOI (S=1, O=01, H=0), codepoint 0 (Compact No-Code FEC), an
    optional EXT_FDT header extension, then the FEC payload ID."""
    ext = b""
    if fdt_id is not None:
        ext = struct.pack("!I", (192 << 24) | (2 << 20) | fdt_id)
    hdr_len = (16 + len(ext)) // 4
    flags = (1 << 12) | (0 << 10) | (0 << 8) | (1 << 7) | (1 << 5) | \
        (1 if close_obj else 0)
    lct = struct.pack("!HBB", flags, hdr_len, 0) + struct.pack(
        "!III", 0, tsi, toi) + ext
    return lct + struct.pack("!HH", sbn, esi) + payload


DISCOVERY = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
             b'<ESGProviderDiscovery><ServiceProvider>'
             b'<ProviderURI>urn:example</ProviderURI>'
             b'</ServiceProvider></ESGProviderDiscovery>\n')

FDT = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
       b'<FDT-Instance Expires="3900000000" '
       b'xmlns="urn:IETF:metadata:2005:FLUTE:FDT">\n'
       b'<File TOI="1" Content-Location="ESGProviderDiscovery.xml" '
       b'Content-Length="%d" Content-Type="text/xml"/>\n'
       b'</FDT-Instance>\n') % len(DISCOVERY)

SRC = bytes([192, 0, 2, 10])
DST = bytes([224, 0, 23, 14])


def build():
    frames = []
    # 1: FDT instance (TOI 0) announcing the ESG provider discovery file
    frames.append(eth_ipv4_udp(SRC, DST, 40000, PORT,
                               alc(1, 0, FDT, fdt_id=1), 1))
    # 2-3: the discovery file (TOI 1) in two encoding symbols, the second
    # closing the object
    frames.append(eth_ipv4_udp(SRC, DST, 40000, PORT,
                               alc(1, 1, DISCOVERY[:64]), 2))
    frames.append(eth_ipv4_udp(SRC, DST, 40000, PORT,
                               alc(1, 1, DISCOVERY[64:], esi=1,
                                   close_obj=True), 3))
    return frames


def build_malformed():
    # 1: only the first LCT octets
    return [eth_ipv4_udp(SRC, DST, 40000, PORT, b"\x10\x00", 4)]


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "dvb-ipdc-coverage.pcap"), build())
    write_pcap(os.path.join(out, "dvb-ipdc-coverage-malformed.pcap"),
               build_malformed())

#!/usr/bin/env python3
# Generates test/captures/nflog_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# mknflog.py <outdir> [-v]: writes nflog-coverage.pcap and nflog-coverage-malformed.pcap
# (link type 239, LINKTYPE_NFLOG). TLV length and type are host (little) endian.
import struct
import sys
import os
import socket

def tlv(t, v, flag=0):
    ln = 4 + len(v)
    return struct.pack("<HH", ln, t | flag) + v + b"\0" * (-ln % 4)

def hdr(fam=2, ver=0, res=0x1234):
    return struct.pack(">BBH", fam, ver, res)

def ip4(payload=b"", proto=17, src="192.0.2.1", dst="192.0.2.2"):
    l = 20 + len(payload)
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, l, 1, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    s = sum(struct.unpack(">10H", h))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return h[:10] + struct.pack(">H", (~s) & 0xffff) + h[12:] + payload

def udp(sp, dp, data):
    return struct.pack(">HHHH", sp, dp, 8 + len(data), 0) + data

def ip6(payload=b"", nxt=17):
    return struct.pack(">IHBB16s16s", 0x60000000, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                       socket.inet_pton(socket.AF_INET6, "2001:db8::2")) + payload

def eth(proto, payload=b""):
    return bytes.fromhex("020000000002020000000001") + struct.pack(">H", proto) + payload

P4 = ip4(udp(40000, 9, b"nflog test"))
P6 = ip6(udp(40000, 9, b"nflog v6"))
TS = struct.pack(">QQ", 1700000000, 123456)

def pkthdr(proto=0x0800, hook=1):
    return tlv(1, struct.pack(">HBB", proto, hook, 0))

def u32(t, v):
    return tlv(t, struct.pack(">I", v))

def frames():
    fr, sec = [], []
    def add(n, f):
        sec.append((n, len(fr) + 1, len(fr) + len(f)))
        fr.extend(f)
    # full log record: every attribute, payload inside the TLV
    full = (pkthdr(0x0800, 3) + u32(2, 0xabcd) + tlv(3, TS) + u32(4, 2) + u32(5, 3) + u32(6, 4) + u32(7, 5)
            + tlv(8, struct.pack(">H", 6) + b"\0\0" + bytes.fromhex("020000000001") + b"\0\0")
            + tlv(10, b"IN-eth0: \0") + u32(11, 1000) + u32(12, 7) + u32(13, 8) + u32(14, 100) + tlv(15, struct.pack(">H", 1))
            + tlv(17, struct.pack(">H", 14)) + tlv(18, b"ct-state new\0") + u32(19, 2)
            + tlv(21, b"\x01\x02\x03\x04\x05\x06\x07")
            + tlv(16, eth(0x0800)) + tlv(9, P4))
    # attributes in kernel order (hwheader after payload as the kernel emits)
    kern = (pkthdr(0x0800, 1) + u32(4, 2) + u32(5, 3) + tlv(3, TS) + tlv(10, b"FW-DROP:\0") + tlv(16, eth(0x0800)) +
            tlv(9, P4) + u32(12, 99) + u32(14, 0) + tlv(17, struct.pack(">H", 14)) + tlv(15, struct.pack(">H", 1)))
    add("full records", [hdr() + full, hdr(2, 0, 0) + kern, hdr(10, 0, 5) + pkthdr(0x86dd, 0) + tlv(9, P6)])
    # payload dissected by family when there is no packet header
    add("family only", [hdr(2) + tlv(9, P4), hdr(10) + tlv(9, P6), hdr(3) + tlv(9, b"\x01\x02\x03\x04"),
                        hdr(12) + tlv(9, b"arp"), hdr(7) + tlv(9, b"bridge"), hdr(0) + tlv(9, b"x")])
    # hardware protocol selects the payload dissector; unknown ethertype goes to data
    add("hw protocol", [hdr(2) + pkthdr(0x0800) + tlv(9, P4), hdr(10) + pkthdr(0x86dd) + tlv(9, P6),
                        hdr(2) + pkthdr(0x1234) + tlv(9, b"\xde\xad\xbe\xef"),
                        hdr(2) + pkthdr(0x0806) + tlv(9, bytes.fromhex("0001080006040001") + bytes(20)),
                        hdr(2) + pkthdr(0x0800) + tlv(9, P4[:20])])
    # hardware header: Ethernet when the hardware protocol is IP, else data; header before payload
    add("hw header", [hdr(2) + pkthdr(0x0800) + tlv(16, eth(0x0800)) + tlv(9, P4),
                      hdr(2) + pkthdr(0x86dd) + tlv(16, eth(0x86dd)) + tlv(9, P6),
                      hdr(2) + tlv(16, eth(0x0800, P4)),
                      hdr(2) + pkthdr(0x0800) + tlv(16, eth(0x0800, P4)),
                      hdr(2) + pkthdr(0x0800) + tlv(16, eth(0x0806, bytes(28))) + tlv(9, P4)])
    # every attribute with a wrong length goes to the unknown value; lengths that are valid in two forms
    bad = []
    bad.append(hdr() + tlv(1, b"\x08\x00\x01") + tlv(4, b"\x01") + tlv(5, b"\x01\x02\x03\x04\x05") + tlv(6, b"") +
               tlv(7, b"\x01\x02") + tlv(10, b"") + tlv(11, b"\x01\x02\x03") + tlv(14, b"\x01") + tlv(3, TS[:8]) +
               tlv(15, b"\x01") + tlv(18, b"") + tlv(19, b"\x01\x02"))
    bad.append(hdr() + tlv(1, b"\x08\x00\x01\x00\x00\x00") + tlv(17, b"\x01\x02\x03") + tlv(17, struct.pack(">I", 14)) +
               tlv(15, b"\x01\x02\x03") + tlv(15, b"\x01\x02") + tlv(2, b"\x01") + tlv(2, struct.pack(">I", 7)))
    add("short and odd values", bad)
    # types without a decoder, the nested flag (bit 15), unknown types, values of every size mod 4
    odd = []
    odd.append(hdr() + tlv(0, b"") + tlv(20, b"\x01\x02\x03\x04") + tlv(22, b"zz") + tlv(255, b"\1\2\3\4\5"))
    odd.append(hdr() + tlv(2, struct.pack(">I", 1), flag=0x8000) + tlv(10, b"nested\0", flag=0x8000) +
               tlv(9, P4, flag=0x4000))
    odd.append(hdr() + b"".join(tlv(10, b"p" * n) for n in range(1, 9)) + tlv(9, P4))
    odd.append(hdr() + tlv(12, struct.pack(">I", 1)) + tlv(18, b"c" * 5))
    add("unknown types and padding", odd)
    # the header alone, a header plus fewer than 4 octets, and a TLV length below 4 (stops decoding)
    add("stop conditions", [hdr(), hdr() + b"\x08\x00\x01", hdr() + struct.pack("<HH", 3, 1) + pkthdr(0x0800) + tlv(9, P4),
                            hdr() + struct.pack("<HH", 0, 9) + tlv(9, P4), hdr() + pkthdr(0x0800) + struct.pack("<HH", 2, 9)])
    return fr, sec

def malformed():
    fr = []
    # TLV length past the packet (payload / hwheader subsets and the generic items)
    fr.append(hdr() + struct.pack("<HH", 200, 9) + P4)
    fr.append(hdr() + struct.pack("<HH", 100, 16) + b"\x01\x02")
    fr.append(hdr() + pkthdr(0x0800) + struct.pack("<HH", 64, 9) + P4[:20])
    fr.append(hdr() + struct.pack("<HH", 0xffff, 11) + b"abc")
    fr.append(hdr() + struct.pack("<HH", 40, 3) + b"\x01\x02\x03\x04")
    fr.append(hdr() + struct.pack("<HH", 20, 1) + b"\x08\x00\x01\x00")
    # truncated header, empty packet
    fr.append(b"\x02\x00")
    fr.append(b"")
    # payload that is itself broken
    fr.append(hdr() + tlv(9, P4[:12]))
    fr.append(hdr() + pkthdr(0x86dd) + tlv(9, P6[:30]))
    fr.append(hdr(2) + pkthdr(0x0800) + tlv(9, b""))
    fr.append(hdr(2) + pkthdr(0x0800) + tlv(16, b"") + tlv(9, P4))
    fr.append(hdr(2) + pkthdr(0x0800) + tlv(16, b"\x01\x02\x03") + tlv(9, P4))
    fr.append(hdr(2) + pkthdr(0x0800) + tlv(16, eth(0x0800)))
    fr.append(hdr() + pkthdr(0x0800) + tlv(16, b"\x01" * 6) + tlv(9, P4))
    return fr

def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 239))
        for i, p in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)

out = sys.argv[1] if len(sys.argv) > 1 else "."
fr, sec = frames()
write_pcap(os.path.join(out, "nflog-coverage.pcap"), fr)
m = malformed()
write_pcap(os.path.join(out, "nflog-coverage-malformed.pcap"), m)
if "-v" in sys.argv:
    for n, a, b in sec:
        print("%-26s frames %d-%d" % (n, a, b))
    print("main %d frames, malformed capture %d frames" % (len(fr), len(m)))

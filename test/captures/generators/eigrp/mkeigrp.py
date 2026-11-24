#!/usr/bin/env python3
# Generates test/captures/eigrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EIGRP dissector
(packet-eigrp.c, RFC 7868).

EIGRP runs over IPv4 and IPv6 (IP protocol 88), IPX (socket 0x85BE)
and AppleTalk DDP (type 88), all registered by default. A packet is a
20 octet header (version, opcode, checksum, flags, sequence and
acknowledgement numbers, virtual router ID, AS) and TLVs: the general
TLVs (parameters, authentication, sequence, software version, next
multicast sequence, stub, termination, topology ID list), the legacy
IPv4, IPv6, IPX and AppleTalk route TLVs, the multi-topology (MTR)
TLVs and the wide metric multi-protocol TLVs with extended attributes
and SAF services. IPX/SAP updates go to the IPX SAP dissector.

The authentication TLV carries made-up digest octets: the dissector
only shows them, nothing is computed or checked.

Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkeigrp.py <output directory>

Writes:
  eigrp-coverage.pcap            every opcode, TLV, address family,
                                 attribute and community type, the
                                 reproducers of the fixed offsets
  eigrp-coverage-malformed.pcap  TLV lengths below 4, truncated TLVs,
                                 bad sequence address lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from pkt import (LINKTYPE_ETHERNET, csum16, eth, ip4, ip6, ipv4, ipv6,
                 write_pcap)

R1, R2 = "192.0.2.1", "192.0.2.2"
MCAST = "224.0.0.10"

# ------------------------------------------------------------ framing


def eigrp(opcode, tlvs, flags=0, seq=0, ack=0, vrid=0, asn=100, ver=2,
          bad_checksum=False):
    body = b"".join(tlvs)
    hdr = struct.pack(">BBHIIIHH", ver, opcode, 0, flags, seq, ack, vrid, asn)
    c = csum16(hdr + body)
    if bad_checksum:
        c ^= 0x5555
    return hdr[:2] + struct.pack(">H", c) + hdr[4:] + body


def over_ipv4(pkt, src=R1, dst=MCAST, n=1):
    dmac = 0x0a if dst == MCAST else 2
    return eth(ipv4(pkt, 88, src, dst, ttl=1 if dst == MCAST else 64,
                    ident=n), 0x0800, 1, dmac)


def over_ipv6(pkt):
    return eth(ipv6(pkt, 88, "fe80::1", "ff02::a", 255), 0x86DD, 1, 0x0a)


def over_ipx(pkt):
    """Ethernet II, IPX header to socket 0x85BE."""
    ln = 30 + len(pkt)
    hdr = struct.pack(">HHBB", 0xFFFF, ln, 0, 4)
    hdr += struct.pack(">I", 0x10) + b"\xff" * 6 + struct.pack(">H", 0x85BE)
    hdr += struct.pack(">I", 0x10) + bytes([2, 0, 0, 0, 0, 1]) + struct.pack(">H", 0x85BE)
    return eth(hdr + pkt, 0x8137, 1, 0xff)


def over_ddp(pkt):
    """802.3 with LLC/SNAP (Apple OUI, PID 0x809B), long DDP header, DDP
    type 88."""
    ddp = struct.pack(">HHHHBBBBB", 13 + len(pkt), 0, 100, 100, 0xff, 1,
                      88, 88, 88) + pkt
    llc = b"\xaa\xaa\x03\x08\x00\x07\x80\x9b" + ddp
    fr = b"\x09\x00\x07\xff\xff\xff" + bytes([2, 0, 0, 0, 0, 1]) + struct.pack(">H", len(llc)) + llc
    if len(fr) < 60:
        fr += b"\0" * (60 - len(fr))
    return fr


# ------------------------------------------------------------- TLVs


def tlv(t, v, length=None):
    return struct.pack(">HH", t, 4 + len(v) if length is None else length) + v


def param(k=(1, 0, 1, 0, 0, 0), hold=15):
    return tlv(0x0001, bytes(k) + struct.pack(">H", hold))


def auth(atype, alen, digest, keyid=1, keyseq=7):
    return tlv(0x0002, struct.pack(">HHII", atype, alen, keyid, keyseq) +
               b"\0" * 8 + digest)


def seq_tlv(addrs):
    return tlv(0x0003, b"".join(bytes([len(a)]) + a for a in addrs))


def sw_version(ios=(12, 4), eigrp_=(2, 0)):
    return tlv(0x0004, bytes(ios + eigrp_))


def legacy_metric(delay=2560, bw=25600, mtu=1500, hops=1, rel=255, load=1,
                  intag=0, flags=0):
    return (struct.pack(">II", delay, bw) + struct.pack(">I", mtu)[1:] +
            bytes([hops, rel, load, intag, flags]))


def extdata(origrid="192.0.2.99", asn=200, tag=5, metric=20, proto=6,
            flags=0x03):
    return (ip4(origrid) + struct.pack(">IIIHBB", asn, tag, metric, 0,
                                       proto, flags))


def ipx_extdata(proto=4, flags=0x02):
    return (bytes([2, 0, 0, 0, 0, 9]) + struct.pack(">IIBBHH", 300, 7, proto,
                                                    flags, 3, 4))


def v4dest(plen, addr):
    nbytes = (plen + 7) // 8
    return bytes([plen]) + ip4(addr)[:nbytes]


def v6dest(plen, addr):
    """IPv6 destination as the dissector reads it: whole prefix octets,
    plus one octet when the prefix is a multiple of 8 below 128."""
    nbytes = (plen + 7) // 8
    if plen < 128 and plen % 8 == 0:
        nbytes += 1
    return bytes([plen]) + (ip6(addr) + b"\0")[:nbytes]


def dests(*d):
    """Several destinations in one TLV. The dissector steps over the
    prefix length octet twice (packet-eigrp.c:1098/1113 and 1152/1165),
    so it skips one octet after each destination; one padding octet
    between the destinations keeps the next one where it looks for it.
    (The unpadded form is in the malformed capture.)"""
    return b"\xee".join(d)


def wide_metric(attrs=b"", prio=0, rel=255, load=1, mtu=1500, hops=0,
                delay=1000000, bw=100000, flags=0):
    hdr = bytes([len(attrs) // 2, prio, rel, load]) + struct.pack(">I", mtu)[1:]
    hdr += bytes([hops]) + struct.pack(">Q", delay)[2:] + struct.pack(">Q", bw)[2:]
    hdr += struct.pack(">HH", 0, flags << 8)
    return hdr + attrs


def attr(op, data):
    return bytes([op, len(data) // 2]) + data


def comm(ctype, data6):
    return struct.pack(">H", ctype) + data6


def nexthop(afi):
    if afi in (1, 16385):
        return ip4("192.0.2.254")
    if afi in (2, 16386):
        return ip6("2001:db8::fe")
    if afi == 11:
        return struct.pack(">I", 0x20) + bytes([2, 0, 0, 0, 0, 0x20])
    return b""


def service(svc=101, sub=1, dtype=1, data=b"", afi=1, seq=1):
    if afi == 1:
        addr = ip4("192.0.2.80") + b"\0" * 12
    elif afi == 2:
        addr = ip6("2001:db8::80")
    else:
        addr = bytes(range(16))
    reach = struct.pack(">HHH", afi, 5060, 17) + addr
    return (struct.pack(">HH", svc, sub) + bytes(range(0x10, 0x20)) +
            struct.pack(">HH", dtype, len(data)) + reach +
            struct.pack(">I", seq) + data)


def mp_tlv(t, afi, dest, metric=None, ext=None, tid=0, rid="192.0.2.1"):
    v = struct.pack(">HH", tid, afi) + ip4(rid)
    v += wide_metric() if metric is None else metric
    v += nexthop(afi)
    if t & 0xf == 3:
        v += (ipx_extdata() if afi == 11 else extdata()) if ext is None else ext
    return tlv(t, v + dest)


def mtr_tlv(t, afi, dest, tid=2):
    v = b"\0\0" + struct.pack(">HH", tid, afi) + ip4("192.0.2.1")
    v += struct.pack(">I", 0x77) + legacy_metric() + nexthop(afi)
    if t & 0xf == 3:
        v += ipx_extdata() if afi == 11 else extdata()
    return tlv(t, v + dest)


# ------------------------------------------------------------ packets


def main_frames():
    F = []
    n = [0]

    def v4(pkt, dst=MCAST):
        n[0] += 1
        F.append(over_ipv4(pkt, R1, dst, n[0]))

    # 1: Hello: parameters, software version, stub with every flag
    v4(eigrp(5, [param(), sw_version(), tlv(0x0006, b"\x00\x3f")]))
    # 2: Hello with an acknowledgement number (shown as Hello (Ack)),
    #    unicast, multicast VRID
    v4(eigrp(5, [], ack=11, vrid=0x0001), R2)
    # 3: Hello with every flag, a sequence TLV (IPv4, IPX and IPv6
    #    addresses), next multicast sequence, peer termination parameters
    #    (K1-K5 255), graceful peer termination, topology ID lists
    #    (0x0008 and the MTR 0x00f5)
    v4(eigrp(5, [param((255, 255, 255, 255, 255, 255), 0),
                 seq_tlv([ip4(R2), struct.pack(">I", 0xAABBCCDD) +
                          bytes([2, 0, 0, 0, 0, 0x44]),
                          ip6("2001:db8::2")]),
                 tlv(0x0005, struct.pack(">I", 1234)),
                 tlv(0x0007, b""),
                 tlv(0x0008, struct.pack(">HHHH", 0, 4, 0, 2)),
                 tlv(0x00f5, struct.pack(">HH", 1, 0))],
             flags=0x0f, seq=20, vrid=0x8000))
    # 4: the fix "EIGRP: Fix the community attribute and IPX sequence
    #    address offsets", IPX part: a sequence TLV with an IPv4 address
    #    and then an IPX address, which was formatted from offset 1 of
    #    the TLV instead of its own offset.
    v4(eigrp(5, [seq_tlv([ip4(R2), struct.pack(">I", 0x00000123) +
                          bytes([2, 0, 0, 0, 0, 0x99])])], seq=21))
    # 5: authentication: MD5 (16 octets) and SHA-256 (32 octets) digests,
    #    shown as opaque octets
    v4(eigrp(5, [auth(2, 16, bytes(range(0xA0, 0xB0))), param()]))
    v4(eigrp(5, [auth(3, 32, bytes(range(0x40, 0x60)), keyid=2), param()]))
    # 7: authentication type NONE, TEXT and unknown (warnings)
    v4(eigrp(5, [auth(0, 0, b""), auth(1, 8, b"password"),
                 auth(9, 0, b"")]))
    # 8: Update with the INIT flag and classic IPv4 routes: request,
    #    internal (/24, /0, /32 and /16 in one TLV), external, community
    v4(eigrp(1, [tlv(0x0101, ip4("0.0.0.0") + legacy_metric() + v4dest(24, "198.51.100.0")),
                 tlv(0x0102, ip4("0.0.0.0") + legacy_metric(flags=0x0f) +
                     dests(v4dest(24, "198.51.100.0"), v4dest(0, "0.0.0.0"),
                           v4dest(32, "198.51.100.7"), v4dest(16, "203.0.0.0"))),
                 tlv(0x0103, ip4("192.0.2.9") + extdata() + legacy_metric() +
                     v4dest(8, "10.0.0.0")),
                 tlv(0x0104, ip4("0.0.0.0") + legacy_metric() + v4dest(20, "198.18.0.0"))],
             flags=1, seq=30), R2)
    # 9: Query, Reply, SIA-Query, SIA-Reply, Request, Probe, Stub-Info and
    #    ACK opcodes, unknown VRID 0x8001
    for op in (3, 4, 10, 11, 2, 7, 9, 8):
        v4(eigrp(op, [tlv(0x0102, ip4("0.0.0.0") + legacy_metric(delay=0xFFFFFFFF) +
                          v4dest(24, "198.51.100.0"))] if op in (3, 4) else [],
                 seq=31 + op, ack=30, vrid=0x8001), R2)
    # 17: unknown opcode, version 1, bad checksum (warning)
    v4(eigrp(0x20, [], ver=1, bad_checksum=True))
    # 18: unknown general TLV 0x000a and unknown TLV group 0x0500
    #     (warnings)
    v4(eigrp(5, [tlv(0x000a, b"\x01\x02"), tlv(0x0500, b"\x03\x04"), param()]))

    # 19: IPv6 Update over IPv6: internal (/64, /128, /0, /33), external
    #     and community routes
    F.append(over_ipv6(eigrp(1, [
        tlv(0x0402, ip6("::") + legacy_metric() +
            dests(v6dest(64, "2001:db8:1::"), v6dest(128, "2001:db8::7"),
                  v6dest(0, "::"), v6dest(33, "2001:db8:8000::"))),
        tlv(0x0403, ip6("fe80::2") + extdata(proto=9) + legacy_metric() +
            v6dest(48, "2001:db8:2::")),
        tlv(0x0404, ip6("::") + legacy_metric() + v6dest(56, "2001:db8:300::"))],
        seq=40)))

    # 20: IPX Update over IPX: internal and external routes
    F.append(over_ipx(eigrp(1, [
        tlv(0x0302, nexthop(11) + legacy_metric() + struct.pack(">I", 0x30)),
        tlv(0x0303, nexthop(11) + ipx_extdata() + legacy_metric() + struct.pack(">I", 0x31))],
        seq=50)))
    # 21: IPX/SAP update over IPX: handed to the IPX SAP dissector
    sap = struct.pack(">HH", 2, 4) + b"PRINTSRV".ljust(48, b"\0") + \
        struct.pack(">I", 0x30) + bytes([2, 0, 0, 0, 0, 3]) + struct.pack(">HH", 0x0451, 1)
    F.append(over_ipx(eigrp(6, [sap], seq=51)))

    # 22: AppleTalk over DDP: an external route (the cable range shown in
    #     the summary is read from fixed offsets 36/38) and a cable
    #     configuration TLV
    F.append(over_ddp(eigrp(1, [
        tlv(0x0203, struct.pack(">I", 0x00640001) + extdata() + legacy_metric() +
            struct.pack(">HH", 100, 110)),
        tlv(0x0204, struct.pack(">HHI", 100, 200, 0x0A000001))], seq=60)))

    # 23: multi-protocol (wide metric) TLVs: request, internal, external
    #     and community for IPv4, every metric flag, infinite delay and
    #     bandwidth
    v4(eigrp(1, [
        mp_tlv(0x0601, 1, v4dest(24, "198.51.100.0")),
        mp_tlv(0x0602, 1, dests(v4dest(24, "198.51.100.0"), v4dest(32, "198.51.100.1")),
               metric=wide_metric(prio=1, flags=0x0f, delay=0xFFFFFFFFFFFF,
                                  bw=0xFFFFFFFFFFFF)),
        mp_tlv(0x0603, 1, v4dest(16, "10.1.0.0")),
        mp_tlv(0x0604, 1, v4dest(8, "10.0.0.0"))], seq=70), R2)
    # 24: wide metric attributes: no-op, scaled, tag, jitter, energies,
    #     an unknown attribute
    attrs = (attr(0, b"") + attr(1, struct.pack(">I", 0x100)) +
             attr(2, struct.pack(">I", 42)) + attr(4, struct.pack(">I", 7)) +
             attr(5, struct.pack(">I", 8)) + attr(6, struct.pack(">I", 9)) +
             attr(9, b"\xab\xcd"))
    v4(eigrp(1, [mp_tlv(0x0602, 1, v4dest(24, "198.51.100.0"),
                        metric=wide_metric(attrs))], seq=71), R2)
    # 25: the fix, community part: community attributes of every type
    #     and an unknown type. The 8 octet community was read with the
    #     offset and remaining length of the attribute list, so it read
    #     the wrong octets and threw.
    ctypes = (0x8800, 0x8806, 0x8801, 0x8802, 0x8803, 0x8804, 0x8805,
              0x0003, 0x0103, 0x4444)
    attrs = b"".join(attr(3, comm(c, struct.pack(">HI", i, 0x01000000 + i)))
                     for i, c in enumerate(ctypes))
    v4(eigrp(1, [mp_tlv(0x0603, 1, v4dest(24, "198.51.100.0"),
                        metric=wide_metric(attrs))], seq=72), R2)
    # 26: wide metric TLVs for IPv6 (internal, external) and IPX
    #     (internal, external)
    v4(eigrp(1, [
        mp_tlv(0x0602, 2, v6dest(64, "2001:db8:1::")),
        mp_tlv(0x0603, 2, v6dest(48, "2001:db8:2::")),
        mp_tlv(0x0602, 11, struct.pack(">I", 0x40)),
        mp_tlv(0x0603, 11, struct.pack(">I", 0x41))], seq=73), R2)
    # 27: SAF services (service family, IPv4 and IPv6 service family):
    #     XML data, plain text data, no data; reachability IPv4, IPv6,
    #     other
    xml = b"  <capability version=\"1\"/>"
    v4(eigrp(1, [
        mp_tlv(0x0602, 16384, service(100, 1, 1, xml, 1)),
        mp_tlv(0x0602, 16385, service(101, 2, 2, b"plain service text", 2) +
               service(102, 3, 1, b"", 7)),
        mp_tlv(0x0603, 16386, service(103, 4, 1, b"x", 1))],
        vrid=0x8000, seq=74), R2)
    # 28: unknown address family in a wide metric TLV (warning)
    v4(eigrp(1, [mp_tlv(0x0602, 99, b"\x01\x02\x03")], seq=75), R2)

    # 29: multi-topology (MTR) TLVs: request, internal, external,
    #     community for IPv4
    v4(eigrp(1, [mtr_tlv(0x00f1, 1, v4dest(24, "198.51.100.0")),
                 mtr_tlv(0x00f2, 1, v4dest(24, "198.51.100.0")),
                 mtr_tlv(0x00f3, 1, v4dest(16, "10.2.0.0")),
                 mtr_tlv(0x00f4, 1, v4dest(8, "10.0.0.0"))], seq=80), R2)
    # 30: MTR for IPv6, IPX (internal and external) and SAF; unknown AFI
    #     (warning)
    v4(eigrp(1, [mtr_tlv(0x00f2, 2, v6dest(64, "2001:db8:5::")),
                 mtr_tlv(0x00f3, 2, v6dest(64, "2001:db8:6::")),
                 mtr_tlv(0x00f2, 11, struct.pack(">I", 0x50)),
                 mtr_tlv(0x00f3, 11, struct.pack(">I", 0x51)),
                 mtr_tlv(0x00f2, 16385, service(100, 1, 1, b"", 1)),
                 mtr_tlv(0x00f2, 77, b"")], seq=81), R2)
    return F


def malformed_frames():
    F = []
    # 1: TLV length below 4 (error)
    F.append(over_ipv4(eigrp(5, [param(), struct.pack(">HH", 0x0001, 2)])))
    # 2: sequence TLV with an address length of 6 (error)
    F.append(over_ipv4(eigrp(5, [seq_tlv([b"\x01" * 6])])))
    # 3: sequence TLV shorter than its address (error)
    F.append(over_ipv4(eigrp(5, [tlv(0x0003, b"\x10\x01\x02")])))
    # 4: AppleTalk internal route: the cable range in the summary is read
    #    at offset 36, past the end of the 24 octet value
    F.append(over_ddp(eigrp(1, [tlv(0x0202, struct.pack(">I", 0x00640001) +
                                    legacy_metric() + struct.pack(">HH", 1, 2))])))
    # 5: TLV length beyond the packet
    F.append(over_ipv4(eigrp(1, [tlv(0x0102, ip4("0.0.0.0") + legacy_metric(), 200)])))
    # 6: wide metric attribute list longer than the TLV
    F.append(over_ipv4(eigrp(1, [mp_tlv(0x0602, 1, b"",
                                        metric=wide_metric(b"\x02\x02\x00\x00\x00\x2a")[:-6] +
                                        b"\x03\x10")])))
    # 7: peer topology ID list longer than the TLV
    F.append(over_ipv4(eigrp(5, [tlv(0x0008, struct.pack(">HHH", 0, 10, 1))])))
    # 8: header only, cut in the AS number
    F.append(over_ipv4(eigrp(5, [])[:18]))
    # 9: MD5 and SHA-256 digests of the wrong length (malformed group
    #    warnings)
    F.append(over_ipv4(eigrp(5, [auth(2, 8, b"\x01" * 8),
                                 auth(3, 16, b"\x02" * 16)])))
    # 10: classic IPv4 route with a prefix length above 32 (warning)
    F.append(over_ipv4(eigrp(1, [tlv(0x0102, ip4("0.0.0.0") + legacy_metric() +
                                     b"\x21\x01\x02\x03\x04")]), R1, R2))
    # 11: IPv6 route with a prefix length above 128 (warning)
    F.append(over_ipv6(eigrp(1, [tlv(0x0402, ip6("::") + legacy_metric() +
                                     b"\x81" + b"\0" * 16)])))
    # 12-13: two IPv4 and two IPv6 destinations back to back in one TLV,
    #       as RFC 7868 encodes them: the dissector skips the first
    #       octet of the second one and reports an invalid prefix length
    #       (warning) or shows a wrong address
    F.append(over_ipv4(eigrp(1, [tlv(0x0102, ip4("0.0.0.0") + legacy_metric() +
                                     v4dest(24, "198.51.100.0") + v4dest(24, "203.0.113.0"))]), R1, R2))
    F.append(over_ipv6(eigrp(1, [tlv(0x0402, ip6("::") + legacy_metric() +
                                     bytes([64]) + ip6("2001:db8:1::")[:8] +
                                     bytes([64]) + ip6("2001:db8:2::")[:8])])))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "eigrp-coverage.pcap"), main_frames(),
               LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, "eigrp-coverage-malformed.pcap"),
               malformed_frames(), LINKTYPE_ETHERNET)


if __name__ == "__main__":
    main()

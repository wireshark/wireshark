# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers shared by the coverage generators: pcap writing,
Ethernet, IPv4, IPv6, UDP and TCP headers with correct checksums, and
Exported PDU records. Everything is built with struct; nothing comes
from a real network."""
import struct

LINKTYPE_ETHERNET = 1
LINKTYPE_ENC = 109
LINKTYPE_MPEG_2_TS = 243
LINKTYPE_WIRESHARK_UPPER_PDU = 252


def write_pcap(path, frames, linktype, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                            linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def eth(payload, ethertype, src=1, dst=2):
    fr = mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload
    if len(fr) < 60:
        fr += b"\0" * (60 - len(fr))
    return fr


def ip4(a):
    return bytes(int(x) for x in a.split("."))


def ipv4(payload, proto, src="192.0.2.1", dst="192.0.2.2", ttl=64, ident=1):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                      0x4000, ttl, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack("!H", csum16(hdr)) + hdr[12:]
    return hdr + payload


def ip6(a):
    import ipaddress
    return ipaddress.IPv6Address(a).packed


def ipv6(payload, nh, src="2001:db8::1", dst="2001:db8::2", hlim=64):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, hlim,
                       ip6(src), ip6(dst)) + payload


def _pseudo4(src, dst, proto, length):
    return ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, length)


def udp(payload, sport, dport, src="192.0.2.1", dst="192.0.2.2"):
    ln = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, ln, 0)
    c = csum16(_pseudo4(src, dst, 17, ln) + hdr + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, ln, c) + payload


def udp6(payload, sport, dport, src="2001:db8::1", dst="2001:db8::2"):
    ln = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, ln, 0)
    ph = ip6(src) + ip6(dst) + struct.pack("!IxxxB", ln, 17)
    c = csum16(ph + hdr + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, ln, c) + payload


def tcp(payload, sport, dport, seq, ack, flags=0x18, src="192.0.2.1",
        dst="192.0.2.2", win=65535):
    # SYNs carry the MSS and SACK permitted options and no
    # acknowledgement number
    opts = (struct.pack("!BBHBBBB", 2, 4, 1460, 1, 1, 4, 2)
            if flags & 0x02 else b"")
    if not flags & 0x10:
        ack = 0
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts
    c = csum16(_pseudo4(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    return hdr + payload


class TcpFlow:
    """A TCP connection between a client and a server: handshake and
    data segments in both directions with the right sequence numbers."""

    def __init__(self, cip, sip, cport, sport, cmac=1, smac=2):
        self.c = (cip, cport, cmac)
        self.s = (sip, sport, smac)
        self.seq = {True: 1000, False: 5000}

    def _seg(self, from_client, payload, flags):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        seg = tcp(payload, a[1], b[1], self.seq[from_client],
                  self.seq[not from_client], flags, a[0], b[0])
        self.seq[from_client] = (self.seq[from_client] + len(payload) +
                                 (1 if flags & 0x03 else 0)) & 0xFFFFFFFF
        return eth(ipv4(seg, 6, a[0], b[0]), 0x0800, a[2], b[2])

    def handshake(self):
        f = [self._seg(True, b"", 0x02)]
        f.append(self._seg(False, b"", 0x12))
        f.append(self._seg(True, b"", 0x10))
        return f

    def data(self, from_client, payload):
        return self._seg(from_client, payload, 0x18)


def exp_pdu(name, payload):
    """Exported PDU with a dissector name tag."""
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return (struct.pack("!HH", 12, len(n) + pad) + n + b"\0" * pad +
            struct.pack("!HH", 0, 0) + payload)

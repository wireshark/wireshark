#!/usr/bin/env python3
# Generates test/captures/hiqnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Writes the HiQnet coverage captures. Usage: mkhiqnet.py <outdir> [-v]
All packets are built with struct; addresses are from 192.0.2.0/24."""
import struct
import sys
import os

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
PORT = 3804

REQACK, ACK, INFO, ERROR, GUAR, MULTI, SESSION = 0x1, 0x2, 0x4, 0x8, 0x20, 0x40, 0x100


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def u16s(s):
    """UCS-2 big endian string."""
    return s.encode("utf-16-be")


def lstr(s):
    """Length (in octets) and UCS-2 string."""
    b = u16s(s)
    return struct.pack("!H", len(b)) + b


def vd(*a):
    return bytes(a)


def pdu(msgid, payload=b"", flags=0, src=(0x1001, 1, 2, 3, 4), dst=(0x2002, 5, 6, 7, 8),
        hop=1, seq=1, err=None, multi=None, sess=None, ver=2, mlen=None, hlen=None):
    opt = b""
    if err is not None:
        opt += struct.pack("!B", err[0]) + u16s(err[1])
        flags |= ERROR
    if multi is not None:
        opt += struct.pack("!BI", *multi)
        flags |= MULTI
    if sess is not None:
        opt += struct.pack("!H", sess)
        flags |= SESSION
    h = 25 + len(opt)
    total = h + len(payload)
    return (struct.pack("!BBI", ver, h if hlen is None else hlen,
                        total if mlen is None else mlen)
            + struct.pack("!H", src[0]) + bytes(src[1:])
            + struct.pack("!H", dst[0]) + bytes(dst[1:])
            + struct.pack("!HHBH", msgid, flags, hop, seq) + opt + payload)


def data(t, v=None):
    """A data item of datatype t."""
    b = struct.pack("!B", t)
    if t == 0:
        return b + struct.pack("!b", -5)
    if t == 1:
        return b + struct.pack("!B", 200)
    if t == 2:
        return b + struct.pack("!h", -1234)
    if t == 3:
        return b + struct.pack("!H", 54321)
    if t == 4:
        return b + struct.pack("!i", -123456)
    if t == 5:
        return b + struct.pack("!I", 4000000000)
    if t == 6:
        return b + struct.pack("!f", 0.5)
    if t == 7:
        return b + struct.pack("!d", -0.25)
    if t == 8:
        return b + struct.pack("!H", 5) + b"\x01\x02\x03\x04\x05"
    if t == 9:
        return b + lstr("Fader")
    if t == 10:
        return b + struct.pack("!q", -(1 << 40))
    if t == 11:
        return b + struct.pack("!Q", 1 << 60)
    return b                                  # invalid datatype, no value


SERNUM = b"\x00\x1a\x2b\x3c\x4d\x5e\x6f\x70"
TCPIP = struct.pack("!B", 1) + MAC_B + b"\x01" + IP_B + bytes([255, 255, 255, 0]) + bytes([192, 0, 2, 254])
RS232 = struct.pack("!BBIBBBB", 4, 2, 115200, 1, 2, 8, 2)
OTHER_NET = struct.pack("!B", 2)


def sernum(sn=SERNUM):
    return struct.pack("!H", len(sn)) + sn


class Cap:
    def __init__(self):
        self.frames = []
        self.ipid = 0x3000
        self.tcp_seq = {}

    def n(self):
        return len(self.frames) + 1

    def udp(self, payload, sport=3804, dport=PORT, src=IP_A, dst=IP_B):
        u = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        self.ipid += 1
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(u), self.ipid, 0, 64, 17, 0, src, dst)
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        self.frames.append(MAC_B + MAC_A + b"\x08\x00" + iph + u)

    def tcp(self, payload=b"", flags=0x18, sport=40000, dport=PORT, reverse=False,
            seq=None, ack=None):
        key = (sport, dport)
        st = self.tcp_seq.setdefault(key, [999, 5000])
        src, dst = (IP_B, IP_A) if reverse else (IP_A, IP_B)
        smac, dmac = (MAC_B, MAC_A) if reverse else (MAC_A, MAC_B)
        if reverse:
            a, b = dport, sport
            s, k = st[1], st[0]
        else:
            a, b = sport, dport
            s, k = st[0], st[1]
        if seq is not None:
            s = seq
        opts = b"\x02\x04\x05\xb4" if flags & 2 else b""
        t = struct.pack("!HHIIBBHHH", a, b, s, k if flags & 0x10 else 0,
                        0x50 + len(opts) * 4, flags, 8192, 0, 0) + opts + payload
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(t))
        t = t[:16] + struct.pack("!H", csum(pseudo + t)) + t[18:]
        adv = len(payload) + (1 if flags & 3 else 0)
        if reverse:
            st[1] += adv
        else:
            st[0] += adv
        self.ipid += 1
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(t), self.ipid, 0, 64, 6, 0, src, dst)
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        self.frames.append(dmac + smac + b"\x08\x00" + iph + t)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)))
                f.write(fr)


def main(outdir, verbose):
    c = Cap()
    marks = []

    def mark(name):
        marks.append((c.n(), name))

    mark("Routing layer")
    # DiscoInfo with the three network info forms
    for net in (TCPIP, RS232, OTHER_NET):
        c.udp(pdu(0x0000, struct.pack("!HB", 0x1001, 3) + sernum()
                  + struct.pack("!IH", 1500, 30) + net, flags=INFO))
    c.udp(pdu(0x0001))                                           # reserved
    c.udp(pdu(0x0003))
    c.udp(pdu(0x0002, sernum()))                                 # GetNetworkInfo request
    c.udp(pdu(0x0002, sernum() + struct.pack("!H", 3)
              + struct.pack("!I", 1500) + TCPIP
              + struct.pack("!I", 1000) + RS232
              + struct.pack("!I", 500) + OTHER_NET, flags=INFO))
    c.udp(pdu(0x0002, sernum() + struct.pack("!H", 0), flags=INFO))
    c.udp(pdu(0x0004, struct.pack("!H", 0x1234)))                # RequestAddress
    c.udp(pdu(0x0005))                                           # AddressUsed
    c.udp(pdu(0x0006, sernum() + struct.pack("!H", 0x1234) + TCPIP))   # SetAddress
    c.udp(pdu(0x0006, sernum() + struct.pack("!H", 0x1235) + RS232))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001)))                # Goodbye
    c.udp(pdu(0x0008, struct.pack("!HH", 0x4321, 0x0101)))       # Hello
    c.udp(pdu(0x0008, struct.pack("!HH", 0x4322, 0x0000), flags=INFO))
    c.udp(pdu(0x7777, b"\x01\x02\x03"))                          # unknown message ID
    mark("Header options")
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), flags=REQACK | GUAR))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), flags=ACK | INFO))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), err=(0x03, "Bad device")))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), err=(0x06, "")))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), multi=(7, 1024)))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), sess=0xabcd, hop=5, seq=0xfffe))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), multi=(8, 2048), sess=0x1111))
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001), err=(0x01, "V"), multi=(9, 3000)))
    mark("Parameters")
    # MultiParamSet: every data type, then an invalid one
    c.udp(pdu(0x0100, struct.pack("!H", 12)
              + b"".join(struct.pack("!H", 0x100 + t) + data(t) for t in range(12))))
    c.udp(pdu(0x0100, struct.pack("!H", 1) + struct.pack("!H", 0x200) + data(99)))
    c.udp(pdu(0x0100, struct.pack("!H", 0)))
    # MultiParamGet request and reply
    c.udp(pdu(0x0103, struct.pack("!H", 2) + struct.pack("!H", 1) + struct.pack("!H", 2)))
    c.udp(pdu(0x0103, struct.pack("!H", 3) + struct.pack("!H", 1) + data(6)
              + struct.pack("!H", 2) + data(9) + struct.pack("!H", 3) + data(8), flags=INFO))
    # MultiObjectParamSet (the object address now goes into the object tree)
    c.udp(pdu(0x0101, struct.pack("!H", 2)
              + vd(1, 2, 3, 4) + struct.pack("!H", 2)
              + struct.pack("!H", 10) + data(6) + struct.pack("!H", 11) + data(1)
              + vd(5, 6, 7, 8) + struct.pack("!H", 1)
              + struct.pack("!H", 20) + data(9)))
    # ParamSetPercent
    c.udp(pdu(0x0102, struct.pack("!H", 2) + struct.pack("!HH", 1, 0x4000)
              + struct.pack("!Hh", 2, -16384)))
    mark("Attributes")
    c.udp(pdu(0x010d, struct.pack("!H", 3) + struct.pack("!HHH", 0, 1, 2)))     # request
    c.udp(pdu(0x010d, struct.pack("!H", 3) + struct.pack("!H", 0) + data(9)
              + struct.pack("!H", 1) + data(9) + struct.pack("!H", 3) + data(8), flags=INFO))
    c.udp(pdu(0x010e, struct.pack("!H", 2) + struct.pack("!H", 1) + data(9)
              + struct.pack("!H", 4) + data(5)))
    mark("Subscriptions")
    sub = (struct.pack("!HB", 0x10, 1) + bytes([1, 2, 3, 4, 5, 6]) + struct.pack("!H", 0x20)
           + b"\x00" + b"\x00\x00" + struct.pack("!H", 100))
    c.udp(pdu(0x010f, struct.pack("!H", 2) + sub + sub))                     # MultiParamSubscribe
    c.udp(pdu(0x0111, struct.pack("!H", 1) + sub))                           # ParamSubscribePercent
    c.udp(pdu(0x0112, struct.pack("!H", 2) + struct.pack("!HH", 1, 2) + struct.pack("!HH", 3, 4)))
    c.udp(pdu(0x0113, struct.pack("!H", 0x1001) + vd(1, 2, 3, 4)
              + struct.pack("!BHH", 0, 50, 0x0001)))                         # ParamSubscribeAll
    c.udp(pdu(0x0114, struct.pack("!H", 0x1001) + vd(1, 2, 3, 4) + b"\x01"))  # ParamUnsubscribeAll
    mark("Event log")
    c.udp(pdu(0x0115, struct.pack("!HI", 1024, 0x00004ffe)))                 # all categories
    c.udp(pdu(0x0115, struct.pack("!HI", 512, 0x00000002)))
    c.udp(pdu(0x012b, struct.pack("!I", 0x00000104)))                        # Unsubscribe
    c.udp(pdu(0x012c, b""))                                                  # RequestEventLog
    ev1 = (struct.pack("!HHBI", 7, 0x0005, 1, 100) + lstr("12:34:56") + lstr("2026-01-02")
           + lstr("Invalid Parameter") + struct.pack("!H", 3) + b"\xde\xad\x00")
    ev2 = (struct.pack("!HHBI", 3, 0x0011, 0, 101) + lstr("12:34:57") + lstr("2026-01-02")
           + lstr("Not a Router") + struct.pack("!H", 0))
    c.udp(pdu(0x012c, struct.pack("!H", 2) + ev1 + ev2, flags=INFO))         # reply (the fix)
    c.udp(pdu(0x012c, struct.pack("!H", 0), flags=INFO))
    mark("Virtual devices, scenes, locate")
    c.udp(pdu(0x011a, lstr("Group/Path")))                                  # GetVDList request
    c.udp(pdu(0x011a, lstr("Group/Path") + struct.pack("!H", 2)
              + struct.pack("!BH", 1, 0x1000) + struct.pack("!BH", 2, 0x2000), flags=INFO))
    c.udp(pdu(0x0124, struct.pack("!BH", 2, 5) + lstr("Scenes/A") + b"\x01"))     # Store
    c.udp(pdu(0x0125, struct.pack("!BH", 3, 6) + lstr("Snaps/B") + b"\x02"))      # Recall
    c.udp(pdu(0x0129, struct.pack("!H", 0xffff) + sernum()))                      # Locate on
    c.udp(pdu(0x0129, struct.pack("!H", 0x0000) + sernum()))
    mark("Two PDUs in one datagram")
    c.udp(pdu(0x0007, struct.pack("!H", 0x1001)) + pdu(0x0005) + pdu(0x0004, struct.pack("!H", 9)))

    mark("TCP")
    c.tcp(flags=0x02)
    c.tcp(flags=0x12, reverse=True)
    c.tcp(flags=0x10)
    p1 = pdu(0x0008, struct.pack("!HH", 0x4321, 0x0101))
    c.tcp(p1)
    c.tcp(flags=0x10, reverse=True)
    # Two PDUs in one segment
    c.tcp(pdu(0x0007, struct.pack("!H", 0x1001)) + pdu(0x0005), reverse=True)
    # One PDU over two segments, followed by a PDU
    big = pdu(0x0100, struct.pack("!H", 12)
              + b"".join(struct.pack("!H", 0x100 + t) + data(t) for t in range(12)))
    c.tcp(big[:40])
    c.tcp(big[40:] + pdu(0x0005))
    # The header split after 4 octets (needs 6 for the length)
    q = pdu(0x0129, struct.pack("!H", 0xffff) + sernum())
    c.tcp(q[:4], reverse=True)
    c.tcp(q[4:], reverse=True)
    mark("end")
    main_n = len(c.frames)
    c.write(os.path.join(outdir, "hiqnet-coverage.pcap"))

    m = Cap()
    # Header length shorter than the optional headers: error string length
    m.udp(pdu(0x0007, struct.pack("!H", 1), err=(1, "abc"), hlen=20))
    # Truncated PDUs
    m.udp(pdu(0x0100, struct.pack("!H", 5) + struct.pack("!H", 1) + data(6)))
    m.udp(pdu(0x0000, struct.pack("!HB", 1, 3) + struct.pack("!H", 100) + b"ab"))
    m.udp(pdu(0x012c, struct.pack("!H", 3) + struct.pack("!HHBI", 1, 2, 1, 5) + struct.pack("!H", 400), flags=INFO))
    m.udp(pdu(0x0100, struct.pack("!H", 1) + struct.pack("!H", 1) + data(9)[:3]))
    m.udp(pdu(0x0100, struct.pack("!H", 1) + struct.pack("!H", 1) + data(8)[:-3]))
    m.udp(pdu(0x0006, sernum()))
    # Message length shorter than the header / longer than the datagram
    m.udp(pdu(0x0007, struct.pack("!H", 1), mlen=10))
    m.udp(pdu(0x0007, struct.pack("!H", 1), mlen=5000))
    m.udp(pdu(0x0007, struct.pack("!H", 1), mlen=0))
    m.udp(pdu(0x0007, struct.pack("!H", 1), mlen=0xffffffff))   # -1: to the end of the datagram, offset wraps
    m.udp(pdu(0x0007, struct.pack("!H", 1), mlen=0xfffffff0))
    m.udp(pdu(0x0007, b"")[:20])                     # cut inside the header
    # Datagram with a trailing partial PDU
    m.udp(pdu(0x0005) + pdu(0x0005)[:10])
    # Counts bigger than the data
    m.udp(pdu(0x0100, struct.pack("!H", 65535)))
    m.udp(pdu(0x010d, struct.pack("!H", 65535)))
    m.udp(pdu(0x010d, struct.pack("!H", 65535), flags=INFO))
    m.udp(pdu(0x012c, struct.pack("!H", 65535), flags=INFO))
    m.udp(pdu(0x0101, struct.pack("!H", 65535)))
    m.udp(pdu(0x010f, struct.pack("!H", 65535)))
    m.udp(pdu(0x0112, struct.pack("!H", 65535)))
    m.udp(pdu(0x0002, sernum() + struct.pack("!H", 65535), flags=INFO))
    m.udp(pdu(0x011a, lstr("x") + struct.pack("!H", 65535), flags=INFO))
    # TCP with a PDU length of 0 / below the header
    m.tcp(flags=0x02)
    m.tcp(flags=0x12, reverse=True)
    m.tcp(flags=0x10)
    m.tcp(pdu(0x0007, struct.pack("!H", 1), mlen=3))
    m.write(os.path.join(outdir, "hiqnet-coverage-malformed.pcap"))
    if verbose:
        for n, name in marks:
            print(n, name)
        print("main frames", main_n)


if __name__ == "__main__":
    main(sys.argv[1], "-v" in sys.argv)

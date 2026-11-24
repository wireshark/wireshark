#!/usr/bin/env python3
# Generates test/captures/rftap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the RFtap coverage captures (packet-rftap.c).

Usage: mkrftap.py [-v] [outdir]   (writes rftap-coverage.pcap and
rftap-coverage-malformed.pcap, built with struct only).

RFtap is reached by default through the UDP heuristic dissector
"RFtap over UDP" (enabled by default, any port, "RFta" magic), so no
Decode As is needed. The sub-dissector is chosen by DLT (pcap_pktdata) or
by the dissector name tag. Nothing comes from a real network.
"""
# ---- classic pcap / pcapng writers and Ethernet/IPv4/UDP helpers ----
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Cap:
    """Frames of one or more interfaces; written as pcap (one link type) or pcapng."""
    def __init__(self, linktype=1, snaplen=262144):
        self.links = [linktype]; self.snap = snaplen
        self.frames = []; self.ts = 1700000000.0; self.ipid = 1
    def iface(self, linktype):
        self.links.append(linktype); return len(self.links) - 1
    def raw(self, data, iface=0):
        self.frames.append((self.ts, bytes(data), iface)); self.ts += 0.01
        return len(self.frames)
    def ip(self, src, dst, proto, payload):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), self.ipid, 0, 64, proto, 0,
                        bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, ipkt, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02', et=0x0800):
        return d + s + struct.pack('!H', et) + ipkt
    def udp(self, src, dst, sp, dp, payload, iface=0):
        u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
        return self.raw(self.eth(self.ip(src, dst, 17, u)), iface)
    def write(self, path):
        if len(self.links) == 1:
            with open(path, 'wb') as f:
                f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, self.snap, self.links[0]))
                for ts, d, _ in self.frames:
                    f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(d), len(d)) + d)
        else:
            def blk(t, body):
                body += b'\0' * ((-len(body)) % 4)
                return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
            out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
            for lt in self.links:
                out += blk(1, struct.pack('<HHI', lt, 0, self.snap))
            for ts, d, i in self.frames:
                t = int(ts * 1e6)
                out += blk(6, struct.pack('<IIIII', i, t >> 32, t & 0xffffffff, len(d), len(d)) + d)
            open(path, 'wb').write(out)

A, B = '192.0.2.10', '192.0.2.20'

def sip(body, call='c11call'):
    h = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n'
         'Contact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (call, call, len(body)))
    return h.encode() + body

def sdp(port, pt, rtpmap=None, media='video'):
    s = ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
         'm=%s %d RTP/AVP %d\r\n' % (media, port, pt))
    if rtpmap:
        s += 'a=rtpmap:%d %s\r\n' % (pt, rtpmap)
    return s.encode()

_seq = [100]
def rtp(payload, pt, marker=0):
    _seq[0] += 1
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, _seq[0], _seq[0] * 3000, 0x1234) + payload

def exp_pdu(name, payload):
    """Exported PDU (link type 252) naming a registered dissector (tags padded to 4)."""
    n = name.encode(); pad = (-len(n)) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

# ---- RFtap headers ----
MAGIC = 0x61744652

def rftap(flags, fields=b"", tag=b"", payload=b"", len32=None):
    """RFtap header: magic, length in 32 bit words, 16 bit flags, the fixed
    flag-driven fields, then optional tagged parameters (padded to 4 octets)."""
    body = struct.pack("<IHH", MAGIC, 0, flags) + fields + tag
    body += b"\0" * ((-len(body)) % 4)
    n = len(body) // 4 if len32 is None else len32
    return body[:4] + struct.pack("<H", n) + body[6:] + payload

def name_tag(name, tag_id=16, tag_len=None, tag_flags=255):
    n = name.encode()
    return struct.pack("<HBB", tag_id, len(n) if tag_len is None else tag_len, tag_flags) + n

F_DLT, F_FREQ, F_NOM, F_OFS, F_DBM, F_SIG, F_NOISE, F_SNR, F_QUAL, F_UNIX, F_TIME, F_DUR, F_LOC = [1 << i for i in range(13)]

def all_fields(dbm=True, unix=True):
    flags = F_DLT | F_FREQ | F_NOM | F_OFS | F_SIG | F_NOISE | F_SNR | F_QUAL | F_TIME | F_DUR | F_LOC
    if dbm: flags |= F_DBM
    if unix: flags |= F_UNIX
    f = struct.pack("<I", 195)                                       # DLT: IEEE 802.15.4 with FCS
    f += struct.pack("<ddd", 2.4e9 + 5e6, 2.405e9, 1250.0)          # frequency, nominal frequency, frequency offset
    f += struct.pack("<fff", -42.5, -96.25, 53.75)                  # signal power, noise power, SNR
    f += struct.pack("<I", 1000)                                     # signal quality
    f += struct.pack("<dd", 1700000000.0, 0.125)                     # time (integer and fractional seconds)
    f += struct.pack("<d", 0.0025)                                   # duration
    f += struct.pack("<ddd", -33.875, 151.25, 58.5)                  # latitude, longitude, altitude
    return flags, f

def ip4_udp(payload, sp=1234, dp=5678, src="198.51.100.1", dst="198.51.100.2"):
    u = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(u), 7, 0, 64, 17, 0,
                    bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + u

# an IEEE 802.15.4 data frame (PAN 0x1234, short addresses 0x0001 -> 0x0002) with FCS
def ieee802154(payload=b"hello"):
    payload = b"\x00" + payload          # 00xxxxxx: not a LoWPAN frame, no 6LoWPAN parsing
    f = struct.pack("<HBHHH", 0x8861, 5, 0x1234, 0x0002, 0x0001) + payload
    crc = 0
    for b in f:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return f + struct.pack("<H", crc)

def eth_frame(payload):
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + payload


# ---- main ----
PORT = 52001

def build(outdir, verbose=False):
    c = Cap(1)
    marks = []
    def mark(n): marks.append((len(c.frames) + 1, n))
    def send(p, sp=40000, dp=PORT):
        return c.udp(A, B, sp, dp, p)
    mark("header only (no DLT, no name): the payload is shown as data")
    send(rftap(0, payload=b"plain data"))
    mark("DLT 195 (IEEE 802.15.4 with FCS), DLT 1 (Ethernet), DLT 101 (raw IP), DLT 147 (no dissector)")
    send(rftap(F_DLT, struct.pack("<I", 195), payload=ieee802154()))
    send(rftap(F_DLT, struct.pack("<I", 1), payload=eth_frame(ip4_udp(b"ethernet payload"))))
    send(rftap(F_DLT, struct.pack("<I", 101), payload=ip4_udp(b"raw ip payload")))
    send(rftap(F_DLT, struct.pack("<I", 147), payload=b"user dlt data"))
    mark("every parameter: frequencies, power in dBm and in dB, SNR, quality, time, duration, location")
    fl, fd = all_fields(dbm=True, unix=True)
    send(rftap(fl, fd, payload=ieee802154(b"all fields")))
    fl, fd = all_fields(dbm=False, unix=False)
    send(rftap(fl, fd, payload=ieee802154(b"dB, no unix time")))
    mark("single parameters")
    send(rftap(F_FREQ, struct.pack("<d", 868.3e6), payload=b"freq"))
    send(rftap(F_NOM | F_OFS, struct.pack("<dd", 868e6, -300.0), payload=b"nominal"))
    send(rftap(F_DBM | F_SIG | F_NOISE, struct.pack("<ff", -10.0, -90.0), payload=b"dbm"))
    send(rftap(F_SNR | F_QUAL, struct.pack("<fI", 20.0, 0xffffffff), payload=b"snr"))
    send(rftap(F_TIME | F_DUR, struct.pack("<dddd", 1.0, 0.5, 1e-6, 0.0), payload=b"time"))
    send(rftap(F_LOC, struct.pack("<ddd", 0.0, 0.0, 0.0), payload=b"loc"))
    mark("reserved parameter bits 13-15: parsing stops at the first one")
    for bit in (13, 14, 15):
        send(rftap((1 << bit) | F_FREQ, struct.pack("<d", 1e9) + b"\0\0\0\0", payload=b"reserved"))
    mark("dissector name tag: ip, eth_withoutfcs, an unknown name, the name together with a DLT")
    send(rftap(0, tag=name_tag("ip"), payload=ip4_udp(b"named ip")))
    send(rftap(0, tag=name_tag("eth_withoutfcs"), payload=eth_frame(ip4_udp(b"named eth"))))
    send(rftap(F_FREQ, struct.pack("<d", 5.8e9), tag=name_tag("nosuchdissector"), payload=b"unknown name"))
    send(rftap(F_DLT, struct.pack("<I", 195), tag=name_tag("ip"), payload=ieee802154(b"DLT wins")))
    mark("tag that is ignored: another id, length 0, length 255, flags not 255")
    send(rftap(0, tag=name_tag("ip", tag_id=17), payload=b"tag id 17"))
    send(rftap(0, tag=name_tag("ip", tag_len=0), payload=b"tag len 0"))
    send(rftap(0, tag=struct.pack("<HBB", 16, 255, 255) + b"\0" * 8, payload=b"tag len 255"))
    send(rftap(0, tag=name_tag("ip", tag_flags=0), payload=b"tag flags 0"))
    mark("RFtap nested through the dissector name tag (the reproducer of the fixed pointer cast): 8 layers, the innermost names ip")
    nest = ip4_udp(b"innermost")
    inner = rftap(0, tag=name_tag("ip"), payload=nest)
    for _ in range(7):
        inner = rftap(0, tag=name_tag("rftap"), payload=inner)
    send(inner)
    mark("RFtap nested through DLT 101 (raw IP, UDP, RFtap), 3 levels")
    lvl = rftap(F_DLT, struct.pack("<I", 147), payload=b"deep")
    for _ in range(2):
        lvl = rftap(F_DLT, struct.pack("<I", 101), payload=ip4_udp(lvl, dp=PORT))
    send(lvl)
    mark("not RFtap: wrong magic, fewer than 8 octets (the UDP heuristic declines)")
    send(b"RFtX" + bytes(12))
    send(b"RFta\x02\x00")
    c.write(os.path.join(outdir, "rftap-coverage.pcap"))
    n = len(c.frames)
    # malformed: header longer than the datagram, cut parameters, too deep nesting
    m = Cap(1)
    def msend(p): m.udp(A, B, 40000, PORT, p)
    fl, fd = all_fields()
    for cut in (0, 1, 4, 5, 12, 20, 36, 48, 60, 70):
        msend(rftap(fl, fd[:cut]))                       # header cut inside the parameters
    msend(rftap(fl, fd, len32=200))                      # length beyond the datagram
    msend(rftap(F_DLT, b"\x01"))
    msend(rftap(0, tag=name_tag("ip", tag_len=40)))      # name longer than the header
    msend(rftap(0, tag=struct.pack("<HB", 16, 3)))       # tag cut
    for depth in (9, 12):
        inner = rftap(0, tag=name_tag("data"), payload=b"end")
        for _ in range(depth - 1):
            inner = rftap(0, tag=name_tag("rftap"), payload=inner)
        msend(inner)                                     # more than 8 nested layers: expert info, no recursion
    m.write(os.path.join(outdir, "rftap-coverage-malformed.pcap"))
    if verbose:
        for i, (f, nme) in enumerate(marks):
            e = marks[i + 1][0] - 1 if i + 1 < len(marks) else n
            print("%4d-%-4d %s" % (f, e, nme))
        print("main %d frames, malformed %d frames" % (n, len(m.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)

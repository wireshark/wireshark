# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers for the MPEG coverage generators: MPEG-2 CRC, sections, TS
packetisation, Ethernet/IPv4/UDP/TCP framing and pcap writing. Everything
is built with struct; nothing comes from a real network."""
import struct

LINKTYPE_ETHERNET = 1
LINKTYPE_MPEG_2_TS = 243
LINKTYPE_WIRESHARK_UPPER_PDU = 252


def crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def section(table_id, body, ssi=True, reserved=3, crc=True, length=None,
            badcrc=False):
    """table_id, flags and length, body (everything after the length field
    up to the CRC) and the CRC."""
    blen = len(body) + (4 if crc else 0)
    if length is None:
        length = blen
    hdr = bytes([table_id]) + struct.pack(
        ">H", (0x8000 if ssi else 0) | (reserved << 12) | (length & 0xFFF))
    s = hdr + body
    if crc:
        c = crc32_mpeg2(s)
        if badcrc:
            c ^= 0xFFFFFFFF
        s += struct.pack(">I", c)
    return s


def ext_header(id16, version, cur_next=1, sect=0, last=0):
    return struct.pack(">HBBB", id16, 0xC0 | (version << 1) | cur_next,
                       sect, last)


def descr(tag, data):
    return bytes([tag, len(data)]) + data


class TS:
    """Packetise sections or PES packets into 188 octet TS packets with a
    continuity counter per PID."""

    def __init__(self):
        self.cc = {}

    def pkt(self, pid, pusi, payload, afc=1, af=b"", cc=None, tsc=0, tei=0):
        if cc is None:
            cc = self.cc.get(pid, 0)
            self.cc[pid] = (cc + 1) & 0xF
        hdr = struct.pack(">BHB", 0x47,
                          (tei << 15) | (0x4000 if pusi else 0) | pid,
                          (tsc << 6) | (afc << 4) | cc)
        body = af + payload
        assert len(body) <= 184, len(body)
        return hdr + body + b"\xff" * (184 - len(body))

    def sections(self, pid, sects):
        data = b"".join(sects)
        pkts = []
        first = True
        while data or first:
            if first:
                chunk = data[:183]
                data = data[183:]
                pkts.append(self.pkt(pid, True, b"\x00" + chunk))
                first = False
            else:
                chunk = data[:184]
                data = data[184:]
                pkts.append(self.pkt(pid, False, chunk))
        return pkts

    def pes(self, pid, pes, pcr=None):
        """A PES packet starting in a TS packet with PUSI, no pointer."""
        pkts = []
        first = True
        data = pes
        while data or first:
            if first:
                af = b""
                afc = 1
                if pcr is not None:
                    af = bytes([7, 0x10]) + struct.pack(">IH", pcr, 0x7E00)
                    afc = 3
                room = 184 - len(af)
                chunk, data = data[:room], data[room:]
                pkts.append(self.pkt(pid, True, chunk, afc=afc, af=af))
                first = False
            else:
                chunk, data = data[:184], data[184:]
                pkts.append(self.pkt(pid, False, chunk))
        return pkts


def write_pcap(path, frames, linktype, t0=1700000000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                            linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t0 + i, 0, len(fr), len(fr)))
            f.write(fr)


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return (struct.pack("!HH", 12, len(n) + pad) + n + b"\0" * pad +
            struct.pack("!HH", 0, 0) + payload)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(proto, payload, src="192.0.2.1", dst="192.0.2.2", ident=1):
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0,
                     64, proto, 0, s, d)
    ip = ip[:10] + struct.pack(">H", csum(ip)) + ip[12:]
    return ip, s, d


def eth(ip):
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip


def udp_frame(payload, sport=40000, dport=5000, src="192.0.2.1",
              dst="192.0.2.2"):
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip, s, d = ip4(17, u, src, dst)
    return eth(ip + u)


class Tcp:
    """One TCP connection, client 192.0.2.1:40000 -> server 192.0.2.2:80."""

    def __init__(self, cport=40000, sport=80):
        self.c = cport
        self.s = sport
        self.seq = {True: 1000, False: 5000}   # True = client to server
        self.frames = []
        self.n = 1

    def _seg(self, c2s, flags, data=b""):
        sp, dp = (self.c, self.s) if c2s else (self.s, self.c)
        src, dst = ("192.0.2.1", "192.0.2.2") if c2s else ("192.0.2.2",
                                                           "192.0.2.1")
        seq = self.seq[c2s]
        ack = self.seq[not c2s] if flags & 0x10 else 0
        opt = b"\x02\x04\x05\xb4" if flags & 2 else b""
        th = struct.pack(">HHIIBBHHH", sp, dp, seq, ack,
                         (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        s = bytes(int(x) for x in src.split("."))
        d = bytes(int(x) for x in dst.split("."))
        pseudo = s + d + struct.pack(">BBH", 0, 6, len(th) + len(data))
        c = csum(pseudo + th + data)
        th = th[:16] + struct.pack(">H", c) + th[18:]
        ip, _, _ = ip4(6, th + data, src, dst, self.n)
        self.n += 1
        self.frames.append(eth(ip + th + data))
        self.seq[c2s] = (seq + len(data) + (1 if flags & 3 else 0)) & 0xFFFFFFFF

    def handshake(self):
        self._seg(True, 0x02)
        self._seg(False, 0x12)
        self._seg(True, 0x10)

    def send(self, c2s, data, mss=1400, psh=True):
        for i in range(0, max(len(data), 1), mss):
            self._seg(c2s, 0x18 if psh else 0x10, data[i:i + mss])
            self._seg(not c2s, 0x10)

    def close(self):
        self._seg(True, 0x11)
        self._seg(False, 0x11)
        self._seg(True, 0x10)

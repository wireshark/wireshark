# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small helpers shared by the M2PA/M2TP/M2UA/M3UA generators (synthetic
addresses only): Ethernet/IPv4/SCTP/TCP framing and pcap writing."""
import struct

A = [192, 0, 2, 1]
B = [192, 0, 2, 2]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip4(src, dst, proto, payload):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def eth(rev, payload):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    if rev:
        a, b = b, a
    return b + a + b'\x08\x00' + payload


class Sctp:
    """One SCTP association (DATA chunks only, one stream)."""

    def __init__(self, port, ppid, cport=40000, vtag=0x01020304):
        self.port, self.ppid, self.cport, self.vtag = port, ppid, cport, vtag
        self.tsn = {False: 1000, True: 5000}
        self.ssn = {False: 0, True: 0}

    def frame(self, payload, rev=False, ppid=None):
        tsn = self.tsn[rev]
        self.tsn[rev] += 1
        ssn = self.ssn[rev]
        self.ssn[rev] = (ssn + 1) & 0xffff
        chunk = struct.pack('>BBHIHHI', 0, 3, 16 + len(payload), tsn, 0, ssn,
                            self.ppid if ppid is None else ppid) + payload
        chunk += b'\0' * ((4 - len(chunk) % 4) % 4)
        sp, dp = (self.cport, self.port) if not rev else (self.port, self.cport)
        sctp = struct.pack('>HHII', sp, dp, self.vtag, 0) + chunk
        src, dst = (B, A) if rev else (A, B)
        return eth(rev, ip4(src, dst, 132, sctp))


class Tcp:
    def __init__(self, port, cport=40001):
        self.port, self.cport = port, cport
        self.seq = {False: 1, True: 1}

    def frame(self, payload, rev=False, flags=0x18):
        sp, dp = (self.cport, self.port) if not rev else (self.port, self.cport)
        other = self.seq[not rev]
        t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[rev], other, 5 << 4, flags, 65535, 0, 0) + payload
        self.seq[rev] += len(payload)
        src, dst = (B, A) if rev else (A, B)
        return eth(rev, ip4(src, dst, 6, t))


def write_pcap(name, frames, link=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# ---- MTP3 payloads (ITU, 14 bit point codes) ----
def mtp3_label(dpc, opc, sls):
    return struct.pack('<I', (dpc & 0x3fff) | ((opc & 0x3fff) << 14) | ((sls & 0xf) << 28))


def mtp3_sltm(dpc=2, opc=1, sls=0, pattern=b'ABCD', ni=0):
    """Signalling link test message: SIO (SI 1), label, H0H1 0x11, length."""
    return bytes([(ni << 6) | 1]) + mtp3_label(dpc, opc, sls) + b'\x11' + \
        bytes([len(pattern) << 4]) + pattern


def mtp3_coo(dpc=2, opc=1, sls=0, fsn=5, ni=0):
    """Changeover order (SNM): SIO (SI 0), label, H0H1 0x11, FSN."""
    return bytes([ni << 6]) + mtp3_label(dpc, opc, sls) + b'\x11' + bytes([fsn])

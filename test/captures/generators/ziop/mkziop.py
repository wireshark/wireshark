#!/usr/bin/env python3
# Generates test/captures/ziop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ZIOP coverage captures: mkziop.py <outdir>.
ZIOP is reached over TCP by its heuristic dissector (the first segment of
a connection must start with "ZIOP"); the conversation then stays ZIOP.
UDP needs Decode As (udp.port ==9999 -> ziop), used only by the
malformed capture."""
import struct
import sys
import os

A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MA, MB = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'

def ipck(ip):
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    return ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]

class Conn:
    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.id = 1
    def _pkt(self, fromc, flags, payload, seq, ack):
        if fromc:
            s, d, sp, dp, ms, md = A, B, self.cport, self.sport, MA, MB
        else:
            s, d, sp, dp, ms, md = B, A, self.sport, self.cport, MB, MA
        opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        self.id += 1
        ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), self.id, 0, 64, 6, 0, s, d))
        return md + ms + b'\x08\x00' + ip + tcp + payload
    def syn(self):
        return self._pkt(True, 0x02, b'', self.cseq, 0)
    def synack(self):
        return self._pkt(False, 0x12, b'', self.sseq, self.cseq + 1)
    def ack(self):
        self.cseq += 1; self.sseq += 1
        return self._pkt(True, 0x10, b'', self.cseq, self.sseq)
    def c(self, payload):
        p = self._pkt(True, 0x18, payload, self.cseq, self.sseq); self.cseq += len(payload); return p
    def s(self, payload):
        p = self._pkt(False, 0x18, payload, self.sseq, self.cseq); self.sseq += len(payload); return p

def ziop(mtype=0, comp=1, orig=100, data=b'\x78\x9c' + bytes(range(30)), little=False, major=1, minor=2, flags=None,
         size=None, magic=b'ZIOP', raw=None):
    e = '<' if little else '>'
    body = struct.pack(e + 'H', comp) + b'\0\0' + struct.pack(e + 'I', orig) + data
    if raw is not None:
        body = raw
    if flags is None:
        flags = 1 if little else 0
    return magic + bytes([major, minor, flags, mtype]) + struct.pack(e + 'I', len(body) if size is None else size) + body

def giop(mtype=5, size=0):
    return b'GIOP' + bytes([1, 2, 0, mtype]) + struct.pack('>I', size)

def udp(payload, sport=40001, dport=9999, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), ident, 0, 64, 17, 0, A, B))
    return MB + MA + b'\x08\x00' + ip + u + payload

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main(out):
    fr = []
    c = Conn(40100, 40200)
    c.cseq += 1; c.sseq += 1                                          # start after the handshake
    fr.append(c.c(ziop(0, 1, 100)))                                   # 4 heuristic claims the connection: Request, GZIP
    fr.append(c.s(ziop(1, 3, 2000, little=True)))                     # 5 little-endian Reply, BZIP2
    fr.append(c.c(ziop(0, 4, 300) + ziop(7, 5, 400)))                 # 6 two PDUs in one segment (ZLIB, Fragment/LZMA)
    p = ziop(3, 0, 10, data=bytes(40))
    fr.append(c.c(p[:20])); fr.append(c.c(p[20:]))                    # 7-8 PDU split across two segments
    p = ziop(4, 9, 77, little=True, data=bytes(range(50, 80)))
    fr.append(c.s(p[:6])); fr.append(c.s(p[6:]))                      # 9-10 split inside the fixed header
    fr.append(c.c(ziop(0x42, 99, 5)))                                 # 12 unknown message type and compressor
    fr.append(c.c(ziop(0, 1, 1, major=1, minor=1)))                   # 13 GIOP 1.1: version warning
    fr.append(c.c(ziop(6, 2, 1, major=0, minor=9)))                   # 14 major 0
    fr.append(c.c(b'JUNKJUNKJUNKJUNKJUNK'))                           # 15 neither ZIOP nor GIOP
    fr.append(c.c(ziop(2, 6, 1) + ziop(5, 7, 3) + ziop(0, 8, 8)))    # 16 three PDUs in a segment
    # a second connection claimed by a little-endian first PDU
    d = Conn(40101, 40201)
    fr.append(d.c(ziop(0, 1, 100, little=True)))                      # 17
    fr.append(d.s(ziop(1, 2, 100)))                                   # 18
    # a connection whose first segment is not ZIOP: stays TCP/data
    e = Conn(40102, 40202)
    fr.append(e.c(b'NOTZIOP-NOTZIOP-NOTZIOP'))                        # 19
    write_pcap(os.path.join(out, 'ziop-coverage.pcap'), fr)

    bad = []
    c = Conn(40300, 40400)
    # fix reproducer: a size that wraps around when the header size is added
    bad.append(c.c(ziop(0, 1, 1, size=0xfffffff4)))
    c = Conn(40301, 40401)
    bad.append(c.c(ziop(0, 1, 1, size=0xfffffffe, little=True)))
    c = Conn(40302, 40402)
    # fix reproducer: a bad magic in the second PDU of a segment (checked at the offset)
    bad.append(c.c(ziop(0, 1, 1)))
    bad.append(c.c(ziop(0, 1, 1) + ziop(0, 1, 1, magic=b'ZIOQ')))
    c = Conn(40303, 40403)
    bad.append(c.c(ziop(0, 1, 1)))
    bad.append(c.c(ziop(0, 1, 1, size=0, raw=b'')))                            # no compression data in the PDU
    bad.append(c.c(ziop(0, 1, 1, size=3, raw=b'\x00\x01\x00')))                            # shorter than the compressor id and length
    c = Conn(40304, 40404)
    bad.append(c.c(ziop(0, 1, 1)))
    bad.append(c.c(giop(5)))                                          # a GIOP message on a ZIOP connection (frame.protocols differs between passes)
    c = Conn(40305, 40405)
    bad.append(c.c(b'ZIOP\x01\x02\x00'))                              # shorter than the header: heuristic refuses
    # UDP with Decode As udp.port==9999,ziop (no default UDP port)
    bad.append(udp(ziop(0, 1, 1), ident=10))
    bad.append(udp(ziop(1, 2, 2, little=True) + ziop(7, 3, 3), ident=11))
    bad.append(udp(giop(5), ident=12))
    bad.append(udp(b'JUNKJUNKJUNKJUNK', ident=13))
    bad.append(udp(ziop(0, 1, 1, size=0xfffffff4), ident=14))
    write_pcap(os.path.join(out, 'ziop-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

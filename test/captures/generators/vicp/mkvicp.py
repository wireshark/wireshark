# Generates test/captures/vicp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import struct
import sys

def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def exppdu(name, payload):
    """Exported PDU frame (linktype 252) naming a dissector."""
    b = name.encode()
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('>HH', 12, len(b)) + b + struct.pack('>HH', 0, 0) + payload


def inet_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', etype) + payload


def ip4(proto, src, dst, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    hdr = hdr[:10] + struct.pack('>H', inet_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192, opts=b''):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return hdr[:8] + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data, flags=3):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((4 - ln % 4) % 4)


def sctp_init(tag, chunk_type=1):
    return struct.pack('>BBHIIHHI', chunk_type, 0, 20, tag, 65535, 4, 4, 1000)




def pcapng(path, linktypes, frames):
    """frames: (interface id, data). Writes SHB, one IDB per link type, EPBs."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, data) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
#!/usr/bin/env python3
"""Generate the synthetic captures for the LeCroy VICP dissector
(packet-vicp.c).

VICP is registered on TCP port 1861, so a real trace reaches it with no
configuration: an oscilloscope client talks to the instrument over TCP with
an 8 octet header (operation flags, version, sequence number, an unused
octet and a 32 bit data length) followed by the data (usually a SCPI/remote
command or its reply).  Packets are built from scratch with struct;
addresses are from 192.0.2.0/24.

Usage: mkvicp.py <output directory>

Writes:
  vicp-coverage.pcap            two TCP sessions with commands and replies,
                                every operation flag combination, empty data
                                and a large reply
  vicp-coverage-malformed.pcap  data lengths larger than the segment
"""

C, S = '192.0.2.20', '192.0.2.21'
MC, MS = b'\x02\0\0\0\0\x14', b'\x02\0\0\0\0\x15'


def vicp(op, seq, data=b'', ver=1, unused=0, length=None):
    return struct.pack('>BBBBI', op, ver, seq, unused, len(data) if length is None else length) + data


class Flow:
    def __init__(self, cport, dport=1861):
        self.cport, self.dport = cport, dport
        self.cseq, self.sseq = 1000, 5000
        self.frames = []
        self.ident = cport

    def _send(self, from_client, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
        if from_client:
            seg = tcp(self.cport, self.dport, self.cseq, 0 if flags == 2 else self.sseq, flags, payload, opts=opts)
            fr = ether(ip4(6, C, S, seg, self.ident), dst=MS, src=MC)
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            seg = tcp(self.dport, self.cport, self.sseq, self.cseq, flags, payload, opts=opts)
            fr = ether(ip4(6, S, C, seg, self.ident + 1), dst=MC, src=MS)
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        self.ident += 2
        self.frames.append(fr)

    def handshake(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)

    def c(self, payload):
        self._send(True, 0x18, payload)
        self._send(False, 0x10)

    def s(self, payload):
        self._send(False, 0x18, payload)
        self._send(True, 0x10)

    def close(self):
        self._send(True, 0x11)
        self._send(False, 0x11)
        self._send(True, 0x10)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f1 = Flow(49152)
    f1.handshake()
    # data + EOI, sequence 1: a command; the reply carries sequence 1
    f1.c(vicp(0x81, 1, b'*IDN?'))
    f1.s(vicp(0x81, 1, b'LECROY,WR104Xi,LCRY0001,1.0.0'))
    # remote-enable (0x90 = data + remote), local lock-out, device clear
    f1.c(vicp(0x91, 2, b'TRIG_MODE?'))
    f1.s(vicp(0x81, 2, b'TRMD AUTO'))
    f1.c(vicp(0xa1, 3, b'*RST'))
    f1.c(vicp(0xc1, 4, b''))
    f1.c(vicp(0x41, 5, b'', unused=0x55))
    # a serial poll (0x08 | 0x80) with a one octet status reply
    f1.c(vicp(0x88, 6, b''))
    f1.s(vicp(0x88, 6, b'\x40'))
    # no EOI: a request split in two VICP blocks in two segments
    f1.c(vicp(0x80, 7, b'WF? DAT1;'))
    f1.c(vicp(0x81, 8, b'WF? DAT2'))
    # a large waveform block
    f1.s(vicp(0x81, 8, bytes(i & 0xff for i in range(1400))))
    # a newer protocol version and a zero length block
    f1.c(vicp(0x81, 9, b'ALST?', ver=2))
    f1.s(vicp(0x81, 9, b'', ver=2))
    # two VICP blocks in one segment: only the first header is decoded
    f1.s(vicp(0x80, 10, b'first ') + vicp(0x81, 10, b'second'))
    # sequence number wrap, all flag bits set
    f1.c(vicp(0xff, 255, b'X'))
    # a payload too short for a VICP header (7 octets): not decoded
    f1.c(b'ABCDEFG')
    # exactly the 8 octet header with length 0
    f1.c(vicp(0x81, 11))
    f1.close()
    # the reproducer-free second flow: instrument answers in a second session
    f2 = Flow(49153)
    f2.handshake()
    f2.c(vicp(0x81, 1, b'COMM_FORMAT?'))
    f2.s(vicp(0x81, 1, b'CFMT DEF9,WORD,BIN'))
    f2.close()
    pcap(os.path.join(out, 'vicp-coverage.pcap'), 1, f1.frames + f2.frames)

    m = Flow(49160)
    m.handshake()
    # the data length is larger than the segment: the data field runs past the end
    m.c(vicp(0x81, 1, b'short', length=100))
    m.s(vicp(0x81, 1, b'', length=0xffffffff))
    # a length that is huge but fits a signed 32 bit value
    m.c(vicp(0x81, 2, b'x', length=0x7fffffff))
    m.close()
    pcap(os.path.join(out, 'vicp-coverage-malformed.pcap'), 1, m.frames)


main()

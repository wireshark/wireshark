#!/usr/bin/env python3
# Generates test/captures/reload-framing_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RELOAD Framing captures (draft-ietf-p2psip-base framing header).
# Usage: mkreload-framing.py <outdir> [-v]
# Writes reload-framing-coverage.pcapng and reload-framing-coverage-malformed.pcap
import struct
import sys
import os

CLI = bytes([192, 0, 2, 1]); SRV = bytes([192, 0, 2, 2]); SRV2 = bytes([192, 0, 2, 3])
E_C = b'\x02\x00\x00\x00\x00\x01'; E_S = b'\x02\x00\x00\x00\x00\x02'

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(proto, l4, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = (E_S + E_C if src == CLI else E_C + E_S)
    return eth + b'\x08\x00' + ip + l4

def udp(payload, sport, dport, src=CLI, dst=SRV):
    return ip4(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src=CLI, dst=SRV):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
    t = t[:16] + struct.pack('!H', csum(ph + t + payload)) + t[18:]
    return ip4(6, t + payload, src, dst)

def reload_msg(tid, padlen=0):
    # a RELOAD Ping request (dissected by packet-reload.c; see the RELOAD
    # captures) with a valid security block of constant filler bytes
    body = struct.pack('!H', padlen) + b'\0' * padlen
    contents = struct.pack('!HI', 23, len(body)) + body + struct.pack('!I', 0)
    ident = b'\x02' + b'\x04' + bytes(range(4))
    security = struct.pack('!H', 0) + b'\x02\x01' + b'\x01' + struct.pack('!H', len(ident)) + ident \
        + struct.pack('!H', 8) + b'\xaa' * 8
    total = 38 + len(contents) + len(security)
    hdr = struct.pack('!IIHBBII', 0xd2454c4f, 1, 0, 1, 64, 0, total)
    hdr += struct.pack('!Q', tid) + struct.pack('!I', 0) + struct.pack('!HHH', 0, 0, 0)
    return hdr + contents + security

def data(seq, msg): return struct.pack('!BI', 128, seq) + struct.pack('!I', len(msg))[1:] + msg
def ack(seq, received): return struct.pack('!BII', 129, seq, received)

class Pcapng:
    def __init__(self): self.b = b''; self.n = 0
    def blk(self, t, body):
        body += b'\0' * (-len(body) % 4)
        self.b += struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    def start(self):
        self.blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        self.blk(1, struct.pack('<HHI', 1, 0, 65535))      # interface 0: Ethernet
        self.blk(1, struct.pack('<HHI', 252, 0, 65535))    # interface 1: Exported PDU
    def pkt(self, p, ifid=0):
        self.n += 1
        self.blk(6, struct.pack('<IIIII', ifid, 0, self.n * 250000, len(p), len(p)) + p)
    def write(self, path): open(path, 'wb').write(self.b)

def exp_pdu(payload, name=b'reload-framing', ipv4=None):
    t = b''
    n = name + b'\0' * (-len(name) % 4)
    t += struct.pack('!HH', 12, len(n)) + n
    if ipv4:
        t += struct.pack('!HH4s', 20, 4, ipv4[0]) + struct.pack('!HH4s', 21, 4, ipv4[1])
    return t + struct.pack('!HH', 0, 0) + payload

def build():
    png = Pcapng(); png.start(); mark = []
    def sect(name, fn):
        a = png.n + 1; fn(); mark.append((name, a, png.n))
    P = png.pkt
    UP = 6084
    def udp_basic():
        for i, (seq, tid) in enumerate(((1, 0x10), (2, 0x11), (3, 0x12))):
            P(udp(data(seq, reload_msg(tid, 4 * i)), 40000, UP))
        # ACK received masks: all, none, first only, a pair, a series, gaps, last
        for k, (seq, mask) in enumerate(((1, 0xffffffff), (2, 0x00000000), (3, 0x80000000),
                (3, 0xc0000000), (3, 0xe0000000), (3, 0x00000001), (3, 0x00000003),
                (3, 0x00000007), (3, 0xa0000000), (3, 0xf0f0f0f0), (3, 0x0f0f0f0f),
                (3, 0x80000001), (3, 0xc0000003), (3, 0xaaaaaaaa), (3, 0x55555555),
                (3, 0xe00000e0), (3, 0xc00000c0), (3, 0x80008000), (3, 0xfffffffe),
                (3, 0x7fffffff), (3, 0x20000000), (3, 0x30000000), (3, 0x0000000e))):
            P(udp(ack(seq, mask), UP, 40000, SRV, CLI))
        # retransmitted DATA and a duplicate ACK
        P(udp(data(1, reload_msg(0x10)), 40000, UP))
        P(udp(ack(1, 0x1), UP, 40000, SRV, CLI))
        # ACK for a sequence with no DATA in this conversation
        P(udp(ack(900, 0x3), UP, 40000, SRV, CLI))
        # a second client and a second server
        P(udp(data(5, reload_msg(0x20)), 40001, UP, CLI, SRV2))
        P(udp(ack(5, 0x1), UP, 40001, SRV2, CLI))
    sect('UDP 6084: DATA, ACKs with many received masks, duplicates', udp_basic)
    def udp_reject():
        # rejected by the sanity checks (shown as plain UDP): bad token, short
        # message, short frame, unknown type, short DATA
        m = bytearray(data(7, reload_msg(0x30))); m[8:12] = b'\0\0\0\0'
        P(udp(bytes(m), 40002, UP))
        P(udp(struct.pack('!BI', 128, 8) + struct.pack('!I', 20)[1:] + reload_msg(0x31)[:20], 40002, UP))
        P(udp(b'\x81\x00\x00\x00', 40002, UP))
        P(udp(b'\x55' + b'\0' * 20, 40002, UP))
        P(udp(data(9, reload_msg(0x32))[:11], 40002, UP))
        # ACK first in a conversation: rejected on every pass (the 2-pass fix)
        P(udp(ack(5, 0xc0000000), 40003, UP))
        P(udp(data(6, reload_msg(0x20)), 40003, UP))
    sect('UDP 6084: rejected frames, ACK before DATA (reproducer of the 2-pass fix)', udp_reject)
    def heur_udp():
        P(udp(data(21, reload_msg(0x40, 2)), 5000, 5001))
        P(udp(ack(21, 0x1), 5001, 5000, SRV, CLI))
        P(udp(ack(70, 0x1), 5003, 5004))
    sect('UDP heuristic on other ports', heur_udp)
    def tcp_port():
        seq = 100; sseq = 7000
        m1 = data(1, reload_msg(0x50)); m2 = data(2, reload_msg(0x51, 40))
        P(tcp(m1, 41000, UP, seq, sseq)); seq += len(m1)
        # two PDUs of different lengths in one segment (reproducer of the PDU length fix)
        P(tcp(m1 + m2, 41000, UP, seq, sseq)); seq += len(m1 + m2)
        # a PDU split over three segments (reassembly)
        m3 = data(3, reload_msg(0x52, 80))
        for part in (m3[:5], m3[5:60], m3[60:]):
            P(tcp(part, 41000, UP, seq, sseq)); seq += len(part)
        # ACKs over TCP: two in one segment, one split
        a = ack(1, 0xffffffff) + ack(2, 0x3)
        P(tcp(a, UP, 41000, sseq, seq, 0x18, SRV, CLI)); sseq += len(a)
        a = ack(3, 0x1)
        for part in (a[:4], a[4:]):
            P(tcp(part, UP, 41000, sseq, seq, 0x18, SRV, CLI)); sseq += len(part)
    sect('TCP 6084: DATA, two PDUs in a segment (PDU length fix), reassembly, ACKs', tcp_port)
    def tcp_heur():
        m = data(30, reload_msg(0x60)); seq = 500
        P(tcp(m, 42000, 5002, seq, 0))
        P(tcp(ack(30, 0x1), 5002, 42000, 800, seq + len(m), 0x18, SRV, CLI))
        P(tcp(ack(80, 0x1), 42001, 5003, 900, 0))
    sect('TCP heuristic on other ports', tcp_heur)
    def exp():
        # Exported PDU without addresses: the dissector refuses it
        P(exp_pdu(data(40, reload_msg(0x70))), 1)
        # with IPv4 addresses (no ports, no transport type)
        P(exp_pdu(data(41, reload_msg(0x71)), ipv4=(CLI, SRV)), 1)
        P(exp_pdu(ack(41, 0x1), ipv4=(SRV, CLI)), 1)
    sect('Exported PDU entry', exp)
    return png, mark

def build_malformed():
    # nothing here is malformed on the framing level; DATA with a RELOAD
    # message cut short (the RELOAD dissector raises exceptions)
    out = []
    m = reload_msg(0x80, 20)
    out.append(udp(data(50, m[:60]), 43000, 6084))
    out.append(udp(data(51, m)[:-5], 43001, 6084))
    big = data(52, m)
    out.append(tcp(big[:-10], 43002, 6084, 100, 0))      # cut off by the snaplen? no: short TCP segment
    return out

if __name__ == '__main__':
    out = sys.argv[1]
    png, mark = build()
    png.write(os.path.join(out, 'reload-framing-coverage.pcapng'))
    with open(os.path.join(out, 'reload-framing-coverage-malformed.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(build_malformed()):
            f.write(struct.pack('<IIII', 1 + i, 0, len(p), len(p)) + p)
    if '-v' in sys.argv:
        for n, a, b in mark: print('%4d-%4d  %s' % (a, b, n))
        print(png.n, 'frames')

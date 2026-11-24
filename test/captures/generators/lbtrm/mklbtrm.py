#!/usr/bin/env python3
# Generates test/captures/lbtrm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the LBT-RM (Ultra Messaging reliable multicast) coverage captures.
# Usage: mklbtrm.py <outdir> [-v]
# lbtrm-coverage.pcapng: main capture (Ethernet + one Exported PDU frame)
# lbtrm-coverage-malformed.pcap: truncated and unknown packets
# Addresses are from 192.0.2.0/24 and the default LBT-RM multicast groups.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def udp_frame(payload, src, dst, sport, dport, mcast=None):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    if dst.startswith('224.'):
        d = bytes([0x01, 0x00, 0x5e]) + ip4(dst)[1:]
        d = bytes([0x01, 0x00, 0x5e, ip4(dst)[1] & 0x7f, ip4(dst)[2], ip4(dst)[3]])
    else:
        d = bytes([2, 0, 0, 0, 0, ip4(dst)[3]])
    eth = d + bytes([2, 0, 0, 0, 0, ip4(src)[3]]) + b'\x08\x00'
    return eth + ip + udp


class Cap:
    def __init__(self):
        self.pk = []   # (linktype, data)
        self.notes = []

    def add(self, data, lt=1):
        self.pk.append((lt, data))
        return len(self.pk)

    def mark(self, label):
        self.notes.append((len(self.pk) + 1, label))

    def write_pcap(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, (lt, d) in enumerate(self.pk):
                assert lt == 1
                f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(d), len(d)))
                f.write(d)

    def write_pcapng(self, path):
        def blk(t, body):
            body += b'\0' * ((-len(body)) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 262144))
        out += blk(1, struct.pack('<HHI', 252, 0, 262144))
        for i, (lt, d) in enumerate(self.pk):
            ts = (1700000000 + i // 1000) * 1000000 + (i % 1000) * 1000
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        open(path, 'wb').write(out)


# ---- LBMC payload (the minimum, the LBMC dissector is covered elsewhere) ---
def lbmc(data=b'payload', tidx=1, sqn=1, nhdr=0, hdrs=b''):
    body = hdrs + data
    return struct.pack('!BBHII', 0x00, nhdr, 12 + len(body), tidx, sqn) + body


# ---- LBT-RM -----------------------------------------------------------------
DATA, SM, NAK, NCF = 0, 2, 3, 4


def hdr(ptype, ucast, sid, nxt=0, ver=0):
    return struct.pack('!BBHI', (ver << 4) | ptype, nxt, ucast, sid)


def data(sqn, trail=0, flags=0, tgsz=0, fec=0, payload=None, ucast=14390, sid=0x11223344, opts=b'', nxt=0, ft=0):
    if payload is None:
        payload = lbmc(b'msg%d' % sqn, 1, sqn)
    return (hdr(DATA, ucast, sid, nxt) + struct.pack('!IIBBH', sqn, trail, (flags << 4) | ft, tgsz, fec) +
            opts + payload)


def sm(sm_sqn, lead, trail, flags=0, tgsz=0, res=0, ucast=14390, sid=0x11223344, opts=b'', nxt=0):
    return hdr(SM, ucast, sid, nxt) + struct.pack('!IIIBBH', sm_sqn, lead, trail, flags << 4, tgsz, res) + opts


def nak(sqns, fmt=0, ucast=14390, sid=0x11223344, num=None, opts=b'', nxt=0):
    return (hdr(NAK, ucast, sid, nxt) + struct.pack('!HH', len(sqns) if num is None else num, fmt) +
            b''.join(struct.pack('!I', s) for s in sqns) + opts)


def ncf(sqns, reason=0, fmt=0, trail=0, ucast=14390, sid=0x11223344, num=None, opts=b'', nxt=0):
    return (hdr(NCF, ucast, sid, nxt) + struct.pack('!IHBB', trail, len(sqns) if num is None else num, 0, (reason << 4) | fmt) +
            b''.join(struct.pack('!I', s) for s in sqns) + opts)


def opt(nxt, total, res=0, fill=b''):
    '''option header: next header, length of this header, 2 reserved octets'''
    return struct.pack('!BBH', nxt, total, res) + fill + b'\0' * (total - 4 - len(fill))


def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload


SRC_A = '192.0.2.1'; GRP_A = '224.10.10.10'
SRC_B = '192.0.2.2'; GRP_B = '224.10.10.12'
SRC_M = '192.0.2.3'; GRP_M = '224.10.10.21'
RX1 = '192.0.2.50'; RX2 = '192.0.2.51'


def build_main(c):
    A = lambda p, sport=33000: c.add(udp_frame(p, SRC_A, GRP_A, sport, 14400))
    B = lambda p: c.add(udp_frame(p, SRC_B, GRP_B, 33001, 14400))
    c.mark('NAK before any other packet of its transport (transport not known)')
    c.add(udp_frame(nak([1, 2], sid=0x99999999, ucast=14395), RX1, '192.0.2.99', 33100, 14395))
    c.mark('source A: DATA sequence 0-3 with LBMC payloads, flags and FEC fields, SM')
    A(data(0))
    A(data(1, trail=0, flags=0x8, tgsz=0x5a, fec=0x1234, ft=0x3))        # unicast NAKs flag, tgsz, fec symbol
    A(sm(0, 1, 0))
    A(data(2, trail=1, flags=0x4))                                         # multicast NAKs flag
    A(data(3, trail=1, flags=0x1))                                         # late join flag
    A(sm(1, 3, 1, flags=0x8, tgsz=3, res=0x0102))
    c.mark('sequence gap (4 missing), NAK from two receivers, NCF with every reason')
    A(data(5, trail=1))
    A(data(6, trail=1))
    c.add(udp_frame(nak([4]), RX1, SRC_A, 33100, 14390))
    c.add(udp_frame(nak([4, 7, 9], fmt=0x8000), RX2, SRC_A, 33101, 14390))
    c.add(udp_frame(nak([4], fmt=0x4001), RX1, SRC_A, 33100, 14390))
    c.add(udp_frame(nak([], fmt=0x0000), RX2, SRC_A, 33101, 14390))
    for r in (0, 1, 2, 3, 7):
        A(ncf([4, 7][:1 + (r & 1)], reason=r, trail=1))
    A(ncf([], reason=0, fmt=1))
    A(ncf([4, 7, 8], reason=2, fmt=0))
    c.mark('retransmission of 4 (RX flag), out of order and duplicate DATA, SM out of order, duplicate and with a gap')
    A(data(4, trail=1, flags=0x2))                      # RX
    A(data(7, trail=1))
    A(data(7, trail=1))                                 # duplicate
    A(data(6, trail=1))                                 # out of order, duplicate
    A(data(8, trail=1, flags=0x2))                      # retransmission above the high sqn
    A(data(10, trail=1))                                # gap
    A(data(9, trail=1))                                 # out of order, not a duplicate
    A(sm(2, 10, 1))
    A(sm(5, 10, 1))                                     # SM gap
    A(sm(3, 10, 1))                                     # SM out of order
    A(sm(3, 10, 1))                                     # SM duplicate
    A(sm(6, 10, 1))
    c.mark('option headers: one, a chain of three, a zero-length header; DATA with and without payload')
    A(data(11, nxt=1, opts=opt(0, 8, fill=b'\x01\x02\x03\x04')))
    A(data(12, nxt=1, opts=opt(2, 4) + opt(3, 12) + opt(0, 8)))
    A(data(13, nxt=1, opts=opt(5, 0)))                                     # hdr_len 0: stop, no payload decode
    A(sm(7, 13, 1, nxt=1, opts=opt(0, 4)))
    A(data(14, payload=b'', trail=1))
    A(data(15, payload=lbmc(b'', 1, 15), trail=1))
    c.mark('source B on its own group (second transport), data and SM; unicast NAK to B')
    B(data(0, ucast=14391, sid=0xaabbccdd))
    B(data(1, ucast=14391, sid=0xaabbccdd))
    B(sm(0, 1, 0, ucast=14391, sid=0xaabbccdd))
    c.add(udp_frame(nak([1], ucast=14391, sid=0xaabbccdd), RX1, SRC_B, 33102, 14391))
    c.add(udp_frame(nak([1], ucast=14391, sid=0x01010101), RX1, SRC_B, 33102, 14391))   # session unknown
    c.add(udp_frame(nak([1], ucast=14399, sid=0xaabbccdd), RX1, SRC_B, 33102, 14391))   # ucast port unknown
    c.mark('source A again with another session id on the same group, and a different source port')
    A(data(0, sid=0x55667788), 33010)
    A(data(1, sid=0x55667788), 33010)
    c.mark('MIM: 224.10.10.21 port 14401 (incoming and outgoing default to the same group)')
    c.add(udp_frame(data(0, ucast=14392, sid=0x01020304), SRC_M, GRP_M, 33002, 14401))
    c.add(udp_frame(sm(0, 0, 0, ucast=14392, sid=0x01020304), SRC_M, GRP_M, 33002, 14401))
    c.add(udp_frame(ncf([1], reason=1, ucast=14392, sid=0x01020304), SRC_M, GRP_M, 33002, 14401))
    c.mark('Exported PDU naming lbtrm: no addresses (reproducer of the tag lookup crash)')
    c.add(exp_pdu('lbtrm', data(1, ucast=14390, sid=0x11223344)), lt=252)
    c.add(exp_pdu('lbtrm', sm(1, 1, 0)), lt=252)
    c.mark('110 DATA packets with sequence number 100 (reproducer of the sequence list; needs -2 and sequence analysis)')
    for i in range(110):
        A(data(100, trail=100, flags=(0x2 if i == 2 else 0), payload=lbmc(b'x', 1, 100)), 33020)
    c.mark('unicast DATA to a port in the source port range; source A, group B ports outside the range are not LBT-RM')
    c.add(udp_frame(data(30, ucast=14393, sid=0x31313131), '192.0.2.77', RX1, 33003, 14393))
    c.mark('end of main capture')


def build_malformed(c):
    A = lambda p, **k: c.add(udp_frame(p, SRC_A, GRP_A, 33000, 14400))
    c.mark('valid DATA and SM so that the transport exists')
    A(data(0)); A(sm(0, 0, 0))
    c.mark('truncated headers (found by the heuristic, which needs the 8 octet header)')
    d = data(1)
    for cut in (8, 9, 12, 15, 19):
        A(d[:cut])
    s = sm(1, 1, 1)
    for cut in (8, 12, 16, 20, 23):
        A(s[:cut])
    n = nak([1, 2, 3])
    for cut in (8, 10, 11, 12, 15, 19):
        A(n[:cut])
    c.add(udp_frame(n[:10], RX1, SRC_A, 33100, 14390))
    c.add(udp_frame(n[:19], RX1, SRC_A, 33100, 14390))
    f = ncf([1, 2, 3], reason=2)
    for cut in (8, 12, 14, 15, 16, 19, 23):
        A(f[:cut])
    c.mark('NAK/NCF with a count larger than the data')
    A(nak([1], num=3))
    A(nak([1], num=0xffff))
    A(ncf([1], num=3))
    A(ncf([1], num=0xffff))
    c.add(udp_frame(nak([1], num=0xffff), RX1, SRC_A, 33100, 14390))
    c.mark('option header cut short, option length longer than the packet')
    A(data(2, nxt=1, opts=b''))
    A(data(3, nxt=1, opts=b'\x00'))
    A(data(4, nxt=1, opts=b'\x00\x08\x00\x00'))
    A(data(5, nxt=1, opts=opt(0, 200), payload=b''))
    A(sm(2, 2, 2, nxt=1, opts=b''))
    A(nak([1], nxt=1, opts=b''))
    A(ncf([1], nxt=1, opts=b''))
    c.mark('DATA without any payload after the header / LBMC header cut short')
    A(data(6, payload=b''))
    A(data(7, payload=b'\x00\x00'))
    A(data(8, payload=lbmc(b'abcdef')[:10]))
    c.mark('unknown packet type 1 and 5 (only reachable with Decode As), version 1 (heuristic rejects)')
    A(hdr(1, 14390, 0x11223344) + b'\0' * 12)
    A(hdr(5, 14390, 0x11223344) + b'\0' * 12)
    A(hdr(15, 14390, 0x11223344))
    A(hdr(DATA, 14390, 0x11223344, ver=1) + data(1)[8:])
    c.mark('heuristic rejects: ports and groups outside the ranges, broadcast/unicast to a wrong port, short packets')
    c.add(udp_frame(data(1), SRC_A, GRP_A, 33000, 14500))
    c.add(udp_frame(data(1), SRC_A, '224.10.10.15', 33000, 14400))
    c.add(udp_frame(data(1), SRC_A, '224.10.10.9', 33000, 14400))
    c.add(udp_frame(data(1), SRC_A, '224.10.10.22', 33000, 14401))
    c.add(udp_frame(data(1), SRC_A, GRP_M, 33000, 14400))
    c.add(udp_frame(data(1), SRC_A, GRP_A, 33000, 14401))
    c.add(udp_frame(data(1), SRC_A, RX1, 33000, 14500))
    c.add(udp_frame(data(1), SRC_A, RX1, 33000, 14389))
    c.add(udp_frame(b'\0\0\0\0', SRC_A, GRP_A, 33000, 14400))
    c.mark('Exported PDU frames with a truncated header and an unknown type')
    c.add(exp_pdu('lbtrm', data(1)[:6]), lt=252)
    c.add(exp_pdu('lbtrm', nak([1, 2])), lt=252)
    c.add(exp_pdu('lbtrm', ncf([1, 2], reason=3)), lt=252)
    c.add(exp_pdu('lbtrm', hdr(9, 1, 2) + b'\0' * 8), lt=252)
    c.mark('end of malformed capture')


if __name__ == '__main__':
    os.makedirs(OUT, exist_ok=True)
    m = Cap(); build_main(m); m.write_pcapng(os.path.join(OUT, 'lbtrm-coverage.pcapng'))
    x = Cap(); build_malformed(x)
    # the malformed capture contains Exported PDU frames: pcapng too
    x.write_pcapng(os.path.join(OUT, 'lbtrm-coverage-malformed.pcapng'))
    if VERBOSE:
        for name, cc in (('lbtrm-coverage.pcapng', m), ('lbtrm-coverage-malformed.pcapng', x)):
            print(name, len(cc.pk), 'frames')
            for n, l in cc.notes:
                print('  %4d  %s' % (n, l))

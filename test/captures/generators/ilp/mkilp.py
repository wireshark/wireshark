#!/usr/bin/env python3
# Generates test/captures/ilp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ILP coverage captures. Usage: mkilp.py <outdir>

ilp-coverage.pcap: ILP PDUs (OMA SUPL, unaligned PER) over TCP port 7276
(one PDU per segment, several PDUs in one segment, a PDU split over
segments) and over HTTP (media type application/oma-supl-ilp).
ilp-coverage-malformed.pcap: PDUs that only malformed input reaches.
The PDUs are encoded from the type tree read out of packet-ilp.c
(perschema.py); the IP/TCP/HTTP framing is built here with struct. All
values are made up."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import sys
from perschema import PerSchema

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get('ILP_C', os.path.join(SRCDIR, 'epan/dissectors/packet-ilp.c'))
sc = PerSchema(SRC, 'ilp', seed=774)

def bcd(s, digits, n=8):
    d = digits + 'f' * (2 * n - len(digits))
    return bytes((int(d[2 * i + 1], 16) << 4) | int(d[2 * i], 16) for i in range(n))


def pickbcd(*ds):
    return lambda s: bcd(s, s.rng.choice(ds))


# BCD contents for the helpers behind SETId (E.164, E.212 and a plain
# digit string)
sc.fixed = {
    'dissect_ilp_T_msisdn': pickbcd('4912345678', '15551230123', '46701234567'),
    'dissect_ilp_T_mdn': pickbcd('4912345678123456', '1555123012', '0123456789012345'),
    'dissect_ilp_T_imsi': pickbcd('262011234567890', '310260123456789', '460001234567890'),
    # RRLP assistanceDataAck with the reference numbers 0 to 7, and LPP
    # messages with only an endTransaction / an acknowledgement
    'dissect_ilp_T_rrlpPayload': lambda s: bytes([(s.rng.randrange(8) << 5) | 0x06]),
    'dissect_ilp_T_lPPPayload_item': lambda s: s.rng.choice([b'\x08', b'\x22']),
}

BAD = set()     # candidate PDU numbers that the check run found not clean (moved to the malformed capture)


def ilp_pdu(version=None, session=None):
    sc.opt_skip = sc.rng.choice([0.05, 0.2, 0.35, 0.5])
    sc.ext_prob = sc.rng.choice([0.1, 0.25, 0.4])
    w = sc.enc('dissect_ilp_ILP_PDU')
    n = len(w.tobytes())
    for i in range(16):
        w.b[i] = (n >> (15 - i)) & 1
    return w.tobytes()


# ---- IP / TCP / HTTP framing
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class Conn:
    def __init__(self, cport, sport, client=(192, 0, 2, 1), server=(192, 0, 2, 2)):
        self.cport, self.sport = cport, sport
        self.client, self.server = bytes(client), bytes(server)
        self.seq = {True: 1000, False: 5000}
        self.ipid = 1

    def seg(self, payload, from_client=True, flags=0x18):
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        seq = self.seq[from_client]
        ack = self.seq[not from_client] if flags & 0x10 else 0
        opt = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.seq[from_client] = (seq + len(payload) + (1 if flags & 3 else 0)) & 0xffffffff
        eth = (b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' if from_client else b'\x02\0\0\0\0\x01' + b'\x02\0\0\0\0\x02') + b'\x08\x00'
        return eth + ip + tcp

    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]


def pcap(frames):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
    return out


def http_post(body, ctype='application/oma-supl-ilp'):
    return (b'POST /supl HTTP/1.1\r\nHost: supl.example.net\r\nContent-Type: ' + ctype.encode() +
            b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def build_main():
    frames = []
    # candidate PDUs: three rounds over the IlpMessage alternatives
    pdus = []
    for i in range(360):
        pdus.append(ilp_pdu())
    ok = [p for i, p in enumerate(pdus) if i not in BAD]
    bad = [p for i, p in enumerate(pdus) if i in BAD]
    c = Conn(40000, 7276)
    frames += c.handshake()
    # one PDU per segment (client to server, answers from the server)
    for i, p in enumerate(ok[:200]):
        frames.append(c.seg(p, i % 3 != 2))
    # two or three PDUs in one segment
    i = 200
    while i + 3 <= 300:
        frames.append(c.seg(b''.join(ok[i:i + 2 + (i % 2)]), True))
        i += 2 + (i % 2)
    # a PDU split over two and over three segments (reassembly)
    for p in ok[300:303]:
        h = max(3, len(p) // 2)
        frames.append(c.seg(p[:h], True))
        frames.append(c.seg(p[h:], True))
    for p in ok[303:306]:
        a, b = len(p) // 3, 2 * len(p) // 3
        a = max(a, 1)
        frames.append(c.seg(p[:1], True))                  # shorter than the header
        frames.append(c.seg(p[1:b], True))
        frames.append(c.seg(p[b:], True))
    # ILP in HTTP POST bodies and responses (media type
    # application/oma-supl-ilp)
    h = Conn(41000, 80)
    frames += h.handshake()
    for i, p in enumerate(ok[306:326]):
        frames.append(h.seg(http_post(p), True))
        resp = (b'HTTP/1.1 200 OK\r\nContent-Type: application/oma-supl-ilp\r\nContent-Length: ' +
                str(len(ok[326 + i])).encode() + b'\r\n\r\n' + ok[326 + i])
        frames.append(h.seg(resp, False))
    return frames, bad


def build_malformed(bad):
    import random
    r = random.Random(7276)
    frames = []
    c = Conn(42000, 7276)
    frames += c.handshake()
    for p in bad:
        frames.append(c.seg(p, True))
    # truncated PDUs (length field larger than the data is TCP framing; the
    # PER decoding runs out of data inside the PDU)
    pdus = [ilp_pdu() for _ in range(60)]
    for p in pdus:
        cut = r.randrange(5, len(p))
        q = bytearray(p[:cut])
        q[0:2] = struct.pack('>H', len(q))
        frames.append(c.seg(bytes(q), True))
    # bit flips, same length
    for p in pdus:
        q = bytearray(p)
        for _ in range(3):
            q[r.randrange(2, len(q))] ^= 1 << r.randrange(8)
        frames.append(c.seg(bytes(q), True))
    # a zero length and a length of 1 and 2 (shorter than any PDU)
    for n in (0, 1, 2, 3):
        frames.append(c.seg(struct.pack('>H', n) + b'\x00' * max(0, n - 2), True))
    # an HTTP body that is not ILP
    h = Conn(43000, 80)
    frames += h.handshake()
    frames.append(h.seg(http_post(b'\x00\x05\x01\x02\x03'), True))
    frames.append(h.seg(http_post(b''), True))
    return frames


def main(out):
    frames, bad = build_main()
    open(os.path.join(out, 'ilp-coverage.pcap'), 'wb').write(pcap(frames))
    print('main capture: %d frames, %d bad candidates' % (len(frames), len(bad)))
    m = build_malformed(bad)
    open(os.path.join(out, 'ilp-coverage-malformed.pcap'), 'wb').write(pcap(m))
    print('malformed capture: %d frames' % len(m))


if __name__ == '__main__':
    main(sys.argv[1])

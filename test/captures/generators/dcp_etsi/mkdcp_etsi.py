#!/usr/bin/env python3
# Generates test/captures/dcp_etsi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ETSI DCP dissector
(packet-dcp-etsi.c: DCP, DCP-AF, DCP-PFT and DCP-TPL).

All packets are built from scratch with struct; no captured traffic is
used. A DRM content server (192.0.2.1) sends DCP over UDP to a
transmitter (192.0.2.2), port 50000 to 50000. DCP is found by its UDP
heuristic (enabled by default), so no Decode As is needed.

The Reed-Solomon parity of the PFT fragments with FEC is computed here
with the RS(255,207) code of ETSI TS 102 821 clause 7.3.1 (GF(2^8) with
the polynomial x^8+x^4+x^3+x^2+1, generator roots alpha^1..alpha^48),
the same code as epan/reedsolomon.c.

Usage: mkdcp_etsi.py <output directory>

Writes:
  dcp-etsi-coverage.pcap            AF and PF packets, PFT fragments with
                                    and without FEC and addresses, two
                                    Reed-Solomon reassemblies, TPL tags,
                                    packets the heuristic rejects, and
                                    the RS k of 0 reproducer
  dcp-etsi-coverage-malformed.pcap  bad CRCs, short and overlong packets,
                                    the reassembly errors
"""

import os
import struct
import sys

SRC = '192.0.2.1'
DST = '192.0.2.2'
PORT = 50000


# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / UDP)

def ipcsum(h):
    s = sum(struct.unpack('!%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp4(payload, sport=PORT, dport=PORT, src=SRC, dst=DST, ipid=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    sa = bytes(int(x) for x in src.split('.'))
    da = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ipid & 0xffff, 0,
                    64, 17, 0, sa, da)
    h = h[:10] + struct.pack('!H', ipcsum(h)) + h[12:]
    return (b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' +
            b'\x08\x00' + h + u)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, payload, **kw):
        self.frames.append(udp4(payload, ipid=len(self.frames) + 1, **kw))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
                f.write(fr)


# --------------------------------------------------------------------------
# CRC (CRC-16/CCITT-FALSE, sent inverted: TS 102 821 annex A)

def crc16(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def with_crc(data):
    return data + struct.pack('!H', crc16(data) ^ 0xFFFF)


# --------------------------------------------------------------------------
# Reed-Solomon RS(255,207) encoder

EXP = [0] * 512
LOG = [0] * 256
x = 1
for i in range(255):
    EXP[i] = x
    LOG[x] = i
    x <<= 1
    if x & 0x100:
        x ^= 0x11d
for i in range(255, 512):
    EXP[i] = EXP[i - 255]


def gmul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


# generator polynomial, highest degree first: prod (x - alpha^i), i = 1..48
GEN = [1]
for i in range(1, 49):
    nxt = GEN + [0]
    for j, c in enumerate(GEN):
        nxt[j + 1] ^= gmul(c, EXP[i])
    GEN = nxt


def rs_parity(data207):
    """48 parity bytes for 207 data bytes (first byte = highest degree)."""
    assert len(data207) == 207
    rem = list(data207) + [0] * 48
    for i in range(207):
        coef = rem[i]
        if coef:
            for j in range(1, 49):
                rem[i + j] ^= gmul(GEN[j], coef)
    return bytes(rem[207:])


def fec_encode(af, fcount):
    """Return (rsk, rsz, plen, fragments) for an AF packet: TS 102 821
    clause 7.3: c = ceil(L/207) blocks of k data bytes plus 48 parity
    bytes, z padding bytes, then interleaved over fcount fragments."""
    L = len(af)
    c = -(-L // 207)
    k = -(-L // c)
    z = c * k - L
    data = af + bytes(z)
    stream = b''
    for i in range(c):
        chunk = data[i * k:(i + 1) * k]
        stream += chunk + rs_parity(chunk + bytes(207 - k))
    plen = -(-len(stream) // fcount)
    stream += bytes(plen * fcount - len(stream))
    frags = [bytes(stream[r * fcount + f] for r in range(plen)) for f in range(fcount)]
    return k, z, plen, frags


# --------------------------------------------------------------------------
# DCP layers

def tag(name, value, bits=None):
    if bits is None:
        bits = 8 * len(value)
    return name + struct.pack('!I', bits) + value


def af(payload, seq, crc=True, pt=b'T', rev=0x10, trailer=b''):
    hdr = b'AF' + struct.pack('!IHB', len(payload), seq, (0x80 if crc else 0) | rev) + pt
    if crc:
        return with_crc(hdr + payload) + trailer
    return hdr + payload + b'\0\0' + trailer


def pft(payload, seq, findex, fcount, fec=None, addr=None, plen=None, bad_hcrc=False):
    if plen is None:
        plen = len(payload)
    word = plen & 0x3fff
    opt = b''
    if fec is not None:
        word |= 0x8000
        opt += struct.pack('!BB', *fec)
    if addr is not None:
        word |= 0x4000
        opt += struct.pack('!HH', *addr)
    hdr = (b'PF' + struct.pack('!H', seq) + struct.pack('!I', findex)[1:] +
           struct.pack('!I', fcount)[1:] + struct.pack('!H', word) + opt)
    hdr = with_crc(hdr)
    if bad_hcrc:
        hdr = hdr[:-1] + bytes([hdr[-1] ^ 0xff])
    return hdr + payload


def tpl_full(n=0):
    """A TAG packet with the tag items of a DRM MDI stream."""
    return (tag(b'*ptr', b'DMDI' + struct.pack('!HH', 1, 0)) +
            tag(b'dlfc', struct.pack('!I', 1000 + n)) +
            tag(b'fac_', bytes(range(0x10, 0x19))) +
            tag(b'sdc_', b'\x0a' + bytes(range(1, 21))) +
            tag(b'robm', b'\x01') +
            tag(b'str0', bytes((i * 7 + n) & 0xff for i in range(100))) +
            tag(b'rinf', b'BBC0' + struct.pack('!I', 0x01020304)) +
            tag(b'info', b'synthetic DCP coverage capture') +
            tag(b'Ttst', b'\xa5\x80', bits=9) +      # bits not a multiple of 8
            tag(b'Tnil', b''))                       # 0 bits


def tpl_small(n):
    return (tag(b'*ptr', b'DMDI' + struct.pack('!HH', 1, 0)) +
            tag(b'dlfc', struct.pack('!I', n)))


def tpl_sized(n, size):
    """A TAG packet with a str0 tag filling it up to size bytes."""
    head = tpl_small(n)
    body = bytes((i * 13 + n) & 0xff for i in range(size - len(head) - 8))
    return head + tag(b'str0', body)


def main(outdir):
    m = Pcap()

    # --- AF packets ------------------------------------------------------
    m.add(af(tpl_full(), 1))                            # 1: CRC used
    m.add(af(tpl_small(2), 2, crc=False))               # 2: no CRC
    m.add(af(tpl_small(3), 3, trailer=b'\xde\xad\xbe\xef'))  # 3: bytes after the AF frame
    m.add(af(b'', 4))                                   # 4: no tag items

    # --- packets the heuristic rejects (UDP data) ---------------------------
    m.add(af(tpl_small(5), 5, rev=0x20))                # 5: AF revision 2.0
    m.add(af(tpl_small(6), 6, pt=b'X'))                 # 6: AF payload type X
    m.add(b'PF' + bytes(10))                            # 7: PF, 12 octets
    m.add(b'PF' + bytes(8) + b'\xc0\x10' + bytes(4))    # 8: PF, FEC and Addr, 16 octets
    m.add(pft(af(tpl_small(9), 9), 9, 0, 1, bad_hcrc=True))  # 9: bad header CRC
    m.add(b'XY' + bytes(18))                            # 10: no sync
    m.add(b'AF' + bytes(8))                             # 11: AF, 10 octets

    # --- PFT, not fragmented ---------------------------------------------
    m.add(pft(af(tpl_small(12), 12), 100, 0, 1))                           # 12
    m.add(pft(af(tpl_small(13), 13), 101, 0, 1, addr=(0x1234, 0x5678)))    # 13
    m.add(pft(af(tpl_small(14), 14), 102, 0, 1, fec=(20, 0), addr=(1, 2)))  # 14: FEC, Fcount 1

    # --- PFT fragments without FEC -----------------------------------------
    a = af(tpl_full(15), 15)                     # 263 octets
    parts = [a[0:100], a[100:200], a[200:]]
    for i, p in enumerate(parts):                # 15-17: in order, with addresses
        m.add(pft(p, 110, i, 3, addr=(0x0001, 0x0002)))
    a = af(tpl_full(18), 18)
    parts = [a[0:100], a[100:200], a[200:]]
    for i in (2, 0, 1):                          # 18-20: last fragment first
        m.add(pft(parts[i], 111, i, 3))
    a = af(tpl_full(21), 21)
    parts = [a[0:100], a[100:200], a[200:]]
    for i in (0, 2):                             # 21-22: fragment 1 lost
        m.add(pft(parts[i], 112, i, 3))
    m.add(pft(b'\x11' * 40, 113, 0, 2, plen=50))  # 23: fragment length error
    m.add(pft(b'', 114, 1, 2))                    # 24: empty fragment

    # --- PFT fragments with Reed-Solomon FEC ---------------------------------
    # 25-27: AF of 300 octets, 2 RS blocks (k 150) over 3 fragments of 132
    # octets: every fragment is needed (rx_min 3), so the reassembly is
    # done when the last arrives. Fragment 1 carries 12 corrupted octets,
    # which the RS decoder corrects (the AF CRC is good).
    a = af(tpl_sized(25, 288), 25)
    assert len(a) == 300
    rsk, rsz, plen, frags = fec_encode(a, 3)
    assert (rsk, rsz, plen) == (150, 0, 132)
    bad = bytearray(frags[1])
    for i in range(0, 120, 10):
        bad[i] ^= 0x5a
    frags[1] = bytes(bad)
    for i, f in enumerate(frags):
        m.add(pft(f, 120, i, 3, fec=(rsk, rsz), addr=(0x0001, 0x0002)))

    # 28-34: AF of 150 octets, 1 RS block over 8 fragments of 25 octets
    # (rx_min 7). Fragment 6 is lost: when fragment 7 arrives, 7 of 8 are
    # there, fragment 6 is filled with zeros and the RS decoder corrects
    # the 20 wrong octets (at most 24).
    a = af(tpl_sized(28, 138), 28)
    assert len(a) == 150
    rsk, rsz, plen, frags = fec_encode(a, 8)
    assert (rsk, rsz, plen) == (150, 0, 25)
    assert sum(1 for b in frags[6] if b) <= 24
    for i in (0, 1, 2, 3, 4, 5, 7):
        m.add(pft(frags[i], 121, i, 8, fec=(rsk, rsz)))

    # 35-38: the reproducer of "ETSI DCP: Zero the corrected data, reject an RS k of 0"
    # (dcp_pft_fec_rsk0.pcap): 4 fragments of 20 zero octets
    # with FEC and RSk 0. Rejected: no reassembly.
    for i in range(4):
        m.add(pft(bytes(20), 1, i, 4, fec=(0, 0)))

    # 39-40: RSk 208, larger than 207: no reassembly
    for i in range(2):
        m.add(pft(bytes(range(i, 60 + i)), 122, i, 2, fec=(208, 0)))

    m.write(os.path.join(outdir, 'dcp-etsi-coverage.pcap'))

    # --- malformed -----------------------------------------------------
    b = Pcap()
    x = af(tpl_small(1), 1)
    b.add(x[:-1] + bytes([x[-1] ^ 0xff]))                    # 1: bad AF CRC
    x = af(tpl_small(2), 2)
    b.add(x[:2] + struct.pack('!I', 0x100) + x[6:])          # 2: AF length too long
    b.add(b'AF\x00\x00\x00\x08\x00\x00\x10T*ptr\xff\xff\xff\xff\x00\x00')  # 3: tag bits 0xffffffff (dcp_tpl_hugebits.pcap)
    b.add(af(b'*ptr\x00\x00\x00\x40DM', 4))     # 4: tag value truncated
    b.add(pft(b'AF\x00', 10, 0, 1))                          # 5: PFT with a 3 octet AF
    b.add(pft(bytes(8), 11, 0, 300000, fec=(100, 0)))        # 6: Fcount above MAX_FRAGMENTS
    # 7-9: Findex above MAX_FRAGMENTS in the fragment list
    b.add(pft(bytes(8), 12, 0, 3, fec=(100, 0)))
    b.add(pft(bytes(8), 12, 300000, 3, fec=(100, 0)))
    b.add(pft(bytes(8), 12, 1, 3, fec=(100, 0)))
    # 10: a gap of more than 1000 fragments (rx_min is 1)
    b.add(pft(bytes(100), 13, 1500, 3, fec=(10, 0)))
    # 11-12: fragments of different sizes
    b.add(pft(bytes(30), 14, 0, 2, fec=(10, 0)))
    b.add(pft(bytes(20), 14, 1, 2, fec=(10, 0)))
    # 13-15: too many errors for the RS decoder
    a = af(tpl_sized(25, 288), 25)
    rsk, rsz, plen, frags = fec_encode(a, 3)
    f = bytearray(frags[1])
    for i in range(0, plen, 2):
        f[i] ^= ((i * 37 + 11) & 0xff) | 1
    frags[1] = bytes(f)
    for i, f in enumerate(frags):
        b.add(pft(f, 15, i, 3, fec=(rsk, rsz)))
    # 16-17: AF of 400 octets, RS k 200: the RS output is not written
    # beyond 455 octets of the 496 (see README)
    a = af(tpl_sized(17, 388), 17)
    rsk, rsz, plen, frags = fec_encode(a, 2)
    assert (rsk, plen) == (200, 248)
    for i, f in enumerate(frags):
        b.add(pft(f, 16, i, 2, fec=(rsk, rsz)))
    b.write(os.path.join(outdir, 'dcp-etsi-coverage-malformed.pcap'))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

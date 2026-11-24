#!/usr/bin/env python3
# Generates test/captures/mtp2_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MTP2 coverage captures. Usage: mkmtp2.py <outdir>
mtp2-coverage.pcapng       main capture (default preferences)
mtp2-coverage-erf.pcapng   ERF HDLC records (needs erf.hdlc_type:mtp2)
mtp2-coverage-malformed.pcapng  bad LI, short frames, bad FCS
Everything is synthetic."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---------------------------------------------------------------- pcapng
def blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

class Pcapng:
    def __init__(self):
        self.b = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        self.n = 0
        self.ts = 1700000000
    def idb(self, linktype):
        self.b += blk(1, struct.pack('<HHI', linktype, 0, 65535))
        self.n += 1
        return self.n - 1
    def pkt(self, ifid, data, usec=0):
        self.ts += 1
        t = self.ts * 1000000 + usec
        self.b += blk(6, struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data)) + data)
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(self.b)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_udp(src, dst, sport, dport, payload):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

# ---------------------------------------------------------------- MTP2
def su(bsn, bib, fsn, fib, li, payload=b'', spare=0):
    return bytes([bsn | bib << 7, fsn | fib << 7, (li & 0x3f) | spare << 6]) + payload

def su_ext(bsn, bib, fsn, fib, li, payload=b'', res=0, res1=None):
    # Annex A: 12 bit sequence numbers, 9 bit LI, little endian 16 bit words
    w0 = bsn | res << 12 | bib << 15
    w1 = fsn | (res if res1 is None else res1) << 12 | fib << 15
    w2 = li
    return struct.pack('<HHH', w0, w1, w2) + payload

def sltm(dpc, opc, sls, pattern, ni=0):
    sio = 0x01 | ni << 6                       # SI=1 (SNT), NI
    rl = dpc | opc << 14 | sls << 28
    return bytes([sio]) + struct.pack('<I', rl) + bytes([0x11, min(len(pattern), 15) << 4]) + pattern

def slta(dpc, opc, sls, pattern, ni=0):
    sio = 0x01 | ni << 6
    rl = dpc | opc << 14 | sls << 28
    return bytes([sio]) + struct.pack('<I', rl) + bytes([0x21, min(len(pattern), 15) << 4]) + pattern

def snm(dpc, opc, sls, h, body=b'', ni=0):
    sio = 0x00 | ni << 6
    rl = dpc | opc << 14 | sls << 28
    return bytes([sio]) + struct.pack('<I', rl) + bytes([h]) + body

def msu(bsn, fsn, mtp3, ext=False, bib=0, fib=0):
    li = min(len(mtp3), 63)
    if ext:
        return su_ext(bsn, bib, fsn, fib, len(mtp3), mtp3)
    return su(bsn, bib, fsn, fib, li, mtp3)

def fcs16(data):
    # CRC-16/X-25 as used by HDLC and MTP2
    crc = 0xffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return (~crc) & 0xffff

def with_fcs(data, bad=False):
    f = fcs16(data)
    if bad: f ^= 0x1234
    return data + struct.pack('<H', f)

# ---------------------------------------------------------------- bitstream
class Bits:
    def __init__(self):
        self.bits = []
    def flag(self):
        self.bits += [0, 1, 1, 1, 1, 1, 1, 0]
    def data(self, bs, stuff=True):
        ones = 0
        for byte in bs:
            for k in range(8):                 # LSB first (HDLC order)
                b = (byte >> k) & 1
                self.bits.append(b)
                ones = ones + 1 if b else 0
                if ones == 5 and stuff:
                    self.bits.append(0)
                    ones = 0
    def raw(self, s):
        self.bits += [int(c) for c in s]
    def frame(self, bs):
        self.flag(); self.data(bs); self.flag()
    def bytes_(self):
        b = list(self.bits)
        while len(b) % 8:
            b.append(0)
        out = bytearray()
        for i in range(0, len(b), 8):
            v = 0
            for k in range(8):
                v = v << 1 | b[i + k]           # MSB first on the wire
            out.append(v)
        return bytes(out)

def rtp(seq, ts, ssrc, pt, payload, m=0):
    return struct.pack('>BBHII', 0x80, pt | m << 7, seq, ts, ssrc) + payload

def cut(data, sizes):
    out, i, k = [], 0, 0
    while i < len(data):
        n = sizes[k % len(sizes)]
        out.append(data[i:i + n]); i += n; k += 1
    return out

def sip_sdp(method, cip, port, call='c1', pt=96, name='MTP2/8000', cseq=1, status=None):
    sdp = ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
           'm=audio %d RTP/AVP %d\r\na=rtpmap:%d %s\r\n' % (cip, cip, port, pt, pt, name))
    if status:
        start = 'SIP/2.0 200 OK'
    else:
        start = 'INVITE sip:ss7@192.0.2.2 SIP/2.0'
    hdr = (start + '\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
           'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:b@192.0.2.2>%s\r\nCall-ID: %s\r\n'
           'CSeq: %d INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
           % (';tag=2' if status else '', call, cseq, len(sdp)))
    return (hdr + sdp).encode()

A = [192, 0, 2, 1]
B = [192, 0, 2, 2]

def main():
    pc = Pcapng()
    if0 = pc.idb(140)       # LINKTYPE_MTP2
    if1 = pc.idb(139)       # LINKTYPE_MTP2_WITH_PHDR
    if2 = pc.idb(1)         # Ethernet
    # ---- 1..: raw MTP2, no FCS, standard 7 bit sequence numbers
    pc.pkt(if0, su(0, 1, 0, 1, 0))                                   # FISU
    pc.pkt(if0, su(5, 0, 5, 0, 1, b'\x00'))                          # LSSU SIO, one octet
    pc.pkt(if0, su(5, 0, 6, 1, 2, b'\x01\x00'))                      # LSSU SIN with the extra octet
    for sf, name in enumerate(range(6)):
        pc.pkt(if0, su(6, 1, 7 + sf, 0, 1, bytes([sf])))             # every status indication 0..5
    pc.pkt(if0, su(7, 0, 12, 0, 1, b'\x09'))                         # unknown status field
    pc.pkt(if0, msu(8, 13, sltm(100, 200, 3, b'TESTPATTERN12')))     # MSU, SI=1
    pc.pkt(if0, msu(8, 14, slta(200, 100, 3, b'TESTPATTERN12')))
    pc.pkt(if0, msu(9, 15, sltm(100, 200, 3, b'X' * 15)))            # LI 22 (< 63)
    pc.pkt(if0, msu(10, 16, snm(100, 200, 1, 0x11, b'\x05')))            # SNM COO
    long_sltm = sltm(100, 200, 3, b'L' * 15)
    pc.pkt(if0, su(11, 0, 17, 0, 63, long_sltm + b'Z' * 60))         # payload longer than 62: LI = 63
    # ---- raw MTP2 with 6 bit ... with the pseudo header (sent, annex A, link number)
    def ph(sent, annex, link):
        return struct.pack('>BBH', sent, annex, link)
    pc.pkt(if1, ph(1, 0, 1) + su(1, 0, 1, 0, 0))                    # annex A not used, FISU
    pc.pkt(if1, ph(0, 0, 2) + su(2, 0, 2, 0, 1, b'\x03'))           # LSSU
    pc.pkt(if1, ph(1, 0, 1) + msu(3, 3, sltm(1, 2, 0, b'PHDR-NOT-EXT')))
    pc.pkt(if1, ph(1, 1, 1) + su_ext(100, 0, 300, 1, 0))            # annex A used: extended FISU
    pc.pkt(if1, ph(0, 1, 1) + su_ext(101, 1, 301, 0, 1, b'\x04'))   # extended LSSU, LI 1
    pc.pkt(if1, ph(0, 1, 1) + su_ext(102, 0, 302, 0, 2, b'\x02\x00'))  # extended LSSU, LI 2 (extra octet)
    pc.pkt(if1, ph(1, 1, 1) + su_ext(2000 & 0xfff, 1, 4095, 1, 20, sltm(10, 20, 2, b'EXTENDED-LONG')[:20]))
    m = sltm(10, 20, 2, b'E' * 15)
    pc.pkt(if1, ph(1, 1, 1) + su_ext(103, 0, 303, 0, len(m), m))     # extended MSU
    m = sltm(10, 20, 2, b'E' * 15) + b'Y' * 70
    pc.pkt(if1, ph(1, 1, 1) + su_ext(103, 0, 304, 0, len(m), m))     # extended, LI > 63
    pc.pkt(if1, ph(0, 1, 1) + su_ext(104, 0, 305, 0, 0, res=0, res1=5))   # reserved bits differ in BSN and FSN words
    pc.pkt(if1, ph(0, 2, 1) + su(4, 0, 4, 0, 0))                     # annex A unknown: default (7 bit)
    pc.pkt(if1, ph(0, 2, 1) + msu(4, 5, sltm(1, 2, 0, b'UNKNOWN-ANNEX')))
    # ---- RTP carrying the MTP2 bitstream (SDP names the payload type "MTP2")
    pc.pkt(if2, eth_udp(A, B, 5060, 5060, sip_sdp('INVITE', '192.0.2.1', 5004)))
    pc.pkt(if2, eth_udp(B, A, 5060, 5060, sip_sdp('200', '192.0.2.2', 5004, status=True)))
    fwd = Bits()
    # leading garbage bits before the first flag (the 1111110x pattern at the very start is not a flag)
    fwd.raw('0111111')
    fwd.raw('10')
    fwd.frame(su(0, 1, 0, 1, 0))                                     # FISU
    fwd.flag()
    fwd.data(su(1, 0, 1, 0, 1, b'\x00')); fwd.flag()                 # LSSU
    fwd.data(msu(2, 2, sltm(100, 200, 3, b'FWD-MSU-0001'))); fwd.flag()
    fwd.data(msu(3, 3, sltm(100, 200, 3, b'\xff\xff\xff\xfe\x3f' * 6))); fwd.flag()   # stuffing
    fwd.data(su(3, 0, 4, 0, 1, b'\x01'), ); fwd.raw('101'); fwd.flag()     # unaligned: 3 extra bits
    fwd.data(su(4, 0, 5, 0, 1, b'\x02')); fwd.flag()
    fwd.data(su(4, 0, 6, 0, 1, b'\x03')); fwd.raw('1111111'); fwd.raw('0')  # 7 ones: out of sync (frame reset)
    fwd.data(b'\x55\x55\x55')                                       # garbage while out of sync
    fwd.flag()
    fwd.data(msu(5, 7, sltm(100, 200, 3, b'AFTER-RESET-01'))); fwd.flag()
    fwd.data(msu(6, 8, sltm(100, 200, 3, b'L' * 40))); fwd.flag()   # long frame, spans packets
    fwd.data(su(6, 0, 9, 0, 0)); fwd.flag()
    fwd.data(msu(7, 10, sltm(100, 200, 3, b'M' * 60))); fwd.flag()
    fwd.flag(); fwd.flag()
    fwd.data(su(7, 0, 11, 0, 2, b'\x00\x00')); fwd.flag()
    bwd = Bits()
    bwd.raw('0')
    bwd.frame(su(9, 0, 3, 1, 0))
    bwd.data(msu(9, 4, slta(200, 100, 3, b'BWD-MSU-0001'))); bwd.flag()
    bwd.data(su(10, 0, 5, 0, 1, b'\x05')); bwd.flag()
    bwd.data(msu(11, 6, slta(200, 100, 3, b'B' * 30))); bwd.flag()
    bwd.data(su(12, 0, 7, 0, 0)); bwd.flag()
    fb = fwd.bytes_(); bb = bwd.bytes_()
    fchunks = cut(fb, [9, 12, 4, 3, 17, 6, 8, 5])
    bchunks = cut(bb, [7, 3, 11, 5])
    seqf = seqb = 1000
    order = []
    fi = bi = 0
    while fi < len(fchunks) or bi < len(bchunks):
        for _ in range(2):
            if fi < len(fchunks):
                order.append(('f', fchunks[fi])); fi += 1
        if bi < len(bchunks):
            order.append(('b', bchunks[bi])); bi += 1
    for d, chunk in order:
        if d == 'f':
            pc.pkt(if2, eth_udp(A, B, 5004, 5004, rtp(seqf, seqf * 160, 0x1111, 96, chunk)))
            seqf += 1
        else:
            pc.pkt(if2, eth_udp(B, A, 5004, 5004, rtp(seqb, seqb * 160, 0x2222, 96, chunk)))
            seqb += 1
    # ---- an RTP packet with only 1-bits: out of sync in the middle of a packet with no flag
    pc.pkt(if2, eth_udp(A, B, 5004, 5004, rtp(seqf, seqf * 160, 0x1111, 96, b'\xff\xff\xff')))
    seqf += 1
    pc.pkt(if2, eth_udp(A, B, 5004, 5004, rtp(seqf, seqf * 160, 0x1111, 96, b'\x00\x00')))
    # ---- second bitstream conversation: first packet without any HDLC flag,
    # a frame reset inside a frame that spans two packets, a frame longer
    # than 255 bytes and a packet longer than 255 bytes (idle flags)
    pc.pkt(if2, eth_udp(A, B, 5060, 5060, sip_sdp('INVITE', '192.0.2.2', 5008, call='c3', cseq=2)))
    pc.pkt(if2, eth_udp(B, A, 5060, 5060, sip_sdp('200', '192.0.2.1', 5008, call='c3', cseq=2, status=True)))
    def r8(seq, payload):
        pc.pkt(if2, eth_udp(A, B, 5008, 5008, rtp(seq, seq * 160, 0x4444, 96, payload)))
    r8(1, b'\x00' * 16)                                              # no flag at all (first packet)
    b1 = Bits(); b1.flag(); b1.data(b'\x01\x02\x03')
    r8(2, b1.bytes_())                                               # flag, start of a frame
    b2 = Bits(); b2.raw('11111111'); b2.flag(); b2.data(su(0, 0, 1, 0, 0)); b2.flag()
    r8(3, b2.bytes_())                                               # reset inside the frame, then a FISU
    b3 = Bits(); b3.frame(su(1, 0, 2, 0, 63, sltm(100, 200, 1, b'BIG') + b'F' * 280))
    r8(4, b3.bytes_())                                               # one frame of 300 bytes
    r8(5, b'\x7e' * 270 + b''.join(bytes([0x7e]) for _ in range(0)))   # only idle flags, over 255 bytes
    b4 = Bits(); b4.data(su(2, 0, 3, 0, 0)); b4.flag()
    r8(6, b'\x7e' * 260 + b4.bytes_())                               # frame after more than 255 bytes
    r8(7, b'\xff\xff')                                              # all ones: out of sync, no flag
    pc.write('mtp2-coverage.pcapng')

    # ---- bug reproducers / extra: packet with no HDLC flag at all (wmem_new0 fix),
    # the first packet of another conversation, sent twice
    # (included in the main capture above as the 'no flag' packets) -- plus a
    # separate conversation here is added to the main capture:
    # ---- ERF capture (the ERF dissector needs erf.hdlc_type:mtp2)
    pe = Pcapng()
    ife = pe.idb(197)
    def erf(rec_type, payload, extra=0):
        h = struct.pack('<QBB', 0, rec_type, 0) + struct.pack('>HHH', 16 + len(payload), 0, len(payload) + extra)
        return h + payload
    pe.pkt(ife, erf(1, with_fcs(su(0, 0, 0, 0, 0))))
    pe.pkt(ife, erf(1, with_fcs(su(1, 0, 1, 0, 1, b'\x00'))))
    pe.pkt(ife, erf(1, with_fcs(msu(2, 2, sltm(100, 200, 3, b'ERF-MSU-0001')))))
    pe.pkt(ife, erf(1, with_fcs(msu(3, 3, sltm(100, 200, 3, b'ERF-MSU-0002')), bad=True)))
    pe.pkt(ife, erf(1, with_fcs(msu(4, 4, sltm(100, 200, 3, b'ERF-TRUNCATED')))[:-4], extra=4))   # FCS cut off by the capture
    pe.write('mtp2-coverage-erf.pcapng')

    # ---- malformed / odd input
    pm = Pcapng()
    m0 = pm.idb(140); m1 = pm.idb(139); m2 = pm.idb(1)
    pm.pkt(m0, su(0, 0, 0, 0, 5))                                   # FISU-size frame, LI 5 != 0 -> wait: LI 5
    pm.pkt(m0, su(0, 0, 0, 0, 3, b'\x00\x00'))                       # LI 3 but 2 payload bytes
    pm.pkt(m0, su(0, 0, 0, 0, 20, b'\x00' * 70))                     # long payload, LI != 63
    pm.pkt(m0, su(0, 0, 0, 0, 0, b'\x00' * 2))                       # LI 0, payload present
    pm.pkt(m0, b'\x01\x02')                                          # truncated header
    pm.pkt(m0, su(0, 0, 0, 0, 1))                                    # LSSU with the status octet missing
    pm.pkt(m0, su(0, 0, 0, 0, 2, b'\x00'))                           # LSSU, extra octet missing
    pm.pkt(m0, su(0, 0, 0, 0, 4, b'\x00\x00\x00\x00'))               # MSU without a full routing label
    pm.pkt(m0, su(0, 0, 0, 0, 1) [:3])
    pm.pkt(m1, struct.pack('>BBH', 0, 1, 1) + su_ext(1, 0, 1, 0, 7, b'\x00\x00'))   # ext, LI mismatch
    pm.pkt(m1, struct.pack('>BBH', 0, 1, 1) + su_ext(1, 0, 1, 0, 1, b'\x00'))
    pm.pkt(m1, struct.pack('>BBH', 0, 1, 1) + b'\x00\x00')
    pm.pkt(m1, struct.pack('>BBH', 0, 1, 1) + su_ext(1, 0, 1, 0, 2, b'\x00'))
    pm.pkt(m1, struct.pack('>BBH', 0, 1, 1))
    # RTP bitstream conversation with no HDLC flag at all, repeated (bug fix reproducer)
    pm.pkt(m2, eth_udp(A, B, 5060, 5060, sip_sdp('INVITE', '192.0.2.2', 6004, call='c2')))
    for i in range(3):
        pm.pkt(m2, eth_udp(A, B, 6004, 6004, rtp(1 + i, 160 * i, 0x3333, 96, b'\x00' * 16)))
    pm.pkt(m2, eth_udp(A, B, 6004, 6004, rtp(10, 1600, 0x3333, 96, b'')))
    pm.write('mtp2-coverage-malformed.pcapng')

main()

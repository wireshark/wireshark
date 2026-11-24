#!/usr/bin/env python3
# Generates test/captures/mp2t_coverage.pcapng.gz, mp2t_coverage_ts.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds the MP2T (ISO/IEC 13818-1 transport stream) coverage captures. Usage: mkmp2t.py <outdir> [-v]
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(a):
    return bytes(int(x) for x in a.split('.'))

ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01'

def ethip(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + b'\x08\x00' + ip + payload

def udp(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ethip(17, u, src, dst)

def tcp(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ip4(src) + ip4(dst) + struct.pack('>BBH', 0, 6, len(t))
    c = csum(pseudo + t)
    t = t[:16] + struct.pack('>H', c) + t[18:]
    return ethip(6, t, src, dst)

def exp_pdu(name, payload, extra=b''):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + extra + struct.pack('>HH', 0, 0) + payload

def rtp(pt, seq, ts, payload, ssrc=0x11223344, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq & 0xffff, ts & 0xffffffff, ssrc) + payload

class Cap:
    """pcapng writer with interface 0 = Ethernet, 1 = Exported PDU (252)."""
    def __init__(self):
        self.frames = []
    def eth(self, data, note=None):
        self.frames.append((1, data)); return len(self.frames)
    def epdu(self, name, payload, extra=b''):
        self.frames.append((252, exp_pdu(name, payload, extra))); return len(self.frames)
    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 1, 0, 0))
        out += blk(1, struct.pack('<HHI', 252, 0, 0))
        for i, (lt, d) in enumerate(self.frames):
            out += blk(6, struct.pack('<IIIII', 0 if lt == 1 else 1, 0, 1000 + i, len(d), len(d)) + d)
        open(fname, 'wb').write(out)

def pcap(fname, linktype, pkts):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)) + p)

def crc32_mpeg2(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc

def section(table_id, ext, data, ver=1, sec=0, last=0, long_form=True):
    if long_form:
        body = struct.pack('>HBBB', ext, 0xc1 | (ver << 1), sec, last) + data
        ln = len(body) + 4
        hdr = bytes([table_id, 0xb0 | (ln >> 8), ln & 0xff])
        sec_b = hdr + body
        return sec_b + struct.pack('>I', crc32_mpeg2(sec_b))
    ln = len(data)
    return bytes([table_id, 0x30 | (ln >> 8), ln & 0xff]) + data

def fcs16(data):
    fcs = 0xffff
    for b in data:
        fcs ^= b
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
    return fcs ^ 0xffff

def pat(progs):
    return section(0x00, 1, b''.join(struct.pack('>HH', n, 0xe000 | p) for n, p in progs))

def pmt(prog, pcr_pid, streams, prog_desc=b''):
    d = struct.pack('>HH', 0xe000 | pcr_pid, 0xf000 | len(prog_desc)) + prog_desc
    for st, pid, desc in streams:
        d += struct.pack('>BHH', st, 0xe000 | pid, 0xf000 | len(desc)) + desc
    return section(0x02, prog, d)

def reg_desc(fourcc):
    return bytes([0x05, 4]) + fourcc

def pts(v, marker=0x2):
    return bytes([(marker << 4) | (((v >> 30) & 7) << 1) | 1, (v >> 22) & 0xff, (((v >> 15) & 0x7f) << 1) | 1,
                  (v >> 7) & 0xff, ((v & 0x7f) << 1) | 1])

def pes(stream_id, payload, bounded=True, with_pts=True, length=None):
    hdr = b'\x80' + (b'\x80' if with_pts else b'\x00') + bytes([5 if with_pts else 0]) + (pts(90000) if with_pts else b'')
    body = hdr + payload
    ln = len(body) if length is None else length
    if not bounded:
        ln = 0
    return b'\x00\x00\x01' + bytes([stream_id]) + struct.pack('>H', ln) + body

def tsp(pid, cc, payload=b'', pusi=0, tsc=0, tei=0, tp=0, af=None, afc=None, stuff=0xff, af_fill=False):
    """One 188 octet TS packet. af = adaptation field content without its length octet.
    af_fill pads the adaptation field with stuffing so that a short payload fills the packet."""
    cap = 184
    af_b = None
    if af is not None:
        af_b = bytes(af)
    if af_fill:
        need = cap - len(payload)
        if need > 0:
            base = af_b if af_b is not None else b''
            if af_b is None:
                if need == 1:
                    af_b = b''                         # length 0: one stuffing octet
                else:
                    af_b = b'\x00' + bytes([stuff]) * (need - 2)
            else:
                af_b = base + bytes([stuff]) * (need - 1 - len(base))
    if af_b is not None:
        field = bytes([len(af_b)]) + af_b
        if afc is None:
            afc = 3 if payload or len(field) < cap else 2
        pl = payload
        total = field + pl
        total += bytes([stuff]) * (cap - len(total))
        body = total[:cap]
    else:
        if afc is None:
            afc = 1
        body = payload + bytes([stuff]) * (cap - len(payload))
        body = body[:cap]
    h = bytes([0x47, (tei << 7) | (pusi << 6) | (tp << 5) | (pid >> 8), pid & 0xff, (tsc << 6) | (afc << 4) | (cc & 15)])
    return h + body

class Stream:
    """TS packets for one conversation, with a continuity counter per PID."""
    def __init__(self):
        self.cc = {}
    def p(self, pid, payload=b'', **kw):
        cc = self.cc.get(pid, 0)
        kw_cc = kw.pop('cc', None)
        if kw_cc is not None:
            cc = kw_cc
        pkt = tsp(pid, cc, payload, **kw)
        afc = (pkt[3] >> 4) & 3
        self.cc[pid] = (cc + (1 if afc & 1 else 0)) & 15
        return pkt

def pcr(base, ext=0):
    v = (base << 15) | (0x3f << 9) | ext
    return v.to_bytes(6, 'big')

def sect_tsps(s, pid, pointer_pad=0, first_prefix=b''):
    """Split a section (or concatenated sections) over TSPs: first with PUSI and pointer."""
    out = []
    data = first_prefix + s
    first = bytes([pointer_pad]) + b'\xff' * 0 + data
    chunks = [first[:184]]
    rest = first[184:]
    while rest:
        chunks.append(rest[:184])
        rest = rest[184:]
    for i, c in enumerate(chunks):
        out.append((c, 1 if i == 0 else 0))
    return out

def main(out, verbose):
    cap = Cap()
    marks = []
    def mark(name):
        marks.append((name, len(cap.frames) + 1))
    A, B = '192.0.2.10', '192.0.2.20'
    state = {'ident': 1}
    def dgram(tsps, sport=1234, dport=1234, src=A, dst=B):
        cap.eth(udp(b''.join(tsps), sport, dport, src, dst))
    s = Stream()

    # 1. PSI: PAT, PMT with stream types and registration descriptors
    mark('PSI')
    dgram([s.p(0, bytes([0]) + pat([(1, 0x100), (2, 0x110)]), pusi=1),
           s.p(0x100, bytes([0]) + pmt(1, 0x101, [(0x02, 0x101, reg_desc(b'HDMV')), (0x0f, 0x102, b''),
                                                  (0x06, 0x103, reg_desc(b'AC-3')), (0x86, 0x104, b'')]), pusi=1),
           s.p(0x110, bytes([0]) + pmt(2, 0x111, [(0x02, 0x111, b''), (0x03, 0x112, b'')]), pusi=1)])
    # 2. video PES, bounded, over three TSPs; AF with PCR and stuffing
    mark('PES')
    v = pes(0xe0, bytes(range(256)) * 1)
    dgram([s.p(0x101, v[:170], pusi=1, af=b'\x10' + pcr(1000, 5)),
           s.p(0x101, v[170:170 + 184]),
           s.p(0x101, v[170 + 184:], af_fill=True)])
    # PES exactly filling the last TSP, no stuffing (frag_cur_pos + remaining == frag_tot_len)
    v2 = pes(0xe0, bytes(184 + 100 - 14 - 6 + 0))
    v2 = pes(0xe0, bytes(184 - 14 + 184 - 0 - 0))
    dgram([s.p(0x101, v2[:184], pusi=1), s.p(0x101, v2[184:368]) if len(v2) >= 368 else s.p(0x101, v2[184:], af_fill=True)])
    # small audio PES in one TSP, with stuffing in the AF; two PES in one TSP
    a1 = pes(0xc0, bytes(30))
    dgram([s.p(0x102, a1, pusi=1, af_fill=True),
           s.p(0x102, a1 + pes(0xc0, bytes(20)), pusi=1),
           s.p(0x102, a1 + b'\xff' * 10, pusi=1)])
    # unbounded PES (length 0) across TSPs, ended by the next PES start with PUSI
    u = pes(0xe0, bytes(300), bounded=False)
    dgram([s.p(0x101, u[:184], pusi=1), s.p(0x101, u[184:], af_fill=True),
           s.p(0x101, pes(0xe0, bytes(10), bounded=False), pusi=1, af_fill=True),
           s.p(0x101, b'', pusi=1, af=b'\x00', afc=2, af_fill=True)])
    # PES without PTS, private stream, padding stream id
    dgram([s.p(0x103, pes(0xbd, bytes(40), with_pts=False), pusi=1, af_fill=True),
           s.p(0x103, pes(0xbe, bytes(40), with_pts=False), pusi=1, af_fill=True),
           s.p(0x103, pes(0xe1, bytes(40)), pusi=1, af_fill=True)])
    # PES header split: only five octets of the PES header fit in the first TSP
    mark('PES header split')
    sp = pes(0xe0, bytes(100))
    dgram([s.p(0x101, sp[:5], pusi=1, af_fill=True)]); dgram([s.p(0x101, sp[5:], af_fill=True)])
    # PES split where the first TSP carries only the first four octets (below the six needed for the length)
    sp = pes(0xe0, bytes(100))
    dgram([s.p(0x101, sp[:4], pusi=1, af_fill=True)]); dgram([s.p(0x101, sp[4:], af_fill=True)])
    # 3. sections: a long private section over three TSPs
    mark('Sections')
    big = section(0x80, 0x1234, bytes(range(256)) + bytes(60), long_form=True)
    tp = sect_tsps(big, 0x20)
    dgram([s.p(0x20, c, pusi=p) for c, p in tp])
    # pointer > 0: tail of the previous section, then stuffing then a new section
    sa = section(0x80, 1, bytes(200), ver=2)
    tpa = sect_tsps(sa, 0x21)
    # second TSP of sa carries the tail: pointer = tail length, followed by a short section
    tail = tpa[1][0]
    nsec = section(0x81, 2, b'abc')
    dgram([s.p(0x21, tpa[0][0], pusi=1),
           s.p(0x21, bytes([len(tail)]) + tail + b'\xff\xff' + nsec, pusi=1)])
    # two complete sections in one TSP, then stuffing; a short-form section
    dgram([s.p(0x22, bytes([0]) + section(0x80, 1, b'x' * 20) + section(0x81, 2, b'y' * 10) +
               section(0x82, 0, b'zz', long_form=False), pusi=1)])
    # stuffing between sections, stuffing only after a pointer
    dgram([s.p(0x22, bytes([0]) + b'\xff\xff\xff' + section(0x80, 3, b'q' * 8) + b'\xff' * 5 +
               section(0x81, 4, b'r' * 8), pusi=1)])
    dgram([s.p(0x23, bytes([0]) + b'\xff' * 183, pusi=1)])
    # a continuing section that ends, followed by stuffing, with PUSI 0
    sb = section(0x80, 5, bytes(190))
    tb = sect_tsps(sb, 0x24)
    dgram([s.p(0x24, tb[0][0], pusi=1), s.p(0x24, tb[1][0])])
    # section header split across two TSPs: total length such that 2 octets remain
    s1 = section(0x80, 6, bytes(181 - 12), ver=3)            # 3+5+data+4 = 181
    s2 = section(0x81, 7, bytes(40))
    first = bytes([0]) + s1 + s2[:2]
    dgram([s.p(0x25, first, pusi=1)]); dgram([s.p(0x25, s2[2:])])
    # header split with a single octet left
    s1 = section(0x80, 6, bytes(182 - 12), ver=3)
    first = bytes([0]) + s1 + s2[:1]
    dgram([s.p(0x25, first, pusi=1)]); dgram([s.p(0x25, s2[1:])])
    # a header split with no data left at all, then the new section's start in the next TSP
    dgram([s.p(0x28, bytes([0]) + section(0x80, 6, bytes(184 - 1 - 12 - 0)), pusi=1)])
    dgram([s.p(0x28, bytes([0]) + section(0x81, 7, b'next'), pusi=1)])
    # the PES/SECT type is chosen from the first PUSI payload; a PES start code on a PSI PID
    dgram([s.p(0x26, pes(0xe0, bytes(20)), pusi=1, af_fill=True)])
    # a section with pointer and a fully packed continuation
    sc = section(0x80, 8, bytes(170))
    tc = sect_tsps(sc, 0x27)
    dgram([s.p(0x27, c, pusi=p) for c, p in tc] + [s.p(0x27, bytes([0]) + section(0x81, 9, b'next'), pusi=1)])

    # 4. DOCSIS MAC frames on PID 0x1ffe
    mark('DOCSIS')
    def docsis(n):
        eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x88, 0xb5]) + bytes(n)
        hdr = struct.pack('>BBH', 0x00, 0x00, len(eth) + 4)
        return hdr + struct.pack('<H', fcs16(hdr)) + eth + b'\0\0\0\0'
    d1 = docsis(40)
    d2 = docsis(250)          # 274 octets: 183 in the first TSP, 91 in the next
    d3 = docsis(120)          # 144 octets
    dgram([s.p(0x1ffe, bytes([0]) + d1, pusi=1),
           s.p(0x1ffe, bytes([0]) + d2[:183], pusi=1),
           s.p(0x1ffe, bytes([91]) + d2[183:] + b'\xff\xff' + d1, pusi=1),
           s.p(0x1ffe, bytes([0]) + d3, pusi=1),
           s.p(0x1ffe, bytes([0]) + d2[:183], pusi=1),
           s.p(0x1ffe, d2[183:])])
    # DOCSIS header split: three octets of the next frame at the end of a TSP
    dd = docsis(156)
    dn = docsis(60)
    dgram([s.p(0x1ffe, bytes([0]) + dd + dn[:3], pusi=1)]); dgram([s.p(0x1ffe, dn[3:])])
    # DOCSIS with an adaptation field: the invalid AFC warning
    dgram([s.p(0x1ffe, bytes([0]) + d1, pusi=1, af=b'\x00', afc=3)])

    # UDP datagrams the MP2T heuristic rejects: empty, wrong sync byte, not a multiple of 188
    cap.eth(udp(b'', 1234, 1234, A, B))
    cap.eth(udp(b'\x00' + tsp(0x100, 0, b'')[1:], 1234, 1234, A, B))
    cap.eth(udp(tsp(0x100, 0, b'') + tsp(0x100, 1, b'')[:100], 2345, 2345, A, B))
    # 5. NULL packets and the invalid AFC for them
    mark('NULL')
    dgram([tsp(0x1fff, 0, b'', afc=1) for _ in range(3)] + [tsp(0x1fff, 0, b'', afc=3, af=b'\x00')])

    # 6. adaptation fields on a PID without payload type (no PUSI payload)
    mark('Adaptation fields')
    P = 0x200
    afs = []
    afs.append(s.p(P, b'', af=b'\xe0', afc=2, af_fill=True))                  # DI RAI ESPI only
    afs.append(s.p(P, b'', af=b'\x10' + pcr(123456789, 100), afc=2, af_fill=True))
    afs.append(s.p(P, b'', af=b'\x18' + pcr(1, 2) + pcr(3, 4), afc=2, af_fill=True))   # PCR + OPCR
    afs.append(s.p(P, b'', af=b'\x04\x7f', afc=2, af_fill=True))               # splicing point
    afs.append(s.p(P, b'', af=b'\x02\x05hello', afc=2, af_fill=True))          # transport private data
    ext = b'\x01' + bytes([1 + 2]) + b'\x80' + b'\xff\xfe'                     # extension: LTW
    afs.append(s.p(P, b'', af=ext, afc=2, af_fill=True))
    ext = b'\x01' + bytes([1 + 3]) + b'\x40' + b'\xc0\x01\x02'                 # piecewise rate
    afs.append(s.p(P, b'', af=ext, afc=2, af_fill=True))
    ext = b'\x01' + bytes([1 + 5]) + b'\x20' + bytes([0x2a, 0x12, 0x35, 0x56, 0x79])   # seamless splice
    afs.append(s.p(P, b'', af=ext, afc=2, af_fill=True))
    ext = b'\x01' + bytes([1 + 2 + 3 + 5 + 4]) + b'\xe0' + b'\xff\xfe' + b'\xc0\x01\x02' + bytes([0x2a, 0x12, 0x35, 0x56, 0x79]) + b'\xaa' * 4
    afs.append(s.p(P, b'', af=ext, afc=2, af_fill=True))                       # all, reserved bytes
    ext = b'\x01' + bytes([1 + 3]) + b'\x00' + b'\x11\x22\x33'                 # only reserved bytes
    afs.append(s.p(P, b'', af=ext, afc=2, af_fill=True))
    afs.append(s.p(P, b'', af=b'\x00', afc=2, af_fill=True))                   # flags only
    afs.append(s.p(P, b'', afc=2, af=b''))                                      # adaptation_field_length 0 (afc 2)
    afs.append(s.p(P, b'', afc=3, af=b''))                                      # afc 3 with length 0, stuffing as payload
    dgram(afs[:7]); dgram(afs[7:])
    # afc 3 with an adaptation field and payload that cannot be typed (PUSI 0 first), TEI and TP bits
    dgram([tsp(0x201, 0, b'\x11' * 100, afc=3, af=b'\x10' + pcr(5, 6) + b'\xff\xff', tei=1, tp=1, af_fill=True),
           tsp(0x201, 1, b'\x22' * 50, pusi=0),
           tsp(0x201, 2, b'\x22\x33\x44', pusi=1),                           # PUSI but too short to type
           tsp(0x201, 3, b'', afc=2, af=b'\x00', af_fill=True),
           tsp(0x201, 3, bytes(184), afc=0)])                              # reserved AFC value
    # AF taking the whole payload (afc 3, adaptation_field_length 183: no payload left)
    dgram([tsp(0x202, 0, b'', afc=3, af=b'\x00' + b'\xff' * 182)])
    # scrambled payloads, even and odd keys, reserved value
    dgram([tsp(0x203, 0, bytes(range(184)), tsc=2), tsp(0x203, 1, bytes(range(184)), tsc=3),
           tsp(0x203, 2, bytes(range(184)), tsc=1)])

    # 7. continuity counter: same CC (allowed with an adaptation field only), then increments
    mark('Continuity')
    dgram([tsp(0x204, 5, b'', afc=2, af=b'\x00', af_fill=True), tsp(0x204, 5, b'', afc=2, af=b'\x00', af_fill=True),
           tsp(0x204, 6, bytes(184), pusi=0), tsp(0x204, 7, bytes(184)), tsp(0x204, 8, bytes(184))])

    # 8. second direction of the same conversation (two MP2T streams in opposite directions)
    mark('Reverse direction')
    r = Stream()
    dgram([r.p(0, bytes([0]) + pat([(3, 0x300)]), pusi=1),
           r.p(0x300, bytes([0]) + pmt(3, 0x301, [(0x06, 0x301, reg_desc(b'HEVC'))]), pusi=1),
           r.p(0x301, pes(0xe0, bytes(40)), pusi=1, af_fill=True)], src=B, dst=A)
    # 9. a different conversation (another UDP port pair)
    mark('Second conversation')
    s2c = Stream()
    dgram([s2c.p(0x100, pes(0xe0, bytes(30)), pusi=1, af_fill=True), tsp(0x1fff, 0, b'')], sport=5555, dport=5556)

    # 10. RTP payload type 33 (MP2T) announced by SDP
    mark('RTP')
    sdp = ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=mp2t\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\n'
           'm=video 6000 RTP/AVP 33\r\na=rtpmap:33 MP2T/90000\r\n')
    sip = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n'
           'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: mp2t@192.0.2.10\r\n'
           'CSeq: 1 INVITE\r\nContact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n' % len(sdp)) + sdp
    cap.eth(udp(sip.encode(), 5060, 5060, A, B))
    rs = Stream()
    for i in range(3):
        cap.eth(udp(rtp(33, 10 + i, 1000 * i, b''.join(
            [rs.p(0x100, pes(0xe0, bytes(20)), pusi=1, af_fill=True) for _ in range(7)])), 6000, 6000, A, B))
    # 11. HTTP body of type video/mp2t
    mark('HTTP')
    hs = Stream()
    body = b''.join([hs.p(0x100, pes(0xe0, bytes(30)), pusi=1, af_fill=True) for _ in range(4)])
    resp = (b'HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
    seq = 1000
    cap.eth(tcp(b'GET /seg.ts HTTP/1.1\r\nHost: a\r\n\r\n', 40000, 80, 1, 1, src=A, dst=B))
    greq = 1 + len(b'GET /seg.ts HTTP/1.1\r\nHost: a\r\n\r\n')
    for i in range(0, len(resp), 600):
        ch = resp[i:i + 600]
        cap.eth(tcp(ch, 80, 40000, seq, greq, src=B, dst=A)); seq += len(ch)
    mark('end')
    cap.write(os.path.join(out, 'mp2t-coverage.pcapng'))
    # Transport stream linktype (243, WTAP_ENCAP_MPEG_2_TS): the file itself is the stream
    write_ts_pcap(os.path.join(out, 'mp2t-coverage-ts.pcap'))

    # Malformed and error-severity paths
    m = Cap()
    ms = Stream()
    def md(tsps, sport=7000):
        m.eth(udp(b''.join(tsps), sport, sport, A, B))
    # continuity counter drops (PI_ERROR)
    md([tsp(0x300, 1, b'\x00' * 184), tsp(0x300, 2, bytes(184)), tsp(0x300, 5, bytes(184)), tsp(0x300, 6, bytes(184)),
        tsp(0x300, 6, bytes(184)), tsp(0x300, 0, bytes(184))])
    # pointer larger than the remaining data
    md([tsp(0x301, 0, bytes([200]) + bytes(100), pusi=1), tsp(0x301, 1, bytes([184]) + bytes(183), pusi=1)])
    md([tsp(0x302, 0, bytes([183]) + b'\xff', pusi=1), tsp(0x302, 1, bytes([182]) + section(0x80, 1, b'ab'), pusi=1)])
    # NULL packet and DOCSIS with AF only
    md([tsp(0x1fff, 0, b'', afc=2, af=b'\x00', af_fill=True), tsp(0x1fff, 0, bytes(184), afc=0)])
    badpmt = section(0x02, 1, struct.pack('>HH', 0xe101, 0xf000) + b'\x1b' + struct.pack('>HH', 0xe101, 0xf0ff) + bytes(240))
    tpb = sect_tsps(badpmt, 0x29)
    md([tsp(0x29, 0, c, pusi=p) for c, p in tpb])        # exception in the reassembled PMT (a TRY block in MP2T)
    # reassembled data that a subdissector cannot parse (PMT cut short, PES cut short, DOCSIS cut short)
    bad_pmt = section(0x02, 1, struct.pack('>HH', 0xe101, 0xf000) + b'\x1b\xe1')            # stream entry cut
    md([tsp(0x400, 0, bytes([0]) + bad_pmt, pusi=1), tsp(0x400, 1, bytes([0]) + bad_pmt[:10], pusi=1)])
    md([tsp(0x401, 0, pes(0xe0, bytes(30), length=500)[:100], pusi=1), tsp(0x401, 1, bytes(20), af_fill=True)])
    md([tsp(0x1ffe, 0, bytes([0]) + docsis(40)[:20] + bytes(10), pusi=1)])
    md([tsp(0x1ffe, 0, bytes([0]) + b'\x00\x00\x00\x03\x00\x00ab', pusi=1)])
    # dropped packet in the middle of a section / PES (reassembly without its first part)
    md([tsp(0x402, 3, bytes(184), pusi=0), tsp(0x402, 4, bytes([100]) + bytes(183), pusi=1)])
    md([tsp(0x403, 0, bytes([0]) + section(0x80, 1, bytes(300))[:170], pusi=1), tsp(0x403, 2, bytes(184)), tsp(0x403, 3, bytes(184))])
    md([tsp(0x403, 4, bytes(50), pusi=0, af_fill=True)])
    # adaptation field longer than the packet
    md([bytes([0x47, 0x10, 0x00, 0x30]) + bytes([200]) + bytes(183)])
    md([bytes([0x47, 0x10, 0x01, 0x30]) + bytes([183, 0x10]) + bytes(182)])        # PCR beyond the end
    md([bytes([0x47, 0x10, 0x01, 0x31]) + bytes([5, 0x02, 200]) + bytes(182)])     # private data longer than the AF
    md([bytes([0x47, 0x10, 0x01, 0x32]) + bytes([5, 0x01, 100, 0xe0]) + bytes(181)])
    # AF-only packets whose adaptation field does not fill the packet: the rest is stuffing,
    # but the dissector then processes it as payload (observation in the README)
    md([tsp(0x101, 0, b'', pusi=1, af=b'\x00', afc=2), tsp(0x101, 1, b'', pusi=0, af=b'\x10' + pcr(1, 1), afc=2)])
    md([tsp(0x404, 0, b'', pusi=1, af=b'\x00', afc=2)])
    # a datagram with an incomplete last TSP (not a multiple of 188: the heuristic does not accept it)
    m.eth(udp(tsp(0x500, 0, bytes(184)) + b'\x47\x00', 7000, 7000, A, B))
    # a TS with TEI set and frames over the Decode-As port
    md([tsp(0x600, 0, bytes(184), tei=1)], sport=7100)
    m.write(os.path.join(out, 'mp2t-coverage-malformed.pcapng'))
    if verbose:
        print(marks, 'total', len(cap.frames))

def write_ts_pcap(fname):
    """pcap with linktype 243: each record holds whole TS packets."""
    st = Stream()
    pkts = [b''.join([st.p(0, bytes([0]) + pat([(1, 0x100)]), pusi=1),
                      st.p(0x100, bytes([0]) + pmt(1, 0x101, [(0x02, 0x101, b'')]), pusi=1),
                      st.p(0x101, pes(0xe0, bytes(40)), pusi=1, af_fill=True)]),
            b''.join([st.p(0x101, pes(0xe0, bytes(10)), pusi=1, af_fill=True), tsp(0x1fff, 0, b'')])]
    pcap(fname, 243, pkts)

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

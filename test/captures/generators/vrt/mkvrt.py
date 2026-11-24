# Generates test/captures/vrt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

# ---- VITA 49 Radio Transport (VRT) over UDP 4991 ----

SZ0 = {8: 8, 9: 8, 10: 4, 11: 52, 12: 52, 13: 44, 14: 44, 15: 8, 16: 4, 17: 8, 18: 4, 19: 4, 20: 8, 21: 8,
       22: 4, 23: 4, 24: 4, 25: 8, 26: 8, 27: 8, 28: 8, 29: 8, 30: 4, 31: 0}
SZ1 = {1: 8, 2: 4, 3: 4, 4: 4, 5: 8, 6: 4, 7: 0, 8: 0, 9: 0, 10: 52, 11: 0, 12: 0, 13: 8, 14: 4, 15: 8, 16: 4,
       17: 4, 18: 4, 19: 4, 20: 4, 21: 0, 22: 0, 23: 0, 24: 4, 25: 4, 26: 4, 27: 4, 28: 0, 29: 4, 30: 4, 31: 4}
VAR0 = (8, 9)
VAR1 = (7, 9, 11, 28)

def udp_pkt(payload, sport=50000, dport=4991):
    return eth(ip4(17, udp(sport, dport, payload)))

def vrt_pkt(ptype, body, cid=0, t=0, tsi=0, tsf=0, seq=0, sid=None, classid=None, ts_int=None, ts_frac=None,
            words=None, tsm=0):
    """body: everything after the optional header fields (data or context fields)."""
    b0 = (ptype << 4) | (cid << 3) | ((tsm if ptype == 4 else t) << 2 if ptype != 4 else tsm)
    if ptype != 4:
        b0 = (ptype << 4) | (cid << 3) | (t << 2)
    b1 = (tsi << 6) | (tsf << 4) | (seq & 0xf)
    opt = b''
    if ptype in (1, 3, 4, 5):
        opt += struct.pack('!I', 0x11223344 if sid is None else sid)
    if cid:
        opt += classid if classid is not None else struct.pack('!BBBBHH', 0, 0x00, 0x12, 0xa2, 0x0001, 0x0102)
    if tsi:
        opt += struct.pack('!I', 1700000000 if ts_int is None else ts_int)
    if tsf:
        opt += struct.pack('!Q', 123456789012 if ts_frac is None else ts_frac)
    data = opt + body
    n = 1 + len(data) // 4 if words is None else words
    return struct.pack('!BBH', b0, b1, n) + data

def field0(bit, val=None, var=None):
    """bytes of a CIF0 field."""
    n = SZ0[bit]
    if bit == 8:       # assoc lists: src, sys, vec, asy sizes; word 2 = vec (16) | a (1) | asy (15)
        src, sy, vec, asy, a = var or (1, 1, 1, 1, 1)
        w1 = (src << 16) | sy
        w2 = (vec << 16) | (a << 15) | asy
        total = src + sy + vec + asy + (asy if a else 0)
        return struct.pack('!II', w1, w2) + bytes(range(1, 1 + 4 * total))
    if bit == 9:       # GPS ASCII: OUI word, word count, data
        nw = 3 if var is None else var
        return struct.pack('!II', 0x0012a200, nw) + b'GPS$GPGGA,hello'.ljust(4 * nw, b'.')[:4 * nw]
    if val is not None:
        return val
    return bytes((bit * 7 + i * 3) & 0xff for i in range(n))

def field1(bit, val=None, var=None):
    n = SZ1[bit]
    if bit in VAR1:
        nw = 4 if var is None else var            # total words, including the count word
        return struct.pack('!I', nw) + bytes((bit + i) & 0xff for i in range(4 * (nw - 1)))
    if val is not None:
        return val
    return bytes((bit * 5 + i * 11) & 0xff for i in range(n))

def ctx_body(bits0=(), bits1=(), extra_cifs=(), vals0=None, vals1=None, var0=None, var1=None, cif0_extra=0, cif1_extra=0):
    vals0 = vals0 or {}
    vals1 = vals1 or {}
    var0 = var0 or {}
    var1 = var1 or {}
    cif0 = cif0_extra
    for b in bits0:
        cif0 |= 1 << b
    if bits1 or cif1_extra:
        cif0 |= 1 << 1
    for e in extra_cifs:
        cif0 |= 1 << e
    cif1 = cif1_extra
    for b in bits1:
        cif1 |= 1 << b
    body = struct.pack('!I', cif0)
    if cif0 & (1 << 1):
        body += struct.pack('!I', cif1)
    for e in extra_cifs:
        body += struct.pack('!I', 0x80000001 | (e << 8))
    for b in sorted(bits0, reverse=True):
        body += field0(b, vals0.get(b), var0.get(b))
    for b in sorted(bits1, reverse=True):
        body += field1(b, vals1.get(b), var1.get(b))
    return body

def i64(v): return struct.pack('!q', v)
def hz(f): return i64(int(round(f * 1048576)))

def build(outdir):
    pk = []
    add = lambda payload: pk.append(udp_pkt(payload))
    d = bytes(range(64))
    # data packets: all four types, class ID, timestamps of every kind, trailers
    add(vrt_pkt(0, d))
    add(vrt_pkt(1, d, seq=1))
    add(vrt_pkt(2, d, seq=2))
    add(vrt_pkt(3, d, seq=3, cid=1))
    add(vrt_pkt(1, d, seq=4, tsi=1, tsf=1))
    add(vrt_pkt(1, d, seq=5, tsi=2, tsf=2, cid=1))
    add(vrt_pkt(1, d, seq=6, tsi=3, tsf=3))
    add(vrt_pkt(0, d, seq=7, tsi=1))
    add(vrt_pkt(0, d, seq=8, tsf=2))
    add(vrt_pkt(0, d, seq=9, tsi=3, tsf=1, cid=1))
    # trailers with every enable and indicator combination
    for i, tr in enumerate((0x00000000, 0xFFF00000, 0xFFFFFFFF, 0x80000800, 0x00100000 | 0x0000000f, 0xA5A5A5A5,
                            0x7FF000FF, 0x0AAA0555, 0xFFF0FFF0)):
        add(vrt_pkt(1, d + struct.pack('!I', tr), t=1, seq=i, tsi=1))
    add(vrt_pkt(0, struct.pack('!I', 0xFF0FFF00), t=1))                   # trailer only (no samples)
    add(vrt_pkt(1, b'', seq=10))                                           # no payload
    add(vrt_pkt(0, b''))
    add(vrt_pkt(5, d))                                                     # extension context packet
    add(vrt_pkt(6, d))                                                     # reserved packet types
    add(vrt_pkt(15, d))
    # context packets: no fields, one field per bit, all fields
    add(vrt_pkt(4, ctx_body(), seq=1))
    add(vrt_pkt(4, ctx_body(), seq=2, cid=1, tsi=1, tsf=2, tsm=1))
    add(vrt_pkt(4, ctx_body(), seq=3, tsi=2, tsf=1))
    add(vrt_pkt(4, ctx_body(), seq=4, tsi=3, tsf=3, cid=1))
    for bit in range(31, 7, -1):
        add(vrt_pkt(4, ctx_body(bits0=[bit]), seq=bit & 15, tsi=1, tsf=2))
    # variable size fields of different sizes
    add(vrt_pkt(4, ctx_body(bits0=[8], var0={8: (0, 0, 0, 0, 0)})))
    add(vrt_pkt(4, ctx_body(bits0=[8], var0={8: (2, 3, 4, 5, 0)})))
    add(vrt_pkt(4, ctx_body(bits0=[8], var0={8: (1, 0, 0, 3, 1)})))
    add(vrt_pkt(4, ctx_body(bits0=[8], var0={8: (0x1ff & 3, 0x1ff & 2, 1, 2, 1)})))
    add(vrt_pkt(4, ctx_body(bits0=[9], var0={9: 0})))
    add(vrt_pkt(4, ctx_body(bits0=[9], var0={9: 10})))
    # CIF1 bits and the CIF2 to CIF7 words
    for bit in range(31, 0, -1):
        add(vrt_pkt(4, ctx_body(bits1=[bit]), seq=bit & 15))
    for bit in (7, 9, 11, 28):
        add(vrt_pkt(4, ctx_body(bits1=[bit], var1={bit: 1})))
        add(vrt_pkt(4, ctx_body(bits1=[bit], var1={bit: 9})))
    for e in range(2, 8):
        add(vrt_pkt(4, ctx_body(extra_cifs=[e])))
    add(vrt_pkt(4, ctx_body(extra_cifs=[2, 3, 4, 5, 6, 7])))
    # every CIF0 and CIF1 field together; all with trailing data words
    all0 = [b for b in range(31, 7, -1)]
    all1 = [b for b in range(31, 0, -1)]
    add(vrt_pkt(4, ctx_body(bits0=all0, bits1=all1, extra_cifs=[2, 3, 4, 5, 6, 7]) + b'\xde\xad\xbe\xef' * 3,
                cid=1, tsi=1, tsf=2, seq=15))
    add(vrt_pkt(4, ctx_body(bits0=all0, bits1=all1), cid=1, tsi=2, tsf=1, seq=14))
    # engineering prefixes: femtoseconds ... kiloseconds (timestamp adjustment, bit 20)
    for raw in (0, 1, 999, 1000, 2 * 10**3, 5 * 10**6, 7 * 10**9, 3 * 10**12, 10**15, 4 * 10**18, 9 * 10**18,
                -1, -(5 * 10**6), -(3 * 10**12), -(10**15), -(8 * 10**18), (1 << 63) - 1, -(1 << 63)):
        add(vrt_pkt(4, ctx_body(bits0=[20], vals0={20: i64(raw)})))
    # hertz: bandwidth, RF/IF frequency, sample rate, offsets (bits 29 28 27 21 26 25)
    for f in (0.0, 0.5, 1e-3, 1.0, 999.0, 1e3, 12345.678, 1e6, 2.4e9, 5.8e9, 1e12, 3e12, 8e12, -1e6,
              -2.4e9, -0.5, -1e12):
        raw = hz(f)
        add(vrt_pkt(4, ctx_body(bits0=[29, 28, 27, 26, 25, 21],
                                vals0={29: raw, 28: raw, 27: raw, 26: raw, 25: raw, 21: raw})))
    add(vrt_pkt(4, ctx_body(bits0=[29], vals0={29: i64((1 << 63) - 1)})))
    add(vrt_pkt(4, ctx_body(bits0=[29], vals0={29: i64(-(1 << 63))})))
    # 32 bit meters, unsigned meters and metres per second: GPS/INS/ephemeris position fields (bits 11-14)
    for sec in (0, 1, 2, 3):
        for bits in ([14], [13], [12], [11]):
            frac = b''
            pass
    def eph(tsi, tsf, oui=0x00012a):
        h = bytes([(tsi << 2) | tsf]) + struct.pack('!I', oui)[1:] + struct.pack('!I', 1700000000)
        h += struct.pack('!Q', 424242)
        vals = [0, 1, -1, 100 * 32, -100 * 32, 0x7fffffff, -0x80000000, 12345678, 65536, 1 << 20, -(1 << 20),
                3 << 16]
        return h + b''.join(struct.pack('!i', v) for v in vals[:9])
    def gpsfmt(tsi, tsf):
        h = bytes([(tsi << 2) | tsf]) + b'\x00\x12\xa2' + struct.pack('!I', 1700000000) + struct.pack('!Q', 99)
        vals = [0x1d000000, -0x1d000000, 5 * 32, -3 * 32, 0x7fffffff, -0x80000000, 0x1234567]
        return h + b''.join(struct.pack('!i', v) for v in vals) + struct.pack('!i', 0)
    for tsf in (0, 1, 2, 3):
        add(vrt_pkt(4, ctx_body(bits0=[14, 13, 12, 11],
                                vals0={14: gpsfmt(1, tsf)[:44].ljust(44, b'\0'), 13: gpsfmt(2, tsf)[:44].ljust(44, b'\0'),
                                       12: eph(1, tsf)[:52].ljust(52, b'\0'), 11: eph(3, tsf)[:52].ljust(52, b'\0')})))
    # temperature, gain, reference level, device ID, state/event, signal data format with extreme values
    add(vrt_pkt(4, ctx_body(bits0=[18, 23, 24], vals0={18: struct.pack('!HH', 0, 0xFFFF), 23: struct.pack('!hh', -128, 127),
                                                    24: struct.pack('!HH', 0, 0x8000)})))
    add(vrt_pkt(4, ctx_body(bits0=[16], vals0={16: b'\xff\xff\xff\xff'})))
    add(vrt_pkt(4, ctx_body(bits0=[16], vals0={16: b'\x00\x00\x00\x00'})))
    for item in (0x00, 0x01, 0x07, 0x0D, 0x0E, 0x0F, 0x10, 0x17, 0x1f):
        for typ in (0, 1, 2, 3):
            pass
        add(vrt_pkt(4, ctx_body(bits0=[15], vals0={15: bytes([0x80 | (1 << 5) | item, 0x7f, 0x1f, 0xff, 0x00, 0x10, 0xff, 0xff])})))
    add(vrt_pkt(4, ctx_body(bits0=[15], vals0={15: bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])})))
    add(vrt_pkt(4, ctx_body(bits0=[15], vals0={15: bytes([0x45, 0x55, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78])})))
    # CIF1 values: version/build code, polarization and phase offset
    add(vrt_pkt(4, ctx_body(bits1=[2, 30, 31], vals1={2: struct.pack('!HH', 0xFFFF, 0xFFFF),
                                                    30: struct.pack('!hh', -8192, 8192), 31: struct.pack('!HH', 0, 0xC000)})))
    # with a trailing data payload and trailer after a context
    add(vrt_pkt(4, ctx_body(bits0=[29]) + b'\0' * 8))
    # a zero bandwidth is shown with an empty prefix (reproducer of "VRT: Check variable field lengths ...")
    add(vrt_pkt(4, struct.pack('!I', (1 << 29) | (1 << 21) | (1 << 20)) + b'\0' * 24, sid=0x22222222))
    pcap_write(os.path.join(outdir, 'vrt-coverage.pcap'), pk)

    # the Ettus UHD data packet header (only with vrt.ettus_uhd_header_format); in the malformed capture
    # because with the default preference it is not a valid packet
    mal = []
    madd = lambda payload: mal.append(udp_pkt(payload))
    madd(b'\0\0\0\0' + vrt_pkt(1, d, seq=3, tsi=1, tsf=1))
    madd(b'\0\0\0\0' + vrt_pkt(4, ctx_body(bits0=[29])))
    # the reproducers of "VRT: Check variable field lengths and use real ett values"
    madd(vrt_pkt(4, struct.pack('!III', 0x11111111, 1 << 1, (1 << 7) | (1 << 3)) + struct.pack('!I', 0x20000000) + b'\xAA' * 24,
                 sid=None, words=None)[:0] + struct.pack('!BBH', 0x40, 0, 9) + struct.pack('!III', 0x11111111, 1 << 1, (1 << 7) | (1 << 3)) +
         struct.pack('!I', 0x20000000) + b'\xAA' * 24)
    madd(struct.pack('!BBH', 0x40, 0, 8) + struct.pack('!II', 0x44444444, (1 << 9)) + struct.pack('!II', 0, 0x40000000) +
         b'\0' * 16)
    madd(struct.pack('!BBH', 0x40, 0, 9) + struct.pack('!II', 0x44444444, (1 << 8)) + struct.pack('!II', 0x01FF01FF, 0xFFFFFFFF) +
         b'\0' * 16)
    madd(struct.pack('!BBH', 0x40, 0, 9) + struct.pack('!II', 0x44444444, (1 << 8)) + struct.pack('!II', 0x00000000, 0x7FFF7FFF) +
         b'\0' * 16)
    # array of records with a count larger than the packet, in each CIF1 bit that has one
    for bit in (7, 9, 11, 28):
        madd(vrt_pkt(4, struct.pack('!II', 1 << 1, 1 << bit) + struct.pack('!I', 0x1000) + b'\0' * 8))
    # context packets cut short at every field
    base = vrt_pkt(4, ctx_body(bits0=all0, bits1=all1, extra_cifs=[2, 3]), cid=1, tsi=1, tsf=2)
    for cut in (3, 7, 12, 20, 28, 33, 40, 44, 60, 100, 200, 300, 400, 500):
        mal.append(udp_pkt(base[:cut]))
    # headers cut short
    for cut in (0, 1, 2, 3):
        mal.append(udp_pkt(vrt_pkt(1, d)[:cut]))
    madd(vrt_pkt(1, d)[:6])
    # header length larger than the packet and smaller than the header fields
    madd(struct.pack('!BBH', 0x1c, 0xf0, 2) + b'\0' * 8)
    madd(struct.pack('!BBH', 0x14, 0x00, 0) + b'\0' * 8)
    madd(struct.pack('!BBH', 0x14, 0x00, 1) + b'\0' * 8)
    madd(struct.pack('!BBH', 0x14, 0x00, 500) + b'\0' * 8)
    madd(vrt_pkt(1, d + struct.pack('!I', 0xffffffff), t=1, words=3)[:60])
    pcap_write(os.path.join(outdir, 'vrt-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vrt-coverage.pcap'), os.path.join(outdir, 'vrt_coverage.pcap.gz'))

all0 = [b for b in range(31, 7, -1)]
all1 = [b for b in range(31, 0, -1)]

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

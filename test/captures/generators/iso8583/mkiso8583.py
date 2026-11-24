#!/usr/bin/env python3
# Generates test/captures/iso8583_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISO 8583 coverage captures. Usage: mkiso8583.py <outdir>
# Everything is synthetic: documentation addresses, a test card number and
# made-up field values.
import struct
import sys
import os


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))

# (type, max size, length of the length prefix) for bits 1..128, from the
# iso_1987 and iso_1993 tables of packet-iso8583.c
T1987 = [('B', 0, 0), ('N', 19, 2), ('N', 6, 0), ('N', 12, 0), ('N', 12, 0),
    ('N', 12, 0), ('N', 10, 0), ('N', 8, 0), ('N', 8, 0), ('N', 8, 0),
    ('N', 6, 0), ('N', 6, 0), ('N', 4, 0), ('N', 4, 0), ('N', 4, 0),
    ('N', 4, 0), ('N', 4, 0), ('N', 4, 0), ('N', 3, 0), ('N', 3, 0),
    ('N', 3, 0), ('N', 3, 0), ('N', 3, 0), ('N', 3, 0), ('N', 2, 0),
    ('N', 2, 0), ('N', 1, 0), ('XN', 9, 0), ('XN', 9, 0), ('XN', 9, 0),
    ('XN', 9, 0), ('N', 11, 2), ('N', 11, 2), ('NS', 28, 2), ('Z', 37, 2),
    ('AN', 104, 3), ('AN', 12, 0), ('AN', 6, 0), ('AN', 2, 0), ('ANS', 3, 0),
    ('ANS', 8, 0), ('ANS', 15, 0), ('ANS', 40, 0), ('ANS', 25, 2),
    ('ANS', 76, 2), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 3, 0), ('AN', 3, 0), ('AN', 3, 0), ('B', 8, 0), ('N', 8, 0),
    ('AN', 120, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('B', 8, 0), ('B', 0, 0), ('N', 1, 0),
    ('N', 2, 0), ('N', 3, 0), ('N', 3, 0), ('N', 3, 0), ('N', 4, 0),
    ('N', 4, 0), ('N', 6, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0),
    ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0),
    ('N', 12, 0), ('N', 12, 0), ('N', 12, 0), ('N', 12, 0), ('N', 15, 0),
    ('N', 15, 0), ('N', 15, 0), ('N', 15, 0), ('N', 42, 0), ('ANS', 1, 0),
    ('N', 2, 0), ('N', 5, 0), ('ANS', 7, 0), ('ANS', 42, 0), ('B', 8, 0),
    ('XN', 17, 0), ('ANS', 25, 0), ('N', 11, 2), ('N', 11, 2),
    ('ANS', 17, 2), ('ANS', 28, 2), ('ANS', 28, 2), ('ANS', 100, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('B', 8, 0)]
T1993 = [('B', 0, 0), ('N', 19, 2), ('N', 6, 0), ('N', 12, 0), ('N', 12, 0),
    ('N', 12, 0), ('N', 10, 0), ('N', 8, 0), ('N', 8, 0), ('N', 8, 0),
    ('N', 6, 0), ('N', 12, 0), ('N', 4, 0), ('N', 4, 0), ('N', 4, 0),
    ('N', 4, 0), ('N', 4, 0), ('N', 4, 0), ('N', 3, 0), ('N', 3, 0),
    ('N', 3, 0), ('AN', 12, 0), ('N', 3, 0), ('N', 3, 0), ('N', 4, 0),
    ('N', 4, 0), ('N', 1, 0), ('N', 6, 0), ('N', 3, 0), ('N', 24, 0),
    ('ANS', 99, 2), ('N', 11, 2), ('N', 11, 2), ('NS', 28, 2), ('Z', 37, 2),
    ('Z', 104, 3), ('AN', 12, 0), ('AN', 6, 0), ('N', 3, 0), ('N', 3, 0),
    ('ANS', 8, 0), ('ANS', 15, 0), ('ANS', 99, 2), ('ANS', 99, 2),
    ('ANS', 76, 2), ('ANS', 204, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('AN', 3, 0), ('AN', 3, 0), ('AN', 3, 0), ('B', 8, 0), ('B', 48, 0),
    ('ANS', 120, 3), ('B', 255, 3), ('N', 35, 2), ('N', 3, 0), ('N', 11, 2),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('B', 8, 0), ('B', 0, 0), ('ANS', 204, 3), ('N', 2, 0),
    ('N', 3, 0), ('N', 3, 0), ('N', 3, 0), ('N', 6, 0), ('ANS', 999, 3),
    ('N', 6, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0),
    ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 10, 0),
    ('N', 10, 0), ('N', 10, 0), ('N', 10, 0), ('N', 16, 0), ('N', 16, 0),
    ('N', 16, 0), ('N', 16, 0), ('N', 10, 0), ('N', 3, 0), ('N', 3, 0),
    ('N', 11, 2), ('N', 11, 2), ('ANS', 99, 2), ('B', 999, 3), ('XN', 17, 0),
    ('ANS', 25, 0), ('AN', 11, 2), ('N', 11, 2), ('ANS', 17, 2),
    ('ANS', 28, 2), ('ANS', 28, 2), ('ANS', 100, 3), ('N', 16, 0),
    ('N', 16, 0), ('N', 10, 0), ('N', 10, 0), ('ANS', 84, 2), ('ANS', 84, 2),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3), ('ANS', 999, 3),
    ('ANS', 999, 3), ('B', 8, 0)]


class Cfg:
    """Preferences the capture is built for (the dissector defaults are
    ASCII digits, hex ASCII binary data and a little endian length)."""
    def __init__(self, charset='ascii', binenc='ascii', endian='little'):
        self.charset, self.binenc, self.endian = charset, binenc, endian


DEFAULT = Cfg()


def sample(bit, row, short=False, hexz=False):
    """A valid value for the field: str, or bytes for type B."""
    t, mx, var = row
    n = mx
    if var:
        n = min(mx, 12 if short else mx if mx <= 40 else 40)
    if t == 'N':
        return ('%d' % (bit * 7919 + 1)).zfill(n)[-n:] if n else ''
    if t == 'XN':
        return ('C%d' % (bit * 31)).ljust(n, '0')[:n]
    if t == 'NS':
        return ('12-34 56/78' * 5)[:n]
    if t == 'Z':
        if hexz:
            return ('4000000000000002D25121010000' * 5)[:n]
        return ('4000000000000002=25121010000' * 3)[:n]
    if t == 'AN':
        return ('Ab12Cd34Ef56' * 12)[:n]
    if t == 'ANS':
        return ('Test data, 1-2 ' + 'x' * 100)[:n]
    if t == 'B':
        return bytes((bit * 3 + i) & 0xff for i in range(n))
    raise ValueError(t)


def bcd(digits, nbytes=None):
    d = digits
    if len(d) % 2:
        d = '0' + d
    return bytes.fromhex(d)


def encode_field(row, val, cfg):
    t, mx, var = row
    if t == 'B':
        n = len(val)
        data = val.hex().upper().encode() if cfg.binenc == 'ascii' else val
    elif t == 'Z':
        n = len(val)
        data = val.encode() if cfg.binenc == 'ascii' else val.encode()
    elif t in ('N', 'XN') and cfg.charset == 'bcd':
        n = len(val)
        data = bcd(val)
    else:
        n = len(val)
        data = val.encode()
    if not var:
        return data
    if cfg.charset == 'bcd':
        return bcd(('%d' % n).zfill(var + (var % 2))) + data
    return ('%d' % n).zfill(var).encode() + data


def bitmaps(bits, cfg, nbitmaps=None):
    bm = [0, 0]
    for b in bits:
        bm[(b - 1) // 64] |= 1 << (63 - (b - 1) % 64)
    if any(b > 64 for b in bits):
        bm[0] |= 1 << 63
    two = bm[0] >> 63
    out = b''
    for i in range(2 if two else 1):
        if cfg.binenc == 'ascii':
            out += ('%016X' % bm[i]).encode()
        else:
            out += struct.pack('>Q', bm[i])
    return out


def msg(mti, bits, cfg=DEFAULT, values=None, table=None, bitmap=None):
    """One ISO 8583 message with its 2 octet length."""
    ver = mti[0]
    table = table or (T1987 if ver == '0' else T1993)
    values = values or {}
    body = (mti.encode() if cfg.charset == 'ascii' else bcd(mti))
    body += bitmap if bitmap is not None else bitmaps(bits, cfg)
    for b in sorted(bits):
        if b in (1, 65):
            continue
        v = values.get(b)
        if v is None:
            v = sample(b, table[b - 1], hexz=cfg.charset == 'bcd')
        body += encode_field(table[b - 1], v, cfg)
    return struct.pack('<H' if cfg.endian == 'little' else '>H', len(body)) + body


class Stream:
    def __init__(self, cport, sport=8583):
        self.cport, self.sport = cport, sport
        self.seq = {True: 1000, False: 5000}

    def seg(self, data, to_server=True, pad=0):
        s = self.seq[to_server]
        self.seq[to_server] += len(data)
        a = self.seq[not to_server]
        sp, dp = (self.cport, self.sport) if to_server else (self.sport, self.cport)
        src, dst = ('192.0.2.1', '192.0.2.2') if to_server else ('192.0.2.2', '192.0.2.1')
        e = eth(0x0800, ipv4(6, tcp(sp, dp, data, s, a), src, dst),
                dst=b'\x02\0\0\0\0\x02' if to_server else b'\x02\0\0\0\0\x01',
                src=b'\x02\0\0\0\0\x01' if to_server else b'\x02\0\0\0\0\x02')
        return e


def all_bits(lo, hi, skip=()):
    return [b for b in range(lo, hi + 1) if b not in skip and b not in (1, 65)]


def main(outdir):
    frames = []
    st = Stream(40000)
    # 1: 0200 financial request, the usual card fields; bit 2 is the
    #    reproducer of the LLVAR length prefix fix (length "16")
    frames.append(st.seg(msg('0200', [2, 3, 4, 7, 11, 12, 13, 14, 18, 22, 25, 32,
                                       35, 37, 41, 42, 43, 49, 52],
                              values={2: '4000000000000002', 32: '123456',
                                      52: bytes(range(8))})))
    # 2: 0210 response
    frames.append(st.seg(msg('0210', [3, 4, 7, 11, 37, 38, 39, 41, 49]), False))
    # 3: the fixed length fields 5-31 and 50-53
    frames.append(st.seg(msg('0220', all_bits(5, 31) + [50, 51, 53])))
    # 4: the variable length fields of the first bitmap
    frames.append(st.seg(msg('0420', [2, 33, 34, 36, 44, 45, 46, 47, 48, 54, 55,
                                       56, 57, 58, 59, 60, 61, 62, 63, 64])))
    # 5: field 38-43, 52 and 64 (MAC)
    frames.append(st.seg(msg('0100', [38, 39, 40, 41, 42, 43, 52, 64])))
    # 6: network management with the second bitmap, bit 70
    frames.append(st.seg(msg('0800', [11, 70, 71, 100], values={70: '301'})))
    # 7: second bitmap, the fixed fields 66-99
    frames.append(st.seg(msg('0220', [2, 4] + all_bits(66, 99)), False))
    # 8: second bitmap, 100-128
    frames.append(st.seg(msg('0600', all_bits(100, 128))))
    # 9: version 1993, first bitmap
    frames.append(st.seg(msg('1100', [2] + all_bits(3, 64, skip=(52,)) + [52]), False))
    # 10: version 1993, second bitmap
    frames.append(st.seg(msg('1220', all_bits(66, 128))))
    # 11: Length prefix of 3 bits for B (56 and 97 in 1993)
    frames.append(st.seg(msg('1304', [56, 97, 128, 52, 64]), False))
    # 12: two messages in one segment
    frames.append(st.seg(msg('0500', [3, 11]) + msg('0510', [3, 11, 39])))
    # 13, 14: one message split in two segments (TCP reassembly)
    m = msg('0200', [2, 3, 4, 11, 41, 42])
    frames.append(st.seg(m[:9]))
    frames.append(st.seg(m[9:]))
    # 15: reserved/other types of the MTI: administrative, fee, unknown
    for mti in ('0620', '0720', '0920', '0020'):
        frames.append(st.seg(msg(mti, [3, 11]), False))
    # 19: minimal message: bitmap with only bit 1 clear and a single field
    frames.append(st.seg(msg('0800', [11])))
    write_pcap(os.path.join(outdir, 'iso8583-coverage.pcap'), 1, frames)
    write_prefs(outdir)
    write_malformed(outdir)


def write_prefs(outdir):
    """Messages for the preferences: BCD digits, binary data and a big
    endian length. Each capture needs its own -o options (see runcov.sh)."""
    bitsets = [[2, 3, 4, 7, 11, 12, 13, 14, 35, 37, 41, 42, 52],
               [2, 33, 34, 36, 44, 45, 46, 54, 55, 56],
               [11, 28, 29, 30, 31, 70, 98, 100, 102],
               [3, 4, 11, 12, 25, 70, 90, 91]]
    for name, cfg in (('bcd', Cfg('bcd', 'ascii', 'little')),
                      ('big', Cfg('ascii', 'ascii', 'big')),
                      ('bin', Cfg('ascii', 'bin', 'little')),
                      ('all', Cfg('bcd', 'bin', 'big'))):
        st = Stream(40001)
        fr = []
        for i, bits in enumerate(bitsets):
            fr.append(st.seg(msg('0200', bits, cfg), bool(i % 2 == 0)))
        fr.append(st.seg(msg('1200', [2, 3, 4, 11, 31, 35, 36, 43, 56, 57, 97, 128], cfg)))
        # BCD: an odd number of digits in a variable length field
        fr.append(st.seg(msg('0200', [2, 3, 11, 32], cfg,
                             values={2: '40000000000000021', 32: '12345'})))
        if name == 'bin':
            # 16 octets after the MTI that are neither hex digit characters
            # nor contain NUL: the heuristic rejects the message (shown as
            # TCP payload)
            body = b'0200' + b'ZZZZZZZZZZZZZZZZ' + b'12345678'
            fr.append(Stream(40050).seg(struct.pack('<H', len(body)) + body))
        write_pcap(os.path.join(outdir, 'iso8583-coverage-%s.pcap' % name), 1, fr)


def write_malformed(outdir):
    frames = []
    cp = [40010]

    def mk(body, length=None):
        cp[0] += 1
        n = len(body) if length is None else length
        return Stream(cp[0]).seg(struct.pack('<H', n) + body)

    # 1: not ISO 8583: MTI that is not numeric, and a version 2 MTI
    body = b'02X0' + b'4000000000000000' + b'123456'
    frames.append(mk(body))
    body = b'2200' + b'4000000000000000' + b'123456'
    frames.append(mk(body))
    # 3: bitmap 1 not hex
    body = b'0200' + b'40000000000000ZZ' + b'123456'
    frames.append(mk(body))
    # 4: bit 1 set, second bitmap not hex
    body = b'0200' + b'C000000000000000' + b'4000000000000ZZZ' + b'123456'
    frames.append(mk(body))
    # 5: three bitmaps
    body = b'0200' + b'C000000000000000' + b'8000000000000000' + b'123456'
    frames.append(mk(body))
    # 6: length field shorter than the bitmap
    body = b'0200' + b'4000000000000000'
    frames.append(mk(body + b'xxxxxxxx', 20))
    # 7: bit 3 not numeric
    body = b'0200' + b'2000000000000000' + b'12A456'
    frames.append(mk(body))
    # 8: bit 2 with a length prefix that is not numeric
    body = b'0200' + b'4000000000000000' + b'1X' + b'4000000000000002'
    frames.append(mk(body))
    # 9: bit 2 longer than the maximum of 19
    body = b'0200' + b'4000000000000000' + b'25' + b'4' * 25
    frames.append(mk(body))
    # 10: bit 2 runs past the end of the message
    body = b'0200' + b'4000000000000000' + b'16' + b'4000'
    frames.append(mk(body))
    # 11: bit 4 (12 digits) runs past the end
    body = b'0200' + b'1000000000000000' + b'12345'
    frames.append(mk(body))
    # 12: LLLVAR (bit 36) length prefix cut
    body = b'0200' + b'0000000800000000' + b'1'
    frames.append(mk(body))
    # 13: bit 52 is not hex
    body = b'0200' + b'0000000000080000' + b'ZZZZZZZZZZZZZZZZ'
    frames.append(mk(body))
    # 14: bit 28 (hex digits) not hex
    body = b'0200' + b'0000001000000000' + b'XYZXYZXYZ'
    frames.append(mk(body))
    # 15: bit 35 (Z) with a character that is not printable
    body = b'0200' + b'0000000020000000' + b'05' + b'ab\x01de'
    frames.append(mk(body))
    # 17: second bitmap announced, but the message ends inside it
    body = b'0200' + b'C000000000000000' + b'40000'
    frames.append(mk(body))
    # 16: bit 128 in the second bitmap cut short
    body = b'0200' + b'8000000000000000' + b'0000000000000001' + b'abc'
    frames.append(mk(body))
    # 17: too short for ISO 8583
    frames.append(mk(b'0200' + b'4000', 10))
    # 18: length field says more than the segment (waits for data), then the
    # connection ends with a truncated PDU
    write_pcap(os.path.join(outdir, 'iso8583-coverage-malformed.pcap'), 1, frames)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

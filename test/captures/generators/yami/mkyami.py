#!/usr/bin/env python3
# Generates test/captures/yami_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the YAMI coverage captures with struct only (nothing is captured).
# Usage: mkyami.py <outdir>
#   yami-coverage.pcap            Exported PDU (linktype 252) naming "yami"
#   yami-coverage-malformed.pcap  Exported PDU, truncated / bad data
#   yami-coverage-tcp.pcap        Ethernet/IP/TCP and UDP port 4444, for
#                                 Decode As in runcov.sh (reassembly)
import struct
import sys
import os

def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def exp_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(proto, payload, src=bytes([192, 0, 2, 1]), dst=bytes([192, 0, 2, 2])):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + payload

def tcp(sport, dport, seq, payload, flags=0x18):
    return ip4(6, struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, flags, 65535, 0, 0) + payload)

def udp(sport, dport, payload):
    return ip4(17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload)

# --- YAMI encoding ---
def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)

def s(x):
    x = x.encode() if isinstance(x, str) else x
    return struct.pack('<I', len(x)) + pad4(x)

def param(name, typ, body):
    return s(name) + struct.pack('<I', typ) + body

def p_bool(n, v): return param(n, 1, struct.pack('<I', v))
def p_int(n, v): return param(n, 2, struct.pack('<i', v))
def p_long(n, v): return param(n, 3, struct.pack('<q', v))
def p_double(n, v): return param(n, 4, struct.pack('<d', v))
def p_str(n, v): return param(n, 5, s(v))
def p_bin(n, v): return param(n, 6, s(v))

def p_boolarr(n, bits):
    body = struct.pack('<I', len(bits))
    for i in range(0, len(bits), 32):
        w = 0
        for j, b in enumerate(bits[i:i + 32]):
            w |= (1 if b else 0) << j
        body += struct.pack('<I', w)
    return param(n, 7, body)

def p_intarr(n, v): return param(n, 8, struct.pack('<I', len(v)) + b''.join(struct.pack('<i', x) for x in v))
def p_longarr(n, v): return param(n, 9, struct.pack('<I', len(v)) + b''.join(struct.pack('<q', x) for x in v))
def p_dblarr(n, v): return param(n, 10, struct.pack('<I', len(v)) + b''.join(struct.pack('<d', x) for x in v))
def p_strarr(n, v): return param(n, 11, struct.pack('<I', len(v)) + b''.join(s(x) for x in v))
def p_binarr(n, v): return param(n, 12, struct.pack('<I', len(v)) + b''.join(s(x) for x in v))
def p_nested(n, params, count=None):
    return param(n, 13, struct.pack('<I', len(params) if count is None else count) + b''.join(params))

def msg(params, count=None):
    return struct.pack('<I', len(params) if count is None else count) + b''.join(params)

def frame(hdr, data, msgid=1, num=1, hdr_size=None, payload_size=None):
    payload = hdr + data
    hs = len(hdr) if hdr_size is None else hdr_size
    ps = len(payload) if payload_size is None else payload_size
    return struct.pack('<iiii', msgid, num, hs, ps) + payload

def chain(levels, leaf=None):
    p = leaf if leaf is not None else p_int('', 7)
    for i in range(levels):
        p = p_nested('n%d' % i if i < 3 else '', [p])
    return p

def main(out):
    std_hdr = msg([p_str('object', 'obj'), p_str('message', 'ping'), p_int('seq', 1)])
    F = []   # main frames (YAMI payloads)
    # 1: scalar parameters
    F.append(frame(std_hdr, msg([
        p_bool('flag_true', 1), p_bool('flag_false', 0), p_int('i', -5),
        p_long('l', -(1 << 40)), p_double('d', 2.5), p_str('s', 'hello'),
        p_str('empty', ''), p_str('s4', 'abcd'), p_bin('b', b'\x01\x02\x03\x04\x05'),
        p_bin('b0', b'')]), msgid=100))
    # 2: arrays (boolean array of 40, 5 and exactly 32 items)
    F.append(frame(std_hdr, msg([
        p_boolarr('ba40', [i % 3 == 0 for i in range(40)]), p_boolarr('ba5', [1, 0, 1, 1, 0]),
        p_boolarr('ba32', [1] * 32), p_boolarr('ba0', []),
        p_intarr('ia', [1, -2, 3]), p_longarr('la', [1 << 33, -1]),
        p_dblarr('da', [1.5, -0.25]), p_strarr('sa', ['a', 'bcde', '']),
        p_binarr('bina', [b'\xde\xad', b'', b'\xbe\xef\x00'])]), msgid=101))
    # 3: normal nesting, 2-3 levels, with a following sibling
    F.append(frame(std_hdr, msg([
        p_nested('outer', [p_int('a', 1), p_nested('mid', [p_str('b', 'two'),
                 p_nested('inner', [p_int('c', 3)])]), p_bool('d', 1)]),
        p_nested('empty', []), p_int('after', 9)]), msgid=102))
    # 4: last frame (-1), empty header and data
    F.append(frame(msg([]), msg([]), msgid=103, num=-1))
    # 5: continuation frame (not parsed)
    F.append(frame(b'', b'continuation data', msgid=104, num=2, hdr_size=8))
    # 6: header size larger than the payload (skipped)
    F.append(frame(std_hdr, msg([p_int('x', 1)]), msgid=105, hdr_size=4000))
    # 7: header size larger than the header (offset corrected, padding skipped)
    hdr = msg([p_str('k', 'v')])
    F.append(frame(hdr + b'\0' * 8, msg([p_int('x', 2)]), msgid=106, hdr_size=len(hdr) + 8))
    # 8: header size smaller than the header: the data message is parsed from the wrong place
    hdr = msg([p_str('k', 'v'), p_int('z', 5)])
    F.append(frame(hdr, msg([p_int('x', 3)]), msgid=107, hdr_size=len(hdr) - 4))
    # 9: unknown parameter type in the header, data message still shown
    hdr = msg([param('weird', 99, b'\0' * 4)])
    F.append(frame(hdr, msg([p_int('x', 4)]), msgid=108))
    # 10: 32 nesting levels (the limit; decodes cleanly)
    F.append(frame(std_hdr, msg([chain(32)]), msgid=109))
    # 11: 33 nesting levels (expert info "nested too deeply")
    F.append(frame(std_hdr, msg([chain(33)]), msgid=110))
    # 12: negative header size (-8), fixed to an expert info (was a backwards parse)
    hdr2 = struct.pack('<I', 1) + struct.pack('<III', 4, 5, 3) + b'abc\0' + struct.pack('<I', 4) + b'xyz\0'
    F.append(frame(hdr2, struct.pack('<I', 0), msgid=111, hdr_size=-8))
    # 14: huge frame payload size: frame size shown without integer overflow
    F.append(frame(std_hdr, msg([p_int('x', 6)]), msgid=113, payload_size=0x7fffffff))
    # 15: header size 4 and an empty header message
    F.append(frame(msg([]), msg([p_str('only', 'data')]), msgid=114, hdr_size=4))
    # 16: negative payload size (frame size shown) with a header size of 4
    F.append(frame(msg([]), msg([]), msgid=115, hdr_size=4, payload_size=-100))
    pcap(os.path.join(out, 'yami-coverage.pcap'), 252, [exp_pdu('yami', f) for f in F])

    # malformed
    M = []
    full = frame(std_hdr, msg([p_str('s', 'text'), p_bin('b', b'1234567'), p_int('i', 1)]))
    # cut in the header message, a parameter name and a value (payload size adjusted)
    for n in (20, 28, 40, 60, 70):
        M.append(struct.pack("<iiii", 1, 1, 4 if n == 20 else 8, n - 16) + full[16:n])
    # header size 3 (below 4)
    M.append(frame(std_hdr, msg([p_int('x', 5)]), hdr_size=3))
    # 5: parameter count far beyond the data
    M.append(frame(msg([p_int('a', 1)], count=1000), msg([])))
    # 6: string longer than the frame
    M.append(frame(msg([param('s', 5, struct.pack('<I', 5000) + b'abc')]), msg([])))
    # 7: binary longer than the frame
    M.append(frame(msg([param('b', 6, struct.pack('<I', 5000) + b'abc')]), msg([])))
    # 8: array counts beyond the data
    for t in (7, 8, 9, 10, 11, 12):
        M.append(frame(msg([param('a', t, struct.pack('<I', 100000) + b'\0' * 8)]), msg([])))
    # 14: name length beyond the frame
    M.append(frame(struct.pack('<II', 1, 0x7fffffff) + b'abcd', msg([])))
    # 15: nested count beyond the data, with a nested parameter failing inside
    M.append(frame(msg([p_nested('n', [p_int('a', 1)], count=5)]), msg([])))
    # 16: 36 and 600 levels (the original reproducer): expert info, no assertion
    M.append(frame(std_hdr, msg([chain(36)])))
    M.append(frame(struct.pack('<I', 1) + chain(600), msg([])))
    # 18: unknown type inside a nested parameter
    M.append(frame(msg([p_nested('n', [param('w', 77, b'\0' * 4)])]), msg([])))
    # 19: data message cut inside a parameter
    M.append(frame(std_hdr, msg([p_str('s', 'text')])[:10]))
    # 20: header message ok, nothing after (data message count missing)
    M.append(frame(std_hdr, b''))
    # 21: frame header only
    M.append(frame(b'', b'', hdr_size=0))
    # A binary (or binary array item) at the very end of the frame: the item
    # is added with the length field and padding (length + 4 octets from the
    # data pointer), which reads up to 4 octets beyond the end of the tvb
    M.append(frame(std_hdr, msg([p_bin('b', b'\x01')])))
    M.append(frame(std_hdr, msg([p_binarr('ba', [b'\x01\x02\x03'])])))
    pcap(os.path.join(out, 'yami-coverage-malformed.pcap'), 252, [exp_pdu('yami', f) for f in M])

    # Ethernet/TCP and UDP (Decode As tcp.port 4444 / udp.port 4444 in runcov.sh)
    T = []
    a = frame(std_hdr, msg([p_str('s', 'tcp one'), p_int('i', 1)]), msgid=200)
    b = frame(std_hdr, msg([p_str('s', 'tcp two'), p_int('i', 2)]), msgid=201)
    c = frame(std_hdr, msg([p_nested('n', [p_int('i', 3)]), p_boolarr('b', [1] * 40)]), msgid=202)
    seq = 1000
    # 1: one complete PDU
    T.append(tcp(40000, 4444, seq, a)); seq += len(a)
    # 2: two PDUs in one segment
    T.append(tcp(40000, 4444, seq, b + a)); seq += len(b) + len(a)
    # 3,4: one PDU split in two segments (reassembly)
    T.append(tcp(40000, 4444, seq, c[:25])); seq += 25
    T.append(tcp(40000, 4444, seq, c[25:])); seq += len(c) - 25
    # 5,6,7: split inside the 16 octet frame header (3 segments)
    T.append(tcp(40000, 4444, seq, b[:5])); seq += 5
    T.append(tcp(40000, 4444, seq, b[5:12])); seq += 7
    T.append(tcp(40000, 4444, seq, b[12:])); seq += len(b) - 12
    # 8: 600 levels nested in a TCP stream
    big = frame(struct.pack('<I', 1) + chain(600), msg([]), msgid=203)
    T.append(tcp(40001, 4444, 5000, big[:1400]));
    T.append(tcp(40001, 4444, 5000 + 1400, big[1400:]))
    # UDP
    T.append(udp(40002, 4444, a))
    T.append(udp(4444, 40002, c))
    pcap(os.path.join(out, 'yami-coverage-tcp.pcap'), 1, T)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

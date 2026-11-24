#!/usr/bin/env python3
# Generates test/captures/sigcomp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
# Generates the SigComp coverage captures (synthetic, built with struct,
# hashlib and the small UDVM assembler in udvm.py):
#   sigcomp-coverage.pcap            main capture, decodes clean (warnings only)
#   sigcomp-coverage-malformed.pcap  decompression failures and framing errors
# Usage: mksigcomp.py <outdir> [path of packet-sigcomp.c]
# The static dictionary of RFC 3485 is read from packet-sigcomp.c to build
# messages that copy text out of it.
import re
import socket
import struct
import sys

from udvm import (Asm, Ref, Lit, Mt, Mem, At, Raw, state_id, crc16_x25, OPS, enc_mt, enc_mem)  # noqa: E402

OPS_END = 35

STACK, BUF, OUT, TMP = 0x0800, 0x4000, 0x6000, 0x0300
DICT_AT = 0x5000

SIP_SDP_ID = bytes.fromhex('fbe507dfe5e6')            # first 6 bytes of the state identifier
PRESENCE_ID = bytes.fromhex('d942297d0bb3')


def sipmsg(callid, extra=b''):
    return (b'OPTIONS sip:bob@example.com SIP/2.0\r\n'
            b'Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n'
            b'Max-Forwards: 70\r\n'
            b'To: <sip:bob@example.com>\r\n'
            b'From: <sip:alice@example.com>;tag=1928301774\r\n'
            b'Call-ID: ' + callid + b'@pc33.example.com\r\n'
            b'CSeq: 63104 OPTIONS\r\n' + extra +
            b'Content-Length: 0\r\n\r\n')


# --------------------------------------------------------------------------
# packet writers
# --------------------------------------------------------------------------
def _csum16(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(proto, payload, src, dst):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', _csum16(h)) + h[12:]
    return h + payload


def ip6(proto, payload, src, dst):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), proto, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def eth(payload, v6=False):
    return (b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' +
            struct.pack('!H', 0x86dd if v6 else 0x0800) + payload)


C4, S4 = '192.0.2.10', '192.0.2.20'
C6, S6 = '2001:db8::10', '2001:db8::20'


def udp(payload, sport=49152, dport=5555, v6=False):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    if v6:
        pseudo = (socket.inet_pton(socket.AF_INET6, C6) + socket.inet_pton(socket.AF_INET6, S6) +
                  struct.pack('!IBBBB', len(u), 0, 0, 0, 17))
        c = _csum16(pseudo + u) or 0xffff
        u = u[:6] + struct.pack('!H', c) + u[8:]
        return eth(ip6(17, u, C6, S6), True)
    return eth(ip4(17, u, C4, S4))


class Tcp:
    def __init__(self, sport=49200, dport=5555):
        self.sport, self.dport, self.seq = sport, dport, 1000

    def seg(self, payload):
        h = struct.pack('!HHIIBBHHH', self.sport, self.dport, self.seq, 1, 5 << 4, 0x18, 65535, 0, 0)
        self.seq += len(payload)
        return eth(ip4(6, h + payload, C4, S4))


def tcp_wrap(msg, quote=False):
    """SigComp over a stream: 0xFF is escaped as 0xFF 0x00, 0xFFFF ends the message"""
    out = b''
    for b in msg:
        out += b'\xff\x00' if b == 0xff else bytes([b])
    return out + b'\xff\xff'


def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# --------------------------------------------------------------------------
# SigComp message formats
# --------------------------------------------------------------------------
def feedback(fb):
    if fb is None:
        return b''
    if len(fb) == 1 and fb[0] < 0x80:
        return fb
    return bytes([0x80 | len(fb)]) + fb


def fmt2(code, msg=b'', dest=1, fb=None, T=None):
    t = 1 if (fb is not None) else 0
    if T is not None:
        t = T
    L = len(code)
    return (bytes([0xf8 | (t << 2)]) + feedback(fb) +
            bytes([(L >> 4) & 0xff, ((L & 0xf) << 4) | dest]) + code + msg)


def fmt1(pid, msg=b'', fb=None):
    code = {6: 1, 9: 2, 12: 3}[len(pid)]
    t = 1 if fb is not None else 0
    return bytes([0xf8 | (t << 2) | code]) + feedback(fb) + pid + msg


def nack(reason, opcode, pc, sha1, details=b'', fb=None):
    t = 1 if fb is not None else 0
    return (bytes([0xf8 | (t << 2)]) + feedback(fb) + bytes([0x00, 0x01, reason, opcode]) +
            struct.pack('!H', pc) + sha1 + details)


# --------------------------------------------------------------------------
# UDVM programs
# --------------------------------------------------------------------------
def prologue(a, order=0, bcl=0, bcr=0):
    a.ins('MULTILOAD', 64, Lit(4), bcl, bcr, order, STACK)


def endmsg(a, slen=0, saddr=0, sinstr=0, minacc=6, prio=0, fbloc=0, retloc=0):
    a.ins('END-MESSAGE', fbloc, retloc, Mt(slen, 'gen'), Mt(saddr, 'gen'), Mt(sinstr, 'gen'), minacc, prio)


def prog_copy(msg, state=False):
    """INPUT-BYTES the message into memory and OUTPUT it; with state=True the
    END-MESSAGE creates a state item that holds the program itself, so that a
    later message of the same length can name it (message format 1)."""
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-BYTES', Mt(len(msg), 'gen'), BUF, At('fail'))
    a.ins('OUTPUT', BUF, Mt(len(msg), 'gen'))
    if state:
        # placeholder of the same size; patched below once the length is known
        a.ins('END-MESSAGE', 0, 0, Mt(0, 'gen'), Mt(128, 'gen'), Mt(128, 'gen'), 6, 1)
    else:
        endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    code = a.assemble()
    if state:
        a2 = Asm(128)
        prologue(a2)
        a2.ins('INPUT-BYTES', Mt(len(msg), 'gen'), BUF, At('fail'))
        a2.ins('OUTPUT', BUF, Mt(len(msg), 'gen'))
        a2.ins('END-MESSAGE', 0, 0, Mt(len(code), 'gen'), Mt(128, 'gen'), Mt(128, 'gen'), 6, 1)
        a2.label('fail')
        a2.ins('DECOMPRESSION-FAILURE')
        code = a2.assemble()
    return code, msg


def prog_alu(msg):
    n = len(msg)
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-BYTES', n, BUF, At('fail'))
    # every operand form: literals, memory operands, power-of-two forms
    a.ins('LOAD', 0x310, Mt(5, 'lit6'))
    a.ins('LOAD', 0x312, Mt(128, 'pow6'))
    a.ins('LOAD', 0x314, Mt(64, 'pow6'))
    a.ins('LOAD', 0x316, Mt(256, 'pow8'))
    a.ins('LOAD', 0x318, Mt(32768, 'pow8'))
    a.ins('LOAD', 0x31a, Mt(65535, 'hi5'))
    a.ins('LOAD', 0x31c, Mt(61440 + 0x123, 'hi12'))
    a.ins('LOAD', 0x31e, Mt(4000, 'l13'))
    a.ins('LOAD', 0x320, Mt(12345, 'gen'))
    a.ins('LOAD', 0x322, Mem(0x31e, 'm13'))
    a.ins('LOAD', 0x324, Mem(100, 'm6'))
    a.ins('LOAD', 0x326, Mem(0x31c, 'mgen'))
    a.ins('LOAD', Mem(0x31e, 'm13'), 7)
    a.ins('LOAD', 0x328, 0xffff)
    # start address: 0x1000 << 2 == BUF
    a.ins('MULTILOAD', 0x330, Lit(2, 'l14'), 0x1234, 0x5678)     # literal operand forms
    a.ins('MULTILOAD', 0x338, Lit(2, 'l16'), 0x1234, 0x5678)
    a.ins('SWITCH', Lit(2, 'l16'), 1, At('sw0'), At('sw1'))
    a.label('sw0')
    a.ins('JUMP', At('sw1'))
    a.label('sw1')
    a.ins('LOAD', 0x300, 0x1000)
    a.ins('LSHIFT', Ref(0x300, 'r14'), 2)
    # length: ((n*16+5) >> 4) + 5000 - 5000, * 7 / 7, | 0, & 0xffff, ~~
    a.ins('LOAD', 0x302, Mt(n * 16 + 5))
    a.ins('RSHIFT', Ref(0x302, 'r16'), Mt(4))
    a.ins('ADD', Ref(0x302), Mt(5000))
    a.ins('SUBTRACT', Ref(0x302), Mt(5000))
    a.ins('MULTIPLY', Ref(0x302), 7)
    a.ins('DIVIDE', Ref(0x302), 7)
    a.ins('OR', Ref(0x302), Mem(100, 'm6'))
    a.ins('AND', Ref(0x302), Mem(0x328, 'mgen'))
    a.ins('NOT', Ref(0x302))
    a.ins('NOT', Ref(0x302))
    a.ins('LOAD', 0x304, Mt(n + 1024))
    a.ins('REMAINDER', Ref(0x304), 1024)
    a.ins('SUBTRACT', Ref(0x302), Mem(0x304))                 # 0
    a.ins('ADD', Ref(0x302), Mem(0x304))                      # n
    a.ins('OUTPUT', Mem(0x300), Mem(0x302))
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), msg


def prog_flow(msg):
    n = len(msg)
    n0, n1, n2 = 37, 60, 71
    a = Asm(128)
    CNT, W = 0x310, 0x312
    prologue(a)
    a.ins('INPUT-BYTES', n, BUF, At('fail'))
    a.ins('LOAD', CNT, 0)
    a.label('loop')
    a.ins('CALL', At('emit'))
    a.ins('ADD', Ref(CNT), 1)
    a.ins('COMPARE', Mem(CNT), 4, At('loop'), At('done'), At('fail'))
    a.label('done')
    a.ins('COMPARE', Mem(CNT), 3, At('fail'), At('fail'), At('gt'))
    a.label('gt')
    a.ins('COMPARE', Mem(CNT), 9, At('ok'), At('fail'), At('fail'))
    a.label('ok')
    a.ins('JUMP', At('fin'))
    a.label('emit')
    a.ins('SWITCH', Lit(4), Mem(CNT), At('c0'), At('c1'), At('c2'), At('c3'))
    a.label('c0')
    a.ins('OUTPUT', BUF, n0)
    a.ins('RETURN')
    a.label('c1')
    a.ins('PUSH', BUF + n0)
    a.ins('POP', W)
    a.ins('OUTPUT', Mem(W), n1)
    a.ins('RETURN')
    a.label('c2')
    a.ins('OUTPUT', BUF + n0 + n1, n2)
    a.ins('RETURN')
    a.label('c3')
    a.ins('OUTPUT', BUF + n0 + n1 + n2, n - n0 - n1 - n2)
    a.ins('RETURN')
    a.label('fin')
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), msg


def prog_copy2(crc_ok=True):
    """COPY-LITERAL, MEMSET, COPY-OFFSET, SHA-1 and CRC building the message"""
    head = b'OPTIONS sip:bob@example.com SIP/2.0\r\n'
    tail = (b'Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n'
            b'To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=1928301774\r\n'
            b'Call-ID: copy2@pc33.example.com\r\nCSeq: 63104 OPTIONS\r\nContent-Length: 0\r\n\r\n')
    pre = b'Subject: '
    line = pre + b'abcdefghijkl' + b'\r\n'
    out = head + line + line + tail
    inp = head + pre + b'\r\n' + tail
    n1, npre = len(head), len(pre)
    PTR, DIG = 0x310, 0x340
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-BYTES', len(inp), BUF, At('fail'))
    a.ins('LOAD', PTR, OUT)
    a.ins('COPY-LITERAL', BUF, n1, Ref(PTR))
    a.ins('COPY-LITERAL', BUF + n1, npre, Ref(PTR))
    a.ins('MEMSET', Mem(PTR), 12, ord('a'), 1)
    a.ins('ADD', Ref(PTR), 12)
    a.ins('COPY-LITERAL', BUF + n1 + npre, 2, Ref(PTR))
    a.ins('COPY-OFFSET', len(line), len(line), Ref(PTR))
    a.ins('COPY-LITERAL', BUF + n1 + npre + 2, len(tail), Ref(PTR))
    a.ins('SUBTRACT', Ref(PTR), OUT)
    a.ins('LOAD', DIG, DIG + 0x10)                        # the digest goes to DIG + 0x10
    a.ins('SHA-1', OUT, Mem(PTR), Ref(DIG))
    crc = crc16_x25(out) ^ 0xffff        # the dissector compares ~CRC of crc16_ccitt_seed()
    a.ins('CRC', crc if crc_ok else (crc ^ 0x55aa), OUT, Mem(PTR), At('crcbad'))
    a.ins('OUTPUT', OUT, Mem(PTR))
    endmsg(a)
    a.label('crcbad')
    a.ins('OUTPUT', OUT, Mem(PTR))
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), inp, out


def prog_sha1(msg):
    """SHA-1 of the message; the 20 digest bytes in memory are compared with
    the expected words (a digest with every other byte missing fails)"""
    import hashlib
    n = len(msg)
    dig = hashlib.sha1(msg).digest()
    DIG = 0x350
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-BYTES', n, BUF, At('fail'))
    a.ins('LOAD', 0x340, DIG)
    a.ins('SHA-1', BUF, n, Ref(0x340))
    for i in range(10):
        w = struct.unpack('!H', dig[2 * i:2 * i + 2])[0]
        a.label('c%d' % i)
        a.ins('COMPARE', Mem(DIG + 2 * i), w, At('fail'), At('c%d' % (i + 1)), At('fail'))
    a.label('c10')
    a.ins('OUTPUT', BUF, n)
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), msg


def prog_wrap(msg):
    """byte_copy_left/right set: copies, SHA-1, CRC, MEMSET and the state
    creation wrap around inside the window"""
    n = len(msg)
    WIN = 0x5200 - 100
    PTR, DIG = 0x310, 0x340
    a = Asm(128)
    prologue(a, bcl=0x5000, bcr=0x5200)
    a.ins('INPUT-BYTES', 16, BUF, At('fail'))            # the first 16 bytes land outside the window
    a.ins('INPUT-BYTES', n, WIN, At('fail'))             # the message wraps in the window
    a.ins('LOAD', DIG, DIG + 0x10)
    a.ins('SHA-1', WIN, n, Ref(DIG))
    a.ins('CRC', crc16_x25(msg) ^ 0xffff, WIN, n, At('fail'))
    a.ins('MEMSET', 0x51f8, 24, ord('A'), 0)             # wraps at 0x5200
    a.ins('COPY', WIN, n, 0x6100)                        # the source wraps
    a.ins('LOAD', PTR, 0x51fc)
    a.ins('COPY-LITERAL', WIN, 16, Ref(PTR))             # the destination wraps
    a.ins('LOAD', PTR, 0x5010)
    a.ins('COPY-OFFSET', 32, 8, Ref(PTR))                # the position steps back over the left bound
    a.ins('LOAD', PTR, 0x5002)
    a.ins('COPY-OFFSET', 8, 4, Ref(PTR))
    a.ins('LOAD', DIG, 0x51f8)                           # a digest that wraps at 0x5200
    a.ins('SHA-1', WIN, n, Ref(DIG))
    a.ins('INPUT-BYTES', n, WIN, At('fail'))             # load the message again
    a.ins('STATE-CREATE', n, WIN, 0, 6, 1)
    a.ins('OUTPUT', WIN, n)
    endmsg(a, n, WIN, 0, 6, 1)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), b'\0' * 16 + msg + msg


def bit_stream(fields, order):
    """fields: list of (value, nbits). order bit 0: P (octets reversed), bit 2: F (field bits reversed)"""
    bits = []
    for v, nb in fields:
        if order & 4:
            v = int(format(v, '0%db' % nb)[::-1], 2)
        bits += [int(c) for c in format(v, '0%db' % nb)]
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        o = int(''.join(map(str, bits[i:i + 8])), 2)
        if order & 1:
            o = int(format(o, '08b')[::-1], 2)
        out.append(o)
    return bytes(out)


def prog_bits(msg, order):
    a = Asm(128)
    PTR = 0x310
    prologue(a, order=order)
    a.ins('LOAD', PTR, BUF)
    a.label('loop')
    a.ins('INPUT-BITS', 7, TMP, At('eoi'))
    a.ins('COPY', TMP + 1, 1, Mem(PTR))
    a.ins('ADD', Ref(PTR), 1)
    a.ins('JUMP', At('loop'))
    a.label('eoi')
    a.ins('SUBTRACT', Ref(PTR), BUF)
    a.ins('OUTPUT', BUF, Mem(PTR))
    endmsg(a)
    code = a.assemble()
    fields = [(c, 7) for c in msg]
    return code, bit_stream(fields, order)


HUFF = [(5, 0, 15, 0x0a), (3, 128, 191, 0x1a), (1, 384, 511, 0x5a)]


def huff_fields(c):
    i = c - 0x0a
    if i < 16:
        return [(i, 5)]
    if i < 80:
        v = 128 + (i - 16)
        return [(v >> 3, 5), (v & 7, 3)]
    v = 384 + (i - 80)
    return [(v >> 4, 5), ((v >> 1) & 7, 3), (v & 1, 1)]


def prog_huff(msg, order):
    a = Asm(128)
    PTR = 0x310
    prologue(a, order=order)
    a.ins('LOAD', PTR, BUF)
    a.label('loop')
    ops = [TMP, At('eoi'), Lit(3)]
    for g in HUFF:
        ops += list(g)
    a.ins('INPUT-HUFFMAN', *ops)
    a.ins('COPY', TMP + 1, 1, Mem(PTR))
    a.ins('ADD', Ref(PTR), 1)
    a.ins('JUMP', At('loop'))
    a.label('eoi')
    a.ins('SUBTRACT', Ref(PTR), BUF)
    a.ins('OUTPUT', BUF, Mem(PTR))
    endmsg(a)
    code = a.assemble()
    fields = []
    for c in msg:
        fields += huff_fields(c)
    return code, bit_stream_huff(fields, order)


def bit_stream_huff(fields, order):
    # the Huffman bit order is bit 1 of the order word (H): every group is reversed
    bits = []
    for v, nb in fields:
        if order & 2:
            v = int(format(v, '0%db' % nb)[::-1], 2)
        bits += [int(c) for c in format(v, '0%db' % nb)]
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        o = int(''.join(map(str, bits[i:i + 8])), 2)
        if order & 1:
            o = int(format(o, '08b')[::-1], 2)
        out.append(o)
    return bytes(out)


def pad_fit_bits(text, bitcount_fn, maxpad):
    """add a Subject header with k letters until the padding bits at the end
    of the bit stream are at most maxpad (a letter changes the bit count)"""
    for k in range(0, 32):
        t = text if k == 0 else text.replace(b'Max-Forwards: 70\r\n',
                                             b'Max-Forwards: 70\r\nSubject: ' + b'a' * k + b'\r\n', 1)
        if (-bitcount_fn(t)) % 8 <= maxpad:
            return t
    raise RuntimeError('no padding fits')


def prog_state_create(ma, mb):
    """INPUT-BYTES two messages, STATE-CREATE two items (the first message; a
    junk prefix and the second message) and STATE-FREE, OUTPUT the first"""
    na, nb = len(ma), len(mb)
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-BYTES', na + 8 + nb, BUF, At('fail'))
    a.ins('STATE-CREATE', na, BUF, 0, 6, 1)
    a.ins('STATE-CREATE', 8 + nb, BUF + na, 0, 8, 2)
    a.ins('STATE-FREE', Mt(0x330), 6)
    a.ins('OUTPUT', BUF, na)
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), ma + b'JUNKJUNK' + mb


def prog_state_access(pid, n, begin=0, slen=None, saddr=OUT, sinstr=0):
    """STATE-ACCESS of a state item; the bytes are written to saddr and output"""
    a = Asm(128)
    prologue(a)
    pidp = pid + b'\0' * (len(pid) % 2)
    words = [struct.unpack('!H', pidp[i:i + 2])[0] for i in range(0, len(pidp), 2)]
    a.ins('MULTILOAD', 0x320, Lit(len(words)), *words)
    a.ins('STATE-ACCESS', 0x320, len(pid), begin, n if slen is None else slen, saddr, sinstr)
    a.ins('OUTPUT', saddr, n if slen is None else slen)
    endmsg(a)
    return a.assemble()


KINDS = {
    'AND': 'rm', 'OR': 'rm', 'NOT': 'r', 'LSHIFT': 'rm', 'RSHIFT': 'rm', 'ADD': 'rm', 'SUBTRACT': 'rm',
    'MULTIPLY': 'rm', 'DIVIDE': 'rm', 'REMAINDER': 'rm', 'SORT-ASCENDING': 'mmm', 'SORT-DESCENDING': 'mmm',
    'SHA-1': 'mmr', 'LOAD': 'mm', 'MULTILOAD': 'mlmmm', 'PUSH': 'm', 'POP': 'm', 'COPY': 'mmm',
    'COPY-LITERAL': 'mmr', 'COPY-OFFSET': 'mmr', 'MEMSET': 'mmmm', 'JUMP': 'a', 'COMPARE': 'mmaaa',
    'CALL': 'a', 'RETURN': '', 'SWITCH': 'lmaaa', 'CRC': 'mmma', 'INPUT-BYTES': 'mma', 'INPUT-BITS': 'mma',
    'INPUT-HUFFMAN': 'malmmmmmmmm', 'STATE-ACCESS': 'mmmmmm', 'STATE-CREATE': 'mmmmm', 'STATE-FREE': 'mm',
    'OUTPUT': 'mm', 'END-MESSAGE': 'mmmmmmm',
}
MT_FORMS = ('lit6', 'pow6', 'pow8', 'hi5', 'hi12', 'l13', 'gen')
MT_VALUES = {'lit6': 5, 'pow6': 128, 'pow8': 1024, 'hi5': 65530, 'hi12': 61500, 'l13': 4000, 'gen': 12345}


def sweep_code(op, variant):
    """one instruction with every operand in the forms of 'variant' (0: memory
    forms, 1: literal forms), followed by a bare END-MESSAGE. The code is only
    meant to be shown by the UDVM code dissection."""
    a = Asm(128)
    ops = []
    kinds = KINDS[op]
    for i, k in enumerate(kinds):
        if k == 'r':
            ops.append(Ref(0x40 + 2 * i, ('r7', 'r14', 'r16')[(i + variant) % 3]))
        elif k == 'l':
            ops.append(Lit(2 if op in ('MULTILOAD', 'INPUT-HUFFMAN', 'SWITCH') else 5, ('l7', 'l14', 'l16')[(i + variant) % 3]))
        elif k == 'm' and variant == 0:
            f = ('m6', 'm13', 'mgen')[i % 3]
            ops.append(Mem((0x40 if f == 'm6' else 0x300) + 2 * i, f))
        elif k == 'm':
            f = MT_FORMS[(i + 3 * variant) % len(MT_FORMS)]
            ops.append(Mt(MT_VALUES[f], f))
        elif k == 'a' and variant == 0:
            f = ('m6', 'm13', 'mgen')[i % 3]
            ops.append(Raw(enc_mem((0x40 if f == 'm6' else 0x320) + 2 * i, f)))
        else:
            f = MT_FORMS[(i + 2 * variant + 1) % len(MT_FORMS)]
            ops.append(Raw(enc_mt(MT_VALUES[f], f)))
    # the operand counts of the loops: MULTILOAD #n, SWITCH #n, INPUT-HUFFMAN #n
    if op == 'MULTILOAD':
        ops = ops[:2] + [Mt(1), Mt(2)]
    if op == 'SWITCH':
        ops = ops[:2] + [ops[2], Raw(enc_mt(30, 'lit6'))]
    if op == 'INPUT-HUFFMAN':
        ops = ops[:3] + [Mt(5), Mt(0), Mt(31), Mt(7), Mt(4), Mt(32), Mt(63), Mt(100)]
    a.ins(op, *ops)
    a.data(bytes([OPS_END]))
    return a.assemble()


def build_sweeps(add, m):
    for variant in (0, 1):
        for op in KINDS:
            add(udp(fmt2(sweep_code(op, variant), m)))
    # END-MESSAGE cut short: no operands, one, five and six operands
    for nops in (0, 1, 2, 5, 6):
        a = Asm(128)
        a.ins('END-MESSAGE', *([0] * nops))
        add(udp(fmt2(a.assemble(), m)))


def build_operand_failures(add, m):
    """an instruction placed so that its k-th operand starts at 0x10000: the
    operand cannot be decoded and the decompression fails"""
    for op, kinds in KINDS.items():
        if op in ('RETURN', 'SORT-ASCENDING', 'SORT-DESCENDING'):
            continue
        for k in range(len(kinds)):
            pre = bytes([OPS[op]]) + bytes([1 if kinds[i] == 'l' else 0 for i in range(k)])
            start = 65536 - len(pre)
            a = Asm(128)
            prologue(a)
            a.ins('INPUT-BYTES', len(pre), Mt(start, 'gen'), Mt(0))
            jaddr = 128 + len(a.assemble())
            a.ins('JUMP', Mt((start - jaddr) & 0xffff, 'gen'))
            code = a.assemble()
            add(udp(fmt2(code, pre)))


def prog_access_wrap(msg):
    """STATE-ACCESS of the static dictionary into a window: the copy wraps"""
    n = len(msg)
    a = Asm(128)
    prologue(a, bcl=0x5000, bcr=0x5200)
    words = [struct.unpack('!H', SIP_SDP_ID[i:i + 2])[0] for i in range(0, 6, 2)]
    a.ins('MULTILOAD', 0x320, Lit(3), *words)
    a.ins('STATE-ACCESS', 0x320, 6, 0, 0, 0x51f0, 0)
    a.ins('INPUT-BYTES', n, BUF, At('fail'))
    a.ins('OUTPUT', BUF, n)
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), msg


def load_dictionary(path):
    src = open(path).read()
    i = src.index('sip_sdp_static_dictionary_for_sigcomp[0x12e4]')
    i = src.index('=', i)
    j = src.index('};', i)
    vals = re.findall(r'0x([0-9a-fA-F]{2})', src[i:j])
    return bytes(int(v, 16) for v in vals)


def prog_dict(dic):
    """copy text out of the static SIP/SDP dictionary (STATE-ACCESS with the
    state length taken from the state), and out of the input"""
    pieces = [
        ('lit', b'OPTIONS sip:bob@example.com SIP/2.0'),
        ('dict', b'\r\nVia: SIP/2.0/UDP '),
        ('lit', b'pc33.example.com;branch=z9hG4bK776asdhds'),
        ('dict', b'\r\nTo: '),
        ('lit', b'<sip:bob@example.com>'),
        ('dict', b'\r\nFrom: '),
        ('lit', b'<sip:alice@example.com>;tag=1928301774'),
        ('dict', b'\r\nCall-ID: '),
        ('lit', b'dict@pc33.example.com'),
        ('dict', b'\r\nCSeq: '),
        ('lit', b'63104 OPTIONS'),
        ('dict', b'\r\nContent-Length: '),
        ('lit', b'0'),
        ('dict', b'\r\n\r\n'),
    ]
    inp = b''.join(p for k, p in pieces if k == 'lit')
    out = b''.join(p for k, p in pieces)
    PTR = 0x310
    a = Asm(128)
    prologue(a)
    words = [struct.unpack('!H', SIP_SDP_ID[i:i + 2])[0] for i in range(0, 6, 2)]
    a.ins('MULTILOAD', 0x320, Lit(3), *words)
    a.ins('STATE-ACCESS', 0x320, 6, 0, 0, DICT_AT, 0)            # length from the state
    a.ins('INPUT-BYTES', len(inp), BUF, At('fail'))
    a.ins('LOAD', PTR, OUT + 0x2000)
    pos = 0
    for k, p in pieces:
        if k == 'lit':
            a.ins('COPY-LITERAL', BUF + pos, len(p), Ref(PTR))
            pos += len(p)
        else:
            off = dic.find(p)
            assert off >= 0, p
            a.ins('COPY-LITERAL', DICT_AT + off, len(p), Ref(PTR))
    a.ins('SUBTRACT', Ref(PTR), OUT + 0x2000)
    a.ins('OUTPUT', OUT + 0x2000, Mem(PTR))
    endmsg(a)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    return a.assemble(), inp, out


# --------------------------------------------------------------------------
# captures
# --------------------------------------------------------------------------
def build_main(out, dic):
    fr = []
    marks = {}

    def add(f, name=None):
        fr.append(f)
        if name:
            marks[name] = len(fr)

    m1, m2, m3 = sipmsg(b'c1'), sipmsg(b'c2'), sipmsg(b'c3')

    # ---- format 2: the bytecode is uploaded with the message ----
    code, msg = prog_copy(m1)
    add(udp(fmt2(code, msg)), 'copy')
    code, msg = prog_copy(m2)
    add(udp(fmt2(code, msg, dest=2)), 'copy_dest2')
    add(udp(fmt2(code, msg, dest=0)), 'copy_dest0')
    add(udp(fmt2(code, msg, dest=15)), 'copy_dest15')
    add(udp(fmt2(code, msg, fb=b'\x15')), 'copy_fb1')
    add(udp(fmt2(code, msg, fb=b'FEEDBACK-ITEM')), 'copy_fb_long')
    add(udp(fmt2(code, msg), v6=True, dport=6666), 'copy_v6_6666')
    code, msg = prog_alu(m3)
    add(udp(fmt2(code, msg)), 'alu')
    code, msg = prog_flow(sipmsg(b'flow'))
    add(udp(fmt2(code, msg)), 'flow')
    for crc_ok in (True, False):
        code, inp, outm = prog_copy2(crc_ok)
        add(udp(fmt2(code, inp)), 'copy2_crc_%s' % ('ok' if crc_ok else 'bad'))
    mw = sipmsg(b'wrap')
    code, inp = prog_wrap(mw)
    add(udp(fmt2(code, inp)), 'wrap')
    # bit and Huffman input in every bit order
    for order in range(8):
        txt = pad_fit_bits(sipmsg(b'bits%d' % order), lambda t: 7 * len(t), 0)
        code, data = prog_bits(txt, order)
        add(udp(fmt2(code, data)), 'bits_%d' % order)
    for order in range(8):
        txt = pad_fit_bits(sipmsg(b'huff%d' % order),
                           lambda t: sum(nb for c in t for _, nb in huff_fields(c)), 4)
        code, data = prog_huff(txt, order)
        add(udp(fmt2(code, data)), 'huff_%d' % order)

    # ---- state creation and access ----
    ms1, ms2 = sipmsg(b'st1'), sipmsg(b'st2')
    code, inp = prog_state_create(ms1, ms2)
    add(udp(fmt2(code, inp)), 'state_create')
    id1 = state_id(len(ms1), BUF, 0, 6, ms1)
    id2 = state_id(8 + len(ms2), BUF + len(ms1), 0, 8, b'JUNKJUNK' + ms2)
    add(udp(fmt2(prog_state_access(id1[:6], len(ms1)))), 'state_access_1')
    add(udp(fmt2(prog_state_access(id2[:6], len(ms2), begin=8, saddr=OUT + 0x100))), 'state_access_2_begin')
    # program that creates a state with itself, then format 1 messages using it
    ma, mb = sipmsg(b'ab01'), sipmsg(b'ab02')
    code, msg = prog_copy(ma, state=True)
    add(udp(fmt2(code, msg)), 'prog_state_create')
    pid = state_id(len(code), 128, 128, 6, code)
    add(udp(fmt1(pid[:6], mb)), 'fmt1_6')
    add(udp(fmt1(pid[:9], sipmsg(b'ab03'))), 'fmt1_9')
    add(udp(fmt1(pid[:12], sipmsg(b'ab04'))), 'fmt1_12')
    add(udp(fmt1(pid[:6], sipmsg(b'ab05'), fb=b'\x2a')), 'fmt1_fb')
    add(udp(fmt1(pid[:6], sipmsg(b'ab06'), fb=b'RETURNED-FEEDBACK')), 'fmt1_fb_long')
    add(udp(fmt1(pid[:6], sipmsg(b'ab07')), dport=6666, v6=True), 'fmt1_v6')

    # ---- the static dictionary ----
    code, inp, outm = prog_dict(dic)
    add(udp(fmt2(code, inp)), 'dict')

    code, msg = prog_access_wrap(sipmsg(b'accwrap'))
    add(udp(fmt2(code, msg)), 'dict_wrap')

    # ---- the reproducers of the fixes on the branch ----
    code, msg = prog_sha1(sipmsg(b'sha1'))
    add(udp(fmt2(code, msg)), 'sha1_digest')
    # a state whose address + length is past the end of the memory
    SL, SA = 0x1000, 0xff00
    mr = sipmsg(b'repro')
    a = Asm(128)
    a.ins('INPUT-BYTES', len(mr), BUF, At('fail'))
    a.ins('OUTPUT', BUF, len(mr))
    a.ins('END-MESSAGE', 0, 0, Mt(SL, 'gen'), Mt(SA, 'gen'), 0, 6, 0)
    a.label('fail')
    a.ins('DECOMPRESSION-FAILURE')
    code = a.assemble()
    mem = bytearray(65536)
    mem[0:10] = bytes([0, 0, 0, 16, 0, 1, 0, 0, 0, 0])
    mem[128:128 + len(code)] = code
    data = bytes(mem[(SA + i) & 0xffff] for i in range(SL))
    add(udp(fmt2(code, mr)), 'repro_state_create')
    add(udp(fmt1(state_id(SL, SA, 0, 6, data)[:6], b'\0' * 16)), 'repro_state_oob')
    # a reference operand at the last address of the memory
    a = Asm(128)
    a.ins('LOAD', Mt(65534, 'gen'), Mt(0x01c0, 'gen'))
    a.ins('JUMP', Mt((65534 - (128 + 7)) & 0xffff, 'gen'))
    add(udp(fmt2(a.assemble())), 'repro_refop')
    # COPY-OFFSET with the largest offset in a loop
    a = Asm(128)
    a.label('top')
    a.ins('COPY-OFFSET', Mt(0xffff, 'gen'), 0, Ref(0))
    a.ins('JUMP', At('top', 'gen'))
    add(udp(fmt2(a.assemble(), b'A' * 1400)), 'repro_copyoffset')
    # STATE-ACCESS with a partial identifier that runs off the end of the memory
    a = Asm(128)
    a.ins('STATE-ACCESS', Mt(0xfffe, 'gen'), 20, 0, 0, 0, 0)
    add(udp(fmt2(a.assemble())), 'repro_stateaccess')
    # bytecode that outputs the whole message again: SigComp, SIP, SigComp, ...
    L = 29
    H1, H2 = (L >> 4) & 0xff, ((L & 0xf) << 4) | 1
    a = Asm(128)
    a.ins('LOAD', Mt(124, 'gen'), Mt(0x00f8, 'gen'))
    a.ins('LOAD', Mt(126, 'gen'), Mt((H1 << 8) | H2, 'gen'))
    a.ins('OUTPUT', Mt(125, 'gen'), Mt(3 + L, 'gen'))
    a.ins('END-MESSAGE', 0, 0, 0, 0, 0, 6, 0)
    rc = a.assemble()
    assert len(rc) == L
    add(udp(fmt2(rc)), 'repro_recursion')

    # ---- NACK messages ----
    sha = bytes(range(20))
    add(udp(nack(1, 0x1f, 0x0123, sha, SIP_SDP_ID)), 'nack_state_not_found')
    add(udp(nack(21, 0x1f, 0x0123, sha, SIP_SDP_ID + b'\x01\x02\x03')), 'nack_id_not_unique')
    add(udp(nack(23, 0x20, 0x0200, sha, bytes(range(20)))), 'nack_state_too_short')
    add(udp(nack(2, 0x01, 0x0044, sha, b'\x10')), 'nack_cycles')
    add(udp(nack(18, 0x22, 0x0044, sha, b'\x01\x00')), 'nack_bytecodes_too_large')
    add(udp(nack(3, 0x00, 0x0000, sha), ), 'nack_user_requested')
    add(udp(nack(19, 0x7f, 0x0010, sha, b'', fb=b'\x07')), 'nack_fb')
    add(udp(nack(25, 0x7f, 0x0010, sha, b'', fb=b'NACK-FEEDBACK')), 'nack_fb_long')

    # ---- SigComp over TCP, with escaped 0xFF and reassembly ----
    t = Tcp()
    code, msg = prog_copy(sipmsg(b'tcp1'))
    add(t.seg(tcp_wrap(fmt2(code, msg))), 'tcp_one')
    two = tcp_wrap(fmt2(*prog_copy(sipmsg(b'tcp2')))) + tcp_wrap(fmt2(*prog_copy(sipmsg(b'tcp3'))))
    add(t.seg(two), 'tcp_two')
    code, msg = prog_copy(sipmsg(b'tcp4'))
    full = tcp_wrap(fmt2(code, msg))
    add(t.seg(full[:60]), 'tcp_split1')
    add(t.seg(full[60:]), 'tcp_split2')
    add(t.seg(tcp_wrap(nack(1, 0x1f, 0x0123, sha, SIP_SDP_ID))), 'tcp_nack')
    # a delimiter in front of a message and a message with a literal 0xFF
    add(t.seg(b'\xff\xff' + tcp_wrap(nack(3, 0, 0, bytes([0xff] * 20)))), 'tcp_leading_delim')

    # ---- SIP carries SigComp (any payload starting with 0xF8) ----
    code, msg = prog_copy(sipmsg(b'sipudp'))
    add(udp(fmt2(code, msg), dport=5060), 'sip_udp')
    add(Tcp(49300, 5060).seg(tcp_wrap(fmt2(code, msg))), 'sip_tcp')

    write_pcap(os.path.join(out, 'sigcomp-coverage.pcap'), fr)
    return marks


def build_malformed(out, dic):
    fr = []

    def add(f):
        fr.append(f)

    m = sipmsg(b'bad')
    sha = bytes(range(20))

    def prog(build):
        a = Asm(128)
        prologue(a)
        build(a)
        return fmt2(a.assemble(), m)

    def prog_order(order, build):
        a = Asm(128)
        prologue(a, order=order)
        build(a)
        return fmt2(a.assemble(), m)

    # DECOMPRESSION-FAILURE with and without output
    add(udp(prog(lambda a: a.ins('DECOMPRESSION-FAILURE'))))
    add(udp(prog(lambda a: (a.ins('INPUT-BYTES', 20, BUF, At('f')), a.ins('OUTPUT', BUF, 20),
                            a.label('f'), a.ins('DECOMPRESSION-FAILURE')))))
    # division by zero (every instruction), switch too high, jump out, stack underflow
    for op in ('MULTIPLY', 'DIVIDE', 'REMAINDER'):
        add(udp(prog(lambda a, op=op: (a.ins('LOAD', 0x310, 5), a.ins(op, Ref(0x310), 0)))))
    add(udp(prog(lambda a: a.ins('SWITCH', Lit(2), 5, At('x'), At('x')))))
    add(udp(prog(lambda a: (a.ins('SWITCH', Lit(2), 1, At('x'), At('x')), a.label('x'), a.ins('JUMP', Mt(0xfff0, 'hi12'))))))
    add(udp(prog(lambda a: a.ins('RETURN'))))
    add(udp(prog(lambda a: a.ins('POP', 0x310))))
    # cycles exhausted: a tight loop
    add(udp(prog(lambda a: (a.label('l'), a.ins('JUMP', At('l'))))))
    # shifts above 15 (invalid shift value), invalid instruction, sort not implemented
    add(udp(prog(lambda a: (a.ins('LOAD', 0x310, 1), a.ins('LSHIFT', Ref(0x310), 16)))))
    add(udp(prog(lambda a: (a.ins('LOAD', 0x310, 1), a.ins('RSHIFT', Ref(0x310), 17)))))
    add(udp(fmt2(bytes([0x7e]) + b'\0' * 8, m)))
    add(udp(prog(lambda a: a.ins('SORT-ASCENDING', 0x310, 4, 2))))
    add(udp(prog(lambda a: a.ins('SORT-DESCENDING', 0x310, 4, 2))))
    # input past the end of the message
    add(udp(prog(lambda a: a.ins('INPUT-BYTES', 5000, BUF, At('x')) or a.label('x'))))
    add(udp(prog(lambda a: (a.ins('INPUT-BYTES', 5000, BUF, At('x')), a.label('x'), a.ins('OUTPUT', BUF, 8),
                            a.ins('DECOMPRESSION-FAILURE')))))
    add(udp(prog(lambda a: a.ins('INPUT-BITS', 17, TMP, At('x')) or a.label('x'))))
    add(udp(prog_order(8, lambda a: a.ins('INPUT-BITS', 8, TMP, At('x')) or a.label('x'))))
    add(udp(prog(lambda a: a.ins('INPUT-BITS', 16, TMP, At('x')) or a.label('x'))))
    add(udp(fmt2(Asm(128).assemble() or b'\x10', b'')))
    # INPUT-BITS beyond the end of a short message, then jump
    def short_bits(a):
        a.ins('INPUT-BITS', 16, TMP, At('x'))
        a.ins('INPUT-BITS', 16, TMP, At('x'))
        a.label('x')
        a.ins('INPUT-BITS', 16, TMP, At('y'))
        a.label('y')
        a.ins('DECOMPRESSION-FAILURE')
    a = Asm(128)
    prologue(a)
    short_bits(a)
    add(udp(fmt2(a.assemble(), b'\x01\x02\x03')))
    # Huffman: no match, and input exhausted
    def huff_nomatch(a):
        a.ins('INPUT-HUFFMAN', TMP, At('x'), Lit(1), 3, 0, 1, 0)
        a.label('x')
        a.ins('DECOMPRESSION-FAILURE')
    add(udp(prog(huff_nomatch)))
    def huff_big(a):
        a.ins('INPUT-HUFFMAN', TMP, At('x'), Lit(1), 20, 0, 1, 0)
        a.label('x')
        a.ins('DECOMPRESSION-FAILURE')
    add(udp(prog(huff_big)))
    a = Asm(128)
    prologue(a)
    a.ins('INPUT-HUFFMAN', TMP, At('x'), Lit(1), 16, 0, 0xffff, 0)
    a.ins('INPUT-HUFFMAN', TMP, At('x'), Lit(1), 16, 0, 0xffff, 0)
    a.label('x')
    a.ins('DECOMPRESSION-FAILURE')
    add(udp(fmt2(a.assemble(), b'\x01\x02\x03')))
    # state handling errors: too many creates, bad priority, bad min access
    def many(a):
        for _ in range(5):
            a.ins('STATE-CREATE', 4, BUF, 0, 6, 1)
    add(udp(prog(many)))
    add(udp(prog(lambda a: a.ins('STATE-CREATE', 4, BUF, 0, 6, 0xffff, ))))
    add(udp(prog(lambda a: a.ins('STATE-CREATE', 4, BUF, 0, 5, 1))))
    add(udp(prog(lambda a: a.ins('STATE-CREATE', 4, BUF, 0, 21, 1))))
    def four(a):
        for _ in range(4):
            a.ins('STATE-CREATE', 4, BUF, 0, 6, 1)
        a.ins('END-MESSAGE', 0, 0, 0, 0, 0, 6, 0)
    add(udp(prog(four)))                                  # the fifth creation is the END-MESSAGE

    # STATE-ACCESS errors: id length, not found, state too short, begin without length
    for plen in (5, 21):
        add(udp(prog(lambda a, plen=plen: a.ins('STATE-ACCESS', 0x320, plen, 0, 0, DICT_AT, 0))))
    add(udp(prog(lambda a: a.ins('STATE-ACCESS', 0x320, 6, 0, 0, DICT_AT, 0))))                        # nothing in memory: no match
    def acc(a, begin, ln):
        words = [struct.unpack('!H', SIP_SDP_ID[i:i + 2])[0] for i in range(0, 6, 2)]
        a.ins('MULTILOAD', 0x320, Lit(3), *words)
        a.ins('STATE-ACCESS', 0x320, 6, begin, ln, DICT_AT, 0)
        a.ins('OUTPUT', DICT_AT, 4)
    add(udp(prog(lambda a: acc(a, 0x1000, 0x400))))                                                       # begin + length > size
    add(udp(prog(lambda a: acc(a, 100, 0))))                                                             # length from state, begin != 0
    add(udp(prog(lambda a: acc(a, 0, 0x12e4))))
    # a 9 byte identifier does not find a state (the table is keyed by the first 6 bytes)
    ms1x = sipmsg(b'st1')
    add(udp(fmt2(prog_state_access(state_id(len(ms1x), BUF, 0, 6, ms1x)[:9], len(ms1x)))))
    # presence dictionary with default address and instruction
    def acc_pres(a):
        words = [struct.unpack('!H', PRESENCE_ID[i:i + 2])[0] for i in range(0, 6, 2)]
        a.ins('MULTILOAD', 0x320, Lit(3), *words)
        a.ins('STATE-ACCESS', 0x320, 6, 0, 0, DICT_AT, 0)
        a.ins('OUTPUT', DICT_AT, 40)
        endmsg(a)
    add(udp(prog(acc_pres)))
    # message format 1: a state that does not exist, the dictionary as program, a short partial id
    add(udp(fmt1(bytes(6), m)))
    add(udp(fmt1(SIP_SDP_ID, m)))
    add(udp(fmt1(PRESENCE_ID + b'\x01\x02\x03', m)))
    # a state created with an id used twice (the second creation is dropped)
    code, msg = prog_copy(sipmsg(b'dup1'), state=True)
    add(udp(fmt2(code, msg)))
    add(udp(fmt2(code, msg)))
    # SHA-1 and CRC with bad ranges
    add(udp(prog(lambda a: a.ins('SHA-1', 0xfff0, 0x40, Ref(0x310)))))
    add(udp(prog(lambda a: a.ins('CRC', 0, 0xfff0, 0x40, At('x')) or a.label('x'))))
    add(udp(prog(lambda a: (a.ins('MULTILOAD', 0x7ff0, Lit(20), *([1] * 20)),))))
    # invalid operand reads at the end of memory
    add(udp(prog(lambda a: a.ins('LOAD', 0xffff, 5))))
    add(udp(prog(lambda a: a.ins('JUMP', Mt(0xffff - 128 - 4, 'gen')))))
    # code shorter than its instructions (operands past the end of the code)
    add(udp(fmt2(bytes([14, 0x80]), m)))
    add(udp(fmt2(bytes([34]), m)))
    # a length of 0 and a version other than 1: bytecode of length zero
    add(udp(bytes([0xf8, 0x00, 0x02]) + m))
    # NACK with the unknown reason, short NACK, a NACK without hash
    add(udp(nack(99, 0x30, 1, sha, b'xx')))
    add(udp(bytes([0xf8, 0x00, 0x01, 0x04, 0x01])))
    # TCP framing: truncated escape, illegal escape code, quote form, unterminated message
    t = Tcp(49400, 5555)
    code, msg = prog_copy(sipmsg(b'tcpbad'))
    add(t.seg(fmt2(code, msg)))                       # no delimiter: waits for more data
    add(t.seg(b'\xff\xffshort\xff'))
    add(t.seg(b'\xf8\x00\x01\xff\x90\xff\xff'))        # illegal escape code
    add(t.seg(b'\xf8\x00\x01\xff\x04ABCD\xff\xff'))    # quote form
    add(t.seg(b'\xf8\x00\x01\xff'))                    # ends with a lone escape
    t2 = Tcp(49500, 5555)
    add(t2.seg(b'\xf8' + b'\0' * 3 + b'\xff\xff' + b'\xf8' + b'\x00\x02' + b'\xff\xff'))

    # not SigComp at all on a SigComp port; a TCP quote that is longer than the data
    add(udp(b'hello, this is not a sigcomp message'))
    add(t2.seg(b'\xf8\x00\x01\xff\x7fABC'))
    # every instruction with its operands in the memory forms and in the literal forms,
    # END-MESSAGE cut short, and operands that cannot be decoded
    build_sweeps(add, m)
    build_operand_failures(add, m)

    write_pcap(os.path.join(out, 'sigcomp-coverage-malformed.pcap'), fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    src = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRCDIR, 'epan/dissectors/packet-sigcomp.c')
    os.makedirs(out, exist_ok=True)
    dic = load_dictionary(src)
    assert len(dic) == 0x12e4, len(dic)
    marks = build_main(out, dic)
    build_malformed(out, dic)
    with open(os.path.join(out, 'sigcomp-marks.txt'), 'w') as f:
        for k, v in sorted(marks.items(), key=lambda kv: kv[1]):
            f.write('%d %s\n' % (v, k))
    print('main frames:', len(marks))


if __name__ == '__main__':
    main()

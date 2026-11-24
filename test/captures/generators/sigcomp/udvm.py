# Helper module for the sigcomp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# A small UDVM (RFC 3320) assembler used by mksigcomp.py.
# Operand kinds: Ref ($), Lit (#), Mt (% literal), Mem (% memory), At (@).
import hashlib
import struct

OPS = {
    'DECOMPRESSION-FAILURE': 0, 'AND': 1, 'OR': 2, 'NOT': 3, 'LSHIFT': 4, 'RSHIFT': 5,
    'ADD': 6, 'SUBTRACT': 7, 'MULTIPLY': 8, 'DIVIDE': 9, 'REMAINDER': 10,
    'SORT-ASCENDING': 11, 'SORT-DESCENDING': 12, 'SHA-1': 13, 'LOAD': 14,
    'MULTILOAD': 15, 'PUSH': 16, 'POP': 17, 'COPY': 18, 'COPY-LITERAL': 19,
    'COPY-OFFSET': 20, 'MEMSET': 21, 'JUMP': 22, 'COMPARE': 23, 'CALL': 24,
    'RETURN': 25, 'SWITCH': 26, 'CRC': 27, 'INPUT-BYTES': 28, 'INPUT-BITS': 29,
    'INPUT-HUFFMAN': 30, 'STATE-ACCESS': 31, 'STATE-CREATE': 32, 'STATE-FREE': 33,
    'OUTPUT': 34, 'END-MESSAGE': 35,
}


class Ref:      # $operand: the 2-byte word at memory[addr]
    def __init__(self, addr, form=None):
        self.addr, self.form = addr, form


class Lit:      # #operand: a literal 0..65535
    def __init__(self, n, form=None):
        self.n, self.form = n, form


class Mt:       # %operand, literal value
    def __init__(self, v, form=None):
        self.v, self.form = v & 0xffff, form


class Mem:      # %operand, the word at memory[addr]
    def __init__(self, addr, form=None):
        self.addr, self.form = addr, form


class At:       # @operand: a label
    def __init__(self, label, form=None):
        self.label, self.form = label, form


class Raw:
    def __init__(self, b):
        self.b = b


def enc_lit(n, form=None):
    if form is None:
        form = 'l7' if n < 128 else ('l14' if n < 16384 else 'l16')
    if form == 'l7':
        return bytes([n])
    if form == 'l14':
        return struct.pack('!H', 0x8000 | n)
    return b'\xc0' + struct.pack('!H', n)


def enc_ref(addr, form=None):
    if form is None:
        if addr % 2 == 0 and addr // 2 < 128:
            form = 'r7'
        elif addr % 2 == 0 and addr // 2 < 16384:
            form = 'r14'
        else:
            form = 'r16'
    if form == 'r7':
        return bytes([addr // 2])
    if form == 'r14':
        return struct.pack('!H', 0x8000 | (addr // 2))
    return b'\xc0' + struct.pack('!H', addr)


def enc_mt(v, form=None):
    if form is None:
        if v < 64:
            form = 'lit6'
        elif v >= 65504:
            form = 'hi5'
        elif v in (64, 128):
            form = 'pow6'
        elif v in (256, 512, 1024, 2048, 4096, 8192, 16384, 32768):
            form = 'pow8'
        elif v >= 61440:
            form = 'hi12'
        elif v < 8192:
            form = 'l13'
        else:
            form = 'gen'
    if form == 'lit6':
        return bytes([v])
    if form == 'pow6':
        return bytes([0x86 | (1 if v == 128 else 0)])
    if form == 'pow8':
        return bytes([0x88 | (v.bit_length() - 1 - 8)])
    if form == 'hi5':
        return bytes([0xe0 | (v - 65504)])
    if form == 'hi12':
        return struct.pack('!H', 0x9000 | (v - 61440))
    if form == 'l13':
        return struct.pack('!H', 0xa000 | v)
    return b'\x80' + struct.pack('!H', v)


def enc_mem(addr, form=None):
    if form is None:
        if addr % 2 == 0 and addr // 2 < 64:
            form = 'm6'
        elif addr < 8192:
            form = 'm13'
        else:
            form = 'mgen'
    if form == 'm6':
        return bytes([0x40 | (addr // 2)])
    if form == 'm13':
        return struct.pack('!H', 0xc000 | addr)
    return b'\x81' + struct.pack('!H', addr)


class Asm:
    def __init__(self, org=128):
        self.org = org
        self.items = []
        self.force_gen = False

    def label(self, name):
        self.items.append(('label', name))

    def ins(self, name, *ops):
        self.items.append(('ins', name, ops))

    def data(self, b):
        self.items.append(('data', b))

    def _encode(self, labels):
        out = b''
        addrs = {}
        pos = self.org
        for it in self.items:
            if it[0] == 'label':
                addrs[it[1]] = pos
                continue
            if it[0] == 'data':
                out += it[1]
                pos += len(it[1])
                continue
            _, name, ops = it
            here = pos
            b = bytes([OPS[name]])
            for o in ops:
                if isinstance(o, int):
                    o = Mt(o)
                if isinstance(o, Ref):
                    b += enc_ref(o.addr, o.form)
                elif isinstance(o, Lit):
                    b += enc_lit(o.n, o.form)
                elif isinstance(o, Mt):
                    b += enc_mt(o.v, o.form)
                elif isinstance(o, Mem):
                    b += enc_mem(o.addr, o.form)
                elif isinstance(o, At):
                    d = (labels.get(o.label, here) - here) & 0xffff
                    b += enc_mt(d, 'gen' if self.force_gen else o.form)
                elif isinstance(o, Raw):
                    b += o.b
                else:
                    raise TypeError(o)
            out += b
            pos += len(b)
        return out, addrs

    def assemble(self):
        labels = {}
        for _ in range(12):
            out, addrs = self._encode(labels)
            if addrs == labels:
                self.labels = addrs
                return out
            labels = addrs
        self.force_gen = True
        for _ in range(12):
            out, addrs = self._encode(labels)
            if addrs == labels:
                self.labels = addrs
                return out
            labels = addrs
        raise RuntimeError('assembler did not converge')

    def addr_of(self, name):
        self.assemble()
        return self.labels[name]


def state_id(length, address, instr, minacc, data):
    h = struct.pack('!HHHH', length, address, instr, minacc) + data
    return hashlib.sha1(h).digest()


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff

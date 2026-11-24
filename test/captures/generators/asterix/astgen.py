# Helper module for the asterix capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build ASTERIX records for every category, edition and UAP that
packet-asterix-generated.h knows, following the structure that the
generated dissector code expects (used by mkasterix.py).

The generated header is only read to find out which items a UAP has and
how long each one is (fixed, extended, repetitive, compound, explicit,
RE); the octets themselves are made up here: a running pattern, with
spare bits cleared and FX bits set as the structure needs.
"""
import re
import struct


class Spec:
    def __init__(self, path):
        src = open(path).read()
        self.src = src
        self.funcs = {}
        for m in re.finditer(r'^static int (dissect_\w+)\(tvbuff_t[^)]*\)[^\n]*\n\{\n(.*?)\n\}\n', src, re.S | re.M):
            self.funcs[m.group(1)] = m.group(2)
        # UAP tables: (cat, edition, uap name) -> list of function names (None for spare)
        self.uaps = {}
        self.order = []
        for m in re.finditer(r'if \(ed == value_(\d+)_(\d+)_(\d+) && uap == uap_\d+_\d+_\d+_(\w+)\)\n\s*\{\n'
                             r'\s*table->table_size = (\d+);\n.*?table->table_pointer = (\w+);', src, re.S):
            cat, major, minor, uap, size, table = m.groups()
            key = (int(cat), '%s.%s' % (major, minor), uap)
            self.uaps[key] = self.table(table)
            self.order.append(key)
        # default editions
        self.default_ed = {}
        self.default_re = {}
        for m in re.finditer(r'\{ (\d+), &value_\d+_(\d+)_(\d+)(_re)?_default, \w+, "\w+", "[^"]*", (true|false) \}', src):
            cat, major, minor, re_, basic = m.groups()
            (self.default_re if re_ else self.default_ed)[int(cat)] = '%s.%s' % (major, minor)
        # all editions of each category, in order
        self.editions = {}
        for (cat, ed, uap) in self.order:
            eds = self.editions.setdefault(cat, [])
            if ed not in eds:
                eds.append(ed)
        self.re_editions = {}
        self.re_tables = {}
        for m in re.finditer(r'if \(ed == value_(\d+)_(\d+)_(\d+)_re\)\n\s*\{\n\s*table->table_size = (\d+);\n'
                             r'\s*table->table_pointer = (\w+);', src):
            cat, major, minor, size, table = m.groups()
            ed = '%s.%s' % (major, minor)
            self.re_editions.setdefault(int(cat), []).append(ed)
            self.re_tables[(int(cat), ed)] = self.table(table)
        self.re_edition = dict(self.default_re)   # RE edition used to encode
        self.counter = 0

    def table(self, name):
        m = re.search(r'static const ttt %s\[\] = \{\n(.*?)\n\};' % name, self.src, re.S)
        out = []
        for line in m.group(1).splitlines():
            f = line.strip().lstrip('&').split(',')[0].split()[0]
            out.append(None if f == 'NULL' else f)
        return out

    # ------------------------------------------------------------------

    def pattern(self, n):
        out = bytearray()
        for _ in range(n):
            self.counter += 1
            out.append((self.counter * 73 + 41) & 0xff)
        return out

    @staticmethod
    def clear_spares(data, text):
        for k, n in re.findall(r'check_spare_bits \(tvb, \(offset \* 8\) \+ (\d+), (\d+),', text):
            for b in range(int(k), int(k) + int(n)):
                if b // 8 < len(data):
                    data[b // 8] &= ~(0x80 >> (b % 8)) & 0xff

    def fixed(self, body):
        lens = re.findall(r'return (\d+);', body)
        if not lens:
            raise ValueError('no length')
        data = self.pattern(int(lens[-1]))
        self.clear_spares(data, body)
        for k in re.findall(r'!asterix_extended_end\(tvb, offset \+ (\d+) - 1\)', body):
            data[int(k) - 1] &= 0xfe
        return bytes(data)

    def extended(self, body, all_parts=True):
        lines = body.splitlines()
        parts = []          # (length, text, fx_checked)
        text = []
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            m = re.match(r'if \((!?)asterix_extended_end\(tvb, offset[^)]*\)\)$', line)
            if m:
                neg = m.group(1) == '!'
                # find the next "offset+=K;" (inside the block for a
                # continuation, after the error block for the last part)
                j = i + 1
                while not re.match(r'offset\+=\d+;', lines[j].strip()):
                    j += 1
                k = int(re.match(r'offset\+=(\d+);', lines[j].strip()).group(1))
                parts.append((k, '\n'.join(text), True, not neg))
                text = []
                if neg:
                    break
                # skip to after the "offset+=K;" that follows the block
                j += 1
                while not re.match(r'offset\+=\d+;', lines[j].strip()):
                    j += 1
                i = j + 1
                continue
            if line == 'end:':
                break
            text.append(lines[i])
            i += 1
        if not all_parts:
            parts = parts[:1]
        out = bytearray()
        for n, (k, t, fx, more) in enumerate(parts):
            d = self.pattern(k)
            self.clear_spares(d, t)
            if n < len(parts) - 1:
                d[-1] |= 1
            else:
                d[-1] &= 0xfe
            out += d
        return bytes(out)

    def fspec(self, bits):
        """FSPEC octets with the given bit positions set (0 is the MSB of
        the first octet; bit 7 of each octet is FX and must not be given)."""
        if not bits:
            return b'\x00'
        n = max(bits) // 8 + 1
        fs = bytearray(n)
        for b in bits:
            assert b % 8 != 7, b
            fs[b // 8] |= 0x80 >> (b % 8)
        for i in range(n - 1):
            fs[i] |= 1
        return bytes(fs)

    def encode(self, name, cat=None):
        b = self.funcs[name]
        if 'asterix_fspec_check' in b:
            subs = re.findall(r'if \(asterix_field_exists \(tvb, offset_start, (\d+)\)\)\n  \{\n    int fun_len = (\w+)\(', b)
            bits, data = [], b''
            for bit, f in subs:
                bits.append(int(bit))
                data += self.encode(f, cat)
            return self.fspec(bits) + data
        m = re.search(r'asterix_parse_re_field \(tvb, offset, sub_tree, 1, (\d+)\)', b)
        if m:
            rcat = int(m.group(1))
            table = self.re_tables.get((rcat, self.re_edition.get(rcat)), [])
            bits, data = [], b''
            for i, f in enumerate(table[:7]):
                if f:
                    bits.append(i)
                    data += self.encode(f, rcat)
            fs = bytearray(self.fspec(bits)[:1])
            fs[0] &= 0xfe
            body = bytes(fs) + data
            return struct.pack('B', len(body) + 1) + body
        if 'unsigned int bytes = asterix_get_unsigned_value(tvb , offset, 1)' in b:
            return b'\x03' + bytes(self.pattern(2))
        if 'while (true)' in b:
            f = re.search(r'fun_len = (\w+)\(', b).group(1)
            e1 = bytearray(self.encode(f, cat))
            e2 = bytearray(self.encode(f, cat))
            e1[-1] |= 1
            e2[-1] &= 0xfe
            return bytes(e1 + e2)
        m = re.search(r'repetitive_length = asterix_get_unsigned_value\(tvb, offset, (\d)\)', b)
        if m:
            f = re.search(r'fun_len = (\w+)\(', b).group(1)
            n = int(m.group(1))
            return (2).to_bytes(n, 'big') + self.encode(f, cat) + self.encode(f, cat)
        if 'unsigned len = tvb_get_uint8(tvb, offset);' in b:
            # explicit item that is skipped (length octet includes itself)
            return b'\x03' + bytes(self.pattern(2))
        if 'goto end' in b or not re.search(r'return \d+;', b):
            return self.extended(b)
        return self.fixed(b)

    def record(self, key, frns=None):
        """A record of the UAP with every item (or the given FRNs, 1-based)."""
        table = self.uaps[key]
        bits, data = [], b''
        for i, f in enumerate(table):
            if f is None or (frns is not None and i + 1 not in frns):
                continue
            bits.append(i + i // 7)
            data += self.encode(f, key[0])
        return self.fspec(bits) + data


def datablock(cat, records):
    body = b''.join(records)
    return struct.pack('>BH', cat, 3 + len(body)) + body

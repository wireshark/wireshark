#!/usr/bin/env python3
# Generates the rbm captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic Ruby Marshal (RBM) coverage files for file-rbm.c.

usage: mkrbm.py <outdir> [-v]
rbm-coverage-nesting.rbm (main: every type the dissector decodes, the
integers of every length form, nesting of 60 levels, a hash key whose
inline dump has an unsupported version, a struct with a 2 octet name
length) and the malformed files (nesting limit of 64, bad types). The
objects follow what file-rbm.c reads; see the README. Ruby Marshal files
are read by the Ruby Marshal file reader (the 04 08 header), there is no
port or media type. Everything here is generated.
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def w(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    if VERBOSE:
        print(name, len(data))


# ---- Ruby Marshal encoding (w_long in Ruby's marshal.c)
def w_long(v):
    if v == 0:
        return b'\0'
    if 0 < v < 123:
        return bytes([v + 5])
    if -124 < v < 0:
        return struct.pack('b', v - 5)
    out = b''
    x = v
    for i in range(1, 5):
        out += bytes([x & 0xff])
        x >>= 8
        if v >= 0 and x == 0:
            return bytes([i]) + out
        if v < 0 and x == -1:
            return struct.pack('b', -i) + out
    raise ValueError(v)


def raw_int(c, data=b''):
    """An integer with an explicit type octet c and data octets."""
    return b'i' + struct.pack('b', c) + data


def i(v):
    return b'i' + w_long(v)


NIL, TRUE, FALSE = b'0', b'T', b'F'


def sym(s):
    return b':' + w_long(len(s)) + s.encode()


def symlink(n):
    return b';' + w_long(n)


def objlink(n):
    return b'@' + w_long(n)


def string(s, enc=TRUE):
    """A String with one instance variable (the encoding), as file-rbm.c
    reads it; wrapped in I as Ruby writes it."""
    b = s.encode()
    return b'I"' + w_long(len(b)) + b + w_long(1) + sym('E') + enc


def bare_string(s):
    """The string part on its own (the '"' type)."""
    b = s.encode()
    return b'"' + w_long(len(b)) + b + w_long(1) + symlink(0) + FALSE


def array(*items):
    return b'[' + w_long(len(items)) + b''.join(items)


def hash_(*pairs):
    return b'{' + w_long(len(pairs)) + b''.join(k + v for k, v in pairs)


def flt(s):
    return b'f' + w_long(len(s)) + s.encode()


def klass(s):
    return b'c' + w_long(len(s)) + s.encode()


def module(s):
    return b'm' + w_long(len(s)) + s.encode()


def regex(s, opts=1):
    b = s.encode()
    return b'I/' + w_long(len(b)) + b + bytes([opts]) + w_long(1) + sym('E') + FALSE


def struct_(name, *pairs):
    return b'S:' + w_long(len(name)) + name.encode() + w_long(len(pairs)) + b''.join(k + v for k, v in pairs)


def userclass(obj):
    return b'C' + obj


def extended(obj):
    return b'e' + obj


def drbobject(a, b):
    return b'u' + a + b


def inline(obj, version=b'\x04\x08'):
    return b',' + version + obj


def rubyobject(cls, *ivars):
    """Ruby object: class symbol and instance variables. file-rbm.c
    reads all objects up to the end of the data, so it must come last."""
    return b'o' + sym(cls) + w_long(len(ivars)) + b''.join(k + v for k, v in ivars)


def dump(obj, version=b'\x04\x08'):
    return version + obj


def dump(obj, version=b'\x04\x08'):
    return version + obj


# Integers of every length form: (type octet, data, value)
INTS = [
    (0x00, b'', 0),
    (0x06, b'', 1),
    (0x7f, b'', 122),
    (0xfa, b'', -1),               # c == -6: left uninitialised before the fix
    (0x80, b'', -123),
    (0x01, b'\xff', 255),
    (0x02, b'\x34\x12', 0x1234),
    (0x03, b'\x56\x34\x12', 0x123456),
    (0x04, b'\x78\x56\x34\x12', 0x12345678),   # decoded as -1 before the fix
    (0x04, b'\xff\xff\xff\x7f', 0x7fffffff),
    (0xff, b'\x00', -256),
    (0xfe, b'\xcc\xed', -0x1234),
    (0xfd, b'\xaa\xbb\xcc', -0x334456),
    (0xfc, b'\x00\x00\x00\x80', -0x80000000),
    (0xfb, b'', 0),                 # c == -5: decoded as 5 data octets before the fix
]


def int_args():
    return [raw_int(struct.unpack('b', bytes([c]))[0], d) for c, d, _ in INTS]


def every_type():
    """One of each type file-rbm.c decodes (except the Ruby object)."""
    return [
        NIL, TRUE, FALSE, i(42), sym('name'), symlink(0), string('text'),
        bare_string('bare'), array(i(1), array(i(2), NIL), string('x')),
        hash_((sym('a'), i(1)), (string('b'), array())),
        hash_(), objlink(1), flt('1.5'), flt('-0.25'), klass('Integer'),
        module('Comparable'), regex('^a.*z$'),
        struct_('Point', (sym('x'), i(1)), (sym('y'), i(-2))),
        userclass(string('subclassed')), extended(module('Mod')),
        drbobject(sym('DRb::DRbObject'), i(7)), inline(i(99)),
        array(raw_int(-6), NIL),     # array with a -1 element count
    ]



def int_args():
    return [raw_int(struct.unpack('b', bytes([c]))[0], d) for c, d, _ in INTS]


def every_type():
    """One of each type file-rbm.c decodes (except the Ruby object)."""
    return [
        NIL, TRUE, FALSE, i(42), sym('name'), symlink(0), string('text'),
        bare_string('bare'), array(i(1), array(i(2), NIL), string('x')),
        hash_((sym('a'), i(1)), (string('b'), array())),
        hash_(), objlink(1), flt('1.5'), flt('-0.25'), klass('Integer'),
        module('Comparable'), regex('^a.*z$'),
        struct_('Point', (sym('x'), i(1)), (sym('y'), i(-2))),
        userclass(string('subclassed')), extended(module('Mod')),
        drbobject(sym('DRb::DRbObject'), i(7)), inline(i(99)),
        array(raw_int(-6), NIL),     # array with a -1 element count
    ]


def nested(n, leaf=NIL):
    """n arrays of one element inside each other."""
    return b'[\x06' * n + leaf


# the fixes of "RBM: Bound object nesting and fix NULL strings and struct names"
fixes = [
    nested(60),                                             # below the nesting limit of 64
    hash_((inline(b'', b'\x05\x05'), NIL)),                  # key with an unsupported version
    hash_((sym('k'), inline(b'', b'\x03\x00'))),             # value with an unsupported version
    struct_('N' * 200, (sym('x'), i(1))),                   # name length in 1 octet (data octet follows)
    struct_('M' * 300, (sym('x'), i(1))),                   # name length in 2 octets
]

main = dump(array(*(every_type() + int_args() + fixes
                    + [rubyobject('Foo', (sym('@a'), i(1)))])))
w('rbm-coverage-nesting.rbm', main)

# one file per nesting depth around the limit
for n in (63, 65, 70):
    w('rbm-coverage-depth%d.rbm' % n, dump(nested(n)))
# the reproducer of the review had 5000 nested arrays (the limit stops at 64;
# the dissection depth limit of 500 is the backstop)
w('rbm-coverage-deep300.rbm', dump(nested(300)))
# the committed one: 64 arrays, one level more than the limit allows
w('rbm-coverage-deep.rbm', dump(nested(64)))
# the limit reached inside an inline dump (the nested object returns the type of
# the inline dump through its output arguments)
w('rbm-coverage-deep-inline.rbm', dump(nested(63, inline(NIL))))
# nesting through the other containers: hash values, struct members, DRb
# objects, user classes, extended objects, instance variables
mixed = NIL
for k in range(70):
    mixed = [array(mixed), hash_((sym('k'), mixed)), userclass(mixed),
             extended(mixed), b'I' + mixed + w_long(0), drbobject(NIL, mixed),
             struct_('S', (sym('m'), mixed))][k % 7]
w('rbm-coverage-mixed.rbm', dump(mixed))

bad = []
bad.append(('type', dump(array(i(1), b'd:\x06X'))))             # unknown type
bad.append(('bignum', dump(b'l+\x06\x01\x00\x00\x00\x00\x00\x00\x00')))
bad.append(('hash-default', dump(b'}\x00i\x06')))
bad.append(('version', b'\x04\x07' + NIL))                    # unsupported version
bad.append(('version2', b'\x03\x00' + NIL))
bad.append(('inline-version', dump(array(inline(i(1), b'\x03\x00')))))
bad.append(('struct-neg', dump(b'o:\x00\x00' + b'S:\xf7' + b'\x00' * 8)))   # name length -4
bad.append(('struct-noname', dump(b'Si\x06' + w_long(0))))
bad.append(('cut', dump(array(i(1), string('cut')))[:-4]))
bad.append(('string-len', dump(b'"' + w_long(100) + b'abc')))
bad.append(('array-neg', dump(b'[\xfa' + NIL * 16)))
bad.append(('ruby-trailing', dump(rubyobject('Foo', (sym('@a'), i(1))) + b'd')))
for n_, d in bad:
    w('rbm-bad-%s.rbm' % n_, d)

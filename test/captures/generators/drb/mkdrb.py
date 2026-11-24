#!/usr/bin/env python3
# Generates test/captures/drb_coverage.pcap.gz, rbm_coverage.rbm.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DRb dissector
(packet-drb.c, Distributed Ruby) and the Ruby Marshal dissector it uses
(file-rbm.c).

A DRb message is a sequence of Ruby Marshal dumps, each preceded by a
32 bit big endian length: a request holds the receiver reference, the
message name, the argument count, the arguments and the block; a reply
holds the success flag and the result. Each dump starts with the
Marshal version 4.8. DRb has no default port (it is registered for
Decode As on tcp.port); these captures use TCP port 8787, so dissect
them with "-d tcp.port==8787,drb".

The objects follow what file-rbm.c expects. Where that differs from
what Ruby writes, the README says so. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkdrb.py <output directory>

Writes:
  drb-coverage.pcap            DRb requests and replies carrying every
                               Marshal type file-rbm.c decodes, and
                               integers of every length form
  drb-coverage-malformed.pcap  the reproducer of the fix, unknown types,
                               an unsupported version, short messages
  rbm-coverage.rbm             a Ruby Marshal file (read by the Ruby
                               Marshal file reader, no Decode As)
  rbm-coverage-malformed.rbm   a Ruby Marshal file with an invalid type
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import TcpConn, pcap

PORT = 8787


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


def elem(obj, version=b'\x04\x08'):
    d = dump(obj, version)
    return struct.pack('!I', len(d)) + d


def request(ref, msg, args, block=NIL):
    return elem(ref) + elem(string(msg)) + elem(i(len(args))) + \
        b''.join(elem(a) for a in args) + elem(block)


def reply(ok, result):
    return elem(TRUE if ok else FALSE) + elem(result)


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


def main_frames():
    f = []
    c = TcpConn(41000, PORT)
    # 1-2: a call greet("world", 3) with a nil block, and its reply
    f.append(c.send(request(NIL, 'greet', [string('world'), i(3)])))
    f.append(c.send(reply(True, string('hello world')), True))
    # 3-4: a call with an integer of every length form, reply true
    f.append(c.send(request(NIL, 'sum', int_args())))
    f.append(c.send(reply(True, raw_int(4, b'\x78\x56\x34\x12')), True))
    # 5-6: a call with every other type and a reply with a hash
    f.append(c.send(request(drbobject(sym('DRb::DRbObject'), i(1)), 'store', every_type())))
    f.append(c.send(reply(True, hash_((sym('ok'), TRUE), (sym('n'), i(23)))), True))
    # 7-8: a call with no arguments and a Ruby object as the block, and
    # an exception reply (false) with a Ruby object as the result
    f.append(c.send(request(NIL, 'each', [], rubyobject('Proc', (sym('@id'), i(5))))))
    f.append(c.send(reply(False, rubyobject('NameError', (sym('mesg'), string('undefined method')),
                                            (sym('bt'), array(string('x.rb:1')))) + NIL), True))
    # 9-10: a call whose argument is an array with element count -1 (the
    # type octet 0xfa of the reproducer, decoded as -1), and its reply
    f.append(c.send(request(NIL, 'neg', [b'[\xfa'])))
    f.append(c.send(reply(True, NIL), True))
    return f


def malformed_frames():
    f = []
    c = TcpConn(41001, PORT)
    # 1: the reproducer (drb_rbm_uninit.py): an array with
    # the count octet 0xfa followed by '0' octets
    obj = b'\x04\x08' + b'[' + b'\xfa' + b'0' * 16
    f.append(c.send(struct.pack('!I', len(obj)) + obj))
    # 2-4: unknown types: bignum, hash with default, user marshal
    for t in (b'l+\x06\x01\x00\x00\x00\x00\x00\x00\x00', b'}\x00i\x06', b'U:\x06Ai\x06'):
        f.append(c.send(request(NIL, 'm', [t])))
    # 5: an unsupported Marshal version
    f.append(c.send(elem(NIL) + elem(string('m')) + elem(i(1)) + elem(i(1), b'\x04\x07') + elem(NIL)))
    # 6: a nested (inline) dump with an unsupported version
    f.append(c.send(request(NIL, 'm', [inline(i(1), b'\x03\x00')])))
    # 7: a reply cut short
    f.append(c.send(reply(True, string('cut'))[:-4], True))
    # 8: a string length past the end
    f.append(c.send(request(NIL, 'm', [b'"' + w_long(100) + b'abc'])))
    # 9: deeply nested arrays
    f.append(c.send(request(NIL, 'm', [b'[\x06' * 200 + NIL])))
    # 10: a struct without its name symbol
    f.append(c.send(request(NIL, 'm', [b'Si\x06' + w_long(0)])))
    return f


def rbm_file():
    return dump(array(*(every_type() + int_args() + [rubyobject('Foo', (sym('@a'), i(1)))])))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'drb-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'drb-coverage-malformed.pcap'), malformed_frames())
    with open(os.path.join(out, 'rbm-coverage.rbm'), 'wb') as fh:
        fh.write(rbm_file())
    with open(os.path.join(out, 'rbm-coverage-malformed.rbm'), 'wb') as fh:
        fh.write(dump(array(i(1), b'd:\x06X')))

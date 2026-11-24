#!/usr/bin/env python3
# Generates test/captures/kt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Kyoto Tycoon (KT) binary protocol captures.
Usage: mkkt.py <outdir>.  Writes kt-coverage.pcap and kt-coverage-malformed.pcap."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

C, S = '192.0.2.10', '192.0.2.20'
u32 = lambda v: struct.pack('!I', v & 0xffffffff)
u16 = lambda v: struct.pack('!H', v)
u64 = lambda v: struct.pack('!Q', v)

# ---- messages -------------------------------------------------------------
def repl_wait(ts=1700000000 * 10**9 + 123456789): return b'\xb0' + u64(ts)
def repl_req(flags=0, ts=1700000000 * 10**9, sid=7): return b'\xb1' + u32(flags) + u64(ts) + u16(sid)
def repl_resp(log=b'log-record', ts=1700000001 * 10**9 + 5, size=None):
    return b'\xb1' + u64(ts) + u32(len(log) if size is None else size) + log
def repl_ack(): return b'\xb1'
def play_req(name=b'echo', recs=((b'key1', b'val1'),), rnum=None, flags=0):
    b = b'\xb4' + u32(flags) + u32(len(name)) + u32(len(recs) if rnum is None else rnum) + name
    for k, v in recs:
        b += u32(len(k)) + u32(len(v)) + k + v
    return b
def play_resp(recs=((b'key1', b'val1'),), hits=None):
    b = b'\xb4' + u32(len(recs) if hits is None else hits)
    for k, v in recs:
        b += u32(len(k)) + u32(len(v)) + k + v
    return b
def set_req(recs=((0, b'k', b'v', 3600),), rnum=None, flags=0):
    b = b'\xb8' + u32(flags) + u32(len(recs) if rnum is None else rnum)
    for db, k, v, xt in recs:
        b += u16(db) + u32(len(k)) + u32(len(v)) + u64(xt) + k + v
    return b
def set_resp(hits=1): return b'\xb8' + u32(hits)
def rm_req(recs=((0, b'k'),), rnum=None, flags=0):
    b = b'\xb9' + u32(flags) + u32(len(recs) if rnum is None else rnum)
    for db, k in recs:
        b += u16(db) + u32(len(k)) + k
    return b
def rm_resp(hits=1): return b'\xb9' + u32(hits)
def get_req(recs=((0, b'k'),), rnum=None, flags=0):
    b = b'\xba' + u32(flags) + u32(len(recs) if rnum is None else rnum)
    for db, k in recs:
        b += u16(db) + u32(len(k)) + k
    return b
def get_resp(recs=((0, b'k', b'v', 1700000000),), hits=None):
    b = b'\xba' + u32(len(recs) if hits is None else hits)
    for db, k, v, xt in recs:
        b += u16(db) + u32(len(k)) + u32(len(v)) + u64(xt) + k + v
    return b
def get_none(): return b'\xba' + u32(0)
def err(): return b'\xbf'

def mk_main(path):
    p = Pcap()
    def conv(port, sport, exchanges):
        p.tcp(C, S, sport, port, b'', flags=0x02)
        p.tcp(S, C, port, sport, b'', flags=0x12)
        p.tcp(C, S, sport, port, b'', flags=0x10)
        for direction, data in exchanges:
            if direction == '>':
                p.tcp(C, S, sport, port, data)
            else:
                p.tcp(S, C, port, sport, data)
        p.tcp(C, S, sport, port, b'', flags=0x11)
        p.tcp(S, C, port, sport, b'', flags=0x11)
    binkey = bytes([0, 1, 2, 0xff, 0x80]) * 2
    conv(1978, 50000, [
        ('>', set_req(((0, b'alpha', b'one', 3600), (1, b'beta', b'', 0), (0, b'', b'v', 1)))),
        ('<', set_resp(3)),
        ('>', get_req(((0, b'alpha'), (1, b'beta'), (0, b'nokey')))),
        ('<', get_resp(((0, b'alpha', b'one', 1700003600), (1, b'beta', b'', 0)))),
        ('>', get_req(((0, b'gone'),))),
        ('<', get_none()),
        ('>', rm_req(((0, b'alpha'), (1, b'beta')))),
        ('<', rm_resp(2)),
        ('>', rm_req(((0, b'alpha'),))),
        ('<', rm_resp(0)),
        ('>', play_req(b'incrementer', ((b'num', b'5'), (b'bin', binkey)))),
        ('<', play_resp(((b'num', b'6'), (b'bin', binkey)))),
        ('>', play_req(b'noop', ())),
        ('<', b'\xb4' + u32(0)),                       # response without records
        ('>', play_req(b'',  ((b'k', b'v'),))),
        ('<', err()),
        ('>', repl_wait()),
        ('<', repl_ack()),
        ('>', repl_req()),
        ('<', repl_resp(b'\x01\x02\x03' * 10)),
        ('>', repl_req(flags=1, sid=0x1234)),
        ('<', repl_resp(b'')),
        ('<', repl_wait(5 * 10**9 + 1)),
    ])
    # Several messages in one segment (a request is followed by the next one)
    conv(1979, 50001, [
        ('<', err() + get_none()),
        ('>', get_req(((0, b'k1'),)) + get_req(((0, b'k2'),))),
        ('<', get_resp(((0, b'k1', b'v1', 1), (2, b'k2', b'v2', 2))) + set_resp(0)),
        ('>', set_req(((3, b'a', b'b', 9),)) + rm_req(((3, b'a'),)) + play_req(b'p', ((b'x', b'y'),))),
        ('<', rm_resp(1)),
        ('>', repl_wait() + repl_wait(1)),
        ('<', repl_ack()),
        # unknown magic after a known message: the rest is not dissected
        ('>', err() + b'\x00junk'),
        ('<', err() * 3),
    ])
    p.write(path)

def mk_mal(path):
    p = Pcap()
    n = [0]
    def t(data, port=1978):
        n[0] += 1
        p.tcp(C, S, 51000 + n[0], port, data)
    # the fixed bug: sizes of 0xFFFFFFFF (reproducer of kt_negsize_blowup.py, 65000 octets as there)
    t(b'\xb4' + b'\xff' * 64999)
    t(b'\xb4' + b'\xff' * 100)
    # every sized field larger than the data
    t(play_req(b'x', ((b'k', b'v'),))[:-1])
    t(play_req(b'x' * 100, ())[:20])
    t(b'\xb4' + u32(0) + u32(0xffffffff) + u32(0))           # name size past the end
    t(b'\xb4' + u32(0) + u32(2) + u32(1) + b'ab' + u32(0xffffff) + u32(1) + b'k')   # key
    t(b'\xb4' + u32(0) + u32(2) + u32(1) + b'ab' + u32(1) + u32(0xffffff) + b'kv')  # value
    t(b'\xb4' + u32(1) + u32(0xffffffff) + u32(2) + b'k')    # response: key size
    t(b'\xb4' + u32(1) + u32(1) + u32(0xffffffff) + b'kv')   # response: value size
    t(set_req(((0, b'k', b'v', 1),))[:-1])
    t(b'\xb8' + u32(0) + u32(1) + u16(0) + u32(0xffffffff) + u32(1) + u64(0) + b'kv')
    t(b'\xb8' + u32(0) + u32(1) + u16(0) + u32(1) + u32(0xffffffff) + u64(0) + b'kv')
    t(rm_req(((0, b'key'),))[:-1])
    t(b'\xb9' + u32(0) + u32(1) + u16(0) + u32(0x7fffffff) + b'k')
    t(get_req(((0, b'key'),))[:-1])
    t(b'\xba' + u32(0) + u32(1) + u16(0) + u32(0xffffffff) + b'k')
    t(get_resp(((0, b'key', b'value', 1),))[:-1])
    t(b'\xba' + u32(1) + u16(0) + u32(0xffffffff) + u32(1) + u64(0) + b'kv')
    t(b'\xba' + u32(1) + u16(0) + u32(1) + u32(0xffffffff) + u64(0) + b'kv')
    t(repl_resp(b'abc', size=3000))
    t(repl_resp(b'abc', size=0xffffffff))
    # record counts past the data, fields cut short
    t(set_req(((0, b'k', b'v', 1),), rnum=2))
    t(rm_req(((0, b'k'),), rnum=0xffffffff))
    t(get_req(((0, b'k'),), rnum=5))
    t(play_req(b'n', ((b'k', b'v'),), rnum=3))
    t(get_resp(((0, b'k', b'v', 1),), hits=4))
    t(play_resp(((b'k', b'v'),), hits=0x10000))
    t(b'\xb4\x00\x00')
    t(b'\xb0\x00\x00\x00')
    t(b'\xb1\x00\x00\x00\x01')
    t(b'\xb1\x00\x00\x00\x00\x00\x00\x00\x01')
    t(b'\xb8\x00')
    t(b'\xba\x00\x00\x00\x00\x00\x00\x00')
    t(b'\xb9\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00')
    # not KT: unknown first octet
    t(b'\x00\x01\x02')
    t(b'\xb2' + b'\0' * 8)
    p.write(path)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mk_main(os.path.join(out, 'kt-coverage.pcap'))
    mk_mal(os.path.join(out, 'kt-coverage-malformed.pcap'))

#!/usr/bin/env python3
# Generates test/captures/etch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Etch-over-TCP captures. Usage: mketch.py <outdir>
# Everything is built with struct; nothing comes from a real network.
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

CLI = bytes([192, 0, 2, 1]); SRV = bytes([192, 0, 2, 2])
MAC_C = bytes.fromhex('020000000001'); MAC_S = bytes.fromhex('020000000002')

class Cap:
    def __init__(self):
        self.pkts = []
    def add(self, p):
        self.pkts.append(p)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
                f.write(p)

class Stream:
    """One TCP connection, client port cport -> server port sport."""
    def __init__(self, cap, cport, sport=4001, handshake=True):
        self.cap = cap; self.cport = cport; self.sport = sport
        self.cseq = 1000; self.sseq = 5000; self.ipid = 1
        if handshake:
            self.raw(True, b'', 0x02); self.cseq += 1
            self.raw(False, b'', 0x12); self.sseq += 1
            self.raw(True, b'', 0x10)
    def raw(self, c2s, payload, flags):
        if c2s:
            src, dst, sp, dp, seq, ack = CLI, SRV, self.cport, self.sport, self.cseq, self.sseq
            em = MAC_S + MAC_C
        else:
            src, dst, sp, dp, seq, ack = SRV, CLI, self.sport, self.cport, self.sseq, self.cseq
            em = MAC_C + MAC_S
        if flags == 0x02:
            ack = 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.cap.add(em + b'\x08\x00' + ip + tcp + payload)
    def send(self, c2s, payload):
        self.raw(c2s, payload, 0x18)
        if c2s:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)
    def ack(self, c2s):
        self.raw(c2s, b'', 0x10)

# ---- Etch encoders ----
def tiny(n):
    assert -64 <= n <= 127
    return bytes([n & 0xff])
def byte(n): return b'\x84' + struct.pack('!b', n)
def short(n): return b'\x85' + struct.pack('!h', n)
def int_(n): return b'\x86' + struct.pack('!i', n)
def hint(h): return b'\x86' + struct.pack('!I', h)
def long_(n): return b'\x87' + struct.pack('!q', n)
def float_(f): return b'\x88' + struct.pack('!f', f)
def double(f): return b'\x89' + struct.pack('!d', f)
NULL = b'\x80'; NONE = b'\x81'; FALSE = b'\x82'; TRUE = b'\x83'
EMPTY = b'\x92'
def ln(n, kind='t'):
    if kind == 't': return tiny(n)
    if kind == 'b': return b'\x84' + struct.pack('!B', n)
    if kind == 's': return b'\x85' + struct.pack('!H', n)
    return b'\x86' + struct.pack('!I', n)
def bytes_(d, kind='t'): return b'\x8b' + ln(len(d), kind) + d
def string(s, kind='t'):
    s = s.encode(); return b'\x93' + ln(len(s), kind) + s
def array(elemtype, items, dim=1, kind='t', custom_hash=None):
    et = elemtype if elemtype != 0x95 else b'\x95\x86' + struct.pack('!I', custom_hash)
    if isinstance(et, int): et = bytes([et])
    return b'\x91' + et + bytes([dim]) + ln(len(items), kind) + b''.join(items) + NONE
def struct_(h, kvs, kind='t', hashval=None):
    # custom struct value: 0x95 hash count kv... end
    hv = hashval if hashval is not None else hint(h)
    return b'\x95' + hv + ln(len(kvs), kind) + b''.join(k + v for k, v in kvs) + NONE
def msg_body(h, kvs, kind='t', hashval=None):
    hv = hashval if hashval is not None else hint(h)
    return hv + ln(len(kvs), kind) + b''.join(k + v for k, v in kvs) + NONE
def etch(body, ver=1):
    m = bytes([ver]) + body
    return b'\xde\xad\xbe\xef' + struct.pack('!I', len(m)) + m
def pdu(h, kvs, **kw): return etch(msg_body(h, kvs, **kw))

# message type / key hashes (also in the symbol file for runcov)
H_ADD, H_ADD_RESULT, H_NOTIFY = 0x11223344, 0x55667788, 0x99aabbcc
K_X, K_Y, K_RESULT, K_MSGID = 0x01020304, 0x05060708, 0x0a0b0c0d, 0x0e0f1011
def k(h): return hint(h)

main = Cap()
# --- Stream 1: ordinary calls and results ---
s = Stream(main, 40001)
# 1 simple call, hash type, keys INT hashes, tiny values
s.send(True, pdu(H_ADD, [(k(K_X), tiny(5)), (k(K_Y), tiny(-3))])); s.ack(False)
s.send(False, pdu(H_ADD_RESULT, [(k(K_RESULT), tiny(2)), (k(K_MSGID), long_(1))])); s.ack(True)
# all scalar types, with a struct count encoded as tiny/byte/short/int
allv = [(k(K_X), NULL), (k(K_X), NONE), (k(K_X), FALSE), (k(K_X), TRUE),
        (k(K_X), byte(-7)), (k(K_X), short(-300)), (k(K_X), int_(70000)),
        (k(K_X), long_(-5000000000)), (k(K_X), float_(1.5)), (k(K_X), double(-2.25)),
        (k(K_X), EMPTY), (k(K_X), tiny(127)), (k(K_X), tiny(0)), (k(K_X), tiny(-64)),
        (k(K_X), tiny(-1)), (k(K_X), b'\x94'), (k(K_X), b'\x96'), (k(K_X), b'\x8a'),
        (k(K_X), b'\xa0')]
s.send(True, pdu(H_NOTIFY, allv)); s.ack(False)
# fixed bug: field count encoded as BYTE, SHORT and INT
two = [(k(K_X), tiny(1)), (k(K_Y), tiny(2))]
for kind in 'bsi':
    s.send(True, pdu(H_NOTIFY, two, kind=kind)); s.ack(False)
# strings and bytes with all length encodings
s.send(True, pdu(H_NOTIFY, [(k(K_X), string('hello')), (k(K_X), string('x' * 130, 'b')),
                            (k(K_X), string('y' * 300, 's')), (k(K_X), string('zz', 'i')),
                            (k(K_X), bytes_(b'\x01\x02\x03')), (k(K_X), bytes_(b'\xff' * 140, 'b')),
                            (k(K_X), bytes_(b'', 's')), (k(K_X), bytes_(b'ab', 'i')),
                            (k(K_X), string(''))])); s.ack(False)
# string-keyed entries and arrays
s.send(True, pdu(H_NOTIFY, [(string('name'), string('value')),
        (k(K_Y), array(0x86, [int_(1), int_(2), int_(3)])),
        (k(K_Y), array(0x84, [], dim=2)),
        (k(K_Y), array(0x93, [string('a'), string('b')], dim=1, kind='b')),
        (k(K_Y), array(0x95, [struct_(0x77, [(k(K_X), tiny(1))])], custom_hash=0x1234abcd, kind='s')),
        (k(K_Y), array(0x91, [array(0x86, [tiny(1)])], dim=2, kind='i'))])); s.ack(False)
# nested structs (custom)
inner = struct_(0x77, [(k(K_X), tiny(9)), (k(K_Y), struct_(0x78, [(k(K_X), string('deep'))]))])
s.send(False, pdu(H_ADD_RESULT, [(k(K_RESULT), inner), (k(K_MSGID), long_(2))])); s.ack(True)
# empty struct, version 2, struct type given as tiny value
s.send(True, etch(msg_body(H_NOTIFY, []), ver=2)); s.ack(False)
s.send(True, etch(msg_body(0, [(k(K_X), tiny(1))], hashval=tiny(7)))); s.ack(False)
# message type not an INT (string): no Info symbol lookup
s.send(True, etch(msg_body(0, [(k(K_X), tiny(1))], hashval=string('Add')))); s.ack(False)
# message type as BYTE
s.send(True, etch(msg_body(0, [], hashval=byte(3)))); s.ack(False)

# --- Stream 2: two PDUs in one segment, reassembly ---
s2 = Stream(main, 40002)
a = pdu(H_ADD, [(k(K_X), tiny(1))]); b = pdu(H_ADD_RESULT, [(k(K_RESULT), tiny(2))])
s2.send(True, a + b); s2.ack(False)
# three PDUs in one segment
s2.send(True, a + b + a); s2.ack(False)
# PDU split over two segments
big = pdu(H_NOTIFY, [(k(K_X), string('q' * 100)), (k(K_Y), tiny(4))])
s2.send(True, big[:40]); s2.send(True, big[40:]); s2.ack(False)
# header split: 3 bytes, then rest
s2.send(False, big[:3]); s2.send(False, big[3:]); s2.ack(True)
# 6 bytes, then the rest (header incomplete: length unknown)
s2.send(True, big[:6]); s2.send(True, big[6:]); s2.ack(False)
# PDU followed by the start of the next one, then the rest of it
s2.send(True, a + big[:20]); s2.send(True, big[20:70]); s2.send(True, big[70:] + b); s2.ack(False)
# one PDU spread over three segments
s2.send(True, big[:12]); s2.send(True, big[12:50]); s2.send(True, big[50:]); s2.ack(False)

# --- Stream 3: non-Etch data is not claimed, then Etch on the same port ---
s3 = Stream(main, 40003)
s3.send(True, b'\x00\x01\x02binary junk\x03'); s3.ack(False)
s3.send(True, b'\xde\xad'); s3.ack(False)                    # shorter than the magic
s3.send(True, b'\xde\xad\xbe\xee\x00\x00\x00\x01\x01'); s3.ack(False)  # wrong magic
# --- Stream 4: Etch on another port, FIN close ---
s4 = Stream(main, 40004, sport=9999)
s4.send(True, pdu(H_ADD, [(k(K_X), tiny(1))])); s4.ack(False)
s4.send(False, pdu(H_ADD_RESULT, [(k(K_RESULT), tiny(1))])); s4.ack(True)
s4.raw(True, b'', 0x11); s4.cseq += 1
s4.raw(False, b'', 0x11); s4.sseq += 1
s4.raw(True, b'', 0x10)

# ---- malformed capture ----
mal = Cap()
m = Stream(mal, 41001)
def mk(body, ver=1): return etch(body, ver)
HD = hint(H_ADD)
# 1 negative tiny count of struct (expert, length 0)
m.send(True, mk(HD + tiny(-5) + NONE)); m.ack(False)
# 2 BYTES with negative tiny length
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x8b' + tiny(-2) + NONE + NONE)); m.ack(False)
# 3 string length coded with a type that is not 1/2/4 bytes (LONG, ARRAY)
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x93\x87' + b'\x00' * 8 + NONE)); m.ack(False)
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x93\x91\x00\x00\x00' + NONE)); m.ack(False)
# 4 struct count coded as LONG
m.send(True, mk(HD + b'\x87' + b'\x00' * 8 + NONE)); m.ack(False)
# 5 huge counts: BYTES 0x80000000, STRING 0xFFFFFF00, array 0x7fffffff
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x8b\x86\x80\x00\x00\x00AAAA' + NONE)); m.ack(False)
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x93\x86\xff\xff\xff\x00AAAA' + NONE)); m.ack(False)
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x91\x86\x01\x86\x7f\xff\xff\xff' + b'\x01' * 200 + NONE)); m.ack(False)
m.send(True, mk(HD + tiny(1) + k(K_X) + b'\x93\x86\xff\xff\xff\xffAAAA' + NONE)); m.ack(False)
m.send(True, mk(HD + b'\x86\xff\xff\xff\xf8' + NONE)); m.ack(False)
# 6 struct with a count but no fields (truncated)
m.send(True, mk(HD + tiny(100))); m.ack(False)
# 7 deep nesting (recursion bound)
n = 3000
body = HD + tiny(1)
for _ in range(n):
    body += k(K_X) + b'\x95' + tiny(1) + tiny(1)
body += k(K_X) + tiny(5) + NONE * (n + 1)
m.send(True, mk(body)); m.ack(False)
# 8 length 0xFFFFFFF8 (wraps), then 0xFFFFFFFF
m.send(True, b'\xde\xad\xbe\xef\xff\xff\xff\xf8\x01' + HD + tiny(1) + k(K_X) + tiny(1) + NONE); m.ack(False)
m.send(True, b'\xde\xad\xbe\xef\xff\xff\xff\xff\x01' + HD + tiny(1) + k(K_X) + tiny(1) + NONE); m.ack(False)
# 9 version only (length 1), header only
m.send(True, b'\xde\xad\xbe\xef\x00\x00\x00\x01\x01'); m.ack(False)
m2 = Stream(mal, 41002)
m2.send(True, b'\xde\xad\xbe\xef\x00\x00\x00\x00'); m2.ack(False)
m2.send(True, b'\xde\xad\xbe\xef\x00\x00\x00\x02\x01\x86'); m2.ack(False)
# 10 array with truncated values, custom array type with truncated hash
m2.send(True, mk(HD + tiny(1) + k(K_X) + b'\x91\x95\x86\x00\x00')); m2.ack(False)
m2.send(True, mk(HD + tiny(1) + k(K_X) + b'\x91\x86\x01\x05' + tiny(1))); m2.ack(False)
# 11 truncated number
m2.send(True, mk(HD + tiny(1) + k(K_X) + b'\x89\x00\x00')); m2.ack(False)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
main.write(os.path.join(out, 'etch-coverage.pcap'))
mal.write(os.path.join(out, 'etch-coverage-malformed.pcap'))
print(len(main.pkts), len(mal.pkts))

#!/usr/bin/env python3
# Generates test/captures/monero_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Monero coverage captures: mkmonero.py <outdir> [-v]

Levin protocol messages (header + portable storage payload) over TCP
port 18080, reached through the Monero heuristic (the Levin signature);
a second connection on port 28080 is reached by the conversation set by
the heuristic. Synthetic: addresses 192.0.2.0/24, made-up hashes.
"""
import os
import struct
import sys

SIG = bytes.fromhex('0121010101010101')       # little endian 0x0101010101012101
# The dissector skips the 9 magic octets (two signatures and the version)
MAGIC = bytes.fromhex('0111010101010201') + b'\x01'

def varint(n, size=None):
    if size is None:
        size = 1 if n < 64 else 2 if n < 16384 else 4 if n < (1 << 30) else 8
    flag = {1: 0, 2: 1, 4: 2, 8: 3}[size]
    return (n << 2 | flag).to_bytes(size, 'little')

T = dict(i64=1, i32=2, i16=3, i8=4, u64=5, u32=6, u16=7, u8=8, f64=9, str=10, bool=11, struct=12)
def item(key, typ, value, vsize=None):
    k = key.encode()
    return bytes([len(k)]) + k + bytes([typ]) + value
def val(typ, v, vsize=None):
    if typ == 'i64': return struct.pack('<q', v)
    if typ == 'i32': return struct.pack('<i', v)
    if typ == 'i16': return struct.pack('<h', v)
    if typ == 'i8': return struct.pack('<b', v)
    if typ == 'u64': return struct.pack('<Q', v)
    if typ == 'u32': return struct.pack('<I', v)
    if typ == 'u16': return struct.pack('<H', v)
    if typ == 'u8': return bytes([v])
    if typ == 'f64': return struct.pack('<d', v)
    if typ == 'bool': return bytes([1 if v else 0])
    if typ == 'str': return varint(len(v), vsize) + v
    if typ == 'struct': return dictionary(v, vsize)
    raise Exception(typ)
def dictionary(entries, size=None):
    return varint(len(entries), size) + b''.join(entries)
def it(key, typ, v, vsize=None):
    return item(key, T[typ], val(typ, v, vsize))
def arr(key, typ, vals, asize=None, vsize=None):
    return item(key, 0x80 | T[typ], varint(len(vals), asize) + b''.join(val(typ, v, vsize) for v in vals))
def payload(entries, magic=MAGIC, size=None):
    return magic + dictionary(entries, size)

def levin(cmd, body, req=True, flags=None, ret=True, code=0, version=1, length=None):
    if flags is None: flags = 1 if req else 2
    return SIG + struct.pack('<QBIiII', len(body) if length is None else length, 1 if ret else 0, cmd, code, flags, version) + body

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
class Net:
    def __init__(self): self.frames = []; self.seq = {}
    def raw(self, payload, sport, dport, seq, ack, flags, src, dst):
        s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
        opt = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), len(self.frames) + 1, 0, 64, 6, 0, s, d)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        ph = s + d + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        eth = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00'
        if src == '192.0.2.2': eth = eth[6:12] + eth[0:6] + eth[12:]
        self.frames.append(eth + ip + tcp + payload)
    def handshake(self, c, s):
        self.seq[c] = 1000; self.seq[s] = 5000
        self.raw(b'', c, s, 1000, 0, 0x02, '192.0.2.1', '192.0.2.2')
        self.raw(b'', s, c, 5000, 1001, 0x12, '192.0.2.2', '192.0.2.1')
        self.raw(b'', c, s, 1001, 5001, 0x10, '192.0.2.1', '192.0.2.2')
        self.seq[c] = 1001; self.seq[s] = 5001
    def send(self, payload, client, c, s, retrans=False):
        sport, dport = (c, s) if client else (s, c)
        src, dst = ('192.0.2.1', '192.0.2.2') if client else ('192.0.2.2', '192.0.2.1')
        seq = self.seq[sport]
        if not retrans: self.seq[sport] = seq + len(payload)
        self.raw(payload, sport, dport, seq, self.seq[dport], 0x18, src, dst)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr))); f.write(fr)

def nest_struct(levels):
    n = varint(1) + b'\x01k\x08\x01'
    for _ in range(levels):
        n = varint(1) + b'\x01s\x0c' + n
    return n

H = bytes(range(32))
def node_data(port=18080):
    return it('node_data', 'struct', [
        it('network_id', 'str', bytes.fromhex('1230f171610441611731008216a1a110')),
        it('peer_id', 'u64', 0x1122334455667788), it('my_port', 'u32', port), it('rpc_port', 'u16', 18089),
        it('rpc_credits_per_hash', 'u32', 0), it('support_flags', 'u32', 1)])
def payload_data(h=3000000):
    return it('payload_data', 'struct', [
        it('current_height', 'u64', h), it('cumulative_difficulty', 'u64', 123456789012),
        it('cumulative_difficulty_top64', 'u64', 0), it('top_id', 'str', H), it('top_version', 'u8', 16),
        it('pruning_seed', 'u32', 387)])
def peerlist(n):
    ents = []
    for i in range(n):
        ents.append(dictionary([it('adr', 'struct', [it('type', 'u8', 1), it('addr', 'struct', [
            it('m_ip', 'u32', 0x0200000a + i), it('m_port', 'u32', 18080)])]), it('id', 'u64', 1000 + i),
            it('last_seen', 'i64', -5 * i)]))
    return item('local_peerlist_new', 0x80 | T['struct'], varint(len(ents)) + b''.join(ents))

def main(outdir, verbose=False):
    os.makedirs(outdir, exist_ok=True)
    net = Net(); ranges = []
    C, S = 49200, 18080
    net.handshake(C, S)
    def snd(data, client=True): net.send(data, client, C, S)
    def mark(n, st): ranges.append((n, st, len(net.frames)))
    st = len(net.frames) + 1
    snd(levin(1001, payload([node_data(), payload_data()])))
    snd(levin(1001, payload([node_data(), payload_data(), peerlist(3)]), False, code=1), False)
    snd(levin(1002, payload([payload_data()])))
    snd(levin(1002, payload([payload_data(), peerlist(2)]), False), False)
    snd(levin(1003, payload([]), True, ret=True))
    snd(levin(1003, payload([it('status', 'str', b'OK'), it('peer_id', 'u64', 77)]), False), False)
    snd(levin(1007, payload([]), True)); snd(levin(1007, payload([it('support_flags', 'u32', 1)]), False), False)
    mark('Handshake, TimedSync, Ping, SupportFlags (request and response)', st)

    st = len(net.frames) + 1
    # every payload scalar type, every array type, nested structs
    allt = [it('i8', 'i8', -5), it('i16', 'i16', -300), it('i32', 'i32', -70000), it('i64', 'i64', -5 << 40),
            it('u8', 'u8', 200), it('u16', 'u16', 60000), it('u32', 'u32', 4000000000), it('u64', 'u64', 1 << 60),
            it('f64', 'f64', 3.5), it('s', 'str', b'hello'), it('b_true', 'bool', True), it('b_false', 'bool', False),
            it('st', 'struct', [it('inner', 'u8', 1), it('deep', 'struct', [it('x', 'i32', 5)])])]
    snd(levin(2001, payload(allt)))
    arrs = [arr('a_i8', 'i8', [-1, 2]), arr('a_i16', 'i16', [-300, 4]), arr('a_i32', 'i32', [-1, 70000]),
            arr('a_i64', 'i64', [-1, 5]), arr('a_u8', 'u8', [1, 2, 3]), arr('a_u16', 'u16', [1, 2]),
            arr('a_u32', 'u32', [1, 2]), arr('a_u64', 'u64', [1, 2]), arr('a_f64', 'f64', [1.5, -2.25]),
            arr('a_str', 'str', [b'one', b'', b'three']), arr('a_bool', 'bool', [True, False]),
            arr('a_struct', 'struct', [[it('k', 'u8', 1)], [it('k', 'u8', 2), it('m', 'str', b'v')]]),
            arr('a_empty', 'u8', [])]
    snd(levin(2002, payload(arrs)), True)
    snd(levin(2003, payload([arr('blocks', 'str', [H, H[::-1]]), it('prune', 'bool', True)])))
    snd(levin(2004, payload([arr('blocks', 'struct', [[it('block', 'str', b'\x01' * 40), arr('txs', 'str', [b'\x02' * 20])]]),
                             it('current_blockchain_height', 'u64', 3000001)]), False), False)
    snd(levin(2006, payload([arr('block_ids', 'str', [H] * 3), it('prune', 'bool', False)])))
    snd(levin(2007, payload([it('start_height', 'u64', 10), it('total_height', 'u64', 11), arr('m_block_ids', 'str', [H])]), False), False)
    snd(levin(2008, payload([it('b', 'struct', [it('block', 'str', b'\x03' * 30)]), it('current_blockchain_height', 'u64', 5)])))
    snd(levin(2009, payload([it('block_hash', 'str', H), arr('missing_tx_indices', 'u64', [1, 2])])))
    snd(levin(2010, payload([arr('hashes', 'str', [H])])))
    snd(levin(2011, payload([])), True)
    snd(levin(2012, payload([arr('txs', 'str', [H])])))
    snd(levin(5555, payload([it('u', 'u8', 1)])))               # unknown command
    snd(levin(2001, MAGIC + nest_struct(40)))                    # deeply nested structs
    mark('every command name, every scalar and array type, nested structs, unknown command', st)

    st = len(net.frames) + 1
    # varint sizes: 1, 2, 4 and 8 octet counts / lengths (non-canonical sizes too)
    snd(levin(1003, payload([it('big', 'str', b'x' * 300)])))                  # 2 octet length
    snd(levin(1003, payload([it('big', 'str', b'y' * 20000)])))                # 4 octet length (needs two segments in a real stream)
    snd(levin(1003, payload([it('s', 'str', b'z' * 5, 4), it('t', 'str', b'w' * 5, 8), arr('a', 'u8', [1, 2], 8)], size=2)))
    snd(levin(1003, payload([it('s', 'u8', 1)], size=8)))
    snd(levin(1003, payload([it('s', 'u8', 1)], size=4)))
    mark('varints of 1, 2, 4 and 8 octets', st)

    st = len(net.frames) + 1
    # header flags and TCP framing
    for fl in (0, 1, 2, 4, 8, 3, 0x10, 0xfffffff5):
        snd(levin(1003, payload([]), True, flags=fl))
    snd(levin(1003, payload([]), False, code=-1, version=0), False)
    pdu1 = levin(1003, payload([it('a', 'u32', 1)])); pdu2 = levin(1007, payload([it('b', 'u32', 2)]))
    snd(pdu1 + pdu2)                                                  # two PDUs in a segment
    big = levin(2004, payload([it('blk', 'str', b'\x05' * 3000)]), False)
    snd(big[:1000], False); snd(big[1000:2200], False); snd(big[2200:], False)  # reassembly over three segments
    snd(pdu1[:20]); snd(pdu1[20:] + pdu2[:10]); snd(pdu2[10:])        # header split, PDU split
    snd(pdu1, True);
    net.send(pdu1, True, C, S, retrans=True)                           # retransmission
    mark('flags, return codes, two PDUs per segment, reassembly, header split, retransmission', st)

    st = len(net.frames) + 1
    # a second connection on port 28080 reached through the conversation
    C2, S2 = 49201, 28080
    net.handshake(C2, S2)
    net.send(levin(1003, payload([])), True, C2, S2)
    net.send(levin(1003, payload([it('status', 'str', b'OK')]), False), False, C2, S2)
    # the conversation now belongs to Monero: data that does not start with the signature is dissected too
    net.send(levin(1002, payload([payload_data()])), True, C2, S2)
    mark('second connection (port 28080)', st)
    net.write(os.path.join(outdir, 'monero-coverage.pcap'))
    if verbose:
        for r in ranges: print('%d-%d %s' % (r[1], r[2], r[0]))
        print(len(net.frames), 'frames')

    # ---------------- malformed capture
    net = Net(); C, S = 49300, 18080
    net.handshake(C, S)
    def snd(data, client=True): net.send(data, client, C, S)
    snd(levin(1001, payload([it('u', 'u8', 1)])))
    # unknown payload type
    snd(levin(1001, payload([]) [:9] + varint(1) + b'\x01k' + b'\x30'))
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([0x80 | 0x30]) + varint(2)))   # array of unknown type
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([0x80 | 0x00]) + varint(2)))
    # string longer than the data
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([10]) + varint(200) + b'abc'))
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([10]) + varint(2 ** 40, 8) + b'abc'))
    # truncated values
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([5]) + b'\x01\x02'))
    snd(levin(1001, MAGIC + varint(3) + b'\x01k' + bytes([8, 1])))
    snd(levin(1001, MAGIC[:5]))
    snd(levin(1001, b''))
    # a deep struct nesting beyond the dissection depth limit
    snd(levin(1001, MAGIC + nest_struct(300)))

    # array with a huge count, struct count huge
    snd(levin(1001, MAGIC + varint(1) + b'\x01k' + bytes([0x80 | 4]) + varint(1 << 40, 8) + b'\x00'))
    snd(levin(1001, MAGIC + varint(1 << 40, 8)))
    # header-only PDU and a body length of 2^40 (clamped to INT_MAX less the header; reassembly never completes)
    # (each on its own connection: the message never completes, later data would be swallowed)
    net.handshake(49303, 18083)
    net.send(levin(1001, payload([it('u', 'u8', 1)]), length=100), True, 49303, 18083)
    net.handshake(49304, 18084)
    net.send(levin(1003, b'', length=1 << 40), True, 49304, 18084)
    net.send(b'\x00' * 100, True, 49304, 18084)
    # not Monero: fewer than 8 octets, a wrong signature (the heuristic rejects them)
    net.handshake(49301, 18081)
    net.send(b'\x01\x21\x01', True, 49301, 18081)
    net.handshake(49302, 18082)
    net.send(b'\x01\x21\x01\x01\x01\x01\x01\x02' + b'\0' * 30, True, 49302, 18082)
    net.write(os.path.join(outdir, 'monero-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

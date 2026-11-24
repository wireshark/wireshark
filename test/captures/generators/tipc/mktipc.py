#!/usr/bin/env python3
# Generates test/captures/tipc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the TIPC coverage captures.  Usage: mktipc.py <outdir> [-v]
import struct
import sys
import os
from pcaplib import eth, ip4, TcpFlow, udp_pkt, write_pcap

def node(z, s, p):
    return (z << 24) | (s << 12) | p

N1, N2, N3 = node(1, 1, 1), node(1, 1, 2), node(1, 2, 3)

def word0(ver, user, hdrw, size, flags=0):
    return (ver << 29) | (user << 25) | (hdrw << 21) | (flags << 17) | size

def msg(ver, user, hdrw, words, payload=b'', flags=0, size=None):
    """words: the header words after word 0, padded with zeros up to hdrw words"""
    words = list(words) + [0] * (hdrw - 1 - len(words))
    if size is None:
        size = hdrw * 4 + len(payload)
    return struct.pack('!%dI' % hdrw, word0(ver, user, hdrw, size, flags), *words[:hdrw - 1]) + payload

# ---------------- v2 ----------------
def v2data(user, mtype, payload=b'', hdrw=10, err=0, rer=0, lsc=0, optp=0, org_port=0x11111111, dst_port=0x22222222,
           o=N1, d=N2, ntype=0x1000, inst=7, upper=None, opts=b'', flags=0, size=None):
    w1 = (mtype << 29) | (err << 25) | (rer << 21) | (lsc << 19) | (optp << 16) | 0x0123
    words = [w1, (5 << 16) | 6, N3, org_port, dst_port, o, d, ntype, inst]
    if hdrw > 10:
        words.append(upper if upper is not None else inst + 5)
    words = words[:hdrw - 1]
    return msg(2, user, hdrw, words, opts + payload, flags, size)

def v2int(user, mtype, extra=(), hdrw=10, payload=b'', size=None, w1low=0, flags=0):
    """internal message: w1 holds the message type, w3 the previous node, w6/w7 the nodes"""
    words = [(mtype << 29) | w1low, (3 << 16) | 4, N3, 0, 0, N1, N2, 0, 0]
    words = words[:hdrw - 1]
    for i, v in extra:
        words[i - 1] = v
    return msg(2, user, hdrw, words, payload, flags, size)

# ---------------- v1 ----------------
def v1hdr(user, hdrw, words, payload=b'', size=None, flags=0, ver=1):
    return msg(ver, user, hdrw, words, payload, flags, size)

def v1data(user, mtype, payload=b'', hdrw=10, err=0, rer=0, actid=0x123456, org_port=0x1000, dst_port=0x2000,
           o=N1, d=N2, ntype=2000, inst=33, size=None, flags=0, ver=1):
    # w1 ack/link level seq, w2 previous processor, w3 originating port, w4 destination port,
    # w5 msg type/error/reroute/activity id, w6 originating, w7 destination processor, w8 name type, w9 name instance
    w5 = (mtype << 28) | (err << 24) | (rer << 20) | (actid & 0xfffff)
    words = [(5 << 16) | 6, N3, org_port, dst_port, w5, o, d, ntype, inst][:hdrw - 1]
    return v1hdr(user, hdrw, words, payload, size, flags, ver)

def v1int(user, mtype, payload=b'', hdrw=7, w3=0, remote=0, w6=0, size=None, ver=1):
    # w3: link selector etc., w4: remote address, w5: message type in the top nibble
    words = [(7 << 16) | 8, N3, w3, remote, (mtype << 28) | 0x0001, w6]
    return v1hdr(user, hdrw, words[:hdrw - 1], payload, size, 0, ver)

def ip4_packet(payload=b'tipc carried', proto=253):
    return ip4([10, 0, 0, 1], [10, 0, 0, 2], proto, payload)

pk = []
marks = []
def add(p, src=1, dst=2, etype=0x88CA):
    pk.append(eth(p, etype, src, dst))
def addudp(p, sport=6118, dport=6118):
    pk.append(udp_pkt(sport, dport, p))
def mark(name):
    marks.append((len(pk) + 1, name))

# ===== v2 data messages
mark('v2 payload messages: header sizes 6-11, message types, errors, options')
add(v2data(1, 0, b'conn msg', hdrw=6))
add(v2data(0, 0, b'conn msg, rer', hdrw=7, rer=3))
add(v2data(1, 2, b'named, header 9', hdrw=9, ntype=0x2222))
add(v2data(2, 2, b'named, header 10', hdrw=10, ntype=0x3333, inst=44))
add(v2data(3, 1, b'mcast, header 11', hdrw=11, ntype=0x4444, inst=10, upper=20))
add(v2data(1, 3, b'direct msg', hdrw=8, lsc=2))
add(v2data(1, 2, b'named, same range', hdrw=11, ntype=0x5555, inst=9, upper=9))
for err in range(1, 8):
    add(v2data(1, 0, b'error %d' % err, hdrw=10, err=err))
add(v2data(0, 0, b'', hdrw=6))
add(v2data(1, 2, ip4_packet(), hdrw=10, ntype=0x1234))                       # IP over TIPC (heuristic)
add(v2data(1, 2, b'opt 1', hdrw=10, optp=1, opts=b'\xaa\xbb\xcc\xdd'))
add(v2data(1, 2, b'opt 2', hdrw=10, optp=2, opts=b'\xaa' * 8))
add(v2data(1, 2, b'nonseq/flags', hdrw=10, flags=0xf))
add(v2data(3, 0, b'non-rejectable', hdrw=10))

# ===== v2 internal users
mark('v2 broadcast, link protocol, connection manager')
add(v2int(5, 0, extra=[(8, 0x01020304), (9, 0x00000001)]))
add(v2int(5, 0, extra=[(4, 0x7), (9, 9)], hdrw=10))
for mt, extra in ((0, []), (1, []), (2, [])):
    # link state / reset / activate: session, flags, bearer, priority, plane, probe
    w5 = (0x4321 << 16) | (3 << 8) | (5 << 6) | (4 << 3) | 1   # session, redundant link, bearer id, link prio, network plane, probe
    add(v2int(7, mt, extra=[(5, w5), (9, (1500 << 16) | 1000), (8, 0x55)], payload=b'eth:eth1\0\0\0\0' if mt == 1 else b''))
mark('v2 link protocol with a bearer name')
for blen, mt in ((12, 1), (11, 1), (8, 0), (13, 2)):
    name = b'eth:' + b'x' * (blen - 4)
    add(v2int(7, mt, payload=name + b'\0' * (4 - len(name) % 4)))
add(v2int(7, 1, payload=b'eth:eth0\0\0\0\0' + b'\x55' * 40))                # reset with MTU discovery filler
add(v2int(7, 1, payload=b'udp:x\0\0\0'))
add(v2int(7, 0, payload=b'eth:state\0\0\0'))

mark('v2 connection manager')
for mt in (0, 1, 2):
    add(v2int(8, mt, hdrw=10, extra=[(4, 0xaaaa), (5, 0xbbbb), (9, 0x0000002a)]))
add(v2int(8, 2, hdrw=10, extra=[(1, (2 << 29) | (6 << 25) | (1 << 16))]))   # error code
add(v2int(8, 0, hdrw=10, w1low=(1 << 16)))                                  # options present
add(v2int(8, 2, hdrw=10, w1low=(2 << 16), payload=b'\0' * 8))

mark('v2 route distributor (1.6 and 1.7 formats)')
for mt in range(5):
    add(v2int(9, mt, hdrw=10, payload=b'\xff\x00\x0f\x01' * 4))
for mt in range(3):
    add(v2int(9, mt, hdrw=10, extra=[(9, 7 << 24), (7, N1), (8, N2)], payload=struct.pack('!5I', N1, N2, N3, (3 << 8) | 2, 0)))
add(v2int(9, 0, hdrw=11, extra=[(9, 8 << 24)], payload=b'\0' * 32))

mark('v2 changeover')
for mt in (0, 1, 2):
    add(v2int(10, mt, hdrw=10, extra=[(9, 5)]))
add(v2int(10, 0, hdrw=10, payload=v2data(1, 0, b'duplicate msg', hdrw=6)))

mark('v2 name distributor')
def v2nd(mt, items, item_size=7, hdrw=10, inst=0):
    pl = b''.join(struct.pack('!7I', 1000 + i, 1 + i, 2 + i, 0x0001, 4 + i, N1, 0x01) + b'\0' * (4 * (item_size - 7) if item_size > 7 else 0) for i in range(items))
    return v2int(11, mt, hdrw=hdrw, extra=[(9, item_size << 24), (6, N1), (7, N2)], payload=pl)
add(v2nd(0, 5))
add(v2nd(1, 5))
def v2nd_old(items):
    pl = b''.join(struct.pack('!5I', 2000 + i, 3, 3 + i, 0x0101, 6 + i) for i in range(items))
    return v2int(11, 0, hdrw=10, extra=[(9, 0)], payload=pl)
add(v2nd_old(3))

mark('v2 neighbour discovery')
for mt, media in ((0, 1), (1, 2)):
    w1 = (mt << 29) | (3 << 16) | 0x1234
    add(msg(2, 13, 10, [w1, 0x01001000, N3, 0xabcdef01, media, 1, 2, 3, 4], b''))
add(msg(2, 13, 10, [(0 << 29) | 0x1234, 0x01001000, N3, 1, 1, 1, 2, 3, 4], b'vendor data'))

# ===== fragmentation (v2)
mark('v2 message fragmenter: three fragments of one message')
inner = v2data(1, 2, b'F' * 90, hdrw=10)
for i, (mt, part) in enumerate(((0, inner[:40]), (1, inner[40:80]), (2, inner[80:]))):
    add(v2int(12, mt, hdrw=10, extra=[(4, (i + 1) << 16 | 42)], payload=part))
mark('v2 message fragmenter: two fragments, no reassembly yet (second message), then done')
inner2 = v2data(1, 0, b'G' * 30, hdrw=6)
add(v2int(12, 0, hdrw=10, extra=[(4, (1 << 16) | 43)], payload=inner2[:30]))
add(v2int(12, 2, hdrw=10, extra=[(4, (2 << 16) | 43)], payload=inner2[30:]))
add(v2int(12, 1, hdrw=10, extra=[(4, (2 << 16) | 44)], payload=b'x' * 16))     # fragment of a message that never completes

# ===== v2 bundler
mark('v2 bundler, nested')
def bundle(msgs, hdrw=10, count=None, mt=1):
    body = b''
    for m in msgs:
        body += m + b'\0' * (-len(m) % 4)
    return v2int(6, mt, hdrw=hdrw, extra=[(9, (len(msgs) if count is None else count) << 16 | 1000)], payload=body)
add(bundle([v2data(1, 0, b'a' * 8, hdrw=6), v2data(1, 2, b'bb', hdrw=10), v2int(7, 0, payload=b'')]))
add(bundle([bundle([v2data(1, 0, b'nested msg', hdrw=6)] * 2), v2data(0, 0, b'x' * 8, hdrw=6)]))
add(bundle([v2data(1, 0, b'odd size!', hdrw=6)] * 3))

# ===== v1
mark('v1 payload messages')
add(v1data(0, 0, b'v1 conn, prio 0', hdrw=6))
add(v1data(1, 0, b'v1 conn, prio 1', hdrw=7))
add(v1data(2, 2, b'v1 named message with a header', hdrw=10))
add(v1data(3, 3, b'v1 direct', hdrw=8))
add(v1data(1, 4, b'v1 overload', hdrw=10, err=4))
add(v1data(1, 2, ip4_packet(), hdrw=10, ntype=77))
add(v1data(1, 9, b'v1 unknown type', hdrw=10, err=7, rer=2))
add(v1data(0, 0, b'ver 0', hdrw=8, ver=0))
add(v1data(1, 0, b'short header, five words', hdrw=5))
mark('v1 name distributor, connection manager')
nd = b''.join(struct.pack('!5I', 100 + i, 1, 2, 0x1234 + i, 8) for i in range(3))
add(v1data(9, 0, nd, hdrw=10))
add(v1data(9, 1, b''.join(struct.pack('!5I', 300 + i, 1, 2, 0x99 + i, 8) for i in range(7)), hdrw=10))
add(v1data(10, 0, b'', hdrw=8))
add(v1data(10, 1, b'', hdrw=10))
mark('v1 routing manager, link protocol, changeover, segmentation manager, bundler')
for mt in range(5):
    add(v1int(8, mt, payload=b'\x01\x02\x03\x04', remote=N2))
add(v1int(8, 0, hdrw=7, remote=N2))
for mt, extra in ((10, b''), (11, b''), (12, b'eth:eth0\0\0\0\0'), (0, b'eth:eth1\0\0\0\0')):
    add(v1int(11, mt, payload=extra, w3=0x00010003))
add(v1int(11, 12, payload=b'', w3=0x00010003))
add(v1int(13, 0, payload=v1data(1, 0, b'duplicate message', hdrw=6), w3=0x0007))
add(v1int(13, 1, payload=v1data(1, 0, b'original message', hdrw=6), w3=0x0007))
add(v1int(13, 2, payload=b'info', w3=0x0007))
add(v1int(13, 3, payload=b'bad', w3=0x0007))
add(v1int(13, 1, hdrw=7))
# segmentation manager: a 100 octet message in three segments (40, 40, 20), link selector 5
big = v1data(1, 0, b'S' * 70, hdrw=6)
assert len(big) == 94, len(big)
big = big + b'\0' * 6
for i, (mt, part) in enumerate(((1, big[:40]), (2, big[40:80]), (2, big[80:]))):
    add(v1int(14, mt, payload=part, w3=0x0005, size=28 + len(part) if i < 2 else 68), src=1)
# a first segment whose follow-up never comes, another link selector
add(v1int(14, 1, payload=big[:40], w3=0x0003))
add(v1int(14, 2, payload=big[40:80], w3=0x0003, w6=0))
add(v1int(14, 2, payload=b'z' * 8, w3=0x0009))                        # segment without first
add(v1int(14, 1, payload=big[:40], w3=0x000f, hdrw=7, size=28 + 40))
# bundler
def v1bundle(msgs):
    body = b''.join(msgs)
    return v1int(15, 0, payload=body, w3=len(msgs) << 8)
add(v1bundle([v1data(1, 0, b'one one one', hdrw=6), v1data(2, 2, b'two two two two two two two', hdrw=10)]))
add(v1bundle([v1bundle([v1data(1, 0, b'inner inner', hdrw=6)]), v1data(1, 0, b'x' * 8, hdrw=6)]))
add(v1int(16 - 1, 0, payload=b'', hdrw=7))                                   # bundler without data
add(v1int(12, 0, payload=b'user 12', w3=0))                                  # unknown v1 user (data)

# ===== UDP transport
mark('over UDP 6118')
addudp(v2data(1, 2, b'over udp', hdrw=10))
addudp(v1data(1, 0, b'over udp v1', hdrw=6))
addudp(v2int(7, 0, payload=b'eth:u\0\0\0'))

# ===== TCP transport, needs Decode As tcp.port==6119,tipc.tcp
mark('over TCP 6119 (Decode As tipc.tcp)')
TS, TC = 6119, 40001
fl = TcpFlow(TC, TS)
pk.append(fl.c2s(v2data(1, 2, b'tcp one', hdrw=10)))
m1 = v2data(1, 2, b'T' * 60, hdrw=10)
m2 = v1data(1, 0, b'second message!', hdrw=6)
pk.append(fl.c2s(m1 + m2))                                  # two PDUs in one segment
pk.append(fl.c2s(m1[:30]))                                  # PDU split over two segments
pk.append(fl.c2s(m1[30:] + m2[:10]))
pk.append(fl.c2s(m2[10:]))
pk.append(fl.s2c(v2int(7, 0, payload=b'eth:t\0\0\0')))

# ===== reproducers of the fixes (decode cleanly now)
mark('fix: NAME_DISTRIBUTOR item size below 7 (expert info, no malformed frame)')
# the item_size is the top byte of word 9; 1 and 0 are rejected, 7 and above are fine
def nd_item_size(item_size, nitems, words=7):
    data = b''.join(struct.pack('!%dI' % words, *([1000 + i, 1, 2, 3, 4, 0x01001001, 0][:words])) for i in range(nitems))
    w0 = (2 << 29) | (11 << 25) | (10 << 21) | (40 + len(data))
    return struct.pack('!10I', w0, 0, 0, 0x01001001, 0, 0, 0x01001001, 0x01001002, 0, item_size << 24) + data
# both carry 140 octets of items (5 items of 7 words or 7 items of 5 words), so that they
# decode without a malformed frame whatever the handle_v2_as preference is
add(nd_item_size(1, 5))
add(nd_item_size(0, 7, words=5))
mark('fix: options longer than the header (hdr_size underflow)')
add(v2data(1, 2, b'opts', hdrw=6, optp=7, opts=b'\0' * 28))
add(v2data(1, 2, b'opts', hdrw=6, optp=3, opts=b'\0' * 12))

mal = []
def addm(p, src=1, dst=2, etype=0x88CA):
    mal.append(eth(p, etype, src, dst))
# message size below the header size, truncations, recursion, bundle sizes
addm(msg(2, 1, 6, [], size=20))                                  # v2 data, size < header
addm(msg(2, 5, 10, [], size=36))                                 # v2 internal, size < header
addm(msg(1, 1, 10, [], size=36))                                 # v1 data, size < header
addm(msg(1, 1, 5, [], size=16))
addm(v2data(1, 2, b'x', hdrw=10)[:30])
addm(v1data(1, 2, b'x', hdrw=10)[:30])
addm(v2int(7, 0, payload=b'eth')[:44])
addm(nd_item_size(0, 1))                                         # 7-word items with item_size 0
addm(v2nd(0, 1, item_size=9))                                    # extra words in an item
addm(v2nd(0, 0))
addm(v2int(7, 1))                                                # reset without a bearer name
addm(v1data(2, 2, b'short', hdrw=10))
addm(v2int(6, 1, hdrw=10, extra=[(9, 5 << 16)], payload=struct.pack('!I', (2 << 29) | (1 << 25) | 0x1ffff)))
rec = v2data(1, 0, b'deep', hdrw=6)
for _ in range(12):
    rec = v2int(6, 1, hdrw=10, extra=[(9, 1 << 16)], payload=rec)
addm(rec)
rec1 = v1data(1, 0, b'deep', hdrw=6)
for _ in range(12):
    rec1 = v1int(15, 0, payload=rec1)
addm(rec1)
rec2 = v1data(1, 0, b'deep', hdrw=6)
for _ in range(12):
    rec2 = v1int(13, 0, payload=rec2)
addm(rec2)
addm(v1int(15, 0, payload=struct.pack('!I', 0x20000000 | 4) + b'\0\0\0\0'))      # bundle entry of 4 octets
addm(v1int(15, 0, payload=struct.pack('!I', 0x1ffff) + b'\0' * 8))             # bundle entry larger than the rest
addm(v1int(15, 0, payload=b'\0\0\0\0' * 3))                                    # entry of size 0
addm(v1int(14, 1, payload=b'', size=28 + 0))
addm(v1int(14, 1, payload=b'\0' * 8, size=28))
addm(v2int(7, 1, payload=b'e'))                                                # unterminated bearer name
addm(v2int(11, 0, hdrw=10, extra=[(9, 8 << 24)], payload=b'\0' * 20))        # name table item cut short
addm(v2int(11, 0, hdrw=10, extra=[(9, 0)], payload=b'\0' * 12))
addm(v2int(12, 1, hdrw=10, extra=[(4, 1)], payload=b'x' * 4), 1, 2)
addm(msg(2, 15, 10, []))                                                       # unknown v2 user
addm(msg(2, 4, 10, [], size=40))                                               # user 4: unknown
addm(msg(3, 1, 10, []))                                                        # unknown version
addm(v2data(1, 2, b'x' * 30, hdrw=10, optp=7, opts=b'\0' * 28)[:50])
addm(v2nd(0, 1, item_size=7)[:60])
addm(v1data(9, 0, b'\0' * 10, hdrw=10))
addm(v1int(11, 12, payload=b'', hdrw=7)[:20])
addm(v2int(5, 0)[:20])
addm(v2int(13, 0, hdrw=10)[:33])
addm(v2int(10, 1, hdrw=10)[:36])

if len(sys.argv) < 2:
    sys.exit('usage: mktipc.py <outdir> [-v]')
out = sys.argv[1]
write_pcap(os.path.join(out, 'tipc-coverage.pcap'), pk)
write_pcap(os.path.join(out, 'tipc-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for n, name in marks:
        print(n, name)
    print('main', len(pk), 'malformed', len(mal))

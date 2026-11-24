#!/usr/bin/env python3
# Generates test/captures/bitcoin_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bitcoin dissector
(packet-bitcoin.c).

Bitcoin P2P messages over TCP, found by the "bitcoin_tcp" heuristic from
the magic number (enabled by default; port 8333 is used but is not
registered). Every packet is built from scratch with struct; no captured
traffic is used. Hashes, nonces and keys are made-up byte patterns.

Usage: mkbitcoin.py <output directory>

Writes:
  bitcoin-coverage.pcap            every message type in each direction,
                                   every varint size for every count and
                                   length, PDUs split over segments and
                                   several in one segment, every magic
  bitcoin-coverage-malformed.pcap  the PDU length wrap reproducer (small),
                                   hostile varint lengths, address length
                                   mismatch, script length past INT_MAX,
                                   truncated messages
"""

import hashlib
import os
import struct
import sys

MAIN = 0xD9B4BEF9
TESTNET = 0xDAB5BFFA
TESTNET3 = 0x0709110B
TESTNET4 = 0x283F161C

T0 = 1700000000


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.recs = []
        self.t = 0

    def add(self, pkt):
        self.t += 1
        sec, usec = T0 + self.t // 1000, (self.t % 1000) * 1000
        self.recs.append(struct.pack('<IIII', sec, usec, len(pkt), len(pkt)) + pkt)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            f.write(b''.join(self.recs))


class Conn:
    """A TCP connection between a client and a server; tracks the sequence
    numbers of both directions."""

    def __init__(self, cap, cport, sport=8333, chost=1, shost=2, handshake=True):
        self.cap = cap
        self.ep = {'c': (bytes([192, 0, 2, chost]), cport),
                   's': (bytes([198, 51, 100, shost]), sport)}
        self.seq = {'c': 1000 + cport, 's': 50000 + cport}
        if handshake:
            self.raw('c', b'', 0x02)
            self.seq['c'] += 1
            self.raw('s', b'', 0x12)
            self.seq['s'] += 1
            self.raw('c', b'', 0x10)

    def raw(self, d, payload, flags=0x18):
        o = 's' if d == 'c' else 'c'
        (src, sp), (dst, dp) = self.ep[d], self.ep[o]
        ack = self.seq[o] if flags != 0x02 else 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS 1460 on SYNs
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum16(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000,
                         64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum16(ip)) + ip[12:]
        mac = {'c': b'\x02\x00\x00\x00\x00\x01', 's': b'\x02\x00\x00\x00\x00\x02'}
        self.cap.add(mac[o] + mac[d] + b'\x08\x00' + ip + tcp + payload)
        self.seq[d] += len(payload)

    def send(self, d, *chunks):
        """Send each chunk as one segment."""
        for c in chunks:
            self.raw(d, c)


# Bitcoin encoding ---------------------------------------------------------

def msg(cmd, payload, magic=MAIN, length=None, checksum=None):
    if length is None:
        length = len(payload)
    if checksum is None:
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return (struct.pack('<I', magic) + cmd.encode().ljust(12, b'\0')[:12] +
            struct.pack('<I', length) + checksum + payload)


def vi(v, form=None):
    """A varint; form 1, 3, 5 or 9 forces that size (non-canonical for
    small values, which the dissector accepts); a value too large for the
    form gets the smallest size that holds it."""
    canon = 9 if v > 0xffffffff else 5 if v > 0xffff else 3 if v >= 0xfd else 1
    form = max(form or 1, canon)
    if form == 9:
        return b'\xff' + struct.pack('<Q', v)
    if form == 5:
        return b'\xfe' + struct.pack('<I', v)
    if form == 3:
        return b'\xfd' + struct.pack('<H', v)
    return bytes([v])


def h32(n):
    return hashlib.sha256(b'synthetic-%d' % n).digest()


def netaddr(services, ip4, port):
    return (struct.pack('<Q', services) + b'\0' * 10 + b'\xff\xff' + bytes(ip4) +
            struct.pack('>H', port))


def varstr(s, form=None):
    return vi(len(s), form) + s


ALL_SERVICES = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x400 | 0x800


def version_payload(ver, form=None):
    p = struct.pack('<I', ver) + struct.pack('<Q', 0x409) + struct.pack('<II', T0, 0)
    p += netaddr(0x1, (198, 51, 100, 2), 8333)
    if ver >= 106:
        p += netaddr(ALL_SERVICES, (192, 0, 2, 1), 40001)
        p += struct.pack('<Q', 0x1122334455667788)
        p += varstr(b'/Synthetic:0.1/', form)
    if ver >= 209:
        p += struct.pack('<I', 840000)
    if ver >= 70002:
        p += b'\x01'
    return p


def addr_payload(form):
    p = vi(2, form)
    p += struct.pack('<I', T0 - 60) + netaddr(0x409, (203, 0, 113, 7), 8333)
    p += struct.pack('<I', T0 - 120) + netaddr(ALL_SERVICES, (203, 0, 113, 8), 18333)
    return p


def addrv2_entry(net, addr, port, sform=None, aform=None, services=0x409):
    return (struct.pack('<I', T0 - 30) + vi(services, sform) + bytes([net]) +
            vi(len(addr), aform) + addr + struct.pack('>H', port))


def addrv2_payload(form):
    entries = [
        addrv2_entry(1, bytes([203, 0, 113, 9]), 8333, form, form),
        addrv2_entry(2, bytes.fromhex('20010db8000000000000000000000001'), 8333, form, form,
                     ALL_SERVICES),
        addrv2_entry(3, bytes(range(1, 11)), 9050, form),
        addrv2_entry(4, bytes(range(32)), 8333, None, form),
        addrv2_entry(5, bytes(range(32, 64)), 0, form),
        addrv2_entry(6, bytes.fromhex('fc000000000000000000000000000001'), 8333),
        addrv2_entry(7, b'\xaa\xbb\xcc', 1234),   # unknown network id
    ]
    return vi(len(entries), form) + b''.join(entries)


INV_TYPES = [0, 1, 2, 3, 4, 5, 0x40000001, 0x40000002, 7]


def inv_payload(form, types=INV_TYPES):
    return vi(len(types), form) + b''.join(struct.pack('<I', t) + h32(t) for t in types)


def locator_payload(form, n):
    return struct.pack('<I', 70016) + vi(n, form) + b''.join(h32(100 + i) for i in range(n)) + h32(999)


def tx_payload(segwit=False, form=None, nin=1, nout=2, witness_items=2, seed=0):
    p = struct.pack('<I', 2 if segwit else 1)
    if segwit:
        p += b'\x00\x01'
    p += vi(nin, form)
    for i in range(nin):
        # A segwit input has an empty script; a legacy one a 72 octet push
        script = b'' if segwit else (b'\x48' + bytes((seed + i + j) & 0xff for j in range(0x48)))
        p += h32(seed * 10 + i) + struct.pack('<I', i) + vi(len(script), form) + script
        p += struct.pack('<I', 0xfffffffd)
    p += vi(nout, form)
    for i in range(nout):
        script = b'\x00\x14' + bytes((seed + i + j) & 0xff for j in range(20))
        p += struct.pack('<Q', 50000 * (i + 1)) + vi(len(script), form) + script
    if segwit:
        for i in range(nin):
            p += vi(witness_items, form)
            for k in range(witness_items):
                item = bytes(((seed + k + j) & 0xff) for j in range(33 if k else 72))
                p += vi(len(item), form) + item
    p += struct.pack('<I', 0)
    return p


def coinbase_tx():
    script = b'\x03\x40\xd1\x0c' + b'synthetic coinbase'
    return (struct.pack('<I', 1) + vi(1) + b'\0' * 32 + struct.pack('<I', 0xffffffff) +
            vi(len(script)) + script + struct.pack('<I', 0xffffffff) + vi(1) +
            struct.pack('<Q', 312500000) + vi(25) + b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac' +
            struct.pack('<I', 0))


def block_header(n):
    return (struct.pack('<I', 0x20000000) + h32(200 + n) + h32(300 + n) +
            struct.pack('<III', T0 - 600 * n, 0x17034219, 0x12345678 + n))


def block_payload(txs, form=None):
    return block_header(0) + vi(len(txs), form) + b''.join(txs)


def headers_payload(form, n=2):
    return vi(n, form) + b''.join(block_header(i) + vi(0, form) for i in range(n))


def reject_payload(message, ccode, reason, data=b'', form=None):
    return varstr(message, form) + bytes([ccode]) + varstr(reason, form) + data


def filterload_payload(nflags, form=None):
    return varstr(bytes(range(16)), form) + struct.pack('<IIB', 11, 0x5eed, nflags)


def merkleblock_payload(form, nhashes=3):
    return (block_header(5) + struct.pack('<I', 7) + vi(nhashes, form) +
            b''.join(h32(400 + i) for i in range(nhashes)) + varstr(b'\x1d\x01', form))


# Main capture ---------------------------------------------------------------

def main_capture(path):
    cap = Pcap()
    ver = struct.pack

    # Stream 1: handshake and every message type; one PDU per segment.
    c = Conn(cap, 40001)
    c.send('c', msg('version', version_payload(70016)))
    c.send('s', msg('version', version_payload(70015)))
    c.send('c', msg('wtxidrelay', b''))
    c.send('c', msg('sendaddrv2', b''))
    c.send('c', msg('verack', b''))
    c.send('s', msg('verack', b''))
    c.send('s', msg('sendheaders', b''))
    c.send('s', msg('sendcmpct', b'\x00' + ver('<Q', 2)))
    c.send('c', msg('sendcmpct', b'\x01' + ver('<Q', 1)))
    c.send('c', msg('feefilter', ver('<q', 1000)))
    c.send('s', msg('feefilter', ver('<q', 12345)))
    c.send('c', msg('ping', ver('<Q', 0x0102030405060708)))
    c.send('s', msg('pong', ver('<Q', 0x0102030405060708)))
    c.send('c', msg('getaddr', b''))
    for form in (1, 3, 5, 9):
        c.send('s', msg('addr', addr_payload(form)))
    for form in (1, 3, 5, 9):
        c.send('s', msg('addrv2', addrv2_payload(form)))
    for form in (1, 3, 5, 9):
        c.send('s', msg('inv', inv_payload(form)))
    for form in (1, 3, 5, 9):
        c.send('c', msg('getdata', inv_payload(form)))
    for form in (1, 3, 5, 9):
        c.send('s', msg('notfound', inv_payload(form, [1, 0x40000001])))
    for form, n in ((1, 2), (3, 1), (5, 0), (9, 3)):
        c.send('c', msg('getblocks', locator_payload(form, n)))
    for form, n in ((1, 2), (3, 1), (5, 0), (9, 3)):
        c.send('c', msg('getheaders', locator_payload(form, n)))
    for form in (1, 3, 5, 9):
        c.send('s', msg('headers', headers_payload(form)))
    # Legacy and segwit transactions with every varint size
    for form in (1, 3, 5, 9):
        c.send('s', msg('tx', tx_payload(False, form, seed=form)))
    for form in (1, 3, 5, 9):
        c.send('s', msg('tx', tx_payload(True, form, nin=2, seed=form + 10)))
    c.send('s', msg('tx', tx_payload(True, None, nin=1, nout=1, witness_items=0, seed=30)))
    c.send('s', msg('block', block_payload([coinbase_tx(), tx_payload(True, seed=40),
                                           tx_payload(False, seed=41)])))
    c.send('s', msg('block', block_payload([coinbase_tx()], 9)))
    c.send('s', msg('block', block_payload([], 3)))
    c.send('c', msg('mempool', b''))
    for nflags, form in ((0, 1), (1, 3), (2, 5), (3, 9)):
        c.send('c', msg('filterload', filterload_payload(nflags, form)))
    for form in (1, 3, 5, 9):
        c.send('c', msg('filteradd', varstr(h32(500 + form), form)))
    c.send('c', msg('filterclear', b''))
    for form, n in ((1, 3), (3, 1), (5, 0), (9, 2)):
        c.send('s', msg('merkleblock', merkleblock_payload(form, n)))
    c.send('s', msg('reject', reject_payload(b'tx', 0x10, b'bad-txns-inputs-missingorspent',
                                             h32(600))))
    for form, (cc, m) in zip((1, 3, 5, 9), ((0x01, b'block'), (0x11, b'version'),
                                            (0x12, b'tx'), (0x40, b'tx'))):
        c.send('s', msg('reject', reject_payload(m, cc, b'reason', b'', form)))
    for cc in (0x41, 0x42, 0x43, 0x99):
        c.send('s', msg('reject', reject_payload(b'tx', cc, b'rejected', h32(cc))))
    # Commands registered with the empty handler
    for cmd in ('checkorder', 'submitorder', 'reply', 'alert'):
        c.send('s', msg(cmd, b'\x01\x02\x03\x04'))
    # BIP 152 messages and a made-up command, which have no handler
    c.send('s', msg('cmpctblock', block_header(9) + ver('<Q', 42) + vi(0) + vi(0)))
    c.send('c', msg('getblocktxn', h32(9) + vi(1) + vi(0)))
    c.send('s', msg('blocktxn', h32(9) + vi(1) + coinbase_tx()))
    c.send('c', msg('synthetic', b'hello'))

    # Stream 2: several PDUs per segment, PDUs split over segments
    c = Conn(cap, 40002)
    m = [msg('version', version_payload(70016)), msg('verack', b''),
         msg('ping', ver('<Q', 1)), msg('pong', ver('<Q', 1))]
    c.send('c', b''.join(m))          # four PDUs in one segment
    big = msg('block', block_payload([coinbase_tx()] + [tx_payload(True, None, nin=2, seed=50 + i)
                                                       for i in range(8)]))
    third = len(big) // 3
    c.send('s', big[:third], big[third:2 * third], big[2 * third:])   # one PDU, three segments
    a = msg('inv', inv_payload(None))
    b = msg('getdata', inv_payload(None, [1, 2]))
    d = msg('ping', ver('<Q', 2))
    e = msg('notfound', inv_payload(None, [5]))
    c.send('c', a[:10], a[10:])                     # header split after 10 octets
    c.send('c', b[:50], b[50:] + d + e[:40], e[40:])  # PDU tail, whole PDU, PDU head
    tx = msg('tx', tx_payload(True, None, nin=3, seed=60))
    c.send('s', d + tx[:30], tx[30:100], tx[100:])

    # Streams 3-5: the testnet magic numbers, on other ports
    for i, magic in enumerate((TESTNET, TESTNET3, TESTNET4)):
        c = Conn(cap, 40010 + i, sport=(18333, 18333, 48333)[i], chost=10 + i, shost=10 + i)
        c.send('c', msg('version', version_payload(70016), magic))
        c.send('s', msg('version', version_payload(70016), magic))
        c.send('c', msg('verack', b'', magic), msg('ping', ver('<Q', 3 + i), magic))
        c.send('s', msg('verack', b'', magic) + msg('pong', ver('<Q', 3 + i), magic))

    # Stream 6: older protocol versions (fewer version fields), and string
    # lengths in every varint size
    c = Conn(cap, 40020)
    for v in (60, 106, 209, 70001):
        c.send('c', msg('version', version_payload(v)))
    for form in (3, 5, 9):
        c.send('s', msg('version', version_payload(70016, form)))

    # Stream 7: not Bitcoin (no magic): the heuristic rejects it
    c = Conn(cap, 40030)
    c.send('c', b'NOT A BITCOIN STREAM\r\n')
    c.send('s', b'OK')

    cap.write(path)


# Malformed capture ---------------------------------------------------------

def malformed_capture(path):
    cap = Pcap()
    ver = struct.pack
    port = [41000]

    def one(*chunks, d='c'):
        port[0] += 1
        c = Conn(cap, port[0], handshake=False)
        c.send(d, *chunks)
        return c

    # PDU length wrap reproducer (bitcoin_pdulen_wrap.py), 20
    # segments: payload length 0xffffffe8 used to give a PDU length of 0.
    port[0] += 1
    c = Conn(cap, port[0], handshake=False)
    c.send('c', msg('ping', b'', length=0xffffffe8, checksum=b'\0' * 4))
    for _ in range(19):
        c.send('c', b'Z' * 1400)

    # Hostile varint lengths (bitcoin_malformed.py)
    one(msg('reject', vi(0xffffffff, 5) + b'tx' + b'\x10' + vi(3) + b'bad' + b'X' * 8))
    v = version_payload(70015)
    v = v[:80] + vi(0xffffffff, 5) + b'/x/' + ver('<I', 5) + b'\x01'
    one(msg('version', v))
    one(msg('addrv2', vi(0xffffffffffffffff) + (ver('<I', 0) + vi(1) + b'\x02' +
                                                 vi(0xffffffff, 5) + b'\0' * 16 + b'\x20\x8d') * 4))
    one(msg('merkleblock', block_header(1) + ver('<I', 1) + vi(1) + b'\0' * 32 +
            vi(0xffffffff, 5) + b'\xaa\xbb'))
    t = (ver('<I', 2) + b'\x00\x01' + vi(1) + b'\0' * 36 + vi(0) + ver('<I', 0xffffffff) + vi(1) +
         ver('<Q', 1) + vi(1) + b'\x51' + vi(0xffffffffffffffff) + (vi(0xffffffff, 5) + b'WWW') * 50)
    one(msg('tx', t))
    one(msg('block', block_header(1) + vi(0xffffffffffffffff) +
            (ver('<I', 1) + vi(0) + vi(0) + ver('<I', 0)) * 100))
    one(msg('filterload', vi(0xffffffff, 5) + b'\x01\x02\x03' + b'\0' * 9))
    one(msg('filteradd', vi(0xffffffffffffffff) + b'\x01\x02'))
    # addrv2: IPv4 with 5 octets, IPv6 with 20 (address length warnings)
    one(msg('addrv2', vi(2) + addrv2_entry(1, b'\x0a\0\0\x01\x00', 8333) +
            addrv2_entry(2, b'\x20\x01\x0d\xb8' + b'\0' * 16, 8333)))
    # tx: input and output script lengths past INT_MAX (error expert info)
    t = ver('<I', 1) + vi(1) + h32(1) + ver('<I', 0) + vi(0x80000000, 9) + b'\0' * 8
    one(msg('tx', t))
    # (no inputs: a 0 input count would be read as the segwit marker, so use one)
    t = ver('<I', 2) + b'\x00\x01' + vi(0) + vi(1) + ver('<Q', 1) + vi(0xffffffffffff, 9) + b'\0' * 8
    one(msg('tx', t))
    # block whose transaction has a script length past INT_MAX: the loop stops
    one(msg('block', block_header(2) + vi(2) + t + t))
    # Truncated messages
    for cmd in ('version', 'addr', 'addrv2', 'inv', 'getdata', 'notfound', 'getblocks',
                'getheaders', 'tx', 'block', 'headers', 'ping', 'pong', 'reject',
                'feefilter', 'filterload', 'filteradd', 'merkleblock', 'sendcmpct'):
        one(msg(cmd, b'\x05\x00'))
    # Varint counts larger than the data
    for cmd in ('addr', 'inv', 'getdata', 'notfound', 'headers'):
        one(msg(cmd, vi(0xffffffffffffffff) + b'\0' * 40))
    one(msg('getblocks', ver('<I', 1) + vi(0xffffffff, 5) + b'\0' * 40))
    one(msg('getheaders', ver('<I', 1) + vi(0xffffffff, 5) + b'\0' * 40))
    one(msg('merkleblock', block_header(1) + ver('<I', 1) + vi(0xffffffff, 5) + b'\0' * 40))
    # Header split with desegmentation, stream ends before the payload
    one(msg('inv', inv_payload(None))[:40])
    # Segment shorter than the 4 octet magic at the start of a stream
    one(b'\xf9\xbe')
    cap.write(path)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'bitcoin-coverage.pcap'))
    malformed_capture(os.path.join(out, 'bitcoin-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

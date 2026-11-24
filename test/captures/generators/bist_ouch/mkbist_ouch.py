#!/usr/bin/env python3
# Generates test/captures/bist_ouch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BIST OUCH dissector
(packet-bist-ouch.c).

BIST OUCH is found by its heuristic on SoupBinTCP data packets
(Unsequenced Data from the client, Sequenced Data from the server).
SoupBinTCP has no default port. Every packet is built from scratch with
struct; no captured traffic is used. Order entry clients (10.0.0.1 and
10.0.0.3) talk to the exchange gateway (10.0.0.2) on TCP port 21001.

Usage: mkbist_ouch.py <output directory>

Writes:
  bist_ouch-coverage.pcap            every message type, Enter Order with and
                                     without the reserved field, Replace Order
                                     and Order Replaced (with trailing bytes),
                                     Mass Quote with entries, without the
                                     count and with fewer entries than counted,
                                     Mass Quote Rejection lengths, negative
                                     prices, order chains for the orderbook
                                     tracking preference (every grouping case),
                                     several messages per segment and a
                                     message split over two segments
  bist_ouch-coverage-malformed.pcapng truncated messages of every type, a
                                     Replace Order taken for an Order Replaced
                                     by the timestamp heuristic, and (on an
                                     Exported PDU interface) unknown types

Dissect with -d tcp.port==21001,soupbintcp
"""

import os
import struct
import sys

PORT = 21001
CLIENT = (10, 0, 0, 1)
CLIENT2 = (10, 0, 0, 3)
SERVER = (10, 0, 0, 2)
TS = 1761700000000000000          # nanoseconds, > 1e18 as the dissector expects


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', csum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) + 1,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        eth = (b'\x02\x00\x00\x00\x00' + bytes([dst[3]]) +
               b'\x02\x00\x00\x00\x00' + bytes([src[3]]) + b'\x08\x00')
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1761700000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class Conn:
    """A TCP connection from an order entry client to the gateway."""
    def __init__(self, cap, client, cport):
        self.cap, self.client, self.cport = cap, client, cport
        self.cseq, self.sseq = 100000 + cport, 900000 + cport
        cap.tcp(client, SERVER, cport, PORT, self.cseq, 0, 0x02)
        cap.tcp(SERVER, client, PORT, cport, self.sseq, self.cseq + 1, 0x12)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(client, SERVER, cport, PORT, self.cseq, self.sseq, 0x10)

    def c(self, *datas):
        """Each argument is one TCP segment from the client."""
        for d in datas:
            self.cap.tcp(self.client, SERVER, self.cport, PORT, self.cseq, self.sseq, 0x18, d)
            self.cseq += len(d)

    def s(self, *datas):
        for d in datas:
            self.cap.tcp(SERVER, self.client, PORT, self.cport, self.sseq, self.cseq, 0x18, d)
            self.sseq += len(d)

    def close(self):
        self.cap.tcp(self.client, SERVER, self.cport, PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(SERVER, self.client, PORT, self.cport, self.sseq, self.cseq, 0x11)
        self.sseq += 1
        self.cap.tcp(self.client, SERVER, self.cport, PORT, self.cseq, self.sseq, 0x10)


# SoupBinTCP ----------------------------------------------------------------

def soup(ptype, payload=b''):
    return struct.pack('>H', 1 + len(payload)) + ptype + payload


def login_request(user='TRADE1', pw='secret', session='', seq=1):
    return soup(b'L', a(user, 6) + a(pw, 10) + a(session, 10) + str(seq).rjust(20).encode())


def login_accept(session='SESSION01', seq=1):
    return soup(b'A', a(session, 10) + str(seq).rjust(20).encode())


def unseq(msg):
    return soup(b'U', msg)


def seqd(msg):
    return soup(b'S', msg)


# BIST OUCH -------------------------------------------------------------------

def a(s, n):
    s = s.encode()
    assert len(s) <= n
    return s + b' ' * (n - len(s))


def tok(s):
    return a(s, 14)


def enter_order(token, ob=70616, side=b'B', qty=1000, price=123450, tif=0, oc=1,
                reserved=True, cat=1):
    m = (b'O' + tok(token) + struct.pack('>I', ob) + side + struct.pack('>Qi', qty, price) +
         bytes([tif, oc]) + a('ACCT0001', 16) + a('CUSTINFO', 15) + a('EXCHINFO', 32) +
         struct.pack('>Q', 100) + bytes([cat, 0, 1, 2]) + b'ABC')
    assert len(m) == 112
    if reserved:
        m += b'\0\0'
    return m


def replace_order(eot, rot, qty=800, price=123500, extra=b''):
    m = (b'U' + tok(eot) + tok(rot) + struct.pack('>Qi', qty, price) + b'\x02' +
         a('ACCT0001', 16) + a('CUSTINFO', 15) + a('EXCHINFO', 32) +
         struct.pack('>Q', 50) + b'\x02' + b'\0' * 8)
    assert len(m) == 122
    return m + extra


def order_replaced(rot, prev, order_id=5000001, qty=800, price=123500, extra=b''):
    m = (b'U' + struct.pack('>Q', TS + 3) + tok(rot) + tok(prev) +
         struct.pack('>I', 70616) + b'B' + struct.pack('>QQi', order_id, qty, price) +
         bytes([3, 2]) + a('ACCT0001', 16) + b'\x01' + a('CUSTINFO', 15) + a('EXCHINFO', 32) +
         struct.pack('>QQ', 0, 50) + b'\x07')
    assert len(m) == 145
    return m + extra


def cancel_order(token):
    return b'X' + tok(token)


def cancel_by_id(order_id=5000002, side=b'S'):
    return b'Y' + struct.pack('>I', 70616) + side + struct.pack('>Q', order_id)


def quote_entry(ob, bid, offer, bsz, osz):
    return struct.pack('>IiiQQ', ob, bid, offer, bsz, osz)


def mass_quote(token, entries=None, count=None, extra=b''):
    m = b'Q' + tok(token) + b'\x02' + a('ACCT0002', 16) + a('MMQUOTE', 16)
    if entries is None:
        return m
    m += struct.pack('>H', len(entries) if count is None else count)
    return m + b''.join(entries) + extra


def accepted(token, order_id=5000001, side=b'B', qty=1000, price=123450, state=1):
    m = (b'A' + struct.pack('>Q', TS + 1) + tok(token) + struct.pack('>I', 70616) + side +
         struct.pack('>QQi', order_id, qty, price) + bytes([0, 1]) + a('ACCT0001', 16) +
         bytes([state]) + a('CUSTINFO', 15) + a('EXCHINFO', 32) +
         struct.pack('>QQ', 0, 100) + bytes([1, 0, 1, 2]) + b'ABC')
    assert len(m) == 137
    return m


def rejected(token, code=-1):
    return b'J' + struct.pack('>Q', TS + 2) + tok(token) + struct.pack('>i', code)


def canceled(token, order_id=5000001, reason=1):
    return (b'C' + struct.pack('>Q', TS + 4) + tok(token) + struct.pack('>I', 70616) + b'B' +
            struct.pack('>Q', order_id) + bytes([reason]))


def executed(token, qty=300, price=123450):
    m = (b'E' + struct.pack('>Q', TS + 5) + tok(token) + struct.pack('>IQi', 70616, qty, price) +
         bytes(range(1, 13)) + b'\x01' + b'\0' * 16)
    assert len(m) == 68
    return m


def quote_ack(token, qty=500, traded=0, price=123400, side=b'B', status=0):
    m = (b'K' + struct.pack('>Q', TS + 6) + tok(token) + struct.pack('>IQQi', 70616, qty, traded, price) +
         side + struct.pack('>I', status))
    assert len(m) == 52
    return m


def quote_reject(token, ob=None, code=None, extra=b''):
    m = b'R' + struct.pack('>Q', TS + 7) + tok(token)
    if ob is not None:
        m += struct.pack('>I', ob)
    if code is not None:
        m += struct.pack('>i', code)
    return m + extra


def main_capture(path):
    cap = Pcap()
    c = Conn(cap, CLIENT, 50001)
    c.c(login_request())
    # No Login Accept in this capture: packet-soupbintcp.c creates a new
    # conversation for it with conversation_new() on the TCP addresses and
    # ports, and on the second pass TCP finds that conversation and starts
    # a new stream for the session (one pass and -2 differ). The Login
    # Accept is in the malformed capture.
    c.s(soup(b'H'))
    # A simple order: enter (no reserved field), accepted, executed
    c.c(unseq(enter_order('TOK1', reserved=False)))
    c.s(seqd(accepted('TOK1')))
    c.s(seqd(executed('TOK1')))
    # Enter order with the reserved field, a sell order, rejected
    c.c(unseq(enter_order('TOK2', side=b'S', price=-250, tif=3, oc=2, cat=7)))
    c.s(seqd(rejected('TOK2', code=-1234)))
    # Replace TOK1 with TOK1R (inbound, EOT seen, ROT new), replaced, canceled
    c.c(unseq(replace_order('TOK1', 'TOK1R')))
    c.s(seqd(order_replaced('TOK1R', 'TOK1')))
    c.c(unseq(cancel_order('TOK1R')))
    c.s(seqd(canceled('TOK1R', reason=5)))
    # Replace again with both tokens of the same chain
    c.c(unseq(replace_order('TOK1', 'TOK1R')))
    # Inbound Replace Order with trailing bytes (length 130). The dissector
    # takes a U of any length but 122 and 145+ for Order Replaced if octets
    # 1-8 read as a timestamp above 10^18, which every token starting with a
    # printable character does, so this EOT starts with a control character.
    # Then Order Replaced with trailing bytes.
    c.c(unseq(replace_order('\x01TOK1R', 'TOK1S', extra=b'\xee' * 8)))
    c.s(seqd(order_replaced('TOK1S', 'TOK1R', extra=b'\xee' * 5)))
    # Cancel by order ID, then a Short side
    c.c(unseq(cancel_by_id()))
    c.c(unseq(enter_order('TOK3', side=b'T', tif=4, oc=4, cat=12)))
    c.s(seqd(accepted('TOK3', order_id=5000003, side=b'T', state=2)))
    # Mass quote with two entries, acknowledged
    c.c(unseq(mass_quote('TOKQ1', [quote_entry(70616, 123400, 123600, 500, 600),
                                    quote_entry(70617, -100, 200, 10, 20)])))
    c.s(seqd(quote_ack('TOKQ1')), seqd(quote_ack('TOKQ1', side=b'S', traded=100, status=5)))
    # Mass quote without the entry count, rejected (token only)
    c.c(unseq(mass_quote('TOKQ2')))
    c.s(seqd(quote_reject('TOKQ2')))
    # Mass quote counting three entries with one present and a partial one
    c.c(unseq(mass_quote('TOKQ3', [quote_entry(70618, 1, 2, 3, 4)], count=3, extra=b'\x11' * 10)))
    c.s(seqd(quote_reject('TOKQ3', ob=70618)))
    c.s(seqd(quote_reject('TOKQ3', ob=70618, code=-5)))
    c.s(seqd(quote_reject('TOKQ3', ob=70618, code=-6, extra=b'\x22' * 4)))
    # Orderbook tracking cases: replace with both tokens unseen
    c.c(unseq(replace_order('TOK5', 'TOK6')))
    # replace whose ROT is a chain and EOT is new (EOT differs from the
    # chain's initial token)
    c.c(unseq(enter_order('TOK7')))
    c.c(unseq(replace_order('TOK8', 'TOK7')))
    # replace joining two chains (TOK5/TOK6 and TOK3)
    c.c(unseq(replace_order('TOK5', 'TOK3')))
    # Several SoupBinTCP packets in one segment: server heartbeat and a
    # debug message; client heartbeat and a cancel by order ID
    c.s(soup(b'H') + soup(b'+', b'debug text'))
    c.c(soup(b'R') + unseq(cancel_by_id(order_id=5000010)))
    # An Order Accepted split over two segments (reassembly)
    m = seqd(accepted('TOK7', order_id=5000007))
    c.s(m[:60], m[60:])
    c.c(soup(b'O'))
    # Data whose first octet is no BIST OUCH (nor OUCH) message type
    c.c(unseq(b'Mnot-ouch'))
    c.s(soup(b'Z'))
    c.close()
    # Second session: Order Replaced messages whose previous token was never
    # seen (chains without an initial token), and chains joined twice
    c2 = Conn(cap, CLIENT2, 50002)
    c2.c(login_request(user='TRADE2', session='SESSION01', seq=20))
    c2.s(soup(b'H'))
    c2.c(unseq(enter_order('TOK20', qty=42, price=1)))
    c2.s(seqd(accepted('TOK20', order_id=5000020, qty=42, price=1)))
    c2.s(seqd(order_replaced('TOK21', 'TOK9', order_id=5000021)))
    c2.s(seqd(order_replaced('TOK11', 'TOK10', order_id=5000022)))
    # Replace naming both tokens of the TOK10 chain (no initial token yet)
    c2.c(unseq(replace_order('TOK10', 'TOK11')))
    # Chains TOK30 and TOK40 (with TOK41), joined, then joined to TOK21's
    # chain, which is older and has no initial token
    c2.c(unseq(enter_order('TOK30')))
    c2.c(unseq(enter_order('TOK40')))
    c2.c(unseq(replace_order('TOK40', 'TOK41')))
    c2.c(unseq(replace_order('TOK30', 'TOK40')))
    c2.c(unseq(replace_order('TOK21', 'TOK30')))
    # TOK41 still maps to the TOK40 chain, two levels below the root
    c2.c(unseq(cancel_order('TOK41')))
    c2.s(seqd(executed('TOK21', qty=42, price=1)))
    c2.close()
    cap.write(path)


def malformed_capture(path):
    cap = Pcap()
    c = Conn(cap, CLIENT, 50003)
    c.c(login_request())
    c.s(login_accept())
    # Every type with five zero octets after the type
    for t in b'OUXYQAJCEKR':
        msg = bytes([t]) + b'\0' * 5
        (c.c if t in b'OUXYQ' else c.s)(unseq(msg) if t in b'OUXYQ' else seqd(msg))
    # Only the type octet of an inbound U
    c.c(unseq(b'U'))
    # Order Replaced recognized by its timestamp but 140 octets long
    c.s(seqd(order_replaced('TOKM1', 'TOKM0')[:140]))
    # Replace Order 100 octets long (EOT starting with a control character,
    # so not taken for Order Replaced)
    c.c(unseq(replace_order('\x01TOKM2', 'TOKM3')[:100]))
    # Replace Order with 8 trailing octets and a printable EOT: taken for an
    # Order Replaced by the timestamp heuristic, and too short for it
    c.c(unseq(replace_order('TOKM4', 'TOKM5', extra=b'\xee' * 8)))
    # Mass quote with a huge entry count and few octets (from
    # bist_ouch_tracking.py)
    c.c(unseq(b'Q' + tok('TOKQ') + b'\x01' + b'A' * 16 + b'E' * 16 + struct.pack('>H', 65535) + b'\0' * 60))
    c.close()
    # Exported PDUs naming the "bist-ouch" dissector, which is the only way
    # to reach its unknown message type case (the heuristic rejects unknown
    # types): an unknown type with and without a body
    epdus = [b'Z' + b'unknown', b'Z']
    write_pcapng(path, cap.frames, epdus)


def epdu(payload, name='bist-ouch'):
    v = name.encode()
    v += b'\0' * ((-len(v)) % 4)
    return struct.pack('>HH', 12, len(v)) + v + struct.pack('>HH', 0, 0) + payload


def write_pcapng(path, eth_frames, epdu_payloads):
    """pcapng with interface 0 Ethernet and interface 1 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = [block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)),
           block(1, struct.pack('<HHI', 1, 0, 65535)),
           block(1, struct.pack('<HHI', 252, 0, 65535))]
    t = 1761700000 * 1000000
    recs = [(0, f) for f in eth_frames] + [(1, epdu(p)) for p in epdu_payloads]
    for i, (ifid, f) in enumerate(recs):
        ts = t + i * 1000000
        out.append(block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                        len(f), len(f)) + f))
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(os.path.join(out, 'bist_ouch-coverage.pcap'))
    malformed_capture(os.path.join(out, 'bist_ouch-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/corosync_totemsrp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Totem Single Ring
Protocol dissector of the Corosync cluster engine
(packet-corosync-totemsrp.c).

Totem SRP messages travel over UDP ports 5404-5405 (registered for
corosync_totemnet, which hands unencrypted packets to corosync_totemsrp).
A message starts with a type, an encapsulation octet, an endian detector
(0x22FF little-endian, 0xFF22 big-endian) and the sender's node ID; every
later integer is in the byte order the detector gives. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkcorosync_totemsrp.py <output directory>

Writes:
  corosync-totemsrp-coverage.pcap            every message type in both
                                             byte orders, every address
                                             family, retransmission lists,
                                             processor and failed lists,
                                             commit token entries,
                                             encapsulated mcast messages and
                                             packets that are not Totem SRP
  corosync-totemsrp-coverage-malformed.pcap  truncated messages, entry
                                             counts past the end and
                                             encapsulation nested past the
                                             dissection depth limit
"""

import os
import struct
import sys

PORT = 5405
NODE = {1: bytes([192, 0, 2, 1]), 2: bytes([192, 0, 2, 2]), 3: bytes([192, 0, 2, 3])}
MCAST_IP = bytes([239, 192, 104, 1])

AF_INET = 2
AF_INET6 = {'bsd': 24, 'freebsd': 28, 'darwin': 30, 'linux': 10, 'solaris': 26,
            'winsock': 23}

ORF, MCAST, MERGE, JOIN, COMMIT, CANCEL = range(6)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(src, dst, payload, ident, sport=PORT, dport=PORT):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, 8 + len(payload))
    c = csum(pseudo + udp + payload) or 0xffff
    udp = udp[:6] + struct.pack('>H', c)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + 8 + len(payload), ident, 0,
                     64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac = b'\x02\x00\x00\x00\x00' + bytes([src[3]])
    if dst[0] >= 224:
        dmac = b'\x01\x00\x5e' + bytes([dst[1] & 0x7f, dst[2], dst[3]])
    else:
        dmac = b'\x02\x00\x00\x00\x00' + bytes([dst[3]])
    return dmac + smac + b'\x08\x00' + ip + udp + payload


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        t = 1767225600
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', t + i // 10, (i % 10) * 100000, len(fr), len(fr)))
            f.write(fr)


class Totem:
    """Builds Totem SRP structures in one byte order."""

    def __init__(self, little):
        self.e = '<' if little else '>'
        self.detector = b'\x22\xff' if little else b'\xff\x22'

    def u16(self, v):
        return struct.pack(self.e + 'H', v)

    def u32(self, v):
        return struct.pack(self.e + 'I', v & 0xffffffff)

    def u64(self, v):
        return struct.pack(self.e + 'Q', v)

    def header(self, mtype, encap, nodeid):
        return struct.pack('BB', mtype, encap) + self.detector + self.u32(nodeid)

    def ip(self, nodeid, family=AF_INET, addr=None):
        if family == AF_INET:
            a = (addr or bytes([192, 0, 2, nodeid & 0xff])) + b'\0' * 12
        else:
            a = addr or (bytes.fromhex('20010db8000000000000000000000000')[:15] +
                         bytes([nodeid & 0xff]))
        return self.u32(nodeid) + self.u16(family) + a

    def ring_id(self, nodeid, seq, family=AF_INET):
        return self.ip(nodeid, family) + self.u64(seq)

    def srp_addr(self, nodeid, fam0=AF_INET, fam1=AF_INET, nodeid1=None):
        return self.ip(nodeid, fam0) + self.ip(nodeid if nodeid1 is None else nodeid1, fam1)

    def rtr_item(self, nodeid, ring_seq, seq, family=AF_INET):
        return self.ring_id(nodeid, ring_seq, family) + self.u32(seq)

    def orf_token(self, sender, seq, token_seq, aru, aru_addr, ring, backlog, fcc,
                  retrans, rtr=()):
        body = (self.u32(seq) + self.u32(token_seq) + self.u32(aru) + self.u32(aru_addr) +
                ring + self.u32(backlog) + self.u32(fcc) + self.u32(retrans) +
                self.u32(len(rtr)) + b''.join(rtr))
        return self.header(ORF, 0, sender) + body

    def mcast(self, sender, encap, system_from, seq, this_seqno, ring, node_id,
              guarantee, payload):
        return (self.header(MCAST, encap, sender) + system_from + self.u32(seq) +
                self.u32(this_seqno) + ring + self.u32(node_id) + self.u32(guarantee) +
                payload)

    def merge_detect(self, sender, system_from, ring):
        return self.header(MERGE, 0, sender) + system_from + ring

    def join(self, sender, system_from, ring_seq, procs, failed):
        return (self.header(JOIN, 0, sender) + system_from + self.u32(len(procs)) +
                self.u32(len(failed)) + self.u64(ring_seq) + b''.join(procs) +
                b''.join(failed))

    def memb_entry(self, ring, aru, high_delivered, received):
        return ring + self.u32(aru) + self.u32(high_delivered) + self.u32(received)

    def commit(self, sender, token_seq, ring, retrans, memb_index, addrs, entries,
               count=None):
        return (self.header(COMMIT, 0, sender) + self.u32(token_seq) + ring +
                self.u32(retrans) + self.u32(memb_index) +
                self.u32(len(addrs) if count is None else count) + b''.join(addrs) +
                b''.join(entries))

    def cancel(self, sender, ring):
        return self.header(CANCEL, 0, sender) + ring


def main_frames():
    frames = []
    ident = [0x100]

    def add(src, dst, payload):
        ident[0] += 1
        frames.append(udp_frame(src, dst, payload, ident[0]))

    n1, n2, n3 = NODE[1], NODE[2], NODE[3]

    # ---- little-endian (Linux x86) ring, IPv4 addresses ----
    le = Totem(True)
    ring = le.ring_id(1, 0x1004)
    # 1: ORF token without retransmission entries
    add(n1, n2, le.orf_token(1, 7, 20, 18, 1, ring, 0, 3, 0))
    # 2: ORF token with two retransmission entries; the token_seq field
    #    (20 -> 21) and seq (8) differ, see the fix on the branch
    add(n2, n3, le.orf_token(2, 8, 21, 19, 2, ring, 5, 4, 1,
                             [le.rtr_item(1, 0x1004, 19), le.rtr_item(3, 0x1004, 21)]))
    # 3: the reproducer of the fix: a not-encapsulated mcast message; the
    #    node ID (0x0a0b0c0d) and guarantee (2) belong in the mcast subtree
    add(n1, MCAST_IP, le.mcast(1, 2, le.srp_addr(1), 22, 21, ring, 0x0a0b0c0d, 2,
                               b'corosync cpg payload'))
    # 4: an encapsulated mcast message (a message retransmitted on behalf
    #    of another node) holding a not-encapsulated mcast message
    inner = le.mcast(3, 2, le.srp_addr(3), 19, 19, ring, 3, 1, b'retransmitted payload')
    add(n2, MCAST_IP, le.mcast(2, 1, le.srp_addr(2), 23, 22, ring, 2, 0, inner))
    # 5: merge detect
    add(n3, MCAST_IP, le.merge_detect(3, le.srp_addr(3), le.ring_id(3, 0x1008)))
    # 6: join with two processors and one failed processor
    add(n1, MCAST_IP, le.join(1, le.srp_addr(1), 0x100c,
                              [le.srp_addr(1), le.srp_addr(2)], [le.srp_addr(3)]))
    # 7: commit token with three members
    ring2 = le.ring_id(1, 0x100c)
    add(n1, n2, le.commit(1, 1, ring2, 0, 1,
                          [le.srp_addr(1), le.srp_addr(2), le.srp_addr(3)],
                          [le.memb_entry(le.ring_id(1, 0x1004), 22, 22, 1),
                           le.memb_entry(le.ring_id(1, 0x1004), 21, 20, 0),
                           le.memb_entry(le.ring_id(3, 0x1008), 5, 5, 1)]))
    # 8: token hold cancel
    add(n2, MCAST_IP, le.cancel(2, ring2))

    # ---- big-endian ring, IPv6 addresses with every AF_INET6 value ----
    be = Totem(False)
    f = AF_INET6
    ring6 = be.ring_id(1, 0x2000, f['linux'])
    # 9: ORF token, one retransmission entry (Solaris AF_INET6)
    add(n1, n2, be.orf_token(1, 30, 40, 39, 1, ring6, 2, 1, 1,
                             [be.rtr_item(2, 0x2000, 40, f['solaris'])]))
    # 10: not-encapsulated mcast, system_from with BSD and FreeBSD AF_INET6
    add(n2, MCAST_IP, be.mcast(2, 2, be.srp_addr(2, f['bsd'], f['freebsd']), 41, 41,
                               ring6, 2, 3, b'big-endian payload'))
    # 11: encapsulated mcast holding an encapsulated mcast holding a
    #     not-encapsulated one (two levels), Darwin and Windows AF_INET6
    inner2 = be.mcast(3, 2, be.srp_addr(3, f['darwin'], f['winsock']), 35, 35, ring6, 3,
                      0, b'')
    inner1 = be.mcast(2, 1, be.srp_addr(2, f['winsock'], f['darwin']), 36, 36, ring6, 2,
                      0, inner2)
    add(n1, MCAST_IP, be.mcast(1, 1, be.srp_addr(1, f['linux'], f['linux']), 42, 41,
                               ring6, 1, 0, inner1))
    # 12: merge detect, an unknown address family (99) on the second
    #     interface and AF_INET on the first
    add(n3, MCAST_IP, be.merge_detect(3, be.srp_addr(3, AF_INET, 99),
                                      be.ring_id(3, 0x2004, f['darwin'])))
    # 13: join without processors or failed processors
    add(n2, MCAST_IP, be.join(2, be.srp_addr(2, f['linux'], f['linux']), 0x2008, [], []))
    # 14: join with one processor and two failed processors
    add(n1, MCAST_IP, be.join(1, be.srp_addr(1, f['linux'], f['linux']), 0x2008,
                              [be.srp_addr(1, f['linux'], f['linux'])],
                              [be.srp_addr(2, f['linux'], AF_INET),
                               be.srp_addr(3, f['freebsd'], f['bsd'])]))
    # 15: commit token with no entries
    add(n1, n2, be.commit(1, 2, be.ring_id(1, 0x2008, f['linux']), 1, 0, [], []))
    # 16: commit token with one entry
    add(n2, n1, be.commit(2, 3, be.ring_id(1, 0x2008, f['linux']), 0, 0,
                          [be.srp_addr(2, f['linux'], f['linux'])],
                          [be.memb_entry(be.ring_id(1, 0x2000, f['linux']), 42, 41, 1)]))
    # 17: token hold cancel (unknown address family 0)
    add(n1, MCAST_IP, be.cancel(1, be.ring_id(1, 0x2008, 0)))

    # ---- UDP 5405 packets that are not Totem SRP (shown as data) ----
    # 18: too short for a message header
    add(n3, n1, b'\x00\x00\x22\xff\x01')
    # 19: message type 6 (past cancel)
    add(n3, n1, le.header(6, 0, 3) + b'\0' * 30)
    # 20: an endian detector that is neither 0x22FF nor 0xFF22
    add(n3, n1, b'\x00\x00\x12\x34' + b'\0' * 60)
    # 21: a little-endian ORF token from the other port (5404)
    ident[0] += 1
    frames.append(udp_frame(n3, n1, le.orf_token(3, 9, 22, 22, 3, ring, 0, 0, 0),
                            ident[0], 5404, 5404))
    # 22: an mcast with an empty payload and guarantee 0, little-endian
    add(n2, MCAST_IP, le.mcast(2, 2, le.srp_addr(2), 24, 24, ring, 2, 0, b''))
    return frames


def malformed_frames():
    frames = []
    ident = [0x900]

    def add(payload, dst=NODE[2]):
        ident[0] += 1
        frames.append(udp_frame(NODE[1], dst, payload, ident[0]))

    le = Totem(True)
    be = Totem(False)
    ring = le.ring_id(1, 0x1004)
    # 1: ORF token cut inside the ring ID
    add(le.orf_token(1, 1, 2, 2, 1, ring, 0, 0, 0)[:30])
    # 2: ORF token claiming 1000 retransmission entries, holding one
    add(le.orf_token(1, 1, 2, 2, 1, ring, 0, 0, 0, [le.rtr_item(1, 1, 1)])[:-38] +
        le.u32(1000) + le.rtr_item(1, 1, 1))
    # 3: mcast cut inside system_from
    add(le.mcast(1, 2, le.srp_addr(1), 1, 1, ring, 1, 0, b'')[:30], MCAST_IP)
    # 4: encapsulated mcast whose inner message is cut
    inner = le.mcast(1, 2, le.srp_addr(1), 1, 1, ring, 1, 0, b'')[:50]
    add(le.mcast(1, 1, le.srp_addr(1), 1, 1, ring, 1, 0, inner), MCAST_IP)
    # 5: join with 0xffffffff processors
    j = be.join(1, be.srp_addr(1), 1, [], [])
    add(j[:8 + 44] + be.u32(0xffffffff) + j[8 + 48:], MCAST_IP)
    # 6: join with one failed processor missing
    j = le.join(1, le.srp_addr(1), 1, [le.srp_addr(1)], [le.srp_addr(2)])
    add(j[:-20], MCAST_IP)
    # 7: commit token claiming 0x10000 entries, holding one
    add(be.commit(1, 1, be.ring_id(1, 1), 0, 0, [be.srp_addr(1)],
                  [be.memb_entry(be.ring_id(1, 1), 0, 0, 0)], count=0x10000))
    # 8: merge detect cut in the ring ID
    add(le.merge_detect(1, le.srp_addr(1), ring)[:60], MCAST_IP)
    # 9: hold cancel cut
    add(be.cancel(1, be.ring_id(1, 1))[:20], MCAST_IP)
    # 10: encapsulated mcast messages nested 600 deep (past the dissection
    #     depth or tree depth limit; throws instead of recursing further)
    m = le.mcast(1, 2, le.srp_addr(1), 1, 1, ring, 1, 0, b'innermost')
    for _ in range(600):
        m = le.mcast(1, 1, le.srp_addr(1), 1, 1, ring, 1, 0, m)
    add(m, MCAST_IP)
    # 11: commit token cut inside the member entries
    add(le.commit(1, 1, ring, 0, 0, [le.srp_addr(1)],
                  [le.memb_entry(ring, 0, 0, 0)])[:-10])
    # 12: an IPv6 address cut short
    add(le.cancel(1, le.ring_id(1, 1, AF_INET6['linux']))[:8 + 10], MCAST_IP)
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'corosync-totemsrp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'corosync-totemsrp-coverage-malformed.pcap'),
               malformed_frames())


if __name__ == '__main__':
    main()

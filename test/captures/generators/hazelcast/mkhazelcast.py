#!/usr/bin/env python3
# Generates test/captures/hazelcast_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Hazelcast dissector
(packet-hazelcast.c).

The Hazelcast wire protocol (version 6, TCP port 5701) has a 13 octet
header (message length, key length, value length, version) followed by
operation, block id, thread id, a flags octet that selects optional
fields (lock count, timeout, ttl, transaction id, long value, version),
an optional lock address, call id, response type, a name, an index
count, two partition hashes, the key and the value. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkhazelcast.py <output directory>

Writes:
  hazelcast-coverage.pcap            requests/responses for every
                                     operation in the value strings,
                                     every one of the 256 flag
                                     combinations, names, keys, values,
                                     messages split over several
                                     segments, several per segment,
                                     an unsupported version
  hazelcast-coverage-malformed.pcap  a length that wraps around, fields
                                     past the end of the message
"""

import os
import struct
import sys

# ---------------------------------------------------------------- network
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([10, 0, 0, 1])
IP_B = bytes([10, 0, 0, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip4(proto, payload, src, dst):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64,
                      proto, 0, src, dst)
    s = sum(struct.unpack('>10H', hdr))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('>H', (~s) & 0xffff) + hdr[12:]
    return hdr + payload


def eth_ip(proto, payload, to_b):
    if to_b:
        return MAC_B + MAC_A + b'\x08\x00' + ip4(proto, payload, IP_A, IP_B)
    return MAC_A + MAC_B + b'\x08\x00' + ip4(proto, payload, IP_B, IP_A)


def udp(sport, dport, payload, to_b):
    return eth_ip(17, struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload, to_b)


class Tcp:
    """One TCP connection, A is the client."""

    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.seq = {True: 1000, False: 5000}

    def seg(self, payload, to_b, flags=0x18):
        s, d = (self.cport, self.sport) if to_b else (self.sport, self.cport)
        me, other = self.seq[to_b], self.seq[not to_b]
        hdr = struct.pack('>HHIIBBHHH', s, d, me, other, 0x50, flags, 65535, 0, 0)
        self.seq[to_b] += len(payload)
        return eth_ip(6, hdr + payload, to_b)



def hz(op, flags=0x80, name=b'', key=b'', value=b'', block=1, thread=2,
       call=7, rtype=3, idx=0, khash=0x11111111, vhash=0x22222222,
       version=6, optional=None, msglen=None, keylen=None, vallen=None):
    """One message. 'optional' overrides the optional fields selected by
    the flags (default: counting values)."""
    opt = b''
    if optional is None:
        if flags & 0x01:
            opt += struct.pack('>I', 3)
        if flags & 0x02:
            opt += struct.pack('>Q', 5000)
        if flags & 0x04:
            opt += struct.pack('>Q', 60000)
        if flags & 0x08:
            opt += struct.pack('>Q', 0x1122334455667788)
        if flags & 0x10:
            opt += struct.pack('>Q', 424242)
        if flags & 0x20:
            opt += struct.pack('>Q', 9)
        if not flags & 0x80:
            opt += bytes([10, 1, 2, 3]) + struct.pack('>I', 5701)
    else:
        opt = optional
    rest = (bytes([op]) + struct.pack('>II', block, thread) + bytes([flags]) + opt
            + struct.pack('>QBI', call, rtype, len(name)) + name
            + bytes([idx]) + struct.pack('>II', khash, vhash))
    ml = len(rest) if msglen is None else msglen
    kl = len(key) if keylen is None else keylen
    vl = len(value) if vallen is None else vallen
    return struct.pack('>IIIB', ml, kl, vl, version) + rest + key + value


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    fr = []
    mal = []
    t = Tcp(52000, 5701)

    def send(c, to_b=True):
        fr.append(t.seg(c, to_b))

    # every operation, with a rotating flag set; the unknown values
    # 121 and 200 give "Unknown (0x..)"
    for op in list(range(0, 121)) + [121, 200, 255]:
        flags = (op * 37) & 0xff
        name = b'map-%d' % op if op % 3 == 0 else b''
        key = bytes([op]) * (op % 5) if op % 2 else b''
        value = b'v' * (op % 4)
        send(hz(op, flags, name, key, value, rtype=2 + op % 4, call=op), op % 2 == 0)
    # every flag combination
    for flags in range(256):
        send(hz(46, flags, b'flags', b'k', b'vv', call=1000 + flags), flags & 1 == 0)
    # response types, including ones with no value string
    for rt in (0, 1, 2, 3, 4, 5, 6, 255):
        send(hz(1, 0x80, b'resp', rtype=rt), False)
    # long names, key and value
    send(hz(37, 0x80, b'n' * 300, b'K' * 700, b'V' * 900))
    # an unsupported version: only the 12 octet fixed part and a note
    send(hz(37, 0x80, b'x', version=5))
    send(hz(37, 0x80, b'x', version=7), False)
    # several messages in one segment
    send(hz(3, 0x80) + hz(4, 0x80, b'two') + hz(5, 0x80, b'three', b'k', b'v'))
    # one message over three segments, then two segments each with the
    # end of one and the start of the next message
    big = hz(38, 0x7f, b'bigmap', b'KEY' * 40, b'VALUE' * 50, call=99)
    nxt = hz(46, 0x80, b'next', b'a', b'b', call=100)
    send(big[:20])
    send(big[20:100])
    send(big[100:] + nxt[:5])
    send(nxt[5:] + hz(3, 0x80, call=101)[:14])
    send(hz(3, 0x80, call=101)[14:])
    # a message of exactly the minimum size; message, key and value
    # lengths of zero
    send(hz(0, 0x80, b'', b'', b''))
    # a session on a second client port
    t2 = Tcp(52001, 5701)
    fr.append(t2.seg(hz(98, 0x80, b'authenticate', b'user', b'secret-placeholder'), True))
    fr.append(t2.seg(hz(1, 0x80, rtype=3, value=b'ok'), False))
    pcap(os.path.join(out, 'hazelcast-coverage.pcap'), fr)

    # --------------------------------------------------------- malformed
    port = [52100]

    def m(c):
        port[0] += 1
        mal.append(Tcp(port[0], 5701).seg(c, True))

    # message length smaller than the fields it holds: the name length
    # and the key run past the end of the PDU
    m(hz(37, 0x80, b'abc', b'key', b'value', msglen=12))
    m(hz(37, 0x80, b'abc', b'key', b'value', msglen=12)[:-3])
    # name length larger than the message
    m(hz(37, 0x80, b'abc')[:-0 or None].replace(struct.pack('>I', 3) + b'abc', struct.pack('>I', 3000) + b'abc'))
    # key and value lengths larger than the data
    m(hz(37, 0x80, b'abc', b'key', b'value', keylen=10))
    m(hz(37, 0x80, b'abc', b'key', b'value', vallen=10))
    # lengths summing up past 32 bits (the PDU length wraps around)
    m(hz(37, 0x80, b'abc', msglen=0xfffffff0, keylen=0x10, vallen=0x10))
    m(hz(37, 0x80, b'abc', msglen=0xffffffff, keylen=0xffffffff, vallen=0xffffffff))
    m(hz(37, 0x80, b'abc', msglen=0xffffffff, keylen=0, vallen=0))
    # flags select fields that are not there
    m(hz(37, 0x7f, b'', optional=b'\x00\x01'))
    # only a part of the header
    m(hz(37, 0x80, b'a')[:12])
    m(hz(37, 0x80, b'a')[:13])
    m(hz(37, 0x80, b'a')[:30])
    pcap(os.path.join(out, 'hazelcast-coverage-malformed.pcap'), mal)


main()

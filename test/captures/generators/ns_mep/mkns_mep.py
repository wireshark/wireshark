#!/usr/bin/env python3
# Generates test/captures/ns_mep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NetScaler GSLB metric exchange protocol (NS-MEP) coverage captures
(synthetic, struct only).

Usage: mkns_mep.py <outdir> [-v]

Writes, into <outdir>:
  ns-mep-coverage.pcap            main capture: Exported PDU frames (link type
                                  252) naming the "nstrace.mep" dissector
  ns-mep-coverage-malformed.pcap  truncated messages, cut entries
  ns-mep-tcp.pcap                 the same message types over TCP port 3011
                                  (needs Decode As tcp.port 3011): used by
                                  runcov.sh only
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv


def msg(maj, minr, mtype, body, errcode=0, mlen=None):
    """Header: major, minor, type (LE16), message length (LE16, the whole
    message), error code (LE16)."""
    n = 8 + len(body) if mlen is None else mlen
    return bytes([maj, minr]) + struct.pack('<HHH', mtype, n, errcode) + body


IP = lambda a, b, c, d: bytes([a, b, c, d])


def metric_update(ip, port, svc, state=7, eff=7, flag=1, newer=True):
    e = struct.pack('<HH', 1, state) + ip + struct.pack('!H', port) + struct.pack('<H', svc)
    return e + (bytes([eff, flag]) + b'\0\0' if newer else b'\0' * 4)


def force_req(ip, port, svc, flag=1, newer=True):
    e = ip + struct.pack('!H', port) + struct.pack('<I', svc)
    return e + (bytes([flag, 0]) if newer else b'\0\0')


def force_update(ip, port, svc, newer=True, n=1):
    e = struct.pack('<HH', 1, 7) + ip + struct.pack('!H', port) + struct.pack('<H', svc)
    e += (bytes([7, 1]) + b'\0\0' if newer else b'\0' * 4)
    e += struct.pack('<6I', 10 * n, 11 * n, 12 * n, 13 * n, 14 * n, 15 * n)
    e += struct.pack('<4Q', 1000 * n, 2000 * n, 3000 * n, 4000 * n)
    assert len(e) == 72
    return e


def netw(ip, rtt, hops):
    return ip + struct.pack('<H', rtt) + bytes([hops, 0])


def persist(ldns, serv, port, pid):
    return ldns + serv + struct.pack('<HH', port, pid)


def dom_info(ip, port, svc, dom, vs, cookie=b'', prefix=b'', persistence=1, timeout=300, flags=0):
    e = ip + struct.pack('!H', port) + struct.pack('<H', svc)
    e += bytes([len(dom), len(prefix), len(cookie), persistence]) + struct.pack('<II', timeout, len(vs))
    e += bytes([flags]) + b'\0\0'
    assert len(e) == 23
    return e + dom + cookie + vs + prefix


def flush_dom(ip, port, svc, dom):
    return ip + struct.pack('!H', port) + struct.pack('<H', svc) + bytes([len(dom)]) + dom


def getsvc(ip, port, svc, dom):
    return flush_dom(ip, port, svc, dom)


def getsvc_resp(ip, port, svc, dom, ttl):
    return ip + struct.pack('!H', port) + struct.pack('<H', svc) + bytes([len(dom)]) + struct.pack('<I', ttl) + dom


def expdu(data, name=b'nstrace.mep'):
    pad = (-len(name)) % 4
    return struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0) + data


def write_pcap(fname, frames, linktype):
    with open(os.path.join(OUT, fname), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def tcp_frame(payload, seq, sport=40000, dport=3011):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + tcp


RANGES = []


class Cap:
    def __init__(self, name, wrap=expdu):
        self.name, self.frames, self.wrap = name, [], wrap

    def add(self, data):
        self.frames.append(self.wrap(data) if self.wrap else data)
        return len(self.frames)

    def group(self, text):
        first = len(self.frames) + 1
        return lambda: RANGES.append((self.name, first, len(self.frames), text))


def messages():
    """(group text, [messages]) for the main capture."""
    out = []
    S = lambda i: IP(198, 51, 100, i)
    out.append(('SITE METRIC UPDATE: versions 1.0, 2.1, 2.2 (old layout), 2.3-2.6 (effective state, MEP flag); one to three entries; states and service types', [
        msg(1, 0, 1, metric_update(S(1), 80, 0, newer=False)),
        msg(2, 1, 1, metric_update(S(2), 443, 14, state=1, newer=False) + metric_update(S(3), 53, 15, state=2, newer=False)),
        msg(2, 2, 1, metric_update(S(4), 8080, 8, state=3, newer=False)),
        msg(2, 3, 1, metric_update(S(5), 80, 2, state=4, eff=5, flag=0)),
        msg(2, 4, 1, metric_update(S(6), 80, 3, state=5, eff=7, flag=1) + metric_update(S(7), 81, 4, state=7, eff=8, flag=2)
            + metric_update(S(8), 82, 0x27, state=8, eff=3, flag=3)),
        msg(2, 5, 1, metric_update(S(9), 5060, 0x24, state=9, eff=2, flag=0)),
        msg(2, 6, 1, metric_update(S(10), 554, 0x28, state=0, eff=1, flag=1)),
        msg(2, 3, 1, b''),
        msg(2, 3, 1, metric_update(S(11), 80, 0x99) + b'\x01\x02\x03'),   # trailing octets, unknown service type
    ]))
    out.append(('SITE METRIC FORCE REQ: old and new layout, several entries', [
        msg(2, 2, 2, force_req(S(1), 80, 0, newer=False)),
        msg(2, 3, 2, force_req(S(2), 443, 14, flag=1) + force_req(S(3), 80, 0, flag=2)),
    ]))
    out.append(('SITE ADV IP ADDR, ACK and NACK, KEEP ALIVE, NONE, CNAME PERSIST RECORD, SITE INFO, unknown message type', [
        msg(2, 3, 3, S(20)),
        msg(2, 3, 4, b''),
        msg(2, 3, 5, b''),
        msg(2, 3, 9, b''),
        msg(2, 3, 0, b''),
        msg(2, 3, 10, b'\0' * 4),
        msg(2, 3, 12, b'\0' * 4),
        msg(2, 3, 99, b'\0' * 4),
    ]))
    out.append(('SITE METRIC FORCE UPDATE: old and new layout, two entries', [
        msg(2, 2, 6, force_update(S(1), 80, 0, newer=False)),
        msg(2, 3, 6, force_update(S(2), 80, 0, n=1) + force_update(S(3), 443, 14, n=2)),
    ]))
    out.append(('NETWORK METRIC UPDATE, PERSIST RECORD', [
        msg(2, 3, 7, netw(IP(203, 0, 113, 1), 25, 9) + netw(IP(203, 0, 113, 2), 300, 15)),
        msg(2, 3, 8, persist(IP(203, 0, 113, 1), S(30), 80, 7) + persist(IP(203, 0, 113, 2), S(31), 443, 8)),
    ]))
    out.append(('DOMAIN INFO: plain, with a cookie domain, prefix, flags (none, flush all, undefined), two entries', [
        msg(2, 3, 11, dom_info(S(1), 80, 0, b'www.example.invalid', b'vserver1')),
        msg(2, 3, 11, dom_info(S(2), 443, 14, b'a.example.invalid', b'vs2', cookie=b'cookie.example.invalid', prefix=b'pre', flags=4)),
        msg(2, 3, 11, dom_info(S(3), 80, 0, b'b.example.invalid', b'vs3', prefix=b'p', flags=1)
            + dom_info(S(4), 80, 0, b'c.example.invalid', b'vs4', cookie=b'ck')),
    ]))
    out.append(('FLUSH DOMAIN, FLUSH SVC, GET SVC, GET SVC RESP', [
        msg(2, 3, 14, flush_dom(S(1), 80, 0, b'www.example.invalid')),
        msg(2, 3, 14, flush_dom(S(2), 80, 0, b'a.invalid') + flush_dom(S(3), 443, 14, b'b.invalid')),
        msg(2, 3, 13, S(1) + struct.pack('!H', 80) + struct.pack('<H', 0)),
        msg(2, 3, 15, getsvc(S(1), 80, 0, b'www.example.invalid')),
        msg(2, 3, 16, getsvc_resp(S(1), 80, 0, b'www.example.invalid', 30)),
    ]))
    out.append(('unknown MEP versions (0x0003, 0x0701, 0x0000, 0xffff): only the Info column says so', [
        msg(3, 0, 1, b'\0' * 16),
        msg(1, 7, 1, b'\0' * 16),
        msg(0, 0, 0, b''),
        msg(0xff, 0xff, 1, b'\0' * 8),
    ]))
    out.append(('two messages in one frame; the NetScaler RPC signature (0xA5A5 in the length field) hands the frame to the RPC dissector', [
        None,
        None,
    ]))
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    c = Cap('ns-mep-coverage.pcap')
    tc = Cap('ns-mep-tcp.pcap', wrap=None)
    seq = [1]
    for text, ms in messages():
        g = c.group(text)
        if ms[0] is None:
            a = msg(2, 3, 3, IP(198, 51, 100, 20))
            b = msg(2, 3, 4, b'')
            c.add(a + b)
            # RPC signature at offset 4
            c.add(struct.pack('<HHH', 0x0303, 0, 0xA5A5) + b'\0' * 14)
        else:
            for m in ms:
                c.add(m)
        g()
        for m in (ms if ms[0] is not None else []):
            tc.frames.append(tcp_frame(m, seq[0]))
            seq[0] += len(m)
    # the two messages and a message split over two segments, over TCP
    a = msg(2, 3, 3, IP(198, 51, 100, 20)) + msg(2, 3, 4, b'')
    tc.frames.append(tcp_frame(a, seq[0])); seq[0] += len(a)
    big = msg(2, 3, 7, netw(IP(203, 0, 113, 1), 25, 9) * 4)
    tc.frames.append(tcp_frame(big[:13], seq[0])); seq[0] += 13
    tc.frames.append(tcp_frame(big[13:], seq[0])); seq[0] += len(big) - 13
    write_pcap('ns-mep-coverage.pcap', c.frames, 252)
    write_pcap('ns-mep-tcp.pcap', tc.frames, 1)

    m = Cap('ns-mep-coverage-malformed.pcap')
    g = m.group('truncated messages and entries (exceptions), a length smaller than the header')
    good = msg(2, 3, 11, dom_info(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid', b'vs'))
    m.add(good[:6])
    m.add(good[:9])
    m.add(msg(2, 3, 11, dom_info(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid', b'vs')[:30], mlen=8 + 30))
    m.add(msg(2, 3, 11, dom_info(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid', b'vs')[:-1]))   # prefix/vs short by one
    m.add(msg(2, 3, 11, dom_info(IP(1, 2, 3, 4), 80, 0, b'x' * 200, b'vs', cookie=b'y' * 50)[:40]))
    m.add(msg(2, 3, 14, flush_dom(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid')[:12]))
    m.add(msg(2, 3, 15, getsvc(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid')[:10]))
    m.add(msg(2, 3, 16, getsvc_resp(IP(1, 2, 3, 4), 80, 0, b'www.example.invalid', 3)[:14]))
    m.add(msg(2, 3, 13, b'\0' * 5))
    m.add(msg(2, 3, 3, b'\0\0'))
    m.add(msg(2, 3, 1, metric_update(IP(1, 2, 3, 4), 80, 0)[:10]))
    m.add(msg(2, 3, 1, b'', mlen=0))
    m.add(msg(2, 3, 6, force_update(IP(1, 2, 3, 4), 80, 0)[:70]))
    m.add(b'\x03\x02\x01\x00\x08')
    m.add(b'\x03')
    g()
    write_pcap('ns-mep-coverage-malformed.pcap', m.frames, 252)
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(c.frames), len(m.frames), len(tc.frames))


main()

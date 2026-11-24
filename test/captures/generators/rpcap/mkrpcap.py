#!/usr/bin/env python3
# Generates test/captures/rpcap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the RPCAP (remote packet capture protocol) coverage captures.
# Usage: mkrpcap.py <outdir>
# Writes rpcap-coverage.pcapng (main, decodes cleanly) and rpcap-coverage-malformed.pcapng.
# Everything is built with struct; nothing comes from a real network.
import os
import struct
import sys

C, S = "192.0.2.1", "192.0.2.2"

def u(*v):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in v)


def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return u(len(b)) + b + b'\0' * (-len(b) % 4)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(payload):
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + payload


def exp_pdu(name, payload):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload


class Cap:
    """Frames with a running time stamp; pcapng with one IDB per link type."""
    def __init__(self):
        self.frames = []        # (linktype, bytes, usec)
        self.t = 1700000000 * 1000000
        self.n = 0

    def add(self, fr, lt=1, dt=1000, orig=None):
        self.t += dt
        self.frames.append((lt, fr, self.t, orig if orig else len(fr)))
        self.n += 1
        return self.n

    def udp(self, sport, dport, data, to_server=True, dt=1000, keep=None):
        src, dst = (C, S) if to_server else (S, C)
        h = struct.pack('!HHHH', sport, dport, 8 + len(data), 0)
        fr = eth(ipv4(17, h + data, src, dst))
        if keep is not None:
            return self.add(fr[:14 + 20 + 8 + keep], dt=dt, orig=len(fr))
        return self.add(fr, dt=dt)

    def write(self, fn):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        lts = []
        for lt, _, _, _ in self.frames:
            if lt not in lts:
                lts.append(lt)
        for lt in lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for lt, fr, ts, orig in self.frames:
            out += blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, len(fr), orig) + fr)
        open(fn, 'wb').write(out)


class Tcp:
    """One TCP connection; every call returns the frame number."""
    def __init__(self, cap, cport, sport, caddr=C, saddr=S):
        self.cap, self.cport, self.sport, self.caddr, self.saddr = cap, cport, sport, caddr, saddr
        self.cseq, self.sseq = 1000, 5000

    def _seg(self, to_server, flags, data, seq=None, dt=1000):
        if to_server:
            sp, dp, src, dst, s, a = self.cport, self.sport, self.caddr, self.saddr, self.cseq, self.sseq
        else:
            sp, dp, src, dst, s, a = self.sport, self.cport, self.saddr, self.caddr, self.sseq, self.cseq
        if seq is not None:
            s = seq
        if flags & 0x02:
            # SYN and SYN+ACK carry the MSS option; a SYN has no ACK number
            t = struct.pack('!HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0, 0x60, flags, 65535, 0, 0) \
                + b'\x02\x04\x05\xb4' + data
        else:
            t = struct.pack('!HHIIBBHHH', sp, dp, s, a, 0x50, flags, 65535, 0, 0) + data
        return self.cap.add(eth(ipv4(6, t, src, dst)), dt=dt)

    def handshake(self):
        self._seg(True, 0x02, b'')
        self.cseq += 1
        self._seg(False, 0x12, b'')
        self.sseq += 1
        self._seg(True, 0x10, b'')

    def c2s(self, data, dt=1000):
        n = self._seg(True, 0x18, data, dt=dt)
        self.cseq += len(data)
        return n

    def s2c(self, data, dt=1000):
        n = self._seg(False, 0x18, data, dt=dt)
        self.sseq += len(data)
        return n


PORT = 2002          # rpcapd's default port; found by the heuristics (nothing is registered)


def msg(typ, value=0, payload=b'', plen=None, ver=0):
    return struct.pack('!BBHI', ver, typ, value, len(payload) if plen is None else plen) + payload


def sa4(ip, af=2, port=0):
    return struct.pack('!HH', af, port) + bytes(int(x) for x in ip.split('.')) + b'\0' * 120


def sa6(addr_hex, af=23, port=0, flow=0, scope=0):
    return struct.pack('!HHI', af, port, flow) + bytes.fromhex(addr_hex) + struct.pack('!I', scope) + b'\0' * 100


def sa_unknown(af):
    return struct.pack('!H', af) + b'\xaa' * 126


def sa_unspec():
    return struct.pack('!H', 0) + b'\0' * 126


def iface(name, desc, flags, addrs):
    return struct.pack('!HHIHH', len(name), len(desc), flags, len(addrs), 0) + name.encode() + desc.encode() \
        + b''.join(b''.join(a) for a in addrs)


def bpf(code, jt, jf, k):
    return struct.pack('!HBBI', code, jt, jf, k)


def pkt_msg(inner, ts=1700000000, usec=0, n=1, caplen=None, ln=None):
    caplen = len(inner) if caplen is None else caplen
    ln = len(inner) if ln is None else ln
    body = struct.pack('!IIIII', ts, usec, caplen, ln, n) + inner
    return msg(7, 0, body)


def ip_udp(sport, dport, data, src='198.51.100.1', dst='198.51.100.2'):
    return ipv4(17, struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data, src, dst)


def eth_frame(ippkt):
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + ippkt


MARKS = []


def mark(cap, text):
    MARKS.append((cap.n + 1, text))


def main_capture(cap):
    inner = eth_frame(ip_udp(1000, 2000, b'hello'))
    # a link-layer type that no Open Reply has defined yet: the packet is shown as data
    mark(cap, 'UDP: a PACKET message before any OPEN_REPLY (the link-layer type is unknown: shown as data); '
              'reproducer of the link-type-per-pass fix')
    cap.udp(2002, 2002, pkt_msg(inner, n=1))
    mark(cap, 'Exported PDU: FINDALLIF reply with an IPv6 address (reproducer of the IPv6 padding fix)')
    body = b''.join([iface('eth0', 'First', 0x1, [(sa4('192.0.2.7'), sa4('255.255.255.0'), sa4('192.0.2.255'), sa4('0.0.0.0')),
                                                      (sa6('20010db8000000000000000000000001'), sa6('ffffffffffffffff0000000000000000'),
                                                       sa_unspec(), sa_unspec())])])
    cap.add(exp_pdu('rpcap', msg(0x82, 1, body)), lt=252)

    t = Tcp(cap, 50000, PORT)
    t.handshake()
    mark(cap, 'TCP: authentication: NULL request, empty reply (old server), reply with versions only; '
              'password request; replies with a big-endian, a little-endian and an invalid byte-order magic')
    t.c2s(msg(8, 0, struct.pack('!HHHH', 0, 0, 0, 0)))
    t.s2c(msg(0x88, 0, b''))
    t.c2s(msg(8, 0, struct.pack('!HHHH', 1, 0, 5, 6) + b'alice' + b'secret'))
    t.s2c(msg(0x88, 0, bytes([0, 1])))
    t.c2s(msg(8, 0, struct.pack('!HHHH', 0, 0, 0, 0)))
    t.s2c(msg(0x88, 0, bytes([0, 1]) + b'\0\0' + bytes([0xa1, 0xb2, 0xc3, 0xd4])))
    t.c2s(msg(8, 0, struct.pack('!HHHH', 0, 0, 0, 0)))
    t.s2c(msg(0x88, 0, bytes([0, 1]) + b'\0\0' + bytes([0xd4, 0xc3, 0xb2, 0xa1])))
    t.c2s(msg(8, 0, struct.pack('!HHHH', 0, 0, 0, 0)))
    t.s2c(msg(0x88, 0, bytes([0, 1]) + b'\0\0' + bytes([1, 2, 3, 4])))
    mark(cap, 'TCP: FINDALLIF request and reply: interfaces with IPv4, IPv6 (Winsock), BSD, Linux, '
              'HP-UX, AIX and Solaris style address families, unspecified and unknown families, '
              'no name or description, no addresses')
    t.c2s(msg(2))
    ifs = []
    ifs.append(iface('eth0', 'Ethernet adapter', 0x1, [
        (sa4('192.0.2.7'), sa4('255.255.255.0'), sa4('192.0.2.255'), sa4('0.0.0.0')),
        (sa6('20010db8000000000000000000000001'), sa6('ffffffffffffffff0000000000000000'), sa6('00' * 16), sa6('00' * 16, scope=3)),
    ]))
    ifs.append(iface('lo', '', 0x2, [(sa4('127.0.0.1', af=0x1002), sa4('255.0.0.0', af=0x1000), sa_unspec(), sa_unspec())]))
    ifs.append(iface('', 'Anonymous', 0, []))
    ifs.append(iface('bsd0', 'BSD', 0, [(sa6('fe80' + '00' * 12 + '0001', af=af), sa_unspec(), sa_unspec(), sa_unspec())
                                        for af in (0x1c18, 0x1c1c, 0x1c1e, 0x1c00, 10, 22, 24, 26)][:1]))
    for af in (0x1c1c, 0x1c1e, 0x1c00, 10, 22, 24, 26):
        ifs.append(iface('if%d' % af, 'AF %d' % af, 4, [(sa6('fe80' + '00' * 12 + '0001', af=af), sa_unspec(), sa_unspec(), sa_unspec())]))
    ifs.append(iface('weird0', 'unknown family', 0, [(sa_unknown(77), sa_unspec(), sa_unspec(), sa_unspec())]))
    t.s2c(msg(0x82, len(ifs), b''.join(ifs)))
    mark(cap, 'TCP: OPEN request and reply (Ethernet), START CAPTURE request with every flag and a BPF program, reply')
    t.c2s(msg(3, 0, b'eth0'))
    t.s2c(msg(0x83, 0, struct.pack('!Ii', 1, 3600)))
    ops = [bpf(0x28, 0, 0, 12), bpf(0x20, 0, 0, 0), bpf(0x01, 0, 0, 4), bpf(0x61, 0, 0, 0),
           bpf(0x02, 0, 0, 0), bpf(0x03, 0, 0, 1),
           bpf(0x04, 0, 0, 1), bpf(0x0c, 0, 0, 0),
           bpf(0x15, 1, 0, 0x800), bpf(0x25, 0, 0, 0), bpf(0x45, 0, 0, 1), bpf(0x05, 0, 0, 2), bpf(0x1d, 0, 1, 0),
           bpf(0x06, 0, 0, 0xffff), bpf(0x16, 0, 0, 0), bpf(0x07, 0, 0, 0), bpf(0x87, 0, 0, 0)]
    flt = struct.pack('!HHI', 0, 0, len(ops)) + b''.join(ops)
    t.c2s(msg(4, 0, struct.pack('!IIHH', 65535, 1000, 0x1f, 0) + flt))
    t.s2c(msg(0x84, 0, struct.pack('!IHH', 1000000, 2003, 0)))
    t.c2s(msg(4, 0, struct.pack('!IIHH', 96, 0, 0, 5000) + struct.pack('!HHI', 0, 0, 0)))
    mark(cap, 'TCP: PACKET messages: Ethernet frames (UDP, ICMP), '
              'two PACKET messages in one segment, one split in two segments')
    t.s2c(msg(0x84, 0, struct.pack('!IHH', 1000000, 2004, 0)))
    t.s2c(pkt_msg(inner, n=1, usec=1))
    t.s2c(pkt_msg(eth_frame(ipv4(1, b'\x08\x00\xf7\xff\0\0\0\0', '198.51.100.1', '198.51.100.2')), n=2, usec=2))
    p1 = pkt_msg(inner, n=4, usec=4)
    p2 = pkt_msg(inner, n=5, usec=5)
    t.s2c(p1 + p2)
    p3 = pkt_msg(inner, n=6, usec=6)
    t.s2c(p3[:20]); t.s2c(p3[20:], dt=5000)
    mark(cap, 'TCP: UPDATEFILTER request and reply, STATS request and reply, SETSAMPLING (none, 1 every N, '
              'first after N ms, unknown method) request and reply')
    t.c2s(msg(5, 0, struct.pack('!HHI', 0, 0, 2) + bpf(0x06, 0, 0, 0xffff) + bpf(0x06, 0, 0, 0)))
    t.s2c(msg(0x85, 0))
    t.c2s(msg(9))
    t.s2c(msg(0x89, 0, struct.pack('!IIII', 100, 2, 1, 98)))
    for method, val in ((0, 0), (1, 10), (2, 250), (9, 7)):
        t.c2s(msg(0x0b, 0, struct.pack('!BBHI', method, 0, 0, val)))
        t.s2c(msg(0x8b, 0))
    mark(cap, 'TCP: ERROR messages (error code in the value field; with text; without text), '
              'an unknown message type in a stream already identified as RPCAP')
    t.s2c(msg(1, 3, b'Authentication failed'))
    t.s2c(msg(1, 10, b''))
    t.s2c(msg(1, 16, b'bad message'))
    t.c2s(msg(0x20, 0, b'??'))
    t.c2s(msg(0x20, 0, b''))
    mark(cap, 'TCP: END CAPTURE request and reply, CLOSE')
    t.c2s(msg(0x0a))
    t.s2c(msg(0x8a))
    t.c2s(msg(6))

    # A second connection: another link-layer type; packet with a Linux cooked header and a raw IP packet
    mark(cap, 'TCP, second connection: OPEN reply with link-layer type 113 (Linux cooked), PACKET; '
              'then type 9999 (unsupported: shown as data) and 101 (raw IP)')
    t2 = Tcp(cap, 50001, PORT)
    t2.handshake()
    t2.c2s(msg(3, 0, b'any'))
    t2.s2c(msg(0x83, 0, struct.pack('!Ii', 113, 0)))
    sll = struct.pack('!HHH', 0, 1, 6) + bytes.fromhex('020000000001') + b'\0\0' + b'\x08\x00' + ip_udp(1000, 2000, b'sll')
    t2.s2c(pkt_msg(sll, n=1))
    t2.s2c(msg(0x83, 0, struct.pack('!Ii', 9999, 0)))
    t2.s2c(pkt_msg(b'\x01\x02\x03\x04', n=3))
    t2.c2s(msg(3, 0, b'tun0'))
    t2.s2c(msg(0x83, 0, struct.pack('!Ii', 101, 0)))
    t2.s2c(pkt_msg(ip_udp(1000, 2000, b'raw'), n=2))
    # Every message type as the first message of a connection: the heuristic checks the length of each
    mark(cap, 'TCP, one message per connection (no handshake): each message type as the first PDU, '
              'which the heuristic accepts only with the right length')
    singles = [(2, 0, b''), (5 + 0x80, 0, b''), (9, 0, b''), (6, 0, b''), (0x8b, 0, b''), (0x0a, 0, b''), (0x8a, 0, b''),
               (0x83, 0, struct.pack('!Ii', 1, 0)), (0x84, 0, struct.pack('!IHH', 1000, 2003, 0)),
               (0x0b, 0, struct.pack('!BBHI', 1, 0, 0, 4)), (0x89, 0, struct.pack('!IIII', 1, 2, 3, 4)),
               (7, 0, struct.pack('!IIIII', 1700000000, 0, len(inner), len(inner), 1) + inner),
               (0x82, 1, iface('wlan0', 'one', 1, [])), (1, 5, b'Open failed'), (1, 0, b'no code'),
               (3, 0, b'eth1'), (4, 0, struct.pack('!IIHH', 96, 0, 0, 5000) + struct.pack('!HHI', 0, 0, 1) + bpf(6, 0, 0, 96)),
               (5, 0, struct.pack('!HHI', 0, 0, 1) + bpf(6, 0, 0, 96)), (8, 0, struct.pack('!HHHH', 0, 0, 0, 0)),
               (0x88, 0, bytes([0, 1]))]
    for i, (typ, val, pay) in enumerate(singles):
        ts = Tcp(cap, 51000 + i, PORT)
        ts.c2s(msg(typ, val, pay))
    mark(cap, 'TCP, a connection that does not carry RPCAP (rejected by the heuristics)')
    ts = Tcp(cap, 51100, PORT)
    ts.c2s(b'This is not an RPCAP message at all, it is text.\r\n')
    # UDP: packets after the opens (the link type of the last open is in effect)
    mark(cap, 'UDP: a PACKET message after the Open replies (the last Open reply in the capture sets Ethernet); one that is not valid RPCAP stays UDP')
    cap.udp(2002, 2002, pkt_msg(eth_frame(ip_udp(1000, 2000, b'udp')), n=7))
    cap.udp(2002, 2002, b'\x00\x07\x00\x00')


def malformed_capture(cap):
    inner = eth_frame(ip_udp(1000, 2000, b'hello'))
    t = Tcp(cap, 50100, PORT)
    t.handshake()
    # truncated captured packets (caplen < len) and one shorter than an Ethernet header (the exception
    # is shown by RPCAP)
    t.s2c(pkt_msg(inner[:42], n=3, usec=3, ln=len(inner)))
    t.s2c(pkt_msg(inner[:5], n=9, usec=9))
    # PACKET with a capture length bigger than the message; the heuristic needs caplen == plen - 20
    t.s2c(msg(0x83, 0, struct.pack('!Ii', 1, 0)))
    t.s2c(msg(7, 0, struct.pack('!IIIII', 1700000000, 0, 200, 200, 1) + inner, plen=20 + len(inner)))
    # FINDALLIF reply without interfaces (the item has no data)
    t.c2s(msg(2))
    t.s2c(msg(0x82, 0, b''))
    # FINDALLIF reply: more interfaces and more addresses than the message holds
    t.s2c(msg(0x82, 5, iface('eth0', 'x', 1, [(sa4('192.0.2.7'), sa4('255.255.255.0'), sa4('192.0.2.255'), sa4('0.0.0.0'))] * 3)[:-300]))
    t.s2c(msg(0x82, 3, struct.pack('!HHIHH', 4, 0, 1, 2, 0) + b'eth0' + sa4('192.0.2.7') + sa4('255.255.255.0') + sa4('192.0.2.255') + sa4('0.0.0.0')))
    # filters with fewer instructions than announced
    t.c2s(msg(5, 0, struct.pack('!HHI', 0, 0, 5) + bpf(0x06, 0, 0, 1)))
    t.c2s(msg(4, 0, struct.pack('!IIHH', 65535, 0, 0, 0) + struct.pack('!HHI', 0, 0, 3)))
    # truncated start capture request and open reply, sampling request, auth request
    t.c2s(msg(4, 0, b'\0' * 6))
    t.s2c(msg(0x83, 0, b'\0\0'))
    t.c2s(msg(8, 0, struct.pack('!HHHH', 1, 0, 300, 300) + b'abc'))
    # a message whose payload length is shorter than the structure it holds
    t.s2c(msg(0x89, 0, b'\0' * 16, plen=16)[:12])
    # the length of the payload is not the rest of the segment
    t.c2s(msg(3, 0, b'eth0')[:9])
    t.c2s(msg(2) + b'\x00\x02')
    # Exported PDU entry point with a PACKET message whose caplen is too big
    cap.add(exp_pdu('rpcap', msg(7, 0, struct.pack('!IIIII', 1, 0, 500, 500, 1) + inner[:20])), lt=252)
    # first messages of a connection that the heuristic rejects: wrong version, an invalid error code,
    # payload where none is allowed, wrong sizes for the fixed size messages, a PACKET with a wrong
    # capture length, a variable length message whose length field is not the length of the rest
    bad = [msg(2, 0, b'', ver=1), msg(1, 99, b'x'), msg(2, 0, b'abcd'), msg(2, 0, b'', plen=4),
           msg(0x83, 0, b'\0' * 4), msg(0x83, 0, b'\0' * 8, plen=9), msg(0x89, 0, b'\0' * 8),
           msg(7, 0, b'\0' * 10, plen=10), msg(7, 0, struct.pack('!IIIII', 1, 0, 9, 9, 1) + b'abcde'),
           msg(7, 0, struct.pack('!IIIII', 1, 0, 70000, 70000, 1) + b'abcde', plen=70020),
           msg(3, 0, b'eth0', plen=7), msg(8, 0, b'\0' * 8, plen=3), msg(0x82, 1, b'', plen=5),
           msg(0x30, 0, b''), msg(0x0c, 0, b'')]
    for i, b in enumerate(bad):
        Tcp(cap, 51200 + i, PORT).c2s(b)
    # UDP RPCAP that is rejected by the heuristics: the version, the type and the payload length
    cap.udp(2002, 2002, b'\x01\x07\x00\x00\x00\x00\x00\x14' + b'\0' * 20)
    cap.udp(2002, 2002, b'\x00\x07\x00\x01\x00\x00\x00\x14' + b'\0' * 20)
    cap.udp(2002, 2002, b'\x00\x02\x00\x00\x00\x00\x00\x00')
    cap.udp(2002, 2002, b'\x00\x07\x00\x00\x00\x00\x00\x08' + b'\0' * 8)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    cap = Cap()
    main_capture(cap)
    cap.write(os.path.join(out, 'rpcap-coverage.pcapng'))
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for n, text in MARKS:
            f.write('%d %s\n' % (n, text))
    print('main: %d frames' % cap.n)
    mc = Cap()
    malformed_capture(mc)
    mc.write(os.path.join(out, 'rpcap-coverage-malformed.pcapng'))
    print('malformed: %d frames' % mc.n)


if __name__ == '__main__':
    main()

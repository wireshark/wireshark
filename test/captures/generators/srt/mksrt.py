#!/usr/bin/env python3
# Generates test/captures/srt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SRT coverage captures: mksrt.py <outdir> [-v].  All data is synthetic."""
import os
import struct
import sys
import socket
from c17lib import Cap, udp, udp6

MAGIC = 0x4A17

def ctl(typ, addinfo, ts, sock, body=b'', ext=0):
    return struct.pack('>HHIII', 0x8000 | typ, ext, addinfo, ts, sock) + body

def peer_ip(addr):
    """The peer address of a handshake: 16 octets in 32 bit little endian words."""
    if ':' in addr:
        raw = socket.inet_pton(socket.AF_INET6, addr)
        return b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return bytes(int(x) for x in addr.split('.'))[::-1] + b'\0' * 12

def hs_body(version, enc_or_type, ext_or_magic, isn, mtu, win, reqtype, hsid, cookie, peer, ext=b''):
    ip = peer if isinstance(peer, bytes) else peer_ip(peer)
    return struct.pack('>IHHIIIiII', version, enc_or_type, ext_or_magic, isn, mtu, win, reqtype, hsid, cookie) + ip + ext

def hs_v4(reqtype, socktype, **kw):
    return ctl(0, 0, 100, 0, struct.pack('>IIIIIiII', 4, socktype, 1000, 1500, 8192, reqtype, 77, 0xabcd) + peer_ip('192.0.2.1'))

def blk(btype, words):
    """handshake extension block; words = payload (multiple of four octets)."""
    assert len(words) % 4 == 0
    return struct.pack('>HH', btype, len(words) // 4) + words

def hsreq(version=0x010501, flags=0x7f, peer_lat=120, agent_lat=130):
    return struct.pack('>IIHH', version, flags, peer_lat, agent_lat)

def km(kk=3, slen=4, klen=4, wrap=48, cipher=2, auth=0, se=2, v=1, pt=2, s=0):
    return (bytes([(s << 7) | (v << 4) | pt]) + b'\x20\x29' + bytes([kk]) + struct.pack('>I', 0) + bytes([cipher, auth, se, 0])
            + struct.pack('>H', 0) + bytes([slen, klen]) + b'\x11' * (4 * slen) + b'\xa5' * wrap)

def sid_words(text):
    t = text.encode()
    t += b'\0' * ((4 - len(t) % 4) % 4)
    out = b''
    for i in range(0, len(t), 4):
        out += t[i:i + 4][::-1]
    return out

def data(seq, msgno_bits, ts, sock, payload=b'synthetic payload'):
    return struct.pack('>IIII', seq, msgno_bits, ts, sock) + payload

def main(out, verbose):
    c = Cap(1)
    cl, sv = '192.0.2.10', '192.0.2.20'
    def tx(p, sport=4001, dport=4002, v6=False):
        c.add(udp6(sport, dport, p) if v6 else udp(sport, dport, p, cl, sv))
    def rx(p, sport=4002, dport=4001, v6=False):
        c.add(udp6(sport, dport, p, '2001:db8::2', '2001:db8::1') if v6 else udp(sport, dport, p, sv, cl))

    c.mark('Version 4 handshakes (induction, conclusion, a stream socket type). The UDT heuristic claims a conversation that starts with a version 4 handshake first, so these are shown as UDT; with the UDT heuristic disabled (runcov.sh) they reach the SRT version 4 path')
    tx(hs_v4(1, 2)); rx(hs_v4(1, 2))
    tx(hs_v4(-1, 2))
    tx(hs_v4(1, 1), 4010, 4011)
    c.mark('Version 5 (the conversation starts with the listener induction response, which carries the magic code; the capture is taken after the caller request): the version 4 induction request of the caller, conclusion with HSREQ, KMREQ, SID, CONGESTION, FILTER and GROUP extension blocks')
    rx(ctl(0, 0, 210, 0, hs_body(5, 4, MAGIC, 5000, 1500, 8192, 1, 0x1001, 0xc0ffee, '192.0.2.10')), 4004, 4003)
    tx(ctl(0, 0, 200, 0, hs_body(4, 0, 2, 5000, 1500, 8192, 1, 0x1001, 0, '192.0.2.10')), 4003, 4004)
    exts = (blk(1, hsreq()) + blk(3, km()) + blk(5, sid_words('#!::u=synthetic,r=stream1')) + blk(6, sid_words('live'))
            + blk(7, sid_words('fec,cols:10,rows:5')) + blk(8, struct.pack('>IBBH', 0x1234, 1, 0x10, 7)))
    tx(ctl(0, 0, 220, 0, hs_body(5, 0x04, 0x0007, 5000, 1500, 8192, -1, 0x1001, 0xc0ffee, '192.0.2.10', exts)), 4003, 4004)
    c.mark('Version 5 conclusion response (HSRSP, KMRSP, extension blocks that are not known, a bad HSREQ length, a short and a long group block)')
    rx(ctl(0, 0, 230, 0, hs_body(5, 0, 0x0003, 5001, 1500, 8192, -1, 0x2002, 0, '192.0.2.10',
        blk(2, hsreq(0x010501, 0x2f, 100, 100)) + blk(4, km(kk=1, wrap=24, se=0, cipher=4, auth=1)))), 4004, 4003)
    rx(ctl(0, 0, 231, 0, hs_body(5, 0, 0x0001, 5001, 1500, 8192, -1, 0x2002, 0, '192.0.2.10',
        blk(4, struct.pack('>I', 4)) + blk(2, b'\0' * 8) + blk(99, b'\0' * 8) + blk(8, b'\0' * 4) + blk(8, struct.pack('>IBBHI', 9, 2, 0, 3, 0)))), 4004, 4003)
    rx(ctl(0, 0, 232, 0, hs_body(5, 3, 0x0004, 5001, 1500, 8192, -1, 0x2002, 0, '192.0.2.10',
        blk(3, km(kk=2, slen=2, klen=2, wrap=16, se=1, cipher=0)))), 4004, 4003)
    c.mark('Rendezvous (waveahand, agreement) with IPv6 and IPv4 peer addresses (in little endian words) and an all zero peer address')
    ip6 = peer_ip('2001:db8::1')
    tx(ctl(0, 0, 240, 0, hs_body(5, 2, 0x0007, 7000, 1500, 8192, 0, 0x3003, 0, ip6)), 4005, 4006)
    rx(ctl(0, 0, 241, 0, hs_body(5, 2, 0x0007, 7000, 1500, 8192, -2, 0x3003, 0, peer_ip('2001:db8:1:2::9'))), 4006, 4005)
    tx(ctl(0, 0, 242, 0, hs_body(5, 2, 0x0007, 7000, 1500, 8192, -2, 0x3003, 0, peer_ip('10.0.0.1'))), 4005, 4006)
    tx(ctl(0, 0, 243, 0, hs_body(5, 2, 0x0007, 7000, 1500, 8192, -2, 0x3003, 0, peer_ip('0.0.0.0'))), 4005, 4006)
    c.mark('Handshake rejections: every reason code, internal, predefined and user defined ranges')
    for rej in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 999, 1000, 1999, 2000, 5000):
        rx(ctl(0, 0, 250, 0, hs_body(5, 0, 0, 0, 1500, 8192, 1000 + rej, 0x4004, 0, '192.0.2.10')), 4004, 4003)
    c.mark('Handshake in an IPv6 conversation')
    tx(ctl(0, 0, 260, 0, hs_body(5, 0, 0x0007, 7000, 1500, 8192, 1, 0x5005, 0, '192.0.2.10')), 4007, 4008, v6=True)
    rx(ctl(0, 0, 261, 0, hs_body(5, 0, 0x0007, 7000, 1500, 8192, 1, 0x5005, 0, '192.0.2.10')), 4008, 4007, v6=True)
    tx(data(1, 0xc0000001, 300, 0x5005), 4007, 4008, v6=True)

    c.mark('Control packets of the conversation 4003/4004: keepalive, ACK (full, with rate, light, short), ACKACK, congestion warning, shutdown, peer error')
    tx(ctl(1, 0, 1000, 0x2002), 4003, 4004)
    tx(ctl(2, 15, 1001, 0x2002, struct.pack('>IIII', 777, 40000, 5000, 8192) + struct.pack('>III', 1000, 1000000, 500)), 4003, 4004)
    tx(ctl(2, 16, 1002, 0x2002, struct.pack('>IIII', 778, 40000, 5000, 8192) + struct.pack('>II', 1000, 1000000)), 4003, 4004)
    tx(ctl(2, 17, 1003, 0x2002, struct.pack('>IIII', 779, 40000, 5000, 8192)), 4003, 4004)
    tx(ctl(2, 18, 1004, 0x2002, struct.pack('>I', 780)), 4003, 4004)
    rx(ctl(6, 15, 1006, 0x1001), 4004, 4003)
    tx(ctl(4, 0, 1007, 0x2002), 4003, 4004)
    tx(ctl(8, 6, 1008, 0x2002), 4003, 4004)
    tx(ctl(5, 0, 1009, 0x2002), 4003, 4004)
    c.mark('Loss reports (single sequence numbers, ranges, a range ending the report) and drop requests')
    tx(ctl(3, 0, 1010, 0x2002, struct.pack('>I', 100)), 4003, 4004)
    tx(ctl(3, 0, 1011, 0x2002, struct.pack('>II', 0x80000000 | 200, 210)), 4003, 4004)
    tx(ctl(3, 0, 1012, 0x2002, struct.pack('>IIIIII', 5, 0x80000000 | 20, 30, 40, 0x80000000 | 50, 60)), 4003, 4004)
    tx(ctl(3, 0, 1013, 0x2002, struct.pack('>II', 7, 0x80000000 | 9)), 4003, 4004)
    tx(ctl(3, 0, 1014, 0x2002), 4003, 4004)
    tx(ctl(7, 12, 1015, 0x2002, struct.pack('>II', 1000, 1010)), 4003, 4004)
    tx(ctl(7, 12, 1016, 0x2002), 4003, 4004)
    c.mark('Extended control packets: HSREQ and HSRSP, KMREQ and KMRSP (also the 4 octet error form), a KMREQ longer than the 104 octet limit, an EXT type that is not known, a control type that is not known')
    tx(ctl(0x7fff, 0, 1020, 0x2002, hsreq(), ext=1), 4003, 4004)
    rx(ctl(0x7fff, 0, 1021, 0x1001, hsreq(), ext=2), 4004, 4003)
    tx(ctl(0x7fff, 0, 1022, 0x2002, km(), ext=3), 4003, 4004)
    rx(ctl(0x7fff, 0, 1023, 0x1001, km(kk=3), ext=4), 4004, 4003)
    rx(ctl(0x7fff, 0, 1024, 0x1001, struct.pack('>I', 3), ext=4), 4004, 4003)
    tx(ctl(0x7fff, 0, 1025, 0x2002, km(wrap=120), ext=3), 4003, 4004)
    tx(ctl(0x7fff, 0, 1026, 0x2002, b'\0' * 8, ext=77), 4003, 4004)
    tx(ctl(0x7fff, 0, 1027, 0x2002, b'\0' * 4, ext=5), 4003, 4004)
    tx(ctl(12, 0, 1028, 0x2002), 4003, 4004)
    c.mark('Data packets: every packet boundary value, in-order flag, encryption key flags (none, even, odd), retransmission flag and message numbers')
    for i, bits in enumerate((0x00000001, 0x40000002, 0x80000003, 0xc0000004, 0xe0000005, 0xc8000006, 0xd0000007, 0xc4000008, 0xdc000009, 0x0fffffff)):
        tx(data(1000 + i, bits, 2000 + i, 0x2002, b'data packet %d, plain filler' % i), 4003, 4004)
    rx(data(0x7fffffff, 0xc0000001, 0xffffffff, 0x1001, b''), 4004, 4003)

    c.mark('UDP packets the heuristic rejects (shorter than 24 octets, not a handshake, handshake version 7)')
    tx(b'\x80\0\0\0' + b'\0' * 8, 4020, 4021)
    tx(ctl(1, 0, 5, 1, b'\0' * 12), 4020, 4021)
    tx(ctl(0, 0, 1, 0, hs_body(7, 0, 0x4A17, 1, 1500, 8192, 1, 1, 1, '192.0.2.10')), 4020, 4021)

    m = Cap(1)
    def mtx(p, sport=4001, dport=4002):
        m.add(udp(sport, dport, p, cl, sv))
    m.mark('An ACK with a rate but no link capacity, handshake extension blocks that are cut short or odd: block lengths past the packet, KMREQ with a negative wrap length, a huge salt length, empty SID blocks, group block of 4 octets')
    base = hs_body(5, 4, MAGIC, 5000, 1500, 8192, -1, 1, 2, '192.0.2.10')
    mtx(ctl(0, 0, 1, 0, base)); mtx(ctl(0, 0, 1, 0, base[:30]))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 3, 2) + b'\0' * 8))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 3, 5) + bytes(14) + b'\xff\x00' + bytes(4)))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 5, 0) + struct.pack('>HH', 5, 0)))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 8, 1) + b'\0' * 4))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 1, 40) + b'\0' * 8))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 5, 2) + b'\xff\xfe\x00\x41' * 2))
    mtx(ctl(0, 0, 1, 0, base + struct.pack('>HH', 1, 3) + b'\0' * 12 + struct.pack('>HH', 6, 1) + b'live'))
    mtx(ctl(2, 19, 1005, 0x2002, struct.pack('>IIII', 781, 40000, 5000, 8192) + struct.pack('>I', 1000)))
    m.mark('Truncated control packets and extended KMREQ with 0-39 octet payloads')
    for n in range(0, 40, 3):
        mtx(struct.pack('>HHIII', 0xffff, 3, 0, 0, 1) + b'\0' * n)
    for typ, n in ((2, 2), (2, 18), (2, 22), (3, 0), (7, 2), (6, 0), (1, 0), (5, 0)):
        mtx(ctl(typ, 0, 0, 1, b'\0' * n)[:16 + n - 1 if n else 15])
    c.write(os.path.join(out, 'srt-coverage.pcap'))
    m.write(os.path.join(out, 'srt-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)

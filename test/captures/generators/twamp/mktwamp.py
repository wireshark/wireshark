#!/usr/bin/env python3
# Generates test/captures/twamp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)


def tcp(payload, sport, dport, seq=1, ack=1, flags=0x18, src=IP_A, dst=IP_B):
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    return h[:16] + struct.pack('>H', c) + h[18:] + payload


def tcp_frame(payload, sport, dport, seq=1, ack=1, flags=0x18, down=False, ident=1):
    if down:
        return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags, src=IP_B, dst=IP_A), 6, src=IP_B, dst=IP_A, ident=ident), 0x0800, dst=MAC_A, src=MAC_B)
    return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags), 6, ident=ident), 0x0800)


class Tcp:
    """One TCP connection with consistent sequence numbers (client = IP_A)."""
    def __init__(self, cport, sport, ident=1):
        self.cport, self.sport, self.ident = cport, sport, ident
        self.cseq, self.sseq = 1000, 5000

    def c(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.cport, self.sport, self.cseq, self.sseq, 0x18, False, self.ident)
        self.cseq += len(payload)
        return f

    def s(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.sport, self.cport, self.sseq, self.cseq, 0x18, True, self.ident)
        self.sseq += len(payload)
        return f


def raw_eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload

# ---- twamp ----
# TWAMP-Control on TCP port 862 (default), TWAMP-Test on the UDP ports of the
# accepted sessions (conversation set by the control exchange), and
# OWAMP-Test, which has only Decode As (here UDP port 8760).
# Filler values are used for the key id, token, IVs and HMACs.
CPORT = 50862
SPORT = 862
V6A = bytes.fromhex('20010db8000000000000000000000001')
V6B = bytes.fromhex('20010db8000000000000000000000002')


def c6(payload, nh):
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + V6A + V6B + payload


class Tcp6:
    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000

    def _f(self, payload, sp, dp, seq, ack, down):
        src, dst = (V6B, V6A) if down else (V6A, V6B)
        h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0)
        pseudo = src + dst + struct.pack('>IBBBB', len(h) + len(payload), 0, 0, 0, 6)
        h = h[:16] + struct.pack('>H', csum(pseudo + h + payload)) + h[18:]
        ip = struct.pack('>IHBB', 0x60000000, len(h) + len(payload), 6, 64) + src + dst + h + payload
        return eth(ip, 0x86dd, dst=MAC_A, src=MAC_B) if down else eth(ip, 0x86dd)

    def c(self, p):
        f = self._f(p, self.cport, self.sport, self.cseq, self.sseq, False)
        self.cseq += len(p)
        return f

    def s(self, p):
        f = self._f(p, self.sport, self.cport, self.sseq, self.cseq, True)
        self.sseq += len(p)
        return f


def udp6(payload, sp, dp, down=False):
    src, dst = (V6B, V6A) if down else (V6A, V6B)
    n = 8 + len(payload)
    h = struct.pack('>HHHH', sp, dp, n, 0)
    pseudo = src + dst + struct.pack('>IBBBB', n, 0, 0, 0, 17)
    h = h[:6] + struct.pack('>H', csum(pseudo + h + payload) or 0xffff) + h[8:]
    ip = struct.pack('>IHBB', 0x60000000, n, 17, 64) + src + dst + h + payload
    return eth(ip, 0x86dd, dst=MAC_A, src=MAC_B) if down else eth(ip, 0x86dd)


def greeting(modes=7):
    return bytes(12) + struct.pack('>I', modes) + bytes(range(16)) + bytes(range(16, 32)) + struct.pack('>I', 1024) + bytes(12)


def setup(mode=1):
    return struct.pack('>I', mode) + bytes(range(80)) + bytes(64) + bytes(16)


def server_start(accept=0):
    return bytes(15) + bytes([accept]) + bytes(range(16)) + struct.pack('>II', 0xe8000000, 0x80000000) + bytes(8)


def request(sport, rport, ipvn=4, saddr=b'', raddr=b'', cmd=1, padlen=0, tslots=0, npk=100):
    if ipvn == 6:
        sa, ra = saddr or bytes(16), raddr or bytes(16)
    else:
        sa, ra = (saddr or bytes(4)).ljust(16, b'\0'), (raddr or bytes(4)).ljust(16, b'\0')
    return (struct.pack('>BBBBIIHH', cmd, ipvn, 0, 0, tslots, npk, sport, rport) + sa + ra +
            bytes(range(16)) + struct.pack('>I', padlen) + struct.pack('>II', 0xe8000000, 0) +
            struct.pack('>II', 2, 0) + struct.pack('>I', 0x2e) + bytes(8) + bytes(16))


def accept(code, port, sid=bytes(range(16))):
    return bytes([code, 0]) + struct.pack('>H', port) + sid + bytes(12) + bytes(16)


def start_sessions(cmd=2):
    return bytes([cmd]) + bytes(15) + bytes(16)


def start_ack(code=0):
    return bytes([code]) + bytes(15) + bytes(16)


def stop_sessions(code=0, n=1):
    return bytes([3, code, 0, 0]) + struct.pack('>I', n) + bytes(8) + bytes(16)


def test_sender(seq, est, pad=13):
    return struct.pack('>IIIH', seq, 0xe8000000 + seq, 0x40000000, est) + bytes(pad)


def test_reflect(seq, est, sest, pad=0):
    return (struct.pack('>IIIH', seq, 0xe8000001, 0x80000000, est) + bytes(2) +      # sender part, MBZ
            struct.pack('>II', 0xe8000002, 0x80000000) +                              # receive timestamp
            struct.pack('>I', seq - 1) +                                              # sender seq
            struct.pack('>II', 0xe8000000, 0x40000000) +                              # sender timestamp
            struct.pack('>H', sest) + bytes(2) + bytes([255]) + bytes(pad))           # sender error estimate, MBZ, TTL


def u4(p, sp, dp, down=False, ident=1):
    if down:
        return eth(ipv4(udp(p, sp, dp, src=IP_B, dst=IP_A), src=IP_B, dst=IP_A, ident=ident), 0x0800, dst=MAC_A, src=MAC_B)
    return udp_frame(p, sp, dp, ident)


def build(out):
    main = Pcap()
    t = Tcp(CPORT, SPORT)
    ident = [100]

    def n():
        ident[0] += 1
        return ident[0]
    main.add(t.s(greeting()))                                                  # 1 server greeting, all three modes
    main.add(t.c(setup(1)))                                                    # 2 setup response
    main.add(t.s(server_start(0)))                                             # 3 server start, accepted
    main.add(t.c(request(41000, 5000)))                                        # 4 request session, addresses zero: taken from the IP header
    main.add(t.s(accept(0, 6000)))                                             # 5 accept session: UDP conversation 41000 <-> 6000
    main.add(t.c(start_sessions()))                                            # 6 start sessions
    main.add(t.s(start_ack(0)))                                                # 7 start sessions ack
    main.add(u4(test_sender(1, 0x8503), 41000, 6000, ident=n()))               # 8 TWAMP-Test sender packet (S bit, scale 5, multiplier 3)
    main.add(u4(test_reflect(1, 0x0305, 0x8503), 6000, 41000, True, n()))      # 9 reflected packet, Z bit clear
    main.add(u4(test_sender(2, 0xc102, pad=60), 41000, 6000, ident=n()))       # 10 sender packet with the Z bit and a long padding (looks like a reflected one)
    main.add(u4(test_reflect(2, 0x4000, 0xc000, pad=100), 6000, 41000, True, n()))   # 11 reflected packet with the Z bits and padding
    main.add(t.c(stop_sessions(0, 1)))                                         # 12 stop sessions
    main.add(t.s(stop_sessions(0, 1)))                                         # 13 another message in the stop state (state stays)
    # connection B: errors, IPv6 session, second request, other commands
    t = Tcp(CPORT + 1, SPORT)
    g = greeting(1)
    main.add(t.s(g[:40]))                                                      # 14 greeting, first 40 octets (reassembly)
    main.add(t.s(g[40:]))                                                      # 15 rest of the greeting
    main.add(t.c(setup(2)))                                                    # 16 setup response (authenticated)
    main.add(t.s(server_start(3)))                                             # 17 server start with an error (accept 3)
    main.add(t.c(request(42000, 5001, 6, V6A, V6B, padlen=64)))                # 18 request session with IPv6 addresses and a padding length
    main.add(t.s(accept(0, 6001)))                                             # 19 accept: second UDP conversation
    main.add(t.c(accept(4, 0)))                                                # 20 command 4 (not start/stop/request): state stays "Accept Session"
    main.add(t.c(request(42000, 5001, 6, V6A, V6B, cmd=5)))                    # 21 command 5: a new request in state "Request Session"
    main.add(t.s(accept(0, 6001, bytes(16))))                                  # 22 accept again for the same session (conversation exists)
    main.add(t.c(start_sessions(2)))                                           # 23 start sessions
    main.add(t.s(start_ack(1)))                                                # 24 start ack with the error "reason unspecified"
    main.add(u4(test_sender(7, 0x0101), 42000, 6001, ident=n()))               # 25 test packet of the second session
    main.add(t.c(stop_sessions(2, 3)))                                         # 26 stop sessions, accept field 2
    # connection C: error codes and a second request with the same sender port
    t = Tcp(CPORT + 2, SPORT)
    main.add(t.s(greeting(2)))                                                 # 27 greeting with the authenticated mode only
    main.add(t.c(setup(4)))                                                    # 28 setup response (encrypted)
    main.add(t.s(server_start(0)))                                             # 29 server start
    main.add(t.c(request(43000, 5002, 4, bytes([192, 0, 2, 77]), bytes([192, 0, 2, 78]), tslots=3)))   # 30 request session with IPv4 addresses
    main.add(t.s(accept(5, 0)))                                                # 31 accept with the error "temporary resource limitations"
    main.add(t.c(start_sessions(3)))                                           # 32 command 3: state "Stop Session"
    main.add(t.s(stop_sessions(77, 0)))                                        # 33 stop with an unknown accept value
    # connection D: sender port repeated, accept error values 1, 2, 4, unknown
    t = Tcp(CPORT + 3, SPORT)
    main.add(t.s(greeting(5)))                                                 # 34 greeting
    main.add(t.c(setup(1)))                                                    # 35
    main.add(t.s(server_start(77)))                                            # 36 server start with an unknown error value
    main.add(t.c(request(44000, 5003, 4, bytes([192, 0, 2, 5]), b'')))         # 37 request, receiver address zero
    main.add(t.s(accept(4, 0)))                                                # 38 accept with error 4
    main.add(t.c(request(44000, 5003, 4, cmd=5)))                              # 39 command 5: request in state accept
    main.add(t.s(accept(1, 0)))                                                # 40 accept with error 1
    main.add(t.c(request(44000, 5003, 4, cmd=5)))                              # 41 command 5 again
    main.add(t.s(accept(2, 0)))                                                # 42 error 2
    # connection E over IPv6, addresses zero in the request
    t6 = Tcp6(CPORT + 4, SPORT)
    main.add(t6.s(greeting(7)))                                                # 43 greeting over IPv6
    main.add(t6.c(setup(1)))                                                   # 44
    main.add(t6.s(server_start(0)))                                            # 45
    main.add(t6.c(request(45000, 5004, 6)))                                    # 46 IPv6 request with zero addresses: taken from the IPv6 header
    main.add(t6.s(accept(0, 6004)))                                            # 47 accept
    main.add(udp6(test_sender(1, 0x8000, pad=20), 45000, 6004))                # 48 TWAMP-Test over IPv6
    main.add(udp6(test_reflect(1, 0x8000, 0x8000), 6004, 45000, True))         # 49 reflected packet over IPv6
    # OWAMP-Test, only through Decode As of UDP port 8760
    main.add(u4(struct.pack('>IIIH', 1, 0xe8000000, 0x40000000, 0x8503) + bytes(32), 8760, 8761, ident=n()))   # 50 OWAMP-Test, NTP timestamp
    main.add(u4(struct.pack('>IIIH', 2, 0xe8000000, 0x40000000, 0xc503) + bytes(5), 8760, 8761, ident=n()))    # 51 OWAMP-Test, Z bit: seconds and nanoseconds timestamp
    main.add(u4(struct.pack('>IIIH', 3, 0xe8000000, 0x40000000, 0x0000), 8761, 8760, ident=n()))                # 52 OWAMP-Test without padding
    main.write(os.path.join(out, 'twamp-coverage.pcap'))

    bad = Pcap()
    t = Tcp(CPORT + 10, SPORT)
    bad.add(t.c(setup(1)))                                                     # 1 client message before any greeting: not decoded
    bad.add(t.s(b'short greeting'))                                            # 2 server message that is not 64 octets
    bad.add(t.s(greeting()[:63]))                                              # 3 63 octets
    bad.add(t.s(greeting()))                                                   # 4 greeting
    bad.add(t.c(setup(1)[:20]))                                                # 5 setup response cut in the key id
    bad.add(t.s(server_start(0)[:30]))                                         # 6 server start cut
    bad.add(t.c(request(46000, 5005)[:30]))                                    # 7 request session cut before the ports and addresses
    bad.add(t.s(accept(0, 6005)[:2]))                                          # 8 accept cut after two octets
    bad.add(t.c(start_sessions()[:10]))                                        # 9 start sessions cut
    bad.add(t.s(start_ack()[:1]))                                              # 10 start ack: one octet
    bad.add(t.c(stop_sessions()[:6]))                                          # 11 stop sessions cut
    t = Tcp(CPORT + 11, SPORT)
    bad.add(t.s(greeting()))                                                   # 12 new connection
    bad.add(t.c(setup(1)))                                                     # 13
    bad.add(t.s(server_start(0)))                                              # 14
    bad.add(t.c(request(47000, 5006, 4)[:10]))                                 # 15 request cut before the ports (reads the ports: exception)
    bad.add(u4(b'\x00\x00\x00\x01' + bytes(8), 41000, 6000, ident=1))        # 16 test packet too short for the error estimate
    bad.add(u4(b'\x00\x00\x00\x01', 8760, 8761, ident=2))                     # 17 OWAMP-Test with only a sequence number
    bad.add(u4(struct.pack('>IIIH', 1, 0, 0, 0)[:12], 8760, 8761, ident=3))     # 18 OWAMP-Test cut in the timestamp
    bad.add(u4(bytes(14) + b'x', 8762, 8763, ident=4))                          # 19 plain UDP data
    bad.write(os.path.join(out, 'twamp-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

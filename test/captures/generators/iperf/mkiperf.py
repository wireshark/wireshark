# Generates test/captures/iperf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic traffic only) ----
import struct
import sys
import os

ETH_C = bytes.fromhex('020000000001')
ETH_S = bytes.fromhex('020000000002')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4_hdr(src, dst, proto, payload_len, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, ident, 0x4000,
                    64, proto, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]


def eth(src_is_client):
    return (ETH_S + ETH_C if src_is_client else ETH_C + ETH_S) + b'\x08\x00'


def tcp_seg(src, dst, sport, dport, seq, ack, payload, flags=0x18, c2s=True):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('!H', c) + hdr[18:]
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 6, len(seg)) + seg


def udp_dgram(src, dst, sport, dport, payload, c2s=True):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 17, len(seg)) + seg


class Tcp:
    """One TCP connection; frames collects (data) in order."""
    def __init__(self, frames, c, s, cport, sport, isn_c=1000, isn_s=5000, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.sc, self.ss = isn_c, isn_s
        if handshake:
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, 0, b'', 0x02))
            self.f.append(tcp_seg(s, c, sport, cport, self.ss, self.sc + 1, b'', 0x12, c2s=False))
            self.sc += 1
            self.ss += 1
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, self.ss, b'', 0x10))

    def send(self, payload, c2s=True):
        if c2s:
            self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, payload))
            self.sc += len(payload)
        else:
            self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, payload, c2s=False))
            self.ss += len(payload)

    def fin(self):
        self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, b'', 0x11))
        self.sc += 1
        self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, b'', 0x11, c2s=False))
        self.ss += 1


def write_pcap(path, frames, linktype=1, snaplen=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000 % 1000000, len(fr), len(fr)))
            f.write(fr)


def _blk(btype, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack('<II', btype, tot) + body + b'\0' * pad + struct.pack('<I', tot)


def write_pcapng(path, linktypes, frames):
    """frames: list of (interface_index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifidx, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff,
                                   len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
# ---- end common helpers ----
#!/usr/bin/env python3
"""Generate the iPerf2 coverage captures: mkiperf.py <outdir>
Writes iperf-coverage.pcap and iperf-coverage-malformed.pcap (Ethernet).
iPerf2 has no default port: decode TCP/UDP port 5001 with Decode As
(-d tcp.port==5001,iperf2_tcp -d udp.port==5001,iperf2_udp; cfg/ has a
decode_as_entries file). All traffic is synthetic."""

C, S = '192.0.2.50', '192.0.2.51'

# flags of the first word
V1, EXT, UDPT, SEQ64, V2, PEER, AVOID1, BB = (0x80000000, 0x40000000, 0x20000000, 0x08000000,
                                              0x04000000, 0x02000000, 0x01000000, 0x00800000)
SMALL = 0x00020000
LENBIT = 0x00010000
# upper flags (16 bit)
ISOCH, L2ETHPIPV6, L2LENCHECK, NOUDPFIN, TRIPTIME, UNUSED2, ISOCH_SET, UNITS_PPS, BWSET, \
    FQRATESET, REVERSE, FULLDUPLEX, EPOCH_START, PERIODICBURST, WRITEPREFETCH, TCPQUICKACK = \
    [1 << i for i in range(16)]
CCA = 0x8000
PATTERN = b'0123456789'


def pattern(n, start=0):
    return bytes(PATTERN[(start + i) % 10] for i in range(n))


def client_hdr(flags, threads=1, mport=5001, buflen=131072, winband=0, amount=-1000):
    return struct.pack('!IIIIIi', flags, threads, mport, buflen, winband, amount)


def ext_hdr(upper=0, lower=0, typ=0, length=0, major=2, minor=1, tos=0, rate=0, units=0, rt=0):
    return struct.pack('!IIHHIIHHIII', typ, length, upper, lower, major, minor, 0, tos, rate, units, rt)


def fq_hdr(sec=1700000000, usec=250000, ratel=1000, rateu=0):
    return struct.pack('!IIIII', 0, sec, usec, ratel, rateu)


def isoch_hdr():
    return struct.pack('!IIIIIIII', 60, 0, 1, 0, 2, 0, 16667, 0)


def cca_hdr(name=b'cubic'):
    return struct.pack('!H', len(name)) + name


def bounceback(flags=BB | V1, ts=(1700000000, 1, 1700000000, 2, 1700000000, 3, 1700000000, 4)):
    # 4 flags + size + id + (bbflags+tos) + runtime = 20, 4 timestamps = 32, hold, rtt = 8, read ts = in ts list
    b = struct.pack('!IIIHHI', flags, 64, 7, 0xF800, 0x2e, 100)
    b += struct.pack('!6I', ts[0], ts[1], ts[2], ts[3], ts[4], ts[5])    # client tx, server rx, server tx
    b += struct.pack('!II', 5, 6)                                       # hold, rtt
    b += struct.pack('!II', ts[6], ts[7])                               # read ts
    b += struct.pack('!I', 1500)                                        # reply size
    return b


assert len(bounceback()) == 64, len(bounceback())
assert len(client_hdr(V1)) == 24 and len(ext_hdr()) == 36

frames = []
mal = []
HUGE = 0xfffffff0           # microseconds that overflow a signed int * 1000


def flow(frs, cport, sport=5001, c=C, s=S, **kw):
    return Tcp(frs, c, s, cport, sport, **kw)


def build(frs, mal=False):
    port = [42000]

    def conn(**kw):
        port[0] += 1
        return flow(frs, port[0], **kw)

    # ---------------------------------------------------- TCP, first write
    t = conn()                                   # plain client header, no payload
    t.send(client_hdr(V1 | V2))
    t.send(pattern(1448))                        # payload only
    t.send(pattern(100, 3))                      # rotated start, trailing partial block
    t.send(pattern(35, 7))
    t.send(pattern(24, 5))
    t.fin()

    t = conn()                                   # header and payload in one segment
    t.send(client_hdr(V1) + pattern(200))
    t.send(client_hdr(V1 | V2 | PEER | UDPT | SEQ64 | LENBIT | 0x1fe | 1) + b'\xaa' * 30)
    t.fin()

    t = conn()                                   # extended header without key
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=WRITEPREFETCH | TCPQUICKACK | PERIODICBURST * 0,
                                          major=2, minor=2, tos=0x10, rate=1000000, units=1, rt=5))
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=BWSET | UNITS_PPS | L2ETHPIPV6 | L2LENCHECK | NOUDPFIN | ISOCH)
           + b'\x00\x00' + pattern(50))
    t.fin()

    t = conn()                                   # permit key
    key = b'0123456789ab'
    t.send(client_hdr(V1 | EXT) + ext_hdr() + struct.pack('!H', len(key)) + key)
    t.send(client_hdr(V1 | EXT) + ext_hdr() + struct.pack('!H', 500) + b'tooshort')
    t.send(client_hdr(V1 | EXT) + ext_hdr() + b'\x00')     # one octet after the header
    t.fin()

    # headers selected by the upper flags are only found in the second pass
    # of the dissector: the segment must hold everything
    t = conn()
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=TRIPTIME, rate=1) + fq_hdr(usec=HUGE))
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=FQRATESET | ISOCH_SET | EPOCH_START) + fq_hdr() + pattern(40))
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=FULLDUPLEX | REVERSE) + isoch_hdr() + b'\x00' * 8)
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=PERIODICBURST | TRIPTIME | UNUSED2) + fq_hdr() + isoch_hdr() + b'\x00' * 8)
    t.send(client_hdr(V1 | EXT) + ext_hdr(upper=EPOCH_START | REVERSE) + fq_hdr() + isoch_hdr() + b'\x00' * 8 + pattern(30))
    t.fin()

    t = conn()                                   # CCA header (fq, isoch and the CCA name)
    # the dissector reads the CCA header right after 32 octets of isochronous
    # header (the 40 octet one of iperf2 is only partly read, see README)
    t.send(client_hdr(V1 | EXT) + ext_hdr(lower=CCA) + fq_hdr() + isoch_hdr() + cca_hdr())
    t.send(client_hdr(V1 | EXT) + ext_hdr(lower=CCA, upper=TRIPTIME) + fq_hdr(usec=HUGE) + isoch_hdr() + b'\x00' * 8
           + cca_hdr(b'bbr') + pattern(25))
    t.fin()

    t = conn()                                   # bounceback header
    t.send(bounceback())
    t.send(bounceback(ts=(1, HUGE, 2, HUGE, 3, 4, 5, HUGE)) + pattern(12))
    t.fin()

    # ----------------------------------- desegmentation (more data needed)
    t = conn()
    t.send(b'\x80\x00\x00')                      # shorter than the 24 octet client header
    t.send(client_hdr(V1)[3:])
    t.send(pattern(48))
    t.fin()

    t = conn()                                   # extended header split in two
    m = client_hdr(V1 | EXT) + ext_hdr(upper=WRITEPREFETCH, major=2, minor=3)
    t.send(m[:30])
    t.send(m[30:])
    t.send(pattern(30))
    t.fin()

    t = conn()                                   # bounceback split in two
    m = bounceback(ts=(1700000000, 9, 1700000000, 8, 1700000000, 7, 1700000000, HUGE))
    t.send(m[:40])
    t.send(m[40:])
    t.fin()

    t = conn()                                   # extended header with permit key in three segments
    m = client_hdr(V1 | EXT) + ext_hdr() + struct.pack('!H', 4) + b'key!' + pattern(20)
    t.send(m[:10])
    t.send(m[10:50])
    t.send(m[50:])
    t.fin()

    # a segment of a made-up stream that looks like a header (the dissector
    # looks at every segment, it has no per connection state)
    t = conn()
    t.send(pattern(60) + b'xyz' + pattern(40))
    t.send(pattern(30)[:-1] + b'x')
    t.fin()

    # --------------------------------------------------------- UDP
    def udp(sport, payload):
        frs.append(udp_dgram(C, S, sport, 5001, payload))

    def uhdr(seq, sec, usec, upper, flags):
        return struct.pack('!iIIiI', seq, sec, usec, upper, flags)

    n = 1
    # plain header (flags without extend), then payload
    udp(43001, uhdr(1, 1700000000, 1000, 0, V1) + b'\0' * 20 + b'U' * 100)
    udp(43001, uhdr(2, 1700000000, 2000, 0, V1 | V2 | UDPT) + b'\0' * 20 + b'U' * 100)
    udp(43001, uhdr(3, 1700000000, 999999, 0, 0) + b'\0' * 20)           # nothing after the header
    udp(43001, uhdr(-1, 1700000000, HUGE, 0, V1) + b'\0' * 20 + b'U' * 10)   # usec overflow
    udp(43001, uhdr(4, 1700000001, 0xffffffff, 1, V1 | SEQ64) + b'\0' * 20)
    udp(43001, uhdr(5, 1700000001, 0x80000000, 1, V1) + client_hdr(0)[4:] + b'U' * 8)
    # small trip times: only the flags word
    udp(43002, uhdr(1, 1700000000, 0, 0, SMALL | V1))
    if mal:
        # client header size 4 with payload: dissect_iperf2_client_header()
        # returns an absolute offset here, the UDP dissector then runs past the end
        udp(43002, uhdr(2, 1700000000, 0, 0, SMALL | V1) + b'P' * 64)
    # full extended headers: ext (36), isoch payload header (32), fq (20), isoch (32)
    full = lambda usec, **k: (uhdr(1, 1700000000, usec, 0, V1 | EXT) + client_hdr(0)[4:]
                              + ext_hdr(**k)
                              + struct.pack('!IIIIIIII', 60, 1700000000, usec, 0, 1, 1448, 96, 0)
                              + fq_hdr(usec=usec) + isoch_hdr())
    udp(43003, full(1000))
    udp(43003, full(HUGE, upper=ISOCH | TRIPTIME, lower=CCA, major=2, minor=2) + b'D' * 50)
    udp(43003, full(0xffffffff, upper=0xffff, lower=0x7fff))
    udp(43003, full(1000000, upper=0, lower=0) + b'D' * 5)
    udp(43003, full(1999999, upper=0, lower=0))


build(frames)
write_pcap(os.path.join(sys.argv[1], 'iperf-coverage.pcap'), frames)

# ----------------------------------------------------------------- malformed
mal = []
build(mal, mal=True)
t = flow(mal, 44001)
# the headers selected by the upper flags do not fit the segment (the first
# pass of the dissector does not know the flags: it asks for no more data)
t.send(client_hdr(V1 | EXT) + ext_hdr(upper=TRIPTIME))
t.send(client_hdr(V1 | EXT) + ext_hdr(upper=FULLDUPLEX))
t.send(client_hdr(V1 | EXT) + ext_hdr(upper=TRIPTIME | FULLDUPLEX) + fq_hdr())
t.send(client_hdr(V1 | EXT) + ext_hdr(lower=CCA))
t.send(client_hdr(V1 | EXT) + ext_hdr(lower=CCA) + fq_hdr() + isoch_hdr() + struct.pack('!H', 400))
t.send(client_hdr(V1 | EXT) + ext_hdr(lower=CCA) + fq_hdr() + isoch_hdr() + b'\0' * 8 + struct.pack('!H', 400) + b'abc')
t.send(client_hdr(V1 | EXT) + ext_hdr()[:20])
t.send(bounceback()[:60])
t.send(b'\xff' * 30)
t.send(b'\xaa' * 100)
t.send(b'x' * 100)
t.fin()
udpf = lambda sport, payload: mal.append(udp_dgram(C, S, sport, 5001, payload))
base = struct.pack('!iIIiI', 1, 1700000000, 5, 0, V1 | EXT)
udpf(45001, base[:15])
udpf(45001, base)
udpf(45001, base + b'\0' * 10)
udpf(45001, base + b'\0' * 20)
udpf(45001, base + b'\0' * 20 + ext_hdr()[:20])
udpf(45001, base + b'\0' * 20 + ext_hdr() + b'\0' * 10)
udpf(45001, base + b'\0' * 20 + ext_hdr() + b'\0' * 32 + b'\0' * 10)
udpf(45001, struct.pack('!iIIiI', 1, 1700000000, 5, 0, V1 | SMALL)[:19])
udpf(45001, b'\0' * 7)
write_pcap(os.path.join(sys.argv[1], 'iperf-coverage-malformed.pcap'), mal)

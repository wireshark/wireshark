#!/usr/bin/env python3
# Generates test/captures/rdt_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- helpers (struct only) ----
import struct
import sys

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s): return bytes(map(int, s.split('.')))

class Cap:
    def __init__(self, linktype=1):
        self.frames = []; self.linktype = linktype
        self.seq = {}; self.ipid = 1; self.ts = 1700000000.0
    def raw(self, data, caplen=None):
        self.frames.append((self.ts, bytes(data), caplen)); self.ts += 0.01
        return len(self.frames)
    def ip(self, src, dst, proto, payload, ttl=64, frag=0):
        self.ipid += 1
        h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), self.ipid, frag, ttl, proto, 0, ip4(src), ip4(dst))
        h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
        return h + payload
    def eth(self, pkt, et=0x0800, s=b'\x02\0\0\0\0\x01', d=b'\x02\0\0\0\0\x02'):
        return d + s + struct.pack('!H', et) + pkt
    def ip6(self, src, dst, nh, payload, hop=64):
        return struct.pack('!IHBB', 0x60000000, len(payload), nh, hop) + src + dst + payload
    def udp(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0) + payload
        return self.raw(self.eth(self.ip(src, dst, 17, u, ttl=1 if dst.startswith('224.') else 64)))
    def udp6(self, src, dst, sp, dp, payload):
        u = struct.pack('!HHHH', sp, dp, 8+len(payload), 0)
        ph = src + dst + struct.pack('!IBBBB', 8+len(payload), 0, 0, 0, 17)
        c = csum(ph + u + payload) or 0xffff
        u = u[:6] + struct.pack('!H', c) + payload
        return self.raw(self.eth(self.ip6(src, dst, 17, u), et=0x86dd,
                                 d=b'\x33\x33\0\0\0\x09'))
    def tcp(self, src, dst, sp, dp, payload, flags=0x18, seq=None, urp=0):
        k = (src, dst, sp, dp)
        if seq is None: seq = self.seq.get(k, 1000 + (sp * 7919 + dp) % 100000)
        self.seq[k] = seq + len(payload) + (1 if flags & 3 else 0)
        ack = self.seq.get((dst, src, dp, sp), 0)
        if flags & 2:   # SYN: MSS option
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x70, flags, 65535, 0, urp) + b'\x02\x04\x05\xb4\x04\x02\x01\x01' + payload
        else:
            t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, urp) + payload
        return self.raw(self.eth(self.ip(src, dst, 6, t)))
    def hs(self, src, dst, sp, dp):
        # three-way handshake: SYN, SYN/ACK, ACK
        self.tcp(src, dst, sp, dp, b'', flags=0x02, seq=1000 + (sp * 7919 + dp) % 100000 - 1)
        self.tcp(dst, src, dp, sp, b'', flags=0x12, seq=5000)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
    def fin(self, src, dst, sp, dp):
        self.tcp(src, dst, sp, dp, b'', flags=0x11)
        self.tcp(dst, src, dp, sp, b'', flags=0x11)
        self.tcp(src, dst, sp, dp, b'', flags=0x10)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for ts, d, cl in self.frames:
                c = d if cl is None else d[:cl]
                f.write(struct.pack('<IIII', int(ts), int((ts % 1)*1e6), len(c), len(d)) + c)


class CapNG(Cap):
    """pcapng with one interface per link type: raw(data, lt=1)"""
    def __init__(self, linktypes=(1, 252)):
        Cap.__init__(self, 1); self.lts = list(linktypes)
    def raw(self, data, caplen=None, lt=1):
        self.frames.append((self.ts, bytes(data), caplen, self.lts.index(lt))); self.ts += 0.01
        return len(self.frames)
    def write(self, path):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.lts:
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
        for ts, d, cl, ifx in self.frames:
            c = d if cl is None else d[:cl]
            t = int(ts * 1e6)
            out += blk(6, struct.pack('<IIIII', ifx, t >> 32, t & 0xffffffff, len(c), len(d)) + c)
        open(path, 'wb').write(out)

def expdu(name, payload):
    n = name.encode(); pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload
# ---- end helpers ----
out = sys.argv[1] if len(sys.argv) > 1 else '.'
def data(stream=1, seq=1, ts=0, payload=b'', lenincl=False, need_rel=False, reliable=False,
         b2b=False, slow=False, asm=0, total_rel=0, sid_ex=0, asm_ex=0, length=None):
    f1 = (lenincl << 7) | (need_rel << 6) | (stream << 1) | int(reliable)
    f2 = (b2b << 7) | (slow << 6) | asm
    body = struct.pack('!BB', f2, 0) [:1] + struct.pack('!I', ts)
    if stream == 31: body += struct.pack('!H', sid_ex)
    if need_rel: body += struct.pack('!H', total_rel)
    if asm == 63: body += struct.pack('!H', asm_ex)
    body += payload
    hl = 3 + (2 if lenincl else 0)
    total = hl + len(body)
    h = struct.pack('!BH', f1, seq)
    if lenincl: h += struct.pack('!H', total if length is None else length)
    return h + body
def ctl(ptype, flags=0, lenincl=False, body=b'', length=None):
    f = flags | (0x80 if lenincl else 0)
    h = struct.pack('!BH', f, ptype)
    if lenincl:
        h += struct.pack('!H', 5 + len(body) if length is None else length)
    return h + body
def asm_action(stream=3, relseq=7, lenincl=True, payload=b'ab', sid_ex=0):
    # flags: length-included (0x80), stream id (0x7c)
    f = (lenincl << 7) | (stream << 2)
    h = struct.pack('!BHH', f, 0xff00, relseq)
    if lenincl: h += struct.pack('!H', 0)       # patched below
    if stream == 31: h += struct.pack('!H', sid_ex)
    h += payload
    if lenincl: h = h[:5] + struct.pack('!H', len(h)) + h[7:]
    return h
def stream_end(stream=2, need_rel=False, ext=False, sent=True, seq=9, ts=1000, sid_ex=0, total_rel=0, extra=b''):
    f = (need_rel << 7) | (stream << 2) | (sent << 1) | int(ext)
    h = struct.pack('!BHHI', f, 0xff06, seq, ts)
    if stream == 31: h += struct.pack('!H', sid_ex)
    if need_rel: h += struct.pack('!H', total_rel)
    if ext: h += struct.pack('!BHI', 0x55, 0x1234, 0xdeadbeef) + extra
    return h
def bandwidth(lenincl=True): return ctl(0xff01, lenincl=lenincl, body=struct.pack('!HIB', 1000, 2000000, 5), length=None)
def ack(lost_high=False, lenincl=True, payload=b'\x01\x02\x03'): return ctl(0xff02, flags=0x40 if lost_high else 0, lenincl=lenincl, body=payload)
def rtt_req(): return struct.pack('!BH', 0, 0xff03)
def rtt_resp(): return struct.pack('!BHII', 0, 0xff04, 1700000000, 123456)
def congestion(): return struct.pack('!BHII', 0, 0xff05, 0x10000, 0x20000)
def report(lenincl=True): return ctl(0xff07, lenincl=lenincl, body=b'\xaa\xbb\xcc')
def latency(lenincl=True): return ctl(0xff08, lenincl=lenincl, body=struct.pack('!I', 5000))
def tirq(rtt=True, buf=True, ms=77):
    f = (rtt << 1) | int(buf)
    return struct.pack('!BH', f, 0xff09) + (struct.pack('!I', ms) if rtt else b'')
def tirp(rtt=True, delayed=True, buf=True, n=2):
    f = (rtt << 2) | (delayed << 1) | int(buf)
    h = struct.pack('!BH', f, 0xff0a)
    if rtt:
        h += struct.pack('!I', 111)
        if delayed: h += struct.pack('!I', 222)
    if buf:
        h += struct.pack('!H', n)
        for i in range(n): h += struct.pack('!HIII', i + 1, 1000 * i, 1000 * i + 500, 4096 * (i + 1))
    return h
def bwprobe(lenincl=True): return ctl(0xff0b, lenincl=lenincl, body=struct.pack('!BI', 3, 4000))
def unknown(ptype=0xff20, flags=0x13): return struct.pack('!BH', flags, ptype) + b'\x01\x02\x03\x04'

SRV, CLI = '192.0.2.20', '192.0.2.10'
c = CapNG()
def U(payload, sp=49152, dp=6970, src=CLI, dst=SRV): return c.udp(src, dst, sp, dp, payload)
# Part 1: UDP port 6970 (registered by default)
U(data(stream=1, seq=1, ts=100, payload=b'media data 0123456789'))                          # 1 data, stream 1
U(data(stream=31, seq=2, ts=200, payload=b'ext', lenincl=True, need_rel=True, reliable=True, b2b=True, slow=True,
       asm=63, total_rel=17, sid_ex=300, asm_ex=500))                                     # 2 length included, stream 31, need-reliable, assembly rule 63 (extended)
U(data(stream=0, seq=3, ts=300, payload=b'x', slow=True, asm=5))                           # 3 stream 0, slow data, rule 5
U(asm_action(stream=3, relseq=7))                                                          # 4 ASM action, length included
U(asm_action(stream=31, relseq=8, lenincl=False, sid_ex=4000, payload=b'rule'))            # 5 ASM action, stream 31, no length
U(bandwidth(True))                                                                         # 6 bandwidth report with length
U(bandwidth(False))                                                                        # 7 bandwidth report without length
U(ack(True, True))                                                                         # 8 ack, lost-high, length
U(ack(False, False))                                                                       # 9 ack, no length
U(rtt_req())                                                                               # 10 RTT request
U(rtt_resp(), sp=6970, dp=49152, src=SRV, dst=CLI)                                         # 11 RTT response
U(congestion())                                                                            # 12 congestion
U(stream_end(stream=2))                                                                    # 13 stream end
U(stream_end(stream=31, need_rel=True, ext=True, sid_ex=9, total_rel=3, extra=b'more'))    # 14 stream end: stream 31, need-reliable, extension flag
U(report(True))                                                                            # 15 report with length
U(report(False))                                                                           # 16 report without length
U(latency(True))                                                                           # 17 latency report with length
U(latency(False))                                                                          # 18 latency report, no length
U(tirq(True, True))                                                                        # 19 transport info request with rtt info
U(tirq(False, False))                                                                      # 20 transport info request, no flags
U(tirp(True, True, True, 2), sp=6970, dp=49152, src=SRV, dst=CLI)                           # 21 transport info response: rtt, delayed, two buffer infos
U(tirp(False, False, False, 0), sp=6970, dp=49152, src=SRV, dst=CLI)                       # 22 transport info response, nothing
U(tirp(True, False, False, 0), sp=6970, dp=49152, src=SRV, dst=CLI)                        # 23 transport info response, rtt without delay
U(bwprobe(True))                                                                           # 24 bandwidth probing with length
U(bwprobe(False))                                                                          # 25 bandwidth probing, no length
U(unknown())                                                                               # 26 unknown control packet
U(rtt_req() + congestion() + ack() + asm_action() + latency() + bandwidth() + report() + bwprobe()
  + data(stream=2, seq=4, ts=400, payload=b'tail', lenincl=True))                          # 27 eight packets in one datagram, the last a data packet with its length
U(rtt_req() + rtt_resp() + stream_end(stream=5) + tirq(True, False) + data(stream=3, seq=5, ts=500, payload=b'q'))   # 28 control packets followed by a data packet
# Part 2: RTSP sets up the RDT streams (UDP on a port that is not 6970)
T = lambda payload, cli=True, sp=50000: (c.tcp(CLI, SRV, sp, 554, payload) if cli else c.tcp(SRV, CLI, 554, sp, payload))
c.tcp(CLI, SRV, 50000, 554, b'', flags=0x02)
c.tcp(SRV, CLI, 554, 50000, b'', flags=0x12)
c.tcp(CLI, SRV, 50000, 554, b'', flags=0x10)
T(b'SETUP rtsp://192.0.2.20/real/streamid=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: x-real-rdt/udp;client_port=6971;mode=play\r\n\r\n')   # 32
T(b'RTSP/1.0 200 OK\r\nCSeq: 2\r\nRDTFeatureLevel: 2\r\nSession: 12345\r\nTransport: x-real-rdt/udp;client_port=6971;server_port=6972\r\n\r\n', cli=False)   # 33
U(data(stream=1, seq=10, ts=1000, payload=b'via rtsp'), sp=6972, dp=6971, src=SRV, dst=CLI)       # 34 RDT on the port from the RTSP reply, stream setup shown
U(ack(False, True), sp=6972, dp=6971, src=SRV, dst=CLI)                                              # 35 second packet of that stream (setup info from the stored conversation data)
# Part 3: RDT interleaved in RTSP over TCP (x-pn-tng is a synonym of x-real-rdt)
c.tcp(CLI, SRV, 50001, 554, b'', flags=0x02)
c.tcp(SRV, CLI, 554, 50001, b'', flags=0x12)
c.tcp(CLI, SRV, 50001, 554, b'', flags=0x10)
T(b'SETUP rtsp://192.0.2.20/real/streamid=1 RTSP/1.0\r\nCSeq: 2\r\nTransport: x-pn-tng/tcp;interleaved=2-3\r\n\r\n', sp=50001)
T(b'RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 6789\r\nTransport: x-pn-tng/tcp;interleaved=2-3\r\n\r\n', cli=False, sp=50001)
pl = data(stream=1, seq=20, ts=2000, payload=b'interleaved', lenincl=True)
T(b'$\x02' + struct.pack('!H', len(pl)) + pl, cli=False, sp=50001)                                 # interleaved channel 2
# Part 4: Exported PDU naming the dissector (the reproducer of the endless loop is a 70000 byte data packet without a length field)
c.raw(expdu('rdt', data(stream=4, seq=30, ts=3000, payload=b'exported pdu')), lt=252)
c.raw(expdu('rdt', data(stream=0, seq=1, ts=0, payload=b'\0' * (70000 - 8))), lt=252)             # 70000 octets: packet length does not fit 16 bits
c.write(out + '/rdt-coverage.pcapng')
m = CapNG()
def MU(payload, sp=49152, dp=6970, src=CLI, dst=SRV): return m.udp(src, dst, sp, dp, payload)
MU(b'\x00\x00')                                                                           # 1: two octets: fewer than three
MU(data(stream=1, seq=1, ts=1, payload=b'abc', lenincl=True, length=200))                  # 2: data packet length larger than the frame
MU(data(stream=1, seq=1, ts=1, payload=b'abc', lenincl=True, length=4))                    # 3: data packet length too small
MU(rtt_req() + data(stream=1, seq=1, ts=1, payload=b'abc', lenincl=True, length=300))      # 4: data after a control packet with a bad length
MU(ack(lenincl=True)[:3] + struct.pack('!H', 200) + b'\x01')                               # 5: ack length larger than the frame
MU(bandwidth(True)[:5])                                                                    # 6: bandwidth report cut short
MU(ctl(0xff07, lenincl=True, body=b'\x01', length=3))                                      # 7: report length smaller than its header
MU(struct.pack('!BHB', 0x10, 0xff0a, 0) + b'\x00\x05' + b'\0' * 20)                        # 8: five buffer infos but only 20 octets (the count is trusted)
MU(struct.pack('!BHB', 0x00, 0x0000, 0))                                                  # 9: data packet cut after the flags
MU(struct.pack('!BHHB', 0x00, 0xff06, 0, 0))                                               # 10: stream end cut short
MU(unknown(0xffee)[:3])                                                                    # 11: unknown control packet without data
MU(struct.pack('!BHHH', 0x80 | (3 << 2), 0xff00, 7, 2) + b'ab')                         # 12: ASM action with a length smaller than its header
MU(ctl(0xff01, lenincl=True, body=struct.pack('!HIB', 1, 2, 3), length=2))                 # 13: bandwidth report, length 2
MU(ctl(0xff02, lenincl=True, body=b'\x01', length=2))                                      # 14: ack, length 2
MU(ctl(0xff08, lenincl=True, body=struct.pack('!I', 1), length=2))                         # 15: latency report, length 2
MU(ctl(0xff0b, lenincl=True, body=struct.pack('!BI', 1, 2), length=2))                     # 16: bandwidth probing, length 2
m.write(out + '/rdt-coverage-malformed.pcapng')

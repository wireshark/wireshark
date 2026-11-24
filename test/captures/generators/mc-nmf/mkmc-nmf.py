#!/usr/bin/env python3
# Generates test/captures/mc-nmf_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the MC-NMF dissector
(packet-mc-nmf.c, [MC-NMF] .NET Message Framing Protocol). TCP port 9389
is claimed by both packet-nmf.c and packet-mc-nmf.c, so MC-NMF is not
reached by default from TCP; the main capture reaches it through Exported
PDU ("mc-nmf") carrying TCP addresses and ports, so that the conversation
state (Upgrade Request/Response) is tracked. The malformed capture also has
real TCP frames for Decode As (-d tcp.port==9389,mc-nmf).

Usage: mkmc-nmf.py <output directory> [-v]
Writes mc-nmf-coverage.pcapng (main) and mc-nmf-coverage-malformed.pcapng.
"""
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ MC-NMF

def epdu_tcp(payload, src, sport, dst, dport):
    nm = b'mc-nmf'
    pad = (4 - len(nm) % 4) % 4
    tags = struct.pack('!HH', 12, len(nm) + pad) + nm + b'\0' * pad
    tags += struct.pack('!HH', 20, 4) + ip4(src) + struct.pack('!HH', 21, 4) + ip4(dst)
    tags += struct.pack('!HHI', 24, 4, 2) + struct.pack('!HHI', 25, 4, sport) + struct.pack('!HHI', 26, 4, dport)
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def varint(n):
    out = b''
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def rec_version(maj=1, minr=0): return bytes([0, maj, minr])
def rec_mode(m): return bytes([1, m])
def rec_via(s): return b'\x02' + varint(len(s)) + s.encode()
def rec_known(e): return bytes([3, e])
def rec_ext(s): return b'\x04' + varint(len(s)) + s.encode()
def rec_sized(d): return b'\x06' + varint(len(d)) + d
def rec_unsized(chunks): return b'\x05' + b''.join(varint(len(c)) + c for c in chunks) + b'\x00'
def rec_fault(s): return b'\x08' + varint(len(s)) + s.encode()
def rec_upgrade(s): return b'\x09' + varint(len(s)) + s.encode()
REC_END, REC_UPRSP, REC_ACK, REC_PEND = b'\x07', b'\x0a', b'\x0b', b'\x0c'

CLI, SRV = '192.0.2.31', '192.0.2.32'
VIA = 'net.tcp://dc.example.org:9389/ActiveDirectoryWebServices/Windows/Resource'


class Conv:
    def __init__(self, cport):
        self.cport = cport

    def c(self, payload):
        return epdu_tcp(payload, CLI, self.cport, SRV, 9389)

    def s(self, payload):
        return epdu_tcp(payload, SRV, 9389, CLI, self.cport)


def main_frames():
    f = []
    # 1: negotiate upgrade (ADWS style): preamble, upgrade request, response,
    # then the security negotiation (handed to MS-NNS) in both directions
    a = Conv(49500)
    f.append(a.c(rec_version() + rec_mode(2) + rec_via(VIA) + rec_known(8) + rec_upgrade('application/negotiate')))
    f.append(a.s(REC_UPRSP))
    # NTLMSSP NEGOTIATE (structure only, no keys)
    ntlm = b'NTLMSSP\0' + struct.pack('<II', 1, 0x00088207) + struct.pack('<HHI', 0, 0, 32) * 2
    nns = bytes([0x16, 1, 0]) + struct.pack('>H', len(ntlm)) + ntlm
    f.append(a.c(nns))
    f.append(a.s(bytes([0x14, 1, 0]) + struct.pack('>H', 0)))
    f.append(a.c(b'\x00\x00'))
    # 2: TLS upgrade, then TLS records (application data, encrypted)
    b = Conv(49501)
    f.append(b.c(rec_version() + rec_mode(2) + rec_via(VIA) + rec_known(7) + rec_upgrade('application/ssl-tls')))
    f.append(b.s(REC_UPRSP))
    f.append(b.c(bytes([0x17, 3, 3]) + struct.pack('>H', 8) + bytes(range(0xa0, 0xa8))))
    f.append(b.s(bytes([0x17, 3, 3]) + struct.pack('>H', 4) + bytes(range(0xb0, 0xb4))))
    # 3: an upgrade protocol that is neither (state: upgrade requested only)
    c = Conv(49502)
    f.append(c.c(rec_version(1, 0) + rec_mode(1) + rec_via('net.tcp://h/x') + rec_known(0) + rec_upgrade('application/x-other')))
    f.append(c.s(REC_UPRSP))
    f.append(c.c(rec_sized(b'after upgrade')))
    # 4: every record type without an upgrade
    d = Conv(49503)
    for m in (1, 2, 3, 4, 5, 0):
        f.append(d.c(rec_version(1, 0) + rec_mode(m)))
    f.append(d.c(rec_version(2, 1)))
    for e in range(0, 10):
        f.append(d.c(rec_known(e)))
    f.append(d.c(rec_ext('application/soap+xml; charset=utf-8')))
    f.append(d.c(rec_via('x' * 130)))                           # two octet size
    f.append(d.c(rec_via('y' * 20000)))                         # three octet size
    f.append(d.c(rec_sized(b'\x01\x02\x03' * 100)))
    f.append(d.c(rec_sized(b'')))
    f.append(d.c(rec_unsized([b'chunk one', b'chunk two' * 20, b'x'])))
    f.append(d.c(rec_unsized([b'only'])))
    f.append(d.c(rec_fault('s:Sender')))
    f.append(d.c(rec_fault('')))
    f.append(d.c(REC_END))
    f.append(d.s(REC_ACK))
    f.append(d.c(REC_PEND))
    f.append(d.s(REC_UPRSP))                                     # response without a request
    f.append(d.c(b'\x0d'))                                       # unknown record type
    f.append(d.c(b'\xff'))
    # several records in one frame
    f.append(d.c(rec_sized(b'one') + rec_sized(b'two') + REC_END + rec_fault('f') + rec_unsized([b'z'])))
    f.append(d.c(rec_sized(b'x' * 130) + rec_unsized([b'y' * 200, b'z' * 300])))
    # varints of up to five octets for the record sizes (sizes that fit in the frame)
    f.append(d.c(b'\x06' + bytes([0x85, 0x00]) + b'\0' * 5))      # redundant continuation
    return f


def malformed_frames():
    f = []
    d = Conv(49600)

    def c(p):
        f.append(d.c(p))

    # sizes above 32 bits, a run of continuation octets (no terminator)
    c(b'\x02' + bytes([0xff, 0xff, 0xff, 0xff, 0x7f]) + b'abc')
    c(b'\x06' + bytes([0xff, 0xff, 0xff, 0xff, 0x0f]) + b'abc')
    c(b'\x06' + bytes([0x80] * 6))
    c(b'\x02' + bytes([0x80] * 5))
    c(b'\x09' + bytes([0x80] * 5))
    c(b'\x04' + bytes([0xff, 0xff, 0xff, 0xff, 0x1f]))
    c(b'\x08' + bytes([0x80] * 5))
    c(b'\x05' + bytes([0x80] * 5))
    c(b'\x05' + bytes([0xff, 0xff, 0xff, 0xff, 0x7f]))
    # sizes longer than the frame
    c(rec_via('abc')[:-1])
    c(b'\x02\x40abc')
    c(b'\x06\x20' + b'x' * 5)
    c(b'\x08\x30fault')
    c(b'\x09\x30application/neg')
    c(b'\x04\x30text')
    # unsized envelope without a terminator, or with a chunk past the end
    c(b'\x05\x03abc')
    c(b'\x05\x03abc\x03xyz')
    c(b'\x05\x09abc')
    c(b'\x05')
    # truncated fixed records
    c(b'\x00\x01')
    c(b'\x00')
    c(b'\x01')
    c(b'\x03')
    # the size is exactly at the end
    c(b'\x06\x00')
    c(b'\x02')
    # upgrade response before the request, then the request (the reproducer
    # of the pass-two state bug: frames are MC-NMF in one pass and handed to
    # MS-NNS with tshark -2); real TCP frames for Decode As
    t = TCP(CLI, 40001, SRV, 9389)
    f += t.handshake()
    f.append(t.s2c(REC_UPRSP))
    f.append(t.c2s(rec_version() + rec_mode(2) + rec_upgrade('application/negotiate')))
    f.append(t.s2c(REC_UPRSP))
    f.append(t.c2s(REC_PEND))
    f.append(t.s2c(b'\x16\x01\x00\x00\x04\x01\x02\x03\x04'))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    pcapng(out + '/mc-nmf-coverage.pcapng', mf)
    xf = malformed_frames()
    pcapng(out + '/mc-nmf-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main', len(mf), 'malformed', len(xf))


main()

# Generates test/captures/shim6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# --- pcap helpers (synthetic addresses only) ---
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64, flags_frag=0, options=b''):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ihl = 5 + len(options) // 4
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags_frag, ttl, proto, 0, s, d) + options
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]

def eth(payload, ethertype=0x0800, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst) + u)

def tcp(sport, dport, payload, seq=1, ack=1, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst) + t)

def ipv6(nxt, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)

def write(fn, pkts, linktype=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def exported_pdu(name, payload, tag=12):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', tag, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

class Flow:
    '''TCP connection with a handshake and tracked sequence numbers.'''
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', cisn=1000, sisn=5000, hs=False):
        self.cp, self.sp, self.c, self.s = cport, sport, client, server
        self.cseq, self.sseq = cisn, sisn
        self.pk = []
        if hs:
            self.pk.append(tcp(cport, sport, b'', self.cseq, 0, client, server, 0x02)); self.cseq += 1
            self.pk.append(tcp(sport, cport, b'', self.sseq, self.cseq, server, client, 0x12)); self.sseq += 1
            self.pk.append(tcp(cport, sport, b'', self.cseq, self.sseq, client, server, 0x10))
    def c2s(self, data):
        self.pk.append(tcp(self.cp, self.sp, data, self.cseq, self.sseq, self.c, self.s)); self.cseq += len(data)
    def s2c(self, data):
        self.pk.append(tcp(self.sp, self.cp, data, self.sseq, self.cseq, self.s, self.c)); self.sseq += len(data)

def tpkt(payload):
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload

def cotp_dt(payload, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + payload)

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t
_CRC_T = _crc32c_table()

def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _CRC_T[(c ^ b) & 0xff] ^ (c >> 8)
    return (~c) & 0xffffffff

def sctp_data(sport, dport, payload, ppi=0, tsn=1, sid=0, ssn=0, vtag=0x11223344, src='192.0.2.1', dst='192.0.2.2', flags=3):
    '''SCTP packet with one DATA chunk (B and E flags set by default).'''
    pad = (-len(payload)) % 4
    chunk = struct.pack('!BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppi) + payload + b'\0' * pad
    hdr = struct.pack('!HHII', sport, dport, vtag, 0)
    cs = crc32c(hdr + chunk)
    hdr = struct.pack('!HHI', sport, dport, vtag) + struct.pack('<I', cs)
    pkt = hdr + chunk
    return eth(ipv4(132, pkt, src, dst) + pkt)

def write_pcapng(fn, pkts, linktypes=(1,), snap=262144):
    '''pkts: list of (interface index, bytes). One IDB per link-layer type.'''
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, snap))
    for i, (ifc, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(fn, 'wb').write(out)
# --- end helpers ---
# Generator for the SHIM6 coverage captures: python3 mkshim6.py <outdir>
# SHIM6 is IPv6 next header (IP protocol) 140, registered by default.
#
# The control messages are laid out the way this version of the dissector
# reads them (see the README): the type specific data starts at octet 5 and
# the options at 14 + the length of the type specific data. The generator
# computes the checksum of the whole header so that it verifies.
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
CLI, SRV = '2001:db8::1', '2001:db8::2'
CT = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])

def u32(v): return struct.pack('!I', v)

def ipv6_frame(nxt, payload, src=CLI, dst=SRV):
    return eth(ipv6(nxt, payload, src, dst) + payload, 0x86dd)

def shim6(ptype, spec=b'', opts=b'', nxt=59, hlen=None, bad_csum=False, trailer=b'\0' * 96):
    '''Control message: octet 0 next header, 1 length, 2 P=0 | type,
    3-4 checksum, 5.. type specific data, then options.'''
    body = bytearray(b'\0' * 5) + spec
    # options are placed where dissect_shimopts() reads the first one
    opt_off = 14 + len(spec)
    need = max(len(body), opt_off + len(opts)) if opts else len(body)
    if hlen is None:
        hlen = (need + 7) // 8 * 8
        hlen = max(hlen, 16)
    hdr = bytearray(hlen)
    hdr[0], hdr[1], hdr[2] = nxt, hlen // 8 - 1, ptype
    hdr[5:5 + len(spec)] = spec
    if opts:
        hdr[opt_off:opt_off + len(opts)] = opts
    # The dissector reads the checksum at octets 3-4, which straddles two
    # 16 bit words, so the field holds the byte swapped usual value
    cs = csum(bytes(hdr))
    cs = ((cs & 0xff) << 8) | (cs >> 8)
    if bad_csum: cs ^= 0x1234
    hdr[3:5] = struct.pack('!H', cs)
    return bytes(hdr) + trailer

def opt(otype, content, critical=0, length=None):
    L = len(content) if length is None else length
    pad = 7 - ((L + 3) % 8)
    return struct.pack('!HH', (otype << 1) | critical, L) + content + b'\0' * pad

def payload_ext(ct0=0x15, nxt=59, trailer=b'\0' * 32):
    hdr = bytes([nxt, 0, 0x80 | ct0, 0x23, 0x45, 0x67, 0x89, 0xab])
    return hdr + trailer

pk = []
def V6(sh, **k): pk.append(ipv6_frame(140, sh, **k))

# --- control messages without options: every type
V6(shim6(1, CT + u32(0x11111111)))                                         # I1
V6(shim6(2, b'\0\0' + u32(0x22222222) + u32(0x33333333)))                  # R1
V6(shim6(3, CT + u32(1) + u32(2) + b'\0' * 4), src=SRV, dst=CLI)            # I2
V6(shim6(4, CT + u32(0x44444444)), src=SRV, dst=CLI)                        # R2
V6(shim6(5, CT + u32(0x55555555)))                                         # R1bis
V6(shim6(6, CT + u32(1) + u32(2) + b'\0' * 6 + CT))                        # I2bis
V6(shim6(0x40, CT + u32(0x66666666)))                                      # Update Request
V6(shim6(0x41, CT + u32(0x66666666)), src=SRV, dst=CLI)                    # Update Acknowledgment
V6(shim6(0x42, CT + b'\0' * 4))                                            # Keepalive
V6(shim6(0x7f, b'\0' * 8))                                                 # unknown type
# probe messages: none, sent only, received only, both; REAP states
def probe(sent, rcvd, state):
    spec = CT + bytes([(rcvd << 4) | sent, state << 6, 0, 0])
    for i in range(sent + rcvd):
        spec += bytes.fromhex('20010db8000000000000000000000001') + bytes.fromhex('20010db8000000000000000000000002') + u32(0xa0 + i) + u32(0xb0 + i)
    return spec
V6(shim6(0x43, probe(0, 0, 0)))
V6(shim6(0x43, probe(2, 0, 1)))
V6(shim6(0x43, probe(0, 1, 2)))
V6(shim6(0x43, probe(1, 2, 3)))
# --- options (placed after a type specific part of ten octets: I1)
CIDS = CT + u32(0x12345678)
LOC1 = bytes.fromhex('20010db8000000000000000000000011')
LOC2 = bytes.fromhex('20010db8000000000000000000000012')
V6(shim6(1, CIDS, opt(1, b'\xaa' * 8)))                                     # responder validator
V6(shim6(1, CIDS, opt(2, bytes([2, 1, 2]) + b'\0' * 5 + LOC1 + LOC2)))     # locator list, two locators
V6(shim6(1, CIDS, opt(2, bytes([8]) + bytes(range(1, 9)) + b"\0" * 7 + LOC1 * 8)))   # locator list, eight locators
V6(shim6(1, CIDS, opt(3, bytes([3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), length=7)))     # locator preferences, 3 octet elements
V6(shim6(1, CIDS, opt(3, bytes([2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), length=7)))     # 2 octet elements
V6(shim6(1, CIDS, opt(3, bytes([1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), length=7)))     # 1 octet elements
V6(shim6(1, CIDS, opt(4, b'cga parameter data structure')))                 # CGA parameter data
V6(shim6(1, CIDS, opt(5, b'cga signature bytes!!!', critical=1)))            # CGA signature
V6(shim6(1, CIDS, opt(6, b'\0' * 4 + LOC1 + LOC2, critical=1)))              # ULID pair
V6(shim6(1, CIDS, opt(7, u32(0xcafebabe))))                                  # forked instance id
V6(shim6(1, CIDS, opt(0x55, b'unknown option')))                             # unknown option type
V6(shim6(1, CIDS, opt(1, b'\x01' * 4) + opt(7, u32(1)) + opt(4, b'pdm')))   # several options
# --- payload extension header (P bit set) with a context tag
V6(payload_ext(0x15))
V6(payload_ext(0x00, trailer=b'\0' * 40))
# --- from IPv4 (IP protocol 140)
sh4 = shim6(1, CIDS)
pk.append(eth(ipv4(140, sh4, '192.0.2.1', '192.0.2.2') + sh4))
sh4p = payload_ext(0x33)
pk.append(eth(ipv4(140, sh4p, '192.0.2.1', '192.0.2.2') + sh4p))
write(os.path.join(outdir, 'shim6-coverage.pcap'), pk)

# Malformed capture: bad checksum, invalid locator preference element
# length, truncated headers and options
m = []
def M(sh, **k): m.append(ipv6_frame(140, sh, **k))
M(shim6(1, CIDS, bad_csum=True))
M(shim6(1, CIDS, opt(3, bytes([0, 1, 2, 3, 4, 5, 6]), length=7)))
M(shim6(1, CIDS, opt(3, bytes([4, 1, 2, 3, 4, 5, 6]), length=7)))

M(shim6(0x43, probe(3, 3, 1))[:70])
M(shim6(1, CIDS)[:12])
M(bytes([59, 0]))
M(shim6(1, CIDS, opt(2, bytes([200]) + b'\0' * 10), trailer=b''))
M(shim6(1, CIDS, opt(6, b'\0' * 10), trailer=b''))
M(shim6(1, CIDS, b'', trailer=b'') [:20])
M(payload_ext(trailer=b'')[:6])
write(os.path.join(outdir, 'shim6-coverage-malformed.pcap'), m)

# Generates test/captures/shicp_coverage.pcap.gz
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
# Generator for the SHICP coverage captures: python3 mkshicp.py <outdir>
# SHICP is a heuristic dissector on UDP, destination port 3250.
#
# Layout built here (this is what the dissector decodes, see the README):
#   0-1  header 0xABC0 | version (little endian), 2-7 destination MAC,
#   8-13 source MAC, 14 flags, 15 message type, 16 payload length (the
#   dissector reads 16 bits at 16 but advances one octet, so the second
#   octet is the first payload octet and must be 0 for the length to be
#   right), 17.. payload.
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
MOD = b'\x02\x11\x22\x33\x44\x55'
HOST = b'\x02\xaa\xbb\xcc\xdd\xee'
BCAST = b'\xff' * 6
REQ, RESP, ERR = 0x00, 0x01, 0x02

def msg(mtype, payload=b'', flags=REQ, dst=BCAST, src=HOST, ver=1, plen=None, pad=0):
    if plen is None: plen = len(payload)
    return struct.pack('<H', 0xABC0 | ver) + dst + src + bytes([flags, mtype, plen]) + payload + b'\0' * pad

def tlv(key, val):
    return bytes([key, len(val)]) + val

def ip(a): return bytes(map(int, a.split('.')))[::-1]     # shown little endian by the dissector

TOKEN = b'\x00' + bytes(range(0x41, 0x41 + 35))     # 36 octets, first octet 0

def pkt(m, dport=3250, sport=50000, src='192.0.2.10', dst='192.0.2.20'):
    return udp(sport, dport, m, src, dst)

main = []
# 1: discover request (broadcast) without parameters, padded to the 18 octet minimum
main.append(pkt(msg(0x00, b'', REQ, plen=0, pad=1)))
# 2: discover response with every parameter
disc = (tlv(0x00, b'\x01') + tlv(0x01, b'1.2.3') + tlv(0x02, b'Test module') +
        tlv(0x03, bytes([0, 1, 2, 3, 4, 5, 9])) + tlv(0x04, ip('192.0.2.77')) +
        tlv(0x05, ip('255.255.255.0')) + tlv(0x06, ip('192.0.2.1')) +
        tlv(0x07, ip('192.0.2.53')) + tlv(0x08, ip('192.0.2.54')) + tlv(0x09, b'\x00') +
        tlv(0x0A, b'module-1') + tlv(0x0B, b'\x20') + tlv(0x0C, b'\x40') + tlv(0x7f, b'xx'))
main.append(pkt(msg(0x00, disc, RESP, dst=HOST, src=MOD), dport=3250, sport=3250))
# 3: discover response with authentication not required and one supported message
main.append(pkt(msg(0x00, tlv(0, b'\x00') + tlv(3, b'\x02'), RESP, dst=HOST, src=MOD)))
# 4: authentication challenge request (too short for a challenge), 5: response
main.append(pkt(msg(0x01, b'\x00', REQ, dst=MOD, src=HOST)))
main.append(pkt(msg(0x01, b'\x00\x01\x02\x03\x1e', RESP, dst=HOST, src=MOD)))
# 6: configuration request with a token and every parameter
cfg = (TOKEN + tlv(0x00, ip('192.0.2.88')) + tlv(0x01, ip('255.255.0.0')) +
       tlv(0x02, ip('192.0.2.2')) + tlv(0x03, ip('192.0.2.3')) + tlv(0x04, ip('192.0.2.4')) +
       tlv(0x05, b'\x01') + tlv(0x06, b'newname') + tlv(0x07, b'secret') + tlv(0x55, b'??'))
main.append(pkt(msg(0x02, cfg, REQ, dst=MOD, src=HOST)))
# 7: configuration response, one octet payload shown as an error code
main.append(pkt(msg(0x02, b'\x00', RESP, dst=HOST, src=MOD)))
# 8: configuration without token (parameters only)
main.append(pkt(msg(0x02, tlv(0, ip('192.0.2.99')) + tlv(6, b'x'), REQ, dst=MOD, src=HOST)))
# 9: wink request with token and type, 10: wink that is too short, 11: wink response
main.append(pkt(msg(0x03, TOKEN + b'\x01', REQ, dst=MOD, src=HOST)))
main.append(pkt(msg(0x03, b'\x00\x00', REQ, dst=MOD, src=HOST)))
main.append(pkt(msg(0x03, b'\x00', RESP, dst=HOST, src=MOD)))
# 12-13: restart request, immediate and delayed
main.append(pkt(msg(0x04, TOKEN + b'\x00', REQ, dst=MOD, src=HOST)))
main.append(pkt(msg(0x04, TOKEN + b'\x01', REQ, dst=MOD, src=HOST)))
# 14: restart too short, 15: mass restart, 16: unknown message type
main.append(pkt(msg(0x04, b'\x00', REQ, dst=MOD, src=HOST)))
main.append(pkt(msg(0x05, b'\x00', REQ)))
main.append(pkt(msg(0x09, b'\x00', REQ, dst=MOD)))
# 17-19: error messages. The error code is read from the octet after the
# length (the second octet of the 16 bit length), so only code 0 is
# reachable: request class, response class, and a frame laid out with a
# 16 bit length (01 00 05) whose code 5 is not shown (see the README).
main.append(pkt(msg(0x02, b'\x00', ERR, dst=HOST, src=MOD)))
main.append(pkt(msg(0x02, b'\x00', ERR | RESP, dst=HOST, src=MOD)))
main.append(pkt(msg(0x02, b'\x00\x05', ERR | RESP, dst=HOST, src=MOD, plen=1)))
# Protocol version 0 (the version is in the low three bits of the header tag)
main.append(pkt(msg(0x00, b'', REQ, ver=0, plen=0, pad=1)))
# Not SHICP: destination port 3251, bad header tag, longer than 548 octets
main.append(pkt(msg(0x00, b'', REQ, plen=0, pad=1), dport=3251))
bad = bytearray(msg(0x00, b'', REQ, plen=0, pad=1)); bad[1] = 0xAA
main.append(pkt(bytes(bad)))
main.append(pkt(msg(0x00, b'', REQ, plen=0, pad=540)))
write(os.path.join(outdir, 'shicp-coverage.pcap'), main)

# Malformed: error messages with a payload length other than 1, and
# parameter lists that run past the end of the datagram
m2 = []
m2.append(pkt(msg(0x02, b'\x00', ERR | RESP, dst=HOST, src=MOD, plen=0)))
m2.append(pkt(msg(0x02, b'\x00\x01', ERR | RESP, dst=HOST, src=MOD)))
m2.append(pkt(msg(0x00, b'\x00\x01\x01\x03\x20', RESP, dst=HOST, src=MOD, pad=10)))
m2.append(pkt(msg(0x00, tlv(0, b'\x01') + b'\x01', RESP, dst=HOST, src=MOD, plen=40, pad=3)))
m2.append(pkt(msg(0x02, TOKEN + b'\x00\x04\x01', REQ, dst=MOD, src=HOST)))
write(os.path.join(outdir, 'shicp-coverage-malformed.pcap'), m2)

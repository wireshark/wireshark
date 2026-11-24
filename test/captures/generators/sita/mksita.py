# Generates test/captures/sita_coverage.pcap.gz
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
# Generator for the SITA coverage captures: python3 mksita.py <outdir>
# SITA WAN frames use pcap link-layer type 196 (LINKTYPE_SITA): a five octet
# pseudo-header (flags, signals, errors1, errors2, protocol) and the payload.
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
TX, RX = 0x00, 0x01

def sita(flags, signals, e1, e2, proto, payload=b''):
    return bytes([flags, signals, e1, e2, proto]) + payload

# payloads for the protocols the dissector hands over to
X25_DATA = b'\x10\x01\x00' + b'x25 user data'
lapb_i = b'\x01\x00' + X25_DATA                  # information frame
lapb_rr = b'\x01\x11'                            # receive ready, P/F set
lapb_sabm = b'\x03\x3f'                          # SABM
udp_pkt = struct.pack('!HHHH', 1000, 2000, 12, 0) + b'abcd'
ip = ipv4(17, udp_pkt) + udp_pkt
frl = b'\x18\x01\x03\xcc' + ip                   # Q.922 address, UI, NLPID IP, IPv4 packet
uts = b'\x01\x20\x20\x02\x31\x32\x33\x03\x04'    # SOH, address, STX, text, ETX, EOT
ipars = b'\x16\x01\x03\x00\x01\x02\x03\x04'

pk = []
# direction, signals and no buffer flag with a LAPB payload
pk.append(sita(TX, 0x00, 0, 0, 0x01, lapb_sabm))
pk.append(sita(RX, 0x1f, 0, 0, 0x01, lapb_rr))
pk.append(sita(TX, 0x0f, 0, 0, 0x01, lapb_i))
pk.append(sita(RX | 0x80, 0x10, 0, 0, 0x01, lapb_i))
# receive errors: every bit of errors1 and errors2, and some single bits
pk.append(sita(RX, 0x01, 0x1f, 0xff, 0x01, lapb_rr))
pk.append(sita(RX, 0x02, 0x01, 0x01, 0x01, lapb_rr))
pk.append(sita(RX, 0x04, 0x10, 0x40, 0x01, lapb_rr))
pk.append(sita(RX, 0x08, 0x00, 0x80, 0x01, lapb_rr))
# transmit errors
pk.append(sita(TX, 0x00, 0x00, 0x0f, 0x01, lapb_rr))
pk.append(sita(TX | 0x80, 0x02, 0x00, 0x01, 0x01, lapb_rr))
pk.append(sita(TX, 0x04, 0x00, 0x08, 0x01, lapb_rr))
# the other protocols with a dissector: Frame Relay, UTS, IPARS
pk.append(sita(TX, 0x1f, 0, 0, 0x12, frl))
pk.append(sita(RX, 0x1f, 0, 0, 0x06, uts))
pk.append(sita(TX, 0x1f, 0, 0, 0x05, ipars))
# protocols that have a name but no dissector, and unnamed ones
for proto in (0x00, 0x02, 0x03, 0x04, 0x07, 0x08, 0x09, 0x10, 0x11, 0x55):
    pk.append(sita(RX if proto & 1 else TX, 0x03, 0, 0, proto, b'payload %02x' % proto))
write(os.path.join(outdir, 'sita-coverage.pcap'), pk, linktype=196)

# Truncated payloads of the sub-dissectors
m = []
m.append(sita(TX, 0, 0, 0, 0x01))                        # no payload at all
m.append(sita(RX, 0x1f, 0, 0, 0x01, b'\x01'))
m.append(sita(TX, 0x1f, 0, 0, 0x12, b'\x18'))
m.append(sita(TX, 0x1f, 0, 0, 0x12, b'\x18\x01\x03\xcc\x45\x00'))
m.append(sita(RX, 0x1f, 0, 0, 0x06, b'\x01'))
m.append(sita(RX, 0x1f, 0, 0, 0x05, b'\x16'))
m.append(sita(TX, 0x00, 0, 0, 0x01, b'\x01\x00\x10'))
write(os.path.join(outdir, 'sita-coverage-malformed.pcap'), m, linktype=196)

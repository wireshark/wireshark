# Generates test/captures/slimp3_coverage.pcap.gz
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
# Generator for the SliMP3 coverage captures: python3 mkslimp3.py <outdir>
# UDP ports 1069 (old protocol) and 3483 are registered by default.
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
CLI, SRV = '192.0.2.50', '192.0.2.1'
CMAC = b'\x02\x00\x00\x00\x00\x01'      # the Ethernet source of udp() frames

def u16(v): return struct.pack('!H', v)
def u32(v): return struct.pack('!I', v)

pk = []
def to_srv(m, port=3483, sport=3483):   # client -> server
    pk.append(udp(sport, port, m, CLI, SRV))
def to_cli(m, port=3483, dport=3483):   # server -> client
    pk.append(udp(port, dport, m, SRV, CLI))

# --- infrared codes: SLIMP3 remote (known and unknown), JVC (known and
# unknown), and a code id nobody knows
def ir(cid, bits, code):
    return b'i\x00' + u32(625000 * 3 + 17) + bytes([cid, bits]) + u32(code) + b'\0' * 6
to_srv(ir(0x02, 32, 0x768910ef), sport=40000)
to_srv(ir(0x02, 32, 0x12345678), sport=40000)
to_srv(ir(0xff, 16, 0xf786), sport=40000)
to_srv(ir(0xff, 16, 0x1234), sport=40000)
to_srv(ir(0x05, 8, 0xabcdef01), sport=40000)
# the old protocol: the server port is 1069
to_srv(ir(0x02, 32, 0x768940bf), port=1069, sport=40000)

# --- display: delay, characters (printable, repeated blanks, not
# printable), commands (with and without the second octet of Set), unknown
def disp(*cmds): return b'l' + b'\0' * 17 + b''.join(cmds)
def ch(c): return bytes([3, ord(c) if isinstance(c, str) else c])
to_cli(disp(b'\x00\x05', ch('H'), ch('i'), ch(' '), ch(' '), ch('x'), ch(0x07), b'\x00\x01',
            b'\x02\x01', b'\x02\x30\x00\x02', b'\x02\x30\x03\x00', b'\x02\x0c', b'\x02\x20', b'\x07\x07',
            ch('A')), dport=40000)
to_cli(disp(*[ch('a') for _ in range(70)]), dport=40000)                # string longer than the text buffer
to_cli(disp(b'\x02\x80', ch('B'), b'\x00\x00', ch('C')), dport=40000)
to_cli(disp(), dport=40000)                                            # no commands
to_cli(disp(b'\x00\x00' * 70), dport=40000)

# --- stream control
for c in (1, 2, 4, 9):
    to_cli(b's' + bytes([c]) + b'\0' * 16, dport=40000)

# --- hello: client response to the server, server request to the client
# (and the same on port 3483 on both sides, told apart by the client MAC)
to_srv(b'h\x03\x12' + b'\0' * 15, sport=40000)
to_cli(b'h' + b'\0' * 17, dport=40000)
to_srv(b'h\x03\x20' + b'\0' * 9 + CMAC)                                 # MAC is the sender: to server
to_cli(b'h\x03\x20' + b'\0' * 9 + b'\x02\x99\x99\x99\x99\x99', dport=3483)    # another MAC: to client

# --- I2C
to_srv(b'2' + b'\x01\x02\x03' * 3, sport=40000)
to_cli(b'2' + b'\x04\x05\x06' * 3, dport=40000)

# --- data request and MPEG data (new protocol: command, write pointer,
# sequence number; old protocol on port 1069: offset)
to_srv(b'r\0' + u16(0x0123) + b'\0' * 14, sport=40000)
for cmd, wp, seq in ((0, 0x100, 1), (1, 0x200, 2), (3, 0x300, 3), (9, 0x400, 4)):
    to_cli(b'm' + bytes([cmd]) + b'\0' * 4 + u16(wp) + b'\0\0' + u16(seq) + b'\0' * 6 + bytes(range(32)), dport=40000)
to_cli(b'm\0' + u16(0x0abc) + b'\0' * 14 + b'MPEG' * 8, port=1069, dport=40000)
to_srv(b'r\0' + u16(0x0044) + b'\0' * 14, port=1069, sport=40000)

# --- discovery
to_srv(b'd\x03\x21' + b'\0' * 15, sport=40000)
to_cli(b'D\0' + bytes([192, 0, 2, 1]) + u16(3483) + b'\0' * 10, dport=40000)

# --- acknowledgement
to_srv(b'a\0\0\0\0\0' + u16(0x0100) + u16(0x00f0) + u16(5) + CMAC, sport=40000)

# not SliMP3: unknown opcode
to_srv(b'Z' + b'\0' * 17, sport=40000)
write(os.path.join(outdir, 'slimp3-coverage.pcap'), pk)

# Short packets: fields past the end of the packet
m = []
m.append(udp(40000, 3483, b'i\x00\x00', CLI, SRV))
m.append(udp(3483, 40000, b'l' + b'\0' * 17 + b'\x02', SRV, CLI))
m.append(udp(3483, 40000, b'l' + b'\0' * 17 + b'\x03', SRV, CLI))
m.append(udp(3483, 40000, b'm\0\0\0', SRV, CLI))
m.append(udp(3483, 40000, b'D\0\xc0', SRV, CLI))
m.append(udp(40000, 3483, b'd', CLI, SRV))
m.append(udp(40000, 3483, b'a\0\0\0\0\0\0', CLI, SRV))
m.append(udp(40000, 3483, b'r\0', CLI, SRV))
m.append(udp(40000, 3483, b's', CLI, SRV))
m.append(udp(40000, 3483, b'h\x03', CLI, SRV))
write(os.path.join(outdir, 'slimp3-coverage-malformed.pcap'), m)

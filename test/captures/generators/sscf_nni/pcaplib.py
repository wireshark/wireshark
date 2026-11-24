# Helper module for the sscf_nni capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Small helpers to build synthetic captures with struct.
import struct
import zlib

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    def __init__(self, linktype, snaplen=262144):
        self.linktype = linktype
        self.snaplen = snaplen
        self.frames = []
    def add(self, data, ts=None):
        self.frames.append(bytes(data))
        return len(self.frames)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, self.snaplen, self.linktype))
            for i, fr in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1000000 + i, (i * 1000) % 1000000, len(fr), len(fr)) + fr)

MAC_A = b'\x02\x00\x00\x00\x00\x01'
MAC_B = b'\x02\x00\x00\x00\x00\x02'

def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('!H', etype) + payload

def eth8023(payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('!H', len(payload)) + payload

def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(payload, sport, dport):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def tcp(payload, sport, dport, seq, ack, flags=0x18, win=65535):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff

def sctp_data(payload, sport, dport, vtag, tsn, ppi, sid=0, ssn=0, flags=3):
    ch = struct.pack('!BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppi) + payload
    ch += b'\0' * ((-len(ch)) % 4)
    hdr = struct.pack('!HHII', sport, dport, vtag, 0) + ch
    cs = crc32c(hdr)
    return hdr[:8] + struct.pack('<I', cs) + hdr[12:]

def exported_pdu(name, payload):
    n = name.encode()
    tag = struct.pack('!HH', 12, len(n)) + n
    return tag + struct.pack('!HH', 0, 0) + bytes(payload)

class Pcapng:
    def __init__(self):
        self.ifaces = []
        self.frames = []
    def iface(self, linktype, snaplen=262144):
        self.ifaces.append((linktype, snaplen))
        return len(self.ifaces) - 1
    def add(self, data, iface=0):
        self.frames.append((iface, bytes(data)))
        return len(self.frames)
    def write(self, path):
        def blk(t, body):
            body += b'\0' * ((-len(body)) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt, sl in self.ifaces:
            out += blk(1, struct.pack('<HHI', lt, 0, sl))
        for i, (ifc, d) in enumerate(self.frames):
            ts = 1000000 * 1000 + i * 1000
            out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        with open(path, 'wb') as f:
            f.write(out)

# --- HDLC / LAPD bit streams -------------------------------------------------
def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return (~crc) & 0xffff

def hdlc_bits(frame, fcs='<'):
    """Bits (in transmission order, LSB of each octet first) of a frame with
    its FCS and zero insertion, without flags."""
    data = bytes(frame) + struct.pack(fcs + 'H', crc16_x25(frame))
    bits, ones = [], 0
    for b in data:
        for i in range(8):
            bit = (b >> i) & 1
            bits.append(bit)
            ones = ones + 1 if bit else 0
            if ones == 5:
                bits.append(0)
                ones = 0
    return bits

FLAG_BITS = [0, 1, 1, 1, 1, 1, 1, 0]

def pack_bits(bits):
    """Pack bits, first transmitted bit in the most significant position."""
    bits = list(bits) + [0] * ((-len(bits)) % 8)
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

def reverse8(b):
    return int('{:08b}'.format(b)[::-1], 2)

def hdlc_stream(frames, lead=2, fcs='<', align=8, gap=0, tail=0):
    """Octet stream of frames separated by flags (and `gap` extra flags);
    padded with flag bits to a multiple of `align` octets."""
    bits = FLAG_BITS * lead
    for f in frames:
        bits += hdlc_bits(f, fcs) + FLAG_BITS * (1 + gap)
    bits += FLAG_BITS * tail
    n = -(-len(bits) // (8 * align)) * (8 * align)
    while len(bits) < n:
        bits += FLAG_BITS
    return pack_bits(bits[:n])

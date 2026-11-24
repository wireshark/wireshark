# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the batch 35 c11 coverage generators (synthetic data only)
import struct
import gzip

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), ident, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')

def eth(ip, etype=0x0800, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('!H', etype) + ip

def udp(sport, dport, payload, rev=False, **kw):
    u = struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload
    if rev:
        kw = dict(kw); kw.setdefault('src', '192.0.2.2'); kw.setdefault('dst', '192.0.2.1')
        return eth(ipv4(17, u, **kw), dst=MAC_A, src=MAC_B)
    return eth(ipv4(17, u, **kw))

def ipv4_pseudo(src, dst, l):
    return bytes(map(int, src.split('.'))) + bytes(map(int, dst.split('.'))) + struct.pack('!BBH', 0, 6, l)

class TcpStream:
    """One TCP connection; c2s()/s2c() return Ethernet frames."""
    def __init__(self, cport, sport, caddr='192.0.2.1', saddr='192.0.2.2'):
        self.cport, self.sport, self.caddr, self.saddr = cport, sport, caddr, saddr
        self.cseq, self.sseq = 1000, 5000
    def _tcp(self, fromc, payload, flags):
        if fromc:
            sp, dp, seq, ack, src, dst = self.cport, self.sport, self.cseq, self.sseq, self.caddr, self.saddr
        else:
            sp, dp, seq, ack, src, dst = self.sport, self.cport, self.sseq, self.cseq, self.saddr, self.caddr
        opts = b''
        if flags & 2:       # SYN: MSS option; a plain SYN has no ACK number
            opts = b'\x02\x04\x05\xb4'
            if flags == 0x02: ack = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        c = csum(ipv4_pseudo(src, dst, len(t)) + t)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        f = eth(ipv4(6, t, src=src, dst=dst), dst=MAC_B if fromc else MAC_A, src=MAC_A if fromc else MAC_B)
        n = len(payload) + (1 if flags & 3 else 0)
        if fromc: self.cseq += n
        else: self.sseq += n
        return f
    def handshake(self):
        return [self._tcp(True, b'', 0x02), self._tcp(False, b'', 0x12), self._tcp(True, b'', 0x10)]
    def c2s(self, payload, flags=0x18): return self._tcp(True, payload, flags)
    def s2c(self, payload, flags=0x18): return self._tcp(False, payload, flags)

def write_pcap(fn, frames, linktype=1, t0=1000.0):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple): ts, fr = fr
            else: ts = t0 + i
            f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1000000), len(fr), len(fr)) + fr)

def gz(fn, out=None):
    with open(fn, 'rb') as f: d = f.read()
    with open(out or fn + ".gz", "wb") as g:
        g.write(gzip.compress(d, 9, mtime=0))

def exported_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return struct.pack('!HH', 12, len(n)+pad) + n + b'\0'*pad + struct.pack('!HH', 0, 0) + payload

# --- BER ---
def blen(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag, v=b''):
    if isinstance(tag, int): tag = bytes([tag]) if tag < 256 else tag.to_bytes(2, 'big')
    return tag + blen(len(v)) + v

def seq(*items, tag=0x30): return tlv(tag, b''.join(items))

def integer(v, tag=0x02):
    if v == 0: b = b'\0'
    elif v > 0: b = v.to_bytes((v.bit_length()+8)//8, 'big')
    else:
        n = ((-v-1).bit_length()+8)//8
        b = (v + (1 << (8*n))).to_bytes(n, 'big')
    return tlv(tag, b)

def octets(b, tag=0x04):
    if isinstance(b, str): b = b.encode()
    return tlv(tag, b)

def oid(s, tag=0x06):
    a = [int(x) for x in s.split('.')]
    out = bytes([a[0]*40 + a[1]])
    for x in a[2:]:
        e = [x & 0x7f]; x >>= 7
        while x: e.append(0x80 | (x & 0x7f)); x >>= 7
        out += bytes(reversed(e))
    return tlv(tag, out)

def null(tag=0x05): return tlv(tag)
def boolean(v, tag=0x01): return tlv(tag, b'\xff' if v else b'\0')
def utf8(s, tag=0x0c): return tlv(tag, s.encode())
def ia5(s, tag=0x16): return tlv(tag, s.encode())
def bitstr(b, unused=0, tag=0x03): return tlv(tag, bytes([unused]) + b)

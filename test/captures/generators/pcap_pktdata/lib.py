# Helper module for the pcap_pktdata capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# shared helpers for synthetic captures (synthetic addresses only)
import struct
import socket
import sys
import gzip
import shutil

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s): return socket.inet_aton(s)
def ip6(s): return socket.inet_pton(socket.AF_INET6, s)

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ttl=64, ident=1, flags=0, frag=0, opts=b''):
    ihl = 5 + len(opts)//4
    h = struct.pack('!BBHHHBBH4s4s', 0x40|ihl, 0, 4*ihl+len(payload), ident, (flags<<13)|frag, ttl, proto, 0, ip4(src), ip4(dst)) + opts
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ipv6(nh, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, hlim, ip6(src), ip6(dst)) + payload

def eth(payload, etype=0x0800, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    return dst + src + struct.pack('!H', etype) + payload

def udp_payload(sport, dport, payload, src=None, dst=None):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    return eth(ipv4(17, udp_payload(sport, dport, payload), src, dst))

def udp6_payload(sport, dport, payload, src='2001:db8::1', dst='2001:db8::2'):
    u = struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload
    ph = ip6(src) + ip6(dst) + struct.pack('!IBBBB', len(u), 0, 0, 0, 17)
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def udp6(sport, dport, payload, src='2001:db8::1', dst='2001:db8::2'):
    u = udp6_payload(sport, dport, payload, src, dst)
    return eth(ipv6(17, u, src, dst), 0x86dd)

def tcp_seg(sport, dport, seq, ack, payload, flags=0x18, win=65535):
    return struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5<<4, flags, win, 0, 0) + payload

def tcp(sport, dport, seq, ack, payload, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    return eth(ipv4(6, tcp_seg(sport, dport, seq, ack, payload, flags), src, dst))

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (data, original length) for a truncated frame
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000+i, 0, len(fr), orig) + fr)

def gz(name, dest=None):
    # dest default: the dashes of the base name become underscores
    if dest is None:
        d, _, b = name.rpartition('/')
        dest = (d + '/' if d else '') + b.replace('-', '_') + '.gz'
    with open(name, 'rb') as i, gzip.GzipFile(dest, 'wb', 9, mtime=0) as o:
        shutil.copyfileobj(i, o)

# pcapng
def pad4(b): return b + b'\0' * (-len(b) % 4)
def blk(btype, body):
    body = pad4(body)
    return struct.pack('<II', btype, 12+len(body)) + body + struct.pack('<I', 12+len(body))
def shb(): return blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
def idb(lt=1, snap=0): return blk(1, struct.pack('<HHI', lt, 0, snap))
def epb(data, iface=0, ts=0, orig=None):
    return blk(6, struct.pack('<IIIII', iface, ts>>32, ts & 0xffffffff, len(data), len(data) if orig is None else orig) + pad4(data))
def cb(pen, data, copy=True):
    return blk(0x00000BAD if copy else 0x40000BAD, struct.pack('<I', pen) + data)
def write_pcapng(name, blocks):
    with open(name, 'wb') as f:
        f.write(b''.join(blocks))

def exp_pdu(name, payload):
    n = name.encode()
    tags = struct.pack('!HH', 12, len(n) + (-len(n) % 4)) + n + b'\0' * (-len(n) % 4)
    return tags + struct.pack('!HH', 0, 0) + payload


class TcpStream:
    """A TCP connection with a handshake; send() puts data into frames."""
    def __init__(self, frames, cport, sport, caddr='192.0.2.1', saddr='192.0.2.2', v6=False, handshake=True):
        self.frames = frames
        self.cport, self.sport, self.caddr, self.saddr, self.v6 = cport, sport, caddr, saddr, v6
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self.raw(True, b'', 0x02)
            self.cseq += 1
            self.raw(False, b'', 0x12)
            self.sseq += 1
            self.raw(True, b'', 0x10)

    def raw(self, from_client, data, flags=0x18):
        if from_client:
            sp, dp, seq, ack, s, d = self.cport, self.sport, self.cseq, self.sseq, self.caddr, self.saddr
        else:
            sp, dp, seq, ack, s, d = self.sport, self.cport, self.sseq, self.cseq, self.saddr, self.caddr
        if flags == 0x02:
            ack = 0
        seg = tcp_seg(sp, dp, seq, ack, data, flags)
        if self.v6:
            self.frames.append(eth(ipv6(6, seg, s, d), 0x86dd))
        else:
            self.frames.append(eth(ipv4(6, seg, s, d)))

    def send(self, from_client, data, cuts=()):
        """Send data in one segment or cut at the given offsets."""
        pos = 0
        for end in list(cuts) + [len(data)]:
            chunk = data[pos:end]
            if chunk or not cuts:
                self.raw(from_client, chunk)
                if from_client:
                    self.cseq += len(chunk)
                else:
                    self.sseq += len(chunk)
            pos = end

    def close(self):
        self.raw(True, b'', 0x11)
        self.cseq += 1
        self.raw(False, b'', 0x11)
        self.sseq += 1
        self.raw(True, b'', 0x10)

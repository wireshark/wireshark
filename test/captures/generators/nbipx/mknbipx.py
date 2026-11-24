#!/usr/bin/env python3
# Generates test/captures/nbipx_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- IPX, NBIPX (socket 0x455) and NMPI (sockets 0x551, 0x553) ----
ETH_IPX = 0x8137
PEP, WANBCAST = 4, 0x14
S_NBIPX, S_NMPI, S_MAILSLOT, S_SMB_SRV = 0x0455, 0x0551, 0x0553, 0x0550

def ipx(ptype, dsock, ssock, payload, dnode=1, snode=2, hops=0):
    n = 30 + len(payload)
    h = struct.pack('!HHBB', 0xffff, n, hops, ptype)
    h += struct.pack('!I', 0x1000) + bytes([0, 0, 0, 0, 0, dnode]) + struct.pack('!H', dsock)
    h += struct.pack('!I', 0x2000) + bytes([0, 0, 0, 0, 0, snode]) + struct.pack('!H', ssock)
    return eth(h + payload, snode, dnode, ETH_IPX)

def nbname(s, t=0):
    return s.encode().ljust(15, b' ') + bytes([t])

def routers(nets):
    return b''.join(struct.pack('!I', n) for n in (list(nets) + [0] * 8)[:8])

def smb_negprot():
    d = b'\x02NT LM 0.12\x00'
    return struct.pack('<4sBIBHH8sHHHHH', b'\xffSMB', 0x72, 0, 0x18, 0xc853, 0, b'\0' * 8, 0,
                       0xffff, 0x1234, 0, 1) + b'\x00' + struct.pack('<H', len(d)) + d

def session(ctl, typ, src, dst, seq, total, off, dlen, rseq, brecv, payload=b''):
    return bytes([ctl, typ]) + struct.pack('<HHHHHHHH', src, dst, seq, total, off, dlen, rseq, brecv) + payload

frames = []
def nb(ptype, payload, **kw):
    frames.append(ipx(ptype, S_NBIPX, S_NBIPX, payload, **kw))

# --- name operations in WAN broadcasts: 8 networks, flags byte, type, name
NETS = [0x11, 0, 0x22, 0, 0, 0xdeadbeef, 0, 0x33]
for typ, flags in [(1, 0x00), (3, 0xc0), (5, 0x01), (2, 0x44), (4, 0x82), (3, 0x07), (1, 0xff)]:
    nb(WANBCAST, routers(NETS) + bytes([flags, typ]) + nbname('WORKSTATION1', 0x20))
nb(WANBCAST, routers([]) + bytes([0x40, 3]) + nbname('GROUP', 0x00))
# --- PEP replies of exactly 50 bytes with a name type are taken to have the 8 networks
for typ in (1, 2, 3, 4, 5):
    nb(PEP, routers([0x55, 0x66]) + bytes([0x40, typ]) + nbname('SERVER', 0x20))
# --- 50 bytes with another type at that offset: no networks, so no name operation
nb(PEP, bytes([0x40, 6]) + bytes(48))
# --- PEP name operations without the networks (18 bytes)
for typ in (1, 2, 3, 4, 5):
    nb(PEP, bytes([0x80 | typ, typ]) + nbname('NOROUTES', 0x03))
# --- session packets
smb = smb_negprot()
nb(PEP, session(0x00, 6, 0x0101, 0x0202, 1, len(smb), 0, len(smb), 0, 0, smb))
nb(PEP, session(0xc0, 6, 0x0101, 0x0202, 2, len(smb), 0, len(smb), 1, 0, smb))
nb(PEP, session(0x30, 6, 0x0202, 0x0101, 3, 100, 0, 8, 2, 40, b'notsmb!!'))
nb(PEP, session(0x08, 6, 0x0202, 0x0101, 3, 100, 8, 8, 2, 40, b'notsmb!!'))
nb(PEP, session(0x20, 6, 0x0202, 0x0101, 4, 0, 0, 0, 2, 40))        # no payload
nb(PEP, session(0x80, 7, 0x0101, 0x0202, 5, 0, 0, 0, 3, 0))
nb(PEP, session(0x40, 8, 0x0202, 0x0101, 6, 0, 0, 0, 5, 0))
# --- directed datagrams: receiver and sender names, then a payload
nb(PEP, bytes([0x00, 11]) + nbname('RECEIVER', 0) + nbname('SENDER', 3) + b'datagram payload, 21 b')
# a datagram of exactly 50 bytes whose byte 33 (the sender name type) is a name operation is taken as
# a name operation with 8 networks (the heuristic of the dissector)
nb(PEP, bytes([0x00, 11]) + nbname('RECEIVER', 0) + nbname('SENDER', 3) + b'datagram payload')
nb(PEP, bytes([0x10, 11]) + nbname('RECEIVER', 0) + nbname('SENDER', 3) + smb)
nb(PEP, bytes([0x00, 11]) + nbname('RECEIVER', 0) + nbname('SENDER', 3))   # no payload
# --- types without a decoding
nb(PEP, bytes([0x00, 9]) + bytes(20))
nb(PEP, bytes([0x00, 10]) + bytes(40))
nb(PEP, bytes([0x00, 0x77]) + b'unknown')

# --- NMPI: name management on socket 0x551, mailslot writes on 0x553
def nmpi(op, ntype, mid, name, src, extra=b'', sock=S_NMPI, nets=NETS):
    p = routers(nets) + bytes([op, ntype]) + struct.pack('<H', mid) + nbname(name, 3) + nbname(src, 0) + extra
    frames.append(ipx(WANBCAST, sock, sock, p))
for op, nt in [(0xf1, 1), (0xf2, 2), (0xf3, 3), (0xf4, 1), (0xf5, 2), (0xfc, 3), (0xfd, 1), (0xfe, 2), (0x00, 0x00), (0xaa, 9)]:
    nmpi(op, nt, 0x1000 + op, 'NMPINAME', 'NMPISRC')
nmpi(0xfc, 3, 0x2000, 'MAILSLOT', 'SENDER', smb, S_MAILSLOT)
nmpi(0xfc, 3, 0x2001, 'MAILSLOT', 'SENDER', b'\\MAILSLOT\\BROWSE\x00\x01data', S_MAILSLOT)
nmpi(0xfc, 3, 0x2002, 'MAILSLOT', 'SENDER', b'', S_MAILSLOT)         # nothing after the header
nmpi(0xf3, 1, 0x2003, 'QUERY', 'SENDER', b'', S_MAILSLOT, nets=[])
# one using the higher socket as the name query socket on the other side
frames.append(ipx(PEP, S_SMB_SRV, S_NMPI, routers([1]) + bytes([0xf3, 1, 1, 0]) + nbname('Q', 3) + nbname('R', 0)))

main = frames
frames = []
# --- not decodable
# truncated: name operation shorter than the name, session header cut short
nb(PEP, bytes([0x40, 3]) + b'SHORT')
nb(PEP, bytes([0x00, 6]) + b'\x01\x01\x02')
# 50 bytes long, the byte at 33 is a name type but the packet is IPX type 4: 8 networks
nb(PEP, bytes([0x00]))
# NMPI shorter than its header
frames.append(ipx(WANBCAST, S_NMPI, S_NMPI, routers(NETS) + b'\xf1\x01'))
# directed datagram with a cut name
nb(PEP, bytes([0x00, 11]) + nbname('RECEIVER', 0) + b'SEND')
# the same through a broadcast with only 20 bytes of networks
nb(WANBCAST, routers(NETS)[:20])

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'nbipx-coverage.pcap'), main)
    gz(os.path.join(out, 'nbipx-coverage.pcap'))
    os.rename(os.path.join(out, 'nbipx-coverage.pcap.gz'), os.path.join(out, 'nbipx_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'nbipx-coverage-malformed.pcap'), frames)

#!/usr/bin/env python3
# Generates test/captures/wap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-wap.c (tvb_get_uintvar(), the
WAP variable length integer), reached through connectionless WSP on UDP 9200.
    mkwap.py <outdir>
Writes wap-coverage.pcap and wap-coverage-malformed.pcap
"""
import struct
import socket
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

MAC_C = b'\x02\0\0\0\0\x01'
MAC_S = b'\x02\0\0\0\0\x02'
CLI = '192.0.2.1'
SRV = '192.0.2.2'

def ipv4(proto, payload, src, dst, ident=1, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def eth_ip(ip, from_client):
    d, s = (MAC_S, MAC_C) if from_client else (MAC_C, MAC_S)
    return d + s + b'\x08\x00' + ip

def udp(sp, dp, payload, from_client=True):
    src, dst = (CLI, SRV) if from_client else (SRV, CLI)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    return eth_ip(ipv4(17, u, src, dst), from_client)

class Tcp:
    """One TCP connection, client port cp to server port sp."""
    def __init__(self, cp, sp):
        self.cp, self.sp = cp, sp
        self.cseq, self.sseq = 1000, 5000
    def seg(self, payload, from_client=True, flags=0x18):
        if from_client:
            sport, dport, seq, ack = self.cp, self.sp, self.cseq, self.sseq
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sport, dport, seq, ack = self.sp, self.cp, self.sseq, self.cseq
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        src, dst = (CLI, SRV) if from_client else (SRV, CLI)
        t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return eth_ip(ipv4(6, t, src, dst), from_client)
    def handshake(self):
        return [self.seg(b'', True, 0x02), self.seg(b'', False, 0x12), self.seg(b'', True, 0x10)]
    def close(self):
        return [self.seg(b'', False, 0x11), self.seg(b'', True, 0x11), self.seg(b'', False, 0x10)]

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)

def uintvar(v, pad=0):
    """WAP uintvar: 7 bits per octet, high bit set on all but the last."""
    o = [v & 0x7f]
    v >>= 7
    while v:
        o.insert(0, 0x80 | (v & 0x7f))
        v >>= 7
    o = [0x80] * pad + o
    return bytes(o)

def wsp(pdu, tid=1):
    return udp(9200, 9200, bytes([tid]) + pdu)

def wsp_reply(pdu, tid=1):
    return udp(9200, 9200, bytes([tid]) + pdu, from_client=False)

def xhdrs(n):
    """n bytes of 'text name, text value' headers"""
    h = b''
    while len(h) + 5 <= n:
        h += b'Xh\x00v\x00'
    assert len(h) == n
    return h

def main(outdir):
    f = []
    # Get: URI length in 1, 2 and 3 octets (the last with a 16 KB URI)
    f.append(wsp(b'\x40' + uintvar(11) + b'/index.html'))
    uri = b'/' + b'a' * 199
    f.append(wsp(b'\x40' + uintvar(len(uri)) + uri))
    uri = b'/' + b'b' * 16399
    f.append(wsp(b'\x40' + uintvar(len(uri)) + uri))
    # Get with a redundant leading zero octet (0x80) in the uintvar
    f.append(wsp(b'\x40' + uintvar(5, pad=1) + b'/pad/'))
    # Get with headers: Accept: text/plain, q-value
    f.append(wsp(b'\x40' + uintvar(2) + b'/x' + b'\x80\x83'))
    # Post: uriLength (1 octet) and headersLength (1 and 2 octets)
    ct = b'\x83'   # text/plain
    f.append(wsp(b'\x60' + uintvar(2) + uintvar(1 + 0) + b'/p' + ct + b'body'))
    hd = ct + xhdrs(125)
    f.append(wsp(b'\x60' + uintvar(2) + uintvar(len(hd)) + b'/p' + hd + b'second body'))
    # Put
    f.append(wsp(b'\x61' + uintvar(2) + uintvar(1) + b'/q' + ct + b'put data'))
    # Push and Confirmed Push: headersLength
    f.append(wsp(b'\x06' + uintvar(1) + ct + b'pushed'))
    f.append(wsp(b'\x07' + uintvar(len(hd)) + hd + b'confirmed'))
    # Reply from the server (status 200 = 0x20, headersLength uintvar, content type, body)
    f.append(wsp_reply(b'\x04\x20' + uintvar(1) + ct + b'reply body'))
    f.append(wsp_reply(b'\x04\x20' + uintvar(len(hd)) + hd + b'reply body 2'))
    write_pcap(os.path.join(outdir, 'wap-coverage.pcap'), f)

    m = []
    # uintvar that exceeds the 100 million limit in 4 octets: clamped
    m.append(wsp(b'\x40' + b'\xff\xff\xff\x7f' + b'/x'))
    # a 5 octet uintvar: the value wraps before it is checked
    m.append(wsp(b'\x40' + b'\x8f\xff\xff\xff\x7f' + b'/x'))
    m.append(wsp(b'\x40' + b'\x81\x80\x80\x80\x00' + b'/x'))
    # 4 octets, just under the limit (0x5f5e100 is 100000000)
    m.append(wsp(b'\x40' + uintvar(100000000) + b'/x'))
    m.append(wsp(b'\x40' + uintvar(100000001) + b'/x'))
    # uintvar cut off by the end of the frame (high bit set on the last octet)
    m.append(wsp(b'\x40' + b'\x81'))
    # URI length larger than the frame
    m.append(wsp(b'\x40' + uintvar(5000) + b'/short'))
    # Post/Reply/Push with oversized lengths
    m.append(wsp(b'\x60' + b'\xff\xff\xff\x7f' + b'\x01' + b'/x'))
    m.append(wsp(b'\x60' + b'\x01\xff\xff\xff\x7f' + b'/x'))
    m.append(wsp(b'\x06' + b'\xff\xff\xff\xff\x7f'))
    m.append(wsp_reply(b'\x04\x20' + b'\xff\xff\xff\x7f'))
    write_pcap(os.path.join(outdir, 'wap-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')

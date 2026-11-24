#!/usr/bin/env python3
# Generates test/captures/rmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(a): return bytes(int(x) for x in a.split('.'))

def ip_pkt(proto, l4, src, dst, ident=1, ttl=64):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, ttl, proto, 0, ip4(src), ip4(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + l4

ETH = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'
def eth_wrap(ippkt, etype=0x0800, rev=False):
    mac = ETH[6:] + ETH[:6] if rev else ETH
    return mac + struct.pack('>H', etype) + ippkt

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_wrap(ip_pkt(17, udp, src, dst))

class Tcp:
    '''A TCP connection that tracks sequence numbers.'''
    def __init__(self, a, ap, b, bp):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.seq = {0: 1000, 1: 5000}
    def seg(self, payload, d=0, flags=0x18, advance=True):
        if d == 0: s, sp, t, tp = self.a, self.ap, self.b, self.bp
        else: s, sp, t, tp = self.b, self.bp, self.a, self.ap
        seq, ack = self.seq[d], self.seq[1 - d]
        tcp = struct.pack('>HHIIBBHHH', sp, tp, seq, ack, 0x50, flags, 8192, 0, 0) + payload
        if advance:
            self.seq[d] += len(payload) + (1 if flags & 3 else 0)
        return eth_wrap(ip_pkt(6, tcp, s, t))
    def handshake(self):
        return [self.seg(b'', 0, 0x02), self.seg(b'', 1, 0x12), self.seg(b'', 0, 0x10)]

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def llc_frame(dsap_x, sxsap, rmp, dst=b'\x02\x00\x00\x00\x00\x02', src=b'\x02\x00\x00\x00\x00\x01'):
    '''802.3 frame, LLC UI with the HP extended SAP (0xf8), HPEXT header, RMP data.'''
    hpext = b'\x00\x00\x00' + struct.pack('>HH', dsap_x, sxsap)
    body = b'\xf8\xf8\x03' + hpext + rmp
    return dst + src + struct.pack('>H', len(body)) + body

def machtype(s):
    return s.ljust(20, b'\0')

def fname(s):
    return bytes([len(s)]) + s

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    D, S = 0x608, 0x609
    f = []
    # 1-3: boot request with and without a filename and with trailing data
    f.append(llc_frame(D, S, struct.pack('>BBIHH', 1, 0, 1, 0, 1) + machtype(b'9000/720')))
    f.append(llc_frame(D, S, struct.pack('>BBIHH', 1, 0, 2, 0, 1) + machtype(b'9000/720') + fname(b'SYSHPUX')))
    f.append(llc_frame(D, S, struct.pack('>BBIHH', 1, 0, 3, 0, 1) + machtype(b'9000/735') + fname(b'SYSHPUX') + b'\xde\xad\xbe\xef'))
    # 4-5: boot reply: OK with a file name and trailing data, then errors
    f.append(llc_frame(S, D, struct.pack('>BBIHH', 129, 0, 2, 0x4242, 1) + fname(b'SYSHPUX')))
    f.append(llc_frame(S, D, struct.pack('>BBIHH', 129, 16, 3, 0, 1) + fname(b'') + b'\x01\x02'))
    # 6-7: read request without and with trailing data
    f.append(llc_frame(D, S, struct.pack('>BBIHH', 2, 0, 0, 0x4242, 1024)))
    f.append(llc_frame(D, S, struct.pack('>BBIHH', 2, 0, 1024, 0x4242, 1024) + b'\x00' * 4))
    # 8-10: read replies: data, end of file, bad session id
    f.append(llc_frame(S, D, struct.pack('>BBIH', 130, 0, 0, 0x4242) + bytes(range(64))))
    f.append(llc_frame(S, D, struct.pack('>BBIH', 130, 2, 1024, 0x4242) + b'\x00' * 8))
    f.append(llc_frame(S, D, struct.pack('>BBIH', 130, 25, 0, 0x9999)))
    # 11-12: boot done with and without trailing data (the BOOT_DONE data offset fix)
    f.append(llc_frame(D, S, struct.pack('>BBIH', 3, 0, 0, 0x4242)))
    f.append(llc_frame(D, S, struct.pack('>BBIH', 3, 0, 0, 0x4242) + b'trailing boot done data'))
    # 13: unknown type; 14: abort/busy/timeout/file errors in boot reply
    f.append(llc_frame(D, S, b'\x55' + b'unknown type payload'))
    for code in (3, 4, 5, 17, 18, 19, 27):
        f.append(llc_frame(S, D, struct.pack('>BBIHH', 129, code, 9, 0, 1) + fname(b'X')))
    # the destination XSAP decides: HPEXT with an unregistered XSAP is not RMP
    f.append(llc_frame(0x1234, S, b"\x01\x02\x03"))
    write_pcap(os.path.join(out, 'rmp-coverage.pcap'), f)
    mal = []
    mal.append(llc_frame(D, S, b'\x01\x00\x00\x00'))                              # boot request cut
    mal.append(llc_frame(D, S, struct.pack('>BBIHH', 1, 0, 1, 0, 1) + machtype(b'x') + b'\x20abc'))  # filename past end
    mal.append(llc_frame(S, D, struct.pack('>BBIHH', 129, 0, 1, 0, 1)))           # reply without filename length
    mal.append(llc_frame(S, D, struct.pack('>BBIHH', 129, 0, 1, 0, 1) + b'\x30ab'))
    mal.append(llc_frame(D, S, b'\x02\x00\x00'))                                  # read request cut
    mal.append(llc_frame(S, D, b'\x82\x00\x00\x00'))                              # read reply cut
    mal.append(llc_frame(S, D, struct.pack('>BBIH', 130, 0, 0, 1)))               # read reply without data
    mal.append(llc_frame(D, S, b'\x03\x00\x00'))                                  # boot done cut
    mal.append(llc_frame(D, S, b'\x55'))                                          # unknown type, no payload
    write_pcap(os.path.join(out, 'rmp-coverage-malformed.pcap'), mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()

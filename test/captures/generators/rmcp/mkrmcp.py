#!/usr/bin/env python3
# Generates test/captures/rmcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic RMCP/RSP coverage captures. Usage: mkrmcp.py <outdir> [-v]"""
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.')); d = bytes(int(x) for x in dst.split('.'))
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + udp

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def rmcp(cls, payload=b'', seq=0xff, ver=6):
    return struct.pack('>BBBB', ver, 0, seq, cls) + payload

def asf(typ, tag, data=b'', iana=4542):
    return struct.pack('>IBBBB', iana, typ, tag, 0, len(data)) + data

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    A, B = '192.0.2.10', '192.0.2.20'
    main_f = []
    def add(payload, sport=40000, dport=623, src=A, dst=B):
        main_f.append(udp_frame(payload, sport, dport, src, dst))
    # 1-2: ASF presence ping and pong (normal, class ASF)
    add(rmcp(0x06, asf(0x80, 1)))
    add(rmcp(0x06, asf(0x40, 1, struct.pack('>IIBB6s', 4542, 0, 0x81, 0x00, b'\0' * 6)), seq=0xff),
        623, 40000, B, A)
    # 3: RMCP ACK (class ASF with the ACK bit): no data block expected
    add(rmcp(0x86, seq=1), 623, 40000, B, A)
    # 4: ACK for IPMI class
    add(rmcp(0x87, seq=2))
    # 5: IPMI class (ipmi session wrapper), no auth
    add(rmcp(0x07, b'\x00' + struct.pack('<II', 0, 0) + b'\x09' + bytes(range(9)), seq=0xff))
    # 6: OEM class: no sub-dissector, falls to the data dissector
    add(rmcp(0x08, b'\x01\x02\x03\x04\x05\x06'))
    # 7: OEM class with no data
    add(rmcp(0x08))
    # 8: unknown class: not RMCP (data on UDP)
    add(rmcp(0x09, b'\xaa\xbb'))
    # 9: version other than 6
    add(rmcp(0x06, asf(0x80, 2), ver=0x10))
    # 10-12: RSP on UDP 664: session id, sequence, then an RMCP message
    add(struct.pack('>II', 0, 5) + rmcp(0x06, asf(0x80, 3)), 40001, 664)
    add(struct.pack('>II', 0x12345678, 6) + rmcp(0x07, b'\x00' * 12), 40001, 664)
    add(struct.pack('>II', 0, 7) + rmcp(0x86, seq=3), 664, 40001, B, A)
    # RSP followed by an unknown class and by a truncated RMCP header
    add(struct.pack('>II', 0, 8) + rmcp(0x0b, b'\x00\x01'), 40001, 664)
    write_pcap(os.path.join(out, 'rmcp-coverage.pcap'), main_f)
    # malformed capture
    mal = []
    def madd(payload, sport=40000, dport=623):
        mal.append(udp_frame(payload, sport, dport))
    madd(b'\x06\x00\xff')           # too short for the class byte
    madd(b'')                       # empty
    madd(struct.pack('>II', 0, 1), 40001, 664)   # RSP with nothing after the header
    madd(b'\x00\x01\x02', 40001, 664)            # RSP shorter than its header
    madd(b'\x06\x00\xff\x06\x00\x00\x00\x4e')    # truncated ASF
    write_pcap(os.path.join(out, 'rmcp-coverage-malformed.pcap'), mal)
    if verbose:
        print('main', len(main_f), 'malformed', len(mal))

main()

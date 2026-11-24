#!/usr/bin/env python3
# Generates test/captures/ppcap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the PPCAP coverage captures. Usage: mkppcap.py <outdir> [-v]
# PPCAP is only reached through Exported PDU (the "ppcap" dissector name), so
# every frame is an Exported PDU frame (linktype 252).
import os
import struct
import sys
from pcaplib import exported_pdu, write_pcap

def pad4(b): return b + b'\0' * (-len(b) % 4)
def ptype(name):
    b = name.encode()
    return struct.pack('>HH', 1, len(b)) + pad4(b)
def pdata(d):
    return struct.pack('>HH', 2, len(d)) + pad4(d)
def src_ssnspc(ssn, pc):  return struct.pack('>HHHHB', 3, 4, 0, 1, ssn) + pc.to_bytes(3, 'big')
def src_spc(pc):          return struct.pack('>HHHH', 3, 2, 0, 2) + struct.pack('>H', 0) + struct.pack('>I', pc)[2:]
def src_ip4(a):           return struct.pack('>HHHH', 3, 4, 0, 3) + bytes(int(x) for x in a.split('.'))
def src_ip6(b16):         return struct.pack('>HHHH', 3, 16, 0, 3) + b16
def src_node(s):          return struct.pack('>HHHH', 3, len(s), 0, 4) + pad4(s.encode())
def dst_ssnspc(ssn, pc):  return struct.pack('>HHHHB', 4, 4, 0, 1, ssn) + pc.to_bytes(3, 'big')
def dst_spc(pc):          return struct.pack('>HHHH', 4, 4, 0, 2) + struct.pack('>I', pc)
def dst_ip4(a):           return struct.pack('>HHHH', 4, 4, 0, 3) + bytes(int(x) for x in a.split('.'))
def dst_ip6(b16):         return struct.pack('>HHHH', 4, 16, 0, 3) + b16
def dst_node(s):          return struct.pack('>HHHH', 4, len(s), 0, 4) + pad4(s.encode())
def lport(p):             return struct.pack('>HH', 5, p) + b'\0' * 4
def rport(p):             return struct.pack('>HH', 6, p) + b'\0' * 4
def transport(s):         return struct.pack('>HH', 7, 4) + s.encode()
def sctp_assoc(s):        return struct.pack('>HH', 8, len(s)) + s.encode().ljust(16, b'\0')
def info(s):              return struct.pack('>HH', 256, len(s)) + pad4(s.encode())
def unknown(tag):         return struct.pack('>H', tag)

V6A = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])
V6B = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [2])

SIP = b'OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nFrom: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\nCall-ID: abc@192.0.2.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
def _tl(t, b): return bytes([t, len(b)]) + b
_m = _tl(0x30, _tl(0xa1, _tl(0x80, b'\x01') + _tl(0xa1, _tl(0xa0, _tl(0x80, bytes([192, 0, 2, 1])))) +
                   _tl(0xa2, _tl(0xa0, _tl(0x80, b'\x03\xe9')))))
H248 = _m + b'\0' * (-len(_m) % 4)                        # H.248 message with an error descriptor
GTPV2 = bytes.fromhex('4001000400000100')
SGSAP = bytes.fromhex('01' '0108' '0910103254769810' '0208' '07' + b'abcdefg'.hex() + '200101')   # SGsAP-PAGING-REQUEST
BSSAP = bytes.fromhex('000121')                          # BSSMAP Clear Complete
TCAP_B = bytes.fromhex('6206480400000001')               # TCAP Begin without components
TCAP_E = bytes.fromhex('6406490400000001')               # TCAP End without components
UDT = bytes.fromhex('0900030507') + bytes.fromhex('024208') + bytes.fromhex('024208') + bytes.fromhex('08') + TCAP_B
MTP3 = bytes.fromhex('03' '01000200') + UDT
RANAP = bytes.fromhex('000a000a00000100040001000200')

def frame(*parts): return exported_pdu('ppcap', b''.join(parts))

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    def add(*p): F.append(frame(*p))
    mark('reproducers: Node Id source address of length 0 and a destination Node Id without NUL')
    add(ptype('sip'), src_node('') , dst_node('abc'), pdata(SIP))
    add(ptype('sip'), src_node('nodeA'), dst_node('abc'), pdata(SIP))
    mark('payload types: sip, h248, gtpv2, sgsap, bssap, sccp, mtp3, tcap (with and without a destination SSN) and an unknown one')
    add(ptype('sip'), src_ip4('192.0.2.1'), dst_ip4('192.0.2.2'), lport(5060), rport(5060), transport('udp '), pdata(SIP))
    add(ptype('h248'), src_ip4('192.0.2.1'), dst_ip4('192.0.2.2'), transport('sctp'), sctp_assoc('assoc1'), pdata(H248))
    add(ptype('gtpv2'), src_ip6(V6A), dst_ip6(V6B), lport(2123), rport(2123), pdata(GTPV2))
    add(ptype('sgsap'), src_ip4('192.0.2.3'), dst_ip4('192.0.2.4'), pdata(SGSAP))
    add(ptype('bssap'), src_spc(100), dst_spc(200), pdata(BSSAP))
    add(ptype('sccp'), src_ssnspc(8, 0x010203), dst_ssnspc(8, 0x040506), pdata(UDT))
    add(ptype('mtp3'), src_spc(1), dst_spc(2), pdata(MTP3))
    add(ptype('tcap'), src_ssnspc(6, 0x010203), dst_ssnspc(6, 0x040506), pdata(TCAP_B))
    add(ptype('tcap'), src_ssnspc(0xfe, 0x010203), dst_ssnspc(0xfe, 0x040506), pdata(TCAP_E))
    add(ptype('tcap'), src_spc(3), dst_spc(4), pdata(TCAP_B))
    add(ptype('other'), info('free text'), pdata(b'\x01\x02\x03\x04\x05'))
    mark('addresses: IPv6 source with IPv4 destination, SPC, Node Id, info string, unknown tags')
    add(ptype('sip'), src_ip6(V6A), dst_node('node-b'), info('hello'), pdata(SIP))
    add(ptype('sip'), unknown(0x1234), src_node('abcdefgh'), dst_ip4('192.0.2.9'), pdata(SIP))
    add(ptype('sip'), dst_spc(77), src_spc(88), pdata(SIP))
    add(ptype('sip'), pdata(SIP))
    return F, marks

def malformed_frames():
    F = []
    def add(*p): F.append(frame(*p))
    add(ptype('sip'), src_node('abc')[:-1])                       # Node Id cut short
    add(ptype('tcap'), dst_ssnspc(6, 1), pdata(b'\x62\x05\x48'))  # TCAP via SSN, cut short
    add(ptype('sccp'), pdata(b'\x09\x00\x03'))
    add(ptype('mtp3'), pdata(b'\x03\x01'))
    add(ptype('ranap'), src_spc(3), dst_spc(4), pdata(RANAP))
    add(ptype('ranap'), pdata(b'\x00\x0a\xff'))
    add(ptype('bssap'), pdata(b'\x00\xff\x21'))
    add(ptype('h248'), pdata(b'\xff\xff'))
    add(ptype('gtpv2'), pdata(b'\x48\x01\x00\x20'))
    add(ptype('sgsap'), pdata(b'\x01\xff'))
    add(struct.pack('>HH', 2, 100) + b'abc')                      # payload data longer than the frame
    add(struct.pack('>HH', 1, 40) + b'sip')                       # payload type longer than the frame
    add(struct.pack('>HHHH', 3, 16, 0, 3) + V6A[:6])               # IPv6 source cut short
    add(struct.pack('>HHHH', 4, 16, 0, 3) + V6A[:6])
    add(src_ip4('192.0.2.1')[:-2])
    add(struct.pack('>HHHH', 3, 20, 0, 3) + b'\x01' * 20)         # a length that is not 4 or 16: item error
    add(struct.pack('>HHHH', 4, 0, 0, 4))                         # empty destination Node Id
    add(struct.pack('>HHHH', 3, 0, 0, 4))                         # empty source Node Id (the reproducer)
    add(struct.pack('>HHHH', 3, 0, 0, 3))                         # IPv6 branch with length 0
    add(struct.pack('>HHHH', 4, 0, 0, 3))
    add(struct.pack('>HHHH', 3, 8, 0, 3) + b'\x01' * 8)           # IPv4 branch, wrong length
    add(struct.pack('>HHHH', 3, 4, 0, 9) + b'\x01' * 4)           # unknown address type
    add(struct.pack('>HHHH', 4, 4, 0, 9) + b'\x01' * 4)
    add(struct.pack('>HHHH', 3, 4, 0, 1) + b'\x01\x02')
    add(struct.pack('>HHH', 5, 80, 0))                            # local port cut short
    add(struct.pack('>HH', 8, 40) + b'x')                         # SCTP association cut short
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'ppcap-coverage.pcap'), F, linktype=252)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'ppcap-coverage-malformed.pcap'), M, linktype=252)
    if '-v' in sys.argv:
        for n, s in marks: print(s, n)
        print(len(F), 'frames', len(M), 'malformed frames')

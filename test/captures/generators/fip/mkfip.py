#!/usr/bin/env python3
# Generates test/captures/fip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the FIP dissector (packet-fip.c).
Usage: mkfip.py <output directory>
FIP (FCoE Initialization Protocol) runs over Ethernet with ethertype
0x8914 (registered by default). Writes fip-coverage.pcap and
fip-coverage-malformed.pcap."""
# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, win, 0, 0)
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()

import os
import sys

MAC_ENODE = bytes.fromhex('0e00fc000001')
MAC_FCF = bytes.fromhex('0efc00000002')
ALL_FCF = bytes.fromhex('011018010002')
ALL_ENODE = bytes.fromhex('011018010001')
WWNN = bytes.fromhex('2000000000000001')
WWPN = bytes.fromhex('1000000000000002')
FAB = bytes.fromhex('2000000000000099')

def fip(op, sub, flags, descs, ver=1, rlen=None, res=0):
    body = b''.join(descs)
    n = len(body) // 4 if rlen is None else rlen
    return struct.pack('>HHBBHH', (ver << 12) | res, op, 0, sub, n, flags) + body

def d(t, words, payload=b'', pad=True):
    """Descriptor: type, length in words (computed if None), payload."""
    if words is None:
        words = (2 + len(payload) + 3) // 4
    b = bytes([t, words]) + payload
    return b + b'\0' * (words * 4 - len(b)) if pad else b

def d_pri(p): return d(1, 1, b'\0' + bytes([p]))
def d_mac(m): return d(2, 2, m)
def d_oui(o): return d(3, 2, b'\0\0\0' + o)
def d_name(w): return d(4, 3, b'\0\0' + w)
def d_fab(vfid, oui, w): return d(5, 4, struct.pack('>H', vfid) + b'\0' + oui + w)
def d_size(s): return d(6, 1, struct.pack('>H', s))
def d_vn(mac, fid, wwpn): return d(11, 5, mac + b'\0' + fid + wwpn)
def d_fka(ms): return d(12, 2, b'\0\0' + struct.pack('>I', ms))
def d_vend(vid, data=b''): return d(13, None, b'\0\0' + vid + data)
def d_vlan(v): return d(14, 1, struct.pack('>H', v))

def fc_els(cmd, rctl=0x22):
    """FC header (24 octets, ELS) and an ELS payload."""
    hdr = (bytes([rctl]) + b'\xff\xff\xfe' + b'\0' + b'\0\0\0' + b'\x01' + b'\x29\x00\x00' +
           b'\0' + b'\0' + struct.pack('>HHHI', 0, 0x1234, 0xffff, 0))[:24]
    return hdr + cmd

def flogi(cmd=0x04):
    svc = struct.pack('>HHHHIII', 0x2008, 0x0000, 0x8800, 0x0800, 0x0000, 0xfffff, 0x0a)[:16]
    p = bytes([cmd, 0, 0, 0]) + svc + WWPN + WWNN
    p += b'\x80\x00\x00\x00' + bytes(12)    # class 1/6
    p += b'\x88\x00\x00\x00' + b'\x00\x00\x08\x00' + bytes(8)   # class 2
    p += b'\x88\x00\x00\x00' + b'\x00\x00\x08\x00' + bytes(8)   # class 3
    p += bytes(16) + bytes(16)
    return p

def logo():
    return bytes([0x05, 0, 0, 0, 0, 0xc0, 0, 1]) + WWPN

def acc(cmd=0x02):
    return bytes([cmd, 0, 0, 0]) + flogi()[4:]

def eth_fip(payload, dst=ALL_FCF, src=MAC_ENODE):
    fr = eth(dst, src, 0x8914, payload)
    return fr + b'\0' * max(0, 60 - len(fr))

def fc4f():
    types = bytearray(32)
    types[3] = 0x05                       # bits 0 and 2 of the low byte
    types[7] |= 0x01                      # word 1: GS3 (type 32)
    feat = bytearray(128)
    feat[4:8] = b'\x00\x00\x00\x03'       # FCP: target and initiator
    return d(15, 41, bytes(2) + bytes(types) + bytes(feat))

def main(out):
    F = []
    # Discovery solicitation from an ENode (FPMA and SPMA)
    F.append(eth_fip(fip(1, 1, 0xc000, [d_mac(MAC_ENODE), d_name(WWNN), d_size(2158)])))
    # Discovery advertisement from an FCF: solicited, available, F_Port
    F.append(eth_fip(fip(1, 2, 0x0007, [d_pri(128), d_mac(MAC_FCF), d_name(WWNN), d_fab(1, bytes.fromhex('0efc00'), FAB), d_fka(8000)]), ALL_ENODE, MAC_FCF))
    # unsolicited advertisement, only available
    F.append(eth_fip(fip(1, 2, 0x4004, [d_pri(0), d_mac(MAC_FCF), d_name(WWNN), d_oui(bytes.fromhex('0efc00')), d_fka(90000)]), ALL_ENODE, MAC_FCF))
    # Link service: FLOGI, FDISC, LOGO, ELP requests and replies
    F.append(eth_fip(fip(2, 1, 0x8000, [d(7, None, bytes(2) + fc_els(flogi())), d_mac(MAC_ENODE)]), MAC_FCF, MAC_ENODE))
    F.append(eth_fip(fip(2, 2, 0x8000, [d(7, None, bytes(2) + fc_els(acc(), 0x23)), d_mac(MAC_ENODE)]), MAC_ENODE, MAC_FCF))
    F.append(eth_fip(fip(2, 1, 0x4000, [d(8, None, bytes(2) + fc_els(flogi(0x51)))]), MAC_FCF, MAC_ENODE))
    F.append(eth_fip(fip(2, 1, 0x0000, [d(9, None, bytes(2) + fc_els(logo()))]), MAC_FCF, MAC_ENODE))
    F.append(eth_fip(fip(2, 2, 0x0000, [d(9, None, bytes(2) + fc_els(bytes([2, 0, 0, 0]), 0x23))]), MAC_ENODE, MAC_FCF))
    F.append(eth_fip(fip(2, 1, 0x0000, [d(10, None, bytes(2) + fc_els(bytes([0x10, 0, 0, 0]) + bytes(16)))]), MAC_FCF, MAC_FCF))
    # Control: keep alive with a VN_Port info descriptor, clear virtual link
    F.append(eth_fip(fip(3, 1, 0x0000, [d_mac(MAC_ENODE), d_vn(MAC_FCF, bytes.fromhex('010203'), WWPN)]), MAC_FCF, MAC_ENODE))
    F.append(eth_fip(fip(3, 2, 0x0000, [d_mac(MAC_FCF), d_name(WWNN), d_vn(MAC_ENODE, bytes.fromhex('0a0b0c'), WWPN), d_vn(MAC_ENODE, bytes.fromhex('0a0b0d'), WWNN)]), MAC_ENODE, MAC_FCF))
    # VLAN request and reply
    F.append(eth_fip(fip(4, 1, 0x0000, [d_mac(MAC_ENODE)]), ALL_FCF, MAC_ENODE))
    F.append(eth_fip(fip(4, 2, 0x0000, [d_vlan(1002), d_vlan(4094)]), MAC_ENODE, MAC_FCF))
    # VN2VN subcodes 1-5
    for sc in range(1, 6):
        F.append(eth_fip(fip(5, sc, 0x0008 if sc & 1 else 0x0000, [d_mac(MAC_ENODE), d_name(WWNN), d_vn(MAC_ENODE, bytes.fromhex('0a0b0c'), WWPN)] + ([d_fka(8000), d_size(2112)] if sc == 5 else [])), ALL_FCF, MAC_ENODE))
    # Vendor descriptors with and without vendor specific data, FC-4 features, unknown descriptor
    F.append(eth_fip(fip(1, 1, 0xc000, [d_vend(b'ACME-FIP', b''), d_vend(b'ACME-FIP', b'\xde\xad\xbe\xef\x01\x02\x03\x04'), fc4f(), d(0x20, 2, b'\x01\x02\x03\x04\x05\x06'), d(0xf0, 1, b'\xaa\xbb')])))
    # FC4 with no FCP target/initiator bits
    f4 = fc4f(); f4 = f4[:-128 + 4] + bytes(124)
    F.append(eth_fip(fip(1, 1, 0xc000, [f4])))
    # unknown subcodes and opcodes, and a version other than 1
    for op in (1, 2, 3, 4, 5):
        F.append(eth_fip(fip(op, 0x7f, 0x0000, [d_mac(MAC_ENODE)])))
    F.append(eth_fip(fip(9, 3, 0x0000, [d_mac(MAC_ENODE)], ver=2, res=0x123)))
    # no descriptors at all
    F.append(eth_fip(fip(3, 1, 0x0000, [])))
    # Descriptor length (in words) cut at the descriptor list, trailing bytes
    F.append(eth_fip(fip(1, 1, 0x0000, [d_mac(MAC_ENODE)]) + b'\x01\x01'))
    pcap(os.path.join(out, 'fip-coverage.pcap'), F)

    M = []
    # descriptor list shorter than the descriptor, descriptor longer than the packet
    M.append(eth_fip(fip(1, 1, 0, [d_mac(MAC_ENODE)], rlen=1)))
    M.append(eth_fip(fip(1, 1, 0, [d(2, 30, MAC_ENODE, pad=False)], rlen=30)))
    # zero length descriptor (expert info)
    M.append(eth_fip(fip(1, 1, 0, [d_pri(1), bytes([0x02, 0x00, 1, 2, 3, 4]), d_pri(2)], rlen=3)))
    # descriptors too short for their type
    for t in (1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15):
        M.append(eth_fip(fip(1, 1, 0, [d(t, 1, b'')]) )[:14 + 10 + 4])
    # FLOGI descriptor with a truncated FC frame
    M.append(eth_fip(fip(2, 1, 0, [d(7, 3, bytes(2) + b'\x22\xff\xff\xfe\0\0')]))[:14 + 10 + 12])
    # shorter than the 10 octet header
    M.append(eth(ALL_FCF, MAC_ENODE, 0x8914, b'\x10\x00\x00\x01\x00\x01'))
    M.append(eth(ALL_FCF, MAC_ENODE, 0x8914, b''))
    pcap(os.path.join(out, 'fip-coverage-malformed.pcap'), M)

if __name__ == '__main__':
    main(sys.argv[1])

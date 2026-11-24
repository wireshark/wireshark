#!/usr/bin/env python3
# Generates test/captures/ldp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the LDP dissector
(packet-ldp.c).

LDP runs over UDP port 646 (Hello) and TCP port 646 (sessions); both
ports are registered, so no Decode As is needed. Every packet is built
from scratch with struct; no captured traffic is used.

Usage: mkldp.py <output directory>

Writes:
  ldp-coverage.pcap            Hellos, one TCP session with every message
                               type and the TLVs the dissector decodes, the
                               FEC element types, pseudowire interface
                               parameters, a PDU split over two TCP
                               segments, and the reproducers of the
                               fixes on the branch
  ldp-coverage-malformed.pcap  length errors in the TLVs, FEC elements and
                               messages
"""

import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, l4, src, dst, ttl=64):
    sa = bytes(map(int, src.split('.')))
    da = bytes(map(int, dst.split('.')))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0, sa, da)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4, sa, da


def eth(p, src_mac=b'\x02\x00\x00\x00\x00\x01', dst_mac=b'\x02\x00\x00\x00\x00\x02'):
    return dst_mac + src_mac + b'\x08\x00' + p


def udp_frame(payload, src='10.0.0.1', dst='224.0.0.2', sport=646, dport=646):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip, _, _ = ipv4(17, udp, src, dst, 1 if dst == '224.0.0.2' else 64)
    mac = b'\x01\x00\x5e\x00\x00\x02' if dst == '224.0.0.2' else b'\x02\x00\x00\x00\x00\x02'
    return eth(ip, dst_mac=mac)


class Tcp:
    """One TCP connection, client 10.0.0.1:50000 -> server 10.0.0.2:646."""

    def __init__(self, c='10.0.0.1', s='10.0.0.2', cport=50000, sport=646):
        self.c, self.s, self.cport, self.sport = c, s, cport, sport
        self.cseq = 1000
        self.sseq = 9000

    def seg(self, payload, flags, from_client):
        if from_client:
            src, dst, sp, dp, seq, ack = self.c, self.s, self.cport, self.sport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = self.s, self.c, self.sport, self.cport, self.sseq, self.cseq
        if flags == 0x02:
            ack = 0
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
        hdr = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        l4 = hdr + payload
        ip, sa, da = ipv4(6, l4, src, dst)
        # TCP checksum over the pseudo header
        ph = sa + da + struct.pack('!BBH', 0, 6, len(l4))
        ck = csum(ph + l4)
        l4 = l4[:16] + struct.pack('!H', ck) + l4[18:]
        ip, _, _ = ipv4(6, l4, src, dst)
        if from_client:
            self.cseq += len(payload) + (1 if flags & 0x02 else 0)
            return eth(ip)
        self.sseq += len(payload) + (1 if flags & 0x02 else 0)
        return eth(ip, b'\x02\x00\x00\x00\x00\x02', b'\x02\x00\x00\x00\x00\x01')

    def handshake(self):
        return [self.seg(b'', 0x02, True), self.seg(b'', 0x12, False),
                self.seg(b'', 0x10, True)]

    def data(self, payload, from_client=True):
        return self.seg(payload, 0x18, from_client)


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ---- LDP building blocks -------------------------------------------------

def ip4(a):
    return bytes(map(int, a.split('.')))


def tlv(t, v=b'', uf=0, length=None):
    """TLV with type t (U and F bits in uf), value v."""
    return struct.pack('!HH', (uf << 14) | t, len(v) if length is None else length) + v


def msg(t, tlvs=b'', mid=1, ubit=0, extra=b'', length=None):
    body = struct.pack('!I', mid) + extra + tlvs
    return struct.pack('!HH', (ubit << 15) | t, len(body) if length is None else length) + body


def pdu(msgs, lsr='10.0.0.1', ls=0, version=1, length=None):
    body = ip4(lsr) + struct.pack('!H', ls) + msgs
    return struct.pack('!HH', version, len(body) if length is None else length) + body


# FEC elements
def fec_wild():
    return b'\x01'


def fec_crlsp():
    return b'\x04'


def fec_prefix(fam, plen, prefix):
    return struct.pack('!BHB', 2, fam, plen) + prefix


def fec_host(fam, hlen, addr):
    return struct.pack('!BHB', 3, fam, hlen) + addr


def fec_p2mp(t, root, opaque, fam=1, alen=4):
    return struct.pack('!BHB', t, fam, alen) + root + struct.pack('!H', len(opaque)) + opaque


# Pseudowire interface parameters
def ip_param(t, v=b''):
    return struct.pack('!BB', t, 2 + len(v)) + v


def all_ifparams():
    return [
        ip_param(0x01, struct.pack('!H', 1500)),                  # MTU
        ip_param(0x02, struct.pack('!H', 28)),                    # max ATM cells
        ip_param(0x03, b'port-1'),                                # description
        ip_param(0x04, struct.pack('!H', 192)),                   # CEP bytes
        ip_param(0x05, struct.pack('!H', 0x8f45)),                # CEP options
        ip_param(0x06, struct.pack('!H', 100)),                   # VLAN id
        ip_param(0x07, struct.pack('!I', 1544000)),               # TDM bps
        ip_param(0x08, struct.pack('!H', 2)),                     # FR DLCI length
        ip_param(0x09, b'\x00\x00'),                              # fragmentation
        ip_param(0x0a, struct.pack('!H', 4)),                     # FCS retention
        ip_param(0x0b, struct.pack('!H', 0xe000)),                # TDM options short
        ip_param(0x0b, struct.pack('!HBBH', 0xe000, 0x5a, 0x7f, 8000)),  # to 8 bytes
        ip_param(0x0b, struct.pack('!HBBHI', 0xe000, 0x5a, 0x7f, 8000, 0xdeadbeef)),  # 12 bytes
        ip_param(0x0c, b'\x07\x1f'),                              # VCCV
        ip_param(0x17, b'\xc0\x00'),                              # flow label
        ip_param(0x0d, b'\x01\x02'),                              # unknown
    ]


def pw_fec(t, cbit, pwtype, groupid, pwid, params):
    info = struct.pack('!I', pwid) + b''.join(params)
    return (struct.pack('!BHB', t, (cbit << 15) | pwtype, len(info)) +
            struct.pack('!I', groupid) + info)


def agi(t, v):
    return struct.pack('!BB', t, len(v)) + v


AAI2 = struct.pack('!III', 0x00000001, 0x0a000001, 0x00000005)   # type 2 AII body


def gen_fec(t, cbit, pwtype, items):
    info = b''.join(items)
    return struct.pack('!BHB', t, (cbit << 15) | pwtype, len(info)) + info


def build_main():
    frames = []
    # --- UDP Hellos --------------------------------------------------------
    def hello(flags, extra=b'', hold=15, mid=1, lsr='10.0.0.1', dst='224.0.0.2'):
        return udp_frame(pdu(msg(0x0100, tlv(0x0400, struct.pack('!HH', hold, flags)) + extra, mid), lsr=lsr), dst=dst)
    # 1. Link hello, GTSM supported (chat)
    frames.append(hello(0x2000, tlv(0x0401, ip4('10.0.0.1')) + tlv(0x0402, struct.pack('!I', 77))))
    # 2. Link hello, GTSM not supported (chat), IPv6 transport address
    frames.append(hello(0x0000, tlv(0x0403, bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1]))))
    # 3. Targeted hello, request bit, no GTSM (warn)
    frames.append(hello(0xc000, b'', hold=45, mid=2, dst='10.0.0.2'))
    # 4. Targeted + GTSM (warn)
    frames.append(hello(0xa000, b'', hold=0xffff, mid=3, dst='10.0.0.2'))
    # 5. Hello with MAC TLV (two addresses) and an unknown TLV with U bit
    frames.append(hello(0x0000, tlv(0x0404, b'\x02\x00\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x0b') +
                        tlv(0x0fff, b'\x01\x02\x03', uf=2)))
    # --- TCP session -------------------------------------------------------
    t = Tcp()
    frames += t.handshake()
    cs = tlv(0x0500, struct.pack('!HHBBHIH', 1, 180, 0x80, 0, 4096, 0x0a000002, 0))
    # 9. Initialization: common session params (A bit), ATM and FR params,
    #    FT session
    atm = tlv(0x0501, bytes([0x40 | 0x08 | 0x01, 0, 0, 0]) +
              struct.pack('!HHHH', 1, 32, 2, 1000) + struct.pack('!HHHH', 5, 64, 6, 2000))
    # numlr is bits 2..5 of the first byte: 2 ranges = 0x08
    atm = tlv(0x0501, bytes([0xc0 | 0x08 | 0x01, 0, 0, 0]) +
              struct.pack('!HHHH', 1, 32, 2, 1000) + struct.pack('!HHHH', 5, 64, 6, 2000))
    fr = tlv(0x0502, bytes([0x80 | 0x04, 0, 0, 0]) +
             bytes([0x01, 0x00, 0x10, 0x00]) + bytes([0x00, 0x00, 0x40, 0x00]))
    ft = tlv(0x0503, struct.pack('!HHII', 0x8000 | 0x0001 | 0x0040 | 0x0020 | 0x0010 | 0x0008, 0, 30000, 60000))
    frames.append(t.data(pdu(msg(0x0200, cs + atm + fr + ft))))
    # 10. Initialization back (server), Init with D bit, path vector limit
    cs2 = tlv(0x0500, struct.pack('!HHBBHIH', 1, 90, 0x40, 5, 1500, 0x0a000001, 0))
    frames.append(t.data(pdu(msg(0x0200, cs2 + tlv(0x0504, struct.pack('!I', 5)) + tlv(0x0505), mid=2,),
                             lsr='10.0.0.2'), False))
    # 11. Keepalive from both
    frames.append(t.data(pdu(msg(0x0201, b'', mid=3))))
    frames.append(t.data(pdu(msg(0x0201, b'', mid=3), lsr='10.0.0.2'), False))
    # 13. Capability: dynamic capability, entropy label, upstream label
    #     assignment (S bit), HSMP, P2MP/MP2MP/MBB, typed wildcard, ...
    frames.append(t.data(pdu(msg(0x0202,
        tlv(0x0506, b'\x80\x00') + tlv(0x0206, uf=1) + tlv(0x0507, b'\x80') +
        tlv(0x0902, b'\x00') + tlv(0x0508, b'\x80') + tlv(0x0509, b'\x80') +
        tlv(0x050a, b'\x80') + tlv(0x050b, b'\x80\x00\x01') +
        tlv(0x050c, struct.pack('!HH', 0, 0)) + tlv(0x050d, b'\x80') +
        tlv(0x050e) + tlv(0x050f, b'\x00') + tlv(0x0510, b'\x00') +
        tlv(0x0603, b'\x80') + tlv(0x0700, b'\x00') + tlv(0x0701, b'\x00') +
        tlv(0x0703, b'\x00'), mid=4))))
    # 14. Address message: IPv4 (two addresses), IPv6, unknown family
    frames.append(t.data(pdu(msg(0x0300,
        tlv(0x0101, struct.pack('!H', 1) + ip4('10.0.0.1') + ip4('10.1.0.1')),
        mid=5) + msg(0x0300,
        tlv(0x0101, struct.pack('!H', 2) + bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])),
        mid=6) + msg(0x0300,
        tlv(0x0101, struct.pack('!H', 9) + b'\x01\x02\x03\x04'), mid=60) + msg(0x0301,
        tlv(0x0101, struct.pack('!H', 1) + ip4('10.2.0.1')), mid=7))))
    # 15. Label mapping with a Prefix FEC and generic label, hop count,
    #     path vector, label request message id
    fec1 = tlv(0x0100, fec_wild() + fec_crlsp() +
               fec_prefix(1, 24, ip4('192.0.2.0')[:3]) +
               fec_prefix(1, 21, ip4('192.0.8.0')[:3]) +
               fec_prefix(2, 64, bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1])) +
               fec_prefix(1, 0, b'') +
               fec_host(1, 4, ip4('192.0.2.9')) +
               fec_host(2, 16, bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [2])) +
               fec_prefix(5, 8, b'\x01') +     # unknown family, skipped
               fec_host(7, 4, b'\x01\x02\x03\x04')) + tlv(0x0100, b'\x99\x01\x02\x03')
    frames.append(t.data(pdu(msg(0x0400, fec1 + tlv(0x0200, struct.pack('!I', 0x00012345)) +
        tlv(0x0103, b'\x03') + tlv(0x0104, ip4('10.0.0.1') + ip4('10.0.0.2')) +
        tlv(0x0600, struct.pack('!I', 99)) + tlv(0x0203, struct.pack('!I', 12)) +
        tlv(0x0001, struct.pack('!I', 12)), mid=8), lsr='10.0.0.2'), False))
    # 16. ATM and Frame Relay labels, upstream assigned label (and request)
    frames.append(t.data(pdu(msg(0x0400, tlv(0x0100, fec_wild()) +
        tlv(0x0201, struct.pack('!HH', 0x2000 | 5, 77)) +
        tlv(0x0202, struct.pack('!I', (2 << 23) | 0x1234)), mid=9) +
        msg(0x0401, tlv(0x0100, fec_prefix(1, 32, ip4('192.0.2.1'))) +
            tlv(0x0205, struct.pack('!I', 0)), mid=10) +
        msg(0x0400, tlv(0x0100, fec_wild()) + tlv(0x0204, struct.pack('!II', 0, 4001)),
            mid=11))))
    # 17. Label request, withdraw, release, abort with explicit-route TLVs
    er = (tlv(0x0801, b'\x80\x00\x00\x18' + ip4('10.0.0.0')[:4]) )
    er = tlv(0x0801, bytes([0x80, 0, 0, 24]) + ip4('10.9.0.0'))
    er6 = tlv(0x0802, bytes([0x00, 0, 0, 64]) + bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 12))
    eras = tlv(0x0803, struct.pack('!HH', 0x8000, 65001))
    erlsp = tlv(0x0804, struct.pack('!HHI', 0, 7, 0x0a000001))
    erhop = tlv(0x0829, er + er6 + eras + erlsp)
    frames.append(t.data(pdu(msg(0x0401, tlv(0x0100, fec_prefix(1, 32, ip4('192.0.2.1'))) +
        erhop + tlv(0x0800, b'\x01\x02\x03\x04') +
        tlv(0x0810, struct.pack('!BBBB', 0xfc, 3, 0, 0) +
            struct.pack('!fffff', 1e6, 1500.0, 5e5, 1000.0, 2000.0)) +
        tlv(0x0810, struct.pack('!BBBB', 0x00, 0, 0, 0) +
            struct.pack('!fffff', 0.0, 0.0, 0.0, 0.0, 0.0)) +
        tlv(0x0820, b'\x03\x04\x00\x00') +
        tlv(0x0821, struct.pack('!HHI', 1, 2, 0x0a000001)) +
        tlv(0x0822, struct.pack('!I', 0xff)) + tlv(0x0823, struct.pack('!I', 0x80000000)) +
        tlv(0x0901, b'\x00\x00\x00\x02' + struct.pack('!BBH', 0, 3, 0x0a00) +
            struct.pack('!BBH', 0, 5, 0x0001)) +
        tlv(0x0901, b'\x80\x00\x00\x00' + b'\x00\x00' + struct.pack('!H', 0x0402)),
        mid=12), lsr='10.0.0.2'), False))
    frames.append(t.data(pdu(
        msg(0x0402, tlv(0x0100, fec_wild()), mid=13) +
        msg(0x0403, tlv(0x0100, fec_wild()) + tlv(0x0200, struct.pack('!I', 40)), mid=14) +
        msg(0x0404, tlv(0x0100, fec_wild()) + tlv(0x0600, struct.pack('!I', 10)), mid=15))))
    # 19. Notification with Status, extended status and returned PDU/messages
    def status(code, e=0, f=0, mid=0, mtype=0):
        return tlv(0x0300, struct.pack('!IIH', (e << 31) | (f << 30) | code, mid, mtype))
    frames.append(t.data(pdu(
        msg(0x0001, status(0), mid=16) +
        msg(0x0001, status(0x0a, 1, 1, 8, 0x0400) + tlv(0x0301, struct.pack('!I', 0x1234)) +
            tlv(0x0302, struct.pack('!HHIH', 1, 20, 0x0a000001, 0) + b'\x00\x01\x02') +
            tlv(0x0303, struct.pack('!HHI', 0x0400, 8, 44) + b'\xaa\xbb\xcc\xdd') +
            tlv(0x0303, struct.pack('!HHI', 0x3e01, 8, 45)) +
            tlv(0x0303, struct.pack('!HHI', 0x3f01, 8, 46) + b'\x01') +
            tlv(0x0303, struct.pack('!HH', 0x8123, 4)) +
            tlv(0x0303, struct.pack('!HHI', 0x0001, 8, 47)) +
            tlv(0x0304, b'\x01\x00\x00\x00'), mid=17) +
        msg(0x0001, status(0x3f), mid=18) +
        msg(0x0001, status(0x7fffffff, 0, 0, 0xffffffff, 0xffff), mid=19), lsr='10.0.0.2'), False))
    # 20. Call setup/release and RG messages (generic TLVs), unknown message
    frames.append(t.data(pdu(
        msg(0x0500, tlv(0x0831, b'\x00' * 8) + tlv(0x0832, b'\x00' * 4), mid=20) +
        msg(0x0501, tlv(0x0833, b'\x00\x00'), mid=21) +
        msg(0x0700, tlv(0x0700, b'\x00\x00\x00\x01'), mid=22) +
        msg(0x0701, b'', mid=23) + msg(0x0702, b'', mid=24) + msg(0x0703, tlv(0x0700, b'\x00'), mid=25) +
        msg(0x0777, tlv(0x0f00, b'\x00'), mid=26, ubit=1))))
    # 21. Vendor-private and experimental messages / TLVs
    frames.append(t.data(pdu(
        msg(0x3e05, tlv(0x3e05, struct.pack('!I', 0x0000e5e5) + b'\x01\x02\x03'), mid=27,
            extra=struct.pack('!I', 0x00001234)) +
        msg(0x3f05, tlv(0x3f05, struct.pack('!I', 7)) + tlv(0x3e00, struct.pack('!I', 9)) +
            tlv(0x3f00, struct.pack('!I', 8) + b'\x05'), mid=28,
            extra=struct.pack('!I', 0x00005678)))))
    # 22. Pseudowire FEC elements and TLVs
    prms = all_ifparams()
    frames.append(t.data(pdu(msg(0x0400,
        tlv(0x0100, pw_fec(0x80, 1, 5, 0x11, 0x2222, prms)) +
        tlv(0x096a, struct.pack('!I', 0x0000001f)) +
        tlv(0x096b, b''.join(prms)) +
        tlv(0x096c, struct.pack('!I', 3)) +
        tlv(0x0200, struct.pack('!I', 600)) +
        tlv(0x0100, pw_fec(0x80, 0, 4, 1, 100, [ip_param(1, struct.pack('!H', 1500))])) +
        tlv(0x0100, pw_fec(0x80, 0, 7, 1, 100, [])) +
        tlv(0x0100, struct.pack('!BHB', 0x80, 5, 4) + struct.pack('!I', 1) + struct.pack('!I', 5)),
        mid=29), lsr='10.0.0.2'), False))
    # 23. Generalized PWid FEC (0x81), typed wildcard (0x05), P2MP PW upstream (0x82)
    gen81 = gen_fec(0x81, 1, 5, [agi(1, b'\x00\x00\x00\x01'), agi(2, b'\x01\x02\x03\x04'), agi(0x15, b'\x07\x08')])
    gen81b = gen_fec(0x81, 0, 4, [agi(1, b''), agi(2, b''), agi(0x15, b'')])
    typed = (struct.pack('!BHB', 0x05, 5, 4 + 4 + 4) + struct.pack('!I', 9) +
             struct.pack('!I', 4) + ip_param(1, struct.pack('!H', 1400)) + ip_param(6, struct.pack('!H', 7)))
    p2mp_up = gen_fec(0x82, 1, 5, [agi(1, b'\xaa\xbb'), agi(2, struct.pack('!III', 1, 0x0a000001, 5)),
                                   agi(2, struct.pack('!III', 2, 0x0a000002, 6))])
    p2mp_up2 = gen_fec(0x82, 0, 5, [agi(1, b'\xaa\xbb'), agi(3, b'\x01\x02\x03'), agi(4, b'\x04\x05')])
    frames.append(t.data(pdu(msg(0x0400,
        tlv(0x0100, gen81) + tlv(0x0100, gen81b) + tlv(0x0100, typed) +
        tlv(0x0100, p2mp_up) + tlv(0x0100, p2mp_up2) + tlv(0x0200, struct.pack('!I', 601)),
        mid=30))))
    # 24. P2MP / MP2MP / HSMP FEC elements and the multicast TLVs
    opq = b'\x01\x00\x04\x00\x00\x00\x2a'
    frames.append(t.data(pdu(msg(0x0400,
        tlv(0x0100, fec_p2mp(0x06, ip4('10.0.0.9'), opq) + fec_p2mp(0x07, ip4('10.0.0.9'), b'') +
            fec_p2mp(0x08, ip4('10.0.0.9'), opq) + fec_p2mp(0x09, ip4('10.0.0.8'), opq) +
            fec_p2mp(0x0a, ip4('10.0.0.8'), b'')) +
        tlv(0x0200, struct.pack('!I', 700)) +
        tlv(0x001d, b'\x01\x00\x01\x04' + ip4('10.0.0.9') + struct.pack('!H', 3) + b'\x01\x02\x03') +
        tlv(0x001c, struct.pack('!IHHI', 9, 0, 7, 0x0a000001)) +
        tlv(0x001e, ip4('10.0.0.5') + ip4('232.1.1.1')),
        mid=31), lsr='10.0.0.2'), False))
    # 25. IPv4 Interface ID with each sub TLV (the fixes: IP multicast tunnel
    #     and MPLS context label get the TLV length, not the PDU remainder)
    iid_hdr = ip4('10.0.0.1') + struct.pack('!I', 5)
    sub_mc = tlv(0x001e, ip4('10.0.0.5') + ip4('232.1.1.1'))
    sub_rsvp = tlv(0x001c, struct.pack('!IHHI', 9, 0, 7, 0x0a000001))
    sub_ldp = tlv(0x001d, b'\x01\x00\x01\x04' + ip4('10.0.0.9') + struct.pack('!H', 7) + b'\x01\x02\x03\x04\x05\x06\x07')
    sub_ctx = tlv(0x001f, ip4('10.0.0.6') + sub_mc)
    frames.append(t.data(pdu(msg(0x0400, tlv(0x0100, fec_wild()) +
        tlv(0x082d, iid_hdr + sub_mc) + tlv(0x082d, iid_hdr + sub_rsvp) +
        tlv(0x082d, iid_hdr + sub_ldp) + tlv(0x082d, iid_hdr + sub_ctx) +
        tlv(0x001f, ip4('10.0.0.7') + sub_mc) + tlv(0x001e, ip4('10.0.0.8') + ip4('232.2.2.2')) +
        tlv(0x0200, struct.pack('!I', 701)), mid=32))))
    # 26. Label mapping with a FEC TLV holding only a 1 byte Wildcard element
    #     (reproducer of the P2MP opaque length read before the FEC type)
    frames.append(t.data(pdu(msg(0x0402, tlv(0x0100, fec_wild()), mid=33), lsr='10.0.0.2'), False))
    # 27. Reproducer: MPLS context label inside a message that is followed by
    #     more TLVs
    # 28. TLV with the unknown/forward bits, unknown TLV type, vendor TLV
    frames.append(t.data(pdu(msg(0x0400, tlv(0x0100, fec_wild(), uf=3) +
        tlv(0x0200, struct.pack('!I', 5), uf=1) + tlv(0x0f01, b'\x01\x02', uf=3), mid=34))))
    # 29. A PDU split over two TCP segments (reassembly)
    big = pdu(msg(0x0300, tlv(0x0101, struct.pack('!H', 1) +
                              b''.join(ip4('10.3.%d.1' % i) for i in range(30))), mid=35))
    frames.append(t.data(big[:50], False))
    frames.append(t.data(big[50:], False))
    # 31. Two PDUs in one segment, the second one split from its header
    p1 = pdu(msg(0x0201, b'', mid=36))
    p2 = pdu(msg(0x0201, b'', mid=37))
    frames.append(t.data(p1 + p2[:2]))
    frames.append(t.data(p2[2:]))
    # 33. Header split: PDU header cut in the middle of the length
    p3 = pdu(msg(0x0201, b'', mid=38))
    frames.append(t.data(p3[:3]))
    frames.append(t.data(p3[3:]))
    # 35. A PDU with a PDU length smaller than the frame (trailing bytes
    #     are another PDU)
    frames.append(t.data(pdu(msg(0x0201, b'', mid=39)) + pdu(msg(0x0201, b'', mid=40))))
    # 36. A UDP packet whose PDU length is smaller than the payload: the
    #     bytes after the PDU are ignored
    frames.append(udp_frame(pdu(msg(0x0201, b'', mid=42)) + b'\x00' * 6,
                            src='10.0.0.1', dst='10.0.0.2'))
    # 37. Hello over UDP unicast (targeted hello), both directions
    frames.append(udp_frame(pdu(msg(0x0100, tlv(0x0400, struct.pack('!HH', 45, 0xc000)), mid=41)),
                            src='10.0.0.1', dst='10.0.0.2'))
    return frames


def build_malformed():
    frames = []
    t = Tcp()
    frames += t.handshake()
    d = lambda p: frames.append(t.data(p))
    # TLV length errors
    def one(tl, t_msg=0x0400):
        d(pdu(msg(t_msg, tl)))
    one(tlv(0x0103, b'\x01\x02'))                          # hop count
    one(tlv(0x0200, b'\x00\x01'))                          # generic label
    one(tlv(0x0203, b'\x00'))                              # FT protection
    one(tlv(0x0206, b'\x00'))                              # entropy label capa
    one(tlv(0x0301, b'\x00'))                              # extended status
    one(tlv(0x0401, b'\x00'))                              # IPv4 transport
    one(tlv(0x0402, b'\x00'))                              # config seq no
    one(tlv(0x0403, b'\x00'))                              # IPv6 transport
    one(tlv(0x0504, b'\x00'))                              # FT ack
    one(tlv(0x0505, b'\x00'))                              # FT cork
    one(tlv(0x0600, b'\x00'))                              # label request msg id
    one(tlv(0x3e01, b'\x00'))                              # vendor private
    one(tlv(0x3f01, b'\x00'))                              # experimental
    one(tlv(0x0101, b'\x00'))                              # address list too short
    one(tlv(0x0101, struct.pack('!H', 9) + b'\x01\x02'))   # unknown family
    one(tlv(0x0101, struct.pack('!H', 1) + ip4('10.0.0.1') + b'\x01'))  # extra data
    one(tlv(0x0104, ip4('10.0.0.1') + b'\x01'))            # path vector extra
    one(tlv(0x0201, b'\x00\x01'))                          # ATM label
    one(tlv(0x0202, b'\x00\x01'))                          # FR label
    one(tlv(0x0300, b'\x00\x01'))                          # status
    one(tlv(0x0302, b'\x00\x01'))                          # returned PDU
    one(tlv(0x0303, b'\x00\x01'))                          # returned message
    one(tlv(0x0404, b'\x00' * 7))                          # MAC extra
    one(tlv(0x0500, b'\x00' * 4))                          # common session
    one(tlv(0x0501, b'\x00'))                              # ATM params short
    one(tlv(0x0501, bytes([0x0c, 0, 0, 0]) + b'\x00' * 8)) # ATM params, 3 ranges but 1
    one(tlv(0x0502, b'\x00'))                              # FR params short
    one(tlv(0x0502, bytes([0x0c, 0, 0, 0]) + b'\x00' * 8))
    one(tlv(0x0503, b'\x00'))                              # FT session
    one(tlv(0x0821, b'\x00'))                              # LSPID
    one(tlv(0x0801, b'\x00'))
    one(tlv(0x0802, b'\x00'))
    one(tlv(0x0803, b'\x00'))
    one(tlv(0x0804, b'\x00'))
    one(tlv(0x0810, b'\x00'))
    one(tlv(0x0820, b'\x00'))
    one(tlv(0x0822, b'\x00'))
    one(tlv(0x0823, b'\x00'))
    one(tlv(0x0901, b'\x00'))
    one(tlv(0x0902, b'\x00\x00'))                          # HSMP capability
    one(tlv(0x0507, b'\x00\x00'))
    one(tlv(0x0205, b'\x00'))
    one(tlv(0x0204, b'\x00'))
    one(tlv(0x096a, b'\x00'))                              # PW status
    one(tlv(0x082d, b'\x00' * 12))                         # IPv4 interface ID, bad length
    one(tlv(0x001f, b'\x00\x01'))                          # MPLS context label < 4 (fix)
    one(tlv(0x0829, b'\x00\x01'))                          # ER hop with truncated TLV
    # interface parameter errors in the PW interface parameter TLV
    one(tlv(0x096b, ip_param(1, b'\x05\xdc') + b'\x02\x01'))     # length 1
    one(tlv(0x096b, b'\x01\xf0\x00\x00'))                         # length past the TLV
    # FEC errors
    one(tlv(0x0100, b'\x02\x00'))                           # prefix FEC too short
    one(tlv(0x0100, b'\x02\x00\x01\x20\x0a'))               # prefix too short for the length
    one(tlv(0x0100, fec_prefix(1, 40, ip4('10.0.0.1')[:4]) + b'\x01'))  # prefix len > addr
    one(tlv(0x0100, fec_prefix(5, 8, b'\x01')))             # unknown family
    one(tlv(0x0100, b'\x03\x00'))                           # host FEC short
    one(tlv(0x0100, fec_host(1, 8, ip4('10.0.0.1') + b'\x01\x02\x03\x04')))  # host len != 4
    one(tlv(0x0100, fec_host(7, 4, ip4('10.0.0.1'))))       # unknown family
    one(tlv(0x0100, fec_host(1, 4, ip4('10.0.0.1')[:2])))   # host short
    one(tlv(0x0100, b'\x05\x00\x01\x04'))                   # typed wildcard short
    one(tlv(0x0100, struct.pack('!BHB', 5, 5, 2) + b'\x00' * 4))  # vc info length < 4
    one(tlv(0x0100, struct.pack('!BHB', 5, 5, 8) + struct.pack('!II', 1, 2) + b'\x01\x01'))
    one(tlv(0x0100, struct.pack('!BHB', 5, 5, 20) + struct.pack('!II', 1, 2) + b'\x01\xf0\x01'))
    one(tlv(0x0100, b'\x82\x00'))                           # P2MP PW upstream short
    one(tlv(0x0100, struct.pack('!BHB', 0x82, 5, 0) + b'\x00' * 4))
    one(tlv(0x0100, struct.pack('!BHB', 0x82, 5, 4) + agi(1, b'')))   # no SAII
    one(tlv(0x0100, struct.pack('!BHB', 0x82, 5, 6) + agi(1, b'') + agi(1, b'')))  # no TAII
    one(tlv(0x0100, gen_fec(0x82, 0, 5, [agi(1, b''), agi(2, b'\x01\x02'), agi(2, b'\x01')])))
    one(tlv(0x0100, gen_fec(0x82, 0, 5, [agi(1, b''), agi(2, b'\x01\x02'), agi(2, b'\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e')])))
    one(tlv(0x0100, b'\x06\x00\x01'))                       # P2MP short
    one(tlv(0x0100, fec_p2mp(6, ip4('10.0.0.1'), b'')[:-2] + struct.pack('!H', 100)))  # opaque too long
    one(tlv(0x0100, b'\x80\x00\x05'))                       # PWid short
    one(tlv(0x0100, pw_fec(0x80, 0, 5, 1, 2, [b'\x01\x00'])))   # interface param length 0
    # Observation: pwid_len is not reduced by the 4 byte PW ID, so a second
    # FEC element after the parameters is read as another parameter
    one(tlv(0x0100, pw_fec(0x80, 0, 5, 1, 2, [ip_param(1, b'\x05\xdc')]) + fec_wild() + fec_wild()))
    one(tlv(0x0100, pw_fec(0x80, 0, 5, 1, 2, [b'\x01\xf0\x00\x00'])))  # length past the end
    one(tlv(0x0100, b'\x81\x00'))                           # generalized short
    one(tlv(0x0100, b'\x99\x01\x02\x03'))                   # unknown FEC type
    one(tlv(0x0100, b'\x84\x01\x02\x03'))                   # P2MP PW downstream
    one(tlv(0x0100, struct.pack('!BHB', 0x05, 5, 20) + struct.pack('!I', 9) + struct.pack('!I', 4) + b'\x01\x00'))
    one(tlv(0x0100, b'\x08\x00\x01\x04\x0a\x00\x00\x01\x00\x20'))   # MP2MP opaque length 32 > 0
    # Same errors with another TLV after them, so that the error item
    # fits in the frame and the dissection goes on
    tail = tlv(0x0200, struct.pack('!I', 5))
    one(tlv(0x0100, struct.pack('!BHB', 5, 5, 6) + struct.pack('!II', 9, 4) + b'\x01\xf0') + tail)
    one(tlv(0x0100, pw_fec(0x80, 0, 5, 1, 2, [b'\x01\xf0'])) + tail)
    one(tlv(0x0100, struct.pack('!BHB', 0x82, 5, 2) + agi(1, b'')) + tail)
    one(tlv(0x0100, struct.pack('!BHB', 0x82, 5, 4) + agi(1, b'') + agi(1, b'')) + tail)
    one(tlv(0x096b, b'\x01\xf0\x00\x00') + tail)
    # message errors
    d(pdu(b'\x01\x00\x00'))                                 # PDU holding a 3 byte message
    d(pdu(struct.pack('!HHI', 0x0400, 2, 1)))               # message length < 4
    d(pdu(struct.pack('!HHII', 0x3e01, 6, 1, 2)))           # vendor message length < 8
    d(pdu(msg(0x0400, tlv(0x0100, fec_wild()) + b'\x01\x02')))   # trailing 2 bytes after TLV
    d(pdu(msg(0x0400, tlv(0x0100, b'\x01', length=500))))   # TLV length past the message
    d(pdu(b'\x04\x00\x00\x40\x00\x00\x00\x01', length=300)) # PDU length past the frame
    # PDU length < message
    d(pdu(msg(0x0400, tlv(0x0100, fec_wild())), length=14))
    # IPv4 interface ID sub-TLVs with the wrong sizes, MPLS context with
    # nested contexts
    iid_hdr = ip4('10.0.0.1') + struct.pack('!I', 5)
    sub_mc = tlv(0x001e, ip4('10.0.0.5') + ip4('232.1.1.1'))
    d(pdu(msg(0x0400, tlv(0x082d, iid_hdr + sub_mc + b'\x00\x00\x00\x00'))))
    d(pdu(msg(0x0400, tlv(0x082d, iid_hdr + tlv(0x001f, ip4('10.0.0.6') + tlv(0x001f, ip4('10.0.0.7') + sub_mc)))
              + tlv(0x0200, struct.pack('!I', 1)))))
    # bad PDU version and a short hello
    d(struct.pack('!HH', 2, 6) + b'\x00' * 6)
    d(b'\x00')
    frames.append(udp_frame(pdu(msg(0x0100, tlv(0x0400, struct.pack('!HH', 15, 0))), version=2)))
    frames.append(udp_frame(b'\x00'))
    # P2MP element length that put the opaque value beyond the TLV
    # (fix) and the 1 byte wildcard
    frames.append(udp_frame(pdu(msg(0x0402, tlv(0x0100, fec_wild(), length=1)))))
    return frames


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'ldp-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'ldp-coverage-malformed.pcap'), build_malformed())


if __name__ == '__main__':
    main()

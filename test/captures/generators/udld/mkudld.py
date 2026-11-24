#!/usr/bin/env python3
# Generates test/captures/udld_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: pcap writer and Ethernet / MPLS / IPv4 / UDP builders.
import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def eth(payload, etype, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4(payload, proto=17, src=IP_A, dst=IP_B, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                    64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def ipv6(payload, nh=17):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('>IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(payload, sport, dport, src=IP_A, dst=IP_B):
    n = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, n)
    h = struct.pack('>HHHH', sport, dport, n, 0)
    c = csum(pseudo + h + payload) or 0xffff
    return struct.pack('>HHHH', sport, dport, n, c) + payload


def udp_frame(payload, sport, dport, ident=1):
    return eth(ipv4(udp(payload, sport, dport), ident=ident), 0x0800)


def mpls(label, payload, ttl=64, tc=0, bos=1):
    return struct.pack('>I', (label << 12) | (tc << 9) | (bos << 8) | ttl) + payload


def mpls_frame(label, payload, **kw):
    return eth(mpls(label, payload, **kw), 0x8847)


class Pcap:
    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def add(self, data, snap=None):
        # snap: captured length smaller than the original length
        self.frames.append((data, snap))
        return len(self.frames)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype))
            for i, (d, snap) in enumerate(self.frames):
                t = 1700000000 + i
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', t, 1000 * i, len(cap), len(d)))
                f.write(cap)
        return len(self.frames)


def tcp(payload, sport, dport, seq=1, ack=1, flags=0x18, src=IP_A, dst=IP_B):
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(pseudo + h + payload)
    return h[:16] + struct.pack('>H', c) + h[18:] + payload


def tcp_frame(payload, sport, dport, seq=1, ack=1, flags=0x18, down=False, ident=1):
    if down:
        return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags, src=IP_B, dst=IP_A), 6, src=IP_B, dst=IP_A, ident=ident), 0x0800, dst=MAC_A, src=MAC_B)
    return eth(ipv4(tcp(payload, sport, dport, seq, ack, flags), 6, ident=ident), 0x0800)


class Tcp:
    """One TCP connection with consistent sequence numbers (client = IP_A)."""
    def __init__(self, cport, sport, ident=1):
        self.cport, self.sport, self.ident = cport, sport, ident
        self.cseq, self.sseq = 1000, 5000

    def c(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.cport, self.sport, self.cseq, self.sseq, 0x18, False, self.ident)
        self.cseq += len(payload)
        return f

    def s(self, payload):
        self.ident += 1
        f = tcp_frame(payload, self.sport, self.cport, self.sseq, self.cseq, 0x18, True, self.ident)
        self.sseq += len(payload)
        return f


def raw_eth(dst, src, etype, payload):
    return dst + src + struct.pack('>H', etype) + payload

# ---- udld ----
# UDLD (Cisco Unidirectional Link Detection): LLC/SNAP with the Cisco OUI and
# PID 0x0111 on Ethernet (reached by default), and Cisco HDLC protocol 0x0111
# (the extra capture udld-coverage-chdlc.pcap, link type 104).
CISCO_MAC = bytes.fromhex('01000ccccccc')


def tlv(t, data, length=None):
    return struct.pack('>HH', t, 4 + len(data) if length is None else length) + data


def pdu(op, flags=0, tlvs=b'', ver=1, csum=0x1234):
    return struct.pack('>BBH', (ver << 5) | op, flags, csum) + tlvs


def frame(p):
    llc = b'\xaa\xaa\x03\x00\x00\x0c\x01\x11' + p
    return raw_eth(CISCO_MAC, MAC_A, len(llc), llc)


def build(out):
    main = Pcap()
    full = (tlv(1, b'SAL1234ABCD\0') + tlv(2, b'Gi0/1') + tlv(3, b'\0\0\0\1\0\0\0\2' + b'\0\0\0\3') +
            tlv(4, b'\x0f') + tlv(5, b'\x05') + tlv(6, b'switch1\0') + tlv(7, struct.pack('>I', 0xdeadbeef)))
    main.add(frame(pdu(1, 0, full)))                                               # 1 Probe with every TLV type, Port ID in the middle
    main.add(frame(pdu(2, 1, tlv(1, b'SAL5678EFGH\0') + tlv(2, b'Gi0/2') + tlv(3, bytes(8)))))   # 2 Echo, flag RT
    main.add(frame(pdu(3, 2, tlv(1, b'flush-dev\0') + tlv(2, b'Te1/0/1'))))          # 3 Flush, flag ReSynch; Port ID is the last TLV (the fix)
    main.add(frame(pdu(0, 3, tlv(7, bytes(4)), ver=7)))                            # 4 reserved opcode 0, version 7, both flags
    main.add(frame(pdu(1, 0, tlv(0x0099, b'unknown tlv data'))))                   # 5 unknown TLV type
    main.add(frame(pdu(1, 0, tlv(1, b''))))                                        # 6 Device ID with no data
    main.add(frame(pdu(1, 0, tlv(0x0042, b''))))                                   # 7 unknown TLV of length 4: dissection returns at once
    main.add(frame(pdu(1, 0, tlv(2, b'Gi0/3xyz', length=9))))                      # 8 Port ID TLV whose length is too short: length + 3
    main.add(frame(pdu(1, 0, tlv(2, b'Fa0/1') + tlv(1, b'dev\0'))))                # 9 Port ID followed by a TLV (the byte after is 0)
    main.add(frame(pdu(1, 0)))                                                     # 10 header only, no TLVs
    main.add(frame(pdu(1, 0, tlv(1, b'a' * 100 + b'\0'))))                         # 11 long Device ID
    main.write(os.path.join(out, 'udld-coverage.pcap'))
    ch = Pcap(104)
    for p in (pdu(1, 0, tlv(1, b'chdlc-dev\0') + tlv(2, b'Se0/0')), pdu(2, 1, tlv(7, bytes(4)))):
        ch.add(b'\x0f\x00\x01\x11' + p)                                            # Cisco HDLC frames, protocol 0x0111
    ch.write(os.path.join(out, 'udld-coverage-chdlc.pcap'))
    bad = Pcap()
    bad.add(frame(pdu(1, 0, tlv(1, b'dev\0') + struct.pack('>HH', 7, 2) + b'xx')))   # 1 TLV with length 2 (< 4): warning, dissection stops
    bad.add(frame(pdu(1, 0, struct.pack('>HH', 7, 0))))                            # 2 TLV with length 0
    bad.add(frame(pdu(1, 0, tlv(1, b'abc', length=200))))                          # 3 Device ID longer than the packet
    bad.add(frame(pdu(1, 0, struct.pack('>HH', 1, 40) + b'ab')))                   # 4 same, cut off
    bad.add(frame(pdu(1, 0, tlv(2, b'Gi0/1', length=300))))                        # 5 Port ID longer than the packet
    bad.add(frame(pdu(1, 0, tlv(0x0099, b'xy', length=50))))                       # 6 unknown TLV longer than the packet
    bad.add(frame(pdu(1, 0, b'\x00\x01')))                                         # 7 TLV cut in the header
    bad.add(frame(b'\x21\x00'))                                                    # 8 UDLD header cut in the checksum
    bad.add(frame(pdu(1, 0, tlv(2, b'Gi0/1')) ), )                                 # 9 (control, valid)
    bad.write(os.path.join(out, 'udld-coverage-malformed.pcap'))
    print('main', len(main.frames), 'malformed', len(bad.frames))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

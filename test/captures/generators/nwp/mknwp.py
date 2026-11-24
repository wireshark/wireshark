#!/usr/bin/env python3
# Generates test/captures/nwp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NWP dissector
(packet-nwp.c, Neighborhood Watch Protocol, Ethernet type 0xC0DF).

Every packet is built with struct; nothing comes from a real network.

Usage: mknwp.py <output directory>

Writes:
  nwp-coverage.pcap            announcements and neighbour lists with several
                               HIDs, hardware address lengths and neighbour
                               device counts
  nwp-coverage-malformed.pcap  unknown types (error expert info), truncated
                               announcements and neighbour lists
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IPA = bytes((192, 0, 2, 1))
IPB = bytes((192, 0, 2, 2))

def ip4(proto, payload, src=IPA, dst=IPB, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('>H', csum(h)) + h[12:] + payload

def eth(payload, et=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', et) + payload

def udp_frame(payload, sport, dport, src=IPA, dst=IPB):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('>BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
    return eth(ip4(17, u, src, dst))

class Tcp:
    """Minimal TCP flow: handshake, then data segments in both directions."""
    def __init__(self, sport, dport, cseq=1000, sseq=70000):
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = cseq, sseq
        self.frames = []

    def _seg(self, to_server, payload, flags):
        if to_server:
            src, dst, sp, dp, seq, ack = IPA, IPB, self.sport, self.dport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = IPB, IPA, self.dport, self.sport, self.sseq, self.cseq
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, 0x50, flags, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(ph + t)) + t[18:]
        mac_s, mac_d = (MAC_A, MAC_B) if to_server else (MAC_B, MAC_A)
        self.frames.append(eth(ip4(6, t, src, dst), src=mac_s, dst=mac_d))
        adv = len(payload) + (1 if flags & 3 else 0)
        if to_server:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._seg(True, b'', 0x02)
        self._seg(False, b'', 0x12)
        self._seg(True, b'', 0x10)

    def send(self, to_server, payload):
        self._seg(to_server, payload, 0x18)
        self._seg(not to_server, b'', 0x10)

def write_pcap(path, frames, linktype=1, snap=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)



def hid(n):
    return bytes(((n * 31 + k * 7) & 0xff) for k in range(20))


def ann(hids, haddr, version=1, typ=1, hid_count=None, hlen=None):
    return (struct.pack('>BBBB', version, typ, len(hids) if hid_count is None else hid_count,
                        len(haddr) if hlen is None else hlen) + haddr + b''.join(hids))


def nlist(entries, hlen, hid_count=None):
    """entries: list of (hid, [hardware addresses])."""
    b = struct.pack('>BBBB', 1, 2, len(entries) if hid_count is None else hid_count, hlen)
    for h, addrs in entries:
        b += h + bytes((len(addrs),)) + b''.join(addrs)
    return b


def frame(payload, src=MAC_A, dst=bytes.fromhex('ffffffffffff')):
    return eth(payload, et=0xc0df, src=src, dst=dst)


def main_capture(path):
    fr = []
    ha = bytes.fromhex('020000000011')
    fr.append(frame(ann([hid(1)], ha)))
    fr.append(frame(ann([hid(1), hid(2), hid(3)], ha)))
    fr.append(frame(ann([], ha)))                                       # no HIDs
    fr.append(frame(ann([hid(4)], bytes.fromhex('0a0b'))))              # 2 octet hardware address
    fr.append(frame(ann([hid(5), hid(6)], bytes(range(16)))))           # 16 octet address
    fr.append(frame(ann([hid(7)], b'')))                                # no address
    fr.append(frame(ann([hid(n) for n in range(20)], ha), src=MAC_B))   # many HIDs
    a6 = lambda n: bytes.fromhex('0200000000%02x' % n)
    fr.append(frame(nlist([(hid(1), [a6(1)])], 6)))
    fr.append(frame(nlist([(hid(1), [a6(1), a6(2)]), (hid(2), [a6(3)]), (hid(3), [])], 6)))
    fr.append(frame(nlist([(hid(8), [bytes((1, 2)), bytes((3, 4)), bytes((5, 6))])], 2)))
    fr.append(frame(nlist([(hid(9), [bytes(range(16))])], 16), src=MAC_B))
    fr.append(frame(nlist([(hid(n), [a6(n)]) for n in range(12)], 6)))
    fr.append(frame(nlist([(hid(10), [])], 0)))                         # hardware address length 0
    fr.append(frame(ann([hid(11)], ha, version=2)))                     # other version
    fr.append(frame(ann([hid(1)], ha) + b'\xff\xff\xff'))               # trailing data
    write_pcap(path, fr)


def malformed_capture(path):
    fr = []
    ha = bytes.fromhex('020000000011')
    fr.append(frame(nlist([], 6)))                                      # no neighbours: the list item has no data
    fr.append(frame(ann([hid(1)], ha, typ=3)))                          # unknown type: error expert info
    fr.append(frame(ann([hid(1)], ha, typ=0)))
    fr.append(frame(ann([hid(1)], ha, typ=0xff)))
    fr.append(frame(b'\x01\x01\x00'))                                   # shorter than the header
    fr.append(frame(b'\x01'))
    fr.append(frame(ann([hid(1), hid(2)], ha)[:-5]))                    # last HID cut
    fr.append(frame(ann([hid(1)], ha, hid_count=5)))                    # more HIDs than present
    fr.append(frame(ann([hid(1)], ha, hlen=40)))                        # address longer than the packet
    fr.append(frame(nlist([(hid(1), [bytes(6)])], 6)[:-3]))             # neighbour cut
    fr.append(frame(nlist([(hid(1), [bytes(6)])], 6, hid_count=4)))     # more neighbours than present
    fr.append(frame(nlist([(hid(1), [bytes(6)])], 6)[:10]))             # neighbour list cut in the HID
    b = bytearray(nlist([(hid(1), [bytes(6)])], 6))
    b[4 + 20] = 200                                                     # device count beyond the packet
    fr.append(frame(bytes(b)))
    write_pcap(path, fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'nwp-coverage.pcap'))
    malformed_capture(os.path.join(out, 'nwp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/nxp_802154_sniffer_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the NXP 802.15.4 Sniffer
dissector (packet-nxp_802154_sniffer.c, UDP port 49999).

A sniffer packet is a 5 octet timestamp, a NUL terminated sniffer ID, the
channel (11-26), the LQI, the length of the IEEE 802.15.4 frame and the
frame itself, which includes the 2 octet FCS. The frames handed to the
IEEE 802.15.4 dissector are built here with a CRC-16/KERMIT FCS. Every
packet is built with struct; nothing comes from a real network.

Usage: mknxp_802154_sniffer.py <output directory>

Writes:
  nxp_802154_sniffer-coverage.pcap            sniffer packets with beacon,
                                              data, ACK and MAC command frames
                                              on every channel, ID strings of
                                              several lengths, packets that the
                                              check rejects (stay plain UDP)
  nxp_802154_sniffer-coverage-malformed.pcap  frames that decode with errors
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



def fcs(b):
    crc = 0
    for x in b:
        crc ^= x
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return struct.pack('<H', crc)


def mac_data(seq, dst, src, payload=b'', pan=0x1234):
    return struct.pack('<HBH', 0x8841, seq, pan) + struct.pack('<HH', dst, src) + payload


ZB_BEACON = b'\x00\x22\x84' + bytes(range(8)) + b'\xff\xff\xff' + b'\x01'


def mac_beacon(seq, src, payload=ZB_BEACON):
    return struct.pack('<HBHH', 0x8000, seq, 0x1234, src) + struct.pack('<HBB', 0xcfff, 0, 0) + payload


def mac_ack(seq):
    return struct.pack('<HB', 0x0002, seq)


def mac_assoc(seq, dst=0x0000, srcpan=0x1234, src=0x1122334455667788):
    return struct.pack('<HBHHH', 0xc823, seq, 0x1234, dst, srcpan) + struct.pack('<Q', src) + b'\x01\x8e'


def mac_cmd(seq, cmd, dst=0x0000, src=0x0001, extra=b''):
    return struct.pack('<HBHHH', 0x8863, seq, 0x1234, dst, src) + bytes([cmd]) + extra


def sniff(frame, channel=11, lqi=200, ts=0x0102030405, sid=b'JN5168-A', with_fcs=True, length=None):
    f = frame + (fcs(frame) if with_fcs else b'')
    return (ts.to_bytes(5, 'big') + sid + b'\0' + bytes((channel, lqi, len(f) if length is None else length)) + f)


def main_capture(path):
    fr = []
    n = [0]

    def add(payload, sport=50000, dport=49999):
        n[0] += 1
        fr.append(udp_frame(payload, sport, dport))
    # every channel of the 2.4 GHz PHY
    for ch in range(11, 27):
        add(sniff(mac_data(ch, 0xffff, 0x0001, b'\x00' + bytes(range(1, 10)) + bytes([ch])), channel=ch, lqi=(ch * 9) & 0xff, ts=ch * 1000))
    add(sniff(mac_beacon(1, 0x0001), channel=15, lqi=0))
    add(sniff(mac_ack(7), channel=16, lqi=255))
    add(sniff(mac_assoc(8), channel=17))                             # association request
    add(sniff(mac_cmd(9, 4), channel=17))                             # data request
    add(sniff(mac_data(10, 0x0002, 0x0001, b'\x00' + bytes(range(99))), channel=20))
    add(sniff(mac_data(11, 0x0002, 0x0001, b'\x00' + bytes(range(1, 100))), channel=20, sid=b''))          # empty ID
    add(sniff(mac_data(12, 0x0002, 0x0001, b'\x00x'), channel=20, sid=b'a-sniffer-id-that-is-longer-than-usual'))
    add(sniff(mac_data(13, 0x0002, 0x0001, b'\x00x'), channel=20, ts=0xffffffffff))
    add(sniff(mac_data(14, 0x0002, 0x0001, b'\x00' + bytes(range(1, 110))), channel=26))                      # 127 octet frame (maximum)
    # rejected by the check: stay plain UDP
    add(sniff(mac_ack(16), channel=10))                                                   # channel < 11
    add(sniff(mac_ack(17), channel=27))                                                   # channel > 26
    add(sniff(mac_ack(18), length=1))                                                     # length < FCS length
    add(sniff(mac_ack(19), length=128))                                                   # length > 127
    add(sniff(mac_ack(20), length=6))                                                     # length does not match
    add(sniff(mac_ack(21)) + b'\0')                                                       # trailing octet
    add(b'\0' * 5 + b'noterminator' + bytes((11, 0, 5)))                                  # ID without NUL
    add(b'\0\0\0\0\0A\0\x0b')                                                             # ends in the channel field
    add(b'12345678')                                                                      # shorter than 9 octets
    write_pcap(path, fr)


def malformed_capture(path):
    fr = []
    n = [0]

    def add(payload):
        n[0] += 1
        fr.append(udp_frame(payload, 51000 + n[0], 49999))
    add(sniff(mac_data(1, 2, 1, b'abc'), with_fcs=False, length=len(mac_data(1, 2, 1, b'abc'))))   # no FCS, bad FCS
    f = mac_data(2, 2, 1, b'abc')
    add(sniff(f + b"\0\0", length=len(f) + 2))
    add(sniff(b'', channel=11))                                                            # frame of 2 octets: FCS only
    add(sniff(b'\x41\x88', channel=12))                                                    # frame control only
    add(sniff(b'\xff\xff\xff\xff\xff\xff', channel=12))                                    # reserved frame type
    add(sniff(b'\x03\x00\x01', channel=12))                                                # frame type 3 (MAC command) cut short
    write_pcap(path, fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'nxp_802154_sniffer-coverage.pcap'))
    malformed_capture(os.path.join(out, 'nxp_802154_sniffer-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()

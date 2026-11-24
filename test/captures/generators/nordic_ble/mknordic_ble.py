#!/usr/bin/env python3
# Generates the nordic_ble captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Nordic BLE sniffer coverage captures (synthetic, struct only).

Usage: mknordic_ble.py <outdir> [-v]

Writes, into <outdir>:
  nordic_ble-coverage.pcapng            main capture (linktype 272, two interfaces)
  nordic_ble-coverage-malformed.pcapng  bad length, bad CRC/MIC, unknown version, short frames
  nordic_ble_protodata_confusion.pcap   reproducer of 9cf3a8a6fa (needs Decode As udp.port 5555)
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

AA_ADV = 0x8e89bed6
PHY_1M, PHY_2M, PHY_CODED = 0, 1, 2


# ------------------------------------------------------------ BLE payloads
def adv_pdu(ptype=0, data=b'\x02\x01\x06', txadd=0, addr=b'\x01\x02\x03\x04\x05\x06'):
    pl = addr + data
    return bytes([ptype | (txadd << 6), len(pl)]) + pl


def ll_data(llid=1, payload=b'', nesn=0, sn=0):
    return bytes([llid | (nesn << 2) | (sn << 3), len(payload)]) + payload


def ble(aa, pdu, ci=None):
    return struct.pack('<I', aa) + (bytes([ci]) if ci is not None else b'') + pdu + b'\xaa\xbb\xcc'   # CRC


# ------------------------------------------------------------ nordic frames
def flags_byte(crc=1, direction=0, enc=0, mic=0, phy=0, aux=0, res=0):
    return (crc & 1) | (direction << 1) | (enc << 2) | (mic << 3) | (phy << 4) | (res << 7)


def nordic(protover, ptype, flags, channel, rssi, evcnt, time, blebytes, counter=1, board=0,
           pid=None, plen=None, evlen=10, marker=False):
    """ptype: the packet id (0x06 data, 0x02 advertising, ...)."""
    pid = ptype if pid is None else pid
    if protover == 0:
        ev = struct.pack('<BBBHI', flags, channel, rssi, evcnt, time)
        rest = ev + blebytes
        pl = len(rest) if plen is None else plen
        return b'\xbe\xef' + struct.pack('<BHHB', pid, counter, 0, pl) + rest
    ev = struct.pack('<BBBBHI', evlen, flags, channel, rssi, evcnt, time)
    rest = ev + blebytes
    pl = len(rest) if plen is None else plen
    if protover == 1:
        return struct.pack('<BBBBHB', board, 6, pl, protover, counter, pid) + rest
    return struct.pack('<BHBHB', board, pl, protover, counter, pid) + rest


def pcapng(frames, ifaces=1, name='x'):
    """frames: list of (interface id, bytes)."""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for i in range(ifaces):
        out += blk(1, struct.pack('<HHI', 272, 0, 0))
    ts = 1700000000 * 10**6
    for n, (i, d) in enumerate(frames):
        t = ts + n * 1000
        out += blk(6, struct.pack('<IIIII', i, t >> 32, t & 0xffffffff, len(d), len(d)) + d)
    return out


def write(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)


RANGES = []


class Cap:
    def __init__(self, name, ifaces=1):
        self.name, self.ifaces, self.frames = name, ifaces, []

    def add(self, data, iface=0):
        self.frames.append((iface, data))
        return len(self.frames)

    def group(self, text):
        first = len(self.frames) + 1
        return lambda: RANGES.append((self.name, first, len(self.frames), text))

    def save(self):
        write(self.name, pcapng(self.frames, self.ifaces))


def main():
    os.makedirs(OUT, exist_ok=True)
    c = Cap('nordic_ble-coverage.pcapng', 2)
    t = [1000]

    def tm(step=500):
        t[0] += step
        return t[0]

    adv = ble(AA_ADV, adv_pdu())
    scan_req = ble(AA_ADV, bytes([0x03, 12]) + bytes(range(1, 13)))
    empty = ble(0x50123456, ll_data())
    data = ble(0x50123456, ll_data(2, b'\x04\x00\x04\x00\x0a\x0b'))

    # --- legacy (0xBEEF) and version 1 and 2: access address tells adv from data
    g = c.group('legacy (0xBEEF) frames: advertising, data, directions, PHY')
    for ph, (b, d) in enumerate(((adv, 0), (empty, 0), (data, 1), (scan_req, 0))):
        c.add(nordic(0, 0x06, flags_byte(1, d, 0, 0, PHY_1M), 37 + ph % 3, 50 + ph, ph, tm(), b))
    c.add(nordic(0, 0x06, flags_byte(1, 0, 0, 0, PHY_2M), 12, 60, 5, tm(), empty))
    g()
    g = c.group('version 1 frames')
    for ph, (b, d) in enumerate(((adv, 0), (empty, 1), (data, 0), (scan_req, 0))):
        c.add(nordic(1, 0x06, flags_byte(1, d, 0, 0, PHY_1M), 38, 61 + ph, 10 + ph, tm(), b, counter=20 + ph))
    c.add(nordic(1, 0x06, flags_byte(1, 0, 0, 0, PHY_2M), 12, 62, 14, tm(), data, counter=30, board=3))
    g()
    g = c.group('version 2 frames: delta times, 1M, 2M and coded PHY, two interfaces')
    for ph, (b, d, phy) in enumerate(((adv, 0, PHY_1M), (empty, 1, PHY_1M), (data, 0, PHY_2M),
                                      (scan_req, 0, PHY_2M), (ble(0x50123456, ll_data(), ci=0), 0, PHY_CODED),
                                      (adv, 0, 3))):
        c.add(nordic(2, 0x06, flags_byte(1, d, 0, 0, phy), 37, 40 + ph, 100 + ph, 150 + 10 * ph, b, counter=40 + ph))
    c.add(nordic(2, 0x06, flags_byte(1, 1, 0, 0, PHY_1M), 5, 40, 120, 300, empty), iface=1)
    c.add(nordic(2, 0x06, flags_byte(1, 0, 0, 0, PHY_1M), 5, 41, 121, 310, data), iface=1)
    g()
    # --- version 3
    g = c.group('version 3: advertising PDUs (packet id 2), PHYs, coded PHY CI values')
    for ph, (phy, ci) in enumerate(((PHY_1M, None), (PHY_2M, None), (PHY_CODED, 0), (PHY_CODED, 1),
                                    (PHY_CODED, 2), (3, None))):
        b = ble(AA_ADV, adv_pdu(), ci=ci)
        c.add(nordic(3, 0x02, flags_byte(1, 0, 0, 0, phy), 37, 50, 200 + ph, tm(), b, counter=50 + ph))
    c.add(nordic(3, 0x02, flags_byte(1, 0, 0, 0, PHY_1M), 38, 50, 210, tm(), scan_req, counter=60), iface=1)
    c.add(nordic(3, 0x02, flags_byte(1, 0, 0, 0, PHY_1M) | 0x08, 39, 51, 211, tm(), adv, counter=61), iface=1)
    g()
    g = c.group('version 3: extended advertising on data channels (aux types 0-3, address resolved)')
    ext = ble(AA_ADV, bytes([0x07, 1, 0x00]))
    for aux in range(4):
        c.add(nordic(3, 0x02, flags_byte(1) | (aux << 1) | 0x08 * (aux & 1), 5 + aux, 70, 220 + aux, tm(), ext,
                     counter=70 + aux))
    g()
    g = c.group('version 3: data PDUs (packet id 6): direction, encrypted, MIC ok, not relevant')
    c.add(nordic(3, 0x06, flags_byte(1, 0), 10, 45, 300, tm(), empty, counter=80))
    c.add(nordic(3, 0x06, flags_byte(1, 1), 10, 45, 300, tm(), data, counter=81))
    c.add(nordic(3, 0x06, flags_byte(1, 1, 1, 1), 10, 45, 301, tm(), ble(0x50123456, ll_data(2, b'\x11' * 9)), counter=82))
    c.add(nordic(3, 0x06, flags_byte(1, 0, 1, 1, PHY_2M), 11, 45, 301, tm(), ble(0x50123456, ll_data(2, b'\x22' * 9)), counter=83))
    c.add(nordic(3, 0x06, flags_byte(1, 0, 0, 1), 11, 45, 302, tm(), empty, counter=84))
    c.add(nordic(3, 0x06, flags_byte(1, 0, 0, 0, PHY_CODED), 12, 45, 303, tm(), ble(0x50123456, ll_data(), ci=0), counter=85))
    c.add(nordic(3, 0x06, flags_byte(1, 1, 0, 0, PHY_CODED), 12, 45, 303, tm(), ble(0x50123456, ll_data(), ci=1), counter=86))
    g()
    g = c.group('version 3: other packet ids (unknown PDU type), reserved flag bits, board ids')
    c.add(nordic(3, 0x05, flags_byte(1), 20, 45, 310, tm(), empty, counter=90, board=7))
    c.add(nordic(3, 0x0c, flags_byte(1), 20, 45, 311, tm(), empty, counter=91, board=0xff))
    c.add(nordic(3, 0x02, flags_byte(1, res=1), 38, 45, 312, tm(), adv, counter=92))
    c.add(nordic(3, 0x06, flags_byte(1, res=1), 10, 45, 313, tm(), empty, counter=93))
    g()
    g = c.group('time ordering: a timestamp that goes back, equal timestamps, a frame on the other interface')
    c.add(nordic(3, 0x06, flags_byte(1), 10, 45, 320, 5, empty, counter=100))
    c.add(nordic(3, 0x06, flags_byte(1), 10, 45, 321, 5, empty, counter=101))
    c.add(nordic(3, 0x06, flags_byte(1), 10, 45, 322, 0xfffffff0, empty, counter=102), iface=1)
    c.add(nordic(3, 0x06, flags_byte(1), 10, 45, 323, 3, empty, counter=103), iface=1)
    g()
    c.save()

    # ---- malformed / error expert infos
    m = Cap('nordic_ble-coverage-malformed.pcapng', 1)
    g = m.group('bad CRC (v3 data, v3 advertising, v2), bad MIC (CRC ok / CRC bad), bad lengths, unknown version')
    m.add(nordic(3, 0x06, flags_byte(0), 10, 45, 1, 100, empty))
    m.add(nordic(3, 0x02, flags_byte(0), 37, 45, 2, 200, adv))
    m.add(nordic(2, 0x06, flags_byte(0), 37, 45, 3, 300, adv))
    m.add(nordic(3, 0x06, flags_byte(1, 0, 1, 0), 10, 45, 4, 400, ble(0x50123456, ll_data(2, b'\x11' * 9))))
    m.add(nordic(3, 0x06, flags_byte(0, 0, 1, 0), 10, 45, 5, 500, ble(0x50123456, ll_data(2, b'\x11' * 9))))
    m.add(nordic(3, 0x06, flags_byte(1), 10, 45, 6, 600, empty, plen=3))        # bad length (v3)
    m.add(nordic(2, 0x06, flags_byte(1), 10, 45, 7, 700, empty, plen=40))       # bad length (v2)
    m.add(nordic(1, 0x06, flags_byte(1), 10, 45, 8, 800, empty, plen=4))        # bad length (v1)
    m.add(nordic(0, 0x06, flags_byte(1), 10, 45, 9, 900, empty, plen=4))        # bad length (legacy)
    m.add(nordic(4, 0x06, flags_byte(1), 10, 45, 10, 1000, empty))               # unknown version
    m.add(nordic(9, 0x02, flags_byte(1), 37, 45, 11, 1100, adv))
    # coded PHY with a PDU shorter than the AA and CI: packet time computation wraps
    m.add(nordic(3, 0x06, flags_byte(1, 0, 0, 0, PHY_CODED), 12, 45, 12, 1200, b'\x01\x02'))
    g()
    g = m.group('truncated frames (exceptions): header only, cut in the event')
    full = nordic(3, 0x06, flags_byte(1), 10, 45, 13, 1300, empty)
    for n in (1, 3, 7, 8, 12, 16):
        m.add(full[:n])
    full2 = nordic(0, 0x06, flags_byte(1), 10, 45, 13, 1300, empty)
    for n in (2, 5, 9):
        m.add(full2[:n])
    g()
    m.save()

    # ---- reproducer of 9cf3a8a6fa: two PDUs in one frame (needs Decode As)
    def csum(b):
        if len(b) % 2:
            b += b'\0'
        s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff

    def ipv4_udp(payload, sport=5555, dport=5555):
        udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
        hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                          bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
        return hdr + udp

    def n3(v):   # a complete, well-formed PDU of the given version
        return nordic(v, 0x06, flags_byte(1), 10, 40, 7, 1000, empty)

    def submux(pdu):
        return struct.pack('!HH', 0xC000 | (2 + len(pdu)), 0x0021) + pdu
    payload = submux(ipv4_udp(n3(3))) + submux(ipv4_udp(n3(2)))
    eth = b'\xff\x03' + struct.pack('!H', 0x0059) + payload      # PPP, PPPMux
    rec = lambda d, i: struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)) + d
    write('nordic_ble_protodata_confusion.pcap',
          struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 9) + rec(eth, 0)
          + rec(b'\xff\x03' + struct.pack('!H', 0x0059) + submux(ipv4_udp(n3(2))) + submux(ipv4_udp(n3(3))), 1))
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(c.frames), len(m.frames))


main()

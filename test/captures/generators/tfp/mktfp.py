#!/usr/bin/env python3
# Generates test/captures/tfp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Tinkerforge Protocol (TFP)
dissector (packet-tfp.c).

TFP runs over TCP port 4223 (brickd) and over USB bulk endpoints of
devices with vendor 0x16D0 and product 0x063D (heuristic dissector
"usb.bulk"; the device descriptor must be in the capture).

Usage: mktfp.py <output directory>

Writes:
  tfp-coverage.pcapng            TFP over TCP (several UIDs, flags, with
                                 and without payload) and over USB
                                 (bulk OUT and IN), a bulk transfer of a
                                 device that is not a Tinkerforge brick
  tfp-coverage-malformed.pcap    TCP segments shorter than the 8 octet
                                 header
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def pcapng(path, linktypes, frames):
    """frames: list of (interface index, bytes)."""
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += block(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def usbhdr(urb_id, typ, xfer, ep, length, caplen, setup=b'\0' * 8, dev=1, bus=1,
           flag_setup=None, flag_data=0):
    """64-byte usbmon header (DLT 220). typ 'S' submit or 'C' complete."""
    if flag_setup is None:
        flag_setup = ord('-')
    return struct.pack('<QBBBBHBBqiiII8siiII', urb_id, ord(typ), xfer, ep, dev, bus,
                       flag_setup, flag_data, 0, 0, 0 if typ == 'C' else -115,
                       length, caplen, setup, 0, 0, 0, 0)


def usb_descriptor(urb, vid, pid, dev=1):
    """Two frames: GET DESCRIPTOR (device) submit and complete."""
    setup = struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)
    s = usbhdr(urb, 'S', 2, 0x80, 18, 0, setup, dev=dev, flag_setup=0, flag_data=ord('<'))
    desc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, 0x0100, 0, 0, 0, 1)
    c = usbhdr(urb, 'C', 2, 0x80, 18, 18, setup, dev=dev, flag_setup=ord('-')) + desc
    return [s, c]


def usb_bulk_out(urb, data, ep=0x02, dev=1):
    return usbhdr(urb, 'S', 3, ep, len(data), len(data), dev=dev) + data


def usb_bulk_in(urb, data, ep=0x81, dev=1):
    return usbhdr(urb, 'C', 3, ep, len(data), len(data), dev=dev) + data

BASE58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'


def tfp(uid, fid, seq=1, r=1, a=0, oo=0, e=0, future=0, payload=b'', length=None):
    if length is None:
        length = 8 + len(payload)
    b6 = (seq << 4) | (r << 3) | (a << 2) | oo
    b7 = (e << 6) | future
    return struct.pack('<IBBBB', uid, length, fid, b6, b7) + payload


def tcp_frames():
    T = []
    c = [1, 1]   # client and server sequence numbers

    def cl(p):
        T.append(tcp(50100, 4223, c[0], c[1], p))
        c[0] += len(p)

    def sv(p):
        T.append(tcp(4223, 50100, c[1], c[0], p, rev=True))
        c[1] += len(p)
    # 1: header only: UID 0 (shown as "1"), get_authentication_nonce style
    cl(tfp(0, 1, seq=1))
    # 2: callback with payload, UID of one character (57 -> "z")
    sv(tfp(57, 2, seq=2, r=0, payload=b'\x01\x02\x03\x04'))
    # 3: UID 58 -> two characters "21"; response expected, other options
    cl(tfp(58, 3, seq=15, r=1, a=1, oo=3, payload=b'\xff' * 5))
    # 4: error code 1..3 and future use bits
    sv(tfp(0x12345678, 4, seq=0, r=0, a=0, oo=0, e=2, future=0x2a,
           payload=b'\x00'))
    # 5: the largest UID (6 characters)
    cl(tfp(0xffffffff, 255, seq=7, payload=b'payload of get_chip_temperature'))
    # 6: UID with a base58 digit of every kind at the high end
    sv(tfp(3 * 58 ** 5 + 57 * 58 + 11, 9, seq=3, e=3, payload=bytes(range(8))))
    # 7: segment with exactly the 8 octet header and a length field of 20
    cl(tfp(1234567, 10, length=20))
    return T


def usb_frames():
    U = []
    urb = 0
    # device 1: Tinkerforge (0x16D0:0x063D)
    urb += 1
    U += usb_descriptor(urb, 0x16D0, 0x063D, dev=1)
    # bulk OUT (host to device) and IN (device to host)
    urb += 1
    U.append(usb_bulk_out(urb, tfp(0x00abcdef, 1, seq=1)))
    urb += 1
    U.append(usb_bulk_in(urb, tfp(0x00abcdef, 1, seq=1, r=0, payload=b'\x07\x00\x00\x00')))
    urb += 1
    U.append(usb_bulk_out(urb, tfp(0x00abcdef, 5, seq=2, r=1, a=1, payload=b'123456789')))
    # device 2: another vendor, same kind of data (not TFP)
    urb += 1
    U += usb_descriptor(urb, 0x1234, 0x5678, dev=2)
    urb += 1
    U.append(usb_bulk_out(urb, tfp(0x00abcdef, 1, seq=1), dev=2))
    # device 3: bulk without any descriptor seen (not TFP)
    urb += 1
    U.append(usb_bulk_out(urb, tfp(0x00abcdef, 1, seq=1), dev=3))
    # device 4: vendor matches, product does not
    urb += 1
    U += usb_descriptor(urb, 0x16D0, 0x0001, dev=4)
    urb += 1
    U.append(usb_bulk_out(urb, tfp(0x00abcdef, 1, seq=1), dev=4))
    return U


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = [(0, f) for f in tcp_frames()] + [(1, f) for f in usb_frames()]
    pcapng(os.path.join(out, 'tfp-coverage.pcapng'), [1, 220], frames)
    # malformed: segments shorter than the header
    mal = [tcp(50101, 4223, 1, 1, tfp(5, 1)[:7]),
           tcp(4223, 50101, 1, 8, tfp(5, 1)[:3], rev=True),
           tcp(50101, 4223, 8, 4, tfp(0x7fffffff, 2, payload=b'ab')[:9])]
    pcap(os.path.join(out, 'tfp-coverage-malformed.pcap'), mal)


if __name__ == '__main__':
    main()

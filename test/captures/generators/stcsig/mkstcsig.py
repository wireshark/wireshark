#!/usr/bin/env python3
# Generates test/captures/stcsig_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Spirent Test Center Signature
(STCSIG) post-dissector (packet-stcsig.c).

STCSIG is a post-dissector that is disabled by default (enable it with
"--enable-protocol stcsig" or in Analyze > Enabled Protocols). It looks for
a 20 octet signature at the end of the frame (optionally followed by a 4
octet or 8 octet FCS, and preceded by a zero octet) and decodes it. The
signature is obfuscated with a fixed table (not cryptography); this
generator applies the inverse of the table.

Usage: mkstcsig.py <output directory>

Writes:
  stcsig-coverage.pcap            frames with signatures of every layout,
                                  sequence number forms, timestamps and
                                  stream types, and frames without one
  stcsig-coverage-malformed.pcap  (see the README) frames that are
                                  too short or only nearly signatures
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

# deobfuscation table of packet-stcsig.c (decode_signature)
DEOBFUSCATE = [
    0x00, 0x71, 0xe3, 0x92, 0xb6, 0xc7, 0x55, 0x24,
    0x1c, 0x6d, 0xff, 0x8e, 0xaa, 0xdb, 0x49, 0x38,
    0x39, 0x48, 0xda, 0xab, 0x8f, 0xfe, 0x6c, 0x1d,
    0x25, 0x54, 0xc6, 0xb7, 0x93, 0xe2, 0x70, 0x01,
    0x72, 0x03, 0x91, 0xe0, 0xc4, 0xb5, 0x27, 0x56,
    0x6e, 0x1f, 0x8d, 0xfc, 0xd8, 0xa9, 0x3b, 0x4a,
    0x4b, 0x3a, 0xa8, 0xd9, 0xfd, 0x8c, 0x1e, 0x6f,
    0x57, 0x26, 0xb4, 0xc5, 0xe1, 0x90, 0x02, 0x73,
    0xe4, 0x95, 0x07, 0x76, 0x52, 0x23, 0xb1, 0xc0,
    0xf8, 0x89, 0x1b, 0x6a, 0x4e, 0x3f, 0xad, 0xdc,
    0xdd, 0xac, 0x3e, 0x4f, 0x6b, 0x1a, 0x88, 0xf9,
    0xc1, 0xb0, 0x22, 0x53, 0x77, 0x06, 0x94, 0xe5,
    0x96, 0xe7, 0x75, 0x04, 0x20, 0x51, 0xc3, 0xb2,
    0x8a, 0xfb, 0x69, 0x18, 0x3c, 0x4d, 0xdf, 0xae,
    0xaf, 0xde, 0x4c, 0x3d, 0x19, 0x68, 0xfa, 0x8b,
    0xb3, 0xc2, 0x50, 0x21, 0x05, 0x74, 0xe6, 0x97,
    0xb8, 0xc9, 0x5b, 0x2a, 0x0e, 0x7f, 0xed, 0x9c,
    0xa4, 0xd5, 0x47, 0x36, 0x12, 0x63, 0xf1, 0x80,
    0x81, 0xf0, 0x62, 0x13, 0x37, 0x46, 0xd4, 0xa5,
    0x9d, 0xec, 0x7e, 0x0f, 0x2b, 0x5a, 0xc8, 0xb9,
    0xca, 0xbb, 0x29, 0x58, 0x7c, 0x0d, 0x9f, 0xee,
    0xd6, 0xa7, 0x35, 0x44, 0x60, 0x11, 0x83, 0xf2,
    0xf3, 0x82, 0x10, 0x61, 0x45, 0x34, 0xa6, 0xd7,
    0xef, 0x9e, 0x0c, 0x7d, 0x59, 0x28, 0xba, 0xcb,
    0x5c, 0x2d, 0xbf, 0xce, 0xea, 0x9b, 0x09, 0x78,
    0x40, 0x31, 0xa3, 0xd2, 0xf6, 0x87, 0x15, 0x64,
    0x65, 0x14, 0x86, 0xf7, 0xd3, 0xa2, 0x30, 0x41,
    0x79, 0x08, 0x9a, 0xeb, 0xcf, 0xbe, 0x2c, 0x5d,
    0x2e, 0x5f, 0xcd, 0xbc, 0x98, 0xe9, 0x7b, 0x0a,
    0x32, 0x43, 0xd1, 0xa0, 0x84, 0xf5, 0x67, 0x16,
    0x17, 0x66, 0xf4, 0x85, 0xa1, 0xd0, 0x42, 0x33,
    0x0b, 0x7a, 0xe8, 0x99, 0xbd, 0xcc, 0x5e, 0x2f,]


def deob10(k):
    for _ in range(10):
        k = DEOBFUSCATE[k]
    return k


def is_signature(b):
    """The check of is_signature() in packet-stcsig.c."""
    return b[0] + (b[10] ^ deob10(b[0])) == 255


def make_sig(iv, plain_tail):
    """plain_tail: the 19 decoded octets 1..19 (octet 10 must be 255 - iv
    for the signature check). Returns the 20 obfuscated octets."""
    plain = bytearray([iv]) + bytearray(plain_tail)
    assert plain[10] == 255 - iv
    enc = bytearray(plain)
    ov = iv
    for i in range(1, 16):
        ov = DEOBFUSCATE[ov]
        enc[i] = plain[i] ^ ov
    assert is_signature(enc)
    return bytes(enc)


def sig(iv=0x11, csp=0x0102, hard=False, index=0x0007, seq=0x01020304, edm=True,
        ticks=0x123456789, prb=0, tslr=0, trailer=b'\xde\xad\xbe\xef'):
    """Build a signature. The decoded layout: IV (octet 0), 4 octets of
    stream id (CSP 2 octets, then the type bit and the 15 bit index),
    6 octets of sequence number (EDM form: the complement of the high 16
    bits, then the 32 bit number; otherwise a 48 bit number), 5 octets of
    timestamp (32 bit tick count, then 6 more bits of the count and the PRBS
    and TSLR bits; 2.5 ns ticks), 4 octets of unobfuscated trailer. The low
    octet of the sequence number is replaced by 255 - IV, which the
    signature check requires."""
    streamid = struct.pack('>HH', csp, (0x8000 if hard else 0) | index)
    if edm:
        seq = (seq & ~0xff) | (255 - iv)
        sn = struct.pack('>HI', 0xffff - (seq >> 16), seq)
    else:
        seq = (seq & ~0xff) | (255 - iv)
        sn = struct.pack('>Q', seq)[2:]
        assert struct.unpack('>H', sn[0:2])[0] + struct.unpack('>H', sn[2:4])[0] != 0xffff
    t = struct.pack('>IB', ticks & 0xffffffff, ((ticks >> 32) << 2) | (prb << 1) | tslr)
    return make_sig(iv, streamid + sn + t + trailer)


def frame(sigbytes, fcs=b'', zero=True, payload=b'stcsig test payload'):
    body = payload + (b'\0' if zero else b'\x55') + sigbytes + fcs
    return udp(40000, 40001, body)


def detected(fr):
    """Emulate the choice in dissect_stcsig(): number of octets of the
    signature (including the FCS) found at the end of the frame, or 0."""
    n = len(fr)
    if n >= 21 and fr[n - 21] == 0 and is_signature(fr[n - 20:]):
        return 20
    if n >= 25 and fr[n - 25] == 0 and is_signature(fr[n - 24:]):
        return 24
    if n >= 29 and fr[n - 29] == 0 and is_signature(fr[n - 28:]):
        return 28
    if n >= 20 and is_signature(fr[n - 20:]):
        return 20
    if n >= 24 and is_signature(fr[n - 24:]):
        return 24
    if n >= 28 and is_signature(fr[n - 28:]):
        return 28
    return 0


def fcs_for(sigbytes, n, zero, other=b''):
    """Find FCS octets (4 or 8) after the signature so that the signature
    check at the tail does not match earlier than the real one."""
    for k in range(1, 256):
        fcs = bytes([k, k ^ 0x5a, 0x33, 0xc7, 0x01, 0x02, 0x03, 0x04][:n])
        fr = frame(sigbytes, fcs, zero)
        want = len(sigbytes) + n
        if detected(fr) == want:
            return fcs
    raise SystemExit('no FCS found')


def main_frames():
    F = []
    # 1: signature (20 octets) after a zero octet, EDM sequence number,
    #    soft stream, PRBS and TSLR clear
    F.append(frame(sig()))
    # 2: hard stream, other CSP and index, PRBS and TSLR set
    F.append(frame(sig(iv=0x40, csp=0xbeef, hard=True, index=0x7fff,
                       prb=1, tslr=1)))
    # 3: sequence mode (48 bit sequence number), large timestamp
    F.append(frame(sig(iv=0x80, edm=False, seq=0x112233445566,
                       ticks=0x3fffffffff)))
    # 4: signature followed by a 4 octet FCS
    s4 = sig(iv=0x21, seq=70000)
    F.append(frame(s4, fcs_for(s4, 4, True), True))
    # 5: signature followed by an 8 octet FCS (Fibre Channel)
    s5 = sig(iv=0x22, hard=True, seq=0x7ffffff0)
    F.append(frame(s5, fcs_for(s5, 8, True), True))
    # 6: signature that is not preceded by a zero octet
    F.append(frame(sig(iv=0x33, seq=5), zero=False))
    # 7: not preceded by zero, with a 4 octet FCS
    s7 = sig(iv=0x44, seq=9)
    F.append(frame(s7, fcs_for(s7, 4, False), False))
    # 8: not preceded by zero, with an 8 octet FCS
    s8 = sig(iv=0x55, seq=10, edm=False, ticks=1)
    F.append(frame(s8, fcs_for(s8, 8, False), False))
    # 9: IV 0 (the first entry of the tables), timestamp 0
    F.append(frame(sig(iv=0x00, ticks=0, seq=0)))
    # 10: IV 255
    F.append(frame(sig(iv=0xff, ticks=1, seq=0xffffff00)))
    # 11: no signature (all zero payload of 60 octets)
    F.append(udp(40000, 40001, bytes(40)))
    # 12: an ARP frame (no signature), 42 octets
    F.append(eth(struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A,
                             bytes([192, 0, 2, 1]), bytes(6), bytes([192, 0, 2, 2])),
                 0x0806))
    # check the layouts
    want = [20, 20, 20, 24, 28, 20, 24, 28, 20, 20, 0, 0]
    assert [detected(f) for f in F] == want, [detected(f) for f in F]
    return F


def malformed_frames():
    F = []
    # frames shorter than a signature, a signature with a wrong check
    # octet, and a frame of exactly 20 octets without Ethernet header
    bad = bytearray(sig())
    bad[10] ^= 0x01
    F.append(frame(bytes(bad)))
    F.append(eth(b'\x01\x02', 0x88b5))
    F.append(eth(bytes(19), 0x88b5))
    F.append(eth(bytes(7), 0x88b5)[:20])
    # exactly 28 and 29 octet tail frames: frame = signature only after
    # an Ethernet header cut so that the signature is the whole frame
    F.append(sig() + sig()[:0])
    F.append(b'\0' + sig())
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'stcsig-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'stcsig-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

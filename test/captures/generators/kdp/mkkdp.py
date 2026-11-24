#!/usr/bin/env python3
# Generates test/captures/kdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the KDP (Kontiki Delivery Protocol) coverage captures.

Usage: mkkdp.py <outdir>

  kdp-coverage.pcap            valid KDP and SDDP datagrams (UDP 19948)
  kdp-coverage-malformed.pcap  bad option length, header longer than the
                               datagram, short headers
Synthetic: built with struct only.
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')
PORT = 19948

F_DROP, F_SYN, F_ACK, F_RST, F_BCST, F_DUP = 1, 2, 4, 8, 16, 32


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def udp_frame(payload, sport=40000, dport=PORT):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return CMAC + SMAC + b'\x08\x00' + ip + u


def hdr(flags, errors=0, *, dest=None, src=None, seq=0x1000, ack=None, mss=None,
        options=b'', frag=None, body=b'', hlen=None):
    """A KDP version 2 datagram. The header length byte counts 4 octets;
    with a body the header ends with the fragment and fragment total."""
    h = b''
    if dest is not None:
        h += struct.pack('!I', dest)
    if src is not None:
        h += struct.pack('!I', src)
    h += struct.pack('!I', seq)
    if ack is not None:
        h += struct.pack('!I', ack)
    if mss is not None:
        h += struct.pack('!I', mss)
    h += options
    if body:
        h += struct.pack('!HH', *(frag or (0, 1)))
    h = bytes([2, 0, flags, errors]) + h
    assert len(h) % 4 == 0, len(h)
    h = bytes([2, len(h) // 4 if hlen is None else hlen]) + h[2:]
    return h + body


def opt(n, v=b''):
    return bytes([n, 2 + len(v)]) + v


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main(out):
    fr = []

    def add(p, **kw):
        fr.append(udp_frame(p, **kw))

    # 1: the 4 byte header alone
    add(bytes([2, 1, 0, 0]))
    # 2: SYN with source flow id, sequence and maximum segment size
    add(hdr(F_SYN, 0, src=0xaabb0001, seq=1, mss=1400))
    # 3: SYN | ACK
    add(hdr(F_SYN | F_ACK, 0, dest=0xaabb0001, src=0xccdd0002, seq=1, ack=2, mss=1400),
        sport=PORT, dport=40000)
    # 4: ACK
    add(hdr(F_ACK, 0, dest=0xccdd0002, seq=3, ack=2))
    # 5: broadcast
    add(hdr(F_BCST, 0, src=0x01020304, seq=9))
    # 6: SYN | BCST (one source flow id)
    add(hdr(F_SYN | F_BCST, 3, src=0x01020304, seq=9, mss=576))
    # 7: RST with errors
    add(hdr(F_RST, 17, seq=0x20))
    # 8: DROP | DUP
    add(hdr(F_DROP | F_DUP, 255, seq=0x21))
    # 9: every flag
    add(hdr(0x3f, 1, dest=1, src=2, seq=3, ack=4, mss=5))
    # 10: undefined flag bits only
    add(hdr(0xc0, 0, seq=0x22))
    # 11: options 1 to 9 and an unknown one, option 0 padding (no body)
    o = (opt(1, b'\x00\x10') + opt(2, b'\x00\x20') + opt(3, b'\x00\x02') + opt(4) + opt(5)
         + opt(6, b'\x01\x02\x03\x04') + opt(7, b'\x00\x01') + opt(8, b'\x00\x08')
         + opt(9, b'\x00\x09') + opt(0x20, b'\xaa\xbb\xcc') + b'\x00\x00\x00')
    o += b'\x00' * (-(len(o) + 8) % 4)
    add(hdr(F_ACK, 0, dest=7, seq=5, ack=6, options=o))
    # 12: a body: options, fragment 2 of 5 and 20 bytes
    add(hdr(0, 0, seq=0x30, options=opt(1, b'\x00\x40'), frag=(2, 5), body=bytes(range(20))))
    # 13: a body with ACK, SYN and no options
    add(hdr(F_ACK | F_SYN, 0, dest=1, src=2, seq=3, ack=4, mss=1200, frag=(0, 1),
            body=b'encrypted body'))
    # 14: header length 4 with a body that is not decoded
    add(bytes([2, 1, 0, 0]) + b'trailing')
    # 15: SDDP (version byte not 2): XML body
    add(b'<?xml version="1.0"?><sddp><device name="x"/></sddp>')
    # 16: version 1
    add(b'\x01' + b'data')
    # 17: reproducer of "KDP: Do not truncate the header length": header
    # length byte 65 (260 bytes, stored in a uint8_t it wrapped to 4):
    # 63 options of 4 octets after the sequence number
    o = b''.join(opt(n, struct.pack('!H', i)) for i in range(63) for n in [(1, 2, 3, 7, 8, 9)[i % 6]])
    add(hdr(0, 0, seq=0x40, options=o))
    # 18: the same with a body (the option loop ends 4 octets before the end)
    add(hdr(0, 5, seq=0x41, options=o, frag=(1, 2), body=b'big header body'))
    pcap(os.path.join(out, 'kdp-coverage.pcap'), fr)

    mal = []
    mal.append(udp_frame(hdr(0, 0, seq=1, options=bytes([6, 1, 0, 0]))))
    mal.append(udp_frame(hdr(0, 0, seq=1, options=bytes([0x30, 0, 0, 0]))))
    # header length longer than the datagram
    mal.append(udp_frame(hdr(0, 0, seq=1, hlen=0x80)))
    # option whose length runs past the datagram
    mal.append(udp_frame(hdr(0, 0, seq=1, options=bytes([6, 200, 1, 2]))))
    # SYN flag, but the header ends after 6 octets
    mal.append(udp_frame(bytes([2, 2, F_SYN, 0, 0, 0, 0, 0])))
    # one byte only
    mal.append(udp_frame(b'\x02'))
    pcap(os.path.join(out, 'kdp-coverage-malformed.pcap'), mal)


if __name__ == '__main__':
    main(sys.argv[1])

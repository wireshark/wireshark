#!/usr/bin/env python3
# Generates test/captures/ubdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the UBDP coverage captures: mkubdp.py <outdir>

ubdp-coverage.pcap            Ubiquiti discovery messages (version 1 and 2)
ubdp-coverage-malformed.pcap  TLVs that run past the message, short messages
ubdp-coverage-udp.pcap        the first five messages as UDP port 10001 frames (Decode As)
Frames are Exported PDU (link type 252) naming the "ubdp" dissector; UBDP has
no default port (UDP 10001 needs Decode As, see runcov.sh).
"""
import os
import struct
import sys

LT = 252


def exp_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def tlv(t, v):
    return struct.pack('>BH', t, len(v)) + v


def msg(tlvs, version=1, command=6):
    body = b''.join(tlvs)
    return exp_pdu('ubdp', struct.pack('>BBH', version, command, len(body)) + body)


MAC = bytes.fromhex('00156d112233')
IP = bytes([192, 168, 1, 20])


def build():
    frames = []
    # a discovery request: header only
    frames.append(msg([], version=1, command=1))
    frames.append(msg([], version=2, command=1))
    # a version 1 reply with the fields of an access point
    frames.append(msg([tlv(1, MAC), tlv(2, MAC + IP), tlv(3, b'BZ.ar7240.v3.7.58.6385.170508.0824'),
                       tlv(10, struct.pack('>I', 86400)), tlv(11, 'ap-lobby'.encode()),
                       tlv(12, b'U7PG2'), tlv(13, b'Ubiquiti'), tlv(14, b'\x02'),
                       tlv(15, b'https://192.168.1.20:8443'), tlv(16, b'\xe5\xa5'),
                       tlv(18, struct.pack('>I', 77))], version=1))
    # a version 2 reply with the other TLVs
    frames.append(msg([tlv(4, IP), tlv(5, MAC), tlv(19, MAC), tlv(6, b'ubnt'), tlv(7, bytes(range(16))),
                       tlv(8, bytes(range(32, 48))), tlv(9, bytes(range(64, 80))),
                       tlv(20, b'UGW4'), tlv(21, b'US24P250'), tlv(22, b'4.4.55.5377260'),
                       tlv(23, b'\x01'), tlv(24, b'\x00'), tlv(25, b'\x01'), tlv(26, b'\x00'),
                       tlv(27, b'UniFi-Gateway/4.4.55'), tlv(28, struct.pack('>H', 22))], version=2))
    # four octet default and locating flags; a UTF-8 hostname
    frames.append(msg([tlv(23, struct.pack('>I', 1)), tlv(24, struct.pack('>I', 0)),
                       tlv(11, 'käyttäjä-日本'.encode()), tlv(13, b'guest wifi')], version=2))
    # product, type and model names from the table and unknown ones
    for t in (12, 20, 21):
        for name in (b'UP5tc', b'US8P150', b'p2N', b'U7MP', b'NoSuchModel'):
            frames.append(msg([tlv(t, name)], version=1 + (t & 1)))
    # unknown TLV types and an empty TLV
    frames.append(msg([tlv(0x30, b'\x01\x02\x03'), tlv(17, b''), tlv(29, b'xyz'), tlv(255, bytes(7)),
                       tlv(6, b''), tlv(1, MAC)], version=1))
    # warnings: unsupported versions (no TLVs are decoded), wrong lengths
    frames.append(msg([tlv(1, MAC)], version=0))
    frames.append(msg([tlv(1, MAC)], version=3))
    for t, v in ((1, b'\x00\x11'), (5, b''), (19, bytes(7)), (2, bytes(7)), (4, bytes(5)),
                 (10, b'\x00'), (14, b'\x00\x01'), (16, b'\x01'), (18, bytes(3)),
                 (23, bytes(2)), (24, bytes(3)), (25, bytes(2)), (26, bytes(4)), (28, b'\x16')):
        frames.append(msg([tlv(t, v), tlv(11, b'after')], version=1))

    mal = []
    # a TLV longer than the rest of the message, for typed and untyped TLVs
    for t in (1, 2, 3, 10, 11, 12, 99, 28):
        body = struct.pack('>BH', t, 40) + bytes(5)
        mal.append(exp_pdu('ubdp', struct.pack('>BBH', 1, 6, len(body)) + body))
    # a TLV header cut after one or two octets
    mal.append(exp_pdu('ubdp', struct.pack('>BBH', 1, 6, 3) + b'\x0b\x00\x00'[:2]))
    mal.append(exp_pdu('ubdp', struct.pack('>BBH', 2, 6, 3) + b'\x0b'))
    # messages shorter than the four octet header
    for n in range(4):
        mal.append(exp_pdu('ubdp', b'\x01\x06\x00\x00'[:n]))
    # a message of invalid UTF-8 and non-ASCII strings
    mal.append(msg([tlv(11, b'\xff\xfe\x80abc'), tlv(15, b'\xc3'), tlv(6, b'\x80\xff'), tlv(13, b'\xe9')], version=2))
    return frames, mal


def udp_frame(payload, sport=10001, dport=10001, dst=bytes([255] * 4)):
    """Ethernet / IPv4 / UDP frame (broadcast discovery on UDP 10001)."""
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 168, 1, 20]), dst)
    s = 0
    for i in range(0, 20, 2):
        s += (ip[i] << 8) | ip[i + 1]
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    eth = bytes.fromhex('ffffffffffff00156d112233') + b'\x08\x00'
    return eth + ip + udp


def write_pcap(path, frames, lt=None):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, lt or LT))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


frames, mal = build()
out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
write_pcap(os.path.join(out, 'ubdp-coverage.pcap'), frames)
write_pcap(os.path.join(out, 'ubdp-coverage-malformed.pcap'), mal)
# the same discovery messages on UDP port 10001 (Decode As, see runcov.sh)
raw = [f[16:] for f in frames[:5]]      # strip the Exported PDU header (16 octets for "ubdp")
write_pcap(os.path.join(out, 'ubdp-coverage-udp.pcap'), [udp_frame(r) for r in raw], lt=1)
print(len(frames), len(mal))

#!/usr/bin/env python3
# Generates test/captures/csn1_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CSN.1 decoder library
(packet-csn1.c) through its users, the GSM RLC/MAC dissector
(packet-gsm_rlcmac.c) and the GMR-1 BCCH dissector (packet-gmr1_bcch.c).

The capture is a pcapng file with two interfaces:
  0  Ethernet: GSMTAP v2 over UDP port 4729
       - GSM Um PACCH, downlink and uplink (ARFCN uplink flag), carrying
         RLC/MAC control blocks (CS-1)
       - GSM Um PDTCH, carrying GPRS data blocks (CS-1..CS-4, chosen by
         the block length), EGPRS blocks (header types 1-3, MCS-1..9)
         and uplink access bursts (8 and 11 bit)
       - GMR-1 Um BCCH, carrying GMR-1 System Information
  1  Exported PDU (link type 252), dissector names gsm_rlcmac_ul /
     gsm_rlcmac_dl / gsm_ec_rlcmac_ul / gsm_ec_rlcmac_dl: EC-GSM-IoT
     control blocks, which nothing else hands to the RLC/MAC dissector,
     and the reproducer frames of csn1_var_tarray_overflow.py exactly as
     that script builds them.

Most RLC/MAC message bodies are pseudo-random bits from a seeded
generator (random.Random) with a given probability of a 1 bit, behind a
correct MAC header and message type; the (kind, message type, seed,
probability, length) tuples in SELECTED were chosen from a few
thousand candidates because they decode without errors and between them
add every field, subtree and message type the candidates reach (greedy
set cover); MALFORMED_SELECTED holds one candidate per distinct expert
info. The other
messages are built field by field. Nothing comes from a real network.

Usage: mkcsn1.py <output directory>

Writes:
  csn1-coverage.pcapng            messages that decode without errors,
                                  the boundary and reproducer frames
                                  (gzipped as csn1_coverage.pcapng.gz for
                                  the test suite; the file is pcapng)
  csn1-coverage-malformed.pcapng  CSN.1 error paths (truncated messages,
                                  bad FIXED values, union and choice
                                  indexes, too many elements)
"""

import os
import random
import struct
import sys

# ---------------------------------------------------------------- bits


class Bits:
    def __init__(self):
        self.s = ''

    def put(self, v, n):
        if n:
            self.s += format(v & ((1 << n) - 1), '0%db' % n)
        return self

    def putbits(self, s):
        self.s += s
        return self

    def __len__(self):
        return len(self.s)

    def bytes(self, total, pad='spare'):
        """Pad to 'total' octets with the 0x2b spare pattern (or zeros)
        relative to the octet boundaries, as GSM does."""
        s = self.s
        if len(s) > total * 8:
            raise ValueError('message too long: %d > %d bits' % (len(s), total * 8))
        if pad == 'spare':
            spare = ''.join(format(0x2b, '08b') for _ in range(total))
            s = s + spare[len(s):]
        else:
            s = s + '0' * (total * 8 - len(s))
        return int(s, 2).to_bytes(total, 'big') if total else b''


def rand_bits(rng, n, p):
    return ''.join('1' if rng.random() < p else '0' for _ in range(n))

# ---------------------------------------------------------------- framing

def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


GSMTAP_TYPE_UM = 0x01
GSMTAP_TYPE_GMR1_UM = 0x0a
GSMTAP_CHANNEL_PACCH = 0x0b
GSMTAP_CHANNEL_PDTCH = 0x0d
GSMTAP_GMR1_BCCH = 0x01
UPLINK = 0x4000


def gsmtap(gtype, sub_type, payload, uplink=False, arfcn=17, fn=0, ts=0):
    hdr = struct.pack('>BBBBHbBIBBBB', 2, 4, gtype, ts,
                      arfcn | (UPLINK if uplink else 0), -70, 30, fn,
                      sub_type, 0, 0, 0)
    udp_payload = hdr + payload
    sip, dip = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])
    udp = struct.pack('>HHHH', 40000, 4729, 8 + len(udp_payload), 0) + udp_payload
    ph = sip + dip + struct.pack('>BBH', 0, 17, len(udp))
    c = csum16(ph + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0, sip, dip)
    ip = ip[:10] + struct.pack('>H', csum16(ip)) + ip[12:]
    eth = bytes.fromhex('020000000014') + bytes.fromhex('02000000000a') + b'\x08\x00'
    return (0, eth + ip + udp)


def exported_pdu(name, payload):
    n = name.encode()
    tags = struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0)
    return (1, tags + payload)


def write_pcapng(path, frames):
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack('<II', btype, total) + body + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))     # Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 65535))   # Exported PDU
    t = 1700000000 * 1000000
    for i, (ifid, data) in enumerate(frames):
        ts = t + i * 1000
        out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)

# ---------------------------------------------------------------- random bodies

def rand_frame(kind, mt, seed, p, length):
    """A message of the given kind and message type whose body is
    pseudo-random with probability p of a 1 bit."""
    rng = random.Random('%s/%d/%d/%s/%d' % (kind, mt, seed, p, length))
    b = Bits()
    if kind == 'dl':          # PACCH downlink, MAC header without optional octets
        b.put(1, 2).put(rng.randrange(4), 2).put(rng.randrange(2), 1).put(rng.randrange(8), 3)
        b.put(mt, 6)
    elif kind == 'dlopt':     # payload type 2: RBSN, RTI, FS, AC, optional octets
        rbsn, fs, ac = seed & 1, (seed >> 1) & 1, (seed >> 2) & 1
        b.put(2, 2).put(rng.randrange(4), 2).put(rng.randrange(2), 1).put(rng.randrange(8), 3)
        b.put(rbsn, 1).put(rng.randrange(32), 5).put(fs, 1).put(ac, 1)
        if ac:
            b.put(rng.randrange(4), 2).put(rng.randrange(32), 5).put(rng.randrange(2), 1)
        if rbsn and not fs:
            b.put(rng.randrange(8), 3).put(rng.randrange(2), 1).put(0, 4)
        b.put(mt, 6)
    elif kind == 'ul':        # PACCH uplink: payload type 1, spare, R, type
        b.put(1, 2).put(0, 5).put(rng.randrange(2), 1).put(mt, 6)
    elif kind == 'ecdl':      # EC-GSM-IoT downlink: header of 5 or 13 bits
        long_hdr = seed & 1
        b.put(rng.randrange(2), 1).put(long_hdr, 1)
        b.putbits(rand_bits(rng, 11 if long_hdr else 3, 0.5))
        b.put(mt, 5)
    elif kind == 'ecul':
        b.put(mt, 5)
    elif kind in ('dldata', 'uldata'):
        b.put(0, 2)           # payload type data, the rest is random
    elif kind == 'prach':     # access burst: 8 bit (0x1f / 000) or 11 bit forms
        b.putbits(['011111', '000', '111111001', '110111'][mt])
    elif kind == 'gmr1':      # GMR-1 BCCH: protocol version, block type (1: SI1)
        b.put(rng.randrange(16), 4).put(mt, 1)
    # egprs_dl / egprs_ul: random from the first bit
    b.putbits(rand_bits(rng, length * 8 - len(b), p))
    data = b.bytes(length)
    return wrap(kind, data, mt)


def wrap(kind, data, mt=0):
    if kind in ('dl', 'dlopt'):
        return gsmtap(GSMTAP_TYPE_UM, GSMTAP_CHANNEL_PACCH, data, fn=mt)
    if kind == 'ul':
        return gsmtap(GSMTAP_TYPE_UM, GSMTAP_CHANNEL_PACCH, data, uplink=True, fn=mt)
    if kind in ('dldata', 'egprs_dl'):
        return gsmtap(GSMTAP_TYPE_UM, GSMTAP_CHANNEL_PDTCH, data, fn=mt)
    if kind in ('uldata', 'egprs_ul', 'prach'):
        return gsmtap(GSMTAP_TYPE_UM, GSMTAP_CHANNEL_PDTCH, data, uplink=True, fn=mt)
    if kind == 'ecdl':
        return exported_pdu('gsm_ec_rlcmac_dl', data)
    if kind == 'ecul':
        return exported_pdu('gsm_ec_rlcmac_ul', data)
    if kind == 'exp_ul':
        return exported_pdu('gsm_rlcmac_ul', data)
    if kind == 'gmr1':
        return gsmtap(GSMTAP_TYPE_GMR1_UM, GSMTAP_GMR1_BCCH, data)
    raise ValueError(kind)

DL_TYPES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x15, 0x16, 0x21, 0x22, 0x23, 0x24, 0x25, 0x31, 0x32, 0x33, 0x36, 0x37]
UL_TYPES = list(range(0x0e))
ECDL_TYPES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x11, 0x12]
ECUL_TYPES = [0x01, 0x02]

SELECTED = [
    ('dl', 1, 0, 0.1, 23), ('dl', 1, 4, 0.1, 23), ('dl', 1, 0, 0.3, 23),
    ('dl', 1, 3, 0.3, 23), ('dl', 1, 5, 0.5, 23), ('dl', 1, 2, 0.2, 64),
    ('dl', 1, 5, 0.2, 64), ('dl', 2, 4, 0.3, 23), ('dl', 2, 5, 0.3, 23),
    ('dl', 3, 0, 0.5, 23), ('dl', 4, 5, 0.2, 64), ('dl', 5, 1, 0.1, 23),
    ('dl', 5, 1, 0.5, 23), ('dl', 7, 3, 0.3, 23), ('dl', 7, 0, 0.5, 23),
    ('dl', 7, 1, 0.3, 64), ('dl', 8, 0, 0.0, 23), ('dl', 9, 0, 0.1, 23),
    ('dl', 9, 2, 0.1, 64), ('dl', 10, 2, 0.2, 23), ('dl', 10, 5, 0.5, 23),
    ('dl', 10, 0, 0.1, 64), ('dl', 10, 0, 0.3, 64), ('dl', 10, 2, 0.3, 64),
    ('dl', 11, 5, 0.2, 23), ('dl', 12, 0, 0.0, 23), ('dl', 12, 4, 0.1, 23),
    ('dl', 13, 0, 0.0, 23), ('dl', 21, 1, 0.1, 23), ('dl', 21, 3, 0.1, 23),
    ('dl', 21, 1, 0.2, 23), ('dl', 21, 4, 0.1, 64), ('dl', 21, 5, 0.2, 64),
    ('dl', 21, 0, 0.3, 64), ('dl', 21, 3, 0.3, 64), ('dl', 22, 0, 0.0, 23),
    ('dl', 33, 2, 0.2, 23), ('dl', 34, 2, 0.1, 23), ('dl', 34, 2, 0.5, 23),
    ('dl', 35, 0, 0.2, 23), ('dl', 36, 0, 0.0, 23), ('dl', 37, 0, 0.0, 23),
    ('dl', 49, 4, 0.3, 23), ('dl', 50, 2, 0.1, 23), ('dl', 50, 4, 0.2, 23),
    ('dl', 50, 0, 0.3, 23), ('dl', 50, 1, 0.3, 23), ('dl', 51, 2, 0.3, 23),
    ('dl', 51, 4, 0.2, 64), ('dl', 51, 5, 0.3, 64), ('dl', 54, 5, 0.1, 23),
    ('dl', 54, 0, 0.3, 64), ('dl', 55, 1, 0.5, 23), ('dl', 55, 4, 0.5, 23),
    ('dl', 55, 5, 0.5, 23), ('dlopt', 2, 7, 0.3, 23),
    ('dlopt', 9, 1, 0.1, 23), ('dlopt', 10, 3, 0.3, 23),
    ('ul', 0, 7, 0.5, 64), ('ul', 1, 0, 0.5, 23), ('ul', 2, 2, 0.5, 23),
    ('ul', 2, 3, 0.5, 23), ('ul', 3, 0, 0.0, 23), ('ul', 4, 1, 0.2, 64),
    ('ul', 4, 0, 0.5, 64), ('ul', 4, 1, 0.5, 64), ('ul', 4, 4, 0.5, 64),
    ('ul', 5, 4, 0.3, 64), ('ul', 5, 5, 0.5, 64), ('ul', 5, 7, 0.5, 64),
    ('ul', 6, 0, 0.0, 23), ('ul', 7, 6, 0.3, 64), ('ul', 8, 1, 0.1, 23),
    ('ul', 8, 0, 0.5, 23), ('ul', 9, 0, 0.0, 23), ('ul', 10, 4, 0.1, 23),
    ('ul', 10, 1, 0.5, 64), ('ul', 11, 1, 0.5, 64), ('ul', 11, 7, 0.5, 64),
    ('ul', 12, 1, 0.3, 23), ('ul', 12, 0, 0.5, 23), ('ul', 12, 3, 0.3, 64),
    ('ul', 12, 5, 0.3, 64), ('ul', 13, 4, 0.1, 23), ('ecdl', 1, 0, 0.0, 23),
    ('ecdl', 2, 0, 0.0, 23), ('ecdl', 3, 0, 0.0, 23), ('ecdl', 4, 0, 0.0, 23),
    ('ecdl', 5, 0, 0.2, 23), ('ecdl', 5, 1, 0.3, 23), ('ecdl', 6, 4, 0.5, 23),
    ('ecdl', 7, 0, 0.0, 23), ('ecdl', 17, 0, 0.0, 23),
    ('ecdl', 18, 0, 0.0, 23), ('ecul', 1, 0, 0.0, 23),
    ('ecul', 2, 3, 0.3, 23), ('dldata', 0, 0, 0.1, 23),
    ('dldata', 0, 1, 0.1, 34), ('dldata', 0, 1, 0.1, 40),
    ('dldata', 0, 0, 0.1, 54), ('uldata', 0, 3, 0.1, 23),
    ('uldata', 0, 1, 0.1, 34), ('uldata', 0, 0, 0.1, 40),
    ('uldata', 0, 0, 0.1, 54), ('egprs_dl', 0, 0, 0.5, 27),
    ('egprs_dl', 0, 3, 0.3, 33), ('egprs_dl', 0, 0, 0.1, 42),
    ('egprs_dl', 0, 0, 0.1, 49), ('egprs_dl', 0, 3, 0.1, 60),
    ('egprs_dl', 0, 7, 0.3, 61), ('egprs_dl', 0, 2, 0.1, 78),
    ('egprs_dl', 0, 1, 0.1, 79), ('egprs_dl', 0, 8, 0.5, 118),
    ('egprs_dl', 0, 9, 0.5, 119), ('egprs_dl', 0, 3, 0.3, 142),
    ('egprs_dl', 0, 1, 0.5, 143), ('egprs_dl', 0, 0, 0.1, 154),
    ('egprs_dl', 0, 2, 0.1, 155), ('egprs_ul', 0, 1, 0.3, 33),
    ('egprs_ul', 0, 0, 0.3, 42), ('egprs_ul', 0, 0, 0.1, 49),
    ('egprs_ul', 0, 0, 0.1, 61), ('egprs_ul', 0, 1, 0.1, 78),
    ('egprs_ul', 0, 0, 0.1, 79), ('egprs_ul', 0, 8, 0.5, 119),
    ('egprs_ul', 0, 0, 0.3, 142), ('egprs_ul', 0, 7, 0.3, 143),
    ('egprs_ul', 0, 0, 0.5, 154), ('egprs_ul', 0, 1, 0.1, 155),
    ('prach', 0, 0, 0.3, 2), ('prach', 1, 0, 0.3, 2), ('prach', 2, 0, 0.3, 2),
    ('gmr1', 0, 2, 0.3, 24), ('gmr1', 0, 3, 0.3, 24), ('gmr1', 0, 5, 0.3, 24),
    ('gmr1', 0, 10, 0.3, 24), ('gmr1', 0, 17, 0.3, 24),
    ('gmr1', 0, 25, 0.3, 24), ('gmr1', 0, 43, 0.5, 24),
    ('gmr1', 1, 1, 0.3, 24), ('gmr1', 1, 2, 0.3, 24), ('gmr1', 1, 4, 0.3, 24),
    ('gmr1', 1, 9, 0.3, 24), ('gmr1', 1, 11, 0.3, 24),
    ('gmr1', 1, 14, 0.3, 24), ('gmr1', 1, 15, 0.3, 24),
    ('gmr1', 1, 17, 0.3, 24), ('gmr1', 1, 24, 0.3, 24),
    ('gmr1', 1, 26, 0.3, 24), ('gmr1', 1, 30, 0.3, 24),
    ('gmr1', 1, 31, 0.3, 24), ('gmr1', 1, 35, 0.3, 24),
    ('gmr1', 1, 36, 0.3, 24), ('gmr1', 1, 40, 0.3, 24),
    ('gmr1', 1, 41, 0.3, 24), ('gmr1', 1, 49, 0.3, 24),
    ('gmr1', 1, 53, 0.3, 24), ('gmr1', 1, 64, 0.3, 24),
    ('gmr1', 1, 66, 0.3, 24), ('gmr1', 1, 70, 0.3, 24),
    ('gmr1', 1, 73, 0.3, 24), ('gmr1', 1, 83, 0.3, 24),
    ('gmr1', 1, 90, 0.3, 24), ('gmr1', 1, 98, 0.3, 24),
    ('gmr1', 1, 114, 0.3, 24), ('gmr1', 1, 122, 0.3, 24),
    ('gmr1', 1, 130, 0.3, 24), ('gmr1', 1, 136, 0.3, 24),
    ('gmr1', 1, 138, 0.3, 24), ('gmr1', 1, 19, 0.5, 24),
    ('gmr1', 1, 24, 0.5, 24), ('gmr1', 1, 29, 0.5, 24),
    ('gmr1', 1, 52, 0.5, 24), ('gmr1', 1, 62, 0.5, 24),
    ('gmr1', 1, 80, 0.5, 24), ('gmr1', 1, 210, 0.5, 24),
]

MALFORMED_SELECTED = [
    ('dl', 1, 0, 0.1, 3), ('dl', 1, 0, 0.5, 3), ('dl', 1, 1, 0.3, 7),
    ('dl', 1, 1, 0.5, 13), ('dl', 1, 3, 0.5, 13), ('dl', 1, 6, 0.3, 23),
    ('dl', 1, 1, 0.5, 23), ('dl', 1, 1, 0.7, 23), ('dl', 1, 2, 0.7, 23),
    ('dl', 2, 1, 0.3, 3), ('dl', 2, 0, 0.1, 5), ('dl', 2, 2, 0.3, 5),
    ('dl', 2, 1, 0.1, 7), ('dl', 2, 2, 0.1, 7), ('dl', 2, 3, 0.1, 7),
    ('dl', 2, 1, 0.3, 7), ('dl', 2, 2, 0.3, 7), ('dl', 2, 3, 0.3, 7),
    ('dl', 2, 0, 0.5, 7), ('dl', 2, 2, 0.1, 9), ('dl', 2, 0, 0.3, 9),
    ('dl', 2, 2, 0.5, 11), ('dl', 2, 1, 0.5, 13), ('dl', 2, 1, 0.5, 15),
    ('dl', 2, 2, 0.3, 23), ('dl', 2, 0, 0.5, 23), ('dl', 3, 0, 0.1, 3),
    ('dl', 3, 0, 0.5, 5), ('dl', 3, 0, 0.3, 7), ('dl', 3, 2, 0.3, 7),
    ('dl', 3, 1, 0.5, 9), ('dl', 3, 3, 0.3, 23), ('dl', 4, 2, 0.5, 3),
    ('dl', 4, 2, 0.5, 7), ('dl', 4, 1, 0.5, 23), ('dl', 5, 1, 0.1, 3),
    ('dl', 5, 1, 0.5, 3), ('dl', 5, 1, 0.1, 5), ('dl', 5, 1, 0.3, 5),
    ('dl', 5, 1, 0.5, 5), ('dl', 5, 3, 0.5, 5), ('dl', 5, 2, 0.5, 7),
    ('dl', 5, 3, 0.5, 7), ('dl', 5, 0, 0.1, 9), ('dl', 5, 5, 0.5, 23),
    ('dl', 6, 0, 0.1, 3), ('dl', 6, 0, 0.1, 23), ('dl', 7, 0, 0.1, 3),
    ('dl', 7, 0, 0.1, 5), ('dl', 7, 1, 0.3, 5), ('dl', 7, 2, 0.3, 5),
    ('dl', 7, 2, 0.5, 5), ('dl', 7, 3, 0.5, 5), ('dl', 7, 0, 0.1, 7),
    ('dl', 7, 3, 0.1, 7), ('dl', 7, 3, 0.3, 7), ('dl', 7, 3, 0.1, 9),
    ('dl', 7, 3, 0.3, 9), ('dl', 7, 2, 0.5, 13), ('dl', 7, 2, 0.5, 15),
    ('dl', 7, 0, 0.3, 23), ('dl', 7, 4, 0.3, 23), ('dl', 7, 7, 0.3, 23),
    ('dl', 7, 3, 0.7, 23), ('dl', 8, 0, 0.1, 3), ('dl', 9, 1, 0.3, 7),
    ('dl', 9, 1, 0.1, 13), ('dl', 9, 2, 0.1, 23), ('dl', 9, 0, 0.5, 23),
    ('dl', 10, 0, 0.1, 5), ('dl', 10, 1, 0.1, 5), ('dl', 10, 2, 0.3, 5),
    ('dl', 10, 1, 0.5, 5), ('dl', 10, 3, 0.1, 7), ('dl', 10, 0, 0.5, 7),
    ('dl', 10, 2, 0.1, 9), ('dl', 10, 1, 0.5, 9), ('dl', 10, 2, 0.5, 9),
    ('dl', 10, 0, 0.1, 23), ('dl', 10, 2, 0.3, 23), ('dl', 10, 4, 0.3, 23),
    ('dl', 10, 6, 0.3, 23), ('dl', 10, 0, 0.5, 23), ('dl', 10, 2, 0.5, 23),
    ('dl', 10, 4, 0.5, 23), ('dl', 10, 6, 0.5, 23), ('dl', 10, 7, 0.5, 23),
    ('dl', 10, 1, 0.7, 23), ('dl', 10, 2, 0.7, 23), ('dl', 11, 2, 0.5, 5),
    ('dl', 12, 0, 0.1, 5), ('dl', 13, 0, 0.1, 3), ('dl', 21, 0, 0.1, 3),
    ('dl', 21, 1, 0.1, 5), ('dl', 21, 1, 0.3, 5), ('dl', 21, 0, 0.5, 9),
    ('dl', 21, 0, 0.1, 11), ('dl', 21, 0, 0.3, 11), ('dl', 21, 1, 0.3, 15),
    ('dl', 21, 3, 0.3, 15), ('dl', 21, 3, 0.3, 23), ('dl', 22, 0, 0.1, 3),
    ('dl', 33, 3, 0.5, 11), ('dl', 33, 7, 0.5, 23), ('dl', 34, 0, 0.5, 3),
    ('dl', 34, 1, 0.5, 3), ('dl', 34, 3, 0.3, 15), ('dl', 34, 1, 0.5, 15),
    ('dl', 34, 0, 0.3, 23), ('dl', 34, 1, 0.5, 23), ('dl', 34, 5, 0.7, 23),
    ('dl', 35, 0, 0.1, 3), ('dl', 35, 0, 0.3, 3), ('dl', 35, 0, 0.1, 23),
    ('dl', 36, 0, 0.1, 3), ('dl', 36, 0, 0.1, 5), ('dl', 49, 0, 0.1, 3),
    ('dl', 49, 0, 0.1, 5), ('dl', 49, 1, 0.1, 5), ('dl', 49, 3, 0.3, 7),
    ('dl', 49, 0, 0.1, 9), ('dl', 49, 3, 0.3, 9), ('dl', 49, 0, 0.1, 11),
    ('dl', 49, 0, 0.1, 13), ('dl', 49, 0, 0.3, 13), ('dl', 49, 2, 0.5, 13),
    ('dl', 49, 0, 0.1, 15), ('dl', 49, 1, 0.3, 15), ('dl', 49, 5, 0.5, 23),
    ('dl', 49, 6, 0.5, 23), ('dl', 49, 1, 0.7, 23), ('dl', 49, 2, 0.7, 23),
    ('dl', 50, 0, 0.1, 5), ('dl', 50, 2, 0.3, 5), ('dl', 50, 0, 0.1, 7),
    ('dl', 50, 1, 0.3, 7), ('dl', 50, 3, 0.3, 7), ('dl', 50, 0, 0.3, 9),
    ('dl', 50, 0, 0.5, 9), ('dl', 50, 3, 0.3, 11), ('dl', 50, 3, 0.5, 11),
    ('dl', 50, 3, 0.3, 23), ('dl', 51, 0, 0.1, 3), ('dl', 51, 0, 0.1, 5),
    ('dl', 51, 1, 0.1, 5), ('dl', 51, 1, 0.3, 7), ('dl', 51, 3, 0.3, 11),
    ('dl', 51, 4, 0.3, 23), ('dl', 51, 1, 0.5, 23), ('dl', 51, 6, 0.5, 23),
    ('dl', 51, 2, 0.7, 23), ('dl', 51, 6, 0.7, 23), ('dl', 51, 7, 0.7, 23),
    ('dl', 54, 3, 0.5, 9), ('dl', 55, 0, 0.1, 3), ('dl', 55, 1, 0.3, 7),
    ('dl', 55, 3, 0.3, 9), ('dl', 55, 3, 0.1, 11), ('dl', 55, 3, 0.1, 13),
    ('dl', 55, 1, 0.7, 23), ('ul', 0, 0, 0.1, 3), ('ul', 0, 0, 0.1, 7),
    ('ul', 0, 2, 0.3, 9), ('ul', 0, 1, 0.5, 9), ('ul', 0, 2, 0.5, 9),
    ('ul', 0, 1, 0.3, 11), ('ul', 0, 1, 0.5, 11), ('ul', 1, 0, 0.5, 7),
    ('ul', 2, 0, 0.1, 3), ('ul', 2, 0, 0.1, 5), ('ul', 2, 0, 0.1, 13),
    ('ul', 2, 1, 0.1, 13), ('ul', 2, 0, 0.1, 15), ('ul', 2, 1, 0.1, 15),
    ('ul', 2, 2, 0.3, 15), ('ul', 2, 1, 0.5, 15), ('ul', 4, 0, 0.1, 7),
    ('ul', 4, 1, 0.1, 7), ('ul', 4, 2, 0.1, 7), ('ul', 4, 3, 0.5, 7),
    ('ul', 4, 1, 0.1, 9), ('ul', 4, 2, 0.1, 9), ('ul', 4, 0, 0.3, 9),
    ('ul', 4, 1, 0.3, 9), ('ul', 4, 1, 0.5, 9), ('ul', 4, 2, 0.5, 9),
    ('ul', 4, 1, 0.1, 11), ('ul', 4, 1, 0.3, 11), ('ul', 4, 1, 0.3, 13),
    ('ul', 4, 3, 0.5, 15), ('ul', 4, 4, 0.1, 23), ('ul', 4, 0, 0.3, 23),
    ('ul', 4, 3, 0.5, 23), ('ul', 4, 2, 0.7, 23), ('ul', 4, 7, 0.7, 23),
    ('ul', 5, 0, 0.1, 3), ('ul', 5, 2, 0.1, 3), ('ul', 5, 1, 0.1, 7),
    ('ul', 5, 3, 0.3, 7), ('ul', 5, 1, 0.3, 9), ('ul', 5, 3, 0.5, 9),
    ('ul', 5, 0, 0.3, 11), ('ul', 5, 1, 0.3, 11), ('ul', 5, 1, 0.5, 13),
    ('ul', 5, 3, 0.5, 13), ('ul', 5, 2, 0.5, 15), ('ul', 5, 0, 0.3, 23),
    ('ul', 5, 1, 0.5, 23), ('ul', 5, 4, 0.5, 23), ('ul', 5, 5, 0.5, 23),
    ('ul', 5, 7, 0.5, 23), ('ul', 5, 0, 0.7, 23), ('ul', 5, 4, 0.7, 23),
    ('ul', 5, 5, 0.7, 23), ('ul', 6, 2, 0.3, 3), ('ul', 7, 0, 0.5, 3),
    ('ul', 7, 1, 0.3, 5), ('ul', 7, 2, 0.3, 5), ('ul', 7, 3, 0.1, 23),
    ('ul', 8, 0, 0.1, 3), ('ul', 8, 3, 0.3, 3), ('ul', 8, 1, 0.3, 5),
    ('ul', 8, 2, 0.3, 5), ('ul', 8, 3, 0.5, 7), ('ul', 8, 3, 0.1, 9),
    ('ul', 8, 1, 0.3, 9), ('ul', 8, 1, 0.1, 13), ('ul', 8, 3, 0.1, 13),
    ('ul', 8, 3, 0.5, 13), ('ul', 8, 2, 0.3, 23), ('ul', 8, 3, 0.3, 23),
    ('ul', 8, 4, 0.3, 23), ('ul', 8, 6, 0.5, 23), ('ul', 9, 0, 0.1, 5),
    ('ul', 10, 2, 0.3, 7), ('ul', 10, 5, 0.5, 23), ('ul', 11, 1, 0.5, 9),
    ('ul', 11, 0, 0.5, 11), ('ul', 11, 2, 0.5, 15), ('ul', 11, 2, 0.1, 23),
    ('ul', 11, 1, 0.5, 23), ('ul', 11, 3, 0.5, 23), ('ul', 11, 5, 0.7, 23),
    ('ul', 11, 7, 0.7, 23), ('ul', 12, 0, 0.1, 3), ('ul', 12, 0, 0.1, 5),
    ('ul', 12, 3, 0.1, 5), ('ul', 12, 3, 0.5, 7), ('ul', 12, 0, 0.3, 9),
    ('ul', 12, 2, 0.5, 11), ('ul', 12, 0, 0.5, 13), ('ul', 12, 7, 0.7, 23),
    ('ul', 13, 0, 0.1, 3), ('ul', 13, 0, 0.7, 23), ('ecdl', 1, 0, 0.3, 3),
    ('ecdl', 1, 3, 0.5, 3), ('ecdl', 1, 0, 0.3, 5), ('ecdl', 1, 1, 0.3, 7),
    ('ecdl', 2, 1, 0.5, 3), ('ecdl', 4, 1, 0.5, 5), ('ecdl', 5, 1, 0.3, 3),
    ('ecdl', 5, 0, 0.5, 3), ('ecdl', 5, 0, 0.3, 5), ('ecdl', 5, 0, 0.5, 7),
    ('ecdl', 5, 2, 0.5, 7), ('ecdl', 5, 3, 0.3, 9), ('ecdl', 5, 5, 0.3, 23),
    ('ecdl', 6, 0, 0.5, 5), ('ecdl', 6, 3, 0.5, 5), ('ecdl', 6, 0, 0.3, 7),
    ('ecdl', 6, 0, 0.5, 9), ('ecdl', 7, 1, 0.3, 9), ('ecdl', 7, 2, 0.5, 9),
    ('ecdl', 17, 1, 0.3, 3), ('ecul', 1, 0, 0.3, 5), ('ecul', 2, 3, 0.5, 3),
    ('ecul', 2, 0, 0.5, 5), ('egprs_ul', 0, 1, 0.3, 27),
    ('egprs_ul', 0, 1, 0.3, 154), ('gmr1', 0, 1, 0.5, 6),
    ('gmr1', 0, 2, 0.5, 24), ('gmr1', 1, 0, 0.5, 6),
]


# ---------------------------------------------------------------- built by hand

def pmr_head(b, union_sel):
    """Packet Measurement Report up to the NC/EXT union (as in
    csn1_var_tarray_overflow.py)."""
    b.put(1, 2); b.put(0, 5); b.put(0, 1); b.put(4, 6)  # MAC header, MESSAGE_TYPE 4
    b.put(0x12345678, 32)                               # TLLI
    b.put(0, 1)                                         # no PSI5_CHANGE_MARK
    b.put(union_sel, 1)


def meas(b, n):
    for i in range(n):
        b.put(i & 0x3f, 6); b.put(0, 1); b.put(0x20, 6)  # FREQUENCY_N, no BSIC, RXLEV_N


def ext_report(n, total=64):
    """EXT Measurement Report with NUMBER_OF_EXT_MEASUREMENTS n
    (EXT_Measurements[] holds 9)."""
    b = Bits(); pmr_head(b, 1)
    b.put(0, 2)              # EXT_REPORTING_TYPE
    b.put(0, 1)              # Exist_I_LEVEL = 0
    b.put(0, 6)              # Slot[0].I_LEVEL
    b.put(0, 7)              # Slot[1..7].Exist = 0
    b.put(n, 5)
    meas(b, n)
    b.put(0, 1)              # no AdditionsR99
    return b.bytes(total, pad='zero')


def nc_report(n, total=23):
    """NC Measurement Report with NUMBER_OF_NC_MEASUREMENTS n
    (NC_Measurements[] holds 6)."""
    b = Bits(); pmr_head(b, 0)
    b.put(0, 1)                     # NC_MODE
    b.put(0x20, 6); b.put(0, 1)     # Serving_Cell_Data RXLEV + fixed 0
    b.put(n, 3)
    meas(b, n)
    b.put(0, 1)
    return b.bytes(total, pad='zero')


def r99_3g(n, total=23):
    """AdditionsR99 3G Measurement Report with N_3G n
    (Measurements_3G[] holds 6; the field is coded as n - 1)."""
    b = Bits(); pmr_head(b, 0)
    b.put(0, 1); b.put(0x20, 6); b.put(0, 1); b.put(0, 3)  # NC report, 0 meas
    b.put(1, 1)              # Exist_AdditionsR99
    b.put(0, 1)              # Exist_Info3G = 0
    b.put(1, 1)              # Exist_MeasurementReport3G
    b.put(n - 1, 3)
    for i in range(n):
        b.put(i, 7); b.put(0x15, 6)
    b.put(0, 1)
    return b.bytes(total, pad='zero')


def additional_ms_rac(content_bits, acc_tech=0, total=23):
    """Additional MS Radio Access Capabilities with a TLLI and one MS RA
    capability value whose Content is the given bit string (its 7 bit
    length is the length of the string)."""
    b = Bits()
    b.put(1, 2).put(0, 5).put(0, 1).put(0x0b, 6)   # MAC header, MESSAGE_TYPE 11
    b.put(1, 1).put(0x0badcafe, 32)                # ID: TLLI
    b.put(acc_tech, 4)                             # MS RA capability value choice
    b.put(len(content_bits), 7).putbits(content_bits)
    b.put(0, 1)                                    # no further value
    return b.bytes(total)


def reproducer_frames():
    """csn1_var_tarray_overflow.py, byte for byte: 31 EXT
    measurements, 7 NC measurements, 8 3G measurements."""
    return [wrap('exp_ul', p) for p in (ext_report(31), nc_report(7), r99_3g(8))]


def boundary_frames():
    """The largest counts the arrays hold (9, 6, 6), which still decode."""
    return [wrap('exp_ul', p) for p in (ext_report(9), nc_report(6), r99_3g(6))]


def hand_frames():
    return [
        # Content that ends right after Exist_A5_bits = 1: { 1 < end > }
        # with only nullable members behind it is stored as { 0 }.
        wrap('ul', additional_ms_rac('101' '1')),
        # Content that ends right after Exist_Multislot_capability = 1,
        # followed by a member that is not nullable: kept as { 1 }, and
        # Multislot_capability then has no bits left.
        wrap('ul', additional_ms_rac('011' '0' '1010' '1')),
        # Content with RF power, A5 bits, ES_IND..VBS and a truncated rest.
        wrap('ul', additional_ms_rac('100' '1' '1010101' '0110' '0' '0' '1')),
    ]


def main_frames():
    return ([rand_frame(*sel) for sel in SELECTED] + hand_frames() +
            boundary_frames() + reproducer_frames())


def malformed_frames():
    frames = [rand_frame(*sel) for sel in MALFORMED_SELECTED]
    # MS RA capability value with the one access technology type (15)
    # that no choice element matches.
    frames.append(wrap('ul', additional_ms_rac('101' '0', acc_tech=15)))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'csn1-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'csn1-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

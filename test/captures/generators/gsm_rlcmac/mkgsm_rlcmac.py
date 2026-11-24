#!/usr/bin/env python3
# Generates test/captures/gsm_rlcmac_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic GSM RLC/MAC coverage captures.

The main capture is a pcapng file with two interfaces:
  0  Ethernet: GSMTAP v2 over UDP port 4729
       - GSM Um PACCH, downlink and uplink (ARFCN uplink flag), carrying
         RLC/MAC control blocks (CS-1)
       - GSM Um PDTCH, carrying GPRS data blocks (CS-1..CS-4, chosen by
         the block length), EGPRS blocks (header types 1-3, MCS-1..9),
         uplink access bursts (8 and 11 bit) and control blocks of other
         coding schemes
  1  Exported PDU (link type 252), dissector names gsm_rlcmac_ul /
     gsm_rlcmac_dl / gsm_ec_rlcmac_ul / gsm_ec_rlcmac_dl: EC-GSM-IoT
     control blocks, which nothing else hands to the RLC/MAC dissector,
     and blocks that reach the RLC/MAC dissector without a coding scheme.

Most RLC/MAC message bodies are pseudo-random bits from a seeded
generator (random.Random) with a given probability of a 1 bit, behind a
correct MAC header and message type; the (kind, message type, seed,
probability, length) tuples in SELECTED and EXTRA were chosen from
thousands of candidates because they decode without errors and between
them add every field, subtree and message type the candidates reach
(greedy set cover); MALFORMED_SELECTED holds one candidate per distinct
expert info. Data blocks with length indicators, the access bursts, the
Packet Handover Command to UTRAN, the Packet Measurement Order with long
frequency lists and the 3G neighbour cell descriptions are built field by
field. Nothing comes from a real network.

Usage: mkgsm_rlcmac.py <output directory>

Writes:
  gsm_rlcmac-coverage.pcapng            messages that decode without errors
  gsm_rlcmac-coverage-malformed.pcapng  error paths (truncated messages,
                                        bad FIXED values, union and choice
                                        indexes, too many elements, too
                                        many length indicators)
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
    if kind == 'exp_dl':
        return exported_pdu('gsm_rlcmac_dl', data)
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
    ]

EXTRA = [('dl', 1, 276, 0.5, 64), ('dl', 3, 1148, 0.5, 64), ('dl', 1, 1996, 0.35, 64),
         ('dl', 3, 150, 0.5, 64), ('dl', 51, 3959, 0.35, 64), ('dl', 21, 33, 0.35, 64)]

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
    ('egprs_ul', 0, 1, 0.3, 154), ]


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


# ---------------------------------------------------------------- data blocks

def overlay(data, bitpos, bits):
    """Replace len(bits) bits of data starting at bit position bitpos."""
    s = format(int.from_bytes(data, 'big'), '0%db' % (len(data) * 8))
    s = s[:bitpos] + bits + s[bitpos + len(bits):]
    return int(s, 2).to_bytes(len(data), 'big')


def data_bits(n):
    return ''.join(format(0xa0 + (i & 0x0f), '08b') for i in range(n))


def gprs_dl(total, lis=(), usf=0, rrbp=0, sp=0, tfi=0, fbi=0, bsn=0, data=0, pt=0):
    """GPRS downlink data block: MAC header, RLC header, LI octets
    (li, m) and data."""
    b = Bits()
    b.put(pt, 2).put(rrbp, 2).put(sp, 1).put(usf, 3)
    b.put(0, 2).put(tfi, 5).put(fbi, 1)
    b.put(bsn, 7).put(0 if lis else 1, 1)
    for i, (li, m) in enumerate(lis):
        b.put(li, 6).put(m, 1).put(1 if i == len(lis) - 1 else 0, 1)
    b.putbits(data_bits(data))
    return b.bytes(total)


def gprs_ul(total, lis=(), cv=15, tfi=0, bsn=0, tlli=None, pfi=None, data=0, pt=0):
    """GPRS uplink data block; tlli / pfi set the TI / PI bits and follow
    the LI octets."""
    b = Bits()
    b.put(pt, 2).put(cv, 4).put(0, 1).put(0, 1)
    b.put(0, 1).put(1 if pfi is not None else 0, 1).put(tfi, 5).put(1 if tlli is not None else 0, 1)
    b.put(bsn, 7).put(0 if lis else 1, 1)
    for i, (li, m) in enumerate(lis):
        b.put(li, 6).put(m, 1).put(1 if i == len(lis) - 1 else 0, 1)
    if tlli is not None:
        b.put(tlli, 32)
    if pfi is not None:
        b.put(pfi, 7).put(1, 1)
    b.putbits(data_bits(data))
    return b.bytes(total)


# (header type, MCS, first data block bit offset (downlink, uplink), data octets)
EGPRS_LAYOUT = {
    27: (3, 1, 31, 31, 22), 33: (3, 2, 31, 31, 28), 42: (3, 3, 31, 31, 37), 49: (3, 4, 31, 31, 44),
    61: (2, 5, 28, 37, 56), 79: (2, 6, 28, 37, 74),
    119: (1, 7, 40, 46, 56), 143: (1, 8, 40, 46, 68), 155: (1, 9, 40, 46, 74),
}


def egprs_block(ul, lis, tlli=None, data=6, fbi=0):
    """Octets of one EGPRS data block as the dissector sees them after it
    has aligned the block: the first octet holds E (bit 0) and FBI / TI
    (bit 1), then the LI octets (li << 1 | e, e is 1 on the last), the
    TLLI (little endian) and data."""
    t = [(0 if lis else 1) | ((1 if tlli is not None else fbi) << 1)]
    for i, li in enumerate(lis):
        t.append((li << 1) | (1 if i == len(lis) - 1 else 0))
    if tlli is not None:
        t += list(tlli.to_bytes(4, 'little'))
    t += [0xa0 + (i & 0x0f) for i in range(data)]
    return t


def overlay_block(data, offset, octets):
    """Write the block octets into the data at bit offset: the GSMTAP
    dissector aligns EGPRS data blocks from a bit stream that runs from the
    least to the most significant bit of each octet."""
    bits = [(data[k] >> j) & 1 for k in range(len(data)) for j in range(8)]
    for t in (0, 1):
        bits[offset + t] = (octets[0] >> t) & 1
    for i, v in enumerate(octets[1:]):
        for t in range(8):
            bits[offset + 2 + 8 * i + t] = (v >> t) & 1
    return bytes(sum(bits[8 * k + j] << j for j in range(8)) for k in range(len(data)))


def egprs_with_blocks(ul, length, seed, p, block1, block2=None):
    """A random EGPRS block of the given length whose data block bits are
    replaced by block1 (and block2 for header type 1)."""
    kind = 'egprs_ul' if ul else 'egprs_dl'
    rng = random.Random('%s/%d/%d/%s/%d' % (kind, 0, seed, p, length))
    data = int(rand_bits(rng, length * 8, p), 2).to_bytes(length, 'big')
    htype, mcs, dl_off, ul_off, dbl = EGPRS_LAYOUT[length]
    off = ul_off if ul else dl_off
    data = overlay_block(data, off, block1)
    if htype == 1 and block2 is not None:
        data = overlay_block(data, off + dbl * 8 + 2, block2)
    return wrap(kind, data)


# an RRC HandoverToUTRANCommand that the RRC dissector decodes without an
# error (24 octets; found by random search, most others are refused)
RRC_CONTAINER = bytes.fromhex('5d0c6359b2e392440880ba8ce4b084f028ad2d38e14184e7')


def ps_handover_to_utran(container, tfi=3, container_id=1):
    """Packet Handover Command with the UTRAN payload: an RRC
    HandoverToUTRANCommand container of the given octets."""
    b = Bits()
    b.put(1, 2).put(0, 2).put(0, 1).put(0, 3)    # MAC header
    b.put(0x15, 6).put(0, 2)       # MESSAGE_TYPE 21, PAGE_MODE
    b.put(0, 1)                    # fixed 0
    b.put(0, 1).put(tfi, 5)        # Global TFI: uplink
    b.put(container_id, 2)
    b.put(1, 2)                    # union: UTRAN payload
    b.put(len(container), 8)
    b.putbits(''.join(format(c, '08b') for c in container))
    return b.bytes(max(23, (len(b) + 7) // 8))


# (uplink, length, block 1 LI values, block 2 LI values, TLLI)
EGPRS_SPECS = [
    (False, 33, [126], None, None),
    (False, 61, [126, 127], None, None),
    (False, 119, [127], [10, 126, 127], None),
    (False, 143, [0, 126], [127, 4], None),
    (True, 33, [126], None, 0x0badcafe),
    (True, 79, [126, 127], None, None),
    (True, 119, [127], [10, 126, 127], None),
]
# seed and probability of the random block that carries each of them
# (the header must be coded for the MCS that the block length implies)
EGPRS_SEEDS = {0: (3, 0.3), 1: (1, 0.1), 2: (2, 0.3), 3: (4, 0.5), 4: (1, 0.3),
               5: (1, 0.1), 6: (8, 0.5)}


def egprs_frame(n):
    ul, length, lis1, lis2, tlli = EGPRS_SPECS[n]
    seed, p = EGPRS_SEEDS.get(n, (0, 0.3))
    return egprs_with_blocks(ul, length, seed, p, egprs_block(ul, lis1, tlli=tlli),
                             egprs_block(ul, lis2, data=8) if lis2 else None)


def pmo_freq_diff(nr_freq, diff_len_code, total=40):
    """Reproducer of "GSM RLC/MAC: Set FREQ_DIFF_LENGTH for all 32
    frequencies": a downlink Packet Measurement Order whose NC frequency
    list holds an Additional Frequency List of nr_freq (up to 31)
    frequencies of diff_len_code + 1 bit each. The callback copied
    FREQ_DIFF_LENGTH into the first 16 array entries only, so the later
    entries were read with a 0 bit FREQUENCY_DIFF and the rest of the
    message was misaligned (the Info column and the BSIC / cell selection
    fields of the entries after the 16th were wrong)."""
    b = Bits()
    b.put(1, 2).put(0, 2).put(0, 1).put(0, 3)       # MAC header, payload type 1
    b.put(3, 6).put(0, 2)                            # PMO, PAGE_MODE
    b.put(0, 1).put(0, 1).put(0, 5)                  # ID: Global TFI, uplink TFI 0
    b.put(0, 3).put(0, 3)                            # PMO_INDEX, PMO_COUNT
    b.put(1, 1)                                      # NC_Measurement_Parameters
    b.put(0, 2).put(0, 1).put(1, 1)                  # NCO, no NC periods, frequency list
    b.put(0, 1)                                      # no removed frequencies
    b.put(1, 1)                                      # one Add_Frequency_list follows
    b.put(1, 10).put(0, 6).put(0, 1)                 # START_FREQUENCY, BSIC, no cell selection
    b.put(nr_freq, 5).put(diff_len_code, 3)          # NR_OF_FREQUENCIES, FREQ_DIFF_LENGTH
    for i in range(nr_freq):
        b.put((i + 1) & ((2 << diff_len_code) - 1), diff_len_code + 1).put(63 - i, 6).put(0, 1)
    b.put(0, 1)                                      # end of the Add_Frequency list
    b.put(0, 1).put(0, 1)                            # no EXT parameters, no AdditionsR98
    return b.bytes(total)


# The first 145 bits of the downlink Packet Measurement Order
# rand_frame('dl', 3, 150, 0.5, 64): they reach the LU mode only
# capable cell list of PMO_AdditionsR5 (found by random search); the next
# bits are NR_OF_FREQUENCIES (5) and FREQ_DIFF_LENGTH (3) of the first
# Add_lu_ModeOnlyFrequencyList.
LU_PREFIX = format(int('740f114c45fb4130cb5e9f234e1d761d64ea', 16), '0144b') + '0'


def pmo_lu_freq_diff(nr_freq, diff_len_code, total=64):
    """Reproducer for the LU mode only frequency list of the same fix:
    an Add_lu_ModeOnlyFrequencyList of nr_freq (up to 31) entries."""
    b = Bits().putbits(LU_PREFIX)
    b.put(nr_freq, 5).put(diff_len_code, 3)
    for i in range(nr_freq):
        # unlike the NC list the field is not coded with an offset of 1
        b.put((i + 1) & ((1 << diff_len_code) - 1), diff_len_code).put(63 - i, 6).put(0, 1)
    b.put(0, 1)               # end of the list
    b.put(0, 1).put(0, 1)     # no GPRS_AdditionalMeasurementParams3G, no AdditionsR6
    return b.bytes(total)


# The first 108 bits of rand_frame('dl', 1, 276, 0.5, 64), a Packet Cell
# Change Order whose 3G neighbour cell description has a UTRAN TDD
# description: the next bits are NrOfCells of its first neighbour cells.
TDD_PREFIX = format(int('740778df23f33311efcd8f5017', 16), '0104b') + '0000'


def pcco_tdd_zero_window(nr_cells, total=64):
    """The TDD cell information is a sequence of windows of 10, 9, 9, 8, ...
    bits; a window of 0 ends it early."""
    b = Bits().putbits(TDD_PREFIX)
    b.put(nr_cells, 5)
    b.put(0, 10)              # first window 0: no cells in the information
    return b.bytes(total, pad='zero')


def data_block_frames():
    f = []
    # GPRS downlink: LI 63 (filler only), LI 63 behind a length, S/P and FBI
    f.append(wrap('dldata', gprs_dl(23, lis=[(63, 0)], usf=3, rrbp=1, sp=1, tfi=9, fbi=1, bsn=11)))
    f.append(wrap('dldata', gprs_dl(34, lis=[(4, 1), (63, 0)], usf=1, tfi=2, bsn=12, data=4)))
    f.append(wrap('dldata', gprs_dl(54, lis=[(3, 1), (0, 0)], usf=5, tfi=7, bsn=13, data=3)))
    f.append(wrap('dldata', gprs_dl(40, lis=[(2, 1), (2, 1), (2, 1), (2, 1), (2, 1), (1, 0)],
                                    usf=2, tfi=6, bsn=14, data=11)))
    # GPRS uplink: TLLI and PFI behind the LI octets, LI 63, plain
    f.append(wrap('uldata', gprs_ul(23, lis=[(3, 1), (2, 0)], tfi=4, bsn=5, tlli=0x0badcafe, pfi=0x2a, data=10)))
    f.append(wrap('uldata', gprs_ul(40, lis=[(63, 0)], cv=3, tfi=1, bsn=6, tlli=0x12345678)))
    f.append(wrap('uldata', gprs_ul(54, tfi=12, bsn=100, cv=0, pfi=5, data=44)))
    # EGPRS: LI 126 and 127 first / not first, E bit of the LI octet set / clear
    for n in range(len(EGPRS_SPECS)):
        f.append(egprs_frame(n))
    return f


def other_block_frames():
    f = []
    # access bursts: the 11 bit Packet Control Acknowledgement with the
    # TN/RRBP, and one that no format matches
    f.append(wrap('prach', rand_prach(3, 0.3)[0:2], 3))
    f.append(wrap('prach', bytes([0xa5]), 4))
    # control blocks of the wrong coding scheme (CS-2/CS-3/CS-4 length)
    f.append(wrap('dldata', gprs_dl(34, pt=1, usf=1)))
    f.append(wrap('dldata', gprs_dl(40, pt=1, usf=2)))
    f.append(wrap('uldata', gprs_ul(34, pt=1)))
    # TDD neighbour cell information that ends in a window of 0
    f.append(wrap('dl', pcco_tdd_zero_window(4), 1))
    f.append(wrap('dl', pcco_tdd_zero_window(11), 1))
    # the reproducer: 20 and 31 frequencies in the Additional Frequency List
    f.append(wrap('dl', pmo_freq_diff(20, 2), 3))
    f.append(wrap('dl', pmo_freq_diff(31, 3, 64), 3))
    f.append(wrap('dl', pmo_freq_diff(16, 1), 3))
    f.append(wrap('dl', pmo_lu_freq_diff(20, 2), 3))
    f.append(wrap('dl', pmo_lu_freq_diff(31, 3), 3))
    # Packet Handover Command to UTRAN: the RRC container (HandoverToUTRANCommand)
    f.append(wrap('dl', ps_handover_to_utran(RRC_CONTAINER, tfi=7, container_id=3), 0x15))
    # reserved payload type 3, downlink and uplink
    f.append(wrap('dldata', gprs_dl(23, pt=3, usf=5, rrbp=2, sp=1)))
    f.append(wrap('uldata', gprs_ul(23, pt=3)))
    return f


def rand_prach(mt, p):
    rng = random.Random('prach/%d/%s' % (mt, p))
    b = Bits().putbits(['011111', '000', '111111001', '110111'][mt])
    b.putbits(rand_bits(rng, 16 - len(b), p))
    return b.bytes(2)


def exported_frames():
    f = []
    # no coding scheme is known: CS-1; a data block shorter than a CS-1
    # block, one longer (spare octets), a two octet uplink block is an
    # access burst
    f.append(wrap('exp_dl', gprs_dl(10, lis=[(2, 1), (1, 0)], tfi=3, bsn=9, data=5)))
    f.append(wrap('exp_dl', gprs_dl(30, lis=[(8, 0)], tfi=3, bsn=10, data=20)))
    f.append(wrap('exp_ul', rand_prach(0, 0.3)))
    f.append(wrap('exp_ul', gprs_ul(23, tfi=2, bsn=3, data=18)))
    # control blocks with message types that the dissector does not know
    f.append(wrap('exp_dl', Bits().put(1, 2).put(0, 2).put(0, 1).put(1, 3).put(0x2e, 6).bytes(23)))
    f.append(wrap('exp_ul', Bits().put(1, 2).put(0, 5).put(0, 1).put(0x2e, 6).bytes(23)))
    f.append(wrap('ecdl', Bits().put(0, 2).put(0, 3).put(0x1f, 5).bytes(23)))
    f.append(wrap('ecul', Bits().put(0x1f, 5).bytes(23)))
    return f


def main_frames():
    return ([rand_frame(*sel) for sel in SELECTED + EXTRA] + hand_frames() +
            boundary_frames() + data_block_frames() + other_block_frames() +
            exported_frames())


def malformed_frames():
    frames = [rand_frame(*sel) for sel in MALFORMED_SELECTED]
    # MS RA capability value with the one access technology type (15)
    # that no choice element matches.
    frames.append(wrap('ul', additional_ms_rac('101' '0', acc_tech=15)))
    # more length indicators than the dissector keeps (7 downlink, 10 uplink)
    frames.append(wrap('dldata', gprs_dl(54, lis=[(1, 1)] * 7 + [(1, 0)], tfi=1, bsn=1, data=20)))
    frames.append(wrap('uldata', gprs_ul(54, lis=[(1, 1)] * 10 + [(1, 0)], tfi=1, bsn=1, data=20)))
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'gsm_rlcmac-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'gsm_rlcmac-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

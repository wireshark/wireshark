# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers for the SBAS L1 / L5 coverage generators: EMS file records with
CRC-24Q checksums built bit by bit.  EMS (EGNOS Message Server) is a text file
format read by the wiretap EMS reader; each record is one SBAS message."""
import random

def crc24q(bits):
    """CRC-24Q (polynomial 0x1864CFB, initial value 0) of a bit string."""
    crc = 0
    for b in bits:
        crc ^= int(b) << 23
        if crc & 0x800000:
            crc = ((crc << 1) ^ 0x1864CFB) & 0xffffff
        else:
            crc = (crc << 1) & 0xffffff
    return crc

def sbas(head_bits, data_bits, badcrc=False):
    """226 bits of message (header + data) + 24 bit CRC + 6 pad bits, as hex."""
    msg = head_bits + data_bits
    assert len(msg) == 226, len(msg)
    c = crc24q(msg) ^ (0x5a5a5a if badcrc else 0)
    return int(msg + format(c, '024b') + '000000', 2).to_bytes(32, 'big').hex().upper()

def l1(mt, data_bits, preamble=0x53, badcrc=False):
    assert len(data_bits) == 212
    return sbas(format(preamble, '08b') + format(mt, '06b'), data_bits, badcrc)

def l5(mt, data_bits, preamble=0x5, badcrc=False):
    assert len(data_bits) == 216
    return sbas(format(preamble, '04b') + format(mt, '06b'), data_bits, badcrc)

def rnd_bits(rng, n):
    return ''.join(rng.choice('01') for _ in range(n))

def put(bits, off, field):
    """Replace len(field) bits at offset off."""
    return bits[:off] + field + bits[off + len(field):]

def stamp(prn, y, mo, d, h, mi, s):
    return '%03u %02u %02u %02u %02u %02u %02u' % (prn, y, mo, d, h, mi, s)

def l1_line(prn, t, mt, hexmsg):
    # "%2u" MT: a one digit MT is followed directly by a space
    return '%s %u %s' % (stamp(prn, *t), mt, hexmsg)

def l5_line(prn, t, frac, flag, nbits, mt, hexmsg):
    return '%s.%06u %s %04X %02u %s' % (stamp(prn, *t), frac, flag, nbits, mt, hexmsg)

def write_lines(path, lines):
    with open(path, 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

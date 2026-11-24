#!/usr/bin/env python3
# Generates test/captures/ems_coverage.ems.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic files that exercise the EGNOS Message Server (EMS)
dissector (packet-egnos-ems.c, protocol "ems").

EMS is a text file format (ESA-EGN-EPO-ICD-0031): one SBAS message per
line. wiretap/ems.c recognises the file heuristically and hands each line
to the "ems" dissector (WTAP_ENCAP_EMS), which shows the PRN, date and
time, and then either an L1 record (MT and 64 hex characters) or an L5 /
non-standard record (seconds with fraction, service flag, number of bits
in hex, MT, hex message). The decoded message bytes go to the
"ems.svc_flag" table: "L1" to SBAS L1, "L5" to SBAS L5, anything else to
the data dissector. Every line is generated; the SBAS messages are
built bit by bit with valid preambles and CRC-24Q checksums (a plain CRC,
no cryptography). No real EGNOS data is used.

Usage: mkems.py <output directory>

Writes:
  ems-coverage.ems            L1 records with one and two digit MTs
                              (MT 0, 1, 9, 63), L5 records (MT 0, 31, 63),
                              non-standard records with 16, 9 and 0 bits
  ems-coverage-malformed.ems  an L5 record whose hex message is shorter
                              than its bit count (the exception that
                              leaked the byte array before the fix), a
                              negative bit count ("-008"), a record with
                              characters that are not hex
"""

import os
import sys


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


def sbas(head_bits, data_bits):
    """226 bits of message (header + data) + 24 bit CRC + 6 pad bits."""
    msg = head_bits + data_bits
    assert len(msg) == 226, len(msg)
    bits = msg + format(crc24q(msg), '024b') + '000000'
    return int(bits, 2).to_bytes(32, 'big').hex().upper()


def l1(mt, data_bits=None, preamble=0x53):
    if data_bits is None:
        data_bits = '0' * 212
    return sbas(format(preamble, '08b') + format(mt, '06b'), data_bits)


def l5(mt, data_bits=None, preamble=0x5):
    if data_bits is None:
        data_bits = '0' * 216
    return sbas(format(preamble, '04b') + format(mt, '06b'), data_bits)


def stamp(prn, y, mo, d, h, mi, s):
    return '%03u %02u %02u %02u %02u %02u %02u' % (prn, y, mo, d, h, mi, s)


def l1_line(prn, t, mt, hexmsg):
    # "%2u" MT: a one digit MT is followed directly by a space
    return '%s %u %s' % (stamp(prn, *t), mt, hexmsg)


def l5_line(prn, t, frac, flag, nbits, mt, hexmsg):
    return '%s.%06u %s %04X %02u %s' % (stamp(prn, *t), frac, flag, nbits, mt, hexmsg)


def main_lines():
    t = (24, 3, 15, 12, 0)
    out = []
    # 1-4: L1 records: MT 63 (null), MT 1 (PRN mask, one and two digit
    # MT columns), MT 0 ("do not use", a warning), MT 9 with the second
    # preamble
    mask = '1' * 32 + '0' * 178 + '01'      # PRN mask bits + IODP
    out.append(l1_line(123, t + (0,), 63, l1(63)))
    out.append(l1_line(123, t + (1,), 1, l1(1, mask)))
    out.append(l1_line(136, t + (2,), 0, l1(0)))
    out.append(l1_line(136, t + (3,), 9, l1(9, '01' * 106, preamble=0x9a)))
    # 5-7: L5 records (250 bits): MT 63, MT 31, MT 0
    out.append(l5_line(123, t + (4,), 0, 'L5', 250, 63, l5(63)))
    out.append(l5_line(126, t + (5,), 500000, 'L5', 250, 31, l5(31, '10' * 108)))
    out.append(l5_line(126, t + (6,), 999999, 'L5', 250, 0, l5(0, preamble=0xc)))
    # 8: an L1 record in the L5 layout ("L1" flag, 250 bits)
    out.append(l5_line(148, t + (7,), 250000, 'L1', 250, 63, l1(63, preamble=0xc6)))
    # 9-11: non-standard service flags: 16 bits, 9 bits (rounded up to
    # two octets), no bits at all
    out.append(l5_line(158, t + (8,), 1, 'XX', 16, 1, 'A5C3'))
    out.append(l5_line(120, t + (9,), 2, 'E5', 9, 62, '8001'))
    out.append(l5_line(120, (25, 12, 31, 23, 59, 59), 3, 'ZZ', 0, 2, ''))
    return out


def malformed_lines():
    t = (24, 3, 15, 13, 0)
    return [
        # 1: 256 bits announced, 10 hex characters present: the NOF item
        # throws after the byte array was allocated (leaked before
        # "EMS: Free the NOF byte array when an exception is thrown")
        l5_line(123, t + (0,), 0, "L5", 256, 1, '0123456789'),
        # 2: a negative bit count, accepted by the wiretap reader's %x
        # but not by the dissector (error expert info)
        '%s.000000 L5 -008 63 %s' % (stamp(123, *t, 1), '00' * 8),
        # 3: hex message with characters that are not hex digits
        l5_line(123, t + (2,), 0, 'L5', 32, 1, 'GHIJKLMN'),
        # 4: L1 record whose message is not hex
        l1_line(123, t + (3,), 63, 'X' * 64),
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    with open(os.path.join(out, 'ems-coverage.ems'), 'w', newline='\n') as f:
        f.write('\n'.join(main_lines()) + '\n')
    with open(os.path.join(out, 'ems-coverage-malformed.ems'), 'w', newline='\n') as f:
        f.write('\n'.join(malformed_lines()) + '\n')


if __name__ == '__main__':
    main()

#!/usr/bin/python3
# Generates test/captures/midi_sysex_digitech_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the DigiTech X MIDI SysEx coverage captures.
Usage: mkmidi_sysex_digitech.py <outdir> [-v]
Writes midi-sysex_digitech-coverage.pcap and
midi-sysex_digitech-coverage-malformed.pcap (Exported PDU naming the
"midi_sysex" dissector, link type 252; the SysEx dissector hands manufacturer
00 00 10 (DOD Electronics) to the DigiTech dissector). Synthetic."""
import struct
import sys
import os

P = struct.pack

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return P('>HH', 12, len(n) + pad) + n + b'\0' * pad + P('>HH', 0, 0) + payload

def write_pcap(fn, pkts):
    with open(fn, 'wb') as f:
        f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, p in enumerate(pkts):
            f.write(P('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def pack(data):
    """7-bit pack: an octet with the high bits precedes each 7 octets."""
    out = bytearray()
    for i in range(0, len(data), 7):
        chunk = data[i:i + 7]
        msb = 0
        for j, b in enumerate(chunk):
            msb |= (b >> 7) << (6 - j)
        out.append(msb)
        out.extend(b & 0x7F for b in chunk)
    return bytes(out)

def msg(proc, data=b'', device=0x7F, family=0x5E, product=0x05, bad_checksum=False,
        raw=None, checksum=True):
    packed = pack(data) if raw is None else raw
    body = bytes([device, family, product, proc]) + packed
    c = 0x10
    for b in body:
        c ^= b
    if bad_checksum:
        c ^= 0x55
    tail = bytes([c]) if checksum else b''
    return exp_pdu('midi_sysex', b'\xF0\x00\x00\x10' + body + tail + b'\xF7')

def param(pid, pos, value):
    """A parameter: ID, position, then a value (int < 0x80, bytes for a
    multibyte value with one-octet or two-octet count)."""
    b = P('>HB', pid, pos)
    if isinstance(value, int):
        return b + bytes([value])
    if len(value) < 0x7F:
        return b + bytes([0x80 | len(value)]) + value
    return b + b'\x80' + P('>H', len(value)) + value

def build():
    main = []
    add = main.append
    # WhoAmI: request, replies (version 1 with OS mode, other families,
    # version 0 with three octets, extra octets), different device IDs
    add(msg(0x01, bytes([0x7F, 0x5E, 0x05])))
    add(msg(0x02, bytes([0x00, 0x5E, 0x05, 0x00])))                    # RP500, normal OS mode
    add(msg(0x02, bytes([0x01, 0x5E, 0x03, 0x01]), device=0x01))       # RP350, flash update
    add(msg(0x02, bytes([0x00, 0x5C, 0x07, 0x00]), family=0x5C))       # X floor, unknown product
    add(msg(0x02, bytes([0x00, 0x5F, 0x01]), family=0x5F, product=0x01))   # version 0 reply (three octets)
    add(msg(0x02, bytes([0x00, 0x5E, 0x05, 0x00, 0x42, 0x43])))        # extra octets (undecoded)
    add(msg(0x01, bytes([0x00, 0x7F, 0x7F]), family=0x7F, product=0x01))   # family All
    add(msg(0x01, bytes([0x00, 0x60, 0x02]), family=0x60, product=0x02))   # Vocalist
    add(msg(0x01, bytes([0x00, 0x5D, 0x02]), family=0x5D, product=0x02))   # JamMan
    # preset names
    for bank in (0, 1, 2, 3, 4, 5, 6, 7):
        add(msg(0x21, bytes([bank])))
    add(msg(0x22, bytes([0, 3]) + b'Clean\0Crunch\0Lead\0'))
    for n in range(1, 17):                                              # names of 1-16 octets (data sizes around the 7 octet groups)
        add(msg(0x22, bytes([1, 1]) + b'n' * n + b'\0'))
    add(msg(0x22, bytes([2, 0])))                                      # no names
    add(msg(0x2A, bytes([1, 12])))                                     # request preset
    add(msg(0x2B, bytes([1, 12]) + b'My Preset\0' + bytes([1, 6])))    # preset start
    add(msg(0x2B, bytes([0, 0]) + b'\0' + bytes([0, 0])))              # empty name
    # preset parameters in every position (position names and ID tables)
    pos = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 33, 132, 99]
    ids = {0: 1, 2: 65, 3: 129, 4: 193, 5: 257, 6: 321, 7: 385, 8: 449, 9: 513, 10: 577, 11: 641,
           12: 705, 13: 2562, 14: 1793, 15: 1857, 16: 1921, 17: 2626, 18: 2626, 19: 5, 20: 8195,
           21: 6, 22: 7, 23: 8, 24: 3203, 25: 3212, 26: 9, 33: 3649, 132: 10, 99: 4000}
    params = b''.join(param(ids[p], p, 5 + (p % 100)) for p in pos)
    add(msg(0x2D, P('>H', len(pos)) + params))
    # parameter encodings: single octet, one-octet count, two-octet count
    add(msg(0x2D, P('>H', 4) + param(1862, 15, 0x7F) + param(1863, 15, b'\x01\x02\x03')
            + param(1864, 15, bytes(range(200, 255)) * 3) + param(1865, 15, 0)))
    add(msg(0x41, param(1860, 15, 40)))                                # parameter value
    add(msg(0x41, param(1860, 16, b'\xAA\xBB')))
    add(msg(0x41, param(65535, 33, 1)))                                # unknown ID
    # ID tables of every position, a different known ID each (names)
    for p, i in ((2, 65), (3, 129), (4, 193), (5, 257), (6, 321), (7, 385), (8, 449),
                 (13, 2562), (14, 1793), (16, 1921), (24, 3207), (25, 3207), (33, 3649)):
        add(msg(0x41, param(i, p, 9)))
    # ACK and NACK
    add(msg(0x7E, bytes([0x41])))
    add(msg(0x7F, bytes([0x2B])))
    # procedures without a decoder (an undecoded warning when there is data)
    add(msg(0x08))
    add(msg(0x09, bytes([1, 2, 3])))
    add(msg(0x70, b''))
    add(msg(0x5E, b'', raw=b''))                                       # no data octets
    marks = len(main)

    mal = []
    madd = mal.append
    # bad checksums (warning)
    madd(msg(0x22, bytes([1, 5]) + b'One\0Two\0'))                    # count larger than the names
    madd(msg(0x01, bytes([0x7F, 0x5E, 0x05]), bad_checksum=True))
    madd(msg(0x7E, bytes([0x41]), bad_checksum=True))
    # a message with no procedure data (shorter than the header)
    madd(exp_pdu('midi_sysex', b'\xF0\x00\x00\x10\x7F\x5E\x05\x01\xF7'))
    madd(exp_pdu('midi_sysex', b'\xF0\x00\x00\x10\x7F\x5E\x05\xF7'))
    # truncated data: the preset names count is larger than the data, a name
    # without a terminator, a preset start without the rest, truncated
    # parameters
    madd(msg(0x22, bytes([0, 2]) + b'abc'))
    madd(msg(0x2B, bytes([0, 1]) + b'no-terminator'))
    madd(msg(0x2B, bytes([0, 1])))
    madd(msg(0x2D, P('>H', 5) + param(1860, 15, 3)))
    madd(msg(0x2D, P('>H', 1) + P('>HB', 1860, 15)))
    madd(msg(0x41, P('>H', 1860)))
    madd(msg(0x41, param(1860, 15, b'\x01\x02')[:-1]))                 # multibyte data cut short
    madd(msg(0x41, P('>HB', 1860, 15) + b'\x80\x00\x40'))              # two-octet count, data missing
    madd(msg(0x01, b''))
    madd(msg(0x02, b''))
    madd(msg(0x02, bytes([0x00])))
    madd(msg(0x21, b''))
    madd(msg(0x2A, bytes([1])))
    madd(msg(0x7E, b''))
    # DigiTech header cut short
    madd(exp_pdu('midi_sysex', b'\xF0\x00\x00\x10\x7F\x5E\xF7'))
    madd(exp_pdu('midi_sysex', b'\xF0\x00\x00\x10\xF7'))
    # reproducer of the version tracking bug (not fixed on the branch): the
    # WhoAmI reply with three data octets means "version 0", but the next
    # message is decoded as version 1 (a position octet that is not there)
    madd(msg(0x02, bytes([0x00, 0x5E, 0x05])))
    madd(msg(0x41, P('>HB', 10, 5)))
    return main, mal, marks

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, marks = build()
    write_pcap(os.path.join(out, 'midi-sysex_digitech-coverage.pcap'), main)
    write_pcap(os.path.join(out, 'midi-sysex_digitech-coverage-malformed.pcap'), mal)
    if '-v' in sys.argv:
        print('main frames %d; malformed %d' % (len(main), len(mal)))

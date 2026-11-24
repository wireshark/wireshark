#!/usr/bin/env python3
# Generates test/captures/cimd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CIMD (Computer Interface
to Message Distribution, version 2) dissector (packet-cimd.c).

CIMD is a text protocol over TCP: STX, a two digit operation code, ':',
a three digit packet number, then TAB-separated "ccc:value" parameters,
an optional two hex digit checksum after the last TAB, and ETX. The
dissector is found by a TCP heuristic (enabled by default) and can be
chosen with Decode As on any TCP port. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkcimd.py <output directory>

Writes:
  cimd-coverage.pcap            every operation, every parameter, every
                                DCS coding group, user data with combining
                                sequences, checksum present/absent/invalid,
                                the reproducer cimd_param_past_etx, an
                                unknown operation (Decode As only) and TCP
                                payloads the heuristic rejects
  cimd-coverage-malformed.pcap  parameters shorter than their code, a
                                message that ends right after the header
"""

import os
import struct
import sys

IP_C = bytes((192, 0, 2, 1))
IP_S = bytes((192, 0, 2, 2))
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
PORT = 9971          # not registered: found by the heuristic
PORT_DA = 9972       # unknown operation code: Decode As only
PORT_REJ = 9973      # payloads the heuristic rejects


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident, 0x4000,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + tcp + payload


class Conn:
    """One TCP connection with a three way handshake and a close, so
    sequence numbers are tracked from the start."""

    def __init__(self, frames, cport, sport=PORT):
        self.f = frames
        self.cport = cport
        self.sport = sport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, self.sport, data, self.cseq,
                           self.sseq if flags != 0x02 else 0, IP_C, IP_S, flags,
                           ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(self.sport, self.cport, data, self.sseq, self.cseq, IP_S, IP_C,
                           flags, ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


def cimd(oc, pn, params=(), cc=True, raw_tail=None):
    """A CIMD message. params: (code, value) pairs, value bytes or str.
    cc=True appends the correct checksum, an int appends that (wrong)
    checksum, False none. raw_tail replaces the checksum and ETX."""
    m = b'\x02' + b'%02d:%03d\t' % (oc, pn)
    for code, val in params:
        if isinstance(val, str):
            val = val.encode('latin-1')
        if isinstance(code, int):
            code = b'%03d' % code
        m += code + b':' + val + b'\t'
    if raw_tail is not None:
        return m + raw_tail
    if cc is True:
        m += b'%02X' % (sum(m) & 0xff)
    elif cc is not False:
        m += b'%02X' % cc
    return m + b'\x03'


# User data (parameter 033): Latin-1 text with "_XX" combining sequences
# for GSM characters that have no Latin-1 equivalent.
UD_ALL_COMBINING = ''.join(('_Oa', '_L-', '_Y-', '_e`', "_e'", '_u`', '_i`', '_o`', '_C,',
                            '_O/', '_o/', '_A*', '_a*', '_gd', '_--', '_gf', '_gg', '_gl',
                            '_go', '_gp', '_gi', '_gs', '_gt', '_gx', '_XX', '_AE', '_ae',
                            '_ss', "_E'", '_qq', '_ox', '_!!', '_A"', '_O"', '_N~', '_U"',
                            '_so', '_??', '_a"', '_o"', '_n~', '_n"', '_a`'))


def main_frames():
    F = []
    c = Conn(F, 40001)
    # Session: login, every operation and its response, logout
    c.add(True, cimd(1, 1, [(10, 'user01'), (11, 'secret'), (12, '5'), (19, '8')], cc=False))
    c.add(False, cimd(51, 1, [(19, '8')]))
    c.add(True, cimd(3, 3, [
        (21, '+358401234567'), (23, '12345'), (27, 'ACME'), (30, '0'),
        (32, '050003A10201'), (33, 'Hello world @$'), (44, '1'), (50, '167'),
        (51, '261231235959'), (52, '0'), (53, '10'), (54, '261231120000'), (55, '1'),
        (56, '62'), (58, '1'), (64, '3'), (65, '7'), (67, '1')]))
    c.add(False, cimd(53, 3, [(21, '+358401234567'), (60, '261030120000')]))
    c.add(True, cimd(4, 5, [(21, '+358401234567'), (60, '261030120000')]))
    c.add(False, cimd(54, 5, [(21, '+358401234567'), (60, '261030120000'), (61, '4'),
                              (62, '0')]))
    c.add(True, cimd(5, 7, [(68, '2')]))
    c.add(False, cimd(55, 7, [(66, '3')]))
    c.add(True, cimd(6, 9, [(59, '2'), (21, '+358401234567'), (60, '261030120000')]))
    c.add(False, cimd(56, 9))
    c.add(True, cimd(8, 11, [(11, 'secret'), (12, '3')]))
    c.add(False, cimd(58, 11))
    c.add(True, cimd(9, 13, [(500, '501')]))
    c.add(False, cimd(59, 13, [(501, '261030120001')]))
    c.add(True, cimd(40, 15))
    c.add(False, cimd(90, 15))
    # SC to application: delivery and status report
    c.add(False, cimd(20, 2, [
        (21, '12345'), (23, '+358409876543'), (26, '244051234567890'), (28, '+358405550000'),
        (60, '261030120002'), (69, '+358405550001'), (52, '0'), (30, '8'),
        (34, '00480065006C006C006F')]))
    c.add(True, cimd(70, 2))
    c.add(False, cimd(23, 4, [(21, '+358401234567'), (60, '261030120000'), (61, '3'),
                              (62, '13'), (63, '261030120005')]))
    c.add(True, cimd(73, 4))
    # Errors
    c.add(True, cimd(3, 17, [(21, '')]))
    c.add(False, cimd(98, 17, [(900, '300'), (901, 'Incorrect destination address')]))
    c.add(True, cimd(1, 19, [(10, 'user01'), (11, 'wrong')]))
    c.add(False, cimd(99, 19, [(900, '2')]))
    # Status codes and status error codes
    c.add(False, cimd(23, 6, [(61, '6'), (62, '9')]))
    c.add(True, cimd(73, 6))
    # Data coding schemes: group 0 without and with a message class
    # (0x00, 0x11), compressed with class 2 (0x26), group 8 (reserved),
    # message waiting groups 0xC8, 0xD9, 0xEA, and data coding 0xF5, 0xF0
    pn = 21
    for dcs in (0x00, 0x11, 0x26, 0x80, 0xC8, 0xD9, 0xEA, 0xF5, 0xF0):
        c.add(True, cimd(3, pn, [(21, '12345'), (30, str(dcs)), (33, 'dcs %d' % dcs)]))
        c.add(False, cimd(53, pn, [(21, '12345'), (60, '261030120010')]))
        pn += 2
    # User data: every combining sequence; Latin-1 characters with a GSM
    # equivalent and some without (0x01, 0x60, 0x7F, 0x80, 0xFF); an
    # unknown combining sequence; "_" too near the end of the value
    c.add(True, cimd(3, pn, [(21, '12345'), (33, UD_ALL_COMBINING)]))
    c.add(False, cimd(53, pn))
    pn += 2
    c.add(True, cimd(3, pn, [(21, '12345'),
                             (33, 'Kr\xa3\xa4\xa5\xa7\xbf\xc4\xc5\xc6\xc7 \x01\x60\x7f\x80\xff'
                                  '\r\n{|}~[\\]^_zz end_X')]))
    c.add(False, cimd(53, pn))
    pn += 2
    c.add(True, cimd(3, pn, [(21, '12345'), (33, 'x_')]))
    c.add(False, cimd(53, pn))
    pn += 2
    c.add(True, cimd(3, pn, [(21, '12345'), (33, '')]))
    c.add(False, cimd(53, pn))
    pn += 2
    # An unknown parameter code (not shown), then a known one
    c.add(True, cimd(3, pn, [(999, 'unknown'), (21, '12345')]))
    c.add(False, cimd(53, pn))
    pn += 2
    # Checksums: wrong value, and a trailer that is neither a TAB nor a
    # checksum (both "invalid checksum")
    c.add(True, cimd(40, pn, [(10, 'x')], cc=0x00))
    c.add(False, cimd(90, pn))
    pn += 2
    c.add(True, cimd(40, pn, [(10, 'x')], raw_tail=b'A\t7\x03'))
    c.add(False, cimd(90, pn))
    pn += 2
    # The reproducer cimd_param_past_etx.py: a last parameter
    # without a closing TAB followed (in the same segment) by a second
    # message; the parameter search now stops at the first ETX
    rep = (b'\x0203:001\t021:12345\t010:user\x03' + b'\x0203:002\t021:67890\t\x03')
    rep_frame = c.add(True, rep)
    c.add(False, cimd(53, 1, [(21, '12345'), (60, '261030120020')]))
    c.add(True, cimd(2, pn))
    c.add(False, cimd(52, pn))
    c.close()
    # Unknown operation code 77: the heuristic rejects it; with
    # "-d tcp.port==9972,cimd" it is dissected as "Unknown (77)"
    d = Conn(F, 40002, PORT_DA)
    d.add(True, cimd(77, 1, [(10, 'x')]))
    d.close()
    # TCP payloads the heuristic rejects (shown as TCP payload): too
    # short, no STX, no ETX, a non-numeric operation code, no colon, no
    # TAB after the packet number
    r = Conn(F, 40003, PORT_REJ)
    for p in (b'\x0201:01\x03', b'X01:001\t\x03', b'\x0201:001\t010:x\t',
              b'\x02AB:001\t\x03', b'\x0201-001\t\x03', b'\x0201:001X\x03'):
        r.add(True, p)
    r.close()
    return F, rep_frame


def malformed_frames():
    F = []
    c = Conn(F, 41001)
    # A parameter shorter than its code: the value length is negative
    c.add(True, b'\x0203:001\t02\t\x03')
    # A data coding scheme parameter with a 2 digit code
    c.add(True, b'\x0203:002\t030\t\x03')
    # A user data parameter with only a code
    c.add(True, b'\x0203:003\t033\t\x03')
    # An error code parameter with only a code
    c.add(True, b'\x0298:004\t900\t\x03')
    # ETX right after the packet number (no TAB): heuristic rejects it,
    # Decode As (port 41002) dissects it
    d = Conn(F, 41002, PORT_DA)
    d.add(True, b'\x0203:005\x03')
    d.add(True, b'\x0203:006\t\x03')
    d.add(True, b'\x02\x03XXXXX')
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames, rep = main_frames()
    write_pcap(os.path.join(out, 'cimd-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'cimd-coverage-malformed.pcap'), malformed_frames())
    print('main: %d frames (reproducer frame %d)' % (len(frames), rep))


if __name__ == '__main__':
    main()

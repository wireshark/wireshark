#!/usr/bin/env python3
# Generates test/captures/osi_options_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSI (CLNP) options coverage captures for packet-osi-options.c.

Usage: mkosi_options.py <outdir>
Writes osi-options-coverage.pcap and osi-options-coverage-malformed.pcap.
The options are dissected for every CLNP PDU (here over IPv4 protocol 80 and
LLC SAP 0xFE, both reached by default). Nothing comes from a real network.
"""
import os
import struct
import sys

MAC_DST = bytes.fromhex('020000000002')
MAC_SRC = bytes.fromhex('020000000001')
IP_SRC = (192, 0, 2, 1)
IP_DST = (198, 51, 100, 2)


def nsap(sysid, nsel):
    return bytes.fromhex('47000580ffff000000000100010000') + bytes([0x00]) \
        + struct.pack('>I', sysid)[1:] + bytes([nsel])


NSAP_A = lambda nsel: nsap(0x0a0b0c, nsel)
NSAP_B = lambda nsel: nsap(0x0d0e0f, nsel)
DT, ER = 0x1c, 0x01


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def fletcher(hdr, pos):
    c0 = c1 = 0
    for b in hdr:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = pos + 1
    L = len(hdr)
    x = ((L - n) * c0 - c1) % 255
    y = ((L - n + 1) * (-c0) + c1) % 255
    return (x or 255), (y or 255)


def clnp(ntype, data=b'', options=b'', nsel=0x22, short=False):
    """A CLNP PDU; NSEL 0x22 keeps the payload from being decoded as COTP/CLTP."""
    dst, src = NSAP_B(nsel), NSAP_A(nsel)
    addr = bytes([len(dst)]) + dst + bytes([len(src)]) + src
    hl = 9 + len(addr) + len(options)
    h = bytes([0x81, hl, 1, 30, ntype]) + struct.pack('>HH', hl + len(data), 0) + addr + options
    x, y = fletcher(h[:hl], 7)
    h = h[:7] + bytes([x, y]) + h[9:]
    return h + data


def opt(code, val):
    return bytes([code, len(val)]) + val


def llc_frame(pdu):
    llc = b'\xfe\xfe\x03' + pdu
    return MAC_DST + MAC_SRC + struct.pack('>H', len(llc)) + llc


def ip_frame(pdu, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(pdu), ident, 0,
                      64, 80, 0, bytes(IP_SRC), bytes(IP_DST))
    hdr = hdr[:10] + struct.pack('>H', csum16(hdr)) + hdr[12:]
    return MAC_DST + MAC_SRC + b'\x08\x00' + hdr + pdu


DATA = b'payload-0123'
QOS, SEC, PRIO, PAD, AMASK, SMASK, ESCT = 0xc3, 0xc5, 0xcd, 0xcc, 0xe1, 0xe2, 0xc6
SRCR, RECR, RFD = 0xc8, 0xcb, 0xc1


def net(n):
    return bytes([len(n)]) + n


NET1 = bytes.fromhex('49000100aa0000bb')
NET2 = bytes.fromhex('4900020011')


def main_frames():
    F = []
    # 1 quality of service maintenance: reserved, source specific, destination specific
    # (no flags decoded) and globally unique with every flag set / none set
    F.append(llc_frame(clnp(DT, DATA, opt(QOS, b'\x00') + opt(QOS, b'\x7f') + opt(QOS, b'\xbf') +
                            opt(QOS, b'\xff') + opt(QOS, b'\xc0'))))
    # 2 priority (valid, maximum, invalid), padding, address mask, SNPA mask, ESCT
    F.append(llc_frame(clnp(DT, DATA, opt(PRIO, b'\x05') + opt(PRIO, b'\x0e') + opt(PRIO, b'\x0f') +
                            opt(PAD, b'\0\0\0\0') + opt(AMASK, bytes.fromhex('490001')) +
                            opt(SMASK, bytes.fromhex('0123456789ab')) + opt(ESCT, b'\x00\x3c'))))
    # 3 security: reserved, source specific, destination specific, globally unique with and without
    # a payload, and a zero length option followed by a globally unique one (its type is read as
    # the security type of the empty option)
    F.append(llc_frame(clnp(DT, DATA, opt(SEC, b'\x00') + opt(SEC, b'\x40\x11') + opt(SEC, b'\x80\x22') +
                            opt(SEC, b'\xc0\x01\x02\x03') + opt(SEC, b'\xc0') + opt(SEC, b'') +
                            opt(SEC, b'\xc0\x07'))))
    # 4 source routing: partial and complete
    sr = bytes([0x03, 0x03, 0x04, 0x49, 0x00, 0x01, 0x02, 0x03, 0x02, 0x49, 0x00])
    F.append(llc_frame(clnp(DT, DATA, opt(SRCR, bytes([0x00]) + sr[1:]) + opt(SRCR, bytes([0x01]) + sr[1:]))))
    # 5 record of route: nothing recorded yet, terminated, with two NETs (partial / complete)
    F.append(llc_frame(clnp(DT, DATA, opt(RECR, b'\x00\x03' + bytes(4)) + opt(RECR, b'\x01\xff') +
                            opt(RECR, b'\x00' + bytes([4 + len(net(NET1)) + len(net(NET2))]) + net(NET1) + net(NET2)) +
                            opt(RECR, b'\x01' + bytes([4 + len(net(NET1))]) + net(NET1)))))
    # 6-11 reason for discard in error reports, one per error class and each field value
    classes = [(0x00, range(8)), (0x80, range(2)), (0x90, range(4)), (0xa0, range(2)),
               (0xb0, range(5)), (0xc0, range(1))]
    for base, fields in classes:
        o = b''.join(opt(RFD, bytes([base | f, f])) for f in fields)
        F.append(llc_frame(clnp(ER, b'', o)))
    # 12 the same options in an IPv4 (protocol 80) frame, an unknown option and a DT with an ES
    # configuration timer: unknown option codes are skipped
    F.append(ip_frame(clnp(DT, DATA, opt(0x99, b'\1\2\3') + opt(ESCT, b'\x00\x0a'))))
    # 13-15 the reproducers of the fixed bugs (batch s7, osi_options_route.py)
    F.append(ip_frame(clnp(DT, DATA, bytes([0xcb, 6, 0x00, 0x03, 0, 0, 0, 0]))))
    F.append(ip_frame(clnp(DT, DATA, bytes([0xc1, 2, 0x00, 0x05]))))
    F.append(ip_frame(clnp(DT, DATA, bytes([0xc8, 6, 0x00, 0x03, 3, 0x49, 0x00, 0x02]))))
    # 16 a PDU without options (the note "No Options for this PDU")
    F.append(ip_frame(clnp(DT, DATA), ident=2))
    return F


def malformed_frames():
    F = []
    # reason for discard with an unknown error class (warning), several fields
    for cls in (0xd0, 0xe0, 0xf0):
        F.append(llc_frame(clnp(ER, b'', opt(RFD, bytes([cls | 1, 9])))))
    # options cut short: the option length runs past the header / the frame
    F.append(llc_frame(clnp(DT, DATA, bytes([QOS, 4, 0xff]))))
    F.append(llc_frame(clnp(DT, DATA, opt(SEC, b'\xc0\x01\x02') + bytes([PRIO]))))
    F.append(llc_frame(clnp(DT, b'', opt(RECR, b'\x00\x30\x03\x49'))))
    F.append(llc_frame(clnp(DT, b'', opt(RECR, b'\x00\x08\x03\x49\x00\x01\x02'))))
    F.append(llc_frame(clnp(DT, b'', opt(RECR, b'\x00\x08\x20\x49\x00\x01\x02\x03'))))
    F.append(llc_frame(clnp(DT, b'', opt(SRCR, b'\x00\x30\x03'))))
    F.append(llc_frame(clnp(DT, b'', opt(SRCR, b'\x00'))))
    F.append(llc_frame(clnp(DT, b'', bytes([ESCT, 2, 0]))))
    F.append(llc_frame(clnp(DT, b'', bytes([RFD, 1, 0]))))
    F.append(llc_frame(clnp(DT, b'', bytes([PAD, 9, 0]))))
    F.append(llc_frame(clnp(DT, b'', bytes([AMASK, 20, 0x49]))))
    F.append(llc_frame(clnp(DT, b'', bytes([SMASK, 20, 0x49]))))
    F.append(llc_frame(clnp(DT, b'', bytes([PRIO, 1]))))
    # a header whose option part is empty is in the CLNP capture ("No Options for this PDU")
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'osi-options-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'osi-options-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

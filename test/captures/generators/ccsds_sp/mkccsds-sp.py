#!/usr/bin/env python3
# Generates test/captures/ccsds_sp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CCSDS Space Packet
dissector (packet-ccsds-sp.c).

The Space Packet dissector ("ccsds") has no port of its own: it is
offered in Decode As for UDP (here port 5000, -d udp.port==5000,ccsds)
and called by the EHS, VCDU and raw IEEE 802.3 dissectors. A packet is a
6 octet primary header (version, type, secondary header flag, APID,
sequence flags and count, length - 1), an optional 10 octet secondary
header (coarse and fine time, time ID, checkword flag, then a core or a
payload part depending on the type bit), the user data and an optional
16 bit checkword (the sum of all other 16 bit words). APID 2045 goes to
CFDP. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkccsds-sp.py <output directory>

Writes:
  ccsds-sp-coverage.pcap            Ethernet/IPv4/UDP: packets without and
                                    with a core or payload secondary header,
                                    correct and incorrect checkwords, every
                                    sequence flag, CFDP on APID 2045, short
                                    packets padded by the transport, trailing
                                    octets
  ccsds-sp-coverage-malformed.pcap  Exported PDU (dissector "ccsds"): the
                                    reproducer 
                                    ccsds-sp_checkword_short.py, lengths past
                                    the end, short packets with a checkword
                                    flag, truncated headers
"""

import os
import struct
import sys

SRC = (192, 0, 2, 10)
DST = (198, 51, 100, 20)
PORT = 5000


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(payload, ident):
    hdr = struct.pack('>HHHH', PORT, PORT, 8 + len(payload), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xffff
    l4 = hdr[:6] + struct.pack('>H', c) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0x4000, 64, 17, 0,
                     bytes(SRC), bytes(DST))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000014') + bytes.fromhex('02000000000a') + b'\x08\x00' + ip + l4


def exp_pdu(payload, name='ccsds'):
    n = name.encode()
    pad = (-len(n)) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def write_pcap(path, frames, linktype):
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)]
    t = 1792000000
    for i, f in enumerate(frames):
        out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


def checkword(data):
    """16 bit running sum of the packet without the checkword."""
    if len(data) % 2:
        data += b'\0'
    return sum(struct.unpack('>%dH' % (len(data) // 2), data)) & 0xffff


def sec_core(coarse=1000000, fine=0x80, timeid=1, cw=0, ptype=4,
             element=1, cmd_data=1, fmt_version=2, ext_fmt=0, frame_id=7):
    """Core secondary header (type bit 0)."""
    b5 = (timeid << 6) | (cw << 5) | ptype
    w = (element << 11) | (cmd_data << 10) | (fmt_version << 6) | ext_fmt
    return struct.pack('>IBBHBB', coarse, fine, b5, w, 0, frame_id)


def sec_payload(coarse=2000000, fine=0x40, timeid=2, cw=0, zoe=1, ptype=6, vid=0x1234, dcc=0xabcd):
    """Payload secondary header (type bit 1)."""
    b5 = (timeid << 6) | (cw << 5) | (zoe << 4) | ptype
    return struct.pack('>IBBHH', coarse, fine, b5, vid, dcc)


def sp(apid, data, ptype=0, sec=None, seqflag=3, seq=1, cw=False, cw_value=None, length=None):
    """A Space Packet; sec is the secondary header (or None). With cw a
    checkword is appended (cw_value overrides the correct sum)."""
    body = (sec or b'') + data
    total = 6 + len(body) + (2 if cw else 0)
    if length is None:
        length = total - 7
    first = (ptype << 12) | ((1 if sec is not None else 0) << 11) | apid
    pkt = struct.pack('>HHH', first, (seqflag << 14) | seq, length) + body
    if cw:
        pkt += struct.pack('>H', checkword(pkt) if cw_value is None else cw_value)
    return pkt


def cfdp_eof():
    """A CFDP EOF PDU (version 1, 1 octet IDs) with a fault location TLV."""
    data = bytes([0x04, 0x00]) + struct.pack('>II', 0x01020304, 512) + bytes([0x06, 1, 0x05])
    return bytes([0x20]) + struct.pack('>H', len(data)) + bytes([0x00, 0x01, 0x02, 0x03]) + data


def cfdp_prompt():
    data = bytes([0x09, 0x80])
    return bytes([0x20]) + struct.pack('>H', len(data)) + bytes([0x00, 0x01, 0x02, 0x03]) + data


def main_frames():
    p = []
    # 1-4: no secondary header, every sequence flag
    p.append(sp(100, b'telemetry frame without secondary header', seqflag=3, seq=1))
    p.append(sp(100, b'first segment', seqflag=1, seq=2))
    p.append(sp(100, b'continuation segment', seqflag=0, seq=3))
    p.append(sp(100, b'last segment', seqflag=2, seq=0x3fff))
    # 5-8: core secondary header, no checkword, several packet types,
    # element IDs and format IDs
    p.append(sp(200, b'core', sec=sec_core(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
    p.append(sp(201, b'housekeeping', sec=sec_core(1500000000, 0xff, 3, 0, 4, 1, 1, 2, 63, 255)))
    p.append(sp(202, b'file transfer', sec=sec_core(123456, 0x10, 1, 0, 11, 11, 0, 9, 16, 1)))
    p.append(sp(203, b'reserved values', sec=sec_core(654321, 0x01, 2, 0, 15, 15, 1, 15, 0, 2)))
    # 9-10: core secondary header with a correct and an incorrect checkword
    p.append(sp(300, b'checked data', sec=sec_core(cw=1), cw=True))
    p.append(sp(301, b'checked data', sec=sec_core(cw=1), cw=True, cw_value=0x1234))
    # 11-13: payload secondary header, without and with a checkword
    p.append(sp(400, b'payload science data', ptype=1, sec=sec_payload()))
    p.append(sp(401, b'payload science data', ptype=1, sec=sec_payload(zoe=0, ptype=10, cw=1), cw=True))
    p.append(sp(402, b'payload', ptype=1, sec=sec_payload(cw=1), cw=True, cw_value=0))
    # 14: exactly the primary and secondary header, no user data
    p.append(sp(500, b'', sec=sec_core()))
    # 15: a 10 octet packet in a padded UDP payload: the dissector shows
    # 16 octets as user data (it assumes at least both headers)
    p.append(sp(501, b'abcd') + b'\0' * 6)
    # 16: octets after the packet go to the data dissector
    p.append(sp(502, b'0123456789', sec=sec_core()) + b'\xde\xad\xbe\xef')
    # 17-19: CFDP on APID 2045, without and with a secondary header, and
    # with a checkword (CFDP gives the checkword octets to the data
    # dissector before the Space Packet dissector shows the checkword)
    p.append(sp(2045, cfdp_eof()))
    p.append(sp(2045, cfdp_prompt(), sec=sec_core(ptype=11)))
    p.append(sp(2045, cfdp_eof(), sec=sec_core(cw=1), cw=True))
    # 20: telecommand type, no secondary header
    p.append(sp(0x7fe, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a', ptype=1))
    return [udp_frame(x, i + 1) for i, x in enumerate(p)]


def reproducer():
    """ccsds-sp_checkword_short.py: secondary header and
    checkword flag, length field 9 (exactly both headers)."""
    p = struct.pack('>HHH', 0x0800 | 0x123, 0xc001, 9)
    p += struct.pack('>IB', 1000, 0x80) + bytes([0x20]) + b'\x00\x01\x00\x02'
    return p


def malformed_frames():
    p = []
    # 1: the reproducer: room for both headers but not for the checkword;
    # the user data length becomes -2 and the item throws
    p.append(reproducer())
    # 2: the same with APID 2045 (CFDP): offset moves back by 2, the
    # checkword is read from the secondary header
    p.append(sp(2045, b'', sec=sec_core(cw=1), length=9))
    # 3: length field past the end of the packet
    p.append(sp(100, b'abc', length=100))
    # 4: length past the end with a checkword flag
    p.append(sp(100, b'abcdefgh', sec=sec_core(cw=1), length=60))
    # 5: a length field below both headers, with a secondary header and a
    # checkword flag ("Packet does not contain a Checkword")
    p.append(sp(100, b'', sec=sec_core(cw=1), length=3))
    # 6: shorter than the primary header
    p.append(b'\x08\x64\xc0')
    # 7: secondary header cut short
    p.append(struct.pack('>HHH', 0x0800 | 100, 0xc001, 20) + b'\x00\x01')
    # 8: payload secondary header cut short
    p.append(struct.pack('>HHH', 0x1800 | 100, 0xc001, 20) + b'\x00\x01\x02\x03\x04\x20\x00')
    # 9: CFDP on APID 2045 cut short
    p.append(sp(2045, cfdp_eof()[:8] + b'\0' * 8))
    # 10: a complete 10 octet packet without a secondary header and
    # nothing after it: the dissector assumes 16 octets (observation 2)
    p.append(sp(501, b'abcd'))
    return [exp_pdu(x) for x in p]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ccsds-sp-coverage.pcap'), main_frames(), 1)
    write_pcap(os.path.join(out, 'ccsds-sp-coverage-malformed.pcap'), malformed_frames(), 252)


if __name__ == '__main__':
    main()

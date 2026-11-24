#!/usr/bin/env python3
# Generates test/captures/bmc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BMC dissector (packet-bmc.c)
and the UMTS/GSM Cell Broadcast dissector it calls (packet-cell_broadcast.c).

BMC (UMTS Broadcast/Multicast Control, 3GPP TS 25.324) is carried on the
CTCH by UMTS RLC. BMC octets are bit-reversed on the wire. The frames are
Exported PDUs (linktype 252) naming the "bmc", "umts_cell_broadcast" or
"gsm_cbs" dissector, and one naming "ip" whose IPv4/UDP datagram carries
RLC over UDP framing ("umts-rlc", heuristic rlc_udp, disabled by default)
for a CTCH UM PDU holding a BMC message. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkbmc.py <output directory>

Writes:
  bmc-coverage.pcap            every BMC message type, every Data Coding
                               Scheme group, schedule messages (period
                               length 255, 10, 8 and 0), the reproducers,
                               BMC through RLC, GSM CBS pages incl. a
                               two-page reassembly
  bmc-coverage-malformed.pcap  truncated messages (exceptions)
"""

import os
import struct
import sys


def write_pcap(path, frames, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def exp_pdu(name, payload):
    """Exported PDU: EXP_PDU_TAG_DISSECTOR_NAME (12), end of options."""
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad +
            struct.pack('>HH', 0, 0) + payload)


def rev(b):
    """BMC is bit-reversed on the wire."""
    return bytes(int('{:08b}'.format(x)[::-1], 2) for x in b)


def pack7(text):
    """Pack a GSM 7 bit default alphabet string (ASCII letters, digits,
    space and CR map to themselves) into octets, LSB first."""
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in text:
        c = ord(ch)
        assert c < 0x80 and ch not in '@$_`', ch
        bits |= c << nbits
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            nbits -= 8
    if nbits:
        out.append(bits & 0xff)
    return bytes(out)


def ucs2(text):
    return text.encode('utf-16-be')


# BMC ----------------------------------------------------------------------

def bmc_cbs(msg_id, serial, dcs, data):
    """BMC CBS Message: type 1, Message ID, Serial Number, DCS, CB Data."""
    return exp_pdu('bmc', rev(struct.pack('>BHHB', 1, msg_id, serial, dcs) + data))


def bmc_schedule(offset, length, bitmap, descriptions, tail=b''):
    """BMC Schedule Message. descriptions: list of (type, extra bytes)."""
    body = struct.pack('>BBB', 2, offset, length) + bitmap
    for t, extra in descriptions:
        body += bytes([t]) + extra
    return exp_pdu('bmc', rev(body + tail))


def desc(i):
    """Message description i of a schedule: cycles through every type,
    including the unknown 9, with its Message ID or CTCH BS index offset."""
    t = i % 10
    if t in (1, 5):
        return (t, struct.pack('>H', 0x1000 + i))
    if t in (0, 4):
        return (t, bytes([i & 0xff]))
    return (t, b'')


def serial_no(gs, code, update):
    return (gs << 14) | (code << 4) | update


# RLC over UDP -------------------------------------------------------------

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4_udp(sport, dport, data, src=(192, 0, 2, 1), dst=(198, 51, 100, 1)):
    uhdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + uhdr + data) or 0xffff
    u = uhdr[:6] + struct.pack('>H', c) + data
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + u


def rlc_ctch(sn, bmc):
    """RLC over UDP framing (packet-umts_rlc.h): "umts-rlc", channel type
    CTCH, direction downlink, LI size 7 bits, payload. The UM PDU holds
    exactly one SDU: LI 0x7c (an SDU starts here), then an LI equal to the
    SDU length."""
    framing = (b'umts-rlc' + bytes([0x02, 5]) + bytes([0x04, 1]) +
               bytes([0x07, 1]) + bytes([0x01]))
    um = bytes([(sn << 1) | 1, (0x7c << 1) | 1, len(bmc) << 1]) + rev(bmc)
    return exp_pdu('ip', ipv4_udp(40000, 50000, framing + um))


# GSM CBS page -------------------------------------------------------------

def gsm_page(serial, msg_id, dcs, page, total, data):
    """GSM CBS page (TS 23.041 9.4.1): 6 octet header, 82 octets of data."""
    hdr = struct.pack('>HHBB', serial, msg_id, dcs, (page << 4) | total)
    return exp_pdu('gsm_cbs', hdr + data)


def pad7(text, cr=True):
    """82 octets of packed 7 bit text, padded with CR characters (93
    septets fill 81.4 octets)."""
    if cr:
        text = text + '\r' * (93 - len(text))
    d = pack7(text)
    return d + b'\0' * (82 - len(d))


def main_capture():
    f = []
    # 1-19: CBS messages, one per Data Coding Scheme group / character set,
    # Message IDs walking through every range of the identifier decoder.
    f.append(bmc_cbs(0, serial_no(0, 1, 1), 0x0F, pack7('Hello BMC')))         # 1 group 0 7 bit
    f.append(bmc_cbs(40, serial_no(1, 2, 2), 0x10,
                     pack7('en\rWeather report')))                               # 2 group 1 7 bit + language
    f.append(bmc_cbs(500, serial_no(2, 3, 3), 0x11,
                     pack7('de') + ucs2('Grüße')))                     # 3 group 1 UCS2 + language
    f.append(bmc_cbs(2000, serial_no(3, 4, 4), 0x20, pack7('Group two')))      # 4
    f.append(bmc_cbs(4100, serial_no(0, 5, 5), 0x30, pack7('Group three')))    # 5
    f.append(bmc_cbs(4300, serial_no(1, 6, 6), 0x44, b'Eight bit data'))       # 6 group 4 8 bit
    f.append(bmc_cbs(4357, serial_no(2, 7, 7), 0x48, ucs2('UCS2 text')))       # 7 group 4 UCS2
    f.append(bmc_cbs(4390, serial_no(3, 8, 8), 0x52, pack7('Class two')))      # 8 group 5, class
    f.append(bmc_cbs(5000, serial_no(0, 9, 9), 0x4C, b'reserved charset'))     # 9 group 4 reserved charset
    f.append(bmc_cbs(0x1111, 0x0010, 0x80, b'ABC'))                            # 10 reserved group 8
    f.append(bmc_cbs(30000, serial_no(1, 10, 10), 0x94, b'UDH 8 bit'))         # 11 group 9 8 bit
    f.append(bmc_cbs(42000, serial_no(2, 11, 11), 0x98, ucs2('UDH UCS2')))     # 12 group 9 UCS2
    f.append(bmc_cbs(43510, serial_no(3, 12, 12), 0x90, pack7('UDH seven')))   # 13 group 9 7 bit
    f.append(bmc_cbs(43550, serial_no(0, 13, 13), 0x9C, b'UDH reserved'))      # 14 group 9 reserved
    f.append(bmc_cbs(44000, serial_no(1, 14, 14), 0xA0, b'reserved A'))        # 15 groups 10-13
    f.append(bmc_cbs(46000, serial_no(2, 15, 15), 0xE0, b'WAP'))               # 16 group 14
    f.append(bmc_cbs(50000, serial_no(3, 16, 0), 0xF0, pack7('Group fifteen'))) # 17 group 15 7 bit
    f.append(bmc_cbs(65535, serial_no(0, 17, 1), 0xF4, b'G15 8 bit'))          # 18 group 15 8 bit
    f.append(bmc_cbs(4352, serial_no(1, 1023, 2), 0x01, b''))                  # 19 no CB data
    # 20: the original reproducer's bytes (bmc_dcs_null_tvb.py):
    # DCS 0x0F, then 0x80 'A' 'B' 'C' as 7 bit text.
    f.append(exp_pdu('bmc', rev(bytes([0x01, 0x11, 0x12, 0x00, 0x10, 0x0f,
                                       0x80, 0x41, 0x42, 0x43]))))
    # 21: second reproducer, "umts_cell_broadcast" directly, reserved DCS
    f.append(exp_pdu('umts_cell_broadcast', bytes([0x80, 0x41, 0x42])))
    # 22: Schedule Message, period length 255 (bmc_sched_len255.py
    # had 255 x "no message"; here every description type), extension
    # bitmap with a serial number list of two entries.
    f.append(bmc_schedule(3, 255, b'\xff' * 32, [desc(i) for i in range(1, 256)],
                          tail=bytes([0x01, 2]) + struct.pack('>HB', 0x1234, 7) +
                          struct.pack('>HB', 0x5678, 9)))
    # 23: period length 10 (two bitmap octets), no extension bitmap
    f.append(bmc_schedule(0, 10, b'\xa5\x80', [desc(i) for i in range(1, 11)]))
    # 24: period length 8 (one bitmap octet), extension bitmap without list
    f.append(bmc_schedule(1, 8, b'\x0f', [desc(i) for i in range(1, 9)],
                          tail=bytes([0x00])))
    # 25: period length 0, extension bitmap with an empty list
    f.append(bmc_schedule(2, 0, b'', [], tail=bytes([0x01, 0])))
    # 26: CBS41 message
    f.append(exp_pdu('bmc', rev(bytes([3]) + bytes.fromhex('0102030405') + b'CBS41 data')))
    # 27-28: reserved message types
    f.append(exp_pdu('bmc', rev(bytes([0]))))
    f.append(exp_pdu('bmc', rev(bytes([7, 1, 2, 3]))))
    # 29: BMC CBS message through RLC over UDP on the CTCH
    f.append(rlc_ctch(0, struct.pack('>BHHB', 1, 4371, serial_no(2, 20, 3), 0x0F) +
                      pack7('Via RLC CTCH')))
    # 30-34: GSM CBS pages: single page padded with CR, a two-page message
    # (reassembled in 32), a single UCS2 page, a page of CR only, and a
    # reserved coding scheme.
    f.append(gsm_page(serial_no(1, 30, 1), 50, 0x0F, 1, 1, pad7('Single GSM page')))
    f.append(gsm_page(serial_no(1, 31, 1), 60, 0x0F, 1, 2, pad7('A' * 93, cr=False)))
    f.append(gsm_page(serial_no(1, 31, 1), 60, 0x0F, 2, 2, pad7('Second page')))
    f.append(gsm_page(serial_no(1, 32, 1), 70, 0x48, 1, 1,
                      (ucs2('UCS2 page') + b'\0' * 82)[:82]))
    f.append(gsm_page(serial_no(1, 33, 1), 80, 0x0F, 1, 1, pad7('')))
    f.append(gsm_page(serial_no(1, 34, 1), 90, 0x80, 1, 1, b'\x55' * 82))
    return f


def malformed_capture():
    f = []
    f.append(exp_pdu('bmc', b''))                                       # 1 no message type
    f.append(exp_pdu('bmc', rev(bytes([1, 0x00]))))                     # 2 CBS: Message ID cut
    f.append(exp_pdu('bmc', rev(bytes([1, 0x00, 0x01, 0x00]))))         # 3 CBS: Serial Number cut
    f.append(exp_pdu('bmc', rev(bytes([1, 0x00, 0x01, 0x00, 0x01]))))   # 4 CBS: no DCS
    f.append(exp_pdu('bmc', rev(bytes([2, 0]))))                        # 5 Schedule: no length
    f.append(exp_pdu('bmc', rev(bytes([2, 0, 16, 0xff]))))              # 6 Schedule: bitmap cut
    f.append(exp_pdu('bmc', rev(bytes([2, 0, 3, 0xe0, 1, 0x10]))))      # 7 Schedule: Message ID cut
    f.append(exp_pdu('bmc', rev(bytes([2, 0, 1, 0x80, 8, 0x01, 3, 0x12, 0x34, 1]))))  # 8 list cut
    f.append(exp_pdu('bmc', rev(bytes([3, 1, 2]))))                     # 9 CBS41: address cut
    f.append(exp_pdu('umts_cell_broadcast', b''))                      # 10 no DCS
    f.append(exp_pdu('gsm_cbs', bytes([0x40, 0x10, 0x00])))             # 11 GSM page header cut
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bmc-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'bmc-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()

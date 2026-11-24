#!/usr/bin/env python3
# Generates test/captures/cell_broadcast_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the GSM Cell Broadcast
Service dissector (packet-cell_broadcast.c).

The dissector registers "gsm_cbs" (a GSM CBS page: serial number,
message identifier, data coding scheme, page parameter and 82 octets of
content, reassembled into a message over several pages) and
"umts_cell_broadcast" (a UMTS CBS message: data coding scheme and
content). Both are reached here through Exported PDU (linktype 252)
with the dissector name; the GSM pages are also reached the way a real
capture does, through GSMTAP (also carried in Exported PDU, dissector
"gsmtap") on the CBCH, whose four blocks are reassembled into a page.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkcell_broadcast.py <output directory>

Writes:
  cell_broadcast-coverage.pcap            single and multi-page messages in
                                          every encoding, every message
                                          identifier range, the reproducer
                                          cell_broadcast_page_zero, CBCH
  cell_broadcast-coverage-malformed.pcap  unhandled encodings, a conflicting
                                          page, truncated pages
"""

import os
import struct
import sys

PAGE_DATA = 82          # 88 octet page minus the 6 octet header


def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
            + struct.pack('>HH', 0, 0) + payload)


# GSM 7 bit default alphabet for the characters used here (the same as
# ASCII for letters, digits, space and most punctuation)
GSM7 = {'@': 0x00, '\n': 0x0a, '\r': 0x0d, '_': 0x11}


def gsm7_pack(text, octets=None, pad='\r'):
    """Pack text in the GSM 7 bit alphabet. With octets, pad the text
    with CR to fill exactly that many octets (3GPP TS 23.041)."""
    if octets is not None:
        text = text + pad * ((octets * 8) // 7 - len(text))
    sept = [GSM7.get(c, ord(c)) for c in text]
    bits = 0
    nbits = 0
    out = bytearray()
    for s in sept:
        bits |= s << nbits
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            nbits -= 8
    if nbits:
        out.append(bits & 0xff)
    if octets is not None:
        out = out[:octets]
        out += b'\0' * (octets - len(out))
    return bytes(out)


def ucs2(text, octets=None):
    b = text.encode('utf-16-be')
    if octets is not None:
        b += '\r'.encode('utf-16-be') * ((octets - len(b)) // 2)
    return b


def serial(gs, code, update):
    return (gs << 14) | (code << 4) | update


def page(ser, msgid, dcs, cur, tot, data):
    return struct.pack('>HHBB', ser, msgid, dcs, (cur << 4) | tot) + data


def gsmtap_cbch(block_octet, block, fn):
    """A GSMTAP v2 header (type UM, sub type CBCH51) and one CBCH block."""
    hdr = struct.pack('>BBBBHbBIBBBB', 2, 4, 1, 0, 17, -60, 20, fn, 0x0f, 0, 0, 0)
    return hdr + bytes([block_octet]) + block


def cbch_page(pg, fn):
    """The four CBCH blocks of one 88 octet page."""
    assert len(pg) == 88
    out = []
    for i in range(4):
        octet = 0x20 | i | (0x10 if i == 3 else 0)
        out.append(gsmtap_cbch(octet, pg[22 * i:22 * i + 22], fn + 4 * i))
    return out


def main_frames():
    F = []

    def G(p):
        F.append(exp_pdu('gsm_cbs', p))
        return len(F)

    def U(p):
        F.append(exp_pdu('umts_cell_broadcast', p))
        return len(F)

    # 1-10: the reproducer cell_broadcast_page_zero.py:
    # page 0 of 2 (now page 1 of 1), pages 1 and 2 of the same message
    # (reassembled), page 15 of 2 and page 0 of 0 (page 1 of 1), a UCS2
    # message with a language of one octet and with an odd UCS2 part, a
    # short 7 bit message with a language, a lone UCS2 surrogate, and 8 bit
    # data starting with NUL
    rep = [
        page(0x1234, 50, 0x0f, 0, 2, b'\xc8\x34' * 41),
        page(0x1234, 50, 0x0f, 1, 2, b'\xc8\x34' * 41),
        page(0x1234, 50, 0x0f, 2, 2, b'\xc8\x34' * 41),
        page(0x1235, 51, 0x0f, 15, 2, b'\xc8\x34' * 41),
        page(0x1236, 52, 0x0f, 0, 0, b'\xc8\x34' * 41),
        page(0x1237, 53, 0x11, 1, 1, b'\xe5'),
        page(0x1238, 54, 0x11, 1, 1, b'\xe5\x37\x00'),
        page(0x1239, 55, 0x10, 1, 1, b'\x0d'),
        page(0x123a, 56, 0x48, 1, 1, b'\x00\x41\xd8\x00'),
        page(0x123b, 57, 0x44, 1, 1, bytes(range(256))[:82]),
    ]
    for p in rep:
        G(p)

    # 11-13: a three page 7 bit message (geographic scope PLMN-wide)
    s = serial(1, 100, 1)
    for i, t in enumerate(('First page of three. ', 'Second page of three. ',
                           'Third and last page.')):
        G(page(s, 4370, 0x0f, i + 1, 3, gsm7_pack(t, PAGE_DATA)))
    # 14-15: a two page message received last page first (scope LA-wide)
    s = serial(2, 200, 2)
    G(page(s, 4371, 0x01, 2, 2, gsm7_pack('the end.', PAGE_DATA)))
    G(page(s, 4371, 0x01, 1, 2, gsm7_pack('Out of order: ', PAGE_DATA)))
    # 16: page 2 again after the message was reassembled (same content)
    G(page(s, 4371, 0x01, 2, 2, gsm7_pack('the end.', PAGE_DATA)))

    # 17-35: single page messages in every coding group and encoding,
    # each with a message identifier from a different range
    singles = [
        (0x02, 0, gsm7_pack('Group 0 language 2', PAGE_DATA)),        # 7 bit
        (0x10, 500, gsm7_pack('en\rEnglish with a language', PAGE_DATA)),  # 7 bit + lang
        (0x11, 2000, gsm7_pack('de', 2)[:2] + ucs2('Grüße', PAGE_DATA - 2)),
        (0x20, 4100, gsm7_pack('Group 2 Czech', PAGE_DATA)),
        (0x30, 4300, gsm7_pack('Group 3', PAGE_DATA)),
        (0x40, 4357, gsm7_pack('Group 4 uncompressed GSM 7 bit', PAGE_DATA)),
        (0x51, 4390, gsm7_pack('Group 5 class 1', PAGE_DATA)),
        (0x44, 5000, b'Group 4 8 bit data' + b'\r' * (PAGE_DATA - 18)),
        (0x48, 10000, ucs2('Δ UCS2 €', PAGE_DATA)),
        (0x5a, 42000, ucs2('UCS2 class 2', PAGE_DATA)),
        (0x91, 43510, gsm7_pack('Group 9 with UDH', PAGE_DATA)),
        (0x95, 43550, b'Group 9 8 bit' + b'\r' * (PAGE_DATA - 13)),
        (0x9a, 44000, ucs2('Group 9 UCS2', PAGE_DATA)),
        (0xf1, 50000, gsm7_pack('Group 15 7 bit class 1', PAGE_DATA)),
        (0xf6, 4352, b'Group 15 8 bit class 2' + b'\r' * (PAGE_DATA - 22)),
        (0x0f, 1000, gsm7_pack('', PAGE_DATA)),                   # only CR padding
        (0x0f, 65535, gsm7_pack('This text has exactly ninety-three characters'
                                ' and fills the page: no CR padding at the end...',
                                PAGE_DATA)),
        (0x0f, 4380, gsm7_pack('@_\n', PAGE_DATA)),
        (0x0f, 60, b''),                                          # no content
    ]
    for i, (dcs, mid, data) in enumerate(singles):
        G(page(serial(3 if i % 2 else 0, 300 + i, i % 16), mid, dcs, 1, 1, data))

    # 36-43: a two page message over GSMTAP CBCH (4 blocks per page)
    s = serial(3, 400, 3)
    p1 = page(s, 4352, 0x0f, 1, 2, gsm7_pack('Earthquake warning via CBCH, ', PAGE_DATA))
    p2 = page(s, 4352, 0x0f, 2, 2, gsm7_pack('page two.', PAGE_DATA))
    for b in cbch_page(p1, 1000) + cbch_page(p2, 1100):
        F.append(exp_pdu('gsmtap', b))

    # 44-50: UMTS CBS messages: 7 bit, 7 bit with a language, UCS2 with a
    # language, UCS2, 8 bit, 7 bit group 15, an empty message
    U(b'\x0f' + gsm7_pack('UMTS 7 bit message', 20))
    U(b'\x10' + gsm7_pack('fr\rBonjour', 9))
    U(b'\x11' + gsm7_pack('it', 2)[:2] + ucs2('Ciao'))
    U(b'\x48' + ucs2('UMTS UCS2'))
    U(b'\x44' + b'UMTS 8 bit')
    U(b'\xf0' + gsm7_pack('Group 15', 7))
    U(b'\x0f')
    return F


def malformed_frames():
    F = []

    def G(p):
        F.append(exp_pdu('gsm_cbs', p))

    def U(p):
        F.append(exp_pdu('umts_cell_broadcast', p))

    # 1-6: encodings the dissector does not handle (reserved coding groups
    # 8, 10-14, reserved character sets of groups 4-7 and 9): warning
    for dcs in (0x80, 0xa0, 0xe0, 0x4c, 0x9c):
        G(page(serial(0, 1, 1), 50, dcs, 1, 1, b'\x41' * PAGE_DATA))
    U(b'\x80' + b'\x41' * 10)
    # 7-8: the same page twice with different content (overlap conflict)
    s = serial(1, 2, 2)
    G(page(s, 60, 0x0f, 1, 2, gsm7_pack('one', PAGE_DATA)))
    G(page(s, 60, 0x0f, 1, 2, gsm7_pack('two', PAGE_DATA)))
    # 9: the last page, which completes the message
    G(page(s, 60, 0x0f, 2, 2, gsm7_pack('three', PAGE_DATA)))
    # 10-11: truncated pages (no page parameter, no data coding scheme)
    G(struct.pack('>HHB', 0x1000, 50, 0x0f))
    G(struct.pack('>HH', 0x1000, 50))
    # 12: an empty UMTS message
    U(b'')
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = main_frames()
    write_pcap(os.path.join(out, 'cell_broadcast-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'cell_broadcast-coverage-malformed.pcap'),
               malformed_frames())
    print('main: %d frames' % len(frames))


if __name__ == '__main__':
    main()

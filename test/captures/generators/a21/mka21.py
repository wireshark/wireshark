#!/usr/bin/env python3
# Generates test/captures/a21_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic A21 (3GPP2 A21/S102) coverage captures.

Usage: mka21.py <outdir> [-v]

  a21-coverage.pcapng            main capture (Ethernet and Exported PDU)
  a21-coverage-malformed.pcapng  paths only malformed input reaches

Every packet is built with struct; addresses are from 192.0.2.0/24.
"""
import struct
import sys
import os

LT_ETH = 1
LT_EXPPDU = 252
A21_PORT = 23272


def pcapng(path, frames):
    """frames: list of (interface, bytes). Interface 0 is Ethernet,
    interface 1 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', LT_ETH, 0, 65535))
    out += block(1, struct.pack('<HHI', LT_EXPPDU, 0, 65535))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IDENT = [0]


def udp_frame(payload, sport=40000, dport=A21_PORT, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    IDENT[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IDENT[0], 0x4000, 64, 17, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return (0, bytes.fromhex('020000000002' '020000000001' '0800') + h + u)


def exppdu(name, payload):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return (1, struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload)


def hdr(mtype, corr=1):
    """Message type and the fixed Correlation ID IE."""
    return bytes([mtype, 0x04, 0x04]) + struct.pack('>I', corr)


def ie(t, data):
    if t == 0xC0:
        return bytes([t]) + struct.pack('>H', len(data)) + data
    return bytes([t, len(data)]) + data


# ---------------------------------------------------------------- IEs

def pilot(ch_rec=b'\x00\x08\x10', cell_info=0, cell_data=b'', ref=True, pn=0x0123,
          strength=0x15, delay=None):
    p = bytes([len(ch_rec)]) + ch_rec
    p += bytes([cell_info]) + cell_data
    word = (0x8000 if ref else 0) | (pn & 0x7fff)
    p += struct.pack('>H', word)
    b = strength & 0x3f
    if delay is not None:
        b |= 0x40
    p += bytes([b])
    if delay is not None:
        p += struct.pack('>H', delay)
    return p


def pilot_list(pilots):
    return ie(0x03, bytes([len(pilots)]) + b''.join(pilots))


def mn_id_none():
    return ie(0x05, bytes([0x00 | (5 << 3)]))


def mn_id_meid():
    return ie(0x05, bytes([0x01 | 0x08]) + bytes(range(1, 7)))


def mn_id_esn():
    return ie(0x05, bytes([0x05 | 0x08 | 0x30, 0x55]))


def mn_id_imsi(digits):
    """IMSI in the A21 format: odd/even bit, first digit in the high nibble."""
    odd = len(digits) % 2
    ds = [int(c) for c in digits]
    first = ds[0]
    rest = ds[1:]
    b = bytes([(first << 4) | (odd << 3) | 6])
    if len(rest) % 2:
        rest.append(0xf)
    for i in range(0, len(rest), 2):
        b += bytes([(rest[i + 1] << 4) | rest[i]])
    return ie(0x05, b)


def mob_sub(records):
    return ie(0x0B, b''.join(records))


def band_rec(bands, all_bands=True, cur_sub=3):
    body = bytes([(0x80 if all_bands else 0) | cur_sub])
    for bc, all_sub, sub in bands:
        body += bytes([bc])
        body += bytes([(0x80 if all_sub else 0) | len(sub)]) + bytes(sub)
    return bytes([0x00, len(body)]) + body


def gcsna_status(status=None, priority=None, gec=0):
    b = 0x02 if gec else 0
    d = b''
    if status is not None:
        b |= 0x01
        d += bytes([status])
    if priority is not None:
        b |= 0x04
        d += bytes([priority & 0x0f])
    return ie(0x0C, bytes([b]) + d)


def bits_servicereject(seq, cause, extra):
    """GCSNA Service Reject: 6 bit sequence, 8 bit cause, then the bytes
    of the cause specific part (after the cause the bits are not aligned,
    so the following octets are shifted by 6 bits)."""
    bits = format(seq, '06b') + format(cause, '08b')
    for e in extra:
        bits += format(e, '08b')
    bits += '0' * ((8 - len(bits) % 8) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


# a CDMA2000 TLAC header and an Order Indication Message, which the cdma2k
# dissector decodes without errors
CDMA2K_ORDER = bytes([0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00])


def main_frames():
    F = []

    def add(mtype, ies, corr=None, **kw):
        F.append(udp_frame(hdr(mtype, corr if corr is not None else len(F) + 1)
                           + b''.join(ies), **kw))

    # 1-9: every message type with typical IEs
    add(0x01, [ie(0x01, bytes(range(1, 20))),
               ie(0x07, bytes([0x0f, 0x07])),
               mn_id_imsi('001010123456789')])
    add(0x02, [ie(0x08, bytes([0x04]))])
    add(0x03, [ie(0x02, bytes(range(8))), mn_id_esn()])
    add(0x04, [ie(0x09, bytes([0x02])), mn_id_meid()])
    add(0x05, [mn_id_imsi('00101')])
    add(0x06, [ie(0x0A, struct.pack('>H', 0x003B)), mn_id_none()])
    add(0x07, [ie(0x08, bytes([0x00])), ie(0x0A, struct.pack('>H', 0x5901))])
    add(0x08, [ie(0x0D, bytes([0x01, 0x23, 0x04, 0xab, 0xc5]))])
    add(0x09, [ie(0x0D, bytes([0x12, 0x34, 0x05, 0xff, 0xf0])),
               ie(0x08, bytes([0x07]))])
    add(0x0A, [ie(0x08, bytes([0x03]))])           # 10: unknown message type
    # 11: header only, no IEs
    add(0x02, [])

    # 12-14: Correlation ID IE in the list: value 7 (fix reproducer), 0xffffffff,
    # and the value of a second one shown as in the header
    add(0x01, [ie(0x04, struct.pack('>I', 7)), ie(0x08, bytes([0x03]))])
    add(0x02, [ie(0x04, struct.pack('>I', 0xffffffff))], corr=0xfffffffe)
    add(0x04, [ie(0x08, bytes([0x05])), ie(0x04, struct.pack('>I', 0x01020304))])

    # 15-26: Cause values (all defined, one reserved)
    for c in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0B, 0x80):
        add(0x02, [ie(0x08, bytes([c]))])

    # Events: all defined values, 7 with allowed forward link messages, others with info
    for e in range(0, 0x0c):
        add(0x04, [ie(0x09, bytes([e]))])
    add(0x04, [ie(0x09, bytes([0x07, 0x12, 0x34]))])
    add(0x04, [ie(0x09, bytes([0x01, 0x00, 0x05]))])
    add(0x04, [ie(0x09, bytes([0x0b, 0xff, 0xff]))])
    add(0x04, [ie(0x09, bytes([0x20]))])           # reserved event

    # Mobile Identity: every type
    add(0x01, [mn_id_none()])
    add(0x01, [ie(0x05, bytes([0x00 | (17 << 3)]))])
    add(0x01, [mn_id_meid()])
    add(0x01, [ie(0x05, bytes([0x01]) + bytes(range(0xa0, 0xa7)))])
    add(0x01, [mn_id_esn()])
    add(0x01, [ie(0x05, bytes([0x05, 0x7f]))])
    add(0x01, [mn_id_imsi('310260123456789')])
    add(0x01, [mn_id_imsi('2406912345678')])       # even/odd
    add(0x01, [mn_id_imsi('460001234567890')])
    add(0x01, [ie(0x05, bytes([0x02, 0x01, 0x02, 0x03]))])  # unknown type of identity
    add(0x01, [ie(0x05, bytes([0x07]))])                   # type 7

    # Message Transmission Control
    for a, b in ((0x00, 0x00), (0x0f, 0x07), (0x0a, 0x02), (0x05, 0xff)):
        add(0x01, [ie(0x07, bytes([a, b]))])

    # Authentication Challenge Parameter
    add(0x01, [ie(0x06, bytes([0x01]) + struct.pack('>I', 0xdeadbeef))])
    add(0x01, [ie(0x06, bytes([0x00]))])
    add(0x01, [ie(0x06, bytes([0x0f]))])
    add(0x01, [ie(0x06, bytes([0xf1]) + struct.pack('>I', 0x01020304))])

    # Service Option
    for so in (0x003B, 0x5900, 0x0001, 0x007f, 0x8000):
        add(0x06, [ie(0x0A, struct.pack('>H', so))])

    # Reference Cell ID
    for d in (bytes([0, 0, 0, 0, 0]), bytes([0xff, 0xff, 0xff, 0xff, 0xff]),
              bytes([0x00, 0x7b, 0x01, 0x12, 0x34])):
        add(0x08, [ie(0x0D, d)])

    # 1x LAC Encapsulated PDU and 1x Parameters of several lengths
    for n in (1, 3, 4, 40, 255):
        add(0x01, [ie(0x01, bytes((i * 7) & 0xff for i in range(n)))])
    for n in (1, 16, 200):
        add(0x03, [ie(0x02, bytes((i * 3) & 0xff for i in range(n)))])

    # GCSNA Status: all combinations
    add(0x01, [gcsna_status()])
    add(0x01, [gcsna_status(status=1)])
    add(0x01, [gcsna_status(status=2, gec=1)])
    add(0x01, [gcsna_status(priority=5)])                  # fix reproducer
    add(0x01, [gcsna_status(status=1, priority=15, gec=1)])
    add(0x01, [gcsna_status(status=3, priority=0)])

    # Mobile Subscription Information
    add(0x06, [mob_sub([band_rec([(0, True, []), (1, False, [0x05]), (5, True, [0xff]),
                                  (0x14, False, [0x81]), (0x55, True, [0x01])]),
                        band_rec([(7, True, [0x0a]), (8, False, [])], all_bands=False, cur_sub=0x7f)])])
    # Records of other identifiers are shown as raw content
    add(0x06, [mob_sub([bytes([0x01, 0x03, 0xaa, 0xbb, 0xcc]),
                        band_rec([(2, True, [0x03])]),
                        bytes([0x7f, 0x00])])])
    add(0x06, [mob_sub([band_rec([])])])
    # a band class list across all 21 defined classes: names in the item text
    add(0x06, [mob_sub([band_rec([(bc, False, [bc]) for bc in range(0, 22)])])])

    # Pilot List: every Cell ID Info value, reference pilot and delay combinations
    add(0x08, [pilot_list([pilot(cell_info=0)])])
    add(0x08, [pilot_list([pilot(cell_info=1, cell_data=bytes([0, 1, 2, 0x12, 0x34]), ref=True),
                          pilot(cell_info=2, cell_data=bytes([0, 1, 2, 0x12, 0x35]), ref=False,
                                delay=0x0102)])])
    add(0x08, [pilot_list([pilot(cell_info=3, cell_data=bytes([3, 4, 5, 0x56, 0x78]), delay=0xffff)])])
    add(0x08, [pilot_list([pilot(cell_info=7, cell_data=bytes([9, 8, 7, 0x00, 0x01]), ref=False)])])
    for ci in (4, 5, 6):
        add(0x08, [pilot_list([pilot(cell_info=ci, cell_data=bytes([16]) + bytes(range(16))),
                              pilot(cell_info=ci, cell_data=bytes([1, 0xaa]), ref=False, delay=3),
                              pilot(cell_info=ci, cell_data=bytes([0]), ref=True)])])
    add(0x08, [pilot_list([pilot(ch_rec=bytes([0x01, 0x40 | 0x05, 0x55]), cell_info=0),
                          pilot(ch_rec=bytes([0x02, 0xa0, 0x07]), cell_info=0xf8),
                          pilot(ch_rec=bytes([0x00, 0xf8 | 0x07, 0xff]), cell_info=0x08, strength=0x3f),
                          pilot(ch_rec=bytes([0x00, 0x00, 0x00]), cell_info=0, ref=False, strength=0)])])
    add(0x08, [pilot_list([])])
    # Pilot List fix reproducers: HRPD Sector ID of 16 octets, and the Pilot
    # item length with a Channel Record subtree
    add(0x08, [pilot_list([pilot(cell_info=4, cell_data=bytes([16]) + bytes(range(16)))])])
    # many pilots
    add(0x08, [pilot_list([pilot(pn=i * 5, strength=i, cell_info=(i % 3 and 0) or 0) for i in range(30)])])

    # GCSNA PDU carrying GCSNA messages (the gcsna dissector sets the protocol column)
    add(0x01, [ie(0xC0, bytes([0x02, 0x15]))])                       # L2 Ack
    for cause, extra in ((0, [2, 0x00, 0x08]), (2, [1, 0x08, 0x05]), (1, [6]), (3, [0x77]),
                         (5, [2, 1, 2]), (4, [0x55]), (9, [0xaa, 0xbb])):
        add(0x01, [ie(0xC0, bytes([0x03]) + bits_servicereject(5, cause, extra))])
    add(0x01, [ie(0xC0, bytes([0x01, 0x00, 0x00, 0x00]) + CDMA2K_ORDER)])      # circuit service
    bits = '1' + '00000010' + '00000001' + '00001000' + '1' + '1010101010101010' + '1' + '0' + '000101' + '01'
    bits += '0' * ((8 - len(bits) % 8) % 8)
    add(0x01, [ie(0xC0, bytes([0x01, 0x08]) + bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
                  + CDMA2K_ORDER)])                                   # alternative options, IWS ID
    add(0x01, [ie(0xC0, bytes([0x02, 0x00])), ie(0x0C, bytes([0x01, 0x01]))])

    # Unknown IEs ("IE data not dissected yet") before and after known ones
    add(0x01, [ie(0x30, bytes([1, 2, 3])), ie(0x08, bytes([0x03]))])
    add(0x01, [ie(0x08, bytes([0x03])), ie(0x3f, b''), ie(0xff, bytes([9]))])
    add(0x01, [ie(0x0E, bytes([9, 9]))])

    # Different source ports, and A21 over a port that is not 23272 is not tried
    add(0x01, [ie(0x08, bytes([0x01]))], sport=23272, dport=45678)
    add(0x02, [ie(0x08, bytes([0x04]))], sport=23272, dport=23272)

    # Exported PDU: a21, same payload as frame 12
    F.append(exppdu('a21', hdr(0x01, 99) + ie(0x04, struct.pack('>I', 7)) + ie(0x08, bytes([0x03]))))
    F.append(exppdu('a21', hdr(0x08, 100) + pilot_list([pilot(cell_info=4, cell_data=bytes([4, 1, 2, 3, 4]))])
                    + mn_id_imsi('001019876543210')))
    return F


def malformed_frames():
    F = []

    def raw(p, **kw):
        F.append(udp_frame(p, **kw))

    # header shorter than 7 octets
    raw(bytes([0x01]))
    raw(bytes([0x01, 0x04, 0x04, 0, 0]))
    # IE list: a single type octet (no length)
    raw(hdr(1) + bytes([0x08]))
    # GCSNA PDU IE with a single length octet
    raw(hdr(1) + bytes([0xC0, 0x00]))
    # IE length past the end
    raw(hdr(1) + bytes([0x08, 5, 3]))
    raw(hdr(1) + bytes([0x05, 20, 0x06, 0x01]))
    raw(hdr(1) + bytes([0xC0, 0x00, 0x20, 0x02]))
    # IE bodies shorter than the dissector reads
    raw(hdr(1) + bytes([0x04, 0]) + bytes([0x08, 1, 0x03]))              # corr id len 0
    raw(hdr(1) + bytes([0x04, 2, 0, 7]))
    raw(hdr(1) + bytes([0x03, 2, 1, 0]) + bytes([0x08, 1, 3, 0x08, 1, 3]))   # pilot list
    raw(hdr(1) + bytes([0x03, 0]))
    raw(hdr(1) + bytes([0x03, 3, 1, 3, 0]))                              # truncated channel record
    raw(hdr(1) + bytes([0x03, 8, 1, 3, 0, 8, 0x10, 0x04, 0xff, 0x00]))   # HRPD length 255
    raw(hdr(1) + bytes([0x03, 9, 1, 3, 0, 8, 0x10, 0x01, 1, 2]))        # cell id info 1, cut
    raw(hdr(1) + bytes([0x03, 9, 1, 3, 0, 8, 0x10, 0x00, 0x80, 0x01]))  # pn cut
    raw(hdr(1) + bytes([0x03, 11, 1, 3, 0, 8, 0x10, 0x00, 0x80, 0x01, 0x45]))  # delay cut
    raw(hdr(1) + bytes([0x03, 5, 200, 3, 0, 8, 0x10]))                   # 200 pilots, cut
    raw(hdr(1) + bytes([0x05, 0]))
    raw(hdr(1) + bytes([0x05, 1, 0x05]))                                # ESN without ESN octet
    raw(hdr(1) + bytes([0x05, 1, 0x06]))                                # IMSI without digits
    raw(hdr(1) + bytes([0x07, 1, 0x0f]))
    raw(hdr(1) + bytes([0x07, 0]))
    raw(hdr(1) + bytes([0x06, 0]))
    raw(hdr(1) + bytes([0x06, 1, 0x01]))                                # RAND value missing
    raw(hdr(1) + bytes([0x06, 3, 0x01, 1, 2]))
    raw(hdr(1) + bytes([0x08, 0]))
    raw(hdr(1) + bytes([0x09, 0]))
    raw(hdr(1) + bytes([0x09, 2, 0x07, 0x12]))
    raw(hdr(1) + bytes([0x09, 2, 0x01, 0x12]))
    raw(hdr(1) + bytes([0x0A, 1, 0x00]))
    raw(hdr(1) + bytes([0x0A, 0]))
    raw(hdr(1) + bytes([0x0D, 3, 1, 2, 3]))
    raw(hdr(1) + bytes([0x0D, 0]))
    raw(hdr(1) + bytes([0x0C, 0]))
    raw(hdr(1) + bytes([0x0C, 1, 0x01]))                                # status missing
    raw(hdr(1) + bytes([0x0C, 1, 0x04]))                                # priority missing
    raw(hdr(1) + bytes([0x0C, 2, 0x05, 0x01]))
    raw(hdr(1) + bytes([0x0B, 1, 0x00]))
    raw(hdr(1) + bytes([0x0B, 3, 0x00, 0x20, 0x80]))                    # record longer than IE
    raw(hdr(1) + bytes([0x0B, 5, 0x00, 0x03, 0x80, 0x01, 0x8f]))        # subclass length past end
    raw(hdr(1) + bytes([0x0B, 4, 0x01, 0x20, 1, 2]))                    # other record, length past end
    raw(hdr(1) + bytes([0x0B, 2, 0x00, 0x00]))
    raw(hdr(1) + bytes([0x01, 0]) + bytes([0x08, 1, 3]))                # empty LAC PDU, then more
    raw(hdr(1) + bytes([0x02, 0]))
    raw(hdr(1) + bytes([0x30, 5, 1]))                                   # unknown IE past the end
    # GCSNA PDU with malformed GCSNA content
    raw(hdr(1) + bytes([0xC0, 0x00, 0x01, 0x01]))                        # circuit service, cut
    raw(hdr(1) + bytes([0xC0, 0x00, 0x01, 0x03]))                        # service reject, cut
    raw(hdr(1) + bytes([0xC0, 0x00, 0x03, 0x03, 0x00, 0x00, 0x05]))     # reject cause 0, count cut
    raw(hdr(1) + bytes([0xC0, 0x00, 0x01, 0x09, 0x7f]))                 # unknown GCSNA message
    raw(hdr(1) + bytes([0xC0, 0x00, 0x00]))                            # empty GCSNA message
    raw(hdr(1) + ie(0xC0, bytes([0x03]) + bits_servicereject(5, 4, [])))   # reject, no sequence
    raw(hdr(1) + ie(0xC0, bytes([0x01, 0x00, 0x00]) + bytes(4)))          # circuit service, CDMA2K cut
    F.append(exppdu('a21', bytes([0x01, 0x04])))
    F.append(exppdu('a21', hdr(1) + bytes([0x04, 3, 0, 0, 7])))
    return F


def main():
    out = sys.argv[1]
    pcapng(os.path.join(out, 'a21-coverage.pcapng'), main_frames())
    pcapng(os.path.join(out, 'a21-coverage-malformed.pcapng'), malformed_frames())
    if '-v' in sys.argv:
        print(len(main_frames()), len(malformed_frames()))


main()

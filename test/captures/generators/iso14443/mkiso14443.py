#!/usr/bin/env python3
# Generates test/captures/iso14443_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISO 14443 coverage captures (pcap link type 264, the
# "ISO 14443 with pseudo header" format). Usage: mkiso14443.py <outdir>
# Everything is synthetic: made-up UIDs, PUPIs, historical bytes and APDUs.
import struct
import sys
import os


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))

EVT_PICC_PCD = 0xFF
EVT_PCD_PICC = 0xFE
EVT_FIELD_OFF = 0xFD
EVT_FIELD_ON = 0xFC
EVT_PICC_PCD_NOCRC = 0xFB
EVT_PCD_PICC_NOCRC = 0xFA


def crc_a(b):
    """CRC_A of ISO/IEC 14443-3 (initial value 0x6363, reflected 0x1021)."""
    crc = 0x6363
    for ch in b:
        ch ^= crc & 0xff
        ch = (ch ^ (ch << 4)) & 0xff
        crc = (crc >> 8) ^ (ch << 8) ^ (ch << 3) ^ (ch >> 4)
    return struct.pack('<H', crc & 0xffff)


def crc_b(b):
    """CRC_B: CRC-16/X-25 (initial value 0xFFFF, complemented)."""
    crc = 0xFFFF
    for ch in b:
        crc ^= ch
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return struct.pack('<H', crc ^ 0xFFFF)


def rec(event, payload=b''):
    return struct.pack('!BBH', 0, event, len(payload)) + payload


class Card:
    """Builds the records. kind selects the CRC (A or B); dropped=True uses
    the "CRC bytes were dropped" events, crc=False sends the frame as it is
    (short frames without CRC)."""
    def __init__(self, kind='A'):
        self.kind = kind
        self.frames = []

    def crc(self, b):
        return crc_a(b) if self.kind == 'A' else crc_b(b)

    def tx(self, payload, crc=True, dropped=False):      # reader -> card
        if dropped:
            self.frames.append(rec(EVT_PCD_PICC_NOCRC, payload))
        else:
            self.frames.append(rec(EVT_PCD_PICC, payload + (self.crc(payload) if crc else b'')))

    def rx(self, payload, crc=True, dropped=False):      # card -> reader
        if dropped:
            self.frames.append(rec(EVT_PICC_PCD_NOCRC, payload))
        else:
            self.frames.append(rec(EVT_PICC_PCD, payload + (self.crc(payload) if crc else b'')))

    def raw(self, event, payload=b''):
        self.frames.append(rec(event, payload))


def bcc(b):
    x = 0
    for ch in b:
        x ^= ch
    return bytes([x])


def apdu_select(aid):
    return bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + b'\x00'


def build_a(c):
    c.raw(EVT_FIELD_ON)
    c.tx(b'\x26', crc=False)                  # REQA
    c.rx(b'\x44\x00', crc=False)              # ATQA, 7 octet UID
    c.tx(b'\x93\x20', crc=False)              # anticollision, cascade level 1
    u1 = b'\x88\x04\x05\x06'
    c.rx(u1 + bcc(u1), crc=False)             # CT + UID part + BCC
    c.tx(b'\x93\x70' + u1 + bcc(u1))         # select
    c.rx(b'\x04')                             # SAK, UID not complete
    c.tx(b'\x95\x20', crc=False)
    u2 = b'\x07\x08\x09\x0a'
    c.rx(u2 + bcc(u2), crc=False)
    c.tx(b'\x95\x70' + u2 + bcc(u2))
    c.rx(b'\x20')                             # SAK, ISO 14443-4 compliant
    c.tx(b'\xe0\x50')                         # RATS, FSD 64, CID 0
    # ATS: TL, T0 (TA1, TB1, TC1, FSCI 8), TA1, TB1, TC1, historical bytes
    c.rx(bytes([0x0a, 0x78, 0x77, 0x81, 0x03]) + b'\x80\x31\x80\x00\x00')
    # I-block with NAD (reproducer of the NAD fix), block 0, CRC dropped
    c.tx(bytes([0x06, 0x12]) + apdu_select(bytes.fromhex('A0000000041010')), dropped=True)
    c.rx(bytes([0x02]) + b'\x6f\x10\x84\x07\xa0\x00\x00\x00\x04\x10\x10\x90\x00')
    # I-block with CID (block 1), not chained
    c.tx(bytes([0x0b, 0x01]) + b'\x80\xca\x9f\x7f\x00')
    c.rx(bytes([0x0a, 0x01]) + b'\x9f\x7f\x02\x01\x02\x90\x00')
    # command chained in two I-blocks (reassembly), R(ACK) in between
    c.tx(bytes([0x12]) + b'\x80\xd6\x00\x00\x20' + bytes(range(11)))
    c.rx(bytes([0xa3]))                       # R(ACK), block 1
    c.tx(bytes([0x03]) + bytes(range(11, 32)))
    c.rx(bytes([0x03]) + b'\x90\x00')
    # R(NAK) and R(ACK) with CID
    c.tx(bytes([0xb2]))                       # R(NAK), block 0
    c.rx(bytes([0xaa, 0x03]))                 # R(ACK) with CID
    # WTX: request from the card (with power level), response from the reader
    c.rx(bytes([0xf2, 0x41]))
    c.tx(bytes([0xf2, 0x01]))
    c.tx(bytes([0xfa, 0x05, 0x01]))           # S-block, CID following (WTX)
    # a 300 octet APDU in one I-block (reproducer of the length fix)
    c.tx(bytes([0x02]) + bytes((i * 7) & 0xff for i in range(256)) + bytes(44), dropped=True)
    c.rx(bytes([0x03]) + b'\x90\x00', dropped=True)
    # HLTA
    c.tx(b'\x50\x00')
    c.raw(EVT_FIELD_OFF)
    # WUPA (0x52), ATQA with a 4 and 10 octet UID
    c.raw(EVT_FIELD_ON)
    c.tx(b'\x52', crc=False)
    c.rx(b'\x04\x00', crc=False)
    c.tx(b'\x93\x20', crc=False)
    u = b'\x11\x22\x33\x44'
    c.rx(u + bcc(u), crc=False)
    c.tx(b'\x93\x70' + u + bcc(u), dropped=True)
    c.rx(b'\x28', dropped=True)               # SAK, not ISO 14443-4 compliant
    c.tx(b'\x52', crc=False)
    c.rx(b'\x84\x00', crc=False)
    c.raw(EVT_FIELD_OFF)


def build_b(c):
    c.raw(EVT_FIELD_ON)
    c.tx(b'\x05\x00\x08')                    # REQB, AFI 0, N=1
    # ATQB: 0x50, PUPI, application data, protocol info (3), CRC
    atqb = b'\x50\xde\xad\xbe\xef' + b'\x00\x00\x00\x00' + bytes([0x81, 0x81, 0x01])
    c.rx(atqb)
    c.tx(b'\x05\x00\x18')                    # WUPB, extended ATQB
    # ATQB with ADC (application data coding), 4 octets protocol info
    atqb = b'\x50\xde\xad\xbe\xef' + bytes([0x00, 0x00, 0x00, 0x00]) + bytes([0x88, 0x71, 0x45, 0x03])
    c.rx(atqb)
    # protocol info 3, ADC set, NAD+CID, max frame size code 5, bit rate
    # capabilities not applicable (b4 set)
    atqb = b'\x50\xde\xad\xbe\xef' + bytes([0x01, 0x02, 0x03, 0x04]) + bytes([0x08, 0x52, 0x06])
    c.rx(atqb, dropped=True)
    # Attrib: PUPI, params 1-4, no higher layer INF
    c.tx(b'\x1d\xde\xad\xbe\xef' + bytes([0x00, 0x08, 0x01, 0x01]))
    c.rx(bytes([0x00]))                       # response to Attrib: MBLI 0, CID 0
    # I-block, now with CRC_B
    c.tx(bytes([0x02]) + apdu_select(bytes.fromhex('A000000003101001')))
    c.rx(bytes([0x02]) + b'\x90\x00')
    # Attrib with higher layer INF and CRC dropped, response with INF
    c.tx(b'\x1d\xde\xad\xbe\xef' + bytes([0x00, 0x08, 0x01, 0x01]) + b'\x01\x02', dropped=True)
    c.rx(bytes([0x10]) + b'\x01\x02', dropped=True)
    # HLTB-like (not B): second REQB in the same session, then the field goes
    c.tx(b'\x05\x00\x00')
    c.rx(b'\x50' + b'\x00' * 11, dropped=True)
    c.raw(EVT_FIELD_OFF)
    # REQB with CRC dropped
    c.tx(b'\x05\x00\x08', dropped=True)
    c.rx(b'\x50\xde\xad\xbe\xef' + bytes(4) + bytes([0x81, 0x81, 0x01, 0x40]), dropped=True)


def main(outdir):
    c = Card('A')
    build_a(c)
    cb = Card('B')
    build_b(cb)
    # a block with the reserved block type 01 as the answer to an I-block
    cb.tx(bytes([0x02, 0x01]), dropped=True)
    cb.rx(bytes([0x42, 0x33]), dropped=True)
    # the first frame is a card answer without a command before it (no
    # transaction): it is only shown as the pseudo header
    first = [rec(EVT_PICC_PCD, b'\x00\x00')]
    write_pcap(os.path.join(outdir, 'iso14443-coverage.pcap'), 264, first + c.frames + cb.frames)
    write_malformed(outdir)


def write_malformed(outdir):
    c = Card('A')
    c.raw(EVT_FIELD_ON)
    # ATQA with the reserved UID size bits (invalid UID size warning)
    c.tx(b'\x26', crc=False)
    c.rx(b'\xc4\x00', crc=False)
    # wrong CRC (select, RATS)
    c.tx(b'\xe0\x50\x00\x00')
    c.rx(bytes([0x05, 0x78, 0x00, 0x00, 0x00]), crc=False)
    # unknown command
    c.tx(b'\x77\x77\x77')
    c.rx(b'\x77\x77\x77')
    # ISO 14443 header with a wrong length field, wrong version, unknown event
    c.frames.append(struct.pack('!BBH', 0, EVT_PCD_PICC, 7) + b'\x26')
    c.frames.append(struct.pack('!BBH', 1, EVT_PCD_PICC, 1) + b'\x26')
    c.frames.append(struct.pack('!BBH', 0, 0x10, 1) + b'\x26')
    # fewer than 4 octets
    c.frames.append(b'\x00\xfe')
    # I-block shorter than the CRC (negative INF length), I-block that
    # ends inside the CID/NAD bytes, an I-block without INF
    c.tx(bytes([0x02]), crc=False)
    c.tx(bytes([0x02, 0x00]), crc=False)
    c.tx(bytes([0x06]), crc=False)
    c.tx(bytes([0x0a]), crc=False)
    c.tx(bytes([0x02]), crc=True)
    c.tx(bytes([0x02]), dropped=True)
    c.rx(bytes([0x02]), dropped=True)
    # S(DESELECT): the dissector expects one octet of INF, which a
    # DESELECT does not have (the CRC is then cut)
    c.tx(bytes([0xc2]), crc=True)
    c.rx(bytes([0xc2]), crc=True)
    # truncated messages of every type
    for cmd in (b'\x50', b'\x93\x70', b'\xe0', b'\x1d\xde\xad', b'\x05\x00', b'\xa2', b'\xc2'):
        c.tx(cmd, crc=False)
    c.raw(EVT_FIELD_OFF)
    # responses: ATS too short, ATQB too short, Attrib response empty
    c.tx(b'\xe0\x50')
    c.rx(bytes([0x0a]), crc=False)
    c.tx(b'\xe0\x50')
    c.rx(b'', crc=False)
    c.tx(b'\x05\x00\x08')
    c.rx(b'\x50\xde\xad', crc=False)
    c.tx(b'\x1d\xde\xad\xbe\xef\x00\x08\x01\x01')
    c.rx(b'', crc=False)
    write_pcap(os.path.join(outdir, 'iso14443-coverage-malformed.pcap'), 264, c.frames)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

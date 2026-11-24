#!/usr/bin/env python3
# Generates test/captures/bthci_iso_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-bthci_iso.c coverage.
# Usage: mkbthci_iso.py <outdir>
# Writes bthci_iso-coverage.pcap (main, H4 with direction, DLT 201),
# bthci_iso-coverage-malformed.pcap (DLT 201),
# bthci_iso-coverage-nodir.pcap (H4 without direction, DLT 187) and
# bthci_iso-coverage-epdu.pcap (Exported PDU, DLT 252).
# Every packet is built here with struct; nothing is captured from a
# real network.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

DLT_H4 = 187
DLT_H4_PHDR = 201
DLT_EXPORTED_PDU = 252

SENT, RECV = 0, 1

LOCAL = bytes.fromhex('001bdc000001')      # display order
REMOTE = bytes.fromhex('c0ffee0000c4')     # LE peer
REMOTE2 = bytes.fromhex('c0ffee0000d5')    # LE peer without a name

ACL = 0x0040     # LE ACL connection handle
CIS1 = 0x0060    # CIS on ACL, from LE Create CIS
CIS2 = 0x0061    # CIS on ACL, from LE CIS Request
BIS = 0x0070     # BIS of a BIG, no ACL connection
ACL2 = 0x0041    # second LE ACL connection handle
CIS3 = 0x0062    # CIS on ACL2


def pcap(path, linktype, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def phdr(direction, pkt):
    return struct.pack('>I', direction) + pkt


def epdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def bd(a):
    return a[::-1]


def cmd(opcode, params):
    return phdr(SENT, b'\x01' + struct.pack('<HB', opcode, len(params)) + params)


def evt(code, params):
    return phdr(RECV, b'\x04' + struct.pack('<BB', code, len(params)) + params)


def cmd_complete(opcode, ret):
    return evt(0x0e, struct.pack('<BH', 1, opcode) + ret)


def cmd_status(opcode):
    return evt(0x0f, struct.pack('<BBH', 0, 1, opcode))


def name248(s):
    return s.encode().ljust(248, b'\0')


def iso_raw(handle, pb, ts, payload, length=None):
    if length is None:
        length = len(payload)
    return b'\x05' + struct.pack('<HH', (handle & 0xfff) | (pb << 12) | (ts << 14), length) + payload


def iso(direction, handle, pb, ts, payload, length=None):
    return phdr(direction, iso_raw(handle, pb, ts, payload, length))


def sdu_hdr(seq, sdu_len, status=0, timestamp=None):
    h = struct.pack('<HH', seq, sdu_len | (status << 14))
    if timestamp is not None:
        h = struct.pack('<I', timestamp) + h
    return h


def cis_established(handle):
    return evt(0x3e, b'\x19' + struct.pack('<BH', 0, handle)
               + (struct.pack('<I', 1000)[:3]) * 4
               + bytes([2, 2, 2, 1, 1, 1, 1]) + struct.pack('<HHH', 120, 120, 8))


def setup():
    """Local address and name, LE connection to REMOTE with a name, CIS1
    created by the host, CIS2 requested by the peer."""
    p = []
    p.append(cmd(0x1009, b''))                                              # 1 Read BD_ADDR
    p.append(cmd_complete(0x1009, b'\x00' + bd(LOCAL)))                     # 2
    p.append(cmd(0x0c14, b''))                                              # 3 Read Local Name
    p.append(cmd_complete(0x0c14, b'\x00' + name248('ws-local')))           # 4
    le = struct.pack('<BBHBB', 0x01, 0, ACL, 0, 0) + bd(REMOTE) + struct.pack('<HHHB', 0x18, 0, 0x48, 0)
    p.append(evt(0x3e, le))                                                 # 5 LE Connection Complete
    p.append(cmd(0x0419, bd(REMOTE) + struct.pack('<BBH', 1, 0, 0)))         # 6 Remote Name Request
    p.append(evt(0x07, b'\x00' + bd(REMOTE) + name248('ws-earbud')))        # 7 Remote Name Request Complete
    p.append(cmd(0x2064, struct.pack('<BHH', 1, CIS1, ACL)))                # 8 LE Create CIS
    p.append(cmd_status(0x2064))                                            # 9
    p.append(cis_established(CIS1))                                         # 10 LE CIS Established
    p.append(evt(0x3e, b'\x1a' + struct.pack('<HHBB', ACL, CIS2, 1, 2)))    # 11 LE CIS Request
    p.append(cmd(0x2066, struct.pack('<H', CIS2)))                          # 12 LE Accept CIS Request
    p.append(cmd_status(0x2066))                                            # 13
    p.append(cis_established(CIS2))                                         # 14 LE CIS Established
    return p


def main_capture():
    p = setup()
    # 15-16: complete SDUs without timestamp, both ways (sent ones have
    # no status flag)
    p.append(iso(SENT, CIS1, 2, 0, sdu_hdr(1, 4) + b'\x01\x02\x03\x04'))                    # 15
    p.append(iso(RECV, CIS1, 2, 0, sdu_hdr(1, 4) + b'\x05\x06\x07\x08'))                    # 16
    # 17-20: complete SDUs with timestamp, status 0-3 (3 is RFU), lost
    # data with no SDU
    p.append(iso(RECV, CIS1, 2, 1, sdu_hdr(2, 2, 0, 0x00010000) + b'\xaa\xbb'))             # 17 valid
    p.append(iso(RECV, CIS1, 2, 1, sdu_hdr(3, 2, 1, 0x00012710) + b'\xcc\xdd'))             # 18 possibly invalid
    p.append(iso(RECV, CIS1, 2, 1, sdu_hdr(4, 0, 2, 0x00014e20)))                          # 19 lost data
    p.append(iso(RECV, CIS1, 2, 0, sdu_hdr(5, 1, 3) + b'\xee'))                             # 20 status 3
    p.append(iso(SENT, CIS1, 2, 1, sdu_hdr(2, 3, 0, 0x00020000) + b'abc'))                  # 21 sent, timestamp
    # 22-24: received SDU in three fragments, no timestamp
    sdu = bytes(range(0x40, 0x60))                                                          # 32 octets
    p.append(iso(RECV, CIS1, 0, 0, sdu_hdr(6, len(sdu)) + sdu[:8]))                         # 22 first
    p.append(iso(RECV, CIS1, 1, 0, sdu[8:20]))                                              # 23 continuation
    p.append(iso(RECV, CIS1, 3, 0, sdu[20:]))                                               # 24 last
    # 25-28: received SDU with timestamp in the first of two fragments
    # (the reassembled SDU shows timestamp, sequence number and SDU
    # length), a sent complete SDU in between
    sdu = b'timestamped SDU!'                                                               # 16 octets
    p.append(iso(RECV, CIS1, 0, 1, sdu_hdr(7, len(sdu), 0, 0x11111111) + sdu[:4]))          # 25 first, TS
    p.append(iso(SENT, CIS1, 2, 0, sdu_hdr(3, 1) + b'x'))                                   # 26
    p.append(iso(RECV, CIS1, 3, 0, sdu[4:]))                                                # 27 last
    # 28: stray last fragment after the completed SDU (not attached to it)
    p.append(iso(RECV, CIS1, 3, 0, b'CCCC'))                                                # 28
    # 29-31: sent SDU in fragments interleaved with a received one on CIS2
    sdu = b'0123456789'
    p.append(iso(SENT, CIS2, 0, 0, sdu_hdr(1, len(sdu)) + sdu[:3]))                         # 29 first
    p.append(iso(RECV, CIS2, 2, 0, sdu_hdr(1, 2) + b'rx'))                                  # 30 complete
    p.append(iso(SENT, CIS2, 3, 0, sdu[3:]))                                                # 31 last
    # 32-37: BIG with one BIS (no ACL connection: "remote ()"), the
    # first SDU starts with a continuation whose first fragment is not
    # in the capture
    big = struct.pack('<BB', 0, 1) + struct.pack('<I', 2000)[:3] * 2 + bytes([2, 1, 1, 0, 1]) \
        + struct.pack('<HHB', 40, 8, 1) + struct.pack('<H', BIS)
    p.append(cmd(0x2068, struct.pack('<BBB', 1, 0, 1) + struct.pack('<I', 10000)[:3]
                 + struct.pack('<HHBBBBB', 40, 10, 2, 2, 0, 0, 0) + bytes(16)))                 # 32 LE Create BIG
    p.append(cmd_status(0x2068))                                                            # 33
    p.append(evt(0x3e, b'\x1b' + big))                                                      # 34 LE Create BIG Complete
    p.append(iso(SENT, BIS, 1, 0, b'orphan'))                                               # 35 continuation, no first
    p.append(iso(SENT, BIS, 3, 0, b'orphan'))                                               # 36 last, no first
    p.append(iso(SENT, BIS, 2, 1, sdu_hdr(1, 4, 0, 0x00030000) + b'bis!'))                  # 37 complete
    # 38-41: a received SDU on CIS2, then CIS1 is disconnected
    p.append(iso(RECV, CIS2, 2, 0, sdu_hdr(2, 2) + b'ok'))                                  # 38
    p.append(cmd(0x0406, struct.pack('<HB', CIS1, 0x13)))                                   # 39 Disconnect
    p.append(cmd_status(0x0406))                                                            # 40
    p.append(evt(0x05, struct.pack('<BHB', 0, CIS1, 0x16)))                                 # 41 Disconnection Complete
    # 42-46: a second LE connection, to a peer without a known name, and
    # a CIS on it
    le = struct.pack('<BBHBB', 0x01, 0, ACL2, 0, 1) + bd(REMOTE2) + struct.pack('<HHHB', 0x18, 0, 0x48, 0)
    p.append(evt(0x3e, le))                                                                 # 42 LE Connection Complete
    p.append(cmd(0x2064, struct.pack('<BHH', 1, CIS3, ACL2)))                               # 43 LE Create CIS
    p.append(cmd_status(0x2064))                                                            # 44
    p.append(cis_established(CIS3))                                                         # 45 LE CIS Established
    p.append(iso(SENT, CIS3, 2, 0, sdu_hdr(1, 3) + b'new'))                                 # 46
    return p


def malformed_capture():
    p = setup()
    # 15: complete SDU with Data Total Length shorter than the data
    p.append(iso(RECV, CIS1, 2, 0, sdu_hdr(1, 4) + b'abcdef', length=8))
    # 16: complete SDU whose SDU length is larger than the data
    p.append(iso(RECV, CIS1, 2, 0, sdu_hdr(2, 10) + b'abcd'))
    # bthci_iso_reasm_edges.py (the "Invalid length"
    # warnings appear in the first pass only):
    # 17-19: large claimed SDU, a short last fragment
    p.append(iso(RECV, 0x61, 0, 0, sdu_hdr(1, 4000) + b'A' * 10))
    p.append(iso(RECV, 0x61, 1, 0, b'B' * 20))
    p.append(iso(RECV, 0x61, 3, 0, b'C' * 3))
    # 20-21: first fragment larger than its SDU (not stored), last
    p.append(iso(RECV, 0x62, 0, 0, sdu_hdr(1, 2) + b'A' * 10))
    p.append(iso(RECV, 0x62, 3, 0, b'D'))
    # 22-24: first fragment with the header only, an over-long
    # continuation (clipped), a last fragment after it
    p.append(iso(RECV, 0x63, 0, 0, sdu_hdr(1, 4)))
    p.append(iso(RECV, 0x63, 1, 0, b'E' * 50))
    p.append(iso(RECV, 0x63, 3, 0, b'F' * 5))
    # 25: truncated first fragment with timestamp (throws on every pass)
    p.append(iso(RECV, 0x64, 0, 1, b'\x00\x00'))
    # 26: bthci_iso_stale_last.py
    p.append(iso(RECV, 0x65, 0, 1, sdu_hdr(7, 8, 0, 0x11111111) + b'AAAA'))
    p.append(iso(RECV, 0x65, 3, 0, b'BBBB'))
    p.append(iso(RECV, 0x65, 3, 0, b'CCCC'))
    # 29: truncated header, 30: SDU header cut
    p.append(phdr(SENT, b'\x05\x60\x20'))
    p.append(iso(RECV, CIS1, 2, 1, b'\x01\x02\x03\x04\x05'))
    return p


def nodir_capture():
    # H4 without direction: "UnknownDirection", no source/destination
    return [iso_raw(CIS1, 2, 0, sdu_hdr(1, 2) + b'nd'),
            iso_raw(CIS1, 0, 0, sdu_hdr(2, 4) + b'n'),
            iso_raw(CIS1, 3, 0, b'dir')]


def epdu_capture():
    # bthci_iso_epdu_null.py: "bthci_iso_data" and
    # "bthci_iso" without dissector data return 0 (shown as data)
    return [epdu('bthci_iso_data', bytes.fromhex('01000400aabbccdd')),
            epdu('bthci_iso', bytes.fromhex('6020080001000400aabbccdd'))]


pcap(os.path.join(OUT, 'bthci_iso-coverage.pcap'), DLT_H4_PHDR, main_capture())
pcap(os.path.join(OUT, 'bthci_iso-coverage-malformed.pcap'), DLT_H4_PHDR, malformed_capture())
pcap(os.path.join(OUT, 'bthci_iso-coverage-nodir.pcap'), DLT_H4, nodir_capture())
pcap(os.path.join(OUT, 'bthci_iso-coverage-epdu.pcap'), DLT_EXPORTED_PDU, epdu_capture())

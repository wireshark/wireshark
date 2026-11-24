#!/usr/bin/env python3
# Generates test/captures/iso15765_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISO 15765 (ISO-TP)
dissector (packet-iso15765.c).

ISO 15765 is reached by default through LIN diagnostic frames (frame IDs
0x3c master request and 0x3d slave response). CAN, FlexRay (the ISO 15765
FlexRay variant) are reached through the Decode As tables
can.subdissector / flexray.subdissector or the CAN ID range preferences.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkiso15765.py <output directory>

Writes pcapng files with five interfaces:
  0  LINKTYPE_LIN (212)              LIN diagnostic frames, default reach
  1  LINKTYPE_CAN_SOCKETCAN (227)    CAN and CAN FD (needs -o/-d)
  2  LINKTYPE_FLEXRAY (210)          FlexRay (needs -d)
  3  LINKTYPE_ETHERNET (1)           PDU Transport over UDP port 30490
                                     (needs -d udp.port,30490,pdu_transport
                                     and the PDU transport config table)
  4  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming "iso15765"
                                     (no LIN/CAN information: rejected)

  iso15765-coverage.pcapng            every message type, reassembly,
                                      padding, FlowControl and the
                                      reproducers of the fixes
  iso15765-coverage-malformed.pcapng  bad message types and frames that
                                      only the error paths reach
"""

import os
import struct
import sys

T0 = 1700000000
CAN_EFF_FLAG = 0x80000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = (struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data))
            + pad4(data))
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


def write(path, frames):
    with open(path, 'wb') as f:
        f.write(shb() + idb(212) + idb(227) + idb(210) + idb(1) + idb(252))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.001, data))


def lin(frame_id, payload):
    """LINKTYPE_LIN record: revision, 3 reserved, length/type/checksum
    type, PID, checksum, errors, payload."""
    assert len(payload) <= 8
    hdr = bytes([1, 0, 0, 0, (len(payload) << 4) | 2, frame_id & 0x3f, 0, 0])
    return (0, hdr + payload)


def can(can_id, payload, fd=False):
    """LINKTYPE_CAN_SOCKETCAN (big endian CAN ID)."""
    if fd:
        return (1, struct.pack('>IBBBB', can_id, len(payload), 0x04, 0, 0) + payload)
    assert len(payload) <= 8
    return (1, struct.pack('>IBBBB', can_id, len(payload), 0, 0, 0) + payload.ljust(8, b'\0'))


def flexray(frame_id, cycle, payload, channel_b=False):
    """LINKTYPE_FLEXRAY: measurement header, error flags, 5 byte header,
    payload (even length), 3 byte CRC."""
    if len(payload) % 2:
        payload += b'\0'
    pl = len(payload) // 2
    hdr = bytes([0x20 | ((frame_id >> 8) & 7), frame_id & 0xff, (pl << 1) & 0xfe, 0, cycle & 0x3f])
    return (2, bytes([0x81 if channel_b else 0x01, 0]) + hdr + payload + b'\0\0\0')


def pdu_udp(pdu_id, payload, sport=40000, dport=30490):
    """Ethernet/IPv4/UDP frame with a PDU Transport PDU: 32 bit ID,
    32 bit length, payload."""
    pdu = struct.pack('>II', pdu_id, len(payload)) + payload
    udp = struct.pack('>HHHH', sport, dport, 8 + len(pdu), 0) + pdu
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([192, 168, 0, 1]), bytes([192, 168, 0, 2]))
    csum = sum(struct.unpack('>10H', ip))
    csum = (csum & 0xffff) + (csum >> 16)
    csum = (csum & 0xffff) + (csum >> 16)
    ip = ip[:10] + struct.pack('>H', (~csum) & 0xffff) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return (3, eth + ip + udp)


NAD = 0x10
REQ, RSP = 0x3c, 0x3d
CC = 0xcc


def sf(fid, data, nad=NAD):
    return lin(fid, bytes([nad, len(data)]) + data + bytes([CC] * (6 - len(data))))


def ff12(fid, total, data, nad=NAD):
    return lin(fid, bytes([nad, 0x10 | (total >> 8), total & 0xff]) + data)


def ff32(fid, total, data, nad=NAD):
    return lin(fid, bytes([nad, 0x10, 0x00]) + struct.pack('>I', total) + data)


def cf(fid, seq, data, nad=NAD, pad=True):
    if pad:
        data = data + bytes([CC] * (6 - len(data)))
    return lin(fid, bytes([nad, 0x20 | (seq & 15)]) + data)


def fc(fid, status, bs, stmin, nad=NAD):
    return lin(fid, bytes([nad, 0x30 | status, bs, stmin, CC, CC, CC, CC]))


def transfer(fid, data, nad=NAD, ff32bit=False, first_data=5):
    """Frames of one segmented transfer: FF plus CFs; the last one is
    padded with 0xCC."""
    frames = []
    if ff32bit:
        first = 1
        frames.append(ff32(fid, len(data), data[:first], nad))
    else:
        first = 5
        frames.append(ff12(fid, len(data), data[:first], nad))
    pos = first
    seq = 1
    while pos < len(data):
        frames.append(cf(fid, seq, data[pos:pos + 6], nad))
        pos += 6
        seq += 1
    return frames


def pat(n, base=0):
    return bytes((base + i) & 0xff for i in range(n))


def build_main():
    fr = []
    # Single frames, request and response, padded
    fr.append(sf(REQ, bytes([0x22, 0xf1, 0x90])))
    fr.append(sf(RSP, bytes([0x62, 0xf1, 0x90, 0x41, 0x42])))
    fr.append(sf(REQ, b''))                      # length 0
    fr.append(sf(RSP, bytes([0x7f, 0x22, 0x31])))
    fr.append(sf(REQ, bytes([0x3e, 0x00]), nad=0x7f))   # broadcast NAD
    fr.append(lin(RSP, bytes([NAD, 0x06, 1, 2, 3, 4, 5, 6])))   # 6 bytes, no padding
    # Flow control: every status, block size, STmin in ms and in us
    fr.append(fc(REQ, 0, 0, 0))
    fr.append(fc(RSP, 1, 4, 20))
    fr.append(fc(REQ, 2, 8, 0x7f))
    fr.append(fc(RSP, 0, 2, 0xf1))
    fr.append(fc(REQ, 0, 2, 0xf9))
    fr.append(fc(RSP, 0, 2, 0xf0))               # 0xF0 is not a us value
    fr.append(fc(REQ, 0, 2, 0xfa))
    # A transfer with a padded last frame: FF(5) + CFs of 6 = 20 bytes
    t1 = pat(20, 0x10)
    fr += transfer(RSP, t1)
    # A transfer with an exact last frame and a sequence number wrap (125 = 5 + 20 * 6)
    t2 = pat(125, 0x40)
    fr += transfer(REQ, t2)
    # Both directions interleaved (distinct reassemblies by frame ID)
    ta = pat(23, 0x01)
    tb = pat(17, 0x80)
    fa = transfer(REQ, ta)
    fb = transfer(RSP, tb, nad=0x20)
    for a, b in zip(fa, fb):
        fr += [a, b]
    fr += fa[len(fb):] + fb[len(fa):]
    # FF with a 32 bit length (escape) and a FC in between
    t3 = pat(12, 0xa0)
    ff = transfer(RSP, t3, ff32bit=True)
    fr += [ff[0], fc(REQ, 0, 0, 10)] + ff[1:]
    # Another transfer on the same ID directly after: new reassembly
    fr += transfer(RSP, pat(9, 0x30))
    # A transfer with a single CF that is not padded (7 bytes: 5 + 2... use 11 = 5 + 6)
    fr += transfer(REQ, pat(11, 0x55))
    # CF without a First Frame
    fr.append(cf(0x3e, 3, pat(6)))
    fr.append(cf(0x3d, 9, pat(6), nad=0x33))
    # Reproducer, ISO 15765 length underflow: FF announces 10 bytes, CF 5
    # arrives (CFs 1-4 are missing)
    fr.append(lin(RSP, bytes([0x21, 0x10, 0x0a, 1, 2, 3, 4, 5])))
    fr.append(lin(RSP, bytes([0x21, 0x25, 6, 7, 8, 9, 10, 11])))
    fr.append(lin(RSP, bytes([0x21, 0x26, 6, 7, 8, 9, 10, 11])))
    # A CF with an old sequence number after a much newer one: error in the
    # conversation (frag_id + window < last_frag_id), not reassembled
    fr.append(ff12(REQ, 200, pat(5), nad=0x22))
    fr.append(cf(REQ, 1, pat(6, 1), nad=0x22))
    fr.append(cf(REQ, 15, pat(6, 15), nad=0x22))
    fr.append(cf(REQ, 5, pat(6, 5), nad=0x22))
    fr.append(cf(REQ, 6, pat(6, 6), nad=0x22))
    # Reproducer, too many CFs with one sequence number is in the
    # malformed capture (it is an error expert info)
    # Segments up to 255 with the same sequence number: legitimate large
    # transfer, 255 CFs with sequence 1 fit (frag_id_high reaches 255)
    fr.append(ff32(RSP, 100000, b'\xaa', nad=0x44))
    for i in range(200):
        fr.append(cf(RSP, 1, pat(6, i), nad=0x44))

    # FlexRay-variant message types, which are dissected on any bus
    fr.append(lin(REQ, bytes([NAD, 0x40, 0x04, 1, 2, 3, 4, 0])))             # Single Frame Ext
    fr.append(lin(REQ, bytes([NAD, 0x50, 0, 0, 0, 12, 0xde])))               # First Frame Ext, 32 bit length
    fr.append(lin(REQ, bytes([NAD, 0x61, 1, 2, 3, 4, 5, 6])))                # Consecutive Frame 2
    fr.append(lin(REQ, bytes([NAD, 0x62, 7, 8, 9, 10, 11, 12])))
    fr.append(lin(RSP, bytes([NAD, 0x70, 0x04, 0x14, 0x21, 0, 0, 0])))       # Ack frame, ms
    fr.append(lin(RSP, bytes([NAD, 0x71, 0x04, 0xf2, 0x32, 0, 0, 0])))       # Ack frame, us
    # LIN frames that are not diagnostic frames: not ISO 15765
    fr.append(lin(0x10, pat(8)))
    return fr


def can_frames():
    """CAN and CAN FD (ISO 15765 over CAN needs -o iso15765.can.ids or
    -d can.subdissector,iso15765). Normal addressing: no address byte."""
    fr = []
    ID_REQ, ID_RSP = 0x7e0, 0x7e8
    fr.append(can(ID_REQ, bytes([0x03, 0x22, 0xf1, 0x90, CC, CC, CC, CC])))
    fr.append(can(ID_RSP, bytes([0x05, 0x62, 0xf1, 0x90, 0x41, 0x42, CC, CC])))
    # 20 byte transfer, FF has 6 data bytes
    d = pat(20, 0x20)
    fr.append(can(ID_RSP, bytes([0x10, 20]) + d[:6]))
    fr.append(can(ID_REQ, bytes([0x30, 0x00, 0x00, CC, CC, CC, CC, CC])))
    pos, seq = 6, 1
    while pos < len(d):
        chunk = d[pos:pos + 7]
        fr.append(can(ID_RSP, bytes([0x20 | seq]) + chunk + bytes([CC] * (7 - len(chunk)))))
        pos += 7
        seq += 1
    # Extended (29 bit) IDs: 0x19880000 | target << 8 | source, address mapping
    for tgt, src, body in ((0xf1, 0x10, bytes([0x02, 0x3e, 0x00])), (0x10, 0xf1, bytes([0x02, 0x7e, 0x00]))):
        fr.append(can(CAN_EFF_FLAG | 0x19880000 | (tgt << 8) | src, body + bytes([CC] * (8 - len(body)))))
    # Standard ID mapped with a single ECU address (low 4 bits)
    fr.append(can(0x6a3, bytes([0x02, 0x19, 0x02, CC, CC, CC, CC, CC])))
    fr.append(can(0x6a3, bytes([0x10, 0x09, 1, 2, 3, 4, 5, 6])))
    fr.append(can(0x6a3, bytes([0x21, 7, 8, 9, CC, CC, CC, CC])))
    # CAN FD: SF with CAN_DL > 8, escape sequence, FF with 12 bit length
    fr.append(can(0x7e2, bytes([0x00, 12]) + pat(12) + bytes([CC] * 6), fd=True))
    fr.append(can(0x7e2, bytes([0x05]) + pat(5) + bytes([CC] * 10), fd=True))   # SF with CAN_DL > 8 but length <= 15
    fr.append(can(0x7e3, bytes([0x10, 0x28]) + pat(14), fd=True))
    fr.append(can(0x7e3, bytes([0x21]) + pat(15, 14), fd=True))
    fr.append(can(0x7e3, bytes([0x22]) + pat(11, 29) + bytes([CC] * 4), fd=True))
    # FD FF with a 32 bit length
    fr.append(can(0x7e4, bytes([0x10, 0x00, 0, 0, 0x10, 0x00]) + pat(10), fd=True))
    # Address mapping with a wider target mask than source mask
    fr.append(can(0x5a1, bytes([0x02, 0x3e, 0x00, CC, CC, CC, CC, CC])))
    # I-PduM over CAN FD: CAN ID 0x300 carries two PDUs of 8 bytes, each
    # an ISO 15765 Single Frame (needs the I-PduM tables, -o iso15765.ipdum.pdu.id)
    fr.append(can(0x300, bytes([0x03, 0x22, 0xf1, 0x90, CC, CC, CC, CC]) + bytes([0x02, 0x3e, 0x00, CC, CC, CC, CC, CC]), fd=True))
    fr.append(can(0x300, bytes([0x10, 0x09, 1, 2, 3, 4, 5, 6]) + bytes([0x21, 7, 8, 9, CC, CC, CC, CC]), fd=True))
    return fr


def flexray_frames():
    """ISO 15765 over FlexRay (-d flexray.subdissector,iso15765): source
    and target address, then the PCI. The dissector keys a transfer on the
    frame ID and the cycle count, so all frames of a transfer use cycle 0."""
    fr = []
    sa, ta = 0x12, 0x34
    h = bytes([sa, ta])
    fr.append(flexray(20, 0, h + bytes([0x03, 0x22, 0xf1, 0x90])))
    fr.append(flexray(20, 0, h + bytes([0x40, 0x03, 0xaa, 0xbb, 0xcc])))   # SF Ext
    d = pat(24, 0x60)
    fr.append(flexray(21, 0, h + bytes([0x50, 0, 0, 0, 24]) + d[:7]))      # FF Ext
    pos, seq = 7, 1
    while pos < len(d):
        fr.append(flexray(21, 0, h + bytes([0x60 | seq]) + d[pos:pos + 12].ljust(12, bytes([CC]))))
        pos += 12
        seq += 1
    fr.append(flexray(21, 0, h + bytes([0x30, 0x00, 0x00])))                # Flow control
    fr.append(flexray(21, 0, h + bytes([0x70, 0x00, 0x00, 0x13])))          # Ack
    # Classic types over FlexRay
    fr.append(flexray(22, 0, h + bytes([0x10, 30]) + pat(10)))
    fr.append(flexray(22, 0, h + bytes([0x21]) + pat(13, 10)))
    fr.append(flexray(22, 0, h + bytes([0x22]) + pat(7, 23) + bytes([CC] * 6)))
    fr.append(flexray(22, 0, h + bytes([0x04, 1, 2, 3, 4])))
    return fr


def exported_pdu_frames():
    """An Exported PDU naming "iso15765": no bus information is passed, the
    dissector declines and the payload is data."""
    name = b'iso15765\0\0\0\0'
    return [(4, struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0)
             + bytes([0x03, 0x22, 0xf1, 0x90]))]


def pdu_frames():
    """ISO 15765 over PDU Transport. The PDU IDs are bound by the
    "ISO15765 PDU Transport Config" table (cfg/ISO15765_pdu_transport_config):
      0x100  one address byte in the payload
      0x101  one fixed address
      0x102  source and target address, one byte each
      0x103  fixed source address, two byte target address
      0x104  fixed source and target addresses
      0x105  no address at all"""
    fr = []
    fr.append(pdu_udp(0x100, bytes([0x42, 0x03, 0x22, 0xf1, 0x90])))
    fr.append(pdu_udp(0x101, bytes([0x02, 0x3e, 0x00])))
    fr.append(pdu_udp(0x102, bytes([0x10, 0x20, 0x03, 0x22, 0xf1, 0x90])))
    fr.append(pdu_udp(0x103, bytes([0x00, 0x77, 0x02, 0x3e, 0x00])))
    fr.append(pdu_udp(0x104, bytes([0x02, 0x3e, 0x00])))
    fr.append(pdu_udp(0x105, bytes([0x10, 12]) + pat(6)))
    fr.append(pdu_udp(0x105, bytes([0x21]) + pat(6, 6)))
    fr.append(pdu_udp(0x102, bytes([0x10, 0x20, 0x10, 9]) + pat(4)))
    fr.append(pdu_udp(0x102, bytes([0x10, 0x20, 0x21]) + pat(5, 4)))
    # PDU ID without configuration: PDU Transport only
    fr.append(pdu_udp(0x999, bytes([0x02, 0x3e, 0x00])))
    return fr


def build_malformed():
    fr = []
    # Bad message types 8..15
    for t in (0x80, 0x9f, 0xa0, 0xf5):
        fr.append(lin(REQ, bytes([NAD, t, 1, 2, 3, 4, 5, 6])))
    # Reproducer, too many segments with the same sequence number: FF with a
    # 32 bit length followed by 256 CFs with sequence number 1
    fr.append(lin(RSP, bytes([NAD, 0x10, 0x00, 0xff, 0xff, 0xff, 0xff, 0xAA])))
    for i in range(256):
        fr.append(lin(RSP, bytes([NAD, 0x21]) + bytes([i & 0xff] * 6)))
    # Truncated frames
    fr.append(lin(REQ, bytes([NAD])))
    fr.append(lin(REQ, bytes([NAD, 0x10])))
    fr.append(lin(REQ, bytes([NAD, 0x10, 0x00, 0x00])))
    fr.append(lin(REQ, bytes([NAD, 0x30, 0x00])))
    fr.append(lin(REQ, bytes([NAD, 0x50, 0x00, 0x00])))
    fr.append(lin(REQ, bytes([NAD, 0x70, 0x00, 0x00, 0x00])))
    return fr


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_frames = build_main() + can_frames() + flexray_frames() + pdu_frames() + exported_pdu_frames()
    write(os.path.join(out, 'iso15765-coverage.pcapng'), main_frames)
    write(os.path.join(out, 'iso15765-coverage-malformed.pcapng'), build_malformed())
    print('main frames: %d (LIN %d, CAN %d, FlexRay %d, PDU %d, Exported PDU %d)' % (
        len(main_frames), len(build_main()), len(can_frames()), len(flexray_frames()), len(pdu_frames()), len(exported_pdu_frames())))


if __name__ == '__main__':
    main()

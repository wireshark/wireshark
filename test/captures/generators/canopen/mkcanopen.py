#!/usr/bin/env python3
# Generates test/captures/canopen_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CANopen dissector
(packet-canopen.c).

CANopen is reached only through the "can.subdissector" Decode As table
(-d can.subdissector,canopen): the dissector needs the struct can_info
that the CAN dissectors pass. The COB-ID (11 bit CAN identifier) selects
the message: function code (bits 7-10) and node ID (bits 0-6). Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcanopen.py <output directory>

Writes pcapng files with two interfaces:
  0  LINKTYPE_CAN_SOCKETCAN (227)       CANopen frames
  1  LINKTYPE_WIRESHARK_UPPER_PDU (252) an Exported PDU naming "canopen"
                                        (no CAN information)

  canopen-coverage.pcapng            NMT, SYNC, TIME, EMCY, every PDO,
                                     every SDO client and server command
                                     (including the block transfers), NMT
                                     error control, every LSS master and
                                     slave command, unknown function codes,
                                     extended and RTR frames (not CANopen)
                                     and the reproducers of the fixes
  canopen-coverage-malformed.pcapng  frames shorter than their message
"""

import os
import struct
import sys

T0 = 1700000000

CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000


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
        f.write(shb() + idb(227) + idb(252))
        for i, (ifid, data) in enumerate(frames):
            f.write(epb(ifid, T0 + i * 0.01, data))


def socketcan(canid, data, fd=False):
    """SocketCAN header (big endian ID in LINKTYPE_CAN_SOCKETCAN). The
    data length is the DLC; classic frames are padded to 8 octets."""
    flags = 0x04 if fd else 0      # CANFD_FDF
    payload = data if fd else data.ljust(8, b'\0')
    return struct.pack('>IBBBB', canid, len(data), flags, 0, 0) + payload


def exported_pdu(name, payload):
    n = name.encode()
    return (struct.pack('>HH', 12, len(pad4(n))) + pad4(n)
            + struct.pack('>HH', 0, 0) + payload)


def c(canid, data, fd=False):
    return (0, socketcan(canid, bytes(data), fd))


def sdo(cmd, index=0, sub=0, rest=b''):
    """8 octet SDO: command, index (LE), sub-index, 4 octets."""
    return bytes([cmd]) + struct.pack('<HB', index, sub) + bytes(rest).ljust(4, b'\0')


def lss(cs, rest=b''):
    return bytes([cs]) + bytes(rest).ljust(7, b'\0')


def main_frames():
    f = []
    # --- 1-6: NMT node control (COB-ID 0x000) -------------------------
    for cs, node in ((0x01, 0), (0x02, 5), (0x80, 0x7f), (0x81, 1), (0x82, 0), (0x55, 3)):
        f.append(c(0x000, [cs, node]))
    # --- 7-8: SYNC without and with the counter -------------------------
    f.append(c(0x080, []))
    f.append(c(0x080, [42]))
    # --- 9-10: TIME STAMP: 12:34:56.789 on day 14610 (2024-01-01), and
    #     the largest values
    f.append(c(0x100, struct.pack('<IH', 45296789, 14610)))
    f.append(c(0x100, struct.pack('<IH', 0x0fffffff, 0xffff)))
    # --- 11-13: EMCY: error register bits, all bits, no error ---------
    f.append(c(0x081, struct.pack('<HB', 0x8130, 0x11) + b'\x01\x02\x03\x04\x05'))
    f.append(c(0x0ff, struct.pack('<HB', 0xffff, 0xff) + b'\xff' * 5))
    f.append(c(0x085, struct.pack('<HB', 0x0000, 0x00) + bytes(5)))
    # --- 14-24: PDOs: PDO1-4 tx and rx, an empty PDO, a broadcast COB-ID
    #     (node 0, function code 3) and a CAN FD PDO of 12 octets
    for i, base in enumerate((0x180, 0x200, 0x280, 0x300, 0x380, 0x400, 0x480, 0x500)):
        f.append(c(base + 1 + i, bytes(range(i + 1, i + 1 + (8 if i % 2 == 0 else i + 1)))))
    f.append(c(0x182, []))
    f.append(c(0x180, [0xaa, 0xbb]))
    f.append(c(0x203, bytes(range(12)), fd=True))
    # --- 25-48: SDO client to server (COB-ID 0x600 + node, Default-SDO rx)
    N = 0x10
    rx = 0x600 + N
    f.append(c(rx, [0x00] + list(range(1, 8))))          # download segment, toggle 0
    f.append(c(rx, [0x1f] + list(range(1, 8))))          # toggle 1, n 7, last segment
    f.append(c(rx, sdo(0x23, 0x1017, 0, b'\xe8\x03\0\0')))   # init download, expedited, size
    f.append(c(rx, sdo(0x2f, 0x6040, 0, b'\x0f')))           # expedited, n 3
    f.append(c(rx, sdo(0x21, 0x1008, 0, b'\x10\0\0\0')))     # segmented, size 16
    f.append(c(rx, sdo(0x22, 0x2000, 1, b'\x01\x02\x03\x04')))   # expedited, no size
    f.append(c(rx, sdo(0x40, 0x1000, 0)))                # initiate upload
    f.append(c(rx, [0x60] + [0] * 7))                    # upload segment, toggle 0
    f.append(c(rx, [0x70] + [0] * 7))                    # upload segment, toggle 1
    f.append(c(rx, sdo(0x80, 0x1234, 5, struct.pack('<I', 0x06020000))))   # abort
    f.append(c(rx, sdo(0x80, 0x1234, 6, struct.pack('<I', 0x12345678))))   # unknown code
    f.append(c(rx, sdo(0xa0, 0x1f50, 1, b'\x7f\x10')))   # block upload initiate, blksize 127, pst 16
    f.append(c(rx, sdo(0xa4, 0x1f50, 1, b'\x7f\x10')))   # same with CRC bit: segment, not dissected
    f.append(c(rx, [0xa1] + [0] * 7))                    # end block upload
    f.append(c(rx, [0xa2, 0x05, 0x7f] + [0] * 5))        # block upload response, ackseq 5
    f.append(c(rx, [0xa3] + [0] * 7))                    # start upload
    f.append(c(rx, sdo(0xc0, 0x1f50, 1, b'\x00\x01\0\0')))   # block download initiate, no size
    f.append(c(rx, sdo(0xc6, 0x1f50, 1, b'\x00\x01\0\0')))   # CRC and size bits: not dissected
    f.append(c(rx, [0xc1, 0x34, 0x12] + [0] * 5))        # end block download, n 0, CRC 0x1234
    f.append(c(rx, [0xdd, 0x34, 0x12] + [0] * 5))        # end block download, n 7
    f.append(c(rx, [0xc3, 0x34, 0x12] + [0] * 5))        # bit 1 set: not dissected
    f.append(c(rx, [0xe0] + [0] * 7))                    # ccs 7: unknown
    f.append(c(rx, [0x82] + [0] * 7))                    # abort with no index (all zero)
    f.append(c(0x67f, sdo(0x40, 0x1018, 4)))             # node 0x7f, initiate upload
    # --- 49-69: SDO server to client (COB-ID 0x580 + node, Default-SDO tx)
    tx = 0x580 + N
    f.append(c(tx, [0x00] + list(range(0x41, 0x48))))    # upload segment response
    f.append(c(tx, [0x1d] + list(range(0x41, 0x48))))    # toggle 1, n 6, last
    f.append(c(tx, [0x20] + [0] * 7))                    # download segment response, toggle 0
    f.append(c(tx, [0x30] + [0] * 7))                    # toggle 1
    f.append(c(tx, sdo(0x43, 0x1000, 0, b'\x91\x01\x0f\x00')))   # init upload response, expedited
    f.append(c(tx, sdo(0x4f, 0x1001, 0, b'\x00')))       # n 3
    f.append(c(tx, sdo(0x41, 0x1008, 0, b'\x10\0\0\0')))     # segmented, size 16
    f.append(c(tx, sdo(0x60, 0x1017, 0)))                # initiate download response
    f.append(c(tx, sdo(0x80, 0x6040, 0, struct.pack('<I', 0x06010002))))
    f.append(c(tx, sdo(0x80, 0x6041, 0, struct.pack('<I', 0x08000024))))
    f.append(c(tx, sdo(0x80, 0x6042, 0, struct.pack('<I', 0x05040001))))
    f.append(c(tx, sdo(0xa0, 0x1f50, 1, b'\x20')))       # block download initiate response, blksize 32
    f.append(c(tx, sdo(0xa4, 0x1f50, 1, b'\x20')))       # with CRC bit: not dissected
    f.append(c(tx, [0xa1] + [0] * 7))                    # end block download response
    f.append(c(tx, [0xa2, 0x20, 0x20] + [0] * 5))        # block download response, ackseq 32
    f.append(c(tx, [0xa3] + [0] * 7))                    # subcommand 3: no field list
    f.append(c(tx, sdo(0xc2, 0x1f50, 1, b'\x00\x02\0\0')))   # block upload initiate response, size
    f.append(c(tx, sdo(0xc4, 0x1f50, 1, b'\x00\x02\0\0')))   # with CRC bit: not dissected
    f.append(c(tx, [0xc1, 0xcd, 0xab] + [0] * 5))        # end block upload, CRC 0xabcd
    f.append(c(tx, [0xc3, 0xcd, 0xab] + [0] * 5))        # bit 1 set: not dissected
    f.append(c(tx, [0xe0] + [0] * 7))                    # scs 7: unknown
    # --- 70-76: NMT error control (COB-ID 0x700 + node) ----------------
    for st in (0x00, 0x04, 0x05, 0x7f, 0x85, 0x33):
        f.append(c(0x701, [st]))
    f.append(c(0x702, []))                               # no data
    # --- 77-107: LSS master (COB-ID 0x7E5) ----------------------------
    m = 0x7e5
    for mode in (0x00, 0x01, 0x07):
        f.append(c(m, lss(0x04, [mode])))
    for cs, val in ((0x40, 0x000000aa), (0x41, 0x12345678), (0x42, 0x00010002), (0x43, 0xdeadbeef)):
        f.append(c(m, lss(cs, struct.pack('<I', val))))
    f.append(c(m, lss(0x11, [0x22])))
    f.append(c(m, lss(0x13, [0x00, 0x02])))
    f.append(c(m, lss(0x13, [0x00, 0x0f])))              # unknown table index
    f.append(c(m, lss(0x15, struct.pack('<H', 0x1234))))  # switch delay 4660 ms
    for cs in (0x17, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x4c):
        f.append(c(m, lss(cs)))
    for i, cs in enumerate(range(0x46, 0x4c)):
        f.append(c(m, lss(cs, struct.pack('<I', 0x11111111 * (i + 1)))))
    f.append(c(m, lss(0x51, struct.pack('<I', 0) + bytes([0x80, 0, 0]))))       # all slaves
    f.append(c(m, lss(0x51, struct.pack('<I', 0x12345678) + bytes([0, 1, 2]))))  # bit check 0
    f.append(c(m, lss(0x51, struct.pack('<I', 0x12345678) + bytes([5, 2, 3]))))
    f.append(c(m, lss(0x51, struct.pack('<I', 0x12345678) + bytes([0x40, 3, 7]))))   # reserved
    # the fastscan frame of the reproducer (canopen_nodata-socketcan.pcap
    # frame 1): bit check 31 (1 << 31 used to be a signed overflow)
    f.append(c(m, [0x51, 1, 2, 3, 4, 31, 0, 0]))
    f.append(c(m, lss(0x44)))                            # slave command from the master: invalid
    f.append(c(m, lss(0x99)))                            # unknown command
    # --- 108-125: LSS slave (COB-ID 0x7E4) ----------------------------
    s = 0x7e4
    f.append(c(s, lss(0x44)))
    for err in (0x00, 0x01, 0xff):
        f.append(c(s, lss(0x11, [err, 0x10 if err == 0xff else 0])))
    for err in (0x00, 0x01):
        f.append(c(s, lss(0x13, [err, 0])))
    for err in (0x00, 0x01, 0x02, 0xff):
        f.append(c(s, lss(0x17, [err, 0x20 if err == 0xff else 0])))
    for cs, val in ((0x5a, 0x000000aa), (0x5b, 0x12345678), (0x5c, 0x00010002), (0x5d, 0xdeadbeef)):
        f.append(c(s, lss(cs, struct.pack('<I', val))))
    f.append(c(s, lss(0x5e, [0x22])))
    f.append(c(s, lss(0x4f)))
    f.append(c(s, lss(0x50)))
    f.append(c(s, lss(0x04)))                            # master command from a slave: invalid
    # --- 126-128: unknown function codes ------------------------------
    f.append(c(0x7e6, bytes(8)))                         # function code 15, other node
    f.append(c(0x780, bytes(8)))                         # function code 15, node 0
    f.append(c(0x681, bytes(8)))                         # function code 13
    # --- 129-130: not for CANopen: extended identifier and RTR --------
    f.append(c(CAN_EFF_FLAG | 0x123, bytes(8)))
    f.append((0, struct.pack('>IBBBB', CAN_RTR_FLAG | 0x701, 1, 0, 0, 0) + bytes(8)))
    # --- 131: the reproducer canopen_nodata.pcap: an Exported PDU naming
    #     "canopen" has no CAN information; the dissector rejects it (it
    #     used to assert) and the payload is data
    f.append((1, exported_pdu('canopen', bytes(8))))
    # --- 132: LSS activate bit timing with a full frame (the switch
    #     delay is 2 octets, followed by 5 reserved octets)
    f.append(c(m, lss(0x15, struct.pack('<H', 0xffff))))
    return f


def malformed_frames():
    f = []
    # 1: the reproducer canopen_nodata-socketcan.pcap frame 2: LSS
    #    activate bit timing with 3 octets (the delay is read as 2
    #    octets; the 5 reserved octets are missing)
    f.append(c(0x7e5, [0x15, 0x10, 0x00]))
    # 2-3: NMT with 1 and 0 octets
    f.append(c(0x000, [0x01]))
    f.append(c(0x000, []))
    # 4: TIME STAMP with 4 octets
    f.append(c(0x100, [1, 2, 3, 4]))
    # 5: EMCY with 3 octets
    f.append(c(0x081, [0x30, 0x81, 0x11]))
    # 6: SDO initiate download with 3 octets
    f.append(c(0x610, [0x23, 0x17, 0x10]))
    # 7: SDO with no data
    f.append(c(0x590, []))
    # 8: LSS master with no data
    f.append(c(0x7e5, []))
    # 9: LSS fastscan with 5 octets
    f.append(c(0x7e5, [0x51, 1, 2, 3, 4]))
    # 10: LSS slave inquire vendor-ID with 2 octets
    f.append(c(0x7e4, [0x5a, 0xaa]))
    # 11: SDO upload segment response with 4 octets
    f.append(c(0x590, [0x00, 1, 2, 3]))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write(os.path.join(out, 'canopen-coverage.pcapng'), main_frames())
    write(os.path.join(out, 'canopen-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

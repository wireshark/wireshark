#!/usr/bin/env python3
# Generates test/captures/bthci_vendor_intel_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the Bluetooth Intel HCI vendor dissector
# (epan/dissectors/packet-bthci_vendor_intel.c, protocol
# "bthci_vendor.intel"). Every packet is built with struct; nothing comes
# from a real device. BD_ADDRs are locally administered (0a:...).
#
# Usage: mkbthci_vendor_intel.py <outdir>
# Writes
#   bthci_vendor_intel-coverage.pcapng            main capture: interface 0
#       is LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR (201), interface 1 is
#       Exported PDU (252) naming "bthci_vendor.intel"
#   bthci_vendor_intel-coverage-malformed.pcapng  exceptions
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

LT_H4 = 201
LT_EXPPDU = 252
IF_H4, IF_EXP = 0, 1


def pcapng_block(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


def write_pcapng(path, frames):
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in (LT_H4, LT_EXPPDU):
            f.write(pcapng_block(1, struct.pack('<HHI', lt, 0, 65535)))
        for i, (ifid, data) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                                len(data), len(data)) + data))


def h4(sent, h4type, payload):
    # 4 octet direction (0 sent, 1 received), then the H4 packet type
    return (IF_H4, struct.pack('>I', 0 if sent else 1) + bytes([h4type]) + payload)


def cmd(opcode, params, plen=None):
    if plen is None:
        plen = len(params)
    return h4(True, 0x01, struct.pack('<HB', opcode, plen) + params)


def evt(code, params):
    return h4(False, 0x04, struct.pack('<BB', code, len(params)) + params)


def cmd_complete(opcode, ret, status=0):
    return evt(0x0e, struct.pack('<BHB', 1, opcode, status) + ret)


def tlv(tag, val):
    val = val + b'\0' * ((-len(val)) % 4)
    return struct.pack('>HH', tag, len(val)) + val


def exppdu(direction, payload, name='bthci_vendor.intel'):
    # direction 0 sent (command), 1 received (event), None: no tag (unknown)
    d = tlv(12, name.encode())
    if direction is not None:
        d += tlv(35, struct.pack('>I', direction))
    return (IF_EXP, d + struct.pack('>HH', 0, 0) + payload)


def x_evt(code, params, plen=None):
    if plen is None:
        plen = len(params)
    return exppdu(1, struct.pack('<BB', code, plen) + params)


def x_cmd(opcode, params, plen=None):
    if plen is None:
        plen = len(params)
    return exppdu(0, struct.pack('<HB', opcode, plen) + params)


def vop(ocf):
    return (0x3f << 10) | ocf


def le16(v):
    return struct.pack('<H', v)


def le32(v):
    return struct.pack('<I', v)


BD_LOCAL = bytes([0xc6, 0xb5, 0xa4, 0x93, 0x82, 0x0a])   # 0a:82:93:a4:b5:c6
BD_PEER = bytes([0xd6, 0xc5, 0xb4, 0xa3, 0x92, 0x0a])    # 0a:92:a3:b4:c5:d6

# Intel OCFs, grouped as the dissector groups them
CMD_UNKNOWN_LAYOUT = [0x02, 0x06, 0x07, 0x08, 0x0e, 0x0f, 0x10, 0x12, 0x22, 0x24,
                      0x32, 0x34, 0x38, 0x39, 0x50, 0x53, 0x89, 0x8a, 0x8c, 0x8d]
CMD_NO_PARAMS = [0x05, 0x0d, 0x30, 0x3f]
CC_NOP = [0x01, 0x09, 0x11, 0x31, 0x3f, 0x4d, 0x52, 0x8e]
CC_UNKNOWN_LAYOUT = [0x02, 0x06, 0x07, 0x08, 0x0d, 0x0e, 0x0f, 0x10, 0x12, 0x22,
                     0x24, 0x2f, 0x32, 0x34, 0x38, 0x39, 0x43, 0x50, 0x53, 0x89,
                     0x8a, 0x8c, 0x8d]


def lmp(opcode, params):
    # LMP PDU: opcode << 1 | TID (0: central)
    return bytes([opcode << 1]) + params


def btle_ll_version():
    # Data channel PDU: access address, LLID 3 (control), length 6,
    # LL_VERSION_IND (0x0c), version 5.0 (9), company 0xffff, subversion,
    # then a 3 octet CRC
    pdu = bytes([0x0c, 0x09]) + le16(0xffff) + le16(0x0101)
    return le32(0x50654c41) + bytes([0x03, len(pdu)]) + pdu + b'\x11\x22\x33'


def main_frames():
    f = []
    # 1-2: Read Local Version Information, manufacturer Intel (0x0002);
    # from here on HCI vendor commands and events go to the Intel dissector
    f.append(cmd(0x1001, b''))
    f.append(cmd_complete(0x1001, bytes([0x09]) + le16(0x0100) + bytes([0x09]) + le16(0x0002) + le16(0x2209)))
    # 3-4: Reset (DDC reload decoded once), its Command Complete
    f.append(cmd(vop(0x01), bytes([0x01, 0x01, 0x01, 0x01]) + le32(0x00012800)))
    f.append(cmd_complete(vop(0x01), b''))
    # 5-24: the commands without a decoded layout, no parameters
    for ocf in CMD_UNKNOWN_LAYOUT:
        f.append(cmd(vop(ocf), b''))
    # 25-28: commands that have no parameters
    for ocf in CMD_NO_PARAMS:
        f.append(cmd(vop(ocf), b''))
    # 29-30: Secure Send Init with a data block, Secure Send Data type only
    f.append(cmd(vop(0x09), bytes([0x00]) + bytes(range(0x20, 0x40))))
    f.append(cmd(vop(0x09), bytes([0x01])))
    # 31: Manufacturer Mode on, reset and activate patches
    f.append(cmd(vop(0x11), bytes([0x01, 0x02])))
    # 32-33: Write BD Data, with and without trailing data
    wbd = BD_LOCAL + bytes(range(1, 7)) + bytes(range(0x10, 0x18)) + b'\x55'
    f.append(cmd(vop(0x2f), wbd))
    f.append(cmd(vop(0x2f), wbd + b'\xaa\xbb\xcc\xdd'))
    # 34: Write BD Address
    f.append(cmd(vop(0x31), BD_LOCAL))
    # 35: Activate/Deactivate Traces
    f.append(cmd(vop(0x43), bytes([0x01, 0x00, 0x01])))
    # 36-37: Stimulate Exception, Fatal and Debug
    f.append(cmd(vop(0x4d), b'\x00'))
    f.append(cmd(vop(0x4d), b'\x01'))
    # 38: Set Event Mask, every defined bit
    f.append(cmd(vop(0x52), struct.pack('<Q', 0x00000000000007ff)))
    # 39: DDC Config Write with two entries (2 and 5 octets of data)
    f.append(cmd(vop(0x8b), bytes([4]) + le16(0x0102) + b'\x0a\x0b' + bytes([7]) + le16(0x0203) + b'\x01\x02\x03\x04\x05'))
    # 40: Memory Write, word access, 4 octets
    f.append(cmd(vop(0x8e), le32(0x00080000) + bytes([0x02, 0x04]) + b'\xde\xad\xbe\xef'))
    # 41-42: unknown OCF with data, unknown OCF without
    f.append(cmd(vop(0x3ff), b'\x01\x02\x03'))
    f.append(cmd(vop(0x3fe), b''))
    # 43-44: a known command with a parameter it does not take (Unexpected
    # parameter), and one of the undecoded commands with a parameter
    f.append(cmd(vop(0x05), b'\x99'))
    f.append(cmd(vop(0x02), b'\x01\x02'))

    # 45-52: Command Complete without return parameters
    for ocf in CC_NOP:
        f.append(cmd_complete(vop(ocf), b''))
    # 53-75: Command Complete for the undecoded commands, with data
    # (success), 76-77 with data on failure, 78 without data
    for ocf in CC_UNKNOWN_LAYOUT:
        f.append(cmd_complete(vop(ocf), b'\x01\x02'))
    f.append(cmd_complete(vop(0x02), b'\x01', status=0x01))
    f.append(cmd_complete(vop(0x8d), b'\x01\x02\x03\x04', status=0x12))
    f.append(cmd_complete(vop(0x34), b''))
    # 79: Read Version
    f.append(cmd_complete(vop(0x05), bytes([0x37, 0x0b, 0x10, 0x06, 0x01, 0x10, 0x25, 0x15, 0x00])))
    # 80: Read BD Data
    f.append(cmd_complete(vop(0x30), BD_LOCAL))
    # 81: DDC Config Write (failed identifier)
    f.append(cmd_complete(vop(0x8b), le16(0x0203)))
    # 82-84: unknown OCF: data on success, data on failure, no data
    f.append(cmd_complete(vop(0x3ff), b'\x01\x02'))
    f.append(cmd_complete(vop(0x3ff), b'\x01\x02', status=0x01))
    f.append(cmd_complete(vop(0x3fe), b''))
    # 85: Read Version with an octet more (Unexpected parameter)
    f.append(cmd_complete(vop(0x05), bytes([0x37, 0x0b, 0x10, 0x06, 0x01, 0x10, 0x25, 0x15, 0x00, 0xee])))
    # 86: HCI Vendor-Specific event (0xFF): bthci_evt hands the whole event
    # to the vendor dissector, which sees event code 0xFF (undecoded)
    f.append(evt(0xff, bytes([0x2c]) + b'trace'))

    # 87: the reproducer bthci_vendor_intel_cmd_complete_length.py
    # byte for byte: Exported PDU, Command Complete for Read Version
    f.append(x_evt(0x0e, struct.pack('<BHB', 1, vop(0x05), 0) + bytes([0x37, 0x0b, 0x10, 0x06, 0x01, 0x10, 0x25, 0x15, 0x00])))
    # 88-89: Exported PDU commands (no Bluetooth data): Write BD Address,
    # Reset
    f.append(x_cmd(vop(0x31), BD_PEER))
    f.append(x_cmd(vop(0x01), bytes([0x00, 0x00, 0x00, 0x00]) + le32(0)))
    # 90: Command Complete for Read BD Data without Bluetooth data
    f.append(x_evt(0x0e, struct.pack('<BHB', 1, vop(0x30), 0) + BD_PEER))
    # 91-92: Fatal Exception, Debug Exception
    f.append(x_evt(0x01, le16(1234) + bytes([0x05, 0x02])))
    f.append(x_evt(0x08, le16(77) + bytes([0xf0, 0x01])))
    # 93-94: Bootup (operational firmware after an Intel Reset command,
    # bootloader after power on)
    f.append(x_evt(0x02, bytes([0x00, 0x01, 0x01, 0x02, 0x02, 0x01])))
    f.append(x_evt(0x02, bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00])))
    # 95: Default BD Data
    f.append(x_evt(0x05, b'\x02'))
    # 96: Secure Send Commands Result
    f.append(x_evt(0x06, bytes([0x03]) + le16(vop(0x09)) + b'\x00'))
    # 97: LE Link Established
    f.append(x_evt(0x0f, le16(0x0040) + bytes(range(8)) + le32(0x8e89bed6) + b'\x01\x02\x03'))
    # 98: Scan Status, page and inquiry scan on
    f.append(x_evt(0x11, b'\x03'))
    # 99: Activate/Deactivate Traces Complete
    f.append(x_evt(0x16, b'\x00'))
    # 100-101: Link PDU Trace, LMP Rx: LMP_version_req, LMP_name_res
    f.append(x_evt(0x17, bytes([0x00]) + le16(0x0001) + b'\x00' +
                   lmp(0x25, bytes([0x09]) + le16(0x0002) + le16(0x2209)) + le32(0x00012345)))
    f.append(x_evt(0x17, bytes([0x00]) + le16(0x0001) + b'\x00' +
                   lmp(0x02, bytes([0x00, 0x08]) + b'Coverage' + bytes(6)) + le32(0x00012346)))
    # 102-103: LMP Tx: LMP_accepted (LMP_host_connection_req),
    # LMP_features_req_ext page 1
    f.append(x_evt(0x17, bytes([0x01]) + le16(0x0001) + b'\x00' +
                   lmp(0x03, bytes([0x33 << 1])) + le32(0x00012350) + b'\x07'))
    f.append(x_evt(0x17, bytes([0x01]) + le16(0x0001) + b'\x00' +
                   bytes([0x7f << 1, 0x03, 0x01, 0x02]) + bytes([0x0f]) + bytes(7) + le32(0x00012351) + b'\x08'))
    # 104: LMP Ack
    f.append(x_evt(0x17, bytes([0x02]) + le16(0x0001) + le32(0x00012352) + b'\x07'))
    # 105-106: LL Rx, LL Tx (LL_VERSION_IND to btle)
    for t in (0x03, 0x04):
        f.append(x_evt(0x17, bytes([t]) + le16(0x0040) + le16(5 + t) + b'\x01' + b'\x00\x00' + btle_ll_version()))
    # 107: LL Ack
    f.append(x_evt(0x17, bytes([0x05]) + le16(0x0040) + le16(9) + b'\x01'))
    # 108: unknown trace type: only the handle
    f.append(x_evt(0x17, bytes([0x06]) + le16(0x0040)))
    # 109: Write BD Data Complete
    f.append(x_evt(0x19, b'\x00'))
    # 110: SCO Rejected via LMP
    f.append(x_evt(0x25, BD_PEER + b'\x0d'))
    # 111: PTT Switch Notification, EDR
    f.append(x_evt(0x26, le16(0x0001) + b'\x01'))
    # 112: System Exception, Data Abort
    f.append(x_evt(0x29, b'\x03' + bytes(range(16))))
    # 113-115: FW Trace String, FW Trace Binary, an empty FW Trace String
    f.append(x_evt(0x2c, b'fw: coverage trace'))
    f.append(x_evt(0x2e, bytes(range(12))))
    f.append(x_evt(0x2c, b''))
    # 116-118: events the Intel table does not name: a standard HCI code
    # (Connection Complete, name from bthci_evt), an unknown code with
    # data and without
    f.append(x_evt(0x03, b'\x00\x01\x00'))
    f.append(x_evt(0x7f, b'\x01\x02'))
    f.append(x_evt(0x7f, b''))
    # 119: event with data after the parameters (Unexpected data)
    f.append(x_evt(0x05, b'\x02\xaa\xbb', plen=1))
    # 120: without a direction
    f.append(exppdu(None, b'\x01\x02\x03'))
    return f


def malformed_frames():
    f = []
    f.append(cmd(0x1001, b''))
    f.append(cmd_complete(0x1001, bytes([0x09]) + le16(0x0100) + bytes([0x09]) + le16(0x0002) + le16(0x2209)))
    # 3-4: HCI Command Status for a vendor command: bthci_evt gives the
    # Intel dissector the whole event (code 0x0F), decoded as LE Link
    # Established and cut short (observation 1)
    f.append(cmd(vop(0x09), b'\x00'))
    f.append(evt(0x0f, struct.pack('<BBH', 0, 1, vop(0x09))))
    # 5: parameter length larger than the data
    f.append(cmd(vop(0x31), BD_LOCAL[:3], plen=6))
    # 6: Reset cut short
    f.append(cmd(vop(0x01), b'\x01\x01'))
    # 7: DDC Config Write entry longer than the data (no exception, no
    # expert info: observation 3)
    f.append(cmd(vop(0x8b), bytes([9]) + le16(0x0102) + b'\x0a'))
    # 8: DDC Config Write entry length 1 (identifier past the entry)
    f.append(cmd(vop(0x8b), bytes([1]) + b'\x01'))
    # 9: Memory Write with a data length past the end (no exception, no
    # expert info: observation 3)
    f.append(cmd(vop(0x8e), le32(0x00080000) + bytes([0x00, 0x20]) + b'\x01\x02'))
    # 10: Set Event Mask cut short
    f.append(cmd(vop(0x52), b'\xff\xff'))
    # 11: Command Complete for Read Version cut short
    f.append(cmd_complete(vop(0x05), b'\x37\x0b'))
    # 12-13: Link PDU Trace LMP Rx with fewer than 4 octets after the
    # header octet, LMP Tx with fewer than 5
    f.append(x_evt(0x17, bytes([0x00]) + le16(1) + b'\x00' + b'\x01\x02\x03'))
    f.append(x_evt(0x17, bytes([0x01]) + le16(1) + b'\x00' + b'\x01\x02\x03\x04'))
    # 14: LMP Rx without the header octet
    f.append(x_evt(0x17, bytes([0x00]) + le16(1)))
    # 15-17: events cut short: Bootup, Secure Send Commands Result,
    # LE Link Established
    f.append(x_evt(0x02, b'\x00\x01'))
    f.append(x_evt(0x06, b'\x00'))
    f.append(x_evt(0x0f, le16(1) + bytes(4)))
    # 18: parameter length larger than the event
    f.append(x_evt(0x25, BD_PEER[:2], plen=7))
    # 19: Command Complete without the opcode
    f.append(x_evt(0x0e, b'\x01'))
    # 20: empty Exported PDU, received
    f.append(exppdu(1, b''))
    # 21-22: LE Link Established and System Exception with nothing after
    # their last field: the trailing "Data" item of length -1 throws at the
    # end of the parameters (observation 2)
    f.append(x_evt(0x0f, le16(0x0041) + bytes(range(8)) + le32(0x50654c41)))
    f.append(x_evt(0x29, b'\x01'))
    # 23: LMP Tx with a bad LMP_eSCO_link_req inside (short)
    f.append(x_evt(0x17, bytes([0x01]) + le16(1) + b'\x00' + bytes([0x7f << 1, 0x0c, 0x01]) + le32(0) + b'\x01'))
    return f


write_pcapng(os.path.join(OUT, 'bthci_vendor_intel-coverage.pcapng'), main_frames())
write_pcapng(os.path.join(OUT, 'bthci_vendor_intel-coverage-malformed.pcapng'), malformed_frames())

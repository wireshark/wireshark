#!/usr/bin/env python3
# Generates test/captures/bthci_vendor_broadcom_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the Broadcom HCI vendor dissector
# (epan/dissectors/packet-bthci_vendor_broadcom.c, "bthci_vendor.broadcom").
# Every packet is built with struct; nothing comes from a real device.
#
# Usage: mkbthci_vendor_broadcom.py <outdir>
# Writes
#   bthci_vendor_broadcom-coverage.pcapng: interface 0 HCI H4 with direction
#     (DLT 201): Read Local Version Information naming Broadcom (0x000F),
#     then vendor commands and their Command Complete events;
#     interface 1 Exported PDU (DLT 252) naming "bthci_vendor.broadcom"
#     (no bluetooth_data_t), with the reproducers.
#   bthci_vendor_broadcom-coverage-malformed.pcapng: the same two
#     interfaces, frames that only malformed input reaches.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

H4, EXPPDU = 0, 1
MANUFACTURER = 0x000F   # Broadcom


def write_pcapng(path, linktypes, pkts):
    """pkts: list of (interface id, packet)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    with open(path, 'wb') as f:
        f.write(block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
        for lt in linktypes:
            f.write(block(1, struct.pack('<HHI', lt, 0, 65535)))
        for i, (ifid, p) in enumerate(pkts):
            # 10 ms apart
            ts = 1700000000 * 1000000 + i * 10000
            f.write(block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p))


def h4(sent, h4type, payload):
    # LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR: 4 octet direction, 0 sent, 1 received
    return (H4, struct.pack('>I', 0 if sent else 1) + bytes([h4type]) + payload)


def op(ogf, ocf):
    return (ogf << 10) | ocf


def vop(ocf):
    return op(0x3f, ocf)


def cmd(opcode, params):
    return h4(True, 0x01, struct.pack('<HB', opcode, len(params)) + params)


def evt(code, params):
    return h4(False, 0x04, struct.pack('<BB', code, len(params)) + params)


def cc(opcode, status, ret=b''):
    return evt(0x0e, struct.pack('<BHB', 1, opcode, status) + ret)


def cs(opcode, status=0):
    return evt(0x0f, struct.pack('<BBH', status, 1, opcode))


def tlv(tag, val):
    # The length covers the padding (the dissector does not skip it)
    val += b'\0' * ((-len(val)) % 4)
    return struct.pack('>HH', tag, len(val)) + val


def exppdu(payload, direction=None, name='bthci_vendor.broadcom'):
    t = tlv(12, name.encode())
    if direction is not None:
        t += tlv(35, struct.pack('>I', direction))
    return (EXPPDU, t + struct.pack('>HH', 0, 0) + payload)


def vcmd_raw(ocf, params, plen=None):
    if plen is None:
        plen = len(params)
    return struct.pack('<HB', vop(ocf), plen) + params


def vevt_raw(code, params, plen=None):
    if plen is None:
        plen = len(params)
    return struct.pack('<BB', code, plen) + params


def le16(v):
    return struct.pack('<H', v)


def le32(v):
    return struct.pack('<I', v)


BD1 = bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])   # 11:22:33:44:55:66
BD2 = bytes([0x06, 0x05, 0x04, 0x03, 0x02, 0x00])   # 00:02:03:04:05:06


def ad31(name):
    # Flags, Complete Local Name, padded to 31 octets
    d = bytes([2, 0x01, 0x06]) + bytes([len(name) + 1, 0x09]) + name
    return d.ljust(31, b'\0')


def read_local_version():
    return [
        cmd(op(0x04, 0x0001), b''),
        # status, HCI version 5.3, revision, LMP version, manufacturer, subversion
        cc(op(0x04, 0x0001), 0, struct.pack('<BHBHH', 0x0c, 0x1234, 0x0c, MANUFACTURER, 0x5678)),
    ]


def a2dp_start_legacy(codec, scms=(0, 0), bitrate=320000, codec_info=b''):
    p = bytes([0x01]) + le32(codec) + le16(200) + bytes(scms) + le32(0x00000002) + \
        bytes([0x02, 0x02]) + le32(bitrate) + le16(0x0040) + le16(0x0041) + le16(895)
    return p + codec_info.ljust(32, b'\0')


SBC_INFO = bytes([0x15, 2, 53, 0x21])
AAC_INFO = bytes([0x40, 0x80])
LDAC_INFO = le32(0x0000012d) + le16(0x00aa) + bytes([0x01, 0x07])
LDAC_RES_INFO = le32(0x0000012d) + le16(0x00aa) + bytes([0x05, 0x04])
LDAC_ABR_INFO = le32(0x0000012d) + le16(0x00aa) + bytes([0x7f, 0x01])


def vendor_capabilities(version, v2=True):
    r = bytes([4, 1]) + le16(1024) + bytes([16, 1, 32, 1]) + le16(version) + le16(64) + \
        bytes([1, 1, 1]) + le32(0x0000001f) + bytes([1]) + le32(0x00000007)
    if v2:
        r += bytes([1])
    return r


def main_frames():
    """(section name, frames) for interface 0."""
    sections = []
    sections.append(('Read Local Version Information (Broadcom)', read_local_version()))

    # Commands with their Command Complete event
    f = []

    def pair(ocf, params, ret=b'', status=0):
        f.append(cmd(vop(ocf), params))
        f.append(cc(vop(ocf), status, ret))

    pair(0x0001, BD2)                                        # Write BD ADDR
    pair(0x0018, bytes([0x00, 0x00]) + le32(3000000))       # Update Baudrate
    pair(0x001C, bytes([0x01, 0x04, 0x00, 0x00, 0x01]))     # Write SCO PCM INT Parameter
    pair(0x001D, b'', bytes([0x00, 0x02, 0x01, 0x01, 0x00]))  # Read SCO PCM INT Parameter
    pair(0x001E, bytes([0x00, 0x00, 0x03, 0x00, 0x01]))     # Write PCM Data Format Parameter
    pair(0x0027, bytes([0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x10, 0x10, 0x00, 0x00]))  # Sleep Mode
    pair(0x002E, b'')                                       # Download MiniDriver
    pair(0x003B, bytes([0x01]))                             # Enable USB HID Emulation
    pair(0x0045, bytes([0x01]))                             # Write UART Clock Setting
    pair(0x004C, le32(0x00210000) + bytes(range(16)))      # Write Memory
    pair(0x004D, le32(0x00210000) + bytes([8]), bytes(range(0x30, 0x38)))  # Read Memory
    pair(0x004E, le32(0xffffffff))                          # Launch RAM
    pair(0x0057, le16(0x0001) + bytes([0xff]))              # Set ACL Priority
    pair(0x005A, b'', le16(0x0a5c) + le16(0x21e8))          # Read VID PID
    pair(0x006D, bytes([0x01, 0x01, 0x01, 0x02]))           # Write I2S PCM Interface Parameter
    pair(0x0079, b'', bytes([0x63, 0xfe]) + le16(0x1234) + le16(0x0567))  # Read Verbose Config
    pair(0x007E, bytes([0x01]) + le16(0x0002))              # Enable WBS (enable, mSBC)
    pair(0x007E, bytes([0x00]))                             # Enable WBS (disable)
    for ocf in (0x0102, 0x0111, 0x0112, 0x0113, 0x0114, 0x0158):  # undecoded both ways
        pair(ocf, bytes([0x01, 0x02, 0x03]), bytes([0x04, 0x05]))
    pair(0x0153, b'', vendor_capabilities(0x0060))          # LE Get Vendor Capabilities v0.96, A2DP v2
    pair(0x0153, b'', vendor_capabilities(0x0100, False))   # v1.00, without A2DP v2 octet
    pair(0x0153, b'', status=0x01)                          # failure
    # LE Multi Advertising: every subcode
    pair(0x0154, bytes([0x01]) + le16(0x00a0) + le16(0x00b0) + bytes([0x00, 0x01]) + BD1 +
         bytes([0x00]) + BD2 + bytes([0x07, 0x00, 0x01, 0xf8]), bytes([0x01]))
    pair(0x0154, bytes([0x02]) + ad31(b'BRCM-ADV') + bytes([0x01]), bytes([0x02]))
    pair(0x0154, bytes([0x03]) + ad31(b'BRCM-SCAN') + bytes([0x01]), bytes([0x03]))
    pair(0x0154, bytes([0x04]) + BD1 + bytes([0x02]), bytes([0x04]))
    pair(0x0154, bytes([0x05, 0x01, 0x02]), bytes([0x05]))
    pair(0x0154, bytes([0x06]), bytes([0x06]))              # unknown subcode, nothing more
    # LE Batch Scan
    pair(0x0156, bytes([0x01, 0x01]), bytes([0x01]))
    pair(0x0156, bytes([0x02, 0x32, 0x0a, 0x5f]), bytes([0x02]))
    pair(0x0156, bytes([0x03, 0x03]) + le32(0x12) + le32(0x400) + bytes([0x00, 0x01]), bytes([0x03]))
    pair(0x0156, bytes([0x04, 0x01]), bytes([0x04, 0x01, 0x05]))
    pair(0x0156, bytes([0x04, 0x02]), bytes([0x04]), status=0x0c)  # Read Results failed
    pair(0x0156, bytes([0x07]), bytes([0x07]))              # unknown subcode
    # LE Advertising Filter: Add with every subcode, Delete, Clear
    for sub in range(0x00, 0x09):
        pair(0x0157, bytes([sub, 0x00, sub]) + bytes([0xa0 + sub, 0xb0]), bytes([sub, 0x00, 15 - sub]))
    pair(0x0157, bytes([0x03, 0x01, 0x02]), bytes([0x03, 0x01, 0x0e]))
    pair(0x0157, bytes([0x08, 0x02, 0x00]), bytes([0x08]), status=0x12)  # Clear, failed
    pair(0x0159, b'', le32(1000) + le32(2000) + le32(3000) + le32(4000))  # LE Energy Info
    pair(0x0159, b'', status=0x01)
    # A2DP Hardware Offload
    pair(0x015D, a2dp_start_legacy(0x01, (0x00, 0x00), 0, SBC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x02, (0x01, 0x01), 256000, AAC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x01, 0x02), 0x01000000, LDAC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x00, 0x00), 990000, LDAC_RES_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x00, 0x00), 0, LDAC_ABR_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x04, (0x00, 0x00), 352000, bytes(range(32))), bytes([0x01]))
    pair(0x015D, bytes([0x02]), bytes([0x02]))
    pair(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x00]) + le16(895) +
         bytes([0x01, 0x02, 0x04]) + bytes([0xde, 0xad, 0xbe, 0xef]), bytes([0x03]))
    pair(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x01]) + le16(895) +
         bytes([0x00, 0x00, 0x00]), bytes([0x03]))
    pair(0x015D, bytes([0x04]) + le16(0x0040) + le16(0x0041) + bytes([0x00]), bytes([0x04]))
    pair(0x015D, bytes([0x05]), bytes([0x05]))              # unknown subcode, nothing more
    pair(0x0200, bytes([0x11, 0x22]), bytes([0x33, 0x44]))  # unknown command
    pair(0x0201, b'')                                       # unknown command, no parameters
    sections.append(('vendor commands / Command Complete', f))

    sections.append(('other events', [
        cmd(vop(0x004D), le32(0x00200000) + bytes([4])),
        cc(vop(0x004D), 0x02),                              # Read Memory failed
        cmd(vop(0x0112), b''),
        cs(vop(0x0112)),                                    # Command Status
        evt(0xff, bytes([0x55, 0x01, 0x02, 0x03])),         # Vendor-Specific event
    ]))

    # Exported PDU, no bluetooth_data_t
    sections.append(('Exported PDU', [
        # Reproducer bthci_vendor_broadcom_multiadv_null_data.py
        exppdu(vcmd_raw(0x0154, bytes([0x02, 0x05, 0x09]) + b'test' + bytes(31 - 6) + bytes([0x01])), 0),
        exppdu(vcmd_raw(0x0154, bytes([0x03]) + ad31(b'exp') + bytes([0x02])), 0),
        # Reproducer bthci_vendor_broadcom_energy_info.py
        exppdu(vevt_raw(0x0e, struct.pack('<BHB', 1, vop(0x0159), 0) + struct.pack('<IIII', 1000, 2000, 3000, 4000)), 1),
        exppdu(vcmd_raw(0x0001, BD1), 0),                    # Write BD ADDR, not stored
        exppdu(vcmd_raw(0x0154, bytes([0x01]) + le16(0x00a0) + le16(0x00b0) + bytes([0x00, 0x01]) + BD1 +
                        bytes([0x00]) + BD2 + bytes([0x07, 0x00, 0x01, 0xf8])), 0),
        exppdu(vevt_raw(0x0e, struct.pack('<BHB', 1, vop(0x005A), 0) + le16(0x0a5c) + le16(0x21e8)), 1),
        exppdu(vevt_raw(0xff, bytes([0x01, 0x02])), 1),
        exppdu(vevt_raw(0xfd, bytes([0x01])), 1),            # event code without a name
        exppdu(bytes([0x01, 0x02, 0x03])),                   # unknown direction
        exppdu(b''),                                         # unknown direction, empty
    ]))
    return sections


def malformed_frames():
    f = []
    f += read_local_version()

    def c(ocf, params, plen=None):
        f.append((H4, struct.pack('>I', 0) + b'\x01' + vcmd_raw(ocf, params, plen)))

    def e(ocf, status, ret):
        f.append(cc(vop(ocf), status, ret))

    c(0x0153, bytes([0x01]))                     # no-parameter command with a parameter
    c(0x0154, bytes([0x01, 0x02]))               # short Set Parameter
    c(0x0154, bytes([0x02]) + bytes(10))         # short advertising data
    c(0x0157, bytes([0x09, 0x00, 0x01, 0xaa]))   # Add with an unknown subcode
    c(0x0157, bytes([0x03, 0x01, 0x01, 0xaa]))   # Delete with data
    c(0x015D, bytes([0x02, 0x01]))               # Stop (legacy) with a parameter
    c(0x015D, bytes([0x05, 0x01]))               # unknown subcode with a parameter
    c(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x00]) + le16(895) +
      bytes([0x00, 0x00, 0xc8]) + bytes(4))       # vendor parameters length > 128
    c(0x015D, bytes([0x01]) + le32(0x01))        # truncated Start (legacy)
    c(0x003B, bytes([0x01, 0x02]))               # extra parameter
    c(0x0018, bytes([0x00]), 6)                  # parameter length larger than data
    e(0x0153, 0, bytes(5))                       # short capabilities
    e(0x0001, 0, bytes([0x01]))                  # return parameter after Write BD ADDR
    e(0x0159, 0, bytes(8))                       # short energy info
    e(0x005A, 0, le16(1) + le16(2) + bytes([0x99]))  # extra return parameter
    # bthci_vendor.broadcom called by name with odd data
    f.append(exppdu(vcmd_raw(0x0154, bytes([0x02]) + bytes(4)), 0))
    f.append(exppdu(vcmd_raw(0x0001, BD1) + b'\x99', 0))   # data after the parameters
    f.append(exppdu(vevt_raw(0x0e, bytes([1])), 1))
    f.append(exppdu(b'\x01', 0))
    f.append(exppdu(b'\x0e', 1))
    return f


def main():
    pkts = []
    for name, fr in main_frames():
        print('%-45s frames %d-%d' % (name, len(pkts) + 1, len(pkts) + len(fr)))
        pkts += fr
    write_pcapng(os.path.join(OUT, 'bthci_vendor_broadcom-coverage.pcapng'), [201, 252], pkts)
    mal = malformed_frames()
    print('malformed: %d frames' % len(mal))
    write_pcapng(os.path.join(OUT, 'bthci_vendor_broadcom-coverage-malformed.pcapng'), [201, 252], mal)


main()

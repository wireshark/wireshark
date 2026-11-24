#!/usr/bin/env python3
# Generates test/captures/bthci_vendor_android_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the Android HCI vendor dissector
# (epan/dissectors/packet-bthci_vendor_android.c, "bthci_vendor.android").
# Every packet is built with struct; nothing comes from a real device.
#
# Usage: mkbthci_vendor_android.py <outdir>
# Writes
#   bthci_vendor_android-coverage.pcapng: interface 0 HCI H4 with direction
#     (DLT 201): Read Local Version Information naming Google (0x00E0),
#     then vendor commands, their Command Complete events and Bluetooth
#     Quality Report vendor events; interface 1 Exported PDU (DLT 252)
#     naming "bthci_vendor.android" (no bluetooth_data_t), with the
#     reproducers.
#   bthci_vendor_android-coverage-malformed.pcapng: the same two
#     interfaces, frames that only malformed input reaches.
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

H4, EXPPDU = 0, 1
MANUFACTURER = 0x00E0   # Google


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


def exppdu(payload, direction=None, name='bthci_vendor.android'):
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



def vendor_capabilities(version, extra=b''):
    # max adv instance, RPA offload, total scan results, max IRK list,
    # filter support, max filter, energy support, version (at offset 8),
    # advertisers tracked, extended scan, debug logging, address generation,
    # A2DP source offload mask, BQR support, dynamic audio buffer mask
    return bytes([4, 1]) + le16(1024) + bytes([16, 1, 32, 1]) + le16(version) + le16(64) + \
        bytes([1, 1, 1]) + le32(0x0000001f) + bytes([1]) + le32(0x00000007) + extra


def bqr_link():
    return bytes([0x19]) + le16(0x0001) + bytes([0x00, 0x04, 0xc4, 0x1e, 0x05, 0x03]) + le16(8000) + \
        b''.join(le32(v) for v in (0x123456, 2, 3, 4, 0x2000, 5, 0x3000, 6, 7)) + BD1 + bytes([0]) + \
        b''.join(le32(v) for v in (100, 1, 2, 3, 4, 5, 6)) + le16(0x0005)


def bqr_energy():
    return le16(120) + b''.join(le32(v) for v in (1, 2, 3, 4, 5, 6)) + bytes([0xf6]) + le32(7) + le32(8) + \
        le32(9) + le32(10) + bytes([0xfb]) + le32(11) + le32(12) + \
        b''.join(le32(v) for v in range(13, 13 + 9))


def bqr_advanced(ext):
    return bytes([ext]) + b''.join(le32(v) for v in range(1, 1 + 25)) + bytes([10, 11, 12, 13]) + \
        le32(0x04030201)


def bqr_health():
    return le32(1000) + le32(2000) + le16(27) + le16(255) + \
        b''.join(le32(v) for v in range(1, 8)) + le16(0x0003) + bytes([2, 1, 1, 0])


def bqr_lea():
    return bytes([0x01, 0x00]) + BD1 + bytes([0xff] * 4 + [0x1f]) + bytes([0xff] * 4 + [0x0f]) + \
        bytes([0x04]) + le32(0x10000) + struct.pack('<I', 0x123456)[:3] + bytes([0x01]) + BD2 + \
        le32(1000) + le32(3) + le32(10) + le32(1) + bytes([0xff] * 4 + [0x1f]) + bytes([0x02, 0xc4]) + bytes(4)


V = bytes([0x56, 0x44])   # vendor specific parameters after a report


def bqr_event(report_id, body, vendor=b''):
    return evt(0xff, bytes([0x58, report_id]) + body + vendor)


def main_frames():
    """(section name, frames)."""
    sections = []
    sections.append(('Read Local Version Information (Google)', read_local_version()))

    f = []

    def c(ocf, params):
        f.append(cmd(vop(ocf), params))

    def e(ocf, status, ret=b''):
        f.append(cc(vop(ocf), status, ret))

    def pair(ocf, params, ret=b'', status=0):
        c(ocf, params)
        e(ocf, status, ret)

    # LE Get Vendor Capabilities: version 0.96 (fields valid), 0.98 (reserved),
    # 1.05 (ISO feedback, sniff offload) and 1.06 (BIG channel map, handles)
    pair(0x0153, b'', vendor_capabilities(0x0060))
    pair(0x0153, b'', vendor_capabilities(0x0060, bytes([1])))
    pair(0x0153, b'', vendor_capabilities(0x0098, bytes([1])))
    pair(0x0153, b'', vendor_capabilities(0x0105, bytes([1, 1, 0])))
    pair(0x0153, b'', vendor_capabilities(0x0106, bytes([1, 1, 1]) + le16(0x0003) + le16(0x0100) +
                                           le16(0x01ff) + bytes([0x40])))
    pair(0x0153, b'', status=0x01)
    # LE Multi Advertising
    pair(0x0154, bytes([0x01]) + le16(0x00a0) + le16(0x00b0) + bytes([0x00, 0x01]) + BD1 +
         bytes([0x00]) + BD2 + bytes([0x07, 0x00, 0x01, 0xf8]), bytes([0x01]))
    pair(0x0154, bytes([0x02]) + ad31(b'ANDROID-ADV') + bytes([0x01]), bytes([0x02]))
    pair(0x0154, bytes([0x03]) + ad31(b'ANDROID-SCAN') + bytes([0x01]), bytes([0x03]))
    pair(0x0154, bytes([0x04]) + BD1 + bytes([0x02]), bytes([0x04]))
    pair(0x0154, bytes([0x05, 0x01, 0x02]), bytes([0x05]))
    pair(0x0154, bytes([0x06]), bytes([0x06]))              # unknown subcode
    # LE Batch Scan
    pair(0x0156, bytes([0x01, 0x01]), bytes([0x01]))
    pair(0x0156, bytes([0x02, 0x32, 0x0a, 0x5f]), bytes([0x02]))
    pair(0x0156, bytes([0x03, 0x03]) + le32(0x12) + le32(0x400) + bytes([0x00, 0x01]), bytes([0x03]))
    pair(0x0156, bytes([0x04, 0x01]), bytes([0x04, 0x01, 0x05]))
    pair(0x0156, bytes([0x04, 0x02]), bytes([0x04]), status=0x0c)
    pair(0x0156, bytes([0x07]), bytes([0x07]))
    sections.append(('capabilities, multi advertising, batch scan', f))

    # APCF
    f = []
    filt = bytes([0x00, 0x03]) + le16(0x007f) + le16(0x0001) + bytes([0x01, 0xc4, 0x01]) + le16(500) + \
        bytes([0x02, 0xa6]) + le16(1000) + le16(8)
    # Set Filtering Parameters cut after each optional field
    cuts = [0, 2, 6, 7, 8, 9, 11, 12, 13, 15, 17]
    c(0x0157, bytes([0x00, 0x01]))                  # Enable (Enable)
    e(0x0157, 0, bytes([0x00, 0x01]))
    c(0x0157, bytes([0x00, 0x00]))                  # Enable (Disable)
    e(0x0157, 0, bytes([0x00]))                     # without the enable octet
    c(0x0157, bytes([0x00]))                        # Enable without a value
    for n in cuts:
        c(0x0157, bytes([0x01]) + filt[:n])
    c(0x0157, bytes([0x01, 0x02, 0x03]))            # Clear: no further parameters
    e(0x0157, 0, bytes([0x01, 0x00, 0x0f]))
    e(0x0157, 0, bytes([0x01, 0x02]))               # without available spaces
    e(0x0157, 0, bytes([0x01]))                     # without action
    c(0x0157, bytes([0x02, 0x00, 0x03]) + BD1 + bytes([0x02]))  # Broadcaster Address
    c(0x0157, bytes([0x02]))
    e(0x0157, 0, bytes([0x02, 0x00, 0x0e]))
    c(0x0157, bytes([0x03, 0x00, 0x03]) + le16(0x180d) + le16(0xffff))  # 16-bit Service UUID
    c(0x0157, bytes([0x03, 0x01, 0x03]) + bytes(range(16)) + b'\xff' * 16)  # 128-bit, Delete
    c(0x0157, bytes([0x03, 0x02, 0x03]))            # Clear
    c(0x0157, bytes([0x03, 0x00, 0x03]))            # nothing after the index
    c(0x0157, bytes([0x03]))
    e(0x0157, 0, bytes([0x03, 0x00, 0x0d]))
    c(0x0157, bytes([0x04, 0x00, 0x03]) + le16(0xfe2c) + le16(0xffff))  # Solicitation UUID
    e(0x0157, 0, bytes([0x04, 0x00, 0x0c]))
    c(0x0157, bytes([0x05, 0x00, 0x03]) + b'Pixel')  # Local Name
    e(0x0157, 0, bytes([0x05, 0x00, 0x0b]))
    c(0x0157, bytes([0x06, 0x00, 0x03]) + bytes([0xe0, 0x00, 0x01, 0x02]) + b'\xff' * 4)  # Manufacturer
    e(0x0157, 0, bytes([0x06, 0x00, 0x0a]))
    c(0x0157, bytes([0x07, 0x00, 0x03]) + bytes([0xaa, 0xfe, 0x10]) + b'\xff' * 3)  # Service Data
    e(0x0157, 0, bytes([0x07, 0x00, 0x09]))
    c(0x0157, bytes([0x08, 0x00, 0x03]))            # Transport Discovery Service
    c(0x0157, bytes([0x08]))
    e(0x0157, 0, bytes([0x08]))                     # (no specific decoding)
    c(0x0157, bytes([0x09, 0x00, 0x03, 0x16, 0x03]) + bytes([0xaa, 0xfe, 0x10]) + b'\xff' * 3)  # AD Type
    c(0x0157, bytes([0x09, 0x00, 0x03, 0x16, 0x00]))  # AD data length 0
    c(0x0157, bytes([0x09, 0x00, 0x03, 0x16, 0x04]))  # length 4, no data
    c(0x0157, bytes([0x09, 0x00, 0x03]))              # nothing after the index
    c(0x0157, bytes([0x09, 0x02, 0x03]))              # Clear
    c(0x0157, bytes([0x09]))
    e(0x0157, 0, bytes([0x09, 0x00, 0x08]))
    c(0x0157, bytes([0xff]))                          # Read Extended Features
    e(0x0157, 0, bytes([0xff]) + le16(0x0001))
    e(0x0157, 0, bytes([0xff]))
    c(0x0157, bytes([0x0a]))                          # unknown subcode
    e(0x0157, 0, bytes([0x0a]))
    e(0x0157, 0x0c, bytes([0x01]))                    # failure
    sections.append(('APCF', f))

    f = []
    # Bluetooth Quality Report command
    pair(0x015E, bytes([0x00]) + le32(0x0001003f) + le16(500) + le32(0x00000003) + le32(0x00000001) +
         le32(2), le32(0x0001003f) + le32(0x00000003) + le32(0x00000001) + le32(500))
    pair(0x015E, bytes([0x03]) + le32(0x00000001) + le16(100), le32(0x00000001))
    pair(0x015E, bytes([0x03]) + le32(0x00000001))
    pair(0x015E, bytes([0x02]))
    pair(0x015E, b'', status=0x12)
    pair(0x0159, b'', le32(1000) + le32(2000) + le32(3000) + le32(4000))  # Energy Info
    pair(0x0159, b'', status=0x01)
    # A2DP Hardware Offload
    pair(0x015D, a2dp_start_legacy(0x01, (0x00, 0x00), 0, SBC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x02, (0x01, 0x01), 256000, AAC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x01, 0x02), 0x01000000, LDAC_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x00, 0x00), 990000, LDAC_RES_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x10, (0x00, 0x00), 0, LDAC_ABR_INFO), bytes([0x01]))
    pair(0x015D, a2dp_start_legacy(0x08, (0x00, 0x00), 352000, bytes(range(32))), bytes([0x01]))
    pair(0x015D, bytes([0x02]), bytes([0x02]))
    pair(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x00]) + le16(895) +
         bytes([0x01, 0x02, 0x04]) + bytes([0xde, 0xad, 0xbe, 0xef]), bytes([0x03]))
    pair(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x01]) + le16(895) +
         bytes([0x00, 0x00, 0x00]), bytes([0x03]))
    pair(0x015D, bytes([0x04]) + le16(0x0040) + le16(0x0041) + bytes([0x00]), bytes([0x04]))
    pair(0x015D, bytes([0x05]), bytes([0x05]))
    pair(0x0158, bytes([0x01, 0x02]), bytes([0x03, 0x04]))  # LE Tracking Advertising (not decoded)
    pair(0x0200, b'')                                       # unknown command
    sections.append(('BQR, energy info, A2DP offload, others', f))

    sections.append(('vendor events', [
        # A report without vendor specific data at the end is malformed (see
        # README), so every report here carries some.
        bqr_event(0x01, bqr_link(), V),
        bqr_event(0x02, bqr_link(), V),
        bqr_event(0x03, bqr_link(), V),
        bqr_event(0x04, bqr_link(), V),
        bqr_event(0x07, bqr_link(), V),
        bqr_event(0x08, bqr_link(), V),
        bqr_event(0x05, bytes([0x01, 0x80]), V),
        bqr_event(0x06, bqr_energy(), V),
        bqr_event(0x09, bqr_advanced(0x01), V),
        bqr_event(0x0a, bqr_advanced(0x03), V),
        bqr_event(0x0b, bqr_health(), V),
        bqr_event(0x0c, bqr_health(), V),
        bqr_event(0x11, le16(0x0001), V),
        bqr_event(0x12, le16(0x0002), V),
        bqr_event(0x13, le16(0x0003), V),
        bqr_event(0x16, bqr_lea(), V),
        bqr_event(0x0d, b'', V),                          # unknown report id
        evt(0xff, bytes([0x58])),                         # BQR without report id
        evt(0xff, bytes([0x55, 0x01, 0x00])),             # other sub-event
        cmd(vop(0x0156), bytes([0x04, 0x01])),
        cs(vop(0x0156)),                                  # Command Status
    ]))

    sections.append(('Exported PDU', [
        # Reproducers bthci_vendor_broadcom_android_multiadv_null_data.py and
        # bthci_vendor_android_null_bluetooth_data.py (the same PDU)
        exppdu(vcmd_raw(0x0154, bytes([0x02, 0x05, 0x09]) + b'test' + bytes(31 - 6) + bytes([0x01])), 0),
        exppdu(vcmd_raw(0x0154, bytes([0x03]) + ad31(b'exp') + bytes([0x02])), 0),
        exppdu(vcmd_raw(0x0154, bytes([0x01]) + le16(0x00a0) + le16(0x00b0) + bytes([0x00, 0x01]) + BD1 +
                        bytes([0x00]) + BD2 + bytes([0x07, 0x00, 0x01, 0xf8])), 0),
        exppdu(vcmd_raw(0x0157, bytes([0x02, 0x00, 0x03]) + BD1 + bytes([0x02])), 0),
        exppdu(vevt_raw(0x0e, struct.pack('<BHB', 1, vop(0x0159), 0) + struct.pack('<IIII', 1000, 2000, 3000, 4000)), 1),
        exppdu(vevt_raw(0xff, bytes([0x58, 0x01]) + bqr_link() + V), 1),
        exppdu(vevt_raw(0xff, bytes([0x58, 0x16]) + bqr_lea() + V), 1),
        exppdu(vevt_raw(0xfd, bytes([0x01])), 1),            # event code without a name
        exppdu(vevt_raw(0xff, b''), 1),                      # empty vendor event
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
    c(0x0159, bytes([0x01]))
    c(0x0154, bytes([0x01, 0x02]))               # short Set Parameter
    c(0x0154, bytes([0x02]) + bytes(10))         # short advertising data
    c(0x0154, bytes([0x05, 0x01, 0x02, 0x03]))   # extra parameter
    c(0x0157, bytes([0x00, 0x01, 0x02]))         # APCF Enable with extra data
    c(0x0157, bytes([0x01, 0x00, 0x01, 0x7f]))   # odd cut in Set Filtering Parameters
    c(0x0157, bytes([0x02, 0x00, 0x01, 0x01]))   # short Broadcaster Address
    c(0x015D, bytes([0x02, 0x01]))               # Stop (legacy) with a parameter
    c(0x015D, bytes([0x05, 0x01]))               # unknown subcode with a parameter
    c(0x015D, bytes([0x03]) + le16(0x0040) + le16(0x0041) + bytes([0x00]) + le16(895) +
      bytes([0x00, 0x00, 0xc8]) + bytes(4))       # vendor parameters length > 128
    c(0x015D, bytes([0x01]) + le32(0x01))        # truncated Start (legacy)
    c(0x0201, bytes([0x01, 0x02]))               # unknown command with parameters
    c(0x015E, bytes([0x00, 0x01]))               # BQR with an odd trailing octet
    e(0x0153, 0, bytes(5))                       # short capabilities
    e(0x0153, 0, vendor_capabilities(0x0106, bytes([1, 1, 1, 0x02])))  # extra octets
    e(0x0159, 0, bytes(8))                       # short energy info
    e(0x0154, 0, bytes([0x01, 0x99]))            # extra return parameter
    e(0x0201, 0, bytes([0x01]))                  # unknown command
    f.append(bqr_event(0x05, bytes([0x01, 0x80])))   # report without vendor data
    f.append(bqr_event(0x12, le16(0x0002)))
    f.append(bqr_event(0x01, bqr_link()[:20]))   # truncated link report
    f.append(bqr_event(0x06, bqr_energy()[:10]))
    f.append(bqr_event(0x09, bqr_advanced(1)[:10]))
    f.append(bqr_event(0x0b, bqr_health()[:10]))
    f.append(bqr_event(0x16, bqr_lea()[:10]))
    # bthci_vendor.android called by name with odd data
    f.append(exppdu(vcmd_raw(0x0154, bytes([0x02]) + bytes(4)), 0))
    f.append(exppdu(vcmd_raw(0x0153, b'') + b'\x99', 0))   # data after the parameters
    f.append(exppdu(vevt_raw(0x10, bytes([0x01, 0x02])), 1))  # other event with data
    f.append(exppdu(vevt_raw(0x0e, bytes([1])), 1))
    f.append(exppdu(b'\x01', 0))
    f.append(exppdu(b'\x0e', 1))
    return f


def main():
    pkts = []
    for name, fr in main_frames():
        print('%-45s frames %d-%d' % (name, len(pkts) + 1, len(pkts) + len(fr)))
        pkts += fr
    write_pcapng(os.path.join(OUT, 'bthci_vendor_android-coverage.pcapng'), [201, 252], pkts)
    mal = malformed_frames()
    print('malformed: %d frames' % len(mal))
    write_pcapng(os.path.join(OUT, 'bthci_vendor_android-coverage-malformed.pcapng'), [201, 252], mal)


main()

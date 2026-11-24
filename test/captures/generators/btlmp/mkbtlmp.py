#!/usr/bin/env python3
# Generates test/captures/btlmp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the Bluetooth Link Manager Protocol
# dissector (epan/dissectors/packet-btlmp.c, protocol "btlmp"). Every
# packet is built with struct; nothing comes from a real device.
#
# Usage: mkbtlmp.py <outdir>
# Writes
#   btlmp-coverage.pcapng            main capture: interface 0 is Exported
#       PDU (252) naming "btlmp", interface 1 is
#       LINKTYPE_BLUETOOTH_BREDR_BB (255) carrying LMP in DM1 packets on a
#       connection set up by a page FHS (so btlmp gets a connection_info_t)
#   btlmp-coverage-malformed.pcapng  PDUs cut short
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

LT_EXPPDU = 252
LT_BREDR_BB = 255
IF_EXP, IF_BB = 0, 1


def pcapng_block(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)


def write_pcapng(path, frames):
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for lt in (LT_EXPPDU, LT_BREDR_BB):
            f.write(pcapng_block(1, struct.pack('<HHI', lt, 0, 65535)))
        for i, (ifid, data) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                                len(data), len(data)) + data))


def exppdu(payload, name='btlmp'):
    n = name.encode()
    pad = (-len(n)) % 4
    return (IF_EXP, struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload)


def lmp(op, params=b'', tid=0):
    """op < 0x100: 7 bit opcode; 0x100-0x4ff: escape (op >> 8) with the
    extended opcode in the low octet (escape 4 = 0x7f)."""
    if op >= 0x100:
        return bytes([((0x7c + (op >> 8) - 1) << 1) | tid, op & 0xff]) + params
    return bytes([(op << 1) | tid]) + params


def le16(v):
    return struct.pack('<H', v)


def le32(v):
    return struct.pack('<I', v)


RAND = bytes(range(0x10, 0x20))
KEY = bytes(range(0xa0, 0xb0))
BD = bytes([0xd6, 0xc5, 0xb4, 0xa3, 0x92, 0x0a])

# --- BR/EDR baseband (from btbredr_rf-coverage/mkbtbredr_rf.py) -------------
F_DEWHITENED, F_SP, F_NP, F_DECRYPTED, F_LAP_VALID, F_DATA = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
F_UAP_VALID, F_HEC_CHECKED, F_HEC_PASS, F_CRC_CHECKED, F_CRC_PASS = 0x80, 0x100, 0x200, 0x400, 0x800
OK = F_DEWHITENED | F_DECRYPTED | F_DATA | F_CRC_CHECKED | F_CRC_PASS | \
    F_HEC_CHECKED | F_HEC_PASS | F_LAP_VALID | F_UAP_VALID | F_SP | F_NP
ACL_BR = 0x30
P_LAP, P_UAP, P_NAP = 0x0aa1b2, 0xdc, 0x0a1b    # peripheral 0a:1b:dc:0a:a1:b2
C_LAP, C_UAP, C_NAP = 0x0cc1d2, 0x7d, 0x0a1b    # central 0a:1b:7d:0c:c1:d2


def rev8(v):
    v = ((v >> 1) & 0x55) | ((v << 1) & 0xaa)
    v = ((v >> 2) & 0x33) | ((v << 2) & 0xcc)
    return ((v >> 4) & 0x0f) | ((v << 4) & 0xf0)


def check_hec(uap, h):
    h &= 0x3ffff
    h ^= rev8(uap) & 0xff
    for _ in range(10):
        if h & 1:
            h ^= (0xe5 << 1)
        h >>= 1
    return h == 0


def header(uap, ltaddr, ptype, flow=1, arqn=0, seqn=0):
    d = ltaddr | (ptype << 3) | (flow << 7) | (arqn << 8) | (seqn << 9)
    for hec in range(256):
        if check_hec(uap, d | (hec << 10)):
            return d | (hec << 10)
    raise Exception("no hec")


def crc16(uap, data):
    crc = rev8(uap) << 8
    for b in data:
        crc ^= b
        for _ in range(8):
            x = crc & 1
            crc >>= 1
            if x:
                crc ^= 0x8408
    return crc


def with_crc(uap, data):
    return data + struct.pack('<H', crc16(uap, data))


def bb(lap, uap, hdr, flags, payload, chan=4, pt=ACL_BR):
    return (IF_BB, struct.pack('<BbbBBBh', chan, -45, -90, 0, pt, 0, 0) +
            struct.pack('<I', lap) + struct.pack('<I', lap)[:3] + bytes([uap]) +
            struct.pack('<I', hdr) + struct.pack('<H', flags) + payload)


def fhs(lap, uap, nap, ltaddr, clk=0x123456, cod=0x5a020c, eir=1, sr=1, sp=2):
    w = 0x2b3c4d5e1 | (lap << 34) | (eir << 58) | (sr << 60) | (sp << 62)
    return struct.pack('<QBH', w, uap, nap) + struct.pack('<I', cod)[:3] + \
        struct.pack('<I', ltaddr | (clk << 3))


seqn = [0]


def dm1_lmp(pdu):
    s = seqn[0]
    seqn[0] ^= 1
    body = bytes([3 | (1 << 2) | (len(pdu) << 3)]) + pdu
    return bb(C_LAP, C_UAP, header(C_UAP, 1, 3, arqn=1, seqn=s), OK, with_crc(C_UAP, body))


def features(page):
    return {0: bytes.fromhex('bffecffedbff7b87'), 1: bytes.fromhex('0f00000000000000'),
            2: bytes.fromhex('ff03000000000000')}.get(page, bytes(8))


# --- Main capture --------------------------------------------------------------

def main_frames():
    f = []

    def x(op, params=b'', tid=0):
        f.append(exppdu(lmp(op, params, tid)))

    # Basic opcodes 1-0x42 in order, spec layout, alternating TID
    x(0x01, b'\x00')                                     # name_req (offset)
    x(0x02, b'\x00\x0d' + b'Coverage host' + b'\x00', 1)  # name_res
    x(0x02, b'\x00\x00')                                 # name_res, empty name, no fragment
    x(0x03, b'\x33')                                     # accepted
    x(0x04, b'\x2b\x1a', 1)                              # not_accepted
    x(0x05)                                              # clkoffset_req
    x(0x06, le16(0x1234), 1)                             # clkoffset_res
    x(0x07, b'\x13')                                     # detach
    for op in (0x08, 0x09, 0x0b, 0x0d, 0x11):            # in_rand, comb_key, au_rand, temp_rand, start_encryption_req
        x(op, RAND)
    x(0x0a, KEY)                                         # unit_key
    x(0x0c, le32(0xcafef00d), 1)                         # sres
    x(0x0e, KEY)                                         # temp_key
    x(0x0f, b'\x01')                                     # encryption_mode_req
    x(0x10, b'\x10')                                     # encryption_key_size_req
    x(0x12)                                              # stop_encryption_req
    x(0x13, le32(0x00010000))                            # switch_req
    x(0x14, le16(0x0400) + le32(0x00020000))             # hold
    x(0x15, le16(0x0800) + le32(0x00030000))             # hold_req
    x(0x17, b'\x02' + le16(0) + le16(800) + le16(4) + le16(1))   # sniff_req
    x(0x18)                                              # unsniff_req
    x(0x1f, b'\x00')                                     # incr_power_req
    x(0x20, b'\x00')                                     # decr_power_req
    x(0x21)                                              # max_power
    x(0x22)                                              # min_power
    x(0x23)                                              # auto_rate
    # The reproducer btlmp_preferred_rate.py byte for byte:
    # LMP_preferred_rate, no FEC, 3-slot packets, 2 Mb/s 3-slot
    f.append(exppdu(bytes([(0x24 << 1) | 0, 0x15])))
    x(0x25, b'\x0b' + le16(0x0002) + le16(0x2209))       # version_req
    x(0x26, b'\x0c' + le16(0x000f) + le16(0x1234), 1)    # version_res
    x(0x27, features(0))                                 # features_req
    x(0x28, bytes.fromhex('40a50a1424508000'), 1)        # features_res (other bits)
    x(0x29, le16(40) + b'\x02')                          # quality_of_service
    x(0x2a, le16(50) + b'\x03')                          # quality_of_service_req
    x(0x2b, b'\x01\x02\x00\x06\x02\x02')                 # SCO_link_req (HV3, CVSD)
    x(0x2c, b'\x01\x13')                                 # remove_SCO_link_req
    x(0x2d, b'\x05')                                     # max_slot
    x(0x2e, b'\x03')                                     # max_slot_req
    x(0x2f)                                              # timing_accuracy_req
    x(0x30, b'\x14\x0a', 1)                              # timing_accuracy_res
    x(0x31)                                              # setup_complete
    x(0x32)                                              # use_semi_permanent_key
    x(0x33)                                              # host_connection_req
    x(0x34, le16(625) + BD)                              # slot_offset
    x(0x35, b'\x00\x01')                                 # page_mode_req
    x(0x36, b'\x00\x02')                                 # page_scan_mode_req
    x(0x37, le16(0x7d00))                                # supervision_timeout
    x(0x38)                                              # test_activate
    x(0x39, bytes([0x01, 0x00, 0x27, 0x27, 0x00, 0x0a, 0x04, 0x1b]))   # test_control
    x(0x3a)                                              # encryption_key_size_mask_req
    x(0x3b, le16(0xfff0), 1)                             # encryption_key_size_mask_res
    x(0x3c, le32(0x00040000) + b'\x01' + bytes.fromhex('fffffffffffffffffe7f'))   # set_AFH
    x(0x3d, b'\x01\x02\x04')                             # encapsulated_header (P-256)
    x(0x3e, bytes(range(16)))                            # encapsulated_payload
    x(0x3f, bytes(range(16, 32)))                        # Simple_Pairing_Confirm
    x(0x40, bytes(range(32, 48)), 1)                     # Simple_Pairing_Number
    x(0x41, bytes(range(48, 64)))                        # DHkey_Check
    x(0x42, RAND)                                        # pause_encryption_aes_req
    # Opcodes the dissector does not decode: 0 and reserved ones, with a
    # parameter octet each
    for op in (0x00, 0x16, 0x19, 0x1e, 0x43, 0x7b):
        x(op, b'\x5a')
    # Escape 1-3 (opcodes 124-126) with an extended opcode
    for esc in (1, 2, 3):
        x(esc << 8 | 0x01, b'\x01\x02')
    # Escape 4 (opcode 127)
    for esc_op in (0x7c, 0x7d, 0x7e, 0x7f):              # accepted_ext for every escape
        x(0x401, bytes([esc_op, 0x0c]), 1)
    x(0x402, bytes([0x7f, 0x0b, 0x11]))                  # not_accepted_ext
    for page in (0, 1, 2, 3):                            # features_req_ext / res_ext
        x(0x403, bytes([page, 2]) + features(page))
        x(0x404, bytes([page, 2]) + features(page), 1)
    x(0x405, b'\x01' + le32(0x00050000) + le16(0xfe0c) + b'\x02\x01' + le32(0x00060000))   # clk_adj
    x(0x406, b'\x01', 1)                                 # clk_adj_ack
    x(0x407, le16(0x0100) + b'\x01\x10')                 # clk_adj_req
    x(0x40b, b'\x01')                                    # packet_type_table_req
    # eSCO_link_req: 2-EV3 both ways, 60 octets, transparent, two
    # negotiation states
    x(0x40c, bytes([5, 2, 0, 0, 12, 4, 0x26, 0x26]) + le16(60) + le16(60) + b'\x03\x00')
    x(0x40c, bytes([6, 3, 2, 2, 6, 2, 0x07, 0x00]) + le16(30) + le16(0) + b'\x02\x03', 1)
    x(0x40d, b'\x05\x13')                                # remove_eSCO_link_req
    x(0x410, b'\x01' + le16(0x0640) + le16(0xbb80))      # channel_classification_req
    x(0x411, bytes([0x1b, 0xe4, 0xff, 0x00, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x07]))   # channel_classification
    x(0x415, b'\x04' + le16(0x0010) + le32(0x00070000))  # sniff_subrating_req
    x(0x416, b'\x02' + le16(0x0020) + le32(0x00080000), 1)   # sniff_subrating_res
    x(0x417)                                             # pause_encryption_req
    x(0x418)                                             # resume_encryption_req
    x(0x419, b'\x01\x00\x03')                            # IO_Capability_req
    x(0x41a, b'\x03\x01\x05', 1)                         # IO_Capability_res
    x(0x41b)                                             # numeric_comparison_failed
    x(0x41c)                                             # passkey_failed
    x(0x41d)                                             # oob_failed
    x(0x41e, b'\x01')                                    # keypress_notification
    x(0x41f, b'\x02')                                    # power_control_req
    x(0x420, b'\x26', 1)                                 # power_control_res
    x(0x421)                                             # ping_req
    x(0x422, b'', 1)                                     # ping_res
    x(0x423, b'\x01' + bytes(range(14)))                 # SAM_set_type0
    x(0x424, b'\x02\x10\x04' + bytes(range(12)))         # SAM_define_map
    x(0x425, b'\x02\x00\x08' + le32(0x00090000))         # SAM_switch
    # Escape 4 opcodes the dissector does not decode
    for op in (0x408, 0x40e, 0x412, 0x426, 0x4ff):
        x(op, b'\x5a')

    # BR/EDR baseband: inquiry response FHS from the peripheral (GIAC),
    # page response FHS (central assigns LT_ADDR 1), then LMP in DM1
    # packets on that connection, including an eSCO link request for
    # LT_ADDR 2 (btlmp passes the connection to btbredr_rf)
    GIAC = 0x9e8b33
    f.append(bb(GIAC, 0, header(0, 0, 2), OK & ~F_UAP_VALID,
                with_crc(0, fhs(P_LAP, P_UAP, P_NAP, 0)), chan=2, pt=0x00))
    f.append(bb(P_LAP, 0, header(P_UAP, 0, 2), OK & ~F_UAP_VALID,
                with_crc(P_UAP, fhs(C_LAP, C_UAP, C_NAP, 1, eir=0, sr=0, sp=0))))
    f.append(dm1_lmp(lmp(0x25, b'\x0b' + le16(0x0002) + le16(0x2209))))
    f.append(dm1_lmp(lmp(0x26, b'\x0b' + le16(0x0002) + le16(0x2209), 1)))
    f.append(dm1_lmp(lmp(0x40c, bytes([5, 2, 0, 0, 6, 2, 7, 7]) + le16(30) + le16(30) + b'\x03\x00')))
    f.append(dm1_lmp(lmp(0x401, b'\x7f\x0c', 1)))
    # EV3 on the eSCO transport, LT_ADDR 2: btbredr_rf knows the link from
    # the request and takes the 30 octet payload as voice
    f.append(bb(C_LAP, C_UAP, header(C_UAP, 2, 7), OK,
                with_crc(C_UAP, bytes(range(0x40, 0x40 + 30))), pt=0x20))
    f.append(dm1_lmp(lmp(0x31)))
    return f


def malformed_frames():
    f = []

    def x(pdu):
        f.append(exppdu(pdu))
    # 1: empty
    x(b'')
    # 2: escape opcode without the extended opcode
    x(bytes([0x7f << 1]))
    # 3: short LMP_eSCO_link_req: the fields that are there, then the
    # exception (fixed on the branch: it used to stop before the fields)
    x(lmp(0x40c, bytes([5, 2, 0, 0, 6])))
    # 4-10: other PDUs cut short
    x(lmp(0x02, b'\x00'))                     # name_res without the length
    x(lmp(0x08, RAND[:8]))                    # in_rand
    x(lmp(0x17, b'\x02\x00'))                 # sniff_req
    x(lmp(0x27, b'\xff\xff'))                 # features_req
    x(lmp(0x3c, le32(0) + b'\x01\xff\xff'))   # set_AFH
    x(lmp(0x404, b'\x00'))                    # features_res_ext without the max page
    x(lmp(0x401, b''))                        # accepted_ext without the opcode
    x(lmp(0x411, b'\x1b\xe4'))                # channel_classification
    x(lmp(0x40d, b''))                        # remove_eSCO_link_req
    x(lmp(0x425, b'\x02'))                    # SAM_switch
    return f


write_pcapng(os.path.join(OUT, 'btlmp-coverage.pcapng'), main_frames())
write_pcapng(os.path.join(OUT, 'btlmp-coverage-malformed.pcapng'), malformed_frames())

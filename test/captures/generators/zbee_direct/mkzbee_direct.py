#!/usr/bin/env python3
# Generates test/captures/zbee_direct_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-zbee-direct.c (ZigBee Direct).

usage: mkzbee_direct.py <outdir> [-v]    (-v prints the frame ranges)

Writes zbee-direct-coverage.pcapng and zbee-direct-coverage-malformed.pcapng.

ZigBee Direct is reached over Bluetooth ATT (linktype 201): an HCI
connection, an ATT MTU exchange and Find Information responses map handles
to the characteristic UUIDs.  The ZBD Configuration cluster (0x003d) is
reached through ZCL over IEEE 802.15.4 (linktype 230).

No cryptography: encrypted frames are filler octets and never decrypt.
"Dump Info" notifications report made-up session keys in plaintext, as the
dissector expects (that is how it learns keys from a capture).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from zbeelib import (
    aps_data, att_find_info, att_indicate, att_mtu, att_notify, att_write, att_write_cmd, CH_DUMP,
    CH_FB, CH_FORM, CH_IDENTIFY, CH_JOIN, CH_LEAVE, CH_MANAGE, CH_PERMIT, CH_SEC_AESMMO,
    CH_SEC_P256, CH_SEC_SHA256, CH_STATUS, CH_TUNNEL, EUI_A, EUI_B, H, HANDLES, hci_conn_complete,
    ieee, LT_BLUETOOTH_H4_PHDR, LT_IEEE802_15_4_NOFCS, nwk, Pcapng, tlv, transport_key, wpan_data,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
BT, WP = LT_BLUETOOTH_H4_PHDR, LT_IEEE802_15_4_NOFCS
H_DUMP = H[CH_DUMP]


def key_n(i):
    return struct.pack('<I', i) + bytes([0x60 + (i % 16)]) * 12


def dump_key(i, zdd=0x00124b0001020304, zvd=0x00124b00aabbccdd):
    """Dump Info: set key (type 1): key, ZDD IEEE, ZVD IEEE."""
    return b'\x01' + key_n(i) + ieee(zdd) + ieee(zvd)


def wzcl(cluster, zcl, seq=1, src=0x0001, dst=0x0000):
    aps = aps_data(zcl, cluster, counter=seq)
    return wpan_data(nwk(aps, src=src, dst=dst, seq=seq, ext_src=EUI_A), seq=seq, src=src, dst=dst)


def run():
    p = Pcapng()
    marks = {}
    mal = Pcapng()
    mm = {}

    def setup(cap):
        cap.add(BT, hci_conn_complete())
        cap.add(BT, att_mtu(517, 0))
        cap.add(BT, att_mtu(517, 1))
        for i in range(0, len(HANDLES), 5):
            cap.add(BT, att_find_info(HANDLES[i:i + 5]))
    setup(p)
    setup(mal)

    def bt(name, ch, value, op='notify', cap=None, mk=None):
        cap = cap or p
        mk = marks if mk is None else mk
        mk.setdefault(name, []).append(len(cap) + 1)
        fn = {'notify': att_notify, 'write': att_write, 'cmd': att_write_cmd,
              'ind': att_indicate}[op]
        cap.add(BT, fn(H[ch], value))

    # ------------------------------------------------ plain characteristics
    bt('permit', CH_PERMIT, b'\x3c', 'write')              # open for 60 s
    bt('permit', CH_PERMIT, b'\x00', 'write')              # close
    bt('leave', CH_LEAVE, b'\x01\x01', 'write')            # remove children, rejoin
    bt('leave', CH_LEAVE, b'\x00\x00', 'write')
    bt('identify', CH_IDENTIFY, b'\x1e\x00', 'write')      # 30 s
    bt('identify', CH_IDENTIFY, b'\x00\x00', 'write')      # stop
    bt('fb', CH_FB, b'\x0a\x01', 'write')                  # endpoint 10, initiator
    bt('fb', CH_FB, b'\x01\x00', 'write')
    bt('form', CH_FORM, tlv(1, b'\x62\x1a') + tlv(2, bytes([1]) + struct.pack('<I', 0x07fff800)), 'write')
    bt('join', CH_JOIN, tlv(7, b'\x00') + tlv(8 + 1, ieee(EUI_A)), 'write')
    bt('status', CH_STATUS, tlv(8, ieee(EUI_B)) + tlv(10, b'\x0a'))
    bt('manage', CH_MANAGE, tlv(2, b'\x01') + tlv(1, ieee(EUI_B)) + tlv(0, bytes(range(16))), 'write')
    for ch, name in ((CH_SEC_AESMMO, 'secur'), (CH_SEC_SHA256, 'secur'), (CH_SEC_P256, 'secur')):
        for mt in (2, 3, 4, 1):                  # SE4 switches encryption on, SE1 off again
            bt(name, ch, bytes([mt]) + tlv(0, b'\x01\xff') + tlv(3, b'\x02'), 'write')
    bt('secur-unknown', CH_SEC_P256, bytes([9]) + tlv(3, b'\x02'), 'write')
    # plaintext tunnel traffic: a NWK command and a Transport Key (key goes in the NWK key ring)
    nwk_cmd = nwk(bytes([0x08, 0x61, 0x01, 0x00, 0x00]), cmd=True, src=0x1234, dst=0, ext_src=EUI_A, seq=1)
    nwk_tk = nwk(transport_key(key_n(900), dst64=EUI_B, src64=EUI_A, counter=3), src=0, dst=0x1234,
                 ext_src=EUI_A, seq=2)
    for n in (nwk_cmd, nwk_tk):
        bt('tunnel', CH_TUNNEL, tlv(0, bytes([0, len(n)]) + n))

    # ---------------------------------------------------- Dump Info: keys
    bt('dump-delete', CH_DUMP, b'\x00')                    # obsolete delete command
    bt('dump-key', CH_DUMP, dump_key(1))                   # one key reported over the air
    bt('dump-key', CH_DUMP, dump_key(2, zdd=0x00124b00000000a1))
    bt('dump-key', CH_DUMP, dump_key(1))                   # the same key again: not added twice
    bt('dump-key', CH_DUMP, dump_key(3, zvd=0x00124b00000000b2))
    # ------------------------------------- encryption on: nothing decrypts
    bt('enc-on', CH_DUMP, b'\x02\x01')
    bt('enc-on', CH_DUMP, b'\x02\x01')                     # already on
    bt('enc-frames', CH_STATUS, key_n(0)[:4] + b'\x5a' * 16)       # fails: key tried both as ZDD and ZVD
    bt('enc-frames', CH_PERMIT, b'\x01\x00\x00\x00' + b'\x5a' * 5, 'write')
    bt('enc-frames', CH_JOIN, b'\x02\x00\x00\x00' + b'\x5a' * 30, 'write')
    bt('enc-frames', CH_TUNNEL, b'\x03\x00\x00\x00' + b'\x5a' * 40)
    bt('enc-frames', CH_FB, b'\x04\x00\x00\x00' + b'\x5a' * 8, 'write')     # exactly counter + MIC
    bt('enc-short', CH_LEAVE, b'\x05\x00\x00', 'write')    # too short for counter and MIC
    bt('enc-short', CH_IDENTIFY, b'\x05\x00\x00\x00\x01\x02', 'write')
    # security service frames are never decrypted
    bt('enc-secur', CH_SEC_AESMMO, bytes([2]) + tlv(0, b'\x01\xff'), 'write')
    bt('enc-secur', CH_SEC_SHA256, bytes([3]) + tlv(3, b'\x04'), 'write')
    bt('enc-off', CH_DUMP, b'\x02\x00')
    bt('enc-off', CH_DUMP, b'\x02\x00')                    # already off
    bt('plain-after', CH_PERMIT, b'\x05', 'write')
    bt('plain-after', CH_LEAVE, b'\x01\x00', 'write')
    # a second encrypted block (the key ring now holds more keys)
    bt('dump-key', CH_DUMP, dump_key(4))
    bt('enc-on', CH_DUMP, b'\x02\x01')
    bt('enc-frames', CH_STATUS, b'\x09\x00\x00\x00' + b'\x5a' * 24)
    bt('enc-frames', CH_TUNNEL, b'\x0a\x00\x00\x00' + b'\x5a' * 24)
    # SE4 is sent while encryption is on, SE1 ends it
    bt('enc-secur', CH_SEC_AESMMO, bytes([1]) + tlv(0, b'\x01\xff'), 'write')
    bt('plain-after', CH_FB, b'\x01\x01', 'write')
    bt('enc-secur', CH_SEC_AESMMO, bytes([4]) + tlv(0, b'\x01\xff'), 'write')
    bt('enc-frames', CH_JOIN, b'\x0b\x00\x00\x00' + b'\x5a' * 20, 'write')
    bt('enc-off', CH_DUMP, b'\x02\x00')

    # --------------------------- the cap of 32 keys reported over the air
    # (keys 1-4 are in the ring already: 28 more fit, the next ones are refused)
    for i in range(10, 10 + 32):
        bt('dump-cap', CH_DUMP, dump_key(i))
    bt('dump-cap', CH_DUMP, dump_key(12))                  # a key in the ring (known)
    bt('dump-cap', CH_DUMP, dump_key(41))                  # a key that did not fit
    bt('enc-on', CH_DUMP, b'\x02\x01')
    bt('enc-frames-cap', CH_STATUS, b'\x20\x00\x00\x00' + b'\x5a' * 24)    # tries 32 keys
    bt('enc-frames-cap', CH_TUNNEL, b'\x21\x00\x00\x00' + b'\x5a' * 24)
    bt('enc-off', CH_DUMP, b'\x02\x00')
    bt('plain-after', CH_STATUS, tlv(8, ieee(EUI_A)))

    # ------------------------------------------- ZBD Configuration cluster
    seq = [0]

    def z(name, zcl, cluster=0x003d):
        seq[0] += 1
        marks.setdefault(name, []).append(len(p) + 1)
        p.add(WP, wzcl(cluster, zcl, seq=seq[0]))
    C = 0x01                                  # cluster specific, to the server
    Cs = 0x09                                 # cluster specific, from the server
    z('zcl-config', bytes([C, 1, 0x00, 0x01]))                         # Configure ZBD Interface: enabled
    z('zcl-config', bytes([C, 2, 0x00, 0xfe]))                         # reserved bits
    z('zcl-config', bytes([C, 3, 0x01]) + b'\x58\x02\x00')             # Anonymous Join Timeout 600 s
    z('zcl-config', bytes([C, 4, 0x07]))                               # unknown command to the server
    z('zcl-config', bytes([Cs, 5, 0x00, 0x00, 0x01]))                  # response: success, state enabled
    z('zcl-config', bytes([Cs, 6, 0x00, 0x85, 0x00]))                  # response: failure status
    z('zcl-config', bytes([Cs, 7, 0x09]))                              # unknown command from the server
    z('zcl-config', bytes([C, 8, 0x00, 0x01, 0xde, 0xad]))             # leftover octets
    # foundation commands naming the cluster attributes
    z('zcl-attr', bytes([0x08, 9, 0x01]) + struct.pack('<HBBB', 0x0000, 0, 0x18, 0x01)
      + struct.pack('<HBB', 0x0001, 0, 0x22) + b'\x58\x02\x00' + struct.pack('<HBB', 0x0002, 0, 0x20) + b'\x07')
    z('zcl-attr', bytes([0x08, 10, 0x0a]) + struct.pack('<HB', 0x0000, 0x18) + b'\x00'
      + struct.pack('<HB', 0x0001, 0x22) + b'\x2c\x01\x00')
    z('zcl-attr', bytes([0x00, 11, 0x00]) + struct.pack('<HH', 0x0000, 0x0001))
    z('zcl-attr', bytes([0x08, 12, 0x01]) + struct.pack('<HB', 0x0000, 0x86))      # unsupported attribute
    z('zcl-attr', bytes([0x00, 13, 0x02]) + struct.pack('<HB', 0x0000, 0x18) + b'\x01')   # write attribute
    p.write(os.path.join(OUT, 'zbee-direct-coverage.pcapng'))

    # ----------------------------------------------------------- malformed
    def m(name, ch, value, op='notify'):
        bt(name, ch, value, op, cap=mal, mk=mm)
    # more than the maximum ATT size while encrypted
    m('enc-huge', CH_DUMP, b'\x02\x01')
    m('enc-huge', CH_STATUS, b'\x01\x00\x00\x00' + b'\x5a' * 530)
    m('enc-huge', CH_DUMP, b'\x02\x00')
    # a Dump Info too short for its fields; empty Dump Info; encryption status without value
    m('dump-cut', CH_DUMP, b'\x01' + key_n(1)[:10])
    m('dump-cut', CH_DUMP, b'\x01' + key_n(1) + ieee(EUI_A)[:5])
    m('dump-cut', CH_DUMP, b'\x02')
    m('dump-cut', CH_DUMP, b'')
    m('dump-unknown-type', CH_DUMP, b'\x07')
    # empty security message, cut TLVs
    m('secur-cut', CH_SEC_P256, b'', 'write')
    m('secur-cut', CH_SEC_P256, bytes([2, 0]), 'write')
    m('permit-cut', CH_LEAVE, b'\x01', 'write')
    m('permit-cut', CH_FB, b'\x01', 'write')
    m('permit-cut', CH_IDENTIFY, b'\x01', 'write')
    # tunnel NPDU longer than the TLV
    m('tunnel-cut', CH_TUNNEL, tlv(0, bytes([0, 9, 0x08, 0x00])))
    # ZCL configuration cluster cut short
    mal.add(WP, wzcl(0x003d, bytes([0x01, 1, 0x01]) + b'\x58', seq=1))
    mal.add(WP, wzcl(0x003d, bytes([0x09, 2, 0x00, 0x00]), seq=2))
    mal.add(WP, wzcl(0x003d, bytes([0x08, 3, 0x01]) + struct.pack('<HBB', 0x0001, 0, 0x22) + b'\x01', seq=3))
    mal.write(os.path.join(OUT, 'zbee-direct-coverage-malformed.pcapng'))
    if VERBOSE:
        print('main: %d frames' % len(p))
        for k, v in marks.items():
            print('  %-16s %s' % (k, v))
        print('malformed: %d frames' % len(mal))
        for k, v in mm.items():
            print('  %-16s %s' % (k, v))


run()

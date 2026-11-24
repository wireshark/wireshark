#!/usr/bin/env python3
# Generates test/captures/zbee_tlv_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for packet-zbee-tlv.c (ZigBee TLVs).

usage: mkzbee_tlv.py <outdir> [-v]    (-v prints the frame ranges)

Writes zbee-tlv-coverage.pcapng and zbee-tlv-coverage-malformed.pcapng.
Every TLV is reached the way a capture reaches it: ZigBee Direct over
Bluetooth ATT (linktype 201), ZDP/APS/NWK commands and beacons over
IEEE 802.15.4 (linktype 230) and, for the global TLVs without a command
context, the "zbee_tlv" dissector through Exported PDU (linktype 252).
Nothing here encrypts anything: keys appear only as made-up constants.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from zbeelib import (
    aps_cmd, aps_data, att_find_info, att_indicate, att_mtu, att_notify, att_read_rsp, att_write,
    att_write_cmd, CH_FORM, CH_JOIN, CH_MANAGE, CH_SEC_AESMMO, CH_SEC_P256, CH_SEC_SHA256,
    CH_STATUS, CH_TUNNEL, EUI_A, EUI_B, EUI_C, H, HANDLES, hci_conn_complete, ieee,
    LT_BLUETOOTH_H4_PHDR, LT_EXPORTED_PDU, LT_IEEE802_15_4_NOFCS, nwk, Pcapng, tlv, transport_key,
    wpan_beacon, wpan_data, zdp,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

BT, WP, EX = LT_BLUETOOTH_H4_PHDR, LT_IEEE802_15_4_NOFCS, LT_EXPORTED_PDU
KEY = bytes(range(0x10, 0x20))          # made-up 16 byte constants
KEY2 = bytes(range(0x30, 0x40))
EUI = lambda n: ieee(n)


def chanlist(*masks):
    """Channel page list: count + one mask per page (page in bits 27-31)."""
    return bytes([len(masks)]) + b''.join(struct.pack('<I', m) for m in masks)


# channel masks: page 0 channels 11-26, an isolated channel, ranges with
# gaps, an empty mask and a high page
M_ALL = 0x07fff800
M_GAPS = (1 << 11) | (1 << 12) | (1 << 13) | (1 << 15) | (1 << 20) | (1 << 21) | (1 << 26)
M_ONE = 1 << 25
M_NONE = 0
M_PAGE5 = (5 << 27) | 0x3ff

# ---------------------------------------------------------------- ZBD TLVs
# Commissioning TLV ids (Form / Join / Status / Manage Joiners)
C_EXTPAN, C_SHORTPAN, C_CHANNEL, C_NWKKEY, C_LNKKEY, C_DEVTYPE, C_NWKADDR, C_JOINM, \
    C_IEEE, C_TC, C_STATUSMAP, C_UPDID, C_KEYSEQ, C_ADMIN, C_STATUSCODE = range(15)

form_tlvs = [
    tlv(C_ADMIN, KEY), tlv(C_TC, EUI(EUI_A)), tlv(C_EXTPAN, EUI(EUI_B)),
    tlv(C_SHORTPAN, b'\x62\x1a'), tlv(C_CHANNEL, chanlist(M_ALL)),
    tlv(C_NWKKEY, KEY), tlv(C_LNKKEY, b'\x03' + KEY2), tlv(C_LNKKEY, b'\x00' + KEY2),
    tlv(C_LNKKEY, b'\x01' + KEY2), tlv(C_LNKKEY, b'\x02' + KEY2),
    tlv(C_NWKADDR, b'\x00\x00'), tlv(C_UPDID, b'\x05'), tlv(C_KEYSEQ, b'\x01'),
    tlv(0x1f, b'\x01\x02\x03'),                      # unknown commissioning TLV
]
join_tlvs = [
    tlv(C_JOINM, b'\x00'), tlv(C_JOINM, b'\x01'), tlv(C_JOINM, b'\x02'), tlv(C_JOINM, b'\x03'),
    tlv(C_ADMIN, KEY), tlv(C_TC, EUI(EUI_A)), tlv(C_EXTPAN, EUI(EUI_B)),
    tlv(C_SHORTPAN, b'\x62\x1a'),
    tlv(C_CHANNEL, chanlist(M_GAPS, M_ONE, M_NONE, M_PAGE5)),
    tlv(C_NWKKEY, KEY), tlv(C_LNKKEY, b'\x03' + KEY2), tlv(C_NWKADDR, b'\x34\x12'),
    tlv(C_UPDID, b'\x00'), tlv(C_KEYSEQ, b'\x02'), tlv(0x2a, b'\xee'),
]
status_tlvs = [
    tlv(C_IEEE, EUI(EUI_A)), tlv(C_TC, EUI(EUI_B)), tlv(C_EXTPAN, EUI(EUI_C)),
    tlv(C_SHORTPAN, b'\x62\x1a'), tlv(C_CHANNEL, chanlist(M_ALL, M_ONE)),
    tlv(C_NWKKEY, KEY), tlv(C_NWKADDR, b'\x01\x00'), tlv(C_UPDID, b'\x07'),
    tlv(C_KEYSEQ, b'\x03'), tlv(C_DEVTYPE, b'\x00'), tlv(C_DEVTYPE, b'\x01'),
    tlv(C_DEVTYPE, b'\x02'),
    # Network Status Map: joined 0..4 and the reserved 5..7, open, centralized
    tlv(C_STATUSMAP, b'\x00'), tlv(C_STATUSMAP, b'\x01'), tlv(C_STATUSMAP, b'\x02'),
    tlv(C_STATUSMAP, b'\x0a'), tlv(C_STATUSMAP, b'\x13'), tlv(C_STATUSMAP, b'\x1b'),
    tlv(C_STATUSMAP, b'\x03'), tlv(C_STATUSMAP, b'\x04'),
    tlv(C_STATUSCODE, b'\x00\x00'), tlv(C_STATUSCODE, b'\x02\x15'),
    tlv(0x30, b'\x01'),                                # unknown
]
MJ = [tlv(2, b'\x00'), tlv(2, b'\x01'), tlv(2, b'\x02'),           # commands drop / add / remove
      tlv(1, EUI(EUI_A)), tlv(0, KEY), tlv(9, b'\x00\x01')]

# global TLVs (type >= 64) with a value that decodes completely
KNM = tlv(65, bytes([0x07, 0x1f]) + EUI(EUI_A))                 # supported key negotiation
KNM0 = tlv(65, bytes([0x00, 0x00]) + EUI(EUI_B))
G_TLVS = [
    tlv(64, b'\x34\x12' + b'manufacturer'),              # manufacturer specific
    tlv(64, b'\x34\x12\x00'),                               # ... with one value byte
    KNM, KNM0,
    tlv(66, b'\x03\x00'),                                   # PAN ID conflict report
    tlv(67, b'\x62\x1a'),                                   # next PAN ID
    tlv(68, struct.pack('<I', M_GAPS)),                     # next channel change
    tlv(69, b'passphrase-16byte'[:16]),                     # passphrase
    tlv(70, b'\xff\x00'), tlv(70, b'\x00\x00'),             # router information
    tlv(70, b'\x55\xaa'),
    tlv(71, b'\x01\x00\x01\x40\x00'),                       # fragmentation parameters
    tlv(75, b'\x07\x00'), tlv(75, b'\x00\x00'),             # configuration mode parameters
    tlv(76, b'\x01\x00'), tlv(76, b'\x00\x00'),             # device capability extension
    tlv(100, b'\x01\x02\x03\x04'),                          # unknown global TLV
    tlv(255, b'\xff'),
]

frames_bt = {}      # not used; kept simple


def zbd_frames(p):
    """Bluetooth capture: connection, handle discovery, then every ZBD
    characteristic carrying every TLV the dissector knows."""
    p.add(BT, hci_conn_complete())
    p.add(BT, att_mtu(517, 0))
    p.add(BT, att_mtu(517, 1))
    for i in range(0, len(HANDLES), 5):
        p.add(BT, att_find_info(HANDLES[i:i + 5]))
    marks = {}

    def notif(name, ch, value, op='notify'):
        marks.setdefault(name, []).append(len(p) + 1)
        if op == 'notify':
            p.add(BT, att_notify(H[ch], value))
        elif op == 'write':
            p.add(BT, att_write(H[ch], value))
        elif op == 'cmd':
            p.add(BT, att_write_cmd(H[ch], value))
        elif op == 'ind':
            p.add(BT, att_indicate(H[ch], value))
        else:
            p.add(BT, att_read_rsp(value))

    # Form Network (write), Join Network (write command)
    for i in range(0, len(form_tlvs), 5):
        notif('form', CH_FORM, b''.join(form_tlvs[i:i + 5]), 'write')
    for i in range(0, len(join_tlvs), 5):
        notif('join', CH_JOIN, b''.join(join_tlvs[i:i + 5]), 'cmd')
    # Commissioning Status: one notification per TLV group
    for i in range(0, len(status_tlvs), 4):
        notif('status', CH_STATUS, b''.join(status_tlvs[i:i + 4]))
    # the reproducer of "ZigBee TLV: Fix network status map index": joined
    # status 5, 6 and 7 are reserved values (were NULL / out of bounds)
    for joined in (5, 6, 7):
        notif('status-reserved', CH_STATUS, tlv(C_STATUSMAP, bytes([joined])))
    # Manage Joiners
    notif('manage', CH_MANAGE, b''.join(MJ[:3]), 'write')
    notif('manage', CH_MANAGE, b''.join(MJ[3:]), 'write')
    # Security service: the four messages on each of the three characteristics
    sec = {
        'se-key-method': tlv(0, b'\x01\xff'), 'se-key-method2': tlv(0, b'\x03\x02'),
        'pp-p256': tlv(1, EUI(EUI_A) + bytes(range(64))),
        'pp-c25519': tlv(2, EUI(EUI_B) + bytes(range(32))),
        'seqnum': tlv(3, b'\x04'), 'mac': tlv(4, bytes(range(16))),
    }
    for ch in (CH_SEC_AESMMO, CH_SEC_SHA256, CH_SEC_P256):
        for mt in (2, 3, 4, 1):          # ends with SE1: encryption stays off
            body = bytes([mt]) + sec['se-key-method'] + sec['pp-c25519' if ch != CH_SEC_P256 else 'pp-p256'] \
                + sec['seqnum'] + sec['mac']
            notif('secur', ch, body, 'write' if mt in (1, 3) else 'notify')
    notif('secur', CH_SEC_AESMMO, bytes([2]) + sec['se-key-method2'] + tlv(0x20, b'\x01\x02')
          + G_TLVS[2], 'write')
    notif('secur', CH_SEC_P256, bytes([9]) + sec['seqnum'], 'write')    # unrecognized SE message
    # Tunneling: an NPDU TLV carrying a NWK data frame and a NWK command
    nwk_cmd = nwk(bytes([0x08, 0x61, 0x01, 0x00, 0x00]), cmd=True, ext_src=EUI_A)
    nwk_data_f = nwk(aps_data(b'\x00\x01\x02', 0x0006), ext_src=EUI_A, seq=3)
    for flags, n in ((0, nwk_cmd), (1, nwk_data_f), (0xfe, nwk_cmd)):
        v = bytes([flags, len(n)]) + n
        notif('tunnel', CH_TUNNEL, tlv(0, v))
    notif('tunnel', CH_TUNNEL, tlv(5, b'\x01\x02\x03\x04'))            # unknown tunneling TLV
    # global TLVs inside ZBD messages
    notif('zbd-global', CH_STATUS, b''.join(G_TLVS[:5]))
    notif('zbd-global', CH_JOIN, b''.join(G_TLVS[5:12]), 'write')
    notif('zbd-global', CH_FORM, b''.join(G_TLVS[12:]), 'write')
    # a TLV longer than the decoder reads: the surplus is shown as a value
    # (ZBD TLV total length of 258 octets: the old uint8_t wrapped)
    notif('zbd-long', CH_STATUS, tlv(C_EXTPAN, EUI(EUI_A) + b'\xee' * 247))
    notif('zbd-long', CH_STATUS, tlv(C_EXTPAN, EUI(EUI_A) + b'\xee' * 2))
    notif('zbd-long', CH_JOIN, tlv(0x31, b'\x42' * 253), 'write')
    # TLV length 0xfd..0xff in a Security message
    notif('zbd-long', CH_SEC_SHA256, bytes([1]) + tlv(3, b'\x04' + b'\x77' * 254))
    return marks


# ----------------------------------------------------------- IEEE 802.15.4
def zdp_frames(p, marks):
    """ZDP commands whose TLVs the dissector decodes (R23)."""
    seq = [0]

    def z(name, cluster, body):
        seq[0] += 1
        marks.setdefault(name, []).append(len(p) + 1)
        p.add(WP, wpan_data(nwk(zdp(cluster, body, counter=seq[0], seq=seq[0]), seq=seq[0], ext_src=EUI_A),
                            seq=seq[0]))

    st = b'\x00'
    t0 = lambda v: tlv(0, v)
    eui_list = lambda *e: bytes([len(e)]) + b''.join(EUI(x) for x in e)
    # Clear All Bindings request: EUI64 list
    z('zdp-clear', 0x002b, t0(eui_list(EUI_A, EUI_B)))
    z('zdp-clear', 0x002b, t0(eui_list()) + tlv(1, b'\x01\x02'))
    z('zdp-clear', 0x002b, KNM)
    # Start Key Negotiation request / response: public point TLV
    z('zdp-keyneg', 0x0040, t0(EUI(EUI_A) + bytes(range(32))))
    z('zdp-keyneg', 0x8040, st + t0(EUI(EUI_B) + bytes(range(32))))
    z('zdp-keyneg', 0x8040, st + tlv(3, b'\x00') + KNM)
    # Get Authentication Token
    z('zdp-token', 0x0041, t0(b'\x44'))
    z('zdp-token', 0x0041, tlv(2, b'\x01\x02\x03'))
    z('zdp-token', 0x8041, st + tlv(0, b'\x01\x02\x03\x04'))
    # Get Authentication Level
    z('zdp-level', 0x0042, t0(EUI(EUI_A)))
    z('zdp-level', 0x0042, tlv(1, b'\x01\x02'))
    z('zdp-level', 0x8042, st + t0(EUI(EUI_A) + b'\x02\x03'))
    z('zdp-level', 0x8042, st + tlv(1, b'\x01\x02'))
    # Set / Get Security Configuration
    z('zdp-config', 0x0043, tlv(0, b'\x01\x02\x03'))
    z('zdp-config', 0x8043, st + t0(b'\x02\x01\x00\x02\x01'))
    z('zdp-config', 0x8043, st + tlv(1, b'\x05\x05'))
    z('zdp-config', 0x0044, b'\x02\x01\x02')
    z('zdp-config', 0x8044, st + tlv(0, b'\x09\x08'))
    # Start Key Update request / response
    z('zdp-keyupd', 0x0045, t0(b'\x01\x00' + EUI(EUI_A)))
    z('zdp-keyupd', 0x0045, t0(b'\x02\x01' + EUI(EUI_A)))
    z('zdp-keyupd', 0x8045, st + t0(b'\x00\xff' + EUI(EUI_B)))
    z('zdp-keyupd', 0x8045, st + tlv(1, b'\x00'))
    # Decommission request / response
    z('zdp-decom', 0x0046, t0(eui_list(EUI_A)))
    z('zdp-decom', 0x0046, tlv(4, b'\x00'))
    z('zdp-decom', 0x8046, st + t0(b'\x01\x02'))
    # Security Challenge request / response
    z('zdp-chal', 0x0047, t0(EUI(EUI_A) + bytes(range(8))))
    z('zdp-chal', 0x0047, tlv(6, b'\x00\x01\x02'))
    z('zdp-chal', 0x8047, st + t0(EUI(EUI_A) + bytes(range(8)) + struct.pack('<II', 7, 9) + bytes(range(8))))
    z('zdp-chal', 0x8047, st + tlv(7, b'\x00'))
    # Beacon Survey request / response
    z('zdp-survey', 0x003c, t0(b'\x02' + struct.pack('<II', M_ALL, M_GAPS) + b'\x01'))
    z('zdp-survey', 0x003c, t0(b'\x00\x01') + tlv(5, b'\x00'))
    z('zdp-survey', 0x803c, st + t0(b'\x01\x02' + struct.pack('<II', M_ALL, M_ONE)))
    z('zdp-survey', 0x803c, st + tlv(1, b'\x04\x02\x01\x03'))
    z('zdp-survey', 0x803c, st + tlv(2, struct.pack('<HB', 0x1234, 90) + b'\x02'
                                     + struct.pack('<HB', 0x1111, 80) + struct.pack('<HB', 0x2222, 70)))
    z('zdp-survey', 0x803c, st + tlv(9, b'\xaa'))
    # Node Descriptor response with the selected key negotiation method TLV
    nd = bytes([0x00, 0x34, 0x12]) + bytes([0x01, 0x40, 0x8e, 0x34, 0x12, 0x52, 0x52, 0x00, 0x00, 0x2e, 0x52, 0x00, 0x00])
    z('zdp-nodedesc', 0x8002, nd + t0(b'\x01\x00' + EUI(EUI_A)))
    z('zdp-nodedesc', 0x0002, b'\x34\x12' + tlv(0, b'\x01\x02'))
    # Permit Joining request with a TLV (unknown local TLV, then global)
    z('zdp-permit', 0x0036, b'\x3c\x01' + tlv(2, b'\x01'))
    z('zdp-permit', 0x0036, b'\x3c\x01' + G_TLVS[3] + G_TLVS[5])
    z('zdp-permit', 0x0036, b'\x3c\x01')
    # global TLVs in ZDP messages
    z('zdp-global', 0x0042, KNM + G_TLVS[2])
    z('zdp-global', 0x0045, b''.join(G_TLVS[:8]))
    # long ZDP TLVs: surplus bytes after the decoded value
    z('zdp-long', 0x0042, t0(EUI(EUI_A) + b'\x11' * 247))
    z('zdp-long', 0x0042, t0(EUI(EUI_A) + b'\x11' * 20))
    z('zdp-long', 0x002b, tlv(9, b'\x22' * 256))


def nwk_aps_frames(p, marks):
    seq = [100]

    def w(name, payload, **kw):
        seq[0] += 1
        marks.setdefault(name, []).append(len(p) + 1)
        p.add(WP, wpan_data(payload, seq=seq[0]))

    # NWK commands with TLVs: Route Request, Route Reply, Network Status
    rr = bytes([0x01, 0x00, 0x07, 0x34, 0x12, 0x05])
    w('nwk-route-req', nwk(rr + tlv(0, b'\x10\x00\x05') + tlv(1, b'\x0a\x08') +
                           tlv(2, struct.pack('<HHH', 0x1111, 0x2222, 0x3333)) + tlv(9, b'\x01'),
                           cmd=True, seq=1))
    w('nwk-route-req', nwk(rr + tlv(2, b'\x01\x02') + G_TLVS[3], cmd=True, seq=2))
    rp = bytes([0x02, 0x00, 0x07, 0x34, 0x12, 0x01, 0x00, 0x03])
    w('nwk-route-reply', nwk(rp + tlv(0, b'\x20\x00') + tlv(4, b'\x01\x02'), cmd=True, seq=3))
    rs = bytes([0x03, 0x01, 0x34, 0x12])
    w('nwk-status', nwk(rs + tlv(0, b'\x30\x00') + tlv(3, b'\x00'), cmd=True, seq=4))
    w('nwk-status', nwk(bytes([0x03, 0x13, 0x34, 0x12, 0x04]) + tlv(8, b'\x01'), cmd=True, seq=5))
    w('nwk-status', nwk(bytes([0x03, 0x0b, 0x34, 0x12]) + tlv(8, b'\x01'), cmd=True, seq=5))
    # any other NWK command: unknown TLV, global TLV
    w('nwk-other', nwk(bytes([0x08, 0x61]) + b'\x01\x00\x33' + tlv(5, b'\xaa\xbb'), cmd=True, seq=6))
    w('nwk-other', nwk(bytes([0x04, 0x40]) + G_TLVS[0], cmd=True, seq=7))
    # APS commands: Transport Key with the link-key features TLV, others
    tk = transport_key(KEY)
    w('aps-transport', nwk(tk + tlv(0, b'\x01'), seq=8, ext_src=EUI_B))
    w('aps-transport', nwk(transport_key(KEY2, counter=2) + tlv(0, b'\x00') + G_TLVS[3], seq=9))
    # Relay Message upstream / downstream with a relayed APS command
    inner = aps_cmd(0x09, bytes([0x00]), counter=9)
    w('aps-relay', nwk(aps_cmd(0x12, tlv(0, EUI(EUI_C) + inner), counter=3), seq=10, ext_src=EUI_A))
    w('aps-relay', nwk(aps_cmd(0x11, tlv(0, EUI(EUI_C) + inner), counter=4), seq=11, src=0x0000, dst=0x0001))
    # other APS commands: unknown local TLV, global TLV
    w('aps-other', nwk(aps_cmd(0x09, b'\x00' + tlv(3, b'\x01\x02')), seq=12))
    w('aps-other', nwk(aps_cmd(0x09, b'\x01') + KNM, seq=13))


def beacon_frames(p, marks):
    def b(name, payload, seq=1):
        marks.setdefault(name, []).append(len(p) + 1)
        p.add(WP, wpan_beacon(payload, seq=seq))

    # ZigBee beacons (protocol ID 0), R22+ with TX offset and update ID
    def zb(tlvs, ver=2):
        return bytes([0x00]) + struct.pack('<H', 0x0002 | (ver << 4) | 0x0c00 | 0x8000) \
            + EUI(EUI_A) + b'\xff\xff\xff' + b'\x01' + tlvs
    b('beacon', zb(b''.join(G_TLVS[3:8])), 1)
    b('beacon', zb(KNM + tlv(70, b'\xff\x00'), 3), 2)
    # nested encapsulation: joiner encapsulation (72) and beacon appendix
    # encapsulation (73) holding other TLVs: two and three levels, and one
    # that is past the recursion limit (expert info, no more decoding)
    lvl1 = tlv(72, KNM + tlv(67, b'\x62\x1a'))
    lvl2 = tlv(73, tlv(72, tlv(66, b'\x01\x00')))
    b('beacon-nested', zb(lvl1 + lvl2), 3)
    deep = tlv(66, b'\x09\x00')
    for t in (72, 73, 72, 73):
        deep = tlv(t, deep)
    b('beacon-recursion', zb(deep), 4)
    # ZigBee IP beacon (protocol ID 2): network id, then TLVs
    b('beacon-zbip', bytes([0x02, 0xc0]) + b'zbip-net-id-0001' + G_TLVS[3] + tlv(33, b'\x01\x02'), 5)
    # a beacon whose payload is not ZigBee at all starts with TLVs
    b('beacon-plain', b''.join(G_TLVS[:3]) + tlv(0x33, b'\x01'), 6)
    b('beacon-plain', tlv(72, tlv(65, bytes([0x07, 0x1f]) + EUI(EUI_C))) + b'\xaa', 7)


def exported_frames(p, marks):
    """The zbee_tlv dissector through Exported PDU (no command context)."""
    name = b'zbee_tlv'
    hdr = struct.pack('>HH', 12, len(name)) + name + b'\x00' * (-len(name) % 4) + struct.pack('>HH', 0, 0)

    def e(label, payload):
        marks.setdefault(label, []).append(len(p) + 1)
        p.add(EX, hdr + payload)

    e('exp', b''.join(G_TLVS[:6]))
    e('exp', tlv(0, b'\x01\x02\x03') + tlv(10, b'\x04') + G_TLVS[3])      # local ids: unknown TLV
    e('exp', tlv(72, KNM + tlv(72, tlv(67, b'\x62\x1a'))) + b'\xcc')      # leftover octet after TLVs
    e('exp', b''.join(G_TLVS[6:]))


def main():
    main_cap = Pcapng()
    marks = {}
    marks.update(zbd_frames(main_cap))
    zdp_frames(main_cap, marks)
    nwk_aps_frames(main_cap, marks)
    beacon_frames(main_cap, marks)
    exported_frames(main_cap, marks)
    main_cap.write(os.path.join(OUT, 'zbee-tlv-coverage.pcapng'))

    # malformed
    mal = Pcapng()
    mm = {}
    mal.add(BT, hci_conn_complete())
    mal.add(BT, att_mtu(517, 0))
    mal.add(BT, att_mtu(517, 1))
    mal.add(BT, att_find_info(HANDLES[:5]))
    mal.add(BT, att_find_info(HANDLES[5:10]))
    mal.add(BT, att_find_info(HANDLES[10:]))

    def m(name, linktype, data, olen=None):
        mm.setdefault(name, []).append(len(mal) + 1)
        mal.add(linktype, data, olen)
    # manufacturer specific TLV with a one byte value (length - 2 wraps)
    m('mfr1', WP, wpan_beacon(bytes([0x00, 0x22, 0x84]) + EUI(EUI_A) + b'\xff\xff\xff\x01' + tlv(64, b'\x34'), seq=1))
    # public point TLVs shorter than the EUI64 (length - 8 wraps)
    m('pp-short', BT, att_write(H[CH_SEC_AESMMO], bytes([1]) + tlv(2, b'\x01\x02\x03')))
    m('pp-short', BT, att_write(H[CH_SEC_P256], bytes([1]) + tlv(1, b'\x01')))
    # a TLV whose value is cut off by the end of the frame
    m('cut', BT, att_notify(H[CH_STATUS], bytes([C_EXTPAN, 7]) + b'\x01\x02\x03'))
    m('cut', BT, att_notify(H[CH_JOIN], bytes([C_CHANNEL, 8, 3]) + struct.pack('<I', M_ALL)))
    m('cut', BT, att_write(H[CH_FORM], bytes([C_LNKKEY, 16, 0]) + KEY[:10]))
    # status code and map TLV length 0 in the wrong place; relay TLV lengths
    m('relay', WP, wpan_data(nwk(aps_cmd(0x12, bytes([0, 0]) + EUI(EUI_C)), seq=1, ext_src=EUI_A)))
    m('relay', WP, wpan_data(nwk(aps_cmd(0x12, bytes([0, 5]) + EUI(EUI_C)), seq=2, ext_src=EUI_A), seq=2))
    m('relay', WP, wpan_data(nwk(aps_cmd(0x11, bytes([0, 0xff]) + EUI(EUI_C) + b'\x01'), seq=3), seq=3))
    # ZDP TLVs that run off the end
    m('zdp-cut', WP, wpan_data(nwk(zdp(0x0040, tlv(0, EUI(EUI_A))[:6]), ext_src=EUI_A, seq=4), seq=4))
    m('zdp-cut', WP, wpan_data(nwk(zdp(0x803c, b'\x00' + tlv(2, b'\x34\x12\x50\x05\x01\x02')), ext_src=EUI_A, seq=5), seq=5))
    m('zdp-cut', WP, wpan_data(nwk(zdp(0x0047, tlv(0, EUI(EUI_A) + b'\x01\x02')), ext_src=EUI_A, seq=6), seq=6))
    # NWK route request TLVs that run off the end
    m('nwk-cut', WP, wpan_data(nwk(bytes([0x01, 0, 7, 0x34, 0x12, 5]) + bytes([2, 9, 1, 2]), cmd=True, seq=7), seq=7))
    # tunnel NPDU longer than the TLV
    m('tunnel', BT, att_notify(H[CH_TUNNEL], bytes([0, 5, 0, 200]) + b'\x08\x00\x00\x01\x00'))
    # a lone type octet at the end of a message is ignored, a type and
    # length without value is cut
    m('tail', BT, att_notify(H[CH_STATUS], tlv(C_DEVTYPE, b'\x01') + bytes([C_NWKADDR])))
    m('tail', BT, att_notify(H[CH_STATUS], tlv(C_DEVTYPE, b'\x01') + bytes([C_NWKADDR, 1])))
    mal.write(os.path.join(OUT, 'zbee-tlv-coverage-malformed.pcapng'))
    if VERBOSE:
        print('main: %d frames' % len(main_cap))
        for k, v in marks.items():
            print('  %-16s %s' % (k, v))
        print('malformed: %d frames' % len(mal))
        for k, v in mm.items():
            print('  %-16s %s' % (k, v))


main()

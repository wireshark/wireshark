#!/usr/bin/env python3
# Generates test/captures/netlink-nl80211_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic nl80211 (Generic Netlink) captures for packet-netlink-nl80211.c.

Usage: mknl80211.py <outdir>
Writes nl80211-coverage.pcap (clean) and nl80211-coverage-malformed.pcap.
LINKTYPE_NETLINK (253): 4 byte "cooked" header (here the 16 byte netlink
sockaddr header used by nlmon), then netlink messages.  The generic
netlink family id is mapped to "nl80211" by a CTRL_CMD_NEWFAMILY frame.
"""
import struct
import sys
import os

LE = '<'
FID = 0x21
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000

def sll(proto=16):
    return struct.pack('>HHH8sH', 4, 824, 0, b'\0' * 8, proto)

def nla(t, payload=b''):
    l = 4 + len(payload)
    return struct.pack(LE + 'HH', l, t) + payload + b'\0' * ((4 - l % 4) % 4)

def nlmsg(t, payload, seq=1, flags=0, pid=0):
    return struct.pack(LE + 'IHHII', 16 + len(payload), t, flags, seq, pid) + payload

def genl(cmd, payload=b'', ver=1):
    return struct.pack(LE + 'BBH', cmd, ver, 0) + payload

def u32(v): return struct.pack(LE + 'I', v)
def u16(v): return struct.pack(LE + 'H', v)
def s32(v): return struct.pack(LE + 'i', v)

def family():
    attrs = nla(1, u16(FID)) + nla(2, b'nl80211\0')
    return sll() + nlmsg(0x10, genl(1, attrs))

def msg(cmd, attrs=b'', seq=1, flags=0):
    return sll() + nlmsg(FID, genl(cmd, attrs), seq, flags)

def pcap(frames, fn):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 253))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def arr(t, items):
    """Nested array: attribute t holding (index, payload) elements."""
    return nla(t, b''.join(nla(i, p) for i, p in items))

def sub(*pairs):
    return b''.join(nla(t, p) for t, p in pairs)

# Payload lengths used for attributes that only reach the generic decoder.
GEN = [u32(0x11223344), u16(0x5566), struct.pack(LE + 'Q', 0x1122334455667788),
       b'\x01\x02\x03', b'\x07', b'abcdefghijkl', b'']

def generic_sub(n=8):
    return b''.join(nla(i + 1, GEN[i % len(GEN)]) for i in range(n))

# IEEE 802.11 tagged parameters: SSID, rates, DS parameter set
IES = (b'\x00\x04test' + b'\x01\x04\x82\x84\x8b\x96' + b'\x03\x01\x06')
HTCAP = (struct.pack('<H', 0x01ef) + b'\x17' + bytes(16) + struct.pack('<HIB', 0, 0, 0))
HTMCS = bytes([0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0])
VHTCAP = struct.pack('<I', 0x0f8259b2) + struct.pack('<HHHH', 0xfffa, 0x01fe, 0xfffa, 0x01fe)
VHTMCS = struct.pack('<HHHH', 0xfffa, 0x01fe, 0xfffa, 0x01fe)
# Probe request: fc, dur, da, sa, bssid, seq, SSID
FRAME80211 = (b'\x40\x00\x00\x00' + b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x01' + b'\xff' * 6 +
              b'\x10\x00' + b'\x00\x04test')
EAPOL_START = b'\x02\x01\x00\x00'
MAC = b'\x02\x00\x00\x00\x00\x01'

# Attribute numbers (ws_nl80211_attrs) handled specially by dissect_nl80211_attrs.
NESTED = [32, 17, 21, 27, 23, 47, 80, 84, 58, 59, 90, 94, 110, 112, 35, 132, 120, 122,
          129, 134, 225, 227, 230, 240, 241, 265, 121, 341, 344, 50]
NESTED_ARR = [37, 22, 34, 331, 312]
# value attribute -> payload (by the hf type)
VALUES = {159: u32(2), 2: b'phy0\0', 39: u32(1), 4: b'wlan0\0', 5: u16(2), 6: MAC,
          25: b'\x01', 33: b'AU\0', 48: b'\x01', 49: b'\x01', 53: u32(0), 55: u32(1),
          66: u32(1), 93: u32(1), 97: u32(1), 116: b'\x03', 138: b'\x01', 146: b'\x01',
          151: s32(-60), 154: u32(1), 155: u32(1), 164: u32(1), 165: u32(1), 168: u32(1),
          179: u16(1), 213: b'\x01', 228: b'\x01', 248: u32(1), 260: u32(1), 173: u32(1)}
SPECIAL = {42: IES, 77: IES, 78: IES, 127: IES, 128: IES, 185: IES, 31: HTCAP,
           157: struct.pack('<I', 0x0f8259b2) + VHTMCS, 51: FRAME80211,
           57: u32(0x000fac04) + u32(0x000fac02) + u32(0x00123401)}

def sta_info():
    return sub((7, b'\xc4'), (13, b'\xc0'), (30, b'\xbf'), (34, b'\xc5'), (35, b'\xc6'),
               (8, generic_sub(6)), (14, generic_sub(4)), (15, generic_sub(5)),
               (1, u32(1000)), (2, u32(2)), (16, struct.pack(LE + 'Q', 99))) + \
        arr(31, [(0, nla(1, struct.pack(LE + 'Q', 5)) + nla(6, generic_sub(5)) + nla(2, u32(3))),
                 (1, nla(6, generic_sub(9)))])

def band(idx_extra=False):
    freqs = arr(1, [(0, sub((1, u32(2412)), (2, b''), (3, b''), (6, u32(0)), (8, u32(2000)),
                            (7, generic_sub(3)), (18, generic_sub(4)), (9, u32(1)))),
                    (1, sub((1, u32(2417)), (7, generic_sub(2))))])
    rates = arr(2, [(0, nla(1, u32(10)) + nla(2, b'')), (1, nla(1, u32(20)))])
    iftype = arr(9, [(0, nla(1, sub((1, b''), (2, b''))) + nla(2, b'\x01\x02\x03\x04') +
                      nla(3, b'\x01\x02')),
                     (1, nla(1, sub((4, b''))) + nla(5, bytes(8)))])
    return (freqs + rates + iftype + nla(3, HTMCS) + nla(4, HTCAP[:2]) + nla(7, VHTMCS) +
            nla(8, struct.pack('<I', 0x0f8259b2)) + nla(5, b'\x01') + nla(6, b'\x02') + nla(10, u32(5)))

def top_attr(n):
    if n in SPECIAL: return SPECIAL[n]
    if n in VALUES: return VALUES[n]
    return GEN[n % 4]

def main(out):
    os.makedirs(out, exist_ok=True)
    fr = [family()]
    # --- every command carries a few common attributes
    for cmd in range(1, 170):
        fr.append(msg(cmd, nla(3, u32(2 + cmd % 3)) + nla(6, MAC) + nla(4, b'wlan0\0'), seq=cmd))
    # commands without a payload and with a bare header
    fr.append(msg(0))
    fr.append(msg(1))
    # --- every top-level attribute number, one frame per attribute so that
    # the attribute-name table is exercised
    for n in range(1, 376):
        if n in NESTED:
            continue
        if n in NESTED_ARR:
            continue
        if n == 51:
            continue
        fr.append(msg(1, nla(n, top_attr(n))))
    # attributes whose value sets use the padding path (odd lengths)
    fr.append(msg(1, nla(2, b'wl\0') + nla(4, b'x\0') + nla(1, b'\x01\x02\x03')))
    # --- nested attributes with generic children of every width
    for n in NESTED:
        if n in (21, 47, 230):
            continue
        fr.append(msg(1, nla(n | NLA_F_NESTED, generic_sub(8))))
    fr.append(msg(1, nla(21 | NLA_F_NESTED, sta_info())))
    fr.append(msg(1, nla(47 | NLA_F_NESTED, sub((1, MAC), (9, u32(1)), (12, u32(1)), (6, IES), (11, IES),
                                                (3, u16(100)), (4, u16(0x431)), (7, u32(1)), (14, b'\x01\x02\x03')))))
    # IFTYPE_EXT_CAPA is itself an nl80211 attribute list (nests into dissect_nl80211_attrs)
    fr.append(msg(1, nla(230 | NLA_F_NESTED, sub((5, u16(2)), (31, HTCAP), (2, b'phy0\0'),
                                                 (230, sub((5, u16(3)), (42, IES)))))))
    # --- nested arrays
    fr.append(msg(1, arr(22 | NLA_F_NESTED, [(0, band()), (1, band())])))
    for n in NESTED_ARR:
        if n != 22:
            fr.append(msg(1, arr(n | NLA_F_NESTED, [(0, generic_sub(4)), (1, generic_sub(6))])))
    # FRAME decoded as IEEE 802.11 and as EAPOL (CONTROL_PORT_FRAME)
    fr.append(msg(59, nla(3, u32(2)) + nla(51, FRAME80211)))
    fr.append(msg(129, nla(3, u32(2)) + nla(6, MAC) + nla(51, EAPOL_START)))
    # NLA_F_NET_BYTEORDER on a u32 and on a u16 value
    fr.append(msg(1, nla(159 | NLA_F_NET_BYTEORDER, struct.pack('>I', 3)) +
                  nla(5 | NLA_F_NET_BYTEORDER, struct.pack('>H', 2))))
    # A GET_WIPHY style request and a multi attribute NEW_STATION
    fr.append(msg(1, nla(3, u32(2)) + nla(1, u32(0)), flags=0x301))
    fr.append(msg(19, nla(3, u32(2)) + nla(6, MAC) + nla(21 | NLA_F_NESTED, sta_info()), flags=0x501))
    # --- the reproducers of the nl80211 / Netlink fixes
    # Bounded recursion: IFTYPE_EXT_CAPA nested 16 deep (the limit is 32)
    inner = b''
    for _ in range(16):
        inner = nla(230 | NLA_F_NESTED, inner)
    fr.append(msg(1, inner))
    # 40 levels: "Netlink: Bound message length and attribute nesting" stops at
    # 32 levels with the netlink.nesting_too_deep expert info (a warning)
    inner = b''
    for _ in range(40):
        inner = nla(230 | NLA_F_NESTED, inner)
    fr.append(msg(1, inner))
    pcap(fr, os.path.join(out, 'nl80211-coverage.pcap'))
    nclean = len(fr)

    # ------------------------------------------------------------------
    mal = [family()]
    # 40 levels: Netlink stops at 32 with an expert info
    inner = b''
    for _ in range(40):
        inner = nla(230 | NLA_F_NESTED, inner)
    mal.append(msg(1, inner))
    # the original 16000-deep reproducer
    inner = b''
    for _ in range(16000):
        inner = struct.pack(LE + 'HH', 4 + len(inner), 230) + inner
    mal.append(msg(1, inner))
    # band HT/VHT attributes shorter than the structures (fixed by e9a53c9cbf)
    mal.append(msg(1, arr(22, [(0, nla(3, b'\x01') + nla(4, b'') + nla(7, b'\x01\x02') + nla(8, b'\x01'))])))
    mal.append(msg(1, arr(22, [(0, nla(3, b'\x01'))])))
    mal.append(msg(1, arr(22, [(0, nla(4, HTCAP) + nla(3, HTMCS + b'\x00'*4) + nla(7, VHTMCS + b'\0'*4) +
                                  nla(8, VHTCAP[:4] + b'\0'*8))])))
    mal.append(msg(1, nla(6, b'\x02\0\0\0\0\x01') + nla(6, b'\x02\0\0')))
    mal.append(msg(1, nla(31, b'\x01') + nla(157, b'\x01\x02')))
    mal.append(msg(1, nla(42, b'\x00\x20ab') + nla(42, b'\xdd\x05\x00\x50\xf2\x04')))
    mal.append(msg(59, nla(51, b'\x80\x00\x00')))
    mal.append(msg(129, nla(51, b'\x01\x03\x00\x05\x02')))
    mal.append(msg(1, nla(57, b'\x01\xac\x0f\x00\x02')))
    mal.append(msg(1, nla(47, nla(6, b'\x00\x01a') + nla(11, b'\x30\x02\x01\x00') + nla(9, b'\x01\x02'))))
    mal.append(msg(1, nla(2, b'') + nla(2, b'phy0') + nla(3, b'\x01\x02\x03\x04\x05')))
    mal.append(msg(1, nla(21, nla(7, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09') + nla(8, b'\x01'))))
    mal.append(msg(1, nla(21, nla(31, nla(1, nla(1, b'\x01'))))))
    # attribute length larger than the message, and shorter than its header
    mal.append(sll() + nlmsg(FID, genl(1, struct.pack(LE + 'HH', 200, 3) + b'\0\0\0\0')))
    mal.append(sll() + nlmsg(FID, genl(1, struct.pack(LE + 'HH', 2, 3) + b'\0\0\0\0')))
    # truncated generic netlink header
    mal.append(sll() + nlmsg(FID, b'\x01\x01'))
    pcap(mal, os.path.join(out, 'nl80211-coverage-malformed.pcap'))
    print('clean frames', nclean, 'malformed frames', len(mal))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

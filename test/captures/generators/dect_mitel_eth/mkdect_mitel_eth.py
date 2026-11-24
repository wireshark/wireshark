#!/usr/bin/env python3
# Generates test/captures/dect_mitel_eth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DECT-MITEL-ETH dissector
(packet-dect-mitel-eth.c).

DECT-MITEL-ETH is the internal link between the DECT burst processor and
the ARM processor of Aastra/Mitel DECT base stations (RFPs). On Ethernet
it uses ethertype 0xA000 with a 2 octet length and 2 unknown octets in
front of the layer octet (RFPc 0x78, Lc 0x79, MAC 0x7A, Mt 0x7C,
Sync 0x7D). Between an OMM and an RFP the same messages are carried in
DECT-MITEL-RFP "ETH" messages (type 0x0301) over TCP port 16321, without
the length field. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkdect_mitel_eth.py <output directory>

Writes:
  dect-mitel-eth-coverage.pcap            every RFPc message type and
                                          item type, every Lc/MAC
                                          primitive, Mt items, Sync, an
                                          unknown layer, LC_DATA with a
                                          DLC/NWK payload, the reproducer
                                          frames, messages over TCP
  dect-mitel-eth-coverage-malformed.pcap  items and fields cut short
"""

import os
import struct
import sys

MAC_RFP = bytes.fromhex('020000000002')
MAC_ARM = bytes.fromhex('020000000001')
IP_OMM = bytes([192, 0, 2, 1])
IP_RFP = bytes([192, 0, 2, 2])
RFP_PORT = 16321

# Layers
RFPC, LC, MAC, MT, SYNC = 0x78, 0x79, 0x7A, 0x7C, 0x7D


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def eth(payload, up=True):
    """Ethertype 0xA000 frame; up = from the burst processor."""
    src, dst = (MAC_RFP, MAC_ARM) if up else (MAC_ARM, MAC_RFP)
    return dst + src + struct.pack('>H', 0xA000) + payload


def mitel(body, length=None, up=True):
    """Length field, 2 unknown octets, then the layer octet and the rest."""
    if length is None:
        length = len(body)
    return eth(struct.pack('>HH', length, 0) + body, up)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Tcp:
    """One TCP connection OMM (client) <-> RFP port 16321, with sequence
    numbers kept per direction so TCP analysis stays quiet."""

    def __init__(self, sport=40000):
        self.sport = sport
        self.seq = {True: 1000, False: 5000}   # key: from the OMM

    def frame(self, payload, from_omm=True, flags=0x18):
        src, dst = (IP_OMM, IP_RFP) if from_omm else (IP_RFP, IP_OMM)
        sp, dp = (self.sport, RFP_PORT) if from_omm else (RFP_PORT, self.sport)
        seq = self.seq[from_omm]
        ack = self.seq[not from_omm]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.seq[from_omm] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        smac, dmac = (MAC_ARM, MAC_RFP) if from_omm else (MAC_RFP, MAC_ARM)
        return dmac + smac + b'\x08\x00' + ip + tcp + payload

    def handshake(self):
        f = []
        f.append(self.frame(b'', True, 0x02))
        f.append(self.frame(b'', False, 0x12))
        f.append(self.frame(b'', True, 0x10))
        return f

    def rfp_eth(self, body, from_omm=True):
        """DECT-MITEL-RFP ETH message (0x0301) around a MITEL-ETH body
        without its length field."""
        return self.frame(struct.pack('>HH', 0x0301, len(body)) + body, from_omm)


def item(t, value):
    return bytes([t, len(value)]) + value


def rfpc(msg_type, *items):
    return bytes([RFPC, msg_type]) + b''.join(items)


# RFPc items with their decoded contents
REVISION = item(0x02, bytes([0x05]) + struct.pack('>HHH', 0x0102, 0x0304, 0x0506))
RFPI = item(0x04, bytes([0x80 | (0x1 << 4) | 0x2, 0x34, 0x56, 0x78, 0x9a]))   # SARIs, class B
RFPI_A = item(0x04, bytes([0x00, 0x01, 0x02, 0x03, 0x04]))                     # class A, no SARIs
HLC = item(0x06, struct.pack('>H', 0xfffe))
HLC0 = item(0x06, struct.pack('>H', 0x0000))
EXTCAP = item(0x07, bytes([0x0f]) + struct.pack('>I', 0x1f0fffff))          # relay stations, all flags
EXTCAP0 = item(0x07, bytes([0x00]) + struct.pack('>I', 0))
MACCAP = item(0x0d, bytes([0x0d, 0xff, 0xff]))
MACCAP0 = item(0x0d, bytes([0x00, 0x00, 0x00]))
STATS = item(0x10, b''.join(struct.pack('>H', 0x0100 + k) for k in range(8))
             + struct.pack('>H', 7) + bytes(16)          # lost connections, 16 unknown
             + struct.pack('>H', 3) + bytes(4)           # MAC reset, 4 unknown
             + struct.pack('>H', 2)                       # reject dummy
             + struct.pack('>II', 12, 123456)             # bad, good frames
             + struct.pack('>H', 90))                     # handoff timer
PLI = item(0x27, bytes([31]))
EXTCAP2 = item(0x29, struct.pack('>H', 0x0fe1) + bytes([0xff, 0xf8, 0x3c]))  # all MAC bits, all flags
EXTCAP2_CAT = [item(0x29, struct.pack('>H', 0) + struct.pack('>I', (c << 19))[1:]) for c in range(6)]
NUMBER_OF_UPN = item(0x01, struct.pack('>H', 16))


def other_items():
    """Items without a decoder: shown as a value."""
    out = []
    for t in (0x01, 0x03, 0x05, 0x08, 0x0f, 0x11, 0x12, 0x14, 0x15, 0x20, 0x21,
              0x22, 0x23, 0x24, 0x25, 0x26, 0x28, 0x2a, 0x2b, 0x7f):
        out.append(item(t, bytes([t, 0xaa, 0x55])[:1 + (t % 3)]))
    return out


def nwk_dlc(nwk):
    """DECT DLC frame (address, control, length indicator) around an NWK
    message, as LC_DATA carries it."""
    return bytes([0x01, 0x03, (len(nwk) << 2) | 1]) + nwk


# A DECT NWK MM LOCATE-REQUEST (protocol discriminator 5, type 0x54) with a
# PORTABLE-IDENTITY IE (IPUI type N, an IPEI).
NWK_LOCATE_REQ = bytes([0x05, 0x54, 0x05, 0x07, 0x80, 0x80 | 40,
                        0x01, 0x23, 0x45, 0x67, 0x89])
NWK_CC_RELEASE_COM = bytes([0x03, 0x5a])


def lc_data(prim, mcei, subfield, payload, up):
    return mitel(bytes([LC, prim, mcei, subfield, len(payload)]) + payload, up=up)


def main_frames():
    F = []
    # --- RFPc: every message type ---
    # 1-26: every message type with items spread over them.
    rfpc_types = [0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0f, 0x10,
                  0x11, 0x12, 0x13, 0x16, 0x17, 0x18, 0x20, 0x21, 0x22, 0x23,
                  0x24, 0x25, 0x26, 0x30, 0x31, 0x32]
    others = other_items()
    payloads = {
        0x01: [REVISION, RFPI, HLC, EXTCAP, MACCAP, PLI, EXTCAP2, NUMBER_OF_UPN],
        0x02: [RFPI_A, HLC0, EXTCAP0, MACCAP0],
        0x17: [STATS],
        0x06: [HLC],
        0x08: [item(0x08, bytes([0x01, 0x02]))],
    }
    for k, t in enumerate(rfpc_types):
        items = payloads.get(t, [])
        if not items:
            items = [others[k % len(others)]]
        F.append(mitel(rfpc(t, *items), up=(k % 2 == 0)))
    # 27: unknown message type, every undecoded item type and an unknown one
    F.append(mitel(rfpc(0x7e, *others)))
    # 28-33: every DPRS data category value
    for it in EXTCAP2_CAT:
        F.append(mitel(rfpc(0x01, it)))
    # 34: RFPc message whose item is longer than the 3 octets of its type
    F.append(mitel(rfpc(0x13, item(0x27, bytes([20, 0xee, 0xee])))))
    # 35: zero length item
    F.append(mitel(rfpc(0x20, item(0x14, b''), item(0x21, b'\x01'))))

    # --- Lc / MAC primitives ---
    mcei = 0x21
    # 36: MAC_CON_IND with handover flag; 37: without
    F.append(mitel(bytes([MAC, 0x01, mcei, 0x00, 0x01, 0x23, 0x02])))
    F.append(mitel(bytes([MAC, 0x01, mcei + 1, 0x00, 0x04, 0x56, 0x00])))
    # 38: LC_DATA_REQ (to the PP) with an NWK message, 39: LC_DATA_IND
    F.append(lc_data(0x05, mcei, 0x01, nwk_dlc(NWK_CC_RELEASE_COM), up=False))
    F.append(lc_data(0x06, mcei, 0x00, nwk_dlc(NWK_LOCATE_REQ), up=True))
    # 40: LC_DTR_IND
    F.append(mitel(bytes([LC, 0x07, mcei, 0x01])))
    # 41: MAC_PAGE_REQ
    F.append(mitel(bytes([MAC, 0x08, 0x00, 0x42, 0x00, 0x00]), up=False))
    # 42: MAC_ENC_KEY_REQ
    F.append(mitel(bytes([MAC, 0x09, mcei]) + bytes.fromhex('0011223344556677') + b'\x05', up=False))
    # 43: MAC_ENC_EKS_IND encrypted; 44: with ID and PPN; 45: unknown type
    F.append(mitel(bytes([MAC, 0x0a, mcei, 0x01])))
    F.append(mitel(bytes([MAC, 0x0a, mcei, 0x02, 0x07, 0x12, 0x34])))
    F.append(mitel(bytes([MAC, 0x0a, mcei, 0x09])))
    # 46: MAC_HO_IN_PROGRESS_IND
    F.append(mitel(bytes([MAC, 0x0b, mcei, 0x00, 0x01, 0x23])))
    # 47: MAC_HO_IN_PROGRESS_RES
    F.append(mitel(bytes([MAC, 0x0c, mcei, 0x00]) + bytes.fromhex('8899aabbccddeeff') + b'\x00\x03',
                   up=False))
    # 48: MAC_HO_FAILED_IND
    F.append(mitel(bytes([MAC, 0x0d, mcei, 0x01])))
    # 49: MAC_INFO_IND (the info string loses its last 9 octets, see README)
    F.append(mitel(bytes([MAC, 0x1c, mcei, 0x00, 0x01, 0x23, 0x00]) + b'Mitel-Handset-600d-SW-1.2.3'))
    # 50: MAC_CLEAR_DEF_CKEY_REQ
    F.append(mitel(bytes([MAC, 0x1f, 0x00, 0x01, 0x23]), up=False))
    # 51: MAC_DIS_REQ
    F.append(mitel(bytes([MAC, 0x02, mcei]), up=False))
    # 52-54: MAC_DIS_IND with every reason
    for r in (1, 2, 3):
        F.append(mitel(bytes([MAC, 0x03, mcei, r])))
    # 55-67: primitives without a decoder
    for p in (0x0e, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1d, 0x1e, 0x20, 0x21):
        F.append(mitel(bytes([MAC, p, mcei, 0x00])))
    # 68: unknown primitive
    F.append(mitel(bytes([MAC, 0x7f, 0x00])))
    # --- other layers ---
    # 69: Mt with items
    F.append(mitel(bytes([MT, 0x01]) + item(0x10, b'\x01\x02\x03') + item(0x11, b'') + item(0x12, b'\xff')))
    # 70: Sync
    F.append(mitel(bytes([SYNC, 0x01, 0x00, 0x00])))
    # 71: unknown layer
    F.append(mitel(bytes([0x7b, 0x02, 0x00])))
    # 72: length below 3: only the length is shown
    F.append(mitel(bytes([RFPC, 0x01]), length=2))

    # --- reproducers (dect_mitel_eth_small.py) ---
    # 73: MAC_INFO_IND "HELLO-WORLD-1234567" (shown as "HELLO-WORLD")
    F.append(mitel(bytes([MAC, 0x1c]) + bytes([0x05]) + bytes([0x00, 0x12, 0x34]) + b'\x00'
                   + b'HELLO-WORLD-1234567'))
    # 74: RFPI item of length 2, then NUMBER_OF_UPN and RFP_SITE_LOCATION
    items = bytes([0x04, 0x02, 0x80, 0x01])
    items += bytes([0x01, 0x02, 0x00, 0x10])
    items += bytes([0x26, 0x01, 0x00])
    F.append(mitel(bytes([RFPC, 0x01]) + items))

    # --- over TCP in DECT-MITEL-RFP ETH messages (no length field) ---
    t = Tcp()
    F.append(t.rfp_eth(rfpc(0x02, RFPI, HLC, MACCAP), from_omm=True))       # 75
    F.append(t.rfp_eth(rfpc(0x01, REVISION, EXTCAP2), from_omm=False))      # 76
    F.append(t.rfp_eth(bytes([MAC, 0x01, 0x30, 0x00, 0x07, 0x89, 0x00]), from_omm=False))  # 77
    F.append(t.rfp_eth(bytes([LC, 0x05, 0x30, 0x01, len(nwk_dlc(NWK_CC_RELEASE_COM))])
                       + nwk_dlc(NWK_CC_RELEASE_COM), from_omm=True))      # 78
    F.append(t.rfp_eth(bytes([MAC, 0x03, 0x30, 0x02]), from_omm=False))     # 79
    F.append(t.rfp_eth(rfpc(0x13), from_omm=True))                           # 80: no items
    return F


def malformed_frames():
    F = []
    # RFPc item longer than the frame
    F.append(mitel(rfpc(0x01, bytes([0x22, 0x10, 0x01]))))
    # each decoded item cut short at the end of the frame
    for it in (REVISION, RFPI, HLC, EXTCAP, MACCAP, STATS, PLI, EXTCAP2):
        F.append(mitel(rfpc(0x01, it[:2])))
    # RFPc item type without its length
    F.append(mitel(rfpc(0x01, b'\x02')))
    # primitives cut short
    for p in (0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1f):
        F.append(mitel(bytes([MAC, p]), length=8))
    # EKS with ID, PPN missing
    F.append(mitel(bytes([MAC, 0x0a, 0x21, 0x02, 0x07])))
    # LC_DATA with a payload length past the end
    F.append(mitel(bytes([LC, 0x06, 0x21, 0x00, 0x20, 0x01, 0x03])))
    # Mt item longer than the frame; Mt key without length
    F.append(mitel(bytes([MT, 0x01, 0x10, 0x08, 0x01])))
    F.append(mitel(bytes([MT, 0x01, 0x10])))
    # layer missing; prim type missing; length only
    F.append(mitel(b'', length=4))
    F.append(mitel(bytes([MAC]), length=4))
    F.append(eth(b'\x00'))
    # MAC_INFO_IND with a string shorter than 9 octets: shown empty
    F.append(mitel(bytes([MAC, 0x1c, 0x21, 0x00, 0x01, 0x23, 0x00]) + b'short'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dect-mitel-eth-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dect-mitel-eth-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

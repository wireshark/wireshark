#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers to build synthetic 802.11 management frames in a radiotap pcap.
# Everything is made up (locally administered MAC addresses, SSIDs from
# RFC 2606 style names); nothing comes from a real network.
import struct

WFA = b'\x50\x6f\x9a'
MS = b'\x00\x50\xf2'

A1 = bytes.fromhex('02aa00000001')
A2 = bytes.fromhex('02aa00000002')
A3 = bytes.fromhex('02aa00000003')
BCAST = b'\xff' * 6
NANB = bytes.fromhex('51006f9a0100')   # NAN cluster / network ID addresses
NANC = bytes.fromhex('50006f9a0100')

RADIOTAP = struct.pack('<BBHI', 0, 0, 8, 0)


class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, data, ts=None):
        self.frames.append(bytes(data))
        return len(self.frames)

    def write(self, fn, linktype=127):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144,
                                linktype))
            for i, p in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1000 + i, 0, len(p), len(p)))
                f.write(p)


def mgmt(subtype, a1, a2, a3, body, seq=0):
    """802.11 management frame (type 0) with radiotap header."""
    fc = (subtype << 4)
    return RADIOTAP + struct.pack('<HH', fc, 0) + a1 + a2 + a3 + \
        struct.pack('<H', seq << 4) + body


def tag(tid, data):
    assert len(data) <= 255, (tid, len(data))
    return bytes([tid, len(data)]) + data


def vendor_ie(oui, sub, data):
    return tag(221, oui + bytes([sub]) + data)


def wfa_ie(sub, data):
    return vendor_ie(WFA, sub, data)


def beacon(tags, interval=100, capab=0x0401, a1=BCAST, a2=A2, a3=A2):
    return mgmt(8, a1, a2, a3, struct.pack('<QHH', 0, interval, capab) + tags)


def probe_req(tags, a1=BCAST, a2=A1, a3=BCAST):
    return mgmt(4, a1, a2, a3, tags)


def probe_resp(tags, a1=A1, a2=A2, a3=A2, capab=0x0401):
    return mgmt(5, a1, a2, a3, struct.pack('<QHH', 0, 100, capab) + tags)


def assoc_req(tags, a1=A2, a2=A1, a3=A2):
    return mgmt(0, a1, a2, a3, struct.pack('<HH', 0x0401, 10) + tags)


def assoc_resp(tags, a1=A1, a2=A2, a3=A2):
    return mgmt(1, a1, a2, a3, struct.pack('<HHH', 0x0401, 0, 0xc001) + tags)


def public_action_vendor(sub, data, a1=A2, a2=A1, a3=A2, oui=WFA):
    """Public action (category 4), action 9 (vendor specific)."""
    return mgmt(13, a1, a2, a3, bytes([4, 9]) + oui + bytes([sub]) + data)


def vendor_action(sub, data, a1=A2, a2=A1, a3=A2, oui=WFA):
    """Vendor specific protected-less action (category 127)."""
    return mgmt(13, a1, a2, a3, bytes([127]) + oui + bytes([sub]) + data)


def adv_proto_anqp():
    return tag(108, bytes([0x7f, 0x00]))


def adv_proto_vs(oui, sub, dppsub=1):
    # Advertisement Protocol tuple: info, id 221, length, OUI, WFA subtype,
    # DPP subtype (1 = DPP Configuration Protocol)
    return tag(108, bytes([0x7f, 221, 5]) + oui + bytes([sub, dppsub]))


def gas_req(adv, query, token=1, a1=A2, a2=A1, a3=A2):
    return mgmt(13, a1, a2, a3, bytes([4, 10, token]) + adv +
                struct.pack('<H', len(query)) + query)


def gas_resp(adv, resp, token=1, status=0, delay=0, a1=A1, a2=A2, a3=A2):
    return mgmt(13, a1, a2, a3, bytes([4, 11, token]) +
                struct.pack('<HH', status, delay) + adv +
                struct.pack('<H', len(resp)) + resp)


def anqp_vendor(sub, payload):
    """ANQP vendor specific list element, WFA OUI."""
    body = WFA + bytes([sub]) + payload
    return struct.pack('<HH', 56797, len(body)) + body


def gas_comeback_resp(adv, resp, frag, more, token=1, status=0, delay=0,
                      a1=A1, a2=A2, a3=A2):
    return mgmt(13, a1, a2, a3, bytes([4, 13, token]) +
                struct.pack('<H', status) + bytes([frag | (0x80 if more else 0)]) +
                struct.pack('<H', delay) + adv + struct.pack('<H', len(resp)) + resp)


class PcapNg:
    """pcapng writer with one interface per link type (127 radiotap, 1 Ethernet)."""
    def __init__(self):
        self.frames = []
        self.links = []

    @staticmethod
    def block(btype, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

    def add(self, data, link=127):
        if link not in self.links:
            self.links.append(link)
        self.frames.append((self.links.index(link), bytes(data)))
        return len(self.frames)

    def write(self, fn):
        out = self.block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for l in self.links:
            out += self.block(1, struct.pack('<HHI', l, 0, 262144))
        for i, (ifc, p) in enumerate(self.frames):
            ts = 1000000000 + i
            out += self.block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
        with open(fn, 'wb') as f:
            f.write(out)

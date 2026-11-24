#!/usr/bin/env python3
# Generates test/captures/btbnep_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic coverage captures for the Bluetooth BNEP dissector
# (epan/dissectors/packet-btbnep.c). Every packet is built with struct;
# nothing comes from a real network.
#
# Usage: mkbtbnep.py <outdir>
#   btbnep-coverage.pcapng            main capture (H4 + L2CAP PSM 0x000F,
#                                     and Exported PDU "btbnep")
#   btbnep-coverage-malformed.pcapng  warnings, errors and exceptions
import os
import struct
import sys

SENT, RECV = 0, 1
LT_H4_PHDR = 201
LT_EXP_PDU = 252
HANDLE = 0x002b
SCID, DCID = 0x0040, 0x0041          # local and remote L2CAP channel IDs
PSM_BNEP = 0x000F

MAC_A = bytes.fromhex('020000000001')     # locally administered, unicast
MAC_B = bytes.fromhex('001122334455')     # globally unique, unicast
BCAST = b'\xff' * 6

UUID_NAP, UUID_PANU, UUID_GN = 0x1116, 0x1115, 0x1117
BT_BASE = bytes.fromhex('00001000800000805f9b34fb')   # last 12 octets of the base UUID


class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(1, struct.pack('<HHI', linktype, 0, 262144))
        return self.ifaces[linktype]

    def add(self, linktype, data):
        i = self.iface(linktype)
        self.ts += 1000
        self._block(6, struct.pack('<IIIII', i, self.ts >> 32, self.ts & 0xffffffff,
                                   len(data), len(data)) + data)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


# ---------------------------------------------------------------- HCI / L2CAP
def h4_acl(direction, cid, payload, handle=HANDLE):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    acl = struct.pack('<HH', (handle & 0x0fff) | 0x2000, len(l2)) + l2
    return struct.pack('>I', direction) + b'\x02' + acl


def conn_complete(handle=HANDLE, bd_addr=bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])):
    params = struct.pack('<BH', 0, handle) + bd_addr + bytes([0x01, 0x00])
    return struct.pack('>I', RECV) + b'\x04' + bytes([0x03, len(params)]) + params


def l2cap_connect(ident=1):
    req = struct.pack('<BBHHH', 0x02, ident, 4, PSM_BNEP, SCID)
    rsp = struct.pack('<BBHHHHH', 0x03, ident, 8, DCID, SCID, 0, 0)
    return [h4_acl(SENT, 1, req), h4_acl(RECV, 1, rsp)]


def bnep(direction, payload):
    """BNEP over the dynamic channel: sent to the remote CID, received on ours."""
    return h4_acl(direction, DCID if direction == SENT else SCID, payload)


def exp_pdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


# ---------------------------------------------------------------- payloads
def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4_udp(payload=b'BNEP'):
    src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    udp_len = 8 + len(payload)
    pseudo = src + dst + struct.pack('>BBH', 0, 17, udp_len)
    udp = struct.pack('>HHHH', 1000, 2000, udp_len, 0) + payload
    udp = udp[:6] + struct.pack('>H', csum(pseudo + udp)) + udp[8:]
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + udp_len, 1, 0, 64, 17, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + udp


def arp(op=1):
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op,
                       MAC_A, bytes([192, 0, 2, 1]), b'\0' * 6, bytes([192, 0, 2, 2]))


def llc_snap_ipv4():
    return bytes([0xAA, 0xAA, 0x03, 0, 0, 0]) + struct.pack('>H', 0x0800) + ipv4_udp()


def ipx():
    # IPX header only: checksum 0xFFFF, length 30, packet type 4 (PEP),
    # destination and source network/node/socket.
    return struct.pack('>HHBB4s6sH4s6sH', 0xFFFF, 30, 0, 4,
                       b"\0\0\0\1", BCAST, 0x7777, b"\0\0\0\1", MAC_B, 0x7778)


def ctl(ctype, data=b''):
    return bytes([ctype]) + data


def setup_req(size, dst, src):
    def uuid(u):
        if size == 2:
            return struct.pack('>H', u)
        if size == 4:
            return struct.pack('>I', u)
        return struct.pack('>I', u) + BT_BASE
    return ctl(0x01, bytes([size]) + uuid(dst) + uuid(src))


def ext(more, etype, data):
    return bytes([(0x80 if more else 0) | etype, len(data)]) + data


# ---------------------------------------------------------------- captures
def main_capture():
    c = Pcapng()
    h4 = lambda d: c.add(LT_H4_PHDR, d)

    h4(conn_complete())                                              # 1
    for f in l2cap_connect():                                        # 2-3
        h4(f)
    # 4-5: Setup Connection with 16-bit UUIDs (NAP <- PANU) and response
    h4(bnep(SENT, bytes([0x01]) + setup_req(2, UUID_NAP, UUID_PANU)))
    h4(bnep(RECV, bytes([0x01]) + ctl(0x02, struct.pack('>H', 0))))
    # 6: Setup Connection Request with 32-bit UUIDs (NAP <- PANU), the
    #    reproducer of btbnep_extension_hdr.py frame 5
    h4(bnep(SENT, bytes([0x01]) + setup_req(4, UUID_NAP, UUID_PANU)))
    # 7: Setup Connection Request with 128-bit UUIDs (GN <- PANU)
    h4(bnep(SENT, bytes([0x01]) + setup_req(16, UUID_GN, UUID_PANU)))
    # 8: Setup Connection Response "Connection Not Allowed"
    h4(bnep(RECV, bytes([0x01]) + ctl(0x02, struct.pack('>H', 4))))
    # 9-10: Command Not Understood, of a known and of an unknown control type
    h4(bnep(RECV, bytes([0x01]) + ctl(0x00, bytes([0x03]))))
    h4(bnep(RECV, bytes([0x01]) + ctl(0x00, bytes([0x09]))))
    # 11-12: Filter Net Type Set (IPv4..IPv4, ARP..IPv6) and Response
    h4(bnep(SENT, bytes([0x01]) + ctl(0x03, struct.pack('>HHHHH', 8, 0x0800, 0x0800, 0x0806, 0x86DD))))
    h4(bnep(RECV, bytes([0x01]) + ctl(0x04, struct.pack('>H', 1))))
    # 13-14: Filter Multi Addr Set (two ranges) and Response
    h4(bnep(SENT, bytes([0x01]) + ctl(0x05, struct.pack('>H', 24) +
                                      bytes.fromhex('01005e000001') + bytes.fromhex('01005e0000ff') +
                                      bytes.fromhex('333300000001') + bytes.fromhex('3333ffffffff'))))
    h4(bnep(RECV, bytes([0x01]) + ctl(0x06, struct.pack('>H', 3))))
    # 15: unknown control type 0x09 (no data)
    h4(bnep(SENT, bytes([0x01]) + ctl(0x09)))
    # 16: General Ethernet, IPv4/UDP
    h4(bnep(SENT, bytes([0x00]) + MAC_B + MAC_A + struct.pack('>H', 0x0800) + ipv4_udp()))
    # 17: Compressed Ethernet, IPv4/UDP
    h4(bnep(RECV, bytes([0x02]) + struct.pack('>H', 0x0800) + ipv4_udp(b'pong')))
    # 18: Compressed Ethernet Source Only, ARP request
    h4(bnep(SENT, bytes([0x03]) + MAC_A + struct.pack('>H', 0x0806) + arp(1)))
    # 19: Compressed Ethernet Destination Only, broadcast, ARP reply
    h4(bnep(RECV, bytes([0x04]) + BCAST + struct.pack('>H', 0x0806) + arp(2)))
    # 20: General Ethernet with an 802.3 length: LLC/SNAP IPv4
    p = llc_snap_ipv4()
    h4(bnep(SENT, bytes([0x00]) + MAC_B + MAC_A + struct.pack('>H', len(p)) + p))
    # 21: Compressed Ethernet with an 802.3 length: raw IPX (0xFFFF)
    p = ipx()
    h4(bnep(SENT, bytes([0x02]) + struct.pack('>H', len(p)) + p))
    # 22-23: the reproducer of btbnep_extension_hdr.py frames
    #    3 and 4: Compressed Ethernet, two chained extension control headers
    #    (Filter Net Type Response 1 and 0), then IPv4; a single one
    p = (bytes([0x82]) + struct.pack('>H', 0x0800) +
         ext(True, 0, ctl(0x04, struct.pack('>H', 1))) +
         ext(False, 0, ctl(0x04, struct.pack('>H', 0))) + ipv4_udp())
    h4(bnep(SENT, p))
    p = (bytes([0x82]) + struct.pack('>H', 0x0800) +
         ext(False, 0, ctl(0x04, struct.pack('>H', 1))) + ipv4_udp())
    h4(bnep(SENT, p))
    # 24: Control with an extension: Setup Connection Response, then an
    #    extension control with Filter Multi Addr Response
    h4(bnep(RECV, bytes([0x81]) + ctl(0x02, struct.pack('>H', 0)) +
            ext(False, 0, ctl(0x06, struct.pack('>H', 0)))))
    # 25: General Ethernet, three extensions: unknown type 0x15 (4 octets,
    #    stepped over), an extension control longer than its control (the
    #    rest is stepped over), an unknown type 0x7F empty; then IPv4
    p = (bytes([0x80]) + MAC_B + MAC_A + struct.pack('>H', 0x0800) +
         ext(True, 0x15, b'\x01\x02\x03\x04') +
         ext(True, 0, ctl(0x04, struct.pack('>H', 2)) + b'\xaa\xbb') +
         ext(False, 0x7F, b'') + ipv4_udp())
    h4(bnep(SENT, p))
    # 26: Compressed Ethernet Destination Only with an extension, ARP
    p = (bytes([0x84]) + MAC_B + struct.pack('>H', 0x0806) +
         ext(False, 0, ctl(0x00, bytes([0x01]))) + arp(1))
    h4(bnep(SENT, p))
    # 27: BNEP type 0x7F (Reserved for 802.2 LLC) with an IPv4 ethertype
    h4(bnep(SENT, bytes([0x7F]) + struct.pack('>H', 0x0800) + ipv4_udp()))
    # 28: unknown BNEP type 0x05 with an IPv4 ethertype
    h4(bnep(SENT, bytes([0x05]) + struct.pack('>H', 0x0800) + ipv4_udp()))
    # 29-30: Exported PDU "btbnep" without a direction (UnknownDirection):
    #    Setup Connection Request and Compressed Ethernet IPv4
    c.add(LT_EXP_PDU, exp_pdu('btbnep', bytes([0x01]) + setup_req(2, UUID_NAP, UUID_GN)))
    c.add(LT_EXP_PDU, exp_pdu('btbnep', bytes([0x02]) + struct.pack('>H', 0x0800) + ipv4_udp()))
    return c


def malformed_capture():
    c = Pcapng()
    h4 = lambda d: c.add(LT_H4_PHDR, d)

    h4(conn_complete())                                              # 1
    for f in l2cap_connect():                                        # 2-3
        h4(f)
    # 4: invalid length/type 0x05FF (warning), payload to data
    h4(bnep(SENT, bytes([0x02]) + struct.pack('>H', 0x05FF) + b'\x01\x02\x03\x04'))
    # 5: General Ethernet with a group source address (warning)
    h4(bnep(SENT, bytes([0x00]) + MAC_B + BCAST + struct.pack('>H', 0x0806) + arp()))
    # 6: 802.3 length past the end of the payload (error)
    h4(bnep(SENT, bytes([0x02]) + struct.pack('>H', 100) + llc_snap_ipv4()[:20]))
    # 7: 802.3 length with nothing after it (tvb_bytes_exist false)
    h4(bnep(SENT, bytes([0x02]) + struct.pack('>H', 0)))
    # 8: control type only, Setup Connection Request cut short
    h4(bnep(SENT, bytes([0x01, 0x01, 0x10]) + struct.pack('>I', UUID_NAP)))
    # 9: Filter Net Type Set with a list longer than the data
    h4(bnep(SENT, bytes([0x01]) + ctl(0x03, struct.pack('>HHH', 40, 0x0800, 0x0800))))
    # 10: Filter Multi Addr Set with a list longer than the data
    h4(bnep(SENT, bytes([0x01]) + ctl(0x05, struct.pack('>H', 48) + BCAST)))
    # 11: extension header with its length octet missing
    h4(bnep(SENT, bytes([0x82]) + struct.pack('>H', 0x0800) + b'\x00'))
    # 12: extension length past the end, more extensions flagged
    h4(bnep(SENT, bytes([0x82]) + struct.pack('>H', 0x0800) + b'\x80\x40\x04'))
    # 13: empty BNEP packet
    h4(bnep(SENT, b''))
    # 14: Command Not Understood without the unknown type
    h4(bnep(RECV, bytes([0x01, 0x00])))
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'btbnep-coverage.pcapng'))
    malformed_capture().write(os.path.join(out, 'btbnep-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()

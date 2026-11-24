#!/usr/bin/env python3
# Generates test/captures/autosar_nm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic AUTOSAR NM coverage captures (pcapng).

Usage: mkautosar_nm.py <outdir>

Writes autosar_nm-coverage.pcapng (clean) and
autosar_nm-coverage-malformed.pcapng. Every packet is built here with
struct; nothing was captured from a network.

Interfaces (in both files):
  0  LINKTYPE_CAN_SOCKETCAN (227)      AUTOSAR NM over CAN (heuristic,
                                       default can_id 0 / mask 0xffffffff)
  1  LINKTYPE_ETHERNET (1)             AUTOSAR NM over UDP port 30500 and
                                       PDU Transport over UDP port 30501
                                       (both need -d / -o, no default port)
  2  LINKTYPE_WIRESHARK_UPPER_PDU (252) Exported PDUs naming "autosar-nm"
                                       and "autosar-nm.can"
"""
import struct
import sys
import os

NM_UDP_PORT = 30500
PDUT_UDP_PORT = 30501
PDUT_NM_ID = 0x4e4d0001     # set autosar-nm.pdu_transport.ids to this
PDUT_OTHER_ID = 0x00000777  # not configured: shows as data

T0 = 1700000000


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def shb():
    body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    tot = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, tot) + body + struct.pack('<I', tot)


def idb(linktype):
    body = struct.pack('<HHI', linktype, 0, 0)
    tot = 12 + len(body)
    return struct.pack('<II', 1, tot) + body + struct.pack('<I', tot)


def epb(ifid, ts, data):
    t = int(ts * 1000000)
    body = struct.pack('<IIIII', ifid, t >> 32, t & 0xffffffff, len(data), len(data)) + pad4(data)
    tot = 12 + len(body)
    return struct.pack('<II', 6, tot) + body + struct.pack('<I', tot)


# --- link layer builders ---------------------------------------------------
CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000


def socketcan(canid, data, fd=False):
    """SocketCAN header (big-endian ID in LINKTYPE_CAN_SOCKETCAN)."""
    flags = 0x04 if fd else 0      # CANFD_FDF
    if not fd:
        data = data[:8]
    return struct.pack('>IBBBB', canid, len(data), flags, 0, 0) + data


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_eth(sport, dport, payload, src=(10, 0, 0, 1), dst=(10, 0, 0, 255)):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4B4B', 0x45, 0, 20 + len(udp), 0x1234, 0, 64, 17, 0, *src, *dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + udp


def exported_pdu(name, payload):
    n = name.encode()
    return (struct.pack('>HH', 12, len(pad4(n))) + pad4(n) +
            struct.pack('>HH', 0, 0) + payload)


def pdu_transport(pdus):
    return b''.join(struct.pack('>II', i, len(p)) + p for i, p in pdus)


# --- NM payloads -------------------------------------------------------------
def nm(cbv, sni, user=b''):
    return bytes([cbv, sni]) + user


USER6 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])


def main_frames():
    f = []   # (ifid, data)
    # Frames 1-12: CAN ID 0 (standard), one bit of the CBV at a time and
    # all bits, different source nodes, 8 octets
    for i, cbv in enumerate([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0x41, 0x13]):
        f.append((0, socketcan(0x000, nm(cbv, 0x10 + i, USER6))))
    # 13: two octets only (no user data)
    f.append((0, socketcan(0x000, nm(0x01, 0x05))))
    # 14: extended ID 0 (EFF flag is masked out by CAN_EFF_MASK: matches)
    f.append((0, socketcan(CAN_EFF_FLAG | 0, nm(0x10, 0x21, USER6))))
    # 15: CAN FD, ID 0, 16 octets
    f.append((0, socketcan(0x000, nm(0x40, 0x22, bytes(range(0xa0, 0xae))), fd=True)))
    # 16: CAN FD, ID 0, 64 octets
    f.append((0, socketcan(0x000, nm(0x48, 0x23, bytes(range(62))), fd=True)))
    # 17-19: not for AUTOSAR NM: other ID, extended other ID, RTR ID 0
    f.append((0, socketcan(0x123, nm(0x01, 0x02, USER6))))
    f.append((0, socketcan(CAN_EFF_FLAG | 0x1abcde, nm(0x01, 0x02, USER6))))
    f.append((0, socketcan(CAN_RTR_FLAG | 0x000, b'')))
    # 20: error frame
    f.append((0, socketcan(CAN_ERR_FLAG | 0x004, bytes(8))))
    # 21-24: UDP port 30500, NM direct
    f.append((1, udp_eth(NM_UDP_PORT, NM_UDP_PORT, nm(0x01, 0x31, USER6))))
    f.append((1, udp_eth(NM_UDP_PORT, NM_UDP_PORT, nm(0x50, 0x32, bytes(range(0x40, 0x40 + 30))))))
    f.append((1, udp_eth(NM_UDP_PORT, NM_UDP_PORT, nm(0x08, 0x33))))
    f.append((1, udp_eth(NM_UDP_PORT, NM_UDP_PORT, nm(0x7f, 0x34, b'\x01'))))
    # 25-27: PDU Transport on UDP 30501, NM PDU (ID PDUT_NM_ID), two
    # PDUs in one datagram, and an unconfigured PDU next to an NM PDU
    f.append((1, udp_eth(PDUT_UDP_PORT, PDUT_UDP_PORT, pdu_transport([(PDUT_NM_ID, nm(0x11, 0x41, USER6))]))))
    f.append((1, udp_eth(PDUT_UDP_PORT, PDUT_UDP_PORT, pdu_transport([(PDUT_NM_ID, nm(0x01, 0x42, USER6)),
                                                                     (PDUT_NM_ID, nm(0x20, 0x43, b'\xaa\xbb'))]))))
    f.append((1, udp_eth(PDUT_UDP_PORT, PDUT_UDP_PORT, pdu_transport([(PDUT_OTHER_ID, b'\xde\xad\xbe\xef'),
                                                                     (PDUT_NM_ID, nm(0x02, 0x44, USER6))]))))
    # 28-30: Exported PDU "autosar-nm" (no data argument needed)
    f.append((2, exported_pdu('autosar-nm', nm(0x09, 0x51, USER6))))
    f.append((2, exported_pdu('autosar-nm', nm(0x29, 0x52, bytes(range(0x80, 0x80 + 22))))))
    f.append((2, exported_pdu('autosar-nm', nm(0x00, 0x53))))
    # 31: reproducer: Exported PDU naming "autosar-nm.can" (no CAN info
    # as data). It used to assert; now the dissector rejects it and the
    # payload shows as data.
    f.append((2, exported_pdu('autosar-nm.can', bytes([1, 2, 3, 4, 5, 6, 7, 8]))))
    return f


def malformed_frames():
    f = []
    # 1-2: one octet / empty over CAN ID 0: SNI (and CBV) beyond the end
    f.append((0, socketcan(0x000, b'\x01')))
    f.append((0, socketcan(0x000, b'')))
    # 3-4: same as Exported PDU
    f.append((2, exported_pdu('autosar-nm', b'\x01')))
    f.append((2, exported_pdu('autosar-nm', b'')))
    # 5: one octet over UDP
    f.append((1, udp_eth(NM_UDP_PORT, NM_UDP_PORT, b'\x01')))
    return f


def write(path, frames):
    with open(path, 'wb') as out:
        out.write(shb())
        for lt in (227, 1, 252):
            out.write(idb(lt))
        for i, (ifid, data) in enumerate(frames):
            out.write(epb(ifid, T0 + i, data))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    write(os.path.join(outdir, 'autosar_nm-coverage.pcapng'), main_frames())
    write(os.path.join(outdir, 'autosar_nm-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()

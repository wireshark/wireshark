#!/usr/bin/env python3
# Generates test/captures/socketcan_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SocketCAN dissector
(packet-socketcan.c): CAN, CAN FD and CAN XL frames in LINKTYPE_CAN_SOCKETCAN
(227, big endian ID and flags field) and in Linux cooked captures
(LINKTYPE_LINUX_SLL 113 and LINKTYPE_LINUX_SLL2 276, host endian; the
generator assumes a little endian host).

Usage: mksocketcan.py <output directory>

Writes:
  socketcan-coverage.pcapng            classic CAN (standard and extended
                                       IDs, RTR, padding, every error
                                       frame class), CAN FD (flags, data
                                       lengths up to 64), CAN XL (every
                                       flag, SDU types, padding) on the
                                       three link types and several
                                       interfaces; frames of invalid sizes;
                                       Exported PDU frames that select the
                                       dissector by name
  socketcan-coverage-malformed.pcapng  error frames with a wrong DLC,
                                       data lengths past the end of the
                                       frame
  socketcan-coverage-pcap.pcap         a classic pcap file (no interface IDs
                                       in the records), for runcov.sh
  cfg-uat/                             CAN interface mapping and sender/
                                       receiver UAT files for runcov.sh
  cfg-uat-bad/                         the same with rejected records
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def pcapng(path, linktypes, frames, names=None):
    """frames: list of (interface index, bytes); names: optional if_name
    option of every interface."""
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for k, lt in enumerate(linktypes):
        opts = b''
        if names and names[k]:
            nm = names[k].encode()
            opts = struct.pack('<HH', 2, len(nm)) + nm + b'\0' * ((-len(nm)) % 4)
            opts += struct.pack('<HH', 0, 0)
        out += block(1, struct.pack('<HHI', lt, 0, 65535) + opts)
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def usbhdr(urb_id, typ, xfer, ep, length, caplen, setup=b'\0' * 8, dev=1, bus=1,
           flag_setup=None, flag_data=0):
    """64-byte usbmon header (DLT 220). typ 'S' submit or 'C' complete."""
    if flag_setup is None:
        flag_setup = ord('-')
    return struct.pack('<QBBBBHBBqiiII8siiII', urb_id, ord(typ), xfer, ep, dev, bus,
                       flag_setup, flag_data, 0, 0, 0 if typ == 'C' else -115,
                       length, caplen, setup, 0, 0, 0, 0)


def usb_descriptor(urb, vid, pid, dev=1):
    """Two frames: GET DESCRIPTOR (device) submit and complete."""
    setup = struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)
    s = usbhdr(urb, 'S', 2, 0x80, 18, 0, setup, dev=dev, flag_setup=0, flag_data=ord('<'))
    desc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, 0x0100, 0, 0, 0, 1)
    c = usbhdr(urb, 'C', 2, 0x80, 18, 18, setup, dev=dev, flag_setup=ord('-')) + desc
    return [s, c]


def usb_bulk_out(urb, data, ep=0x02, dev=1):
    return usbhdr(urb, 'S', 3, ep, len(data), len(data), dev=dev) + data


def usb_bulk_in(urb, data, ep=0x81, dev=1):
    return usbhdr(urb, 'C', 3, ep, len(data), len(data), dev=dev) + data

CAN_EFF = 0x80000000
CAN_RTR = 0x40000000
CAN_ERR = 0x20000000

XLF, SEC, RRS = 0x80, 0x01, 0x02
BRS, ESI, FDF = 0x01, 0x02, 0x04

# interfaces of the pcapng files
IF_CAN0, IF_SLL, IF_SLL2, IF_CAN1, IF_PDU = 0, 1, 2, 3, 4
LINKTYPES = [227, 113, 276, 227, 252]
NAMES = ['can0', 'any', 'any2', 'can1', None]


def can(cid, data=b'', length=None, flags_byte=0, big=True, pad_to=16, r1=0, r2=0, dlc8=0):
    """Classic CAN frame: ID and flags (4), length, 3 octets (reserved x2
    and the 8 bit DLC), data, padded to 16 octets."""
    if length is None:
        length = len(data)
    f = struct.pack('>I' if big else '<I', cid) + bytes([length, r1, r2, dlc8]) + data
    return f + bytes(max(0, pad_to - len(f)))


def canfd(cid, data=b'', flags=FDF, big=True, length=None, rsv=b'\0\0'):
    """CAN FD frame: ID and flags (4), length, flags, 2 reserved octets,
    data."""
    if length is None:
        length = len(data)
    return struct.pack('>I' if big else '<I', cid) + bytes([length, flags]) + rsv + data


def canxl(prio, vcid, flags, sdu, data, acceptance=0x11223344, big=True, length=None, xl_big=False):
    """CAN XL frame: priority (11 bits) and VCID (bits 16..23) as one 32 bit
    word, flags, SDU type, 16 bit length, 32 bit acceptance field, data.
    The length, the acceptance field are little endian; the first word is
    big endian in LINKTYPE_CAN_SOCKETCAN and host endian (little) in
    cooked captures."""
    if length is None:
        length = len(data)
    word = prio | (vcid << 16)
    return (struct.pack('>I' if big else '<I', word) + bytes([flags, sdu]) +
            struct.pack('>HI' if xl_big else '<HI', length, acceptance) + data)


def pdu(name, payload):
    """Exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU): the dissector name tag
    selects the dissector registered with that name."""
    nm = name.encode()
    nm += b'\0' * ((-len(nm)) % 4)       # the padding is part of the length
    return struct.pack('>HH', 12, len(nm)) + nm + struct.pack('>HH', 0, 0) + payload


def sll(proto, payload, pkttype=0):
    return struct.pack('>HHH8sH', pkttype, 280, 0, bytes(8), proto) + payload


def sll2(proto, payload, ifindex=2, pkttype=0):
    return struct.pack('>HHIHBB8s', proto, 0, ifindex, 280, pkttype, 0, bytes(8)) + payload


P_CAN, P_CANFD, P_CANXL = 0x000C, 0x000D, 0x000E


def main_frames():
    F = []

    def add(ifc, fr):
        F.append((ifc, fr))
    # --- classic CAN on LINKTYPE_CAN_SOCKETCAN (can0)
    add(IF_CAN0, can(0x123, bytes([1, 2, 3, 4, 5, 6, 7, 8])))                # std, 8 octets
    add(IF_CAN0, can(0x7ff, bytes([0xaa]), dlc8=1))                          # std, 1 octet, padding
    add(IF_CAN0, can(0x001))                                                 # std, no data
    add(IF_CAN0, can(CAN_EFF | 0x18daf110, bytes([2, 0x10, 0x01, 0, 0, 0, 0, 0])))  # extended
    add(IF_CAN0, can(CAN_EFF | 0x1fffffff, bytes([1, 2, 3])))                # extended, max ID
    add(IF_CAN0, can(CAN_RTR | 0x321, length=4))                             # RTR standard
    add(IF_CAN0, can(CAN_RTR | CAN_EFF | 0x00abcdef, length=0))              # RTR extended
    add(IF_CAN0, can(0x500, bytes([0x10, 0x00, 0, 0, 0, 0, 0, 0])))           # NM style frame
    add(IF_CAN0, can(0x7e0, bytes([3, 0x22, 0xf1, 0x90, 0, 0, 0, 0])))        # UDS style frame
    add(IF_CAN0, can(0x7df, bytes([2, 1, 0x0d, 0, 0, 0, 0, 0]), dlc8=8, r1=1, r2=2))  # reserved octets set
    # --- error frames (class ID bits, the 8 octets of the frame)
    add(IF_CAN0, can(CAN_ERR | 0x001, length=8))                             # TX timeout
    add(IF_CAN0, can(CAN_ERR | 0x002, bytes([17, 0, 0, 0, 0, 0, 0, 0]), length=8))   # lost arbitration, bit 17
    add(IF_CAN0, can(CAN_ERR | 0x004, bytes([0, 0x7f, 0, 0, 0, 0, 0, 0]), length=8)) # controller, all flags
    add(IF_CAN0, can(CAN_ERR | 0x008, bytes([0, 0, 0xff, 0x03, 0, 0, 0, 0]), length=8))  # protocol, all types, SOF
    add(IF_CAN0, can(CAN_ERR | 0x008, bytes([0, 0, 0x0c, 0x0a, 0, 0, 0, 0]), length=8))  # data section
    add(IF_CAN0, can(CAN_ERR | 0x010, bytes([0, 0, 0, 0, 0x57, 0, 0, 0]), length=8))  # transceiver
    add(IF_CAN0, can(CAN_ERR | 0x010, bytes([0, 0, 0, 0, 0x2a, 0, 0, 0]), length=8))  # transceiver (other nibbles)
    add(IF_CAN0, can(CAN_ERR | 0x020, length=8))                             # no ACK
    add(IF_CAN0, can(CAN_ERR | 0x040, length=8))                             # bus off
    add(IF_CAN0, can(CAN_ERR | 0x080, length=8))                             # bus error
    add(IF_CAN0, can(CAN_ERR | 0x100, length=8))                             # restarted
    add(IF_CAN0, can(CAN_ERR | 0x1fe00, length=8))                           # reserved bits
    add(IF_CAN0, can(CAN_ERR | 0x0ff, bytes([1, 2, 3, 4, 5, 6, 7, 8]), length=8))  # many flags with specific data
    add(IF_CAN0, can(CAN_ERR | CAN_EFF | 0x40, length=8))                    # error flag with the extended flag
    # --- CAN FD on can0
    add(IF_CAN0, canfd(0x100, bytes(range(8)), flags=FDF))                   # 8 octets
    add(IF_CAN0, canfd(0x101, bytes(range(12)), flags=FDF | BRS))            # BRS
    add(IF_CAN0, canfd(0x102, bytes(range(16)), flags=FDF | ESI))            # ESI
    add(IF_CAN0, canfd(CAN_EFF | 0x1abcdef, bytes(range(20)), flags=FDF | BRS | ESI))
    add(IF_CAN0, canfd(0x103, bytes(range(24))))
    add(IF_CAN0, canfd(0x104, bytes(range(32)), flags=FDF | BRS))
    add(IF_CAN0, canfd(0x105, bytes(range(48))))
    add(IF_CAN0, canfd(0x106, bytes(range(64)), flags=0))                    # 72 octets, FD without the FDF flag
    add(IF_CAN0, canfd(0x107, b'', flags=FDF))                               # FD, no data (8 octets)
    add(IF_CAN0, canfd(0x108, bytes(range(10)), flags=FDF, rsv=b'\x12\x34'))  # data length 10 (not an FD size), reserved set
    add(IF_CAN0, canfd(0x109, bytes(range(5)) + bytes(5), length=5, flags=FDF))  # padding
    # --- CAN XL on can0
    add(IF_CAN0, canxl(0x123, 0x01, XLF | SEC, 0x03, bytes(range(16))))
    add(IF_CAN0, canxl(0x7ff, 0xff, XLF | RRS, 0x01, b'\x01'))
    add(IF_CAN0, canxl(0x000, 0x00, XLF, 0x04, bytes(64)))                   # 802.3
    add(IF_CAN0, canxl(0x010, 0x02, XLF, 0x05, bytes(10)))
    add(IF_CAN0, canxl(0x011, 0x03, XLF, 0x06, bytes(8)))
    add(IF_CAN0, canxl(0x012, 0x04, XLF, 0x07, bytes(8)))
    add(IF_CAN0, canxl(0x013, 0x05, XLF, 0x08, bytes(8)))
    add(IF_CAN0, canxl(0x014, 0x06, XLF, 0x09, bytes(8)))
    add(IF_CAN0, canxl(0x015, 0x07, XLF, 0x0a, bytes(8)))
    add(IF_CAN0, canxl(0x016, 0x08, XLF, 0x00, bytes(8)))
    add(IF_CAN0, canxl(0x017, 0x09, XLF, 0xff, bytes(8)))
    add(IF_CAN0, canxl(0x018, 0x0a, XLF, 0x03, bytes(2048)))                 # longest data, 2060 octets
    add(IF_CAN0, canxl(0x019, 0x0b, XLF, 0x03, bytes(12) + b'padding', length=12))
    # --- frames of sizes no CAN type can have: not dissected
    add(IF_CAN0, can(0x200, bytes(8)) + bytes(5))                           # 21 octets, no FDF flag
    add(IF_CAN0, bytes(4) + b'\x00\x00\x00')                                  # 7 octets
    add(IF_CAN0, canfd(0x201, b'', flags=FDF)[:7])                           # FDF flag but 7 octets
    add(IF_CAN0, canfd(0x202, bytes(100), flags=FDF))                        # FDF flag, 108 octets
    add(IF_CAN0, canxl(0x20, 1, XLF, 3, b'')[:12])                           # XL flag, 12 octets
    add(IF_CAN0, canxl(0x20, 1, XLF, 3, bytes(2100)))                        # XL flag, more than 2060
    # --- second interface (can1): a few frames
    add(IF_CAN1, can(0x123, bytes([8, 7, 6, 5, 4, 3, 2, 1])))
    add(IF_CAN1, canfd(0x124, bytes(range(16)), flags=FDF | BRS))
    add(IF_CAN1, canxl(0x125, 2, XLF, 3, bytes(5)))
    # --- Linux cooked capture (SLL), host (little) endian
    add(IF_SLL, sll(P_CAN, can(0x123, bytes([1, 2, 3, 4, 5, 6, 7, 8]), big=False)))
    add(IF_SLL, sll(P_CAN, can(CAN_EFF | 0x12345, bytes([9, 9]), big=False), pkttype=4))
    add(IF_SLL, sll(P_CAN, can(CAN_ERR | 0x040, length=8, big=False)))
    add(IF_SLL, sll(P_CAN, can(CAN_RTR | 0x456, length=2, big=False)))
    add(IF_SLL, sll(P_CANFD, canfd(0x321, bytes(range(32)), flags=FDF | BRS, big=False)))
    add(IF_SLL, sll(P_CANFD, canfd(CAN_EFF | 0x321, bytes(range(12)), flags=FDF | ESI, big=False)))
    add(IF_SLL, sll(P_CANXL, canxl(0x200, 0x10, XLF | SEC, 0x03, bytes(range(20)), big=False)))
    # --- Linux cooked capture v2 (SLL2)
    add(IF_SLL2, sll2(P_CAN, can(0x124, bytes([1, 2]), big=False)))
    add(IF_SLL2, sll2(P_CANFD, canfd(0x322, bytes(range(24)), flags=FDF, big=False)))
    add(IF_SLL2, sll2(P_CANXL, canxl(0x201, 0x11, XLF, 0x01, bytes(range(9)), big=False)))
    # --- Exported PDU: the dissectors by name (candump and other files use
    #     "can-hostendian"; "can-littleendian", "canfd-bigendian" ... are for
    #     protocols that carry CAN frames in a fixed byte order)
    add(IF_PDU, pdu('can-hostendian', can(0x150, bytes([1, 2, 3]), big=False)))
    add(IF_PDU, pdu('can-littleendian', can(0x151, bytes([4, 5, 6]), big=False)))
    add(IF_PDU, pdu('can-bigendian', can(CAN_EFF | 0x152, bytes([7, 8]))))
    add(IF_PDU, pdu('can-bigendian', canfd(0x153, bytes(range(12)), flags=FDF | BRS)))
    add(IF_PDU, pdu('can-bigendian', canxl(0x154, 3, XLF, 3, bytes(7))))
    add(IF_PDU, pdu('canfd', canfd(0x155, bytes(range(16)), flags=FDF, big=False)))
    add(IF_PDU, pdu('canfd-littleendian', canfd(0x156, bytes(range(20)), flags=FDF | ESI, big=False)))
    add(IF_PDU, pdu('canfd-bigendian', canfd(CAN_EFF | 0x157, bytes(range(24)), flags=FDF | BRS | ESI)))
    add(IF_PDU, pdu('canxl', canxl(0x158, 4, XLF | SEC, 4, bytes(9), big=False)))
    add(IF_PDU, pdu('canxl-littleendian', canxl(0x159, 5, XLF, 5, bytes(10), big=False)))
    add(IF_PDU, pdu('canxl-bigendian', canxl(0x15a, 6, XLF | RRS, 6, bytes(11), big=True, xl_big=True)))
    return F


def malformed_frames():
    F = []

    def add(ifc, fr):
        F.append((ifc, fr))
    # error frames whose length is not 8: expert info "DLC mismatch"
    add(IF_CAN0, can(CAN_ERR | 0x040, length=0))
    add(IF_CAN0, can(CAN_ERR | 0x040, length=4))
    # data length larger than the rest of the frame (exception)
    add(IF_CAN0, can(0x123, bytes(8), length=9, pad_to=0))
    add(IF_CAN0, can(0x123, bytes(4), length=15, pad_to=12))
    add(IF_CAN0, canfd(0x100, bytes(10), length=40, flags=FDF))
    add(IF_CAN0, canxl(0x123, 1, XLF, 3, bytes(4), length=100))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(out, 'socketcan-coverage.pcapng'), LINKTYPES, main_frames(), NAMES)
    pcapng(os.path.join(out, 'socketcan-coverage-malformed.pcapng'), LINKTYPES, malformed_frames(), NAMES)
    # a classic pcap file: no interface ID in the records (no bus ID)
    pcap(os.path.join(out, 'socketcan-coverage-pcap.pcap'), [
        can(0x123, bytes([1, 2, 3, 4, 5, 6, 7, 8])),
        can(CAN_ERR | 0x040, length=8),
        canfd(0x100, bytes(range(12)), flags=FDF | BRS),
        canxl(0x123, 1, XLF, 3, bytes(range(16)))], 227)
    # UAT files for the preference tests in runcov.sh
    d = os.path.join(out, 'cfg-uat')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'CAN_interface_mapping'), 'w') as f:
        f.write('"ffffffff","can0","1"\n"ffffffff","can1","2"\n"1","","3"\n'
                '"ffffffff","any","4"\n"2","","7"\n')
    with open(os.path.join(d, 'CAN_senders_receivers'), 'w') as f:
        f.write('"1","123","ECU A","ECU B, ECU C"\n"0","7ff","Gateway","All"\n'
                '"2","123","ECU D","ECU E"\n')
    # UAT files with a bus ID that does not fit 16 bits (rejected records)
    d = os.path.join(out, 'cfg-uat-bad')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'CAN_interface_mapping'), 'w') as f:
        f.write('"ffffffff","can0","10000"\n')
    with open(os.path.join(d, 'CAN_senders_receivers'), 'w') as f:
        f.write('"10000","123","ECU A","ECU B"\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/bluetooth_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-bluetooth.c coverage.
# Usage: mkbluetooth.py <outdir>
# Writes bluetooth-coverage.pcapng (main) and
# bluetooth-coverage-malformed.pcapng. Every packet is built here with
# struct; nothing is captured from a real network.
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

# pcapng link types
LT_H4 = 187            # Bluetooth HCI H4, no direction
LT_H4_PHDR = 201       # Bluetooth HCI H4 with 4 octet direction
LT_USBMON_MM = 220     # Linux usbmon, memory mapped header (64 octets)
LT_LE_LL = 251         # Bluetooth LE Link Layer
LT_EXP_PDU = 252       # Wireshark Exported PDU
LT_BTMON = 254         # Bluetooth Linux Monitor
LT_LE_LL_PHDR = 256    # Bluetooth LE LL with btle_rf header

LOCAL = bytes.fromhex('001bdc000001')    # big-endian (display order)
REMOTE = bytes.fromhex('001bdc000002')
ADVA = bytes.fromhex('c0ffee000003')
INITA = bytes.fromhex('c0ffee000004')


def le_addr(a):
    return a[::-1]


# ---------------------------------------------------------------- pcapng
class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        self._block(0x0A0D0D0A, shb)

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


# ---------------------------------------------------------------- HCI
def hci_cmd(opcode, params):
    return b'\x01' + struct.pack('<HB', opcode, len(params)) + params


def hci_evt(code, params):
    return b'\x04' + struct.pack('<BB', code, len(params)) + params


def hci_acl(handle, payload, pb=2):
    return b'\x02' + struct.pack('<HH', handle | (pb << 12), len(payload)) + payload


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def cmd_complete(opcode, ret):
    return hci_evt(0x0e, struct.pack('<BH', 1, opcode) + ret)


def cmd_status(opcode, status=0):
    return hci_evt(0x0f, struct.pack('<BBH', status, 1, opcode))


def ad(t, data):
    return struct.pack('<BB', len(data) + 1, t) + data


def uuid128_le(s):
    return bytes.fromhex(s.replace('-', ''))[::-1]


ANCS = '7905F431-B5CE-4E99-A40F-4B1E122D00D0'       # built-in custom UUID
SYNCML_CLIENT = '00000002-0000-1000-8000-0002EE000002'
BASE_110A = '0000110A-0000-1000-8000-00805F9B34FB'  # collapses to 0x110a
CUSTOM1 = '11223344-5566-7788-99AA-BBCCDDEEFF00'    # named only by the UAT


def h4phdr(sent, pkt):
    return struct.pack('>I', 0 if sent else 1) + pkt


# ---------------------------------------------------------------- SDP
def des(content):
    return struct.pack('>BB', 0x35, len(content)) + content


def sdp_uuid16(u):
    return struct.pack('>BH', 0x19, u)


def sdp_uuid32(u):
    return struct.pack('>BI', 0x1A, u)


def sdp_uuid128(s):
    return b'\x1C' + bytes.fromhex(s.replace('-', ''))


def sdp_uint16(v):
    return struct.pack('>BH', 0x09, v)


def sdp_uint32(v):
    return struct.pack('>BI', 0x0A, v)


def sdp_pdu(pid, tid, params):
    return struct.pack('>BHH', pid, tid, len(params)) + params


# ---------------------------------------------------------------- BTLE
def ble_crc(pdu, init=0x555555):
    state = int('{:024b}'.format(init)[::-1], 2)
    for byte in pdu:
        for _ in range(8):
            nb = (state ^ byte) & 1
            byte >>= 1
            state >>= 1
            if nb:
                state |= 1 << 23
                state ^= 0x5a6000
    return struct.pack('<I', state)[:3]


ADV_AA = 0x8E89BED6


def ble_adv(pdu_type, payload, txadd=0, rxadd=0):
    hdr = struct.pack('<BB', pdu_type | (txadd << 6) | (rxadd << 7), len(payload))
    pdu = hdr + payload
    return struct.pack('<I', ADV_AA) + pdu + ble_crc(pdu)


def ble_data(aa, crcinit, llid, payload, nesn=0, sn=0, md=0):
    hdr = struct.pack('<BB', llid | (nesn << 2) | (sn << 3) | (md << 4), len(payload))
    pdu = hdr + payload
    return struct.pack('<I', aa) + pdu + ble_crc(pdu, crcinit)


def btle_rf(channel, pkt, pdutype=0, flags=0x0001 | 0x0002 | 0x0004):
    flags |= pdutype << 7
    return struct.pack('<BbbBIH', channel, -40, -90, 0, ADV_AA, flags) + pkt


# ---------------------------------------------------------------- btmon
def btmon(opcode, data, adapter=0):
    return struct.pack('>HH', adapter, opcode) + data


# ---------------------------------------------------------------- USB
URB_ISO, URB_INT, URB_CTRL, URB_BULK = 0, 1, 2, 3
_urb_id = [0x1000]


def usbmon(ev, xtype, ep, dev, data=b'', setup=None, urb_len=None, status=0):
    if ev == 'S':
        _urb_id[0] += 0x100
    uid = _urb_id[0]
    setup_flag = 0 if setup is not None else ord('-')
    data_flag = 0 if data else (ord('<') if ep & 0x80 else ord('>'))
    if urb_len is None:
        urb_len = len(data)
    hdr = struct.pack('<QBBBBHbbqiiII', uid, ord(ev), xtype, ep, dev, 1,
                      setup_flag, data_flag, 1700000000, 0, status, urb_len, len(data))
    hdr += setup if setup is not None else b'\0' * 8
    hdr += struct.pack('<iiII', 0, 0, 0, 0)
    assert len(hdr) == 64
    return hdr + data


# ---------------------------------------------------------------- Exported PDU
def exp_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return (struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad +
            struct.pack('>HH', 0, 0) + payload)


# ======================================================================
def main_capture():
    p = Pcapng()
    H = lambda sent, pkt: p.add(LT_H4_PHDR, h4phdr(sent, pkt))

    # --- H4 with direction: HCI commands and events
    H(True, hci_cmd(0x0c03, b''))                                   # Reset
    H(False, cmd_complete(0x0c03, b'\x00'))
    H(True, hci_cmd(0x0c13, b'BT Coverage Host'.ljust(248, b'\0')))  # Write Local Name
    H(False, cmd_complete(0x0c13, b'\x00'))
    eir = (ad(0x09, b'Coverage EIR Name') + ad(0x08, b'CovEIR') +
           ad(0x03, struct.pack('<HHH', 0x110a, 0x1101, 0x3fff)) +
           ad(0x05, struct.pack('<II', 0x12345678, 0x0000180f)) +
           ad(0x07, uuid128_le(ANCS) + uuid128_le(BASE_110A)) +
           ad(0x07, uuid128_le(CUSTOM1)) +
           ad(0x0a, b'\x04'))
    H(True, hci_cmd(0x0c52, b'\x00' + eir.ljust(240, b'\0')))      # Write EIR
    H(False, cmd_complete(0x0c52, b'\x00'))
    # LE Set Advertising Data: exactly 31 octets of entries, no terminator
    advdata = ad(0x01, b'\x06') + ad(0x09, b'Coverage LE Adv1') + ad(0x02, struct.pack('<HHHH', 0x180d, 0x180f, 0x1812, 0xfd6f))
    advdata = advdata.ljust(31, b'\0')[:31]
    assert len(ad(0x01, b'\x06') + ad(0x09, b'Coverage LE Adv1') + ad(0x02, struct.pack('<HHHH', 0x180d, 0x180f, 0x1812, 0xfd6f))) == 31
    H(True, hci_cmd(0x2008, bytes([31]) + advdata))
    H(False, cmd_complete(0x2008, b'\x00'))
    # Read Connection Accept Timeout (0.625 ms units) and LE Set Default
    # Rate Parameters (0.125 ms units)
    H(True, hci_cmd(0x0c15, b''))
    H(False, cmd_complete(0x0c15, struct.pack('<BH', 0, 0x1fa0)))
    H(True, hci_cmd(0x20a2, struct.pack('<9H', 0x0050, 0x00a0, 1, 4, 0, 1, 0x0c80, 0x0008, 0x0010)))
    H(False, cmd_complete(0x20a2, b'\x00'))
    # Create Connection to REMOTE, Command Status, Connection Complete
    H(True, hci_cmd(0x0405, le_addr(REMOTE) + struct.pack('<HBBHB', 0xcc18, 1, 0, 0, 1)))
    H(False, cmd_status(0x0405))
    H(False, hci_evt(0x03, struct.pack('<BH', 0, 0x0001) + le_addr(REMOTE) + b'\x01\x00'))
    # L2CAP connect to SDP (PSM 1) on handle 1
    H(True, hci_acl(1, l2cap(1, struct.pack('<BBHHH', 0x02, 1, 4, 0x0001, 0x0040))))
    H(False, hci_acl(1, l2cap(1, struct.pack('<BBHHHHH', 0x03, 1, 8, 0x0041, 0x0040, 0, 0))))
    # SDP Service Search with 16, 32 (collapsing and not) and 128 bit
    # (collapsing, custom built-in name, unknown) UUIDs
    pattern = des(sdp_uuid16(0x0100) + sdp_uuid16(0x3fff) + sdp_uuid32(0x00001101) + sdp_uuid32(0x12345678) +
                  sdp_uuid128(BASE_110A) + sdp_uuid128(SYNCML_CLIENT) + sdp_uuid128(CUSTOM1))
    H(True, hci_acl(1, l2cap(0x0041, sdp_pdu(0x02, 1, pattern + struct.pack('>H', 10) + b'\0'))))
    H(False, hci_acl(1, l2cap(0x0040, sdp_pdu(0x03, 1, struct.pack('>HHII', 2, 2, 0x10000, 0x10001) + b'\0'))))
    # Service Search Attribute, response with a ServiceClassIDList
    attrs = des(sdp_uint32(0x0000ffff))
    H(True, hci_acl(1, l2cap(0x0041, sdp_pdu(0x06, 2, des(sdp_uuid128(SYNCML_CLIENT)) +
                                              struct.pack('>H', 0x200) + attrs + b'\0'))))
    rec = des(sdp_uint16(0x0000) + sdp_uint32(0x10000) +
              sdp_uint16(0x0001) + des(sdp_uuid128(SYNCML_CLIENT) + sdp_uuid16(0x1101)) +
              sdp_uint16(0x0004) + des(des(sdp_uuid16(0x0100)) + des(sdp_uuid16(0x0003) + struct.pack('>BB', 0x08, 3))))
    lists = des(rec)
    H(False, hci_acl(1, l2cap(0x0040, sdp_pdu(0x07, 2, struct.pack('>H', len(lists)) + lists + b'\0'))))
    # LE connection on handle 0x40, ATT discovery
    H(False, hci_evt(0x3e, struct.pack('<BBHBB', 0x01, 0, 0x0040, 0, 0) + le_addr(ADVA) +
                     struct.pack('<HHHB', 24, 0, 72, 0)))
    H(True, hci_acl(0x40, l2cap(4, struct.pack('<BHHH', 0x10, 0x0001, 0xffff, 0x2800))))
    H(False, hci_acl(0x40, l2cap(4, struct.pack('<BB', 0x11, 6) +
                                 struct.pack('<HHH', 0x0001, 0x0005, 0x1800) +
                                 struct.pack('<HHH', 0x0006, 0x0009, 0x180f))))
    H(True, hci_acl(0x40, l2cap(4, struct.pack('<BHHH', 0x10, 0x000a, 0xffff, 0x2800))))
    H(False, hci_acl(0x40, l2cap(4, struct.pack('<BBHH', 0x11, 20, 0x000a, 0x0010) + uuid128_le(ANCS))))
    H(True, hci_acl(0x40, l2cap(4, struct.pack('<BHH', 0x04, 0x000b, 0x0010))))
    H(False, hci_acl(0x40, l2cap(4, struct.pack('<BBH', 0x05, 2, 0x000b) + uuid128_le('00002902-0000-1000-8000-00805F9B34FB'))))
    H(False, hci_acl(0x40, l2cap(4, struct.pack('<BBH', 0x05, 2, 0x000c) + uuid128_le(CUSTOM1))))
    H(True, hci_acl(0x40, l2cap(4, struct.pack('<BH', 0x0a, 0x000c))))
    H(False, hci_acl(0x40, l2cap(4, b'\x0b' + b'Custom value')))

    # --- H4 without direction
    p.add(LT_H4, hci_cmd(0x0c03, b''))
    p.add(LT_H4, cmd_complete(0x0c03, b'\x00'))

    # --- Linux Bluetooth monitor
    p.add(LT_BTMON, btmon(0, struct.pack('<BB', 0, 1) + le_addr(LOCAL) + b'hci0\0\0\0\0'))
    p.add(LT_BTMON, btmon(2, struct.pack('<HB', 0x0c03, 0)))
    p.add(LT_BTMON, btmon(3, struct.pack('<BBBHB', 0x0e, 4, 1, 0x0c03, 0)))

    # --- LE Link Layer advertising
    gaen = struct.pack('<H', 0xfd6f) + bytes(range(0x10, 0x20)) + bytes.fromhex('a1b2c3d4')
    p.add(LT_LE_LL, ble_adv(0, le_addr(ADVA) + ad(0x01, b'\x1a') + ad(0x03, struct.pack('<H', 0xfd6f)) +
                            ad(0x16, gaen), txadd=1))
    # GAEN service data shorter than 20 octets: declined, shown as data
    p.add(LT_LE_LL, ble_adv(0, le_addr(ADVA) + ad(0x01, b'\x1a') + ad(0x16, struct.pack('<H', 0xfd6f) + b'\x01\x02\x03\x04'), txadd=1))
    # Matter commissionable, network recovery and an unknown opcode
    p.add(LT_LE_LL, ble_adv(0, le_addr(ADVA) + ad(0x16, struct.pack('<HBHHHB', 0xfff6, 0x00, 0x1123, 0xfff1, 0x8001, 0x01)), txadd=1))
    p.add(LT_LE_LL, ble_adv(0, le_addr(ADVA) + ad(0x16, struct.pack('<HBBQB', 0xfff6, 0x01, 0x10, 0x0102030405060708, 0x02)), txadd=1))
    p.add(LT_LE_LL, ble_adv(0, le_addr(ADVA) + ad(0x16, struct.pack('<HB', 0xfff6, 0x05) + b'\xaa\xbb'), txadd=1))
    # Scan response: 32 and 128 bit service data with a custom UUID
    p.add(LT_LE_LL, ble_adv(4, le_addr(ADVA) + ad(0x20, struct.pack('<I', 0x12345678) + b'\x55') +
                            ad(0x21, uuid128_le(ANCS) + b'\x66'), txadd=1))
    # CONNECT_IND, then data channel packets
    AA = 0x50655A3C
    CRCINIT = 0x123456
    lldata = (struct.pack('<I', AA) + struct.pack('<I', CRCINIT)[:3] +
              struct.pack('<BHHHH', 2, 0, 24, 0, 72) + b'\xff\xff\xff\xff\x1f' + b'\x05')
    p.add(LT_LE_LL_PHDR, btle_rf(0, ble_adv(5, le_addr(INITA) + le_addr(ADVA) + lldata, txadd=1, rxadd=1), pdutype=1))
    p.add(LT_LE_LL_PHDR, btle_rf(5, ble_data(AA, CRCINIT, 3, struct.pack('<BBHH', 0x0c, 0x0b, 0x000f, 0x0001)), pdutype=2))
    p.add(LT_LE_LL_PHDR, btle_rf(5, ble_data(AA, CRCINIT, 3, struct.pack('<BBHH', 0x0c, 0x0b, 0x000f, 0x0002), nesn=1), pdutype=3))
    p.add(LT_LE_LL_PHDR, btle_rf(5, ble_data(AA, CRCINIT, 2, l2cap(4, struct.pack('<BHHH', 0x08, 0x0001, 0xffff, 0x2803)), sn=1, nesn=1), pdutype=2))
    p.add(LT_LE_LL_PHDR, btle_rf(5, ble_data(AA, CRCINIT, 2, l2cap(4, struct.pack('<BBHBHH', 0x09, 7, 0x0002, 0x02, 0x0003, 0x2a00)), sn=1, nesn=0), pdutype=3))

    # --- LE LL with RF pseudo-header
    p.add(LT_LE_LL_PHDR, btle_rf(0, ble_adv(2, le_addr(ADVA) + ad(0x01, b'\x06') +
                                          ad(0x16, struct.pack('<HBHHHB', 0xfff6, 0, 0x0f00, 0xfff1, 0x8000, 0x00)), txadd=1)))

    # --- USB: device descriptor of a 0a5c:21e8 adapter, then HCI over USB
    DEV = 3
    p.add(LT_USBMON_MM, usbmon('S', URB_CTRL, 0x80, DEV, setup=struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18), urb_len=18))
    devdesc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0xe0, 0x01, 0x01, 64, 0x0a5c, 0x21e8, 0x0112, 1, 2, 3, 1)
    p.add(LT_USBMON_MM, usbmon('C', URB_CTRL, 0x80, DEV, data=devdesc))
    cmd = struct.pack('<HB', 0x0c03, 0)
    p.add(LT_USBMON_MM, usbmon('S', URB_CTRL, 0x00, DEV, data=cmd, setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, len(cmd))))
    p.add(LT_USBMON_MM, usbmon('S', URB_INT, 0x81, DEV, urb_len=16))
    p.add(LT_USBMON_MM, usbmon('C', URB_INT, 0x81, DEV, data=struct.pack('<BBBHB', 0x0e, 4, 1, 0x0c03, 0)))
    p.add(LT_USBMON_MM, usbmon('S', URB_INT, 0x81, DEV, urb_len=16))
    lecc = struct.pack('<BBHBB', 0x01, 0, 0x0040, 0, 0) + le_addr(ADVA) + struct.pack('<HHHB', 24, 0, 72, 0)
    p.add(LT_USBMON_MM, usbmon('C', URB_INT, 0x81, DEV, data=struct.pack('<BB', 0x3e, len(lecc)) + lecc))
    att = l2cap(4, struct.pack('<BH', 0x0a, 0x0003))
    p.add(LT_USBMON_MM, usbmon('S', URB_BULK, 0x02, DEV, data=struct.pack('<HH', 0x2040, len(att)) + att))
    p.add(LT_USBMON_MM, usbmon('C', URB_BULK, 0x02, DEV, urb_len=len(att) + 4))
    p.add(LT_USBMON_MM, usbmon('S', URB_BULK, 0x82, DEV, urb_len=64))
    att = l2cap(4, b'\x0b' + b'Coverage')
    p.add(LT_USBMON_MM, usbmon('C', URB_BULK, 0x82, DEV, data=struct.pack('<HH', 0x2040, len(att)) + att))

    # --- Exported PDUs naming the dissectors of packet-bluetooth.c
    E = lambda name, data: p.add(LT_EXP_PDU, exp_pdu(name, data))
    E('bluetooth.usb', bytes([0x01, 0x03, 0x0c, 0x00]))   # reproducer: no URB info
    E('bluetooth', bytes([0x01, 0x03, 0x0c, 0x00]))
    E('bluetooth.bthci', bytes([0x01, 0x03, 0x0c, 0x00]))
    E('bluetooth.btmon', bytes([0x01, 0x03, 0x0c, 0x00]))
    E('bluetooth_ubertooth', ble_adv(2, le_addr(ADVA) + ad(0x01, b'\x06'), txadd=1))
    E('bluetooth.gaen', bytes(range(0x30, 0x40)) + bytes.fromhex('01020304'))
    E('bluetooth.gaen', bytes.fromhex('0102030405'))     # shorter than 20: declined
    E('bluetooth.alt_beacon', struct.pack('>H', 0xbeac) + bytes(range(1, 21)) + b'\xc5\x00')
    E('bluetooth.apple.ibeacon', struct.pack('>BB', 2, 21) + bytes.fromhex(CUSTOM1.replace('-', '')) +
      struct.pack('>HHb', 1, 2, -59))
    E('bluetooth.matter', struct.pack('<BHHHB', 0x00, 0x0f00, 0xfff1, 0x8002, 0x03))
    return p


def malformed_capture():
    p = Pcapng()
    E = lambda name, data: p.add(LT_EXP_PDU, exp_pdu(name, data))
    # Truncated AltBeacon, iBeacon and Matter
    E('bluetooth.alt_beacon', b'\xbe\xac\x01')
    E('bluetooth.apple.ibeacon', b'\x02\x15')
    E('bluetooth.matter', b'\x00\x01')
    E('bluetooth.matter', b'\x01\x10\x01')
    # bluetooth_ubertooth with junk (btle exception)
    E('bluetooth_ubertooth', b'\xd6\xbe\x89')
    # bluetooth.usb with empty data
    E('bluetooth.usb', b'')
    # GAEN in an advertisement shorter than 20 octets in the reported length
    # but truncated in the captured data is not possible with pcapng EPB here.
    # H4 phdr with an HCI command that is too short
    p.add(LT_H4_PHDR, h4phdr(True, b'\x01\x03'))
    # HCI USB: completion of the HCI command control transfer without
    # data throws in hci_usb (not in packet-bluetooth.c)
    DEV = 4
    p.add(LT_USBMON_MM, usbmon('S', URB_CTRL, 0x80, DEV, setup=struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18), urb_len=18))
    devdesc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0xe0, 0x01, 0x01, 64, 0x0a5c, 0x21e8, 0x0112, 1, 2, 3, 1)
    p.add(LT_USBMON_MM, usbmon('C', URB_CTRL, 0x80, DEV, data=devdesc))
    cmd = struct.pack('<HB', 0x0c03, 0)
    p.add(LT_USBMON_MM, usbmon('S', URB_CTRL, 0x00, DEV, data=cmd, setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, len(cmd))))
    p.add(LT_USBMON_MM, usbmon('C', URB_CTRL, 0x00, DEV, urb_len=len(cmd)))
    # LE LL with bad CRC
    pkt = bytearray(ble_adv(0, le_addr(ADVA) + ad(0x01, b'\x06'), txadd=1))
    pkt[-1] ^= 0xff
    p.add(LT_LE_LL, bytes(pkt))
    return p


def nointerface_capture():
    """A pcap file: records without an interface ID."""
    recs = [h4phdr(True, hci_cmd(0x0c03, b'')), h4phdr(False, cmd_complete(0x0c03, b'\x00'))]
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LT_H4_PHDR)
    for i, r in enumerate(recs):
        out += struct.pack('<IIII', 1700000000 + i, 0, len(r), len(r)) + r
    return out


if __name__ == '__main__':
    main_capture().write(OUT + '/bluetooth-coverage.pcapng')
    malformed_capture().write(OUT + '/bluetooth-coverage-malformed.pcapng')
    with open(OUT + '/bluetooth-coverage-pcap.pcap', 'wb') as f:
        f.write(nointerface_capture())

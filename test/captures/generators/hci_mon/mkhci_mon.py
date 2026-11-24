#!/usr/bin/env python3
# Generates test/captures/hci_mon_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth Linux monitor
dissector (packet-hci_mon.c).

The Linux Bluetooth monitor (btmon) link type
LINKTYPE_BLUETOOTH_LINUX_MONITOR (254) has a four octet big endian
pseudo header (adapter id, opcode) followed by a payload that depends on
the opcode: adapter index information (new/delete/open/close/info),
HCI commands, events, ACL, SCO and ISO packets without the H4 type
octet, vendor diagnostics, system notes, user log messages and control
socket messages. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkhci_mon.py <output directory>

Writes:
  hci_mon-coverage.pcapng            two adapters on two interfaces,
                                     every opcode, HCI traffic with a
                                     connection that is torn down by a
                                     Delete Index
  hci_mon-coverage-malformed.pcapng  payloads cut short, a record
                                     shorter than the pseudo header
                                     is not possible (file error), an
                                     Exported PDU naming hci_mon
"""

import os
import struct
import sys

# ------------------------------------------------------------ pcapng
def blk(t, body):
    pad = (-len(body)) % 4
    l = 12 + len(body) + pad
    return struct.pack('<II', t, l) + body + b'\0' * pad + struct.pack('<I', l)


def opt(code, val):
    pad = (-len(val)) % 4
    return struct.pack('<HH', code, len(val)) + val + b'\0' * pad


class Pcapng:
    def __init__(self, linktypes):
        self.data = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in linktypes:
            self.data += blk(1, struct.pack('<HHI', lt, 0, 65535))
        self.ts = 1700000000 * 1000000

    def epb(self, ifid, pkt, direction=None):
        """direction: None (no flags option), 0 unknown, 1 inbound, 2 outbound."""
        self.ts += 1000
        o = b''
        if direction is not None:
            o = opt(2, struct.pack('<I', direction)) + opt(0, b'')
        self.data += blk(6, struct.pack('<IIIII', ifid, self.ts >> 32, self.ts & 0xffffffff,
                                        len(pkt), len(pkt)) + pkt + b'\0' * ((-len(pkt)) % 4) + o)
        # the option block follows the padded packet data

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.data)



LT = 254


def mon(adapter, opcode, payload=b''):
    return struct.pack('>HH', adapter, opcode) + payload


def cmd(opcode, params=b''):
    return struct.pack('<HB', opcode, len(params)) + params


def evt(code, params=b''):
    return struct.pack('<BB', code, len(params)) + params


def acl(handle, data, pb=2):
    return struct.pack('<HH', handle | (pb << 12), len(data)) + data


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def sco(handle, data):
    return struct.pack('<HB', handle, len(data)) + data


def iso(handle, data):
    return struct.pack('<HH', handle, len(data)) + data


BDADDR = bytes([1, 2, 3, 4, 5, 6])


def new_index(bus, typ, addr, name):
    return bytes([bus, typ]) + addr + name.ljust(8, b'\0')[:8]


def user_log(prio, ident, msg):
    return bytes([prio, len(ident) + 1]) + ident + b'\0' + msg


def control_open(cookie, fmt, ver, rev, flags, command):
    return (struct.pack('<IHBHIB', cookie, fmt, ver, rev, flags, len(command))
            + command)


def session(a):
    """An HCI session on adapter a; the connection handle is a + 1."""
    h = a + 1
    return [
        mon(a, 2, cmd(0x0c03)),                                    # Reset
        mon(a, 3, evt(0x0e, bytes([1, 0x03, 0x0c, 0]))),           # Command Complete
        mon(a, 2, cmd(0x0405, BDADDR + struct.pack('<HBBHB', 0xcc18, 0, 0, 0, 1))),
        mon(a, 3, evt(0x03, struct.pack('<BH', 0, h) + BDADDR + bytes([1, 0]))),  # Connection Complete
        mon(a, 4, acl(h, l2cap(0x0001, bytes([2, 1, 4, 0, 1, 0x10, 0x40, 0])))),   # ACL Tx
        mon(a, 5, acl(h, l2cap(0x0001, bytes([3, 1, 8, 0, 0x41, 0, 0x40, 0, 0, 0, 0, 0])))),  # ACL Rx
        mon(a, 4, acl(h, l2cap(0x0041, b'\x01\x02\x03\x04'))),
        mon(a, 5, acl(h, l2cap(0x0040, b'\x05\x06\x07\x08'))),
        mon(a, 6, sco(h, bytes(range(8)))),                         # SCO Tx
        mon(a, 7, sco(h, bytes(range(8, 16)))),                     # SCO Rx
        mon(a, 18, iso(h, struct.pack('<HH', 1, 0) + b'\x01\x02\x03\x04')),  # ISO Tx
        mon(a, 19, iso(h, struct.pack('<HH', 1, 0) + b'\x01\x02\x03\x04')),  # ISO Rx
    ]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    p = Pcapng([LT, LT])

    def e(ifid, pkt):
        p.epb(ifid, pkt)

    # adapters appear: BR/EDR over USB and AMP over UART, then each
    # gets opened and described
    e(0, mon(0, 0, new_index(0, 1, BDADDR, b'hci0')))
    e(0, mon(0, 8))                                                  # Open Index
    e(0, mon(0, 10, bytes([6, 5, 4, 3, 2, 1]) + struct.pack('<H', 15)))   # Index Info
    e(1, mon(0, 0, new_index(1, 3, bytes([9, 8, 7, 6, 5, 4]), b'hci0-amp')))
    e(1, mon(1, 0, new_index(0, 0, bytes([1, 1, 1, 1, 1, 1]), b'a-name-longer-than-8')))
    for typ in (2, 4, 5, 6, 7):
        e(0, mon(2, 0, new_index(0, typ, bytes([typ] * 6), b'hci2')))
    # the same adapter number on the other interface is another adapter
    e(1, mon(1, 8))
    e(1, mon(1, 10, bytes([6, 5, 4, 3, 2, 1]) + struct.pack('<H', 2)))
    for pk in session(0):
        e(0, pk)
    for pk in session(1):
        e(1, pk)
    # vendor diagnostic, system notes, user logging (every priority)
    e(0, mon(0, 11))
    e(0, mon(0, 11, b'\xde\xad\xbe\xef'))
    e(0, mon(0, 12, b'Bluetooth subsystem version 2.22\0'))
    e(0, mon(0, 12, b'no terminator'))
    e(0, mon(0, 12))
    for prio in range(8):
        e(0, mon(0xffff, 13, user_log(prio, b'bluetoothd', b'message %d' % prio)))
    e(0, mon(0xffff, 13, user_log(9, b'', b'')))
    e(0, mon(0xffff, 13, bytes([6, 0]) + b'text without an ident'))
    # control socket messages: open (raw, user, control and an unknown
    # format), the commands and events (every event value of the table
    # and an unknown one), close
    for fmt in (0, 1, 2, 3):
        e(0, mon(0xffff, 14, control_open(0x1000 + fmt, fmt, 2, 22, fmt & 1, b'bluetoothd'.ljust(16, b'\0'))))
    e(0, mon(0xffff, 14, control_open(0x2000, 2, 2, 22, 0, b'')))
    for opc in (0x0001, 0x0002, 0x0003, 0x0010, 0x0123, 0x0400):
        e(0, mon(0xffff, 16, struct.pack('<IH', 0x1002, opc)))
    e(0, mon(0xffff, 16, struct.pack('<IH', 0x1002, 0x0001) + b'\x01\x02'))   # payload: unknown data
    for ev in list(range(1, 0x27)) + [0x27, 0x40, 0xffff]:
        e(0, mon(0xffff, 17, struct.pack('<IH', 0x1002, ev)))
    e(0, mon(0xffff, 17, struct.pack('<IH', 0x1002, 0x0001) + bytes([0, 0, 0, 0])))  # payload: unknown data
    e(0, mon(0xffff, 15, struct.pack('<I', 0x1002)))
    e(0, mon(0xffff, 15, struct.pack('<I', 0x1003)))
    # opcodes that are not in the table
    for opc in (20, 21, 100, 0xffff):
        e(0, mon(0, opc, b'\x01\x02\x03'))
    # an empty payload for every opcode that takes none
    for opc in (1, 8, 9, 11):
        e(1, mon(1, opc))
    # a close, then adapter 0 on interface 0 goes away (Delete Index);
    # later packets for it see the frame of the deletion
    e(0, mon(0, 9))
    e(0, mon(0, 1))
    e(0, mon(0, 0, new_index(0, 1, BDADDR, b'hci0')))
    e(0, mon(0, 2, cmd(0x0c03)))
    e(0, mon(0, 3, evt(0x0e, bytes([1, 0x03, 0x0c, 0]))))
    e(1, mon(1, 2, cmd(0x0c03)))              # adapter 1 on the other interface is unaffected
    e(0, mon(1, 2, cmd(0x0c03)))              # adapter 1 on interface 0 was never deleted
    e(0, mon(0, 1))                           # deleted again
    e(0, mon(0, 2, cmd(0x0c03)))
    p.write(os.path.join(out, 'hci_mon-coverage.pcapng'))

    # -------------------------------------------------------- malformed
    q = Pcapng([LT, 252])

    def m(pkt):
        q.epb(0, pkt)

    m(mon(0, 0, b'\x00'))                      # new index cut short
    m(mon(0, 0, new_index(0, 1, BDADDR, b'hci0')[:10]))   # name cut short
    m(mon(0, 10, BDADDR))                      # index info without manufacturer
    m(mon(0, 10, b'\x01\x02'))
    m(mon(0xffff, 13, b'\x06'))                # user logging without ident length
    m(mon(0xffff, 13, bytes([6, 200]) + b'short'))   # ident longer than the data
    m(mon(0xffff, 14, struct.pack('<IH', 1, 2)))     # control open cut short
    m(mon(0xffff, 14, struct.pack('<IHBHIB', 1, 2, 2, 22, 0, 40) + b'abc'))  # command longer than data
    m(mon(0xffff, 15, b'\x01'))                # control close cut short
    m(mon(0xffff, 16, b'\x01\x02\x03\x04\x05'))
    m(mon(0xffff, 17, b'\x01\x02\x03\x04\x05'))
    m(mon(0, 2, b'\x03'))                      # HCI command cut short
    m(mon(0, 3, b'\x0e\x10\x01'))
    m(mon(0, 4, b'\x01\x20\xff\x00\x01'))
    m(mon(0, 6, b'\x01'))
    m(mon(0, 18, b'\x01\x00\x20\x00'))
    # a connection of adapter 5 is torn down by Delete Index; an ACL packet
    # for it afterwards is out of any connection handle session (the
    # frame of the deletion is passed to the ACL dissector)
    for pk in session(5)[:6]:
        m(pk)
    m(mon(5, 1))
    m(mon(5, 4, acl(6, l2cap(0x0041, b'\x01\x02\x03\x04'))))
    # Exported PDU naming hci_mon: no Bluetooth metadata is passed down
    tag = struct.pack('>HH', 12, 8) + b'hci_mon\0' + struct.pack('>HH', 0, 0)
    q.epb(1, tag + b'\x00\x01\x02')
    q.epb(1, tag + mon(0, 2, cmd(0x0c03)))
    q.write(os.path.join(out, 'hci_mon-coverage-malformed.pcapng'))


main()

#!/usr/bin/env python3
# Generates test/captures/i1d3_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the X-Rite i1 Display Pro (i1d3) coverage captures. Usage: mki1d3.py <outdir>
# Linux usbmon records (LINKTYPE_USB_LINUX_MMAPPED) in a pcapng with a second
# interface for Exported PDU; built with struct, nothing comes from a real device.
#   i1d3-coverage.pcapng            main capture
#   i1d3-coverage-malformed.pcapng  paths only unusual input reaches
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import usbmon_helper
from usbmon_helper import Cap

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def blk(typ, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    n = len(body) + 12
    return struct.pack('<II', typ, n) + body + struct.pack('<I', n)


class Capng:
    """pcapng writer: interface 0 usbmon, interface 1 Exported PDU"""
    def __init__(self):
        self.b = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        self.b += blk(1, struct.pack('<HHI', 220, 0, 65535))
        self.b += blk(1, struct.pack('<HHI', 252, 0, 65535))
        self.t = 1700000000 * 1000000
        self.cap = Cap()
        self.n = 0

    def flush(self):
        for r in self.cap.recs[self.n:]:
            self.pkt(0, r)
        self.n = len(self.cap.recs)

    def pkt(self, iface, data):
        self.t += 1000
        self.b += blk(6, struct.pack('<IIIII', iface, self.t >> 32, self.t & 0xffffffff,
                                     len(data), len(data)) + data)

    def exp_pdu(self, name, payload):
        self.flush()
        n = name.encode()
        n += b'\0' * ((4 - len(n) % 4) % 4)
        self.pkt(1, struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload)

    def write(self, name):
        self.flush()
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(self.b)


def pad(b, n=64):
    return b + b'\0' * (n - len(b))


class Dev:
    """a colorimeter, the commands and responses of one conversation"""
    def __init__(self, cap, addr, ep_out=0x01, ep_in=0x01, pid=0x5020, vid=0x0765):
        self.c = cap
        self.addr, self.eo, self.ei = addr, ep_out, ep_in
        usbmon_helper.DEV = addr
        cap.cap.enumerate(bcd=0x0100, vid=vid, pid=pid)

    def cmd(self, data, ln=64):
        usbmon_helper.DEV = self.addr
        c = self.c.cap
        c.id += 1
        data = pad(data, ln) if ln else data
        c._rec(c.id, b'S', 1, self.eo, None, data, len(data))

    def resp(self, data, ln=64):
        usbmon_helper.DEV = self.addr
        c = self.c.cap
        c.id += 1
        data = pad(data, ln) if ln else data
        c._rec(c.id, b'C', 1, self.ei, None, data, len(data))

    def xfer(self, cmd, resp, **kw):
        self.cmd(cmd, **kw)
        self.resp(resp, **kw)


def main_capture():
    ng = Capng()
    # Exported PDU naming i1d3 before any conversation: no direction, nothing is decoded
    ng.exp_pdu('i1d3', pad(b'\x00\x10'))
    d = Dev(ng, 2)
    # control transfers to endpoint 0 (HID class requests) are not for i1d3
    c = ng.cap
    usbmon_helper.DEV = 2
    c.control(bytes([0x81, 6, 0, 0x22, 0, 0, 4, 0]), bytes([5, 1, 9, 2]))
    c.control(bytes([0x21, 9, 0, 2, 0, 0, 2, 0]), b'', out_data=b'\x00\x01')
    # information and strings
    d.xfer(b'\x00\x00', b'\x00\x00' + b'Model=i1Display3;Rev=1\0')
    d.xfer(b'\x00\x01', b'\x00\x00\x00\x07\x00')            # status 0x000700: OK
    d.xfer(b'\x00\x01', b'\x00\x00\x00\x03\x00')            # status 0x000300: Bad
    d.xfer(b'\x00\x01', b'\x00\x00\x01\x00\x00')            # status with the 0xff0000 byte set: OK
    d.xfer(b'\x00\x10', b'\x00\x00i1Display3\0')
    d.xfer(b'\x00\x11', b'\x00\x00\x00\x00\x01')            # product type 0x0001
    d.xfer(b'\x00\x12', b'\x00\x001.23\0')
    d.xfer(b'\x00\x13', b'\x00\x00Sep 12 2012\0')
    d.xfer(b'\x00\x20', b'\x00\x00\x00\x01')                # locked
    d.xfer(b'\x00\x20', b'\x00\x00\x00\x00')                # unlocked (low byte 0)
    d.xfer(b'\x00\x20', b'\x00\x00\x01\x00')                # unlocked (high byte set)
    # lock challenge and unlock
    d.xfer(b'\x99\x00', pad(b'\x00\x99\x11\x22') + b'')
    resp = bytearray(64); resp[0] = 0; resp[1] = 0x99; resp[2] = 0xa5; resp[3] = 0x5a
    resp[35:43] = bytes(range(1, 9))
    d.xfer(b'\x99\x00', bytes(resp))
    d.xfer(b'\x9a\x00' + bytes(22) + bytes(range(16)) + bytes(24), b'\x00\x9a\x77')   # unlocked
    d.xfer(b'\x9a\x00' + bytes(22) + bytes(range(16, 32)) + bytes(24), b'\x00\x9a\x00')  # failed
    d.xfer(b'\x9b\x00', b'\x00\x9b')                        # relock
    # measurements
    d.xfer(b'\x01' + struct.pack('<I', 1200000), b'\x00\x01' + struct.pack('<III', 12, 34, 56))
    d.xfer(b'\x02' + struct.pack('<HHH', 3, 4, 5),
           b'\x00\x02' + struct.pack('<III', 6000000, 3000000, 1500000))
    d.xfer(b'\x93\x00', b'\x00\x93\x12\x34')                # analog sensor (no decoding)
    # EEPROM reads
    d.xfer(b'\x08\x10\x08', b'\x00\x08\x00\x00' + bytes(range(8)))
    d.xfer(b'\x12' + struct.pack('>H', 0x0120) + b'\x10', b'\x00\x12\x00\x00\x00' + bytes(range(16)))
    # LED
    d.xfer(b'\x21\x01\x80\x20\x03', b'\x00\x21')            # blink, 3 pulses
    d.xfer(b'\x21\x03\x10\x20\x80', b'\x00\x21')            # blink with fade, infinite
    # diffuser
    d.xfer(b'\x94\x00', b'\x00\x00')                        # display
    d.xfer(b'\x94\x00', b'\x00\x01')                        # ambient
    # error response
    d.xfer(b'\x00\x10', b'\x01\x00')
    # command repeated so that its response is shown at the request
    d.xfer(b'\x00\x00', b'\x00\x00' + b'again\0')
    ng.exp_pdu('i1d3', pad(b'\x00\x00'))
    ng.write('i1d3-coverage.pcapng')


def malformed_capture():
    ng = Capng()
    d = Dev(ng, 2)
    d.xfer(b'\x77\x00', b'\x00\x00')                        # unknown command (code 0x7700)
    d.xfer(b'\x00\x10', b'\x00\x05i1Display3\0')            # echoed command code mismatch
    d.xfer(b'\x94\x00', b'\x00\x07')                        # unknown diffuser position
    d.xfer(b'\x00\x10', b'\x00\x00' + b'x' * 20, ln=30)     # packet of unusual length
    d.xfer(b'\x00\x10', b'\x00\x00' + b'x' * 20, ln=0)
    # one-byte response: throws at the echoed command code, then another response
    # to the same request (reproducer of "USB-I1D3: Do not assert on a response
    # that was already matched")
    d.cmd(b'\x00\x10')
    d.resp(b'\x00', ln=0)
    d.resp(b'\x00\x00i1Display3\0')
    d.resp(b'\x00\x00i1Display3\0')
    # a response without a request
    d2 = Dev(ng, 3)
    d2.resp(b'\x00\x00i1Display3\0')
    d2.resp(b'\x03\x00')                                    # error code, no request
    # the realistic layout: commands to OUT endpoint 0x01, responses from IN endpoint 0x81
    d3 = Dev(ng, 4, ep_out=0x01, ep_in=0x81)
    d3.xfer(b'\x00\x10', b'\x00\x00i1Display3\0')
    d3.xfer(b'\x00\x00', b'\x00\x00info\0')
    # truncated payloads for every command
    for cmd in (b'\x08\x10', b'\x12\x01', b'\x21\x01', b'\x01\x00', b'\x02\x00', b'\x9a\x00'):
        d.cmd(cmd, ln=len(cmd))
    d.resp(b'\x00\x08', ln=3)
    # direction unknown through Exported PDU, a direction-less record
    ng.exp_pdu('i1d3', b'\x00')
    ng.write('i1d3-coverage-malformed.pcapng')


main_capture()
malformed_capture()

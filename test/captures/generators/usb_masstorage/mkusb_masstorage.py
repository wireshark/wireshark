#!/usr/bin/env python3
# Generates test/captures/usb_masstorage_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB Mass Storage Class coverage captures (packet-usb-masstorage.c).

usage: mkusb_masstorage.py <outdir> [-v]
Writes usb-masstorage-coverage.pcapng and usb-masstorage-coverage-malformed.pcapng.

packet-usb-masstorage.c is the class dispatcher: for interface class 8 it hands
bulk, control, interrupt and descriptor traffic to the sub-dissector registered
for the interface protocol (0x50 Bulk-Only, 0x62 UAS, others have none).
Devices (Linux usbmon, 64 octet header, bus 1 unless noted):
  2  Bulk-Only disk (8/6/0x50): class requests, SCSI commands, a vendor descriptor
  3  UAS disk (8/6/0x62) with pipe usage descriptors
  4  CBI floppy (8/4/0x00, UFI) with an interrupt endpoint
  5  CBI with completion interrupt (8/4/0x01) on USBPcap (bus 3)
  6  vendor specific protocol (8/6/0xff) and "obsolete" protocol 2 (8/5/2)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mscgen import (
    BOT_GET_MAX_LUN, bot_ifaces, BOT_RESET, BULK, Bus, cbw, cdb_inquiry, cdb_read10, cdb_tur,
    cfg_desc, CLS_IF_IN, CLS_IF_OUT, csw, dev_desc, ep_desc, if_desc, inquiry_data, INT,
    LT_USB_LINUX_MM, LT_USBPCAP, Pcapng, setup, uas_ifaces,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)

    s0 = w.count
    # Bulk-Only: a class-specific descriptor of a type nobody dissects follows the interface descriptor
    vend = bytes([5, 0x24, 0x01, 0x02, 0x03])
    mm.enumerate(2, dev_desc(vid=0x0781, pid=0x5581),
                 cfg_desc(bot_ifaces(extra=vend)))
    mm.control(2, setup(CLS_IF_IN, BOT_GET_MAX_LUN, 0, 0, 1), b'\x01')
    mm.control(2, setup(CLS_IF_OUT, BOT_RESET, 0, 0, 0))
    mm.control(2, setup(CLS_IF_OUT, 0x00, 0, 0, 12), out_data=bytes(12))   # a class request BOT does not know
    mm.xfer(2, 0x02, BULK, cbw(1, 96, 0x80, 0, cdb_inquiry(96)))
    mm.xfer(2, 0x81, BULK, inquiry_data())
    mm.xfer(2, 0x81, BULK, csw(1, 0, 0))
    mm.xfer(2, 0x02, BULK, cbw(2, 512, 0x80, 0, cdb_read10(0, 1)))
    mm.xfer(2, 0x81, BULK, bytes(range(256)) * 2 + csw(2, 0, 0))
    mark(w, 'device 2, Bulk-Only: descriptor, class requests, commands', s0)

    s0 = w.count
    mm.enumerate(3, dev_desc(vid=0x174c, pid=0x55aa), cfg_desc(uas_ifaces(alt=0)))
    iu = struct.pack('>BBHBBBB', 1, 0, 1, 0, 0, 0, 0) + bytes(8) + cdb_tur().ljust(16, b'\0')
    mm.xfer(3, 0x01, BULK, iu)
    mm.xfer(3, 0x82, BULK, struct.pack('>BBHHB', 3, 0, 1, 0, 0) + bytes(7) + struct.pack('>H', 0))
    mark(w, 'device 3, UAS: pipe usage descriptors, Command and Sense IU', s0)

    s0 = w.count
    # control/bulk/interrupt/descriptor traffic of protocols that have no sub-dissector
    ufi_if = if_desc(0, 0, 3, 8, 4, 0) + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64) + ep_desc(0x83, 3, 2, 255)
    mm.enumerate(4, dev_desc(vid=0x03eb, pid=0x6124), cfg_desc(ufi_if + bytes([6, 0x24, 7, 7, 7, 7])))
    mm.control(4, setup(0x21, 0x00, 0, 0, 12), out_data=bytes([0x12, 0, 0, 0, 36, 0]) + bytes(6))   # ADSC (UFI INQUIRY)
    mm.xfer(4, 0x81, BULK, inquiry_data(n=36))
    mm.xfer(4, 0x83, INT, b'\x00\x00')            # interrupt: command completion status
    mm.xfer(4, 0x83, INT, b'\x00\x01')
    mm.control(4, setup(0xa1, 0xfe, 0, 0, 1), b'\x00')       # Get Max LUN is a Bulk-Only request
    mark(w, 'device 4, CBI (protocol 0) with interrupt endpoint', s0)

    s0 = w.count
    cbi_if = if_desc(0, 0, 3, 8, 6, 1) + ep_desc(0x82, 2, 512) + ep_desc(0x03, 2, 512) + ep_desc(0x81, 3, 2, 1)
    pc.enumerate(5, dev_desc(vid=0x0d7d, pid=0x1400), cfg_desc(cbi_if))
    pc.control(5, setup(0x21, 0x00, 0, 0, 12), out_data=bytes(12))
    pc.xfer(5, 0x81, INT, b'\x00\x00')
    pc.xfer(5, 0x02, BULK, b'x' * 20)
    mark(w, 'USBPcap device 5, CBI with completion interrupt (protocol 1)', s0)

    s0 = w.count
    v_if = if_desc(0, 0, 2, 8, 6, 0xff) + ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512)
    mm.enumerate(6, dev_desc(vid=0x1058, pid=0x0748), cfg_desc(v_if))
    mm.control(6, setup(0xc1, 0x01, 0, 0, 4), b'\xde\xad\xbe\xef')
    mm.xfer(6, 0x02, BULK, b'vendor specific bulk')
    mm.xfer(6, 0x81, BULK, b'vendor specific response')
    o_if = if_desc(0, 0, 2, 8, 5, 2) + ep_desc(0x84, 2, 512) + ep_desc(0x05, 2, 512)
    mm.enumerate(7, dev_desc(vid=0x1058, pid=0x0749), cfg_desc(o_if))
    mm.xfer(7, 0x05, BULK, b'protocol 2 bulk')
    mark(w, 'devices 6 and 7, vendor and obsolete protocols', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(), cfg_desc(bot_ifaces()))
    # a Get Max LUN response with no data and a Reset with data; the CBW truncated to 30 octets
    mm.control(2, setup(CLS_IF_IN, BOT_GET_MAX_LUN, 0, 0, 1), b'')
    mm.control(2, setup(CLS_IF_OUT, BOT_RESET, 0, 0, 2), out_data=b'ab')
    mm.xfer(2, 0x02, BULK, cbw(1, 0, 0, 0, cdb_tur())[:30])
    # a class descriptor of length 3 with a wrong length field that is larger than the configuration
    mm.enumerate(3, dev_desc(), cfg_desc(bot_ifaces(extra=bytes([200, 0x24, 1]))))
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-masstorage-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-masstorage-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-70s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

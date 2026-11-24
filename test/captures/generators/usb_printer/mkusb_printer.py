#!/usr/bin/env python3
# Generates test/captures/usb_printer_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB Printer class coverage captures (packet-usb-printer.c).

usage: mkusb_printer.py <outdir> [-v]
Writes usb-printer-coverage.pcapng and usb-printer-coverage-malformed.pcapng.
Devices:
  2  printer (7/1/2, bidirectional), Linux usbmon: GET_DEVICE_ID with several
     lengths, GET_PORT_STATUS, SOFT_RESET, an undefined request, print data
  3  printer on USBPcap (bus 3) with interface 0 (7/1/1) and interface 1 (7/1/3),
     requests that address interface 1 (wIndex = interface << 8 | alternate setting)
  4  printer on Linux usbmon, 48 octet header (bus 2)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    BULK, Bus, cfg_desc, dev_desc, ep_desc, if_desc, LT_USB_LINUX, LT_USB_LINUX_MM, LT_USBPCAP,
    Pcapng, setup,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

GET_DEVICE_ID, GET_PORT_STATUS, SOFT_RESET = 0, 1, 2
CLS_IN, CLS_OUT, CLS_OTHER_OUT = 0xa1, 0x21, 0x23


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def dev_id(s, length=None):
    """IEEE 1284 device ID: 16 bit big endian length (including itself) and the string."""
    b = s.encode('ascii')
    return struct.pack('>H', 2 + len(b) if length is None else length) + b


def printer_if(num, alt, proto, eps=2):
    b = if_desc(num, alt, eps, 7, 1, proto) + ep_desc(0x01 + num, 2, 512)
    if eps > 1:
        b += ep_desc(0x81 + num, 2, 512)
    return b


ID_HP = 'MFG:Hewlett-Packard;CMD:PJL,PCL,PCLXL,POSTSCRIPT;MDL:HP LaserJet 4000;CLS:PRINTER;DES:HP LaserJet 4000;'
ID_EPSON = 'MFG:EPSON;CMD:ESCPL2,BDC,D4,D4PX;MDL:Stylus Photo R200;CLS:PRINTER;'


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    if_48 = w.idb(LT_USB_LINUX)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)
    l48 = Bus(w, 'l48', if_48, bus=2)

    s0 = w.count
    mm.enumerate(2, dev_desc(vid=0x03f0, pid=0x1004), cfg_desc(printer_if(0, 0, 2)))
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), dev_id(ID_HP))
    mm.control(2, setup(CLS_IN, GET_PORT_STATUS, 0, 0x0000, 1), b'\x18')
    mm.control(2, setup(CLS_OUT, SOFT_RESET, 0, 0x0000, 0))
    mm.control(2, setup(CLS_OTHER_OUT, SOFT_RESET, 0, 0x0000, 0))
    mm.control(2, setup(CLS_IN, 3, 0, 0x0000, 4), b'\0\0\0\0')              # a request code the class does not define
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 2), dev_id('', 2))     # Device ID of length 2: no string
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 2), dev_id('', 0))     # length 0
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 3), dev_id('Z', 3))    # a one character string
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 64), dev_id(ID_EPSON) + b'trailing')   # data after the Device ID
    mark(w, 'device 2, class requests', s0)

    s0 = w.count
    mm.xfer(2, 0x02, BULK, b'\x1b%-12345X@PJL JOB NAME="synthetic"\r\n@PJL ENTER LANGUAGE=PCL\r\n\x1bE')
    mm.xfer(2, 0x81, BULK, b'@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="READY"\r\n\x0c')
    mark(w, 'device 2, print data and status on the bulk endpoints', s0)

    s0 = w.count
    two = cfg_desc(printer_if(0, 0, 1, eps=1) + printer_if(1, 0, 3) + printer_if(1, 1, 3), nif=2)
    pc.enumerate(3, dev_desc(vid=0x04b8, pid=0x0005), two)
    pc.control(3, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), dev_id(ID_EPSON))           # interface 0
    pc.control(3, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0101, 1024), dev_id(ID_HP))              # interface 1, alternate setting 1
    pc.control(3, setup(CLS_IN, GET_PORT_STATUS, 0, 0x0100, 1), b'\x38')                      # interface 1
    pc.control(3, setup(CLS_IN, GET_DEVICE_ID, 1, 0x0000, 1024), dev_id(ID_EPSON))           # configuration index 1
    pc.control(3, setup(CLS_OUT, SOFT_RESET, 0, 0x0001, 0))
    pc.xfer(3, 0x02, BULK, b'\x1b@\x1b(R\x08\x00\x00REMOTE1')
    mark(w, 'USBPcap device 3, two interfaces', s0)

    s0 = w.count
    l48.enumerate(4, dev_desc(vid=0x04a9, pid=0x1721), cfg_desc(printer_if(0, 0, 2)))
    l48.control(4, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), dev_id('MFG:Canon;CMD:LBP-SIM;MDL:LBP2900;CLS:PRINTER;'))
    l48.control(4, setup(CLS_IN, GET_PORT_STATUS, 0, 0x0000, 1), b'\x08')
    mark(w, 'device 4, 48 octet usbmon header', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(), cfg_desc(printer_if(0, 0, 2)))
    # Device ID length field larger than the data, a response of one octet (length field cut), and
    # a response with no data at all
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), dev_id(ID_HP, 500))
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), b'\x00')
    mm.control(2, setup(CLS_IN, GET_DEVICE_ID, 0, 0x0000, 1024), b'')
    # a request with a data stage that is shorter than the 6 octets the dissector reads
    mm.control(2, setup(CLS_OUT, GET_DEVICE_ID, 0, 0x0000, 3), out_data=b'abc')
    mm.control(2, setup(CLS_OUT, GET_PORT_STATUS, 0, 0x0000, 4), out_data=b'abcd')
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-printer-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-printer-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-60s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

#!/usr/bin/env python3
# Generates test/captures/usb_dfu_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB DFU coverage captures (packet-usb-dfu.c).

usage: mkusbdfu.py <outdir> [-v]
Writes usb-dfu-coverage.pcapng and usb-dfu-coverage-malformed.pcapng.
Devices (Linux usbmon, 64 octet header, bus 1):
  2  DFU runtime interface (class 0xfe, subclass 1, protocol 1)
  3  DFU mode interface (protocol 2) with a download and upload session
  4  DFU 1.0 functional descriptor (7 octets)
  5, 8  0x1d50:0x6001 (Ubertooth Zero DFU): the product table sends every
     packet of the device to the DFU dissector
  6  0x05ac:0x1227 (Apple DFU mode), USBPcap
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    BULK, Bus, cfg_desc, CTRL, dev_desc, if_desc, INT, linux, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng,
    setup,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

DETACH, DNLOAD, UPLOAD, GETSTATUS, CLRSTATUS, GETSTATE, ABORT = range(7)
OUT_IF = 0x21        # class, interface, host to device
IN_IF = 0xa1


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def dfu_func(attrs=0x0f, detach=255, xfer=1024, bcd=0x0110, length=9):
    d = struct.pack('<BBBHHH', length, 0x21, attrs, detach, xfer, bcd)
    return d[:length]


def dfu_config(proto, func):
    b = if_desc(0, 0, 0, 0xfe, 1, proto) + func
    return cfg_desc(b, nif=1)


def status(st=0, poll=0, state=2, istr=0):
    return struct.pack('<B', st) + struct.pack('<I', poll)[:3] + bytes([state, istr])


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)

    s0 = w.count
    # runtime device
    mm.enumerate(2, dev_desc(vid=0x0483, pid=0x5740, mps=64), dfu_config(1, dfu_func()))
    mm.control(2, setup(IN_IF, GETSTATE, 0, 0, 1), b'\x00')                 # appIdle
    mm.control(2, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 0))
    mm.control(2, setup(OUT_IF, DETACH, 1000, 0, 0), reqonly=True)          # DFU_DETACH, timeout in wValue (its empty response is flagged, see README)
    mm.control(2, setup(IN_IF, GETSTATE, 0, 0, 1), b'\x01')                 # appDetach
    mark(w, 'runtime device 2', s0)

    s0 = w.count
    # DFU mode device: download, upload, status polling
    mm.enumerate(3, dev_desc(vid=0x0483, pid=0xdf11, mps=64), dfu_config(2, dfu_func(attrs=0x0b, xfer=2048)))
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 2))        # dfuIdle
    for blk in range(3):
        mm.control(3, setup(OUT_IF, DNLOAD, blk, 0, 16), out_data=bytes(range(blk, blk + 16)), reqonly=True)
        mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 5 + blk, 4, 0))   # dfuDNBUSY
        mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 5, 0))         # dfuDNLOAD-IDLE
    mm.control(3, setup(OUT_IF, DNLOAD, 3, 0, 0), reqonly=True)             # zero length: end of download
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 20, 6, 0))    # dfuMANIFEST-SYNC
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 7, 0))     # dfuMANIFEST
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 8, 0))     # dfuMANIFEST-WAIT-RESET
    mm.control(3, setup(IN_IF, UPLOAD, 0, 0, 16), bytes(range(100, 116)))
    mm.control(3, setup(IN_IF, UPLOAD, 1, 0, 16), bytes(range(116, 120)))   # short block
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 9, 0))     # dfuUPLOAD-IDLE
    mm.control(3, setup(OUT_IF, ABORT, 0, 0, 0), reqonly=True)
    mm.control(3, setup(IN_IF, GETSTATE, 0, 0, 1), b'\x02')
    # every status and state value of the tables
    for st in range(16):
        mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(st, st * 100, 10 if st else 2, st))
    mm.control(3, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0x55, 1, 77, 1))     # values outside the tables
    mm.control(3, setup(OUT_IF, CLRSTATUS, 0, 0, 0), reqonly=True)
    mm.control(3, setup(IN_IF, GETSTATE, 0, 0, 1), b'\x0b')
    mm.control(3, setup(OUT_IF, DETACH, 0, 0, 0), reqonly=True)
    mark(w, 'DFU mode device 3', s0)

    s0 = w.count
    # DFU 1.0 functional descriptor (7 octets, no bcdDFUVersion)
    mm.enumerate(4, dev_desc(vid=0x1209, pid=0x0001), dfu_config(2, dfu_func(length=7)))
    mm.control(4, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 2))
    mark(w, 'DFU 1.0 descriptor device 4', s0)

    s0 = w.count
    # devices in the product table (usb.product): the DFU dissector sees every packet of the device
    mm.get_desc(5, 1, 0, dev_desc(vid=0x1d50, pid=0x6001, mps=64), 18)
    mm.control(5, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 2))
    mm.control(5, setup(OUT_IF, DNLOAD, 0, 0, 4), out_data=b'\xde\xad\xbe\xef', reqonly=True)
    mm.control(5, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 5))
    mm.control(5, setup(0xa1, UPLOAD, 7, 0, 8), bytes(range(8)))
    mm.xfer(5, 0x81, BULK, b'bulk on a product table device')
    mm.xfer(5, 0x02, BULK, b'bulk out')
    mm.xfer(5, 0x83, INT, b'\x01\x02')
    mm.get_desc(5, 1, 0, dev_desc(vid=0x1d50, pid=0x6003, mps=64), 18)      # second product of the table on another device number
    mm.get_desc(7, 1, 0, dev_desc(vid=0x1d50, pid=0x6003, mps=64), 18)
    # a device of the table whose first non-standard packets are bulk/interrupt data and a response
    # without any DFU command before: "Response: Unknown"
    mm.get_desc(8, 1, 0, dev_desc(vid=0x1d50, pid=0x6001, mps=64), 18)
    mm.xfer(8, 0x81, BULK, b'data before any DFU command')
    mm.emit(linux(b'C', CTRL, 0x80, 8, 1, 0x7811, None, b'orphan', 6))
    mm.control(7, setup(IN_IF, GETSTATE, 0, 0, 1), b'\x02')
    mark(w, 'product table devices 5, 7', s0)

    s0 = w.count
    pc = Bus(w, 'pcap', if_pc, bus=3)
    pc.get_desc(6, 1, 0, dev_desc(vid=0x05ac, pid=0x1227, mps=64), 18)
    pc.get_desc(6, 2, 0, dfu_config(2, dfu_func()), 18)
    pc.control(6, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 0, 2))
    pc.control(6, setup(OUT_IF, DNLOAD, 0, 0, 8), out_data=bytes(range(8)), reqonly=True)
    pc.control(6, setup(IN_IF, GETSTATUS, 0, 0, 6), status(0, 10, 4))
    pc.control(6, setup(IN_IF, UPLOAD, 0, 0, 8), bytes(range(8)))
    pc.control(6, setup(OUT_IF, CLRSTATUS, 0, 0, 0), reqonly=True)
    mark(w, 'USBPcap Apple DFU device 6', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    # functional descriptor with an invalid length (8) and one with length 7 and 8 octets of data
    mm.enumerate(2, dev_desc(), dfu_config(2, dfu_func(length=8) + b'\0'))
    # command and request type that do not belong together
    mm.control(2, setup(0x21, GETSTATUS, 0, 0, 6), status(0, 0, 2))
    mm.control(2, setup(0xa1, DNLOAD, 0, 0, 2), b'ab')
    mm.control(2, setup(0xa1, ABORT, 0, 0, 0))
    mm.control(2, setup(0x21, 9, 0, 0, 0))
    # DETACH with a data stage (unexpected data after the request) and a response with data for a
    # command that has none, and a status response that is cut short
    mm.control(2, setup(OUT_IF, DETACH, 1, 0, 2), out_data=b'xy')
    mm.control(2, setup(OUT_IF, ABORT, 0, 0, 2), b'zz')
    mm.control(2, setup(OUT_IF, CLRSTATUS, 0, 0, 2), b'zz')
    mm.control(2, setup(OUT_IF, DNLOAD, 9, 0, 2), b'zz', out_data=b'ab')
    mm.control(2, setup(IN_IF, GETSTATUS, 0, 0, 6), b'\x00\x01')
    mm.control(2, setup(IN_IF, GETSTATE, 0, 0, 1), b'')
    # complete requests and responses of the commands that have no response data: the empty status stage
    # response is reported as "Unexpected response for this command" (error), see README
    mm.enumerate(3, dev_desc(vid=0x0483, pid=0xdf11), dfu_config(2, dfu_func()))
    mm.control(3, setup(OUT_IF, DETACH, 1000, 0, 0))
    mm.control(3, setup(OUT_IF, DNLOAD, 0, 0, 4), out_data=b'abcd')
    mm.control(3, setup(OUT_IF, DNLOAD, 1, 0, 0))
    mm.control(3, setup(OUT_IF, CLRSTATUS, 0, 0, 0))
    mm.control(3, setup(OUT_IF, ABORT, 0, 0, 0))
    # a device in the product table with requests that are not DFU commands and with wrong directions
    mm.get_desc(5, 1, 0, dev_desc(vid=0x1d50, pid=0x6001, mps=64), 18)
    mm.control(5, setup(0xc0, 0x42, 0, 0, 3), b'\x01\x02\x03')
    mm.control(5, setup(0x40, 0x43, 0, 0, 0))
    mm.control(5, setup(OUT_IF, GETSTATUS, 0, 0, 6))
    mm.control(5, setup(IN_IF, DNLOAD, 1, 0, 4), b'\0\0\0\0')
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-dfu-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-dfu-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-30s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

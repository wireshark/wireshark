#!/usr/bin/env python3
# Generates test/captures/usb_hub_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB hub coverage captures (packet-usb-hub.c).

usage: mkusbhub.py <outdir> [-v]
Writes usb-hub-coverage.pcapng and usb-hub-coverage-malformed.pcapng.
The hub is a Linux usbmon (64 octet header, link type 220) device; a few
sequences are repeated on USBPcap and FreeBSD, and on a device that was
never enumerated (the hub dissector is also registered for class
unknown).
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    Bus, cfg_desc, CTRL, dev_desc, ep_desc, if_desc, INT, linux, LT_USB_FREEBSD, LT_USB_LINUX_MM,
    LT_USBPCAP, Pcapng, setup,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

# bmRequestType values of the hub class requests (USB 2.0, table 11-15)
HUB_OUT = 0x20      # class, device
PORT_OUT = 0x23     # class, other
HUB_IN = 0xa0
PORT_IN = 0xa3

CLEAR_FEATURE, GET_STATUS, SET_FEATURE, GET_DESCRIPTOR, SET_DESCRIPTOR = 1, 0, 3, 6, 7
CLEAR_TT_BUFFER, RESET_TT, GET_TT_STATE, STOP_TT = 8, 9, 10, 11


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def hub_desc(nports=4, chars=0x0009, pwr_good=50, current=100):
    removable = bytes([0x00] * ((nports + 8) // 8))
    mask = bytes([0xff] * ((nports + 8) // 8))
    body = removable + mask
    return struct.pack('<BBBHBB', 7 + len(body), 0x29, nports, chars, pwr_good, current) + body


def ss_hub_desc(nports=4):
    return struct.pack('<BBBHBBBH', 12, 0x2a, nports, 0x0009, 50, 0, 3, 0xffff)


def hub_config(proto=1):
    b = if_desc(0, 0, 1, 9, 0, 0 if proto == 0 else proto)
    b += ep_desc(0x81, 3, 1, 12)
    if proto == 1:
        b += if_desc(0, 1, 1, 9, 0, 2)                         # alternate setting with a TT per port
        b += ep_desc(0x81, 3, 1, 12)
    return cfg_desc(b, nif=1, attr=0xe0)


def port_status(conn=0, enable=0, suspend=0, oc=0, reset=0, power=0, low=0, high=0, test=0, ind=0,
                c_conn=0, c_enable=0, c_suspend=0, c_oc=0, c_reset=0):
    st = conn | enable << 1 | suspend << 2 | oc << 3 | reset << 4 | power << 8 | low << 9 | high << 10 | test << 11 | ind << 12
    ch = c_conn | c_enable << 1 | c_suspend << 2 | c_oc << 3 | c_reset << 4
    return struct.pack('<HH', st, ch)


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    if_bsd = w.idb(LT_USB_FREEBSD)
    s0 = w.count
    mm = Bus(w, 'mm', if_mm, bus=1)
    # enumeration of the hub
    mm.enumerate(2, dev_desc(cls=9, sub=0, proto=1, mps=64, vid=0x05e3, pid=0x0608, bcd=0x0200), hub_config(1))
    mm.get_desc(2, 0x29, 0, hub_desc(), 255, bm=0xa0)             # GET_HUB_DESCRIPTOR (class device request)
    mm.get_desc(2, 0x29, 0, hub_desc(7, 0x00e9, 100, 0)[:8], 8, bm=0xa0)
    mm.get_desc(2, 0x2a, 0, ss_hub_desc(), 12, bm=0xa0)
    # hub and port status
    mm.control(2, setup(HUB_IN, GET_STATUS, 0, 0, 4), b'\x00\x00\x00\x00')
    mm.control(2, setup(HUB_IN, GET_STATUS, 0, 0, 4), b'\x03\x00\x03\x00')
    for port, st in ((1, port_status(conn=1, enable=1, power=1, high=1, c_conn=1)),
                     (2, port_status(power=1)),
                     (3, port_status(conn=1, power=1, low=1, suspend=1, c_suspend=1)),
                     (4, port_status(conn=1, enable=1, power=1, oc=1, reset=1, test=1, ind=1, c_enable=1, c_oc=1, c_reset=1))):
        mm.control(2, setup(PORT_IN, GET_STATUS, 0, port, 4), st)
    # features: every selector of the value tables, hub and port
    for sel in (0, 1, 2, 99):
        mm.control(2, setup(HUB_OUT, SET_FEATURE, sel, 0, 0))
        mm.control(2, setup(HUB_OUT, CLEAR_FEATURE, sel, 0, 0))
    for sel in (0, 1, 2, 3, 4, 8, 9, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99):
        mm.control(2, setup(PORT_OUT, SET_FEATURE, sel, 1 | (sel & 7) << 8, 0))
    for sel in (16, 17, 18, 19, 20, 29, 25, 99):
        mm.control(2, setup(PORT_OUT, CLEAR_FEATURE, sel, 2, 0))
    mm.control(2, setup(PORT_OUT, SET_FEATURE, 4, 3, 0), b'')   # PORT_RESET
    # transaction translator requests
    mm.control(2, setup(PORT_OUT, CLEAR_TT_BUFFER, 0x1201, 1, 0))   # endpoint 1, device 18
    mm.control(2, setup(PORT_OUT, CLEAR_TT_BUFFER, 0x0502, 3, 0))
    mm.control(2, setup(PORT_OUT, RESET_TT, 0, 1, 0))
    mm.control(2, setup(PORT_OUT, RESET_TT, 0, 4, 0))
    mm.control(2, setup(PORT_IN, GET_TT_STATE, 1, 2, 8), b'\x01\x02\x03\x04\x05\x06\x07\x08')
    mm.control(2, setup(PORT_IN, GET_TT_STATE, 0, 1, 0), b'')
    mm.control(2, setup(PORT_OUT, STOP_TT, 0, 3, 0))
    mm.control(2, setup(HUB_OUT, SET_DESCRIPTOR, 0x2900, 0, 9), out_data=hub_desc()[:9])
    mm.control(2, setup(HUB_OUT, SET_DESCRIPTOR, 0x2900, 0, 0))
    # requests the hub dissector does not know: an unknown request, a request with an
    # request type that is not in the table, a request to an interface
    mm.control(2, setup(PORT_OUT, 0x42, 0, 1, 0))
    mm.control(2, setup(0xa2, GET_STATUS, 0, 1, 4), b'\0\0\0\0')
    mm.control(2, setup(0xa1, GET_STATUS, 0, 0, 2), b'\0\0')
    # a response whose request was not captured, and a request without response
    mm.emit(linux(b'C', CTRL, 0x80, 2, 1, 0x7771, None, b'\x01\x01\x00\x00', 4))
    mm.control(2, setup(PORT_IN, GET_STATUS, 0, 2, 4), reqonly=True)
    # status change interrupt endpoint of the hub
    mm.xfer(2, 0x81, INT, b'\x06')
    mm.xfer(2, 0x81, INT, b'\x02\x00')
    mark(w, 'usbmon 64, hub 2', s0)

    # a device that was never enumerated: the hub dissector is also registered for class "unknown"
    s0 = w.count
    mm.control(5, setup(HUB_IN, GET_DESCRIPTOR, 0x2900, 0, 9), hub_desc()[:9])
    mm.control(5, setup(PORT_IN, GET_STATUS, 0, 1, 4), port_status(conn=1, enable=1, power=1))
    mm.control(5, setup(PORT_OUT, SET_FEATURE, 8, 1, 0))
    mm.control(5, setup(HUB_OUT, CLEAR_FEATURE, 0, 0, 0))
    mm.control(5, setup(PORT_OUT, CLEAR_TT_BUFFER, 0x0301, 2, 0))
    mark(w, 'not enumerated device 5', s0)

    # USBPcap and FreeBSD
    s0 = w.count
    pc = Bus(w, 'pcap', if_pc, bus=3)
    pc.enumerate(1, dev_desc(cls=9, proto=2, vid=0x1a40, pid=0x0101), hub_config(2))
    pc.control(1, setup(HUB_IN, GET_DESCRIPTOR, 0x2900, 0, 9), hub_desc()[:9])
    pc.control(1, setup(PORT_IN, GET_STATUS, 0, 2, 4), port_status(conn=1, power=1))
    pc.control(1, setup(PORT_OUT, SET_FEATURE, 8, 2, 0))
    pc.control(1, setup(PORT_OUT, CLEAR_TT_BUFFER, 0x0301, 2, 0))
    mark(w, 'USBPcap', s0)
    s0 = w.count
    bsd = Bus(w, 'bsd', if_bsd, bus=4)
    bsd.enumerate(2, dev_desc(cls=9, proto=2, vid=0x1a40, pid=0x0101), hub_config(2))
    bsd.control(2, setup(HUB_IN, GET_DESCRIPTOR, 0x2900, 0, 9), hub_desc()[:9])
    bsd.control(2, setup(PORT_IN, GET_STATUS, 0, 2, 4), port_status(conn=1, power=1))
    bsd.control(2, setup(PORT_OUT, SET_FEATURE, 4, 2, 0))
    bsd.control(2, setup(PORT_OUT, RESET_TT, 0, 2, 0))
    mark(w, 'FreeBSD', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(cls=9, proto=1), hub_config(1))
    # requests and responses cut short: setup packet complete but the response is shorter than the
    # port status (the bitmask fields run past the end)
    mm.control(2, setup(PORT_IN, GET_STATUS, 0, 1, 4), b'\x01\x01')
    mm.control(2, setup(PORT_IN, GET_STATUS, 0, 1, 4), b'')
    # a hub request whose setup packet is truncated
    mm.emit(linux(b'S', CTRL, 0x80, 2, 1, 0x9101, setup(PORT_IN, GET_STATUS, 0, 1, 4), b'', 4)[:48 + 0])
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-hub-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-hub-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-26s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

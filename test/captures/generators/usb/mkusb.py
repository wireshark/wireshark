#!/usr/bin/env python3
# Generates test/captures/usb_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB coverage captures (packet-usb.c).

usage: mkusb.py <outdir> [-v]
writes usb-coverage.pcapng (clean), usb-coverage-malformed.pcapng.
Each link type uses its own bus number: usbmon 64 byte 1, usbmon 48 byte 2,
USBPcap 3, FreeBSD 4, macOS 5, USB/IP 6.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    bos_desc, BULK, Bus, cap, cfg_desc, CTRL, darwin, darwin_frame, dev_desc, ep_companion,
    ep_desc, FB_COMPLETE, FB_CTRL, FB_FLAG_DATA, FB_FLAG_READ, FB_ISO, FB_ST_CONTROL_HDR,
    FB_SUBMIT, freebsd, iad_desc, if_desc, INT, ISO, langid_desc, linux, LT_ETH, LT_USB_DARWIN,
    LT_USB_FREEBSD, LT_USB_LINUX, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng, setup, string_desc, Tcp,
    usbip_ret, usbip_ret_unlink, usbip_submit, usbip_unlink, usbpcap,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


# ---------------------------------------------------------------- descriptors used in several places

def big_config():
    """Composite device: CDC ACM + data (SuperSpeed companions), mass storage,
    HID boot keyboard, audio control + streaming (alt 0-2), misc, DFU runtime,
    IrDA, USBTMC, vendor, unknown class descriptors, IAD."""
    b = b''
    b += iad_desc(0, 2, 2, 2, 1)
    b += if_desc(0, 0, 1, 2, 2, 1)
    b += bytes([5, 0x24, 0, 0x10, 0x01])                    # CDC header (class specific)
    b += ep_desc(0x83, 3, 8, 255)
    b += ep_companion(0, 0, 8)
    b += if_desc(1, 0, 2, 10, 0, 0)
    b += ep_desc(0x81, 2, 512)
    b += ep_companion(15, 0x1f, 0, 6)                       # bulk, max streams
    b += ep_desc(0x02, 2, 512)
    b += ep_companion(15, 0x00, 0)
    b += if_desc(2, 0, 2, 8, 6, 0x50)
    b += ep_desc(0x84, 2, 64)
    b += ep_desc(0x05, 2, 64)
    b += if_desc(3, 0, 1, 3, 1, 1)
    b += struct.pack('<BBHBBBH', 9, 0x21, 0x0111, 0, 1, 0x22, 63)
    b += ep_desc(0x86, 3, 8, 10)
    b += ep_companion(1, 0, 16)
    b += if_desc(15, 0, 1, 3, 0, 0)                         # HID, not a boot interface
    b += ep_desc(0x8e, 3, 8, 10)
    b += ep_desc(0x0d, 0, 64)                                # control endpoint descriptor (endpoint 13)
    b += ep_companion(0, 0, 0)
    b += if_desc(4, 0, 0, 1, 1, 0)
    b += if_desc(5, 0, 0, 1, 2, 0)
    b += if_desc(5, 1, 1, 1, 2, 0)
    b += ep_desc(0x87, 0x05, 0x00c8, 1, b'\x00\x00', length=9)    # audio: bRefresh, bSynchAddress
    b += ep_companion(0, 0x02, 200)                          # isochronous companion
    b += if_desc(5, 2, 1, 1, 2, 0)
    b += ep_desc(0x07, 0x0d, 0x0190, 1, b'\x00\x88', length=9)
    b += if_desc(6, 0, 0, 0xef, 2, 1)
    b += if_desc(7, 0, 0, 0xfe, 1, 1)
    b += bytes([9, 0x21, 0x0b, 0xff, 0x00, 0x40, 0x00, 0x10, 0x01])   # DFU functional
    b += if_desc(8, 0, 0, 0xfe, 2, 0)
    b += if_desc(9, 0, 0, 0xfe, 3, 1)
    b += if_desc(10, 0, 0, 0xfe, 0x42, 0)
    b += if_desc(11, 0, 1, 9, 0, 0)
    b += ep_desc(0x88, 3, 2, 12)
    b += if_desc(12, 0, 2, 0xff, 0xff, 0xff)
    b += ep_desc(0x89, 2, 512)
    b += ep_desc(0x0a, 2, 512)
    b += bytes([4, 0x42, 1, 2])                              # unknown descriptor type
    b += if_desc(13, 0, 1, 0x0b, 0, 0)                       # smart card (CCID class), no descriptors
    b += ep_desc(0x8b, 3, 8, 255)
    b += if_desc(14, 0, 1, 0x12, 0, 0)                       # class with no dissector
    b += ep_desc(0x8c, 2, 512)
    b += if_desc(16, 0, 1, 0, 0, 0, length=10) + b'\x01'    # class 0 (use the device class), descriptor with an extra octet
    b += ep_desc(0x8d, 2, 512)
    b += if_desc(17, 0, 3, 0xe0, 1, 1)                       # wireless controller / Bluetooth
    b += ep_desc(0x8f, 3, 16, 1) + ep_desc(0x0f, 2, 64) + ep_desc(0x90, 2, 64)
    return cfg_desc(b, nif=18, attr=0xe0)


def bos_ss():
    uuid_web = bytes.fromhex('38b6 0834 a909 a047 8bfd a0768815b665'.replace(' ', ''))
    uuid_ms = bytes.fromhex('df60ddd8 8945 c74c 9cd2 659d9e648a9f'.replace(' ', ''))
    uuid_other = bytes(range(16))
    return bos_desc([
        cap(2, struct.pack('<I', 0x0000f6)),                             # USB 2.0 extension
        cap(3, struct.pack('<BHBBH', 0x02, 0x000e, 1, 10, 0x0100)),      # SuperSpeed
        cap(5, b'\0' + uuid_web + struct.pack('<HBB', 0x0100, 1, 1)),
        cap(5, b'\0' + uuid_ms + struct.pack('<IHBB', 0x06030000, 0x00b2, 2, 0)),
        cap(5, b'\0' + uuid_other),
        cap(0x0a, b''),                                                  # other capability type
    ])


def ss_config():
    b = if_desc(0, 0, 3, 0xff, 0, 0)
    b += ep_desc(0x81, 2, 1024) + ep_companion(15, 0x1f, 0)
    b += ep_desc(0x02, 2, 1024) + ep_companion(15, 0x00, 0)
    b += ep_desc(0x83, 3, 1024, 8) + ep_companion(3, 0, 3072)
    b += if_desc(0, 1, 1, 0xff, 0, 0)
    b += ep_desc(0x84, 1, 1024, 1) + ep_companion(2, 2, 3072)
    return cfg_desc(b, nif=1)


def freebsd_config(ep_attr_mps):
    b = if_desc(0, 0, len(ep_attr_mps), 0xff, 0, 0)
    for i, (attr, mps) in enumerate(ep_attr_mps):
        b += ep_desc(0x81 + i if i % 2 == 0 else 0x01 + i, attr, mps, 4)
    return cfg_desc(b, nif=1)


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_l48 = w.idb(LT_USB_LINUX)
    if_pc = w.idb(LT_USBPCAP)
    if_bsd = w.idb(LT_USB_FREEBSD)
    if_mac = w.idb(LT_USB_DARWIN)
    if_eth = w.idb(LT_ETH)

    # ------------------------------------------------------------ Linux usbmon 64
    s0 = w.count
    mm = Bus(w, 'mm', if_mm, bus=1)
    # device 2: composite, enumerated with partial reads first
    cfg = big_config()
    mm.get_desc(2, 1, 0, dev_desc()[:8], 8)
    mm.get_desc(2, 1, 0, dev_desc(), 18)
    mm.get_desc(2, 6, 0, struct.pack('<BBHBBBBBB', 10, 6, 0x0200, 0, 0, 0, 64, 1, 0), 10)     # device qualifier
    mm.get_desc(2, 2, 0, cfg[:9], 9)
    mm.get_desc(2, 2, 0, cfg, len(cfg))
    mm.get_desc(2, 2, 0, cfg[:60], 60)                      # truncated mid-descriptor, wLength smaller than total
    mm.get_desc(2, 7, 0, cfg[:40], 40)                      # other speed configuration, truncated
    mm.get_desc(2, 3, 0, langid_desc(0x0409, 0x0407), 255)
    mm.get_desc(2, 3, 1, string_desc('Acme'), 255, lang=0x0409)
    mm.get_desc(2, 3, 2, string_desc('Test Widget'), 4, lang=0x0409)      # host asked for part of the string
    mm.get_desc(2, 3, 3, string_desc('Serial 0001'), 1, lang=0x0409)      # wLength 1: reproducer of the string clamp
    mm.get_desc(2, 3, 3, string_desc('Serial 0001'), 0, lang=0x0409)      # wLength 0
    mm.get_desc(2, 0x22, 0, b'\x06\x22\x01\x02\x03\x04', 6)                 # unknown standard descriptor type, device recipient
    mm.get_desc(2, 4, 0, if_desc(0, 0, 0, 0xff, 0, 0), 9)                   # interface and endpoint descriptors on their own
    mm.get_desc(2, 5, 0, ep_desc(0x81, 2, 64), 7)
    mm.control(2, setup(0x00, 9, 1), b'\x00')               # SET_CONFIGURATION, stray octet
    mm.control(2, setup(0x80, 8, 0, 0, 1), b'\x01')          # GET_CONFIGURATION
    mm.control(2, setup(0x80, 0, 0, 0, 2), b'\x03\x00')      # GET_STATUS device
    mm.control(2, setup(0x81, 0, 0, 3, 2), b'\x00\x00')      # interface
    mm.control(2, setup(0x82, 0, 0, 0x81, 2), b'\x01\x00')   # endpoint
    mm.control(2, setup(0x83, 0, 0, 1, 2), b'\x00\x00')      # other
    mm.control(2, setup(0x00, 1, 1, 0), b'\x00')            # CLEAR_FEATURE device (remote wakeup), device returns a stray octet
    mm.control(2, setup(0x01, 1, 0, 3))                      # interface
    mm.control(2, setup(0x02, 1, 0, 0x81))                   # endpoint halt
    mm.control(2, setup(0x03, 1, 0, 1))                      # other
    mm.control(2, setup(0x00, 3, 2, 0), b'\x00')            # SET_FEATURE device (test mode), stray octet
    mm.control(2, setup(0x01, 3, 0, 3))
    mm.control(2, setup(0x02, 3, 0, 0x82))
    mm.control(2, setup(0x03, 3, 5, 6))
    mm.control(2, setup(0x00, 5, 7), b'\x00')               # SET_ADDRESS, stray octet
    mm.control(2, setup(0x80, 10, 0, 3, 1), b'\x00')          # GET_INTERFACE
    mm.control(2, setup(0x01, 11, 1, 5))                     # SET_INTERFACE 5/1 (audio streaming)
    mm.control(2, setup(0x01, 11, 2, 5), b'\x00')           # SET_INTERFACE, stray octet
    mm.control(2, setup(0x01, 11, 0, 5))
    mm.control(2, setup(0x01, 11, 9, 5))                     # alternate setting that does not exist
    mm.control(2, setup(0x82, 12, 0, 0x81, 2), b'\x12\x34')  # SYNCH_FRAME
    mm.control(2, setup(0x00, 7, 0x0200, 0, 4), out_data=b'\xaa\xbb\xcc\xdd')  # SET_DESCRIPTOR, data stage
    mm.control(2, setup(0x00, 48, 0, 0, 6), out_data=b'\0\1\2\3\4\5')   # SET_SEL (USB 3)
    mm.control(2, setup(0x00, 49, 0x1234, 0))                # SET_ISOCH_DELAY
    mm.control(2, setup(0x80, 99, 0, 0, 3), b'\x01\x02\x03') # unknown standard request, response payload
    mm.control(2, setup(0x00, 99, 1, 2, 0))                  # unknown, no data stage
    mm.control(2, setup(0xc0, 1, 2, 3, 4), b'vend')          # vendor, device recipient
    mm.control(2, setup(0x40, 2, 2, 3, 4), out_data=b'vend') # vendor OUT with data
    mm.control(2, setup(0xc1, 1, 2, 3, 4), b'\x01\x02\x03\x04')   # vendor, interface recipient
    mm.control(2, setup(0xc2, 1, 2, 0x81, 4), b'abcd')       # vendor, endpoint recipient
    mm.control(2, setup(0x21, 0x22, 3, 0, 0))                # class interface request to the CDC control interface
    mm.control(2, setup(0xa1, 3, 0, 7, 6), b'\x00\x10\x00\x00\x02\x00')   # DFU GET_STATUS on the DFU runtime interface
    mm.control(2, setup(0xa1, 0x21, 0, 0, 7), b'\x00\xc2\x01\x00\x00\x00\x08')
    mm.control(2, setup(0xa1, 1, 0x0100, 3, 8), b'\x01\x02\x03\x04\x05\x06\x07\x08')   # HID GET_REPORT
    mm.control(2, setup(0x21, 10, 0, 3, 0))                  # HID SET_IDLE
    mm.control(2, setup(0x22, 0x01, 0x0100, 0x89, 3), out_data=b'\x01\x02\x03')       # class request to an endpoint of the vendor interface
    mm.control(2, setup(0xa2, 0x81, 0x0100, 0x89, 3), b'\x01\x02\x03')
    mm.control(2, setup(0x81, 6, 0x2200, 3, 63), b'\x05\x01\x09\x06')                # GET_DESCRIPTOR to an interface (HID report descriptor)
    mm.control(2, setup(0x80, 6, 0x0100, 0, 18), reqonly=True)   # request without response
    # response without a matching request
    mm.emit(linux(b'C', CTRL, 0x80, 2, 1, 0x7777, None, b'orphan', 6))
    # control URB submit without setup data (data stage only), usbmon 64 and 48
    mm.emit(linux(b'S', CTRL, 0x00, 2, 1, 0x7779, None, b'datastage', 9, setup_flag=ord('-')))
    mm.emit(linux(b'C', CTRL, 0x00, 2, 1, 0x7779, None, b'', 9))
    # error completion types
    mm.emit(linux(b'S', CTRL, 0x80, 2, 1, 0x7778, setup(0x80, 0, 0, 0, 2), b'', 2))
    mm.emit(linux(b'E', CTRL, 0x80, 2, 1, 0x7778, None, b'', 0, -32))
    # data transfers on the composite device
    mm.xfer(2, 0x83, INT, b'\xa1\x20\x00\x00\x00\x00\x02\x00\x03\x00')     # CDC notification (interrupt IN)
    mm.xfer(2, 0x81, BULK, b'hello from the device')
    mm.xfer(2, 0x02, BULK, b'hello to the device')
    mm.xfer(2, 0x84, BULK, b'\x55\x53\x42\x43' + b'\0' * 27)
    mm.xfer(2, 0x86, INT, b'\x00\x00\x04\x00\x00\x00\x00\x00')             # HID boot keyboard report
    mm.xfer(2, 0x89, BULK, b'vendor bulk in')                               # vendor class: no dissector
    mm.xfer(2, 0x0a, BULK, b'vendor bulk out')
    mm.xfer(2, 0x8c, BULK, b'class without dissector')
    mm.xfer(2, 0x8b, INT, b'\x50\x03\x00')                                   # CCID class
    mm.xfer(2, 0x8d, BULK, b'class 0 interface')                             # interface class 0: the device class is used
    mm.xfer(2, 0x8e, INT, b'\x01\x02\x03\x04\x05\x06\x07\x08')                 # HID, not boot
    mm.xfer(2, 0x8f, INT, b'\x0e\x04\x01\x03\x0c\x00')                       # HCI event (Command Complete), Bluetooth interface
    mm.xfer(2, 0x0f, BULK, b'\x01\x03\x0c\x00')
    mm.xfer(2, 0x88, INT, b'\x04')                                           # hub status change
    mm.xfer(2, 0x81, BULK, b'', status=-71)                                  # error status, no data
    mm.xfer(2, 0x7f, BULK, b'endpoint nobody described')                    # unknown endpoint 0x7f (no conversation info)
    # isochronous (audio streaming interface, alt 1 and 2 selected above)
    isod = bytes(range(48))
    mm.emit(linux(b'S', ISO, 0x87, 2, 1, 0x9001, None, b'', 96, descs=[(0, 0, 0), (0, 0, 0)], interval=1, start_frame=100, xfer_flags=2))
    mm.emit(linux(b'C', ISO, 0x87, 2, 1, 0x9001, None, b'', 96, descs=[(0, 0, 24), (0, 24, 24), (-18, 48, 0)],
                  iso_data=isod, interval=1, start_frame=100, iso_err=1))
    mm.emit(linux(b'S', ISO, 0x07, 2, 1, 0x9002, None, b'', 48, descs=[(-18, 0, 24), (-18, 24, 24)], iso_data=isod, interval=1))
    mm.emit(linux(b'C', ISO, 0x07, 2, 1, 0x9002, None, b'', 48, descs=[(0, 0, 24), (0, 24, 24)]))
    mm.emit(linux(b'C', ISO, 0x87, 2, 1, 0x9003, None, b'', 24, descs=[], ndesc=0))     # no descriptors at all
    # the same device: speed unknown on Linux, so max packet checks are skipped. Reproducer of SET_INTERFACE growth:
    # one config with many interface descriptors for interface 0 (only 256 alternate settings are kept)
    many = b''.join(if_desc(0, i % 256, 0, 0xff, 0, 0) for i in range(300))
    mm.get_desc(6, 2, 0, cfg_desc(many, nif=1), 9 + len(many))
    mm.control(6, setup(0x01, 11, 255, 0))
    mm.control(6, setup(0x01, 11, 7, 0))
    mm.control(6, setup(0x01, 11, 77, 0))
    # device 3: SuperSpeed device with BOS
    bos = bos_ss()
    mm.get_desc(3, 1, 0, dev_desc(bcd=0x0310, mps=9, cls=0xff), 18)
    mm.get_desc(3, 0x0f, 0, bos[:5], 5)
    mm.get_desc(3, 0x0f, 0, bos, len(bos))
    mm.get_desc(3, 2, 0, ss_config(), len(ss_config()))
    mm.xfer(3, 0x81, BULK, b'ss bulk in')
    mm.xfer(3, 0x83, INT, b'ss int in')
    mm.control(3, setup(0x00, 1, 0, 0x82))
    mm.control(3, setup(0x01, 3, 4, 0))                      # SET_FEATURE interface with function suspend selector
    mark(w, 'Linux usbmon 64 (1)', s0)

    # ------------------------------------------------------------ Linux usbmon 48
    s0 = w.count
    l48 = Bus(w, 'l48', if_l48, bus=2)
    cfg2 = cfg_desc(if_desc(0, 0, 3, 0xff, 0, 0) + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64) + ep_desc(0x83, 3, 8, 4)
                    + if_desc(1, 0, 1, 1, 2, 0) + ep_desc(0x84, 1, 192, 1), nif=2)
    l48.get_desc(2, 1, 0, dev_desc(vid=0x0951, pid=0x1666, mps=8)[:8], 8)
    l48.get_desc(2, 1, 0, dev_desc(vid=0x0951, pid=0x1666, mps=8), 18)
    l48.get_desc(2, 2, 0, cfg2, len(cfg2))
    l48.control(2, setup(0x00, 9, 1))
    l48.control(2, setup(0x01, 11, 0, 1))
    l48.control(2, setup(0xc0, 5, 0, 0, 2), b'\x01\x02')
    l48.control(2, setup(0x40, 6, 0, 0, 3), out_data=b'abc')
    l48.emit(linux(b'S', CTRL, 0x00, 2, 2, 0x5101, None, b'datastage', 9, setup_flag=ord('-'), hdr64=False))
    l48.xfer(2, 0x81, BULK, b'bulk in on usbmon 48')
    l48.xfer(2, 0x02, BULK, b'bulk out')
    l48.xfer(2, 0x83, INT, b'\x01\x02\x03\x04')
    l48.emit(linux(b'S', ISO, 0x84, 2, 2, 0x5001, None, b'', 192, descs=[(0, 0, 0)], hdr64=False))
    l48.emit(linux(b'C', ISO, 0x84, 2, 2, 0x5001, None, b'', 192, descs=[(0, 0, 8)], iso_data=b'isodata!', hdr64=False))
    l48.emit(linux(b'S', ISO, 0x04, 2, 2, 0x5002, None, b'', 8, descs=[(-18, 0, 8)], iso_data=b'outdata!', hdr64=False))
    mark(w, 'Linux usbmon 48 (2)', s0)

    # ------------------------------------------------------------ USBPcap
    s0 = w.count
    pc = Bus(w, 'pcap', if_pc, bus=3)
    cfg3 = cfg_desc(if_desc(0, 0, 4, 0xff, 0, 0) + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64) + ep_desc(0x83, 3, 8, 4)
                    + ep_desc(0x84, 1, 192, 1), nif=1)
    pc.get_desc(1, 1, 0, dev_desc(vid=0x1d6b, pid=0x0002, mps=64)[:8], 8)
    pc.get_desc(1, 1, 0, dev_desc(vid=0x1d6b, pid=0x0002, mps=64), 18)
    pc.get_desc(1, 2, 0, cfg3[:9], 9)
    pc.get_desc(1, 2, 0, cfg3, len(cfg3))
    pc.control(1, setup(0x00, 9, 1))
    pc.control(1, setup(0x80, 8, 0, 0, 1), b'\x01')
    pc.control(1, setup(0x40, 6, 0, 0, 3), out_data=b'abc')       # OUT with data in the setup packet (USBPcap 1.5)
    pc.control(1, setup(0xc0, 6, 0, 0, 3), b'xyz')
    pc.xfer(1, 0x81, BULK, b'usbpcap bulk in')
    pc.xfer(1, 0x02, BULK, b'usbpcap bulk out')
    pc.xfer(1, 0x83, INT, b'\x01\x02')
    # old USBPcap (before 1.5.0.0): the OUT setup stage carries only the setup packet, the data stage follows
    pc.uid += 1
    u = pc.uid
    pc.emit(usbpcap(0, 3, 1, 0, CTRL, u, 0, setup(0x40, 7, 0, 0, 4)))
    pc.emit(usbpcap(0, 3, 1, 0, CTRL, u, 1, b'\x01\x02\x03\x04'))
    pc.emit(usbpcap(1, 3, 1, 0, CTRL, u, 2, b''))
    # IRP info packet and a status stage completion without any setup
    pc.emit(usbpcap(0, 3, 1, 0, 0xfe, 0x4242, None, b'', function=0x1a))
    pc.emit(usbpcap(1, 3, 1, 0, 0xfe, 0x4242, None, b'', function=0x09))
    pc.emit(usbpcap(1, 3, 1, 0x80, CTRL, 0x4343, 2, b''))
    # isochronous: IN submit, IN completion (relevant lengths), OUT submit
    pc.emit(usbpcap(0, 3, 1, 0x84, ISO, 0x6001, None, b'', iso=(1000, 0, [(0, 0, 0), (96, 0, 0)]), datalen=192))
    pc.emit(usbpcap(1, 3, 1, 0x84, ISO, 0x6001, None, b'', iso=(1000, 1, [(0, 90, 0), (96, 96, 0)]),
                    iso_data=bytes(range(186)) + b'', datalen=192))
    pc.emit(usbpcap(0, 3, 1, 0x84, ISO, 0x6003, None, b'', iso=(1002, 0, [(8, 0, 0), (4, 0, 0)]), datalen=8))
    pc.emit(usbpcap(0, 3, 1, 0x04, ISO, 0x6002, None, b'', iso=(1001, 0, [(0, 4, 0), (4, 4, 0)]),
                    iso_data=b'12345678', datalen=8))
    pc.emit(usbpcap(1, 3, 1, 0x04, ISO, 0x6002, None, b'', iso=(1001, 0, [(0, 4, 0), (4, 4, 0)]), datalen=8))
    mark(w, 'USBPcap (3)', s0)

    # ------------------------------------------------------------ FreeBSD
    s0 = w.count
    bsd = Bus(w, 'bsd', if_bsd, bus=4)
    # full speed device: legal packet sizes
    fcfg = freebsd_config([(2, 64), (2, 64), (3, 8), (1, 1023), (1, 400)])
    hcfg0 = freebsd_config([(2, 512), (2, 512), (3, 1024), (1, 1024), (1, 512)])
    bsd.get_desc(2, 1, 0, dev_desc(mps=64)[:8], 8)
    bsd.get_desc(2, 1, 0, dev_desc(mps=64), 18)
    bsd.get_desc(2, 6, 0, struct.pack('<BBHBBBBBB', 10, 6, 0x0200, 0, 0, 0, 64, 1, 0), 10)
    bsd.get_desc(2, 2, 0, fcfg, len(fcfg))
    bsd.get_desc(2, 7, 0, hcfg0, len(hcfg0))               # other speed configuration of a full speed device: high speed sizes
    bsd.control(2, setup(0x00, 9, 1))
    bsd.control(2, setup(0x80, 6, 0x0300, 0, 4), b'\x04\x03\x09\x04')
    bsd.control(2, setup(0x40, 6, 0, 0, 6), out_data=b'abcdef')  # OUT: setup frame then a data frame
    bsd.xfer(2, 0x81, BULK, b'freebsd bulk in')
    bsd.xfer(2, 0x02, BULK, b'freebsd bulk out')
    bsd.xfer(2, 0x83, INT, b'\x01\x02\x03')
    # isochronous: frames with and without data
    bsd.emit(freebsd(FB_SUBMIT, FB_ISO, 0x84, 2, [(FB_FLAG_READ, b'', 96), (FB_FLAG_READ, b'', 96)]))
    bsd.emit(freebsd(FB_COMPLETE, FB_ISO, 0x84, 2, [(FB_FLAG_READ | FB_FLAG_DATA, bytes(range(40)), None), (FB_FLAG_READ, b'', 0)]))
    # high speed device, speed field 3
    hcfg = hcfg0
    # the same sequences again with other speed settings
    for dev, sp in ((3, 3), (4, 1), (5, 4), (6, 0)):
        cf = hcfg if sp in (3, 4, 0) else fcfg
        ocf = fcfg if sp == 3 else hcfg0
        if sp == 1:
            cf = freebsd_config([(3, 8), (3, 8)])
            ocf = cf
        d = dev_desc(mps=64 if sp == 3 else 8 if sp == 1 else 9)
        for utype, frs in ((FB_SUBMIT, [(FB_FLAG_DATA, setup(0x80, 6, 0x0100, 0, 18), None)]),):
            bsd.emit(freebsd(utype, FB_CTRL, 0, dev, frs, speed=sp, xferstatus=FB_ST_CONTROL_HDR | 1))
        bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, d, None)], speed=sp))
        bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, dev, [(FB_FLAG_DATA, setup(0x80, 6, 0x0200, 0, len(cf)), None)], speed=sp,
                         xferstatus=FB_ST_CONTROL_HDR | 1))
        bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, cf, None)], speed=sp))
        bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, dev, [(FB_FLAG_DATA, setup(0x80, 6, 0x0700, 0, len(ocf)), None)], speed=sp,
                         xferstatus=FB_ST_CONTROL_HDR | 1))
        bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, ocf, None)], speed=sp))
    # device qualifier of a high speed device (the speed is swapped for the other speed)
    dq = struct.pack('<BBHBBBBBB', 10, 6, 0x0200, 0, 0, 0, 8, 1, 0)
    bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, 3, [(FB_FLAG_DATA, setup(0x80, 6, 0x0600, 0, 10), None)], speed=3, xferstatus=FB_ST_CONTROL_HDR | 1))
    bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, 3, [(FB_FLAG_DATA, dq, None)], speed=3))
    bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, 2, [(FB_FLAG_DATA, setup(0x80, 6, 0x0600, 0, 10), None)], speed=2, xferstatus=FB_ST_CONTROL_HDR | 1))
    bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, 2, [(FB_FLAG_DATA, struct.pack('<BBHBBBBBB', 10, 6, 0x0200, 0, 0, 0, 64, 1, 0), None)], speed=2))
    # a data stage frame of a control transfer without CONTROL_HDR flag, and a transfer with an unknown type
    bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, 2, [(FB_FLAG_DATA, b'datastage', None)], xferstatus=1))
    bsd.emit(freebsd(FB_SUBMIT, 9, 0x81, 2, [(FB_FLAG_DATA, b'unknown', None)]))
    # reproducer of the empty composite assert: two zero length data frames
    z = [(FB_FLAG_DATA, b'', 0), (FB_FLAG_DATA, b'', 0)]
    bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, 7, z, xferstatus=FB_ST_CONTROL_HDR))
    bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, 7, z))
    mark(w, 'FreeBSD (4)', s0)

    # ------------------------------------------------------------ macOS
    s0 = w.count
    mac = Bus(w, 'mac', if_mac, bus=5)
    loc = 0x05100000
    mac.get_desc(2, 1, 0, dev_desc(vid=0x05ac, pid=0x12a8)[:8], 8)
    mac.get_desc(2, 1, 0, dev_desc(vid=0x05ac, pid=0x12a8), 18)
    mcfg = cfg_desc(if_desc(0, 0, 3, 0xff, 0, 0) + ep_desc(0x81, 2, 64) + ep_desc(0x02, 2, 64) + ep_desc(0x83, 1, 192, 1), nif=1)
    mac.get_desc(2, 2, 0, mcfg, len(mcfg))
    mac.control(2, setup(0x00, 9, 1))
    mac.control(2, setup(0x40, 6, 0, 0, 3), out_data=b'abc')
    mac.xfer(2, 0x81, BULK, b'macos bulk in')
    mac.xfer(2, 0x02, BULK, b'macos bulk out')
    mac.xfer(2, 0x83, INT, b'\x09\x08')
    # isochronous: submit with frame headers (20 octets), completion with data (28 octet headers)
    f0 = darwin_frame(20, 0, 0, 1) + darwin_frame(20, 0, 0, 2)
    mac.emit(darwin(0, 1, 0x83, 2, 48, num_iso=2, data=f0))
    f1 = darwin_frame(28, 24, 0, 1, 111, bytes(range(24))) + darwin_frame(28, 24, 0xe00002e7, 2, 222, bytes(range(24, 48)))
    mac.emit(darwin(1, 1, 0x83, 2, 48, num_iso=2, data=f1))
    mac.emit(darwin(0, 9, 0x85, 2, 8, data=b'unknown type'))
    mac.emit(darwin(1, 3, 0x83, 2, 2, status=0xe00002d6, data=b''))
    mark(w, 'macOS (5)', s0)

    # ------------------------------------------------------------ USB/IP
    s0 = w.count
    t = Tcp()
    devid = (6 << 16) | 2

    def usbip(c, data):
        w.pkt(if_eth, t.seg(c, data))

    seq = 1
    # control IN GET_DESCRIPTOR(device)
    usbip(True, usbip_submit(seq, devid, 1, 0, length=18, setup_b=setup(0x80, 6, 0x0100, 0, 18)))
    usbip(False, usbip_ret(seq, data=dev_desc()))
    seq += 1
    usbip(True, usbip_submit(seq, devid, 1, 0, length=len(mcfg), setup_b=setup(0x80, 6, 0x0200, 0, len(mcfg))))
    usbip(False, usbip_ret(seq, data=mcfg))
    seq += 1
    # control OUT with data
    usbip(True, usbip_submit(seq, devid, 0, 0, data=b'abc', setup_b=setup(0x40, 6, 0, 0, 3)))
    usbip(False, usbip_ret(seq))
    seq += 1
    # bulk and interrupt
    usbip(True, usbip_submit(seq, devid, 1, 1, length=64))
    usbip(False, usbip_ret(seq, data=b'usbip bulk in'))
    seq += 1
    usbip(True, usbip_submit(seq, devid, 0, 2, data=b'usbip bulk out'))
    usbip(False, usbip_ret(seq))
    seq += 1
    usbip(True, usbip_submit(seq, devid, 1, 3, length=8, interval=4))
    usbip(False, usbip_ret(seq, data=b'\x01\x02'))
    seq += 1
    # isochronous IN: descriptors follow the data
    ids = struct.pack('!IIII', 0, 96, 24, 0) + struct.pack('!IIII', 24, 96, 24, 0) + struct.pack('!IIII', 48, 96, 0, 0xffffffed & 0xffffffff)
    usbip(True, usbip_submit(seq, devid, 1, 3, length=288, npk=3, start_frame=5, iso=struct.pack('!IIII', 0, 96, 0, 0) * 3))
    usbip(False, usbip_ret(seq, data=bytes(range(48)), npk=3, iso=ids))
    seq += 1
    # isochronous OUT
    usbip(True, usbip_submit(seq, devid, 0, 4, data=bytes(range(32)), npk=2,
                             iso=struct.pack('!IIII', 0, 16, 16, 0) + struct.pack('!IIII', 16, 16, 16, 0)))
    usbip(False, usbip_ret(seq, npk=2, iso=struct.pack('!IIII', 0, 16, 16, 0) + struct.pack('!IIII', 16, 16, 16, 0)))
    seq += 1
    # unlink
    usbip(True, usbip_submit(seq, devid, 1, 1, length=64))
    seq += 1
    usbip(True, usbip_unlink(seq, devid, 1, 1, seq - 1))
    usbip(False, usbip_ret_unlink(seq))
    seq += 1
    # reply with an error status: USB is not dissected
    usbip(True, usbip_submit(seq, devid, 1, 1, length=64))
    usbip(False, usbip_ret(seq, status=0xffffffed & 0xffffffff))
    mark(w, 'USB/IP (6)', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    if_bsd = w.idb(LT_USB_FREEBSD)
    if_mac = w.idb(LT_USB_DARWIN)
    mm = Bus(w, 'mm', if_mm, bus=1)
    # configuration descriptor with an invalid descriptor length (2), with a length past the end,
    # with an SS companion in front of an endpoint, a bad string descriptor, and so on
    c = cfg_desc(if_desc(0, 0, 1, 0xff, 0, 0) + bytes([2, 5]) + b'\0' * 7, nif=1)
    mm.get_desc(2, 2, 0, c, len(c))
    c = cfg_desc(if_desc(0, 0, 1, 0xff, 0, 0) + bytes([200, 5]) + b'\0' * 7, nif=1)
    mm.get_desc(2, 2, 0, c, len(c))
    c = cfg_desc(if_desc(0, 0, 1, 0xff, 0, 0) + ep_companion() + ep_desc(0x81, 2, 64) + ep_desc(0x82, 2, 64, extra=b'\0\0')
                 + ep_desc(0x83, 2, 64) + ep_companion(0, 0, 0, 9), nif=1)
    mm.get_desc(2, 2, 0, c, len(c))
    mm.get_desc(2, 3, 5, bytes([1, 3]), 255)                           # string descriptor, bLength 1
    mm.get_desc(2, 3, 5, bytes([0, 3]), 255)
    mm.get_desc(2, 3, 6, bytes([5, 3, 0x41, 0, 0x42]), 255)           # odd length
    mm.get_desc(2, 3, 0, bytes([5, 3, 0x09, 0x04, 0x07]), 255)
    # BOS: too short capability, unexpected descriptor type, truncated capability
    bad = struct.pack('<BBHB', 5, 0x0f, 5 + 5 + 8 + 2, 3) + bytes([5, 0x04, 0, 0, 0]) + bytes([8, 0x10, 2, 0, 0, 0, 0, 7]) + bytes([2, 0x10])
    mm.get_desc(3, 0x0f, 0, bad, len(bad))
    # bulk setup flag set on a non-control URB
    mm.emit(linux(b'S', BULK, 0x02, 4, 1, 0x1111, setup(0, 0, 0, 0, 0), b'x', 1))
    mm.emit(linux(b'C', BULK, 0x02, 4, 1, 0x1111, None, b'', 1))
    # unknown transfer type
    mm.emit(linux(b'S', 7, 0x02, 4, 1, 0x1112, None, b'zz', 2))
    # isochronous packets whose descriptors do not fit
    mm.emit(linux(b'C', ISO, 0x87, 4, 1, 0x1113, None, b'', 96, descs=[(0, 0, 24), (0, 24, 4000)], iso_data=b'short'))
    # speeds that make the packet size checks fail
    bsd = Bus(w, 'bsd', if_bsd, bus=4)
    for dev, sp, eps in ((2, 1, [(2, 64), (1, 8), (3, 64)]), (3, 2, [(2, 100), (2, 7), (3, 100), (1, 1100), (2, 20)]),
                         (4, 3, [(2, 100), (3, 1100), (3, 0x0e00), (1, 0x1400), (3, 0x0a00), (1, 0x0200), (1, 0x0a00), (3, 0x1800)]),
                         (5, 1, [(1, 8), (3, 16), (2, 8)])):
        cf = freebsd_config(eps)
        d = dev_desc(mps=9 if sp != 3 else 8)
        bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, dev, [(FB_FLAG_DATA, setup(0x80, 6, 0x0100, 0, 18), None)], speed=sp, xferstatus=FB_ST_CONTROL_HDR | 1))
        bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, d, None)], speed=sp))
        bsd.emit(freebsd(FB_SUBMIT, FB_CTRL, 0, dev, [(FB_FLAG_DATA, setup(0x80, 6, 0x0200, 0, len(cf)), None)], speed=sp, xferstatus=FB_ST_CONTROL_HDR | 1))
        bsd.emit(freebsd(FB_COMPLETE, FB_CTRL, 0, dev, [(FB_FLAG_DATA, cf, None)], speed=sp))
    # USBPcap: unknown transfer type; too many isochronous packets; truncated packets
    pc = Bus(w, 'pcap', if_pc, bus=3)
    pc.emit(usbpcap(0, 3, 1, 0x81, 0xff, 0x7001, None, b'', datalen=0))
    pc.emit(usbpcap(1, 3, 1, 0x84, ISO, 0x7002, None, b'', iso=(0, 0, []), datalen=0)[:27] + struct.pack('<III', 0, 200000, 0))
    # truncated FreeBSD packets (cut inside the frames) and macOS packets
    full = freebsd(FB_COMPLETE, FB_CTRL, 0, 2, [(FB_FLAG_DATA, b'abcdefgh', None)])
    w.pkt(if_bsd, full[:136])
    # Darwin: iso frame header length shorter than 20, frame header length larger than the data
    mac = Bus(w, 'mac', if_mac, bus=5)
    mac.emit(darwin(1, 1, 0x83, 2, 48, num_iso=2, data=darwin_frame(28, 99, 0, 3, 5, b'short')))  # frame length larger than the data
    mac.emit(darwin(1, 1, 0x83, 2, 48, num_iso=2, data=struct.pack('<IIIQ', 12, 8, 0, 1) + b'\0' * 12))
    mac.emit(darwin(1, 1, 0x83, 2, 48, num_iso=2, data=struct.pack('<IIIQ', 4000, 8, 0, 1) + b'\0' * 20))
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-22s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

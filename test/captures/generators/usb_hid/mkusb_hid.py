#!/usr/bin/env python3
# Generates test/captures/usb_hid_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the USB HID coverage captures. Usage: mkusb_hid.py <outdir>
# Linux usbmon records (LINKTYPE_USB_LINUX_MMAPPED) plus Exported PDU
# records in one pcapng; built with struct, nothing comes from a real device.
#   usb-hid-coverage.pcapng            main capture
#   usb-hid-coverage-malformed.pcapng  paths only malformed input reaches
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


# ---- report descriptor items --------------------------------------------
MAIN, GLOBAL, LOCAL = 0, 1, 2
SIZES = {0: 0, 1: 1, 2: 2, 4: 3}


def item(typ, tag, data=b''):
    return bytes([(tag << 4) | (typ << 2) | SIZES[len(data)]]) + data


def uval(v, size=None):
    if size is None:
        size = 1 if v < 0x100 else 2 if v < 0x10000 else 4
    return v.to_bytes(size, 'little')


def sval(v, size):
    return v.to_bytes(size, 'little', signed=True)


def usage_page(v, size=None): return item(GLOBAL, 0, uval(v, size))
def log_min(v, size=1): return item(GLOBAL, 1, sval(v, size))
def log_max(v, size=1): return item(GLOBAL, 2, sval(v, size))
def phy_min(v, size=1): return item(GLOBAL, 3, sval(v, size))
def phy_max(v, size=1): return item(GLOBAL, 4, sval(v, size))
def unit_exp(v): return item(GLOBAL, 5, uval(v))
def unit(v, size=1): return item(GLOBAL, 6, uval(v, size))
def rsize(v): return item(GLOBAL, 7, uval(v))
def rid(v): return item(GLOBAL, 8, uval(v))
def rcount(v, size=None): return item(GLOBAL, 9, uval(v, size))
def push(d=b''): return item(GLOBAL, 10, d)
def pop(d=b''): return item(GLOBAL, 11, d)
def usage(v, size=None): return item(LOCAL, 0, uval(v, size))
def usage_min(v, size=None): return item(LOCAL, 1, uval(v, size))
def usage_max(v, size=None): return item(LOCAL, 2, uval(v, size))
def inp(v=2, size=1): return item(MAIN, 8, uval(v, size))
def outp(v=2, size=1): return item(MAIN, 9, uval(v, size))
def feat(v=2, size=1): return item(MAIN, 11, uval(v, size))
def coll(v): return item(MAIN, 10, uval(v))
def endc(): return item(MAIN, 12)


# Input/Output flag values
VAR_ABS, VAR_REL, CONST, ARRAY = 2, 6, 1, 0

# generic mouse: three buttons, padding, X, Y and wheel
DESC_MOUSE = (usage_page(1) + usage(2) + coll(1) + usage(1) + coll(0) +
              usage_page(9) + usage_min(1) + usage_max(3) + log_min(0) + log_max(1) +
              rcount(3) + rsize(1) + inp(VAR_ABS) +
              rcount(1) + rsize(5) + inp(CONST) +
              usage_page(1) + usage(0x30) + usage(0x31) + usage(0x38) +
              log_min(-127) + log_max(127) + rsize(8) + rcount(3) + inp(VAR_REL) +
              endc() + endc())

# every Generic Desktop usage the dissector knows, 16 bit values, plus a hat switch
DESC_AXES = (usage_page(1) + usage(4) + coll(1) +
             usage(0x30) + usage(0x31) + usage(0x32) + usage(0x33) + usage(0x34) +
             usage(0x35) + usage(0x36) + usage(0x40) + usage(0x41) + usage(0x42) +
             usage(0x43) + usage(0x44) + usage(0x45) + usage(0x46) +
             log_min(-32768, 2) + log_max(32767, 2) + rsize(16) + rcount(14) + inp(VAR_ABS) +
             usage(0x39) + log_min(0) + log_max(7) + rsize(4) + rcount(1) + inp(VAR_ABS) +
             rsize(4) + rcount(1) + inp(CONST) +
             # extended usages (page and id in one item) as buttons
             usage_min(0x00090001, 4) + usage_max(0x00090004, 4) +
             log_min(0) + log_max(1) + rsize(1) + rcount(4) + inp(VAR_ABS) +
             rsize(4) + rcount(1) + inp(CONST) +
             endc())

# keyboard with report IDs: modifiers, array of keys, LEDs, consumer, vendor
DESC_KBD = (usage_page(1) + usage(6) + coll(1) +
            rid(1) +
            usage_page(7) + usage_min(0xe0) + usage_max(0xe7) + log_min(0) + log_max(1) +
            rsize(1) + rcount(8) + inp(VAR_ABS) +
            rcount(1) + rsize(8) + inp(CONST) +
            usage_min(0) + usage_max(0x65) + log_min(0) + log_max(0x65) +
            rsize(8) + rcount(6) + inp(ARRAY) +
            usage_page(8) + usage_min(1) + usage_max(5) + log_min(0) + log_max(1) +
            rsize(1) + rcount(5) + outp(VAR_ABS) +
            rsize(3) + rcount(1) + outp(CONST) +
            rid(2) +
            usage_page(0x0c) + usage_min(0) + usage_max(0x3ff) + log_min(1, 2) + log_max(0x3ff, 2) +
            rsize(16) + rcount(2) + inp(ARRAY) +
            rid(3) +
            usage_page(0xff00, 2) + usage(1) + usage(2) + log_min(0) + log_max(255, 2) +
            rsize(8) + rcount(4) + inp(VAR_ABS) +
            usage(1) + usage(2) + usage(3) + rcount(2) + inp(VAR_ABS) +
            rsize(0) + rcount(1) + inp(VAR_ABS) +
            usage_page(9) + usage(1) + usage(0) + usage(4) + rsize(1) + rcount(3) + outp(VAR_ABS) +
            rsize(5) + rcount(1) + outp(CONST) +
            endc())

# 32 bit report size, the largest allowed
DESC_WIDE = (usage_page(1) + usage(1) + coll(1) + usage(0x30) +
             log_min(-2147483648, 4) + log_max(2147483647, 4) + rsize(32) + rcount(1) + inp(VAR_REL) +
             feat(VAR_ABS) + endc())

# the usage pages with a usage or two each
PAGES = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
         0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x40, 0x41, 0x59, 0x80, 0x81,
         0x82, 0x84, 0x85, 0x8c, 0x8d, 0x8e, 0x90, 0x91, 0xf1d0, 0xff00, 0xff99, 0x7777]
IDS = {0x09: (0x00, 0x01, 0x04, 0x11), 0x0a: (0, 5), 0x0c: (1, 0x30, 0x7fff),
       0x0e: (1, 0x2002), 0x10: (0x41, 0x1234), 0x20: (1, 0x1b, 0x47, 0x7d, 0x1234),
       0x81: (1, 0x1234), 0x01: (2, 0x30, 0xffff)}


def tour_descriptor():
    d = b''
    for p in PAGES:
        d += usage_page(p)
        for i in IDS.get(p, (1, 0x1234)):
            d += usage(i)
    return d


# every item type and size, including reserved tags and a long item
DESC_ITEMS = (usage_page(1) + usage(2) + coll(1) +
              # collection types
              coll(0) + endc() + coll(2) + endc() + coll(3) + endc() + coll(4) + endc() +
              coll(5) + endc() + coll(6) + endc() + coll(0x10) + endc() + coll(0x85) + endc() +
              # global items with different sizes
              usage_page(0x1234, 2) + usage_page(7, 4) + usage_page(9, 1) +
              log_min(-1, 1) + log_min(-300, 2) + log_max(300, 2) + log_max(70000, 4) +
              phy_min(-10, 1) + phy_min(-1000, 2) + phy_max(10, 1) + phy_max(1000, 2) +
              unit_exp(0) + unit_exp(7) + unit_exp(0xe) + unit(0x13) + unit(0x01010011, 4) +
              rsize(8) + rid(0x5a) + rcount(2) + rcount(300) +
              push() + push(b'\x01') + pop() + pop(b'\x02') +
              item(GLOBAL, 12, b'\x01') + item(GLOBAL, 15) +
              # local items
              usage(1) + usage(0x1234, 2) + usage(0x00090002, 4) +
              usage_min(1) + usage_max(3) + item(LOCAL, 3, b'\x01') + item(LOCAL, 4, b'\x01') +
              item(LOCAL, 5, b'\x02') + item(LOCAL, 7, b'\x03') + item(LOCAL, 8, b'\x04') +
              item(LOCAL, 9, b'\x05') + item(LOCAL, 10, b'\x01') + item(LOCAL, 6, b'\x06') +
              item(LOCAL, 11, b'\x07') +
              # main items: every flag, 1 and 2 byte, output, feature, reserved tags
              inp(0x00) + inp(0x7f) + inp(0x1ff, 2) + inp(0x80) + inp(0x100, 2) +
              outp(0x00) + outp(0xff) + outp(0x1ff, 2) + feat(0x00) + feat(0xff) + feat(0x1ff, 2) +
              item(MAIN, 0, b'\x01') + item(MAIN, 13, b'\x01') + item(MAIN, 15) +
              # long item (prefix 0xfe, length, tag, data) and a reserved item type
              bytes([0xfe, 0, 0x42]) +
              endc())

# parse failures: each one leaves the descriptor unusable (not stored)
FAIL = {
    'no logical limits': usage_page(1) + usage(1) + rsize(8) + rcount(1) + inp(),
    'usage before usage page': usage(1) + log_min(0) + log_max(1) + rsize(1) + rcount(1) + inp(),
    'usage page too large': usage_page(0x10000, 4),
    'logical minimum of 3 bytes': usage_page(1) + bytes([0x16, 1, 2, 3]) + bytes([0x17, 1, 2, 3, 4]),
    'report id after an item': usage_page(1) + usage(1) + log_min(0) + log_max(1) + rsize(1) + rcount(1) + inp() + rid(1),
    'push': usage_page(1) + push(),
    'pop': usage_page(1) + pop(),
    'unknown local item': usage_page(1) + item(LOCAL, 3, b'\x01'),
    'long item (reserved type)': bytes([0xfe, 0, 0x42]),
    'usage maximum without minimum': usage_page(1) + usage_max(3),
    'usage maximum without a usage page': usage_min(0x00090001, 4) + usage_max(3),
    'extended minimum, plain maximum': usage_min(0x00090001, 4) + usage_max(3),
    'plain minimum, extended maximum': usage_page(9) + usage_min(1) + usage_max(0x00090003, 4),
    'minimum and maximum on different pages': usage_min(0x00090001, 4) + usage_max(0x000a0003, 4),
    'minimum above maximum': usage_page(9) + usage_min(5) + usage_max(2),
    'report size 33': usage_page(1) + usage(1) + log_min(0) + log_max(1) + rsize(33) + rcount(1) + inp(),
    'report size 65 (reproducer)': usage_page(1) + usage(0x30) + log_min(0) + log_max(1) + rsize(65) + rcount(1) + inp(),
    'output report size 40': usage_page(1) + usage(1) + log_min(0) + log_max(1) + rsize(40) + rcount(1) + outp(),
    'array bits wrap (reproducer)': usage_page(1) + usage(0x30) + log_min(0) + log_max(1) + rsize(33) + rcount(0xf07c1f08, 4) + inp(ARRAY),
    'size times count above 64 KiB': usage_page(1) + usage(1) + log_min(0) + log_max(1) + rsize(32) + rcount(16384, 2) + inp(),
    'reserved item type': bytes([0xfc]),
    'too many usages (reproducer)': (usage_page(1) + log_min(0) + log_max(1) + rsize(1) + rcount(1) +
                                     (usage_min(0, 2) + usage_max(0xffff, 2) + inp()) * 3),
    'too many single usages': (usage_page(1) + log_min(0) + log_max(1) + rsize(1) + rcount(1) +
                               (usage_min(0, 2) + usage_max(0xffff, 2) + inp()) * 2 + usage(1)),
    'logical minimum without data': usage_page(1) + item(GLOBAL, 1),
    'logical maximum without data': usage_page(1) + log_min(0) + item(GLOBAL, 2),
    'output without logical limits': usage_page(1) + usage(1) + rsize(8) + rcount(1) + outp(),
    'usage minimum without a usage page': usage_min(1),
    'failure after an output item': (usage_page(1) + usage(1) + log_min(0) + log_max(1) + rsize(1) +
                                     rcount(1) + outp() + inp() + push()),
}


def nested(n):
    return usage_page(1) + usage(2) + b''.join(coll(1) for _ in range(n)) + b''.join(endc() for _ in range(n))


class Hid:
    """a HID device with an interface 0 (class 3), interrupt IN 0x81 and OUT 0x01"""
    def __init__(self, ng, addr, desc=b'', sub=0, proto=0, vid=0x1234, pid=0x5678, extra_desc=False):
        self.ng, self.c, self.addr = ng, ng.cap, addr
        usbmon_helper.DEV = addr
        self.c.enumerate(bcd=0x0100, vid=vid, pid=pid)
        ndesc = 2 if extra_desc else 1
        hid = struct.pack('<BBHBBBH', 6 + 3 * ndesc, 0x21, 0x0111, 33, ndesc, 0x22, len(desc))
        if extra_desc:
            hid += struct.pack('<BH', 0x23, 8)
        intf = bytes([9, 4, 0, 0, 2, 3, sub, proto, 0])
        body = intf + hid + bytes([7, 5, 0x81, 3, 0x40, 0, 10]) + bytes([7, 5, 0x01, 3, 0x40, 0, 10])
        cfg = struct.pack('<BBHBBBBB', 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body
        self.control(bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', 255), cfg)

    def control(self, setup, resp=b'', out_data=b''):
        usbmon_helper.DEV = self.addr
        self.c.control(setup, resp, out_data)

    def report_descriptor(self, desc):
        self.control(bytes([0x81, 6, 0, 0x22, 0, 0]) + struct.pack('<H', len(desc)), desc)

    def get_descriptor(self, typ, resp):
        self.control(bytes([0x81, 6, 0, typ, 0, 0]) + struct.pack('<H', len(resp)), resp)

    def intr_in(self, data):
        usbmon_helper.DEV = self.addr
        c = self.c
        c.id += 1
        c._rec(c.id, b'S', 1, 0x81, None, b'', 64)
        c._rec(c.id, b'C', 1, 0x81, None, data, len(data))

    def intr_out(self, data):
        usbmon_helper.DEV = self.addr
        c = self.c
        c.id += 1
        c._rec(c.id, b'S', 1, 0x01, None, data, len(data))
        c._rec(c.id, b'C', 1, 0x01, None, b'', len(data))

    def get_report(self, typ, rid_, data):
        self.control(bytes([0xa1, 1, rid_, typ, 0, 0]) + struct.pack('<H', len(data)), data)

    def set_report(self, typ, rid_, data):
        self.control(bytes([0x21, 9, rid_, typ, 0, 0]) + struct.pack('<H', len(data)), b'', data)

    def class_req(self, rt, req, val, ln, resp=b''):
        self.control(bytes([rt, req]) + struct.pack('<HHH', val, 0, ln), resp)


def main_capture():
    ng = Capng()
    # Exported PDU: boot protocol reports, which the Bluetooth ATT dissector
    # hands to these dissectors, and the HID dissectors without a USB URB
    for mods in (0x00, 0x01, 0x22, 0xff):
        ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes([mods, 0, 4, 5, 0x39, 0xe0, 0, 0]))
    ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes([0x04, 0, 0, 0, 0, 0, 0, 0]))
    ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes([0x05, 0, 4, 5, 6, 7, 8, 9]))
    ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes([0x00, 0, 0, 0, 0, 0, 0xff, 0xff]))
    ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes(8))
    for leds in (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff):
        ng.exp_pdu('usbhid.boot_report.keyboard.output', bytes([leds]))
    for b in (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0x05):
        ng.exp_pdu('usbhid.boot_report.mouse.input', bytes([b, 3, 0xfd]))
    ng.exp_pdu('usbhid.boot_report.mouse.input', bytes([1, 2, 3, 0xff]))
    ng.exp_pdu('usbhid.boot_report.mouse.input', bytes([1, 2, 3, 0xff, 1]))
    ng.exp_pdu('usbhid.boot_report.mouse.input', bytes([1, 2, 3, 0xff, 1, 0xaa, 0xbb]))
    hid_desc = struct.pack('<BBHBBBH', 9, 0x21, 0x0111, 33, 1, 0x22, 52)
    ng.exp_pdu('usbhid.class_descriptors', hid_desc)
    ng.exp_pdu('usbhid.class_descriptors', struct.pack('<BBHBBBHBH', 12, 0x21, 0x0110, 0, 2, 0x22, 52, 0x23, 8))
    ng.exp_pdu('usbhid.class_descriptors', bytes([9, 0x22, 0, 0, 0, 0, 0, 0, 0]))   # not a HID descriptor
    ng.exp_pdu('usbhid.data', bytes([1, 2, 3]))
    ng.exp_pdu('usbhid.control', bytes([1, 2, 3]))

    # a mouse: report descriptor, reports, class requests
    d = Hid(ng, 2, DESC_MOUSE, sub=1, proto=2, extra_desc=True)
    d.get_descriptor(0x21, struct.pack('<BBHBBBH', 9, 0x21, 0x0111, 0, 1, 0x22, len(DESC_MOUSE)))
    d.control(bytes([0x81, 0, 0, 0, 0, 0, 2, 0]), b'\0\0')          # GET_STATUS to the interface
    d.report_descriptor(DESC_MOUSE)
    d.intr_in(bytes([0x01, 5, 0xfb, 1]))
    d.intr_in(bytes([0x06, 0x80, 0x7f, 0xff]))
    d.intr_in(bytes([0x00, 0, 0, 0]))
    d.get_report(1, 0, bytes([0x07, 1, 1, 0]))                      # GET_REPORT response is decoded
    d.class_req(0xa1, 1, 0x0100, 4)                                 # GET_REPORT with no data
    d.set_report(2, 0, bytes([0x01]))                               # SET_REPORT (no output fields)
    d.class_req(0xa1, 2, 0x0000, 1, bytes([0]))                     # GET_IDLE: indefinite
    d.class_req(0xa1, 2, 0x0000, 1, bytes([125]))                   # GET_IDLE: 500 ms
    d.class_req(0x21, 0x0a, 0x7d00, 0)                              # SET_IDLE
    d.class_req(0xa1, 3, 0, 1, bytes([1]))                          # GET_PROTOCOL: report protocol
    d.class_req(0xa1, 3, 0, 1, bytes([0]))                          # boot protocol
    d.class_req(0x21, 0x0b, 1, 0)                                   # SET_PROTOCOL
    d.class_req(0xa1, 4, 0, 1, bytes([0]))                          # reserved request: not decoded here
    d.class_req(0xc1, 0x20, 0, 4, bytes([1, 0, 0, 0]))              # vendor request: HID data only with Decode As
    d.control(bytes([0x21, 0x0b, 1, 0, 0, 0, 0, 0]))                # SET_PROTOCOL, again without the helper
    # a second descriptor on the same interface replaces the first
    d.report_descriptor(DESC_MOUSE)
    d.intr_in(bytes([0x02, 1, 1, 1]))

    # axes
    d = Hid(ng, 3, DESC_AXES)
    d.report_descriptor(DESC_AXES)
    rep = b''.join(struct.pack('<h', v) for v in range(-7, 7)) + bytes([0x35, 0x0a])
    d.intr_in(rep)
    d.intr_in(bytes(len(rep)))

    # keyboard with report IDs
    d = Hid(ng, 4, DESC_KBD, sub=1, proto=1)
    d.report_descriptor(DESC_KBD)
    d.intr_in(bytes([1, 0x02, 0, 4, 5, 6, 0, 0, 0]))                 # shift + keys
    d.intr_in(bytes([1, 0x00, 0, 0, 0, 0, 0, 0, 0]))                 # all keys up
    d.intr_in(bytes([2, 0xe9, 0x00, 0x00, 0x00]))                 # consumer: usage 0x00e8 then no control
    d.intr_in(bytes([2, 0x01, 0x00, 0xff, 0x7f]))                 # in range, out of range
    d.intr_in(bytes([3, 1, 2, 3, 4, 5, 6, 7, 8]))                 # vendor data
    d.intr_in(bytes([9, 1, 2, 3]))                                # unknown report ID
    d.intr_out(bytes([1, 0x03]))                                  # LEDs (output report)
    d.intr_out(bytes([3, 0x05]))                                  # output buttons of report 3
    d.set_report(2, 1, bytes([1, 0x04]))                          # SET_REPORT with the LEDs
    d.get_report(1, 1, bytes([1, 0x80, 0, 4, 0, 0, 0, 0, 0]))        # GET_REPORT response with the keys

    # all usage pages, in the descriptor only
    tour = tour_descriptor()
    d = Hid(ng, 5, tour)
    d.report_descriptor(tour)
    d.intr_in(bytes([1, 2, 3]))

    # every item type, size, flag and a long item
    d = Hid(ng, 6, DESC_ITEMS)
    d.report_descriptor(DESC_ITEMS)
    d.intr_in(bytes([1, 2, 3]))

    # the largest allowed report size and nesting just under the limit
    d = Hid(ng, 7, DESC_WIDE)
    d.report_descriptor(DESC_WIDE)
    d.intr_in(struct.pack('<i', -5))
    d.intr_in(struct.pack('<i', 2147483647))
    d.report_descriptor(nested(31))
    d.report_descriptor(nested(32))
    d.report_descriptor(nested(33))                                # reaches the limit: an expert info
    d.report_descriptor(nested(36))                                # reproducer of the recursion

    # descriptors the report parser refuses: reports stay raw
    d = Hid(ng, 8, b'')
    for name, desc in FAIL.items():
        d.report_descriptor(desc)
        d.intr_in(bytes([1, 2, 3, 4]))
    ng.write('usb-hid-coverage.pcapng')


def malformed_capture():
    ng = Capng()
    d = Hid(ng, 2, b'')
    usbmon_helper.DEV = 2
    ng.cap.id += 1
    ng.cap._rec(ng.cap.id, b'C', 2, 0x80, None, b'\x01\x02', 2)       # control response without a request
    d.report_descriptor(DESC_MOUSE[:-3])                           # cut inside an item
    d.report_descriptor(bytes([0x05]))                             # item without its data
    d.report_descriptor(bytes([0xfe, 3, 0x42, 1, 2, 3]))           # long item with data (taken for short items)
    d.report_descriptor(bytes([0xfe, 9, 0x42, 1]))                 # long item cut short
    d.report_descriptor(bytes([0xa0, 0x00, 0xa1]))                 # collection data cut short
    d.report_descriptor(usage_page(1) + bytes([0x75]))             # report size without data
    d.report_descriptor(bytes([0x1b, 1]))                          # unit with four bytes cut
    d.report_descriptor(bytes([0x85]))
    # reports shorter than the descriptor with fields that run past the end
    d.report_descriptor(DESC_MOUSE)
    d.intr_in(bytes([1]))
    d.intr_in(b'')
    d.report_descriptor(DESC_MOUSE)
    d.intr_in(bytes([0x02]))                                       # report shorter than the descriptor
    d3 = Hid(ng, 3, DESC_KBD)
    d3.report_descriptor(DESC_KBD)
    d3.intr_in(bytes([1, 2]))
    d3.intr_in(bytes([2, 1]))
    d3.intr_in(bytes([3, 1]))
    d3.set_report(2, 1, b'')
    d3.class_req(0xa1, 2, 0, 1)                                    # GET_IDLE response missing
    d3.class_req(0xa1, 3, 0, 1)
    d3.control(bytes([0x81, 6, 0, 0x22, 0, 0, 5, 0]), DESC_MOUSE[:5])
    ng.exp_pdu('usbhid.boot_report.keyboard.input', bytes([1]))    # boot reports cut short
    ng.exp_pdu('usbhid.boot_report.keyboard.input', b'')
    ng.exp_pdu('usbhid.boot_report.keyboard.output', b'')
    ng.exp_pdu('usbhid.boot_report.mouse.input', bytes([1]))
    ng.exp_pdu('usbhid.boot_report.mouse.input', b'')
    ng.exp_pdu('usbhid.class_descriptors', bytes([9]))
    ng.exp_pdu('usbhid.class_descriptors', struct.pack('<BBHBBBH', 12, 0x21, 0x0110, 0, 9, 0x22, 52))
    ng.write('usb-hid-coverage-malformed.pcapng')


main_capture()
malformed_capture()

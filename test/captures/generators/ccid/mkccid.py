#!/usr/bin/env python3
# Generates test/captures/ccid_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the USB CCID coverage captures. Usage: mkccid.py <outdir>
# Linux usbmon captures (LINKTYPE_USB_LINUX_MMAPPED); built with struct,
# nothing comes from a real device.
#   ccid-coverage.pcap            main capture
#   ccid-coverage-malformed.pcap  paths only malformed input reaches
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import usbmon_helper
from usbmon_helper import Cap

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def ccid_desc(bcd=0x0110, maxslot=3, volt=7, protos=3, defclk=4000, maxclk=8000, nclk=0,
              rate=10752, maxrate=344064, nrate=0, ifsd=254, synch=0, mech=0,
              feat=0x000207b2, maxmsg=271, getresp=0, envelope=0, lcd=0x0204, pin=3,
              busy=1):
    d = struct.pack('<BBHBBIIIBIIBIIIIIBBHBB', 54, 0x21, bcd, maxslot, volt, protos,
                    defclk, maxclk, nclk, rate, maxrate, nrate, ifsd, synch, mech,
                    feat, maxmsg, getresp, envelope, lcd, pin, busy)
    assert len(d) == 54, len(d)
    return d


def config(extra, eps=True):
    body = bytes([9, 4, 0, 0, 3, 0x0b, 0, 0, 0]) + extra
    if eps:
        body += bytes([7, 5, 0x02, 2, 0x40, 0, 0])      # bulk OUT
        body += bytes([7, 5, 0x81, 2, 0x40, 0, 0])      # bulk IN
        body += bytes([7, 5, 0x83, 3, 0x08, 0, 8])      # interrupt IN
    return struct.pack('<BBHBBBBB', 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body


def setup_device(c, dev, vid=0x08e6, pid=0x3437, cfgbody=None):
    usbmon_helper.DEV = dev
    c.enumerate(bcd=0x0100, vid=vid, pid=pid)
    cfg = config(cfgbody)
    c.control(bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(cfg)), cfg)


def out(c, msg, ep=0x02):
    c.id += 1
    c._rec(c.id, b'S', 3, ep, None, msg, len(msg))
    c._rec(c.id, b'C', 3, ep, None, b'', len(msg))


def inn(c, msg, ep=0x81):
    c.id += 1
    c._rec(c.id, b'S', 3, ep, None, b'', 271)
    c._rec(c.id, b'C', 3, ep, None, msg, len(msg))


def intr(c, msg, ep=0x83):
    c.id += 1
    c._rec(c.id, b'S', 1, ep, None, b'', 8)
    c._rec(c.id, b'C', 1, ep, None, msg, len(msg))


def hdr(t, ln, slot, seq, b7=0, b8=0, b9=0):
    return struct.pack('<BIBBBBB', t, ln, slot, seq, b7, b8, b9)


def main_capture():
    c = Cap()
    setup_device(c, 2, cfgbody=ccid_desc())
    # PC to reader
    t0 = bytes([0x11, 0x00, 0x00, 0x0a, 0x00])
    out(c, hdr(0x61, 5, 0, 1, 0, 0, 0) + t0)                       # SetParameters T=0
    out(c, hdr(0x61, 0, 0, 2, 0, 0, 0))                            # T=0, no data structure
    t1 = bytes([0x11, 0x10, 0x00, 0x4d, 0x00, 0xfe, 0x00])
    out(c, hdr(0x61, 7, 0, 3, 1, 0, 0) + t1)                       # SetParameters T=1
    out(c, hdr(0x61, 4, 0, 4, 0x80, 0, 0) + b'\x01\x02\x03\x04')   # 2-wire: data
    for i, volt in enumerate((0, 1, 2, 3)):
        out(c, hdr(0x62, 0, i, 5 + i, volt, 0, 0))                 # IccPowerOn
    out(c, hdr(0x63, 0, 0, 9))                                     # IccPowerOff
    out(c, hdr(0x65, 0, 0, 10))                                    # GetSlotStatus
    out(c, hdr(0x6c, 0, 0, 11))                                    # GetParameters
    apdu = bytes.fromhex('00a4040007a0000000041010')
    out(c, struct.pack('<BIBBBH', 0x6f, len(apdu), 0, 12, 5, 0x0100) + apdu)   # XfrBlock
    out(c, struct.pack('<BIBBBH', 0x6f, 0, 0, 13, 0, 0))           # XfrBlock without data
    esc = bytes.fromhex('0102030405')
    out(c, struct.pack('<BIBB3s', 0x6b, len(esc), 0, 14, b'\0\0\0') + esc)     # Escape
    out(c, struct.pack('<BIBB3s', 0x6b, 0, 0, 15, b'\1\2\3'))      # Escape, no data
    for t, seq in ((0x69, 16), (0x6a, 17), (0x6d, 18), (0x6e, 19), (0x71, 20), (0x72, 21), (0x73, 22)):
        out(c, hdr(t, 0, 0, seq))                                  # messages without a decoding
    # reader to PC
    atr = bytes.fromhex('3b8f8001804f0ca000000306030001000000006a')
    inn(c, struct.pack('<BIBBBBB', 0x80, len(atr), 0, 5, 0x00, 0, 0) + atr)     # DataBlock, ICC active
    inn(c, struct.pack('<BIBBBBB', 0x80, 2, 0, 12, 0x40, 0xfe, 1) + b'\x6a\x82')  # failed, chained
    inn(c, struct.pack('<BIBBBBB', 0x80, 0, 0, 13, 0x80, 0, 0))                  # time extension, no data
    inn(c, struct.pack('<BIBBBBB', 0x81, 0, 0, 10, 0x01, 0, 0))                  # SlotStatus, inactive, running
    inn(c, struct.pack('<BIBBBBB', 0x81, 0, 1, 10, 0x02, 0, 1))                  # no ICC, stopped in L
    inn(c, struct.pack('<BIBBBBB', 0x81, 0, 1, 10, 0x03, 0, 2))                  # RFU, stopped in H
    inn(c, struct.pack('<BIBBBBB', 0x81, 0, 1, 10, 0x00, 0, 3))                  # unknown stopped
    inn(c, struct.pack('<BIBBBBB', 0x82, 5, 0, 1, 0, 0, 0) + t0)                 # Parameters T=0
    inn(c, struct.pack('<BIBBBBB', 0x82, 0, 0, 2, 0, 0, 0))                      # T=0, no structure
    inn(c, struct.pack('<BIBBBBB', 0x82, 7, 0, 3, 0, 0, 1) + t1)                 # T=1
    inn(c, struct.pack('<BIBBBBB', 0x82, 3, 0, 4, 0, 0, 0x80) + b'\x01\x02\x03') # other structure
    inn(c, struct.pack('<BIBBBBB', 0x83, 3, 0, 14, 0, 0, 0) + b'abc')            # Escape response
    inn(c, struct.pack('<BIBBBBB', 0x83, 0, 0, 15, 0, 0, 0))                     # no data
    # interrupt IN: slot change (Decode As is needed) and hardware error
    intr(c, bytes([0x50, 0xff]))              # one byte: slots 0-3 all present and changed
    intr(c, bytes([0x50, 0x03, 0xff]))        # two state bytes: slots 0-3 and slots 4-7
    intr(c, bytes([0x50, 0x00]))
    intr(c, bytes([0x51, 0x00, 0x07, 0x2a]))  # hardware error
    # second reader: other descriptors in the interface (not a CCID descriptor),
    # a CCID descriptor with a list of clocks and without LCD, other values
    setup_device2(c)
    c.write(os.path.join(OUT, 'ccid-coverage.pcap'))


def setup_device2(c):
    usbmon_helper.DEV = 3
    c.enumerate(bcd=0x0100, vid=0x04e6, pid=0xe003)
    other = bytes([5, 0x24, 1, 0x10, 0x01]) + ccid_desc(maxslot=0, volt=0, protos=1, nclk=2, nrate=3,
                                                       feat=0x00010010, lcd=0, pin=0, busy=0, maxmsg=65538)
    cfg = config(other)
    c.control(bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(cfg)), cfg)
    out(c, hdr(0x65, 0, 0, 1))
    inn(c, hdr(0x81, 0, 0, 1, 0, 0, 0))


def malformed_capture():
    c = Cap()
    setup_device(c, 2, cfgbody=ccid_desc())
    out(c, b'\x62')                                  # one byte: header cut short
    out(c, hdr(0x61, 5, 0, 1, 0, 0, 0)[:8])          # SetParameters cut short
    out(c, hdr(0x61, 7, 0, 3, 1, 0, 0) + b'\x11\x10') # T=1 structure cut short
    out(c, hdr(0x6f, 100, 0, 3, 0, 0, 0) + b'abcd')  # data shorter than dwLength
    inn(c, hdr(0x80, 0xffffffff, 0, 3, 0, 0, 0) + b'abcd')   # dwLength far beyond the data
    inn(c, hdr(0x82, 7, 0, 3, 0, 0, 1) + b'\x11\x10')        # T=1 structure cut short
    inn(c, hdr(0x82, 0, 0, 3, 0, 0, 0)[:9])
    intr(c, bytes([0x50]))                           # notification without the state byte
    intr(c, bytes([0x51, 0x00]))                     # hardware error cut short
    c.write(os.path.join(OUT, 'ccid-coverage-malformed.pcap'))
    # a descriptor cut short
    c = Cap()
    usbmon_helper.DEV = 4
    c.enumerate(bcd=0x0100, vid=0x08e6, pid=0x3437)
    cfg = config(ccid_desc()[:30], eps=False)
    c.control(bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(cfg)), cfg)
    c.write(os.path.join(OUT, 'ccid-coverage-malformed2.pcap'))


main_capture()
malformed_capture()

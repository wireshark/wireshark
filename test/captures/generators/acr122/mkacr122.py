#!/usr/bin/env python3
# Generates test/captures/acr122_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
# Generate the ACR122 coverage captures. Usage: mkacr122.py <outdir>
# Linux usbmon (LINKTYPE_USB_LINUX_MMAPPED) with USB CCID bulk transfers
# whose payload is ACR122 APDUs; built with struct, nothing comes from a
# real device.  ACR122 is reached through "Decode As" of
# usbccid.subdissector (the only way to reach it).
#   acr122-coverage.pcap            main capture
#   acr122-coverage-malformed.pcap  paths only malformed input reaches
import os, struct, sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
import usbmon_helper
from usbmon_helper import Cap

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
EPO, EPI = 0x02, 0x82


def ccid_desc():
    # CCID class descriptor (54 bytes), values of no interest
    return struct.pack('<BBHBBIIIBIIBIIIIIBBHBB', 54, 0x21, 0x0100, 0, 7, 2,
                       4000, 4000, 0, 10752, 10752, 0, 254, 0, 0,
                       0x00010030, 271, 0, 0, 0, 0, 1)


def config():
    body = bytes([9, 4, 0, 0, 2, 0x0b, 0, 0, 0]) + ccid_desc()
    body += bytes([7, 5, EPO, 2, 0x40, 0, 0])
    body += bytes([7, 5, EPI, 2, 0x40, 0, 0])
    return struct.pack('<BBHBBBBB', 9, 2, 9 + len(body), 1, 1, 0, 0x80, 50) + body


def setup_device(c, dev):
    usbmon_helper.DEV = dev
    c.enumerate(bcd=0x0100, vid=0x072f, pid=0x2200)
    cfg = config()
    c.control(bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(cfg)), cfg)


class Dev:
    def __init__(self, c, dev):
        self.c, self.dev, self.seq = c, dev, 0
        setup_device(c, dev)

    def _bulk(self, typ_out, ep, msg):
        c = self.c
        usbmon_helper.DEV = self.dev
        c.id += 1
        if typ_out:
            c._rec(c.id, b'S', 3, ep, None, msg, len(msg))
            c._rec(c.id, b'C', 3, ep, None, b'', len(msg))
        else:
            c._rec(c.id, b'S', 3, ep, None, b'', 271)
            c._rec(c.id, b'C', 3, ep, None, msg, len(msg))

    def cmd(self, apdu, ep=EPO):
        """PC_to_RDR_XfrBlock"""
        self.seq = (self.seq + 1) & 0xff
        self._bulk(True, ep, struct.pack('<BIBBBH', 0x6F, len(apdu), 0, self.seq, 0, 0) + apdu)

    def rsp(self, data, ep=EPI):
        """RDR_to_PC_DataBlock"""
        self._bulk(False, ep, struct.pack('<BIBBBBB', 0x80, len(data), 0, self.seq, 0, 0, 0) + data)

    def xchg(self, apdu, data, ep_o=EPO, ep_i=EPI):
        self.cmd(apdu, ep_o)
        self.rsp(data, ep_i)


OK = b'\x90\x00'


def a(*b):
    return bytes(b)


def pn532(*b):
    return bytes(b)


def main_capture():
    c = Cap()
    d = Dev(c, 3)
    # Get Firmware Version (the reproducer: response on 0x82, command on 0x02)
    d.xchg(a(0xFF, 0x00, 0x48, 0x00, 0x00), b'ACR122U201')
    # Get Data UID / ATS (ATS must not be taken for UID)
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x04, 0xA1, 0xB2, 0xC3) + OK)
    d.xchg(a(0xFF, 0xCA, 0x01, 0x00, 0x00), a(0x3B, 0x80, 0x80, 0x01, 0x01) + OK)
    # Load Authentication Keys
    d.xchg(a(0xFF, 0x82, 0x00, 0x01, 0x06, 1, 2, 3, 4, 5, 6), OK)
    d.xchg(a(0xFF, 0x82, 0x20, 0x00, 0x06, 6, 5, 4, 3, 2, 1), a(0x63, 0x00))
    # Authentication (obsolete): FF 88 00 <block> <key type> <key number>
    d.xchg(a(0xFF, 0x88, 0x00, 0x04, 0x60, 0x01), OK)
    # Authentication
    d.xchg(a(0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00), OK)
    # Read Binary Blocks
    d.xchg(a(0xFF, 0xB0, 0x00, 0x04, 0x10), bytes(range(16)) + OK)
    # Update Binary Blocks
    d.xchg(a(0xFF, 0xD6, 0x00, 0x04, 0x10) + bytes(range(0x20, 0x30)), OK)
    # Value Block Operation (store, inc, dec)
    for op, val in ((0x00, 5), (0x01, 10), (0x02, 3)):
        d.xchg(a(0xFF, 0xD7, 0x00, 0x05, 0x05, op) + struct.pack('>i', val), OK)
    # Read Value Block (the Read Value Block reproducer: response is
    # matched, the value is skipped and the status word is read at offset 4)
    d.xchg(a(0xFF, 0xB1, 0x00, 0x04, 0x04), struct.pack('>i', 5) + OK)
    d.xchg(a(0xFF, 0xB1, 0x00, 0x05, 0x04), struct.pack('>i', -7) + a(0x63, 0x00))
    # Restore Value Block
    d.xchg(a(0xFF, 0xD7, 0x00, 0x04, 0x02, 0x03, 0x05), OK)
    # Direct Transmit (PN532 GetFirmwareVersion, InListPassiveTarget)
    d.xchg(a(0xFF, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x02), a(0xD5, 0x03, 0x32, 0x01, 0x06, 0x07) + OK)
    d.xchg(a(0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x4A, 0x01, 0x00), a(0xD5, 0x4B, 0x00) + OK)
    d.xchg(a(0xFF, 0x00, 0x00, 0x00, 0x00), OK)             # no data
    d.xchg(a(0xFF, 0x00, 0x00, 0x00, 0x02, 0xD4, 0x02), OK)  # response of just the status word
    # Bi-Color and Buzzer LED control (several P2 values)
    for p2, sw in ((0x00, 0x00), (0xFF, 0x03), (0x5A, 0x02), (0xA5, 0x01)):
        d.xchg(a(0xFF, 0x00, 0x40, p2, 0x04, 0x01, 0x01, 0x03, 0x01), a(0x90, sw))
    # Get / Set PICC Operating Parameter
    d.xchg(a(0xFF, 0x00, 0x50, 0x00, 0x00), a(0x90, 0xFF))
    d.xchg(a(0xFF, 0x00, 0x51, 0xFF, 0x00), a(0x90, 0x55))
    d.xchg(a(0xFF, 0x00, 0x51, 0x00, 0x00), a(0x90, 0x00))
    # Set Timeout Parameter: 0, 0xff, < 12, >= 12
    for t in (0x00, 0xFF, 0x03, 0x0B, 0x0C, 0x18):
        d.xchg(a(0xFF, 0x00, 0x41, t, 0x00), OK)
    # Set Buzzer Output for Card Detection
    d.xchg(a(0xFF, 0x00, 0x52, 0xFF, 0x00), OK)
    d.xchg(a(0xFF, 0x00, 0x52, 0x00, 0x00), OK)
    # Status words: error classes, 61xx (length), unknown
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x61, 0x08))
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x63, 0x00))
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x6A, 0x81))
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x12, 0x34))
    # Unknown commands (a class other than 0xFF, an unknown instruction)
    d.xchg(a(0x00, 0xA4, 0x04, 0x00, 0x00), a(0x6D, 0x00))
    d.xchg(a(0xFF, 0x7F, 0x00, 0x00, 0x00), a(0x6D, 0x00))
    # A command answered twice: the second response is not matched
    d.cmd(a(0xFF, 0x00, 0x48, 0x00, 0x00))
    d.rsp(b'ACR122U202')
    d.rsp(b'ACR122U202')
    # A response before any command on another device
    d2 = Dev(c, 4)
    d2.rsp(OK)
    d2.xchg(a(0xFF, 0x00, 0x48, 0x00, 0x00), b'ACR122U203')
    # Responses on the same endpoint number as the command
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), a(0x01, 0x02, 0x03, 0x04) + OK, EPO, EPO)
    # Command sent twice, then one response: matched to the later one
    d.cmd(a(0xFF, 0xCA, 0x01, 0x00, 0x00))
    d.cmd(a(0xFF, 0xCA, 0x00, 0x00, 0x00))
    d.rsp(a(0x01, 0x02, 0x03, 0x04) + OK)
    # Responses too short for the status word / the value (expert info)
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), b'\x90')
    d.xchg(a(0xFF, 0xB1, 0x00, 0x04, 0x04), b'\x00\x01')
    c.write(os.path.join(OUT, 'acr122-coverage.pcap'))


def malformed_capture():
    c = Cap()
    d = Dev(c, 3)
    d.cmd(a(0xFF, 0x00, 0x48))                       # APDU shorter than 5 bytes
    d.cmd(a(0xFF, 0xB0, 0x00, 0x04, 0x10))           # Lc/Le of 0x10, no data: item beyond the end
    d.cmd(a(0xFF, 0x88, 0x00, 0x04, 0x60))           # obsolete auth without the key number
    d.cmd(a(0xFF, 0xD6, 0x00, 0x04, 0x10) + b'\x01')  # update, data truncated
    d.cmd(a(0xFF, 0x82, 0x00, 0x01, 0x06, 1, 2))      # short key
    d.cmd(a(0xFF, 0xD7, 0x00, 0x05, 0x05, 0x00, 0x01))  # short value
    d.cmd(a(0xFF, 0x00, 0x40, 0x00, 0x04, 0x01))      # short LED control
    d.cmd(a(0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4))      # direct transmit short
    d.cmd(a(0xFF, 0x86, 0x00, 0x00, 0x05, 0x01))      # short auth
    d.cmd(a(0xFF, 0xD7, 0x00, 0x04, 0x02, 0x03))      # short restore
    d.cmd(a(0xFF, 0x88, 0x00, 0x04, 0x01, 0x60))      # short obsolete auth
    # responses
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), b'\x90')           # status word too short
    d.xchg(a(0xFF, 0xCA, 0x00, 0x00, 0x00), b'\x90')
    d.xchg(a(0xFF, 0xCA, 0x01, 0x00, 0x00), b'')
    d.xchg(a(0xFF, 0xB0, 0x00, 0x04, 0x10), b'\x90')
    d.xchg(a(0xFF, 0xB1, 0x00, 0x04, 0x04), b'\x00\x01')
    d.xchg(a(0xFF, 0x00, 0x41, 0x01, 0x00), b'\x90')
    c.write(os.path.join(OUT, 'acr122-coverage-malformed.pcap'))


main_capture()
malformed_capture()

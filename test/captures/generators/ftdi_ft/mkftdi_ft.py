#!/usr/bin/env python3
# Generates test/captures/ftdi_ft_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the FTDI FT coverage captures (Linux usbmon, LINKTYPE 220).

ftdi-ft-coverage.pcap            devices of all chip types, every vendor request
                                 and response, serial traffic on four interfaces,
                                 bit-bang, MPSSE and MCU traffic, reassembly
ftdi-ft-coverage-malformed.pcap  paths that need malformed input
Usage: mkftdi_ft.py <outdir>
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from ftdi_usbmon import Cap

# bcdDevice values (chip identification)
FT8U232AM, FT232B, FT2232D, FT232R, FT2232H, FT4232H, FT232H, XSERIES = 0x0200, 0x0400, 0x0500, 0x0600, 0x0700, 0x0800, 0x0900, 0x1000


def status(modem=0x60, line=0x00):
    return bytes([modem, line])


def main_capture():
    c = Cap()

    # ---- Device 2: FT2232H, vendor requests --------------------------------
    c.enumerate(FT2232H, dev=2)
    # Reset: purge RX and TX (0), RX (1), TX (2), port A and B
    c.request(0x00, 0x0000, 1, dev=2)
    c.request(0x00, 0x0001, 1, dev=2)
    c.request(0x00, 0x0002, 2, dev=2)
    # ModemCtrl: DTR and RTS, set and clear
    c.request(0x01, 0x0101, 1, dev=2)
    c.request(0x01, 0x0202, 1, dev=2)
    c.request(0x01, 0x0303, 2, dev=2)
    c.request(0x01, 0x0000, 2, dev=2)
    # SetFlowCtrl: none, RTS/CTS, DTR/DSR, XON/XOFF with the characters
    c.request(0x02, 0x1311, 0x0001, dev=2)
    c.request(0x02, 0x1311, 0x0101, dev=2)
    c.request(0x02, 0x1311, 0x0201, dev=2)
    c.request(0x02, 0x1311, 0x0401, dev=2)
    # SetBaudRate (FT2232H: port in the low index byte, bits in the high byte)
    c.request(0x03, 0x4138, 0x0001, dev=2)
    c.request(0x03, 0x4138, 0x0302, dev=2)
    # SetData: 8N1, 7E1, 8O2 with break, 8 mark, 8 space
    c.request(0x04, 0x0008, 1, dev=2)
    c.request(0x04, 0x0207, 1, dev=2)
    c.request(0x04, 0x5108, 2, dev=2)
    c.request(0x04, 0x0308, 2, dev=2)
    c.request(0x04, 0x0408, 2, dev=2)
    # GetModemStat: the status bits, then with the high speed bit and other bits
    c.request(0x05, 0, 1, resp=b'\x01\x60', dev=2)
    c.request(0x05, 0, 1, resp=b'\xb2\x7e', dev=2)
    # SetEventChar, SetErrorChar
    c.request(0x06, 0x017f, 1, dev=2)
    c.request(0x06, 0x0000, 1, dev=2)
    c.request(0x07, 0x0100, 1, dev=2)
    c.request(0x07, 0x0000, 2, dev=2)
    # Latency timer
    c.request(0x09, 16, 1, dev=2)
    c.request(0x0A, 0, 1, resp=b'\x10', dev=2)
    c.request(0x0A, 0, 1, resp=b'\x10\xee', dev=2)        # one byte more than expected
    # GetPins
    c.request(0x0C, 0, 1, resp=b'\xa5', dev=2)
    # EEPROM
    c.request(0x90, 0, 0x0003, resp=b'\x03\x04', dev=2)
    c.request(0x91, 0x1234, 0x0004, dev=2)
    c.request(0x92, 0, 0, dev=2)
    # A request that is not known, with and without a response
    c.request(0x55, 0x0102, 0x0304, dev=2)
    c.request(0x56, 0, 0, resp=b'\x01\x02\x03', dev=2)
    # A vendor request to the interface and a class request are not for this dissector
    c.request(0x01, 0x0101, 1, rtype=0x41, dev=2)
    c.control(struct.pack('<BBHHH', 0x21, 0x22, 3, 0, 0), dev=2)
    # SetBitMode on a request of the wrong length
    c.request(0x0B, 0x0000, 1, dev=2, wlength=0)

    # ---- every chip: SetBaudRate and a status/serial exchange ---------------
    chips = [(3, FT8U232AM, 1), (4, FT8U232AM, 0), (5, FT232B, 0), (6, 0x0300, 0), (7, FT2232D, 0),
             (8, FT232R, 0), (9, FT4232H, 0), (10, FT232H, 0), (11, XSERIES, 0), (12, FT232B, 0)]
    for dev, bcd, iserial in chips:
        c.enumerate(bcd, iserial=iserial, dev=dev)
        c.request(0x03, 0x4138, 0x0002, dev=dev)
        c.request(0x03, 0xc009, 0x0100, dev=dev)
        c.bulk_out(b'AT\r\n', ep=0x02, dev=dev)
        c.bulk_in(b'OK\r\n', ep=0x81, dev=dev)

    # ---- unknown response: a device whose request was not captured ----------
    c.enumerate(FT232R, dev=13)
    c.control(struct.pack('<BBHHH', 0xC0, 0x05, 0, 1, 2), b'\x01\x60', dev=13, with_submit=False)

    # ---- serial traffic on device 2, A and B --------------------------------
    c.bulk_out(b'Hello, serial world\r\n', ep=0x02, dev=2)
    c.bulk_in(b'Hello back\r\n', ep=0x81, dev=2)
    c.bulk_in(b'', ep=0x81, dev=2)                                   # only the status bytes
    c.bulk_in(b'status change', ep=0x81, status=status(0xf0, 0x7e), dev=2)
    # full speed: 64 byte packets (62 data octets) and a short one
    c.bulk_in_raw((status(0x31) + bytes(range(62))) * 2 + status(0x31) + b'tail', ep=0x81, dev=2)
    # high speed: 512 byte packets
    c.bulk_in_raw(status(0x32) + bytes([0x41 + i % 26 for i in range(510)]) + status(0x32) + b'second', ep=0x81, dev=2)
    c.bulk_out(b'port B transmit', ep=0x04, dev=2)
    c.bulk_in(b'port B receive', ep=0x83, dev=2)
    c.bulk_out(b'', ep=0x02, dev=2)                                  # an empty TX URB
    # an endpoint that is not an FTDI data endpoint, and an unknown one
    c.bulk_out(b'ignored', ep=0x0a, dev=2)

    # ---- device 9 (FT4232H): interfaces C and D -----------------------------
    c.bulk_out(b'port C out', ep=0x06, dev=9)
    c.bulk_in(b'port C in', ep=0x85, dev=9)
    c.bulk_out(b'port D out', ep=0x08, dev=9)
    c.bulk_in(b'port D in', ep=0x87, dev=9)

    # bit-bang mode on ports C and D of the FT4232H (the interface comes from the request index)
    c.set_bitmode(0x01, 3, 0xff, dev=9)
    c.bulk_out(bytes([1, 2, 3]), ep=0x06, dev=9)
    c.set_bitmode(0x01, 4, 0xff, dev=9)
    c.bulk_out(bytes([4, 5, 6]), ep=0x08, dev=9)
    c.bulk_in(bytes([7]), ep=0x87, dev=9)

    # ---- bit-bang mode: payload is not decoded -------------------------------
    c.set_bitmode(0x01, 1, 0xff, dev=2)
    c.bulk_out(bytes([0x00, 0x55, 0xaa, 0xff]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x00, 0x55]), ep=0x81, dev=2)
    c.set_bitmode(0x00, 1, 0x00, dev=2)                               # back to serial
    c.bulk_out(b'serial again', ep=0x02, dev=2)

    # ---- MPSSE on port A of device 2 ----------------------------------------
    c.set_bitmode(0x02, 1, 0xff, dev=2)
    c.bulk_out(bytes([0x80, 0x08, 0x0b, 0x86, 0x05, 0x00, 0x87]), ep=0x02, dev=2)
    c.bulk_out(bytes([0x81, 0x83]), ep=0x02, dev=2)
    c.bulk_in(bytes([0x5a, 0xa5]), ep=0x81, dev=2)
    c.bulk_out(bytes([0x20, 0x03, 0x00]), ep=0x02, dev=2)
    c.bulk_in(bytes([1, 2, 3, 4]), ep=0x81, dev=2)
    # Bad command, then the response of the device
    c.bulk_out(bytes([0xaa, 0x87]), ep=0x02, dev=2)
    c.bulk_in(bytes([0xfa, 0xaa]), ep=0x81, dev=2)

    # --- reassembly -------------------------------------------------------------
    # (1) Reproducer of the assertion in the reassembly code ("FTDI FT: Fix assertion in
    # reassembly and repeated state updates"): Bad Command 0x00 on TX, then RX FA and RX FA
    # (MPSSE asks for reassembly at offset 1 of FA FA), then the real response FA 00
    c.set_bitmode(0x02, 2, 0xff, dev=2)
    c.bulk_out(bytes([0x00]), ep=0x04, dev=2)
    c.bulk_in(bytes([0xfa]), ep=0x83, dev=2)
    c.bulk_in(bytes([0xfa]), ep=0x83, dev=2)
    c.bulk_in(bytes([0x00]), ep=0x83, dev=2)
    # (2) A command with parameters split over three TX URBs, and a command that
    # ends one reassembly and starts another in the same URB
    c.set_bitmode(0x02, 1, 0xff, dev=9)
    c.bulk_out(bytes([0x31, 0x03]), ep=0x02, dev=9)                  # 0x31: length and data are missing
    c.bulk_out(bytes([0x00, 0xaa]), ep=0x02, dev=9)                  # length known, 3 of 4 data bytes missing
    c.bulk_out(bytes([0xbb, 0xcc, 0xdd, 0x31, 0x01]), ep=0x02, dev=9)  # ends the first, starts a second
    c.bulk_out(bytes([0x00, 0x11, 0x22, 0x87]), ep=0x02, dev=9)      # ends the second, then Send Immediate
    c.bulk_in(bytes([9, 8, 7, 6]), ep=0x81, dev=9)
    c.bulk_in(bytes([1, 2]), ep=0x81, dev=9)
    # (3) A response split over two RX URBs
    c.bulk_out(bytes([0x2c, 0x04, 0x00, 0x87]), ep=0x02, dev=9)
    c.bulk_in(bytes([0x10, 0x11, 0x12]), ep=0x81, dev=9)
    c.bulk_in(bytes([0x13, 0x14]), ep=0x81, dev=9)

    # (4) Reproducer "MPSSE: 2pass_cmd": Read Low Byte, a partial 0x31, then its end
    c.enumerate(FT2232H, dev=14)
    c.set_bitmode(0x02, 1, 0xff, dev=14)
    c.bulk_out(bytes([0x81, 0x31, 0x03, 0x00, 0xAA]), ep=0x02, dev=14)
    c.bulk_out(bytes([0xBB, 0xCC, 0xDD]), ep=0x02, dev=14)

    # MCU host bus emulation mode
    c.set_bitmode(0x08, 2, 0xff, dev=14)
    c.bulk_out(bytes([0x92, 0x10, 0x55, 0x93, 0x01, 0x02, 0x99, 0x90, 0x10, 0x91, 0x01, 0x02]), ep=0x04, dev=14)
    c.bulk_in(bytes([0x42, 0x43]), ep=0x83, dev=14)

    # Repeated SetBitMode requests: only the first pass records them
    c.set_bitmode(0x00, 1, 0x00, dev=14)
    c.set_bitmode(0x01, 1, 0x0f, dev=14)
    c.set_bitmode(0x04, 1, 0x0f, dev=14)
    c.set_bitmode(0x10, 1, 0x0f, dev=14)
    c.set_bitmode(0x20, 1, 0x0f, dev=14)
    c.set_bitmode(0x40, 1, 0x0f, dev=14)
    c.set_bitmode(0x80, 1, 0x0f, dev=14)
    c.set_bitmode(0x02, 5, 0xff, dev=14)                               # an interface that does not exist
    c.set_bitmode(0x02, 0, 0xff, dev=14)                               # "any interface" is port A
    return c


def reproducers():
    """Reproducers of the review (kept separate for the README)"""
    return []


def malformed_capture():
    c = Cap()
    # (a) reproducer "MPSSE: len_wrap": Clock Data Bytes In with length 0xFFFF
    c.enumerate(FT2232H, dev=2)
    c.set_bitmode(0x02, 1, 0xff, dev=2)
    c.bulk_out(bytes([0x20, 0xff, 0xff]), ep=0x02, dev=2)
    # (b) reproducer "MPSSE: prelim_stale": re-enumerated as another chip
    c.enumerate(FT2232H, dev=3)
    c.set_bitmode(0x02, 1, 0xff, dev=3)
    c.bulk_out(bytes([0x81, 0x31, 0x03, 0x00, 0xAA]), ep=0x02, dev=3)
    c.enumerate(FT2232D, dev=3)
    c.bulk_out(bytes([0xBB, 0xCC, 0xDD]), ep=0x02, dev=3)
    c.enumerate(FT2232H, dev=3)
    c.bulk_out(bytes([0x81]), ep=0x02, dev=3)
    # (c) control responses shorter than the data the dissector reads
    c.request(0x05, 0, 1, resp=b'\x01', dev=2)          # GetModemStat: one octet
    c.request(0x90, 0, 3, resp=b'\x03', dev=2)          # ReadEEPROM: one octet
    c.request(0x0A, 0, 1, resp=b'', dev=2, wlength=1)   # GetLatTimer: no data
    c.request(0x0C, 0, 1, resp=b'', dev=2, wlength=1)   # GetPins: no data
    # (d) a bulk IN URB with one octet only (shorter than the two status octets)
    c.bulk_in_raw(b'\x01', ep=0x81, dev=2)
    # (e) two status octets claiming a full speed packet, then nothing
    c.bulk_in_raw(b'\x31\x00', ep=0x81, dev=2)
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    main_capture().write(os.path.join(out, 'ftdi-ft-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'ftdi-ft-coverage-malformed.pcap'))

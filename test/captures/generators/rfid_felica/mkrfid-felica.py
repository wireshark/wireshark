#!/usr/bin/env python3
# Generates test/captures/rfid_felica_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the Sony FeliCa coverage captures (packet-rfid-felica.c).

Usage: mkrfid-felica.py [-v] [outdir]   (writes rfid-felica-coverage.pcap and
rfid-felica-coverage-malformed.pcap, usbmon DLT 220, built with struct only).

FeliCa has no port of its own; PN532 hands it its payload. By default that is
the five octets of an InListPassiveTarget request (BrTy FeliCa 212/424 kbps);
all other frames are InCommunicateThru payloads that PN532 only passes on with
the preference pn532.prtype532:felica. PN532 itself is reached through PN532
HCI on a USB bulk endpoint of device 04e6:5591, so the capture starts with
the GET_DESCRIPTOR(DEVICE) exchange that names that device. Nothing here comes
from a real network or device.
"""
# ---- USB (usbmon, DLT 220) helpers shared by the PN532 family generators ----
import struct
import sys
import os

class Cap:
    """Collects raw frames and writes a classic pcap with the given link type."""
    def __init__(self, linktype, snaplen=262144):
        self.lt = linktype; self.snap = snaplen; self.frames = []; self.t = 1700000000.0
    def add(self, data, dt=0.001):
        self.t += dt
        self.frames.append((self.t, bytes(data)))
        return len(self.frames)
    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, self.snap, self.lt))
            for t, p in self.frames:
                s = int(t); us = int((t - s) * 1e6)
                f.write(struct.pack("<IIII", s, us, len(p), len(p)) + p)

def usbhdr(urb_id, typ, xfer, ep, length, caplen, setup=b"\0" * 8, dev=1, bus=1, flag_setup=None, flag_data=0):
    """64-byte usbmon header (DLT 220). typ 'S' submit or 'C' complete."""
    if flag_setup is None:
        flag_setup = ord('-')
    return struct.pack("<QBBBBHBBqiiII8siiII", urb_id, ord(typ), xfer, ep, dev, bus,
                       flag_setup, flag_data, 0, 0, 0 if typ == 'C' else -115,
                       length, caplen, setup, 0, 0, 0, 0)

class Usb:
    """One USB device (bus 1, address 1) with a given VID:PID."""
    def __init__(self, cap, vid=0x04e6, pid=0x5591):
        self.cap = cap; self.vid = vid; self.pid = pid; self.urb = 0
    def descriptor(self):
        self.urb += 1
        setup = struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, 18)
        self.cap.add(usbhdr(self.urb, 'S', 2, 0x80, 18, 0, setup, flag_setup=0, flag_data=ord('<')))
        desc = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, self.vid, self.pid, 0x0100, 0, 0, 0, 1)
        return self.cap.add(usbhdr(self.urb, 'C', 2, 0x80, 18, 18, setup, flag_setup=ord('-')) + desc)
    def out(self, data, ep=0x02):
        """Host to device bulk transfer (submit)."""
        self.urb += 1
        return self.cap.add(usbhdr(self.urb, 'S', 3, ep, len(data), len(data)) + data)
    def inn(self, data, ep=0x82):
        """Device to host bulk transfer (complete). ep=0x02 gives the same
        endpoint byte as the command, which is the only way PN532 pairs them."""
        self.urb += 1
        return self.cap.add(usbhdr(self.urb, 'C', 3, ep, len(data), len(data)) + data)

# ---- PN532 HCI frames ----
def hci_normal(payload, preamble=b"\x00", postamble=b"\x00", bad_lcs=False, bad_dcs=False):
    l = len(payload)
    lcs = (-l) & 0xff
    dcs = (-sum(payload)) & 0xff
    if bad_lcs: lcs ^= 0x55
    if bad_dcs: dcs ^= 0x55
    return preamble + b"\x00\xff" + bytes([l, lcs]) + payload + bytes([dcs]) + postamble

def hci_ext(payload, preamble=b"\x00", postamble=b"\x00", bad_lcs=False, bad_dcs=False):
    l = len(payload)
    lcs = (-((l >> 8) + (l & 0xff))) & 0xff
    dcs = (-sum(payload)) & 0xff
    if bad_lcs: lcs ^= 0x55
    if bad_dcs: dcs ^= 0x55
    return preamble + b"\x00\xff\xff\xff" + struct.pack(">H", l) + bytes([lcs]) + payload + bytes([dcs]) + postamble

HCI_ACK = b"\x00\x00\xff\x00\xff\x00"
HCI_NACK = b"\x00\x00\xff\xff\x00\x00"
def hci_err(code=0x7f):
    return b"\x00\x00\xff\x01\xff" + bytes([code, (-code) & 0xff, 0x00])
def D4(cmd, data=b""): return bytes([0xd4, cmd]) + data
def D5(cmd, data=b""): return bytes([0xd5, cmd]) + data

# ---- PN532 command exchanges (shared by the PN532 family generators) ----
def exch(u, req, rsp=None, matched=True, **kw):
    """One command (host to PN532, ep 0x02) and its response. matched=True
    sends the response as a completion on the same endpoint byte (0x02), the
    only way the dissector's request/response pairing finds the command."""
    a = u.out(hci_normal(req, **kw))
    b = None
    if rsp is not None:
        b = u.inn(hci_normal(rsp, **kw), ep=0x02 if matched else 0x82)
    return a, b

UID4 = bytes.fromhex("01020304")
NFCID3 = bytes(range(0x30, 0x3a))
NFCID2 = bytes.fromhex("0102030405060708")
PAD = bytes.fromhex("c0c1c2c3c4c5c6c7")

def pn532_basic(u, R):
    """Commands without a payload type (default preference). R records frame ranges."""
    def mark(name, a):
        R.append((name, a))
    # GetFirmwareVersion, GetGeneralStatus
    a, b = exch(u, D4(0x02), D5(0x03, bytes([0x32, 0x01, 0x06, 0x07]))); mark("GetFirmwareVersion", a)
    exch(u, D4(0x04), D5(0x05, bytes([0x00, 0x01, 0x02,  1, 0x00, 0x00, 0x10,  2, 0x01, 0x01, 0x00,  0x00])))
    exch(u, D4(0x04), D5(0x05, bytes([0x2d, 0x00, 0x00, 0x80])), matched=False)
    # Diagnose: every test number, matched and unmatched responses
    exch(u, D4(0x00, bytes([0x00, 0x04]) + b"ping"), D5(0x01, bytes([0x07, 0x00, 0x04]) + b"ping"))
    exch(u, D4(0x00, bytes([0x01, 0x00])), D5(0x01, bytes([0x01, 0x00])))
    exch(u, D4(0x00, bytes([0x02, 0x00])), D5(0x01, bytes([0x01, 0xff])))
    exch(u, D4(0x00, bytes([0x04, 0x01, 0x02])), D5(0x01, bytes([0x01, 0x03])))
    exch(u, D4(0x00, bytes([0x05, 0x03, 0x05, 0x40, 0x41])), D5(0x01, bytes([0x00])))
    exch(u, D4(0x00, bytes([0x06, 0x00])), D5(0x01, bytes([0x01, 0x01])))
    exch(u, D4(0x00, bytes([0x07, 0x01, 0xf3])), D5(0x01, bytes([0x01, 0x00])))
    exch(u, D4(0x00, bytes([0x03, 0x02, 0xaa, 0xbb])), D5(0x01, bytes([0x02, 0xcc, 0xdd])))   # unknown test number
    exch(u, D4(0x00, bytes([0x04, 0x02, 0x02])), D5(0x01), matched=True)                       # empty response
    exch(u, D4(0x00, bytes([0x00, 0x01, 0x55])), D5(0x01, bytes([0x04, 0x00, 0x01, 0x55])), matched=False)  # no request seen
    exch(u, D4(0x00, bytes([0x05, 0x01, 0x05, 0x40, 0x41])), D5(0x01, bytes([0x01, 0x07])))    # test 5 response with extra data
    # Registers
    exch(u, D4(0x06, bytes.fromhex("63016302 6303".replace(" ", ""))), D5(0x07, bytes([0x10, 0x20, 0x30])))
    exch(u, D4(0x06, bytes.fromhex("630163")), D5(0x07))     # odd length address list
    exch(u, D4(0x08, bytes.fromhex("63011263 02 34".replace(" ", ""))), D5(0x09))
    exch(u, D4(0x08, bytes.fromhex("630112 63")), D5(0x09))   # trailing byte
    # GPIO
    exch(u, D4(0x0c), D5(0x0d, bytes([0x28, 0x03, 0x01])))
    exch(u, D4(0x0e, bytes([0x80, 0xff])), D5(0x0f))
    # SetSerialBaudRate, SetParameters
    for br in range(0, 9, 4):
        exch(u, D4(0x10, bytes([br])), D5(0x11))
    for fl in (0x00, 0xff, 0x14):
        exch(u, D4(0x12, bytes([fl])), D5(0x13))
    # SAMConfiguration, PowerDown
    exch(u, D4(0x14, bytes([0x01, 0x00, 0x01])), D5(0x15))
    exch(u, D4(0x14, bytes([0x02, 0x14])), D5(0x15))
    exch(u, D4(0x14, bytes([0x03, 0x0a, 0x00])), D5(0x15))
    exch(u, D4(0x14, bytes([0x04, 0xff, 0x01])), D5(0x15))
    exch(u, D4(0x16, bytes([0xf0, 0x01])), D5(0x17, bytes([0x00])))
    exch(u, D4(0x16, bytes([0x20])), D5(0x17, bytes([0x80 | 0x40 | 0x13])))
    # RFConfiguration: every item, unknown item
    exch(u, D4(0x32, bytes([0x01, 0x03])), D5(0x33))
    exch(u, D4(0x32, bytes([0x02, 0x00, 0x0b, 0x0a])), D5(0x33))
    exch(u, D4(0x32, bytes([0x04, 0x01])), D5(0x33))
    exch(u, D4(0x32, bytes([0x05, 0xff, 0x01, 0x02])), D5(0x33))
    exch(u, D4(0x32, bytes([0x0a]) + bytes(range(1, 12))), D5(0x33))
    exch(u, D4(0x32, bytes([0x0b]) + bytes(range(1, 9))), D5(0x33))
    exch(u, D4(0x32, bytes([0x0c, 0x01, 0x02, 0x03])), D5(0x33))
    exch(u, D4(0x32, bytes([0x0d]) + bytes(range(1, 10))), D5(0x33))
    exch(u, D4(0x32, bytes([0x0e, 0x01, 0x02])), D5(0x33))
    # RF regulation test (response should never happen)
    exch(u, D4(0x58, bytes([0x8a])), D5(0x59))
    exch(u, D4(0x58, bytes([0x00])), D5(0x59, b"\x00"))
    # InJumpForDEP / PSL: passive (106 and 212), active, with all optional parts
    exch(u, D4(0x56, bytes([0x00, 0x00, 0x01]) + UID4), D5(0x57, bytes([0x00, 0x01]) + NFCID3 + bytes([0x00, 0x02, 0x02, 0x0e, 0x00]) + b"G" * 10))
    exch(u, D4(0x56, bytes([0x00, 0x01, 0x07]) + b"\x01\x02\x03\x04\x05" + NFCID3 + b"GI"), D5(0x57, bytes([0x40, 0x01]) + NFCID3 + bytes([0x00, 0x02, 0x02, 0x0e, 0x00]) + b"G" * 10))
    exch(u, D4(0x56, bytes([0x01, 0x02, 0x00])), D5(0x57, bytes([0x00, 0x01]) + NFCID3 + bytes([0x01, 0x01, 0x01, 0x0e, 0x00]) + b"g" * 10))
    exch(u, D4(0x56, bytes([0x00, 0x00, 0x02]) + NFCID3), D5(0x57, bytes([0x00, 0x01]) + NFCID3 + bytes([0x00, 0x00, 0x00, 0x00, 0x00]) + b"G" * 10))
    exch(u, D4(0x56, bytes([0x00, 0x00, 0x04]) + b"general"), D5(0x57, bytes([0x00, 0x01]) + NFCID3 + bytes([0, 0, 0, 0, 0]) + b"G" * 10))
    exch(u, D4(0x46, bytes([0x00, 0x02, 0x03]) + UID4[:0] + b"\x01\x02\x03\x04\x05" + NFCID3), D5(0x47, bytes([0x00, 0x01]) + NFCID3 + bytes([0, 0, 0, 0, 0]) + b"G" * 10))
    exch(u, D4(0x4e, bytes([0x01, 0x02, 0x01])), D5(0x4f, bytes([0x00])))
    # InATR
    exch(u, D4(0x50, bytes([0x01, 0x03]) + NFCID3 + b"GI"), D5(0x51, bytes([0x00]) + NFCID3 + bytes([0x00, 0x02, 0x02, 0x0e, 0x00]) + b"G" * 10))
    exch(u, D4(0x50, bytes([0x01, 0x01]) + NFCID3), D5(0x51, bytes([0x00]) + NFCID3 + bytes([0, 0, 0, 0, 0]) + b"G" * 10))
    exch(u, D4(0x50, bytes([0x02, 0x02]) + b"GI"), D5(0x51, bytes([0x01]) + NFCID3 + bytes([0, 0, 0, 0, 0]) + b"G" * 10))
    exch(u, D4(0x50, bytes([0x01, 0x00])), D5(0x51, bytes([0x2a]) + NFCID3 + bytes([0, 0, 0, 0, 0]) + b"G" * 10))
    # InSelect, InDeselect, InRelease
    for c in (0x54, 0x44, 0x52):
        exch(u, D4(c, bytes([0x01])), D5(c + 1, bytes([0x00])))
    exch(u, D4(0x44, bytes([0x00])), D5(0x45, bytes([0xc1])))        # NAD present, MI, error code
    # InAutoPoll: poll number, period and several types
    exch(u, D4(0x60, bytes([0xff, 0x0f, 0x10, 0x11, 0x03, 0x80])), D5(0x61, bytes([0x00])))
    exch(u, D4(0x60, bytes([0x01, 0x02, 0x00])), D5(0x61, bytes([0x01, 0x20, 0x04]) + b"\x01\x02\x03\x04"))
    exch(u, D4(0x60, bytes([0x01, 0x02, 0x40, 0x41])), D5(0x61, bytes([0x02, 0x10, 0x03]) + b"abc" + bytes([0x23, 0x02]) + b"de"))
    # InAutoPoll response: DEP passive 106, DEP active, FeliCa/non-DEP, two targets
    exch(u, D4(0x60, bytes([0x01, 0x01, 0x40])), D5(0x61, bytes([0x01, 0xc0, 0x04]) + b"data" + NFCID3 + bytes([0x00, 0x02, 0x02, 0x0e, 0x00]) + b"G" * 10))
    exch(u, D4(0x60, bytes([0x01, 0x01, 0x41])), D5(0x61, bytes([0x01, 0x41, 0x00]) + NFCID3 + bytes([0x00, 0x02, 0x02, 0x0e, 0x00]) + b"G" * 10))
    # InCommunicateThru, InDataExchange (data payload), unmatched
    exch(u, D4(0x40, bytes([0x01]) + b"\x30\x04"), D5(0x41, bytes([0x00]) + bytes(range(16))))
    exch(u, D4(0x42, bytes([0x06, 0x00, 0xff, 0xff, 0x01, 0x00])), D5(0x43, bytes([0x00, 0x13, 0x01]) + NFCID2 + PAD))
    exch(u, D4(0x40, bytes([0x02]) + b"\x30\x07"), D5(0x41, bytes([0x14])), matched=False)
    # TgInitAsTarget
    tg = bytes([0x07]) + bytes.fromhex("0400") + bytes.fromhex("010203") + bytes([0x20]) + NFCID2 + PAD + bytes.fromhex("ffff") + NFCID3
    exch(u, D4(0x8c, tg + bytes([0x00, 0x00])), D5(0x8d, bytes([0x26, 0xe0, 0x80])))
    exch(u, D4(0x8c, bytes([0x00]) + tg[1:] + bytes([0x02]) + b"GT" + bytes([0x03]) + b"TKX"), D5(0x8d, bytes([0x0c, 0x01, 0x02])))
    exch(u, D4(0x8c, bytes([0x01]) + tg[1:] + bytes([0x00, 0x00])), D5(0x8d, bytes([0x04])))
    # Target commands
    exch(u, D4(0x92, b"general bytes"), D5(0x93, bytes([0x00])))
    exch(u, D4(0x86), D5(0x87, bytes([0x00]) + b"target data"))
    exch(u, D4(0x88), D5(0x89, bytes([0x00]) + b"initiator cmd"))
    exch(u, D4(0x8a), D5(0x8b, bytes([0x81, 0x21])))
    exch(u, D4(0x8a), D5(0x8b, bytes([0x00, 0x00])), matched=False)
    exch(u, D4(0x8e, b"set data"), D5(0x8f, bytes([0x00])))
    exch(u, D4(0x90, b"respond"), D5(0x91, bytes([0x00])))
    exch(u, D4(0x94, b"metadata"), D5(0x95, bytes([0x00])))

def pn532_list_passive(u):
    """InListPassiveTarget: every BrTy, request and response."""
    # 106 kbps type A: no initiator data / one or two UIDs; two targets, one with ATS
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x01, 0x01, 0x00, 0x04, 0x08, 0x04]) + UID4))
    exch(u, D4(0x4a, bytes([0x02, 0x00]) + UID4 + UID4[::-1]),
         D5(0x4b, bytes([0x02, 0x01, 0x00, 0x04, 0x28, 0x07]) + b"\x04\x03\x02\x01\x00\xff\x80" + bytes([0x05, 0x01, 0x00, 0x02, 0x20]) + bytes([0x02, 0x00, 0x04, 0x20, 0x02, 0x01, 0x02])))
    # ATS: length 0 (fix 7), length 1 (no ATS data), length 3
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x01, 0x01, 0x03, 0x04, 0x20, 0x04]) + UID4 + bytes([0x00])))
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x01, 0x01, 0x03, 0x04, 0x20, 0x04]) + UID4 + bytes([0x01])))
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x01, 0x01, 0x03, 0x04, 0x20, 0x04]) + UID4 + bytes([0x03, 0x78, 0x80])))
    # FeliCa 212 and 424: polling request goes to the FeliCa dissector
    exch(u, D4(0x4a, bytes([0x01, 0x01, 0x00, 0xff, 0xff, 0x01, 0x00])),
         D5(0x4b, bytes([0x01, 0x01, 0x12, 0x01]) + NFCID2 + PAD + bytes([0x12, 0xfc])))
    exch(u, D4(0x4a, bytes([0x01, 0x02, 0x00, 0x12, 0xfc, 0x00, 0x03])),
         D5(0x4b, bytes([0x01, 0x01, 0x12, 0x01]) + NFCID2 + PAD))
    exch(u, D4(0x4a, bytes([0x01, 0x01, 0x00, 0xff, 0xff, 0x01, 0x00])),
         D5(0x4b, bytes([0x01, 0x01, 0x12, 0x01]) + NFCID2 + PAD + b"\x12"))   # a single byte after the PAD
    # 106 kbps type B
    exch(u, D4(0x4a, bytes([0x01, 0x03, 0x00])), D5(0x4b, bytes([0x01, 0x01]) + bytes(range(0x50, 0x5c)) + bytes([0x03, 1, 2, 3])))
    exch(u, D4(0x4a, bytes([0x01, 0x03, 0x00, 0x01])), D5(0x4b, bytes([0x01, 0x01]) + bytes(range(0x50, 0x5c)) + bytes([0x00])))
    # Jewel / Topaz
    exch(u, D4(0x4a, bytes([0x01, 0x04])), D5(0x4b, bytes([0x01, 0x01, 0x0c, 0x00, 0xde, 0xad, 0xbe, 0xef])))
    # BrTy that is not known: request without parameters and response with unknown format
    exch(u, D4(0x4a, bytes([0x01, 0x09])), D5(0x4b, bytes([0x01, 0x01, 0x02, 0x03])))
    # zero targets and an unmatched response
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x00])))
    exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x01, 0x01, 0x03, 0x04, 0x20, 0x04]) + UID4), matched=False)
    # a response whose request was a different command (response_frame_number already used): second response
    a, _ = exch(u, D4(0x4a, bytes([0x01, 0x00])), D5(0x4b, bytes([0x00])))
    u.inn(hci_normal(D5(0x4b, bytes([0x00]))), ep=0x02)

def pn532_misc(u):
    """Unknown command and unexpected data (note and warning expert infos)."""
    exch(u, D4(0xfe, b"\x01\x02"), D5(0xff, b"\x03"))
    exch(u, D4(0x02, b"junk"), D5(0x03, bytes([0x32, 0x01, 0x06, 0x07, 0xff])))   # trailing bytes: unexpected data
    exch(u, D4(0x0c), D5(0x0d, bytes([0x28, 0x03, 0x01, 0x99])))

# ---- PN532 frames whose payload is only dissected with pn532.prtype532 ----
FELICA_ALL = [0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0x13,
              0x14, 0x15, 0x16, 0x17, 0x32, 0x33, 0x38, 0x39, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
              0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x4c, 0x4d, 0x7e]   # 0x7e is not a FeliCa command

def felica_frame(op, body):
    """FeliCa frame as the PN532 carries it: length byte (counts itself) + opcode + body"""
    return bytes([len(body) + 2, op]) + body

def pn532_felica(u):
    """InCommunicateThru frames for the FeliCa payload type (pn532.prtype532:felica)."""
    IDM = NFCID2
    PNM = PAD
    # Polling and its responses (with and without system code), all request codes
    for rc in (0, 1, 2):
        f = felica_frame(0x00, bytes.fromhex("ffff") + bytes([rc, 0x03]))
        exch(u, D4(0x42, f), D5(0x43, bytes([0x00]) + felica_frame(0x01, IDM + PNM + (b"\x12\xfc" if rc else b""))))
    exch(u, D4(0x42, felica_frame(0x00, bytes.fromhex("88b4") + bytes([0, 0]))),
         D5(0x43, bytes([0x00]) + felica_frame(0x01, IDM + PNM + b"\x88\xb4")))
    # Read Without Encryption: no blocks, one block, several blocks; response with data
    exch(u, D4(0x42, felica_frame(0x06, IDM + bytes([0x01]) + bytes.fromhex("0900") + bytes([0x00]))),
         D5(0x43, bytes([0x00]) + felica_frame(0x07, IDM + bytes([0, 0, 0]))))
    exch(u, D4(0x42, felica_frame(0x06, IDM + bytes([0x01]) + bytes.fromhex("0900") + bytes([0x01]) + bytes.fromhex("8000"))),
         D5(0x43, bytes([0x00]) + felica_frame(0x07, IDM + bytes([0, 0, 1]) + bytes(range(16)))))
    exch(u, D4(0x42, felica_frame(0x06, IDM + bytes([0x01]) + bytes.fromhex("0900") + bytes([0x03]) + bytes.fromhex("800080018002"))),
         D5(0x43, bytes([0x00]) + felica_frame(0x07, IDM + bytes([0xa5, 0x00, 3]) + bytes(range(48)))))
    # every other opcode: a few bytes of body, request and response
    for op in FELICA_ALL:
        exch(u, D4(0x42, felica_frame(op, IDM + b"\x01\x02")),
             D5(0x43, bytes([0x00]) + felica_frame(op | 1, IDM + b"\x00\x00")))
    # System code names
    for sc in (0x88b4, 0xfee1, 0x12fc, 0xfe00, 0xde80, 0xffff, 0x1234):
        exch(u, D4(0x42, felica_frame(0x00, struct.pack(">H", sc) + bytes([1, 0]))))
    # a response that is not on the matching endpoint
    exch(u, D4(0x42, felica_frame(0x00, bytes.fromhex("ffff0100"))), D5(0x43, bytes([0x00]) + felica_frame(0x01, IDM + PNM)), matched=False)

MIFARE_KEYA = bytes.fromhex("a0a1a2a3a4a5")
def pn532_mifare(u):
    """InDataExchange frames for the MiFare payload type (pn532.prtype532:mifare)."""
    exch(u, D4(0x40, bytes([0x01, 0x60, 0x04]) + MIFARE_KEYA + UID4), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0x61, 0x05]) + bytes.fromhex("b0b1b2b3b4b5") + UID4), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0x30, 0x04])), D5(0x41, bytes([0x00]) + bytes(range(16))))
    exch(u, D4(0x40, bytes([0x01, 0xa0, 0x04]) + bytes(range(16))), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0xb0, 0x04])), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0xc0, 0x04]) + struct.pack(">i", 5)), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0xc1, 0x04]) + struct.pack(">i", -2)), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0xc2, 0x04]) + struct.pack(">i", 0)), D5(0x41, bytes([0x00])))
    exch(u, D4(0x40, bytes([0x01, 0x99, 0x04])), D5(0x41, bytes([0x00])))     # unknown command

def pn532_iso7816(u):
    """InDataExchange frames for the ISO 7816 payload type (pn532.prtype532:iso7816)."""
    aid = bytes.fromhex("a0000000041010")
    exch(u, D4(0x40, bytes([0x01, 0x00, 0xa4, 0x04, 0x00, len(aid)]) + aid + b"\x00"),
         D5(0x41, bytes([0x00, 0x6f, 0x0a, 0x84, 0x07]) + aid + bytes([0x90, 0x00])))
    exch(u, D4(0x40, bytes([0x01, 0x00, 0xb2, 0x01, 0x0c, 0x00])), D5(0x41, bytes([0x00, 0x6a, 0x82])))
    exch(u, D4(0x40, bytes([0x01, 0x80, 0xa8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00])), D5(0x41, bytes([0x00, 0x77, 0x04, 0x82, 0x02, 0x20, 0x00, 0x90, 0x00])))


def felica_default_pref(u):
    """InListPassiveTarget (FeliCa 212/424) hands five octets to the FeliCa
    dissector, whatever the payload type preference is."""
    for br in (1, 2):
        exch(u, D4(0x4a, bytes([1, br, 0x00, 0xff, 0xff, 0x01, 0x00])),
             D5(0x4b, bytes([1, 1, 0x12, 0x01]) + NFCID2 + PAD + b"\x12\xfc"))
    for op in FELICA_ALL + [0x00, 0x02]:
        u.out(hci_normal(D4(0x4a, bytes([1, 1, op, 0x11, 0x22, 0x33, 0x44]))))

def felica_malformed(u):
    """FeliCa payloads that end too early (InCommunicateThru, needs the felica payload type)."""
    def thru(f): u.out(hci_normal(D4(0x42, bytes([len(f) + 1]) + f)))
    def thru_rsp(f): u.out(hci_normal(D5(0x43, bytes([0x00, len(f) + 1]) + f)))
    thru(b"")                                       # no FeliCa octet at all
    thru(b"\x00\xff\xff")                           # Polling cut
    thru(b"\x00\xff\xff\x01")
    thru(b"\x06" + NFCID2)                          # Read Without Encryption cut after IDm
    thru(b"\x06" + NFCID2 + b"\x01\x09\x00")        # cut after the service code
    thru(b"\x06" + NFCID2 + b"\x01\x09\x00\x02\x80\x00")   # second block number missing
    thru_rsp(b"")
    thru_rsp(b"\x01" + NFCID2)                      # Polling response cut
    thru_rsp(b"\x01" + NFCID2 + PAD[:4])
    thru_rsp(b"\x07" + NFCID2 + b"\x00")            # Read response cut
    # five octets from InListPassiveTarget are always enough for Polling, but a
    # Read Without Encryption needs 13 or more
    u.out(hci_normal(D4(0x4a, bytes([1, 1, 0x06, 1, 2, 3, 4]))))
    u.out(hci_normal(D4(0x4a, bytes([1, 1, 0x07, 1, 2, 3, 4]))))
    u.out(hci_normal(D4(0x4a, bytes([1, 1, 0x01, 1, 2, 3, 4]))))
    u.out(hci_normal(D4(0x4a, bytes([1, 1, 0x00, 0xff]))))     # fewer than five octets (the subset is longer than the data)

def build(outdir, verbose=False):
    cap = Cap(220)
    u = Usb(cap)
    R = []
    def rng(name, fn):
        a = len(cap.frames) + 1
        fn()
        R.append((name, a, len(cap.frames)))
    rng("USB device descriptor (04e6:5591, SCL3711: PN532 HCI)", u.descriptor)
    rng("InListPassiveTarget with FeliCa 212/424: five octets to the FeliCa dissector (default preferences), every opcode", lambda: felica_default_pref(u))
    rng("InCommunicateThru with the FeliCa payload type", lambda: pn532_felica(u))
    cap.write(os.path.join(outdir, "rfid-felica-coverage.pcap"))
    mal = Cap(220); mu = Usb(mal); mu.descriptor()
    felica_malformed(mu)
    mal.write(os.path.join(outdir, "rfid-felica-coverage-malformed.pcap"))
    if verbose:
        for n, a, b in R:
            print("%5d-%-5d %s" % (a, b, n))
        print("main %d frames, malformed %d frames" % (len(cap.frames), len(mal.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)

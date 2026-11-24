#!/usr/bin/env python3
# Generates test/captures/rfid_pn532_hci_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generator of the PN532 HCI coverage captures (packet-rfid-pn532-hci.c).

Usage: mkrfid-pn532-hci.py [-v] [outdir]   (writes rfid-pn532-hci-coverage.pcap
and rfid-pn532-hci-coverage-malformed.pcap, usbmon DLT 220, built with struct only).

PN532 HCI is registered on usb.product 04e6:5591 (SCL3711), so the capture
starts with the GET_DESCRIPTOR(DEVICE) exchange that names that device and
then sends bulk transfers. Nothing here comes from a real network or device.
Includes the reproducers of the fixed infinite loop (preamble and postamble
scans with more than 65537 bytes without 00 FF).
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

# ---- PN532 HCI framing frames ----
FILLER = 0x41     # a byte that is never part of 00 FF
UID4 = bytes.fromhex("01020304")

def hci_frames(u):
    """HCI framing variants: ACK/NACK/error frames, preamble and postamble,
    checksums, extended frames, several frames in one transfer."""
    gfv = D4(0x02)
    # ACK, NACK, error frames (host and device direction, with and without postamble)
    u.out(HCI_ACK); u.inn(HCI_ACK, ep=0x82)
    u.out(HCI_NACK)
    u.inn(hci_err(0x7f))
    u.inn(hci_err(0x01)[:-1])                         # error frame without postamble
    u.inn(b"\x00\x00\xff\x01\xff\x7f\x81\x00\x41\x42")      # error frame followed by junk
    # normal information frames: with and without preamble/postamble variants
    u.out(hci_normal(gfv))
    u.out(hci_normal(gfv, preamble=b""))              # the start code is at offset 0
    u.out(hci_normal(gfv, preamble=b"\x00\x00\x00"))
    u.out(hci_normal(gfv, preamble=b"\x41\x42\x43\x44"))     # junk before the start code
    u.out(hci_normal(gfv, postamble=b""))
    u.out(hci_normal(gfv, postamble=b"\x00\x41"))     # one postamble byte and one ignored
    u.out(hci_normal(gfv, postamble=b"\x00\x41\x42\x43"))
    u.out(hci_normal(gfv, bad_lcs=True))
    u.out(hci_normal(gfv, bad_dcs=True))
    u.out(hci_normal(gfv, bad_lcs=True, bad_dcs=True))
    u.out(hci_normal(D4(0x4a, bytes([0x01, 0x00]))))
    u.inn(hci_normal(D5(0x4b, bytes([0x01, 0x01, 0x00, 0x04, 0x08, 0x04]) + UID4)), ep=0x82)
    # a frame of 255 bytes (the largest normal frame, length 0xfe)
    u.out(hci_normal(D4(0x8e, bytes(range(256)) [:252])))
    # several frames in one transfer: ACK + response, command + command
    u.inn(HCI_ACK + hci_normal(D5(0x03, bytes([0x32, 0x01, 0x06, 0x07]))), ep=0x82)
    u.out(hci_normal(gfv) + hci_normal(D4(0x04)))
    u.out(HCI_ACK + HCI_ACK)
    # extended information frames as the dissector reads them: it never skips
    # the FF FF packet code, so the length is always 0xFFFF and the length
    # checksum byte is the first length octet (02). A real extended frame
    # (hci_ext) is therefore malformed, see mal_hci.py and the README.
    u.out(hci_ext_ffff())
    u.out(hci_ext_ffff(bad_dcs=True))
    # a transfer shorter than six bytes is not dissected
    u.out(b"\x00\x00\xff\x00\xff")
    u.inn(b"\x00")
    # the reproducers of the infinite loop (fixed): more than 65537 bytes
    # without 00 FF (65540 > 65537). 1. preamble: the start code only after 65540 filler bytes
    u.out(bytes([FILLER]) * 65540 + HCI_ACK)
    # 2. postamble: a frame followed by 65540 bytes without 00 FF
    u.out(hci_normal(gfv, postamble=b"") + bytes([FILLER]) * 65540)

def hci_ext_ffff(preamble=b"\x00", postamble=b"\x00", bad_dcs=False):
    """A frame with packet code FF FF as dissect_pn532_hci() reads it: the
    length is the packet code itself (65535), followed by LENM=02 (which
    makes the length checksum zero) and 65535 octets of PN532 data."""
    data = bytes([0xd4, 0x02]) + bytes(65533)
    dcs = (-sum(data)) & 0xff
    if bad_dcs: dcs ^= 0x55
    return preamble + b"\x00\xff\xff\xff" + b"\x02" + data + bytes([dcs]) + postamble

def hci_malformed(u):
    gfv = D4(0x02)
    u.out(bytes([FILLER]) * 5 + b"\x00\xff")         # start code at the very end
    u.out(b"\x00\x00\xff\x03\xfd\xd4")                                                    # payload cut by the transfer end
    u.out(b"\x00\x00\xff\x20\xe0\xd4\x02\x00")                                           # length 32, 3 bytes present
    u.out(b"\x00\x00\xff\xff\xff\x01\x00\xff")                                           # extended frame cut at the length
    u.out(b"\x00\x00\xff\xff\xff\x00\x10\xf0\xd4\x8e\x00")                               # extended length beyond the transfer
    u.out(b"\x00\x00\xff\x01\xff")                                                       # error frame without code
    u.out(hci_normal(gfv)[:-1])                                                           # data checksum present, no postamble
    u.out(hci_normal(gfv)[:-2])                                                           # no data checksum
    # real extended frames (length and checksum in the right place): the dissector
    # reads the packet code FF FF as the length, so they are malformed
    u.out(hci_ext(D4(0x8e, b"x" * 10)))
    u.out(hci_ext(D4(0x8e, b"x" * 10), bad_lcs=True))
    u.out(hci_ext(D4(0x8e, bytes(range(256)) * 2), preamble=b"\x00\x00"))
    u.out(hci_ext(D4(0x8e, b"x" * 10))[:-2])
    u.out(hci_ext_ffff()[:-3])                                                          # data checksum cut off
    u.out(hci_ext_ffff()[:70000][:-10])                                                 # data ends before the length says
    u.out(hci_normal(D4(0x4a, bytes([0x01, 0x01, 0x00, 0xff])))[:-3])


# ---- main ----
def build(outdir, verbose=False):
    cap = Cap(220)
    u = Usb(cap)
    R = []
    def rng(name, fn):
        a = len(cap.frames) + 1
        fn()
        R.append((name, a, len(cap.frames)))
    rng("USB device descriptor (04e6:5591, SCL3711)", u.descriptor)
    rng("HCI framing: ACK/NACK/error, preamble, postamble, checksums, extended frames, loop reproducers", lambda: hci_frames(u))
    cap.write(os.path.join(outdir, "rfid-pn532-hci-coverage.pcap"))
    mal = Cap(220); mu = Usb(mal); mu.descriptor()
    hci_malformed(mu)
    mal.write(os.path.join(outdir, "rfid-pn532-hci-coverage-malformed.pcap"))
    if verbose:
        for n, a, b in R:
            print("%5d-%-5d %s" % (a, b, n))
        print("main %d frames, malformed %d frames" % (len(cap.frames), len(mal.frames)))

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "-v" else ".", "-v" in sys.argv)

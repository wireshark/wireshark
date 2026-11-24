#!/usr/bin/env python3
# Generates the hci_usb captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth HCI USB
transport dissector (packet-hci_usb.c).

A USB Bluetooth adapter (device class 0xE0/0x01/0x01, recognized from
the device descriptor) carries HCI commands in control transfers on
endpoint 0, events in interrupt transfers, ACL data in bulk transfers
and SCO data in isochronous transfers. A transfer can carry only part
of an HCI packet; the dissector reassembles the parts of one packet per
(bus, device, endpoint, direction). Captured with Linux usbmon
(LINKTYPE_USB_LINUX_MMAPPED, 220) or FreeBSD usbpf (LINKTYPE_USBPF,
249, several frames per record). Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkhci_usb.py <output directory>

Writes:
  hci_usb-coverage.pcapng            device descriptor, commands, events
                                     (also split over three transfers),
                                     ACL data (also split), SCO, FreeBSD
                                     records with several frames
                                     (reproducer of the fix), a
                                     truncated capture
  hci_usb-coverage-multiframe.pcapng FreeBSD records with several HCI
                                     packets (reproducer of the fix); the
                                     two passes differ by design
  hci_usb-coverage-malformed.pcapng  completions of control transfers
                                     without data, bulk and interrupt
                                     data cut short, Exported PDU
"""

import os
import struct
import sys

# ------------------------------------------------------------ pcapng
def blk(t, body):
    pad = (-len(body)) % 4
    l = 12 + len(body) + pad
    return struct.pack('<II', t, l) + body + b'\0' * pad + struct.pack('<I', l)


def opt(code, val):
    pad = (-len(val)) % 4
    return struct.pack('<HH', code, len(val)) + val + b'\0' * pad


class Pcapng:
    def __init__(self, linktypes):
        self.data = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in linktypes:
            self.data += blk(1, struct.pack('<HHI', lt, 0, 65535))
        self.ts = 1700000000 * 1000000

    def epb(self, ifid, pkt, direction=None, origlen=None):
        """direction: None (no flags option), 0 unknown, 1 inbound, 2 outbound."""
        self.ts += 1000
        o = b''
        if direction is not None:
            o = opt(2, struct.pack('<I', direction)) + opt(0, b'')
        self.data += blk(6, struct.pack('<IIIII', ifid, self.ts >> 32, self.ts & 0xffffffff,
                                        len(pkt), origlen or len(pkt)) + pkt + b'\0' * ((-len(pkt)) % 4) + o)
        # the option block follows the padded packet data

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.data)



LT_USB_LINUX_MMAPPED = 220
LT_USB_FREEBSD = 186
LT_EXP_PDU = 252

URB_ISO, URB_INT, URB_CTRL, URB_BULK = 0, 1, 2, 3
_urb_id = [0x1000]


def usbmon(ev, xtype, ep, dev, data=b'', setup=None, urb_len=None, status=0, bus=1):
    """Linux usbmon header, 64 octets (mmapped)."""
    if ev == 'S':
        _urb_id[0] += 0x100
    uid = _urb_id[0]
    setup_flag = 0 if setup is not None else ord('-')
    data_flag = 0 if data else (ord('<') if ep & 0x80 else ord('>'))
    if urb_len is None:
        urb_len = len(data)
    hdr = struct.pack('<QBBBBHbbqiiII', uid, ord(ev), xtype, ep, dev, bus,
                      setup_flag, data_flag, 1700000000, 0, status, urb_len, len(data))
    hdr += setup if setup is not None else b'\0' * 8
    hdr += struct.pack('<iiII', 0, 0, 0, 0)
    assert len(hdr) == 64
    return hdr + data


FB_SUBMIT, FB_COMPLETE = 0, 1
FB_CTRL, FB_ISO, FB_BULK, FB_INT = 0, 1, 2, 3


def usbpf(bus, addr, urbtype, xtype, ep, frames, status=0):
    """FreeBSD usbpf header (128 octets) and frames. frames: list of
    payloads (None: a frame without data)."""
    body = b''
    for f in frames:
        if f is None:
            body += struct.pack('<II', 0, 0)
        else:
            body += struct.pack('<II', len(f), 2 | (1 if ep & 0x80 else 0))
            body += f + b'\0' * ((-len(f)) % 4)
    hdr = struct.pack('<IIBBBBIIIIIII', 128 + len(body), bus, addr, 0, urbtype, xtype,
                      0, status, 0, 0, len(frames), 0, 0)
    hdr += struct.pack('<B', ep) + b'\0\0\0' + struct.pack('<B', 3)
    hdr += b'\0' * (128 - len(hdr))
    return hdr + body


def cmd(opcode, params=b''):
    return struct.pack('<HB', opcode, len(params)) + params


def evt(code, params=b''):
    return struct.pack('<BB', code, len(params)) + params


def acl(handle, data, pb=2):
    return struct.pack('<HH', handle | (pb << 12), len(data)) + data


def l2cap(cid, payload):
    return struct.pack('<HH', len(payload), cid) + payload


def sco(handle, data):
    return struct.pack('<HB', handle, len(data)) + data


BDADDR = bytes([1, 2, 3, 4, 5, 6])
DEVDESC = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0xe0, 0x01, 0x01, 64,
                      0x0a5c, 0x21e8, 0x0112, 1, 2, 3, 1)
CONN = evt(0x03, struct.pack('<BH', 0, 0x0001) + BDADDR + bytes([1, 0]))   # Connection Complete


def describe(p, dev, bus=1):
    """GET_DESCRIPTOR(DEVICE) request and response for a Bluetooth adapter."""
    p.epb(0, usbmon('S', URB_CTRL, 0x80, dev, setup=struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18),
                    urb_len=18, bus=bus))
    p.epb(0, usbmon('C', URB_CTRL, 0x80, dev, data=DEVDESC, bus=bus))


def split(data, n):
    return [data[i:i + n] for i in range(0, len(data), n)]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    p = Pcapng([LT_USB_LINUX_MMAPPED, LT_USB_FREEBSD])
    DEV = 3
    L = lambda *a, **k: p.epb(0, usbmon(*a, **k))
    F = lambda pkt: p.epb(1, pkt)

    describe(p, DEV)
    # HCI commands on the control endpoint; the setup request byte is
    # shown (0 primary controller function, others from the table)
    for breq, c in ((0x00, cmd(0x0c03)),
                    (0x2b, cmd(0x0c13, b'hci_usb coverage'.ljust(248, b'\0'))),
                    (0xe0, cmd(0x1001)),
                    (0x55, cmd(0x1009))):
        L('S', URB_CTRL, 0x00, DEV, data=c, setup=struct.pack('<BBHHH', 0x20, breq, 0, 0, len(c)))
    # events on the interrupt endpoint
    def ev(e):
        L('S', URB_INT, 0x81, DEV, urb_len=16)
        L('C', URB_INT, 0x81, DEV, data=e)
    ev(evt(0x0e, bytes([1, 0x03, 0x0c, 0])))                        # Command Complete (Reset)
    ev(CONN)                                                         # Connection Complete
    # an event split over three transfers of 16, 16 and 8 octets
    big = evt(0x0e, bytes([1, 0x13, 0x0c, 0]) + b'hci_usb coverage name!!!!!!!!!!!!!')
    assert len(big) == 40
    for part in split(big, 16):
        ev(part)
    # an event in two parts: 2 octet header first, then the parameters
    e2 = evt(0x0e, bytes([1, 0x01, 0x10, 0, 6, 0x34, 0x12, 6, 0x0f, 0x00, 0x01, 0x00]))
    ev(e2[:2])
    ev(e2[2:])
    # ACL data on the bulk endpoints
    def bulk_out(pk):
        L('S', URB_BULK, 0x02, DEV, data=pk)
        L('C', URB_BULK, 0x02, DEV, urb_len=len(pk))
    def bulk_in(pk):
        L('S', URB_BULK, 0x82, DEV, urb_len=64)
        L('C', URB_BULK, 0x82, DEV, data=pk)
    bulk_out(acl(1, l2cap(0x0001, bytes([2, 1, 4, 0, 1, 0x10, 0x40, 0]))))
    bulk_in(acl(1, l2cap(0x0001, bytes([3, 1, 8, 0, 0x41, 0, 0x40, 0, 0, 0, 0, 0]))))
    # a 100 octet ACL packet in three parts on each endpoint
    long_pkt = acl(1, l2cap(0x0041, bytes(range(96))))
    for part in split(long_pkt, 40):
        bulk_in(part)
    for part in split(long_pkt, 50):
        bulk_out(part)
    # the same packet sent to another endpoint address keeps its own
    # reassembly state
    for part in split(long_pkt, 64):
        L('S', URB_BULK, 0x84, DEV, urb_len=64)
        L('C', URB_BULK, 0x84, DEV, data=part)
    # a command with its parameters split on the control endpoint
    c2 = cmd(0x0c13, b'split command name'.ljust(248, b'\0'))
    L('S', URB_CTRL, 0x00, DEV, data=c2[:100], setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, len(c2)))
    L('S', URB_CTRL, 0x00, DEV, data=c2[100:], setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, len(c2)))
    # a second adapter on bus 2
    describe(p, 5, bus=2)
    p.epb(0, usbmon('S', URB_CTRL, 0x00, 5, data=cmd(0x0c03), setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, 3), bus=2))
    p.epb(0, usbmon('C', URB_INT, 0x81, 5, data=evt(0x0e, bytes([1, 0x03, 0x0c, 0])), bus=2))
    # a truncated capture of a bulk transfer: not reassembled, shown as
    # an unknown fragment
    full = usbmon('C', URB_BULK, 0x82, DEV, data=acl(1, l2cap(0x0040, bytes(40))))
    p.epb(0, full[:64 + 10], origlen=len(full))
    # isochronous (SCO) in a Linux capture: one descriptor
    iso_hdr = bytearray(usbmon('C', URB_ISO, 0x83, DEV, data=b'', urb_len=8))
    iso_hdr[60:64] = struct.pack('<I', 1)                        # ndesc
    iso_hdr[14] = ord('-')
    iso = bytes(iso_hdr) + struct.pack('<iII', 0, 0, 8) + b'\0\0\0\0' + sco(1, bytes(range(8)))
    p.epb(0, iso)

    # FreeBSD usbpf: a device descriptor, then records with one or
    # several frames per transfer. Device 4 on bus 1.
    FD = 4
    F(usbpf(1, FD, FB_SUBMIT, FB_CTRL, 0x80, [struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)], status=0x80 | 0x100))
    F(usbpf(1, FD, FB_COMPLETE, FB_CTRL, 0x80, [None, DEVDESC], status=0x80))
    F(usbpf(1, FD, FB_COMPLETE, FB_INT, 0x81, [CONN]))
    # one frame per record: bulk out, interrupt in
    F(usbpf(1, FD, FB_SUBMIT, FB_BULK, 0x02, [acl(1, l2cap(0x0040, b'\x01\x02\x03\x04'))]))
    F(usbpf(1, FD, FB_COMPLETE, FB_INT, 0x81, [evt(0x13, struct.pack('<BHH', 1, 1, 2))]))
    # frames of an isochronous transfer (SCO) and of an unknown transfer type
    F(usbpf(1, FD, FB_COMPLETE, FB_ISO, 0x83, [sco(1, bytes(range(8))), sco(1, bytes(range(8, 16)))]))
    F(usbpf(1, FD, FB_COMPLETE, 7, 0x83, [b'\x01\x02\x03\x04']))
    p.write(os.path.join(out, 'hci_usb-coverage.pcapng'))

    # ------------------------------------------------------- multi-frame
    # A FreeBSD record with several frames, each a complete HCI packet:
    # the reassembly of all of them ends in the same frame number but at
    # different layers. The first pass decodes every frame; on a second
    # pass the lookup by frame number finds the last reassembly, so the
    # others are shown as fragments (and without the fix a NULL
    # reassembled tvb was passed to the ACL/event dissector). That makes
    # the output of the two passes differ, so these records are not in
    # the main capture.
    r = Pcapng([LT_USB_FREEBSD])
    R = lambda pkt: r.epb(0, pkt)
    R(usbpf(1, FD, FB_SUBMIT, FB_CTRL, 0x80, [struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)], status=0x80 | 0x100))
    R(usbpf(1, FD, FB_COMPLETE, FB_CTRL, 0x80, [None, DEVDESC], status=0x80))
    R(usbpf(1, FD, FB_COMPLETE, FB_INT, 0x81, [CONN]))
    # the reproducer: several frames in one record, each a complete HCI
    # packet; the reassembly of all of them ends in the same frame
    # number but at different layers
    R(usbpf(1, FD, FB_SUBMIT, FB_BULK, 0x02,
            [acl(1, l2cap(0x0040, b'frame one')),
             acl(1, l2cap(0x0040, b'frame two')),
             acl(1, l2cap(0x0040, b'frame three'))]))
    R(usbpf(1, FD, FB_COMPLETE, FB_INT, 0x81,
            [evt(0x13, struct.pack('<BHH', 1, 1, 1)),
             evt(0x13, struct.pack('<BHH', 1, 1, 2))]))
    # a split packet whose parts are in one record
    f2 = acl(1, l2cap(0x0040, bytes(range(60))))
    R(usbpf(1, FD, FB_SUBMIT, FB_BULK, 0x02, [f2[:30], f2[30:]]))
    r.write(os.path.join(out, 'hci_usb-coverage-multiframe.pcapng'))

    # -------------------------------------------------------- malformed
    q = Pcapng([LT_USB_LINUX_MMAPPED, LT_EXP_PDU])
    DEV = 7
    describe(q, DEV)
    c = cmd(0x0c03)
    q.epb(0, usbmon('S', URB_CTRL, 0x00, DEV, data=c, setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, len(c))))
    # completion of a control transfer without data
    q.epb(0, usbmon('C', URB_CTRL, 0x00, DEV, urb_len=len(c)))
    # control request with a setup but no data
    q.epb(0, usbmon('S', URB_CTRL, 0x00, DEV, setup=struct.pack('<BBHHH', 0x20, 0, 0, 0, 3)))
    # interrupt data of one octet (length byte missing), bulk of 3 octets
    q.epb(0, usbmon('C', URB_INT, 0x81, DEV, data=b'\x0e'))
    q.epb(0, usbmon('C', URB_BULK, 0x82, DEV, data=b'\x01\x00\x00'))
    # a packet whose length says more than the transfer, then a transfer
    # that completes it with extra data (too long)
    q.epb(0, usbmon('C', URB_INT, 0x81, DEV, data=evt(0x0e, bytes(10))[:6]))
    q.epb(0, usbmon('C', URB_INT, 0x81, DEV, data=bytes(20)))
    # an event whose parameters are shorter than the length it announces
    q.epb(0, usbmon('C', URB_INT, 0x81, DEV, data=evt(0x0e, bytes(4))))
    # Exported PDU naming hci_usb: no URB info is passed down
    tag = struct.pack('>HH', 12, 8) + b'hci_usb\0' + struct.pack('>HH', 0, 0)
    q.epb(1, tag + cmd(0x0c03))
    q.epb(1, tag)
    q.write(os.path.join(out, 'hci_usb-coverage-malformed.pcapng'))


main()

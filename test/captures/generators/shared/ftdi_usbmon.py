#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helper (copied and extended from ftdi_usbmon.py of the review batch): write a
# synthetic Linux usbmon (LINKTYPE_USB_LINUX_MMAPPED, 220) capture of FTDI
# devices. Several devices (bus 1, addresses 2...) can be enumerated.
import struct

BUS = 1


class Cap:
    def __init__(self):
        self.recs = []
        self.id = 0x1000
        self.t = 0
        self.dev = 2

    def _rec(self, urb_id, typ, xfer, ep, setup, data, urb_len, status=0, dev=None):
        self.t += 1
        dev = self.dev if dev is None else dev
        if setup is not None:
            flag_setup = b'\x00'
            setup_b = setup
        else:
            flag_setup = b'-'
            setup_b = b'\x00' * 8
        flag_data = b'\x00' if data else b'<'
        hdr = struct.pack('<QcBBBHcc', urb_id, typ, xfer, ep, dev, BUS, flag_setup, flag_data)
        hdr += struct.pack('<qiiII', 1700000000, self.t, status, urb_len, len(data))
        hdr += setup_b
        hdr += struct.pack('<iiII', 0, 0, 0, 0)
        assert len(hdr) == 64
        self.recs.append(hdr + data)

    def control(self, setup, resp=b'', out_data=b'', dev=None, with_submit=True):
        """A control transfer: submit with the setup packet and completion
        with the response (with_submit False: only the completion)"""
        self.id += 1
        wlen = struct.unpack('<H', setup[6:8])[0]
        ep = 0x80 if setup[0] & 0x80 else 0x00
        if with_submit:
            self._rec(self.id, b'S', 2, ep, setup, out_data, wlen, dev=dev)
        self._rec(self.id, b'C', 2, ep, None if with_submit else None, resp, len(resp), dev=dev)

    def request(self, brequest, wvalue=0, windex=0, resp=None, data=b'', rtype=0x40, dev=None, wlength=None):
        """Vendor request to the device; resp is not None for IN requests"""
        if resp is not None:
            rtype |= 0x80
        wl = len(resp) if resp is not None else len(data)
        if wlength is not None:
            wl = wlength
        setup = struct.pack('<BBHHH', rtype, brequest, wvalue, windex, wl)
        self.control(setup, resp or b'', data, dev=dev)

    def enumerate(self, bcd=0x0700, vid=0x0403, pid=0x6010, iserial=0, dev=None):
        dd = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, bcd, 1, 2, iserial, 1)
        self.control(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), dd, dev=dev)

    def set_bitmode(self, mode, iface=1, mask=0xFF, dev=None):
        self.request(0x0B, (mode << 8) | mask, iface, dev=dev)

    def bulk_out(self, data, ep=0x02, dev=None):
        self.id += 1
        self._rec(self.id, b'S', 3, ep, None, data, len(data), dev=dev)
        self._rec(self.id, b'C', 3, ep, None, b'', len(data), dev=dev)

    def bulk_in(self, data, ep=0x81, status=b'\x00\x60', dev=None):
        """data is the payload; the two modem status bytes are prepended"""
        self.id += 1
        d = status + data
        self._rec(self.id, b'S', 3, ep, None, b'', 512, dev=dev)
        self._rec(self.id, b'C', 3, ep, None, d, len(d), dev=dev)

    def bulk_in_raw(self, data, ep=0x81, dev=None):
        """data is the complete URB payload (status bytes included)"""
        self.id += 1
        self._rec(self.id, b'S', 3, ep, None, b'', 512, dev=dev)
        self._rec(self.id, b'C', 3, ep, None, data, len(data), dev=dev)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 220))
            for i, r in enumerate(self.recs):
                f.write(struct.pack('<IIII', 1700000000 + i // 1000, (i % 1000) * 1000, len(r), len(r)))
                f.write(r)

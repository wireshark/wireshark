#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helper: write a synthetic Linux usbmon (LINKTYPE_USB_LINUX_MMAPPED, 220)
# capture of an FTDI FT2232H (0403:6010) device put into MPSSE mode.
import struct

BUS = 1
DEV = 2


class Cap:
    def __init__(self):
        self.recs = []
        self.id = 0x1000
        self.t = 0

    def _rec(self, urb_id, typ, xfer, ep, setup, data, urb_len, status=0):
        self.t += 1
        if setup is not None:
            flag_setup = b'\x00'
            setup_b = setup
        else:
            flag_setup = b'-'
            setup_b = b'\x00' * 8
        flag_data = b'\x00' if data else b'<'
        hdr = struct.pack('<QcBBBHcc', urb_id, typ, xfer, ep, DEV, BUS,
                          flag_setup, flag_data)
        hdr += struct.pack('<qiiII', 1700000000, self.t, status, urb_len,
                           len(data))
        hdr += setup_b
        hdr += struct.pack('<iiII', 0, 0, 0, 0)
        assert len(hdr) == 64
        self.recs.append(hdr + data)

    def control(self, setup, resp=b'', out_data=b''):
        self.id += 1
        wlen = struct.unpack('<H', setup[6:8])[0]
        ep = 0x80 if setup[0] & 0x80 else 0x00
        self._rec(self.id, b'S', 2, ep, setup, out_data, wlen)
        self._rec(self.id, b'C', 2, ep, None, resp, len(resp))

    def enumerate(self, bcd=0x0700, vid=0x0403, pid=0x6010):
        dd = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64,
                         vid, pid, bcd, 1, 2, 0, 1)
        self.control(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), dd)

    def set_bitmode(self, mode, iface=1):
        self.control(bytes([0x40, 0x0B, 0xFF, mode, iface, 0, 0, 0]))

    def bulk_out(self, data, ep=0x02):
        self.id += 1
        self._rec(self.id, b'S', 3, ep, None, data, len(data))
        self._rec(self.id, b'C', 3, ep, None, b'', len(data))

    def bulk_in(self, data, ep=0x81):
        """data is the payload; two modem status bytes are prepended"""
        self.id += 1
        d = b'\x00\x60' + data
        self._rec(self.id, b'S', 3, ep, None, b'', 512)
        self._rec(self.id, b'C', 3, ep, None, d, len(d))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 220))
            for i, r in enumerate(self.recs):
                f.write(struct.pack('<IIII', 1700000000, i, len(r), len(r)))
                f.write(r)

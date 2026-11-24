#!/usr/bin/env python3
# Generates test/captures/u3v_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the U3V coverage captures. Usage: mku3v.py <outdir>
#
# USB3 Vision over Linux usbmon (LINKTYPE_USB_LINUX_MMAPPED, 220), reached the
# way a capture reaches it: a GET_DESCRIPTOR(configuration) exchange that
# carries the miscellaneous class (0xEF, subclass 5) interface and the U3V
# device info descriptor, then bulk transfers; the second device has no
# descriptors and is found by the usb.bulk heuristic from the GenCP prefix.
#
# Device 3 keeps commands and acknowledgements on one endpoint (0x81): the
# usb conversation, and with it the transaction and the register base
# addresses, are per endpoint, so only then does an acknowledgement find its
# command (see the README). Device 4 uses the real layout (commands on the OUT
# endpoint 0x01, acknowledgements on the IN endpoint 0x81).
import os
import struct
import sys

CTRL, EVT, LEAD, TRAIL = 0x43563355, 0x45563355, 0x4C563355, 0x54563355

class Cap:
    def __init__(self):
        self.recs = []
        self.t = 0
        self.uid = 0x2000

    def rec(self, dev, urb_id, typ, xfer, ep, data, urb_len, setup=None, status=0):
        self.t += 1
        hdr = struct.pack('<QcBBBHcc', urb_id, typ, xfer, ep, dev, 1,
                          b'\x00' if setup else b'-', b'\x00' if data else b'<')
        hdr += struct.pack('<qiiII', 1700000000, self.t, status, urb_len, len(data))
        hdr += (setup or b'\x00' * 8) + struct.pack('<iiII', 0, 0, 0, 0)
        self.recs.append(hdr + data)

    def control_in(self, dev, setup, data, urb_len=None):
        self.uid += 1
        self.rec(dev, self.uid, b'S', 2, 0x80, b'', struct.unpack('<H', setup[6:8])[0], setup)
        self.rec(dev, self.uid, b'C', 2, 0x80, data, len(data) if urb_len is None else urb_len)

    def sub(self, dev, ep, data):      # data sent by the host (submit)
        self.uid += 1
        self.rec(dev, self.uid, b'S', 3, ep, data, len(data))

    def comp(self, dev, ep, data):     # data returned by the device (complete)
        self.uid += 1
        self.rec(dev, self.uid, b'C', 3, ep, data, len(data))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 220))
            for i, r in enumerate(self.recs):
                f.write(struct.pack('<IIII', 1700000000, i * 1000, len(r), len(r)))
                f.write(r)

# --------------------------------------------------------------- GenCP
def cmd(cid, req, payload, prefix=CTRL, flags=0x4000, length=None):
    return struct.pack('<IHHHH', prefix, flags, cid,
                       len(payload) if length is None else length, req) + payload

def ack(cid, req, payload, status=0, prefix=CTRL):
    return struct.pack('<IHHHH', prefix, status, cid, len(payload), req) + payload

READ, READ_ACK, WRITE, WRITE_ACK, PENDING, EVENT, EVENT_ACK = \
    0x0800, 0x0801, 0x0802, 0x0803, 0x0805, 0x0C00, 0x0C01

class Gen:
    """Device with commands and acknowledgements on one endpoint."""
    def __init__(self, cap, dev, ep_cmd, ep_ack):
        self.c, self.dev, self.ec, self.ea, self.req = cap, dev, ep_cmd, ep_ack, 0

    def _send(self, ep, data, comp=False):
        (self.c.comp if comp else self.c.sub)(self.dev, ep, data)

    def read(self, addr, n, data=None, status=0):
        self.req += 1
        self._send(self.ec, cmd(READ, self.req, struct.pack('<QHH', addr, 0, n)))
        d = data if data is not None else bytes((addr + i) & 0xff for i in range(n))
        self._send(self.ea, ack(READ_ACK, self.req, d if not status else b'', status), True)

    def write(self, addr, data, cnt=None, status=0):
        self.req += 1
        self._send(self.ec, cmd(WRITE, self.req, struct.pack('<Q', addr) + data))
        self._send(self.ea, ack(WRITE_ACK, self.req,
                                struct.pack('<HH', 0, len(data) if cnt is None else cnt), status), True)

def descriptors():
    cfg = struct.pack('<BBHBBBBB', 9, 2, 0, 3, 1, 0, 0x80, 250)
    def iface(n, proto, neps):
        return struct.pack('<BBBBBBBBB', 9, 4, n, 0, neps, 0xEF, 5, proto, 0)
    def u3vdesc():
        return struct.pack('<BBBIIBBBBBBBBB', 20, 0x24, 1, 0x00010000, 0x00030001,
                           1, 2, 3, 4, 5, 6, 7, 8, 0x1c)
    def ep(a):
        return struct.pack('<BBBBHB', 7, 5, a, 2, 1024, 0)
    body = iface(0, 0, 2) + u3vdesc() + ep(0x01) + ep(0x81) + iface(1, 1, 1) + ep(0x83) + \
        iface(2, 2, 1) + ep(0x82)
    full = cfg + body
    return full[:2] + struct.pack('<H', len(full)) + full[4:]

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    c = Cap()
    DEV = 3
    # ---- descriptors of device 3
    d = descriptors()
    c.control_in(DEV, bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(d)), d)
    g = Gen(c, DEV, 0x81, 0x81)
    # ---- the base address registers first, so that everything after is
    # decoded the same way in one and in two passes
    g.read(0x1D0, 8, struct.pack('<Q', 0x5000))                  # manifest table
    g.read(0x1D8, 8, struct.pack('<Q', 0x1000))                  # SBRM
    g.read(0x1000 + 0x20, 8, struct.pack('<Q', 0x2000))          # SIRM
    g.read(0x1000 + 0x2C, 8, struct.pack('<Q', 0x3000))          # EIRM
    g.read(0x1000 + 0x38, 8, struct.pack('<Q', 0x4000))          # IIDC2
    # ABRM registers
    for a, n in ((0x0, 4), (0x4, 64), (0x44, 64), (0x84, 64), (0xC4, 64), (0x104, 64),
                 (0x144, 64), (0x184, 64), (0x1C4, 8), (0x1CC, 4), (0x1D0, 8), (0x1D8, 8),
                 (0x1E0, 8), (0x1E8, 4), (0x1EC, 4), (0x1F0, 8), (0x1F8, 4), (0x1FC, 8),
                 (0x204, 4), (0x208, 4), (0x20C, 4)):
        g.read(a, n, (b'name-%x' % a).ljust(n, b'\0') if n == 64 else
               struct.pack('<Q', 0x5000) if a == 0x1D0 else
               struct.pack('<Q', 0x1000) if a == 0x1D8 else None)
    g.read(0x4, 100)                    # longer than 64: no decoding of the string
    g.read(0x300, 4)                    # an address no register has
    # SBRM, SIRM and EIRM registers
    for off, n in ((0x0, 4), (0x4, 8), (0xC, 8), (0x14, 4), (0x18, 4), (0x1C, 4), (0x20, 8),
                   (0x28, 4), (0x2C, 8), (0x34, 4), (0x38, 8), (0x40, 4), (0x50, 4)):
        g.read(0x1000 + off, n, struct.pack('<Q', {0x20: 0x2000, 0x2C: 0x3000, 0x38: 0x4000}[off])
               if off in (0x20, 0x2C, 0x38) else None)
    for off, n in ((0x0, 4), (0x4, 4), (0x8, 8), (0x10, 4), (0x14, 4), (0x18, 4), (0x1C, 4),
                   (0x20, 4), (0x24, 4), (0x28, 4), (0x2C, 4), (0x30, 4)):
        g.read(0x2000 + off, n)
    for off, n in ((0x0, 4), (0x4, 4), (0x8, 4), (0xC, 4)):
        g.read(0x3000 + off, n)
    # writes to known registers (each ack carries the number of bytes written)
    for a, v in ((0x1E0, 8), (0x1E8, 4), (0x204, 4), (0x1000 + 0xC, 8), (0x2000 + 0x4, 4),
                 (0x3000 + 0x0, 4), (0x3000 + 0x8, 4), (0x300, 4)):
        g.write(a, bytes(range(v)))
    g.write(0x20000, b'custom write data')
    g.write(0x20000, b'')
    g.write(0x100000000, b'\x01\x02\x03\x04')           # address above 32 bits
    g.read(0x100000000, 4)
    g.read(0x30000, 16)
    # acknowledgements with an error status: nothing is decoded behind the header
    for st in (0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006, 0x8007, 0x800F, 0xA001, 0xA002,
               0xA003, 0xA004, 0xA100, 0xA101, 0x8123):
        g.read(0x30000, 4, status=st)
    g.write(0x20000, b'abcd', status=0x8004)
    # pending acknowledgement, and commands the dissector does not know
    g.req += 1
    g._send(0x81, cmd(READ, g.req, struct.pack('<QHH', 0x30000, 0, 4)))
    g._send(0x81, ack(PENDING, g.req, struct.pack('<HH', 0, 500)), True)
    g._send(0x81, ack(READ_ACK, g.req, bytes(4)), True)
    g._send(0x81, cmd(0x0900, 90, b'unknown command payload'))
    g._send(0x81, ack(0x0901, 90, b'unknown ack payload'), True)
    g._send(0x81, ack(0x0901, 91, b'', status=0x8001), True)
    # events: standard, the test event, error, device specific, with and without data,
    # and an event acknowledgement the dissector does not decode
    for eid, data in ((0x0001, b''), (0x4FFF, b'EVENTDAT'), (0x8000, b''), (0x8001, b'e'),
                      (0x8FFF, b'err'), (0x9000, b'12345678'), (0xFFFF, b'')):
        g._send(0x81, cmd(EVENT, 7, struct.pack('<HHQ', 0, eid, 0x1122334455667788) + data,
                          prefix=EVT))
    g._send(0x81, ack(EVENT_ACK, 7, b'', prefix=EVT), True)
    # ---- streaming on the endpoint 0x82 of device 3 (the interface of
    # the descriptors); the leader sets the stream endpoint, the payload
    # that follows has no prefix
    def leader(ptype, block, extra=b''):
        h = struct.pack('<IHHQHH', LEAD, 0, 52, block, 0, ptype)
        if ptype in (0x0001, 0x4001, 0x4000):
            h += struct.pack('<Q', 123456789)
        if ptype in (0x0001, 0x4001):
            h += struct.pack('<IIIIIHH', 0x01080001, 640, 480, 16, 8, 2, 0)
        return h + extra
    def trailer(block, tail=b''):
        return struct.pack('<IHHQHHQ', TRAIL, 0, 32, block, 0, 0, 640 * 480) + tail
    S = 0x82
    for blk, pt in ((1, 0x0001), (2, 0x4001), (3, 0x4000), (4, 0x0005)):
        c.comp(DEV, S, leader(pt, blk))
        c.comp(DEV, S, bytes(range(256)) * 4)
        c.comp(DEV, S, trailer(blk))
    c.comp(DEV, S, trailer(5, struct.pack('<I', 480)))
    c.comp(DEV, S, trailer(6, struct.pack('<II', 480, 0x1234)))

    # ---- device 4: no descriptors, the real endpoint layout: commands on
    # the OUT endpoint 0x01, acknowledgements on the IN endpoint 0x81.
    # The acknowledgement is another conversation than the command, so it has no
    # transaction.
    g4 = Gen(c, 4, 0x01, 0x81)
    g4.read(0x1D8, 8, struct.pack('<Q', 0x1000))
    g4.read(0x1000, 4)
    g4.write(0x20000, b'xyz1')
    g4.write(0x1E0, b'\x00' * 8)
    g4._send(0x01, cmd(READ, 99, struct.pack('<QHH', 0x30000, 0, 8)))
    g4._send(0x81, ack(PENDING, 99, struct.pack('<HH', 0, 10)), True)
    g4._send(0x01, cmd(EVENT, 3, struct.pack('<HHQ', 0, 0x0001, 5), prefix=EVT))
    c.comp(4, 0x82, leader(0x0001, 9))
    c.comp(4, 0x82, trailer(9))
    # data on the event interface's endpoint of device 3 that is not GenCP (the
    # class dissector is called and finds nothing), and short or foreign data
    # on a device whose class is unknown (the heuristic refuses it)
    c.comp(DEV, 0x83, b'not a GenCP telegram')
    c.comp(5, 0x81, b'\x01\x02')
    c.comp(5, 0x81, b'XXXXXXXXXXXXXXXX')
    # a class specific descriptor of another type behind a miscellaneous interface
    d2 = struct.pack('<BBHBBBBB', 9, 2, 9 + 9 + 3, 1, 1, 0, 0x80, 250) + \
        struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 0, 0xEF, 5, 0, 0) + bytes([3, 0x21, 7])
    c.control_in(6, bytes([0x80, 6, 0, 2, 0, 0]) + struct.pack('<H', len(d2)), d2)
    c.write(os.path.join(outdir, 'u3v-coverage.pcap'))

    # ---- malformed
    m = Cap()
    m.control_in(3, bytes([0x80, 6, 0, 2, 0, 0, 40, 0]), descriptors()[:9 + 9 + 6],
                 urb_len=len(descriptors()))   # cut descriptor
    full = descriptors()
    m.control_in(3, bytes([0x80, 6, 0, 2, 0, 0, 40, 0]), full[:9 + 9 + 3])
    m.control_in(3, bytes([0x80, 6, 0, 2, 0, 0, 40, 0]), full[:9 + 9 + 12], urb_len=len(full))
    m.control_in(3, bytes([0x80, 6, 0, 2, 0, 0, 40, 0]), full[:9 + 9 + 17], urb_len=len(full))
    m.control_in(3, bytes([0x80, 6, 0, 2, 0, 0, 40, 0]), full[:9 + 9 + 3], urb_len=len(full))
    mg = Gen(m, 3, 0x81, 0x81)
    mg.read(0x1D8, 8, struct.pack('<Q', 0x1000))
    # a write command with a length shorter than its address (the expert info
    # of "U3V: Fix state kept across passes and length handling")
    mg.req += 1
    mg._send(0x81, cmd(WRITE, mg.req, struct.pack('<Q', 0x2000), length=4))
    mg._send(0x81, ack(WRITE_ACK, mg.req, struct.pack('<HH', 0, 0)), True)
    m.comp(3, 0x82, b'\x01\x02')                              # stream payload shorter than a prefix
    mg._send(0x81, cmd(READ, 5, b'\0' * 4))                  # READMEM command cut
    mg._send(0x81, cmd(READ, 6, struct.pack('<QHH', 0x1000, 0, 4))[:14])
    mg._send(0x81, ack(READ_ACK, 6, bytes(4))[:11])
    mg._send(0x81, cmd(EVENT, 8, b'\0\0', prefix=EVT))        # event cut
    mg._send(0x81, cmd(WRITE, 9, b'\x00' * 3, length=3))      # shorter than an address
    mg._send(0x81, cmd(READ, 10, struct.pack('<QHH', 0x2000, 0, 4), length=500))
    mg._send(0x81, ack(PENDING, 10, b'\x00'), True)
    mg._send(0x81, struct.pack('<I', CTRL))                   # prefix only
    mg._send(0x81, struct.pack('<IHH', CTRL, 0, 0x0800))
    m.comp(3, 0x82, struct.pack('<IHHQ', LEAD, 0, 52, 1))     # leader cut
    m.comp(3, 0x82, struct.pack('<IHHQHH', LEAD, 0, 52, 1, 0, 1))     # image leader without the rest
    m.comp(3, 0x82, struct.pack('<IHHQHHQ', LEAD, 0, 52, 1, 0, 1, 5)[:30])
    m.comp(3, 0x82, struct.pack('<IHHQ', TRAIL, 0, 32, 1))    # trailer cut
    m.comp(3, 0x82, struct.pack('<IHHQHH', TRAIL, 0, 32, 1, 0, 0))
    m.write(os.path.join(outdir, 'u3v-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')

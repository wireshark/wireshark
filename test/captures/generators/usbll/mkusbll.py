#!/usr/bin/env python3
# Generates test/captures/usbll_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic USB 2.0 link layer (packet-usbll.c) coverage captures.
# Usage: mkusbll.py <outdir>
# Writes usbll-coverage.pcapng and usbll-coverage-malformed.pcapng.  The
# captures have four interfaces: USB 2.0 high-speed (295), full-speed (294),
# low-speed (293) and unknown speed (288).
import os
import struct
import sys

from usbll_lib import Cap, HS, FS, LS, UNK  # noqa: E402

CTRL, ISO, BULK, INT = 0, 1, 2, 3


def u16(v):
    return struct.pack('<H', v)


def devdesc(mps0, vid, pid):
    return struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, mps0, vid, pid, 0x0100, 1, 2, 3, 1)


def epd(addr, attr, mps, interval):
    return bytes([7, 5, addr, attr]) + u16(mps) + bytes([interval])


def cfgdesc(eps, cls=0xFF, extra=b''):
    # One interface per endpoint: the USB dissector shares one transfer type and
    # packet size between all the endpoints of an interface.
    body = b''
    for n, e in enumerate(eps):
        body += bytes([9, 4, n, 0, 1, cls, 0, 0, 0]) + (extra if n == 0 else b'') + e
    return bytes([9, 2]) + u16(9 + len(body)) + bytes([len(eps), 1, 0, 0x80, 50]) + body


def strdesc(s):
    b = s.encode('utf-16-le')
    return bytes([2 + len(b), 3]) + b


def gdesc(typ, idx, wlen, wval_lang=0):
    return bytes([0x80, 6, idx, typ]) + u16(wval_lang) + u16(wlen)


class G(Cap):
    def __init__(self):
        super().__init__()
        self.tg = {}
        self.marks = []

    def mark(self, name):
        self.marks.append((len(self.pk) + 1, name))

    # data toggle: returns DATA0/DATA1 alternating per (addr, ep, dir)
    def nxt(self, addr, ep, d):
        k = (addr, ep, d)
        p = self.tg.get(k, 0)
        self.tg[k] = p ^ 1
        return 'DATA1' if p else 'DATA0'

    def cur(self, addr, ep, d):
        return 'DATA1' if self.tg.get((addr, ep, d), 0) ^ 1 else 'DATA0'

    def rst(self, addr, ep, d):
        self.tg[(addr, ep, d)] = 0

    # ---------------- control transfers (no split) ----------------
    def setup(self, addr, s8, ep=0):
        self.tok('SETUP', addr, ep)
        self.data('DATA0', s8)
        self.hs('ACK')

    def ctrl_read(self, addr, s8, data, mps, nak=False, retx=False, hs_status=False):
        """SETUP, IN data stage in mps sized packets, OUT status"""
        self.setup(addr, s8)
        wlen = struct.unpack('<H', s8[6:8])[0]
        chunks = [data[i:i + mps] for i in range(0, len(data), mps)] or []
        if len(data) % mps == 0 and len(data) < wlen:
            chunks.append(b'')
        pid = 'DATA1'
        for n, c in enumerate(chunks):
            if nak and n == 0:
                self.tok('IN', addr, 0)
                self.hs('NAK')
            self.tok('IN', addr, 0)
            self.data(pid, c)
            if retx and n == 0:
                # host's ACK lost, device sends the packet again
                self.tok('IN', addr, 0)
                self.data(pid, c)
            self.hs('ACK')
            pid = 'DATA0' if pid == 'DATA1' else 'DATA1'
        if hs_status:
            self.tok('OUT', addr, 0)
            self.data('DATA1')
            self.hs('NYET')
            self.tok('PING', addr, 0)
            self.hs('ACK')
        else:
            self.tok('OUT', addr, 0)
            self.data('DATA1')
            self.hs('ACK')

    def ctrl_write(self, addr, s8, data, mps, nak=False, nyet=False):
        self.setup(addr, s8)
        chunks = [data[i:i + mps] for i in range(0, len(data), mps)]
        pid = 'DATA1'
        for n, c in enumerate(chunks):
            if nak and n == 0:
                self.tok('OUT', addr, 0)
                self.data(pid, c)
                self.hs('NAK')
            self.tok('OUT', addr, 0)
            self.data(pid, c)
            if nyet and n == 0:
                self.hs('NYET')
                self.tok('PING', addr, 0)
                self.hs('NAK')
                self.tok('PING', addr, 0)
                self.hs('ACK')
            else:
                self.hs('ACK')
            pid = 'DATA0' if pid == 'DATA1' else 'DATA1'
        self.tok('IN', addr, 0)
        self.data('DATA1')
        self.hs('ACK')

    def ctrl_nodata(self, addr, s8):
        self.setup(addr, s8)
        self.tok('IN', addr, 0)
        self.data('DATA1')
        self.hs('ACK')

    # ---------------- bulk / interrupt / iso (no split) ----------------
    def bulk_in(self, addr, ep, chunks, nak_first=False, retx_first=False, ack=True):
        for n, c in enumerate(chunks):
            if nak_first and n == 0:
                self.tok('IN', addr, ep)
                self.hs('NAK')
            self.tok('IN', addr, ep)
            pid = self.nxt(addr, ep, 'in')
            self.data(pid, c)
            if retx_first and n == 0:
                self.tok('IN', addr, ep)
                self.data(pid, c)
            if ack:
                self.hs('ACK')

    def bulk_out(self, addr, ep, chunks, hs=False, retx_first=False):
        for n, c in enumerate(chunks):
            pid = self.nxt(addr, ep, 'out')
            self.tok('OUT', addr, ep)
            self.data(pid, c)
            if hs and n == 0:
                self.hs('NYET')
                self.tok('PING', addr, ep)
                self.hs('ACK')
            elif retx_first and n == 0:
                self.hs('NAK')
                if hs:
                    self.tok('PING', addr, ep)
                    self.hs('NAK')
                    self.tok('PING', addr, ep)
                    self.hs('ACK')
                self.tok('OUT', addr, ep)
                self.data(pid, c)
                self.hs('ACK')
            else:
                self.hs('ACK')

    # ---------------- control transfers behind a hub (split) ----------------
    def sp_s(self, hub, port, et, s=0, eu=0):
        self.split(hub, port, 0, s, et, eu)

    def sp_c(self, hub, port, et, s=0, eu=0):
        self.split(hub, port, 1, s, et, eu)

    def sctrl_setup(self, hub, port, s, addr, s8, nak=False):
        self.sp_s(hub, port, CTRL, s)
        self.tok('SETUP', addr, 0)
        self.data('DATA0', s8)
        if nak:
            self.hs('NAK')
            self.sp_s(hub, port, CTRL, s)
            self.tok('SETUP', addr, 0)
            self.data('DATA0', s8)
        self.hs('ACK')
        self.sp_c(hub, port, CTRL, s)
        self.tok('SETUP', addr, 0)
        self.hs('NYET')
        self.sp_c(hub, port, CTRL, s)
        self.tok('SETUP', addr, 0)
        self.hs('ACK')

    def sctrl_in(self, hub, port, s, addr, pid, payload, naks=False, start_nak=False):
        self.sp_s(hub, port, CTRL, s)
        self.tok('IN', addr, 0)
        if start_nak:
            self.hs('NAK')
            self.sp_s(hub, port, CTRL, s)
            self.tok('IN', addr, 0)
        self.hs('ACK')
        if naks:
            self.sp_c(hub, port, CTRL, s)
            self.tok('IN', addr, 0)
            self.hs('NAK')
        self.sp_c(hub, port, CTRL, s)
        self.tok('IN', addr, 0)
        self.hs('NYET')
        self.sp_c(hub, port, CTRL, s)
        self.tok('IN', addr, 0)
        self.data(pid, payload)

    def sctrl_out(self, hub, port, s, addr, pid, payload, naks=False):
        self.sp_s(hub, port, CTRL, s)
        self.tok('OUT', addr, 0)
        self.data(pid, payload)
        if naks:
            self.hs('NAK')
            self.sp_s(hub, port, CTRL, s)
            self.tok('OUT', addr, 0)
            self.data(pid, payload)
        self.hs('ACK')
        self.sp_c(hub, port, CTRL, s)
        self.tok('OUT', addr, 0)
        self.hs('NYET')
        self.sp_c(hub, port, CTRL, s)
        self.tok('OUT', addr, 0)
        self.hs('ACK')

    def sctrl_read(self, hub, port, s, addr, s8, data, mps, naks=False):
        self.sctrl_setup(hub, port, s, addr, s8, nak=naks)
        wlen = struct.unpack('<H', s8[6:8])[0]
        chunks = [data[i:i + mps] for i in range(0, len(data), mps)]
        if len(data) % mps == 0 and len(data) < wlen:
            chunks.append(b'')
        pid = 'DATA1'
        for n, c in enumerate(chunks):
            self.sctrl_in(hub, port, s, addr, pid, c, naks and n == 0, naks and n == 1)
            pid = 'DATA0' if pid == 'DATA1' else 'DATA1'
        self.sctrl_out(hub, port, s, addr, 'DATA1', b'')

    def sctrl_nodata(self, hub, port, s, addr, s8):
        self.sctrl_setup(hub, port, s, addr, s8)
        self.sctrl_in(hub, port, s, addr, 'DATA1', b'')

    def sctrl_write(self, hub, port, s, addr, s8, data, mps):
        self.sctrl_setup(hub, port, s, addr, s8)
        chunks = [data[i:i + mps] for i in range(0, len(data), mps)]
        pid = 'DATA1'
        for n, c in enumerate(chunks):
            self.sctrl_out(hub, port, s, addr, pid, c, n < 2)
            pid = 'DATA0' if pid == 'DATA1' else 'DATA1'
        self.sctrl_in(hub, port, s, addr, 'DATA1', b'')

    def sctrl_stall(self, hub, port, s, addr, out):
        """a control transfer whose data stage is stopped by a STALL (or NAK) at
        the complete split"""
        self.sctrl_setup(hub, port, s, addr, bytes([0x40 if out else 0xC0, 7, 0, 0, 0, 0, 8, 0]))
        self.sp_s(hub, port, CTRL, s)
        if out:
            self.tok('OUT', addr, 0)
            self.data('DATA1', bytes(8))
            self.hs('ACK')
            self.sp_c(hub, port, CTRL, s)
            self.tok('OUT', addr, 0)
            self.hs('NAK')
            self.sp_c(hub, port, CTRL, s)
            self.tok('OUT', addr, 0)
            self.hs('STALL')
        else:
            self.tok('IN', addr, 0)
            self.hs('ACK')
            self.sp_c(hub, port, CTRL, s)
            self.tok('IN', addr, 0)
            self.hs('STALL')

    # bulk behind a hub
    def sbulk_out(self, hub, port, addr, ep, pid, payload, res=('NYET', 'ACK'), start_nak=False):
        self.sp_s(hub, port, BULK)
        self.tok('OUT', addr, ep)
        self.data(pid, payload)
        self.hs('NAK' if start_nak else 'ACK')
        if start_nak:
            return
        for r in res:
            self.sp_c(hub, port, BULK)
            self.tok('OUT', addr, ep)
            self.hs(r)

    def sbulk_in(self, hub, port, addr, ep, pid, payload, pre=('NYET',), end='DATA', start_nak=False):
        self.sp_s(hub, port, BULK)
        self.tok('IN', addr, ep)
        self.hs('NAK' if start_nak else 'ACK')
        if start_nak:
            return
        for r in pre:
            self.sp_c(hub, port, BULK)
            self.tok('IN', addr, ep)
            self.hs(r)
        self.sp_c(hub, port, BULK)
        self.tok('IN', addr, ep)
        if end == 'DATA':
            self.data(pid, payload)
        else:
            self.hs(end)

    # interrupt behind a hub
    def sint_out(self, hub, port, s, addr, ep, pid, payload, res):
        self.sp_s(hub, port, INT, s)
        self.tok('OUT', addr, ep)
        self.data(pid, payload)
        self.sp_c(hub, port, INT, s)
        self.tok('OUT', addr, ep)
        self.hs(res)

    def sint_in(self, hub, port, s, addr, ep, pid, payload, end='DATA'):
        self.sp_s(hub, port, INT, s)
        self.tok('IN', addr, ep)
        self.sp_c(hub, port, INT, s)
        self.tok('IN', addr, ep)
        if end == 'DATA':
            self.data(pid, payload)
        else:
            self.hs(end)

    # isochronous behind a hub
    def siso_out(self, hub, port, addr, ep, payload, se=3):
        # S and E bits carry the position of the data in the OUT payload
        self.split(hub, port, 0, se & 1, 1, se >> 1)
        self.tok('OUT', addr, ep)
        self.data('DATA0', payload)

    def siso_in(self, hub, port, addr, ep, pid, payload, end='DATA'):
        self.split(hub, port, 0, 0, 1)
        self.tok('IN', addr, ep)
        self.split(hub, port, 1, 0, 1)
        self.tok('IN', addr, ep)
        if end == 'DATA':
            self.data(pid, payload)
        else:
            self.hs(end)


def enum_direct(g, speed_mps, addr, dev, cfg, mps0_ctrl_chunk, ctrl_hs=False, str_first=True):
    """GET_DESCRIPTOR(device, 8) at address 0, SET_ADDRESS, device and
    configuration descriptors at the new address."""
    g.ctrl_read(0, gdesc(1, 0, 8), dev[:8], mps0_ctrl_chunk, nak=True)
    g.ctrl_nodata(0, bytes([0, 5, addr, 0, 0, 0, 0, 0]))
    g.ctrl_read(addr, gdesc(1, 0, 18), dev, mps0_ctrl_chunk, hs_status=ctrl_hs)
    g.ctrl_read(addr, gdesc(2, 0, 255), cfg, mps0_ctrl_chunk)


def enum_split(g, hub, port, s, mps0, addr, dev, cfg):
    g.sctrl_read(hub, port, s, 0, gdesc(1, 0, 8), dev[:8], mps0, naks=True)
    g.sctrl_nodata(hub, port, s, 0, bytes([0, 5, addr, 0, 0, 0, 0, 0]))
    g.sctrl_read(hub, port, s, addr, gdesc(1, 0, 18), dev, mps0)
    g.sctrl_read(hub, port, s, addr, gdesc(2, 0, 255), cfg, mps0, naks=True)
    g.sctrl_nodata(hub, port, s, addr, bytes([0, 9, 1, 0, 0, 0, 0, 0]))


def build_main():
    g = G()
    fn = [0]

    def sof(n=1):
        for _ in range(n):
            g.sof(fn[0])
            fn[0] += 1

    # ======= 1. High-speed device at address 5 =======
    g.mark('1. split complete without start split, high-speed device 5')
    g.idb = HS
    # the capture starts in the middle of a split transaction, before any start split
    g.sp_c(98, 5, BULK)
    g.tok('IN', 12, 1)
    g.data('DATA0', bytes(10))
    sof(3)
    d1 = devdesc(64, 0x1D6B, 0x0104)
    c1 = cfgdesc([epd(0x81, BULK, 512, 0), epd(0x02, BULK, 512, 0), epd(0x83, INT, 8, 4),
                  epd(0x84, INT, (1 << 11) | 1024, 1), epd(0x85, ISO, (1 << 11) | 1024, 1),
                  epd(0x06, ISO, (1 << 11) | 1024, 1), epd(0x87, INT, 64, 3), epd(0x08, BULK, 512, 0),
                  epd(0x09, CTRL, 64, 0), epd(0x89, CTRL, 64, 0)])
    assert len(c1) > 64
    enum_direct(g, 64, 5, d1, c1, 64, ctrl_hs=True)
    sof()
    g.ctrl_read(5, gdesc(3, 1, 255, 0x0409), strdesc('Synthetic'), 64, retx=True)
    g.ctrl_nodata(5, bytes([0, 9, 1, 0, 0, 0, 0, 0]))
    sof()
    g.mark('control transfers of device 5')
    # vendor request with an OUT data stage, NYET and PING on the first packet
    g.ctrl_write(5, bytes([0x40, 1, 0, 0, 0, 0, 100, 0]), bytes(range(100)), 64, nyet=True)
    # short OUT data stage, NAKed and sent again
    g.ctrl_write(5, bytes([0x40, 2, 0, 0, 0, 0, 12, 0]), bytes(range(12)), 64, nak=True)
    # IN data stage stalled after the first packet
    g.setup(5, bytes([0xC0, 3, 0, 0, 0, 0, 128, 0]))
    g.tok('IN', 5, 0); g.data('DATA1', bytes(64)); g.hs('ACK')
    g.tok('IN', 5, 0); g.hs('STALL')
    # IN data stage stalled before any data
    g.setup(5, bytes([0xC0, 4, 0, 0, 0, 0, 16, 0]))
    g.tok('IN', 5, 0); g.hs('STALL')
    # OUT data stage stalled on the second packet
    g.setup(5, bytes([0x40, 5, 0, 0, 0, 0, 200, 0]))
    g.tok('OUT', 5, 0); g.data('DATA1', bytes(64)); g.hs('ACK')
    g.tok('OUT', 5, 0); g.data('DATA0', bytes(64)); g.hs('STALL')
    sof()
    g.mark('SETUP to a non-control endpoint, endpoints without descriptors')
    # SETUP to an endpoint that is not a control endpoint
    g.tok('SETUP', 5, 1); g.data('DATA0', bytes([0x40, 1, 0, 0, 0, 0, 0, 0])); g.hs('ACK')
    # data to endpoints without a descriptor
    g.tok('OUT', 5, 7); g.data('DATA0', b'\x01\x02\x03\x04'); g.hs('ACK')
    g.tok('IN', 77, 3); g.data('DATA1', b'\x05\x06'); g.hs('ACK')
    # a control transfer on endpoint 9, which the descriptors declare as control
    g.setup(5, bytes([0xC0, 8, 0, 0, 0, 0, 4, 0]), ep=9)
    g.tok('IN', 5, 9); g.data('DATA1', bytes(4)); g.hs('ACK')
    g.tok('OUT', 5, 9); g.data('DATA1'); g.hs('ACK')
    # a PING to the control endpoint
    g.tok('PING', 5, 0); g.hs('NAK')
    sof()
    g.mark('bulk transfers of device 5')
    # bulk IN: three packets, NAK first, first packet repeated
    g.bulk_in(5, 1, [bytes([i & 255 for i in range(512)]), bytes(512), bytes(100)],
              nak_first=True, retx_first=True)
    # bulk IN ended by a zero length packet
    g.bulk_in(5, 1, [bytes(512), b''])
    # bulk IN, one short packet
    g.bulk_in(5, 1, [b'short in'])
    # bulk OUT: NYET + PING, then a short packet
    g.bulk_out(5, 2, [bytes(512), bytes(512), b'tail'], hs=True)
    # bulk OUT: NAK, PING NAK, PING ACK, packet sent again
    g.bulk_out(5, 2, [bytes(512), b'tail2'], hs=True, retx_first=True)
    g.bulk_out(5, 8, [b'x' * 10])
    sof()
    g.mark('bulk STALL cases')
    # bulk OUT stalled: NYET then PING STALL; NAK then PING STALL; OUT STALL
    g.tok('OUT', 5, 2); g.data(g.nxt(5, 2, 'out'), bytes(512)); g.hs('NYET')
    g.tok('PING', 5, 2); g.hs('STALL')
    g.rst(5, 2, 'out')
    g.tok('OUT', 5, 2); g.data(g.nxt(5, 2, 'out'), bytes(512)); g.hs('NAK')
    g.tok('PING', 5, 2); g.hs('NAK')
    g.tok('PING', 5, 2); g.hs('STALL')
    g.rst(5, 2, 'out')
    g.tok('OUT', 5, 2); g.data(g.nxt(5, 2, 'out'), bytes(512)); g.hs('STALL')
    g.rst(5, 2, 'out')
    g.tok('OUT', 5, 2); g.data('DATA1', bytes(512)); g.hs('STALL')
    g.rst(5, 2, 'out')
    # bulk IN stalled after a full packet
    g.tok('IN', 5, 1); g.data(g.nxt(5, 1, 'in'), bytes(512)); g.hs('ACK')
    g.tok('IN', 5, 1); g.hs('STALL')
    g.rst(5, 1, 'in')
    g.bulk_in(5, 1, [b'after stall'])
    sof()
    g.mark('interrupt and isochronous transfers of device 5')
    # interrupt IN, NAK, STALL
    g.tok('IN', 5, 3); g.data('DATA0', bytes(8)); g.hs('ACK')
    g.tok('IN', 5, 3); g.hs('NAK')
    g.tok('IN', 5, 3); g.data('DATA1', b'abc'); g.hs('ACK')
    g.tok('IN', 5, 3); g.hs('STALL')
    # high-bandwidth interrupt IN: two packets, then a short one
    g.tok('IN', 5, 4); g.data('DATA1', bytes(1024)); g.hs('ACK')
    g.tok('IN', 5, 4); g.data('DATA0', bytes(1024)); g.hs('ACK')
    g.tok('IN', 5, 4); g.data('DATA1', bytes(100)); g.hs('ACK')
    # high-bandwidth isochronous IN (DATA2, DATA1, DATA0) and OUT (MDATA, DATA0)
    sof()
    for pid, n in (("DATA2", 1024), ("DATA1", 1024), ('DATA0', 100)):
        g.tok('IN', 5, 5); g.data(pid, bytes(n))
    g.tok('OUT', 5, 6); g.data('MDATA', bytes(1024))
    g.tok('OUT', 5, 6); g.data('DATA0', bytes(100))
    sof()
    g.mark('LPM and SubPIDs')
    # Link Power Management
    for r in ('ACK', 'NYET', 'STALL'):
        g.tok('EXT', 5, 0); g.lpm(1, 4, 1); g.hs(r)
    g.tok('EXT', 5, 0); g.lpm(0, 0, 0, 1); g.hs('ACK')
    for besl in (1, 2, 5, 7, 15):
        g.tok('EXT', 5, 0); g.lpm(1, besl, 0); g.hs('ACK')
    # SubPIDs that are reserved for future use
    for n in ('MDATA', 'STALL', 'DATA1', 'NAK', 'DATA2', 'NYET', 'ACK', 'EXT'):
        g.tok('EXT', 5, 0); g.hs(n)
    # PRE and ERR PIDs
    g.hs('ERR')
    sof()
    g.mark('full-speed device 6')
    # ======= 2. Full-speed device at address 6 =======
    g.idb = FS
    d2 = devdesc(64, 0x04D8, 0x0053)
    c2 = cfgdesc([epd(0x81, BULK, 64, 0), epd(0x02, BULK, 64, 0), epd(0x83, INT, 8, 10),
                  epd(0x84, ISO, 64, 1), epd(0x05, ISO, 64, 1)])
    sof()
    g.ctrl_read(0, gdesc(1, 0, 8), d2[:8], 64, nak=True)
    g.ctrl_nodata(0, bytes([0, 5, 6, 0, 0, 0, 0, 0]))
    # the maximum packet size of the new address is not known yet: 64 octets
    # are not a short packet, 25 are
    g.ctrl_read(6, gdesc(2, 0, 255), c2, 64)
    g.ctrl_nodata(6, bytes([0, 9, 1, 0, 0, 0, 0, 0]))
    g.bulk_in(6, 1, [bytes(64), bytes(64), bytes(5)])
    g.bulk_in(6, 1, [bytes(64), b''], nak_first=True)
    g.bulk_out(6, 2, [bytes(64), bytes(64), b'end'])
    g.bulk_out(6, 2, [bytes(64), b'end'], retx_first=True)
    g.tok('OUT', 6, 2); g.data(g.nxt(6, 2, 'out'), bytes(64)); g.hs('STALL')
    g.rst(6, 2, 'out')
    g.tok('IN', 6, 3); g.data('DATA0', bytes(8)); g.hs('ACK')
    g.tok('IN', 6, 3); g.data('DATA1', bytes(2)); g.hs('ACK')
    g.tok('IN', 6, 4); g.data('DATA0', bytes(64))
    g.tok('OUT', 6, 5); g.data('DATA0', bytes(64))
    sof()
    g.mark('low-speed device 7')
    # ======= 3. Low-speed device at address 7, multi-packet control =======
    g.idb = LS
    d3 = devdesc(8, 0x046D, 0xC016)
    c3 = cfgdesc([epd(0x81, INT, 8, 10)], cls=3, extra=bytes([9, 0x21, 0x10, 0x01, 0, 1, 0x22, 50, 0]))
    sof()
    g.ctrl_read(0, gdesc(1, 0, 8), d3[:8], 8)
    g.ctrl_nodata(0, bytes([0, 5, 7, 0, 0, 0, 0, 0]))
    g.ctrl_read(7, gdesc(1, 0, 18), d3, 8, retx=True)
    g.ctrl_read(7, gdesc(2, 0, 255), c3, 8)
    g.ctrl_nodata(7, bytes([0, 9, 1, 0, 0, 0, 0, 0]))
    g.ctrl_write(7, bytes([0x21, 9, 0, 2, 0, 0, 12, 0]), bytes(range(12)), 8)
    g.tok('IN', 7, 1); g.data('DATA0', bytes(8)); g.hs('ACK')
    g.tok('IN', 7, 1); g.data('DATA1', bytes(4)); g.hs('ACK')
    g.sof(fn[0])
    g.mark('unknown speed')
    # ======= 4. Unknown speed =======
    g.idb = UNK
    sof()
    g.ctrl_read(0, gdesc(1, 0, 8), devdesc(64, 1, 2)[:8], 64)
    g.ctrl_nodata(0, bytes([0, 5, 9, 0, 0, 0, 0, 0]))
    g.tok('OUT', 9, 1); g.data('DATA0', b'unknown speed'); g.hs('ACK')
    g.mark('split transactions behind hub 3')
    # ======= 5. Full-speed and low-speed devices behind a high-speed hub =======
    g.idb = HS
    H = 3
    d4 = devdesc(8, 0x1234, 0x6001)
    c4 = cfgdesc([epd(0x81, BULK, 64, 0), epd(0x02, BULK, 64, 0), epd(0x83, INT, 8, 10),
                  epd(0x84, ISO, 64, 1), epd(0x05, ISO, 64, 1)])
    sof()
    enum_split(g, H, 2, 0, 8, 10, d4, c4)
    # a vendor OUT request with data behind the hub
    g.sctrl_write(H, 2, 0, 10, bytes([0x40, 1, 0, 0, 0, 0, 12, 0]), bytes(range(12)), 8)
    g.sctrl_stall(H, 2, 0, 10, True)
    g.sctrl_stall(H, 2, 0, 10, False)
    g.mark('split bulk')
    sof()
    # bulk OUT: NYET, ACK; NAK at the start; NAK at the complete split
    g.sbulk_out(H, 2, 10, 2, 'DATA0', bytes(64))
    g.sbulk_out(H, 2, 10, 2, 'DATA1', bytes(10), res=('NAK', 'NYET', 'ACK'))
    g.sbulk_out(H, 2, 10, 2, 'DATA0', bytes(64), start_nak=True)
    g.sbulk_out(H, 2, 10, 2, 'DATA1', bytes(64), start_nak=True)
    g.sbulk_out(H, 2, 10, 2, 'DATA0', bytes(64), res=('STALL',))
    # bulk IN: data, NAK at the complete split, NYET, STALL, NAK at the start
    g.sbulk_in(H, 2, 10, 1, 'DATA0', bytes(64))
    g.sbulk_in(H, 2, 10, 1, 'DATA1', bytes(64), pre=('NAK', 'NYET'))
    g.sbulk_in(H, 2, 10, 1, 'DATA0', bytes(9), pre=())
    g.sbulk_in(H, 2, 10, 1, None, None, pre=('NYET',), end='STALL')
    g.sbulk_in(H, 2, 10, 1, None, None, start_nak=True)
    g.sbulk_in(H, 2, 10, 1, 'DATA1', bytes(64))
    g.sbulk_in(H, 2, 10, 1, None, None, pre=(), end='STALL')
    sof()
    g.mark('split interrupt')
    # interrupt OUT: ACK, NAK, STALL, NYET, ERR
    for pid, res in (('DATA0', 'ACK'), ('DATA1', 'NAK'), ('DATA0', 'STALL'), ('DATA1', 'NYET')):
        g.sint_out(H, 2, 0, 10, 3, pid, bytes(8), res)
    g.sint_out(H, 2, 0, 10, 3, 'DATA0', bytes(8), 'ERR')
    # interrupt IN: DATA0, DATA1, MDATA then DATA0, NAK, STALL, NYET, ERR
    g.sint_in(H, 2, 0, 10, 3, 'DATA0', bytes(8))
    g.sint_in(H, 2, 0, 10, 3, 'DATA1', bytes(3))
    g.sint_in(H, 2, 0, 10, 3, 'MDATA', bytes(8))
    g.sint_in(H, 2, 0, 10, 3, 'DATA0', bytes(2))
    for e in ('NAK', 'STALL', 'NYET', 'ERR'):
        g.sint_in(H, 2, 0, 10, 3, None, None, e)
    sof()
    g.mark('split isochronous')
    # isochronous: OUT (all, begin, middle, end), IN data, MDATA, ERR, NYET
    for se in (3, 1, 0, 2):
        g.siso_out(H, 2, 10, 5, bytes(64), se)
    g.siso_in(H, 2, 10, 4, 'DATA0', bytes(64))
    g.siso_in(H, 2, 10, 4, 'MDATA', bytes(64))
    g.siso_in(H, 2, 10, 4, None, None, 'ERR')
    g.siso_in(H, 2, 10, 4, None, None, 'NYET')
    # an isochronous start split that is followed by a SOF
    g.split(H, 2, 0, 0, 1)
    sof()
    g.mark('low-speed device 11 on port 4')
    # low-speed device on port 4 (S bit set)
    d5 = devdesc(8, 0x046D, 0xC31C)
    c5 = cfgdesc([epd(0x81, INT, 8, 10)], cls=3)
    enum_split(g, H, 4, 1, 8, 11, d5, c5)
    g.sint_in(H, 4, 1, 11, 1, 'DATA0', bytes(8))
    g.sint_in(H, 4, 1, 11, 1, 'DATA1', bytes(8))
    # complete split without a start split (capture started in the middle)
    g.sp_c(H, 99, BULK)
    g.tok('IN', 12, 1)
    g.data('DATA0', bytes(10))
    g.sp_c(H, 98, CTRL)
    g.tok('SETUP', 12, 0)
    g.hs('ACK')
    sof()
    g.mark('end')
    return g


def build_malformed():
    g = G()
    g.idb = HS
    # bad CRCs
    g.sof(5, bad=True)
    g.tok('IN', 5, 1, bad=True)
    g.split(3, 2, 0, 0, 2, bad=True)
    g.lpm(bad=True)
    g.tok('SETUP', 7, 0)
    g.data('DATA0', bytes(8), bad=True)
    g.hs('ACK')
    # invalid PIDs
    g.hs(0x00)
    g.hs(0xFF, b'\x01')
    g.hs(0x11)
    # handshake and data without a transaction
    g.sof(1)
    g.hs('ACK')
    g.hs('NAK')
    g.data('DATA0', b'abc')
    g.data('DATA1', b'abc')
    g.data('DATA2', b'abc')
    g.data('MDATA', b'abc')
    g.hs('NYET')
    g.hs('STALL')
    # data in the wrong place
    g.tok('IN', 3, 1)
    g.data('DATA2', b'x')
    g.tok('IN', 3, 1)
    g.data('MDATA', b'x')
    g.tok('OUT', 3, 1)
    g.data('DATA2', b'x')
    g.tok('OUT', 3, 1)
    g.hs('ACK')
    g.tok('PING', 3, 1)
    g.data('DATA0', b'x')
    g.tok('SETUP', 3, 0)
    g.data('DATA1', bytes(8))
    g.tok('SETUP', 3, 0)
    g.hs('ACK')
    # trailing bytes
    g.sof(2, extra=b'\x00')
    g.tok('IN', 3, 1, extra=b'\x00\x01')
    g.hs('ACK', b'\x00')
    # SETUP data that is not 8 bytes long
    g.tok('SETUP', 3, 0)
    g.data('DATA0', bytes(7))
    g.hs('ACK')
    g.tok('SETUP', 3, 0)
    g.data('DATA0', bytes(9))
    g.hs('ACK')
    # subpids
    for n in ('SETUP', 'ERR', 'IN', 'SPLIT', 'SOF', 'PING', 'OUT'):
        g.tok('EXT', 3, 0)
        g.hs(n)              # PIDs that cannot be reused as SubPIDs
    g.tok('EXT', 3, 0)
    g.hs(0x2D, b'\x00\x00')   # conflicts with SETUP
    g.tok('EXT', 3, 0)
    g.hs(0x00, b'\x00\x00')   # invalid
    g.tok('EXT', 3, 0)
    g.lpm()
    g.hs('DATA0')
    # truncated packets
    g.add(b'\x69\x01')
    g.add(b'\xA5')
    g.add(b'\x78\x01\x02')
    g.add(b'\xC3')
    g.add(b'\xC3\x00')
    g.add(b'\x2D')
    g.add(b'\xB4\x00')
    g.add(b'\xF0')
    g.add(b'\xC3\x01')
    # control transfers with unexpected PIDs
    g.tok('SETUP', 8, 0)
    g.data('DATA0', bytes([0xC0, 6, 0, 1, 0, 0, 18, 0]))
    g.hs('ACK')
    g.tok('IN', 8, 0)
    g.data('DATA0', bytes(8))          # DATA0 straight after SETUP
    g.hs('ACK')
    g.tok('IN', 8, 0)
    g.data('DATA2', bytes(8))          # DATA2 in a control transfer
    g.hs('ACK')
    g.tok('SETUP', 8, 0)
    g.data('DATA0', bytes([0x40, 6, 0, 1, 0, 0, 18, 0]))
    g.hs('ACK')
    g.tok('OUT', 8, 0)
    g.data('DATA0', bytes(8))          # DATA0 straight after SETUP, OUT
    g.hs('ACK')
    g.tok('OUT', 8, 0)
    g.data('MDATA', bytes(8))
    g.hs('ACK')
    # split packets with bits that must be zero
    g.split(3, 2, 0, 1, 2)            # bulk start with the speed bit
    g.tok('OUT', 9, 2)
    g.data('DATA0', b'x')
    g.hs('ACK')
    g.split(3, 2, 0, 0, 2, eu=1)      # E bit
    g.tok('OUT', 9, 2)
    g.data('DATA0', b'x')
    g.hs('ACK')
    g.split(3, 2, 1, 0, 2, eu=1)      # U bit of a complete split
    g.tok('OUT', 9, 2)
    g.hs('ACK')
    g.split(3, 2, 0, 0, 0, eu=1)
    g.tok('IN', 9, 0)
    g.hs('ACK')
    g.split(3, 2, 0, 1, 1)            # isochronous IN start with the speed bit
    g.tok('IN', 9, 4)
    g.split(3, 2, 1, 1, 1, eu=1)
    g.tok('IN', 9, 4)
    g.hs('ACK')
    g.split(3, 2, 0, 1, 1)
    g.tok('IN', 9, 4)
    g.split(3, 2, 0, 0, 1, eu=1)      # isochronous IN start with the E bit
    g.tok('IN', 9, 4)
    # handshakes that do not fit the split transaction
    g.split(3, 2, 1, 0, 3)
    g.tok('OUT', 9, 3)
    g.hs('NAK')
    g.split(3, 2, 0, 0, 3)
    g.hs('ACK')
    g.split(3, 2, 1, 0, 3)
    g.hs('ACK')
    g.split(3, 2, 1, 0, 1)
    g.data('DATA0', b'zz')
    g.split(3, 2, 1, 0, 0)
    g.data('DATA1', b'zz')
    g.sof(3)
    return g


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m = build_main()
    m.write(os.path.join(out, 'usbll-coverage.pcapng'))
    x = build_malformed()
    x.write(os.path.join(out, 'usbll-coverage-malformed.pcapng'))
    print(len(m.pk), 'frames in the main capture,', len(x.pk), 'in the malformed one')
    if '-v' in sys.argv:
        for n, name in m.marks:
            print('%5d  %s' % (n, name))

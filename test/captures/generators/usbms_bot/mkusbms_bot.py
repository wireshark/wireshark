#!/usr/bin/env python3
# Generates test/captures/usbms_bot_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB mass storage Bulk-Only Transport coverage captures (packet-usbms-bot.c).

usage: mkusbms_bot.py <outdir> [-v]
Writes usbms-bot-coverage.pcapng and usbms-bot-coverage-malformed.pcapng.
Devices (Linux usbmon, 64 octet header, bus 1 unless noted):
  2  BOT disk (interface 8/6/0x50): class requests, SCSI commands on LUN 0 and 1
  3  BOT CD-ROM-like device on USBPcap (bus 3), CSW and data before any CBW
  5  device without descriptors: the bulk heuristic ("ms_usb_bulk")
  6  UAS device: a Command IU, then a CBW signature on the command pipe
     (BOT must leave it to the UAS dissector, see the fix "Return the
     dissector result from the heuristic")
  7  Bulk-Only alternate setting whose interface was given to UAS by its pipe usage
     descriptors: the class data belongs to another class (not dissected as BOT)
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mscgen import (
    BOT_GET_MAX_LUN, bot_ifaces, BOT_RESET, BULK, Bus, cbw, CBW_SIG, cdb_inquiry, cdb_mode_sense6,
    cdb_prevent, cdb_read10, cdb_read16, cdb_read_capacity10, cdb_read_toc, cdb_report_luns,
    cdb_request_sense, cdb_start_stop, cdb_sync_cache, cdb_tur, cdb_write10, cfg_desc, CLS_IF_IN,
    CLS_IF_OUT, csw, dev_desc, inquiry_data, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng, sense_data,
    setup, uas_ifaces,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


class Disk:
    """One BOT device: sends commands as CBW, optional data, CSW."""

    def __init__(self, bus, dev, ep_in=0x81, ep_out=0x02):
        self.bus, self.dev, self.ei, self.eo = bus, dev, ep_in, ep_out
        self.tag = 0x100

    def out(self, data):
        self.bus.xfer(self.dev, self.eo, BULK, data)

    def inn(self, data):
        self.bus.xfer(self.dev, self.ei, BULK, data)

    def cmd(self, cdb, datalen=0, direction_in=True, lun=0, data=b'', status=0, residue=0,
            cblen=None, concat=False):
        """CBW, data stage, CSW. concat joins the data and the CSW of an IN
        transfer into one bulk transfer."""
        self.tag += 1
        flags = 0x80 if direction_in else 0
        self.out(cbw(self.tag, datalen, flags, lun, cdb, cblen))
        c = csw(self.tag, residue, status)
        if data and direction_in and concat:
            self.inn(data + c)
            return
        if data and direction_in:
            self.inn(data)
        elif data:
            self.out(data)
        self.inn(c)


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)

    s0 = w.count
    mm.enumerate(2, dev_desc(vid=0x0951, pid=0x1666), cfg_desc(bot_ifaces()))
    mm.control(2, setup(CLS_IF_IN, BOT_GET_MAX_LUN, 0, 0, 1), b'\x02')
    mm.control(2, setup(CLS_IF_OUT, BOT_RESET, 0, 0, 0))
    mm.control(2, setup(0x21, 0x77, 0, 0, 0))       # an unknown class request: no BOT dissector for it
    mark(w, 'device 2 enumeration, Get Max LUN, Reset', s0)

    s0 = w.count
    d = Disk(mm, 2)
    d.cmd(cdb_tur(), status=1)                                          # not ready
    d.cmd(cdb_request_sense(), 18, True, data=sense_data())             # its sense data
    d.cmd(cdb_inquiry(96), 96, True, data=inquiry_data())
    d.cmd(cdb_inquiry(evpd=1, page=0x80), 20, True, data=bytes([0, 0x80, 0, 16]) + b'SN0123456789ABCD')
    d.cmd(cdb_tur())
    d.cmd(cdb_read_capacity10(), 8, True, data=struct.pack('>II', 0x3fffff, 512))
    d.cmd(cdb_mode_sense6(), 192, True, data=bytes([3, 0, 0, 0]), residue=188)
    d.cmd(cdb_prevent())
    d.cmd(cdb_read10(0, 1), 512, True, data=bytes(range(256)) * 2)
    d.cmd(cdb_write10(8, 1), 512, False, data=bytes(range(255, -1, -1)) * 2)
    d.cmd(cdb_read10(16, 2), 1024, True, data=b'\xa5' * 1024, status=1, residue=512)
    d.cmd(cdb_read16(1 << 33, 1), 512, True, data=b'\x5a' * 512)
    d.cmd(cdb_sync_cache())
    d.cmd(cdb_start_stop(1, 0), status=2)                                # phase error
    d.cmd(bytes([0xc0]) + bytes(9), 0, True)                             # vendor command
    d.cmd(b'', 0, True, cblen=0)                                         # CDB length 0
    mark(w, 'device 2 SCSI commands', s0)

    s0 = w.count
    # a second LUN and a target number in the same byte, a 6 octet CDB in a 16 octet field
    d.cmd(cdb_inquiry(96), 96, True, lun=0x11, data=inquiry_data(devtype=5, product=b'SYNTH CD', removable=True))
    d.cmd(cdb_read_toc(), 12, True, lun=0x11, data=bytes([0, 10, 1, 1]) + bytes(8))
    d.cmd(cdb_read10(0, 1), 2048, True, lun=0x11, data=b'\x3c' * 2048)
    d.cmd(cdb_report_luns(), 16, True, lun=0, data=struct.pack('>II', 16, 0) + bytes(8) + bytes([0, 1]) + bytes(6))
    mark(w, 'device 2 LUN 1 (target 1) CD-ROM', s0)

    s0 = w.count
    # Data and status in one bulk transfer, data and the next command in one
    # transfer (the USB link layer does not split them)
    d.cmd(cdb_read10(32, 1), 512, True, data=b'\x11' * 512, concat=True)
    d.tag += 1
    d.out(cbw(d.tag, 4, 0, 0, cdb_write10(40, 1)))
    d.tag += 1
    d.out(b'\xde\xad\xbe\xef' + cbw(d.tag, 96, 0x80, 0, cdb_inquiry(96)))   # data out + the next CBW
    d.inn(inquiry_data() + csw(d.tag, 0, 0))                             # data in + CSW
    d.tag += 1
    d.out(cbw(d.tag, 4, 0, 0, cdb_write10(48, 1)))
    d.out(b'\x01\x02\x03\x04' + csw(d.tag, 0, 0))                           # data out + a CSW (not valid for an OUT)
    d.inn(csw(d.tag, 0, 0))
    # a READ whose declared length is much larger than the data transferred (the reproducer of
    # the exercise capture of the review: payload subset longer than the transfer)
    d.tag += 1
    d.out(cbw(d.tag, 0xfffffff0, 0x80, 0, cdb_read10(0, 8), cblen=0x1f))
    d.inn(b'\xa5' * 64)
    d.inn(csw(d.tag, 0, 0))
    mark(w, 'device 2 data with CSW and CBW concatenated, huge declared length', s0)

    s0 = w.count
    # USBPcap device: a CSW and data before any CBW (no ITLQ yet), then a normal exchange
    pc.enumerate(3, dev_desc(vid=0x13fe, pid=0x4300), cfg_desc(bot_ifaces(sub=2)))
    pd = Disk(pc, 3)
    pd.inn(csw(0x77, 0, 0))                      # CSW with no command before
    pd.inn(b'data in with no command before')    # data in, no ITLQ for it
    pd.out(b'data out with no command before')
    pd.cmd(cdb_inquiry(96), 96, True, data=inquiry_data(devtype=5))
    pd.cmd(cdb_read10(0, 1), 2048, True, data=b'\x00' * 2048)
    mark(w, 'USBPcap device 3, data and CSW without a command', s0)

    s0 = w.count
    # a device whose descriptors were not captured: the heuristic recognises the signatures
    mm.get_desc(5, 1, 0, dev_desc(vid=0x0781, pid=0x5567), 18)
    hd = Disk(mm, 5)
    hd.cmd(cdb_inquiry(96), 96, True, data=inquiry_data(devtype=0))
    hd.cmd(cdb_read10(0, 1), 512, True, data=b'\x22' * 512)
    hd.out(b'USBC' + b'x' * 36)                  # signature, but not a 31 octet CBW: handled as data
    hd.inn(b'USBS' + b'y' * 20)
    hd.out(b'\x01\x02\x03')                      # shorter than the signature: not claimed
    hd.out(b'plain bytes that are not BOT')      # no signature: not claimed
    mark(w, 'device 5, bulk heuristic', s0)

    s0 = w.count
    # UAS interface: a Command IU on the command pipe, then a CBW signature on the same pipe.
    # The BOT heuristic must not claim it because the endpoint belongs to UAS.
    cfg = cfg_desc(bot_ifaces(eps=((0x81, 2, 512), (0x02, 2, 512))) + uas_ifaces(alt=1, cmd=0x01, sta=0x82, din=0x83, dout=0x04), nif=1)
    mm.enumerate(6, dev_desc(vid=0x174c, pid=0x55aa), cfg)
    mm.control(6, setup(0x01, 11, 1, 0, 0))     # SET_INTERFACE 0 alt 1
    iu = struct.pack('>BBHBBBB', 1, 0, 1, 0, 0, 0, 0) + bytes(8) + cdb_tur().ljust(16, b'\0')
    mm.xfer(6, 0x01, BULK, iu)
    mm.xfer(6, 0x01, BULK, cbw(2, 0, 0, 0, cdb_tur()))
    mark(w, 'device 6, UAS endpoint with a CBW signature', s0)

    s0 = w.count
    # Bulk-Only alternate setting 0 and UAS alternate setting 1 in one configuration, no SET_INTERFACE: the pipe usage
    # descriptors give the interface to UAS, so the Bulk-Only table dissector finds class data of another class
    cfg = cfg_desc(bot_ifaces(eps=((0x81, 2, 512), (0x02, 2, 512))) + uas_ifaces(alt=1, cmd=0x01, sta=0x82, din=0x83, dout=0x04), nif=1)
    mm.enumerate(7, dev_desc(vid=0x0bda, pid=0x0316), cfg)
    bd = Disk(mm, 7)
    bd.out(cbw(1, 0, 0, 0, cdb_tur()))
    bd.inn(csw(1, 0, 0))
    mark(w, 'device 7, Bulk-Only interface owned by UAS', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(), cfg_desc(bot_ifaces()))
    d = Disk(mm, 2)
    # truncated CBW (30 octets) and CSW (12 octets) are data, not commands
    d.out(cbw(1, 0, 0, 0, cdb_tur())[:30])
    d.inn(csw(1, 0, 0)[:12])
    # Get Max LUN and Reset with unexpected lengths
    mm.control(2, setup(CLS_IF_IN, BOT_GET_MAX_LUN, 0, 0, 1), b'')
    mm.control(2, setup(CLS_IF_OUT, BOT_RESET, 0, 0, 0), b'xx')
    # a CBW with CDB length 31 (masked to 0x1f) and 16 octets of CDB: the CDB tvb is longer than the packet
    d.out(cbw(2, 0, 0, 0, cdb_tur(), cblen=0x1f)[:31])
    d.out(struct.pack('<IIIBBB', CBW_SIG, 3, 512, 0x80, 0, 6) + cdb_inquiry())   # CBW 6 + 6 = 25 octets
    d.out(cbw(4, 0, 0, 0, cdb_tur(), cblen=6) + b'x')                            # 32 octets: not a CBW
    # CSW with all status values, unknown status
    for st in (0, 1, 2, 3, 0xff):
        d.cmd(cdb_tur(), status=st)
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usbms-bot-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usbms-bot-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-60s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

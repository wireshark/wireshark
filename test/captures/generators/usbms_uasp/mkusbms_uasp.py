#!/usr/bin/env python3
# Generates test/captures/usbms_uasp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB Attached SCSI coverage captures (packet-usbms-uasp.c).

usage: mkusbms_uasp.py <outdir> [-v]
Writes usbms-uasp-coverage.pcapng and usbms-uasp-coverage-malformed.pcapng.
Devices (Linux usbmon, 64 octet header, bus 1 unless noted):
  2  UAS disk: alternate setting 0 is Bulk-Only, alternate setting 1 is UAS with
     pipe usage descriptors (command 0x01, status 0x82, data-in 0x83, data-out 0x04)
  3  UAS device on USBPcap (bus 3) with pipe usage descriptors in another order
  4  UAS interface whose configuration has no pipe usage descriptor for the data pipes
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mscgen import (
    bot_ifaces, BULK, Bus, cbw, cdb_inquiry, cdb_mode_sense6, cdb_prevent, cdb_read10,
    cdb_read_capacity10, cdb_sync_cache, cdb_tur, cdb_write10, cfg_desc, csw, dev_desc, ep_desc,
    if_desc, inquiry_data, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng, sense_data, setup, uas_ifaces,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

CMD, STA, DIN, DOUT = 0x01, 0x82, 0x83, 0x04
IU_CMD, IU_SENSE, IU_RESP, IU_TM, IU_RREADY, IU_WREADY = 1, 3, 4, 5, 6, 7


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def lun8(n, volume_set=False):
    """SCSI LUN field: peripheral device addressing, or volume set addressing (bit 6) with a 14 bit LUN."""
    if volume_set:
        return struct.pack('>H', 0x4000 | n) + bytes(6)
    return bytes([0, n]) + bytes(6)


def iu_cmd(tag, cdb, lun=0, prio=0, attr=0, add=0, volume_set=False):
    """Command IU: 16 octet header, LUN at offset 8, CDB from offset 16 (16 + `add` octets)."""
    return (struct.pack('>BBHBBBB', IU_CMD, 0, tag, (prio << 3) | attr, 0, add, 0) +
            lun8(lun, volume_set) + cdb.ljust(16 + add, b'\0'))


def iu_sense(tag, status=0, qual=0, sense=b'', length=None):
    return (struct.pack('>BBHHB', IU_SENSE, 0, tag, qual, status) + bytes(7) +
            struct.pack('>H', len(sense) if length is None else length) + sense)


def iu_resp(tag, info=0, code=0):
    return struct.pack('>BBH', IU_RESP, 0, tag) + info.to_bytes(3, 'big') + bytes([code])


def iu_tm(tag, func, managed, lun=0):
    return struct.pack('>BBHBBH', IU_TM, 0, tag, func, 0, managed) + lun8(lun)


def iu_ready(kind, tag):
    return struct.pack('>BBH', kind, 0, tag)


class Uas:
    def __init__(self, bus, dev, cmd=CMD, sta=STA, din=DIN, dout=DOUT):
        self.bus, self.dev = bus, dev
        self.cmd_ep, self.sta_ep, self.din_ep, self.dout_ep = cmd, sta, din, dout
        self.tag = 0

    def x(self, ep, data):
        self.bus.xfer(self.dev, ep, BULK, data)

    def command(self, cdb, lun=0, **kw):
        self.tag += 1
        self.x(self.cmd_ep, iu_cmd(self.tag, cdb, lun, **kw))
        return self.tag

    def read(self, cdb, data, lun=0, status=0, sense=b'', qual=0, **kw):
        t = self.command(cdb, lun, **kw)
        self.x(self.sta_ep, iu_ready(IU_RREADY, t))
        self.x(self.din_ep, data)
        self.x(self.sta_ep, iu_sense(t, status, qual, sense))
        return t

    def write(self, cdb, data, lun=0, status=0, sense=b'', **kw):
        t = self.command(cdb, lun, **kw)
        self.x(self.sta_ep, iu_ready(IU_WREADY, t))
        self.x(self.dout_ep, data)
        self.x(self.sta_ep, iu_sense(t, status, 0, sense))
        return t

    def nodata(self, cdb, lun=0, status=0, sense=b'', qual=0, **kw):
        t = self.command(cdb, lun, **kw)
        self.x(self.sta_ep, iu_sense(t, status, qual, sense))
        return t


def uas_config(order=(1, 2, 3, 4), pipes=True):
    """Alternate setting 0: Bulk-Only; alternate setting 1: UAS."""
    b = bot_ifaces(eps=((0x81, 2, 512), (0x02, 2, 512)))
    if pipes:
        b += uas_ifaces(alt=1, pipe_order=order)
    else:
        b += if_desc(0, 1, 4, 8, 6, 0x62)
        for a in (CMD, STA, DIN, DOUT):
            b += ep_desc(a, 2, 512)
    return cfg_desc(b, nif=1)


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)

    s0 = w.count
    mm.enumerate(2, dev_desc(vid=0x174c, pid=0x55aa), uas_config())
    mm.control(2, setup(0x01, 11, 1, 0, 0))                     # SET_INTERFACE 0, alternate setting 1 (UAS)
    mark(w, 'device 2 enumeration (pipe usage descriptors), alternate setting 1', s0)

    s0 = w.count
    u = Uas(mm, 2)
    u.nodata(cdb_tur(), status=2, sense=sense_data(2, 0x3a, 0), qual=1)         # CHECK CONDITION with sense data
    u.read(cdb_inquiry(96), inquiry_data())
    u.read(cdb_read_capacity10(), struct.pack('>II', 0xfffff, 512))
    u.read(cdb_read10(0, 1), bytes(range(256)) * 2, prio=3, attr=2)              # priority and task attribute
    u.write(cdb_write10(8, 1), b'\xa5' * 512)
    u.write(cdb_write10(9, 1), b'\x5a' * 512, status=2, sense=sense_data(3, 0x0c, 0))   # write error with sense
    u.read(cdb_mode_sense6(), bytes([3, 0, 0, 0]))
    u.nodata(cdb_prevent())
    u.nodata(cdb_sync_cache())
    mark(w, 'device 2 SCSI commands: Command, Read/Write Ready, data, Sense IUs', s0)

    s0 = w.count
    u.read(cdb_read10(0, 1), b'\x01' * 512, lun=1)                               # LUN 1
    u.read(cdb_read10(0, 1), b'\x02' * 512, lun=0x123, volume_set=True)          # volume set addressing (LUN 0x123)
    # a variable length CDB: 16 octets of additional CDB
    u.read(bytes([0x7f, 0, 0, 0, 0, 0, 0, 0x18, 0x00, 0x09]) + bytes(22), b'\x03' * 512, add=16)
    mark(w, 'device 2 LUNs and an additional CDB', s0)

    s0 = w.count
    t = u.command(cdb_read10(100, 1))
    u.x(STA, iu_tm(0x40, 1, t, 0))                   # Task Management IU on the status pipe
    u.x(CMD, iu_tm(0x40, 1, t, 0))                   # abort task for the command above (host to device)
    u.x(STA, iu_resp(0x40, 0, 0))                     # response: task management function complete
    u.x(STA, iu_resp(0x41, 0x010203, 8))              # response with additional info
    u.x(STA, iu_sense(t, 6, 0, b''))                  # sense IU that completes the command (status ABORTED / task aborted)
    u.x(CMD, iu_tm(0x42, 2, 0x99, 1))                  # abort task set, other LUN, tag of no known command
    u.x(CMD, struct.pack('>BBH', 0x77, 0, 0x55) + b'\0\0')   # an IU ID that is not defined
    mark(w, 'device 2 Task Management and Response IUs, unknown IU', s0)

    s0 = w.count
    # IUs for tags that have no command, data before any ready IU
    u.x(STA, iu_sense(0x7000, 0, 0, b''))                # Sense IU without a Command IU
    u.x(STA, iu_ready(IU_RREADY, 0x7001))              # Read Ready without a command
    u.x(STA, iu_ready(IU_WREADY, 0x7002))
    mm.xfer(2, DIN, BULK, b'data in with the tag of a ready IU that has no command')
    mm.xfer(2, DOUT, BULK, b'data out with the tag of a ready IU that has no command')
    mm.xfer(2, 0x05, BULK, b'bulk on an endpoint with no pipe usage descriptor')   # not a UAS pipe of the device
    u.x(CMD, b'\x01\x00\x00')                         # shorter than an IU header
    mark(w, 'device 2 IUs without a matching command', s0)

    s0 = w.count
    # reused tag: the second command with tag 1 is a new ITLQ nexus
    t2 = 1
    u.x(CMD, iu_cmd(t2, cdb_tur()))
    u.x(STA, iu_sense(t2, 0, 0, b''))
    mark(w, 'device 2 reused tag', s0)

    s0 = w.count
    # USBPcap, pipe usage descriptors in another order (status, data-out, data-in, command)
    pc.enumerate(3, dev_desc(vid=0x152d, pid=0x0578), uas_config(order=(2, 4, 3, 1)))
    pc.control(3, setup(0x01, 11, 1, 0, 0))
    pu = Uas(pc, 3)
    pu.read(cdb_inquiry(96), inquiry_data(devtype=5, product=b'UAS CD'))
    pu.read(cdb_read10(0, 1), b'\x00' * 2048)
    pu.nodata(cdb_tur())
    mark(w, 'USBPcap device 3, pipes in another order', s0)

    s0 = w.count
    # UAS with no pipe usage descriptor for the data pipes: only command and status are known
    cfg = cfg_desc(bot_ifaces(eps=((0x81, 2, 512), (0x02, 2, 512))) + if_desc(0, 1, 4, 8, 6, 0x62) +
                   ep_desc(CMD, 2, 512) + bytes([4, 0x24, 1, 0]) + ep_desc(STA, 2, 512) + bytes([4, 0x24, 2, 0]) +
                   ep_desc(DIN, 2, 512) + ep_desc(DOUT, 2, 512) +
                   bytes([4, 0x24, 9, 0]) +                    # a pipe usage descriptor with an undefined pipe ID
                   bytes([5, 0x25, 1, 2, 3]))                  # a class-specific descriptor of another type
    mm.enumerate(4, dev_desc(vid=0x0bc2, pid=0xab21), cfg)
    mm.control(4, setup(0x01, 11, 1, 0, 0))
    nu = Uas(mm, 4)
    nu.command(cdb_inquiry(96))
    nu.x(STA, iu_sense(1, 0, 0, b''))
    mm.xfer(4, DIN, BULK, b'data-in pipe without a usage descriptor')
    mm.xfer(4, DOUT, BULK, b'data-out pipe without a usage descriptor')
    mark(w, 'device 4, no pipe usage descriptors for the data pipes', s0)
    s0 = w.count
    # The first configuration read stops after alternate setting 0 (Bulk-Only) and Bulk-Only traffic follows. Then the
    # whole configuration is read and the interface switches to UAS: the conversation already belongs to Bulk-Only,
    # so UAS leaves it alone (pipe usage descriptors and IUs)
    cfg5 = uas_config()
    mm.get_desc(5, 1, 0, dev_desc(vid=0x04e8, pid=0x61f5), 18)
    mm.get_desc(5, 2, 0, cfg5[:9], 9)
    mm.get_desc(5, 2, 0, cfg5[:32], 32)      # the first read is cut after alternate setting 0 (Bulk-Only)
    mm.control(5, setup(0x00, 9, 1))
    mm.xfer(5, 0x02, BULK, cbw(1, 0, 0, 0, cdb_tur()))
    mm.xfer(5, 0x81, BULK, csw(1, 0, 0))
    mm.get_desc(5, 2, 0, cfg5, len(cfg5))
    mm.control(5, setup(0x01, 11, 1, 0, 0))
    mm.xfer(5, CMD, BULK, iu_cmd(1, cdb_tur()))
    mm.xfer(5, STA, BULK, iu_sense(1, 0, 0, b''))
    mark(w, 'device 5, conversation owned by Bulk-Only', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(), uas_config())
    mm.control(2, setup(0x01, 11, 1, 0, 0))
    u = Uas(mm, 2)
    # truncated IUs: a Command IU cut after the LUN, a Sense IU with a sense length larger than the data,
    # a Sense IU cut inside its header, a Response IU of 5 octets, a Task Management IU of 6 octets
    u.x(CMD, iu_cmd(1, cdb_tur())[:12])
    u.x(CMD, iu_cmd(2, cdb_inquiry(96)))
    u.x(STA, iu_sense(2, 2, 0, sense_data(), length=0xffff))
    u.x(STA, iu_sense(2, 0, 0, b'')[:10])
    u.x(STA, iu_resp(3)[:5])
    u.x(CMD, iu_tm(4, 1, 2)[:6])
    # additional CDB length larger than the IU
    u.x(CMD, iu_cmd(5, cdb_tur(), add=0xff)[:40])
    u.x(CMD, iu_cmd(6, cdb_tur())[:16])
    # a Command IU on the data-in pipe, read ready with a very short IU
    u.x(STA, struct.pack('>BBH', IU_RREADY, 0, 7)[:4])
    # pipe usage descriptor of 2 octets (invalid length) in a configuration
    cfg = cfg_desc(bot_ifaces(eps=((0x81, 2, 512), (0x02, 2, 512))) + if_desc(0, 1, 1, 8, 6, 0x62) +
                   ep_desc(0x01, 2, 512) + bytes([3, 0x24, 1]))
    mm.enumerate(3, dev_desc(), cfg)
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usbms-uasp-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usbms-uasp-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-70s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

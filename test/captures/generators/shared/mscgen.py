#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers for synthetic USB mass storage captures (BOT, UAS, CBI).

Everything is built with struct; nothing comes from a real device.
"""
import struct
from usbgen import (
    BULK, Bus, cfg_desc, dev_desc, ep_desc, if_desc, INT, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng,
    setup,
)

CBW_SIG, CSW_SIG = 0x43425355, 0x53425355

# class requests of the Bulk-Only Transport
BOT_GET_MAX_LUN, BOT_RESET = 0xfe, 0xff
CLS_IF_IN, CLS_IF_OUT = 0xa1, 0x21


def cbw(tag, datalen, flags, lun, cdb, cblen=None, sig=CBW_SIG, pad=16):
    return struct.pack('<IIIBBB', sig, tag, datalen, flags, lun,
                       len(cdb) if cblen is None else cblen) + cdb.ljust(pad, b'\0')


def csw(tag, residue, status, sig=CSW_SIG):
    return struct.pack('<IIIB', sig, tag, residue, status)


def inquiry_data(vendor=b'WSTEST', product=b'SYNTH DISK', rev=b'1.0', devtype=0, removable=True, n=96):
    d = bytes([devtype, 0x80 if removable else 0, 6, 2, n - 5, 0, 0, 0])
    d += vendor.ljust(8)[:8] + product.ljust(16)[:16] + rev.ljust(4)[:4]
    return d.ljust(n, b'\0')[:n]


def sense_data(key=2, asc=0x3a, ascq=0):
    return bytes([0x70, 0, key, 0, 0, 0, 0, 10, 0, 0, 0, 0, asc, ascq, 0, 0, 0, 0])


# CDBs
def cdb_tur():
    return bytes(6)


def cdb_inquiry(alloc=96, evpd=0, page=0):
    return bytes([0x12, evpd, page, 0, alloc, 0])


def cdb_request_sense(alloc=18):
    return bytes([0x03, 0, 0, 0, alloc, 0])


def cdb_read_capacity10():
    return bytes([0x25]) + bytes(9)


def cdb_read10(lba, blocks):
    return struct.pack('>BBIBHB', 0x28, 0, lba, 0, blocks, 0)


def cdb_write10(lba, blocks):
    return struct.pack('>BBIBHB', 0x2a, 0, lba, 0, blocks, 0)


def cdb_read16(lba, blocks):
    return struct.pack('>BBQIBB', 0x88, 0, lba, blocks, 0, 0)


def cdb_mode_sense6(page=0x3f, alloc=192):
    return bytes([0x1a, 0, page, 0, alloc, 0])


def cdb_prevent(prevent=1):
    return bytes([0x1e, 0, 0, 0, prevent, 0])


def cdb_sync_cache():
    return bytes([0x35]) + bytes(9)


def cdb_start_stop(loej=1, start=0):
    return bytes([0x1b, 0, 0, 0, (loej << 1) | start, 0])


def cdb_read_toc(alloc=12):
    return struct.pack('>BBBBBBBHB', 0x43, 0, 0, 0, 0, 0, 0, alloc, 0)


def cdb_report_luns(alloc=64):
    return struct.pack('>BBBBBBIBB', 0xa0, 0, 0, 0, 0, 0, alloc, 0, 0)


# descriptors
def bot_ifaces(proto=0x50, sub=6, cls=8, eps=((0x81, 2, 512), (0x02, 2, 512)), iface=0, alt=0, extra=b''):
    b = if_desc(iface, alt, len(eps), cls, sub, proto) + extra
    for a, t, m in eps:
        b += ep_desc(a, t, m)
    return b


def uas_ifaces(iface=0, alt=1, cmd=0x01, sta=0x82, din=0x83, dout=0x04, pipe_order=(1, 2, 3, 4)):
    b = if_desc(iface, alt, 4, 8, 6, 0x62)
    eps = {1: cmd, 2: sta, 3: din, 4: dout}
    for pid in pipe_order:
        b += ep_desc(eps[pid], 2, 512) + bytes([4, 0x24, pid, 0])
    return b

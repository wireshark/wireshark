#!/usr/bin/env python3
# Generates test/captures/usb_ptp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB PTP/MTP coverage captures (packet-usb-ptp.c).

usage: mkusb_ptp.py <outdir> [-v]
Writes usb-ptp-coverage.pcapng and usb-ptp-coverage-malformed.pcapng.

PTP is dissected on the bulk endpoints of an interface of class 6, subclass 1,
protocol 1. Container types are Command, Data, Response and Event; events
travel on the interrupt endpoint in a real device, which the PTP dissector is
not registered for, so the capture sends them on the bulk IN endpoint.
Devices (Linux usbmon, 64 octet header, bus 1 unless noted):
  2   generic PTP camera: a full session, every payload decoder
  3   MTP player (vendor extension 6): the MTP opcode tables after GetDeviceInfo;
      a command sent before GetDeviceInfo is decoded with the PTP tables in one
      and in two passes (the fix "Keep the vendor flavor stable across
      dissection passes"); a later GetDeviceInfo without the MTP extension
      switches the tables back
  4..13 one device per vendor of the flavor table: Canon, Nikon, Fuji, Kodak,
      Casio, Olympus, Leica, Parrot, Panasonic, Sony
  14  PTP camera on USBPcap (bus 3)
  15  interface of class 6 (alternate setting 0, PTP) that UAS owns through the pipe
      usage descriptors of its alternate setting 1: the PTP dissector finds class data
      of another class and leaves the transfers alone
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    BULK, Bus, cfg_desc, dev_desc, ep_desc, if_desc, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng,
)
from mscgen import uas_ifaces

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

T_CMD, T_DATA, T_RSP, T_EVT = 1, 2, 3, 4

OC_GETDEVICEINFO, OC_OPENSESSION, OC_CLOSESESSION = 0x1001, 0x1002, 0x1003
OC_GETSTORAGEIDS, OC_GETSTORAGEINFO, OC_GETOBJECTHANDLES = 0x1004, 0x1005, 0x1007
OC_GETOBJECTINFO, OC_GETOBJECT, OC_GETDEVICEPROPDESC = 0x1008, 0x1009, 0x1014
OC_SETDEVICEPROPVALUE = 0x1016
OC_GETOBJECTPROPSSUPPORTED, OC_GETOBJECTPROPDESC = 0x9801, 0x9802


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def container(typ, code, tid, payload=b'', length=None):
    return struct.pack('<IHHI', 12 + len(payload) if length is None else length, typ, code, tid) + payload


def ucs2(s):
    """PTP string: number of characters including the terminating NUL, then UCS-2; empty is a single 0."""
    if not s:
        return b'\x00'
    s += '\0'
    return bytes([len(s)]) + s.encode('utf-16-le')


def arr16(vals):
    return struct.pack('<I', len(vals)) + b''.join(struct.pack('<H', v) for v in vals)


def arr32(vals):
    return struct.pack('<I', len(vals)) + b''.join(struct.pack('<I', v) for v in vals)


def devinfo(ext_id=0, ext_desc='', ops=(0x1001, 0x1002, 0x1003, 0x1004, 0x1007, 0x9001, 0x9801),
            evts=(0x4002, 0x400d, 0xc001), props=(0x5001, 0x5003, 0xd001), capf=(0x3801,),
            imgf=(0x3801, 0x3000, 0x3804), mfr='Wireshark Test', model='Synthetic Camera', ver='1.0',
            serial='0001'):
    d = struct.pack('<HIH', 100, ext_id, 100) + ucs2(ext_desc) + struct.pack('<H', 0)
    d += arr16(ops) + arr16(evts) + arr16(props) + arr16(capf) + arr16(imgf)
    d += ucs2(mfr) + ucs2(model) + ucs2(ver) + ucs2(serial)
    return d


def ptp_config():
    b = (if_desc(0, 0, 3, 6, 1, 1) + ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512) +
         ep_desc(0x83, 3, 8, 6))
    return cfg_desc(b)


class Cam:
    def __init__(self, bus, dev, eo=0x02, ei=0x81):
        self.bus, self.dev, self.eo, self.ei = bus, dev, eo, ei
        self.tid = 0

    def out(self, data):
        self.bus.xfer(self.dev, self.eo, BULK, data)

    def inn(self, data):
        self.bus.xfer(self.dev, self.ei, BULK, data)

    def cmd(self, code, *params):
        self.tid += 1
        self.out(container(T_CMD, code, self.tid, b''.join(struct.pack('<I', p) for p in params)))

    def data_in(self, code, payload):
        self.inn(container(T_DATA, code, self.tid, payload))

    def data_out(self, code, payload):
        self.out(container(T_DATA, code, self.tid, payload))

    def resp(self, code=0x2001, *params):
        self.inn(container(T_RSP, code, self.tid, b''.join(struct.pack('<I', p) for p in params)))

    def event(self, code, *params):
        self.inn(container(T_EVT, code, 0xffffffff, b''.join(struct.pack('<I', p) for p in params)))


def session(c, cam_name='Synthetic'):
    """A typical session on any camera (generic opcodes only)."""
    c.cmd(OC_GETDEVICEINFO)
    c.data_in(OC_GETDEVICEINFO, devinfo())
    c.resp()
    c.cmd(OC_OPENSESSION, 1)
    c.resp()
    c.cmd(OC_GETSTORAGEIDS)
    c.data_in(OC_GETSTORAGEIDS, arr32([0x00010001, 0x00020001]))
    c.resp()


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)

    s0 = w.count
    mm.enumerate(2, dev_desc(vid=0x1234, pid=0x5678), ptp_config())
    c = Cam(mm, 2)
    session(c)
    c.cmd(OC_GETSTORAGEINFO, 0x00010001)
    c.cmd(OC_GETOBJECTHANDLES, 0xffffffff, 0, 0)
    c.data_in(OC_GETOBJECTHANDLES, arr32([1, 2, 3]))
    c.resp()
    c.cmd(OC_GETOBJECTHANDLES, 0x00020001, 0, 0)
    c.data_in(OC_GETOBJECTHANDLES, arr32([]))                       # empty array
    c.resp()
    c.cmd(OC_GETOBJECTINFO, 1)
    c.data_in(OC_GETOBJECTINFO, bytes(range(64)))                   # a data block without a decoder: generic payload
    c.resp()
    c.cmd(OC_GETOBJECT, 1)
    c.data_in(OC_GETOBJECT, b'\xff\xd8\xff\xe0' + b'JFIF' + bytes(100))
    c.resp()
    mark(w, 'device 2 session start: GetDeviceInfo, OpenSession, storage and object commands', s0)

    s0 = w.count
    c.cmd(OC_GETDEVICEPROPDESC, 0x5001)                             # parameter is a device property code
    c.data_in(OC_GETDEVICEPROPDESC, struct.pack('<HHB', 0x5001, 2, 0) + bytes(8))
    c.resp()
    c.cmd(OC_SETDEVICEPROPVALUE, 0x5005)                            # command with the property code as its only parameter
    c.data_out(OC_SETDEVICEPROPVALUE, struct.pack('<H', 2))         # the new value (data out, no decoder)
    c.resp()
    c.cmd(OC_GETDEVICEPROPDESC, 0x5fff)                             # property code not in the table: "Unknown"
    c.resp(0x200a)                                                  # response code InvalidDevicePropCode
    c.cmd(0x9999, 1, 2, 3)                                          # opcode nobody knows
    c.resp(0x2005)                                                  # OperationNotSupported
    c.cmd(OC_GETOBJECTPROPSSUPPORTED, 0x3801)                        # MTP-only opcode with a format code parameter
    c.data_in(OC_GETOBJECTPROPSSUPPORTED, arr16([0xdc01, 0xdc02, 0xdc03, 0xdc07]))
    c.resp()
    c.cmd(OC_GETOBJECTPROPDESC, 0xdc07, 0x3801)                      # property code and format code
    c.resp(0x2001, 0x1234)                                          # a response with a parameter
    c.cmd(0x1010)                                                    # ResetDevice: a command without parameters
    c.resp(0x2002)
    c.cmd(OC_CLOSESESSION)
    c.resp()
    mark(w, 'device 2 properties, unknown opcode, MTP-only opcodes with PTP tables', s0)

    s0 = w.count
    c.event(0x4002, 0x00000010)                                      # ObjectAdded
    c.event(0x400d, 0)                                               # StoreFull-like, no parameter value kept
    c.event(0xc001, 1, 2, 3)                                         # a vendor event code, three parameters
    c.event(0x4004)                                                  # an event without parameters
    c.event(0x4fff, 7)                                               # event code not in the table
    mark(w, 'device 2 events on the bulk endpoint', s0)

    s0 = w.count
    # MTP: the reproducer first. GetObjectPropsSupported is an MTP opcode; before GetDeviceInfo has told us
    # that the device is MTP, it is decoded with the PTP tables ("UNKNOWN") in one pass and in two passes.
    mm.enumerate(3, dev_desc(vid=0x045e, pid=0x00f1), ptp_config())
    m = Cam(mm, 3)
    m.cmd(OC_GETOBJECTPROPSSUPPORTED, 0x3000)
    m.resp(0x2005)
    m.cmd(OC_GETDEVICEINFO)
    m.data_in(OC_GETDEVICEINFO, devinfo(ext_id=6, ext_desc='microsoft.com: 1.0; android.com: 1.0;', ops=(0x1001, 0x9801, 0x9802, 0x9803, 0x9810),
                                        mfr='Synthetic MTP', model='Player'))
    m.resp()
    m.cmd(OC_GETOBJECTPROPSSUPPORTED, 0x3000)                         # now an MTP command
    m.data_in(OC_GETOBJECTPROPSSUPPORTED, arr16([0xdc01, 0xdc02, 0xdc04, 0xdc41]))
    m.resp()
    m.cmd(OC_GETOBJECTPROPDESC, 0xdc01, 0x3000)
    m.resp()
    m.cmd(0x9805, 1, 0xdc01)                                          # GetObjPropList, generic parameters
    m.resp(0xa801)                                                    # an MTP response code
    m.event(0xc801, 1)                                                # an MTP event code
    # a device that is not MTP any more (device info with vendor extension 0)
    m.cmd(OC_GETDEVICEINFO)
    m.data_in(OC_GETDEVICEINFO, devinfo(ext_id=0, ops=(0x1001,), evts=(), props=(), capf=(), imgf=()))
    m.resp()
    m.cmd(OC_GETOBJECTPROPSSUPPORTED, 0x3000)                         # PTP tables again: UNKNOWN
    m.resp(0x2005)
    mark(w, 'device 3 MTP: opcode tables before and after GetDeviceInfo, back to PTP', s0)

    vendors = [(4, 0x04a9, 'Canon', (0x9001, 0x9003, 0x9006, 0x9013), 0xc000, 0xa101, 0xd001),
               (5, 0x04b0, 'Nikon', (0x9001, 0x9006, 0x9008, 0x9201), 0xc101, 0xa001, 0xd001),
               (6, 0x04cb, 'Fuji', (0x9020, 0x9021, 0x9022, 0x9026), 0xc001, 0xa001, 0xd001),
               (7, 0x040a, 'Kodak', (0x9001, 0x9003, 0x9006, 0x9008), 0xc001, 0xa001, 0xd001),
               (8, 0x07cf, 'Casio', (0x9001, 0x9002, 0x9007, 0x9009), 0xc001, 0xa001, 0xd001),
               (9, 0x07b4, 'Olympus', (0x9001, 0x9101, 0x9102, 0x9301), 0xc001, 0xa001, 0xd001),
               (10, 0x1a98, 'Leica', (0x9001, 0x9003, 0x9005, 0x9007), 0xc001, 0xa001, 0xd001),
               (11, 0x19cf, 'Parrot', (0x9001, 0x9201, 0x9202, 0x9203), 0xc001, 0xa001, 0xd001),
               (12, 0x04da, 'Panasonic', (0x9101, 0x9102, 0x9108, 0x9401), 0xc001, 0xa001, 0xd001),
               (13, 0x054c, 'Sony', (0x9201, 0x9202, 0x9205, 0x9207), 0xc201, 0xa001, 0xd201)]
    for dev, vid, name, ops, evt, rsp, prop in vendors:
        s0 = w.count
        mm.enumerate(dev, dev_desc(vid=vid, pid=0x0100 + dev), ptp_config())
        v = Cam(mm, dev)
        v.cmd(OC_GETDEVICEINFO)
        v.data_in(OC_GETDEVICEINFO, devinfo(mfr=name, ops=ops, evts=(evt,), props=(prop,)))
        v.resp()
        for op in ops:
            v.cmd(op, 1)
            v.resp(rsp)
        v.cmd(OC_GETDEVICEPROPDESC, prop)
        v.event(evt, 5)
        mark(w, 'device %d vendor %s' % (dev, name), s0)

    s0 = w.count
    pc.enumerate(14, dev_desc(vid=0x04a9, pid=0x3199), ptp_config())
    p = Cam(pc, 14)
    session(p)
    p.cmd(0x9001, 4)
    p.resp(0xa101)
    mark(w, 'USBPcap device 14 (Canon)', s0)
    s0 = w.count
    both = cfg_desc(if_desc(0, 0, 2, 6, 1, 1) + ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512) +
                    uas_ifaces(alt=1, cmd=0x01, sta=0x82, din=0x83, dout=0x04))
    mm.enumerate(15, dev_desc(vid=0x1234, pid=0x9999), both)
    o = Cam(mm, 15)
    o.cmd(OC_GETDEVICEINFO)
    o.resp()
    mark(w, 'device 15, PTP interface owned by UAS', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    # class 6 interface that is not PTP (subclass 1, protocol 2): "Not dissected yet"
    nonptp = cfg_desc(if_desc(0, 0, 2, 6, 1, 2) + ep_desc(0x81, 2, 512) + ep_desc(0x02, 2, 512))
    mm.enumerate(2, dev_desc(), nonptp)
    mm.xfer(2, 0x02, BULK, container(T_CMD, 0x1001, 1))
    mm.xfer(2, 0x81, BULK, container(T_RSP, 0x2001, 1))
    mm.enumerate(3, dev_desc(vid=0x04a9), ptp_config())
    c = Cam(mm, 3)
    # container type that is not defined, with and without payload
    c.out(container(0, 0x1001, 1))
    c.out(container(9, 0x1001, 2, b'\x01\x02\x03\x04'))
    # arrays whose count is larger than the data, strings longer than the data
    c.cmd(OC_GETSTORAGEIDS)
    c.data_in(OC_GETSTORAGEIDS, struct.pack('<I', 1000) + struct.pack('<II', 1, 2))
    c.cmd(OC_GETOBJECTPROPSSUPPORTED, 0)
    c.data_in(OC_GETOBJECTPROPSSUPPORTED, struct.pack('<I', 0xffffffff) + b'\x01\xdc')
    c.cmd(OC_GETDEVICEINFO)
    c.data_in(OC_GETDEVICEINFO, devinfo()[:40])                      # cut in the middle of the arrays
    c.cmd(OC_GETDEVICEINFO)
    c.data_in(OC_GETDEVICEINFO, struct.pack('<HIH', 100, 6, 100) + bytes([200]) + b'ab')   # string longer than the data
    # truncated containers: 6 octets, and a command whose parameter is cut
    c.out(container(T_CMD, 0x1001, 3)[:6])
    c.out(container(T_CMD, OC_SETDEVICEPROPVALUE, 4)[:12] + b'\x01\x02')
    c.out(container(T_CMD, OC_GETOBJECTPROPDESC, 5, struct.pack('<I', 0xdc01)))   # second parameter missing
    c.out(container(T_CMD, 0x9999, 6, b'\x01\x02\x03'))              # parameters that are not a multiple of 4
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-ptp-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-ptp-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-70s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

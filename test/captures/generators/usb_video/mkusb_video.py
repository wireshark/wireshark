#!/usr/bin/env python3
# Generates test/captures/usb_video_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the USB Video Class coverage captures (packet-usb-video.c).

usage: mkusb_video.py <outdir> [-v]
Writes usb-video-coverage.pcapng and usb-video-coverage-malformed.pcapng.
Devices (Linux usbmon, 64 octet header, bus 1 unless noted):
  2  UVC 1.1 camera: interface association, VideoControl interface with every
     terminal and unit descriptor, class-specific interrupt endpoint, VideoStreaming
     interface with uncompressed, MJPEG and frame based formats; all class requests,
     probe/commit controls and interrupt status packets
  3  UVC 1.0 style device on USBPcap (bus 3): 26 octet probe, processing unit
     without bmVideoStandards, selector and extension units with other sizes
  4  device with a video interface collection (subclass 3) and an interface with
     undefined subclass: class descriptors nobody decodes
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from usbgen import (
    Bus, cfg_desc, dev_desc, ep_desc, iad_desc, if_desc, INT, LT_USB_LINUX_MM, LT_USBPCAP, Pcapng,
    setup,
)

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
RANGES = []

SET_CUR, SET_CUR_ALL = 0x01, 0x11
GET_CUR, GET_MIN, GET_MAX, GET_RES, GET_LEN, GET_INFO, GET_DEF = 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
GET_CUR_ALL, GET_MIN_ALL, GET_MAX_ALL, GET_RES_ALL, GET_DEF_ALL = 0x91, 0x92, 0x93, 0x94, 0x97

# entities of the VideoControl interface
CT, OT_STREAM, SU, PU, XU, IT_MT, IT_VEND, EU, OT_DISP, OT_MT = 1, 3, 4, 5, 6, 7, 8, 9, 10, 11
VC_IF, VS_IF = 0, 1

YUY2 = bytes.fromhex('59555932000010008000' '00aa00389b71')
NV12 = bytes.fromhex('4e563132000010008000 00aa00389b71'.replace(' ', ''))
H264G = bytes.fromhex('48323634000010008000 00aa00389b71'.replace(' ', ''))


def mark(w, name, start):
    RANGES.append((name, start + 1, w.count))


def cs_if(sub, body):
    return bytes([3 + len(body), 0x24, sub]) + body


def cs_ep(sub, body):
    return bytes([3 + len(body), 0x25, sub]) + body


# ---- VideoControl descriptors
def vc_header(total, nvs=1, ifs=(1,), bcd=0x0110, clock=48000000):
    return cs_if(1, struct.pack('<HHIB', bcd, total, clock, nvs) + bytes(ifs))


def vc_it(tid, ttype, assoc=0, istr=0, extra=b''):
    return cs_if(2, struct.pack('<BHBB', tid, ttype, assoc, istr) + extra)


def camera_extra(fmin=0, fmax=0, focal=0, controls=(0x0e, 0x0a, 0x00)):
    return struct.pack('<HHH', fmin, fmax, focal) + bytes([len(controls)]) + bytes(controls)


def vc_ot(tid, ttype, src, assoc=0, istr=0, extra=b''):
    return cs_if(3, struct.pack('<BHBBB', tid, ttype, assoc, src, istr) + extra)


def vc_su(uid, sources=(1, 7), istr=0):
    return cs_if(4, bytes([uid, len(sources)]) + bytes(sources) + bytes([istr]))


def vc_pu(uid, src, mult=0x4000, controls=(0xff, 0x05, 0x00), istr=0, standards=0x1f):
    b = bytes([uid, src]) + struct.pack('<H', mult) + bytes([len(controls)]) + bytes(controls) + bytes([istr])
    if standards is not None:
        b += bytes([standards])
    return cs_if(5, b)


def vc_xu(uid, guid, nctrl=8, sources=(5,), controls=(0xff,), istr=0):
    return cs_if(6, bytes([uid]) + guid + bytes([nctrl, len(sources)]) + bytes(sources) +
                 bytes([len(controls)]) + bytes(controls) + bytes([istr]))


# ---- VideoStreaming descriptors
def vs_input_header(nformats, total, ep=0x81, info=1, link=OT_STREAM, still=2, trigger=1, usage=0, csize=1, controls=None):
    controls = controls if controls is not None else [0x3f] * nformats
    b = bytes([nformats]) + struct.pack('<H', total) + bytes([ep, info, link, still, trigger, usage, csize])
    for c in controls:
        b += bytes([c]) * csize if isinstance(c, int) else bytes(c)
    return cs_if(1, b)


def vs_format_unc(idx, nframes, guid=YUY2, bpp=16, default=1, ax=4, ay=3, interlace=0x00, copy=0, sub=4):
    return cs_if(sub, bytes([idx, nframes]) + guid + bytes([bpp, default, ax, ay, interlace, copy]))


def vs_format_mjpeg(idx, nframes, flags=1, default=1, ax=16, ay=9, interlace=0x0f, copy=1):
    return cs_if(6, bytes([idx, nframes, flags, default, ax, ay, interlace, copy]))


def vs_format_fb(idx, nframes, guid=H264G, bpp=0, default=1, ax=16, ay=9, interlace=0, copy=0, variable=1):
    return cs_if(0x10, bytes([idx, nframes]) + guid + bytes([bpp, default, ax, ay, interlace, copy, variable]))


def vs_frame(idx, w, h, intervals=(333333, 666666), continuous=None, caps=3, sub=5, maxsize=None, bpl=None):
    """sub 5 uncompressed, 7 MJPEG, 0x11 frame based (no max frame size, bytes per line)."""
    b = bytes([idx, caps]) + struct.pack('<HHII', w, h, w * h * 2 * 8, w * h * 2 * 30)
    if sub != 0x11:
        b += struct.pack('<I', w * h * 2 if maxsize is None else maxsize)
    b += struct.pack('<I', 333333)
    if continuous:
        b += bytes([0])
        if sub == 0x11:
            b += struct.pack('<I', 0 if bpl is None else bpl)
        b += struct.pack('<III', *continuous)
    else:
        b += bytes([len(intervals)])
        if sub == 0x11:
            b += struct.pack('<I', 0 if bpl is None else bpl)
        b += b''.join(struct.pack('<I', i) for i in intervals)
    return cs_if(sub, b)


def vs_color(p=1, t=1, m=4):
    return cs_if(0x0d, bytes([p, t, m]))


def video_config(mt_total_pad=0):
    """UVC 1.1 camera: VC interface 0 (14/1/0) with an interrupt endpoint and VS interface 1 (14/2/0)."""
    xguid = bytes.fromhex('2d1a05a4 5a4a 4d3a 8a26 7c3e5d1a9bc1'.replace(' ', ''))
    units = (vc_it(CT, 0x0201, 0, 0, camera_extra(0, 0, 0, (0x0e, 0x0a, 0x0a))) +
             vc_su(SU, (CT, IT_MT)) +
             vc_pu(PU, SU) +
             vc_xu(XU, xguid, 8, (PU,), (0xff, 0x00, 0x00)) +
             vc_it(IT_MT, 0x0202, 0, 0, b'\x00\x00\x00') +                 # media transport input: bytes beyond the generic fields
             vc_it(IT_VEND, 0x0200) +                                      # vendor specific input terminal
             cs_if(7, bytes([EU, PU, 0, 1, 2, 3])) +                       # encoding unit (UVC 1.5): not decoded
             vc_ot(OT_STREAM, 0x0101, PU) +
             vc_ot(OT_DISP, 0x0301, PU) +
             vc_ot(OT_MT, 0x0302, PU, extra=b'\x00\x01'))
    hdr_len = len(vc_header(0, 1, (1,)))
    vc_total = hdr_len + len(units)
    vc = (if_desc(0, 0, 1, 14, 1, 0, istr=0) + vc_header(vc_total) + units +
          ep_desc(0x87, 3, 16, 6) + cs_ep(3, struct.pack('<H', 16)) +
          cs_ep(1, b'\x00\x01\x02'))                                        # class-specific endpoint, subtype other than interrupt
    vs_forms = (vs_format_unc(1, 2) +
                vs_frame(1, 640, 480, continuous=(333333, 1000000, 333333)) +
                vs_frame(2, 1280, 720, intervals=(333333, 400000, 1000000)) +
                vs_color() +
                vs_format_mjpeg(2, 2) +
                vs_frame(1, 1920, 1080, intervals=(333333,), sub=7) +
                vs_frame(2, 320, 240, continuous=(333333, 2000000, 333333), sub=7, caps=0) +
                vs_color(2, 7, 5) +
                vs_format_fb(3, 2) +
                vs_frame(1, 800, 600, intervals=(166666, 333333), sub=0x11, bpl=1600) +
                vs_frame(2, 1024, 768, continuous=(166666, 1000000, 166666), sub=0x11, bpl=2048) +
                vs_format_unc(4, 1, guid=NV12, bpp=12, sub=4, interlace=0x0f) +
                vs_frame(1, 352, 288, intervals=(333333,)) +
                cs_if(3, bytes([0, 2, 640 & 255, 640 >> 8, 480 & 255, 480 >> 8, 0]) + b'\x00\x00') +   # still image frame (not decoded)
                cs_if(0x0a, bytes([5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) +                       # MPEG2-TS format (not decoded)
                cs_if(0x30, b'\x01\x02\x03'))                                                          # a subtype that does not exist
    vs_total = len(vs_input_header(4, 0)) + len(vs_forms)
    vs = if_desc(1, 0, 0, 14, 2, 0) + vs_input_header(4, vs_total, controls=[1, 2, 3, 0x3f]) + vs_forms + \
        if_desc(1, 1, 1, 14, 2, 0) + ep_desc(0x81, 5, 0x0400, 1)
    iad = iad_desc(0, 2, 14, 3, 0)
    return cfg_desc(iad + vc + vs, nif=2)


def pu_config_v10():
    """UVC 1.0 device: processing unit without bmVideoStandards, control size 2."""
    units = (vc_it(1, 0x0201, 0, 0, camera_extra(10, 20, 15, (0x02, 0x00))) +
             vc_pu(2, 1, controls=(0x0f, 0x00), standards=None) +
             vc_su(4, (1,)) +
             vc_xu(6, bytes(range(16)), 4, (2, 4), tuple(range(12)))  +       # control size 12: shown as bytes
             vc_ot(3, 0x0101, 2))
    total = len(vc_header(0, 1, (1,), bcd=0x0100)) + len(units)
    vc = if_desc(0, 0, 0, 14, 1, 0) + vc_header(total, bcd=0x0100) + units
    vs = if_desc(1, 0, 0, 14, 2, 0) + vs_input_header(1, 20, ep=0x82, trigger=0, controls=[0]) + \
        vs_format_unc(1, 1) + vs_frame(1, 160, 120, intervals=(333333,))
    return cfg_desc(vc + vs, nif=2)


def probe(hint=0x0001, fmt=1, frame=1, interval=333333, kf=0, pf=0, q=5000, window=0, delay=32, maxframe=614400,
          maxpayload=3072, extended=True, clock=48000000, framing=3, pref=1, minv=0, maxv=255, uvc15=False):
    b = struct.pack('<HBBIHHHHHII', hint, fmt, frame, interval, kf, pf, q, window, delay, maxframe, maxpayload)
    if extended:
        b += struct.pack('<IBBBB', clock, framing, pref, minv, maxv)
    if uvc15:
        b += bytes(14)
    return b


def main_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    if_pc = w.idb(LT_USBPCAP)
    mm = Bus(w, 'mm', if_mm, bus=1)
    pc = Bus(w, 'pcap', if_pc, bus=3)

    def cls(dev, bus, req, sel, entity, intf, data=b'', dir_in=None, length=None, status=0, recip=1):
        """A class request to an interface (recipient 1), or an endpoint (2). Reads (bRequest >= 0x81) return data."""
        reading = (req & 0x80) != 0
        bm = (0xa0 if reading else 0x20) | recip
        wlen = (len(data) if length is None else length)
        if reading:
            bus.control(dev, setup(bm, req, sel << 8, (entity << 8) | intf, wlen), data, status=status)
        else:
            bus.control(dev, setup(bm, req, sel << 8, (entity << 8) | intf, wlen), out_data=data, status=status)

    s0 = w.count
    cfg = video_config()
    mm.enumerate(2, dev_desc(cls=0xef, sub=2, proto=1, vid=0x046d, pid=0x0825), cfg)
    mark(w, 'device 2 enumeration: every VC and VS descriptor', s0)

    s0 = w.count
    # VideoControl interface requests (entity 0)
    cls(2, mm, GET_CUR, 0x01, 0, VC_IF, b'\x00')                    # power mode
    cls(2, mm, SET_CUR, 0x01, 0, VC_IF, b'\x01')
    cls(2, mm, GET_CUR, 0x02, 0, VC_IF, b'\x00')                    # request error code: no error
    cls(2, mm, GET_CUR, 0x02, 0, VC_IF, b'\x06')                    # invalid control
    cls(2, mm, GET_CUR, 0x02, 0, VC_IF, b'\xff')
    cls(2, mm, GET_INFO, 0x01, 0, VC_IF, b'\x03')
    cls(2, mm, GET_CUR, 0x30, 0, VC_IF, b'\x00')                    # control selector not in the table: "Interface 0 control 0x30"
    mark(w, 'device 2 VideoControl interface requests', s0)

    s0 = w.count
    # camera terminal
    cls(2, mm, GET_CUR, 0x01, CT, VC_IF, b'\x00')                   # scanning mode
    cls(2, mm, SET_CUR, 0x02, CT, VC_IF, b'\x02')                   # auto exposure mode
    cls(2, mm, GET_CUR, 0x04, CT, VC_IF, struct.pack('<I', 156))    # exposure time (absolute), 4 octets
    cls(2, mm, GET_MIN, 0x04, CT, VC_IF, struct.pack('<I', 1))
    cls(2, mm, GET_MAX, 0x04, CT, VC_IF, struct.pack('<I', 5000))
    cls(2, mm, GET_RES, 0x04, CT, VC_IF, struct.pack('<I', 1))
    cls(2, mm, GET_DEF, 0x04, CT, VC_IF, struct.pack('<I', 156))
    cls(2, mm, GET_LEN, 0x04, CT, VC_IF, struct.pack('<H', 4))
    cls(2, mm, GET_INFO, 0x04, CT, VC_IF, b'\x0f')
    cls(2, mm, GET_CUR, 0x0b, CT, VC_IF, struct.pack('<H', 100))    # zoom (absolute), 2 octets
    cls(2, mm, SET_CUR, 0x0b, CT, VC_IF, struct.pack('<H', 200))
    cls(2, mm, GET_CUR, 0x0d, CT, VC_IF, struct.pack('<ii', 3600, -3600))     # pan/tilt: 8 octets shown as bytes
    cls(2, mm, GET_MAX, 0x0d, CT, VC_IF, struct.pack('<ii', 648000, 648000))
    cls(2, mm, SET_CUR, 0x11, CT, VC_IF, b'\x01')                   # privacy
    cls(2, mm, GET_CUR, 0x13, CT, VC_IF, bytes(12))                 # window: 12 octets
    cls(2, mm, GET_CUR, 0x7f, CT, VC_IF, b'\x00')                   # camera control selector not in the table
    mark(w, 'device 2 camera terminal requests', s0)

    s0 = w.count
    # processing unit, selector unit, extension unit, unit that does not exist
    cls(2, mm, GET_CUR, 0x02, PU, VC_IF, struct.pack('<h', 64))     # brightness
    cls(2, mm, GET_MIN, 0x02, PU, VC_IF, struct.pack('<h', -64))
    cls(2, mm, GET_MAX, 0x02, PU, VC_IF, struct.pack('<h', 64))
    cls(2, mm, SET_CUR, 0x03, PU, VC_IF, struct.pack('<H', 32))     # contrast
    cls(2, mm, GET_CUR, 0x05, PU, VC_IF, b'\x02')                   # power line frequency
    cls(2, mm, GET_CUR, 0x0a, PU, VC_IF, struct.pack('<H', 4600))   # white balance temperature
    cls(2, mm, GET_CUR, 0x0c, PU, VC_IF, struct.pack('<I', 0x00800080))   # white balance component
    cls(2, mm, GET_CUR, 0x0b, PU, VC_IF, b'\x01')
    cls(2, mm, GET_CUR, 0x7e, PU, VC_IF, b'\x01')                   # not in the processing unit table
    cls(2, mm, GET_CUR, 0x01, SU, VC_IF, b'\x01')                   # selector unit: input select
    cls(2, mm, SET_CUR, 0x01, SU, VC_IF, b'\x02')
    cls(2, mm, GET_CUR, 0x01, XU, VC_IF, b'\x00\x00\x00\x01')       # extension unit: no table, "Unit 6 control 0x1"
    cls(2, mm, GET_LEN, 0x01, XU, VC_IF, struct.pack('<H', 4))
    cls(2, mm, GET_CUR, 0x05, 99, VC_IF, b'\x01\x02')               # unit that is not in the descriptors
    cls(2, mm, GET_CUR, 0x01, IT_MT, VC_IF, b'\x01')                # input terminal of another type: no table
    mark(w, 'device 2 processing, selector and extension unit requests', s0)

    s0 = w.count
    # UVC 1.5 request codes
    cls(2, mm, GET_CUR_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 1, 2))
    cls(2, mm, GET_MIN_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 0, 0))
    cls(2, mm, GET_MAX_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 100, 100))
    cls(2, mm, GET_RES_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 1, 1))
    cls(2, mm, SET_CUR_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 5, 6))
    cls(2, mm, GET_DEF_ALL, 0x02, PU, VC_IF, struct.pack('<hh', 5, 6))     # not handled by the dissector
    cls(2, mm, 0x20, 0x02, PU, VC_IF, b'\x00')                      # a request code that does not exist
    mark(w, 'device 2 UVC 1.5 request codes', s0)

    s0 = w.count
    # VideoStreaming interface requests: probe and commit
    cls(2, mm, SET_CUR, 0x01, 0, VS_IF, probe())                    # probe, UVC 1.1 (34 octets)
    cls(2, mm, GET_CUR, 0x01, 0, VS_IF, probe(maxframe=1228800, maxpayload=1024))
    cls(2, mm, GET_MIN, 0x01, 0, VS_IF, probe(extended=False))      # UVC 1.0 (26 octets)
    cls(2, mm, GET_MAX, 0x01, 0, VS_IF, probe(fmt=2, frame=2, hint=0x001f))
    cls(2, mm, GET_DEF, 0x01, 0, VS_IF, probe(hint=0, interval=0))
    cls(2, mm, GET_RES, 0x01, 0, VS_IF, probe(hint=0xffff, framing=0))
    cls(2, mm, SET_CUR, 0x02, 0, VS_IF, probe())                    # commit
    cls(2, mm, GET_CUR, 0x02, 0, VS_IF, probe())
    cls(2, mm, GET_CUR, 0x01, 0, VS_IF, probe(uvc15=True))          # 48 octets: the rest is left as control data
    cls(2, mm, SET_CUR, 0x03, 0, VS_IF, bytes(11))                  # still probe: generic value
    cls(2, mm, GET_CUR, 0x04, 0, VS_IF, bytes(11))
    cls(2, mm, SET_CUR, 0x05, 0, VS_IF, b'\x01')                    # still image trigger
    cls(2, mm, GET_CUR, 0x06, 0, VS_IF, b'\x00')                    # stream error code
    cls(2, mm, SET_CUR, 0x07, 0, VS_IF, b'\x01')                    # generate key frame
    cls(2, mm, SET_CUR, 0x08, 0, VS_IF, struct.pack('<H', 3))       # update frame segment
    cls(2, mm, GET_CUR, 0x09, 0, VS_IF, struct.pack('<H', 100))     # synch delay
    cls(2, mm, GET_CUR, 0x20, 0, VS_IF, b'\x00')                    # selector not in the table
    cls(2, mm, GET_CUR, 0x01, 0, VS_IF, probe()[:34] + b'', length=34)
    mm.control(2, setup(0x01, 11, 1, 1, 0))                         # SET_INTERFACE 1, alternate setting 1
    mark(w, 'device 2 VideoStreaming probe and commit', s0)

    s0 = w.count
    cls(2, mm, GET_CUR, 0x0b, CT, 0x82, struct.pack('<H', 1), recip=2)   # request to an endpoint (recipient 2)
    mark(w, 'device 2 request to an endpoint', s0)

    s0 = w.count
    # interrupt status packets: VideoControl originator
    def intr(data):
        mm.xfer(2, 0x87, INT, data)
    intr(bytes([0x01, CT, 0x00, 0x0b, 0x00]) + struct.pack('<H', 100))          # zoom value changed
    intr(bytes([0x01, PU, 0x00, 0x02, 0x00]) + struct.pack('<h', -5))           # brightness value
    intr(bytes([0x01, CT, 0x00, 0x04, 0x00]) + struct.pack('<I', 200))          # 4 octet value
    intr(bytes([0x01, PU, 0x00, 0x02, 0x01, 0x0b]))                             # info change
    intr(bytes([0x01, PU, 0x00, 0x03, 0x02, 0x06]))                             # failure, error code
    intr(bytes([0x01, CT, 0x00, 0x0b, 0x03]) + struct.pack('<H', 0))            # minimum
    intr(bytes([0x01, CT, 0x00, 0x0b, 0x04]) + struct.pack('<H', 500))          # maximum
    intr(bytes([0x01, CT, 0x00, 0x0d, 0x00]) + bytes(8))                        # 8 octet value shown as bytes
    intr(bytes([0x01, PU, 0x00, 0x05, 0x09, 0xaa, 0xbb]))                       # unknown attribute
    intr(bytes([0x01, 77, 0x00, 0x01, 0x00, 0x01]))                             # entity that does not exist
    intr(bytes([0x01, 0x00, 0x00, 0x02, 0x02, 0x01]))                           # interface (entity 0) control
    intr(bytes([0x02, 0x01, 0x00, 0x00, 0x00]))                                 # VideoStreaming originator (not decoded)
    intr(bytes([0x03, 0x01]))                                                   # another originator
    mark(w, 'device 2 interrupt status packets', s0)

    s0 = w.count
    # UVC 1.0 device on USBPcap
    pc.enumerate(3, dev_desc(cls=0, vid=0x04f2, pid=0xb008), pu_config_v10())
    cls(3, pc, GET_CUR, 0x02, 2, 0, struct.pack('<h', 10))
    cls(3, pc, SET_CUR, 0x01, 0, 1, probe(extended=False))
    cls(3, pc, GET_CUR, 0x01, 0, 1, probe(extended=False))
    cls(3, pc, GET_CUR, 0x01, 6, 0, bytes(4))                                 # extension unit
    pc.xfer(3, 0x81, INT, bytes([0x01, 2, 0x00, 0x02, 0x00]) + struct.pack('<h', 1))
    mark(w, 'USBPcap UVC 1.0 device 3', s0)

    s0 = w.count
    # video interface collection and an interface of undefined subclass
    odd = (if_desc(0, 0, 0, 14, 3, 0) + cs_if(1, struct.pack('<HHIB', 0x0110, 20, 1, 0)) +
           if_desc(1, 0, 0, 14, 0, 0) + cs_if(1, b'\x00\x01\x02') +
           bytes([4, 0x26, 1, 2]))                                         # a descriptor type of another class
    mm.enumerate(4, dev_desc(cls=0xef, sub=2, proto=1), cfg_desc(odd, nif=2))
    mark(w, 'device 4 odd subclasses', s0)
    return w


def malformed_capture():
    w = Pcapng()
    if_mm = w.idb(LT_USB_LINUX_MM)
    mm = Bus(w, 'mm', if_mm, bus=1)
    mm.enumerate(2, dev_desc(cls=0xef, sub=2, proto=1), video_config())

    def cls(dev, req, sel, entity, intf, data=b'', length=None):
        reading = (req & 0x80) != 0
        bm = (0xa0 if reading else 0x20) | 1
        wlen = len(data) if length is None else length
        if reading:
            mm.control(dev, setup(bm, req, sel << 8, (entity << 8) | intf, wlen), data)
        else:
            mm.control(dev, setup(bm, req, sel << 8, (entity << 8) | intf, wlen), out_data=data)

    # GET_LEN and GET_INFO on the probe control of a VideoStreaming interface: the response is cut by the probe decoder
    cls(2, GET_LEN, 0x01, 0, 1, struct.pack('<H', 34))
    cls(2, GET_INFO, 0x01, 0, 1, b'\x03')
    # a value of 3 octets cannot be shown as an integer; 0 octets for GET_INFO and GET_LEN
    cls(2, GET_CUR, 0x0b, CT, 0, b'\x01\x02\x03')
    cls(2, SET_CUR, 0x02, PU, 0, b'\x01\x02\x03')
    cls(2, GET_INFO, 0x04, CT, 0, b'')
    cls(2, GET_LEN, 0x04, CT, 0, b'\x04')
    cls(2, GET_CUR, 0x01, 0, 1, b'\x01\x02\x03\x04\x05')                 # probe cut short
    cls(2, SET_CUR, 0x02, 0, 1, b'')                                      # commit without data
    cls(2, GET_CUR, 0x02, 0, 0, b'')                                      # error code without data
    # interrupt packets cut short
    mm.xfer(2, 0x87, INT, b'\x01')
    mm.xfer(2, 0x87, INT, b'\x01\x01\x00')
    mm.xfer(2, 0x87, INT, b'\x01\x01\x00\x0b\x00')
    mm.xfer(2, 0x87, INT, b'\x01\x01\x00\x0b\x01')                        # info change without value
    mm.xfer(2, 0x87, INT, b'\x01\x01\x00\x0b\x02')                        # failure without error code
    mm.xfer(2, 0x87, INT, b'\x01\x01\x00\x0b\x00\x01\x02\x03')            # value of 3 octets
    # descriptors: an unknown VC subtype, bmControl size above 4 for the camera and processing units,
    # a processing unit cut after the source id, a header with more interfaces than the descriptor holds
    bad_units = (cs_if(0x0a, bytes([0x20, 1, 2, 3])) +
                 vc_it(1, 0x0201, 0, 0, camera_extra(0, 0, 0, (1, 2, 3, 4, 5, 6))) +
                 vc_pu(5, 1, controls=(1, 2, 3, 4, 5, 6)) +
                 cs_if(5, bytes([6, 1])) +
                 cs_if(1, struct.pack('<HHIB', 0x0110, 30, 1, 9) + bytes([1])) +
                 vc_su(4, (1, 2, 3, 4, 5)) +
                 vs_format_unc(1, 1)[:10])
    vc = if_desc(0, 0, 0, 14, 1, 0) + vc_header(100) + bad_units
    vs_bad = if_desc(1, 0, 0, 14, 2, 0) + vs_input_header(2, 20, csize=2, controls=[[1, 0], [2, 0]]) + \
        vs_frame(1, 640, 480, intervals=(333333, 400000))[:-4] + vs_color()[:-1] + vs_format_fb(3, 1)[:12] + \
        cs_ep(3, b'')
    mm.enumerate(3, dev_desc(cls=0xef, sub=2, proto=1), cfg_desc(vc + vs_bad, nif=2))
    # a video control descriptor of subtype 1 with a very long bInCollection
    # two configurations: interface 0 is VideoControl in configuration 1 and VideoStreaming in
    # configuration 2; the conversation keeps its video class data, so the streaming control selectors have names
    cfg1 = cfg_desc(video_config()[9:], nif=2)
    cfg2 = cfg_desc(if_desc(0, 0, 0, 14, 2, 0) + vs_input_header(1, 20, controls=[0]) + vs_format_unc(1, 1) +
                    vs_frame(1, 160, 120, intervals=(333333,)), nif=1, val=2)
    mm.enumerate(4, dev_desc(cls=0xef, sub=2, proto=1, ncfg=2), cfg1)
    mm.get_desc(4, 2, 1, cfg2[:9], 9)
    mm.get_desc(4, 2, 1, cfg2, len(cfg2))
    cls(4, SET_CUR, 0x01, 0, 0, probe())                                  # probe on interface 0, which is streaming now
    cls(4, GET_CUR, 0x02, 0, 0, probe())
    cls(4, GET_CUR, 0x06, 0, 0, b'\x01')
    return w


if __name__ == '__main__':
    w = main_capture()
    w.write(os.path.join(OUT, 'usb-video-coverage.pcapng'))
    m = malformed_capture()
    m.write(os.path.join(OUT, 'usb-video-coverage-malformed.pcapng'))
    if VERBOSE:
        for n, a, b in RANGES:
            print('%-70s frames %d-%d' % (n, a, b))
        print('main', w.count, 'malformed', m.count)

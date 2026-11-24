#!/usr/bin/env python3
# Generates the usb-audio captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic USB Audio (packet-usb-audio.c) coverage captures, Linux usbmon.
# Usage: mkusb-audio.py <outdir> [-v]
# Writes usb-audio-coverage.pcap (main) and usb-audio-coverage-malformed.pcap.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from usbaudio_lib import Mon, u16, cfg, iface, ep_audio, devdesc, cs_if, cs_ep, gdesc  # noqa: E402

AC, AS, MS = 1, 2, 3          # interface subclasses
V1, V2 = 0x00, 0x20           # interface protocols


def terms_v1():
    """audio control body of the class 1.0 device"""
    ac = b''
    hdr_body_len = 0
    items = []
    # input terminal: id 1, USB streaming, 2 channels
    items.append(cs_if(2, bytes([1]) + u16(0x0101) + bytes([0, 2]) + u16(3) + bytes([0, 0])))
    # input terminal: id 6, microphone (0x0201), 1 channel
    items.append(cs_if(2, bytes([6]) + u16(0x0201) + bytes([0, 1]) + u16(1) + bytes([0, 0])))
    # output terminal: id 2, speaker (0x0301) fed by unit 3
    items.append(cs_if(3, bytes([2]) + u16(0x0301) + bytes([0, 3, 0])))
    # feature unit id 3, source 1, controlsize 2, three control sets
    items.append(cs_if(6, bytes([3, 1, 2]) + u16(0x0003) + u16(0x0001) + u16(0x0001) + bytes([0])))
    # feature unit id 7, controlsize 1, one set
    items.append(cs_if(6, bytes([7, 6, 1, 0x03, 0])))
    # selector unit id 4: two input pins
    items.append(cs_if(5, bytes([4, 2, 1, 6, 0])))
    # mixer unit id 5: two input pins, 2 channels
    items.append(cs_if(4, bytes([5, 2, 3, 7, 2]) + u16(3) + bytes([0, 0x0F, 0])))
    body = b''.join(items)
    # header: bcdADC 1.00, total length, two streaming interfaces
    hdr = cs_if(1, u16(0x0100) + u16(8 + 3 + 0) + bytes([2, 1, 2]))
    total = len(hdr) + len(body)
    hdr = cs_if(1, u16(0x0100) + u16(total) + bytes([2, 1, 2]))
    return hdr + body


def as_v1_alt(num, alt, fmt_desc, ep_addr, ep_attr, wformat=1):
    d = iface(num, 0, 0, AS)
    d += iface(num, alt, 1, AS)
    d += cs_if(1, bytes([1, 1]) + u16(wformat))
    d += fmt_desc
    d += ep_audio(ep_addr, ep_attr, 200)
    d += cs_ep(1, bytes([0x81, 2]) + u16(0))
    return d


def fmt1(freqs, nch=2, sub=2, bits=16):
    if freqs is None:       # continuous range
        return cs_if(2, bytes([1, nch, sub, bits, 0]) + (44100).to_bytes(3, 'little') + (96000).to_bytes(3, 'little'))
    return cs_if(2, bytes([1, nch, sub, bits, len(freqs)]) + b''.join(f.to_bytes(3, 'little') for f in freqs))


def fmt2(freqs):
    if freqs is None:
        return cs_if(2, bytes([2]) + u16(256) + u16(1152) + bytes([0]) + (8000).to_bytes(3, 'little') + (48000).to_bytes(3, 'little'))
    return cs_if(2, bytes([2]) + u16(256) + u16(1152) + bytes([len(freqs)]) +
                 b''.join(f.to_bytes(3, 'little') for f in freqs))


def fmt3(freqs, nch=2, sub=2, bits=16):
    if freqs is None:
        return cs_if(2, bytes([3, nch, sub, bits, 0]) + (8000).to_bytes(3, 'little') + (48000).to_bytes(3, 'little'))
    return cs_if(2, bytes([3, nch, sub, bits, len(freqs)]) + b''.join(f.to_bytes(3, 'little') for f in freqs))


def midi_if(num):
    ms = b''
    jacks = [
        cs_if(2, bytes([1, 1, 0])),                       # IN jack, embedded, id 1
        cs_if(2, bytes([2, 2, 0])),                       # IN jack, external, id 2
        cs_if(3, bytes([1, 3, 1, 2, 1, 0])),              # OUT jack, embedded, id 3, source 2.1
        cs_if(3, bytes([2, 4, 1, 1, 1, 0])),              # OUT jack, external, id 4, source 1.1
        # element id 5: two inputs, one output, caps size 3
        cs_if(4, bytes([5, 2, 1, 1, 3, 1, 1, 1, 1, 3, 0x7F, 0x0F, 0x55, 0])),
        cs_if(4, bytes([6, 0, 1, 1, 1, 0, 0])),           # element without inputs, no caps
        cs_if(4, bytes([8, 1, 1, 1, 1, 1, 1, 1, 0x3F, 0])),  # caps size 1
        cs_if(4, bytes([9, 1, 1, 1, 1, 1, 1, 2, 0x3F, 0x01, 0])),  # caps size 2
    ]
    body = b''.join(jacks)
    hdr = cs_if(1, u16(0x0100) + u16(7 + len(body)))
    d = iface(num, 0, 2, MS) + hdr + body
    d += ep_audio(0x03, 2, 64) + cs_ep(1, bytes([1, 1]))
    d += ep_audio(0x83, 2, 64) + cs_ep(1, bytes([2, 3, 4]))
    return d


def config_a():
    d = iface(0, 0, 0, AC) + terms_v1()
    d += as_v1_alt(1, 1, fmt1([44100, 48000]), 0x01, 0x09)
    d += as_v1_alt(2, 1, fmt2([32000]), 0x82, 0x05, wformat=0x1001)
    d += as_v1_alt(3, 1, fmt3([48000]), 0x04, 0x0D, wformat=0x2001)
    d += as_v1_alt(5, 1, fmt1(None, 1, 3, 24), 0x85, 0x0D)
    d += as_v1_alt(6, 1, fmt2(None), 0x86, 0x05, wformat=0x1002)
    d += as_v1_alt(7, 1, fmt3(None), 0x07, 0x0D, wformat=0x2002)
    d += midi_if(4)
    return cfg(d, 8)


# ---------------- class 2.0 ----------------
def config_b():
    items = []
    items.append(cs_if(0x0A, bytes([0x10, 0x03, 0x07, 0, 0])))             # clock source 0x10
    items.append(cs_if(0x0A, bytes([0x12, 0x01, 0x01, 0, 0])))             # clock source 0x12
    items.append(cs_if(0x0B, bytes([0x11, 2, 0x10, 0x12, 0x03, 0])))       # clock selector, 2 pins
    items.append(cs_if(2, bytes([1]) + u16(0x0101) + bytes([0, 0x11, 2]) + (3).to_bytes(4, 'little') + bytes([0]) + u16(0x00FF) + bytes([0])))
    items.append(cs_if(6, bytes([2, 1]) + (0xF).to_bytes(4, 'little') + (3).to_bytes(4, 'little') + (3).to_bytes(4, 'little') + bytes([0])))
    items.append(cs_if(3, bytes([3]) + u16(0x0301) + bytes([0, 2, 0x11]) + u16(0x000F) + bytes([0])))
    items.append(cs_if(5, bytes([5, 2, 1, 2, 0x03, 0])))                   # selector unit v2
    items.append(cs_if(9, bytes([4]) + u16(0x1234) + bytes([1, 1, 2]) + (3).to_bytes(4, 'little') + bytes([0, 0x0F, 0])))   # extension unit
    body = b''.join(items)
    hdr = cs_if(1, u16(0x0200) + bytes([1]) + u16(9 + len(body)) + bytes([0]))
    d = iface(0, 0, 0, AC, V2) + hdr + body
    for num, alt, ftype, formats, ntype in ((1, 1, 1, 1, 1), (2, 1, 2, 0x1, 2), (3, 1, 3, 0x3, 3),
                                              (4, 1, 4, 0x1, 4), (5, 1, 5, 0x55, 5), (6, 1, 0, 0, 6)):
        d += iface(num, 0, 0, AS, V2) + iface(num, alt, 1, AS, V2)
        d += cs_if(1, bytes([1, 0x03, ftype]) + formats.to_bytes(4, 'little') + bytes([2]) + (3).to_bytes(4, 'little') + bytes([0]))
        if ftype == 1:
            d += cs_if(2, bytes([1, 4, 24]))
        elif ftype in (2, 3, 4):
            d += cs_if(2, bytes([ftype]))
        d += ep_audio(0x01 + num, 0x05, 512, 1)
        d += cs_ep(1, bytes([0x80, 0x03, 2]) + u16(1))
    return cfg(d, 7)


def ev(cable, cin, b1=0, b2=0, b3=0):
    return bytes([(cable << 4) | cin, b1, b2, b3])


def req(rt, r, val, idx, wlen):
    return bytes([rt, r]) + u16(val) + u16(idx) + u16(wlen)


def sysex_start(cable=0, mfr=0x7D):
    return ev(cable, 4, 0xF0, mfr, 0x00)


def sysex_cont(cable=0, a=1, b=2, c=3):
    return ev(cable, 4, a, b, c)


def sysex_end(cable=0, n=3):
    return {1: ev(cable, 5, 0xF7), 2: ev(cable, 6, 0x05, 0xF7), 3: ev(cable, 7, 0x04, 0x05, 0xF7)}[n]


def build_main():
    m = Mon()
    DA, DB = 4, 5
    m.mark('class 1.0 device (address 4): descriptors')
    m.control(DA, gdesc(1, 0, 18), devdesc(0x1234, 0x0001))
    cfa = config_a()
    m.control(DA, gdesc(2, 0, 1024), cfa)
    m.mark('class 2.0 device (address 5): descriptors')
    m.control(DB, gdesc(1, 0, 18), devdesc(0x1234, 0x0002))
    cfb = config_b()
    m.control(DB, gdesc(2, 0, 1024), cfb)

    # ---- class 1.0 requests ----
    m.mark('class 1.0 requests (feature unit 3, selector unit 4)')
    CLS_SET, CLS_GET = 0x21, 0xA1
    for ch in (0, 1, 2):
        m.control(DA, req(CLS_SET, 0x01, 0x0100 | ch, 0x0300, 1), b'\x01')           # SET_CUR mute
        m.control(DA, req(CLS_GET, 0x81, 0x0100 | ch, 0x0300, 1), b'\x00')           # GET_CUR mute
    for r in (0x81, 0x82, 0x83, 0x84):
        m.control(DA, req(CLS_GET, r, 0x0201, 0x0300, 2), u16(0xF600 + r))             # volume
    m.control(DA, req(CLS_SET, 0x01, 0x0201, 0x0300, 2), u16(0x8000))                 # silence
    m.control(DA, req(CLS_SET, 0x01, 0x0202, 0x0300, 2), u16(0x0100))
    m.control(DA, req(CLS_SET, 0x01, 0x0000, 0x0400, 1), b'\x02')                    # selector
    m.control(DA, req(CLS_GET, 0x81, 0x0000, 0x0400, 1), b'\x02')
    m.control(DA, req(CLS_SET, 0x01, 0x0100, 0x0700, 1), b'\x00')                    # feature unit 7, mute
    m.control(DA, req(CLS_SET, 0x01, 0x0100, 0x0300, 1), b'\x01', status=0)
    m.control(DA, req(CLS_SET, 0x01, 0x0100, 0x0300, 1), b'\x01', status=-32)         # stalled

    # ---- class 2.0 requests ----
    m.mark('class 2.0 requests (clock source 0x10/0x12, selector 0x11, interfaces)')
    for ent in (0x10, 0x12):
        m.control(DB, req(0xA1, 1, 0x0100, ent << 8, 4), (48000).to_bytes(4, 'little'))     # CUR sample rate
        m.control(DB, req(0x21, 1, 0x0100, ent << 8, 4), (44100).to_bytes(4, 'little'))     # SET CUR
        m.control(DB, req(0xA1, 1, 0x0200, ent << 8, 1), b'\x01')                          # clock valid
    rng = lambda n, size, base: u16(n) + b''.join(
        (base + i).to_bytes(size, 'little') + (base + i + 100).to_bytes(size, 'little') + (1).to_bytes(size, 'little')
        for i in range(n))
    m.control(DB, req(0xA1, 2, 0x0100, 0x1000, 2 + 3 * 12), rng(3, 4, 8000))             # RANGE, all of it
    m.control(DB, req(0xA1, 2, 0x0100, 0x1000, 14), rng(3, 4, 8000)[:14])                # wLength for one range
    m.control(DB, req(0xA1, 2, 0x0100, 0x1000, 2), rng(3, 4, 8000)[:2])                  # wLength 2
    m.control(DB, req(0xA1, 2, 0x0200, 0x1000, 2 + 3 * 2), rng(2, 1, 0))                  # clock valid RANGE layout 1
    m.control(DB, req(0xA1, 1, 0x0100, 0x1100, 1), b'\x01')                              # clock selector CUR
    m.control(DB, req(0x21, 1, 0x0100, 0x1100, 1), b'\x02')
    m.control(DB, req(0xA1, 2, 0x0100, 0x1100, 2 + 3), rng(1, 1, 1))                      # clock selector RANGE
    for n in (1, 2, 3, 4, 5, 6):                                                           # interface controls
        m.control(DB, req(0xA1, 1, 0x0100, n, 1), b'\x01')                                # active alt setting
        m.control(DB, req(0xA1, 1, 0x0200, n, 3), b'\x02\x03\x00')                       # valid alt settings
        m.control(DB, req(0xA1, 1, 0x0300, n, 4), (1).to_bytes(4, 'little'))              # audio data format
    m.control(DB, req(0xA1, 2, 0x0100, 0x1000, 2 + 3 * 4), rng(1, 4, 1))
    m.control(DB, req(0x21, 1, 0x0100, 0x1000, 4), (44100).to_bytes(4, 'little'), status=-32)

    # ---- USB-MIDI ----
    m.mark('USB-MIDI events on bulk IN 0x83 and OUT 0x03 of device 4')
    m.bulk_in(DA, 3, b''.join(ev(c, 8, 0x90 | c, 60 + c, 100) for c in range(16)))
    m.bulk_in(DA, 3, ev(0, 0, 1, 2, 3) + ev(1, 1, 4, 5, 6) + ev(2, 2, 0xF1, 0x20) + ev(3, 3, 0xF2, 0x10, 0x00))
    m.bulk_in(DA, 3, ev(0, 8, 0x80, 60, 0) + ev(0, 9, 0x90, 60, 100) + ev(0, 0xA, 0xA0, 60, 20) +
              ev(0, 0xB, 0xB0, 7, 100) + ev(0, 0xC, 0xC0, 5) + ev(0, 0xD, 0xD0, 33) +
              ev(0, 0xE, 0xE0, 0, 0x40) + ev(0, 0xF, 0xFE))
    m.bulk_out(DA, 3, ev(1, 9, 0x91, 64, 90) + ev(1, 8, 0x81, 64, 0) + ev(1, 0xF, 0xF8))
    m.bulk_in(DA, 3, ev(0, 9, 0x90, 62, 80) + b'\x00\x00')                               # partial event at the end
    m.mark('SysEx: one frame, ends with 1, 2 and 3 octets, several frames, two cables')
    m.bulk_in(DA, 3, sysex_start() + sysex_cont() + sysex_end(0, 3))
    m.bulk_in(DA, 3, sysex_start() + sysex_end(0, 2))
    m.bulk_in(DA, 3, sysex_start() + sysex_end(0, 1))
    m.bulk_in(DA, 3, sysex_start() + sysex_cont())
    m.bulk_in(DA, 3, sysex_cont(0, 4, 5, 6) + sysex_cont(0, 7, 8, 9))
    m.bulk_in(DA, 3, sysex_cont(0, 10, 11, 12) + sysex_end(0, 3))                           # completes here
    m.bulk_in(DA, 3, sysex_start(1) + sysex_cont(1))                                         # cable 1, started
    m.bulk_in(DA, 3, sysex_start(2) + sysex_cont(2))                                   # cable 2, started
    m.bulk_in(DA, 3, ev(1, 9, 0x91, 60, 100) + sysex_cont(1, 3, 3, 3) + sysex_end(1, 2))    # cable 1 completes
    m.bulk_in(DA, 3, sysex_end(2, 1))                                                        # cable 2 completes
    m.bulk_out(DA, 3, sysex_start() + sysex_cont() + sysex_end(0, 2))
    m.mark('a long SysEx that never ends in the first frames and completes in the last one')
    # 20 frames of 4096 events: with the quadratic fragment_add_seq_next() this
    # took minutes; "reassemble: Find the next fragment number from the first gap"
    n = 4096
    m.bulk_in(DA, 3, sysex_start() + sysex_cont() * (n - 1))
    for i in range(18):
        m.bulk_in(DA, 3, sysex_cont() * n)
    m.bulk_in(DA, 3, sysex_cont() * (n - 1) + sysex_end(0, 3))
    m.mark('Exported PDU frames that name the registered dissectors (no URB data)')
    m.exppdu('usbaudio', ev(0, 9, 0x90, 60, 100))
    m.exppdu('usbaudio.control', b'\x01\x02\x03')
    m.exppdu('usbaudio.bulk', b'\x01\x02\x03')
    m.mark('end')
    return m, cfa, cfb


def build_malformed():
    m = Mon()
    m.mark('device 6: class 1.0 descriptors that are invalid or not decoded')
    d = iface(0, 0, 0, AC)
    items = [
        cs_if(2, bytes([1]) + u16(0x0101) + bytes([0, 2]) + u16(3) + bytes([0, 0, 0xEE, 0xEE])),   # input terminal, extra octets
        cs_if(7, bytes([1, 2, 3, 4])),                         # effect unit (not decoded)
        cs_if(8, bytes([1, 2, 3, 4])),                         # processing unit (not decoded)
        cs_if(0x0C, bytes([1, 2, 3])),                         # clock multiplier
        cs_if(0x0D, bytes([1, 2, 3])),                         # sample rate converter
        cs_if(0x42, bytes([1, 2, 3])),                         # unknown subtype
        cs_if(0x42, b''),
    ]
    body = b''.join(items)
    d += cs_if(1, u16(0x0100) + u16(8 + len(body)) + bytes([1, 1])) + body
    # audio streaming: invalid Type III values, encoder, unknown subtypes and format types
    d += iface(1, 0, 0, AS) + iface(1, 1, 1, AS)
    d += cs_if(1, bytes([1, 1]) + u16(0x2001))
    d += fmt3([48000], nch=1, sub=1, bits=8)
    d += fmt3([48000], nch=2, sub=2, bits=24)
    d += cs_if(2, bytes([4, 1, 2, 3]))                         # format type 4 in a version 1 descriptor
    d += cs_if(3, bytes([1, 2, 3]))                            # encoder
    d += cs_if(0x55, bytes([1, 2, 3]))
    d += ep_audio(0x01, 0x09, 200) + cs_ep(1, bytes([0x81, 2]) + u16(0) + bytes([0xAA]))
    d += cs_ep(2, bytes([1, 2]))                               # unknown endpoint subtype
    # MIDI streaming: unknown subtypes
    d += iface(2, 0, 0, MS) + cs_if(1, u16(0x0100) + u16(7)) + cs_if(0x7F, bytes([1, 2])) + cs_ep(2, bytes([1]))
    # an interface of the audio class with the undefined subclass
    d += iface(3, 0, 0, 0) + cs_if(1, bytes([1, 2, 3]))
    d += bytes([5, 0x23, 1, 2, 3])                             # not a class specific type
    m.control(6, gdesc(1, 0, 18), devdesc(0x1234, 0x0006))
    cfc = cfg(d, 4)
    m.control(6, gdesc(2, 0, 1024), cfc)

    m.mark('device 7: class 2.0 descriptors that are invalid or not decoded')
    d = iface(0, 0, 0, AC, V2)
    items = [
        cs_if(0x42, bytes([1])),
    ]
    body = b''.join(items)
    d += cs_if(1, u16(0x0200) + bytes([1]) + u16(9 + len(body)) + bytes([0])) + body
    d += iface(1, 0, 0, AS, V2) + iface(1, 1, 1, AS, V2)
    d += cs_if(1, bytes([1, 0x03, 1]) + (1).to_bytes(4, 'little') + bytes([2]) + (3).to_bytes(4, 'little') + bytes([0]))
    d += cs_if(2, bytes([1, 4, 24, 0xEE]))                     # format type descriptor with an extra octet
    d += ep_audio(0x01, 0x05, 512) + cs_ep(1, bytes([0x80, 0x03, 2]) + u16(1) + bytes([0xAA]))
    m.control(7, gdesc(1, 0, 18), devdesc(0x1234, 0x0007))
    cfd = cfg(d, 2)
    m.control(7, gdesc(2, 0, 1024), cfd)

    m.mark('devices 10-20: one invalid feature unit descriptor each (the exception ends the configuration)')
    fus = [
        (V1, bytes([3, 1, 0, 0, 0, 0])),                       # bControlSize 0
        (V1, bytes([3, 1, 2, 0x03, 0x00, 0])),                 # 2 octets of controls: 7 + n * (ch + 1) does not fit
        (V1, bytes([3, 1, 1, 0x03, 0, 0, 0, 0])),
        (V1, bytes([3, 1, 2])),                                # only 6 octets long
        (V1, bytes([3, 1])),                                   # 5 octets
        (V1, bytes([3])),                                      # 4
        (V2, bytes([2, 1, 0, 0, 0, 0])),                       # 9 octets: not 6 + 4 * n
        (V2, bytes([2, 1, 0, 0, 0, 0, 0, 0, 0])),              # 12 octets
        (V2, bytes([2, 1, 0, 0])),                             # 7 octets
        (V2, bytes([2, 1])),                                   # 5 octets
        (V2, bytes([2])),                                      # 4
    ]
    for n, (proto, fu) in enumerate(fus):
        dev = 10 + n
        d = iface(0, 0, 0, AC, proto) + cs_if(1, (u16(0x0100) + u16(9) + bytes([1, 1])) if proto == V1
                                               else (u16(0x0200) + bytes([1]) + u16(9) + bytes([0])))
        d += cs_if(6, fu)
        m.control(dev, gdesc(1, 0, 18), devdesc(0x1234, 0x0100 + n))
        m.control(dev, gdesc(2, 0, 1024), cfg(d, 1))
    m.mark('devices 21-37: descriptors cut short (exceptions)')
    cuts = [
        (V2, cs_if(0x0A, bytes([0x10, 0x03]))),                # clock source
        (V2, cs_if(0x0B, bytes([0x11, 3, 1]))),                # clock selector with pins missing
        (V2, cs_if(1, u16(0x0200))),                           # header
        (V1, cs_if(5, bytes([4, 3, 1]))),                      # selector unit with pins missing
        (V1, cs_if(4, bytes([5, 3, 1]))),                      # mixer
        (V2, cs_if(9, bytes([4, 0x34]))),                      # extension unit
        (V1, cs_if(2, bytes([1, 1]))),                         # input terminal
        (V1, cs_if(3, bytes([1, 1]))),                         # output terminal
        ('AS1', cs_if(1, bytes([1]))),                         # AS general
        ('AS1', cs_if(2, bytes([1, 2, 2, 16, 3, 0x44]))),      # format type I with frequencies missing
        ('AS1', cs_if(2, bytes([2, 1]))),                      # format type II
        ('AS2', cs_if(1, bytes([1, 3, 1]))),                   # AS general version 2
        ('AS1', cs_ep(1, bytes([0x01]))),                      # AS endpoint
        ('MS', cs_if(1, bytes([0, 1]))),                       # MIDI header
        ('MS', cs_if(3, bytes([1, 2, 3, 4]))),                 # MIDI OUT jack with 3 pins declared
        ('MS', cs_if(4, bytes([5, 3, 1]))),                    # MIDI element
        ('MS', cs_ep(1, bytes([3, 1]))),                       # MIDI endpoint, jacks missing
    ]
    for n, (proto, desc) in enumerate(cuts):
        dev = 21 + n
        if proto == 'AS1':
            d = iface(0, 0, 0, AS) + desc
        elif proto == 'AS2':
            d = iface(0, 0, 0, AS, V2) + desc
        elif proto == 'MS':
            d = iface(0, 0, 0, MS) + desc
        else:
            d = iface(0, 0, 0, AC, proto) + desc
        m.control(dev, gdesc(1, 0, 18), devdesc(0x1234, 0x0200 + n))
        m.control(dev, gdesc(2, 0, 1024), cfg(d, 1))

    m.mark('device 40: audio control interface without units (no entity types are known)')
    d = iface(0, 0, 0, AC) + cs_if(1, u16(0x0100) + u16(9) + bytes([1, 1]))
    d += cs_if(2, bytes([1]) + u16(0x0101) + bytes([0, 2]) + u16(3) + bytes([0, 0]))
    d += cs_if(3, bytes([2]) + u16(0x0301) + bytes([0, 1, 0]))
    m.control(40, gdesc(1, 0, 18), devdesc(0x1234, 0x0036))
    m.control(40, gdesc(2, 0, 1024), cfg(d, 1))
    m.control(40, req(0x21, 0x01, 0x0100, 0x0300, 1), b'\x01')
    m.control(40, req(0xA1, 0x81, 0x0100, 0x0300, 1), b'\x01')
    m.mark('device 8: class with an unknown protocol; device 9: audio streaming interface with bulk')
    d = iface(0, 0, 0, AC, 0x10)
    d += cs_if(1, u16(0x0100) + u16(9) + bytes([1, 1]))
    d += cs_if(2, bytes([1]) + u16(0x0101) + bytes([0, 2]) + u16(3) + bytes([0, 0]))
    d += cs_if(3, bytes([2]) + u16(0x0301) + bytes([0, 3, 0]))
    d += cs_if(6, bytes([3, 1, 2, 0, 0, 0]))
    d += cs_if(5, bytes([4, 1, 1, 0]))
    d += cs_if(0x0A, bytes([0x10, 0x03, 0x07, 0, 0]))
    d += iface(1, 0, 0, AS, 0x10) + iface(1, 1, 1, AS, 0x10)
    d += cs_if(1, bytes([1, 1]) + u16(1)) + cs_if(2, bytes([1, 2, 2, 16, 1, 0x44, 0xAC, 0]))
    d += ep_audio(0x01, 0x05, 200) + cs_ep(1, bytes([0, 0, 0, 0, 0]))
    m.control(8, gdesc(1, 0, 18), devdesc(0x1234, 0x0008))
    m.control(8, gdesc(2, 0, 1024), cfg(d, 2))
    m.control(8, req(0xA1, 0x81, 0x0100, 0x0300, 1), b'\x00')
    m.control(8, req(0xA1, 1, 0x0100, 0x0300, 1), b'\x00')
    d = iface(0, 0, 0, AC) + cs_if(1, u16(0x0100) + u16(9) + bytes([1, 1]))
    d += iface(1, 0, 1, AS) + cs_if(1, bytes([1, 1]) + u16(1)) + ep_audio(0x81, 0x02, 64) + cs_ep(1, bytes([0, 0, 0, 0, 0]))
    m.control(9, gdesc(1, 0, 18), devdesc(0x1234, 0x0009))
    m.control(9, gdesc(2, 0, 1024), cfg(d, 2))
    m.bulk_in(9, 1, bytes(range(16)))
    m.bulk_out(9, 1, b'out')

    m.mark('class 1.0 requests that are not fully decoded (device 4 of the main capture)')
    # these reuse the descriptors of device 6 (entities 3: feature unit, no class data)
    m.control(4, gdesc(1, 0, 18), devdesc(0x1234, 0x0001))
    m.control(4, gdesc(2, 0, 1024), config_a())
    CLS_SET, CLS_GET = 0x21, 0xA1
    m.control(4, req(CLS_SET, 0x01, 0x0100, 0x0500, 1), b'\x01')                 # mixer unit: entity not known
    m.control(4, req(CLS_GET, 0x81, 0x0100, 0x0500, 1), b'\x01')
    m.control(4, req(CLS_SET, 0x01, 0x0200, 0x0001, 2), u16(0x1234))              # AS interface
    m.control(4, req(CLS_SET, 0x01, 0x0100, 0x0000, 1), b'\x01')                 # entity 0
    m.control(4, req(0x22, 0x01, 0x0100, 0x0001, 3), bytes([0x44, 0xAC, 0x00]))   # endpoint 1: sampling frequency
    m.control(4, req(0xA2, 0x81, 0x0100, 0x0081, 3), bytes([0x44, 0xAC, 0x00]))
    m.control(4, req(CLS_GET, 0x81, 0x0300, 0x0300, 1), b'\x01')                 # bass
    m.control(4, req(CLS_SET, 0x01, 0x0100, 0x0300, 3), b'\x01\x02\x03')          # mute with 3 octets
    m.control(4, req(CLS_SET, 0x01, 0x0201, 0x0300, 4), b'\x01\x02\x03\x04')
    m.control(4, req(CLS_SET, 0x01, 0x0100, 0x0400, 1), b'\x01')                 # selector with wValue
    m.control(4, req(CLS_GET, 0xFF, 0x0000, 0x0300, 1), b'\x00')                 # GET_STAT
    m.control(4, req(CLS_SET, 0x05, 0x0000, 0x0300, 4), bytes(4))                 # SET_MEM
    m.control(4, req(CLS_GET, 0x85, 0x0000, 0x0300, 4), bytes(4))
    m.control(4, req(CLS_SET, 0x77, 0x0100, 0x0300, 1), b'\x00')                 # unknown request
    m.control(4, req(CLS_SET, 0x01, 0x0100, 0x0300, 0), b'')                      # no data stage
    m.control(4, req(CLS_GET, 0x81, 0x0100, 0x0300, 1), b'', status=-32)          # stalled GET: no data
    m.control(4, req(0x20, 0x01, 0, 0, 0), b'')                                   # class request to the device
    m.control(4, req(0x41, 0x01, 0, 0, 0), b'')                                   # vendor request

    m.mark('class 2.0 requests that are not fully decoded (device 5 of the main capture)')
    m.control(5, gdesc(1, 0, 18), devdesc(0x1234, 0x0002))
    m.control(5, gdesc(2, 0, 1024), config_b())
    m.control(5, req(0xA1, 1, 0x0100, 0x0200, 4), bytes(4))                       # feature unit
    m.control(5, req(0xA1, 2, 0x0100, 0x0200, 14), bytes(14))
    m.control(5, req(0xA1, 1, 0x0100, 0x0400, 4), bytes(4))                       # extension unit
    m.control(5, req(0xA1, 1, 0x0100, 0x0500, 1), bytes(1))                       # selector unit
    m.control(5, req(0xA1, 3, 0x0100, 0x1000, 4), bytes(4))                       # MEM
    m.control(5, req(0xA1, 9, 0x0100, 0x1000, 4), bytes(4))                       # unknown request
    m.control(5, req(0xA1, 1, 0x0900, 0x1000, 4), bytes(4))                       # clock source, unknown control
    m.control(5, req(0xA1, 1, 0x0900, 0x1100, 4), bytes(4))                       # clock selector, unknown control
    m.control(5, req(0xA1, 1, 0x0901, 0x0001, 4), bytes(4))                       # interface, unknown control
    m.control(5, req(0xA1, 1, 0x0101, 0x0001, 1), bytes(1))                       # interface control, channel 1
    m.control(5, req(0xA1, 1, 0x0001, 0x1000, 4), bytes(4))                       # clock source control, channel 1: sampling frequency
    m.control(5, req(0xA1, 2, 0x0900, 0x1000, 8), bytes(8))                       # RANGE of an unknown control
    m.control(5, req(0xA1, 2, 0x0100, 0x1000, 10), rng2(2, 4, 8000)[:10])         # RANGE: wLength 10 for 2 subranges
    m.control(5, req(0xA1, 2, 0x0100, 0x1000, 1), rng2(3, 4, 8000)[:1])           # RANGE answered with one octet
    m.control(5, req(0xA1, 1, 0x0200, 0x0001, 4), bytes(4))                       # interface control with extra data
    m.control(5, req(0x21, 1, 0x0100, 0x1000, 4), (44100).to_bytes(4, 'little'), status=-32)
    m.control(5, req(0xA1, 1, 0x0100, 0x1000, 4), b'', status=-32)                # stalled GET: no data
    m.control(5, req(0x22, 1, 0x0000, 0x0002, 1), b'\x00')                        # endpoint request
    m.control(5, req(0xA2, 1, 0x0000, 0x0082, 1), b'\x00')

    m.mark('MIDI: a SysEx that does not start with F0 and several messages in one frame')
    m.bulk_in(4, 3, sysex_end(0, 1))
    m.bulk_in(4, 3, sysex_start() + sysex_end(0, 3) + sysex_start() + sysex_end(0, 3))
    m.bulk_in(4, 3, sysex_start() + sysex_end(0, 2) + ev(0, 9, 0x90, 60, 1))
    m.bulk_in(4, 3, sysex_start() + sysex_cont() + sysex_end(0, 1) + sysex_start())
    m.bulk_in(4, 3, sysex_end(0, 3))
    m.bulk_in(4, 3, sysex_start(3) + sysex_cont(3) + sysex_start(4) + sysex_end(4, 3) + sysex_end(3, 3))
    m.bulk_in(4, 3, b'')
    m.bulk_in(4, 3, b'\x04\x01')
    m.bulk_in(4, 3, ev(0, 4, 0xF0, 0x41, 0x10) + sysex_cont(0, 0x42, 0x12, 0x40) + sysex_end(0, 3))     # a Roland SysEx
    m.bulk_out(4, 3, sysex_start() + sysex_end(0, 3))
    m.mark('end')
    return m


def rng2(n, size, base):
    return u16(n) + b''.join(
        (base + i).to_bytes(size, 'little') + (base + i + 100).to_bytes(size, 'little') + (1).to_bytes(size, 'little')
        for i in range(n))


def write_bad_feature_unit(path, malformed):
    """Frames 11, 12, 35 and 36 of the malformed capture: class 1.0 feature
    unit descriptors cut short. Written as editcap wrote them when the file
    was cut from the malformed capture (its application name included)."""
    from capgen import Pcapng, pcapng_option
    w = Pcapng(shb_options=pcapng_option(
        4, b'Editcap (Wireshark) 5.1.0 (v5.1.0rc0-3036-g914e79068d5b)'))
    w.interface(220)    # LINKTYPE_USB_LINUX_MMAPPED
    for n in (11, 12, 35, 36):
        # Mon.write() puts frame i at 1700000000 s + i ms.
        w.packet(0, malformed.pk[n - 1], ts=(1700000000, (n - 1) * 1000))
    w.write(path)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    m, ca, cb = build_main()
    m.write_pcapng(os.path.join(out, 'usb-audio-coverage.pcapng'))
    x = build_malformed()
    x.write(os.path.join(out, 'usb-audio-coverage-malformed.pcap'))
    write_bad_feature_unit(os.path.join(out, 'usb_audio_bad_feature_unit.pcapng'), x)
    print(len(m.pk), 'frames in the main capture,', len(x.pk), 'in the malformed one')
    if '-v' in sys.argv:
        for n, name in m.marks:
            print('%5d  %s' % (n, name))
        print('malformed:')
        for n, name in x.marks:
            print('%5d  %s' % (n, name))

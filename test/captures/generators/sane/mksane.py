#!/usr/bin/env python3
# Generates test/captures/sane_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SANE coverage captures. Usage: mksane.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, TcpStream

PORT = 6566

def w(*v):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in v)

def s(text):
    """SANE string: a length word that counts the terminating NUL, then the characters and the NUL"""
    b = text.encode() + b'\0' if text else b'\0'
    return w(len(b)) + b

def fixed(x):
    return int(x * 65536)

# opcodes
INIT, GET_DEVICES, OPEN, CLOSE, GET_OPT, CONTROL, GET_PARAMS, START, CANCEL, AUTH, EXIT = range(11)

def ver(major=1, minor=0, build=3):
    return (major << 24) | (minor << 16) | build

def desc(name, title, descr, vtype, unit, size, caps, constraint=None):
    out = w(1) + s(name) + s(title) + s(descr) + w(vtype, unit, size, caps)
    if constraint is None:
        return out + w(0)
    kind, data = constraint
    if kind == 1:
        return out + w(1, 1, *data)                      # range: pointer, min, max, quant
    if kind == 2:
        return out + w(2, len(data), *data)              # word list
    return out + w(3, len(data)) + b''.join(s(x) for x in data)   # string list

def main(out):
    p = Pcap()
    t = TcpStream(p, 40300, PORT)
    # ---- init
    t.c(w(INIT, ver(1, 0, 3)) + s('alice'))
    t.s(w(0, ver(1, 0, 3)))
    # ---- get devices: two devices and the terminating null pointer
    t.c(w(GET_DEVICES))
    t.s(w(0, 3) + w(1) + s('net:scanner0') + s('Acme') + s('ScanMaster 3000') + s('flatbed scanner') +
        w(1) + s('net:scanner1') + s('Acme') + s('ScanMaster 3100') + s('sheetfed scanner') + w(0))
    t.c(w(GET_DEVICES))
    t.s(w(0, 1) + w(0))                                                  # no devices
    # ---- open, with the authorization flow
    t.c(w(OPEN) + s('net:scanner0'))
    t.s(w(0, 7) + s(''))
    t.c(w(OPEN) + s('net:scanner1'))
    t.s(w(0, 0) + s('scanner1$MD5$abcdef'))                              # needs authorization
    t.c(w(AUTH) + s('scanner1$MD5$abcdef') + s('alice') + s('not-a-real-password'))
    t.s(w(0))                                                            # authorize response
    t.s(w(0, 8) + s(''))                                                 # the open response that follows
    # ---- option descriptors: every value type, unit and constraint
    t.c(w(GET_OPT, 7))
    opts = [
        desc('', 'Number of options', 'Read-only option that specifies how many options a specific devices supports.', 1, 0, 4, 0x04),
        desc('mode', 'Scan mode', 'Selects the scan mode', 3, 0, 8, 0x01 | 0x04, (3, ['Lineart', 'Gray', 'Color'])),
        desc('resolution', 'Resolution', 'Sets the resolution of the scanned image.', 1, 4, 4, 0x01 | 0x04 | 0x02, (2, [75, 150, 300, 600])),
        desc('tl-x', 'Top-left x', 'Top-left x position of scan area.', 2, 3, 4, 0x01 | 0x04 | 0x08, (1, [0, fixed(215.9), 0])),
        desc('brightness', 'Brightness', 'Controls the brightness of the acquired image.', 1, 5, 4, 0x10 | 0x20 | 0x40, (1, [-100, 100, 1])),
        desc('exposure', 'Exposure time', 'Exposure time in microseconds', 1, 6, 4, 0x01, (2, [10, 20, 40])),
        desc('depth', 'Bit depth', 'Bits per sample', 1, 2, 4, 0x01, (2, [1, 8, 16])),
        desc('pixels', 'Pixels', 'Number of pixels', 1, 1, 4, 0x01, (1, [1, 5000, 1])),
        desc('preview', 'Preview', 'Request a preview-quality scan.', 0, 0, 4, 0x01 | 0x04, None),
        desc('scan', 'Scan button', 'Start a scan', 4, 0, 0, 0x01 | 0x04, None),
        desc('', 'Geometry', 'Scan area and media size', 5, 0, 0, 0x40, None),
        desc('gamma', 'Gamma', 'Fixed point word list', 2, 9, 4, 0x01, (2, [fixed(1.0), fixed(2.2)])),
        desc('xfixed', 'Fixed unit', 'Fixed point with a unit', 2, 4, 4, 0x01, (2, [fixed(75), fixed(150)])),
        desc('flag', 'Flag', 'Boolean word list', 0, 0, 4, 0x01, (2, [0, 1, 7])),
        desc('', '', 'An option without a name or title', 1, 0, 4, 0x00, None),
        desc('count', 'Count', 'Integer word list without a unit', 1, 0, 4, 0x01, (2, [1, 2, 3])),
        desc('fx', 'Fixed', 'Fixed point word list without a unit', 2, 0, 4, 0x01, (2, [fixed(1.0)])),
        desc('strw', 'Strw', 'A word list on a string option', 3, 0, 4, 0x01, (2, [1, 2])),
    ]
    t.s(w(0 and 0, len(opts))[4:] + b''.join(opts))
    # ---- control option: get, set (string, int, fixed, bool vector, button), responses
    def control_req(handle, index, action, vtype, size, value):
        return w(CONTROL, handle, index, action, vtype, size) + value
    t.c(control_req(7, 1, 0, 1, 4, w(1) + w(0)))                         # get value (int)
    t.s(w(0, 0, 1, 4) + w(1, 600) + s(''))
    t.c(control_req(7, 3, 1, 2, 4, w(1) + w(fixed(100.5))))              # set fixed
    t.s(w(0, 6, 2, 4) + w(1, fixed(100.5)) + s(''))
    t.c(control_req(7, 4, 2, 0, 4, w(1) + w(1)))                         # set auto on a bool
    t.s(w(0, 2, 0, 4) + w(1, 1) + s(''))
    t.c(control_req(7, 7, 1, 77, 4, w(1) + w(5)))                        # unknown value type
    t.s(w(4, 0, 77, 4) + w(1, 5) + s(''))
    # ---- parameters, start, cancel, close, exit
    t.c(w(GET_PARAMS, 7))
    t.s(w(0, 1, 1, 2550, 850, 1100, 8))
    t.c(w(GET_PARAMS, 7))
    t.s(w(0, 0, 0, 100, 100, 100, 1))
    for fmt in (2, 3, 4, 9):
        t.c(w(GET_PARAMS, 7))
        t.s(w(0, fmt, 0, 1, 1, 1, 8))
    t.c(w(START, 7))
    t.s(w(0, 40001, 0x1234) + s(''))
    t.c(w(START, 7))
    t.s(w(3, 0, 0) + s(''))
    t.c(w(CANCEL, 7))
    t.s(w(0))
    t.c(w(CLOSE, 7))
    t.s(w(0))
    # status values in a response
    for st_ in range(1, 12):
        t.c(w(START, 7))
        t.s(w(st_, 0, 0) + s(''))
    None
    t.c(w(START, 7))
    t.s(w(77, 0, 0) + s(''))
    t.c(w(EXIT))
    t.c(w(99))                                                           # unknown opcode
    # ---- several PDUs in one segment, a PDU split over segments
    t.c(w(GET_PARAMS, 7) + w(GET_DEVICES))                               # two requests in a segment: the response is for the last
    t.s(w(0, 1) + w(0))
    big = w(0, 3) + w(1) + s('net:scanner0') + s('Acme') + s('ScanMaster 3000') + s('flatbed scanner') + w(1) + s('net:s1') + s('V') + s('M') + s('T') + w(0)
    t.c(w(GET_DEVICES))
    t.s(big[:6]); t.s(big[6:40]); t.s(big[40:])
    t.fin()
    p.write(os.path.join(out, 'sane-coverage.pcap'))

    # ===== malformed and unusual
    m = Pcap()
    # two responses in one segment (the opcode is stored once per frame, so the second is read with the first one's)
    t = TcpStream(m, 41303, PORT)
    t.c(w(OPEN) + s('net:scanner0'))
    t.s(w(0, 9) + s('') + w(0, 1, 1, 1, 1, 1, 1))
    t.c(w(GET_PARAMS, 7))
    t.s(w(0, 1, 1, 1, 1, 1, 1) + w(0, 1, 1, 1, 1, 1, 1))
    t.c(w(GET_DEVICES))
    t.s(w(0, 1) + w(0) + w(0, 1) + w(0))
    t.fin()
    # control option values the dissector reads wrongly (see README): a string value, a button, vectors
    t = TcpStream(m, 41302, PORT)
    t.c(w(OPEN) + s('net:scanner0'))
    t.s(w(0, 7) + s(''))
    t.c(control_req(7, 2, 1, 3, len(s('Color')), w(1) + s('Color')))   # set string
    t.s(w(0, 1, 3, len(s('Color'))) + w(1) + s('Color') + s(''))
    t.c(control_req(7, 5, 1, 4, 0, w(0)))                                # button
    t.s(w(0, 0, 4, 0) + w(0) + s(''))
    t.c(control_req(7, 6, 1, 1, 12, w(1) + w(1, 2, 3)))                  # int vector
    t.s(w(0, 1, 1, 12) + w(1, 1, 2, 3) + s(''))
    t.c(control_req(7, 8, 1, 2, 8, w(1) + w(fixed(1.5), fixed(-2.25))))  # fixed vector
    t.s(w(11, 7, 2, 8) + w(1, fixed(1.5), fixed(-2.25)) + s('res'))
    t.fin()
    # responses without a request (the expected opcode is not known): no PDU length
    t = TcpStream(m, 41300, PORT)
    t.s(w(0, 1, 2, 3))
    t.s(w(0))
    t.fin()
    # truncated and odd requests and responses
    t = TcpStream(m, 41301, PORT)
    t.c(w(INIT, ver()) + w(500) + b'short')                              # string longer than the data
    t.c(b'\x00\x00')                                                     # less than a word
    t.c(w(OPEN, 100) + b'abc')
    t.c(w(CONTROL, 1, 2, 0, 1, 4000))                                    # value size larger than the data
    t.c(w(AUTH) + s('a') + s('b'))                                       # password missing
    t.c(w(START))                                                        # handle missing
    t.c(w(0xffffffff))                                                   # opcode out of range
    t.s(w(0, 1))
    t.s(w(0, 1, 2))
    t.c(w(GET_DEVICES))
    t.s(w(0))                                                            # device count missing
    t.c(w(GET_DEVICES))
    t.s(w(0, 0))                                                         # device count of zero
    t.c(w(GET_DEVICES))
    t.s(w(0, 5) + w(1) + s('net:x'))                                     # devices counted but missing
    t.c(w(GET_OPT, 7))
    t.s(w(0xffff))                                                       # a huge option count with no data
    t.c(w(GET_OPT, 7))
    t.s(w(1) + w(1) + s('n') + s('t') + s('d') + w(1, 0, 4, 0) + w(1, 1, 5))   # range cut
    t.c(w(GET_OPT, 7))
    t.s(w(1) + w(1) + s('n') + s('t') + s('d') + w(1, 0, 4, 0) + w(3, 3) + s('only one'))   # string list cut
    t.c(w(GET_OPT, 7))
    t.s(w(1) + w(1) + s('n') + s('t') + s('d') + w(1, 0, 4, 0) + w(2, 3, 1))                 # word list cut
    t.c(w(CONTROL, 7, 1, 0, 1, 4) + w(1) + w(0))
    t.s(w(0, 0, 1, 4000) + w(1, 2))                                      # value size beyond the data
    t.c(w(CONTROL, 7, 1, 3, 0) + w(0))                                   # value size 0, string type
    t.s(w(0, 0, 3, 0) + w(0) + w(0))
    t.c(w(CONTROL, 7, 1, 5, 4) + w(1, 0))
    t.s(w(0, 0, 5, 4) + w(1, 0) + s(''))
    t.c(w(GET_PARAMS, 7))
    t.s(w(0, 1, 1))                                                      # parameters cut
    t.c(w(START, 7))
    t.s(w(0, 1, 1) + w(2000) + b'ab')                                    # string beyond the data
    t.c(w(OPEN) + s('x'))
    t.s(w(0, 1))
    t.c(w(INIT, ver()) + s('x'))
    t.s(w(0))
    t.fin()
    m.write(os.path.join(out, 'sane-coverage-malformed.pcap'))

main(sys.argv[1])

#!/usr/bin/env python3
# Generates test/captures/dua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DUA dissector
(packet-dua.c, DPNSS/DASS2-User Adaptation Layer, RFC 4129).

DUA runs over SCTP with payload protocol identifier 10, which is
registered by default, so no Decode As is needed. Every packet is built
from scratch with struct; nothing comes from a real network.

Usage: mkdua.py <output directory>

Writes:
  dua-coverage.pcap            an SCTP association (INIT, INIT ACK,
                               COOKIE ECHO, COOKIE ACK) carrying every
                               DUA message class and type with every
                               parameter, known and unknown values,
                               padding, DPNSS messages in Protocol Data
                               (the reproducer of "DUA: Show the
                               protocol data length when DPNSS is used"),
                               then SHUTDOWN
  dua-coverage-malformed.pcap  parameters whose length field is 0, 2, 3
                               or larger than the data (from the review
                               reproducer dua_short_param_len.py)
"""

import os
import struct
import sys


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


ASP = (bytes([192, 0, 2, 1]), 2904, bytes.fromhex('020000000001'))
SGP = (bytes([192, 0, 2, 2]), 9900, bytes.fromhex('020000000002'))
VTAG = {True: 0x11223344, False: 0x55667788}   # tag the receiver expects


def sctp_frame(from_asp, chunks):
    a, b = (ASP, SGP) if from_asp else (SGP, ASP)
    body = b''
    for c in chunks:
        body += c + b'\0' * ((4 - len(c) % 4) % 4)
    vtag = 0 if chunks[0][0] == 1 else VTAG[not from_asp]
    s = struct.pack('!HHII', a[1], b[1], vtag, 0) + body
    s = s[:8] + struct.pack('<I', crc32c(s)) + s[12:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(s), 1, 0x4000, 64, 132, 0, a[0], b[0])
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b[2] + a[2] + b'\x08\x00' + ip + s


class Assoc:
    def __init__(self, frames):
        self.frames = frames
        self.tsn = {True: 1000, False: 5000}
        self.ssn = {True: 0, False: 0}

    def setup(self):
        init = struct.pack('!BBHIIHHI', 1, 0, 20, VTAG[True], 65535, 2, 2, self.tsn[True])
        self.frames.append(sctp_frame(True, [init]))
        cookie = struct.pack('!HH', 7, 12) + b'COOKIE01'
        ack = struct.pack('!BBHIIHHI', 2, 0, 20 + len(cookie), VTAG[False], 65535, 2, 2,
                          self.tsn[False]) + cookie
        self.frames.append(sctp_frame(False, [ack]))
        self.frames.append(sctp_frame(True, [struct.pack('!BBH', 10, 0, 12) + b'COOKIE01']))
        self.frames.append(sctp_frame(False, [struct.pack('!BBH', 11, 0, 4)]))

    def data(self, from_asp, payload, ppi=10, stream=0):
        tsn = self.tsn[from_asp]
        self.tsn[from_asp] += 1
        ssn = self.ssn[from_asp]
        self.ssn[from_asp] = (ssn + 1) & 0xffff
        chunk = struct.pack('!BBHIHHI', 0, 3, 16 + len(payload), tsn, stream, ssn, ppi) + payload
        self.frames.append(sctp_frame(from_asp, [chunk]))

    def shutdown(self):
        self.frames.append(sctp_frame(True, [struct.pack('!BBHI', 7, 0, 8, self.tsn[False] - 1)]))
        self.frames.append(sctp_frame(False, [struct.pack('!BBH', 8, 0, 4)]))
        self.frames.append(sctp_frame(True, [struct.pack('!BBH', 14, 0, 4)]))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------------------- DUA

def dua(cls, typ, *params, version=1):
    p = b''.join(params)
    return struct.pack('!BBBBI', version, 0, cls, typ, 8 + len(p)) + p


def param(tag, value, length=None, pad=None):
    """A parameter; padded to 4 octets unless pad is given."""
    if length is None:
        length = 4 + len(value)
    if pad is None:
        pad = b'\0' * ((4 - len(value) % 4) % 4)
    return struct.pack('!HH', tag, length) + value + pad


def p_int_iid(v):
    return param(0x01, struct.pack('!I', v))


def p_text_iid(s):
    return param(0x03, s.encode())


def p_info(s):
    return param(0x04, s.encode())


def p_dlci(v=0x0141, spare=0):
    return param(0x05, struct.pack('!HH', v, spare))


def p_diag(b):
    return param(0x07, b)


def p_ranges(*ranges):
    return param(0x08, b''.join(struct.pack('!II', a, b) for a, b in ranges))


def p_beat(b):
    return param(0x09, b)


def p_tmt(v):
    return param(0x0b, struct.pack('!I', v))


def p_err(v):
    return param(0x0c, struct.pack('!I', v))


def p_status(t, i):
    return param(0x0d, struct.pack('!HH', t, i))


def p_data(b):
    return param(0x0e, b)


def p_reason(v):
    return param(0x0f, struct.pack('!I', v))


def p_tei(v):
    return param(0x10, struct.pack('!I', v))


def p_asp(v):
    return param(0x11, struct.pack('!I', v))


def p_dlc_status(b):
    return param(0x12, b)


MGMT, ASPSM, ASPTM, DPTM = 0, 3, 4, 13

# DPNSS messages for the protocol data parameter
DPNSS_LLRM = bytes([0x42, 0x01])                 # link-by-link reject, cause 1
DPNSS_LLMC = bytes([0x40]) + b'*1#'              # link-by-link message (complete)
DPNSS_CC_ISRM = bytes([0x00]) + b'\x11' + b'*50*123#'   # call control ISRM(C), SIC, string


def main_frames():
    frames = []
    a = Assoc(frames)
    a.setup()                                                     # 1-4
    asp, sgp = True, False
    # ASP state maintenance, 5-10
    a.data(asp, dua(ASPSM, 1, p_asp(7), p_info('asp one')))       # ASP up
    a.data(sgp, dua(ASPSM, 4, p_info('up ack')))                  # ASP up ack
    a.data(asp, dua(ASPSM, 3, p_beat(b'\x01\x02\x03\x04\x05')))   # BEAT (padding)
    a.data(sgp, dua(ASPSM, 6, p_beat(b'\x01')))                  # BEAT ack, 1 byte
    # ASP traffic maintenance, 11-14 (frames 9..12 here, numbered below)
    a.data(asp, dua(ASPTM, 1, p_tmt(1), p_ranges((0, 3), (10, 12)), p_info('active')))
    a.data(sgp, dua(ASPTM, 3, p_tmt(2), p_int_iid(1)))
    a.data(asp, dua(ASPTM, 1, p_tmt(9), p_ranges((5, 5))))       # unknown traffic mode
    a.data(sgp, dua(ASPTM, 3, p_tmt(9), p_text_iid('dpnss-link-A')))
    # Management
    a.data(sgp, dua(MGMT, 1, p_status(1, 1), p_asp(7), p_info('as down')))
    a.data(sgp, dua(MGMT, 1, p_status(1, 2)))
    a.data(sgp, dua(MGMT, 1, p_status(1, 3), p_int_iid(1)))
    a.data(sgp, dua(MGMT, 1, p_status(1, 4)))
    a.data(sgp, dua(MGMT, 1, p_status(2, 1)))
    a.data(sgp, dua(MGMT, 1, p_status(2, 2)))
    a.data(sgp, dua(MGMT, 1, p_status(2, 9)))                     # unknown status
    for code in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0d, 0x0e, 0x0f, 0x1c, 0x1d, 0x63):
        diag = b'\xde' if code == 0x63 else b'\xde\xad\xbe'
        a.data(sgp, dua(MGMT, 0, p_err(code), p_int_iid(1), p_diag(diag)))
    a.data(asp, dua(MGMT, 5, p_int_iid(1), p_dlci(0x0141)))       # DLC status request
    a.data(sgp, dua(MGMT, 6, p_int_iid(1), p_dlci(0x0141),
                    p_dlc_status(b'\x00\x01\x00\x02\x00\x03\x00\x00')))
    a.data(sgp, dua(MGMT, 7, p_text_iid('link'), p_dlci(0x0001), p_dlc_status(b'')))
    # DPNSS boundary primitive transport
    a.data(asp, dua(DPTM, 5, p_int_iid(1), p_dlci(0x0141)))       # EST_REQ
    a.data(sgp, dua(DPTM, 6, p_int_iid(1), p_dlci(0x0141)))       # EST_CON
    a.data(sgp, dua(DPTM, 7, p_text_iid('link'), p_dlci(0x0003)))  # EST_IND
    # DATA_REQ with an integer interface identifier and a 4-byte protocol
    # data (the review reproducer dua_protocol_data_text.py)
    a.data(asp, dua(DPTM, 1, p_int_iid(1), p_data(b'\x00\x01\x02\x03')))
    a.data(asp, dua(DPTM, 1, p_int_iid(1), p_dlci(0x0141), p_data(DPNSS_LLRM)))
    a.data(sgp, dua(DPTM, 2, p_int_iid(1), p_dlci(0x0141), p_data(DPNSS_LLMC)))
    a.data(sgp, dua(DPTM, 2, p_text_iid('link'), p_dlci(0x0141), p_data(DPNSS_CC_ISRM)))
    for r in (0, 1, 2, 3, 9):
        a.data(asp, dua(DPTM, 8, p_int_iid(1), p_dlci(0x0141), p_reason(r)))   # REL_REQ
    a.data(sgp, dua(DPTM, 9, p_int_iid(1), p_dlci(0x0141)))       # REL_CON
    a.data(sgp, dua(DPTM, 10, p_int_iid(1), p_dlci(0x0141), p_reason(1)))   # REL_IND
    # TEI status (an IUA parameter) and an unknown parameter
    for t in (0, 1, 7):
        a.data(sgp, dua(MGMT, 1, p_status(1, 3), p_tei(t)))
    a.data(sgp, dua(MGMT, 1, p_status(1, 3), param(0x99, b'\x01\x02\x03'),
                    param(0x98, b''),
                    param(0x97, b'\x01')))
    # unknown message type in each class, and an unknown class
    a.data(sgp, dua(MGMT, 9, p_info('x')))
    a.data(sgp, dua(ASPSM, 9))
    a.data(sgp, dua(ASPTM, 9))
    a.data(sgp, dua(DPTM, 99))
    a.data(sgp, dua(7, 1))
    # the rest of the ASP state maintenance messages
    a.data(asp, dua(ASPTM, 2, p_int_iid(1), p_info('inactive')))
    a.data(sgp, dua(ASPTM, 4, p_int_iid(1)))
    a.data(asp, dua(ASPSM, 2, p_asp(7)))
    a.data(sgp, dua(ASPSM, 5))
    a.shutdown()
    return frames


def malformed_frames():
    frames = []
    a = Assoc(frames)
    a.setup()
    asp = True
    # the review reproducer dua_short_param_len.py
    a.data(asp, dua(ASPSM, 1, struct.pack('!HHI', 0x11, 8, 7)))             # valid ASP up
    a.data(asp, dua(ASPSM, 1, struct.pack('!HH', 0x11, 0) + b'\0' * 4))     # length 0
    a.data(asp, dua(MGMT, 0, struct.pack('!HH', 0x04, 2) + b'\0' * 4))      # length 2
    a.data(asp, dua(DPTM, 1, struct.pack('!HH', 0x0e, 3) + b'\0' * 4))      # length 3
    a.data(asp, dua(MGMT, 0, struct.pack('!HH', 0x99, 200) + b'abcd'))      # > remaining
    # every fixed-size parameter cut short
    for tag in (0x01, 0x05, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11):
        a.data(asp, dua(MGMT, 1, struct.pack('!HH', tag, 4)))
    # a header without parameters cut short, DPNSS with an unknown group
    a.data(asp, b'\x01\x00\x03')
    a.data(asp, dua(DPTM, 1, p_int_iid(1), p_data(b'\xf0')))
    a.data(asp, dua(DPTM, 1, p_int_iid(1), p_data(b'')))
    a.shutdown()
    return frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dua-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dua-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

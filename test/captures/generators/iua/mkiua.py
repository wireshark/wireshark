#!/usr/bin/env python3
# Generates test/captures/iua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the IUA dissector
(packet-iua.c, ISDN Q.921-User Adaptation Layer, RFC 3057).

IUA runs over SCTP, on port 9900 and on payload protocol identifier 1, both
registered by default.  The common header (version, class, type, length)
is followed by TLV parameters padded to 4 octets.  Every packet is built
with struct; no captured traffic is used.

Usage: mkiua.py <output directory>

Writes:
  iua-coverage.pcap            an SCTP association between an ASP and a
                               signalling gateway with every message class
                               and type and every parameter
  iua-coverage-malformed.pcap  parameters with bad lengths, cut short
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


ASP = (bytes([192, 0, 2, 1]), 2905, bytes.fromhex('020000000001'))
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

    def data(self, from_asp, payload, ppi=1, stream=1):
        tsn = self.tsn[from_asp]
        self.tsn[from_asp] += 1
        ssn = self.ssn[from_asp]
        self.ssn[from_asp] = (ssn + 1) & 0xffff
        chunk = struct.pack('!BBHIHHI', 0, 3, 16 + len(payload), tsn, stream, ssn, ppi) + payload
        self.frames.append(sctp_frame(from_asp, [chunk]))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------------------- IUA

def iua(cls, typ, *params, version=1, length=None):
    p = b''.join(params)
    return struct.pack('!BBBBI', version, 0, cls, typ, 8 + len(p) if length is None else length) + p


def param(tag, value, length=None, pad=None):
    """A parameter; padded to 4 octets unless pad is given."""
    if length is None:
        length = 4 + len(value)
    if pad is None:
        pad = b'\0' * ((4 - len(value) % 4) % 4)
    return struct.pack('!HH', tag, length) + value + pad


def p_int_iid(*v):
    return param(0x01, b''.join(struct.pack('!I', x) for x in v))


def p_text_iid(s):
    return param(0x03, s.encode())


def p_info(s):
    return param(0x04, s.encode())


def p_dlci(sapi_byte=0x00, tei_byte=0x01, spare=0):
    return param(0x05, struct.pack('!BBH', sapi_byte, tei_byte, spare))


def p_diag(b):
    return param(0x07, b)


def p_ranges(*ranges):
    return param(0x08, b''.join(struct.pack('!II', a, b) for a, b in ranges))


def p_beat(b):
    return param(0x09, b)


def p_reason(v):
    return param(0x0a, struct.pack('!I', v))


def p_tmt(v):
    return param(0x0b, struct.pack('!I', v))


def p_err(v):
    return param(0x0c, struct.pack('!I', v))


def p_status(t, i):
    return param(0x0d, struct.pack('!HH', t, i))


def p_data(b):
    return param(0x0e, b)


def p_release(v):
    return param(0x0f, struct.pack('!I', v))


def p_tei(v):
    return param(0x10, struct.pack('!I', v))


def p_asp(v):
    return param(0x11, struct.pack('!I', v))


def dlci(sapi, tei):
    """DLCI value octets: SAPI in the top six bits (bit 1 spare), TEI in
    the top seven bits with the "one" bit set."""
    return (sapi << 2), (tei << 1) | 1


# Q.931 SETUP (protocol discriminator 8, call reference 1, SETUP, bearer capability)
Q931 = bytes.fromhex('08 01 01 05 04 03 80 90 a3')
LAYER2 = bytes.fromhex('00 01 02 03')
RSL = bytes.fromhex('02 04 01 08 02 00')        # RLL ESTablish REQuest, channel number, link identifier
X25 = bytes.fromhex('10 01 00 00 01 02')      # X.25 call request header


def main_frames():
    fr = []
    a = Assoc(fr)
    a.setup()
    d = a.data
    # --- ASP state maintenance (class 3)
    d(True, iua(3, 1, p_asp(7), p_info('asp one')))                  # ASP up (info string, ASP identifier)
    d(False, iua(3, 4, p_info('sgp')))                               # ASP up ack
    d(True, iua(3, 3, p_beat(b'beat-data!')))                        # Heartbeat (10 octets, padded)
    d(False, iua(3, 6, p_beat(b'beat-data!')))                       # Heartbeat ack
    d(True, iua(3, 2, p_reason(1)))                                  # ASP down, reason: management inhibit
    d(True, iua(3, 2, p_reason(9)))                                  # unknown reason
    d(False, iua(3, 5))                                              # ASP down ack, no parameters
    d(True, iua(3, 1))
    d(False, iua(3, 4))
    # --- ASP traffic maintenance (class 4)
    d(True, iua(4, 1, p_tmt(1), p_int_iid(5)))                       # ASP active, over-ride
    d(False, iua(4, 3, p_tmt(2), p_int_iid(5)))                      # ASP active ack, load-share
    d(True, iua(4, 1, p_tmt(7), p_text_iid('PRI-1')))                # unknown traffic mode type, text id
    d(True, iua(4, 2, p_int_iid(5, 6, 7)))                           # ASP inactive, three ids
    d(False, iua(4, 4, p_int_iid(5, 6, 7)))                          # ASP inactive ack
    d(True, iua(4, 1, p_ranges((1, 4), (10, 20))))                   # integer range interface identifier
    # --- management (class 0)
    for code in range(1, 16):
        d(False, iua(0, 0, p_err(code), p_diag(b'\x01\x02\x03')))    # Error, every code
    d(False, iua(0, 0, p_err(0x40), p_diag(b'')))                    # unknown error code, empty diag
    for t, i in ((1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (3, 9)):
        d(False, iua(0, 1, p_status(t, i), p_info('ntfy')))          # Notify, status type/identification
    d(True, iua(0, 2, p_int_iid(1), p_dlci(*dlci(0, 64))))           # TEI status request
    d(False, iua(0, 3, p_int_iid(1), p_dlci(*dlci(0, 64)), p_tei(0)))   # TEI status confirmation
    d(False, iua(0, 4, p_int_iid(1), p_dlci(*dlci(0, 64)), p_tei(1)))   # TEI status indication, unassigned
    d(False, iua(0, 4, p_int_iid(1), p_tei(5)))                      # unknown TEI status
    d(True, iua(0, 5, p_int_iid(1)))                                 # TEI query request (no name)
    # --- Q.921/Q.931 boundary primitive transport (class 5)
    d(True, iua(5, 5, p_int_iid(1), p_dlci(*dlci(0, 64))))           # Establish request
    d(False, iua(5, 6, p_int_iid(1), p_dlci(*dlci(0, 64))))          # Establish confirm
    d(False, iua(5, 7, p_int_iid(1), p_dlci(*dlci(0, 64))))          # Establish indication
    # Protocol data: with GSM SAPIs (default) the SAPI selects the dissector
    # table entry, SAPI 0 is the radio signalling (RSL), the others have no
    # dissector here; without them (use_gsm_sapi_values off) SAPI 0 and 1 are Q.931
    # and SAPI 16 X.25
    for typ in (1, 2, 3, 4):
        d(True, iua(5, typ, p_int_iid(1), p_dlci(*dlci(0, 64)), p_data(RSL)))      # SAPI 0 -> RSL
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(1, 64)), p_data(Q931)))           # SAPI 1
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(16, 64)), p_data(X25)))           # SAPI 16
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(12, 64)), p_data(LAYER2)))        # SAPI 12
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(63, 127)), p_data(LAYER2 + b'\xaa')))  # SAPI 63 (odd length, padded)
    d(True, iua(5, 1, p_int_iid(1), p_data(Q931)))                                  # protocol data without DLCI
    d(True, iua(5, 1, p_int_iid(1), p_dlci(0x02 | 0x04, 0x00), p_data(Q931)))      # spare bit set (SAPI 1), "one" bit clear
    d(True, iua(5, 3, p_int_iid(2), p_dlci(*dlci(63, 127)), p_data(b'')))           # empty protocol data
    d(True, iua(5, 8, p_int_iid(1), p_dlci(*dlci(0, 64)), p_release(0)))           # Release request, reasons 0-3
    d(False, iua(5, 9, p_int_iid(1), p_dlci(*dlci(0, 64))))                        # Release confirm
    d(False, iua(5, 10, p_int_iid(1), p_dlci(*dlci(0, 64)), p_release(1)))         # Release indication
    d(False, iua(5, 10, p_int_iid(1), p_dlci(*dlci(0, 64)), p_release(2)))
    d(False, iua(5, 10, p_int_iid(1), p_dlci(*dlci(0, 64)), p_release(3)))
    d(False, iua(5, 10, p_int_iid(1), p_dlci(*dlci(0, 64)), p_release(77)))
    # --- other classes, types and parameters
    d(True, iua(1, 1, p_int_iid(1)))                                 # transfer class: no name
    d(True, iua(2, 1))                                               # SSNM class
    d(True, iua(5, 11, p_int_iid(1)))                                # QPTM, unknown type
    d(True, iua(9, 1, p_int_iid(1)))                                 # unknown class
    d(True, iua(0, 1, param(0x7f, b'\x01\x02\x03\x04\x05'), param(0x02, b'')))    # unknown tags
    d(True, iua(0, 1, param(0x7f, b'')))                             # unknown tag, no value
    d(True, iua(3, 1, p_info('a'), p_info('bc'), p_info('def')))     # padding of 3, 2, 1
    d(True, iua(0, 1, version=2))                                    # protocol version other than 1
    d(True, iua(0, 1, p_text_iid('PRI-2')))
    d(True, iua(0, 1, p_text_iid('')))                               # empty text id
    d(True, iua(0, 1, p_int_iid()))                                  # integer ids, none
    d(True, iua(0, 1, p_ranges()))                                   # ranges, none
    d(True, iua(0, 1, p_beat(b'')))
    # IUA also on payload protocol identifier 1 on another port
    a.data(True, iua(3, 3, p_beat(b'ppi-only')), ppi=1)
    # Two messages in one SCTP packet: separate DATA chunks
    c1 = struct.pack('!BBHIHHI', 0, 3, 16 + 8, a.tsn[True], 1, 40, 1) + iua(3, 3)
    c2 = struct.pack('!BBHIHHI', 0, 3, 16 + 8, a.tsn[True] + 1, 1, 41, 1) + iua(3, 6)
    a.tsn[True] += 2
    fr.append(sctp_frame(True, [c1, c2]))
    return fr


def malformed_frames():
    fr = []
    a = Assoc(fr)
    a.setup()
    d = a.data
    # protocol data that the GSM SAPI dissectors (RSL, TFP, OML, PGSL) reject
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(0, 64)), p_data(Q931)))
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(0, 64)), p_data(b'')))
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(10, 64)), p_data(bytes(8))))
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(62, 0)), p_data(LAYER2 + b'\xaa')))
    d(True, iua(5, 1, p_int_iid(1), p_dlci(*dlci(12, 64)), p_data(bytes(8))))
    # parameter length smaller than the header
    d(True, iua(0, 1, param(0x03, b'ABCD', length=3)))              # text id, length 3 (length - 4 wraps)
    d(True, iua(0, 1, param(0x04, b'ABCD', length=2)))              # info string, length 2
    d(True, iua(0, 1, param(0x07, b'ABCD', length=0)))              # diagnostic, length 0
    d(True, iua(0, 1, param(0x09, b'ABCD', length=1)))              # heartbeat data, length 1
    d(True, iua(0, 1, param(0x7f, b'ABCD', length=2)))              # unknown parameter, length 2
    d(True, iua(0, 1, param(0x0e, b'ABCD', length=3)))              # protocol data, length 3
    d(True, iua(0, 1, param(0x01, b'ABCD', length=3)))              # integer id, length 3
    d(True, iua(0, 1, param(0x08, b'ABCD', length=3)))              # ranges, length 3
    # parameter length larger than the data
    d(True, iua(0, 1, param(0x01, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x03, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x04, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x05, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x07, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x08, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x09, b'ABCD', length=40)))
    d(True, iua(0, 1, param(0x7f, b'ABCD', length=40)))
    d(True, iua(5, 1, param(0x05, struct.pack('!BBH', 0, 1, 0)), param(0x0e, b'ABCD', length=40)))
    # fixed-size parameters too short
    for tag in (0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0f, 0x10):
        d(True, iua(0, 1, param(tag, b'\x01')))
    d(True, iua(0, 1, param(0x11, b'\x01')))
    # truncated parameter header and common header
    d(True, iua(0, 1) + b'\x00\x01')
    d(True, iua(0, 1) + b'\x00')
    d(True, b'\x01\x00\x03')
    d(True, b'\x01')
    # parameters with the Implementers Guide differences, malformed
    d(True, iua(0, 1, param(0x11, b'\x01')))
    return fr


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'iua-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'iua-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

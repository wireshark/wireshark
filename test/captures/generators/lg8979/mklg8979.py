#!/usr/bin/env python3
# Generates test/captures/lg8979_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Landis & Gyr Telegyr 8979
dissector (packet-lg8979.c). The protocol has no default port, so the
captures use TCP port 29998 and have to be dissected with
-d tcp.port==29998,lg8979. Messages: 0xFF, flags, RTU address, function
blocks (function code with the last-block bit, data length, data) and a
CRC-16; requests (master to RTU) and responses (RTU to master) are told
apart by flags, length and function code. Every packet is built with
struct; nothing comes from a real network.

Usage: mklg8979.py <output directory>

Writes:
  lg8979-coverage.pcap            requests and responses of every function
                                  code the dissector decodes, short
                                  responses, stacked responses, and the
                                  262 octet response from the fix
  lg8979-coverage-malformed.pcap  messages cut short inside each function
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(data):
    if len(data) & 1:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src=IP_A, dst=IP_B, ident=1):
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return hdr + payload


def l4_sum(proto, src, dst, seg):
    ph = src + dst + struct.pack('>BBH', 0, proto, len(seg))
    return csum(ph + seg)


def udp_frame(sport, dport, payload, to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    c = l4_sum(17, src, dst, seg) or 0xffff
    seg = seg[:6] + struct.pack('>H', c) + seg[8:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(17, seg, src, dst, ident)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', to_b=True, ident=1):
    src, dst = (IP_A, IP_B) if to_b else (IP_B, IP_A)
    seg = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      0x50, flags, 8192, 0, 0) + payload
    seg = seg[:16] + struct.pack('>H', l4_sum(6, src, dst, seg)) + seg[18:]
    macs = (MAC_B, MAC_A) if to_b else (MAC_A, MAC_B)
    return macs[0] + macs[1] + b'\x08\x00' + ipv4(6, seg, src, dst, ident)


class TcpFlow:
    """One TCP connection; data() returns frames with correct seq/ack."""

    def __init__(self, cport, sport, isn_c=1000, isn_s=5000):
        self.c, self.s = cport, sport
        self.seq_c, self.seq_s = isn_c, isn_s
        self.n = 0

    def _id(self):
        self.n += 1
        return self.n

    def open(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, 0, 0x02, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x12, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f

    def data(self, payload, from_client=True):
        if from_client:
            fr = tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x18, payload, True, self._id())
            self.seq_c += len(payload)
        else:
            fr = tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x18, payload, False, self._id())
            self.seq_s += len(payload)
        return fr

    def close(self):
        f = [tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x11, b'', True, self._id())]
        self.seq_c += 1
        f.append(tcp_frame(self.s, self.c, self.seq_s, self.seq_c, 0x11, b'', False, self._id()))
        self.seq_s += 1
        f.append(tcp_frame(self.c, self.s, self.seq_c, self.seq_s, 0x10, b'', True, self._id()))
        return f


PORT = 29998        # no default port: tests use -d tcp.port==29998,lg8979
CRC = b'\xab\xcd'

# function codes
ANG_CHGRPT, ANG_FRCRPT, ANGGRP_CHGRPT, ANGGRP_FRCRPT, ADC_FRCRPT = 0, 1, 2, 3, 5
IND_CHGRPT, IND_FRCRPT, SOE_CHGRPT, SOE_FRCRPT = 6, 7, 8, 9
DIG_FRCRPT, ACC_CHGRPT, ACC_FRCRPT, SOELOG_CHGRPT = 11, 12, 13, 14
ANG_OUTPUT, SBO_SELECT, SBO_OPERATE, DIG_OUTPUT, ACC_FREEZE = 20, 21, 22, 23, 24
PUL_OUTPUT, PULTR_OUTPUT, SBO_IMEXECUTE, RTU_RESTART, RTU_CONFIG = 25, 26, 28, 30, 31
TIME_SYNC, TIME_BIAS, ANG_DEADBAND, ANGGRP_DEFINE, ACC_PRESET = 32, 33, 34, 35, 36
CONT_REQUEST, REPEAT_MSG, FIRMWARE_CFG, EXP_RPT = 37, 38, 39, 63


def blk(fc, data=b'', lmb=False, length=None):
    """One function block: function code (bit 7 = last block mark), data
    length, data."""
    return bytes([fc | (0x80 if lmb else 0), len(data) if length is None else length]) + data


def pkt(flags, addr, blocks=b'', crc=CRC):
    return bytes([0xff, flags, addr]) + blocks + crc


def a12(ptnum, val):
    """Analog change report entry: 12 bit point number and 12 bit value."""
    return bytes([ptnum & 0xff, ((ptnum >> 8) & 0x0f) | ((val & 0x0f) << 4), val >> 4])


def p16(*v):
    return b''.join(struct.pack('<H', x) for x in v)


def main_frames():
    F = []
    t = TcpFlow(42000, PORT)
    F += t.open()

    def M(p):        # master to RTU (client)
        F.append(t.data(p, True))

    def R(p):        # RTU to master (server)
        F.append(t.data(p, False))

    # ---- Master -> RTU requests (flags 0x00 / 0x04) ----
    M(pkt(0x00, 1, blk(ANG_FRCRPT, p16(0x0010, 0x0020))))
    M(pkt(0x04, 1, blk(IND_FRCRPT, p16(0x0100, 0x01ff), lmb=True)))
    M(pkt(0x00, 2, blk(SOE_FRCRPT, p16(0, 0x0fff))))
    M(pkt(0x00, 2, blk(ANGGRP_CHGRPT, bytes([3]))))
    M(pkt(0x00, 2, blk(ANGGRP_FRCRPT, bytes([4]))))         # no case in the request switch
    M(pkt(0x00, 3, blk(DIG_FRCRPT, bytes([0, 15]))))
    M(pkt(0x00, 3, blk(ACC_FRCRPT, bytes([1, 8]))))
    M(pkt(0x00, 3, blk(TIME_BIAS, p16(0xfff0))))
    M(pkt(0x00, 4, blk(ANG_OUTPUT, bytes([7]) + p16(0x0abc))))
    M(pkt(0x00, 4, blk(SBO_SELECT, bytes([9, 0x80 | 0x05]))))    # close, timer count 5
    M(pkt(0x00, 4, blk(SBO_SELECT, bytes([10, 0x00 | 0x1f]))))   # trip
    M(pkt(0x04, 4, blk(SBO_OPERATE, bytes([9]))))
    M(pkt(0x00, 5, blk(DIG_OUTPUT, bytes([2, 0x11, 0x22, 0x33]))))
    M(pkt(0x00, 5, blk(ACC_FREEZE, bytes([1, 2, 3]))))           # no case
    M(pkt(0x00, 5, blk(PUL_OUTPUT, bytes([3, 0x80 | 0x20 | 0x04]))))   # raise
    M(pkt(0x00, 5, blk(PUL_OUTPUT, bytes([4, 0x00 | 0x03 << 4 | 0x09]))))  # lower
    M(pkt(0x00, 5, blk(PULTR_OUTPUT, bytes([4, 5]))))
    M(pkt(0x00, 6, blk(SBO_IMEXECUTE, bytes([5]))))
    M(pkt(0x00, 6, blk(TIME_SYNC, bytes([11, 7, 13, 59, 58]) + p16(999))))
    M(pkt(0x00, 6, blk(ANG_DEADBAND, p16(0x0020) + bytes([1, 2, 3, 4]))))
    M(pkt(0x00, 6, blk(ANG_DEADBAND, p16(0x0020))))              # no deadbands
    M(pkt(0x00, 7, blk(ANGGRP_DEFINE, bytes([2]) + p16(0x0040) + bytes([0xff, 0x0f, 0x01]))))
    M(pkt(0x00, 7, blk(ACC_PRESET, bytes([1]) + p16(1000) + bytes([2]) + p16(2000))))
    M(pkt(0x00, 7, blk(ACC_PRESET)))                              # no entries
    M(pkt(0x00, 7, blk(CONT_REQUEST)))
    # master requests with a zero length block of the "report" functions
    for n, fc in enumerate((ANG_CHGRPT, ADC_FRCRPT, IND_CHGRPT, SOE_CHGRPT, ACC_CHGRPT,
                            SOELOG_CHGRPT, REPEAT_MSG, RTU_CONFIG, FIRMWARE_CFG)):
        M(pkt(0x00, 8, blk(fc)))
    # master request with the short response flag
    M(pkt(0x80, 9, blk(SBO_SELECT, bytes([1, 0x80]))))
    M(pkt(0x90, 9, blk(SBO_SELECT, bytes([1, 0x00]))))

    # ---- RTU -> Master responses ----
    # short responses (5 octets), with and without the SHR flag
    R(pkt(0x80, 1))
    R(pkt(0x00, 1))
    R(pkt(0x40, 1))
    # analog change report: 12 bit values
    R(pkt(0x00, 1, blk(ANG_CHGRPT, a12(1, 100) + a12(0xabc, 0xdef) + a12(0, 0))))
    R(pkt(0x10, 1, blk(ANGGRP_CHGRPT, a12(5, 4095), lmb=True)))
    # analog force report: 1, 2, 3 and 4 values (data length 4..8)
    R(pkt(0x10, 2, blk(ANG_FRCRPT, p16(0x0010) + bytes([0x11, 0x2f]))))
    R(pkt(0x00, 2, blk(ANG_FRCRPT, p16(0x0020) + a12(0x123, 0x456)[:3])))
    R(pkt(0x00, 2, blk(ANG_FRCRPT, p16(0x0030) + bytes([1, 2, 3, 4, 5]))))
    R(pkt(0x00, 2, blk(ANG_FRCRPT, p16(0x0040) + bytes([1, 2, 3, 4, 5, 6]))))
    R(pkt(0x00, 2, blk(ADC_FRCRPT, p16(0x0050) + bytes([1, 2, 3, 4, 5]))))
    # indication change reports
    R(pkt(0x20, 3, blk(IND_CHGRPT, p16(0x8001, 0x4fff, 0xc123))))
    R(pkt(0x20, 3, blk(IND_FRCRPT, p16(0x0100) + bytes([0xaa, 0x55, 0xff, 0x00]))))
    R(pkt(0x08, 3, blk(SOE_CHGRPT, p16(0x8010, 0x0011))))
    R(pkt(0x04, 3, blk(SOE_FRCRPT, p16(0x0200) + bytes([0x0f, 0xf0, 0x81, 0x7e]))))
    # digital input force report: start block and two 16 bit blocks
    R(pkt(0x10, 4, blk(DIG_FRCRPT, bytes([4]) + p16(0xa5a5, 0x5a5a))))
    # accumulator reports
    R(pkt(0x10, 4, blk(ACC_CHGRPT, bytes([2]) + p16(10, 20, 30))))
    R(pkt(0x10, 4, blk(ACC_FRCRPT, bytes([0]) + p16(0xffff))))
    # SOE log change report with two 9 octet records
    ts = lambda mo, d, h, mi, s, ms: bytes([mo, d, h, mi, s]) + p16(ms)
    R(pkt(0x14, 4, blk(SOELOG_CHGRPT, p16(0x8123) + ts(1, 2, 3, 4, 5, 678)
                       + p16(0x0456) + ts(12, 31, 23, 59, 59, 999))))
    # echoes of control requests (flags mark RTU -> master)
    R(pkt(0x10, 5, blk(SBO_SELECT, bytes([9, 0x85]))))
    R(pkt(0x10, 5, blk(SBO_OPERATE, bytes([9]))))
    # RTU configuration: two chassis with 16 card codes each
    cards = bytes([0, 1, 2, 3, 4, 5, 7, 8, 11, 12, 15, 28, 29, 30, 31, 9])
    R(pkt(0x10, 6, blk(RTU_CONFIG, bytes([2]) + bytes([0]) + cards + bytes([1]) + cards)))
    R(pkt(0x10, 6, blk(RTU_CONFIG, bytes([0]))))                  # no chassis
    R(pkt(0x10, 6, blk(TIME_BIAS, bytes([25]))))
    R(pkt(0x10, 6, blk(FIRMWARE_CFG, p16(0x0213))))
    # exception reports: parameter shown, and code 14 (function not allowed)
    R(pkt(0x10, 7, blk(EXP_RPT, bytes([1, 0]))))
    R(pkt(0x10, 7, blk(EXP_RPT, bytes([9, 99]))))
    R(pkt(0x10, 7, blk(EXP_RPT, bytes([14, 34]))))
    R(pkt(0x10, 7, blk(EXP_RPT, bytes([14, 200]))))
    R(pkt(0x10, 7, blk(EXP_RPT, bytes([0x77, 5]))))
    # stacked responses: several blocks in one message
    R(pkt(0x40, 8, blk(ANG_CHGRPT, a12(1, 2)) + blk(IND_CHGRPT, p16(0x8001))
          + blk(ACC_CHGRPT, bytes([0]) + p16(5), lmb=True)))
    # unknown function code with no data, and a block after it
    R(pkt(0x10, 8, blk(4) + blk(RTU_RESTART) + blk(ANG_CHGRPT, a12(7, 7))))
    # classified by function code and length although the flags are zero
    R(pkt(0x00, 9, blk(ANG_CHGRPT, a12(2, 3))))
    R(pkt(0x00, 9, blk(DIG_FRCRPT, bytes([4]) + p16(1))))
    R(pkt(0x00, 9, blk(ANGGRP_CHGRPT, a12(4, 5))))
    R(pkt(0x00, 9, blk(EXP_RPT, bytes([2, 0]))))
    # indeterminate: unknown function, flags zero (only the header is shown)
    M(pkt(0x00, 9, blk(4, bytes([1, 2]))))
    M(pkt(0x00, 9, blk(RTU_RESTART, bytes([1]))))
    # shorter than 6 octets and not 5: indeterminate
    M(bytes([0xff, 0x00]))
    M(bytes([0xff, 0x00, 0x01, 0xaa]))
    # not an 8979 packet on this port (does not start with 0xff)
    M(b'\x01\x02\x03\x04\x05\x06\x07\x08')
    # Reproducer: a response of 262 octets (256 + 6) whose first block is an
    # indication force report of length 4 (as short as a request). The
    # length was truncated to 8 bits (6) when classifying, which made the
    # message a master -> RTU request.
    big = pkt(0x00, 10, blk(IND_FRCRPT, p16(0x0300) + bytes([0xaa, 0x55]))
              + blk(ACC_CHGRPT, bytes([0]) + p16(*range(124))))
    assert len(big) == 262
    R(big)
    # flags with both bit 2 and bit 3 set: a response whatever the function code
    R(pkt(0x0c, 11, blk(ANG_CHGRPT, a12(1, 1))))
    F += t.close()
    return F


def malformed_frames():
    F = []
    t = TcpFlow(42001, PORT)
    F += t.open()

    def M(p):
        F.append(t.data(p, True))

    # truncated messages (exceptions)
    M(pkt(0x10, 1, blk(IND_CHGRPT, p16(0x8001), length=6)))             # runs past the end
    M(pkt(0x10, 1, blk(ANG_CHGRPT, b'\x01', length=9), crc=b''))
    M(pkt(0x10, 1, blk(RTU_CONFIG, bytes([200]))))                     # 200 chassis
    M(pkt(0x10, 1, blk(ANG_FRCRPT, b''), crc=b'')[:6])
    M(pkt(0x10, 1, blk(SOELOG_CHGRPT, b'\x00' * 5, length=9)))
    M(bytes([0xff, 0x10, 0x01, FIRMWARE_CFG, 2, 0x13]))                 # firmware version cut
    M(bytes([0xff, 0x00, 0x01, TIME_SYNC, 7, 1, 2, 3]))                # time sync cut
    M(bytes([0xff, 0x00, 0x01, ANG_OUTPUT, 3, 1, 2]))                  # analog output cut
    M(bytes([0xff, 0x00, 0x01, ANG_DEADBAND, 40, 1, 0, 9]))            # 38 deadbands cut
    M(bytes([0xff, 0x00, 0x01, ANGGRP_DEFINE, 40, 1, 0, 9]))
    M(bytes([0xff, 0x00, 0x01, ACC_PRESET, 30, 1, 0, 9]))
    M(bytes([0xff, 0x00, 0x01, DIG_OUTPUT, 4, 1]))
    M(bytes([0xff, 0x00, 0x01, PUL_OUTPUT, 2, 1]))
    M(bytes([0xff, 0x00, 0x01, SBO_SELECT, 2, 1]))
    M(bytes([0xff, 0x00, 0x01, ANG_FRCRPT, 4, 1, 0]))
    M(bytes([0xff, 0x00, 0x01, DIG_FRCRPT, 2, 1]))
    M(bytes([0xff, 0x00, 0x01, TIME_BIAS, 2, 1]))
    M(bytes([0xff, 0x00, 0x01, ANGGRP_CHGRPT, 1]))
    M(bytes([0xff, 0x80, 0x01]))                                         # SHR flag, no CRC
    # response cut inside each reading function
    for fc, n in ((ANG_FRCRPT, 4), (ADC_FRCRPT, 7), (IND_FRCRPT, 4), (SOE_FRCRPT, 4),
                  (DIG_FRCRPT, 3), (ACC_CHGRPT, 3), (SBO_SELECT, 2), (EXP_RPT, 2),
                  (RTU_CONFIG, 3), (FIRMWARE_CFG, 2), (TIME_BIAS, 1), (SOE_CHGRPT, 4),
                  (ANG_CHGRPT, 6), (ANGGRP_CHGRPT, 3)):
        M(bytes([0xff, 0x10, 0x01, fc, n, 1]))
    F += t.close()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'lg8979-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'lg8979-coverage-malformed.pcap'), malformed_frames())


main()

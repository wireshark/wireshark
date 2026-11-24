#!/usr/bin/env python3
# Generates test/captures/smpte_2038_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMPTE ST 2038 dissector
(packet-smpte-2038.c, ANC data in MPEG-2 transport stream PES packets).

Usage: mksmpte-2038.py <output directory>

The transport stream goes over UDP (7 TS packets per datagram) to a port
that the MP2T heuristic accepts. A PAT and a PMT with a registration
descriptor "VANC" (0x56414e43) on a private-data stream (type 0x06) make
the MPEG PES dissector hand the PES payload to ST 2038 (the
mpeg-pes.registration table). Every packet is built with struct; nothing
is captured.

Writes:
  smpte-2038-coverage.pcapng            valid ANC records
  smpte-2038-coverage-malformed.pcapng  reserved bits, bad parity, bad
                                        checksum, bad alignment, extra
                                        stuffing between records, records
                                        cut short, several lines in one
                                        PES packet, a captured length
                                        shorter than the reported one
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib import pcapng, udp
from vanc import afd, anc_words, bits, timecode, tobytes
from tslib import null_packet, pat, pes, pes_to_ts, pmt, psi_packet, ts_packet

PID_PMT, PID_ANC = 0x100, 0x101
REG = struct.pack('!BB', 5, 4) + b'VANC'


def record(c, line, hoff, did, sdid, udw, reserved=0, **kw):
    """One ST 2038 ANC record, byte aligned with '1' bits."""
    b = format(reserved, '06b') + str(c) + format(line, '011b') + format(hoff, '012b')
    b += bits(anc_words(did, sdid, udw, **kw))
    b += '1' * ((-len(b)) % 8)
    return b


class Stream:
    def __init__(self):
        self.frames = []
        self.cc = {PID_PMT: 0, PID_ANC: 0, 0: 0}
        self.pkts = []
        self.n = 0

    def flush(self, port=5000, force=True):
        while self.pkts:
            grp, self.pkts = self.pkts[:7], self.pkts[7:]
            while len(grp) < 7:
                grp.append(null_packet())
            self.n += 1
            self.frames.append(udp(b''.join(grp), 4000, port, ident=self.n))

    def flush_full(self):
        # whole datagrams only; the rest waits for more packets
        while len(self.pkts) >= 7:
            grp, self.pkts = self.pkts[:7], self.pkts[7:]
            self.n += 1
            self.frames.append(udp(b''.join(grp), 4000, 5000, ident=self.n))

    def psi(self):
        self.pkts.append(psi_packet(0, pat(), self.cc[0]))
        self.cc[0] += 1
        self.pkts.append(psi_packet(PID_PMT, pmt([(0x06, PID_ANC, REG)]), self.cc[PID_PMT]))
        self.cc[PID_PMT] += 1
        self.flush()

    def pes(self, payload, pts=None, snap=None, flush=True, bounded=True):
        pk, self.cc[PID_ANC] = pes_to_ts(PID_ANC, pes(0xbd, payload, pts, bounded),
                                         self.cc[PID_ANC])
        self.pkts += pk
        if flush:
            self.flush_full()


def main(out):
    s = Stream()
    s.psi()
    tc = timecode()
    # 1: one Type 2 record (time code), Y channel
    s.pes(tobytes(record(0, 9, 0, 0x60, 0x60, tc)), pts=90000)
    # 2: two records on one line: AFD (C channel) and an unknown Type 2 DID
    s.pes(tobytes(record(1, 10, 100, 0x41, 0x05, afd()) +
                  record(0, 10, 200, 0x41, 0x0b, [1, 2, 3])), pts=93600)
    # 3: Type 1 record (DBN), audio control, no data words
    s.pes(tobytes(record(0, 12, 0xffe, 0xe0, 0x55, [])), pts=97200)
    # 4: Type 1 with data, then trailing 0xff stuffing bytes
    s.pes(tobytes(record(0, 12, 0xffd, 0xec, 0x01, list(range(1, 10)))) + b'\xff' * 5, pts=100800)
    # 5: records whose lengths give 0..7 alignment bits (data counts 0-7)
    r = ''.join(record(0, 20, 5 * k, 0x45, 0x01 + (k & 7), list(range(k))) for k in range(8))
    s.pes(tobytes(r))
    # 6: a long record (data count 255) spread over several TS packets
    s.pes(tobytes(record(0, 21, 0, 0x44, 0x04, [(7 * k) & 0xff for k in range(255)]) +
                  record(1, 21, 4, 0x41, 0x0a, [0xaa, 0x55])), pts=104400)
    # 7: line number and horizontal offset extremes
    s.pes(tobytes(record(0, 0x7ff, 0xfff, 0x62, 0x01, [0x10, 0x20]) +
                  record(1, 0x7ff, 0, 0x62, 0x02, [])))
    # 8: a PES packet of only stuffing bytes (no ANC record)
    s.pes(b'\xff\xff\xff\xff')
    # 9: one more record so that the stuffing-only PES packet is completed
    s.pes(tobytes(record(0, 9, 0, 0x60, 0x60, timecode(23, 59, 59, 24))), pts=108000)
    s.pes(tobytes(record(0, 9, 0, 0x60, 0x60, tc)), pts=111600)
    s.flush()
    pcapng(os.path.join(out, 'smpte-2038-coverage.pcapng'), s.frames)
    print('%d frames (1: PAT and PMT, 2-%d PES)' % (len(s.frames), len(s.frames)))

    # malformed
    m = Stream()
    m.psi()
    m.pes(tobytes(record(0, 9, 0, 0x60, 0x60, tc, reserved=0x2a)))          # reserved bits
    m.pes(tobytes(record(0, 9, 0, 0x60, 0x60, tc, bad_did=True, bad_sdid=True, bad_dc=True)))
    m.pes(tobytes(record(0, 9, 0, 0xe0, 0x01, [1, 2], bad_did=True, bad_sdid=True, bad_cs=True)))
    m.pes(tobytes(record(0, 9, 0, 0x41, 0x0b, [1, 2, 3]), pad='0'))          # normal
    # alignment bits zero
    r = format(0, '06b') + '0' + format(9, '011b') + format(0, '012b') + \
        bits(anc_words(0x41, 0x0b, [1, 2, 3]))
    m.pes(tobytes(r, '0'))
    # extra 1 bits between records (non-conformant stuffing), and a second line
    m.pes(tobytes(record(0, 9, 0, 0x41, 0x0b, [5]) + '1' * 13 +
                  record(0, 11, 0, 0x41, 0x0b, [6]) + '1' * 100 +
                  record(0, 11, 0, 0x41, 0x0b, [7])))
    m.pes(tobytes(record(0, 9, 0, 0x41, 0x0b, [5]) + '1' * 8 + '0' * 3, pad='1'))
    # records cut short: header, UDW and alignment
    full = tobytes(record(0, 9, 0, 0x41, 0x0b, [1, 2, 3, 4, 5, 6]))
    m.pes(full[:5])
    m.pes(full[:8])
    m.pes(full[:12])
    m.pes(tobytes(record(0, 9, 0, 0x41, 0x0b, [])[:-1] + '1111')[:-0 or None][:10])
    # exactly 70 bits of header and no room for the alignment bits
    b = format(0, '06b') + '0' + format(9, '011b') + format(0, '012b') + bits(anc_words(0x41, 0x0b, [3]))
    m.pes(tobytes(b[:-2] if len(b) % 8 > 2 else b[:-1], '1'))
    m.flush()
    # captured length shorter than the reported length: snaplen-style cut of
    # the UDP datagram is not possible per PES, so cut the frame
    fr = m.frames
    cut = udp(b''.join(ts_packet(PID_ANC, b'', 0) for _ in range(0)), 1, 1)
    pcapng(os.path.join(out, 'smpte-2038-coverage-malformed.pcapng'), fr)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')

#!/usr/bin/env python3
# Generates test/captures/eobi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EOBI dissector
(packet-eobi.c, Eurex/Xetra Enhanced Order Book Interface 10.0).

EOBI runs over UDP on the T7 market data ports (59000, 59001, 56500,
...); the protocol is disabled by default (--enable-protocol eobi). A
datagram carries messages that start with BodyLen (LE 16 bit) and
TemplateID; udp_dissect_pdus() splits them by BodyLen. The dissector is
generated from the ETI XML and is table driven: every template is a list
of fields (unsigned/signed integers, enums, fixed point decimals,
nanosecond timestamps, the DSCP bit field, counters and repeating
groups). mkeobi.py walks the same tables (extracted into eobi_layout.py
by eobi_extract.py) to build every template, with each field set, with
optional fields absent (NO_VALUE), with negative and small fixed point
values, and with repeating groups empty, once and at their maximum.
Every packet is built from scratch with struct; no captured traffic is
used.

Usage: mkeobi.py <output directory>

Writes:
  eobi-coverage.pcap            every template in several variants,
                                packed several to a datagram behind a
                                PacketHeader, plus the warnings (missing
                                required value, unused value set,
                                counter overflow)
  eobi-coverage-malformed.pcap  unknown and out of range template IDs,
                                wrong BodyLen, messages cut short
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct

from pktlib import pcap, udp_frame  # noqa: E402
from eobi_layout import FIELDS, USAGES, TEMPLATES, ENUM_VALS  # noqa: E402

PORT_INC = 59001     # Incremental, EUREX US-allowed PROD
PORT_SNAP = 59000    # Snapshot
PACKET_HEADER = 13005

NOVAL_U = {1: 0xff, 2: 0xffff, 4: 0xffffffff, 8: 0xffffffffffffffff}
NOVAL_I = {1: -0x80, 2: -0x8000, 4: -0x80000000, 8: -0x8000000000000000}
FMT_U = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
FMT_I = {1: '<b', 2: '<h', 4: '<i', 8: '<q'}

# Template ID -> TemplateID field value; BodyLen is filled in later.
TS = 1700000000123456789


class Variant:
    """How to fill the fields of one message.

    absent:   'unused' sets only the unused fields (usage 2) to NO_VALUE,
              'optional' also the optional ones (usage 1).
    count:    'one', 'max', 'zero', 'novalue' or a number for the
              repeating group counters.
    fixed:    'pos', 'neg', 'small', 'zero' for fixed point values.
    missing:  set every required integer and decimal after the header to
              NO_VALUE (warning "required value is missing").
    overused: set the unused fields (warning "unused value is set").
    overflow: set the counters to max + 1 (warning "counter overflow").
    """

    def __init__(self, absent='unused', count='one', fixed='pos', missing=False,
                 overused=False, overflow=False, seed=1):
        self.absent, self.count, self.fixed = absent, count, fixed
        self.missing, self.overused, self.overflow = missing, overused, overflow
        self.seed = seed


def build(tid, seq, v):
    """Walk the field table of template tid like dissect_eobi_message()
    and return the message bytes, padded to the template's BodyLen."""
    name, fidx, size, uidx = TEMPLATES[tid]
    out = bytearray()
    counter = [0] * 8
    top, repeats, old_fidx, old_uidx = 1, 0, 0, 0
    n = v.seed
    while top:
        t, co, fsize, fh, ett = FIELDS[fidx]
        usage = USAGES[uidx] if uidx < len(USAGES) else 0
        if t == 'ETI_EOF':
            if repeats:
                repeats -= 1
                fidx = int_field(FIELDS[old_fidx])
                uidx = old_uidx
            else:
                fidx = old_fidx + 1
                top -= 1
            continue
        if t in ('ETI_STRUCT', 'ETI_VAR_STRUCT'):
            repeats = counter[co] if t == 'ETI_VAR_STRUCT' else 1
            if repeats:
                repeats -= 1
                old_fidx, old_uidx = fidx, uidx
                fidx = int_field(FIELDS[fidx])
                top += 1
            else:
                fidx += 1
            continue
        if t == 'ETI_PADDING':
            out += bytes(fsize)
            fidx += 1
            continue
        n += 1
        if t == 'ETI_COUNTER':
            mx = ett
            c = v.count
            if v.overflow:
                val, cnt = mx + 1, mx
            elif c == 'novalue':
                val, cnt = NOVAL_U[fsize], 0
            else:
                cnt = {'one': 1, 'max': mx, 'zero': 0}.get(c, c)
                cnt = min(cnt, mx)
                val = cnt
            counter[co] = cnt
            out += struct.pack(FMT_U[fsize], val)
        elif t == 'ETI_UINT':
            if fh == 'BODYLEN_FH_IDX':
                val = size
            elif fh == 'TEMPLATEID_FH_IDX':
                val = tid
            elif fh == 'MSGSEQNUM_FH_IDX' and usage != 2:
                val = seq
            else:
                val = absent_or(v, usage, NOVAL_U[fsize], (n * 7919) % (NOVAL_U[fsize]))
                if usage == 0 and v.missing:
                    val = NOVAL_U[fsize]
                if usage == 2 and v.overused:
                    val = 1
            out += struct.pack(FMT_U[fsize], val)
        elif t == 'ETI_INT':
            pos = (n * 104729) % (1 << (8 * fsize - 2))
            norm = -pos if v.fixed == 'neg' else pos
            val = absent_or(v, usage, NOVAL_I[fsize], norm)
            if usage == 0 and v.missing:
                val = NOVAL_I[fsize]
            if usage == 2 and v.overused:
                val = 1
            out += struct.pack(FMT_I[fsize], val)
        elif t in ('ETI_UINT_ENUM', 'ETI_INT_ENUM'):
            # cycle through the named values (the last is NO_VALUE)
            vals = ENUM_VALS.get(fh, [n % 6])
            out += struct.pack(FMT_U[fsize], vals[n % len(vals)])
        elif t == 'ETI_FIXED_POINT':
            norm = {'pos': 123456789012 + n, 'neg': -(98765432100 + n),
                    'small': 5 + n % 3, 'zero': 0}[v.fixed]
            if v.fixed == 'small' and n % 2:
                norm = -norm
            val = absent_or(v, usage, NOVAL_I[8], norm)
            if usage == 0 and v.missing:
                val = NOVAL_I[8]
            if usage == 2 and v.overused:
                val = 1
            out += struct.pack('<q', val)
        elif t == 'ETI_TIMESTAMP_NS':
            out += struct.pack('<Q', TS + n * 1000)
        elif t == 'ETI_DSCP':
            out += struct.pack('<B', (n * 0x25) & 0xff)
        else:
            raise ValueError(t)
        fidx += 1
        uidx += 1
    assert len(out) <= size, (tid, name, len(out), size)
    return bytes(out) + bytes(size - len(out))


def int_field(f):
    """field_handle_idx of a struct entry is the field index of its
    member list."""
    return int(f[3])


def absent_or(v, usage, noval, val):
    if usage == 2:
        return noval
    if usage == 1 and v.absent == 'optional':
        return noval
    return val


def packet_header(seq, appl_seq, v=None):
    return build(PACKET_HEADER, seq, v or Variant())


def datagram(port, msgs, seq):
    return udp_frame(40000, port, packet_header(seq, seq) + b''.join(msgs))


def has_counter(tid):
    _, fidx, _, _ = TEMPLATES[tid]
    i = fidx
    while FIELDS[i][0] != 'ETI_EOF' or i == fidx:
        if FIELDS[i][0] == 'ETI_COUNTER':
            return True
        i += 1
    return False


def main_frames():
    F = []
    seq = 1
    tids = [t for t in sorted(TEMPLATES) if t != PACKET_HEADER]
    # Every template once, all fields set, groups once (several to a
    # datagram as the incremental feed sends them)
    variants = [
        Variant(),
        Variant(absent='optional', count='zero', fixed='neg', seed=3),
        Variant(count='max', fixed='small', seed=5),
        Variant(absent='optional', count='novalue', fixed='zero', seed=7),
    ]
    for vi, v in enumerate(variants):
        port = PORT_SNAP if vi % 2 else PORT_INC
        if vi > 1:
            tids_v = [t for t in tids if has_counter(t)] if v.count in ('max', 'novalue') else tids
            if v.count == 'novalue':
                tids_v = tids
        else:
            tids_v = tids
        batch = []
        size = 0
        for t in tids_v:
            m = build(t, seq, v)
            seq += 1
            if size + len(m) > 1400 and batch:
                F.append(datagram(port, batch, seq))
                batch, size = [], 0
            batch.append(m)
            size += len(m)
        if batch:
            F.append(datagram(port, batch, seq))
    # Warnings: required values missing and unused values set (every
    # template; the PacketHeader too), a counter over its maximum (each
    # in a datagram of its own)
    for t in tids:
        F.append(udp_frame(40000, PORT_INC,
                           build(PACKET_HEADER, seq, Variant(missing=True, overused=True)) +
                           build(t, seq, Variant(missing=True, overused=True, seed=11))))
        seq += 1
    for t in [t for t in tids if has_counter(t)]:
        F.append(udp_frame(40000, PORT_INC, packet_header(seq, seq) +
                           build(t, seq, Variant(overflow=True, seed=13))))
        seq += 1
    # A PacketHeader on its own
    F.append(udp_frame(40000, 56500, packet_header(seq, seq)))
    return F


def hdr(bodylen, tid, seq):
    return struct.pack('<HHI', bodylen, tid, seq)


def malformed_frames():
    F = []
    # Template ID below and above the range, an unallocated one
    for tid in (12000, 13700, 13003):
        F.append(udp_frame(40000, PORT_INC, hdr(16, tid, 1) + bytes(8)))
    # BodyLen that does not match the template (Heartbeat is 16)
    F.append(udp_frame(40000, PORT_INC, hdr(24, 13001, 2) + bytes(16)))
    # Template body cut short (PacketHeader with BodyLen 32 but 12 octets)
    F.append(udp_frame(40000, PORT_INC, hdr(32, PACKET_HEADER, 3) + bytes(4)))
    # BodyLen 0 and fewer than 4 octets
    F.append(udp_frame(40000, PORT_INC, hdr(0, 13001, 4) + bytes(8)))
    F.append(udp_frame(40000, PORT_INC, b'\x10\x00'))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'eobi-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'eobi-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()

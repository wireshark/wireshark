#!/usr/bin/env python3
# Generates test/captures/ipmi_trace_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-trace.c (HPM.2 trace data blocks, pcap
# link-layer type 260 = DLT_IPMI_HPM_2).
# usage: mkipmi-trace.py <outdir> [-v]   (prints the frame ranges with -v)
# The embedded IPMB/KCS/TMode messages are only decoded as commands with
# -o ipmi.dissect_bus_commands:TRUE; the trace dissector does not need it.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from ipmilib import Cap, gz, req, rsp, trace_block

ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

def tb(cap, btype, chn, dtype, pdata, payload, secs=1000, msecs=5, dlen=None):
    return cap.add('trace', trace_block(btype, chn, dtype, pdata, payload, secs, msecs, dlen))

def build(cap):
    rq = req(6, 0x01, b'', 1)
    rs = rsp(6, 0x01, bytes([0x20, 0x81, 0x05, 0x02, 0x02, 0xbf, 0x57, 0x01, 0x00, 0x34, 0x12]), 1)
    kcs_rq = bytes([6 << 2, 0x01])
    kcs_rs = bytes([7 << 2, 0x01, 0]) + bytes(11)
    tm_rq = bytes([6 << 2, 3 << 2 | 1, 0x01])
    tm_rs = bytes([7 << 2, 3 << 2 | 1, 0x01, 0]) + bytes(11)

    # --- trace packet data (block type 0) for each protocol type
    s = len(cap.frames)
    tb(cap, 0, 0, 1, 0x0000, rq)                                    # IPMB-1.0, first channel, from the controller
    tb(cap, 0, 0, 1, 0x0080 | 0x40 | 5, rs)                          # to the controller, second channel, link 5
    tb(cap, 0, 3, 1, 0x00bf, rq, secs=0xffffffff, msecs=999)
    tb(cap, 0, 5, 5, 0x0000, kcs_rq)                                 # KCS
    tb(cap, 0, 5, 5, 0x0080, kcs_rs)
    tb(cap, 0, 1, 6, 0x0080, b'\x01\x02\x03')                        # SMIC: no decoder, data
    tb(cap, 0, 1, 7, 0x0000, b'\x01\x02\x03')                        # BT-10
    tb(cap, 0, 1, 8, 0x0080, b'\x01\x02\x03')                        # BT-15
    tb(cap, 0, 2, 9, 0x0000, tm_rq)                                  # TMode
    tb(cap, 0, 2, 9, 0x0080, tm_rs)
    tb(cap, 0, 0, 2, 0x1234, b'\xaa\xbb')                            # ICMB: protocol data shown as a number
    tb(cap, 0, 0, 4, 0x0101, b'\xaa\xbb')                            # IPMI-SMBus
    tb(cap, 0, 0, 0, 0x0000, b'')                                    # n/a, no data
    for t in (0x1c, 0x1d, 0x1e, 0x1f, 0x33):                         # OEM protocols and a reserved value
        tb(cap, 0, 7, t, 0xffff, b'\x01\x02')
    tb(cap, 0, 15, 1, 0x0000, rq)                                    # channel 15
    mark(cap, 'Trace packet data: IPMB, KCS, TMode, other protocol types', s + 1)

    # --- timestamps
    s = len(cap.frames)
    tb(cap, 0, 0, 1, 0x0000, rq, secs=0, msecs=0)
    tb(cap, 0, 0, 1, 0x0000, rq, secs=1, msecs=999)
    tb(cap, 0, 0, 1, 0x0000, rq, secs=2, msecs=1000)                 # invalid milliseconds: shown as 0
    tb(cap, 0, 0, 1, 0x0000, rq, secs=3, msecs=65535)
    mark(cap, 'Timestamps (milliseconds 0, 999, 1000, 65535)', s + 1)

    # --- channel state change notifications (block type 1)
    s = len(cap.frames)
    for st in (0x00, 0x08, 0x01, 0x0a, 0x05, 0x0f, 0x07, 0x03, 0x04, 0x02, 0x06):
        tb(cap, 1, 0, 1, 0x0000, bytes([0x00, st]))                  # IPMB state notify: format 0 and a state byte
    tb(cap, 1, 1, 1, 0x0000, bytes([0x01, 0x08]))                    # another format
    tb(cap, 1, 0, 5, 0x0000, b'\x00\x01')                            # other protocol: data
    tb(cap, 1, 0, 9, 0x0000, b'')
    mark(cap, 'Channel state change notifications (override and local status values)', s + 1)

    # --- embedded ASCII messages (block type 2)
    s = len(cap.frames)
    for txt in (b'IPMB-A bus error', b'x', b'a longer message with some text in it, 70 characters of text, here'):
        tb(cap, 2, 0, 0, 0x0000, txt)
    tb(cap, 2, 1, 0, 0x0000, b'')                                    # empty message
    tb(cap, 2, 1, 1, 0x0000, b'text')
    mark(cap, 'Embedded ASCII messages', s + 1)

    # --- reserved block type, short blocks
    s = len(cap.frames)
    tb(cap, 3, 0, 1, 0x0000, rq)
    tb(cap, 3, 4, 0x00, 0x0000, b'')
    cap.add('trace', trace_block(0, 0, 1, 0, b'')[:10])             # 10 octets: shorter than the header
    cap.add('trace', b'\x00')
    cap.add('trace', b'')
    mark(cap, 'Reserved block type, blocks shorter than the header (data)', s + 1)

def build_malformed(cap):
    # messages that stop inside a field of the header or the embedded message
    cap.add('trace', trace_block(2, 0, 0, 0, b'abc', dlen=40))      # ASCII length beyond the block
    cap.add('trace', trace_block(0, 0, 1, 0, req(6, 1, b'', 1)[:5]))
    cap.add('trace', trace_block(0, 0, 5, 0, b'\x18'))
    cap.add('trace', trace_block(0, 0, 9, 0, b'\x18\x00'))
    cap.add('trace', trace_block(1, 0, 1, 0, b''))                    # state notify without data
    cap.add('trace', trace_block(1, 0, 1, 0, b'\x00'))
    cap.add('trace', trace_block(0, 0, 1, 0, b'\x20\x18\xc8\x81'))

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-trace-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-trace-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-trace-coverage.pcapng.gz'), os.path.join(out, 'ipmi_trace_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-trace-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()

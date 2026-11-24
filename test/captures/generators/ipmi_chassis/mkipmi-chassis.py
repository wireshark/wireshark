#!/usr/bin/env python3
# Generates test/captures/ipmi_chassis_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-chassis.c (IPMI NetFn Chassis).
# usage: mkipmi-chassis.py <outdir> [-v]   (prints the frame ranges with -v)
# Reached through RMCP+ on UDP 623; dissected with -o ipmi.dissect_bus_commands:TRUE.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from ipmilib import Cap, gz, req, rsp

NF = 0
ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

class G:
    seq = 0

def nseq():
    G.seq = (G.seq % 63) + 1
    return G.seq

def pair(cap, cmd, rq, rs, cc=0, how='udp'):
    n = nseq()
    for m in (req(NF, cmd, rq, n), rsp(NF, cmd, rs, n, cc)):
        cap.udp(m) if how == 'udp' else cap.exp(m)

def rq(cap, cmd, data=b''):
    cap.udp(req(NF, cmd, data, nseq()))

def rs(cap, cmd, data=b'', cc=0):
    cap.udp(rsp(NF, cmd, data, nseq(), cc))

def build(cap):
    # --- Get/Set Chassis Capabilities
    s = len(cap.frames)
    pair(cap, 0x00, b'', bytes([0x0f, 0x20, 0x22, 0x24, 0x26]))              # exactly 5 octets (fixed bug)
    pair(cap, 0x00, b'', bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x28]))         # with the bridge address
    pair(cap, 0x00, b'', bytes([0x09, 0x30, 0x31, 0x32, 0x33, 0x34]))
    pair(cap, 0x05, bytes([0x03, 0x20, 0x22, 0x24, 0x26]), b'')              # Set Chassis Capabilities
    pair(cap, 0x05, bytes([0x00, 0x20, 0x22, 0x24, 0x26, 0x28]), b'')
    mark(cap, 'Get/Set Chassis Capabilities (without and with the bridge device address)', s + 1)

    # --- Get Chassis Status
    s = len(cap.frames)
    pair(cap, 0x01, b'', bytes([0x21, 0x10, 0x4e, 0x55]))
    pair(cap, 0x01, b'', bytes([0x5f, 0x1f, 0x7f]))                          # without the front panel byte
    pair(cap, 0x01, b'', bytes([0x00, 0x00, 0x00, 0x00]))
    pair(cap, 0x01, b'', bytes([0xff, 0xff, 0xff, 0xff]))
    for pol in range(4):
        pair(cap, 0x01, b'', bytes([(pol << 5) | 0x01, 0x00, 0x20 * pol, 0x0f]))
    mark(cap, 'Get Chassis Status', s + 1)

    # --- Chassis Control, Reset, Identify
    s = len(cap.frames)
    for c in range(6):
        pair(cap, 0x02, bytes([c]), b'')
    pair(cap, 0x03, b'', b'')
    pair(cap, 0x04, b'', b'')                                                # no data: default interval
    pair(cap, 0x04, b'\x0f', b'')
    pair(cap, 0x04, b'\x0f\x01', b'')
    pair(cap, 0x04, b'\x00\x00', b'')
    mark(cap, 'Chassis Control, Chassis Reset, Chassis Identify', s + 1)

    # --- Power restore policy, restart cause, POH counter
    s = len(cap.frames)
    for pol in range(4):
        pair(cap, 0x06, bytes([pol]), bytes([0x07]))
    pair(cap, 0x06, b'\x07', b'\x00')
    for cause in (0x00, 0x05, 0x0b, 0x4c, 0xf3):
        pair(cap, 0x07, b'', bytes([cause, 0x0f]))
    pair(cap, 0x0f, b'', bytes([60]) + struct.pack('<I', 123456))
    pair(cap, 0x0a, b'\x01', b'')                                            # not decoded
    pair(cap, 0x0b, b'\x01', b'')
    pair(cap, 0x0c, b'\x01', b'')                                            # unknown
    mark(cap, 'Set/Get Power Restore Policy, Get System Restart Cause, POH counter, undecoded commands', s + 1)

    # --- System boot options
    s = len(cap.frames)
    boot = [
        (0, bytes([0x01])), (0, bytes([0x02])), (0, bytes([0x00])), (0, bytes([0x03])),
        (1, bytes([0x07])),
        (2, bytes([0x03])), (2, bytes([0x00])),
        (3, bytes([0x1f])), (3, bytes([0x00])),
        (4, bytes([0x1f, 0x1f])), (4, bytes([0x00, 0x00])),
        (5, bytes([0xe0, 0xff, 0xff, 0xff, 0x1f])), (5, bytes([0x00, 0x00, 0x00, 0x00, 0x00])),
        (5, bytes([0x80, 0x14, 0x21, 0x0c, 0x00])), (5, bytes([0xa0, 0x3c, 0x82, 0x01, 0x00])),
        (6, bytes([0x04]) + struct.pack('<I', 0x30303030) + struct.pack('<I', 0x5f000000)),
        (6, bytes([0x0f]) + struct.pack('<I', 7) + struct.pack('<I', 0xffffffff)),
        (7, bytes([0x01]) + bytes(range(16))),
        (8, b'\x01\x02\x03'), (96, b'\x01\x02'), (127, b'\xff'), (50, b'\x05'),
    ]
    for pno, data in boot:
        pair(cap, 0x08, bytes([0x80 | pno]) + data, b'')                    # Set System Boot Options, marked invalid/locked
        pair(cap, 0x08, bytes([pno]) + data, b'')
    pair(cap, 0x08, bytes([0x80]), b'')                                      # only validity
    pair(cap, 0x08, bytes([0x01]), b'', cc=0x82)
    pair(cap, 0x08, bytes([0x00, 0x01]), b'', cc=0x81)
    pair(cap, 0x08, bytes([0x09, 0x01]), b'', cc=0x80)
    mark(cap, 'Set System Boot Options (every parameter, OEM and reserved selectors)', s + 1)

    s = len(cap.frames)
    for pno, data in boot:
        pair(cap, 0x09, bytes([pno, 0x00, 0x00]), bytes([0x01, 0x80 | pno]) + data)     # Get System Boot Options
        pair(cap, 0x09, bytes([0x80 | pno, 0x01, 0x02]), bytes([0x11, pno]) + data)
    pair(cap, 0x09, bytes([0x09, 0, 0]), b'', cc=0x80)
    mark(cap, 'Get System Boot Options (every parameter, OEM and reserved selectors)', s + 1)

    s = len(cap.frames)
    pair(cap, 0x00, b'', bytes([0x0f, 0x20, 0x22, 0x24, 0x26]), how='exp')
    mark(cap, 'Exported PDU', s + 1)

def build_malformed(cap):
    G.seq = 0
    cap.exp(rsp(NF, 0x00, bytes([0x0f, 0x20, 0x22, 0x24]), 1))
    cap.exp(rsp(NF, 0x01, bytes([0x0f, 0x20]), 1))
    cap.exp(req(NF, 0x05, bytes([0x0f, 0x20, 0x22, 0x24]), 2))
    cap.exp(rsp(NF, 0x06, b'', 2))
    cap.exp(req(NF, 0x06, b'', 2))
    cap.exp(rsp(NF, 0x07, bytes([1]), 3))
    cap.exp(req(NF, 0x02, b'', 3))
    cap.exp(req(NF, 0x08, b'', 4))
    cap.exp(req(NF, 0x09, b'\x01', 5))
    cap.exp(rsp(NF, 0x09, b'\x01', 5))
    cap.exp(rsp(NF, 0x0f, b'\x01\x02', 6))
    # boot option parameters cut short
    for pno, ln in ((0, 0), (1, 0), (2, 0), (3, 0), (4, 1), (5, 4), (6, 8), (7, 0)):
        cap.exp(req(NF, 0x08, bytes([pno]) + bytes(ln + 1)[:ln] + (b'' if ln else b''), 7))
        cap.exp(rsp(NF, 0x09, bytes([1, pno]) + bytes(ln), 8))
    cap.exp(req(NF, 0x08, bytes([4, 1]), 9))
    cap.exp(req(NF, 0x08, bytes([5, 1, 2, 3, 4]), 9))
    cap.exp(req(NF, 0x08, bytes([6, 1, 2, 3, 4, 5, 6, 7, 8]), 9))
    # boot initiator mailbox with a block selector but no block data: the empty field raises an exception (observation)
    cap.exp(req(NF, 0x08, bytes([7, 0x00]), 10))
    cap.exp(rsp(NF, 0x09, bytes([1, 7, 0x00]), 10))

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-chassis-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-chassis-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-chassis-coverage.pcapng.gz'), os.path.join(out, 'ipmi_chassis_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-chassis-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()

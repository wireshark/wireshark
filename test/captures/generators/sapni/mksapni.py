#!/usr/bin/env python3
# Generates test/captures/sapni_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP NI (Network Interface) coverage captures.
# Usage: mksapni.py <outdir>
# SAP NI frames every SAP protocol on TCP 3200 and 40000: a 4 byte length and
# the payload; NI_PING and NI_PONG are NI messages of their own.  Nothing is
# captured from a network.
import os
import struct
import sys
from sapcov_lib import Cap, Flow, ni, ni_route

CLI = '192.0.2.1'
n = [55000]
MAGIC = b'\xab\xcd\xe1\x23'


def flow(c, srv, port):
    n[0] += 1
    f = Flow(c, CLI, srv, n[0], port)
    f.syn()
    return f


def igs(func='ADM:PONG', extra=b''):
    return func.encode().ljust(32, b'\0') + b'\0' * 160 + extra


def build_main(out):
    c = Cap()
    # --- keep-alive messages and SAP IGS on 40000 ----------------------------------
    f = flow(c, '192.0.2.2', 40000)
    f.send(ni(b'NI_PING\0'))
    f.send(ni(b'NI_PONG\0'), False)
    f.send(ni(igs()))
    f.send(ni(igs('ADM:PING', b'PW001')), False)
    f.send(ni(b''))                                              # a zero length message
    f.send(ni(b'NI_PING\0') + ni(igs()))                         # two messages in one segment
    f.send(ni(b'\x00\x01\x02'))                                  # not NI_PING/NI_PONG, 3 bytes, no dissector
    # a message split over three segments, and over two in the middle of the length
    f.split(ni(igs('ADM:REGPW', b'PW001' + b'\0' * 28 + b'7.53')), 3)
    whole = ni(igs('ADM:PING', b'PW002'))
    f.send(whole[:2])
    f.send(whole[2:])
    # a message and the start of the next one in the same segment
    a, b = ni(igs()), ni(igs('ADM:PING', b'PW003'))
    f.send(a + b[:50])
    f.send(b[50:])
    # --- SAP Diag on 3200 --------------------------------------------------------------
    g = flow(c, '192.0.2.3', 3200)
    g.send(ni(bytes([0, 0x28, 0, 0, 1, 0, 0, 0]) + bytes([0x10, 4, 0x1c, 0, 4]) + b'USER' + bytes([0x0c])))
    g.send(ni(b'NI_PING\0'), False)
    g.send(ni(b'NI_PONG\0'))
    # --- SAP Enqueue found by the heuristic ------------------------------------------------
    h = flow(c, '192.0.2.4', 3200)
    h.send(ni(MAGIC + struct.pack('!III', 1, 0, 0) + bytes([6, 6, 0, 0]) + bytes([6, 6, 0, 0, 0, 0, 0, 0])))
    h.send(ni(MAGIC + struct.pack('!III', 2, 0, 0) + bytes([6, 6, 0, 0]) + b'\0\0\0\0'), False)
    # --- SAP Router: route, route accepted (NI_PONG in a router conversation), routed message
    r = Flow(c, CLI, '192.0.2.5', 40000, 3299)
    r.send(ni(ni_route([('router.example', '3299', ''), ('igs.example', '40000', '')])))
    r.send(ni(b'NI_PONG\0'), False)
    r.send(ni(igs()))
    # --- a port that is not a SAP NI port by default (see runcov.sh) -----------------------
    p = flow(c, '192.0.2.6', 3201)
    p.send(ni(igs()))
    p.send(ni(b'NI_PING\0'))
    c.write(os.path.join(out, 'sapni-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    f = flow(c, '192.0.2.2', 40000)
    f.send(ni(igs())[:60])                                       # shorter than its length (no reassembly)
    f.send(struct.pack('!I', 0xffffffff) + b'abc')               # length wraps (0xffffffff + 4)
    f.send(struct.pack('!I', 0xfffffffc) + b'abc')               # length + 4 wraps to 0
    f.send(struct.pack('!I', 8) + b'NI_PING\0'[:5])
    f.send(b'\0\0')                                              # shorter than the NI header
    f.send(ni(b'NI_PING\0')[:9])
    c.write(os.path.join(out, 'sapni-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)

#!/usr/bin/env python3
# Generates test/captures/saprouter_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP Router coverage captures.  Usage: mksaprouter.py <outdir>
# SAP Router is reached through the SAP NI protocol: the client source
# port is 40000 (a default SAP NI port) and the router service port is 3299
# (sapni.port).  The captures have no SYN: with the handshake TCP would only
# try the server port.  Nothing is captured from a network.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from sapcov_lib import Cap, Flow, ni, ni_route, rterr_ctl, rterr_err, snc_frame

CLI = '192.0.2.1'
IGS = b'ADM:PONG'.ljust(192, b' ')
n = [10]


def flow(c, port=3299):
    n[0] += 1
    return Flow(c, CLI, '192.0.2.%d' % n[0], 40000, port)


def admin(opcode, body=b'', ni_version=39):
    return b'ROUTER_ADM\0' + bytes([ni_version, opcode]) + body


ERRFIELDS = ['LOCATION', '1', 'ERROR', 'NI_ROUTE_ERR', 'NI (network interface)', '720', '3',
             'nixxi.cpp', '3430', 'hop ok', 'Wed Nov 11 05:00:00 2026', 'connect', '111',
             'Connection refused', '1', 'loc', 'u1', 'u2', 'u3', 'u4', 'ERROR-END']


def build_main(out):
    c = Cap()
    # --- route accepted, routed messages dispatched to SAP IGS --------------
    f = flow(c)
    f.send(ni(ni_route([('router.example', '3299', ''), ('igs.example', '40000', 'secret')])))
    f.send(ni(b'NI_PONG\0'), False)
    f.send(ni(IGS))
    f.send(ni(IGS), False)
    # --- the route string with every kind of service name ------------------
    # (one conversation each: the route state is per conversation)
    for svc in ('sapdp00', 'sapgw01', 'sapms02', '3200', 'sapxx12', 'sapdp', 'name'):
        f = flow(c)
        f.send(ni(ni_route([('h1.example', '3299', ''), ('h2.example', svc, '')], talk=0)))
    f = flow(c)
    f.send(ni(ni_route([('only.example', '3200', 'pw1')], talk=1, rest=1, version=3)))
    # --- niping ------------------------------------------------------------
    f = flow(c)
    f.send(ni(b'EYECATCHER' + b'\0' * 20))
    f.send(ni(b'EYECATCHER'), False)
    # --- admin messages --------------------------------------------------
    f = flow(c)
    f.send(ni(admin(2, b'\0\0')))                      # info request without password
    f.send(ni(admin(2, b'\0\0adminpw\0')))             # with password
    for op in (3, 4, 5, 7, 8, 9, 14, 99):
        f.send(ni(admin(op, b'\0\0\0\0')))
    f.send(ni(admin(10, b'192.0.2.*'.ljust(32, b'\0'))))
    f.send(ni(admin(11, b'*.*.*.*'.ljust(32, b'\0'))))
    f.send(ni(admin(6, b'\0\0\0\x03' + struct.pack('!3I', 1, 2, 3))))
    f.send(ni(admin(12, struct.pack('!I', 2) + struct.pack('!2I', 7, 8))))
    f.send(ni(admin(13, struct.pack('!I', 1) + struct.pack('!I', 9))))
    # --- NI_RTERR: error information, every return code --------------------
    f = flow(c)
    for rc in (-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17,
               -18, -19, -20, -90, -91, -92, -93, -94, -95, -96, -97, -98, -99, -100, -101,
               -102, -103, -104, -55):
        f.send(ni(rterr_err(rc, ERRFIELDS[:5], tail=b'\0\0\0\x01')), False)
    f.send(ni(rterr_err(-94, ERRFIELDS, tail=b'\xff\xff\xff\xfe')), False)   # all text fields
    f.send(ni(rterr_err(-94, ERRFIELDS[:3], tail=b'x')), False)              # tail < 4 bytes
    f.send(ni(rterr_err(-94, [], tail=b'\0\0\0\0\0')), False)                # no error text
    # --- NI_RTERR: control messages (opcodes other than 0) -----------------
    f = flow(c)
    for op in (1, 2, 5, 6, 8):
        f.send(ni(rterr_ctl(op, 0, b'version 39\0', b'abcd')), False)
    f.send(ni(rterr_ctl(1, 0, b'', b'\0')), False)                      # empty text
    f.send(ni(rterr_ctl(2, -13, b'text', b'')), False)                  # nothing after the text
    f.send(ni(rterr_ctl(7, 0, b'\0', b'')), False)                      # unknown opcode
    # --- routed messages without any route information ---------------------
    f = flow(c)
    f.send(ni(b'XYZ\0unrouted payload'))
    f.send(ni(b'NI_PONG\0'), False)                                     # PONG, no route known
    # --- SNC protected route (the SNC dissector has its own capture) -------
    f = flow(c)
    f.send(ni(ni_route([('router.example', '3299', ''), ('igs.example', '40000', '')])))
    f.send(ni(b'NI_PONG\0'), False)
    f.send(ni(rterr_ctl(70, 0, b'', snc_frame(0x01, token=b'\1' * 8))))
    f.send(ni(rterr_ctl(71, 0, b'', snc_frame(0x04, token=b'\2' * 8))), False)
    f.send(ni(snc_frame(0x07, data=IGS)))
    # --- recursion reproducer: a route to the SAP Router port itself ------
    # (fixed: routed messages used to re-enter SAP Router without end and
    # ended in a dissector assertion).  Source port 3299, dest port 40000
    # as in the review reproducer.
    f = Flow(c, CLI, '192.0.2.200', 3299, 40000)
    f.send(ni(ni_route([('192.0.2.2', '3299', '')])))
    f.send(ni(b'XXXX\0' + b'A' * 16))
    c.write(os.path.join(out, 'saprouter-coverage.pcap'))


def build_malformed(out):
    c = Cap()
    # routed message sent before the route is accepted: first pass and -2 differ
    f = flow(c)
    f.send(ni(ni_route([('r.example', '3299', ''), ('d.example', '40000', '')])))
    f.send(ni(IGS))
    f.send(ni(b'NI_PONG\0'), False)
    # route messages with bad lengths and offsets
    f = flow(c)
    f.send(ni(b'NI_ROUTE\0\x02\x27\x01\x02\0\0\0'))                         # shorter than 24
    f.send(ni(ni_route([('h', '1', '')], route_off=0) + b'extra'))           # length mismatch
    f.send(ni(ni_route([('h', '1', '')], route_off=0xffff)))                 # offset ignored, ok
    f.send(ni(ni_route([('h', '1', '')], route_len=1000)))                   # length > remaining
    f.send(ni(ni_route([], route=b'host\0')))                                # hostname only
    f.send(ni(ni_route([], route=b'host\0port')))                            # unterminated port
    f.send(ni(ni_route([], route=b'host\0port\0pass')))                      # unterminated password
    f.send(ni(ni_route([], route=b'')))                                      # no route string
    f.send(ni(b'NI_PONG\0'), False)
    # unterminated eyecatcher / short messages
    f = flow(c)
    f.send(ni(b'ROUTER_ADM\0'))
    f.send(ni(b'ROUTER_ADM\0\x27'))
    f.send(ni(admin(2, b'\0')))
    f.send(ni(admin(6, b'\0\0')))
    f.send(ni(admin(12, b'\0\0')))
    f.send(ni(admin(6, b'\0\0\0\x05' + struct.pack('!2I', 1, 2))))           # count mismatch
    f.send(ni(admin(6, b'\0\0\0\x01' + struct.pack('!I', 1) + b'xy')))       # trailing bytes
    f.send(ni(admin(13, struct.pack('!I', 3) + struct.pack('!I', 9))))
    f.send(ni(b'NI_RTERR\0'))
    f.send(ni(b'NI_RTERR\0\x27'))
    f.send(ni(b'NI_RTERR\0\x27\x01\0\0\0\0\0\0\0\0\0'))                       # 12 fixed bytes missing 1
    f.send(ni(rterr_err(-1, ERRFIELDS[:3], text_len=500, tail=b'')))         # text longer than frame
    f.send(ni(rterr_ctl(1, 0, b'abc', b'', text_len=500)))                   # control text longer
    f.send(ni(rterr_err(-1, ERRFIELDS[:3], tail=b'')[:-6]))                  # error text unterminated
    f.send(ni(b'EYECATCHER'))
    f.send(ni(b'\xff\xfe\xfd'))
    f.send(ni(b'NI_PONG'))                                                   # no NUL
    # error text with an unterminated field at each position
    f = flow(c)
    for k in range(0, len(ERRFIELDS)):
        txt = b''.join(x.encode() + b'\0' for x in ERRFIELDS[:k]) + b'partial'
        f.send(ni(b'NI_RTERR\0' + bytes([39, 0, 0]) + struct.pack('!i', -3) +
                  struct.pack('!I', len(txt)) + txt))
    # SNC protected route with a short SNC frame and an SNC-less message
    f = flow(c)
    f.send(ni(rterr_ctl(70, 0, b'', b'SNC')))
    f.send(ni(rterr_ctl(70, 0, b'', b'')))                                # SNC opcode, no frame
    f.send(ni(b'whatever'))
    # routed message to the SAP Router port, with state for later passes
    f = Flow(c, CLI, '192.0.2.201', 3299, 40000)
    f.send(ni(ni_route([('192.0.2.2', '3299', '')])))
    f.send(ni(b'NI_PONG\0'), False)
    f.send(ni(b'XXXX\0' + b'A' * 16))
    c.write(os.path.join(out, 'saprouter-coverage-malformed.pcap'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)

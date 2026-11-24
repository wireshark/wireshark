#!/usr/bin/env python3
# Generates test/captures/ipmi_session_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi-session.c (IPMI v1.5 and v2.0/RMCP+
# session wrappers carried in RMCP class IPMI, UDP 623).
# usage: mkipmi-session.py <outdir> [-v]   (prints the frame ranges with -v)
# Authentication codes, RAKP payloads and encrypted payloads are constant
# placeholder octets; nothing is computed or checked.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from ipmilib import Cap, gz, req, RMCP, rmcp_plus, rmcp_v15, rsp, udp4

ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

PH = bytes([0xa5]) * 16                     # placeholder authentication code / payload
MSG_RQ = req(6, 0x38, bytes([0x8e, 0x04]), 1)
MSG_RS = rsp(6, 0x38, bytes([0x0e, 0xbf, 0x3f, 0x03, 0, 0, 0, 0]), 1)

def v20(cap, payload, ptype=0, session=0, seq=0, trailer=b'', resp=False, **kw):
    cap.add('eth', udp4(rmcp_plus(payload, payloadtype=ptype, session=session, seq=seq, trailer=trailer, **kw), reverse=resp))

def v15(cap, payload, auth=0, session=0, seq=0, trailer=b'', resp=False):
    cap.add('eth', udp4(rmcp_v15(payload, auth=auth, session=session, seq=seq, trailer=trailer), reverse=resp))

def build(cap):
    # --- IPMI v1.5 session wrappers
    s = len(cap.frames)
    v15(cap, MSG_RQ)                                         # no authentication: no authentication code
    v15(cap, MSG_RS, resp=True)
    for auth in (1, 2, 4, 5):                                # MD2, MD5, straight password, OEM: placeholder auth code
        v15(cap, MSG_RQ, auth=auth, session=0x11223344, seq=auth)
        v15(cap, MSG_RS, auth=auth, session=0x11223344, seq=auth, resp=True)
    v15(cap, MSG_RQ, session=0x11223344, seq=9, trailer=b'\x00\x01\x02')        # trailer after the message
    v15(cap, b'', session=0)                                 # empty message
    mark(cap, 'IPMI v1.5 session wrappers (authentication types NONE, MD2, MD5, PASSWORD, OEM)', s + 1)

    # --- IPMI v2.0 / RMCP+ session wrappers
    s = len(cap.frames)
    v20(cap, MSG_RQ, 0, session=0, seq=0)                    # IPMI message
    v20(cap, MSG_RS, 0, session=0, seq=0, resp=True)
    v20(cap, MSG_RQ, 0x40, session=0xa0a1a2a3, seq=7)        # authenticated, not encrypted
    v20(cap, MSG_RS, 0x40, session=0xa0a1a2a3, seq=7, trailer=PH + b'\x00' * 4, resp=True)
    v20(cap, MSG_RQ, 0x80, session=0xa0a1a2a3, seq=8)        # encrypted: left as data
    v20(cap, PH, 0xc0, session=0xa0a1a2a3, seq=9, trailer=bytes(12))      # encrypted and authenticated
    v20(cap, MSG_RQ, 0, session=1, seq=1, trailer=b'\x01\x02\x03')       # trailer after an unencrypted message
    mark(cap, 'RMCP+ IPMI messages (plain, authenticated, encrypted, with trailers)', s + 1)

    s = len(cap.frames)
    for pt in (0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x20, 0x23, 0x27, 0x30, 0x3f):
        v20(cap, bytes(range(pt, pt + 20)), pt, session=0, seq=0, resp=bool(pt & 1))
    v20(cap, PH, 0x01, session=0x5555aaaa, seq=3)           # SOL payload
    v20(cap, PH, 0x41, session=0x5555aaaa, seq=4, trailer=PH)
    mark(cap, 'RMCP+ payload types other than IPMI (SOL, session setup, RAKP, OEM): data', s + 1)

    s = len(cap.frames)
    v20(cap, PH, 0x02, session=0x01020304, seq=5, oem=(b'\x00\x00\x1b\xcd', b'\x02\x00'))    # OEM explicit
    v20(cap, MSG_RQ, 0x02, session=0x01020304, seq=6)
    v20(cap, PH, 0x42, session=0x01020304, seq=7, trailer=PH)
    v20(cap, PH, 0x82, session=0x01020304, seq=8)           # OEM explicit, encrypted
    mark(cap, 'RMCP+ OEM explicit payload type (IANA number and payload ID)', s + 1)

    # Exported PDU naming the dissector registered by this file: the session wrapper (v1.5)
    s = len(cap.frames)
    cap.exp(bytes([0]) + struct.pack('<II', 5, 0x01020304) + bytes([len(MSG_RQ)]) + MSG_RQ, 'ipmi_session')
    cap.exp(bytes([6, 0]) + struct.pack('<IIH', 0x01020304, 6, len(MSG_RS)) + MSG_RS, 'ipmi_session')
    mark(cap, 'Exported PDU ipmi_session (v1.5 and RMCP+)', s + 1)

def build_malformed(cap):
    # the session wrapper is shorter than its header, or the message length lies
    cap.add('eth', udp4(RMCP + b'\x06'))
    cap.add('eth', udp4(RMCP + b'\x06\x00\x00\x00'))
    cap.add('eth', udp4(RMCP + b'\x00\x00\x00\x00'))
    cap.add('eth', udp4(RMCP + b'\x00' + b'\x00' * 8 + b'\x20' + MSG_RQ[:4]))
    cap.add('eth', udp4(RMCP + b'\x02' + b'\x00' * 8 + b'\x20' + MSG_RQ[:4]))
    cap.add('eth', udp4(RMCP + b'\x06\x02' + b'\x00' * 8))
    cap.add('eth', udp4(RMCP + b'\x06\x02' + b'\x00' * 12))
    cap.add('eth', udp4(RMCP + b'\x06\x00' + struct.pack('<IIH', 0, 0, 200) + MSG_RQ))   # message length longer than the packet
    cap.add('eth', udp4(RMCP + b'\x00' + struct.pack('<II', 0, 0) + bytes([200]) + MSG_RQ))
    cap.add('eth', udp4(RMCP + b'\x06\x10' + struct.pack('<IIH', 0, 0, 200) + PH))
    cap.add('eth', udp4(RMCP + b'\x06\x80' + struct.pack('<IIH', 0, 0, 200) + PH))

def main():
    out = sys.argv[1]
    cap = Cap(); build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-session-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-session-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-session-coverage.pcapng.gz'), os.path.join(out, 'ipmi_session_coverage.pcapng.gz'))
    bad = Cap(); build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-session-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()

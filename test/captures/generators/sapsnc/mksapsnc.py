#!/usr/bin/env python3
# Generates test/captures/sapsnc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the SAP SNC coverage captures.  Usage: mksapsnc.py <outdir>
# SNC frames travel inside SAP Router control messages (NI_RTERR opcodes
# 70 and 71) and routed messages of an SNC protected route; the handler
# registered as "sapsnc" itself is only reached through Exported PDU, so the
# captures are pcapng with an Ethernet and an Exported PDU interface.
# Nothing is captured from a network and no key material or ciphertext is
# built: the SNC tokens and data are arbitrary bytes.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from sapcov_lib import Cap, Flow, ni, ni_route, rterr_ctl, snc_frame

CLI, SRV, SRV2 = '192.0.2.1', '192.0.2.2', '192.0.2.3'
# Client source port 40000 is a SAP NI port; with no SYN in the capture (it
# service on port 3299 is handed to SAP Router through sapni.port.
IGS = b'ADM:PONG'.ljust(192, b' ')


def router_flow(c, cport, srv, hops=(('client.example', '3299', ''), ('igs.example', '40000', ''))):
    f = Flow(c, CLI, srv, cport, 3299)
    f.send(ni(ni_route(list(hops))))
    f.send(ni(b'NI_PONG\0'), False)
    return f


def build_main(out):
    c = Cap()
    f = router_flow(c, 40000, SRV)
    # SNC request (opcode 70) with an INIT_REQ frame, and the answer (71)
    # with an ACCEPT frame carrying an extension field
    f.send(ni(rterr_ctl(70, 0, b'', snc_frame(0x01, token=bytes(range(20))))))
    f.send(ni(rterr_ctl(71, 0, b'', snc_frame(0x04, token=b'\xaa' * 12, ext=(b'EXTFIELD01', None)))), False)
    # routed messages of the now SNC protected conversation
    for ftype in (0x02, 0x03, 0x05, 0x07, 0x08, 0x09):
        data = IGS if ftype in (0x07, 0x08) else b'\x11\x22\x33\x44' * 4
        f.send(ni(snc_frame(ftype, token=b'tok' if ftype < 5 else b'', data=data)))
    # every frame type name once more, in the other direction
    for ftype in (0x00, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e):
        f.send(ni(snc_frame(ftype, mech=ftype, flags=0, qop=ftype)), False)
    # extension of odd size, token only, data only
    f.send(ni(snc_frame(0x01, token=b'T' * 8, ext=(b'E' * 40, None), mech=0x0a, qop=0x01)))
    f.send(ni(snc_frame(0x09, data=b'D' * 30, ext=(b'', None), mech=1, qop=0x03)))
    # the same through Exported PDU for the sapsnc handle itself
    c.exp_pdu('sapsnc', snc_frame(0x01, token=b'\x05' * 16))
    c.exp_pdu('sapsnc', snc_frame(0x07, data=b'abcdefgh', ext=(b'xy', None)))
    c.exp_pdu('sapsnc', snc_frame(0x0b))
    c.write_ng(os.path.join(out, 'sapsnc-coverage.pcapng'))


def build_malformed(out):
    c = Cap()
    f = router_flow(c, 40000, SRV2)
    f.send(ni(rterr_ctl(70, 0, b'', snc_frame(0x01, token=b'x'))))
    # protected conversation; invalid SNC frames follow
    f.send(ni(snc_frame(0x01, hl=5)))                       # header length < 10
    f.send(ni(snc_frame(0x01, hl=20)))                      # header length < 24
    f.send(ni(snc_frame(0x01, hl=300, token=b'abc')))       # longer than the frame
    f.send(ni(snc_frame(0x01, token=b'abc', tok_len=1000))) # token longer than frame
    f.send(ni(snc_frame(0x07, data=b'abc', data_len=1000))) # data longer than frame
    f.send(ni(snc_frame(0x01, ext=(b'abc', 500))))          # extension field too long
    f.send(ni(b'SNCFRAME\x01\x02\x00\x18\0\0'))             # shorter than 24 bytes
    # opcode 71 control message with a short SNC frame
    f.send(ni(rterr_ctl(71, 0, b'', b'SNC')), False)
    c.exp_pdu('sapsnc', b'SNCFRAME\x01')
    c.exp_pdu('sapsnc', snc_frame(0x01, hl=5))
    c.exp_pdu('sapsnc', snc_frame(0x01, hl=20))
    c.exp_pdu('sapsnc', snc_frame(0x01, hl=300, token=b'abc'))
    c.exp_pdu('sapsnc', snc_frame(0x01, token=b'abc', tok_len=1000))
    c.exp_pdu('sapsnc', snc_frame(0x07, data=b'abc', data_len=1000))
    c.write_ng(os.path.join(out, 'sapsnc-coverage-malformed.pcapng'))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main(out)
    build_malformed(out)

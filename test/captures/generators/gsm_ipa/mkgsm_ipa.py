#!/usr/bin/env python3
# Generates test/captures/gsm_ipa_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic IPA (ip.access) captures.  Usage: mkgsm_ipa.py <outdir>
TCP streams on the default IPA ports; the UDP header variant only in the
malformed capture (UDP has no default port)."""
import struct
import sys
import os
from pcaplib import pcap, Flow, udp_frame

def ipa(t, payload):
    return struct.pack('>HB', len(payload), t) + payload

def ie(t, v): return bytes([t, len(v)]) + v

# ---- sub-protocol payloads --------------------------------------------
RSL_CHAN_RQD = bytes([0x0c, 0x12, 0x01, 0x88, 0x18, 0x01, 0x10, 0x00, 0x2a, 0x00])
RSL_BCCH = bytes([0x0c, 0x11, 0x01, 0x80, 0x1e, 0x01])
RSL_ERR = bytes([0x08, 0x25, 0x01, 0x08])
OML_OPSTART = bytes([0x80, 0x80, 0x00, 0x05, 0x74, 0x01, 0xff, 0xff, 0xff])
def sccp_udt(data):
    called = bytes([2, 0x42, 254]); calling = bytes([2, 0x42, 254])
    return (bytes([0x09, 0x01, 3, 2 + len(called), 1 + len(called) + len(calling)])
            + called + calling + bytes([len(data)]) + data)
BSSMAP_RESET = bytes([0x00, 0x04, 0x30, 0x04, 0x01, 0x20])
SCCP = sccp_udt(BSSMAP_RESET)
MGCP = b'CRCX 1 23@mgw MGCP 1.0\r\nC: 1\r\nL: p:20\r\nM: recvonly\r\n'
IMSI = bytes.fromhex('620210214365 87f9'.replace(' ',''))
GSUP = bytes([0x08]) + ie(0x01, IMSI)
CTRL = b'GET 1 bts.0.trx.0.rf_locked\n'

def build(outdir):
    fr = []
    # ---- stream 1: OML/RSL on 3002 (IPA CCM + A-bis)
    f = Flow(40001, 3002, fr)
    f.open()
    f.s2c(ipa(0xfe, bytes([0x04]) + bytes([0x01, 0x08, 0x01, 0x07, 0x01, 0x02, 0x01, 0x0a])))  # ID GET: tags
    f.c2s(ipa(0xfe, bytes([0x05]) + b'\x00\x0a\x01' + b'1234/0/0\x00' + b'\x00\x08\x05' + b'v1.2.3\x00'))
    f.s2c(ipa(0xfe, bytes([0x06])))      # ID ACK
    f.c2s(ipa(0xfe, bytes([0x00])))      # PING
    f.s2c(ipa(0xfe, bytes([0x01])))      # PONG
    f.s2c(ipa(0xfe, bytes([0x07])))      # ID NACK
    f.c2s(ipa(0xfe, bytes([0x08, 0x01, 0x02])))   # PROXY REQUEST
    f.s2c(ipa(0xfe, bytes([0x09])))      # PROXY ACK
    f.s2c(ipa(0xfe, bytes([0x0a])))      # PROXY NACK
    f.c2s(ipa(0xfe, bytes([0x0b, 0x00])))   # SSL INFO
    f.s2c(ipa(0xfe, bytes([0x42, 0x01])))   # unknown IPA message type
    # ID response with an unknown attribute type, a request tag, a zero length
    # string (the reproducer of the fix) and a string
    f.c2s(ipa(0xfe, bytes([0x05, 0x7f, 0x00, 0x01, 0x05, 0x00, 0x00, 0x01, 0x03, 0x00, 0x05, 0x04]) + b'abc\x00'))
    f.c2s(ipa(0xfe, bytes([0x04, 0x01, 0x00, 0x01, 0x01])))
    f.c2s(ipa(0x00, RSL_CHAN_RQD))                  # RSL stream 0
    f.s2c(ipa(0x01, RSL_BCCH))                      # RSL stream 1
    f.c2s(ipa(0x1f, RSL_ERR))                       # RSL stream 31
    f.c2s(ipa(0xff, OML_OPSTART))                   # OML
    f.s2c(ipa(0x01, RSL_BCCH) + ipa(0xfe, bytes([0x00])) + ipa(0x00, RSL_CHAN_RQD))  # three PDUs in one segment
    # an unknown type (0x20..0xdc) after a valid PDU is skipped
    f.s2c(ipa(0xfe, bytes([0x01])) + ipa(0x42, b'xyz'))
    f.c2s(ipa(0x20, b'\x01\x02'))     # starts with an unknown type: not IPA
    f.c2s(b'\x00\x01\x00')            # shorter than 4 octets: not IPA
    f.ack_s()
    # ---- stream 2: SCCP, old MGCP, HSL debug on 5000
    g = Flow(40002, 5000, fr, cseq=2000, sseq=7000)
    g.open()
    g.c2s(ipa(0xfd, SCCP))
    g.s2c(ipa(0xfc, MGCP))
    g.c2s(ipa(0xdd, b'hello debug\x00'))
    g.s2c(ipa(0xdd, b'two\x00') + ipa(0xdd, b'three\x00'))
    g.c2s(ipa(0xfd, SCCP) + ipa(0xfc, MGCP))
    g.ack_s()
    # ---- stream 3: OSMO EXT on 4249 and the GSUP port 4222
    h = Flow(40003, 4249, fr, cseq=3000, sseq=8000)
    h.open()
    h.c2s(ipa(0xee, bytes([0x00]) + CTRL))                  # CTRL, text
    h.s2c(ipa(0xee, bytes([0x00]) + b'GET_REPLY 1 bts.0.trx.0.rf_locked 0\n'))
    h.c2s(ipa(0xee, bytes([0x01]) + b'AUEP 7 *@mgw MGCP 1.0\r\n'))  # MGCP through ipa.osmo.protocol
    h.s2c(ipa(0xee, bytes([0x02]) + b'lac'))                # LAC: data
    h.s2c(ipa(0xee, bytes([0x03]) + b'smsc'))               # SMSC
    h.s2c(ipa(0xee, bytes([0x04]) + b'orc'))                # ORC
    h.s2c(ipa(0xee, bytes([0x06]) + b'\x01\x02\x03'))       # OAP
    h.s2c(ipa(0xee, bytes([0x7f]) + b'\x01\x02\x03'))       # unknown osmo protocol
    h.s2c(ipa(0xee, bytes([0x00])))                          # empty CTRL
    h.ack_c()
    k = Flow(40004, 4250, fr, cseq=4000, sseq=9000)
    k.open()
    k.c2s(ipa(0xfe, bytes([0x04, 0x01, 0x08])))
    k.s2c(ipa(0xfe, bytes([0x05, 0x00, 0x09, 0x01]) + b"osmo-ms\x00"))
    k.c2s(ipa(0xee, bytes([0x05]) + GSUP))
    k.s2c(ipa(0xee, bytes([0x05]) + bytes([0x0a]) + ie(0x01, IMSI)))
    k.ack_c()
    pcap(os.path.join(outdir, 'gsm_ipa-coverage.pcap'), fr)

    # ---- malformed capture
    ml = []
    m = Flow(41001, 3002, ml)
    m.open()
    m.c2s(ipa(0xfe, bytes([0x05, 0x00])))          # string attribute cut after its type
    m.c2s(ipa(0xfe, bytes([0x05, 0x00, 0x20, 0x01]) + b'abc'))  # string longer than the PDU
    m.c2s(b'\x00\x40\x00' + bytes(10))             # length beyond the segment (OML 0xff? type 0 RSL)
    m.c2s(b'\x00\x20\xff' + bytes(6))              # OML longer than the data
    m.c2s(ipa(0xee, b''))                          # OSMO EXT without a protocol octet
    m.c2s(ipa(0xdd, b''))
    m.c2s(ipa(0xdd, b'no terminator'))          # with hsl_debug_in_info: no NUL in the PDU
    m.ack_s()
    # UDP, reached with Decode As: header with the extra 4th octet and without
    u = [udp_frame('10.0.0.1', '10.0.0.2', 40010, 6001, struct.pack('>HBB', 3, 0xfe, 0) + bytes([0x00, 0x01, 0x00])),
         udp_frame('10.0.0.1', '10.0.0.2', 40010, 6001, struct.pack('>HB', 3, 0xfe) + bytes([0x00, 0x01, 0x00])),
         udp_frame('10.0.0.1', '10.0.0.2', 40010, 6001, struct.pack('>HBB', 6, 0xee, 0) + bytes([0, 1, 2, 3, 4, 5])),
         udp_frame('10.0.0.1', '10.0.0.2', 40010, 6001, b'\x00\x01\x20xx')]
    pcap(os.path.join(outdir, 'gsm_ipa-coverage-malformed.pcap'), ml + u)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')

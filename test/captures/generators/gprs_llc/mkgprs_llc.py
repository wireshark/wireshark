#!/usr/bin/env python3
# Generates test/captures/gprs_llc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GPRS LLC coverage captures. Usage: mkgprs_llc.py <outdir>
Linktype 169 (LINKTYPE_GPRS_LLC): each frame is one LLC PDU."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import pcap

POLY = 0xAD85DD     # reflected CRC-24 of 3GPP TS 44.064
TBL = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ POLY if c & 1 else c >> 1
    TBL.append(c)

def fcs(b):
    f = 0xffffff
    for x in b:
        f = (f >> 8) ^ TBL[(f ^ x) & 0xff]
    return (~f) & 0xffffff

def pdu(addr, ctrl, info=b'', crc='good', crc_len=None):
    """addr: address octet, ctrl: control field bytes, info: information field.
    crc: good, bad, none (no FCS at all)"""
    body = bytes([addr]) + ctrl + info
    if crc == 'none':
        return body
    n = len(body) if crc_len is None else min(crc_len, len(body))
    c = fcs(body[:n])
    if crc == 'bad':
        c ^= 0x010203
    return body + struct.pack('<I', c)[:3]

def A(sapi, cr=0): return (0x40 if cr else 0) | sapi

def ctrl_i(ns, nr, a=0, s=0):
    v = (a << 22) | (ns << 12) | (nr << 2) | s
    return struct.pack('>I', v)[1:]

def ctrl_s(nr, s, a=0, sp=0):
    return struct.pack('>H', 0x8000 | (a << 13) | (sp << 11) | (nr << 2) | s)

def ctrl_ui(nu, e=0, pm=0, sp=0):
    return struct.pack('>H', 0xC000 | (sp << 11) | (nu << 2) | (e << 1) | pm)

def ctrl_u(cmd, pf=0): return bytes([0xE0 | (pf << 4) | cmd])

# ------------------------------------------------------------ XID parameters
def xid_param(t, val=b'', xl=False):
    """parameter type t (5 bits), value bytes; XL form carries a 8 bit length"""
    n = len(val)
    if n > 3:
        xl = True
    if xl:
        b1 = 0x80 | (t << 2) | (n >> 6)
        b2 = ((n & 0x3f) << 2)
        return bytes([b1, b2]) + val
    return bytes([(t << 2) | n]) + val

def xid_all():
    return (xid_param(0, b'\x00') + xid_param(1, struct.pack('>I', 0x11223344)) + xid_param(2, struct.pack('>I', 0x55667788))
            + xid_param(3, b'\x03\xe8') + xid_param(4, b'\x05') + xid_param(5, b'\x05\xf0') + xid_param(6, b'\x05\xf0')
            + xid_param(7, struct.pack('>I', 0x1000)[1:]) + xid_param(8, struct.pack('>I', 0x1000)[1:])
            + xid_param(9, b'\x10') + xid_param(10, b'\x10') + xid_param(12, b'') + xid_param(13, b'\x01\x02')
            + xid_param(20, b'\x01\x02\x03'))

# SNDCP XID: version, compression entities... keep it small: version 0 parameter list
SNDCP_XID = bytes([0x00, 0x01, 0x00])

def main(outdir):
    F, marks = [], []
    def add(p): F.append(p)
    def mark(s): marks.append((len(F) + 1, s))
    IP0 = bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) + struct.pack('>HHHH', 40000, 40001, 8, 0)
    def SN_DATA(nsapi, p, npdu=1): return bytes([0x40 | nsapi, 0, npdu]) + p
    def SN_UNIT(nsapi, npdu, p, seg=0): return bytes([0x60 | nsapi, 0, (seg << 4) | (npdu >> 8), npdu & 0xff]) + p
    IP = SN_DATA(5, IP0)

    mark('dummy UI command, invalid address (protocol discriminator bit)')
    add(bytes([0x43, 0xc0, 0x01, 0x2b, 0x2b, 0x2b]))
    add(pdu(0x81, ctrl_ui(0, pm=1), b'abc'))
    mark('UI frames: every SAPI (command and response), good and bad FCS, N(U), E and PM bits, spare bits')
    for sapi in range(16):
        info = {1: b'\x08\x11', 7: b'\x09\x04', 2: b'\x01tom', 8: b'\x01tom'}.get(sapi)
        if info is None:
            info = SN_UNIT(sapi if sapi in (3, 5, 9, 11) else 1, 1000 + sapi, IP0) if sapi in (3, 5, 9, 11) else b'raw data'
        add(pdu(A(sapi, cr=sapi & 1), ctrl_ui(sapi * 7, pm=1), info))
    add(pdu(A(3), ctrl_ui(100, pm=0), SN_UNIT(3, 5, IP0)))                 # PM=0: FCS only covers header + N202 octets
    add(pdu(A(3), ctrl_ui(100, pm=0), SN_UNIT(3, 6, IP0), crc='bad'))      # bad FCS on a partial FCS
    add(pdu(A(5), ctrl_ui(101, pm=1, sp=3), SN_UNIT(5, 7, IP0), crc='bad'))
    add(pdu(A(5), ctrl_ui(102, e=1, pm=1), bytes(range(30)), crc='bad'))    # ciphered, bad FCS
    add(pdu(A(5), ctrl_ui(103, e=1, pm=1), bytes(range(30))))               # ciphered, good FCS
    add(pdu(A(9), ctrl_ui(0x1ff, pm=1), b''))                                 # empty information field
    add(pdu(A(9), ctrl_ui(7, pm=1), SN_UNIT(9, 8, IP0)))
    add(pdu(A(7), ctrl_ui(9, pm=1), b'\x09\x04'))
    add(pdu(A(7), ctrl_ui(10, pm=1, e=0), b'\x09\x10\x11'))
    mark('truncated frames: FCS cannot be computed')
    full = pdu(A(9), ctrl_ui(8, pm=1), b'data data data')
    add((full[:12], len(full)))
    add(pdu(A(9), ctrl_ui(8, pm=1), b'', crc='none')[:3])     # only 3 octets: too short for a FCS
    mark('TOM (SAPI 2 and 8) in UI, I and S frames: protocol, remaining length, header and capsule')
    for sapi in (2, 8):
        add(pdu(A(sapi), ctrl_ui(1, pm=1), bytes([0x01]) + b'capsule'))                 # RL 0, TIA/EIA-136
        add(pdu(A(sapi), ctrl_ui(2, pm=1), bytes([0x22, 0xaa, 0xbb]) + b'capsule'))     # RL 2, RRLP
        add(pdu(A(sapi), ctrl_ui(3, pm=1), bytes([0xf0]) + b'extension'))               # RL 15: reserved
        add(pdu(A(sapi), ctrl_i(1, 2, a=1, s=1), bytes([0x13, 1, 2, 3]) + b'xyz'))
        add(pdu(A(sapi), ctrl_i(1, 2, a=1, s=1), bytes([0xf3]) + b'ext'))
        add(pdu(A(sapi), ctrl_s(5, 0), bytes([0x20]) + b'abc'))
        add(pdu(A(sapi), ctrl_s(5, 1, a=1), bytes([0x12, 5, 6]) + b'abc'))
        add(pdu(A(sapi), ctrl_s(5, 2), bytes([0xf7]) + b'ext'))
    mark('I frames: RR, ACK, RNR and SACK with 1, 2 and 32 R bitmap octets, A bit, N(S), N(R)')
    add(pdu(A(3, 1), ctrl_i(0, 0, s=0), IP))
    add(pdu(A(3), ctrl_i(511, 511, a=1, s=1), IP))
    add(pdu(A(5), ctrl_i(123, 321, s=2), IP))
    add(pdu(A(9), ctrl_i(5, 6, s=1), SN_DATA(9, IP0)))
    add(pdu(A(11), ctrl_i(7, 8, a=1, s=0), SN_DATA(11, IP0)))
    add(pdu(A(1), ctrl_i(9, 10, s=3), bytes([0x1f]) + bytes(range(32)) + b'\x08\x11'))
    add(pdu(A(1), ctrl_i(9, 10, s=3), bytes([0xe0, 0x0f]) + b'\x08\x11', crc='bad'))
    mark('S frames: RR, ACK, RNR, SACK (with and without data), A bit, spare bits')
    add(pdu(A(3), ctrl_s(0, 0)))
    add(pdu(A(3, 1), ctrl_s(300, 1, a=1)))
    add(pdu(A(5), ctrl_s(511, 2, sp=3)))
    add(pdu(A(5), ctrl_s(12, 3), bytes([0xaa, 0x55, 0xff])))
    add(pdu(A(5), ctrl_s(12, 3), b''))
    add(pdu(A(9), ctrl_s(4, 0), SN_DATA(9, IP0)))
    add(pdu(A(4), ctrl_s(4, 0), b'reserved sapi'))
    add(pdu(A(6), ctrl_i(4, 0), b'reserved sapi'))
    add(pdu(A(1), ctrl_s(4, 1), b'\x08\x11'))
    mark('U frames: DM, DISC, NULL, UA with and without XID, SABM, XID with every parameter, FRMR, unknown code')
    add(pdu(A(1, 1), ctrl_u(1, pf=1), b''))
    add(pdu(A(1), ctrl_u(1), b'info'))
    add(pdu(A(3), ctrl_u(4, pf=1), b''))
    add(pdu(A(3), ctrl_u(0), b''))
    add(pdu(A(3), ctrl_u(6), b''))
    add(pdu(A(3), ctrl_u(6), xid_all()))
    add(pdu(A(3), ctrl_u(7, pf=1), xid_all()))
    add(pdu(A(5), ctrl_u(0xb), xid_all()))
    add(pdu(A(5), ctrl_u(0xb), xid_param(3, b'\x03\xe8') + xid_param(11, SNDCP_XID) + xid_param(4, b'\x05')))
    add(pdu(A(5), ctrl_u(0xb), xid_param(11, b'')))
    add(pdu(A(5), ctrl_u(0xb), xid_param(11, SNDCP_XID * 3, xl=True)))
    add(pdu(A(5), ctrl_u(0xb), xid_param(5, bytes(range(70)), xl=True) + xid_param(6, b'\x01', xl=False)))
    add(pdu(A(5), ctrl_u(0xb), xid_param(14, bytes(12), xl=True) + xid_param(31, b'\x01\x02\x03')))
    add(pdu(A(5), ctrl_u(0xb), xid_param(7, b'', xl=True) + xid_param(2, b'\x01\x02')))
    add(pdu(A(5), ctrl_u(0xb), b''))
    add(pdu(A(5), ctrl_u(8, pf=1), struct.pack('>HHH', 0xe1c0, 0x0101, 0x0202) + struct.pack('>I', 0x0ffa03ff)))
    add(pdu(A(5), ctrl_u(8), struct.pack('>HHH', 0, 0, 0) + struct.pack('>I', 0xf0040000 | 0xf)))
    add(pdu(A(5), ctrl_u(2), b'abc'))
    add(pdu(A(5), ctrl_u(0xf), b'abc'))

    mal = []
    m = lambda p: mal.append(p)
    m(bytes([0x03]))                              # address only
    for c in (0xE1, 0xE4, 0xE6, 0xE7, 0xE8, 0xEB, 0xE0, 0xEF):   # U frames of 2 octets: shorter than a FCS
        m(bytes([0x05, c]))
    m(bytes([0x05, 0xEB, 0x00]))
    m(bytes([0x05, 0xE6, 0x00, 0x00]))
    m(bytes([0x03, 0xc0]))                        # UI control field cut
    m(bytes([0x03, 0x00, 0x00]))                  # I control field cut
    m(bytes([0x03, 0x80]))                        # S control field cut
    m(pdu(A(3), ctrl_i(1, 1, s=3), b'', crc='none') + b'\x00\x00\x00')   # SACK k byte beyond the end
    m(pdu(A(3), ctrl_i(1, 1, s=3), bytes([0x1f, 1, 2]), crc='good'))      # R bitmap longer than the frame
    m(pdu(A(2), ctrl_ui(1, pm=1), bytes([0x55]) + b'ab'))                 # TOM header longer than the frame
    m(pdu(A(8), ctrl_i(1, 1, s=0), bytes([0xa5, 1])))
    m(pdu(A(5), ctrl_u(0xb), bytes([0x83])))                            # XL parameter without the second octet
    m(pdu(A(5), ctrl_u(0xb), bytes([0x0f, 1, 2])))                      # parameter longer than the frame
    m(pdu(A(5), ctrl_u(0xb), bytes([0xff, 0xfc]) + bytes(10)))          # XL parameter with a length of 255
    m(pdu(A(5), ctrl_u(8), struct.pack('>HH', 1, 2)))                   # FRMR information field too short
    m(pdu(A(5), ctrl_u(6), b'', crc='none')[:2])
    m(pdu(A(5), ctrl_u(0xb), xid_param(11, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')))   # L3 parameter, sndcp-xid too long
    m(pdu(A(2), ctrl_s(1, 0), b''))                                      # TOM S frame without information

    pcap(outdir + '/gprs-llc-coverage.pcap', F, linktype=169)
    pcap(outdir + '/gprs-llc-coverage-malformed.pcap', mal, linktype=169)
    for n, s in marks:
        print(n, s)
    print(len(F), 'frames;', len(mal), 'malformed')

main(sys.argv[1])

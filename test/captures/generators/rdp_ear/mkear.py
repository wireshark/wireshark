#!/usr/bin/env python3
# Generates test/captures/rdp_ear_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP authentication redirection (MS-RDPEAR) captures for
# packet-rdp_ear.c.  Usage: mkear.py <outdir> [-v]
# Everything after the GSS-API unwrap needs Kerberos keys: the payloads here
# are GSS-API framing without keys (nothing is decrypted, no ciphertext is
# generated), so only the header handling is covered.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import create_req, create_resp, data, data_first

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
NAME = 'Microsoft::Windows::RDS::AuthRedirection'


def ear(payload, length=None, magic=0x4eacc3c8, ver=1, ctx=0x1234):
    return struct.pack('<IIIIQ', magic, len(payload) if length is None else length, ver, 0, ctx) + payload


KRB_HDR = b'\x60\x20\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01\x00' + bytes(30)
PAYLOADS = (b'\x60\x05\x06\x03\x2a\x86\x48', b'NTLMSSP\0\x01\0\0\0' + bytes(20), b'\x04\x04' + bytes(30), KRB_HDR)


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    S = lambda p: s.chan('drdynvc', p, False)
    C = lambda p: s.chan('drdynvc', p, True)
    S(create_req(6, NAME))
    C(create_resp(6))
    for p in PAYLOADS:
        S(data(6, ear(p)))
        C(data(6, ear(p, ctx=0x5678)))
    S(data(6, ear(PAYLOADS[1], ver=2, magic=0x4eacc3c9)))             # another magic and version
    pdu = ear(PAYLOADS[1])
    S(data_first(6, len(pdu), pdu[:30]))                              # reassembled
    S(data(6, pdu[30:]))
    S(data(6, ear(PAYLOADS[1]) + ear(PAYLOADS[0])))                   # two PDUs in one DVC PDU: the first is dissected
    cookie = bytes(range(16))
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', create_req(7, NAME), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data(7, ear(PAYLOADS[1])), False, sport=50050, pt=3)
    cap.write(os.path.join(OUT, 'ear-coverage.pcapng'))
    if VERBOSE:
        print('ear-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'])
    s.chan('drdynvc', create_req(6, NAME), False)
    S = lambda p: s.chan('drdynvc', data(6, p), False)
    S(b'\x01\x02\x03')
    S(ear(b'')[:10])
    S(ear(b''))                                                       # no payload at all
    S(ear(bytes(4), length=0xffffffe8))                               # pduLength that wraps (fixed on the branch)
    S(ear(bytes(4), length=0xffffffff))
    S(ear(bytes(4), length=0x1000))
    S(ear(b'\x60\x00'))
    S(ear(bytes(16)))                                                 # a payload that is not GSS-API (warning)
    S(ear(b'\x30\x80' + bytes(20)))
    cap.write(os.path.join(OUT, 'ear-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()

#!/usr/bin/env python3
# Generates test/captures/rdp_multitransport_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP multitransport (MS-RDPEMT) captures for
# packet-rdp_multitransport.c.  Usage: mkmultitransport.py <outdir> [-v]
# The tunnel PDUs travel in (D)TLS in real life; a decrypted stream reaches
# the dissector through the "rdpmt_dtls" / "rdpmt_tls_" heuristic dissectors,
# so the frames are Exported PDUs naming them (or the dissector "rdpmt").
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv
COOKIE = bytes(range(16))


def mt(action, payload=b'', flags=0, sub=b'', hlen=None, plen=None):
    h = 4 + len(sub) if hlen is None else hlen
    return struct.pack('<BHB', (flags << 4) | action, len(payload) if plen is None else plen, h) + sub + payload


def autodetect(typ, seq, rt, body=b''):
    return struct.pack('<BBHH', 6, typ, seq, rt) + body


def create_req(rid, cookie=COOKIE):
    return struct.pack('<II', rid, 0) + cookie


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + COOKIE)      # lossy
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x11223344, 1, 0) + COOKIE)      # reliable
    sp = dict(sport=50050, pt=3)

    def U(payload, c2s=True, heur=None, **kw):
        a = dict(sp)
        a.update(kw)
        if heur:
            return cap.exp(heur, payload, c2s, heur=True, **a)
        return cap.exp('rdpmt', payload, c2s, **a)

    # direct dissector
    U(mt(0, create_req(0x55667788)))                                     # tunnel create request (links to the TCP request)
    U(mt(1, struct.pack('<i', 0)), False)                                # tunnel create response
    U(mt(1, struct.pack('<i', -2147467259)), False)
    U(mt(2, b'\x10\x05' + b'foo\0'), False)                              # data: a DVC create request
    U(mt(2, b''), False)                                                 # data without payload
    U(mt(2, b'\x10\x05' + b'foo\0', flags=0xa), False)                   # flags in the action octet
    # sub headers: auto detect requests (server) and responses (client)
    for rt, body in ((0x0001, b''), (0x1001, b''), (0x0014, b''), (0x0114, b''), (0x1014, b''),
                     (0x0002, struct.pack('<H', 4) + b'data'), (0x002b, struct.pack('<H', 2) + b'xy'),
                     (0x0429, b''), (0x0629, b''), (0x0840, struct.pack('<II', 5, 6)), (0x0880, struct.pack('<I', 7)),
                     (0x08c0, struct.pack('<III', 8, 9, 10)), (0x7777, b'')):
        sub = autodetect(0, 1, rt, body)
        U(mt(2, b'\x10\x05foo\0', sub=sub), False)
    for rt, body in ((0x0000, b''), (0x0003, struct.pack('<II', 100, 2000)), (0x000b, struct.pack('<II', 1, 2)), (0x7777, b'')):
        U(mt(2, b'\x10\x05foo\0', sub=autodetect(1, 2, rt, body)), True)
    # a header length below 4 is not a sub header length: nothing to skip (fix on the branch)
    U(mt(1, struct.pack('<i', 0), hlen=3), False)
    U(mt(1, struct.pack('<i', 0), hlen=0), False)
    # heuristic dissector (decrypted DTLS and TLS)
    U(mt(0, create_req(0x55667788)), heur='rdpmt_dtls')
    U(mt(1, struct.pack('<i', 0)), False, heur='rdpmt_dtls')
    U(mt(2, b'\x10\x06bar\0'), False, heur='rdpmt_tls_')
    U(mt(2, b'\x10\x08q\0', sub=autodetect(0, 3, 0x0001)), False, heur='rdpmt_dtls')
    # data that is not RDPMT: every condition of the heuristic
    for bad in (b'\x00\x00\x00', mt(3, b'abcd'), mt(2, b'', hlen=3), mt(2, b'abcd', plen=100), mt(2, b'xxxxxxxx', plen=4, hlen=5),
                mt(2, b'', sub=b'\x01\x00'), mt(2, b'', sub=autodetect(0, 1, 1)[:1] + b'\x09' + bytes(4)),
                mt(2, b'', sub=struct.pack('<BBHH', 6, 5, 1, 1)), mt(2, b'', sub=struct.pack('<BBHH', 1, 0, 1, 1))):
        U(bad, False, heur='rdpmt_dtls')
    # a lossy second tunnel for a request that has no TCP counterpart, and the reliable one
    U(mt(0, create_req(0x99999999)), sport=50051)
    U(mt(0, create_req(0x11223344)), sport=50052)
    U(mt(2, b'\x10\x07baz\0'), False, sport=50052)
    cap.write(os.path.join(OUT, 'multitransport-coverage.pcapng'))
    if VERBOSE:
        print('multitransport-coverage.pcapng', len(cap.frames), 'frames')


def build_malformed():
    cap = Cap()
    X = lambda p, **kw: cap.exp('rdpmt', p, True, sport=50050, pt=3, **kw)
    X(b'\x00')
    X(b'\x00\x10\x00')
    X(mt(0, b'\0' * 10))                                            # create request cut short
    X(mt(1, b''))
    X(mt(2, b'x', plen=10))
    X(mt(2, b'x', sub=autodetect(0, 1, 0x0002, struct.pack('<H', 600))))
    X(mt(2, b'x', sub=autodetect(0, 1, 0x0840, b'')))
    X(mt(2, b'x', hlen=200))
    X(mt(2, b'', hlen=5))
    cap.write(os.path.join(OUT, 'multitransport-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build_main()
    build_malformed()

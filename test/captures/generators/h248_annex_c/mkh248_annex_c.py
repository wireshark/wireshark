#!/usr/bin/env python3
# Generates test/captures/h248_annex_c_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-h248_annex_c.c (H.248.1 Annex C, the
"Media stream properties" package, id 0x0000: media, ATM/AAL, IP, FR,
ISDN and H.324 properties and the SDP lines of Annex C).
Usage: mkh248_annex_c.py <outdir>
Writes h248_annex_c-coverage.pcapng and h248_annex_c-coverage-malformed.pcapng."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from h248common import (
    A, action, ber_int, CODECS, command, megaco, NSAPS, pkg_main, prop_msg, prop_parm, struct,
    term_id, term_list, tlv, trx_req, udp, USI,
)

PK = [0x0000]
T = term_id(b'\x01\x02')
I = lambda v: tlv(2, ber_int(v))
MG = ('192.0.2.12', 2945, '192.0.2.13', 2945)


def pp(item, content):
    return prop_parm(0, item, [content])


def specific(g, sw):
    F = []
    # the codec (ACodec) in every form the Annex C decoder shows: ITU-T and ETSI codecs with and without configuration
    for k, c in enumerate(CODECS):
        F.append(prop_msg(T, [pp(0x1006, tlv(4, c))], 2 + k % 2, 10 + k))
    # a termination with the bearer information reference and the NSAP address: with the context tracking
    # the references are shown for each termination of the context
    for k, nsap in enumerate(NSAPS):
        F.append(udp(megaco([trx_req(30 + k, [action(5 + k, [command(0, term_list(term_id(bytes([k + 1]))),
                            A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, pp(0x3002, tlv(4, bytes([0, k, 0, 1]))), pp(0x3003, tlv(4, nsap)))))))])])]),
                     *MG))
    # the second termination of the first context, with the same references
    F.append(udp(megaco([trx_req(40, [action(5, [command(0, term_list(term_id(b'\x09')),
                        A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, pp(0x3002, tlv(4, bytes([0, 0, 0, 1]))), pp(0x3003, tlv(4, NSAPS[0])))))))])])]),
                 *MG))
    # SDP lines: every line type, and media lines with a port, without one, with a text instead of a port
    for k, (item, txt) in enumerate(((0xb001, b'0'), (0xb002, b'- 1 2 IN IP4 192.0.2.1'), (0xb003, b'-'), (0xb004, b'i'),
                                     (0xb005, b'http://example.invalid/'), (0xb006, b'a@example.invalid'),
                                     (0xb007, b'+1 555 0100'), (0xb008, b'IN IP4 192.0.2.1'), (0xb008, b'IN IP6 2001:db8::2'),
                                     (0xb009, b'AS:64'), (0xb00a, b'0 0'), (0xb00b, b'prompt'), (0xb00c, b'ptime:20'),
                                     (0xb00d, b'0 0'), (0xb00e, b'0 0 0 0'), (0xb00f, b'audio 5004 RTP/AVP 0'),
                                     (0xb00f, b'video 0 RTP/AVP 31'), (0xb00f, b'audio x RTP/AVP 0'), (0xb00f, b'audio'),
                                     (0xb00f, b'audio 5004'), (0xb00f, b'audio  RTP'), (0xb00f, b'image 65535 udptl t38'))):
        F.append(prop_msg(T, [pp(item, tlv(0x16, txt))], 2 + k % 2, 50 + k))
    # ATM virtual path / channel, the Q.931 user service information, the connection/AAL parameters
    F.append(prop_msg(T, [pp(0x4002, struct.pack('>HH', 1, 32)), pp(0x4002, struct.pack('>HH', 4095, 65535))], 2, 80))
    F.append(prop_msg(T, [pp(0x9008, tlv(4, u)) for u in USI] + [pp(0x9023, tlv(4, USI[0]))], 2, 81))
    F.append(prop_msg(T, [pp(0x1001, I(1)), pp(0x1002, I(2)), pp(0x1005, I(64000)), pp(0x1008, tlv(1, b'\xff')),
                          pp(0x1008, tlv(1, b'\x00')), pp(0x4009, tlv(4, b'\x00\x00\x10')), pp(0x400f, tlv(1, b'\xff')),
                          pp(0x6001, tlv(4, b'\xc0\x00\x02\x01')), pp(0x6002, tlv(4, bytes(range(16)))), pp(0x6003, I(5004)),
                          pp(0xA003, tlv(4, b'\x01')), pp(0x2001, tlv(4, b'\x01\x02'))], 3, 82))
    # unknown property ids of the package, and the package in a local control descriptor of a stream
    F.append(prop_msg(T, [pp(0x1000, I(1)), pp(0x7fff, I(1))], 2, 83))
    lcd = tlv(0xA0, tlv(0xA0, tlv(0xA0, tlv(0xA3, pp(0x1007, I(20)), pp(0x1006, tlv(4, CODECS[0]))))))
    F.append(udp(megaco([trx_req(84, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA1, tlv(0xA0, lcd)))))])])])))
    return F


def bad():
    M = []
    # ACodec that is not an octet string (the NULL tvb of the fixed assertion), an empty one, an unknown organisation
    M.append(megaco([trx_req(1, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0, 0x1006, [tlv(2, b'\x00')]))))))])])]))
    M.append(megaco([trx_req(2, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0, 0x1006, [tlv(4, tlv(4, b''))]))))))])])]))
    for c in (b'\x05\x01\x02', b'\x02', b''):
        M.append(megaco([trx_req(3, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0, 0x1006, [tlv(4, tlv(4, c))]))))))])])]))
    # an SDP media port out of range (error expert info), a vpvc of three octets, an SDP line that is not an IA5String
    for item, v in ((0xb00f, tlv(0x16, b'audio 99999999999 RTP/AVP 0')), (0xb00f, tlv(0x16, b'audio 4294967296 RTP/AVP 0')),
                    (0x4002, b'\x00\x01\x00'), (0xb001, tlv(4, b'0')), (0xb008, b''), (0x9008, tlv(4, b'')), (0x3003, tlv(4, b'')),
                    (0x3002, tlv(4, b'')), (0x1001, tlv(4, b'x')), (0x1008, tlv(2, b'\x01'))):
        M.append(megaco([trx_req(4, [action(1, [command(0, term_list(T), A(1, tlv(0xA0, tlv(0xA0, tlv(0xA0, prop_parm(0, item, [v]))))))])])]))
    return M


if __name__ == '__main__':
    pkg_main(sys.argv[1] if len(sys.argv) > 1 else '.', 'h248_annex_c', PK, specific, bad, 61, passes=3, nrand=60)

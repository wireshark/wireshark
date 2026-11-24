#!/usr/bin/env python3
# Generates test/captures/isis_clv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates isis-clv-coverage.pcap (clean) and isis-clv-coverage-malformed.pcap.
# packet-isis-clv.c has no port or ethertype of its own: it holds the TLV code
# shared by the hello, LSP and SNP dissectors, so every frame here is a hello,
# LSP, CSNP or PSNP carrying the shared TLVs: area addresses (1), instance
# identifier (7), authentication (10), hostname (137), IPv4 (132) and IPv6
# (232) interface addresses, TE router ID (134), protocols supported (129),
# multi topology (229) and the TLV loop (isis_dissect_clvs).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from isislib import (
    area, auth_clear, auth_crypto, auth_md5, csnp, hello, ip4, ip6, lsp, lsp_entry, psnp, struct,
    tlv, write_pcap,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
A1 = tlv(1, area(b'\x49\x00\x01'))
AREAS = tlv(1, area(b'', b'\x49\x00\x01', b'\x47\x00\x05\x80\x00\x01\x00\x00'))
IIDS = tlv(7, struct.pack('>H', 5) + struct.pack('>HHH', 1, 2, 3))
IIDS1 = tlv(7, struct.pack('>H', 6) + struct.pack('>H', 1))
NLPIDS = tlv(129, bytes([0xcc, 0x8e, 0xc1, 0x00, 0x83]))
IP4 = tlv(132, ip4(192, 0, 2, 1) + ip4(192, 0, 2, 2))
IP6 = tlv(232, ip6('fe80::1') + ip6('2001:db8::2'))
MT = tlv(229, struct.pack('>HHHHHHHH', 0, 0x8002, 0x4001, 3, 4, 5, 0xc7ff, 7))
TERID = tlv(134, ip4(10, 0, 0, 1))
HOST = tlv(137, b'router-one.example')
ENTRY = tlv(9, lsp_entry(6, 7))
digests = {16: 'hmac-md5', 20: 'sha1', 28: 'sha224', 32: 'sha256', 48: 'sha384', 64: 'sha512'}

frames = []
add = frames.append
# hello PDUs (L1, L2, point to point)
add(hello(1, [AREAS, IIDS, NLPIDS, IP4, IP6, MT]))                       # 1
add(hello(2, [AREAS, IIDS1, NLPIDS, IP4, IP6, MT]))                      # 2
add(hello(3, [AREAS, IIDS, NLPIDS, IP4, IP6, MT]))                       # 3
# LSP PDUs
add(lsp(1, [AREAS, IIDS, NLPIDS, IP4, IP6, MT, TERID, HOST]))            # 4
add(lsp(2, [A1, IIDS1, tlv(137, b''), tlv(137, b'x'), TERID, tlv(134, b'')]))   # 5  empty hostname, empty TE router ID
# SNP PDUs carry the instance identifier and the authentication TLV
add(csnp(1, [IIDS, ENTRY]))                                              # 6
add(csnp(2, [IIDS1, ENTRY]))                                             # 7
add(psnp(1, [IIDS, ENTRY]))                                              # 8
add(psnp(2, [IIDS1, ENTRY]))                                             # 9
# authentication in every PDU type and every digest length
for i, (n, name) in enumerate(digests.items()):
    pdu = [hello(1, [A1, auth_crypto(i, bytes(range(n)))]), lsp(1, [A1, auth_crypto(i, bytes(range(n)))]),
           csnp(2, [auth_crypto(i, bytes(range(n))), ENTRY]), psnp(2, [auth_crypto(i, bytes(range(n))), ENTRY]),
           hello(3, [A1, auth_crypto(i, bytes(range(n)))]), lsp(2, [A1, auth_crypto(i, bytes(range(n)))])][i % 6]
    add(pdu)                                                             # 10-15
add(hello(2, [A1, auth_crypto(9, bytes(range(21)))]))                    # 16 illegal digest length
add(lsp(1, [A1, auth_clear(b'pass')]))                                   # 17
add(csnp(1, [auth_clear(b'pass'), ENTRY]))                               # 18
add(psnp(1, [tlv(10, b'\x01'), ENTRY]))                                  # 19 no password
add(hello(1, [A1, auth_md5()]))                                          # 20
add(lsp(2, [A1, auth_md5()]))                                            # 21
add(hello(1, [A1, tlv(10, b'\x36' + bytes(5))]))                         # 22 md5 with a bad length
add(lsp(1, [A1, tlv(10, b'\x77\x01\x02')]))                              # 23 unknown type (warning)
add(hello(2, [A1, tlv(10, b'\x03\x00'), tlv(10, b'\x03\x00\x01')]))      # 24 reproducer of the Key ID fix (warning)
add(lsp(1, [A1, tlv(10, b'\x03\x00'), HOST]))                            # 25 the same in an LSP: the hostname must stay a hostname
add(lsp(1, [tlv(10, b''), A1]))                                          # 26 empty authentication
# unknown TLV code in each PDU type
add(hello(1, [A1, tlv(200, b'x')]))                                      # 27
add(lsp(1, [A1, tlv(200, b'x')]))                                        # 28
add(csnp(1, [tlv(200, b'x'), ENTRY]))                                    # 29
add(psnp(1, [tlv(200, b'x'), ENTRY]))                                    # 30
# an empty TLV list and a TLV that fills the PDU
add(hello(1, []))                                                        # 31
add(lsp(2, [tlv(137, b'a' * 255)]))                                      # 32
add(lsp(1, [tlv(132, b''), tlv(232, b''), tlv(134, b''), tlv(129, b''), tlv(1, b''), tlv(229, b''), tlv(137, b''), A1]))   # 33 empty TLVs
add(hello(1, [tlv(132, b''), tlv(232, b''), tlv(129, b''), tlv(1, b''), tlv(229, b''), A1]))                      # 34
write_pcap(os.path.join(out, 'isis-clv-coverage.pcap'), frames)

mal = []
madd = mal.append
madd(hello(1, [tlv(1, b'\x05\x01')]))                    # area address longer than the TLV
madd(lsp(1, [tlv(1, b'\x03')]))                          # no payload after the area length
madd(hello(1, [A1, tlv(132, ip4(1, 2, 3, 4) + b'\x01')]))   # short IPv4
madd(lsp(1, [tlv(132, b'\x01\x02')]))
madd(hello(1, [A1, tlv(232, ip6('::1') + b'\x01')]))        # short IPv6
madd(lsp(1, [tlv(232, b'\x01')]))
madd(lsp(1, [tlv(134, b'\x01\x02\x03\x04\x05')]))        # malformed TE router ID
madd(hello(1, [A1, tlv(229, b'\x00\x00\x00')]))          # odd multi topology length
madd(lsp(1, [tlv(229, b'\x00')]))
madd(hello(1, [A1, tlv(7, b''), tlv(7, b'\x01')]))        # instance identifier too short
madd(lsp(1, [tlv(7, b'\x00'), A1]))
madd(hello(1, [A1, tlv(50, bytes(60))])[:-30])           # TLV longer than the PDU
madd(csnp(1, [tlv(10, b'\x03\x00\x01')])[:-1])           # truncated authentication
madd(hello(1, [A1, bytes([50, 60]) + bytes(5)]))            # TLV length beyond the end of the PDU (short CLV header)
madd(lsp(2, [A1, bytes([50, 60]) + bytes(5)]))
madd(csnp(1, [ENTRY, bytes([50, 60]) + bytes(5)]))
madd(psnp(1, [ENTRY, bytes([50, 60]) + bytes(5)]))
madd(hello(1, [A1, b'\x01']))                               # a lone TLV code at the end of the PDU
madd(lsp(1, [A1, b'\x01']))
write_pcap(os.path.join(out, 'isis-clv-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))

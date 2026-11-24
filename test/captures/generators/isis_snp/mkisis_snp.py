#!/usr/bin/env python3
# Generates test/captures/isis_snp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates isis-snp-coverage.pcap (clean) and isis-snp-coverage-malformed.pcap
# for packet-isis-snp.c (CSNP and PSNP, level 1 and 2).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from isislib import (
    auth_clear, auth_crypto, auth_md5, CKSUM, csnp, lsp_entry, psnp, struct, tlv, with_checksum,
    write_pcap,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
IID = tlv(7, struct.pack('>H', 5) + struct.pack('>HH', 1, 2))
def entries(n, count=3, base=1):
    return tlv(9, b''.join(lsp_entry(n, 0x100 + i, life=1200 - i, cks=0xabc0 + i, idx=base + i, frag=i) for i in range(count)))

frames = []
add = frames.append
# CSNPs
add(csnp(1, [entries(6)]))                                              # 1  L1 CSNP, 3 entries
add(csnp(2, [entries(6, 5, 10)]))                                       # 2  L2 CSNP, 5 entries
add(csnp(1, [IID, entries(6, 1), auth_clear()]))                        # 3  instance identifier, clear text
add(csnp(2, [auth_md5(), entries(6, 2)]))                               # 4  HMAC-MD5
add(csnp(1, [auth_crypto(3, bytes(range(32))), entries(6, 2)]))         # 5  CRYPTO_AUTH, sha256 placeholder digest
add(csnp(2, [tlv(133, b'ippass'), tlv(133, b'')]))                      # 6  IP authentication
add(csnp(1, [tlv(10, b'\x99\x01'), tlv(10, b'\x01'), tlv(10, b'')]))    # 7  unknown type (warning), no password
add(with_checksum(csnp(1, [entries(6, 2), CKSUM])))                     # 8  good checksum
add(csnp(2, [entries(6, 2), tlv(12, b'\x00\x00')]))                     # 9  checksum not present
add(csnp(2, [tlv(99, b'xyz'), entries(6, 1)]))                          # 10 unknown TLV
add(csnp(1, [entries(0, 1)], idlen=255))                                # 11 null system ID: entries of 2+0+2+4+2
add(csnp(2, [entries(8, 2)], idlen=8))                                  # 12 ID length 8
add(csnp(1, [entries(1, 2)], idlen=1))                                  # 13 ID length 1
add(csnp(1, [tlv(9, b'')]))                                             # 14 empty LSP entries TLV
add(csnp(1, [tlv(9, lsp_entry(6, 1) * 12)]))                            # 15 full TLV (12 entries = 192 octets)
# PSNPs
add(psnp(1, [entries(6)]))                                              # 16 L1 PSNP
add(psnp(2, [entries(6, 4, 20)]))                                       # 17 L2 PSNP
add(psnp(1, [IID, entries(6, 1), auth_clear()]))                        # 18
add(psnp(2, [auth_md5(), entries(6, 2)]))                               # 19
add(psnp(1, [auth_crypto(4, bytes(range(20))), entries(6, 2)]))         # 20 CRYPTO_AUTH, sha1 placeholder digest
add(psnp(2, [tlv(133, b'ippass'), tlv(133, b'')]))                      # 21
add(psnp(1, [tlv(10, b'\x99\x01'), tlv(10, b'\x01'), tlv(10, b'')]))    # 22
add(with_checksum(psnp(2, [entries(6, 2), CKSUM])))                     # 23 good checksum
add(psnp(1, [entries(6, 2), tlv(12, b'\x00\x00')]))                     # 24 checksum not present
add(psnp(2, [tlv(99, b'xyz'), entries(6, 1)]))                          # 25 unknown TLV
add(psnp(1, [entries(0, 1)], idlen=255))                                # 26
add(psnp(2, [entries(8, 2)], idlen=8))                                  # 27
add(psnp(1, [entries(1, 2)], idlen=1))                                  # 28
# over ethertype 0x22F4
add((csnp(1, [entries(6)]), 'eth'))                                     # 29
add((psnp(2, [entries(6)]), 'eth'))                                     # 30
# Reproducer of the fix in isis_dissect_authentication_clv (isis_smallfixes frame 7): CRYPTO_AUTH
# with one octet left for the Key ID gives a warning instead of reading the next TLV
add(csnp(1, [tlv(10, b'\x03\x00'), entries(6, 1)]))                    # 31
add(psnp(1, [tlv(10, b'\x03\x00'), entries(6, 1)]))                    # 32
write_pcap(os.path.join(out, 'isis-snp-coverage.pcap'), frames)

mal = []
madd = mal.append
for hl in (9, 8 + 2 + 6 + 1 - 1, 8 + 2 + 6 + 1 + 8 - 1):
    madd(csnp(1, [entries(6, 1)], hdrlen=hl))
madd(csnp(2, [entries(6, 1)], hdrlen=8))
for hl in (9, 8 + 2 + 6 + 1 - 1):
    madd(psnp(1, [entries(6, 1)], hdrlen=hl))
madd(csnp(1, [entries(6, 1)], pdulen=10))                         # PDU length less than header
madd(csnp(1, [entries(6, 1)], pdulen=900))                        # PDU length greater than packet
madd(psnp(2, [entries(6, 1)], pdulen=10))
madd(psnp(2, [entries(6, 1)], pdulen=900))
madd(csnp(1, [tlv(9, lsp_entry(6, 1) + b'\x01\x02\x03')]))        # short LSP entry
madd(psnp(1, [tlv(9, lsp_entry(6, 1)[:-1])]))
madd(csnp(1, [tlv(12, b'\x00')]))                                 # checksum length 1
madd(psnp(2, [tlv(12, b'\x00\x00\x00')]))
madd(csnp(1, [tlv(12, b'\x12\x34')]))                             # bad checksum
madd(psnp(1, [tlv(12, b'\x12\x34')]))
madd((with_checksum(csnp(1, [CKSUM, tlv(8, bytes(40))])), 'snap:20'))    # checksum cannot be verified
madd((with_checksum(psnp(1, [CKSUM, tlv(8, bytes(40))])), 'snap:20'))
madd(csnp(1, [tlv(7, b'')]))                                      # empty instance identifier
madd(psnp(2, [tlv(7, b''), tlv(7, b'\x01')]))
madd(csnp(1, [tlv(9, lsp_entry(6, 1))])[:-8])                     # truncated PDU
madd(psnp(1, [tlv(9, lsp_entry(6, 1))])[:-8])
madd(csnp(1, [tlv(9, lsp_entry(6, 1)), tlv(99, bytes(10))], pdulen=60)[:-20])   # TLV longer than the PDU
write_pcap(os.path.join(out, 'isis-snp-coverage-malformed.pcap'), mal)
print(len(frames), len(mal))

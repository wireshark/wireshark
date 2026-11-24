#!/usr/bin/env python3
# Helper module for the dcerpc_krb5rpc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""KRB5RPC sendto_kdc request/response carrying a small Kerberos blob.
krb5rpc returns the offset from dissect_kerberos_main(), which is relative
to the krb5 sub-tvb, not to the stub; the response adds 16 more."""
import struct
import os
from dcerpc_cl_small import pair, pcap
K = '8f73de50-768c-11ca-bffc-08001e039431'
def der(tag, body):
    return bytes([tag, len(body)]) + body
# KRB-ERROR [APPLICATION 30] SEQUENCE { pvno[0] 5, msg-type[1] 30, stime[4], susec[5], error-code[6] }
gt = b'\x18\x0f20261101000000Z'
seq = der(0xa0, b'\x02\x01\x05') + der(0xa1, b'\x02\x01\x1e') + der(0xa4, gt) + der(0xa5, b'\x02\x01\x00') + der(0xa6, b'\x02\x01\x06') + der(0xa9, der(0x1b, b'EXAMPLE.TEST')) + der(0xaa, der(0x30, der(0xa0, b'\x02\x01\x01') + der(0xa1, der(0x30, der(0x1b, b'krbtgt')))))
blob = der(0x7e, der(0x30, seq))
fr = []
pair(fr, K, 1, 0, struct.pack('<II', len(blob), len(blob)) + blob,
     struct.pack('<IIII', len(blob), 4096, 0, len(blob)) + blob)
pcap(os.path.splitext(os.path.abspath(__file__))[0] + '.pcap', fr)

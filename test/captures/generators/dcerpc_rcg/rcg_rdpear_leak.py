#!/usr/bin/env python3
# Helper module for the dcerpc_rcg capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# RDPEAR (rdp_ear) frames carrying an RCG KerbCredIsoRemoteInput
# (RemoteCallKerbNegotiateVersion) in an unsealed CFX wrap token.
# Every frame leaks the NDR pointer list that dissect_rdpear_packagePayload()
# creates with init_ndr_pointer_list() and never frees.
import struct
import sys
from rcg_rdpear_common import rdpear_frame, write_pcap
N = int(sys.argv[1]) if len(sys.argv) > 1 else 200
buf = b'\0' * 16 + b'\0' * 24
buf += struct.pack('<HH', 0x100, 0x100) + struct.pack('<I', 0x00020000) + struct.pack('<I', 1)
buf += b'\0' * 16
write_pcap(sys.argv[2] if len(sys.argv) > 2 else 'rcg_rdpear_leak.pcap',
           [rdpear_frame('Kerberos', buf) for _ in range(N)])

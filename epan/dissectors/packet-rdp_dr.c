/* packet-rdp_dr.c
 * Routines for the DR RDP channel
 * Copyright 2025, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPEFS] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"
#include "packet-dcerpc.h"
#include "packet-dcerpc-rdpdr_smartcard.h"

void proto_register_rdpdr(void);
void proto_reg_handoff_rdpdr(void);

static int proto_rdpdr;

static int hf_rdpdr_component;
static int hf_rdpdr_packetid;
static int hf_rdpdr_deviceCount;
static int hf_rdpdr_deviceType;
static int hf_rdpdr_deviceId;
static int hf_rdpdr_dosName;
static int hf_rdpdr_deviceDataLen;
static int hf_rdpdr_deviceData;
static int hf_rdpdr_numCapabilities;
static int hf_rdpdr_padding;
static int hf_rdpdr_capaType;
static int hf_rdpdr_capaLen;
static int hf_rdpdr_capaVersion;
static int hf_rdpdr_capa_gen_osType;
static int hf_rdpdr_capa_gen_osVersion;
static int hf_rdpdr_capa_gen_protocolMajor;
static int hf_rdpdr_capa_gen_protocolMinor;
static int hf_rdpdr_capa_gen_ioCode1;
static int hf_rdpdr_capa_gen_ioCode2;
static int hf_rdpdr_capa_gen_extendedPdu;
static int hf_rdpdr_capa_gen_extraFlags1;
static int hf_rdpdr_capa_gen_extraFlags2;
static int hf_rdpdr_capa_gen_specialTypeDeviceCap;
static int hf_rdpdr_fileId;
static int hf_rdpdr_completionId;
static int hf_rdpdr_ioreq_dr_majorFunction;
static int hf_rdpdr_ioreq_dr_minorFunction;
static int hf_rdpdr_ioreq_sc_majorFunction;
static int hf_rdpdr_ioreq_sc_minorFunction;
static int hf_rdpdr_ioreq_sc_command;
static int hf_rdpdr_ioreq_sc_returnCode;
static int hf_rdpdr_printer_cacheEvent;
static int hf_rdpdr_pnpNameLength;
static int hf_rdpdr_pnpName;
static int hf_rdpdr_driverNameLength;
static int hf_rdpdr_driverName;
static int hf_rdpdr_printerNameLength;
static int hf_rdpdr_printerName;
static int hf_rdpdr_cachedFieldsLength;
static int hf_rdpdr_cachedFields;
static int hf_rdpdr_resultCode;
static int hf_rdpdr_ioStatus;
static int hf_rdpdr_io_request_control_outputBufLen;
static int hf_rdpdr_io_request_control_inputBufLen;
static int hf_rdpdr_io_request_control_ioControlCode;
static int hf_rdpdr_io_request_control_padding;
static int hf_rdpdr_io_request_frame;
static int hf_rdpdr_io_result_frame;
static int hf_rdpdr_create_info;
static int hf_rdpdr_device_name;


static int ett_rdpdr;
static int ett_rdpdr_device;
static int ett_rdpdr_capabilities;

enum {
	RDPDR_CTYP_CORE = 0x4472,
	RDPDR_CTYP_PRN = 0x5052,
};

enum {
	PAKID_CORE_SERVER_ANNOUNCE = 0x496E,
	PAKID_CORE_CLIENTID_CONFIRM = 0x4343,
	PAKID_CORE_CLIENT_NAME = 0x434E,
	PAKID_CORE_DEVICELIST_ANNOUNCE = 0x4441,
	PAKID_CORE_DEVICE_REPLY = 0x6472,
	PAKID_CORE_DEVICE_IOREQUEST = 0x4952,
	PAKID_CORE_DEVICE_IOCOMPLETION = 0x4943,
	PAKID_CORE_SERVER_CAPABILITY = 0x5350,
	PAKID_CORE_CLIENT_CAPABILITY = 0x4350,
	PAKID_CORE_DEVICELIST_REMOVE = 0x444D,
	PAKID_PRN_CACHE_DATA = 0x5043,
	PAKID_CORE_USER_LOGGEDON = 0x554C,
	PAKID_PRN_USING_XPS = 0x5543,
};

enum {
	RDPDR_DTYP_SERIAL = 0x01,
	RDPDR_DTYP_PARALLEL = 0x02,
	RDPDR_DTYP_PRINT = 0x04,
	RDPDR_DTYP_FILESYSTEM = 0x08,
	RDPDR_DTYP_SMARTCARD = 0x20,
};

enum {
	CAP_GENERAL_TYPE = 0x0001,
	CAP_PRINTER_TYPE = 0x0002,
	CAP_PORT_TYPE = 0x0003,
	CAP_DRIVE_TYPE = 0x0004,
	CAP_SMARTCARD_TYPE = 0x0005
};

static const value_string rdpdr_capaType_vals[] = {
	{ CAP_GENERAL_TYPE, "General" },
	{ CAP_PRINTER_TYPE, "Printer" },
	{ CAP_PORT_TYPE, "Port" },
	{ CAP_DRIVE_TYPE, "Drive" },
	{ CAP_SMARTCARD_TYPE, "Smartcard" },
	{ 0x0, NULL},
};

enum {
	IRP_MJ_CREATE = 0x00000000,
	IRP_MJ_CLOSE = 0x00000002,
	IRP_MJ_READ = 0x00000003,
	IRP_MJ_WRITE = 0x00000004,
	IRP_MJ_DEVICE_CONTROL = 0x0000000E,
	IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0000000A,
	IRP_MJ_SET_VOLUME_INFORMATION = 0x0000000B,
	IRP_MJ_QUERY_INFORMATION = 0x00000005,
	IRP_MJ_SET_INFORMATION = 0x00000006,
	IRP_MJ_DIRECTORY_CONTROL = 0x0000000C,
	IRP_MJ_LOCK_CONTROL = 0x00000011,

	IRP_MN_QUERY_DIRECTORY = 0x00000001,
	IRP_MN_NOTIFY_CHANGE_DIRECTORY = 0x00000002,
};

enum {
	FILE_SUPERSEDED = 0x00000000,
	FILE_OPENED = 0x00000001,
	FILE_OVERWRITTEN = 0x00000003,
};

static const value_string rdpdr_component_vals[] = {
	{ RDPDR_CTYP_CORE, "RDPDR_CTYP_CORE"},
	{ RDPDR_CTYP_PRN, "RDPDR_CTYP_PRN"},
	{ 0x0, NULL},
};

static const value_string rdpdr_packetid_vals[] = {
	{ PAKID_CORE_SERVER_ANNOUNCE, "PAKID_CORE_SERVER_ANNOUNCE" },
	{ PAKID_CORE_CLIENTID_CONFIRM, "PAKID_CORE_CLIENTID_CONFIRM" },
	{ PAKID_CORE_CLIENT_NAME, "PAKID_CORE_CLIENT_NAME" },
	{ PAKID_CORE_DEVICELIST_ANNOUNCE, "PAKID_CORE_DEVICELIST_ANNOUNCE"},
	{ PAKID_CORE_DEVICE_REPLY, "PAKID_CORE_DEVICE_REPLY"},
	{ PAKID_CORE_DEVICE_IOREQUEST, "PAKID_CORE_DEVICE_IOREQUEST"},
	{ PAKID_CORE_DEVICE_IOCOMPLETION, "PAKID_CORE_DEVICE_IOCOMPLETION"},
	{ PAKID_CORE_SERVER_CAPABILITY, "PAKID_CORE_SERVER_CAPABILITY"},
	{ PAKID_CORE_CLIENT_CAPABILITY, "PAKID_CORE_CLIENT_CAPABILITY"},
	{ PAKID_CORE_DEVICELIST_REMOVE, "PAKID_CORE_DEVICELIST_REMOVE"},
	{ PAKID_PRN_CACHE_DATA, "PAKID_PRN_CACHE_DATA"},
	{ PAKID_CORE_USER_LOGGEDON, "PAKID_CORE_USER_LOGGEDON"},
	{ PAKID_PRN_USING_XPS, "PAKID_PRN_USING_XPS"},
	{ 0x0, NULL},
};

static const value_string rdpdr_deviceType_vals[] = {
	{ RDPDR_DTYP_SERIAL, "RDPDR_DTYP_SERIAL"},
	{ RDPDR_DTYP_PARALLEL, "RDPDR_DTYP_PARALLEL"},
	{ RDPDR_DTYP_PRINT, "RDPDR_DTYP_PRINT"},
	{ RDPDR_DTYP_FILESYSTEM, "RDPDR_DTYP_FILESYSTEM"},
	{ RDPDR_DTYP_SMARTCARD, "RDPDR_DTYP_SMARTCARD"},
	{ 0x0, NULL},
};

static const value_string rdpdr_dr_majorF_vals[] = {
	{ IRP_MJ_CREATE, "IRP_MJ_CREATE" },
	{ IRP_MJ_CLOSE, "IRP_MJ_CLOSE" },
	{ IRP_MJ_READ, "IRP_MJ_READ" },
	{ IRP_MJ_WRITE, "IRP_MJ_WRITE" },
	{ IRP_MJ_DEVICE_CONTROL, "IRP_MJ_DEVICE_CONTROL" },
	{ IRP_MJ_QUERY_VOLUME_INFORMATION, "IRP_MJ_QUERY_VOLUME_INFORMATION" },
	{ IRP_MJ_SET_VOLUME_INFORMATION, "IRP_MJ_SET_VOLUME_INFORMATION" },
	{ IRP_MJ_QUERY_INFORMATION, "IRP_MJ_QUERY_INFORMATION" },
	{ IRP_MJ_SET_INFORMATION, "IRP_MJ_SET_INFORMATION" },
	{ IRP_MJ_DIRECTORY_CONTROL, "IRP_MJ_DIRECTORY_CONTROL" },
	{ IRP_MJ_LOCK_CONTROL, "IRP_MJ_LOCK_CONTROL" },
	{ 0x0, NULL},
};

static const value_string rdpdr_dr_minorF_vals[] = {
	{ IRP_MN_QUERY_DIRECTORY, "IRP_MN_QUERY_DIRECTORY" },
	{ IRP_MN_NOTIFY_CHANGE_DIRECTORY, "IRP_MN_NOTIFY_CHANGE_DIRECTORY" },
	{ 0x0, NULL},
};

static const value_string rdpdr_dr_createinfo_vals[] = {
		{ FILE_SUPERSEDED, "FILE_SUPERSEDED" },
		{ FILE_OPENED, "FILE_OPENED" },
		{ FILE_OVERWRITTEN, "FILE_OVERWRITTEN" },
		{ 0x0, NULL},
};

enum {
	SCARD_IOCTL_ESTABLISHCONTEXT = 0x00090014,
	SCARD_IOCTL_RELEASECONTEXT = 0x00090018,
	SCARD_IOCTL_ISVALIDCONTEXT = 0x0009001C,
	SCARD_IOCTL_LISTREADERGROUPSA = 0x00090020,
	SCARD_IOCTL_LISTREADERGROUPSW = 0x00090024,
	SCARD_IOCTL_LISTREADERSA = 0x00090028,
	SCARD_IOCTL_LISTREADERSW = 0x0009002C,
	SCARD_IOCTL_INTRODUCEREADERGROUPA = 0x00090050,
	SCARD_IOCTL_INTRODUCEREADERGROUPW = 0x00090054,
	SCARD_IOCTL_FORGETREADERGROUPA = 0x00090058,
	SCARD_IOCTL_FORGETREADERGROUPW = 0x0009005C,
	SCARD_IOCTL_INTRODUCEREADERA = 0x00090060,
	SCARD_IOCTL_INTRODUCEREADERW = 0x00090064,
	SCARD_IOCTL_FORGETREADERA = 0x00090068,
	SCARD_IOCTL_FORGETREADERW = 0x0009006C,
	SCARD_IOCTL_ADDREADERTOGROUPA = 0x00090070,
	SCARD_IOCTL_ADDREADERTOGROUPW = 0x00090074,
	SCARD_IOCTL_REMOVEREADERFROMGROUPA = 0x00090078,
	SCARD_IOCTL_REMOVEREADERFROMGROUPW = 0x0009007C,
	SCARD_IOCTL_LOCATECARDSA = 0x00090098,
	SCARD_IOCTL_LOCATECARDSW = 0x0009009C,
	SCARD_IOCTL_GETSTATUSCHANGEA = 0x000900A0,
	SCARD_IOCTL_GETSTATUSCHANGEW = 0x000900A4,
	SCARD_IOCTL_CANCEL = 0x000900A8,
	SCARD_IOCTL_CONNECTA = 0x000900AC,
	SCARD_IOCTL_CONNECTW = 0x000900B0,
	SCARD_IOCTL_RECONNECT = 0x000900B4,
	SCARD_IOCTL_DISCONNECT = 0x000900B8,
	SCARD_IOCTL_BEGINTRANSACTION = 0x000900BC,
	SCARD_IOCTL_ENDTRANSACTION = 0x000900C0,
	SCARD_IOCTL_STATE = 0x000900C4,
	SCARD_IOCTL_STATUSA = 0x000900C8,
	SCARD_IOCTL_STATUSW = 0x000900CC,
	SCARD_IOCTL_TRANSMIT = 0x000900D0,
	SCARD_IOCTL_CONTROL = 0x000900D4,
	SCARD_IOCTL_GETATTRIB = 0x000900D8,
	SCARD_IOCTL_SETATTRIB = 0x000900DC,
	SCARD_IOCTL_ACCESSSTARTEDEVENT = 0x000900E0,
	SCARD_IOCTL_LOCATECARDSBYATRA = 0x000900E8,
	SCARD_IOCTL_LOCATECARDSBYATRW = 0x000900EC,
	SCARD_IOCTL_READCACHEA = 0x000900F0,
	SCARD_IOCTL_READCACHEW = 0x000900F4,
	SCARD_IOCTL_WRITECACHEA = 0x000900F8,
	SCARD_IOCTL_WRITECACHEW = 0x000900FC,
	SCARD_IOCTL_GETTRANSMITCOUNT = 0x00090100,
	SCARD_IOCTL_RELEASETARTEDEVENT = 0x000900E4,
	SCARD_IOCTL_GETREADERICON = 0x00090104,
	SCARD_IOCTL_GETDEVICETYPEID = 0x00090108,
};

enum {
	RDPDR_ADD_PRINTER_EVENT = 0x00000001,
	RDPDR_UPDATE_PRINTER_EVENT = 0x00000002,
	RDPDR_DELETE_PRINTER_EVENT = 0x00000003,
	RDPDR_RENAME_PRINTER_EVENT = 0x00000004,
};

#define STR_VALUE(v) { v, #v }
static const value_string rdpdr_dr_ioControlCode_vals[] = {
	STR_VALUE(SCARD_IOCTL_ESTABLISHCONTEXT),
	STR_VALUE(SCARD_IOCTL_RELEASECONTEXT),
	STR_VALUE(SCARD_IOCTL_ISVALIDCONTEXT),
	STR_VALUE(SCARD_IOCTL_LISTREADERGROUPSA),
	STR_VALUE(SCARD_IOCTL_LISTREADERGROUPSW),
	STR_VALUE(SCARD_IOCTL_LISTREADERSA),
	STR_VALUE(SCARD_IOCTL_LISTREADERSW),
	STR_VALUE(SCARD_IOCTL_INTRODUCEREADERGROUPA),
	STR_VALUE(SCARD_IOCTL_INTRODUCEREADERGROUPW),
	STR_VALUE(SCARD_IOCTL_FORGETREADERGROUPA),
	STR_VALUE(SCARD_IOCTL_FORGETREADERGROUPW),
	STR_VALUE(SCARD_IOCTL_INTRODUCEREADERA),
	STR_VALUE(SCARD_IOCTL_INTRODUCEREADERW),
	STR_VALUE(SCARD_IOCTL_FORGETREADERA),
	STR_VALUE(SCARD_IOCTL_FORGETREADERW),
	STR_VALUE(SCARD_IOCTL_ADDREADERTOGROUPA),
	STR_VALUE(SCARD_IOCTL_ADDREADERTOGROUPW),
	STR_VALUE(SCARD_IOCTL_REMOVEREADERFROMGROUPA),
	STR_VALUE(SCARD_IOCTL_REMOVEREADERFROMGROUPW),
	STR_VALUE(SCARD_IOCTL_LOCATECARDSA),
	STR_VALUE(SCARD_IOCTL_LOCATECARDSW),
	STR_VALUE(SCARD_IOCTL_GETSTATUSCHANGEA),
	STR_VALUE(SCARD_IOCTL_GETSTATUSCHANGEW),
	STR_VALUE(SCARD_IOCTL_CANCEL),
	STR_VALUE(SCARD_IOCTL_CONNECTA),
	STR_VALUE(SCARD_IOCTL_CONNECTW),
	STR_VALUE(SCARD_IOCTL_RECONNECT),
	STR_VALUE(SCARD_IOCTL_DISCONNECT),
	STR_VALUE(SCARD_IOCTL_BEGINTRANSACTION),
	STR_VALUE(SCARD_IOCTL_ENDTRANSACTION),
	STR_VALUE(SCARD_IOCTL_STATE),
	STR_VALUE(SCARD_IOCTL_STATUSA),
	STR_VALUE(SCARD_IOCTL_STATUSW),
	STR_VALUE(SCARD_IOCTL_TRANSMIT),
	STR_VALUE(SCARD_IOCTL_CONTROL),
	STR_VALUE(SCARD_IOCTL_GETATTRIB),
	STR_VALUE(SCARD_IOCTL_SETATTRIB),
	STR_VALUE(SCARD_IOCTL_ACCESSSTARTEDEVENT),
	STR_VALUE(SCARD_IOCTL_LOCATECARDSBYATRA),
	STR_VALUE(SCARD_IOCTL_LOCATECARDSBYATRW),
	STR_VALUE(SCARD_IOCTL_READCACHEA),
	STR_VALUE(SCARD_IOCTL_READCACHEW),
	STR_VALUE(SCARD_IOCTL_WRITECACHEA),
	STR_VALUE(SCARD_IOCTL_WRITECACHEW),
	STR_VALUE(SCARD_IOCTL_GETTRANSMITCOUNT),
	STR_VALUE(SCARD_IOCTL_RELEASETARTEDEVENT),
	STR_VALUE(SCARD_IOCTL_GETREADERICON),
	STR_VALUE(SCARD_IOCTL_GETDEVICETYPEID),
	{ 0x0, NULL},
};

static const value_string rdpdr_printer_cacheEvent_vals[] = {
	STR_VALUE(RDPDR_ADD_PRINTER_EVENT),
	STR_VALUE(RDPDR_UPDATE_PRINTER_EVENT),
	STR_VALUE(RDPDR_DELETE_PRINTER_EVENT),
	STR_VALUE(RDPDR_RENAME_PRINTER_EVENT),
	{ 0x0, NULL},
};

#undef STR_VALUE

typedef struct {
	uint32_t completionId;
	uint32_t reqFrame;
	uint32_t resFrame;
	uint32_t majorFn;
	uint32_t minorFn;
	uint32_t ioControlCode;
} DrIoRequest;

typedef struct {
	uint32_t deviceType;
	uint32_t deviceId;
	char name[9];
	wmem_multimap_t *ioRequests;
} DrDevice;

typedef struct {
  wmem_multimap_t *channels;
} rdpdr_conv_info_t;

static unsigned idptr_hashFunc(const void *key) {
	uint32_t *intPtr = (uint32_t *)key;

	return *intPtr;
}

static gboolean idptr_equalFunc(const void *a, const void *b) {
	uint32_t *aPtr = (uint32_t *)a;
	uint32_t *bPtr = (uint32_t *)b;

	return (*aPtr == *bPtr);
}


static rdpdr_conv_info_t *
rdpdr_get_conversation_data(packet_info *pinfo)
{
	conversation_t *conversation, *conversation_tcp;
	rdpdr_conv_info_t *info;

	conversation = find_or_create_conversation(pinfo);

	info = (rdpdr_conv_info_t *)conversation_get_proto_data(conversation, proto_rdpdr);
	if (!info) {
		conversation_tcp = rdp_find_tcp_conversation_from_udp(conversation);
		if (conversation_tcp)
			info = (rdpdr_conv_info_t *)conversation_get_proto_data(conversation_tcp, proto_rdpdr);
	}

	if (info == NULL) {
		info = wmem_new0(wmem_file_scope(), rdpdr_conv_info_t);
		info->channels = wmem_multimap_new(wmem_file_scope(), idptr_hashFunc, idptr_equalFunc);
		conversation_add_proto_data(conversation, proto_rdpdr, info);
	}

	return info;
}

static int
dissect_smartcard_req(tvbuff_t *in_tvb, int in_offset, packet_info *pinfo, proto_tree *tree, uint32_t ioControlCode)
{
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s req", val_to_str_const(ioControlCode, rdpdr_dr_ioControlCode_vals, "<unknown>"));
	if (ioControlCode == SCARD_IOCTL_ACCESSSTARTEDEVENT)
		return in_offset + 4;

	dcerpc_info di = { 0 };
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00};

	dcerpc_call_value call_data = { 0 };
	di.conformant_run = 0;
	di.call_data = &call_data;
	init_ndr_pointer_list(&di);

	int offset = 16;
	tvbuff_t *tvb = tvb_new_subset_remaining(in_tvb, in_offset);

	switch (ioControlCode) {
	case SCARD_IOCTL_ESTABLISHCONTEXT:
		offset = scard_pack_dissect_struct_EstablishContext_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_ISVALIDCONTEXT:
	case SCARD_IOCTL_RELEASECONTEXT:
	case SCARD_IOCTL_CANCEL:
		offset = scard_pack_dissect_struct_Context_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_LISTREADERSA:
		offset = scard_pack_dissect_struct_ListReadersA_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_LISTREADERSW:
		offset = scard_pack_dissect_struct_ListReadersW_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETDEVICETYPEID:
		offset = scard_pack_dissect_struct_GetDeviceTypeId_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETSTATUSCHANGEA:
		offset = scard_pack_dissect_struct_GetStatusChangeA_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETSTATUSCHANGEW:
		offset = scard_pack_dissect_struct_GetStatusChangeW_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_CONNECTA:
		offset = scard_pack_dissect_struct_ConnectA_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_CONNECTW:
		offset = scard_pack_dissect_struct_ConnectW_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_DISCONNECT:
	case SCARD_IOCTL_BEGINTRANSACTION:
	case SCARD_IOCTL_ENDTRANSACTION:
		offset = scard_pack_dissect_struct_HCardAndDisposition_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_STATE:
		offset = scard_pack_dissect_struct_State_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_STATUSA:
	case SCARD_IOCTL_STATUSW:
		offset = scard_pack_dissect_struct_Status_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_TRANSMIT:
		offset = scard_pack_dissect_struct_Transmit_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_READCACHEA:
		offset = scard_pack_dissect_struct_ReadCacheA_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_READCACHEW:
		offset = scard_pack_dissect_struct_ReadCacheW_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_WRITECACHEA:
		offset = scard_pack_dissect_struct_WriteCacheA_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_WRITECACHEW:
		offset = scard_pack_dissect_struct_WriteCacheW_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETATTRIB:
		offset = scard_pack_dissect_struct_GetAttrib_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_RECONNECT:
		offset = scard_pack_dissect_struct_Reconnect_Call(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	default:
		return in_offset;
	}
	return in_offset + dissect_deferred_pointers(pinfo, tvb, offset, &di, drep);
}

static int
dissect_smartcard_resp(tvbuff_t *in_tvb, int in_offset, packet_info *pinfo, proto_tree *tree, uint32_t ioControlCode)
{
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s resp", val_to_str_const(ioControlCode, rdpdr_dr_ioControlCode_vals, "<unknown>"));

	dcerpc_info di = { 0 };
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00};

	dcerpc_call_value call_data = { 0 };
	di.conformant_run = 0;
	di.call_data = &call_data;
	init_ndr_pointer_list(&di);

	int offset = 16;
	proto_tree_add_item(tree, hf_rdpdr_ioreq_sc_returnCode, in_tvb, in_offset + 16, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	tvbuff_t *tvb = tvb_new_subset_remaining(in_tvb, in_offset);

	switch (ioControlCode) {
	case SCARD_IOCTL_ESTABLISHCONTEXT:
		offset = scard_pack_dissect_struct_EstablishContext_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_ACCESSSTARTEDEVENT:
	case SCARD_IOCTL_ISVALIDCONTEXT:
	case SCARD_IOCTL_RELEASECONTEXT:
	case SCARD_IOCTL_DISCONNECT:
	case SCARD_IOCTL_CANCEL:
	case SCARD_IOCTL_BEGINTRANSACTION:
	case SCARD_IOCTL_ENDTRANSACTION:
	case SCARD_IOCTL_WRITECACHEA:
	case SCARD_IOCTL_WRITECACHEW:
	case SCARD_IOCTL_SETATTRIB:
	case SCARD_IOCTL_INTRODUCEREADERGROUPA:
	case SCARD_IOCTL_INTRODUCEREADERGROUPW:
	case SCARD_IOCTL_FORGETREADERGROUPA:
	case SCARD_IOCTL_FORGETREADERGROUPW:
	case SCARD_IOCTL_INTRODUCEREADERA:
	case SCARD_IOCTL_INTRODUCEREADERW:
	case SCARD_IOCTL_FORGETREADERA:
	case SCARD_IOCTL_FORGETREADERW:
	case SCARD_IOCTL_ADDREADERTOGROUPA:
	case SCARD_IOCTL_ADDREADERTOGROUPW:
	case SCARD_IOCTL_REMOVEREADERFROMGROUPA:
	case SCARD_IOCTL_REMOVEREADERFROMGROUPW:
		offset = scard_pack_dissect_struct_long_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_LISTREADERSA:
	case SCARD_IOCTL_LISTREADERSW:
		offset = scard_pack_dissect_struct_ListReaders_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETDEVICETYPEID:
		offset = scard_pack_dissect_struct_GetDeviceTypeId_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETSTATUSCHANGEA:
	case SCARD_IOCTL_GETSTATUSCHANGEW:
		offset = scard_pack_dissect_struct_GetStatusChange_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_CONNECTA:
	case SCARD_IOCTL_CONNECTW:
		offset = scard_pack_dissect_struct_Connect_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_RECONNECT:
		offset = scard_pack_dissect_struct_Reconnect_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_STATUSA:
	case SCARD_IOCTL_STATUSW:
		offset = scard_pack_dissect_struct_Status_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_TRANSMIT:
		offset = scard_pack_dissect_struct_Transmit_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_READCACHEA:
	case SCARD_IOCTL_READCACHEW:
		offset = scard_pack_dissect_struct_ReadCache_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	case SCARD_IOCTL_GETATTRIB:
		offset = scard_pack_dissect_struct_GetAttrib_Return(tvb, offset, pinfo, tree, &di, drep, hf_rdpdr_ioreq_sc_command, 0);
		break;
	default:
		return in_offset;
	}

	return in_offset + dissect_deferred_pointers(pinfo, tvb, offset, &di, drep);
}


static int
dissect_rdpdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
{
	proto_item *item;
	int offset = 0;
	proto_tree *tree;
	//bool packetToServer = rdp_isServerAddressTarget(pinfo);

	parent_tree = proto_tree_get_root(parent_tree);
	item = proto_tree_add_item(parent_tree, proto_rdpdr, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdpdr);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPDR");
	col_clear(pinfo->cinfo, COL_INFO);

	uint32_t component, packetId;
	proto_tree_add_item_ret_uint(tree, hf_rdpdr_component, tvb, offset, 2, ENC_LITTLE_ENDIAN, &component);
	offset += 2;
	proto_tree_add_item_ret_uint(tree, hf_rdpdr_packetid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &packetId);
	offset += 2;

	rdpdr_conv_info_t *info = rdpdr_get_conversation_data(pinfo);
	uint32_t deviceId;

	if (component == RDPDR_CTYP_CORE) {
		switch(packetId) {
		case PAKID_CORE_SERVER_ANNOUNCE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Server announce");
			break;
		case PAKID_CORE_DEVICELIST_ANNOUNCE: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Device list announce");
			uint32_t deviceCount;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_deviceCount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceCount);
			offset += 4;

			for (uint32_t i = 0; i < deviceCount; i++) {
				uint32_t deviceDataLen = tvb_get_uint32(tvb, offset + 16, ENC_LITTLE_ENDIAN);
				char dosName[8];
				tvb_get_raw_bytes_as_string(tvb, offset + 8, dosName, 8);

				proto_tree *dev_tree = proto_tree_add_subtree(tree, tvb, offset, 16 + deviceDataLen, ett_rdpdr_device, NULL, dosName);

				uint32_t deviceType;
				proto_tree_add_item_ret_uint(dev_tree, hf_rdpdr_deviceType, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceType);
				offset += 4;
				proto_tree_add_item_ret_uint(dev_tree, hf_rdpdr_deviceId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceId);
				offset += 4;
				proto_tree_add_item(dev_tree, hf_rdpdr_dosName, tvb, offset, 8, ENC_ASCII);
				offset += 8;
				proto_tree_add_item(dev_tree, hf_rdpdr_deviceDataLen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(dev_tree, hf_rdpdr_deviceData, tvb, offset, deviceDataLen, ENC_NA);
				offset += deviceDataLen;

				if (!PINFO_FD_VISITED(pinfo)) {
					DrDevice *device = wmem_alloc(wmem_file_scope(), sizeof(*device));
					device->deviceId = deviceId;
					device->deviceType = deviceType;
					memcpy(device->name, dosName, 8);
					device->name[8] = 0;
					device->ioRequests = wmem_multimap_new(wmem_file_scope(), idptr_hashFunc, idptr_equalFunc);

					wmem_multimap_insert32(info->channels, &device->deviceId, pinfo->num, device);
				}
			}
			break;
		}
		case PAKID_CORE_DEVICE_IOREQUEST: {
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_deviceId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceId);
			offset += 4;

			DrDevice *device = wmem_multimap_lookup32_le(info->channels, &deviceId, pinfo->num);

			uint32_t dtype = RDPDR_DTYP_FILESYSTEM;
			if (device)
				dtype = device->deviceType;

			int majorFnIdx;
			int minorFnIdx;
			switch(dtype) {
			case RDPDR_DTYP_SMARTCARD:
				majorFnIdx = hf_rdpdr_ioreq_sc_majorFunction;
				minorFnIdx = hf_rdpdr_ioreq_sc_minorFunction;
				break;
			case RDPDR_DTYP_FILESYSTEM:
			default:
				majorFnIdx = hf_rdpdr_ioreq_dr_majorFunction;
				minorFnIdx = hf_rdpdr_ioreq_dr_minorFunction;
				break;
			}

			uint32_t fileId, completionId;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_fileId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fileId);
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_rdpdr_completionId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &completionId);
			offset += 4;

			uint32_t majorFn;
			proto_tree_add_item_ret_uint(tree, majorFnIdx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &majorFn);
			offset += 4;

			uint32_t minorFn;
			proto_tree_add_item_ret_uint(tree, minorFnIdx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &minorFn);
			offset += 4;

			DrIoRequest *ioReq = NULL;
			if (!PINFO_FD_VISITED(pinfo)) {
				if (device) {
					ioReq = wmem_alloc(wmem_file_scope(), sizeof(*ioReq));

					ioReq->completionId = completionId;
					ioReq->majorFn = majorFn;
					ioReq->minorFn = minorFn;
					ioReq->reqFrame = pinfo->num;
					ioReq->resFrame = 0;

					wmem_multimap_insert32(device->ioRequests, &ioReq->completionId, pinfo->num, ioReq);
				}
			} else {
				if (device)
					ioReq = wmem_multimap_lookup32_le(device->ioRequests, &completionId, pinfo->num);
			}

			switch(majorFn) {
			case IRP_MJ_CREATE:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_CREATE");
				break;
			case IRP_MJ_CLOSE:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_CLOSE");
				break;
			case IRP_MJ_READ:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_READ");
				break;
			case IRP_MJ_WRITE:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_WRITE");
				break;
			case IRP_MJ_DEVICE_CONTROL: {
				uint32_t inputBufLen;
				uint32_t ioControlCode;
				//col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_DEVICE_CONTROL");
				proto_tree_add_item(tree, hf_rdpdr_io_request_control_outputBufLen, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_io_request_control_inputBufLen, tvb, offset, 4, ENC_LITTLE_ENDIAN, &inputBufLen);
				offset += 4;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_io_request_control_ioControlCode, tvb, offset, 4, ENC_LITTLE_ENDIAN, &ioControlCode);
				offset += 4;

				proto_tree_add_item(tree, hf_rdpdr_io_request_control_padding, tvb, offset, 20, ENC_NA);
				offset += 20;

				if (!PINFO_FD_VISITED(pinfo) && ioReq)
					ioReq->ioControlCode = ioControlCode;

				if (device && device->deviceType == RDPDR_DTYP_SMARTCARD)
					dissect_smartcard_req(tvb, offset, pinfo, tree, ioControlCode);
				break;
			}
			case IRP_MJ_QUERY_VOLUME_INFORMATION:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_QUERY_VOLUME_INFORMATION");
				break;
			case IRP_MJ_SET_VOLUME_INFORMATION:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_SET_VOLUME_INFORMATION");
				break;
			case IRP_MJ_QUERY_INFORMATION:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_QUERY_INFORMATION");
				break;
			case IRP_MJ_SET_INFORMATION:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_SET_INFORMATION");
				break;
			case IRP_MJ_DIRECTORY_CONTROL:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_DIRECTORY_CONTROL");
				break;
			case IRP_MJ_LOCK_CONTROL:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_LOCK_CONTROL");
				break;
			default:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS unhandled");
				break;
			}

			if (ioReq) {
				if (ioReq->resFrame) {
					proto_item_set_generated(
						proto_tree_add_uint(tree, hf_rdpdr_io_result_frame, tvb, 0, 0, ioReq->resFrame)
					);
				}
			}
			break;
		}
		case PAKID_CORE_DEVICE_REPLY: {
			uint32_t statusCode;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_deviceId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceId);
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_rdpdr_resultCode, tvb, offset, 4, ENC_LITTLE_ENDIAN, &statusCode);
			offset += 4;

			DrDevice *device = wmem_multimap_lookup32_le(info->channels, &deviceId, pinfo->num);
			if (device)
				col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s, status=0x%x", device->name, statusCode);
			break;
		}
		case PAKID_CORE_DEVICE_IOCOMPLETION: {
			uint32_t statusCode, completionId;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_deviceId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceId);
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_rdpdr_completionId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &completionId);
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_rdpdr_ioStatus, tvb, offset, 4, ENC_LITTLE_ENDIAN, &statusCode);
			offset += 4;

			//const char *name = NULL;
			DrIoRequest *ioReq = NULL;
			DrDevice *device = wmem_multimap_lookup32_le(info->channels, &deviceId, pinfo->num);
			if (device) {
				//name = device->name;
				ioReq = wmem_multimap_lookup32_le(device->ioRequests, &completionId, pinfo->num);
				if (ioReq) {
					if (!PINFO_FD_VISITED(pinfo))
						ioReq->resFrame = pinfo->num;
				}
			}

			if (ioReq) {
				proto_item_set_generated(
					proto_tree_add_uint(tree, hf_rdpdr_io_request_frame, tvb, 0, 0, ioReq->reqFrame)
				);

				if (device->deviceType == RDPDR_DTYP_FILESYSTEM) {
					switch(ioReq->majorFn) {
					case IRP_MJ_CREATE:
						if (tvb_captured_length_remaining(tvb, offset)) {
							proto_tree_add_item(tree, hf_rdpdr_create_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						}
						break;
					}
				} else if (device->deviceType == RDPDR_DTYP_SMARTCARD) {
					if (ioReq->majorFn == IRP_MJ_DEVICE_CONTROL)
						return dissect_smartcard_resp(tvb, offset, pinfo, tree, ioReq->ioControlCode);
				}
			}
			//col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s%sIO completion completionId=0x%x status=0x%x", name ? name : "", name ? " " : "", completionId, statusCode);
			break;
		}

		case PAKID_CORE_CLIENT_CAPABILITY:
		case PAKID_CORE_SERVER_CAPABILITY: {
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s", val_to_str_const(packetId, rdpdr_packetid_vals, "<unknown command>"));

			uint32_t ncapa;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_numCapabilities, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ncapa);
			offset += 2;

			proto_tree_add_item(tree, hf_rdpdr_padding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;


			for (uint32_t i = 0; i < ncapa; i++) {
				uint32_t capaType = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
				uint32_t capaLen = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);


				tvbuff_t *capaTvb = tvb_new_subset_length(tvb, offset, capaLen);
				offset += capaLen;

				int subOffset = 0;
				proto_tree *subtree = proto_tree_add_subtree(tree, capaTvb, 0, capaLen, ett_rdpdr_capabilities, NULL, val_to_str_const(capaType, rdpdr_capaType_vals, "<unknown>"));
				proto_tree_add_item(subtree, hf_rdpdr_capaType, capaTvb, subOffset, 2, ENC_LITTLE_ENDIAN);
				subOffset += 2;

				proto_tree_add_item(subtree, hf_rdpdr_capaLen, capaTvb, subOffset, 2, ENC_LITTLE_ENDIAN);
				subOffset += 2;

				uint32_t capaVersion;
				proto_tree_add_item_ret_uint(subtree, hf_rdpdr_capaVersion, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN, &capaVersion);
				subOffset += 4;

				switch (capaType) {
				case CAP_GENERAL_TYPE:
					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_osType, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_osVersion, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_protocolMajor, capaTvb, subOffset, 2, ENC_LITTLE_ENDIAN);
					subOffset += 2;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_protocolMinor, capaTvb, subOffset, 2, ENC_LITTLE_ENDIAN);
					subOffset += 2;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_ioCode1, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_ioCode2, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_extendedPdu, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_extraFlags1, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					proto_tree_add_item(subtree, hf_rdpdr_capa_gen_extraFlags2, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					subOffset += 4;

					if (capaVersion == 0x00000002)
						proto_tree_add_item(subtree, hf_rdpdr_capa_gen_specialTypeDeviceCap, capaTvb, subOffset, 4, ENC_LITTLE_ENDIAN);
					break;

				case CAP_PRINTER_TYPE:
				case CAP_SMARTCARD_TYPE:
				case CAP_PORT_TYPE:
				case CAP_DRIVE_TYPE:
					break;
				}
			}
			break;
		}
		default:
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s", val_to_str_const(packetId, rdpdr_packetid_vals, "<unknown command>"));
			break;
		}
	} else if (component == RDPDR_CTYP_PRN) {
		switch (packetId) {
		case PAKID_PRN_USING_XPS: {
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_deviceId, tvb, offset, 4, ENC_LITTLE_ENDIAN, &deviceId);
			offset += 4;

			DrDevice *device = wmem_multimap_lookup32_le(info->channels, &deviceId, pinfo->num);
			if (device) {
				proto_item_set_generated(
					proto_tree_add_string(tree, hf_rdpdr_device_name, tvb, 0, 0, device->name)
				);

				col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "PAKID_PRN_USING_XPS %s", device->name);
			} else {
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "PAKID_PRN_USING_XPS");
			}
			break;
		}
		case PAKID_PRN_CACHE_DATA: {
			uint32_t eventId;
			proto_tree_add_item_ret_uint(tree, hf_rdpdr_printer_cacheEvent, tvb, offset, 4, ENC_LITTLE_ENDIAN, &eventId);
			offset += 4;

			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s", val_to_str_const(eventId, rdpdr_printer_cacheEvent_vals, "<unknown command>"));
			switch (eventId) {
			case RDPDR_ADD_PRINTER_EVENT: {
				uint32_t pnpNameLength, driveNameLength, printerNameLength, cachedFieldsLength;

				proto_tree_add_item(tree, hf_rdpdr_dosName, tvb, offset, 8, ENC_ASCII);
				offset += 8;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_pnpNameLength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pnpNameLength);
				offset += 4;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_driverNameLength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &driveNameLength);
				offset += 4;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_printerNameLength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &printerNameLength);
				offset += 4;

				proto_tree_add_item_ret_uint(tree, hf_rdpdr_cachedFieldsLength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &cachedFieldsLength);
				offset += 4;

				proto_tree_add_item(tree, hf_rdpdr_pnpName, tvb, offset, pnpNameLength, ENC_UTF_16|ENC_LITTLE_ENDIAN);
				offset += pnpNameLength;

				proto_tree_add_item(tree, hf_rdpdr_driverName, tvb, offset, driveNameLength, ENC_UTF_16|ENC_LITTLE_ENDIAN);
				offset += driveNameLength;

				proto_tree_add_item(tree, hf_rdpdr_printerName, tvb, offset, printerNameLength, ENC_UTF_16|ENC_LITTLE_ENDIAN);
				offset += printerNameLength;

				proto_tree_add_item(tree, hf_rdpdr_cachedFields, tvb, offset, cachedFieldsLength, ENC_NA);
				break;
			}
			case RDPDR_UPDATE_PRINTER_EVENT:
				break;
			case RDPDR_DELETE_PRINTER_EVENT:
				break;
			case RDPDR_RENAME_PRINTER_EVENT:
				break;
			default:
				break;
			}
			break;
		}
		default:
			break;
		}

	}

	return offset;
}


void proto_register_rdpdr(void) {
	static hf_register_info hf[] = {
		{ &hf_rdpdr_component,
		  { "Component", "rdpdr.component",
		    FT_UINT16, BASE_HEX, VALS(rdpdr_component_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_packetid,
		  { "PacketId", "rdpdr.packetid",
			FT_UINT16, BASE_HEX, VALS(rdpdr_packetid_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_deviceCount,
		  { "Device count", "rdpdr.devicecount",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_deviceType,
		  { "Device type", "rdpdr.devicetype",
			FT_UINT32, BASE_HEX, VALS(rdpdr_deviceType_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_deviceId,
		  { "Device id", "rdpdr.deviceid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_dosName,
		  { "DOS name", "rdpdr.dosname",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_deviceDataLen,
		  { "Device data length", "rdpdr.devicedatalen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_deviceData,
		  { "Device data", "rdpdr.devicedata",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_fileId,
		  { "File id", "rdpdr.fileid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_completionId,
		  { "Completion id", "rdpdr.completionid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_dr_majorFunction,
		  { "Major function", "rdpdr.majorfunction",
			FT_UINT32, BASE_HEX, VALS(rdpdr_dr_majorF_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_dr_minorFunction,
		  { "Minor function", "rdpdr.minorfunction",
			FT_UINT32, BASE_HEX, VALS(rdpdr_dr_minorF_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_sc_majorFunction,
		  { "Major function", "rdpdr.majorfunction",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_sc_minorFunction,
		  { "Minor function", "rdpdr.minorfunction",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_resultCode,
		  { "Result code", "rdpdr.resultcode",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioStatus,
		  { "IoStatus", "rdpdr.iostatus",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_request_control_outputBufLen,
		  { "OutputBufferLen", "rdpdr.outputbuflen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_request_control_inputBufLen,
		  { "InputBufferLen", "rdpdr.inputbuflen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_request_control_ioControlCode,
		  { "IoControlCode", "rdpdr.iocontrolcode",
			FT_UINT32, BASE_HEX, VALS(rdpdr_dr_ioControlCode_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_request_control_padding,
		  { "Padding", "rdpdr.padding20",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_request_frame,
		  { "Request in frame", "rdpdr.iorequestframe",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_io_result_frame,
		  { "IO result in frame", "rdpdr.ioresultframe",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_create_info,
		  { "Information", "rdpdr.dr.create.info",
			FT_UINT8, BASE_HEX, VALS(rdpdr_dr_createinfo_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_numCapabilities,
		  { "numCapabilities", "rdpdr.numcapabilities",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_padding,
		  { "Padding", "rdpdr.padding",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capaType,
		  { "Type", "rdpdr.capa.type",
			FT_UINT16, BASE_HEX, VALS(rdpdr_capaType_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capaLen,
		  { "Length", "rdpdr.capa.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capaVersion,
		  { "Version", "rdpdr.capa.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_osType,
		  { "osType", "rdpdr.capa.gen.ostype",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_osVersion,
		  { "osVersion", "rdpdr.capa.gen.osversion",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_protocolMajor,
		  { "protocolMajorVersion", "rdpdr.capa.gen.protocolmajor",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_protocolMinor,
		  { "protocolMinorVersion", "rdpdr.capa.gen.protocolminor",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_ioCode1,
		  { "ioCode1", "rdpdr.capa.gen.iocode1",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_ioCode2,
		  { "ioCode2", "rdpdr.capa.gen.iocode2",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_extendedPdu,
		  { "extendedPDU", "rdpdr.capa.gen.extendedpdu",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_extraFlags1,
		  { "extraFlags1", "rdpdr.capa.gen.extraflags1",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_extraFlags2,
		  { "extraFlags2", "rdpdr.capa.gen.extraflags2",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_capa_gen_specialTypeDeviceCap,
		  { "specialTypeDeviceCap", "rdpdr.capa.gen.specialtypedevicecap",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_sc_command,
		  { "Command", "rdpdr.sc.command",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_ioreq_sc_returnCode,
		  { "ReturnCode", "rdpdr.sc.returnCode",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_rdpdr_device_name,
		  { "Device", "rdpdr.device",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_printer_cacheEvent,
		  { "EventId", "rdpdr.printer.eventid",
			FT_UINT32, BASE_HEX, VALS(rdpdr_printer_cacheEvent_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_pnpNameLength,
		  { "PnPNameLen", "rdpdr.printer.pnpnamelen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_pnpName,
		  { "PnPName", "rdpdr.printer.pnpname",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_driverNameLength,
		  { "DriverNameLen", "rdpdr.printer.drivernamelen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_driverName,
		  { "DriverName", "rdpdr.printer.drivername",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_printerNameLength,
		  { "PrintNameLen", "rdpdr.printer.printnamelen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_printerName,
		  { "PrinterName", "rdpdr.printer.printername",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_cachedFieldsLength,
		  { "CacheFieldsLen", "rdpdr.printer.cachefieldslen",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rdpdr_cachedFields,
		  { "CacheFields", "rdpdr.printer.cachefields",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rdpdr,
		&ett_rdpdr_device,
		&ett_rdpdr_capabilities,
	};

	proto_rdpdr = proto_register_protocol("RDP disk redirection virtual channel Protocol", "RDPDR", "rdpdr");

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdpdr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdpdr", dissect_rdpdr, proto_rdpdr);
}

void proto_reg_handoff_rdpdr(void) {
}

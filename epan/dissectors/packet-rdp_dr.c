/* Packet-rdp_dr.c
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

#define PNAME  "RDP disk redirection virtual channel Protocol"
#define PSNAME "RDPDR"
#define PFNAME "rdpdr"

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
static int hf_rdpdr_fileId;
static int hf_rdpdr_completionId;
static int hf_rdpdr_ioreq_dr_majorFunction;
static int hf_rdpdr_ioreq_dr_minorFunction;
static int hf_rdpdr_ioreq_sc_majorFunction;
static int hf_rdpdr_ioreq_sc_minorFunction;
static int hf_rdpdr_resultCode;
static int hf_rdpdr_ioStatus;
static int hf_rdpdr_io_request_frame;
static int hf_rdpdr_io_result_frame;
static int hf_rdpdr_create_info;


static int ett_rdpdr;
static int ett_rdpdr_device;

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

typedef struct {
	uint32_t completionId;
	uint32_t reqFrame;
	uint32_t resFrame;
	uint32_t majorFn;
	uint32_t minorFn;
} DrIoRequest;

typedef struct {
	uint32_t deviceType;
	uint32_t deviceId;
	char name[8];
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
dissect_rdpdr(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
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
			col_set_str(pinfo->cinfo, COL_INFO, "Server announce");
			break;
		case PAKID_CORE_DEVICELIST_ANNOUNCE: {
			col_set_str(pinfo->cinfo, COL_INFO, "Device list announce");
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

			switch (dtype) {
			case RDPDR_DTYP_SMARTCARD:
				col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "SMARTCARD Fn");
				break;
			case RDPDR_DTYP_FILESYSTEM:
			default:
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
				case IRP_MJ_DEVICE_CONTROL:
					col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FS IRP_MJ_DEVICE_CONTROL");
					break;
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
				break;
			}

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

			const char *name = NULL;
			DrIoRequest *ioReq = NULL;
			DrDevice *device = wmem_multimap_lookup32_le(info->channels, &deviceId, pinfo->num);
			if (device) {
				name = device->name;
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
				}
			}
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s%sIO completion completionId=0x%x status=0x%x", name ? name : "", name ? " " : "", completionId, statusCode);
			break;
		}

		default:
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, ",", "%s", val_to_str_const(packetId, rdpdr_packetid_vals, "<unknown command>"));
			break;
		}
	} else if (component == RDPDR_CTYP_PRN) {

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

	};

	static int *ett[] = {
		&ett_rdpdr,
		&ett_rdpdr_device,
	};

	proto_rdpdr = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdpdr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector(PFNAME, dissect_rdpdr, proto_rdpdr);
}

void proto_reg_handoff_rdpdr(void) {
}

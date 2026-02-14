/* Packet-rdp_conctrl.c
 * Routines for the CONCTRL RDP channel
 * Copyright 2025, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

void proto_register_rdp_ecam(void);
void proto_reg_handoff_rdp_ecam(void);

static int proto_rdp_ecam;

static int hf_ecam_version;
static int hf_ecam_messageId;
static int hf_ecam_errorCode;
static int hf_ecam_streamIndex;
static int hf_ecam_stream_frameSource;
static int hf_ecam_stream_category;
static int hf_ecam_stream_selected;
static int hf_ecam_stream_canBeShared;
static int hf_ecam_media_format;
static int hf_ecam_media_width;
static int hf_ecam_media_height;
static int hf_ecam_media_framerate_numerator;
static int hf_ecam_media_framerate_denominator;
static int hf_ecam_media_aspect_ratio_numerator;
static int hf_ecam_media_aspect_ratio_denominator;
static int hf_ecam_media_flags;

static int ett_rdp_ecam;
static int ett_rdp_ecam_stream_descr;
static int ett_rdp_ecam_media_descr;

enum {
	CAM_MSG_ID_SuccessResponse = 0x01,
	CAM_MSG_ID_ErrorResponse = 0x02,
	CAM_MSG_ID_SelectVersionRequest = 0x03,
	CAM_MSG_ID_SelectVersionResponse = 0x04,
	CAM_MSG_ID_DeviceAddedNotification = 0x05,
	CAM_MSG_ID_DeviceRemovedNotification = 0x06,
	CAM_MSG_ID_ActivateDeviceRequest = 0x07,
	CAM_MSG_ID_DeactivateDeviceRequest = 0x08,
	CAM_MSG_ID_StreamListRequest = 0x09,
	CAM_MSG_ID_StreamListResponse = 0x0A,
	CAM_MSG_ID_MediaTypeListRequest = 0x0B,
	CAM_MSG_ID_MediaTypeListResponse = 0x0C,
	CAM_MSG_ID_CurrentMediaTypeRequest = 0x0D,
	CAM_MSG_ID_CurrentMediaTypeResponse = 0x0E,
	CAM_MSG_ID_StartStreamsRequest = 0x0F,
	CAM_MSG_ID_StopStreamsRequest = 0x10,
	CAM_MSG_ID_SampleRequest = 0x11,
	CAM_MSG_ID_SampleResponse = 0x12,
	CAM_MSG_ID_SampleErrorResponse = 0x13,
	CAM_MSG_ID_PropertyListRequest = 0x14,
	CAM_MSG_ID_PropertyListResponse = 0x15,
	CAM_MSG_ID_PropertyValueRequest = 0x16,
	CAM_MSG_ID_PropertyValueResponse = 0x17,
	CAM_MSG_ID_SetPropertyValueRequest = 0x18,
};

static const value_string ecam_message_vals[] = {
	{ CAM_MSG_ID_SuccessResponse, "SuccessResponse" },
	{ CAM_MSG_ID_ErrorResponse, "ErrorResponse" },
	{ CAM_MSG_ID_SelectVersionRequest, "SelectVersion" },
	{ CAM_MSG_ID_SelectVersionResponse, "SelectVersionResponse" },
	{ CAM_MSG_ID_DeviceAddedNotification, "DeviceAddedNotification" },
	{ CAM_MSG_ID_DeviceRemovedNotification, "DeviceRemovedNotification" },
	{ CAM_MSG_ID_ActivateDeviceRequest, "ActivateDeviceRequest" },
	{ CAM_MSG_ID_DeactivateDeviceRequest, "DeactivateDeviceRequest" },
	{ CAM_MSG_ID_StreamListRequest, "StreamListRequest" },
	{ CAM_MSG_ID_StreamListResponse, "StreamListResponse" },
	{ CAM_MSG_ID_MediaTypeListRequest, "MediaTypeListRequest" },
	{ CAM_MSG_ID_MediaTypeListResponse, "MediaTypeListResponse" },
	{ CAM_MSG_ID_CurrentMediaTypeRequest, "CurrentMediaTypeRequest" },
	{ CAM_MSG_ID_CurrentMediaTypeResponse, "CurrentMediaTypeResponse" },
	{ CAM_MSG_ID_StartStreamsRequest, "StartStreamsRequest" },
	{ CAM_MSG_ID_StopStreamsRequest, "StopStreamsRequest" },
	{ CAM_MSG_ID_SampleRequest, "SampleRequest" },
	{ CAM_MSG_ID_SampleResponse, "SampleResponse" },
	{ CAM_MSG_ID_SampleErrorResponse, "SampleErrorResponse" },
	{ CAM_MSG_ID_PropertyListRequest, "PropertyListRequest" },
	{ CAM_MSG_ID_PropertyListResponse, "PropertyListResponse" },
	{ CAM_MSG_ID_PropertyValueRequest, "PropertyValueRequest" },
	{ CAM_MSG_ID_PropertyValueResponse, "PropertyValueResponse" },
	{ CAM_MSG_ID_SetPropertyValueRequest, "SetPropertyValueRequest" },
	{ 0x0, NULL},
};

enum {
	CAM_ERROR_CODE_UnexpectedError = 0x00000001,
	CAM_ERROR_CODE_InvalidMessage = 0x00000002,
	CAM_ERROR_CODE_NotInitialized = 0x00000003,
	CAM_ERROR_CODE_InvalidRequest = 0x00000004,
	CAM_ERROR_CODE_InvalidStreamNumber = 0x00000005,
	CAM_ERROR_CODE_InvalidMediaType = 0x00000006,
	CAM_ERROR_CODE_OutOfMemory = 0x00000007,
	CAM_ERROR_CODE_ItemNotFound = 0x00000008,
	CAM_ERROR_CODE_SetNotFound = 0x00000009,
	CAM_ERROR_CODE_OperationNotSupported = 0x0000000A,
};

static const value_string ecam_error_vals[] = {
	{ CAM_ERROR_CODE_UnexpectedError, "SuccessResponse" },
	{ CAM_ERROR_CODE_InvalidMessage, "InvalidMessage" },
	{ CAM_ERROR_CODE_NotInitialized, "NotInitialized" },
	{ CAM_ERROR_CODE_InvalidRequest, "InvalidRequest" },
	{ CAM_ERROR_CODE_InvalidStreamNumber, "InvalidStreamNumber" },
	{ CAM_ERROR_CODE_InvalidMediaType, "InvalidMediaType" },
	{ CAM_ERROR_CODE_OutOfMemory, "OutOfMemory" },
	{ CAM_ERROR_CODE_ItemNotFound, "ItemNotFound" },
	{ CAM_ERROR_CODE_SetNotFound, "SetNotFound" },
	{ CAM_ERROR_CODE_OperationNotSupported, "OperationNotSupported" },
	{ 0x0, NULL},
};


static const value_string ecam_formats_vals[] = {
	{ 0x01, "H264" },
	{ 0x02, "MJPG" },
	{ 0x03, "YUY2" },
	{ 0x04, "NV12" },
	{ 0x05, "I420" },
	{ 0x06, "RGB24" },
	{ 0x07, "RGB32" },
	{ 0x0, NULL},
};

static int
dissect_stream_description(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ecam_stream_frameSource, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_ecam_stream_category, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset ++;

	proto_tree_add_item(tree, hf_ecam_stream_selected, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset ++;

	proto_tree_add_item(tree, hf_ecam_stream_canBeShared, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset ++;

	return offset;
}

static int
dissect_media_descriptor(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ecam_media_format, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_ecam_media_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_framerate_numerator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_framerate_denominator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_aspect_ratio_numerator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_aspect_ratio_denominator, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_ecam_media_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	return offset;
}

static int
dissect_rdp_ecam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
{
	int offset = 0;
	//bool packetToServer = rdp_isServerAddressTarget(pinfo);

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPECAM");

	proto_item *item = proto_tree_add_item(parent_tree, proto_rdp_ecam, tvb, 0, 0, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_rdp_ecam);

	proto_tree_add_item(tree, hf_ecam_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	uint32_t cmdId;
	proto_tree_add_item_ret_uint(tree, hf_ecam_messageId, tvb, offset, 1, ENC_LITTLE_ENDIAN, &cmdId);
	offset += 1;

	col_append_sep_str(pinfo->cinfo, COL_INFO, ",", val_to_str_const(cmdId, ecam_message_vals, "<unknown message>"));
	switch (cmdId) {
	case CAM_MSG_ID_SuccessResponse:
	case CAM_MSG_ID_ActivateDeviceRequest:
	case CAM_MSG_ID_DeactivateDeviceRequest:
	case CAM_MSG_ID_StreamListRequest:
	case CAM_MSG_ID_PropertyListRequest:
		break;
	case CAM_MSG_ID_ErrorResponse:
		proto_tree_add_item(tree, hf_ecam_errorCode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;

	case CAM_MSG_ID_MediaTypeListRequest:
	case CAM_MSG_ID_CurrentMediaTypeRequest:
	case CAM_MSG_ID_SampleRequest:
		proto_tree_add_item(tree, hf_ecam_streamIndex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;

	case CAM_MSG_ID_SelectVersionRequest:
	case CAM_MSG_ID_SelectVersionResponse:
	case CAM_MSG_ID_DeviceAddedNotification:
	case CAM_MSG_ID_DeviceRemovedNotification:
	case CAM_MSG_ID_StreamListResponse:
		while (tvb_captured_length_remaining(tvb, offset) >= 5)
		{
			proto_tree *stream_tree = proto_tree_add_subtree(tree, tvb, offset, 5, ett_rdp_ecam_stream_descr, NULL, "StreamDescription");

			offset = dissect_stream_description(tvb, offset, stream_tree);
		}
		break;
	case CAM_MSG_ID_MediaTypeListResponse:
		while (tvb_captured_length_remaining(tvb, offset) >= 26)
		{
			proto_tree *media_tree = proto_tree_add_subtree(tree, tvb, offset, 5, ett_rdp_ecam_media_descr, NULL, "MediaDescription");

			offset = dissect_media_descriptor(tvb, offset, media_tree);
		}
		break;
	case CAM_MSG_ID_CurrentMediaTypeResponse:
		offset = dissect_media_descriptor(tvb, offset, tree);
		break;
	case CAM_MSG_ID_StartStreamsRequest:
		proto_tree_add_item(tree, hf_ecam_streamIndex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		offset = dissect_media_descriptor(tvb, offset, tree);
		break;
	case CAM_MSG_ID_StopStreamsRequest:
		break;
	case CAM_MSG_ID_SampleResponse:
		proto_tree_add_item(tree, hf_ecam_streamIndex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case CAM_MSG_ID_SampleErrorResponse:
	case CAM_MSG_ID_PropertyListResponse:
	case CAM_MSG_ID_PropertyValueRequest:
	case CAM_MSG_ID_PropertyValueResponse:
	case CAM_MSG_ID_SetPropertyValueRequest:
	default:
		break;
	}

	return offset;
}

void proto_register_rdp_ecam(void) {
	static hf_register_info hf[] = {
		{ &hf_ecam_version,
		  { "Version", "rdp_ecam.version",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_messageId,
		  { "MessageId", "rdp_ecam.messageid",
			FT_UINT8, BASE_HEX, VALS(ecam_message_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_errorCode,
		  { "Error code", "rdp_ecam.errorcode",
			FT_UINT32, BASE_HEX, VALS(ecam_error_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_streamIndex,
		  { "Stream index", "rdp_ecam.streamindex",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_format,
		  { "Format", "rdp_ecam.media.format",
			FT_UINT8, BASE_HEX, VALS(ecam_formats_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_width,
		  { "Width", "rdp_ecam.media.width",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_height,
		  { "Height", "rdp_ecam.media.height",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_framerate_numerator,
		  { "Framerate numerator", "rdp_ecam.media.frameratenumerator",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_framerate_denominator,
		  { "Framerate denominator", "rdp_ecam.media.frameratedenominator",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_aspect_ratio_numerator,
		  { "Aspect ratio numerator", "rdp_ecam.media.aspectrationumerator",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_aspect_ratio_denominator,
		  { "Aspect ratio denominator", "rdp_ecam.media.aspectratiodenominator",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_media_flags,
		  { "Flags", "rdp_ecam.media.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_stream_frameSource,
		  { "FrameSourceTypes", "rdp_ecam.stream.sourcetypes",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_stream_category,
		  { "StreamCategory", "rdp_ecam.stream.category",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_stream_selected,
		  { "Selected", "rdp_ecam.stream.selected",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ecam_stream_canBeShared,
		  { "CanBeShared", "rdp_ecam.stream.canbeshared",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rdp_ecam,
		&ett_rdp_ecam_stream_descr,
		&ett_rdp_ecam_media_descr,
	};


	proto_rdp_ecam = proto_register_protocol("RDP Video Capture Virtual Channel Extension", "RDPECAM", "rdp_ecam");

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_ecam, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_ecam", dissect_rdp_ecam, proto_rdp_ecam);
}

void proto_reg_handoff_rdp_ecam(void) {
}

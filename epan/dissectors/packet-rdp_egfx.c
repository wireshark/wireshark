/* Packet-rdp_egfx.c
 * Routines for the EGFX RDP channel
 * Copyright 2021, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPEGFX] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/tvbuff_rdp.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

void proto_register_rdp_egfx(void);
void proto_reg_handoff_rdp_egfx(void);

static int proto_rdp_egfx = -1;

static int hf_egfx_cmdId = -1;
static int hf_egfx_flags = -1;
static int hf_egfx_pduLength = -1;

static int hf_egfx_caps_capsSetCount = -1;
static int hf_egfx_cap_version = -1;
static int hf_egfx_cap_length = -1;

static int hf_egfx_reset_width = -1;
static int hf_egfx_reset_height = -1;
static int hf_egfx_reset_monitorCount = -1;
static int hf_egfx_reset_monitorDefLeft = -1;
static int hf_egfx_reset_monitorDefTop = -1;
static int hf_egfx_reset_monitorDefRight = -1;
static int hf_egfx_reset_monitorDefBottom = -1;
static int hf_egfx_reset_monitorDefFlags = -1;


static int hf_egfx_ack_queue_depth = -1;
static int hf_egfx_ack_frame_id = -1;
static int hf_egfx_ack_total_decoded = -1;

static int hf_egfx_ackqoe_frame_id = -1;
static int hf_egfx_ackqoe_timestamp = -1;
static int hf_egfx_ackqoe_timediffse = -1;
static int hf_egfx_ackqoe_timediffedr = -1;

static int hf_egfx_start_timestamp = -1;
static int hf_egfx_start_frameid = -1;
static int hf_egfx_end_frameid = -1;


static int ett_rdp_egfx = -1;
static int ett_egfx_caps = -1;
static int ett_egfx_capsconfirm = -1;
static int ett_egfx_cap = -1;
static int ett_egfx_ack = -1;
static int ett_egfx_ackqoe = -1;
static int ett_egfx_reset = -1;
static int ett_egfx_monitors = -1;
static int ett_egfx_monitordef = -1;


static expert_field ei_egfx_pdulen_invalid = EI_INIT;
static expert_field ei_egfx_invalid_compression = EI_INIT;


#define PNAME  "RDP Graphic pipeline channel Protocol"
#define PSNAME "EGFX"
#define PFNAME "rdp_egfx"

enum {
	RDPGFX_CMDID_WIRETOSURFACE_1 		= 0x0001,
	RDPGFX_CMDID_WIRETOSURFACE_2 		= 0x0002,
	RDPGFX_CMDID_DELETEENCODINGCONTEXT 	= 0x0003,
	RDPGFX_CMDID_SOLIDFILL 				= 0x0004,
	RDPGFX_CMDID_SURFACETOSURFACE 		= 0x0005,
	RDPGFX_CMDID_SURFACETOCACHE 		= 0x0006,
	RDPGFX_CMDID_CACHETOSURFACE 		= 0x0007,
	RDPGFX_CMDID_EVICTCACHEENTRY 		= 0x0008,
	RDPGFX_CMDID_CREATESURFACE 			= 0x0009,
	RDPGFX_CMDID_DELETESURFACE 			= 0x000a,
	RDPGFX_CMDID_STARTFRAME 			= 0x000b,
	RDPGFX_CMDID_ENDFRAME 				= 0x000c,
	RDPGFX_CMDID_FRAMEACKNOWLEDGE 		= 0x000d,
	RDPGFX_CMDID_RESETGRAPHICS 			= 0x000e,
	RDPGFX_CMDID_MAPSURFACETOOUTPUT 	= 0x000f,
	RDPGFX_CMDID_CACHEIMPORTOFFER 		= 0x0010,
	RDPGFX_CMDID_CACHEIMPORTREPLY 		= 0x0011,
	RDPGFX_CMDID_CAPSADVERTISE 			= 0x0012,
	RDPGFX_CMDID_CAPSCONFIRM 			= 0x0013,
	RDPGFX_CMDID_MAPSURFACETOWINDOW 	= 0x0015,
	RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE 	= 0x0016,
	RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT = 0x0017,
	RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW = 0x0018,
};

enum {
	RDPGFX_CAPVERSION_8 = 0x00080004,
	RDPGFX_CAPVERSION_81 = 0x00080105,
	RDPGFX_CAPVERSION_101 = 0x000A0100,
	RDPGFX_CAPVERSION_102 = 0x000A0200,
	RDPGFX_CAPVERSION_103 = 0x000A0301,
	RDPGFX_CAPVERSION_104 = 0x000A0400,
	RDPGFX_CAPVERSION_105 = 0x000A0502,
	RDPGFX_CAPVERSION_106 = 0x000A0600
};

static const value_string rdp_egfx_cmd_vals[] = {
	{ RDPGFX_CMDID_WIRETOSURFACE_1, "Wire to surface 1" },
	{ RDPGFX_CMDID_WIRETOSURFACE_2, "Wire to surface 2" },
	{ RDPGFX_CMDID_DELETEENCODINGCONTEXT, "delete encoding context" },
	{ RDPGFX_CMDID_SOLIDFILL, "Solid fill" },
	{ RDPGFX_CMDID_SURFACETOSURFACE, "Surface to surface" },
	{ RDPGFX_CMDID_SURFACETOCACHE, "Surface to cache" },
	{ RDPGFX_CMDID_CACHETOSURFACE, "Cache to surface" },
	{ RDPGFX_CMDID_EVICTCACHEENTRY, "Evict cache entry" },
	{ RDPGFX_CMDID_CREATESURFACE, "Create surface" },
	{ RDPGFX_CMDID_DELETESURFACE, "Delete surface" },
	{ RDPGFX_CMDID_STARTFRAME, "Start frame" },
	{ RDPGFX_CMDID_ENDFRAME, "End frame" },
	{ RDPGFX_CMDID_FRAMEACKNOWLEDGE, "Frame acknowlegde" },
	{ RDPGFX_CMDID_RESETGRAPHICS, "Reset graphics" },
	{ RDPGFX_CMDID_MAPSURFACETOOUTPUT, "Map Surface to output" },
	{ RDPGFX_CMDID_CACHEIMPORTOFFER, "Cache import offer" },
	{ RDPGFX_CMDID_CACHEIMPORTREPLY, "Cache import reply" },
	{ RDPGFX_CMDID_CAPSADVERTISE, "Caps advertise" },
	{ RDPGFX_CMDID_CAPSCONFIRM, "Caps confirm" },
	{ RDPGFX_CMDID_MAPSURFACETOWINDOW, "Map surface to window" },
	{ RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE, "Qoe frame acknowlegde" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, "Map surface to scaled output" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, "Map surface to scaled window" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_caps_version_vals[] = {
	{ RDPGFX_CAPVERSION_8, "8" },
	{ RDPGFX_CAPVERSION_81, "8.1" } ,
	{ RDPGFX_CAPVERSION_101, "10.1" },
	{ RDPGFX_CAPVERSION_102, "10.2" },
	{ RDPGFX_CAPVERSION_103, "10.3" },
	{ RDPGFX_CAPVERSION_104, "10.4" },
	{ RDPGFX_CAPVERSION_105, "10.5" },
	{ RDPGFX_CAPVERSION_106, "10.6" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_monitor_flags_vals[] = {
	{ 0x00000000, "is secondary" },
	{ 0x00000001, "is primary" },
	{ 0x0, NULL },
};


typedef struct {
	zgfx_context_t *zgfx;
} egfx_conv_info_t;


static egfx_conv_info_t *
egfx_get_conversation_data(packet_info *pinfo)
{
	conversation_t  *conversation, *conversation_tcp;
	egfx_conv_info_t *info;

	conversation = find_or_create_conversation(pinfo);

	info = (egfx_conv_info_t *)conversation_get_proto_data(conversation, proto_rdp_egfx);
	if (!info) {
		conversation_tcp = rdp_find_tcp_conversation_from_udp(conversation);
		if (conversation_tcp)
			info = (egfx_conv_info_t *)conversation_get_proto_data(conversation_tcp, proto_rdp_egfx);
	}

	if (info == NULL) {
		info = wmem_new0(wmem_file_scope(), egfx_conv_info_t);
		info->zgfx = zgfx_context_new(wmem_file_scope());
		conversation_add_proto_data(conversation, proto_rdp_egfx, info);
	}

	return info;
}


static int
dissect_rdp_egfx_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree;
	proto_tree *subtree;
	gint offset = 0;
	guint16 cmdId = 0;
	guint32 pduLength;
	guint32 i;


	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_captured_length_remaining(tvb, offset) > 8) {
		pduLength = tvb_get_guint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);

		item = proto_tree_add_item(parent_tree, proto_rdp_egfx, tvb, offset, pduLength, ENC_NA);
		tree = proto_item_add_subtree(item, ett_rdp_egfx);

		cmdId = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_egfx_cmdId, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_pduLength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (pduLength < 8) {
			expert_add_info_format(pinfo, item, &ei_egfx_pdulen_invalid, "pduLength is %u, not < 8", pduLength);
			return offset;
		}

		switch (cmdId) {
		case RDPGFX_CMDID_CAPSADVERTISE: {
			guint16 capsSetCount = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps advertise");
			proto_tree_add_item(tree, hf_egfx_caps_capsSetCount, tvb, offset, 2, ENC_LITTLE_ENDIAN);

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_caps, NULL, "Caps");
			offset += 2;

			for (i = 0; i < capsSetCount; i++) {
				guint32 capsDataLength;

				proto_tree_add_item(subtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(subtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				capsDataLength = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
				offset += 4;

				offset += capsDataLength;
			}
			break;
		}

		case RDPGFX_CMDID_CAPSCONFIRM: {
			guint32 capsDataLength;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps confirm");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_capsconfirm, NULL, "Caps confirm");
			proto_tree_add_item(subtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &capsDataLength);
			offset += 4 + capsDataLength;
			break;
		}

		case RDPGFX_CMDID_RESETGRAPHICS: {
			guint32 nmonitor;
			proto_tree *monitors_tree;
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Reset graphics");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-4, ett_egfx_reset, NULL, "Reset graphics");
			proto_tree_add_item(subtree, hf_egfx_reset_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_reset_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_reset_monitorCount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nmonitor);
			offset += 4;

			monitors_tree = proto_tree_add_subtree(subtree, tvb, offset, nmonitor * 20, ett_egfx_monitors, NULL, "Monitors");
			for (i = 0; i < nmonitor; i++) {
				proto_item *monitor_tree;
				guint32 left, top, right, bottom;
				left = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
				top = tvb_get_guint32(tvb, offset+4, ENC_LITTLE_ENDIAN);
				right = tvb_get_guint32(tvb, offset+8, ENC_LITTLE_ENDIAN);
				bottom = tvb_get_guint32(tvb, offset+12, ENC_LITTLE_ENDIAN);

				monitor_tree = proto_tree_add_subtree_format(monitors_tree, tvb, offset, 20, ett_egfx_monitordef, NULL,
						"(%d,%d) - (%d,%d)", left, top, right, bottom);

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefLeft, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefTop, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefRight, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefBottom, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(monitor_tree, hf_egfx_reset_monitorDefFlags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}

			offset += (pduLength - 8);
			break;
		}

		case RDPGFX_CMDID_STARTFRAME: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Start frame");
			proto_tree_add_item(tree, hf_egfx_start_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			// TODO: dissect timestamp
			offset += 4;

			proto_tree_add_item(tree, hf_egfx_start_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;
		}

		case RDPGFX_CMDID_ENDFRAME:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "End frame");
			proto_tree_add_item(tree, hf_egfx_end_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;

		case RDPGFX_CMDID_FRAMEACKNOWLEDGE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ack, NULL, "Frame acknowledge");
			proto_tree_add_item(subtree, hf_egfx_ack_queue_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ack_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ack_total_decoded, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			break;

		case RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge QoE");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ackqoe, NULL, "Frame acknowledge QoE");
			proto_tree_add_item(subtree, hf_egfx_ackqoe_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffse, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffedr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			break;

		default:
			offset += (pduLength - 8);
			break;
		}
	}
	return offset;
}

static int
dissect_rdp_egfx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	tvbuff_t *work_tvb = tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	parent_tree = proto_tree_get_root(parent_tree);

	if (!rdp_isServerAddressTarget(pinfo)) {
		egfx_conv_info_t *infos = egfx_get_conversation_data(pinfo);
		work_tvb = rdp8_decompress(infos->zgfx, wmem_packet_scope(), tvb, 0);
		if (!work_tvb && parent_tree) {
			expert_add_info_format(pinfo, parent_tree->last_child, &ei_egfx_invalid_compression, "invalid compression");
			return 0;
		}
		add_new_data_source(pinfo, work_tvb, "Uncompressed GFX");
	}

	dissect_rdp_egfx_payload(work_tvb, pinfo, parent_tree, data);
	return tvb_reported_length(tvb);
}


void proto_register_rdp_egfx(void) {
	static hf_register_info hf[] = {
		{ &hf_egfx_cmdId,
		  { "CmdId", "rdp_egfx.cmdid",
		    FT_UINT16, BASE_HEX, VALS(rdp_egfx_cmd_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_flags,
		  { "flags", "rdp_egfx.flags",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_pduLength,
		  { "pduLength", "rdp_egfx.pdulength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_caps_capsSetCount,
		  { "capsSetCount", "rdp_egfx.caps.setcount",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_version,
		  { "Version", "rdp_egfx.cap.version",
			FT_UINT32, BASE_HEX, VALS(rdp_egfx_caps_version_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_length,
		  { "capsDataLength", "rdp_egfx.cap.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_queue_depth,
		  { "queueDepth", "rdp_egfx.ack.queuedepth",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_frame_id,
		  { "frameId", "rdp_egfx.ack.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_total_decoded,
		  { "Total frames decoded", "rdp_egfx.ack.totalframesdecoded",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_frame_id,
		  { "frameId", "rdp_egfx.ackqoe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timestamp,
		  { "Timestamp", "rdp_egfx.ackqoe.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timediffse,
		  { "TimeDiffSE", "rdp_egfx.ackqoe.timediffse",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_timediffedr,
		  { "TimeDiffEDR", "rdp_egfx.ackqoe.timediffedr",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_width,
		  { "Width", "rdp_egfx.reset.width",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_height,
		  { "Height", "rdp_egfx.reset.height",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorCount,
		  { "Monitor count", "rdp_egfx.reset.monitorcount",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefLeft,
		  { "Left", "rdp_egfx.monitor.left",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefTop,
		  { "Top", "rdp_egfx.monitor.top",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefRight,
		  { "Right", "rdp_egfx.monitor.right",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefBottom,
		  { "Bottom", "rdp_egfx.monitor.bottom",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_reset_monitorDefFlags,
		  { "Flags", "rdp_egfx.monitor.flags",
			FT_UINT32, BASE_DEC, VALS(rdp_egfx_monitor_flags_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_start_timestamp,
		  { "Timestamp", "rdp_egfx.startframe.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_start_frameid,
		  { "Frame id", "rdp_egfx.startframe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_end_frameid,
		  { "Frame id", "rdp_egfx.endframe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_rdp_egfx,
		&ett_egfx_caps,
		&ett_egfx_cap,
		&ett_egfx_ack,
		&ett_egfx_ackqoe,
		&ett_egfx_reset,
		&ett_egfx_capsconfirm,
		&ett_egfx_monitors,
		&ett_egfx_monitordef,
	};

	static ei_register_info ei[] = {
		{ &ei_egfx_pdulen_invalid, { "rdp_egfx.pdulength.invalid", PI_PROTOCOL, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_egfx_invalid_compression, { "rdp_egfx.compression.invalid", PI_PROTOCOL, PI_ERROR, "Invalid compression", EXPFILL }},
	};
	expert_module_t* expert_egfx;


	proto_rdp_egfx = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_egfx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_egfx = expert_register_protocol(proto_rdp_egfx);
	expert_register_field_array(expert_egfx, ei, array_length(ei));

	register_dissector("rdp_egfx", dissect_rdp_egfx, proto_rdp_egfx);
}

void proto_reg_handoff_rdp_egfx(void) {
}

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
#include <epan/proto_data.h>
#include <epan/tvbuff_rdp.h>
#include <epan/crc32-tvb.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

void proto_register_rdp_egfx(void);
void proto_reg_handoff_rdp_egfx(void);

static int proto_rdp_egfx;

static int hf_egfx_cmdId;
static int hf_egfx_flags;
static int hf_egfx_pduLength;

static int hf_egfx_caps_capsSetCount;
static int hf_egfx_cap_version;
static int hf_egfx_cap_length;
static int hf_egfx_cap_flags;
static int hf_egfx_cap_flag_thinclient;
static int hf_egfx_cap_flag_smallcache;
static int hf_egfx_cap_flag_avc420_enabled;
static int hf_egfx_cap_flag_avc_disabled;
static int hf_egfx_cap_flag_avc_thinclient;
static int hf_egfx_cap_flag_scaledmap_disable;
static int hf_egfx_cap_flag_scp_disable;

static int hf_egfx_reset_width;
static int hf_egfx_reset_height;
static int hf_egfx_reset_monitorCount;
static int hf_egfx_reset_monitorDefLeft;
static int hf_egfx_reset_monitorDefTop;
static int hf_egfx_reset_monitorDefRight;
static int hf_egfx_reset_monitorDefBottom;
static int hf_egfx_reset_monitorDefFlags;

static int hf_egfx_ack_queue_depth;
static int hf_egfx_ack_frame_id;
static int hf_egfx_ack_total_decoded;
static int hf_egfx_ack_frame_start;
static int hf_egfx_ack_frame_end;

static int hf_egfx_ackqoe_frame_id;
static int hf_egfx_ackqoe_timestamp;
static int hf_egfx_ackqoe_timediffse;
static int hf_egfx_ackqoe_timediffedr;
static int hf_egfx_ackqoe_frame_start;
static int hf_egfx_ackqoe_frame_end;

static int hf_egfx_start_timestamp;
static int hf_egfx_start_frameid;
static int hf_egfx_start_acked_in;

static int hf_egfx_end_frameid;
static int hf_egfx_end_acked_in;

static int hf_egfx_surfaceid;
static int hf_egfx_codecid;
static int hf_egfx_codeccontextid;
static int hf_egfx_pixelformat;
static int hf_egfx_windowid;
static int hf_egfx_cacheslot;
static int hf_egfx_cachekey;

static int hf_egfx_watermark_width;
static int hf_egfx_watermark_height;
static int hf_egfx_watermark_opacity;
static int hf_egfx_watermark_hpadding;
static int hf_egfx_watermark_vpadding;
static int hf_egfx_watermark_imgsize;
static int hf_egfx_unknown_bytes;

static int ett_rdp_egfx;
static int ett_egfx_caps;
static int ett_egfx_capsconfirm;
static int ett_egfx_cap;
static int ett_egfx_cap_version;
static int ett_egfx_flags;
static int ett_egfx_ack;
static int ett_egfx_ackqoe;
static int ett_egfx_reset;
static int ett_egfx_monitors;
static int ett_egfx_monitordef;
static int ett_egfx_watermark;
static int ett_egfx_createsurface;
static int ett_egfx_mapsurfacetooutput;
static int ett_egfx_mapsurfacetowindow;
static int ett_egfx_mapsurfacetoscaledoutput;
static int ett_egfx_mapsurfacetoscaledwindow;
static int ett_egfx_wiretosurface1;
static int ett_egfx_wiretosurface2;
static int ett_egfx_protectsurface;
static int ett_egfx_surfacetosurface;
static int ett_egfx_surfacetocache;
static int ett_egfx_deletesurface;
static int ett_egfx_deleteencodingcontext;
static int ett_egfx_solidfill;
static int ett_egfx_cachetosurface;

static expert_field ei_egfx_pdulen_invalid;
static expert_field ei_egfx_invalid_compression;
static expert_field ei_egfx_invalid_offset;

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
	RDPGFX_CMDID_DIAGNOSTIC				= 0x0014,
	RDPGFX_CMDID_MAPSURFACETOWINDOW 	= 0x0015,
	RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE 	= 0x0016,
	RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT = 0x0017,
	RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW = 0x0018,
	RDPGFX_CMDID_PROTECT_SURFACE = 0x0019,
	RDPGFX_CMDID_WATERMARK = 0x001A,
};

enum {
	RDPGFX_CAPVERSION_8 = 0x00080004,
	RDPGFX_CAPVERSION_81 = 0x00080105,
	RDPGFX_CAPVERSION_10 = 0x000A0002,
	RDPGFX_CAPVERSION_101 = 0x000A0100,
	RDPGFX_CAPVERSION_102 = 0x000A0200,
	RDPGFX_CAPVERSION_103 = 0x000A0301,
	RDPGFX_CAPVERSION_104 = 0x000A0400,
	RDPGFX_CAPVERSION_105 = 0x000A0502,
	RDPGFX_CAPVERSION_106_ERROR = 0x000A0600,
	RDPGFX_CAPVERSION_106 = 0x000A0601,
	RDPGFX_CAPVERSION_107 = 0x000A0701,

	RDPGFX_CAPVERSION_111 = 0x000b0101,
	RDPGFX_CAPVERSION_112 = 0x000b0200,
	RDPGFX_CAPVERSION_113 = 0x000b0300,
};

enum {
	RDPGFX_CAPS_FLAG_THINCLIENT = 0x00000001,
	RDPGFX_CAPS_FLAG_SMALL_CACHE = 0x00000002,
	RDPGFX_CAPS_FLAG_AVC420_ENABLED = 0x00000010,
	RDPGFX_CAPS_FLAG_AVC_DISABLED = 0x00000020,
	RDPGFX_CAPS_FLAG_AVC_THINCLIENT = 0x00000040,
	RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE = 0x00000080,
	RDPGFX_CAPS_FLAG_SCP_DISABLE = 0x00000100,
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
	{ RDPGFX_CMDID_FRAMEACKNOWLEDGE, "Frame acknowledge" },
	{ RDPGFX_CMDID_RESETGRAPHICS, "Reset graphics" },
	{ RDPGFX_CMDID_MAPSURFACETOOUTPUT, "Map Surface to output" },
	{ RDPGFX_CMDID_CACHEIMPORTOFFER, "Cache import offer" },
	{ RDPGFX_CMDID_CACHEIMPORTREPLY, "Cache import reply" },
	{ RDPGFX_CMDID_CAPSADVERTISE, "Caps advertise" },
	{ RDPGFX_CMDID_CAPSCONFIRM, "Caps confirm" },
	{ RDPGFX_CMDID_MAPSURFACETOWINDOW, "Map surface to window" },
	{ RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE, "Qoe frame acknowledge" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT, "Map surface to scaled output" },
	{ RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW, "Map surface to scaled window" },
	{ RDPGFX_CMDID_PROTECT_SURFACE, "Protect surface" },
	{ RDPGFX_CMDID_WATERMARK, "Watermark surface" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_caps_version_vals[] = {
	{ RDPGFX_CAPVERSION_8, "8.0" },
	{ RDPGFX_CAPVERSION_81, "8.1" } ,
	{ RDPGFX_CAPVERSION_10, "10.0" } ,
	{ RDPGFX_CAPVERSION_101, "10.1" },
	{ RDPGFX_CAPVERSION_102, "10.2" },
	{ RDPGFX_CAPVERSION_103, "10.3" },
	{ RDPGFX_CAPVERSION_104, "10.4" },
	{ RDPGFX_CAPVERSION_105, "10.5" },
	{ RDPGFX_CAPVERSION_106_ERROR, "10.6 bogus" },
	{ RDPGFX_CAPVERSION_106, "10.6" },
	{ RDPGFX_CAPVERSION_107, "10.7" },
	{ RDPGFX_CAPVERSION_111, "11.1" },
	{ RDPGFX_CAPVERSION_112, "11.2" },
	{ RDPGFX_CAPVERSION_113, "11.3" },

	{ 0x0, NULL },
};


static const value_string rdp_egfx_monitor_flags_vals[] = {
	{ 0x00000000, "is secondary" },
	{ 0x00000001, "is primary" },
	{ 0x0, NULL },
};


static const value_string rdp_egfx_codecs_vals[] = {
	{ 0x0000, "UNCOMPRESSED" },
	{ 0x0003, "CAVIDEO" },
	{ 0x0008, "CLEARCODEC" },
	{ 0x0009, "CAPROGRESSIVE" },
	{ 0x000A, "PLANAR" },
	{ 0x000B, "AVC420" },
	{ 0x000C, "ALPHA" },
	{ 0x000E, "AVC444" },
	{ 0x000F, "AVC444v2" },
	{ 0x0, NULL },
};

static const value_string rdp_egfx_pixelformats_vals[] = {
	{ 0x20, "XRGB_8888" },
	{ 0x21, "ARGB_8888" },
	{ 0x0, NULL },
};

typedef struct {
	zgfx_context_t *zgfx;
	wmem_map_t *frames;
} egfx_conv_info_t;

enum {
	EGFX_PDU_KEY = 1
};

typedef struct {
	wmem_tree_t* pdus;
} egfx_pdu_info_t;

typedef struct {
	int startNum;
	int endNum;
	int ackNum;
} egfx_frame_t;


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
		info->frames = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
		conversation_add_proto_data(conversation, proto_rdp_egfx, info);
	}

	return info;
}

static void
parseCapaSet(tvbuff_t *tvb, proto_tree *tree, uint32_t version)
{
	switch (version) {
	case RDPGFX_CAPVERSION_101:
		break;
	case RDPGFX_CAPVERSION_8:
	case RDPGFX_CAPVERSION_81:
	case RDPGFX_CAPVERSION_10:
	case RDPGFX_CAPVERSION_102:
	case RDPGFX_CAPVERSION_103:
	case RDPGFX_CAPVERSION_104:
	case RDPGFX_CAPVERSION_105:
	case RDPGFX_CAPVERSION_106_ERROR:
	case RDPGFX_CAPVERSION_106:
	case RDPGFX_CAPVERSION_107:
	case RDPGFX_CAPVERSION_111:
	case RDPGFX_CAPVERSION_112:
	case RDPGFX_CAPVERSION_113: {
		static int *bits[] = {
			&hf_egfx_cap_flag_thinclient,
			&hf_egfx_cap_flag_smallcache,
			&hf_egfx_cap_flag_avc420_enabled,
			&hf_egfx_cap_flag_avc_disabled,
			&hf_egfx_cap_flag_avc_thinclient,
			&hf_egfx_cap_flag_scaledmap_disable,
			&hf_egfx_cap_flag_scp_disable,
			NULL
		};
		proto_tree_add_bitmask(tree, tvb, 0, hf_egfx_cap_flags, ett_egfx_flags, bits, ENC_LITTLE_ENDIAN);
		break;
	}
	default:
		break;
	}
}


static int
dissect_rdp_egfx_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, egfx_conv_info_t *conv, void *data _U_)
{
	proto_item *item;
	proto_item *pi;
	proto_tree *tree;
	proto_tree *subtree;
	int offset = 0;
	uint32_t cmdId = 0;
	uint32_t pduLength;
	uint32_t i;

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_captured_length_remaining(tvb, offset) > 8) {
		pduLength = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);

		item = proto_tree_add_item(parent_tree, proto_rdp_egfx, tvb, offset, pduLength, ENC_NA);
		tree = proto_item_add_subtree(item, ett_rdp_egfx);

		proto_tree_add_item_ret_uint(tree, hf_egfx_cmdId, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cmdId);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_flags, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(tree, hf_egfx_pduLength, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (pduLength < 8) {
			expert_add_info_format(pinfo, item, &ei_egfx_pdulen_invalid, "pduLength is %u, not < 8", pduLength);
			return offset;
		}

		int nextOffset = offset + (pduLength - 8);
		switch (cmdId) {
		case RDPGFX_CMDID_CAPSADVERTISE: {
			uint16_t capsSetCount = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps advertise");
			proto_tree_add_item(tree, hf_egfx_caps_capsSetCount, tvb, offset, 2, ENC_LITTLE_ENDIAN);

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_caps, NULL, "Caps");
			offset += 2;

			for (i = 0; i < capsSetCount; i++) {
				uint32_t version = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
				uint32_t capsDataLength = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);
				proto_tree* vtree = proto_tree_add_subtree(subtree, tvb, offset, 8 + capsDataLength, ett_egfx_cap_version, NULL, /*find_egfx_version(version)*/
						val_to_str_const(version, rdp_egfx_caps_version_vals, "<unknown>"));

				proto_tree_add_item(vtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(vtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				parseCapaSet(tvb_new_subset_length(tvb, offset, capsDataLength), vtree, version);
				offset += capsDataLength;
			}
			break;
		}

		case RDPGFX_CMDID_CAPSCONFIRM: {
			uint32_t version, capsDataLength;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Caps confirm");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_capsconfirm, NULL, "Caps confirm");
			proto_tree_add_item_ret_uint(subtree, hf_egfx_cap_version, tvb, offset, 4, ENC_LITTLE_ENDIAN, &version);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_cap_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &capsDataLength);
			offset += 4;

			parseCapaSet(tvb_new_subset_length(tvb, offset, capsDataLength), subtree, version);
			break;
		}

		case RDPGFX_CMDID_RESETGRAPHICS: {
			uint32_t nmonitor;
			proto_tree *monitors_tree;
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Reset graphics");

			subtree = proto_tree_add_subtree(tree, tvb, offset, pduLength-8, ett_egfx_reset, NULL, "Reset graphics");
			proto_tree_add_item(subtree, hf_egfx_reset_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_reset_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_reset_monitorCount, tvb, offset, 4, ENC_LITTLE_ENDIAN, &nmonitor);
			offset += 4;

			monitors_tree = proto_tree_add_subtree(subtree, tvb, offset, nmonitor * 20, ett_egfx_monitors, NULL, "Monitors");
			for (i = 0; i < nmonitor; i++) {
				proto_item *monitor_tree;
				uint32_t left, top, right, bottom;
				left = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
				top = tvb_get_uint32(tvb, offset+4, ENC_LITTLE_ENDIAN);
				right = tvb_get_uint32(tvb, offset+8, ENC_LITTLE_ENDIAN);
				bottom = tvb_get_uint32(tvb, offset+12, ENC_LITTLE_ENDIAN);

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
			break;
		}

		case RDPGFX_CMDID_STARTFRAME: {
			uint32_t frameId;
			egfx_frame_t *frame;
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Start frame");
			proto_tree_add_item(tree, hf_egfx_start_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			// TODO: dissect timestamp
			offset += 4;

			proto_tree_add_item_ret_uint(tree, hf_egfx_start_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = pinfo->num;
				frame->endNum = -1;
				frame->ackNum = -1;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->ackNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_start_acked_in, tvb, offset, 4, frame->ackNum);
				proto_item_set_generated(pi);
			}
			break;
		}

		case RDPGFX_CMDID_ENDFRAME: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "End frame");
			proto_tree_add_item_ret_uint(tree, hf_egfx_end_frameid, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);

			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->ackNum = -1;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->endNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->ackNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_end_acked_in, tvb, offset, 4, frame->ackNum);
				proto_item_set_generated(pi);
			}

			break;
		}

		case RDPGFX_CMDID_FRAMEACKNOWLEDGE: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ack, NULL, "Frame acknowledge");
			proto_tree_add_item(subtree, hf_egfx_ack_queue_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item_ret_uint(subtree, hf_egfx_ack_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ack_total_decoded, tvb, offset, 4, ENC_LITTLE_ENDIAN);

			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->endNum = -1;
				frame->ackNum = frameId;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->ackNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->startNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ack_frame_start, tvb, offset - 4, 4, frame->startNum);
				proto_item_set_generated(pi);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->endNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ack_frame_end, tvb, offset - 4, 4, frame->endNum);
				proto_item_set_generated(pi);
			}
			break;
		}

		case RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE: {
			uint32_t frameId;
			egfx_frame_t *frame;

			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Frame acknowledge QoE");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_ackqoe, NULL, "Frame acknowledge QoE");
			proto_tree_add_item_ret_uint(subtree, hf_egfx_ackqoe_frame_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &frameId);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffse, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_ackqoe_timediffedr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			frame = wmem_map_lookup(conv->frames, GUINT_TO_POINTER(frameId));
			if (!frame) {
				frame = wmem_alloc0(wmem_file_scope(), sizeof(*frame));
				frame->startNum = -1;
				frame->endNum = -1;
				frame->ackNum = frameId;
				wmem_map_insert(conv->frames, GUINT_TO_POINTER(frameId), frame);
			}

			frame->ackNum = pinfo->num;

			if (PINFO_FD_VISITED(pinfo) && frame->startNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ackqoe_frame_start, tvb, 0, 0, frame->startNum);
				proto_item_set_generated(pi);
			}

			if (PINFO_FD_VISITED(pinfo) && frame->endNum != -1) {
				pi = proto_tree_add_uint(tree, hf_egfx_ackqoe_frame_end, tvb, 0, 0, frame->endNum);
				proto_item_set_generated(pi);
			}

			break;
		}

		case RDPGFX_CMDID_CREATESURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Create Surface");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_createsurface, NULL, "Create surface");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			// TODO: width / height
			offset += 2 * 2;

			proto_tree_add_item(subtree, hf_egfx_pixelformat, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			break;

		case RDPGFX_CMDID_MAPSURFACETOOUTPUT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Output");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_mapsurfacetooutput, NULL, "Map surface to output");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);

			//offset += 2;
			// TODO: reserved / outputOriginX /outputOriginY
			break;

		case RDPGFX_CMDID_WIRETOSURFACE_1:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Wire To Surface 1");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_wiretosurface1, NULL, "Wire to surface 1");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_codecid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_pixelformat, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			// offset ++;
			// TODO: destRect / bitmapDataLength / bitmapData
			break;

		case RDPGFX_CMDID_WIRETOSURFACE_2:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Wire To Surface 2");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_wiretosurface2, NULL, "Wire to surface 2");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_codecid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_codeccontextid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(subtree, hf_egfx_pixelformat, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			// offset++;
			// TODO: bitmapDataLength / bitmapData
			break;

		case RDPGFX_CMDID_DELETEENCODINGCONTEXT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Delete Encoding Context");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_deleteencodingcontext, NULL, "Delete encoding context");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_codeccontextid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			break;

		case RDPGFX_CMDID_SOLIDFILL:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Solid Fill");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_solidfill, NULL, "Solid fill");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			// offset += 2;
			// TODO: fillPixel / fillRectCount / fillRects
			break;

		case RDPGFX_CMDID_SURFACETOSURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Surface To Surface");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_surfacetosurface, NULL, "Surface to surface");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			// TODO: surfaceIdDest / rectSrc / destPtsCount / destPts
			break;

		case RDPGFX_CMDID_SURFACETOCACHE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Surface To Cache");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_surfacetocache, NULL, "Surface to cache");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_cachekey, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			offset += 8;

			proto_tree_add_item(subtree, hf_egfx_cacheslot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			// TODO: rectSrc
			break;

		case RDPGFX_CMDID_CACHETOSURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache To Surface");

			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_cachetosurface, NULL, "Cache to surface");
			proto_tree_add_item(subtree, hf_egfx_cacheslot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			// TODO: destPtsCout / destPts
			break;

		case RDPGFX_CMDID_EVICTCACHEENTRY:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Evict Cache Entry");
			proto_tree_add_item(tree, hf_egfx_cacheslot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			break;

		case RDPGFX_CMDID_DELETESURFACE:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Delete Surface");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_deletesurface, NULL, "Delete surface");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			break;

		case RDPGFX_CMDID_CACHEIMPORTOFFER:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache Import Offer");
			break;

		case RDPGFX_CMDID_CACHEIMPORTREPLY:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Cache Import Reply");
			break;

		case RDPGFX_CMDID_MAPSURFACETOWINDOW:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Window");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_mapsurfacetowindow, NULL, "Map surface to window");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_windowid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			// offset += 8;
			// TODO: mappedWidth / mappedHeight
			break;

		case RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Scaled Output");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_mapsurfacetoscaledoutput, NULL, "Map surface to scaled output");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			// TODO: reserved / outputOriginX / outputOriginY / targetWidth / targetHeight
			break;

		case RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW:
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Map Surface To Scaled Window");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_mapsurfacetoscaledwindow, NULL, "Map surface to scaled window");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_windowid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			// offset += 8
			// TODO : mappedWidth / mappedHeight / targetWidth / targetHeight
			break;

		case RDPGFX_CMDID_PROTECT_SURFACE: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Protect surface");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_protectsurface, NULL, "Protect surface");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			//offset += 2;
			break;
		}

		case RDPGFX_CMDID_WATERMARK: {
			col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "Watermark surface");
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_egfx_watermark, NULL, "Watermark");
			proto_tree_add_item(subtree, hf_egfx_surfaceid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_watermark_width, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_watermark_height, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			// XXX
			proto_tree_add_item(subtree, hf_egfx_unknown_bytes, tvb, offset, 6, ENC_NA);
			offset += 6;

			proto_tree_add_item(subtree, hf_egfx_pixelformat, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			// XXX
			proto_tree_add_item(subtree, hf_egfx_unknown_bytes, tvb, offset, 2, ENC_NA);
			offset += 2;

			proto_tree_add_item(subtree, hf_egfx_watermark_opacity, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			// XXX
			proto_tree_add_item(subtree, hf_egfx_unknown_bytes, tvb, offset, 6, ENC_NA);
			offset += 6;

			proto_tree_add_item(subtree, hf_egfx_watermark_hpadding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(subtree, hf_egfx_watermark_vpadding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;

			// XXX
			proto_tree_add_item(subtree, hf_egfx_unknown_bytes, tvb, offset, 8, ENC_NA);
			offset += 8;

			uint32_t sz;
			proto_tree_add_item_ret_uint(subtree, hf_egfx_watermark_imgsize, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sz);
			//offset += 2;
			// TODO: image bytes
			break;
		}
		default:
			break;
		}

		offset = nextOffset;
	}
	return offset;
}

static int
dissect_rdp_egfx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	tvbuff_t *work_tvb = tvb;
	egfx_conv_info_t *infos = egfx_get_conversation_data(pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EGFX");
	col_clear(pinfo->cinfo, COL_INFO);

	parent_tree = proto_tree_get_root(parent_tree);

	if (!rdp_isServerAddressTarget(pinfo)) {
		uint32_t hash = crc32_ccitt_tvb(tvb, tvb_captured_length_remaining(tvb, 0));
		egfx_pdu_info_t *pdu_infos = p_get_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY);
		if (!pdu_infos) {
			pdu_infos = wmem_alloc(wmem_file_scope(), sizeof(*pdu_infos));
			pdu_infos->pdus = wmem_tree_new(wmem_file_scope());
			p_set_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY, pdu_infos);
		}

		if (!PINFO_FD_VISITED(pinfo)) {
			work_tvb = rdp8_decompress(infos->zgfx, wmem_file_scope(), tvb, 0);
			if (work_tvb) {
				//printf("%d: zgfx sz=%d\n", pinfo->num, tvb_captured_length(work_tvb));
				wmem_tree_insert32(pdu_infos->pdus, hash, work_tvb);
			}
		} else {
			pdu_infos = p_get_proto_data(wmem_file_scope(), pinfo, proto_rdp_egfx, EGFX_PDU_KEY);
			work_tvb = wmem_tree_lookup32(pdu_infos->pdus, hash);
		}

		if (work_tvb)
			add_new_data_source(pinfo, work_tvb, "Uncompressed GFX");
	}

	if (work_tvb)
		dissect_rdp_egfx_payload(work_tvb, pinfo, parent_tree, infos, data);
	else {
		if (parent_tree)
			expert_add_info_format(pinfo, parent_tree->last_child, &ei_egfx_invalid_compression, "invalid compression");
	}

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
		{ &hf_egfx_cap_flags,
		  { "Flags", "rdp_egfx.cap.flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
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
		{ &hf_egfx_ack_frame_start,
		  { "Frame starts in", "rdp_egfx.ack.framestart",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ack_frame_end,
		  { "Frame ends in", "rdp_egfx.ack.frameend",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
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
		{ &hf_egfx_ackqoe_frame_start,
		  { "Frame starts in", "rdp_egfx.ackqoe.framestart",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_ackqoe_frame_end,
		  { "Frame ends in", "rdp_egfx.ackqoe.frameend",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
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
			FT_UINT32, BASE_HEX, VALS(rdp_egfx_monitor_flags_vals), 0x0,
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
		{ &hf_egfx_start_acked_in,
		  { "Frame acked in", "rdp_egfx.startframe.ackedin",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_end_frameid,
		  { "Frame id", "rdp_egfx.endframe.frameid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_end_acked_in,
		  { "Frame acked in", "rdp_egfx.endframe.ackedin",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_surfaceid,
		  { "Surface id", "rdp_egfx.surfaceid",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_codecid,
		  { "Codec id", "rdp_egfx.codecid",
			FT_UINT16, BASE_HEX, VALS(rdp_egfx_codecs_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_codeccontextid,
		  { "Codec context id", "rdp_egfx.codeccontextid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_windowid,
		  { "Windows id", "rdp_egfx.windowid",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cacheslot,
		  { "Cache slot", "rdp_egfx.cacheslot",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_cachekey,
		  { "Cache key", "rdp_egfx.cachekey",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_width,
		  { "Width", "rdp_egfx.watermark.width",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_height,
		  { "Height", "rdp_egfx.watermark.height",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_pixelformat,
		  { "Pixel format", "rdp_egfx.pixelformat",
			FT_UINT8, BASE_HEX, VALS(rdp_egfx_pixelformats_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_opacity,
		  { "Opacity", "rdp_egfx.watermark.opacity",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_hpadding,
		  { "HPadding", "rdp_egfx.watermark.hpadding",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_vpadding,
		  { "VPadding", "rdp_egfx.watermark.vpadding",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_egfx_watermark_imgsize,
		  { "Image size", "rdp_egfx.watermark.imgsize",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_egfx_cap_flag_thinclient,
		  { "Thinclient", "rdp_egfx.cap.thinclient",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_THINCLIENT,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_smallcache,
		  { "Smallcache", "rdp_egfx.cap.smallcache",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_SMALL_CACHE,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_avc420_enabled,
		  { "AVC420_ENABLED", "rdp_egfx.cap.avc420enabled",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_AVC420_ENABLED,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_avc_disabled,
		  { "AVC_DISABLED", "rdp_egfx.cap.avcdisabled",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_AVC_DISABLED,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_avc_thinclient,
		  { "AVC_THINCLIENT", "rdp_egfx.cap.avcthinclient",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_AVC_THINCLIENT,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_scaledmap_disable,
		  { "SCALEDMAP_DISABLE", "rdp_egfx.cap.scaledmapdisable",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE,
			NULL, HFILL }
		},
		{ &hf_egfx_cap_flag_scp_disable,
		  { "SCP_DISABLE", "rdp_egfx.cap.scpdisable",
			FT_UINT32, BASE_HEX, NULL, RDPGFX_CAPS_FLAG_SCP_DISABLE,
			NULL, HFILL }
		},
		{ &hf_egfx_unknown_bytes,
		  { "Unknown bytes", "rdp_egfx.unknown",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		}
	};

	static int *ett[] = {
		&ett_rdp_egfx,
		&ett_egfx_caps,
		&ett_egfx_cap,
		&ett_egfx_cap_version,
		&ett_egfx_flags,
		&ett_egfx_ack,
		&ett_egfx_ackqoe,
		&ett_egfx_reset,
		&ett_egfx_capsconfirm,
		&ett_egfx_monitors,
		&ett_egfx_monitordef,
		&ett_egfx_watermark,
		&ett_egfx_createsurface,
		&ett_egfx_mapsurfacetooutput,
		&ett_egfx_mapsurfacetowindow,
		&ett_egfx_mapsurfacetoscaledoutput,
		&ett_egfx_mapsurfacetoscaledwindow,
		&ett_egfx_wiretosurface1,
		&ett_egfx_wiretosurface2,
		&ett_egfx_protectsurface,
		&ett_egfx_surfacetosurface,
		&ett_egfx_surfacetocache,
		&ett_egfx_deletesurface,
		&ett_egfx_deleteencodingcontext,
		&ett_egfx_solidfill,
		&ett_egfx_cachetosurface
	};

	static ei_register_info ei[] = {
		{ &ei_egfx_pdulen_invalid, { "rdp_egfx.pdulength.invalid", PI_PROTOCOL, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_egfx_invalid_compression, { "rdp_egfx.compression.invalid", PI_PROTOCOL, PI_ERROR, "Invalid compression", EXPFILL }},
		{ &ei_egfx_invalid_offset, { "rdp_egfx.invalid.offset", PI_PROTOCOL, PI_ERROR, "Invalid Offset", EXPFILL }},
	};
	expert_module_t* expert_egfx;


	proto_rdp_egfx = proto_register_protocol("RDP Graphic pipeline channel Protocol", "EGFX", "rdp_egfx");
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_egfx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_egfx = expert_register_protocol(proto_rdp_egfx);
	expert_register_field_array(expert_egfx, ei, array_length(ei));

	register_dissector("rdp_egfx", dissect_rdp_egfx, proto_rdp_egfx);
}

void proto_reg_handoff_rdp_egfx(void) {
}

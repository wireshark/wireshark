/* wimax_harq_map_decoder.c
 * WiMax HARQ Map Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "crc.h"
#include "wimax-int.h"
#include "wimax_compact_dlmap_ie_decoder.h"
#include "wimax_compact_ulmap_ie_decoder.h"

extern gint proto_wimax;

static gint proto_wimax_harq_map_decoder = -1;
static gint ett_wimax_harq_map_decoder = -1;

/* MASKs */
#define LSB_NIBBLE_MASK      0x0F

/* HARQ MAP masks */
#define WIMAX_HARQ_MAP_INDICATOR_MASK    0xE00000
#define WIMAX_HARQ_UL_MAP_APPENDED_MASK  0x100000
#define WIMAX_HARQ_MAP_RESERVED_MASK     0x080000
#define WIMAX_HARQ_MAP_MSG_LENGTH_MASK   0x07FC00
#define WIMAX_HARQ_MAP_DL_IE_COUNT_MASK  0x0003F0
#define WIMAX_HARQ_MAP_MSG_LENGTH_SHIFT  10
#define WIMAX_HARQ_MAP_DL_IE_COUNT_SHIFT 4

/* HARQ MAP display indexies */
static gint hf_harq_map_indicator = -1;
static gint hf_harq_ul_map_appended = -1;
static gint hf_harq_map_reserved = -1;
static gint hf_harq_map_msg_length = -1;
static gint hf_harq_dl_ie_count = -1;
static gint hf_harq_map_msg_crc = -1;
static gint hf_harq_map_msg_crc_status = -1;

static expert_field ei_harq_map_msg_crc = EI_INIT;


/* Copied and renamed from proto.c because global value_strings don't work for plugins */
static const value_string plugin_proto_checksum_vals[] = {
	{ PROTO_CHECKSUM_E_BAD,        "Bad"  },
	{ PROTO_CHECKSUM_E_GOOD,       "Good" },
	{ PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
	{ PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },

	{ 0,        NULL }
};

/* HARQ MAP message decoder */
static int dissector_wimax_harq_map_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint i, offset = 0;
	guint tvb_len, length, dl_ie_count;
	guint ie_length;
	proto_item *harq_map_item = NULL;
	proto_tree *harq_map_tree = NULL;
	guint nibble_offset;
	proto_item *parent_item = NULL;
	guint ulmap_appended;
	guint32 harq_map_msg_crc, calculated_crc;
	guint32 first_24bits;

	/* check the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	if(!tvb_len)
	{	/* do nothing if tvb is empty */
		return 0;
	}
	/* Ensure the right payload type */
	first_24bits = tvb_get_ntoh24(tvb, offset);
	if((first_24bits & WIMAX_HARQ_MAP_INDICATOR_MASK) != WIMAX_HARQ_MAP_INDICATOR_MASK)
	{	/* do nothing if tvb is not a HARQ MAP message */
		return 0;
	}
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "HARQ-MAP Message: ");
	if (tree)
	{	/* we are being asked for details */
		/* get the parent */
		parent_item = proto_tree_get_parent(tree);
		/* display HARQ-MAP Message and create subtree */
		harq_map_item = proto_tree_add_protocol_format(tree, proto_wimax_harq_map_decoder, tvb, offset, tvb_len, "HARQ-MAP Message (%u bytes)", tvb_len);
		harq_map_tree = proto_item_add_subtree(harq_map_item, ett_wimax_harq_map_decoder);
		/* display the HARQ MAP Indicator */
		proto_tree_add_item(harq_map_tree, hf_harq_map_indicator, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the HARQ MAp UL-MAP Appended */
		proto_tree_add_item(harq_map_tree, hf_harq_ul_map_appended, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the reserved bit */
		proto_tree_add_item(harq_map_tree, hf_harq_map_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the HARQ MAP message length */
		proto_tree_add_item(harq_map_tree, hf_harq_map_msg_length, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* display the DL IE count */
		proto_tree_add_item(harq_map_tree, hf_harq_dl_ie_count, tvb, offset, 3, ENC_BIG_ENDIAN);
		/* get the message length */
		/* XXX - make sure the length isn't smaller than the minimum */
		length = ((first_24bits & WIMAX_HARQ_MAP_MSG_LENGTH_MASK) >> WIMAX_HARQ_MAP_MSG_LENGTH_SHIFT);
		/* get the DL IE count */
		dl_ie_count = ((first_24bits & WIMAX_HARQ_MAP_DL_IE_COUNT_MASK) >> WIMAX_HARQ_MAP_DL_IE_COUNT_SHIFT);
		/* get the UL MAP appended */
		ulmap_appended = (first_24bits & WIMAX_HARQ_UL_MAP_APPENDED_MASK);

		/* set the offsets to Compact DL-MAP IEs */
		offset += 2;
		nibble_offset = 1;
		/* process the compact dl_map ies */
		for(i=0; i<dl_ie_count; i++)
		{	/* add the DL-MAp IEs info */
			proto_item_append_text(parent_item, " - DL-MAP IEs");
			/* decode Compact DL-MAP IEs */
			ie_length = wimax_compact_dlmap_ie_decoder(harq_map_tree, pinfo, tvb, offset, nibble_offset);
			offset += ((nibble_offset + ie_length) >> 1);
			nibble_offset = ((nibble_offset + ie_length) & 1);
		}
		/* check if there exist the compact ul_map IEs */
		if (ulmap_appended)
		{	/* add the UL-MAp IEs info */
			proto_item_append_text(parent_item, ",UL-MAP IEs");
			/* process the compact ul_map ies */
			while(offset < (length - (int)sizeof(harq_map_msg_crc)))
			{	/* decode Compact UL-MAP IEs */
				ie_length = wimax_compact_ulmap_ie_decoder(harq_map_tree, pinfo, tvb, offset, nibble_offset);
				/* Prevent endless loop with erroneous data. */
				if (ie_length < 2)
					ie_length = 2;
				offset += ((nibble_offset + ie_length) >> 1);
				nibble_offset = ((nibble_offset + ie_length) & 1);
			}
		}
		/* handle the padding */
		if(nibble_offset)
		{
			/* add the Padding info */
			proto_item_append_text(parent_item, ",Padding");
			proto_tree_add_protocol_format(harq_map_tree, proto_wimax_harq_map_decoder, tvb, offset, 1, "Padding Nibble: 0x%x", (tvb_get_guint8(tvb, offset) & LSB_NIBBLE_MASK));
		}
		/* add the CRC info */
		proto_item_append_text(parent_item, ",CRC");
		/* calculate the HARQ MAM Message CRC */
		if (length >= (int)sizeof(harq_map_msg_crc)) {
			calculated_crc = wimax_mac_calc_crc32(tvb_get_ptr(tvb, 0, length - (int)sizeof(harq_map_msg_crc)), length - (int)sizeof(harq_map_msg_crc));
			proto_tree_add_checksum(tree, tvb, length - (int)sizeof(harq_map_msg_crc), hf_harq_map_msg_crc, hf_harq_map_msg_crc_status, &ei_harq_map_msg_crc,
									pinfo, calculated_crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
		}
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax HARQ MAP Protocol */
void wimax_proto_register_wimax_harq_map(void)
{
	/* HARQ MAP display */
	static hf_register_info hf_harq_map[] =
	{
		{
			&hf_harq_map_indicator,
			{"HARQ MAP Indicator", "wmx.harq_map.indicator", FT_UINT24, BASE_HEX, NULL, WIMAX_HARQ_MAP_INDICATOR_MASK, NULL, HFILL}
		},
		{
			&hf_harq_ul_map_appended,
			{"HARQ UL-MAP Appended", "wmx.harq_map.ul_map_appended", FT_UINT24, BASE_HEX, NULL, WIMAX_HARQ_UL_MAP_APPENDED_MASK, NULL, HFILL}
		},
		{
			&hf_harq_map_reserved,
			{"Reserved", "wmx.harq_map.reserved", FT_UINT24, BASE_HEX, NULL, WIMAX_HARQ_MAP_RESERVED_MASK, NULL, HFILL}
		},
		{
			&hf_harq_map_msg_length,
			{"Map Message Length", "wmx.harq_map.msg_length", FT_UINT24, BASE_DEC, NULL, WIMAX_HARQ_MAP_MSG_LENGTH_MASK, NULL, HFILL}
		},
		{
			&hf_harq_dl_ie_count,
			{"DL IE Count", "wmx.harq_map.dl_ie_count", FT_UINT24, BASE_DEC, NULL, WIMAX_HARQ_MAP_DL_IE_COUNT_MASK, NULL, HFILL}
		},
		{
			&hf_harq_map_msg_crc,
			{"HARQ MAP Message CRC", "wmx.harq_map.msg_crc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_harq_map_msg_crc_status,
			{"HARQ MAP Message CRC Status", "wmx.harq_map.msg_crc.status", FT_UINT8, BASE_NONE, VALS(plugin_proto_checksum_vals), 0x0, NULL, HFILL}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
	{
		&ett_wimax_harq_map_decoder,
	};

	static ei_register_info ei[] = {
		{ &ei_harq_map_msg_crc, { "wmx.harq_map.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_harq_map;

	proto_wimax_harq_map_decoder = proto_wimax;

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_wimax_harq_map_decoder, hf_harq_map, array_length(hf_harq_map));
	expert_harq_map = expert_register_protocol(proto_wimax_harq_map_decoder);
	expert_register_field_array(expert_harq_map, ei, array_length(ei));

	register_dissector("wimax_harq_map_handler", dissector_wimax_harq_map_decoder, proto_wimax_harq_map_decoder);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

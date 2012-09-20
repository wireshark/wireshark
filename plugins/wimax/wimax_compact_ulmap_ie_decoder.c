/* wimax_compact_ulmap_ie_decoder.c
 * WiMax Compact UL-MAP IE decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"

/* MASKs */
#define MSB_NIBBLE_MASK      0xF0
#define LSB_NIBBLE_MASK      0x0F

#define CID_TYPE_NORMAL      0
#define CID_TYPE_RCID11      1
#define CID_TYPE_RCID7       2
#define CID_TYPE_RCID3       3

/* Global Variables */
extern guint cid_type;
extern guint band_amc_subchannel_type;
extern guint max_logical_bands;
extern guint num_of_broadcast_symbols;
extern guint num_of_dl_band_amc_symbols;
extern guint num_of_ul_band_amc_symbols;
extern guint harq_mode;
extern gint  proto_wimax;

/* forward reference */
guint wimax_cdma_allocation_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
guint wimax_extended_uiuc_dependent_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_compact_ulmap_rcid_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_compact_ulmap_harq_control_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_culmap_extension_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);

static gint proto_wimax_compact_ulmap_ie_decoder = -1;

#if 0 /* not used ?? */
static gint ett_wimax_compact_ulmap_ie_decoder = -1;
static gint ett_wimax_rcid_ie_decoder = -1;
static gint ett_wimax_harq_control_ie_decoder = -1;
static gint ett_wimax_extended_uiuc_dependent_ie_decoder = -1;
static gint ett_wimax_extension_type_ie_decoder = -1;
#endif

/* Prefixes */
static const true_false_string tfs_prefix =
{
    "Enable HARQ",
    "Temporary Disable HARQ"
};

/* Region Changes */
static const true_false_string tfs_region_change =
{
    "Region Changed",
    "No Region Change"
};

/* Region Changes */
static const true_false_string tfs_yes_no_ie =
{
    "Yes",
    "No"
};

/* Repetition Coding Indications */
static const value_string vals_repetitions[] =
{
    { 0, "No Repetition Coding" },
    { 1, "Repetition Coding of 2 Used" },
    { 2, "Repetition Coding of 4 Used" },
    { 3, "Repetition Coding of 6 Used" },
    { 0,  NULL }
};

/* Allocation Modes */
static const value_string vals_allocation_modes[] =
{
    { 0, "Same Number Of Subchannels For The Selected Bands" },
    { 1, "Different Same Number Of Subchannels For The Selected Bands" },
    { 2, "Total Number Of Subchannels For The Selected Bands Determined by Nsch Code and Nep Code" },
    { 3, "Reserved" },
    { 0,  NULL }
};

/* CTypes */
static const value_string vals_ctypes[] =
{
    { 0, "2 Mini-subchannels (defines M=2)" },
    { 1, "2 Mini-subchannels (defines M=2)" },
    { 2, "3 Mini-subchannels (defines M=3)" },
    { 3, "6 Mini-subchannels (defines M=6)" },
    { 0,  NULL }
};

/* Masks */
#define UL_MAP_TYPE_MASK       0xE0
#define UL_MAP_RESERVED_MASK   0x10
#define SHORTENED_UIUC_MASK    0xE0
#define COMPANDED_SC_MASK      0x1F
#define UL_MAP_TYPE_MASK_1     0x0E
#define UL_MAP_RESERVED_MASK_1 0x01
#define SHORTENED_UIUC_MASK_1  0x0E00
#define COMPANDED_SC_MASK_1    0x01F0
#define MIDDLE_BYTE_MASK       0x0FF0

#define ALLOCATION_MODE_MASK   0xC0
#define ALLOCATION_MODE_MASK_1 0x0C

/* display indexies */
static gint hf_culmap_ul_map_type = -1;
static gint hf_culmap_reserved = -1;
static gint hf_culmap_nep_code = -1;
static gint hf_culmap_nsch_code = -1;
static gint hf_culmap_num_bands = -1;
static gint hf_culmap_band_index = -1;
static gint hf_culmap_nb_bitmap = -1;
static gint hf_culmap_ul_map_type_1 = -1;
static gint hf_culmap_reserved_1 = -1;
static gint hf_culmap_nep_code_1 = -1;
static gint hf_culmap_nsch_code_1 = -1;
static gint hf_culmap_num_bands_1 = -1;
/*static gint hf_culmap_band_index_1 = -1;*/
static gint hf_culmap_nb_bitmap_1 = -1;

static gint hf_culmap_shortened_uiuc = -1;
static gint hf_culmap_companded_sc = -1;
static gint hf_culmap_shortened_uiuc_1 = -1;
static gint hf_culmap_companded_sc_1 = -1;

static gint hf_culmap_bin_offset = -1;
static gint hf_culmap_bin_offset_1 = -1;

static gint hf_culmap_uiuc_ofdma_symbol_offset = -1;
static gint hf_culmap_uiuc_ofdma_symbol_offset_1 = -1;
static gint hf_culmap_uiuc_subchannel_offset_7 = -1;
static gint hf_culmap_uiuc_num_of_ofdma_symbols_7 = -1;
static gint hf_culmap_uiuc_num_of_subchannels_7 = -1;
static gint hf_culmap_uiuc_ranging_method = -1;
static gint hf_culmap_uiuc_reserved = -1;
static gint hf_culmap_uiuc_subchannel_offset_7_1 = -1;
static gint hf_culmap_uiuc_num_of_ofdma_symbols_7_1 = -1;
static gint hf_culmap_uiuc_num_of_subchannels_7_1 = -1;
static gint hf_culmap_uiuc_ranging_method_1 = -1;
static gint hf_culmap_uiuc_reserved_1 = -1;
static gint hf_culmap_uiuc_repetition_coding_indication = -1;
static gint hf_culmap_uiuc_repetition_coding_indication_1 = -1;
static gint hf_culmap_uiuc_reserved1 = -1;
static gint hf_culmap_uiuc_reserved11_1 = -1;
static gint hf_culmap_uiuc_subchannel_offset = -1;
static gint hf_culmap_uiuc_subchannel_offset_1 = -1;
static gint hf_culmap_uiuc_num_of_ofdma_symbols = -1;
static gint hf_culmap_uiuc_num_of_ofdma_symbols_1 = -1;
static gint hf_culmap_uiuc_num_of_subchannels = -1;
static gint hf_culmap_uiuc_num_of_subchannels_1 = -1;

static gint hf_culmap_harq_region_change_indication = -1;
static gint hf_culmap_harq_region_change_indication_1 = -1;
static gint hf_culmap_cqi_region_change_indication = -1;
static gint hf_culmap_cqi_region_change_indication_1 = -1;

static gint hf_culmap_uiuc = -1;
static gint hf_culmap_uiuc_1 = -1;

static gint hf_culmap_allocation_mode = -1;
static gint hf_culmap_allocation_mode_rsvd = -1;
static gint hf_culmap_num_subchannels = -1;
static gint hf_culmap_allocation_mode_1 = -1;
static gint hf_culmap_allocation_mode_rsvd_1 = -1;
static gint hf_culmap_num_subchannels_1 = -1;

static gint hf_culmap_reserved_type = -1;
static gint hf_culmap_reserved_type_1 = -1;

/* display indexies */
static gint hf_rcid_ie_prefix = -1;
static gint hf_rcid_ie_prefix_1 = -1;
static gint hf_rcid_ie_normal_cid = -1;
static gint hf_rcid_ie_normal_cid_1 = -1;
static gint hf_rcid_ie_cid3 = -1;
static gint hf_rcid_ie_cid3_1 = -1;
static gint hf_rcid_ie_cid7 = -1;
static gint hf_rcid_ie_cid7_1 = -1;
static gint hf_rcid_ie_cid11 = -1;
static gint hf_rcid_ie_cid11_1 = -1;
static gint hf_rcid_ie_cid11_2 = -1;
static gint hf_rcid_ie_cid11_3 = -1;

/* Masks */
#define WIMAX_RCID_IE_NORMAL_CID_MASK_1      0x0FFFF0
#define WIMAX_RCID_IE_PREFIX_MASK            0x8000
#define WIMAX_RCID_IE_PREFIX_MASK_1          0x0800
#define WIMAX_RCID_IE_CID3_MASK              0x7000
#define WIMAX_RCID_IE_CID3_MASK_1            0x0700
#define WIMAX_RCID_IE_CID7_MASK              0x7F00
#define WIMAX_RCID_IE_CID7_MASK_1            0x07F0
#define WIMAX_RCID_IE_CID11_MASK             0x7FF0
#define WIMAX_RCID_IE_CID11_MASK_1           0x07FF

/* HARQ MAP HARQ Control IE display indexies */
static gint hf_harq_control_ie_prefix = -1;
static gint hf_harq_control_ie_ai_sn = -1;
static gint hf_harq_control_ie_spid = -1;
static gint hf_harq_control_ie_acid = -1;
static gint hf_harq_control_ie_reserved = -1;
static gint hf_harq_control_ie_prefix_1 = -1;
static gint hf_harq_control_ie_ai_sn_1 = -1;
static gint hf_harq_control_ie_spid_1 = -1;
static gint hf_harq_control_ie_acid_1 = -1;
static gint hf_harq_control_ie_reserved_1 = -1;

/* Masks */
#define WIMAX_HARQ_CONTROL_IE_PREFIX_MASK      0x80
#define WIMAX_HARQ_CONTROL_IE_AI_SN_MASK       0x40
#define WIMAX_HARQ_CONTROL_IE_SPID_MASK        0x30
#define WIMAX_HARQ_CONTROL_IE_ACID_MASK        0x0F
#define WIMAX_HARQ_CONTROL_IE_RESERVED_MASK    0x70
#define WIMAX_HARQ_CONTROL_IE_PREFIX_MASK_1    0x0800
#define WIMAX_HARQ_CONTROL_IE_AI_SN_MASK_1     0x0400
#define WIMAX_HARQ_CONTROL_IE_SPID_MASK_1      0x0300
#define WIMAX_HARQ_CONTROL_IE_ACID_MASK_1      0x00F0
#define WIMAX_HARQ_CONTROL_IE_RESERVED_MASK_1  0x0700

/* Extension Type */
#define EXTENSION_TYPE_MASK         0xE000
#define EXTENSION_TYPE_MASK_1       0x0E00
#define EXTENSION_SUBTYPE_MASK      0x1F00
#define EXTENSION_SUBTYPE_MASK_1    0x01F0
#define EXTENSION_LENGTH_MASK       0x00F0
#define EXTENSION_LENGTH_MASK_1     0x000F

static gint hf_culmap_extension_type = -1;
static gint hf_culmap_extension_subtype = -1;
static gint hf_culmap_extension_length = -1;
static gint hf_culmap_extension_type_1 = -1;
static gint hf_culmap_extension_subtype_1 = -1;
static gint hf_culmap_extension_length_1 = -1;

static gint hf_culmap_extension_time_diversity_mbs = -1;
static gint hf_culmap_extension_harq_mode = -1;
static gint hf_culmap_extension_unknown_sub_type = -1;
static gint hf_culmap_extension_time_diversity_mbs_1 = -1;
static gint hf_culmap_extension_harq_mode_1 = -1;
static gint hf_culmap_extension_unknown_sub_type_1 = -1;

/* UL-MAP CDMA Allocation IE */
#define CDMA_ALLOCATION_DURATION_MASK               0xFC00
#define CDMA_ALLOCATION_UIUC_MASK                   0x03C0
#define CDMA_ALLOCATION_REPETITION_CODE_MASK        0x0030
#define CDMA_ALLOCATION_FRAME_NUMBER_INDEX_MASK     0x000F

#define CDMA_ALLOCATION_RANGING_SUBCHANNEL_MASK     0xFE
#define CDMA_ALLOCATION_BW_REQUEST_MANDATORY_MASK   0x01

#define CDMA_ALLOCATION_DURATION_MASK_1             0x0FC0
#define CDMA_ALLOCATION_UIUC_MASK_1                 0x003C
#define CDMA_ALLOCATION_REPETITION_CODE_MASK_1      0x0003
#define CDMA_ALLOCATION_FRAME_NUMBER_INDEX_MASK_1   0xF0000000
#define CDMA_ALLOCATION_RANGING_CODE_MASK_1         0x0FF00000
#define CDMA_ALLOCATION_RANGING_SYMBOL_MASK_1       0x000FF000
#define CDMA_ALLOCATION_RANGING_SUBCHANNEL_MASK_1   0x00000FE0
#define CDMA_ALLOCATION_BW_REQUEST_MANDATORY_MASK_1 0x00000010

static gint hf_cdma_allocation_duration = -1;
static gint hf_cdma_allocation_uiuc = -1;
static gint hf_cdma_allocation_repetition = -1;
static gint hf_cdma_allocation_frame_number_index = -1;
static gint hf_cdma_allocation_ranging_code = -1;
static gint hf_cdma_allocation_ranging_symbol = -1;
static gint hf_cdma_allocation_ranging_subchannel = -1;
static gint hf_cdma_allocation_bw_req = -1;
static gint hf_cdma_allocation_duration_1 = -1;
static gint hf_cdma_allocation_uiuc_1 = -1;
static gint hf_cdma_allocation_repetition_1 = -1;
static gint hf_cdma_allocation_frame_number_index_1 = -1;
static gint hf_cdma_allocation_ranging_code_1 = -1;
static gint hf_cdma_allocation_ranging_symbol_1 = -1;
static gint hf_cdma_allocation_ranging_subchannel_1 = -1;
static gint hf_cdma_allocation_bw_req_1 = -1;

/* UL-MAP Extended UIUCs (table 290a) */
#define MINI_SUBCHANNEL_CTYPE_MASK           0xC0
#define MINI_SUBCHANNEL_CTYPE_MASK_16        0x0C00
#define MINI_SUBCHANNEL_DURATION_MASK        0x3F
#define MINI_SUBCHANNEL_DURATION_MASK_16     0x03F0
#define MINI_SUBCHANNEL_CID_MASK             0xFFFF00
#define MINI_SUBCHANNEL_UIUC_MASK            0x0000F0
#define MINI_SUBCHANNEL_REPETITION_MASK      0x00000C
#define MINI_SUBCHANNEL_CID_MASK_1           0x0FFFF000
#define MINI_SUBCHANNEL_UIUC_MASK_1          0x00000F00
#define MINI_SUBCHANNEL_REPETITION_MASK_1    0x000000C0
#define MINI_SUBCHANNEL_CID_MASK_2           0x03FFFF00
#define MINI_SUBCHANNEL_UIUC_MASK_2          0x000000F0
#define MINI_SUBCHANNEL_REPETITION_MASK_2    0x0000000C
#define MINI_SUBCHANNEL_CID_MASK_3           0x3FFFF000
#define MINI_SUBCHANNEL_UIUC_MASK_3          0x00000F00
#define MINI_SUBCHANNEL_REPETITION_MASK_3    0x000000C0
#define MINI_SUBCHANNEL_PADDING_MASK         0xF0
#define MINI_SUBCHANNEL_PADDING_MASK_1       0x0000000F

static gint hf_extended_uiuc_ie_uiuc = -1;
static gint hf_extended_uiuc_ie_length = -1;
static gint hf_extended_uiuc_ie_uiuc_1 = -1;
static gint hf_extended_uiuc_ie_length_1 = -1;
static gint hf_extended_uiuc_ie_power_control = -1;
static gint hf_extended_uiuc_ie_power_measurement_frame = -1;
static gint hf_extended_uiuc_ie_power_control_24 = -1;
static gint hf_extended_uiuc_ie_power_measurement_frame_24 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_ctype = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_duration = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_ctype_16 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_duration_16 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_cid = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_repetition = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_padding = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_cid_1 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_1 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_1 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_cid_2 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_2 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_2 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_cid_3 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_3 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_3 = -1;
static gint hf_extended_uiuc_ie_mini_subchannel_alloc_padding_1 = -1;
static gint hf_extended_uiuc_ie_aas_ul = -1;
static gint hf_extended_uiuc_ie_cqich_alloc = -1;
static gint hf_extended_uiuc_ie_ul_zone = -1;
static gint hf_extended_uiuc_ie_phymod_ul = -1;
static gint hf_extended_uiuc_ie_mimo_ul_basic = -1;
static gint hf_extended_uiuc_ie_fast_tracking = -1;
static gint hf_extended_uiuc_ie_ul_pusc_burst_allocation = -1;
static gint hf_extended_uiuc_ie_fast_ranging = -1;
static gint hf_extended_uiuc_ie_ul_allocation_start = -1;
static gint hf_extended_uiuc_ie_unknown_uiuc = -1;


/* Compact UL-MAP IE Types (table 90) */
#define COMPACT_UL_MAP_TYPE_NORMAL_SUBCHANNEL	0
#define COMPACT_UL_MAP_TYPE_BAND_AMC		1
#define COMPACT_UL_MAP_TYPE_SAFETY		2
#define COMPACT_UL_MAP_TYPE_UIUC		3
#define COMPACT_UL_MAP_TYPE_HARQ_REGION_IE	4
#define COMPACT_UL_MAP_TYPE_CQICH_REGION_IE	5
#define COMPACT_UL_MAP_TYPE_RESERVED		6
#define COMPACT_UL_MAP_TYPE_EXTENSION		7

/* Compact UL-MAP IE decoder */
guint wimax_compact_ulmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint uiuc, byte, length = 0;
	guint ul_map_type;
	guint harq_region_change_indication;
	guint cqi_region_change_indication;
	guint ul_map_offset, nibble_length;
	guint nband, band_count, i, allocation_mode;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Compact UL-MAP IEs");
#endif
	/* set the local offset */
	ul_map_offset = offset;
	/* Get the first byte */
	byte = tvb_get_guint8(tvb, ul_map_offset);
	/* get the ul-map type */
	if(nibble_offset & 1)
	{
		ul_map_type = ((byte & UL_MAP_TYPE_MASK_1) >> 1);
	}
	else
	{
		ul_map_type = ((byte & UL_MAP_TYPE_MASK) >> 5);
	}
	/* process the Compact UL-MAP IE (table 90) */
	switch (ul_map_type)
	{
		case COMPACT_UL_MAP_TYPE_NORMAL_SUBCHANNEL:/* 6.3.2.3.43.7.1 */
			/* display the UL-MAP type and reserved bit */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
				nibble_offset = 0;
			}
			else
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_ulmap_rcid_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
			ul_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_nep_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
					proto_tree_add_item(tree, hf_culmap_nsch_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_nep_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_nsch_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened UIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				ul_map_offset++;
				length += 2;
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_ulmap_harq_control_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_UL_MAP_TYPE_BAND_AMC:/* 6.3.2.3.43.7.2 */
			/* display the UL-MAP type and reserved bit */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
				nibble_offset = 0;
			}
			else
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_ulmap_rcid_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
			ul_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_nep_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
					proto_tree_add_item(tree, hf_culmap_nsch_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_nep_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_nsch_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened UIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				ul_map_offset++;
				length += 2;
			}
			/* get the Nband */
			if(max_logical_bands)
			{	/* get and display the Nband */
				nband = tvb_get_guint8(tvb, ul_map_offset);
				length++;
				if(nibble_offset & 1)
				{
					nband = (nband & LSB_NIBBLE_MASK);
					/* display the Nband */
					proto_tree_add_item(tree, hf_culmap_num_bands_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
					nibble_offset = 0;
					if(max_logical_bands == 3)
					{
						proto_tree_add_item(tree, hf_culmap_band_index, tvb, ul_map_offset, nband, ENC_NA);
						length += (nband * 2);
						/* update offset */
						ul_map_offset += nband;
					}
					else
					{
						nibble_offset = (nband & 1);
						proto_tree_add_item(tree, hf_culmap_band_index, tvb, ul_map_offset, ((nband >> 1) + nibble_offset), ENC_NA);
						length += nband;
						/* update offset */
						ul_map_offset += (nband >> 1);
					}
				}
				else
				{
					nband = ((nband & MSB_NIBBLE_MASK) >> 4);
					/* display the Nband */
					proto_tree_add_item(tree, hf_culmap_num_bands, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 1;
					if(max_logical_bands == 3)
					{
						proto_tree_add_item(tree, hf_culmap_band_index, tvb, ul_map_offset, (nband + nibble_offset), ENC_NA);
						length += (nband * 2);
						/* update offset */
						ul_map_offset += nband;
					}
					else
					{
						proto_tree_add_item(tree, hf_culmap_band_index, tvb, ul_map_offset, ((nband >> 1) + nibble_offset), ENC_NA);
						length += nband;
						/* update offset */
						ul_map_offset += ((nband + nibble_offset) >> 1);
						if(nband & 1)
							nibble_offset = 0;
					}
				}
				band_count = nband;
			}
			else
			{
				band_count = 1;
				/* display the Nb-BITMAP */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_nb_bitmap_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
					nibble_offset = 0;
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_nb_bitmap, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 1;
				}
				length++;
			}
			/* Get the Allocation Mode */
			byte = tvb_get_guint8(tvb, ul_map_offset);
			if(nibble_offset & 1)
			{
				allocation_mode = ((byte & ALLOCATION_MODE_MASK_1) >> 2);
				proto_tree_add_item(tree, hf_culmap_allocation_mode_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_culmap_allocation_mode_rsvd_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 0;
				ul_map_offset++;
			}
			else
			{
				allocation_mode = ((byte & ALLOCATION_MODE_MASK) >> 6);
				proto_tree_add_item(tree, hf_culmap_allocation_mode, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_culmap_allocation_mode_rsvd, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length++;
			/* Decode Allocation Mode - need to be done */
			if(!allocation_mode)
			{
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_num_subchannels_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_num_subchannels, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				ul_map_offset++;
				length += 2;
			}
			else if(allocation_mode == 1)
			{
				for(i=0; i<band_count; i++)
				{
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_culmap_num_subchannels_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_culmap_num_subchannels, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					}
					ul_map_offset++;
				}
				length += (band_count * 2);
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_ulmap_harq_control_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_UL_MAP_TYPE_SAFETY:/* 6.3.2.3.43.7.3 */
			/* display the UL-MAP type and reserved bit */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
				nibble_offset = 0;
			}
			else
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_ulmap_rcid_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
			ul_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_nep_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
					proto_tree_add_item(tree, hf_culmap_nsch_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_nep_code, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_nsch_code_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					ul_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened UIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_shortened_uiuc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_companded_sc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				ul_map_offset++;
				length += 2;
			}
			/* display BIN offset */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_culmap_bin_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
			}
			else
			{
				proto_tree_add_item(tree, hf_culmap_bin_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
			}
			length += 2;
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_ulmap_harq_control_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_UL_MAP_TYPE_UIUC:/* 6.3.2.3.43.7.4 */
			/* display the UL-MAP type and reserved bit */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				ul_map_offset++;
				/* get the new byte */
				byte = tvb_get_guint8(tvb, ul_map_offset);
				/* get the UIUC */
				uiuc = ((byte & MSB_NIBBLE_MASK) >> 4);
				/* display the UIUC */
				proto_tree_add_item(tree, hf_culmap_uiuc, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
			}
			else
			{
				/* display the UL-MAP type */
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_culmap_reserved, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the UIUC */
				uiuc = (byte & LSB_NIBBLE_MASK);
				/* display the UIUC */
				proto_tree_add_item(tree, hf_culmap_uiuc_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
			}
			length = 2;
			/* decode RCID IE */
			nibble_length = wimax_compact_ulmap_rcid_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
			ul_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			if(uiuc == 15)
			{	/* Extended UIUC dependent IE */
				nibble_length =  wimax_extended_uiuc_dependent_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
				length += nibble_length;
				ul_map_offset += (nibble_length >> 1);
				nibble_offset = (nibble_length & 1);
			}
			else if(uiuc == 14)
			{	/* CDMA Allocation IE */
				nibble_length =  wimax_cdma_allocation_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
				length += nibble_length;
				ul_map_offset += (nibble_length >> 1);
				nibble_offset = (nibble_length & 1);
			}
			else if(uiuc == 12)
			{
				if(nibble_offset & 1)
				{
					/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset_7_1, tvb, ul_map_offset, 4, ENC_BIG_ENDIAN);
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols_7_1, tvb, ul_map_offset, 4, ENC_BIG_ENDIAN);
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels_7_1, tvb, ul_map_offset, 4, ENC_BIG_ENDIAN);
					/* display the ranging method */
					proto_tree_add_item(tree, hf_culmap_uiuc_ranging_method_1, tvb, ul_map_offset, 4, ENC_BIG_ENDIAN);
					/* display the reserved */
					proto_tree_add_item(tree, hf_culmap_uiuc_reserved_1, tvb, ul_map_offset, 4, ENC_BIG_ENDIAN);
					ul_map_offset += 3;
				}
				else
				{	/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset_7, tvb, ul_map_offset, 3, ENC_BIG_ENDIAN);
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols_7, tvb, ul_map_offset, 3, ENC_BIG_ENDIAN);
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels_7, tvb, ul_map_offset, 3, ENC_BIG_ENDIAN);
					/* display the ranging method */
					proto_tree_add_item(tree, hf_culmap_uiuc_ranging_method, tvb, ul_map_offset, 3, ENC_BIG_ENDIAN);
					/* display the reserved */
					proto_tree_add_item(tree, hf_culmap_uiuc_reserved, tvb, ul_map_offset, 3, ENC_BIG_ENDIAN);
					ul_map_offset += 3;
				}
				length += 8;
			}
			else
			{	/* display Number of subchannels */
				if(nibble_offset & 1)
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
				else
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				length += 2;
				/* display the repetition coding indication and reserved bits */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_culmap_uiuc_repetition_coding_indication_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_uiuc_reserved_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 0;
				}
				else
				{
					proto_tree_add_item(tree, hf_culmap_uiuc_repetition_coding_indication, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_culmap_uiuc_reserved, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 1;
				}
				length += 1;
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_ulmap_harq_control_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_UL_MAP_TYPE_HARQ_REGION_IE:/* 6.3.2.3.43.7.5 */
			if(nibble_offset & 1)
			{	/* display the UL-MAP type */
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the HARQ Region Change Indication */
				proto_tree_add_item(tree, hf_culmap_harq_region_change_indication_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the HARQ Region Change Indication */
				harq_region_change_indication = (byte & 0x01);
				/* move to next byte */
				ul_map_offset++;
				nibble_offset = 0;
			}
			else
			{	/* display the UL-MAP type */
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the HARQ Region Change Indication */
				proto_tree_add_item(tree, hf_culmap_harq_region_change_indication, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the HARQ Region Change Indication */
				harq_region_change_indication = (byte & 0x10);
				nibble_offset = 1;
			}
			length = 1;
			if(harq_region_change_indication == 1)
			{
				if(nibble_offset & 1)
				{
					/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
				}
				else
				{	/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
				}
				length += 8;
			}
		break;
		case COMPACT_UL_MAP_TYPE_CQICH_REGION_IE:/* 6.3.2.3.43.7.6 */
			if(nibble_offset & 1)
			{	/* display the UL-MAP type */
				proto_tree_add_item(tree, hf_culmap_ul_map_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the CQI Region Change Indication */
				proto_tree_add_item(tree, hf_culmap_cqi_region_change_indication_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the CQI Region Change Indication */
				cqi_region_change_indication = (byte & 0x01);
				/* move to next byte */
				ul_map_offset++;
				nibble_offset = 0;
			}
			else
			{	/* display the UL-MAP type */
				proto_tree_add_item(tree, hf_culmap_ul_map_type, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the CQI Region Change Indication */
				proto_tree_add_item(tree, hf_culmap_cqi_region_change_indication, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the CQI Region Change Indication */
				cqi_region_change_indication = (byte & 0x10);
				nibble_offset = 1;
			}
			length = 1;
			if(cqi_region_change_indication == 1)
			{
				if(nibble_offset & 1)
				{
					/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels_1, tvb, ul_map_offset, 2, ENC_BIG_ENDIAN);
					ul_map_offset++;
				}
				else
				{	/* display the OFDMA symbol offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_ofdma_symbol_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the subchannel offset */
					proto_tree_add_item(tree, hf_culmap_uiuc_subchannel_offset, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of OFDMA symbols */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_ofdma_symbols, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
					/* display the number of subchannels */
					proto_tree_add_item(tree, hf_culmap_uiuc_num_of_subchannels, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
					ul_map_offset++;
				}
				length += 8;
			}
		break;
		case COMPACT_UL_MAP_TYPE_EXTENSION:/* 6.3.2.3.43.7.7 */
			/* decode the Compact UL-MAP externsion IE */
			nibble_length = wimax_culmap_extension_ie_decoder(tree, pinfo, tvb, ul_map_offset, nibble_offset);/*, cqich_indicator);*/
			length = nibble_length;
		break;
		default:/* Reserved Type */
			/* display the reserved type */
			proto_tree_add_item(tree, hf_culmap_reserved_type_1, tvb, ul_map_offset, 1, ENC_BIG_ENDIAN);
			length = 1;
		break;
	}
	/* Update the nibble_offset and length */
	return length;
}

/* Compact UL-MAP Reduced CID IE (6.3.2.3.43.3) decoder */
static guint wimax_compact_ulmap_rcid_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint length = 0;
	guint prefix;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RCID IE");
#endif
	if(nibble_offset & 1)
	{
		if(cid_type == CID_TYPE_NORMAL)
		{	/* display the normal CID */
			proto_tree_add_item(tree, hf_rcid_ie_normal_cid_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* Get the prefix bit */
			prefix = (tvb_get_guint8(tvb, offset) & 0x08);
			/* display the prefix */
			proto_tree_add_item(tree, hf_rcid_ie_prefix_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			if(prefix)
			{	/* display the CID11 */
				proto_tree_add_item(tree, hf_rcid_ie_cid11_3, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = 3;
			}
			else
			{
				 if(cid_type == CID_TYPE_RCID11)
				{	/* display the CID11 */
					proto_tree_add_item(tree, hf_rcid_ie_cid11_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 3;
				}
				else if(cid_type == CID_TYPE_RCID7)
				{	/* display the normal CID7 */
					proto_tree_add_item(tree, hf_rcid_ie_cid7_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 2;
				}
				else if(cid_type == CID_TYPE_RCID3)
				{	/* display the CID3 */
					proto_tree_add_item(tree, hf_rcid_ie_cid3_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 1;
				}
			}
		}
	}
	else
	{
		if(cid_type == CID_TYPE_NORMAL)
		{	/* display the normal CID */
			proto_tree_add_item(tree, hf_rcid_ie_normal_cid, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* Get the prefix bit */
			prefix = (tvb_get_guint8(tvb, offset) & 0x08);
			/* display the prefix */
			proto_tree_add_item(tree, hf_rcid_ie_prefix, tvb, offset, 2, ENC_BIG_ENDIAN);
			if(prefix || (cid_type == CID_TYPE_RCID11))
			{	/* display the CID11 */
				proto_tree_add_item(tree, hf_rcid_ie_cid11_2, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = 3;
			}
			else
			{
				if(cid_type == CID_TYPE_RCID11)
				{	/* display the CID11 */
					proto_tree_add_item(tree, hf_rcid_ie_cid11, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 3;
				}
				else if(cid_type == CID_TYPE_RCID7)
				{	/* display the CID7 */
					proto_tree_add_item(tree, hf_rcid_ie_cid7, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 2;
				}
				else if(cid_type == CID_TYPE_RCID3)
				{	/* display the CID3 */
					proto_tree_add_item(tree, hf_rcid_ie_cid3, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 1;
				}
			}
		}
	}
	/* return the IE length in nibbles */
	return length;
}

/* Compact UL-MAP HARQ Control IE (6.3.2.3.43.4) decoder */
static guint wimax_compact_ulmap_harq_control_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint byte, prefix, length = 0;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "HARQ Control IE");
#endif
	/* Get the first byte */
	byte = tvb_get_guint8(tvb, offset);
	if(nibble_offset & 1)
	{	/* Get the prefix bit */
		prefix = (byte & 0x08);
		/* display the prefix */
		proto_tree_add_item(tree, hf_harq_control_ie_prefix_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		if(prefix)
		{	/* display the ai_sn */
			proto_tree_add_item(tree, hf_harq_control_ie_ai_sn_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the spid */
			proto_tree_add_item(tree, hf_harq_control_ie_spid_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the acid */
			proto_tree_add_item(tree, hf_harq_control_ie_acid_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = 2;
		}
		else
		{	/* display the reserved bits */
			proto_tree_add_item(tree, hf_harq_control_ie_reserved_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = 1;
		}
	}
	else
	{	/* Get the prefix bit */
		prefix = (byte & 0x80);
		/* display the prefix */
		proto_tree_add_item(tree, hf_harq_control_ie_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
		if(prefix)
		{	/* display the ai_sn */
			proto_tree_add_item(tree, hf_harq_control_ie_ai_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* display the spid */
			proto_tree_add_item(tree, hf_harq_control_ie_spid, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* display the acid */
			proto_tree_add_item(tree, hf_harq_control_ie_acid, tvb, offset, 1, ENC_BIG_ENDIAN);
			length = 2;
		}
		else
		{	/* display the reserved bits */
			proto_tree_add_item(tree, hf_harq_control_ie_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
			length = 1;
		}
	}
	/* return the IE length in nibbles */
	return length;
}

/* UL-MAP Extension IE sub-types */
#define HARQ_MODE_SWITCH          0
#define EXTENSION_TYPE_SHIFT      13
#define EXTENSION_TYPE_SHIFT_1    9
#define EXTENSION_SUBTYPE_SHIFT   8
#define EXTENSION_SUBTYPE_SHIFT_1 4
#define EXTENSION_LENGTH_SHIFT    4

/* Compact UL-MAP Extension IE (6.3.2.3.43.7.7) decoder */
static guint wimax_culmap_extension_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint tvb_value, ul_map_type, sub_type, length;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "UL-MAP Extension IE");
#endif
	/* Get the first 16-bit word */
	tvb_value = tvb_get_ntohs(tvb, offset);
	if(nibble_offset & 1)
	{	/* Get the ul-map type */
		ul_map_type = ((tvb_value & EXTENSION_TYPE_MASK_1) >> EXTENSION_TYPE_SHIFT_1);
		if(ul_map_type != COMPACT_UL_MAP_TYPE_EXTENSION)
			return 0;
		/* Get the sub-type */
		sub_type = ((tvb_value & EXTENSION_SUBTYPE_MASK_1) >> EXTENSION_SUBTYPE_SHIFT_1);
		/* Get the IE length */
		length = (tvb_value & EXTENSION_LENGTH_MASK_1);
		/* display the UL-MAP type */
		proto_tree_add_item(tree, hf_culmap_extension_type_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the UL-MAP extension subtype */
		proto_tree_add_item(tree, hf_culmap_extension_subtype_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the IE length */
		proto_tree_add_item(tree, hf_culmap_extension_length_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		switch (sub_type)
		{
			case HARQ_MODE_SWITCH:
				/* display the HARQ mode */
				proto_tree_add_item(tree, hf_culmap_extension_harq_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* Get the next byte */
				tvb_value = tvb_get_guint8(tvb, offset);
				/* get the HARQ mode */
				harq_mode = ((tvb_value & MSB_NIBBLE_MASK) >> 4);
			break;
			default:
				/* display the unknown sub-type in HEX */
				proto_tree_add_item(tree, hf_culmap_extension_unknown_sub_type_1, tvb, offset, (length - 2), ENC_NA);
			break;
		}
	}
	else
	{	/* Get the UL-MAp type */
		ul_map_type = ((tvb_value & EXTENSION_TYPE_MASK) >> EXTENSION_TYPE_SHIFT);
		if(ul_map_type != COMPACT_UL_MAP_TYPE_EXTENSION)
			return 0;
		/* Get the sub-type */
		sub_type = ((tvb_value & EXTENSION_SUBTYPE_MASK) >> EXTENSION_SUBTYPE_SHIFT);
		/* Get the IE length */
		length = ((tvb_value & EXTENSION_LENGTH_MASK) >> EXTENSION_LENGTH_SHIFT);
		/* display the UL-MAP type */
		proto_tree_add_item(tree, hf_culmap_extension_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the UL-MAP extension subtype */
		proto_tree_add_item(tree, hf_culmap_extension_subtype, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the IE length */
		proto_tree_add_item(tree, hf_culmap_extension_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		switch (sub_type)
		{
			case HARQ_MODE_SWITCH:
				/* display the HARQ mode */
				proto_tree_add_item(tree, hf_culmap_extension_harq_mode_1, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* get the HARQ mode */
				harq_mode = (tvb_value & LSB_NIBBLE_MASK);
			break;
			default:
				/* display the unknown sub-type in HEX */
				proto_tree_add_item(tree, hf_culmap_extension_unknown_sub_type, tvb, (offset + 1), (length - 1), ENC_NA);
			break;
		}
	}
	/* return the IE length in nibbles */
	return (length * 2);
}

/* 8.4.5.4.3 (table 290) */
guint wimax_cdma_allocation_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CDMA Allocation IE");
#endif
	if(nibble_offset & 1)
	{	/* display the Duration */
		proto_tree_add_item(tree, hf_cdma_allocation_duration_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the UIUC */
		proto_tree_add_item(tree, hf_cdma_allocation_uiuc_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Repetition Coding Indication */
		proto_tree_add_item(tree, hf_cdma_allocation_repetition_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the frame number index */
		proto_tree_add_item(tree, hf_cdma_allocation_frame_number_index_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		/* display the Ranging Code */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_code_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		/* display the Ranging Symbol */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_symbol_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		/* display the Ranging Subchannel */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_subchannel_1, tvb, offset, 4, ENC_BIG_ENDIAN);
		/* display the BW Request Mandatory */
		proto_tree_add_item(tree, hf_cdma_allocation_bw_req_1, tvb, offset, 4, ENC_BIG_ENDIAN);
	}
	else
	{	/* display the Duration */
		proto_tree_add_item(tree, hf_cdma_allocation_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the UIUC */
		proto_tree_add_item(tree, hf_cdma_allocation_uiuc, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Repetition Coding Indication */
		proto_tree_add_item(tree, hf_cdma_allocation_repetition, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the frame number index */
		proto_tree_add_item(tree, hf_cdma_allocation_frame_number_index, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the Ranging Code */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_code, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Ranging Symbol */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_symbol, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the Ranging Subchannel */
		proto_tree_add_item(tree, hf_cdma_allocation_ranging_subchannel, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display the BW Request Mandatory */
		proto_tree_add_item(tree, hf_cdma_allocation_bw_req, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	/* return the IE length in nibbles */
	return 8;
}

/* Extended UIUCs (table 290a) */
#define POWER_CONTROL_IE                   0
#define MINI_SUBCHANNEL_ALLOCATION_IE      1
#define AAS_UL_IE                          2
#define CQICH_ALLOC_IE                     3
#define UL_ZONE_IE                         4
#define PHYMOD_UL_IE                       5
#define MIMO_UL_BASIC_IE                   6
#define UL_MAP_FAST_TRACKING_IE            7
#define UL_PUSC_BURST_ALLOCATION_IN_OTHER_SEGMENT_IE 8
#define FAST_RANGING_IE                    9
#define UL_ALLOCATION_START_IE             10

/* 8.4.5.4.4.1 (table 290b) */
guint wimax_extended_uiuc_dependent_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint ext_uiuc, length, m, i;
	guint8 byte;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Extended UIUC IE");
#endif

	/* get the first byte */
	byte =  tvb_get_guint8(tvb, offset);
	if(nibble_offset & 1)
	{	/* get the extended UIUC */
		ext_uiuc = (byte & LSB_NIBBLE_MASK);
		/* display extended UIUC */
		proto_tree_add_item(tree, hf_extended_uiuc_ie_uiuc_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next byte */
		offset++;
		/* get the 2nd byte */
		byte =  tvb_get_guint8(tvb, offset);
		/* get the length */
		length = ((byte & MSB_NIBBLE_MASK) >> 4);
		/* display extended UIUC length */
		proto_tree_add_item(tree, hf_extended_uiuc_ie_length_1, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	else
	{	/* get the extended UIUC */
		ext_uiuc = ((byte & MSB_NIBBLE_MASK) >> 4);
		/* get the length */
		length = (byte & LSB_NIBBLE_MASK);
		/* display extended UIUC */
		proto_tree_add_item(tree, hf_extended_uiuc_ie_uiuc, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display extended UIUC length */
		proto_tree_add_item(tree, hf_extended_uiuc_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next byte */
		offset++;
	}
	/* 8.4.5.4.4.1 (table 290b) */
	switch (ext_uiuc)
	{
		case POWER_CONTROL_IE:
			/* 8.4.5.4.5 Power Control IE */
			if(nibble_offset & 1)
			{	/* display power control value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_power_control_24, tvb, offset, 3, ENC_BIG_ENDIAN);
				/* display power measurement frame value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_power_measurement_frame_24, tvb, offset, 3, ENC_BIG_ENDIAN);
			}
			else
			{	/* display power control value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_power_control, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* display power measurement frame value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_power_measurement_frame, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
			}
		break;
		case MINI_SUBCHANNEL_ALLOCATION_IE:
			/* 8.4.5.4.8 Mini Subchannel Allocation IE */
			/* set the M value */
			switch (length)
			{
				case 15:
					m = 6;
				break;
				case 9:
					m = 3;
				break;
				case 7:
				default:
					m = 2;
				break;
			}
			if(nibble_offset & 1)
			{
				/* display MINI Subchannel Allocation CType value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_ctype_16, tvb, offset, 2, ENC_BIG_ENDIAN);
				/* display MINI Subchannel Allocation Duration value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_duration_16, tvb, offset, 2, ENC_BIG_ENDIAN);
			}
			else
			{	/* display MINI Subchannel Allocation CType value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_ctype, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* display MINI Subchannel Allocation Duration value */
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_duration, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			offset++;
			/* decode and display CIDs, UIUCs, and Repetitions */
			for(i=0; i<m; i+=2)
			{
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_cid_1, tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_1, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_1, tvb, offset, 4, ENC_BIG_ENDIAN);
					if(i < (m-2))
					{
						offset += 3;
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_cid_3, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_3, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 2;
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_3, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 3;
					}
					else if(m == 3)
					{
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_padding_1, tvb, offset, 4, ENC_BIG_ENDIAN);
					}
				}
				else
				{
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_cid, tvb, offset, 3, ENC_BIG_ENDIAN);
					offset += 2;
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_repetition, tvb, offset, 3, ENC_BIG_ENDIAN);
					offset += 3;
					if(i < (m-2))
					{
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_cid_2, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 2;
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_2, tvb, offset, 4, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_2, tvb, offset, 4, ENC_BIG_ENDIAN);
						offset += 4;
					}
					else if(m == 3)
					{
						proto_tree_add_item(tree, hf_extended_uiuc_ie_mini_subchannel_alloc_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
					}
				}
			}
		break;
		case AAS_UL_IE:
			/* 8.4.5.4.6 AAS UL IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_aas_ul, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_aas_ul, tvb, offset, length, ENC_NA);
			}
		break;
		case CQICH_ALLOC_IE:
			/* 8.4.5.4.12 CQICH_ALLOC_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_cqich_alloc, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_cqich_alloc, tvb, offset, length, ENC_NA);
			}
		break;
		case UL_ZONE_IE:
			/* 8.4.5.4.7 UL Zone Switch IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_zone, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_zone, tvb, offset, length, ENC_NA);
			}
		break;
		case PHYMOD_UL_IE:
			/* 8.4.5.4.14 PHYMOD_UL_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_phymod_ul, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_phymod_ul, tvb, offset, length, ENC_NA);
			}
		break;
		case MIMO_UL_BASIC_IE:
			/* 8.4.5.4.11 MIMO_UL_BASIC_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mimo_ul_basic, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_mimo_ul_basic, tvb, offset, length, ENC_NA);
			}
		break;
		case UL_MAP_FAST_TRACKING_IE:
			/* 8.4.5.4.22 UL_MAP_FAST_TRACKING_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_fast_tracking, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_fast_tracking, tvb, offset, length, ENC_NA);
			}
		break;
		case UL_PUSC_BURST_ALLOCATION_IN_OTHER_SEGMENT_IE:
			/* 8.4.5.4.17 UL PUSC Burst Allocation in Other Segment IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_pusc_burst_allocation, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_pusc_burst_allocation, tvb, offset, length, ENC_NA);
			}
		break;
		case FAST_RANGING_IE:
			/* 8.4.5.4.21 FAST_RANGING_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_fast_ranging, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_fast_ranging, tvb, offset, length, ENC_NA);
			}
		break;
		case UL_ALLOCATION_START_IE:
			/* 8.4.5.4.15`UL_ALLOCATION_START_IE */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_allocation_start, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_ul_allocation_start, tvb, offset, length, ENC_NA);
			}
		break;
		default:
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_unknown_uiuc, tvb, offset, (length + 1), ENC_NA);
			}
			else
			{
				proto_tree_add_item(tree, hf_extended_uiuc_ie_unknown_uiuc, tvb, offset, length, ENC_NA);
			}
		break;
	}
	return ((length + 1) * 2 ); /* length in nibbles */
}

/* Register Wimax Compact UL-MAP IE Protocol */
void proto_register_wimax_compact_ulmap_ie(void)
{
	/* Compact UL-MAP IE display */
	static hf_register_info hf_compact_ulmap[] =
	{
		{
			&hf_culmap_ul_map_type,
			{"UL-MAP Type", "wmx.compact_ulmap.ul_map_type", FT_UINT8, BASE_DEC, NULL, UL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_ul_map_type_1,
			{"UL-MAP Type", "wmx.compact_ulmap.ul_map_type", FT_UINT8, BASE_DEC, NULL, UL_MAP_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_reserved,
			{"Reserved", "wmx.compact_ulmap.reserved", FT_UINT8, BASE_HEX, NULL, UL_MAP_RESERVED_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_reserved_1,
			{"Reserved", "wmx.compact_ulmap.reserved", FT_UINT8, BASE_HEX, NULL, UL_MAP_RESERVED_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_nep_code,
			{"Nep Code", "wmx.compact_ulmap.nep_code", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_nep_code_1,
			{"Nep Code", "wmx.compact_ulmap.nep_code", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_nsch_code,
			{"Nsch Code", "wmx.compact_ulmap.nsch_code", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_nsch_code_1,
			{"Nsch Code", "wmx.compact_ulmap.nsch_code", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_shortened_uiuc,
			{"Shortened UIUC", "wmx.compact_ulmap.shortened_uiuc", FT_UINT8, BASE_HEX, NULL, SHORTENED_UIUC_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_companded_sc,
			{"Companded SC", "wmx.compact_ulmap.companded_sc", FT_UINT8, BASE_HEX, NULL, COMPANDED_SC_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_shortened_uiuc_1,
			{"Shortened UIUC", "wmx.compact_ulmap.shortened_uiuc", FT_UINT16, BASE_HEX, NULL, SHORTENED_UIUC_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_companded_sc_1,
			{"Companded SC", "wmx.compact_ulmap.companded_sc", FT_UINT16, BASE_HEX, NULL, COMPANDED_SC_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_num_bands,
			{"Number Of Bands", "wmx.compact_ulmap.num_bands", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_num_bands_1,
			{"Number Of Bands", "wmx.compact_ulmap.num_bands", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_band_index,
			{"Band Index", "wmx.compact_ulmap.band_index", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_nb_bitmap,
			{"Number Of Bits For Band BITMAP", "wmx.compact_ulmap.nb_bitmap", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_nb_bitmap_1,
			{"Number Of Bits For Band BITMAP", "wmx.compact_ulmap.nb_bitmap", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_allocation_mode,
			{"Allocation Mode", "wmx.compact_ulmap.allocation_mode", FT_UINT8, BASE_DEC, VALS(vals_allocation_modes), ALLOCATION_MODE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_allocation_mode_1,
			{"Allocation Mode", "wmx.compact_ulmap.allocation_mode", FT_UINT8, BASE_DEC, VALS(vals_allocation_modes), ALLOCATION_MODE_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_allocation_mode_rsvd,
			{"Reserved", "wmx.compact_ulmap.allocation_mode_rsvd", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL}
		},
		{
			&hf_culmap_allocation_mode_rsvd_1,
			{"Reserved", "wmx.compact_ulmap.allocation_mode_rsvd", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL}
		},
		{
			&hf_culmap_num_subchannels,
			{"Number Of Subchannels", "wmx.compact_ulmap.num_subchannels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_num_subchannels_1,
			{"Number Of Subchannels", "wmx.compact_ulmap.num_subchannels", FT_UINT16, BASE_DEC, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_bin_offset,
			{"BIN Offset", "wmx.compact_ulmap.bin_offset", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_bin_offset_1,
			{"BIN Offset", "wmx.compact_ulmap.bin_offset", FT_UINT16, BASE_HEX, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc,
			{"UIUC", "wmx.compact_ulmap.uiuc", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_1,
			{"UIUC", "wmx.compact_ulmap.uiuc", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_ofdma_symbol_offset,
			{"OFDMA Symbol Offset", "wmx.compact_ulmap.uiuc_ofdma_symbol_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_ofdma_symbol_offset_1,
			{"OFDMA Symbol Offset", "wmx.compact_ulmap.uiuc_ofdma_symbol_offset", FT_UINT16, BASE_DEC, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_subchannel_offset_7,
			{"Subchannel Offset", "wmx.compact_ulmap.uiuc_subchannel_offset", FT_UINT24, BASE_DEC, NULL, 0xFE0000, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_ofdma_symbols_7,
			{"Number Of OFDMA Symbols", "wmx.compact_ulmap.uiuc_num_of_ofdma_symbols", FT_UINT24, BASE_DEC, NULL, 0x01FC00, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_subchannels_7,
			{"Number Of Subchannels", "wmx.compact_ulmap.uiuc_num_of_subchannels", FT_UINT24, BASE_DEC, NULL, 0x0003F8, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_ranging_method,
			{"Ranging Method", "wmx.compact_ulmap.uiuc_ranging_method", FT_UINT24, BASE_DEC, NULL, 0x000006, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_reserved,
			{"Reserved", "wmx.compact_ulmap.uiuc_reserved", FT_UINT24, BASE_HEX, NULL, 0x000001, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_subchannel_offset_7_1,
			{"Subchannel Offset", "wmx.compact_ulmap.uiuc_subchannel_offset", FT_UINT32, BASE_DEC, NULL, 0x00FE0000, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_ofdma_symbols_7_1,
			{"Number Of OFDMA Symbols", "wmx.compact_ulmap.uiuc_num_of_ofdma_symbols", FT_UINT32, BASE_DEC, NULL, 0x0001FC00, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_subchannels_7_1,
			{"Number Of Subchannels", "wmx.compact_ulmap.uiuc_num_of_subchannels", FT_UINT32, BASE_DEC, NULL, 0x000003F80, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_ranging_method_1,
			{"Ranging Method", "wmx.compact_ulmap.uiuc_ranging_method", FT_UINT32, BASE_DEC, NULL, 0x00000006, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_reserved_1,
			{"Reserved", "wmx.compact_ulmap.uiuc_reserved", FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_repetition_coding_indication,
			{"Repetition Coding Indication", "wmx.compact_ulmap.uiuc_repetition_coding_indication", FT_UINT8, BASE_DEC, VALS(vals_repetitions), ALLOCATION_MODE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_repetition_coding_indication_1,
			{"Repetition Coding Indication", "wmx.compact_ulmap.uiuc_repetition_coding_indication", FT_UINT8, BASE_DEC, VALS(vals_repetitions), ALLOCATION_MODE_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_reserved1,
			{"Reserved", "wmx.compact_ulmap.uiuc_reserved1", FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_reserved11_1,
			{"Reserved", "wmx.compact_ulmap.uiuc_reserved1", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
		},

		{
			&hf_culmap_uiuc_subchannel_offset,
			{"Subchannel Offset", "wmx.compact_ulmap.uiuc_subchannel_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_subchannel_offset_1,
			{"Subchannel Offset", "wmx.compact_ulmap.uiuc_subchannel_offset", FT_UINT16, BASE_DEC, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_ofdma_symbols,
			{"Number Of OFDMA Symbols", "wmx.compact_ulmap.uiuc_num_of_ofdma_symbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_ofdma_symbols_1,
			{"Number Of OFDMA Symbols", "wmx.compact_ulmap.uiuc_num_of_ofdma_symbols", FT_UINT16, BASE_DEC, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_subchannels,
			{"Number Of Subchannels", "wmx.compact_ulmap.uiuc_num_of_subchannels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_uiuc_num_of_subchannels_1,
			{"Number Of Subchannels", "wmx.compact_ulmap.uiuc_num_of_subchannels", FT_UINT16, BASE_DEC, NULL, MIDDLE_BYTE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_harq_region_change_indication,
			{"HARQ Region Change Indication", "wmx.compact_ulmap.harq_region_change_indication", FT_BOOLEAN, 8, TFS(&tfs_region_change), 0x10, NULL, HFILL}
		},
		{
			&hf_culmap_harq_region_change_indication_1,
			{"HARQ Region Change Indication", "wmx.compact_ulmap.harq_region_change_indication", FT_BOOLEAN, 8, TFS(&tfs_region_change), 0x01, NULL, HFILL}
		},
		{
			&hf_culmap_cqi_region_change_indication,
			{"CQI Region Change Indication", "wmx.compact_ulmap.cqi_region_change_indication", FT_BOOLEAN, 8, TFS(&tfs_region_change), 0x10, NULL, HFILL}
		},
		{
			&hf_culmap_cqi_region_change_indication_1,
			{"CQI Region Change Indication", "wmx.compact_ulmap.cqi_region_change_indication", FT_BOOLEAN, 8, TFS(&tfs_region_change), 0x01, NULL, HFILL}
		},
		{
			&hf_culmap_reserved_type,
			{"UL-MAP Reserved Type", "wmx.compact_ulmap.reserved_type", FT_UINT8, BASE_DEC, NULL, UL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_reserved_type_1,
			{"UL-MAP Reserved Type", "wmx.compact_ulmap.reserved_type", FT_UINT8, BASE_DEC, NULL, UL_MAP_TYPE_MASK_1, NULL, HFILL}
		}
	};

	/* HARQ MAP Reduced CID IE display */
	static hf_register_info hf_rcid[] =
	{
		{
			&hf_rcid_ie_normal_cid,
			{"Normal CID", "wmx.harq_map.rcid_ie.normal_cid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_rcid_ie_normal_cid_1,
			{"Normal CID", "wmx.harq_map.rcid_ie.normal_cid", FT_UINT24, BASE_HEX, NULL, WIMAX_RCID_IE_NORMAL_CID_MASK_1, NULL, HFILL}
		},
		{
			&hf_rcid_ie_prefix,
			{"Prefix", "wmx.harq_map.rcid_ie.prefix", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_PREFIX_MASK, NULL, HFILL}
		},
		{
			&hf_rcid_ie_prefix_1,
			{"Prefix", "wmx.harq_map.rcid_ie.prefix", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_PREFIX_MASK_1, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid3,
			{"3 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid3", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID3_MASK, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid3_1,
			{"3 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid3", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID3_MASK_1, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid7,
			{"7 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid7", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID7_MASK, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid7_1,
			{"7 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid7", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID7_MASK_1, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid11,
			{"11 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid11_1,
			{"11 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK_1, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid11_2,
			{"11 LSB Of Multicast, AAS or Broadcast CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK, NULL, HFILL}
		},
		{
			&hf_rcid_ie_cid11_3,
			{"11 LSB Of Multicast, AAS or Broadcast CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK_1, NULL, HFILL}
		}
	};

	/* HARQ MAP HARQ Control IE display */
	static hf_register_info hf_harq_control[] =
	{
		{
			&hf_harq_control_ie_prefix,
			{"Prefix", "wmx.harq_map.harq_control_ie.prefix", FT_BOOLEAN, 8, TFS(&tfs_prefix), WIMAX_HARQ_CONTROL_IE_PREFIX_MASK, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_ai_sn,
			{"HARQ ID Sequence Number(AI_SN)", "wmx.harq_map.harq_control_ie.ai_sn", FT_UINT8, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_AI_SN_MASK, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_spid,
			{"Subpacket ID (SPID)", "wmx.harq_map.harq_control_ie.spid", FT_UINT8, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_SPID_MASK, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_acid,
			{"HARQ CH ID (ACID)", "wmx.harq_map.harq_control_ie.acid", FT_UINT8, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_ACID_MASK, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_reserved,
			{"Reserved", "wmx.harq_map.harq_control_ie.reserved", FT_UINT8, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_RESERVED_MASK, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_prefix_1,
			{"Prefix", "wmx.harq_map.harq_control_ie.prefix", FT_BOOLEAN, 16, TFS(&tfs_prefix), WIMAX_HARQ_CONTROL_IE_PREFIX_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_ai_sn_1,
			{"HARQ ID Sequence Number(AI_SN)", "wmx.harq_map.harq_control_ie.ai_sn", FT_UINT16, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_AI_SN_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_spid_1,
			{"Subpacket ID (SPID)", "wmx.harq_map.harq_control_ie.spid", FT_UINT16, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_SPID_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_acid_1,
			{"HARQ CH ID (ACID)", "wmx.harq_map.harq_control_ie.acid", FT_UINT16, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_ACID_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_control_ie_reserved_1,
			{"Reserved", "wmx.harq_map.harq_control_ie.reserved", FT_UINT16, BASE_HEX, NULL, WIMAX_HARQ_CONTROL_IE_RESERVED_MASK_1, NULL, HFILL}
		}
	};

	static hf_register_info hf_extension_type[] =
	{
		{
			&hf_culmap_extension_type,
			{"UL-MAP Type", "wmx.extension_type.ul_map_type", FT_UINT16, BASE_DEC, NULL, EXTENSION_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_extension_type_1,
			{"UL-MAP Type", "wmx.extension_type.ul_map_type", FT_UINT16, BASE_DEC, NULL, EXTENSION_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_extension_subtype,
			{"Extension Subtype", "wmx.extension_type.subtype", FT_UINT16, BASE_DEC, NULL, EXTENSION_SUBTYPE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_extension_subtype_1,
			{"Extension Subtype", "wmx.extension_type.subtype", FT_UINT16, BASE_DEC, NULL, EXTENSION_SUBTYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_extension_length,
			{"Extension Length", "wmx.extension_type.length", FT_UINT16, BASE_DEC, NULL, EXTENSION_LENGTH_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_extension_length_1,
			{"Extension Length", "wmx.extension_type.length", FT_UINT16, BASE_DEC, NULL, EXTENSION_LENGTH_MASK_1, NULL, HFILL}
		},
		{
			&hf_culmap_extension_time_diversity_mbs,
			{"Time Diversity MBS", "wmx.extension_type.time_diversity_mbs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_extension_time_diversity_mbs_1,
			{"Time Diversity MBS", "wmx.extension_type.time_diversity_mbs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_extension_harq_mode_1,
			{"HARQ Mode Switch", "wmx.extension_type.harq_mode", FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL}
		},
		{
			&hf_culmap_extension_harq_mode,
			{"HARQ Mode Switch", "wmx.extension_type.harq_mode", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_culmap_extension_unknown_sub_type,
			{"Unknown Extension Subtype", "wmx.extension_type.unknown_sub_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_culmap_extension_unknown_sub_type_1,
			{"Unknown Extension Subtype", "wmx.extension_type.unknown_sub_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	static hf_register_info hf_cdma_allocation[] =
	{
		{	/* display the Duration */
			&hf_cdma_allocation_duration,
			{"Duration", "wmx.cdma_allocation.duration", FT_UINT16, BASE_DEC, NULL, CDMA_ALLOCATION_DURATION_MASK, NULL, HFILL}
		},
		{	/* display the UIUC */
			&hf_cdma_allocation_uiuc,
			{"UIUC For Transmission", "wmx.cdma_allocation.uiuc", FT_UINT16, BASE_DEC, NULL, CDMA_ALLOCATION_UIUC_MASK, NULL, HFILL}
		},
		{	/* display the Repetition Coding Indication */
			&hf_cdma_allocation_repetition,
			{"Repetition Coding Indication", "wmx.cdma_allocation.allocation_repetition", FT_UINT16, BASE_DEC, VALS(vals_repetitions), CDMA_ALLOCATION_REPETITION_CODE_MASK, NULL, HFILL}
		},
		{	/* display the Frame Number Index */
			&hf_cdma_allocation_frame_number_index,
			{"Frame Number Index (LSBs of relevant frame number)", "wmx.cdma_allocation.frame_number_index", FT_UINT16, BASE_DEC, NULL, CDMA_ALLOCATION_FRAME_NUMBER_INDEX_MASK, NULL, HFILL}
		},
		{	/* display the Ranging Code */
			&hf_cdma_allocation_ranging_code,
			{"Ranging Code", "wmx.cdma_allocation.ranging_code", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* display the Ranging Symbol */
			&hf_cdma_allocation_ranging_symbol,
			{"Ranging Symbol", "wmx.cdma_allocation.ranging_symbol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* display the Ranging Subchannel */
			&hf_cdma_allocation_ranging_subchannel,
			{"Ranging Subchannel", "wmx.cdma_allocation.ranging_subchannel", FT_UINT8, BASE_DEC, NULL, CDMA_ALLOCATION_RANGING_SUBCHANNEL_MASK, NULL, HFILL}
		},
		{	/* display the BW Request Mandatory */
			&hf_cdma_allocation_bw_req,
			{"BW Request Mandatory", "wmx.cdma_allocation.bw_req", FT_BOOLEAN, 8, TFS(&tfs_yes_no_ie), CDMA_ALLOCATION_BW_REQUEST_MANDATORY_MASK, NULL, HFILL}
		},
		{	/* display the Duration */
			&hf_cdma_allocation_duration_1,
			{"Duration", "wmx.cdma_allocation.duration", FT_UINT16, BASE_DEC, NULL, CDMA_ALLOCATION_DURATION_MASK_1, NULL, HFILL}
		},
		{	/* display the UIUC */
			&hf_cdma_allocation_uiuc_1,
			{"UIUC For Transmission", "wmx.cdma_allocation.uiuc", FT_UINT16, BASE_DEC, NULL, CDMA_ALLOCATION_UIUC_MASK_1, NULL, HFILL}
		},
		{	/* display the Repetition Coding Indication */
			&hf_cdma_allocation_repetition_1,
			{"Repetition Coding Indication", "wmx.cdma_allocation.allocation_repetition", FT_UINT16, BASE_DEC, VALS(vals_repetitions), CDMA_ALLOCATION_REPETITION_CODE_MASK_1, NULL, HFILL}
		},
		{	/* display the Frame Number Index */
			&hf_cdma_allocation_frame_number_index_1,
			{"Frame Number Index (LSBs of relevant frame number)", "wmx.cdma_allocation.frame_number_index", FT_UINT32, BASE_DEC, NULL, CDMA_ALLOCATION_FRAME_NUMBER_INDEX_MASK_1, NULL, HFILL}
		},
		{	/* display the Ranging Code */
			&hf_cdma_allocation_ranging_code_1,
			{"Ranging Code", "wmx.cdma_allocation.ranging_code", FT_UINT32, BASE_DEC, NULL, CDMA_ALLOCATION_RANGING_CODE_MASK_1, NULL, HFILL}
		},
		{	/* display the Ranging Symbol */
			&hf_cdma_allocation_ranging_symbol_1,
			{"Ranging Symbol", "wmx.cdma_allocation.ranging_symbol", FT_UINT32, BASE_DEC, NULL, CDMA_ALLOCATION_RANGING_SYMBOL_MASK_1, NULL, HFILL}
		},
		{	/* display the Ranging Subchannel */
			&hf_cdma_allocation_ranging_subchannel_1,
			{"Ranging Subchannel", "wmx.cdma_allocation.ranging_subchannel", FT_UINT32, BASE_DEC, NULL, CDMA_ALLOCATION_RANGING_SUBCHANNEL_MASK_1, NULL, HFILL}
		},
		{	/* display the BW Request Mandatory */
			&hf_cdma_allocation_bw_req_1,
			{"BW Request Mandatory", "wmx.cdma_allocation.bw_req", FT_BOOLEAN, 32, TFS(&tfs_yes_no_ie), CDMA_ALLOCATION_BW_REQUEST_MANDATORY_MASK_1, NULL, HFILL}
		}
	};

	static hf_register_info hf_extended_uiuc[] =
	{
		{	/* 8.4.5.4.4 Extended UIUC */
			&hf_extended_uiuc_ie_uiuc,
			{"Extended UIUC", "wmx.extended_uiuc_ie.uiuc", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL }
		},
		{	/* 8.4.5.4.4 Extended UIUC */
			&hf_extended_uiuc_ie_uiuc_1,
			{"Extended UIUC", "wmx.extended_uiuc_ie.uiuc", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL }
		},
		{	/* 8.4.5.4.4 IE Length */
			&hf_extended_uiuc_ie_length,
			{"Length", "wmx.extended_uiuc_ie.length", FT_UINT8, BASE_DEC, NULL, MSB_NIBBLE_MASK, NULL, HFILL }
		},
		{	/* 8.4.5.4.4 IE Length */
			&hf_extended_uiuc_ie_length_1,
			{"Length", "wmx.extended_uiuc_ie.length", FT_UINT24, BASE_DEC, NULL, LSB_NIBBLE_MASK, NULL, HFILL }
		},
		{	/* 8.4.5.4.5 Power Control IE */
			&hf_extended_uiuc_ie_power_control,
			{"Power Control", "wmx.extended_uiuc_ie.power_control", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.5 Power Control IE */
			&hf_extended_uiuc_ie_power_control_24,
			{"Power Control", "wmx.extended_uiuc_ie.power_control", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_power_measurement_frame,
			{"Power Measurement Frame", "wmx.extended_uiuc_ie.power_measurement_frame", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_power_measurement_frame_24,
			{"Power Measurement Frame", "wmx.extended_uiuc_ie.power_measurement_frame", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.8 Mini Subchannel Allocation IE */
			&hf_extended_uiuc_ie_mini_subchannel_alloc_ctype,
			{"C Type", "wmx.extended_uiuc_ie.mini_subchannel_alloc.ctype", FT_UINT8, BASE_HEX, VALS(vals_ctypes), MINI_SUBCHANNEL_CTYPE_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_ctype_16,
			{"C Type", "wmx.extended_uiuc_ie.mini_subchannel_alloc.ctype", FT_UINT16, BASE_HEX, VALS(vals_ctypes), MINI_SUBCHANNEL_CTYPE_MASK_16, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_duration,
			{"Duration", "wmx.extended_uiuc_ie.mini_subchannel_alloc.duration", FT_UINT8, BASE_DEC, NULL, MINI_SUBCHANNEL_DURATION_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_duration_16,
			{"Duration", "wmx.extended_uiuc_ie.mini_subchannel_alloc.duration", FT_UINT16, BASE_DEC, NULL, MINI_SUBCHANNEL_DURATION_MASK_16, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_cid,
			{"CID", "wmx.extended_uiuc_ie.mini_subchannel_alloc.cid", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_CID_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc,
			{"UIUC", "wmx.extended_uiuc_ie.mini_subchannel_alloc.uiuc", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_UIUC_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_repetition,
			{"Repetition", "wmx.extended_uiuc_ie.mini_subchannel_alloc.repetition", FT_UINT24, BASE_HEX, VALS(vals_repetitions), MINI_SUBCHANNEL_REPETITION_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_cid_1,
			{"CID", "wmx.extended_uiuc_ie.mini_subchannel_alloc.cid", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_CID_MASK_1, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_1,
			{"UIUC", "wmx.extended_uiuc_ie.mini_subchannel_alloc.uiuc", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_UIUC_MASK_1, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_1,
			{"Repetition", "wmx.extended_uiuc_ie.mini_subchannel_alloc.repetition", FT_UINT24, BASE_HEX, VALS(vals_repetitions), MINI_SUBCHANNEL_REPETITION_MASK_1, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_cid_2,
			{"CID", "wmx.extended_uiuc_ie.mini_subchannel_alloc.cid", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_CID_MASK_2, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_2,
			{"UIUC", "wmx.extended_uiuc_ie.mini_subchannel_alloc.uiuc", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_UIUC_MASK_2, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_2,
			{"Repetition", "wmx.extended_uiuc_ie.mini_subchannel_alloc.repetition", FT_UINT24, BASE_HEX, VALS(vals_repetitions), MINI_SUBCHANNEL_REPETITION_MASK_2, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_cid_3,
			{"CID", "wmx.extended_uiuc_ie.mini_subchannel_alloc.cid", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_CID_MASK_3, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_uiuc_3,
			{"UIUC", "wmx.extended_uiuc_ie.mini_subchannel_alloc.uiuc", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_UIUC_MASK_2, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_repetition_3,
			{"Repetition", "wmx.extended_uiuc_ie.mini_subchannel_alloc.repetition", FT_UINT24, BASE_HEX, VALS(vals_repetitions), MINI_SUBCHANNEL_REPETITION_MASK_3, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_padding,
			{"Padding", "wmx.extended_uiuc_ie.mini_subchannel_alloc.padding", FT_UINT8, BASE_HEX, NULL, MINI_SUBCHANNEL_PADDING_MASK, NULL, HFILL }
		},
		{
			&hf_extended_uiuc_ie_mini_subchannel_alloc_padding_1,
			{"Padding", "wmx.extended_uiuc_ie.mini_subchannel_alloc.padding", FT_UINT24, BASE_HEX, NULL, MINI_SUBCHANNEL_PADDING_MASK_1, NULL, HFILL }
		},
		{	/* 8.4.5.4.6 AAS_UL_IE */
			&hf_extended_uiuc_ie_aas_ul,
			{"AAS_UL_IE (not implemented)", "wmx.extended_uiuc_ie.aas_ul", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.12 CQICH Allocation IE */
			&hf_extended_uiuc_ie_cqich_alloc,
			{"CQICH Allocation IE (not implemented)", "wmx.extended_uiuc_ie.cqich_alloc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.7 UL Zone IE */
			&hf_extended_uiuc_ie_ul_zone,
			{"UL Zone IE (not implemented)", "wmx.extended_uiuc_ie.ul_zone", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		{	/* 8.4.5.4.14 MIMO_UL_Basic_IE */
			&hf_extended_uiuc_ie_mimo_ul_basic,
			{"MIMO UL Basic IE (not implemented)", "wmx.extended_uiuc_ie.mimo_ul_basic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.22 UL-MAP Fast Tracking IE */
			&hf_extended_uiuc_ie_fast_tracking,
			{"UL-MAP Fast Tracking IE (not implemented)", "wmx.extended_uiuc_ie.fast_tracking", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.21 Fast Ranging IE */
			&hf_extended_uiuc_ie_fast_ranging,
			{"Fast Ranging IE (not implemented)", "wmx.extended_uiuc_ie.fast_ranging", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.14 UL-MAP Physical Modifier IE */
			&hf_extended_uiuc_ie_phymod_ul,
			{"UL-MAP Physical Modifier IE (not implemented)", "wmx.extended_uiuc_ie.phymod_ul", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.17 UL PUSC Burst Allocation in Other Segment IE */
			&hf_extended_uiuc_ie_ul_pusc_burst_allocation,
			{"UL_PUSC_Burst_Allocation_in_Other_Segment_IE (not implemented)", "wmx.extended_uiuc_ie.ul_pusc_burst_allocation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.4.15 UL Allocation Start IE */
			&hf_extended_uiuc_ie_ul_allocation_start,
			{"UL Allocation Start IE (not implemented)", "wmx.extended_uiuc_ie.ul_allocation_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* unknown UIUC */
			&hf_extended_uiuc_ie_unknown_uiuc,
			{"Unknown Extended UIUC", "wmx.extended_uiuc.unknown_uiuc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

#if 0 /* not used ?? */
	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_wimax_compact_ulmap_ie_decoder,
			&ett_wimax_rcid_ie_decoder,
			&ett_wimax_harq_control_ie_decoder,
			&ett_wimax_extended_uiuc_dependent_ie_decoder,
			&ett_wimax_extension_type_ie_decoder,
		};
	proto_register_subtree_array(ett, array_length(ett));
#endif

	proto_wimax_compact_ulmap_ie_decoder = proto_wimax;

	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_compact_ulmap, array_length(hf_compact_ulmap));
	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_rcid, array_length(hf_rcid));
	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_harq_control, array_length(hf_harq_control));
	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_extension_type, array_length(hf_extension_type));
	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_cdma_allocation, array_length(hf_cdma_allocation));
	proto_register_field_array(proto_wimax_compact_ulmap_ie_decoder, hf_extended_uiuc, array_length(hf_extended_uiuc));
}

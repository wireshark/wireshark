/* wimax_compact_dlmap_ie_decoder.c
 * WiMax HARQ Map Message decoder
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
#include "wimax_tlv.h"

extern gint proto_wimax;

/* MASKs */
#define MSB_NIBBLE_MASK      0xF0
#define LSB_NIBBLE_MASK      0x0F

#define CID_TYPE_NORMAL      0
#define CID_TYPE_RCID11      1
#define CID_TYPE_RCID7       2
#define CID_TYPE_RCID3       3

/* Global Variables */
guint cid_type = 0;
guint band_amc_subchannel_type = 0;
guint max_logical_bands = 12;
guint num_of_broadcast_symbols = 0;
guint num_of_dl_band_amc_symbols = 0;
guint num_of_ul_band_amc_symbols = 0;
/* from switch HARQ mode extension IE */
guint harq_mode = 0;

/* forward reference */
static guint wimax_compact_dlmap_format_configuration_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_compact_dlmap_rcid_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_compact_dlmap_harq_control_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_compact_dlmap_cqich_control_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
static guint wimax_cdlmap_extension_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);
guint wimax_extended_diuc_dependent_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset);

static gint proto_wimax_compact_dlmap_ie_decoder = -1;

#if 0 /* not used ?? */
static gint ett_wimax_compact_dlmap_ie_decoder = -1;
static gint ett_wimax_format_configuration_ie_decoder = -1;
static gint ett_wimax_rcid_ie_decoder = -1;
static gint ett_wimax_harq_control_ie_decoder = -1;
static gint ett_wimax_extended_diuc_dependent_ie_decoder = -1;
static gint ett_wimax_cqich_control_ie_decoder = -1;
static gint ett_wimax_extension_type_ie_decoder = -1;
#endif

/* New Format Indications */
static const true_false_string tfs_indication =
{
    "New format",
    "No new format"
};

/* Prefixes */
static const true_false_string tfs_prefix =
{
    "Enable HARQ",
    "Temporary Disable HARQ"
};

/* CQICH Indicator */
static const true_false_string tfs_cqich_ind =
{
    "With CQICH Control IE",
    "No CQICH Control IE"
};

/* CID types */
static const value_string vals_cid_types[] =
{
    { 0, "Normal CID" },
    { 1, "RCID11 (default)" },
    { 2, "RCID7" },
    { 3, "RCID3" },
    { 0,  NULL }
};

/* Subchannel Types */
static const value_string vals_subchannel_types[] =
{
    { 0, "Default Type" },
    { 1, "1 bin x 6 symbols Type" },
    { 2, "2 bin x 3 symbols Type" },
    { 3, "3 bin x 2 symbols Type" },
    { 0,  NULL }
};

/* Max Logical Bands */
static const value_string vals_max_logical_bands[] =
{
    { 0, "3 Bands" },
    { 1, "6 Bands" },
    { 2, "12 Bands (default)" },
    { 3, "24 Bands" },
    { 0,  NULL }
};

/* Repetition Coding Indications */
static const value_string rep_msgs[] =
{
    { 0, "No Repetition Coding" },
    { 1, "Repetition Coding of 2 Used" },
    { 2, "Repetition Coding of 4 Used" },
    { 3, "Repetition Coding of 6 Used" },
    { 0,  NULL }
};

/* Repetition Coding Indications */
static const value_string vals_allocation_modes[] =
{
    { 0, "Same Number Of Subchannels For The Selected Bands" },
    { 1, "Different Same Number Of Subchannels For The Selected Bands" },
    { 2, "Total Number Of Subchannels For The Selected Bands Determined by Nsch Code and Nep Code" },
    { 3, "Reserved" },
    { 0,  NULL }
};

/* Masks */
#define DL_MAP_TYPE_MASK      0xE0
#define UL_MAP_APPEND_MASK    0x10
#define SHORTENED_DIUC_MASK   0xE0
#define COMPANDED_SC_MASK     0x1F
#define DL_MAP_TYPE_MASK_1    0x0E
#define UL_MAP_APPEND_MASK_1  0x01
#define SHORTENED_DIUC_MASK_1 0x0E00
#define COMPANDED_SC_MASK_1   0x01F0

/* display indexies */
static gint hf_cdlmap_dl_map_type = -1;
static gint hf_cdlmap_ul_map_append = -1;
static gint hf_cdlmap_reserved = -1;
static gint hf_cdlmap_nep_code = -1;
static gint hf_cdlmap_nsch_code = -1;
static gint hf_cdlmap_num_bands = -1;
static gint hf_cdlmap_band_index = -1;
static gint hf_cdlmap_nb_bitmap = -1;
static gint hf_cdlmap_dl_map_type_1 = -1;
static gint hf_cdlmap_ul_map_append_1 = -1;
static gint hf_cdlmap_reserved_1 = -1;
static gint hf_cdlmap_nep_code_1 = -1;
static gint hf_cdlmap_nsch_code_1 = -1;
static gint hf_cdlmap_num_bands_1 = -1;
/*static gint hf_cdlmap_band_index_1 = -1;*/
static gint hf_cdlmap_nb_bitmap_1 = -1;

static gint hf_cdlmap_shortened_diuc = -1;
static gint hf_cdlmap_companded_sc = -1;
static gint hf_cdlmap_shortened_uiuc = -1;
static gint hf_cdlmap_shortened_diuc_1 = -1;
static gint hf_cdlmap_companded_sc_1 = -1;
static gint hf_cdlmap_shortened_uiuc_1 = -1;

static gint hf_cdlmap_bin_offset = -1;
static gint hf_cdlmap_bin_offset_1 = -1;

static gint hf_cdlmap_diuc_num_of_subchannels = -1;
static gint hf_cdlmap_diuc_num_of_subchannels_1 = -1;
static gint hf_cdlmap_diuc_repetition_coding_indication = -1;
static gint hf_cdlmap_diuc_repetition_coding_indication_1 = -1;
static gint hf_cdlmap_diuc_reserved = -1;
static gint hf_cdlmap_diuc_reserved_1 = -1;

static gint hf_cdlmap_bit_map_length = -1;
static gint hf_cdlmap_bit_map_length_1 = -1;
static gint hf_cdlmap_bit_map = -1;

static gint hf_cdlmap_diuc = -1;
static gint hf_cdlmap_diuc_1 = -1;

static gint hf_cdlmap_allocation_mode = -1;
static gint hf_cdlmap_allocation_mode_rsvd = -1;
static gint hf_cdlmap_num_subchannels = -1;
static gint hf_cdlmap_allocation_mode_1 = -1;
static gint hf_cdlmap_allocation_mode_rsvd_1 = -1;
static gint hf_cdlmap_num_subchannels_1 = -1;

static gint hf_cdlmap_reserved_type = -1;
static gint hf_cdlmap_reserved_type_1 = -1;

/* display indexies */
static gint hf_format_config_ie_dl_map_type = -1;
static gint hf_format_config_ie_dl_map_type_1 = -1;
static gint hf_format_config_ie_dl_map_type_32 = -1;
static gint hf_format_config_ie_new_format_indication = -1;
static gint hf_format_config_ie_new_format_indication_1 = -1;
static gint hf_format_config_ie_new_format_indication_32 = -1;
static gint hf_format_config_ie_cid_type = -1;
static gint hf_format_config_ie_cid_type_1 = -1;
static gint hf_format_config_ie_safety_pattern = -1;
static gint hf_format_config_ie_safety_pattern_1 = -1;
static gint hf_format_config_ie_subchannel_type = -1;
static gint hf_format_config_ie_subchannel_type_1 = -1;
static gint hf_format_config_ie_max_logical_bands = -1;
static gint hf_format_config_ie_max_logical_bands_1 = -1;
static gint hf_format_config_ie_num_of_broadcast_symbol = -1;
static gint hf_format_config_ie_num_of_broadcast_symbol_1 = -1;
static gint hf_format_config_ie_num_of_dl_band_amc_symbol = -1;
static gint hf_format_config_ie_num_of_dl_band_amc_symbol_1 = -1;
static gint hf_format_config_ie_num_of_ul_band_amc_symbol = -1;
static gint hf_format_config_ie_num_of_ul_band_amc_symbol_1 = -1;

/* Format Configuration IE Masks */
#define FORMAT_CONFIG_IE_DL_MAP_TYPE_MASK    0xE0000000
#define FORMAT_CONFIG_IE_NEW_FORMAT_IND_MASK 0x10000000
#define CID_TYPE_MASK_1                      0x0C000000
#define SAFETY_PATTERN_MASK_1                0x03E00000
#define BAND_AMC_SUBCHANNEL_TYPE_MASK_1      0x00180000
#define MAX_LOGICAL_BANDS_MASK_1             0x00060000
#define NUM_BROADCAST_SYMBOLS_MASK_1         0x0001F000
#define NUM_DL_AMC_SYMBOLS_MASK_1            0x00000FC0
#define NUM_UL_AMC_SYMBOLS_MASK_1            0x0000003F
#define CID_TYPE_MASK                        0xC0000000
#define SAFETY_PATTERN_MASK                  0x3E000000
#define BAND_AMC_SUBCHANNEL_TYPE_MASK        0x01800000
#define MAX_LOGICAL_BANDS_MASK               0x00600000
#define NUM_BROADCAST_SYMBOLS_MASK           0x001F0000
#define NUM_DL_AMC_SYMBOLS_MASK              0x0000FC00
#define NUM_UL_AMC_SYMBOLS_MASK              0x000003F0

/* display indexies */
static gint hf_harq_rcid_ie_prefix = -1;
static gint hf_harq_rcid_ie_prefix_1 = -1;
static gint hf_harq_rcid_ie_normal_cid = -1;
static gint hf_harq_rcid_ie_normal_cid_1 = -1;
static gint hf_harq_rcid_ie_cid3 = -1;
static gint hf_harq_rcid_ie_cid3_1 = -1;
static gint hf_harq_rcid_ie_cid7 = -1;
static gint hf_harq_rcid_ie_cid7_1 = -1;
static gint hf_harq_rcid_ie_cid11 = -1;
static gint hf_harq_rcid_ie_cid11_1 = -1;
static gint hf_harq_rcid_ie_cid11_2 = -1;
static gint hf_harq_rcid_ie_cid11_3 = -1;

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

/* HARQ MAP CQICH Control IE display indexies */
static gint hf_cqich_control_ie_indicator = -1;
static gint hf_cqich_control_ie_alloc_id = -1;
static gint hf_cqich_control_ie_period = -1;
static gint hf_cqich_control_ie_frame_offset = -1;
static gint hf_cqich_control_ie_duration = -1;
static gint hf_cqich_control_ie_cqi_rep_threshold = -1;
static gint hf_cqich_control_ie_indicator_1 = -1;
static gint hf_cqich_control_ie_alloc_id_1 = -1;
static gint hf_cqich_control_ie_period_1 = -1;
static gint hf_cqich_control_ie_frame_offset_1 = -1;
static gint hf_cqich_control_ie_duration_1 = -1;
static gint hf_cqich_control_ie_cqi_rep_threshold_1 = -1;

/* Masks */
#define WIMAX_CQICH_CONTROL_IE_INDICATOR_MASK           0x8000
#define WIMAX_CQICH_CONTROL_IE_ALLOCATION_INDEX_MASK    0x7E00
#define WIMAX_CQICH_CONTROL_IE_PERIOD_MASK              0x0180
#define WIMAX_CQICH_CONTROL_IE_FRAME_OFFSET_MASK        0x0070
#define WIMAX_CQICH_CONTROL_IE_DURATION_MASK            0x000F
#define WIMAX_CQICH_CONTROL_IE_CQI_REP_THRESHOLD_MASK   0x7000
#define WIMAX_CQICH_CONTROL_IE_INDICATOR_MASK_1         0x080000
#define WIMAX_CQICH_CONTROL_IE_ALLOCATION_INDEX_MASK_1  0x07E000
#define WIMAX_CQICH_CONTROL_IE_PERIOD_MASK_1            0x001800
#define WIMAX_CQICH_CONTROL_IE_FRAME_OFFSET_MASK_1      0x000700
#define WIMAX_CQICH_CONTROL_IE_DURATION_MASK_1          0x0000F0
#define WIMAX_CQICH_CONTROL_IE_CQI_REP_THRESHOLD_MASK_1 0x070000

/* Extension Type */
#define EXTENSION_TYPE_MASK         0xE000
#define EXTENSION_TYPE_MASK_1       0x0E00
#define EXTENSION_SUBTYPE_MASK      0x1F00
#define EXTENSION_SUBTYPE_MASK_1    0x01F0
#define EXTENSION_LENGTH_MASK       0x00F0
#define EXTENSION_LENGTH_MASK_1     0x000F

static gint hf_cdlmap_extension_type = -1;
static gint hf_cdlmap_extension_subtype = -1;
static gint hf_cdlmap_extension_length = -1;
static gint hf_cdlmap_extension_type_1 = -1;
static gint hf_cdlmap_extension_subtype_1 = -1;
static gint hf_cdlmap_extension_length_1 = -1;

static gint hf_cdlmap_extension_time_diversity_mbs = -1;
static gint hf_cdlmap_extension_harq_mode = -1;
static gint hf_cdlmap_extension_unknown_sub_type = -1;
static gint hf_cdlmap_extension_time_diversity_mbs_1 = -1;
static gint hf_cdlmap_extension_harq_mode_1 = -1;
static gint hf_cdlmap_extension_unknown_sub_type_1 = -1;

/* Extended DIUC dependent IE display indexies */
static gint hf_extended_diuc_dependent_ie_diuc = -1;
static gint hf_extended_diuc_dependent_ie_diuc_1 = -1;
static gint hf_extended_diuc_dependent_ie_length = -1;
static gint hf_extended_diuc_dependent_ie_length_1 = -1;
static gint hf_extended_diuc_dependent_ie_channel_measurement = -1;
static gint hf_extended_diuc_dependent_ie_stc_zone = -1;
static gint hf_extended_diuc_dependent_ie_aas_dl = -1;
static gint hf_extended_diuc_dependent_ie_data_location = -1;
static gint hf_extended_diuc_dependent_ie_cid_switch = -1;
static gint hf_extended_diuc_dependent_ie_mimo_dl_basic = -1;
static gint hf_extended_diuc_dependent_ie_mimo_dl_enhanced = -1;
static gint hf_extended_diuc_dependent_ie_harq_map_pointer = -1;
static gint hf_extended_diuc_dependent_ie_phymod_dl = -1;
static gint hf_extended_diuc_dependent_ie_dl_pusc_burst_allocation = -1;
static gint hf_extended_diuc_dependent_ie_ul_interference_and_noise_level = -1;
static gint hf_extended_diuc_dependent_ie_unknown_diuc = -1;


/* Compact DL-MAP IE Types (table 89) */
#define COMPACT_DL_MAP_TYPE_NORMAL_SUBCHANNEL	0
#define COMPACT_DL_MAP_TYPE_BAND_AMC		1
#define COMPACT_DL_MAP_TYPE_SAFETY		2
#define COMPACT_DL_MAP_TYPE_UIUC		3
#define COMPACT_DL_MAP_TYPE_FORMAT_CONF_IE	4
#define COMPACT_DL_MAP_TYPE_HARQ_ACK_BITMAP_IE	5
#define COMPACT_DL_MAP_TYPE_RESERVED		6
#define COMPACT_DL_MAP_TYPE_EXTENSION		7

/* Compact DL-MAP IE decoder */
guint wimax_compact_dlmap_ie_decoder(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint diuc, byte, length = 0;
	guint dl_map_type, ul_map_append;
	guint dl_map_offset, nibble_length, bit_map_length;
	guint nband, band_count, i, allocation_mode;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Compact DL-MAP IEs");
#endif
	/* set the local offset */
	dl_map_offset = offset;
	/* Get the first byte */
	byte = tvb_get_guint8(tvb, dl_map_offset);
	if(nibble_offset & 1)
	{
		dl_map_type = ((byte & DL_MAP_TYPE_MASK_1) >> 1);
		ul_map_append = (byte & UL_MAP_APPEND_MASK_1);
	}
	else
	{
		dl_map_type = ((byte & DL_MAP_TYPE_MASK) >> 5);
		ul_map_append = (byte & UL_MAP_APPEND_MASK);
	}
	switch (dl_map_type)
	{
		case COMPACT_DL_MAP_TYPE_NORMAL_SUBCHANNEL:/* 6.3.2.3.43.6.1 */
			if(nibble_offset & 1)
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the UL-MAP append */
				proto_tree_add_item(tree, hf_cdlmap_ul_map_append_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
				nibble_offset = 0;
			}
			else
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the UL-MAP append */
				proto_tree_add_item(tree, hf_cdlmap_ul_map_append, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_dlmap_rcid_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
					proto_tree_add_item(tree, hf_cdlmap_nsch_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_nsch_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened DIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_companded_sc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				dl_map_offset++;
				length += 2;
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			/* decode CQICH Control IE */
			nibble_length = wimax_compact_dlmap_cqich_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			if(ul_map_append)
			{	/* check harq mode */
				if(harq_mode == 1)
				{	/* display the Shortened UIUC and Companded SC */
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_cdlmap_shortened_uiuc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_shortened_uiuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					}
					/* move to next byte */
					dl_map_offset++;
					length += 2;
				}
				else if(!harq_mode)
				{	/* display the Nep and Nsch Code */
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_cdlmap_nep_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						/* move to next byte */
						dl_map_offset++;
						proto_tree_add_item(tree, hf_cdlmap_nsch_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_nep_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_nsch_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						/* move to next byte */
						dl_map_offset++;
					}
					length += 2;
				}
				/* decode HARQ Control IE */
				nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
				length += nibble_length;
			}
		break;
		case COMPACT_DL_MAP_TYPE_BAND_AMC:/* 6.3.2.3.43.6.2 */
			if(nibble_offset & 1)
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
				nibble_offset = 0;
			}
			else
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_dlmap_rcid_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
					proto_tree_add_item(tree, hf_cdlmap_nsch_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_nsch_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened DIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_companded_sc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				dl_map_offset++;
				length += 2;
			}
			/* get the Nband */
			if(max_logical_bands)
			{	/* get and display the Nband */
				nband = tvb_get_guint8(tvb, dl_map_offset);
				if(nibble_offset & 1)
				{
					nband = (nband & LSB_NIBBLE_MASK);
					/* display the Nband */
					proto_tree_add_item(tree, hf_cdlmap_num_bands_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
					nibble_offset = 0;
					if(max_logical_bands == 3)
					{
						proto_tree_add_item(tree, hf_cdlmap_band_index, tvb, dl_map_offset, nband, ENC_NA);
						length += (nband * 2);
						/* update offset */
						dl_map_offset += nband;
					}
					else
					{
						nibble_offset = (nband & 1);
						proto_tree_add_item(tree, hf_cdlmap_band_index, tvb, dl_map_offset, ((nband >> 1) + nibble_offset), ENC_NA);
						length += nband;
						/* update offset */
						dl_map_offset += (nband >> 1);
					}
				}
				else
				{
					nband = ((nband & MSB_NIBBLE_MASK) >> 4);
					/* display the Nband */
					proto_tree_add_item(tree, hf_cdlmap_num_bands, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 1;
					if(max_logical_bands == 3)
					{
						proto_tree_add_item(tree, hf_cdlmap_band_index, tvb, dl_map_offset, (nband + nibble_offset), ENC_NA);
						length += (nband * 2);
						/* update offset */
						dl_map_offset += nband;
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_band_index, tvb, dl_map_offset, ((nband >> 1) + nibble_offset), ENC_NA);
						length += nband;
						/* update offset */
						dl_map_offset += ((nband + nibble_offset) >> 1);
						if(nband & 1)
							nibble_offset = 0;
					}
				}
				length++;
				band_count = nband;
			}
			else
			{
				band_count = 1;
				/* display the Nb-BITMAP */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_nb_bitmap_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
					nibble_offset = 0;
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_nb_bitmap, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					nibble_offset = 1;
				}
				length++;
			}
			/* Get the Allocation Mode */
			byte = tvb_get_guint8(tvb, dl_map_offset);
			if(nibble_offset & 1)
			{
				allocation_mode = ((byte & 0x0C) >> 2);
				proto_tree_add_item(tree, hf_cdlmap_allocation_mode_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_allocation_mode_rsvd_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 0;
				dl_map_offset++;
			}
			else
			{
				allocation_mode = ((byte & 0xC0) >> 6);
				proto_tree_add_item(tree, hf_cdlmap_allocation_mode, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_cdlmap_allocation_mode_rsvd, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			/* Decode Allocation Mode - need to be done */
			if(!allocation_mode)
			{
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_num_subchannels_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_num_subchannels, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				dl_map_offset++;
			}
			else if(allocation_mode == 1)
			{
				for(i=0; i<band_count; i++)
				{
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_cdlmap_num_subchannels_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_num_subchannels, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					}
					dl_map_offset++;
				}
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			/* decode CQICH Control IE */
			nibble_length = wimax_compact_dlmap_cqich_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_DL_MAP_TYPE_SAFETY:/* 6.3.2.3.43.6.3 */
			if(nibble_offset & 1)
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the UL-MAP append */
				proto_tree_add_item(tree, hf_cdlmap_ul_map_append_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
				nibble_offset = 0;
			}
			else
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the UL-MAP append */
				proto_tree_add_item(tree, hf_cdlmap_ul_map_append, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				nibble_offset = 1;
			}
			length = 1;
			/* decode RCID IE */
			nibble_length = wimax_compact_dlmap_rcid_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += (nibble_length >> 1);
			nibble_offset = (nibble_length & 1);
			/* check harq mode */
			if(!harq_mode)
			{	/* display the Nep and Nsch Code */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
					proto_tree_add_item(tree, hf_cdlmap_nsch_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_nep_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_nsch_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
				}
				length += 2;
			}
			else if(harq_mode == 1)
			{	/* display the Shortened DIUC and Companded SC */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_companded_sc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_shortened_diuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				/* move to next byte */
				dl_map_offset++;
				length += 2;
			}
			/* display BIN offset */
			if(nibble_offset & 1)
			{
				proto_tree_add_item(tree, hf_cdlmap_bin_offset_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
			}
			else
			{
				proto_tree_add_item(tree, hf_cdlmap_bin_offset, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
			}
			length += 2;
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			/* decode CQICH Control IE */
			nibble_length = wimax_compact_dlmap_cqich_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			if(ul_map_append)
			{	/* check harq mode */
				if(harq_mode == 1)
				{	/* display the Shortened DIUC and Companded SC */
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_cdlmap_shortened_diuc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_shortened_diuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_companded_sc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					}
					/* move to next byte */
					dl_map_offset++;
					length += 2;
				}
				else if(!harq_mode)
				{	/* display the Nep and Nsch Code */
					if(nibble_offset & 1)
					{
						proto_tree_add_item(tree, hf_cdlmap_nep_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						/* move to next byte */
						dl_map_offset++;
						proto_tree_add_item(tree, hf_cdlmap_nsch_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					}
					else
					{
						proto_tree_add_item(tree, hf_cdlmap_nep_code, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tree, hf_cdlmap_nsch_code_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
						/* move to next byte */
						dl_map_offset++;
					}
					length += 2;
				}
				/* display BIN offset */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_bin_offset_1, tvb, dl_map_offset, 2, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_bin_offset, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					/* move to next byte */
					dl_map_offset++;
				}
				length += 2;
				/* decode HARQ Control IE */
				nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
				length += nibble_length;
			}
		break;
		case COMPACT_DL_MAP_TYPE_UIUC:/* 6.3.2.3.43.6.4 */
			if(nibble_offset & 1)
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
				/* get the new byte */
				byte = tvb_get_guint8(tvb, dl_map_offset);
				/* get the DIUC */
				diuc = ((byte & MSB_NIBBLE_MASK) >> 4);
				/* display the DIUC */
				proto_tree_add_item(tree, hf_cdlmap_diuc, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
			}
			else
			{
				/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* get the DIUC */
				diuc = (tvb_get_guint8(tvb, dl_map_offset) & LSB_NIBBLE_MASK);
				/* display the DIUC */
				proto_tree_add_item(tree, hf_cdlmap_diuc_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* move to next byte */
				dl_map_offset++;
			}
			length = 2;
			if(diuc == 15)
			{	/* Extended DIUC dependent IE */
				nibble_length =  wimax_extended_diuc_dependent_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
				length += nibble_length;
				dl_map_offset += (nibble_length >> 1);
				nibble_offset = (nibble_length & 1);
			}
			else
			{	/* decode RCID IE */
				nibble_length = wimax_compact_dlmap_rcid_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
				length += nibble_length;
				dl_map_offset += (nibble_length >> 1);
				nibble_offset = (nibble_length & 1);
				/* display Number of subchannels */
				if(nibble_offset & 1)
					proto_tree_add_item(tree, hf_cdlmap_diuc_num_of_subchannels_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				else
					proto_tree_add_item(tree, hf_cdlmap_diuc_num_of_subchannels, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				length += 2;
				/* display the repetition coding indication and reserved bits */
				if(nibble_offset & 1)
				{
					proto_tree_add_item(tree, hf_cdlmap_diuc_repetition_coding_indication_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_diuc_reserved_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				else
				{
					proto_tree_add_item(tree, hf_cdlmap_diuc_repetition_coding_indication, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tree, hf_cdlmap_diuc_reserved, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				}
				length += 1;
			}
			/* decode HARQ Control IE */
			nibble_length = wimax_compact_dlmap_harq_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
			dl_map_offset += ((nibble_offset + nibble_length) >> 1);
			nibble_offset = ((nibble_offset + nibble_length) & 1);
			/* decode CQICH Control IE */
			nibble_length = wimax_compact_dlmap_cqich_control_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length += nibble_length;
		break;
		case COMPACT_DL_MAP_TYPE_FORMAT_CONF_IE:/* 6.3.2.3.43.2 */
			/* decode the format configuration IE */
			nibble_length = wimax_compact_dlmap_format_configuration_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);
			length = nibble_length;
		break;
		case COMPACT_DL_MAP_TYPE_HARQ_ACK_BITMAP_IE:/* 6.3.2.3.43.6.5 */
			if(nibble_offset & 1)
			{	/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				length = 1;
				/* move to next byte */
				dl_map_offset++;
				/* get the bit map length */
				byte = tvb_get_guint8(tvb, dl_map_offset);
				bit_map_length = ((byte & MSB_NIBBLE_MASK) >> 4);
				/* display BITMAP Length */
				proto_tree_add_item(tree, hf_cdlmap_bit_map_length, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display BITMAP */
				proto_tree_add_item(tree, hf_cdlmap_bit_map, tvb, dl_map_offset, bit_map_length + 1, ENC_NA);
				length += (1 + bit_map_length * 2);
			}
			else
			{
				/* display the DL-MAP type */
				proto_tree_add_item(tree, hf_cdlmap_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display the reserved */
				proto_tree_add_item(tree, hf_cdlmap_reserved, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				/* display BITMAP Length */
				proto_tree_add_item(tree, hf_cdlmap_bit_map_length_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
				length = 2;
				/* get the bit map length */
				bit_map_length =  (byte & LSB_NIBBLE_MASK);
				/* move to next byte */
				dl_map_offset++;
				/* display BITMAP */
				proto_tree_add_item(tree, hf_cdlmap_bit_map, tvb, dl_map_offset, bit_map_length, ENC_NA);
				length += (bit_map_length * 2);
			}
		break;
		case COMPACT_DL_MAP_TYPE_EXTENSION:/* 6.3.2.3.43.6.6 */
			/* decode the Compact DL-MAP externsion IE */
			nibble_length = wimax_cdlmap_extension_ie_decoder(tree, pinfo, tvb, dl_map_offset, nibble_offset);/*, cqich_indicator);*/
			length = nibble_length;
		break;
		default:/* Reserved Type */
			/* display the reserved type */
			proto_tree_add_item(tree, hf_cdlmap_reserved_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
			length = 1;
		break;
	}
	/* Update the nibble_offset and length */
	return length;
}

/* Format Configuration IE shifts */
#define CID_TYPE_SHIFT                      30
#define SAFETY_PATTERN_SHIFT                25
#define BAND_AMC_SUBCHANNEL_TYPE_SHIFT      23
#define MAX_LOGICAL_BANDS_SHIFT             21
#define NUM_BROADCAST_SYMBOLS_SHIFT         16
#define NUM_DL_AMC_SYMBOLS_SHIFT            10
#define NUM_UL_AMC_SYMBOLS_SHIFT            4
#define CID_TYPE_SHIFT_1              (CID_TYPE_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
#define SAFETY_PATTERN_SHIFT_1        (SAFETY_PATTERN_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
#define BAND_AMC_SUBCHANNEL_TYPE_SHIFT_1 (BAND_AMC_SUBCHANNEL_TYPE_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
#define MAX_LOGICAL_BANDS_SHIFT_1     (MAX_LOGICAL_BANDS_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
#define NUM_BROADCAST_SYMBOLS_SHIFT_1 (NUM_BROADCAST_SYMBOLS_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
#define NUM_DL_AMC_SYMBOLS_SHIFT_1    (NUM_DL_AMC_SYMBOLS_SHIFT-NUM_UL_AMC_SYMBOLS_SHIFT)
/*#define NUM_UL_AMC_SYMBOLS_SHIFT_1    0*/

/* Compact DL-MAP Format Configuration IE (6.3.2.3.43.2) decoder */
static guint wimax_compact_dlmap_format_configuration_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint length = 0;
	guint dl_map_type, new_format_ind;
	guint dl_map_offset;
	guint32 tvb_value;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Format Configuration IE");
#endif
	/* set the local offset */
	dl_map_offset = offset;
	/* Get the first byte */
	tvb_value = tvb_get_guint8(tvb, dl_map_offset);
	if(nibble_offset & 1)
	{	/* get the DL-MAP type */
		dl_map_type = ((tvb_value & DL_MAP_TYPE_MASK_1) >> 1);
		/* ensure the dl-map type is Format Configuration IE */
		if(dl_map_type != COMPACT_DL_MAP_TYPE_FORMAT_CONF_IE)
			return 0;
		new_format_ind = (tvb_value & 0x01);
		/* display the DL-MAP type */
		proto_tree_add_item(tree, hf_format_config_ie_dl_map_type_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
		/* display the New format Indication */
		proto_tree_add_item(tree, hf_format_config_ie_new_format_indication_1, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
		/* update the length in nibble */
		length = 1;
		/* move to next byte */
		dl_map_offset++;
		if(new_format_ind)
		{	/* display the CID Type */
			proto_tree_add_item(tree, hf_format_config_ie_cid_type, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the Safety Pattern */
			proto_tree_add_item(tree, hf_format_config_ie_safety_pattern, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the Subchannel pattern */
			proto_tree_add_item(tree, hf_format_config_ie_subchannel_type, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the max logical bands */
			proto_tree_add_item(tree, hf_format_config_ie_max_logical_bands, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of broadcast symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_broadcast_symbol, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of dl band AMC symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_dl_band_amc_symbol, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of ul band AMC symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_ul_band_amc_symbol, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* update the length in nibble */
			length += 7;
			/* Get the next 32-bit word */
			tvb_value = tvb_get_ntohl(tvb, dl_map_offset);
			/* get the CID type */
			cid_type = ((tvb_value & CID_TYPE_MASK) >> CID_TYPE_SHIFT);
			/* get the subchannel type for band AMC */
			band_amc_subchannel_type = ((tvb_value & BAND_AMC_SUBCHANNEL_TYPE_MASK) >> BAND_AMC_SUBCHANNEL_TYPE_SHIFT);
			/* get the max logical bands */
			max_logical_bands = ((tvb_value & MAX_LOGICAL_BANDS_MASK) >> MAX_LOGICAL_BANDS_SHIFT);
			/* get the number of symbols for broadcast */
			num_of_broadcast_symbols = ((tvb_value & NUM_BROADCAST_SYMBOLS_MASK) >> NUM_BROADCAST_SYMBOLS_SHIFT);
			/* get the number of symbols for DL band AMC */
			num_of_dl_band_amc_symbols = ((tvb_value & NUM_DL_AMC_SYMBOLS_MASK) >> NUM_DL_AMC_SYMBOLS_SHIFT);
			/* get the number of symbols for UL band AMC */
			num_of_ul_band_amc_symbols = ((tvb_value & NUM_UL_AMC_SYMBOLS_MASK) >> NUM_UL_AMC_SYMBOLS_SHIFT);
		}
	}
	else
	{
		dl_map_type = ((tvb_value & DL_MAP_TYPE_MASK) >> 5);
		/* ensure the dl-map type is Format Configuration IE */
		if(dl_map_type != COMPACT_DL_MAP_TYPE_FORMAT_CONF_IE)
			return 0;
		new_format_ind = (tvb_value & 0x10);
		if(new_format_ind)
		{	/* display the DL-MAP type */
			proto_tree_add_item(tree, hf_format_config_ie_dl_map_type_32, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the New format Indication */
			proto_tree_add_item(tree, hf_format_config_ie_new_format_indication_32, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the CID Type */
			proto_tree_add_item(tree, hf_format_config_ie_cid_type_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the Safety Pattern */
			proto_tree_add_item(tree, hf_format_config_ie_safety_pattern_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the Subchannel pattern */
			proto_tree_add_item(tree, hf_format_config_ie_subchannel_type_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the max logical bands */
			proto_tree_add_item(tree, hf_format_config_ie_max_logical_bands_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of broadcast symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_broadcast_symbol_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of dl band AMC symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_dl_band_amc_symbol_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* display the number of ul band AMC symbols */
			proto_tree_add_item(tree, hf_format_config_ie_num_of_ul_band_amc_symbol_1, tvb, dl_map_offset, 4, ENC_BIG_ENDIAN);
			/* update the length in nibble */
			length = 8;
			/* Get the next 32-bit word */
			tvb_value = tvb_get_ntohl(tvb, dl_map_offset);
			/* get the CID type */
			cid_type = ((tvb_value & CID_TYPE_MASK_1) >> CID_TYPE_SHIFT_1);
			/* get the subchannel type for band AMC */
			band_amc_subchannel_type = ((tvb_value & BAND_AMC_SUBCHANNEL_TYPE_MASK_1) >> BAND_AMC_SUBCHANNEL_TYPE_SHIFT_1);
			/* get the max logical bands */
			max_logical_bands = ((tvb_value & MAX_LOGICAL_BANDS_MASK_1) >> MAX_LOGICAL_BANDS_SHIFT_1);
			/* get the number of symbols for broadcast */
			num_of_broadcast_symbols = ((tvb_value & NUM_BROADCAST_SYMBOLS_MASK_1) >> NUM_BROADCAST_SYMBOLS_SHIFT_1);
			/* get the number of symbols for DL band AMC */
			num_of_dl_band_amc_symbols = ((tvb_value & NUM_DL_AMC_SYMBOLS_MASK_1) >> NUM_DL_AMC_SYMBOLS_SHIFT_1);
			/* get the number of symbols for UL band AMC */
			num_of_ul_band_amc_symbols = (tvb_value & NUM_UL_AMC_SYMBOLS_MASK_1);
		}
		else
		{	/* display the DL-MAP type */
			proto_tree_add_item(tree, hf_format_config_ie_dl_map_type, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
			/* display the New format Indication */
			proto_tree_add_item(tree, hf_format_config_ie_new_format_indication, tvb, dl_map_offset, 1, ENC_BIG_ENDIAN);
			/* update the length in nibble */
			length = 1;
		}
	}
	/* return the IE length in nibbles */
	return length;
}

/* Compact DL-MAP Reduced CID IE (6.3.2.3.43.3) decoder */
static guint wimax_compact_dlmap_rcid_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
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
			proto_tree_add_item(tree, hf_harq_rcid_ie_normal_cid_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* Get the prefix bit */
			prefix = (tvb_get_guint8(tvb, offset) & 0x08);
			/* display the prefix */
			proto_tree_add_item(tree, hf_harq_rcid_ie_prefix_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			if(prefix)
			{	/* display the CID11 */
				proto_tree_add_item(tree, hf_harq_rcid_ie_cid11_3, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = 3;
			}
			else
			{
				 if(cid_type == CID_TYPE_RCID11)
				{	/* display the CID11 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid11_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 3;
				}
				else if(cid_type == CID_TYPE_RCID7)
				{	/* display the normal CID7 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid7_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 2;
				}
				else if(cid_type == CID_TYPE_RCID3)
				{	/* display the CID3 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid3_1, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 1;
				}
			}
		}
	}
	else
	{
		if(cid_type == CID_TYPE_NORMAL)
		{	/* display the normal CID */
			proto_tree_add_item(tree, hf_harq_rcid_ie_normal_cid, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* Get the prefix bit */
			prefix = (tvb_get_guint8(tvb, offset) & 0x08);
			/* display the prefix */
			proto_tree_add_item(tree, hf_harq_rcid_ie_prefix, tvb, offset, 2, ENC_BIG_ENDIAN);
			if(prefix || (cid_type == CID_TYPE_RCID11))
			{	/* display the CID11 */
				proto_tree_add_item(tree, hf_harq_rcid_ie_cid11_2, tvb, offset, 2, ENC_BIG_ENDIAN);
				length = 3;
			}
			else
			{
				if(cid_type == CID_TYPE_RCID11)
				{	/* display the CID11 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid11, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 3;
				}
				else if(cid_type == CID_TYPE_RCID7)
				{	/* display the CID7 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid7, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 2;
				}
				else if(cid_type == CID_TYPE_RCID3)
				{	/* display the CID3 */
					proto_tree_add_item(tree, hf_harq_rcid_ie_cid3, tvb, offset, 2, ENC_BIG_ENDIAN);
					length = 1;
				}
			}
		}
	}
	/* return the IE length in nibbles */
	return length;
}

/* Compact DL-MAP HARQ Control IE (6.3.2.3.43.4) decoder */
static guint wimax_compact_dlmap_harq_control_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
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

/* Compact DL-MAP CQICH Control IE (6.3.2.3.43.5) decoder */
static guint wimax_compact_dlmap_cqich_control_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint byte, cqich_indicator, length = 0;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CQICH Control IE");
#endif
	/* Get the first byte */
	byte = tvb_get_guint8(tvb, offset);
	if(nibble_offset & 1)
	{	/* Get the CQICH indicator */
		cqich_indicator = (byte & 0x08);
		if(cqich_indicator)
		{	/* display the CQICH indicator */
			proto_tree_add_item(tree, hf_cqich_control_ie_indicator_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			/* display the allocation index */
			proto_tree_add_item(tree, hf_cqich_control_ie_alloc_id_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			/* display the period */
			proto_tree_add_item(tree, hf_cqich_control_ie_period_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			/* display the frame offset */
			proto_tree_add_item(tree, hf_cqich_control_ie_frame_offset_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			/* display the duration */
			proto_tree_add_item(tree, hf_cqich_control_ie_duration_1, tvb, offset, 3, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* display the CQICH indicator */
			proto_tree_add_item(tree, hf_cqich_control_ie_indicator_1, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* display the CQI reporting threshold */
			proto_tree_add_item(tree, hf_cqich_control_ie_cqi_rep_threshold_1, tvb, offset, 1, ENC_BIG_ENDIAN);
			length = 1;
		}
	}
	else
	{	/* Get the CQICH indicator */
		cqich_indicator = (byte & 0x80);
		if(cqich_indicator)
		{	/* display the CQICH indicator */
			proto_tree_add_item(tree, hf_cqich_control_ie_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the allocation index */
			proto_tree_add_item(tree, hf_cqich_control_ie_alloc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the period */
			proto_tree_add_item(tree, hf_cqich_control_ie_period, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the frame offset */
			proto_tree_add_item(tree, hf_cqich_control_ie_frame_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* display the duration */
			proto_tree_add_item(tree, hf_cqich_control_ie_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
			length = 4;
		}
		else
		{	/* display the CQICH indicator */
			proto_tree_add_item(tree, hf_cqich_control_ie_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* display the CQI reporting threshold */
			proto_tree_add_item(tree, hf_cqich_control_ie_cqi_rep_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
			length = 1;
		}
	}
	/* return the IE length in nibbles */
	return length;
}

/* DL-MAP Extension IE sub-types */
#define TIME_DIVERSITY_MBS  0
#define HARQ_MODE_SWITCH    1

/* Compact DL-MAP Extension IE (6.3.2.3.43.6.6) decoder */
static guint wimax_cdlmap_extension_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint tvb_value, dl_map_type, sub_type, length;

#ifdef DEBUG
	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DL-MAP Extension IE");
#endif
	/* Get the first 16-bit word */
	tvb_value = tvb_get_ntohs(tvb, offset);
	if(nibble_offset & 1)
	{	/* Get the dl-map type */
		dl_map_type = ((tvb_value & 0x0E00) >> 9);
		if(dl_map_type != COMPACT_DL_MAP_TYPE_EXTENSION)
			return 0;
		/* Get the sub-type */
		sub_type = ((tvb_value & 0x01F0) >> 4);
		/* Get the IE length */
		length = (tvb_value & 0x000F);
		/* display the DL-MAP type */
		proto_tree_add_item(tree, hf_cdlmap_extension_type_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the DL-MAP extension subtype */
		proto_tree_add_item(tree, hf_cdlmap_extension_subtype_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the IE length */
		proto_tree_add_item(tree, hf_cdlmap_extension_length_1, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		switch (sub_type)
		{
			case TIME_DIVERSITY_MBS:
			/* display the time-diversity MBS in HEX */
			proto_tree_add_item(tree, hf_cdlmap_extension_time_diversity_mbs_1, tvb, offset, (length - 2), ENC_NA);
			break;
			case HARQ_MODE_SWITCH:
			/* display the HARQ mode */
			proto_tree_add_item(tree, hf_cdlmap_extension_harq_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
			/* Get the next byte */
			tvb_value = tvb_get_guint8(tvb, offset);
			/* get the HARQ mode */
			harq_mode = ((tvb_value & MSB_NIBBLE_MASK) >> 4);
			break;
			default:
			/* display the unknown sub-type in HEX */
			proto_tree_add_item(tree, hf_cdlmap_extension_unknown_sub_type_1, tvb, offset, (length - 2), ENC_NA);
			break;
		}
	}
	else
	{	/* Get the dl-map type */
		dl_map_type = ((tvb_value & 0xE000) >> 13);
		if(dl_map_type != COMPACT_DL_MAP_TYPE_EXTENSION)
			return 0;
		/* Get the sub-type */
		sub_type = ((tvb_value & 0x1F00) >> 8);
		/* Get the IE length */
		length = ((tvb_value & 0x00F0) >> 4);
		/* display the DL-MAP type */
		proto_tree_add_item(tree, hf_cdlmap_extension_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the DL-MAP extension subtype */
		proto_tree_add_item(tree, hf_cdlmap_extension_subtype, tvb, offset, 2, ENC_BIG_ENDIAN);
		/* display the IE length */
		proto_tree_add_item(tree, hf_cdlmap_extension_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		switch (sub_type)
		{
			case TIME_DIVERSITY_MBS:
			/* display the time-diversity MBS in HEX */
			proto_tree_add_item(tree, hf_cdlmap_extension_time_diversity_mbs, tvb, (offset + 1), (length - 1), ENC_NA);
			break;
			case HARQ_MODE_SWITCH:
			/* display the HARQ mode */
			proto_tree_add_item(tree, hf_cdlmap_extension_harq_mode_1, tvb, offset, 2, ENC_BIG_ENDIAN);
			/* get the HARQ mode */
			harq_mode = (tvb_value & 0x000F);
			break;
			default:
			/* display the unknown sub-type in HEX */
			proto_tree_add_item(tree, hf_cdlmap_extension_unknown_sub_type, tvb, (offset + 1), (length - 1), ENC_NA);
			break;
		}
	}
	/* return the IE length in nibbles */
	return (length * 2);
}

/* Extended DIUCs (table 277a) */
#define CHANNEL_MEASUREMENT_IE             0
#define STC_ZONE_IE                        1
#define AAS_DL_IE                          2
#define DATA_LOCATION_IN_ANOTHER_BS_IE     3
#define CID_SWITCH_IE                      4
#define MIMO_DL_BASIC_IE                   5
#define MIMO_DL_ENHANCED_IE                6
#define HARQ_MAP_POINTER_IE                7
#define PHYMOD_DL_IE                       8
#define DL_PUSC_BURST_ALLOCATION_IN_OTHER_SEGMENT_IE 11
#define UL_INTERFERENCE_AND_NOISE_LEVEL_IE 15

/* Extended DIUC IE (8.4.5.3.2) */
guint wimax_extended_diuc_dependent_ie_decoder(proto_tree *tree, packet_info *pinfo _U_, tvbuff_t *tvb, guint offset, guint nibble_offset)
{
	guint ext_diuc, length;
	guint8 byte;

	/* get the first byte */
	byte =  tvb_get_guint8(tvb, offset);
	if(nibble_offset & 1)
	{	/* get the extended DIUC */
		ext_diuc = (byte & LSB_NIBBLE_MASK);
		/* display extended DIUC */
		proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_diuc_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next byte */
		offset++;
		/* get the 2nd byte */
		byte =  tvb_get_guint8(tvb, offset);
		/* get the length */
		length = ((byte & MSB_NIBBLE_MASK) >> 4);
		/* display extended DIUC length */
		proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* 8.4.5.3.2.1 (table 277a) */
		switch (ext_diuc)
		{
			case CHANNEL_MEASUREMENT_IE:
				/* 8.4.5.3.? Channel_Measurement_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_channel_measurement, tvb, offset, (length + 1), ENC_NA);
			break;
			case STC_ZONE_IE:
				/* 8.4.5.3.4 STC_Zone_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_stc_zone, tvb, offset, (length + 1), ENC_NA);
			break;
			case AAS_DL_IE:
				/* 8.4.5.3.3 AAS_DL_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_aas_dl, tvb, offset, (length + 1), ENC_NA);
			break;
			case DATA_LOCATION_IN_ANOTHER_BS_IE:
				/* 8.4.5.3.6 Data_location_in_another_BS_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_data_location, tvb, offset, (length + 1), ENC_NA);
			break;
			case CID_SWITCH_IE:
				/* 8.4.5.3.7 CID_Switch_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_cid_switch, tvb, offset, (length + 1), ENC_NA);
			break;
			case MIMO_DL_BASIC_IE:
				/* 8.4.5.3.8 MIMO_DL_Basic_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_mimo_dl_basic, tvb, offset, (length + 1), ENC_NA);
			break;
			case MIMO_DL_ENHANCED_IE:
				/* 8.4.5.3.9 MIMO_DL_Enhanced_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_mimo_dl_enhanced, tvb, offset, (length + 1), ENC_NA);
			break;
			case HARQ_MAP_POINTER_IE:
				/* 8.4.5.3.10 HARQ_Map_Pointer_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_harq_map_pointer, tvb, offset, (length + 1), ENC_NA);
			break;
			case PHYMOD_DL_IE:
				/* 8.4.5.3.11 PHYMOD_DL_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_phymod_dl, tvb, offset, (length + 1), ENC_NA);
			break;
			case DL_PUSC_BURST_ALLOCATION_IN_OTHER_SEGMENT_IE:
				/* 8.4.5.3.13 DL PUSC Burst Allocation in Other Segment IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_dl_pusc_burst_allocation, tvb, offset, (length + 1), ENC_NA);
			break;
			case UL_INTERFERENCE_AND_NOISE_LEVEL_IE:
				/* 8.4.5.3.19 UL_interference_and_noise_level_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_ul_interference_and_noise_level, tvb, offset, (length + 1), ENC_NA);
			break;
			default:
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_unknown_diuc, tvb, offset, (length + 1), ENC_NA);
			break;
		}
	}
	else
	{	/* get the extended DIUC */
		ext_diuc = ((byte & MSB_NIBBLE_MASK) >> 4);
		/* get the length */
		length = (byte & LSB_NIBBLE_MASK);
		/* display extended DIUC */
		proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_diuc, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* display extended DIUC length */
		proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_length_1, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next byte */
		offset++;
		/* 8.4.5.3.2.1 (table 277a) */
		switch (ext_diuc)
		{
			case CHANNEL_MEASUREMENT_IE:
				/* 8.4.5.3.? Channel_Measurement_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_channel_measurement, tvb, offset, length, ENC_NA);
			break;
			case STC_ZONE_IE:
				/* 8.4.5.3.4 STC_Zone_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_stc_zone, tvb, offset, length, ENC_NA);
			break;
			case AAS_DL_IE:
				/* 8.4.5.3.3 AAS_DL_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_aas_dl, tvb, offset, length, ENC_NA);
			break;
			case DATA_LOCATION_IN_ANOTHER_BS_IE:
				/* 8.4.5.3.6 Data_location_in_another_BS_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_data_location, tvb, offset, length, ENC_NA);
			break;
			case CID_SWITCH_IE:
				/* 8.4.5.3.7 CID_Switch_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_cid_switch, tvb, offset, length, ENC_NA);
			break;
			case MIMO_DL_BASIC_IE:
				/* 8.4.5.3.8 MIMO_DL_Basic_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_mimo_dl_basic, tvb, offset, length, ENC_NA);
			break;
			case MIMO_DL_ENHANCED_IE:
				/* 8.4.5.3.9 MIMO_DL_Enhanced_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_mimo_dl_enhanced, tvb, offset, length, ENC_NA);
			break;
			case HARQ_MAP_POINTER_IE:
				/* 8.4.5.3.10 HARQ_Map_Pointer_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_harq_map_pointer, tvb, offset, length, ENC_NA);
			break;
			case PHYMOD_DL_IE:
				/* 8.4.5.3.11 PHYMOD_DL_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_phymod_dl, tvb, offset, length, ENC_NA);
			break;
			case DL_PUSC_BURST_ALLOCATION_IN_OTHER_SEGMENT_IE:
				/* 8.4.5.3.13 DL PUSC Burst Allocation in Other Segment IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_dl_pusc_burst_allocation, tvb, offset, length, ENC_NA);
			break;
			case UL_INTERFERENCE_AND_NOISE_LEVEL_IE:
				/* 8.4.5.3.19 UL_interference_and_noise_level_IE */
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_ul_interference_and_noise_level, tvb, offset, length, ENC_NA);
			break;
			default:
				proto_tree_add_item(tree, hf_extended_diuc_dependent_ie_unknown_diuc, tvb, offset, length, ENC_NA);
			break;
		}
	}
	return ((length + 1) * 2 ); /* length in nibbles */

}

/* Register Wimax Compact DL-MAP IE Protocol */
void proto_register_wimax_compact_dlmap_ie(void)
{
	/* Compact DL-MAP IE display */
	static hf_register_info hf_compact_dlmap[] =
	{
		{
			&hf_cdlmap_dl_map_type,
			{"DL-MAP Type", "wmx.compact_dlmap.dl_map_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_dl_map_type_1,
			{"DL-MAP Type", "wmx.compact_dlmap.dl_map_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_ul_map_append,
			{"UL-MAP Append", "wmx.compact_dlmap.ul_map_append", FT_UINT8, BASE_HEX, NULL, UL_MAP_APPEND_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_ul_map_append_1,
			{"UL-MAP Append", "wmx.compact_dlmap.ul_map_append", FT_UINT8, BASE_HEX, NULL, UL_MAP_APPEND_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_reserved,
			{"Reserved", "wmx.compact_dlmap.reserved", FT_UINT8, BASE_HEX, NULL, UL_MAP_APPEND_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_reserved_1,
			{"Reserved", "wmx.compact_dlmap.reserved", FT_UINT8, BASE_HEX, NULL, UL_MAP_APPEND_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_nep_code,
			{"Nep Code", "wmx.compact_dlmap.nep_code", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_nep_code_1,
			{"Nep Code", "wmx.compact_dlmap.nep_code", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_nsch_code,
			{"Nsch Code", "wmx.compact_dlmap.nsch_code", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_nsch_code_1,
			{"Nsch Code", "wmx.compact_dlmap.nsch_code", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_num_bands,
			{"Number Of Bands", "wmx.compact_dlmap.num_bands", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_num_bands_1,
			{"Number Of Bands", "wmx.compact_dlmap.num_bands", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_band_index,
			{"Band Index", "wmx.compact_dlmap.band_index", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#if 0
		{
			&hf_cdlmap_band_index_1,
			{"Band Index", "wmx.compact_dlmap.band_index", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{
			&hf_cdlmap_nb_bitmap,
			{"Number Of Bits For Band BITMAP", "wmx.compact_dlmap.nb_bitmap", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_nb_bitmap_1,
			{"Number Of Bits For Band BITMAP", "wmx.compact_dlmap.nb_bitmap", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_shortened_uiuc,
			{"Shortened UIUC", "wmx.compact_dlmap.shortened_uiuc", FT_UINT8, BASE_HEX, NULL, SHORTENED_DIUC_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_shortened_uiuc_1,
			{"Shortened UIUC", "wmx.compact_dlmap.shortened_uiuc", FT_UINT16, BASE_HEX, NULL, SHORTENED_DIUC_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_shortened_diuc,
			{"Shortened DIUC", "wmx.compact_dlmap.shortened_diuc", FT_UINT8, BASE_HEX, NULL, SHORTENED_DIUC_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_shortened_diuc_1,
			{"Shortened DIUC", "wmx.compact_dlmap.shortened_diuc", FT_UINT16, BASE_HEX, NULL, SHORTENED_DIUC_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_companded_sc,
			{"Companded SC", "wmx.compact_dlmap.companded_sc", FT_UINT8, BASE_HEX, NULL, COMPANDED_SC_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_companded_sc_1,
			{"Companded SC", "wmx.compact_dlmap.companded_sc", FT_UINT16, BASE_HEX, NULL, COMPANDED_SC_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_bin_offset,
			{"BIN Offset", "wmx.compact_dlmap.bin_offset", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_bin_offset_1,
			{"BIN Offset", "wmx.compact_dlmap.bin_offset", FT_UINT16, BASE_HEX, NULL, 0x0FF0, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_num_of_subchannels,
			{"Number Of Subchannels", "wmx.compact_dlmap.diuc_num_of_subchannels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_num_of_subchannels_1,
			{"Number Of Subchannels", "wmx.compact_dlmap.diuc_num_of_subchannels", FT_UINT16, BASE_DEC, NULL, 0x0FF0, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_repetition_coding_indication,
			{"Repetition Coding Indication", "wmx.compact_dlmap.diuc_repetition_coding_indication", FT_UINT8, BASE_DEC, VALS(rep_msgs), 0xC0, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_repetition_coding_indication_1,
			{"Repetition Coding Indication", "wmx.compact_dlmap.diuc_repetition_coding_indication", FT_UINT8, BASE_DEC, VALS(rep_msgs), 0x0C, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_reserved,
			{"Reserved", "wmx.compact_dlmap.diuc_reserved", FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_reserved_1,
			{"Reserved", "wmx.compact_dlmap.diuc_reserved", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
		},
		{
			&hf_cdlmap_bit_map_length,
			{"BIT MAP Length", "wmx.compact_dlmap.bit_map_length", FT_UINT8, BASE_DEC, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_bit_map_length_1,
			{"BIT MAP Length", "wmx.compact_dlmap.bit_map_length", FT_UINT8, BASE_DEC, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_bit_map,
			{"BIT MAP", "wmx.compact_dlmap.bit_map", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc,
			{"DIUC", "wmx.compact_dlmap.diuc", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_diuc_1,
			{"DIUC", "wmx.compact_dlmap.diuc", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_allocation_mode,
			{"Allocation Mode", "wmx.compact_dlmap.allocation_mode", FT_UINT8, BASE_DEC, VALS(vals_allocation_modes), 0xC0, NULL, HFILL}
		},
		{
			&hf_cdlmap_allocation_mode_1,
			{"Allocation Mode", "wmx.compact_dlmap.allocation_mode", FT_UINT8, BASE_DEC, VALS(vals_allocation_modes), 0x0C, NULL, HFILL}
		},
		{
			&hf_cdlmap_allocation_mode_rsvd,
			{"Reserved", "wmx.compact_dlmap.allocation_mode_rsvd", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL}
		},
		{
			&hf_cdlmap_allocation_mode_rsvd_1,
			{"Reserved", "wmx.compact_dlmap.allocation_mode_rsvd", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL}
		},
		{
			&hf_cdlmap_num_subchannels,
			{"Number Of Subchannels", "wmx.compact_dlmap.num_subchannels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_num_subchannels_1,
			{"Number Of Subchannels", "wmx.compact_dlmap.num_subchannels", FT_UINT16, BASE_DEC, NULL, 0x0FF0, NULL, HFILL}
		},
		{
			&hf_cdlmap_reserved_type,
			{"DL-MAP Reserved Type", "wmx.compact_dlmap.reserved_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_reserved_type_1,
			{"DL-MAP Reserved Type", "wmx.compact_dlmap.reserved_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK_1, NULL, HFILL}
		}
	};

	/* HARQ MAP Format Configuration IE display */
	static hf_register_info hf_format_config[] =
	{
		{
			&hf_format_config_ie_dl_map_type,
			{"DL-MAP Type", "wmx.format_config_ie.dl_map_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_dl_map_type_1,
			{"DL-MAP Type", "wmx.format_config_ie.dl_map_type", FT_UINT8, BASE_DEC, NULL, DL_MAP_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_dl_map_type_32,
			{"DL-MAP Type", "wmx.format_config_ie.dl_map_type", FT_UINT32, BASE_DEC, NULL, FORMAT_CONFIG_IE_DL_MAP_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_new_format_indication,
			{"New Format Indication", "wmx.format_config_ie.new_format_indication", FT_BOOLEAN, 8, TFS(&tfs_indication), UL_MAP_APPEND_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_new_format_indication_1,
			{"New Format Indication", "wmx.format_config_ie.new_format_indication", FT_BOOLEAN, 8, TFS(&tfs_indication), UL_MAP_APPEND_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_new_format_indication_32,
			{"New Format Indication", "wmx.format_config_ie.new_format_indication", FT_BOOLEAN, 32, TFS(&tfs_indication), FORMAT_CONFIG_IE_NEW_FORMAT_IND_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_cid_type,
			{"HARQ MAP Indicator", "wmx.harq_map.format_config_ie.indicator", FT_UINT32, BASE_HEX, VALS(vals_cid_types), CID_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_cid_type_1,
			{"CID Type", "wmx.harq_map.format_config_ie.cid_type", FT_UINT32, BASE_HEX, VALS(vals_cid_types), CID_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_safety_pattern,
			{"Safety Pattern", "wmx.harq_map.format_config_ie.safety_pattern", FT_UINT32, BASE_HEX, NULL, SAFETY_PATTERN_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_safety_pattern_1,
			{"Safety Pattern", "wmx.harq_map.format_config_ie.safety_pattern", FT_UINT32, BASE_HEX, NULL, SAFETY_PATTERN_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_subchannel_type,
			{"Subchannel Type For Band AMC", "wmx.harq_map.format_config_ie.subchannel_type", FT_UINT32, BASE_HEX, VALS(vals_subchannel_types), BAND_AMC_SUBCHANNEL_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_subchannel_type_1,
			{"Subchannel Type For Band AMC", "wmx.harq_map.format_config_ie.subchannel_type", FT_UINT32, BASE_HEX, VALS(vals_subchannel_types), BAND_AMC_SUBCHANNEL_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_max_logical_bands,
			{"Max Logical Bands", "wmx.harq_map.format_config_ie.max_logical_bands", FT_UINT32, BASE_HEX, VALS(vals_max_logical_bands), MAX_LOGICAL_BANDS_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_max_logical_bands_1,
			{"Max Logical Bands", "wmx.harq_map.format_config_ie.max_logical_bands", FT_UINT32, BASE_HEX, VALS(vals_max_logical_bands), MAX_LOGICAL_BANDS_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_broadcast_symbol,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.format_config_ie.num_of_broadcast_symbol", FT_UINT32, BASE_HEX, NULL, NUM_BROADCAST_SYMBOLS_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_broadcast_symbol_1,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.num_of_broadcast_symbol", FT_UINT32, BASE_HEX, NULL, NUM_BROADCAST_SYMBOLS_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_dl_band_amc_symbol,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.format_config_ie.num_of_dl_band_amc_symbol", FT_UINT32, BASE_HEX, NULL, NUM_DL_AMC_SYMBOLS_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_dl_band_amc_symbol_1,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.num_of_dl_band_amc_symbol", FT_UINT32, BASE_HEX, NULL, NUM_DL_AMC_SYMBOLS_MASK_1, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_ul_band_amc_symbol,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.format_config_ie.num_of_ul_band_amc_symbol", FT_UINT32, BASE_HEX, NULL, NUM_UL_AMC_SYMBOLS_MASK, NULL, HFILL}
		},
		{
			&hf_format_config_ie_num_of_ul_band_amc_symbol_1,
			{"Number Of Symbols for Broadcast", "wmx.harq_map.num_of_ul_band_amc_symbol", FT_UINT32, BASE_HEX, NULL, NUM_UL_AMC_SYMBOLS_MASK_1, NULL, HFILL}
		}
	};

	/* HARQ MAP Reduced CID IE display */
	static hf_register_info hf_rcid[] =
	{
		{
			&hf_harq_rcid_ie_normal_cid,
			{"Normal CID", "wmx.harq_map.rcid_ie.normal_cid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_normal_cid_1,
			{"Normal CID", "wmx.harq_map.rcid_ie.normal_cid", FT_UINT24, BASE_HEX, NULL, WIMAX_RCID_IE_NORMAL_CID_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_prefix,
			{"Prefix", "wmx.harq_map.rcid_ie.prefix", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_PREFIX_MASK, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_prefix_1,
			{"Prefix", "wmx.harq_map.rcid_ie.prefix", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_PREFIX_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid3,
			{"3 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid3", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID3_MASK, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid3_1,
			{"3 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid3", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID3_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid7,
			{"7 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid7", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID7_MASK, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid7_1,
			{"7 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid7", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID7_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid11,
			{"11 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid11_1,
			{"11 LSB Of Basic CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK_1, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid11_2,
			{"11 LSB Of Multicast, AAS or Broadcast CID", "wmx.harq_map.rcid_ie.cid11", FT_UINT16, BASE_HEX, NULL, WIMAX_RCID_IE_CID11_MASK, NULL, HFILL}
		},
		{
			&hf_harq_rcid_ie_cid11_3,
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

	/* HARQ MAP CQICH Control IE display */
	static hf_register_info hf_cqich_control[] =
	{
		{
			&hf_cqich_control_ie_indicator,
			{"CQICH Indicator", "wmx.harq_map.cqich_control_ie.cqich_indicator", FT_BOOLEAN, 16, TFS(&tfs_cqich_ind), WIMAX_CQICH_CONTROL_IE_INDICATOR_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_alloc_id,
			{"Allocation Index", "wmx.harq_map.cqich_control_ie.alloc_id", FT_UINT16, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_ALLOCATION_INDEX_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_period,
			{"PERIOD", "wmx.harq_map.cqich_control_ie.period", FT_UINT16, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_PERIOD_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_frame_offset,
			{"Frame Offset", "wmx.harq_map.cqich_control_ie.frame_offset", FT_UINT16, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_FRAME_OFFSET_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_duration,
			{"Duration", "wmx.harq_map.cqich_control_ie.duration", FT_UINT16, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_DURATION_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_cqi_rep_threshold,
			{"CQI Reporting Threshold", "wmx.harq_map.cqich_control_ie.cqi_rep_threshold", FT_UINT16, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_CQI_REP_THRESHOLD_MASK, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_indicator_1,
			{"CQICH Indicator", "wmx.harq_map.cqich_control_ie.cqich_indicator", FT_BOOLEAN, 24, TFS(&tfs_cqich_ind), WIMAX_CQICH_CONTROL_IE_INDICATOR_MASK_1, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_alloc_id_1,
			{"Allocation Index", "wmx.harq_map.cqich_control_ie.alloc_id", FT_UINT24, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_ALLOCATION_INDEX_MASK_1, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_period_1,
			{"PERIOD", "wmx.harq_map.cqich_control_ie.period", FT_UINT24, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_PERIOD_MASK_1, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_frame_offset_1,
			{"Frame Offset", "wmx.harq_map.cqich_control_ie.frame_offset", FT_UINT24, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_FRAME_OFFSET_MASK_1, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_duration_1,
			{"Duration", "wmx.harq_map.cqich_control_ie.duration", FT_UINT24, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_DURATION_MASK_1, NULL, HFILL}
		},
		{
			&hf_cqich_control_ie_cqi_rep_threshold_1,
			{"CQI Reporting Threshold", "wmx.harq_map.cqich_control_ie.cqi_rep_threshold", FT_UINT24, BASE_HEX, NULL, WIMAX_CQICH_CONTROL_IE_CQI_REP_THRESHOLD_MASK_1, NULL, HFILL}
		}
	};

	static hf_register_info hf_extension_type[] =
	{
		{
			&hf_cdlmap_extension_type,
			{"DL-MAP Type", "wmx.extension_type.dl_map_type", FT_UINT16, BASE_DEC, NULL, EXTENSION_TYPE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_type_1,
			{"DL-MAP Type", "wmx.extension_type.dl_map_type", FT_UINT16, BASE_DEC, NULL, EXTENSION_TYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_subtype,
			{"Extension Subtype", "wmx.extension_type.subtype", FT_UINT16, BASE_DEC, NULL, EXTENSION_SUBTYPE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_subtype_1,
			{"Extension Subtype", "wmx.extension_type.subtype", FT_UINT16, BASE_DEC, NULL, EXTENSION_SUBTYPE_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_length,
			{"Extension Length", "wmx.extension_type.length", FT_UINT16, BASE_DEC, NULL, EXTENSION_LENGTH_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_length_1,
			{"Extension Length", "wmx.extension_type.length", FT_UINT16, BASE_DEC, NULL, EXTENSION_LENGTH_MASK_1, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_time_diversity_mbs,
			{"Time Diversity MBS", "wmx.extension_type.time_diversity_mbs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_time_diversity_mbs_1,
			{"Time Diversity MBS", "wmx.extension_type.time_diversity_mbs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_harq_mode_1,
			{"HARQ Mode Switch", "wmx.extension_type.harq_mode", FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_harq_mode,
			{"HARQ Mode Switch", "wmx.extension_type.harq_mode", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_unknown_sub_type,
			{"Unknown Extension Subtype", "wmx.extension_type.unknown_sub_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cdlmap_extension_unknown_sub_type_1,
			{"Unknown Extension Subtype", "wmx.extension_type.unknown_sub_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	/* Extended DIUC dependent IE */
	static hf_register_info hf_extended_diuc[] =
	{
		{
			&hf_extended_diuc_dependent_ie_diuc,
			{"Extended DIUC", "wmx.extended_diuc_dependent_ie.diuc", FT_UINT8, BASE_HEX, NULL, MSB_NIBBLE_MASK, NULL, HFILL }
		},
		{
			&hf_extended_diuc_dependent_ie_diuc_1,
			{"Extended DIUC", "wmx.extended_diuc_dependent_ie.diuc", FT_UINT8, BASE_HEX, NULL, LSB_NIBBLE_MASK, NULL, HFILL }
		},
		{
			&hf_extended_diuc_dependent_ie_length,
			{"Length", "wmx.extended_diuc_dependent_ie.length", FT_UINT8, BASE_DEC, NULL, MSB_NIBBLE_MASK, NULL, HFILL }
		},
		{
			&hf_extended_diuc_dependent_ie_length_1,
			{"Length", "wmx.extended_diuc_dependent_ie.length", FT_UINT8, BASE_DEC, NULL, LSB_NIBBLE_MASK, NULL, HFILL }
		},
		{	/* 8.4.5.3.? Channel_Measurement_IE */
			&hf_extended_diuc_dependent_ie_channel_measurement,
			{"Channel_Measurement_IE (not implemented)", "wmx.extended_diuc_dependent_ie.channel_measurement", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.4 STC_Zone_IE */
			&hf_extended_diuc_dependent_ie_stc_zone,
			{"STC_Zone_IE (not implemented)", "wmx.extended_diuc_dependent_ie.stc_zone", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.3 AAS_DL_IE */
			&hf_extended_diuc_dependent_ie_aas_dl,
			{"AAS_DL_IE (not implemented)", "wmx.extended_diuc_dependent_ie.aas_dl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.6 Data_location_in_another_BS_IE */
			&hf_extended_diuc_dependent_ie_data_location,
			{"Data_location_in_another_BS_IE (not implemented)", "wmx.extended_diuc_dependent_ie.data_location", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.7 CID_Switch_IE */
			&hf_extended_diuc_dependent_ie_cid_switch,
			{"CID_Switch_IE (not implemented)", "wmx.extended_diuc_dependent_ie.cid_switch", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		{	/* 8.4.5.3.8 MIMO_DL_Basic_IE */
			&hf_extended_diuc_dependent_ie_mimo_dl_basic,
			{"MIMO_DL_Basic_IE (not implemented)", "wmx.extended_diuc_dependent_ie.mimo_dl_basic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.9 MIMO_DL_Enhanced_IE */
			&hf_extended_diuc_dependent_ie_mimo_dl_enhanced,
			{"MIMO_DL_Enhanced_IE (not implemented)", "wmx.extended_diuc_dependent_ie.mimo_dl_enhanced", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.10 HARQ_Map_Pointer_IE */
			&hf_extended_diuc_dependent_ie_harq_map_pointer,
			{"HARQ_Map_Pointer_IE (not implemented)", "wmx.extended_diuc_dependent_ie.harq_map_pointer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.11 PHYMOD_DL_IE */
			&hf_extended_diuc_dependent_ie_phymod_dl,
			{"PHYMOD_DL_IE (not implemented)", "wmx.extended_diuc_dependent_ie.phymod_dl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.13 DL PUSC Burst Allocation in Other Segment IE */
			&hf_extended_diuc_dependent_ie_dl_pusc_burst_allocation,
			{"DL_PUSC_Burst_Allocation_in_Other_Segment_IE (not implemented)", "wmx.extended_diuc_dependent_ie.dl_pusc_burst_allocation", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* 8.4.5.3.19 UL_interference_and_noise_level_IE */
			&hf_extended_diuc_dependent_ie_ul_interference_and_noise_level,
			{"UL_interference_and_noise_level_IE (not implemented)", "wmx.extended_diuc_dependent_ie.ul_interference_and_noise_level", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{	/* unknown DIUC */
			&hf_extended_diuc_dependent_ie_unknown_diuc,
			{"Unknown Extended DIUC", "wmx.extended_diuc_dependent_ie.unknown_diuc", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

#if 0 /* Not used ?? */
        /* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_wimax_compact_dlmap_ie_decoder,
			&ett_wimax_format_configuration_ie_decoder,
			&ett_wimax_rcid_ie_decoder,
			&ett_wimax_harq_control_ie_decoder,
			&ett_wimax_extended_diuc_dependent_ie_decoder,
			&ett_wimax_cqich_control_ie_decoder,
			&ett_wimax_extension_type_ie_decoder,
		};
	proto_register_subtree_array(ett, array_length(ett));
#endif

	proto_wimax_compact_dlmap_ie_decoder = proto_wimax;

	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_compact_dlmap, array_length(hf_compact_dlmap));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_format_config, array_length(hf_format_config));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_rcid, array_length(hf_rcid));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_harq_control, array_length(hf_harq_control));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_cqich_control, array_length(hf_cqich_control));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_extension_type, array_length(hf_extension_type));
	proto_register_field_array(proto_wimax_compact_dlmap_ie_decoder, hf_extended_diuc, array_length(hf_extended_diuc));
}

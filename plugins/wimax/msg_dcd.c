/* msg_dcd.c
 * WiMax MAC Management DCD Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
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

/*
#define DEBUG
*/

#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"

/* Delete the following variable as soon as possible */
extern gboolean include_cor2_changes;

void proto_register_mac_mgmt_msg_dcd(void);
void proto_reg_handoff_mac_mgmt_msg_dcd(void);

static gint proto_mac_mgmt_msg_dcd_decoder = -1;
static gint ett_mac_mgmt_msg_dcd_decoder = -1;

/* fix fields */
static gint hf_dcd_downlink_channel_id = -1;
static gint hf_dcd_config_change_count = -1;
static gint hf_dcd_dl_burst_profile_rsv = -1;
static gint hf_dcd_dl_burst_profile_diuc = -1;

static gint hf_dcd_bs_eirp = -1;
static gint hf_dcd_frame_duration = -1;
static gint hf_dcd_phy_type = -1;
static gint hf_dcd_power_adjustment = -1;
static gint hf_dcd_channel_nr = -1;
static gint hf_dcd_ttg = -1;
static gint hf_dcd_rtg = -1;
#ifdef	WIMAX_16D_2004
static gint hf_dcd_rss = -1;
#endif
static gint hf_dcd_channel_switch_frame_nr = -1;
static gint hf_dcd_frequency = -1;
static gint hf_dcd_bs_id = -1;
static gint hf_dcd_frame_duration_code = -1;
static gint hf_dcd_frame_nr = -1;
#ifdef  WIMAX_16D_2004
static gint hf_dcd_size_cqich_id = -1;
#endif
static gint hf_dcd_h_arq_ack_delay = -1;
static gint hf_dcd_mac_version = -1;
static gint hf_dcd_restart_count = -1;

/* static gint hf_dl_burst_reserved = -1; */
/* static gint hf_dl_burst_diuc = -1; */
static gint hf_dcd_burst_freq = -1;
static gint hf_dcd_burst_fec = -1;
static gint hf_dcd_burst_diuc_exit_threshold = -1;
static gint hf_dcd_burst_diuc_entry_threshold = -1;
static gint hf_dcd_burst_tcs = -1;
static gint hf_dcd_tlv_t_19_permutation_type_for_broadcast_regions_in_harq_zone = -1;
static gint hf_dcd_tlv_t_20_maximum_retransmission = -1;
static gint hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter = -1;
static gint hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_physical_cinr_measurements = -1;
static gint hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_rssi_measurements = -1;
static gint hf_dcd_tlv_t_22_dl_amc_allocated_physical_bands_bitmap = -1;

static gint hf_dcd_tlv_t_34_dl_region_definition = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_num_region = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_reserved = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_symbol_offset = -1;
static gint hf_dcd_eirxp = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_subchannel_offset = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_num_symbols = -1;
static gint hf_dcd_tlv_t_34_dl_region_definition_num_subchannels = -1;
static gint hf_dcd_tlv_t_50_ho_type_support = -1;
static gint hf_dcd_tlv_t_50_ho_type_support_ho = -1;
static gint hf_dcd_tlv_t_50_ho_type_support_mdho = -1;
static gint hf_dcd_tlv_t_50_ho_type_support_fbss_ho = -1;
static gint hf_dcd_tlv_t_50_ho_type_support_reserved = -1;
static gint hf_dcd_tlv_t_31_h_add_threshold = -1;
static gint hf_dcd_tlv_t_45_paging_interval_length = -1;
static gint hf_dcd_tlv_t_45_paging_interval_reserved = -1;
static gint hf_dcd_tlv_t_32_h_delete_threshold = -1;
static gint hf_dcd_tlv_t_33_asr = -1;
static gint hf_dcd_tlv_t_33_asr_m = -1;
static gint hf_dcd_tlv_t_33_asr_l = -1;
static gint hf_dcd_tlv_t_35_paging_group_id = -1;
static gint hf_dcd_tlv_t_36_tusc1_permutation_active_subchannels_bitmap = -1;
static gint hf_dcd_tlv_t_37_tusc2_permutation_active_subchannels_bitmap = -1;
static gint hf_dcd_tlv_t_51_hysteresis_margin = -1;
static gint hf_dcd_tlv_t_52_time_to_trigger_duration = -1;
static gint hf_dcd_tlv_t_60_noise_interference = -1;
static gint hf_dcd_tlv_t_153_downlink_burst_profile_for_mutiple_fec_types = -1;

static gint hf_dcd_tlv_t_541_type_function_action       = -1;
static gint hf_dcd_tlv_t_541_type = -1;
static gint hf_dcd_tlv_t_541_function = -1;
static gint hf_dcd_tlv_t_541_action = -1;
static gint hf_dcd_tlv_t_542_trigger_value = -1;
static gint hf_dcd_tlv_t_543_trigger_averaging_duration = -1;

static gint hf_dcd_unknown_type = -1;
static gint hf_dcd_invalid_tlv = -1;

/* DCD DIUC messages (table 143) */
static const value_string diuc_msgs[] =
{
	{ 0, "Downlink Burst Profile 1"},
	{ 1, "Downlink Burst Profile 2"},
	{ 2, "Downlink Burst Profile 3"},
	{ 3, "Downlink Burst Profile 4"},
	{ 4, "Downlink Burst Profile 5"},
	{ 5, "Downlink Burst Profile 6"},
	{ 6, "Downlink Burst Profile 7"},
	{ 7, "Downlink Burst Profile 8"},
	{ 8, "Downlink Burst Profile 9"},
	{ 9, "Downlink Burst Profile 10"},
	{10, "Downlink Burst Profile 11"},
	{11, "Downlink Burst Profile 12"},
	{12, "Downlink Burst Profile 13"},
	{13, "Reserved"},
	{14, "Gap"},
	{15, "End of DL-MAP"},
	{0,  NULL}
};

static const value_string vals_dcd_type[] =
{
    {0, "CINR metric"},
    {1, "RSSI metric"},
    {2, "RTD metric"},
    {3, "Reserved"},
    {0,  NULL}
};

static const value_string vals_dcd_function[] =
{
    {0, "Reserved"},
    {1, "Metric of neighbor BS is greater than absolute value"},
    {2, "Metric of neighbor BS is less than absolute value"},
    {3, "Metric of neighbor BS is greater than serving BS metric by relative value"},
    {4, "Metric of neighbor BS is less than serving BS metric by relative value"},
    {5, "Metric of serving BS greater than absolute value"},
    {6, "Metric of serving BS less than absolute value"},
    {7, "Reserved"},
    {0,  NULL}
};

static const value_string vals_dcd_action[] =
{
    {0, "Reserved"},
    {1, "Respond on trigger with MOB_SCN-REP after the end of each scanning interval"},
    {2, "Respond on trigger with MOB_MSH-REQ"},
    {3, "On trigger, MS starts neighbor BS scanning process by sending MOB_SCN-REQ"},
    {4, "Reserved"},
    {0,  NULL}
};

static const value_string vals_dcd_power_adjustmnt[] =
{
    {0, "Preserve Peak Power"},
    {1, "Preserve Mean Power"},
    {0,  NULL}
};

#if 0
static const true_false_string tfs_dcd_power_adjustment =
{
    "Preserve Mean Power",
    "Preserve Peak Power"
};
#endif

#if 0
static const value_string vals_reg_rsp_status[] =
{
    {0, "OK"},
    {1, "Message authentication failure"},
    {0,  NULL}
};
#endif

static const value_string vals_dcd_burst_tcs[] =
{
    {0, "TCS disabled"},
    {1, "TCS enabled"},
    {0,  NULL}
};

#if 0
static const true_false_string tfs_dcd_burst_tcs =
{
    "TCS enabled",
    "TCS disabled"
};
#endif

static const value_string vals_dcd_frame_duration[] =
{
    {0, "2.5"},
    {1, "4"},
    {2, "5"},
    {3, "8"},
    {4, "10"},
    {5, "12.5"},
    {6, "20"},
    {0,  NULL}
};

#ifdef WIMAX_16D_2004
static const value_string vals_dcd_size_of_cqich_id[] =
{
    {0, "Reserved"},
    {1, "3 bits"},
    {2, "4 bits"},
    {3, "5 bits"},
    {4, "6 bits"},
    {5, "7 bits"},
    {6, "8 bits"},
    {7, "9 bits"},
    {0,  NULL}
};
#endif

static const value_string vals_dcd_mac_version[] =
{
    { 1, "Conformance with IEEE Std 802.16-2001"},
    { 2, "Conformance with IEEE Std 802.16c-2002 and its predecessors"},
    { 3, "Conformance with IEEE Std 802.16a-2003 and its predecessors"},
    { 4, "Conformance with IEEE Std 802.16-2004"},
    { 5, "Conformance with IEEE Std 802.16-2004 and IEEE Std 802.16e-2005"},
    { 6, "Conformance with IEEE Std 802.16-2004, IEEE Std 802.16e-2005 and IEEE Std 802.16f-2005"},
    { 7, "Conformance with IEEE Std 802.16-2004, IEEE Std 802.16e-2005, IEEE Std 802.16f-2005 and IEEE Std 802.16g-2007"},
    { 8, "Conformance with IEEE Std 802.16-2009"},
    { 9, "Conformance with IEEE Std 802.16-2009 and IEEE Std 802.16j-2009"},
    {10, "Reserved"},
    {0, NULL}
};

/* table 363 */
static const value_string vals_dcd_burst_fec_ofdma[] =
{
    { 0, "QPSK (CC) 1/2"},
    { 1, "QPSK (CC) 3/4"},
    { 2, "16-QAM (CC) 1/2"},
    { 3, "16-QAM (CC) 3/4"},
    { 4, "64-QAM (CC) 1/2"},
    { 5, "64-QAM (CC) 2/3"},
    { 6, "64-QAM (CC) 3/4"},
    { 7, "QPSK (BTC) 1/2"},
    { 8, "QPSK (BTC) 3/4 or 2/3"},
    { 9, "16-QAM (BTC) 3/5"},
    {10, "16-QAM (BTC) 4/5"},
    {11, "64-QAM (BTC) 2/3 or 5/8"},
    {12, "64-QAM (BTC) 5/6 or 4/5"},
    {13, "QPSK (CTC) 1/2"},
    {14, "Reserved"},
    {15, "QPSK (CTC) 3/4"},
    {16, "16-QAM (CTC) 1/2"},
    {17, "16-QAM (CTC) 3/4"},
    {18, "64-QAM (CTC) 1/2"},
    {19, "64-QAM (CTC) 2/3"},
    {20, "64-QAM (CTC) 3/4"},
    {21, "64-QAM (CTC) 5/6"},
    {22, "QPSK (ZT CC) 1/2"},
    {23, "QPSK (ZT CC) 3/4"},
    {24, "16-QAM (ZT CC) 1/2"},
    {25, "16-QAM (ZT CC) 3/4"},
    {26, "64-QAM (ZT CC) 1/2"},
    {27, "64-QAM (ZT CC) 2/3"},
    {28, "64-QAM (ZT CC) 3/4"},
    {29, "QPSK (LDPC) 1/2"},
    {30, "QPSK (LDPC) 2/3 A code"},
    {31, "16-QAM (LDPC) 3/4 A code"},
    {32, "16-QAM (LDPC) 1/2"},
    {33, "16-QAM (LDPC) 2/3 A code"},
    {34, "16-QAM (LDPC) 3/4 A code"},
    {35, "64-QAM (LDPC) 1/2"},
    {36, "64-QAM (LDPC) 2/3 A code"},
    {37, "64-QAM (LDPC) 3/4 A code"},
    {38, "QPSK (LDPC) 2/3 B code"},
    {39, "QPSK (LDPC) 3/4 B code"},
    {40, "16-QAM (LDPC) 2/3 B code"},
    {41, "16-QAM (LDPC) 3/4 B code"},
    {42, "64-QAM (LDPC) 2/3 B code"},
    {43, "64-QAM (LDPC) 3/4 B code"},
    {44, "QPSK (CC with optional interleaver) 1/2"},
    {45, "QPSK (CC with optional interleaver) 3/4"},
    {46, "16-QAM (CC with optional interleaver) 1/2"},
    {47, "16-QAM (CC optional interleaver) 3/4"},
    {48, "64-QAM (CC with optional interleaver) 2/3"},
    {49, "64-QAM (CC with optional interleaver) 3/4"},
    {50, "QPSK (LDPC) 5/6"},
    {51, "16-QAM (LDPC) 5/6"},
    {52, "64-QAM (LDPC) 5/6"},
    {0,  NULL}
};

static const value_string vals_dcd_permutation_type[] =
{
    {0, "PUSC"},
    {1, "FUSC"},
    {2, "optional FUSC"},
    {3, "AMC"},
    {0,  NULL}
};

static const value_string tfs_support[] =
{
    {0, "not supported"},
    {1, "supported"},
    {0,  NULL}
};


/* WiMax MAC Management DCD message (table 15) dissector */
static int dissect_mac_mgmt_msg_dcd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset = 0;
	guint tvb_len, length;
	gint  tlv_type, tlv_len, tlv_offset, tlv_value_offset;
	guint dl_burst_diuc, dl_num_regions;
	proto_item *dcd_item, *tlv_item, *sub_item;
	proto_tree *dcd_tree, *tlv_tree, *sub_tree;
	tlv_info_t tlv_info;
	gchar* proto_str;

	{	/* we are being asked for details */
		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type DCD */
		dcd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_dcd_decoder, tvb, offset, tvb_len, "Downlink Channel Descriptor (DCD)");
		/* add MAC DCD subtree */
		dcd_tree = proto_item_add_subtree(dcd_item, ett_mac_mgmt_msg_dcd_decoder);
		/* Decode and display the Downlink Channel Descriptor (DCD) */
		/* display the Downlink Channel ID */
		proto_tree_add_item(dcd_tree, hf_dcd_downlink_channel_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the Configuration Change Count */
		offset++;
		/* display the Configuration Change Count */
		proto_tree_add_item(dcd_tree, hf_dcd_config_change_count, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* set the offset for the TLV Encoded info */
		offset++;
		/* process the DCD TLV Encoded information (table 358) */
		while(offset < tvb_len)
		{
			/* get the TLV information */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DCD TLV error");
				proto_tree_add_item(dcd_tree, hf_dcd_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the TLV value offset */
			tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
			proto_tree_add_protocol_format(dcd_tree, proto_mac_mgmt_msg_dcd_decoder, tvb, offset, (tlv_len + tlv_value_offset), "DCD Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len, offset, tvb_len);
#endif
			/* update the offset */
			offset += tlv_value_offset;
			/* process DCD TLVs */
			switch (tlv_type)
			{
				case DCD_DOWNLINK_BURST_PROFILE:
				{	/* Downlink Burst Profile TLV (table 363)*/
					/* get the DIUC */
					dl_burst_diuc = (tvb_get_guint8(tvb, offset) & 0x0F);
					/* display TLV info */
					/* add TLV subtree */
					proto_str = wmem_strdup_printf(wmem_packet_scope(), "Downlink_Burst_Profile (DIUC=%u)", dl_burst_diuc);
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dcd_decoder, dcd_tree, proto_mac_mgmt_msg_dcd_decoder, tvb, offset-tlv_value_offset, tlv_len, proto_str);
					/* detail display */
					proto_tree_add_item(tlv_tree, hf_dcd_dl_burst_profile_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_dl_burst_profile_diuc, tvb, offset, 1, ENC_BIG_ENDIAN);
					/* process subTLVs */
					for (tlv_offset = 1; tlv_offset < tlv_len;  )
					{	/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, (offset+tlv_offset));
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "DL Burst Profile TLV error");
							proto_tree_add_item(tlv_tree, hf_dcd_invalid_tlv, tvb, offset, (tlv_len - offset - tlv_offset), ENC_NA);
							break;
						}

						switch (tlv_type)
						{
							case DCD_BURST_FREQUENCY:
							{
								tlv_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_burst_freq, tvb, (offset+tlv_offset), ENC_BIG_ENDIAN);
								proto_item_append_text(tlv_item, " kHz");
								break;
							}
							case DCD_BURST_FEC_CODE_TYPE:
							{
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_burst_fec, tvb, (offset+tlv_offset), ENC_BIG_ENDIAN);
								break;
							}
							case DCD_BURST_DIUC_EXIT_THRESHOLD:
							{
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_burst_diuc_exit_threshold, tvb, (offset+tlv_offset), ENC_BIG_ENDIAN);
								break;
							}
							case DCD_BURST_DIUC_ENTRY_THRESHOLD:
							{
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_burst_diuc_entry_threshold, tvb, (offset+tlv_offset), ENC_BIG_ENDIAN);
								break;
							}
							case DCD_BURST_TCS_ENABLE:
							{
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_burst_tcs, tvb, (offset+tlv_offset), ENC_BIG_ENDIAN);
								break;
							}
							default:
								/* ??? */
								break;
						}
						tlv_offset += (length+get_tlv_value_offset(&tlv_info));
					}
					break;
				}
				case DCD_BS_EIRP:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_bs_eirp, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dBm");
					break;
				}
				case DCD_FRAME_DURATION:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_frame_duration, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_PHY_TYPE:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_phy_type, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_POWER_ADJUSTMENT:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_power_adjustment, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_CHANNEL_NR:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_channel_nr, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TTG:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_ttg, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " PS");
					break;
				}
				case DCD_RTG:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_rtg, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " PS");
					break;
				}
#ifdef WIMAX_16D_2004
				case DCD_RSS:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_rss, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dBm");
					break;
				}
#else
				case DCD_EIRXP:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_eirxp, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dBm");
					break;
				}
#endif
				case DCD_CHANNEL_SWITCH_FRAME_NR:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_channel_switch_frame_nr, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_FREQUENCY:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_frequency, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " kHz");
					break;
				}
				case DCD_BS_ID:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_bs_id, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_FRAME_DURATION_CODE:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_frame_duration_code, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_FRAME_NR:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_frame_nr, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
#ifdef WIMAX_16D_2004
				case DCD_SIZE_CQICH_ID:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_size_cqich_id, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
#endif
				case DCD_H_ARQ_ACK_DELAY:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_h_arq_ack_delay, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " frame offset");
					break;
				}
				case DCD_MAC_VERSION:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_mac_version, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_19_PERMUTATION_TYPE_FOR_BROADCAST_REGION_IN_HARQ_ZONE:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_19_permutation_type_for_broadcast_regions_in_harq_zone, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_20_MAXIMUM_RETRANSMISSION:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_20_maximum_retransmission, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_21_DEFAULT_RSSI_AND_CINR_AVERAGING_PARAMETER:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_mac_mgmt_msg_dcd_decoder);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_physical_cinr_measurements, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_rssi_measurements, tvb, offset, 1, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_22_DL_AMC_ALLOCATED_PHYSICAL_BANDS_BITMAP:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_22_dl_amc_allocated_physical_bands_bitmap, tvb, offset-tlv_value_offset, ENC_NA);
					break;
				}
				case DCD_TLV_T_34_DL_REGION_DEFINITION:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_34_dl_region_definition, tvb, offset-tlv_value_offset, ENC_NA);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_mac_mgmt_msg_dcd_decoder);
					dl_num_regions = tvb_get_guint8(tvb, offset);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_num_region, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
					tlv_offset = offset;
					for(length = 0; length < dl_num_regions; length++)
					{
						proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_symbol_offset, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_subchannel_offset, tvb, (tlv_offset+1), 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_num_symbols, tvb, (tlv_offset+2), 1, ENC_BIG_ENDIAN);
						proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_34_dl_region_definition_num_subchannels, tvb, (tlv_offset+3), 1, ENC_BIG_ENDIAN);
						tlv_offset += 4;
					}
					break;
				}
				case DCD_TLV_T_50_HO_TYPE_SUPPORT:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_50_ho_type_support, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_mac_mgmt_msg_dcd_decoder);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_50_ho_type_support_ho, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_50_ho_type_support_mdho, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_50_ho_type_support_fbss_ho, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_50_ho_type_support_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_31_H_ADD_THRESHOLD:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_31_h_add_threshold, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dB");
					break;
				}
				case DCD_TLV_T_32_H_DELETE_THRESHOLD:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_32_h_delete_threshold, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dB");
					break;
				}
				case DCD_TLV_T_33_ASR:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_33_asr, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_mac_mgmt_msg_dcd_decoder);
					tlv_item = proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_33_asr_m, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " frames");
					tlv_item = proto_tree_add_item(tlv_tree, hf_dcd_tlv_t_33_asr_l, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " frames");
					break;
				}
				case DCD_TLV_T_35_PAGING_GROUP_ID:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_35_paging_group_id, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_36_TUSC1_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_36_tusc1_permutation_active_subchannels_bitmap, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_37_TUSC2_PERMUTATION_ACTIVE_SUBCHANNELS_BITMAP:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_37_tusc2_permutation_active_subchannels_bitmap, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_51_HYSTERSIS_MARGIN:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_51_hysteresis_margin, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " dB");
					break;
				}
				case DCD_TLV_T_52_TIME_TO_TRIGGER_DURATION:
				{
					tlv_item = add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_52_time_to_trigger_duration, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item, " ms");
					break;
				}
				case DCD_TLV_T_54_TRIGGER:
				{	/* Trigger TLV (table 358a & 358b) */
					/* add TLV subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_dcd_decoder, dcd_tree, proto_mac_mgmt_msg_dcd_decoder, tvb, offset-tlv_value_offset, tlv_len, "DCD Trigger");
					for (tlv_offset = 0; tlv_offset < tlv_len;  )
					{
						/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, (offset + tlv_offset));
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Trigger TLV error");
							proto_tree_add_item(tlv_tree, hf_dcd_invalid_tlv, tvb, offset, (tlv_len - offset - tlv_offset), ENC_NA);
							break;
						}
						/* update the offset */
						tlv_offset += get_tlv_value_offset(&tlv_info);
						/* table 358a */
						switch (tlv_type)
						{
							case DCD_TLV_T_541_TYPE_FUNCTION_ACTION:
							{	/* table 358b */
								sub_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_tlv_t_541_type_function_action, tvb, (offset + tlv_offset)-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
								sub_tree = proto_item_add_subtree(sub_item, ett_mac_mgmt_msg_dcd_decoder);
								proto_tree_add_item(sub_tree, hf_dcd_tlv_t_541_type, tvb, (offset + tlv_offset), 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(sub_tree, hf_dcd_tlv_t_541_function, tvb, (offset + tlv_offset), 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(sub_tree, hf_dcd_tlv_t_541_action, tvb, (offset + tlv_offset), 1, ENC_BIG_ENDIAN);
							}
							break;
							case DCD_TLV_T542_TRIGGER_VALUE:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_tlv_t_542_trigger_value, tvb, (offset + tlv_offset)-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case DCD_TLV_T_543_TRIGGER_AVERAGING_DURATION:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_dcd_tlv_t_543_trigger_averaging_duration, tvb, (offset + tlv_offset)-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
						}
						tlv_offset += length;
					}
					break;
				}
				case DCD_TLV_T_60_NOISE_AND_INTERFERENCE:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_60_noise_interference, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_153_DOWNLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_153_downlink_burst_profile_for_mutiple_fec_types, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_RESTART_COUNT:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_restart_count, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					break;
				}
				case DCD_TLV_T_45_PAGING_INTERVAL_LENGTH:
				{
					if (include_cor2_changes) {
						add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_45_paging_interval_reserved, tvb, offset-tlv_value_offset, ENC_NA);
					} else {
						add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_tlv_t_45_paging_interval_length, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					}
					break;
				}
				default:
				{
					add_tlv_subtree(&tlv_info, dcd_tree, hf_dcd_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
					break;
				}
			}
			offset += tlv_len;
		}	/* end of TLV process while loop */
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_dcd(void)
{
	/* DCD display */
	static hf_register_info hf[] =
	{
		{
			&hf_dcd_tlv_t_33_asr,
			{
				"ASR (Anchor Switch Report) Slot Length (M) and Switching Period (L)", "wmx.dcd.asr",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_33_asr_l,
			{
				"ASR Switching Period (L)", "wmx.dcd.asr.l",
				FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_33_asr_m,
			{
				"ASR Slot Length (M)", "wmx.dcd.asr.m",
				FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL
			}
		},
		{
			&hf_dcd_bs_eirp,
			{
				"BS EIRP", "wmx.dcd.bs_eirp",
				FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_bs_id,
			{
				"Base Station ID", "wmx.dcd.bs_id",
				FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_restart_count,
			{
				"BS Restart Count", "wmx.dcd.bs_restart_count",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
#if 0
		{
			&hf_dl_burst_diuc,
			{
				"DIUC", "wmx.dcd.burst.diuc",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
#endif
		{
			&hf_dcd_burst_diuc_entry_threshold,
			{
				"DIUC Minimum Entry Threshold (in 0.25 dB units)", "wmx.dcd.burst.diuc_entry_threshold",
				FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_burst_diuc_exit_threshold,
			{
				"DIUC Mandatory Exit Threshold (in 0.25 dB units)", "wmx.dcd.burst.diuc_exit_threshold",
				FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_burst_fec,
			{
				"FEC Code Type", "wmx.dcd.burst.fec",
				FT_UINT8, BASE_DEC, VALS(vals_dcd_burst_fec_ofdma), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_burst_freq,
			{
				"Frequency", "wmx.dcd.burst.freq",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
#if 0
		{
			&hf_dl_burst_reserved,
			{
				"Reserved", "wmx.dcd.burst.reserved",
				FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL
			}
		},
#endif
		{
			&hf_dcd_burst_tcs,
			{
				"TCS", "wmx.dcd.burst.tcs",
				FT_UINT8, BASE_DEC, VALS(vals_dcd_burst_tcs), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_channel_nr,
			{
				"Channel Nr", "wmx.dcd.channel_nr",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_config_change_count,
			{
				"Configuration Change Count", "wmx.dcd.config_change_count",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_physical_cinr_measurements,
			{
				"Default Averaging Parameter for Physical CINR Measurements (in multiples of 1/16)", "wmx.dcd.default_physical_cinr_meas_averaging_parameter",
				FT_UINT8, BASE_HEX, NULL, 0xf0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter,
			{
				"Default RSSI and CINR Averaging Parameter", "wmx.dcd.default_rssi_and_cinr_averaging_parameter",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_21_default_rssi_and_cinr_averaging_parameter_rssi_measurements,
			{
				"Default Averaging Parameter for RSSI Measurements (in multiples of 1/16)", "wmx.dcd.default_rssi_meas_averaging_parameter",
				FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_22_dl_amc_allocated_physical_bands_bitmap,
			{
				"DL AMC Allocated Physical Bands Bitmap", "wmx.dcd.dl_amc_allocated_phy_bands_bitmap",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dcd_dl_burst_profile_diuc,
			{
				"DIUC", "wmx.dcd.dl_burst_profile_diuc",
				FT_UINT8, BASE_DEC, VALS(diuc_msgs), 0x0F, NULL, HFILL
			}
		},
		{
			&hf_dcd_dl_burst_profile_rsv,
			{
				"Reserved", "wmx.dcd.dl_burst_profile_rsv",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_dcd_downlink_channel_id,
			{
				"Reserved", "wmx.dcd.dl_channel_id",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_153_downlink_burst_profile_for_mutiple_fec_types,
			{
				"Downlink Burst Profile for Multiple FEC Types","wimax.dcd.dl_burst_profile_multiple_fec_types",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition,
			{
				"DL Region Definition", "wmx.dcd.dl_region_definition",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_num_region,
			{
				"Number of Regions", "wmx.dcd.dl_region_definition.num_region",
				FT_UINT8, BASE_DEC, NULL, 0xFC, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_num_subchannels,
			{
				"Number of Subchannels", "wmx.dcd.dl_region_definition.num_subchannels",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_num_symbols,
			{
				"Number of OFDMA Symbols", "wmx.dcd.dl_region_definition.num_symbols",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_reserved,
			{
				"Reserved", "wmx.dcd.dl_region_definition.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_subchannel_offset,
			{
				"Subchannel Offset", "wmx.dcd.dl_region_definition.subchannel_offset",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_34_dl_region_definition_symbol_offset,
			{
				"OFDMA Symbol Offset", "wmx.dcd.dl_region_definition.symbol_offset",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
#ifndef WIMAX_16D_2004
			{
			&hf_dcd_eirxp,
			{
				"EIRXP (IR, max)", "wmx.dcd.eirxp",
				FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
#endif
		{
			&hf_dcd_frame_duration,
			{
				"Frame Duration", "wmx.dcd.frame_duration",
				FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_frame_duration_code,
			{
				"Frame Duration Code", "wmx.dcd.frame_duration_code",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_frame_duration), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_frame_nr,
			{
				"Frame Number", "wmx.dcd.frame_nr",
				FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_frequency,
			{
				"Downlink Center Frequency", "wmx.dcd.frequency",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_31_h_add_threshold,
			{
				"H_add Threshold", "wmx.dcd.h_add_threshold",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
#ifdef WIMAX_16D_2004
		{
			&hf_dcd_h_arq_ack_delay,
			{
				"H-ARQ ACK Delay for DL Burst", "wmx.dcd.h_arq_ack_delay_dl_burst",
				FT_UINT8, BASE_DEC, NULL, 0x00, "", HFILL
			}
		},
#else
			{
			&hf_dcd_h_arq_ack_delay,
			{
				"H-ARQ ACK Delay for UL Burst", "wmx.dcd.h_arq_ack_delay_ul_burst",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
#endif
			{
			&hf_dcd_tlv_t_32_h_delete_threshold,
			{
				"H_delete Threshold", "wmx.dcd.h_delete_threshold",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_50_ho_type_support,
			{
				"HO Type Support", "wmx.dcd.ho_type_support",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_50_ho_type_support_fbss_ho,
			{
				"FBSS HO", "wmx.dcd.ho_type_support.fbss_ho",
				FT_UINT8, BASE_HEX, VALS(tfs_support), 0x20, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_50_ho_type_support_ho,
			{
				"HO", "wmx.dcd.ho_type_support.ho",
				FT_UINT8, BASE_HEX, VALS(tfs_support), 0x80, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_50_ho_type_support_mdho,
			{
				"MDHO", "wmx.dcd.ho_type_support.mdho",
				FT_UINT8, BASE_HEX, VALS(tfs_support), 0x40, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_50_ho_type_support_reserved,
			{
				"Reserved", "wmx.dcd.ho_type_support.reserved",
				FT_UINT8, BASE_HEX, NULL, 0x1f, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_51_hysteresis_margin,
			{
				"Hysteresis Margin", "wmx.dcd.hysteresis_margin",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dcd_invalid_tlv,
			{
				"Invalid TLV", "wmx.dcd.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_dcd_mac_version,
			{
				"MAC Version", "wmx.dcd.mac_version",
				FT_UINT8, BASE_DEC, VALS(vals_dcd_mac_version), 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_20_maximum_retransmission,
			{
				"Maximum Retransmission", "wmx.dcd.maximum_retransmission",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_60_noise_interference,
			{
				"Noise and Interference", "wmx.dcd.noise_interference",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_35_paging_group_id,
			{
				"Paging Group ID", "wmx.dcd.paging_group_id",
				FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dcd_tlv_t_36_tusc1_permutation_active_subchannels_bitmap,
			{
				"TUSC1 permutation active subchannels bitmap", "wmx.dcd.tusc1",
				FT_UINT16, BASE_HEX, NULL, 0xFF80, NULL, HFILL
			}
		},
		{
			&hf_dcd_tlv_t_37_tusc2_permutation_active_subchannels_bitmap,
			{
				"TUSC2 permutation active subchannels bitmap", "wmx.dcd.tusc2",
				FT_UINT16, BASE_HEX, NULL, 0xFFF8, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_45_paging_interval_length,
			{
				"Paging Interval Length", "wmx.dcd.paging_interval_length",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_45_paging_interval_reserved,
			{
				"Reserved", "wmx.dcd.paging_interval_reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_19_permutation_type_for_broadcast_regions_in_harq_zone,
			{
				"Permutation Type for Broadcast Region in HARQ Zone", "wmx.dcd.permutation_type_broadcast_region_in_harq_zone",
				FT_UINT8, BASE_DEC, VALS(vals_dcd_permutation_type), 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_phy_type,
			{
				"PHY Type", "wmx.dcd.phy_type",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_dcd_power_adjustment,
			{
				"Power Adjustment Rule", "wmx.dcd.power_adjustment",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_power_adjustmnt), 0x00, NULL, HFILL
			}
		},
#ifdef WIMAX_16D_2004
		{
			&hf_dcd_rss,
			{
				"RSS (IR, max)", "wmx.dcd.rss",
				FT_INT16, BASE_DEC, NULL, 0x00, "", HFILL
			}
		},
#endif
		{
			&hf_dcd_rtg,
			{
				"RTG", "wmx.dcd.rtg",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
#ifdef WIMAX_16D_2004
		{
			&hf_dcd_size_cqich_id,
			{
				"Size of CQICH-ID Field", "wmx.dcd.size_cqich_id",
				FT_UINT8, BASE_DEC, VALS(vals_dcd_size_of_cqich_id), 0x00, "", HFILL
			}
		},
#endif
		{
			&hf_dcd_channel_switch_frame_nr,
			{
				"Channel Switch Frame Number", "wmx.dcd.switch_frame",
				FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_52_time_to_trigger_duration,
			{
				"Time to Trigger Duration", "wmx.dcd.time_trigger_duration",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_543_trigger_averaging_duration,
			{
				"Trigger Averaging Duration", "wmx.dcd.trigger_averaging_duration",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_542_trigger_value,
			{
				"Trigger Value", "wmx.dcd.trigger_value",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_dcd_ttg,
			{
				"TTG", "wmx.dcd.ttg",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_541_type_function_action,
			{
				"Type/Function/Action", "wmx.dcd.type_function_action",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_541_action,
			{
				"Action", "wmx.dcd.type_function_action.action",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_action), 0x7, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_541_function,
			{
				"Function", "wmx.dcd.type_function_action.function",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_function), 0x38, NULL, HFILL
			}
		},
			{
			&hf_dcd_tlv_t_541_type,
			{
				"Type", "wmx.dcd.type_function_action.type",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_type), 0xC0, NULL, HFILL
			}
		},
		{
			&hf_dcd_unknown_type,
			{
				"Unknown DCD Type", "wmx.dcd.unknown_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_dcd_decoder,
		};

	proto_mac_mgmt_msg_dcd_decoder = proto_register_protocol (
		"WiMax DCD Messages", /* name       */
		"WiMax DCD",     /* short name */
		"wmx.dcd"                  /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_dcd_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_mac_mgmt_msg_dcd(void)
{
	dissector_handle_t dcd_handle;

	dcd_handle = create_dissector_handle(dissect_mac_mgmt_msg_dcd_decoder, proto_mac_mgmt_msg_dcd_decoder);
	dissector_add_uint("wmx.mgmtmsg", MAC_MGMT_MSG_DCD, dcd_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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

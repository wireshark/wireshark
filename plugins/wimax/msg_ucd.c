/* msg_ucd.c
 * WiMax MAC Management UCD Message decoder
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

/*
#define DEBUG
*/

#include <glib.h>
#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"

extern gint proto_mac_mgmt_msg_dcd_decoder;
extern gboolean include_cor2_changes;

guint cqich_id_size;		/* Set for CQICH_Alloc_IE */

static gint proto_mac_mgmt_msg_ucd_decoder = -1;
static gint ett_mac_mgmt_msg_ucd_decoder = -1;

/* fix fields */
static gint hf_ucd_message_type = -1;
static gint hf_ucd_res_timeout = -1;
static gint hf_ucd_bw_req_size = -1;
static gint hf_ucd_ranging_req_size = -1;
static gint hf_ucd_freq = -1;
static gint hf_ucd_subchan_params_num_chan = -1;
static gint hf_ucd_ul_allocated_subchannles_bitmap = -1;
static gint hf_ucd_subchan_params_num_sym = -1;
static gint hf_ucd_subchan_codes = -1;

static gint hf_ucd_ul_burst_reserved = -1;
static gint hf_ucd_ul_burst_uiuc = -1;
static gint hf_ucd_burst_fec = -1;
static gint hf_ucd_burst_ranging_data_ratio = -1;
/*static gint hf_ucd_burst_power_boost = -1;
*static gint hf_ucd_burst_tcs_enable = -1;
*/

static gint hf_ucd_tlv_t_159_band_amc_allocation_threshold = -1;
static gint hf_ucd_tlv_t_158_optional_permutation_ul_allocated_subchannels_bitmap = -1;
static gint hf_ucd_tlv_t_160_band_amc_release_threshold = -1;
static gint hf_ucd_tlv_t_161_band_amc_allocation_timer = -1;
static gint hf_ucd_tlv_t_162_band_amc_release_timer = -1;
static gint hf_ucd_tlv_t_163_band_status_report_max_period = -1;
static gint hf_ucd_tlv_t_164_band_amc_retry_timer = -1;
static gint hf_ucd_tlv_t_171_harq_ack_delay_dl_burst = -1;
static gint hf_ucd_tlv_t_170_safety_channel_retry_timer = -1;
static gint hf_ucd_tlv_t_172_cqich_band_amc_transition_delay = -1;
static gint hf_ucd_tlv_t_174_maximum_retransmission = -1;
static gint hf_ucd_tlv_t_177_normalized_cn_override2 = -1;
static gint hf_ucd_tlv_t_177_normalized_cn_override2_first_line = -1;
static gint hf_ucd_tlv_t_177_normalized_cn_override2_list = -1;
static gint hf_ucd_tlv_t_176_size_of_cqich_id_field  = -1;
static gint hf_ucd_tlv_t_186_upper_bound_aas_preamble = -1;
static gint hf_ucd_tlv_t_187_lower_bound_aas_preamble = -1;
static gint hf_ucd_tlv_t_188_allow_aas_beam_select_message = -1;
static gint hf_ucd_tlv_t_189_use_cqich_indication_flag = -1;
static gint hf_ucd_tlv_t_190_ms_specific_up_power_addjustment_step = -1;
static gint hf_ucd_tlv_t_191_ms_specific_down_power_addjustment_step = -1;
static gint hf_ucd_tlv_t_192_min_level_power_offset_adjustment = -1;
static gint hf_ucd_tlv_t_193_max_level_power_offset_adjustment = -1;
static gint hf_ucd_tlv_t_194_handover_ranging_codes = -1;
static gint hf_ucd_tlv_t_195_initial_ranging_interval = -1;
static gint hf_ucd_tlv_t_196_tx_power_report = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_threshold = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_interval = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_a_p_avg = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_threshold_icqch = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_interval_icqch = -1;
static gint hf_ucd_tlv_t_196_tx_power_report_a_p_avg_icqch = -1;
static gint hf_ucd_tlv_t_197_normalized_cn_channel_sounding = -1;
static gint hf_ucd_tlv_t_202_uplink_burst_profile_for_multiple_fec_types = -1;
static gint hf_ucd_tlv_t_203_ul_pusc_subchannel_rotation = -1;
static gint hf_ucd_tlv_t_205_relative_power_offset_ul_harq_burst = -1;
static gint hf_ucd_tlv_t_206_relative_power_offset_ul_burst_containing_mac_mgmt_msg = -1;
static gint hf_ucd_tlv_t_207_ul_initial_transmit_timing = -1;
static gint hf_ucd_tlv_t_210_fast_feedback_region = -1;
static gint hf_ucd_tlv_t_211_harq_ack_region = -1;
static gint hf_ucd_tlv_t_212_ranging_region = -1;
static gint hf_ucd_tlv_t_213_sounding_region = -1;
static gint hf_ucd_tlv_t_150_initial_ranging_codes = -1;
static gint hf_ucd_tlv_t_151_periodic_ranging_codes = -1;
static gint hf_ucd_tlv_t_152_bandwidth_request_codes = -1;
static gint hf_ucd_tlv_t_155_start_of_ranging_codes_group = -1;
static gint hf_ucd_tlv_t_156_permutation_base = -1;

static gint hf_ucd_unknown_type = -1;
static gint hf_ucd_invalid_tlv = -1;

static const value_string vals_dcd_burst_tcs[] =
{
	{0, "TCS disabled"},
	{1, "TCS enabled"},
	{0,  NULL}
};

static const value_string vals_dcd_burst_fec[] =
{
	{0, "QPSK (CC) 1/2"},
	{1, "QPSK (CC) 3/4"},
	{2, "16-QAM (CC) 1/2"},
	{3, "16-QAM (CC) 3/4"},
	{4, "64-QAM (CC) 1/2"},
	{5, "64-QAM (CC) 2/3"},
	{6, "64-QAM (CC) 3/4"},
	{7, "QPSK (BTC) 1/2"},
	{8, "QPSK (BTC) 3/4 or 2/3"},
	{9, "16-QAM (BTC) 3/5"},
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
	{47, "16-QAM (CC optional interleaver) 0%00"},
	{48, "64-QAM (CC with optional interleaver) 2/3"},
	{49, "64-QAM (CC with optional interleaver) 3/4"},
	{50, "QPSK (LDPC) 5/6"},
	{51, "16-QAM (LDPC) 5/6"},
	{52, "64-QAM (LDPC) 5/6"},
	{0,  NULL}
};

static const value_string vals_ucd_cqich_size[] =
{
	{0, "0 bits"},
	{1, "3 bits"},
	{2, "4 bits"},
	{3, "5 bits"},
	{4, "6 bits"},
	{5, "7 bits"},
	{6, "8 bits"},
	{7, "9 bits"},
	{0,  NULL}
};

static const value_string vals_yes_no_str[] =
{
	{0, "No"},
	{1, "Yes"},
	{0,  NULL}
};


/* UCD dissector */
void dissect_mac_mgmt_msg_ucd_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tvb_len, payload_type, length;
	gint  tlv_type, tlv_len, tlv_offset, tlv_value_offset;
	tlv_info_t tlv_info;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_UCD)
	{
		return;
	}

	if(tree)
	{	/* we are being asked for details */
		proto_item *ucd_item;
		proto_tree *ucd_tree;
		guint ucd_config_change_count;
		guint ucd_ranging_backoff_start;
		guint ucd_ranging_backoff_end;
		guint ucd_request_backoff_start;
		guint ucd_request_backoff_end;

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type UCD */
		ucd_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tvb_len, "Uplink Channel Descriptor (UCD) (%u bytes)", tvb_len);
		/* add MAC UCD subtree */
		ucd_tree = proto_item_add_subtree(ucd_item, ett_mac_mgmt_msg_ucd_decoder);
		/* Decode and display the Uplink Channel Descriptor (UCD) */
		/* display the Message Type */
		proto_tree_add_item(ucd_tree, hf_ucd_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		/* move to next field */
		offset++;
		/* get the Configuration Change Count */
		ucd_config_change_count = tvb_get_guint8(tvb, offset);
		/* display the Configuration Change Count */
		proto_tree_add_text(ucd_tree, tvb, offset, 1, "Configuration Change Count: %u", ucd_config_change_count);
		/* move to next field */
		offset++;
		/* get the ranging backoff start */
		ucd_ranging_backoff_start = tvb_get_guint8(tvb, offset);
		/* display the ranging backoff start */
		proto_tree_add_text(ucd_tree, tvb, offset, 1, "Ranging Backoff Start: 2^%u = %u", ucd_ranging_backoff_start, (1 << ucd_ranging_backoff_start));
		/* move to next field */
		offset++;
		/* get the ranging backoff end */
		ucd_ranging_backoff_end = tvb_get_guint8(tvb, offset);
		/* display the ranging backoff end */
		proto_tree_add_text(ucd_tree, tvb, offset, 1, "Ranging Backoff End: 2^%u = %u", ucd_ranging_backoff_end, (1 << ucd_ranging_backoff_end));
		/* move to next field */
		offset++;
		/* get the request backoff start */
		ucd_request_backoff_start = tvb_get_guint8(tvb, offset);
		/* display the request backoff start */
		proto_tree_add_text(ucd_tree, tvb, offset, 1, "Request Backoff Start: 2^%u = %u", ucd_request_backoff_start, (1 << ucd_request_backoff_start));
		/* move to next field */
		offset++;
		/* get the request backoff end */
		ucd_request_backoff_end = tvb_get_guint8(tvb, offset);
		/* display the request backoff end */
		proto_tree_add_text(ucd_tree, tvb, offset, 1, "Request Backoff End: 2^%u = %u", ucd_request_backoff_end, (1 << ucd_request_backoff_end));
		/* move to next field */
		offset++;
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
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "UCD TLV error");
				proto_tree_add_item(ucd_tree,hf_ucd_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the TLV value offset */
			tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
			proto_tree_add_protocol_format(ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, (tlv_len + tlv_value_offset), "UCD Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len, offset, tvb_len);
#endif
			/* update the offset */
			offset += tlv_value_offset;
			/* process UCD TLV Encoded information */
			if (include_cor2_changes)
			{
				switch (tlv_type)
				{
					proto_tree *tlv_tree;

					case UCD_TLV_T_203_UL_PUSC_SUBCHANNEL_ROTATION:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_203_ul_pusc_subchannel_rotation, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_203_ul_pusc_subchannel_rotation, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
						break;
					}
					case UCD_TLV_T_205_RELATIVE_POWER_OFFSET_UL_HARQ_BURST:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_205_relative_power_offset_ul_harq_burst, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_205_relative_power_offset_ul_harq_burst, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
						break;
					}
					case UCD_TLV_T_206_RELATIVE_POWER_OFFSET_UL_BURST_CONTAINING_MAC_MGMT_MSG:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_206_relative_power_offset_ul_burst_containing_mac_mgmt_msg, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_206_relative_power_offset_ul_burst_containing_mac_mgmt_msg, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
						break;
					}
					case UCD_TLV_T_207_UL_INITIAL_TRANSMIT_TIMING:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_207_ul_initial_transmit_timing, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_207_ul_initial_transmit_timing, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
						break;
					}
					case UCD_TLV_T_210_FAST_FEEDBACK_REGION:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_210_fast_feedback_region, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_210_fast_feedback_region, tvb, offset, tlv_len, ENC_NA);
						break;
					}
					case UCD_TLV_T_211_HARQ_ACK_REGION:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_211_harq_ack_region, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_211_harq_ack_region, tvb, offset, tlv_len, ENC_NA);
						break;
					}
					case UCD_TLV_T_212_RANGING_REGION:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_212_ranging_region, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_212_ranging_region, tvb, offset, tlv_len, ENC_NA);
						break;
					}
					case UCD_TLV_T_213_SOUNDING_REGION:
					{
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_213_sounding_region, tvb, offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_213_sounding_region, tvb, offset, tlv_len, ENC_NA);
						break;
					}
				}
			}
			switch (tlv_type)
			{
				proto_tree *tlv_tree;
				proto_item *tlv_item1;
				guint ul_burst_uiuc;
				guint utemp;

				case UCD_UPLINK_BURST_PROFILE:
				{
					/* get the UIUC */
					ul_burst_uiuc = tvb_get_guint8(tvb, offset) & 0x0F;
					/* add TLV subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Uplink Burst Profile (UIUC = %u) (%u bytes)", ul_burst_uiuc, tlv_len);
					proto_tree_add_item(tlv_tree, hf_ucd_ul_burst_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_ul_burst_uiuc, tvb, offset, 1, ENC_BIG_ENDIAN);
					for (tlv_offset = 1; tlv_offset < tlv_len;)
					{	/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, (offset+tlv_offset));
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						if(tlv_type == -1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "UL Burst Profile error");
							proto_tree_add_item(tlv_tree, hf_ucd_invalid_tlv, tvb, offset, (tlv_len - offset - tlv_offset), ENC_NA);
							break;
						}
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						/* update the offset */
						tlv_offset += get_tlv_value_offset(&tlv_info);
						switch (tlv_type)
						{
							proto_tree *sub_tree;
							proto_item *tlv_item2;
							case UCD_BURST_FEC:
							{
								sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, tlv_tree, hf_ucd_burst_fec, tvb, (offset+tlv_offset), 1, FALSE);
								proto_tree_add_item(sub_tree, hf_ucd_burst_fec, tvb, (offset+tlv_offset), 1, ENC_BIG_ENDIAN);
								break;
							}
							case UCD_BURST_RANGING_DATA_RATIO:
							{
								sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, tlv_tree, hf_ucd_burst_ranging_data_ratio, tvb, (offset+tlv_offset), 1, FALSE);
								tlv_item2 = proto_tree_add_item(sub_tree, hf_ucd_burst_ranging_data_ratio, tvb, (offset+tlv_offset), 1, ENC_BIG_ENDIAN);
								proto_item_append_text(tlv_item2, " dB");
								break;
							}
#if 0 /* for OFDM */
							case UCD_BURST_POWER_BOOST:
							{
								sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, tlv_tree, hf_ucd_burst_power_boost, tvb, (offset+tlv_offset), 1, FALSE);
								tlv_item2 = proto_tree_add_item(sub_tree, hf_ucd_burst_power_boost, tvb, (offset+tlv_offset), length, ENC_BIG_ENDIAN);
								proto_item_append_text(tlv_item2, " dB");
								break;
							}
							case UCD_BURST_TCS_ENABLE:
							{
								sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, tlv_tree, hf_ucd_burst_tcs_enable, tvb, (offset+tlv_offset), 1, FALSE);
								proto_tree_add_item(sub_tree, hf_ucd_burst_tcs_enable, tvb, (offset+tlv_offset), 1, ENC_BIG_ENDIAN);
								break;
							}
#endif
							default:
								/* ??? */
								break;
						}
						tlv_offset += length;
					}
					break;
				}
				case UCD_RESERVATION_TIMEOUT:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_res_timeout, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_res_timeout, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_BW_REQ_SIZE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_bw_req_size, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_bw_req_size, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " PS");
					break;
				}
				case UCD_RANGING_REQ_SIZE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_ranging_req_size, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_ranging_req_size, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " PS");
					break;
				}
				case UCD_FREQUENCY:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_freq, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_freq, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " kHz");
					break;
				}
				case UCD_TLV_T_7_HO_RANGING_START:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "HO ranging start (SCa, OFDM, OFDMA (mobile only)) (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Initial Backoff Window Size for MS Performing Initial During Handover Process: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_8_RANGING_HO_END:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "HO ranging end (SCa, OFDM, OFDMA (mobile only)) (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Final Backoff Window Size for MS Performing Initial During Handover Process: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_158_OPTIONAL_PERMUTATION_UL_ALLOCATED_SUBCHANNELS_BITMAP:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_158_optional_permutation_ul_allocated_subchannels_bitmap, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_158_optional_permutation_ul_allocated_subchannels_bitmap, tvb, offset, tlv_len, ENC_NA);

					break;
				}
				case UCD_TLV_T_159_BAND_AMC_ALLOCATION_THRESHHOLD:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_159_band_amc_allocation_threshold, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_159_band_amc_allocation_threshold, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " dB");
					break;
				}
				case UCD_TLV_T_160_BAND_AMC_RELEASE_THRESHOLD:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_160_band_amc_release_threshold, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_160_band_amc_release_threshold, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " dB");
					break;
				}
				case UCD_TLV_T_161_BAND_AMC_ALLOCATION_TIMER:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_161_band_amc_allocation_timer, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_161_band_amc_allocation_timer, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_162_BAND_AMC_RELEASE_TIMER:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_161_band_amc_allocation_timer, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_162_band_amc_release_timer, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_163_BAND_STATUS_REPORT_MAX_PERIOD:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_163_band_status_report_max_period, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_163_band_status_report_max_period, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_164_BAND_AMC_RETRY_TIMER:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_164_band_amc_retry_timer, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_164_band_amc_retry_timer, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_170_SAFETY_CHANNEL_RETRY_TIMER:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_170_safety_channel_retry_timer, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_170_safety_channel_retry_timer, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_171_HARQ_ACK_DELAY_FOR_DL_BURST:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_171_harq_ack_delay_dl_burst, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_171_harq_ack_delay_dl_burst, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames offset");
					break;
				}
				case UCD_TLV_T_172_CQICH_BAND_AMC_TRANSITION_DELAY:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_172_cqich_band_amc_transition_delay, tvb, offset, tlv_len, FALSE);
					tlv_item1 = proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_172_cqich_band_amc_transition_delay, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					proto_item_append_text(tlv_item1, " frames");
					break;
				}
				case UCD_TLV_T_174_MAXIMUM_RETRANSMISSION:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_174_maximum_retransmission, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_174_maximum_retransmission, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_176_SIZE_OF_CQICH_ID_FIELD:
				{
					utemp = tvb_get_guint8(tvb, offset);
					cqich_id_size = 0;	/* Default is 0 */
					if (utemp && utemp < 8) {
					    /* Set for CQICH_Alloc_IE */
					    cqich_id_size = utemp + 2;
					}
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_176_size_of_cqich_id_field, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_176_size_of_cqich_id_field, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_177_NORMALIZED_CN_OVERRIDE_2:
				{
					/* add TLV subtree */
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_177_normalized_cn_override2, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_177_normalized_cn_override2_first_line, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_177_normalized_cn_override2_list, tvb, offset + 3, 7, ENC_ASCII|ENC_NA);
					break;
				}
				case UCD_TLV_T_186_UPPER_BOUND__AAS_PREAMBLE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_186_upper_bound_aas_preamble, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_186_upper_bound_aas_preamble, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_187_LOWER_BOUND_AAS_PREAMBLE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_187_lower_bound_aas_preamble, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_187_lower_bound_aas_preamble, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_188_ALLOW_AAS_BEAM_SELECT_MESSAGE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_188_allow_aas_beam_select_message, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_188_allow_aas_beam_select_message, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_189_USE_CQICH_INDICATION_FLAG:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_189_use_cqich_indication_flag, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_189_use_cqich_indication_flag, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_190_MS_SPECIFIC_UP_POWER_OFFSET_ADJUSTMENT_STEP:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_190_ms_specific_up_power_addjustment_step, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_190_ms_specific_up_power_addjustment_step, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_191_MS_SPECIFIC_DOWN_POWER_OFSET_ADJUSTMENT_STEP:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_191_ms_specific_down_power_addjustment_step, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_191_ms_specific_down_power_addjustment_step, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_192_MIN_LEVEL_POWER_OFFSET_ADJUSTMENT:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_192_min_level_power_offset_adjustment, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_192_min_level_power_offset_adjustment, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_193_MAX_LEVEL_POWER_OFFSETR_ADJUSTMENT:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_193_max_level_power_offset_adjustment, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_193_max_level_power_offset_adjustment, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_194_HANDOVER_RANGING_CODES:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_194_handover_ranging_codes, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_194_handover_ranging_codes, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_195_INITIAL_RANGING_INTERVAL:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_195_initial_ranging_interval, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_195_initial_ranging_interval, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_196_TX_POWER_REPORT:
				{
					/* add TLV subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Tx Power Report (%u bytes)", tlv_len);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_interval, tvb , offset, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_a_p_avg, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_threshold_icqch, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_interval_icqch, tvb, (offset + 2), 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_196_tx_power_report_a_p_avg_icqch, tvb, (offset + 2), 1, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_197_NORMALIZED_CN_FOR_CHANNEL_SOUNDING:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_195_initial_ranging_interval, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_197_normalized_cn_channel_sounding, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_TLV_T_198_INTIAL_RANGING_BACKOFF_START:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Initial ranging backoff start (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Initial Ranging Backoff Start: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_199_INITIAL_RANGING_BACKOFF_END:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Initial ranging backoff end (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Initial Ranging Backoff End: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_200_BANDWIDTH_REQUESET_BACKOFF_START:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Bandwidth request backoff start (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Bandwidth Request Backoff Start: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_201_BANDWIDTH_REQUEST_BACKOFF_END:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Bandwidth request backoff end (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tvb_len, "Bandwidth Request Backoff End: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_TLV_T_202_UPLINK_BURST_PROFILE_FOR_MULTIPLE_FEC_TYPES:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_202_uplink_burst_profile_for_multiple_fec_types, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_tlv_t_202_uplink_burst_profile_for_multiple_fec_types, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_INITIAL_RANGING_CODES:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_150_initial_ranging_codes, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree,hf_ucd_tlv_t_150_initial_ranging_codes, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_PERIODIC_RANGING_CODES:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_151_periodic_ranging_codes, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree,hf_ucd_tlv_t_151_periodic_ranging_codes, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_BANDWIDTH_REQUEST_CODES:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_152_bandwidth_request_codes, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree,hf_ucd_tlv_t_152_bandwidth_request_codes, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_PERIODIC_RANGING_BACKOFF_START:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Periodic ranging backoff start (%u byte(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tlv_len, "Periodic Ranging Backoff Start: 2^%u = %u", utemp, (1 << utemp));
					break;

				}
				case UCD_PERIODIC_RANGING_BACKOFF_END:
				{
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Periodic ranging backoff end (%u bytes(s))", tlv_len);
					utemp = tvb_get_guint8(tvb, offset);
					proto_tree_add_text(tlv_tree, tvb, offset, tlv_len, "Periodic Ranging Backoff End: 2^%u = %u", utemp, (1 << utemp));
					break;
				}
				case UCD_START_OF_RANGING_CODES_GROUP:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_155_start_of_ranging_codes_group, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree,hf_ucd_tlv_t_155_start_of_ranging_codes_group, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;

				}
				case UCD_PERMUTATION_BASE:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_tlv_t_156_permutation_base, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree,hf_ucd_tlv_t_156_permutation_base, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				}
				case UCD_UL_ALLOCATED_SUBCHANNELS_BITMAP:
				{
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_ucd_decoder, ucd_tree, hf_ucd_ul_allocated_subchannles_bitmap, tvb, offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_ucd_ul_allocated_subchannles_bitmap, tvb, offset, tlv_len, ENC_NA);
					break;
				}
				case UCD_TLV_T_203_UL_PUSC_SUBCHANNEL_ROTATION:
				case UCD_TLV_T_205_RELATIVE_POWER_OFFSET_UL_HARQ_BURST:
				case UCD_TLV_T_206_RELATIVE_POWER_OFFSET_UL_BURST_CONTAINING_MAC_MGMT_MSG:
				case UCD_TLV_T_207_UL_INITIAL_TRANSMIT_TIMING:
				case UCD_TLV_T_210_FAST_FEEDBACK_REGION:
				case UCD_TLV_T_211_HARQ_ACK_REGION:
				case UCD_TLV_T_212_RANGING_REGION:
				case UCD_TLV_T_213_SOUNDING_REGION:
				{
					/* Unknown TLV type if cor2 not enabled. */
					if (!include_cor2_changes)
					{
						proto_tree_add_protocol_format(ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Unknown TLV Type");
					}
					break;
				}
				default:
				{
					proto_tree_add_protocol_format(ucd_tree, proto_mac_mgmt_msg_ucd_decoder, tvb, offset, tlv_len, "Unknown TLV Type");
				}
			}	/* end of switch(tlv_type) */
			offset += tlv_len;
		}	/* end of TLV process while loop */
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_ucd(void)
{
	/* UCD display */
	static hf_register_info hf[] =
	{
		{
			&hf_ucd_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.ucd",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_188_allow_aas_beam_select_message,
			{
				"Allow AAS Beam Select Message", "wmx.ucd.allow_aas_beam_select_message",
				FT_INT8, BASE_DEC, VALS(vals_yes_no_str), 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_159_band_amc_allocation_threshold,
			{
				"Band AMC Allocation Threshold", "wmx.ucd.band_amc.allocation_threshold",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_161_band_amc_allocation_timer,
			{
				"Band AMC Allocation Timer", "wmx.ucd.band_amc.allocation_timer",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_160_band_amc_release_threshold,
			{
				"Band AMC Release Threshold", "wmx.ucd.band_amc.release_threshold",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_162_band_amc_release_timer,
			{
				"Band AMC Release Timer", "wmx.ucd.band_amc.release_timer",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_164_band_amc_retry_timer,
			{
				"Band AMC Retry Timer", "wmx.ucd.band_amc.retry_timer",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_163_band_status_report_max_period,
			{
				"Band Status Report MAC Period", "wmx.ucd.band_status.report_max_period",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_152_bandwidth_request_codes,
			{
				"Bandwidth Request Codes", "wmx.ucd.bandwidth_request",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_burst_fec,
			{
				"FEC Code Type", "wmx.ucd.burst.fec",
				FT_UINT8, BASE_HEX, VALS(vals_dcd_burst_fec), 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_burst_ranging_data_ratio,
			{
				"Ranging Data Ratio", "wmx.ucd.burst.ranging_data_ratio",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_ul_burst_reserved,
			{
				"Reserved", "wmx.ucd.burst.reserved",
				FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_ucd_ul_burst_uiuc,
			{
				"UIUC", "wmx.ucd.burst.uiuc",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
#if 0
		{
			&hf_ucd_burst_power_boost,
			{"Focused Contention Power Boost", "wmx.ucd.burst.power_boost", FT_UINT8, BASE_HEX, NULL, 0, "", HFILL}
		},
		{
			&hf_ucd_burst_tcs_enable,
			{"TCS", "wmx.ucd.burst.tcs", FT_UINT8, BASE_DEC, VALS(vals_dcd_burst_tcs), 0, "", HFILL}
		},
#endif
		{
			&hf_ucd_bw_req_size,
			{
				"Bandwidth Request Opportunity Size", "wmx.ucd.bw_req_size",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_172_cqich_band_amc_transition_delay,
			{
				"CQICH Band AMC-Transition Delay", "wmx.ucd.cqich_band_amc_transition_delay",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_freq,
			{
				"Frequency", "wmx.ucd.frequency",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_194_handover_ranging_codes,
			{
				"Handover Ranging Codes", "wmx.ucd.handover_ranging_codes",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_171_harq_ack_delay_dl_burst,
			{
				"HARQ ACK Delay for DL Burst", "wmx.ucd.harq_ack_delay_dl_burst",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_150_initial_ranging_codes,
			{
				"Initial Ranging Codes", "wmx.ucd.initial_ranging_codes",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_195_initial_ranging_interval,
			{
				"Number of Frames Between Initial Ranging Interval Allocation", "wmx.ucd.initial_ranging_interval",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_invalid_tlv,
			{
				"Invalid TLV", "wmx.ucd.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_187_lower_bound_aas_preamble,
			{
				"Lower Bound AAS Preamble (in units of 0.25 dB)", "wmx.ucd.lower_bound_aas_preamble",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_192_min_level_power_offset_adjustment,
			{
				"Minimum Level of Power Offset Adjustment (in units of 0.1 dB)", "wmx.ucd.min_level_power_offset_adjustment",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_193_max_level_power_offset_adjustment,
			{
				"Maximum Level of Power Offset Adjustment (in units of 0.1 dB)", "wmx.ucd.max_level_power_offset_adjustment",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_174_maximum_retransmission,
			{
				"Maximum Number of Retransmission in UL-HARQ", "wmx.ucd.max_number_of_retransmission_in_ul_harq",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_191_ms_specific_down_power_addjustment_step,
			{
				"MS-specific Down Power Offset Adjustment Step (in units of 0.01 dB)", "wmx.ucd.ms_specific_down_power_offset_adjustment_step",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_190_ms_specific_up_power_addjustment_step,
			{
				"MS-specific Up Power Offset Adjustment Step (in units of 0.01 dB)", "wmx.ucd.ms_specific_up_power_offset_adjustment_step",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_197_normalized_cn_channel_sounding,
			{
				"Normalized C/N for Channel Sounding", "wmx.ucd.normalized_cn.channel_sounding",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_177_normalized_cn_override2,
			{
				"Normalized C/N Override 2", "wmx.ucd.normalized_cn.override_2",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_177_normalized_cn_override2_first_line,
			{
				"Normalized C/N Value", "wmx.ucd.normalized_cn.override_first_line",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_177_normalized_cn_override2_list,
			{
				"Normalized C/N Value List", "wmx.ucd.normalized_cn.override_list",
				FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_158_optional_permutation_ul_allocated_subchannels_bitmap,
			{
				"Optional permutation UL allocated subchannels bitmap", "wmx.ucd.optional_permutation_ul_allocated_subchannels_bitmap",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_151_periodic_ranging_codes,
			{
				"Periodic Ranging Codes", "wmx.ucd.periodic_ranging_codes",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_156_permutation_base,
			{
				"Permutation Base", "wmx.ucd.permutation_base",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_ranging_req_size,
			{
				"Ranging Request Opportunity Size", "wmx.ucd.ranging_req_size",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_res_timeout,
			{
				"Contention-based Reservation Timeout", "wmx.ucd.res_timeout",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_170_safety_channel_retry_timer,
			{
				"Safety Channel Release Timer", "wmx.ucd.safety_channel_release_timer",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_176_size_of_cqich_id_field,
			{
				"Size of CQICH_ID Field", "wmx.ucd.size_of_cqich_id_field",
				FT_UINT8, BASE_DEC, VALS(vals_ucd_cqich_size), 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_155_start_of_ranging_codes_group,
			{
				"Start of Ranging Codes Group", "wmx.ucd.start_of_ranging_codes_group",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
			{
			&hf_ucd_ul_allocated_subchannles_bitmap,
			{
				"UL Allocated Subchannels Bitmap", "wmx.ucd.subchan.bitmap",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_subchan_codes,
			{
				"Periodic Ranging Codes", "wmx.ucd.subchan.codes",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_subchan_params_num_chan,
			{
				"Number of Subchannels", "wmx.ucd.subchan.num_chan",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_subchan_params_num_sym,
			{
				"Number of OFDMA Symbols", "wmx.ucd.subchan.num_sym",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report,
			{
				"Tx Power Report", "wmx.ucd.tx_power_report",
				FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_a_p_avg,
			{
				"A p_avg (in multiples of 1/16)", "wmx.ucd.tx_power_report.a_p_avg",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_a_p_avg_icqch,
			{
				"A p_avg (in multiples of 1/16) when ICQCH is allocated", "wmx.ucd.tx_power_report.a_p_avg_icqch",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_interval,
			{
				"Interval (expressed as power of 2)", "wmx.ucd.tx_power_report.interval",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_interval_icqch,
			{
				"Interval When ICQCH is Allocated (expressed as power of 2)", "wmx.ucd.tx_power_report.interval_icqch",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_threshold,
			{
				"Threshold", "wmx.ucd.tx_power_report.threshold",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_196_tx_power_report_threshold_icqch,
			{
				"Threshold When ICQCH is Allocated to SS (in dB)", "wmx.ucd.tx_power_report.threshold_icqch",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_ucd_unknown_type,
			{
				"Unknown UCD Type", "wmx.ucd.unknown_tlv_type",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_202_uplink_burst_profile_for_multiple_fec_types,
			{
				"Uplink Burst Profile for Multiple FEC Types", "wmx.ucd.uplink_burst_profile.multiple_fec_types",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_203_ul_pusc_subchannel_rotation,
			{
				"Uplink PUSC Subchannel Rotation", "wmx.ucd.uplink_burst_profile.ul_pusc_subchannel_rotation",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_205_relative_power_offset_ul_harq_burst,
			{
				"Relative Power Offset UL HARQ Burst", "wmx.ucd.uplink_burst_profile.relative_power_offset_ul_harq_burst",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_206_relative_power_offset_ul_burst_containing_mac_mgmt_msg,
			{
				"Relative Power Offset UL Burst Containing MAC Mgmt Msg", "wmx.ucd.uplink_burst_profile.relative_power_offset_ul_burst_mac_mgmt_msg",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_207_ul_initial_transmit_timing,
			{
				"UL Initial Transmit Timing", "wmx.ucd.uplink_burst_profile.ul_initial_transmit_timing",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_210_fast_feedback_region,
			{
				"Fast Feedback Region", "wmx.ucd.uplink_burst_profile.fast_feedback_region",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_211_harq_ack_region,
			{
				"HARQ ACK Region", "wmx.ucd.uplink_burst_profile.harq_ack_region",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_212_ranging_region,
			{
				"Ranging Region", "wmx.ucd.uplink_burst_profile.ranging_region",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_213_sounding_region,
			{
				"Sounding Region", "wmx.ucd.uplink_burst_profile.sounding_region",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_186_upper_bound_aas_preamble,
			{
				"Upper Bound AAS Preamble (in units of 0.25 dB)", "wmx.ucd.upper_bound_aas_preamble",
				FT_INT8, BASE_DEC, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_ucd_tlv_t_189_use_cqich_indication_flag,
			{
				"Use CQICH Indication Flag", "wmx.ucd.use_cqich_indication_flag",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_ucd_decoder,
		};

	proto_mac_mgmt_msg_ucd_decoder = proto_mac_mgmt_msg_dcd_decoder;

	proto_register_field_array(proto_mac_mgmt_msg_ucd_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

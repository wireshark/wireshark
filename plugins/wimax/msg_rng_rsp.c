/* msg_rng_rsp.c
 * WiMax MAC Management RNG-RSP Message decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: John R. Underwood <junderx@yahoo.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

extern gint proto_mac_mgmt_msg_rng_req_decoder;
extern gboolean include_cor2_changes;

/* external reference */
extern void dissect_power_saving_class(proto_tree *rng_req_tree, gint tlv_type, tvbuff_t *tvb, guint compound_tlv_len, packet_info *pinfo, guint offset);
extern void dissect_mac_mgmt_msg_sbc_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
extern void dissect_mac_mgmt_msg_reg_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint proto_mac_mgmt_msg_rng_rsp_decoder = -1;
static gint ett_mac_mgmt_msg_rng_rsp_decoder   = -1;
static gint ett_rng_rsp_message_tree           = -1;

/* RNG-RSP fields */
static gint hf_rng_rsp_message_type				= -1;
static gint hf_rng_req_reserved					= -1;
static gint hf_rng_rsp_ul_channel_id				= -1;
static gint hf_rng_rsp_timing_adjust				= -1;
static gint hf_rng_rsp_power_level_adjust			= -1;
static gint hf_rng_rsp_offset_freq_adjust			= -1;
static gint hf_rng_rsp_ranging_status				= -1;
static gint hf_rng_rsp_dl_freq_override				= -1;
static gint hf_rng_rsp_ul_chan_id_override			= -1;
static gint hf_rng_rsp_dl_operational_burst_profile		= -1;
static gint hf_rng_rsp_dl_operational_burst_profile_diuc	= -1;
static gint hf_rng_rsp_dl_operational_burst_profile_ccc		= -1;
static gint hf_rng_rsp_ss_mac_address				= -1;
static gint hf_rng_rsp_basic_cid				= -1;
static gint hf_rng_rsp_primary_mgmt_cid				= -1;
static gint hf_rng_rsp_broadcast				= -1;
static gint hf_rng_rsp_frame_number				= -1;
static gint hf_rng_rsp_opportunity_number			= -1;
static gint hf_rng_rsp_service_level_prediction			= -1;
static gint hf_rng_rsp_resource_retain_flag			= -1;
static gint hf_rng_rsp_ho_process_optimization			= -1;
static gint hf_rng_rsp_ho_process_optimization_0		= -1;
static gint hf_rng_rsp_ho_process_optimization_1_2		= -1;
static gint hf_rng_rsp_ho_process_optimization_3		= -1;
static gint hf_rng_rsp_ho_process_optimization_4		= -1;
static gint hf_rng_rsp_ho_process_optimization_5		= -1;
static gint hf_rng_rsp_ho_process_optimization_6		= -1;
static gint hf_rng_rsp_ho_process_optimization_7		= -1;
static gint hf_rng_rsp_ho_process_optimization_8		= -1;
static gint hf_rng_rsp_ho_process_optimization_9		= -1;
static gint hf_rng_rsp_ho_process_optimization_10		= -1;
static gint hf_rng_rsp_ho_process_optimization_11		= -1;
static gint hf_rng_rsp_ho_process_optimization_12		= -1;
static gint hf_rng_rsp_ho_process_optimization_13		= -1;
static gint hf_rng_rsp_ho_process_optimization_14		= -1;
static gint hf_rng_rsp_ho_process_optimization_15		= -1;
/* Added the following to help implement RNG-RSP message encoding 33 (Table 367 in IEEE 802.16e-2007) */
static gint hf_rng_rsp_dl_op_burst_profile_ofdma		= -1;
static gint hf_rng_rsp_least_robust_diuc			= -1;
static gint hf_rng_rsp_repetition_coding_indication		= -1;
static gint hf_rng_rsp_config_change_count_of_dcd		= -1;
/* Added the following to help implement RNG-RSP message encoding 22 (Table 367 in IEEE 802.16e-2007) */
static gint hf_rng_rsp_ho_id					= -1;
static gint hf_rng_rsp_location_update_response			= -1;
/* Added the following to help implement RNG-RSP message encoding 24 (Table 367 in IEEE 802.16e-2007) */
static gint hf_rng_rsp_paging_information			= -1;
static gint hf_rng_rsp_paging_cycle				= -1;
static gint hf_rng_rsp_paging_offset				= -1;
static gint hf_rng_rsp_paging_group_id				= -1;
static gint hf_rng_rsp_bs_random				= -1;
static gint hf_rng_rsp_akid					= -1;
static gint hf_rng_rsp_ranging_subchan				= -1;
static gint hf_rng_rsp_time_symbol_reference			= -1;
static gint hf_rng_rsp_subchannel_reference			= -1;
static gint hf_rng_rsp_ranging_code_index			= -1;
static gint hf_rng_rsp_frame_number2				= -1;
static gint hf_tlv_type						= -1;
static gint hf_tlv_value					= -1;
static gint hf_rng_invalid_tlv					= -1;

/* STRING RESOURCES */

static const true_false_string tfs_rng_rsp_aas_broadcast = {
    "SS shall not issue contention-based Bandwidth Request",
    "SS may issue contention-based Bandwidth Request"
};

static const true_false_string tfs_rng_rsp_resource_retain_flag = {
	"Retained by the BS",
	"Deleted by the BS"
};

static const value_string vals_rng_rsp_ranging_status[] = {
    {1,					"continue"},
    {2,					"abort"},
    {3,					"success"},
    {4,					"rerange"},
    {0,					NULL}
};

static const value_string vals_rng_rsp_level_of_service[] = {
	{0,		"No service possible for this MS"},
	{1,		"Some service is available for one or"
			" several service flows authorized for the MS"},
	{2,		"For each authorized service flow, a MAC"
			" connection can be established with QoS"
			" specified by the AuthorizedQoSParamSet"},
	{3,		"No service level prediction available"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_0[] = {
	{0,		"SBC-REQ management messages during current re-entry"
			" processing required"},
	{1,		"Omit SBC-REQ management messages during current"
			" re-entry processing"},
	{0,		NULL},
};

static const value_string vals_rng_rsp_ho_process_optimization_1_2[] = {
	{0,		"Perform re-authentication and SA-TEK 3-way handshake."
			" BS should include SA-TEK-Update TLV in the"
			" SA-TEK-Response message. In addition, the RNG-RSP"
			" message does not include SA-TEK-Update TLV or SA"
			" Challenge Tuple TLV."},
	{1,		"SA-TEK-Update TLV is included in the RNG-RSP message."
			" In this case, SA-TEK 3-way handshake is avoided and"
			" SA Challenge Tuple TLV shall not be included in the"
			" RNG-RSP message."},
	{2,		"Reserved"},
	{3,		"Re-authentication and SA-TEK 3-way handshake is not"
			" performed. The RNG-RSP message does not include"
			" SA-TEK-Update TLV nor SA Challenge Tuple TLV. All the"
			" TEKs received from the serving BS are reused"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_3[] = {
	{0,		"Network Address Acquisition management messages during"
	       		" current reentry processing required"},
	{1,		"Omit Network Address Acquisition management messages"
			" during current reentry processing"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_4[] = {
	{0,		"Time of Day Acquisition management messages during"
	       		" current reentry processing required"},
	{1,		"Omit Time of Day Acquisition management messages"
	       		" during current reentry processing"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_5[] = {
	{0,		"TFTP management messages during current re-entry"
	       		" processing required"},
	{1,		"Omit TFTP management messages during current re-entry"
	       		" processing"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_6[] = {
	{0,		"Full service and operational state transfer or sharing"
	       		" between Serving BS and Target BS required"},
	{1,		"Omit Full service and operational state transfer or"
	        	" sharing between Serving BS and Target BS"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_7[] = {
	{0,		"REG-REQ management message during current re-entry"
	       		" processing required"},
	{1,		"Omit REG-REQ management message during current re-entry"
	       		" processing"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_8[] = {
	{0,		"BS shall send not send an unsolicited SBC-RSP"
	       		" management message"},
	{1,		"BS shall send an unsolicited SBC-RSP management message"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_9[] = {
	{0,		"No post-HO re-entry MS DL data pending at target BS"},
	{1,		"post-HO re-entry MS DL data pending at target BS"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_10[] = {
	{0,		"BS shall not send an unsolicited REG-RSP management"
	       		" message"},
	{1,		"BS shall send an unsolicited REG-RSP management message"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_11[] = {
	{0,		"(Target) BS does not support virtual SDU SN"},
	{1,		"(Target} BS supports virtual SDU SN"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_12[] = {
	{0,		"MS shall not send a notification of MS's successful"
	       		" re-entry registration"},
	{1,		"MS shall send a notification of MS's successful"
	       		" re-entry registration"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_ho_process_optimization_13[] = {
	{0,		"MS shall not trigger a higher layer protocol required"
	       		" to refresh its traffic IP address"},
	{1,		"MS shall trigger a higher layer protocol required to"
	       		" refresh its traffic IP address"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_repetition_coding_indication[] = {
	{0,		"No repetition coding"},
	{1,		"Repetition coding of 2"},
	{2,		"Repetition coding of 4"},
	{3,		"Repetition coding of 6"},
	{0,		NULL}
};

static const value_string vals_rng_rsp_location_update_response[] = {
	{0,		"Success of Location Update"},
	{1,		"Failure of Location Update"},
	{3,		"Success of location update and DL traffic pending"},
	{4,		"Reserved"},
	{0,		NULL}
};


/* Decode RNG-RSP messages. */
void dissect_mac_mgmt_msg_rng_rsp_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_item *ranging_status_item = NULL;
	proto_item *dl_freq_override_item = NULL;
        proto_item *ss_mac_address_item = NULL;
        proto_item *frame_number_item = NULL;
        proto_item *opportunity_number_item = NULL;

	guint offset = 0;
	guint tlv_offset;
	guint tvb_len, payload_type;
	proto_item *rng_rsp_item = NULL;
	proto_item *tlv_item = NULL;
	proto_tree *rng_rsp_tree = NULL;
	proto_tree *sub_tree = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;
	gint tlv_type;
	guint tlv_len;
	guint this_offset = 0;
	tlv_info_t sub_tlv_info;
	gint sub_tlv_type;
	gint sub_tlv_len;
	guint sub_tlv_offset;
	float timing_adjust;
	float power_level_adjust;
	gint offset_freq_adjust;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_RNG_RSP)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type RNG-RSP */
		rng_rsp_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, offset, tvb_len, "MAC Management Message, RNG-RSP (5)");
		/* add MAC RNG-RSP subtree */
		rng_rsp_tree = proto_item_add_subtree(rng_rsp_item, ett_mac_mgmt_msg_rng_rsp_decoder);
		/* display the Message Type */
		proto_tree_add_item(rng_rsp_tree, hf_rng_rsp_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(rng_rsp_tree, hf_rng_req_reserved, tvb, 1, 1, ENC_BIG_ENDIAN);
		offset += 2;

		while(offset < tvb_len)
		{
			/* Get the TLV data. */
			init_tlv_info(&tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&tlv_info);
			if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RNG-RSP TLV error");
				proto_tree_add_item(rng_rsp_tree, hf_rng_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the offset to the TLV data */
			tlv_offset = offset + get_tlv_value_offset(&tlv_info);

			switch (tlv_type) {
				case RNG_RSP_TIMING_ADJUST: {
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Timing Adjust (%u byte(s))", tlv_len);
					timing_adjust = (float)(gint32)tvb_get_ntohl(tvb, tlv_offset) / 4;
					tlv_item = proto_tree_add_float_format_value(sub_tree, hf_rng_rsp_timing_adjust, tvb,
						tlv_offset, 4, timing_adjust, " %.2f modulation symbols", timing_adjust);
					if ((timing_adjust < -2) || (timing_adjust > 2))
						proto_item_append_text(tlv_item, " (during periodic ranging shall not exceed +- 2)");
					break;
				}
				case RNG_RSP_POWER_LEVEL_ADJUST: {
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Power Level Adjust (%u byte(s))", tlv_len);
					power_level_adjust = (float)(gint8)tvb_get_guint8(tvb, tlv_offset) / 4;
					proto_tree_add_float_format_value(sub_tree, hf_rng_rsp_power_level_adjust, tvb, tlv_offset, 1,
								power_level_adjust, " %.2f dB", power_level_adjust);
					break;
				}
				case RNG_RSP_OFFSET_FREQ_ADJUST: {
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Offset Frequency Adjust (%u byte(s))", tlv_len);
					offset_freq_adjust = tvb_get_ntohl(tvb, tlv_offset);
					proto_tree_add_int_format_value(sub_tree, hf_rng_rsp_offset_freq_adjust, tvb, tlv_offset, 4,
						offset_freq_adjust, " %d Hz", offset_freq_adjust);
					break;
				}
				case RNG_RSP_RANGING_STATUS:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ranging_status, tvb, tlv_offset, 1, FALSE);
					ranging_status_item = proto_tree_add_item(sub_tree, hf_rng_rsp_ranging_status, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_DL_FREQ_OVERRIDE: {
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_dl_freq_override, tvb, tlv_offset, 4, FALSE);
					dl_freq_override_item = proto_tree_add_item(sub_tree, hf_rng_rsp_dl_freq_override, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
					proto_item_append_text(dl_freq_override_item, " kHz");
					break;
				}
				case RNG_RSP_UL_CHANNEL_ID_OVERRIDE:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ul_chan_id_override, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ul_chan_id_override, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_DL_OPERATIONAL_BURST_PROFILE:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_dl_operational_burst_profile, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_dl_operational_burst_profile_diuc, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_dl_operational_burst_profile_ccc, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_SS_MAC_ADDRESS:
					if (tlv_len == 6)
					{
						sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ss_mac_address, tvb, tlv_offset, 6, FALSE);
						ss_mac_address_item = proto_tree_add_item(sub_tree, hf_rng_rsp_ss_mac_address, tvb, tlv_offset, 6, FALSE);
					} else {
						sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_invalid_tlv, tvb, tlv_offset, tlv_len, FALSE);
						proto_tree_add_item(sub_tree, hf_rng_rsp_ss_mac_address, tvb, tlv_offset, 6, FALSE);
					}
					break;
				case RNG_RSP_BASIC_CID:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_basic_cid, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_basic_cid, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_PRIMARY_MGMT_CID:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_primary_mgmt_cid, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_primary_mgmt_cid, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_AAS_BROADCAST_PERMISSION:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_broadcast, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_broadcast, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_FRAME_NUMBER:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_frame_number, tvb, tlv_offset, 3, FALSE);
					frame_number_item = proto_tree_add_item(sub_tree, hf_rng_rsp_frame_number, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_OPPORTUNITY_NUMBER:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_opportunity_number, tvb, tlv_offset, 1, FALSE);
					opportunity_number_item = proto_tree_add_item(sub_tree, hf_rng_rsp_opportunity_number, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					if (tvb_get_ntohl(tvb, tlv_offset) == 0)
						proto_item_append_text(opportunity_number_item, " (may not be 0!)");
					break;
				case RNG_RSP_SERVICE_LEVEL_PREDICTION:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_service_level_prediction, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_service_level_prediction, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_RESOURCE_RETAIN_FLAG:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_resource_retain_flag, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_resource_retain_flag, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_HO_PROCESS_OPTIMIZATION:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ho_process_optimization, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_0, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_1_2, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_3, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_4, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_5, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_6, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_7, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_8, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_9, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_10, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_11, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_12, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_13, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_14, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_process_optimization_15, tvb, tlv_offset, 2, FALSE);
					break;
				case RNG_RSP_SBC_RSP_ENCODINGS:
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "SBC-RSP Encodings (%u byte(s))", tlv_len);
					dissect_mac_mgmt_msg_sbc_rsp_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, sub_tree);
					break;
				case RNG_RSP_REG_RSP_ENCODINGS:
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "REG-RSP Encodings (%u byte(s))", tlv_len);
					dissect_mac_mgmt_msg_reg_rsp_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, sub_tree);
					break;
				/* Implemented message encoding 33 (Table 367 in IEEE 802.16e-2007) */
				case RNG_RSP_DL_OP_BURST_PROFILE_OFDMA:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_dl_op_burst_profile_ofdma, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_least_robust_diuc, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_repetition_coding_indication, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_config_change_count_of_dcd, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_HO_ID:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ho_id, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ho_id, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_LOCATION_UPDATE_RESPONSE:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_location_update_response, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_location_update_response, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_PAGING_INFORMATION:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_paging_information, tvb, tlv_offset, 5, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_paging_cycle, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_paging_offset, tvb, tlv_offset+2, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_paging_group_id, tvb, tlv_offset+3, 2, ENC_BIG_ENDIAN);
					break;
				case RNG_RSP_POWER_SAVING_CLASS_PARAMETERS:
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Power Saving Class Parameters (%u byte(s))", tlv_len);
					dissect_power_saving_class(sub_tree, tlv_type, tvb, tlv_len, pinfo, tlv_offset);
					break;
				case RNG_RSP_SA_CHALLENGE_TUPLE:
					/* Display SA Challenge Tuple header */
					sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "SA Challenge Tuple (%u byte(s))", tlv_len);
					/* add subtree */
					/* Use a local copy of tlv_offset */
					this_offset = tlv_offset;
					while(this_offset < tlv_len) {
						/* Get the sub TLV data. */
						init_tlv_info(&sub_tlv_info, tvb, this_offset);
						/* get the sub TLV type */
						sub_tlv_type = get_tlv_type(&sub_tlv_info);
						/* get the TLV length */
						sub_tlv_len = get_tlv_length(&sub_tlv_info);
						if(tlv_type == -1 || sub_tlv_len > MAX_TLV_LEN || sub_tlv_len < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "RNG-RSP TLV error");
							proto_tree_add_item(rng_rsp_tree, hf_rng_invalid_tlv, tvb, tlv_offset, (tvb_len - offset), ENC_NA);
							break;
						}
						/* get the offset to the sub TLV data */
						sub_tlv_offset = this_offset + get_tlv_value_offset(&sub_tlv_info);
						switch (sub_tlv_type) {
							case RNG_RSP_SA_CHALLENGE_BS_RANDOM:
								tlv_tree = add_tlv_subtree(&sub_tlv_info, ett_rng_rsp_message_tree, sub_tree, hf_rng_rsp_bs_random, tvb, sub_tlv_offset, sub_tlv_len, FALSE);
								proto_tree_add_item(tlv_tree, hf_rng_rsp_bs_random, tvb, sub_tlv_offset, sub_tlv_len, ENC_NA);
								break;
							case RNG_RSP_SA_CHALLENGE_AKID:
								tlv_tree = add_tlv_subtree(&sub_tlv_info, ett_rng_rsp_message_tree, sub_tree, hf_rng_rsp_akid, tvb, sub_tlv_offset, sub_tlv_len, FALSE);
								proto_tree_add_item(tlv_tree, hf_rng_rsp_akid, tvb, sub_tlv_offset, sub_tlv_len, ENC_NA);
								break;
							default:
								tlv_tree = add_tlv_subtree(&sub_tlv_info, ett_rng_rsp_message_tree, sub_tree, hf_tlv_type, tvb, sub_tlv_offset, sub_tlv_len, FALSE);
								proto_tree_add_item(tlv_tree, hf_tlv_type, tvb, sub_tlv_offset, sub_tlv_len, ENC_NA);
								break;
						}
						this_offset = sub_tlv_len + sub_tlv_offset;
					}
					break;
				case DSx_UPLINK_FLOW:
					/* display Uplink Service Flow Encodings info */
					/* add subtree */
					sub_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_rng_rsp_decoder, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Uplink QOS Parameters (%u bytes)", tlv_len);
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, sub_tree);
					break;
				case DSx_DOWNLINK_FLOW:
					/* display Downlink Service Flow Encodings info */
					/* add subtree */
					sub_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_rng_rsp_decoder, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Downlink QOS Parameters (%u bytes)", tlv_len);
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, sub_tree);
					break;
				case RNG_RSP_RANGING_CODE_ATTRIBUTES:
				/* case SHORT_HMAC_TUPLE: */
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_rng_rsp_ranging_subchan, tvb, tlv_offset, 4, FALSE);
					proto_tree_add_item(sub_tree, hf_rng_rsp_time_symbol_reference, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_subchannel_reference, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_ranging_code_index, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(sub_tree, hf_rng_rsp_frame_number2, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
					break;
				case SHORT_HMAC_TUPLE_COR2:
					if (include_cor2_changes) {
						sub_tree = add_protocol_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, proto_mac_mgmt_msg_rng_rsp_decoder, tvb, tlv_offset, tlv_len, "Short HMAC Tuple (%u byte(s))", tlv_len);
						wimax_short_hmac_tuple_decoder(sub_tree, tvb, tlv_offset, tvb_len - offset);
					} else {
						/* Unknown TLV type */
						sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_tlv_type, tvb, tlv_offset, 1, FALSE);
						proto_tree_add_item(sub_tree, hf_tlv_type, tvb, tlv_offset, tlv_len, ENC_NA);
					}
					break;
			
				default:
					sub_tree = add_tlv_subtree(&tlv_info, ett_rng_rsp_message_tree, rng_rsp_tree, hf_tlv_type, tvb, tlv_offset, 1, FALSE);
					proto_tree_add_item(sub_tree, hf_tlv_type, tvb, tlv_offset, tlv_len, ENC_NA);
					break;
					
			}
			offset = tlv_len + tlv_offset;
		}	/* end of TLV process while loop */
		if (ranging_status_item && dl_freq_override_item)
			proto_item_append_text(ranging_status_item, " (shall be set to 2 because Downlink Frequency Override is present)");
		if (ss_mac_address_item && frame_number_item) {
			proto_item_append_text(frame_number_item, " (mutually exclusive with SS MAC Address!)");
			proto_item_append_text(ss_mac_address_item, " (mutually exclusive with Frame Number!)");
		}
		if (ss_mac_address_item && opportunity_number_item) {
			proto_item_append_text(opportunity_number_item, " (mutually exclusive with SS MAC Address!)");
			proto_item_append_text(ss_mac_address_item, " (mutually exclusive with Initial Ranging Opportunity Number!)");
		}
		if (!ranging_status_item)
			proto_item_append_text(rng_rsp_tree, " (Ranging status is missing!)");

	}
}


/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_rng_rsp(void)
{
	/* RNG-RSP fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_rng_rsp_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.rng_rsp",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_broadcast,
			{
				"AAS broadcast permission", "wmx.rng_rsp.aas_broadcast",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_rng_rsp_aas_broadcast), 0x0, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_akid,
			{
				"AKId", "wmx.rng_rsp.akid",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_basic_cid,
			{
				"Basic CID", "wmx.rng_rsp.basic_cid",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_bs_random,
			{
				"BS_Random", "wmx.rng_rsp.bs_random",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_config_change_count_of_dcd,
			{
				"Configuration Change Count value of DCD defining DIUC associated burst profile", "wmx.rng_rsp.config_change_count_of_dcd",
				FT_UINT16, BASE_HEX, NULL, 0xFF00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_dl_freq_override,
			{
				"Downlink Frequency Override", "wmx.rng_rsp.dl_freq_override",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_dl_operational_burst_profile_ccc,
			{
				"CCC value of DCD defining the burst profile associated with DIUC", "wmx.rng_rsp.dl_op_burst_prof.ccc",
				FT_UINT16, BASE_DEC, NULL, 0x00FF, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_dl_operational_burst_profile_diuc,
			{
				"The least robust DIUC that may be used by the BS for transmissions to the SS", "wmx.rng_rsp.dl_op_burst_prof.diuc",
				FT_UINT16, BASE_DEC, NULL, 0xFF00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_dl_operational_burst_profile,
			{
				"Downlink Operational Burst Profile", "wmx.rng_rsp.dl_op_burst_profile",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		/* Added the following to help implement RNG-RSP message encoding 33 (Table 367 in IEEE 802.16e-2007) */
		{
			&hf_rng_rsp_dl_op_burst_profile_ofdma,
			{
				"Downlink Operational Burst Profile for OFDMA", "wmx.rng_rsp.dl_op_burst_profile_ofdma",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_frame_number2,
			{
				"The 8 least significant bits of the frame number of the OFDMA frame where the SS sent the ranging code", "wmx.rng_rsp.eight_bit_frame_num",
				FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_frame_number,
			{
				"Frame number", "wmx.rng_rsp.frame_number",
				FT_UINT24, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		/* Added the following to help implement RNG-RSP message encoding 22 (IEEE 802.16e-2007) */
		{
			&hf_rng_rsp_ho_id,
			{
				"HO ID", "wmx.rng_rsp.ho_id",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization,
			{
				"HO Process Optimization", "wmx.rng_rsp.ho_process_optimization",
				FT_UINT16, BASE_HEX, NULL, 0x0000, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_0,
			{
				"Bit #0", "wmx.rng_rsp.ho_process_optimization.omit_sbc_req",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_0), 0x0001, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_1_2,
			{
				"Bits #1-2", "wmx.rng_rsp.ho_process_optimization.perform_reauthentication",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_1_2), 0x0006, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_3,
			{
				"Bit #3", "wmx.rng_rsp.ho_process_optimization.omit_network_address",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_3), 0x0008, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_4,
			{
				"Bit #4", "wmx.rng_rsp.ho_process_optimization.omit_time_of_day",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_4), 0x0010, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_5,
			{
				"Bit #5", "wmx.rng_rsp.ho_process_optimization.omit_tftp",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_5), 0x0020, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_6,
			{
				"Bit #6", "wmx.rng_rsp.ho_process_optimization.transfer_or_sharing",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_6), 0x0040, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_7,
			{
				"Bit #7", "wmx.rng_rsp.ho_process_optimization.omit_reg_req",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_7), 0x0080, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_8,
			{
				"Bit #8", "wmx.rng_rsp.ho_process_optimization.unsolicited_sbc_rsp",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_8), 0x0100, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_9,
			{
				"Bit #9", "wmx.rng_rsp.ho_process_optimization.post_ho_reentry",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_9), 0x0200, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_10,
			{
				"Bit #10", "wmx.rng_rsp.ho_process_optimization.unsolicited_reg_rsp",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_10), 0x0400, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_11,
			{
				"Bit #11", "wmx.rng_rsp.ho_process_optimization.virtual_sdu_sn",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_11), 0x0800, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_12,
			{
				"Bit #12", "wmx.rng_rsp.ho_process_optimization.send_notification",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_12), 0x1000, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_13,
			{
				"Bit #13", "wmx.rng_rsp.ho_process_optimization.trigger_higher_layer_protocol",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_ho_process_optimization_13), 0x2000, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_14,
			{
				"Bit #14: Reserved", "wmx.rng_rsp.ho_process_optimization.reserved",
				FT_UINT16, BASE_HEX, NULL, 0x4000, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ho_process_optimization_15,
			{
				"Bit #15: Reserved", "wmx.rng_rsp.ho_process_optimization.reserved",
				FT_UINT16, BASE_HEX, NULL, 0x8000, NULL, HFILL
			}
		},
		{
			&hf_rng_invalid_tlv,
			{
				"Invalid TLV", "wmx.rng_rsp.invalid_tlv", 
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_least_robust_diuc,
			{
				"Least Robust DIUC that may be used by the BS for transmissions to the MS", "wmx.rng_rsp.least_robust_diuc",
				FT_UINT16, BASE_HEX, NULL, 0x000F, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_location_update_response,
			{
				"Location Update Response", "wmx.rng_rsp.location_update_response",
				FT_UINT8, BASE_DEC, VALS(vals_rng_rsp_location_update_response), 0xFF, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_offset_freq_adjust,
			{
				"Offset Frequency Adjust", "wmx.rng_rsp.offset_freq_adjust",
				FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_opportunity_number,
			{
				"Initial ranging opportunity number", "wmx.rng_rsp.opportunity_number",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_paging_cycle,
			{
				"Paging Cycle", "wmx.rng_rsp.paging_cycle",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_paging_group_id,
			{
				"Paging Group ID", "wmx.rng_rsp.paging_group_id",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_paging_information,
			{
				"Paging Information", "wmx.rng_rsp.paging_information",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_paging_offset,
			{
				"Paging Offset", "wmx.rng_rsp.paging_offset",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_power_level_adjust,
			{
				"Power Level Adjust", "wmx.rng_rsp.power_level_adjust",
				FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_primary_mgmt_cid,
			{
				"Primary Management CID", "wmx.rng_rsp.primary_mgmt_cid",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ranging_code_index,
			{
				"The ranging code index that was sent by the SS", "wmx.rng_rsp.ranging_code_index",
				FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ranging_status,
			{
				"Ranging status", "wmx.rng_rsp.ranging_status",
				FT_UINT8, BASE_DEC, VALS(vals_rng_rsp_ranging_status), 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ranging_subchan,
			{
				"Ranging code attributes", "wmx.rng_rsp.ranging_subchannel",
				FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_repetition_coding_indication,
			{
				"Repetition Coding Indication", "wmx.rng_rsp.repetition_coding_indication",
				FT_UINT16, BASE_HEX, VALS(vals_rng_rsp_repetition_coding_indication), 0x00F0, NULL, HFILL
			}
		},
		{
			&hf_rng_req_reserved,
			{
				"Reserved", "wmx.rng_rsp.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_resource_retain_flag,
			{
				"The connection information for the MS is", "wmx.rng_rsp.resource_retain_flag",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_rng_rsp_resource_retain_flag), 0x0, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_service_level_prediction,
			{
				"Service Level Prediction", "wmx.rng_rsp.service_level_prediction",
				FT_UINT8, BASE_DEC, VALS(vals_rng_rsp_level_of_service), 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ss_mac_address,
			{
				"SS MAC Address", "wmx.rng_rsp.ss_mac_address",
				FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
			{
			&hf_rng_rsp_subchannel_reference,
			{
				"OFDMA subchannel reference used to transmit the ranging code", "wmx.rng_rsp.subchannel_reference",
				FT_UINT32, BASE_DEC, NULL, 0x003f0000, NULL, HFILL
			}
		},
			{
			&hf_rng_rsp_time_symbol_reference,
			{
				"OFDM time symbol reference used to transmit the ranging code", "wmx.rng_rsp.time_symbol_reference",
				FT_UINT32, BASE_DEC, NULL, 0xFFC00000, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_timing_adjust,
			{
				"Timing Adjust", "wmx.rng_rsp.timing_adjust",
				FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ul_channel_id,
			{
				"Uplink Channel ID", "wmx.rng_rsp.ul_chan_id",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_rng_rsp_ul_chan_id_override,
			{
				"Uplink channel ID Override", "wmx.rng_rsp.ul_chan_id_override",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_tlv_type,
			{
				"Unknown TLV Type", "wmx.rng_rsp.unknown_tlv_type",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_tlv_value,
			{
				"Value", "wmx.rng_rsp.tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_rng_rsp_decoder,
			&ett_rng_rsp_message_tree
		};

	proto_mac_mgmt_msg_rng_rsp_decoder = proto_mac_mgmt_msg_rng_req_decoder;

	proto_register_field_array(proto_mac_mgmt_msg_rng_rsp_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

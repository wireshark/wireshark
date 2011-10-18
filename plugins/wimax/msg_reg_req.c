/* msg_reg_req.c
 * WiMax MAC Management REG-REQ Message decoder
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

#define WIMAX_16E_2005

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_tlv.h"
#include "wimax_mac.h"
#include "wimax_utils.h"

extern gint proto_wimax;
extern gboolean include_cor2_changes;

gint proto_mac_mgmt_msg_reg_req_decoder = -1;
static gint ett_mac_mgmt_msg_reg_req_decoder = -1;

/* REG-REQ fields */
static gint hf_reg_ss_mgmt_support                   = -1;
static gint hf_reg_ip_mgmt_mode                      = -1;
static gint hf_reg_ip_version                        = -1;
static gint hf_reg_req_secondary_mgmt_cid            = -1;
static gint hf_reg_ul_cids                           = -1;
static gint hf_reg_max_classifiers                   = -1;
static gint hf_reg_phs                               = -1;
static gint hf_reg_arq                               = -1;
static gint hf_reg_dsx_flow_control                  = -1;
static gint hf_reg_mac_crc_support                   = -1;
static gint hf_reg_mca_flow_control                  = -1;
static gint hf_reg_mcast_polling_cids                = -1;
static gint hf_reg_num_dl_trans_cid		     = -1;
static gint hf_reg_mac_address                       = -1;
static gint hf_reg_tlv_t_20_1_max_mac_level_data_per_dl_frame      = -1;
static gint hf_reg_tlv_t_20_2_max_mac_level_data_per_ul_frame      = -1;
static gint hf_reg_tlv_t_21_packing_support                        = -1;
static gint hf_reg_tlv_t_22_mac_extended_rtps_support	           = -1;
static gint hf_reg_tlv_t_23_max_num_bursts_concurrently_to_the_ms = -1;
static gint hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcp     = -1;
static gint hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_mobile_ipv4 = -1;
static gint hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcpv6   = -1;
static gint hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_ipv6     = -1;
static gint hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_rsvd     = -1;
static gint hf_reg_tlv_t_27_handover_fbss_mdho_ho_disable          = -1;
static gint hf_reg_tlv_t_27_handover_fbss_mdho_dl_rf_monitoring_maps = -1;
static gint hf_reg_tlv_t_27_handover_mdho_dl_monitoring_single_map = -1;
static gint hf_reg_tlv_t_27_handover_mdho_dl_monitoring_maps       = -1;
static gint hf_reg_tlv_t_27_handover_mdho_ul_multiple              = -1;
static gint hf_reg_tlv_t_27_handover_reserved                      = -1;
static gint hf_reg_tlv_t_29_ho_process_opt_ms_timer                = -1;
static gint hf_reg_tlv_t_31_mobility_handover                      = -1;
static gint hf_reg_tlv_t_31_mobility_sleep_mode                    = -1;
static gint hf_reg_tlv_t_31_mobility_idle_mode                     = -1;
static gint hf_reg_req_tlv_t_32_sleep_mode_recovery_time           = -1;
static gint hf_ms_previous_ip_address_v4                           = -1;
static gint hf_ms_previous_ip_address_v6                           = -1;
static gint hf_idle_mode_timeout				   = -1;
static gint hf_reg_req_tlv_t_45_ms_periodic_ranging_timer          = -1;
static gint hf_reg_tlv_t_40_arq_ack_type_selective_ack_entry = -1;
static gint hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_entry = -1;
static gint hf_reg_tlv_t_40_arq_ack_type_cumulative_with_selective_ack_entry = -1;
static gint hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_with_block_sequence_ack = -1;
static gint hf_reg_tlv_t_40_arq_ack_type_reserved                  = -1;
static gint hf_reg_tlv_t_41_ho_connections_param_processing_time   = -1;
static gint hf_reg_tlv_t_42_ho_tek_processing_time                 = -1;
static gint hf_reg_tlv_t_43_bandwidth_request_ul_tx_power_report_header_support = -1;
static gint hf_reg_tlv_t_43_bandwidth_request_cinr_report_header_support = -1;
static gint hf_reg_tlv_t_43_cqich_allocation_request_header_support = -1;
static gint hf_reg_tlv_t_43_phy_channel_report_header_support      = -1;
static gint hf_reg_tlv_t_43_bandwidth_request_ul_sleep_control_header_support = -1;
static gint hf_reg_tlv_t_43_sn_report_header_support               = -1;
static gint hf_reg_tlv_t_43_feedback_header_support                = -1;
static gint hf_reg_tlv_t_43_sdu_sn_extended_subheader_support_and_parameter = -1;
static gint hf_reg_tlv_t_43_sdu_sn_parameter                       = -1;
static gint hf_reg_tlv_t_43_dl_sleep_control_extended_subheader    = -1;
static gint hf_reg_tlv_t_43_feedback_request_extended_subheader    = -1;
static gint hf_reg_tlv_t_43_mimo_mode_feedback_extended_subheader  = -1;
static gint hf_reg_tlv_t_43_ul_tx_power_report_extended_subheader  = -1;
static gint hf_reg_tlv_t_43_mini_feedback_extended_subheader       = -1;
static gint hf_reg_tlv_t_43_sn_request_extended_subheader          = -1;
static gint hf_reg_tlv_t_43_pdu_sn_short_extended_subheader        = -1;
static gint hf_reg_tlv_t_43_pdu_sn_long_extended_subheader         = -1;
static gint hf_reg_tlv_t_43_reserved                               = -1;
static gint hf_reg_tlv_t_46_handover_indication_readiness_timer    = -1;
static gint hf_reg_req_min_time_for_intra_fa			   = -1;
static gint hf_reg_req_min_time_for_inter_fa			   = -1;
static gint hf_reg_encap_atm_4                                     = -1;
static gint hf_reg_encap_ipv4_4                                      = -1;
static gint hf_reg_encap_ipv6_4                                      = -1;
static gint hf_reg_encap_802_3_4                                     = -1;
static gint hf_reg_encap_802_1q_4                                    = -1;
static gint hf_reg_encap_ipv4_802_3_4                                = -1;
static gint hf_reg_encap_ipv6_802_3_4                                = -1;
static gint hf_reg_encap_ipv4_802_1q_4                               = -1;
static gint hf_reg_encap_ipv6_802_1q_4                               = -1;
static gint hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_4  = -1;
static gint hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_4 = -1;
static gint hf_reg_encap_packet_ip_rohc_header_compression_4         = -1;
static gint hf_reg_encap_packet_ip_ecrtp_header_compression_4        = -1;
static gint hf_reg_encap_rsvd_4                                     = -1;
static gint hf_reg_encap_atm_2                                     = -1;
static gint hf_reg_encap_ipv4_2                                      = -1;
static gint hf_reg_encap_ipv6_2                                      = -1;
static gint hf_reg_encap_802_3_2                                     = -1;
static gint hf_reg_encap_802_1q_2                                    = -1;
static gint hf_reg_encap_ipv4_802_3_2                                = -1;
static gint hf_reg_encap_ipv6_802_3_2                                = -1;
static gint hf_reg_encap_ipv4_802_1q_2                               = -1;
static gint hf_reg_encap_ipv6_802_1q_2                               = -1;
static gint hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_2  = -1;
static gint hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_2 = -1;
static gint hf_reg_encap_packet_ip_rohc_header_compression_2         = -1;
static gint hf_reg_encap_packet_ip_ecrtp_header_compression_2        = -1;
static gint hf_reg_encap_rsvd_2                                     = -1;
static gint hf_tlv_type                                            = -1;
static gint hf_reg_invalid_tlv                                     = -1;
static gint hf_reg_power_saving_class_type_i                       = -1;
static gint hf_reg_power_saving_class_type_ii                      = -1;
static gint hf_reg_power_saving_class_type_iii                     = -1;
static gint hf_reg_multi_active_power_saving_classes               = -1;
static gint hf_reg_total_power_saving_class_instances              = -1;
static gint hf_reg_power_saving_class_reserved                     = -1;

static gint hf_reg_req_message_type                                = -1;

/* STRING RESOURCES */

static const true_false_string tfs_reg_ip_mgmt_mode = {
    "IP-managed mode",
    "Unmanaged mode"
};

static const true_false_string tfs_reg_ss_mgmt_support = {
    "secondary management connection",
    "no secondary management connection"
};

static const true_false_string tfs_arq_enable = {
	    "ARQ Requested/Accepted",
	        "ARQ Not Requested/Accepted"
};

static const true_false_string tfs_arq_deliver_in_order = {
	    "Order of delivery is preserved",
	        "Order of delivery is not preserved"
};

static const true_false_string tfs_reg_fbss_mdho_ho_disable = {
    "Disable",
    "Enable"
};

static const value_string vals_reg_ip_version[] = {
    {0x1,                               "IPv4"},
    {0x2,				"IPV6"},
    {0,					NULL}
};

static const value_string vals_reg_phs_support[] = {
    {0,                                 "no PHS support"},
    {1,                                 "ATM PHS"},
    {2,                                 "Packet PHS"},
    {3,					"ATM and Packet PHS"},
    {0,					NULL}
};

static const true_false_string tfs_supported = {
    "supported",
    "unsupported"
};

static const true_false_string tfs_mac_crc_support = {
    "MAC CRC Support (Default)",
    "No MAC CRC Support"
};

static const value_string tfs_support[] = {
    {0,					"not supported"},
    {1,					"supported"},
    {0,					NULL}
};

/* Decode REG-REQ sub-TLV's. */
void dissect_extended_tlv(proto_tree *reg_req_tree, gint tlv_type, tvbuff_t *tvb, guint tlv_offset, guint tlv_len, packet_info *pinfo, guint offset, gint proto_registry)
{
	proto_item *tlv_item = NULL;
	proto_tree *tlv_tree = NULL;
	proto_tree *sub_tree = NULL;
	guint tvb_len;
	tlv_info_t tlv_info;
	guint tlv_end;
	guint length;
	guint nblocks;

	/* Get the tvb reported length */
	tvb_len =  tvb_reported_length(tvb);

	/* get the TLV information */
	init_tlv_info(&tlv_info, tvb, offset);

#ifdef WIMAX_16E_2005
	switch (tlv_type) {
		case REG_ARQ_PARAMETERS:
			/* display ARQ Service Flow Encodings info */
			/* add subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "ARQ Service Flow Encodings (%u byte(s))", tlv_len);
			/* decode and display the DL Service Flow Encodings */
			wimax_service_flow_encodings_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, tlv_tree);
			break;
		case REG_SS_MGMT_SUPPORT:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_ss_mgmt_support, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_ss_mgmt_support, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_IP_MGMT_MODE:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_ip_mgmt_mode, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_ip_mgmt_mode, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_IP_VERSION:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_ip_version, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_ip_version, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_UL_TRANSPORT_CIDS_SUPPORTED:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_ul_cids, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_ul_cids, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
			break;
			
		case REG_POWER_SAVING_CLASS_CAPABILITY:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Power saving class capability (%d)", tvb_get_ntohs(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_power_saving_class_type_i, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_power_saving_class_type_ii, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_power_saving_class_type_iii, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_multi_active_power_saving_classes, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_total_power_saving_class_instances, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_power_saving_class_reserved, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			break;
		case REG_IP_PHS_SDU_ENCAP:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Classification/PHS options and SDU encapsulation support 0x%04x", tvb_get_ntohs(tvb, tlv_offset));

#ifdef WIMAX_16E_2005
			if (tlv_len == 2){
				proto_tree_add_item(tlv_tree, hf_reg_encap_atm_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_802_3_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_802_1q_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_802_3_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_802_3_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_802_1q_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_802_1q_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_ip_rohc_header_compression_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_ip_ecrtp_header_compression_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_rsvd_2, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
			} else if(tlv_len == 4){
				proto_tree_add_item(tlv_tree, hf_reg_encap_atm_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_802_3_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_802_1q_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_802_3_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_802_3_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv4_802_1q_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_ipv6_802_1q_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_ip_rohc_header_compression_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_packet_ip_ecrtp_header_compression_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_reg_encap_rsvd_4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
			}
#endif
			break;
		case REG_MAX_CLASSIFIERS_SUPPORTED:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_max_classifiers, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_max_classifiers, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			break;
		case REG_PHS_SUPPORT:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_phs, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_phs, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_ARQ_SUPPORT:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_arq, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_arq, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_DSX_FLOW_CONTROL:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_dsx_flow_control, tvb, tlv_offset, tlv_len, FALSE);
			tlv_item = proto_tree_add_item(tlv_tree, hf_reg_dsx_flow_control, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			if (tvb_get_guint8(tvb, tlv_offset) == 0) {
				proto_item_append_text(tlv_item, " (no limit)");
			}
			break;
		case REG_MAC_CRC_SUPPORT:
			if (!include_cor2_changes) {
				proto_tree_add_item(reg_req_tree, hf_reg_mac_crc_support, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
				tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_mac_crc_support, tvb, tlv_offset, tlv_len, FALSE);
				proto_tree_add_item(tlv_tree, hf_reg_mac_crc_support, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			} else {
				/* Unknown TLV Type */
				tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, (tvb_len - tlv_offset), FALSE);
				proto_tree_add_item(tlv_tree, hf_tlv_type, tvb, tlv_offset, (tvb_len - tlv_offset), ENC_NA);
			}
			break;
		case REG_MCA_FLOW_CONTROL:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_mca_flow_control, tvb, tlv_offset, tlv_len, FALSE);
			tlv_item = proto_tree_add_item(tlv_tree, hf_reg_mca_flow_control, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			if (tvb_get_guint8(tvb, tlv_offset) == 0) {
				proto_item_append_text(tlv_item, " (no limit)");
			}
			break;
		case REG_MCAST_POLLING_CIDS:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_mcast_polling_cids, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_mcast_polling_cids, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_NUM_DL_TRANS_CID:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_num_dl_trans_cid, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_num_dl_trans_cid, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
			break;
		case REG_MAC_ADDRESS:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_mac_address, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_mac_address, tvb, tlv_offset, 6, FALSE);
			break;
		case REG_TLV_T_20_MAX_MAC_DATA_PER_FRAME_SUPPORT:
			/* display Maximum MAC level data per frame info */
			/* add subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Maximum MAC level data per frame (%u byte(s))", tlv_len);
			/* decode and display Maximum MAC level data per frame for UL & DL */
			/* Set endpoint of the subTLVs (tlv_offset + length) */
			tlv_end = tlv_offset + tlv_len;
			/* process subTLVs */
			while ( tlv_offset < tlv_end )
			{	/* get the TLV information */
				init_tlv_info(&tlv_info, tvb, tlv_offset);
				/* get the TLV type */
				tlv_type = get_tlv_type(&tlv_info);
				/* get the TLV length */
				length = get_tlv_length(&tlv_info);
				if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
				{	/* invalid tlv info */
					col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "REG-REQ TLV error");
					proto_tree_add_item(reg_req_tree, hf_reg_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
					break;
				}
				/* update the offset */
				tlv_offset += get_tlv_value_offset(&tlv_info);
				nblocks = tvb_get_ntohs(tvb, tlv_offset);
				switch (tlv_type)
				{
					case REG_TLV_T_20_1_MAX_MAC_LEVEL_DATA_PER_DL_FRAME:
						sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, tlv_tree, hf_reg_tlv_t_20_1_max_mac_level_data_per_dl_frame, tvb, tlv_offset, length, FALSE);
						tlv_item = proto_tree_add_item(sub_tree, hf_reg_tlv_t_20_1_max_mac_level_data_per_dl_frame, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
						if ( nblocks == 0 )
						{
							proto_item_append_text(tlv_item, " (Unlimited bytes)");
						} else {
							proto_item_append_text(tlv_item, " (%d bytes)", 256 * nblocks);
						}
						break;
					case REG_TLV_T_20_2_MAX_MAC_LEVEL_DATA_PER_UL_FRAME:
						sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, tlv_tree, hf_reg_tlv_t_20_2_max_mac_level_data_per_ul_frame, tvb, tlv_offset, length, FALSE);
						tlv_item = proto_tree_add_item(sub_tree, hf_reg_tlv_t_20_2_max_mac_level_data_per_ul_frame, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
						if ( nblocks == 0 )
						{
							proto_item_append_text(tlv_item, " (Unlimited bytes)");
						} else {
							proto_item_append_text(tlv_item, " (%d bytes)", 256 * nblocks);
						}
						break;
					default:
						sub_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, tlv_tree, hf_reg_invalid_tlv, tvb, tlv_offset, (tlv_end - tlv_offset), FALSE);
						proto_tree_add_item(sub_tree, hf_reg_invalid_tlv, tvb, tlv_offset, (tlv_end - tlv_offset), ENC_NA);
						break;
				}
				tlv_offset += length;
			}
			break;

		case REG_TLV_T_21_PACKING_SUPPORT:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_21_packing_support, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_21_packing_support, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_22_MAC_EXTENDED_RTPS_SUPPORT:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_22_mac_extended_rtps_support, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_22_mac_extended_rtps_support, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_23_MAX_NUM_BURSTS_TRANSMITTED_CONCURRENTLY_TO_THE_MS:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_23_max_num_bursts_concurrently_to_the_ms, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_23_max_num_bursts_concurrently_to_the_ms, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_26_METHOD_FOR_ALLOCATING_IP_ADDR_SECONDARY_MGMNT_CONNECTION:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Method for allocating IP address for the secondary management connection (%d)", tvb_get_guint8(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcp, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_mobile_ipv4, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcpv6, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_ipv6, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_rsvd, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_27_HANDOVER_SUPPORTED:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Handover Support (%d)", tvb_get_guint8(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_fbss_mdho_ho_disable, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_fbss_mdho_dl_rf_monitoring_maps, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_mdho_dl_monitoring_single_map, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_mdho_dl_monitoring_maps, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_mdho_ul_multiple, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_27_handover_reserved, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_29_HO_PROCESS_OPTIMIZATION_MS_TIMER:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_29_ho_process_opt_ms_timer, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_29_ho_process_opt_ms_timer, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_31_MOBILITY_FEATURES_SUPPORTED:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "Mobility Features Supported (%d)", tvb_get_guint8(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_31_mobility_handover, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_31_mobility_sleep_mode, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_31_mobility_idle_mode, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_40_ARQ_ACK_TYPE:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "ARQ ACK Type 0x%02x", tvb_get_guint8(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_40_arq_ack_type_selective_ack_entry, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_entry, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_40_arq_ack_type_cumulative_with_selective_ack_entry, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_with_block_sequence_ack, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_40_arq_ack_type_reserved, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_41_MS_HO_CONNECTIONS_PARAM_PROCESSING_TIME:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_41_ho_connections_param_processing_time, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_41_ho_connections_param_processing_time, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_42_MS_HO_TEK_PROCESSING_TIME:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_42_ho_tek_processing_time, tvb, tlv_offset, tlv_len, FALSE);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_42_ho_tek_processing_time, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case REG_TLV_T_43_MAC_HEADER_AND_EXTENDED_SUBHEADER_SUPPORT:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "MAC header and extended subheader support %d", tvb_get_ntoh24(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_bandwidth_request_ul_tx_power_report_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_bandwidth_request_cinr_report_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_cqich_allocation_request_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_phy_channel_report_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_bandwidth_request_ul_sleep_control_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_sn_report_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_feedback_header_support, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_sdu_sn_extended_subheader_support_and_parameter, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_sdu_sn_parameter, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_dl_sleep_control_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_feedback_request_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_mimo_mode_feedback_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_ul_tx_power_report_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_mini_feedback_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_sn_request_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_pdu_sn_short_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_pdu_sn_long_extended_subheader, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_tlv_t_43_reserved, tvb, tlv_offset, 3, ENC_BIG_ENDIAN);
			break;
		case REG_REQ_BS_SWITCHING_TIMER:
			/* add TLV subtree */
			tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, tlv_len, "BS switching timer (%d)", tvb_get_guint8(tvb, tlv_offset));
			proto_tree_add_item(tlv_tree, hf_reg_req_min_time_for_intra_fa, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_reg_req_min_time_for_inter_fa, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
			break;
		case VENDOR_SPECIFIC_INFO:
		case VENDOR_ID_ENCODING:
		case CURRENT_TX_POWER:
		case MAC_VERSION_ENCODING:
		case CMAC_TUPLE:	/* Table 348b */
			wimax_common_tlv_encoding_decoder(tvb_new_subset(tvb, offset, (tvb_len - offset), (tvb_len - offset)), pinfo, reg_req_tree);
			break;
		default:
			tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_registry, tvb, tlv_offset, (tvb_len - tlv_offset), FALSE);
			proto_tree_add_item(tlv_tree, hf_tlv_type, tvb, tlv_offset, (tvb_len - tlv_offset), ENC_NA);
			break;
	}
#endif
}


/* Decode REG-REQ messages. */
void dissect_mac_mgmt_msg_reg_req_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	guint tlv_offset;
	guint tvb_len, payload_type;
	proto_item *reg_req_item = NULL;
	proto_tree *reg_req_tree = NULL;
	proto_tree *tlv_tree = NULL;
	gboolean hmac_found = FALSE;
	tlv_info_t tlv_info;
	gint tlv_type;
	gint tlv_len;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if (payload_type != MAC_MGMT_MSG_REG_REQ)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type REG-REQ */
		reg_req_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_reg_req_decoder, tvb, offset, tvb_len, "MAC Management Message, REG-REQ (6)");
		/* add MAC REG-REQ subtree */
		reg_req_tree = proto_item_add_subtree(reg_req_item, ett_mac_mgmt_msg_reg_req_decoder);
		/* display the Message Type */
		proto_tree_add_item(reg_req_tree, hf_reg_req_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

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
				col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "REG-REQ TLV error");
				proto_tree_add_item(reg_req_tree, hf_reg_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
				break;
			}
			/* get the offset to the TLV data */
			tlv_offset = offset + get_tlv_value_offset(&tlv_info);

			switch (tlv_type) {
				case REG_ARQ_PARAMETERS:
				case REG_SS_MGMT_SUPPORT:
				case REG_IP_MGMT_MODE:
				case REG_IP_VERSION:
				case REG_UL_TRANSPORT_CIDS_SUPPORTED:
				case REG_IP_PHS_SDU_ENCAP:
				case REG_MAX_CLASSIFIERS_SUPPORTED:
				case REG_PHS_SUPPORT:
				case REG_ARQ_SUPPORT:
				case REG_DSX_FLOW_CONTROL:
				case REG_MAC_CRC_SUPPORT:
				case REG_MCA_FLOW_CONTROL:
				case REG_MCAST_POLLING_CIDS:
				case REG_NUM_DL_TRANS_CID:
				case REG_MAC_ADDRESS:
#ifdef WIMAX_16E_2005
				case REG_TLV_T_20_MAX_MAC_DATA_PER_FRAME_SUPPORT:
				case REG_TLV_T_21_PACKING_SUPPORT:
				case REG_TLV_T_22_MAC_EXTENDED_RTPS_SUPPORT:
				case REG_TLV_T_23_MAX_NUM_BURSTS_TRANSMITTED_CONCURRENTLY_TO_THE_MS:
				case REG_TLV_T_26_METHOD_FOR_ALLOCATING_IP_ADDR_SECONDARY_MGMNT_CONNECTION:
				case REG_TLV_T_27_HANDOVER_SUPPORTED:
				case REG_TLV_T_29_HO_PROCESS_OPTIMIZATION_MS_TIMER:
				case REG_TLV_T_31_MOBILITY_FEATURES_SUPPORTED:
				case REG_TLV_T_40_ARQ_ACK_TYPE:
				case REG_TLV_T_41_MS_HO_CONNECTIONS_PARAM_PROCESSING_TIME:
				case REG_TLV_T_42_MS_HO_TEK_PROCESSING_TIME:
				case REG_TLV_T_43_MAC_HEADER_AND_EXTENDED_SUBHEADER_SUPPORT:
				case REG_REQ_BS_SWITCHING_TIMER:
				case REG_POWER_SAVING_CLASS_CAPABILITY:
#endif
					/* Decode REG-REQ sub-TLV's. */
					dissect_extended_tlv(reg_req_tree, tlv_type, tvb, tlv_offset, tlv_len, pinfo, offset, proto_mac_mgmt_msg_reg_req_decoder);
					break;
				case REG_REQ_SECONDARY_MGMT_CID:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_req_secondary_mgmt_cid, tvb, tlv_offset, 2, FALSE);
					proto_tree_add_item(tlv_tree, hf_reg_req_secondary_mgmt_cid, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
					break;
				case REG_REQ_TLV_T_32_SLEEP_MODE_RECOVERY_TIME:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_req_tlv_t_32_sleep_mode_recovery_time, tvb, tlv_offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_reg_req_tlv_t_32_sleep_mode_recovery_time, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
					break;
				case REG_REQ_TLV_T_33_MS_PREV_IP_ADDR:
					if ( tlv_len == 4 ) {
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_ms_previous_ip_address_v4, tvb, tlv_offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ms_previous_ip_address_v4, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
					} else if ( tlv_len == 16 ) {
						tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_ms_previous_ip_address_v6, tvb, tlv_offset, tlv_len, FALSE);
						proto_tree_add_item(tlv_tree, hf_ms_previous_ip_address_v6, tvb, tlv_offset, tlv_len, ENC_NA);
					}
					break;
				case REG_TLV_T_37_IDLE_MODE_TIMEOUT:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_idle_mode_timeout, tvb, tlv_offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_idle_mode_timeout, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				case REG_REQ_TLV_T_45_MS_PERIODIC_RANGING_TIMER_INFO:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_req_tlv_t_45_ms_periodic_ranging_timer, tvb, tlv_offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_reg_req_tlv_t_45_ms_periodic_ranging_timer, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
					break;
				case REG_HANDOVER_INDICATION_READINESS_TIMER:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_reg_tlv_t_46_handover_indication_readiness_timer, tvb, tlv_offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_reg_tlv_t_46_handover_indication_readiness_timer, tvb, tlv_offset, tlv_len, ENC_BIG_ENDIAN);
					break;

				case DSx_UPLINK_FLOW:
					/* display Uplink Service Flow Encodings info */
					/* add subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_mac_mgmt_msg_reg_req_decoder, tvb, tlv_offset, tlv_len, "Uplink Service Flow Encodings (%u byte(s))", tlv_len);
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, tlv_tree);
					break;
				case DSx_DOWNLINK_FLOW:
					/* display Downlink Service Flow Encodings info */
					/* add subtree */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_mac_mgmt_msg_reg_req_decoder, tvb, tlv_offset, tlv_len, "Downlink Service Flow Encodings (%u byte(s))", tlv_len);
					/* decode and display the DL Service Flow Encodings */
					wimax_service_flow_encodings_decoder(tvb_new_subset(tvb, tlv_offset, tlv_len, tlv_len), pinfo, tlv_tree);
					break;
				case HMAC_TUPLE:	/* Table 348d */
					/* decode and display the HMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_mac_mgmt_msg_reg_req_decoder, tvb, tlv_offset, tlv_len, "HMAC Tuple (%u byte(s))", tlv_len);
					wimax_hmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					hmac_found = TRUE;
					break;
				case CMAC_TUPLE:	/* Table 348b */
					/* decode and display the CMAC Tuple */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, proto_mac_mgmt_msg_reg_req_decoder, tvb, tlv_offset, tlv_len, "CMAC Tuple (%u byte(s))", tlv_len);
					wimax_cmac_tuple_decoder(tlv_tree, tvb, tlv_offset, tlv_len);
					break;
				default:
					tlv_tree = add_tlv_subtree(&tlv_info, ett_mac_mgmt_msg_reg_req_decoder, reg_req_tree, hf_tlv_type, tvb, tlv_offset, tlv_len, FALSE);
					proto_tree_add_item(tlv_tree, hf_tlv_type, tvb, tlv_offset, tlv_len, ENC_NA);
					break;
			}
			/* update the offset */
			offset = tlv_len + tlv_offset;
		} /* End while() looping through the tvb. */
		if (!hmac_found)
			proto_item_append_text(reg_req_tree, " (HMAC Tuple is missing !)");
	}
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_reg_req(void)
{
	/* REG-REQ fields display */
	static hf_register_info hf[] =
	{
		{
			&hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcp,
			{
				"DHCP", "wmx.reg.alloc_sec_mgmt_dhcp",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_dhcpv6,
			{
				"DHCPv6", "wmx.reg.alloc_sec_mgmt_dhcpv6",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x04, NULL, HFILL
			}
		},
		{
			&hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_ipv6,
			{
				"IPv6 Stateless Address Autoconfiguration", "wmx.reg.alloc_sec_mgmt_ipv6",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x08, NULL, HFILL
			}
		},
		{
			&hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_mobile_ipv4,
			{
				"Mobile IPv4", "wmx.reg.alloc_sec_mgmt_mobile_ipv4",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x02, NULL, HFILL
			}
		},
		{
			&hf_reg_method_for_allocating_ip_addr_sec_mgmt_conn_rsvd,
			{
				"Reserved", "wmx.reg.alloc_sec_mgmt_rsvd",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_reg_arq,
			{
				"ARQ support", "wmx.reg.arq",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_entry,
			{
				"Cumulative ACK entry", "wmx.reg.arq_ack_type_cumulative_ack_entry",
				FT_UINT8, BASE_DEC, NULL, 0x2, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_40_arq_ack_type_cumulative_ack_with_block_sequence_ack,
			{
				"Cumulative ACK with Block Sequence ACK", "wmx.reg.arq_ack_type_cumulative_ack_with_block_sequence_ack",
				FT_UINT8, BASE_DEC, NULL, 0x8, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_40_arq_ack_type_cumulative_with_selective_ack_entry,
			{
				"Cumulative with Selective ACK entry", "wmx.reg.arq_ack_type_cumulative_with_selective_ack_entry",
				FT_UINT8, BASE_DEC, NULL, 0x4, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_40_arq_ack_type_reserved,
			{
				"Reserved", "wmx.reg.arq_ack_type_reserved",
				FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_40_arq_ack_type_selective_ack_entry,
			{
				"Selective ACK entry", "wmx.reg.arq_ack_type_selective_ack_entry",
				FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_bandwidth_request_cinr_report_header_support,
			{
				"Bandwidth request and CINR report header support", "wmx.reg.bandwidth_request_cinr_report_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x2, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_bandwidth_request_ul_sleep_control_header_support,
			{
				"Bandwidth request and uplink sleep control header support", "wmx.reg.bandwidth_request_ul_sleep_control_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x10, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_cqich_allocation_request_header_support,
			{
				"CQICH Allocation Request header support", "wmx.reg.cqich_allocation_request_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x4, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_dl_sleep_control_extended_subheader,
			{
				"Downlink sleep control extended subheader", "wmx.reg.dl_sleep_control_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x800, NULL, HFILL
			}
		},
		{
			&hf_reg_dsx_flow_control,
			{
				"DSx flow control", "wmx.reg.dsx_flow_control",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		/* When REG-REQ TLV 7 is length 2 */
		{
			&hf_reg_encap_802_1q_2,
			{
				"Packet, 802.1Q VLAN", "wmx.reg.encap_802_1q",
				FT_UINT16, BASE_HEX, NULL, 0x0010, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_802_3_2,
			{
				"Packet, 802.3/Ethernet", "wmx.reg.encap_802_3",
				FT_UINT16, BASE_HEX, NULL, 0x00000008, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_atm_2,
			{
				"ATM", "wmx.reg.encap_atm",
				FT_UINT16, BASE_HEX, NULL, 0x00000001, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_2,
			{
				"Packet, IPv4", "wmx.reg.encap_ipv4",
				FT_UINT16, BASE_HEX, NULL, 0x00000002, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_2,
			{
				"Packet, IPv6", "wmx.reg.encap_ipv6",
				FT_UINT16, BASE_HEX, NULL, 0x00000004, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_802_1q_2,
			{
				"Packet, IPv4 over 802.1Q VLAN", "wmx.reg.encap_ipv4_802_1q",
				FT_UINT16, BASE_HEX, NULL, 0x00000080, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_802_3_2,
			{
				"Packet, IPv4 over 802.3/Ethernet", "wmx.reg.encap_ipv4_802_3",
				FT_UINT16, BASE_HEX, NULL, 0x00000020, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_802_1q_2,
			{
				"Packet, IPv6 over 802.1Q VLAN", "wmx.reg.encap_ipv6_802_1q",
				FT_UINT16, BASE_HEX, NULL, 0x00000100, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_802_3_2,
			{
				"Packet, IPv6 over 802.3/Ethernet", "wmx.reg.encap_ipv6_802_3",
				FT_UINT16, BASE_HEX, NULL, 0x00000040, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_2,
			{
				"Packet, 802.3/Ethernet (with optional 802.1Q VLAN tags) and ECRTP header compression", "wmx.reg.encap_packet_802_3_ethernet_and_ecrtp_header_compression",
				FT_UINT16, BASE_HEX, NULL, 0x00000400, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_2,
			{
				"Packet, 802.3/Ethernet (with optional 802.1Q VLAN tags) and ROHC header compression", "wmx.reg.encap_packet_802_3_ethernet_and_rohc_header_compression",
				FT_UINT16, BASE_HEX, NULL, 0x00000200, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_ip_ecrtp_header_compression_2,
			{
				"Packet, IP (v4 or v6) with ECRTP header compression", "wmx.reg.encap_packet_ip_ecrtp_header_compression",
				FT_UINT16, BASE_HEX, NULL, 0x00001000, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_ip_rohc_header_compression_2,
			{
				"Packet, IP (v4 or v6) with ROHC header compression", "wmx.reg.encap_packet_ip_rohc_header_compression",
				FT_UINT16, BASE_HEX, NULL, 0x00000800, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_rsvd_2,
			{
				"Reserved", "wmx.reg.encap_rsvd",
				FT_UINT16, BASE_HEX, NULL, 0x0000E000, NULL, HFILL
			}
		},
		/* When REG-REQ TLV 7 is length 4 */
		{
			&hf_reg_encap_802_1q_4,
			{
				"Packet, 802.1Q VLAN", "wmx.reg.encap_802_1q",
				FT_UINT32, BASE_HEX, NULL, 0x0010, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_802_3_4,
			{
				"Packet, 802.3/Ethernet", "wmx.reg.encap_802_3",
				FT_UINT32, BASE_HEX, NULL, 0x00000008, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_atm_4,
			{
				"ATM", "wmx.reg.encap_atm",
				FT_UINT32, BASE_HEX, NULL, 0x00000001, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_4,
			{
				"Packet, IPv4", "wmx.reg.encap_ipv4",
				FT_UINT32, BASE_HEX, NULL, 0x00000002, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_802_1q_4,
			{
				"Packet, IPv4 over 802.1Q VLAN", "wmx.reg.encap_ipv4_802_1q",
				FT_UINT32, BASE_HEX, NULL, 0x00000080, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv4_802_3_4,
			{
				"Packet, IPv4 over 802.3/Ethernet", "wmx.reg.encap_ipv4_802_3",
				FT_UINT32, BASE_HEX, NULL, 0x00000020, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_4,
			{
				"Packet, IPv6", "wmx.reg.encap_ipv6",
				FT_UINT32, BASE_HEX, NULL, 0x00000004, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_802_1q_4,
			{
				"Packet, IPv6 over 802.1Q VLAN", "wmx.reg.encap_ipv6_802_1q",
				FT_UINT32, BASE_HEX, NULL, 0x00000100, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_ipv6_802_3_4,
			{
				"Packet, IPv6 over 802.3/Ethernet", "wmx.reg.encap_ipv6_802_3",
				FT_UINT32, BASE_HEX, NULL, 0x00000040, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_8023_ethernet_and_ecrtp_header_compression_4,
			{
				"Packet, 802.3/Ethernet (with optional 802.1Q VLAN tags) and ECRTP header compression", "wmx.reg.encap_packet_802_3_ethernet_and_ecrtp_header_compression",
				FT_UINT32, BASE_HEX, NULL, 0x00000400, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_8023_ethernet_and_rohc_header_compression_4,
			{
				"Packet, 802.3/Ethernet (with optional 802.1Q VLAN tags) and ROHC header compression", "wmx.reg.encap_packet_802_3_ethernet_and_rohc_header_compression",
				FT_UINT32, BASE_HEX, NULL, 0x00000200, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_ip_ecrtp_header_compression_4,
			{
				"Packet, IP (v4 or v6) with ECRTP header compression", "wmx.reg.encap_packet_ip_ecrtp_header_compression",
				FT_UINT32, BASE_HEX, NULL, 0x00001000, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_packet_ip_rohc_header_compression_4,
			{
				"Packet, IP (v4 or v6) with ROHC header compression", "wmx.reg.encap_packet_ip_rohc_header_compression",
				FT_UINT32, BASE_HEX, NULL, 0x00000800, NULL, HFILL
			}
		},
		{
			&hf_reg_encap_rsvd_4,
			{
				"Reserved", "wmx.reg.encap_rsvd",
				FT_UINT32, BASE_HEX, NULL, 0xFFFFE000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_22_mac_extended_rtps_support,
			{
				"MAC extended rtPS support", "wmx.reg.ext_rtps_support",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_fbss_mdho_dl_rf_monitoring_maps,
			{
				"FBSS/MDHO DL RF Combining with monitoring MAPs from active BSs", "wmx.reg.fbss_mdho_dl_rf_combining",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x02, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_bandwidth_request_ul_tx_power_report_header_support,
			{
				"Bandwidth request and UL Tx Power Report header support",
				"wimax.reg.bandwidth_request_ul_tx_pwr_report_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x1, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_fbss_mdho_ho_disable,
			{
				"MDHO/FBSS HO. BS ignore all other bits when set to 1", "wmx.reg.fbss_mdho_ho_disable",
				FT_BOOLEAN, 8, TFS(&tfs_reg_fbss_mdho_ho_disable), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_feedback_header_support,
			{
				"Feedback header support", "wmx.reg.feedback_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x40, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_feedback_request_extended_subheader,
			{
				"Feedback request extended subheader", "wmx.reg.feedback_request_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x1000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_46_handover_indication_readiness_timer,
			{
				"Handover indication readiness timer", "wmx.reg.handover_indication_readiness_timer",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_reserved,
			{
				"Reserved", "wmx.reg.handover_reserved",
				FT_UINT8, BASE_DEC, NULL, 0xE0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_41_ho_connections_param_processing_time,
			{
				"MS HO connections parameters processing time", "wmx.reg.ho_connections_param_processing_time",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_29_ho_process_opt_ms_timer,
			{
				"HO Process Optimization MS Timer", "wmx.reg.ho_process_opt_ms_timer",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_42_ho_tek_processing_time,
			{
				"MS HO TEK processing time", "wmx.reg.ho_tek_processing_time",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_idle_mode_timeout,
			{
				"Idle Mode Timeout", "wmx.reg.idle_mode_timeout",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_ip_mgmt_mode,
			{
				"IP management mode", "wmx.reg.ip_mgmt_mode",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_reg_ip_mgmt_mode), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_ip_version,
			{
				"IP version", "wmx.reg.ip_version",
				FT_UINT8, BASE_HEX, VALS(vals_reg_ip_version), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_mac_address,
			{
				"MAC Address of the SS", "wmx.reg.mac_address",
				FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_mac_crc_support,
			{
				"MAC CRC", "wmx.reg.mac_crc_support",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_mac_crc_support), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_max_classifiers,
			{
				"Maximum number of classification rules", "wmx.reg.max_classifiers",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_23_max_num_bursts_concurrently_to_the_ms,
			{
				"Maximum number of bursts transmitted concurrently to the MS", "wmx.reg.max_num_bursts_to_ms",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_mca_flow_control,
			{
				"MCA flow control", "wmx.reg.mca_flow_control",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_mcast_polling_cids,
			{
				"Multicast polling group CID support", "wmx.reg.mcast_polling_cids",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_mdho_ul_multiple,
			{
				"MDHO UL Multiple transmission", "wmx.reg.mdh_ul_multiple",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x10, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_mdho_dl_monitoring_maps,
			{
				"MDHO DL soft combining with monitoring MAPs from active BSs", "wmx.reg.mdho_dl_monitor_maps",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x08, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_27_handover_mdho_dl_monitoring_single_map,
			{
				"MDHO DL soft Combining with monitoring single MAP from anchor BS", "wmx.reg.mdho_dl_monitor_single_map",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x04, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_mimo_mode_feedback_extended_subheader,
			{
				"MIMO mode feedback request extended subheader", "wmx.reg.mimo_mode_feedback_request_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x2000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_mini_feedback_extended_subheader,
			{
				"Mini-feedback extended subheader", "wmx.reg.mini_feedback_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x8000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_31_mobility_handover,
			{
				"Mobility (handover)", "wmx.reg.mobility_handover",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_31_mobility_idle_mode,
			{
				"Idle mode", "wmx.reg.mobility_idle_mode",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x04, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_31_mobility_sleep_mode,
			{
				"Sleep mode", "wmx.reg.mobility_sleep_mode",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x02, NULL, HFILL
			}
		},
		{
			&hf_reg_num_dl_trans_cid,
			{
				"Number of Downlink transport CIDs the SS can support", "wmx.reg.dl_cids_supported",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_21_packing_support,
			{
				"Packing support", "wmx.reg.packing.support",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_pdu_sn_long_extended_subheader,
			{
				"PDU SN (long) extended subheader", "wmx.reg.pdu_sn_long_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x40000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_pdu_sn_short_extended_subheader,
			{
				"PDU SN (short) extended subheader", "wmx.reg.pdu_sn_short_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x20000, NULL, HFILL
			}
		},
		{
			&hf_reg_phs,
			{
				"PHS support", "wmx.reg.phs",
				FT_UINT8, BASE_DEC, VALS(vals_reg_phs_support), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_phy_channel_report_header_support,
			{
				"PHY channel report header support", "wmx.reg.phy_channel_report_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x8, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_reserved,
			{
				"Reserved", "wmx.reg.reserved",
				FT_UINT24, BASE_DEC, NULL, 0xf80000, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_sdu_sn_extended_subheader_support_and_parameter,
			{
				"SDU_SN extended subheader support", "wmx.reg.sdu_sn_extended_subheader_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x80, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_sdu_sn_parameter,
			{
				"SDU_SN parameter", "wmx.reg.sdu_sn_parameter",
				FT_UINT24, BASE_DEC, NULL, 0x700, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_sn_report_header_support,
			{
				"SN report header support", "wmx.reg.sn_report_header_support",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x20, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_sn_request_extended_subheader,
			{
				"SN request extended subheader", "wmx.reg.sn_request_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x10000, NULL, HFILL
			}
		},
		{
			&hf_reg_ss_mgmt_support,
			{
				"SS management support", "wmx.reg.ss_mgmt_support",
				FT_BOOLEAN, BASE_NONE, TFS(&tfs_reg_ss_mgmt_support), 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_ul_cids,
			{
				"Number of Uplink transport CIDs the SS can support", "wmx.reg.ul_cids_supported",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_43_ul_tx_power_report_extended_subheader,
			{
				"UL Tx power report extended subheader", "wmx.reg.ul_tx_power_report_extended_subheader",
				FT_UINT24, BASE_DEC, VALS(tfs_support), 0x4000, NULL, HFILL
			}
		},
		{
			&hf_tlv_type,
			{
				"Unknown TLV Type", "wmx.reg.unknown_tlv_type",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_reg_req_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.reg_req",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_invalid_tlv,
			{
				"Invalid TLV", "wmx.reg_req.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_20_1_max_mac_level_data_per_dl_frame,
			{
				"Maximum MAC level DL data per frame", "wmx.reg_req.max_mac_dl_data",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_tlv_t_20_2_max_mac_level_data_per_ul_frame,
			{
				"Maximum MAC level UL data per frame", "wmx.reg_req.max_mac_ul_data",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_req_min_time_for_inter_fa,
			{
				"Minimum time for inter-FA HO, default=3", "wmx.reg_req.min_time_for_inter_fa",
				FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_reg_req_min_time_for_intra_fa,
			{
				"Minimum time for intra-FA HO, default=2", "wmx.reg_req.min_time_for_intra_fa",
				FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_reg_req_tlv_t_45_ms_periodic_ranging_timer,
			{
				"MS periodic ranging timer information", "wmx.reg_req.ms_periodic_ranging_timer_info",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{	/* IPv4 Mask */
			&hf_ms_previous_ip_address_v4,
			{
				"MS Previous IP address", "wmx.reg_req.ms_prev_ip_addr_v4",
				FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{	/* IPv6 Source Address */
			&hf_ms_previous_ip_address_v6,
			{
				"MS Previous IP address", "wmx.reg_req.ms_prev_ip_addr_v6",
				FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_req_secondary_mgmt_cid,
			{
				"Secondary Management CID", "wmx.reg_req.secondary_mgmt_cid",
				FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_req_tlv_t_32_sleep_mode_recovery_time,
			{
				"Frames required for the MS to switch from sleep to awake-mode", "wmx.reg_req.sleep_recovery",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_reg_power_saving_class_type_i,
			{
				"Power saving class type I supported", "wmx.reg.power_saving_class_type_i",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x01, NULL, HFILL
			}
		},
		{
			&hf_reg_power_saving_class_type_ii,
			{
				"Power saving class type II supported", "wmx.reg.power_saving_class_type_ii",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x02, NULL, HFILL
			}
		},
		{
			&hf_reg_power_saving_class_type_iii,
			{
				"Power saving class type III supported", "wmx.reg.power_saving_class_type_iii",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x04, NULL, HFILL
			}
		},
		{
			&hf_reg_multi_active_power_saving_classes,
			{
				"Multiple active power saving classes supported", "wmx.reg.multi_active_power_saving_classes",
				FT_BOOLEAN, 8, TFS(&tfs_supported), 0x08, NULL, HFILL
			}
		},
		{
			&hf_reg_total_power_saving_class_instances,
			{
				"Total number of power saving class instances of all", "wmx.reg_req.total_power_saving_class_instances",
				FT_UINT16, BASE_DEC, NULL, 0x1F0, NULL, HFILL
			}
		},
		{
			&hf_reg_power_saving_class_reserved,
			{
				"Reserved", "wmx.reg.reserved",
				FT_UINT16, BASE_DEC, NULL, 0xFE00, NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_mac_mgmt_msg_reg_req_decoder
		};


	proto_mac_mgmt_msg_reg_req_decoder = proto_register_protocol (
		"WiMax REG-REQ/RSP Messages", /* name       */
		"WiMax REG-REQ/RSP (reg)",    /* short name */
		"wmx.reg"                     /* abbrev     */
		);

	proto_register_field_array(proto_mac_mgmt_msg_reg_req_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

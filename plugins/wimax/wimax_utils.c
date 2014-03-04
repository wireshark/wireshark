/* wimax_utils.c
 * WiMax Utility Decoders
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

/*
#define DEBUG
*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include "wimax_tlv.h"
#include "wimax_mac.h"

#include "wimax_bits.h"
#include "wimax_utils.h"

void proto_register_wimax_utility_decoders(void);

extern gint proto_mac_mgmt_msg_rng_req_decoder;
extern gint proto_mac_mgmt_msg_reg_req_decoder;

extern gint mac_sdu_length;                   /* declared in packet-wmx.c */
extern gboolean include_cor2_changes;

static gint proto_wimax_utility_decoders = -1;
static gint ett_wimax_service_flow_encodings = -1;
static gint ett_wimax_cst_encoding_rules = -1;
static gint ett_wimax_error_parameter_set = -1;
static gint ett_wimax_hmac_tuple = -1;
static gint ett_wimax_cmac_tuple = -1;
static gint ett_wimax_short_hmac_tuple = -1;
static gint ett_security_negotiation_parameters = -1;
static gint ett_pkm_tlv_encoded_attributes_decoder = -1;
static gint ett_sa_descriptor_decoder = -1;
static gint ett_cryptographic_suite_list_decoder = -1;
static gint ett_security_capabilities_decoder = -1;
static gint ett_vendor_specific_info_decoder = -1;
static gint ett_vendor_id_encoding_decoder = -1;
static gint ett_ul_service_flow_decoder = -1;
static gint ett_dl_service_flow_decoder = -1;

static dissector_handle_t eap_handle = NULL;

/* The following two variables save the Scheduling Service type for
   the Grant Management subheader dissector and track whether or not
   one has been seen.
   */
static guint scheduling_service_type = -1;
gint seen_a_service_type = 0;

/* The following two functions set and access the variables above */
guint get_service_type( void )
{
	return scheduling_service_type;
}

void set_service_type( guint set_to )
{
	if( seen_a_service_type == 0 ){
		scheduling_service_type = set_to;
		seen_a_service_type = 1;
	}
}

/* Setup protocol subtree array */
static gint *ett[] =
{
	&ett_wimax_service_flow_encodings,
	&ett_wimax_cst_encoding_rules,
	&ett_wimax_error_parameter_set,
	&ett_wimax_hmac_tuple,
	&ett_wimax_cmac_tuple,
	&ett_wimax_short_hmac_tuple,
	&ett_security_negotiation_parameters,
	&ett_pkm_tlv_encoded_attributes_decoder,
	&ett_sa_descriptor_decoder,
	&ett_cryptographic_suite_list_decoder,
	&ett_security_capabilities_decoder,
	&ett_vendor_specific_info_decoder,
	&ett_vendor_id_encoding_decoder,
	&ett_ul_service_flow_decoder,
	&ett_dl_service_flow_decoder,
};

static const value_string vals_mbs_service[] =
{
	{0, "No available MBS"},
	{1, "Single-BS-MBS"},
	{2, "Multi-BS-MBS"},
	{0,  NULL}
};

static const value_string vals_ul_grant_scheduling[] =
{
	{0, "Reserved"},
	{1, "Undefined (BS implementation-dependent)"},
	{2, "BE (default)"},
	{3, "nrtPS"},
	{4, "rtPS"},
	{5, "Extended rtPS"},
	{6, "UGS"},
	{0,  NULL}
};

static const value_string vals_fixed_len_sdu[] =
{
	{0, "Variable-length SDUs (default)"},
	{1, "Fixed-length SDUs"},
	{0,  NULL}
};

static const value_string vals_arq_enable[] =
{
	{0, "ARQ not requested/accepted"},
	{1, "ARQ requested/accepted"},
	{0,  NULL}
};
#if 0
static const value_string vals_arq_block_lifetime[] =
{
	{0, "Infinite"},
	{0, NULL}
};
#endif
static const value_string vals_arq_sync_loss_timeout[] =
{
	{0, "Infinite"},
	{0, NULL}
};

static const value_string vals_arq_deliver_in_order[] =
{
	{0, "Order of delivery is not preserved"},
	{1, "Order of delivery is preserved"},
	{0,  NULL}
};
static const value_string vals_arq_rx_purge_timeout[] =
{
	{0, "Infinite"},
	{0, NULL}
};

static const value_string vals_fsn_size[] =
{
	{0, "3-bit FSN"},
	{1, "11-bit FSN (default)"},
	{0,  NULL}
};

static const value_string vals_sn_fb_enable[] =
{
	{0, "Is disabled (default)"},
	{1, "Is enabled"},
	{0,  NULL}
};

static const value_string vals_harq[] =
{
	{0, "Non HARQ (default)"},
	{1, "HARQ connection" },
	{0,  NULL}
};

static const value_string vals_cs_specification[] =
{
	{0, "Reserved"},
	{1, "Packet, IPv4"},
	{2, "Packet, IPv6"},
	{3, "Packet, IEEE 802.3/Ethernet"},
	{4, "Packet, IEEE 802.1Q VLAN"},
	{5, "Packet, IPv4 over IEEE 802.3/Ethernet"},
	{6, "Packet, IPv6 over IEEE 802.3/Ethernet"},
	{7, "Packet, IPv4 over IEEE 802.1Q VLAN"},
	{8, "Packet, IPv6 over IEEE 802.1Q VLAN"},
	{9, "ATM"},
	{10, "Packet, IEEE 802.3/Ethernet with ROCH header compression"},
	{11, "Packet, IEEE 802.3/Ethernet with ECRTP header compression"},
	{12, "Packet, IP2 with ROCH header compression"},
	{13, "Packet, IP2 with ECRTP header compression"},
	{0, NULL}
};

static const value_string vals_type_of_data_delivery_services[] =
{
	{0, "Continuing grant service"},
	{1, "Real time variable rate service"},
	{2, "Non-real time variable rate service"},
	{3, "Best-efforts service"},
	{4, "Extended real-time variable rate service"},
	{0,  NULL}
};

static const value_string vals_paging_preference[] =
{
	{0, "No paging generation"},
	{1, "Paging generation"},
	{0,  NULL}
};
static const value_string vals_pdu_sn_ext_subheader[] =
{
	{0, "No support for PDU SN in this connection (default)"},
	{1, "PDU SN (short) extended Subheader"},
	{2, "PDU SN (long) extended Subheader"},
	{0,  NULL}
};

static const value_string vals_cst_classifier_action[] =
{
	{0, "DSC Add Classifier"},
	{1, "DSC Replace Classifier"},
	{2, "DSC Delete Classifier"},
	{0,  NULL}
};

static const value_string vals_cst_phs_dsc_action[] =
{
	{0, "Add PHS rule"},
	{1, "Set PHS rule"},
	{2, "Delete PHS rule"},
	{3, "Delete all PHS rules"},
	{0,  NULL}
};

static const value_string vals_verify[] =
{
	{0, "Verify"},
	{1, "Don't verify"},
	{0,  NULL}
};

static const value_string vals_atm_switching_encodings[] =
{
	{0, "No switching methodology applied"},
	{1, "VP switching"},
	{2, "VC switching"},
	{0,  NULL}
};

static const value_string vals_cc[] =
{
	{0, "OK/success"},
	{1, "Reject-other"},
	{2, "Reject-unrecognized-configuration-setting"},
	{3, "Reject-temporary / reject-resource"},
	{4, "Reject-permanent / reject-admin"},
	{5, "Reject-not-owner"},
	{6, "Reject-service-flow-not-found"},
	{7, "Reject-service-flow-exists"},
	{8, "Reject-required-parameter-not-present"},
	{9, "Reject-header-suppression"},
	{10, "Reject-unknown-transaction-id"},
	{11, "Reject-authentication-failure"},
	{12, "Reject-add-aborted"},
	{13, "Reject-exceeded-dynamic-service-limit"},
	{14, "Reject-not-authorized-for-the-request-SAID"},
	{15, "Reject-fail-to-establish-the-requested-SA"},
	{16, "Reject-not-supported-parameter"},
	{17, "Reject-not-supported-parameter-value"},
	{0,  NULL}
};

static const value_string vals_classification_action_rule[] =
{
	{0, "None"},
	{1, "Discarded packet"},
	{0,  NULL}
};

static const true_false_string tfs_supported =
{
    "supported",
    "not supported"
};

#if 0
static const true_false_string disabled_enabled =
{
	"enabled",
	"disabled"
};
#endif

#if 0
static const true_false_string default_enabled =
{
	"enabled",
	"use default action"
};
#endif

static const value_string vals_pkm_attr_error_codes[] =
{	/* table 373 */
	{0, "All (no information)"},
	{1, "Auth Reject Auth Invalid (unauthorized SS)"},
	{2, "Auth Reject, Key Reject (unauthorized SAID)"},
	{3, "Auth Invalid (unsolicited)"},
	{4, "Auth Invalid, TEK Invalid (invalid key sequence number)"},
	{5, "Auth Invalid (message (key request) authorization failure)"},
	{6, "Auth Reject (permanent authorization failure)"},
	{0,  NULL}
};

static const value_string vs_sa_type[] =
{
	{0, "Primary"},
	{1, "Static"},
	{2, "Dynamic"},
	{0,  NULL}
};

static const value_string va_key_push_modes[] =
{
	{0, "GKEK update mode"},
	{1, "GTEK update mode"},
	{0,  NULL}
};

#if 0
static const value_string vals_pkm_version[] =
{
	{0, "Reserved"},
	{1, "PKM (Initial standard release"},
	{0,  NULL}
};
#endif

static const value_string vs_success_reject[] =
{
	{0, "Success"},
	{1, "Reject"},
	{0,  NULL}
};

static const value_string vs_sa_service_type[] =
{
	{0, "Unicast service"},
	{1, "Group multicast service"},
	{2, "MBS service"},
	{0,  NULL}
};

static const value_string vals_data_encryption_ids[] =
{	/* table 375 */
	{0, "No data encryption"},
	{1, "CBC-Mode, 56-bit DES"},
	{2, "CCM-Mode, 128-bit AES"},
	{3, "CBC-Mode, 128-bit AES"},
	{128, "CTR-Mode, 128-bit AES for MBS with 8 bit ROC"},
	{0,  NULL}
};

static const value_string vals_data_authentication_ids[] =
{	/* table 376 */
	{0, "No data authentication"},
	{1, "CCM-Mode, 128-bit AES"},
	{0,  NULL}
};

static const value_string vals_tek_encryption_ids[] =
{	/* table 377 */
	{0, "No TEK encryption"},
	{1, "3-DES EDE with 128-bit key"},
	{2, "RSA with 1024-bit key"},
	{3, "ECB mode AES with 128-bit key"},
	{4, "AES key wrap with 128-bit key"},
	{0,  NULL}
};

static const value_string vals_dcd_mac_version[] =
{
    {1, "Conformance with IEEE Std 802.16-2001"},
    {2, "Conformance with IEEE Std 802.16c-2002 and its predecessors"},
    {3, "Conformance with IEEE Std 802.16a-2003 and its predecessors"},
    {4, "Conformance with IEEE Std 802.16-2004"},
    {5, "Conformance with IEEE Std 802.16-2004 and IEEE Std 802.16e-2005"},
    {6, "reserved"},
    {0, NULL}
};

/* fix fields */
static gint hf_sfe_unknown_type = -1;
static gint hf_sfe_sf_id = -1;
static gint hf_sfe_cid = -1;
static gint hf_sfe_service_class_name = -1;
static gint hf_sfe_mbs_service = -1;
static gint hf_sfe_qos_params_set = -1;
static gint hf_sfe_set_provisioned = -1;
static gint hf_sfe_set_admitted = -1;
static gint hf_sfe_set_active = -1;
static gint hf_sfe_set_rsvd = -1;
static gint hf_sfe_traffic_priority = -1;
static gint hf_sfe_max_str = -1;
static gint hf_sfe_max_traffic_burst = -1;
static gint hf_sfe_min_rtr = -1;
static gint hf_sfe_reserved_10 = -1;
static gint hf_sfe_ul_grant_scheduling = -1;
static gint hf_sfe_req_tx_policy = -1;
static gint hf_sfe_policy_broadcast_bwr = -1;
static gint hf_sfe_policy_multicast_bwr = -1;
static gint hf_sfe_policy_piggyback = -1;
static gint hf_sfe_policy_fragment = -1;
static gint hf_sfe_policy_headers = -1;
static gint hf_sfe_policy_packing = -1;
static gint hf_sfe_policy_crc = -1;
static gint hf_sfe_policy_rsvd1 = -1;
static gint hf_sfe_jitter = -1;
static gint hf_sfe_max_latency = -1;
static gint hf_sfe_fixed_len_sdu = -1;
static gint hf_sfe_sdu_size = -1;
static gint hf_sfe_target_said = -1;
static gint hf_sfe_cs_specification = -1;
static gint hf_sfe_type_of_data_delivery_services = -1;
static gint hf_sfe_sdu_inter_arrival_interval = -1;
static gint hf_sfe_time_base = -1;
static gint hf_sfe_paging_preference = -1;
static gint hf_sfe_mbs_zone_identifier_assignment = -1;
static gint hf_sfe_sn_feedback_enabled = -1;
static gint hf_sfe_harq_service_flows = -1;
static gint hf_sfe_harq_channel_mapping_index = -1;
static gint hf_sfe_fsn_size = -1;
static gint hf_sfe_unsolicited_grant_interval = -1;
static gint hf_sfe_unsolicited_polling_interval = -1;
/* static gint hf_sfe_harq_channel_mapping = -1; */
static gint hf_sfe_global_service_class_name = -1;
static gint hf_sfe_reserved_36 = -1;
static gint hf_sfe_reserved_34 = -1;

static gint hf_sfe_arq_enable = -1;
static gint hf_sfe_arq_transmitter_delay = -1;
static gint hf_sfe_arq_receiver_delay = -1;
static gint hf_sfe_arq_block_lifetime = -1;
static gint hf_sfe_arq_sync_loss_timeout = -1;
static gint hf_sfe_arq_transmitter_delay_cor2 = -1;
static gint hf_sfe_arq_receiver_delay_cor2 = -1;
static gint hf_sfe_arq_block_lifetime_cor2 = -1;
static gint hf_sfe_arq_sync_loss_timeout_cor2 = -1;
static gint hf_sfe_arq_deliver_in_order = -1;
static gint hf_sfe_arq_rx_purge_timeout = -1;
static gint hf_sfe_arq_window_size = -1;
static gint hf_sfe_arq_block_size = -1;
static gint hf_sfe_arq_block_size_cor2 = -1;
static gint hf_sfe_arq_min_block_size = -1;
static gint hf_sfe_arq_max_block_size = -1;

/* static gint hf_sfe_cid_alloc_for_active_bs = -1; */
static gint hf_sfe_cid_alloc_for_active_bs_cid = -1;
static gint hf_sfe_pdu_sn_ext_subheader_reorder = -1;
static gint hf_sfe_mbs_contents_ids = -1;
static gint hf_sfe_mbs_contents_ids_id = -1;
static gint hf_sfe_authorization_token = -1;

static gint hf_cst_classifier_dsc_action = -1;
static gint hf_cst_error_set_errored_param = -1;
static gint hf_cst_error_set_error_code = -1;
static gint hf_cst_error_set_error_msg = -1;

static gint hf_cst_pkt_class_rule = -1;

static gint hf_cst_pkt_class_rule_priority = -1;
static gint hf_cst_pkt_class_rule_range_mask = -1;
static gint hf_cst_pkt_class_rule_tos_low = -1;
static gint hf_cst_pkt_class_rule_tos_high = -1;
static gint hf_cst_pkt_class_rule_tos_mask = -1;
static gint hf_cst_pkt_class_rule_protocol = -1;
/*static gint hf_cst_pkt_class_rule_protocol_number = -1;*/
static gint hf_cst_pkt_class_rule_ip_masked_src_address = -1;
static gint hf_cst_pkt_class_rule_ip_masked_dest_address = -1;
static gint hf_cst_pkt_class_rule_src_ipv4 = -1;
static gint hf_cst_pkt_class_rule_dest_ipv4 = -1;
static gint hf_cst_pkt_class_rule_mask_ipv4 = -1;
static gint hf_cst_pkt_class_rule_src_ipv6 = -1;
static gint hf_cst_pkt_class_rule_dest_ipv6 = -1;
static gint hf_cst_pkt_class_rule_mask_ipv6 = -1;
static gint hf_cst_pkt_class_rule_prot_src_port_range = -1;
static gint hf_cst_pkt_class_rule_src_port_low = -1;
static gint hf_cst_pkt_class_rule_src_port_high = -1;
static gint hf_cst_pkt_class_rule_prot_dest_port_range = -1;
static gint hf_cst_pkt_class_rule_dest_port_low = -1;
static gint hf_cst_pkt_class_rule_dest_port_high = -1;
static gint hf_cst_pkt_class_rule_dest_mac_address = -1;
static gint hf_cst_pkt_class_rule_dest_mac = -1;
static gint hf_cst_pkt_class_rule_src_mac_address = -1;
static gint hf_cst_pkt_class_rule_src_mac = -1;
static gint hf_cst_pkt_class_rule_mask_mac = -1;
static gint hf_cst_pkt_class_rule_ethertype = -1;
static gint hf_cst_pkt_class_rule_etype = -1;
static gint hf_cst_pkt_class_rule_eprot1 = -1;
static gint hf_cst_pkt_class_rule_eprot2 = -1;
static gint hf_cst_pkt_class_rule_user_priority          = -1;
static gint hf_cst_pkt_class_rule_pri_low                = -1;
static gint hf_cst_pkt_class_rule_pri_high               = -1;
static gint hf_cst_pkt_class_rule_vlan_id                = -1;
static gint hf_cst_pkt_class_rule_vlan_id1               = -1;
static gint hf_cst_pkt_class_rule_vlan_id2               = -1;
static gint hf_cst_pkt_class_rule_phsi                   = -1;
static gint hf_cst_pkt_class_rule_index                  = -1;
static gint hf_cst_pkt_class_rule_ipv6_flow_label        = -1;
static gint hf_cst_pkt_class_rule_vendor_spec            = -1;
static gint hf_cst_pkt_class_rule_classifier_action_rule = -1;
static gint hf_cst_pkt_class_rule_classifier_action_rule_bit0 = -1;
static gint hf_cst_pkt_class_rule_classifier_action_rule_bit1 = -1;

static gint hf_cst_large_context_id = -1;
static gint hf_cst_short_format_context_id = -1;

static gint hf_cst_phs_dsc_action = -1;
static gint hf_cst_phs_rule = -1;
static gint hf_cst_phs_phsi = -1;
static gint hf_cst_phs_phsf = -1;
static gint hf_cst_phs_phsm = -1;
static gint hf_cst_phs_phss = -1;
static gint hf_cst_phs_phsv = -1;
static gint hf_cst_phs_vendor_spec = -1;
static gint hf_cst_invalid_tlv = -1;

static gint hf_csper_atm_switching_encoding = -1;
static gint hf_csper_atm_classifier = -1;
static gint hf_csper_atm_classifier_vpi = -1;
static gint hf_csper_atm_classifier_vci = -1;
static gint hf_csper_atm_classifier_id = -1;
/*static gint hf_csper_atm_classifier_dsc_action = -1;*/
static gint hf_csper_unknown_type = -1;

static gint hf_xmac_tuple_rsvd = -1;
static gint hf_xmac_tuple_key_seq_num = -1;
static gint hf_hmac_tuple_hmac_digest = -1;
static gint hf_packet_number_counter = -1;
static gint hf_cmac_tuple_cmac_value = -1;
static gint hf_cmac_tuple_bsid = -1;

/* bit masks */
/* 11.13.4 */
#define SFE_QOS_PARAMS_SET_PROVISIONED_SET 0x01
#define SFE_QOS_PARAMS_SET_ADMITTED_SET    0x02
#define SFE_QOS_PARAMS_SET_ACTIVE_SET      0x04
#define SFE_QOS_PARAMS_SET_RESERVED        0xF8
/* 11.13.12 */
#define SFE_REQ_TX_POLICY_BROADCAST_BWR    0x01
#define SFE_REQ_TX_POLICY_MULTICAST_BWR    0x02
#define SFE_REQ_TX_POLICY_PIGGYBACK        0x04
#define SFE_REQ_TX_POLICY_FRAGMENT_DATA    0x08
#define SFE_REQ_TX_POLICY_PAYLOAD_HEADER   0x10
#define SFE_REQ_TX_POLICY_PACKINGS         0x20
#define SFE_REQ_TX_POLICY_CRC              0x40
#define SFE_REQ_TX_POLICY_RESERVED         0x80

/* bit masks */
/* 11.13.19.3.4.17 */
#define CST_PKT_CLASS_RULE_CLASSIFIER_ACTION_RULE_BIT0 0x80
#define CST_PKT_CLASS_RULE_CLASSIFIER_ACTION_RULE_RSV  0x7F

/* bit masks */
/* 11.1.2 (table 348) */
#define XMAC_TUPLE_RESERVED        0xF0
#define XMAC_TUPLE_KEY_SEQ_NUM     0x0F

/* WiMax Security Negotiation Parameters display */
static gint hf_snp_pkm_version_support = -1;
static gint hf_snp_pkm_version_support_bit0 = -1;
static gint hf_snp_pkm_version_support_bit1 = -1;
static gint hf_snp_pkm_version_support_reserved = -1;
static gint hf_snp_auth_policy_support = -1;
static gint hf_snp_auth_policy_support_bit0 = -1;
static gint hf_snp_auth_policy_support_bit1 = -1;
static gint hf_snp_auth_policy_support_bit2 = -1;
static gint hf_snp_auth_policy_support_bit3 = -1;
static gint hf_snp_auth_policy_support_bit4 = -1;
static gint hf_snp_auth_policy_support_bit5 = -1;
static gint hf_snp_auth_policy_support_bit6 = -1;
static gint hf_snp_auth_policy_support_bit7 = -1;
static gint hf_snp_mac_mode = -1;
static gint hf_snp_mac_mode_bit0 = -1;
static gint hf_snp_mac_mode_bit1 = -1;
static gint hf_snp_mac_mode_bit1_rsvd = -1;
static gint hf_snp_mac_mode_bit2 = -1;
static gint hf_snp_mac_mode_bit3 = -1;
static gint hf_snp_mac_mode_bit4 = -1;
static gint hf_snp_mac_mode_bit5 = -1;
static gint hf_snp_mac_mode_reserved = -1;
static gint hf_snp_mac_mode_reserved1 = -1;
static gint hf_snp_pn_window_size = -1;
static gint hf_snp_max_conc_transactions = -1;
static gint hf_snp_max_suppt_sec_assns = -1;
static gint hf_snp_unknown_type = -1;

/* bit masks */
/* 11.8.4.1 */
#define SNP_PKM_VERSION_SUPPORT_BIT0 0x01
#define SNP_PKM_VERSION_SUPPORT_BIT1 0x02
#define SNP_PKM_VERSION_SUPPORT_RSV  0xFC
/* 11.8.4.2 */
#define SNP_AUTH_POLICY_SUPPORT_BIT0 0x01
#define SNP_AUTH_POLICY_SUPPORT_BIT1 0x02
#define SNP_AUTH_POLICY_SUPPORT_BIT2 0x04
#define SNP_AUTH_POLICY_SUPPORT_BIT3 0x08
#define SNP_AUTH_POLICY_SUPPORT_BIT4 0x10
#define SNP_AUTH_POLICY_SUPPORT_BIT5 0x20
#define SNP_AUTH_POLICY_SUPPORT_BIT6 0x40
#define SNP_AUTH_POLICY_SUPPORT_BIT7 0x80
/* 11.8.4.3 */
#define SNP_MAC_MODE_BIT0 0x01
#define SNP_MAC_MODE_BIT1 0x02
#define SNP_MAC_MODE_BIT2 0x04
#define SNP_MAC_MODE_BIT3 0x08
#define SNP_MAC_MODE_BIT4 0x10
#define SNP_MAC_MODE_BIT5 0x20
#define SNP_MAC_MODE_RSV  0xE0
#define SNP_MAC_MODE_RSV1 0xC0

/* PKM display */
static gint hf_pkm_msg_unknown_type = -1;
static gint hf_pkm_msg_attr_display = -1;
static gint hf_pkm_config_settings_authorize_waitout = -1;
static gint hf_pkm_config_settings_reauthorize_waitout = -1;
static gint hf_pkm_config_settings_grace_time = -1;
static gint hf_pkm_config_settings_operational_waittime = -1;
static gint hf_pkm_msg_attr_auth_key = -1;
static gint hf_pkm_msg_attr_tek = -1;
static gint hf_pkm_msg_attr_key_life_time = -1;
static gint hf_pkm_msg_attr_key_seq_num = -1;
static gint hf_pkm_msg_attr_hmac_digest = -1;
static gint hf_pkm_msg_attr_said = -1;
static gint hf_pkm_msg_attr_cbc_iv = -1;
static gint hf_pkm_msg_attr_error_code = -1;
static gint hf_pkm_msg_attr_ca_certificate = -1;
static gint hf_pkm_msg_attr_ss_certificate = -1;
static gint hf_pkm_attr_auth_result_code = -1;
static gint hf_pkm_attr_sa_service_type = -1;
static gint hf_pkm_attr_frame_number = -1;
static gint hf_pkm_attr_ss_random = -1;
static gint hf_pkm_attr_bs_random = -1;
static gint hf_pkm_attr_pre_pak = -1;
static gint hf_pkm_attr_bs_certificate = -1;
static gint hf_pkm_attr_sig_bs = -1;
static gint hf_pkm_attr_ms_mac_address = -1;
static gint hf_pkm_attr_cmac_digest = -1;
static gint hf_pkm_attr_cmac_digest_pn = -1;
static gint hf_pkm_attr_cmac_digest_value = -1;
static gint hf_pkm_attr_eap_payload = -1;
static gint hf_pkm_attr_nonce = -1;
static gint hf_pkm_sa_type = -1;
static gint hf_pkm_msg_crypto_suite = -1;
static gint hf_pkm_msg_crypto_suite_msb = -1;
static gint hf_pkm_msg_crypto_suite_middle = -1;
static gint hf_pkm_msg_crypto_suite_lsb = -1;
/*static gint hf_pkm_msg_version = -1;*/
static gint hf_pkm_attr_push_modes = -1;
static gint hf_pkm_attr_key_push_counter = -1;
static gint hf_pkm_attr_gkek = -1;
static gint hf_pkm_attr_sig_ss = -1;
static gint hf_pkm_attr_akid = -1;
static gint hf_pkm_config_settings_rekey_wait_timeout = -1;
static gint hf_pkm_config_settings_tek_grace_time = -1;
static gint hf_pkm_config_settings_authorize_reject_wait_timeout = -1;

/* static gint hf_pkm_attr_pak_ak_seq_number = -1; */
static gint hf_pkm_attr_associated_gkek_seq_number = -1;
/* static gint hf_pkm_attr_gkek_params = -1; */

/* static gint hf_common_tlv_unknown_type = -1; */
static gint hf_common_tlv_mac_version = -1;
static gint hf_common_tlv_vendor_id = -1;
static gint hf_common_tlv_vendor_specific_type = -1;
static gint hf_common_tlv_vendor_specific_length = -1;
static gint hf_common_tlv_vendor_specific_length_size = -1;
static gint hf_common_tlv_vendor_specific_value = -1;
static gint hf_common_current_transmitted_power = -1;

/* Register WiMax Utility Routines */
void proto_register_wimax_utility_decoders(void)
{
	/* WiMax Service Flow Encodings display */
	static hf_register_info hf_sfe[] =
	{
		{	/* 1 Service Flow ID */
			&hf_sfe_sf_id,
			{"Service Flow ID", "wmx.sfe.sf_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 2 CID */
			&hf_sfe_cid,
			{"CID", "wmx.sfe.cid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 3 Service Class Name */
			&hf_sfe_service_class_name,
			{"Service Class Name", "wmx.sfe.service_class_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 4 MBS Service */
			&hf_sfe_mbs_service,
			{"MBS Service", "wmx.sfe.mbs_service", FT_UINT8, BASE_DEC, VALS(vals_mbs_service), 0x0, NULL, HFILL}
		},
		{	/* 5 QoS Parameter Set Type */
			&hf_sfe_qos_params_set,
			{"QoS Parameter Set Type", "wmx.sfe.qos_params_set", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 5.1 */
			&hf_sfe_set_provisioned,
			{"Provisioned Set", "wmx.sfe.qos_params_set.provisioned", FT_BOOLEAN, 8, NULL, SFE_QOS_PARAMS_SET_PROVISIONED_SET, NULL, HFILL}
		},
		{	/* 5.2 */
			&hf_sfe_set_admitted,
			{"Admitted Set", "wmx.sfe.qos_params_set.admitted", FT_BOOLEAN, 8, NULL, SFE_QOS_PARAMS_SET_ADMITTED_SET, NULL, HFILL}
		},
		{	/* 5.3 */
			&hf_sfe_set_active,
			{"Active Set", "wmx.sfe.qos_params_set.active", FT_BOOLEAN, 8, NULL, SFE_QOS_PARAMS_SET_ACTIVE_SET, NULL, HFILL}
		},
		{	/* 5.4 */
			&hf_sfe_set_rsvd,
			{"Reserved", "wmx.sfe.qos_params_set.rsvd", FT_UINT8, BASE_HEX, NULL, SFE_QOS_PARAMS_SET_RESERVED, NULL, HFILL}
		},
		{	/* 6 Traffic Priority */
			&hf_sfe_traffic_priority,
			{"Traffic Priority", "wmx.sfe.traffic_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 7 Maximum Sustained Traffic Rate */
			&hf_sfe_max_str,
			{"Maximum Sustained Traffic Rate", "wmx.sfe.msr", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 8 Maximum Traffic Burst */
			&hf_sfe_max_traffic_burst,
			{"Maximum Traffic Burst", "wmx.sfe.max_traffic_burst", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 9 Minimum Reserved Traffic Rate */
			&hf_sfe_min_rtr,
			{"Minimum Reserved Traffic Rate", "wmx.sfe.mrr", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			/* 10 Reserved */
			&hf_sfe_reserved_10,
			{"Reserved", "wmx.sfe.reserved_10", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
#if 0
		{	/* 10 reserved by 16E */
			&hf_sfe_mtr,
			{"Minimum tolerable traffic rate", "wmx.sfe.mtr", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11 Service Flow Scheduling Type */
			&hf_sfe_ul_grant_scheduling,
			{"Uplink Grant Scheduling Type", "wmx.sfe.uplink_grant_scheduling", FT_UINT8, BASE_DEC, VALS(vals_ul_grant_scheduling), 0x0, NULL, HFILL}
		},
		{	/* 12 Request/Transmission Policy */
			&hf_sfe_req_tx_policy,
			{"Request/Transmission Policy", "wmx.sfe.req_tx_policy", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 12.1 */
			&hf_sfe_policy_broadcast_bwr,
			{"The Service Flow Shall Not Use Broadcast Bandwidth Request Opportunities", "wmx.sfe.policy.broadcast_bwr", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_BROADCAST_BWR, NULL, HFILL}
		},
		{	/* 12.2 */
			&hf_sfe_policy_multicast_bwr,
			{"The Service Flow Shall Not Use Multicast Bandwidth Request Opportunities", "wmx.sfe.policy.bit1", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_MULTICAST_BWR, NULL, HFILL}
		},
		{	/* 12.3 */
			&hf_sfe_policy_piggyback,
			{"The Service Flow Shall Not Piggyback Requests With Data", "wmx.sfe.policy.piggyback", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_PIGGYBACK, NULL, HFILL}
		},
		{	/* 12.4 */
			&hf_sfe_policy_fragment,
			{"The Service Flow Shall Not Fragment Data", "wmx.sfe.policy.fragment", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_FRAGMENT_DATA, NULL, HFILL}
		},
		{	/* 12.5 */
			&hf_sfe_policy_headers,
			{"The Service Flow Shall Not Suppress Payload Headers", "wmx.sfe.policy.headers", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_PAYLOAD_HEADER, NULL, HFILL}
		},
		{	/* 12.6 */
			&hf_sfe_policy_packing,
			{"The Service Flow Shall Not Pack Multiple SDUs (Or Fragments) Into Single MAC PDUs", "wmx.sfe.policy.packing", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_PACKINGS, NULL, HFILL}
		},
		{	/* 12.7 */
			&hf_sfe_policy_crc,
			{"The Service Flow Shall Not Include CRC In The MAC PDU", "wmx.sfe.policy.crc", FT_BOOLEAN, 8, NULL, SFE_REQ_TX_POLICY_CRC, NULL, HFILL}
		},
		{	/* 12.8 */
			&hf_sfe_policy_rsvd1,
			{"Reserved", "wmx.sfe.policy.rsvd1", FT_UINT8, BASE_HEX, NULL, SFE_REQ_TX_POLICY_RESERVED, NULL, HFILL}
		},
		{	/* 13 Tolerated Jitter */
			&hf_sfe_jitter,
			{"Tolerated Jitter", "wmx.sfe.jitter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 14 Maximum Latency */
			&hf_sfe_max_latency,
			{"Maximum Latency", "wmx.sfe.max_latency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 15 Fixed/Variable Length SDU */
			&hf_sfe_fixed_len_sdu,
			{"Fixed/Variable Length SDU", "wmx.sfe.fixed_len_sdu", FT_UINT8, BASE_DEC, VALS(vals_fixed_len_sdu), 0x0, NULL, HFILL}
		},
		{	/* 16 SDU Size */
			&hf_sfe_sdu_size,
			{"SDU Size", "wmx.sfe.sdu_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 17 SAID Onto Which SF Is Mapped */
			&hf_sfe_target_said,
			{"SAID Onto Which SF Is Mapped", "wmx.sfe.target_said", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 18 ARQ Enable */
			&hf_sfe_arq_enable,
			{"ARQ Enable", "wmx.arq.enable", FT_UINT8, BASE_DEC, VALS(vals_arq_enable), 0x0, NULL, HFILL}
		},
		{	/* 19 ARQ Window Size */
			&hf_sfe_arq_window_size,
			{"ARQ Window Size", "wmx.arq.window_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 20 ARQ Transmitter Delay */
			&hf_sfe_arq_transmitter_delay,
			{"ARQ Transmitter Delay (10us granularity)", "wmx.arq.transmitter_delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 21 ARQ Receiver Delay */
			&hf_sfe_arq_receiver_delay,
			{"ARQ Receiver Delay (10us granularity)", "wmx.arq.receiver_delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 22 ARQ Block Lifetime */
			&hf_sfe_arq_block_lifetime,
			{"ARQ Block Lifetime (10us granularity)", "wmx.arq.block_lifetime", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 23 ARQ Sync Loss Timeout */
			&hf_sfe_arq_sync_loss_timeout,
			{"ARQ Sync Loss Timeout (10us granularity)", "wmx.arq.sync_loss_timeout", FT_UINT16, BASE_DEC, VALS(vals_arq_sync_loss_timeout), 0x0, NULL, HFILL}
		},
		{	/* 20 ARQ Transmitter Delay */
			&hf_sfe_arq_transmitter_delay_cor2,
			{"ARQ Transmitter Delay (100us granularity)", "wmx.arq.transmitter_delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 21 ARQ Receiver Delay */
			&hf_sfe_arq_receiver_delay_cor2,
			{"ARQ Receiver Delay (100us granularity)", "wmx.arq.receiver_delay", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 22 ARQ Block Lifetime */
			&hf_sfe_arq_block_lifetime_cor2,
			{"ARQ Block Lifetime (100us granularity)", "wmx.arq.block_lifetime", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 23 ARQ Sync Loss Timeout */
			&hf_sfe_arq_sync_loss_timeout_cor2,
			{"ARQ Sync Loss Timeout (100us granularity)", "wmx.arq.sync_loss_timeout", FT_UINT16, BASE_DEC, VALS(vals_arq_sync_loss_timeout), 0x0, NULL, HFILL}
		},
		{	/* 24 ARQ Deliver In Order */
			&hf_sfe_arq_deliver_in_order,
			{"ARQ Deliver In Order", "wmx.arq.deliver_in_order", FT_UINT8, BASE_DEC, VALS(vals_arq_deliver_in_order), 0x0, NULL, HFILL}
		},
		{	/* 25 ARQ Purge Timeout */
			&hf_sfe_arq_rx_purge_timeout,
			{"ARQ RX Purge Timeout (100us granularity)", "wmx.arq.rx_purge_timeout", FT_UINT16, BASE_DEC, VALS(vals_arq_rx_purge_timeout), 0x0, NULL, HFILL}
		},
		{	/* 26 ARQ Block Size */
			&hf_sfe_arq_block_size,
			{"ARQ Block Size", "wmx.arq.block_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 26 ARQ Block Size */
			&hf_sfe_arq_block_size_cor2,
			{"ARQ Block Size", "wmx.arq.block_size", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 26 ARQ Block Size for Corrigendum 2 */
			&hf_sfe_arq_min_block_size,
			{"ARQ Minimum Block Size", "wmx.arq.min_block_size", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
		},
		{	/* 26 ARQ Block Size for Corrigendum 2 */
			&hf_sfe_arq_max_block_size,
			{"ARQ Maximum Block Size", "wmx.arq.max_block_size", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
		},
	/* 27 reserved */
		{	/* 28 CS Specification */
			&hf_sfe_cs_specification,
			{"CS Specification", "wmx.sfe.cs_specification", FT_UINT8, BASE_DEC, VALS(vals_cs_specification), 0x0, NULL, HFILL}
		},
			{	/* 29 Type of Data Delivery Services */
			&hf_sfe_type_of_data_delivery_services,
			{"Type of Data Delivery Services", "wmx.sfe.type_of_data_delivery_services", FT_UINT8, BASE_DEC, VALS(vals_type_of_data_delivery_services), 0x0, NULL, HFILL}
		},
			{	/* 30 SDU Inter-Arrival Interval */
			&hf_sfe_sdu_inter_arrival_interval,
			{"SDU Inter-Arrival Interval (in the resolution of 0.5 ms)", "wmx.sfe.sdu_inter_arrival_interval", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 31 Time Base */
			&hf_sfe_time_base,
			{"Time Base", "wmx.sfe.time_base", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 32 Paging Preference */
			&hf_sfe_paging_preference,
			{"Paging Preference", "wmx.sfe.paging_preference", FT_UINT8, BASE_DEC, VALS(vals_paging_preference), 0x0, NULL, HFILL}
		},
			{	/* 33 MBS Zone Identifier */
			&hf_sfe_mbs_zone_identifier_assignment,
			{"MBS Zone Identifier", "wmx.sfe.mbs_zone_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
			{	/* 34 Traffic Indication Preference */
			&hf_sfe_reserved_34,
			{"Reserved", "wmx.sfe.reserved_34", FT_UINT8, BASE_DEC, NULL /*VALS(vals_traffic_indication_preference)*/, 0x0, NULL, HFILL}
		},
		{	/* 35 Global Service Class Name */
			&hf_sfe_global_service_class_name,
			{"Global Service Class Name", "wmx.sfe.global_service_class_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
	/* 36 reserved by 16E */
			/* 36 Reserved */
		{
			&hf_sfe_reserved_36,
			{"Reserved", "wmx.sfe.reserved_36", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 37 SN Feedback Enable */
			&hf_sfe_sn_feedback_enabled,
			{"SN Feedback", "wmx.sfe.sn_feedback_enabled", FT_UINT8, BASE_DEC, VALS(vals_sn_fb_enable), 0x0, NULL, HFILL}
		},
		{	/* 38 FSN Size */
			&hf_sfe_fsn_size,
			{"FSN Size", "wmx.sfe.fsn_size", FT_UINT8, BASE_DEC, VALS(vals_fsn_size), 0x0, NULL, HFILL}
		},
#if 0
		{	/* 39 CID allocation for Active BSs */
			&hf_sfe_cid_alloc_for_active_bs,
			{"CID Allocation For Active BSs", "wmx.sfe.cid_alloc_for_active_bs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
		{	/* 39.1 */
			&hf_sfe_cid_alloc_for_active_bs_cid,
			{"CID", "wmx.sfe.cid_alloc_for_active_bs_cid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 40 Unsolicited Grant Interval */
			&hf_sfe_unsolicited_grant_interval,
			{"Unsolicited Grant Interval", "wmx.sfe.unsolicited_grant_interval", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 41 Unsolicited Polling Interval */
			&hf_sfe_unsolicited_polling_interval,
			{"Unsolicited Polling Interval", "wmx.sfe.unsolicited_polling_interval", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 42 PDU SN extended subheader for HARQ reordering */
			&hf_sfe_pdu_sn_ext_subheader_reorder,
			{"PDU SN Extended Subheader For HARQ Reordering", "wmx.sfe.pdu_sn_ext_subheader_reorder", FT_UINT8, BASE_DEC, VALS(vals_pdu_sn_ext_subheader), 0x0, NULL, HFILL}
		},
		{	/* 43 MBS contents ID */
			&hf_sfe_mbs_contents_ids,
			{"MBS contents IDs", "wmx.sfe.mbs_contents_ids", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 43.1 */
			&hf_sfe_mbs_contents_ids_id,
			{"MBS Contents ID", "wmx.sfe.mbs_contents_ids_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
			{	/* 44 HARQ Service Flows */
			&hf_sfe_harq_service_flows,
			{"HARQ Service Flows", "wmx.sfe.harq_service_flows", FT_UINT8, BASE_DEC, VALS(vals_harq), 0x0, NULL, HFILL}
		},
		{	/* 45 Authorization Token */
			&hf_sfe_authorization_token,
			{"Authorization Token", "wmx.sfe.authorization_token", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#if 0
			{	/* 46 HARQ Channel Mapping */
			&hf_sfe_harq_channel_mapping,
			{"HARQ Channel Mapping", "wmx.sfe.harq_channel_mapping", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
			{	/* 46.1 HARQ Channel Index*/
			&hf_sfe_harq_channel_mapping_index,
			{"HARQ Channel Index", "wmx.sfe.harq_channel_mapping.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
	/* unknown types */
		{	/* unknown SFE types */
			&hf_sfe_unknown_type,
			{"Unknown SFE TLV type", "wmx.sfe.unknown_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	/* WiMax Convergence Service Parameter Encoding Rules display */
	static hf_register_info hf_csper[] =
	{	/* 99 - 111 CS parameter encoding rules */
		{	/* Classifier DSC Action */
			&hf_cst_classifier_dsc_action,
			{"Classifier DSC Action", "wmx.cst.classifier_action", FT_UINT8, BASE_DEC, VALS(vals_cst_classifier_action), 0x0, NULL, HFILL}
		},
		{	/* Errored Parameter */
			&hf_cst_error_set_errored_param,
			{"Errored Parameter", "wmx.cst.error_set.errored_param", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Error Code */
			&hf_cst_error_set_error_code,
			{"Error Code", "wmx.cst.error_set.error_code", FT_UINT8, BASE_HEX, VALS(vals_cc), 0x0, NULL, HFILL}
		},
		{	/* Error Message */
			&hf_cst_error_set_error_msg,
			{"Error Message", "wmx.cst.error_set.error_msg", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Packet Classification Rule */
			&hf_cst_pkt_class_rule,
			{"Packet Classification Rule", "wmx.cst.pkt_class_rule", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Classification Rule Priority */
			&hf_cst_pkt_class_rule_priority,
			{"Classification Rule Priority", "wmx.cst.pkt_class_rule.priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* ToS/Differentiated Services Codepoint (DSCP) Range And Mask */
			&hf_cst_pkt_class_rule_range_mask,
			{"ToS/Differentiated Services Codepoint (DSCP) Range And Mask", "wmx.cst.pkt_class_rule.range_mask", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* ToS-Low */
			&hf_cst_pkt_class_rule_tos_low,
			{"ToS-Low", "wmx.cst.pkt_class_rule.tos-low", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* ToS-High */
			&hf_cst_pkt_class_rule_tos_high,
			{"ToS-High", "wmx.cst.pkt_class_rule.tos-high", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* ToS-Mask */
			&hf_cst_pkt_class_rule_tos_mask,
			{"ToS-Mask", "wmx.cst.pkt_class_rule.tos-mask", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* Protocol */
			&hf_cst_pkt_class_rule_protocol,
			{"Protocol", "wmx.cst.pkt_class_rule.protocol", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
#if 0 /* Removed by the changes of 802.16E 2005 */
		{	/* Protocol */
			&hf_cst_pkt_class_rule_protocol,
			{"Protocol", "wmx.cst.pkt_class_rule.protocol", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
		{	/* Protocol Number */
			&hf_cst_pkt_class_rule_protocol_number,
			{"Protocol Number", "wmx.cst.pkt_class_rule.protocol.number", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* IP Masked Source Address */
			&hf_cst_pkt_class_rule_ip_masked_src_address,
			{"IP Masked Source Address", "wmx.cst.pkt_class_rule.ip_masked_src_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IP Masked Destination Address */
			&hf_cst_pkt_class_rule_ip_masked_dest_address,
			{"IP Masked Destination Address", "wmx.cst.pkt_class_rule.ip_masked_dest_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv4 Source Address */
			&hf_cst_pkt_class_rule_src_ipv4,
			{"IPv4 Source Address", "wmx.cst.pkt_class_rule.src_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv4 Destination Address */
			&hf_cst_pkt_class_rule_dest_ipv4,
			{"IPv4 Destination Address", "wmx.cst.pkt_class_rule.dst_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv4 Mask */
			&hf_cst_pkt_class_rule_mask_ipv4,
			{"IPv4 Mask", "wmx.cst.pkt_class_rule.mask_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv6 Source Address */
			&hf_cst_pkt_class_rule_src_ipv6,
			{"IPv6 Source Address", "wmx.cst.pkt_class_rule.src_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv6 Destination Address */
			&hf_cst_pkt_class_rule_dest_ipv6,
			{"IPv6 Destination Address", "wmx.cst.pkt_class_rule.dst_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv6 Mask */
			&hf_cst_pkt_class_rule_mask_ipv6,
			{"IPv6 Mask", "wmx.cst.pkt_class_rule.mask_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Protocol Source Port Range */
			&hf_cst_pkt_class_rule_prot_src_port_range,
			{"Protocol Source Port Range", "wmx.cst.pkt_class_rule.prot_src_port_range", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Src-Port Low */
			&hf_cst_pkt_class_rule_src_port_low,
			{"Src-Port Low", "wmx.cst.pkt_class_rule.src_port_low", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Src-Port High */
			&hf_cst_pkt_class_rule_src_port_high,
			{"Src-Port High", "wmx.cst.pkt_class_rule.src_port_high", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Protocol Destination Port Range */
			&hf_cst_pkt_class_rule_prot_dest_port_range,
			{"Protocol Destination Port Range", "wmx.cst.pkt_class_rule.prot_dest_port_range", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Dst-Port Low */
			&hf_cst_pkt_class_rule_dest_port_low,
			{"Dst-Port Low", "wmx.cst.pkt_class_rule.dst_port_low", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Dst-Port High */
			&hf_cst_pkt_class_rule_dest_port_high,
			{"Dst-Port High", "wmx.cst.pkt_class_rule.dst_port_high", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 802.3/Ethernet Destination MAC Address */
			&hf_cst_pkt_class_rule_dest_mac_address,
			{"802.3/Ethernet Destination MAC Address", "wmx.cst.pkt_class_rule.dest_mac_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Destination MAC Address */
			&hf_cst_pkt_class_rule_dest_mac,
			{"Destination MAC Address", "wmx.cst.pkt_class_rule.dst_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 802.3/Ethernet Source MAC Address */
			&hf_cst_pkt_class_rule_src_mac_address,
			{"802.3/Ethernet Source MAC Address", "wmx.cst.pkt_class_rule.src_mac_address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Source MAC Address */
			&hf_cst_pkt_class_rule_src_mac,
			{"Source MAC Address", "wmx.cst.pkt_class_rule.src_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* MAC Address Mask */
			&hf_cst_pkt_class_rule_mask_mac,
			{"MAC Address Mask", "wmx.cst.pkt_class_rule.mask_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Ethertype/IEEE Std 802.2-1998 SAP */
			&hf_cst_pkt_class_rule_ethertype,
			{"Ethertype/IEEE Std 802.2-1998 SAP", "wmx.cst.pkt_class_rule.ethertype", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Ethertype */
			&hf_cst_pkt_class_rule_etype,
			{"Ethertype", "wmx.cst.pkt_class_rule.ethertype", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Eprot1 */
			&hf_cst_pkt_class_rule_eprot1,
			{"Eprot1", "wmx.cst.pkt_class_rule.eprot1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* Eprot2 */
			&hf_cst_pkt_class_rule_eprot2,
			{"Eprot2", "wmx.cst.pkt_class_rule.eprot2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* IEEE Std 802.1D-1998 User_Priority */
			&hf_cst_pkt_class_rule_user_priority,
			{"IEEE Std 802.1D-1998 User_Priority", "wmx.cst.pkt_class_rule.user_priority", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cst_pkt_class_rule_pri_low,
			{"Pri-Low", "wmx.cst.pkt_class_rule.pri-low", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cst_pkt_class_rule_pri_high,
			{"Pri-High", "wmx.cst.pkt_class_rule.pri-high", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* IEEE Std 802.1Q-1998 VLAN_ID */
			&hf_cst_pkt_class_rule_vlan_id,
			{"IEEE Std 802.1Q-1998 VLAN_ID", "wmx.cst.pkt_class_rule.vlan_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Vlan_Id1 */
			&hf_cst_pkt_class_rule_vlan_id1,
			{"Vlan_Id1", "wmx.cst.pkt_class_rule.vlan_id1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* Vlan_Id2 */
			&hf_cst_pkt_class_rule_vlan_id2,
			{"Vlan_Id2", "wmx.cst.pkt_class_rule.vlan_id2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* Associated PHSI */
			&hf_cst_pkt_class_rule_phsi,
			{"Associated PHSI", "wmx.cst.pkt_class_rule.phsi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Packet Classifier Rule Index */
			&hf_cst_pkt_class_rule_index,
			{"Packet Classifier Rule Index (PCRI)", "wmx.cst.pkt_class_rule.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Large Context ID for ROHC/ECRTP Compressed Packet or ROHC Feedback Packet */
			&hf_cst_large_context_id,
			{"Large Context ID", "wmx.cst.large_context_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Short-Format Context ID for ROHC/ECRTP Compressed Packet or ROHC Feedback Packet */
			&hf_cst_short_format_context_id,
			{"Short-Format Context ID", "wmx.cst.short_format_context_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* Vendor-Specific Classifier Parameters */
			&hf_cst_pkt_class_rule_vendor_spec,
			{"Vendor-Specific Classifier Parameters", "wmx.cst.pkt_class_rule.vendor_spec", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* Classifier Action Rule */
			&hf_cst_pkt_class_rule_classifier_action_rule,
			{"Classifier Action Rule", "wmx.cst.pkt_class_rule.classifier.action.rule", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cst_pkt_class_rule_classifier_action_rule_bit0,
			{"Bit #0", "wmx.cst.pkt_class_rule.classifier.action.rule.bit0", FT_UINT8, BASE_HEX, VALS(vals_classification_action_rule), CST_PKT_CLASS_RULE_CLASSIFIER_ACTION_RULE_BIT0, NULL, HFILL}
		},
		{
			&hf_cst_pkt_class_rule_classifier_action_rule_bit1,
			{"Reserved", "wmx.cst.pkt_class_rule.classifier.action.rule.reserved", FT_UINT8, BASE_HEX, NULL, CST_PKT_CLASS_RULE_CLASSIFIER_ACTION_RULE_RSV, NULL, HFILL}
		},
		{	/* PHS DSC action */
			&hf_cst_phs_dsc_action,
			{"PHS DSC action", "wmx.cst.phs_dsc_action", FT_UINT8, BASE_DEC, VALS(vals_cst_phs_dsc_action), 0x0, NULL, HFILL}
		},
		{	/* PHS Rule */
			&hf_cst_phs_rule,
			{"PHS Rule", "wmx.cst.phs_rule", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 1 */
			&hf_cst_phs_phsi,
			{"PHSI", "wmx.cst.phs_rule.phsi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 2 */
			&hf_cst_phs_phsf,
			{"PHSF", "wmx.cst.phs_rule.phsf", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 3 */
			&hf_cst_phs_phsm,
			{"PHSM (bit x: 0-don't suppress the (x+1) byte; 1-suppress the (x+1) byte)", "wmx.cst.phs_rule.phsm", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 4 */
			&hf_cst_phs_phss,
			{"PHSS", "wmx.cst.phs_rule.phss", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 5 */
			&hf_cst_phs_phsv,
			{"PHSV", "wmx.cst.phs_rule.phsv", FT_UINT8, BASE_DEC, VALS(vals_verify), 0x0, NULL, HFILL}
		},
		{	/* PHS Rule 143 */
			&hf_cst_phs_vendor_spec,
			{"Vendor-Specific PHS Parameters", "wmx.cst.phs.vendor_spec", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* IPv6 Flow Label */
			&hf_cst_pkt_class_rule_ipv6_flow_label,
			{"IPv6 Flow Label", "wmx.cst.pkt_class_rule.ipv6_flow_label", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* ATM Switching Encoding */
			&hf_csper_atm_switching_encoding,
			{"ATM Switching Encoding", "wmx.csper.atm_switching_encoding", FT_UINT8, BASE_DEC, VALS(vals_atm_switching_encodings), 0x0, NULL, HFILL}
		},
		{	/* ATM Classifier TLV */
			&hf_csper_atm_classifier,
			{"ATM Classifier TLV", "wmx.csper.atm_classifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* ATM VPI Classifier */
			&hf_csper_atm_classifier_vpi,
			{"VPI Classifier", "wmx.csper.atm_classifier_vpi", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* ATM VCI Classifier */
			&hf_csper_atm_classifier_vci,
			{"VCI Classifier", "wmx.csper.atm_classifier_vci", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* ATM Classifier ID */
			&hf_csper_atm_classifier_id,
			{"Classifier ID", "wmx.csper.atm_classifier_tlv", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
	/* unknown types */
		{	/* unknown CSPER types */
			&hf_csper_unknown_type,
			{"Unknown CSPER TLV type", "wmx.csper.unknown_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cst_invalid_tlv,
			{"Invalid TLV", "wmx.cst.invalid_tlv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	/* WiMax HMAC/CMAC/Short-HMAC Tuples display */
	static hf_register_info hf_xmac[] =
	{
		{
			&hf_xmac_tuple_rsvd,
			{"Reserved", "wmx.xmac_tuple.reserved", FT_UINT8, BASE_HEX, NULL, XMAC_TUPLE_RESERVED, NULL, HFILL}
		},
		{
			&hf_xmac_tuple_key_seq_num,
			{"Key Sequence Number", "wmx.xmac_tuple.key_sn", FT_UINT8, BASE_DEC, NULL, XMAC_TUPLE_KEY_SEQ_NUM, NULL, HFILL}
		},
		{
			&hf_hmac_tuple_hmac_digest,
			{"HMAC Digest", "wmx.xmac_tuple.hmac_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cmac_tuple_bsid,
			{"BSID", "wmx.cmac_tuple.bsid", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_cmac_tuple_cmac_value,
			{"CMAC Value", "wmx.cmac_tuple.cmac.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_packet_number_counter,
			{"Packet Number Counter", "wmx.xmac_tuple.packet_number_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		}
	};

	static hf_register_info hf_snp[] =
	{
		{	/* 11.8.4.1 */
			&hf_snp_pkm_version_support,
			{"PKM Version Support", "wmx.security_negotiation_parameters.pkm_version_support",FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_snp_pkm_version_support_bit0,
			{"PKM version 1", "wmx.security_negotiation_parameters.pkm_version_support.bit0",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_PKM_VERSION_SUPPORT_BIT0, NULL, HFILL}
		},
		{
			&hf_snp_pkm_version_support_bit1,
			{"PKM version 2", "wmx.security_negotiation_parameters.pkm_version_support.bit1",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_PKM_VERSION_SUPPORT_BIT1, NULL, HFILL}
		},
		{
			&hf_snp_pkm_version_support_reserved,
			{"Reserved", "wmx.security_negotiation_parameters.pkm_version_support.reserved",FT_UINT8, BASE_HEX, NULL, SNP_PKM_VERSION_SUPPORT_RSV, NULL, HFILL}
		},
		{	/* 11.8.4.2 */
			&hf_snp_auth_policy_support,
			{"Authorization Policy Support", "wmx.security_negotiation_parameters.auth_policy_support",FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit0,
			{"RSA-based Authorization At The Initial Network Entry", "wmx.security_negotiation_parameters.auth_policy_support.bit0",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT0, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit1,
			{"EAP-based Authorization At The Initial Network Entry", "wmx.security_negotiation_parameters.auth_policy_support.bit1",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT1, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit2,
			{"Authenticated EAP-based Authorization At The Initial Network Entry", "wmx.security_negotiation_parameters.auth_policy_support.bit2",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT2, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit3,
			{"Reserved", "wmx.security_negotiation_parameters.auth_policy_support.bit3",FT_UINT8, BASE_HEX, NULL, SNP_AUTH_POLICY_SUPPORT_BIT3, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit4,
			{"RSA-based Authorization At Re-entry", "wmx.security_negotiation_parameters.auth_policy_support.bit4",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT4, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit5,
			{"EAP-based Authorization At Re-entry", "wmx.security_negotiation_parameters.auth_policy_support.bit5",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT5, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit6,
			{"Authenticated EAP-based Authorization At Re-entry", "wmx.security_negotiation_parameters.auth_policy_support.bit6",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_AUTH_POLICY_SUPPORT_BIT6, NULL, HFILL}
		},
		{
			&hf_snp_auth_policy_support_bit7,
			{"Reserved", "wmx.security_negotiation_parameters.auth_policy_support.bit7",FT_UINT8, BASE_HEX, NULL, SNP_AUTH_POLICY_SUPPORT_BIT7, NULL, HFILL}
		},
		{	/* 11.8.4.3 */
			&hf_snp_mac_mode,
			{"MAC (Message Authentication Code) Mode", "wmx.security_negotiation_parameters.mac_mode",FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit0,
			{"HMAC", "wmx.security_negotiation_parameters.mac_mode.bit0",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT0, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit1,
			{"CMAC", "wmx.security_negotiation_parameters.mac_mode.bit1",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT1, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit1_rsvd,
			{"Reserved", "wmx.security_negotiation_parameters.mac_mode.bit1_rsvd",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT1, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit2,
			{"64-bit Short-HMAC", "wmx.security_negotiation_parameters.mac_mode.bit2",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT2, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit3,
			{"80-bit Short-HMAC", "wmx.security_negotiation_parameters.mac_mode.bit3",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT3, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit4,
			{"96-bit Short-HMAC", "wmx.security_negotiation_parameters.mac_mode.bit4",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT4, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_bit5,
			{"CMAC", "wmx.security_negotiation_parameters.mac_mode.bit5",FT_BOOLEAN, 8, TFS(&tfs_supported), SNP_MAC_MODE_BIT5, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_reserved,
			{"Reserved", "wmx.security_negotiation_parameters.mac_mode.reserved",FT_UINT8, BASE_HEX, NULL, SNP_MAC_MODE_RSV, NULL, HFILL}
		},
		{
			&hf_snp_mac_mode_reserved1,
			{"Reserved", "wmx.security_negotiation_parameters.mac_mode.reserved",FT_UINT8, BASE_HEX, NULL, SNP_MAC_MODE_RSV1, NULL, HFILL}
		},
		{	/* 11.8.4.4 */
			&hf_snp_pn_window_size,
			{"PN Window Size", "wmx.security_negotiation_parameters.pn_window_size",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.8.4.5 */
			&hf_snp_max_conc_transactions,
			{"Maximum concurrent transactions (0 indicates no limit)", "wmx.security_negotiation_parameters.max_conc_transactions",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.8.4.6 */
			&hf_snp_max_suppt_sec_assns,
			{"Maximum number of security associations supported by the SS", "wmx.security_negotiation_parameters.max_suppt_sec_assns",FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_snp_unknown_type,
			{"Unknown Security Negotiation Parameter type", "wmx.security_negotiation_parameters.unknown.type",FT_BYTES, BASE_NONE, NULL, 0x0,	NULL, HFILL}
		}
	};

	static hf_register_info hf_pkm[] =
	{
		{	/* 11.9.1 - type 6 */
			&hf_pkm_msg_attr_display,
			{"Display String", "wmx.pkm_msg.pkm_attr.display_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.2 - type 7 */
			&hf_pkm_msg_attr_auth_key,
			{"Auth Key", "wmx.pkm_msg.pkm_attr.auth_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.3 - type 8 */
			&hf_pkm_msg_attr_tek,
			{"TEK", "wmx.pkm_msg.pkm_attr.tek", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.4 - type 9 */
			&hf_pkm_msg_attr_key_life_time,
			{"Key Lifetime", "wmx.pkm_msg.pkm_attr.key_life_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.5 - type 10 */
			&hf_pkm_msg_attr_key_seq_num,
			{"Key Sequence Number", "wmx.pkm_msg.pkm_attr.key_seq_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.6 - type 11 */
			&hf_pkm_msg_attr_hmac_digest,
			{"HMAC-Digest", "wmx.pkm_msg.pkm_attr.hmac_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.7 - type 12 */
			&hf_pkm_msg_attr_said,
			{"SAID", "wmx.pkm_msg.pkm_attr.said", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
#if 0	/* not been used */
		{	/* 11.9.8 - type 13 */
			&hf_pkm_msg_attr_tek_param,
			{"TEK Parameters", "wmx.pkm_msg.pkm_attr.tek_parameters", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11.9.9 - type 15 */
			&hf_pkm_msg_attr_cbc_iv,
			{"CBC IV", "wmx.pkm_msg.pkm_attr.cbc_iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.10 - type 16 */
			&hf_pkm_msg_attr_error_code,
			{"Error Code", "wmx.pkm_msg.pkm_attr.error_code", FT_UINT8, BASE_DEC, VALS(vals_pkm_attr_error_codes), 0x0, NULL, HFILL}
		},
		{	/* 11.9.11 - type 17 */
			&hf_pkm_msg_attr_ca_certificate,
			{"CA Certificate", "wmx.pkm_msg.pkm_attr.ca_certificate", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.12 - type 18 */
			&hf_pkm_msg_attr_ss_certificate,
			{"SS Certificate", "wmx.pkm_msg.pkm_attr.ss_certificate", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#if 0	/* not been used */
		{	/* 11.9.13 - type 19 */
			&hf_pkm_msg_attr_security_capabilities,
			{"Security Capabilities", "wmx.pkm_msg.pkm_attr.security_capabilities", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11.9.14 - type 20 */
			&hf_pkm_msg_crypto_suite,
			{"Cryptography", "wmx.pkm_msg.pkm_attr.crypto_suite", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_msg_crypto_suite_msb,
			{"Data Encryption Algorithm Identifiers", "wmx.pkm_msg.pkm_attr.crypto_suite.msb", FT_UINT8, BASE_DEC, VALS(vals_data_encryption_ids), 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_msg_crypto_suite_middle,
			{"Data Authentication Algorithm Identifiers", "wmx.pkm_msg.pkm_attr.crypto_suite.middle", FT_UINT8, BASE_DEC, VALS(vals_data_authentication_ids), 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_msg_crypto_suite_lsb,
			{"TEK Encryption Algorithm Identifiers", "wmx.pkm_msg.pkm_attr.crypto_suite.lsb", FT_UINT8, BASE_DEC, VALS(vals_tek_encryption_ids), 0x0, NULL, HFILL}
		},
#if 0	/* not been used */
		{	/* 11.9.15 - type 21 */
			&hf_pkm_msg_crypto_list,
			{"Cryptographic-Suite List", "wmx.pkm_msg.pkm_attr.crypto_suite_list", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
#if 0	/* deleted by 802.16E */
		{	/* 11.9.16 - type 22 */
			&hf_pkm_msg_version,
			{"Reserved ", "wmx.pkm_msg.pkm_attr.version", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
#if 0	/* not been used */
		{	/* 11.9.17 - type 23 */
			&hf_pkm_msg_sa_descriptor,
			{"SA Descriptor", "wmx.pkm_msg.pkm_attr.sa_descriptor", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11.9.18 - type 24 */
			&hf_pkm_sa_type,
			{"SA Type", "wmx.pkm_msg.pkm_attr.sa_type", FT_UINT8, BASE_DEC, VALS(vs_sa_type), 0x0, NULL, HFILL}
		},
#if 0	/* not been used */
		{	/* 11.9.?? - type 25 */
			&hf_pkm_attr_security_negotiation_parameters,
			{"Security Negotiation Parameters", "wmx.pkm_msg.pkm_attr.security_negotiation_parameters", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
#if 0	/* not been used */
		{	/* 11.9.19 - type 27 */
			&hf_pkm_attr_config_settings,
			{"PKM Configuration Settings", "wmx.pkm_msg.pkm_attr.config_settings", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11.9.19.1 */
			&hf_pkm_config_settings_authorize_waitout,
			{"Authorize Wait Timeout (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.authorize_waitout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.2 */
			&hf_pkm_config_settings_reauthorize_waitout,
			{"Reauthorize Wait Timeout (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.reauthorize_waitout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.3 */
			&hf_pkm_config_settings_grace_time,
			{"Authorization Grace Time (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.grace_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.4 */
			&hf_pkm_config_settings_operational_waittime,
			{"Operational Wait Timeout (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.operational_wait_timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.5 */
			&hf_pkm_config_settings_rekey_wait_timeout,
			{"Rekey Wait Timeout (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.rekey_wait_timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.6 */
			&hf_pkm_config_settings_tek_grace_time,
			{"TEK Grace Time (in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.tek_grace_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.19.7 */
			&hf_pkm_config_settings_authorize_reject_wait_timeout,
			{"Authorize Reject Wait Timeout(in seconds)", "wmx.pkm_msg.pkm_attr.config_settings.authorize_reject_wait_timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.20 - type 29 */
			&hf_pkm_attr_nonce,
			{"Nonce", "wmx.pkm_msg.pkm_attr.nonce", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.21 - type 33 */
			&hf_pkm_attr_ss_random,
			{"SS_RANDOM", "wmx.pkm_msg.pkm_attr.ss_random", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.22 - type 34 */
			&hf_pkm_attr_bs_random,
			{"BS_RANDOM", "wmx.pkm_msg.pkm_attr.bs_random", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.23 - type 35 */
			&hf_pkm_attr_pre_pak,
			{"Pre-PAK", "wmx.pkm_msg.pkm_attr.pre_pak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#if 0	/* no definition */
		{	/* 11.9.?? - type 36 */
			&hf_pkm_attr_pak_ak_seq_number,
			{"PAK/AK Sequence Number", "wmx.pkm_msg.pkm_attr.pak_ak_seq_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
		{	/* 11.9.24 - type 37 */
			&hf_pkm_attr_bs_certificate,
			{"BS Certificate", "wmx.pkm_msg.pkm_attr.bs_certificate", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.25 - type 38 */
			&hf_pkm_attr_sig_bs,
			{"SigBS", "wmx.pkm_msg.pkm_attr.sig_bs",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.26 - type 39 */
			&hf_pkm_attr_ms_mac_address,
			{"MS-MAC Address", "wmx.pkm_msg.pkm_attr.ms_mac_address",FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.27 - type 40 */
			&hf_pkm_attr_cmac_digest,
			{"CMAC Digest", "wmx.pkm_msg.pkm_attr.cmac_digest",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_attr_cmac_digest_pn,
			{"CMAC Packet Number counter, CMAC_PN_*", "wmx.pkm_msg.pkm_attr.cmac_digest.pn",FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_pkm_attr_cmac_digest_value,
			{"CMAC Value", "wmx.pkm_msg.pkm_attr.cmac_digest.value",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.28 - type 41 */
			&hf_pkm_attr_push_modes,
			{"Key Push Modes", "wmx.pkm_msg.pkm_attr.key_push_modes",FT_UINT8, BASE_DEC, VALS(va_key_push_modes), 0x0, NULL, HFILL}
		},
		{	/* 11.9.29 - type 42 */
			&hf_pkm_attr_key_push_counter,
			{"Key Push Counter", "wmx.pkm_msg.pkm_attr.key_push_counter",FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.30 - type 43 */
			&hf_pkm_attr_gkek,
			{"GKEK", "wmx.pkm_msg.pkm_attr.gkek",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.31 - type 44 */
			&hf_pkm_attr_sig_ss,
			{"SigSS", "wmx.pkm_msg.pkm_attr.sig_ss",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.32 - type 45 */
			&hf_pkm_attr_akid,
			{"AKID", "wmx.pkm_msg.pkm_attr.akid",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.33 - type 28 */
			&hf_pkm_attr_eap_payload,
			{"EAP Payload", "wmx.pkm_msg.pkm_attr.eap_payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{	/* 11.9.34 - type 30 */
			&hf_pkm_attr_auth_result_code,
			{"Auth Result Code", "wmx.pkm_msg.pkm_attr.auth_result_code", FT_UINT8, BASE_DEC, VALS(vs_success_reject), 0x0, NULL, HFILL}
		},
		{	/* 11.9.35 - type 31 */
			&hf_pkm_attr_sa_service_type,
			{"SA Service Type", "wmx.pkm_msg.pkm_attr.sa_service_type", FT_UINT8, BASE_DEC, VALS(vs_sa_service_type), 0x0, NULL, HFILL}
		},
#if 0	/* same as 11.9.19 */
		{	/* 11.9.36 - type 27 */
			&hf_pkm_attr_config_settings,
			{"PKMv2 Configuration Settings", "wmx.pkm_msg.pkm_attr.config_settings", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL}
		},
#endif
		{	/* 11.9.37 - type 32 */
			&hf_pkm_attr_frame_number,
			{"Frame Number", "wmx.pkm_msg.pkm_attr.frame_number", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
#if 1	/* no definitions [??] */
		{	/* 11.9.?? - type 46 */
			&hf_pkm_attr_associated_gkek_seq_number,
			{"Associated GKEK Sequence Number", "wmx.pkm_msg.pkm_attr.associated_gkek_seq_number",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
#if 0
		{	/* 11.9.?? - type 47 */
			&hf_pkm_attr_gkek_params,
			{"GKEK Parameters", "wmx.pkm_msg.pkm_attr.gkek_params",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
		{
			&hf_pkm_msg_unknown_type,
			{"Unknown Type", "wmx.pkm.unknown.type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
	};

	/* WiMax Common TLV Encoding display */
	static hf_register_info hf_common_tlv[] =
	{
		{
			&hf_common_tlv_mac_version,
			{ "MAC Version", "wmx.common_tlv.mac_version", FT_UINT8, BASE_DEC, VALS(vals_dcd_mac_version), 0x0, NULL, HFILL}
		},
		{
			&hf_common_tlv_vendor_id,
			{ "Vendor ID Encoding", "wmx.common_tlv.vendor_id_encoding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_common_tlv_vendor_specific_type,
			{ "Vendor Specific Type", "wmx.common_tlv.vendor_specific_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_common_tlv_vendor_specific_length_size,
			{
				"Vendor Specific Length Size", "wmx.common_tlv.vendor_specific_length_size",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_common_tlv_vendor_specific_length,
			{ "Vendor Specific Length", "wmx.common_tlv.vendor_specific_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_common_tlv_vendor_specific_value,
			{ "Vendor Specific Value", "wmx.common_tlv.vendor_specific_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_common_current_transmitted_power,
			{ "Current Transmitted Power", "wmx.common_tlv.current_transmitted_power", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#if 0
		{
			&hf_common_tlv_unknown_type,
			{"Unknown Common TLV Type", "wmx.common_tlv.unknown_type", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		}
#endif
	};

	if(proto_wimax_utility_decoders == -1)
	{
		proto_wimax_utility_decoders = proto_register_protocol (
							"WiMax Sub-TLV Messages",
 /* name */
							"WiMax Sub-TLV (sub)", /* short name */
							"wmx.sub" /* abbrev */
							);

		proto_register_subtree_array(ett, array_length(ett));
		proto_register_field_array(proto_wimax_utility_decoders, hf_sfe, array_length(hf_sfe));
		proto_register_field_array(proto_wimax_utility_decoders, hf_csper, array_length(hf_csper));
		proto_register_field_array(proto_wimax_utility_decoders, hf_xmac, array_length(hf_xmac));
		proto_register_field_array(proto_wimax_utility_decoders, hf_snp, array_length(hf_snp));
		proto_register_field_array(proto_wimax_utility_decoders, hf_pkm, array_length(hf_pkm));
		proto_register_field_array(proto_wimax_utility_decoders, hf_common_tlv, array_length(hf_common_tlv));

		eap_handle = find_dissector("eap");
	}
}

/**************************************************************/
/* wimax_error_parameter_set_decoder()                        */
/* decode and display the WiMax Error Parameter Set           */
/* parameter:                                                 */
/*   tvb - pointer of the tvb of error_parameter_set          */
/*   tree - pointer of Wireshark display tree                 */
/*   pinfo - pointer of Wireshark packet information structure*/
/**************************************************************/
void wimax_error_parameter_set_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len;
	gint  tlv_type;
	proto_item *ceps_item = NULL;
	proto_tree *ceps_tree = NULL;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	offset = 0;
	/* display error parameter information */
	ceps_item = proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, tvb_len, "Error Parameter Set (%u bytes)", tvb_len);
	/* add CS Parameter Encoding Rules subtree */
	ceps_tree = proto_item_add_subtree(ceps_item, ett_wimax_error_parameter_set);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Error Parameter Set");
		return;
	}
	/* process the classifier error parameter set */
	while(offset < tvb_len)
	{	/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "EPS TLV error");
			proto_tree_add_item(ceps_tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(ceps_tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len+2+get_tlv_size_of_length(&tlv_info)), "EPS TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len, offset, tvb_len);
#endif
		/* parse the Classifier Error Parameter Set */
		switch (tlv_type)
		{
			case CST_ERROR_SET_ERRORED_PARAM:
				add_tlv_subtree(&tlv_info, ceps_tree, hf_cst_error_set_errored_param, tvb, offset, ENC_NA);
			break;
			case CST_ERROR_SET_ERROR_CODE:
				add_tlv_subtree(&tlv_info, ceps_tree, hf_cst_error_set_error_code, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case CST_ERROR_SET_ERROR_MSG:
				add_tlv_subtree(&tlv_info, ceps_tree, hf_cst_error_set_error_msg, tvb, offset, ENC_ASCII|ENC_NA);
			break;
		}
		offset += (tlv_len+get_tlv_value_offset(&tlv_info));
	}
}

/****************************************************************/
/* wimax_convengence_service_parameter_encoding_rules_decoder() */
/* decode and display the WiMax Convergence Service Parameter   */
/*        Encoding Rules                                        */
/* parameter:                                                   */
/*   sfe_type - Service Flow Encodings type                     */
/*   tvb - pointer of the tvb of service flow encodings         */
/*   tree - pointer of Wireshark display tree                   */
/*   pinfo - pointer of Wireshark packet information structure  */
/****************************************************************/
/* CS Parameter Encoding Rules handling function */
void wimax_convengence_service_parameter_encoding_rules_decoder(guint sfe_type, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset, tlv_offset;
	guint tvb_len, tlv_len, length;
	gint  tlv_type;
	proto_item *csper_item;
	proto_tree *csper_tree;
	proto_tree *tlv_tree, *ti_tree;
	proto_item *tlv_item, *ti_item;
	tlv_info_t tlv_info;
	gboolean ipv6 = ((sfe_type == SFE_CSPER_PACKET_IPV6) || (sfe_type == SFE_CSPER_PACKET_IPV6_802_3) || (sfe_type == SFE_CSPER_PACKET_IPV6_802_1Q));

	/* sanity check */
	if((sfe_type < SFE_CSPER_ATM) || (sfe_type > SFE_CSPER_PACKET_IP_802_3_ECRTP_COMPRESSION))
		return; /* invalid CS Parameter Encodings */

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	offset = 0;
	/* display SFE information */
	csper_item = proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, tvb_len, "Convergence Service Parameter Encoding Rules (%u bytes)", tvb_len);
	/* add CS Parameter Encoding Rules subtree */
	csper_tree = proto_item_add_subtree(csper_item, ett_wimax_cst_encoding_rules);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Convergence Service Parameter Encoding Rules");
		return;
	}
	/* process WiMax Service Flow Encodings */
	while(offset < tvb_len)
	{	/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CSPER TLV error");
			proto_tree_add_item(csper_tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(csper_tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len+2+get_tlv_size_of_length(&tlv_info)), "CSPER TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len, offset, tvb_len);
#endif
		/* update the offset */
		offset += get_tlv_value_offset(&tlv_info);
		/* parse the CS parameter Encoding Rule TLV */
		if(sfe_type == SFE_CSPER_ATM)
		{	/* ATM CS Encodings */
			switch (tlv_type)
			{
				case CST_ATM_SWITCHING:
					add_tlv_subtree(&tlv_info, csper_tree, hf_csper_atm_switching_encoding, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
				break;
				case CST_ATM_CLASSIFIER:
					/* add TLV subtree */
					tlv_item = add_tlv_subtree(&tlv_info, csper_tree, hf_csper_atm_classifier, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_NA);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_cst_encoding_rules);
					tlv_offset = offset;
					while(tlv_offset < (tlv_len + offset))
					{
						/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, tlv_offset);
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "ATM Classifier TLV error");
							proto_tree_add_item(tlv_tree, hf_cst_invalid_tlv, tvb, offset, (tlv_len - tlv_offset), ENC_NA);
							break;
						}
#ifdef DEBUG /* for debug only */
						proto_tree_add_protocol_format(csper_tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len+2+get_tlv_size_of_length(&tlv_info)), "ATM Classifier TLV Type: %u (%u bytes, offset=%u, tlv_len=%u)", tlv_type, length, offset, tlv_len);
#endif
						switch (tlv_type)
						{
							case ATM_VPI_CLASSIFIER:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_csper_atm_classifier_vpi, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							case ATM_VCI_CLASSIFIER:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_csper_atm_classifier_vci, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							case ATM_CLASSIFIER_ID:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_csper_atm_classifier_id, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							default:
							break;
						}
						tlv_offset += (length + get_tlv_value_offset(&tlv_info));
					}	/* end of while loop */
				break;
				case CST_ATM_CLASSIFIER_DSC_ACTION:
					add_tlv_subtree(&tlv_info, csper_tree, hf_cst_classifier_dsc_action, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
				break;
				case CST_ATM_CLASSIFIER_ERROR_PARAMETER_SET:
					/* call the error parameter set function */
					tlv_tree = add_protocol_subtree(&tlv_info, ett_wimax_cst_encoding_rules, csper_tree, proto_wimax_utility_decoders, tvb, offset-get_tlv_value_offset(&tlv_info), tlv_len, "Classifier Error Parameter Set");
					wimax_error_parameter_set_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
				break;
				default:
					/* display the unknown ATM CS encoding in hex */
					add_tlv_subtree(&tlv_info, csper_tree, hf_csper_unknown_type, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_NA);
				break;
			}
		}
		else
		{
			switch (tlv_type)
			{
				case CST_CLASSIFIER_ACTION:
					add_tlv_subtree(&tlv_info, csper_tree, hf_cst_classifier_dsc_action, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
				break;
				case CST_CLASSIFIER_ERROR_PARAM_SET:
				case CST_PHS_ERROR_PARAM_SET:
					tlv_tree = add_protocol_subtree(&tlv_info, ett_wimax_cst_encoding_rules, csper_tree, proto_wimax_utility_decoders, tvb, offset-get_tlv_value_offset(&tlv_info), tlv_len, "Classifier Error Parameter Set");
					/* call the error parameter set function */
					wimax_error_parameter_set_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
				break;
				case CST_PACKET_CLASSIFICATION_RULE:
				{
					/* add TLV subtree */
					tlv_item = add_tlv_subtree(&tlv_info, csper_tree, hf_cst_pkt_class_rule, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_NA);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_cst_encoding_rules);
					tlv_offset = offset;
					while(tlv_offset < (tlv_len + offset))
					{
						/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, tlv_offset);
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Packet Classification Rule TLV error");
							proto_tree_add_item(tlv_tree, hf_cst_invalid_tlv, tvb, offset, (tlv_len - tlv_offset), ENC_NA);
							break;
						}
#ifdef DEBUG /* for debug only */
						proto_tree_add_protocol_format(csper_tree, proto_wimax_utility_decoders, tvb, tlv_offset, (length + get_tlv_value_offset(&tlv_info)), "Packet Classification Rule TLV Type: %u (%u bytes, offset=%u, tlv_len=%u)", tlv_type, length, tlv_offset, tlv_len);
#endif
						/* update the offset */
						tlv_offset += get_tlv_value_offset(&tlv_info);
						switch (tlv_type)
						{
							case CST_PKT_CLASS_RULE_PRIORITY:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_priority, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_RANGE_MASK:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_range_mask, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_tos_low, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_tos_high, tvb, tlv_offset + 1, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_tos_mask, tvb, tlv_offset + 2, 1, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_PROTOCOL:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_protocol, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_SRC_IP:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_ip_masked_src_address, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								if(ipv6)
								{
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_src_ipv6, tvb, tlv_offset, 16, ENC_NA);
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_ipv6, tvb, tlv_offset + 16, 16, ENC_NA);
								}
								else
								{
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_src_ipv4, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_ipv4, tvb, tlv_offset + 4, 4, ENC_BIG_ENDIAN);
								}
							break;
							case CST_PKT_CLASS_RULE_DST_IP:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_ip_masked_dest_address, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								if(ipv6)
								{
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_dest_ipv6, tvb, tlv_offset, 16, ENC_NA);
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_ipv6, tvb, tlv_offset + 16, 16, ENC_NA);
								}
								else
								{
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_dest_ipv4, tvb, tlv_offset, 4, ENC_BIG_ENDIAN);
									proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_ipv4, tvb, tlv_offset + 4, 4, ENC_BIG_ENDIAN);
								}
							break;
							case CST_PKT_CLASS_RULE_SRCPORT_RANGE:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_prot_src_port_range, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_src_port_low, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_src_port_high, tvb, tlv_offset + 2, 2, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_DSTPORT_RANGE:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_prot_dest_port_range, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_dest_port_low, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_dest_port_high, tvb, tlv_offset + 2, 2, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_DST_MAC:
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_dest_mac_address, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								/* add TLV subtree */
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_dest_mac, tvb, tlv_offset, 6, ENC_NA);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_mac, tvb, tlv_offset + 6, 6, ENC_NA);
							break;
							case CST_PKT_CLASS_RULE_SRC_MAC:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_src_mac_address, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_src_mac, tvb, tlv_offset, 6, ENC_NA);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_mask_mac, tvb, tlv_offset + 6, 6, ENC_NA);
							break;
							case CST_PKT_CLASS_RULE_ETHERTYPE:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_ethertype, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_etype, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_eprot1, tvb, tlv_offset + 1, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_eprot2, tvb, tlv_offset + 2, 1, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_USER_PRIORITY:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_user_priority, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_pri_low, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_pri_high, tvb, tlv_offset + 1, 1, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_VLAN_ID:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_vlan_id, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_vlan_id1, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_vlan_id2, tvb, tlv_offset + 1, 1, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_PHSI:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_phsi, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_INDEX:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_index, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_IPv6_FLOW_LABEL:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_ipv6_flow_label, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_VENDOR_SPEC:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_vendor_spec, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_NA);
							break;
							case CST_CLASSIFIER_ACTION_RULE:
								/* add TLV subtree */
								ti_item = add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_pkt_class_rule_classifier_action_rule, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
								ti_tree = proto_item_add_subtree(ti_item, ett_wimax_cst_encoding_rules);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_classifier_action_rule_bit0, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
								proto_tree_add_item(ti_tree, hf_cst_pkt_class_rule_classifier_action_rule_bit1, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_LARGE_CONTEXT_ID:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_large_context_id, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							case CST_PKT_CLASS_RULE_SHORT_FORMAT_CONTEXT_ID:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_short_format_context_id, tvb, tlv_offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
							break;
							default:
							break;
						}	/* end of switch */
						tlv_offset += length;
					}	/* end of while loop */
					break;
				}
				case CST_PHS_DSC_ACTION:
					add_tlv_subtree(&tlv_info, csper_tree, hf_cst_phs_dsc_action, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_BIG_ENDIAN);
				break;
				case CST_PHS_RULE:
				{
					/* add TLV subtree */
					tlv_item = add_tlv_subtree(&tlv_info, csper_tree, hf_cst_phs_rule, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_NA);
					tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_cst_encoding_rules);
					tlv_offset = offset;
					while(tlv_offset < (tlv_len + offset))
					{
						/* get the TLV information */
						init_tlv_info(&tlv_info, tvb, tlv_offset);
						/* get the TLV type */
						tlv_type = get_tlv_type(&tlv_info);
						/* get the TLV length */
						length = get_tlv_length(&tlv_info);
						if(tlv_type == -1 || length > MAX_TLV_LEN || length < 1)
						{	/* invalid tlv info */
							col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PHS n Rule TLV error");
							proto_tree_add_item(tlv_tree, hf_cst_invalid_tlv, tvb, offset, (tlv_len - tlv_offset), ENC_NA);
							break;
						}
#ifdef DEBUG /* for debug only */
						proto_tree_add_protocol_format(csper_tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len+2+get_tlv_size_of_length(&tlv_info)), "PHS Rule TLV Type: %u (%u bytes, offset=%u, tlv_len=%u)", tlv_type, length, offset, tlv_len);
#endif
						switch (tlv_type)
						{
							case CST_PHS_PHSI:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_phsi, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							case CST_PHS_PHSF:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_phsf, tvb, tlv_offset, ENC_NA);
							break;
							case CST_PHS_PHSM:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_phsm, tvb, tlv_offset, ENC_NA);
							break;
							case CST_PHS_PHSS:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_phss, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							case CST_PHS_PHSV:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_phsv, tvb, tlv_offset, ENC_BIG_ENDIAN);
							break;
							case CST_PHS_VENDOR_SPEC:
								add_tlv_subtree(&tlv_info, tlv_tree, hf_cst_phs_vendor_spec, tvb, tlv_offset, ENC_NA);
							break;
						}
						tlv_offset += (length+get_tlv_value_offset(&tlv_info));
					}
					break;
				}
				default:
					/* display the unknown csper type in hex */
					add_tlv_subtree(&tlv_info, tree, hf_csper_unknown_type, tvb, offset-get_tlv_value_offset(&tlv_info), ENC_NA);
				break;
			}	/* end of switch */
		}	/* end of if */
		offset += tlv_len;
	}	/* end of while loop */
}

/**************************************************************/
/* wimax_service_flow_encodings_decoder()                     */
/* decode and display the WiMax Service Flow Encodings        */
/* parameter:                                                 */
/*   tvb - pointer of the tvb of service flow encodings       */
/*   tree - pointer of Wireshark display tree                 */
/*   pinfo - pointer of Wireshark packet information structure*/
/**************************************************************/
void wimax_service_flow_encodings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset, i;
	guint tvb_len, tlv_len, tlv_value_offset, tlv_value;
	gint  tlv_type;
	guint value;
	proto_item *tlv_item = NULL;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
#ifdef DEBUG /* for debug only */
	/* display dissector information */
	proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, 0, tvb_len, "WiMax Service Flow Encodings (%u bytes)", tvb_len);
#endif
	/* process WiMax Service Flow Encodings */
	offset = 0;
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Service Flow Encodings");
		return;
	}
	while(offset < tvb_len)
	{	/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Service Flow Encodings TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Service Flow Encodings TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, tlv_len, offset, tvb_len);
#endif
		/* update the offset */
		offset += tlv_value_offset;
		/* parse the Service Flow Encodings TLV */
		switch (tlv_type)
		{
			case SFE_SF_ID:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_sf_id, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_CID:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_cid, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_SERVICE_CLASS_NAME:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_service_class_name, tvb, offset-tlv_value_offset, ENC_ASCII|ENC_NA);
			break;
			case SFE_MBS_SERVICE:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_mbs_service, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_QOS_PARAMS_SET:
				/* add TLV subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_qos_params_set, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
				proto_tree_add_item(tlv_tree, hf_sfe_set_provisioned, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_set_admitted, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_set_active, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_set_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;
			case SFE_TRAFFIC_PRIORITY:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_traffic_priority, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " (allowed values are 0-7)");
			break;
			case SFE_MAX_STR:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_max_str, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " bps");
			break;
			case SFE_MAX_TRAFFIC_BURST:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_max_traffic_burst, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " bytes");
			break;
			case SFE_MIN_RTR:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_min_rtr, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " bps");
			break;
			case SFE_RESERVED_10:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_reserved_10, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_UL_SCHEDULING:
				/* TODO: Find a way to get the correct service type from the TLV */
				tlv_value = tvb_get_guint8(tvb, offset);
				set_service_type( tlv_value );
				add_tlv_subtree(&tlv_info, tree, hf_sfe_ul_grant_scheduling, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_TX_POLICY:
				/* add TLV subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_req_tx_policy, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_broadcast_bwr, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_multicast_bwr, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_piggyback, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_fragment, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_headers, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_packing, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_sfe_policy_rsvd1, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;
			case SFE_TOLERATED_JITTER:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_jitter, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " ms");
			break;
			case SFE_MAX_LATENCY:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_max_latency, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " ms");
			break;
			case SFE_FIXED_LEN_SDU:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_fixed_len_sdu, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_SDU_SIZE:
				/* save the SDU size */
				mac_sdu_length = tvb_get_guint8(tvb, offset);
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_sdu_size, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " bytes");
			break;
			case SFE_TARGET_SAID:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_target_said, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_ARQ_ENABLE:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_enable, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_ARQ_WINDOW_SIZE:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_window_size, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_ARQ_TRANSMITTER_DELAY:
				if (include_cor2_changes)
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_transmitter_delay_cor2, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
				else
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_transmitter_delay, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
			break;
			case SFE_ARQ_RECEIVER_DELAY:
				if (include_cor2_changes)
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_receiver_delay_cor2, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
				else
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_receiver_delay, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
			break;
			case SFE_ARQ_BLOCK_LIFETIME:
				if (include_cor2_changes)
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_block_lifetime_cor2, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
				else
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_block_lifetime, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
			break;
			case SFE_ARQ_SYNC_LOSS_TIMEOUT:
				if (include_cor2_changes)
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_sync_loss_timeout_cor2, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
				else
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_sync_loss_timeout, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
			break;
			case SFE_ARQ_DELIVER_IN_ORDER:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_deliver_in_order, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_ARQ_RX_PURGE_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_rx_purge_timeout, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_ARQ_BLOCK_SIZE:
				if (include_cor2_changes)
				{
					tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_block_size_cor2, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
					/* add TLV subtree */
					tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
					value = tvb_get_guint8(tvb, offset);
					tlv_item = proto_tree_add_item(tlv_tree, hf_sfe_arq_min_block_size, tvb, offset, 1, ENC_BIG_ENDIAN);
					/* Size is 2^((value & 0x0F) + 4)) */
					proto_item_append_text(tlv_item, " ( %d bytes )", 0x10 << (value & 0x0F));
					tlv_item = proto_tree_add_item(tlv_tree, hf_sfe_arq_max_block_size, tvb, offset, 1, ENC_BIG_ENDIAN);
					if (value & 0xF0)
						/* Size is 2^(((value & 0xF0) >> 4) + 4)) */
						proto_item_append_text(tlv_item, " ( %d bytes )", 0x10 << ((value & 0xF0) >> 4));
				}
				else
				{
					add_tlv_subtree(&tlv_info, tree, hf_sfe_arq_block_size, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				}
			break;
			case SFE_CS_SPECIFICATION:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_cs_specification, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_TYPE_OF_DATA_DELIVERY_SERVICES:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_type_of_data_delivery_services, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_SDU_INTER_ARRIVAL_INTERVAL:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_sdu_inter_arrival_interval, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_TIME_BASE:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_time_base, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " ms");
			break;
			case SFE_PAGING_PREFERENCE:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_paging_preference, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_MBS_ZONE_IDENTIFIER_ASSIGNMENT:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_mbs_zone_identifier_assignment, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_RESERVED_34:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_reserved_34, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_GLOBAL_SERVICE_CLASS_NAME:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_global_service_class_name, tvb, offset-tlv_value_offset, ENC_ASCII|ENC_NA);
			break;
/* 36 reserved */
			case SFE_RESERVED_36:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_reserved_36, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;

			case SFE_SN_FEEDBACK_ENABLED:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_sn_feedback_enabled, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_FSN_SIZE:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_fsn_size, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_CID_ALLOCATION_FOR_ACTIVE_BS:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_cid_alloc_for_active_bs_cid, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
				for(i = 0; i < tlv_len; i+=2)
					proto_tree_add_item(tlv_tree, hf_sfe_cid_alloc_for_active_bs_cid, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
			break;
			case SFE_UNSOLICITED_GRANT_INTERVAL:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_unsolicited_grant_interval, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " ms");
			break;
			case SFE_UNSOLOCITED_POLLING_INTERVAL:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_unsolicited_polling_interval, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				proto_item_append_text(tlv_item, " ms");
			break;
			case SFE_PDU_SN_EXT_SUBHEADER_HARQ_REORDER:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_pdu_sn_ext_subheader_reorder, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_MBS_CONTENTS_ID:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_mbs_contents_ids, tvb, offset-tlv_value_offset, ENC_NA);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
				for(i = 0; i < tlv_len; i+=2)
					proto_tree_add_item(tlv_tree, hf_sfe_mbs_contents_ids_id, tvb, (offset+i), 2, ENC_BIG_ENDIAN);
			break;
			case SFE_HARQ_SERVICE_FLOWS:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_harq_service_flows, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case SFE_AUTHORIZATION_TOKEN:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_authorization_token, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case SFE_HARQ_CHANNEL_MAPPING:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_sfe_harq_channel_mapping_index, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_wimax_service_flow_encodings);
				for(i = 0; i < tlv_len; i++)
					proto_tree_add_item(tlv_tree, hf_sfe_harq_channel_mapping_index, tvb, (offset+i), 1, ENC_BIG_ENDIAN);
			break;
/* 99 - 111 CS parameter encodings */
			case SFE_CSPER_ATM:
			case SFE_CSPER_PACKET_IPV4:
			case SFE_CSPER_PACKET_IPV6:
			case SFE_CSPER_PACKET_802_3:
			case SFE_CSPER_PACKET_802_1Q:
			case SFE_CSPER_PACKET_IPV4_802_3:
			case SFE_CSPER_PACKET_IPV6_802_3:
			case SFE_CSPER_PACKET_IPV4_802_1Q:
			case SFE_CSPER_PACKET_IPV6_802_1Q:
			case SFE_CSPER_PACKET_IP_ROCH_COMPRESSION:
			case SFE_CSPER_PACKET_IP_ECRTP_COMPRESSION:
			case SFE_CSPER_PACKET_IP_802_3_ROCH_COMPRESSION:
			case SFE_CSPER_PACKET_IP_802_3_ECRTP_COMPRESSION:
				/* call CS Parameter Encoding Rules handling function */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_wimax_service_flow_encodings, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "CS Parameter Encoding Rules");
				wimax_convengence_service_parameter_encoding_rules_decoder(tlv_type, tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_sfe_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
			break;
		}	/* end of switch */
		offset += tlv_len;
        }	/* end of while loop */
}

/**************************************************************/
/* wimax_hmac_tuple_decoder()                                 */
/* decode and display the WiMax HMAC Tuple (Table 348)        */
/* parameter:                                                 */
/*   tree - pointer of Wireshark display tree                 */
/*   tvb - pointer of the tvb which contains the HMAC Tuple   */
/*   offset - the HMAC Tuple offset in the tvb                */
/*   length - length of the HMAC Tuple                        */
/**************************************************************/
void wimax_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length)
{
	guint hmac_offset;
	proto_item *hmac_item = NULL;
	proto_tree *hmac_tree = NULL;

	/* display decoder info (length should be 21 bytes) */
	hmac_item = proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, length, "HMAC Tuple (%u bytes)", length);
	/* add HMAC subtree */
	hmac_tree = proto_item_add_subtree(hmac_item, ett_wimax_hmac_tuple);
	/* init the local offset */
	hmac_offset = offset;
	/* decode and display HMAC Tuple */
	proto_tree_add_item(hmac_tree, hf_xmac_tuple_rsvd, tvb, hmac_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(hmac_tree, hf_xmac_tuple_key_seq_num, tvb, hmac_offset, 1, ENC_BIG_ENDIAN);
	hmac_offset++;
	proto_tree_add_item(hmac_tree, hf_hmac_tuple_hmac_digest, tvb, hmac_offset, (length-1), ENC_NA);
}

/**************************************************************/
/* wimax_cmac_tuple_decoder()                                 */
/* decode and display the WiMax CMAC Tuple (Table 348b)       */
/* parameter:                                                 */
/*   tree - pointer of Wireshark display tree                 */
/*   tvb - pointer of the tvb which contains the CMAC Tuple   */
/*   offset - the CMAC Tuple offset in the tvb                */
/*   length - length of the CMAC Tuple                        */
/**************************************************************/
void wimax_cmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length)
{
	guint cmac_offset;
	proto_item *cmac_item = NULL;
	proto_tree *cmac_tree = NULL;

	/* display decoder info (length should be 13 or 19 bytes) */
	cmac_item = proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, length, "CMAC Tuple (%u bytes)", length);
	/* add CMAC subtree */
	cmac_tree = proto_item_add_subtree(cmac_item, ett_wimax_cmac_tuple);
	/* init the local offset */
	cmac_offset = offset;
	/* decode and display CMAC Tuple */
	proto_tree_add_item(cmac_tree, hf_xmac_tuple_rsvd, tvb, cmac_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(cmac_tree, hf_xmac_tuple_key_seq_num, tvb, cmac_offset, 1, ENC_BIG_ENDIAN);
	cmac_offset++;
	if(length > 13)
	{
		proto_tree_add_item(cmac_tree, hf_cmac_tuple_bsid, tvb, cmac_offset, 6, ENC_NA);
		cmac_offset += 6;
	}
	proto_tree_add_item(cmac_tree, hf_packet_number_counter, tvb, cmac_offset, 4, ENC_BIG_ENDIAN);
	cmac_offset += 4;
	proto_tree_add_item(cmac_tree, hf_cmac_tuple_cmac_value, tvb, cmac_offset, 8, ENC_NA);
}

/******************************************************************/
/* wimax_short_hmac_tuple_decoder()                               */
/* decode and display the WiMax Short-HMAC Tuple (Table 348d)     */
/* parameter:                                                     */
/*   tree - pointer of Wireshark display tree                     */
/*   tvb - pointer of the tvb which contains the Short-HMAC Tuple */
/*   offset - the Short-HMAC Tuple offset in the tvb              */
/*   length - length of the Short-HMAC Tuple                      */
/******************************************************************/
void wimax_short_hmac_tuple_decoder(proto_tree *tree, tvbuff_t *tvb, guint offset, guint length)
{
	guint hmac_offset;
	proto_item *hmac_item = NULL;
	proto_tree *hmac_tree = NULL;

	/* display decoder info (length should be at least 13 bytes ???) */
	hmac_item = proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, length, "Short-HMAC Tuple (%u bytes)", length);
	/* add Short-HMAC subtree */
	hmac_tree = proto_item_add_subtree(hmac_item, ett_wimax_short_hmac_tuple);
	/* init the local offset */
	hmac_offset = offset;
	/* decode and display Short-HMAC Tuple */
	proto_tree_add_item(hmac_tree, hf_xmac_tuple_rsvd, tvb, hmac_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(hmac_tree, hf_xmac_tuple_key_seq_num, tvb, hmac_offset, 1, ENC_BIG_ENDIAN);
	hmac_offset++;
	proto_tree_add_item(hmac_tree, hf_packet_number_counter, tvb, hmac_offset, 4, ENC_BIG_ENDIAN);
	hmac_offset += 4;
	proto_tree_add_item(hmac_tree, hf_hmac_tuple_hmac_digest, tvb, hmac_offset, length - offset - 3, ENC_NA);
}

/******************************************************************/
/* wimax_security_negotiation_parameters_decoder()                */
/* decode and display the WiMax Security Negotiation Parameters   */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_security_negotiation_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Security Negotiation Parameters");
		return;
	}
	/* process Security Negotiation Parameter TLVs */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Security Negotiation Params TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Security Negotiation Parameters Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* update the offset */
		offset += tlv_value_offset;
		/* parse Security Negotiation Parameters TLVs */
		switch (tlv_type)
		{
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PKM_VERSION_SUPPORT:
			/* add TLV subtree */
			tlv_item = add_tlv_subtree(&tlv_info, tree, hf_snp_pkm_version_support, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			tlv_tree = proto_item_add_subtree(tlv_item, ett_security_negotiation_parameters);
			proto_tree_add_item(tlv_tree, hf_snp_pkm_version_support_bit0, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_pkm_version_support_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_pkm_version_support_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
		break;
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_AUTHORIZATION_POLICY_SUPPORT:
			/* add TLV subtree */
			tlv_item = add_tlv_subtree(&tlv_info, tree, hf_snp_auth_policy_support, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			tlv_tree = proto_item_add_subtree(tlv_item, ett_security_negotiation_parameters);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit0, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit2, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit3, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit4, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit5, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit6, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_auth_policy_support_bit7, tvb, offset, 1, ENC_BIG_ENDIAN);
		break;
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_MESSAGE_AUTHENTICATION_CODE:
			/* add TLV subtree */
			tlv_item = add_tlv_subtree(&tlv_info, tree, hf_snp_mac_mode, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			tlv_tree = proto_item_add_subtree(tlv_item, ett_security_negotiation_parameters);
			proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit0, tvb, offset, 1, ENC_BIG_ENDIAN);
			if (include_cor2_changes)
			{
				proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit1_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit1, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit2, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit3, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit4, tvb, offset, 1, ENC_BIG_ENDIAN);
			if (include_cor2_changes)
			{
				proto_tree_add_item(tlv_tree, hf_snp_mac_mode_bit5, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_snp_mac_mode_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(tlv_tree, hf_snp_mac_mode_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
			}
		break;
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PN_WINDOW_SIZE:
			add_tlv_subtree(&tlv_info, tree, hf_snp_pn_window_size, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
		break;
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_PKM_FLOW_CONTROL:
			add_tlv_subtree(&tlv_info, tree, hf_snp_max_conc_transactions, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
		break;
		case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETER_SUB_MAX_SUPPT_SECURITY_ASSNS:
			add_tlv_subtree(&tlv_info, tree, hf_snp_max_suppt_sec_assns, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
		break;
		default:
			add_tlv_subtree(&tlv_info, tree, hf_snp_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
		break;
		}
		offset += tlv_len;
	}
}

/******************************************************************/
/* wimax_cryptographic_suite_list_decoder()                       */
/* decode and display the WiMax Cryptographic Suite List           */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_cryptographic_suite_list_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Crypto Suite List");
		return;
	}
	/* process Cryptographic Suite List (11.9.15) */
	for(offset = 0; offset < tvb_len; )
	{	/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Crypto Suite List TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Cryptographic Suite List TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* update the offset for the TLV value */
		offset += tlv_value_offset;
		/* parse Cryptographic Suite List */
		switch (tlv_type)
		{
			case PKM_ATTR_CRYPTO_SUITE:
				/* add subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_crypto_suite, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_cryptographic_suite_list_decoder);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_msb, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_middle, tvb, offset+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_lsb, tvb, offset+2, 1, ENC_BIG_ENDIAN);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
			break;
		}
		offset += tlv_len;
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_pkm_tlv_encoded_attributes_decoder()                     */
/* decode and display the WiMax PKM message TLV Encoded Attributes*/
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_pkm_tlv_encoded_attributes_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid PKM TLV");
		return;
	}
	/* process PKM message TLV Encoded Attributes (11.9) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PKM TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "PKM TLV Encoded Attributes TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* update the offset for the TLV value */
		offset += tlv_value_offset;
		/* parse PKM TLV Encoded Attributes (table 370) */
		switch (tlv_type)
		{
			case PKM_ATTR_DISPLAY_STRING:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_display, tvb, offset-tlv_value_offset, ENC_ASCII|ENC_NA);
			break;
			case PKM_ATTR_AUTH_KEY:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_auth_key, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_TEK:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_tek, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_KEY_LIFE_TIME:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_key_life_time, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_KEY_SEQ_NUM:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_key_seq_num, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_HMAC_DIGEST:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_hmac_digest, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_SAID:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_said, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_TEK_PARAM:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "TEK Parameters");
				/* add subtree */
				wimax_tek_parameters_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_CBC_IV:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_cbc_iv, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_ERROR_CODE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_error_code, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_CA_CERTIFICATE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_ca_certificate, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_SS_CERTIFICATE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_ss_certificate, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_SECURITY_CAPABILITIES:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Security Capabilities");
				/* add subtree */
				wimax_security_capabilities_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_CRYPTO_SUITE:
				/* add subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_crypto_suite, tvb, offset-tlv_value_offset, ENC_NA);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_pkm_tlv_encoded_attributes_decoder);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_msb, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_middle, tvb, offset+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_lsb, tvb, offset+2, 1, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_CRYPTO_LIST:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Cryptographic-Suite List");
				/* add subtree */
				wimax_cryptographic_suite_list_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
#if 0 /* rserved by IEE 802.16E */
			case PKM_ATTR_VERSION:
				proto_tree_add_item(tree, hf_pkm_msg_version, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
			break;
#endif
			case PKM_ATTR_SA_DESCRIPTOR:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "SA-Descriptor");
				/* add subtree */
				wimax_sa_descriptor_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_SA_TYPE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_sa_type, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_SECURITY_NEGOTIATION_PARAMETERS:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Security Negotiation Parameters");
				/* add subtree */
				wimax_security_negotiation_parameters_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS:
				/* add subtree */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_pkm_tlv_encoded_attributes_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "PKM Configuration Settings");
				wimax_pkm_configuration_settings_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_PKM_EAP_PAYLOAD:
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_eap_payload, tvb, offset-tlv_value_offset, ENC_NA);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_pkm_tlv_encoded_attributes_decoder);
				if (eap_handle)
					call_dissector(eap_handle, tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case PKM_ATTR_PKM_NONCE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_nonce, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_AUTH_RESULT_CODE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_auth_result_code, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_SA_SERVICE_TYPE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_sa_service_type, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_FRAME_NUMBER:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_frame_number, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_SS_RANDOM:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_ss_random, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_BS_RANDOM:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_bs_random, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_PRE_PAK:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_pre_pak, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_BS_CERTIFICATE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_bs_certificate, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_SIG_BS:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_sig_bs, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_MS_MAC_ADDRESS:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_ms_mac_address, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_CMAC_DIGEST:
				/* add TLV subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_cmac_digest, tvb, offset-tlv_value_offset, ENC_NA);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_pkm_tlv_encoded_attributes_decoder);
				proto_tree_add_item(tlv_tree, hf_pkm_attr_cmac_digest_pn, tvb, offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_attr_cmac_digest_value, tvb, (offset + 4), 8, ENC_NA);
			break;
			case PKM_ATTR_KEY_PUSH_MODES:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_push_modes, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_KEY_PUSH_COUNTER:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_key_push_counter, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_GKEK:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_gkek, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_SIG_SS:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_sig_ss, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case PKM_ATTR_AKID:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_akid, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
			break;
		}
		offset += tlv_len;
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_tek_parameters_decoder()                                 */
/* decode and display the WiMax TEK Parameters subattributes      */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_tek_parameters_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid TEK Params");
		return;
	}
	/* process PKM Message TEK Parameters (11.9.8) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "TEK Param TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "TEK Parameters Subattributes TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* parse TEK Parameters Subattributes (table 372) */
		switch (tlv_type)
		{
			case PKM_ATTR_TEK:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_tek, tvb, offset, ENC_NA);
			break;
			case PKM_ATTR_KEY_LIFE_TIME:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_key_life_time, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_KEY_SEQ_NUM:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_key_seq_num, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_CBC_IV:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_cbc_iv, tvb, offset, ENC_NA);
			break;
			case PKM_ATTR_ASSOCIATED_GKEK_SEQ_NUM:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_associated_gkek_seq_number, tvb, offset, ENC_NA);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset, ENC_NA);
			break;
		}
		offset += (tlv_len+tlv_value_offset);
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_pkm_configuration_settings_decoder()                     */
/* decode and display the WiMax PKM Configuration Settings        */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_pkm_configuration_settings_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid PKM Config Settings");
		return;
	}
	/* process PKM Configuration Settings (11.9.19) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PKM Config Settings TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "PKM Configuration Settings TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* parse PKM Configuration Settings (11.9.19.1 - 11.9.19.7 */
		switch (tlv_type)
		{
			case PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZE_WAIT_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_authorize_waitout, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_REAUTHORIZE_WAIT_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_reauthorize_waitout, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZATION_GRACE_TIME:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_grace_time, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_OPERATIONAL_WAIT_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_operational_waittime, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_REKEY_WAIT_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_rekey_wait_timeout, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_TEK_GRACE_TIME:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_tek_grace_time, tvb, offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_PKM_CONFIG_SETTINGS_AUTHORIZE_REJECT_WAIT_TIMEOUT:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_config_settings_authorize_reject_wait_timeout, tvb, offset, ENC_BIG_ENDIAN);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset, ENC_NA);
			break;
		}
		offset += (tlv_len+tlv_value_offset);
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_sa_descriptor_decoder()                                  */
/* decode and display the WiMax PKM message SA-Descriptor         */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_sa_descriptor_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid SA-Descriptor");
		return;
	}
	/* process SA-Descriptor (11.9.17) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "SA-Descriptor TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "SA-Descriptor TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* update the offset for the TLV value */
		offset += tlv_value_offset;
		/* parse SA-Descriptor (table 380) */
		switch (tlv_type)
		{
			case PKM_ATTR_SAID:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_attr_said, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_SA_TYPE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_sa_type, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_SA_SERVICE_TYPE:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_attr_sa_service_type, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case PKM_ATTR_CRYPTO_SUITE:
				/* add subtree */
				tlv_item = add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_crypto_suite, tvb, offset-tlv_value_offset, ENC_NA);
				tlv_tree = proto_item_add_subtree(tlv_item, ett_sa_descriptor_decoder);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_msb, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_middle, tvb, offset+1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tlv_tree, hf_pkm_msg_crypto_suite_lsb, tvb, offset+2, 1, ENC_BIG_ENDIAN);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset-tlv_value_offset, ENC_NA);
			break;
		}
		offset += tlv_len;
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_security_capabilities_decoder()                          */
/* decode and display the WiMax Security Capabilities             */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_security_capabilities_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Security Capabilities");
		return;
	}
	/* process Security Capabilities (11.9.13) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Security Capabilities TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Security Capabilities TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* parse Security Capabilities (table 374) */
		switch (tlv_type)
		{
			case PKM_ATTR_CRYPTO_LIST:
				tlv_tree = add_protocol_subtree(&tlv_info, ett_security_capabilities_decoder, tree, proto_wimax_utility_decoders, tvb, offset, tlv_len, "Cryptographic-Suite List");
				/* add subtree */
				wimax_cryptographic_suite_list_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			default:
				add_tlv_subtree(&tlv_info, tree, hf_pkm_msg_unknown_type, tvb, offset, ENC_NA);
			break;
		}
		offset += (tlv_len+tlv_value_offset);
	}	/* end of TLV process while loop */
}

/******************************************************************/
/* wimax_vendor_specific_information_decoder()                    */
/* decode and display the WiMax Vendor-Specific Information       */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
void wimax_vendor_specific_information_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	tlv_info_t tlv_info;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Vendor Specific Info");
		proto_tree_add_text(tree, tvb, 0, tvb_len, "Invalid TLV info");
		return;
	}
	/* process Vendor Specific Information (11.1.6) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Vendor Specific Info TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Vendor Specific Info TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* parse Vendor Specific Information (11.1.6) */
		if(tlv_type == VENDOR_ID_ENCODING)
		{
			/* decode and display the Vendor ID Encoding */
			add_tlv_subtree(&tlv_info, tree, hf_common_tlv_vendor_id, tvb, offset, ENC_NA);
		}
		else
		{
			/* decode and display the Vendor Specific Info */
			proto_tree_add_item(tree, hf_common_tlv_vendor_specific_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			if(get_tlv_length_type(&tlv_info) == 0)
			{	/* single byte TLV length */
				proto_tree_add_item(tree, hf_common_tlv_vendor_specific_length, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
			}
			else
			{	/* multiple bytes TLV length */
				/* display the length of the TLV length with MSB */
				proto_tree_add_item(tree, hf_common_tlv_vendor_specific_length_size, tvb, (offset + 1), 1, ENC_BIG_ENDIAN);
				if(get_tlv_size_of_length(&tlv_info))
				{	/* display the multiple byte TLV length */
					proto_tree_add_text(tree, tvb, (offset + 2), get_tlv_size_of_length(&tlv_info), "Vendor Specific Length: %u", get_tlv_size_of_length(&tlv_info));
				}
				else
				{	/* length = 0 */
					continue;
				}
			}
			proto_tree_add_item(tree, hf_common_tlv_vendor_specific_value, tvb, (offset + tlv_value_offset), tlv_len, ENC_NA);
		}
		/* update the offset */
		offset += tlv_value_offset + tlv_len;
	}
}

/******************************************************************/
/* wimax_common_tlv_encoding_decoder()                            */
/* decode and display the WiMax Common TLV Encoding (Table 346)   */
/* parameter:                                                     */
/*   tvb - pointer of the tvb of service flow encodings           */
/*   tree - pointer of Wireshark display tree                     */
/*   pinfo - pointer of Wireshark packet information structure    */
/******************************************************************/
guint wimax_common_tlv_encoding_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset, value;
	guint tvb_len, tlv_len, tlv_value_offset;
	gint  tlv_type;
	proto_tree *tlv_tree = NULL;
	tlv_info_t tlv_info;
	gfloat current_power;

	/* get the tvb reported length */
	tvb_len = tvb_reported_length(tvb);
	/* do nothing if the TLV fields is not exist */
	if(!tvb_len)
		return 0;
	/* report error if the packet size is less than 2 bytes (type+length) */
	if(tvb_len < 2)
	{	/* invalid tlv info */
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid Common TLV encoding");
		proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, 0, tvb_len, ENC_NA);
		return 0;
	}
	/* process Common TLV Encoding (11.1) */
	for(offset = 0; offset < tvb_len; )
	{
		/* get the TLV information */
		init_tlv_info(&tlv_info, tvb, offset);
		/* get the TLV type */
		tlv_type = get_tlv_type(&tlv_info);
		/* get the TLV length */
		tlv_len = get_tlv_length(&tlv_info);
		if(tlv_type == -1 || tlv_len > MAX_TLV_LEN || tlv_len < 1)
		{	/* invalid tlv info */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Common TLV encoding TLV error");
			proto_tree_add_item(tree, hf_cst_invalid_tlv, tvb, offset, (tvb_len - offset), ENC_NA);
			break;
		}
		/* get the TLV value offset */
		tlv_value_offset = get_tlv_value_offset(&tlv_info);
#ifdef DEBUG /* for debug only */
		proto_tree_add_protocol_format(tree, proto_wimax_utility_decoders, tvb, offset, (tlv_len + tlv_value_offset), "Common TLV Encoding TLV Type: %u (%u bytes, offset=%u, tvb_len=%u)", tlv_type, (tlv_len + tlv_value_offset), offset, tvb_len);
#endif
		/* update the offset for the TLV value */
		offset += tlv_value_offset;
		/* parse Common TLV Encoding (table 346) */
		switch (tlv_type)
		{
			case VENDOR_SPECIFIC_INFO:
				/* display Vendor-Specific Information */
				/* add subtree */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_vendor_specific_info_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Vendor-Specific Information");
				/* decode and display the Vendor-Specific Information */
				wimax_vendor_specific_information_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case VENDOR_ID_ENCODING:
				add_tlv_subtree(&tlv_info, tree, hf_common_tlv_vendor_id, tvb, offset-tlv_value_offset, ENC_NA);
			break;
			case DSx_UPLINK_FLOW:
				/* display Uplink Service Flow Encodings info */
				/* add subtree */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_ul_service_flow_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Uplink Service Flow Encodings");
				/* decode and display the UL Service Flow Encodings */
				wimax_service_flow_encodings_decoder(tvb_new_subset_length(tvb, offset, tlv_len), pinfo, tlv_tree);
			break;
			case DSx_DOWNLINK_FLOW:
				/* display Downlink Service Flow Encodings info */
				/* add subtree */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_dl_service_flow_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "Downlink Service Flow Encodings");
				/* decode and display the DL Service Flow Encodings */
				wimax_service_flow_encodings_decoder(tvb_new_subset_length(tvb,offset, tlv_len), pinfo, tlv_tree);
			break;
			case CURRENT_TX_POWER:
				tlv_tree = add_tlv_subtree_no_item(&tlv_info, tree, hf_common_current_transmitted_power, tvb, offset-tlv_value_offset);
				value = tvb_get_guint8(tvb, offset);
				current_power = (gfloat)((value - 128) / 2.0);
				proto_tree_add_float_format_value(tlv_tree, hf_common_current_transmitted_power, tvb, offset, tvb_len, current_power, "%.2f dBm (Value: 0x%x)", current_power, value);
			break;
			case MAC_VERSION_ENCODING:
				add_tlv_subtree(&tlv_info, tree, hf_common_tlv_mac_version, tvb, offset-tlv_value_offset, ENC_BIG_ENDIAN);
			break;
			case HMAC_TUPLE:	/* Table 348d */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_vendor_specific_info_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "HMAC Tuple");
				/* decode and display the HMAC Tuple */
				wimax_hmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
			break;
			case CMAC_TUPLE:	/* Table 348b */
				tlv_tree = add_protocol_subtree(&tlv_info, ett_vendor_specific_info_decoder, tree, proto_wimax_utility_decoders, tvb, offset-tlv_value_offset, tlv_len, "CMAC Tuple");
				/* decode and display the CMAC Tuple */
				wimax_cmac_tuple_decoder(tlv_tree, tvb, offset, tlv_len);
			break;
			default:
				/* Back to calling routine to finish decoding. */
				return offset - tlv_value_offset;  /* Ret amount decoded. */
			break;
		}
		offset += tlv_len;
	}	/* end of while loop */
	return offset;
}

/* packet-rsvp.c
 * Routines for RSVP packet disassembly
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * NOTES
 *
 * This module defines routines to disassemble RSVP packets, as defined in
 * RFC 2205. All objects from RFC2205 are supported, in IPv4 and IPv6 mode.
 * In addition, the Integrated Services traffic specification objects
 * defined in RFC2210 are also supported.
 *
 * IPv6 support is not completely tested
 *
 * Mar 3, 2000: Added support for MPLS/TE objects, as defined in
 * <draft-ietf-mpls-rsvp-lsp-tunnel-04.txt>
 *
 * May 6, 2004: Added support for E-NNI objects, as defined in
 * <OIF-E-NNI-01.0>   (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * May 6, 2004: Modified some UNI objects, as defined in
 * <OIF2003.249.09>   (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * June 2, 2005: Modified more UNI objects to show correct TNA
 * addresses; Fixed LSP interface ID subobject (Richard Rabbat)
 * <richard[AT]us.fujitsu.com>
 *
 * July 25, 2005: improved ERROR and LABEL_SET objects dissector;
 * new ASSOCIATION object dissector (Roberto Morro)
 * <roberto.morro[AT]tilab.com>
 *
 * August 22, 2005: added support for tapping and conversations.
 * (Manu Pathak) <mapathak[AT]cisco.com>
 *
 * July 4, 2006: added support for RFC4124; new CLASSTYPE object dissector
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * June 9, 2007: added support for draft-ietf-ccamp-ethernet-traffic-parameters-02
 * and draft-ietf-ccamp-lsp-hierarchy-bis-02; added support for NOTIFY_REQUEST
 * and RECOVERY_LABEL objects (Roberto Morro) * <roberto.morro[AT]tilab.com>
 *
 * Oct 21, 2009: add support for RFC4328, new G.709 traffic parameters,
 * update gpid, switching and encoding type values to actual IANA numbers.
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Gen 20, 2010: add support for ERROR_STRING IF_ID TLV (see RFC 4783)
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Feb 12, 2010: add support for generalized label interpretation: SUKLM
 * format for SONET/SDH label (RFC 4606), t3t2t1 format for G.709 ODUk label
 * (RFC 4328), G.694 format for lambda label (draft-ietf-ccamp-gmpls-g-694-lamb
 * da-labels-05).  Add related user preference option.
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Dec 3, 2010: add support for vendor private class object and ERO/RRO
 * sub-object (see RFC 3936).
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Dec 21, 2010: add new PROTECTION obj c-type 2 (RFC4872),
 * new TLVs for IF_ID (RFC4920), Path Key subobj in ERO (RFC5520),
 * new ASSOCIATION obj c-type 4 (oif2008.389), new LSP_ATTRIBUTES and
 * LSP_REQUIRED_ATTRIBUTES objects (RFC5420), improved ERROR object dissection,
 * new ADMIN_STATUS flags and fix to conversation (not applied to ACK, SREFRESH
 * and HELLO messages).
 * (Roberto Morro) <roberto.morro[AT]telecomitalia.it>
 *
 * Jul 20, 2013: add support for Exclude Routes (XRO) (see RFC 4874)
 * (FF) <francesco.fondelli[AT]gmail.com>
 *
 * Added support for "Ethernet line" LSP encoding (RFC 6004)
 * Added support for flexi-grid label (RFC 7699)
 * Added support for codepoint for network-assigned label (RFC 8359)
 * Added support for clean-up and bug fixes on ERO/RRO/XRO
 * Added support for full support of RFC 8001, including error code
 *   - (c) 2018 Julien Meuric <julien.meuric@orange.com>
 *   - (c) 2018 Khalifa Ndiaye <khalifa.ndiaye@orange.com>
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/in_cksum.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/tap.h>
#include <epan/addr_resolv.h>
#include "packet-rsvp.h"
#include "packet-ip.h"
#include "packet-diffserv-mpls-common.h"
#include "packet-osi.h"

/* RSVP over UDP encapsulation */
#define UDP_PORT_PRSVP 3455

void proto_register_rsvp(void);
void proto_reg_handoff_rsvp(void);

static int proto_rsvp = -1;
static int proto_rsvp_e2e1 = -1;

static int hf_rsvp_error_flags = -1;
static int hf_rsvp_error_flags_path_state_removed = -1;
static int hf_rsvp_error_flags_not_guilty = -1;
static int hf_rsvp_error_flags_in_place = -1;
static int hf_rsvp_eth_tspec_tlv_color_mode = -1;
static int hf_rsvp_eth_tspec_tlv_coupling_flag = -1;
static int hf_rsvp_sender_tspec_standard_contiguous_concatenation = -1;
static int hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation = -1;
static int hf_rsvp_sender_tspec_regenerator_section = -1;
static int hf_rsvp_sender_tspec_multiplex_section = -1;
static int hf_rsvp_sender_tspec_J0_transparency = -1;
static int hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency = -1;
static int hf_rsvp_sender_tspec_K1_K2_transparency = -1;
static int hf_rsvp_sender_tspec_E1_transparency = -1;
static int hf_rsvp_sender_tspec_F1_transparency = -1;
static int hf_rsvp_sender_tspec_E2_transparency = -1;
static int hf_rsvp_sender_tspec_B1_transparency = -1;
static int hf_rsvp_sender_tspec_B2_transparency = -1;
static int hf_rsvp_sender_tspec_M0_transparency = -1;
static int hf_rsvp_sender_tspec_M1_transparency = -1;
static int hf_rsvp_flowspec_standard_contiguous_concatenation = -1;
static int hf_rsvp_flowspec_arbitrary_contiguous_concatenation = -1;
static int hf_rsvp_flowspec_regenerator_section = -1;
static int hf_rsvp_flowspec_multiplex_section = -1;
static int hf_rsvp_flowspec_J0_transparency = -1;
static int hf_rsvp_flowspec_SOH_RSOH_DCC_transparency = -1;
static int hf_rsvp_flowspec_LOH_MSOH_DCC_transparency = -1;
static int hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency = -1;
static int hf_rsvp_flowspec_K1_K2_transparency = -1;
static int hf_rsvp_flowspec_E1_transparency = -1;
static int hf_rsvp_flowspec_F1_transparency = -1;
static int hf_rsvp_flowspec_E2_transparency = -1;
static int hf_rsvp_flowspec_B1_transparency = -1;
static int hf_rsvp_flowspec_B2_transparency = -1;
static int hf_rsvp_flowspec_M0_transparency = -1;
static int hf_rsvp_flowspec_M1_transparency = -1;
static int hf_rsvp_integrity_flags_handshake = -1;
static int hf_rsvp_sa_flags_local = -1;
static int hf_rsvp_sa_flags_label = -1;
static int hf_rsvp_sa_flags_se_style = -1;
static int hf_rsvp_sa_flags_bandwidth = -1;
static int hf_rsvp_sa_flags_node = -1;
static int hf_rsvp_rro_flags_local_avail = -1;
static int hf_rsvp_rro_flags_local_in_use = -1;
static int hf_rsvp_rro_flags_bandwidth = -1;
static int hf_rsvp_rro_flags_node = -1;
static int hf_rsvp_rro_flags_node_address = -1;
static int hf_rsvp_rro_flags_backup_tunnel_bandwidth = -1;
static int hf_rsvp_rro_flags_backup_tunnel_hop = -1;
static int hf_rsvp_rro_flags_global_label = -1;
static int hf_rsvp_lsp_attr = -1;
static int hf_rsvp_lsp_attr_e2e = -1;
static int hf_rsvp_lsp_attr_boundary = -1;
static int hf_rsvp_lsp_attr_segment = -1;
static int hf_rsvp_lsp_attr_integrity = -1;
static int hf_rsvp_lsp_attr_contiguous = -1;
static int hf_rsvp_lsp_attr_stitching = -1;
static int hf_rsvp_lsp_attr_preplanned = -1;
static int hf_rsvp_lsp_attr_nophp = -1;
static int hf_rsvp_lsp_attr_oobmap = -1;
static int hf_rsvp_lsp_attr_entropy = -1;
static int hf_rsvp_lsp_attr_oammep = -1;
static int hf_rsvp_lsp_attr_oammip = -1;
static int hf_rsvp_lsp_attr_loopback = -1;
static int hf_rsvp_lsp_attr_p2mp = -1;
static int hf_rsvp_lsp_attr_rtm = -1;
static int hf_rsvp_lsp_attr_lsi = -1;
static int hf_rsvp_lsp_attr_lsids2e = -1;
static int hf_rsvp_lsp_attr_telinklabel = -1;
static int hf_rsvp_lsp_attr_srlgcollect = -1;
static int hf_rsvp_gen_uni_direction = -1;
static int hf_rsvp_protection_info_flags_secondary_lsp = -1;
static int hf_rsvp_pi_link_flags_extra_traffic = -1;
static int hf_rsvp_pi_link_flags_unprotected = -1;
static int hf_rsvp_pi_link_flags_shared = -1;
static int hf_rsvp_pi_link_flags_dedicated1_1 = -1;
static int hf_rsvp_pi_link_flags_dedicated1plus1 = -1;
static int hf_rsvp_pi_link_flags_enhanced = -1;
static int hf_rsvp_pi_link_flags_extra = -1;
static int hf_rsvp_pi_link_flags_dedicated_1_1 = -1;
static int hf_rsvp_pi_link_flags_dedicated_1plus1 = -1;
static int hf_rsvp_rfc4872_secondary = -1;
static int hf_rsvp_rfc4872_protecting = -1;
static int hf_rsvp_rfc4872_notification_msg = -1;
static int hf_rsvp_rfc4872_operational = -1;
static int hf_rsvp_pi_lsp_flags_full_rerouting = -1;
static int hf_rsvp_pi_lsp_flags_rerouting_extra = -1;
static int hf_rsvp_pi_lsp_flags_1_n_protection = -1;
static int hf_rsvp_pi_lsp_flags_1plus1_unidirectional = -1;
static int hf_rsvp_pi_lsp_flags_1plus1_bidirectional = -1;
static int hf_rsvp_protection_info_in_place = -1;
static int hf_rsvp_protection_info_required = -1;
static int hf_rsvp_pi_seg_flags_full_rerouting = -1;
static int hf_rsvp_pi_seg_flags_rerouting_extra = -1;
static int hf_rsvp_pi_seg_flags_1_n_protection = -1;
static int hf_rsvp_pi_seg_flags_1plus1_unidirectional = -1;
static int hf_rsvp_pi_seg_flags_1plus1_bidirectional = -1;
static int hf_rsvp_frr_flags_one2one_backup = -1;
static int hf_rsvp_frr_flags_facility_backup = -1;
static int hf_rsvp_type = -1;
static int hf_rsvp_3gpp_obj_tid = -1;
static int hf_rsvp_3gpp_obj_ie_len = -1;
static int hf_rsvp_3gpp_obj_ie_type = -1;
static int hf_rsvp_3gpp_obj_ue_ipv4_addr = -1;
static int hf_rsvp_3gpp_obj_ue_ipv6_addr = -1;
static int hf_rsvp_3gpp_obj_tft_d = -1;
static int hf_rsvp_3gpp_obj_tft_ns = -1;
static int hf_rsvp_3gpp_obj_tft_sr_id = -1;
static int hf_rsvp_3gpp_obj_tft_p = -1;
static int hf_rsvp_3gpp_obj_tft_opcode = -1;
static int hf_rsvp_3gpp_obj_tft_n_pkt_flt = -1;
static int hf_rsvp_3gpp_obj_flow_id = -1;
static int hf_rsvp_3gpp_obj_pf_ev_prec = -1;
static int hf_rsvp_3gpp_obj_pf_len = -1;
static int hf_rsvp_3gpp_obj_pf_type = -1;
static int hf_rsvp_3gpp_obj_pf_cont_len = -1;
static int hf_rsvp_3gpp_obj_pf_comp_type_id = -1;
static int hf_rsvp_3gpp_obj_pf_src_ipv4 = -1;
static int hf_rsvp_3gpp_obj_pf_dst_ipv4 = -1;
static int hf_rsvp_3gpp_obj_pf_ipv4_mask = -1;
static int hf_rsvp_3gpp_obj_pf_src_ipv6 = -1;
static int hf_rsvp_3gpp_obj_pf_dst_ipv6 = -1;
static int hf_rsvp_3gpp_obj_pf_ipv6_prefix_length = -1;
static int hf_rsvp_3gpp_obj_pf_prot_next = -1;
static int hf_rsvp_3gpp_obj_pf_dst_port = -1;
static int hf_rsvp_3gpp_obj_pf_src_port = -1;
static int hf_rsvp_3gpp_obj_pf_ipsec_spi = -1;
static int hf_rsvp_3gpp_obj_pf_tos_tc = -1;
static int hf_rsvp_3gpp_obj_pf_flow_lbl = -1;
static int hf_rsvp_3gpp_obj_pf_ipv6 = -1;
static int hf_rsvp_3gpp_obj_pf_treatment = -1;
static int hf_rsvp_3gpp_obj_pf_hint = -1;
static int hf_rsvp_3gpp_obj_tft_qos_list_len = -1;
static int hf_rsvp_3gpp_r_qos_blob_len = -1;
static int hf_rsvp_3gpp_r_qos_blob_flow_pri = -1;
static int hf_rsvp_3gpp_r_qos_blob_num_qos_att_set = -1;
static int hf_rsvp_3gpp_qos_att_set_len = -1;
static int hf_rsvp_3gpp_qos_attribute_set_id = -1;
static int hf_rsvp_3gpp_qos_attribute_verbose = -1;
static int hf_rsvp_3gpp_qos_attribute_prof_id = -1;
static int hf_rsvp_3gpp_qos_attribute_traff_cls = -1;
static int hf_rsvp_3gpp_qos_attribute_peak_rate = -1;
static int hf_rsvp_3gpp_qos_attribute_bucket_size = -1;
static int hf_rsvp_3gpp_qos_attribute_token_rate = -1;
static int hf_rsvp_3gpp_qos_attribute_max_latency = -1;
static int hf_rsvp_3gpp_qos_attribute_max_loss_rte = -1;
static int hf_rsvp_3gpp_qos_attribute_delay_var_sensitive = -1;
static int hf_rsvp_3gpp_qos_attribute_reserved = -1;
static int hf_rsvp_3gpp_r_qos_blob = -1;
static int hf_rsvp_3gpp_qos_result = -1;
static int hf_rsvp_xro_sobj_lbit = -1;
static int hf_rsvp_rro_sobj_dbit = -1;
static int hf_rsvp_xro_sobj_len = -1;
static int hf_rsvp_xro_sobj_ipv4_addr = -1;
static int hf_rsvp_xro_sobj_ipv4_prefix = -1;
static int hf_rsvp_xro_sobj_ipv4_attr = -1;
static int hf_rsvp_xro_sobj_ipv6_attr = -1;
static int hf_rsvp_xro_sobj_srlg_id = -1;
static int hf_rsvp_xro_sobj_srlg_res = -1;
static int hf_rsvp_private_data = -1;
static int hf_rsvp_juniper_numtlvs = -1;
static int hf_rsvp_juniper_padlength = -1;
static int hf_rsvp_juniper_type = -1;
static int hf_rsvp_juniper_length = -1;
static int hf_rsvp_juniper_attrib_cos = -1;
static int hf_rsvp_juniper_attrib_metric1 = -1;
static int hf_rsvp_juniper_attrib_metric2 = -1;
static int hf_rsvp_juniper_attrib_ccc_status = -1;
static int hf_rsvp_juniper_attrib_path = -1;
static int hf_rsvp_juniper_attrib_unknown = -1;
static int hf_rsvp_juniper_unknown = -1;
static int hf_rsvp_juniper_pad = -1;
static int hf_rsvp_unknown_data = -1;
static int hf_rsvp_ctype = -1;
static int hf_rsvp_ctype_session = -1;
static int hf_rsvp_ctype_scope = -1;
static int hf_rsvp_ctype_label_request = -1;
static int hf_rsvp_ctype_integrity = -1;
static int hf_rsvp_ctype_adspec = -1;
static int hf_rsvp_ctype_tspec = -1;
static int hf_rsvp_ctype_call_id = -1;
static int hf_rsvp_ctype_template = -1;
static int hf_rsvp_ctype_style = -1;
static int hf_rsvp_ctype_policy = -1;
static int hf_rsvp_ctype_error = -1;
static int hf_rsvp_ctype_attribute = -1;
static int hf_rsvp_ctype_explicit_route = -1;
static int hf_rsvp_ctype_flowspec = -1;
static int hf_rsvp_ctype_hop = -1;
static int hf_rsvp_ctype_confirm = -1;
static int hf_rsvp_ctype_time_values = -1;
static int hf_rsvp_ctype_record_route = -1;
static int hf_rsvp_ctype_exclude_route = -1;
static int hf_rsvp_ctype_message_id = -1;
static int hf_rsvp_ctype_message_id_ack = -1;
static int hf_rsvp_ctype_message_id_list = -1;
static int hf_rsvp_ctype_hello = -1;
static int hf_rsvp_ctype_dclass = -1;
static int hf_rsvp_ctype_admin_status = -1;
static int hf_rsvp_ctype_lsp_attributes = -1;
static int hf_rsvp_ctype_label_set = -1;
static int hf_rsvp_ctype_association = -1;
static int hf_rsvp_ctype_tunnel_if_id = -1;
static int hf_rsvp_ctype_3gpp_object = -1;
static int hf_rsvp_ctype_restart_cap = -1;
static int hf_rsvp_ctype_link_cap = -1;
static int hf_rsvp_ctype_protection_info = -1;
static int hf_rsvp_ctype_fast_reroute = -1;
static int hf_rsvp_ctype_detour = -1;
static int hf_rsvp_ctype_diffserv = -1;
static int hf_rsvp_ctype_diffserv_aware_te = -1;
static int hf_rsvp_ctype_vendor = -1;
static int hf_rsvp_ctype_juniper = -1;
static int hf_rsvp_ctype_unknown = -1;
static int hf_rsvp_ctype_label = -1;
static int hf_rsvp_ctype_notify_request = -1;
static int hf_rsvp_ctype_generalized_uni = -1;
static int hf_rsvp_parameter = -1;
static int hf_rsvp_parameter_flags = -1;
static int hf_rsvp_parameter_length = -1;
static int hf_rsvp_error_value = -1;
static int hf_rsvp_class = -1;
static int hf_rsvp_class_length = -1;
static int hf_rsvp_reserved = -1;
static int hf_rsvp_switching_granularity = -1;
static int hf_rsvp_callid_srcaddr_ether = -1;
static int hf_rsvp_callid_srcaddr_bytes = -1;
static int hf_rsvp_loose_hop = -1;
static int hf_rsvp_data_length = -1;

static int hf_rsvp_ctype_s2l_sub_lsp = -1;
static int hf_rsvp_s2l_sub_lsp_destination_ipv4_address = -1;
static int hf_rsvp_s2l_sub_lsp_destination_ipv6_address = -1;
static int hf_rsvp_s2l_sub_lsp_data = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_rsvp_message_id_data = -1;
static int hf_rsvp_ero_rro_subobjects_length = -1;
static int hf_rsvp_fast_reroute_hop_limit = -1;
static int hf_rsvp_lsp_tunnel_if_id_router_id = -1;
static int hf_rsvp_ero_rro_subobjects_path_key = -1;
static int hf_rsvp_ifid_tlv_area = -1;
static int hf_rsvp_session_attribute_include_any = -1;
static int hf_rsvp_lsp_tunnel_if_id_sc_pc_scn_address = -1;
static int hf_rsvp_ero_rro_subobjects_ipv6_hop = -1;
static int hf_rsvp_lsp_tunnel_if_id_ipv6_interface_address = -1;
static int hf_rsvp_lsp_tunnel_if_id_component_link_identifier_ipv4 = -1;
static int hf_rsvp_ifid_tlvinterface_id = -1;
static int hf_rsvp_eth_tspec_cir = -1;
static int hf_rsvp_confirm_receiver_address_ipv6 = -1;
static int hf_rsvp_error_error_node_ipv6 = -1;
static int hf_rsvp_time_values_data = -1;
static int hf_rsvp_flowspec_rate = -1;
static int hf_rsvp_session_attribute_hold_priority = -1;
static int hf_rsvp_notify_request_notify_node_address_ipv4 = -1;
static int hf_rsvp_lsp_tunnel_if_id_action = -1;
static int hf_rsvp_scope_data = -1;
static int hf_rsvp_label_request_l3pid = -1;
static int hf_rsvp_eth_tspec_index = -1;
static int hf_rsvp_integrity_sequence_number = -1;
static int hf_rsvp_adspec_message_format_version = -1;
static int hf_rsvp_fast_reroute_setup_priority = -1;
static int hf_rsvp_eth_tspec_reserved = -1;
static int hf_rsvp_eth_tspec_el2cp = -1;
static int hf_rsvp_eth_tspec_il2cp = -1;
static int hf_rsvp_fast_reroute_include_all = -1;
static int hf_rsvp_association_routing_area_id = -1;
static int hf_rsvp_label_label = -1;
static int hf_rsvp_session_attribute_include_all = -1;
static int hf_rsvp_flowspec_token_bucket_rate = -1;
static int hf_rsvp_call_id_address_type = -1;
static int hf_rsvp_session_attribute_name_length = -1;
static int hf_rsvp_detour_data = -1;
static int hf_rsvp_association_node_id = -1;
static int hf_rsvp_ifid_tlv_length = -1;
static int hf_rsvp_flags = -1;
static int hf_rsvp_tspec_message_format_version = -1;
static int hf_rsvp_ifid_tlv_ipv4_address = -1;
static int hf_rsvp_hop_data = -1;
static int hf_rsvp_ifid_tlv_data = -1;
static int hf_rsvp_length = -1;
static int hf_rsvp_ero_rro_subobjects_pce_id_ipv6 = -1;
static int hf_rsvp_association_data = -1;
static int hf_rsvp_tspec_number_of_multiplexed_components = -1;
static int hf_rsvp_session_attribute_setup_priority = -1;
static int hf_rsvp_message_id_flags = -1;
static int hf_rsvp_hop_logical_interface = -1;
static int hf_rsvp_compression_factor = -1;
static int hf_rsvp_ero_rro_subobjects_private_data = -1;
static int hf_rsvp_lsp_attributes_tlv_data = -1;
static int hf_rsvp_flowspec_token_bucket_size = -1;
static int hf_rsvp_call_id_data = -1;
static int hf_rsvp_template_filter_source_address_ipv6 = -1;
static int hf_rsvp_message_id_ack_flags = -1;
static int hf_rsvp_flowspec_multiplier = -1;
static int hf_rsvp_tspec_token_bucket_size = -1;
static int hf_rsvp_admin_status_bits = -1;
static int hf_rsvp_admin_status_data = -1;
static int hf_rsvp_tspec_peak_data_rate = -1;
static int hf_rsvp_flowspec_number_of_virtual_components = -1;
static int hf_rsvp_hop_neighbor_address_ipv6 = -1;
static int hf_rsvp_flowspec_signal_type_sonet = -1;
static int hf_rsvp_ifid_tlv_autonomous_system = -1;
static int hf_rsvp_scope_ipv6_address = -1;
static int hf_rsvp_flowspec_service_header = -1;
static int hf_rsvp_tspec_hint = -1;
static int hf_rsvp_label_set_action = -1;
static int hf_rsvp_error_data = -1;
static int hf_rsvp_style_flags = -1;
static int hf_rsvp_g_pid = -1;
static int hf_rsvp_integrity_key_identifier = -1;
static int hf_rsvp_adspec_service_header = -1;
static int hf_rsvp_ifid_tlv_error_string = -1;
static int hf_rsvp_session_destination_address = -1;
static int hf_rsvp_ifid_tlv_node_id = -1;
static int hf_rsvp_lsp_tunnel_if_id_component_link_identifier = -1;
static int hf_rsvp_call_id_international_segment = -1;
static int hf_rsvp_fast_reroute_include_any = -1;
static int hf_rsvp_label_request_min_vci = -1;
static int hf_rsvp_tspec_profile = -1;
static int hf_rsvp_eth_tspec_length = -1;
static int hf_rsvp_exclude_route_data = -1;
static int hf_rsvp_record_route_data = -1;
static int hf_rsvp_confirm_receiver_address_ipv4 = -1;
static int hf_rsvp_message_id_list_message_id = -1;
static int hf_rsvp_template_filter_ipv4_tunnel_sender_address = -1;
static int hf_rsvp_template_filter_ipv6_tunnel_sender_address = -1;
static int hf_rsvp_template_filter_sub_group_originator_id = -1;
static int hf_rsvp_template_filter_sub_group_id = -1;
static int hf_rsvp_template_filter_data = -1;
static int hf_rsvp_notify_request_notify_node_address_ipv6 = -1;
static int hf_rsvp_message_id_ack_data = -1;
static int hf_rsvp_eth_tspec_profile = -1;
static int hf_rsvp_label_request_max_vpi = -1;
static int hf_rsvp_ero_rro_subobjects_private_length = -1;
static int hf_rsvp_fast_reroute_exclude_any = -1;
static int hf_rsvp_lsp_tunnel_if_id_data = -1;
static int hf_rsvp_hello_destination_instance = -1;
static int hf_rsvp_tspec_signal_type_g709 = -1;
static int hf_rsvp_call_id_reserved = -1;
static int hf_rsvp_version = -1;
static int hf_rsvp_association_source_ipv6 = -1;
static int hf_rsvp_ero_rro_subobjects_flags = -1;
static int hf_rsvp_lsp_tunnel_if_id_lsp_encoding_type = -1;
static int hf_rsvp_association_type = -1;
static int hf_rsvp_tspec_data = -1;
static int hf_rsvp_session_destination_port = -1;
static int hf_rsvp_association_id = -1;
static int hf_rsvp_integrity_hash = -1;
static int hf_rsvp_flowspec_number_of_contiguous_components = -1;
static int hf_rsvp_policy_data = -1;
static int hf_rsvp_tspec_token_bucket_rate = -1;
static int hf_rsvp_tspec_multiplier = -1;
static int hf_rsvp_dclass_dscp = -1;
static int hf_rsvp_tspec_number_of_contiguous_components = -1;
static int hf_rsvp_session_p2mp_id = -1;
static int hf_rsvp_session_data = -1;
static int hf_rsvp_lsp_tunnel_if_id_target_igp_instance = -1;
static int hf_rsvp_flowspec_profile = -1;
static int hf_rsvp_message_id_ack_epoch = -1;
static int hf_rsvp_hello_source_instance = -1;
static int hf_rsvp_scope_ipv4_address = -1;
static int hf_rsvp_label_request_lsp_encoding_type = -1;
static int hf_rsvp_fast_reroute_hold_priority = -1;
static int hf_rsvp_label_request_max_vci = -1;
static int hf_rsvp_fast_reroute_flags = -1;
static int hf_rsvp_flowspec_peak_data_rate = -1;
static int hf_rsvp_ero_rro_subobjects_label = -1;
static int hf_rsvp_notify_request_data = -1;
static int hf_rsvp_lsp_tunnel_if_id_connection_id = -1;
static int hf_rsvp_eth_tspec_ebs = -1;
static int hf_rsvp_fast_reroute_data = -1;
static int hf_rsvp_label_request_min_vpi = -1;
static int hf_rsvp_session_attribute_data = -1;
static int hf_rsvp_protection_info_data = -1;
static int hf_rsvp_tspec_transparency = -1;
static int hf_rsvp_ifid_tlv_label = -1;
static int hf_rsvp_session_extended_ipv4_address = -1;
static int hf_rsvp_diffserv_aware_te_data = -1;
static int hf_rsvp_lsp_tunnel_if_id_signal_type = -1;
static int hf_rsvp_ero_rro_subobjects_pce_id_ipv4 = -1;
static int hf_rsvp_error_error_node_ipv4 = -1;
static int hf_rsvp_session_protocol = -1;
static int hf_rsvp_tspec_signal_type_sonet = -1;
static int hf_rsvp_session_attribute_flags = -1;
static int hf_rsvp_ero_rro_subobjects_router_id = -1;
static int hf_rsvp_message_id_list_data = -1;
static int hf_rsvp_style_style = -1;
static int hf_rsvp_tspec_number_of_virtual_components = -1;
static int hf_rsvp_tspec_mtu = -1;
static int hf_rsvp_lsp_tunnel_if_id_length = -1;
static int hf_rsvp_ifid_tlv_ipv6_address = -1;
static int hf_rsvp_diffserv_data = -1;
static int hf_rsvp_session_flags = -1;
static int hf_rsvp_flowspec_transparency = -1;
static int hf_rsvp_dclass_data = -1;
static int hf_rsvp_lsp_tunnel_if_id_interface_id = -1;
static int hf_rsvp_lsp_tunnel_if_id_sc_pc_id = -1;
static int hf_rsvp_error_error_code = -1;
static int hf_rsvp_lsp_tunnel_if_id_ipv4_interface_address = -1;
static int hf_rsvp_session_attribute_exclude_any = -1;
static int hf_rsvp_sending_ttl = -1;
static int hf_rsvp_integrity_flags = -1;
static int hf_rsvp_message_id_ack_message_id = -1;
static int hf_rsvp_message_id_message_id = -1;
static int hf_rsvp_ero_rro_subobjects_interface_id = -1;
static int hf_rsvp_message_length = -1;
static int hf_rsvp_message_id_epoch = -1;
static int hf_rsvp_flowspec_signal_type_g709 = -1;
static int hf_rsvp_label_request_data = -1;
static int hf_rsvp_restart_cap_data = -1;
static int hf_rsvp_lsp_attributes_tlv = -1;
static int hf_rsvp_flowspec_mtu = -1;
static int hf_rsvp_flowspec_m = -1;
static int hf_rsvp_tspec_service_header = -1;
static int hf_rsvp_eth_tspec_cbs = -1;
static int hf_rsvp_call_id_national_segment = -1;
static int hf_rsvp_template_filter_source_port = -1;
static int hf_rsvp_eth_tspec_eir = -1;
static int hf_rsvp_ero_rro_subobjects_ipv4_hop = -1;
static int hf_rsvp_lsp_tunnel_if_id_switching_type = -1;
static int hf_rsvp_flowspec_number_of_multiplexed_components = -1;
static int hf_rsvp_label_request_switching_type = -1;
static int hf_rsvp_ero_rro_subobjects_prefix_length = -1;
static int hf_rsvp_explicit_route_data = -1;
static int hf_rsvp_association_source_ipv4 = -1;
static int hf_rsvp_call_id_local_identifier = -1;
static int hf_rsvp_flowspec_message_format_version = -1;
static int hf_rsvp_tspec_requested_concatenation = -1;
static int hf_rsvp_association_padding = -1;
static int hf_rsvp_hop_neighbor_address_ipv4 = -1;
static int hf_rsvp_flowspec_requested_concatenation = -1;
static int hf_rsvp_fast_reroute_bandwidth = -1;
static int hf_rsvp_message_id_list_epoch = -1;
static int hf_rsvp_style_data = -1;
static int hf_rsvp_session_dscp = -1;
static int hf_rsvp_confirm_data = -1;
static int hf_rsvp_protection_info_link_flags = -1;
static int hf_rsvp_message_id_list_flags = -1;
static int hf_rsvp_label_data = -1;
static int hf_rsvp_flowspec_slack_term = -1;
static int hf_rsvp_label_generalized_label = -1;
static int hf_rsvp_label_generalized_label_evpl_vlad_id = -1;
static int hf_rsvp_session_attribute_name = -1;
static int hf_rsvp_ifid_tlv_padding = -1;
static int hf_rsvp_max_dlci = -1;
static int hf_rsvp_minimum_policed_unit = -1;
static int hf_rsvp_dlci_length = -1;
static int hf_rsvp_label_request_m = -1;
static int hf_rsvp_detour_avoid_node_id = -1;
static int hf_rsvp_restart_cap_restart_time = -1;
static int hf_rsvp_nsap_length = -1;
static int hf_rsvp_message_checksum = -1;
static int hf_rsvp_ero_rro_autonomous_system = -1;
static int hf_rsvp_gen_uni_service_level = -1;
static int hf_rsvp_hf_rsvp_adspec_break_bit = -1;
static int hf_rsvp_extended_tunnel_id = -1;
static int hf_rsvp_extended_tunnel_ipv6 = -1;
static int hf_rsvp_maximum_packet_size = -1;
static int hf_rsvp_min_dlci = -1;
static int hf_rsvp_gen_uni_data = -1;
static int hf_rsvp_gen_uni_logical_port_id = -1;
static int hf_rsvp_refresh_interval = -1;
static int hf_rsvp_detour_plr_id = -1;
static int hf_rsvp_restart_cap_recovery_time = -1;
static int hf_rsvp_extended_tunnel = -1;
static int hf_rsvp_call_attributes_endpont_id = -1;
static int hf_rsvp_isis_area_id = -1;
static int hf_rsvp_adspec_type = -1;
static int hf_rsvp_adspec_len = -1;
static int hf_rsvp_adspec_uint = -1;
static int hf_rsvp_adspec_float = -1;
static int hf_rsvp_adspec_bytes = -1;
static int hf_rsvp_wavelength_grid = -1;
static int hf_rsvp_wavelength_cs1 = -1;
static int hf_rsvp_wavelength_cs2 = -1;
static int hf_rsvp_wavelength_cs3 = -1;
static int hf_rsvp_wavelength_channel_spacing = -1;
static int hf_rsvp_wavelength_n = -1;
static int hf_rsvp_wavelength_m = -1;
static int hf_rsvp_wavelength_freq = -1;
static int hf_rsvp_wavelength_wavelength = -1;
static int hf_rsvp_sonet_s = -1;
static int hf_rsvp_sonet_u = -1;
static int hf_rsvp_sonet_k = -1;
static int hf_rsvp_sonet_l = -1;
static int hf_rsvp_sonet_m = -1;
static int hf_rsvp_g709_t3 = -1;
static int hf_rsvp_g709_t2 = -1;
static int hf_rsvp_g709_t1 = -1;
static int hf_rsvp_label_set_type = -1;
static int hf_rsvp_label_set_subchannel = -1;
static int hf_rsvp_nsap_address = -1;
static int hf_rsvp_class_diversity = -1;
static int hf_rsvp_egress_label_type = -1;
static int hf_rsvp_egress_label = -1;
static int hf_rsvp_source_transport_network_addr = -1;
static int hf_rsvp_ie_data = -1;
static int hf_rsvp_3gpp_obj_pf_dst_port_range = -1;
static int hf_rsvp_3gpp_obj_pf_src_port_range = -1;

static expert_field ei_rsvp_invalid_length = EI_INIT;
static expert_field ei_rsvp_packet_filter_component = EI_INIT;
static expert_field ei_rsvp_bundle_component_msg = EI_INIT;
static expert_field ei_rsvp_parameter = EI_INIT;
static expert_field ei_rsvp_adspec_type = EI_INIT;
static expert_field ei_rsvp_call_id_address_type = EI_INIT;
static expert_field ei_rsvp_session_type = EI_INIT;

static int rsvp_tap = -1;

/*
 * All RSVP packets belonging to a particular flow  belong to the same
 * conversation. The following structure definitions are for auxillary
 * structures which have all the relevant flow information to make up the
 * RSVP five-tuple. Note that the values of the five-tuple are determined
 * from the session object and sender template/filter spec for PATH/RESV
 * messages.
 * Update rsvp_request_equal() when you add stuff here. You might also
 * have to update rsvp_request_hash().
 * TODO: Support for IPv6 conversations.
 */

typedef struct rsvp_session_ipv4_info {
    address destination;
    guint8 protocol;
    guint16 udp_dest_port;
} rsvp_session_ipv4_info;

typedef struct rsvp_session_ipv6_info {
    /* not supported yet */

    guint8 dummy;
} rsvp_session_ipv6_info;

typedef struct rsvp_session_ipv4_lsp_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_lsp_info;

typedef struct rsvp_session_ipv6_lsp_info {
    address destination;
    guint16 udp_dest_port;
    guint64 ext_tunnel_id;
} rsvp_session_ipv6_lsp_info;

typedef struct rsvp_session_agg_ipv4_info {
    address destination;
    guint8 dscp;
} rsvp_session_agg_ipv4_info;

typedef struct rsvp_session_ipv4_uni_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_uni_info;

typedef struct rsvp_session_ipv4_p2mp_lsp_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_p2mp_lsp_info;

typedef struct rsvp_session_ipv6_p2mp_lsp_info {
    address destination;
    guint16 udp_dest_port;
    guint64 ext_tunnel_id;
} rsvp_session_ipv6_p2mp_lsp_info;

typedef struct rsvp_session_ipv4_enni_info {
    address destination;
    guint16 udp_dest_port;
    guint32 ext_tunnel_id;
} rsvp_session_ipv4_enni_info;

typedef struct rsvp_template_filter_info {
    address source;
    guint16 udp_source_port;
} rsvp_template_filter_info;

/*
 * The actual request key consists of a union of the various session objects
 * (which are uniquely identified based on the session type), and the
 * source_info structure, which has the information derived from the sender
 * template or the filter spec.
 * The request key is populated by copying the information from the
 * rsvp_conversation_info structure (rsvph), which in turn is populated when
 * the session, filter and sender template objects are dissected.
 */
struct rsvp_request_key {
    guint32 session_type;

    union { /* differentiated by session_type field */
        rsvp_session_ipv4_info session_ipv4;
        rsvp_session_ipv6_info session_ipv6;
        rsvp_session_ipv4_lsp_info session_ipv4_lsp;
        rsvp_session_ipv6_lsp_info session_ipv6_lsp;
        rsvp_session_agg_ipv4_info session_agg_ipv4;
        rsvp_session_ipv4_uni_info session_ipv4_uni;
        rsvp_session_ipv4_p2mp_lsp_info session_ipv4_p2mp_lsp;
        rsvp_session_ipv6_p2mp_lsp_info session_ipv6_p2mp_lsp;
        rsvp_session_ipv4_enni_info session_ipv4_enni;
    } u;

    rsvp_template_filter_info source_info;
    guint32 conversation;
};

/*
 * At present, there is nothing particularly important that we need to
 * store for the request value for each rsvp_request_key, so we just
 * store the unique 32-bit identifier internally allocated for the key
 * (and stored in the conversation attribute of rsvp_request_key above.
 * If this changes in the future, then other stuff can be added here.
 */
struct rsvp_request_val {
    guint32 value;
};

/*
 * Initialize the conversation related data structures.
 */
static wmem_map_t *rsvp_request_hash = NULL;

/*
 * The list of tree types
 */
enum {
    TT_RSVP,
    TT_HDR,
    TT_SESSION,
    TT_HOP,
    TT_HOP_SUBOBJ,
    TT_TIME_VALUES,
    TT_ERROR,
    TT_ERROR_SUBOBJ,
    TT_ERROR_FLAGS,
    TT_SCOPE,
    TT_STYLE,
    TT_CONFIRM,
    TT_SENDER_TEMPLATE,
    TT_FILTER_SPEC,
    TT_TSPEC,
    TT_TSPEC_SUBTREE,
    TT_FLOWSPEC,
    TT_FLOWSPEC_SUBTREE,
    TT_ETHSPEC_SUBTREE,
    TT_ADSPEC,
    TT_ADSPEC_SUBTREE,
    TT_INTEGRITY,
    TT_INTEGRITY_FLAGS,
    TT_DCLASS,
    TT_LSP_TUNNEL_IF_ID,
    TT_LSP_TUNNEL_IF_ID_SUBTREE,
    TT_POLICY,
    TT_MESSAGE_ID,
    TT_MESSAGE_ID_ACK,
    TT_MESSAGE_ID_LIST,
    TT_LABEL,
    TT_LABEL_SET,
    TT_LABEL_REQUEST,
    TT_SESSION_ATTRIBUTE,
    TT_SESSION_ATTRIBUTE_FLAGS,
    TT_HELLO_OBJ,
    TT_EXPLICIT_ROUTE,
    TT_EXPLICIT_ROUTE_SUBOBJ,
    TT_EXCLUDE_ROUTE,
    TT_EXCLUDE_ROUTE_SUBOBJ,
    TT_RECORD_ROUTE,
    TT_RECORD_ROUTE_SUBOBJ,
    TT_RECORD_ROUTE_SUBOBJ_FLAGS,
    TT_ADMIN_STATUS,
    TT_ADMIN_STATUS_FLAGS,
    TT_LSP_ATTRIBUTES,
    TT_LSP_ATTRIBUTES_FLAGS,
    TT_ASSOCIATION,
    TT_GEN_UNI,
    TT_GEN_UNI_SUBOBJ,
    TT_CALL_ID,
    TT_3GPP2_OBJECT,
    TT_BUNDLE_COMPMSG,
    TT_RESTART_CAP,
    TT_LINK_CAP,
    TT_PROTECTION_INFO,
    TT_PROTECTION_INFO_LINK,
    TT_PROTECTION_INFO_LSP,
    TT_PROTECTION_INFO_SEG,
    TT_FAST_REROUTE,
    TT_FAST_REROUTE_FLAGS,
    TT_DETOUR,
    TT_DIFFSERV,
    TT_DIFFSERV_MAP,
    TT_DIFFSERV_MAP_PHBID,
    TT_CLASSTYPE,
    TT_PRIVATE_CLASS,
    TT_JUNIPER,
    TT_UNKNOWN_CLASS,
    TT_3GPP_OBJ_FLOW,
    TT_3GPP_OBJ_QOS,
    TT_3GPP_OBJ_QOS_SUB_BLOB,
    TT_3GPP_OBJ_T2,
    TT_3GPP_OBJ_HO,
    TT_ADSPEC_TYPE_SUBTREE,
    TT_WAVELENGTH,
    TT_SONET_SDH,
    TT_G709,
    TT_RSVP_LSP_ATTR,

    TT_MAX
};
static gint ett_treelist[TT_MAX];
#define TREE(X) ett_treelist[(X)]

/* Should we dissect bundle messages? */
static gboolean rsvp_bundle_dissect = TRUE;

/* FF: How should we dissect generalized label? */
static const enum_val_t rsvp_generalized_label_options[] = {
    /* see RFC 3471 Section 3.2.1.2 */
    { "data", "data (no interpretation)", 1 },
    /* see RFC 4606 Section 3 */
    { "SUKLM", "SONET/SDH (\"S, U, K, L, M\" scheme)", 2 },
    /* see I-D draft-ietf-ccamp-gmpls-g-694-lambda-labels-05 */
    { "G694", "Wavelength Label (fixed or flexi grid)", 3 },
    /* see RFC 4328 Section 4.1 */
    { "G709", "ODUk Label", 4 },
    { NULL, NULL, 0 }
};

static guint rsvp_generalized_label_option = 1;

/*
 * RSVP message types.
 * See
 *
 *      http://www.iana.org/assignments/rsvp-parameters
 */
typedef enum {
    RSVP_MSG_PATH          =  1,        /* RFC 2205 */
    RSVP_MSG_RESV,                      /* RFC 2205 */
    RSVP_MSG_PERR,                      /* RFC 2205 */
    RSVP_MSG_RERR,                      /* RFC 2205 */
    RSVP_MSG_PTEAR,                     /* RFC 2205 */
    RSVP_MSG_RTEAR,                     /* RFC 2205 */
    RSVP_MSG_CONFIRM,                   /* XXX - DREQ, RFC 2745? */
                                        /* 9 is DREP, RFC 2745 */
    RSVP_MSG_RTEAR_CONFIRM = 10,        /* from Fred Baker at Cisco */
                                        /* 11 is unassigned */
    RSVP_MSG_BUNDLE        = 12,        /* RFC 2961 */
    RSVP_MSG_ACK,                       /* RFC 2961 */
                                        /* 14 is reserved */
    RSVP_MSG_SREFRESH      = 15,        /* RFC 2961 */
                                        /* 16, 17, 18, 19 not listed */
    RSVP_MSG_HELLO         = 20,        /* RFC 3209 */
    RSVP_MSG_NOTIFY                     /* [RFC3473] */
                                        /* 25 is Integrity Challenge RFC 2747, RFC 3097 */
                                        /* 26 is Integrity Response RFC 2747, RFC 3097 */
                                        /* 66 is DSBM_willing [SBM] */
                                        /* 67 is I_AM_DSBM [SBM] */
                                        /* [SBM] is Subnet Bandwidth Manager ID from July 1997 */
} rsvp_message_types;

static const value_string message_type_vals[] = {
    { RSVP_MSG_PATH,            "PATH Message. "},
    { RSVP_MSG_RESV,            "RESV Message. "},
    { RSVP_MSG_PERR,            "PATH ERROR Message. "},
    { RSVP_MSG_RERR,            "RESV ERROR Message. "},
    { RSVP_MSG_PTEAR,           "PATH TEAR Message. "},
    { RSVP_MSG_RTEAR,           "RESV TEAR Message. "},
    { RSVP_MSG_CONFIRM,         "CONFIRM Message. "},
    { RSVP_MSG_RTEAR_CONFIRM,   "RESV TEAR CONFIRM Message. "},
    { RSVP_MSG_BUNDLE,          "BUNDLE Message. "},
    { RSVP_MSG_ACK,             "ACK Message. "},
    { RSVP_MSG_SREFRESH,        "SREFRESH Message. "},
    { RSVP_MSG_HELLO,           "HELLO Message. "},
    { RSVP_MSG_NOTIFY,          "NOTIFY Message. "},
    { 0, NULL}
};
static value_string_ext message_type_vals_ext = VALUE_STRING_EXT_INIT(message_type_vals);

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/rsvp-parameters
 * Registry Name: 'Class'
 */
enum rsvp_classes {
    RSVP_CLASS_NULL              =   0,
    RSVP_CLASS_SESSION,

    RSVP_CLASS_HOP               =   3,
    RSVP_CLASS_INTEGRITY,
    RSVP_CLASS_TIME_VALUES,
    RSVP_CLASS_ERROR,
    RSVP_CLASS_SCOPE,
    RSVP_CLASS_STYLE,
    RSVP_CLASS_FLOWSPEC,
    RSVP_CLASS_FILTER_SPEC,
    RSVP_CLASS_SENDER_TEMPLATE,
    RSVP_CLASS_SENDER_TSPEC,
    RSVP_CLASS_ADSPEC,
    RSVP_CLASS_POLICY,
    RSVP_CLASS_CONFIRM,
    RSVP_CLASS_LABEL,
    RSVP_CLASS_HOP_COUNT,
    RSVP_CLASS_STRICT_SOURCE_ROUTE,
    RSVP_CLASS_LABEL_REQUEST     =  19,
    RSVP_CLASS_EXPLICIT_ROUTE,
    RSVP_CLASS_RECORD_ROUTE,

    RSVP_CLASS_HELLO,

    RSVP_CLASS_MESSAGE_ID,
    RSVP_CLASS_MESSAGE_ID_ACK,
    RSVP_CLASS_MESSAGE_ID_LIST,

    /* 26-29  Unassigned */

    RSVP_CLASS_DIAGNOSTIC        = 30,
    RSVP_CLASS_ROUTE,
    RSVP_CLASS_DIAG_RESPONSE,
    RSVP_CLASS_DIAG_SELECT,
    RSVP_CLASS_RECOVERY_LABEL,
    RSVP_CLASS_UPSTREAM_LABEL,
    RSVP_CLASS_LABEL_SET,
    RSVP_CLASS_PROTECTION,

    /* 38-41  Unassigned */
    RSVP_CLASS_DSBM_IP_ADDRESS   = 42,
    RSVP_CLASS_SBM_PRIORITY,
    RSVP_CLASS_DSBM_TIMER_INTERVALS,
    RSVP_CLASS_SBM_INFO,

    /* 46-49  Unassigned */

    RSVP_CLASS_S2L_SUB_LSP       = 50,

    /* 51-62  Unassigned */

    RSVP_CLASS_DETOUR            = 63,
    RSVP_CLASS_CHALLENGE,
    RSVP_CLASS_DIFFSERV,
    RSVP_CLASS_CLASSTYPE, /* FF: RFC4124 */
    RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES = 67,

    /* 68-123  Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_1  = 124,
    RSVP_CLASS_VENDOR_PRIVATE_2  = 125,
    RSVP_CLASS_VENDOR_PRIVATE_3  = 126,
    RSVP_CLASS_VENDOR_PRIVATE_4  = 127,

    RSVP_CLASS_NODE_CHAR         = 128,
    RSVP_CLASS_SUGGESTED_LABEL,
    RSVP_CLASS_ACCEPTABLE_LABEL_SET,
    RSVP_CLASS_RESTART_CAP,
    RSVP_CLASS_LINK_CAP          = 133,

    /* 132-160 Unassigned */

    /* 166-187 Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_5  = 188,
    RSVP_CLASS_VENDOR_PRIVATE_6  = 189,
    RSVP_CLASS_VENDOR_PRIVATE_7  = 190,
    RSVP_CLASS_VENDOR_PRIVATE_8  = 191,

    RSVP_CLASS_SESSION_ASSOC     = 192,
    RSVP_CLASS_LSP_TUNNEL_IF_ID,
    /* 194 Unassigned */
    RSVP_CLASS_NOTIFY_REQUEST    = 195,
    RSVP_CLASS_ADMIN_STATUS,
    RSVP_CLASS_LSP_ATTRIBUTES,
    RSVP_CLASS_ALARM_SPEC,
    RSVP_CLASS_ASSOCIATION,
    RSVP_CLASS_CALL_ATTRIBUTES   = 202,

    /* 203-204  Unassigned */
    /*
        204 Proprietary Juniper LSP properties
        https://www.juniper.net/techpubs/en_US/junos12.1/information-products/topic-collections/nog-mpls-logs/topic-20284.html
     */
    RSVP_CLASS_JUNIPER_PROPERTIES = 204,
    RSVP_CLASS_FAST_REROUTE      = 205,
    /* 206 Unassigned */
    RSVP_CLASS_SESSION_ATTRIBUTE = 207,
    /* 208-223 Unassigned */
    /*
      Class Numbers 224-255 are assigned by IANA using FCFS allocation.
      RSVP will silently ignore, but FORWARD an object with a Class Number
      in this range that it does not understand.
    */
    /* 224  Unassigned */
    RSVP_CLASS_DCLASS            = 225,
    RSVP_CLASS_PACKETCABLE_EXTENSIONS,
    RSVP_CLASS_ATM_SERVICECLASS,
    RSVP_CLASS_CALL_OPS,
    RSVP_CLASS_GENERALIZED_UNI,
    RSVP_CLASS_CALL_ID,
    RSVP_CLASS_3GPP2_OBJECT,
    RSVP_CLASS_EXCLUDE_ROUTE,

    /* 233-251 Unassigned */

    RSVP_CLASS_VENDOR_PRIVATE_9  = 252,
    RSVP_CLASS_VENDOR_PRIVATE_10 = 253,
    RSVP_CLASS_VENDOR_PRIVATE_11 = 254,
    RSVP_CLASS_VENDOR_PRIVATE_12 = 255
};

/* XXX: are any/all of the "missing" values below supposed to have value-strings */
static const value_string rsvp_class_vals[] = {
    { RSVP_CLASS_NULL,                  "NULL object"},
    { RSVP_CLASS_SESSION,               "SESSION object"},

    { RSVP_CLASS_HOP,                   "HOP object"},
    { RSVP_CLASS_INTEGRITY,             "INTEGRITY object"},
    { RSVP_CLASS_TIME_VALUES,           "TIME VALUES object"},
    { RSVP_CLASS_ERROR,                 "ERROR object"},
    { RSVP_CLASS_SCOPE,                 "SCOPE object"},
    { RSVP_CLASS_STYLE,                 "STYLE object"},
    { RSVP_CLASS_FLOWSPEC,              "FLOWSPEC object"},
    { RSVP_CLASS_FILTER_SPEC,           "FILTER SPEC object"},
    { RSVP_CLASS_SENDER_TEMPLATE,       "SENDER TEMPLATE object"},
    { RSVP_CLASS_SENDER_TSPEC,          "SENDER TSPEC object"},
    { RSVP_CLASS_ADSPEC,                "ADSPEC object"},
    { RSVP_CLASS_POLICY,                "POLICY object"},
    { RSVP_CLASS_CONFIRM,               "CONFIRM object"},
    { RSVP_CLASS_LABEL,                 "LABEL object"},
    { RSVP_CLASS_HOP_COUNT,             "HOP_COUNT object"},
    { RSVP_CLASS_STRICT_SOURCE_ROUTE,   "STRICT_SOURCE_ROUTE object"},
    { RSVP_CLASS_LABEL_REQUEST,         "LABEL REQUEST object"},
    { RSVP_CLASS_EXPLICIT_ROUTE,        "EXPLICIT ROUTE object"},
    { RSVP_CLASS_RECORD_ROUTE,          "RECORD ROUTE object"},

    { RSVP_CLASS_HELLO,                 "HELLO object"},

    { RSVP_CLASS_MESSAGE_ID,            "MESSAGE-ID object"},
    { RSVP_CLASS_MESSAGE_ID_ACK,        "MESSAGE-ID ACK/NACK object"},
    { RSVP_CLASS_MESSAGE_ID_LIST,       "MESSAGE-ID LIST object"},

/*
    RSVP_CLASS_DIAGNOSTIC
    RSVP_CLASS_ROUTE,
    RSVP_CLASS_DIAG_RESPONSE,
    RSVP_CLASS_DIAG_SELECT,
*/

    { RSVP_CLASS_RECOVERY_LABEL,        "RECOVERY-LABEL object"},
    { RSVP_CLASS_UPSTREAM_LABEL,        "UPSTREAM-LABEL object"},
    { RSVP_CLASS_LABEL_SET,             "LABEL-SET object"},
    { RSVP_CLASS_PROTECTION,            "PROTECTION object"},

/*
    RSVP_CLASS_DSBM_IP_ADDRESS
    RSVP_CLASS_SBM_PRIORITY,
    RSVP_CLASS_DSBM_TIMER_INTERVALS,
    RSVP_CLASS_SBM_INFO,
*/
    { RSVP_CLASS_S2L_SUB_LSP,           "S2L_SUB_LSP object"},
    { RSVP_CLASS_DETOUR,                "DETOUR object"},
/*
    RSVP_CLASS_CHALLENGE,
*/
    { RSVP_CLASS_DIFFSERV,              "DIFFSERV object"},
    { RSVP_CLASS_CLASSTYPE,             "CLASSTYPE object"},

    { RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES, "LSP REQUIRED ATTRIBUTES object"},


    { RSVP_CLASS_VENDOR_PRIVATE_1,      "VENDOR PRIVATE object (0bbbbbbb: "
                                        "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_2,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_3,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_4,      "VENDOR PRIVATE object (0bbbbbbb: "
                                         "reject if unknown)"},

/*
    RSVP_CLASS_NODE_CHAR
*/
    { RSVP_CLASS_SUGGESTED_LABEL,       "SUGGESTED-LABEL object"},
    { RSVP_CLASS_ACCEPTABLE_LABEL_SET,  "ACCEPTABLE-LABEL-SET object"},
    { RSVP_CLASS_RESTART_CAP,           "RESTART-CAPABILITY object"},
    { RSVP_CLASS_LINK_CAP,              "LINK-CAPABILITY object"},

    { RSVP_CLASS_VENDOR_PRIVATE_5,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_6,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_7,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_8,      "VENDOR PRIVATE object (10bbbbbb: "
                                         "ignore if unknown)"},
/*
    RSVP_CLASS_SESSION_ASSOC
*/
    { RSVP_CLASS_LSP_TUNNEL_IF_ID,      "LSP-TUNNEL INTERFACE-ID object"},

    { RSVP_CLASS_NOTIFY_REQUEST,        "NOTIFY-REQUEST object"},
    { RSVP_CLASS_ADMIN_STATUS,          "ADMIN-STATUS object"},
    { RSVP_CLASS_LSP_ATTRIBUTES,        "LSP ATTRIBUTES object"},
/*
    RSVP_CLASS_ALARM_SPEC,
*/
    { RSVP_CLASS_ASSOCIATION,           "ASSOCIATION object"},

    { RSVP_CLASS_CALL_ATTRIBUTES,       "CALL ATTRIBUTES object"},

    { RSVP_CLASS_JUNIPER_PROPERTIES,    "Juniper properties object"},
    { RSVP_CLASS_FAST_REROUTE,          "FAST-REROUTE object"},

    { RSVP_CLASS_SESSION_ATTRIBUTE,     "SESSION ATTRIBUTE object"},

    { RSVP_CLASS_DCLASS,                "DCLASS object"},
/*
    RSVP_CLASS_PACKETCABLE_EXTENSIONS,
    RSVP_CLASS_ATM_SERVICECLASS,
    RSVP_CLASS_CALL_OPS,
*/
    { RSVP_CLASS_GENERALIZED_UNI,       "GENERALIZED-UNI object"},
    { RSVP_CLASS_CALL_ID,               "CALL-ID object"},
    { RSVP_CLASS_3GPP2_OBJECT,          "3GPP2 object"},
    { RSVP_CLASS_EXCLUDE_ROUTE,         "EXCLUDE ROUTE object"},

    { RSVP_CLASS_VENDOR_PRIVATE_9,      "VENDOR PRIVATE object (11bbbbbb: "
                                         "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_10,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_11,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { RSVP_CLASS_VENDOR_PRIVATE_12,     "VENDOR PRIVATE object (11bbbbbb: "
                                          "forward if unknown)"},
    { 0, NULL}
};
static value_string_ext rsvp_class_vals_ext = VALUE_STRING_EXT_INIT(rsvp_class_vals);

/*
 * RSVP error values
 */
enum rsvp_error_types {
    RSVP_ERROR_CONFIRM   = 0,
    RSVP_ERROR_ADMISSION,
    RSVP_ERROR_POLICY,
    RSVP_ERROR_NO_PATH,
    RSVP_ERROR_NO_SENDER,
    RSVP_ERROR_CONFLICT_RESV_STYLE,
    RSVP_ERROR_UNKNOWN_RESV_STYLE,
    RSVP_ERROR_CONFLICT_DEST_PORTS,
    RSVP_ERROR_CONFLICT_SRC_PORTS,
    /* 9-11 Reserved */
    RSVP_ERROR_PREEMPTED =12,
    RSVP_ERROR_UNKNOWN_CLASS,
    RSVP_ERROR_UNKNOWN_C_TYPE,
    /* 15-19 Reserved */
    RSVP_ERROR_RES_FOR_API = 20,
    RSVP_ERROR_TRAFFIC,
    RSVP_ERROR_TRAFFIC_SYSTEM,
    RSVP_ERROR_SYSTEM,
    RSVP_ERROR_ROUTING,
    RSVP_ERROR_NOTIFY,
    RSVP_ERROR_NEW_AGGR,            /* RFC3175 */
    RSVP_ERROR_DIFFSERV,
    RSVP_ERROR_DSTE,                /* RFC4124 */
    RSVP_ERROR_UNKNOWN_ATTR_TLV,    /* RFC5420 */
    RSVP_ERROR_UNKNOWN_ATTR_BIT,    /* RFC5420 */
    RSVP_ERROR_ALARMS,              /* RFC4783 */
    RSVP_ERROR_CALL_MGMT,           /* RFC4974 */
    RSVP_ERROR_USER_ERROR_SPEC,     /* RFC5284 */
    RSVP_ERROR_REROUTE,            /* RFC5710 */
    RSVP_ERROR_HO_PROC_FAIL,        /* RFC5852 */
    RSVP_ERROR_UNREC_REC_PROXY_ERR, /* RFC5946 */
    RSVP_ERROR_RSVP_OVER_MPLS_PROB, /* RFC6016 */
    RSVP_ERROR_LSP_HIER_ISSUE,      /* RFC6107 */
    RSVP_ERROR_VCAT_CALL_MGMT       /* RFC6344 */

};

static const value_string rsvp_error_codes[] = {
    { RSVP_ERROR_CONFIRM,              "Confirmation"},
    { RSVP_ERROR_ADMISSION,            "Admission Control Failure "},
    { RSVP_ERROR_POLICY,               "Policy Control Failure"},
    { RSVP_ERROR_NO_PATH,              "No PATH information for this RESV message"},
    { RSVP_ERROR_NO_SENDER,            "No sender information for this RESV message"},
    { RSVP_ERROR_CONFLICT_RESV_STYLE,  "Conflicting reservation styles"},
    { RSVP_ERROR_UNKNOWN_RESV_STYLE,   "Unknown reservation style"},
    { RSVP_ERROR_CONFLICT_DEST_PORTS,  "Conflicting destination ports"},
    { RSVP_ERROR_CONFLICT_SRC_PORTS,   "Conflicting source ports"},
    { RSVP_ERROR_PREEMPTED,            "Service preempted"},
    { RSVP_ERROR_UNKNOWN_CLASS,        "Unknown object class"},
    { RSVP_ERROR_UNKNOWN_C_TYPE,       "Unknown object C-type"},
    { RSVP_ERROR_RES_FOR_API,          "Reserved for API"},
    { RSVP_ERROR_TRAFFIC,              "Traffic Control Error"},
    { RSVP_ERROR_TRAFFIC_SYSTEM,       "Traffic Control System Error"},
    { RSVP_ERROR_SYSTEM,               "RSVP System Error"},
    { RSVP_ERROR_ROUTING,              "Routing Error"},
    { RSVP_ERROR_NOTIFY,               "RSVP Notify Error"},
    { RSVP_ERROR_NEW_AGGR,             "New aggregate needed"},
    { RSVP_ERROR_DIFFSERV,             "RSVP Diff-Serv Error"},
    { RSVP_ERROR_DSTE,                 "RSVP DiffServ-aware TE Error"},
    { RSVP_ERROR_UNKNOWN_ATTR_TLV,     "Unknown attributes TLV"},
    { RSVP_ERROR_UNKNOWN_ATTR_BIT,     "Unknown attributes bit"},
    { RSVP_ERROR_ALARMS,               "Alarms"},
    { RSVP_ERROR_CALL_MGMT,            "Call management"},
    { RSVP_ERROR_USER_ERROR_SPEC,      "User error spec"},
    { RSVP_ERROR_REROUTE,              "Reroute"},
    { RSVP_ERROR_HO_PROC_FAIL,         "Handover Procedure Failure"},
    { RSVP_ERROR_UNREC_REC_PROXY_ERR,  "Unrecoverable Receiver Proxy Error"},
    { RSVP_ERROR_RSVP_OVER_MPLS_PROB,  "RSVP over MPLS Problem"},
    { RSVP_ERROR_LSP_HIER_ISSUE,       "LSP Hierarchy Issue"},
    { RSVP_ERROR_VCAT_CALL_MGMT,       "VCAT Call Management"},

    { 0, NULL}
};
static value_string_ext rsvp_error_codes_ext = VALUE_STRING_EXT_INIT(rsvp_error_codes);

static const value_string rsvp_admission_control_error_vals[] = {
    { 1, "Delay bound cannot be met"},
    { 2, "Requested bandwidth unavailable"},
    { 3, "MTU in flowspec larger than interface MTU"},
    { 4, "LSP Admission Failure"},
    { 5, "Bad Association Type"},
    { 0, NULL}
};
static value_string_ext rsvp_admission_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_admission_control_error_vals);

static const value_string rsvp_policy_control_error_vals[] = {
    {   0, "Information reporting"},
    {   1, "Warning"},
    {   2, "Reason unknown"},
    {   3, "Generic Policy Rejection"},
    {   4, "Quota or Accounting violation"},
    {   5, "Flow was preempted"},
    {   6, "Previously installed policy expired (not refreshed)"},
    {   7, "Previous policy data was replaced & caused rejection"},
    {   8, "Policies could not be merged (multicast)"},
    {   9, "PDP down or non functioning"},
    {  10, "Third Party Server (e.g., Kerberos) unavailable"},
    {  11, "POLICY_DATA object has bad syntax"},
    {  12, "POLICY_DATA object failed Integrity Check"},
    {  13, "POLICY_ELEMENT object has bad syntax"},
    {  14, "Mandatory PE Missing (Empty PE is in the PD object)"},
    {  15, "PEP Out of resources to handle policies."},
    {  16, "PDP encountered bad RSVP objects or syntax"},
    {  17, "Service type was rejected"},
    {  18, "Reservation Style was rejected"},
    {  19, "FlowSpec was rejected (too large)"},
    {  20, "Hard Pre-empted"},
    {  21, "SRLG Recording Rejected"},
    { 100, "Unauthorized sender"},
    { 101, "Unauthorized receiver"},
    { 102, "ERR_PARTIAL_PREEMPT"},
    { 103, "Inter-domain policy failure"},
    { 104, "Inter-domain explicit route rejected"},
    {   0, NULL}
};
static value_string_ext rsvp_policy_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_policy_control_error_vals);

static const value_string rsvp_traffic_control_error_vals[] = {
    { 1, "Service conflict"},
    { 2, "Service unsupported"},
    { 3, "Bad Flowspec value"},
    { 4, "Bad Tspec value"},
    { 5, "Bad Adspec value"},
    { 0, NULL}
};
static value_string_ext rsvp_traffic_control_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_traffic_control_error_vals);

static const value_string rsvp_routing_error_vals[] = {
    {   1, "Bad EXPLICIT_ROUTE object"},
    {   2, "Bad strict node"},
    {   3, "Bad loose node"},
    {   4, "Bad initial subobject"},
    {   5, "No route available toward destination"},
    {   6, "Unacceptable label value"},
    {   7, "RRO indicated routing loops"},
    {   8, "non-RSVP-capable router stands in the path"},
    {   9, "MPLS label allocation failure"},
    {  10, "Unsupported L3PID"},
    {  11, "Label Set"},
    {  12, "Switching Type"},
    {  13, "Unassigned"},
    {  14, "Unsupported Encoding"},
    {  15, "Unsupported Link Protection"},
    {  16, "Unknown Interface Index"},
    {  17, "Unsupported LSP Protection"},
    {  18, "PROTECTION object not applicable"},
    {  19, "Bad PRIMARY_PATH_ROUTE object"},
    {  20, "PRIMARY_PATH_ROUTE object not applicable"},
    {  21, "LSP Segment Protection Failed"},
    {  22, "Re-routing limit exceeded"},
    {  23, "Unable to Branch"},
    {  24, "Unsupported LSP Integrity"},
    {  25, "P2MP Re-Merge Detected"},
    {  26, "P2MP Re-Merge Parameter Mismatch"},
    {  27, "ERO Resulted in Re-Merge"},
    {  28, "Contiguous LSP type not supported"},
    {  29, "ERO conflicts with inter-domain signaling method"},
    {  30, "Stitching unsupported"},
    {  31, "Unknown PCE-ID for PKS expansion"},
    {  32, "Unreachable PCE for PKS expansion"},
    {  33, "Unknown Path Key for PKS expansion"},
    {  34, "ERO too large for MTU"},
    {  64, "Unsupported Exclude Route Subobject Type"},
    {  65, "Inconsistent Subobject"},
    {  66, "Local Node in Exclude Route"},
    {  67, "Route Blocked by Exclude Route"},
    {  68, "XRO Too Complex"},
    {  69, "EXRS Too Complex"},
    { 100, "Diversity not available"},
    { 101, "Service level not available"},
    { 102, "Invalid/Unknown connection ID"},
    { 103, "No route available toward source (ASON)"},
    { 104, "Unacceptable interface ID (ASON)"},
    { 105, "Invalid/unknown call ID (ASON)"},
    { 106, "Invalid SPC interface ID/label (ASON)"},
    {   0, NULL}
};
static value_string_ext rsvp_routing_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_routing_error_vals);

static const value_string rsvp_notify_error_vals[] = {
    {  1, "RRO too large for MTU"},
    {  2, "RRO Notification"},
    {  3, "Tunnel locally repaired"},
    {  4, "Control Channel Active State"},
    {  5, "Control Channel Degraded State"},
    {  6, "Preferable path exists"},
    {  7, "Link maintenance required"},
    {  8, "Node maintenance required"},
    {  9, "LSP Failure"},
    { 10, "LSP recovered"},
    { 11, "LSP Local Failure"},
    { 12, "No OOB mapping received"},
    {  0, NULL}
};
static value_string_ext rsvp_notify_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_notify_error_vals);

static const value_string rsvp_diffserv_error_vals[] = {
    { 1, "Unexpected DIFFSERV object"},
    { 2, "Unsupported PHB"},
    { 3, "Invalid `EXP<->PHB mapping'"},
    { 4, "Unsupported PSC"},
    { 5, "Per-LSP context allocation failure"},
    { 0, NULL}
};
static value_string_ext rsvp_diffserv_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_diffserv_error_vals);

/* FF: RFC4124 */
static const value_string rsvp_diffserv_aware_te_error_vals[] = {
    { 1, "Unexpected CLASSTYPE object"},
    { 2, "Unsupported Class-Type"},
    { 3, "Invalid Class-Type value"},
    { 4, "CT and setup priority do not form a configured TE-Class"},
    { 5, "CT and holding priority do not form a configured TE-Class"},
    { 6, "CT and setup priority do not form a configured TE-Class AND CT and holding priority do not form a configured TE-Class"},
    { 7, "Inconsistency between signaled PSC and signaled CT"},
    { 8, "Inconsistency between signaled PHBs and signaled CT"},
    { 0, NULL}
};
static value_string_ext rsvp_diffserv_aware_te_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_diffserv_aware_te_error_vals);

static const value_string rsvp_call_mgmt_error_vals[] = {
    { 1, "Call ID Contention"},
    { 2, "Connections still Exist"},
    { 3, "Unknown Call ID"},
    { 4, "Duplicate Call"},
    { 0, NULL}
};
static value_string_ext rsvp_call_mgmt_error_vals_ext = VALUE_STRING_EXT_INIT(rsvp_call_mgmt_error_vals);

/*
 * Defines the reservation style plus style-specific information that
 * is not a FLOWSPEC or FILTER_SPEC object, in a RESV message.
 */
#define RSVP_DISTINCT (1 << 3)
#define RSVP_SHARED   (2 << 3)
#define RSVP_SHARING_MASK (RSVP_DISTINCT | RSVP_SHARED)

#define RSVP_SCOPE_WILD     1
#define RSVP_SCOPE_EXPLICIT 2
#define RSVP_SCOPE_MASK     0x07

#define RSVP_WF (RSVP_SHARED   | RSVP_SCOPE_WILD)
#define RSVP_FF (RSVP_DISTINCT | RSVP_SCOPE_EXPLICIT)
#define RSVP_SE (RSVP_SHARED   | RSVP_SCOPE_EXPLICIT)

static const value_string style_vals[] = {
    { RSVP_WF, "Wildcard Filter" },
    { RSVP_FF, "Fixed Filter" },
    { RSVP_SE, "Shared-Explicit" },
    { 0,       NULL }
};

enum {
    RSVP_SESSION_TYPE_IPV4 = 1,
    RSVP_SESSION_TYPE_IPV6,

    RSVP_SESSION_TYPE_IPV4_LSP = 7,
    RSVP_SESSION_TYPE_IPV6_LSP,

    RSVP_SESSION_TYPE_AGGREGATE_IPV4 = 9,
    RSVP_SESSION_TYPE_AGGREGATE_IPV6,

    RSVP_SESSION_TYPE_IPV4_UNI = 11,

    RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4 = 13,
    RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6,
    RSVP_SESSION_TYPE_IPV4_E_NNI
};

/*
 * Defines a desired QoS, in a RESV message.
 */
enum    qos_service_type {
    QOS_QUALITATIVE =     128,          /* Qualitative service */
    QOS_NULL =              6,          /* Null service (RFC2997) */
    QOS_CONTROLLED_LOAD=    5,          /* Controlled Load Service */
    QOS_GUARANTEED =        2,          /* Guaranteed service */
    QOS_TSPEC =             1           /* Traffic specification */
};

static const value_string qos_vals[] = {
    { QOS_QUALITATIVE,     "Qualitative QoS" },
    { QOS_NULL,            "Null-Service QoS" },
    { QOS_CONTROLLED_LOAD, "Controlled-load QoS" },
    { QOS_GUARANTEED,      "Guaranteed rate QoS" },
    { QOS_TSPEC,           "Traffic specification" },
    { 0, NULL }
};

static const value_string svc_vals[] = {
    { 126, "Compression Hint" },
    { 127, "Token bucket" },
    { 128, "Null Service" },
    { 130, "Guaranteed-rate RSpec" },
    { 0, NULL }
};
static value_string_ext svc_vals_ext = VALUE_STRING_EXT_INIT(svc_vals);

enum rsvp_spec_types { INTSRV = 2 };

enum intsrv_services {
    INTSRV_GENERAL     =   1,
    INTSRV_GTD         =   2,
    INTSRV_CLOAD       =   5,
    INTSRV_NULL        =   6,
    INTSRV_QUALITATIVE = 128
};

static const value_string intsrv_services_str[] = {
    { INTSRV_GENERAL,     "Default General Parameters"},
    { INTSRV_GTD,         "Guaranteed Rate"},
    { INTSRV_CLOAD,       "Controlled Load"},
    { INTSRV_NULL,        "Null Service"},
    { INTSRV_QUALITATIVE, "Null Service"},
    { 0, NULL }
};
static value_string_ext intsrv_services_str_ext = VALUE_STRING_EXT_INIT(intsrv_services_str);

/*Ingress Layer 2 Control Processing values*/
static const value_string il2cp_val_str[] = {
    { 0, "Ingress Layer 2 Control Processing: 0 - Reserved" },
    { 1, "Ingress Layer 2 Control Processing: 1 - Discard/Block" },
    { 2, "Ingress Layer 2 Control Processing: 2 - Peer/Process" },
    { 3, "Ingress Layer 2 Control Processing: 3 - Pass to EVC/Pass" },
    { 4, "Ingress Layer 2 Control Processing: 4 - Peer and Pass to EVC" },
    { 0, NULL }
};

/*Egress Layer 2 Control Processing values*/
static const value_string el2cp_val_str[] = {
    { 0, "Egress Layer 2 Control Processing: 0 - Reserved" },
    { 1, "Egress Layer 2 Control Processing: 1 - Based on IL2CP Value" },
    { 2, "Egress Layer 2 Control Processing: 2 - Generate" },
    { 3, "Egress Layer 2 Control Processing: 3 - None" },
    { 4, "Egress Layer 2 Control Processing: 4 - Reserved" },
    { 0, NULL }
};

#if 0
enum intsrv_field_name {
    INTSRV_NON_IS_HOPS           = 1,
    INTSRV_COMPOSED_NON_IS_HOPS,
    INTSRV_IS_HOPS,
    INTSRV_COMPOSED_IS_HOPS,
    INTSRV_PATH_BANDWIDTH,
    INTSRV_MIN_PATH_BANDWIDTH,
    INTSRV_IF_LATENCY,
    INTSRV_PATH_LATENCY,
    INTSRV_MTU,
    INTSRV_COMPOSED_MTU,

    INTSRV_TOKEN_BUCKET_TSPEC    = 127,
    INTSRV_QUALITATIVE_TSPEC     = 128,
    INTSRV_GTD_RSPEC             = 130,

    INTSRV_DELAY = 131,         /* Gtd Parameter C - Max Delay Bound - bytes */
    INTSRV_MAX_JITTER,          /* Gtd Parameter D - Max Jitter */
    INTSRV_E2E_DELAY,           /* Gtd Parameter Ctot */
    INTSRV_E2E_MAX_JITTER,      /* Gtd Parameter Dtot */
    INTSRV_SHP_DELAY,           /* Gtd Parameter Csum */
    INTSRV_SHP_MAX_JITTER       /* Gtd Parameter Dsum */
};
#endif

static const value_string adspec_params[] = {
    {   4, "IS Hop Count"},
    {   6, "Path b/w estimate"},
    {   8, "Minimum path latency"},
    {  10, "Composed MTU"},
    { 133, "End-to-end composed value for C"},
    { 134, "End-to-end composed value for D"},
    { 135, "Since-last-reshaping point composed C"},
    { 136, "Since-last-reshaping point composed D"},
    {   0, NULL }
};
static value_string_ext adspec_params_ext = VALUE_STRING_EXT_INIT(adspec_params);

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters/gmpls-sig-parameters.xhtml
 * Registry Name: 'LSP Encoding Types'
 */
const range_string gmpls_lsp_enc_rvals[] = {
    {   1,   1, "Packet" },
    {   2,   2, "Ethernet" },
    {   3,   3, "ANSI/ETSI PDH" },
    {   4,   4, "Reserved" },
    {   5,   5, "SDH ITU-T G.707 / SONET ANSI T1.105" },
    {   6,   6, "Reserved" },
    {   7,   7, "Digital Wrapper" },
    {   8,   8, "Lambda (photonic)" },
    {   9,   9, "Fiber" },
    {  10,  10, "Reserved" },
    {  11,  11, "FiberChannel" },
    {  12,  12, "G.709 ODUk (Digital Path)" },
    {  13,  13, "G.709 Optical Channel" },
    {  14,  14, "Ethernet Line (EPL Type 2)" },
    {  15, 239, "Unassigned" },
    { 240, 255, "Experimental Usage/temporarily" },
    {   0,   0, NULL }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters/gmpls-sig-parameters.xhtml
 * Registry Name: 'Switching Types'
 */
const range_string gmpls_switching_type_rvals[] = {
    {   1,   1, "Packet-Switch Capable-1 (PSC-1)" },
    {   2,   2, "Packet-Switch Capable-2 (PSC-2)" },
    {   3,   3, "Packet-Switch Capable-3 (PSC-3)" },
    {   4,   4, "Packet-Switch Capable-4 (PSC-4)" },
    {   5,  29, "Unassigned" },
    {  30,  30, "Ethernet Virtual Private Line (EVPL)" },
    {  31,  39, "Unassigned" },
    {  40,  40, "802.1 PBB-TE" },
    {  41,  50, "Unassigned" },
    {  51,  51, "Layer-2 Switch Capable (L2SC)" },
    {  52,  99, "Unassigned" },
    { 100, 100, "Time-Division-Multiplex Capable (TDM)" },
    { 101, 124, "Unassigned" },
    { 125, 125, "Data Channel Switching Capable (DCSC)" },
    { 126, 149, "Unassigned" },
    { 150, 150, "Lambda-Switch Capable (LSC)" },
    { 151, 151, "WSON-LSC"},
    { 152, 152, "Flexi-Grid-LSC"},
    { 153, 169, "Unassigned" },
    { 200, 200, "Fiber-Switch Capable (FSC)" },
    { 201, 255, "Unassigned" },
    {   0,   0, NULL }
};

/*
 * FF: please keep this list in sync with
 * http://www.iana.org/assignments/gmpls-sig-parameters/gmpls-sig-parameters.xhtml
 * Registry Name: 'Generalized PID (G-PID)'
 */
static const range_string gmpls_gpid_rvals[] = {
    {      0,     0, "Unknown" },
    {      1,     4, "Reserved" },
    {      5,     5, "Asynchronous mapping of E4" },
    {      6,     6, "Asynchronous mapping of DS3/T3" },
    {      7,     7, "Asynchronous mapping of E3" },
    {      8,     8, "Bit synchronous mapping of E3" },
    {      9,     9, "Byte synchronous mapping of E3" },
    {     10,    10, "Asynchronous mapping of DS2/T2" },
    {     11,    11, "Bit synchronous mapping of DS2/T2" },
    {     12,    12, "Reserved" },
    {     13,    13, "Asynchronous mapping of E1" },
    {     14,    14, "Byte synchronous mapping of E1" },
    {     15,    15, "Byte synchronous mapping of 31 * DS0" },
    {     16,    16, "Asynchronous mapping of DS1/T1" },
    {     17,    17, "Bit synchronous mapping of DS1/T1" },
    {     18,    18, "Byte synchronous mapping of DS1/T1" },
    {     19,    19, "VC-11 in VC-12" },
    {     20,    21, "Reserved" },
    {     22,    22, "DS1 SF Asynchronous" },
    {     23,    23, "DS1 ESF Asynchronous" },
    {     24,    24, "DS3 M23 Asynchronous" },
    {     25,    25, "DS3 C-Bit Parity Asynchronous" },
    {     26,    26, "VT/LOVC" },
    {     27,    27, "STS SPE/HOVC" },
    {     28,    28, "POS - No Scrambling, 16 bit CRC" },
    {     29,    29, "POS - No Scrambling, 32 bit CRC" },
    {     30,    30, "POS - Scrambling, 16 bit CRC" },
    {     31,    31, "POS - Scrambling, 32 bit CRC" },
    {     32,    32, "ATM mapping" },
    {     33,    33, "Ethernet PHY" },
    {     34,    34, "SONET/SDH" },
    {     35,    35, "Reserved (SONET deprecated)" },
    {     36,    36, "Digital Wrapper" },
    {     37,    37, "Lambda" },
    {     38,    38, "ANSI/ETSI PDH" },
    {     39,    39, "Reserved" },
    {     40,    40, "Link Access Protocol SDH (LAPS - X.85 and X.86)" },
    {     41,    41, "FDDI" },
    {     42,    42, "DQDB (ETSI ETS 300 216)" },
    {     43,    43, "FiberChannel-3 (Services)" },
    {     44,    44, "HDLC" },
    {     45,    45, "Ethernet V2/DIX (only)" },
    {     46,    46, "Ethernet 802.3 (only)" },
    {     47,    47, "G.709 ODUj" },
    {     48,    48, "G.709 OTUk(v)" },
    {     49,    49, "CBR/CBRa" },
    {     50,    50, "CBRb" },
    {     51,    51, "BSOT" },
    {     52,    52, "BSNT" },
    {     53,    53, "IP/PPP (GFP)" },
    {     54,    54, "Ethernet MAC (framed GFP)" },
    {     55,    55, "Ethernet PHY (transparent GFP" },
    {     56,    56, "ESCON" },
    {     57,    57, "FICON" },
    {     58,    58, "Fiber Channel" },
    {     59, 31743, "Unassigned" },
    {  31744, 32767, "Experimental Usage/temporarily" },
    {  32768, 65535, "Reserved" },
    {      0,     0, NULL },
};

const value_string gmpls_protection_cap_str[] = {
    {   1, "Extra Traffic"},
    {   2, "Unprotected"},
    {   4, "Shared"},
    {   8, "Dedicated 1:1"},
    {  16, "Dedicated 1+1"},
    {  32, "Enhanced"},
    {  64, "Reserved"},
    { 128, "Reserved"},
    {   0, NULL }
};

static const value_string gmpls_sonet_signal_type_str[] = {
    {  1, "VT1.5 SPE / VC-11"},
    {  2, "VT2 SPE / VC-12"},
    {  3, "VT3 SPE"},
    {  4, "VT6 SPE / VC-2"},
    {  5, "STS-1 SPE / VC-3"},
    {  6, "STS-3c SPE / VC-4"},
    {  7, "STS-1 / STM-0 (transp)"},
    {  8, "STS-3 / STM-1 (transp)"},
    {  9, "STS-12 / STM-4 (transp)"},
    { 10, "STS-48 / STM-16 (transp)"},
    { 11, "STS-192 / STM-64 (transp)"},
    { 12, "STS-768 / STM-256 (transp)"},

    /* Extended non-SONET signal types */
    { 13, "VTG / TUG-2"},
    { 14, "TUG-3"},
    { 15, "STSG-3 / AUG-1"},
    { 16, "STSG-12  / AUG-4"},
    { 17, "STSG-48  / AUG-16"},
    { 18, "STSG-192 / AUG-64"},
    { 19, "STSG-768 / AUG-256"},

    /* Other SONEt signal types */
    { 21, "STS-12c SPE / VC-4-4c"},
    { 22, "STS-48c SPE / VC-4-16c"},
    { 23, "STS-192c SPE / VC-4-64c"},
    {  0, NULL}
};
value_string_ext gmpls_sonet_signal_type_str_ext = VALUE_STRING_EXT_INIT(gmpls_sonet_signal_type_str);

static const value_string ouni_guni_diversity_str[] = {
    { 1, "Node Diverse"},
    { 2, "Link Diverse"},
    { 3, "Shared-Risk Link Group Diverse"},
    { 4, "Shared Path"},
    { 0, NULL}
};

/* FF: RFC 4328 G.709 signal type */
static const range_string gmpls_g709_signal_type_rvals[] = {
    { 0,   0, "Not significant"},
    { 1,   1, "ODU1 (i.e., 2.5 Gbps)"},
    { 2,   2, "ODU2 (i.e., 10  Gbps)"},
    { 3,   3, "ODU3 (i.e., 40  Gbps)"},
    { 4,   5, "Reserved (for future use)"},
    { 6,   6, "OCh at 2.5 Gbps"},
    { 7,   7, "OCh at 10  Gbps"},
    { 8,   8, "OCh at 40  Gbps"},
    { 9, 255, "Reserved (for future use)"},
    { 0,   0, NULL}
};

/* XRO related */

static const value_string rsvp_xro_sobj_lbit_vals[] = {
    { 1, "Should be avoided" },
    { 0, "Must be excluded" },
    { 0, NULL }
};

/* RRO related */
static const value_string rsvp_rro_sobj_dbit_vals[] = {
    { 1, "Upstream direction" },
    { 0, "Downstream direction" },
    { 0, NULL }
};

#if 0
static const value_string rsvp_xro_sobj_type_vals[] = {
    {  1, "IPv4 prefix" },
    {  2, "IPv6 prefix" },
    {  4, "Unnumbered Interface ID" },
    { 32, "Autonomous system number" },
    { 33, "Explicit Exclusion Route subobject (EXRS)" },
    { 34, "SRLG" },
    {  0, NULL }
};
#endif

static const value_string rsvp_xro_sobj_ip_attr_vals[] = {
    {  0, "Interface" },
    {  1, "Node" },
    {  2, "SRLG" },
    {  0, NULL }
};

static const value_string rsvp_juniper_attr_vals[] = {
    {  0x01, "Cos" },
    {  0x02, "Metric 1" },
    {  0x04, "Metric 2" },
    {  0x08, "CCC Status" },
    {  0x10, "Path Type" },
    {  0, NULL }
};

static const value_string rsvp_juniper_path_attr_vals[] = {
    {  0x02, "Primary" },
    {  0x03, "Secondary" },
    {  0, NULL }
};

/* -------------------- Stuff for MPLS/TE objects -------------------- */

static const value_string proto_vals[] = {
    { IP_PROTO_ICMP, "ICMP"},
    { IP_PROTO_IGMP, "IGMP"},
    { IP_PROTO_TCP,  "TCP" },
    { IP_PROTO_UDP,  "UDP" },
    { IP_PROTO_OSPF, "OSPF"},
    { 0,             NULL  }
};

/* Filter keys */
enum hf_rsvp_filter_keys {

    /* Message types */
    RSVPF_MSG,          /* Message type */
    /* Shorthand for message types */
    RSVPF_PATH,
    RSVPF_RESV,
    RSVPF_PATHERR,
    RSVPF_RESVERR,
    RSVPF_PATHTEAR,
    RSVPF_RESVTEAR,
    RSVPF_RCONFIRM,
    RSVPF_JUNK_MSG8,
    RSVPF_JUNK_MSG9,
    RSVPF_RTEARCONFIRM,
    RSVPF_JUNK11,
    RSVPF_BUNDLE,
    RSVPF_ACK,
    RSVPF_JUNK14,
    RSVPF_SREFRESH,
    RSVPF_JUNK16,
    RSVPF_JUNK17,
    RSVPF_JUNK18,
    RSVPF_JUNK19,
    RSVPF_HELLO,
    RSVPF_NOTIFY,
    /* Does the message contain an object of this type? */
    RSVPF_OBJECT,
    /* Object present shorthands */
    RSVPF_SESSION,
    RSVPF_DUMMY_1,
    RSVPF_HOP,
    RSVPF_INTEGRITY,
    RSVPF_TIME_VALUES,
    RSVPF_ERROR,
    RSVPF_SCOPE,
    RSVPF_STYLE,
    RSVPF_FLOWSPEC,
    RSVPF_FILTER_SPEC,
    RSVPF_SENDER,
    RSVPF_TSPEC,
    RSVPF_ADSPEC,
    RSVPF_POLICY,
    RSVPF_CONFIRM,
    RSVPF_LABEL,
    RSVPF_DUMMY_2,
    RSVPF_DUMMY_3,
    RSVPF_LABEL_REQUEST,
    RSVPF_EXPLICIT_ROUTE,
    RSVPF_RECORD_ROUTE,
    RSVPF_HELLO_OBJ,
    RSVPF_MESSAGE_ID,
    RSVPF_MESSAGE_ID_ACK,
    RSVPF_MESSAGE_ID_LIST,
    RSVPF_RECOVERY_LABEL,
    RSVPF_UPSTREAM_LABEL,
    RSVPF_LABEL_SET,
    RSVPF_PROTECTION,
    RSVPF_DIFFSERV,
    RSVPF_DSTE,

    RSVPF_SUGGESTED_LABEL,
    RSVPF_ACCEPTABLE_LABEL_SET,
    RSVPF_RESTART_CAP,

    RSVPF_LINK_CAP,

    RSVPF_SESSION_ATTRIBUTE,
    RSVPF_DCLASS,
    RSVPF_LSP_TUNNEL_IF_ID,
    RSVPF_NOTIFY_REQUEST,
    RSVPF_ADMIN_STATUS,
    RSVPF_ADMIN_STATUS_REFLECT,
    RSVPF_ADMIN_STATUS_HANDOVER,
    RSVPF_ADMIN_STATUS_LOCKOUT,
    RSVPF_ADMIN_STATUS_INHIBIT,
    RSVPF_ADMIN_STATUS_CALL_MGMT,
    RSVPF_ADMIN_STATUS_TESTING,
    RSVPF_ADMIN_STATUS_DOWN,
    RSVPF_ADMIN_STATUS_DELETE,
    RSVPF_LSP_ATTRIBUTES,
    RSVPF_ASSOCIATION,
    RSVPF_CALL_ATTRIBUTES,
    RSVPF_GENERALIZED_UNI,
    RSVPF_CALL_ID,
    RSVPF_3GPP2_OBJECT,
    RSVPF_UNKNOWN_OBJ,

    /* Session object */
    RSVPF_SESSION_IP,
    RSVPF_SESSION_SHORT_CALL_ID,
    RSVPF_SESSION_PROTO,
    RSVPF_SESSION_PORT,
    RSVPF_SESSION_TUNNEL_ID,
    RSVPF_SESSION_EXT_TUNNEL_ID,
    RSVPF_SESSION_EXT_TUNNEL_ID_IPV6,

    /* Sender template */
    RSVPF_SENDER_IP,
    RSVPF_SENDER_PORT,
    RSVPF_SENDER_LSP_ID,
    RSVPF_SENDER_SHORT_CALL_ID,

    /* Diffserv object */
    RSVPF_DIFFSERV_MAPNB,
    RSVPF_DIFFSERV_MAP,
    RSVPF_DIFFSERV_MAP_EXP,
    RSVPF_DIFFSERV_PHBID,
    RSVPF_DIFFSERV_PHBID_DSCP,
    RSVPF_DIFFSERV_PHBID_CODE,
    RSVPF_DIFFSERV_PHBID_BIT14,
    RSVPF_DIFFSERV_PHBID_BIT15,

    /* Diffserv-aware TE object */
    RSVPF_DSTE_CLASSTYPE,

    /* Generalized UNI object */
    RSVPF_GUNI_SRC_IPV4,
    RSVPF_GUNI_DST_IPV4,
    RSVPF_GUNI_SRC_IPV6,
    RSVPF_GUNI_DST_IPV6,

    /* CALL ID object */
    RSVPF_CALL_ID_SRC_ADDR_IPV4,
    RSVPF_CALL_ID_SRC_ADDR_IPV6,

    /* EXCLUDE ROUTE object */
    RSVPF_EXCLUDE_ROUTE,

    /* Vendor Private objects */
    RSVPF_PRIVATE_OBJ,
    RSVPF_ENT_CODE,

    RSVPF_JUNIPER,

    /* Sentinel */
    RSVPF_MAX
};

static const true_false_string tfs_desired_not_desired = { "Desired", "Not Desired" };
static const true_false_string tfs_next_next_hop_next_hop = { "Next-Next-Hop", "Next-Hop" };
static const true_false_string tfs_loose_strict_hop = { "Loose Hop", "Strict Hop" };
static const true_false_string tfs_can_cannot = { "Can", "Cannot" };
static const true_false_string tfs_gen_uni_direction = { "U: 1 - Upstream label/port ID", "U: 0 - Downstream label/port ID" };

static const unit_name_string units_word_not_including_header = { " word, not including header", " words, not including header" };

static int hf_rsvp_filter[RSVPF_MAX] = { -1 };

/* RSVP Conversation related Hash functions */

/*
 * Compare two RSVP request keys to see if they are equal. Return 1 if they
 * are, 0 otherwise.
 * Two RSVP request keys are equal if and only if they have the exactly the
 * same internal conversation identifier, session type, and matching values in
 * the session info and source info structures.
 */
static gint
rsvp_equal(gconstpointer k1, gconstpointer k2)
{
    const struct rsvp_request_key *key1 = (const struct rsvp_request_key*) k1;
    const struct rsvp_request_key *key2 = (const struct rsvp_request_key*) k2;

    if (key1->conversation != key2->conversation) {
        return 0;
    }

    if (key1->session_type != key2->session_type) {
        return 0;
    }

    switch (key1->session_type) {
    case RSVP_SESSION_TYPE_IPV4:
        if (addresses_equal(&key1->u.session_ipv4.destination,
                            &key2->u.session_ipv4.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4.protocol != key2->u.session_ipv4.protocol)
            return 0;

        if (key1->u.session_ipv4.udp_dest_port != key2->u.session_ipv4.udp_dest_port)
            return 0;

        break;

    case RSVP_SESSION_TYPE_IPV6:
        /* this is not supported yet for conversations */
        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        if (addresses_equal(&key1->u.session_ipv4_lsp.destination,
                            &key2->u.session_ipv4_lsp.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_lsp.udp_dest_port !=
            key2->u.session_ipv4_lsp.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_lsp.ext_tunnel_id !=
            key2->u.session_ipv4_lsp.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        if (addresses_equal(&key1->u.session_agg_ipv4.destination,
                            &key2->u.session_agg_ipv4.destination) == FALSE)
            return 0;

        if (key1->u.session_agg_ipv4.dscp != key2->u.session_agg_ipv4.dscp)
            return 0;

        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV6:
        /* this is not supported yet for conversations */
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        if (addresses_equal(&key1->u.session_ipv4_uni.destination,
                            &key2->u.session_ipv4_uni.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_uni.udp_dest_port !=
            key2->u.session_ipv4_uni.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_uni.ext_tunnel_id !=
            key2->u.session_ipv4_uni.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4:
        if (addresses_equal(&key1->u.session_ipv4_p2mp_lsp.destination,
                            &key2->u.session_ipv4_p2mp_lsp.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_p2mp_lsp.udp_dest_port !=
            key2->u.session_ipv4_p2mp_lsp.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_p2mp_lsp.ext_tunnel_id !=
            key2->u.session_ipv4_p2mp_lsp.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6:
        if (addresses_equal(&key1->u.session_ipv6_p2mp_lsp.destination,
                            &key2->u.session_ipv6_p2mp_lsp.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv6_p2mp_lsp.udp_dest_port !=
            key2->u.session_ipv6_p2mp_lsp.udp_dest_port)
            return 0;


        if (key1->u.session_ipv6_p2mp_lsp.ext_tunnel_id !=
            key2->u.session_ipv6_p2mp_lsp.ext_tunnel_id)
            return 0;

        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        if (addresses_equal(&key1->u.session_ipv4_enni.destination,
                            &key2->u.session_ipv4_enni.destination) == FALSE)
            return 0;

        if (key1->u.session_ipv4_enni.udp_dest_port !=
            key2->u.session_ipv4_enni.udp_dest_port)
            return 0;


        if (key1->u.session_ipv4_enni.ext_tunnel_id !=
            key2->u.session_ipv4_enni.ext_tunnel_id)
            return 0;

        break;

    default:
        /* This should never happen. */
        break;
    }

    if (addresses_equal(&key1->source_info.source,
                        &key2->source_info.source) == FALSE)
        return 0;

    if (key1->source_info.udp_source_port != key2->source_info.udp_source_port)
        return 0;

    /* If we get here, the two keys are equal. */
    return 1;
}

/*
 * Calculate a hash key for the supplied RSVP request. The internally allocated
 * conversation-id is unique, so we just use that.
 */
static guint
rsvp_hash(gconstpointer k)
{
    const struct rsvp_request_key *key = (const struct rsvp_request_key*) k;
    return key->conversation;
}

static const char* rsvp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_IPv4))
        return "ip.src";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_IPv4))
        return "ip.dst";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_IPv4))
        return "ip.addr";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t rsvp_ct_dissector_info = {&rsvp_conv_get_filter_type};

static tap_packet_status
rsvp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const rsvp_conversation_info *rsvph = (const rsvp_conversation_info *)vip;

    add_conversation_table_data(hash, &rsvph->source, &rsvph->destination,
        0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &rsvp_ct_dissector_info, CONVERSATION_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* rsvp_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == AT_IPv4))
        return "ip.addr";

    return CONV_FILTER_INVALID;
}

static et_dissector_info_t rsvp_endpoint_dissector_info = {&rsvp_endpoint_get_filter_type};

static tap_packet_status
rsvp_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    const rsvp_conversation_info *rsvph = (const rsvp_conversation_info *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures
     * that all packets are counted properly (even if address is sending to
     * itself). XXX - this could probably be done more efficiently inside
     * endpoint_table
     */
    add_endpoint_table_data(hash, &rsvph->source, 0, TRUE, 1, pinfo->fd->pkt_len, &rsvp_endpoint_dissector_info, ENDPOINT_NONE);
    add_endpoint_table_data(hash, &rsvph->destination, 0, FALSE, 1, pinfo->fd->pkt_len, &rsvp_endpoint_dissector_info, ENDPOINT_NONE);
    return TAP_PACKET_REDRAW;
}

static inline int
rsvp_class_to_filter_num(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
    case RSVP_CLASS_HOP :
    case RSVP_CLASS_INTEGRITY :
    case RSVP_CLASS_TIME_VALUES :
    case RSVP_CLASS_ERROR :
    case RSVP_CLASS_SCOPE :
    case RSVP_CLASS_STYLE :
    case RSVP_CLASS_FLOWSPEC :
    case RSVP_CLASS_FILTER_SPEC :
    case RSVP_CLASS_SENDER_TEMPLATE :
    case RSVP_CLASS_SENDER_TSPEC :
    case RSVP_CLASS_ADSPEC :
    case RSVP_CLASS_POLICY :
    case RSVP_CLASS_CONFIRM :
    case RSVP_CLASS_LABEL :
    case RSVP_CLASS_LABEL_REQUEST :
    case RSVP_CLASS_HELLO :
    case RSVP_CLASS_EXPLICIT_ROUTE :
    case RSVP_CLASS_RECORD_ROUTE :
    case RSVP_CLASS_MESSAGE_ID :
    case RSVP_CLASS_MESSAGE_ID_ACK :
    case RSVP_CLASS_MESSAGE_ID_LIST :
        return classnum + RSVPF_OBJECT;
        break;

    case RSVP_CLASS_RECOVERY_LABEL :
    case RSVP_CLASS_UPSTREAM_LABEL :
    case RSVP_CLASS_LABEL_SET :
    case RSVP_CLASS_PROTECTION :
        return RSVPF_RECOVERY_LABEL + (classnum - RSVP_CLASS_RECOVERY_LABEL);

    case RSVP_CLASS_SUGGESTED_LABEL :
    case RSVP_CLASS_ACCEPTABLE_LABEL_SET :
    case RSVP_CLASS_RESTART_CAP :
        return RSVPF_SUGGESTED_LABEL + (classnum - RSVP_CLASS_SUGGESTED_LABEL);

    case RSVP_CLASS_LINK_CAP :
        return RSVPF_LINK_CAP;

    case RSVP_CLASS_DIFFSERV :
        return RSVPF_DIFFSERV;

    case RSVP_CLASS_CLASSTYPE :
        return RSVPF_DSTE;

    case RSVP_CLASS_NOTIFY_REQUEST :
        return RSVPF_NOTIFY_REQUEST;
    case RSVP_CLASS_ADMIN_STATUS :
        return RSVPF_ADMIN_STATUS;
    case RSVP_CLASS_LSP_ATTRIBUTES :
        return RSVPF_LSP_ATTRIBUTES;
    case RSVP_CLASS_ASSOCIATION :
        return RSVPF_ASSOCIATION;
    case RSVP_CLASS_CALL_ATTRIBUTES:
        return RSVPF_CALL_ATTRIBUTES;

    case RSVP_CLASS_SESSION_ATTRIBUTE :
        return RSVPF_SESSION_ATTRIBUTE;
    case RSVP_CLASS_GENERALIZED_UNI :
        return RSVPF_GENERALIZED_UNI;
    case RSVP_CLASS_CALL_ID :
        return RSVPF_CALL_ID;
    case RSVP_CLASS_3GPP2_OBJECT :
        return RSVPF_3GPP2_OBJECT;
    case RSVP_CLASS_DCLASS :
        return RSVPF_DCLASS;
    case RSVP_CLASS_LSP_TUNNEL_IF_ID :
        return RSVPF_LSP_TUNNEL_IF_ID;
    case RSVP_CLASS_EXCLUDE_ROUTE:
        return RSVPF_EXCLUDE_ROUTE;

    case RSVP_CLASS_JUNIPER_PROPERTIES :
        return RSVPF_JUNIPER;
    case RSVP_CLASS_VENDOR_PRIVATE_1:
    case RSVP_CLASS_VENDOR_PRIVATE_2:
    case RSVP_CLASS_VENDOR_PRIVATE_3:
    case RSVP_CLASS_VENDOR_PRIVATE_4:
    case RSVP_CLASS_VENDOR_PRIVATE_5:
    case RSVP_CLASS_VENDOR_PRIVATE_6:
    case RSVP_CLASS_VENDOR_PRIVATE_7:
    case RSVP_CLASS_VENDOR_PRIVATE_8:
    case RSVP_CLASS_VENDOR_PRIVATE_9:
    case RSVP_CLASS_VENDOR_PRIVATE_10:
    case RSVP_CLASS_VENDOR_PRIVATE_11:
    case RSVP_CLASS_VENDOR_PRIVATE_12:
       return RSVPF_PRIVATE_OBJ;

    default:
        return RSVPF_UNKNOWN_OBJ;
    }
}

static inline int
rsvp_class_to_tree_type(int classnum)
{
    switch(classnum) {
    case RSVP_CLASS_SESSION :
        return TT_SESSION;
    case RSVP_CLASS_HOP :
        return TT_HOP;
    case RSVP_CLASS_INTEGRITY :
        return TT_INTEGRITY;
    case RSVP_CLASS_TIME_VALUES :
        return TT_TIME_VALUES;
    case RSVP_CLASS_ERROR :
        return TT_ERROR;
    case RSVP_CLASS_SCOPE :
        return TT_SCOPE;
    case RSVP_CLASS_STYLE :
        return TT_STYLE;
    case RSVP_CLASS_FLOWSPEC :
        return TT_FLOWSPEC;
    case RSVP_CLASS_FILTER_SPEC :
        return TT_FILTER_SPEC;
    case RSVP_CLASS_SENDER_TEMPLATE :
        return TT_SENDER_TEMPLATE;
    case RSVP_CLASS_SENDER_TSPEC :
        return TT_TSPEC;
    case RSVP_CLASS_ADSPEC :
        return TT_ADSPEC;
    case RSVP_CLASS_POLICY :
        return TT_POLICY;
    case RSVP_CLASS_CONFIRM :
        return TT_CONFIRM;
    case RSVP_CLASS_RECOVERY_LABEL :
    case RSVP_CLASS_UPSTREAM_LABEL :
    case RSVP_CLASS_SUGGESTED_LABEL :
    case RSVP_CLASS_LABEL :
        return TT_LABEL;
    case RSVP_CLASS_LABEL_REQUEST :
        return TT_LABEL_REQUEST;
    case RSVP_CLASS_HELLO :
        return TT_HELLO_OBJ;
    case RSVP_CLASS_EXPLICIT_ROUTE :
        return TT_EXPLICIT_ROUTE;
    case RSVP_CLASS_RECORD_ROUTE :
        return TT_RECORD_ROUTE;
    case RSVP_CLASS_MESSAGE_ID :
        return TT_MESSAGE_ID;
    case RSVP_CLASS_MESSAGE_ID_ACK :
        return TT_MESSAGE_ID_ACK;
    case RSVP_CLASS_MESSAGE_ID_LIST :
        return TT_MESSAGE_ID_LIST;
    case RSVP_CLASS_LABEL_SET :
        return TT_LABEL_SET;
    case RSVP_CLASS_PROTECTION :
        return TT_PROTECTION_INFO;
    case RSVP_CLASS_ACCEPTABLE_LABEL_SET :
        return TT_UNKNOWN_CLASS;
    case RSVP_CLASS_RESTART_CAP :
        return TT_RESTART_CAP;
    case RSVP_CLASS_LINK_CAP :
        return TT_LINK_CAP;
    case RSVP_CLASS_DIFFSERV :
        return TT_DIFFSERV;
    case RSVP_CLASS_CLASSTYPE:
        return TT_CLASSTYPE;
    case RSVP_CLASS_NOTIFY_REQUEST :
        return TT_UNKNOWN_CLASS;
    case RSVP_CLASS_ADMIN_STATUS :
        return TT_ADMIN_STATUS;
    case RSVP_CLASS_LSP_ATTRIBUTES :
    case RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES :
        return TT_LSP_ATTRIBUTES;
    case RSVP_CLASS_ASSOCIATION :
        return TT_ASSOCIATION;
    case RSVP_CLASS_CALL_ATTRIBUTES:
        return RSVPF_CALL_ATTRIBUTES;
    case RSVP_CLASS_JUNIPER_PROPERTIES :
        return TT_JUNIPER;
    case RSVP_CLASS_SESSION_ATTRIBUTE :
        return TT_SESSION_ATTRIBUTE;
    case RSVP_CLASS_GENERALIZED_UNI :
        return TT_GEN_UNI;
    case RSVP_CLASS_CALL_ID :
        return TT_CALL_ID;
    case RSVP_CLASS_3GPP2_OBJECT :
        return TT_3GPP2_OBJECT;
    case RSVP_CLASS_DCLASS :
        return TT_DCLASS;
    case RSVP_CLASS_LSP_TUNNEL_IF_ID :
        return TT_LSP_TUNNEL_IF_ID;
    case RSVP_CLASS_EXCLUDE_ROUTE :
        return TT_EXCLUDE_ROUTE;
    case RSVP_CLASS_VENDOR_PRIVATE_1:
    case RSVP_CLASS_VENDOR_PRIVATE_2:
    case RSVP_CLASS_VENDOR_PRIVATE_3:
    case RSVP_CLASS_VENDOR_PRIVATE_4:
    case RSVP_CLASS_VENDOR_PRIVATE_5:
    case RSVP_CLASS_VENDOR_PRIVATE_6:
    case RSVP_CLASS_VENDOR_PRIVATE_7:
    case RSVP_CLASS_VENDOR_PRIVATE_8:
    case RSVP_CLASS_VENDOR_PRIVATE_9:
    case RSVP_CLASS_VENDOR_PRIVATE_10:
    case RSVP_CLASS_VENDOR_PRIVATE_11:
    case RSVP_CLASS_VENDOR_PRIVATE_12:
        return TT_PRIVATE_CLASS;
    default:
        return TT_UNKNOWN_CLASS;
    }
}

static void
find_rsvp_session_tempfilt(tvbuff_t *tvb, int hdr_offset, int *session_offp, int *tempfilt_offp)
{
    int   s_off = 0, t_off = 0;
    int   len, off;
    guint obj_length;

    if (!tvb_bytes_exist(tvb, hdr_offset+6, 2))
        goto done;

    len = tvb_get_ntohs(tvb, hdr_offset+6) + hdr_offset;
    for (off = hdr_offset + 8; (off < len) && tvb_bytes_exist(tvb, off, 3); off += obj_length) {
        obj_length = tvb_get_ntohs(tvb, off);
        if (obj_length == 0)
            break;
        switch(tvb_get_guint8(tvb, off+2)) {
        case RSVP_CLASS_SESSION:
            s_off = off;
            break;
        case RSVP_CLASS_SENDER_TEMPLATE:
        case RSVP_CLASS_FILTER_SPEC:
            t_off = off;
            break;
        default:
            break;
        }
    }

 done:
    if (session_offp)  *session_offp  = s_off;
    if (tempfilt_offp) *tempfilt_offp = t_off;
}

static const value_string rsvp_c_type_session_vals[] = {
    {RSVP_SESSION_TYPE_IPV4,                 "IPv4"},
    {RSVP_SESSION_TYPE_IPV4_LSP,             "IPv4-LSP"},
    {RSVP_SESSION_TYPE_IPV6_LSP,             "IPv6-LSP"},
    {RSVP_SESSION_TYPE_AGGREGATE_IPV4,       "IPv4-Aggregate"},
    {RSVP_SESSION_TYPE_IPV4_UNI,             "IPv4-UNI"},
    {RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4, "IPv4-P2MP LSP TUNNEL"},
    {RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6, "IPv6-P2MP LSP TUNNEL"},
    {RSVP_SESSION_TYPE_IPV4_E_NNI,           "IPv4-E-NNI"},
    {0,    NULL }
};

static const value_string rsvp_c_type_call_id_vals[] = {
    {0,  "Empty"},
    {1,  "Operator Specific"},
    {2,  "Globally Unique"},
    {0,  NULL }
};

static const value_string rsvp_c_type_hop_vals[] = {
    {1,  "IPv4"},
    {2,  "IPv6"},
    {3,  "IPv4  IF-ID"},
    {4,  "IPv6  IF-ID"},
    {0,  NULL }
};

static const value_string rsvp_c_type_time_values_vals[] = {
    {1,  "Time Values"},
    {0,  NULL }
};

static const value_string rsvp_c_type_error_vals[] = {
    {1,  "IPv4"},
    {2,  "IPv6"},
    {3,  "IPv4  IF-ID"},
    {4,  "IPv6  IF-ID"},
    {0,  NULL }
};

static const value_string rsvp_c_type_scope_vals[] = {
    {1,  "IPv4"},
    {2,  "IPv6"},
    {0,  NULL }
};

static const value_string rsvp_c_type_style_vals[] = {
    {1,  "Style"},
    {0,  NULL }
};

static const value_string rsvp_c_type_confirm_vals[] = {
    {1,  "IPv4"},
    {2,  "IPv6"},
    {0,  NULL }
};

static const value_string rsvp_c_type_template_vals[] = {
    {1,  "IPv4"},
    {2,  "IPv6"},
    {7,  "IPv4 LSP"},
    {8,  "IPv6 LSP"},
    {9,  "IPv4 Aggregate"},
    {12,  "P2MP_LSP_TUNNEL_IPv4"},
    {13,  "P2MP_LSP_TUNNEL_IPv6"},
    {0,  NULL }
};

static const value_string rsvp_c_type_tspec_vals[] = {
    {2,  "Integrated Services"},
    {4,  "SONET/SDH"},
    {5,  "G.709"},
    {6,  "Ethernet"},
    {0,  NULL }
};

static const value_string rsvp_c_type_flowspec_vals[] = {
    {2,  "Integrated Services"},
    {4,  "SONET/SDH"},
    {5,  "G.709"},
    {6,  "Ethernet"},
    {0,  NULL }
};

static const value_string rsvp_c_type_label_request_vals[] = {
    { 2, "Label Request with ATM label Range"},
    { 3, "Label Request with Frame-Relay label Range"},
    { 4, "Generalized Label Request"},
    { 5, "Generalized Channel_set Label Request"},
    { 0, NULL }
};

static const value_string rsvp_c_type_attribute_vals[] = {
    { 1, "IPv4 LSP"},
    { 7, "IPv4 LSP Resource Affinities"},
    { 0, NULL }
};

static const value_string rsvp_c_type_association_vals[] = {
    { 1, "IPv4"},
    { 2, "IPv6"},
    { 4, "Routing Area"},
    { 0, NULL }
};

static const value_string rsvp_c_type_tunnel_if_vals[] = {
    { 1, "Unnumbered interface"},
    { 2, "IPv4"},
    { 3, "IPv6"},
    { 4, "Unnumbered interface with target"},
    { 0, NULL }
};

static const value_string rsvp_c_type_diffserv_vals[] = {
    { 1, "E-LSP"},
    { 2, "L-LSP"},
    { 0, NULL }
};

static const value_string rsvp_c_type_label_vals[] = {
    { 1, "Packet Label"},
    { 2, "Generalized Label"},
    { 4, "Generalized Channel_set"},
    { 0, NULL }
};

static const value_string rsvp_c_type_notify_request_vals[] = {
    { 1, "IPv4"},
    { 2, "IPv6"},
    { 0, NULL }
};

static const value_string rsvp_c_type_s2l_sub_lsp_vals[] = {
    { 1, "IPv4"},
    { 2, "IPv6"},
    { 0, NULL }
};

static char *
summary_session(wmem_allocator_t *pool, tvbuff_t *tvb, int offset)
{
    switch(tvb_get_guint8(tvb, offset+3)) {
    case RSVP_SESSION_TYPE_IPV4:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4, Destination %s, Protocol %d, Port %d. ",
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_guint8(tvb, offset+8),
                                  tvb_get_ntohs(tvb, offset+10));
        break;
    case RSVP_SESSION_TYPE_IPV4_LSP:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4-LSP, Destination %s, Short Call ID %d, Tunnel ID %d, Ext ID %0x. ",
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+8),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_get_ntohl(tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_IPV6_LSP:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv6-LSP, Destination %s, Short Call ID %d, Tunnel ID %d, Ext ID %0x%0x%0x%0x. ",
                                  tvb_ip6_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+20),
                                  tvb_get_ntohs(tvb, offset+22),
                                  tvb_get_ntohl(tvb, offset+24),
                                  tvb_get_ntohl(tvb, offset+28),
                                  tvb_get_ntohl(tvb, offset+32),
                                  tvb_get_ntohl(tvb, offset+36));
    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4-Aggregate, Destination %s, DSCP %d. ",
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_guint8(tvb, offset+11));
        break;
    case RSVP_SESSION_TYPE_IPV4_UNI:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4-UNI, Destination %s, Tunnel ID %d, Ext Address %s. ",
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_ip_to_str(pool, tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4-P2MP LSP TUNNEL, PSMP ID %d, Tunnel ID %d, Ext Tunnel %s. ",
                                  tvb_get_ntohl(tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_ip_to_str(pool, tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv6-P2MP LSP TUNNEL, PSMP ID %d, Tunnel ID %d, Ext Tunnel %s. ",
                                  tvb_get_ntohl(tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_ip6_to_str(pool, tvb, offset+12));
        break;
    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        return wmem_strdup_printf(pool,
                                  "SESSION: IPv4-E-NNI, Destination %s, Tunnel ID %d, Ext Address %s. ",
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_ip_to_str(pool, tvb, offset+12));
        break;
    default:
        return wmem_strdup_printf(pool,
                                  "SESSION: Type %d. ", tvb_get_guint8(tvb, offset+3));
        break;
    }
    DISSECTOR_ASSERT_NOT_REACHED();
}

static char *
summary_template(wmem_allocator_t *pool, tvbuff_t *tvb, int offset)
{
    const char *objtype;

    if (tvb_get_guint8(tvb, offset+2) == RSVP_CLASS_FILTER_SPEC)
        objtype = "FILTERSPEC";
    else
        objtype = "SENDER TEMPLATE";

    switch(tvb_get_guint8(tvb, offset+3)) {
    case 1:
        return wmem_strdup_printf(pool,
                                  "%s: IPv4, Sender %s, Port %d. ", objtype,
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10));
        break;
    case 7:
        return wmem_strdup_printf(pool,
                                  "%s: IPv4-LSP, Tunnel Source: %s, Short Call ID: %d, LSP ID: %d. ", objtype,
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+8),
                                  tvb_get_ntohs(tvb, offset+10));
        break;
    case 8:
        return wmem_strdup_printf(pool,
                                  "%s: IPv6-LSP, Tunnel Source: %s, Short Call ID: %d, LSP ID: %d. ", objtype,
                                  tvb_ip6_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+20),
                                  tvb_get_ntohs(tvb, offset+22));
        break;
    case 9:
        return wmem_strdup_printf(pool,
                                  "%s: IPv4-Aggregate, Aggregator %s. ", objtype,
                                  tvb_ip_to_str(pool, tvb, offset+4));
        break;
    case 12:
        return wmem_strdup_printf(pool,
                                  "%s: P2MP_LSP_TUNNEL_IPv4, IPv4 tunnel sender address %s, LSP ID: %d, Sub-Group ID %d. ", objtype,
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+10),
                                  tvb_get_ntohs(tvb, offset+18));
        break;
    case 13:
        return wmem_strdup_printf(pool,
                                  "%s: P2MP_LSP_TUNNEL_IPv6, IPv6 tunnel sender address %s, LSP ID: %d, Sub-Group ID %d. ", objtype,
                                  tvb_ip_to_str(pool, tvb, offset+4),
                                  tvb_get_ntohs(tvb, offset+22),
                                  tvb_get_ntohs(tvb, offset+40));
        break;
    default:
        return wmem_strdup_printf(pool,
                                  "%s: Type %d. ", objtype, tvb_get_guint8(tvb, offset+3));
        break;
    }
    DISSECTOR_ASSERT_NOT_REACHED();
}

/*------------------------------------------------------------------------------
 * SESSION
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_session(packet_info *pinfo, proto_item *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type,
                     rsvp_conversation_info *rsvph)
{
    proto_item *hidden_item;
    int         offset2 = offset + 4;

    proto_item_set_text(ti, "%s", summary_session(pinfo->pool, tvb, offset));

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case RSVP_SESSION_TYPE_IPV4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_PROTO], tvb,
                            offset2+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_flags, tvb, offset2+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_PORT], tvb,
                            offset2+6, 2, ENC_BIG_ENDIAN);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->protocol = tvb_get_guint8(tvb, offset2+4);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);

        break;

    case RSVP_SESSION_TYPE_IPV6:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_destination_address, tvb, offset2, 16, ENC_NA);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_protocol, tvb, offset2+16, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_flags, tvb, offset2+17, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_destination_port, tvb, offset2+18, 2, ENC_BIG_ENDIAN);
        /*
         * Save this information to build the conversation request key
         * later. IPv6 conversatiuon support is not implemented yet, so only
         * the session type is stored.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV6;

        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);;
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        /*short call id*/
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_SHORT_CALL_ID],
                            tvb, offset2+4, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_extended_tunnel_id, tvb, offset2+8, 4,
                            tvb_get_ntohl(tvb, offset2+8), "%u (%s)",
                            tvb_get_ntohl(tvb, offset2+8),
                            tvb_ip_to_str(pinfo->pool, tvb, offset2+8));
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_LSP;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);
        break;

    case RSVP_SESSION_TYPE_IPV6_LSP:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 16, ENC_BIG_ENDIAN);

        /*short call id*/
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_SHORT_CALL_ID],
                            tvb, offset2+16, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+18, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_extended_tunnel_ipv6, tvb, offset2+20, 16, ENC_NA);
        proto_item_set_text(ti, "Extended Tunnel ID: (%s)", tvb_ip6_to_str(pinfo->pool, tvb, offset2+20));


        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID_IPV6],
                                   tvb, offset2+20, 16, ENC_NA);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV6_LSP;
        set_address_tvb(&rsvph->destination, AT_IPv6, 16, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+18);
        rsvph->ext_tunnel_id_ipv6_pre = tvb_get_ntoh64(tvb, offset2+20);
        rsvph->ext_tunnel_id_ipv6_post = tvb_get_ntoh64(tvb, offset2+28);
        break;


    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);;
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_dscp, tvb, offset2+7, 1, ENC_BIG_ENDIAN);
        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_AGGREGATE_IPV4;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->dscp = tvb_get_guint8(tvb, offset2+7);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_extended_ipv4_address, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_UNI;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);

        break;

    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_session_p2mp_id,
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_extended_tunnel, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);

        break;
    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_session_p2mp_id,
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_extended_tunnel, tvb, offset2+8, 16, ENC_NA);
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID_IPV6],
                                   tvb, offset2+8, 16, ENC_NA);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6;
        set_address_tvb(&rsvph->destination, AT_IPv6, 16, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+18);
        rsvph->ext_tunnel_id_ipv6_pre = tvb_get_ntoh64(tvb, offset2+20);
        rsvph->ext_tunnel_id_ipv6_post = tvb_get_ntoh64(tvb, offset2+28);
        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_IP],
                            tvb, offset2, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
                            tvb, offset2+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_extended_ipv4_address, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_item(rsvp_object_tree,
                                   hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
                                   tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_hidden(hidden_item);

        /*
         * Save this information to build the conversation request key
         * later.
         */
        rsvph->session_type = RSVP_SESSION_TYPE_IPV4_E_NNI;
        set_address_tvb(&rsvph->destination, AT_IPv4, 4, tvb, offset2);
        rsvph->udp_dest_port = tvb_get_ntohs(tvb, offset2+6);
        rsvph->ext_tunnel_id = tvb_get_ntohl(tvb, offset2 + 8);

        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_session, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_data, tvb, offset2, obj_length-4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * TLVs for HOP, ERROR and other IF_ID extended objects (RFC4920)
 * (TODO: TLV type 12, 13, 25)
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_ifid_tlv(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb, int offset, int length,
                      int subtree_type)
{
    int         tlv_off, padding;
    guint16     tlv_type;
    int         tlv_len;
    guint8      isis_len;
    const char *tlv_name, *ip_str;
    proto_tree *rsvp_ifid_subtree=NULL, *ti2 = NULL;

    for (tlv_off = 0; tlv_off < length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || (tlv_off+tlv_len > length)) {
            proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length,
                                tvb, offset+tlv_off+2, 2, "Invalid TLV length");
            return;
        }
        switch(tlv_type) {
        case 1:                         /* IPv4 */
            tlv_name = "";
            goto ifid_ipv4;
        case 14:                        /* PREVIOUS_HOP_IPV4 */
            tlv_name = "Previous-Hop ";
            goto ifid_ipv4;
        case 16:                        /* INCOMING_IPV4 */
            tlv_name = "Incoming ";
        ifid_ipv4:
            ip_str = tvb_ip_to_str(pinfo->pool, tvb, offset+tlv_off+4);
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sIPv4 TLV - %s", tlv_name,
                                      ip_str);

            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sIPv4)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_ipv4_address, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%sIPv4: %s. ", tlv_name, ip_str);
            break;

        case 2:                         /* IPv6 */
            tlv_name = "";
            goto ifid_ipv6;
        case 15:                        /* PREVIOUS_HOP_IPV6 */
            tlv_name = "Previous-Hop ";
            goto ifid_ipv6;
        case 17:                        /* INCOMING_IPV6 */
            tlv_name = "Incoming ";
        ifid_ipv6:
            ip_str = tvb_ip6_to_str(pinfo->pool, tvb, offset+tlv_off+4);
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sIPv6 TLV - %s", tlv_name, ip_str);

            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sIPv6)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_ipv6_address, tvb, offset+tlv_off+4, 16, ENC_NA);
            proto_item_append_text(ti, "%sIPv6: %s. ", tlv_name, ip_str);
            break;

        case 3:                         /* IF_INDEX */
            tlv_name = "";
            goto ifid_ifindex;
        case 4:                         /* COMPONENT_IF_DOWNSTREAM */
            tlv_name = " Forward";
            goto ifid_ifindex;
        case 5:                         /* COMPONENT_IF_UPSTREAM */
            tlv_name = " Reverse";
            goto ifid_ifindex;
        case 18:                        /* INCOMING_IF_INDEX */
            tlv_name = " Incoming";
        ifid_ifindex:
            ip_str = tvb_ip_to_str(pinfo->pool, tvb, offset+tlv_off+4);
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "Interface-Index%s TLV - %s, %d",
                                      tlv_name,
                                      ip_str,
                                      tvb_get_ntohl(tvb, offset+tlv_off+8));
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (Interface Index%s)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_ipv4_address, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlvinterface_id, tvb, offset+tlv_off+8, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "Data If-Index%s: %s, %d. ", tlv_name, ip_str,
                                   tvb_get_ntohl(tvb, offset+tlv_off+8));
            break;

        case 6:                         /* DOWNSTREAM_LABEL */
            tlv_name = "Downstream";
            goto ifid_label;
        case 7:                         /* UPSTREAM_LABEL */
            tlv_name = "Upstream";
            goto ifid_label;
        case 19:                        /* INCOMING_DOWN_LABEL */
            tlv_name = "Incoming-Downstream";
            goto ifid_label;
        case 20:                        /* INCOMING_UP_LABEL */
            tlv_name = "Incoming-Upstream";
        ifid_label:
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%s-Label TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%s-Label)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_label, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%s-Label: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;


        case 8:                         /* NODE_ID */
            tlv_name = "";
            goto ifid_nodeid;
        case 21:                        /* REPORTING_NODE_ID */
            tlv_name = "Reporting-";
        ifid_nodeid:
            ip_str = tvb_ip_to_str(pinfo->pool, tvb, offset+tlv_off+4);
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sNode-ID TLV - %s", tlv_name,
                                      ip_str);
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sNode-ID)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_node_id, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%sNode-ID: %s. ", tlv_name, ip_str);
            break;

        case 9:                         /* OSPF_AREA */
            tlv_name = "";
            goto ifid_ospf;
        case 22:                        /* REPORTING_OSPF_AREA */
            tlv_name = "Reporting-";
        ifid_ospf:
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sOSPF-Area TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sOSPF-Area)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_area, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%sOSPF-Area: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;

        case 10:                        /* ISIS_AREA */
            tlv_name = "";
            goto ifid_isis;
        case 23:                        /* REPORTING_ISIS_AREA */
            tlv_name = "Reporting-";
        ifid_isis:
            isis_len = tvb_get_guint8(tvb, offset+tlv_off+4);
            if ((isis_len < 2) || (isis_len > 11))
            {
              proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset+tlv_off, tlv_len,
                                  "%sISIS-Area TLV - Invalid Length field", tlv_name);
              break;
            }
            ip_str = print_nsap_net(pinfo->pool, tvb, offset+tlv_off+5, isis_len);
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sISIS-Area TLV - %s", tlv_name,
                                      ip_str);
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sISIS-Area)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_string(rsvp_ifid_subtree, hf_rsvp_isis_area_id, tvb, offset+tlv_off+4, 4, ip_str);
            proto_item_append_text(ti, "%sISIS-Area: %s. ", tlv_name, ip_str);
            break;

        case 11:                        /* AUTONOMOUS_SYSTEM */
            tlv_name = "";
            goto ifid_as;
        case 24:                        /* REPORTING_AUTONOMOUS_SYSTEM */
            tlv_name = "Reporting-";
        ifid_as:
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "%sAS TLV - %u", tlv_name,
                                      tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%sAS)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_autonomous_system, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%sAS: %u. ", tlv_name,
                                   tvb_get_ntohl(tvb, offset+tlv_off+4));
            break;

        case 26:                        /* NODE_EXCLUSIONS */
            tlv_name = "Node";
            goto ifid_ex;
        case 27:                        /* LINK_EXCLUSIONS */
            tlv_name = "Link";
        ifid_ex:
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, &ti2, "%s-Exclusions TLV - ", tlv_name);
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%d (%s-Exclusions)", tlv_type, tlv_name);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            dissect_rsvp_ifid_tlv(ti2, pinfo, rsvp_ifid_subtree, tvb, offset+tlv_off+4,
                                  tlv_len-4, TREE(TT_HOP_SUBOBJ));
            break;
        case 516:
            /* FF: ERROR_STRING TLV, RFC 4783 */
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree,
                                  tvb, offset + tlv_off,
                                  tlv_len,
                                  subtree_type, NULL, "ERROR_STRING TLV - %s",
                                  tvb_format_text(pinfo->pool, tvb, offset + tlv_off + 4,
                                                  tlv_len - 4));
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset + tlv_off, 2,
                                tlv_type, "516 (ERROR_STRING)");
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset + tlv_off + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_error_string, tvb, offset + tlv_off + 4, tlv_len - 4, ENC_NA|ENC_ASCII);
            break;

        default:
            /* FF: not yet known TLVs are displayed as raw data */
            rsvp_ifid_subtree = proto_tree_add_subtree_format(rsvp_object_tree,
                                      tvb, offset + tlv_off,
                                      tlv_len,
                                      subtree_type, NULL, "Unknown TLV (%u)", tlv_type);
            proto_tree_add_uint_format_value(rsvp_ifid_subtree, hf_rsvp_type, tvb, offset + tlv_off, 2,
                                tlv_type, "%u (Unknown)", tlv_type);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_length, tvb, offset + tlv_off + 2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_data, tvb, offset + tlv_off + 4, tlv_len - 4, ENC_NA);
            break;
        }

        padding = (4 - (tlv_len % 4)) % 4;
        if (padding != 0)
            proto_tree_add_item(rsvp_ifid_subtree, hf_rsvp_ifid_tlv_padding, tvb, offset + tlv_off + tlv_len, padding, ENC_NA);
        tlv_off += tlv_len + padding;
    }
}

/*------------------------------------------------------------------------------
 * HOP
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_hop(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                 tvbuff_t *tvb,
                 int offset, int obj_length,
                 int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hop, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_neighbor_address_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_logical_interface, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "HOP: IPv4, %s",
                            tvb_ip_to_str(pinfo->pool, tvb, offset2));
        break;

    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hop, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_neighbor_address_ipv6, tvb, offset2, 16, ENC_NA);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_logical_interface, tvb, offset2+16, 4, ENC_BIG_ENDIAN);
        break;

    case 3:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hop, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_neighbor_address_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_logical_interface, tvb, offset2+4, 4, ENC_BIG_ENDIAN);

        proto_item_set_text(ti, "HOP: IPv4 IF-ID. Control IPv4: %s. ",
                            tvb_ip_to_str(pinfo->pool, tvb, offset2));

        dissect_rsvp_ifid_tlv(ti, pinfo, rsvp_object_tree, tvb, offset+12, obj_length-12,
                              TREE(TT_HOP_SUBOBJ));

        break;

    case 4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hop, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_neighbor_address_ipv6, tvb, offset2, 16, ENC_NA);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_logical_interface, tvb, offset2+16, 4, ENC_BIG_ENDIAN);

        proto_item_set_text(ti, "HOP: IPv6 IF-ID. Control IPv6: %s. ",
                            tvb_ip6_to_str(pinfo->pool, tvb, offset2));

        dissect_rsvp_ifid_tlv(ti, pinfo, rsvp_object_tree, tvb, offset+24, obj_length-24,
                              TREE(TT_HOP_SUBOBJ));

        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hop, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hop_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * TIME VALUES
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_time_values(proto_item *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_time_values, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_refresh_interval, tvb, offset2, 4,
                            tvb_get_ntohl(tvb, offset2), "%u ms (%u seconds)",
                            tvb_get_ntohl(tvb, offset2),
                            tvb_get_ntohl(tvb, offset2)/1000);
        proto_item_set_text(ti, "TIME VALUES: %d ms",
                            tvb_get_ntohl(tvb, offset2));
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_time_values, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_time_values_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * Error value field in ERROR object
 *------------------------------------------------------------------------------*/
static guint16
dissect_rsvp_error_value(proto_tree *ti, tvbuff_t *tvb,
                         int offset, guint8 error_code)
{
    guint16           error_val;
    guint8            error_class, error_ctype;
    value_string_ext *rsvp_error_vals_ext_p = NULL;

    error_val = tvb_get_ntohs(tvb, offset);
    switch (error_code) {
    case RSVP_ERROR_ADMISSION:
        rsvp_error_vals_ext_p = &rsvp_admission_control_error_vals_ext;
        break;
    case RSVP_ERROR_POLICY:
        rsvp_error_vals_ext_p = &rsvp_policy_control_error_vals_ext;
        break;
    case RSVP_ERROR_TRAFFIC:
        rsvp_error_vals_ext_p = &rsvp_traffic_control_error_vals_ext;
        break;
    case RSVP_ERROR_ROUTING:
        rsvp_error_vals_ext_p = &rsvp_routing_error_vals_ext;
        break;
    case RSVP_ERROR_NOTIFY:
        rsvp_error_vals_ext_p = &rsvp_notify_error_vals_ext;
        break;
    case RSVP_ERROR_DIFFSERV:
        rsvp_error_vals_ext_p = &rsvp_diffserv_error_vals_ext;
        break;
    case RSVP_ERROR_DSTE:
        rsvp_error_vals_ext_p = &rsvp_diffserv_aware_te_error_vals_ext;
        break;
    case RSVP_ERROR_CALL_MGMT:
        rsvp_error_vals_ext_p = &rsvp_call_mgmt_error_vals_ext;
        break;
    }

    switch (error_code) {
    case RSVP_ERROR_ADMISSION:
    case RSVP_ERROR_TRAFFIC:
        if ((error_val & 0xc0) == 0) {
            DISSECTOR_ASSERT(rsvp_error_vals_ext_p != NULL);
            proto_tree_add_uint_format_value(ti, hf_rsvp_error_value, tvb, offset, 2,
                error_val, "%s (%u)",
                val_to_str_ext(error_val, rsvp_error_vals_ext_p, "Unknown (%d)"), error_val);
        }
        else if ((error_val & 0xc0) == 0x80) {
            proto_tree_add_uint_format_value(ti, hf_rsvp_error_value, tvb, offset, 2,
                error_val, "Organization specific subcode (%u)", error_val);
        }
        else if ((error_val & 0xc0) == 0xc0) {
            proto_tree_add_uint_format_value(ti, hf_rsvp_error_value, tvb, offset, 2,
                error_val, "Service specific subcode (%u)", error_val);
        }
        break;
    case RSVP_ERROR_UNKNOWN_CLASS:
    case RSVP_ERROR_UNKNOWN_C_TYPE:
        error_class = error_val / 256;
        error_ctype = error_val % 256;
        proto_tree_add_uint_format_value(ti, hf_rsvp_class, tvb, offset, 2, error_class, "%u (%s) - CType: %u",
                            error_class, val_to_str_ext_const(error_class, &rsvp_class_vals_ext, "Unknown"),
                            error_ctype);
        break;
    case RSVP_ERROR_POLICY:
    case RSVP_ERROR_NOTIFY:
    case RSVP_ERROR_ROUTING:
    case RSVP_ERROR_DIFFSERV:
    case RSVP_ERROR_DSTE:
    case RSVP_ERROR_CALL_MGMT:
        DISSECTOR_ASSERT(rsvp_error_vals_ext_p != NULL);
        proto_tree_add_uint_format_value(ti, hf_rsvp_error_value, tvb, offset, 2, error_val, "%s (%u)",
                            val_to_str_ext(error_val, rsvp_error_vals_ext_p, "Unknown (%d)"), error_val);
        break;
    default:
        proto_tree_add_uint_format_value(ti, hf_rsvp_error_value, tvb, offset, 2, error_val, "%u", error_val);
        break;
    }
    return error_val;
}

/*------------------------------------------------------------------------------
 * ERROR
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_error(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         offset3 = 0;
    guint8      error_flags;
    guint8      error_code;
    guint16     error_val;
    proto_tree *ti2 = NULL, *rsvp_error_subtree;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_error, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if(obj_length>4) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_error_node_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);

        offset3 = offset2+4;
        }
        break;
    }

    case 2: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_error, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if(obj_length>4) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_error_node_ipv6, tvb, offset2, 16, ENC_NA);

        offset3 = offset2+16;
        }
        break;
    }

    case 3: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_error, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if(obj_length>4) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_error_node_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);

        offset3 = offset2+4;
        }
        break;
    }

    case 4: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_error, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if(obj_length>16) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_error_node_ipv6, tvb, offset2, 16, ENC_NA);

        offset3 = offset2+16;
        }
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_error, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if(obj_length>4) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_data, tvb, offset2, obj_length - 4, ENC_NA);
        }
        return;
    }

    if(obj_length>4) {
        error_flags = tvb_get_guint8(tvb, offset3);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_flags,
                                 tvb, offset3, 1, ENC_BIG_ENDIAN);
        rsvp_error_subtree = proto_item_add_subtree(ti2, TREE(TT_ERROR_FLAGS));
        proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_path_state_removed,
                                 tvb, offset3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_not_guilty,
                                 tvb, offset3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_error_subtree, hf_rsvp_error_flags_in_place,
                                 tvb, offset3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti2, " %s %s %s",
                               (error_flags & (1U<<2))  ? "Path-State-Removed" : "",
                               (error_flags & (1U<<1))  ? "NotGuilty" : "",
                               (error_flags & (1U<<0))  ? "InPlace" : "");
        error_code = tvb_get_guint8(tvb, offset3+1);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_error_error_code, tvb, offset3+1, 1, ENC_BIG_ENDIAN);
        error_val = dissect_rsvp_error_value(rsvp_object_tree, tvb, offset3+2, error_code);



        switch (type) {
        case 1:
            proto_item_set_text(ti, "ERROR: IPv4, Error code: %s, Value: %d, Error Node: %s",
                                val_to_str_ext(error_code, &rsvp_error_codes_ext, "Unknown (%d)"),
                                error_val, tvb_ip_to_str(pinfo->pool, tvb, offset2));
            break;
        case 3:
            proto_item_set_text(ti, "ERROR: IPv4 IF-ID, Error code: %s, Value: %d, Control Node: %s. ",
                                val_to_str_ext(error_code, &rsvp_error_codes_ext, "Unknown (%d)"),
                                error_val, tvb_ip_to_str(pinfo->pool, tvb, offset2));
            dissect_rsvp_ifid_tlv(ti, pinfo, rsvp_object_tree, tvb, offset+12, obj_length-12,
                                  TREE(TT_ERROR_SUBOBJ));
            break;
        }
    }
}

/*------------------------------------------------------------------------------
 * SCOPE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_scope(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    mylen = obj_length - 4;
    switch(type) {
    case 1: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_scope, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        while (mylen > 0) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_scope_ipv4_address, tvb, offset2, 4, ENC_BIG_ENDIAN);
            offset2 += 4;
            mylen -= 4;
        }
        break;
    }

    case 2: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_scope, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        while (mylen > 0) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_scope_ipv6_address, tvb, offset2, 16, ENC_NA);
            offset2 += 16;
            mylen -= 16;
        }
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_scope, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_scope_data, tvb, offset2, mylen, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * STYLE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_style(proto_item *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1: {
        guint32 style;

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_style, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_style_flags, tvb, offset2, 1, ENC_BIG_ENDIAN);
        style = tvb_get_ntoh24(tvb, offset2+1);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_style_style, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "STYLE: %s (%d)",
                            val_to_str_const(style, style_vals, "Unknown"),
                            style);
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_style, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_style_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CONFIRM
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_confirm(proto_item *ti, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_confirm, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_confirm_receiver_address_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "CONFIRM: Receiver %s",
                            tvb_ip_to_str(wmem_packet_scope(), tvb, offset2));
        break;
    }

    case 2: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_confirm, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_confirm_receiver_address_ipv6, tvb, offset2, 16, ENC_NA);
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_confirm, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_confirm_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * SENDER TEMPLATE and FILTERSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_template_filter(packet_info *pinfo, proto_item *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class, int type,
                             rsvp_conversation_info *rsvph)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "%s", summary_template(pinfo->pool, tvb, offset));
    switch(type) {
    case 1:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_PORT],
                             tvb, offset2+6, 2, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         set_address_tvb(&rsvph->source, AT_IPv4, 4, tvb, offset2);
         rsvph->udp_source_port = tvb_get_ntohs(tvb, offset2+6);
         break;

     case 2:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_template_filter_source_address_ipv6, tvb, offset2, 16, ENC_NA);
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_template_filter_source_port, tvb, offset2+18, 2, ENC_BIG_ENDIAN);
         break;

     case 7:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);
         /*short call ID*/
         if (rsvp_class == RSVP_CLASS_SENDER_TEMPLATE){
             proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_SHORT_CALL_ID],
                             tvb, offset2+4, 2, ENC_BIG_ENDIAN);
         }

         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
                             tvb, offset2+6, 2, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         set_address_tvb(&rsvph->source, AT_IPv4, 4, tvb, offset2);
         rsvph->udp_source_port = tvb_get_ntohs(tvb, offset2+6);
         break;

     case 8:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 16, ENC_BIG_ENDIAN);
         /*short call ID*/
         if (rsvp_class == RSVP_CLASS_SENDER_TEMPLATE){
            proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_SHORT_CALL_ID],
                             tvb, offset2+16, 2, ENC_BIG_ENDIAN);
         }
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
                             tvb, offset2+18, 2, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         set_address_tvb(&rsvph->source, AT_IPv6, 16, tvb, offset2);
         rsvph->udp_source_port = tvb_get_ntohs(tvb, offset2+18);
         break;

    case 9:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_IP],
                             tvb, offset2, 4, ENC_BIG_ENDIAN);

         /*
          * Save this information to build the conversation request key later.
          */
         set_address_tvb(&rsvph->source, AT_IPv4, 4, tvb, offset2);
         break;

    case 12:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_ipv4_tunnel_sender_address,
                             tvb, offset2, 4, ENC_BIG_ENDIAN);
         offset2 += 4;
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_reserved,
                             tvb, offset2, 2, ENC_NA);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
                             tvb, offset2, 2, ENC_BIG_ENDIAN);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_sub_group_originator_id,
                             tvb, offset2, 4, ENC_NA);
         offset2 += 4;
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_reserved,
                             tvb, offset2, 2, ENC_NA);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_sub_group_id,
                             tvb, offset2, 2, ENC_BIG_ENDIAN);
         /*offset += 2;*/
         break;

    case 13:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_ipv6_tunnel_sender_address,
                             tvb, offset2, 16, ENC_NA);
         offset2 += 16;
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_reserved,
                             tvb, offset2, 2, ENC_NA);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
                             tvb, offset2, 2, ENC_BIG_ENDIAN);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_sub_group_originator_id,
                             tvb, offset2, 16, ENC_NA);
         offset2 += 16;
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_reserved,
                             tvb, offset2, 2, ENC_NA);
         offset2 += 2;
         proto_tree_add_item(rsvp_object_tree,
                             hf_rsvp_template_filter_sub_group_id,
                             tvb, offset2, 2, ENC_BIG_ENDIAN);
         /*offset += 2;*/
         break;

     default:
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_template, tvb, offset+3, 1, ENC_BIG_ENDIAN);
         proto_tree_add_item(rsvp_object_tree, hf_rsvp_template_filter_data, tvb, offset2, obj_length - 4, ENC_NA);
         break;
 }
}

/*------------------------------------------------------------------------------
 * TLVs for Ethernet SENDER TSPEC and FLOWSPEC (RFC6003)
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_eth_tspec_tlv(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                           tvbuff_t *tvb, int offset, int tlv_length,
                           int subtree_type)
{
    int         tlv_off;
    int         bit_offset;
    guint16     tlv_type;
    int         tlv_len;
    guint8      profile;
    proto_tree *rsvp_ethspec_subtree, *ethspec_profile_subtree, *ti3;

    for (tlv_off = 0; tlv_off < tlv_length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || (tlv_off+tlv_len > tlv_length)) {
            proto_tree_add_expert(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset+tlv_off+2, 2);
            return;
        }
        switch(tlv_type) {
        case 0:
        case 1:

        /*case 2: ethernet bandwidth profile accordig to RFC 6003*/
        case 2:
            rsvp_ethspec_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len, subtree_type, NULL,
                                      "Ethernet Bandwidth Profile TLV: CIR=%.10g, CBS=%.10g, "
                                      "EIR=%.10g, EBS=%.10g",
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            proto_tree_add_uint_format_value(rsvp_ethspec_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%u - Ethernet Bandwidth Profile", tlv_type);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            profile = tvb_get_guint8(tvb, offset+tlv_off+4);
            ti3 = proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_profile, tvb, offset+tlv_off+4, 1, ENC_NA);
            ethspec_profile_subtree = proto_item_add_subtree(ti3, TREE(TT_ETHSPEC_SUBTREE));
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_color_mode,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_coupling_flag,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti3, " %s %s",
                                   (profile & (1U<<1))  ? "CM" : "",
                                   (profile & (1U<<0))  ? "CF" : "");
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_index, tvb, offset+tlv_off+5, 1, ENC_NA);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_reserved, tvb, offset+tlv_off+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_cir, tvb, offset+tlv_off+8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_cbs, tvb, offset+tlv_off+12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_eir, tvb, offset+tlv_off+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_ebs, tvb, offset+tlv_off+20, 4, ENC_BIG_ENDIAN);

            proto_item_append_text(ti, "ETH profile: CIR=%.10g, CBS=%.10g, EIR=%.10g, "
                                       "EBS=%.10g",
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            break;

        /* L2CP RFC 6004 */
        case 3:
            if (tlv_len != 8){
                proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length,
                                             tvb, offset+tlv_off+2, 2, "Invalid TLV length");
            return;
            }
            /* point to the first bit in the Ingress Layer 2 Control Processing */
            bit_offset = (offset<<5) + 31;
            proto_tree_add_bits_item(rsvp_object_tree, hf_rsvp_eth_tspec_il2cp, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            proto_tree_add_bits_item(rsvp_object_tree, hf_rsvp_eth_tspec_el2cp, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            break;

        case 255:
            rsvp_ethspec_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len,
                                      subtree_type, NULL, "RESERVED (RFC6003)");
            proto_tree_add_uint_format_value(rsvp_ethspec_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%u (RESERVED)", tlv_type);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            break;

        case 129:     /* OIF demo 2009 */
            rsvp_ethspec_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+tlv_off, tlv_len, subtree_type, NULL,
                                      "Ethernet Bandwidth Profile TLV: CIR=%.10g, CBS=%.10g, "
                                      "EIR=%.10g, EBS=%.10g",
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                      tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            proto_tree_add_uint_format_value(rsvp_ethspec_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "%u - Ethernet Bandwidth Profile", tlv_type);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            profile = tvb_get_guint8(tvb, offset+tlv_off+4);
            ti3 = proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_profile, tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            ethspec_profile_subtree = proto_item_add_subtree(ti3, TREE(TT_ETHSPEC_SUBTREE));
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_color_mode,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ethspec_profile_subtree, hf_rsvp_eth_tspec_tlv_coupling_flag,
                             tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti3, " %s %s",
                                   (profile & (1U<<1))  ? "CM" : "",
                                   (profile & (1U<<0))  ? "CF" : "");
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_index, tvb, offset+tlv_off+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_reserved, tvb, offset+tlv_off+6, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_cir, tvb, offset+tlv_off+8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_cbs, tvb, offset+tlv_off+12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_eir, tvb, offset+tlv_off+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ethspec_subtree, hf_rsvp_eth_tspec_ebs, tvb, offset+tlv_off+20, 4, ENC_BIG_ENDIAN);

            proto_item_append_text(ti, "ETH profile: CIR=%.10g, CBS=%.10g, EIR=%.10g, "
                                       "EBS=%.10g",
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+8),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+12),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+16),
                                   tvb_get_ntohieee_float(tvb, offset+tlv_off+20));
            break;

        default:
            proto_tree_add_uint_format(rsvp_object_tree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "Unknown TLV: %u", tlv_type);
            break;
        }
        tlv_off += tlv_len;
    }
}

/*------------------------------------------------------------------------------
 * SENDER TSPEC
 *------------------------------------------------------------------------------*/
static const value_string rsvp_switching_granularity_vals[] = {
   {0,    "Provided in signaling"},
   {1,    "Ethernet port"},
   {2,    "Ethernet frame"},
   {0,    NULL }
};

static void
dissect_rsvp_tspec(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         mylen;
    proto_tree *tspec_tree, *ti2 = NULL;
    guint8      signal_type;
    guint16     m;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    mylen = obj_length - 4;

    switch(type) {
    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_message_format_version, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_data_length, tvb, offset2+2, 2, ENC_BIG_ENDIAN);

        mylen -= 4;
        offset2 += 4;

        proto_item_set_text(ti, "SENDER TSPEC: IntServ, ");

        while (mylen > 0) {
            guint8 param_id;
            guint param_len, raw_len;
            guint param_len_processed;
            guint length;

            proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_service_header, tvb, offset2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(rsvp_object_tree, hf_rsvp_data_length, tvb, offset2+2, 2, ENC_BIG_ENDIAN, &length);

            mylen -= 4;
            offset2 += 4;

            /* Process all known service headers as a set of parameters */
            param_len_processed = 0;
            while (param_len_processed < length) {
                param_id = tvb_get_guint8(tvb, offset2);
                ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_parameter, tvb, offset2, 1, ENC_NA);
                raw_len = tvb_get_ntohs(tvb, offset2+2);
                param_len = raw_len + 1;
                switch(param_id) {
                case 127:
                    /* Token Bucket */
                    proto_item_set_len(ti2, param_len*4);
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_item(tspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(tspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);
                    proto_tree_add_item(tspec_tree, hf_rsvp_tspec_token_bucket_rate, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tspec_tree, hf_rsvp_tspec_token_bucket_size, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tspec_tree, hf_rsvp_tspec_peak_data_rate, tvb, offset2+12, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tspec_tree, hf_rsvp_minimum_policed_unit, tvb, offset2+16, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tspec_tree, hf_rsvp_maximum_packet_size, tvb, offset2+20, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "Token Bucket, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "Rate=%.10g Burst=%.10g Peak=%.10g m=%u M=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohieee_float(tvb, offset2+8),
                                           tvb_get_ntohieee_float(tvb, offset2+12),
                                           tvb_get_ntohl(tvb, offset2+16),
                                           tvb_get_ntohl(tvb, offset2+20));
                    break;

                case 128:
                    /* Null Service (RFC2997) */
                    proto_item_set_len(ti2, param_len*4);
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_item(tspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(tspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);
                    proto_tree_add_item(tspec_tree, hf_rsvp_maximum_packet_size, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "Null Service. M=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti2, "Max pkt size=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    break;

                case 126:
                    /* Compression hint (RFC3006) */
                    proto_item_set_len(ti2, param_len*4);
                    tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

                    proto_tree_add_item(tspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(tspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);
                    proto_tree_add_item(tspec_tree, hf_rsvp_tspec_hint, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tspec_tree, hf_rsvp_compression_factor, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "Compression Hint. Hint=%u, Factor=%u",
                                           tvb_get_ntohl(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    proto_item_append_text(ti2, "Hint=%u, Factor=%u",
                                           tvb_get_ntohl(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    break;

                default:
                    proto_item_set_len(ti2, param_len*4);
                    expert_add_info_format(pinfo, ti2, &ei_rsvp_parameter, "Unknown parameter %d, %d words", param_id, param_len);
                    break;
                }
                param_len_processed += param_len;
                offset2 += param_len*4;
            }
            mylen -= length*4;
        }
        break;

    case 4: /* SONET/SDH Tspec */
        proto_item_set_text(ti, "SENDER TSPEC: SONET/SDH, ");

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_signal_type_sonet, tvb, offset2, 1, ENC_BIG_ENDIAN);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_requested_concatenation, tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_standard_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_number_of_contiguous_components, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_number_of_virtual_components, tvb, offset2+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_multiplier, tvb, offset2+6, 2, ENC_BIG_ENDIAN);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_transparency, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        tspec_tree = proto_item_add_subtree(ti2, TREE(TT_TSPEC_SUBTREE));

        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_regenerator_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_multiplex_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_J0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_K1_K2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_E1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_F1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_E2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_B1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_B2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_M0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tspec_tree, hf_rsvp_sender_tspec_M1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_profile, tvb, offset2+12, 4, ENC_BIG_ENDIAN);

        proto_item_append_text(ti, "Signal [%s], RCC %d, NCC %d, NVC %d, MT %d, Transparency %d, Profile %d",
                               val_to_str_ext_const(signal_type, &gmpls_sonet_signal_type_str_ext, "Unknown"),
                               tvb_get_guint8(tvb, offset2+1), tvb_get_ntohs(tvb, offset2+2),
                               tvb_get_ntohs(tvb, offset2+4), tvb_get_ntohs(tvb, offset2+6),
                               tvb_get_ntohl(tvb, offset2+8), tvb_get_ntohl(tvb, offset2+12));
        break;

    case 5: /* FF: G.709 TSPEC, RFC 4328 */
        proto_item_set_text(ti, "SENDER TSPEC: G.709, ");

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tspec, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_signal_type_g709, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_number_of_multiplexed_components, tvb, offset2 + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_number_of_virtual_components, tvb, offset2 + 4, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_multiplier, tvb, offset2 + 6, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Signal [%s], NMC %d, NVC %d, MT %d",
                               rval_to_str(signal_type,
                                           gmpls_g709_signal_type_rvals,
                                           "Unknown"),
                               tvb_get_ntohs(tvb, offset2 + 2),
                               tvb_get_ntohs(tvb, offset2 + 4),
                               tvb_get_ntohs(tvb, offset2 + 6));
        break;

    case 6: /* Ethernet TSPEC (RFC6003)  */
        proto_item_set_text(ti, "SENDER TSPEC: Ethernet, ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_switching_granularity, tvb, offset2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_mtu, tvb, offset2+2, 2, ENC_BIG_ENDIAN);

        dissect_rsvp_eth_tspec_tlv(ti, pinfo, rsvp_object_tree, tvb, offset+8, obj_length-8,
                                   TREE(TT_TSPEC_SUBTREE));
        break;

    case 8: /* SSON FOWSPEC (RFC7762)*/
        m = tvb_get_ntohs(tvb, offset2);
        proto_item_set_text(ti, "SENDER TSPEC: SSON, ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_m, tvb, offset2, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "slot width (m) = %f (%d)",
                               m*12.5,
                               tvb_get_ntohs(tvb, offset2));
        break;

    default: /* Unknown TSpec */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_tspec_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;

    }
}

/*------------------------------------------------------------------------------
 * FLOWSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_flowspec(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset, int obj_length,
                      int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    int         mylen, signal_type;
    proto_tree *flowspec_tree, *ti2 = NULL;
    proto_item *hidden_item;
    guint16 m;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    mylen = obj_length - 4;

    switch(type) {

    case 2:
        if (mylen < 4) {
            proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, 0, 0,
                                       "Object length %u < 8", obj_length);
            return;
        }
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_message_format_version, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_data_length, tvb, offset2+2, 2, ENC_BIG_ENDIAN);

        proto_item_set_text(ti, "FLOWSPEC: ");

        mylen -= 4;
        offset2+= 4;
        while (mylen > 0) {
            guint8 service_num;
            guint length;
            guint8 param_id;
            guint param_len, raw_len;
            guint param_len_processed;

            if (mylen < 4) {
                proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, 0, 0,
                                           "Object length %u not large enough", obj_length);
                return;
            }
            service_num = tvb_get_guint8(tvb, offset2);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_service_header, tvb, offset2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(rsvp_object_tree, hf_rsvp_data_length, tvb, offset2+2, 2, ENC_BIG_ENDIAN, &length);

            mylen   -= 4;
            offset2 += 4;

            proto_item_append_text(ti, "%s: ",
                                   val_to_str_ext(service_num, &intsrv_services_str_ext,
                                                  "Unknown (%d)"));

            /* Process all known service headers as a set of parameters */
            param_len_processed = 0;
            while (param_len_processed < length) {
                ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_parameter, tvb, offset2, 1, ENC_NA);
                param_id = tvb_get_guint8(tvb, offset2);
                raw_len = tvb_get_ntohs(tvb, offset2+2);
                param_len = raw_len + 1;
                switch(param_id) {
                case 127:
                    /* Token Bucket */
                    proto_item_set_len(ti2, param_len*4);
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

                    proto_tree_add_item(flowspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(flowspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_token_bucket_rate, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_token_bucket_size, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_peak_data_rate, tvb, offset2+12, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_minimum_policed_unit, tvb, offset2+16, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_maximum_packet_size, tvb, offset2+20, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "Token Bucket, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "Rate=%.10g Burst=%.10g Peak=%.10g m=%u M=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohieee_float(tvb, offset2+8),
                                           tvb_get_ntohieee_float(tvb, offset2+12),
                                           tvb_get_ntohl(tvb, offset2+16),
                                           tvb_get_ntohl(tvb, offset2+20));
                    break;

                case 130:
                    /* Guaranteed-rate RSpec */
                    proto_item_set_len(ti2, param_len*4);
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

                    proto_tree_add_item(flowspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(flowspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);

                    proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_rate, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_slack_term, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "RSpec, %.10g bytes/sec. ",
                                           tvb_get_ntohieee_float(tvb, offset2+4));
                    proto_item_append_text(ti2, "R=%.10g, s=%u",
                                           tvb_get_ntohieee_float(tvb, offset2+4),
                                           tvb_get_ntohl(tvb, offset2+8));
                    break;

                case 128:
                    /* Null Service (RFC2997) */
                    proto_item_set_len(ti2, param_len*4);
                    flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

                    proto_tree_add_item(flowspec_tree, hf_rsvp_parameter_flags, tvb, offset2+1, 1, ENC_NA);
                    proto_tree_add_uint(flowspec_tree, hf_rsvp_parameter_length, tvb, offset2+2, 2, raw_len);
                    proto_tree_add_item(flowspec_tree, hf_rsvp_maximum_packet_size, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, "Null Service. M=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    proto_item_append_text(ti2, "Max pkt size=%u",
                                           tvb_get_ntohl(tvb, offset2+4));
                    break;

                default:
                    expert_add_info_format(pinfo, ti2, &ei_rsvp_parameter, "Unknown parameter %d, %d words", param_id, param_len);
                    break;
                }
                param_len_processed += param_len;
                offset2 += param_len * 4;
            }

            /* offset2 += length*4; */
            mylen -= length*4;
        }
        break;

    case 4:
        proto_item_set_text(ti, "FLOWSPEC: SONET/SDH, ");

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_signal_type_sonet, tvb, offset2, 1, ENC_BIG_ENDIAN);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_requested_concatenation, tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_standard_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_arbitrary_contiguous_concatenation,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_number_of_contiguous_components, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_number_of_virtual_components, tvb, offset2+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_multiplier, tvb, offset2+6, 2, ENC_BIG_ENDIAN);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_transparency, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        flowspec_tree = proto_item_add_subtree(ti2, TREE(TT_FLOWSPEC_SUBTREE));

        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_regenerator_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_multiplex_section,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_J0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_SOH_RSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_LOH_MSOH_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_K1_K2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_E1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_F1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_E2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_B1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_B2_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_M0_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(flowspec_tree, hf_rsvp_flowspec_M1_transparency,
                             tvb, offset2+8, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_profile, tvb, offset2+12, 4, ENC_BIG_ENDIAN);

        proto_item_append_text(ti, "Signal [%s], RCC %d, NCC %d, NVC %d, MT %d, Transparency %d, Profile %d",
                               val_to_str_ext_const(signal_type, &gmpls_sonet_signal_type_str_ext, "Unknown"),
                               tvb_get_guint8(tvb, offset2+1), tvb_get_ntohs(tvb, offset2+2),
                               tvb_get_ntohs(tvb, offset2+4), tvb_get_ntohs(tvb, offset2+6),
                               tvb_get_ntohl(tvb, offset2+8), tvb_get_ntohl(tvb, offset2+12));
        break;

    case 5: /* FF: G.709 FLOWSPEC, RFC 4328 */
        proto_item_set_text(ti, "FLOWSPEC: G.709, ");

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        signal_type = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_signal_type_g709, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_number_of_multiplexed_components, tvb, offset2 + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_number_of_virtual_components, tvb, offset2 + 4, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_multiplier, tvb, offset2 + 6, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Signal [%s], NMC %d, NVC %d, MT %d",
                               rval_to_str(signal_type,
                                           gmpls_g709_signal_type_rvals,
                                           "Unknown"),
                               tvb_get_ntohs(tvb, offset2 + 2),
                               tvb_get_ntohs(tvb, offset2 + 4),
                               tvb_get_ntohs(tvb, offset2 + 6));
        break;

    case 6: /* Ethernet FLOWSPEC (RFC6003)  */
        proto_item_set_text(ti, "FLOWSPEC: Ethernet, ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_switching_granularity, tvb, offset2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_mtu, tvb, offset2+2, 2, ENC_BIG_ENDIAN);

        dissect_rsvp_eth_tspec_tlv(ti, pinfo, rsvp_object_tree, tvb, offset+8, obj_length-8,
                                   TREE(TT_FLOWSPEC_SUBTREE));
        break;
    case 8: /* SSON FOWSPEC (RFC7762)*/
        m = tvb_get_ntohs(tvb, offset2);
        proto_item_set_text(ti, "FLOWSPEC: SSON, ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_flowspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_flowspec_m, tvb, offset2, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "slot width (m) = %f (%d)",
                               m*12.5,
                               tvb_get_ntohs(tvb, offset2));
        break;

    default:
        break;
    }
}

/*------------------------------------------------------------------------------
 * ADSPEC
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_adspec(proto_item *ti _U_, packet_info* pinfo, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type _U_)
{
    int         offset2 = offset + 4;
    int         mylen, i;
    proto_tree *adspec_tree, *adspec_type_tree;
    proto_item *ti2;

    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_adspec, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    mylen = obj_length - 4;

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_adspec_message_format_version, tvb, offset2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_data_length, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    mylen -= 4;
    offset2 += 4;
    while (mylen > 0) {
        guint8 service_num;
        guint length;
        const char *str;

        service_num = tvb_get_guint8(tvb, offset2);
        str = val_to_str_ext_const(service_num, &intsrv_services_str_ext, "Unknown");
        length = tvb_get_ntohs(tvb, offset2+2);
        adspec_tree = proto_tree_add_subtree(rsvp_object_tree, tvb, offset2,
                                 (length+1)*4, TREE(TT_ADSPEC_SUBTREE), NULL, str);

        proto_tree_add_item(adspec_tree, hf_rsvp_adspec_service_header, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(adspec_tree, hf_rsvp_hf_rsvp_adspec_break_bit, tvb, offset2+1, 1, ENC_NA);
        proto_tree_add_uint(adspec_tree, hf_rsvp_data_length, tvb, offset2+2, 2, length);
        mylen -= 4;
        offset2 += 4;
        i = length*4;
        while (i > 0) {
            guint id, phdr_length;

            ti2 = proto_tree_add_item_ret_uint(adspec_tree, hf_rsvp_adspec_type, tvb, offset2, 1, ENC_NA, &id);
            adspec_type_tree = proto_item_add_subtree(ti2, TREE(TT_ADSPEC_TYPE_SUBTREE));
            proto_tree_add_item_ret_uint(adspec_type_tree, hf_rsvp_adspec_len, tvb, offset2+2, 2, ENC_BIG_ENDIAN, &phdr_length);
            proto_item_set_len(ti2, phdr_length);
            str = try_val_to_str_ext(id, &adspec_params_ext);
            if (str) {
                switch(id) {
                case 4:
                case 8:
                case 10:
                case 133:
                case 134:
                case 135:
                case 136:
                    /* 32-bit unsigned integer */
                    proto_tree_add_uint_format(adspec_type_tree, hf_rsvp_adspec_uint, tvb, offset2, (phdr_length+1)<<2, tvb_get_ntohl(tvb, offset2+4),
                                        "%s: %u", str, tvb_get_ntohl(tvb, offset2+4));
                    break;

                case 6:
                    /* IEEE float */
                    proto_tree_add_float_format(adspec_type_tree, hf_rsvp_adspec_float, tvb, offset2, (phdr_length+1)<<2, tvb_get_ntohieee_float(tvb, offset2+4),
                                        "%s: %.10g", str, tvb_get_ntohieee_float(tvb, offset2+4));
                    break;
                default:
                    proto_tree_add_bytes_format(adspec_tree, hf_rsvp_adspec_bytes, tvb, offset2, (phdr_length+1)<<2, NULL, "%s", str);
                    break;
                }
            } else {
                expert_add_info(pinfo, ti2, &ei_rsvp_adspec_type);
            }
            offset2 += (phdr_length+1)<<2;
            i -= (phdr_length+1)<<2;
            mylen -= (phdr_length+1)<<2;
        }
    }
}

/*------------------------------------------------------------------------------
 * INTEGRITY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_integrity(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                       tvbuff_t *tvb,
                       int offset, int obj_length,
                       int rsvp_class _U_, int type _U_)
{
    int         offset2 = offset + 4;
    proto_tree *ti2, *rsvp_integ_flags_tree;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_integrity, tvb, offset+3, 1, ENC_BIG_ENDIAN);

    ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_integrity_flags, tvb, offset2, 1, ENC_BIG_ENDIAN);
    rsvp_integ_flags_tree = proto_item_add_subtree(ti2, TREE(TT_INTEGRITY_FLAGS));
    proto_tree_add_item(rsvp_integ_flags_tree, hf_rsvp_integrity_flags_handshake,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_integrity_key_identifier, tvb, offset2+2, 6, ENC_NA);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_integrity_sequence_number, tvb, offset2+8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_integrity_hash, tvb, offset2+16, obj_length - 20, ENC_NA);
}

/*------------------------------------------------------------------------------
 * POLICY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_policy(proto_item *ti _U_, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type _U_)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_policy, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_policy_data, tvb, offset2, obj_length - 4, ENC_NA);
}

/*------------------------------------------------------------------------------
 * LABEL_REQUEST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_label_request(proto_item *ti, proto_tree *rsvp_object_tree,
                           tvbuff_t *tvb,
                           int offset, int obj_length,
                           int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label_request, tvb, offset+3, 1, ENC_BIG_ENDIAN);

    switch(type) {
    case 1: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_l3pid, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LABEL REQUEST: Basic: L3PID: %s (0x%04x)",
                            val_to_str_const(l3pid, etype_vals, "Unknown"),
                            l3pid);
        break;
    }

    case 2: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        unsigned short min_vpi, min_vci, max_vpi, max_vci;
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_l3pid, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_m, tvb, offset2+4, 1, ENC_NA);
        min_vpi = tvb_get_ntohs(tvb, offset2+4) & 0x7f;
        min_vci = tvb_get_ntohs(tvb, offset2+6);
        max_vpi = tvb_get_ntohs(tvb, offset2+8) & 0x7f;
        max_vci = tvb_get_ntohs(tvb, offset2+10);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_min_vpi, tvb, offset2+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_min_vci, tvb, offset2+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_max_vpi, tvb, offset2+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_max_vci, tvb, offset2+10, 2, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LABEL REQUEST: ATM: L3PID: %s (0x%04x). VPI/VCI: Min: %d/%d, Max: %d/%d. %s Merge. ",
                            val_to_str_const(l3pid, etype_vals, "Unknown"), l3pid,
                            min_vpi, min_vci, max_vpi, max_vci,
                            (tvb_get_guint8(tvb, offset2+4) & 0x80) ? "Can" : "Cannot");
        break;
    }

    case 3: {
        guint16 l3pid = tvb_get_ntohs(tvb, offset2+2);
        guint32 min_dlci, max_dlci, dlci_len, dlci_len_code;
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_l3pid, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        dlci_len_code = (tvb_get_ntohs(tvb, offset2+4) & 0x0180) >> 7;
        min_dlci = tvb_get_ntohl(tvb, offset2+4) & 0x7fffff;
        max_dlci = tvb_get_ntohl(tvb, offset2+8) & 0x7fffff;
        switch(dlci_len_code) {
        case 0:
            /* 10-bit DLCIs */
            dlci_len = 10;
            min_dlci &= 0x3ff;
            max_dlci &= 0x3ff;
            break;
        case 2:
            dlci_len = 23;
            break;
        default:
            dlci_len = 0;
            min_dlci = 0;
            max_dlci = 0;
            break;
        }
        proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_dlci_length, tvb, offset2+4, 2,
                            dlci_len, "%s (%d)",
                            (dlci_len==10) ? "10 bits" :
                            (dlci_len==23) ? "23 bits" :
                            "INVALID", dlci_len_code);
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_min_dlci, tvb, offset2+5, 3, min_dlci);
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_max_dlci, tvb, offset2+8, 2, max_dlci);
        proto_item_set_text(ti, "LABEL REQUEST: Frame: L3PID: %s (0x%04x). DLCI Len: %s. Min DLCI: %d. Max DLCI: %d",
                            val_to_str_const(l3pid, etype_vals, "Unknown"), l3pid,
                            (dlci_len==10) ? "10 bits" :
                            (dlci_len==23) ? "23 bits" :
                            "INVALID", min_dlci, max_dlci);
        break;
    }
    case 4:
    case 5: {
        unsigned short l3pid = tvb_get_ntohs(tvb, offset2+2);
        unsigned char  lsp_enc = tvb_get_guint8(tvb,offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_lsp_encoding_type, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_switching_type, tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_g_pid, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LABEL REQUEST: Generalized: LSP Encoding=%s, "
                            "Switching Type=%s, G-PID=%s ",
                            rval_to_str(lsp_enc, gmpls_lsp_enc_rvals, "Unknown (%d)"),
                            rval_to_str(tvb_get_guint8(tvb,offset2+1),
                                       gmpls_switching_type_rvals, "Unknown (%d)"),
                            rval_to_str_const(l3pid, gmpls_gpid_rvals,
                                              val_to_str(l3pid, etype_vals,
                                                         "Unknown (0x%04x)")));
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_request_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    } /* switch(type) */
}

/*-----------------------------------------------------------------------------
 * LABEL
 *---------------------------------------------------------------------------*/

/*
   FF: G.694 lambda label, see draft-ietf-ccamp-gmpls-g-694-lambda-labels-05

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Grid | C.S   |    Reserved     |              n                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static const value_string lambda_grid_vals[] = {
    {   1, "DWDM"},
    {   2, "CWDM"},
    {   3, "Flexi"},
    {   0, NULL }
};

static const value_string grid1_cs_vals[] = {
    {   1, "100GHz"},
    {   2, "50GHz"},
    {   3, "25GHz"},
    {   4, "12.5GHz"},
    {   0, NULL }
};
static const value_string grid2_cs_vals[] = {
    {   1, "20nm"},
    {   0, NULL }
};
static const value_string grid3_cs_vals[] = {
    {   5, "6.25GHz"},
    {   0, NULL }
};

static void
dissect_glabel_lambda(proto_tree *ti, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset)
{
    float freq = 0.0f;
    float slot_width = 0.0f;
    guint32 wavelength = 0;
    float cs_thz = 0.0f;
    proto_tree *wavelength_tree;
    guint8 grid, cs;
    gint16 n, m;



    grid = ((tvb_get_guint8(tvb, offset) & 0xE0) >> 5);
    cs = ((tvb_get_guint8(tvb, offset) & 0x1E) >> 1);
    n = tvb_get_ntohs(tvb, offset + 2);

    wavelength_tree = proto_tree_add_subtree(rsvp_object_tree, tvb, offset, 4, TREE(TT_WAVELENGTH), NULL, "Wavelength Label");
    proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_grid, tvb, offset, 1, ENC_NA);


    switch(grid) {
    case 1: /* DWDM grid: Frequency (THz) = 193.1 THz + n * channel spacing (THz) */
        cs_thz =
        cs == 1 ? 0.1f :
        cs == 2 ? 0.05f :
        cs == 3 ? 0.025f :
        cs == 4 ? 0.0125f :
        0.0f;
        freq = 193.1f + (n * cs_thz);
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_cs1, tvb, offset, 1, ENC_NA);
        proto_tree_add_uint_format_value(wavelength_tree, hf_rsvp_wavelength_n, tvb, offset+2, 2, n, "%d", n);
        proto_tree_add_float_format_value(wavelength_tree, hf_rsvp_wavelength_freq, tvb, offset, 4, freq, "%.2fTHz", freq);
        proto_item_append_text(ti, ": Wavelength: grid=DWDM, channel spacing=%s, central frequency=%d, freq=%.2fTHz",
                               val_to_str_const(cs, grid1_cs_vals, "Unknown"), n, freq);
        break;
    case 2: /* CWDM grid: Wavelength (nm) = 1471 nm + n * 20 nm  */
        wavelength = 1471 + (n * 20);
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_cs2, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_n, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_uint_format_value(wavelength_tree, hf_rsvp_wavelength_wavelength, tvb, offset, 4, wavelength, "%unm", wavelength);
        proto_item_append_text(ti, ": Wavelength: grid=CWDM, channel spacing=%s, central frequenc=%d, wavelength=%unm",
                           val_to_str_const(cs, grid2_cs_vals, "Unknown"), n, wavelength);
        break;
    case 3: /* flexi grid: Slot width (Ghz) = 12.5 Ghz * m, see RFC 7699  */
        m = tvb_get_ntohs(tvb, offset + 4);
        slot_width = 12.5f  * m;
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_cs3, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_n, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_float_format_value(wavelength_tree, hf_rsvp_wavelength_m, tvb, offset, 4, slot_width, "%.2fGHz", slot_width);
        proto_item_append_text(ti, ": Wavelength: grid=flexi, channel spacing=%s, central frequenc=%d, Channel Width=%.2fGhz",
                           val_to_str_const(cs, grid3_cs_vals, "Unknown"), n, slot_width);
    break;
    default: /* unknown grid: */
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_channel_spacing, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(wavelength_tree, hf_rsvp_wavelength_n, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": Wavelength: grid=%u, channel spacing=%u, central frequenc=%d", grid, cs, n);
        break;
    }
}

/*
   FF: SONET/SDH label, see RFC 4606

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               S               |   U   |   K   |   L   |   M   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static void
dissect_glabel_sdh(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset)
{
    guint16 s;
    guint8 u, k, l, m;
    proto_tree* sonet_tree;

    sonet_tree = proto_tree_add_subtree(rsvp_object_tree, tvb, offset, 4, TREE(TT_SONET_SDH), NULL, "SONET/SDH Label");
    proto_tree_add_item(sonet_tree, hf_rsvp_sonet_s, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(sonet_tree, hf_rsvp_sonet_u, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sonet_tree, hf_rsvp_sonet_k, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sonet_tree, hf_rsvp_sonet_l, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sonet_tree, hf_rsvp_sonet_m, tvb, offset+3, 1, ENC_BIG_ENDIAN);

    s = tvb_get_ntohs(tvb, offset);
    u = ((tvb_get_guint8(tvb, offset + 2) & 0xF0) >> 4);
    k = ((tvb_get_guint8(tvb, offset + 2) & 0x0F) >> 0);
    l = ((tvb_get_guint8(tvb, offset + 3) & 0xF0) >> 4);
    m = ((tvb_get_guint8(tvb, offset + 3) & 0x0F) >> 0);
    proto_item_append_text(ti, ": SONET/SDH: S=%u, U=%u, K=%u, L=%u, M=%u",
                           s, u, k, l, m);
}

/*
    FF: G.709 label (aka ODUk label), see RFC 4328

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Reserved                |     t3    | t2  |t1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static void
dissect_glabel_g709(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset)
{
    guint8 t1, t2, t3;
    proto_tree* g709_tree;

    g709_tree = proto_tree_add_subtree(rsvp_object_tree, tvb, offset, 4, TREE(TT_G709), NULL, "G.709 ODUk Label");
    proto_tree_add_item(g709_tree, hf_rsvp_g709_t3, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(g709_tree, hf_rsvp_g709_t2, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(g709_tree, hf_rsvp_g709_t1, tvb, offset+3, 1, ENC_BIG_ENDIAN);

    t2 = ((tvb_get_guint8(tvb, offset + 3) & 0x0E) >> 1);
    t1 = ((tvb_get_guint8(tvb, offset + 3) & 0x01) >> 0);
    t3 = ((tvb_get_guint8(tvb, offset + 2) & 0x03) << 4);
    t3 |= ((tvb_get_guint8(tvb, offset + 3) & 0xF0) >> 4);

    proto_item_append_text(ti, ": G.709 ODUk: "
                        "t3=%u, "
                        "t2=%u, "
                        "t1=%u",
                        t3, t2, t1);
}

/*
  FF: EVPL Generalized Label, see RFC6004
         0                   1
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Rsvd  |        VLAN ID        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static void
dissect_glabel_evpl(proto_tree *ti _U_, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset)
{
    int bit_offset;
    guint16 vlan_id = ((tvb_get_ntohs(tvb,offset) << 4) & 0xFFFF);

    /* point to the first bit in VLAN ID */
    bit_offset = (offset<<2)+3;
    proto_tree_add_bits_item(rsvp_object_tree,hf_rsvp_label_generalized_label_evpl_vlad_id,tvb, bit_offset, 12, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": EVPL Generalized Label: "
                        "VLAN ID = %u" ,vlan_id);
}

static void
dissect_rsvp_label(proto_tree *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length,
                   int rsvp_class, int type)
{
    int         offset2 = offset + 4;
    int         mylen, i;
    const char *name;
    proto_item *hidden_item;
    guint32 unassigned_upstream_label;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    name = (rsvp_class==RSVP_CLASS_SUGGESTED_LABEL ? "SUGGESTED LABEL":
            (rsvp_class==RSVP_CLASS_UPSTREAM_LABEL ? "UPSTREAM LABEL":
             (rsvp_class==RSVP_CLASS_RECOVERY_LABEL ? "RECOVERY LABEL":
             "LABEL")));
    mylen = obj_length - 4;
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_label, tvb, offset2, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "%s: %u", name,
                            tvb_get_ntohl(tvb, offset2));
        break;

    case 2:
        unassigned_upstream_label = tvb_get_ntoh24(tvb, offset2);
        if(unassigned_upstream_label == 0xffffffff){ /* Unassigned upstream label, see RFC 8359 */
            proto_item_append_text(ti, ":  Unassigned upstream label ( 0x%x )",unassigned_upstream_label);
        }
        else {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            if (rsvp_generalized_label_option == 1) { /* FF: no generalized label interpretation */
                proto_item_set_text(ti, "%s: Generalized: ", name);
                for (i = 0; i < mylen; i += 4) {
                    proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_generalized_label, tvb, offset2+i, 4, ENC_BIG_ENDIAN);
                    if (i < 16) {
                        proto_item_append_text(ti, "0x%x%s", tvb_get_ntohl(tvb, offset2+i), i+4<mylen?", ":"");
                    }
                    else if (i == 16) {
                        proto_item_append_text(ti, "...");
                    }
                }
            } else if (rsvp_generalized_label_option == 2) {
                dissect_glabel_sdh(ti, rsvp_object_tree, tvb, offset2);
            } else if (rsvp_generalized_label_option == 4) {
               dissect_glabel_g709(ti, rsvp_object_tree, tvb, offset2);
            } else if (rsvp_generalized_label_option == 3) {
               dissect_glabel_lambda(ti, rsvp_object_tree, tvb, offset2);
            } else if (rsvp_generalized_label_option == 5) {
               dissect_glabel_evpl(ti, rsvp_object_tree, tvb, offset2);
            }
        }
        break;

    case 4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": Generalized Channel_set");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_data, tvb, offset2, mylen, ENC_NA);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_data, tvb, offset2, mylen, ENC_NA);
        break;
    }
}
/*------------------------------------------------------------------------------
 * LABEL_SET
 *------------------------------------------------------------------------------*/
static const value_string action_type_vals[] = {
    { 0, "Inclusive list"},
    { 1, "Exclusive list"},
    { 2, "Inclusive range"},
    { 3, "Exclusive range"},
    { 0, NULL}
};

static void
dissect_rsvp_label_set(proto_item *ti, proto_tree *rsvp_object_tree,
                       tvbuff_t *tvb,
                       int offset, int obj_length,
                       int rsvp_class _U_, int type _U_)
{
    int    offset2 = offset + 8;
    guint8 label_type;
    int    len, i;

    len = obj_length - 8;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_label_set, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_label_set_action, tvb, offset+4, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": %s",
                           val_to_str(tvb_get_guint8(tvb, offset+4),
                           action_type_vals, "Unknown (%u)"));
    label_type = tvb_get_guint8 (tvb, offset+7);
    proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_label_set_type, tvb, offset+7, 1, label_type,
                                     "%s", (label_type == 1) ? "Packet Label" : "Generalized Label");
    proto_item_append_text(ti, ", %s",
                           (label_type == 1) ? "Packet Label: " : "Generalized Label: ");

    for (i = 0; i < len/4; i++) {
        guint32 subchannel = tvb_get_ntohl(tvb, offset2+i*4);
        proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_label_set_subchannel, tvb, offset2+i*4, 4, subchannel,
                                            "Subchannel %u: %u (0x%x)", i+1, subchannel, subchannel);

        if (i<5) {
            if (i!=0)
                proto_item_append_text(ti, ", ");

            proto_item_append_text(ti, "%u",
                                   tvb_get_ntohl(tvb, offset2+i*4));
        }
    }
}

/*------------------------------------------------------------------------------
 * SESSION ATTRIBUTE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_session_attribute(proto_item *ti, proto_tree *rsvp_object_tree,
                               tvbuff_t *tvb,
                               int offset, int obj_length,
                               int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    guint8      flags;
    guint8      name_len;
    proto_tree *ti2, *rsvp_sa_flags_tree;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
    case 7:

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_attribute, tvb, offset+3, 1, ENC_BIG_ENDIAN);

        if (type == 1) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_exclude_any, tvb, offset2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_include_any, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_include_all, tvb, offset2+8, 4, ENC_BIG_ENDIAN);
            offset2 = offset2+12;
        }

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_setup_priority, tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_hold_priority, tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        flags = tvb_get_guint8(tvb, offset2+2);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_flags, tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        rsvp_sa_flags_tree = proto_item_add_subtree(ti2,
                                                    TREE(TT_SESSION_ATTRIBUTE_FLAGS));
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_local,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_label,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_se_style,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_bandwidth,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_sa_flags_tree, hf_rsvp_sa_flags_node,
                             tvb, offset2+2, 1, ENC_BIG_ENDIAN);

        name_len = tvb_get_guint8(tvb, offset2+3);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_name_length, tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_name, tvb, offset2+4, name_len, ENC_NA|ENC_ASCII);
        proto_item_set_text(ti, "SESSION ATTRIBUTE: SetupPrio %d, HoldPrio %d, %s%s%s%s%s [%s]",
                            tvb_get_guint8(tvb, offset2),
                            tvb_get_guint8(tvb, offset2+1),
                            flags &0x01 ? "Local Protection, " : "",
                            flags &0x02 ? "Label Recording, " : "",
                            flags &0x04 ? "SE Style, " : "",
                            flags &0x08 ? "Bandwidth Protection, " : "",
                            flags &0x10 ? "Node Protection, " : "",
                            name_len ? tvb_format_text(wmem_packet_scope(), tvb, offset2+4, name_len) : "");
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_attribute, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_session_attribute_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE AND RECORD ROUTE SUBOBJECTS,
 * RFC 3209, RFC 3473, RFC 5420, RFC 4873, RFC 5553
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_ro_subobjects(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length, int rsvp_class)
{
    int         i, type, lbit, dbit, path_key, l, flags;
    proto_tree *ti2 = NULL, *rsvp_ro_subtree, *rsvp_rro_flags_subtree;
    int         tree_type;

    switch(rsvp_class) {
    case RSVP_CLASS_EXPLICIT_ROUTE:
        tree_type = TREE(TT_EXPLICIT_ROUTE_SUBOBJ);
        break;
    case RSVP_CLASS_RECORD_ROUTE:
        tree_type = TREE(TT_RECORD_ROUTE_SUBOBJ);
        break;
    case RSVP_CLASS_EXCLUDE_ROUTE:
        tree_type = TREE(TT_EXCLUDE_ROUTE_SUBOBJ);
        break;
    default:
        /* Bail out */
        return;
    }
    /*  0                   1                   2                   3    */
    /*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
    /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
    /* |L|    Type     |     Length    |           Value...            | */
    /* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

    for (i=1, l = 0; l < obj_length - 4; i++) {
        type = tvb_get_guint8(tvb, offset + l);
        if ((rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE) ||
            (rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE))
            type &= 0x7f;
        lbit = tvb_get_guint8(tvb, offset + l) & 0x80;
        dbit = tvb_get_guint8(tvb, offset + l + 2) & 0x80;
        switch(type) {
        case 1: /* IPv4 */
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      tree_type, &ti2, "IPv4 Subobject - %s%s",
                                      tvb_ip_to_str(pinfo->pool, tvb, offset+l+2),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (lbit ? ", Loose" : ", Strict") : "");

            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);
            if (rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE){
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_lbit, tvb, offset+l, 1, ENC_BIG_ENDIAN);
            }
            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1, type, "1 (IPv4)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            if(rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE || rsvp_class == RSVP_CLASS_RECORD_ROUTE){
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_ipv4_hop, tvb, offset+l+2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_prefix_length, tvb, offset+l+6, 1, ENC_BIG_ENDIAN);
            }
            if(rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE){
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_ipv4_addr, tvb, offset + l + 2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_ipv4_prefix, tvb, offset + l + 6, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_ipv4_attr, tvb, offset + l + 7, 1, ENC_BIG_ENDIAN);
            }
            if (i < 4) {
                proto_item_append_text(ti, "IPv4 %s%s",
                                       tvb_ip_to_str(pinfo->pool, tvb, offset+l+2),
                                       lbit ? " [L]" : "");
            }
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+7);
                if (flags&0x20) {
                    proto_item_append_text(ti,  " (Node-id)");
                    proto_item_append_text(ti2, " (Node-id)");
                }
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_flags, tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_bandwidth,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node_address,
                             tvb, offset+l+7, 1, ENC_BIG_ENDIAN);
            }

            break;

        case 2: /* IPv6 */
            rsvp_ro_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                      offset+l, 20, tree_type, &ti2,
                                      "IPv6 Subobject");
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE){
                    proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);
                }

                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_lbit,
                                tvb, offset + l, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type,
                                                tvb, offset+l, 1, type, "2 (IPv6)");
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length,
                                                tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_ipv6_hop,
                                                tvb, offset+l+2, 16, ENC_NA);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_prefix_length,
                                                tvb, offset+l+18, 1, ENC_BIG_ENDIAN);
                if(rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE){
                    proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_ipv6_attr,
                                                    tvb, offset + l + 19, 1, ENC_BIG_ENDIAN);
               }
            if (i < 4) {
                proto_item_append_text(ti, "IPv6 [...]%s", lbit ? " [L]":"");
            }
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+19);
                if (flags&0x20) {
                    proto_item_append_text(ti,  " (Node-id)");
                    proto_item_append_text(ti2, " (Node-id)");
                }
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                if (flags&0x04) proto_item_append_text(ti2, ", Backup BW Avail");
                if (flags&0x08) proto_item_append_text(ti2, ", Backup is Next-Next-Hop");
                ti2 = proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_flags, tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));

                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_bandwidth,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_backup_tunnel_hop,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_node_address,
                             tvb, offset+l+19, 1, ENC_BIG_ENDIAN);

            }

            break;

        case 3: /* Label RFC 3477 */
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 8,
                                      tree_type, &ti2, "Label Subobject - %d, %s",
                                      tvb_get_ntohl(tvb, offset+l+4),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (lbit ? "Loose" : "Strict") : "");
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);

            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "3 (Label)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+2);
                if (flags&0x01) proto_item_append_text(ti2, "The label will be understood if received on any interface");
                ti2 = proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_flags, tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));

                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_global_label,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
            }
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ctype, tvb, offset+l+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_label, tvb, offset+l+4, 4, ENC_BIG_ENDIAN);
            if (i < 4) {
                proto_item_append_text(ti, "Label %d%s",
                                       tvb_get_ntohl(tvb, offset+l+4),
                                       lbit ? " [L]":"");
            }
            break;

        case 4: /* Unnumbered Interface-ID RFC 3477, RFC 6107*/
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 8, tree_type, &ti2,
                                      "Unnumbered Interface-ID - %s, %d, %s",
                                      tvb_ip_to_str(pinfo->pool, tvb, offset+l+4),
                                      tvb_get_ntohl(tvb, offset+l+8),
                                      rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE ?
                                      (lbit ? "Loose" : "Strict") : "");
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE)
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);

            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "4 (Unnumbered Interface-ID)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE) {
                flags = tvb_get_guint8(tvb, offset+l+2);
                if (flags&0x01) proto_item_append_text(ti2, ", Local Protection Available");
                if (flags&0x02) proto_item_append_text(ti2, ", Local Protection In Use");
                ti2 = proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_flags, tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                rsvp_rro_flags_subtree =
                    proto_item_add_subtree(ti2, TREE(TT_RECORD_ROUTE_SUBOBJ_FLAGS));
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_avail,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_rro_flags_subtree, hf_rsvp_rro_flags_local_in_use,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
            }
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_router_id, tvb, offset+l+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_interface_id, tvb, offset+l+8, 4, ENC_BIG_ENDIAN);
            if (i < 4) {
                proto_item_append_text(ti, "Unnum %s/%d%s",
                                       tvb_ip_to_str(pinfo->pool, tvb, offset+l+4),
                                       tvb_get_ntohl(tvb, offset+l+8),
                                       lbit ? " [L]":"");
            }
            break;

        case 21:

        case 32: /* AS */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE || rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE) goto defaultsub;
            lbit = tvb_get_ntohs(tvb, offset+l+2);
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 4, tree_type, &ti2,
                                      "Autonomous System %u",
                                      lbit);
            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "32 (Autonomous System Number)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_autonomous_system, tvb, offset+l+2, 2, ENC_BIG_ENDIAN);
            if (i < 4) {
                proto_item_append_text(ti, "AS %d",
                                       tvb_get_ntohs(tvb, offset+l+2));
            }
            break;


        case 34: /* SRLG subobject RFC 4874 */
            if (rsvp_class == RSVP_CLASS_EXPLICIT_ROUTE) goto defaultsub;
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE){
                rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset + l, 8, tree_type, NULL,
                                              "SRLG Subobject - %u",
                                              tvb_get_ntohl(tvb, offset + l + 4));

                proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type,
                                        tvb, offset+l, 1,type, "34 (SRLG sub-object)");
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_len,
                                        tvb, offset + l + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_rro_sobj_dbit,
                                        tvb, offset + l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_srlg_res,
                                        tvb, offset + l + 2, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_srlg_id,
                                        tvb, offset + l + 4, 4, ENC_BIG_ENDIAN);

                if (i < 4) {
                    proto_item_append_text(ti, "SRLG %u%s",
                                               tvb_get_ntohl(tvb, offset + l + 4),
                                               dbit ? " [D]" : "");
                }
            }
            else{
                rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                                  offset + l, 8, tree_type, NULL,
                                                  "SRLG Subobject - %u",
                                                  tvb_get_ntohl(tvb, offset + l + 2));
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_lbit,
                                                  tvb, offset + l, 1, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type,
                                                  tvb, offset+l, 1,type, "34 (SRLG sub-object)");
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_len,
                                                  tvb, offset + l + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_srlg_id,
                                                  tvb, offset + l + 2, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_xro_sobj_srlg_res,
                                                  tvb, offset + l + 6, 2, ENC_BIG_ENDIAN);
                if (i < 4) {
                    proto_item_append_text(ti, "SRLG %u%s",
                                                tvb_get_ntohl(tvb, offset + l + 2),
                                                lbit ? " [L]" : "");
                }
            }
            break;

        case 64: /* PKSv4 - RFC5520 */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE || rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE) goto defaultsub;
            path_key = tvb_get_ntohs(tvb, offset+l+2);
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 8, tree_type, &ti2,
                                      "Path Key subobject - %s, %u",
                                      tvb_ip_to_str(pinfo->pool, tvb, offset+l+4),
                                      path_key);
            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "64 (Path Key with IPv4 PCE-ID)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_path_key, tvb, offset+l+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_pce_id_ipv4, tvb, offset+l+4, 4, ENC_BIG_ENDIAN);
            if (i < 4) {
                proto_item_append_text(ti, "Path Key %d", path_key);
            }
            break;

        case 65: /* PKSv6 - RFC5520 */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE || rsvp_class == RSVP_CLASS_EXCLUDE_ROUTE) goto defaultsub;
            path_key = tvb_get_ntohs(tvb, offset+l+2);
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l, 8, tree_type, &ti2,
                                      "Path Key subobject - %s, %u",
                                      tvb_ip6_to_str(pinfo->pool, tvb, offset+l+4),
                                      path_key);
            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "65 (Path Key with IPv6 PCE-ID)");
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_path_key, tvb, offset+l+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_pce_id_ipv6, tvb, offset+l+4, 16, ENC_NA);
            if (i < 4) {
                proto_item_append_text(ti, "Path Key %d", path_key);
            }
            break;

        case 124:
        case 125:
        case 126:
        case 127:
            /*
             * FF: Types 124 through 127 are to be reserved for Vendor
             * Private Use (see RFC 3936, Section 2.3.1) in case of
             * EXPLICIT_ROUTE (aka ERO).
             */
            if (rsvp_class == RSVP_CLASS_RECORD_ROUTE)
                goto defaultsub;
            else
                goto privatesub;
            break;

        case 252:
        case 253:
        case 254:
        case 255:
            /*
             * FF: Types 252 through 255 are to be reserved for Vendor
             * Private Use (see RFC 3936, Section 2.3.1) in case of
             * RECORD_ROUTE (aka RRO).
             */

        privatesub: /* Private subobject */
            /*
             * FF: The first four octets of the sub-object contents of
             * a Vendor Private sub-object of an EXPLICIT_ROUTE or
             * RECORD_ROUTE object MUST be that vendor's SMI enterprise
             * code in network octet order.
             */
            {
                guint8 private_so_len = tvb_get_guint8(tvb, offset+l+1);
                rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset+l,
                                          tvb_get_guint8(tvb, offset+l+1),
                                          tree_type, &ti2, "Private Subobject: %d", type);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);
                proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                    type, "%u (Private)", type);
                proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_private_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(rsvp_ro_subtree,
                                    hf_rsvp_filter[RSVPF_ENT_CODE],
                                    tvb, offset+l+4, 4, ENC_BIG_ENDIAN);
                if (private_so_len > 8) {
                    /* some private data */
                    proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_private_data, tvb, offset+l+8, private_so_len - 8, ENC_NA);
                }
            }
            break;

        default: /* Unknown subobject */
        defaultsub:
            rsvp_ro_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                      offset+l,
                                      tvb_get_guint8(tvb, offset+l+1),
                                      tree_type, &ti2, "Unknown subobject: %d", type);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_loose_hop, tvb, offset+l, 1, ENC_NA);

            proto_tree_add_uint_format_value(rsvp_ro_subtree, hf_rsvp_type, tvb, offset+l, 1,
                                type, "%u (Unknown)", type);
            proto_tree_add_item(rsvp_ro_subtree, hf_rsvp_ero_rro_subobjects_length, tvb, offset+l+1, 1, ENC_BIG_ENDIAN);
            break;
        }

        if (tvb_get_guint8(tvb, offset+l+1) < 1) {
            proto_tree_add_expert_format(rsvp_ro_subtree, pinfo, &ei_rsvp_invalid_length, tvb, offset+l+1, 1,
                "Invalid length: %u", tvb_get_guint8(tvb, offset+l+1));
            return;
        }
        l += tvb_get_guint8(tvb, offset+l+1);
        if (l < obj_length - 4) {
            if (i < 4)
                proto_item_append_text(ti, ", ");
            else if (i==4)
                proto_item_append_text(ti, "...");
        }
    }
}



/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_explicit_route(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class, int type)
{
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_explicit_route, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "EXPLICIT ROUTE: ");

        dissect_rsvp_ro_subobjects(ti, pinfo, rsvp_object_tree, tvb,
                                        offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_explicit_route, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_explicit_route_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * RECORD ROUTE OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_record_route(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class, int type)
{
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "RECORD ROUTE: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_record_route, tvb, offset+3, 1, ENC_BIG_ENDIAN);

        dissect_rsvp_ro_subobjects(ti, pinfo, rsvp_object_tree, tvb,
                                        offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_record_route, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_record_route_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * EXCLUDE ROUTE OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_exclude_route(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                           tvbuff_t *tvb, int offset, int obj_length,
                           int rsvp_class, int ctype)
{
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "EXCLUDE ROUTE: ");
    switch (ctype) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_exclude_route, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        dissect_rsvp_ro_subobjects(ti, pinfo, rsvp_object_tree, tvb,
                                   offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_exclude_route, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_exclude_route_data, tvb, offset + 4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id(proto_tree *ti, proto_tree *rsvp_object_tree,
                        tvbuff_t *tvb,
                        int offset, int obj_length,
                        int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_epoch, tvb, offset+5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_message_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "MESSAGE-ID: %d %s",
                            tvb_get_ntohl(tvb, offset+8),
                            tvb_get_guint8(tvb, offset+4) & 1 ? "(Ack Desired)" : "");
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID ACK
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id_ack(proto_tree *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id_ack, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_epoch, tvb, offset+5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_message_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "MESSAGE-ID ACK: %d", tvb_get_ntohl(tvb, offset+8));
        break;

    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id_ack, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_epoch, tvb, offset+5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_message_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "MESSAGE-ID NACK: %d", tvb_get_ntohl(tvb, offset+8));
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id_ack, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_ack_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * MESSAGE ID LIST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_message_id_list(proto_tree *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id_list, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_list_flags, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_list_epoch, tvb, offset+5, 3, ENC_BIG_ENDIAN);
        for (mylen = 8; mylen < obj_length; mylen += 4)
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_list_message_id, tvb, offset+mylen, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "MESSAGE-ID LIST: %d IDs",
                            (obj_length - 8)/4);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_message_id_list, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_message_id_list_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * HELLO
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_hello(proto_tree *ti, proto_tree *rsvp_object_tree,
                   tvbuff_t *tvb,
                   int offset, int obj_length _U_,
                   int rsvp_class _U_, int type)
{
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hello, tvb, offset+3,  1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hello_source_instance, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_hello_destination_instance, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": %s. Src Instance: 0x%0x. Dest Instance: 0x%0x. ",
                               type==1 ? "REQUEST" : "ACK",
                               tvb_get_ntohl(tvb, offset+4),
                               tvb_get_ntohl(tvb, offset+8));
        break;
    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_hello, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        break;
    };
}

/*------------------------------------------------------------------------------
 * DCLASS
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_dclass(proto_tree *ti, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    int mylen;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "DCLASS: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_dclass, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        for (mylen = 4; mylen < obj_length; mylen += 4) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_dclass_dscp, tvb, offset+mylen+3, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "%d%s",
                                   tvb_get_guint8(tvb, offset+mylen+3)>>2,
                                   mylen==obj_length-4 ? "":
                                   mylen<16 ? ", ":
                                   mylen==16 ? ", ..." : "");
        }
        break;

    default:
        mylen = obj_length - 4;
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_dclass, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_dclass_data, tvb, offset2, mylen, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * ADMINISTRATIVE STATUS
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_admin_status(proto_tree *ti, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class _U_, int type)
{
    int         offset2 = offset + 4;
    guint32     status;
    static int * const status_flags[] = {
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_REFLECT],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_HANDOVER],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_LOCKOUT],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_INHIBIT],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_CALL_MGMT],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_TESTING],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_DOWN],
        &hf_rsvp_filter[RSVPF_ADMIN_STATUS_DELETE],
        NULL
    };
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "ADMIN STATUS: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_admin_status, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        status = tvb_get_ntohl(tvb, offset2);

        proto_tree_add_bitmask(rsvp_object_tree, tvb, offset2, hf_rsvp_admin_status_bits, TREE(TT_ADMIN_STATUS_FLAGS), status_flags, ENC_BIG_ENDIAN);

        proto_item_set_text(ti, "ADMIN-STATUS: %s%s%s%s%s%s%s%s",
                            (status & (1U<<31)) ? "Reflect " : "",
                            (status & (1U<<6)) ? "Handover " : "",
                            (status & (1U<<5)) ? "Lockout " : "",
                            (status & (1U<<4)) ? "Inhibit " : "",
                            (status & (1U<<3)) ? "Call " : "",
                            (status & (1U<<2)) ? "Testing " : "",
                            (status & (1U<<1)) ? "Admin-Down " : "",
                            (status & (1U<<0)) ? "Deleting " : "");
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_admin_status, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_admin_status_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * LSP ATTRIBUTES
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_lsp_attributes(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb, int offset, int obj_length,
                            int rsvp_class, int type)
{
    int         tlv_off;
    guint32     attributes;
    guint16     tlv_type, tlv_len;
    proto_tree *ti2, *rsvp_lsp_attr_subtree;
    static int * const rsvp_lsp_attr_flags[] = {
        &hf_rsvp_lsp_attr_e2e,
        &hf_rsvp_lsp_attr_boundary,
        &hf_rsvp_lsp_attr_segment,
        &hf_rsvp_lsp_attr_integrity,
        &hf_rsvp_lsp_attr_contiguous,
        &hf_rsvp_lsp_attr_stitching,
        &hf_rsvp_lsp_attr_preplanned,
        &hf_rsvp_lsp_attr_nophp,
        &hf_rsvp_lsp_attr_oobmap,
        &hf_rsvp_lsp_attr_entropy,
        &hf_rsvp_lsp_attr_oammep,
        &hf_rsvp_lsp_attr_oammip,
        &hf_rsvp_lsp_attr_srlgcollect,
        &hf_rsvp_lsp_attr_loopback,
        &hf_rsvp_lsp_attr_p2mp,
        &hf_rsvp_lsp_attr_rtm,
        &hf_rsvp_lsp_attr_telinklabel,
        &hf_rsvp_lsp_attr_lsi,
        &hf_rsvp_lsp_attr_lsids2e,
        NULL
    };
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    if (rsvp_class == RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES)
        proto_item_set_text(ti, "LSP REQUIRED ATTRIBUTES: ");
    else
        proto_item_set_text(ti, "LSP ATTRIBUTES: ");

    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_lsp_attributes, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        for (tlv_off = 4; tlv_off < obj_length-4; ) {
            tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
            tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

            if ((tlv_len == 0) || (tlv_off+tlv_len > obj_length)) {
                proto_tree_add_expert(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset+tlv_off+2, 2);
                return;
            }
            switch(tlv_type) {
            case 1:
                attributes = tvb_get_ntohl(tvb, offset+tlv_off+4);
                ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_attributes_tlv, tvb, offset+tlv_off, 4, ENC_BIG_ENDIAN);
                rsvp_lsp_attr_subtree = proto_item_add_subtree(ti2, TREE(TT_LSP_ATTRIBUTES_FLAGS));
                proto_tree_add_bitmask(rsvp_lsp_attr_subtree, tvb, offset+tlv_off+4, hf_rsvp_lsp_attr, ett_treelist[TT_RSVP_LSP_ATTR], rsvp_lsp_attr_flags, ENC_NA);
                proto_item_append_text(ti, "LSP Attribute:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                                       (attributes & 0x80000000) ? " End-to-end re-routing" : "",
                                       (attributes & 0x40000000) ? " Boundary re-routing" : "",
                                       (attributes & 0x20000000) ? " Segment-based re-routing" : "",
                                       (attributes & 0x10000000) ? " LSP Integrity Required" : "",
                                       (attributes & 0x08000000) ? " Contiguous LSP" : "",
                                       (attributes & 0x04000000) ? " LSP stitching desired" : "",
                                       (attributes & 0x02000000) ? " Pre-Planned LSP Flag" : "",
                                       (attributes & 0x01000000) ? " Non-PHP behavior flag" : "",
                                       (attributes & 0x00800000) ? " OOB mapping flag" : "",
                                       (attributes & 0x00400000) ? " Entropy Label Capability" : "",
                                       (attributes & 0x00200000) ? " OAM MEP entities desired" : "",
                                       (attributes & 0x00100000) ? " OAM MIP entities desired" : "",
                                       (attributes & 0x00080000) ? " SRLG Collection Flag" : "",
                                       (attributes & 0x00040000) ? " Loopback" : "",
                                       (attributes & 0x00020000) ? " P2MP-TE Tree Re-evaluation Request" : "",
                                       (attributes & 0x00010000) ? " RTM_SET" : "",
                                       (attributes & 0x00008000) ? " TE Link Label" : "",
                                       (attributes & 0x00004000) ? " LSI-D" : "",
                                       (attributes & 0x00002000) ? " LSI-D-S2E" : "");

                break;

            default:
                proto_tree_add_uint_format(rsvp_object_tree, hf_rsvp_type, tvb, offset+tlv_off, tlv_len,
                                    tlv_type, "Unknown TLV: %d", tlv_type);
                break;
            }
            tlv_off += tlv_len;
        }
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_lsp_attributes, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_attributes_tlv_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * ASSOCIATION
 *------------------------------------------------------------------------------*/
static const value_string association_type_vals[] = {
    { 0, "Reserved"},
    { 1, "Recovery"},
    { 2, "Resource Sharing"},
    { 3, "Segment Recovery"},
    { 4, "Inter-domain Recovery"},
    { 0, NULL}
};

static void
dissect_rsvp_association(proto_tree *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    guint16 association_type;
    guint16 association_id;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "ASSOCIATION ");
    association_type = tvb_get_ntohs (tvb, offset + 4);
    association_id = tvb_get_ntohs (tvb, offset + 6);
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_association, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "(IPv4): ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%s. ",
                               val_to_str(association_type, association_type_vals, "Unknown (%u)"));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_id, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "ID: %u. ", association_id);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_source_ipv4, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Src: %s", tvb_ip_to_str(wmem_packet_scope(), tvb, offset+8));
        break;

    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_association, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "(IPv6): ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%s. ",
                               val_to_str(association_type, association_type_vals, "Unknown (%u)"));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_id, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "ID: %u. ", association_id);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_source_ipv6, tvb, offset+8, 16, ENC_NA);
        proto_item_append_text(ti, "Src: %s", tvb_ip6_to_str(wmem_packet_scope(), tvb, offset+8));
        break;

    case 4:       /* oif2008.389 */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_association, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "(Routing Area): ");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_type, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%s. ",
                               val_to_str(association_type, association_type_vals, "Unknown (%u)"));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_id, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Association ID: %u, ", association_id);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_routing_area_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Routing Area ID: %u, ", tvb_get_ntohl (tvb, offset+8));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_node_id, tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "Node ID: %s", tvb_ip_to_str(wmem_packet_scope(), tvb, offset+12));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_padding, tvb, offset+8, 16, ENC_NA);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_association, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_association_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}
/*------------------------------------------------------------------------------
 * TLVs for LSP TUNNEL IF ID object
 * draft-ietf-ccamp-lsp-hierarchy-bis-02
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_lsp_tunnel_if_id_tlv(proto_tree *rsvp_object_tree, packet_info* pinfo,
                                  tvbuff_t *tvb, int offset, int tlv_length,
                                  int subtree_type)
{
    int       tlv_off;
    guint16   tlv_type;
    int       tlv_len;
    proto_tree *ti, *rsvp_lsp_tunnel_if_id_subtree;

    for (tlv_off = 0; tlv_off < tlv_length; ) {
        tlv_type = tvb_get_ntohs(tvb, offset+tlv_off);
        tlv_len = tvb_get_ntohs(tvb, offset+tlv_off+2);

        if ((tlv_len == 0) || ((tlv_off+tlv_len) > tlv_length)) {
            proto_tree_add_expert(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset+tlv_off+2, 2);
            return;
        }
        switch(tlv_type) {
        case 1:
            rsvp_lsp_tunnel_if_id_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len, subtree_type, NULL,
                                     "Unnumbered component link identifier: %u",
                                     tvb_get_ntohl(tvb, offset+tlv_off+4));
            proto_tree_add_uint_format_value(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "1 (Unnumbered component link identifier)");
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_component_link_identifier, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            break;

        case 2:
            rsvp_lsp_tunnel_if_id_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len, subtree_type, NULL,
                                     "IPv4 component link identifier: %s",
                                     tvb_ip_to_str(pinfo->pool, tvb, offset+tlv_off+4));
            proto_tree_add_uint_format_value(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "2 (IPv4 component link identifier)");
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_component_link_identifier_ipv4, tvb, offset+tlv_off+4, 4, ENC_BIG_ENDIAN);
            break;

        case 32769:  /* oif-p0040.002.09 demo spec */
            rsvp_lsp_tunnel_if_id_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                     offset+tlv_off, tlv_len, subtree_type, &ti,
                                     "Targeted client layer: ");
            proto_tree_add_uint_format_value(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "32769 (Targeted client layer)");
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_length, tvb, offset+tlv_off+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_lsp_encoding_type, tvb, offset+tlv_off+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_switching_type, tvb, offset+tlv_off+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_signal_type, tvb, offset+tlv_off+6, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_connection_id, tvb, offset+tlv_off+8, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_sc_pc_id, tvb, offset+tlv_off+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_lsp_tunnel_if_id_subtree, hf_rsvp_lsp_tunnel_if_id_sc_pc_scn_address, tvb, offset+tlv_off+20, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "LSP Encoding=%s, Switching Type=%s, Signal Type=%s",
                                   rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+4),
                                              gmpls_lsp_enc_rvals, "Unknown (%d)"),
                                   rval_to_str(tvb_get_guint8(tvb,offset+tlv_off+5),
                                              gmpls_switching_type_rvals, "Unknown (%d)"),
                                   val_to_str_ext(tvb_get_guint8(tvb,offset+tlv_off+6),
                                                  &gmpls_sonet_signal_type_str_ext, "Unknown (%d)"));
            break;

        default:
            proto_tree_add_uint_format(rsvp_object_tree, hf_rsvp_type, tvb, offset+tlv_off, 2,
                                tlv_type, "Unknown TLV: %u", tlv_type);
            break;
        }
        tlv_off += tlv_len;
    }
}

/*------------------------------------------------------------------------------
 * LSP TUNNEL INTERFACE ID
 *------------------------------------------------------------------------------*/
static const value_string lsp_tunnel_if_id_action_str[] = {
    { 0, "LSP is FA (MPLS-TE topology advertisement only)"},
    { 1, "LSP is RA (IP network advertisement only)"},
    { 2, "LSP is RA (both IP and MPLS-TE topology advertisement)"},
    { 3, "LSP is to be used as a virtual local link"},
    { 0, NULL}
};

static void
dissect_rsvp_lsp_tunnel_if_id(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                              tvbuff_t *tvb,
                              int offset, int obj_length,
                              int rsvp_class _U_, int type)
{
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "LSP INTERFACE-ID: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tunnel_if_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_router_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_interface_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LSP INTERFACE-ID: Unnumbered, Router-ID %s, Interface-ID %d",
                            tvb_ip_to_str(pinfo->pool, tvb, offset+4),
                            tvb_get_ntohl(tvb, offset+8));
        break;

    case 2:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tunnel_if_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_ipv4_interface_address, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_target_igp_instance, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LSP INTERFACE-ID: IPv4, interface address %s,"
                            "IGP instance %s",
                            tvb_ip_to_str(pinfo->pool, tvb, offset+4),
                            tvb_ip_to_str(pinfo->pool, tvb, offset+8));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_action, tvb, offset+12, 1, ENC_BIG_ENDIAN);
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, pinfo, tvb, offset+16, obj_length-16,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    case 3:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tunnel_if_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_ipv6_interface_address, tvb, offset+4, 16, ENC_NA);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_target_igp_instance, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LSP INTERFACE-ID: IPv6, interface address %s,"
                            "IGP instance %s",
                            tvb_ip6_to_str(pinfo->pool, tvb, offset+4),
                            tvb_ip_to_str(pinfo->pool, tvb, offset+20));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_action, tvb, offset+24, 1, ENC_BIG_ENDIAN);
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, pinfo, tvb, offset+28, obj_length-28,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    case 4:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tunnel_if_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_router_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_interface_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_target_igp_instance, tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "LSP INTERFACE-ID: Unnumbered with target, Router-ID %s,"
                            " Interface-ID %d, IGP instance %s",
                            tvb_ip_to_str(pinfo->pool, tvb, offset+4),
                            tvb_get_ntohl(tvb, offset+8),
                            tvb_ip_to_str(pinfo->pool, tvb, offset+12));
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_action, tvb, offset+16, 1, ENC_BIG_ENDIAN);
        dissect_rsvp_lsp_tunnel_if_id_tlv(rsvp_object_tree, pinfo, tvb, offset+20, obj_length-20,
                                          TREE(TT_LSP_TUNNEL_IF_ID_SUBTREE));
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_tunnel_if_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_lsp_tunnel_if_id_data, tvb, offset+4, obj_length-4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * NOTIFY REQUEST
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_notify_request(proto_item *ti, proto_tree *rsvp_object_tree,
                            tvbuff_t *tvb,
                            int offset, int obj_length,
                            int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_notify_request, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_notify_request_notify_node_address_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, ": Notify node: %s",
                            tvb_ip_to_str(wmem_packet_scope(), tvb, offset2));
        break;
    }

    case 2: {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_notify_request, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_notify_request_notify_node_address_ipv6, tvb, offset2, 16, ENC_NA);
        proto_item_append_text(ti, ": Notify node: %s",
                               tvb_ip6_to_str(wmem_packet_scope(), tvb, offset2));
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_notify_request, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_notify_request_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * GENERALIZED UNI
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_gen_uni(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int type,
                     rsvp_conversation_info *rsvph)
{
    int         offset2 = offset + 4;
    int         mylen, i, j, k, l;
    proto_item *ti2= NULL, *len_item;
    proto_tree *rsvp_gen_uni_subtree, *rsvp_session_subtree, *rsvp_template_subtree;
    int         s_len, s_class, s_type, sobj_len, nsap_len;
    int         offset3;
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "GENERALIZED UNI: ");

    mylen = obj_length - 4;
    switch(type) {
    case 1: {
        const char *c;
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_generalized_uni, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        for (i=1, l = 0; l < mylen; i++) {
            sobj_len = tvb_get_ntohs(tvb, offset2+l);
            j = tvb_get_guint8(tvb, offset2+l+2);
            switch(j) {
            case 1:
            case 2: /* We do source and destination TNA together */
                c = (j==1) ? "Source" : "Destination";
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                case 1:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset2+l, 8, TREE(TT_GEN_UNI_SUBOBJ), NULL,
                                              "%s IPv4 TNA: %s", c,
                                              tvb_ip_to_str(pinfo->pool, tvb, offset2+l+4));
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j, "%d (%s)", j, c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1,
                                        k, "1 (IPv4)");
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    if (j==1)
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_SRC_IPV4],
                                          tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
                    else
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_DST_IPV4],
                                          tvb, offset2+l+4, 4, ENC_BIG_ENDIAN);
                    if (i < 4) {
                        proto_item_append_text(ti, "%s IPv4 TNA: %s", c,
                                               tvb_ip_to_str(pinfo->pool, tvb, offset2+l+4));
                    }
                    break;

                case 2:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset2+l, 20, TREE(TT_GEN_UNI_SUBOBJ), NULL,
                                              "%s IPv6 TNA:", c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j,  "%d (%s)", j, c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1,
                                        k, "2 (IPv6)");
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    if (j==1)
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_SRC_IPV6],
                                          tvb, offset2+l+4, 16, ENC_NA);
                    else
                      proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_filter[RSVPF_GUNI_DST_IPV6],
                                          tvb, offset2+l+4, 16, ENC_NA);
                    if (i < 4) {
                        proto_item_append_text(ti, "%s IPv6 TNA: %s", c,
                                               tvb_ip6_to_str(pinfo->pool, tvb, offset2+l+4));
                    }
                    break;

                case 3:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              TREE(TT_GEN_UNI_SUBOBJ), NULL, "%s NSAP TNA: ", c);
                    nsap_len = tvb_get_guint8(tvb, offset2+l+4);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j, "%d (%s)", j, c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1,
                                        k, "3 (NSAP)");
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_nsap_length, tvb, offset2+l+4, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_string(rsvp_gen_uni_subtree, hf_rsvp_nsap_address, tvb, offset2+l+5, sobj_len-4,
                                        print_nsap_net(pinfo->pool, tvb, offset2+l+5, nsap_len));
                    if (i < 4) {
                        proto_item_append_text(ti, "%s NSAP TNA: %s", c,
                                               print_nsap_net(pinfo->pool, tvb, offset2+l+5, nsap_len));
                    }
                    break;

                default:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              TREE(TT_GEN_UNI_SUBOBJ), NULL, "%s UNKNOWN TNA", c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j, "%d (%s)", j, c);
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1,
                                        k, "%d (UNKNOWN)", k);
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_gen_uni_data, tvb, offset2+l+4, sobj_len-4, ENC_NA);
                    if (i < 4) {
                        proto_item_append_text(ti, "%s UNKNOWN", c);
                    }
                    break;
                }
                break;

            case 3: /* Diversity subobject */
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                default:
                case 1:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                              offset2+l, tvb_get_ntohs(tvb, offset2+l),
                                              TREE(TT_GEN_UNI_SUBOBJ), &ti2, "Diversity Subobject");
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j, "%d (Diversity)", j);
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1, k);
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_class_diversity, tvb, offset2+l+4, 1, ENC_NA);
                    s_len = tvb_get_ntohs(tvb, offset2+l+8);
                    s_class = tvb_get_guint8(tvb, offset2+l+10);
                    s_type = tvb_get_guint8(tvb, offset2+l+11);
                    rsvp_session_subtree = proto_tree_add_subtree(rsvp_gen_uni_subtree, tvb, offset2+l+8,
                                              s_len, TREE(rsvp_class_to_tree_type(s_class)), &ti2, "Session");
                    len_item = proto_tree_add_uint(rsvp_session_subtree, hf_rsvp_length, tvb, offset2+l+8, 2, s_len);
                    if (s_len < 4) {
                        expert_add_info_format(pinfo, len_item, &ei_rsvp_invalid_length,
                            "Length: %u (bogus, must be >= 4)", s_len);
                        break;
                    }
                    proto_tree_add_uint(rsvp_session_subtree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                                offset2+8+l+10, 1, s_class);
                    dissect_rsvp_session(pinfo, ti2, rsvp_session_subtree, tvb, offset2+l+8,
                                         s_len, s_class, s_type, rsvph);
                    offset3 = offset2 + s_len;
                    s_len = tvb_get_ntohs(tvb, offset3+l+8);
                    s_class = tvb_get_guint8(tvb, offset3+l+10);
                    s_type = tvb_get_guint8(tvb, offset3+l+11);
                    rsvp_template_subtree = proto_tree_add_subtree(rsvp_gen_uni_subtree, tvb, offset3+l+8,
                                              s_len, TREE(rsvp_class_to_tree_type(s_class)), &ti2, "Template");

                    proto_tree_add_uint(rsvp_template_subtree, hf_rsvp_length, tvb, offset3+l+8, 2, s_len);
                    if (s_len < 4) {
                        expert_add_info_format(pinfo, len_item, &ei_rsvp_invalid_length,
                            "Length: %u (bogus, must be >= 4)", s_len);
                        break;
                    }
                    proto_tree_add_uint(rsvp_template_subtree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                                offset3+8+l+10, 1, s_class);
                    dissect_rsvp_template_filter(pinfo, ti2, rsvp_template_subtree, tvb, offset3+l+8,
                                                 s_len, s_class, s_type, rsvph);

                    if (i < 4) {
                        proto_item_append_text(ti, "Diversity");
                    }
                    break;

                }
                break;

            case 4: /* Egress Label */
                k = tvb_get_guint8(tvb, offset2+l+3);
                if (k == 1)             /* Egress label sub-type */
                    rsvp_gen_uni_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len, TREE(TT_GEN_UNI_SUBOBJ), &ti2,
                                              "Egress Label Subobject");
                else if (k == 2)        /* SPC_label sub-type (see G.7713.2) */
                    rsvp_gen_uni_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len, TREE(TT_GEN_UNI_SUBOBJ), &ti2,
                                              "SPC Label Subobject");
                else
                    rsvp_gen_uni_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len, TREE(TT_GEN_UNI_SUBOBJ), &ti2,
                                              "Unknown Label Subobject");
                proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                    j, "%d (Egress/SPC Label)", j);
                proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1, k);
                proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_gen_uni_direction,
                             tvb, offset+l+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_egress_label_type, tvb, offset2+l+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_gen_uni_logical_port_id, tvb, offset2+l+8, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti2, ": %s, Label type %d, Port ID %d, Label ",
                                       tvb_get_guint8(tvb, offset2+l+4) & 0x80 ?
                                       "Upstream" : "Downstream",
                                       tvb_get_guint8(tvb, offset2+l+7),
                                       tvb_get_ntohl(tvb, offset2+l+8));
                for (j=12; j < sobj_len; j+=4) {
                        proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_egress_label, tvb, offset2+l+j, 4, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti2, "%u ", tvb_get_ntohl(tvb, offset2+l+j));
                }
                if (i < 4) {
                        if (k == 1)
                            proto_item_append_text(ti, "Egress Label");
                        else if (k == 2)
                            proto_item_append_text(ti, "SPC Label");
                }
                break;

            case 5: /* Service Level */
                k = tvb_get_guint8(tvb, offset2+l+3);
                switch(k) {
                default:
                case 1:
                    rsvp_gen_uni_subtree = proto_tree_add_subtree(rsvp_object_tree, tvb,
                                              offset2+l, sobj_len, TREE(TT_GEN_UNI_SUBOBJ), &ti2,
                                              "Service Level Subobject");
                    proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_class, tvb, offset2+l+2, 1,
                                        j, "%d (Service Level)", j);
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l+3, 1, k);
                    proto_tree_add_uint(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l, 2, sobj_len);
                    proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_gen_uni_service_level, tvb, offset2+l+4, 1, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti2, ": %u", tvb_get_guint8(tvb, offset2+l+4));
                    if (i < 4) {
                        proto_item_append_text(ti, "Service Level %d", tvb_get_guint8(tvb, offset2+l+4));
                    }
                    break;
                }
                break;

            default: /* Unknown subobject */
                rsvp_gen_uni_subtree = proto_tree_add_subtree_format(rsvp_object_tree, tvb,
                                          offset2+l, sobj_len, TREE(TT_GEN_UNI_SUBOBJ), NULL,
                                          "Unknown subobject: %u",
                                          j);
                proto_tree_add_uint_format_value(rsvp_gen_uni_subtree, hf_rsvp_type, tvb, offset2+l, 1,
                                    j, "%u (Unknown)", j);
                proto_tree_add_item(rsvp_gen_uni_subtree, hf_rsvp_class_length, tvb, offset2+l+1, 1, ENC_BIG_ENDIAN);
                break;
            }

            if (tvb_get_guint8(tvb, offset2+l+1) < 1) {
                proto_tree_add_expert_format(rsvp_gen_uni_subtree, pinfo, &ei_rsvp_invalid_length, tvb, offset2+l+1, 1,
                    "Invalid length: %u", tvb_get_guint8(tvb, offset2+l+1));
                return;
            }
            l += tvb_get_guint8(tvb, offset2+l+1);
            if (l < mylen) {
                if (i < 4)
                    proto_item_append_text(ti, ", ");
                else if (i==4)
                    proto_item_append_text(ti, "...");
            }
        }
        break;
    }

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_generalized_uni, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_gen_uni_data, tvb, offset2, mylen, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CALL_ID
 *------------------------------------------------------------------------------*/
static const value_string address_type_vals[] = {
    { 1, "1 (IPv4)"},
    { 2, "2 (IPv6)"},
    { 3, "3 (NSAP)"},
    { 4, "4 (MAC)"},
    { 0x7f, "0x7f (Vendor-defined)"},
    { 0, NULL}
};

static void
dissect_rsvp_call_id(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                     tvbuff_t *tvb,
                     int offset, int obj_length,
                     int rsvp_class _U_, int c_type)
{
    int           type    = 0;
    const guint8 *str;
    int           offset2 = offset + 4;
    int           offset3, offset4, len;
    proto_tree   *ti2 = NULL, *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);


    proto_item_set_text(ti, "CALL-ID: ");
    switch(c_type) {
    case 0:
        proto_item_append_text(ti,"Empty");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_call_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        if (obj_length > 4)
          proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_data, tvb, offset2, obj_length-4, ENC_NA);
        break;
    case 1:
    case 2:
        type = tvb_get_guint8 (tvb, offset2);
        if (c_type == 1) {
            offset3 = offset2 + 4;
            len = obj_length - 16;
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_call_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_address_type, tvb, offset2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_reserved, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "Operator-Specific. Addr Type: %s. ",
                                   val_to_str(type, address_type_vals, "Unknown (%u)"));
        }
        else {
            offset3 = offset2 + 16;
            len = obj_length - 28;
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_call_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_address_type, tvb, offset2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_string(rsvp_object_tree, hf_rsvp_call_id_international_segment, tvb, offset2 + 1, 3, ENC_NA|ENC_ASCII, pinfo->pool, &str);
            proto_item_append_text(ti, "Globally-Unique. Addr Type: %s. Intl Segment: %s. ",
                                   val_to_str(type, address_type_vals, "Unknown (%u)"), str);
            proto_tree_add_item_ret_string(rsvp_object_tree, hf_rsvp_call_id_national_segment, tvb, offset2 + 4, 12, ENC_NA|ENC_ASCII, pinfo->pool, &str);
            proto_item_append_text(ti, "Natl Segment: %s. ", str);
        }

        switch(type) {
        case 1:
            offset4 = offset3 + 4;
            str = tvb_ip_to_str(pinfo->pool, tvb, offset3);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV4],
                                tvb, offset3, 4, ENC_BIG_ENDIAN);
            break;

        case 2:
            offset4 = offset3 + 16;
            str = tvb_ip6_to_str(pinfo->pool, tvb, offset3);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV6],
                                tvb, offset3, 16, ENC_NA);
            break;

        case 3:
            offset4 = offset3 + 20;
            str = print_nsap_net(pinfo->pool, tvb, offset3, 20);
            proto_tree_add_string(rsvp_object_tree, hf_rsvp_source_transport_network_addr, tvb, offset3, 20, str);
            break;

        case 4:
            offset4 = offset3 + 6;
            str = tvb_ether_to_str(pinfo->pool, tvb, offset3);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_callid_srcaddr_ether, tvb, offset3, 6, ENC_NA);
            break;

        case 0x7F:
            offset4 = offset3 + len;
            str = tvb_bytes_to_str(pinfo->pool, tvb, offset3, len);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_callid_srcaddr_bytes, tvb, offset3, len, ENC_NA);
            break;

        default:
            offset4 = offset3 + len;
            str = "???";
            expert_add_info(pinfo, ti2, &ei_rsvp_call_id_address_type);
            break;
        }

        proto_item_append_text(ti, "Src: %s. ", str);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_local_identifier, tvb, offset4, 8, ENC_NA);
        proto_item_append_text(ti, "Local ID: %s. ", tvb_bytes_to_str(pinfo->pool, tvb, offset4, 8));
        break;

    default:
        proto_item_append_text(ti, " Unknown");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_call_id, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_id_data, tvb, offset2, obj_length-4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * 3GPP2_OBJECT X.S0057-0 v1.0, X.S0011-004-E v1.0
 *------------------------------------------------------------------------------*/
static const value_string rsvp_3gpp_object_ie_type_vals[] = {
    { 0, "TFT IPv4"},
    { 1, "TFT IPv4 Error"},
    { 2, "TFT IPv6"},
    { 3, "TFT IPv6 Error"},
    { 4, "Header Removal"},
    { 5, "Header Removal Error"},
    { 6, "Channel Treatment"},
    { 7, "Channel Treatment Error"},
    { 0, NULL}
};

static const value_string rsvp_3gpp_object_tft_d_vals[] = {
    { 0, "Forward Direction"},
    { 1, "Reverse Direction"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 0, NULL}
};

static const value_string rsvp_3gpp_obj_tft_opcode_vals[] = {
    { 0x00, "Spare"},
    { 0x01, "Create new TFT"},
    { 0x02, "Delete existing TFT"},
    { 0x03, "Add packet filters to existing TFT"},
    { 0x04, "Replace packet filters in existing TFT"},
    { 0x05, "Delete packet filters from existing TFT"},
    { 0x06, "QoS Check"},
    { 0x07, "Reserved"},
    { 0x80, "Initiate Flow Request"},
    { 0x81, "QoS Check Confirm"},
    { 0x82, "Initiate Delete Packet Filter from Existing TFT"},
    { 0x83, "Initiate Replace packet filters in existing TFT"},
    { 0, NULL}
};

static const value_string rsvp_3gpp_obj_pf_comp_type_id_vals[] = {
    { 16,  "IPv4 Source Address with Subnet Mask"},
    { 17,  "IPv4 Destination Address with Subnet Mask"},
    { 32,  "IPv6 Source Address with Prefix Length"},
    { 33,  "IPv6 Destination Address with Prefix Length"},
    { 48,  "Protocol /Next header"},
    { 64,  "Single Destination Port"},
    { 65,  "Destination Port range"},
    { 80,  "Single Source Port"},
    { 81,  "Source Port range"},
    { 96,  "Security Parameter Index"},
    { 112, "Type of Service/Traffic Class"},
    { 128, "Flow label"},
    { 129, "Type 2 Routing Header with Prefix Length"},
    { 130, "Home Address Option with Prefix Length"},
    { 0, NULL}
};

static const value_string rsvp_3gpp_obj_pf_treatment_vals[] = {
    { 0, "Header Compression"},
    { 1, "Maximum Buffer Timer"},
    { 0, NULL}
};

#if 0
static const value_string rsvp_3gpp_qos_result_vals[] = {
    { 0, "Successful"},
    { 1, "UE Initiated QoS is not authorized"},
    { 2, "NW initiated QoS in progress for this flow"},
    { 3, "Requested FlowProfileIDs failed mapping"},
    { 0, NULL}
};
#endif

static const value_string rsvp_3gpp_obj_traffic_class_vals[] = {
    { 0, "Unknown"},
    { 1, "Conversational"},
    { 2, "Streaming"},
    { 3, "Interactive"},
    { 4, "Background"},
    { 0, NULL}
};

static void
dissect_rsvp_3gpp_object(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
    tvbuff_t *tvb,
    int offset, int obj_length,
    int rsvp_class _U_, int c_type)
{
    guint16 length, ie_type;
    proto_tree  *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    offset+=3;
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_3gpp_object, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Set obj_length to the remaining bytes */
    obj_length = obj_length - 4;
    if(c_type==1){
        /* Transaction ID */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        obj_length = obj_length - 4;
        /* IE List */
        while(obj_length>0){
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            ie_type = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_ie_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;

            if ((ie_type == 0)||(ie_type==2)){
                guint8 tft_opcode, tft_n_pkt_flt;
                int i;

                if(ie_type == 0){
                    /*IPv4*/
                    proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_ue_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset+=4;
                }else{
                    proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_ue_ipv6_addr, tvb, offset, 16, ENC_NA);
                    offset+=16;
                }
                /* D Reserved NS SR_ID Reserved P TFT Operation Code Number of Packet filters */
                /* D */
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_d, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* NS */
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_ns, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* SR_ID */
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_sr_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* P */
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_p, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* TFT Operation Code */
                tft_opcode = tvb_get_guint8(tvb, offset+2);
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_opcode, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* Number of Packet filters */
                tft_n_pkt_flt = tvb_get_guint8(tvb, offset+3);
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_n_pkt_flt, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                /* Packet filter list
                * The packet filter list contains a variable number of packet filters. It shall be
                * encoded same as defined in X.S0011-D Chapter 4 [5] except as defined
                * below:
                * For "QoS Check Confirm" operations, the packet filter list shall be empty.
                * For "Initiate Delete Packet Filter from Existing TFT", the packet filter list
                * shall contain a variable number of Flow Identifiers given in the number of
                * packet filters field. In this case, the packet filter evaluation precedence,
                * length, and contents are not included, only the Flow Identifiers are
                * included. See Figure B-6, X.S0011-D [5] .
                * For "Initiate Flow request" and "Initiate Replace Packet Filters in Existing
                * TFT" Replace Packet Filters in Existing TFT the packet filter list shall
                * contain a variable number of Flow Identifiers, along with the packet filter
                * contents. See Figure B-7, X.S0011-D
                */
                if((tft_opcode!=0x81)&&(tft_n_pkt_flt != 0)){
                    /* Packet Filter List */
                    for (i = 0; i < tft_n_pkt_flt; i++) {
                        proto_tree   *flow_tree, *t2_tree;
                        guint16 pkt_flt_len, item_len, pf_cont_len;
                        guint8 pf_comp_type_id;

                        flow_tree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset, -1, ett_treelist[TT_3GPP_OBJ_FLOW], &ti, "Flow Identifier Num %u",i+1);
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        item_len = 1;
                        if((tft_opcode==0x05)||(tft_opcode==0x82)){
                            /* delete packet filters from existing TFT, Initiate Delete Packet Filter from Existing TFT */
                            proto_item_set_len(ti, item_len);
                            continue;
                        }
                        /* Packet filter evaluation precedence */
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ev_prec, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        /* Packet filter length */
                        pkt_flt_len = tvb_get_ntohs(tvb,offset);
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                        item_len = item_len + pkt_flt_len +1;
                        offset+=2;
                        /* Packet filter contents */
                        /* PF Type (0-1) */
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        /* Length */
                        pf_cont_len = tvb_get_guint8(tvb, offset);
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_cont_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        /* Packet filter component type identifier */
                        pf_comp_type_id = tvb_get_guint8(tvb, offset);
                        proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_comp_type_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        /* Packet filter component */
                        switch(pf_comp_type_id){
                        case 16: /* IPv4 Source Address with Subnet Mask */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_src_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                            pf_cont_len-=11;
                            break;
                        case 17: /* IPv4 Destination Address with Subnet Mask */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_dst_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                            /* Items length (8 + 3)*/
                            pf_cont_len-=11;
                            break;
                        case 32: /* IPv6 Source Address with Prefix Length */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_src_ipv6, tvb, offset, 16, ENC_NA);
                            offset+=16;
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ipv6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (17 + 3)*/
                            pf_cont_len-=20;
                            break;
                        case 33: /* IPv6 Destination Address with Prefix Length */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_dst_ipv6, tvb, offset, 16, ENC_NA);
                            offset+=16;
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ipv6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (17 + 3)*/
                            pf_cont_len-=20;
                            break;
                        case 48: /* Protocol /Next header */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_prot_next, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (1 + 3)*/
                            pf_cont_len-=4;
                            break;
                        case 64: /* Single Destination Port */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset+=2;
                            /* Items length (2 + 3)*/
                            pf_cont_len-=5;
                            break;
                        case 65: /* Destination Port range */
                            proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_3gpp_obj_pf_dst_port_range, tvb, offset, 4,
                                                            tvb_get_ntohs(tvb,offset), "%u-%u", tvb_get_ntohs(tvb,offset), tvb_get_ntohs(tvb,offset+2));
                            offset+=4;
                            break;
                        case 80: /* Single Source Port */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                            offset+=2;
                            /* Items length (2 + 3)*/
                            pf_cont_len-=5;
                            break;
                        case 81: /* Source Port range */
                            proto_tree_add_uint_format_value(rsvp_object_tree, hf_rsvp_3gpp_obj_pf_src_port_range, tvb, offset, 4,
                                                            tvb_get_ntohs(tvb,offset), "Source Port range %u-%u", tvb_get_ntohs(tvb,offset), tvb_get_ntohs(tvb,offset+2));
                            offset+=4;
                            /* Items length (4 + 3)*/
                            pf_cont_len-=7;
                            break;
                        case 96: /* Security Parameter Index */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_ipsec_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                            /* Items length (4 + 3)*/
                            pf_cont_len-=7;
                            break;
                        case 112: /* Type of Service/Traffic Class */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_tos_tc, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (1 + 3)*/
                            pf_cont_len-=4;
                            break;
                        case 128: /* Flow label */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_flow_lbl, tvb, offset, 3, ENC_BIG_ENDIAN);
                            offset+=3;
                            /* Items length (3 + 3)*/
                            pf_cont_len-=6;
                            break;
                        case 129: /* Type 2 Routing Header with Prefix Length */
                            t2_tree = proto_tree_add_subtree(flow_tree, tvb, offset, 17, ett_treelist[TT_3GPP_OBJ_T2], NULL, "Type 2 Routing Header packet filter");
                            proto_tree_add_item(t2_tree, hf_rsvp_3gpp_obj_pf_ipv6, tvb, offset, 16, ENC_NA);
                            offset+=16;
                            proto_tree_add_item(t2_tree, hf_rsvp_3gpp_obj_pf_ipv6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (17 + 3)*/
                            pf_cont_len-=20;
                            break;
                        case 130: /* Home Address Option with Prefix Length */
                            t2_tree = proto_tree_add_subtree(flow_tree, tvb, offset, 17, ett_treelist[TT_3GPP_OBJ_HO], NULL, "Home address Option packet filter");
                            proto_tree_add_item(t2_tree, hf_rsvp_3gpp_obj_pf_ipv6, tvb, offset, 16, ENC_NA);
                            offset+=16;
                            proto_tree_add_item(t2_tree, hf_rsvp_3gpp_obj_pf_ipv6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* Items length (17 + 3)*/
                            pf_cont_len-=20;
                            break;

                        default:
                            proto_tree_add_expert(flow_tree, pinfo, &ei_rsvp_packet_filter_component, tvb, offset, pf_cont_len-2);
                            offset = offset + pkt_flt_len - 5;
                            pf_cont_len=0;
                            break;
                        }
                        if(pf_cont_len != 0){
                            /* Packet filter treatment */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_treatment, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            /* [RFC 3006] hint */
                            proto_tree_add_item(flow_tree, hf_rsvp_3gpp_obj_pf_hint, tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset+=4;
                        }
                        proto_item_set_len(ti, item_len);
                    }
                }
                /* QoS List (QoS Check, QoS-Check Confirm  Initiate Flow Request
                * and Initiate Replace Packet Filters in Existing TFT)
                * XXX
                * Create new TFT?
                */
                if((tft_opcode ==  0x01)||(tft_opcode ==  0x06)||(tft_opcode == 0x80)||(tft_opcode == 0x81)||(tft_opcode == 0x83)){
                    /* QoS List Length */
                    gint32 tft_qos_list_len;
                    guint8 blob_len, item_len, padding_len;
                    gboolean verbose;
                    proto_tree   *qos_tree, *qos_sub_blob_tree, *qos_att_tree;
                    int num = 0, j, num_qos_att_set;

                    tft_qos_list_len = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(rsvp_object_tree, hf_rsvp_3gpp_obj_tft_qos_list_len, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset+=2;
                    tft_qos_list_len-=2;
                    if(tft_qos_list_len > 0){
                        while (tft_qos_list_len>0) {
                            int bit_offset; /* offset in bits */
                            guint8 qos_attribute_set_len;

                            num++;

                            qos_tree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset, -1,
                                        ett_treelist[TT_3GPP_OBJ_QOS], NULL, "QOS Flow Identifier Num %u", num);

                            /* Flow Identifier */
                            proto_tree_add_item(qos_tree, hf_rsvp_3gpp_obj_flow_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            tft_qos_list_len--;

                            /* R_QOS_SUB_BLOB_LEN 1 */
                            blob_len = tvb_get_guint8(tvb, offset);
                            proto_tree_add_item(qos_tree, hf_rsvp_3gpp_r_qos_blob_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                            tft_qos_list_len--;

                            /* R_QoS_SUB_BLOB X.S0011-004-D */
                            ti = proto_tree_add_item(qos_tree, hf_rsvp_3gpp_r_qos_blob, tvb, offset, blob_len, ENC_NA);
                            qos_sub_blob_tree = proto_item_add_subtree(ti, ett_treelist[TT_3GPP_OBJ_QOS_SUB_BLOB]);

                            proto_tree_add_item(qos_sub_blob_tree, hf_rsvp_3gpp_r_qos_blob_flow_pri, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(qos_sub_blob_tree, hf_rsvp_3gpp_r_qos_blob_num_qos_att_set, tvb, offset, 1, ENC_BIG_ENDIAN);
                            num_qos_att_set = (tvb_get_guint8(tvb, offset) & 0x0e)>>1;
                            /* point to the first bit in the QoS_ATTRIBUTE_SET */
                            bit_offset = (offset<<3)+7;
                            for (j = 0; j < num_qos_att_set; j++) {
                                qos_attribute_set_len = tvb_get_bits8(tvb,bit_offset,4);
                                qos_att_tree = proto_tree_add_subtree_format(qos_sub_blob_tree, tvb, bit_offset>>3, qos_attribute_set_len, ett_treelist[TT_3GPP_OBJ_QOS_SUB_BLOB], NULL,
                                     "QoS_ATTRIBUTE_SET %u(%u bytes)", j+1, qos_attribute_set_len);
                                proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_att_set_len, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                                bit_offset+=4;

                                if(qos_attribute_set_len==0){
                                    break;
                                }

                                proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_set_id, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
                                bit_offset+=7;

                                verbose = tvb_get_bits8(tvb, bit_offset, 1);
                                proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_verbose, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
                                bit_offset++;


                                if(verbose == FALSE){
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_prof_id, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=16;
                                }else{
                                    /* Traffic_Class 0 or 3 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_traff_cls, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                                    bit_offset+=3;
                                    /* Peak_Rate 0 or 16 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_peak_rate, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=16;
                                    /* Bucket_Size 0 or 16 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_bucket_size, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=16;
                                    /* Token_Rate 0 or 16 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_token_rate, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=16;
                                    /* Max_Latency 0 or 8 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_max_latency, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=8;
                                    /* Max_Loss_Rate 0 or 8 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_max_loss_rte, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=8;
                                    /* Delay_Var_Sensitive 0 or 1 */
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_delay_var_sensitive, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
                                    bit_offset+=1;
                                }
                                /* Padd to fill up to octet boundary, Reserved 0-7 as needed */
                                padding_len = 0;
                                if((bit_offset & 0x07) != 0){
                                    padding_len = 8 - (bit_offset & 0x07);
                                    proto_tree_add_bits_item(qos_att_tree, hf_rsvp_3gpp_qos_attribute_reserved, tvb, bit_offset, padding_len, ENC_BIG_ENDIAN);
                                }
                                bit_offset = bit_offset + padding_len;
                            }


                            offset = offset + blob_len;
                            tft_qos_list_len = tft_qos_list_len - blob_len;

                            /* Result Code This field is only included in the ResvConf message when
                             * the TFT Operation Code field is set to QoS-Check Confirm.
                             */
                            item_len = blob_len + 2;
                            if(tft_opcode ==  0x81){
                                proto_tree_add_item(qos_tree, hf_rsvp_3gpp_qos_result, tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset++;
                                tft_qos_list_len--;
                                item_len++;
                            }
                            proto_item_set_len(ti, item_len);
                        }
                    }
                }else{
                    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ie_data, tvb, offset, length-2, ENC_NA);
                }
                obj_length = obj_length - length;
            }
        }
    }
}
/*------------------------------------------------------------------------------
 * RESTART CAPABILITY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_restart_cap(proto_tree *ti, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{
    int offset2 = offset + 4;
    guint restart, recovery;
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "RESTART CAPABILITY: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_restart_cap, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(rsvp_object_tree, hf_rsvp_restart_cap_restart_time, tvb, offset2, 4,
                            ENC_BIG_ENDIAN, &restart);
        proto_tree_add_item_ret_uint(rsvp_object_tree, hf_rsvp_restart_cap_recovery_time, tvb, offset2+4, 4,
                            ENC_BIG_ENDIAN, &recovery);
        proto_item_append_text(ti, "Restart Time: %d ms. Recovery Time: %d ms.",
                            restart, recovery);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_restart_cap, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_restart_cap_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * LINK CAPABILITY
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_link_cap(proto_item *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class, int type)
{
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "LINK CAPABILITY: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_link_cap, tvb, offset+3, 1, type);

        dissect_rsvp_ro_subobjects(ti, pinfo, rsvp_object_tree, tvb,
                                        offset + 4, obj_length, rsvp_class);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_link_cap, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_record_route_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }

}
/*------------------------------------------------------------------------------
 * PROTECTION INFORMATION
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_protection_info(proto_tree *ti, proto_tree *rsvp_object_tree,
                             tvbuff_t *tvb,
                             int offset, int obj_length,
                             int rsvp_class _U_, int type)
{
    guint8      flags1, lsp_flags, link_flags, seg_flags;
    proto_tree *ti2, *rsvp_pi_link_flags_tree, *rsvp_pi_lsp_flags_tree, *rsvp_pi_seg_flags_tree;
    int         offset2 = offset + 4;
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "PROTECTION_INFO: ");
    switch(type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_protection_info, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        flags1 = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_flags_secondary_lsp,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);

        link_flags = tvb_get_guint8(tvb, offset2+3);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_link_flags, tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        rsvp_pi_link_flags_tree = proto_item_add_subtree(ti2, TREE(TT_PROTECTION_INFO_LINK));
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_extra_traffic,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_unprotected,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_shared,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated1_1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated1plus1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_enhanced,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "%s%s%s%s%s%s%s.",
                               flags1&0x80 ? "SecondaryLSP ":"",
                               link_flags&0x01 ? "ExtraTraffic ":"",
                               link_flags&0x02 ? "Unprotected ":"",
                               link_flags&0x04 ? "Shared ":"",
                               link_flags&0x08 ? "Dedicated1:1 ":"",
                               link_flags&0x10 ? "Dedicated1+1 ":"",
                               link_flags&0x20 ? "Enhanced ":"");
        break;

    case 2:       /* RFC4872 */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_protection_info, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        flags1 = tvb_get_guint8(tvb, offset2);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_secondary,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_protecting,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_notification_msg,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_rfc4872_operational,
                             tvb, offset2, 1, ENC_BIG_ENDIAN);

        lsp_flags = tvb_get_guint8(tvb, offset2+1);
        rsvp_pi_lsp_flags_tree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset2+1, 1,
                                  TREE(TT_PROTECTION_INFO_LSP), NULL, "LSP Flags: 0x%02x -%s%s%s%s%s%s", lsp_flags,
                                  lsp_flags == 0 ? " Unprotected":"",
                                  lsp_flags&0x01 ? " Rerouting":"",
                                  lsp_flags&0x02 ? " Rerouting with extra-traffic":"",
                                  lsp_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                                  lsp_flags&0x08 ? " 1+1 Unidirectional protection":"",
                                  lsp_flags&0x10 ? " 1+1 Bidirectional protection":"");
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_full_rerouting,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_rerouting_extra,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1_n_protection,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1plus1_unidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_lsp_flags_tree, hf_rsvp_pi_lsp_flags_1plus1_bidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);

        link_flags = tvb_get_guint8(tvb, offset2+3);
        rsvp_pi_link_flags_tree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset2+3, 1,
                                  TREE(TT_PROTECTION_INFO_LINK), NULL, "Link Flags: 0x%02x -%s%s%s%s%s%s", link_flags,
                                  link_flags&0x01 ? " ExtraTraffic":"",
                                  link_flags&0x02 ? " Unprotected":"",
                                  link_flags&0x04 ? " Shared":"",
                                  link_flags&0x08 ? " Dedicated1:1":"",
                                  link_flags&0x10 ? " Dedicated1+1":"",
                                  link_flags&0x20 ? " Enhanced":"");
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_extra,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_unprotected,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_shared,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated_1_1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_dedicated_1plus1,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_link_flags_tree, hf_rsvp_pi_link_flags_enhanced,
                             tvb, offset2+3, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_in_place,
                             tvb, offset2+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_required,
                             tvb, offset2+4, 1, ENC_BIG_ENDIAN);

        seg_flags = tvb_get_guint8(tvb, offset2+5);
        rsvp_pi_seg_flags_tree = proto_tree_add_subtree_format(rsvp_object_tree, tvb, offset2+5, 1,
                                 TREE(TT_PROTECTION_INFO_SEG), NULL, "Segment recovery Flags: 0x%02x - %s%s%s%s%s%s", seg_flags,
                                  seg_flags == 0 ? " Unprotected":"",
                                  seg_flags&0x01 ? " Rerouting":"",
                                  seg_flags&0x02 ? " Rerouting with extra-traffic":"",
                                  seg_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                                  seg_flags&0x08 ? " 1+1 Unidirectional protection":"",
                                  seg_flags&0x10 ? " 1+1 Bidirectional protection":"");
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_full_rerouting,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_rerouting_extra,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1_n_protection,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1plus1_unidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_pi_seg_flags_tree, hf_rsvp_pi_seg_flags_1plus1_bidirectional,
                             tvb, offset2+1, 1, ENC_BIG_ENDIAN);

        proto_item_append_text(ti, "%s%s%s%s Link:%s%s%s%s%s%s, LSP:%s%s%s%s%s%s.",
                               flags1&0x80 ? "SecondaryLSP ":"",
                               flags1&0x40 ? "ProtectingLSP ":"",
                               flags1&0x20 ? "Notification ":"",
                               flags1&0x10 ? "OperationalLSP ":"",
                               link_flags&0x01 ? " ExtraTraffic":"",
                               link_flags&0x02 ? " Unprotected":"",
                               link_flags&0x04 ? " Shared":"",
                               link_flags&0x08 ? " Dedicated1:1":"",
                               link_flags&0x10 ? " Dedicated1+1":"",
                               link_flags&0x20 ? " Enhanced":"",
                               lsp_flags == 0 ? " Unprotected":"",
                               lsp_flags&0x01 ? " Rerouting":"",
                               lsp_flags&0x02 ? " Rerouting with extra-traffic":"",
                               lsp_flags&0x04 ? " 1:N Protection with extra-traffic":"",
                               lsp_flags&0x08 ? " 1+1 Unidirectional protection":"",
                               lsp_flags&0x10 ? " 1+1 Bidirectional protection":"");
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_protection_info, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_protection_info_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * FAST REROUTE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_fast_reroute(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                          tvbuff_t *tvb,
                          int offset, int obj_length,
                          int rsvp_class _U_, int type)
{
    guint8      flags;
    proto_tree *ti2, *rsvp_frr_flags_tree;
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "FAST_REROUTE: ");
    switch(type) {
    case 1:
    case 7:
        if (((type == 1) && (obj_length != 24)) || ((type == 7) && (obj_length != 20))) {
            proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset, obj_length,
                                "Invalid length: cannot decode");
            proto_item_append_text(ti, "Invalid length");
            break;
        }
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_fast_reroute, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_setup_priority, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_hold_priority, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_hop_limit, tvb, offset+6, 1, ENC_BIG_ENDIAN);

        flags = tvb_get_guint8(tvb, offset+7);
        ti2 = proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_flags, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        rsvp_frr_flags_tree = proto_item_add_subtree(ti2, TREE(TT_FAST_REROUTE_FLAGS));
        proto_tree_add_item(rsvp_frr_flags_tree, hf_rsvp_frr_flags_one2one_backup,
                             tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_frr_flags_tree, hf_rsvp_frr_flags_facility_backup,
                             tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_bandwidth, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_include_any, tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_exclude_any, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        if (type == 1) {
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_include_all, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        }

        proto_item_append_text(ti, "%s%s",
                               flags &0x01 ? "One-to-One Backup, " : "",
                               flags &0x02 ? "Facility Backup" : "");
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_fast_reroute, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_fast_reroute_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * S2L_SUB_LSP
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_s2l_sub_lsp(proto_tree *ti, packet_info* pinfo _U_, proto_tree *rsvp_object_tree,
                         tvbuff_t *tvb,
                         int offset, int obj_length,
                         int rsvp_class _U_, int type)
{

    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "S2L SUB LSP: ");
    switch(type) {
    case 1: /* IPv4 */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_s2l_sub_lsp, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_s2l_sub_lsp_destination_ipv4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;

    case 2: /* IPv6 */
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_s2l_sub_lsp, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(rsvp_object_tree, hf_rsvp_s2l_sub_lsp_destination_ipv6_address, tvb, offset, 16, ENC_NA);
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_s2l_sub_lsp, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_s2l_sub_lsp_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * DETOUR
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_detour(proto_tree *ti, packet_info* pinfo, proto_tree *rsvp_object_tree,
                    tvbuff_t *tvb,
                    int offset, int obj_length,
                    int rsvp_class _U_, int type)
{
    int remaining_length, count;
    int iter;
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "DETOUR: ");
    switch(type) {
    case 7:
        iter = 0;
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_detour, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        for (remaining_length = obj_length - 4, count = 1;
             remaining_length > 0; remaining_length -= 8, count++) {
            if (remaining_length < 8) {
                proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length, tvb, offset+remaining_length,
                                    obj_length-remaining_length,
                                    "Invalid length: cannot decode");
                proto_item_append_text(ti, "Invalid length");
                break;
            }
            iter++;
            proto_tree_add_ipv4_format(rsvp_object_tree, hf_rsvp_detour_plr_id, tvb, offset+(4*iter), 4,
                                tvb_get_ntohl(tvb, offset+(4*iter)), "PLR ID %d: %s", count,
                                tvb_ip_to_str(pinfo->pool, tvb, offset+(4*iter)));
            iter++;
            proto_tree_add_ipv4_format(rsvp_object_tree, hf_rsvp_detour_avoid_node_id, tvb, offset+(4*iter), 4,
                                tvb_get_ntohl(tvb, offset+(4*iter)), "Avoid Node ID %d: %s", count,
                                tvb_ip_to_str(pinfo->pool, tvb, offset+(4*iter)));
        }
        break;

    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_detour, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_detour_data, tvb, offset+4, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * DIFFSERV
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_diffserv(proto_tree *ti, proto_tree *rsvp_object_tree,
                      tvbuff_t *tvb,
                      int offset, int obj_length,
                      int rsvp_class _U_, int type)
{
    int mapnb, count;
    int *hfindexes[] = {
        &hf_rsvp_filter[RSVPF_DIFFSERV_MAP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_MAP_EXP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_DSCP],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_CODE],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT14],
        &hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT15]
    };
    gint *etts[] = {
        &TREE(TT_DIFFSERV_MAP),
        &TREE(TT_DIFFSERV_MAP_PHBID)
    };
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_item_set_text(ti, "DIFFSERV: ");
    offset += 3;
    switch (type) {
    case 1:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_diffserv, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_filter[RSVPF_DIFFSERV_MAPNB],
                            tvb, offset + 4, 1,
                            mapnb = tvb_get_guint8(tvb, offset + 4) & 15);
        proto_item_append_text(ti, "E-LSP, %u MAP%s", mapnb,
                               (mapnb == 0) ? "" : "s");
        offset += 5;

        for (count = 0; count < mapnb; count++) {
            dissect_diffserv_mpls_common(tvb, rsvp_object_tree, type,
                                         offset, hfindexes, etts);
            offset += 4;
        }
        break;
    case 2:
        proto_item_append_text(ti, "L-LSP");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_diffserv, tvb, offset, 1, ENC_BIG_ENDIAN);
        dissect_diffserv_mpls_common(tvb, rsvp_object_tree, type,
                                     offset + 3, hfindexes, etts);
        break;
    default:
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_diffserv, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_diffserv_data, tvb, offset + 1, obj_length - 4, ENC_NA);
        break;
    }
}

/*------------------------------------------------------------------------------
 * CLASSTYPE
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_diffserv_aware_te(proto_tree *ti, proto_tree *rsvp_object_tree,
                               tvbuff_t *tvb,
                               int offset, int obj_length,
                               int rsvp_class _U_, int type)
{
    proto_item *hidden_item;
    int         offset2 = offset + 4;
    guint8      ct      = 0;

    hidden_item = proto_tree_add_item(rsvp_object_tree,
                               hf_rsvp_filter[RSVPF_DSTE],
                               tvb, offset, 8, ENC_NA);
    proto_item_set_hidden(hidden_item);

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    switch(type) {
    case 1:
        ct = tvb_get_guint8(tvb, offset2+3);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_diffserv_aware_te, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree,
                            hf_rsvp_filter[RSVPF_DSTE_CLASSTYPE],
                            tvb, offset2+3, 1, ENC_BIG_ENDIAN);
        proto_item_set_text(ti, "CLASSTYPE: CT %u", ct);
        break;
    default:
        proto_item_set_text(ti, "CLASSTYPE: (Unknown C-type)");
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_diffserv_aware_te, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_diffserv_aware_te_data, tvb, offset2, obj_length - 4, ENC_NA);
        break;
    }
}

/*----------------------------------------------------------------------------
 * VENDOR PRIVATE USE
 *---------------------------------------------------------------------------*/
static void
dissect_rsvp_vendor_private_use(proto_tree *ti _U_,
                                proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length,
                                int rsvp_class _U_, int type _U_)
{
    /*
     * FF: from Section 2, RFC 3936
     *
     * "Organization/Vendor Private" ranges refer to values that are
     * enterprise-specific;  these MUST NOT be registered with IANA.  For
     * Vendor Private values, the first 4-octet word of the data field MUST
     * be an enterprise code [ENT: www.iana.org/assignments/enterprise-numbers]
     * (network order) as registered with the IANA SMI Network Management
     * Private Enterprise Codes, and the rest of the data thereafter is for
     * the private use of the registered enterprise.
     */
    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree,
                                      hf_rsvp_filter[RSVPF_PRIVATE_OBJ],
                                      tvb, offset, obj_length, ENC_NA);
    proto_item_set_hidden(hidden_item);

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_vendor, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree,
                        hf_rsvp_filter[RSVPF_ENT_CODE],
                        tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_object_tree, hf_rsvp_private_data, tvb, offset + 8,
                        obj_length - 8, ENC_NA);
}

/*----------------------------------------------------------------------------
 * CALL ATTRIBUTES
 *---------------------------------------------------------------------------*/
static void
dissect_rsvp_call_attributes(proto_tree *ti _U_, packet_info* pinfo, proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb, int offset, int obj_length _U_, int rsvp_class _U_, int type _U_)
{

    int offset2 = offset + 4;
    guint16 tlv_type;
    guint16  tlv_len;

    tlv_type = tvb_get_ntohs(tvb, offset2);
    tlv_len = tvb_get_ntohs(tvb, offset2+2);

    if (tlv_len < 4){
        proto_tree_add_expert_format(rsvp_object_tree, pinfo, &ei_rsvp_invalid_length,
                                     tvb, offset2+2, 2, "Invalid TLV length");
        return;
    }

    switch(tlv_type){
        case 2:
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_call_attributes_endpont_id, tvb, offset2 + 4, tlv_len - 4, ENC_NA|ENC_ASCII);
        break;
    }
}

/*----------------------------------------------------------------------------
 * JUNIPER PROPRIETARY
 *---------------------------------------------------------------------------*/
static void
dissect_rsvp_juniper(proto_tree *ti _U_,
                                proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length,
                                int rsvp_class _U_, int type)
{
    /*
     * Juniper proprietary TLVs:
     * According to the tcpdump code, this is of the form:
     * #TLVs (2 bytes)
     * #Padbytes (2 bytes)
     * per TLV:
     *   type (1 byte)
     *   length
     *   value (length-2 bytes)
     * padbytes
     */

    proto_item *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree,
                                      hf_rsvp_filter[RSVPF_JUNIPER],
                                      tvb, offset, obj_length, ENC_NA);
    proto_item_set_hidden(hidden_item);

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_juniper, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    offset += 4;
    if (type == 1) {
        guint tlvs, pad;
        tlvs = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_numtlvs, tvb,
            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        pad = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_padlength, tvb,
            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        while (tlvs > 0) {
            guint8 t, l;
            t = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_type, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            l = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_length, tvb,
                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            switch (t) {
            case 0x01:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_cos, tvb,
                    offset, l-2, ENC_BIG_ENDIAN);
                offset += (l-2);
                break;
            case 0x02:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_metric1, tvb,
                    offset, l-2, ENC_BIG_ENDIAN);
                offset += (l-2);
                break;
            case 0x04:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_metric2, tvb,
                    offset, l-2, ENC_BIG_ENDIAN);
                offset += (l-2);
                break;
            case 0x08:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_ccc_status, tvb,
                    offset, l-2, ENC_BIG_ENDIAN);
                offset += (l-2);
                break;
            case 0x10:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_path, tvb,
                    offset, l-2, ENC_BIG_ENDIAN);
                offset += (l-2);
                break;
            default:
                proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_attrib_unknown, tvb,
                    offset, l-2, ENC_NA);
                offset += (l-2);
                break;
            }
            tlvs--;
        }
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_pad, tvb,
                offset, pad, ENC_NA);
    } else if (obj_length > 4) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_juniper_unknown, tvb,
                offset, obj_length, ENC_NA);
    }
}

/*----------------------------------------------------------------------------
 * UNKNOWN
 *---------------------------------------------------------------------------*/
static void
dissect_rsvp_unknown(proto_tree *ti _U_,
                                proto_tree *rsvp_object_tree,
                                tvbuff_t *tvb,
                                int offset, int obj_length,
                                int rsvp_class _U_, int type _U_)
{
    proto_tree *hidden_item;

    hidden_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype, tvb, offset+3, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    proto_tree_add_item(rsvp_object_tree, hf_rsvp_ctype_unknown, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    if (obj_length > 4) {
        proto_tree_add_item(rsvp_object_tree, hf_rsvp_unknown_data, tvb, offset + 4,
                        obj_length - 4, ENC_NA);
    }
}


/*------------------------------------------------------------------------------
 * Dissect a single RSVP message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_msg_tree(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      int tree_mode, rsvp_conversation_info *rsvph, gboolean e2ei)
{
    proto_tree *rsvp_tree;
    proto_tree *rsvp_header_tree;
    proto_tree *rsvp_object_tree;
    proto_tree *ti, *len_item;
    proto_item *hidden_item, *cksum_item;
    guint16     cksum, computed_cksum;
    vec_t       cksum_vec[1];
    int         offset    = 0;
    int         len;
    guint8      message_type;
    int         session_off, tempfilt_off;
    int         msg_length;
    int         obj_length;
    gboolean    have_integrity_object = FALSE;

    offset       = 0;
    msg_length   = tvb_get_ntohs(tvb, 6);
    message_type = tvb_get_guint8(tvb, 1);

    ti = proto_tree_add_item(tree, proto_rsvp, tvb, offset, msg_length,
                             ENC_NA);
    rsvp_tree = proto_item_add_subtree(ti, tree_mode);
    if (e2ei)
        proto_item_append_text(rsvp_tree, " (E2E-IGNORE)");
    proto_item_append_text(rsvp_tree, ": ");
    proto_item_append_text(rsvp_tree, "%s", val_to_str_ext(message_type, &message_type_vals_ext,
                                                 "Unknown (%u). "));
    find_rsvp_session_tempfilt(tvb, 0, &session_off, &tempfilt_off);
    if (session_off)
        proto_item_append_text(rsvp_tree, "%s", summary_session(pinfo->pool, tvb, session_off));
    if (tempfilt_off)
        proto_item_append_text(rsvp_tree, "%s", summary_template(pinfo->pool, tvb, tempfilt_off));

    rsvp_header_tree = proto_tree_add_subtree_format(rsvp_tree, tvb, offset, 8,
                             TREE(TT_HDR), &ti, "RSVP Header. %s",
                             val_to_str_ext(message_type, &message_type_vals_ext,
                                        "Unknown Message (%u). "));
    if (e2ei)
        proto_item_append_text(ti, " (E2E-IGNORE)");

    proto_tree_add_item(rsvp_header_tree, hf_rsvp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_header_tree, hf_rsvp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(rsvp_header_tree, hf_rsvp_filter[RSVPF_MSG], tvb,
                        offset+1, 1, message_type);
    switch (RSVPF_MSG + message_type) {

    case RSVPF_PATH:
    case RSVPF_RESV:
    case RSVPF_PATHERR:
    case RSVPF_RESVERR:
    case RSVPF_PATHTEAR:
    case RSVPF_RESVTEAR:
    case RSVPF_RCONFIRM:
    case RSVPF_RTEARCONFIRM:
    case RSVPF_BUNDLE:
    case RSVPF_ACK:
    case RSVPF_SREFRESH:
    case RSVPF_HELLO:
    case RSVPF_NOTIFY:
        hidden_item = proto_tree_add_boolean(rsvp_header_tree, hf_rsvp_filter[RSVPF_MSG + message_type], tvb,
                                      offset+1, 1, 1);
        proto_item_set_hidden(hidden_item);
        break;
    }

    cksum = tvb_get_ntohs(tvb, offset+2);
    cksum_item = proto_tree_add_item(rsvp_header_tree, hf_rsvp_message_checksum, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(rsvp_header_tree, hf_rsvp_sending_ttl, tvb, offset+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(rsvp_header_tree, hf_rsvp_message_length, tvb, offset+6, 2, ENC_BIG_ENDIAN);

    offset = 8;
    len    = 8;

    if (message_type == RSVP_MSG_BUNDLE) {
        /* Bundle message. Dissect component messages */
        if (rsvp_bundle_dissect) {
            int len2 = 8;
            while (len2 < msg_length) {
                gint      sub_len;
                tvbuff_t *tvb_sub;
                sub_len = tvb_get_ntohs(tvb, len2+6);
                tvb_sub = tvb_new_subset_length(tvb, len2, sub_len);
                dissect_rsvp_msg_tree(tvb_sub, pinfo, rsvp_tree, TREE(TT_BUNDLE_COMPMSG), rsvph, e2ei);
                len2 += sub_len;
            }
        } else {
            proto_tree_add_expert(rsvp_tree, pinfo, &ei_rsvp_bundle_component_msg, tvb, offset, msg_length - len);
        }
        return;
    }

    while (len < msg_length) {
        guint8 rsvp_class;
        guint8 type;

        obj_length = tvb_get_ntohs(tvb, offset);
        rsvp_class = tvb_get_guint8(tvb, offset+2);
        type = tvb_get_guint8(tvb, offset+3);
        ti = proto_tree_add_item(rsvp_tree, hf_rsvp_filter[rsvp_class_to_filter_num(rsvp_class)],
                                 tvb, offset, obj_length, ENC_BIG_ENDIAN);
        rsvp_object_tree = proto_item_add_subtree(ti, TREE(rsvp_class_to_tree_type(rsvp_class)));
        len_item = proto_tree_add_item(rsvp_object_tree, hf_rsvp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (obj_length < 4) {
            expert_add_info_format(pinfo, len_item, &ei_rsvp_invalid_length,
                                "Length: %u (bogus, must be >= 4)", obj_length);
            break;
        }
        proto_tree_add_uint(rsvp_object_tree, hf_rsvp_filter[RSVPF_OBJECT], tvb,
                            offset+2, 1, rsvp_class);

        switch(rsvp_class) {

        case RSVP_CLASS_SESSION:
            dissect_rsvp_session(pinfo, ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_HOP:
            dissect_rsvp_hop(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_TIME_VALUES:
            dissect_rsvp_time_values(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ERROR:
            dissect_rsvp_error(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SCOPE:
            dissect_rsvp_scope(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_STYLE:
            dissect_rsvp_style(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_CONFIRM:
            dissect_rsvp_confirm(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SENDER_TEMPLATE:
        case RSVP_CLASS_FILTER_SPEC:
            dissect_rsvp_template_filter(pinfo, ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_SENDER_TSPEC:
            dissect_rsvp_tspec(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_FLOWSPEC:
            dissect_rsvp_flowspec(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ADSPEC:
            dissect_rsvp_adspec(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_INTEGRITY:
            have_integrity_object = TRUE;
            dissect_rsvp_integrity(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_POLICY:
            dissect_rsvp_policy(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LABEL_REQUEST:
            dissect_rsvp_label_request(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RECOVERY_LABEL:
        case RSVP_CLASS_UPSTREAM_LABEL:
        case RSVP_CLASS_SUGGESTED_LABEL:
        case RSVP_CLASS_LABEL:
            dissect_rsvp_label(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LABEL_SET:
            dissect_rsvp_label_set(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_SESSION_ATTRIBUTE:
            dissect_rsvp_session_attribute(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_EXPLICIT_ROUTE:
            dissect_rsvp_explicit_route(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RECORD_ROUTE:
            dissect_rsvp_record_route(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_EXCLUDE_ROUTE:
            dissect_rsvp_exclude_route(ti, pinfo, rsvp_object_tree, tvb, offset,
                                       obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID:
            dissect_rsvp_message_id(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID_ACK:
            dissect_rsvp_message_id_ack(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_MESSAGE_ID_LIST:
            dissect_rsvp_message_id_list(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_HELLO:
            dissect_rsvp_hello(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DCLASS:
            dissect_rsvp_dclass(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ADMIN_STATUS:
            dissect_rsvp_admin_status(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LSP_ATTRIBUTES:
        case RSVP_CLASS_LSP_REQUIRED_ATTRIBUTES:
            dissect_rsvp_lsp_attributes(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_ASSOCIATION:
            dissect_rsvp_association(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LSP_TUNNEL_IF_ID:
            dissect_rsvp_lsp_tunnel_if_id(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_NOTIFY_REQUEST:
            dissect_rsvp_notify_request(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_GENERALIZED_UNI:
            dissect_rsvp_gen_uni(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type, rsvph);
            break;

        case RSVP_CLASS_CALL_ID:
            dissect_rsvp_call_id(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_3GPP2_OBJECT:
            dissect_rsvp_3gpp_object(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_RESTART_CAP:
            dissect_rsvp_restart_cap(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_LINK_CAP:
            dissect_rsvp_link_cap(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_PROTECTION:
            dissect_rsvp_protection_info(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_FAST_REROUTE:
            dissect_rsvp_fast_reroute(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_S2L_SUB_LSP:
            dissect_rsvp_s2l_sub_lsp(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DETOUR:
            dissect_rsvp_detour(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_DIFFSERV:
            dissect_rsvp_diffserv(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_CLASSTYPE:
            dissect_rsvp_diffserv_aware_te(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_VENDOR_PRIVATE_1:
        case RSVP_CLASS_VENDOR_PRIVATE_2:
        case RSVP_CLASS_VENDOR_PRIVATE_3:
        case RSVP_CLASS_VENDOR_PRIVATE_4:
        case RSVP_CLASS_VENDOR_PRIVATE_5:
        case RSVP_CLASS_VENDOR_PRIVATE_6:
        case RSVP_CLASS_VENDOR_PRIVATE_7:
        case RSVP_CLASS_VENDOR_PRIVATE_8:
        case RSVP_CLASS_VENDOR_PRIVATE_9:
        case RSVP_CLASS_VENDOR_PRIVATE_10:
        case RSVP_CLASS_VENDOR_PRIVATE_11:
        case RSVP_CLASS_VENDOR_PRIVATE_12:
            dissect_rsvp_vendor_private_use(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_CALL_ATTRIBUTES:
            dissect_rsvp_call_attributes(ti, pinfo, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;

        case RSVP_CLASS_JUNIPER_PROPERTIES:
            dissect_rsvp_juniper(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;
        case RSVP_CLASS_NULL:
        default:
            dissect_rsvp_unknown(ti, rsvp_object_tree, tvb, offset, obj_length, rsvp_class, type);
            break;
        }

        offset += obj_length;
        len += obj_length;
    }

    /* We delay the checksum check until here so we know if the message
     * contained an integrity object or not */
    if (!pinfo->fragmented && ((int) tvb_captured_length(tvb) >= msg_length)) {
        /* The packet isn't part of a fragmented datagram and isn't
           truncated, so we can checksum it. */
        SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, msg_length);
        computed_cksum = in_cksum(&cksum_vec[0], 1);
        /*
         * in_cksum() should never return 0xFFFF here, because, to quote
         * RFC 1624 section 3 "Discussion":
         *
         *     In one's complement, there are two representations of
         *     zero: the all zero and the all one bit values, often
         *     referred to as +0 and -0.  One's complement addition
         *     of non-zero inputs can produce -0 as a result, but
         *     never +0.  Since there is guaranteed to be at least
         *     one non-zero field in the IP header, and the checksum
         *     field in the protocol header is the complement of the
         *     sum, the checksum field can never contain ~(+0), which
         *     is -0 (0xFFFF).  It can, however, contain ~(-0), which
         *     is +0 (0x0000).
         *
         * RFC 1624 is discussing the checksum of the *IPv4* header,
         * where the "version" field is 4, ensuring that, in a valid
         * IPv4 header, there is at least one non-zero field, but it
         * also applies to an RSVP packet, because header includes a
         * version field with the value 1, so at least one field in
         * the checksummed data is non-zero.
         *
         * in_cksum() returns the negation of the one's-complement
         * sum of all the data handed to it, and that data won't be
         * all zero, so the sum won't be 0 (+0), and thus the negation
         * won't be -0, i.e. won't be 0xFFFF.
         */
        if (computed_cksum == 0) {
            proto_item_append_text(cksum_item, " [correct]");
        } else if (cksum == 0 && have_integrity_object) {
            proto_item_append_text(cksum_item, " [ignored, integrity object used]");
        } else {
            proto_item_append_text(cksum_item, " [incorrect, should be 0x%04x]",
                                in_cksum_shouldbe(cksum, computed_cksum));
        }
    }
}

/*------------------------------------------------------------------------------
 * The main loop
 *------------------------------------------------------------------------------*/
static void
dissect_rsvp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean e2ei)
{
    guint8 message_type;
    int    session_off, tempfilt_off;

    rsvp_conversation_info  *rsvph;
    conversation_t          *conversation;
    struct rsvp_request_key  request_key, *new_request_key;
    struct rsvp_request_val *request_val;

    col_clear(pinfo->cinfo, COL_INFO);

    message_type = tvb_get_guint8(tvb, 1);

    rsvph = wmem_new0(pinfo->pool, rsvp_conversation_info);

    /* Copy over the source and destination addresses from the pinfo strucutre */
    set_address(&rsvph->source, pinfo->src.type, pinfo->src.len, pinfo->src.data);
    set_address(&rsvph->destination, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);

    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str_ext(message_type, &message_type_vals_ext, "Unknown (%u). "));

    if (message_type == RSVP_MSG_BUNDLE) {
        col_set_str(pinfo->cinfo, COL_INFO,
                    rsvp_bundle_dissect ?
                    "Component Messages Dissected" :
                    "Component Messages Not Dissected");
    } else {
        find_rsvp_session_tempfilt(tvb, 0, &session_off, &tempfilt_off);
        if (session_off)
            col_append_str(pinfo->cinfo, COL_INFO, summary_session(pinfo->pool, tvb, session_off));
        if (tempfilt_off)
            col_append_str(pinfo->cinfo, COL_INFO, summary_template(pinfo->pool, tvb, tempfilt_off));
    }

    dissect_rsvp_msg_tree(tvb, pinfo, tree, TREE(TT_RSVP), rsvph, e2ei);

    /* ACK, SREFRESH and HELLO messages don't have any associated SESSION and,
       therefore, no conversation */
    if ((message_type == RSVP_MSG_ACK)      ||
        (message_type == RSVP_MSG_SREFRESH) ||
        (message_type == RSVP_MSG_HELLO))
      return;

    /* Find out what conversation this packet is part of. */
    conversation = find_or_create_conversation(pinfo);

    /* Now build the request key */
    memset(&request_key, 0, sizeof(request_key));
    request_key.conversation = conversation->conv_index;
    request_key.session_type = rsvph->session_type;

    switch (request_key.session_type) {
    case RSVP_SESSION_TYPE_IPV4:
        set_address(&request_key.u.session_ipv4.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4.protocol = rsvph->protocol;
        request_key.u.session_ipv4.udp_dest_port = rsvph->udp_dest_port;
        break;

    case RSVP_SESSION_TYPE_IPV6:
        /* Not supported yet */
        break;

    case RSVP_SESSION_TYPE_IPV4_LSP:
        set_address(&request_key.u.session_ipv4_lsp.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_lsp.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_lsp.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;

    case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
        set_address(&request_key.u.session_agg_ipv4.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_agg_ipv4.dscp = rsvph->dscp;
        break;

    case RSVP_SESSION_TYPE_IPV4_UNI:
        set_address(&request_key.u.session_ipv4_uni.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_uni.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_uni.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;

    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4:
        set_address(&request_key.u.session_ipv4_p2mp_lsp.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_p2mp_lsp.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_p2mp_lsp.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;

    case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6:
        set_address(&request_key.u.session_ipv6_p2mp_lsp.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv6_p2mp_lsp.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv6_p2mp_lsp.ext_tunnel_id = rsvph->ext_tunnel_id_ipv6_pre;
        break;

    case RSVP_SESSION_TYPE_IPV4_E_NNI:
        set_address(&request_key.u.session_ipv4_enni.destination,
                    rsvph->destination.type, rsvph->destination.len,
                    rsvph->destination.data);
        request_key.u.session_ipv4_enni.udp_dest_port = rsvph->udp_dest_port;
        request_key.u.session_ipv4_enni.ext_tunnel_id = rsvph->ext_tunnel_id;
        break;
    default:
        /* This should never happen. */
        proto_tree_add_expert(tree, pinfo, &ei_rsvp_session_type, tvb, 0, 0);
        break;
    }

    copy_address_shallow(&request_key.source_info.source, &rsvph->source);
    request_key.source_info.udp_source_port = rsvph->udp_source_port;

    /* See if a request with this key already exists */
    request_val =
        (struct rsvp_request_val *) wmem_map_lookup(rsvp_request_hash,
                                                        &request_key);

    /* If not, insert the new request key into the hash table */
    if (!request_val) {
        new_request_key = (struct rsvp_request_key *)wmem_memdup(
              wmem_file_scope(), &request_key, sizeof(struct rsvp_request_key));
        switch (request_key.session_type) {
        case RSVP_SESSION_TYPE_IPV4:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv4.destination,
                              &request_key.u.session_ipv4.destination);
            break;
        case RSVP_SESSION_TYPE_IPV4_LSP:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv4_lsp.destination,
                              &request_key.u.session_ipv4_lsp.destination);
            break;
        case RSVP_SESSION_TYPE_AGGREGATE_IPV4:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_agg_ipv4.destination,
                              &request_key.u.session_agg_ipv4.destination);
            break;
        case RSVP_SESSION_TYPE_IPV4_UNI:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv4_uni.destination,
                              &request_key.u.session_ipv4_uni.destination);
            break;
        case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV4:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv4_p2mp_lsp.destination,
                              &request_key.u.session_ipv4_p2mp_lsp.destination);
            break;
        case RSVP_SESSION_TYPE_P2MP_LSP_TUNNEL_IPV6:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv6_p2mp_lsp.destination,
                              &request_key.u.session_ipv6_p2mp_lsp.destination);
            break;
        case RSVP_SESSION_TYPE_IPV4_E_NNI:
            copy_address_wmem(wmem_file_scope(), &new_request_key->u.session_ipv4_enni.destination,
                              &request_key.u.session_ipv4_enni.destination);
            break;
        default:
            break;
        }
        copy_address_wmem(wmem_file_scope(), &new_request_key->source_info.source, &rsvph->source);

        request_val = wmem_new(wmem_file_scope(), struct rsvp_request_val);
        request_val->value = conversation->conv_index;

        wmem_map_insert(rsvp_request_hash, new_request_key, request_val);
    }

    tap_queue_packet(rsvp_tap, pinfo, rsvph);
}

static int
dissect_rsvp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSVP");

    dissect_rsvp_common(tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static int
dissect_rsvp_e2ei(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSVP-E2EI");

    dissect_rsvp_common(tvb, pinfo, tree, TRUE);
    return tvb_captured_length(tvb);
}

static void
register_rsvp_prefs(void)
{
    module_t *rsvp_module;

    rsvp_module = prefs_register_protocol(proto_rsvp, NULL);
    prefs_register_bool_preference(
        rsvp_module, "process_bundle",
        "Dissect sub-messages in BUNDLE message",
        "Specifies whether Wireshark should decode and display sub-messages within BUNDLE messages",
        &rsvp_bundle_dissect);
    prefs_register_enum_preference(
        rsvp_module, "generalized_label_options",
        "Dissect generalized labels as",
        "Specifies how Wireshark should dissect generalized labels",
        (gint *)&rsvp_generalized_label_option,
        rsvp_generalized_label_options,
        FALSE);
}

void
proto_register_rsvp(void)
{
    gint i;

    static hf_register_info rsvpf_info[] = {

        /* Message type number */
        {&hf_rsvp_filter[RSVPF_MSG],
         { "Message Type", "rsvp.msg",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &message_type_vals_ext, 0x0,
           NULL, HFILL }
        },

        /* Message type shorthands */
        {&hf_rsvp_filter[RSVPF_PATH],
         { "Path Message", "rsvp.path",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESV],
         { "Resv Message", "rsvp.resv",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PATHERR],
         { "Path Error Message", "rsvp.perr",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESVERR],
         { "Resv Error Message", "rsvp.rerr",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PATHTEAR],
         { "Path Tear Message", "rsvp.ptear",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESVTEAR],
         { "Resv Tear Message", "rsvp.rtear",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RCONFIRM],
         { "Resv Confirm Message", "rsvp.resvconf",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RTEARCONFIRM],
         { "Resv Tear Confirm Message", "rsvp.rtearconf",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_BUNDLE],
         { "Bundle Message", "rsvp.bundle",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ACK],
         { "Ack Message", "rsvp.ack",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SREFRESH],
         { "Srefresh Message", "rsvp.srefresh",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HELLO],
         { "HELLO Message", "rsvp.hello",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Object class */
        {&hf_rsvp_filter[RSVPF_OBJECT],
         { "Object class", "rsvp.object",
           FT_UINT8, BASE_DEC | BASE_EXT_STRING, &rsvp_class_vals_ext, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype,
         { "C-type", "rsvp.ctype",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_session,
         { "C-type", "rsvp.ctype.session",
           FT_UINT32, BASE_DEC, VALS(rsvp_c_type_session_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_3gpp_object,
         { "C-type", "rsvp.ctype.3gpp_object",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_restart_cap,
         { "C-type", "rsvp.ctype.restart_cap",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_link_cap,
         { "C-type", "rsvp.ctype.link_cap",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_protection_info,
         { "C-type", "rsvp.ctype.protection_info",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_fast_reroute,
         { "C-type", "rsvp.ctype.fast_reroute",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_detour,
         { "C-type", "rsvp.ctype.detour",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_diffserv,
         { "C-type", "rsvp.ctype.diffserv",
           FT_UINT32, BASE_DEC, VALS(rsvp_c_type_diffserv_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_diffserv_aware_te,
         { "C-type", "rsvp.ctype.diffserv_aware_te",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_vendor,
         { "C-type", "rsvp.ctype.vendor",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_juniper,
         { "C-type", "rsvp.ctype.juniper",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_unknown,
         { "C-type", "rsvp.ctype.unknown",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_label,
         { "C-type", "rsvp.ctype.label",
           FT_UINT32, BASE_DEC, VALS(rsvp_c_type_label_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_notify_request,
         { "C-type", "rsvp.ctype.notify_request",
           FT_UINT32, BASE_DEC, VALS(rsvp_c_type_notify_request_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_ctype_generalized_uni,
         { "C-type", "rsvp.ctype.generalized_uni",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_parameter,
         { "Parameter", "rsvp.parameter",
           FT_UINT8, BASE_DEC|BASE_EXT_STRING, &svc_vals_ext, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_parameter_flags,
         { "Parameter flags", "rsvp.parameter_flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_parameter_length,
         { "Parameter length", "rsvp.parameter_length",
           FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_word_not_including_header, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_error_value,
         { "Error value", "rsvp.error_value",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_class,
         { "Class", "rsvp.class",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_class_length,
         { "Length", "rsvp.class_length",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_reserved,
         { "Reserved", "rsvp.ctype.reserved",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_switching_granularity,
         { "Switching granularity", "rsvp.switching_granularity",
           FT_UINT16, BASE_DEC, VALS(rsvp_switching_granularity_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_NOTIFY],
         { "Notify Message", "rsvp.notify",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Object present shorthands */
        {&hf_rsvp_filter[RSVPF_SESSION],
         { "SESSION", "rsvp.session",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HOP],
         { "HOP", "rsvp.hop",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_HELLO_OBJ],
         { "HELLO Request/Ack", "rsvp.hello_obj",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_INTEGRITY],
         { "INTEGRITY", "rsvp.integrity",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_TIME_VALUES],
         { "TIME VALUES", "rsvp.time",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ERROR],
         { "ERROR", "rsvp.error",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SCOPE],
         { "SCOPE", "rsvp.scope",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_STYLE],
         { "STYLE", "rsvp.style",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_FLOWSPEC],
         { "FLOWSPEC", "rsvp.flowspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_FILTER_SPEC],
         { "FILTERSPEC", "rsvp.filter",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER],
         { "SENDER TEMPLATE", "rsvp.sender",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_TSPEC],
         { "SENDER TSPEC", "rsvp.tspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADSPEC],
         { "ADSPEC", "rsvp.adspec",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_POLICY],
         { "POLICY", "rsvp.policy",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CONFIRM],
         { "CONFIRM", "rsvp.confirm",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL],
         { "LABEL", "rsvp.label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RECOVERY_LABEL],
         { "RECOVERY LABEL", "rsvp.recovery_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_UPSTREAM_LABEL],
         { "UPSTREAM LABEL", "rsvp.upstream_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SUGGESTED_LABEL],
         { "SUGGESTED LABEL", "rsvp.suggested_label",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL_SET],
         { "LABEL SET", "rsvp.label_set",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ACCEPTABLE_LABEL_SET],
         { "ACCEPTABLE LABEL SET", "rsvp.acceptable_label_set",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_PROTECTION],
         { "PROTECTION", "rsvp.protection",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV],
         { "DIFFSERV", "rsvp.diffserv",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DSTE],
         { "CLASSTYPE", "rsvp.dste",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RESTART_CAP],
         { "RESTART CAPABILITY", "rsvp.restart",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LINK_CAP],
         { "LINK CAPABILITY", "rsvp.link",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LABEL_REQUEST],
         { "LABEL REQUEST", "rsvp.label_request",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_ATTRIBUTE],
         { "SESSION ATTRIBUTE", "rsvp.session_attribute",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_EXPLICIT_ROUTE],
         { "EXPLICIT ROUTE", "rsvp.explicit_route",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_RECORD_ROUTE],
         { "RECORD ROUTE", "rsvp.record_route",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID],
         { "MESSAGE-ID", "rsvp.msgid",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID_ACK],
         { "MESSAGE-ID ACK", "rsvp.msgid_ack",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_MESSAGE_ID_LIST],
         { "MESSAGE-ID LIST", "rsvp.msgid_list",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DCLASS],
         { "DCLASS", "rsvp.dclass",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LSP_TUNNEL_IF_ID],
         { "LSP INTERFACE-ID", "rsvp.lsp_tunnel_if_id",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS],
         { "ADMIN STATUS", "rsvp.admin_status",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_REFLECT],
         { "Reflect", "rsvp.admin_status.reflect",
           FT_BOOLEAN, 32, NULL, 0x80000000,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_HANDOVER],
         { "Handover", "rsvp.admin_status.handover",
           FT_BOOLEAN, 32, NULL, 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_LOCKOUT],
         { "Lockout", "rsvp.admin_status.lockout",
           FT_BOOLEAN, 32, NULL, 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_INHIBIT],
         { "Inhibit Alarm Communication", "rsvp.admin_status.inhibit",
           FT_BOOLEAN, 32, NULL, 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_CALL_MGMT],
         { "Call Management", "rsvp.admin_status.callmgmt",
           FT_BOOLEAN, 32, NULL, 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_TESTING],
         { "Testing", "rsvp.admin_status.testing",
           FT_BOOLEAN, 32, NULL, 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_DOWN],
         { "Administratively down", "rsvp.admin_status.down",
           FT_BOOLEAN, 32, NULL, 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ADMIN_STATUS_DELETE],
         { "Delete in progress", "rsvp.admin_status.delete",
           FT_BOOLEAN, 32, NULL, 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_LSP_ATTRIBUTES],
         { "LSP ATTRIBUTES", "rsvp.lsp_attributes",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_ASSOCIATION],
         { "ASSOCIATION", "rsvp.association",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CALL_ATTRIBUTES],
         { "CALL ATTRIBUTES", "rsvp.call_attributes",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_NOTIFY_REQUEST],
         { "NOTIFY REQUEST", "rsvp.notify_request",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GENERALIZED_UNI],
         { "GENERALIZED UNI", "rsvp.generalized_uni",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CALL_ID],
         { "CALL ID", "rsvp.call_id",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_3GPP2_OBJECT],
         { "3GPP2 OBJECT", "rsvp.3gpp2_object",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },
        {&hf_rsvp_filter[RSVPF_PRIVATE_OBJ],
         { "Private object", "rsvp.obj_private",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_UNKNOWN_OBJ],
         { "Unknown object", "rsvp.obj_unknown",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Session fields */
        {&hf_rsvp_filter[RSVPF_SESSION_IP],
         { "Destination address", "rsvp.session.ip",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_SHORT_CALL_ID],
         { "Short Call ID", "rsvp.session.short_call_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_PORT],
         { "Port number", "rsvp.session.port",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_PROTO],
         { "Protocol", "rsvp.session.proto",
           FT_UINT8, BASE_DEC, VALS(proto_vals), 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_TUNNEL_ID],
         { "Tunnel ID", "rsvp.session.tunnel_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID],
         { "Extended tunnel ID", "rsvp.session.ext_tunnel_id",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SESSION_EXT_TUNNEL_ID_IPV6],
         { "Extended tunnel ID", "rsvp.session.ext_tunnel_id_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_JUNIPER],
         { "Juniper", "rsvp.juniper",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Sender template/Filterspec fields */
        {&hf_rsvp_filter[RSVPF_SENDER_IP],
         { "Sender IPv4 address", "rsvp.sender.ip",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER_PORT],
         { "Sender port number", "rsvp.sender.port",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER_LSP_ID],
         { "LSP ID", "rsvp.sender.lsp_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_SENDER_SHORT_CALL_ID],
         { "Short Call ID", "rsvp.sender.short_call_id",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* Diffserv object fields */
        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAPNB],
         { "MAPnb", "rsvp.diffserv.mapnb",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           MAPNB_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAP],
         { "MAP", "rsvp.diffserv.map",
           FT_NONE, BASE_NONE, NULL, 0x0,
           MAP_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_MAP_EXP],
         { "EXP", "rsvp.diffserv.map.exp",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           EXP_DESCRIPTION, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID],
         { PHBID_DESCRIPTION, "rsvp.diffserv.phbid",
           FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_DSCP],
         { PHBID_DSCP_DESCRIPTION, "rsvp.diffserv.phbid.dscp",
           FT_UINT16, BASE_DEC, NULL, PHBID_DSCP_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_CODE],
         { PHBID_CODE_DESCRIPTION, "rsvp.diffserv.phbid.code",
           FT_UINT16, BASE_DEC, NULL, PHBID_CODE_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT14],
         { PHBID_BIT14_DESCRIPTION, "rsvp.diffserv.phbid.bit14",
           FT_UINT16, BASE_DEC, VALS(phbid_bit14_vals), PHBID_BIT14_MASK,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_DIFFSERV_PHBID_BIT15],
         { PHBID_BIT15_DESCRIPTION, "rsvp.diffserv.phbid.bit15",
           FT_UINT16, BASE_DEC, VALS(phbid_bit15_vals), PHBID_BIT15_MASK,
           NULL, HFILL }
        },

        /* Diffserv-aware TE object field */
        {&hf_rsvp_filter[RSVPF_DSTE_CLASSTYPE],
         { "CT", "rsvp.dste.classtype",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },

        /* Generalized UNI object field */
        {&hf_rsvp_filter[RSVPF_GUNI_SRC_IPV4],
         { "Source TNA", "rsvp.guni.srctna.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_DST_IPV4],
         { "Destination TNA", "rsvp.guni.dsttna.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_SRC_IPV6],
         { "Source TNA", "rsvp.guni.srctna.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_GUNI_DST_IPV6],
         { "Destination TNA", "rsvp.guni.dsttna.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /* Generalized UNI object field */
        {&hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV4],
         { "Source Transport Network Address", "rsvp.callid.srcaddr.ipv4",
           FT_IPv4, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_filter[RSVPF_CALL_ID_SRC_ADDR_IPV6],
         { "Source Transport Network Address", "rsvp.callid.srcaddr.ipv6",
           FT_IPv6, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_callid_srcaddr_ether,
         { "Source Transport Network Address", "rsvp.callid.srcaddr.ether",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_callid_srcaddr_bytes,
         { "Source Transport Network Address", "rsvp.callid.srcaddr.bytes",
           FT_ETHER, BASE_NONE, NULL, 0x0,
           NULL, HFILL }
        },

        /*
         * FF: Vendor Private object field, please see
         * http://www.iana.org/assignments/enterprise-numbers
         */
        {&hf_rsvp_filter[RSVPF_ENT_CODE],
         { "Enterprise Code", "rsvp.obj_private.enterprise",
           FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
           "IANA Network Management Private Enterprise Code", HFILL }
        },

        {&hf_rsvp_error_flags,
         { "Flags", "rsvp.error_flags",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_path_state_removed,
         { "Path State Removed", "rsvp.error_flags.path_state_removed",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_not_guilty,
         { "NotGuilty", "rsvp.error_flags.not_guilty",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_error_flags_in_place,
         { "InPlace", "rsvp.error_flags.in_place",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_eth_tspec_tlv_color_mode,
         { "Color Mode (CM)", "rsvp.eth_tspec_tlv.color_mode",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_eth_tspec_tlv_coupling_flag,
         { "Coupling Flag (CF)", "rsvp.eth_tspec_tlv.coupling_flag",
           FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_standard_contiguous_concatenation,
         { "Standard contiguous concatenation", "rsvp.sender_tspec.standard_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_arbitrary_contiguous_concatenation,
         { "Arbitrary contiguous concatenation", "rsvp.sender_tspec.arbitrary_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_regenerator_section,
         { "Section/Regenerator Section layer transparency", "rsvp.sender_tspec.regenerator_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0001,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_multiplex_section,
         { "Line/Multiplex Section layer transparency", "rsvp.sender_tspec.multiplex_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0002,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_J0_transparency,
         { "J0 transparency", "rsvp.sender_tspec.J0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0004,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_SOH_RSOH_DCC_transparency,
         { "SOH/RSOH DCC transparency", "rsvp.sender_tspec.SOH_RSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0008,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_LOH_MSOH_DCC_transparency,
         { "LOH/MSOH DCC transparency", "rsvp.sender_tspec.LOH_MSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0010,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_LOH_MSOH_extended_DCC_transparency,
         { "LOH/MSOH Extended DCC transparency", "rsvp.sender_tspec.LOH_MSOH_extended_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0020,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_K1_K2_transparency,
         { "K1/K2 transparency", "rsvp.sender_tspec.K1_K2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0040,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_E1_transparency,
         { "E1 transparency", "rsvp.sender_tspec.E1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0080,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_F1_transparency,
         { "F1 transparency", "rsvp.sender_tspec.F1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0100,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_E2_transparency,
         { "E2 transparency", "rsvp.sender_tspec.E2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0200,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_B1_transparency,
         { "B1 transparency", "rsvp.sender_tspec.B1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0400,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_B2_transparency,
         { "B2 transparency", "rsvp.sender_tspec.B2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0800,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_M0_transparency,
         { "M0 transparency", "rsvp.sender_tspec.M0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x1000,
           NULL, HFILL }
        },

        {&hf_rsvp_sender_tspec_M1_transparency,
         { "M1 transparency", "rsvp.sender_tspec.M1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x2000,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_standard_contiguous_concatenation,
         { "Standard contiguous concatenation", "rsvp.flowspec.standard_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_arbitrary_contiguous_concatenation,
         { "Arbitrary contiguous concatenation", "rsvp.flowspec.arbitrary_contiguous_concatenation",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_regenerator_section,
         { "Section/Regenerator Section layer transparency", "rsvp.flowspec.regenerator_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0001,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_multiplex_section,
         { "Line/Multiplex Section layer transparency", "rsvp.flowspec.multiplex_section",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0002,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_J0_transparency,
         { "J0 transparency", "rsvp.flowspec.J0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0004,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_SOH_RSOH_DCC_transparency,
         { "SOH/RSOH DCC transparency", "rsvp.flowspec.SOH_RSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0008,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_LOH_MSOH_DCC_transparency,
         { "LOH/MSOH DCC transparency", "rsvp.flowspec.LOH_MSOH_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0010,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_LOH_MSOH_extended_DCC_transparency,
         { "LOH/MSOH Extended DCC transparency", "rsvp.flowspec.LOH_MSOH_extended_DCC_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0020,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_K1_K2_transparency,
         { "K1/K2 transparency", "rsvp.flowspec.K1_K2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0040,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_E1_transparency,
         { "E1 transparency", "rsvp.flowspec.E1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0080,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_F1_transparency,
         { "F1 transparency", "rsvp.flowspec.F1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0100,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_E2_transparency,
         { "E2 transparency", "rsvp.flowspec.E2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0200,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_B1_transparency,
         { "B1 transparency", "rsvp.flowspec.B1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0400,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_B2_transparency,
         { "B2 transparency", "rsvp.flowspec.B2_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0800,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_M0_transparency,
         { "M0 transparency", "rsvp.flowspec.M0_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x1000,
           NULL, HFILL }
        },

        {&hf_rsvp_flowspec_M1_transparency,
         { "M1 transparency", "rsvp.flowspec.M1_transparency",
           FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x2000,
           NULL, HFILL }
        },

        {&hf_rsvp_integrity_flags_handshake,
         { "Handshake", "rsvp.integrity.flags.handshake",
           FT_BOOLEAN, 8, TFS(&tfs_capable_not_capable), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_local,
         { "Local protection", "rsvp.sa.flags.local",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_label,
         { "Label recording", "rsvp.sa.flags.label",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_se_style,
         { "SE style", "rsvp.sa.flags.se_style",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_bandwidth,
         { "Bandwidth protection", "rsvp.sa.flags.bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_sa_flags_node,
         { "Node protection", "rsvp.sa.flags.node",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_local_avail,
         { "Local Protection", "rsvp.rro.flags.local_avail",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_local_in_use,
         { "Local Protection", "rsvp.rro.flags.local_in_use",
           FT_BOOLEAN, 8, TFS(&tfs_used_notused), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_bandwidth,
         { "Bandwidth Protection", "rsvp.rro.flags.bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_node,
         { "Node Protection", "rsvp.rro.flags.node",
           FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_node_address,
         { "Address Specifies a Node-id Address", "rsvp.rro.flags.node_address",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_backup_tunnel_bandwidth,
         { "Backup Tunnel Has Bandwidth", "rsvp.rro.flags.backup_tunnel_bandwidth",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_backup_tunnel_hop,
         { "Backup Tunnel Goes To", "rsvp.rro.flags.backup_tunnel_hop",
           FT_BOOLEAN, 8, TFS(&tfs_next_next_hop_next_hop), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_rro_flags_global_label,
         { "Global label", "rsvp.rro.flags.global_label",
           FT_BOOLEAN, 8, NULL, 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr,
         { "LSP Attributes Flags", "rsvp.lsp_attr",
           FT_UINT32, BASE_HEX, NULL, 0x0,
           NULL, HFILL}
        },

        {&hf_rsvp_lsp_attr_e2e,
         { "End-to-end re-routing", "rsvp.lsp_attr.e2e",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x80000000, /* 0 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_boundary,
         { "Boundary re-routing", "rsvp.lsp_attr.boundary",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x40000000, /* 1 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_segment,
         { "Segment-based re-routing", "rsvp.lsp_attr.segment",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x20000000, /* 2 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_integrity,
         { "LSP Integrity Required", "rsvp.lsp_attr.integrity",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x10000000, /* 3 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_contiguous,
         { "Contiguous LSP", "rsvp.lsp_attr.contiguous",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x08000000, /* 4 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_stitching,
         { "LSP stitching desired", "rsvp.lsp_attr.stitching",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x04000000, /* 5 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_preplanned,
         { "Pre-Planned LSP Flag", "rsvp.lsp_attr.preplanned",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x02000000, /* 6 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_nophp,
         { "Non-PHP behavior flag", "rsvp.lsp_attr.nophp",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x01000000, /* 7 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_oobmap,
         { "OOB mapping flag", "rsvp.lsp_attr.oobmap",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00800000, /* 8 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_entropy,
         { "Entropy Label Capability", "rsvp.lsp_attr.entropy",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00400000, /* 9 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_oammep,
         { "OAM MEP entities desired", "rsvp.lsp_attr.oammep",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00200000, /* 10 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_oammip,
         { "OAM MIP entities desired", "rsvp.lsp_attr.oammip",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00100000, /* 11 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_srlgcollect,
         { "SRLG Collection Flag", "rsvp.lsp_attr.srlgcollect",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00080000, /* 12 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_loopback,
         { "Loopback", "rsvp.lsp_attr.Loopback",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00040000, /* 13 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_p2mp,
         { "P2MP-TE Tree Re-evaluation Request", "rsvp.lsp_attr.p2mp",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00020000, /* 14 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_rtm,
         { "RTM_SET", "rsvp.lsp_attr.rtm",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00010000, /* 15 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_telinklabel,
         { "TE Link Label", "rsvp.lsp_attr.telinklabel",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00008000, /* 16 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_lsi,
         { "LSI-D", "rsvp.lsp_attr.lsi",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00004000, /* 17 */
           NULL, HFILL }
        },

        {&hf_rsvp_lsp_attr_lsids2e,
         { "LSI-D-S2E", "rsvp.lsp_attr.lsids2e",
           FT_BOOLEAN, 32, TFS(&tfs_desired_not_desired), 0x00002000, /* 18 */
           NULL, HFILL }
        },

        {&hf_rsvp_gen_uni_direction,
         { "Direction", "rsvp.gen_uni.direction",
           FT_BOOLEAN, 8, TFS(&tfs_gen_uni_direction), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_flags_secondary_lsp,
         { "Secondary LSP", "rsvp.pi.flags.secondary_lsp",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_extra_traffic,
         { "Extra Traffic", "rsvp.pi_link.flags.extra_traffic",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_unprotected,
         { "Unprotected", "rsvp.pi_link.flags.unprotected",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_shared,
         { "Shared", "rsvp.pi_link.flags.shared",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated1_1,
         { "Dedicated 1:1", "rsvp.pi_link.flags.dedicated1_1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated1plus1,
         { "Dedicated 1+1", "rsvp.pi_link.flags.dedicated1plus1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_enhanced,
         { "Enhanced", "rsvp.pi_link.flags.enhanced",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_extra,
         { "Extra Traffic", "rsvp.pi_link.flags.extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated_1_1,
         { "Dedicated 1:1", "rsvp.pi_link.flags.dedicated_1_1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_link_flags_dedicated_1plus1,
         { "Dedicated 1+1", "rsvp.pi_link.flags.dedicated_1plus1",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_secondary,
         { "Secondary LSP", "rsvp.rfc4872.secondary",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_protecting,
         { "Protecting LSP", "rsvp.rfc4872.protecting",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_notification_msg,
         { "Protecting LSP", "rsvp.rfc4872.notification_msg",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
           NULL, HFILL }
        },

        {&hf_rsvp_rfc4872_operational,
         { "Protecting LSP", "rsvp.rfc4872.operational",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_full_rerouting,
         { "(Full) rerouting", "rsvp.pi_lsp.flags.full_rerouting",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_rerouting_extra,
         { "Rerouting without extra-traffic", "rsvp.pi_lsp.flags.rerouting_extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1_n_protection,
         { "1:N protection with extra-traffic", "rsvp.pi_lsp.flags.1_n_protection",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1plus1_unidirectional,
         { "1+1 unidirectional protection", "rsvp.pi_lsp.flags.1plus1_unidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_lsp_flags_1plus1_bidirectional,
         { "1+1 bidirectional protection", "rsvp.pi_lsp.flags.1plus1_bidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_in_place,
         { "In-Place", "rsvp.protection_info.in_place",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
           NULL, HFILL }
        },

        {&hf_rsvp_protection_info_required,
         { "Required", "rsvp.protection_info.required",
           FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_full_rerouting,
         { "(Full) rerouting", "rsvp.pi_seg.flags.full_rerouting",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_rerouting_extra,
         { "Rerouting without extra-traffic", "rsvp.pi_seg.flags.rerouting_extra",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1_n_protection,
         { "1:N protection with extra-traffic", "rsvp.pi_seg.flags.1_n_protection",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x04,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1plus1_unidirectional,
         { "1+1 unidirectional protection", "rsvp.pi_seg.flags.1plus1_unidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x08,
           NULL, HFILL }
        },

        {&hf_rsvp_pi_seg_flags_1plus1_bidirectional,
         { "1+1 bidirectional protection", "rsvp.pi_seg.flags.1plus1_bidirectional",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x10,
           NULL, HFILL }
        },

        {&hf_rsvp_frr_flags_one2one_backup,
         { "One-to-One Backup", "rsvp.frr.flags.one2one_backup",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x01,
           NULL, HFILL }
        },

        {&hf_rsvp_frr_flags_facility_backup,
         { "Facility Backup", "rsvp.frr.flags.facility_backup",
           FT_BOOLEAN, 8, TFS(&tfs_desired_not_desired), 0x02,
           NULL, HFILL }
        },
        {&hf_rsvp_type,
         { "Type", "rsvp.type",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tid,
         { "Transaction ID", "rsvp.3gpp_obj.tid",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_ie_len,
         { "Length", "rsvp.3gpp_obj.length",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_ie_type,
         { "IE Type", "rsvp.3gpp_obj.ie_type",
           FT_UINT32, BASE_DEC, VALS(rsvp_3gpp_object_ie_type_vals), 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_ue_ipv4_addr,
         { "UE IPv4 address", "rsvp.3gpp_obj.ue_ipv4_addr",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_ue_ipv6_addr,
         { "UE IPv6 address", "rsvp.3gpp_obj.ue_ipv6_addr",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_d,
         { "Direction(D)", "rsvp.3gpp_obj.tft_d",
           FT_UINT32, BASE_DEC, VALS(rsvp_3gpp_object_tft_d_vals), 0xc0000000,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_ns,
         { "Non-Specific bit(NS)", "rsvp.3gpp_obj.tft_ns",
           FT_UINT32, BASE_DEC, NULL, 0x08000000,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_sr_id,
         { "SR_ID", "rsvp.3gpp_obj.tft_sr_id",
           FT_UINT32, BASE_DEC, NULL, 0x07000000,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_p,
         { "Persistency(P)", "rsvp.3gpp_obj.tft_p",
           FT_UINT32, BASE_DEC, NULL, 0x00010000,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_opcode,
         { "TFT Operation Code", "rsvp.3gpp_obj.tft_opcode",
           FT_UINT32, BASE_DEC, VALS(rsvp_3gpp_obj_tft_opcode_vals), 0x000ff00,
           NULL, HFILL }
        },
        {&hf_rsvp_3gpp_obj_tft_n_pkt_flt,
         { "Number of Packet filters", "rsvp.3gpp_obj.tft_n_pkt_flt",
           FT_UINT32, BASE_DEC, NULL, 0x00000ff,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_flow_id,
         { "Flow Identifier", "rsvp.3gpp_obj.flow_id",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_ev_prec,
         { "Packet filter evaluation precedence", "rsvp.3gpp_obj.pf_ev_prec",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_len,
         { "Packet filter length", "rsvp.3gpp_obj.pf_len",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_type,
         { "PF Type", "rsvp.3gpp_obj.pf_type",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_cont_len,
         { "Length", "rsvp.3gpp_obj.pf_cont_len",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_comp_type_id,
         { "PF component identifier", "rsvp.3gpp_obj.pf_comp_type_id",
           FT_UINT8, BASE_DEC, VALS(rsvp_3gpp_obj_pf_comp_type_id_vals), 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_src_ipv4,
         { "IPv4 Source Address", "rsvp.3gpp_obj.pf_src_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_dst_ipv4,
         { "IPv4 Destination Address", "rsvp.3gpp_obj.pf_dst_ipv4",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_ipv4_mask,
         { "IPv4 Mask", "rsvp.3gpp_obj.pf_ipv4_mask",
           FT_UINT32, BASE_HEX, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_src_ipv6,
         { "IPv6 Source Address", "rsvp.3gpp_obj.pf_src_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_dst_ipv6,
         { "IPv6 Destination Address", "rsvp.3gpp_obj.pf_dst_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_ipv6_prefix_length,
         { "IPv6 Prefix length", "rsvp.3gpp_obj.pf_ipv6_prefix_length",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_prot_next,
         { "Protocol field(IPv4) or Next Header(IPv6)", "rsvp.3gpp_obj.pf_prot_next",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_dst_port,
         { "Single Destination Port", "rsvp.3gpp_obj.pf_dst_port",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_src_port,
         { "Single Source Port", "rsvp.3gpp_obj.pf_src_port",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_ipsec_spi,
         { "IPsec SPI", "rsvp.3gpp_obj.pf_ipsec_spi",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_tos_tc,
         { "Type of Service (IPv4)/Traffic Class (IPv6)", "rsvp.3gpp_obj.pf_tos_tc",
           FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_flow_lbl,
         { "Flow label", "rsvp.3gpp_obj.pf_flow_lbl",
           FT_UINT24, BASE_DEC, NULL, 0x0fffff,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_ipv6,
         { "IPv6 Address", "rsvp.3gpp_obj.pf_ipv6",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_treatment,
         { "PF Treatment", "rsvp.3gpp_obj.pf_treatment",
           FT_UINT8, BASE_DEC, VALS(rsvp_3gpp_obj_pf_treatment_vals), 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_pf_hint,
         { "PF Hint", "rsvp.3gpp_obj.pf_hint",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_obj_tft_qos_list_len,
         { "QoS List Length", "rsvp.3gpp_obj.qos_list_len",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_r_qos_blob_len,
         { "R_QOS_SUB_BLOB_LEN", "rsvp.3gpp_obj.r_qos_blob_len",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_r_qos_blob_flow_pri,
         { "FLOW_PRIORITY", "rsvp.3gpp_obj.r_qos_blob.flow_pri",
           FT_UINT8, BASE_DEC, NULL, 0xf0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_r_qos_blob_num_qos_att_set,
         { "NUM_QoS_ATTRIBUTE_SETS", "rsvp.3gpp_obj.r_qos_blob.num_qos_att_set",
           FT_UINT8, BASE_DEC, NULL, 0x0e,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_att_set_len,
         { "QoS_ATTRIBUTE_SET_LEN", "rsvp.3gpp_obj.r_qos_blob.qos_att_set_len",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_set_id,
         { "QoS_ATTRIBUTE_SET_ID", "rsvp.3gpp_obj.r_qos_blob.qos_attribute_set_id",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_verbose,
         { "VERBOSE", "rsvp.3gpp_obj.r_qos_blob.verbose",
           FT_BOOLEAN, 8, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_prof_id,
         { "ProfileID", "rsvp.3gpp_obj.r_qos_blob.prof_id",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_traff_cls,
         { "Traffic_Class", "rsvp.3gpp_obj.r_qos_blob.traff_cls",
           FT_UINT8, BASE_DEC, VALS(rsvp_3gpp_obj_traffic_class_vals), 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_peak_rate,
         { "Peak_Rate", "rsvp.3gpp_obj.r_qos_blob.peak_rate",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_bucket_size,
         { "Bucket_Size", "rsvp.3gpp_obj.r_qos_blob.bucket_size",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_token_rate,
         { "Token_Rate", "rsvp.3gpp_obj.r_qos_blob.token_rate",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_max_latency,
         { "Max_Latency", "rsvp.3gpp_obj.r_qos_blob.max_latency",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_max_loss_rte,
         { "Max_Loss_Rate", "rsvp.3gpp_obj.r_qos_blob.max_loss_rte",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_delay_var_sensitive,
         { "Delay_Var_Sensitive", "rsvp.3gpp_obj.r_qos_blob.delay_var_sensitive",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_attribute_reserved,
         { "Reserved", "rsvp.3gpp_obj.r_qos_blob.reserved",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_r_qos_blob,
         { "R_QOS_SUB_BLOB", "rsvp.3gpp_obj.r_qos_blob",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL }
        },
        { &hf_rsvp_3gpp_qos_result,
         { "Result Code", "rsvp.3gpp_obj.qos_result_code",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL }
        },

        { &hf_rsvp_xro_sobj_lbit,
          { "L(oose) bit", "rsvp.xro.sobj.lbit",
            FT_UINT8, BASE_DEC,VALS(rsvp_xro_sobj_lbit_vals), 0x80,
            NULL, HFILL
          }
        },
        { &hf_rsvp_rro_sobj_dbit,
          { "D(irection) bit", "rsvp.rro.sobj.dbit",
            FT_UINT8, BASE_DEC,VALS(rsvp_rro_sobj_dbit_vals), 0x80,
            NULL, HFILL
          }
        },

        { &hf_rsvp_xro_sobj_len,
          { "Length", "rsvp.xro.sobj.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL
          }
        },

        { &hf_rsvp_xro_sobj_ipv4_addr,
         { "IPv4 prefix", "rsvp.xro.sobj.ipv4.addr",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_xro_sobj_ipv4_prefix,
         { "Prefix Length", "rsvp.xro.sobj.ipv4.prefix",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_xro_sobj_ipv4_attr,
         { "Attribute", "rsvp.xro.sobj.ipv4.attr",
           FT_UINT8, BASE_DEC, VALS(rsvp_xro_sobj_ip_attr_vals), 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_xro_sobj_ipv6_attr,
         { "Attribute", "rsvp.xro.sobj.ipv6.attr",
           FT_UINT8, BASE_DEC, VALS(rsvp_xro_sobj_ip_attr_vals), 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_xro_sobj_srlg_id,
         { "SRLG Id", "rsvp.xro.sobj.srlg.id",
           FT_UINT32, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_xro_sobj_srlg_res,
         { "Reserved", "rsvp.xro.sobj.srlg.res",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_private_data,
         { "Data", "rsvp.private.data",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_numtlvs,
         { "Num TLVs", "rsvp.juniper.tlvs",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_padlength,
         { "Padlength", "rsvp.juniper.padlength",
           FT_UINT16, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_type,
         { "Juniper type", "rsvp.juniper.type",
           FT_UINT8, BASE_HEX, VALS(rsvp_juniper_attr_vals), 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_length,
         { "Juniper length", "rsvp.juniper.length",
           FT_UINT8, BASE_DEC, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_cos,
         { "Cos", "rsvp.juniper.attrib.cos",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_metric1,
         { "Metric 1", "rsvp.juniper.attrib.metric1",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_metric2,
         { "Metric 2", "rsvp.juniper.attrib.metric2",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_ccc_status,
         { "CCC Status", "rsvp.juniper.attrib.ccc_status",
           FT_UINT16, BASE_HEX, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_path,
         { "Path type", "rsvp.juniper.attrib.path",
           FT_UINT16, BASE_HEX, VALS(rsvp_juniper_path_attr_vals), 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_attrib_unknown,
         { "Unknown", "rsvp.juniper.attrib.unknown",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_pad,
         { "Pad", "rsvp.juniper.pad",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_juniper_unknown,
         { "Unknown", "rsvp.juniper.unknown",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_unknown_data,
         { "Data", "rsvp.unknown.data",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },

        {&hf_rsvp_loose_hop,
         { "Hop", "rsvp.loose_hop",
           FT_BOOLEAN, 8, TFS(&tfs_loose_strict_hop), 0x80,
           NULL, HFILL }
        },

        { &hf_rsvp_data_length,
         { "Data length", "rsvp.data_length",
           FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_word_not_including_header, 0,
           NULL, HFILL
         }
        },

        { &hf_rsvp_ctype_s2l_sub_lsp,
         { "C-Type", "rsvp.ctype.s2l_sub_lsp",
           FT_UINT32, BASE_DEC, VALS(rsvp_c_type_s2l_sub_lsp_vals), 0,
           NULL, HFILL
         }
        },
        { &hf_rsvp_s2l_sub_lsp_destination_ipv4_address,
         { "IPv4 S2L Sub-LSP destination address", "rsvp.s2l_sub_lsp.destination_ipv4_address",
           FT_IPv4, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },
        { &hf_rsvp_s2l_sub_lsp_destination_ipv6_address,
         { "IPv6 S2L Sub-LSP destination address", "rsvp.s2l_sub_lsp.destination_ipv6_address",
           FT_IPv6, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },
        { &hf_rsvp_s2l_sub_lsp_data,
         { "Data", "rsvp.s2l_sub_lsp.data",
           FT_BYTES, BASE_NONE, NULL, 0,
           NULL, HFILL
         }
        },


      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_rsvp_session_flags, { "Flags", "rsvp.session.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_destination_address, { "Destination address", "rsvp.session.destination_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_protocol, { "Protocol", "rsvp.session.protocol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_destination_port, { "Destination port", "rsvp.session.destination_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_dscp, { "DSCP", "rsvp.session.dscp", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dscp_vals_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_extended_ipv4_address, { "Extended IPv4 Address", "rsvp.session.extended_ipv4_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_p2mp_id, { "P2MP ID", "rsvp.session.p2mp_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_data, { "Data", "rsvp.session.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_length, { "Length", "rsvp.ifid_tlv.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_ipv4_address, { "IPv4 address", "rsvp.ifid_tlv.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_ipv6_address, { "IPv6 address", "rsvp.ifid_tlv.ipv6_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlvinterface_id, { "Interface-ID", "rsvp.ifid_tlv.interface_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_label, { "Label", "rsvp.ifid_tlv.label", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_node_id, { "Node ID", "rsvp.ifid_tlv.node_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_area, { "Area", "rsvp.ifid_tlv.area", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_autonomous_system, { "Autonomous System", "rsvp.ifid_tlv.autonomous_system", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_error_string, { "Error String", "rsvp.ifid_tlv.error_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_data, { "Data", "rsvp.ifid_tlv.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ifid_tlv_padding, { "Padding", "rsvp.ifid_tlv.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_hop, { "C-Type", "rsvp.ctype.hop", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_hop_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_hop_neighbor_address_ipv4, { "Neighbor address", "rsvp.hop.neighbor_address_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hop_logical_interface, { "Logical interface", "rsvp.hop.logical_interface", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hop_neighbor_address_ipv6, { "Neighbor address", "rsvp.neighbor_address_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hop_data, { "Data", "rsvp.hop.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_time_values, { "C-Type", "rsvp.ctype.time_values", FT_UINT32, BASE_DEC,  VALS(rsvp_c_type_time_values_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_time_values_data, { "Data", "rsvp.time_values.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_error, { "C-Type", "rsvp.ctype.error", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_error_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_error_error_node_ipv4, { "Error node", "rsvp.error.error_node_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_error_error_node_ipv6, { "Error node", "rsvp.error.error_node_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_error_data, { "Data", "rsvp.error.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_error_error_code, { "Error code", "rsvp.error.error_code", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &rsvp_error_codes_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_scope, { "C-Type", "rsvp.ctype.scope", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_scope_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_scope_ipv4_address, { "IPv4 Address", "rsvp.scope.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_scope_ipv6_address, { "IPv6 Address", "rsvp.scope.ipv6_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_scope_data, { "Data", "rsvp.scope.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_style, { "C-Type", "rsvp.ctype.style", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_style_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_style_flags, { "Flags", "rsvp.style.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_style_style, { "Style", "rsvp.style.style", FT_UINT24, BASE_HEX, VALS(style_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_style_data, { "Data", "rsvp.style.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_confirm, { "C-Type", "rsvp.ctype.confirm", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_confirm_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_confirm_receiver_address_ipv4, { "Receiver address", "rsvp.confirm.receiver_address_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_confirm_receiver_address_ipv6, { "Receiver address", "rsvp.confirm.receiver_address_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_confirm_data, { "Data", "rsvp.confirm.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_template, { "C-Type", "rsvp.ctype.template", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_template_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_source_address_ipv6, { "Source address", "rsvp.template_filter.source_address_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_source_port, { "Source port", "rsvp.template_filter.source_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_ipv4_tunnel_sender_address, { "IPv4 Tunnel Sender Address", "rsvp.template_filter.ipv4_tunnel_sender_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_ipv6_tunnel_sender_address, { "IPv6 Tunnel Sender Address", "rsvp.template_filter.ipv6_tunnel_sender_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_sub_group_originator_id, { "Sub-Group Originator ID", "rsvp.template_filter.sub_group_originator_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_sub_group_id, { "Sub-Group ID", "rsvp.template_filter.sub_group_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_template_filter_data, { "Data", "rsvp.template_filter.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_length, { "Length", "rsvp.eth_tspec.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_profile, { "Profile", "rsvp.eth_tspec.profile", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_index, { "Index", "rsvp.eth_tspec.index", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_reserved, { "Reserved", "rsvp.eth_tspec.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_el2cp, { "EL2CP", "rsvp.eth_tspec.el2cp", FT_UINT8, BASE_DEC, VALS(el2cp_val_str), 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_il2cp, { "IL2CP", "rsvp.eth_tspec.il2cp", FT_UINT8, BASE_DEC, VALS(il2cp_val_str), 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_cir, { "CIR", "rsvp.eth_tspec.cir", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_cbs, { "CBS", "rsvp.eth_tspec.cbs", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_eir, { "EIR", "rsvp.eth_tspec.eir", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_eth_tspec_ebs, { "EBS", "rsvp.eth_tspec.ebs", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_tspec, { "C-Type", "rsvp.ctype.tspec", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_tspec_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_message_format_version, { "Message format version", "rsvp.tspec.message_format_version", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_tspec_service_header, { "Service header", "rsvp.tspec.service_header", FT_UINT8, BASE_DEC, VALS(qos_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_token_bucket_rate, { "Token bucket rate", "rsvp.tspec.token_bucket_rate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_token_bucket_size, { "Token bucket size", "rsvp.tspec.token_bucket_size", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_peak_data_rate, { "Peak data rate", "rsvp.tspec.peak_data_rate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_hint, { "Hint", "rsvp.tspec.hint", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_compression_factor, { "Compression Factor", "rsvp.tspec.compression_factor", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_signal_type_sonet, { "Signal Type", "rsvp.tspec.signal_type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gmpls_sonet_signal_type_str_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_requested_concatenation, { "Requested Concatenation (RCC)", "rsvp.tspec.requested_concatenation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_number_of_contiguous_components, { "Number of Contiguous Components (NCC)", "rsvp.tspec.number_of_contiguous_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_number_of_virtual_components, { "Number of Virtual Components (NVC)", "rsvp.tspec.number_of_virtual_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_multiplier, { "Multiplier (MT)", "rsvp.tspec.multiplier", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_transparency, { "Transparency (T)", "rsvp.tspec.transparency", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_profile, { "Profile (P)", "rsvp.tspec.profile", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_signal_type_g709, { "Signal Type", "rsvp.tspec.signal_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_g709_signal_type_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_number_of_multiplexed_components, { "Number of Multiplexed Components (NMC)", "rsvp.number_of_multiplexed_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_mtu, { "MTU", "rsvp.tspec.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_tspec_data, { "Data", "rsvp.tspec.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_flowspec, { "C-Type", "rsvp.ctype.flowspec", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_flowspec_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_message_format_version, { "Message format version", "rsvp.flowspec.message_format_version", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_flowspec_service_header, { "Service header", "rsvp.flowspec.service_header", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &intsrv_services_str_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_token_bucket_rate, { "Token bucket rate", "rsvp.flowspec.token_bucket_rate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_token_bucket_size, { "Token bucket size", "rsvp.flowspec.token_bucket_size", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_peak_data_rate, { "Peak data rate", "rsvp.flowspec.peak_data_rate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_rate, { "Rate", "rsvp.flowspec.rate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_slack_term, { "Slack term", "rsvp.flowspec.slack_term", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_signal_type_sonet, { "Signal Type", "rsvp.flowspec.signal_type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gmpls_sonet_signal_type_str_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_requested_concatenation, { "Requested Concatenation (RCC)", "rsvp.flowspec.requested_concatenation", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_number_of_contiguous_components, { "Number of Contiguous Components (NCC)", "rsvp.flowspec.number_of_contiguous_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_number_of_virtual_components, { "Number of Virtual Components (NVC)", "rsvp.flowspec.number_of_virtual_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_multiplier, { "Multiplier (MT)", "rsvp.flowspec.multiplier", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_transparency, { "Transparency (T)", "rsvp.flowspec.transparency", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_profile, { "Profile (P)", "rsvp.flowspec.profile", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_signal_type_g709, { "Signal Type", "rsvp.flowspec.signal_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_g709_signal_type_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_number_of_multiplexed_components, { "Number of Multiplexed Components (NMC)", "rsvp.flowspec.number_of_multiplexed_components", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_mtu, { "MTU", "rsvp.flowspec.mtu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_flowspec_m, { "m", "rsvp.flowspec.m", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_adspec, { "C-Type", "rsvp.ctype.adspec", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_message_format_version, { "Message format version", "rsvp.adspec.message_format_version", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_adspec_service_header, { "Service header", "rsvp.adspec.service_header", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &intsrv_services_str_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_integrity, { "C-Type", "rsvp.ctype.integrity", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_integrity_flags, { "Flags", "rsvp.integrity.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_integrity_key_identifier, { "Key Identifier", "rsvp.integrity.key_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_integrity_sequence_number, { "Sequence Number", "rsvp.integrity.sequence_number", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_integrity_hash, { "Hash", "rsvp.integrity.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_policy, { "C-Type", "rsvp.ctype.policy", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_policy_data, { "Data", "rsvp.policy.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_label_request, { "C-Type", "rsvp.ctype.label_request", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_label_request_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_l3pid, { "L3PID", "rsvp.label_request.l3pid", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_min_vpi, { "Min VPI", "rsvp.label_request.min_vpi", FT_UINT16, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
      { &hf_rsvp_label_request_min_vci, { "Min VCI", "rsvp.label_request.min_vci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_max_vpi, { "Max VPI", "rsvp.label_request.max_vpi", FT_UINT16, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
      { &hf_rsvp_label_request_max_vci, { "Max VCI", "rsvp.label_request.max_vci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_lsp_encoding_type, { "LSP Encoding Type", "rsvp.label_request.lsp_encoding_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_switching_type, { "Switching Type", "rsvp.label_request.switching_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_g_pid, { "G-PID", "rsvp.label_request.g_pid", FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(gmpls_gpid_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_label_request_data, { "Data", "rsvp.label_request.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_label, { "Label", "rsvp.label.label", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_generalized_label, { "Generalized Label", "rsvp.label.generalized_label", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_generalized_label_evpl_vlad_id, { "VLAN ID", "rsvp.label.generalized_label_evpl_vlad_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_data, { "Data", "rsvp.label.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_set_action, { "Action", "rsvp.label_set.action", FT_UINT8, BASE_DEC, VALS(action_type_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_attribute, { "C-Type", "rsvp.ctype.attribute", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_attribute_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_exclude_any, { "Exclude-Any", "rsvp.session_attribute.exclude_any", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_include_any, { "Include-Any", "rsvp.session_attribute.include_any", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_include_all, { "Include-All", "rsvp.session_attribute.include_all", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_setup_priority, { "Setup priority", "rsvp.session_attribute.setup_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_hold_priority, { "Hold priority", "rsvp.session_attribute.hold_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_flags, { "Flags", "rsvp.session_attribute.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_name_length, { "Name length", "rsvp.session_attribute.name_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_name, { "Name", "rsvp.session_attribute.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_session_attribute_data, { "Data", "rsvp.session_attribute.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_length, { "Length", "rsvp.ero_rro_subobjects.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_ipv4_hop, { "IPv4 hop", "rsvp.ero_rro_subobjects.ipv4_hop", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_prefix_length, { "Prefix length", "rsvp.ero_rro_subobjects.prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_flags, { "Flags", "rsvp.ero_rro_subobjects.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_ipv6_hop, { "IPv6 hop", "rsvp.ero_rro_subobjects.ipv6_hop", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_label, { "Label", "rsvp.ero_rro_subobjects.label", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_router_id, { "Router-ID", "rsvp.ero_rro_subobjects.router_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_interface_id, { "Interface-ID", "rsvp.ero_rro_subobjects.interface_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_path_key, { "Path Key", "rsvp.ero_rro_subobjects.path_key", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_pce_id_ipv4, { "PCE-ID", "rsvp.ero_rro_subobjects.pce_id_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_pce_id_ipv6, { "PCE-ID", "rsvp.ero_rro_subobjects.pce_id_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_private_length, { "Length", "rsvp.ero_rro_subobjects.private_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_subobjects_private_data, { "Data", "rsvp.ero_rro_subobjects.private_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_explicit_route, { "C-Type", "rsvp.ctype.explicit_route", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_explicit_route_data, { "Data", "rsvp.explicit_route.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_record_route, { "C-Type", "rsvp.ctype.record_route", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_record_route_data, { "Data", "rsvp.record_route.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_exclude_route, { "C-Type", "rsvp.ctype.exclude_route", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_exclude_route_data, { "Data", "rsvp.exclude_route.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_message_id, { "C-Type", "rsvp.ctype.message_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_flags, { "Flags", "rsvp.message_id.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_epoch, { "Epoch", "rsvp.message_id.epoch", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_message_id, { "Message-ID", "rsvp.message_id.message_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_data, { "Data", "rsvp.message_id.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_message_id_ack, { "C-Type", "rsvp.ctype.message_id_ack", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_ack_flags, { "Flags", "rsvp.message_id_ack.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_ack_epoch, { "Epoch", "rsvp.message_id_ack.epoch", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_ack_message_id, { "Message-ID", "rsvp.message_id_ack.message_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_ack_data, { "Data", "rsvp.message_id_ack.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_message_id_list, { "C-Type", "rsvp.ctype.message_id_list", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_list_flags, { "Flags", "rsvp.message_id_list.flags", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_list_epoch, { "Epoch", "rsvp.message_id_list.epoch", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_list_message_id, { "Message-ID", "rsvp.message_id_list.message_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_id_list_data, { "Data", "rsvp.message_id_list.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_hello, { "C-Type", "rsvp.ctype.hello", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hello_source_instance, { "Source Instance", "rsvp.hello.source_instance", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hello_destination_instance, { "Destination Instance", "rsvp.hello.destination_instance", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_dclass, { "C-Type", "rsvp.ctype.dclass", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_dclass_dscp, { "DSCP", "rsvp.dclass.dscp", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dscp_vals_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_dclass_data, { "Data", "rsvp.dclass.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_admin_status, { "C-Type", "rsvp.ctype.admin_status", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_admin_status_bits, { "Admin Status", "rsvp.admin_status.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_admin_status_data, { "Data", "rsvp.admin_status.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_lsp_attributes, { "C-Type", "rsvp.ctype.lsp_attributes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_attributes_tlv, { "LSP attributes TLV", "rsvp.lsp_attributes_tlv", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_attributes_tlv_data, { "Data", "rsvp.lsp_attributes_tlv.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_association, { "C-Type", "rsvp.ctype.association", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_association_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_association_type, { "Association type", "rsvp.association.type", FT_UINT16, BASE_DEC, VALS(association_type_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_association_id, { "Association ID", "rsvp.association.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_source_ipv4, { "Association source", "rsvp.association.source_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_source_ipv6, { "Association source", "rsvp.association.source_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_routing_area_id, { "Routing Area ID", "rsvp.association.routing_area_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_node_id, { "Node ID", "rsvp.association.node_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_padding, { "Padding", "rsvp.association.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_association_data, { "Data", "rsvp.association.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_tunnel_if_id, { "C-Type", "rsvp.ctype.tunnel_if_id", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_tunnel_if_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_length, { "Length", "rsvp.lsp_tunnel_if_id.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_component_link_identifier, { "Component link identifier", "rsvp.lsp_tunnel_if_id.component_link_identifier", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_component_link_identifier_ipv4, { "Component link identifier", "rsvp.lsp_tunnel_if_id.component_link_identifier_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_lsp_encoding_type, { "LSP Encoding Type", "rsvp.lsp_tunnel_if_id.lsp_encoding_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_lsp_enc_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_switching_type, { "Switching Type", "rsvp.lsp_tunnel_if_id.switching_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(gmpls_switching_type_rvals), 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_signal_type, { "Signal Type", "rsvp.lsp_tunnel_if_id.signal_type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gmpls_sonet_signal_type_str_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_connection_id, { "Sub Interface/Connection ID", "rsvp.lsp_tunnel_if_id.connection_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_sc_pc_id, { "SC PC ID", "rsvp.lsp_tunnel_if_id.sc_pc_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_sc_pc_scn_address, { "SC PC SCN Address", "rsvp.lsp_tunnel_if_id.sc_pc_scn_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_router_id, { "Router ID", "rsvp.lsp_tunnel_if_id.router_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_interface_id, { "Interface ID", "rsvp.lsp_tunnel_if_id.interface_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_ipv4_interface_address, { "IPv4 interface address", "rsvp.lsp_tunnel_if_id.ipv4_interface_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_target_igp_instance, { "Target IGP instance", "rsvp.lsp_tunnel_if_id.target_igp_instance", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_action, { "Action", "rsvp.lsp_tunnel_if_id.action", FT_UINT8, BASE_DEC, VALS(lsp_tunnel_if_id_action_str), 0xF0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_ipv6_interface_address, { "IPv6 interface address", "rsvp.lsp_tunnel_if_id.ipv6_interface_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_lsp_tunnel_if_id_data, { "Data", "rsvp.lsp_tunnel_if_id.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_notify_request_notify_node_address_ipv4, { "Notify node address", "rsvp.notify_request.notify_node_address_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_notify_request_notify_node_address_ipv6, { "Notify node address", "rsvp.notify_request.notify_node_address_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_notify_request_data, { "Data", "rsvp.notify_request.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ctype_call_id, { "C-Type", "rsvp.ctype.call_id", FT_UINT32, BASE_DEC, VALS(rsvp_c_type_call_id_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_data, { "Data", "rsvp.call_id.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_address_type, { "Address type", "rsvp.call_id.address_type", FT_UINT8, BASE_DEC, VALS(address_type_vals), 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_reserved, { "Reserved", "rsvp.call_id.reserved", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_international_segment, { "International Segment", "rsvp.call_id.international_segment", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_national_segment, { "National Segment", "rsvp.call_id.national_segment", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_call_id_local_identifier, { "Local Identifier", "rsvp.call_id.local_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_restart_cap_data, { "Data", "rsvp.restart_cap.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_protection_info_link_flags, { "Link Flags", "rsvp.protection_info.link_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_protection_info_data, { "Data", "rsvp.protection_info.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_setup_priority, { "Setup Priority", "rsvp.fast_reroute.setup_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_hold_priority, { "Hold Priority", "rsvp.fast_reroute.hold_priority", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_hop_limit, { "Hop Limit", "rsvp.fast_reroute.hop_limit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_flags, { "Flags", "rsvp.fast_reroute.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_bandwidth, { "Bandwidth", "rsvp.fast_reroute.bandwidth", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_include_any, { "Include-Any", "rsvp.fast_reroute.include_any", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_exclude_any, { "Exclude-Any", "rsvp.fast_reroute.exclude_any", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_include_all, { "Include-All", "rsvp.fast_reroute.include_all", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_fast_reroute_data, { "Data", "rsvp.fast_reroute.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_detour_data, { "Data", "rsvp.detour.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_diffserv_data, { "Data", "rsvp.diffserv.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_diffserv_aware_te_data, { "Data", "rsvp.diffserv_aware_te.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_version, { "RSVP Version", "rsvp.version", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_flags, { "Flags", "rsvp.flags", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},
      { &hf_rsvp_sending_ttl, { "Sending TTL", "rsvp.sending_ttl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_length, { "Message length", "rsvp.message_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_length, { "Length", "rsvp.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_extended_tunnel_id, { "Extended Tunnel ID", "rsvp.extended_tunnel_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_extended_tunnel_ipv6, { "Extended Tunnel ID", "rsvp.extended_tunnel_id_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_extended_tunnel, { "Extended Tunnel ID", "rsvp.extended_tunnel", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_refresh_interval, { "Refresh interval", "rsvp.refresh_interval", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_minimum_policed_unit, { "Minimum policed unit [m]", "rsvp.minimum_policed_unit", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_maximum_packet_size, { "Maximum packet size [M]", "rsvp.maximum_packet_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_hf_rsvp_adspec_break_bit, { "Break bit", "rsvp.adspec.break_bit", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
      { &hf_rsvp_label_request_m, { "M (Merge in Data Plane)", "rsvp.label_request.m", FT_BOOLEAN, 8, TFS(&tfs_can_cannot), 0x80, NULL, HFILL }},
      { &hf_rsvp_dlci_length, { "DLCI Length", "rsvp.label_request.dlci_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_min_dlci, { "Min DLCI", "rsvp.label_request.min_dlci", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_max_dlci, { "Max DLCI", "rsvp.label_request.max_dlci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ero_rro_autonomous_system, { "Autonomous System", "rsvp.ero_rro_subobjects.autonomous_system", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_nsap_length, { "NSAP Length", "rsvp.nsap_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_gen_uni_data, { "Data", "rsvp.gen_uni.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_gen_uni_logical_port_id, { "Logical Port ID", "rsvp.gen_uni.logical_port_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_gen_uni_service_level, { "Service Level", "rsvp.gen_uni.service_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_restart_cap_restart_time, { "Restart Time", "rsvp.restart_cap.restart_time", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL }},
      { &hf_rsvp_restart_cap_recovery_time, { "Recovery Time", "rsvp.restart_cap.recovery_time", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL }},
      { &hf_rsvp_detour_plr_id, { "PLR ID", "rsvp.detour.plr_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_detour_avoid_node_id, { "Avoid Node ID", "rsvp.detour.avoid_node_id", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_message_checksum, { "Message Checksum", "rsvp.message_checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_call_attributes_endpont_id, { "Endpoint ID", "rsvp.call_attributes.endpoint_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_isis_area_id, { "IS-IS Area Identifier", "rsvp.isis_area_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_type, { "Adspec Type", "rsvp.adspec.type", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &adspec_params_ext, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_len, { "Length", "rsvp.adspec.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_uint, { "Adspec uint", "rsvp.adspec.uint", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_float, { "Adspec float", "rsvp.adspec.float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_adspec_bytes, { "Adspec bytes", "rsvp.adspec.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_wavelength_freq, { "Freq", "rsvp.wavelength.freq", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_wavelength_grid, { "Grid", "rsvp.wavelength.grid", FT_UINT8, BASE_DEC, VALS(lambda_grid_vals), 0xE0, NULL, HFILL }},
      { &hf_rsvp_wavelength_cs1, { "Channel Spacing", "rsvp.wavelength.cs1", FT_UINT8, BASE_DEC, VALS(grid1_cs_vals), 0x1E, NULL, HFILL }},
      { &hf_rsvp_wavelength_cs2, { "Channel Spacing", "rsvp.wavelength.cs2", FT_UINT8, BASE_DEC, VALS(grid2_cs_vals), 0x1E, NULL, HFILL }},
      { &hf_rsvp_wavelength_cs3, { "Channel Spacing", "rsvp.wavelength.cs3", FT_UINT8, BASE_DEC, VALS(grid3_cs_vals), 0x1E, NULL, HFILL }},
      { &hf_rsvp_wavelength_channel_spacing, { "Channel Spacing", "rsvp.wavelength.channel_spacing", FT_UINT8, BASE_DEC, NULL, 0x1E, NULL, HFILL }},
      { &hf_rsvp_wavelength_n, { "Central Frequency", "rsvp.wavelength.n", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_wavelength_m, { "Channel Width (m)", "rsvp.wavelength.m", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_wavelength_wavelength, { "Wavelength", "rsvp.wavelength.wavelength", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_nanometers, 0x0, NULL, HFILL }},
      { &hf_rsvp_sonet_s, { "S", "rsvp.sonet.s", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_sonet_u, { "U", "rsvp.sonet.u", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_sonet_k, { "K", "rsvp.sonet.k", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_rsvp_sonet_l, { "L", "rsvp.sonet.l", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_rsvp_sonet_m, { "M", "rsvp.sonet.m", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_rsvp_g709_t3, { "t3", "rsvp.g709.t3", FT_UINT16, BASE_DEC, NULL, 0x03F0, NULL, HFILL }},
      { &hf_rsvp_g709_t2, { "t2", "rsvp.g709.t2", FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL }},
      { &hf_rsvp_g709_t1, { "t1", "rsvp.g709.t1", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_rsvp_ctype_label_set, { "C-Type", "rsvp.ctype.label_set", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_set_type, { "Label type", "rsvp.label_set.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_label_set_subchannel, { "Subchannel", "rsvp.label_set.subchannel", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_nsap_address, { "NSAP address", "rsvp.nsap_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_class_diversity, { "Diversity", "rsvp.class_diversity", FT_UINT8, BASE_DEC, VALS(ouni_guni_diversity_str), 0xF0, NULL, HFILL }},
      { &hf_rsvp_egress_label_type, { "Label type", "rsvp.egress.label_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_egress_label, { "Label", "rsvp.egress.label", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_source_transport_network_addr, { "Source Transport Network addr", "rsvp.source_transport_network_addr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_ie_data, { "IE Data", "rsvp.ie_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_3gpp_obj_pf_dst_port_range, { "Destination Port range", "rsvp.3gpp_obj.pf_dst_port_range", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_rsvp_3gpp_obj_pf_src_port_range, { "Source Port range", "rsvp.3gpp_obj.pf_src_port_range", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_rsvp_invalid_length, { "rsvp.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_rsvp_packet_filter_component, { "rsvp.packet_filter_component", PI_UNDECODED, PI_WARN, "Not dissected Packet filter component", EXPFILL }},
        { &ei_rsvp_bundle_component_msg, { "rsvp.bundle_component_msg", PI_UNDECODED, PI_WARN, "Bundle Component Messages Not Dissected", EXPFILL }},
        { &ei_rsvp_parameter, { "rsvp.parameter.unknown", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
        { &ei_rsvp_adspec_type, { "rsvp.adspec.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
        { &ei_rsvp_call_id_address_type, { "rsvp.call_id.address_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Transport Network type", EXPFILL }},
        { &ei_rsvp_session_type, { "rsvp.session_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown session type", EXPFILL }},
    };

    expert_module_t* expert_rsvp;

    gint *ett_tree[TT_MAX];

    /* Build the tree array */
    for (i=0; i<TT_MAX; i++) {
        ett_treelist[i] = -1;
        ett_tree[i] = &(ett_treelist[i]);
    }
    proto_rsvp = proto_register_protocol("Resource ReserVation Protocol (RSVP)", "RSVP", "rsvp");
    /* Created to remove Decode As confusion */
    proto_rsvp_e2e1 = proto_register_protocol_in_name_only("Resource ReserVation Protocol (RSVP-E2EI)", "RSVP-E2EI", "rsvp-e2ei", proto_rsvp, FT_PROTOCOL);

    proto_register_field_array(proto_rsvp, rsvpf_info, array_length(rsvpf_info));
    proto_register_subtree_array(ett_tree, array_length(ett_tree));
    expert_rsvp = expert_register_protocol(proto_rsvp);
    expert_register_field_array(expert_rsvp, ei, array_length(ei));
    register_rsvp_prefs();

    rsvp_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), rsvp_hash, rsvp_equal);

    register_conversation_table(proto_rsvp, TRUE, rsvp_conversation_packet, rsvp_endpoint_packet);
}

void
proto_reg_handoff_rsvp(void)
{
    dissector_handle_t rsvp_handle, rsvpe2ei_handle;

    rsvp_handle = create_dissector_handle(dissect_rsvp, proto_rsvp);
    rsvpe2ei_handle = create_dissector_handle(dissect_rsvp_e2ei, proto_rsvp_e2e1);
    dissector_add_uint("ip.proto", IP_PROTO_RSVP, rsvp_handle);
    dissector_add_uint("ip.proto", IP_PROTO_RSVPE2EI, rsvpe2ei_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_PRSVP, rsvp_handle);
    rsvp_tap = register_tap("rsvp");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

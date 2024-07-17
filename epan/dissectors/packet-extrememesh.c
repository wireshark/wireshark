/* packet-extrememesh.c
 * Routines for Motorola Mesh ethernet header disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>

typedef enum _MeshNextProtocol
{
	MESH_NEXT_PROTOCOL_INVALID                      = -1,

	MESH_NEXT_PROTOCOL_MESH                         = 0,    // Extension
	MESH_NEXT_PROTOCOL_MCH                          = 1,    // Extension
	MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH             = 2,    // Terminating
	MESH_NEXT_PROTOCOL_PS                           = 3,    // Terminating
	MESH_NEXT_PROTOCOL_HELLO                        = 4,    // Terminating
	MESH_NEXT_PROTOCOL_LOCATION                     = 5,    // Terminating
	MESH_NEXT_PROTOCOL_SECURITY                     = 6,    // Terminating
	MESH_NEXT_PROTOCOL_SECURED_PAYLOAD              = 7,    // Extension
	MESH_NEXT_PROTOCOL_TEST                         = 8,    // Terminating
	MESH_NEXT_PROTOCOL_FRAGMENT                     = 9,    // Terminating
	MESH_NEXT_PROTOCOL_CFPU                         = 10,   // Terminating
	MESH_NEXT_PROTOCOL_EAPOM                        = 11,   // Terminating
	MESH_NEXT_PROTOCOL_NULL                         = 12,   // Terminating
	MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR     = 13,   // Terminating
	MESH_NEXT_PROTOCOL_L2_UPDATE                    = 14,   // Terminating
	MESH_NEXT_PROTOCOL_PROBE_MESSAGE                = 15,   // Terminating

	MESH_NEXT_PROTOCOL_EOL
} MeshNextProtocol;

typedef enum _MeshPathSelectionFrameType
{
	MESH_PS_FRAME_INVALID = -1,

	MESH_PS_FRAME_AREQ    =  1,    // Authorization Request
	MESH_PS_FRAME_AREP    =  2,    // Authorization Reply
	MESH_PS_FRAME_BREQ    =  3,    // Bind Request
	MESH_PS_FRAME_BREP    =  4,    // Bind Reply
	MESH_PS_FRAME_BANN    =  5,    // Bind Announcement
	MESH_PS_FRAME_BRED    =  6,    // Bind Removed
	MESH_PS_FRAME_SREQ    =  7,    // Status Request
	MESH_PS_FRAME_SREP    =  8,    // Status Reply
	MESH_PS_FRAME_PREQ    =  9,    // Path Request
	MESH_PS_FRAME_PREP    =  10,   // Path Reply
	MESH_PS_FRAME_PERR    =  11,   // Path Error
	MESH_PS_FRAME_PRST    =  12,   // Path Reset
	MESH_PS_FRAME_PREM    =  13,   // Proxy Remove
	MESH_PS_FRAME_TRACE   =  14,   // Trace Path
	MESH_PS_FRAME_PRER    =  15,   // Proxy Error

	MESH_PS_FRAME_EOL
} MeshPathSelectionFrameType;

void proto_register_extrememesh(void);
void proto_reg_handoff_extrememesh(void);

static dissector_handle_t extrememesh_handle;

/* Mesh pkt types */
static int proto_extrememesh;
static int proto_extrememesh_mch;
static int proto_extrememesh_ps_areq;
static int proto_extrememesh_ps_arep;
static int proto_extrememesh_ps_breq;
static int proto_extrememesh_ps_brep;
static int proto_extrememesh_ps_bann;
static int proto_extrememesh_ps_bred;
static int proto_extrememesh_ps_sreq;
static int proto_extrememesh_ps_srep;
static int proto_extrememesh_ps_preq;
static int proto_extrememesh_ps_prep;
static int proto_extrememesh_ps_perr;
static int proto_extrememesh_ps_prst;
static int proto_extrememesh_ps_prem;
static int proto_extrememesh_ps_trace;
static int proto_extrememesh_ps_prer;
//static int proto_extrememesh_hello;
//static int proto_extrememesh_security;
//static int proto_extrememesh_cfpu;
//static int proto_extrememesh_eapom;
static int proto_extrememesh_l2upd;
static int proto_extrememesh_probe;


/*MESH fields*/
static int hf_extrememesh_version;
static int hf_extrememesh_nextproto;

/*MCH fields*/
static int hf_extrememesh_mch_version;
static int hf_extrememesh_mch_next_proto;
static int hf_extrememesh_mch_lq;
static int hf_extrememesh_mch_htl;
static int hf_extrememesh_mch_priority;
static int hf_extrememesh_mch_usr_pri_flags;
static int hf_extrememesh_mch_usr_pri_flags_user_priority;
static int hf_extrememesh_mch_usr_pri_flags_reserved;
static int hf_extrememesh_mch_usr_pri_flags_from_wan;
static int hf_extrememesh_mch_usr_pri_flags_to_wan;
static int hf_extrememesh_mch_usr_pri_flags_forward;
static int hf_extrememesh_mch_sequence;
static int hf_extrememesh_mch_dest;
static int hf_extrememesh_mch_src;

#if 0
/*ENCAP_ETH fields*/
/*Hello fields*/
static int hf_extrememesh_hello_services;
static int hf_extrememesh_hello_HTR;
static int hf_extrememesh_hello_MTR;
static int hf_extrememesh_hello_root_id;
static int hf_extrememesh_hello_next_hop_id;

/*Security fields*/
static int hf_extrememesh_security_version;
static int hf_extrememesh_security_nextproto;
static int hf_extrememesh_security_flags;
static int hf_extrememesh_security_packet_num;
static int hf_extrememesh_security_mic;

/*Cfpu fields*/
static int hf_extrememesh_cfpu_version;
static int hf_extrememesh_cfpu_window;
static int hf_extrememesh_cfpu_cycle;

/*EAPOM fields*/
static int hf_extrememesh_eapom_version;
static int hf_extrememesh_eapom_header_type;
static int hf_extrememesh_eapom_supplicant_addr;
static int hf_extrememesh_eapom_meshid_len;
static int hf_extrememesh_eapom_meshid;
static int hf_extrememesh_eapom_body_len;
#endif

/*Mesh L2 Update fields*/
static int hf_extrememesh_l2upd_proxy_owner;
static int hf_extrememesh_l2upd_ballast;

/*Probe fields*/
static int hf_extrememesh_probe_version;
static int hf_extrememesh_probe_op_code;
static int hf_extrememesh_probe_flags;
static int hf_extrememesh_probe_flags_reserved;
static int hf_extrememesh_probe_flags_reply;
static int hf_extrememesh_probe_priority;
static int hf_extrememesh_probe_job_id;
static int hf_extrememesh_probe_sequence;
static int hf_extrememesh_probe_ballast_len;
static int hf_extrememesh_probe_ballast;

/*Path Selection fields*/
/*PS AREQ fields*/
static int hf_extrememesh_ps_areq_version;
static int hf_extrememesh_ps_areq_frame_type;
static int hf_extrememesh_ps_areq_mpr_addr;
static int hf_extrememesh_ps_areq_orig_addr;
static int hf_extrememesh_ps_areq_opt_tot_len;
static int hf_extrememesh_ps_areq_option;
static int hf_extrememesh_ps_areq_option_len;
static int hf_extrememesh_ps_areq_old_mpr;
static int hf_extrememesh_ps_areq_proxies;

/*PS AREP fields*/
static int hf_extrememesh_ps_arep_version;
static int hf_extrememesh_ps_arep_frame_type;
static int hf_extrememesh_ps_arep_mpr_addr;
static int hf_extrememesh_ps_arep_orig_addr;
static int hf_extrememesh_ps_arep_opt_tot_len;
static int hf_extrememesh_ps_arep_option;
static int hf_extrememesh_ps_arep_option_len;
static int hf_extrememesh_ps_arep_result;
static int hf_extrememesh_ps_arep_timeout;

/*PS BREQ fields*/
static int hf_extrememesh_ps_breq_version;
static int hf_extrememesh_ps_breq_frame_type;
static int hf_extrememesh_ps_breq_mpr_addr;
static int hf_extrememesh_ps_breq_orig_addr;
static int hf_extrememesh_ps_breq_opt_tot_len;
static int hf_extrememesh_ps_breq_option;
static int hf_extrememesh_ps_breq_option_len;
static int hf_extrememesh_ps_breq_proxy_addr;
static int hf_extrememesh_ps_breq_old_mpr;
static int hf_extrememesh_ps_breq_orig_pri;
static int hf_extrememesh_ps_breq_proxy_pri;
static int hf_extrememesh_ps_breq_vlan_id;
static int hf_extrememesh_ps_breq_proxy_vlan_id;
static int hf_extrememesh_ps_breq_seq;

/*PS BREP fields*/
static int hf_extrememesh_ps_brep_version;
static int hf_extrememesh_ps_brep_frame_type;
static int hf_extrememesh_ps_brep_mpr_addr;
static int hf_extrememesh_ps_brep_orig_addr;
static int hf_extrememesh_ps_brep_opt_tot_len;
static int hf_extrememesh_ps_brep_option;
static int hf_extrememesh_ps_brep_option_len;
static int hf_extrememesh_ps_brep_seq;

/*PS BANN fields*/
static int hf_extrememesh_ps_bann_version;
static int hf_extrememesh_ps_bann_frame_type;
static int hf_extrememesh_ps_bann_mpr_addr;
static int hf_extrememesh_ps_bann_orig_addr;
static int hf_extrememesh_ps_bann_opt_tot_len;
static int hf_extrememesh_ps_bann_option;
static int hf_extrememesh_ps_bann_option_len;
static int hf_extrememesh_ps_bann_proxy_addr;
static int hf_extrememesh_ps_bann_old_root;
static int hf_extrememesh_ps_bann_vlan_id;
static int hf_extrememesh_ps_bann_seq;

/*PS BRED fields*/
static int hf_extrememesh_ps_bred_version;
static int hf_extrememesh_ps_bred_frame_type;
static int hf_extrememesh_ps_bred_mpr_addr;
static int hf_extrememesh_ps_bred_orig_addr;
static int hf_extrememesh_ps_bred_opt_tot_len;
static int hf_extrememesh_ps_bred_option;
static int hf_extrememesh_ps_bred_option_len;
static int hf_extrememesh_ps_bred_seq;

/*PS SREQ fields*/
static int hf_extrememesh_ps_sreq_version;
static int hf_extrememesh_ps_sreq_frame_type;
static int hf_extrememesh_ps_sreq_reserved;
static int hf_extrememesh_ps_sreq_orig_addr;
static int hf_extrememesh_ps_sreq_term_addr;
static int hf_extrememesh_ps_sreq_opt_tot_len;
static int hf_extrememesh_ps_sreq_option;
static int hf_extrememesh_ps_sreq_option_len;
static int hf_extrememesh_ps_sreq_vlan_id;

/*PS SREP fields*/
static int hf_extrememesh_ps_srep_version;
static int hf_extrememesh_ps_srep_frame_type;
static int hf_extrememesh_ps_srep_flags;
static int hf_extrememesh_ps_srep_flags_reserved;
static int hf_extrememesh_ps_srep_flags_status;
static int hf_extrememesh_ps_srep_hop_count;
static int hf_extrememesh_ps_srep_orig_addr;
static int hf_extrememesh_ps_srep_dest_addr;
static int hf_extrememesh_ps_srep_term_addr;
static int hf_extrememesh_ps_srep_opt_tot_len;
static int hf_extrememesh_ps_srep_option;
static int hf_extrememesh_ps_srep_option_len;
static int hf_extrememesh_ps_srep_vlan_id;

/*PS PREQ fields*/
static int hf_extrememesh_ps_preq_version;
static int hf_extrememesh_ps_preq_frame_type;
static int hf_extrememesh_ps_preq_flags;
static int hf_extrememesh_ps_preq_flags_broadcast;
static int hf_extrememesh_ps_preq_flags_periodic;
static int hf_extrememesh_ps_preq_flags_state;
static int hf_extrememesh_ps_preq_flags_reserved;
static int hf_extrememesh_ps_preq_flags_gratuitous;
static int hf_extrememesh_ps_preq_flags_destination;
static int hf_extrememesh_ps_preq_flags_unknown;
static int hf_extrememesh_ps_preq_hop_count;
static int hf_extrememesh_ps_preq_ttl;
static int hf_extrememesh_ps_preq_path_metrics;
static int hf_extrememesh_ps_preq_services;
static int hf_extrememesh_ps_preq_services_reserved;
static int hf_extrememesh_ps_preq_services_mobile;
static int hf_extrememesh_ps_preq_services_path_pref;
static int hf_extrememesh_ps_preq_services_geo;
static int hf_extrememesh_ps_preq_services_proxy;
static int hf_extrememesh_ps_preq_services_root;
static int hf_extrememesh_ps_preq_reserved;
static int hf_extrememesh_ps_preq_id;
static int hf_extrememesh_ps_preq_term_addr;
static int hf_extrememesh_ps_preq_dest_addr;
static int hf_extrememesh_ps_preq_dest_seq;
static int hf_extrememesh_ps_preq_orig_addr;
static int hf_extrememesh_ps_preq_orig_seq;
static int hf_extrememesh_ps_preq_opt_tot_len;
static int hf_extrememesh_ps_preq_option;
static int hf_extrememesh_ps_preq_option_len;
static int hf_extrememesh_ps_preq_mcast_sub;
static int hf_extrememesh_ps_preq_vlan_id;
static int hf_extrememesh_ps_preq_mint_id;

/*PS PREP fields*/
static int hf_extrememesh_ps_prep_version;
static int hf_extrememesh_ps_prep_frame_type;
static int hf_extrememesh_ps_prep_flags;
static int hf_extrememesh_ps_prep_flags_reserved;
static int hf_extrememesh_ps_prep_flags_new_route;
static int hf_extrememesh_ps_prep_flags_repair;
static int hf_extrememesh_ps_prep_flags_ack;
static int hf_extrememesh_ps_prep_hop_count;
static int hf_extrememesh_ps_prep_path_metrics;
static int hf_extrememesh_ps_prep_services;
static int hf_extrememesh_ps_prep_services_reserved;
static int hf_extrememesh_ps_prep_services_mobile;
static int hf_extrememesh_ps_prep_services_path_pref;
static int hf_extrememesh_ps_prep_services_geo;
static int hf_extrememesh_ps_prep_services_proxy;
static int hf_extrememesh_ps_prep_services_root;
static int hf_extrememesh_ps_prep_reserved;
static int hf_extrememesh_ps_prep_term_addr;
static int hf_extrememesh_ps_prep_dest_addr;
static int hf_extrememesh_ps_prep_dest_seq;
static int hf_extrememesh_ps_prep_orig_addr;
static int hf_extrememesh_ps_prep_orig_seq;
static int hf_extrememesh_ps_prep_lifetime;
static int hf_extrememesh_ps_prep_opt_tot_len;
static int hf_extrememesh_ps_prep_option;
static int hf_extrememesh_ps_prep_option_len;
static int hf_extrememesh_ps_prep_mcast_sub;
static int hf_extrememesh_ps_prep_vlan_id;
static int hf_extrememesh_ps_prep_mint_id;

/*PS PERR fields*/
static int hf_extrememesh_ps_perr_version;
static int hf_extrememesh_ps_perr_frame_type;
static int hf_extrememesh_ps_perr_flags;
static int hf_extrememesh_ps_perr_flags_reserved;
static int hf_extrememesh_ps_perr_flags_warning;
static int hf_extrememesh_ps_perr_flags_no_delete;
static int hf_extrememesh_ps_perr_dest_count;
static int hf_extrememesh_ps_perr_unrch_dest;
static int hf_extrememesh_ps_perr_unrch_dest_seq;

/*PS PRST fields*/
static int hf_extrememesh_ps_prst_version;
static int hf_extrememesh_ps_prst_frame_type;
static int hf_extrememesh_ps_prst_hops_to_live;
static int hf_extrememesh_ps_prst_reserved;
static int hf_extrememesh_ps_prst_id;
static int hf_extrememesh_ps_prst_orig_addr;
static int hf_extrememesh_ps_prst_dest_addr;

/*PS PREM fields*/
static int hf_extrememesh_ps_prem_version;
static int hf_extrememesh_ps_prem_frame_type;
static int hf_extrememesh_ps_prem_mpr_addr;
static int hf_extrememesh_ps_prem_orig_addr;
static int hf_extrememesh_ps_prem_opt_tot_len;
static int hf_extrememesh_ps_prem_option;
static int hf_extrememesh_ps_prem_option_len;
static int hf_extrememesh_ps_prem_proxy_addr;
static int hf_extrememesh_ps_prem_proxy_vlan_id;

/*PS TRACE fields*/
static int hf_extrememesh_ps_trace_version;
static int hf_extrememesh_ps_trace_frame_type;
static int hf_extrememesh_ps_trace_flags;
static int hf_extrememesh_ps_trace_flags_reserved;
static int hf_extrememesh_ps_trace_flags_reply;
static int hf_extrememesh_ps_trace_flags_no_path;
static int hf_extrememesh_ps_trace_dest_addr;
static int hf_extrememesh_ps_trace_orig_addr;
static int hf_extrememesh_ps_trace_hop_count;
static int hf_extrememesh_ps_trace_addl_path;

/*PS PRER fields*/
static int hf_extrememesh_ps_prer_version;
static int hf_extrememesh_ps_prer_frame_type;
static int hf_extrememesh_ps_prer_dest_count;
static int hf_extrememesh_ps_prer_reserved;
static int hf_extrememesh_ps_prer_orig_addr;
static int hf_extrememesh_ps_prer_dest_addr;
static int hf_extrememesh_ps_prer_unrch_addr;
static int hf_extrememesh_ps_prer_opt_tot_len;
static int hf_extrememesh_ps_prer_option;
static int hf_extrememesh_ps_prer_option_len;
static int hf_extrememesh_ps_prer_vlan_id;

/*ETT for above fields...*/
static int ett_extrememesh;

/*MCH fields*/
static int ett_extrememesh_mch;

/*Hello fields*/
static int ett_extrememesh_hello;

/*Security fields*/
static int ett_extrememesh_security;

/*Cfpu fields*/
static int ett_extrememesh_cfpu;

/*EAPOM fields*/
static int ett_extrememesh_eapom;

/*PS fields*/
static int ett_extrememesh_ps;

/*Ethernet without FCS Dissector handle*/
static dissector_handle_t eth_withoutfcs_handle;

static const value_string mot_mesh_packet_types[] = {
	{0, "Mesh"},
	{1, "MCH"},
	{2, "Encapsulated Ethernet"},
	{3, "PS"},
	{4, "Hello"},
	{5, "Loc"},
	{6, "Sec"},
	{7, "MSH"},
	{8, "Test"},
	{9, "Frag"},
	{10,"CFPU"},
	{11,"EAPOM"},
	{12,"NULL"},
	{13,"Encapsulated Ethernet, no address"},
	{14,"L2Up"},
	{15,"Probe"},
	{0, NULL}
};

static const value_string mot_ps_packet_types[] = {
	{0, "(Invalid)"},
	{1, "AREQ" },
	{2, "AREP" },
	{3, "BREQ" },
	{4, "BREP" },
	{5, "BANN" },
	{6, "BRED" },
	{7, "SREQ" },
	{8, "SREP" },
	{9, "PREQ" },
	{10,"PREP" },
	{11,"PERR" },
	{12,"PRST" },
	{13,"PREM" },
	{14,"TRACE"},
	{15,"PRER" },
	{0, NULL}
};

static const value_string mot_ps_auth_replies[] = {
	{0, "Authorization Rejected"},
	{1, "Authorization Granted"},
	{2, "Authorization Pending"},
	{0, NULL}
};

static void dissect_extrememesh_ps_arep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Authorization Reply");
	proto_tree_add_item(tree, proto_extrememesh_ps_arep, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_arep_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_arep_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_arep_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_arep_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_arep_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_arep_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if (option == 0) continue;
		proto_tree_add_item(tree, hf_extrememesh_ps_arep_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option)
		{
		case 4:
			proto_tree_add_item(tree, hf_extrememesh_ps_arep_result, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 6:
			proto_tree_add_item(tree, hf_extrememesh_ps_arep_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		default:
			/*proto_tree_add_subtree_format(tree, tvb, offset, -1, */
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported authorization reply option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Request

Description:

Dissects the path selection bind request.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_breq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;
	uint8_t option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Request");
	proto_tree_add_item(tree, proto_extrememesh_ps_breq, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_breq_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_breq_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_breq_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_breq_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_breq_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_breq_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if (option == 0) continue;
		proto_tree_add_item(tree, hf_extrememesh_ps_breq_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		option_len = tvb_get_uint8(tvb, offset);
		offset++;
		switch(option)
		{
		case 1:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_breq_proxy_addr, tvb, offset, 6, ENC_NA);
				option_len-=6;
				offset+=6;
				if (option_len < 6) break;
			}
			break;
		case 2:
			proto_tree_add_item(tree, hf_extrememesh_ps_breq_old_mpr, tvb, offset, 6, ENC_NA);
			offset+=6;
			break;
		case 5:
			break;
		case 7:
			proto_tree_add_item(tree, hf_extrememesh_ps_breq_orig_pri, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 8:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_breq_proxy_pri, tvb, offset, 1, ENC_BIG_ENDIAN);
				option_len--;
				offset++;
			}
			break;
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_breq_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 11:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_breq_proxy_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
				option_len-=2;
				offset+=2;
				if (option_len < 2) break;
			}
			break;
		case 12:
			proto_tree_add_item(tree, hf_extrememesh_ps_breq_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported bind request option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Reply

Description:

Dissects the path selection bind reply.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_brep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Reply");
	proto_tree_add_item(tree, proto_extrememesh_ps_brep, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_brep_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_brep_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_brep_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_brep_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_brep_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_brep_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if (option == 0) continue;
		switch(option)
		{
		case 12:
			proto_tree_add_item(tree, hf_extrememesh_ps_brep_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_extrememesh_ps_brep_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported bind reply option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Announcement

Description:

Dissects the path selection bind announcement (BANN) packet.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_bann(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;
	uint8_t option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Announcement");
	proto_tree_add_item(tree, proto_extrememesh_ps_bann, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_bann_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_bann_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_bann_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_bann_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_bann_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_bann_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		option_len = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_extrememesh_ps_bann_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option)
		{
		case 1:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_bann_proxy_addr, tvb, offset, 6, ENC_NA);
				option_len-=6;
				offset+=6;
				if (option_len < 6) break;
			}
			break;
		case 2:
			proto_tree_add_item(tree, hf_extrememesh_ps_bann_old_root, tvb, offset, 6, ENC_NA);
			offset+=6;
			break;
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_bann_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 12:
			proto_tree_add_item(tree, hf_extrememesh_ps_bann_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported bind announcement option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Bind Removed

Description:

Dissects the path selection bind removed packet.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_bred(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Bind Removed");
	proto_tree_add_item(tree, proto_extrememesh_ps_bred, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_bred_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_bred_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_bred_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_bred_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_bred_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_bred_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		proto_tree_add_item(tree, hf_extrememesh_ps_bred_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option)
		{
		case 12:
			proto_tree_add_item(tree, hf_extrememesh_ps_bred_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported bind removed option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Status Request

Description:

Dissects the path selection status request.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_sreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Status Request");
	proto_tree_add_item(tree, proto_extrememesh_ps_sreq, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_term_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_sreq_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_sreq_option, tvb, offset, 2, ENC_BIG_ENDIAN, &option);
		offset+=2;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		proto_tree_add_item(tree, hf_extrememesh_ps_sreq_option_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		switch(option)
		{
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_sreq_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported status request option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Status Reply

Description:

Dissects the path selection status reply.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_srep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Status Reply");
	proto_tree_add_item(tree, proto_extrememesh_ps_srep, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_flags_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_hop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_dest_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_term_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_srep_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_srep_option, tvb, offset, 2, ENC_BIG_ENDIAN, &option);
		offset+=2;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		proto_tree_add_item(tree, hf_extrememesh_ps_srep_option_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		switch(option)
		{
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_srep_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported status reply option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Request

Description:

Dissects the path selection path request.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_preq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;
	uint16_t option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Request");
	proto_tree_add_item(tree, proto_extrememesh_ps_preq, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_broadcast, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_periodic, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_state, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_gratuitous, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_destination, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_flags_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_hop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_ttl, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_path_metrics, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_mobile, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_path_pref, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_geo, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_proxy, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_services_root, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_term_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_dest_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_dest_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_orig_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_preq_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_preq_option, tvb, offset, 2, ENC_BIG_ENDIAN, &option);
		offset+=2;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		option_len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extrememesh_ps_preq_option_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		switch(option)
		{
		case 1:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_preq_mcast_sub, tvb, offset, 6, ENC_NA);
				option_len-=6;
				offset+=6;
				if (option_len < 6) break;
			}
			break;
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_preq_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 14:
			proto_tree_add_item(tree, hf_extrememesh_ps_preq_mint_id, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported path request option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Reply

Description:

Dissects the path selection path reply.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_prep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;
	uint16_t option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Reply");
	proto_tree_add_item(tree, proto_extrememesh_ps_prep, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_flags_new_route, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_flags_repair, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_flags_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_hop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_path_metrics, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_mobile, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_path_pref, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_geo, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_proxy, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_services_root, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_term_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_dest_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_dest_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_orig_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_prep_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_prep_option, tvb, offset, 2, ENC_BIG_ENDIAN, &option);
		offset+=2;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		option_len = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tree, hf_extrememesh_ps_prep_option_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		switch(option)
		{
		case 1:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_prep_mcast_sub, tvb, offset, 6, ENC_NA);
				option_len-=6;
				offset+=6;
				if (option_len < 6) break;
			}
			break;
		case 10:
			proto_tree_add_item(tree, hf_extrememesh_ps_prep_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 14:
			proto_tree_add_item(tree, hf_extrememesh_ps_prep_mint_id, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported path reply option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Error

Description:

Dissects the path selection path error (PERR) packet.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_perr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint8_t dst_cnt = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Error");
	dst_cnt = tvb_get_uint8(tvb, 3);
	proto_tree_add_item(tree, proto_extrememesh_ps_perr, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_flags_warning, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_flags_no_delete, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_perr_dest_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	while (dst_cnt-- > 0)
	{
		proto_tree_add_item(tree, hf_extrememesh_ps_perr_unrch_dest, tvb, offset, 6, ENC_NA);
		offset+=6;
		proto_tree_add_item(tree, hf_extrememesh_ps_perr_unrch_dest_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Path Reset

Description:

Dissects the path selection path reset (PRST).

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_prst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Path Reset");
	proto_tree_add_item(tree, proto_extrememesh_ps_prst, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_hops_to_live, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prst_dest_addr, tvb, offset, 6, ENC_NA);
}

/*****************************************************************************/
/*

Dissect Path Selection Proxy Remove

Description:

Dissects the path selection proxy remove (PREM) packet.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_prem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;
	uint8_t option_len = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Proxy Remove");
	proto_tree_add_item(tree, proto_extrememesh_ps_prem, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_prem_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prem_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prem_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prem_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prem_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_prem_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		option_len = tvb_get_int8(tvb, offset);
		proto_tree_add_item(tree, hf_extrememesh_ps_prem_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option)
		{
		case 1:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_prem_proxy_addr, tvb, offset, 6, ENC_NA);
				option_len-=6;
				offset+=6;
				if (option_len < 6) break;
			}
			break;
		case 11:
			while(option_len > 0)
			{
				proto_tree_add_item(tree, hf_extrememesh_ps_prem_proxy_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
				option_len-=2;
				offset+=2;
				if (option_len < 2) break;
			}
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported proxy remove option (%d)", option);*/
			return;
		}
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Trace Path

Description:

Dissects the path selection trace path (TRACE) packet.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint8_t hop_cnt = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Trace Path");
	hop_cnt = tvb_get_uint8(tvb, 15);
	proto_tree_add_item(tree, proto_extrememesh_ps_trace, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_flags_reply, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_flags_no_path, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_dest_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_trace_hop_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	while(hop_cnt-- > 0)
	{
		proto_tree_add_item(tree, hf_extrememesh_ps_trace_addl_path, tvb, offset, 6, ENC_NA);
		offset+=6;
	}
}

/*****************************************************************************/
/*

Dissect Path Selection Proxy Error

Description:

Dissects the path selection proxy error.

*/
/*****************************************************************************/
static void dissect_extrememesh_ps_prer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Proxy Error");
	proto_tree_add_item(tree, proto_extrememesh_ps_prer, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_dest_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_dest_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_unrch_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_prer_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_prer_option, tvb, offset, 2, ENC_BIG_ENDIAN, &option);
		offset+=2;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		proto_tree_add_item(tree, hf_extrememesh_ps_prer_option_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		switch(option)
		{
		case 11:
			proto_tree_add_item(tree, hf_extrememesh_ps_prer_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"Unsupported status reply option (%d)", option);*/
			return;
		}
	}
}

static void dissect_extrememesh_ps_areq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t offset = 0;
	uint32_t option = 0;

	/*if((pinfo != NULL) && check_col(pinfo->cinfo,COL_INFO))*/
	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Path Selection Authorization Request");
	proto_tree_add_item(tree, proto_extrememesh_ps_areq, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_ps_areq_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_areq_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_ps_areq_mpr_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_areq_orig_addr, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_ps_areq_opt_tot_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	while(tvb_captured_length(tvb) > offset)
	{
		proto_tree_add_item_ret_uint(tree, hf_extrememesh_ps_areq_option, tvb, offset, 1, ENC_BIG_ENDIAN, &option);
		offset++;
		if(option == 0) continue; // Option 0 is a single padding byte, no length byte
		proto_tree_add_item(tree, hf_extrememesh_ps_areq_option_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch(option)
		{
		case 2:
			proto_tree_add_item(tree, hf_extrememesh_ps_areq_old_mpr, tvb, offset, 6, ENC_NA);
			offset+=6;
			break;
		case 3:
			proto_tree_add_item(tree, hf_extrememesh_ps_areq_proxies, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		default:
			return;
		}
	}
}

static int dissect_extrememesh_ps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int frame_type_offset = 1;
	int frame_type = MESH_PS_FRAME_INVALID;

	frame_type = tvb_get_uint8(tvb, frame_type_offset);
	switch(frame_type)
	{
	case MESH_PS_FRAME_AREQ:
		dissect_extrememesh_ps_areq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_AREP:
		dissect_extrememesh_ps_arep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BREQ:
		dissect_extrememesh_ps_breq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BREP:
		dissect_extrememesh_ps_brep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BANN:
		dissect_extrememesh_ps_bann(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_BRED:
		dissect_extrememesh_ps_bred(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_SREQ:
		dissect_extrememesh_ps_sreq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_SREP:
		dissect_extrememesh_ps_srep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREQ:
		dissect_extrememesh_ps_preq(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREP:
		dissect_extrememesh_ps_prep(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PERR:
		dissect_extrememesh_ps_perr(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PRST:
		dissect_extrememesh_ps_prst(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PREM:
		dissect_extrememesh_ps_prem(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_TRACE:
		dissect_extrememesh_ps_trace(tvb, pinfo, tree);
		break;
	case MESH_PS_FRAME_PRER:
		dissect_extrememesh_ps_prer(tvb, pinfo, tree);
		break;
	default:
		/*proto_tree_add_text(tree, tvb, 0, -1, */
		/*"Undefined path selection frame type (%d)", frame_type);*/
		break;
	}
	return MESH_NEXT_PROTOCOL_INVALID;
}

static int dissect_extrememesh_eth_noaddr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *nextTvb;
	unsigned char *ethBuffer;
	int bufferLen;
	//These are encapsulated ethernet frames that have had their
	//src and dest stripped off

	//Copy in the src/dst
	if (pinfo->src.data && pinfo->dst.data) {
		//Get the length of the current buffer
		unsigned tvbLen = tvb_captured_length(tvb);
		//Add space for the src/dst
		bufferLen = tvbLen + pinfo->src.len + pinfo->dst.len;
		//Allocate a new ethernet buffer
		ethBuffer = (unsigned char*)wmem_alloc(pinfo->pool, bufferLen);

		memcpy(ethBuffer, pinfo->dst.data, pinfo->dst.len);
		memcpy(ethBuffer + pinfo->dst.len, pinfo->src.data, pinfo->src.len);

		//Copy in the rest of the packet
		tvb_memcpy(tvb, ethBuffer, pinfo->src.len + pinfo->dst.len, tvbLen);
		nextTvb = tvb_new_real_data(ethBuffer, bufferLen, bufferLen);
		tvb_set_child_real_data_tvbuff(tvb, nextTvb);
		add_new_data_source(pinfo, nextTvb, "Encapsulated Ethernet, no addr");

		if (eth_withoutfcs_handle)
		{
			call_dissector(eth_withoutfcs_handle, nextTvb, pinfo, tree);
		}
	}

	//This is a terminal type
	return MESH_NEXT_PROTOCOL_INVALID;
}

static int dissect_extrememesh_l2upd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh L2 Update");
	proto_tree_add_item(tree, proto_extrememesh_l2upd, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_l2upd_proxy_owner, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(tree, hf_extrememesh_l2upd_ballast, tvb, offset, tvb_captured_length(tvb)-6, ENC_NA);

	return MESH_NEXT_PROTOCOL_INVALID;
}

static int dissect_extrememesh_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	uint16_t ballast_len;

	col_set_str(pinfo->cinfo, COL_INFO, "Extreme Mesh Probe Message");
	ballast_len = tvb_get_ntohs(tvb, 10);
	proto_tree_add_item(tree, proto_extrememesh_probe, tvb, offset, 12+ballast_len, ENC_NA);
	proto_tree_add_item(tree, hf_extrememesh_probe_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_probe_op_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_probe_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_probe_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_extrememesh_probe_flags_reply, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_probe_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(tree, hf_extrememesh_probe_job_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_extrememesh_probe_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(tree, hf_extrememesh_probe_ballast_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(tree, hf_extrememesh_probe_ballast, tvb, offset, ballast_len, ENC_NA);

	return MESH_NEXT_PROTOCOL_INVALID;
}

// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_extrememesh_mch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *meshTree = tree;
	int offset = 0;
	int next_proto;
	tvbuff_t *nextTvb;

	proto_tree_add_item(meshTree, proto_extrememesh_mch, tvb, offset, -1, ENC_NA);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	next_proto = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_next_proto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_lq, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_htl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags_user_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags_from_wan, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags_to_wan, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(meshTree, hf_extrememesh_mch_usr_pri_flags_forward, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_sequence, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_dest, tvb, offset, 6, ENC_NA);
	offset+=6;
	proto_tree_add_item(meshTree, hf_extrememesh_mch_src, tvb, offset, 6, ENC_NA);
	offset+=6;

	nextTvb = tvb_new_subset_length(tvb, offset, -1);

	while(next_proto != (int)MESH_NEXT_PROTOCOL_INVALID)
	{
		switch(next_proto)
		{
		case MESH_NEXT_PROTOCOL_NULL: // Obsolete
		case MESH_NEXT_PROTOCOL_TEST: // Multi-service Enterprise Access (MEA)
									  // Platform only
		case MESH_NEXT_PROTOCOL_FRAGMENT: // MEA only
		case MESH_NEXT_PROTOCOL_LOCATION: // MEA only
		case MESH_NEXT_PROTOCOL_INVALID:
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_MESH:
			// Should never encounter this inside of a MESH packet
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_MCH:
			// We recurse here, but we'll run out of packet before we run out of stack.
			next_proto = dissect_extrememesh_mch(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH:
			if (eth_withoutfcs_handle)
			{
				call_dissector(eth_withoutfcs_handle, nextTvb, pinfo, meshTree);
			}
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		case MESH_NEXT_PROTOCOL_PS:
			next_proto = dissect_extrememesh_ps(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_HELLO:
		case MESH_NEXT_PROTOCOL_SECURITY: // MEA only
		case MESH_NEXT_PROTOCOL_SECURED_PAYLOAD: // MEA only
		case MESH_NEXT_PROTOCOL_CFPU: // Quattro only
		case MESH_NEXT_PROTOCOL_EAPOM:
		case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR:
			next_proto = dissect_extrememesh_eth_noaddr(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_L2_UPDATE:
			next_proto = dissect_extrememesh_l2upd(nextTvb, pinfo, meshTree);
			break;
		case MESH_NEXT_PROTOCOL_PROBE_MESSAGE:
			next_proto = dissect_extrememesh_probe(nextTvb, pinfo, meshTree);
			break;
		default:
			/*proto_tree_add_text(tree, tvb, offset, -1, */
			/*"dissect_extrememesh_mch: Unsupported protocol (%d)", next_proto);*/
			next_proto = MESH_NEXT_PROTOCOL_INVALID;
			break;
		}
	}
	return next_proto;
}

static int dissect_extrememesh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	/*uint8_t packet_type = 0;*/
	tvbuff_t *next_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCX");
	proto_item *ti = NULL;
	proto_tree *meshTree = NULL;
	int next_proto = MESH_NEXT_PROTOCOL_INVALID;

	ti = proto_tree_add_item(tree, proto_extrememesh, tvb, offset, -1, ENC_NA);
	meshTree = proto_item_add_subtree(ti, ett_extrememesh);
	proto_tree_add_item(meshTree, hf_extrememesh_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	next_proto = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(meshTree, hf_extrememesh_nextproto, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	next_tvb = tvb_new_subset_length(tvb, offset, -1);

	while(next_proto != (int)MESH_NEXT_PROTOCOL_INVALID)
	{
		switch(next_proto)
		{
			case MESH_NEXT_PROTOCOL_NULL: // Obsolete
			case MESH_NEXT_PROTOCOL_TEST: // Multi-service Enterprise Access
									  // (MEA) Platform only
			case MESH_NEXT_PROTOCOL_FRAGMENT: // MEA only
			case MESH_NEXT_PROTOCOL_LOCATION: // MEA only
			case MESH_NEXT_PROTOCOL_INVALID:
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_MESH:
				// Should never encounter this inside of a MESH packet
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_MCH:
				next_proto = dissect_extrememesh_mch(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH:
				if (eth_withoutfcs_handle)
				{
					call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, meshTree);
				}
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			case MESH_NEXT_PROTOCOL_PS:
				next_proto = dissect_extrememesh_ps(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_HELLO:
			case MESH_NEXT_PROTOCOL_SECURITY: // MEA only
			case MESH_NEXT_PROTOCOL_SECURED_PAYLOAD: // MEA only
			case MESH_NEXT_PROTOCOL_CFPU: // Quattro only
			case MESH_NEXT_PROTOCOL_EAPOM:
			case MESH_NEXT_PROTOCOL_ENCAPSULATED_ETH_NO_ADDR:
				next_proto = dissect_extrememesh_eth_noaddr(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_L2_UPDATE:
				next_proto = dissect_extrememesh_l2upd(next_tvb, pinfo, meshTree);
				break;
			case MESH_NEXT_PROTOCOL_PROBE_MESSAGE:
				next_proto = dissect_extrememesh_probe(next_tvb, pinfo, meshTree);
				break;
			default:
				next_proto = MESH_NEXT_PROTOCOL_INVALID;
				break;
			}
		}
		return 0;
}

void proto_register_extrememesh(void)
{
	/*register the fields for the various structs*/
	/* extrememesh mesh */
	static hf_register_info hf_extrememesh[] = {
	{ &hf_extrememesh_version, {
		"Version", "extrememesh.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_nextproto, {
		"Next protocol", "extrememesh.nextproto", FT_UINT8, BASE_DEC,
		VALS(mot_mesh_packet_types), 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh control header */
	static hf_register_info hf_extrememesh_mch[] = {
	{ &hf_extrememesh_mch_version, {
		"Version", "extrememesh.mch.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_next_proto, {
		"Next protocol", "extrememesh.mch.nextproto", FT_UINT8, BASE_DEC,
		VALS(mot_mesh_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_lq, {
		"Link Quality Metric", "extrememesh.mch.lq", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_htl, {
		"Hop To Live counter", "extrememesh.mch.htl", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_priority, {
		"Packet Priority", "extrememesh.mch.priority", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags, {
		"Priority/Flags", "extrememesh.mch.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags_user_priority, {
		"User Priority", "extrememesh.mch.flags.user_priority", FT_UINT8, BASE_DEC,
		NULL, 0xF0, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags_reserved, {
		"Reserved", "extrememesh.mch.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0x08, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags_from_wan, {
		"From WAN", "extrememesh.mch.flags.from_wan", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags_to_wan, {
		"To WAN", "extrememesh.mch.flags.to_wan", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_mch_usr_pri_flags_forward, {
		"Forward Flag", "extrememesh.mch.flags.forward", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_mch_sequence, {
		"Sequence", "extrememesh.mch.sequence", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_dest, {
		"Dst", "extrememesh.mch.dst", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_mch_src, {
		"Src", "extrememesh.mch.src", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

#if 0
	/* extrememesh hello */
	static hf_register_info hf_extrememesh_hello[] = {
	{ &hf_extrememesh_hello_services, {
		"Services", "extrememesh.hello.services", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_hello_HTR, {
		"Hops to root", "extrememesh.hello.hr", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_hello_MTR, {
		"Metric to root", "extrememesh.hello.mtr", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_hello_root_id, {
		"Root", "extrememesh.hello.rootid", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_hello_next_hop_id, {
		"Next Hop", "extrememesh.hello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extrememesh security */
	static hf_register_info hf_extrememesh_security[] = {
	{ &hf_extrememesh_security_version, {
		"Version", "extrememesh.security.version", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_security_nextproto, {
		"Next proto", "extrememesh.security.nextproto", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_security_flags, {
		"Flags", "extrememesh.security.flags", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_security_packet_num, {
		"Packet Number", "extrememesh.security.pktnum", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_security_mic, {
		"MIC", "extrememesh.security.mic", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extrememesh contention free period (CFP) update */
	static hf_register_info hf_extrememesh_cfpu[] = {
	{ &hf_extrememesh_cfpu_version, {
		"Version", "extrememesh.cfpu.version", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_cfpu_window, {
		"Window", "extrememesh.cfpu.window", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_cfpu_cycle, {
		"Cycle", "extrememesh.cfpu.cycle", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};

	/* extrememesh EAP over mesh */
	static hf_register_info hf_extrememesh_eapom[] = {
	{ &hf_extrememesh_eapom_version, {
		"Services", "extrememesh.hello.services", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_eapom_header_type, {
		"Hops to root", "extrememesh.hello.hr", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_eapom_supplicant_addr, {
		"Metric to root", "extrememesh.hello.mtr", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_eapom_meshid_len, {
		"Root", "extrememesh.hello.rootid", FT_UINT32, BASE_DEC,
		NULL, 0x10000000, "Drop", HFILL }},
	{ &hf_extrememesh_eapom_meshid, {
		"Next Hop", "extrememesh.hello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }},
	{ &hf_extrememesh_eapom_body_len, {
		"Next Hop", "extrememesh.hello.nhid", FT_UINT32, BASE_DEC,
		NULL, 0xE0000000, NULL, HFILL }}
	};
#endif

	/* extrememesh mesh path selection authorization request */
	static hf_register_info hf_extrememesh_ps_areq[] = {
	{ &hf_extrememesh_ps_areq_version, {
		"Version", "extrememesh.ps.areq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_frame_type, {
		"Frame Type", "extrememesh.ps.areq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_mpr_addr, {
		"MPR Addr", "extrememesh.ps.areq.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_orig_addr, {
		"Orig Addr", "extrememesh.ps.areq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.areq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_option, {
		"Option", "extrememesh.ps.areq.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_option_len, {
		"Length", "extrememesh.ps.areq.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_old_mpr, {
		"Old MPR Addr", "extrememesh.ps.areq.old_mpr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_areq_proxies, {
		"Number of Proxies", "extrememesh.ps.areq.proxies", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection authorization reply */
	static hf_register_info hf_extrememesh_ps_arep[] = {
	{ &hf_extrememesh_ps_arep_version, {
		"Version", "extrememesh.ps.arep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_frame_type, {
		"Frame Type", "extrememesh.ps.arep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_mpr_addr, {
		"MPR Addr", "extrememesh.ps.arep.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_orig_addr, {
		"Orig Addr", "extrememesh.ps.arep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.arep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_option, {
		"Option", "extrememesh.ps.arep.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_option_len, {
		"Length", "extrememesh.ps.arep.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_result, {
		"Result", "extrememesh.ps.arep.result", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_auth_replies), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_arep_timeout, {
		"Timeout", "extrememesh.ps.arep.timeout", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection bind request */
	static hf_register_info hf_extrememesh_ps_breq[] = {
	{ &hf_extrememesh_ps_breq_version, {
		"Version", "extrememesh.ps.breq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_frame_type, {
		"Frame Type", "extrememesh.ps.breq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_mpr_addr, {
		"MPR Addr", "extrememesh.ps.breq.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_orig_addr, {
		"Orig Addr", "extrememesh.ps.breq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.breq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_option, {
		"Option", "extrememesh.ps.breq.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_option_len, {
		"Length", "extrememesh.ps.breq.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_proxy_addr, {
		"Proxy Address", "extrememesh.ps.breq.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_old_mpr, {
		"Old MPR Addr", "extrememesh.ps.breq.old_mpr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_orig_pri, {
		"Orig Priority", "extrememesh.ps.breq.orig_pri", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_proxy_pri, {
		"Proxy Priority", "extrememesh.ps.breq.proxy_pri", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_vlan_id, {
		"VLAN ID", "extrememesh.ps.breq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_proxy_vlan_id, {
		"Proxy VLAN ID", "extrememesh.ps.breq.proxy_vlan_id", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_breq_seq, {
		"Sequence", "extrememesh.ps.breq.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection bind reply */
	static hf_register_info hf_extrememesh_ps_brep[] = {
	{ &hf_extrememesh_ps_brep_version, {
		"Version", "extrememesh.ps.brep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_frame_type, {
		"Frame Type", "extrememesh.ps.brep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_mpr_addr, {
		"MPR Addr", "extrememesh.ps.brep.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_orig_addr, {
		"Orig Addr", "extrememesh.ps.brep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.brep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_option, {
		"Option", "extrememesh.ps.brep.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_option_len, {
		"Length", "extrememesh.ps.brep.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_brep_seq, {
		"Sequence", "extrememesh.ps.brep.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection bind announcement */
	static hf_register_info hf_extrememesh_ps_bann[] = {
	{ &hf_extrememesh_ps_bann_version, {
		"Version", "extrememesh.ps.bann.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_frame_type, {
		"Frame Type", "extrememesh.ps.bann.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_mpr_addr, {
		"MPR Addr", "extrememesh.ps.bann.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_orig_addr, {
		"Orig Addr", "extrememesh.ps.bann.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.bann.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_option, {
		"Option", "extrememesh.ps.bann.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_option_len, {
		"Length", "extrememesh.ps.bann.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_proxy_addr, {
		"Proxy Addr", "extrememesh.ps.bann.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_old_root, {
		"Old Root", "extrememesh.ps.bann.old_root", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_vlan_id, {
		"Old Root Addr", "extrememesh.ps.bann.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bann_seq, {
		"Sequence", "extrememesh.ps.bann.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection bind removed */
	static hf_register_info hf_extrememesh_ps_bred[] = {
	{ &hf_extrememesh_ps_bred_version, {
		"Version", "extrememesh.ps.bred.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_frame_type, {
		"Frame Type", "extrememesh.ps.bred.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_mpr_addr, {
		"MPR Addr", "extrememesh.ps.bred.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_orig_addr, {
		"Orig Addr", "extrememesh.ps.bred.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.bred.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_option, {
		"Option", "extrememesh.ps.bred.option", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_option_len, {
		"Length", "extrememesh.ps.bred.option_len", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_bred_seq, {
		"Sequence", "extrememesh.ps.bred.seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection status request */
	static hf_register_info hf_extrememesh_ps_sreq[] = {
	{ &hf_extrememesh_ps_sreq_version, {
		"Version", "extrememesh.ps.sreq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_frame_type, {
		"Frame Type", "extrememesh.ps.sreq.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_reserved, {
		"Reserved", "extrememesh.ps.sreq.reserved", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_orig_addr, {
		"Orig Addr", "extrememesh.ps.sreq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_term_addr, {
		"Term", "extrememesh.ps.sreq.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.sreq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_option, {
		"Option", "extrememesh.ps.sreq.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_option_len, {
		"Length", "extrememesh.ps.sreq.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_sreq_vlan_id, {
		"VLAN ID", "extrememesh.ps.sreq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection status reply */
	static hf_register_info hf_extrememesh_ps_srep[] = {
	{ &hf_extrememesh_ps_srep_version, {
		"Version", "extrememesh.ps.srep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_frame_type, {
		"Frame Type", "extrememesh.ps.srep.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_flags, {
		"Flags", "extrememesh.ps.srep.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_flags_reserved, {
		"Reserved", "extrememesh.ps.srep.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFE, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_flags_status, {
		"Status Bit", "extrememesh.ps.srep.flags.status", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_hop_count, {
		"Hop Count", "extrememesh.ps.srep.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_orig_addr, {
		"Orig Addr", "extrememesh.ps.srep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_dest_addr, {
		"Dest Addr", "extrememesh.ps.srep.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_term_addr, {
		"Term Addr", "extrememesh.ps.srep.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.srep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_option, {
		"Option", "extrememesh.ps.srep.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_option_len, {
		"Length", "extrememesh.ps.srep.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_srep_vlan_id, {
		"VLAN ID", "extrememesh.ps.srep.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection path request */
	static hf_register_info hf_extrememesh_ps_preq[] = {
	{ &hf_extrememesh_ps_preq_version, {
		"Version", "extrememesh.ps.preq.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_frame_type, {
		"Frame Type", "extrememesh.ps.preq.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags, {
		"Flags", "extrememesh.ps.preq.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_broadcast, {
		"Broadcast", "extrememesh.ps.preq.flags.broadcast", FT_UINT8, BASE_DEC,
		NULL, 0x80, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_periodic, {
		"Periodic", "extrememesh.ps.preq.flags.periodic", FT_UINT8, BASE_DEC,
		NULL, 0x40, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_state, {
		"State of the source node", "extrememesh.ps.preq.flags.state", FT_UINT8,
		BASE_DEC, NULL, 0x20, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_reserved, {
		"Reserved", "extrememesh.ps.preq.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0x18, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_gratuitous, {
                "Gratuitous PREP Flag", "extrememesh.ps.preq.flags.gratuitous",
		FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_destination, {
		"Destination only flag", "extrememesh.ps.preq.flags.destination",
		FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_flags_unknown, {
		"Unknown sequence number", "extrememesh.ps.preq.flags.unknown", FT_UINT8,
		BASE_DEC, NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_hop_count, {
		"Hop Count", "extrememesh.ps.preq.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_ttl, {
		"TTL", "extrememesh.ps.preq.ttl", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_path_metrics, {
		"Path Metrics", "extrememesh.ps.preq.metrics", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services, {
		"Services", "extrememesh.ps.preq.services", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_reserved, {
		"Reserved", "extrememesh.ps.preq.services.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xC0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_mobile, {
		"Mobile", "extrememesh.ps.preq.services.mobile", FT_UINT8, BASE_DEC,
		NULL, 0x20, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_path_pref, {
		"Path Preference", "extrememesh.ps.preq.services.path_pref", FT_UINT8,
		BASE_DEC, NULL, 0x18, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_geo, {
		"Geo", "extrememesh.ps.preq.services.geo", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_proxy, {
		"Proxy", "extrememesh.ps.preq.services.proxy", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_services_root, {
		"Root", "extrememesh.ps.preq.services.root", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_reserved, {
		"Reserved", "extrememesh.ps.preq.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_id, {
		"PREQ ID", "extrememesh.ps.preq.id", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_term_addr, {
		"Term Addr", "extrememesh.ps.preq.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_dest_addr, {
		"Dest Addr", "extrememesh.ps.preq.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_dest_seq, {
		"Dest Seq", "extrememesh.ps.preq.dest_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_orig_addr, {
		"Orig Addr", "extrememesh.ps.preq.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_orig_seq, {
		"Orig Seq", "extrememesh.ps.preq.orig_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.preq.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_option, {
		"Option", "extrememesh.ps.preq.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_option_len, {
		"Length", "extrememesh.ps.preq.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_mcast_sub, {
		"MCAST Sub", "extrememesh.ps.preq.mcast_sub", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_vlan_id, {
		"VLAN ID", "extrememesh.ps.preq.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_preq_mint_id, {
		"Mint ID", "extrememesh.ps.preq.mint_id", FT_UINT32, BASE_HEX,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection path reply */
	static hf_register_info hf_extrememesh_ps_prep[] = {
	{ &hf_extrememesh_ps_prep_version, {
		"Version", "extrememesh.ps.prep.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_frame_type, {
		"Frame Type", "extrememesh.ps.prep.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_flags, {
		"Flags", "extrememesh.ps.prep.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_flags_reserved, {
		"Reserved", "extrememesh.ps.prep.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xF8, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_flags_new_route, {
		"New Route", "extrememesh.ps.prep.flags.new_route", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_flags_repair, {
		"Repair Flag", "extrememesh.ps.prep.flags.repair", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_flags_ack, {
		"Acknowledgement Required", "extrememesh.ps.prep.flags.ack", FT_UINT8,
		BASE_DEC, NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_hop_count, {
		"Hop Count", "extrememesh.ps.prep.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_path_metrics, {
		"Path Metrics", "extrememesh.ps.prep.metrics", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services, {
		"Services", "extrememesh.ps.prep.services", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_reserved, {
		"Reserved", "extrememesh.ps.prep.services.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xC0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_mobile, {
		"Mobile", "extrememesh.ps.prep.services.mobile", FT_UINT8, BASE_DEC,
		NULL, 0x20, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_path_pref, {
		"Path Preference", "extrememesh.ps.prep.services.path_pref", FT_UINT8,
		BASE_DEC, NULL, 0x18, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_geo, {
		"Geo", "extrememesh.ps.prep.services.geo", FT_UINT8, BASE_DEC,
		NULL, 0x04, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_proxy, {
		"Proxy", "extrememesh.ps.prep.services.proxy", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_services_root, {
		"Root", "extrememesh.ps.prep.services.root", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_reserved, {
		"Reserved", "extrememesh.ps.prep.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_term_addr, {
		"Term Addr", "extrememesh.ps.prep.term_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_dest_addr, {
		"Dest Addr", "extrememesh.ps.prep.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_dest_seq, {
		"Dest Seq", "extrememesh.ps.prep.dest_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_orig_addr, {
		"Orig Addr", "extrememesh.ps.prep.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_orig_seq, {
		"Orig Seq", "extrememesh.ps.prep.orig_seq", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_lifetime, {
		"Lifetime", "extrememesh.ps.prep.lifetime", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.prep.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_option, {
		"Option", "extrememesh.ps.prep.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_option_len, {
		"Length", "extrememesh.ps.prep.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_mcast_sub, {
		"MCAST Sub", "extrememesh.ps.prep.mcast_sub", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_vlan_id, {
		"VLAN ID", "extrememesh.ps.prep.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prep_mint_id, {
		"Mint ID", "extrememesh.ps.prep.mint_id", FT_UINT32, BASE_HEX,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection path error */
	static hf_register_info hf_extrememesh_ps_perr[] = {
	{ &hf_extrememesh_ps_perr_version, {
		"Version", "extrememesh.ps.perr.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_frame_type, {
		"Frame Type", "extrememesh.ps.perr.type", FT_UINT8, BASE_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_flags, {
		"Flags", "extrememesh.ps.perr.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_flags_reserved, {
		"Reserved", "extrememesh.ps.perr.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFC, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_flags_warning, {
		"Warning", "extrememesh.ps.perr.flags.warning", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_flags_no_delete, {
		"No Delete", "extrememesh.ps.perr.flags.no_delete", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_dest_count, {
		"Dest Count", "extrememesh.ps.perr.dest_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_unrch_dest, {
		"Unrch Dest", "extrememesh.ps.perr.unrch_dest", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_perr_unrch_dest_seq, {
		"Unrch Dest Seq", "extrememesh.ps.perr.unrch_dest_seq", FT_UINT32,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	};

	/* extrememesh mesh path selection path reset */
	static hf_register_info hf_extrememesh_ps_prst[] = {
	{ &hf_extrememesh_ps_prst_version, {
		"Version", "extrememesh.ps.prst.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_frame_type, {
		"Frame Type", "extrememesh.ps.prst.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_hops_to_live, {
		"Hops To Live", "extrememesh.ps.prst.hops_to_live", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_reserved, {
		"Reserved", "extrememesh.ps.prst.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_id, {
		"PRST ID", "extrememesh.ps.prst.id", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_orig_addr, {
		"Orig Addr", "extrememesh.ps.prst.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prst_dest_addr, {
		"Dest Addr", "extrememesh.ps.prst.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	};

	/* extrememesh mesh path selection proxy remove */
	static hf_register_info hf_extrememesh_ps_prem[] = {
	{ &hf_extrememesh_ps_prem_version, {
		"Version", "extrememesh.ps.prem.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_frame_type, {
		"Frame Type", "extrememesh.ps.prem.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_mpr_addr, {
		"MPR Addr", "extrememesh.ps.prem.mpr_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_orig_addr, {
		"Orig Addr", "extrememesh.ps.prem.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.prem.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_option, {
		"Option", "extrememesh.ps.prem.option", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_option_len, {
		"Length", "extrememesh.ps.prem.option_len", FT_UINT8,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_proxy_addr, {
		"Proxy Addr", "extrememesh.ps.prem.proxy_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prem_proxy_vlan_id, {
		"VLAN ID", "extrememesh.ps.prem.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh path selection trace path */
	static hf_register_info hf_extrememesh_ps_trace[] = {
	{ &hf_extrememesh_ps_trace_version, {
		"Version", "extrememesh.ps.trace.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_frame_type, {
		"Frame Type", "extrememesh.ps.trace.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_flags, {
		"Flags", "extrememesh.ps.trace.flags", FT_UINT8, BASE_HEX,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_flags_reserved, {
		"Reserved", "extrememesh.ps.trace.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFC, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_flags_reply, {
		"Reply Flag", "extrememesh.ps.trace.flags.reply", FT_UINT8, BASE_DEC,
		NULL, 0x02, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_flags_no_path, {
		"No Path Flag", "extrememesh.ps.trace.flags.no_path", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_dest_addr, {
		"Dest Addr", "extrememesh.ps.trace.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_orig_addr, {
		"Orig Addr", "extrememesh.ps.trace.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_hop_count, {
		"Hop Count", "extrememesh.ps.trace.hop_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_trace_addl_path, {
		"Addl Path", "extrememesh.ps.trace.addl_path", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	};

	/* extrememesh mesh path selection proxy error */
	static hf_register_info hf_extrememesh_ps_prer[] = {
	{ &hf_extrememesh_ps_prer_version, {
		"Version", "extrememesh.ps.prer.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_frame_type, {
		"Frame Type", "extrememesh.ps.prer.type", FT_UINT8, BASE_HEX_DEC,
		VALS(mot_ps_packet_types), 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_dest_count, {
		"Dest Count", "extrememesh.ps.prer.dest_count", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_reserved, {
		"Reserved", "extrememesh.ps.prer.reserved", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_orig_addr, {
		"Orig Addr", "extrememesh.ps.prer.orig_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_dest_addr, {
		"Dest Addr", "extrememesh.ps.prer.dest_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_unrch_addr, {
		"Unrch Proxy", "extrememesh.ps.prer.unrch_addr", FT_ETHER, BASE_NONE,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_opt_tot_len, {
		"Options Total Length", "extrememesh.ps.prer.opt_tot_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_option, {
		"Option", "extrememesh.ps.prer.option", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_option_len, {
		"Length", "extrememesh.ps.prer.option_len", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_ps_prer_vlan_id, {
		"VLAN ID", "extrememesh.ps.prer.vlan_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh L2 update */
	static hf_register_info hf_extrememesh_l2upd[] = {
	{ &hf_extrememesh_l2upd_proxy_owner, {
		"Proxy Owner Addr", "extrememesh.l2upd.proxy_owner", FT_ETHER,
		BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_l2upd_ballast, {
		"Ballast", "extrememesh.l2upd.ballast", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	/* extrememesh mesh probe message */
	static hf_register_info hf_extrememesh_probe[] = {
	{ &hf_extrememesh_probe_version, {
		"Version", "extrememesh.probe.version", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_op_code, {
		"Op-code", "extrememesh.probe.op_code", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_flags, {
		"Flags", "extrememesh.probe.flags", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_flags_reserved, {
		"Reserved", "extrememesh.probe.flags.reserved", FT_UINT8, BASE_DEC,
		NULL, 0xFE, NULL, HFILL }},
   { &hf_extrememesh_probe_flags_reply, {
		"Reply", "extrememesh.probe.flags.reply", FT_UINT8, BASE_DEC,
		NULL, 0x01, NULL, HFILL }},
	{ &hf_extrememesh_probe_priority, {
		"Priority", "extrememesh.probe.priority", FT_UINT8, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_job_id, {
		"Job ID", "extrememesh.probe.job_id", FT_UINT16, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_sequence, {
		"Sequence Number", "extrememesh.probe.sequence", FT_UINT32, BASE_HEX_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_ballast_len, {
		"Ballast Length", "extrememesh.probe.ballast_len", FT_UINT16,
		BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_extrememesh_probe_ballast, {
		"Ballast", "extrememesh.probe.ballast", FT_BYTES, BASE_NONE,
		NULL, 0x0, NULL, HFILL }}
	};

	static int *ett[] = {
		&ett_extrememesh,
		&ett_extrememesh_mch,
		&ett_extrememesh_hello,
		&ett_extrememesh_security,
		&ett_extrememesh_cfpu,
		&ett_extrememesh_eapom,
		&ett_extrememesh_ps
	};

	/* registration */
	/* extrememesh mesh */
	proto_extrememesh = proto_register_protocol("Extreme Mesh", "EXTREME MESH", "extrememesh");
	proto_register_field_array(proto_extrememesh, hf_extrememesh, array_length(hf_extrememesh));
	proto_register_subtree_array(ett, array_length(ett));

	extrememesh_handle = register_dissector("extrememesh", dissect_extrememesh, proto_extrememesh);

	/* extrememesh mesh control header */
	proto_extrememesh_mch = proto_register_protocol("Extreme Mesh Control Header", "EXTREME MCH", "extrememesh_mch");
	proto_register_field_array(proto_extrememesh_mch, hf_extrememesh_mch, array_length(hf_extrememesh_mch));


#if 0
	/* extrememesh hello */
	proto_extrememesh_hello = proto_register_protocol("Extreme Hello", "EXTREME HELLO", "extrememesh_hello");
	proto_register_field_array(proto_extrememesh_hello, hf_extrememesh_hello, array_length(hf_extrememesh_hello));

	/* extrememesh security */
	proto_extrememesh_security = proto_register_protocol("Extreme Security", "EXTREME SECURITY", "extrememesh_security");
	proto_register_field_array(proto_extrememesh_security, hf_extrememesh_security, array_length(hf_extrememesh_security));

	/* extrememesh contention free period (CFP) update */
	proto_extrememesh_cfpu = proto_register_protocol("Extreme Cfpu", "EXTREME CFPU", "extrememesh_cfpu");
	proto_register_field_array(proto_extrememesh_cfpu, hf_extrememesh_cfpu, array_length(hf_extrememesh_cfpu));

	/* extrememesh EAP over mesh */
	proto_extrememesh_eapom = proto_register_protocol("Extreme EAPOM", "EXTREME EAPOM", "extrememesh_eapom");
	proto_register_field_array(proto_extrememesh_eapom, hf_extrememesh_eapom, array_length(hf_extrememesh_eapom));
#endif

	/* extrememesh mesh L2 update */
	proto_extrememesh_l2upd = proto_register_protocol("Extreme Mesh L2 Update", "EXTREME L2UPD", "extrememesh_l2upd");
	proto_register_field_array(proto_extrememesh_l2upd, hf_extrememesh_l2upd, array_length(hf_extrememesh_l2upd));

	/* extrememesh mesh probe message */
	proto_extrememesh_probe = proto_register_protocol("Extreme Mesh Probe Message", "EXTREME PROBE", "extrememesh_probe");
	proto_register_field_array(proto_extrememesh_probe, hf_extrememesh_probe, array_length(hf_extrememesh_probe));

	/* extrememesh mesh path selection authorization request */
	proto_extrememesh_ps_areq = proto_register_protocol("Extreme Mesh Path Selection Authorization Request", "EXTREME PS AREQ", "extrememesh_ps_areq");
	proto_register_field_array(proto_extrememesh_ps_areq, hf_extrememesh_ps_areq, array_length(hf_extrememesh_ps_areq));

	/* extrememesh mesh path selection authorization reply */
	proto_extrememesh_ps_arep = proto_register_protocol("Extreme Mesh Path Selection Authorization Reply", "EXTREME PS AREP", "extrememesh_ps_arep");
	proto_register_field_array(proto_extrememesh_ps_arep, hf_extrememesh_ps_arep, array_length(hf_extrememesh_ps_arep));

	/* extrememesh mesh path selection bind request */
	proto_extrememesh_ps_breq = proto_register_protocol("Extreme Mesh Path Selection Bind Request", "EXTREME PS BREQ", "extrememesh_ps_breq");
	proto_register_field_array(proto_extrememesh_ps_breq, hf_extrememesh_ps_breq, array_length(hf_extrememesh_ps_breq));

	/* extrememesh mesh path selection bind reply */
	proto_extrememesh_ps_brep = proto_register_protocol("Extreme Mesh Path Selection Bind Reply", "EXTREME PS BREP", "extrememesh_ps_brep");
	proto_register_field_array(proto_extrememesh_ps_brep, hf_extrememesh_ps_brep, array_length(hf_extrememesh_ps_brep));

	/* extrememesh mesh path selection bind announcement */
	proto_extrememesh_ps_bann = proto_register_protocol("Extreme Mesh Path Selection Bind Announcement", "EXTREME PS BANN", "extrememesh_ps_bann");
	proto_register_field_array(proto_extrememesh_ps_bann, hf_extrememesh_ps_bann, array_length(hf_extrememesh_ps_bann));

	/* extrememesh mesh path selection bind removed */
	proto_extrememesh_ps_bred = proto_register_protocol("Extreme Mesh Path Selection Bind Removed", "EXTREME PS BRED", "extrememesh_ps_bred");
	proto_register_field_array(proto_extrememesh_ps_bred, hf_extrememesh_ps_bred, array_length(hf_extrememesh_ps_bred));

	/* extrememesh mesh path selection status request */
	proto_extrememesh_ps_sreq = proto_register_protocol("Extreme Mesh Path Selection Status Request", "EXTREME PS SREQ", "extrememesh_ps_sreq");
	proto_register_field_array(proto_extrememesh_ps_sreq, hf_extrememesh_ps_sreq, array_length(hf_extrememesh_ps_sreq));

	/* extrememesh mesh path selection status reply */
	proto_extrememesh_ps_srep = proto_register_protocol("Extreme Mesh Path Selection Status Reply", "EXTREME PS SREP", "extrememesh_ps_srep");
	proto_register_field_array(proto_extrememesh_ps_srep, hf_extrememesh_ps_srep, array_length(hf_extrememesh_ps_srep));

	/* extrememesh mesh path selection path request */
	proto_extrememesh_ps_preq = proto_register_protocol("Extreme Mesh Path Selection Path Request", "EXTREME PS PREQ", "extrememesh_ps_preq");
	proto_register_field_array(proto_extrememesh_ps_preq, hf_extrememesh_ps_preq, array_length(hf_extrememesh_ps_preq));

	/* extrememesh mesh path selection path reply */
	proto_extrememesh_ps_prep = proto_register_protocol("Extreme Mesh Path Selection Path Reply", "EXTREME PS PREP", "extrememesh_ps_prep");
	proto_register_field_array(proto_extrememesh_ps_prep, hf_extrememesh_ps_prep, array_length(hf_extrememesh_ps_prep));

	/* extrememesh mesh path selection path error */
	proto_extrememesh_ps_perr = proto_register_protocol("Extreme Mesh Path Selection Path Error", "EXTREME PS PERR", "extrememesh_ps_perr");
	proto_register_field_array(proto_extrememesh_ps_perr, hf_extrememesh_ps_perr, array_length(hf_extrememesh_ps_perr));

	/* extrememesh mesh path selection path reset */
	proto_extrememesh_ps_prst = proto_register_protocol("Extreme Mesh Path Selection Path Reset", "EXTREME PS PRST", "extrememesh_ps_prst");
	proto_register_field_array(proto_extrememesh_ps_prst, hf_extrememesh_ps_prst, array_length(hf_extrememesh_ps_prst));

	/* extrememesh mesh path selection proxy remove */
	proto_extrememesh_ps_prem = proto_register_protocol("Extreme Mesh Path Selection Proxy Remove", "EXTREME PS PREM", "extrememesh_ps_prem");
	proto_register_field_array(proto_extrememesh_ps_prem, hf_extrememesh_ps_prem, array_length(hf_extrememesh_ps_prem));

	/* extrememesh mesh path selection trace path */
	proto_extrememesh_ps_trace = proto_register_protocol("Extreme Mesh Path Selection Trace Path", "EXTREME PS TRACE", "extrememesh_ps_trace");
	proto_register_field_array(proto_extrememesh_ps_trace, hf_extrememesh_ps_trace, array_length(hf_extrememesh_ps_trace));

	/* extrememesh mesh path selection proxy error */
	proto_extrememesh_ps_prer = proto_register_protocol("Extreme Mesh Path Selection Proxy Error", "EXTREME PS PRER", "extrememesh_ps_prer");
	proto_register_field_array(proto_extrememesh_ps_prer, hf_extrememesh_ps_prer, array_length(hf_extrememesh_ps_prer));
}

/*****************************************************************************/
/*

Register Extreme Mesh Handoff

Description:

Initializes the dissector by creating a handle and adding it to the
dissector table.

*/
/*****************************************************************************/
void proto_reg_handoff_extrememesh(void)
{
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

	dissector_add_uint("ethertype", ETHERTYPE_IEEE_EXTREME_MESH, extrememesh_handle);
}




/* packet-smc.c
 * SMC dissector for wireshark
 * By Joe Fowler <fowlerja@us.ibm.com>
 * By Guvenc Gulce <guvenc@linux.ibm.com>
 * (c) Copyright IBM Corporation 2014,2020
 * LICENSE: GNU General Public License, version 2, or (at your option) any
 * version. http://opensource.org/licenses/gpl-2.0.php
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Please refer to the following specs for protocol:
 * - ietf - draft-fox-tcpm-shared-memory-rdma-05
 * - https://www.ibm.com/support/pages/node/6326337
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-tcp.h"
#include <stdbool.h>

#define SMC_TCP_MIN_HEADER_LENGTH 7
#define CLC_MSG_START_OFFSET 5
#define LLC_MSG_START_OFFSET 3
#define RMBE_CTRL_START_OFFSET 2
#define MAC_ADDR_LEN 6
#define SMC_V2 2
#define GID_LEN 16
#define PEERID_LEN 8
#define DIAG_INFO_LEN 4
#define EID_LEN 32
#define ISM_GID_LEN 8
#define ISM_CHID_LEN 2
#define IPV4_SUBNET_MASK_LEN 4
#define IPV6_PREFIX_LEN 16
#define ONE_BYTE_RESERVED 1
#define TWO_BYTE_RESERVED 2
#define QP_LEN 3
#define RKEY_LEN 4
#define VIRTUAL_ADDR_LEN 8
#define FLAG_BYTE_LEN 1
#define LENGTH_BYTE_LEN 2
#define SEQNO_LEN 2
#define CURSOR_LEN 4
#define ALERT_TOKEN_LEN 4
#define DMB_TOKEN_LEN 8
#define PSN_LEN 3
#define CONN_INDEX_LEN 1
#define SMCR_MSG_BYTE_0 0
#define CLC_MSG_BYTE_0 0
#define CLC_MSG_BYTE_1 1
#define CLC_MSG_BYTE_2 2
#define CLC_MSG_BYTE_3 3
#define CLC_MSG_LEN_OFFSET 5
#define LLC_CMD_OFFSET 0
#define LLC_LEN_OFFSET 1
#define LLC_CMD_RSP_OFFSET 3
#define ACCEPT_CONFIRM_QP_OFFSET 38
#define SMCR_CLC_ID 0xe2d4c3d9 /*EBCDIC 'SMCR' */
#define SMCD_CLC_ID 0xe2d4c3c4 /*EBCDIC 'SMCD' */
#define SMC_CLC_V1    0x10
#define SMC_CLC_SMC_R 0x01

#define LLC_FLAG_RESP 0x80
#define RMBE_CTRL 0xfe
#define LLC_MSG_LENGTH 0x2c

typedef enum {
	SMC_CLC_PROPOSAL = 1,
	SMC_CLC_ACCEPT = 2,
	SMC_CLC_CONFIRMATION = 3,
	SMC_CLC_DECLINE = 4
} clc_message;

typedef enum {
	SMC_CLC_SMCR = 0,
	SMC_CLC_SMCD = 1,
	SMC_CLC_NONE = 2,
	SMC_CLC_BOTH = 3,
} clc_type_message;

typedef enum {
	SMC_CLC_OS_ZOS = 1,
	SMC_CLC_OS_LINUX = 2,
	SMC_CLC_OS_AIX = 3,
	SMC_CLC_OS_UNKOWN = 15,
} clc_os_message;

static const value_string smc_clc_os_message_txt[] = {
	{ SMC_CLC_OS_ZOS,      "z/OS" },
	{ SMC_CLC_OS_LINUX,    "Linux" },
	{ SMC_CLC_OS_AIX,      "AIX" },
	{ SMC_CLC_OS_UNKOWN,   "Unknown" },
	{ 0, NULL }
};

static const value_string smc_clc_type_message_txt[] = {
	{ SMC_CLC_SMCR,     "SMC-R" },
	{ SMC_CLC_SMCD,     "SMC-D"   },
	{ SMC_CLC_NONE,     "NONE"  },
	{ SMC_CLC_BOTH,     "SMC-R/SMC-D"  },
	{ 0, NULL }
};


static const value_string smcv2_clc_col_info_message_txt[] = {
	{ SMC_CLC_SMCR,     "[SMC-R-Proposal]" },
	{ SMC_CLC_SMCD,     "[SMC-Dv2-Proposal]"   },
	{ SMC_CLC_NONE,     "[NONE]"  },
	{ SMC_CLC_BOTH,     "[SMC-Dv2/SMC-R-Proposal]"  },
	{ 0, NULL }
};

static const value_string smc_clc_col_info_message_txt[] = {
        { SMC_CLC_SMCR,     "[SMC-R-Proposal]" },
        { SMC_CLC_SMCD,     "[SMC-D-Proposal]"   },
        { SMC_CLC_NONE,     "[NONE]"  },
        { SMC_CLC_BOTH,     "[SMC-D/SMC-R-Proposal]"  },
        { 0, NULL }
};

static const value_string smcr_clc_message_txt[] = {
	{ SMC_CLC_PROPOSAL,     "Proposal" },
	{ SMC_CLC_ACCEPT,       "Accept"   },
	{ SMC_CLC_CONFIRMATION, "Confirm"  },
	{ SMC_CLC_DECLINE,      "Decline"  },
	{ 0, NULL }
};

typedef enum {
	LLC_CONFIRM_LINK                = 0x01,
	LLC_ADD_LINK                    = 0x02,
	LLC_ADD_LINK_CONT               = 0x03,
	LLC_DEL_LINK                    = 0x04,
	LLC_CONFIRM_RKEY                = 0x06,
	LLC_CONFIRM_RKEY_CONT           = 0x08,
	LLC_DELETE_RKEY                 = 0x09,
	LLC_TEST_LINK                   = 0x07,
	LLC_OPT_MSG_CTRL                = 0x80,
	LLC_NWM_DATA                    = 0x8A,
	LLC_RMBE_CTRL                   = 0xFE
} llc_message;

static const value_string smcr_llc_message_txt[] = {
	{ LLC_CONFIRM_LINK,            "Confirm Link" },
	{ LLC_ADD_LINK,                "Add Link"   },
	{ LLC_ADD_LINK_CONT,           "Add Link Continuous"  },
	{ LLC_DEL_LINK,                "Delete Link"  },
	{ LLC_CONFIRM_RKEY,            "Confirm Rkey" },
	{ LLC_CONFIRM_RKEY_CONT,       "Confirm Rkey Continuous"   },
	{ LLC_DELETE_RKEY,             "Delete Rkey"  },
	{ LLC_TEST_LINK,               "Test Link"  },
	{ LLC_OPT_MSG_CTRL,            "OPT Message Control"   },
	{ LLC_NWM_DATA,                "NWM Data"  },
	{ RMBE_CTRL,                   "CDC Message"  },
	{ 0, NULL }
};

static int proto_smc = -1;
static int ett_smcr = -1;
static int hf_smcr_clc_msg = -1;
static int hf_smcr_llc_msg = -1;

/* SMC Proposal for both SMC-D and SMC-R */
static int ett_proposal_flag = -1;
static int ett_proposal_ext_flag2 = -1;
static int hf_proposal_smc_version_release_number = -1;
static int hf_proposal_smc_version_seid = -1;
static int hf_proposal_smc_version = -1;
static int hf_proposal_smc_type = -1;
static int hf_proposal_smc_v2_type = -1;
static int hf_smc_length = -1;
static int hf_smc_proposal_smc_chid = -1;
static int hf_smc_proposal_flags = -1;
static int hf_smc_proposal_eid = -1;
static int hf_smc_proposal_system_eid = -1;
static int hf_smc_proposal_ext_flags = -1;
static int hf_smc_proposal_client_peer_id = -1;
static int hf_smc_proposal_ism_gid = -1;
static int hf_smc_proposal_client_preferred_gid = -1;
static int hf_smc_proposal_client_preferred_mac = -1;
static int hf_smc_proposal_outgoing_interface_subnet_mask = -1;
static int hf_smc_proposal_rocev2_gid_ipv4_addr = -1;
static int hf_smc_proposal_rocev2_gid_ipv6_addr = -1;
static int hf_smc_proposal_outgoing_subnet_mask_signifcant_bits = -1;
static int hf_smc_proposal_ipv6_prefix = -1;
static int hf_smc_proposal_ipv6_prefix_length = -1;

static int hf_smc_reserved = -1;

/* SMC-R Accept */
static int ett_accept_flag = -1;
static int ett_accept_flag2 = -1;
static int hf_accept_smc_version = -1;
static int hf_accept_first_contact = -1;
static int hf_accept_rmb_buffer_size = -1;
static int hf_accept_qp_mtu_value = -1;
static int hf_smcr_accept_flags = -1;
static int hf_smcr_accept_flags2 = -1;
static int hf_smcr_accept_server_peer_id = -1;
static int hf_smcr_accept_server_preferred_gid = -1;
static int hf_smcr_accept_server_preferred_mac = -1;
static int hf_smcr_accept_server_qp_number = -1;
static int hf_smcr_accept_server_rmb_rkey = -1;
static int hf_smcr_accept_server_tcp_conn_index = -1;
static int hf_smcr_accept_server_rmb_element_alert_token = -1;
static int hf_smcr_accept_server_rmb_virtual_address = -1;
static int hf_smcr_accept_initial_psn = -1;

/* SMC-R Confirm */
static int ett_confirm_flag = -1;
static int ett_confirm_flag2 = -1;
static int hf_smcr_confirm_flags = -1;
static int hf_smcr_confirm_client_peer_id = -1;
static int hf_smcr_confirm_client_gid = -1;
static int hf_smcr_confirm_client_mac = -1;
static int hf_smcr_confirm_client_qp_number = -1;
static int hf_smcr_confirm_client_rmb_rkey = -1;
static int hf_smcr_confirm_client_tcp_conn_index = -1;
static int hf_smcr_confirm_client_rmb_element_alert_token = -1;
static int hf_smcr_confirm_flags2 = -1;
static int hf_smcr_confirm_client_rmb_virtual_address = -1;
static int hf_smcr_confirm_initial_psn = -1;
static int hf_confirm_smc_version = -1;
static int hf_confirm_rmb_buffer_size = -1;
static int hf_confirm_qp_mtu_value = -1;

/* SMC-D Accept */
static int hf_accept_smc_type = -1;
static int ett_smcd_accept_flag = -1;
static int ett_smcd_accept_fce_flag = -1;
static int ett_smcd_accept_flag2 = -1;
static int hf_smcd_accept_smc_version = -1;
static int hf_accept_os_type = -1;
static int hf_accept_smc_version_release_number = -1;
static int hf_smcd_accept_first_contact = -1;
static int hf_accept_dmb_buffer_size = -1;
static int hf_smcd_accept_flags = -1;
static int hf_smcd_accept_fce_flags = -1;
static int hf_smcd_accept_flags2 = -1;
static int hf_smcd_accept_server_peer_id = -1;
static int hf_smcd_accept_dmbe_conn_index = -1;
static int hf_smcd_accept_dmb_token = -1;
static int hf_smcd_accept_server_link_id = -1;
static int hf_smcd_accept_smc_chid = -1;
static int hf_smcd_accept_eid = -1;
static int hf_smcd_accept_peer_name = -1;

/* SMC-D Confirm */
static int hf_confirm_smc_type = -1;
static int ett_smcd_confirm_flag = -1;
static int ett_smcd_confirm_fce_flag = -1;
static int ett_smcd_confirm_flag2 = -1;
static int hf_smcd_confirm_smc_version = -1;
static int hf_confirm_os_type = -1;
static int hf_smcd_confirm_flags = -1;
static int hf_smcd_confirm_flags2 = -1;
static int hf_smcd_confirm_first_contact = -1;
static int hf_smcd_confirm_client_peer_id = -1;
static int hf_smcd_confirm_dmb_token = -1;
static int hf_smcd_confirm_dmbe_conn_index = -1;
static int hf_smcd_confirm_client_link_id = -1;
static int hf_confirm_smc_version_release_number = -1;
static int hf_smcd_confirm_dmb_buffer_size = -1;
static int hf_smcd_confirm_smc_chid = -1;
static int hf_smcd_confirm_eid = -1;
static int hf_smcd_confirm_peer_name = -1;

/* SMC-R Decline */
static int ett_decline_flag = -1;
static int ett_decline_flag2 = -1;
static int hf_smc_decline_flags = -1;
static int hf_smc_decline_flags2 = -1;
static int hf_smc_decline_peer_id = -1;
static int hf_smc_decline_diag_info = -1;
static int hf_decline_os_type = -1;
static int hf_decline_smc_version = -1;
static int hf_decline_out_of_sync = -1;

/* SMC-R Confirm Link*/
static int ett_confirm_link_flag = -1;
static int hf_smcr_confirm_link_flags = -1;
static int hf_smcr_confirm_link_mac = -1;
static int hf_smcr_confirm_link_gid = -1;
static int hf_smcr_confirm_link_qp_number = -1;
static int hf_smcr_confirm_link_number = -1;
static int hf_smcr_confirm_link_userid = -1;
static int hf_smcr_confirm_link_max_links = -1;
static int hf_smcr_confirm_link_response = -1;

/* SMC-R Add Link */
static int ett_add_link_flag = -1;
static int ett_add_link_flag2 = -1;
static int hf_smcr_add_link_flags = -1;
static int hf_smcr_add_link_response = -1;
static int hf_smcr_add_link_response_rejected = -1;
static int hf_smcr_add_link_mac = -1;
static int hf_smcr_add_link_gid = -1;
static int hf_smcr_add_link_qp_number = -1;
static int hf_smcr_add_link_number = -1;
static int hf_smcr_add_link_initial_psn = -1;
static int hf_smcr_add_link_flags2 = -1;
static int hf_smcr_add_link_qp_mtu_value = -1;

/* SMC-R Add Link Continue*/
static int ett_add_link_cont_flag = -1;
static int hf_smcr_add_link_cont_flags = -1;
static int hf_smcr_add_link_cont_response = -1;
static int hf_smcr_add_link_cont_link_number = -1;
static int hf_smcr_add_link_cont_number_of_rkeys = -1;
static int hf_smcr_add_link_cont_p1_rkey = -1;
static int hf_smcr_add_link_cont_p1_rkey2 = -1;
static int hf_smcr_add_link_cont_p1_virt_addr = -1;
static int hf_smcr_add_link_cont_p2_rkey = -1;
static int hf_smcr_add_link_cont_p2_rkey2 = -1;
static int hf_smcr_add_link_cont_p2_virt_addr = -1;

/* SMC-R Delete Link */
static int ett_delete_link_flag = -1;
static int hf_smcr_delete_link_flags = -1;
static int hf_smcr_delete_link_response = -1;
static int hf_smcr_delete_link_all = -1;
static int hf_smcr_delete_link_orderly = -1;
static int hf_smcr_delete_link_number = -1;
static int hf_smcr_delete_link_reason_code = -1;

/* SMC-R Confirm Rkey */
static int ett_confirm_rkey_flag = -1;
static int hf_smcr_confirm_rkey_response = -1;
static int hf_smcr_confirm_rkey_flags = -1;
static int hf_smcr_confirm_rkey_negative_response = -1;
static int hf_smcr_confirm_rkey_retry_rkey_set = -1;
static int hf_smcr_confirm_rkey_number = -1;
static int hf_smcr_confirm_rkey_new_rkey = -1;
static int hf_smcr_confirm_rkey_virtual_address = -1;
static int hf_smcr_confirm_rkey_link_number = -1;

/* SMC-R Delete Rkey */
static int ett_delete_rkey_flag = -1;
static int hf_smcr_delete_rkey_flags = -1;
static int hf_smcr_delete_rkey_response = -1;
static int hf_smcr_delete_rkey_negative_response = -1;
static int hf_smcr_delete_rkey_mask = -1;
static int hf_smcr_delete_rkey_deleted = -1;

/* SMC-R Test Link */
static int ett_test_link_flag = -1;
static int hf_smcr_test_link_flags = -1;
static int hf_smcr_test_link_response = -1;

/* SMC-R RMBE Control */
static int ett_rmbe_ctrl_rw_status_flag = -1;
static int ett_rmbe_ctrl_peer_conn_state_flag = -1;
static int hf_smcr_rmbe_ctrl_seqno = -1;
static int hf_smcr_rmbe_ctrl_alert_token = -1;
static int hf_smcr_rmbe_ctrl_prod_wrap_seqno = -1;
static int hf_smcr_rmbe_ctrl_peer_prod_curs = -1;
static int hf_smcr_rmbe_ctrl_cons_wrap_seqno = -1;
static int hf_smcr_rmbe_ctrl_peer_cons_curs = -1;
static int hf_smcr_rmbe_ctrl_conn_rw_status_flags = -1;
static int hf_smcr_rmbe_ctrl_write_blocked = -1;
static int hf_smcr_rmbe_ctrl_urgent_pending = -1;
static int hf_smcr_rmbe_ctrl_urgent_present = -1;
static int hf_smcr_rmbe_ctrl_cons_update_requested = -1;
static int hf_smcr_rmbe_ctrl_failover_validation = -1;
static int hf_smcr_rmbe_ctrl_peer_conn_state_flags = -1;
static int hf_smcr_rmbe_ctrl_peer_sending_done = -1;
static int hf_smcr_rmbe_ctrl_peer_closed_conn = -1;
static int hf_smcr_rmbe_ctrl_peer_abnormal_close = -1;

void proto_register_smcr(void);
void proto_reg_handoff_smcr(void);
static dissector_handle_t smc_tcp_handle;

static void
disect_smc_proposal(tvbuff_t *tvb, proto_tree *tree, bool is_ipv6)
{
	guint offset, suboffset;
	guint16 mask_offset, v2_ext_offset;
	guint16 v2_ext_pos = 0, smcd_v2_ext_offset = 0;
	guint16 smcd_v2_ext_pos = 0;
	guint8 ipv6_prefix_count, smc_version;
	guint8 smc_type, num_of_gids = 0, num_of_eids = 0;
	guint8 smc_type_v1 = 0, smc_type_v2 = 0;
	bool is_smc_v2, is_smcdv1, is_smcdv2;
	proto_item *proposal_flag_item;
	proto_tree *proposal_flag_tree;


	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;
	proposal_flag_item = proto_tree_add_item(tree, hf_smc_proposal_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proposal_flag_tree = proto_item_add_subtree(proposal_flag_item, ett_proposal_flag);
	proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	smc_version = tvb_get_guint8(tvb, offset);
	smc_type = tvb_get_guint8(tvb, offset);
	smc_version = ((smc_version >> 4) & 0x0F);
	is_smc_v2 = (smc_version >= SMC_V2);
	smc_type_v2 = ((smc_type >> 2) & 0x03);
	smc_type_v1 = (smc_type & 0x03);
	is_smcdv1 = ((smc_type_v1 == SMC_CLC_SMCD) || (smc_type_v1 == SMC_CLC_BOTH));
	is_smcdv2 = ((smc_type_v2 == SMC_CLC_SMCD) || (smc_type_v2 == SMC_CLC_BOTH));

	if (is_smc_v2)
		proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_v2_type, tvb,
				offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);

	proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_type, tvb,
			offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);

	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smc_proposal_client_peer_id, tvb, offset,
			    PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smc_proposal_client_preferred_gid, tvb,
			    offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smc_proposal_client_preferred_mac, tvb,
			    offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	mask_offset = tvb_get_ntohs(tvb, offset);

	if (mask_offset != 0) {
		suboffset = offset;
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					suboffset, TWO_BYTE_RESERVED, ENC_NA);
		suboffset += TWO_BYTE_RESERVED;
		if (is_smcdv1 || is_smcdv2) {
			proto_tree_add_item(tree, hf_smc_proposal_ism_gid, tvb,
					suboffset, ISM_GID_LEN, ENC_NA);
		}
		suboffset += ISM_GID_LEN;
		if (is_smc_v2) {
			if (is_smcdv2) {
				proto_tree_add_item(tree, hf_smc_proposal_smc_chid, tvb, suboffset,
						LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
			}
			suboffset += LENGTH_BYTE_LEN;
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						suboffset, TWO_BYTE_RESERVED, ENC_NA);
			v2_ext_offset = tvb_get_ntohs(tvb, suboffset);
			v2_ext_pos = suboffset + TWO_BYTE_RESERVED + v2_ext_offset;
		}
	}
	offset += TWO_BYTE_RESERVED + mask_offset;

	proto_tree_add_item(tree, hf_smc_proposal_outgoing_interface_subnet_mask, tvb,
		offset, IPV4_SUBNET_MASK_LEN, ENC_BIG_ENDIAN);
	offset += IPV4_SUBNET_MASK_LEN;
	proto_tree_add_item(tree, hf_smc_proposal_outgoing_subnet_mask_signifcant_bits, tvb,
		offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
				offset, TWO_BYTE_RESERVED, ENC_NA);
	offset += TWO_BYTE_RESERVED;
	ipv6_prefix_count = tvb_get_guint8(tvb, offset);
	offset += 1;

	while (ipv6_prefix_count != 0) {
		proto_tree_add_item(tree, hf_smc_proposal_ipv6_prefix, tvb,
			offset, IPV6_PREFIX_LEN, ENC_NA);
		offset += IPV6_PREFIX_LEN;
		proto_tree_add_item(tree, hf_smc_proposal_ipv6_prefix_length, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		ipv6_prefix_count--;
	}

	if (v2_ext_pos >= offset) {
		offset = v2_ext_pos;
		num_of_eids = tvb_get_guint8(tvb, offset);
		offset += FLAG_BYTE_LEN;
		num_of_gids = tvb_get_guint8(tvb, offset);
		offset += FLAG_BYTE_LEN;
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					offset, 1, ENC_NA);
		offset += 1;
		proposal_flag_item = proto_tree_add_item(tree, hf_smc_proposal_ext_flags, tvb,
							offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
		proposal_flag_tree = proto_item_add_subtree(proposal_flag_item, ett_proposal_ext_flag2);
		proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_version_release_number,
				tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_version_seid, tvb,
				offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
		offset += FLAG_BYTE_LEN;
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					offset, 2, ENC_NA);
		offset += 2;
		smcd_v2_ext_offset = tvb_get_ntohs(tvb, offset);
		offset += 2;
		smcd_v2_ext_pos = offset + smcd_v2_ext_offset;

		if (is_ipv6) {
			proto_tree_add_item(tree, hf_smc_proposal_rocev2_gid_ipv6_addr, tvb,
				offset, GID_LEN, ENC_NA);
			offset += GID_LEN;
		}
		else {
			offset += 12;
			proto_tree_add_item(tree, hf_smc_proposal_rocev2_gid_ipv4_addr, tvb,
				offset, IPV4_SUBNET_MASK_LEN, ENC_BIG_ENDIAN);
			offset += IPV4_SUBNET_MASK_LEN;
		}
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					offset, 16, ENC_NA);
		offset += 16;
		while (num_of_eids != 0) {
			proto_tree_add_item(tree, hf_smc_proposal_eid, tvb,
					offset, EID_LEN, ENC_ASCII | ENC_NA);
			offset += EID_LEN;
			num_of_eids--;
		}
		if (smcd_v2_ext_pos >= offset) {
			offset = smcd_v2_ext_pos;
			proto_tree_add_item(tree, hf_smc_proposal_system_eid, tvb,
					offset, EID_LEN, ENC_ASCII | ENC_NA);
			offset += EID_LEN;
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						offset, 16, ENC_NA);
			offset += 16;
			while (num_of_gids != 0) {
				proto_tree_add_item(tree, hf_smc_proposal_ism_gid, tvb,
					offset, ISM_GID_LEN, ENC_NA);
				offset += ISM_GID_LEN;
				proto_tree_add_item(tree, hf_smc_proposal_smc_chid, tvb, offset,
						ISM_CHID_LEN, ENC_BIG_ENDIAN);
				offset += ISM_CHID_LEN;
				num_of_gids--;
			}
		}

	}
}

static void
disect_smcd_accept(tvbuff_t* tvb, proto_tree* tree)
{
	guint offset;
	proto_item* accept_flag_item;
	proto_tree* accept_flag_tree;
	proto_item* accept_flag2_item;
	proto_tree* accept_flag2_tree;
	guint8 smc_version, first_contact = 0;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;
	accept_flag_item = proto_tree_add_item(tree, hf_smcd_accept_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	accept_flag_tree = proto_item_add_subtree(accept_flag_item, ett_smcd_accept_flag);
	proto_tree_add_item(accept_flag_tree, hf_smcd_accept_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(accept_flag_tree, hf_smcd_accept_first_contact, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(accept_flag_tree, hf_accept_smc_type, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	smc_version = tvb_get_guint8(tvb, offset);
	first_contact = tvb_get_guint8(tvb, offset);
	smc_version = ((smc_version >> 4) & 0x0F);
	first_contact = ((first_contact >> 3) & 0x01);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcd_accept_server_peer_id, tvb, offset,
		PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;

	proto_tree_add_item(tree, hf_smcd_accept_dmb_token, tvb,
		offset, DMB_TOKEN_LEN, ENC_NA);
	offset += DMB_TOKEN_LEN;

	proto_tree_add_item(tree, hf_smcd_accept_dmbe_conn_index, tvb,
		offset, CONN_INDEX_LEN, ENC_BIG_ENDIAN);
	offset += CONN_INDEX_LEN;

	accept_flag2_item = proto_tree_add_item(tree, hf_smcd_accept_flags2, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	accept_flag2_tree = proto_item_add_subtree(accept_flag2_item, ett_smcd_accept_flag2);
	proto_tree_add_item(accept_flag2_tree, hf_accept_dmb_buffer_size, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcd_accept_server_link_id, tvb,
		offset, ALERT_TOKEN_LEN, ENC_BIG_ENDIAN);
	offset += ALERT_TOKEN_LEN;

	if (smc_version >= SMC_V2) {
		proto_tree_add_item(tree, hf_smcd_accept_smc_chid, tvb, offset,
			LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
		offset += LENGTH_BYTE_LEN;

		proto_tree_add_item(tree, hf_smcd_accept_eid, tvb, offset, 32, ENC_ASCII | ENC_NA);
		offset += 32;
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					offset, 8, ENC_NA);
		offset += 8;

		if (first_contact) {
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						offset, ONE_BYTE_RESERVED, ENC_NA);
			offset += ONE_BYTE_RESERVED;
			accept_flag_item = proto_tree_add_item(tree, hf_smcd_accept_fce_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			accept_flag_tree = proto_item_add_subtree(accept_flag_item, ett_smcd_accept_fce_flag);
			proto_tree_add_item(accept_flag_tree, hf_accept_os_type, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_flag_tree, hf_accept_smc_version_release_number, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			offset += FLAG_BYTE_LEN;
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						offset, TWO_BYTE_RESERVED, ENC_NA);
			offset += TWO_BYTE_RESERVED;
			proto_tree_add_item(tree, hf_smcd_accept_peer_name, tvb, offset, 32, ENC_ASCII | ENC_NA);
			/* offset += 32; */
		}
	}
}

static void
disect_smcd_confirm(tvbuff_t* tvb, proto_tree* tree)
{
	guint offset;
	proto_item* confirm_flag_item;
	proto_tree* confirm_flag_tree;
	proto_item* confirm_flag2_item;
	proto_tree* confirm_flag2_tree;
	guint8 smc_version, first_contact = 0;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;
	confirm_flag_item = proto_tree_add_item(tree, hf_smcd_confirm_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_flag_tree = proto_item_add_subtree(confirm_flag_item, ett_smcd_confirm_flag);
	proto_tree_add_item(confirm_flag_tree, hf_smcd_confirm_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_flag_tree, hf_smcd_confirm_first_contact, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_flag_tree, hf_confirm_smc_type, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	smc_version = tvb_get_guint8(tvb, offset);
	first_contact = tvb_get_guint8(tvb, offset);
	smc_version = ((smc_version >> 4) & 0x0F);
	first_contact = ((first_contact >> 3) & 0x01);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcd_confirm_client_peer_id, tvb, offset,
		PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;

	proto_tree_add_item(tree, hf_smcd_confirm_dmb_token, tvb,
		offset, DMB_TOKEN_LEN, ENC_NA);
	offset += DMB_TOKEN_LEN;

	proto_tree_add_item(tree, hf_smcd_confirm_dmbe_conn_index, tvb,
		offset, CONN_INDEX_LEN, ENC_BIG_ENDIAN);
	offset += CONN_INDEX_LEN;

	confirm_flag2_item = proto_tree_add_item(tree, hf_smcd_confirm_flags2, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_flag2_tree = proto_item_add_subtree(confirm_flag2_item, ett_smcd_confirm_flag2);
	proto_tree_add_item(confirm_flag2_tree, hf_smcd_confirm_dmb_buffer_size, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
				offset, ONE_BYTE_RESERVED, ENC_NA);
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcd_confirm_client_link_id, tvb,
		offset, ALERT_TOKEN_LEN, ENC_BIG_ENDIAN);
	offset += ALERT_TOKEN_LEN;

	if (smc_version >= SMC_V2) {
		proto_tree_add_item(tree, hf_smcd_confirm_smc_chid, tvb, offset,
			LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
		offset += LENGTH_BYTE_LEN;

		proto_tree_add_item(tree, hf_smcd_confirm_eid, tvb, offset, 32, ENC_ASCII | ENC_NA);
		offset += 32;
		proto_tree_add_item(tree, hf_smc_reserved, tvb,
					offset, 8, ENC_NA);
		offset += 8;

		if (first_contact) {
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						offset, ONE_BYTE_RESERVED, ENC_NA);
			offset += ONE_BYTE_RESERVED;
			confirm_flag_item = proto_tree_add_item(tree, hf_smcd_accept_fce_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			confirm_flag_tree = proto_item_add_subtree(confirm_flag_item, ett_smcd_confirm_fce_flag);
			proto_tree_add_item(confirm_flag_tree, hf_confirm_os_type, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			proto_tree_add_item(confirm_flag_tree, hf_confirm_smc_version_release_number, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
			offset += FLAG_BYTE_LEN;
			proto_tree_add_item(tree, hf_smc_reserved, tvb,
						offset, TWO_BYTE_RESERVED, ENC_NA);
			offset += TWO_BYTE_RESERVED;
			proto_tree_add_item(tree, hf_smcd_confirm_peer_name, tvb, offset, 32, ENC_ASCII | ENC_NA);
			/* offset += 32; */
		}
	}
}


static void
disect_smcr_accept(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *accept_flag_item;
	proto_tree *accept_flag_tree;
	proto_item *accept_flag2_item;
	proto_tree *accept_flag2_tree;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;
	accept_flag_item = proto_tree_add_item(tree, hf_smcr_accept_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	accept_flag_tree = proto_item_add_subtree(accept_flag_item, ett_accept_flag);
	proto_tree_add_item(accept_flag_tree, hf_accept_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(accept_flag_tree, hf_accept_first_contact, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_peer_id, tvb, offset,
			PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_preferred_gid, tvb,
			offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_preferred_mac, tvb,
			offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_qp_number, tvb,
			offset, QP_LEN, ENC_BIG_ENDIAN);
	offset += QP_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_rmb_rkey, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
	offset += RKEY_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_tcp_conn_index, tvb,
			offset, CONN_INDEX_LEN, ENC_BIG_ENDIAN);
	offset += CONN_INDEX_LEN;
	proto_tree_add_item(tree, hf_smcr_accept_server_rmb_element_alert_token, tvb,
			    offset, ALERT_TOKEN_LEN, ENC_BIG_ENDIAN);
	offset += ALERT_TOKEN_LEN;
	accept_flag2_item = proto_tree_add_item(tree, hf_smcr_accept_flags2, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	accept_flag2_tree = proto_item_add_subtree(accept_flag2_item, ett_accept_flag2);
	proto_tree_add_item(accept_flag2_tree, hf_accept_rmb_buffer_size, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(accept_flag2_tree, hf_accept_qp_mtu_value, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
				offset, ONE_BYTE_RESERVED, ENC_NA);
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_accept_server_rmb_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
	offset += VIRTUAL_ADDR_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
				offset, ONE_BYTE_RESERVED, ENC_NA);
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_accept_initial_psn, tvb,
			offset, PSN_LEN, ENC_BIG_ENDIAN);
}

static void
disect_smcr_confirm(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *confirm_flag_item;
	proto_tree *confirm_flag_tree;
	proto_item *confirm_flag2_item;
	proto_tree *confirm_flag2_tree;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;
	confirm_flag_item = proto_tree_add_item(tree, hf_smcr_confirm_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_flag_tree = proto_item_add_subtree(confirm_flag_item, ett_confirm_flag);
	proto_tree_add_item(confirm_flag_tree, hf_confirm_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_peer_id, tvb, offset,
			PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_gid, tvb,
			offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_mac, tvb,
			offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_qp_number, tvb,
			offset, QP_LEN, ENC_BIG_ENDIAN);
	offset += QP_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_rmb_rkey, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
	offset += RKEY_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_tcp_conn_index, tvb,
			offset, CONN_INDEX_LEN, ENC_BIG_ENDIAN);
	offset += CONN_INDEX_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_client_rmb_element_alert_token, tvb,
			offset, ALERT_TOKEN_LEN, ENC_BIG_ENDIAN);
	offset += ALERT_TOKEN_LEN;
	confirm_flag2_item = proto_tree_add_item(tree, hf_smcr_confirm_flags2, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_flag2_tree = proto_item_add_subtree(confirm_flag2_item, ett_confirm_flag2);
	proto_tree_add_item(confirm_flag2_tree, hf_confirm_rmb_buffer_size, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_flag2_tree, hf_confirm_qp_mtu_value, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
			offset, ONE_BYTE_RESERVED, ENC_NA);
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_confirm_client_rmb_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
	offset += VIRTUAL_ADDR_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
			offset, ONE_BYTE_RESERVED, ENC_NA);
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_confirm_initial_psn, tvb,
			offset, PSN_LEN, ENC_BIG_ENDIAN);
}

static void
disect_smcr_decline(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item* decline_flag_item;
	proto_tree* decline_flag_tree;
	proto_item* decline_flag2_item;
	proto_tree* decline_flag2_tree;
	guint offset, smc_version;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smc_length, tvb, offset,
		LENGTH_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += LENGTH_BYTE_LEN;

	decline_flag_item = proto_tree_add_item(tree, hf_smc_decline_flags, tvb, offset,
		FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	decline_flag_tree = proto_item_add_subtree(decline_flag_item, ett_decline_flag);
	proto_tree_add_item(decline_flag_tree, hf_decline_smc_version, tvb, offset,
		FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(decline_flag_tree, hf_decline_out_of_sync, tvb, offset,
			FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	smc_version = tvb_get_guint8(tvb, offset);
	smc_version = ((smc_version >> 4) & 0x0F);

	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smc_decline_peer_id, tvb, offset,
			PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smc_decline_diag_info, tvb, offset,
			DIAG_INFO_LEN, ENC_BIG_ENDIAN);
	offset += DIAG_INFO_LEN;
	if (smc_version >= SMC_V2) {
		decline_flag2_item = proto_tree_add_item(tree, hf_smc_decline_flags2, tvb, offset,
			FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
		decline_flag2_tree = proto_item_add_subtree(decline_flag2_item, ett_decline_flag2);
		proto_tree_add_item(decline_flag2_tree, hf_decline_os_type, tvb, offset,
			FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	}
}

static void
disect_smcr_confirm_link(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *confirm_flag_item;
	proto_tree *confirm_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	confirm_flag_item = proto_tree_add_item(tree, hf_smcr_confirm_link_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_flag_tree = proto_item_add_subtree(confirm_flag_item, ett_confirm_link_flag);
	proto_tree_add_item(confirm_flag_tree, hf_smcr_confirm_link_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);

	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_link_mac, tvb,
			offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_link_gid, tvb,
			offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_link_qp_number, tvb,
			offset, QP_LEN, ENC_BIG_ENDIAN);
	offset += QP_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_smcr_confirm_link_userid, tvb,
			offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_smcr_confirm_link_max_links, tvb,
			offset, 1, ENC_BIG_ENDIAN);
}

static void
disect_smcr_add_link(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *add_link_flag_item;
	proto_tree *add_link_flag_tree;
	proto_item *add_link_flag2_item;
	proto_tree *add_link_flag2_tree;

	offset = LLC_MSG_START_OFFSET;
	add_link_flag_item = proto_tree_add_item(tree, hf_smcr_add_link_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	add_link_flag_tree = proto_item_add_subtree(add_link_flag_item, ett_add_link_flag);
	proto_tree_add_item(add_link_flag_tree, hf_smcr_add_link_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(add_link_flag_tree, hf_smcr_add_link_response_rejected, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_add_link_mac, tvb,
			offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb,
			offset, TWO_BYTE_RESERVED, ENC_NA);
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_add_link_gid, tvb,
			offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smcr_add_link_qp_number, tvb,
			offset, QP_LEN, ENC_BIG_ENDIAN);
	offset += QP_LEN;
	proto_tree_add_item(tree, hf_smcr_add_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	add_link_flag2_item = proto_tree_add_item(tree, hf_smcr_add_link_flags2, tvb, offset, 1, ENC_BIG_ENDIAN);
	add_link_flag2_tree = proto_item_add_subtree(add_link_flag2_item, ett_add_link_flag2);
	proto_tree_add_item(add_link_flag2_tree, hf_smcr_add_link_qp_mtu_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_smcr_add_link_initial_psn, tvb,
			offset, PSN_LEN, ENC_BIG_ENDIAN);
}

static void
disect_smcr_add_continuation(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	guint8 num_of_keys;
	proto_item *add_link_flag_item;
	proto_tree *add_link_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	add_link_flag_item = proto_tree_add_item(tree, hf_smcr_add_link_cont_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	add_link_flag_tree = proto_item_add_subtree(add_link_flag_item, ett_add_link_cont_flag);
	proto_tree_add_item(add_link_flag_tree, hf_smcr_add_link_cont_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_add_link_cont_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_smcr_add_link_cont_number_of_rkeys, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	num_of_keys = tvb_get_guint8(tvb,offset);
	offset += 1;

	if (num_of_keys >= 1) {
		proto_tree_add_item(tree, hf_smcr_add_link_cont_p1_rkey, tvb,
				offset, RKEY_LEN, ENC_BIG_ENDIAN);
		offset += RKEY_LEN;
		proto_tree_add_item(tree, hf_smcr_add_link_cont_p1_rkey2, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
		offset += RKEY_LEN;
		proto_tree_add_item(tree, hf_smcr_add_link_cont_p1_virt_addr, tvb,
				offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);

		if (num_of_keys >= 2) {
			offset += VIRTUAL_ADDR_LEN;
			proto_tree_add_item(tree, hf_smcr_add_link_cont_p2_rkey, tvb,
					offset, RKEY_LEN, ENC_BIG_ENDIAN);
			offset += RKEY_LEN;
			proto_tree_add_item(tree, hf_smcr_add_link_cont_p2_rkey2, tvb,
					offset, RKEY_LEN, ENC_BIG_ENDIAN);
			offset += RKEY_LEN;
			proto_tree_add_item(tree, hf_smcr_add_link_cont_p2_virt_addr, tvb,
					offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
		}
	}
}

static void
disect_smcr_delete_link(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *delete_link_flag_item;
	proto_tree *delete_link_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	delete_link_flag_item = proto_tree_add_item(tree, hf_smcr_delete_link_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	delete_link_flag_tree = proto_item_add_subtree(delete_link_flag_item, ett_delete_link_flag);
	proto_tree_add_item(delete_link_flag_tree, hf_smcr_delete_link_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(delete_link_flag_tree, hf_smcr_delete_link_all, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(delete_link_flag_tree, hf_smcr_delete_link_orderly, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_delete_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(tree, hf_smcr_delete_link_reason_code, tvb,
			offset, 4, ENC_BIG_ENDIAN);
}

static void
disect_smcr_confirm_rkey(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	guint8 num_entries;
	proto_item *confirm_rkey_flag_item;
	proto_tree *confirm_rkey_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	confirm_rkey_flag_item = proto_tree_add_item(tree, hf_smcr_confirm_rkey_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_rkey_flag_tree = proto_item_add_subtree(confirm_rkey_flag_item, ett_confirm_rkey_flag);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_negative_response,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_retry_rkey_set,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_rkey_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	num_entries = tvb_get_guint8(tvb,offset);

	if (num_entries > 2)
		num_entries = 2;

	offset += 1;
	proto_tree_add_item(tree, hf_smcr_confirm_rkey_new_rkey, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
	offset += RKEY_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_rkey_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);

	for (; num_entries > 0; num_entries--) {
		offset += VIRTUAL_ADDR_LEN;
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_new_rkey, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
		offset += RKEY_LEN;
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
	}
}

static void
disect_smcr_confirm_rkey_cont(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *confirm_rkey_flag_item;
	proto_tree *confirm_rkey_flag_tree;
	guint8 num_entries;

	offset = LLC_MSG_START_OFFSET;
	confirm_rkey_flag_item = proto_tree_add_item(tree, hf_smcr_confirm_rkey_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	confirm_rkey_flag_tree = proto_item_add_subtree(confirm_rkey_flag_item, ett_confirm_rkey_flag);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_negative_response,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(confirm_rkey_flag_tree, hf_smcr_confirm_rkey_retry_rkey_set,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_confirm_rkey_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	num_entries = tvb_get_guint8(tvb,offset);
	if (num_entries > 3)
			num_entries = 3;

	offset += 1;
	for (; num_entries > 0; num_entries--) {
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_link_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_new_rkey, tvb,
			offset, RKEY_LEN, ENC_BIG_ENDIAN);
		offset += RKEY_LEN;
		proto_tree_add_item(tree, hf_smcr_confirm_rkey_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
		offset += VIRTUAL_ADDR_LEN;
	}
}

static void
disect_smcr_delete_rkey(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	guint8 count;
	proto_item *delete_rkey_flag_item;
	proto_tree *delete_rkey_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	delete_rkey_flag_item = proto_tree_add_item(tree, hf_smcr_delete_rkey_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	delete_rkey_flag_tree = proto_item_add_subtree(delete_rkey_flag_item, ett_delete_rkey_flag);
	proto_tree_add_item(delete_rkey_flag_tree, hf_smcr_delete_rkey_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(delete_rkey_flag_tree, hf_smcr_delete_rkey_negative_response,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_delete_rkey_mask, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	for (count=0; count < 8; count++) {
		proto_tree_add_item(tree, hf_smcr_delete_rkey_deleted, tvb,
				offset, RKEY_LEN, ENC_BIG_ENDIAN);
		offset += RKEY_LEN;
	}
}

static void
disect_smcr_test_link(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	proto_item *test_link_flag_item;
	proto_tree *test_link_flag_tree;

	offset = LLC_MSG_START_OFFSET;
	test_link_flag_item = proto_tree_add_item(tree, hf_smcr_test_link_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	test_link_flag_tree = proto_item_add_subtree(test_link_flag_item, ett_test_link_flag);
	proto_tree_add_item(test_link_flag_tree, hf_smcr_test_link_response, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
}

static void
disect_smcr_rmbe_ctrl(tvbuff_t *tvb, proto_tree *tree)
{
	gint offset;
	proto_item *rmbe_ctrl_rw_status_flag_item;
	proto_tree *rmbe_ctrl_rw_status_flag_tree;
	proto_item *rmbe_ctrl_peer_conn_state_flag_item;
	proto_tree *rmbe_ctrl_peer_conn_state_flag_tree;

	offset = RMBE_CTRL_START_OFFSET;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_seqno, tvb, offset, SEQNO_LEN, ENC_BIG_ENDIAN);
	offset += SEQNO_LEN;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_alert_token, tvb, offset, ALERT_TOKEN_LEN, ENC_BIG_ENDIAN);
	offset += ALERT_TOKEN_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb, offset, TWO_BYTE_RESERVED, ENC_NA);
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_prod_wrap_seqno, tvb, offset, SEQNO_LEN, ENC_BIG_ENDIAN);
	offset += SEQNO_LEN;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_peer_prod_curs, tvb, offset, CURSOR_LEN, ENC_BIG_ENDIAN);
	offset += CURSOR_LEN;
	proto_tree_add_item(tree, hf_smc_reserved, tvb, offset, TWO_BYTE_RESERVED, ENC_NA);
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_cons_wrap_seqno, tvb, offset, SEQNO_LEN, ENC_BIG_ENDIAN);
	offset += SEQNO_LEN;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_peer_cons_curs, tvb, offset, CURSOR_LEN, ENC_BIG_ENDIAN);
	offset += CURSOR_LEN;
	rmbe_ctrl_rw_status_flag_item =
		proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_conn_rw_status_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	rmbe_ctrl_rw_status_flag_tree =
		proto_item_add_subtree(rmbe_ctrl_rw_status_flag_item, ett_rmbe_ctrl_rw_status_flag);
	proto_tree_add_item(rmbe_ctrl_rw_status_flag_tree, hf_smcr_rmbe_ctrl_write_blocked,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_rw_status_flag_tree, hf_smcr_rmbe_ctrl_urgent_pending,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_rw_status_flag_tree, hf_smcr_rmbe_ctrl_urgent_present,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_rw_status_flag_tree, hf_smcr_rmbe_ctrl_cons_update_requested,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_rw_status_flag_tree, hf_smcr_rmbe_ctrl_failover_validation,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	rmbe_ctrl_peer_conn_state_flag_item =
		proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_peer_conn_state_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	rmbe_ctrl_peer_conn_state_flag_tree =
		proto_item_add_subtree(rmbe_ctrl_peer_conn_state_flag_item, ett_rmbe_ctrl_peer_conn_state_flag);
	proto_tree_add_item(rmbe_ctrl_peer_conn_state_flag_tree, hf_smcr_rmbe_ctrl_peer_sending_done,
				tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_peer_conn_state_flag_tree, hf_smcr_rmbe_ctrl_peer_closed_conn,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proto_tree_add_item(rmbe_ctrl_peer_conn_state_flag_tree, hf_smcr_rmbe_ctrl_peer_abnormal_close,
			tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
}

static guint8 get_mixed_type(guint8 v1_type, guint8 v2_type)
{
	if (v1_type == SMC_CLC_BOTH)
		return v1_type;

	if (v1_type == SMC_CLC_NONE)
		return v2_type;

	if (((v2_type == SMC_CLC_SMCD) && (v1_type == SMC_CLC_SMCR)) ||
	    ((v2_type == SMC_CLC_SMCR) && (v1_type == SMC_CLC_SMCD)))
		return SMC_CLC_BOTH;

	return v2_type;
}

static int
dissect_smc_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		void *data _U_)
{
	gint offset;
	guint16 msg_len;
	guint8 smc_type, smc_v2_type = 0, smc_v1_type = 0, smc_version = 0;
	guint8 mixed_type;
	clc_message clc_msgid;
	proto_item *ti;
	proto_tree *smc_tree;
	bool is_ipv6, is_smc_v2, is_smcd = false;

	msg_len = tvb_get_ntohs(tvb, CLC_MSG_LEN_OFFSET);
	offset = 4;
	clc_msgid = (clc_message)tvb_get_guint8(tvb, offset);

	smc_version = tvb_get_guint8(tvb, offset + 3);
	smc_version = ((smc_version >> 4) & 0x0F);
	smc_type = tvb_get_guint8(tvb, offset + 3);
	is_smc_v2 = (smc_version >= SMC_V2);

	if (is_smc_v2 && (clc_msgid == SMC_CLC_PROPOSAL)) {
		smc_v1_type = (smc_type & 0x03);
		smc_v2_type = ((smc_type >> 2) & 0x03);
	}
	else if (clc_msgid != SMC_CLC_DECLINE) {
		smc_v2_type = (smc_type & 0x03);
		smc_v1_type = (smc_type & 0x03);
	}

	is_ipv6 = (pinfo->src.type == AT_IPv6);

	if (is_smc_v2)
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMCv2");
	else
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMC");

	if (clc_msgid == SMC_CLC_PROPOSAL) {
		if (is_smc_v2 && (smc_v2_type != SMC_CLC_NONE)) {
			mixed_type = get_mixed_type(smc_v1_type, smc_v2_type);
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s,",
					val_to_str_const((guint32)mixed_type,
					smcv2_clc_col_info_message_txt, "Unknown Command"));
		} else {
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s,",
					val_to_str_const((guint32)smc_v1_type,
					smc_clc_col_info_message_txt, "Unknown Command"));
		}
	} else if ((smc_v2_type == SMC_CLC_SMCR) && ((clc_msgid == SMC_CLC_ACCEPT) ||
		   (clc_msgid == SMC_CLC_CONFIRMATION))) {
		col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMC-R-%s],",
			val_to_str_const((guint32)clc_msgid,
				smcr_clc_message_txt, "Unknown Command"));
		col_append_fstr(pinfo->cinfo, COL_INFO, " QP=0x%06x",
				tvb_get_ntoh24(tvb, ACCEPT_CONFIRM_QP_OFFSET));
	}
	else if ((smc_v2_type == SMC_CLC_SMCD) && ((clc_msgid == SMC_CLC_ACCEPT) ||
		(clc_msgid == SMC_CLC_CONFIRMATION))) {
		is_smcd = true;
		if (is_smc_v2)
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMC-Dv2-%s],",
					val_to_str_const((guint32)clc_msgid,
					smcr_clc_message_txt, "Unknown Command"));
		else
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMC-D-%s],",
					val_to_str_const((guint32)clc_msgid,
					smcr_clc_message_txt, "Unknown Command"));
	}
	else {
		if (is_smc_v2)
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMCv2-%s],",
					val_to_str_const((guint32)clc_msgid,
					smcr_clc_message_txt, "Unknown Command"));
		else
			col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMC-%s],",
					val_to_str_const((guint32)clc_msgid,
					smcr_clc_message_txt, "Unknown Command"));
	}

	if (!tree)
	    return tvb_reported_length(tvb);

	ti = proto_tree_add_item(tree, proto_smc, tvb, 0, msg_len, ENC_NA);
	smc_tree = proto_item_add_subtree(ti, ett_smcr);
	proto_tree_add_item(smc_tree, hf_smcr_clc_msg, tvb, offset, 1,
			ENC_BIG_ENDIAN);
	switch (clc_msgid) {
		case SMC_CLC_PROPOSAL:
			disect_smc_proposal(tvb, smc_tree, is_ipv6);
			break;
		case SMC_CLC_ACCEPT:
			if (is_smcd)
				disect_smcd_accept(tvb, smc_tree);
			else
				disect_smcr_accept(tvb, smc_tree);
			break;
		case SMC_CLC_CONFIRMATION:
			if (is_smcd)
				disect_smcd_confirm(tvb, smc_tree);
			else
				disect_smcr_confirm(tvb, smc_tree);
			break;
		case SMC_CLC_DECLINE:
			disect_smcr_decline(tvb, smc_tree);
			break;
		default:
			/* Unknown Command */
			break;
	}
	return tvb_reported_length(tvb);
}

static int
dissect_smcr_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16 msg_len;
	llc_message llc_msgid;
	proto_item *ti;
	proto_tree *smcr_tree;

	msg_len = tvb_get_guint8(tvb, LLC_LEN_OFFSET);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMC-R");
	llc_msgid = (llc_message) tvb_get_guint8(tvb, LLC_CMD_OFFSET);
	col_append_str(pinfo->cinfo, COL_INFO, "[SMC-R] ");
	col_append_str(pinfo->cinfo, COL_INFO,
			val_to_str_const((guint32)llc_msgid,
			smcr_llc_message_txt, "Unknown Command"));

	if ((llc_msgid != RMBE_CTRL) &&
		(tvb_get_guint8(tvb, LLC_CMD_RSP_OFFSET) & LLC_FLAG_RESP))
			col_append_str(pinfo->cinfo, COL_INFO, "(Resp)");

	ti = proto_tree_add_item(tree, proto_smc, tvb, 0, msg_len, ENC_NA);
	smcr_tree = proto_item_add_subtree(ti, ett_smcr);
	proto_tree_add_item(smcr_tree, hf_smcr_llc_msg, tvb, 0, 1,
			ENC_BIG_ENDIAN);

	switch (llc_msgid) {
		case LLC_CONFIRM_LINK:
			disect_smcr_confirm_link(tvb, smcr_tree);
			break;

		case LLC_ADD_LINK:
			disect_smcr_add_link(tvb, smcr_tree);
			break;

		case LLC_ADD_LINK_CONT:
			disect_smcr_add_continuation(tvb, smcr_tree);
			break;

		case LLC_DEL_LINK:
			disect_smcr_delete_link(tvb, smcr_tree);
			break;

		case LLC_CONFIRM_RKEY:
			disect_smcr_confirm_rkey(tvb, smcr_tree);
			break;

		case LLC_CONFIRM_RKEY_CONT:
			disect_smcr_confirm_rkey_cont(tvb, smcr_tree);
			break;

		case LLC_DELETE_RKEY:
			disect_smcr_delete_rkey(tvb, smcr_tree);
			break;

		case LLC_TEST_LINK:
			disect_smcr_test_link(tvb, smcr_tree);
			break;

		case RMBE_CTRL:
			disect_smcr_rmbe_ctrl(tvb, smcr_tree);
			break;

		default:
			/* Unknown Command */
			break;
	}

	return tvb_captured_length(tvb);
}

static guint
get_smcr_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint32 length;
	length = tvb_get_ntohs(tvb, offset+CLC_MSG_LEN_OFFSET);
	return length;
}

static int
dissect_smc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, SMC_TCP_MIN_HEADER_LENGTH,
			 get_smcr_pdu_length, dissect_smc_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

static gboolean
dissect_smc_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	if (tvb_captured_length(tvb) < 4) {
		return FALSE;
	}

	if ((tvb_get_ntohl(tvb, CLC_MSG_BYTE_0) != SMCR_CLC_ID) &&
		(tvb_get_ntohl(tvb, CLC_MSG_BYTE_0) != SMCD_CLC_ID))
		return FALSE;

	dissect_smc_tcp(tvb, pinfo, tree, data);
	return TRUE;
}

static gboolean
dissect_smcr_infiniband_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data _U_)
{
	guint16 msg_len;
	llc_message msg_byte0;
	guint8 msg_byte1;

	if (tvb_captured_length_remaining(tvb, SMCR_MSG_BYTE_0) < 2)  /* need at least 2 bytes */
		return FALSE;

	/* Grab the first two bytes of the message, as they are needed */
	/*  for validity checking of both CLC and LLC messages         */
	msg_byte0 = (llc_message) tvb_get_guint8(tvb,CLC_MSG_BYTE_0);
	msg_byte1 = tvb_get_guint8(tvb,CLC_MSG_BYTE_1);


	/* Check for possible LLC Messages */

	if (!((msg_byte1 == LLC_MSG_LENGTH) &&
		(((msg_byte0 >= LLC_CONFIRM_LINK) &&
		(msg_byte0 <= LLC_DELETE_RKEY)) ||
		(msg_byte0 == LLC_RMBE_CTRL))))
		return FALSE;

	msg_len = tvb_get_guint8(tvb, LLC_LEN_OFFSET);
	if (msg_len != tvb_reported_length_remaining(tvb, LLC_CMD_OFFSET))
		return FALSE;

	dissect_smcr_infiniband(tvb, pinfo, tree, data);
	return TRUE;
}

void
proto_register_smcr(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_smcr_clc_msg, {
		"CLC Message", "smc.clc_msg",
		FT_UINT8, BASE_DEC, VALS(smcr_clc_message_txt), 0x0,
		NULL, HFILL}},

		{ &hf_smcr_llc_msg, {
		"LLC Message", "smc.llc_msg",
		FT_UINT8, BASE_DEC, VALS(smcr_llc_message_txt), 0x0,
		NULL, HFILL}},

		{ &hf_proposal_smc_version_release_number, {
		"SMC Version Release Number", "smc.proposal.smc.version.relnum",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},

		{ &hf_proposal_smc_version_seid, {
		"SEID Indicator", "smc.proposal.smc.seid",
		FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },

		{ &hf_proposal_smc_version, {
		"SMC Version", "smc.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_proposal_smc_type, {
		"SMC(v1) Type", "smc.proposal.smc.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_type_message_txt),
		0x03, NULL, HFILL}},

		{ &hf_accept_smc_type, {
		"SMC Type", "smc.accept.smc.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_type_message_txt),
		0x03, NULL, HFILL}},

		{ &hf_confirm_smc_type, {
		"SMC Type", "smc.confirm.smc.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_type_message_txt),
		0x03, NULL, HFILL}},

		{ &hf_proposal_smc_v2_type, {
		"SMC(v2) Type", "smc.proposal.smcv2.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_type_message_txt),
		0x0C, NULL, HFILL}},

		{ &hf_smc_proposal_smc_chid, {
		"ISM CHID", "smc.proposal.smc.chid",
		FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smc_length, {
		"SMC Length", "smc.length",
		FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}},

		{ &hf_accept_smc_version, {
		"SMC Version", "smc.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_smcd_accept_smc_version, {
		"SMC Version", "smc.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_smcd_confirm_smc_version, {
		"SMC Version", "smc.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_first_contact, {
		"First Contact", "smc.proposal.first.contact",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},

		{ &hf_confirm_smc_version, {
		"SMC Version", "smc.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_rmb_buffer_size, {
		"Server RMB Buffers Size (Compressed Notation)",
		"smc.accept.rmb.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_qp_mtu_value, {
		"QP MTU Value (enumerated value)",
		"smc.accept.qp.mtu.value",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},

		{ &hf_confirm_rmb_buffer_size, {
		"Client RMB Buffers Size (Compressed Notation)",
		"smc.confirm.rmb.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_confirm_qp_mtu_value, {
		"QP MTU Value (enumerated value)",
		"smc.confirm.qp.mtu.value",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},

		{ &hf_smc_proposal_flags, {
		"Flags", "smc.proposal.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_ext_flags, {
		"Flag 2", "smc.proposal.extflags.2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_flags, {
		"Flags", "smc.accept.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_flags2, {
		"Flags 2", "smc.accept.flags.2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_flags, {
		"Flags", "smc.confirm.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_decline_smc_version, {
		"SMC Version", "smc.decline.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL} },

		{ &hf_decline_out_of_sync, {
		"Out of Sync", "smc.decline.osync",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL} },

		{ &hf_smc_decline_flags2, {
		"Flags 2", "smc.decline.flags2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_decline_flags, {
		"Flags", "smc.decline.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcr_confirm_flags2, {
		"Flags 2", "smc.confirm.flags.2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_client_peer_id, {
		"Sender (Client) Peer ID", "smc.proposal.sender.client.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_ism_gid, {
		"ISM GID", "smc.proposal.ism.gid",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_client_preferred_gid, {
		"Client Preferred GID", "smc.proposal.client.preferred.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_client_preferred_mac, {
		"Client Preferred MAC Address",
		"smc.proposal.client.preferred.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_peer_id, {
		"Sender (Server) Peer ID", "smc.accept.sender.server.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_preferred_gid, {
		"Server Preferred GID", "smc.accept.server.preferred.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_preferred_mac, {
		"Server Preferred MAC Address",
		"smc.accept.server.preferred.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_rocev2_gid_ipv6_addr, {
		"RoCEv2 GID IPv6 Address",
		"smc.proposal.rocev2.gid.ipv6",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smc_proposal_rocev2_gid_ipv4_addr, {
		"RoCEv2 GID IPv4 Address",
		"smc.proposal.rocev2.gid.ipv4",
		FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_outgoing_interface_subnet_mask, {
		"Outgoing Interface Subnet Mask",
		"smc.outgoing.interface.subnet.mask",
		FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_outgoing_subnet_mask_signifcant_bits, {
		"Outgoing Interface Subnet Mask Number of Significant Bits",
		"smc.outgoing.interface.subnet.mask.number.of.significant.bits",
		FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_ipv6_prefix, {
		"IPv6 Prefix Value","smc.proposal.ipv6.prefix.value",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_ipv6_prefix_length, {
		"IPv6 Prefix Length", "smc.proposal.ipv6.prefix.length",
		FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_qp_number, {
		"Server QP Number","smc.accept.server.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_rkey, {
		"Server RMB Rkey","smc.accept.server.rmb.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_tcp_conn_index, {
		"Server TCP Connection Index",
		"smc.accept.server.tcp.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_element_alert_token, {
		"Server RMB Element Alert Token",
		"smc.accept.server.rmb.element.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_virtual_address, {
		"Server's RMB Virtual Address",
		"smc.accept.server.rmb.virtual.address",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_initial_psn, {
		"Initial PSN","smc.accept.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_peer_id, {
		"Sender (Client) Peer ID",
		"smc.confirm.sender.client.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_gid, {
		"Client GID", "smc.client.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_mac, {
		"Client MAC Address", "smc.confirm.client.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_qp_number, {
		"Client QP Number","smc.confirm.client.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_rkey, {
		"Client RMB Rkey","smc.confirm.client.rmb.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_tcp_conn_index, {
		"Client TCP Connection Index",
		"smc.confirm.client.tcp.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_element_alert_token, {
		"Client RMB Element Alert Token",
		"smc.client.rmb.element.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_virtual_address, {
		"Client's RMB Virtual Address",
		"smc.client.rmb.virtual.address",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_initial_psn, {
		"Initial PSN","smc.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_decline_peer_id, {
		"Sender Peer ID", "smc.sender.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_decline_diag_info, {
		"Peer Diagnosis Information", "smc.peer.diag.info",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_decline_os_type, {
		"OS Type", "smc.decline.os.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_os_message_txt), 0xF0, NULL, HFILL} },

		{ &hf_smcr_confirm_link_gid, {
		"Sender GID", "smc.sender.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_mac, {
		"Sender MAC Address", "smc.confirm.link.sender.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_qp_number, {
		"Sender QP Number","smc.confirm.link.sender.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_number, {
		"Link Number", "smc.confirm.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_userid, {
		"Sender Link User ID",
		"smc.confirm.link.sender.link.userid",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_max_links, {
		"Max Links","smc.confirm.link.max.links",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_flags, {
		"Flags", "smc.confirm.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_response, {
		"Response", "smc.confirm.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_gid, {
		"Sender GID", "smc.add.link.sender.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_mac, {
		"Sender MAC Address", "smc.add.link.sender.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_qp_number, {
		"Sender QP Number","smc.add.link.sender.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_number, {
		"Link Number", "smc.add.link.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_initial_psn, {
		"Initial PSN", "smc.add.link.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_flags, {
		"Flags", "smc.add.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_response, {
		"Add Link Response", "smc.add.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_response_rejected, {
		"Add Link Rejected", "smc.add.link.response.rejected",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_add_link_flags2, {
		"Flags", "smc.add.link.flags2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_smcr_add_link_qp_mtu_value, {
		"QP MTU Value", "smc.add.link.qp.mtu.value",
		FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_flags, {
		"Flags", "smc.add.link.cont.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_response, {
		"Response", "smc.add.link.cont.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_link_number, {
		"Link Number", "smc.add.link.cont.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_number_of_rkeys, {
		"Number of Rkeys", "smc.add.link.cont.rkey.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_rkey, {
		"RMB RToken Pair 1 - Rkey as known on this SMC Link",
		"smc.add.link.cont.rmb.RTok1.Rkey1",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_rkey2, {
		"RMB RToken Pair 1 - Equivalent Rkey for the new SMC Link",
		"smc.add.link.cont.rmb.RTok1.Rkey2",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_virt_addr, {
		"RMB RToken Pair 1 Virtual Address for the new SMC Link",
		"smc.add.link.cont.rmb.RTok1.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_rkey, {
		"RMB RToken Pair 2 - Rkey as known on this SMC Link",
		"smc.add.link.cont.rmb.RTok2.Rkey1",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_rkey2, {
		"RMB RToken Pair 2 - Equivalent Rkey for the new SMC Link",
		"smc.add.link.cont.rmb.RTok2.Rkey2",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_virt_addr, {
		"RMB RToken Pair 2 Virtual Address for the new SMC Link",
		"smc.add.link.cont.rmb.RTok1.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_link_flags, {
		"Flags", "smc.delete.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_link_response, {
		"Response", "smc.delete.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_delete_link_all, {
		"Terminate All Links In The Link Group",
		"smc.delete.link.all",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_delete_link_orderly, {
		"Terminate Links Orderly", "smc.delete.link.orderly",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_delete_link_number, {
		"Link Number For The Failed Link", "smc.delete.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_link_reason_code, {
		"Reason Code", "smc.delete.link.reason.code",
		FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_flags, {
		"Flags", "smc.confirm.rkey.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_response, {
		"Response", "smc.confirm.rkey.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_negative_response, {
		"Negative Response", "smc.confirm.rkey.negative.response",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_retry_rkey_set, {
		"Retry Rkey Set", "smc.confirm.rkey.retry.rkey.set",
		FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_number, {
		"Number of other QP", "smc.confirm.rkey.number.qp",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_new_rkey, {
		"New Rkey for this link","smc.confirm.rkey.new.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_virtual_address, {
		"New RMB virtual address for this link",
		"smc.confirm.rkey.new.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_link_number, {
		"Link Number", "smc.confirm.rkey.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_flags, {
		"Flags", "smc.delete.rkey.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_response, {
		"Response", "smc.delete.rkey.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_negative_response, {
		"Negative Response", "smc.delete.rkey.negative.response",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_mask, {
		"Error Mask", "smc.delete.rkey.error.mask",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_deleted, {
		"RMB Rkey to be deleted", "smc.delete.rkey.deleted",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_test_link_flags, {
		"Flags", "smc.test.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_test_link_response, {
		"Response", "smc.test.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_seqno, {
		"Sequence Number", "smc.rmbe.ctrl.seqno",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_alert_token, {
		"Alert Token", "smc.rmbe.ctrl.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smc_proposal_eid, {
		"EID", "smc.proposal.eid",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smc_proposal_system_eid, {
		"SEID", "smc.proposal.system.eid",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcr_rmbe_ctrl_prod_wrap_seqno, {
		"Producer window wrap sequence number",
		"smc.rmbe.ctrl.prod.wrap.seq",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_prod_curs, {
		"Peer Producer Cursor", "smc.rmbe.ctrl.peer.prod.curs",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_smcr_rmbe_ctrl_cons_wrap_seqno, {
		"Consumer window wrap sequence number",
		"smc.rmbe.ctrl.prod.wrap.seq",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_cons_curs, {
		"Peer Consumer Cursor", "smc.rmbe.ctrl.peer.prod.curs",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_conn_rw_status_flags, {
		"Connection read/write status flags",
		"smc.rmbe.ctrl.conn.rw.status.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_write_blocked, {
		"Write Blocked", "smc.rmbe.ctrl.write.blocked",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_urgent_pending, {
		"Urgent Data Pending", "smc.rmbe.ctrl.urgent.pending",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_urgent_present, {
		"Urgent Data Present", "smc.rmbe.ctrl.urgent.present",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_cons_update_requested, {
		"Consumer Cursor Update Requested",
		"smc.rmbe.ctrl.cons.update.requested",
		FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_failover_validation, {
		"Failover Validation Indicator",
		"smc.rmbe.ctrl.failover.validation",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_conn_state_flags, {
		"Peer Connection State Flags",
		"smc.rmbe.ctrl.peer.conn.state.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_sending_done, {
		"Peer Sending Done", "smc.rmbe.ctrl.peer.sending.done",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_closed_conn, {
		"Peer Closed Connection", "smc.rmbe.ctrl.peer.closed.conn",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_abnormal_close, {
		"Peer Abnormal Close", "smc.rmbe.ctrl.peer.abnormal.close",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcd_accept_eid, {
		"EID", "smc.accept.eid",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_eid, {
		"EID", "smc.confirm.eid",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_peer_name, {
		"Peer Host Name", "smc.accept.peer.host.name",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_peer_name, {
		"Peer Host Name", "smc.confirm.peer.host.name",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_first_contact, {
		"First Contact", "smc.accept.first.contact",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL} },

		{ &hf_smcd_confirm_first_contact, {
		"First Contact", "smc.confirm.first.contact",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL} },

		{ &hf_accept_smc_version_release_number, {
		"SMC Version Release Number", "smc.accept.smc.version.relnum",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },

		{ &hf_confirm_smc_version_release_number, {
		"SMC Version Release Number", "smc.confirm.smc.version.relnum",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL } },

		{ &hf_accept_os_type, {
		"OS Type", "smc.accept.os.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_os_message_txt), 0xF0, NULL, HFILL} },

		{ &hf_confirm_os_type, {
		"OS Type", "smc.confirm.os.type",
		FT_UINT8, BASE_DEC, VALS(smc_clc_os_message_txt), 0xF0, NULL, HFILL} },

		{ &hf_smcd_accept_dmb_token, {
		"DMB Token", "smc.accept.dmb.token",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_dmb_token, {
		"DMB Token", "smc.confirm.dmb.token",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_accept_dmb_buffer_size, {
		"Server DMBE Buffers Size (Compressed Notation)",
		"smc.accept.dmbe.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL} },

		{ &hf_smcd_confirm_dmb_buffer_size, {
		"Client DMBE Buffers Size (Compressed Notation)",
		"smc.confirm.dmbe.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL} },

		{ &hf_smcd_accept_smc_chid, {
		"ISM CHID", "smc.accept.smc.chid",
		FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL} },

		{ &hf_smcd_confirm_smc_chid, {
		"ISM CHID", "smc.confirm.smc.chid",
		FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL} },

		{ &hf_smcd_accept_server_peer_id, {
		"Sender (Server) ISM GID", "smc.accept.sender.server.ism.gid",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_client_peer_id, {
		"Sender (Client) ISM GID", "smc.confirm.sender.client.ism.gid",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_dmbe_conn_index, {
		"DMBE Connection Index",
		"smc.accept.dmbe.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_server_link_id, {
		"Server Link ID",
		"smc.accept.server.linkid",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_dmbe_conn_index, {
		"DMBE Connection Index",
		"smc.confirm.dmbe.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_client_link_id, {
		"Client Link ID",
		"smc.confirm.client.linkid",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_flags, {
		"Flags", "smc.accept.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_flags, {
		"Flags", "smc.confirm.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_flags2, {
		"DMBE Size", "smc.accept.dmbe.size",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_confirm_flags2, {
		"DMBE Size", "smc.confirm.dmbe.size",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smcd_accept_fce_flags, {
		"Flags", "smc.accept.fce.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL} },

		{ &hf_smc_reserved, {
		"Reserved", "smc.reserved",
		FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL} }
	};

	/* Setup protocol subtree arrays */
	static gint* ett[] = {
		&ett_smcr,
		&ett_proposal_flag,
		&ett_proposal_ext_flag2,
		&ett_accept_flag,
		&ett_accept_flag2,
		&ett_smcd_accept_flag,
		&ett_smcd_accept_flag2,
		&ett_smcd_accept_fce_flag,
		&ett_smcd_confirm_flag,
		&ett_smcd_confirm_fce_flag,
		&ett_smcd_confirm_flag2,
		&ett_confirm_flag,
		&ett_confirm_flag2,
		&ett_confirm_link_flag,
		&ett_decline_flag,
		&ett_decline_flag2,
		&ett_add_link_flag,
		&ett_add_link_flag2,
		&ett_add_link_cont_flag,
		&ett_delete_link_flag,
		&ett_confirm_rkey_flag,
		&ett_delete_rkey_flag,
		&ett_test_link_flag,
		&ett_rmbe_ctrl_rw_status_flag,
		&ett_rmbe_ctrl_peer_conn_state_flag
	};

	proto_smc = proto_register_protocol("Shared Memory Communications",
	    "SMC", "smc");

	proto_register_field_array(proto_smc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	smc_tcp_handle = register_dissector("smc", dissect_smc_tcp, proto_smc);
}

void
proto_reg_handoff_smcr(void)
{
	heur_dissector_add("tcp", dissect_smc_tcp_heur, "Shared Memory Communications over TCP", "smc_tcp", proto_smc, HEURISTIC_ENABLE);
	heur_dissector_add("infiniband.payload", dissect_smcr_infiniband_heur, "Shared Memory Communications Infiniband", "smcr_infiniband", proto_smc, HEURISTIC_ENABLE);
	dissector_add_for_decode_as("infiniband", create_dissector_handle( dissect_smcr_infiniband, proto_smc ) );
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

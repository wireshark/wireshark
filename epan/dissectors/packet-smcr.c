/* packet-smcr.c
 * SMC-R dissector for wireshark
 * By Joe Fowler <fowlerja@us.ibm.com>
 * (c) Copyright IBM Corporation 2014
 * LICENSE: GNU General Public License, version 2, or (at your option) any
 * version. http://opensource.org/licenses/gpl-2.0.php
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please refer to the following specs for protocol:
 * - ietf - draft-fox-tcpm-shared-memory-rdma-05
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-tcp.h"

#define SMCR_TCP_MIN_HEADER_LENGTH 7
#define CLC_MSG_START_OFFSET 7
#define LLC_MSG_START_OFFSET 3
#define RMBE_CTRL_START_OFFSET 2
#define MAC_ADDR_LEN 6
#define GID_LEN 16
#define PEERID_LEN 8
#define IPV4_SUBNET_MASK_LEN 4
#define IPV6_PREFIX_LEN 4
#define ONE_BYTE_RESERVED 1
#define TWO_BYTE_RESERVED 2
#define QP_LEN 3
#define RKEY_LEN 4
#define VIRTUAL_ADDR_LEN 8
#define FLAG_BYTE_LEN 1
#define SEQNO_LEN 2
#define CURSOR_LEN 4
#define ALERT_TOKEN_LEN 4
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

static int proto_smcr = -1;
static int ett_smcr = -1;
static int hf_smcr_clc_msg = -1;
static int hf_smcr_llc_msg = -1;

/* SMC-R Proposal */
static int ett_proposal_flag = -1;
static int hf_proposal_smc_version = -1;
static int hf_smcr_proposal_flags = -1;
static int hf_smcr_proposal_client_peer_id = -1;
static int hf_smcr_proposal_client_preferred_gid = -1;
static int hf_smcr_proposal_client_preferred_mac = -1;
static int hf_smcr_proposal_outgoing_interface_subnet_mask = -1;
static int hf_smcr_proposal_outgoing_subnet_mask_signifcant_bits = -1;
static int hf_smcr_proposal_ipv6_prefix = -1;
static int hf_smcr_proposal_ipv6_prefix_length = -1;

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

/* SMC-R Decline */
static int hf_smcr_decline_flags = -1;
static int hf_smcr_decline_peer_id = -1;
static int hf_smcr_decline_diag_info = -1;

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
static dissector_handle_t smcr_tcp_handle;

static void
disect_smcr_proposal(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;
	guint16 mask_offset;
	guint8 ipv6_prefix_count;
	proto_item *proposal_flag_item;
	proto_tree *proposal_flag_tree;

	offset = CLC_MSG_START_OFFSET;
	proposal_flag_item = proto_tree_add_item(tree, hf_smcr_proposal_flags, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	proposal_flag_tree = proto_item_add_subtree(proposal_flag_item, ett_proposal_flag);
	proto_tree_add_item(proposal_flag_tree, hf_proposal_smc_version, tvb, offset, FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_proposal_client_peer_id, tvb, offset,
			    PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smcr_proposal_client_preferred_gid, tvb,
			    offset, GID_LEN, ENC_NA);
	offset += GID_LEN;
	proto_tree_add_item(tree, hf_smcr_proposal_client_preferred_mac, tvb,
			    offset, MAC_ADDR_LEN, ENC_NA);
	offset += MAC_ADDR_LEN;
	mask_offset = tvb_get_ntohs(tvb, offset);
	offset += 2 + mask_offset;
	proto_tree_add_item(tree, hf_smcr_proposal_outgoing_interface_subnet_mask, tvb,
			offset, IPV4_SUBNET_MASK_LEN, ENC_BIG_ENDIAN);
	offset += IPV4_SUBNET_MASK_LEN;
	proto_tree_add_item(tree, hf_smcr_proposal_outgoing_subnet_mask_signifcant_bits, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	/* Bump past reserved bytes */
	offset += TWO_BYTE_RESERVED;
	ipv6_prefix_count = tvb_get_guint8(tvb, offset);
	offset += 2;

	while (ipv6_prefix_count != 0) {
		proto_tree_add_item(tree, hf_smcr_proposal_ipv6_prefix, tvb,
			offset, IPV6_PREFIX_LEN, ENC_NA);
		offset += IPV6_PREFIX_LEN;
		proto_tree_add_item(tree, hf_smcr_proposal_ipv6_prefix_length, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		ipv6_prefix_count--;
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
	/* Bump past reserved byte */
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_accept_server_rmb_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
	offset += VIRTUAL_ADDR_LEN;
	/* Bump past reserved byte */
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
	/* Bump past reserved byte */
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_confirm_client_rmb_virtual_address, tvb,
			offset, VIRTUAL_ADDR_LEN, ENC_BIG_ENDIAN);
	offset += VIRTUAL_ADDR_LEN;
	/* Bump past reserved byte */
	offset += ONE_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_confirm_initial_psn, tvb,
			offset, PSN_LEN, ENC_BIG_ENDIAN);
}

static void
disect_smcr_decline(tvbuff_t *tvb, proto_tree *tree)
{
	guint offset;

	offset = CLC_MSG_START_OFFSET;
	proto_tree_add_item(tree, hf_smcr_decline_flags, tvb, offset,
			FLAG_BYTE_LEN, ENC_BIG_ENDIAN);
	offset += FLAG_BYTE_LEN;
	proto_tree_add_item(tree, hf_smcr_decline_peer_id, tvb, offset,
			PEERID_LEN, ENC_BIG_ENDIAN);
	offset += PEERID_LEN;
	proto_tree_add_item(tree, hf_smcr_decline_diag_info, tvb, offset,
			4, ENC_BIG_ENDIAN);
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
	/* Bump past reserved bytes */
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
	offset += TWO_BYTE_RESERVED;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_prod_wrap_seqno, tvb, offset, SEQNO_LEN, ENC_BIG_ENDIAN);
	offset += SEQNO_LEN;
	proto_tree_add_item(tree, hf_smcr_rmbe_ctrl_peer_prod_curs, tvb, offset, CURSOR_LEN, ENC_BIG_ENDIAN);
	offset += CURSOR_LEN;
	/* Bump past reserved bytes */
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

static int
dissect_smcr_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		void *data _U_)
{
	gint offset;
	guint16 msg_len;
	clc_message clc_msgid;
	proto_item *ti;
	proto_tree *smcr_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMC-R");
	msg_len = tvb_get_ntohs(tvb, CLC_MSG_LEN_OFFSET);
	offset = 4;
	clc_msgid = (clc_message) tvb_get_guint8(tvb, offset);
	col_prepend_fstr(pinfo->cinfo, COL_INFO, "[SMC-R-%s],",
			val_to_str_const((guint32)clc_msgid,
			smcr_clc_message_txt, "Unknown Command"));

	if ((clc_msgid == SMC_CLC_ACCEPT) ||
	    (clc_msgid == SMC_CLC_CONFIRMATION)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " QP=0x%06x",
				tvb_get_ntoh24(tvb, ACCEPT_CONFIRM_QP_OFFSET));
	}

	if (!tree)
	    return tvb_reported_length(tvb);

	ti = proto_tree_add_item(tree, proto_smcr, tvb, 0, msg_len, ENC_NA);
	smcr_tree = proto_item_add_subtree(ti, ett_smcr);
	proto_tree_add_item(smcr_tree, hf_smcr_clc_msg, tvb, offset, 1,
			ENC_BIG_ENDIAN);

	switch (clc_msgid) {
		case SMC_CLC_PROPOSAL:
			disect_smcr_proposal(tvb, smcr_tree);
			break;
		case SMC_CLC_ACCEPT:
			disect_smcr_accept(tvb, smcr_tree);
			break;
		case SMC_CLC_CONFIRMATION:
			disect_smcr_confirm(tvb, smcr_tree);
			break;
		case SMC_CLC_DECLINE:
			disect_smcr_decline(tvb, smcr_tree);
			break;
		default:
			/* Unknown Command */
			break;
	}
	return tvb_reported_length(tvb);
}

static void
dissect_smcr_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_smcr, tvb, 0, msg_len, ENC_NA);
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
	return;
}

static guint
get_smcr_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint32 length;
	length = tvb_get_ntohs(tvb, offset+CLC_MSG_LEN_OFFSET);
	return length;
}

static int
dissect_smcr_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, SMCR_TCP_MIN_HEADER_LENGTH,
			 get_smcr_pdu_length, dissect_smcr_tcp_pdu, data);
	return tvb_reported_length(tvb);
}

static gboolean
dissect_smcr_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	void *data)
{
	if (tvb_captured_length(tvb) < 4) {
		return FALSE;
	}

	if (tvb_get_ntohl(tvb, CLC_MSG_BYTE_0) != SMCR_CLC_ID) return FALSE;
	dissect_smcr_tcp(tvb, pinfo, tree, data);
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

	dissect_smcr_infiniband(tvb, pinfo, tree);
	return TRUE;
}

void
proto_register_smcr(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_smcr_clc_msg, {
		"CLC Message", "smcr.clc_msg",
		FT_UINT8, BASE_DEC, VALS(smcr_clc_message_txt), 0x0,
		NULL, HFILL}},

		{ &hf_smcr_llc_msg, {
		"LLC Message", "smcr.llc_msg",
		FT_UINT8, BASE_DEC, VALS(smcr_llc_message_txt), 0x0,
		NULL, HFILL}},

		{ &hf_proposal_smc_version, {
		"SMC Version", "smcr.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_smc_version, {
		"SMC Version", "smcr.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_first_contact, {
		"First Contact", "smcr.proposal.first.contact",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},

		{ &hf_confirm_smc_version, {
		"SMC Version", "smcr.proposal.smc.version",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_rmb_buffer_size, {
		"Server RMB Buffers Size (Compressed Notation)",
		"smcr.accept.rmb.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_accept_qp_mtu_value, {
		"QP MTU Value (enumerated value)",
		"smcr.accept.qp.mtu.value",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},

		{ &hf_confirm_rmb_buffer_size, {
		"Client RMB Buffers Size (Compressed Notation)",
		"smcr.confirm.rmb.buffer.size",
		FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}},

		{ &hf_confirm_qp_mtu_value, {
		"QP MTU Value (enumerated value)",
		"smcr.confirm.qp.mtu.value",
		FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}},

		{ &hf_smcr_proposal_flags, {
		"Flags", "smcr.proposal.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_flags, {
		"Flags", "smcr.accept.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_flags2, {
		"Flags 2", "smcr.accept.flags.2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_flags, {
		"Flags", "smcr.confirm.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_decline_flags, {
		"Flags", "smcr.decline.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_flags2, {
		"Flags 2", "smcr.confirm.flags.2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_client_peer_id, {
		"Sender (Client) Peer ID", "smcr.proposal.sender.client.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_client_preferred_gid, {
		"Client Preferred GID", "smcr.proposal.client.preferred.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_client_preferred_mac, {
		"Client Preferred MAC Address",
		"smcr.proposal.client.preferred.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_peer_id, {
		"Sender (Server) Peer ID", "smcr.accept.sender.server.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_preferred_gid, {
		"Server Preferred GID", "smcr.accept.server.preferred.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_preferred_mac, {
		"Server Preferred MAC Address",
		"smcr.accept.server.preferred.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_outgoing_interface_subnet_mask, {
		"Outgoing Interface Subnet Mask",
		"smcr.outgoing.interface.subnet.mask",
		FT_IPv4, BASE_NETMASK, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_outgoing_subnet_mask_signifcant_bits, {
		"Outgoing Interface Subnet Mask Number of Significant Bits",
		"smcr.outgoing.interface.subnet.mask.number.of.significant.bits",
		FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_ipv6_prefix, {
		"IPv6 Prefix Value","smcr.proposal.ipv6.prefix.value",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_proposal_ipv6_prefix_length, {
		"IPv6 Prefix Length", "smcr.proposal.ipv6.prefix.length",
		FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_qp_number, {
		"Server QP Number","smcr.accept.server.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_rkey, {
		"Server RMB Rkey","smcr.accept.server.rmb.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_tcp_conn_index, {
		"Server TCP Connection Index",
		"smcr.accept.server.tcp.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_element_alert_token, {
		"Server RMB Element Alert Token",
		"smcr.accept.server.rmb.element.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_server_rmb_virtual_address, {
		"Server's RMB Virtual Address",
		"smcr.accept.server.rmb.virtual.address",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_accept_initial_psn, {
		"Initial PSN","smcr.accept.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_peer_id, {
		"Sender (Client) Peer ID",
		"smcr.confirm.sender.client.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_gid, {
		"Client GID", "smcr.client.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_mac, {
		"Client MAC Address", "smcr.confirm.client.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_qp_number, {
		"Client QP Number","smcr.confirm.client.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_rkey, {
		"Client RMB Rkey","smcr.confirm.client.rmb.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_tcp_conn_index, {
		"Client TCP Connection Index",
		"smcr.confirm.client.tcp.conn.index",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_element_alert_token, {
		"Client RMB Element Alert Token",
		"smcr.client.rmb.element.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_client_rmb_virtual_address, {
		"Client's RMB Virtual Address",
		"smcr.client.rmb.virtual.address",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_initial_psn, {
		"Initial PSN","smcr.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_decline_peer_id, {
		"Sender Peer ID", "smcr.sender.peer.id",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_decline_diag_info, {
		"Peer Diagnosis Information", "smcr.peer.diag.info",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_gid, {
		"Sender GID", "smcr.sender.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_mac, {
		"Sender MAC Address", "smcr.confirm.link.sender.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_qp_number, {
		"Sender QP Number","smcr.confirm.link.sender.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_number, {
		"Link Number", "smcr.confirm.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_userid, {
		"Sender Link User ID",
		"smcr.confirm.link.sender.link.userid",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_max_links, {
		"Max Links","smcr.confirm.link.max.links",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_flags, {
		"Flags", "smcr.confirm.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_link_response, {
		"Response", "smcr.confirm.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_gid, {
		"Sender GID", "smcr.add.link.sender.gid",
		FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_mac, {
		"Sender MAC Address", "smcr.add.link.sender.mac",
		FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_qp_number, {
		"Sender QP Number","smcr.add.link.sender.qp.number",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_number, {
		"Link Number", "smcr.add.link.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_initial_psn, {
		"Initial PSN", "smcr.add.link.initial.psn",
		FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_flags, {
		"Flags", "smcr.add.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_response, {
		"Add Link Response", "smcr.add.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_response_rejected, {
		"Add Link Rejected", "smcr.add.link.response.rejected",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_add_link_flags2, {
		"Flags", "smcr.add.link.flags2",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_smcr_add_link_qp_mtu_value, {
		"QP MTU Value", "smcr.add.link.qp.mtu.value",
		FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_flags, {
		"Flags", "smcr.add.link.cont.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_response, {
		"Response", "smcr.add.link.cont.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_link_number, {
		"Link Number", "smcr.add.link.cont.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_number_of_rkeys, {
		"Number of Rkeys", "smcr.add.link.cont.rkey.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_rkey, {
		"RMB RToken Pair 1 - Rkey as known on this SMC Link",
		"smcr.add.link.cont.rmb.RTok1.Rkey1",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_rkey2, {
		"RMB RToken Pair 1 - Equivalent Rkey for the new SMC Link",
		"smcr.add.link.cont.rmb.RTok1.Rkey2",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p1_virt_addr, {
		"RMB RToken Pair 1 Virtual Address for the new SMC Link",
		"smcr.add.link.cont.rmb.RTok1.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_rkey, {
		"RMB RToken Pair 2 - Rkey as known on this SMC Link",
		"smcr.add.link.cont.rmb.RTok2.Rkey1",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_rkey2, {
		"RMB RToken Pair 2 - Equivalent Rkey for the new SMC Link",
		"smcr.add.link.cont.rmb.RTok2.Rkey2",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_add_link_cont_p2_virt_addr, {
		"RMB RToken Pair 2 Virtual Address for the new SMC Link",
		"smcr.add.link.cont.rmb.RTok1.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_link_flags, {
		"Flags", "smcr.delete.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_link_response, {
		"Response", "smcr.delete.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_delete_link_all, {
		"Terminate All Links In The Link Group",
		"smcr.delete.link.all",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_delete_link_orderly, {
		"Terminate Links Orderly", "smcr.delete.link.orderly",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_delete_link_number, {
		"Link Number For The Failed Link", "smcr.delete.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_link_reason_code, {
		"Reason Code", "smcr.delete.link.reason.code",
		FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_flags, {
		"Flags", "smcr.confirm.rkey.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_response, {
		"Response", "smcr.confirm.rkey.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_negative_response, {
		"Negative Response", "smcr.confirm.rkey.negative.response",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_retry_rkey_set, {
		"Retry Rkey Set", "smcr.confirm.rkey.retry.rkey.set",
		FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_number, {
		"Number of other QP", "smcr.confirm.rkey.number.qp",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_new_rkey, {
		"New Rkey for this link","smcr.confirm.rkey.new.rkey",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_virtual_address, {
		"New RMB virtual address for this link",
		"smcr.confirm.rkey.new.virt",
		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_confirm_rkey_link_number, {
		"Link Number", "smcr.confirm.rkey.link.number",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_flags, {
		"Flags", "smcr.delete.rkey.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_response, {
		"Response", "smcr.delete.rkey.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_negative_response, {
		"Negative Response", "smcr.delete.rkey.negative.response",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_mask, {
		"Error Mask", "smcr.delete.rkey.error.mask",
		FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}},

		{ &hf_smcr_delete_rkey_deleted, {
		"RMB Rkey to be deleted", "smcr.delete.rkey.deleted",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_test_link_flags, {
		"Flags", "smcr.test.link.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_test_link_response, {
		"Response", "smcr.test.link.response",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_seqno, {
		"Sequence Number", "smcr.rmbe.ctrl.seqno",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_alert_token, {
		"Alert Token", "smcr.rmbe.ctrl.alert.token",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_prod_wrap_seqno, {
		"Producer window wrap sequence number",
		"smcr.rmbe.ctrl.prod.wrap.seq",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_prod_curs, {
		"Peer Producer Cursor", "smcr.rmbe.ctrl.peer.prod.curs",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_smcr_rmbe_ctrl_cons_wrap_seqno, {
		"Consumer window wrap sequence number",
		"smcr.rmbe.ctrl.prod.wrap.seq",
		FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_cons_curs, {
		"Peer Consumer Cursor", "smcr.rmbe.ctrl.peer.prod.curs",
		FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_conn_rw_status_flags, {
		"Connection read/write status flags",
		"smcr.rmbe.ctrl.conn.rw.status.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_write_blocked, {
		"Write Blocked", "smcr.rmbe.ctrl.write.blocked",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_urgent_pending, {
		"Urgent Data Pending", "smcr.rmbe.ctrl.urgent.pending",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_urgent_present, {
		"Urgent Data Present", "smcr.rmbe.ctrl.urgent.present",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_cons_update_requested, {
		"Consumer Cursor Update Requested",
		"smcr.rmbe.ctrl.cons.update.requested",
		FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_failover_validation, {
		"Failover Validation Indicator",
		"smcr.rmbe.ctrl.failover.validation",
		FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_conn_state_flags, {
		"Peer Connection State Flags",
		"smcr.rmbe.ctrl.peer.conn.state.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_sending_done, {
		"Peer Sending Done", "smcr.rmbe.ctrl.peer.sending.done",
		FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_closed_conn, {
		"Peer Closed Connection", "smcr.rmbe.ctrl.peer.closed.conn",
		FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL}},

		{ &hf_smcr_rmbe_ctrl_peer_abnormal_close, {
		"Peer Abnormal Close", "smcr.rmbe.ctrl.peer.abnormal.close",
		FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL}}
	};

	/* Setup protocol subtree arrays */
	static gint *ett[] = {
		&ett_smcr,
		&ett_proposal_flag,
		&ett_accept_flag,
		&ett_accept_flag2,
		&ett_confirm_flag,
		&ett_confirm_flag2,
		&ett_confirm_link_flag,
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

	proto_register_field_array(proto_smcr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	proto_smcr = proto_register_protocol("Shared Memory Communications - RDMA",
	    "SMCR", "smcr");
	smcr_tcp_handle = register_dissector("smcr", dissect_smcr_tcp, proto_smcr);
}

void
proto_reg_handoff_smcr(void)
{
	heur_dissector_add("tcp", dissect_smcr_tcp_heur, "Shared Memory Communications over TCP", "smcr_tcp", proto_smcr, HEURISTIC_ENABLE);
	heur_dissector_add("infiniband.payload", dissect_smcr_infiniband_heur, "Shared Memory Communications Infiniband", "smcr_infiniband", proto_smcr, HEURISTIC_ENABLE);
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

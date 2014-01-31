/*
 * packet-smb-direct.c
 *
 * Routines for [MS-SMBD] the RDMA transport layer for SMB2/3
 *
 * Copyright 2012 Stefan Metzmacher <metze@samba.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <glib.h>

#include "packet-windows-common.h"
#include "packet-iwarp-ddp-rdmap.h"
#include "packet-infiniband.h"

static int proto_smb_direct = -1;

static gint ett_smb_direct = -1;
static gint ett_smb_direct_hdr = -1;
static gint ett_smb_direct_flags = -1;

static int hf_smb_direct_negotiate_request = -1;
static int hf_smb_direct_negotiate_response = -1;
static int hf_smb_direct_data_message = -1;
static int hf_smb_direct_min_version = -1;
static int hf_smb_direct_max_version = -1;
static int hf_smb_direct_negotiated_version = -1;
static int hf_smb_direct_credits_requested = -1;
static int hf_smb_direct_credits_granted = -1;
static int hf_smb_direct_status = -1;
static int hf_smb_direct_max_read_write_size = -1;
static int hf_smb_direct_preferred_send_size = -1;
static int hf_smb_direct_max_receive_size = -1;
static int hf_smb_direct_max_fragmented_size = -1;
static int hf_smb_direct_flags = -1;
static int hf_smb_direct_flags_response_requested = -1;
static int hf_smb_direct_remaining_length = -1;
static int hf_smb_direct_data_offset = -1;
static int hf_smb_direct_data_length = -1;

enum SMB_DIRECT_HDR_TYPE {
	SMB_DIRECT_HDR_UNKNOWN = -1,
	SMB_DIRECT_HDR_NEG_REQ = 1,
	SMB_DIRECT_HDR_NEG_REP = 2,
	SMB_DIRECT_HDR_DATA = 3
};

#define SMB_DIRECT_RESPONSE_REQUESTED 0x0001

static heur_dissector_list_t smb_direct_heur_subdissector_list;
static dissector_handle_t data_handle;

static void
dissect_smb_direct_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (!dissector_try_heuristic(smb_direct_heur_subdissector_list,
				    tvb, pinfo, tree, NULL))
		call_dissector(data_handle,tvb, pinfo, tree);
}

static void
dissect_smb_direct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		   enum SMB_DIRECT_HDR_TYPE hdr_type)

{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	proto_tree *neg_req_tree = NULL;
	proto_tree *neg_rep_tree = NULL;
	proto_tree *data_tree = NULL;
	int offset = 0;
	guint32 status = 0;
	guint16 flags = 0;
	proto_tree *flags_tree = NULL;
	proto_item *flags_item = NULL;
	guint32 data_offset = 0;
	guint32 data_length = 0;
	guint rlen = tvb_reported_length(tvb);
	gint len = 0;
	tvbuff_t *next_tvb = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMBDirect");
	col_clear(pinfo->cinfo, COL_INFO);

	if (parent_tree != NULL) {
		item = proto_tree_add_item(parent_tree, proto_smb_direct, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smb_direct);
	}

	switch (hdr_type) {
	case SMB_DIRECT_HDR_UNKNOWN:
		break;

	case SMB_DIRECT_HDR_NEG_REQ:
		col_append_str(pinfo->cinfo, COL_INFO, "NegotiateRequest");

		if (tree == NULL) {
			break;
		}

		item = proto_tree_add_item(tree, hf_smb_direct_negotiate_request, tvb, 0, -1, ENC_NA);
		neg_req_tree = proto_item_add_subtree(item, ett_smb_direct_hdr);

		proto_tree_add_item(neg_req_tree, hf_smb_direct_min_version,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_req_tree, hf_smb_direct_max_version,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* 2 bytes reserved */
		offset += 2;

		proto_tree_add_item(neg_req_tree, hf_smb_direct_credits_requested,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_req_tree, hf_smb_direct_preferred_send_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_req_tree, hf_smb_direct_max_receive_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_req_tree, hf_smb_direct_max_fragmented_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case SMB_DIRECT_HDR_NEG_REP:
		col_append_str(pinfo->cinfo, COL_INFO, "NegotiateResponse");

		status = tvb_get_letohl(tvb, 12);
		if (status != 0) {
			col_append_fstr(
				pinfo->cinfo, COL_INFO, ", Error: %s",
				val_to_str(status, NT_errors, "Unknown (0x%08X)"));
		}

		if (tree == NULL) {
			break;
		}

		item = proto_tree_add_item(tree, hf_smb_direct_negotiate_response, tvb, 0, -1, ENC_NA);
		neg_rep_tree = proto_item_add_subtree(item, ett_smb_direct_hdr);

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_min_version,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_max_version,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_negotiated_version,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		/* 2 bytes reserved */
		offset += 2;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_credits_requested,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_credits_granted,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_status,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_max_read_write_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_preferred_send_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_max_receive_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(neg_rep_tree, hf_smb_direct_max_fragmented_size,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		/* offset += 4; */
		break;

	case SMB_DIRECT_HDR_DATA:
		col_append_str(pinfo->cinfo, COL_INFO, "DataMessage");

		if (tree == NULL) {
			break;
		}

		rlen = MIN(rlen, 24);

		item = proto_tree_add_item(tree, hf_smb_direct_data_message, tvb, 0, rlen, ENC_NA);
		data_tree = proto_item_add_subtree(item, ett_smb_direct_hdr);

		proto_tree_add_item(data_tree, hf_smb_direct_credits_requested,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(data_tree, hf_smb_direct_credits_granted,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		flags = tvb_get_letohs(tvb, offset);
		flags_item = proto_tree_add_item(data_tree, hf_smb_direct_flags,
						 tvb, offset, 2, ENC_LITTLE_ENDIAN);
		flags_tree = proto_item_add_subtree(flags_item, ett_smb_direct_flags);
		proto_tree_add_boolean(flags_tree, hf_smb_direct_flags_response_requested,
				       tvb, offset, 2, flags);
		offset += 2;

		/* 2 bytes reserved */
		offset += 2;

		proto_tree_add_item(data_tree, hf_smb_direct_remaining_length,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		data_offset = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(data_tree, hf_smb_direct_data_offset,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		data_length = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(data_tree, hf_smb_direct_data_length,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		if (data_length > 0 && data_offset > (guint32)offset) {
			len = tvb_reported_length_remaining(tvb, data_offset);
		}

		if (data_length <= (guint32)len) {
			next_tvb = tvb_new_subset(tvb, data_offset,
						  data_length, data_length);
		}

		if (next_tvb != NULL) {
			dissect_smb_direct_payload(next_tvb, pinfo, parent_tree);
		}

		/* offset = data_offset + data_length; */
		break;
	}

	return;
}

static enum SMB_DIRECT_HDR_TYPE
is_smb_direct(tvbuff_t *tvb, packet_info *pinfo _U_)
{
	gboolean maybe_neg_req = FALSE;
	gboolean maybe_data = FALSE;
	guint len = tvb_reported_length(tvb);

	if (len < 20) {
		return SMB_DIRECT_HDR_UNKNOWN;
	}

	if (len == 32 &&
	    tvb_get_letohs(tvb, 0) == 0x0100 && /* min version */
	    tvb_get_letohs(tvb, 2) == 0x0100 && /* max version */
	    tvb_get_letohs(tvb, 4) == 0x0100 && /* negotiated version */
	    tvb_get_letohs(tvb, 6) == 0x0000)   /* reserved */
	{
		/* Negotiate Response */
		return SMB_DIRECT_HDR_NEG_REP;
	}

	if (tvb_get_letohs(tvb, 0) == 0x0100 && /* min version */
	    tvb_get_letohs(tvb, 2) == 0x0100 && /* max version */
	    tvb_get_letohs(tvb, 4) == 0x0000)   /* reserved */
	{
		maybe_neg_req = TRUE;
	}

	if (tvb_get_letohs(tvb, 0) <= 255 &&    /* credits up to 255 */
	    tvb_get_letohs(tvb, 2) <= 255 &&    /* credits up to 255 */
	    tvb_get_letohs(tvb, 4) <= 1   &&    /* flags 0 or 1 */
	    tvb_get_letohs(tvb, 6) == 0)    /* reserved */
	{
		maybe_data = TRUE;
	}

	if (len == 20) {
		if (tvb_get_letohl(tvb, 8) != 0) { /* remaining */
			maybe_data = FALSE;
		}
		if (tvb_get_letohl(tvb, 12) != 0) { /* data offset */
			maybe_data = FALSE;
		}
		if (tvb_get_letohl(tvb, 16) != 0) { /* data length */
			maybe_data = FALSE;
		}

		if (maybe_neg_req && !maybe_data) {
			/* Negotiate Request */
			return SMB_DIRECT_HDR_NEG_REQ;
		}
		/* maybe_neg_req = FALSE; */
		if (maybe_data) {
			/* Data Message */
			return SMB_DIRECT_HDR_DATA;
		}
	}

	if (len <= 24) {
		return SMB_DIRECT_HDR_UNKNOWN;
	}

	if (tvb_get_letohl(tvb, 12) != 24) { /* data offset */
		return SMB_DIRECT_HDR_UNKNOWN;
	}

	if (tvb_get_letohl(tvb, 16) == 0) {  /* data length */
		return SMB_DIRECT_HDR_UNKNOWN;
	}

	if (tvb_get_letohl(tvb, 20) != 0) { /* padding */
		return SMB_DIRECT_HDR_UNKNOWN;
	}

	if (maybe_data) {
		/* Data Message */
		return SMB_DIRECT_HDR_DATA;
	}

	return SMB_DIRECT_HDR_UNKNOWN;
}

static gboolean
dissect_smb_direct_iwarp_heur(tvbuff_t *tvb, packet_info *pinfo,
			      proto_tree *parent_tree, void *data)
{
	struct rdmapinfo *info = (struct rdmapinfo *)data;
	enum SMB_DIRECT_HDR_TYPE hdr_type;

	if (info == NULL) {
		return FALSE;
	}

	switch (info->opcode) {
	case RDMA_SEND:
	case RDMA_SEND_INVALIDATE:
	case RDMA_SEND_SE:
	case RDMA_SEND_SE_INVALIDATE:
		break;
	default:
		return FALSE;
	}

	hdr_type = is_smb_direct(tvb, pinfo);
	if (hdr_type == SMB_DIRECT_HDR_UNKNOWN) {
		return FALSE;
	}

	dissect_smb_direct(tvb, pinfo, parent_tree, hdr_type);
	return TRUE;
}

static gboolean
dissect_smb_direct_infiniband_heur(tvbuff_t *tvb, packet_info *pinfo,
				   proto_tree *parent_tree, void *data)
{
	struct infinibandinfo *info = (struct infinibandinfo *)data;
	enum SMB_DIRECT_HDR_TYPE hdr_type;

	if (info == NULL) {
		return FALSE;
	}

	switch (info->opCode) {
	case RC_SEND_FIRST:
	case RC_SEND_MIDDLE:
	case RC_SEND_LAST:
	case RC_SEND_LAST_IMM:
	case RC_SEND_ONLY:
	case RC_SEND_ONLY_IMM:
	case RC_SEND_LAST_INVAL:
	case RC_SEND_ONLY_INVAL:
		break;
	default:
		return FALSE;
	}

	hdr_type = is_smb_direct(tvb, pinfo);
	if (hdr_type == SMB_DIRECT_HDR_UNKNOWN) {
		return FALSE;
	}

	dissect_smb_direct(tvb, pinfo, parent_tree, hdr_type);
	return TRUE;
}

void proto_register_smb_direct(void)
{
	static gint *ett[] = {
		&ett_smb_direct,
		&ett_smb_direct_hdr,
		&ett_smb_direct_flags,
	};

	static hf_register_info hf[] = {
	{ &hf_smb_direct_negotiate_request,
		{ "NegotiateRequest", "smb_direct.negotiate_request",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_smb_direct_negotiate_response,
		{ "NegotiateResponse", "smb_direct.negotiate_response",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_smb_direct_data_message,
		{ "DataMessage", "smb_direct.data_message",
		FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	{ &hf_smb_direct_min_version,
		{ "MinVersion", "smb_direct.version.min",
		FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_max_version,
		{ "MaxVersion", "smb_direct.version.max",
		FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_negotiated_version,
		{ "NegotiatedVersion", "smb_direct.version.negotiated",
		FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_credits_requested,
		{ "CreditsRequested", "smb_direct.credits.requested",
		FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_credits_granted,
		{ "CreditsGranted", "smb_direct.credits.granted",
		FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_status,
		{ "Status", "smb_direct.status",
		FT_UINT32, BASE_HEX, VALS(NT_errors), 0,
		"NT Status code", HFILL }},

	{ &hf_smb_direct_max_read_write_size,
		{ "MaxReadWriteSize", "smb_direct.max_read_write_size",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_preferred_send_size,
		{ "PreferredSendSize", "smb_direct.preferred_send_size",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_max_receive_size,
		{ "MaxReceiveSize", "smb_direct.max_receive_size",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_max_fragmented_size,
		{ "MaxFragmentedSize", "smb_direct.max_fragmented_size",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_flags,
		{ "Flags", "smb_direct.flags",
		FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_flags_response_requested,
		{ "ResponseRequested", "smb_direct.flags.response_requested",
		FT_BOOLEAN, 16, NULL, SMB_DIRECT_RESPONSE_REQUESTED,
		NULL, HFILL }},

	{ &hf_smb_direct_remaining_length,
		{ "RemainingLength", "smb_direct.remaining_length",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_data_offset,
		{ "DataOffset", "smb_direct.data_offset",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	{ &hf_smb_direct_data_length,
		{ "DataLength", "smb_direct.data_length",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

	};

	proto_smb_direct = proto_register_protocol("SMB-Direct (SMB RDMA Transport)",
						   "SMBDirect", "smb_direct");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb_direct, hf, array_length(hf));

	register_heur_dissector_list("smb_direct",
				     &smb_direct_heur_subdissector_list);
}

void
proto_reg_handoff_smb_direct(void)
{
	data_handle = find_dissector("data");
	heur_dissector_add("iwarp_ddp_rdmap",
			   dissect_smb_direct_iwarp_heur,
			   proto_smb_direct);
	heur_dissector_add("infiniband.payload",
			   dissect_smb_direct_infiniband_heur,
			   proto_smb_direct);

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

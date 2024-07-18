/* packet-rdpudp.c
 * Routines for RDP multi transport packet dissection
 * Copyright 2021, David Fort
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

#define PNAME  "Remote Desktop Protocol Multi-transport"
#define PSNAME "RDPMT"
#define PFNAME "rdpmt"

void proto_register_rdpmt(void);
void proto_reg_handoff_rdpmt(void);

static dissector_handle_t rdpmt_handle;

static int proto_rdpmt;

static int hf_rdpmt_action;
static int hf_rdpmt_flags;
static int hf_rdpmt_payload_len;
static int hf_rdpmt_header_len;
static int hf_rdpmt_subheader_len;
static int hf_rdpmt_subheader_type;
static int hf_rdpmt_createreq_reqId;
static int hf_rdpmt_createreq_reserved;
static int hf_rdpmt_createreq_cookie;
static int hf_rdpmt_createresp_hrResponse;

static int ett_rdpmt;
static int ett_rdpudp_subheaders;
static int ett_rdpmt_create_req;
static int ett_rdpmt_create_resp;
static int ett_rdpmt_data;

static dissector_handle_t drdynvcDissector;

static const value_string rdpmt_action_vals[] = {
	{ 0x00, "CreateRequest"},
	{ 0x01, "CreateResponse"},
	{ 0x02, "Data"},
	{ 0x00, NULL}
};

static const value_string rdpmt_subheader_type_vals[] = {
	{ 0x0, "auto detect request" },
	{ 0x1, "auto detect response" },
	{ 0x0, NULL}
};

enum {
	RDPMT_TUNNEL_CREATE_REQ = 0,
	RDPMT_TUNNEL_CREATE_RESP = 1,
	RDPMT_TUNNEL_DATA = 2,
};

static int
dissect_rdpmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree, *subtree;
	uint8_t action, subheader_len;
	uint16_t payload_len;
	int offset = 0;

	item = proto_tree_add_item(parent_tree, proto_rdpmt, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdpmt);

	action = tvb_get_uint8(tvb, offset) & 0x0f;
	proto_tree_add_item(tree, hf_rdpmt_action, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_rdpmt_flags, tvb, offset, 1, ENC_NA);
	offset++;

	payload_len	= tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_rdpmt_payload_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	subheader_len = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_rdpmt_header_len, tvb, offset, 1, ENC_NA);
	offset += 1;

	if (subheader_len > 4) {
		tvbuff_t *subheaders = tvb_new_subset_length(tvb,  offset, subheader_len-4);
		proto_tree *subheaders_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpudp_subheaders, NULL, "SubHeaders");
		dissect_rdp_bandwidth_req(subheaders, 0, pinfo, subheaders_tree, !!rdp_isServerAddressTarget(pinfo));
	}


	offset += subheader_len - 4;

	switch (action) {
	case RDPMT_TUNNEL_CREATE_REQ: {
		uint8_t cookie[16];
		uint32_t reqId;
		conversation_t *conv = find_or_create_conversation(pinfo);

		col_set_str(pinfo->cinfo, COL_INFO, "TunnelCreateRequest");

		subtree = proto_tree_add_subtree(tree, tvb, offset, payload_len, ett_rdpmt_create_req, NULL, "TunnelCreateRequest");
		proto_tree_add_item(subtree, hf_rdpmt_createreq_reqId, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		reqId = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(subtree, hf_rdpmt_createreq_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(subtree, hf_rdpmt_createreq_cookie, tvb, offset, 16, ENC_NA);
		tvb_memcpy(tvb, cookie, offset, 16);
		offset += 4;

		rdp_transport_set_udp_conversation(&pinfo->dst, pinfo->destport, rdpudp_is_reliable_transport(pinfo), reqId, cookie, conv);
		break;
	}
	case RDPMT_TUNNEL_CREATE_RESP:
		col_set_str(pinfo->cinfo, COL_INFO, "TunnelCreateResponse");
		subtree = proto_tree_add_subtree(tree, tvb, offset, payload_len, ett_rdpmt_create_resp, NULL, "TunnelCreateResponse");
		proto_tree_add_item(subtree, hf_rdpmt_createresp_hrResponse, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;

	case RDPMT_TUNNEL_DATA:
		if (payload_len) {
			tvbuff_t *payload = tvb_new_subset_length(tvb, offset, payload_len);
			subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpmt_data, NULL, "Data");
			call_dissector(drdynvcDissector, payload, pinfo, subtree);
		}
		break;
	}

	return offset;
}

void
proto_register_rdpmt(void) {
	/* List of fields */
	static hf_register_info hf[] = {

	  {&hf_rdpmt_action,
		{"Action", "rdpmt.action", FT_UINT8, BASE_HEX, VALS(rdpmt_action_vals), 0x0F, NULL, HFILL}
	  },
	  {&hf_rdpmt_flags,
		{"Flags", "rdpmt.flags", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
	  },
	  {&hf_rdpmt_payload_len,
		{"Payload length", "rdpmt.payloadlen", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_header_len,
		{"Header length", "rdpmt.headerlen", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_subheader_len,
		{"Sub header length", "rdpmt.subheaderlen", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_subheader_type,
		{"Sub header type", "rdpmt.subheadertype", FT_UINT8, BASE_HEX, VALS(rdpmt_subheader_type_vals), 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_createreq_reqId,
		{"RequestID", "rdpmt.createrequest.requestid", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_createreq_reserved,
		{"Reserved", "rdpmt.createrequest.reserved", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_createreq_cookie,
		{"Security cookie", "rdpmt.createrequest.cookie", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  {&hf_rdpmt_createresp_hrResponse,
		{"hrResponse", "rdpmt.createresponse.hrresponse", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL}
	  }
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_rdpmt,
		&ett_rdpudp_subheaders,
		&ett_rdpmt_create_req,
		&ett_rdpmt_create_resp,
		&ett_rdpmt_data
	};

	/* Register protocol */
	proto_rdpmt = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdpmt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rdpmt_handle = register_dissector("rdpmt", dissect_rdpmt, proto_rdpmt);
}

static bool
rdpmt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint8_t action, header_len;
	uint16_t payload_len;

	if (tvb_reported_length(tvb) <= 4)
		return false;

	action = tvb_get_uint8(tvb, 0);
	if (action > 2)
		return false;

	payload_len = tvb_get_uint16(tvb, 1, ENC_LITTLE_ENDIAN);
	header_len = tvb_get_uint8(tvb, 3);

	if ((header_len < 4UL) || (tvb_reported_length_remaining(tvb, header_len) < payload_len))
		return false;

	if (header_len > 4) {
		uint8_t subheader_len, subheader_type;

		if(header_len < 6)
			return false;

		subheader_len = tvb_get_uint8(tvb, 4);
		if ((subheader_len < 2) || (subheader_len > header_len-4))
			return false;

		subheader_type = tvb_get_uint8(tvb, 5);
		if (subheader_type > 1) /* AUTODETECT_REQUEST or AUTODETECT_RESPONSE */
			return false;
	}

	return dissect_rdpmt(tvb, pinfo, tree, data) > 0;
}

void
proto_reg_handoff_rdpmt(void)
{
	drdynvcDissector = find_dissector("rdp_drdynvc");

	heur_dissector_add("tls", rdpmt_heur, "RDP MultiTransport", "rdpmt_tls_", proto_rdpmt, true);
	heur_dissector_add("dtls", rdpmt_heur, "RDP MultiTransport", "rdpmt_dtls", proto_rdpmt, true);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

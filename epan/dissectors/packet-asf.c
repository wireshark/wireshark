/* packet-asf.c
 * Routines for ASF packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-rmcp.c
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>

/*
 * See
 *	http://www.dmtf.org/standards/standard_alert.php
 *	http://www.dmtf.org/standards/documents/ASF/DSP0136.pdf
 */

void proto_register_asf(void);
void proto_reg_handoff_asf(void);

#define RMCP_CLASS_ASF 0x06

static int proto_asf = -1;
static int hf_asf_iana = -1;
static int hf_asf_type = -1;
static int hf_asf_tag = -1;
static int hf_asf_len = -1;
static int hf_asf_rssp_status_code = -1;
static int hf_asf_mgt_console_id = -1;
static int hf_asf_client_id = -1;
static int hf_asf_payload = -1;
static int hf_asf_payload_type = -1;
static int hf_asf_payload_len = -1;
static int hf_asf_payload_data = -1;
static int hf_asf_auth_alg = -1;
static int hf_asf_integrity_alg = -1;
static int hf_asf_reserved = -1;

static gint ett_asf = -1;
static gint ett_asf_payload = -1;
static gint ett_asf_alg_payload = -1;

static expert_field ei_asf_payload_too_short = EI_INIT;


#define ASF_TYPE_RESET                  0x10
#define ASF_TYPE_PWR_UP                 0x11
#define ASF_TYPE_PWR_DOWN               0x12
#define ASF_TYPE_PWR_CYCLE              0x13
#define ASF_TYPE_PRES_PONG              0x40
#define ASF_TYPE_CAP_RESP               0x41
#define ASF_TYPE_SYS_STATE_RESP         0x42
#define ASF_TYPE_OPEN_SESS_RESP         0x43
#define ASF_TYPE_CLOSE_SESS_RESP        0x44
#define ASF_TYPE_PRES_PING              0x80
#define ASF_TYPE_CAP_RQST               0x81
#define ASF_TYPE_SYS_STATE_RQST         0x82
#define ASF_TYPE_OPEN_SESS_RQST         0x83
#define ASF_TYPE_CLOSE_SESS_RQST        0x84
#define ASF_TYPE_RAKP_MSG_1             0xC0
#define ASF_TYPE_RAKP_MSG_2             0xC1
#define ASF_TYPE_RAKP_MSG_3             0xC2

static const value_string asf_type_vals[] = {
	{ ASF_TYPE_RESET,           "Reset" },
	{ ASF_TYPE_PWR_UP,          "Power-up" },
	{ ASF_TYPE_PWR_DOWN,        "Unconditional Power-down" },
	{ ASF_TYPE_PWR_CYCLE,       "Power Cycle" },
	{ ASF_TYPE_PRES_PONG,       "Presence Pong" },
	{ ASF_TYPE_CAP_RESP,        "Capabilities Response" },
	{ ASF_TYPE_SYS_STATE_RESP,  "System State Response" },
	{ ASF_TYPE_OPEN_SESS_RESP,  "Open Session Response" },
	{ ASF_TYPE_CLOSE_SESS_RESP, "Close Session Response" },
	{ ASF_TYPE_PRES_PING,       "Presence Ping" },
	{ ASF_TYPE_CAP_RQST,        "Capabilities Request" },
	{ ASF_TYPE_SYS_STATE_RQST,  "System State Request" },
	{ ASF_TYPE_OPEN_SESS_RQST,  "Open Session Request" },
	{ ASF_TYPE_CLOSE_SESS_RQST, "Close Session Request" },
	{ ASF_TYPE_RAKP_MSG_1,      "RAKP Message 1" },
	{ ASF_TYPE_RAKP_MSG_2,      "RAKP Message 2" },
	{ ASF_TYPE_RAKP_MSG_3,      "RAKP Message 3" },
	{ 0x00, NULL }
};

static const value_string asf_rssp_status_code_vals[] = {
	{ 0x00, "No errors" },
	{ 0x01, "Insufficient resources to create a session" },
	{ 0x02, "Invalid session ID" },
	{ 0x03, "Invalid payload type" },
	{ 0x04, "Invalid authentication algorithm" },
	{ 0x05, "Invalid integrity algorithm" },
	{ 0x06, "No matching authentication payload" },
	{ 0x07, "No matching integrity payload" },
	{ 0x00, NULL }
};

#define ASF_PAYLOAD_TYPE_NONE           0x00
#define ASF_PAYLOAD_TYPE_AUTHENTICATION 0x01
#define ASF_PAYLOAD_TYPE_INTEGRITY      0x02

static const value_string asf_payload_type_vals[] = {
	{ ASF_PAYLOAD_TYPE_NONE,           "No payload present (end of list)" },
	{ ASF_PAYLOAD_TYPE_AUTHENTICATION, "Authentication algorithm payload" },
	{ ASF_PAYLOAD_TYPE_INTEGRITY,      "Integrity algorithm payload" },
	{ 0x00, NULL }
};

static const value_string asf_authentication_type_vals[] = {
	{ 0x01, "RAKP-HMAC-SHA1" },
	{ 0x00, NULL }
};

static const value_string asf_integrity_type_vals[] = {
	{ 0x01, "HMAC-SHA1-96" },
	{ 0x00, NULL }
};

static void dissect_asf_open_session_request(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, gint len);
static void dissect_asf_open_session_response(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, gint len);
static void dissect_asf_payloads(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, gint len);
static void dissect_asf_payload_authentication(tvbuff_t *tvb, proto_tree *tree,
	gint offset, gint len);
static void dissect_asf_payload_integrity(tvbuff_t *tvb, proto_tree *tree,
	gint offset, gint len);

static int
dissect_asf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree *asf_tree = NULL;
	proto_item *ti;
	guint8      type;
	guint8      len;
	tvbuff_t   *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ASF");

	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 4);
	len = tvb_get_guint8(tvb, 7);

	col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(type, asf_type_vals, "Unknown (0x%02x)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_asf, tvb, 0, 8,ENC_NA);
		asf_tree = proto_item_add_subtree(ti, ett_asf);
		proto_tree_add_item(asf_tree, hf_asf_iana, tvb, 0, 4,ENC_BIG_ENDIAN);
		proto_tree_add_item(asf_tree, hf_asf_type, tvb, 4, 1,ENC_BIG_ENDIAN);
		proto_tree_add_item(asf_tree, hf_asf_tag, tvb, 5, 1,ENC_BIG_ENDIAN);
		proto_tree_add_item(asf_tree, hf_asf_len, tvb, 7, 1,ENC_BIG_ENDIAN);
	}

	if (len) {
		switch(type) {
		case ASF_TYPE_OPEN_SESS_RQST:
			dissect_asf_open_session_request(tvb, pinfo, asf_tree, 8, len);
			break;
		case ASF_TYPE_OPEN_SESS_RESP:
			dissect_asf_open_session_response(tvb, pinfo, asf_tree, 8, len);
			break;

		/* TODO: Add the rest as captures become available to test. */

		default:
			next_tvb = tvb_new_subset_length(tvb, 8, len);
			call_data_dissector(next_tvb, pinfo, tree);
			break;
		}
	}
	return 8 + len;
}

static void
dissect_asf_open_session_request(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, gint len)
{
	proto_tree_add_item(tree, hf_asf_mgt_console_id, tvb, offset, 4,ENC_BIG_ENDIAN);
	offset += 4;
	len    -= 4;
	dissect_asf_payloads(tvb, pinfo, tree, offset, len);
}

static void
dissect_asf_open_session_response(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, gint len)
{
	proto_tree_add_item(tree, hf_asf_rssp_status_code, tvb, offset, 1,ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_asf_mgt_console_id, tvb, offset + 4, 4,ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_asf_client_id, tvb, offset + 8, 4,ENC_BIG_ENDIAN);
	offset += 12;
	len    -= 12;
	dissect_asf_payloads(tvb, pinfo, tree, offset, len);
}

static void
dissect_asf_payloads(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint offset, gint len)
{
	guint8      ptype;
	guint16     plen;
	proto_item *ti;
	proto_tree *ptree;

	while ( len >= 4 )
	{
		ptype = tvb_get_guint8(tvb, offset);
		plen = tvb_get_ntohs(tvb, offset + 2);

		ti = proto_tree_add_none_format(tree, hf_asf_payload, tvb, offset,
			plen, "%s: %u bytes",
			val_to_str(ptype, asf_payload_type_vals, "Unknown (%u)"), plen);
		ptree = proto_item_add_subtree(ti, ett_asf_payload);
		proto_tree_add_item(ptree, hf_asf_payload_type, tvb, offset, 1,ENC_BIG_ENDIAN);
		ti = proto_tree_add_item(ptree, hf_asf_payload_len, tvb, offset + 2, 2,ENC_BIG_ENDIAN);
		if (plen < 4)
		{
			expert_add_info(pinfo, ti, &ei_asf_payload_too_short);
			break;
		}
		if ( ptype && (plen > 4) )
		{
			switch ( ptype )
			{
				case ASF_PAYLOAD_TYPE_AUTHENTICATION:
					dissect_asf_payload_authentication(tvb, ptree,
						offset + 4, plen - 4);
					break;
				case ASF_PAYLOAD_TYPE_INTEGRITY:
					dissect_asf_payload_integrity(tvb, ptree,
						offset + 4, plen - 4);
					break;
				default:
					proto_tree_add_item(ptree, hf_asf_payload_data, tvb,
						offset + 4, plen - 4,ENC_NA);
					break;
			}
		}
		offset += plen;
		len    -= plen;
	}
}

static void
dissect_asf_payload_authentication(tvbuff_t *tvb, proto_tree *tree,
	gint offset, gint len)
{
	guint8      alg;
	proto_item *ti;
	proto_tree *atree;

	alg = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_none_format(tree, hf_asf_payload_data, tvb, offset,
		len, "Authentication Algorithm: %s",
		val_to_str(alg, asf_authentication_type_vals, "Unknown (%u)"));
	atree = proto_item_add_subtree(ti, ett_asf_alg_payload);
	proto_tree_add_item(atree, hf_asf_auth_alg, tvb, offset, 1,ENC_BIG_ENDIAN);
	proto_tree_add_item(atree, hf_asf_reserved, tvb, offset + 1, len - 1,ENC_NA);
}

static void
dissect_asf_payload_integrity(tvbuff_t *tvb, proto_tree *tree,
	gint offset, gint len)
{
	guint8      alg;
	proto_item *ti;
	proto_tree *atree;

	alg = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_none_format(tree, hf_asf_payload_data, tvb, offset,
		len, "Integrity Algorithm: %s",
		val_to_str(alg, asf_integrity_type_vals, "Unknown (%u)"));
	atree = proto_item_add_subtree(ti, ett_asf_alg_payload);
	proto_tree_add_item(atree, hf_asf_integrity_alg, tvb, offset, 1,ENC_BIG_ENDIAN);
	proto_tree_add_item(atree, hf_asf_reserved, tvb, offset + 1, len - 1,ENC_NA);
}

void
proto_register_asf(void)
{
	static hf_register_info hf[] = {
		{ &hf_asf_iana, {
			"IANA Enterprise Number", "asf.iana",
			FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0,
			NULL, HFILL }},
		{ &hf_asf_type, {
			"Message Type", "asf.type",
			FT_UINT8, BASE_HEX, VALS(asf_type_vals), 0,
			"ASF Message Type", HFILL }},
		{ &hf_asf_tag, {
			"Message Tag", "asf.tag",
			FT_UINT8, BASE_HEX, NULL, 0,
			"ASF Message Tag", HFILL }},
		{ &hf_asf_len, {
			"Data Length", "asf.len",
			FT_UINT8, BASE_DEC, NULL, 0,
			"ASF Data Length", HFILL }},
		{ &hf_asf_rssp_status_code, {
			"Status Code", "asf.rssp_status_code",
			FT_UINT8, BASE_DEC, VALS(asf_rssp_status_code_vals), 0,
			"Identifies the status of the previous message", HFILL }},
		{ &hf_asf_mgt_console_id, {
			"Mgt Console Session ID", "asf.mgt_console_id",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_asf_client_id, {
			"Managed Client Session ID", "asf.client_id",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_asf_payload, {
			"Payload", "asf.payload",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_asf_payload_type, {
			"Payload Type", "asf.payload.type",
			FT_UINT8, BASE_DEC, VALS(asf_payload_type_vals), 0,
			"Identifies the type of payload that follows", HFILL }},
		{ &hf_asf_payload_len, {
			"Payload Length", "asf.payload.len",
			FT_UINT16, BASE_DEC, NULL, 0,
			"The total length in bytes of the payload including the header",
			HFILL }},
		{ &hf_asf_payload_data, {
			"Data", "asf.payload.data",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_asf_auth_alg, {
			"Authentication Algorithm", "asf.auth_alg",
			FT_UINT8, BASE_DEC, VALS(asf_authentication_type_vals), 0,
			NULL, HFILL }},
		{ &hf_asf_integrity_alg, {
			"Integrity Algorithm", "asf.integrity_alg",
			FT_UINT8, BASE_DEC, VALS(asf_integrity_type_vals), 0,
			NULL, HFILL }},
		{ &hf_asf_reserved, {
			"Reserved", "asf.reserved",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_asf,
		&ett_asf_payload,
		&ett_asf_alg_payload
	};

	static ei_register_info ei[] = {
		{ &ei_asf_payload_too_short, { "asf.payload_too_short", PI_MALFORMED, PI_ERROR, "Payload length too short to include the type and length", EXPFILL }},
	};

	expert_module_t* expert_asf;

	proto_asf = proto_register_protocol(
		"Alert Standard Forum", "ASF", "asf");

	proto_register_field_array(proto_asf, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_asf = expert_register_protocol(proto_asf);
	expert_register_field_array(expert_asf, ei, array_length(ei));
}

void
proto_reg_handoff_asf(void)
{
	dissector_handle_t asf_handle;

	asf_handle  = create_dissector_handle(dissect_asf, proto_asf);
	dissector_add_uint("rmcp.class", RMCP_CLASS_ASF, asf_handle);
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

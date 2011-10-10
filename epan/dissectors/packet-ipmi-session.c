/* packet-ipmi-session.c
 * Routines for dissection of IPMI session wrapper (v1.5 and v2.0)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
 * Copyright Duncan Laurie <duncan@sun.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Partially copied from packet-ipmi.c.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#define RMCP_CLASS_IPMI 0x07

static int proto_ipmi_session = -1;

static gint ett_ipmi_session = -1;
static gint ett_ipmi_session_payloadtype = -1;

/* IPMI session header */
static int hf_ipmi_session_id = -1;
static int hf_ipmi_session_authtype = -1;
static int hf_ipmi_session_payloadtype = -1;
static int hf_ipmi_session_payloadtype_auth = -1;
static int hf_ipmi_session_payloadtype_enc = -1;
static int hf_ipmi_session_oem_iana = -1;
static int hf_ipmi_session_oem_payload_id = -1;
static int hf_ipmi_session_sequence = -1;
static int hf_ipmi_session_authcode = -1;
static int hf_ipmi_session_msg_len_1b = -1;
static int hf_ipmi_session_msg_len_2b = -1;
static int hf_ipmi_session_trailer = -1;

static dissector_handle_t ipmi_handle;
static dissector_handle_t data_handle;

#define IPMI_AUTH_NONE		0x00
#define IPMI_AUTH_MD2		0x01
#define IPMI_AUTH_MD5		0x02
#define IPMI_AUTH_PASSWORD	0x04
#define IPMI_AUTH_OEM		0x05
#define IPMI_AUTH_RMCPP		0x06

static const value_string ipmi_authtype_vals[] = {
	{ IPMI_AUTH_NONE,	"NONE" },
	{ IPMI_AUTH_MD2,	"MD2" },
	{ IPMI_AUTH_MD5,	"MD5" },
	{ IPMI_AUTH_PASSWORD,	"PASSWORD" },
	{ IPMI_AUTH_OEM,	"OEM" },
	{ IPMI_AUTH_RMCPP,	"RMCP+"},
	{ 0x00,	NULL }
};

#define IPMI_IPMI_MESSAGE	0
#define IPMI_OEM_EXPLICIT	2

static const value_string ipmi_payload_vals[] = {
	{ IPMI_IPMI_MESSAGE,	"IPMI Message" },
	{ 0x01,	"SOL (serial over LAN)" },
	{ IPMI_OEM_EXPLICIT,	"OEM Explicit" },
	/* Session Setup Payload Types */
	{ 0x10,	"RMCP+ Open Session Request" },
	{ 0x11,	"RMCP+ Open Session Response" },
	{ 0x12,	"RAKP Message 1" },
	{ 0x13,	"RAKP Message 2" },
	{ 0x14,	"RAKP Message 3" },
	{ 0x15,	"RAKP Message 4" },
	/* OEM Payload Type Handles */
	{ 0x20,	"OEM0 (OEM Payload)" },
	{ 0x21,	"OEM1 (OEM Payload)" },
	{ 0x22,	"OEM2 (OEM Payload)" },
	{ 0x23,	"OEM3 (OEM Payload)" },
	{ 0x24,	"OEM4 (OEM Payload)" },
	{ 0x25,	"OEM5 (OEM Payload)" },
	{ 0x26,	"OEM6 (OEM Payload)" },
	{ 0x27,	"OEM7 (OEM Payload)" },
	{ 0x00,	NULL }
};

static const true_false_string ipmi_payload_aut_val  = {
  "Payload is authenticated",
  "Payload is unauthenticated"
};

static const true_false_string ipmi_payload_enc_val  = {
  "Payload is encrypted",
  "Payload is unencrypted"
};

static int
dissect_ipmi_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sess_tree = NULL, *s_tree;
	proto_item	*ti = NULL;
	tvbuff_t	*next_tvb;
	guint32		session_id;
	guint8		authtype, payloadtype = 0;
	guint32		msg_start, msg_len, offset = 0;
	gboolean	payloadtype_auth = 0, payloadtype_enc = 0;

	/* session authtype, 0=no authcode present, 6=RMCP+ */
	authtype = tvb_get_guint8(tvb, 0);
	if (authtype == IPMI_AUTH_RMCPP) {
		/* Fetch additional info before trying to interpret
		   the packet. It may not be IPMI at all! */
		payloadtype = tvb_get_guint8(tvb, 1);
		payloadtype_auth = (payloadtype >> 6) & 1;
		payloadtype_enc = (payloadtype >> 7);
		payloadtype &= 0x3f;

		/* IPMI v2.0 packets have session ID BEFORE the session
		   sequence number; just after authentification and payload
		   types. The OEM Explicit payload type has 6 more bytes
		   (IANA + Payload ID) before the session ID. */
		if (payloadtype == IPMI_OEM_EXPLICIT) {
			session_id = tvb_get_letohl(tvb, 8);
			msg_start = 18;
			msg_len = tvb_get_letohs(tvb, 16);
		} else {
			session_id = tvb_get_letohl(tvb, 2);
			msg_start = 12;
			msg_len = tvb_get_letohs(tvb, 10);
		}
	} else {
		/* IPMI v1.5 packets have session ID AFTER the session
		   sequence number. They also have 1 byte for payload
		   message length. */
		session_id = tvb_get_letohl(tvb, 5);
		if (authtype == IPMI_AUTH_NONE) {
			msg_start = 10;
			msg_len = tvb_get_guint8(tvb, 9);
		} else {
			msg_start = 26;
			msg_len = tvb_get_guint8(tvb, 25);
		}
	}

	/* Later it will be overridden with sub-dissector, if any */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		if (authtype == IPMI_AUTH_RMCPP) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMCP+");
		} else {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPMI");
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Session ID 0x%x", session_id);
		if (authtype == IPMI_AUTH_RMCPP) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", payload type: %s",
					val_to_str(payloadtype, ipmi_payload_vals, "Unknown"));
		}
	}

	if (tree) {
		offset = 0;
		ti = proto_tree_add_protocol_format(tree, proto_ipmi_session,
				tvb, 0, tvb_length(tvb),
				"IPMI v%s Session Wrapper, session ID 0x%x",
				authtype == IPMI_AUTH_RMCPP ? "2.0+" : "1.5",
				session_id);
		sess_tree = proto_item_add_subtree(ti, ett_ipmi_session);
		proto_tree_add_item(sess_tree, hf_ipmi_session_authtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		if (authtype == IPMI_AUTH_RMCPP) {
			/* IPMI v2.0+ */
			ti = proto_tree_add_text(sess_tree, tvb, offset, 1,
					"Payload type: %s (0x%02x), %sencrypted, %sauthenticated",
					val_to_str(payloadtype, ipmi_payload_vals, "Unknown"),
					payloadtype,
					payloadtype_enc ? "" : "not ",
					payloadtype_auth ? "" : "not ");
			s_tree = proto_item_add_subtree(ti, ett_ipmi_session_payloadtype);
			proto_tree_add_item(s_tree, hf_ipmi_session_payloadtype_enc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(s_tree, hf_ipmi_session_payloadtype_auth, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(s_tree, hf_ipmi_session_payloadtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;

			if (payloadtype == IPMI_OEM_EXPLICIT) {
				proto_tree_add_item(sess_tree, hf_ipmi_session_oem_iana, tvb, offset, 4, ENC_NA);
				offset += 4;
				proto_tree_add_item(sess_tree, hf_ipmi_session_oem_payload_id, tvb, offset, 2, ENC_NA);
				offset += 2;
			}
			proto_tree_add_item(sess_tree, hf_ipmi_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(sess_tree, hf_ipmi_session_sequence, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(sess_tree, hf_ipmi_session_msg_len_2b, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		} else {
			/* IPMI v1.5 */
			proto_tree_add_item(sess_tree, hf_ipmi_session_sequence, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(sess_tree, hf_ipmi_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			if (authtype != IPMI_AUTH_NONE) {
				proto_tree_add_item(sess_tree, hf_ipmi_session_authcode,
						tvb, offset, 16, ENC_NA);
				offset += 16;
			}
			proto_tree_add_item(sess_tree, hf_ipmi_session_msg_len_1b, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
	}

	/* If we can parse the embedded message, do so */
	next_tvb = tvb_new_subset(tvb, msg_start, msg_len, -1);
	if (payloadtype_enc) {
		/* This is RMCP+, and payload is encrypted. In this case,
		   there is a 'confidentiality header/trailer', whose lengths
		   are unknown to us. These lengths are negotiated during
		   session open process and are retained over a session.
		   Since we are stateless (and more, we may have no session
		   open packet in the capture we parse), we cannot even
		   decipher where a message starts. Just print them as data.
		 */
		call_dissector(data_handle, next_tvb, pinfo, tree);
	} else if (authtype != IPMI_AUTH_RMCPP || payloadtype == IPMI_IPMI_MESSAGE) {
		/* This is an IPMI message, either v1.5 or v2.0+. For now,
		   we don't need to distinguish these kinds. */
		call_dissector(ipmi_handle, next_tvb, pinfo, tree);
	} else {
		/* All other RMCP+ payload types fall here: session open/close
		   requests, RAKP messages, SOL. We cannot parse them yet, thus
		   just output as data. */
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}

	if (tree) {
		/* Account for the message we just parsed. */
		offset += msg_len;

		/* Show the rest of the session wrapper as binary data */
		if (offset < tvb_length(tvb)) {
			proto_tree_add_item(sess_tree, hf_ipmi_session_trailer,
					tvb, offset, tvb_length(tvb) - offset, ENC_NA);
		}
	}
	return tvb_length(tvb);
}

void
proto_register_ipmi_session(void)
{
	static hf_register_info hf[] = {
		{ &hf_ipmi_session_authtype, {
			"Authentication Type", "ipmi.session.authtype",
			FT_UINT8, BASE_HEX, VALS(ipmi_authtype_vals), 0, NULL, HFILL }},
		{ &hf_ipmi_session_payloadtype,{
			"Payload Type", "ipmi.session.payloadtype",
			FT_UINT8, BASE_HEX, VALS(ipmi_payload_vals), 0x3f, NULL, HFILL }},
		{ &hf_ipmi_session_payloadtype_auth,{
			"Authenticated","ipmi.session.payloadtype.auth",
			FT_BOOLEAN,8,  TFS(&ipmi_payload_aut_val), 0x40, NULL, HFILL }},
		{ &hf_ipmi_session_payloadtype_enc,{
			"Encryption","ipmi.session.payloadtype.enc",
			FT_BOOLEAN,8,  TFS(&ipmi_payload_enc_val), 0x80, NULL, HFILL }},
		{ &hf_ipmi_session_oem_iana, {
			"OEM IANA", "ipmi.session.oem.iana",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_oem_payload_id, {
			"OEM Payload ID", "ipmi.session.oem.payloadid",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_sequence, {
			"Session Sequence Number", "ipmi.session.sequence",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_id, {
			"Session ID", "ipmi.session.id",
			FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_authcode, {
			"Authentication Code", "ipmi.session.authcode",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_msg_len_1b, {
			"Message Length", "ipmi.msg.len",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_msg_len_2b, {
			"Message Length", "ipmi.msg.len",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ipmi_session_trailer, {
			"IPMI Session Wrapper (trailer)", "ipmi.sess.trailer",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = { &ett_ipmi_session, &ett_ipmi_session_payloadtype };

	proto_ipmi_session = proto_register_protocol(
			"Intelligent Platform Management Interface (Session Wrapper)", "IPMI Session",
			"ipmi-session");
	proto_register_field_array(proto_ipmi_session, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipmi_session(void)
{
	dissector_handle_t ipmi_session_handle;

	ipmi_session_handle = new_create_dissector_handle(dissect_ipmi_session, proto_ipmi_session);
	dissector_add_uint("rmcp.class", RMCP_CLASS_IPMI, ipmi_session_handle);

	data_handle = find_dissector("data");
	ipmi_handle = find_dissector("ipmi");
}

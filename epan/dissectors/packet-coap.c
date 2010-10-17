/* packet-coap.c
 * Routines for COAP packet disassembly
 * Shoichi Sakane <sakane@tanu.org>
 *
 * $Id$
 * draft-core-coap-02.txt
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>

static dissector_table_t media_type_dissector_table;

static int proto_coap = -1;

static int hf_coap_version		= -1;
static int hf_coap_ttype		= -1;
static int hf_coap_opt_count		= -1;
static int hf_coap_code			= -1;
static int hf_coap_tid			= -1;
static int hf_coap_opt_type		= -1;
static int hf_coap_opt_delta		= -1;
static int hf_coap_opt_length		= -1;
static int hf_coap_opt_ctype		= -1;
static int hf_coap_opt_max_age		= -1;
static int hf_coap_opt_uri_scheme	= -1;
static int hf_coap_opt_etag		= -1;
static int hf_coap_opt_uri_authority	= -1;
static int hf_coap_opt_location		= -1;
static int hf_coap_opt_uri_path		= -1;
static int hf_coap_payload		= -1;

static gint ett_coap			= -1;
static gint ett_coap_noop		= -1;
static gint ett_coap_ctype		= -1;
static gint ett_coap_max_age		= -1;
static gint ett_coap_uri_scheme		= -1;
static gint ett_coap_etag		= -1;
static gint ett_coap_uri_authority	= -1;
static gint ett_coap_location		= -1;
static gint ett_coap_uri_path		= -1;
static gint ett_coap_payload		= -1;

/* TODO: COAP port number will be assigned by IANA after the draft become a RFC */
#define DEFAULT_COAP_PORT	61616

static const gchar *coap_content_type = NULL;
static guint global_coap_port_number = DEFAULT_COAP_PORT;

/*
 * Transaction Type
 */
static const value_string vals_ttype[] = {
	{ 0, "Confirmable" },
	{ 1, "Non-Confirmable" },
	{ 2, "Acknowledgement" },
	{ 3, "Reset" },
	{ 0, NULL },
};

/*
 * Method Code
 * Response Code
 */
static const value_string vals_code[] = {
	/* method code */
	{ 1, "GET" },
	{ 2, "POST" },
	{ 3, "PUT" },
	{ 4, "DELETE" },

	/* response code */
	{ 40,  "100 Continue" },
	{ 80,  "200 OK"},
	{ 81,  "201 Created"},
	{ 124, "304 Not Modified"},
	{ 160, "400 Bad Request"},
	{ 164, "404 Not Found"},
	{ 165, "405 Method Not Allowed"},
	{ 175, "415 Unsupported Media Type"},
	{ 200, "500 Internal Server Error"},
	{ 202, "502 Bad Gateway"},
	{ 203, "503 Service Unavailable"},
	{ 204, "504 Gateway Timeout"},
	{ 0, NULL },
};

/*
 * Option Headers
 * No-Option must not be included in this structure, is handled in the function
 * of the dissector, especially.
 */
#define COAP_OPT_CONTENT_TYPE	1
#define COAP_OPT_MAX_AGE	2
#define COAP_OPT_ETAG		4
#define COAP_OPT_URI_AUTHORITY	5
#define COAP_OPT_LOCATION	6
#define COAP_OPT_URI_PATH	9

static const value_string vals_opt_type[] = {
	{ COAP_OPT_CONTENT_TYPE, "Content-Type" },
	{ COAP_OPT_MAX_AGE, "Max-age"},
	{ COAP_OPT_ETAG, "Etag"},
	{ COAP_OPT_URI_AUTHORITY, "Uri-Authority"},
	{ COAP_OPT_LOCATION, "Location"},
	{ COAP_OPT_URI_PATH, "Uri-Path"},
	{ 0, NULL },
};

static const value_string vals_ctype[] = {
	{ 0, "text/plain (UTF-8)" },
	{ 1, "text/xml (UTF-8)" },
	{ 2, "text/csv (UTF-8)" },
	{ 3, "text/html (UTF-8)" },
	{ 21, "image/gif" },
	{ 22, "image/jpeg" },
	{ 23, "image/png" },
	{ 24, "image/tiff" },
	{ 25, "audio/raw" },
	{ 26, "video/raw" },
	{ 40, "application/link-format" },
	{ 41, "application/xml" },
	{ 42, "application/octet-stream" },
	{ 43, "application/rdf+xml" },
	{ 44, "application/soap+xml" },
	{ 45, "application/atom+xml" },
	{ 46, "application/xmpp+xml" },
	{ 47, "application/exi" },
	{ 48, "application/x-bxml" },
	{ 49, "application/fastinfoset" },
	{ 50, "application/soap+fastinfoset" },
	{ 51, "application/json" },
	{ 0, NULL },
};

void proto_reg_handoff_coap(void);

/*
 * dissector for each option of COAP.
 * return the total length of the option including the header (e.g. delta and length).
 */
static int
dissect_coap_options(tvbuff_t *tvb, proto_tree *coap_tree, proto_tree *parent_tree _U_, int offset, guint8 *opt_code)
{
	guint8 opt_delta;
	guint32 opt_ctype = 0;
	guint opt_max_age = 0;
	gint opt_length;
	proto_tree *subtree = NULL;
	proto_item *item = NULL;
	int opt_hlen = 0;

	opt_delta = (tvb_get_guint8(tvb, offset) & 0xf0) >> 4;
	*opt_code += opt_delta;
	opt_length = (tvb_get_guint8(tvb, offset) & 0x0f);
	opt_hlen = 1;
	if (opt_length == 0x0f) {
		opt_length += tvb_get_guint8(tvb, offset + 1);
		opt_hlen = 2;
	}
	item = proto_tree_add_uint_format(coap_tree, hf_coap_opt_type, tvb, offset, 1, *opt_code,
	    "Option (Length: %u) %s",
	    opt_length, val_to_str(*opt_code, vals_opt_type, "Unknown Option Type"));
	offset += opt_hlen;

	/* if opt_code is a multiple of 14, that means the option is a noop option */
	if (*opt_code % 14 == 0) {
		subtree = proto_item_add_subtree(item, ett_coap_noop);
		proto_tree_add_text(subtree, tvb, 0, 0, "No-Op option");
	} else {
		switch (*opt_code) {
		case COAP_OPT_CONTENT_TYPE:
			subtree = proto_item_add_subtree(item, ett_coap_ctype);
			opt_ctype = tvb_get_guint8(tvb, offset);
			coap_content_type = val_to_str(opt_ctype, vals_code, "Unknown %d");
			proto_tree_add_item(subtree, hf_coap_opt_ctype, tvb, offset, opt_length, FALSE);
			break;
		case COAP_OPT_MAX_AGE:
			subtree = proto_item_add_subtree(item, ett_coap_max_age);
			switch (opt_length) {
			case 1:
				opt_max_age = (guint)tvb_get_guint8(tvb, offset);
				break;
			case 2:
				opt_max_age = (guint)tvb_get_ntohs(tvb, offset);
				break;
			case 3:
				opt_max_age = (guint)tvb_get_ntoh24(tvb, offset);
				break;
			case 4:
				opt_max_age = (guint)tvb_get_ntohl(tvb, offset);
				break;
			default:
				proto_tree_add_text(subtree, tvb, 0, 0, "Invalid length: %d", opt_length);
				break;
			}
			proto_tree_add_item(subtree, hf_coap_opt_max_age, tvb, offset, opt_length, FALSE);
			break;
		case COAP_OPT_ETAG:
			subtree = proto_item_add_subtree(item, ett_coap_etag);
			proto_tree_add_item(subtree, hf_coap_opt_etag, tvb, offset, opt_length, FALSE);
			break;
		case COAP_OPT_URI_AUTHORITY:
			subtree = proto_item_add_subtree(item, ett_coap_uri_authority);
			proto_tree_add_item(subtree, hf_coap_opt_uri_authority, tvb, offset, opt_length, FALSE);
			break;
		case COAP_OPT_LOCATION:
			subtree = proto_item_add_subtree(item, ett_coap_location);
			proto_tree_add_item(subtree, hf_coap_opt_location, tvb, offset, opt_length, FALSE);
			break;
		case COAP_OPT_URI_PATH:
			subtree = proto_item_add_subtree(item, ett_coap_uri_path);
			proto_tree_add_item(subtree, hf_coap_opt_uri_path, tvb, offset, opt_length, FALSE);
			break;
		default:
			proto_tree_add_text(subtree, tvb, 0, 0, "Unkown Option Type");
		}
	}
	return offset + opt_length;
}

static void
dissect_coap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint offset = 0;
	proto_item *coap_root = NULL;
	proto_tree *coap_tree = NULL;
	guint8 ttype = 0;
	guint8 opt_count = 0;
	guint8 code = 0;
	guint16 tid = 0;
	guint coap_length = pinfo->iplen - pinfo->iphdrlen - 8;
	guint8 opt_code = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "COAP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (!parent_tree)
		return;

	coap_root = proto_tree_add_item(parent_tree, proto_coap, tvb, offset, -1, FALSE);
	coap_tree = proto_item_add_subtree(coap_root, ett_coap);

	proto_tree_add_item(coap_tree, hf_coap_version, tvb, offset, 1, FALSE);

	proto_tree_add_item(coap_tree, hf_coap_ttype, tvb, offset, 1, FALSE);
	ttype = (tvb_get_guint8(tvb, offset) & 0x30) >> 4;
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(ttype, vals_ttype, "Unknown %d"));

	proto_tree_add_item(coap_tree, hf_coap_opt_count, tvb, offset, 1, FALSE);
	opt_count = tvb_get_guint8(tvb, offset) & 0x0f;
	offset += 1;

	proto_tree_add_item(coap_tree, hf_coap_code, tvb, offset, 1, FALSE);
	code = tvb_get_guint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(code, vals_code, "Unknown %d"));
	offset += 1;

	proto_tree_add_item(coap_tree, hf_coap_tid, tvb, offset, 2, FALSE);
	tid = tvb_get_ntohs(tvb, offset);
	offset += 2;

	/* append the header information */
	proto_item_append_text(coap_tree, ", TID: %u, Length: %u", tid, coap_length);

	/* dissect the options */
	while (opt_count--) {
		offset = dissect_coap_options(tvb, coap_tree, parent_tree, offset, &opt_code);
		if (coap_length < offset) {
			/* error */
			proto_tree_add_text(coap_tree, tvb, 0, 0, "invalid length: coap_length(%d) < offset(%d)", coap_length, offset);
			return;
		}
	}

	/* dissect the payload */
	if (coap_length > offset) {
		proto_tree *payload_tree = NULL;
		proto_item *payload_item = NULL;
		tvbuff_t *payload_tvb;
		guint payload_length = coap_length - offset;
		char *ctype_str_default = "";
		gboolean result = TRUE;

		/*
		 * TODO:
		 * currently, coap_content_type is used to distinguish whether
		 * the content-type was specified.  If we need to properly handle
		 * the case when the type was unknown, we need another flag.
		 */
		if (coap_content_type == NULL) {
			/* default: coap-02 section 3.2.1 */
			/* when it's NULL, "text/plain" is set anyway */
			coap_content_type = "text/plain";
			ctype_str_default = "(as default)";
		}
		/*
		 * TODO: should the content type be canonicalized,
		 * currently assuming it be small ?
		 */

		payload_item = proto_tree_add_text(coap_tree, tvb, offset, -1, "Payload Content-Type: %s%s, Length: %u, offset: %u",
		    coap_content_type, ctype_str_default, payload_length, offset);
		payload_tree = proto_item_add_subtree(payload_item, ett_coap_payload);
		payload_tvb = tvb_new_subset(tvb, offset, payload_length, payload_length);

		result = dissector_try_string(media_type_dissector_table, coap_content_type, payload_tvb, pinfo, payload_tree);
		if (!result) {
			/* TODO: call heuristic dissector */
			;
		}
	}
}

/*
 * Protocol initialization
 */
void
proto_register_coap(void)
{
	static hf_register_info hf[] = {
	    { &hf_coap_version, { "Version", "coap.version", FT_UINT8, BASE_DEC, NULL, 0xc0, "COAP Version", HFILL }},
	    { &hf_coap_ttype, { "Type", "coap.type", FT_UINT8, BASE_DEC, VALS(&vals_ttype), 0x30, "COAP Transaction Type", HFILL }},
	    { &hf_coap_opt_count, { "Option Count", "coap.optcount", FT_UINT8, BASE_DEC, NULL, 0x0f, "COAP Option Count", HFILL }},
	    { &hf_coap_code, { "Code", "coap.code", FT_UINT8, BASE_DEC, VALS(&vals_code), 0x0, "COAP Method or Response Code", HFILL }},
	    { &hf_coap_tid, { "Transaction ID", "coap.tid", FT_UINT16, BASE_DEC, NULL, 0x0, "COAP Transaction ID", HFILL }},
	    { &hf_coap_opt_type, { "Option Type", "coap.opt.opt_type", FT_UINT8, BASE_DEC, VALS(&vals_opt_type), 0x0, "COAP Option Type", HFILL }},
	    { &hf_coap_opt_delta, { "Option Delta", "coap.opt.delta", FT_UINT8, BASE_DEC, NULL, 0x0, "COAP Option Delta", HFILL }},
	    { &hf_coap_opt_length, { "Option Length", "coap.opt.length", FT_UINT16, BASE_DEC, NULL, 0x0, "COAP Option Length", HFILL }},
	    { &hf_coap_opt_ctype, { "Content-type", "coap.opt.ctype", FT_UINT8, BASE_DEC, VALS(&vals_ctype), 0x0, "COAP Media Type", HFILL }},
	    { &hf_coap_opt_max_age, { "Max-age", "coap.opt.maxage", FT_UINT32, BASE_DEC, NULL, 0x0, "COAP Max-age", HFILL }},
	    { &hf_coap_opt_uri_scheme, { "Uri-Scheme", "coap.opt.uri_scheme", FT_STRING, BASE_NONE, NULL, 0x0, "COAP Max-age", HFILL }},
	    { &hf_coap_opt_etag, { "Etag", "coap.opt.etag", FT_BYTES, BASE_NONE, NULL, 0x0, "COAP Etag", HFILL }},
	    { &hf_coap_opt_uri_authority, { "Uri-Authority", "coap.opt.uri_auth", FT_STRING, BASE_NONE, NULL, 0x0, "COAP Uri-Authority", HFILL }},
	    { &hf_coap_opt_location, { "Location", "coap.opt.location", FT_STRING, BASE_NONE, NULL, 0x0, "COAP Location", HFILL }},
	    { &hf_coap_opt_uri_path, { "Uri-Path", "coap.opt.uri_path", FT_STRING, BASE_NONE, NULL, 0x0, "COAP Uri-Path", HFILL }},
	    { &hf_coap_payload, { "Payload", "coap.opt.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "COAP Payload", HFILL }},
	};

	static gint *ett[] = {
		&ett_coap,
		&ett_coap_ctype,
		&ett_coap_max_age,
		&ett_coap_uri_scheme,
		&ett_coap_etag,
		&ett_coap_uri_authority,
		&ett_coap_location,
		&ett_coap_uri_path,
		&ett_coap_payload,
	};

	module_t *coap_module;

	proto_coap = proto_register_protocol("Constrained Application Protocol", "COAP", "coap");
	proto_register_field_array(proto_coap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("coap", dissect_coap, proto_coap);

	/* Register our configuration options */
	coap_module = prefs_register_protocol (proto_coap, proto_reg_handoff_coap);

	prefs_register_uint_preference (coap_module, "udp_port",
					"COAP port number",
					"Port number used for COAP traffic",
					10, &global_coap_port_number);
}

void
proto_reg_handoff_coap(void)
{
	static gboolean coap_prefs_initialized = FALSE;  
	static dissector_handle_t coap_handle;
	static guint    coap_port_number;

	if (!coap_prefs_initialized) {
		coap_handle = find_dissector("coap");
		media_type_dissector_table = find_dissector_table("media_type");
		coap_prefs_initialized = TRUE;
	} else {
		dissector_delete("udp.port", coap_port_number, coap_handle);
		dissector_delete("tcp.port", coap_port_number, coap_handle);
	}

	coap_port_number = global_coap_port_number;
	dissector_add("udp.port", coap_port_number, coap_handle);
	dissector_add("tcp.port", coap_port_number, coap_handle);
}

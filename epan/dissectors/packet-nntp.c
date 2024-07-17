/* packet-nntp.c
 * Routines for nntp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-tls-utils.h"

void proto_register_nntp(void);
void proto_reg_handoff_nntp(void);

static int proto_nntp;
static int hf_nntp_response;
static int hf_nntp_request;

static int ett_nntp;

static dissector_handle_t nntp_handle;
static dissector_handle_t tls_handle;

#define TCP_PORT_NNTP			119

/* State of NNTP conversation */
typedef struct nntp_conversation_t {
	bool tls_requested;
} nntp_conversation_t;

static int
dissect_nntp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char      *type;
	proto_tree	*nntp_tree;
	proto_item	*ti;
	int		offset = 0;
	int		next_offset;
	const unsigned char    *line;
	int		linelen;
	conversation_t  *conversation;
	nntp_conversation_t *session_state;

	conversation = find_or_create_conversation(pinfo);
	session_state = (nntp_conversation_t *)conversation_get_proto_data(conversation, proto_nntp);
	if (!session_state) {
		session_state = wmem_new0(wmem_file_scope(), nntp_conversation_t);
		session_state->tls_requested = false;
		conversation_add_proto_data(conversation, proto_nntp, session_state);
	}

	if (pinfo->match_uint == pinfo->destport)
		type = "Request";
	else
		type = "Response";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NNTP");

	/*
	 * Put the first line from the buffer into the summary
	 * (but leave out the line terminator).
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
	line    = tvb_get_ptr(tvb, offset, linelen);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", type,
		    tvb_format_text(pinfo->pool, tvb, offset, linelen));

	ti = proto_tree_add_item(tree, proto_nntp, tvb, offset, -1, ENC_NA);
	nntp_tree = proto_item_add_subtree(ti, ett_nntp);

	if (pinfo->match_uint == pinfo->destport) {
		ti = proto_tree_add_boolean(nntp_tree, hf_nntp_request, tvb, 0, 0, true);

		if (line && g_ascii_strncasecmp(line, "STARTTLS", 8) == 0) {
			session_state->tls_requested = true;
		}
	} else {
		ti = proto_tree_add_boolean(nntp_tree, hf_nntp_response, tvb, 0, 0, true);

		if (session_state->tls_requested) {
			if (line && g_ascii_strncasecmp(line, "382", 3) == 0) {
				/* STARTTLS command accepted */
				ssl_starttls_ack(tls_handle, pinfo, nntp_handle);
			}
			session_state->tls_requested = false;
		}
	}
	proto_item_set_hidden(ti);

	/*
	 * Show the request or response as text, a line at a time.
	 * XXX - for requests, we could display the stuff after the
	 * first line, if any, based on what the request was, and
	 * for responses, we could display it based on what the
	 * matching request was, although the latter requires us to
	 * know what the matching request was....
	 */
	while (tvb_offset_exists(tvb, offset)) {
		/*
		 * Find the end of the line.
		 */
		tvb_find_line_end(tvb, offset, -1, &next_offset, false);

		/*
		 * Put this line.
		 */
		proto_tree_add_format_text(nntp_tree, tvb, offset, next_offset - offset);
		offset = next_offset;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_nntp(void)
{
	static hf_register_info hf[] = {
		{ &hf_nntp_response,
		{ "Response",           "nntp.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"true if NNTP response", HFILL }},

		{ &hf_nntp_request,
		{ "Request",            "nntp.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"true if NNTP request", HFILL }}
	};
	static int *ett[] = {
		&ett_nntp,
	};

	proto_nntp = proto_register_protocol("Network News Transfer Protocol",
	    "NNTP", "nntp");
	proto_register_field_array(proto_nntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nntp(void)
{
	nntp_handle = register_dissector("nntp", dissect_nntp, proto_nntp);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_NNTP, nntp_handle);

	tls_handle = find_dissector("tls");
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

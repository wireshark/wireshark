/* packet-rtpproxy.c
 * RTPproxy command protocol dissector
 * Copyright 2013, Peter Lemenkov <lemenkov@gmail.com>
 *
 * This dissector tries to dissect rtpproxy control protocol. Please visit this
 * link for brief details on the command format:
 *
 * http://www.rtpproxy.org/wiki/RTPproxy/Protocol
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <ctype.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

static int proto_rtpproxy = -1;

static int hf_rtpproxy_cookie = -1;
static int hf_rtpproxy_error = -1;
static int hf_rtpproxy_status = -1;
static int hf_rtpproxy_ok = -1;
static int hf_rtpproxy_ipv4 = -1;
static int hf_rtpproxy_ipv6 = -1;
static int hf_rtpproxy_port = -1;
static int hf_rtpproxy_lf = -1;
static int hf_rtpproxy_request = -1;
static int hf_rtpproxy_command = -1;
static int hf_rtpproxy_command_parameters = -1;
static int hf_rtpproxy_callid = -1;
static int hf_rtpproxy_copy_target = -1;
static int hf_rtpproxy_playback_filename = -1;
static int hf_rtpproxy_playback_codec = -1;
static int hf_rtpproxy_notify = -1;
static int hf_rtpproxy_notify_ipv4 = -1;
static int hf_rtpproxy_notify_port = -1;
static int hf_rtpproxy_notify_tag = -1;
static int hf_rtpproxy_tag = -1;
static int hf_rtpproxy_mediaid = -1;
static int hf_rtpproxy_reply = -1;
static int hf_rtpproxy_version_request = -1;
static int hf_rtpproxy_version_supported = -1;

/* Request/response tracking */
static int hf_rtpproxy_request_in = -1;
static int hf_rtpproxy_response_in = -1;
static int hf_rtpproxy_response_time = -1;

typedef struct _rtpproxy_info {
	guint32 req_frame;
	guint32 resp_frame;
	nstime_t req_time;
} rtpproxy_info_t;

typedef struct _rtpproxy_conv_info {
	wmem_tree_t *trans;
} rtpproxy_conv_info_t;


static const string_string versiontypenames[] = {
	{ "20040107", "Basic RTP proxy functionality" },
	{ "20050322", "Support for multiple RTP streams and MOH" },
	{ "20060704", "Support for extra parameter in the V command" },
	{ "20071116", "Support for RTP re-packetization" },
	{ "20071218", "Support for forking (copying) RTP stream" },
	{ "20080403", "Support for RTP statistics querying" },
	{ "20081102", "Support for setting codecs in the update/lookup command" },
	{ "20081224", "Support for session timeout notifications" },
	{ "20090810", "Support for automatic bridging" },
	{ 0, NULL }
};

static const value_string commandtypenames[] = {
	{ 'V', "Handshake/Ping" },
	{ 'v', "Handshake/Ping" },
	{ 'U', "Offer/Update" },
	{ 'u', "Offer/Update" },
	{ 'L', "Answer/Lookup" },
	{ 'l', "Answer/Lookup" },
	{ 'I', "Information"},
	{ 'i', "Information"},
	{ 'X', "Close all active sessions"},
	{ 'x', "Close all active sessions"},
	{ 'D', "Delete an active session (Bye/Cancel/Error)"},
	{ 'd', "Delete an active session (Bye/Cancel/Error)"},
	{ 'P', "Start playback (music-on-hold)"},
	{ 'p', "Start playback (music-on-hold)"},
	{ 'S', "Stop playback (music-on-hold)"},
	{ 's', "Stop playback (music-on-hold)"},
	{ 'R', "Start recording"},
	{ 'r', "Start recording"},
	{ 'C', "Copy stream"},
	{ 'c', "Copy stream"},
	{ 'Q', "Query info about a session"},
	{ 'q', "Query info about a session"},
	{ 0, NULL }
};

static const value_string oktypenames[] = {
	{ '0', "Ok"},
	{ '1', "Version Supported"},
	{ 0, NULL }
};

static const string_string errortypenames[] = {
	{ "E0", "Syntax error" },
	{ "E1", "Syntax error" },
	{ "E2", "Syntax error" },
	{ "E3", "Unknown command" },
	{ "E4", "Syntax error" },
	{ "E5", "Out of memory" },
	{ "E6", "<no description>" },
	{ "E7", "Software error (can't create listener)" },
	{ "E8", "Not Found" },
	{ "E10", "Software error (can't create listener)" },
	{ "E11", "Out of memory" },
	{ "E12", "Out of memory" },
	{ "E13", "Out of memory" },
	{ "E14", "Out of memory" },
	{ 0, NULL }
};

static const value_string flowcontroltypenames[] = {
	{ '\n', "Yes"},
	{ 0, NULL }
};

static gint ett_rtpproxy = -1;

static gint ett_rtpproxy_request = -1;
static gint ett_rtpproxy_command = -1;
static gint ett_rtpproxy_tag = -1;
static gint ett_rtpproxy_notify = -1;

static gint ett_rtpproxy_reply = -1;

static guint rtpproxy_tcp_port = 22222;
static guint rtpproxy_udp_port = 22222;

void proto_reg_handoff_rtpproxy(void);

gint
rtpptoxy_add_tag(proto_tree *rtpproxy_tree, tvbuff_t *tvb, guint begin, guint realsize)
{
	proto_item *ti = NULL;
	proto_tree *another_tree = NULL;
	gint new_offset;
	guint end;

	new_offset = tvb_find_guint8(tvb, begin, -1, ' ');
	if(new_offset < 0)
		end = realsize; /* No more parameters */
	else
		end = new_offset;

	/* SER/OpenSER/OpenSIPS/Kamailio adds Media-ID right after the Tag
	 * separated by a semicolon
	 */
	new_offset = tvb_find_guint8(tvb, begin, end, ';');
	if(new_offset == -1){
		ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, end - begin, ENC_ASCII | ENC_NA);
		another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
		ti = proto_tree_add_item(another_tree, hf_rtpproxy_mediaid, tvb, new_offset+1, 0, ENC_ASCII | ENC_NA);
		proto_item_set_text(ti, "Media-ID: <skipped>");
	}
	else{
		ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, new_offset - begin, ENC_ASCII | ENC_NA);
		another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
		proto_tree_add_item(another_tree, hf_rtpproxy_mediaid, tvb, new_offset+1, end - (new_offset+1), ENC_ASCII | ENC_NA);
	}
	return (end == realsize ? -1 : (gint)end);
}

void
rtpproxy_add_tid(gboolean is_request, tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, rtpproxy_conv_info_t *rtpproxy_conv, gchar* cookie)
{
	rtpproxy_info_t *rtpproxy_info;
	proto_item *pi;

	if (!PINFO_FD_VISITED(pinfo)) {
		if (is_request){
			rtpproxy_info = wmem_new(wmem_file_scope(), rtpproxy_info_t);
			rtpproxy_info->req_frame = PINFO_FD_NUM(pinfo);
			rtpproxy_info->resp_frame = 0;
			rtpproxy_info->req_time = pinfo->fd->abs_ts;
			wmem_tree_insert_string(rtpproxy_conv->trans, cookie, rtpproxy_info, 0);
		} else {
			rtpproxy_info = (rtpproxy_info_t *)wmem_tree_lookup_string(rtpproxy_conv->trans, cookie, 0);
			if (rtpproxy_info) {
				rtpproxy_info->resp_frame = PINFO_FD_NUM(pinfo);
			}
		}
	} else {
		rtpproxy_info = (rtpproxy_info_t *)wmem_tree_lookup_string(rtpproxy_conv->trans, cookie, 0);
		if (rtpproxy_info && (is_request ? rtpproxy_info->resp_frame : rtpproxy_info->req_frame)) {
			nstime_t ns;

			pi = proto_tree_add_uint(rtpproxy_tree, is_request ? hf_rtpproxy_response_in : hf_rtpproxy_request_in, tvb, 0, 0, is_request ? rtpproxy_info->resp_frame : rtpproxy_info->req_frame);
			PROTO_ITEM_SET_GENERATED(pi);

			/* If reply then calculate response time */
			if (!is_request){
				nstime_delta(&ns, &pinfo->fd->abs_ts, &rtpproxy_info->req_time);
				pi = proto_tree_add_time(rtpproxy_tree, hf_rtpproxy_response_time, tvb, 0, 0, &ns);
				PROTO_ITEM_SET_GENERATED(pi);
			}
		}
	}
}

static int
dissect_rtpproxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gboolean has_lf = FALSE;
	gint offset = 0;
	gint new_offset = 0;
	guint tmp;
	gint realsize = 0;
	guint8* rawstr;
	guint8* tmpstr;
	proto_item *ti;
	proto_tree *rtpproxy_tree;
	conversation_t *conversation;
	rtpproxy_conv_info_t *rtpproxy_conv;
	gchar* cookie = NULL;

	/* If it does not start with a printable character it's not RTPProxy */
	if(!isprint(tvb_get_guint8(tvb, 0)))
		return 0;

	/* Extract Cookie */
	offset = tvb_find_guint8(tvb, offset, -1, ' ');
	if(offset == -1)
		return 0;

	/* Clear out stuff in the info column - we''l set it later */
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_rtpproxy, tvb, 0, -1, ENC_NA);
	rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy);

	proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_cookie, tvb, 0, offset, ENC_ASCII | ENC_NA);
	cookie = tvb_get_string(wmem_packet_scope(), tvb, 0, offset);

	/* Skip whitespace */
	offset = tvb_skip_wsp(tvb, offset+1, -1);

	/* Calculate size to prevent recalculation in the future */
	realsize = tvb_reported_length(tvb);

	/* Check for LF (required for TCP connection, optional for UDP) */
	if (tvb_get_guint8(tvb, realsize - 1) == '\n'){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy");
		/* Don't count trailing LF */
		realsize -= 1;
		has_lf = TRUE;
	}
	else
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy (no LF)");

	/* Try to create conversation */
	conversation = find_or_create_conversation(pinfo);
	rtpproxy_conv = (rtpproxy_conv_info_t *)conversation_get_proto_data(conversation, proto_rtpproxy);
	if (!rtpproxy_conv) {
		rtpproxy_conv = wmem_new(wmem_file_scope(), rtpproxy_conv_info_t);
		rtpproxy_conv->trans = wmem_tree_new(wmem_file_scope());
		conversation_add_proto_data(conversation, proto_rtpproxy, rtpproxy_conv);
	}

	/* Get payload string */
	rawstr = tvb_get_string(wmem_packet_scope(), tvb, offset, realsize - offset);

	/* Extract command */
	tmp = g_ascii_tolower(tvb_get_guint8(tvb, offset));
	switch (tmp)
	{
		case 's':
			/* A specific case - long statistics answer */
			/* %COOKIE% sessions created %NUM0% active sessions: %NUM1% */
			rtpproxy_add_tid(FALSE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
			if ('e' == tvb_get_guint8(tvb, offset+1)){
				col_add_fstr(pinfo->cinfo, COL_INFO, "Reply: %s", rawstr);
				ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_reply, tvb, offset, -1, ENC_NA);

				rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_reply);
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_status, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
				break;
			}
		case 'i':
		case 'x':
		case 'u':
		case 'l':
		case 'd':
		case 'p':
		case 'v':
		case 'r':
		case 'c':
		case 'q':
			rtpproxy_add_tid(TRUE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s", rawstr);
			ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_request, tvb, offset, -1, ENC_NA);
			rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_request);

			/* A specific case - version request */
			if ((tmp == 'v') && (offset + (gint)strlen("VF YYYMMDD") + 1 == realsize)){
				/* Skip whitespace */
				new_offset = tvb_skip_wsp(tvb, offset + ((guint)strlen("VF") + 1), -1);
				ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_version_request, tvb, new_offset, (gint)strlen("YYYYMMDD"), ENC_ASCII | ENC_NA);
				tmpstr = tvb_get_string(wmem_packet_scope(), tvb, new_offset, (gint)strlen("YYYYMMDD"));
				proto_item_append_text(ti, " (%s)", str_to_str(tmpstr, versiontypenames, "Unknown"));
				break;
			}

			/* All other commands */
			ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command, tvb, offset, 1, ENC_NA);

			/* A specific case - handshake/ping */
			if (tmp == 'v')
				break; /* No more parameters */

			/* A specific case - close all calls */
			if (tmp == 'x')
				break; /* No more parameters */

			/* Extract parameters */
			/* Parameters should be right after the command and before EOL (in case of Info command) or before whitespace */
			new_offset = (tmp == 'i' ? (realsize - 1 > offset ? offset + (gint)strlen("Ib") : offset + (gint)strlen("I")) : tvb_find_guint8(tvb, offset, -1, ' '));

			if (new_offset != offset + 1){
				rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_command);
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command_parameters, tvb, offset+1, new_offset - (offset+1), ENC_ASCII | ENC_NA);
				rtpproxy_tree = proto_item_get_parent(ti);
			}

			/* A specific case - query information */
			if (tmp == 'i')
				break; /* No more parameters */

			/* Skip whitespace */
			offset = tvb_skip_wsp(tvb, new_offset+1, -1);

			/* Extract Call-ID */
			new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
			proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_callid, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
			/* Skip whitespace */
			offset = tvb_skip_wsp(tvb, new_offset+1, -1);

			/* Extract IP and Port in case of Offer/Answer */
			if ((tmp == 'u') || (tmp == 'l')){
				/* Extract IP */
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				if (tvb_find_guint8(tvb, offset, new_offset - offset, ':') == -1)
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ipv4, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				else
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ipv6, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);

				/* Extract Port */
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);
			}

			/* Extract Copy target */
			if (tmp == 'c'){
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_copy_target, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);
			}

			/* Extract Playback file and codecs */
			if (tmp == 'p'){
				/* Extract filename */
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_playback_filename, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);

				/* Extract codec */
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_playback_codec, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);
			}

			/* Extract first tag */
			new_offset = rtpptoxy_add_tag(rtpproxy_tree, tvb, offset, realsize);
			if(new_offset == -1)
				break; /* No more parameters */
			/* Skip whitespace */
			offset = tvb_skip_wsp(tvb, new_offset+1, -1);

			/* Extract second tag */
			new_offset = rtpptoxy_add_tag(rtpproxy_tree, tvb, offset, realsize);
			if(new_offset == -1)
				break; /* No more parameters */
			/* Skip whitespace */
			offset = tvb_skip_wsp(tvb, new_offset+1, -1);

			/* Extract Notification address */
			if (tmp == 'u'){
				new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
				ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
				proto_item_set_text(ti, "Notify");
				rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_notify);
				if(new_offset == -1){
					/* FIXME only IPv4 is supported */
					new_offset = tvb_find_guint8(tvb, offset, -1, ':');
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, new_offset+1, realsize - (new_offset+1), ENC_ASCII | ENC_NA);
					break; /* No more parameters */
				}
				if(new_offset - offset < 6){
					/* Only port is supplied */
					ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, offset, 0, ENC_ASCII | ENC_NA);
					proto_item_set_text(ti, "Notification IPv4: <skipped>");
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
				}
				else{
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
					proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, new_offset+1, realsize - (new_offset+1), ENC_ASCII | ENC_NA);
				}
				/* Skip whitespace */
				offset = tvb_skip_wsp(tvb, new_offset+1, -1);

				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_tag, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
			}
			break;
		case 'a':
		case 'e':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			rtpproxy_add_tid(FALSE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
			if (tmp == 'e')
				col_add_fstr(pinfo->cinfo, COL_INFO, "Error reply: %s", rawstr);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "Reply: %s", rawstr);

			ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_reply, tvb, offset, -1, ENC_NA);
			rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_reply);

			if (tmp == 'e'){
				tmp = tvb_find_line_end(tvb, offset, -1, &new_offset, FALSE);
				tmpstr = tvb_get_string(wmem_packet_scope(), tvb, offset, tmp);
				ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_error, tvb, offset, (gint)strlen(tmpstr), ENC_ASCII | ENC_NA);
				proto_item_append_text(ti, " (%s)", str_to_str(tmpstr, errortypenames, "Unknown"));
				break;
			}

			if (tmp == 'a'){
				/* A specific case - short statistics answer */
				/* %COOKIE% active sessions: %NUM1% */
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_status, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
				break;
			}
			if ((tmp == '0')&& ((tvb_reported_length(tvb) == (guint)(offset+1))||(tvb_reported_length(tvb) == (guint)(offset+2)))){
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ok, tvb, offset, 1, ENC_ASCII | ENC_NA);
				break;
			}
			if ((tmp == '1') && ((tvb_reported_length(tvb) == (guint)(offset+1))||(tvb_reported_length(tvb) == (guint)(offset+2)))){
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ok, tvb, offset, 1, ENC_ASCII | ENC_NA);
				break;
			}
			if (tvb_reported_length(tvb) == (guint)(offset+9)){
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_version_supported, tvb, offset, 8, ENC_ASCII | ENC_NA);
				break;
			}

			/* Extract Port */
			new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
			proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
			/* Skip whitespace */
			offset = tvb_skip_wsp(tvb, new_offset+1, -1);

			/* Extract IP */
			tmp = tvb_find_line_end(tvb, offset, -1, &new_offset, FALSE);
			if (tvb_find_guint8(tvb, offset, -1, ':') == -1)
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ipv4, tvb, offset, tmp, ENC_ASCII | ENC_NA);
			else
				proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ipv6, tvb, offset, tmp, ENC_ASCII | ENC_NA);
			break;
		default:
			break;
	}
	if (has_lf)
		proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_lf, tvb, realsize, 1, ENC_NA);

	return tvb_length(tvb);
}

void
proto_register_rtpproxy(void)
{
	module_t *rtpproxy_module;

	static hf_register_info hf[] = {
		{
			&hf_rtpproxy_cookie,
			{
				"Cookie",
				"rtpproxy.cookie",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_version_request,
			{
				"Version Request",
				"rtpproxy.version",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_version_supported,
			{
				"Version Supported",
				"rtpproxy.version_supported",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_error,
			{
				"Error",
				"rtpproxy.error",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_ok,
			{
				"Ok",
				"rtpproxy.ok",
				FT_UINT8,
				BASE_DEC,
				VALS(oktypenames),
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_status,
			{
				"Status",
				"rtpproxy.status",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_ipv4,
			{
				"IPv4",
				"rtpproxy.ipv4",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_ipv6,
			{
				"IPv6",
				"rtpproxy.ipv6",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_port,
			{
				"Port",
				"rtpproxy.port",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_request,
			{
				"Request",
				"rtpproxy.request",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_command,
			{
				"Command",
				"rtpproxy.command",
				FT_UINT8,
				BASE_DEC,
				VALS(commandtypenames),
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_command_parameters,
			{
				"Command parameters",
				"rtpproxy.command_parameters",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_copy_target,
			{
				"Copy target",
				"rtpproxy.copy_target",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_playback_filename,
			{
				"Playback filename",
				"rtpproxy.playback_filename",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_playback_codec,
			{
				"Playback codec",
				"rtpproxy.playback_codec",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_callid,
			{
				"Call-ID",
				"rtpproxy.callid",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_notify,
			{
				"Notify",
				"rtpproxy.notify",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_tag,
			{
				"Tag",
				"rtpproxy.tag",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_mediaid,
			{
				"Media-ID",
				"rtpproxy.mediaid",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_notify_ipv4,
			{
				"Notification IPv4",
				"rtpproxy.notify_ipv4",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_notify_port,
			{
				"Notification Port",
				"rtpproxy.notify_port",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_notify_tag,
			{
				"Notification Tag",
				"rtpproxy.notify_tag",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_reply,
			{
				"Reply",
				"rtpproxy.reply",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_lf,
			{
				"LF",
				"rtpproxy.lf",
				FT_UINT8,
				BASE_DEC,
				VALS(flowcontroltypenames),
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_request_in,
			{
				"Request In",
				"rtpproxy.request_in",
				FT_FRAMENUM,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}

		},
		{
			&hf_rtpproxy_response_in,
			{
				"Response In",
				"rtpproxy.response_in",
				FT_FRAMENUM,
				BASE_NONE,
				NULL,
				0x0,
				NULL,
				HFILL
			}
		},
		{
			&hf_rtpproxy_response_time,
			{
				"Response Time",
				"rtpproxy.response_time",
				FT_RELATIVE_TIME,
				BASE_NONE,
				NULL,
				0x0,
				"The time between the Request and the Reply",
				HFILL
			 }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_rtpproxy,
		&ett_rtpproxy_request,
		&ett_rtpproxy_command,
		&ett_rtpproxy_tag,
		&ett_rtpproxy_notify,
		&ett_rtpproxy_reply
	};

	proto_rtpproxy = proto_register_protocol (
			"Sippy RTPproxy Protocol", /* name       */
			"RTPproxy",      /* short name */
			"rtpproxy"       /* abbrev     */
			);

	proto_register_field_array(proto_rtpproxy, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rtpproxy_module = prefs_register_protocol(proto_rtpproxy, proto_reg_handoff_rtpproxy);
	prefs_register_uint_preference(rtpproxy_module, "tcp.port",
								 "RTPproxy TCP Port", /* Title */
								 "RTPproxy TCP Port", /* Descr */
								 10,
								 &rtpproxy_tcp_port);

	prefs_register_uint_preference(rtpproxy_module, "udp.port",
								 "RTPproxy UDP Port", /* Title */
								 "RTPproxy UDP Port", /* Descr */
								 10,
								 &rtpproxy_udp_port);
}

void
proto_reg_handoff_rtpproxy(void)
{
	static guint old_rtpproxy_tcp_port = 0;
	static guint old_rtpproxy_udp_port = 0;

	static gboolean rtpproxy_initialized = FALSE;

	static dissector_handle_t rtpproxy_tcp_handle, rtpproxy_udp_handle;

	if(!rtpproxy_initialized){
		rtpproxy_tcp_handle = new_create_dissector_handle(dissect_rtpproxy, proto_rtpproxy);
		rtpproxy_udp_handle = new_create_dissector_handle(dissect_rtpproxy, proto_rtpproxy);
		rtpproxy_initialized = TRUE;
	}

	/* Register TCP port for dissection */
	if(old_rtpproxy_tcp_port != 0 && old_rtpproxy_tcp_port != rtpproxy_tcp_port)
		dissector_delete_uint("tcp.port", old_rtpproxy_tcp_port, rtpproxy_tcp_handle);
	if(rtpproxy_tcp_port != 0 && old_rtpproxy_tcp_port != rtpproxy_tcp_port)
		dissector_add_uint("tcp.port", rtpproxy_tcp_port, rtpproxy_tcp_handle);
	old_rtpproxy_tcp_port = rtpproxy_tcp_port;

	/* Register UDP port for dissection */
	if(old_rtpproxy_udp_port != 0 && old_rtpproxy_udp_port != rtpproxy_udp_port)
		dissector_delete_uint("udp.port", old_rtpproxy_udp_port, rtpproxy_udp_handle);
	if(rtpproxy_udp_port != 0 && old_rtpproxy_udp_port != rtpproxy_udp_port)
		dissector_add_uint("udp.port", rtpproxy_udp_port, rtpproxy_udp_handle);
	old_rtpproxy_udp_port = rtpproxy_udp_port;
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

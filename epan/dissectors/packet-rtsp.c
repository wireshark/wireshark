/* packet-rtsp.c
 * Routines for RTSP packet disassembly (RFC 2326)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * References:
 * RTSP is defined in RFC 2326, http://www.ietf.org/rfc/rfc2326.txt?number=2326
 * http://www.iana.org/assignments/rsvp-parameters
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <epan/prefs.h>

#include <glib.h>

#include <wsutil/str_util.h>

#include <epan/packet.h>
#include <epan/req_resp_hdrs.h>
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-rdt.h"
#include <epan/conversation.h>
#include <epan/strutil.h>
#include "packet-e164.h"
#include <epan/emem.h>
#include <epan/tap.h>
#include <epan/tap-voip.h>

static int proto_rtsp		= -1;

static gint ett_rtsp		= -1;
static gint ett_rtspframe	= -1;
static gint ett_rtsp_method 	= -1;

static int hf_rtsp_request	= -1;
static int hf_rtsp_response	= -1;
static int hf_rtsp_content_type	= -1;
static int hf_rtsp_content_length	= -1;
static int hf_rtsp_method	= -1;
static int hf_rtsp_url		= -1;
static int hf_rtsp_status	= -1;
static int hf_rtsp_session	= -1;
static int hf_rtsp_transport	= -1;
static int hf_rtsp_rdtfeaturelevel	= -1;
static int hf_rtsp_X_Vig_Msisdn	= -1;

static int voip_tap = -1;

static dissector_handle_t rtp_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t rdt_handle;
static dissector_table_t media_type_dissector_table;

void proto_reg_handoff_rtsp(void);

/*
 * desegmentation of RTSP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean rtsp_desegment_headers = TRUE;

/*
 * desegmentation of RTSP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 * TODO let the user filter on content-type the bodies he wants desegmented
 */
static gboolean rtsp_desegment_body = TRUE;

/* http://www.iana.org/assignments/port-numberslists two rtsp ports */
#define TCP_PORT_RTSP			554
#define TCP_ALTERNATE_PORT_RTSP		8554
static guint global_rtsp_tcp_port = TCP_PORT_RTSP;
static guint global_rtsp_tcp_alternate_port = TCP_ALTERNATE_PORT_RTSP;
/*
 * Takes an array of bytes, assumed to contain a null-terminated
 * string, as an argument, and returns the length of the string -
 * i.e., the size of the array, minus 1 for the null terminator.
 */
#define STRLEN_CONST(str)	(sizeof (str) - 1)

#define RTSP_FRAMEHDR	('$')

typedef struct {
	dissector_handle_t		dissector;
} rtsp_interleaved_t;

#define RTSP_MAX_INTERLEAVED		(256)

/*
 * Careful about dynamically allocating memory in this structure (say
 * for dynamically increasing the size of the 'interleaved' array) -
 * the containing structure is garbage collected and contained
 * pointers will not be freed.
 */
typedef struct {
	rtsp_interleaved_t		interleaved[RTSP_MAX_INTERLEAVED];
} rtsp_conversation_data_t;

static int
dissect_rtspinterleaved(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	guint		length_remaining;
	proto_item	*ti;
	proto_tree	*rtspframe_tree = NULL;
	int		orig_offset;
	guint8		rf_start;		/* always RTSP_FRAMEHDR */
	guint8		rf_chan;        /* interleaved channel id */
	guint16		rf_len;         /* packet length */
	tvbuff_t	*next_tvb;
	conversation_t	*conv;
	rtsp_conversation_data_t	*data;
	dissector_handle_t		dissector;

	/*
	 * This will throw an exception if we don't have any data left.
	 * That's what we want.  (See "tcp_dissect_pdus()", which is
	 * similar.)
	 */
	length_remaining = tvb_ensure_length_remaining(tvb, offset);

	/*
	 * Can we do reassembly?
	 */
	if (rtsp_desegment_headers && pinfo->can_desegment) {
		/*
		 * Yes - would an RTSP multiplexed header starting at
		 * this offset be split across segment boundaries?
		 */
		if (length_remaining < 4) {
			/*
			 * Yes.  Tell the TCP dissector where the data for
			 * this message starts in the data it handed us and
			 * that we need "some more data."  Don't tell it
			 * exactly how many bytes we need because if/when we
			 * ask for even more (after the header) that will
			 * break reassembly.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return -1;
		}
	}

	/*
	 * Get the "$", channel, and length from the header.
	 */
	orig_offset = offset;
	rf_start = tvb_get_guint8(tvb, offset);
	rf_chan = tvb_get_guint8(tvb, offset+1);
	rf_len = tvb_get_ntohs(tvb, offset+2);

	/*
	 * Can we do reassembly?
	 */
	if (rtsp_desegment_body && pinfo->can_desegment) {
		/*
		 * Yes - is the header + encapsulated packet split
		 * across segment boundaries?
		 */
		if (length_remaining < 4U + rf_len) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and return.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = 4U + rf_len - length_remaining;
			return -1;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"Interleaved channel 0x%02x, %u bytes",
			rf_chan, rf_len);

	if (tree != NULL) {
		ti = proto_tree_add_protocol_format(tree, proto_rtsp, tvb,
		    offset, 4,
		    "RTSP Interleaved Frame, Channel: 0x%02x, %u bytes",
		    rf_chan, rf_len);
		rtspframe_tree = proto_item_add_subtree(ti, ett_rtspframe);

		proto_tree_add_text(rtspframe_tree, tvb, offset, 1,
		    "Magic: 0x%02x",
		    rf_start);
	}
	offset += 1;

	if (tree != NULL) {
		proto_tree_add_text(rtspframe_tree, tvb, offset, 1,
		    "Channel: 0x%02x",
		    rf_chan);
	}
	offset += 1;

	if (tree != NULL) {
		proto_tree_add_text(rtspframe_tree, tvb, offset, 2,
		    "Length: %u bytes",
		    rf_len);
	}
	offset += 2;

	/*
	 * We set the actual length of the tvbuff for the interleaved
	 * stuff to the minimum of what's left in the tvbuff and the
	 * length in the header.
	 *
	 * XXX - what if there's nothing left in the tvbuff?
	 * We'd want a BoundsError exception to be thrown, so
	 * that a Short Frame would be reported.
	 */
	if (length_remaining > rf_len)
		length_remaining = rf_len;
	next_tvb = tvb_new_subset(tvb, offset, length_remaining, rf_len);

	conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
		pinfo->srcport, pinfo->destport, 0);

	if (conv &&
	    (data = conversation_get_proto_data(conv, proto_rtsp)) &&
	    /* Add the following condition if it is not always true.
	    rf_chan < RTSP_MAX_INTERLEAVED &&
	    */
	    (dissector = data->interleaved[rf_chan].dissector)) {
		call_dissector(dissector, next_tvb, pinfo, tree);
	} else {
		proto_tree_add_text(rtspframe_tree, tvb, offset, rf_len,
			"Data (%u bytes)", rf_len);
	}

	offset += rf_len;

	return offset - orig_offset;
}

static void process_rtsp_request(tvbuff_t *tvb, int offset, const guchar *data,
                                 size_t linelen, size_t next_line_offset,
                                 proto_tree *tree);

static void process_rtsp_reply(tvbuff_t *tvb, int offset, const guchar *data,
                               size_t linelen, size_t next_line_offset,
                               proto_tree *tree);

typedef enum {
	RTSP_REQUEST,
	RTSP_REPLY,
	RTSP_NOT_FIRST_LINE
} rtsp_type_t;

static const char *rtsp_methods[] = {
	"DESCRIBE",
	"ANNOUNCE",
	"GET_PARAMETER",
	"OPTIONS",
	"PAUSE",
	"PLAY",
	"RECORD",
	"REDIRECT",
	"SETUP",
	"SET_PARAMETER",
	"TEARDOWN"
};

#define RTSP_NMETHODS	(sizeof rtsp_methods / sizeof rtsp_methods[0])

static gboolean
is_rtsp_request_or_reply(const guchar *line, size_t linelen, rtsp_type_t *type)
{
	unsigned	ii;

	/* Is this an RTSP reply? */
	if (linelen >= 5 && g_ascii_strncasecmp("RTSP/", line, 5) == 0) {
		/*
		 * Yes.
		 */
		*type = RTSP_REPLY;
		return TRUE;
	}

	/*
	 * Is this an RTSP request?
	 * Check whether the line begins with one of the RTSP request
	 * methods.
	 */
	for (ii = 0; ii < RTSP_NMETHODS; ii++) {
		size_t len = strlen(rtsp_methods[ii]);
		if (linelen >= len &&
		    g_ascii_strncasecmp(rtsp_methods[ii], line, len) == 0 &&
		    (len == linelen || isspace(line[len])))
		{
			*type = RTSP_REQUEST;
			return TRUE;
		}
	}

	/* Wasn't a request or a response */
	*type = RTSP_NOT_FIRST_LINE;
	return FALSE;
}

static const char rtsp_content_type[] = "Content-Type:";
static const char rtsp_transport[] = "Transport:";
static const char rtsp_sps[] = "server_port=";
static const char rtsp_cps[] = "client_port=";
static const char rtsp_rtp[] = "rtp/";
static const char rtsp_rdt_feature_level[] = "RDTFeatureLevel";
static const char rtsp_real_rdt[] = "x-real-rdt/";
static const char rtsp_real_tng[] = "x-pn-tng/"; /* synonym for x-real-rdt */
static const char rtsp_inter[] = "interleaved=";

static void
rtsp_create_conversation(packet_info *pinfo, const guchar *line_begin,
                         size_t line_len, gint rdt_feature_level)
{
	conversation_t	*conv;
	guchar		buf[256];
	guchar		*tmp;
	gboolean	rtp_transport = FALSE;
	gboolean	rdt_transport = FALSE;
	guint		c_data_port, c_mon_port;
	guint		s_data_port, s_mon_port;
	gboolean	is_video = FALSE; /* FIX ME - need to indicate video or not */

	/* Copy line into buf */
	if (line_len > sizeof(buf) - 1)
	{
		/* Don't overflow the buffer. */
		line_len = sizeof(buf) - 1;
	}
	memcpy(buf, line_begin, line_len);
	buf[line_len] = '\0';

	/* Get past "Transport:" and spaces */
	tmp = buf + STRLEN_CONST(rtsp_transport);
	while (*tmp && isspace(*tmp))
		tmp++;

	/* Work out which transport type is here */
	if (g_ascii_strncasecmp(tmp, rtsp_rtp, strlen(rtsp_rtp)) == 0)
		rtp_transport = TRUE;
	else
	if (g_ascii_strncasecmp(tmp, rtsp_real_rdt, strlen(rtsp_real_rdt)) == 0 ||
	    g_ascii_strncasecmp(tmp, rtsp_real_tng, strlen(rtsp_real_tng)) == 0)
		rdt_transport = TRUE;
	else
	{
		/* Give up on unknown transport types */
		return;
	}

	c_data_port = c_mon_port = 0;
	s_data_port = s_mon_port = 0;

	/* Look for server port */
	if ((tmp = strstr(buf, rtsp_sps))) {
		tmp += strlen(rtsp_sps);
		if (sscanf(tmp, "%u-%u", &s_data_port, &s_mon_port) < 1) {
			g_warning("Frame %u: rtsp: bad server_port",
				pinfo->fd->num);
			return;
		}
	}
	/* Look for client port */
	if ((tmp = strstr(buf, rtsp_cps))) {
		tmp += strlen(rtsp_cps);
		if (sscanf(tmp, "%u-%u", &c_data_port, &c_mon_port) < 1) {
			g_warning("Frame %u: rtsp: bad client_port",
				pinfo->fd->num);
			return;
		}
	}


	/* Deal with RTSP TCP-interleaved conversations. */
	if (!c_data_port) {
		rtsp_conversation_data_t	*data;
		guint				s_data_chan, s_mon_chan;
		int				i;

		/* Search tranport line for interleaved string */
		if ((tmp = strstr(buf, rtsp_inter)) == NULL) {
			/*
			 * No interleaved or server_port - probably a
			 * SETUP request, rather than reply.
			 */
			return;
		}

		/* Move tmp to beyone interleaved string */
		tmp += strlen(rtsp_inter);
		/* Look for channel number(s) */
		i = sscanf(tmp, "%u-%u", &s_data_chan, &s_mon_chan);
		if (i < 1)
		{
			g_warning("Frame %u: rtsp: bad interleaved", pinfo->fd->num);
			return;
		}

		/* At least data channel present, look for conversation (presumably TCP) */
		conv = find_or_create_conversation(pinfo);

		/* Look for previous data */
		data = conversation_get_proto_data(conv, proto_rtsp);

		/* Create new data if necessary */
		if (!data)
		{
			data = se_alloc0(sizeof(rtsp_conversation_data_t));
			conversation_add_proto_data(conv, proto_rtsp, data);
		}

		/* Now set the dissector handle of the interleaved channel
		   according to the transport protocol used */
		if (rtp_transport)
		{
			if (s_data_chan < RTSP_MAX_INTERLEAVED) {
				data->interleaved[s_data_chan].dissector =
					rtp_handle;
			}
			if (i > 1 && s_mon_chan < RTSP_MAX_INTERLEAVED) {
				data->interleaved[s_mon_chan].dissector =
					rtcp_handle;
			}
		}
		else if (rdt_transport)
		{
			if (s_data_chan < RTSP_MAX_INTERLEAVED) {
				data->interleaved[s_data_chan].dissector =
					rdt_handle;
			}
		}
		return;
	}

	/*
	 * We only want to match on the destination address, not the
	 * source address, because the server might send back a packet
	 * from an address other than the address to which its client
	 * sent the packet, so we construct a conversation with no
	 * second address.
	 */
	if (rtp_transport)
	{
		/* There is always data for RTP */
		rtp_add_address(pinfo, &pinfo->dst, c_data_port, s_data_port,
		                "RTSP", pinfo->fd->num, is_video, NULL);

		/* RTCP only if indicated */
		if (c_mon_port)
		{
			rtcp_add_address(pinfo, &pinfo->dst, c_mon_port, s_mon_port,
			                 "RTSP", pinfo->fd->num);
		}
	}
	else
	if (rdt_transport)
	{
		/* Real Data Transport */
		rdt_add_address(pinfo, &pinfo->dst, c_data_port, s_data_port,
		                "RTSP", rdt_feature_level);
	}
}

static const char rtsp_content_length[] = "Content-Length:";

static int
rtsp_get_content_length(const guchar *line_begin, size_t line_len)
{
	guchar		buf[256];
	guchar		*tmp;
	long		content_length;
	char		*p;
	guchar		*up;

	if (line_len > sizeof(buf) - 1) {
		/*
		 * Don't overflow the buffer.
		 */
		line_len = sizeof(buf) - 1;
	}
	memcpy(buf, line_begin, line_len);
	buf[line_len] = '\0';

	tmp = buf + STRLEN_CONST(rtsp_content_length);
	while (*tmp && isspace(*tmp))
		tmp++;
	content_length = strtol(tmp, &p, 10);
	up = p;
	if (up == tmp || (*up != '\0' && !isspace(*up)))
		return -1;	/* not a valid number */
	return content_length;
}

static const char rtsp_Session[] = "Session:";
static const char rtsp_X_Vig_Msisdn[] = "X-Vig-Msisdn";

static int
dissect_rtspmessage(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree)
{
	proto_tree		*rtsp_tree = NULL;
	proto_tree		*sub_tree = NULL;
	proto_item		*ti = NULL;
	const guchar		*line;
	gint			next_offset;
	const guchar		*linep, *lineend;
	int			orig_offset;
	int			first_linelen, linelen;
	int			line_end_offset;
	int			colon_offset;
	gboolean		is_request_or_reply;
	gboolean		body_requires_content_len;
	gboolean		saw_req_resp_or_header;
	guchar			c;
	rtsp_type_t		rtsp_type;
	gboolean		is_header;
	int			datalen;
	int			content_length;
	int			reported_datalen;
	int			value_offset;
	int			value_len;
	e164_info_t		e164_info;
	gint			rdt_feature_level = 0;
	gchar			*media_type_str_lower_case = NULL;
	int			semi_colon_offset;
	int			par_end_offset;
	gchar	*frame_label = NULL;
	gchar	*session_id = NULL;
	voip_packet_info_t *stat_info = NULL;

	/*
	 * Is this a request or response?
	 *
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" call won't throw an exception.
	 */
	first_linelen = tvb_find_line_end(tvb, offset,
	    tvb_ensure_length_remaining(tvb, offset), &next_offset,
	    FALSE);

	/*
	 * Is the first line a request or response?
	 */
	line = tvb_get_ptr(tvb, offset, first_linelen);
	is_request_or_reply = is_rtsp_request_or_reply(line, first_linelen,
	    &rtsp_type);
	if (is_request_or_reply) {
                /*
		 * Yes, it's a request or response.
		 * Do header desegmentation if we've been told to,
		 * and do body desegmentation if we've been told to and
		 * we find a Content-Length header.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    rtsp_desegment_headers, rtsp_desegment_body)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	/*
	 * RFC 2326 says that a content length must be specified
	 * in requests that have a body, although section 4.4 speaks
	 * of a server closing the connection indicating the end of
	 * a reply body.
	 *
	 * We assume that an absent content length in a request means
	 * that we don't have a body, and that an absent content length
	 * in a reply means that the reply body runs to the end of
	 * the connection.  If the first line is neither, we assume
	 * that whatever follows a blank line should be treated as a
	 * body; there's not much else we can do, as we're jumping
	 * into the message in the middle.
	 *
	 * XXX - if there was no Content-Length entity header, we should
	 * accumulate all data until the end of the connection.
	 * That'd require that the TCP dissector call subdissectors
	 * for all frames with FIN, even if they contain no data,
	 * which would require subdissectors to deal intelligently
	 * with empty segments.
	 */
	if (rtsp_type == RTSP_REQUEST)
		body_requires_content_len = TRUE;
	else
		body_requires_content_len = FALSE;

	line = tvb_get_ptr(tvb, offset, first_linelen);
	if (is_request_or_reply) {
		if ( rtsp_type == RTSP_REPLY ) {
			frame_label = ep_strdup_printf("Reply: %s", format_text(line, first_linelen));
		}
		else {
			frame_label = ep_strdup(format_text(line, first_linelen));
		}
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSP");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
 		 * if it's an RTSP request or reply (but leave out the
		 * line terminator).
		 * Otherwise, just call it a continuation.
		 *
		 * Note that "tvb_find_line_end()" will return a value that
		 * is not longer than what's in the buffer, so the
		 * "tvb_get_ptr()" call won't throw an exception.
		 */
		if (is_request_or_reply)
			if ( rtsp_type == RTSP_REPLY ) {
				col_set_str(pinfo->cinfo, COL_INFO, "Reply: ");
				col_append_str(pinfo->cinfo, COL_INFO,
					format_text(line, first_linelen));
			}
			else {
				col_add_str(pinfo->cinfo, COL_INFO,
					format_text(line, first_linelen));
			}

		else
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");

	}

	orig_offset = offset;
	if (tree) {
		ti = proto_tree_add_item(tree, proto_rtsp, tvb, offset,	-1,
		    FALSE);
		rtsp_tree = proto_item_add_subtree(ti, ett_rtsp);
	}

	/*
	 * We haven't yet seen a Content-Length header.
	 */
	content_length = -1;

	/*
	 * Process the packet data, a line at a time.
	 */
	saw_req_resp_or_header = FALSE;	/* haven't seen anything yet */
	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		/*
		 * We haven't yet concluded that this is a header.
		 */
		is_header = FALSE;

		/*
		 * Find the end of the line.
		 */
		linelen = tvb_find_line_end(tvb, offset,
		    tvb_ensure_length_remaining(tvb, offset), &next_offset,
		    FALSE);
		if (linelen < 0)
			return -1;
		line_end_offset = offset + linelen;
		/*
		 * colon_offset may be -1
		 */
		colon_offset = tvb_find_guint8(tvb, offset, linelen, ':');


		/*
		 * Get a buffer that refers to the line.
		 */
		line = tvb_get_ptr(tvb, offset, linelen);
		lineend = line + linelen;

		/*
		 * OK, does it look like an RTSP request or response?
		 */
		is_request_or_reply = is_rtsp_request_or_reply(line, linelen, &rtsp_type);
		if (is_request_or_reply)
			goto is_rtsp;

		/*
		 * No.  Does it look like a blank line (as would appear
		 * at the end of an RTSP request)?
		 */
		if (linelen == 0)
			goto is_rtsp;	/* Yes. */

		/*
		 * No.  Does it look like a header?
		 */
		linep = line;
		while (linep < lineend) {
			c = *linep++;

			/*
			 * This must be a CHAR to be part of a token; that
			 * means it must be ASCII.
			 */
			if (!isascii(c))
				break;	/* not ASCII, thus not a CHAR */

			/*
			 * This mustn't be a CTL to be part of a token.
			 *
			 * XXX - what about leading LWS on continuation
			 * lines of a header?
			 */
			if (iscntrl(c))
				break;	/* CTL, not part of a header */

			switch (c) {

			case '(':
			case ')':
			case '<':
			case '>':
			case '@':
			case ',':
			case ';':
			case '\\':
			case '"':
			case '/':
			case '[':
			case ']':
			case '?':
			case '=':
			case '{':
			case '}':
				/*
				 * It's a tspecial, so it's not
				 * part of a token, so it's not
				 * a field name for the beginning
				 * of a header.
				 */
				goto not_rtsp;

			case ':':
				/*
				 * This ends the token; we consider
				 * this to be a header.
				 */
				is_header = TRUE;
				goto is_rtsp;

			case ' ':
			case '\t':
				/*
				 * LWS (RFC-2616, 4.2); continue the previous
				 * header.
				 */
				goto is_rtsp;
			}
		}

		/*
		 * We haven't seen the colon, but everything else looks
		 * OK for a header line.
		 *
		 * If we've already seen an RTSP request or response
		 * line, or a header line, and we're at the end of
		 * the tvbuff, we assume this is an incomplete header
		 * line.  (We quit this loop after seeing a blank line,
		 * so if we've seen a request or response line, or a
		 * header line, this is probably more of the request
		 * or response we're presumably seeing.  There is some
		 * risk of false positives, but the same applies for
		 * full request or response lines or header lines,
		 * although that's less likely.)
		 *
		 * We throw an exception in that case, by checking for
		 * the existence of the next byte after the last one
		 * in the line.  If it exists, "tvb_ensure_bytes_exist()"
		 * throws no exception, and we fall through to the
		 * "not RTSP" case.  If it doesn't exist,
		 * "tvb_ensure_bytes_exist()" will throw the appropriate
		 * exception.
		 */
		if (saw_req_resp_or_header)
			tvb_ensure_bytes_exist(tvb, offset, linelen + 1);

	not_rtsp:
		/*
		 * We don't consider this part of an RTSP request or
		 * reply, so we don't display it.
		 */
		break;

	is_rtsp:
		/*
		 * Process this line.
		 */
		if (linelen == 0) {
			/*
			 * This is a blank line, which means that
			 * whatever follows it isn't part of this
			 * request or reply.
			 */
			proto_tree_add_text(rtsp_tree, tvb, offset,
			                    next_offset - offset, "%s",
			                    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
			break;
		}

		/*
		 * Not a blank line - either a request, a reply, or a header
		 * line.
		 */
		saw_req_resp_or_header = TRUE;
		if (rtsp_tree) {

			switch (rtsp_type)
			{
				case RTSP_REQUEST:
					process_rtsp_request(tvb, offset, line, linelen, next_offset, rtsp_tree);
					break;

				case RTSP_REPLY:
					process_rtsp_reply(tvb, offset, line, linelen, next_offset, rtsp_tree);
					break;

				case RTSP_NOT_FIRST_LINE:
					/* Drop through, it may well be a header line */
					break;
			}
		}

		if (is_header)
		{
			/* We know that colon_offset must be set */

			/* Skip whitespace after the colon. */
			value_offset = colon_offset + 1;
			while ((value_offset < line_end_offset) &&
				   ((c = tvb_get_guint8(tvb, value_offset)) == ' ' || c == '\t'))
			{
				value_offset++;
			}
			value_len = line_end_offset - value_offset;

			/*
			 * Process some headers specially.
			 */
#define HDR_MATCHES(header) \
	( (size_t)linelen > STRLEN_CONST(header) && \
	 g_ascii_strncasecmp(line, (header), STRLEN_CONST(header)) == 0)

			if (HDR_MATCHES(rtsp_transport))
			{
				proto_tree_add_string(rtsp_tree, hf_rtsp_transport, tvb,
				                      offset, linelen,
				                      tvb_format_text(tvb, value_offset,
				                                      value_len));

				/*
				 * Based on the port numbers specified
				 * in the Transport: header, set up
				 * a conversation that will be dissected
				 * with the appropriate dissector.
				 */
				rtsp_create_conversation(pinfo, line, linelen, rdt_feature_level);
			} else if (HDR_MATCHES(rtsp_content_type))
			{
				proto_tree_add_string(rtsp_tree, hf_rtsp_content_type,
				                      tvb, offset, linelen,
				                      tvb_format_text(tvb, value_offset,
				                                      value_len));

				offset = offset + STRLEN_CONST(rtsp_content_type);
				/* Skip wsp */
				offset = tvb_skip_wsp(tvb, offset, value_len);
				semi_colon_offset = tvb_find_guint8(tvb, value_offset, value_len, ';');
				if ( semi_colon_offset != -1) {
					/* m-parameter present */
					par_end_offset = tvb_skip_wsp_return(tvb, semi_colon_offset-1);
					value_len = par_end_offset - offset;
				}

				media_type_str_lower_case = ascii_strdown_inplace(
                                    (gchar *)tvb_get_ephemeral_string(tvb, offset, value_len));

			} else if (HDR_MATCHES(rtsp_content_length))
			{
				proto_tree_add_uint(rtsp_tree, hf_rtsp_content_length,
				                    tvb, offset, linelen,
				                    atoi(tvb_format_text(tvb, value_offset,
				                                         value_len)));

				/*
				 * Only the amount specified by the
				 * Content-Length: header should be treated
				 * as payload.
				 */
				content_length = rtsp_get_content_length(line, linelen);

			} else if (HDR_MATCHES(rtsp_Session))
			{
				session_id = tvb_format_text(tvb, value_offset, value_len);
				/* Put the value into the protocol tree */
				proto_tree_add_string(rtsp_tree, hf_rtsp_session, tvb,
				                      offset, linelen,
				                      session_id);

			} else if (HDR_MATCHES(rtsp_X_Vig_Msisdn)) {
				/*
				 * Extract the X_Vig_Msisdn string
				 */
				if (colon_offset != -1)
				{
					/* Put the value into the protocol tree */
					ti = proto_tree_add_string(rtsp_tree, hf_rtsp_X_Vig_Msisdn,tvb,
					                           offset, linelen ,
					                           tvb_format_text(tvb, value_offset, value_len));
					sub_tree = proto_item_add_subtree(ti, ett_rtsp_method);

					e164_info.e164_number_type = CALLING_PARTY_NUMBER;
					e164_info.nature_of_address = 0;

					e164_info.E164_number_str = tvb_get_ephemeral_string(tvb, value_offset,
					                                              value_len);
					e164_info.E164_number_length = value_len;
					dissect_e164_number(tvb, sub_tree, value_offset,
					                    value_len, e164_info);
				}
			} else if (HDR_MATCHES(rtsp_rdt_feature_level))
			{
				rdt_feature_level = atoi(tvb_format_text(tvb, value_offset,
				                                         value_len));
				proto_tree_add_uint(rtsp_tree, hf_rtsp_rdtfeaturelevel,
				                    tvb, offset, linelen,
				                    atoi(tvb_format_text(tvb, value_offset,
				                                         value_len)));
			}
			else
			{
				/* Default case for headers. Show line as text */
				proto_tree_add_text(rtsp_tree, tvb, offset,
				                    next_offset - offset, "%s",
				                    tvb_format_text(tvb, offset, next_offset - offset));
			}
		}
		else if (rtsp_type == RTSP_NOT_FIRST_LINE)
		{
			/* Catch-all for all other lines... Show line as text.
			   TODO: should these be shown as errors? */
			proto_tree_add_text(rtsp_tree, tvb, offset,
			                    next_offset - offset, "%s",
			                    tvb_format_text(tvb, offset, next_offset - offset));
		}

		offset = next_offset;
	}

	if (session_id) {
		stat_info = ep_alloc0(sizeof(voip_packet_info_t));
		stat_info->protocol_name = ep_strdup("RTSP");
		stat_info->call_id = session_id;
		stat_info->frame_label = frame_label;
		stat_info->call_state = VOIP_CALL_SETUP;
		stat_info->call_active_state = VOIP_NO_STATE;
		stat_info->frame_comment = frame_label;
		tap_queue_packet(voip_tap, pinfo, stat_info);
	}

	/*
	 * Have now read all of the lines of this message.
	 *
	 * If a content length was supplied, the amount of data to be
	 * processed as RTSP payload is the minimum of the content
	 * length and the amount of data remaining in the frame.
	 *
	 * If no content length was supplied (or if a bad content length
	 * was supplied), the amount of data to be processed is the amount
	 * of data remaining in the frame.
	 */
	datalen = tvb_length_remaining(tvb, offset);
	reported_datalen = tvb_reported_length_remaining(tvb, offset);
	if (content_length != -1) {
		/*
		 * Content length specified; display only that amount
		 * as payload.
		 */
		if (datalen > content_length)
			datalen = content_length;

		/*
		 * XXX - limit the reported length in the tvbuff we'll
		 * hand to a subdissector to be no greater than the
		 * content length.
		 *
		 * We really need both unreassembled and "how long it'd
		 * be if it were reassembled" lengths for tvbuffs, so
		 * that we throw the appropriate exceptions for
		 * "not enough data captured" (running past the length),
		 * "packet needed reassembly" (within the length but
		 * running past the unreassembled length), and
		 * "packet is malformed" (running past the reassembled
		 * length).
		 */
		if (reported_datalen > content_length)
			reported_datalen = content_length;
	} else {
		/*
		 * No content length specified; if this message doesn't
		 * have a body if no content length is specified, process
		 * nothing as payload.
		 */
		if (body_requires_content_len)
			datalen = 0;
	}

	if (datalen > 0) {
		/*
		 * There's stuff left over; process it.
		 */
		tvbuff_t *new_tvb;

		/*
		 * Now create a tvbuff for the Content-type stuff and
		 * dissect it.
		 *
		 * The amount of data to be processed that's
		 * available in the tvbuff is "datalen", which
		 * is the minimum of the amount of data left in
		 * the tvbuff and any specified content length.
		 *
		 * The amount of data to be processed that's in
		 * this frame, regardless of whether it was
		 * captured or not, is "reported_datalen",
		 * which, if no content length was specified,
		 * is -1, i.e. "to the end of the frame.
		 */
		new_tvb = tvb_new_subset(tvb, offset, datalen,
			    reported_datalen);

		if (media_type_str_lower_case &&
			dissector_try_string(media_type_dissector_table,
				media_type_str_lower_case,
				new_tvb, pinfo, rtsp_tree)){

		}else {
			/*
			 * Fix up the top-level item so that it doesn't
			 * include the SDP stuff.
			 */
			if (ti != NULL)
				proto_item_set_len(ti, offset);

			if (tvb_get_guint8(tvb, offset) == RTSP_FRAMEHDR) {
				/*
				 * This is interleaved stuff; don't
				 * treat it as raw data - set "datalen"
				 * to 0, so we won't skip the offset
				 * past it, which will cause our
				 * caller to process that stuff itself.
				 */
				datalen = 0;
			} else {
				proto_tree_add_text(rtsp_tree, tvb, offset,
				    datalen, "Data (%d bytes)",
				    reported_datalen);
			}
		}

		/*
		 * We've processed "datalen" bytes worth of data
		 * (which may be no data at all); advance the
		 * offset past whatever data we've processed.
		 */
		offset += datalen;
	}
	return offset - orig_offset;
}

static void
process_rtsp_request(tvbuff_t *tvb, int offset, const guchar *data,
                     size_t linelen, size_t next_line_offset, proto_tree *tree)
{
	proto_tree		*sub_tree = NULL;
	proto_item		*ti = NULL;
	const guchar	*lineend = data + linelen;
	unsigned		ii;
	const guchar	*url;
	const guchar	*url_start;
	guchar			*tmp_url;

	/* Request Methods */
	for (ii = 0; ii < RTSP_NMETHODS; ii++) {
		size_t len = strlen(rtsp_methods[ii]);
		if (linelen >= len &&
		    g_ascii_strncasecmp(rtsp_methods[ii], data, len) == 0 &&
		    (len == linelen || isspace(data[len])))
			break;
	}
	if (ii == RTSP_NMETHODS) {
		/*
		 * We got here because "is_rtsp_request_or_reply()" returned
		 * RTSP_REQUEST, so we know one of the request methods
		 * matched, so we "can't get here".
		 */
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	/* Add a tree for this request */
	ti = proto_tree_add_string(tree, hf_rtsp_request, tvb, offset,
	                          (gint) (next_line_offset - offset),
	                          tvb_format_text(tvb, offset, (gint) (next_line_offset - offset)));
	sub_tree = proto_item_add_subtree(ti, ett_rtsp_method);


	/* Add method name to tree */
	proto_tree_add_string(sub_tree, hf_rtsp_method, tvb, offset,
	                      (gint) strlen(rtsp_methods[ii]), rtsp_methods[ii]);

	/* URL */
	url = data;
	/* Skip method name again */
	while (url < lineend && !isspace(*url))
		url++;
	/* Skip spaces */
	while (url < lineend && isspace(*url))
		url++;
	/* URL starts here */
	url_start = url;
	/* Scan to end of URL */
	while (url < lineend && !isspace(*url))
		url++;
	/* Create a URL-sized buffer and copy contents */
	tmp_url = ep_strndup(url_start, url - url_start);

	/* Add URL to tree */
	proto_tree_add_string(sub_tree, hf_rtsp_url, tvb,
	                      offset + (gint) (url_start - data), (gint) (url - url_start), tmp_url);
}

/* Read first line of a reply message */
static void
process_rtsp_reply(tvbuff_t *tvb, int offset, const guchar *data,
	size_t linelen, size_t next_line_offset, proto_tree *tree)
{
	proto_tree		*sub_tree = NULL;
	proto_item		*ti = NULL;
	const guchar	*lineend = data + linelen;
	const guchar	*status = data;
	const guchar	*status_start;
	unsigned int	status_i;

	/* Add a tree for this request */
	ti = proto_tree_add_string(tree, hf_rtsp_response, tvb, offset,
	                           (gint) (next_line_offset - offset),
	                           tvb_format_text(tvb, offset, (gint) (next_line_offset - offset)));
	sub_tree = proto_item_add_subtree(ti, ett_rtsp_method);


	/* status code */

	/* Skip protocol/version */
	while (status < lineend && !isspace(*status))
		status++;
	/* Skip spaces */
	while (status < lineend && isspace(*status))
		status++;

	/* Actual code number now */
	status_start = status;
	status_i = 0;
	while (status < lineend && isdigit(*status))
		status_i = status_i * 10 + *status++ - '0';

	/* Add field to tree */
	proto_tree_add_uint(sub_tree, hf_rtsp_status, tvb,
	                    offset + (gint) (status_start - data),
	                    (gint) (status - status_start), status_i);
}

static void
dissect_rtsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	int		len;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		len = (tvb_get_guint8(tvb, offset) == RTSP_FRAMEHDR)
			? dissect_rtspinterleaved(tvb, offset, pinfo, tree)
			: dissect_rtspmessage(tvb, offset, pinfo, tree);
		if (len == -1)
			break;
		offset += len;

		/*
		 * OK, we've set the Protocol and Info columns for the
		 * first RTSP message; make the columns non-writable,
		 * so that we don't change it for subsequent RTSP messages.
		 */
		col_set_writable(pinfo->cinfo, FALSE);
	}
}

void
proto_register_rtsp(void)
{
	static gint *ett[] = {
		&ett_rtspframe,
		&ett_rtsp,
		&ett_rtsp_method,
	};
	static hf_register_info hf[] = {
		{ &hf_rtsp_request,
			{ "Request", "rtsp.request", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_response,
			{ "Response", "rtsp.response", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_method,
			{ "Method", "rtsp.method", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_content_type,
			{ "Content-type", "rtsp.content-type", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_content_length,
			{ "Content-length", "rtsp.content-length", FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_url,
			{ "URL", "rtsp.url", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_status,
			{ "Status", "rtsp.status", FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_session,
			{ "Session", "rtsp.session", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_transport,
			{ "Transport", "rtsp.transport", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_rdtfeaturelevel,
			{ "RDTFeatureLevel", "rtsp.rdt-feature-level", FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }},
		{ &hf_rtsp_X_Vig_Msisdn,
			{ "X-Vig-Msisdn", "rtsp.X_Vig_Msisdn", FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }},


	};
	module_t *rtsp_module;

	proto_rtsp = proto_register_protocol("Real Time Streaming Protocol",
		"RTSP", "rtsp");

	proto_register_field_array(proto_rtsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Make this dissector findable by name */
	register_dissector("rtsp", dissect_rtsp, proto_rtsp);

	/* Register our configuration options, particularly our ports */

	rtsp_module = prefs_register_protocol(proto_rtsp, proto_reg_handoff_rtsp);
	prefs_register_uint_preference(rtsp_module, "tcp.port",
		"RTSP TCP Port",
		"Set the TCP port for RTSP messages",
		10, &global_rtsp_tcp_port);
	prefs_register_uint_preference(rtsp_module, "tcp.alternate_port",
		"Alternate RTSP TCP Port",
		"Set the alternate TCP port for RTSP messages",
		10, &global_rtsp_tcp_alternate_port);
	prefs_register_bool_preference(rtsp_module, "desegment_headers",
	    "Reassemble RTSP headers spanning multiple TCP segments",
	    "Whether the RTSP dissector should reassemble headers "
	    "of a request spanning multiple TCP segments. "
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &rtsp_desegment_headers);
	prefs_register_bool_preference(rtsp_module, "desegment_body",
	    "Trust the \"Content-length:\" header and\ndesegment RTSP "
	    "bodies\nspanning multiple TCP segments",
	    "Whether the RTSP dissector should use the "
	    "\"Content-length:\" value to desegment the body "
	    "of a request spanning multiple TCP segments",
	    &rtsp_desegment_body);

}

void
proto_reg_handoff_rtsp(void)
{
	static dissector_handle_t rtsp_handle;
	static gboolean rtsp_prefs_initialized = FALSE;
	/*
	 * Variables to allow for proper deletion of dissector registration when
	 * the user changes port from the gui.
	 */
	static guint saved_rtsp_tcp_port;
	static guint saved_rtsp_tcp_alternate_port;

	if (!rtsp_prefs_initialized) {
		rtsp_handle = find_dissector("rtsp");
		rtp_handle = find_dissector("rtp");
		rtcp_handle = find_dissector("rtcp");
		rdt_handle = find_dissector("rdt");
		media_type_dissector_table = find_dissector_table("media_type");
	    voip_tap = find_tap_id("voip");
		rtsp_prefs_initialized = TRUE;
	}
	else {
		dissector_delete_uint("tcp.port", saved_rtsp_tcp_port, rtsp_handle);
		dissector_delete_uint("tcp.port", saved_rtsp_tcp_alternate_port, rtsp_handle);
	}
	/* Set our port number for future use */
	dissector_add_uint("tcp.port", global_rtsp_tcp_port, rtsp_handle);
	dissector_add_uint("tcp.port", global_rtsp_tcp_alternate_port, rtsp_handle);

	saved_rtsp_tcp_port = global_rtsp_tcp_port;
	saved_rtsp_tcp_alternate_port = global_rtsp_tcp_alternate_port;

}

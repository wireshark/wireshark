/* packet-ftp.c
 * Routines for ftp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copyright 2001, Juan Toledo <toledo@users.sourceforge.net> (Passive FTP)
 * 
 * $Id: packet-ftp.c,v 1.38 2001/12/03 03:59:34 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "conversation.h"

static int proto_ftp = -1;
static int proto_ftp_data = -1;
static int hf_ftp_response = -1;
static int hf_ftp_request = -1;
static int hf_ftp_request_command = -1;
static int hf_ftp_request_data = -1;
static int hf_ftp_response_code = -1;
static int hf_ftp_response_data = -1;

static gint ett_ftp = -1;
static gint ett_ftp_data = -1;

static dissector_handle_t ftpdata_handle;

#define TCP_PORT_FTPDATA		20
#define TCP_PORT_FTP			21

static void
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * Handle a response to a PASV command.
 *
 * We ignore the IP address in the reply, and use the address from which
 * the request came.
 *
 * XXX - are there cases where they differ?  What if the FTP server is
 * behind a NAT box, so that the address it puts into the reply isn't
 * the address at which you should contact it?  Do all NAT boxes detect
 * FTP PASV replies and rewrite the address?  (I suspect not.)
 *
 * RFC 959 doesn't say much about the syntax of the 227 reply.
 *
 * A proposal from Dan Bernstein at
 *
 *	http://cr.yp.to/ftp/retr.html
 *
 * "recommend[s] that clients use the following strategy to parse the
 * response line: look for the first digit after the initial space; look
 * for the fourth comma after that digit; read two (possibly negative)
 * integers, separated by a comma; the TCP port number is p1*256+p2, where
 * p1 is the first integer modulo 256 and p2 is the second integer modulo
 * 256."
 *
 * wget 1.5.3 looks for a digit, although it doesn't handle negative
 * integers.
 *
 * The FTP code in the source of the cURL library, at
 *
 *	http://curl.haxx.se/lxr/source/lib/ftp.c
 *
 * says that cURL "now scans for a sequence of six comma-separated numbers
 * and will take them as IP+port indicators"; it loops, doing "sscanf"s
 * looking for six numbers separated by commas, stepping the start pointer
 * in the scanf one character at a time - i.e., it tries rather exhaustively.
 *
 * An optimization would be to scan for a digit, and start there, and if
 * the scanf doesn't find six values, scan for the next digit and try
 * again; this will probably succeed on the first try.
 *
 * The cURL code also says that "found reply-strings include":
 *
 *	"227 Entering Passive Mode (127,0,0,1,4,51)"
 *	"227 Data transfer will passively listen to 127,0,0,1,4,51"
 *	"227 Entering passive mode. 127,0,0,1,4,51"
 *
 * so it appears that you can't assume there are parentheses around
 * the address and port number.
 */
static void
handle_pasv_response(const u_char *line, int linelen, packet_info *pinfo)
{
	char *args;
	char *p;
	u_char c;
	int i;
	int address[4], port[2];
	guint16 server_port;
	conversation_t 	*conversation;

	/*
	 * Copy the rest of the line into a null-terminated buffer.
	 */
	args = g_malloc(linelen + 1);
	memcpy(args, line, linelen);
	args[linelen] = '\0';
	p = args;

	for (;;) {
		/*
		 * Look for a digit.
		 */
		while ((c = *p) != '\0' && !isdigit(c))
			p++;

		if (*p == '\0') {
			/*
			 * We ran out of text without finding anything.
			 */
			break;
		}
			
		/*
		 * See if we have six numbers.
		 */
		i = sscanf(p, "%d,%d,%d,%d,%d,%d",
		    &address[0], &address[1], &address[2], &address[3],
		    &port[0], &port[1]);
		if (i == 6) {
			/*
			 * We have a winner!
			 * Set up a conversation, to be dissected as FTP data.
			 */
			server_port = ((port[0] & 0xFF)<<8) | (port[1] & 0xFF);

			/*
			 * XXX - should this call to "find_conversation()"
			 * just use "pinfo->src" and "server_port", and
			 * wildcard everything else?
			 */
			conversation = find_conversation(&pinfo->src,
			    &pinfo->dst, PT_TCP, server_port, 0, NO_PORT_B);
			if (conversation == NULL) {
				/*
				 * XXX - should this call to
				 * "conversation_new()" just use "pinfo->src"
				 * and "server_port", and wildcard everything
				 * else?
				 *
				 * XXX - what if we did find a conversation?
				 * As we create it only on the first pass
				 * through the packets, if we find one, it's
				 * presumably an unrelated conversation.
				 * Should we remove the old one from the hash
				 * table and put this one in its place?
				 * Can the conversaton code handle
				 * conversations not in the hash table?
				 */
				conversation = conversation_new(&pinfo->src,
				    &pinfo->dst, PT_TCP, server_port, 0,
				    NO_PORT2);
				conversation_set_dissector(conversation,
				    ftpdata_handle);
			}
			break;
		}

		/*
		 * Well, that didn't work.  Skip the first number we found,
		 * and keep trying.
		 */
		while ((c = *p) != '\0' && isdigit(c))
			p++;
	}

	g_free(args);
}	

static void
dissect_ftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request;
        proto_tree      *ftp_tree = NULL;
	proto_item	*ti;
	gint		offset = 0;
	const u_char	*line;
	gboolean	is_pasv_response = FALSE;
	gint		next_offset;
	int		linelen;
	int		tokenlen;
	const u_char	*next_token;

	if (pinfo->match_port == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "FTP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * (but leave out the line terminator).
		 */
		col_add_fstr(pinfo->fd, COL_INFO, "%s: %s",
		    is_request ? "Request" : "Response",
		    format_text(line, linelen));
	}
   
	if (tree) {
		ti = proto_tree_add_item(tree, proto_ftp, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		ftp_tree = proto_item_add_subtree(ti, ett_ftp);

		if (is_request) {
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_request, tvb, 0, 0, TRUE);
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_response, tvb, 0, 0, FALSE);
		} else {
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_request, tvb, 0, 0, FALSE);
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_response, tvb, 0, 0, TRUE);
		}
	}

	/*
	 * Extract the first token, and, if there is a first
	 * token, add it as the request or reply code.
	 */
	tokenlen = get_token_len(line, line + linelen, &next_token);
	if (tokenlen != 0) {
		if (is_request) {
			if (tree) {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_request_command, tvb, offset,
				    tokenlen, line, "Request: %s",
				    format_text(line, tokenlen));
			}
		} else {
			/*
			 * This is a response; see if it's a passive-mode
			 * response.
			 *
			 * XXX - check for "229" responses to EPSV
			 * commands, to handle IPv6, as per RFC 2428?
			 *
			 * XXX - does anybody do FOOBAR, as per RFC 1639,
			 * or has that been supplanted by RFC 2428?
			 */
			if (tokenlen == 3 &&
			    strncmp("227", line, tokenlen) == 0)
				is_pasv_response = TRUE;
			if (tree) {
				proto_tree_add_uint_format(ftp_tree,
				    hf_ftp_response_code, tvb, offset,
				    tokenlen, atoi(line), "Response: %s",
				    format_text(line, tokenlen));
			}
		}
		offset += next_token - line;
		linelen -= next_token - line;
		line = next_token;

		/*
		 * If this is a PASV response, handle it if we haven't
		 * already processed this frame.
		 */
		if (!pinfo->fd->flags.visited && is_pasv_response) {
			/*
			 * We haven't processed this frame, and it contains
			 * a PASV response; set up a conversation for the
			 * data.
			 */
			handle_pasv_response(line, linelen, pinfo);
		}
	}

	if (tree) {
		/*
		 * Add the rest of the first line as request or
		 * reply data.
		 */
		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_request_data, tvb, offset,
				    linelen, line, "Request Arg: %s",
				    format_text(line, linelen));
			} else {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_response_data, tvb, offset,
				    linelen, line, "Response Arg: %s",
				    format_text(line, linelen));
			}
		}
		offset = next_offset;

		/*
		 * Show the rest of the request or response as text,
		 * a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(ftp_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

static void
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *ti, *ftp_data_tree;
        int		data_length;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "FTP-DATA");

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, "FTP Data: %u bytes",
		    tvb_length(tvb));
	}

	if (tree) {
		data_length = tvb_length(tvb);

		ti = proto_tree_add_item(tree, proto_ftp_data, tvb, 0,
		    data_length, FALSE);
		ftp_data_tree = proto_item_add_subtree(ti, ett_ftp_data);

		/*
		 * XXX - if this is binary data, it'll produce
		 * a *really* long line.
		 */
		proto_tree_add_text(ftp_data_tree, tvb, 0, data_length,
		    "FTP Data: %s", tvb_format_text(tvb, 0, data_length));
	}
}

void
proto_register_ftp(void)
{
    static hf_register_info hf[] = {
    { &hf_ftp_response,
      { "Response",           "ftp.response",
      	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if FTP response", HFILL }},

    { &hf_ftp_request,
      { "Request",            "ftp.request",
      	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if FTP request", HFILL }},

    { &hf_ftp_request_command,
      { "Request command",    "ftp.request.command",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_request_data,
      { "Request data",	      "ftp.request.data",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_response_code,
      { "Response code",      "ftp.response.code",
      	FT_UINT8,   BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_response_data,
      { "Response data",      "ftp.reponse.data",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }}
  };
  static gint *ett[] = {
    &ett_ftp,
    &ett_ftp_data,
  };

  proto_ftp = proto_register_protocol("File Transfer Protocol (FTP)", "FTP",
				      "ftp");
  proto_ftp_data = proto_register_protocol("FTP Data", "FTP-DATA", "ftp-data");
  proto_register_field_array(proto_ftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ftpdata_handle = create_dissector_handle(dissect_ftpdata, proto_ftp_data);
}

void
proto_reg_handoff_ftp(void)
{
  dissector_handle_t ftpdata_handle, ftp_handle;

  ftpdata_handle = create_dissector_handle(dissect_ftpdata, proto_ftp_data);
  dissector_add("tcp.port", TCP_PORT_FTPDATA, ftpdata_handle);
  ftp_handle = create_dissector_handle(dissect_ftp, proto_ftp);
  dissector_add("tcp.port", TCP_PORT_FTP, ftp_handle);
}

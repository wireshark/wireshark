/* packet-ftp.c
 * Routines for ftp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copyright 2001, Juan Toledo <toledo@users.sourceforge.net> (Passive FTP)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/emem.h>

static int proto_ftp = -1;
static int proto_ftp_data = -1;
static int hf_ftp_response = -1;
static int hf_ftp_request = -1;
static int hf_ftp_request_command = -1;
static int hf_ftp_request_arg = -1;
static int hf_ftp_response_code = -1;
static int hf_ftp_response_arg = -1;
static int hf_ftp_pasv_ip = -1 ;
static int hf_ftp_pasv_port = -1;
static int hf_ftp_pasv_nat = -1;
static int hf_ftp_active_ip = -1;
static int hf_ftp_active_port = -1;
static int hf_ftp_active_nat = -1;

static gint ett_ftp = -1;
static gint ett_ftp_reqresp = -1;
static gint ett_ftp_data = -1;

static dissector_handle_t ftpdata_handle;

#define TCP_PORT_FTPDATA		20
#define TCP_PORT_FTP			21

static const value_string response_table[] = {
	{ 110, "Restart marker reply" },
	{ 120, "Service ready in nnn minutes" },
	{ 125, "Data connection already open; transfer starting" },
	{ 150, "File status okay; about to open data connection" },
	{ 200, "Command okay" },
	{ 202, "Command not implemented, superfluous at this site" },
	{ 211, "System status, or system help reply" },
	{ 212, "Directory status" },
	{ 213, "File status" },
	{ 214, "Help message" },
	{ 215, "NAME system type" },
	{ 220, "Service ready for new user" },
	{ 221, "Service closing control connection" },
	{ 225, "Data connection open; no transfer in progress" },
	{ 226, "Closing data connection" },
	{ 227, "Entering Passive Mode" },
	{ 230, "User logged in, proceed" },
	{ 250, "Requested file action okay, completed" },
	{ 257, "PATHNAME created" },
	{ 331, "User name okay, need password" },
	{ 332, "Need account for login" },
	{ 350, "Requested file action pending further information" },
	{ 421, "Service not available, closing control connection" },
	{ 425, "Can't open data connection" },
	{ 426, "Connection closed; transfer aborted" },
	{ 450, "Requested file action not taken" },
	{ 451, "Requested action aborted: local error in processing" },
	{ 452, "Requested action not taken. Insufficient storage space in system" },
	{ 500, "Syntax error, command unrecognized" },
	{ 501, "Syntax error in parameters or arguments" },
	{ 502, "Command not implemented" },
	{ 503, "Bad sequence of commands" },
	{ 504, "Command not implemented for that parameter" },
	{ 530, "Not logged in" },
	{ 532, "Need account for storing files" },
	{ 550, "Requested action not taken: File unavailable" },
	{ 551, "Requested action aborted: page type unknown" },
	{ 552, "Requested file action aborted: Exceeded storage allocation" },
	{ 553, "Requested action not taken: File name not allowed" },
	{ 0,   NULL }
};
		
static void
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*
 * Parse the address and port information in a PORT command or in the
 * response to a PASV command.  Return TRUE if we found an address and
 * port, and supply the address and port; return FALSE if we didn't find
 * them.
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
static gboolean
parse_port_pasv(const guchar *line, int linelen, guint32 *ftp_ip,
    guint16 *ftp_port)
{
	char *args;
	char *p;
	guchar c;
	int i;
	int address[4], port[2];
	gboolean ret = FALSE;

	/*
	 * Copy the rest of the line into a null-terminated buffer.
	 */
	args = ep_alloc(linelen + 1);
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
			 */
			*ftp_port = ((port[0] & 0xFF)<<8) | (port[1] & 0xFF);
			*ftp_ip = g_htonl((address[0] << 24) | (address[1] <<16) | (address[2] <<8) | address[3]);
			ret = TRUE;
			break;
		}

		/*
		 * Well, that didn't work.  Skip the first number we found,
		 * and keep trying.
		 */
		while ((c = *p) != '\0' && isdigit(c))
			p++;
	}

	return ret;
}

static void
dissect_ftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request;
        proto_tree      *ftp_tree = NULL;
        proto_tree      *reqresp_tree = NULL;
	proto_item	*ti;
	gint		offset = 0;
	const guchar	*line;
	guint32		code;
	gchar		code_str[4];
	gboolean	is_port_request = FALSE;
	gboolean	is_pasv_response = FALSE;
	gint		next_offset;
	int		linelen;
	int		tokenlen;
	const guchar	*next_token;
	guint32		pasv_ip;
	guint32		ftp_ip;
	guint16		ftp_port;
	address		ftp_ip_address;
	gboolean	ftp_nat;
	conversation_t	*conversation;

	ftp_ip_address = pinfo->src;

	if (pinfo->match_port == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * (but leave out the line terminator).
		 */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
		    is_request ? "Request" : "Response",
		    format_text(line, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ftp, tvb, offset, -1,
		    FALSE);
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

		/*
		 * Put the line into the protocol tree.
		 */
		ti = proto_tree_add_text(ftp_tree, tvb, offset,
		    next_offset - offset, "%s",
		    tvb_format_text(tvb, offset, next_offset - offset));
		reqresp_tree = proto_item_add_subtree(ti, ett_ftp_reqresp);
	}

	if (is_request) {
		/*
		 * Extract the first token, and, if there is a first
		 * token, add it as the request.
		 */
		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			if (tree) {
				proto_tree_add_item(reqresp_tree,
				    hf_ftp_request_command, tvb, offset,
				    tokenlen, FALSE);
			}
			if (strncmp(line, "PORT", tokenlen) == 0)
				is_port_request = TRUE;
		}
	} else {
		/*
		 * This is a response; the response code is 3 digits,
		 * followed by a space or hyphen, possibly followed by
		 * text.
		 *
		 * If the line doesn't start with 3 digits, it's part of
		 * a continuation.
		 *
		 * XXX - keep track of state in the first pass, and
		 * treat non-continuation lines not beginning with digits
		 * as errors?
		 */
		if (linelen >= 3 && isdigit(line[0]) && isdigit(line[1])
		    && isdigit(line[2])) {
			/*
			 * One-line reply, or first or last line
			 * of a multi-line reply.
			 */
			tvb_get_nstringz0(tvb, offset, sizeof(code_str), code_str);
			code = strtoul(code_str, NULL, 10);
				
			if (tree) {
				proto_tree_add_uint(reqresp_tree,
				    hf_ftp_response_code, tvb, offset, 3, code);
			}

			/*
			 * See if it's a passive-mode response.
			 *
			 * XXX - check for "229" responses to EPSV
			 * commands, to handle IPv6, as per RFC 2428?
			 *
			 * XXX - does anybody do FOOBAR, as per RFC
			 * 1639, or has that been supplanted by RFC 2428?
			 */
			if (code == 227)
				is_pasv_response = TRUE;

			/*
			 * Skip the 3 digits and, if present, the
			 * space or hyphen.
			 */
			if (linelen >= 4)
				next_token = line + 4;
			else
				next_token = line + linelen;
		} else {
			/*
			 * Line doesn't start with 3 digits; assume it's
			 * a line in the middle of a multi-line reply.
			 */
			next_token = line;
		}
	}
	offset += next_token - line;
	linelen -= next_token - line;
	line = next_token;

	if (tree) {
		/*
		 * Add the rest of the first line as request or
		 * reply data.
		 */
		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_item(reqresp_tree,
				    hf_ftp_request_arg, tvb, offset,
				    linelen, FALSE);
			} else {
				proto_tree_add_item(reqresp_tree,
				    hf_ftp_response_arg, tvb, offset,
				    linelen, FALSE);
			}
		}
		offset = next_offset;
	}

	/*
	 * If this is a PORT request or a PASV response, handle it.
	 */
	if (is_port_request) {
		if (parse_port_pasv(line, linelen, &ftp_ip,
		    &ftp_port)) {
			if (tree) {
				proto_tree_add_ipv4(reqresp_tree,
				    hf_ftp_active_ip, tvb, 0, 0,
				    ftp_ip);
				proto_tree_add_uint(reqresp_tree,
				    hf_ftp_active_port, tvb, 0, 0,
				    ftp_port);
			}
			SET_ADDRESS(&ftp_ip_address, AT_IPv4, 4,
			    (const guint8 *)&ftp_ip);
			ftp_nat = !ADDRESSES_EQUAL(&pinfo->src,
			    &ftp_ip_address);
			if (ftp_nat) {
				if (tree) {
					proto_tree_add_boolean(
					    reqresp_tree,
					    hf_ftp_active_nat, tvb,
					    0, 0, ftp_nat);
				}
			}
		}
	}

	if (is_pasv_response) {
		if (linelen != 0) {
			/*
			 * This frame contains a PASV response; set up a
			 * conversation for the data.
			 */
			if (parse_port_pasv(line, linelen, &pasv_ip,
			    &ftp_port)) {
				if (tree) {
					proto_tree_add_ipv4(reqresp_tree,
					    hf_ftp_pasv_ip, tvb, 0, 0, pasv_ip);
					proto_tree_add_uint(reqresp_tree,
					    hf_ftp_pasv_port, tvb, 0, 0,
					    ftp_port);
				}
				SET_ADDRESS(&ftp_ip_address, AT_IPv4, 4,
				    (const guint8 *)&pasv_ip);
				ftp_nat = !ADDRESSES_EQUAL(&pinfo->src,
				    &ftp_ip_address);
				if (ftp_nat) {
					if (tree) {
						proto_tree_add_boolean(reqresp_tree,
						    hf_ftp_pasv_nat, tvb, 0, 0,
						    ftp_nat);
					}
				}

				/*
				 * We use "ftp_ip_address", so that if
				 * we're NAT'd we look for the un-NAT'd
				 * connection.
				 *
				 * XXX - should this call to
				 * "find_conversation()" just use
				 * "ftp_ip_address" and "server_port", and
				 * wildcard everything else?
				 */
				conversation = find_conversation(pinfo->fd->num, &ftp_ip_address,
				    &pinfo->dst, PT_TCP, ftp_port, 0,
				    NO_PORT_B);
				if (conversation == NULL) {
					/*
					 * XXX - should this call to
					 * "conversation_new()" just use
					 * "ftp_ip_address" and "server_port",
					 * and wildcard everything else?
					 *
					 * XXX - what if we did find a
					 * conversation?  As we create it
					 * only on the first pass through
					 * the packets, if we find one, it's
					 * presumably an unrelated conversation.
					 * Should we remove the old one from
					 * the hash table and put this one in
					 * its place?  Can the conversation
					 * code handle conversations not in
					 * the hash table?  Or should we
					 * make conversations support
					 * start and end frames, as circuits
					 * do, and treat this as an indication
					 * that one conversation was closed
					 * and a new one was opened?
					 */
					conversation = conversation_new(
					    pinfo->fd->num, &ftp_ip_address, &pinfo->dst,
					    PT_TCP, ftp_port, 0, NO_PORT2);
					conversation_set_dissector(conversation,
					    ftpdata_handle);
				}
			}
		}
	}

	if (tree) {
		/*
		 * Show the rest of the request or response as text,
		 * a line at a time.
		 * XXX - only if there's a continuation indicator?
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset, FALSE);

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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTP-DATA");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "FTP Data: %u bytes",
		    tvb_reported_length(tvb));
	}

	if (tree) {
		data_length = tvb_length(tvb);

		ti = proto_tree_add_item(tree, proto_ftp_data, tvb, 0, -1,
		    FALSE);
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

    { &hf_ftp_request_arg,
      { "Request arg",	      "ftp.request.arg",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_response_code,
      { "Response code",      "ftp.response.code",
      	FT_UINT32,   BASE_DEC, VALS(response_table), 0x0,
      	"", HFILL }},

    { &hf_ftp_response_arg,
      { "Response arg",      "ftp.response.arg",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_pasv_ip,
      { "Passive IP address", "ftp.passive.ip",
	FT_IPv4, BASE_NONE, NULL,0x0, 
        "Passive IP address (check NAT)", HFILL}},

    { &hf_ftp_pasv_port,
      { "Passive port", "ftp.passive.port",
       FT_UINT16, BASE_DEC, NULL,0x0,
	"Passive FTP server port", HFILL }},

    { &hf_ftp_pasv_nat,
      {"Passive IP NAT", "ftp.passive.nat",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"NAT is active SIP and passive IP different", HFILL }},

    { &hf_ftp_active_ip,
      { "Active IP address", "ftp.active.cip",
	FT_IPv4, BASE_NONE, NULL, 0x0,
	"Active FTP client IP address", HFILL }},

    { &hf_ftp_active_port,
      {"Active port", "ftp.active.port",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Active FTP client port", HFILL }},

    { &hf_ftp_active_nat,
      { "Active IP NAT", "ftp.active.nat",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"NAT is active", HFILL}}

  };
  static gint *ett[] = {
    &ett_ftp,
    &ett_ftp_reqresp,
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

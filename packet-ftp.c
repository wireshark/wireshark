/* packet-ftp.c
 * Routines for ftp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-ftp.c,v 1.8 1999/10/09 11:56:15 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

static int proto_ftp = -1;
static int hf_ftp_response = -1;
static int hf_ftp_request = -1;
static int hf_ftp_request_command = -1;
static int hf_ftp_request_data = -1;
static int hf_ftp_response_code = -1;
static int hf_ftp_response_data = -1;

void
dissect_ftp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        proto_tree      *ftp_tree, *ti;
	gchar          rr[50], rd[1500];
	int i1 = (u_char *)strchr(pd + offset, ' ') - (pd + offset); /* Where is that space */
	int i2;
	int max_data = pi.captured_len - offset;

	memset(rr, '\0', sizeof(rr));
	memset(rd, '\0', sizeof(rd));

	if (i1 >= 0) {

	  /* Hmmm, check if there was no space in there ... */

	  if (i1 > max_data) {

	    i1 = max_data;  /* Make things below work */
	    strncpy(rr, pd + offset, MIN(max_data - 2, sizeof(rr) - 1));

	  }
	  else {

	    strncpy(rr, pd + offset, MIN(i1, sizeof(rr) - 1));
	    i2 = ((u_char *)strchr(pd + offset + i1 + 1, '\r') - (pd + offset)) - i1 - 1;
	    if (i2 > max_data - i1 - 1 || i2 < 0) {
	      i2 = max_data - i1 - 1;
	    }

	    strncpy(rd, pd + offset + i1 + 1, MIN(i2, sizeof(rd) - 1));
	  }
	}
	else { 

	  i1 = max_data;
	  strncpy(rr, pd + offset, MIN(max_data - 2, sizeof(rr) - 1));  /* Lazy, CRLF */

	}

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "FTP");

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "%s: %s %s", (pi.match_port == pi.destport)? "Request" : "Response", rr, rd);

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_ftp, offset, END_OF_FRAME, NULL);
	  ftp_tree = proto_item_add_subtree(ti, ETT_FTP);

	  if (pi.match_port == pi.destport) { /* Request */

	    proto_tree_add_item_hidden(ftp_tree, hf_ftp_request,
				       offset, i1, TRUE);
	    proto_tree_add_item_hidden(ftp_tree, hf_ftp_response,
				       offset, i1, FALSE);
	    proto_tree_add_item_format(ftp_tree, hf_ftp_request_command,
				       offset, i1, rr, "Request: %s", rr);
	    proto_tree_add_item_format(ftp_tree, hf_ftp_request_data,
				       offset + i1 + 1, END_OF_FRAME, 
				       rd, "Request Arg: %s", rd);
	  }
	  else {

	    proto_tree_add_item_hidden(ftp_tree, hf_ftp_request,
				       offset, i1, FALSE);
	    proto_tree_add_item_hidden(ftp_tree, hf_ftp_response,
				       offset, i1, TRUE);
	    proto_tree_add_item_format(ftp_tree, hf_ftp_response_code, 
				       offset, i1, 
				       atoi(rr), "Response: %s", rr);
	    proto_tree_add_item_format(ftp_tree, hf_ftp_response_data,
				       offset + i1 + 1, END_OF_FRAME,
				       rd, "Response Arg: %s", rd);
	  }

	}
}

void
dissect_ftpdata(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        proto_tree      *ti;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "FTP DATA");

	if (check_col(fd, COL_INFO)) {

	  col_add_fstr(fd, COL_INFO, "FTP Data ...");

	}

	if (tree) {

	  ti = proto_tree_add_text(tree, offset, END_OF_FRAME,
				"File Transfer Protocol Data");

	}
}

void
proto_register_ftp(void)
{
  static hf_register_info hf[] = {
    { &hf_ftp_response,
      { "Response",           "ftp.response",		FT_BOOLEAN, NULL }},
    { &hf_ftp_request,
      { "Request",            "ftp.request",		FT_BOOLEAN, NULL }},
    { &hf_ftp_request_command,
      { "Request command",    "ftp.request.command",	FT_STRING,  NULL }},
    { &hf_ftp_request_data,
      { "Request data",	      "ftp.request.data",	FT_STRING,  NULL }},
    { &hf_ftp_response_code,
      { "Response code",      "ftp.response.code",	FT_UINT8,   NULL }},
    { &hf_ftp_response_data,
      { "Response data",      "ftp.reponse.data",	FT_STRING,  NULL }}
  };

  proto_ftp = proto_register_protocol("File Transfer Protocol", "ftp");
  proto_register_field_array(proto_ftp, hf, array_length(hf));

}

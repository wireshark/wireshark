/* packet-smtp.c
 * Routines for BXXP packet disassembly
 *
 * $Id: packet-smtp.c,v 1.1 2000/08/19 23:06:51 sharpe Exp $
 *
 * Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <string.h>
#include "packet.h"
#include "resolv.h"
#include "prefs.h"

#define TCP_PORT_SMTP 25

void proto_reg_handoff_smtp(void);

static int proto_smtp = -1;

static int hf_smtp_req = -1;
static int hf_smtp_rsp = -1;

static int ett_smtp = -1;

static int global_smtp_tcp_port = TCP_PORT_SMTP;

static
int find_smtp_resp_end(const u_char *pd, int offset)
{
  int cntr = 0;

  /* Look for the CRLF ... but keep in mind the END_OF_FRAME */

  while (END_OF_FRAME >= cntr) {

    if (pd[offset + cntr] == 0x0A) { /* Found it */

      if (END_OF_FRAME >= cntr + 1) cntr++;

      return cntr;

    }

    cntr++;

  }

  return cntr;

}

#if 0
static void
dissect_smtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#else
static void
dissect_smtp(const u_char *pd, int offset, frame_data *fd,
	     proto_tree *tree)
{
  /*    tvbuff_t *tvb = tvb_create_from_top(offset);*/
    packet_info *pinfo = &pi;
#endif
    void            *frame_data;
    proto_tree      *smtp_tree, *ti;
    int             request = 0;
    const u_char            *cmd = NULL, *data = NULL;

    /* Let's figure out this packet ... First check if we have done it 
       all before ... */

    frame_data = p_get_proto_data(fd, proto_smtp);  /* FIXME: What about tvb */

    /* SMTP messages have a simple format ... */

    if (!frame_data) {    /* We parse the frame and create the data */

      request = pinfo -> destport == TCP_PORT_SMTP;
      cmd = pd + offset;   /* FIXME: What about tvb */
      data = index(cmd, ' ');  /* Find the space */
      if (data) data++;                /* Skip the space if there */

    }
    else {

    }

    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "SMTP");

    if (check_col(fd, COL_INFO)) {  /* Add the appropriate type here */

      col_add_fstr(fd, COL_INFO, "%s", format_text(cmd, END_OF_FRAME));

    }

    if (tree) { /* Build the tree info ... */

      ti = proto_tree_add_item(tree, proto_smtp, NullTVB, offset, END_OF_FRAME, FALSE);
      smtp_tree = proto_item_add_subtree(ti, ett_smtp);
      proto_tree_add_boolean_hidden(smtp_tree, (request ? hf_smtp_req : hf_smtp_rsp),
				    NullTVB, offset, 4, TRUE);

      if (request) {
	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 4, "Command: %s", format_text(cmd, 4));
	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 5, END_OF_FRAME, "Parameter: %s", format_text(cmd + 5, END_OF_FRAME - 5));

      }
      else {

	/* Must consider a multi-line response here ... */

	while (END_OF_FRAME >= 4 && pd[offset + 3] == '-') {
	  int resp_len = find_smtp_resp_end(pd, offset);

	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 3, "Response: %s", format_text(pd + offset, 3));
	  proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 4, resp_len, "Parameter: %s", format_text(pd + offset + 4, resp_len - 4));

	  offset += resp_len;
	}

	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset, 3, "Response: %s", format_text(pd + offset, 3));
	proto_tree_add_protocol_format(smtp_tree, proto_smtp, NullTVB, offset + 4, END_OF_FRAME, "Parameter: %s", format_text(pd + offset + 4, END_OF_FRAME - 4));

      }
    }
}

/* Register all the bits needed by the filtering engine */

void
proto_register_smtp(void)
{
  static hf_register_info hf[] = {
    { &hf_smtp_req,
      { "Request", "smtp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},

    { &hf_smtp_rsp,
      { "Response", "smtp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, ""}},
  };
  static gint *ett[] = {
    &ett_smtp
  };
  /*module_t *smtp_module = NULL; */  /* Not yet used */

  /* No Configuration options to register? */

  proto_smtp = proto_register_protocol("Simple Message Transfer Protocol", "smtp");

  proto_register_field_array(proto_smtp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/* The registration hand-off routine */
void
proto_reg_handoff_smtp(void)
{
  static int smtp_prefs_initialized = FALSE;
  static int tcp_port = 0;

  if (smtp_prefs_initialized) {

    dissector_delete("tcp.port", tcp_port, dissect_smtp);

  }
  else {

    smtp_prefs_initialized = TRUE;

  }

  tcp_port = global_smtp_tcp_port;

  dissector_add("tcp.port", global_smtp_tcp_port, dissect_smtp);

}

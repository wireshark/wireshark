/* packet-echo.c
 * Routines for ECHO packet disassembly (RFC862)
 *
 * Only useful to mark the packets as ECHO in the summary and in the
 * protocol hierarchy statistics (since not so many fields to decode ;-)
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#define ECHO_PORT	7

static int proto_echo = -1;

static int hf_echo_data = -1;
static int hf_echo_request = -1;
static int hf_echo_response = -1;

static gint ett_echo = -1;

static void dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  
  proto_tree   *echo_tree = NULL;
  proto_item   *ti;
  int           offset = 0;
  gboolean      request = FALSE;
  const guint8 *data = tvb_get_ptr(tvb, offset, -1);

  if (pinfo->destport == ECHO_PORT) {
    request = TRUE;
  }

  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_add_str(pinfo->cinfo, COL_PROTOCOL, "ECHO");
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", 
		 (request) ? "Request" : "Response");
  }
  
  if (tree) {

    ti = proto_tree_add_item(tree, proto_echo, tvb, offset, -1, FALSE);
    echo_tree = proto_item_add_subtree(ti, ett_echo);

    if (request) {
      proto_tree_add_boolean_hidden(echo_tree, hf_echo_request, tvb, 0, 0, 1);
      
    } else {
      proto_tree_add_boolean_hidden(echo_tree, hf_echo_response, tvb, 0, 0, 1);
    }

    proto_tree_add_bytes(echo_tree, hf_echo_data, tvb, offset, -1, data);

  }

} /* dissect_echo */

void proto_register_echo(void) 
{

  static hf_register_info hf[] = {
    { &hf_echo_data,
      { "Echo data",	"echo.data", 
	FT_BYTES,	BASE_HEX,	NULL,	0x0,
      	"Echo data", HFILL }},
    { &hf_echo_request,
      { "Echo request",	"echo.request", 
	FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
      	"Echo data", HFILL }},
    { &hf_echo_response,
      { "Echo response","echo.response", 
	FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
      	"Echo data", HFILL }}
  };

  static gint *ett[] = {
    &ett_echo
  };

  proto_echo = proto_register_protocol("Echo", "ECHO", "echo");
  proto_register_field_array(proto_echo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_echo(void) 
{

  dissector_handle_t echo_handle = NULL;

  echo_handle = create_dissector_handle(dissect_echo, proto_echo);

  dissector_add("udp.port", ECHO_PORT, echo_handle);
  dissector_add("tcp.port", ECHO_PORT, echo_handle);

}


/* packet-ldp.c
 * Routines for ldp packet disassembly
 *
 * $Id: packet-ldp.c,v 1.2 2000/11/30 06:24:53 sharpe Exp $
 * 
 * Copyright (c) November 2000 by Richard Sharpe <rsharpe@ns.aus.com>
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

#define TCP_PORT_LDP 646
#define UDP_PORT_LDP 646

void proto_reg_handoff_ldp(void);

static int proto_ldp = -1;

/* Delete the following if you do not use it, or add to it if you need */
static int hf_ldp_req = -1;
static int hf_ldp_rsp = -1;
static int hf_ldp_version = -1;
static int hf_ldp_pdu_len = -1;
static int hf_ldp_lsr = -1;
static int hf_ldp_ls_id = -1;

static int ett_ldp = -1;
static int ett_ldp_header = -1;
static int ett_ldp_ldpid = -1;

static int tcp_port = 0;
static int udp_port = 0;

/* Add your functions here */

static int global_ldp_tcp_port = TCP_PORT_LDP;
static int global_ldp_udp_port = UDP_PORT_LDP;

#define LDP_NOTIFICATION       0x0001
#define LDP_HELLO              0x0100
#define LDP_INITIALIZATION     0x0200
#define LDP_KEEPALIVE          0x0201
#define LDP_ADDRESS            0x0300
#define LDP_ADDRESS_WITHDRAWAL 0x0301
#define LDP_LABEL_MAPPING      0x0400
#define LDP_LABEL_REQUEST      0x0401
#define LDP_LABEL_WITHDRAWAL   0x0402
#define LDP_LABEL_RELEASE      0x0403
#define LDP_LABEL_ABORT_REQUEST 0x0404

static const value_string ldp_message_types[] = {
  {LDP_NOTIFICATION,             "Notification"},
  {LDP_HELLO,                    "Hello"},
  {LDP_INITIALIZATION,           "Initialization"},
  {LDP_KEEPALIVE,                "Keep Alive"},
  {LDP_ADDRESS,                  "Address"},
  {LDP_ADDRESS_WITHDRAWAL,       "Address Withdrawal"},
  {LDP_LABEL_MAPPING,            "Label Mapping"},
  {LDP_LABEL_REQUEST,            "Label Request"},
  {LDP_LABEL_WITHDRAWAL,         "Label Withdrawal"},
  {LDP_LABEL_RELEASE,            "Label Release"},
  {LDP_LABEL_ABORT_REQUEST,      "Label Abort Request"},
  {0, NULL}
};

int dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

}

int
dissect_ldp_notification(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_hello(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_initialization(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_keepalive(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_address(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_address_withdrawal(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_label_mapping(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_label_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_label_withdrawal(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_label_release(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

int 
dissect_ldp_label_abort_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{

}

static void
dissect_ldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree     *ldp_tree = NULL, 
                 *ti = NULL,
                 *hdr_tree = NULL, *ldpid_tree = NULL;
  int	         offset = 0, msg_cnt = 0;
  guint16        ldp_message = 0;

/* Add your variables here */

#if 1
  CHECK_DISPLAY_AS_DATA(proto_ldp, tvb, pinfo, tree);
#else
  OLD_CHECK_DISPLAY_AS_DATA(proto_ldp, pd, offset, fd, tree);
#endif

/* Add your dissection code here */

  if (check_col(pinfo->fd, COL_PROTOCOL))

    col_add_str(pinfo->fd, COL_PROTOCOL, "LDP");

  if (tree) {  /* Build the tree info ..., this is wrong! FIXME */

    ti = proto_tree_add_item(tree, proto_ldp, tvb, offset,
			     tvb_length_remaining(tvb, offset), FALSE);
    ldp_tree = proto_item_add_subtree(ti, ett_ldp);

    ti = proto_tree_add_text(ldp_tree, tvb, 0, 10, "Header");

    hdr_tree = proto_item_add_subtree(ti, ett_ldp_header);

    proto_tree_add_item(hdr_tree, hf_ldp_version, tvb, offset, 2, FALSE);

    offset += 2;

    proto_tree_add_item(hdr_tree, hf_ldp_pdu_len, tvb, offset, 2, FALSE);

    offset += 2;

    ti = proto_tree_add_text(hdr_tree, tvb, offset, 6, "LDP Identifier");

    ldpid_tree = proto_item_add_subtree(ti, ett_ldp_ldpid);

    proto_tree_add_item(ldpid_tree, hf_ldp_lsr, tvb, offset, 4, FALSE);

    offset += 4;

    proto_tree_add_item(ldpid_tree, hf_ldp_ls_id, tvb, offset, 2, FALSE);

    offset += 2;

  }

  offset = 10;

  while (tvb_length_remaining(tvb, offset) > 0) { /* Dissect a message */

    ldp_message = tvb_get_ntohs(tvb, offset) & 0x7FFF; /* Get the message type */

    if (check_col(pinfo->fd, COL_INFO)) {  /* Check the type ... */

      if (msg_cnt > 0) 
	col_append_fstr(pinfo->fd, COL_INFO, " %s",
			val_to_str(ldp_message, ldp_message_types, "Unknown Message (0x%04X)"));
      else
	col_add_fstr(pinfo->fd, COL_INFO, "%s", 
		     val_to_str(ldp_message, ldp_message_types, "Unknown Message (0x%04X)"));

    }

    msg_cnt++;

    switch (ldp_message) {

    case LDP_NOTIFICATION:

      offset += dissect_ldp_notification(tvb, offset, pinfo, ldp_tree); 

      break;

    case LDP_HELLO:

      break;

    case LDP_INITIALIZATION:

      break;

    case LDP_KEEPALIVE:

      break;

    case LDP_ADDRESS:

      break;

    case LDP_ADDRESS_WITHDRAWAL:

      break;

    case LDP_LABEL_MAPPING:

      break;

    case LDP_LABEL_REQUEST:

      break;

    case LDP_LABEL_WITHDRAWAL:

      break;

    case LDP_LABEL_RELEASE:

      break;

    case LDP_LABEL_ABORT_REQUEST:

      break;

    default:

      break;

    }
    
    offset += tvb_length_remaining(tvb, offset); /* FIXME: Fake this out */

  }

}

/* Register all the bits needed with the filtering engine */

void 
proto_register_ldp(void)
{
  static hf_register_info hf[] = {
    { &hf_ldp_req,
      /* Change the following to the type you need */
      { "Request", "ldp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_ldp_rsp,
      { "Response", "ldp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "" }},

    { &hf_ldp_version,
      { "Version", "ldp.hdr.version", FT_UINT16, BASE_DEC, NULL, 0x0, "" }},

    { &hf_ldp_pdu_len,
      { "PDU Length", "ldp.hdr.pdu_len", FT_UINT16, BASE_DEC, NULL, 0x0, ""}},

    { &hf_ldp_lsr,
      { "LSR ID", "ldp.hdr.ldpid.lsr", FT_UINT32, BASE_HEX, NULL, 0x0, ""}},

    { &hf_ldp_ls_id,
      { "Label Space ID", "ldp.hdr.ldpid.lsid", FT_UINT16, BASE_HEX, NULL, 0x0, ""}},

    /* Add more fields here */
  };
  static gint *ett[] = {
    &ett_ldp,
    &ett_ldp_header,
    &ett_ldp_ldpid,
  };
  module_t *ldp_module; 

  /* Register our configuration options for , particularly our port */

  ldp_module = prefs_register_module("ldp", "LDP", proto_reg_handoff_ldp);

  prefs_register_uint_preference(ldp_module, "tcp.port", "LDP TCP Port",
				 "Set the port for  messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_tcp_port);

  prefs_register_uint_preference(ldp_module, "udp.port", "LDP UDP Port",
				 "Set the port for  messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_udp_port);

  proto_ldp = proto_register_protocol("Label Distribution Protocol",
				       "ldp");

  proto_register_field_array(proto_ldp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/* The registration hand-off routine */
void
proto_reg_handoff_ldp(void)
{
  static int ldp_prefs_initialized = FALSE;

  if (ldp_prefs_initialized) {

    dissector_delete("tcp.port", tcp_port, dissect_ldp);
    dissector_delete("udp.port", udp_port, dissect_ldp);

  }
  else {

    ldp_prefs_initialized = TRUE;

  }

  /* Set our port number for future use */

  tcp_port = global_ldp_tcp_port;
  udp_port = global_ldp_udp_port;

  dissector_add("tcp.port", global_ldp_tcp_port, dissect_ldp);
  dissector_add("udp.port", global_ldp_udp_port, dissect_ldp);

}


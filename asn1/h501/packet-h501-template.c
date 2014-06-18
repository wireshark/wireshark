/* packet-h501.c
 * Routines for H.501 packet dissection
 * 2007  Tomas Kukosa
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"

#define PNAME  "H.501 Mobility"
#define PSNAME "H.501"
#define PFNAME "h501"

void proto_register_h501(void);

/* Initialize the protocol and registered fields */
static int proto_h501 = -1;
#include "packet-h501-hf.c"

/* Initialize the subtree pointers */
static int ett_h501 = -1;
#include "packet-h501-ett.c"

/* Dissectors */
static dissector_handle_t h501_pdu_handle;

/* Preferences */
static guint h501_udp_port = 2099;
static guint h501_tcp_port = 2099;
static gboolean h501_desegment_tcp = TRUE;

void proto_reg_handoff_h501(void);

#include "packet-h501-fn.c"

static int
dissect_h501_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item  *ti = NULL;
  proto_tree  *h501_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h501, tvb, 0, -1, ENC_NA);
  h501_tree = proto_item_add_subtree(ti, ett_h501);

  return dissect_Message_PDU(tvb, pinfo, h501_tree, NULL);
}

static int
dissect_h501_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  dissect_tpkt_encap(tvb, pinfo, tree, FALSE, h501_pdu_handle);
  return tvb_captured_length(tvb);
}

static int
dissect_h501_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  dissect_tpkt_encap(tvb, pinfo, tree, h501_desegment_tcp, h501_pdu_handle);
  return tvb_captured_length(tvb);
}

/*--- proto_register_h501 ----------------------------------------------*/
void proto_register_h501(void) {
  module_t *h501_module;

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h501-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h501,
#include "packet-h501-ettarr.c"
  };

  /* Register protocol */
  proto_h501 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector(PFNAME, dissect_h501_pdu, proto_h501);

  h501_module = prefs_register_protocol(proto_h501, proto_reg_handoff_h501);
  prefs_register_uint_preference(h501_module, "udp.port",
                                 "UDP port",
                                 "Port to be decoded as h501",
                                 10, &h501_udp_port);
  prefs_register_uint_preference(h501_module, "tcp.port",
                                 "TCP port",
                                 "Port to be decoded as h501",
                                 10, &h501_tcp_port);
  prefs_register_bool_preference(h501_module, "desegment",
                                 "Desegment H.501 over TCP",
                                 "Desegment H.501 messages that span more TCP segments",
                                 &h501_desegment_tcp);

}

/*--- proto_reg_handoff_h501 -------------------------------------------*/
void proto_reg_handoff_h501(void)
{
  static gboolean h501_prefs_initialized = FALSE;
  static dissector_handle_t h501_udp_handle;
  static dissector_handle_t h501_tcp_handle;
  static guint saved_h501_udp_port;
  static guint saved_h501_tcp_port;

  if (!h501_prefs_initialized) {
    h501_pdu_handle = find_dissector(PFNAME);
    h501_udp_handle = new_create_dissector_handle(dissect_h501_udp, proto_h501);
    h501_tcp_handle = new_create_dissector_handle(dissect_h501_tcp, proto_h501);
    h501_prefs_initialized = TRUE;
  } else {
    dissector_delete_uint("udp.port", saved_h501_udp_port, h501_udp_handle);
    dissector_delete_uint("tcp.port", saved_h501_tcp_port, h501_tcp_handle);
  }

  /* Set our port number for future use */
  saved_h501_udp_port = h501_udp_port;
  dissector_add_uint("udp.port", saved_h501_udp_port, h501_udp_handle);
  saved_h501_tcp_port = h501_tcp_port;
  dissector_add_uint("tcp.port", saved_h501_tcp_port, h501_tcp_handle);

}


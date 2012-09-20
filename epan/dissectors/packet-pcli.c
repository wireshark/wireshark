/* packet-pcli.c
 * Routines for Packet Cable Lawful Intercept packet disassembly
 * Packet Cable Lawful Intercept is detailed at
 * http://www.cablelabs.com/specifications/archives/PKT-SP-ESP-I01-991229.pdf
 * Chapter 4 ( Call Content Connection Interface )
 *
 * $Id$
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
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

/* Include files */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

/* Define udp_port for lawful intercept */

#define UDP_PORT_PCLI 9000

void proto_reg_handoff_pcli(void);

/* Define the pcli proto */

static int proto_pcli = -1;

/* Define headers for pcli */

static int hf_pcli_cccid = -1;

/* Define the tree for pcli */

static int ett_pcli = -1;

/*
 * Here are the global variables associated with the preferences
 * for pcli
 */

static guint global_udp_port_pcli = UDP_PORT_PCLI;

/* A static handle for the ip dissector */
static dissector_handle_t ip_handle;

static void
dissect_pcli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

  guint32 cccid;
  proto_tree *ti,*pcli_tree;
  tvbuff_t * next_tvb;

  /* Set the protocol column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCLI");

  /* Get the CCCID */
  cccid = tvb_get_ntohl(tvb,0);

  /* Set the info column */
  if(check_col(pinfo->cinfo,COL_INFO)){
    col_add_fstr(pinfo->cinfo, COL_INFO, "CCCID: %u",cccid);
  }

  /*
   *If we have a non-null tree (ie we are building the proto_tree
   * instead of just filling out the columns ), then add a PLCI
   * tree node and put a CCCID header element under it.
   */
  if(tree) {
    ti = proto_tree_add_item(tree,proto_pcli,tvb,0,0,ENC_NA);
    pcli_tree = proto_item_add_subtree(ti,ett_pcli);
    proto_tree_add_uint(pcli_tree,hf_pcli_cccid,tvb,
			0,4,cccid);
  }

  /*
   * Hand off to the IP dissector.
   */
  next_tvb = tvb_new_subset_remaining(tvb,4);
  call_dissector(ip_handle,next_tvb,pinfo,tree);
}

void
proto_register_pcli(void) {
  static hf_register_info hf[] = {
    { &hf_pcli_cccid,
      { "CCCID", "pcli.cccid", FT_UINT32, BASE_DEC, NULL, 0x0,
	"Call Content Connection Identifier", HFILL }},
  };

  static gint *ett[] = {
    &ett_pcli,
  };

  module_t *pcli_module;

  proto_pcli = proto_register_protocol("Packet Cable Lawful Intercept",
				       "PCLI","pcli");
  proto_register_field_array(proto_pcli,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  pcli_module = prefs_register_protocol(proto_pcli,
					proto_reg_handoff_pcli);
  prefs_register_uint_preference(pcli_module, "udp_port",
				 "PCLI UDP Port",
				 "The UDP port on which "
				 "Packet Cable Lawful Intercept "
				 "packets will be sent",
				 10,&global_udp_port_pcli);

}

/* The registration hand-off routing */

void
proto_reg_handoff_pcli(void) {
  static gboolean pcli_initialized = FALSE;
  static dissector_handle_t pcli_handle;
  static guint udp_port_pcli;

  if(!pcli_initialized) {
    pcli_handle = create_dissector_handle(dissect_pcli,proto_pcli);
    ip_handle = find_dissector("ip");
    pcli_initialized = TRUE;
  } else {
    dissector_delete_uint("udp.port",udp_port_pcli,pcli_handle);
  }

  udp_port_pcli = global_udp_port_pcli;

  dissector_add_uint("udp.port",global_udp_port_pcli,pcli_handle);
}

/* packet-enttec.c
 * Routines for ENTTEC packet disassembly
 *
 * $Id: packet-enttec.c,v 1.1 2003/11/17 20:57:13 guy Exp $
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include <epan/strutil.h>

#include "plugins/plugin_api_defs.h"

/* Define version if we are not building ethereal statically */

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

/*
 * See
 *
 *	http://www.enttec.com/docs/enttec_protocol.pdf
 */

/* Define udp_port for ENTTEC */

#define UDP_PORT_ENTTEC 0x0D05

void proto_reg_handoff_enttec(void);

/* Define the enttec proto */
static int proto_enttec = -1;

/* general */
static int hf_enttec_head = -1;

/* Define the tree for enttec */
static int ett_enttec = -1;

/*
 * Here are the global variables associated with the preferences
 * for enttec
 */

static guint global_udp_port_enttec = UDP_PORT_ENTTEC;
static guint udp_port_enttec = UDP_PORT_ENTTEC;

/* A static handle for the ip dissector */
static dissector_handle_t ip_handle;
static dissector_handle_t rdm_handle;

static void
dissect_enttec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;
  proto_tree *ti,*enttec_tree=NULL;

  /* Set the protocol column */
  if(check_col(pinfo->cinfo,COL_PROTOCOL)){
    col_set_str(pinfo->cinfo,COL_PROTOCOL,"ENTTEC");
  }

  /* Clear out stuff in the info column */
  if(check_col(pinfo->cinfo,COL_INFO)){
    col_clear(pinfo->cinfo,COL_INFO);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_enttec, tvb, offset, -1, FALSE);
    enttec_tree = proto_item_add_subtree(ti, ett_enttec);
  }


  if( enttec_tree ) {
    proto_tree_add_item(enttec_tree, hf_enttec_head, tvb,
                        offset, 4, FALSE );
    offset += 4;
  }
}

void
proto_register_enttec(void) {
  static hf_register_info hf[] = {

    /* General */

    { &hf_enttec_head,
      { "Head",
        "enttec.head",
        FT_STRING, BASE_HEX, NULL, 0x0,
        "Head", HFILL }}
  };

  static gint *ett[] = {
    &ett_enttec,
  };

  module_t *enttec_module;

  proto_enttec = proto_register_protocol("ENTTEC",
				       "ENTTEC","enttec");
  proto_register_field_array(proto_enttec,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  enttec_module = prefs_register_protocol(proto_enttec,
					proto_reg_handoff_enttec);
  prefs_register_uint_preference(enttec_module, "udp_port",
				 "ENTTEC UDP Port",
				 "The UDP port on which "
				 "ENTTEC "
				 "packets will be sent",
				 10,&global_udp_port_enttec);

}

/* The registration hand-off routing */

void
proto_reg_handoff_enttec(void) {
  static int enttec_initialized = FALSE;
  static dissector_handle_t enttec_handle;

  ip_handle = find_dissector("ip");
  rdm_handle = find_dissector("rdm");


  if(!enttec_initialized) {
    enttec_handle = create_dissector_handle(dissect_enttec,proto_enttec);
    enttec_initialized = TRUE;
  } else {
    dissector_delete("udp.port",udp_port_enttec,enttec_handle);
  }

  udp_port_enttec = global_udp_port_enttec;
  
  dissector_add("udp.port",global_udp_port_enttec,enttec_handle);
}

/* Start the functions we need for the plugin stuff */

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_enttec();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat
#ifndef PLUGINS_NEED_ADDRESS_TABLE
_U_
#endif
){
  /* initialise the table of pointers needed in Win32 DLLs */
  plugin_address_table_init(pat);
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_enttec == -1) { /* execute protocol initialization only once */
    proto_register_enttec();
  }
}

#endif

/* End the functions we need for plugin stuff */


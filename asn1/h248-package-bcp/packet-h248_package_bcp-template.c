/* packet-h248_package_bcp.c
 * Routines for H.248/MEGACO-Package_bcp packet dissection
 * Ronnie Sahlberg 2004
 *
 * $Id: packet-h248_package_bcp-template.c 12205 2004-10-05 09:50:19Z sahlberg $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-h248_package_bcp.h"

#define PNAME  "H.248 MEGACO/BCP"
#define PSNAME "H248BCP"
#define PFNAME "h248bcp"

/* Initialize the protocol and registered fields */
static int proto_h248_package_bcp = -1;
#include "packet-h248_package_bcp-hf.c"

/* Initialize the subtree pointers */
static gint ett_h248_package_bcp = -1;
/*#include "packet-h248_package_bcp-ett.c"*/


#include "packet-h248_package_bcp-fn.c"


/*--- proto_register_h248_package_bcp ----------------------------------------------*/
void proto_register_h248_package_bcp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h248_package_bcp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h248_package_bcp,
    /*#include "packet-h248_package_bcp-ettarr.c"*/
  };

  /* Register protocol */
  proto_h248_package_bcp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h248_package_bcp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_h248_package_bcp -------------------------------------------*/
void proto_reg_handoff_h248_package_bcp(void) {
  dissector_handle_t h248_package_bcp_handle;


  h248_package_bcp_handle = create_dissector_handle(dissect_BNCChar_PDU, proto_h248_package_bcp);
  dissector_add("h248.package.bin", 0x001e0001, h248_package_bcp_handle);
}


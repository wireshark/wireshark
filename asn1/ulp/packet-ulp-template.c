/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 *
 * ref OMA-TS-ULP-V1_0-20060127-C
 * http://www.openmobilealliance.org
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include "packet-ulp.h"

#include "packet-ber.h"
#include "packet-per.h"

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

static dissector_handle_t ulp_handle=NULL;

/* IANA Registered Ports  
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
guint gbl_ulp_port = 7275;

/* Initialize the protocol and registered fields */
static int proto_ulp = -1;


#include "packet-ulp-hf.c"

/* Initialize the subtree pointers */
static gint ett_ulp = -1;
#include "packet-ulp-ett.c"

/* Include constants */
#include "packet-ulp-val.h"

#include "packet-ulp-fn.c"

/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{

	ulp_handle = create_dissector_handle(dissect_ULP_PDU_PDU, proto_ulp);

	dissector_add("tcp.port", gbl_ulp_port, ulp_handle);

	/* application/oma-supl-ulp */
	dissector_add_string("media_type","application/oma-supl-ulp", ulp_handle);

}


/*--- proto_register_ulp -------------------------------------------*/
void proto_register_ulp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-ulp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ulp,
#include "packet-ulp-ettarr.c"
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register a configuration option for port */
  ulp_module = prefs_register_protocol(proto_ulp,proto_reg_handoff_ulp);
  prefs_register_uint_preference(ulp_module, "tcp.port",
								   "ULP TCP Port",
								   "Set the TCP port for Ulp messages(IANA registerd port is 7275)",
								   10,
								   &gbl_ulp_port);
 
}





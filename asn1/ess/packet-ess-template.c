/* packet-ess.c
 * Routines for RFC2634 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-ess.h"
#include "packet-cms.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"

#define PNAME  "Extended Security Services"
#define PSNAME "ESS"
#define PFNAME "ess"

/* Initialize the protocol and registered fields */
static int proto_ess = -1;
static int hf_ess_SecurityCategory_type_OID = -1;
#include "packet-ess-hf.c"

/* Initialize the subtree pointers */
#include "packet-ess-ett.c"

static const char *object_identifier_id;

#include "packet-ess-fn.c"


/*--- proto_register_ess ----------------------------------------------*/
void proto_register_ess(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ess_SecurityCategory_type_OID, 
      { "type", "ess.type_OID", FT_STRING, BASE_NONE, NULL, 0,
	"Type of Security Category", HFILL }},
#include "packet-ess-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-ess-ettarr.c"
  };

  /* Register protocol */
  proto_ess = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ess, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ess -------------------------------------------*/
void proto_reg_handoff_ess(void) {
#include "packet-ess-dis-tab.c"
}


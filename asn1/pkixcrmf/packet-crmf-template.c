/* packet-crmf.c
 * Routines for RFC2511 Certificate Request Message Format packet dissection
 *   Ronnie Sahlberg 2004
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-crmf.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "Certificate Request Message Format"
#define PSNAME "CRMF"
#define PFNAME "crmf"

/* Initialize the protocol and registered fields */
int proto_crmf = -1;
static int hf_crmf_type_oid = -1;
#include "packet-crmf-hf.c"

/* Initialize the subtree pointers */
#include "packet-crmf-ett.c"

static const char *object_identifier_id;

#include "packet-crmf-fn.c"


/*--- proto_register_crmf ----------------------------------------------*/
void proto_register_crmf(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_crmf_type_oid,
      { "Type", "crmf.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of AttributeTypeAndValue", HFILL }},
#include "packet-crmf-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-crmf-ettarr.c"
  };

  /* Register protocol */
  proto_crmf = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_crmf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_crmf -------------------------------------------*/
void proto_reg_handoff_crmf(void) {
#include "packet-crmf-dis-tab.c"
}


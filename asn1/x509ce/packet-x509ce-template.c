/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-x411.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
static int hf_x509ce_object_identifier_id = -1;
static int hf_x509ce_IPAddress = -1;
#include "packet-x509ce-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509ce-ett.c"

static const char *object_identifier_id;

#include "packet-x509ce-fn.c"


static void
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_invalidityDate);
}

static void
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "baseUpdateTime", HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "invalidityDate", HFILL }},
    { &hf_x509ce_object_identifier_id, 
      { "Id", "x509ce.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509ce_IPAddress,
      { "iPAddress", "x509ce.IPAddress", FT_IPv4, BASE_NONE, NULL, 0,
        "IP Address", HFILL }},

#include "packet-x509ce-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-x509ce-ettarr.c"
  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
#include "packet-x509ce-dis-tab.c"
	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
}


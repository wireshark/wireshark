/* packet-x509af.c
 * Routines for X.509 Authentication Framework packet dissection
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
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#define PNAME  "X.509 Authentication Framework"
#define PSNAME "X509AF"
#define PFNAME "x509af"

/* Initialize the protocol and registered fields */
static int proto_x509af = -1;
static int hf_x509af_algorithm_id = -1;
static int hf_x509af_extension_id = -1;
#include "packet-x509af-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509af-ett.c"

static char algorithm_id[64]; /*64 chars should be long enough? */


static char extension_id[64]; /*64 chars should be long enough? */


#include "packet-x509af-fn.c"


/*--- proto_register_x509af ----------------------------------------------*/
void proto_register_x509af(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509af_algorithm_id,
      { "Algorithm Id", "x509af.algorithm.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Algorithm Id", HFILL }},
    { &hf_x509af_extension_id,
      { "Extension Id", "x509af.extension.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Extension Id", HFILL }},
#include "packet-x509af-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-x509af-ettarr.c"
  };

  /* Register protocol */
  proto_x509af = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509af, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509af -------------------------------------------*/
void proto_reg_handoff_x509af(void) {
#include "packet-x509af-dis-tab.c"

	/*XXX these should really go to a better place but since that
	  I have not that ITU standard, ill put it here for the time
	  being.
	  Only implemented those algorithms that take no parameters 
	  for the time being,   ronnie
	*/
	/* from http://www.alvestrand.no/objectid/1.3.14.3.2.html */
	register_ber_oid_dissector("1.3.14.3.2.2", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.3", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.4", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSAEncryption");
	register_ber_oid_dissector("1.3.14.3.2.6", dissect_ber_oid_NULL_callback, proto_x509af, "desECB");
	register_ber_oid_dissector("1.3.14.3.2.11", dissect_ber_oid_NULL_callback, proto_x509af, "rsaSignature");
	register_ber_oid_dissector("1.3.14.3.2.14", dissect_ber_oid_NULL_callback, proto_x509af, "mdc2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.15", dissect_ber_oid_NULL_callback, proto_x509af, "shaWithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.16", dissect_ber_oid_NULL_callback, proto_x509af, "dhWithCommonModulus");
	register_ber_oid_dissector("1.3.14.3.2.17", dissect_ber_oid_NULL_callback, proto_x509af, "desEDE");
	register_ber_oid_dissector("1.3.14.3.2.18", dissect_ber_oid_NULL_callback, proto_x509af, "sha");
	register_ber_oid_dissector("1.3.14.3.2.19", dissect_ber_oid_NULL_callback, proto_x509af, "mdc-2");
	register_ber_oid_dissector("1.3.14.3.2.20", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommon");
	register_ber_oid_dissector("1.3.14.3.2.21", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommonWithSHA");
	register_ber_oid_dissector("1.3.14.3.2.22", dissect_ber_oid_NULL_callback, proto_x509af, "rsaKeyTransport");
	register_ber_oid_dissector("1.3.14.3.2.23", dissect_ber_oid_NULL_callback, proto_x509af, "keyed-hash-seal");
	register_ber_oid_dissector("1.3.14.3.2.24", dissect_ber_oid_NULL_callback, proto_x509af, "md2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.25", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.26", dissect_ber_oid_NULL_callback, proto_x509af, "SHA-1");
}


/* packet-pkcs1.c
 * Routines for PKCS#1/RFC2313 packet dissection
 *  Ronnie Sahlberg 2004
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

#include "packet-pkcs1.h"
#include "packet-ber.h"
#include "packet-x509af.h"

#define PNAME  "PKCS#1"
#define PSNAME "PKCS-1"
#define PFNAME "pkcs-1"

/* Initialize the protocol and registered fields */
static int proto_pkcs1 = -1;
#include "packet-pkcs1-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkcs1-ett.c"

#include "packet-pkcs1-fn.c"

/*--- proto_register_pkcs1 ----------------------------------------------*/
void proto_register_pkcs1(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkcs1-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkcs1-ettarr.c"
  };

  /* Register protocol */
  proto_pkcs1 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkcs1 -------------------------------------------*/
void proto_reg_handoff_pkcs1(void) {
	register_ber_oid_dissector("1.2.840.113549.2.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "md2");
	register_ber_oid_dissector("1.2.840.113549.2.4", dissect_ber_oid_NULL_callback, proto_pkcs1, "md4");
	register_ber_oid_dissector("1.2.840.113549.2.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "md5");

	register_ber_oid_dissector("1.2.840.113549.1.1.1", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "md2WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.3", dissect_ber_oid_NULL_callback, proto_pkcs1, "md4WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.4", dissect_ber_oid_NULL_callback, proto_pkcs1, "md5WithRSAEncryption");


	/* these two are not from RFC2313  but pulled in from
 	   http://www.alvestrand.no/objectid/1.2.840.113549.1.1.html
	*/
	register_ber_oid_dissector("1.2.840.113549.1.1.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "shaWithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.6", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaOAEPEncryptionSET");
}


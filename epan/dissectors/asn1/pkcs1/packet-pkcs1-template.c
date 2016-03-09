/* packet-pkcs1.c
 * Routines for PKCS#1/RFC2313 packet dissection
 *  Ronnie Sahlberg 2004
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

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkcs1.h"
#include "packet-x509af.h"

#define PNAME  "PKCS#1"
#define PSNAME "PKCS-1"
#define PFNAME "pkcs-1"

void proto_register_pkcs1(void);
void proto_reg_handoff_pkcs1(void);

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
#include "packet-pkcs1-dis-tab.c"

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
	register_ber_oid_dissector("1.2.840.113549.1.1.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha1WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.6", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaOAEPEncryptionSET");

	/* these sha2 algorithms are from RFC3447 */
	register_ber_oid_dissector("1.2.840.113549.1.1.11", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha256WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.12", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha384WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.13", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha512WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.14", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha224WithRSAEncryption");

	oid_add_from_string("secp192r1","1.2.840.10045.3.1.1");
	oid_add_from_string("sect163k1","1.3.132.0.1");
	oid_add_from_string("sect163r2","1.3.132.0.15");
	oid_add_from_string("secp224r1","1.3.132.0.33");
	oid_add_from_string("sect233k1","1.3.132.0.26");
	oid_add_from_string("sect233r1","1.3.132.0.27");
	oid_add_from_string("secp256r1","1.2.840.10045.3.1.7");
	oid_add_from_string("sect283k1","1.3.132.0.16");
	oid_add_from_string("sect283r1","1.3.132.0.17");
	oid_add_from_string("secp384r1","1.3.132.0.34");
	oid_add_from_string("sect409k1","1.3.132.0.36");
	oid_add_from_string("sect409r1","1.3.132.0.37");
	oid_add_from_string("secp521r1","1.3.132.0.35");
	oid_add_from_string("sect571k1","1.3.132.0.38");
	oid_add_from_string("sect571r1","1.3.132.0.39");

	/* sha2 family, see RFC3447 and http://www.oid-info.com/get/2.16.840.1.101.3.4.2 */
	oid_add_from_string("sha256", "2.16.840.1.101.3.4.2.1");
	oid_add_from_string("sha384", "2.16.840.1.101.3.4.2.2");
	oid_add_from_string("sha512", "2.16.840.1.101.3.4.2.3");
	oid_add_from_string("sha224", "2.16.840.1.101.3.4.2.4");

}


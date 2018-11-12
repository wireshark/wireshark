/* packet-p10.c
 *
 * Routines for PKCS10 packet dissection
 *   Martin Peylo <wireshark@izac.de> 2018
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
#include "packet-pkcs10.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include <epan/prefs.h>

#define PNAME  "PKCS10 Certification Request"
#define PSNAME "PKCS10"
#define PFNAME "pkcs10"

void proto_register_pkcs10(void);

/* Initialize the protocol and registered fields */
static int proto_pkcs10 = -1;
#include "packet-pkcs10-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkcs10-ett.c"
#include "packet-pkcs10-fn.c"

/*--- proto_register_pkcs10 ----------------------------------------------*/
void proto_register_pkcs10(void) {

	/* List of fields */
	static hf_register_info hf[] = {
#include "packet-pkcs10-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
#include "packet-pkcs10-ettarr.c"
	};
	/* Register protocol */
	proto_pkcs10 = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_pkcs10, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("CertificationRequest", proto_pkcs10, dissect_CertificationRequest_PDU);
  register_ber_oid_syntax(".p10", NULL, "CertificationRequest");
  register_ber_oid_syntax(".csr", NULL, "CertificationRequest");
}


/*--- proto_reg_handoff_pkcs10 -------------------------------------------*/
void proto_reg_handoff_pkcs10(void) {
  dissector_handle_t csr_handle;

#include "packet-pkcs10-dis-tab.c"

  csr_handle = create_dissector_handle(dissect_CertificationRequest_PDU, proto_pkcs10);
  dissector_add_string("media_type", "application/pkcs10", csr_handle); /* RFC 5967 */
  dissector_add_string("rfc7468.preeb_label", "CERTIFICATE REQUEST", csr_handle); /* RFC 7468 */
  dissector_add_string("rfc7468.preeb_label", "NEW CERTIFICATE REQUEST", csr_handle); /* RFC 7468 Appendix A. Non-conforming expample*/
}

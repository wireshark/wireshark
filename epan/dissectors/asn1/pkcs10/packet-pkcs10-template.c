/* packet-p10.c
 *
 * Routines for PKCS10 packet dissection
 *   Martin Peylo <wireshark@izac.de> 2018
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/array.h>

#include <epan/oids.h>
#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-pkcs10.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include <epan/prefs.h>

void proto_reg_handoff_pkcs10(void);
void proto_register_pkcs10(void);

static dissector_handle_t csr_handle;

/* Initialize the protocol and registered fields */
static int proto_pkcs10;
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
	static int *ett[] = {
#include "packet-pkcs10-ettarr.c"
	};
	/* Register protocol */
	proto_pkcs10 = proto_register_protocol("PKCS10 Certification Request", "PKCS10", "pkcs10");

	/* Register fields and subtrees */
	proto_register_field_array(proto_pkcs10, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

  csr_handle = register_dissector("pkcs10", dissect_CertificationRequest_PDU, proto_pkcs10);
  register_ber_syntax_dissector("CertificationRequest", proto_pkcs10, dissect_CertificationRequest_PDU);
  register_ber_oid_syntax(".p10", NULL, "CertificationRequest");
  register_ber_oid_syntax(".csr", NULL, "CertificationRequest");
}


/*--- proto_reg_handoff_pkcs10 -------------------------------------------*/
void proto_reg_handoff_pkcs10(void) {

#include "packet-pkcs10-dis-tab.c"

  dissector_add_string("media_type", "application/pkcs10", csr_handle); /* RFC 5967 */
  dissector_add_string("rfc7468.preeb_label", "CERTIFICATE REQUEST", csr_handle); /* RFC 7468 */
  dissector_add_string("rfc7468.preeb_label", "NEW CERTIFICATE REQUEST", csr_handle); /* RFC 7468 Appendix A. Non-conforming example*/
}

/* packet-ns_cert_exts.c
 * Routines for NetScape Certificate Extensions packet dissection
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

#define PNAME  "NetScape Certificate Extensions"
#define PSNAME "NS_CERT_EXTS"
#define PFNAME "ns_cert_exts"

/* Initialize the protocol and registered fields */
int proto_ns_cert_exts = -1;
#include "packet-ns_cert_exts-hf.c"

/* Initialize the subtree pointers */
#include "packet-ns_cert_exts-ett.c"

#include "packet-ns_cert_exts-fn.c"


/*--- proto_register_ns_cert_exts -------------------------------------------*/
void proto_register_ns_cert_exts(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-ns_cert_exts-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-ns_cert_exts-ettarr.c"
  };

  /* Register protocol */
  proto_ns_cert_exts = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ns_cert_exts, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ns_cert_exts ---------------------------------------*/
void proto_reg_handoff_ns_cert_exts(void) {
	register_ber_oid_dissector("2.16.840.1.113730.1.1", dissect_CertType_PDU, proto_ns_cert_exts, "ns-cert-exts.cert_type");
	register_ber_oid_dissector("2.16.840.1.113730.1.2", dissect_BaseUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.base_url");
	register_ber_oid_dissector("2.16.840.1.113730.1.3", dissect_RevocationUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.revocation-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.4", dissect_CaRevocationUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.ca-revocation-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.7", dissect_CertRenewalUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.cert-renewal-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.8", dissect_CaPolicyUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.ca-policy-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.12", dissect_SslServerName_PDU, proto_ns_cert_exts, "ns-cert-exts.ssl-server-name");
	register_ber_oid_dissector("2.16.840.1.113730.1.13", dissect_Comment_PDU, proto_ns_cert_exts, "ns-cert-exts.comment");
}


/* packet-ns_cert_exts.c
 * Routines for NetScape Certificate Extensions packet dissection
 *
 * $Id: packet-ns_cert_exts-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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
static int hf_ns_cert_exts_comment = -1;
static int hf_ns_cert_exts_ssl_server_name = -1;
static int hf_ns_cert_exts_ca_policy_url = -1;
static int hf_ns_cert_exts_cert_renewal_url = -1;
static int hf_ns_cert_exts_ca_revocation_url = -1;
static int hf_ns_cert_exts_revocation_url = -1;
static int hf_ns_cert_exts_base_url = -1;
static int hf_ns_cert_exts_cert_type = -1;
#include "packet-ns_cert_exts-hf.c"

/* Initialize the subtree pointers */
#include "packet-ns_cert_exts-ett.c"

#include "packet-ns_cert_exts-fn.c"


static void
dissect_ns_cert_exts_cert_type_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_CertType(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_cert_type);
}

static void
dissect_ns_cert_exts_base_url_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_BaseUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_base_url);
}

static void
dissect_ns_cert_exts_revocation_url_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_RevocationUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_revocation_url);
}

static void
dissect_ns_cert_exts_ca_revocation_url_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_CaRevocationUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_ca_revocation_url);
}

static void
dissect_ns_cert_exts_cert_renewal_url_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_CertRenewalUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_cert_renewal_url);
}

static void
dissect_ns_cert_exts_ca_policy_url_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_CaPolicyUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_ca_policy_url);
}

static void
dissect_ns_cert_exts_ssl_server_name_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_SslServerName(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_ssl_server_name);
}

static void
dissect_ns_cert_exts_comment_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ns_cert_exts_Comment(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_comment);
}
/*--- proto_register_ns_cert_exts -------------------------------------------*/
void proto_register_ns_cert_exts(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	  { &hf_ns_cert_exts_cert_type,
		  { "Cert Type", "ns_cert_exts.cert-type",
		    FT_BYTES, BASE_HEX, NULL, 0,
		    "Cert Type", HFILL }},
	  { &hf_ns_cert_exts_base_url,
		  { "Base URL", "ns_cert_exts.base-url",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "Base URL", HFILL }},
	  { &hf_ns_cert_exts_revocation_url,
		  { "Revocation URL", "ns_cert_exts.revocation-url",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "Revocation URL", HFILL }},
	  { &hf_ns_cert_exts_ca_revocation_url,
		  { "CA Revocation URL", "ns_cert_exts.ca-revocation-url",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "CA Revocation URL", HFILL }},
	  { &hf_ns_cert_exts_cert_renewal_url,
		  { "Cert Renewal URL", "ns_cert_exts.cert-renewal-url",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "Cert Renewal URL", HFILL }},
	  { &hf_ns_cert_exts_ca_policy_url,
		  { "CA Policy URL", "ns_cert_exts.ca-policy-url",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "CA Policy URL", HFILL }},
	  { &hf_ns_cert_exts_ssl_server_name,
		  { "SSL Server name", "ns_cert_exts.ssl-server-name",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "SSL server Name", HFILL }},
	  { &hf_ns_cert_exts_comment,
		  { "Comment", "ns_cert_exts.comment",
		    FT_STRING, BASE_NONE, NULL, 0,
		    "Comment", HFILL }},
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
	register_ber_oid_dissector("2.16.840.1.113730.1.1", dissect_ns_cert_exts_cert_type_callback, proto_ns_cert_exts, "ns-cert-exts.cert_type");
	register_ber_oid_dissector("2.16.840.1.113730.1.2", dissect_ns_cert_exts_base_url_callback, proto_ns_cert_exts, "ns-cert-exts.base_url");
	register_ber_oid_dissector("2.16.840.1.113730.1.3", dissect_ns_cert_exts_revocation_url_callback, proto_ns_cert_exts, "ns-cert-exts.revocation-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.4", dissect_ns_cert_exts_ca_revocation_url_callback, proto_ns_cert_exts, "ns-cert-exts.ca-revocation-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.7", dissect_ns_cert_exts_cert_renewal_url_callback, proto_ns_cert_exts, "ns-cert-exts.cert-renewal-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.8", dissect_ns_cert_exts_ca_policy_url_callback, proto_ns_cert_exts, "ns-cert-exts.ca-policy-url");
	register_ber_oid_dissector("2.16.840.1.113730.1.12", dissect_ns_cert_exts_ssl_server_name_callback, proto_ns_cert_exts, "ns-cert-exts.ssl-server-name");
	register_ber_oid_dissector("2.16.840.1.113730.1.13", dissect_ns_cert_exts_comment_callback, proto_ns_cert_exts, "ns-cert-exts.comment");
}


/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts.c                                                      */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

/* Input file: packet-ns_cert_exts-template.c */
/* Include files: packet-ns_cert_exts-hf.c, packet-ns_cert_exts-ett.c, packet-ns_cert_exts-fn.c, packet-ns_cert_exts-hfarr.c, packet-ns_cert_exts-ettarr.c, packet-ns_cert_exts-val.h */

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

/*--- Included file: packet-ns_cert_exts-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts-hf.c                                                   */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

/* named bits */
static int hf_ns_cert_exts_CertType_client = -1;
static int hf_ns_cert_exts_CertType_server = -1;
static int hf_ns_cert_exts_CertType_ca = -1;

/*--- End of included file: packet-ns_cert_exts-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-ns_cert_exts-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts-ett.c                                                  */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

static gint ett_ns_cert_exts_CertType = -1;

/*--- End of included file: packet-ns_cert_exts-ett.c ---*/



/*--- Included file: packet-ns_cert_exts-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts-fn.c                                                   */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

/*--- Fields for imported types ---*/



static int
dissect_ns_cert_exts_BaseUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_RevocationUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_CaRevocationUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_CaPolicyUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_Comment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_SslServerName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_ns_cert_exts_CertRenewalUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}

static asn_namedbit CertType_bits[] = {
  {  0, &hf_ns_cert_exts_CertType_client, -1, -1, NULL, NULL },
  {  1, &hf_ns_cert_exts_CertType_server, -1, -1, NULL, NULL },
  {  5, &hf_ns_cert_exts_CertType_ca, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_ns_cert_exts_CertType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 CertType_bits, hf_index, ett_ns_cert_exts_CertType,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-ns_cert_exts-fn.c ---*/



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

/*--- Included file: packet-ns_cert_exts-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts-hfarr.c                                                */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

    { &hf_ns_cert_exts_CertType_client,
      { "client", "ns_cert_exts.client",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_ns_cert_exts_CertType_server,
      { "server", "ns_cert_exts.server",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_ns_cert_exts_CertType_ca,
      { "ca", "ns_cert_exts.ca",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},

/*--- End of included file: packet-ns_cert_exts-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-ns_cert_exts-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-ns_cert_exts-ettarr.c                                               */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

    &ett_ns_cert_exts_CertType,

/*--- End of included file: packet-ns_cert_exts-ettarr.c ---*/

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


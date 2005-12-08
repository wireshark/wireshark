/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-ns_cert_exts.c                                                    */
/* ../../tools/asn2eth.py -X -b -e -p ns_cert_exts -c ns_cert_exts.cnf -s packet-ns_cert_exts-template NETSCAPE-CERT-EXTS.asn */

/* Input file: packet-ns_cert_exts-template.c */

#line 1 "packet-ns_cert_exts-template.c"
/* packet-ns_cert_exts.c
 * Routines for NetScape Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
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

/*--- Included file: packet-ns_cert_exts-hf.c ---*/
#line 1 "packet-ns_cert_exts-hf.c"
static int hf_ns_cert_exts_BaseUrl_PDU = -1;      /* BaseUrl */
static int hf_ns_cert_exts_RevocationUrl_PDU = -1;  /* RevocationUrl */
static int hf_ns_cert_exts_CaRevocationUrl_PDU = -1;  /* CaRevocationUrl */
static int hf_ns_cert_exts_CaPolicyUrl_PDU = -1;  /* CaPolicyUrl */
static int hf_ns_cert_exts_Comment_PDU = -1;      /* Comment */
static int hf_ns_cert_exts_SslServerName_PDU = -1;  /* SslServerName */
static int hf_ns_cert_exts_CertRenewalUrl_PDU = -1;  /* CertRenewalUrl */
static int hf_ns_cert_exts_CertType_PDU = -1;     /* CertType */
/* named bits */
static int hf_ns_cert_exts_CertType_client = -1;
static int hf_ns_cert_exts_CertType_server = -1;
static int hf_ns_cert_exts_CertType_ca = -1;

/*--- End of included file: packet-ns_cert_exts-hf.c ---*/
#line 46 "packet-ns_cert_exts-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-ns_cert_exts-ett.c ---*/
#line 1 "packet-ns_cert_exts-ett.c"
static gint ett_ns_cert_exts_CertType = -1;

/*--- End of included file: packet-ns_cert_exts-ett.c ---*/
#line 49 "packet-ns_cert_exts-template.c"


/*--- Included file: packet-ns_cert_exts-fn.c ---*/
#line 1 "packet-ns_cert_exts-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_ns_cert_exts_BaseUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_RevocationUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CaRevocationUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CaPolicyUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_Comment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_SslServerName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CertRenewalUrl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const asn_namedbit CertType_bits[] = {
  {  0, &hf_ns_cert_exts_CertType_client, -1, -1, "client", NULL },
  {  1, &hf_ns_cert_exts_CertType_server, -1, -1, "server", NULL },
  {  5, &hf_ns_cert_exts_CertType_ca, -1, -1, "ca", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_ns_cert_exts_CertType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    CertType_bits, hf_index, ett_ns_cert_exts_CertType,
                                    NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_BaseUrl_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_BaseUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_BaseUrl_PDU);
}
static void dissect_RevocationUrl_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_RevocationUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_RevocationUrl_PDU);
}
static void dissect_CaRevocationUrl_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_CaRevocationUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_CaRevocationUrl_PDU);
}
static void dissect_CaPolicyUrl_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_CaPolicyUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_CaPolicyUrl_PDU);
}
static void dissect_Comment_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_Comment(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_Comment_PDU);
}
static void dissect_SslServerName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_SslServerName(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_SslServerName_PDU);
}
static void dissect_CertRenewalUrl_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_CertRenewalUrl(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_CertRenewalUrl_PDU);
}
static void dissect_CertType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ns_cert_exts_CertType(FALSE, tvb, 0, pinfo, tree, hf_ns_cert_exts_CertType_PDU);
}


/*--- End of included file: packet-ns_cert_exts-fn.c ---*/
#line 51 "packet-ns_cert_exts-template.c"


/*--- proto_register_ns_cert_exts -------------------------------------------*/
void proto_register_ns_cert_exts(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-ns_cert_exts-hfarr.c ---*/
#line 1 "packet-ns_cert_exts-hfarr.c"
    { &hf_ns_cert_exts_BaseUrl_PDU,
      { "BaseUrl", "ns_cert_exts.BaseUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "BaseUrl", HFILL }},
    { &hf_ns_cert_exts_RevocationUrl_PDU,
      { "RevocationUrl", "ns_cert_exts.RevocationUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "RevocationUrl", HFILL }},
    { &hf_ns_cert_exts_CaRevocationUrl_PDU,
      { "CaRevocationUrl", "ns_cert_exts.CaRevocationUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "CaRevocationUrl", HFILL }},
    { &hf_ns_cert_exts_CaPolicyUrl_PDU,
      { "CaPolicyUrl", "ns_cert_exts.CaPolicyUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "CaPolicyUrl", HFILL }},
    { &hf_ns_cert_exts_Comment_PDU,
      { "Comment", "ns_cert_exts.Comment",
        FT_STRING, BASE_NONE, NULL, 0,
        "Comment", HFILL }},
    { &hf_ns_cert_exts_SslServerName_PDU,
      { "SslServerName", "ns_cert_exts.SslServerName",
        FT_STRING, BASE_NONE, NULL, 0,
        "SslServerName", HFILL }},
    { &hf_ns_cert_exts_CertRenewalUrl_PDU,
      { "CertRenewalUrl", "ns_cert_exts.CertRenewalUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "CertRenewalUrl", HFILL }},
    { &hf_ns_cert_exts_CertType_PDU,
      { "CertType", "ns_cert_exts.CertType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertType", HFILL }},
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
#line 59 "packet-ns_cert_exts-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-ns_cert_exts-ettarr.c ---*/
#line 1 "packet-ns_cert_exts-ettarr.c"
    &ett_ns_cert_exts_CertType,

/*--- End of included file: packet-ns_cert_exts-ettarr.c ---*/
#line 64 "packet-ns_cert_exts-template.c"
  };

  /* Register protocol */
  proto_ns_cert_exts = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ns_cert_exts, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ns_cert_exts ---------------------------------------*/
void proto_reg_handoff_ns_cert_exts(void) {

/*--- Included file: packet-ns_cert_exts-dis-tab.c ---*/
#line 1 "packet-ns_cert_exts-dis-tab.c"
  register_ber_oid_dissector("2.16.840.1.113730.1.1", dissect_CertType_PDU, proto_ns_cert_exts, "ns-cert-exts.cert_type");
  register_ber_oid_dissector("2.16.840.1.113730.1.2", dissect_BaseUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.base_url");
  register_ber_oid_dissector("2.16.840.1.113730.1.3", dissect_RevocationUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.revocation-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.4", dissect_CaRevocationUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.ca-revocation-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.7", dissect_CertRenewalUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.cert-renewal-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.8", dissect_CaPolicyUrl_PDU, proto_ns_cert_exts, "ns-cert-exts.ca-policy-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.12", dissect_SslServerName_PDU, proto_ns_cert_exts, "ns-cert-exts.ssl-server-name");
  register_ber_oid_dissector("2.16.840.1.113730.1.13", dissect_Comment_PDU, proto_ns_cert_exts, "ns-cert-exts.comment");


/*--- End of included file: packet-ns_cert_exts-dis-tab.c ---*/
#line 79 "packet-ns_cert_exts-template.c"
}


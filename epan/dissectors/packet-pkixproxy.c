/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkixproxy.c                                                         */
/* ../../tools/asn2wrs.py -b -p pkixproxy -c ./pkixproxy.cnf -s ./packet-pkixproxy-template -D . -O ../../epan/dissectors PKIXProxy.asn */

/* Input file: packet-pkixproxy-template.c */

#line 1 "../../asn1/pkixproxy/packet-pkixproxy-template.c"
/* packet-pkixproxy.c
 * Routines for RFC3820 PKIXProxy packet dissection
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkixproxy.h"

#define PNAME  "PKIXProxy (RFC3820)"
#define PSNAME "PKIXPROXY"
#define PFNAME "pkixproxy"

void proto_register_pkixproxy(void);
void proto_reg_handoff_pkixproxy(void);

/* Initialize the protocol and registered fields */
static int proto_pkixproxy = -1;

/*--- Included file: packet-pkixproxy-hf.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-hf.c"
static int hf_pkixproxy_ProxyCertInfoExtension_PDU = -1;  /* ProxyCertInfoExtension */
static int hf_pkixproxy_pCPathLenConstraint = -1;  /* ProxyCertPathLengthConstraint */
static int hf_pkixproxy_proxyPolicy = -1;         /* ProxyPolicy */
static int hf_pkixproxy_policyLanguage = -1;      /* OBJECT_IDENTIFIER */
static int hf_pkixproxy_policy = -1;              /* OCTET_STRING */

/*--- End of included file: packet-pkixproxy-hf.c ---*/
#line 44 "../../asn1/pkixproxy/packet-pkixproxy-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkixproxy-ett.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-ett.c"
static gint ett_pkixproxy_ProxyCertInfoExtension = -1;
static gint ett_pkixproxy_ProxyPolicy = -1;

/*--- End of included file: packet-pkixproxy-ett.c ---*/
#line 47 "../../asn1/pkixproxy/packet-pkixproxy-template.c"


/*--- Included file: packet-pkixproxy-fn.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-fn.c"


static int
dissect_pkixproxy_ProxyCertPathLengthConstraint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkixproxy_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_pkixproxy_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ProxyPolicy_sequence[] = {
  { &hf_pkixproxy_policyLanguage, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixproxy_OBJECT_IDENTIFIER },
  { &hf_pkixproxy_policy    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixproxy_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixproxy_ProxyPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProxyPolicy_sequence, hf_index, ett_pkixproxy_ProxyPolicy);

  return offset;
}


static const ber_sequence_t ProxyCertInfoExtension_sequence[] = {
  { &hf_pkixproxy_pCPathLenConstraint, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixproxy_ProxyCertPathLengthConstraint },
  { &hf_pkixproxy_proxyPolicy, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixproxy_ProxyPolicy },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixproxy_ProxyCertInfoExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProxyCertInfoExtension_sequence, hf_index, ett_pkixproxy_ProxyCertInfoExtension);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ProxyCertInfoExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkixproxy_ProxyCertInfoExtension(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkixproxy_ProxyCertInfoExtension_PDU);
}


/*--- End of included file: packet-pkixproxy-fn.c ---*/
#line 49 "../../asn1/pkixproxy/packet-pkixproxy-template.c"


/*--- proto_register_pkixproxy ----------------------------------------------*/
void proto_register_pkixproxy(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkixproxy-hfarr.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-hfarr.c"
    { &hf_pkixproxy_ProxyCertInfoExtension_PDU,
      { "ProxyCertInfoExtension", "pkixproxy.ProxyCertInfoExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixproxy_pCPathLenConstraint,
      { "pCPathLenConstraint", "pkixproxy.pCPathLenConstraint",
        FT_INT32, BASE_DEC, NULL, 0,
        "ProxyCertPathLengthConstraint", HFILL }},
    { &hf_pkixproxy_proxyPolicy,
      { "proxyPolicy", "pkixproxy.proxyPolicy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixproxy_policyLanguage,
      { "policyLanguage", "pkixproxy.policyLanguage",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixproxy_policy,
      { "policy", "pkixproxy.policy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},

/*--- End of included file: packet-pkixproxy-hfarr.c ---*/
#line 57 "../../asn1/pkixproxy/packet-pkixproxy-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkixproxy-ettarr.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-ettarr.c"
    &ett_pkixproxy_ProxyCertInfoExtension,
    &ett_pkixproxy_ProxyPolicy,

/*--- End of included file: packet-pkixproxy-ettarr.c ---*/
#line 62 "../../asn1/pkixproxy/packet-pkixproxy-template.c"
  };

  /* Register protocol */
  proto_pkixproxy = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixproxy, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixproxy -------------------------------------------*/
void proto_reg_handoff_pkixproxy(void) {

/*--- Included file: packet-pkixproxy-dis-tab.c ---*/
#line 1 "../../asn1/pkixproxy/packet-pkixproxy-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.14", dissect_ProxyCertInfoExtension_PDU, proto_pkixproxy, "id-pe-proxyCertInfo");


/*--- End of included file: packet-pkixproxy-dis-tab.c ---*/
#line 77 "../../asn1/pkixproxy/packet-pkixproxy-template.c"
  oid_add_from_string("id-ppl-anyLanguage","1.3.6.1.5.5.7.21.0");
  oid_add_from_string("id-ppl-inheritAll","1.3.6.1.5.5.7.21.1");
  oid_add_from_string("id-ppl-independent","1.3.6.1.5.5.7.21.2");
}


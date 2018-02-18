/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mudurl.c                                                            */
/* asn2wrs.py -b -p mudurl -c ./mudurl.cnf -s ./packet-mudurl-template -D . -O ../.. MUDURL.asn */

/* Input file: packet-mudurl-template.c */

#line 1 "./asn1/mudurl/packet-mudurl-template.c"
/* packet-mudurl-template.c
 * Routines for mudurl found in draft-ietf-opsawg-mud
 * by Eliot Lear
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
/* #include "packet-mudurl.h" */ // At the moment we are not exporting.
#include "packet-x509af.h"

#define PNAME  "MUDURL"
#define PSNAME "MUDURL"
#define PFNAME "mudurl"

void proto_register_mudurl(void);
void proto_reg_handoff_mudurl(void);


/* Initialize the protocol and registered fields */
static int proto_mudurl = -1;

/*--- Included file: packet-mudurl-hf.c ---*/
#line 1 "./asn1/mudurl/packet-mudurl-hf.c"
static int hf_mudurl_MUDURLSyntax_PDU = -1;       /* MUDURLSyntax */

/*--- End of included file: packet-mudurl-hf.c ---*/
#line 32 "./asn1/mudurl/packet-mudurl-template.c"

/* Initialize the subtree pointers */
/* #include "packet-mudurl-ett.c" */

// static const char *object_identifier_id;


/*--- Included file: packet-mudurl-fn.c ---*/
#line 1 "./asn1/mudurl/packet-mudurl-fn.c"


static int
dissect_mudurl_MUDURLSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_MUDURLSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_mudurl_MUDURLSyntax(FALSE, tvb, offset, &asn1_ctx, tree, hf_mudurl_MUDURLSyntax_PDU);
  return offset;
}


/*--- End of included file: packet-mudurl-fn.c ---*/
#line 39 "./asn1/mudurl/packet-mudurl-template.c"


/*--- proto_register_mudurl ----------------------------------------------*/
void proto_register_mudurl(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-mudurl-hfarr.c ---*/
#line 1 "./asn1/mudurl/packet-mudurl-hfarr.c"
    { &hf_mudurl_MUDURLSyntax_PDU,
      { "MUDURLSyntax", "mudurl.MUDURLSyntax",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-mudurl-hfarr.c ---*/
#line 47 "./asn1/mudurl/packet-mudurl-template.c"
  };

  /* List of subtrees */
  /*  static gint *ett[] = {
#include "packet-mudurl-ettarr.c"
  }; */

  /* Register protocol */
  proto_mudurl = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_mudurl, hf, array_length(hf));
  //  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_mudurl -------------------------------------------*/
void proto_reg_handoff_mudurl(void) {

/*--- Included file: packet-mudurl-dis-tab.c ---*/
#line 1 "./asn1/mudurl/packet-mudurl-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.25", dissect_MUDURLSyntax_PDU, proto_mudurl, "id-pe-mud-url");


/*--- End of included file: packet-mudurl-dis-tab.c ---*/
#line 67 "./asn1/mudurl/packet-mudurl-template.c"
}

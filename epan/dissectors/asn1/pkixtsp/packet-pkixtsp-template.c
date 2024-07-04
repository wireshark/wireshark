/* packet-pkixtsp.c
 * Routines for RFC2634 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
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
#include "packet-pkixtsp.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-cms.h"

#define PNAME  "PKIX Time Stamp Protocol"
#define PSNAME "PKIXTSP"
#define PFNAME "pkixtsp"

void proto_register_pkixtsp(void);
void proto_reg_handoff_pkixtsp(void);

static dissector_handle_t timestamp_reply_handle;
static dissector_handle_t timestamp_query_handle;

/* Initialize the protocol and registered fields */
static int proto_pkixtsp;
#include "packet-pkixtsp-hf.c"

/* Initialize the subtree pointers */
static int ett_pkixtsp;
#include "packet-pkixtsp-ett.c"


#include "packet-pkixtsp-fn.c"


static int
dissect_timestamp_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Reply");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampResp(false, tvb, 0, &asn1_ctx, tree, -1);
}

static int
dissect_timestamp_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Query");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampReq(false, tvb, 0, &asn1_ctx, tree, -1);
}


/*--- proto_register_pkixtsp ----------------------------------------------*/
void proto_register_pkixtsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixtsp-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	&ett_pkixtsp,
#include "packet-pkixtsp-ettarr.c"
  };

  /* Register protocol */
  proto_pkixtsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixtsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  timestamp_reply_handle = register_dissector(PFNAME "_reply", dissect_timestamp_reply, proto_pkixtsp);
  timestamp_query_handle = register_dissector(PFNAME "_query", dissect_timestamp_query, proto_pkixtsp);

  register_ber_syntax_dissector("TimeStampReq", proto_pkixtsp, dissect_TimeStampReq_PDU);
  register_ber_syntax_dissector("TimeStampResp", proto_pkixtsp, dissect_TimeStampResp_PDU);

  register_ber_oid_syntax(".tsq", NULL, "TimeStampReq");
  register_ber_oid_syntax(".tsr", NULL, "TimeStampResp");
}


/*--- proto_reg_handoff_pkixtsp -------------------------------------------*/
void proto_reg_handoff_pkixtsp(void) {
	dissector_add_string("media_type", "application/timestamp-reply", timestamp_reply_handle);
	dissector_add_string("media_type", "application/timestamp-query", timestamp_query_handle);

#include "packet-pkixtsp-dis-tab.c"
}


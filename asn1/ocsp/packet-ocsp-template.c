/* packet-ocsp.c
 * Routines for Online Certificate Status Protocol (RFC2560) packet dissection
 *  Ronnie Sahlberg 2004
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <asn1.h>

#include "packet-ber.h"
#include "packet-ocsp.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"

#define PNAME  "Online Certificate Status Protocol"
#define PSNAME "OCSP"
#define PFNAME "ocsp"

/* Initialize the protocol and registered fields */
int proto_ocsp = -1;
static int hf_ocsp_responseType_id = -1;
#include "packet-ocsp-hf.c"

/* Initialize the subtree pointers */
static gint ett_ocsp = -1;
#include "packet-ocsp-ett.c"

static const char *responseType_id;


#include "packet-ocsp-fn.c"


static int
dissect_ocsp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Request");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPRequest(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}


static int
dissect_ocsp_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Response");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPResponse(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

/*--- proto_register_ocsp ----------------------------------------------*/
void proto_register_ocsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ocsp_responseType_id,
      { "ResponseType Id", "x509af.responseType.id",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-ocsp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ocsp,
#include "packet-ocsp-ettarr.c"
  };

  /* Register protocol */
  proto_ocsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ocsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*--- proto_reg_handoff_ocsp -------------------------------------------*/
void proto_reg_handoff_ocsp(void) {
	dissector_handle_t ocsp_request_handle;
	dissector_handle_t ocsp_response_handle;

	ocsp_request_handle = new_create_dissector_handle(dissect_ocsp_request, proto_ocsp);
	ocsp_response_handle = new_create_dissector_handle(dissect_ocsp_response, proto_ocsp);

	dissector_add_string("media_type", "application/ocsp-request", ocsp_request_handle);
	dissector_add_string("media_type", "application/ocsp-response", ocsp_response_handle);

#include "packet-ocsp-dis-tab.c"
}


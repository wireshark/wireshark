/* packet-pkixtsp.c
 * Routines for RFC2634 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
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

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-pkixtsp.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-cms.h"

#define PNAME  "PKIX Time Stamp Protocol"
#define PSNAME "PKIXTSP"
#define PFNAME "pkixtsp"

/* Initialize the protocol and registered fields */
static int proto_pkixtsp = -1;
#include "packet-pkixtsp-hf.c"

/* Initialize the subtree pointers */
static gint ett_pkixtsp = -1;
#include "packet-pkixtsp-ett.c"


#include "packet-pkixtsp-fn.c"


static int
dissect_timestamp_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Reply");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampResp(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int
dissect_timestamp_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIXTSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Query");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_pkixtsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_pkixtsp);
	}

	return dissect_pkixtsp_TimeStampReq(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}


/*--- proto_register_pkixtsp ----------------------------------------------*/
void proto_register_pkixtsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixtsp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	&ett_pkixtsp,
#include "packet-pkixtsp-ettarr.c"
  };

  /* Register protocol */
  proto_pkixtsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixtsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixtsp -------------------------------------------*/
void proto_reg_handoff_pkixtsp(void) {
	dissector_handle_t timestamp_reply_handle;
	dissector_handle_t timestamp_query_handle;

	timestamp_reply_handle = new_create_dissector_handle(dissect_timestamp_reply, proto_pkixtsp);
	dissector_add_string("media_type", "application/timestamp-reply", timestamp_reply_handle);

	timestamp_query_handle = new_create_dissector_handle(dissect_timestamp_query, proto_pkixtsp);
	dissector_add_string("media_type", "application/timestamp-query", timestamp_query_handle);

#include "packet-pkixtsp-dis-tab.c"
}


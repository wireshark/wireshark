/* packet-goose.c
 * Routines for IEC 61850 GOOSE packet dissection
 * Martin Lutz 2008
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
#include <epan/asn1.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"

#define PNAME  "GOOSE"
#define PSNAME "GOOSE"
#define PFNAME "goose"

void proto_register_goose(void);
void proto_reg_handoff_goose(void);

/* Initialize the protocol and registered fields */
static int proto_goose = -1;
static int hf_goose_appid = -1;
static int hf_goose_length = -1;
static int hf_goose_reserve1 = -1;
static int hf_goose_reserve2 = -1;

static expert_field ei_goose_mal_utctime = EI_INIT;

#include "packet-goose-hf.c"

/* Initialize the subtree pointers */
static int ett_goose = -1;

#include "packet-goose-ett.c"

#include "packet-goose-fn.c"

/*
* Dissect GOOSE PDUs inside a PPDU.
*/
static void
dissect_goose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	guint16 length;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	if (parent_tree){
		item = proto_tree_add_item(parent_tree, proto_goose, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_goose);


		/* APPID */
		proto_tree_add_item(tree, hf_goose_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Length */
		length = tvb_get_ntohs(tvb, offset + 2);
		proto_tree_add_item(tree, hf_goose_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

		/* Reserved 1 */
		proto_tree_add_item(tree, hf_goose_reserve1, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

		/* Reserved 2 */
		proto_tree_add_item(tree, hf_goose_reserve2, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

		offset = 8;
		while (offset < length){
			old_offset = offset;
			offset = dissect_goose_GOOSEpdu(FALSE, tvb, offset, &asn1_ctx , tree, -1);
			if (offset == old_offset) {
				proto_tree_add_text(tree, tvb, offset, -1, "Internal error, zero-byte GOOSE PDU");
				return;
			}
		}
	}
}


/*--- proto_register_goose -------------------------------------------*/
void proto_register_goose(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
  	{ &hf_goose_appid,
	{ "APPID",	"goose.appid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_length,
	{ "Length",	"goose.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_reserve1,
	{ "Reserved 1",	"goose.reserve1", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_reserve2,
	{ "Reserved 2",	"goose.reserve2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

#include "packet-goose-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_goose,
#include "packet-goose-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_goose_mal_utctime, { "goose.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding", EXPFILL }},
  };

  expert_module_t* expert_goose;

	/* Register protocol */
	proto_goose = proto_register_protocol(PNAME, PSNAME, PFNAME);
	register_dissector("goose", dissect_goose, proto_goose);

	/* Register fields and subtrees */
	proto_register_field_array(proto_goose, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_goose = expert_register_protocol(proto_goose);
	expert_register_field_array(expert_goose, ei, array_length(ei));
}

/*--- proto_reg_handoff_goose --- */
void proto_reg_handoff_goose(void) {

	dissector_handle_t goose_handle;
	goose_handle = find_dissector("goose");

	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_GOOSE, goose_handle);
}

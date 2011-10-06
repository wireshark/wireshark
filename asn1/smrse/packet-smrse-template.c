/* packet-smrse.c
 * Routines for SMRSE Short Message Relay Service packet dissection
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
#include "packet-smrse.h"

#define PNAME  "Short Message Relaying Service"
#define PSNAME "SMRSE"
#define PFNAME "smrse"

#define TCP_PORT_SMRSE 4321

/* Initialize the protocol and registered fields */
static int proto_smrse = -1;
static int hf_smrse_reserved = -1;
static int hf_smrse_tag = -1;
static int hf_smrse_length = -1;
static int hf_smrse_Octet_Format = -1;
#include "packet-smrse-hf.c"

/* Initialize the subtree pointers */
static gint ett_smrse = -1;
#include "packet-smrse-ett.c"


#include "packet-smrse-fn.c"

static const value_string tag_vals[] = {
	{  1,	"AliveTest" },
	{  2,	"AliveTestRsp" },
	{  3,	"Bind" },
	{  4,	"BindRsp" },
	{  5,	"BindFail" },
	{  6,	"Unbind" },
	{  7,	"MT" },
	{  8,	"MO" },
	{  9,	"Ack" },
	{ 10,	"Error" },
	{ 11,	"Alert" },
	{ 0, NULL }
};

static int
dissect_smrse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 reserved, tag;
	guint16 length;
	int offset=0;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	reserved=tvb_get_guint8(tvb, 0);
	length=tvb_get_ntohs(tvb,1);
	tag=tvb_get_guint8(tvb, 3);

	if( reserved!= 126 )
		return 0;
	if( (tag<1)||(tag>11) )
		return 0;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_smrse, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_smrse);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMRSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(tag, tag_vals,"Unknown Tag:0x%02x"));

	proto_tree_add_item(tree, hf_smrse_reserved, tvb, 0, 1, FALSE);
	proto_tree_add_item(tree, hf_smrse_length, tvb, 1, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_smrse_tag, tvb, 3, 1, ENC_BIG_ENDIAN);

	switch(tag){
	case 1:
	case 2:
		offset=4;
		break;
	case 3:
		offset=dissect_smrse_SMR_Bind(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 4:
		offset=dissect_smrse_SMR_Bind_Confirm(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 5:
		offset=dissect_smrse_SMR_Bind_Failure(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 6:
		offset=dissect_smrse_SMR_Unbind(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 7:
		offset=dissect_smrse_RPDataMT(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 8:
		offset=dissect_smrse_RPDataMO(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 9:
		offset=dissect_smrse_RPAck(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 10:
		offset=dissect_smrse_RPError(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 11:
		offset=dissect_smrse_RPAlertSC(FALSE, tvb, 4, &asn1_ctx, tree, -1);
		break;
	}

	return offset;
}

/*--- proto_register_smrse ----------------------------------------------*/
void proto_register_smrse(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	{ &hf_smrse_reserved, {
		"Reserved", "smrse.reserved", FT_UINT8, BASE_DEC,
		NULL, 0, "Reserved byte, must be 126", HFILL }},
	{ &hf_smrse_tag, {
		"Tag", "smrse.tag", FT_UINT8, BASE_DEC,
		VALS(tag_vals), 0, NULL, HFILL }},
	{ &hf_smrse_length, {
		"Length", "smrse.length", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of SMRSE PDU", HFILL }},
    { &hf_smrse_Octet_Format,
      { "octet-Format", "smrse.octet_Format",
        FT_STRING, BASE_NONE, NULL, 0,
        "SMS-Address/address-value/octet-format", HFILL }},

#include "packet-smrse-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_smrse,
#include "packet-smrse-ettarr.c"
  };

  /* Register protocol */
  proto_smrse = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_smrse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_smrse -------------------------------------------*/
void proto_reg_handoff_smrse(void) {
  dissector_handle_t smrse_handle;

  smrse_handle = new_create_dissector_handle(dissect_smrse, proto_smrse);
  dissector_add_uint("tcp.port",TCP_PORT_SMRSE, smrse_handle);
}


/* packet-smrse.c
 * Routines for SMRSE Short Message Relay Service packet dissection
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
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-smrse.h"

#define PNAME  "Short Message Relaying Service"
#define PSNAME "SMRSE"
#define PFNAME "smrse"

#define TCP_PORT_SMRSE 4321 /* Not IANA registered */

void proto_register_smrse(void);
void proto_reg_handoff_smrse(void);

static dissector_handle_t smrse_handle;

/* Initialize the protocol and registered fields */
static int proto_smrse;
static int hf_smrse_reserved;
static int hf_smrse_tag;
static int hf_smrse_length;
static int hf_smrse_Octet_Format;
#include "packet-smrse-hf.c"

/* Initialize the subtree pointers */
static int ett_smrse;
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
dissect_smrse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	uint8_t reserved, tag;
	int offset=0;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	reserved=tvb_get_uint8(tvb, 0);
	tag=tvb_get_uint8(tvb, 3);

	if( reserved!= 126 )
		return 0;
	if( (tag<1)||(tag>11) )
		return 0;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_smrse, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_smrse);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMRSE");
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(tag, tag_vals,"Unknown Tag:0x%02x"));

	proto_tree_add_item(tree, hf_smrse_reserved, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_smrse_length, tvb, 1, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_smrse_tag, tvb, 3, 1, ENC_BIG_ENDIAN);

	switch(tag){
	case 1:
	case 2:
		offset=4;
		break;
	case 3:
		offset=dissect_smrse_SMR_Bind(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 4:
		offset=dissect_smrse_SMR_Bind_Confirm(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 5:
		offset=dissect_smrse_SMR_Bind_Failure(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 6:
		offset=dissect_smrse_SMR_Unbind(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 7:
		offset=dissect_smrse_RPDataMT(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 8:
		offset=dissect_smrse_RPDataMO(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 9:
		offset=dissect_smrse_RPAck(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 10:
		offset=dissect_smrse_RPError(false, tvb, 4, &asn1_ctx, tree, -1);
		break;
	case 11:
		offset=dissect_smrse_RPAlertSC(false, tvb, 4, &asn1_ctx, tree, -1);
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
  static int *ett[] = {
    &ett_smrse,
#include "packet-smrse-ettarr.c"
  };

  /* Register protocol */
  proto_smrse = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register dissector */
  smrse_handle = register_dissector(PFNAME, dissect_smrse, proto_smrse);

  /* Register fields and subtrees */
  proto_register_field_array(proto_smrse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_smrse -------------------------------------------*/
void proto_reg_handoff_smrse(void) {
  dissector_add_uint_with_preference("tcp.port",TCP_PORT_SMRSE, smrse_handle);
}

